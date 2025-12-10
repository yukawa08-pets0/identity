from pydantic import BaseModel
from base import create_db
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from uuid import UUID


@asynccontextmanager
async def lifespan(app_: FastAPI):
    await create_db()
    yield


class AccessPayload(BaseModel):
    sub: UUID
    sid: UUID
    iat: int
    exp: int


from fastapi import Header
from tokens import parse_token
from di import get_uow
from uow import UnitOfWork
from typing import Annotated
from flows import register_cmd
from fastapi import Response, HTTPException
from clock import now_datetime

UoWDep = Annotated[UnitOfWork, Depends(get_uow)]


async def authn_middleware(
    uow: UoWDep,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AccessPayload:
    if not authorization:
        raise HTTPException(status_code=401, detail="Token not found")

    type_, _, param = authorization.partition(" ")

    if type_ != "Bearer":
        raise HTTPException(status_code=401, detail="Token invalid")

    try:
        access = AccessPayload(**parse_token(param))
    except Exception:
        raise HTTPException(status_code=401, detail="Access token invalid")

    async with uow:
        session = await uow.user_sessions.get_by_id(access.sid)
        if session is None:
            raise HTTPException(status_code=401, detail="Session not found")

        if not session.is_valid(now_datetime()):
            raise HTTPException(status_code=401, detail="Session invalid")

    return access


AccessDep = Annotated[AccessPayload, Depends(authn_middleware)]


app = FastAPI(lifespan=lifespan)


class RegisterDto(BaseModel):
    username: str
    email: str
    password: str


class AccessTokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


from exceptions import AppException


@app.post("/auth/register", status_code=201)
async def register(
    register_in: RegisterDto,
    uow: UoWDep,
):
    try:
        await register_cmd(
            register_in.username, register_in.email, register_in.password, uow
        )
    except AppException as e:
        raise HTTPException(status_code=409, detail=e.detail)

    return {"status": "successful"}


class LoginDto(BaseModel):
    email: str
    password: str


from flows import login_cmd


@app.post("/auth/login", status_code=200)
async def login(
    dto: LoginDto,
    uow: UoWDep,
    response: Response,
):
    try:
        tokens = await login_cmd(dto.email, dto.password, uow)
    except AppException as e:
        raise HTTPException(status_code=404, detail=e.detail)
    response.set_cookie(
        "refresh",
        value=tokens.refresh_token,
        secure=True,
        samesite="lax",
        httponly=True,
        path="/auth",
        max_age=30 * 24 * 60 * 60,
    )
    return AccessTokenOut(access_token=tokens.access_token)


from flows import reset_password_query, reset_password_cmd


class ResetPasswordRequest(BaseModel):
    email: str


@app.post("/auth/reset/request", status_code=200)
async def reset_password_request(
    dto: ResetPasswordRequest,
    uow: UoWDep,
):
    try:
        await reset_password_query(dto.email, uow)
    except AppException as e:
        raise HTTPException(status_code=404, detail=e.detail)


class ResetPasswordConfirm(BaseModel):
    new_password: str


@app.post("/auth/reset/confirm", status_code=204)
async def reset_password_confirm(
    token: str,
    dto: ResetPasswordConfirm,
    uow: UoWDep,
):
    try:
        await reset_password_cmd(token, dto.new_password, uow)
    except AppException as e:
        raise HTTPException(status_code=404, detail=e.detail)


from flows import refresh_cmd
from fastapi import Cookie


@app.post("/auth/refresh", status_code=200)
async def refresh(
    uow: UoWDep,
    response: Response,
    refresh_token: str = Cookie(..., alias="refresh"),
):
    try:
        tokens = await refresh_cmd(refresh_token, uow)
    except AppException as e:
        raise HTTPException(status_code=401, detail=e.detail)

    response.set_cookie(
        "refresh",
        tokens.refresh_token,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/auth",
        max_age=30 * 24 * 60 * 60,
    )

    return AccessTokenOut(access_token=tokens.access_token)


from flows import logout_cmd, logout_all_cmd


@app.post("/auth/logout", status_code=204)
async def logout_current_session(
    uow: UoWDep,
    response: Response,
    access: AccessDep,
    refresh_token: str = Cookie(..., alias="refresh"),
):
    try:
        await logout_cmd(refresh_raw=refresh_token, uow=uow)
    except AppException as e:
        raise HTTPException(status_code=404, detail=e.detail)
    response.delete_cookie("refresh")


@app.post("/auth/logout-all", status_code=204)
async def logout_all_user_sessions(
    access: AccessDep,
    response: Response,
    uow: UoWDep,
):
    try:
        await logout_all_cmd(user_id=access.sub, uow=uow)
    except AppException as e:
        raise HTTPException(status_code=404, detail=e.detail)
    response.delete_cookie("refresh")
