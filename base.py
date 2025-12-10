from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
    AsyncEngine,
)

# TODO добавить конфигурацию
dsn = "postgresql+asyncpg://admin:admin@localhost:5432/authr"

engine: AsyncEngine = create_async_engine(
    dsn, echo=False, pool_size=10, max_overflow=20
)

LocalSession = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def create_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
