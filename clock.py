from datetime import datetime, timezone, timedelta


def now_int() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def now_datetime() -> datetime:
    return datetime.now(tz=timezone.utc)


def expiration_calc_int(iat: int, minutes: int, days: int = 0) -> int:
    datetime_ = datetime.fromtimestamp(iat, tz=timezone.utc) + timedelta(
        days=days, minutes=minutes
    )
    return int(datetime_.timestamp())


def expiration_calc_datetime(minutes: int = 0, days: int = 0) -> datetime:
    return timedelta(days=days, minutes=minutes) + datetime.now(tz=timezone.utc)
