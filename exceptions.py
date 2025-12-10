from dataclasses import dataclass


@dataclass
class AppException(Exception):
    detail: str
