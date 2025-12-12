from argon2 import PasswordHasher
from argon2.low_level import Type

hasher = PasswordHasher(
    time_cost=3,
    parallelism=2,
    memory_cost=64 * 1024,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
