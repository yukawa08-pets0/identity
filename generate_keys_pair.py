from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from settings import settings
from tokens import make_kid
import asyncpg  # type: ignore[import-untyped]
import asyncio  # type: ignore

# step 1: generate private and public key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# step 2: encryption private key and public key pair
password = settings.key_password.get_secret_value().encode()
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password),
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# step 4: kid
kid = make_kid(public_key)

path = f"{settings.keys_dir}\\active_pub_key.pem"
# step 5: save private key to PEM file
with open(settings.private_key_path, "wb") as f:
    f.write(pem_private)

path = f"{settings.keys_dir}\\{settings.public_key_active_file_name}"
with open(path, "wb") as f:
    f.write(pem_public)


# step 6: update public keys db
# async def main():
#     conn = await asyncpg.connect(settings.async_pg_db_url)  # type: ignore[import-untyped]
#     try:
#         async with conn.transaction():  # type: ignore
#             await conn.execute(  # type: ignore
#                 """
#                 UPDATE signing_keys
#                 SET status = 'DEPRECATED'
#                 WHERE status = 'ACTIVE'
#                 """
#             )
#             await conn.execute(  # type: ignore
#                 """
#                 INSERT INTO signing_keys (kid, public_key_pem, algorithm, status)
#                 VALUES ($1, $2, 'RS256', 'ACTIVE')
#                 """,
#                 kid,
#                 pem_public,
#             )
#     finally:
#         await conn.close()  # type: ignore


# asyncio.run(main())
