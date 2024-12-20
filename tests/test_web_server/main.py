from src.issuer import TokenStatusListIssuer
from src.token_status_list import BitArray

from google.auth.crypt.es256 import ES256Signer
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from time import time

MY_HTML = """\
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>My Website</title>
  </head>
  <body>
    <main>
        <h1>This is really my new website.</h1>  
    </main>
  </body>
</html>
"""

""" Define token status list """
STATUS = TokenStatusListIssuer.new(1, 16)
STATUS.status_list = BitArray(1, b"\xb9\xa3")

""" Define signer/verifier """
ES256_KEY = ec.generate_private_key(ec.SECT233K1())

def es256_signer(payload: bytes) -> bytes:
    signer = ES256Signer(ES256_KEY)
    return signer.sign(payload)

""" Create tokens """
def issue_signed_jwt_token() -> str:
    token = STATUS.sign_jwt(
        signer=es256_signer,
        alg="ES256",
        kid="12",
        iss="http://localhost:3001",
        sub="http://localhost:3001/jwt_example",
        iat=int(time()),
        exp=int(time() + 1e5),  # 1e5 seconds ~= 2.5 hours
    )

    return token

def issue_signed_cwt_token() -> bytes:
    token = STATUS.sign_cwt(
        signer=es256_signer,
        alg="ES256",
        kid="12",
        iss="http://localhost:3001",
        sub="http://localhost:3001/cwt_example",
        iat=int(time()),
        exp=int(time() + 10000),
    )

    return token

if __name__ == "__main__":
    with open("/var/www/html/public_key", "wb+") as public_key_file:
      public_key_file.write(ES256_KEY.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))

    with open("/var/www/html/jwt_example", "w+") as jwt_file:
      jwt_file.write(issue_signed_jwt_token())

    with open("/var/www/html/cwt_example", "wb+") as cwt_file:
      cwt_file.write(issue_signed_cwt_token())
