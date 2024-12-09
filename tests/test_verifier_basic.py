"""Test VerifierStatusList."""

import pytest
from time import time

from google.auth.crypt.es256 import ES256Signer, ES256Verifier
from cryptography.hazmat.primitives.asymmetric import ec


from token_status_list import BitArray
from issuer import TokenStatusListIssuer
from verifier import TokenStatusListVerifier

def trivial_signer(payload: bytes) -> bytes:
    return b"signed"

def trivial_verifier(payload: bytes, signature: bytes) -> bool:
    """ Trivial verifier: always says that the signature is valid. """
    return True

@pytest.fixture
def status():
    lst = BitArray(1, b"\xb9\xa3")
    status = TokenStatusListIssuer.new(1, 16)
    status.status_list = lst
    yield status

def test_verify_jwt_trivial(status: TokenStatusListIssuer):
    issuer = "https://example.com"

    payload = status.sign_jwt(
        signer=trivial_signer,
        alg="ES256",
        kid="12",
        iss=issuer,
        sub="https://example.com/statuslists/1",
        iat=int(time()),
        exp=int(time() + 10000),
    )

    # Check that token is correctly verified
    verifier = TokenStatusListVerifier()
    header, payload = verifier.jwt_verify(payload.encode(), trivial_verifier)

    # Check that values match
    for i in range(len(status)):
        assert status[i] == verifier.jwt_get_status(payload, i)

def test_verify_jwt_expired(status: TokenStatusListIssuer):
    payload = status.sign_jwt(
        signer=trivial_signer,
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=10,
        exp=20,
    )

    # Check that token is correctly verified
    verifier = TokenStatusListVerifier()
    try:
        header, payload = verifier.jwt_verify(payload.encode(), trivial_verifier)
        raise ValueError("Token should be expired.")
    except ValueError:
        return

def test_verify_jwt_es256(status: TokenStatusListIssuer):
    private_key = ec.generate_private_key(ec.SECT233K1())
    es256_signer = ES256Signer(private_key)
    es256_verifier = ES256Verifier(private_key.public_key())

    payload = status.sign_jwt(
        signer=es256_signer.sign,
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=int(time()),
        exp=int(time() + 10000),
    )

    # Check that token is correctly verified using ES256
    verifier = TokenStatusListVerifier()
    header, payload = verifier.jwt_verify(payload.encode(), es256_verifier.verify)

    # Check that values match
    for i in range(len(status)):
        assert status[i] == verifier.jwt_get_status(payload, i)
