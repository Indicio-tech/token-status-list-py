"""Test VerifierStatusList."""

import pytest
from time import time

from google.auth.crypt.es256 import ES256Signer, ES256Verifier
from cryptography.hazmat.primitives.asymmetric import ec


from src.token_status_list import BitArray
from src.issuer import TokenStatusListIssuer, ALG, KID, TYP, ISS, SUB, AUD, EXP, NBF, IAT, CTI, STATUS_LIST, TTL, KNOWN_ALGS_TO_CWT_ALG
from src.verifier import TokenStatusListVerifier

from typing import Tuple

@pytest.fixture
def status():
    lst = BitArray(1, b"\xb9\xa3")
    status = TokenStatusListIssuer.new(1, 16)
    status.status_list = lst
    yield status

def trivial_signer(payload: bytes) -> bytes:
    return b"signed"

def trivial_verifier(payload: bytes, signature: bytes) -> bool:
    """ Trivial verifier: always says that the signature is valid. """
    return True

ES256_KEY = ec.generate_private_key(ec.SECT233K1())

@pytest.fixture
def es256_signer():
    signer = ES256Signer(ES256_KEY)
    def sign(payload: bytes) -> bytes:
        return signer.sign(payload)
    yield sign

@pytest.fixture
def es256_verifier():
    verifier = ES256Verifier(ES256_KEY.public_key())
    def verify(payload: bytes, signature: bytes) -> bool:
        return verifier.verify(payload, signature)
    yield verify

def test_verify_jwt_basic(status: TokenStatusListIssuer):
    iat = int(time())
    exp = int(time() + 10000)
    
    payload = status.sign_jwt(
        signer=trivial_signer,
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=iat,
        exp=exp,
    )

    # Check that token is correctly verified
    verifier = TokenStatusListVerifier()
    verifier.jwt_verify(payload.encode(), trivial_verifier)

    # Check that headers and payload are as expected
    assert verifier.encoding == "JWT"
    assert verifier.headers == {"alg": "ES256", "kid": "12", "typ": "statuslist+jwt"}
    assert verifier.payload == {
        "exp": exp,
        "iat": iat,
        "iss": "https://example.com",
        "status_list": {"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
        "sub": "https://example.com/statuslists/1",
    }

    # Check that statuses match
    for i in range(len(status)):
        assert status[i] == verifier.get_status(i)

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

    verifier = TokenStatusListVerifier()
    try:
        verifier.jwt_verify(payload.encode(), trivial_verifier)
        raise ValueError("Token should be expired.")
    except ValueError:
        return

def test_verify_jwt_es256(status: TokenStatusListIssuer, es256_signer, es256_verifier):
    payload = status.sign_jwt(
        signer=es256_signer,
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=int(time()),
        exp=int(time() + 10000),
    )

    # Check that token is correctly verified using ES256
    verifier = TokenStatusListVerifier()
    verifier.jwt_verify(payload.encode(), es256_verifier)

    # Check that values match
    for i in range(len(status)):
        assert status[i] == verifier.get_status(i)

def test_verify_cwt_basic(status: TokenStatusListIssuer):
    try:
        import cbor2
    except ImportError as err:
        raise ImportError("cbor extra required to use this function") from err
    
    iat = int(time())
    exp = int(time()) + 10000
    token = status.sign_cwt(
        lambda payload: b"10",
        kid=b"12",
        alg="ES256",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=iat,
        exp=exp,
    )

    verifier = TokenStatusListVerifier()
    verifier.cwt_verify(token, trivial_verifier)

    # Check that headers and payload are as expected
    assert verifier.encoding == "CWT"
    assert verifier.protected_headers == {ALG: KNOWN_ALGS_TO_CWT_ALG["ES256"], TYP: "statuslist+cwt"}
    assert verifier.unprotected_headers == {KID: b"12"}
    assert verifier.payload == {
        EXP: exp,
        IAT: iat,
        ISS: "https://example.com",
        STATUS_LIST: {"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
        SUB: "https://example.com/statuslists/1",
    }

    # Check that values match
    for i in range(len(status)):
        assert status[i] == verifier.get_status(i)

def test_verify_cwt_expired(status: TokenStatusListIssuer):
    token = status.sign_cwt(
        signer=trivial_signer,
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=10,
        exp=20,
    )

    verifier = TokenStatusListVerifier()
    try:
        verifier.cwt_verify(token, trivial_verifier)
        raise ValueError("Token should be expired.")
    except ValueError:
        return
    
def test_verify_cwt_es256(status: TokenStatusListIssuer, es256_signer, es256_verifier):
    token = status.sign_cwt(
        signer=es256_signer,
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=int(time()),
        exp=int(time() + 10000),
    )

    # Check that token is correctly verified using ES256
    verifier = TokenStatusListVerifier()
    verifier.cwt_verify(token, es256_verifier)

    # Check that values match
    for i in range(len(status)):
        assert status[i] == verifier.get_status(i)