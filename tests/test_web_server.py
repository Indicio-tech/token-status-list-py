from subprocess import call

import pytest
from google.auth.crypt.es256 import ES256Verifier
from cryptography.hazmat.primitives.asymmetric import ec
import requests as r

from src.verifier import TokenStatusListVerifier
from src.issuer import TokenStatusListIssuer
from src.issuer import TokenStatusListIssuer, ALG, KID, TYP, ISS, SUB, AUD, EXP, NBF, IAT, CTI, STATUS_LIST, TTL, KNOWN_ALGS_TO_CWT_ALG
from src.token_status_list import BitArray

ISSUER = "http://localhost:3001"

@pytest.fixture
def status():
    lst = BitArray(1, b"\xb9\xa3")
    status = TokenStatusListIssuer.new(1, 16)
    status.status_list = lst
    yield status

@pytest.fixture
def es256_verifier():
    public_key_bytes = r.get(ISSUER + "/public_key").content
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECT233K1(), public_key_bytes)
    yield ES256Verifier(public_key).verify


EXPECTED_IAT = 1734650332
EXPECTED_EXP = 1744650332 

def test_jwt_verify(status, es256_verifier):
    verifier = TokenStatusListVerifier()
    response = verifier.establish_connection("JWT", ISSUER + "/jwt_example")
    
    # Check that token is correctly verified
    verifier = TokenStatusListVerifier()
    verifier.jwt_verify(response, es256_verifier)

    # Check that headers and payload are as expected
    assert verifier.encoding == "JWT"
    assert verifier.headers == {"alg": "ES256", "kid": "12", "typ": "statuslist+jwt"}
    assert verifier.payload == {
        "iat": EXPECTED_IAT,
        "exp": EXPECTED_EXP,
        "iss": ISSUER,
        "status_list": {"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
        "sub": ISSUER + "/jwt_example",
    }

    # Check that statuses match
    for i in range(len(status)):
        assert status[i] == verifier.get_status(i)


def test_cwt_verify(status, es256_verifier):
    try:
        import cbor2
    except ImportError as err:
        raise ImportError("cbor extra required to use this function") from err
    
    verifier = TokenStatusListVerifier()
    response = verifier.establish_connection("CWT", ISSUER + "/cwt_example")

    verifier.cwt_verify(response, es256_verifier)

    # Check that headers and payload are as expected
    assert verifier.encoding == "CWT"
    assert verifier.protected_headers == {ALG: KNOWN_ALGS_TO_CWT_ALG["ES256"], TYP: "statuslist+cwt"}
    assert verifier.unprotected_headers == {KID: "12"}
    assert verifier.payload == {
        EXP: EXPECTED_EXP,
        IAT: EXPECTED_IAT,
        ISS: ISSUER,
        STATUS_LIST: {"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
        SUB: ISSUER + "/cwt_example",
    }

    # Check that values match
    for i in range(len(status)):
        assert status[i] == verifier.get_status(i)
