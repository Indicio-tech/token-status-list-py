import pytest
import asyncio

pytest_plugins = ('pytest_asyncio',)

from google.auth.crypt.es256 import ES256Verifier
from cryptography.hazmat.primitives.asymmetric import ec
import requests as r

from token_status_list.verifier import TokenStatusListVerifier
from token_status_list.issuer import TokenStatusListIssuer
from token_status_list.issuer import ALG, KID, TYP, ISS, SUB, AUD, EXP, NBF, IAT, CTI, STATUS_LIST, TTL, KNOWN_ALGS_TO_CWT_ALG
from bit_array import BitArray

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

@pytest.mark.asyncio
async def test_jwt_verify(status, es256_verifier):
    verifier = await TokenStatusListVerifier.retrieve_list(
        encoding="JWT",
        status_list_uri=ISSUER + "/jwt_example",
        verifier=es256_verifier
    )
    
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

@pytest.mark.asyncio
async def test_cwt_verify(status, es256_verifier):
    try:
        import cbor2
    except ImportError as err:
        raise ImportError("cbor extra required to use this function") from err
    
    verifier = await TokenStatusListVerifier.retrieve_list(
        encoding="CWT",
        status_list_uri=ISSUER + "/cwt_example",
        verifier=es256_verifier,
    )

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
