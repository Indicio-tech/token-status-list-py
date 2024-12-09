"""Test IssuerStatusList."""

import json
import pytest
from token_status_list import BitArray, b64url_decode
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

def test_verify_jwt_payload_trivial(status: TokenStatusListIssuer):
    issuer = "https://example.com"

    payload = status.sign_jwt(
        signer=trivial_signer,
        alg="ES256",
        kid="12",
        iss=issuer,
        sub="https://example.com/statuslists/1",
        iat=1686920170,
        exp=2291720170,
    )

    verifier = TokenStatusListVerifier(issuer_addr=issuer)
    header, payload = verifier.jwt_verify(payload.encode(), trivial_verifier)

    for i in range(len(status)):
        assert status[i] == verifier.jwt_get_status(payload, i)
