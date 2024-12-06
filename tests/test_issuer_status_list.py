"""Test IssuerStatusList."""

import json
import pytest
from token_status_list import BitArray, b64url_decode
from issuer import TokenStatusListIssuer


@pytest.fixture
def status():
    lst = BitArray(1, b"\xb9\xa3")
    status = TokenStatusListIssuer.new(1, 16)
    status.status_list = lst
    yield status


def test_serde(status: TokenStatusListIssuer):
    expected = status
    actual = TokenStatusListIssuer.load(expected.dump())
    assert len(expected.status_list.lst) == 2
    assert len(actual.status_list.lst) == 2
    assert expected.status_list.lst == actual.status_list.lst
    assert expected.status_list.bits == actual.status_list.bits
    assert expected.status_list.size == actual.status_list.size


def test_sign_jwt_payload(status: TokenStatusListIssuer):
    payload = status.sign_jwt_payload(
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=1686920170,
        exp=2291720170,
    )
    headers, payload = payload.split(b".")
    headers = json.loads(b64url_decode(headers))
    payload = json.loads(b64url_decode(payload))
    assert headers == {"alg": "ES256", "kid": "12", "typ": "statuslist+jwt"}
    assert payload == {
        "exp": 2291720170,
        "iat": 1686920170,
        "iss": "https://example.com",
        "status_list": {"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
        "sub": "https://example.com/statuslists/1",
    }


def test_sign_cwt_payload(status: TokenStatusListIssuer):
    token = status.sign_cwt(
        lambda payload: b"10",
        kid=b"12",
        alg="ES256",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=1686912970,
        exp=2291712970,
    )
    print(token.hex())
