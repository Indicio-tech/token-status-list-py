import pytest
from time import time

from google.auth.crypt.es256 import ES256Signer, ES256Verifier
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from bit_array import BitArray
from bitstring_status_list.issuer import BitstringStatusListIssuer, MIN_LIST_LENGTH
from bitstring_status_list.verifier import BitstringStatusListVerifier

@pytest.fixture
def status():
    status = BitstringStatusListIssuer.new(MIN_LIST_LENGTH)
    for idx in status.take_n(50):
        status[idx] = 1
    yield status

def trivial_signer(payload: bytes) -> bytes:
    return b"signed"

def trivial_verifier(payload: bytes, signature: bytes) -> bool:
    """ Trivial verifier: always says that the signature is valid. """
    return True

def test_verify_jwt_basic_enveloping(status: BitstringStatusListIssuer):
    encoded_jwt = status.sign_jwt_enveloping(
        signer=trivial_signer,
        alg="ES256",
        kid="12",
        status_purpose="revocation",
    )

    credential_status = {
        "id": "https://example.com/credentials/status/3#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "0",
        "statusListCredential": "https://example.com/credentials/status/3"
    }

    verifier = BitstringStatusListVerifier(credential_status)
    verifier.verify_jwt(encoded_jwt, verifier=trivial_verifier)

    assert verifier.headers == {"alg": "ES256", "kid": "12"}
    assert verifier.payload == {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
        ],

        "type": ["BitstringStatusListCredential"],

        "credentialSubject": {
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": status.status_list.to_b64(),
        }
    }

    for i in range(len(status)):
        assert verifier.get_status(i) == {
            "status": status[i],
            "valid": not bool(status[i])
        }

def test_verify_jwt_basic_embedding(status: BitstringStatusListIssuer):
    ...