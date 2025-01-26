import pytest

from google.auth.crypt.es256 import ES256Signer, ES256Verifier
from cryptography.hazmat.primitives.asymmetric import ec

from bit_array import b64url_encode, b64url_decode
from bitstring_status_list.issuer import BitstringStatusListIssuer, EmbeddingTokenSigner, EnvelopingTokenSigner, MIN_LIST_LENGTH
from bitstring_status_list.verifier import BitstringStatusListVerifier, EmbeddingTokenVerifier, EnvelopingTokenVerifier

@pytest.fixture
def status():
    status = BitstringStatusListIssuer.new(MIN_LIST_LENGTH)
    for idx in status.take_n(50):
        status[idx] = 1
    yield status

# Integrity
def trivial_enveloping_signer(payload: bytes) -> bytes:
    return b"signed"

def trivial_enveloping_verifier(payload: bytes, signature: bytes) -> bool:
    """ Trivial verifier: always says that the signature is valid. """
    return True

def trivial_embedding_signer(payload: bytes) -> dict:
    return {"value": "signed"}

def trivial_embedding_verifier(payload: bytes, signature: dict) -> bool:
    """ Trivial verifier: always says that the signature is valid. """
    return True


# More advanced verification
ES256_KEY = ec.generate_private_key(ec.SECT233K1())

@pytest.fixture
def es256_enveloping_signer():
    signer = ES256Signer(ES256_KEY)
    def sign(payload: bytes) -> bytes:
        return signer.sign(payload)
    yield sign

@pytest.fixture
def es256_enveloping_verifier():
    verifier = ES256Verifier(ES256_KEY.public_key())
    def verify(payload: bytes, signature: bytes) -> bool:
        return verifier.verify(payload, signature)
    yield verify

@pytest.fixture
def es256_embedding_signer():
    signer = ES256Signer(ES256_KEY)
    def sign(payload: bytes) -> dict:
        return {"proofValue": b64url_encode(signer.sign(payload)).decode()}
    yield sign

@pytest.fixture
def es256_embedding_verifier():
    verifier = ES256Verifier(ES256_KEY.public_key())
    def verify(payload: bytes, signature: dict) -> bool:
        return verifier.verify(payload, b64url_decode(signature["proofValue"].encode()))
    yield verify

def test_verify_jwt_basic_enveloping(status: BitstringStatusListIssuer):
    encoded_jwt = status.sign_jwt_enveloping(
        signer=trivial_enveloping_signer,
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

    verifier = BitstringStatusListVerifier.from_jwt(
        token=encoded_jwt,
        credential_status=credential_status,
        verifier=trivial_embedding_verifier,
    )

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

    for i in range(status.status_list.size):
        assert verifier.get_status(i) == {
            "status": status[i],
            "valid": not bool(status[i])
        }

def test_verify_jwt_basic_embedding(status: BitstringStatusListIssuer):
    encoded_jwt = status.sign_jwt_embedding(
        signer=trivial_embedding_signer,
        status_purpose="revocation",
    )

    credential_status = {
        "id": "https://example.com/credentials/status/3#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "0",
        "statusListCredential": "https://example.com/credentials/status/3"
    }

    verifier = BitstringStatusListVerifier.from_jwt(
        token=encoded_jwt,
        credential_status=credential_status,
        verifier=trivial_embedding_verifier,
    )

    assert verifier.payload == {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
        ],

        "type": ["BitstringStatusListCredential"],

        "credentialSubject": {
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": status.status_list.to_b64(),
        },

        "proof": {
            "value": "signed",
        },
    }

    for i in range(status.status_list.size):
        assert verifier.get_status(i) == {
            "status": status[i],
            "valid": not bool(status[i])
        }

def test_status_message():
    # Create a bitstring status list with a variety of different statuses
    bitstring = BitstringStatusListIssuer.new(MIN_LIST_LENGTH, bits=2)
    for idx in bitstring.take_n(50):
        bitstring[idx] = 1
    for idx in bitstring.take_n(50):
        bitstring[idx] = 2
    for idx in bitstring.take_n(50):
        bitstring[idx] = 3

    status_messages = [
            {"status":"0x0", "message":"0"},
            {"status":"0x1", "message":"1"},
            {"status":"0x2", "message":"2"},
            {"status":"0x3", "message":"3"},
    ]

    encoded_jwt = bitstring.sign_jwt_enveloping(
        signer=trivial_enveloping_signer,
        alg="ES256",
        kid="12",
        status_purpose="message",
        status_messages=status_messages,
        status_size=2,
    )

    credential_status = {
        "id": "https://example.com/credentials/status/3#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "message",
        "statusListIndex": "0",
        "statusListCredential": "https://example.com/credentials/status/3",
        "statusMessage": status_messages,
        "statusSize": 2,
    }

    verifier = BitstringStatusListVerifier.from_jwt(
        token=encoded_jwt,
        credential_status=credential_status,
        verifier=trivial_enveloping_verifier,
    )

    for i in range(bitstring.status_list.size):
        assert verifier.get_status(i) == {
            "status": bitstring[i],
            "valid": not bool(bitstring[i]),
            "message": str(bitstring[i]),
        }

def test_verify_es256_enveloping(
        status: BitstringStatusListIssuer, 
        es256_enveloping_signer: EnvelopingTokenSigner, 
        es256_enveloping_verifier: EnvelopingTokenVerifier,
):
    encoded_jwt = status.sign_jwt_enveloping(
        signer=es256_enveloping_signer,
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

    verifier = BitstringStatusListVerifier.from_jwt(
        token=encoded_jwt,
        credential_status=credential_status,
        verifier=es256_enveloping_verifier,
    ) 

    for i in range(status.status_list.size):
        assert verifier.get_status(i) == {
            "status": status[i],
            "valid": not bool(status[i])
        }

def test_verify_es256_embedding(
        status: BitstringStatusListIssuer, 
        es256_embedding_signer: EmbeddingTokenSigner, 
        es256_embedding_verifier: EmbeddingTokenVerifier,
):
    encoded_jwt = status.sign_jwt_embedding(
        signer=es256_embedding_signer,
        status_purpose="revocation",
    )

    credential_status = {
        "id": "https://example.com/credentials/status/3#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "0",
        "statusListCredential": "https://example.com/credentials/status/3"
    }

    verifier = BitstringStatusListVerifier.from_jwt(
        token=encoded_jwt,
        credential_status=credential_status,
        verifier=es256_embedding_verifier,
    )

    for i in range(status.status_list.size):
        assert verifier.get_status(i) == {
            "status": status[i],
            "valid": not bool(status[i])
        }