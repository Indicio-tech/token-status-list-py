import json
from time import time
from typing import (
    Any,
    Callable,
    Generic,
    List,
    Literal,
    Optional,
    Protocol,
    Tuple,
    TypeVar,
    Union,
    cast,
)

import requests as r

from token_status_list import *
from issuer import ALG, KID, TYP, ISS, SUB, AUD, EXP, NBF, IAT, CTI, STATUS_LIST, TTL

class TokenVerifier(Protocol):
    """Protocol defining the verifying callable."""

    def __call__(self, payload: bytes, signature: bytes) -> bool:
        """Verify the signature of the payload. Returns true if the signature is valid."""
        ...

class SignatureError(Exception):
    """ Raised when signature is invalid. """

CWT_ALG_TO_KNOWN_ALGS = {
    -7: "ES256",
    -35: "ES384",
    -36: "ES512",
    -8: "EdDSA",
}

# COSE Headers
COSE_HEADERS = {
    ALG: "alg",
    KID: "kid",
    TYP: "typ",  # TBD

    # CWT Claims
    ISS: "iss",
    SUB: "sub",
    AUD: "aud",
    EXP: "exp",
    NBF: "nbf",
    IAT: "iat",
    CTI: "cti",

    STATUS_LIST: "status_list",
    65534: "ttl",
}

class TokenStatusListVerifier():
    def __init__(
        self,
    ):
        ...

    @classmethod
    def establish_connection(cls, issuer_addr: str, status_list_format: Literal["jwt", "cwt"]) -> bytes:
        """ Establish connection. Returns base64 encoded response. """
        response = r.get(issuer_addr, headers={"Accept": f"application/statuslist+{status_list_format}"})
        assert 200 <= response.status_code < 300, f"Unable to establish connection."
        return response.content

    @classmethod
    def jwt_verify(cls, sl_response: bytes, verifier: TokenVerifier) -> Tuple[dict, dict]:
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will return the headers and payload if the format is valid and the signature is correct, and 
        raise an exception if not.

        Args:
            sl_response: REQUIRED. A base64-encoded status_list response, acquired (eg.) from 
            establish_connection().

            verifier: REQUIRED. A callable that verifies the signature of a payload, equivalent to 
            signer in sign_jwt() in issuer.py.

        Returns:
            A tuple containing the header and payload of the ST-JWT in Python dictionary form.
    
        """
        # Check that message is in valid JWT format 
        headers_bytes, payload_bytes, signature = sl_response.split(b".")
        assert headers_bytes and payload_bytes and signature
        
        # Verify signature
        if not verifier(headers_bytes + b"." + payload_bytes, b64url_decode(signature)):
            raise SignatureError("Invalid signature on payload.")

        # Extract data
        headers: dict = json.loads(b64url_decode(headers_bytes))
        payload: dict = json.loads(b64url_decode(payload_bytes))

        # Ensure that correct format has been received.
        if headers.get("typ") != "statuslist+jwt":
            raise TypeError(f"Incorrect format: expected JWT but instead was {headers.get("typ")}")
        
        # Check correctness of format: ensure existence of status_list, sub, and iat fields
        status_list = payload["status_list"]
        _ = status_list["bits"]
        _ = status_list["lst"]

        _ = payload["sub"]
        _ = payload["iat"]
        
        # Check that token is still valid
        if "exp" in payload.keys() and payload["exp"] < int(time()):
            raise ValueError(f"Token is expired: exp = {payload["exp"]}.")

        if "tll" in payload.keys() and payload["iat"] + payload["ttl"] < int(time()):
            raise ValueError(f"Token is expired: ttl = {payload["ttl"]}.")

        return headers, payload

    @classmethod
    def cwt_verify(cls, token: bytes, verifier: TokenVerifier) -> Tuple[dict, dict, dict]:
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will return the headers and payload if the format is valid and the signature is correct, and 
        raise an exception if not.

        Args:
            sl_response: REQUIRED. A base64-encoded status_list response, acquired (eg.) from 
            establish_connection().

            verifier: REQUIRED. A callable that verifies the signature of a payload, equivalent to 
            signer in sign_jwt() in issuer.py.

        Returns:
            A tuple containing the protected header, unprotected header, and payload in Python 
            dictionary form.
        """
         
        try:
            import cbor2
        except ImportError as err:
            raise ImportError("cbor extra required to use this function") from err
        
        # Extract data
        obj = cbor2.loads(token)
        assert obj.tag == 18

        encoded_protected_headers, unprotected_headers, encoded_payload, signature = obj.value
        protected_headers: dict = cbor2.loads(encoded_protected_headers)
        payload: dict = cbor2.loads(encoded_payload)

        status_list = cbor2.loads(payload[STATUS_LIST])

        # Check signature
        if not verifier(encoded_protected_headers + encoded_payload, signature):
            raise SignatureError("Invalid signature on payload.")

        # Ensure that the correct format has been received
        if protected_headers.get(TYP) != "statuslist+cwt":
            raise TypeError(f"Incorrect format: expected CWT but instead was {protected_headers.get(TYP)}")
        
        # Check correctness of format: ensure existence of status_list, sub, and iat fields
        _ = status_list["bits"]
        status_list["lst"] = b64url_encode(status_list["lst"]).decode()  # return status_list in b64 encoding
        payload[STATUS_LIST] = status_list  # put the status_list in human readable form

        _ = payload[SUB]
        _ = payload[IAT]
        
        # Check that the token is still valid
        if EXP in payload.keys() and payload[EXP] < int(time()):
            raise ValueError(f"Token is expired: exp = {payload[EXP]}.")
        
        if TTL in payload.keys() and payload[IAT] + int(payload[TTL]) < int(time()):
            raise ValueError(f"Token is expired: ttl = {payload[TTL]}.")

        return protected_headers, unprotected_headers, payload

    @classmethod
    def get_status(cls, status_list: bytes, index: int) -> int:
        """
        Returns the status of an object from the status_list in payload. 
        Requies that the payload has already been checked using jwt_verify or cwt_verify.

        Args:
            payload: REQUIRED. A verified payload returned from jwt_verify or cwt_verify.

            index: REQUIRED. The index of the token's status in the list.
        
        Returns:
            The status of the requested token.
        """

        bit_array = BitArray.load(status_list)
    
        return bit_array[index]
