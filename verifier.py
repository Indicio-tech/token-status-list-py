import base64
import json
from random import sample
from secrets import choice, randbelow
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

class TokenVerifier(Protocol):
    """Protocol defining the verifying callable."""

    def __call__(self, payload: bytes, signature: bytes) -> bool:
        """Verify the signature of the payload. Returns true if the signature is valid."""
        ...

class SignatureError(Exception):
    """ Raised when signature is invalid. """

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
        Takes a payload and a verifier, and ensures that the payload matches the required format.
        Will return the headers and payload if valid, and raise an exception if not.
        Caller is expected to catch exceptions for correct error-handling.
        """
        # JWT checks are done here implicitly
        headers_bytes, payload_bytes, signature = sl_response.split(b".")
        
        # Verify signature
        verified = verifier(f"{headers_bytes.decode()}.{payload_bytes.decode()}".encode(), b64url_decode(signature))
        if not verified:
            raise SignatureError("Invalid signature on payload.")

        # Extract data
        headers: dict = json.loads(b64url_decode(headers_bytes))
        payload: dict = json.loads(b64url_decode(payload_bytes))

        # Check correctness of format: ensure existence of status_list, sub, and iat fields
        status_list = payload["status_list"]
        _ = status_list["bits"]
        _ = status_list["lst"]

        _ = payload["sub"]
        _ = payload["iat"]
        
        if headers["typ"] != "statuslist+jwt":
            raise TypeError(f"Incorrect format: expected JWT but was {headers["type"]}")
        
        # Check that token is still valid.
        if "exp" in payload.keys() and payload["exp"] < int(time()):
            raise ValueError(f"Token is expired: exp = {payload["exp"]}.")

        if "tll" in payload.keys() and payload["iat"] + payload["ttl"] < int(time()):
            raise ValueError(f"Token is expired: ttl = {payload["ttl"]}.")

        return headers, payload

    @classmethod
    def jwt_get_status(cls, payload: dict, index: int) -> int:
        """
        Returns the status of an object from the status_list in payload. 
        Requies that the payload has already been checked using jwt_verify.
        """

        status_list = BitArray.load(payload["status_list"])
    
        return status_list[index]
