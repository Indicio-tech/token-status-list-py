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
import zlib

import time

import requests as r

from token_status_list import *

class TokenVerifier(Protocol):
    """Protocol defining the verifying callable."""

    def __call__(self, payload: bytes, signature: bytes) -> bool:
        """Verify the signature of the payload. Returns true if the signature is valid."""
        ...

class SignatureError(Exception):
    """ Raised when """

class TokenStatusListVerifier():
    def __init__(
        self,
        issuer_addr: str,
    ):
        self.issuer_addr = issuer_addr

    def establish_connection(self, status_list_format: Literal["jwt", "cwt"]) -> bytes:
        """ Establish connection. Returns base64 encoded response. """
        response = r.get(self.issuer_addr, headers={"Accept": f"application/statuslist+{status_list_format}"})
        assert 200 <= response.status_code < 300, f"Unable to establish connection."
        return response.content

    def jwt_verify(self, sl_response: bytes, verifier: TokenVerifier) -> Tuple[dict, dict]:
        """ 
        Takes a payload and a verifier, and ensures that the payload matches the required format.
        Will return the headers and payload if valid, and raise an exception if not.
        """
        # JWT checks are done here implicitly
        headers_bytes, payload_bytes, signature = sl_response.split(b".")
        
        # Verify signature
        verified = verifier(f"{headers_bytes.decode()}.{payload_bytes.decode()}".encode(), signature)
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
        
        if headers["type"] != "statuslist+jwt":
            raise TypeError(f"Incorrect format: expected JWT but was {headers["type"]}")

        return headers, payload

    def jwt_get_status(self, payload: dict, index: int) -> int:
        """
        Returns the status of an object from the status_list in payload. 
        Requies that the payload has already been checked using jwt_verify.
        """

        status_list = BitArray.load(payload["status_list"])
        return status_list[index]
