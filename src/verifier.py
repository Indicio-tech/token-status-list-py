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

from src.token_status_list import *
from src.issuer import ALG, KID, TYP, ISS, SUB, AUD, EXP, NBF, IAT, CTI, STATUS_LIST, TTL, STATUS

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
        self.issuer_uri: Optional[str] = None

        self.headers: Optional[dict] = None
        self.protected_headers: Optional[dict] = None
        self.unprotected_headers: Optional[dict] = None

        self.payload: Optional[dict] = None

        self.bit_array: Optional[BitArray] = None

    def establish_connection(
        self, 
        status_list_format: Literal["CWT", "JWT"],
        issuer_uri: str,
    ) -> bytes:
        """ Establish connection. Returns base64 encoded response. """
        response = r.get(
            issuer_uri, 
            headers={"Accept": f"application/statuslist+{status_list_format.lower()}"}
        )
        
        # TODO?: Follow links in the 300 range
        assert 200 <= response.status_code < 300, f"Unable to establish connection."
        self.issuer_uri = issuer_uri
        return response.content

    def jwt_verify(self, sl_response: bytes, verifier: TokenVerifier):
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will assign the headers and payload fields in the class if the format is valid and the 
        signature is correct, and raise an exception if not.

        Args:
            sl_response: REQUIRED. A base64-encoded status_list response, acquired (eg.) from 
            establish_connection().

            verifier: REQUIRED. A callable that verifies the signature of a payload, equivalent to 
            signer in sign_jwt() in issuer.py.
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

        # Check issuer uri, if applicable
        if self.issuer_uri is not None and self.issuer_uri != payload["sub"]:
            raise ValueError(f"Expected URI {self.issuer_uri} but instead got {payload["sub"]}")

        self.encoding = "JWT"
        self.headers = headers
        self.payload = payload

    def cwt_verify(self, token: bytes, verifier: TokenVerifier):
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will assign the (un)protected headers and payload fields in the class if the format is valid
        and the signature is correct, and raise an exception if not.

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
        
        # Check issuer uri, if applicable
        if self.issuer_uri is not None and self.issuer_uri != payload[SUB]:
            raise ValueError(f"Expected URI {self.issuer_uri} but instead got {payload[SUB]}")
        
        self.encoding = "CWT"
        self.protected_headers = protected_headers
        self.unprotected_headers = unprotected_headers
        self.payload = payload

    def get_status(self, idx: int) -> int:
        """
        Returns the status of an object from the status_list in payload. 
        Requies that the payload has already been checked using jwt_verify or cwt_verify.

        Args:
            payload: REQUIRED. A verified payload returned from jwt_verify or cwt_verify.

            index: REQUIRED. The index of the token's status in the list.
        
        Returns:
            The status of the requested token.
        """

        assert self.encoding is not None and self.payload is not None,\
            "Before accessing the status, please verify using jwt_verify or cwt_verify"

        if self.bit_array is None:    
            status_list = self.payload["status_list"] if self.encoding == "JWT" else self.payload[STATUS_LIST]
            self.bit_array = BitArray.load(status_list)
        
        return self.bit_array[idx]
