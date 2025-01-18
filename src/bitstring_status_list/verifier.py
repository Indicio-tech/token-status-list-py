from typing import (
    Literal,
    Optional,
    Protocol,
)

import requests as r

from bit_array import *
from bitstring_status_list.issuer import MIN_LIST_LENGTH, StatusListLengthError

class EnvelopingTokenVerifier(Protocol):
    """Protocol defining the verifying callable for enveloping signatures."""

    def __call__(self, payload: bytes, signature: bytes) -> bool:
        """Verify the signature of the payload. Returns true if the signature is valid."""
        ...

class EmbeddingTokenVerifier(Protocol):
    """Protocol defining the verifying callable for embedding signatures."""

    def __call__(self, payload: bytes, signature: dict) -> bool:
        """Verify the signature of the payload. Returns true if the signature is valid."""
        ...

class StatusRetrievalError(Exception):
    """Raised if dereference of URL fails. See Bitstring Status List Spec S. 3.2"""

class StatusVerificationError(Exception):
    """Raised if proofs fail or if format is invalid. See Bitstring Status List Spec S. 3.2"""

class BitstringStatusListVerifier():
    def __init__(
        self,
        credential_status: dict,

        headers: Optional[dict] = None,
        payload: Optional[dict] = None,

        bit_array: Optional[BitArray] = None,
    ):
        self.credential_status = credential_status
        assert all(key in credential_status.keys() for key in ["id", "type", "statusPurpose", "statusListIndex", "statusListCredential"]),\
            "Invalid credentialStatus"

        self.headers = headers
        self.payload = payload

        self._bit_array = bit_array

    def establish_connection(
        self, 
        status_list_format: Literal["CWT", "JWT"],
    ) -> bytes:
        """ Establish connection. Returns base64 encoded response. """
        issuer_uri = self.credential_status["statusListCredential"]
        try:
            response = r.get(issuer_uri)
        except Exception as e:
            raise StatusRetrievalError(f"Dereference of uri {issuer_uri} failed: {e}.")
        
        if not (200 <= response.status_code < 300):
            raise StatusRetrievalError(f"Response status from {issuer_uri} was {response.status_code}.")

        # When establishing a new connection, clear previous cached values.
        self.headers = None
        self.payload = None
        self._bit_array = None

        return response.content

    def verify_jwt(
            self, 
            sl_response: bytes, 
            verifier: EnvelopingTokenVerifier | EmbeddingTokenVerifier,
            min_list_length: int = MIN_LIST_LENGTH,
        ):
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will assign the headers and payload fields in the class if the format is valid and the 
        signature is correct, and raise an exception if not.

        Args:
            sl_response: REQUIRED. A base64-encoded status_list response, acquired (eg.) from 
            establish_connection().

            verifier: REQUIRED. A callable that verifies the signature of a payload. Must match
            the proof format of the sl_response (embedded or enveloping)

            min_list_length: OPTIONAL. The minimum list length, recommended to be 131,072 (see S. 6.1)
        """
        
        if b"." in sl_response:
            # Enveloping proof

            # Check that message is in valid JWT format 
            headers_bytes, payload_bytes, signature = sl_response.split(b".")
            assert headers_bytes and payload_bytes and signature

            # Verify signature. verifier must be of type EnvelopingTokenVerifier
            if not verifier(headers_bytes + b"." + payload_bytes, b64url_decode(signature)):
                raise StatusVerificationError("Invalid signature on payload.")
            
            # Extract data
            self.headers = json.loads(b64url_decode(headers_bytes))
            self.payload = json.loads(b64url_decode(payload_bytes))
        else:
            # Embedding proof

            # Extract data
            self.payload = json.loads(b64url_decode(sl_response))
            
            # Verify signature
            unsigned_payload = {key: self.payload[key] for key in self.payload if key != "proof"}
            if not verifier(dict_to_b64(unsigned_payload), self.payload["proof"]):
                raise StatusVerificationError("Invalid signature on payload")

        # Check values of status list against provided credential
        credential_subject = self.payload["credentialSubject"]
        if credential_subject["statusPurpose"] != self.credential_status["statusPurpose"]:
            raise StatusVerificationError(
                f"statusPurpose in credential is {self.credential_status["statusPurpose"]}, while \
                statusPurpose in status list is {credential_subject["statusPurpose"]}"
            )
        
        # If statusPurpose = message, ensure that a statusMessage list exists in the credential
        bits = self.credential_status.get("statusSize")
        if bits is not None and bits > 1 and self.credential_status.get("statusMessage") is None:
            raise StatusVerificationError("For statusSize > 1, a message must exist.")
        
        if self.credential_status["statusPurpose"] == "message" and self.credential_status.get("statusMessage") is None:
            raise StatusVerificationError("If statusPurpose is `message`, a statusMessage field must \
                                          be included which provides the message associated with each bit.")
        
        # Cache returned status list as BitArray
        self._bit_array = BitArray.from_b64(1 if bits is None else bits, credential_subject["encodedList"])
        if self._bit_array.size < min_list_length:
            raise StatusListLengthError(f"Bitstring status list must be at least {min_list_length} \
                                        bits long, but was {self._bit_array.size} bits long instead.")
        
    def get_status(self, idx: Optional[int] = None):
        assert self._bit_array is not None, "Before accessing the status, please verify using jwt_verify or cwt_verify"
        if idx is None:
            idx = int(self.credential_status["statusListIndex"])

        status = self._bit_array[idx]
        
        return_dict = {
            "status": status,
            "valid": not bool(status),
        }

        # If purpose == message, extract the relevant message and add it to the return_dict, as 
        # described in S. 3.2 Part 14.
        purpose = self.credential_status.get("statusPurpose")
        if purpose is None or purpose != "message":
            return return_dict
        
        # if purpose == "message"
        try:
            for message in self.credential_status["statusMessage"]:
                if int(message["status"], 16) == status:
                    return_dict["message"] = message["message"]
                    return return_dict
        
        except KeyError as k: 
            raise StatusVerificationError(f"statusMessage is malformed or not present: {k}")
        
        raise StatusVerificationError(f"Status {status} not found in message list: {self.credential_status["statusMessage"]}")
    