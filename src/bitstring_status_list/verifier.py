from typing import (
    Optional,
    Protocol,
)

from aiohttp import ClientSession
import json

from src.bit_array import BitArray, b64url_decode, b64url_encode, dict_to_b64
from src.bitstring_status_list.issuer import MIN_LIST_LENGTH, StatusListLengthError

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

        headers: Optional[dict],
        payload: dict,

        bit_array: BitArray,
    ):
        self.credential_status = credential_status
        if not all(key in credential_status.keys() for key in ["id", "type", "statusPurpose", "statusListIndex", "statusListCredential"]):
            raise StatusVerificationError(f"Invalid credential_status: {credential_status}. \
                                            credential status is expected to have keys: \
                                            [id, type, statusPurpose, statusListIndex, statusListCredential]")

        self.headers = headers
        self.payload = payload

        self._bit_array = bit_array

    @classmethod
    async def retrieve_list(
        cls, 
        credential_status: dict,
        verifier: EnvelopingTokenVerifier | EmbeddingTokenVerifier,
        headers: dict | None = None,
        min_list_length: int = MIN_LIST_LENGTH,
    ) -> "BitstringStatusListVerifier":
        """ 
        Establish connection, parse and verify response, and create instance of 
        BitstringStatusListVerifier to access it.

        Args:
            credential_status: REQUIRED. The credentialStatus field of a verifiable credential as
            specified in S. 2.1.

            verifier: REQUIRED. A callable that verifies the signature of a payload, equivalent to 
            signer in sign_jwt() in issuer.py.

            headers: OPTIONAL. Additional headers for the HTTP request.

            min_list_length: OPTIONAL. The minimum list length, recommended to be 131,072 (see S. 6.1)
        Returns:
            An instance of BitstringStatusListVerifier which has been verified for correctness and 
            integrity.
        """

        headers = headers or {}

        async with ClientSession() as session:
            async with session.get(credential_status["statusListCredential"], headers=headers) as resp:
                if not 200 <= resp.status < 300:
                    raise StatusRetrievalError(f"Unable to retrieve token at {credential_status["statusListCredential"]}")
                
                token = await resp.read()

        return cls.from_jwt(token, credential_status, verifier, min_list_length)

    @classmethod
    def from_jwt(
        cls, 
        token: bytes | str, 
        credential_status: dict,
        verifier: EnvelopingTokenVerifier | EmbeddingTokenVerifier,
        min_list_length: int = MIN_LIST_LENGTH,
    ) -> "BitstringStatusListVerifier":
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will assign the headers and payload fields in the class if the format is valid and the 
        signature is correct, and raise an exception if not.

        Args:
            token: REQUIRED. A base64-encoded status_list response, acquired (eg.) from 
            establish_connection().

            credential_status: REQUIRED. The credentialStatus field of a verifiable credential as
            specified in S. 2.1.

            verifier: REQUIRED. A callable that verifies the signature of a payload. Must match
            the proof format of the token (embedded or enveloping)

            min_list_length: OPTIONAL. The minimum list length, recommended to be 131,072 (see S. 6.1)
        """
        # Check that message is in valid JWT format 
        if isinstance(token, str):
            token = token.encode()

        if not token.startswith(b"ey"):
            raise ValueError("JWT requested but token is not a JWT") 

        headers = None
        if b"." in token:
            # Enveloping proof

            # Check that message is in valid JWT format 
            headers_bytes, payload_bytes, signature = token.split(b".", maxsplit=3)
            assert headers_bytes and payload_bytes and signature

            # Verify signature. verifier must be of type EnvelopingTokenVerifier
            if not verifier(headers_bytes + b"." + payload_bytes, signature):
                raise StatusVerificationError("Invalid signature on payload.")
            
            # Extract data
            headers = json.loads(b64url_decode(headers_bytes))
            payload = json.loads(b64url_decode(payload_bytes))
        else:
            # Embedding proof

            # Extract data
            payload = json.loads(b64url_decode(token))
            
            # Verify signature
            unsigned_payload = {key: payload[key] for key in payload if key != "proof"}
            if not verifier(dict_to_b64(unsigned_payload), payload["proof"]):
                raise StatusVerificationError("Invalid signature on payload")

        # Check values of status list against provided credential
        credential_subject = payload["credentialSubject"]
        if credential_subject["statusPurpose"] != credential_status["statusPurpose"]:
            raise StatusVerificationError(
                f"statusPurpose in credential is {credential_status["statusPurpose"]}, while \
                statusPurpose in status list is {credential_subject["statusPurpose"]}"
            )
        
        # If statusPurpose = message, ensure that a statusMessage list exists in the credential
        bits = credential_status.get("statusSize")
        if bits is not None and bits > 1 and credential_status.get("statusMessage") is None:
            raise StatusVerificationError("For statusSize > 1, a message must exist.")
        
        if credential_status["statusPurpose"] == "message" and credential_status.get("statusMessage") is None:
            raise StatusVerificationError("If statusPurpose is `message`, a statusMessage field must \
                                          be included which provides the message associated with each bit.")
        
        # Cache returned status list as BitArray
        bit_array = BitArray.from_b64(1 if bits is None else bits, credential_subject["encodedList"])
        if bit_array.size < min_list_length:
            raise StatusListLengthError(f"Bitstring status list must be at least {min_list_length} \
                                        bits long, but was {bit_array.size} bits long instead.")
        
        return cls(
            credential_status=credential_status,
            headers=headers,
            payload=payload,
            bit_array=bit_array,
        )
        
    def get_status(self, idx: Optional[int] = None):
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

    def serialize_verifier(self) -> dict:
        """
        Utility function: serialize a BitstringStatusListVerifier for storing.

        Returns:
            A dictionary with headers and payload, as well as relevant metadata.
        """

        return {
            "credential_status": self.credential_status,
            **({"headers": self.headers} if self.headers else {}),
            "payload": self.payload,
        }
    

    @classmethod
    def deserialize_verifier(cls, seralized_verifier: dict) -> "BitstringStatusListVerifier":
        """
        Utility function: deserializes a seralized TokenStatusListVerifier, which must be in the
        same format as the return type of seralize_verifier. Returns a TokenStatusListVerifier type
        with fields populated and the status list stored as a BitArray.

        Args:
            serialized_verifier: REQUIRED. Serialized verifier type which must be in the same format 
            as TokenStatusListVerifier.serialize_verifier.

        Returns:
            A TokenStatusListVerifier instance with relevant fields populated.
        """

        bits = seralized_verifier["credential_status"].get("statusSize")
        return cls(
            credential_status=seralized_verifier["credential_status"],
            headers=seralized_verifier.get("headers"),
            payload=seralized_verifier["payload"],
            bit_array=BitArray.from_b64(
                bits=1 if bits is None else bits,
                value=seralized_verifier["payload"]["credentialSubject"]["encodedList"]
            )
        )
    