import json
from time import time
from typing import (
    Literal,
    Optional,
    Protocol,
)

from aiohttp import ClientSession

from bit_array import *
from token_status_list.issuer import ALG, KID, TYP, ISS, SUB, AUD, EXP, NBF, IAT, CTI, STATUS_LIST, TTL, STATUS

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
        encoding: Literal["CWT", "JWT"],
        status_list_uri: str,

        payload: dict,
        bit_array: BitArray,

        headers: Optional[dict] = None,
        protected_headers: Optional[dict] = None,
        unprotected_headers: Optional[dict] = None,
    ):
        self.encoding = encoding
        self.status_list_uri = status_list_uri

        self.headers = headers
        self.protected_headers = protected_headers
        self.unprotected_headers = unprotected_headers

        if headers is None and (protected_headers is None or unprotected_headers is None):
            raise ValueError("Headers must be included.")

        self.payload = payload
        self._bit_array = bit_array

    @classmethod
    async def retrieve_list(
        cls, 
        status_list_uri: str,
        verifier: TokenVerifier,
        encoding: Literal["JWT", "CWT"] = "JWT",
        headers: dict | None = None,
    ) -> "TokenStatusListVerifier":
        """ 
        Establish connection, parse and verify response, and create instance of 
        TokenStatusListVerifier to access it.

        Args:
            status_list_uri: REQUIRED. The uri where the status list can be accessed via HTTP request.

            verifier: REQUIRED. A callable that verifies the signature of a payload, equivalent to 
            signer in sign_jwt() in issuer.py.

            encoding: OPTIONAL. Either JWT or CWT. Default is JWT.

            headers: OPTIONAL. Additional headers for the HTTP request that is sent to status_list_uri.

        Returns:
            An instance of TokenStatusListVerifier which has been verified for correctness and 
            integrity.
        """

        headers = headers or {}
        headers.update({"Accept": f"application/statuslist+{encoding.lower()}"})

        async with ClientSession() as session:
            async with session.get(status_list_uri, headers=headers) as resp:
                # Quick method to raise exception on status outside of 200 range
                # TODO: consider using a more semantically rich exception
                resp.raise_for_status()
                token = await resp.read()

        if encoding == "JWT":
            return cls.from_jwt(token, status_list_uri, verifier)
        if encoding == "CWT":
            return cls.from_cwt(token, status_list_uri, verifier)

    @classmethod
    def from_jwt(
        cls, 
        token: bytes | str, 
        status_list_uri: str,
        verifier: TokenVerifier,
    ) -> "TokenStatusListVerifier":
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will assign the headers and payload fields in the class if the format is valid and the 
        signature is correct, and raise an exception if not.

        Args:
            token: REQUIRED. A base64-encoded status_list response, acquired (eg.) from 
            retrieve_list().

            status_list_uri: REQUIRED. The uri used to access the status list.

            verifier: REQUIRED. A callable that verifies the signature of a payload, equivalent to 
            signer in sign_jwt() in issuer.py.
        
        Returns:
            An instance of TokenStatusListVerifier with the relevant fields (headers, payload) 
            filled out.
        """
        
        # Check that message is in valid JWT format 
        if isinstance(token, str):
            token = token.encode()

        if not token.startswith(b"ey"):
            raise ValueError("JWT requested but token is not a JWT")
        
        headers_bytes, payload_bytes, signature = token.split(b".")
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
        if (payload.get("status_list") is None) or (payload.get("sub") is None) or (payload.get("iat") is None):
            raise ValueError(f"Incorrect format: expected fields status_list, sub, and iat in \
                             payload, but got {payload} instead.")
        
        status_list = payload["status_list"]
        if (status_list.get("bits") is None) or (status_list.get("lst") is None):
            raise ValueError(f"Incorrect format: expected status_list to have a `bits` and `lst` \
                             field, but got {status_list} instead.")
        
        # Check that token is still valid
        if "exp" in payload.keys() and payload["exp"] < int(time()):
            raise ValueError(f"Token is expired: exp = {payload["exp"]}.")

        # Check issuer uri, if applicable
        if status_list_uri != payload["sub"]:
            raise ValueError(f"Expected URI {status_list_uri} but instead got {payload["sub"]}")

        return cls(
            encoding="JWT",
            status_list_uri=status_list_uri,
            headers=headers,
            payload=payload,
            bit_array=BitArray.load(payload["status_list"]),
        )

    @classmethod
    def from_cwt(
            cls,
            token: bytes,
            status_list_uri: str,
            verifier: TokenVerifier,
    ) -> "TokenStatusListVerifier":
        """ 
        Takes a status-list response and a verifier, and ensures that the response matches the 
        required format, verifying the signature using verifier.

        Will assign the (un)protected headers and payload fields in the class if the format is valid
        and the signature is correct, and raise an exception if not.

        Args:
            token: REQUIRED. A base64-encoded status_list response, acquired (eg.) from 
            retrieve_list().

            status_list_uri: REQUIRED. The uri used to access the status list.

            verifier: REQUIRED. A callable that verifies the signature of a payload, equivalent to 
            signer in sign_jwt() in issuer.py.

        Returns:
            An instance of TokenStatusListVerifier with the relevant fields (headers, payload) 
            filled out.
        """
        
        try:
            import cbor2
        except ImportError as err:
            raise ImportError("cbor extra required to use this function") from err
        
        # Ensure that the format is correct
        if token.startswith(b"ey"):
            raise ValueError("CWT request but got JWT")
        
        # Extract data
        obj = cbor2.loads(token)
        if obj.tag != 18:
            raise ValueError(f"Incorrect format: expected tag to be 18 but was {obj.tag} instead.")

        encoded_protected_headers, unprotected_headers, encoded_payload, signature = obj.value
        protected_headers: dict = cbor2.loads(encoded_protected_headers)
        payload: dict = cbor2.loads(encoded_payload)

        if payload.get(STATUS_LIST) is None:
            raise ValueError(f"Incorrect format: unable to find status list tag (65533)")

        status_list = cbor2.loads(payload[STATUS_LIST])

        # Check signature
        if not verifier(encoded_protected_headers + encoded_payload, signature):
            raise SignatureError("Invalid signature on payload.")

        # Ensure that the correct format has been received
        if protected_headers.get(TYP) != "statuslist+cwt":
            raise TypeError(f"Incorrect format: expected CWT but instead was {protected_headers.get(TYP)}.")
        
        # Check correctness of format: ensure existence of status_list, sub, and iat fields
        if status_list.get("bits") is None or status_list.get("lst") is None:
            raise ValueError(f"Incorrect format: unble to find bits and lst fields in status list.")

        status_list["lst"] = b64url_encode(status_list["lst"]).decode()  # return status_list in b64 encoding
        payload[STATUS_LIST] = status_list  # put the status_list in human readable form

        if payload.get(SUB) is None or payload.get(IAT) is None:
            raise ValueError(f"Incorrect format: sub (2) and iat (6) fields not found.")
        
        # Check that the token is still valid
        if EXP in payload.keys() and payload[EXP] < int(time()):
            raise ValueError(f"Token is expired: exp = {payload[EXP]}.")
        
        # Check status_list_uri
        if status_list_uri != payload[SUB]:
            raise ValueError(f"Expected URI {status_list_uri} but instead got {payload[SUB]}")

        return cls(
            encoding="CWT",
            status_list_uri=status_list_uri,
            payload=payload,
            protected_headers=protected_headers,
            unprotected_headers=unprotected_headers,
            bit_array=BitArray.load(payload[STATUS_LIST])
        ) 

    def get_status(self, idx: int) -> int:
        """
        Returns the status of an object from the status_list in payload. 
        Requies that the payload has already been checked using jwt_verify or cwt_verify.
        Caches the status list as a BitArray for ease of future reference.

        Args:
            index: REQUIRED. The index of the token's status in the list.
        
        Returns:
            The status of the requested token.
        """
        
        return self._bit_array[idx]


    def serialize_verifier(self) -> dict:
        """
        Utility function: serialize a TokenStatusListVerifier for storing.

        Returns:
            A dictionary with headers and payload, as well as relevant metadata.
        """
        return_dict = {}
        
        return_dict["encoding"] = self.encoding
        return_dict["status_list_uri"] = self.status_list_uri
        return_dict["payload"] = self.payload

        if self.encoding == "JWT":
            return_dict["headers"] = self.headers
        elif self.encoding == "CWT":
            return_dict["protected_headers"] = self.protected_headers
            return_dict["unprotected_headers"] = self.unprotected_headers
        else:
            raise ValueError(f"Invalid encoding: was {self.encoding} but needs to be JWT or CWT")

        return return_dict
    

    @classmethod
    def deserialize_verifier(cls, seralized_verifier: dict) -> "TokenStatusListVerifier":
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

        if seralized_verifier["encoding"] == "JWT":
            return cls(
                encoding="JWT",
                status_list_uri=seralized_verifier["status_list_uri"],
                payload=seralized_verifier["payload"],
                headers=seralized_verifier["headers"],
                bit_array=BitArray.load(seralized_verifier["payload"]["status_list"])
            )
            
        elif seralized_verifier["encoding"]:
            return cls(
                encoding="CWT",
                status_list_uri=seralized_verifier["status_list_uri"],
                payload=seralized_verifier["payload"],
                unprotected_headers=seralized_verifier["unprotected_headers"],
                protected_headers=seralized_verifier["protected_headers"],
                bit_array=BitArray.load(seralized_verifier["payload"]["status_list"]) 
            )

        raise ValueError(f"Invalid encoding: was {seralized_verifier["encoding"]} but needs to be JWT or CWT")
        