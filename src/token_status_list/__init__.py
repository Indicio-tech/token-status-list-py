"""Token Status List.

Python implementation of Token Status List.

This implementation is based on draft 2, found here:
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-02
"""

import base64
import json
from time import time
from typing import Literal, Optional, Union
import zlib


def b64url_decode(value: bytes) -> bytes:
    """Return the base64 url encoded value, without padding."""
    padding_needed = 4 - (len(value) % 4)
    if padding_needed != 4:
        value += b"=" * padding_needed

    return base64.urlsafe_b64decode(value)


def b64url_encode(value: bytes) -> bytes:
    """Return the decoded base64 url encoded value, without padding."""
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def dict_to_b64(value: dict) -> bytes:
    """Transform a dictionary into base64url encoded json dump of dictionary."""
    return b64url_encode(json.dumps(value, separators=(",", ":")).encode())


VALID = 0x00
INVALID = 0x01
SUSPENDED = 0x02

Bits = Union[Literal[1, 2, 4, 8], int]
StatusTypes = Union[Literal[0x00, 0x01, 0x02], int]


class TokenStatusList:
    """Token Status List."""

    SHIFT_BY = {1: 3, 2: 2, 4: 1, 8: 0}
    # Number of elements that fit in a byte for a number of bits
    PER_BYTE = {1: 8, 2: 4, 4: 2, 8: 1}
    MASK = {1: 0b1, 2: 0b11, 4: 0b1111, 8: 0b11111111}
    MAX = {1: 1, 2: 3, 4: 15, 8: 255}

    def __init__(
        self,
        bits: Bits,
        lst: bytes,
    ):
        """Initialize the list."""
        if bits not in (1, 2, 4, 8):
            raise ValueError("Invalid bits value, must be one of: 1, 2, 4, 8")

        self.bits = bits
        self.per_byte = self.PER_BYTE[bits]
        self.shift = self.SHIFT_BY[bits]
        self.mask = self.MASK[bits]
        self.max = self.MAX[bits]

        # len * indexes per byte
        self.size = len(lst) << self.shift
        self.lst = bytearray(lst)

    @classmethod
    def of_size(cls, bits: Bits, size: int) -> "TokenStatusList":
        """Create empty list of a given size."""
        per_byte = cls.PER_BYTE[bits]
        if size < 1:
            raise ValueError("size must be greater than 1")
        # size mod per_byte
        if size & (per_byte - 1) != 0:
            raise ValueError(f"size must be multiple of {per_byte}")

        length = size >> cls.SHIFT_BY[bits]
        return cls(bits, bytearray(length))

    @classmethod
    def with_at_least(cls, bits: Bits, size: int):
        """Create an empty list large enough to accommodate at least the given size."""
        # Determine minimum number of bytes to fit size
        # This is essentially a fast ceil(n / 2^x)
        length = (size + cls.PER_BYTE[bits] - 1) >> cls.SHIFT_BY[bits]
        return cls(bits, bytearray(length))

    def __getitem__(self, index: int):
        """Retrieve the status of an index."""
        return self.get(index)

    def __setitem__(self, index: int, status: StatusTypes):
        """Set the status of an index."""
        return self.set(index, status)

    def get(self, index: int):
        """Retrieve the status of an index."""
        # index / indexes per byte
        byte_idx = index >> self.shift
        # index mod indexes per byte * bits
        # Determines the number of shifts to move relevant bits all the way right
        bit_idx = (index & (self.per_byte - 1)) * self.bits
        # Shift relevant bits all the way right and mask out irrelevant bits
        return self.mask & (self.lst[byte_idx] >> bit_idx)

    def set(self, index: int, status: StatusTypes):
        """Set the status of an index."""
        if status > self.max:
            raise ValueError(f"status {status} too large for list with bits {self.bits}")
        if index >= self.size:
            raise ValueError("Invalid index; out of range")

        # index / indexes per byte
        byte_idx = index >> self.shift
        # index mod indexes per byte * bits
        # Determines the number of shifts to move relevant bits all the way right
        bit_idx = (index & (self.per_byte - 1)) * self.bits
        byte = self.lst[byte_idx]
        # Shift relevant bits all the way right and mask out irrelevant bits
        current = self.mask & (byte >> bit_idx)
        if current == 0x01 and status != 0x01:
            raise ValueError("Cannot change status of index previously set to invalid")

        # Shift status to relevant position
        status <<= bit_idx
        # Create mask to clear bits getting reset
        # (0 where the bits will be, 1 everywhere else)
        clear_mask = ~(self.mask << bit_idx)
        # Reset bits to zero
        byte &= clear_mask
        # Set status bits
        self.lst[byte_idx] = byte | status

    def compressed(self) -> bytes:
        """Return compressed list."""
        return zlib.compress(self.lst, level=9)

    def serialize(self) -> dict:
        """Return json serializable representation of status list."""
        return {"bits": self.bits, "lst": b64url_encode(self.compressed()).decode()}

    @classmethod
    def deserialize(cls, value: dict) -> "TokenStatusList":
        """Parse status list from dictionary."""
        bits = value.get("bits")
        if not bits:
            raise ValueError("bits missing from status list dictionary")

        if not isinstance(bits, int):
            raise TypeError("bits must be int")

        lst = value.get("lst")
        if not lst:
            raise ValueError("lst missing from status list dictionary")

        if not isinstance(lst, str):
            raise TypeError("lst must be str")

        parsed_lst = zlib.decompress(b64url_decode(lst.encode()))
        return cls(bits, parsed_lst)

    def sign_payload(
        self,
        *,
        alg: str,
        kid: str,
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        ttl: Optional[int] = None,
    ) -> bytes:
        """Create a Status List Token payload for signing.

        Signing is NOT performed by this function; only the payload to the signature is
        prepared. The caller is responsible for producing a signature.

        Args:
            alg: REQUIRED. The algorithm to be used to sign the payload.

            kid: REQUIRED. The kid used to sign the payload.

            iss: REQUIRED when also present in the Referenced Token. The iss (issuer)
                claim MUST specify a unique string identifier for the entity that issued
                the Status List Token. In the absence of an application profile specifying
                otherwise, compliant applications MUST compare issuer values using the
                Simple String Comparison method defined in Section 6.2.1 of [RFC3986].
                The value MUST be equal to that of the iss claim contained within the
                Referenced Token.

            sub: REQUIRED. The sub (subject) claim MUST specify a unique string identifier
                for the Status List Token. The value MUST be equal to that of the uri
                claim contained in the status_list claim of the Referenced Token.

            iat: REQUIRED. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the
                maximum amount of time, in seconds, that the Status List Token can be
                cached by a consumer before a fresh copy SHOULD be retrieved. The value
                of the claim MUST be a positive number.
        """
        headers = {
            "typ": "statuslist+jwt",
            "alg": alg,
            "kid": kid,
        }
        payload = {
            "iss": iss,
            "sub": sub,
            "iat": iat or int(time()),
            "status_list": self.serialize(),
        }
        if exp is not None:
            payload["exp"] = exp

        if ttl is not None:
            payload["ttl"] = ttl

        enc_headers = dict_to_b64(headers).decode()
        enc_payload = dict_to_b64(payload).decode()
        return f"{enc_headers}.{enc_payload}".encode()

    def signed_token(self, signed_payload: bytes, signature: bytes) -> str:
        """Finish creating a signed token.

        Args:
            signed_payload: The value returned from `sign_payload`.
            signature: The signature over the signed_payload in bytes.

        Returns:
            Finished Status List Token.
        """
        return f"{signed_payload.decode()}.{b64url_encode(signature)}"
