"""Token Status List.

Python implementation of Token Status List.

This implementation is based on draft 2, found here:
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-02
"""

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
Bit = Literal[1]
Crumb = Literal[2]
Nibble = Literal[4]
Byte = Literal[8]
StatusTypes = Union[Literal[0x00, 0x01, 0x02], int]


N = TypeVar("N", bound=Bits)


class BitArray(Generic[N]):
    """Variable size bit array."""

    SHIFT_BY = {1: 3, 2: 2, 4: 1, 8: 0}
    # Number of elements that fit in a byte for a number of bits
    PER_BYTE = {1: 8, 2: 4, 4: 2, 8: 1}
    MASK = {1: 0b1, 2: 0b11, 4: 0b1111, 8: 0b11111111}
    MAX = {1: 1, 2: 3, 4: 15, 8: 255}

    def __init__(
        self,
        bits: N,
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
    def of_size(cls, bits: Bits, size: int) -> "BitArray":
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
        if isinstance(index, slice):
            raise ValueError("Slices are not supported on BitArray")

        return self.get(index)

    def __setitem__(self, index: int, status: StatusTypes):
        """Set the status of an index."""
        return self.set(index, status)

    def __len__(self):
        """Return size of array."""
        return self.size

    def get(self, index: int):
        """Retrieve the status of an index."""
        if index >= self.size:
            raise IndexError("Index is out of bounds")

        if index < 0:
            raise IndexError("Index is out of bounds")

        # index / indexes per byte
        byte_idx = index >> self.shift
        # index mod indexes per byte * bits
        # Determines the number of shifts to move relevant bits all the way right
        bit_idx = (index & (self.per_byte - 1)) * self.bits
        # Shift relevant bits all the way right and mask out irrelevant bits
        return self.mask & (self.lst[byte_idx] >> bit_idx)

    def set(self, index: int, status: int):
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

    def to_b64(self) -> str:
        """Return list as compressed b64url encoded str."""
        return b64url_encode(self.compressed()).decode()

    @classmethod
    def from_b64(cls, bits: N, value: str) -> "BitArray":
        """Return list from compressed b64url encoded str."""
        return cls(bits, zlib.decompress(b64url_decode(value.encode())))

    def dump(self) -> dict:
        """Return json serializable representation of BitArray."""
        return {"bits": self.bits, "lst": self.to_b64()}

    @classmethod
    def load(cls, value: dict) -> "BitArray":
        """Deserialize dict into BitArray."""
        bits = value.get("bits")
        if not bits:
            raise ValueError("bits missing from issuer status list dictionary")

        if not isinstance(bits, int):
            raise TypeError("bits must be int")

        if bits not in (1, 2, 4, 8):
            raise ValueError("bits must be 1, 2, 4, or 8")

        lst = value.get("lst")
        if not lst:
            raise ValueError("status_list missing from status list dictionary")

        if not isinstance(lst, str):
            raise TypeError("status_list must be str")

        return cls.from_b64(cast(N, bits), lst)


class NoMoreIndices(Exception):
    """Raised when no more indices are available."""


class IndexAllocator(Protocol):
    """Protocol defining interface for tracking allocated indices."""

    def take(self) -> int:
        """Return next index and mark as allocated."""
        ...

    def take_n(self, n: int) -> List[int]:
        """Return next n indices and mark as allocated."""
        ...

    def dump(self) -> dict:
        """Return serializable representation of allocated indices and metadata."""
        ...

    @classmethod
    def load(cls, value: dict) -> "IndexAllocator":
        """Deseiralize a representation of allocated indices and metadata."""
        ...


class LinearIndexAllocator(IndexAllocator):
    """Linearly allocate indices."""

    def __init__(self, size: int, start: int = 0):
        """Initialize the allocator."""
        self.size = size
        self.next = start

    def take(self) -> int:
        """Return next index and mark as allocated."""
        if self.next >= self.size:
            raise NoMoreIndices("All indices are allocated")

        allocated = self.next
        self.next += 1
        return allocated

    def take_n(self, n: int) -> List[int]:
        """Return next n indices and mark as allocated.

        This may return fewer than n indices if the list is nearly consumed.
        """
        if self.next >= self.size:
            raise NoMoreIndices("All indices are allocated")

        if self.next + n >= self.size:
            n = self.size - self.next
        allocated = list(range(self.next, self.next + n))
        self.next += n
        return allocated

    def dump(self) -> dict:
        """Return serializable representation of allocated indices and metadata."""
        return {
            "type": "linear",
            "next": self.next,
            "size": self.size,
        }

    @classmethod
    def load(cls, value: dict) -> "LinearIndexAllocator":
        """Deseiralize a representation of allocated indices and metadata."""
        typ = value.get("type")
        if typ != "linear":
            raise ValueError(f"type incorrect for {cls.__name__}")

        next = value.get("next")
        if not isinstance(next, int):
            raise TypeError(f"Invalid type for next: {type(next)}")

        size = value.get("size")
        if not isinstance(size, int):
            raise TypeError(f"Invalid type for size: {type(size)}")

        return cls(size, next)


class RandomIndexAllocator(IndexAllocator):
    """Randomly allocate indices."""

    def __init__(self, allocated: BitArray[Bit], num_allocated: Optional[int] = None):
        """Initialize allocator."""
        self.allocated = allocated
        if num_allocated is not None:
            self.num_allocated = num_allocated
        else:
            self.num_allocated = 0
            for chunk in allocated.lst:
                self.num_allocated += chunk.bit_count()

    def linear_scan(self, start: int, stop: int, select: Callable[[int], bool]):
        """Scan a small space and return all indices matching condition."""
        return [i for i in range(start, stop) if select(i)]

    def scan_and_rand(self):
        """Linear scan and random shuffle and select."""
        byte_idx = choice(
            self.linear_scan(
                0, len(self.allocated.lst), lambda i: self.allocated.lst[i] < 255
            )
        )
        start = byte_idx << 3
        end = start + 8
        index = choice(self.linear_scan(start, end, lambda i: self.allocated[i] == 0))
        self.num_allocated += 1
        self.allocated[index] = 1
        return index

    def scan_and_rand_n(self, n: int):
        """Take n."""
        available_bytes = self.linear_scan(
            0, len(self.allocated.lst), lambda i: self.allocated.lst[i] < 255
        )
        available_indices = [
            index
            for byte_idx in available_bytes
            for index in self.linear_scan(
                byte_idx << 3, (byte_idx << 3) + 8, lambda i: self.allocated[i] == 0
            )
        ]
        return sample(available_indices, n)

    def _rand_settle(self, max: int, settled: Callable[[int], bool]):
        """Randomly select a point and 'roll down hill' until settled condition met."""
        direction = choice((-1, 1))
        index = randbelow(max)
        start = index
        count = 0
        while True:
            count += 1
            if settled(index):
                return index
            index += direction
            if index < 0 or index >= max:
                index = start
                direction = -direction

    def rand_and_settle(self):
        """Use rand_settle to randomly select an index."""
        byte_idx = self._rand_settle(
            len(self.allocated.lst), lambda index: self.allocated.lst[index] < 255
        )
        start = byte_idx << 3
        end = start + 8
        index = choice(self.linear_scan(start, end, lambda i: self.allocated[i] == 0))
        self.allocated[index] = 1
        self.num_allocated += 1
        return index

    def rand_and_settle_n(self, n: int):
        """Take n."""
        return [self.rand_and_settle() for _ in range(n)]

    def take(self) -> int:
        """Return next index and mark as allocated."""
        remaining = self.num_allocated - self.allocated.size
        if remaining == 0:
            raise NoMoreIndices("All Indices are allocated.")

        return self.rand_and_settle()

    def take_n(self, n: int) -> List[int]:
        """Return next n indices and mark as allocated.

        This may return fewer than n indices if n is greater than the number of
        indices remaining.
        """
        remaining = self.num_allocated - self.allocated.size
        if remaining == 0:
            raise NoMoreIndices("All Indices are allocated.")

        if self.num_allocated + n >= self.allocated.size:
            n = self.allocated.size - self.num_allocated

        if n / remaining > 0.4:
            return self.scan_and_rand_n(n)

        return self.rand_and_settle_n(n)

    def dump(self) -> dict:
        """Return serializable representation of allocated indices and metadata."""
        return {
            "type": "random",
            "allocated": self.allocated.to_b64(),
            "num_allocated": self.num_allocated,
        }

    @classmethod
    def load(cls, value: dict) -> "IndexAllocator":
        """Deseiralize a representation of allocated indices and metadata."""
        typ = value.get("type")
        if typ != "random":
            raise ValueError(f"type incorrect for {cls.__name__}")

        allocated = value.get("allocated")
        if not isinstance(allocated, str):
            raise TypeError(f"Invalid type for next: {type(allocated)}")

        num_allocated = value.get("num_allocated")
        if not isinstance(num_allocated, int):
            raise TypeError(f"Invalid type for num_allocated: {type(num_allocated)}")

        return cls(BitArray.from_b64(1, allocated), num_allocated)


class TokenSigner(Protocol):
    """Protocol defining the signing callable."""

    def __call__(self, payload: bytes) -> bytes:
        """Sign the payload returning bytes of the signature."""
        ...


# COSE Headers
ALG = 1
KID = 4
TYP = 16  # TBD

# CWT Claims
ISS = 1
SUB = 2
AUD = 3
EXP = 4
NBF = 5
IAT = 6
CTI = 7

# Status List Claims
STATUS_LIST = 65534
KNOWN_ALGS_TO_CWT_ALG = {
    "ES256": -7,
    "ES384": -35,
    "ES512": -36,
    "EdDSA": -8,
}
CWTKnownAlgs = Literal["ES256", "ES384", "ES512", "EdDSA"]


class IssuerStatusList(Generic[N]):
    """Issuer Status List."""

    def __init__(
        self,
        status_list: BitArray[N],
        allocator: IndexAllocator,
    ):
        """Initialize issuer status list."""
        self.allocator = allocator
        self.status_list = status_list

    def __getitem__(self, index: int):
        """Retrieve the status of an index."""
        return self.status_list.get(index)

    def __setitem__(self, index: int, status: StatusTypes):
        """Set the status of an index."""
        current = self.status_list.get(index)
        if current == 0x01 and status != 0x01:
            raise ValueError("Cannot change status of index previously set to invalid")

        return self.status_list.set(index, status)

    def __len__(self):
        """Return size of array."""
        return len(self.status_list.lst)

    def take(self) -> int:
        """Return the next index to use."""
        return self.allocator.take()

    def take_n(self, n: int) -> List[int]:
        """Return the next n indices to use."""
        return self.allocator.take_n(n)

    def dump(self) -> dict:
        """Return serializable representation of issuer status list.

        This is an internal representation of the list, including the index selection
        strategy and the list of taken indices.
        """
        return {
            "allocator": self.allocator.dump(),
            "status_list": self.status_list.dump(),
        }

    @classmethod
    def load(cls, value: dict) -> "IssuerStatusList":
        """Parse issuer status list from dictionary."""
        allocator = value.get("allocator")
        if not allocator:
            raise ValueError("allocator missing from issuer status list dictionary")

        if not isinstance(allocator, dict):
            raise TypeError("allocator must be dict")

        if allocator.get("type") == "linear":
            allocator = LinearIndexAllocator.load(allocator)
        elif allocator.get("type") == "random":
            allocator = RandomIndexAllocator.load(allocator)
        else:
            raise ValueError(f"Invalid allocator: {allocator}")

        status_list = value.get("status_list")
        if not status_list:
            raise ValueError("status_list missing from status list dictionary")

        if not isinstance(status_list, dict):
            raise TypeError("status_list must be dict")

        parsed_status_list = BitArray.load(status_list)
        return cls(parsed_status_list, allocator)

    @classmethod
    def new(cls, bits: Bits, size: int, strategy: Literal["linear", "random"] = "random"):
        """Return a new IssuerStatusList."""
        if strategy == "linear":
            allocator = LinearIndexAllocator(size)
        elif strategy == "random":
            allocator = RandomIndexAllocator(
                BitArray.with_at_least(1, size), num_allocated=0
            )
        else:
            raise ValueError(f"Invalid strategy: {strategy}")

        status_list = BitArray.with_at_least(bits, size)
        return cls(status_list, allocator)

    def sign_jwt_payload(
        self,
        *,
        alg: str,
        kid: str,
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        ttl: Optional[int] = None,
        **additional_claims: Any,
    ) -> bytes:
        """Create payload of Status List Token in JWT format for signing.

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

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the
                maximum amount of time, in seconds, that the Status List Token can be
                cached by a consumer before a fresh copy SHOULD be retrieved. The value
                of the claim MUST be a positive number.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            JWT payload ready for signing.
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
            "status_list": self.status_list.dump(),
            **additional_claims,
        }
        if exp is not None:
            payload["exp"] = exp

        if ttl is not None:
            payload["ttl"] = ttl

        enc_headers = dict_to_b64(headers).decode()
        enc_payload = dict_to_b64(payload).decode()
        return f"{enc_headers}.{enc_payload}".encode()

    def signed_jwt_token(self, signed_payload: bytes, signature: bytes) -> str:
        """Finish creating a signed token.

        Args:
            signed_payload: The value returned from `sign_payload`.
            signature: The signature over the signed_payload in bytes.

        Returns:
            Finished Status List Token.
        """
        return f"{signed_payload.decode()}.{b64url_encode(signature)}"

    def sign_jwt(
        self,
        signer: TokenSigner,
        *,
        alg: str,
        kid: str,
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        ttl: Optional[int] = None,
        **additional_claims: Any,
    ) -> str:
        """Sign status list to produce a token.

        Args:
            signer: REQUIRED. A callable that returns a signature over the payload.

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

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the
                maximum amount of time, in seconds, that the Status List Token can be
                cached by a consumer before a fresh copy SHOULD be retrieved. The value
                of the claim MUST be a positive number.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            Signed JWT of Status List.
        """
        payload = self.sign_jwt_payload(
            alg=alg,
            kid=kid,
            iss=iss,
            sub=sub,
            iat=iat,
            exp=exp,
            ttl=ttl,
            **additional_claims,
        )
        signature = signer(payload)
        return self.signed_jwt_token(payload, signature)

    def sign_cwt_payload(
        self,
        *,
        alg: Union[CWTKnownAlgs, str],
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        **additional_claims: Any,
    ) -> Tuple[bytes, bytes]:
        """Prepare a CWT Format payload of the status list for signing.

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

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            Tuple of encoded_protected_headers and encoded_payload
        """
        try:
            import cbor2
        except ImportError as err:
            raise ImportError("cbor extra required to use this function") from err

        cwt_alg = KNOWN_ALGS_TO_CWT_ALG.get(alg)
        if not alg:
            raise ValueError(f"Unknown alg {alg}")

        protected = {ALG: cwt_alg, TYP: "statuslist+cwt"}
        payload = {
            SUB: sub,
            ISS: iss,
            IAT: iat or int(time()),
            **({EXP: exp} if exp else {}),
            STATUS_LIST: cbor2.dumps(
                {"bits": self.status_list.bits, "lst": self.status_list.compressed()}
            ),
            **additional_claims,
        }

        return cbor2.dumps(protected), cbor2.dumps(payload)

    def signed_cwt_token(
        self,
        kid: str,
        encoded_protected_headers: bytes,
        encoded_payload: bytes,
        signature: bytes,
    ) -> bytes:
        """Return a CWT its parts."""
        try:
            import cbor2
        except ImportError as err:
            raise ImportError("cbor extra required to use this function") from err

        unprotected = {KID: kid}
        cose_sign1 = [encoded_protected_headers, unprotected, encoded_payload, signature]
        tagged = cbor2.CBORTag(18, cose_sign1)
        return cbor2.dumps(tagged)

    def sign_cwt(
        self,
        signer: TokenSigner,
        *,
        alg: str,
        kid: Any,
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        **additional_claims: Any,
    ) -> bytes:
        """Sign status list to produce a CWT token.

        Args:
            signer: REQUIRED. A callable that returns a signature over the payload.

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

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            Signed JWT of Status List.
        """
        headers, payload = self.sign_cwt_payload(
            alg=alg, iss=iss, sub=sub, iat=iat, exp=exp, **additional_claims
        )
        signature = signer(headers + payload)
        token = self.signed_cwt_token(kid, headers, payload, signature)
        return token
