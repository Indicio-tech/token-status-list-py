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

