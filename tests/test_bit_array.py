"""Test BitArray."""

import pytest
from secrets import randbelow

from tests import Timer
from src.token_status_list import SUSPENDED, BitArray, VALID, b64url_decode


def test_get_1_bits():
    bits = BitArray(1, b"\xb9\xa3")
    assert bits.size == 16
    assert len(bits.lst) == 2
    assert bits[0] == 1
    assert bits[1] == 0
    assert bits[2] == 0
    assert bits[3] == 1
    assert bits[4] == 1
    assert bits[5] == 1
    assert bits[6] == 0
    assert bits[7] == 1
    assert bits[8] == 1
    assert bits[9] == 1
    assert bits[10] == 0
    assert bits[11] == 0
    assert bits[12] == 0
    assert bits[13] == 1
    assert bits[14] == 0
    assert bits[15] == 1


def test_set_1_bits():
    bits = BitArray.of_size(1, 16)
    assert len(bits.lst) == 2
    bits[0] = 1
    bits[1] = 0
    bits[2] = 0
    bits[3] = 1
    bits[4] = 1
    bits[5] = 1
    bits[6] = 0
    bits[7] = 1
    bits[8] = 1
    bits[9] = 1
    bits[10] = 0
    bits[11] = 0
    bits[12] = 0
    bits[13] = 1
    bits[14] = 0
    bits[15] = 1
    assert bits[0] == 1
    assert bits[1] == 0
    assert bits[2] == 0
    assert bits[3] == 1
    assert bits[4] == 1
    assert bits[5] == 1
    assert bits[6] == 0
    assert bits[7] == 1
    assert bits[8] == 1
    assert bits[9] == 1
    assert bits[10] == 0
    assert bits[11] == 0
    assert bits[12] == 0
    assert bits[13] == 1
    assert bits[14] == 0
    assert bits[15] == 1


def test_get_2_bits():
    bits = BitArray(2, b"\xc9\x44\xf9")
    assert bits.size == 12
    assert len(bits.lst) == 3
    assert bits[0] == 1
    assert bits[1] == 2
    assert bits[2] == 0
    assert bits[3] == 3
    assert bits[4] == 0
    assert bits[5] == 1
    assert bits[6] == 0
    assert bits[7] == 1
    assert bits[8] == 1
    assert bits[9] == 2
    assert bits[10] == 3
    assert bits[11] == 3


def test_set_2_bits():
    bits = BitArray.of_size(2, 12)
    assert len(bits.lst) == 3
    bits[0] = 1
    bits[1] = 2
    bits[2] = 0
    bits[3] = 3
    bits[4] = 0
    bits[5] = 1
    bits[6] = 0
    bits[7] = 1
    bits[8] = 1
    bits[9] = 2
    bits[10] = 3
    bits[11] = 3
    assert bits[0] == 1
    assert bits[1] == 2
    assert bits[2] == 0
    assert bits[3] == 3
    assert bits[4] == 0
    assert bits[5] == 1
    assert bits[6] == 0
    assert bits[7] == 1
    assert bits[8] == 1
    assert bits[9] == 2
    assert bits[10] == 3
    assert bits[11] == 3


def test_get_4_bits():
    bits = BitArray(4, b"\x11\x22\x33\x44")
    assert bits.size == 8
    assert len(bits.lst) == 4
    assert bits[0] == 1
    assert bits[1] == 1
    assert bits[2] == 2
    assert bits[3] == 2
    assert bits[4] == 3
    assert bits[5] == 3
    assert bits[6] == 4
    assert bits[7] == 4


def test_get_8_bits():
    bits = BitArray(8, b"\x01\x02\x03\x04")
    assert bits.size == 4
    assert len(bits.lst) == 4
    assert bits[0] == 1
    assert bits[1] == 2
    assert bits[2] == 3
    assert bits[3] == 4


def test_compression():
    bits = BitArray(1, b"\xb9\xa3")
    compressed = bits.compressed()
    assert compressed == b64url_decode(b"eNrbuRgAAhcBXQ")


@pytest.mark.performance
@pytest.mark.parametrize("bits", (1, 2, 4, 8))
def test_performance(bits: int):
    print()
    print()
    print("Bits:", bits)

    # Create a large BitArray
    size = 1000000  # Number of indices
    bits_list = BitArray.of_size(bits, size)

    # Generate random bitses
    bitses = []
    while len(bitses) < size:
        run = randbelow(10)
        bits = randbelow(2)
        bitses.extend([bits] * run)

    diff = len(bitses) - size
    if diff > 1:
        for _ in range(diff + 1):
            bitses.pop()

    # Test setting values
    with Timer() as timer:
        for i, bits in enumerate(bitses):
            bits_list[i] = bits
    print(f"Time to set {size} indices: {timer.time:.3f} seconds")

    # Test getting values
    with Timer() as timer:
        for i in range(size):
            bits = bits_list[i]
    print(f"Time to get {size} indices: {timer.time:.3f} seconds")

    # Test compression
    with Timer() as timer:
        compressed_data = bits_list.compressed()

    print(f"Time to compress: {timer.time:.3f} seconds")
    print(f"Original length: {len(bits_list.lst)} bytes")
    print(f"Compressed length: {len(compressed_data)} bytes")
    print(f"Compression ratio: {len(compressed_data) / len(bits_list.lst) * 100:.3f}%")


def test_suspend_to_valid():
    bits = BitArray(2, b"\x80")
    assert bits[3] == SUSPENDED
    bits[3] = 0x00
    assert bits[3] == VALID


def test_of_size():
    with pytest.raises(ValueError):
        bits = BitArray.of_size(1, 3)
    with pytest.raises(ValueError):
        bits = BitArray.of_size(2, 21)
    with pytest.raises(ValueError):
        bits = BitArray.of_size(4, 31)

    # Lists with bits 8 can have arbitrary size since there's no byte
    # boundaries to worry about
    bits = BitArray.of_size(8, 31)
    assert len(bits.lst) == 31

    bits = BitArray.of_size(1, 8)
    assert len(bits.lst) == 1
    bits = BitArray.of_size(1, 16)
    assert len(bits.lst) == 2
    bits = BitArray.of_size(1, 24)
    assert len(bits.lst) == 3
    bits = BitArray.of_size(8, 24)
    assert len(bits.lst) == 24


def test_with_at_least():
    bits = BitArray.with_at_least(1, 3)
    assert len(bits.lst) == 1
    bits = BitArray.with_at_least(2, 21)
    assert len(bits.lst) == 6
    bits = BitArray.with_at_least(4, 31)
    assert len(bits.lst) == 16

    bits = BitArray.with_at_least(1, 8)
    assert len(bits.lst) == 1
    bits = BitArray.with_at_least(2, 24)
    assert len(bits.lst) == 6
    bits = BitArray.with_at_least(4, 32)
    assert len(bits.lst) == 16
