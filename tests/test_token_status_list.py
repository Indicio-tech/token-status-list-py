"""Test TokenStatusList."""

import json
import pytest
from secrets import randbelow

from token_status_list import INVALID, SUSPENDED, TokenStatusList, VALID, b64url_decode


def test_get_1_bits():
    status = TokenStatusList(1, b"\xb9\xa3")
    assert status.size == 16
    assert len(status.lst) == 2
    assert status[0] == 1
    assert status[1] == 0
    assert status[2] == 0
    assert status[3] == 1
    assert status[4] == 1
    assert status[5] == 1
    assert status[6] == 0
    assert status[7] == 1
    assert status[8] == 1
    assert status[9] == 1
    assert status[10] == 0
    assert status[11] == 0
    assert status[12] == 0
    assert status[13] == 1
    assert status[14] == 0
    assert status[15] == 1


def test_set_1_bits():
    status = TokenStatusList.of_size(1, 16)
    assert len(status.lst) == 2
    status[0] = 1
    status[1] = 0
    status[2] = 0
    status[3] = 1
    status[4] = 1
    status[5] = 1
    status[6] = 0
    status[7] = 1
    status[8] = 1
    status[9] = 1
    status[10] = 0
    status[11] = 0
    status[12] = 0
    status[13] = 1
    status[14] = 0
    status[15] = 1
    assert status[0] == 1
    assert status[1] == 0
    assert status[2] == 0
    assert status[3] == 1
    assert status[4] == 1
    assert status[5] == 1
    assert status[6] == 0
    assert status[7] == 1
    assert status[8] == 1
    assert status[9] == 1
    assert status[10] == 0
    assert status[11] == 0
    assert status[12] == 0
    assert status[13] == 1
    assert status[14] == 0
    assert status[15] == 1


def test_get_2_bits():
    status = TokenStatusList(2, b"\xc9\x44\xf9")
    assert status.size == 12
    assert len(status.lst) == 3
    assert status[0] == 1
    assert status[1] == 2
    assert status[2] == 0
    assert status[3] == 3
    assert status[4] == 0
    assert status[5] == 1
    assert status[6] == 0
    assert status[7] == 1
    assert status[8] == 1
    assert status[9] == 2
    assert status[10] == 3
    assert status[11] == 3


def test_set_2_bits():
    status = TokenStatusList.of_size(2, 12)
    assert len(status.lst) == 3
    status[0] = 1
    status[1] = 2
    status[2] = 0
    status[3] = 3
    status[4] = 0
    status[5] = 1
    status[6] = 0
    status[7] = 1
    status[8] = 1
    status[9] = 2
    status[10] = 3
    status[11] = 3
    assert status[0] == 1
    assert status[1] == 2
    assert status[2] == 0
    assert status[3] == 3
    assert status[4] == 0
    assert status[5] == 1
    assert status[6] == 0
    assert status[7] == 1
    assert status[8] == 1
    assert status[9] == 2
    assert status[10] == 3
    assert status[11] == 3


def test_get_4_bits():
    status = TokenStatusList(4, b"\x11\x22\x33\x44")
    assert status.size == 8
    assert len(status.lst) == 4
    assert status[0] == 1
    assert status[1] == 1
    assert status[2] == 2
    assert status[3] == 2
    assert status[4] == 3
    assert status[5] == 3
    assert status[6] == 4
    assert status[7] == 4


def test_get_8_bits():
    status = TokenStatusList(8, b"\x01\x02\x03\x04")
    assert status.size == 4
    assert len(status.lst) == 4
    assert status[0] == 1
    assert status[1] == 2
    assert status[2] == 3
    assert status[3] == 4


def test_compression():
    status = TokenStatusList(1, b"\xb9\xa3")
    compressed = status.compressed()
    assert compressed == b64url_decode(b"eNrbuRgAAhcBXQ")


@pytest.mark.performance
@pytest.mark.parametrize("bits", (1, 2, 4, 8))
def test_performance(bits: int):
    import time

    print()
    print()
    print("Bits:", bits)

    # Create a large TokenStatusList
    size = 1000000  # Number of indices
    status_list = TokenStatusList.of_size(bits, size)

    # Generate random statuses
    statuses = []
    while len(statuses) < size:
        run = randbelow(10)
        status = randbelow(2)
        statuses.extend([status] * run)

    diff = len(statuses) - size
    if diff > 1:
        for _ in range(diff + 1):
            statuses.pop()

    # Test setting values
    start_time = time.time()
    for i, status in enumerate(statuses):
        status_list[i] = status
    end_time = time.time()
    print(f"Time to set {size} indices: {end_time - start_time:.3f} seconds")

    # Test getting values
    start_time = time.time()
    for i in range(size):
        status = status_list[i]
    end_time = time.time()
    print(f"Time to get {size} indices: {end_time - start_time:.3f} seconds")

    # Test compression
    start_time = time.time()
    compressed_data = status_list.compressed()
    end_time = time.time()
    print(f"Time to compress: {end_time - start_time:.3f} seconds")
    print(f"Original length: {len(status_list.lst)} bytes")
    print(f"Compressed length: {len(compressed_data)} bytes")
    print(f"Compression ratio: {len(compressed_data) / len(status_list.lst) * 100:.3f}%")
    # print(f"List in hex: {status_list.lst.hex()}")


def test_serde():
    expected = TokenStatusList(1, b"\xb9\xa3")
    actual = TokenStatusList.deserialize(expected.serialize())
    assert len(expected.lst) == 2
    assert len(actual.lst) == 2
    assert expected.lst == actual.lst
    assert expected.bits == actual.bits
    assert expected.size == actual.size


def test_suspend_to_valid():
    status = TokenStatusList(2, b"\x80")
    assert status[3] == SUSPENDED
    status[3] = 0x00
    assert status[3] == VALID


def test_invalid_to_valid():
    status = TokenStatusList(1, b"\x80")
    assert status[7] == INVALID
    with pytest.raises(ValueError):
        status[7] = 0x00


def test_of_size():
    with pytest.raises(ValueError):
        status = TokenStatusList.of_size(1, 3)
    with pytest.raises(ValueError):
        status = TokenStatusList.of_size(2, 21)
    with pytest.raises(ValueError):
        status = TokenStatusList.of_size(4, 31)

    # Lists with bits 8 can have arbitrary size since there's no byte
    # boundaries to worry about
    status = TokenStatusList.of_size(8, 31)
    assert len(status.lst) == 31

    status = TokenStatusList.of_size(1, 8)
    assert len(status.lst) == 1
    status = TokenStatusList.of_size(1, 16)
    assert len(status.lst) == 2
    status = TokenStatusList.of_size(1, 24)
    assert len(status.lst) == 3
    status = TokenStatusList.of_size(8, 24)
    assert len(status.lst) == 24


def test_with_at_least():
    status = TokenStatusList.with_at_least(1, 3)
    assert len(status.lst) == 1
    status = TokenStatusList.with_at_least(2, 21)
    assert len(status.lst) == 6
    status = TokenStatusList.with_at_least(4, 31)
    assert len(status.lst) == 16

    status = TokenStatusList.with_at_least(1, 8)
    assert len(status.lst) == 1
    status = TokenStatusList.with_at_least(2, 24)
    assert len(status.lst) == 6
    status = TokenStatusList.with_at_least(4, 32)
    assert len(status.lst) == 16


def test_sign_payload():
    status = TokenStatusList(1, b"\xb9\xa3")
    payload = status.sign_payload(
        alg="ES256",
        kid="12",
        iss="https://example.com",
        sub="https://example.com/statuslists/1",
        iat=1686920170,
        exp=2291720170,
    )
    headers, payload = payload.split(b".")
    headers = json.loads(b64url_decode(headers))
    payload = json.loads(b64url_decode(payload))
    assert headers == {"alg": "ES256", "kid": "12", "typ": "statuslist+jwt"}
    assert payload == {
        "exp": 2291720170,
        "iat": 1686920170,
        "iss": "https://example.com",
        "status_list": {"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
        "sub": "https://example.com/statuslists/1",
    }
