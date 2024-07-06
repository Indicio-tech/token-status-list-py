from secrets import randbelow
from typing import Callable
import pytest
from random import sample
from itertools import product

from tests import MemoryTracer, Timer
from token_status_list import BitArray, RandomIndexAllocator

SIZE = 10000


@pytest.fixture
def worst_case():
    def _factory():
        length = (SIZE + 7) >> 3
        allocated = BitArray(1, b"\xff" * length)
        index = randbelow(SIZE)
        allocated[index] = 0
        return allocated

    yield _factory


@pytest.fixture
def empty_case():
    def _factory():
        allocated = BitArray.of_size(1, SIZE)
        return allocated

    yield _factory


@pytest.fixture
def percent_full():
    def _factory(percent: float):
        assert percent < 1 and percent > 0
        allocated = BitArray.of_size(1, SIZE)
        indices = sample(range(SIZE), int(SIZE * percent))
        for i in indices:
            allocated[i] = 1
        return allocated

    yield _factory


@pytest.fixture
def remaining():
    def _factory(n: int):
        length = (SIZE + 7) >> 3
        allocated = BitArray(1, b"\xff" * length)
        indices = sample(range(SIZE), n)
        for i in indices:
            allocated[i] = 0
        return allocated

    yield _factory


@pytest.mark.performance
def test_linear_scanning_time_complexity(
    worst_case: Callable[[], BitArray], empty_case: Callable[[], BitArray]
):
    alloc = RandomIndexAllocator(worst_case(), 999999)
    print("\n")
    print("Linear scan, worst case: ", end="")
    with Timer() as timer:
        result = alloc.linear_scan(0, SIZE, lambda index: alloc.allocated.get(index) == 0)
    print(f"{timer.time:.3f}s")
    print("Result: ", result)
    print("Linear scan and select, worst case: ", end="")
    with Timer() as timer:
        result = alloc.scan_and_rand()
    print(f"{timer.time:.3f}s")
    print("Result: ", result)

    alloc = RandomIndexAllocator(empty_case(), 0)
    print("Linear scan, empty case: ", end="")
    with Timer() as timer:
        result = alloc.linear_scan(0, SIZE, lambda index: alloc.allocated.get(index) == 0)
    print(f"{timer.time:.3f}s")
    print("Linear scan and select, empty case: ", end="")
    with Timer() as timer:
        result = alloc.scan_and_rand()
    print(f"{timer.time:.3f}s")
    print("Result: ", result)

    print("Linear scan over bytes, empty case: ", end="")
    with Timer() as timer:
        result = alloc.linear_scan(
            0, (SIZE + 7) >> 3, lambda byte_idx: alloc.allocated.lst[byte_idx] < 255
        )
    print(f"{timer.time:.3f}s")


@pytest.mark.performance
def test_linear_scanning_space_complexity(
    worst_case: Callable[[], BitArray], empty_case: Callable[[], BitArray]
):
    alloc = RandomIndexAllocator(worst_case(), 999999)
    print("\n")
    print("Linear scan, worst case: ", end="")
    with MemoryTracer() as tracer:
        result = alloc.linear_scan(0, SIZE, lambda index: alloc.allocated.get(index) == 0)
    print(f"{tracer.total:.1f} KiB")
    print("Linear scan and select, worst case: ", end="")
    with MemoryTracer() as tracer:
        result = alloc.scan_and_rand()
    print(f"{tracer.total:.1f} KiB")
    print("Result: ", result)

    alloc = RandomIndexAllocator(empty_case(), 0)
    print("Linear scan, empty case: ", end="")
    with MemoryTracer() as tracer:
        result = alloc.linear_scan(0, SIZE, lambda index: alloc.allocated.get(index) == 0)
    print(f"{tracer.total:.1f} KiB")
    print("Linear scan and select, empty case: ", end="")
    with MemoryTracer() as tracer:
        result = alloc.scan_and_rand()
    print(f"{tracer.total:.1f} KiB")
    print("Result: ", result)

    print("Linear scan over bytes, empty case: ", end="")
    with MemoryTracer() as tracer:
        result = alloc.linear_scan(
            0, (SIZE + 7) >> 3, lambda byte_idx: alloc.allocated.lst[byte_idx] < 255
        )
    print(f"{tracer.total:.1f} KiB")


@pytest.mark.performance
def test_rand_settle_time_complexity(
    worst_case: Callable[[], BitArray], empty_case: Callable[[], BitArray]
):
    alloc = RandomIndexAllocator(worst_case(), 999999)
    print("\n")
    print("Rand and settle, worst case: ", end="")
    with Timer() as timer:
        result = alloc.rand_and_settle()
    print(f"{timer.time:.3f}s")

    alloc = RandomIndexAllocator(empty_case(), 0)
    print("Rand and settle, empty case: ", end="")
    with Timer() as timer:
        result = alloc.rand_and_settle()
    print(f"{timer.time:.3f}s")


@pytest.mark.performance
def test_rand_settle_space_complexity(
    worst_case: Callable[[], BitArray], empty_case: Callable[[], BitArray]
):
    alloc = RandomIndexAllocator(worst_case(), 999999)
    print("\n")
    print("Rand and settle, worst case: ", end="")
    with MemoryTracer() as tracer:
        result = alloc.rand_and_settle()
    print(f"{tracer.total:.1f} KiB")

    alloc = RandomIndexAllocator(empty_case(), 0)
    print("Rand and settle, empty case: ", end="")
    with MemoryTracer() as tracer:
        result = alloc.rand_and_settle()
    print(f"{tracer.total:.1f} KiB")


@pytest.mark.performance
@pytest.mark.parametrize(
    "percent", [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.96, 0.97, 0.98, 0.99]
)
def test_compare_percent(percent: float, percent_full: Callable[[float], BitArray]):
    """Compare selection algorithms."""
    iter = 100
    times_rand_was_slower = 0
    print()
    print(f"Running {iter} iterations with {percent*100}% full list")

    random_alloc = RandomIndexAllocator(percent_full(percent))
    scan_alloc = RandomIndexAllocator(percent_full(percent))
    rand_total = 0.0
    scan_total = 0.0
    for i in range(iter):
        if i % 100 == 0:
            print(i, end="", flush=True)
        else:
            print(".", end="", flush=True)
        with Timer() as rand_timer:
            random_alloc.rand_and_settle()

        with Timer() as scan_timer:
            scan_alloc.scan_and_rand()

        rand_total += rand_timer.time
        scan_total += scan_timer.time
        if rand_timer.time > scan_timer.time:
            times_rand_was_slower += 1
            print("!", end="", flush=True)
    print()

    print("Times rand was slower than scan:", times_rand_was_slower)
    print(f"Rand average: {rand_total / iter:.3f}s")
    print(f"Scan average: {scan_total / iter:.3f}s")
    print(f"Percent faster: {rand_total / scan_total * 100:.3f}%")


@pytest.mark.performance
@pytest.mark.parametrize("n", [100, 50, 30, 20, 10, 5, 4, 3, 2, 1])
def test_compare_remaining_n(n: int, remaining: Callable[[int], BitArray]):
    """Compare selection algorithms."""
    iter = 100
    times_rand_was_slower = 0
    print()
    print(f"Running {iter} iterations with {n} remaining")

    rand_total = 0.0
    scan_total = 0.0
    for i in range(iter):
        if i % 100 == 0:
            print(i, end="", flush=True)
        else:
            print(".", end="", flush=True)
        random_alloc = RandomIndexAllocator(remaining(n))
        scan_alloc = RandomIndexAllocator(remaining(n))
        with Timer() as rand_timer:
            random_alloc.rand_and_settle()

        with Timer() as scan_timer:
            scan_alloc.scan_and_rand()

        rand_total += rand_timer.time
        scan_total += scan_timer.time
        if rand_timer.time > scan_timer.time:
            times_rand_was_slower += 1
            print("!", end="", flush=True)
    print()

    print("Times rand was slower than scan:", times_rand_was_slower)
    print(f"Rand average: {rand_total / iter:.3f}s")
    print(f"Scan average: {scan_total / iter:.3f}s")
    print(f"Percent faster: {rand_total / scan_total * 100:.3f}%")


@pytest.mark.performance
@pytest.mark.parametrize("n", [100, 50, 30, 20, 10, 5, 4, 3, 2, 1])
def test_compare_remaining_n_take_all(n: int, remaining: Callable[[int], BitArray]):
    """Compare selection algorithms."""
    iter = 10
    times_rand_was_slower = 0
    print()
    print(f"Running {iter} iterations with {n} remaining")

    rand_total = 0.0
    scan_total = 0.0
    for i in range(iter):
        if i % 100 == 0:
            print(i, end="", flush=True)
        else:
            print(".", end="", flush=True)
        random_alloc = RandomIndexAllocator(remaining(n))
        scan_alloc = RandomIndexAllocator(remaining(n))
        with Timer() as rand_timer:
            random_alloc.rand_and_settle_n(n)

        with Timer() as scan_timer:
            scan_alloc.scan_and_rand_n(n)

        rand_total += rand_timer.time
        scan_total += scan_timer.time
        if rand_timer.time > scan_timer.time:
            times_rand_was_slower += 1
            print("!", end="", flush=True)
    print()

    print("Times rand was slower than scan:", times_rand_was_slower)
    print(f"Rand average: {rand_total / iter:.3f}s")
    print(f"Scan average: {scan_total / iter:.3f}s")
    print(f"Percent faster: {rand_total / scan_total * 100:.3f}%")


@pytest.mark.performance
@pytest.mark.parametrize(
    ("n", "percent"),
    product([100, 50, 30, 20, 10, 5, 4, 3, 2, 1], [0.9, 0.95, 0.96, 0.97, 0.98, 0.99]),
)
def test_compare_percent_take_n(
    n: int, percent: float, percent_full: Callable[[float], BitArray]
):
    """Compare selection algorithms."""
    iter = 10
    times_rand_was_slower = 0
    print()
    print(f"Running {iter} iterations, taking {n} indices with {percent * 100}% full")

    rand_total = 0.0
    scan_total = 0.0
    for _ in range(iter):
        random_alloc = RandomIndexAllocator(percent_full(percent))
        scan_alloc = RandomIndexAllocator(percent_full(percent))
        with Timer() as rand_timer:
            random_alloc.rand_and_settle_n(n)

        with Timer() as scan_timer:
            scan_alloc.scan_and_rand_n(n)

        rand_total += rand_timer.time
        scan_total += scan_timer.time
        if rand_timer.time > scan_timer.time:
            times_rand_was_slower += 1
            print("!", end="", flush=True)
        else:
            print(".", end="", flush=True)
    print()

    print("Times rand was slower than scan:", times_rand_was_slower)
    print(f"Rand average: {rand_total / iter:.3f}s")
    print(f"Scan average: {scan_total / iter:.3f}s")
    print(f"Percent faster: {rand_total / scan_total * 100:.3f}%")


@pytest.mark.performance
@pytest.mark.parametrize(
    ("x", "n"),
    [
        (x, int(percent * x))
        for x in (100, 200, 300, 400, 500, 600, 700, 800, 900, 1000)
        for percent in (0.1, 0.2, 0.3, 0.4, 0.5)
    ],
)
def test_compare_remaining_x_take_n(x: int, n: int, remaining: Callable[[int], BitArray]):
    """Compare selection algorithms."""
    iter = 100
    times_rand_was_slower = 0
    print()
    print(f"Running {iter} iterations, taking {n} with {x} remaining ({n / x * 100}%)")

    rand_total = 0.0
    scan_total = 0.0
    for i in range(iter):
        random_alloc = RandomIndexAllocator(remaining(x))
        scan_alloc = RandomIndexAllocator(remaining(x))
        with Timer() as rand_timer:
            random_alloc.rand_and_settle_n(n)

        with Timer() as scan_timer:
            scan_alloc.scan_and_rand_n(n)

        rand_total += rand_timer.time
        scan_total += scan_timer.time
        if rand_timer.time > scan_timer.time:
            times_rand_was_slower += 1
            print("!", end="", flush=True)
        else:
            print(".", end="", flush=True)
    print()

    print("Times rand was slower than scan:", times_rand_was_slower)
    print(f"Rand average: {rand_total / iter:.3f}s")
    print(f"Scan average: {scan_total / iter:.3f}s")
    print(f"Percent faster: {rand_total / scan_total * 100:.3f}%")
