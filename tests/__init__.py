import time
import tracemalloc
import linecache
import os


class Timer:
    """Timer for timing operations."""

    def __init__(self):
        self.start = None
        self.end = None

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.time()
        return False

    @property
    def time(self) -> float:
        if self.start is None or self.end is None:
            raise ValueError("Timer is still running!")
        return self.end - self.start


def display_top_memory(snapshot, key_type="lineno", limit=3):
    snapshot = snapshot.filter_traces(
        (
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
            tracemalloc.Filter(False, "<unknown>"),
        )
    )
    top_stats = snapshot.statistics(key_type)

    print("Top %s lines" % limit)
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        # replace "/path/to/module/file.py" with "module/file.py"
        filename = os.sep.join(frame.filename.split(os.sep)[-2:])
        print("#%s: %s:%s: %.1f KiB" % (index, filename, frame.lineno, stat.size / 1024))
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print("    %s" % line)

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print("%s other: %.1f KiB" % (len(other), size / 1024))
    total = sum(stat.size for stat in top_stats)
    print("Total allocated size: %.1f KiB" % (total / 1024))


def total_memory_usage(snapshot, key_type="lineno"):
    """Extract total memory usage in KiB."""
    snapshot = snapshot.filter_traces(
        (
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
            tracemalloc.Filter(False, "<unknown>"),
        )
    )
    top_stats = snapshot.statistics(key_type)
    total = sum(stat.size for stat in top_stats)
    return total / 1024


class MemoryTracer:
    def __init__(self):
        self.snapshot = None

    def __enter__(self):
        tracemalloc.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.snapshot = tracemalloc.take_snapshot()
        tracemalloc.clear_traces()
        return False

    def display_top(self):
        if self.snapshot is None:
            raise ValueError("Memory tracing still running!")
        display_top_memory(self.snapshot)

    @property
    def total(self):
        if self.snapshot is None:
            raise ValueError("Memory tracing still running!")
        return total_memory_usage(self.snapshot)
