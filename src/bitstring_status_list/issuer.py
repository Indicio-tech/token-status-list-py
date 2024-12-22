from bit_array import *

class BitstringStatusListIssuer(Generic[N]):
    """Token Status List Issuer."""

    def __init__(
        self,
        status_list: BitArray[N],
        allocator: IndexAllocator,
    ):
        """Initialize issuer status list."""
        self.allocator = allocator

        if status_list.bits != 1:
            raise ValueError(f"Expected status list to have bits = 1. Instead, bits = {status_list.bits}")
        
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
    def load(cls, value: dict) -> "BitstringStatusListIssuer":
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

        if status_list.get("bits") != 1:
            raise ValueError(f"Expected status list to have bits = 1. Instead, bits = {status_list.get("bits")}")
 
        parsed_status_list = BitArray.load(status_list)
        return cls(parsed_status_list, allocator)

    @classmethod
    def new(cls, size: int, strategy: Literal["linear", "random"] = "random"):
        """Return a new TokenStatusListIssuer."""
        if strategy == "linear":
            allocator = LinearIndexAllocator(size)
        elif strategy == "random":
            allocator = RandomIndexAllocator(
                BitArray.with_at_least(1, size), num_allocated=0
            )
        else:
            raise ValueError(f"Invalid strategy: {strategy}")

        status_list = BitArray.with_at_least(1, size)
        return cls(status_list, allocator)