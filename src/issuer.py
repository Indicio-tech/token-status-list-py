from bit_array import *



class Issuer(Generic[N]):
    """ Base class for a generic issuer. """

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
