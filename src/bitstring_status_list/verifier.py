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

class EnvelopingTokenVerifier(Protocol):
    """Protocol defining the verifying callable for enveloping signatures."""

    def __call__(self, payload: bytes, signature: bytes) -> bool:
        """Verify the signature of the payload. Returns true if the signature is valid."""
        ...

class EmbeddingTokenVerifier(Protocol):
    """Protocol defining the verifying callable for embedding signatures."""

    def __call_(self, payload: bytes, signature: dict) -> bool:
        ...

class BitstringStatusListVerifier():
    def __init__(self):
        pass