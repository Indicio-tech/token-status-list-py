from src.issuer import Issuer
from src.bit_array import BitArray, IndexAllocator, N, LinearIndexAllocator, RandomIndexAllocator, Bits, dict_to_b64

from typing import (
    List,
    Literal,
    Optional,
    Tuple,
    Protocol,
    Union,
)

MIN_LIST_LENGTH = 131072

class EnvelopingTokenSigner(Protocol):
    """Protocol defining the signing callable for enveloping proofs."""

    def __call__(self, payload: bytes) -> bytes:
        """Sign the payload returning bytes of the signature."""
        ...

class EmbeddingTokenSigner(Protocol):
    """Protocol defining the signing callable for embedding proofs."""

    def __call__(self, payload: bytes) -> dict:
        """Sign the payload returning signature in dict form to inject into payload."""
        ...

class StatusListLengthError(Exception):
    """Raised when the status list is insufficiently long."""

class BitstringStatusListIssuer(Issuer):
    """Bitstring Status List Issuer."""
    def __init__(
        self,
        status_list: BitArray[N],
        allocator: IndexAllocator,
        min_list_length: int = MIN_LIST_LENGTH,
    ):
        super().__init__(
            status_list=status_list,
            allocator=allocator
        )
        self.min_list_length = min_list_length

        if len(self.status_list) < self.min_list_length:
            raise StatusListLengthError(f"Bitstring status list must be at least {self.min_list_length} bits \
                                        long, but was {len(self.status_list)} bits long instead.")

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

        parsed_status_list = BitArray.load(status_list)
        return cls(parsed_status_list, allocator)

    @classmethod
    def new(cls, size: int, bits: Bits = 1, strategy: Literal["linear", "random"] = "random", min_list_length: int = MIN_LIST_LENGTH) -> "BitstringStatusListIssuer":
        """Return a new Issuer."""
        if size < min_list_length:
            raise StatusListLengthError(f"Bitstring status list must be at least {min_list_length} bits \
                                        long, but was {size} bits long instead.")
        
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

    def generate_jwt(
        self,
        alg: Optional[str],
        kid: Optional[str],
        status_purpose = Union[str, List[str]],
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        validFrom: Optional[str] = None,
        validUntil: Optional[str] = None,
        ttl: Optional[int] = None,
        issuer: Optional[str] = None,
        status_messages: Optional[list] = None,
        status_size: Optional[Bits] = None,
    ) -> Tuple[dict, dict]:
        if status_purpose == "message":
            assert status_size is not None
            if status_size > 1:
                assert status_messages is not None
        
        headers = {
            "kid": kid,
            "alg": alg,
        }

        payload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
            ],

            **({"id": id} if id else {}),
            "type": (type.append("BitstringStatusListCredential") 
                            if "BitstringStatusListCredential" not in type 
                            else type) 
                    if type 
                    else ["BitstringStatusListCredential"],

            **({"issuer": issuer} if issuer else {}),
            **({"validFrom": validFrom} if validFrom else {}),
            **({"validUntil": validUntil} if validUntil else {}),

            "credentialSubject": {
                **({"id": id} if id else {}),
                "type": "BitstringStatusList",
                "statusPurpose": status_purpose,
                "encodedList": self.status_list.to_b64(),
                **({"ttl": ttl} if ttl else {}),
                **({"statusMessages": status_messages} if status_messages else {}),
                **({"statusSize": status_size} if status_size else {}),
            }
        }

        return headers, payload
    
    def sign_jwt_enveloping(
        self,
        signer: EnvelopingTokenSigner,
        alg: str,
        kid: str,
        status_purpose = str | List[str],
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        validFrom: Optional[str] = None,
        validUntil: Optional[str] = None,
        ttl: Optional[int] = None,
        issuer: Optional[str] = None,
        status_messages: Optional[list] = None,
        status_size: Optional[Bits] = None,
    ) -> bytes:
        headers, payload = self.generate_jwt(
            alg=alg,
            kid=kid,
            status_purpose=status_purpose,
            id=id,
            type=type,
            validFrom=validFrom,
            validUntil=validUntil,
            ttl=ttl,
            issuer=issuer,
            status_messages=status_messages,
            status_size=status_size,
        )
        
        enc_headers = dict_to_b64(headers)
        enc_payload = dict_to_b64(payload)
        enc_to_sign = enc_headers + b"." + enc_payload

        signature = signer(enc_to_sign)
        return enc_to_sign + b"." + signature
    
    def sign_jwt_embedding(
        self,
        signer: EmbeddingTokenSigner,
        status_purpose = str | List[str],
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        validFrom: Optional[str] = None,
        validUntil: Optional[str] = None,
        ttl: Optional[int] = None,
        issuer: Optional[str] = None,
        status_messages: Optional[list] = None,
        status_size: Optional[Bits] = None,
    ):
        headers, payload = self.generate_jwt(
            alg=None,
            kid=None,
            status_purpose=status_purpose,
            id=id,
            type=type,
            validFrom=validFrom,
            validUntil=validUntil,
            ttl=ttl,
            issuer=issuer,
            status_messages=status_messages,
            status_size=status_size,
        )

        unsigned_payload_bytes = dict_to_b64(payload)
        payload["proof"] = signer(unsigned_payload_bytes)

        return dict_to_b64(payload)

   