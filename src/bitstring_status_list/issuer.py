from issuer import *
from bit_array import *

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

MIN_LIST_LENGTH = 131072

class BitstringStatusListIssuer(Issuer):
    """Bitstring Status List Issuer."""
    def __init__(
        self,
        status_list: BitArray[N],
        allocator: IndexAllocator,
    ):
        super().__init__
        if self.status_list.bits != 1:
            raise ValueError("Bitstring status list must have single bit statuses.")
        
        if len(self.status_list) < MIN_LIST_LENGTH:
            raise ValueError(f"Bitstring status list must be at least {MIN_LIST_LENGTH} bits long, 
                             but was {len(self.status_list)} bits long instead.")

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

        if parsed_status_list.bits != 1:
            raise ValueError("Bitstring status list must have single bit statuses.")

        if len(parsed_status_list) < MIN_LIST_LENGTH:
            raise ValueError(f"Bitstring status list must be at least {MIN_LIST_LENGTH} bits long, 
                             but was {len(parsed_status_list)} bits long instead.")

        return cls(parsed_status_list, allocator)

    @classmethod
    def new(cls, size: int, strategy: Literal["linear", "random"] = "random") -> "BitstringStatusListIssuer":
        """Return a new Issuer."""
        if size < MIN_LIST_LENGTH:
            raise ValueError(f"Bitstring status list must be at least {MIN_LIST_LENGTH} bits long, 
                             but was {size} bits long instead.")
        
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

    def generate_jwt(
        self,
        alg: str,
        kid: str,
        status_purpose = str | List[str],
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        validFrom: Optional[str] = None,
        validUntil: Optional[str] = None,
        ttl: Optional[int] = None,  
    ) -> Tuple[dict, dict]:
        headers = {
            "kid": kid,
            "alg": alg,
        }

        payload = {
            # TODO: What is the @context field?
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],

            **({"id": id} if id else {}),
            "type": (type.append("BitstringStatusListCredential") 
                            if "BitstringStatusListCredential" not in type 
                            else type) 
                    if type 
                    else ["BitstringStatusListCredential"],

            **({"validFrom": validFrom} if validFrom else {}),
            **({"validUntil": validUntil} if validUntil else {}),

            "credentialSubject": {
                **({"id": id} if id else {}),  # TODO: this is very unclear
                "type": "BitstringStatusList",
                "statusPurpose": status_purpose,
                "encodedList": self.status_list.dump(),
                **({"ttl": ttl} if ttl else {}),
            }
        }

        return headers, payload
    
    def sign_jwt_enveloping(
        self,
        signer: TokenSigner,
        alg: str,
        kid: str,
        status_purpose = str | List[str],
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        validFrom: Optional[str] = None,
        validUntil: Optional[str] = None,
        ttl: Optional[int] = None,
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
        )
        
        enc_headers = dict_to_b64(headers).decode()
        enc_payload = dict_to_b64(payload).decode()
        enc_to_sign = f"{enc_headers}.{enc_payload}".encode()

        signature = signer(enc_to_sign)
        return enc_to_sign + b"." + signature
    
    def sign_jwt_embedding(
        self,
        proof: dict,
        alg: str,
        kid: str,
        status_purpose = str | List[str],
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        validFrom: Optional[str] = None,
        validUntil: Optional[str] = None,
        ttl: Optional[int] = None,
    ):
        headers, payload = self.generate_jwt(
            alg=alg,
            kid=kid,
            status_purpose=status_purpose,
            id=id,
            type=type,
            validFrom=validFrom,
            validUntil=validUntil,
            ttl=ttl,
        )

        payload["proof"] = proof  # TODO: is this correct?
        return dict_to_b64(headers) + b"." + dict_to_b64(payload)

   