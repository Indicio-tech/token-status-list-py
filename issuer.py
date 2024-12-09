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

from token_status_list import *

# COSE Headers
ALG = 1
KID = 4
TYP = 16  # TBD

# CWT Claims
ISS = 1
SUB = 2
AUD = 3
EXP = 4
NBF = 5
IAT = 6
CTI = 7

# Status List Claims
STATUS_LIST = 65533
TTL = 65534

KNOWN_ALGS_TO_CWT_ALG = {
    "ES256": -7,
    "ES384": -35,
    "ES512": -36,
    "EdDSA": -8,
}

CWTKnownAlgs = Literal["ES256", "ES384", "ES512", "EdDSA"]

class TokenSigner(Protocol):
    """Protocol defining the signing callable."""

    def __call__(self, payload: bytes) -> bytes:
        """Sign the payload returning bytes of the signature."""
        ...

class TokenStatusListIssuer(Generic[N]):
    """Token Status List Issuer."""

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

    @classmethod
    def load(cls, value: dict) -> "TokenStatusListIssuer":
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
    def new(cls, bits: Bits, size: int, strategy: Literal["linear", "random"] = "random"):
        """Return a new TokenStatusListIssuer."""
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

    def sign_jwt_payload(
        self,
        *,
        alg: str,
        kid: str,
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        ttl: Optional[int] = None,
        **additional_claims: Any,
    ) -> bytes:
        """Create payload of Status List Token in JWT format for signing.

        Signing is NOT performed by this function; only the payload to the signature is
        prepared. The caller is responsible for producing a signature.

        Args:
            alg: REQUIRED. The algorithm to be used to sign the payload.

            kid: REQUIRED. The kid used to sign the payload.

            iss: REQUIRED when also present in the Referenced Token. The iss (issuer)
                claim MUST specify a unique string identifier for the entity that issued
                the Status List Token. In the absence of an application profile specifying
                otherwise, compliant applications MUST compare issuer values using the
                Simple String Comparison method defined in Section 6.2.1 of [RFC3986].
                The value MUST be equal to that of the iss claim contained within the
                Referenced Token.

            sub: REQUIRED. The sub (subject) claim MUST specify a unique string identifier
                for the Status List Token. The value MUST be equal to that of the uri
                claim contained in the status_list claim of the Referenced Token.

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the
                maximum amount of time, in seconds, that the Status List Token can be
                cached by a consumer before a fresh copy SHOULD be retrieved. The value
                of the claim MUST be a positive number.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            JWT payload ready for signing.
        """
        headers = {
            "typ": "statuslist+jwt",
            "alg": alg,
            "kid": kid,
        }
        payload = {
            "iss": iss,
            "sub": sub,
            "iat": iat or int(time()),
            "status_list": self.status_list.dump(),
            **additional_claims,
        }
        if exp is not None:
            payload["exp"] = exp

        if ttl is not None:
            payload["ttl"] = ttl

        enc_headers = dict_to_b64(headers).decode()
        enc_payload = dict_to_b64(payload).decode()
        return f"{enc_headers}.{enc_payload}".encode()

    def signed_jwt_token(self, signed_payload: bytes, signature: bytes) -> str:
        """Finish creating a signed token.

        Args:
            signed_payload: The value returned from `sign_payload`.
            signature: The signature over the signed_payload in bytes.

        Returns:
            Finished Status List Token.
        """
        return f"{signed_payload.decode()}.{b64url_encode(signature).decode()}"

    def sign_jwt(
        self,
        signer: TokenSigner,
        *,
        alg: str,
        kid: str,
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        ttl: Optional[int] = None,
        **additional_claims: Any,
    ) -> str:
        """Sign status list to produce a token.

        Args:
            signer: REQUIRED. A callable that returns a signature over the payload.

            alg: REQUIRED. The algorithm to be used to sign the payload.

            kid: REQUIRED. The kid used to sign the payload.

            iss: REQUIRED when also present in the Referenced Token. The iss (issuer)
                claim MUST specify a unique string identifier for the entity that issued
                the Status List Token. In the absence of an application profile specifying
                otherwise, compliant applications MUST compare issuer values using the
                Simple String Comparison method defined in Section 6.2.1 of [RFC3986].
                The value MUST be equal to that of the iss claim contained within the
                Referenced Token.

            sub: REQUIRED. The sub (subject) claim MUST specify a unique string identifier
                for the Status List Token. The value MUST be equal to that of the uri
                claim contained in the status_list claim of the Referenced Token.

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the
                maximum amount of time, in seconds, that the Status List Token can be
                cached by a consumer before a fresh copy SHOULD be retrieved. The value
                of the claim MUST be a positive number.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            Signed JWT of Status List.
        """
        payload = self.sign_jwt_payload(
            alg=alg,
            kid=kid,
            iss=iss,
            sub=sub,
            iat=iat,
            exp=exp,
            ttl=ttl,
            **additional_claims,
        )
        signature = signer(payload)
        return self.signed_jwt_token(payload, signature)

    def sign_cwt_payload(
        self,
        *,
        alg: Union[CWTKnownAlgs, str],
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        ttl: Optional[int] = None,
        **additional_claims: Any,
    ) -> Tuple[bytes, bytes]:
        """Prepare a CWT Format payload of the status list for signing.

        Signing is NOT performed by this function; only the payload to the signature is
        prepared. The caller is responsible for producing a signature.

        Args:
            alg: REQUIRED. The algorithm to be used to sign the payload.

            kid: REQUIRED. The kid used to sign the payload.

            iss: REQUIRED when also present in the Referenced Token. The iss (issuer)
                claim MUST specify a unique string identifier for the entity that issued
                the Status List Token. In the absence of an application profile specifying
                otherwise, compliant applications MUST compare issuer values using the
                Simple String Comparison method defined in Section 6.2.1 of [RFC3986].
                The value MUST be equal to that of the iss claim contained within the
                Referenced Token.

            sub: REQUIRED. The sub (subject) claim MUST specify a unique string identifier
                for the Status List Token. The value MUST be equal to that of the uri
                claim contained in the status_list claim of the Referenced Token.

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            Tuple of encoded_protected_headers and encoded_payload
        """
        try:
            import cbor2
        except ImportError as err:
            raise ImportError("cbor extra required to use this function") from err

        cwt_alg = KNOWN_ALGS_TO_CWT_ALG.get(alg)
        if not cwt_alg:
            raise ValueError(f"Unknown alg {alg}")

        protected = {ALG: cwt_alg, TYP: "statuslist+cwt"}
        payload = {
            SUB: sub,
            ISS: iss,
            IAT: iat or int(time()),
            **({EXP: exp} if exp else {}),
            **({TTL: ttl} if ttl else {}),
            STATUS_LIST: cbor2.dumps(
                {"bits": self.status_list.bits, "lst": self.status_list.compressed()}
            ),
            **additional_claims,
        }

        return cbor2.dumps(protected), cbor2.dumps(payload)

    def signed_cwt_token(
        self,
        kid: str,
        encoded_protected_headers: bytes,
        encoded_payload: bytes,
        signature: bytes,
    ) -> bytes:
        """Return a CWT its parts."""
        try:
            import cbor2
        except ImportError as err:
            raise ImportError("cbor extra required to use this function") from err

        unprotected = {KID: kid}
        cose_sign1 = [encoded_protected_headers, unprotected, encoded_payload, signature]
        tagged = cbor2.CBORTag(18, cose_sign1)
        return cbor2.dumps(tagged)

    def sign_cwt(
        self,
        signer: TokenSigner,
        *,
        alg: str,
        kid: Any,
        iss: str,
        sub: str,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        ttl: Optional[int] = None,
        **additional_claims: Any,
    ) -> bytes:
        """Sign status list to produce a CWT token.

        Args:
            signer: REQUIRED. A callable that returns a signature over the payload.

            alg: REQUIRED. The algorithm to be used to sign the payload.

            kid: REQUIRED. The kid used to sign the payload.

            iss: REQUIRED when also present in the Referenced Token. The iss (issuer)
                claim MUST specify a unique string identifier for the entity that issued
                the Status List Token. In the absence of an application profile specifying
                otherwise, compliant applications MUST compare issuer values using the
                Simple String Comparison method defined in Section 6.2.1 of [RFC3986].
                The value MUST be equal to that of the iss claim contained within the
                Referenced Token.

            sub: REQUIRED. The sub (subject) claim MUST specify a unique string identifier
                for the Status List Token. The value MUST be equal to that of the uri
                claim contained in the status_list claim of the Referenced Token.

            iat: OPTIONAL. The iat (issued at) claim MUST specify the time at which the
                Status List Token was issued. If not provided, `now` is used.

            exp: OPTIONAL. The exp (expiration time) claim, if present, MUST specify the
                time at which the Status List Token is considered expired by its issuer.

            additional_claims: OPTIONAL. Additional claims to include in the token.

        Returns:
            Signed JWT of Status List.
        """
        headers, payload = self.sign_cwt_payload(
            alg=alg, iss=iss, sub=sub, iat=iat, exp=exp, ttl=ttl, **additional_claims
        )
        signature = signer(headers + payload)
        token = self.signed_cwt_token(kid, headers, payload, signature)
        return token
