# token-status-list

This is an implementation of [Token Status List Draft 2][spec].

[spec]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-02


## Features

- Support for 1, 2, 4, and 8 bits.
- Compression as required by the Specification (ZLIB at level 9)
- Formatting and signing Status Lists as either JWT or CWT
    - A `TokenSigner` protocol is defined so the user can Bring Their Own Crypto implementation
    - Alternatively, methods for preparing payloads and assembling payload and signature bytes into the final token is also supported.
- Two Index Allocation strategies, Linear and Random
    - Linear strategy will allocate indices serially
    - Random strategy will allocate indices pseudo-randomly (as the list fills, speed is favored over randomness)
    - Allocators contain state that must be persisted along side the status list itself
    - IssuerStatusList and Allocators are serializeable so the user can persist them to the backend of their choice

## Planned Features

These are features that I intend to include soon.

- VerifierStatusList providing helpers to verify and validate a Status List Token obtained for verification.
- Examples
