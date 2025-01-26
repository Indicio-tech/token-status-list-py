# token-status-list

This is an implementation of [Token Status List Draft 6][spec] and [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/).

[spec]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-06


## Features

- Support for 1, 2, 4, and 8 bits.
- Compression as required by the Specification (ZLIB at level 9)
- Formatting, signing, and verifying Status Lists as either JWT or CWT
    - A `TokenSigner` and `TokenVerifier` protocol is defined so the user can Bring Their Own Crypto implementation
    - Alternatively, methods for preparing payloads and assembling payload and signature bytes into the final token is also supported.
- Two Index Allocation strategies, Linear and Random
    - Linear strategy will allocate indices serially
    - Random strategy will allocate indices pseudo-randomly (as the list fills, speed is favored over randomness)
    - Allocators contain state that must be persisted along side the status list itself
    - IssuerStatusList and Allocators are serializeable so the user can persist them to the backend of their choice
- Basic example using Nginx web server as an issuer to simulate fetching and verifying a Status List
    - Run using `docker-compose up -d && pytest tests/test_web_server.py`
    - Scripts that are issued, as well as other information about issuer are in `tests/test_web_server`
