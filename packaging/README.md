# packaging/

Artifacts consumed at build/install time.

## `dev-key.bin`

**32-byte pre-shared key embedded in debug builds as a dev fallback.**
This key is committed to the repository and is therefore **PUBLIC**.
It is intended solely for local development and CI loopback tests.

The server logs a loud WARN loop at runtime when this key is in use
(see §9.4 of the design spec). In production, install a per-device key
via `netprovd keygen --install` and ensure `$NETPROV_PRODUCTION=1` is
set in the service environment, which disables the dev-key fallback.

## `netprovd.service`

Deferred to Part 2 of the implementation plan.
