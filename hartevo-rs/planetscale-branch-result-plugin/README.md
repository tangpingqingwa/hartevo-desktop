# Hartevo PlanetScale branch-result plugin

Standalone Layer 1 contract and Rust crate for bounded PlanetScale database
branch/deploy/schema posture evidence. The crate deliberately exposes only
proposal, redacted recording, and verification seams. It cannot create or
delete branches, create or apply deploy requests, deploy schema, execute
queries, resolve credentials, claim Connected/native evidence, or adopt a
Work Product.

The fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are
deterministic test seams. All of them report non-native evidence.

API basis: [PlanetScale API reference](https://planetscale.com/docs/api/reference/getting-started-with-planetscale-api).
