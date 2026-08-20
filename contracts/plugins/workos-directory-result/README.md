# WorkOS Directory Sync result contract

This directory defines the standalone Layer-1 contract for bounded WorkOS Directory Sync evidence. It is deliberately isolated from the root Cargo workspace and from Hartevo application, kernel, connector, storage, and UI paths.

The contract permits only typed `GET`-shaped reads for a scoped organization, directory, connection, and one filtered membership direction. User and group identity fields are retained as immutable provider IDs and digests; email, names, custom attributes, domains, API keys, cursors, tokens, login/session material, and raw provider payloads are not retained.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are test/provenance modes. They are never reported as connected or native. Native API-key resolution, HTTPS, durable provider receipts, independent rereads, and consented identity effects remain Layer-2 host responsibilities.
