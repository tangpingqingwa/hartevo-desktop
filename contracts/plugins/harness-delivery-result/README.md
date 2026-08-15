# Harness delivery result contract

This is the Layer-1 boundary for inspecting bounded Harness delivery metadata.
It is deliberately limited to read, proposal, verification, and recording
seams. The crate does not connect to Harness, resolve an API key, or claim
native, first-party, durable provider, Truth, Effect, Outcome, or Work Product
authority.

The provider shape follows the official [Harness API documentation](https://apidocs.harness.io/),
including the account, organization, project, pipeline, execution, stage,
service, environment, and commit identifiers used to bind bounded metadata.
Recorded, fixture, loopback, and `BLOCKED_ENV` transports all remain
non-connected and non-native.
