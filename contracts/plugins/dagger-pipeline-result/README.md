# Dagger pipeline result Layer 1

This contract is a bounded, metadata-only read/proposal/recording seam for
Dagger module, pipeline, function, container, execution result, and OCI
artifact metadata. It is deliberately below Hartevo Truth, Consent, Effect,
Receipt, Verification, Work Product, and Outcome authority.

The provider accepts only an opaque token or OCI `SecretReference`. The crate
never resolves native credentials, executes or cancels a pipeline, mutates a
registry, reads raw logs or shell output, or retains artifact bytes.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are all explicitly
non-connected and non-native. Native credential/runtime resolution, live
Dagger transport, durable provider receipts, independent rereads, consented
effects, and verified Work Product/Outcome adoption remain Layer-2 gaps.

The official API reference for the future native boundary is the
[Dagger API](https://docs.dagger.io/0.16.3/api/).
