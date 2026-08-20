# LaunchDarkly release plugin contract

This is the versioned Layer 1 contract for Hartevo's LaunchDarkly feature-release
plugin. It is deliberately limited to read, proposal, and recording seams:

- exact account/base URL/project/environment/flag/version scope;
- least-privilege opaque service-token references;
- redacted flag, approval, and bounded audit evidence;
- canonical semantic-patch and dry-run validation digests;
- approval, version, audit, registration, revocation, and `BLOCKED_ENV` fences;
- a Mission-consumable release-result proposal with no Effect, Receipt,
  Verification, Truth, Consent, or Outcome authority.

The Rust crate under `hartevo-rs/launchdarkly-release-plugin` is a standalone
nested workspace. It has no live LaunchDarkly transport. Fixture, recording,
loopback, and `BLOCKED_ENV` transports always report recording-only evidence and
never assert Connected, native, or first-party status.
