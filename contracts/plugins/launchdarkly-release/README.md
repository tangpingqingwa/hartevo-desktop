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

## Layer 2 native exit plan (not executed)

This Layer 1 contract has no native LaunchDarkly transport, credential probe, or
canary receipt. The following gates are required before a future Layer 2
implementation may leave `BLOCKED_ENV`; none of these gates is claimed to have
run here:

1. Acquire an opaque service-token `SecretReference` through the approved
   secret provider, then prove its exact account, base URL, project,
   environment, flag, read-only permission set, credential revision, and
   registration digest without exposing token bytes.
2. Run a native read-only canary against exactly one registered project,
   environment, and flag. The canary must fail closed on account/base/scope
   drift, permission drift, token revocation, unsupported API revisions, and
   `429` retry-budget overflow, and must emit bounded redacted flag, approval,
   and audit read evidence.
3. Perform an independent exact read-back canary using the same version,
   provider fence, registration digest, proposal digest, approval digest, and
   audit digest tuple. No patch, toggle, approval mutation, scheduling,
   context evaluation, or event ingestion is part of this exit test.
4. Record an auditable native-exit receipt containing the credential/probe
   revision, permission snapshot, scope/provider fence, request/response
   digests, read-back digests, rejection cases, and operator approval. Product
   acceptance requires all six kernel authority fields and every
   `Connected`/native/first-party claim to remain false in this plugin seam;
   Vercel, Kubernetes, PostHog, Sentry, and kernel owners retain their own
   deployment/runtime/outcome authority.

   Until the credential, permission, probe, canary, read-back, and receipt
   evidence are independently available, this plugin remains Layer 1 and any
   missing native dependency remains `BLOCKED_ENV` rather than acceptance.
