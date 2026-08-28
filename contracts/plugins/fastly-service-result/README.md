# Fastly service-result Layer 1

This contract defines a standalone, read/proposal/recording-only boundary for
bounded Fastly service, version, environment, domain, and validation metadata.
It can produce a revision-fenced Mission proposal, but it cannot resolve a
native API token, make native HTTPS calls, activate or clone a version, upload
VCL/config, purge, mutate domains/DNS/TLS/traffic, retain raw VCL/config, or
claim a durable provider receipt or Hartevo authority.

The package proves only deterministic fixture, recording, fake, loopback, and
`BLOCKED_ENV` transport behavior. Every one of those provenances is explicitly
`connected=false`, `native=false`, and `first_party=false`. Registration binds
the version, API revision, contract, provider, permission, consent, exact
account/service/version/environment/domain/Project/Mission/Work Product scope,
and evidence digest and can be revoked, restored, or reversed.

Native Fastly credential resolution, live HTTPS, independent native read-back,
durable receipts, verified Work Product adoption, and Truth/Consent/Effect/
Receipt/Verification/Outcome authority remain Layer-2 gaps.
