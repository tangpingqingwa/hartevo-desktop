# EXT-TAILSCALE-01 — Tailscale network posture evidence result

This is a standalone Layer-1 contract for bounded, read/proposal/recording-only
Tailscale network posture evidence. It gives a Mission a typed review
projection over tailnet, device, tag, posture, ACL, grant, Project, Mission,
and Work Product scope.

Layer 1 deliberately ships no Tailscale SDK, native HTTP client, credential
resolver, or connected provider. `Fixture`, `Recording`, `Fake`, `Loopback`,
and `BLOCKED_ENV` are the only transport provenance values, and every one is
explicitly `connected: false`, `native: false`, and `firstParty: false`.

The provider allowlist is limited to bounded reads for:

- tailnet devices;
- one device's posture-relevant metadata;
- tailnet ACL policy metadata; and
- bounded grant metadata derived from that policy.

The result retains typed states, bounded counts, deterministic device/posture/
policy/scope/evidence digests, revision and idempotency fences, and redacted
receipts. It never retains raw API bodies, node addresses, credentials, raw
tags, ACL expressions, grant principals, or access-certification claims.

Registration is digest-bound to the contract, provider revision, exact scope,
permission snapshot, consent revision, and opaque secret reference. Reversal,
restore, and revoke are local reversible state transitions; they do not call
Tailscale or mutate devices, ACLs, grants, keys, or tags.

`BLOCKED_ENV` is the honest Layer-2 boundary. Native credential resolution,
live Tailscale API reads, durable provider receipts, independent rereads,
consented external effects, and verified Work Product/Outcome adoption remain
future Layer-2 work. An evidence result is not network reachability, effective
authorization, security truth, or an access certification.

The API basis is the [official Tailscale API reference](https://tailscale.com/docs/reference/tailscale-api).
