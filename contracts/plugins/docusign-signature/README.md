# DocuSign signature plugin — Layer 1

This contract is a typed, read/recording-only boundary for approval-gated
signatures. It can propose an envelope, project a redacted recorded receipt
and recipient statuses, and produce a revision-fenced signed-result adoption
proposal.

Layer 1 never creates or sends a live envelope, starts a signing ceremony,
downloads or asserts PDF contents, consumes a live Connect webhook, performs
independent document readback, or reports Connected/native evidence. Fixture,
loopback, and BLOCKED_ENV observations remain explicitly non-connected. The
HTTPS/OAuth 2.0 transport is a Layer-2 seam only; authentication is an opaque
SecretReference and no token, signer PII, document bytes, or raw provider
payload is retained.
