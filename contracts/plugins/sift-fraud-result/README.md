# Sift fraud decision evidence result Layer 1

This standalone contract is a bounded, read-only Sift decision, score, review,
and workflow-status evidence seam below Hartevo Truth, Consent, Effect,
Receipt, Verification, Outcome, and Work Product authority.

The typed provider exposes only latest decision status, a bounded score, and a
recorded workflow-status seam. Entity, decision, score, review, abuse-type,
Project, Mission, and Work Product values are digest-bound in evidence. API
keys are opaque, non-serializing `SecretReference` values.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`. They are not
first-party provider receipts. Allow, deny, and review are provider-reported
dispositions only; they are not fraud certainty, clearance, proof, or effects.

## Layer-2 gaps

Native API-key resolution and live Sift HTTPS; durable provider receipts;
independent reread/reconciliation; event ingestion; block/allow effects;
workflow or review mutation; raw PII or score-reason export; fraud certainty;
consented effects; and verified Mission Work Product/Outcome adoption remain
Layer-2 work.
