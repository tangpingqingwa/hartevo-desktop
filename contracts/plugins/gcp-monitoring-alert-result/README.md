# GCP Monitoring alert result — Layer 1

This contract is a bounded, read-only proposal and recording seam for Google
Cloud Monitoring alert-policy and alert evidence. It is deliberately below
Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, dashboard, and
incident-causality authority.

The provider names only the Google Monitoring `alertPolicies.list`,
`alertPolicies.get`, `alerts.list`, and `alerts.get` reads. Its transports are
fixture, recording, loopback, and `BLOCKED_ENV`; each is non-connected,
non-native, and non-first-party.

The scope binds the metrics scope, scoping/monitored projects, policy and alert
allowlists, monitored-resource allowlist, Mission, Hartevo Project, permission
and consent digests. Page tokens are opaque and retained only as digests.
Policy state, alert open/closed/unspecified state, severity, and open/close
timestamps are typed. Metric/resource/log labels and policy filter values are
discarded after hashing; raw telemetry, log labels, dashboard data, and causal
incident claims are not retained.

Registration is digest-bound and reversible. Proposals require response fences,
bounded list/get evidence, deterministic proposal digests, idempotent recording,
and deterministic read-back. Policy, snooze, notification-channel, dashboard,
and remediation mutations remain forbidden. Native Google credentials/HTTPS,
durable provider receipts, independent rereads, consented effects, and verified
adoption remain Layer-2 exits through host authority.
