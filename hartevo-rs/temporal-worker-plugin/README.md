# Hartevo Temporal worker plugin — Layer 1

This is a standalone crate and contract for the `EXT-TEMPORAL-01` root Draft.
It maps a typed Mission/Worker plan to a digest-bound proposal containing
Workflow, Activity, Signal, Query, Timer, retry, heartbeat, Continue-As-New,
and cancellation commands.

Layer 1 is plan/read/recording/verification only. `RecordingTransport` and
`FakeTemporalTransport` retain typed metadata and digests, not Temporal payload
bytes or credentials. Same-digest commands replay deterministically; conflicting
commands fail closed. `RecoveryReceipt` proves the local recorded sequence can
be replayed without an uncertain duplicate, while `OutcomeReceipt` explicitly
does not promote Temporal history to Hartevo Outcome authority.

Real Temporal gRPC, Temporal Cloud, and a native worker remain
`BLOCKED_ENV`. This crate does not depend on or modify the root Cargo workspace,
Application, Domain, Storage, mission scheduler, existing providers, or
integration scripts.
