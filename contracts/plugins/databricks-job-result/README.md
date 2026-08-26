# Databricks job-result plugin contract

This is the versioned Layer-1 contract for the Databricks Jobs API 2.2
read/proposal/recording plugin. The implementation is the standalone nested
workspace at `hartevo-rs/databricks-job-result-plugin`.

Layer 1 intentionally stops before native OAuth resolution or any Databricks
effect. It can describe a scope, read bounded recorded metadata, compile a
`run-now` proposal, project a Mission job-result proposal, record metadata-only
evidence, and verify fingerprints. It does not create or mutate jobs, invoke
`run-now`, cancel or repair runs, execute workloads, download unbounded output,
retain raw notebook output, resolve a secret, adopt an Outcome, or claim
Connected/native evidence.

The only authentication input is an opaque OAuth machine-to-machine
`SecretReference`. Client secrets, PATs, bearer tokens, raw task output and
sensitive parameter values are not serializable contract data. Recording,
fixture, loopback and `BLOCKED_ENV` transports are explicitly non-native.
