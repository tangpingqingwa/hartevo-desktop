# GitHub CodeQL result — Layer 1

This standalone contract describes a bounded, read-only GitHub Advanced
Security code-scanning evidence seam. It is scoped to one GitHub App or OAuth
installation, repository, ref, commit, CodeQL analysis, rule, alert, and
Hartevo Mission/Project/Work Product binding.

The implementation retains alert identity, rule, tool, state, severity, commit,
and digest-only location metadata. It never retains source, SARIF, raw bearer
material, user identity, or unbounded provider locations. No API operation can
dismiss or fix an alert, upload SARIF, trigger a scan, mutate a branch or pull
request, or adopt a kernel Outcome.

Fixture, recording, loopback, and BLOCKED_ENV transports are intentionally
non-native and disconnected. Layer 2 must provide consented App/OAuth
resolution, live HTTPS reads, durable provider receipts, independent repeat
reads, verified Work Product adoption, and any remediation effect authority.
