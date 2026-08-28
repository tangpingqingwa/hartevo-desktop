# SonarQube quality-result plugin contract

This directory owns the standalone Layer-1 contract for Issue #400
(`EXT-SONARQUBE-01`). The contract binds one exact SonarQube host,
organization, project, branch-or-pull-request selector, analysis, quality
gate, and bounded measure selection to one Hartevo Project/Mission/Work
Product scope.

`hartevo-rs/sonarqube-quality-result-plugin/` is an independent nested Cargo
workspace. `SonarQubeQualityResultService`, `SonarQubeProvider`, and
`MissionSonarQubeQualityConsumer` expose only typed read, proposal, and local
recording seams. The provider allowlist is limited to:

- `/api/project_analyses/search`
- `/api/qualitygates/project_status`
- `/api/measures/component`

The service never executes an analysis, changes issues or quality gates,
creates webhooks, exports source, evaluates arbitrary query DSL, writes a
dashboard, or adopts a kernel Truth/Consent/Effect/Receipt/Verification/
Outcome. Quality-gate and measure values are bounded metadata only.

Bearer credentials are represented by an opaque non-serializable
`SecretReference`. Only its digest, kind, and revision can appear in a
registration or proposal. Registration is reversible (unmount/remount) and
revocable; revocation and secret revocation fence future reads and proposal
recording.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are explicitly
non-native and non-connected. They never claim first-party, verified, or
durable provider evidence. Native bearer resolution, live HTTPS reads,
durable provider receipts, independent read-back, verified Work Product
adoption, and release approval remain Layer-2 gaps.

Primary API references:

- [SonarQube Web API](https://docs.sonarsource.com/sonarqube-server/extension-guide/web-api)
- [Understanding quality gates](https://docs.sonarsource.com/sonarqube-server/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates)
- [Get project quality gate status](https://next.sonarqube.com/sonarqube/web_api/api/qualitygates/get_by_project)
