## Change and owner

- Change summary:
- Owner/task identity:

<!-- Ordinary feature or routine dependency PRs use only this small block. -->
<!-- hartevo-governance
{
  "schema": "hartevo-pr-admission/v1",
  "changeClass": "feature",
  "owner": "replace-with-one-accountable-owner"
}
-->

<!--
High-risk governance, security, destructive, release, recovery, and
path-sensitive policy changes must instead include positive Issue, exact owned
paths, concrete rollback, and false externalEffects/release fields:

{
  "schema": "hartevo-pr-admission/v1",
  "changeClass": "governance",
  "issue": 0,
  "owner": "replace-with-one-accountable-owner",
  "ownedPaths": ["replace/with/exact/path-or-directory"],
  "rollback": "replace-with-a-specific-recovery-plan",
  "externalEffects": false,
  "release": false
}
-->

## Evidence

- [ ] Local workflow syntax and policy checks pass.
- [ ] Relevant Rust/catalog/evidence gates were run.
- [ ] New evidence is bound to the current commit and does not promote Release/E-level authority.
- [ ] `PASS`, `CODE_FAILURE`, `INFRA_FAILURE`, and `CI_NOT_EXECUTED` are classified honestly where applicable.

## Migrations and contracts

- [ ] No schema, data, or distribution contract migration is needed.
- [ ] If a migration is needed, describe expand/verify/rollback here:
- [ ] #82 distribution outputs are consumed only through the narrow future hook, if applicable.

## Environment and rollback

- `BLOCKED_ENV` / `NOT_IMPLEMENTED` conditions:
- Rollback or recovery plan (required only for high-risk changes):
- External effects, deployments, or long-lived credentials: none unless explicitly described.

## Release safety

- Release enabled: `false`
- [ ] No direct or force push to `main`.
- [ ] No production deployment or tag mutation is performed by this PR.
- [ ] The `hartevo-governance` block is complete for the selected change class.
- [ ] Ordinary feature/dependency PRs will receive one exact-head GitHub `COMMENTED` or `APPROVED` review with the strict `hartevo-github-review/v1` marker and a reviewer task distinct from the owner.
- [ ] High-risk changes include the exact receipt-only review commit; a later code push invalidates that receipt and GitHub review.
