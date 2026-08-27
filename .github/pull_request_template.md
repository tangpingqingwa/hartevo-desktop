## Issue and intent

- Issue: <!-- #number -->
- Change summary:
- Scope kept to:

<!-- Replace every placeholder before opening the PR. This block is parsed by CI. -->
<!-- hartevo-governance
{
  "schema": "hartevo-pr-admission/v1",
  "changeClass": "review-repair",
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
- Rollback or recovery plan:
- External effects, deployments, or long-lived credentials: none unless explicitly described.

## Release safety

- Release enabled: `false`
- [ ] No direct or force push to `main`.
- [ ] No production deployment or tag mutation is performed by this PR.
- [ ] The `hartevo-governance` block is complete and covers every changed path.
- [ ] For an ordinary candidate, `ownedPaths` includes `.github/governance/reviews/pr-<this-number>.json` before the receipt commit is appended.
- [ ] A non-author task will append the exact review receipt as the final receipt-only commit before train admission.
