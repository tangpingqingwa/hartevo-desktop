# Merge-train manifests

`manifests/` contains immutable historical train receipts. A train writes one
new manifest named from its exact `merge-train/*` branch. CI discovers the
single manifest added by that train and verifies its exact history, tree,
candidates, review receipts, paths, and hosted checks.

There is deliberately no `current.json`: live GitHub open-PR state is the
only current-train pointer. Historical receipts must never masquerade as live
coordination state.

`ci-merge-train.py prepare` creates the bounded local composition and immutable
manifest. `ci-merge-train.py publish` revalidates it, performs one normal push,
and creates one exact non-Draft train PR. Only the protected-branch trusted
admission workflow can satisfy `Governance / Train-only merge`.
