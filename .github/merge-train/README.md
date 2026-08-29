# Optional merge-train manifests

`manifests/` contains immutable historical train receipts. A train writes one
new manifest named from its exact `merge-train/*` branch. CI discovers the
single manifest added by that train and verifies its exact history, tree,
candidates, review evidence, paths, and hosted checks.

There is deliberately no `current.json`: live GitHub open-PR state is the
only current-train pointer. Historical manifests are never coordination state
and must not be rewritten.

## When to use a train

An ordinary Cordis feature or routine dependency PR goes through scoped checks,
one independent exact-head GitHub review, and a direct protected merge. A
train is optional and reserved for a multi-PR integration, release milestone,
or explicit high-risk combination. It is not an ordinary required check and
there is no `Governance / Train-only merge` context in the protected ruleset.

## Evidence compatibility

`ci-merge-train.py prepare` creates a bounded local composition and immutable
manifest. New ordinary candidates carry a `hartevo-github-review/v1` evidence
record whose reviewer marker is bound to the candidate head. High-risk
candidates continue to carry exact receipt-only review commits. Existing
manifests retain their historical receipt fields and are validated unchanged;
the verifier accepts both forms without rewriting old files.

`ci-merge-train.py publish` revalidates the live base, candidate tuples, four
stable required checks, admission, review evidence, history, tree, and the
single-open-train invariant. It performs one normal push and opens one
non-Draft PR; it does not merge. The trusted train check reconstructs each
merge and the full Integration matrix runs only for the milestone train.
