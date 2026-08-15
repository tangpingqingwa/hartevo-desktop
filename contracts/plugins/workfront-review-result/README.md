# Workfront review-approval result Layer 1

This standalone contract is a bounded, read-only Adobe Workfront project,
task, review, and approval state seam below Hartevo Truth, Consent, Effect,
Receipt, Verification, Outcome, and Work Product authority.

The typed provider models only allowlisted GET-shaped reads for the exact
tenant/project/task/document/review/approval/assignee/time-window and
Mission/Project/Work Product scope. Projections retain immutable identifier
digests, bounded state, revision fences, decision timestamps, reviewer-role
digests, opaque pagination digests, and redacted request/cost receipts. They
never retain document bytes, document content, reviewer names or contact
details, comments, approval effects, or raw credential material.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deliberately
non-connected, non-native, and non-first-party. A proposal is review evidence
only; it is not an approval, a delivery or legal Truth claim, a durable
provider receipt, independent native read-back, verified adoption, or a second
Workfront work graph.

The operation names follow Adobe's Workfront API families: traditional
`/attask` object reads for projects and tasks and the documented Review and
Approvals surface. The checked-in implementation never opens native HTTPS or
resolves credentials; those are Layer-2 host-owned concerns.

## Layer-2 gaps

Native OAuth/API reference resolution and authenticated Workfront HTTPS;
durable provider receipts; independent read-back; project/task/document/review
or approval mutation; approve/reject/recall effects; document download or raw
proof bytes; reviewer PII and comments; host-owned consent/effect authority;
production provider connectivity; legal or delivery certification; and
verified Mission Work Product adoption remain Layer-2 work.

Primary API basis:

- [Adobe Workfront APIs](https://developer.adobe.com/workfront-apis/)
- [Workfront API basics](https://experienceleague.adobe.com/en/docs/workfront/adobe-workfront-api/api-general-information/api-basics)
