# OpenFGA authorization decision result Layer 1

This standalone contract is a bounded, read-only OpenFGA model/check/tuple
observation seam below Hartevo Truth, Consent, Effect, Receipt, Verification,
Outcome, and Work Product authority.

The service can observe one exact Store/Authorization Model scope, one exact
authorization check, and one exact tuple-read scope. Store, model, user,
object, relation, tuple, Project, Mission, and Work Product identifiers are
represented in evidence by digests. Model evidence retains only bounded counts
and a model/rules digest; check evidence retains only the decision and digest
fences; tuple evidence retains only tuple-key digests. Raw model JSON, raw
tuple keys, raw identifiers, authorization headers, and credential material
are never recorded.

Registration is consent-, revision-, provider-, permission-, scope-, and
secret-reference-digest bound. Revoke and restore are reversible registration
transitions. Proposal, Mission consumption, recording, and verification are
review-only; no operation writes tuples, changes an authorization model, grants
authorization, adopts an Outcome, or adopts a Work Product.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, `first_party=false`, and
`provider_receipt=false`. They are test/evidence seams, not native OpenFGA
connectivity or first-party provider receipts.

## Layer-2 gaps

Native credential resolution and live OpenFGA HTTPS; durable provider receipts;
independent readback and consistency verification; tuple/model mutation;
authorization grant authority; consented effects; production policy truth;
verified Work Product/Outcome adoption; and any connected/native provider
claim remain Layer-2 work.
