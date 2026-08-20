# Cohere inference result — Layer 1

This contract is a standalone, provider-specific evidence seam for bounded
Cohere chat, generate, and embed recordings. It binds a pinned model revision,
API endpoint, task, provider route, account permission, opaque secret
reference, Project, Mission, Work Product, Consent, request revision, and
policy revision to a redacted proposal/evidence pair.

The Rust crate under `hartevo-rs/cohere-inference-result-plugin/` accepts only
fixture, recording, fake, loopback, and `BLOCKED_ENV` frames. Every mode
reports `connected=false`, `native=false`, and `first_party=false`. Prompts,
completions, embedding vectors, tool arguments, and raw provider bodies are
never retained in serializable proposals or evidence. Only bounded metadata
and digests are projected.

This is not a kernel Truth, Consent, Effect, Receipt, Verification, or Outcome
authority. Native credential resolution, live inference, durable provider
receipts, independent readback, tool/file authority, model mutation, and
verified Work Product adoption remain Layer-2 gaps.

Primary API reference:

- <https://docs.cohere.com/reference/about>
