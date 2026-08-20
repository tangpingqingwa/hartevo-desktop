# Mistral inference result — Layer 1

This contract is a standalone, provider-specific evidence seam for bounded
Mistral model-list and inference-result recordings. It binds a Mistral model
revision, task, route, request revision, Project, Mission, Work Product,
Consent, permission, and policy to a redacted proposal/evidence pair.

The Rust crate under `hartevo-rs/mistral-inference-result-plugin/` accepts only
fixture, recording, loopback, and `BLOCKED_ENV` frames. Every mode reports
`connected=false`, `native=false`, and `firstParty=false`. Prompts,
completions, embeddings, file content, tool arguments, and raw provider bodies
are never retained in serializable outputs. Only bounded metadata and digests
are projected.

This is not a kernel Truth, Consent, Effect, Receipt, Verification, or Outcome
authority. Live credential resolution, native inference, durable provider
receipts, independent readback, tool/file authority, model mutation, and
verified Work Product adoption remain Layer-2 gaps.

Primary API references:

- <https://docs.mistral.ai/developers>
- <https://docs.mistral.ai/api>
- <https://docs.mistral.ai/api/endpoint/models>
