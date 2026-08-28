# AssemblyAI transcript-result Layer 1 plugin

This standalone nested workspace owns a bounded, read-only AssemblyAI
transcript-result seam. It binds a transcript job to an exact AssemblyAI host,
account, source and revision, transcript and revision, model/config revision,
bounded utterance segment scope, Mission, Hartevo Project, Work Product, and
read-permission snapshot.

The typed `AssemblyAiTranscriptResultService`, `AssemblyAiProvider`, and
`MissionTranscriptResultConsumer` project only redacted metadata, language,
provider speaker labels, utterance timing/confidence evidence, chapter/summary
metadata, and bounded status/segment/content/registration digests. No raw audio,
raw transcript body, unredacted text, speaker identity, API key, provider error
text, or opaque page token is retained or serialized.

Fake, recording, loopback, and `BLOCKED_ENV` transports are deterministic test
surfaces. Every one reports `connected = false`, `native = false`, and
`first_party = false`; recording is in-memory and is not a durable provider
receipt. The crate owns no external write, upload, arbitrary media fetch,
submission, polling, model training, Outcome adoption, kernel authority, or
verified Work Product adoption.

Native API-key resolution, live HTTPS reads, transcript submission/polling,
durable receipts, independent readback, and verified Work Product adoption are
Layer-2 gaps. HeyGen #315 remains the owner of generated video artifacts, while
document/artifact and retrieval providers remain distinct.

The contract is checked in at
`contracts/plugins/assemblyai-transcript-result/assemblyai-transcript-result.v1.json`.
