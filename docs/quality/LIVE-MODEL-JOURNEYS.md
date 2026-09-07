# Live model journeys

Status: **Current**. These are opt-in development checks, not Release Evidence or a claim that a complete growth workflow is ready.

The Rust native route accepts `openai-compatible` and `grok-compatible` explicitly through `HARTEVO_RUNTIME_PROVIDER`. Existing `deepseek-official` and OpenInterpreter selections retain their routes. The compatible adapters share bounded HTTPS/SSE framing, tool-history translation, credential resolution and normalized errors with the DeepSeek transport. They preserve the configured provider/model identity and do not send DeepSeek's `thinking` extension or assume its reasoning levels. OpenAI requests use `max_completion_tokens`; Grok requests use `max_tokens`.

Configure `HARTEVO_RUNTIME_API_BASE` with an HTTPS API prefix ending in `/v1`, `HARTEVO_RUNTIME_MODEL` with a model available on that endpoint, and `HARTEVO_RUNTIME_API_KEY_ENV` with the **name** of the credential environment variable. The named credential is resolved per call and never enters Session events. Optional `HARTEVO_RUNTIME_CONTEXT_TOKENS` and `HARTEVO_RUNTIME_MAX_TOKENS` set conservative local limits (defaults: 32768 and 4096). These are caller limits, not verified model specifications; exact tokenizer and distribution evidence remain false. This is a native transport route, not a new model-settings UI or a Responses API implementation.

## Run the paid checks

The runner parses `.env` as data; it does not source shell code. It expects `base_url`, `gpt_api` and `grok_api`, maps one credential into each child process, creates a private output directory, and records content-free receipts plus synthetic campaign artifacts. No real customer data, publication, account connection, email or channel write is needed.

```sh
cargo test --locked -p hartevo-desktop --lib --no-run
python3 scripts/run-live-model-journeys.py \
  --env-file /absolute/path/to/.env \
  --output /absolute/path/to/new-private-run \
  --test-binary /absolute/path/to/the/hartevo_desktop-test-executable \
  --mode text --gpt-model gpt-6 --grok-model grok-4.6 --allow-paid
```

Use the executable printed by Cargo, not the desktop app executable. Ordinary Cargo/CI runs ignore the paid test. A zero-test executable, missing receipt, incorrect identity, absent assertion, extra/missing model call or altered draft causes the runner to fail even if the child exits successfully. The runner records SHA256 hashes of itself and the test binary before starting each case.

Each provider runs one VM-04 campaign Mission: persist the Mission, generate a real draft, revise it within the same conversation, check that the original answer was sent as context, replay the correction without another provider call, close the original coordinator, reopen SQLCipher and the exact Cordis Session, adopt the resulting WorkProduct, and reject a stale adoption. Exactly two model requests should occur. The transport observer has a six-request hard stop to bound accidental retries.

This traverses Desktop data-plane dispatch, the real native HTTP adapter, Cordis, Application adoption and SQLCipher. The test supplies the paint acknowledgement and uses `MemorySecretStore` for isolated encryption keys. It does **not** prove a rendered native window, OS Keychain, a separate-process restart, public channel delivery, business outcomes, a media-generation workflow or release readiness. Runtime draft text may contain the model's structured response; this check does not prove a polished content editor.

## Media capability probes

```sh
python3 scripts/run-live-model-journeys.py \
  --env-file /absolute/path/to/.env \
  --output /absolute/path/to/new-private-media-run \
  --mode media --allow-paid
```

This makes one image request each to `gpt-image-2` and `grok-imagine-image-2.0`, and one three-second `grok-imagine-video-1.5` request. These are **provider probes**, not Desktop media-flow tests. Media generation and import are not being added to the Mission tool menu by this change. Endpoint aliases and reported model names are evidence of the configured gateway's behavior, not independent attestation of its upstream model.

Image receipts verify PNG/JPEG dimensions against the requested size/aspect ratio; an image that exists but violates those constraints is retained as a failed artifact. Video receipts verify an MP4 signature and record provider-reported duration. Decode video tracks/frames and visually inspect prompt compliance separately before accepting creative assets; successful transport does not establish visual correctness.

The initial video request ID is persisted before polling. A failed/uncertain POST is never automatically resubmitted. When a job was issued successfully, recover that exact job using GETs only:

```sh
python3 scripts/run-live-model-journeys.py \
  --env-file /absolute/path/to/.env \
  --output /absolute/path/to/existing-private-media-run \
  --mode recover-video --allow-paid
```

Recovery preserves the initial receipt and writes a separate recovery receipt with `postAttempts: 0`. Root-relative gateway asset URLs resolve to the configured HTTPS origin. Only that exact origin may receive its API credential; other asset origins receive no credential, undergo a public-address check and cannot redirect. Provider response bodies, bearer tokens and signed asset URLs are not included in receipts or console output.

Run offline runner checks with `python3 scripts/test-live-model-journeys.py`. They cover missing/false receipts, modified artifacts, configuration parsing, real-world image dimension mismatch, credential origin boundaries and GET-only video recovery.

API references: [OpenAI image generation](https://developers.openai.com/api/docs/guides/image-generation), [xAI image generation](https://docs.x.ai/developers/model-capabilities/images/generation), [xAI video generation](https://docs.x.ai/developers/model-capabilities/video/generation). Product acceptance still follows the repository's Mission and Release contracts.
