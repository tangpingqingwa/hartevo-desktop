# TikTok authenticated read plugin

This standalone package is the first-layer TikTok read boundary for
CHANNEL-01. It owns no publish, reply, browser-scraping, or Connector SDK
code.

The public real-read entrypoint is execute_real_read_gate. It is
environment-gated:

~~~text
HARTEVO_TIKTOK_REAL_READ=1
HARTEVO_TIKTOK_SECRET_REFERENCE=keychain://tiktok/<account>
~~~

The transport receives an opaque SecretReference; OAuth access and refresh
tokens stay in the external credential service. The provider calls only the
official Display API read surfaces:

- user.info.basic for creator identity/probe;
- video.list for durable cursor pagination;
- video.query for independent video/performance readback.

Every result carries tenant/business/account scope, exact provider identity,
revision digest, source generation, freshness, and provenance. Fixture and
controlled-provider results are deterministic test evidence and are rejected
by the Mission consumer. Production admission also requires an exact bound
revision, live credential, matching secret reference, and fresh evidence.

Missing real-read environment or credential material returns typed
BlockedEnvironment; it does not upgrade a local fake transport to first-party
evidence.
