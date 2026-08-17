# Hartevo Zotero Evidence Plugin — Layer 1

This standalone workspace implements `EXT-ZOTERO-01-L1/v1`. It provides a
typed `ZoteroEvidenceService`, `ZoteroEvidenceProvider`, and
`MissionResearchEvidenceConsumer` for bounded, version-fenced Zotero research
evidence and citation proposals.

The Web API v3 (`https://api.zotero.org`) and official local API v3
(`http://localhost:23119/api`) are separate request-planning seams. The local
API has distinct provenance and is never labeled external Connected/native.
Fixtures, recordings, and loopback responses are deterministic test evidence
only and remain `BLOCKED_ENV`.

Layer 1 does not perform live private-library authentication, OAuth exchange,
create/update/delete, attachment upload, streaming reconciliation, unbounded
full-text reads, or durable evidence adoption. `SecretReference` is opaque;
only its digest may appear in diagnostics. A formatted citation is
`formatted_only` and cannot verify source truth without a matching exact item
and library version, conditional/cursor fence, metadata digests, attachment
and full-text reference digests, and registration/provider digests.

The version and conditional semantics follow the official Zotero references:

- <https://www.zotero.org/support/dev/web_api/v3/basics>
- <https://www.zotero.org/support/dev/web_api/v3/syncing>
- <https://www.zotero.org/support/dev/web_api/v3/local_api>
- <https://www.zotero.org/support/dev/web_api/v3/write_requests>
- <https://www.zotero.org/support/dev/web_api/v3/oauth>
