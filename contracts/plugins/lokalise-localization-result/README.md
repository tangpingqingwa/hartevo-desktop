# Lokalise localization-result contract

This Layer-1 contract is a bounded, read-only evidence and proposal seam for
one Lokalise team/project/branch/file/language scope. It normalizes translation,
review, QA, task and export-process metadata into counts and deterministic
content/build digests. Source text, translated text, translator identity,
comments, screenshots, URLs and raw response bodies never leave the provider
parser.

The checked-in Rust crate is a standalone nested workspace at
`hartevo-rs/lokalise-localization-result-plugin`. Its only transports are
fixture, recording, loopback and `BLOCKED_ENV`. Native HTTPS, credential
resolution, export/download effects, approval, publication and independent
native readback remain explicit Layer-2 gaps.

The allowlisted API basis is the official Lokalise REST API v2: project and
branch metadata, languages, files, translations, tasks and background-process
GET endpoints. Translation reads use bounded cursor pagination. See the
[Lokalise REST API](https://developers.lokalise.com/reference/lokalise-rest-api)
and [list all translations](https://developers.lokalise.com/reference/list-all-translations)
references for the provider surface.
