# Heroku deployment result Layer 1

This contract is a standalone, read-only Layer-1 boundary for bounded Heroku
app, build, release, slug, and dyno metadata. It produces digest-bound,
redacted Mission proposals and recordings only. It has no app, build, release,
config-var, slug, or dyno effect authority; it does not expose raw logs, source
bundles, environment values, or secrets.

The crate accepts only deterministic fixture, recording, fake, loopback, or
`BLOCKED_ENV` transports. All five are explicitly non-connected, non-native,
and non-first-party evidence. Native OAuth/token resolution, live Heroku HTTPS
transport, durable provider receipts, independent release/readback authority,
consented effects, and verified Work Product/Outcome adoption remain Layer-2
gaps.

The bounded read surface follows the official
[Heroku Platform API Reference](https://devcenter.heroku.com/articles/platform-api-reference):
`GET /apps/{app_id_or_name}`, `GET /apps/{app_id_or_name}/builds/{build_id}`
and the bounded build list, release list, slug, and dyno metadata resources.
