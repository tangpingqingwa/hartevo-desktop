# CHANNEL-01 phase 1: official read-only channel boundaries

This document records the phase-one boundary implemented by
`hartevo-channel-adapters`. It is deliberately provider-specific and does
not duplicate the generic Connector SDK requested by CONN-01 (#67). The SDK
remote branch was not available when this change was built, so this crate
stops at typed request planning, response parsing, and observation contracts.

## Read-only surfaces

| Provider | Probe/read surface | Authorization and policy facts | Quota/visibility handling |
| --- | --- | --- | --- |
| YouTube | OAuth `channels.list?mine=true`, `videos.list`, `commentThreads.list`, and YouTube Analytics `reports` queries | Channel ID, uploads playlist, ETag, video/comment identity, and revision are retained as typed values | Data API units are ledgered at documented costs; Analytics requests are counted separately without inventing a Data API unit cost |
| TikTok | OAuth identity response, Content Posting API `creator_info/query`, and `status/fetch` | `open_id`, user-granted scopes, token expiry timestamps, app approval, and audit state are modeled without storing token material | Unaudited clients expose `PrivateOnlyUnaudited`; public eligibility requires the approved/audited state and a provider status showing a public post ID |
| Reddit | Approved Data API calls on `oauth.reddit.com`, or an installed Devvit Reddit API surface | The mode is machine-selected from recorded approval/scopes or Devvit installation permission | Missing approval returns typed `AuthorizationRequired`; removed/filtered/deleted content is a typed moderation state |

The Reddit planner has no browser scraping or browser fallback path. Devvit is
limited to the installed community and its supported read surfaces; account
identity is rejected as `UnsupportedSurface` there. An unapproved Data API
integration is not treated as connected.

## Identity, revocation, and late events

Provider/account/channel/content/revision identities are distinct types. A
revision is bound to its content identity and provider, so a provider ID or
ETag cannot be accidentally reused across adapters. HTTP authorization failures
are surfaced as typed authorization or credential-revocation failures. YouTube
quota exhaustion and provider rate limiting are also typed.

Webhook observations carry an exact content and revision identity. The shared
ledger is idempotent: a repeated event is `Duplicate`, while a new event with
an older occurrence time is `Late` and cannot regress the latest known
occurrence.

Requests accept only opaque credential references. Secret-looking request body
keys are rejected, and response/request debug output contains a body digest
instead of body or token material.

## Evidence boundary

The deterministic worlds in `src/testkit.rs` and
`tests/phase1_contracts.rs` prove contract behavior only. They are not
production provider evidence and must not elevate catalog evidence above E0.
This checkout has no real YouTube/TikTok/Reddit credentials, Reddit approval
record, TikTok audited-client state, or production webhook signing setup, so
live provider verification remains `BLOCKED_ENV`.

Phase one intentionally does not expose publish, reply, or any other effect
operation. Phase two can add user-approved effects only after independent
readback is available.

## Official references

- [YouTube Data API: Getting started](https://developers.google.com/youtube/v3/getting-started)
- [YouTube channels.list](https://developers.google.com/youtube/v3/docs/channels/list)
- [YouTube Analytics reports.query](https://developers.google.com/youtube/analytics/reference/reports/query)
- [YouTube quota costs](https://developers.google.com/youtube/v3/determine_quota_cost)
- [YouTube developer policies](https://developers.google.com/youtube/terms/developer-policies)
- [TikTok Content Posting API: Get started](https://developers.tiktok.com/doc/content-posting-api-get-started)
- [TikTok Query Creator Info](https://developers.tiktok.com/doc/content-posting-api-reference-query-creator-info)
- [TikTok Get Post Status](https://developers.tiktok.com/doc/content-posting-api-reference-get-video-status)
- [TikTok scopes](https://developers.tiktok.com/doc/scopes-overview)
- [Reddit API documentation](https://www.reddit.com/dev/api/)
- [Reddit Responsible Builder Policy](https://support.reddithelp.com/hc/en-us/articles/42728983564564-Responsible-Builder-Policy)
- [Devvit Reddit API](https://developers.reddit.com/docs/capabilities/server/reddit-api)
