# AWS Personalize recommendation result — Layer 1

This contract is a standalone, bounded proposal seam for Amazon Personalize
campaign and recommender metadata plus recommendation/ranking evidence.

The owned Rust crate accepts only the four allowlisted read seams:

- `DescribeCampaign`
- `DescribeRecommender`
- `GetRecommendations`
- `GetPersonalizedRanking`

It projects campaign/recommender status, model-revision digests, redacted item
or action identifiers, rank, and score buckets. User identifiers, profile
fields, catalog fields, request context, filter expressions, raw provider
bodies, model bytes, and credential material never enter a serializable
projection. Every scope is exact-account/region/domain/target/filter and
fingerprint bound to one Project, Mission, and Work Product revision.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deterministic
test seams. They never claim `connected`, `native`, or `first_party` evidence.
The crate does not resolve credentials, issue native HTTPS, mutate campaigns or
recommenders, train/import models, create provider receipts, verify outcomes,
or adopt a Work Product.
