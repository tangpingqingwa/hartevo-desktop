# AWS AppSync API result Layer 1

This standalone contract is a bounded, read-only AWS AppSync GraphQL/Event
API configuration and deployment-evidence seam below Hartevo Truth, Consent,
Effect, Receipt, Verification, Outcome, and Work Product authority.

The provider exposes only `ListGraphqlApis`, `GetApi`,
`GetSchemaCreationStatus`, `ListDataSources`, and `ListResolvers` metadata
seams. Opaque `nextToken` values are paginated under a fixed page and page
count budget. API identity, endpoint, authentication mode, schema/revision,
deployment, data-source, and resolver values are projected as digests and
bounded counts; raw GraphQL schemas, query or subscription payloads, endpoint
secrets, resolver templates, data-source credentials, WebSocket messages, and
authorization material are never retained.

Registration binds plugin version, contract, provider/API revision, permission
snapshot, exact account/region/API/type/schema/data-source/resolver/revision
scope, opaque SecretReference, and evidence digests. Registration is
reversible and revocable. A Mission consumer emits review-only proposals and
idempotent recording receipts; it cannot adopt an Outcome or Work Product.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`. They are not
first-party provider receipts and do not certify API availability, GraphQL
business correctness, deployment health, or Work Product adoption.

## Layer-2 gaps

Native SigV4/API-key/OIDC resolution and live AWS HTTPS; durable provider
receipts; GraphQL query or subscription execution; WebSocket/event publish or
subscribe; raw schema or resolver/data-source export; API, schema, resolver,
data-source, authorization, cache, or WAF mutation; independent endpoint
read-back; production availability certification; consented effects; and
verified Mission Work Product adoption remain Layer-2 work.

The operation names and metadata boundary follow the AWS AppSync API reference:
[ListGraphqlApis](https://docs.aws.amazon.com/appsync/latest/APIReference/API_ListGraphqlApis.html),
[GetApi](https://docs.aws.amazon.com/appsync/latest/APIReference/API_GetApi.html),
[GetSchemaCreationStatus](https://docs.aws.amazon.com/appsync/latest/APIReference/API_GetSchemaCreationStatus.html),
[ListDataSources](https://docs.aws.amazon.com/appsync/latest/APIReference/API_ListDataSources.html),
and [ListResolvers](https://docs.aws.amazon.com/appsync/latest/APIReference/API_ListResolvers.html).
