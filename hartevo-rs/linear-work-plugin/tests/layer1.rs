use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use hartevo_linear_work_plugin::{
    ExternalWorkGraphService, LINEAR_PLUGIN_ID, LINEAR_WORK_CONTRACT_VERSION,
    LINEAR_WORK_SCHEMA_VERSION, LinearAccessToken, LinearActorIdentity, LinearAppId,
    LinearAppIdentity, LinearCapabilityComposition, LinearCapabilityState, LinearCursor,
    LinearGraphQlRequest, LinearGraphQlResponse, LinearGraphQlTransport, LinearIssueProposalField,
    LinearMissionId, LinearMissionWorkConsumer, LinearMissionWorkRequest, LinearOAuthInstallation,
    LinearOAuthWorkProvider, LinearOrganizationId, LinearPageRequest, LinearPluginDefinition,
    LinearProposalKind, LinearProviderError, LinearProviderProvenance, LinearRateLimitReceipt,
    LinearRevocationReason, LinearScopeSet, LinearTeamId, LinearUserId, LinearWebhookError,
    LinearWebhookHeaders, LinearWebhookOutcome, LinearWorkProposal,
};
use ring::hmac;
use serde_json::{Value, json};

const NOW_MS: u64 = 1_700_000_000_000;

#[derive(Debug)]
struct FixtureTransport {
    responses: VecDeque<LinearGraphQlResponse>,
    requests: Vec<LinearGraphQlRequest>,
}

impl FixtureTransport {
    fn new(responses: impl IntoIterator<Item = LinearGraphQlResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl LinearGraphQlTransport for FixtureTransport {
    fn execute(
        &mut self,
        request: &LinearGraphQlRequest,
    ) -> Result<LinearGraphQlResponse, hartevo_linear_work_plugin::LinearTransportError> {
        self.requests.push(request.clone());
        self.responses.pop_front().ok_or_else(|| {
            hartevo_linear_work_plugin::LinearTransportError::Http("fixture exhausted".to_owned())
        })
    }
}

fn installation() -> LinearOAuthInstallation {
    LinearOAuthInstallation::new(
        LinearOrganizationId::new("org-1").expect("organization"),
        [LinearTeamId::new("team-1").expect("team")],
        LinearActorIdentity::User(LinearUserId::new("user-1").expect("user")),
        LinearAppIdentity::new("client-1", Some(LinearAppId::new("app-1").expect("app")))
            .expect("app identity"),
        LinearScopeSet::new(vec!["read".to_owned(), "comments:create".to_owned()]).expect("scopes"),
        NOW_MS + 300_000,
        LinearAccessToken::new("oauth-token").expect("token"),
    )
    .expect("installation")
}

fn response(data: Value, remaining: u64) -> LinearGraphQlResponse {
    let mut headers = BTreeMap::new();
    headers.insert("X-RateLimit-Requests-Limit".to_owned(), "5000".to_owned());
    headers.insert(
        "X-RateLimit-Requests-Remaining".to_owned(),
        remaining.to_string(),
    );
    headers.insert(
        "X-RateLimit-Requests-Reset".to_owned(),
        (NOW_MS + 60_000).to_string(),
    );
    let mut envelope = serde_json::Map::new();
    envelope.insert("data".to_owned(), data);
    LinearGraphQlResponse::new(200, headers, Value::Object(envelope).to_string())
}

fn page_info(has_next_page: bool, end_cursor: Option<&str>) -> Value {
    json!({"hasNextPage": has_next_page, "endCursor": end_cursor})
}

fn probe_response() -> LinearGraphQlResponse {
    response(
        json!({
            "viewer": {"id": "user-1", "name": "Fixture User"},
            "organization": {"id": "org-1", "name": "Fixture Org"},
            "teams": {
                "nodes": [{"id": "team-1", "name": "Engineering", "key": "ENG"}],
                "pageInfo": page_info(false, None)
            }
        }),
        4999,
    )
}

fn issue_response() -> LinearGraphQlResponse {
    response(
        json!({
            "team": {
                "id": "team-1",
                "issues": {
                    "nodes": [{
                        "id": "issue-1",
                        "identifier": "ENG-1",
                        "title": "Read-only work item",
                        "description": "Fixture issue",
                        "priority": 2,
                        "createdAt": "2026-08-14T00:00:00.000Z",
                        "updatedAt": "2026-08-14T00:01:00.000Z",
                        "archivedAt": null,
                        "state": {"id": "state-1", "name": "Todo", "type": "backlog"},
                        "project": null,
                        "cycle": null
                    }],
                    "pageInfo": page_info(true, Some("cursor-1"))
                }
            }
        }),
        4998,
    )
}

fn project_response() -> LinearGraphQlResponse {
    response(
        json!({
            "team": {
                "id": "team-1",
                "projects": {
                    "nodes": [{
                        "id": "project-1",
                        "name": "Layer 1",
                        "description": null,
                        "state": {"id": "project-state-1", "name": "planned", "type": "planned"},
                        "startDate": null,
                        "targetDate": null,
                        "updatedAt": "2026-08-14T00:01:00.000Z"
                    }],
                    "pageInfo": page_info(false, None)
                }
            }
        }),
        4997,
    )
}

fn cycle_response() -> LinearGraphQlResponse {
    response(
        json!({
            "team": {
                "id": "team-1",
                "cycles": {
                    "nodes": [{
                        "id": "cycle-1",
                        "name": "Cycle 1",
                        "number": 1,
                        "description": null,
                        "startsAt": null,
                        "endsAt": null,
                        "completedAt": null,
                        "updatedAt": "2026-08-14T00:01:00.000Z"
                    }],
                    "pageInfo": page_info(false, None)
                }
            }
        }),
        4996,
    )
}

fn rate_limited_response() -> LinearGraphQlResponse {
    let mut headers = BTreeMap::new();
    headers.insert("X-RateLimit-Requests-Limit".to_owned(), "5000".to_owned());
    headers.insert("X-RateLimit-Requests-Remaining".to_owned(), "0".to_owned());
    headers.insert(
        "X-RateLimit-Requests-Reset".to_owned(),
        (NOW_MS + 30_000).to_string(),
    );
    LinearGraphQlResponse::new(
        400,
        headers,
        json!({
            "errors": [{
                "message": "rate limited",
                "extensions": {"code": "RATELIMITED"}
            }]
        })
        .to_string(),
    )
}

fn missing_team_probe_response() -> LinearGraphQlResponse {
    response(
        json!({
            "viewer": {"id": "user-1", "name": "Fixture User"},
            "organization": {"id": "org-1", "name": "Fixture Org"},
            "teams": {"nodes": [], "pageInfo": page_info(false, None)}
        }),
        4999,
    )
}

#[test]
fn oauth_probe_and_bounded_reads_are_scoped_and_receipted() {
    let transport = FixtureTransport::new([
        probe_response(),
        issue_response(),
        project_response(),
        cycle_response(),
    ]);
    let mut provider = LinearOAuthWorkProvider::new(transport, installation());

    let probe = provider.probe_at(NOW_MS).expect("probe");
    assert_eq!(probe.organization_id.as_str(), "org-1");
    assert_eq!(probe.observed_team_ids.len(), 1);
    assert_eq!(probe.rate_limit.requests_remaining, Some(4999));
    assert!(!provider.is_native());
    assert!(!provider.is_connected());
    assert!(matches!(
        provider.state(),
        LinearCapabilityState::Connected {
            provenance: LinearProviderProvenance::Fixture,
            ..
        }
    ));

    let page = LinearPageRequest::new(10, None).expect("page");
    let issues = provider
        .read_issues_at(LinearTeamId::new("team-1").expect("team"), &page, NOW_MS)
        .expect("issues");
    assert_eq!(issues.nodes[0].identifier.as_deref(), Some("ENG-1"));
    assert_eq!(issues.read.returned_count, 1);
    assert_eq!(
        issues
            .read
            .page_info
            .end_cursor
            .as_ref()
            .map(LinearCursor::as_str),
        Some("cursor-1")
    );
    assert_eq!(issues.read.rate_limit.requests_remaining, Some(4998));

    let projects = provider
        .read_projects_at(LinearTeamId::new("team-1").expect("team"), &page, NOW_MS)
        .expect("projects");
    assert_eq!(projects.nodes[0].name, "Layer 1");
    assert_eq!(
        projects.nodes[0].state.as_ref().expect("state").name,
        "planned"
    );

    let cycles = provider
        .read_cycles_at(LinearTeamId::new("team-1").expect("team"), &page, NOW_MS)
        .expect("cycles");
    assert_eq!(cycles.nodes[0].number, Some(1));

    let transport = provider.transport_mut();
    assert_eq!(transport.requests.len(), 4);
    assert!(
        transport
            .requests
            .iter()
            .all(|request| !request.query().contains("mutation"))
    );
    assert_eq!(transport.requests[1].variables()["teamId"], "team-1");
    assert_eq!(transport.requests[1].variables()["first"], 10);
}

#[test]
fn rate_limit_errors_are_typed_and_team_scope_loss_revokes_the_mount() {
    let mut rate_limited = LinearOAuthWorkProvider::new(
        FixtureTransport::new([probe_response(), rate_limited_response()]),
        installation(),
    );
    rate_limited.probe_at(NOW_MS).expect("probe");
    let page = LinearPageRequest::new(10, None).expect("page");
    let error = rate_limited
        .read_issues_at(LinearTeamId::new("team-1").expect("team"), &page, NOW_MS)
        .expect_err("rate limit");
    assert!(matches!(
        error,
        LinearProviderError::RateLimited { rate_limit, .. }
            if rate_limit.requests_remaining == Some(0)
    ));
    assert!(matches!(
        rate_limited.state(),
        LinearCapabilityState::Connected { .. }
    ));

    let mut scope_lost = LinearOAuthWorkProvider::new(
        FixtureTransport::new([missing_team_probe_response()]),
        installation(),
    );
    assert!(matches!(
        scope_lost.probe_at(NOW_MS),
        Err(LinearProviderError::MissingTeamScope(_))
    ));
    assert!(matches!(
        scope_lost.state(),
        LinearCapabilityState::Revoked {
            reason: LinearRevocationReason::PermissionChange,
            ..
        }
    ));

    let mut expired =
        LinearOAuthWorkProvider::new(FixtureTransport::new([probe_response()]), installation());
    expired.probe_at(NOW_MS).expect("probe");
    let error = expired
        .read_issues_at(
            LinearTeamId::new("team-1").expect("team"),
            &page,
            NOW_MS + 300_000,
        )
        .expect_err("expired token");
    assert!(matches!(error, LinearProviderError::TokenExpired));
    assert!(matches!(
        expired.state(),
        LinearCapabilityState::Revoked {
            reason: LinearRevocationReason::TokenExpired,
            ..
        }
    ));
}

fn signed_headers(
    body: &[u8],
    delivery_id: &str,
    event: &str,
    timestamp_ms: u64,
) -> LinearWebhookHeaders {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"webhook-secret");
    let signature = hex::encode(hmac::sign(&key, body).as_ref());
    LinearWebhookHeaders::new(signature, delivery_id, event, Some(timestamp_ms)).expect("headers")
}

#[test]
fn webhook_signature_timestamp_and_delivery_fence_revoke_immediately() {
    let mut provider =
        LinearOAuthWorkProvider::new(FixtureTransport::new([probe_response()]), installation());
    provider.probe_at(NOW_MS).expect("probe");

    let stale_body = json!({
        "action": "update",
        "type": "Issue",
        "organizationId": "org-1",
        "data": {"teamId": "team-1"},
        "webhookTimestamp": NOW_MS - 61_000,
        "webhookId": "stale-delivery"
    })
    .to_string();
    let stale_headers = signed_headers(
        stale_body.as_bytes(),
        "stale-delivery",
        "Issue",
        NOW_MS - 61_000,
    );
    assert!(matches!(
        provider.receive_webhook(
            stale_body.as_bytes(),
            stale_headers,
            b"webhook-secret",
            NOW_MS,
        ),
        Err(LinearProviderError::Webhook(
            LinearWebhookError::ReplayWindow { .. }
        ))
    ));

    let body = json!({
        "action": "update",
        "type": "Issue",
        "organizationId": "org-1",
        "data": {"teamId": "team-1"},
        "webhookTimestamp": NOW_MS,
        "webhookId": "delivery-1"
    })
    .to_string();
    let headers = signed_headers(body.as_bytes(), "delivery-1", "Issue", NOW_MS);
    assert!(matches!(
        provider
            .receive_webhook(body.as_bytes(), headers.clone(), b"webhook-secret", NOW_MS)
            .expect("first delivery"),
        LinearWebhookOutcome::Accepted(_)
    ));
    assert!(matches!(
        provider
            .receive_webhook(body.as_bytes(), headers, b"webhook-secret", NOW_MS)
            .expect("duplicate delivery"),
        LinearWebhookOutcome::Duplicate { .. }
    ));

    let permission_body = json!({
        "action": "update",
        "type": "PermissionChange",
        "organizationId": "org-1",
        "data": {"teamId": "team-1"},
        "webhookTimestamp": NOW_MS,
        "webhookId": "delivery-2"
    })
    .to_string();
    let permission_headers = signed_headers(
        permission_body.as_bytes(),
        "delivery-2",
        "PermissionChange",
        NOW_MS,
    );
    provider
        .receive_webhook(
            permission_body.as_bytes(),
            permission_headers,
            b"webhook-secret",
            NOW_MS,
        )
        .expect("permission event");
    assert!(matches!(
        provider.state(),
        LinearCapabilityState::Revoked {
            reason: LinearRevocationReason::PermissionChange,
            ..
        }
    ));
}

#[test]
fn mission_consumer_emits_one_canonical_non_mutating_proposal() {
    let capability = LinearCapabilityComposition::new(
        LinearOrganizationId::new("org-1").expect("organization"),
        [LinearTeamId::new("team-1").expect("team")],
        LinearProviderProvenance::Fixture,
    )
    .expect("capability");
    let request = LinearMissionWorkRequest::new(
        LinearMissionId::new("mission-1").expect("mission"),
        "Prepare the next bounded work step",
        capability,
        LinearTeamId::new("team-1").expect("team"),
        LinearProposalKind::Comment {
            issue_id: hartevo_linear_work_plugin::LinearIssueId::new("issue-1").expect("issue"),
            body: "A transparent, approval-ready proposal".to_owned(),
        },
    )
    .expect("request");
    let consumer = LinearMissionWorkConsumer::new();
    let first = consumer.propose(request.clone()).expect("proposal");
    let second = consumer.propose(request).expect("proposal");
    assert_eq!(first.canonical_digest, second.canonical_digest);
    assert!(first.is_adoptable());
    assert!(!first.external_mutation_performed);
    assert!(first.adoptable_result().mission_truth_source);
    assert_eq!(first.proposal_version, LinearWorkProposal::VERSION);
}

#[test]
fn contract_and_service_definition_are_explicitly_layer_one() {
    let definition = LinearPluginDefinition::baseline();
    assert_eq!(definition.plugin_id, LINEAR_PLUGIN_ID);
    assert!(!definition.provider.agent_session_developer_preview);
    assert!(!definition.provider.has_store_authority);
    assert!(!definition.provider.has_keyring_authority);
    assert!(!definition.provider.has_browser_profile_authority);
    assert!(!definition.provider.has_effect_authority);
    assert!(!definition.mission_consumer.mutating_graphql_operations);
    assert_eq!(
        definition.service.id,
        ExternalWorkGraphService::baseline().id
    );
    assert_eq!(
        LINEAR_WORK_SCHEMA_VERSION,
        "hartevo-linear-work-plugin-contract/v1"
    );
    assert_eq!(LINEAR_WORK_CONTRACT_VERSION, "linear-work-e1/v1");
    assert_eq!(LinearRateLimitReceipt::default().requests_limit, None);
    let _ = LinearIssueProposalField::Title;
}

#[allow(dead_code)]
fn _assert_debug<T: fmt::Debug>() {}
