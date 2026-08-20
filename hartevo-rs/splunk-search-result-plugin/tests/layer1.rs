use hartevo_splunk_search_result_plugin as splunk;
use serde_json::json;

fn scope_with_sid(sid: &str) -> splunk::SplunkSavedSearchResultScope {
    let window = splunk::SplunkSearchResultTimeWindow::new(
        "2026-08-01T00:00:00Z",
        "2026-08-02T00:00:00Z",
        3,
    )
    .expect("time window");
    let resource = splunk::SplunkProviderResourceScope::new(
        splunk::SplunkHost::new("https://splunk.example.test").expect("host"),
        "tenant-1",
        "search",
        "owner-1",
        "saved-search-1",
        sid,
        splunk::SplunkIndexAllowlist::new(["main", "audit"]).expect("index allowlist"),
        splunk::Revision::new(7).expect("search revision"),
        window,
    )
    .expect("resource scope");
    let spec = splunk::SplunkSavedSearchResultScopeSpec::new(
        resource,
        splunk::ProjectBinding::new("project-1", 4).expect("project"),
        splunk::MissionBinding::new("mission-1", 5).expect("mission"),
        splunk::WorkProductBinding::new("work-product-1", 6).expect("work product"),
        splunk::ConsentScope::new("consent-1", 2).expect("consent"),
    );
    splunk::SplunkSavedSearchResultScope::new(spec).expect("scope")
}

fn secret() -> splunk::SecretReference {
    splunk::SecretReference::token("opaque-token-handle", 9).expect("secret")
}

fn status(sid: &str, value: &str) -> serde_json::Value {
    json!({
        "sid": sid,
        "status": value,
        "queueMilliseconds": 12,
        "durationMilliseconds": 34
    })
}

#[allow(clippy::needless_pass_by_value)]
fn page(
    page: u16,
    next_page: Option<u16>,
    partial: bool,
    cells: serde_json::Value,
) -> serde_json::Value {
    let mut value = json!({
        "page": page,
        "fields": [
            {"name": "count", "type": "integer"},
            {"name": "segment", "type": "string"}
        ],
        "cells": cells,
        "partial": partial,
        "durationMilliseconds": 34
    });
    if let Some(next_page) = next_page {
        value["nextPage"] = json!(next_page);
    }
    value
}

#[allow(clippy::needless_pass_by_value)]
fn service_for(
    scope: splunk::SplunkSavedSearchResultScope,
    status_response: serde_json::Value,
    result_responses: Vec<serde_json::Value>,
) -> splunk::SplunkSavedSearchResultService<splunk::FixtureSplunkTransport> {
    let transport = splunk::FixtureSplunkTransport::new(
        splunk::SplunkHttpResponse::json(200, &status_response),
        result_responses
            .iter()
            .map(|response| splunk::SplunkHttpResponse::json(200, response))
            .collect(),
    );
    let provider = splunk::SplunkProvider::new(scope, secret(), transport).expect("provider");
    splunk::SplunkSavedSearchResultService::new(provider).expect("service")
}

#[test]
fn contract_and_layer_one_authority_are_machine_readable() {
    let document: serde_json::Value =
        serde_json::from_str(splunk::SPLUNK_SEARCH_RESULT_CONTRACT_JSON).expect("contract JSON");
    assert_eq!(
        document["schemaVersion"],
        splunk::SPLUNK_SEARCH_RESULT_SCHEMA_VERSION
    );
    assert_eq!(
        document["contractVersion"],
        splunk::SPLUNK_SEARCH_RESULT_CONTRACT_VERSION
    );
    assert_eq!(
        document["provider"]["apiRevision"],
        splunk::SPLUNK_API_REVISION
    );
    assert_eq!(
        document["provider"]["acceptedTransports"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    assert_eq!(document["provider"]["native"], false);
    assert_eq!(document["provider"]["connected"], false);
    assert_eq!(document["provider"]["first_party"], false);
    assert_eq!(
        document["allowlist"]["writes"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!splunk::contract_digest().is_empty());
    assert!(!splunk::Layer1Authority::truth_authority());
    assert!(!splunk::Layer1Authority::consent_authority());
    assert!(!splunk::Layer1Authority::effect_authority());
    assert!(!splunk::Layer1Authority::receipt_authority());
    assert!(!splunk::Layer1Authority::verification_authority());
    assert!(!splunk::Layer1Authority::outcome_authority());
}

#[test]
fn bounded_projection_is_redacted_and_deterministic() {
    let first = vec![
        json!({"count": 2, "segment": "customer@example.test"}),
        json!({"count": 1, "segment": "internal-only"}),
    ];
    let second = vec![
        json!({"segment": "internal-only", "count": 1}),
        json!({"segment": "customer@example.test", "count": 2}),
    ];
    let mut first_service = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![page(0, None, false, json!(first))],
    );
    let mut second_service = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![page(0, None, false, json!(second))],
    );
    let first_proposal = first_service.compile_proposal().expect("first proposal");
    let second_proposal = second_service.compile_proposal().expect("second proposal");
    assert_eq!(first_proposal.status(), splunk::SplunkEvidenceStatus::Done);
    assert!(first_proposal.evidence.is_actionable());
    assert_eq!(
        first_proposal.evidence.result_digest,
        second_proposal.evidence.result_digest
    );
    assert_eq!(
        first_proposal.evidence.evidence_digest,
        second_proposal.evidence.evidence_digest
    );
    let serialized = serde_json::to_string(&first_proposal).expect("proposal serializes");
    assert!(!serialized.contains("customer@example.test"));
    assert!(!serialized.contains("internal-only"));
    assert!(!serialized.contains("opaque-token-handle"));
    assert!(!serialized.contains("_raw"));
    assert!(!format!("{:?}", secret()).contains("opaque-token-handle"));
    assert!(!first_proposal.native && !first_proposal.connected && !first_proposal.first_party);
}

#[test]
fn scope_drift_and_arbitrary_spl_fail_closed() {
    let scope = scope_with_sid("sid-1");
    let registration = {
        let provider = splunk::SplunkProvider::new(
            scope.clone(),
            secret(),
            splunk::FixtureSplunkTransport::new(
                splunk::SplunkHttpResponse::json(200, &status("sid-1", "QUEUED")),
                Vec::new(),
            ),
        )
        .expect("provider");
        provider.registration().clone()
    };
    let changed_scope = scope_with_sid("sid-2");
    let result = splunk::SplunkProvider::with_registration(
        changed_scope,
        secret(),
        splunk::FixtureSplunkTransport::new(
            splunk::SplunkHttpResponse::json(200, &status("sid-2", "QUEUED")),
            Vec::new(),
        ),
        registration,
    );
    assert!(matches!(
        result,
        Err(splunk::SplunkProviderError::ScopeMismatch)
    ));

    let mut service = service_for(scope, status("sid-1", "QUEUED"), Vec::new());
    let _ = service.read().expect("read");
    let mut request = splunk::SplunkProviderRequest {
        method: splunk::SplunkHttpMethod::Get,
        host: "https://splunk.example.test".to_owned(),
        path: "/services/search/jobs/sid-1?search=index%3Dmain".to_owned(),
        operation: splunk::SplunkProviderOperation::JobStatus,
        page: None,
        search_digest: "a".repeat(64),
        sid_digest: "b".repeat(64),
        scope_digest: "c".repeat(64),
        consent_digest: "d".repeat(64),
        secret_reference_digest: "e".repeat(64),
        request_digest: String::new(),
    };
    request.request_digest = request.digest();
    assert!(!request.is_allowlisted());
}

#[test]
fn pagination_is_bounded_and_page_replay_is_tampered() {
    let mut service = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![
            page(0, Some(1), false, json!([{"count": 1, "segment": "a"}])),
            page(1, None, false, json!([{"count": 2, "segment": "b"}])),
        ],
    );
    let proposal = service.compile_proposal().expect("paginated proposal");
    assert_eq!(proposal.evidence.pages_read, 2);
    assert_eq!(proposal.evidence.aggregate_cells.len(), 2);

    let mut replayed = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![
            page(0, Some(1), false, json!([{"count": 1, "segment": "a"}])),
            page(1, Some(1), false, json!([{"count": 2, "segment": "b"}])),
        ],
    );
    let evidence = replayed.read().expect("tamper is normalized");
    assert_eq!(evidence.status, splunk::SplunkEvidenceStatus::Tampered);
    assert_eq!(
        evidence.classification,
        splunk::EvidenceClassification::Tampered
    );
    assert!(!evidence.native && !evidence.connected && !evidence.first_party);
}

#[test]
fn status_transitions_and_empty_partial_are_explicit() {
    let cases = [
        ("QUEUED", splunk::SplunkEvidenceStatus::Queued),
        ("RUNNING", splunk::SplunkEvidenceStatus::Running),
        ("FAILED", splunk::SplunkEvidenceStatus::Failed),
        ("EXPIRED", splunk::SplunkEvidenceStatus::Expired),
        ("EMPTY", splunk::SplunkEvidenceStatus::Empty),
    ];
    for (raw, expected) in cases {
        let mut service = service_for(scope_with_sid("sid-1"), status("sid-1", raw), Vec::new());
        assert_eq!(service.read().expect("status evidence").status, expected);
    }
    let mut partial = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "PARTIAL"),
        vec![page(0, None, true, json!([{"count": 1, "segment": "a"}]))],
    );
    assert_eq!(
        partial.read().expect("partial evidence").status,
        splunk::SplunkEvidenceStatus::Partial
    );
    let mut empty_done = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![page(0, None, false, json!([]))],
    );
    assert_eq!(
        empty_done.read().expect("empty result").status,
        splunk::SplunkEvidenceStatus::Empty
    );
}

#[test]
fn access_loss_http_failures_provider_unknown_and_blocked_env_are_honest() {
    for (status_code, expected) in [
        (401, splunk::SplunkEvidenceStatus::AccessLost),
        (403, splunk::SplunkEvidenceStatus::AccessLost),
        (404, splunk::SplunkEvidenceStatus::Expired),
        (429, splunk::SplunkEvidenceStatus::ProviderUnknown),
        (500, splunk::SplunkEvidenceStatus::ProviderUnknown),
    ] {
        let transport = splunk::FixtureSplunkTransport::new(
            splunk::SplunkHttpResponse::new(
                status_code,
                b"provider diagnostic with query".to_vec(),
            ),
            Vec::new(),
        );
        let provider = splunk::SplunkProvider::new(scope_with_sid("sid-1"), secret(), transport)
            .expect("provider");
        let mut service = splunk::SplunkSavedSearchResultService::new(provider).expect("service");
        let evidence = service.read().expect("HTTP failure evidence");
        assert_eq!(evidence.status, expected);
        assert!(
            !serde_json::to_string(&evidence)
                .expect("evidence serializes")
                .contains("provider diagnostic")
        );
        assert!(!evidence.native && !evidence.connected && !evidence.first_party);
    }
    let provider = splunk::SplunkProvider::new(
        scope_with_sid("sid-1"),
        secret(),
        splunk::BlockedEnvSplunkTransport,
    )
    .expect("blocked provider");
    let mut service = splunk::SplunkSavedSearchResultService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.status, splunk::SplunkEvidenceStatus::AccessLost);
    assert_eq!(
        evidence.classification,
        splunk::EvidenceClassification::BlockedEnv
    );
    assert_eq!(evidence.provenance, splunk::TransportProvenance::BlockedEnv);
}

#[test]
fn response_and_result_bounds_fail_closed_without_raw_projection() {
    let oversized =
        splunk::SplunkHttpResponse::new(200, vec![b'x'; splunk::MAX_RESPONSE_BYTES + 1]);
    let provider = splunk::SplunkProvider::new(
        scope_with_sid("sid-1"),
        secret(),
        splunk::FixtureSplunkTransport::new(oversized, Vec::new()),
    )
    .expect("provider");
    let mut service = splunk::SplunkSavedSearchResultService::new(provider).expect("service");
    assert_eq!(
        service.read().expect("bound evidence").status,
        splunk::SplunkEvidenceStatus::Tampered
    );

    let too_many = (0..=splunk::MAX_CELLS_PER_PAGE)
        .map(|count| json!({"count": count, "segment": "bounded"}))
        .collect::<Vec<_>>();
    let mut service = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![page(0, None, false, json!(too_many))],
    );
    assert_eq!(
        service.read().expect("result bound evidence").status,
        splunk::SplunkEvidenceStatus::Tampered
    );
}

#[test]
fn registration_is_reversible_rotates_digest_and_rejects_old_proposals() {
    let mut service = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![page(0, None, false, json!([{"count": 1, "segment": "a"}]))],
    );
    let original = service.registration().registration_digest.clone();
    let old_proposal = service.compile_proposal().expect("old proposal");
    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.state, splunk::RegistrationState::Revoked);
    assert_ne!(revoked.registration_digest, original);
    assert_eq!(
        service.read().expect("revoked evidence").status,
        splunk::SplunkEvidenceStatus::Revoked
    );
    assert!(matches!(
        service.compile_proposal(),
        Err(splunk::SplunkSavedSearchResultServiceError::RegistrationRevoked)
    ));
    let restored = service.restore().expect("restore");
    assert_eq!(restored.state, splunk::RegistrationState::Active);
    assert_ne!(restored.registration_digest, original);
    assert!(matches!(
        service.verify_proposal(&old_proposal),
        Err(
            splunk::SplunkSavedSearchResultServiceError::EvidenceMismatch
                | splunk::SplunkSavedSearchResultServiceError::RegistrationRevoked,
        )
    ));
}

#[test]
fn mission_consumer_rejects_replay_and_tamper_without_outcome_authority() {
    let provider = splunk::SplunkProvider::new(
        scope_with_sid("sid-1"),
        secret(),
        splunk::FixtureSplunkTransport::new(
            splunk::SplunkHttpResponse::json(200, &status("sid-1", "DONE")),
            vec![splunk::SplunkHttpResponse::json(
                200,
                &page(0, None, false, json!([{"count": 1, "segment": "a"}])),
            )],
        ),
    )
    .expect("provider");
    let mut consumer = splunk::MissionSplunkSearchConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        splunk::MissionSplunkSearchResultState::DecisionReady
    );
    assert!(result.proposal_only);
    assert!(!result.native && !result.connected && !result.first_party);
    assert!(!result.adopts_outcome && !result.adopts_work_product);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(splunk::MissionSplunkSearchConsumerError::ReplayDetected)
    ));

    let mut tampered = proposal;
    tampered.evidence.aggregate_partial = true;
    assert!(matches!(
        consumer.consume(&tampered),
        Err(splunk::MissionSplunkSearchConsumerError::Service(
            splunk::SplunkSavedSearchResultServiceError::EvidenceMismatch
        ))
    ));
}

#[test]
fn invalid_time_window_index_and_raw_event_payloads_are_rejected() {
    assert!(
        splunk::SplunkSearchResultTimeWindow::new(
            "2026-08-02T00:00:00Z",
            "2026-08-01T00:00:00Z",
            1
        )
        .is_err()
    );
    assert!(splunk::SplunkIndexAllowlist::new(Vec::<String>::new()).is_err());
    let mut service = service_for(
        scope_with_sid("sid-1"),
        status("sid-1", "DONE"),
        vec![json!({
            "page": 0,
            "fields": [{"name": "count", "type": "integer"}],
            "cells": [{"count": 1}],
            "results": [{"_raw": "secret event"}]
        })],
    );
    let evidence = service.read().expect("raw payload becomes tampered");
    assert_eq!(evidence.status, splunk::SplunkEvidenceStatus::Tampered);
    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("secret event"));
    assert!(!serialized.contains("_raw"));
}
