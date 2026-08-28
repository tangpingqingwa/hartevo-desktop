use std::collections::BTreeMap;

use serde_json::json;

use crate::{
    ApplicationState, ConsentReceipt, ConsentScope, Digest, FixtureTransport, GreenhouseError,
    GreenhouseHarvestProvider, GreenhouseHiringResultService, GreenhouseScope, HarvestExchange,
    HarvestHttpResponse, HiringDecision, JobId, MissionGreenhouseHiringConsumer,
    MissionHiringRequest, MissionId, OrganizationId, ProjectId, ProposalRequest, ProviderId,
    ReadBackRequest, Revision, SecretKind, SecretReference, StageId, TransportProvenance,
    WorkProductId,
};

fn secret() -> SecretReference {
    SecretReference::for_testing("greenhouse-test-key", 7, SecretKind::HarvestApiKey)
        .expect("opaque test secret")
}

fn scope() -> GreenhouseScope {
    GreenhouseScope::new(
        OrganizationId::new("org-1").expect("organization"),
        JobId::new("job-1").expect("job"),
        crate::ApplicationId::new("application-1").expect("application"),
        None,
        Some(StageId::new("stage-1").expect("stage")),
        None,
        None,
        MissionId::new("mission-1").expect("mission"),
        ProjectId::new("project-1").expect("project"),
        WorkProductId::new("work-product-1").expect("work product"),
        crate::CapabilitySet::read_only(),
        ConsentScope::read_only_hiring_evidence(10_000).expect("consent scope"),
    )
    .expect("scope")
}

fn response(status: u16, body: serde_json::Value) -> HarvestHttpResponse {
    HarvestHttpResponse::json(status, &body)
}

fn routes(status: &str, scorecard: bool) -> BTreeMap<String, Vec<HarvestHttpResponse>> {
    let scope = scope();
    let mut routes = BTreeMap::new();
    routes.insert(
        format!("/v1/jobs/{}", scope.job_id),
        vec![response(
            200,
            json!({"id": "job-1", "title": "Backend role"}),
        )],
    );
    routes.insert(
        format!("/v1/applications/{}", scope.application_id),
        vec![response(
            200,
            json!({
                "id": "application-1",
                "candidate_id": "candidate-secret-id",
                "candidate_name": "Alice Example",
                "email": "alice@example.invalid",
                "phone": "+1-555-0100",
                "resume_url": "https://candidate.invalid/resume.pdf",
                "demographic": {"ethnicity": "redacted"},
                "interview_notes": "private note",
                "status": status,
                "revision": 12,
                "updated_at": "2026-08-14T00:00:00Z"
            }),
        )],
    );
    routes.insert(
        String::from("/v1/candidates/candidate-secret-id/activity_feed"),
        vec![response(
            200,
            json!([{
                "id": "activity-1",
                "stage_id": "stage-1",
                "stage_name": "Phone screen",
                "entered_at": "2026-08-13T00:00:00Z",
                "exited_at": "2026-08-13T01:00:00Z"
            }]),
        )],
    );
    routes.insert(
        format!("/v1/applications/{}/scorecards", scope.application_id),
        if scorecard {
            vec![response(
                200,
                json!([{
                    "id": "scorecard-1",
                    "sections_completed": 3,
                    "sections_total": 3,
                    "average_score_bps": 8400,
                    "submitted_at": "2026-08-13T02:00:00Z",
                    "answers": [{"question": "private", "answer": "raw answer"}]
                }]),
            )]
        } else {
            vec![response(200, json!([]))]
        },
    );
    routes.insert(
        format!("/v1/applications/{}/offers", scope.application_id),
        vec![response(
            200,
            json!([{
                "id": "offer-1",
                "status": "sent",
                "created_at": "2026-08-13T03:00:00Z",
                "sent_at": "2026-08-13T03:01:00Z",
                "compensation_amount": 999_999,
                "attachment_url": "https://candidate.invalid/offer.pdf"
            }]),
        )],
    );
    routes
}

fn provider_with_routes(status: &str, scorecard: bool) -> GreenhouseHarvestProvider {
    GreenhouseHarvestProvider::new(secret(), FixtureTransport::new(routes(status, scorecard)))
        .expect("fixture provider")
}

#[test]
fn fixture_is_bounded_redacted_and_never_connected() {
    let mut provider = provider_with_routes("active", true);
    let evidence = provider.read(&scope()).expect("fixture read");
    evidence.validate_integrity().expect("evidence integrity");
    assert_eq!(evidence.state, ApplicationState::Active);
    assert_eq!(evidence.stage_transitions.len(), 1);
    assert!(
        evidence
            .scorecard
            .as_ref()
            .expect("scorecard")
            .is_complete()
    );
    assert!(!evidence.is_hiring_success_claim());
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(
        evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.method == "GET" && !receipt.connected && !receipt.native)
    );
    assert!(
        evidence
            .request_receipts
            .iter()
            .all(|receipt| !receipt.endpoint.contains("candidate-secret-id"))
    );
    let serialized = serde_json::to_string(&evidence).expect("safe evidence serializes");
    for forbidden in [
        "Alice Example",
        "alice@example.invalid",
        "+1-555-0100",
        "resume.pdf",
        "private note",
        "raw answer",
        "candidate-secret-id",
    ] {
        assert!(!serialized.contains(forbidden), "PII leaked: {forbidden}");
    }
}

#[test]
fn recording_and_link_pagination_retry_are_deterministic() {
    let base = routes("hired", true);
    let scope = scope();
    let scorecard_path = format!("/v1/applications/{}/scorecards", scope.application_id);
    let scorecard_page_two = format!("{scorecard_path}?page=2");
    let mut recording_routes = base;
    recording_routes.insert(
        scorecard_path.clone(),
        vec![
            response(429, json!({"error": "rate limited"})),
            response(
                200,
                json!([{
                    "id": "scorecard-1",
                    "sections_completed": 2,
                    "sections_total": 3,
                    "average_score_bps": 7000
                }]),
            )
            .with_link(format!(
                "<https://harvest.greenhouse.test{scorecard_page_two}>; rel=\"next\""
            )),
        ],
    );
    recording_routes.insert(
        scorecard_page_two.clone(),
        vec![response(
            200,
            json!([{
                "id": "scorecard-2",
                "sections_completed": 1,
                "sections_total": 1,
                "average_score_bps": 9000
            }]),
        )],
    );
    let mut provider =
        GreenhouseHarvestProvider::new(secret(), crate::RecordingTransport::new(recording_routes))
            .expect("recording provider");
    let evidence = provider.read(&scope).expect("recorded read");
    assert_eq!(evidence.state, ApplicationState::Hired);
    assert!(!evidence.is_hiring_success_claim());
    let scorecard_receipt = evidence
        .request_receipts
        .iter()
        .find(|receipt| receipt.endpoint == scorecard_path)
        .expect("scorecard request receipt");
    assert_eq!(scorecard_receipt.attempts, 2);
    assert_eq!(scorecard_receipt.backoff_delays_ms, vec![100]);
    assert!(
        evidence
            .request_receipts
            .iter()
            .any(|receipt| receipt.endpoint == scorecard_page_two)
    );
    assert!(
        evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.method == "GET")
    );
}

#[test]
fn loopback_and_blocked_env_never_claim_native() {
    let scope = scope();
    let mut loopback = GreenhouseHarvestProvider::loopback(secret(), routes("active", false))
        .expect("loopback provider");
    let evidence = loopback.read(&scope).expect("loopback read");
    assert!(
        evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.provenance == TransportProvenance::Loopback)
    );
    assert!(!evidence.connected);
    assert!(!evidence.native);

    let mut blocked = GreenhouseHarvestProvider::blocked_env(secret()).expect("blocked provider");
    assert_eq!(blocked.read(&scope), Err(GreenhouseError::BlockedEnv));
    assert_eq!(
        blocked.transport_provenance(),
        TransportProvenance::BlockedEnv
    );
}

#[test]
fn mission_proposal_is_consent_scope_revision_and_digest_fenced() {
    let scope = scope();
    let mut provider = provider_with_routes("hired", false);
    let service = GreenhouseHiringResultService::new().expect("service");
    let registration = service
        .register_scope(
            scope.clone(),
            provider.definition(),
            provider.secret_reference(),
        )
        .expect("registration");
    assert!(registration.is_active());
    assert_eq!(
        registration.provider_id,
        ProviderId::new("greenhouse.harvest.hiring-result")
            .expect("provider id")
            .to_string()
    );
    let consumer = MissionGreenhouseHiringConsumer::new(registration.clone()).expect("consumer");
    let consent = ConsentReceipt::grant(&scope, 100).expect("consent receipt");
    let result = consumer
        .read_and_propose(
            &mut provider,
            MissionHiringRequest {
                scope: scope.clone(),
                proposal: ProposalRequest {
                    objective: crate::HiringObjective::new("select next human review")
                        .expect("objective"),
                    consent: consent.clone(),
                    expected_provider_revision: Some(Revision::new(12).expect("revision")),
                    expected_evidence_digest: None,
                    now_epoch_seconds: 100,
                },
            },
        )
        .expect("proposal");
    assert_eq!(result.evidence.state, ApplicationState::Hired);
    assert_eq!(result.proposal.decision, HiringDecision::HoldForEvidence);
    assert!(!result.proposal.effect.executable);
    assert_eq!(result.proposal.effect.required_layer, 2);
    assert!(!result.proposal.native);
    assert!(!result.proposal.adopted_outcome);

    let mut recording_service = GreenhouseHiringResultService::new().expect("recording service");
    let recording = recording_service
        .record_result(
            &registration,
            result.evidence.clone(),
            result.proposal.clone(),
        )
        .expect("recording");
    recording.validate().expect("recording integrity");
    let read_back = recording_service
        .read_back_recorded_result(&ReadBackRequest {
            receipt_id: recording.receipt.receipt_id.clone(),
            scope_digest: scope.digest(),
            expected_evidence_digest: recording.evidence.evidence_digest.clone(),
            registration_revision: registration.registration_revision,
        })
        .expect("read back");
    assert!(read_back.verified);
    assert!(!read_back.independent_provider_read_back);

    let mut reversed = registration.clone();
    reversed.reverse().expect("reversible registration");
    assert_eq!(reversed.state, crate::RegistrationState::Reversed);
    assert_eq!(
        reversed.reverse(),
        Err(GreenhouseError::RegistrationTransitionNotAllowed)
    );
    let mut revoked = registration.clone();
    revoked.revoke().expect("revocable registration");
    assert_eq!(revoked.state, crate::RegistrationState::Revoked);
    assert_eq!(
        revoked.ensure_active(),
        Err(GreenhouseError::RegistrationRevoked)
    );

    let mut stale_request = consent;
    stale_request.withdraw();
    let error = GreenhouseHiringResultService::new()
        .expect("service")
        .compile_result_proposal(
            &registration,
            &result.evidence,
            &ProposalRequest {
                objective: crate::HiringObjective::new("stale").expect("objective"),
                consent: stale_request,
                expected_provider_revision: None,
                expected_evidence_digest: Some(Digest::from_text("different")),
                now_epoch_seconds: 100,
            },
        )
        .expect_err("withdrawn or stale proposal must fail");
    assert!(matches!(error, GreenhouseError::ConsentUnavailable));
}

#[test]
fn access_loss_and_provider_unknown_are_explicit_projections() {
    let scope = scope();
    let mut access_routes = routes("active", false);
    access_routes.insert(
        format!("/v1/applications/{}", scope.application_id),
        vec![response(403, json!({"error": "forbidden"}))],
    );
    let mut access_provider =
        GreenhouseHarvestProvider::new(secret(), FixtureTransport::new(access_routes))
            .expect("access provider");
    let access = access_provider
        .read(&scope)
        .expect("access-loss projection");
    assert_eq!(access.state, ApplicationState::AccessLost);
    assert_eq!(
        access.completeness,
        crate::EvidenceCompleteness::Unavailable
    );

    let mut unknown_routes = routes("active", false);
    unknown_routes.insert(
        format!("/v1/jobs/{}", scope.job_id),
        vec![response(404, json!({"error": "not found"}))],
    );
    let mut unknown_provider =
        GreenhouseHarvestProvider::new(secret(), FixtureTransport::new(unknown_routes))
            .expect("unknown provider");
    let unknown = unknown_provider
        .read(&scope)
        .expect("provider-unknown projection");
    assert_eq!(unknown.state, ApplicationState::ProviderUnknown);
    assert_eq!(
        unknown.completeness,
        crate::EvidenceCompleteness::Unavailable
    );
}

#[test]
fn unsafe_pagination_link_is_rejected_before_transport_use() {
    let scope = scope();
    let mut unsafe_routes = routes("active", false);
    unsafe_routes.insert(
        String::from("/v1/candidates/candidate-secret-id/activity_feed"),
        vec![response(200, json!([])).with_link(
            "<https://harvest.greenhouse.test/v1/candidates/candidate-1>; rel=\"next\"",
        )],
    );
    let mut provider =
        GreenhouseHarvestProvider::new(secret(), FixtureTransport::new(unsafe_routes))
            .expect("unsafe-link provider");
    assert!(matches!(
        provider.read(&scope),
        Err(GreenhouseError::EndpointNotAllowed { .. })
    ));
}

#[test]
fn secret_reference_debug_does_not_contain_the_supplied_label() {
    let reference = SecretReference::for_testing("raw-greenhouse-key", 1, SecretKind::OAuth)
        .expect("secret reference");
    let debug = format!("{reference:?}");
    assert!(!debug.contains("raw-greenhouse-key"));
    assert!(debug.contains("reference_digest"));
}

#[test]
fn recording_transport_accepts_explicit_exchanges() {
    let scope = scope();
    let base = routes("rejected", false);
    let exchanges = base
        .into_iter()
        .map(|(path, responses)| {
            HarvestExchange::new(path, responses.into_iter().next().expect("response"))
        })
        .collect::<Vec<_>>();
    let mut provider =
        GreenhouseHarvestProvider::recording(secret(), exchanges).expect("recording provider");
    let evidence = provider.read(&scope).expect("recorded evidence");
    assert_eq!(evidence.state, ApplicationState::Rejected);
    assert_eq!(
        evidence
            .request_receipts
            .first()
            .expect("receipt")
            .provenance,
        TransportProvenance::Recording
    );
}
