#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Utc};
use hartevo_slack_decision_result_plugin::{
    ChannelId, DecisionFingerprint, Digest, FixtureSlackTransport, LoopbackSlackTransport,
    MissionBinding, MissionId, MissionScope, ParticipantClass, ProjectBinding, ProjectId,
    RecordingSlackTransport, RedactionState, RetentionState, Revision, SecretReference,
    SlackDecisionContract, SlackDecisionScope, SlackDecisionService, SlackEvidenceState,
    SlackMessageProjection, SlackProvider, SlackReadPage, SlackReadRequest, TeamId, ThreadId,
    TimeWindow, TokenScope, TransportProvenance, WorkProductBinding, WorkProductId, WorkspaceId,
};

fn at(day: u8) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-08-{day:02}T00:00:00Z"))
        .expect("valid test timestamp")
        .with_timezone(&Utc)
}

fn scope() -> SlackDecisionScope {
    SlackDecisionScope::new(
        WorkspaceId::new("workspace-1").expect("workspace"),
        TeamId::new("team-1").expect("team"),
        ChannelId::new("channel-1").expect("channel"),
        ThreadId::new("thread-1.000001").expect("thread"),
        TimeWindow::new(at(1), at(2)).expect("window"),
        DecisionFingerprint::from_text("decision fingerprint input"),
        MissionScope::new(
            MissionBinding::new(
                MissionId::new("mission-1").expect("mission"),
                Revision::new(2).expect("mission revision"),
            ),
            ProjectBinding::new(
                ProjectId::new("project-1").expect("project"),
                Revision::new(3).expect("project revision"),
            ),
            WorkProductBinding::new(
                WorkProductId::new("work-product-1").expect("Work Product"),
                Revision::new(4).expect("Work Product revision"),
            ),
        ),
        TokenScope::read_only(),
    )
    .expect("scope")
}

fn message(day: u8, marker: Option<&str>) -> SlackMessageProjection {
    SlackMessageProjection::new(
        at(day),
        Digest::from_text(format!("message-{day}")),
        Digest::from_text(format!("content-{day}")),
        Digest::from_text(format!("reaction-{day}")),
        marker.map(Digest::from_text),
        u16::from(day),
        ParticipantClass::User,
    )
    .expect("redacted message projection")
}

fn service() -> SlackDecisionService<RecordingSlackTransport> {
    let scope = scope();
    let secret = SecretReference::for_bot("opaque-bot-reference", &scope).expect("secret");
    let provider = SlackProvider::new(RecordingSlackTransport::default()).expect("provider");
    SlackDecisionService::new(scope, secret, provider).expect("service")
}

fn push_page(
    service: &mut SlackDecisionService<RecordingSlackTransport>,
    request: &SlackReadRequest,
    page_number: u16,
    messages: Vec<SlackMessageProjection>,
    next_cursor: Option<hartevo_slack_decision_result_plugin::OpaqueCursor>,
) {
    let page = SlackReadPage::new(
        request,
        page_number,
        messages,
        next_cursor,
        512,
        RetentionState::WithinWindow,
        RedactionState::Redacted,
        TransportProvenance::Recording,
    )
    .expect("page");
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(page));
}

#[test]
fn contract_scope_and_registration_are_explicitly_bound() {
    SlackDecisionContract::baseline().expect("contract");
    let service = service();
    assert!(service.is_active());
    assert_eq!(
        service.registration().provider_id.as_str(),
        "slack.conversations.read"
    );
    assert_ne!(service.registration().scope_digest, Digest::zero());
    assert_ne!(service.registration().token_scope_digest, Digest::zero());
    assert_ne!(service.registration().evidence_digest, Digest::zero());
    assert_eq!(service.scope().workspace.as_str(), "workspace-1");
    assert_eq!(service.scope().team.as_str(), "team-1");
    assert_eq!(service.scope().channel.as_str(), "channel-1");
    assert_eq!(service.scope().thread.as_str(), "thread-1.000001");
    assert_eq!(service.scope().mission.mission.id.as_str(), "mission-1");
}

#[test]
fn secret_and_cursor_are_opaque_and_never_retain_raw_material() {
    let scope = scope();
    let secret = SecretReference::for_user("raw-user-token-reference", &scope).expect("secret");
    let encoded = serde_json::to_string(&secret).expect("secret JSON");
    assert_eq!(encoded, r#"{"opaque":true}"#);
    assert!(!format!("{secret:?}").contains("raw-user-token-reference"));

    let cursor = hartevo_slack_decision_result_plugin::OpaqueCursor::new("raw-provider-cursor")
        .expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{cursor:?}").contains("raw-provider-cursor"));
    let request = SlackReadRequest::history(&scope, 50, 4, Some(cursor)).expect("request");
    let encoded_request = serde_json::to_string(&request).expect("request JSON");
    assert!(!encoded_request.contains("raw-provider-cursor"));
}

#[test]
fn bounded_history_proposal_record_verify_and_mission_consume_stay_non_native() {
    let scope = scope();
    let mut service = service();
    let request = SlackReadRequest::history(&scope, 50, 4, None).expect("request");
    push_page(
        &mut service,
        &request,
        1,
        vec![message(1, Some("marker"))],
        None,
    );

    let read = service.read_bounded(request.clone()).expect("read");
    assert_eq!(read.evidence.state, SlackEvidenceState::Complete);
    assert_eq!(read.evidence.message_count, 1);
    assert_eq!(read.evidence.reply_count, 1);
    assert!(!read.evidence.connected);
    assert!(!read.evidence.native);
    assert!(!read.evidence.first_party);
    assert!(!read.evidence.raw_message_export);
    assert!(!read.evidence.member_pii);

    push_page(
        &mut service,
        &request,
        1,
        vec![message(1, Some("marker"))],
        None,
    );
    let proposal = service.propose(request, at(3)).expect("proposal");
    assert!(proposal.requires_human_review);
    assert!(!proposal.safe_to_promote);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.adopted_outcome);

    let consumer = hartevo_slack_decision_result_plugin::MissionSlackDecisionConsumer::new(
        scope.clone(),
        service.registration().clone(),
    )
    .expect("consumer");
    let mission_result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(
        mission_result.decision_state,
        hartevo_slack_decision_result_plugin::SlackDecisionState::DecisionObserved
    );
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.adopted_outcome);
    assert!(!mission_result.truth_authority);

    let record = service.record_at(&proposal, at(4)).expect("record");
    assert!(record.recorded);
    assert!(!record.durable_native_receipt);
    let verified = service.verify(&record).expect("verify");
    assert!(verified.verified);
    assert!(!verified.connected);
    assert!(!verified.native);
    assert!(!verified.adopted_outcome);
}

#[test]
fn replies_cursor_loop_and_bounds_fail_closed() {
    let scope = scope();
    let mut service = service();
    let request = SlackReadRequest::replies(&scope, 50, 4, None).expect("request");
    let cursor =
        hartevo_slack_decision_result_plugin::OpaqueCursor::new("page-two").expect("cursor");
    push_page(
        &mut service,
        &request,
        1,
        vec![message(1, Some("marker"))],
        Some(cursor.clone()),
    );
    let next_request = request
        .clone()
        .with_cursor(Some(cursor.clone()))
        .expect("next request");
    push_page(
        &mut service,
        &next_request,
        2,
        vec![message(2, None)],
        Some(cursor),
    );
    let result = service.read(request).expect("bounded loop read");
    assert_eq!(result.evidence.state, SlackEvidenceState::CursorLoop);
    assert_eq!(result.evidence.page_count, 2);

    let mismatched = SlackReadRequest::history(&scope, 50, 4, None).expect("history request");
    assert!(
        mismatched
            .with_cursor(Some(
                hartevo_slack_decision_result_plugin::OpaqueCursor::new("cursor")
                    .expect("cursor")
                    .bind(&Digest::from_text("other-request")),
            ))
            .is_err()
    );
}

#[test]
fn retention_redaction_provider_errors_and_blocked_env_never_claim_native() {
    let scope = scope();
    let secret = SecretReference::for_bot("opaque-bot", &scope).expect("secret");
    let provider = SlackProvider::new(FixtureSlackTransport::default()).expect("provider");
    let mut retention_service =
        SlackDecisionService::new(scope.clone(), secret, provider).expect("service");
    let request = SlackReadRequest::history(&scope, 50, 4, None).expect("request");
    let page = SlackReadPage::new(
        &request,
        1,
        vec![message(1, None)],
        None,
        512,
        RetentionState::Unavailable,
        RedactionState::Redacted,
        TransportProvenance::Fixture,
    )
    .expect("retention page");
    retention_service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(page));
    let result = retention_service.read(request).expect("retention state");
    assert_eq!(
        result.evidence.state,
        SlackEvidenceState::RetentionUnavailable
    );
    assert!(!result.evidence.native);

    let redaction_provider =
        SlackProvider::new(FixtureSlackTransport::default()).expect("provider");
    let redaction_secret =
        SecretReference::for_bot("opaque-redaction-bot", &scope).expect("secret");
    let mut redaction =
        SlackDecisionService::new(scope.clone(), redaction_secret, redaction_provider)
            .expect("redaction service");
    let redaction_request = SlackReadRequest::history(&scope, 50, 4, None).expect("request");
    let redaction_page = SlackReadPage::new(
        &redaction_request,
        1,
        vec![message(1, None)],
        None,
        512,
        RetentionState::WithinWindow,
        RedactionState::Unredacted,
        TransportProvenance::Fixture,
    )
    .expect("unredacted page");
    redaction
        .provider_mut()
        .transport_mut()
        .push_response(Ok(redaction_page));
    let result = redaction.read(redaction_request).expect("redaction state");
    assert_eq!(result.evidence.state, SlackEvidenceState::RedactionLoss);
    assert!(!result.evidence.native);

    let blocked_provider =
        SlackProvider::new(hartevo_slack_decision_result_plugin::BlockedEnvSlackTransport)
            .expect("blocked provider");
    let blocked_secret = SecretReference::for_user("opaque-user", &scope).expect("secret");
    let mut blocked = SlackDecisionService::new(scope.clone(), blocked_secret, blocked_provider)
        .expect("blocked service");
    let result = blocked
        .read(SlackReadRequest::replies(&scope, 50, 4, None).expect("replies"))
        .expect("blocked read");
    assert_eq!(result.evidence.state, SlackEvidenceState::ProviderUnknown);
    assert_eq!(result.evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!result.evidence.connected);
    assert!(!result.evidence.native);
    assert!(!result.evidence.first_party);

    let mut revoked_secret_service = service();
    revoked_secret_service.revoke_secret_reference();
    assert!(
        revoked_secret_service
            .read(SlackReadRequest::history(&scope, 50, 4, None).expect("request"))
            .is_err()
    );

    let _ = LoopbackSlackTransport::default();
}

#[test]
fn proposal_tamper_and_registration_revocation_are_fail_closed() {
    let scope = scope();
    let mut service = service();
    let request = SlackReadRequest::history(&scope, 50, 4, None).expect("request");
    push_page(
        &mut service,
        &request,
        1,
        vec![message(1, Some("marker"))],
        None,
    );
    let proposal = service.propose(request, at(3)).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.message_count = 99;
    assert!(service.verify_proposal(&tampered).is_err());

    let record = service.record_at(&proposal, at(4)).expect("record");
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    assert!(service.record(&proposal).is_err());
    assert!(service.verify(&record).is_err());
    assert!(service.revoke_registration().is_err());
}
