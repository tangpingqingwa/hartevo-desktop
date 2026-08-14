use std::time::Duration;

use hartevo_qualtrics_survey_result_plugin::{
    AnswerPage, BoundedAnswer, ConsentStatus, DatacenterId, Digest, DistributionId,
    FixtureQualtricsTransport, MissionQualtricsSurveyConsumer, OrganizationId, ProviderProvenance,
    QualtricsPayload, QualtricsProvider, QualtricsResultBounds, QualtricsResultState,
    QualtricsScope, QualtricsSurveyResultRequest, QualtricsSurveyResultService, QuestionId,
    QuestionKind, RecordingQualtricsTransport, ResponseId, ResponseMetadata, ResponseStatus,
    ResponseStatusEvidence, Revision, SecretReference, SurveyAnswer, SurveyId, SurveyLifecycle,
    SurveyMetadata,
};

fn scope() -> QualtricsScope {
    QualtricsScope::new(
        DatacenterId::new("ca1").expect("datacenter"),
        OrganizationId::new("org-1").expect("organization"),
        SurveyId::new("SV_1").expect("survey"),
        hartevo_qualtrics_survey_result_plugin::MissionId::new("mission-1").expect("mission"),
        hartevo_qualtrics_survey_result_plugin::ProjectId::new("project-1").expect("project"),
        hartevo_qualtrics_survey_result_plugin::ConsentId::new("consent-1").expect("consent"),
    )
    .expect("scope")
    .with_question_revision(
        QuestionId::new("QID1").expect("question"),
        Revision::new(2).expect("question revision"),
    )
    .with_response_revision(
        ResponseId::new("R_1").expect("response"),
        Revision::new(3).expect("response revision"),
    )
    .with_distribution(DistributionId::new("D_1").expect("distribution"))
    .with_survey_revision(Revision::new(4).expect("survey revision"))
    .with_mission_revision(Revision::new(5).expect("mission revision"))
    .with_project_revision(Revision::new(6).expect("project revision"))
}

fn responses(scope: &QualtricsScope, status: ResponseStatus) -> Vec<QualtricsPayload> {
    let survey = SurveyMetadata::new(
        scope.survey().clone(),
        scope.scope_digest().clone(),
        scope.survey_revision(),
        SurveyLifecycle::Active,
        1,
    )
    .expect("survey metadata");
    let question = hartevo_qualtrics_survey_result_plugin::QuestionMetadata::new(
        scope.survey().clone(),
        scope.question().expect("question").clone(),
        scope.scope_digest().clone(),
        scope.question_revision().expect("question revision"),
        QuestionKind::Numeric,
        0,
    )
    .expect("question metadata");
    let response = ResponseMetadata::new(
        scope.survey().clone(),
        scope.response().expect("response").clone(),
        scope.distribution().cloned(),
        scope.scope_digest().clone(),
        scope.response_revision().expect("response revision"),
        status,
        true,
    );
    let response_status = ResponseStatusEvidence::new(
        scope.survey().clone(),
        scope.response().expect("response").clone(),
        scope.scope_digest().clone(),
        scope.response_revision().expect("response revision"),
        status,
    );
    let answer = SurveyAnswer::new(
        scope.survey().clone(),
        scope.question().expect("question").clone(),
        scope.response().expect("response").clone(),
        scope.question_revision().expect("question revision"),
        scope.response_revision().expect("response revision"),
        BoundedAnswer::numeric(9),
    );
    let page = AnswerPage::new(
        scope.survey().clone(),
        scope.question().expect("question").clone(),
        scope.response().expect("response").clone(),
        scope.scope_digest().clone(),
        scope.question_revision().expect("question revision"),
        scope.response_revision().expect("response revision"),
        0,
        vec![answer],
        None,
        true,
    )
    .expect("answer page");
    vec![
        QualtricsPayload::SurveyMetadata(survey),
        QualtricsPayload::QuestionMetadata(question),
        QualtricsPayload::ResponseMetadata(response),
        QualtricsPayload::ResponseStatus(response_status),
        QualtricsPayload::AnswerPage(page),
    ]
}

fn service_with_status(status: ResponseStatus) -> QualtricsSurveyResultService {
    let scope = scope();
    let payloads = responses(&scope, status).into_iter().map(|payload| {
        hartevo_qualtrics_survey_result_plugin::QualtricsTransportResponse::success(
            payload,
            hartevo_qualtrics_survey_result_plugin::QUALTRICS_PROVIDER_REVISION,
            128,
        )
    });
    let transport = FixtureQualtricsTransport::new(payloads);
    let provider =
        QualtricsProvider::new(transport, ProviderProvenance::Fixture).expect("provider");
    let secret =
        SecretReference::new("opaque-qualtrics-reference", &scope, 7).expect("secret reference");
    QualtricsSurveyResultService::new(scope, secret, provider).expect("service")
}

fn request(scope: &QualtricsScope) -> QualtricsSurveyResultRequest {
    QualtricsSurveyResultRequest::for_scope(scope, QualtricsResultBounds::default())
}

#[test]
fn completed_fixture_is_bounded_and_consumable_without_authority() {
    let mut service = service_with_status(ResponseStatus::Completed);
    let proposal = service.propose(request(service.scope())).expect("proposal");
    assert_eq!(proposal.state(), QualtricsResultState::Completed);
    assert!(proposal.proposal_only());
    assert!(!proposal.is_adopted());
    assert!(!proposal.authority().connected());
    assert!(!proposal.authority().native());
    assert!(!proposal.authority().truth());
    assert_eq!(proposal.evidence().answers().len(), 1);
    assert_eq!(proposal.evidence().receipts().len(), 5);
    assert!(
        proposal
            .evidence()
            .receipts()
            .iter()
            .all(|receipt| receipt.request().method() == "GET")
    );

    let consumer =
        MissionQualtricsSurveyConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume(proposal).expect("mission result");
    assert_eq!(result.state, QualtricsResultState::Completed);
    assert_eq!(result.answer_count, 1);
    assert!(result.proposal_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.truth_authority);
}

#[test]
fn status_projection_keeps_in_progress_partial_and_expired_distinct() {
    for (status, expected) in [
        (ResponseStatus::InProgress, QualtricsResultState::InProgress),
        (ResponseStatus::Partial, QualtricsResultState::Partial),
        (ResponseStatus::Expired, QualtricsResultState::Expired),
    ] {
        let mut service = service_with_status(status);
        let proposal = service.propose(request(service.scope())).expect("proposal");
        assert_eq!(proposal.state(), expected);
    }
}

#[test]
fn consent_block_is_local_and_never_calls_the_transport() {
    let blocked_scope = scope()
        .with_consent_status(ConsentStatus::Withdrawn)
        .expect("consent status");
    let transport = hartevo_qualtrics_survey_result_plugin::BlockedEnvTransport;
    let provider =
        QualtricsProvider::new(transport, ProviderProvenance::BlockedEnv).expect("provider");
    let secret = SecretReference::new("opaque-qualtrics-reference", &blocked_scope, 7)
        .expect("secret reference");
    let mut service =
        QualtricsSurveyResultService::new(blocked_scope, secret, provider).expect("service");
    let proposal = service
        .propose(request(service.scope()))
        .expect("consent proposal");
    assert_eq!(proposal.state(), QualtricsResultState::ConsentBlocked);
    assert!(proposal.evidence().receipts().is_empty());
}

#[test]
fn access_loss_and_tamper_are_not_reported_as_success() {
    let scope = scope();
    let first = responses(&scope, ResponseStatus::Completed)
        .into_iter()
        .next()
        .expect("survey payload");
    let mut recording = RecordingQualtricsTransport::default();
    recording.push_response(
        hartevo_qualtrics_survey_result_result_response(first).with_status_code(403),
    );
    let provider =
        QualtricsProvider::new(recording, ProviderProvenance::Recording).expect("provider");
    let secret =
        SecretReference::new("opaque-qualtrics-reference", &scope, 7).expect("secret reference");
    let mut service =
        QualtricsSurveyResultService::new(scope.clone(), secret, provider).expect("service");
    let proposal = service.propose(request(&scope)).expect("access proposal");
    assert_eq!(proposal.state(), QualtricsResultState::AccessLost);
    assert!(!proposal.authority().connected());

    let mut recording = RecordingQualtricsTransport::default();
    recording.push_response(
        hartevo_qualtrics_survey_result_result_response(
            responses(&scope, ResponseStatus::Completed)
                .into_iter()
                .next()
                .expect("survey payload"),
        )
        .with_response_digest(Digest::from_text("tampered")),
    );
    let provider =
        QualtricsProvider::new(recording, ProviderProvenance::Recording).expect("provider");
    let secret =
        SecretReference::new("opaque-qualtrics-reference", &scope, 7).expect("secret reference");
    let mut service = QualtricsSurveyResultService::new(scope, secret, provider).expect("service");
    assert!(matches!(
        service.propose(request(service.scope())),
        Err(hartevo_qualtrics_survey_result_plugin::QualtricsServiceError::TamperedEvidence)
    ));
}

fn hartevo_qualtrics_survey_result_result_response(
    payload: QualtricsPayload,
) -> hartevo_qualtrics_survey_result_plugin::QualtricsTransportResponse {
    hartevo_qualtrics_survey_result_plugin::QualtricsTransportResponse::success(
        payload,
        hartevo_qualtrics_survey_result_plugin::QUALTRICS_PROVIDER_REVISION,
        128,
    )
}

#[test]
fn secret_reference_and_receipts_do_not_retain_raw_secret_or_payload() {
    let scope = scope();
    let secret =
        SecretReference::new("api-token-never-serialized", &scope, 1).expect("secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("api-token-never-serialized"));

    let mut service = service_with_status(ResponseStatus::Completed);
    let proposal = service.propose(request(service.scope())).expect("proposal");
    let serialized = serde_json::to_string(&proposal).expect("safe proposal JSON");
    assert!(!serialized.contains("api-token"));
    assert!(!serialized.contains("free_text"));
    assert!(!serialized.contains("export bytes"));
}

#[test]
fn retry_is_bounded_and_export_progress_is_proposal_only() {
    let scope = scope();
    let mut transport = RecordingQualtricsTransport::default();
    transport.push_response(
        hartevo_qualtrics_survey_result_result_response(
            responses(&scope, ResponseStatus::Completed)
                .into_iter()
                .next()
                .expect("survey payload"),
        )
        .with_status_code(429)
        .with_retry_after(Duration::from_mins(1)),
    );
    transport.push_response(hartevo_qualtrics_survey_result_result_response(
        responses(&scope, ResponseStatus::Completed)
            .into_iter()
            .next()
            .expect("survey payload"),
    ));
    let provider =
        QualtricsProvider::new(transport, ProviderProvenance::Recording).expect("provider");
    let secret =
        SecretReference::new("opaque-qualtrics-reference", &scope, 7).expect("secret reference");
    let mut service =
        QualtricsSurveyResultService::new(scope.clone(), secret, provider).expect("service");
    let request = request(&scope);
    let proposal = service.propose(request).expect("provider unknown proposal");
    assert_eq!(proposal.state(), QualtricsResultState::ProviderUnknown);
    assert_eq!(
        proposal
            .evidence()
            .receipts()
            .iter()
            .map(|receipt| receipt.response().retry().attempts())
            .max(),
        Some(3)
    );
}
