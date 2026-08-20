use hartevo_lokalise_localization_result_plugin as lokalise;
use serde_json::json;

fn scope() -> lokalise::LokaliseLocalizationScope {
    let spec = lokalise::LokaliseLocalizationScopeSpec::new(
        lokalise::TeamId::new("team-1").expect("team"),
        lokalise::ProjectId::new("project-1").expect("project"),
        lokalise::Revision::new(7).expect("project revision"),
        lokalise::BranchName::new("main").expect("branch"),
        lokalise::Revision::new(8).expect("branch revision"),
        lokalise::FileId::new("11").expect("file"),
        lokalise::Revision::new(9).expect("file revision"),
        lokalise::LokaliseLanguage::new("42", "fr", "French", 10).expect("language"),
        lokalise::LokalisePermissionSet::read_only(11).expect("permissions"),
        lokalise::ProjectBinding::new("project-1", 12).expect("project binding"),
        lokalise::MissionBinding::new("mission-1", 13).expect("mission"),
        lokalise::WorkProductBinding::new("work-product-1", 14).expect("work product"),
        lokalise::ConsentScope::new("consent-1", 15).expect("consent"),
    );
    lokalise::LokaliseLocalizationScope::new(spec).expect("scope")
}

fn secret() -> lokalise::SecretReference {
    lokalise::SecretReference::new("host-keyring-handle", 16).expect("secret reference")
}

fn base_payload(
    translations: Vec<lokalise::LokaliseTranslationPayload>,
) -> lokalise::LokaliseLocalizationPayload {
    lokalise::LokaliseLocalizationPayload {
        project: Some(lokalise::LokaliseProjectPayload::new(
            "project-1",
            "team-1",
            "main",
            "Private project name",
            "localization_files",
        )),
        languages: vec![lokalise::LokaliseLanguagePayload::new(42, "fr", "French")],
        files: vec![lokalise::LokaliseFilePayload::new(
            11,
            "private/path/messages.json",
            2,
        )],
        translations,
        tasks: vec![lokalise::LokaliseTaskPayload::new(21, "in_progress", 50)],
        processes: Vec::new(),
        partial: false,
    }
}

fn service_with_response(
    response: lokalise::LokaliseResponse,
) -> lokalise::LokaliseLocalizationResultService<lokalise::FixtureLokaliseTransport> {
    let provider = lokalise::LokaliseProvider::new(
        scope(),
        secret(),
        lokalise::FixtureLokaliseTransport::new(response),
    )
    .expect("provider");
    lokalise::LokaliseLocalizationResultService::new(provider).expect("service")
}

#[test]
fn localization_result_is_redacted_digest_fenced_and_order_independent() {
    let mut first_translation = lokalise::LokaliseTranslationPayload::translated(
        1,
        101,
        11,
        42,
        "private source text",
        "private translated text",
    );
    first_translation.translator_email = Some("translator@example.test".to_owned());
    first_translation.comment = Some("private review comment".to_owned());
    first_translation.screenshots = vec!["https://private.example/screenshot".to_owned()];
    let second_translation = lokalise::LokaliseTranslationPayload::translated(
        2,
        102,
        11,
        42,
        "second private source",
        "second private translation",
    );
    let payload = base_payload(vec![first_translation, second_translation]);
    let response = lokalise::LokaliseResponse::json(200, &payload);
    let mut service = service_with_response(response);
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal.state(),
        lokalise::LokaliseEvidenceState::Translated
    );
    assert!(proposal.recommendation.non_mutating);
    assert!(proposal.recommendation.provider_reported_only);
    assert!(!proposal.recommendation.claims_translation_quality);
    assert!(!proposal.recommendation.claims_publication);
    assert!(!proposal.recommendation.claims_approval);
    assert!(proposal.proposal_only);
    assert!(!proposal.native && !proposal.connected && !proposal.first_party);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    for secret in [
        "host-keyring-handle",
        "private source text",
        "private translated text",
        "translator@example.test",
        "private review comment",
        "private/path/messages.json",
        "https://private.example/screenshot",
    ] {
        assert!(
            !serialized.contains(secret),
            "serialized proposal leaked {secret}"
        );
    }
    assert!(!format!("{secret:?}", secret = secret()).contains("host-keyring-handle"));

    let reversed_payload = base_payload(vec![
        lokalise::LokaliseTranslationPayload::translated(
            2,
            102,
            11,
            42,
            "second private source",
            "second private translation",
        ),
        lokalise::LokaliseTranslationPayload::translated(
            1,
            101,
            11,
            42,
            "private source text",
            "private translated text",
        ),
    ]);
    let mut reversed =
        service_with_response(lokalise::LokaliseResponse::json(200, &reversed_payload));
    let reversed_proposal = reversed.compile_proposal().expect("reversed proposal");
    assert_eq!(
        proposal.evidence.digest(),
        reversed_proposal.evidence.digest()
    );
    assert_eq!(proposal.digest(), reversed_proposal.digest());
    service.verify_proposal(&proposal).expect("proposal fence");
}

#[test]
fn all_reads_are_allowlisted_gets_and_scope_bound() {
    let payload = base_payload(vec![lokalise::LokaliseTranslationPayload::translated(
        1,
        101,
        11,
        42,
        "source",
        "translation",
    )]);
    let provider = lokalise::LokaliseProvider::new(
        scope(),
        secret(),
        lokalise::RecordingLokaliseTransport::new(lokalise::LokaliseResponse::json(200, &payload)),
    )
    .expect("provider");
    let mut service = lokalise::LokaliseLocalizationResultService::new(provider).expect("service");
    service.read().expect("read");
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 6);
    let paths = requests
        .iter()
        .map(|request| request.path.as_str())
        .collect::<Vec<_>>();
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("/projects/project-1"))
    );
    assert!(paths.iter().any(|path| path.ends_with("/languages")));
    assert!(paths.iter().any(|path| path.ends_with("/files")));
    assert!(paths.iter().any(|path| path.ends_with("/translations")));
    assert!(paths.iter().any(|path| path.ends_with("/tasks")));
    assert!(paths.iter().any(|path| path.ends_with("/processes")));
    for request in requests {
        assert_eq!(request.method, lokalise::LokaliseHttpMethod::Get);
        assert_eq!(request.host, lokalise::LOKALISE_API_HOST);
        assert!(request.is_allowlisted());
        assert_eq!(request.scope_digest, *scope().scope_digest());
        assert_eq!(request.limit, lokalise::MAX_PAGE_SIZE);
        assert!(
            !serde_json::to_string(request)
                .expect("request serializes")
                .contains("host-keyring-handle")
        );
    }
}

#[test]
fn explicit_states_and_non_native_transports_remain_honest() {
    let mut untranslated =
        lokalise::LokaliseTranslationPayload::untranslated(1, 101, 11, 42, "source");
    untranslated.is_untranslated = true;
    let mut service = service_with_response(lokalise::LokaliseResponse::json(
        200,
        &base_payload(vec![untranslated]),
    ));
    assert_eq!(
        service.read().expect("untranslated evidence").state,
        lokalise::LokaliseEvidenceState::Untranslated
    );

    let mut unverified =
        lokalise::LokaliseTranslationPayload::translated(1, 101, 11, 42, "source", "translation");
    unverified.is_unverified = true;
    let mut service = service_with_response(lokalise::LokaliseResponse::json(
        200,
        &base_payload(vec![unverified]),
    ));
    assert_eq!(
        service.read().expect("unverified evidence").state,
        lokalise::LokaliseEvidenceState::Unverified
    );

    let mut reviewed =
        lokalise::LokaliseTranslationPayload::translated(1, 101, 11, 42, "source", "translation");
    reviewed.is_reviewed = true;
    let mut service = service_with_response(lokalise::LokaliseResponse::json(
        200,
        &base_payload(vec![reviewed]),
    ));
    assert_eq!(
        service.read().expect("reviewed evidence").state,
        lokalise::LokaliseEvidenceState::Reviewed
    );

    let mut qa_issue =
        lokalise::LokaliseTranslationPayload::translated(1, 101, 11, 42, "source", "translation");
    qa_issue.qa_issues = vec!["placeholders".to_owned()];
    let mut service = service_with_response(lokalise::LokaliseResponse::json(
        200,
        &base_payload(vec![qa_issue]),
    ));
    assert_eq!(
        service.read().expect("QA evidence").state,
        lokalise::LokaliseEvidenceState::QaIssue
    );

    let mut building_payload = base_payload(Vec::new());
    building_payload.processes = vec![lokalise::LokaliseProcessPayload::new(
        "build-1",
        "in_progress",
        20,
        None,
    )];
    let mut service =
        service_with_response(lokalise::LokaliseResponse::json(200, &building_payload));
    assert_eq!(
        service.read().expect("building evidence").state,
        lokalise::LokaliseEvidenceState::Building
    );

    let mut ready_payload = base_payload(Vec::new());
    ready_payload.processes = vec![lokalise::LokaliseProcessPayload::new(
        "build-1",
        "completed",
        100,
        Some(4),
    )];
    let mut service = service_with_response(lokalise::LokaliseResponse::json(200, &ready_payload));
    assert_eq!(
        service.read().expect("ready evidence").state,
        lokalise::LokaliseEvidenceState::Ready
    );

    let mut expired_payload = base_payload(Vec::new());
    expired_payload.processes = vec![lokalise::LokaliseProcessPayload::new(
        "build-1",
        "expired",
        100,
        Some(3),
    )];
    let mut service =
        service_with_response(lokalise::LokaliseResponse::json(200, &expired_payload));
    assert_eq!(
        service.read().expect("expired evidence").state,
        lokalise::LokaliseEvidenceState::Expired
    );

    let mut partial_payload = base_payload(Vec::new());
    partial_payload.partial = true;
    let mut service =
        service_with_response(lokalise::LokaliseResponse::json(200, &partial_payload));
    assert_eq!(
        service.read().expect("partial evidence").state,
        lokalise::LokaliseEvidenceState::Partial
    );

    let mut blocked = lokalise::LokaliseLocalizationResultService::new(
        lokalise::LokaliseProvider::new(scope(), secret(), lokalise::BlockedEnvLokaliseTransport)
            .expect("blocked provider"),
    )
    .expect("blocked service");
    let blocked_evidence = blocked.read().expect("blocked evidence");
    assert_eq!(
        blocked_evidence.state,
        lokalise::LokaliseEvidenceState::AccessLost
    );
    assert_eq!(
        blocked_evidence.classification,
        lokalise::LokaliseEvidenceClassification::BlockedEnv
    );
    assert!(!blocked_evidence.native && !blocked_evidence.connected);
    assert!(!blocked_evidence.first_party);
}

#[test]
fn status_matrix_rate_limit_and_scope_fail_closed() {
    for (status, expected) in [
        (401, lokalise::LokaliseEvidenceState::AccessLost),
        (403, lokalise::LokaliseEvidenceState::AccessLost),
        (410, lokalise::LokaliseEvidenceState::Expired),
        (500, lokalise::LokaliseEvidenceState::ProviderUnknown),
    ] {
        let mut service = service_with_response(lokalise::LokaliseResponse::json(
            status,
            &json!({"message":"private raw diagnostic","translation":"private raw text"}),
        ));
        let evidence = service.read().expect("status becomes typed evidence");
        assert_eq!(evidence.state, expected);
        assert!(
            !serde_json::to_string(&evidence)
                .expect("evidence serializes")
                .contains("private raw")
        );
    }

    let invalid_rate = lokalise::LokaliseRateLimitReceipt {
        limit_per_minute: 61,
        remaining: Some(61),
        retry_after_seconds: None,
        throttled: false,
    };
    let mut invalid_service =
        service_with_response(lokalise::LokaliseResponse::json_with_rate_limit(
            200,
            &base_payload(Vec::new()),
            invalid_rate,
        ));
    assert_eq!(
        invalid_service
            .read()
            .expect("invalid receipt evidence")
            .state,
        lokalise::LokaliseEvidenceState::ProviderUnknown
    );

    let mut rate_service = service_with_response(lokalise::LokaliseResponse::json(
        200,
        &base_payload(Vec::new()),
    ));
    for _ in 0..10 {
        rate_service.read().expect("bounded read");
    }
    let rate_limited = rate_service.read().expect("rate-limit evidence");
    assert_eq!(
        rate_limited.classification,
        lokalise::LokaliseEvidenceClassification::RateLimited
    );
    assert_eq!(
        rate_limited.state,
        lokalise::LokaliseEvidenceState::RateLimited
    );

    let cursor_response = lokalise::LokaliseResponse::json(200, &base_payload(Vec::new()))
        .with_next_cursor("next-private-cursor")
        .expect("cursor");
    let mut cursor_service = service_with_response(cursor_response);
    let cursor_consent = cursor_service.issue_read_consent();
    let cursor_evidence = cursor_service
        .read_from_cursor(&cursor_consent, Some("input-cursor"))
        .expect("cursor evidence");
    assert!(
        cursor_evidence
            .aggregate
            .as_ref()
            .expect("aggregate")
            .partial
    );
    assert!(
        !serde_json::to_string(&cursor_evidence)
            .expect("cursor evidence serializes")
            .contains("next-private-cursor")
    );
    let invalid_cursor_consent = cursor_service.issue_read_consent();
    assert!(
        cursor_service
            .read_from_cursor(&invalid_cursor_consent, Some(&"x".repeat(257)))
            .is_err()
    );

    let mut out_of_scope =
        lokalise::LokaliseTranslationPayload::translated(1, 101, 99, 42, "source", "translation");
    out_of_scope.file_id = Some(99);
    let mut scope_service = service_with_response(lokalise::LokaliseResponse::json(
        200,
        &base_payload(vec![out_of_scope]),
    ));
    assert!(matches!(
        scope_service.read(),
        Err(lokalise::LokaliseLocalizationResultServiceError::ScopeMismatch)
    ));
}

#[test]
fn registration_and_mission_replay_fences_are_reversible() {
    let payload = base_payload(vec![lokalise::LokaliseTranslationPayload::translated(
        1,
        101,
        11,
        42,
        "source",
        "translation",
    )]);
    let provider = lokalise::LokaliseProvider::new(
        scope(),
        secret(),
        lokalise::FixtureLokaliseTransport::new(lokalise::LokaliseResponse::json(200, &payload)),
    )
    .expect("provider");
    let mut service = lokalise::LokaliseLocalizationResultService::new(provider).expect("service");
    let original_registration = service.registration().registration_digest.clone();
    let proposal = service.compile_proposal().expect("proposal");
    let mut tampered = proposal.clone();
    tampered.connected = true;
    assert!(matches!(
        service.verify_proposal(&tampered),
        Err(lokalise::LokaliseLocalizationResultServiceError::EvidenceMismatch)
    ));

    let revocation = service.provider_mut().revoke().expect("revoke");
    assert_eq!(
        revocation.previous_registration_digest,
        original_registration
    );
    assert_ne!(revocation.registration_digest, original_registration);
    assert!(matches!(
        service.read(),
        Err(lokalise::LokaliseLocalizationResultServiceError::RegistrationRevoked)
    ));
    service.provider_mut().restore().expect("restore");
    assert_ne!(
        service.registration().registration_digest,
        original_registration
    );
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(
            lokalise::LokaliseLocalizationResultServiceError::RegistrationRevoked
                | lokalise::LokaliseLocalizationResultServiceError::EvidenceMismatch
        )
    ));

    let consumer_provider = lokalise::LokaliseProvider::new(
        scope(),
        secret(),
        lokalise::FixtureLokaliseTransport::new(lokalise::LokaliseResponse::json(200, &payload)),
    )
    .expect("consumer provider");
    let mut consumer =
        lokalise::MissionLokaliseLocalizationConsumer::new(consumer_provider).expect("consumer");
    let consumer_proposal = consumer.compile_proposal().expect("consumer proposal");
    let result = consumer.consume(&consumer_proposal).expect("consume");
    assert_eq!(
        result.state,
        lokalise::MissionLokaliseLocalizationResultState::NeedsReview
    );
    assert!(result.proposal_only);
    assert!(!result.native && !result.connected && !result.first_party);
    assert!(!result.adopts_outcome);
    assert!(matches!(
        consumer.consume(&consumer_proposal),
        Err(lokalise::MissionLokaliseLocalizationConsumerError::ReplayDetected)
    ));
    assert!(matches!(
        consumer.consume_at_revisions(&consumer_proposal, 999, 14),
        Err(lokalise::MissionLokaliseLocalizationConsumerError::StaleMission)
    ));
    consumer.revoke().expect("consumer revoke");
    assert!(matches!(
        consumer.read(),
        Err(lokalise::MissionLokaliseLocalizationConsumerError::Revoked)
    ));
    consumer.restore().expect("consumer restore");
}
