use hartevo_gong_conversation_result_plugin::{
    ActionItemCounts, BlockedEnvTransport, CallMetadata, ConsentState, DateWindow, DealId,
    ExternalCrmContextIdentifier, ExternalCrmContextIdentifiers, ExternalObjectId, ExternalSystem,
    GONG_CONVERSATION_RESULT_CONTRACT_JSON, GONG_DAILY_REQUEST_LIMIT, GONG_MAX_RESPONSE_BYTES,
    GONG_PAGE_SIZE, GONG_PROVIDER_REVISION, GONG_REQUESTS_PER_SECOND,
    GongConversationResultContract, GongConversationResultPluginDefinition,
    GongConversationResultProjection, GongConversationResultService, GongConversationScope,
    GongConversationScopeInput, GongProvider, GongProviderError, GongReadOperation,
    GongReadPayload, GongReadRequest, GongReadResponse, GongReadStatus, GongTransportError,
    InteractionMetrics, LoopbackGongTransport, MissionConversationState,
    MissionGongConversationConsumer, RecordingGongTransport, ScorecardEvaluationStatus,
    ScorecardStatus, SecretReference, TopicTrackerSignal, TopicsAndTrackers, TransportProvenance,
    contract_digest, plugin_definition,
};

const NOW: u64 = 1_787_000_000;

fn scope_with_consent(state: ConsentState) -> GongConversationScope {
    GongConversationScope::new(GongConversationScopeInput {
        account_id: "account-1".to_owned(),
        team_id: "team-1".to_owned(),
        user_ids: vec!["user-1".to_owned(), "user-2".to_owned()],
        call_id: "call-1".to_owned(),
        call_revision: 11,
        meeting_id: Some("meeting-1".to_owned()),
        deal_id: Some("deal-1".to_owned()),
        context_ids: vec!["context-1".to_owned()],
        context_revision: 6,
        scorecard_ids: vec!["scorecard-1".to_owned()],
        scorecard_revision: 8,
        tracker_ids: vec!["tracker-1".to_owned()],
        analysis_revision: 7,
        mission_id: "mission-1".to_owned(),
        mission_revision: 4,
        project_id: "project-1".to_owned(),
        project_revision: 9,
        consent_id: "consent-1".to_owned(),
        consent_revision: 3,
        consent_state: state,
    })
    .expect("bounded scope")
}

fn secret() -> SecretReference {
    SecretReference::new("vault/gong/access-key", 5).expect("opaque secret reference")
}

fn provider_and_registration(
    scope: &GongConversationScope,
    secret: &SecretReference,
) -> (
    GongProvider<RecordingGongTransport>,
    hartevo_gong_conversation_result_plugin::RegistrationReceipt,
) {
    let empty_provider = GongProvider::new(RecordingGongTransport::fixture([])).expect("provider");
    let mut definition = GongConversationResultPluginDefinition::layer1().expect("definition");
    definition.provider = empty_provider.definition().clone();
    definition.validate().expect("definition validation");
    let registration = definition
        .bind(scope.clone(), empty_provider.definition(), secret, 1)
        .expect("registration");
    (empty_provider, registration)
}

fn request(
    scope: &GongConversationScope,
    secret: &SecretReference,
    registration: &hartevo_gong_conversation_result_plugin::RegistrationReceipt,
    provider: &GongProvider<RecordingGongTransport>,
    operation: GongReadOperation,
    at: u64,
) -> GongReadRequest {
    GongReadRequest::bound(
        scope,
        operation,
        Some(DateWindow::new("2026-08-01", "2026-08-14").expect("date window")),
        secret,
        &registration.registration_digest,
        &provider.definition().capability_digest,
        at,
    )
    .expect("bound request")
}

fn response(request: &GongReadRequest, payload: GongReadPayload) -> GongReadResponse {
    GongReadResponse::new(request, GongReadStatus::Analyzed, payload, true).expect("response")
}

fn complete_responses(
    scope: &GongConversationScope,
    secret: &SecretReference,
    registration: &hartevo_gong_conversation_result_plugin::RegistrationReceipt,
    provider: &GongProvider<RecordingGongTransport>,
) -> Vec<Result<GongReadResponse, GongTransportError>> {
    let call_request = request(
        scope,
        secret,
        registration,
        provider,
        GongReadOperation::CallMetadata,
        NOW,
    );
    let interaction_request = request(
        scope,
        secret,
        registration,
        provider,
        GongReadOperation::InteractionMetrics,
        NOW,
    );
    let topics_request = request(
        scope,
        secret,
        registration,
        provider,
        GongReadOperation::TopicsTrackers,
        NOW,
    );
    let action_request = request(
        scope,
        secret,
        registration,
        provider,
        GongReadOperation::ActionItemCounts,
        NOW + 1,
    );
    let scorecard_request = request(
        scope,
        secret,
        registration,
        provider,
        GongReadOperation::ScorecardStatus,
        NOW + 1,
    );
    let crm_request = request(
        scope,
        secret,
        registration,
        provider,
        GongReadOperation::ExternalCrmContextIdentifiers,
        NOW + 1,
    );
    vec![
        Ok(response(
            &call_request,
            GongReadPayload::CallMetadata(CallMetadata {
                call_id: scope.call_id.clone(),
                meeting_id: scope.meeting_id.clone(),
                deal_id: scope.deal_id.clone(),
                duration_seconds: Some(900),
                status: hartevo_gong_conversation_result_plugin::GongAnalysisStatus::Analyzed,
                call_revision: scope.call_revision,
                analysis_revision: scope.analysis_revision,
            }),
        )),
        Ok(response(
            &interaction_request,
            GongReadPayload::InteractionMetrics(InteractionMetrics {
                talk_time_seconds: Some(600),
                question_count: 8,
                interruption_count: 1,
                monologue_count: 2,
                speaker_count: Some(2),
            }),
        )),
        Ok(response(
            &topics_request,
            GongReadPayload::TopicsTrackers(TopicsAndTrackers {
                signals: vec![TopicTrackerSignal {
                    tracker_id: scope.tracker_ids[0].clone(),
                    topic_digest: Some(contract_digest()),
                    match_count: 2,
                }],
            }),
        )),
        Ok(response(
            &action_request,
            GongReadPayload::ActionItemCounts(ActionItemCounts {
                total: 3,
                open: 1,
                completed: 2,
            }),
        )),
        Ok(response(
            &scorecard_request,
            GongReadPayload::ScorecardStatus(ScorecardStatus {
                scorecard_id: scope.scorecard_ids[0].clone(),
                scorecard_revision: scope.scorecard_revision,
                status: ScorecardEvaluationStatus::InProgress,
                answered_items: 3,
                total_items: 4,
            }),
        )),
        Ok(response(
            &crm_request,
            GongReadPayload::ExternalCrmContextIdentifiers(ExternalCrmContextIdentifiers {
                deal_id: scope.deal_id.clone().expect("deal scope"),
                context_revision: scope.context_revision,
                identifiers: vec![ExternalCrmContextIdentifier {
                    context_id: scope.context_ids[0].clone(),
                    external_system: ExternalSystem::parse("salesforce").expect("system"),
                    external_object_id: ExternalObjectId::parse("opportunity-1")
                        .expect("object id"),
                }],
            }),
        )),
    ]
}

#[test]
fn contract_and_plugin_definition_are_exactly_layer_one() {
    let contract = GongConversationResultContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(contract.layer, 1);
    assert_eq!(contract.allowlisted_reads.len(), 6);
    assert_eq!(
        contract.bounds.requests_per_second,
        GONG_REQUESTS_PER_SECOND
    );
    assert_eq!(
        contract.bounds.daily_request_limit,
        GONG_DAILY_REQUEST_LIMIT
    );
    assert_eq!(contract.bounds.max_response_bytes, GONG_MAX_RESPONSE_BYTES);
    assert!(contract.authority.read_only);
    assert!(!contract.authority.connected);
    assert!(!contract.authority.native);
    assert!(!contract.authority.external_writes);
    assert!(
        contract
            .negative_capabilities
            .iter()
            .any(|value| value.contains("no_raw_transcript_audio_media"))
    );
    assert!(GONG_CONVERSATION_RESULT_CONTRACT_JSON.len() > 100);

    let definition = plugin_definition().expect("plugin definition");
    definition.validate().expect("definition");
    assert!(!definition.writes);
    assert!(!definition.native);
    assert!(!definition.connected);
    assert!(!definition.generic_crm_registry);
    assert!(!definition.kernel_authority);
    assert_eq!(definition.provider.allowlisted_operations.len(), 6);
}

#[test]
fn complete_fixture_reads_all_allowlisted_seams_with_redacted_receipts() {
    let scope = scope_with_consent(ConsentState::Granted);
    let secret = secret();
    let (empty_provider, registration) = provider_and_registration(&scope, &secret);
    let responses = complete_responses(&scope, &secret, &registration, &empty_provider);
    let provider = GongProvider::new(RecordingGongTransport::fixture(responses)).expect("provider");
    let mut service = GongConversationResultService::new(
        scope.clone(),
        secret.clone(),
        provider,
        Some(DateWindow::new("2026-08-01", "2026-08-14").expect("window")),
        NOW,
    )
    .expect("service");
    let proposal = service.propose().expect("analyzed proposal");
    assert_eq!(
        proposal.projection,
        GongConversationResultProjection::Analyzed
    );
    assert!(proposal.evidence.call_metadata.is_some());
    assert!(proposal.evidence.interaction_metrics.is_some());
    assert!(proposal.evidence.topics_trackers.is_some());
    assert!(proposal.evidence.action_item_counts.is_some());
    assert!(proposal.evidence.scorecard_status.is_some());
    assert!(proposal.evidence.external_crm_context_identifiers.is_some());
    assert!(
        proposal
            .evidence
            .absence_is_not_deal_health_or_customer_intent
    );
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.outcome_authority);
    assert!(proposal.deal_health.is_none());
    assert!(proposal.customer_intent.is_none());
    assert!(proposal.evidence.receipts.iter().all(|receipt| {
        receipt.provider_revision == GONG_PROVIDER_REVISION
            && !receipt.raw_provider_payload_retained
            && !receipt.transcript_retained
            && !receipt.audio_retained
            && !receipt.media_urls_retained
            && !receipt.participant_pii_retained
            && !receipt.phone_numbers_retained
            && !receipt.comments_retained
            && !receipt.raw_crm_objects_retained
            && !receipt.credential_material_retained
    }));
    assert!(
        proposal
            .evidence
            .receipts
            .iter()
            .all(|receipt| receipt.allowlisted_path.starts_with("/v2/"))
    );
    assert_eq!(service.provider().transport().requests().len(), 6);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("vault/gong/access-key"));
    assert!(!serialized.contains("access-key"));
    assert!(!format!("{service:?}").contains("vault/gong/access-key"));
    assert!(!format!("{service:?}").contains("access-key"));

    let consumer =
        MissionGongConversationConsumer::from_registration(scope, service.registration())
            .expect("consumer");
    let consumed = consumer.consume(proposal).expect("consume");
    assert_eq!(consumed.state, MissionConversationState::PendingDecision);
    assert!(!consumed.native);
    assert!(!consumed.connected);
    assert!(!consumed.outcome_authority);
    assert!(consumed.deal_health.is_none());
    assert!(consumed.customer_intent.is_none());
}

#[test]
fn consent_blocked_never_calls_a_transport_and_native_is_never_claimed() {
    let scope = scope_with_consent(ConsentState::Pending);
    let provider = GongProvider::new(BlockedEnvTransport).expect("blocked provider");
    let mut service =
        GongConversationResultService::new(scope, secret(), provider, None, NOW).expect("service");
    let proposal = service.propose().expect("consent projection");
    assert_eq!(
        proposal.projection,
        GongConversationResultProjection::ConsentBlocked
    );
    assert_eq!(service.provider().requests_seen(), 0);
    assert_eq!(
        service.provider().provenance(),
        TransportProvenance::BlockedEnv
    );
    assert!(!service.provider().is_native());
    assert!(!service.provider().is_connected());
}

#[test]
fn blocked_env_access_is_projected_without_exposing_credentials() {
    let scope = scope_with_consent(ConsentState::Granted);
    let mut service = GongConversationResultService::new(
        scope,
        secret(),
        GongProvider::new(BlockedEnvTransport).expect("blocked provider"),
        None,
        NOW,
    )
    .expect("service");
    let proposal = service.propose().expect("access-lost projection");
    assert_eq!(
        proposal.projection,
        GongConversationResultProjection::AccessLost
    );
    assert_eq!(proposal.evidence.provider_issues.len(), 6);
    assert!(
        proposal
            .evidence
            .provider_issues
            .iter()
            .all(|issue| issue.code
                == hartevo_gong_conversation_result_plugin::GongIssueCode::BlockedEnv)
    );
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains("secret")
    );
}

#[test]
fn processing_partial_retention_gap_and_provider_unknown_are_distinct() {
    let scope = scope_with_consent(ConsentState::Granted);
    let secret = secret();
    let (empty_provider, registration) = provider_and_registration(&scope, &secret);
    let call_request = request(
        &scope,
        &secret,
        &registration,
        &empty_provider,
        GongReadOperation::CallMetadata,
        NOW,
    );
    let processing_response = GongReadResponse::new(
        &call_request,
        GongReadStatus::Processing,
        GongReadPayload::CallMetadata(CallMetadata {
            call_id: scope.call_id.clone(),
            meeting_id: scope.meeting_id.clone(),
            deal_id: scope.deal_id.clone(),
            duration_seconds: None,
            status: hartevo_gong_conversation_result_plugin::GongAnalysisStatus::Processing,
            call_revision: scope.call_revision,
            analysis_revision: scope.analysis_revision,
        }),
        false,
    )
    .expect("processing response");
    let processing_provider = GongProvider::new(RecordingGongTransport::fixture(
        std::iter::once(Ok(processing_response))
            .chain(std::iter::repeat_with(|| Err(GongTransportError::RetentionGap)).take(5)),
    ))
    .expect("processing provider");
    let mut processing_service = GongConversationResultService::new(
        scope.clone(),
        secret.clone(),
        processing_provider,
        Some(DateWindow::new("2026-08-01", "2026-08-14").expect("window")),
        NOW,
    )
    .expect("processing service");
    assert_eq!(
        processing_service
            .propose()
            .expect("processing proposal")
            .projection,
        GongConversationResultProjection::Processing
    );

    let partial_provider = GongProvider::new(RecordingGongTransport::fixture(
        std::iter::once(Ok(response(
            &call_request,
            GongReadPayload::CallMetadata(CallMetadata {
                call_id: scope.call_id.clone(),
                meeting_id: scope.meeting_id.clone(),
                deal_id: scope.deal_id.clone(),
                duration_seconds: None,
                status: hartevo_gong_conversation_result_plugin::GongAnalysisStatus::Analyzed,
                call_revision: scope.call_revision,
                analysis_revision: scope.analysis_revision,
            }),
        )))
        .chain(std::iter::repeat_with(|| Err(GongTransportError::RetentionGap)).take(5)),
    ))
    .expect("partial provider");
    let mut partial_service = GongConversationResultService::new(
        scope.clone(),
        secret.clone(),
        partial_provider,
        Some(DateWindow::new("2026-08-01", "2026-08-14").expect("window")),
        NOW,
    )
    .expect("partial service");
    assert_eq!(
        partial_service
            .propose()
            .expect("partial proposal")
            .projection,
        GongConversationResultProjection::Partial(
            hartevo_gong_conversation_result_plugin::PartialReason::MissingOperation
        )
    );

    let retention_provider = GongProvider::new(RecordingGongTransport::fixture(
        std::iter::repeat_with(|| Err(GongTransportError::RetentionGap)).take(6),
    ))
    .expect("retention provider");
    let mut retention_service = GongConversationResultService::new(
        scope.clone(),
        secret.clone(),
        retention_provider,
        None,
        NOW,
    )
    .expect("retention service");
    assert_eq!(
        retention_service
            .propose()
            .expect("retention proposal")
            .projection,
        GongConversationResultProjection::RetentionGap
    );

    let unknown_provider = GongProvider::new(RecordingGongTransport::fixture(
        std::iter::repeat_with(|| {
            Err(GongTransportError::RateLimited {
                retry_after_seconds: 1,
            })
        })
        .take(6),
    ))
    .expect("unknown provider");
    let mut unknown_service =
        GongConversationResultService::new(scope, secret, unknown_provider, None, NOW)
            .expect("unknown service");
    assert_eq!(
        unknown_service
            .propose()
            .expect("unknown proposal")
            .projection,
        GongConversationResultProjection::ProviderUnknown
    );
}

#[test]
fn registration_is_version_provider_scope_digest_bound_and_reversible() {
    let scope = scope_with_consent(ConsentState::Granted);
    let secret = secret();
    let (provider, registration) = provider_and_registration(&scope, &secret);
    assert!(registration.is_active());
    assert_eq!(registration.scope_digest, scope.digest());
    assert_eq!(registration.consent_digest, scope.consent.digest());
    assert_eq!(registration.secret_reference_digest, *secret.digest());
    assert_eq!(
        registration.provider_digest,
        provider.definition().provider_digest()
    );

    let mut revoked = registration.clone();
    let revocation = revoked.revoke().expect("revoke");
    assert!(!revoked.is_active());
    assert_eq!(
        revocation.status,
        hartevo_gong_conversation_result_plugin::RegistrationStatus::Revoked
    );
    assert!(revoked.revoke().is_err());

    let mut service = GongConversationResultService::new(
        scope,
        secret,
        GongProvider::new(LoopbackGongTransport::new([])).expect("loopback"),
        None,
        NOW,
    )
    .expect("service");
    service.revoke_registration().expect("service revoke");
    assert!(service.propose().is_err());
}

#[test]
fn scope_date_page_response_and_rate_bounds_fail_closed() {
    assert!(DateWindow::new("2026-08-01", "2026-09-02").is_err());
    assert!(DateWindow::new("2026-08-14", "2026-08-01").is_err());

    let scope = scope_with_consent(ConsentState::Granted);
    let secret = secret();
    let (provider, registration) = provider_and_registration(&scope, &secret);
    let first_request = request(
        &scope,
        &secret,
        &registration,
        &provider,
        GongReadOperation::CallMetadata,
        NOW,
    );
    assert_eq!(first_request.page_size, GONG_PAGE_SIZE);
    assert!(first_request.for_page(5).is_err());
    assert!(
        GongReadResponse::with_size(
            &first_request,
            GongReadStatus::Analyzed,
            GongReadPayload::CallMetadata(CallMetadata {
                call_id: scope.call_id.clone(),
                meeting_id: scope.meeting_id.clone(),
                deal_id: scope.deal_id.clone(),
                duration_seconds: None,
                status: hartevo_gong_conversation_result_plugin::GongAnalysisStatus::Analyzed,
                call_revision: scope.call_revision,
                analysis_revision: scope.analysis_revision,
            }),
            true,
            GONG_MAX_RESPONSE_BYTES + 1,
        )
        .is_err()
    );

    let responses = (0..4)
        .map(|_| {
            Ok(response(
                &first_request,
                GongReadPayload::CallMetadata(CallMetadata {
                    call_id: scope.call_id.clone(),
                    meeting_id: scope.meeting_id.clone(),
                    deal_id: scope.deal_id.clone(),
                    duration_seconds: None,
                    status: hartevo_gong_conversation_result_plugin::GongAnalysisStatus::Analyzed,
                    call_revision: scope.call_revision,
                    analysis_revision: scope.analysis_revision,
                }),
            ))
        })
        .collect::<Vec<_>>();
    let mut limited =
        GongProvider::new(RecordingGongTransport::fixture(responses)).expect("provider");
    let _ = limited.read(&first_request);
    let second = request(
        &scope,
        &secret,
        &registration,
        &provider,
        GongReadOperation::InteractionMetrics,
        NOW,
    );
    let _ = limited.read(&second);
    let third = request(
        &scope,
        &secret,
        &registration,
        &provider,
        GongReadOperation::TopicsTrackers,
        NOW,
    );
    let _ = limited.read(&third);
    let fourth = request(
        &scope,
        &secret,
        &registration,
        &provider,
        GongReadOperation::ActionItemCounts,
        NOW,
    );
    assert_eq!(
        limited.read(&fourth).expect_err("per-second bound"),
        GongProviderError::BudgetExceeded
    );
}

#[test]
fn stale_request_and_tampered_response_are_rejected() {
    let scope = scope_with_consent(ConsentState::Granted);
    let secret = secret();
    let (provider, registration) = provider_and_registration(&scope, &secret);
    let mut tampered_request = request(
        &scope,
        &secret,
        &registration,
        &provider,
        GongReadOperation::CallMetadata,
        NOW,
    );
    tampered_request.account_id =
        hartevo_gong_conversation_result_plugin::AccountId::parse("other-account")
            .expect("other account");
    let mut provider = GongProvider::new(RecordingGongTransport::fixture([])).expect("provider");
    assert_eq!(
        provider
            .read(&tampered_request)
            .expect_err("tampered request"),
        GongProviderError::Transport(GongTransportError::RequestTampered)
    );

    let clean_request = request(
        &scope,
        &secret,
        &registration,
        &provider,
        GongReadOperation::CallMetadata,
        NOW,
    );
    let mut tampered = response(
        &clean_request,
        GongReadPayload::CallMetadata(CallMetadata {
            call_id: scope.call_id.clone(),
            meeting_id: scope.meeting_id.clone(),
            deal_id: scope.deal_id.clone(),
            duration_seconds: None,
            status: hartevo_gong_conversation_result_plugin::GongAnalysisStatus::Analyzed,
            call_revision: scope.call_revision,
            analysis_revision: scope.analysis_revision,
        }),
    );
    tampered.scope_digest = hartevo_gong_conversation_result_plugin::sha256_digest(b"drift");
    let mut response_provider =
        GongProvider::new(RecordingGongTransport::fixture([Ok(tampered)])).expect("provider");
    assert_eq!(
        response_provider
            .read(&clean_request)
            .expect_err("stale response"),
        GongProviderError::InvalidResponseBinding
    );
}

#[test]
fn transport_provenance_is_explicitly_non_native() {
    let transports = [
        TransportProvenance::Recording,
        TransportProvenance::Fixture,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ];
    assert!(
        transports
            .iter()
            .all(|provenance| { !provenance.is_native() && !provenance.is_connected() })
    );
    let debug = format!(
        "{:?}",
        SecretReference::new("fixture-access-key", 1).expect("secret")
    );
    assert!(!debug.contains("fixture-access-key"));
    assert!(!debug.contains("access-key"));
}

#[test]
fn provider_never_exposes_mutation_operations() {
    let definition = plugin_definition().expect("definition");
    assert!(
        definition
            .provider
            .allowlisted_operations
            .iter()
            .all(|operation| {
                !operation.contains("upload")
                    && !operation.contains("update")
                    && !operation.contains("delete")
                    && !operation.contains("write")
                    && !operation.contains("message")
                    && !operation.contains("download")
            })
    );
    assert!(!definition.provider.native);
    assert!(!definition.provider.connected);
}

#[test]
fn typed_external_scope_ids_do_not_become_raw_crm_objects() {
    let deal = DealId::parse("deal-1").expect("deal");
    let object = ExternalObjectId::parse("object-1").expect("object");
    let identifier = ExternalCrmContextIdentifier {
        context_id: hartevo_gong_conversation_result_plugin::ContextId::parse("context-1")
            .expect("context"),
        external_system: ExternalSystem::parse("salesforce").expect("system"),
        external_object_id: object,
    };
    let value = ExternalCrmContextIdentifiers {
        deal_id: deal,
        context_revision: hartevo_gong_conversation_result_plugin::Revision::new(1)
            .expect("revision"),
        identifiers: vec![identifier],
    };
    let json = serde_json::to_string(&value).expect("bounded identifier JSON");
    assert!(json.contains("externalObjectId"));
    assert!(!json.contains("fields"));
    assert!(!json.contains("raw"));
}
