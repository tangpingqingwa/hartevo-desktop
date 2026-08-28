use hartevo_zoom_meeting_result_plugin::{
    ArtifactVerificationStatus, ConsentReference, ContentByteVerification, DecisionArtifactListing,
    EvidenceKind, FileId, Fingerprint, MeetingId, MeetingOccurrenceMetadata,
    MeetingOccurrenceStatus, MissionContext, MissionZoomMeetingResultConsumer, OccurrenceUuid,
    PageBudget, PageCursor, PluginVersion, ProviderError, ProviderMode, ProviderPage,
    ProviderProvenance, ProviderRequest, ProviderState, RecordingFileMetadata, RecordingFileStatus,
    RecordingFileType, RecordingType, RegistrationRequest, RetentionState, SecretReference,
    SummaryMetadata, TranscriptMetadata, ZoomMeetingResultError, ZoomMeetingResultProvider,
    ZoomMeetingResultProviderPort, ZoomMeetingResultScope, ZoomMeetingResultScopeBinding,
    ZoomMeetingResultService, contract_digest,
};

const MEETING_ID: &str = "meeting-123";
const OCCURRENCE: &str = "123e4567-e89b-12d3-a456-426614174000";
const PROVIDER_REVISION: u64 = 7;

#[derive(Debug)]
struct FailingProvider {
    error: ProviderError,
    state: ProviderState,
}

impl FailingProvider {
    fn new(error: ProviderError) -> Self {
        Self {
            error,
            state: ProviderState::new(
                ProviderMode::Recording,
                ProviderProvenance::ControlledRecording,
                PROVIDER_REVISION,
            )
            .expect("provider state"),
        }
    }
}

impl ZoomMeetingResultProviderPort for FailingProvider {
    fn provider_revision(&self) -> u64 {
        self.state.provider_revision()
    }

    fn state(&self) -> ProviderState {
        self.state
    }

    fn fetch_page(&self, _request: ProviderRequest<'_>) -> Result<ProviderPage, ProviderError> {
        Err(self.error.clone())
    }

    fn revoke(&mut self) {
        self.state.revoke();
    }
}

fn occurrence(status: MeetingOccurrenceStatus) -> MeetingOccurrenceMetadata {
    MeetingOccurrenceMetadata::new(
        MeetingId::new(MEETING_ID).expect("meeting id"),
        OccurrenceUuid::new(OCCURRENCE).expect("occurrence uuid"),
        status,
        Some(1_700_000_000_000),
        Some(1_700_000_360_000),
        1_700_000_400_000,
    )
    .expect("occurrence metadata")
}

fn file(
    id: &str,
    file_type: RecordingFileType,
    status: RecordingFileStatus,
) -> RecordingFileMetadata {
    RecordingFileMetadata::new(
        FileId::new(id).expect("file id"),
        file_type,
        match file_type {
            RecordingFileType::Transcript => RecordingType::Transcript,
            RecordingFileType::Summary => RecordingType::Summary,
            RecordingFileType::Audio => RecordingType::AudioOnly,
            RecordingFileType::Video | RecordingFileType::Chat => RecordingType::GalleryView,
        },
        status,
        Some(1_700_000_000_000),
        Some(1_700_000_360_000),
        Some(4096),
        1_700_000_400_000,
        RetentionState::Active,
        Some(1_800_000_000_000),
        Some(1_700_000_800_000),
    )
    .expect("recording metadata")
}

fn scope() -> ZoomMeetingResultScope {
    let binding = ZoomMeetingResultScopeBinding::new(
        "account-1",
        "user-1",
        "host-1",
        MEETING_ID,
        OCCURRENCE,
        ["recording-1".to_owned()],
        ["transcript-1".to_owned()],
        "project-1",
        "mission-1",
        3,
    )
    .expect("scope binding");
    let consent = ConsentReference::new(
        "consent-ref-1",
        binding.scope_digest().expect("binding digest"),
        5,
        None,
    )
    .expect("consent reference");
    ZoomMeetingResultScope::new(binding, consent).expect("full scope")
}

fn secret(scope: &ZoomMeetingResultScope) -> SecretReference {
    SecretReference::new(
        "secret-ref-1",
        scope.scope_digest().expect("scope digest"),
        2,
    )
    .expect("secret reference")
}

fn page(files: Vec<RecordingFileMetadata>, next_cursor: Option<&str>) -> ProviderPage {
    ProviderPage::new(
        occurrence(MeetingOccurrenceStatus::Available),
        files,
        Some(
            TranscriptMetadata::new(
                FileId::new("transcript-1").expect("transcript id"),
                RecordingFileStatus::Available,
                Some("en-US".to_owned()),
                1_700_000_400_000,
            )
            .expect("transcript metadata"),
        ),
        Some(
            SummaryMetadata::new(
                Some(FileId::new("summary-1").expect("summary id")),
                RecordingFileStatus::Available,
                1_700_000_400_000,
            )
            .expect("summary metadata"),
        ),
        next_cursor.map(|cursor| PageCursor::new(cursor).expect("cursor")),
        PROVIDER_REVISION,
    )
    .expect("provider page")
}

fn service(pages: Vec<ProviderPage>) -> ZoomMeetingResultService<ZoomMeetingResultProvider> {
    let scope = scope();
    let provider = ZoomMeetingResultProvider::fake(pages, PROVIDER_REVISION).expect("provider");
    ZoomMeetingResultService::new(provider, scope.clone(), secret(&scope)).expect("service")
}

#[test]
fn capability_has_typed_seams_and_metadata_only_evidence() {
    let service = service(vec![page(
        vec![
            file(
                "recording-1",
                RecordingFileType::Video,
                RecordingFileStatus::Available,
            ),
            file(
                "transcript-1",
                RecordingFileType::Transcript,
                RecordingFileStatus::Available,
            ),
        ],
        None,
    )]);
    let description = service.describe_capabilities().expect("description");
    assert_eq!(
        description.service().service_id(),
        "zoom.meeting-result.service"
    );
    assert_eq!(
        description.provider().provider_id(),
        "zoom.meeting-result.provider"
    );
    assert_eq!(
        description.consumer().consumer_id(),
        "mission.zoom-meeting-result.consumer"
    );
    assert_eq!(description.service().oauth_capabilities().len(), 4);
    assert!(
        description
            .service()
            .oauth_capabilities()
            .iter()
            .all(|requirement| requirement.read_only() && !requirement.content_bytes_requested())
    );
    assert!(
        description
            .service()
            .oauth_capabilities()
            .iter()
            .all(|requirement| requirement
                .allowed_zoom_scopes()
                .iter()
                .all(|scope| !scope.contains("write")))
    );
    assert!(description.metadata_only());
    assert!(!description.content_bytes_read());
    assert_eq!(
        description.content_byte_verification(),
        ContentByteVerification::NotPerformed
    );
    assert!(
        !description
            .provider()
            .provenance()
            .eq(&ProviderProvenance::BlockedEnvironment)
    );
    assert!(!service.provider_state().can_claim_native_or_connected());
}

#[test]
fn mission_consumer_emits_deterministic_non_mutating_proposal() {
    let scope = scope();
    let service = ZoomMeetingResultService::new(
        ZoomMeetingResultProvider::recording(
            vec![page(
                vec![
                    file(
                        "recording-1",
                        RecordingFileType::Video,
                        RecordingFileStatus::Available,
                    ),
                    file(
                        "transcript-1",
                        RecordingFileType::Transcript,
                        RecordingFileStatus::Available,
                    ),
                ],
                None,
            )],
            PROVIDER_REVISION,
        )
        .expect("recording provider"),
        scope.clone(),
        secret(&scope),
    )
    .expect("service");
    let consumer = MissionZoomMeetingResultConsumer::new(service);
    let context = MissionContext::from_scope(&scope);
    let result = consumer
        .consume(&context, PageBudget::bounded())
        .expect("Mission result");
    assert_eq!(result.listing().recording_files().len(), 2);
    assert_eq!(result.listing().pages_examined(), 1);
    assert_eq!(
        result.proposal().evidence_kind(),
        EvidenceKind::MetadataFingerprintOnly
    );
    assert!(result.proposal().non_mutating());
    assert!(!result.proposal().work_product_adopted());
    assert_eq!(
        result.proposal().content_byte_verification(),
        ContentByteVerification::NotPerformed
    );
    assert_eq!(
        result.verification().status(),
        ArtifactVerificationStatus::MetadataFingerprintBound
    );
    assert!(!result.verification().content_bytes_read());
    assert_eq!(
        result.verification().content_byte_verification(),
        ContentByteVerification::NotPerformed
    );

    let serialized = serde_json::to_string(result.proposal()).expect("proposal JSON");
    assert!(!serialized.contains("accessToken"));
    assert!(!serialized.contains("signedDownloadUrl"));
    assert!(!serialized.contains("transcriptText"));
    assert!(!serialized.contains("participants"));
    assert!(!serialized.contains("mediaBytes"));
    let secret_debug = format!("{:?}", consumer.service().secret_reference());
    assert!(!secret_debug.contains("access-token-sentinel"));
}

#[test]
fn recording_and_fake_are_truthful_and_blocked_env_never_claims_native() {
    let scope = scope();
    let recording = ZoomMeetingResultProvider::recording(
        vec![page(
            vec![file(
                "recording-1",
                RecordingFileType::Video,
                RecordingFileStatus::Available,
            )],
            None,
        )],
        PROVIDER_REVISION,
    )
    .expect("recording provider");
    assert_eq!(recording.mode(), ProviderMode::Recording);
    assert_eq!(
        recording.state().provenance(),
        ProviderProvenance::ControlledRecording
    );
    let fake = ZoomMeetingResultProvider::fake(
        vec![page(
            vec![file(
                "recording-1",
                RecordingFileType::Video,
                RecordingFileStatus::Available,
            )],
            None,
        )],
        PROVIDER_REVISION,
    )
    .expect("fake provider");
    assert_eq!(fake.state().provenance(), ProviderProvenance::Fixture);

    let blocked =
        ZoomMeetingResultProvider::blocked_env("native OAuth is Layer 2", PROVIDER_REVISION)
            .expect("blocked provider");
    assert_eq!(blocked.state().mode(), ProviderMode::BlockedEnv);
    assert_eq!(
        blocked.state().provenance(),
        ProviderProvenance::BlockedEnvironment
    );
    assert!(!blocked.state().can_claim_native_or_connected());
    let service = ZoomMeetingResultService::new(blocked, scope.clone(), secret(&scope))
        .expect("blocked service registration");
    assert_eq!(
        service.probe_meeting_occurrence(),
        Err(ZoomMeetingResultError::Provider(
            ProviderError::BlockedEnvironment
        ))
    );
}

#[test]
fn pagination_is_bounded_and_cursor_loops_or_expiry_fail_closed() {
    let first = page(
        vec![file(
            "recording-1",
            RecordingFileType::Video,
            RecordingFileStatus::Available,
        )],
        Some("page-1"),
    );
    let second = page(
        vec![file(
            "transcript-1",
            RecordingFileType::Transcript,
            RecordingFileStatus::Available,
        )],
        None,
    );
    let listing = service(vec![first, second])
        .list_decision_artifacts(PageBudget::new(2, 4).expect("budget"))
        .expect("two pages");
    assert_eq!(listing.pages_examined(), 2);

    let loop_page = page(
        vec![file(
            "recording-1",
            RecordingFileType::Video,
            RecordingFileStatus::Available,
        )],
        Some("page-0"),
    );
    assert_eq!(
        service(vec![loop_page]).list_decision_artifacts(PageBudget::bounded()),
        Err(ZoomMeetingResultError::PaginationLoop)
    );

    let expired_page = page(
        vec![file(
            "recording-1",
            RecordingFileType::Video,
            RecordingFileStatus::Available,
        )],
        Some("page-99"),
    );
    assert_eq!(
        service(vec![expired_page]).list_decision_artifacts(PageBudget::bounded()),
        Err(ZoomMeetingResultError::Provider(
            ProviderError::CursorExpired
        ))
    );
}

#[test]
fn meeting_id_and_occurrence_uuid_are_independently_fenced() {
    let wrong_occurrence = MeetingOccurrenceMetadata::new(
        MeetingId::new(MEETING_ID).expect("meeting id"),
        OccurrenceUuid::new("123e4567-e89b-12d3-a456-426614174001").expect("uuid"),
        MeetingOccurrenceStatus::Available,
        Some(1_700_000_000_000),
        Some(1_700_000_360_000),
        1_700_000_400_000,
    )
    .expect("metadata");
    let wrong_page = ProviderPage::new(
        wrong_occurrence,
        vec![],
        None,
        None,
        None,
        PROVIDER_REVISION,
    )
    .expect("provider page");
    assert_eq!(
        service(vec![wrong_page]).probe_meeting_occurrence(),
        Err(ZoomMeetingResultError::OccurrenceAmbiguous)
    );
}

#[test]
fn status_metadata_preserves_processing_retention_and_url_expiry_without_url() {
    let scope = scope();
    let processing = RecordingFileMetadata::new(
        FileId::new("recording-1").expect("file id"),
        RecordingFileType::Video,
        RecordingType::GalleryView,
        RecordingFileStatus::Processing,
        None,
        None,
        None,
        1_700_000_400_000,
        RetentionState::AutoDeleteScheduled,
        Some(1_800_000_000_000),
        Some(1_700_000_800_000),
    )
    .expect("processing file");
    let service = ZoomMeetingResultService::new(
        ZoomMeetingResultProvider::fake(
            vec![
                ProviderPage::new(
                    occurrence(MeetingOccurrenceStatus::Processing),
                    vec![
                        processing,
                        file(
                            "transcript-1",
                            RecordingFileType::Transcript,
                            RecordingFileStatus::Available,
                        ),
                    ],
                    None,
                    None,
                    None,
                    PROVIDER_REVISION,
                )
                .expect("page"),
            ],
            PROVIDER_REVISION,
        )
        .expect("provider"),
        scope.clone(),
        secret(&scope),
    )
    .expect("service");
    let listing = service
        .list_decision_artifacts(PageBudget::bounded())
        .expect("listing");
    assert_eq!(
        listing.occurrence().status(),
        MeetingOccurrenceStatus::Processing
    );
    assert_eq!(
        listing.recording_files()[0].status(),
        RecordingFileStatus::Processing
    );
    assert_eq!(
        listing.recording_files()[0].retention_state(),
        RetentionState::AutoDeleteScheduled
    );
    let serialized = serde_json::to_string(&listing).expect("listing JSON");
    assert!(!serialized.contains("https://"));
    assert!(!serialized.contains("signedDownloadUrl"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn stale_mission_consent_and_revocation_cannot_execute() {
    let scope = scope();
    let provider = ZoomMeetingResultProvider::fake(
        vec![page(
            vec![
                file(
                    "recording-1",
                    RecordingFileType::Video,
                    RecordingFileStatus::Available,
                ),
                file(
                    "transcript-1",
                    RecordingFileType::Transcript,
                    RecordingFileStatus::Available,
                ),
            ],
            None,
        )],
        PROVIDER_REVISION,
    )
    .expect("provider");
    let service =
        ZoomMeetingResultService::new(provider, scope.clone(), secret(&scope)).expect("service");
    let consumer = MissionZoomMeetingResultConsumer::new(service);
    let stale_revision = MissionContext::new(
        "project-1",
        "mission-1",
        4,
        scope.consent_reference().clone(),
    )
    .expect("stale context");
    assert_eq!(
        consumer.consume(&stale_revision, PageBudget::bounded()),
        Err(ZoomMeetingResultError::StaleMissionRevision)
    );

    let stale_consent = ConsentReference::new(
        "consent-ref-rotated",
        scope.consent_reference().scope_digest(),
        6,
        None,
    )
    .expect("rotated consent");
    let stale_consent_context = MissionContext::new("project-1", "mission-1", 3, stale_consent)
        .expect("stale consent context");
    assert_eq!(
        consumer.consume(&stale_consent_context, PageBudget::bounded()),
        Err(ZoomMeetingResultError::StaleConsentReference)
    );

    let expired_consent = ConsentReference::new(
        "consent-ref-1",
        scope.consent_reference().scope_digest(),
        5,
        Some(100),
    )
    .expect("expired consent");
    let expired_scope = ZoomMeetingResultScope::new(scope.binding().clone(), expired_consent)
        .expect("expired scope remains exact but has expired consent metadata");
    let expired_service = ZoomMeetingResultService::new(
        ZoomMeetingResultProvider::fake(
            vec![page(
                vec![
                    file(
                        "recording-1",
                        RecordingFileType::Video,
                        RecordingFileStatus::Available,
                    ),
                    file(
                        "transcript-1",
                        RecordingFileType::Transcript,
                        RecordingFileStatus::Available,
                    ),
                ],
                None,
            )],
            PROVIDER_REVISION,
        )
        .expect("expired provider"),
        expired_scope.clone(),
        secret(&expired_scope),
    )
    .expect("expired service");
    let expired_consumer = MissionZoomMeetingResultConsumer::new(expired_service);
    assert_eq!(
        expired_consumer.consume_at(
            &MissionContext::from_scope(&expired_scope),
            PageBudget::bounded(),
            Some(100),
        ),
        Err(ZoomMeetingResultError::ExpiredConsent)
    );

    let mut service = consumer.into_service();
    let receipt = service.revoke();
    assert_eq!(
        receipt.state(),
        hartevo_zoom_meeting_result_plugin::RegistrationState::Revoked
    );
    assert_eq!(
        service.probe_meeting_occurrence(),
        Err(ZoomMeetingResultError::RegistrationRevoked)
    );
}

#[test]
fn tampered_metadata_fingerprint_is_rejected_before_projection() {
    let tampered = RecordingFileMetadata::new_with_metadata_fingerprint(
        FileId::new("recording-1").expect("file id"),
        RecordingFileType::Video,
        RecordingType::GalleryView,
        RecordingFileStatus::Available,
        Some(1_700_000_000_000),
        Some(1_700_000_360_000),
        Some(4096),
        1_700_000_400_000,
        RetentionState::Active,
        None,
        None,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("well-shaped but tampered metadata");
    assert_eq!(
        ProviderPage::new(
            occurrence(MeetingOccurrenceStatus::Available),
            vec![tampered],
            None,
            None,
            None,
            PROVIDER_REVISION,
        ),
        Err(ZoomMeetingResultError::Provider(
            ProviderError::MalformedPage
        ))
    );
}

#[test]
fn http_classification_is_explicit_and_non_mutating() {
    assert_eq!(
        ProviderError::from_http_status(403),
        ProviderError::Forbidden
    );
    assert_eq!(
        ProviderError::from_http_status(404),
        ProviderError::NotFound
    );
    assert_eq!(
        ProviderError::from_http_status(429),
        ProviderError::RateLimited {
            retry_after_seconds: None
        }
    );
    assert_eq!(
        ProviderError::Forbidden.outcome_state(),
        Some(hartevo_zoom_meeting_result_plugin::ProviderOutcomeState::PermissionDenied)
    );
    assert_eq!(ProviderError::NotFound.status_code(), Some(404));
}

#[test]
fn listing_digest_is_stable_for_reordered_provider_files() {
    let first = service(vec![page(
        vec![
            file(
                "recording-1",
                RecordingFileType::Video,
                RecordingFileStatus::Available,
            ),
            file(
                "transcript-1",
                RecordingFileType::Transcript,
                RecordingFileStatus::Available,
            ),
        ],
        None,
    )])
    .list_decision_artifacts(PageBudget::bounded())
    .expect("first listing");
    let second = service(vec![page(
        vec![
            file(
                "transcript-1",
                RecordingFileType::Transcript,
                RecordingFileStatus::Available,
            ),
            file(
                "recording-1",
                RecordingFileType::Video,
                RecordingFileStatus::Available,
            ),
        ],
        None,
    )])
    .list_decision_artifacts(PageBudget::bounded())
    .expect("second listing");
    assert_eq!(first.projection_digest(), second.projection_digest());
}

#[test]
fn missing_and_duplicate_selected_files_fail_closed() {
    let missing = service(vec![page(
        vec![file(
            "recording-1",
            RecordingFileType::Video,
            RecordingFileStatus::Available,
        )],
        None,
    )]);
    assert_eq!(
        missing.list_decision_artifacts(PageBudget::bounded()),
        Err(ZoomMeetingResultError::SelectedFileMissing(
            "transcript-1".to_owned()
        ))
    );

    let duplicate_first = page(
        vec![file(
            "recording-1",
            RecordingFileType::Video,
            RecordingFileStatus::Available,
        )],
        Some("page-1"),
    );
    let duplicate_second = page(
        vec![file(
            "recording-1",
            RecordingFileType::Video,
            RecordingFileStatus::Partial,
        )],
        None,
    );
    assert_eq!(
        service(vec![duplicate_first, duplicate_second])
            .list_decision_artifacts(PageBudget::bounded()),
        Err(ZoomMeetingResultError::DuplicateFileId(
            "recording-1".to_owned()
        ))
    );
}

#[test]
fn permission_loss_is_returned_without_fallback_or_native_claim() {
    let scope = scope();
    let service = ZoomMeetingResultService::new(
        FailingProvider::new(ProviderError::PermissionScopeLost),
        scope.clone(),
        secret(&scope),
    )
    .expect("service");
    assert_eq!(
        service.probe_meeting_occurrence(),
        Err(ZoomMeetingResultError::Provider(
            ProviderError::PermissionScopeLost
        ))
    );

    let service = ZoomMeetingResultService::new(
        FailingProvider::new(ProviderError::Forbidden),
        scope.clone(),
        secret(&scope),
    )
    .expect("403 service");
    assert_eq!(
        service.probe_meeting_occurrence(),
        Err(ZoomMeetingResultError::Provider(ProviderError::Forbidden))
    );
}

#[test]
fn registration_rejects_version_contract_and_provider_revision_drift() {
    let scope = scope();
    let scope_digest = Fingerprint::from_hex(scope.scope_digest().expect("scope digest"))
        .expect("scope fingerprint");
    let current_contract = contract_digest().expect("contract digest");
    let provider = ZoomMeetingResultProvider::fake(
        vec![page(
            vec![
                file(
                    "recording-1",
                    RecordingFileType::Video,
                    RecordingFileStatus::Available,
                ),
                file(
                    "transcript-1",
                    RecordingFileType::Transcript,
                    RecordingFileStatus::Available,
                ),
            ],
            None,
        )],
        PROVIDER_REVISION,
    )
    .expect("provider");

    let wrong_version = RegistrationRequest::new(
        PluginVersion::new(2, 0, 0),
        current_contract.clone(),
        PROVIDER_REVISION,
        scope_digest.clone(),
    )
    .expect("wrong version request");
    assert!(matches!(
        ZoomMeetingResultService::register(
            provider.clone(),
            scope.clone(),
            secret(&scope),
            wrong_version,
        ),
        Err(ZoomMeetingResultError::RegistrationVersionMismatch)
    ));

    let wrong_contract = RegistrationRequest::new(
        PluginVersion::new(1, 0, 0),
        Fingerprint::from_hex("f".repeat(64)).expect("wrong digest"),
        PROVIDER_REVISION,
        scope_digest.clone(),
    )
    .expect("wrong contract request");
    assert!(matches!(
        ZoomMeetingResultService::register(
            provider.clone(),
            scope.clone(),
            secret(&scope),
            wrong_contract,
        ),
        Err(ZoomMeetingResultError::RegistrationContractMismatch)
    ));

    let wrong_revision = RegistrationRequest::new(
        PluginVersion::new(1, 0, 0),
        current_contract,
        PROVIDER_REVISION + 1,
        scope_digest,
    )
    .expect("wrong provider revision request");
    assert!(matches!(
        ZoomMeetingResultService::register(provider, scope.clone(), secret(&scope), wrong_revision,),
        Err(ZoomMeetingResultError::RegistrationProviderRevisionMismatch)
    ));
}

#[test]
fn deletion_and_retention_expiry_remain_truthful_metadata_states() {
    let scope = scope();
    let deleted = RecordingFileMetadata::new(
        FileId::new("recording-1").expect("file id"),
        RecordingFileType::Video,
        RecordingType::GalleryView,
        RecordingFileStatus::Deleted,
        None,
        None,
        None,
        1_700_000_400_000,
        RetentionState::Deleted,
        None,
        None,
    )
    .expect("deleted metadata");
    let transcript = file(
        "transcript-1",
        RecordingFileType::Transcript,
        RecordingFileStatus::Available,
    );
    let service = ZoomMeetingResultService::new(
        ZoomMeetingResultProvider::fake(
            vec![
                ProviderPage::new(
                    occurrence(MeetingOccurrenceStatus::Deleted),
                    vec![deleted, transcript],
                    None,
                    None,
                    None,
                    PROVIDER_REVISION,
                )
                .expect("deleted page"),
            ],
            PROVIDER_REVISION,
        )
        .expect("deleted provider"),
        scope.clone(),
        secret(&scope),
    )
    .expect("deleted service");
    let listing = service
        .list_decision_artifacts(PageBudget::bounded())
        .expect("truthful deleted listing");
    assert_eq!(
        listing.occurrence().status(),
        MeetingOccurrenceStatus::Deleted
    );
    assert_eq!(
        listing.recording_files()[0].status(),
        RecordingFileStatus::Deleted
    );
    assert_eq!(
        listing.recording_files()[0].retention_state(),
        RetentionState::Deleted
    );
}

#[allow(dead_code)]
fn _assert_listing_is_serializable(listing: &DecisionArtifactListing) {
    let _ = serde_json::to_string(listing).expect("listing serializable");
}
