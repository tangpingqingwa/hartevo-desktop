#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Duration, Utc};
use hartevo_aws_control_tower_governance_result_plugin::{
    AwsControlTowerGovernanceContract, AwsControlTowerGovernanceService, AwsControlTowerProvider,
    AwsControlTowerReadRequest, AwsControlTowerScope, BaselineId, BaselineStatus,
    BlockedEnvTransport, Digest, DriftStatus, EnabledBaselineSummary, EvidenceStatus,
    FixtureTransport, GetLandingZoneOperationResponse, GetLandingZoneResponse, LandingZoneDetail,
    LandingZoneIdentity, LandingZoneOperation, LandingZoneStatus, ListEnabledBaselinesPage,
    ListLandingZonesPage, MissionAwsControlTowerConsumer, MissionId, OperationId, OperationStatus,
    OperationType, PermissionScope, ProjectId, ProviderProvenance, ReadBounds, RecordingTransport,
    RevisionId, SecretReference, TargetReference, TransportError, Version, WorkProductId,
};

type Service<T> = AwsControlTowerGovernanceService<T>;

const ACCOUNT: &str = "123456789012";
const HOME_REGION: &str = "us-east-1";
const LANDING_ZONE_ARN: &str = "arn:aws:controltower:us-east-1:123456789012:landingzone/lz-abc123";
const WRONG_REGION_LANDING_ZONE_ARN: &str =
    "arn:aws:controltower:us-west-2:123456789012:landingzone/lz-abc123";
const WRONG_ACCOUNT_LANDING_ZONE_ARN: &str =
    "arn:aws:controltower:us-east-1:999999999999:landingzone/lz-abc123";
const BASELINE_ARN: &str = "arn:aws:controltower:us-east-1:123456789012:baseline/bl-abc123";
const CHILD_BASELINE_ARN: &str = "arn:aws:controltower:us-east-1:123456789012:baseline/bl-child123";
const OU_TARGET_ARN: &str = "arn:aws:organizations::123456789012:ou/o-example/ou-abc12345";
const ACCOUNT_TARGET_ARN: &str = "arn:aws:organizations::123456789012:account/123456789012";
const OPERATION_ID: &str = "11111111-1111-4111-8111-111111111111";
const SECOND_OPERATION_ID: &str = "22222222-2222-4222-8222-222222222222";
const RAW_SECRET: &str = "raw-secret-handle-must-not-escape";

fn at(day: i64, hour: u32) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-08-{day:02}T{hour:02}:00:00Z"))
        .expect("timestamp")
        .with_timezone(&Utc)
}

struct Fixtures {
    scope: AwsControlTowerScope,
    landing_zone: LandingZoneIdentity,
    baseline: BaselineId,
    child_baseline: BaselineId,
    ou_target: TargetReference,
    account_target: TargetReference,
    operation: OperationId,
    permission_digest: Digest,
}

impl Fixtures {
    fn new() -> Self {
        let landing_zone = LandingZoneIdentity::new(LANDING_ZONE_ARN).expect("landing zone");
        let baseline = BaselineId::new(BASELINE_ARN).expect("baseline");
        let child_baseline = BaselineId::new(CHILD_BASELINE_ARN).expect("child baseline");
        let ou_target = TargetReference::new(OU_TARGET_ARN).expect("OU target");
        let account_target = TargetReference::new(ACCOUNT_TARGET_ARN).expect("account target");
        let operation = OperationId::new(OPERATION_ID).expect("operation");
        let second_operation = OperationId::new(SECOND_OPERATION_ID).expect("second operation");
        let permission = PermissionScope::all(
            RevisionId::new("permission-revision-1").expect("permission revision"),
        )
        .expect("permission");
        let permission_digest = permission.permission_digest.clone();
        let scope = AwsControlTowerScope::with_mission_revision(
            hartevo_aws_control_tower_governance_result_plugin::AccountId::new(ACCOUNT)
                .expect("account"),
            hartevo_aws_control_tower_governance_result_plugin::AwsRegion::new(HOME_REGION)
                .expect("region"),
            landing_zone.clone(),
            [baseline.clone(), child_baseline.clone()],
            [ou_target.clone(), account_target.clone()],
            [operation.clone(), second_operation.clone()],
            ProjectId::new("project-control-tower-1").expect("project"),
            MissionId::new("mission-control-tower-1").expect("mission"),
            WorkProductId::new("work-product-control-tower-1").expect("work product"),
            RevisionId::new("mission-revision-7").expect("mission revision"),
            permission,
        )
        .expect("scope");
        Self {
            scope,
            landing_zone,
            baseline,
            child_baseline,
            ou_target,
            account_target,
            operation,
            permission_digest,
        }
    }

    fn secret(&self) -> SecretReference {
        SecretReference::for_sigv4(RAW_SECRET, &self.scope).expect("secret")
    }

    fn service_with_recording(&self, transport: RecordingTransport) -> Service<RecordingTransport> {
        Service::new(
            self.scope.clone(),
            self.secret(),
            AwsControlTowerProvider::new(transport),
        )
        .expect("service")
    }

    fn landing_zone_summary(
        &self,
    ) -> hartevo_aws_control_tower_governance_result_plugin::LandingZoneSummary {
        hartevo_aws_control_tower_governance_result_plugin::LandingZoneSummary::new(
            self.landing_zone.clone(),
            LandingZoneStatus::Active,
            Version::new("3.0").expect("version"),
            at(14, 2),
        )
    }

    fn landing_zone_detail(&self, drift_status: DriftStatus) -> LandingZoneDetail {
        LandingZoneDetail::new(
            self.landing_zone.clone(),
            LandingZoneStatus::Active,
            drift_status,
            Version::new("3.0").expect("version"),
            Some(Version::new("3.1").expect("latest version")),
            Some(Digest::from_text("manifest-is-redacted")),
            at(14, 3),
        )
    }

    fn operation_detail(
        &self,
        status: OperationStatus,
        started_at: DateTime<Utc>,
    ) -> LandingZoneOperation {
        LandingZoneOperation::new(
            self.operation.clone(),
            self.landing_zone.clone(),
            OperationType::Update,
            status,
            Some("raw status message must be digested"),
            started_at,
            Some(started_at + Duration::hours(1)),
        )
        .expect("operation")
    }

    fn baseline(&self, child: bool) -> EnabledBaselineSummary {
        EnabledBaselineSummary::new(
            if child {
                self.child_baseline.clone()
            } else {
                self.baseline.clone()
            },
            self.account_target.clone(),
            Some(self.ou_target.clone()),
            Version::new("4.0").expect("baseline version"),
            BaselineStatus::Enabled,
            DriftStatus::InSync,
            Some(self.operation.clone()),
            child,
            at(14, 4),
        )
    }
}

#[test]
fn contract_scope_registration_and_opaque_secret_are_bound() {
    AwsControlTowerGovernanceContract::baseline().expect("contract validation");
    let fixtures = Fixtures::new();
    fixtures.scope.verify().expect("scope verification");
    let service = fixtures.service_with_recording(RecordingTransport::default());
    service.registration().validate().expect("registration");
    assert_eq!(
        service.registration().scope_digest,
        fixtures.scope.scope_digest
    );
    assert_eq!(service.registration().api_version, "2018-05-10");
    assert_eq!(service.describe_capabilities().operations.len(), 4);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().external_writes);
    assert!(!format!("{:?}", service.secret_reference()).contains(RAW_SECRET));
    assert!(
        !serde_json::to_string(&service.registration())
            .expect("registration JSON")
            .contains(RAW_SECRET)
    );
    let scope_json = serde_json::to_string(service.scope()).expect("scope JSON");
    assert!(!scope_json.contains(LANDING_ZONE_ARN));
    assert!(!scope_json.contains(ACCOUNT_TARGET_ARN));
}

#[test]
fn list_landing_zone_proposes_records_verifies_and_consumes_review_only_evidence() {
    let fixtures = Fixtures::new();
    let mut transport = RecordingTransport::default();
    transport.push_list_landing_zones(Ok(ListLandingZonesPage::for_provenance(
        vec![fixtures.landing_zone_summary()],
        None,
        fixtures.scope.scope_digest.clone(),
        fixtures.permission_digest.clone(),
        ProviderProvenance::Recording,
    )));
    let mut service = fixtures.service_with_recording(transport);
    let proposal = service.propose_list_landing_zones().expect("proposal");
    assert_eq!(proposal.state, EvidenceStatus::Complete);
    assert_eq!(proposal.evidence.landing_zones.len(), 1);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(proposal.evidence.redaction.raw_arns_redacted);
    assert!(proposal.evidence.redaction.raw_timestamps_redacted);
    let json = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!json.contains(LANDING_ZONE_ARN));
    assert!(!json.contains("raw status message"));
    assert!(service.verify_at(&proposal, at(14, 5)).valid);
    let mut consumer =
        MissionAwsControlTowerConsumer::new(fixtures.scope.clone(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.adopted_outcome);
    assert!(!result.adopted_work_product);
    assert!(!result.truth_authority);
    assert!(!result.compliance_claim);
    let first = service
        .record_at(&proposal, "mission-record-1", at(14, 5))
        .expect("record");
    let replay = service
        .record_at(&proposal, "mission-record-1", at(14, 6))
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.evidence_digest, replay.evidence_digest);
    assert!(
        consumer
            .record_at(&proposal, "consumer-record", at(14, 5))
            .expect("consumer record")
            .recorded
    );
}

#[test]
fn get_landing_zone_preserves_drift_and_status_transitions_as_digests() {
    let fixtures = Fixtures::new();
    let mut transport = RecordingTransport::default();
    transport.push_get_landing_zone(Ok(GetLandingZoneResponse::new(
        fixtures.landing_zone_detail(DriftStatus::Drifted),
        1024,
        ProviderProvenance::Recording,
    )));
    let mut service = fixtures.service_with_recording(transport);
    let proposal = service.propose_get_landing_zone().expect("proposal");
    let detail = proposal.evidence.landing_zone.as_ref().expect("detail");
    assert_eq!(detail.drift_status, DriftStatus::Drifted);
    assert_eq!(detail.status, LandingZoneStatus::Active);
    assert!(
        !serde_json::to_string(detail)
            .expect("detail JSON")
            .contains(LANDING_ZONE_ARN)
    );
    assert!(
        !serde_json::to_string(detail)
            .expect("detail JSON")
            .contains("3.0")
    );
    assert!(service.verify_at(&proposal, at(14, 5)).valid);
}

#[test]
fn operation_status_is_bound_to_exact_scope_and_ninety_day_retention() {
    let fixtures = Fixtures::new();
    let started_at = at(1, 2);
    let mut transport = RecordingTransport::default();
    transport.push_get_landing_zone_operation(Ok(GetLandingZoneOperationResponse::new(
        fixtures.operation_detail(OperationStatus::InProgress, started_at),
        1024,
        ProviderProvenance::Recording,
    )));
    let mut service = fixtures.service_with_recording(transport);
    let proposal = service
        .propose_get_landing_zone_operation(fixtures.operation.clone(), at(14, 2))
        .expect("operation proposal");
    assert_eq!(
        proposal
            .evidence
            .operation_detail
            .as_ref()
            .expect("operation")
            .status,
        OperationStatus::InProgress
    );
    assert!(
        proposal
            .evidence
            .operation_detail
            .as_ref()
            .expect("operation")
            .status_digest
            != Digest::zero()
    );

    let mut expired_transport = RecordingTransport::default();
    expired_transport.push_get_landing_zone_operation(Ok(GetLandingZoneOperationResponse::new(
        fixtures.operation_detail(OperationStatus::Succeeded, at(1, 1)),
        1024,
        ProviderProvenance::Recording,
    )));
    let mut expired_service = fixtures.service_with_recording(expired_transport);
    let expired = expired_service
        .propose_get_landing_zone_operation(
            fixtures.operation.clone(),
            at(14, 1) + Duration::days(90),
        )
        .expect("expired proposal");
    assert_eq!(expired.state, EvidenceStatus::RetentionExpired);
    assert!(!expired_service.verify_at(&expired, at(14, 2)).valid);
}

#[test]
fn child_baseline_inclusion_requires_exact_targets_and_explicit_include_children() {
    let fixtures = Fixtures::new();
    let mut transport = RecordingTransport::default();
    transport.push_list_enabled_baselines(Ok(ListEnabledBaselinesPage::for_provenance(
        vec![fixtures.baseline(true)],
        None,
        fixtures.scope.scope_digest.clone(),
        fixtures.permission_digest.clone(),
        ProviderProvenance::Recording,
    )));
    let mut service = fixtures.service_with_recording(transport);
    let proposal = service
        .propose_list_enabled_baselines(true)
        .expect("child baseline proposal");
    assert_eq!(proposal.state, EvidenceStatus::Complete);
    assert_eq!(proposal.evidence.enabled_baselines.len(), 1);
    assert!(proposal.evidence.enabled_baselines[0].is_child);

    let mut rejected_transport = RecordingTransport::default();
    rejected_transport.push_list_enabled_baselines(Ok(ListEnabledBaselinesPage::for_provenance(
        vec![fixtures.baseline(true)],
        None,
        fixtures.scope.scope_digest.clone(),
        fixtures.permission_digest.clone(),
        ProviderProvenance::Recording,
    )));
    let mut rejected_service = fixtures.service_with_recording(rejected_transport);
    let rejected = rejected_service
        .propose_list_enabled_baselines(false)
        .expect("bounded failure proposal");
    assert_eq!(rejected.state, EvidenceStatus::ScopeDrift);

    let injected_filter =
        hartevo_aws_control_tower_governance_result_plugin::EnabledBaselineFilter {
            baseline_ids: [BaselineId::new(
                "arn:aws:controltower:us-east-1:123456789012:baseline/bl-injected",
            )
            .expect("injected baseline")]
            .into_iter()
            .collect(),
            target_ids: fixtures.scope.target_ids.clone(),
        };
    let request = AwsControlTowerReadRequest::ListEnabledBaselines(
        service
            .list_enabled_baselines_request(true)
            .expect("request")
            .with_filter(injected_filter),
    );
    assert!(matches!(
        service.propose(&request),
        Err(hal::AwsControlTowerServiceError::OutOfScope)
    ));
}

#[test]
fn pagination_tokens_are_opaque_and_bounds_fail_closed() {
    let fixtures = Fixtures::new();
    let token = hartevo_aws_control_tower_governance_result_plugin::OpaqueCursor::new(
        "raw-provider-next-token",
    )
    .expect("cursor");
    let mut transport = RecordingTransport::default();
    transport.push_list_landing_zones(Ok(ListLandingZonesPage::for_provenance(
        Vec::new(),
        Some(token.clone()),
        fixtures.scope.scope_digest.clone(),
        fixtures.permission_digest.clone(),
        ProviderProvenance::Recording,
    )));
    transport.push_list_landing_zones(Ok(ListLandingZonesPage::for_provenance(
        vec![fixtures.landing_zone_summary()],
        None,
        fixtures.scope.scope_digest.clone(),
        fixtures.permission_digest.clone(),
        ProviderProvenance::Recording,
    )));
    let mut service = fixtures.service_with_recording(transport);
    let proposal = service
        .propose_list_landing_zones()
        .expect("pagination proposal");
    assert_eq!(proposal.evidence.pagination.pages_observed, 2);
    assert_eq!(proposal.evidence.pagination.cursor_digests.len(), 1);
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains("raw-provider-next-token")
    );
    assert!(!format!("{token:?}").contains("raw-provider-next-token"));

    let mut bounded_transport = RecordingTransport::default();
    bounded_transport.push_list_landing_zones(Ok(ListLandingZonesPage::for_provenance(
        Vec::new(),
        Some(
            hartevo_aws_control_tower_governance_result_plugin::OpaqueCursor::new("still-more")
                .expect("cursor"),
        ),
        fixtures.scope.scope_digest.clone(),
        fixtures.permission_digest.clone(),
        ProviderProvenance::Recording,
    )));
    let provider = AwsControlTowerProvider::with_bounds(
        bounded_transport,
        ReadBounds::new(1, 1, 1).expect("bounds"),
    );
    let secret = fixtures.secret();
    let mut bounded_service =
        Service::new(fixtures.scope.clone(), secret, provider).expect("service");
    let bounded = bounded_service
        .propose_list_landing_zones()
        .expect("bounded failure");
    assert_eq!(bounded.state, EvidenceStatus::PaginationIncomplete);
}

#[test]
fn all_transport_failures_map_to_non_native_fail_closed_states() {
    let cases = [
        (TransportError::BadRequest, EvidenceStatus::ProviderUnknown),
        (TransportError::Unauthorized, EvidenceStatus::AccessLoss),
        (TransportError::Forbidden, EvidenceStatus::AccessLoss),
        (TransportError::NotFound, EvidenceStatus::NotFound),
        (TransportError::Conflict, EvidenceStatus::Conflict),
        (
            TransportError::RateLimited {
                retry_after_seconds: Some(10),
            },
            EvidenceStatus::Throttled,
        ),
        (
            TransportError::ServerFailure {
                status_code: Some(503),
            },
            EvidenceStatus::ProviderUnknown,
        ),
        (TransportError::Timeout, EvidenceStatus::ProviderUnknown),
    ];
    for (error, expected) in cases {
        let fixtures = Fixtures::new();
        let mut transport = RecordingTransport::default();
        transport.push_list_landing_zones(Err(error));
        let mut service = fixtures.service_with_recording(transport);
        let proposal = service
            .propose_list_landing_zones()
            .expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.first_party);
    }
}

#[test]
fn blocked_env_fixture_loopback_and_recording_never_claim_native_or_connected() {
    let fixtures = Fixtures::new();
    let blocked_provider = AwsControlTowerProvider::new(BlockedEnvTransport::default());
    let mut blocked = Service::new(fixtures.scope.clone(), fixtures.secret(), blocked_provider)
        .expect("blocked service");
    let blocked_proposal = blocked
        .propose_list_landing_zones()
        .expect("blocked proposal");
    assert_eq!(blocked_proposal.state, EvidenceStatus::BlockedEnv);
    assert_eq!(
        blocked_proposal.evidence.provenance,
        ProviderProvenance::BlockedEnv
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);

    let fixture_provider = AwsControlTowerProvider::new(FixtureTransport::default());
    assert!(!fixture_provider.definition().connected);
    assert!(!fixture_provider.definition().native);
    assert!(!fixture_provider.definition().first_party);
}

#[test]
fn tamper_replay_revocation_stale_mission_and_region_fences_block() {
    let fixtures = Fixtures::new();
    let mut transport = RecordingTransport::default();
    transport.push_list_landing_zones(Ok(ListLandingZonesPage::for_provenance(
        vec![fixtures.landing_zone_summary()],
        None,
        fixtures.scope.scope_digest.clone(),
        fixtures.permission_digest.clone(),
        ProviderProvenance::Recording,
    )));
    let mut service = fixtures.service_with_recording(transport);
    let proposal = service.propose_list_landing_zones().expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.state = EvidenceStatus::AccessLoss;
    assert!(!service.verify_at(&tampered, at(14, 6)).valid);
    let mut consumer =
        MissionAwsControlTowerConsumer::new(fixtures.scope.clone(), service.registration().clone())
            .expect("consumer");
    consumer.replace_mission(hal::MissionBinding::new(
        fixtures.scope.project_id.clone(),
        MissionId::new("mission-stale").expect("stale mission"),
        fixtures.scope.work_product_id.clone(),
        RevisionId::new("mission-revision-8").expect("revision"),
    ));
    assert!(matches!(
        consumer.consume(&proposal),
        Err(hal::ConsumerError::StaleMission)
    ));

    let mut revoked_service = fixtures.service_with_recording(RecordingTransport::default());
    revoked_service.revoke_registration().expect("revoke");
    assert!(matches!(
        revoked_service.propose_list_landing_zones(),
        Err(hal::AwsControlTowerServiceError::RegistrationRevoked)
    ));

    let wrong_region =
        LandingZoneIdentity::new(WRONG_REGION_LANDING_ZONE_ARN).expect("wrong region");
    assert!(matches!(
        AwsControlTowerScope::new(
            fixtures.scope.account_id.clone(),
            fixtures.scope.home_region.clone(),
            wrong_region,
            fixtures.scope.baseline_ids.clone(),
            fixtures.scope.target_ids.clone(),
            fixtures.scope.operation_ids.clone(),
            fixtures.scope.project_id.clone(),
            fixtures.scope.mission_id.clone(),
            fixtures.scope.work_product_id.clone(),
            fixtures.scope.permission.clone(),
        ),
        Err(hal::model::ModelError::RegionMismatch { .. })
    ));
    let wrong_account =
        LandingZoneIdentity::new(WRONG_ACCOUNT_LANDING_ZONE_ARN).expect("wrong account");
    assert!(matches!(
        AwsControlTowerScope::new(
            fixtures.scope.account_id.clone(),
            fixtures.scope.home_region.clone(),
            wrong_account,
            fixtures.scope.baseline_ids.clone(),
            fixtures.scope.target_ids.clone(),
            fixtures.scope.operation_ids.clone(),
            fixtures.scope.project_id.clone(),
            fixtures.scope.mission_id.clone(),
            fixtures.scope.work_product_id.clone(),
            fixtures.scope.permission.clone(),
        ),
        Err(hal::model::ModelError::AccountMismatch { .. })
    ));
}

#[test]
fn provider_response_mismatch_and_operation_filter_injection_fail_closed() {
    let fixtures = Fixtures::new();
    let wrong_landing_zone =
        LandingZoneIdentity::new(WRONG_REGION_LANDING_ZONE_ARN).expect("wrong LZ");
    let wrong_detail = LandingZoneDetail::new(
        wrong_landing_zone,
        LandingZoneStatus::Active,
        DriftStatus::InSync,
        Version::new("3.0").expect("version"),
        None,
        None,
        at(14, 3),
    );
    let mut transport = RecordingTransport::default();
    transport.push_get_landing_zone(Ok(GetLandingZoneResponse::new(
        wrong_detail,
        512,
        ProviderProvenance::Recording,
    )));
    let mut service = fixtures.service_with_recording(transport);
    let proposal = service.propose_get_landing_zone().expect("drift proposal");
    assert_eq!(proposal.state, EvidenceStatus::RegionMismatch);

    let forged_operation = OperationId::new(SECOND_OPERATION_ID).expect("operation");
    let request = service
        .get_landing_zone_operation_request(forged_operation, at(14, 2))
        .expect("in-scope operation");
    let mut forged = request;
    forged.operation_id =
        OperationId::new("33333333-3333-4333-8333-333333333333").expect("forged operation");
    assert!(matches!(
        service.propose(&AwsControlTowerReadRequest::GetLandingZoneOperation(forged)),
        Err(hal::AwsControlTowerServiceError::OutOfScope)
    ));
}

#[test]
fn fixture_default_is_bounded_and_does_not_require_native_environment() {
    let fixtures = Fixtures::new();
    let provider = AwsControlTowerProvider::new(FixtureTransport::default());
    let mut service =
        Service::new(fixtures.scope.clone(), fixtures.secret(), provider).expect("service");
    let proposal = service.propose_list_landing_zones().expect("empty fixture");
    assert_eq!(proposal.state, EvidenceStatus::Complete);
    assert!(proposal.evidence.landing_zones.is_empty());
    assert!(!service.provider().definition().provenance.is_native());
}

#[test]
fn digest_and_opaque_cursor_properties_are_deterministic() {
    let fixtures = Fixtures::new();
    let first = fixtures.scope.scope_digest.clone();
    let second = fixtures.scope.scope_digest.clone();
    assert_eq!(first, second);
    let cursor = hartevo_aws_control_tower_governance_result_plugin::OpaqueCursor::new("cursor-a")
        .expect("cursor");
    assert_eq!(cursor.digest(), cursor.digest());
    assert_ne!(cursor.digest(), Digest::from_text("cursor-b"));
}

mod hal {
    pub use hartevo_aws_control_tower_governance_result_plugin::consumer::ConsumerError;
    pub use hartevo_aws_control_tower_governance_result_plugin::model;
    pub use hartevo_aws_control_tower_governance_result_plugin::model::MissionBinding;
    pub use hartevo_aws_control_tower_governance_result_plugin::service::AwsControlTowerServiceError;
}
