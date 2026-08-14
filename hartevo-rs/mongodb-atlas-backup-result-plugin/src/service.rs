use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::model::{
    AdoptionAvailability, AtlasCapability, CapabilitySet, ClusterMetadata, Digest,
    MeasurementWindow, ModelError, MongoDbAtlasRegistration, MongoDbAtlasScope,
    ProcessEvidenceState, ProviderFence, ProviderMode, ReadinessState, RestoreVerification,
    Revision, SecretReference, Snapshot, SnapshotStatus,
};
use crate::provider::{
    AtlasOperation, AtlasRequestReceipt, AtlasResultReceipt, BackupSnapshotPage,
    GetClusterMetadataRequest, GetProcessMeasurementsRequest, ListBackupSnapshotsRequest,
    MongoDbAtlasProvider, MongoDbAtlasProviderDefinition, MongoDbAtlasTransport,
    ProcessMeasurementsResponse, TransportError,
};
use crate::{
    MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION, MONGODB_ATLAS_BACKUP_RESULT_SERVICE_ID,
    MONGODB_ATLAS_BACKUP_RESULT_SERVICE_VERSION,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MongoDbAtlasBackupResultServiceDefinition {
    pub service_id: &'static str,
    pub service_version: &'static str,
    pub contract_version: &'static str,
    pub capabilities: CapabilitySet,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
}

impl Default for MongoDbAtlasBackupResultServiceDefinition {
    fn default() -> Self {
        Self {
            service_id: MONGODB_ATLAS_BACKUP_RESULT_SERVICE_ID,
            service_version: MONGODB_ATLAS_BACKUP_RESULT_SERVICE_VERSION,
            contract_version: MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION,
            capabilities: CapabilitySet::read_only(),
            read_only: true,
            live_execution: false,
            native: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub max_retry_after_seconds: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_retry_after_seconds: 300,
        }
    }
}

impl RetryPolicy {
    pub fn new(max_attempts: u8, max_retry_after_seconds: u64) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            max_retry_after_seconds,
        }
    }

    fn should_retry(self, error: &TransportError, attempt: u8) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }
        match error {
            TransportError::RateLimited {
                retry_after_seconds,
                ..
            } => retry_after_seconds.is_none_or(|seconds| seconds <= self.max_retry_after_seconds),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryEvidence {
    pub operation: AtlasOperation,
    pub attempts: u8,
    pub rate_limit_retries: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptKind {
    Request,
    Result,
    TransportFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub operation: AtlasOperation,
    pub kind: ReceiptKind,
    pub digest: Digest,
    pub scope_digest: Digest,
    pub attempt: u8,
    pub status: String,
    pub redacted: bool,
    pub native: bool,
}

impl Receipt {
    fn request(request: &AtlasRequestReceipt, attempt: u8) -> Self {
        Self {
            operation: request.operation,
            kind: ReceiptKind::Request,
            digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            attempt,
            status: "sent".to_owned(),
            redacted: true,
            native: false,
        }
    }

    fn result(result: &AtlasResultReceipt) -> Self {
        Self {
            operation: result.operation,
            kind: ReceiptKind::Result,
            digest: result.result_digest.clone(),
            scope_digest: result.scope_digest.clone(),
            attempt: result.attempt,
            status: result.status.to_owned(),
            redacted: true,
            native: false,
        }
    }

    fn failure(
        operation: AtlasOperation,
        request_digest: &Digest,
        scope_digest: &Digest,
        attempt: u8,
        status: &str,
    ) -> Self {
        Self {
            operation,
            kind: ReceiptKind::TransportFailure,
            digest: request_digest.clone(),
            scope_digest: scope_digest.clone(),
            attempt,
            status: status.to_owned(),
            redacted: true,
            native: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PartialReason {
    PageBoundReached,
    MeasurementWindowIncomplete,
    ClusterBackupDisabled,
    NoSnapshotInBound,
    TransportRateLimited,
    TransportNotFound,
    TransportAccessLost,
    TransportUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEvidence {
    pub page_count: u16,
    pub total_count: u64,
    pub snapshots: Vec<Snapshot>,
    pub digest: Digest,
}

impl SnapshotEvidence {
    fn new(pages: &[BackupSnapshotPage], snapshots: Vec<Snapshot>) -> Self {
        let page_count = pages.len() as u16;
        let total_count = pages.last().map_or(0, BackupSnapshotPage::total_count);
        let mut fields = vec![page_count.to_string(), total_count.to_string()];
        fields.extend(
            snapshots
                .iter()
                .map(|snapshot| snapshot.digest().as_str().to_owned()),
        );
        Self {
            page_count,
            total_count,
            snapshots,
            digest: Digest::from_parts("mongodb-atlas-snapshot-evidence", &fields),
        }
    }

    fn empty() -> Self {
        Self {
            page_count: 0,
            total_count: 0,
            snapshots: Vec::new(),
            digest: Digest::from_text("mongodb-atlas-missing-snapshot-evidence"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementEvidence {
    pub window: MeasurementWindow,
    pub process_digest: Digest,
    pub measurements: Vec<crate::model::MeasurementSeries>,
    pub complete: bool,
    pub state: ProcessEvidenceState,
    pub digest: Digest,
}

impl MeasurementEvidence {
    fn new(response: &ProcessMeasurementsResponse) -> Self {
        let state = if response.measurements().is_empty() {
            ProcessEvidenceState::Unknown
        } else if response.complete() {
            ProcessEvidenceState::Observed
        } else {
            ProcessEvidenceState::Partial
        };
        Self {
            window: response.window().clone(),
            process_digest: response.process_digest().clone(),
            measurements: response.measurements().to_vec(),
            complete: response.complete(),
            state,
            digest: response.digest(),
        }
    }

    fn empty(window: MeasurementWindow, process_digest: Digest) -> Self {
        Self {
            window,
            process_digest,
            measurements: Vec::new(),
            complete: false,
            state: ProcessEvidenceState::Unknown,
            digest: Digest::from_text("mongodb-atlas-missing-measurement-evidence"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterEvidence {
    pub metadata: ClusterMetadata,
    pub digest: Digest,
}

impl ClusterEvidence {
    fn new(metadata: &ClusterMetadata) -> Self {
        Self {
            metadata: metadata.clone(),
            digest: metadata.digest(),
        }
    }

    fn empty(scope: &MongoDbAtlasScope) -> Self {
        let metadata = ClusterMetadata::new(
            scope.project_id().clone(),
            scope.cluster_name().clone(),
            false,
            false,
            false,
            None,
            None,
        );
        Self::new(&metadata)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryReadinessEvidence {
    pub snapshots: SnapshotEvidence,
    pub measurements: MeasurementEvidence,
    pub cluster: ClusterEvidence,
    pub digests: crate::model::EvidenceDigests,
}

impl RecoveryReadinessEvidence {
    fn new(
        scope: &MongoDbAtlasScope,
        provider: &MongoDbAtlasProviderDefinition,
        snapshots: SnapshotEvidence,
        measurements: MeasurementEvidence,
        cluster: ClusterEvidence,
    ) -> Self {
        let digests = crate::model::EvidenceDigests {
            scope_digest: scope.digest().clone(),
            provider_digest: provider.provider_digest.clone(),
            capability_digest: provider.capabilities.digest(),
            consent_digest: scope.consent().digest().clone(),
            snapshot_digest: snapshots.digest.clone(),
            measurement_digest: measurements.digest.clone(),
            cluster_metadata_digest: cluster.digest.clone(),
        };
        Self {
            snapshots,
            measurements,
            cluster,
            digests,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native_provider(self) -> bool {
        false
    }

    pub const fn durable_receipt(self) -> bool {
        false
    }

    pub const fn restore_authority(self) -> bool {
        false
    }

    pub const fn truth_authority(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryReadinessProposal {
    pub state: ReadinessState,
    pub evidence: RecoveryReadinessEvidence,
    pub partial_reasons: Vec<PartialReason>,
    pub retry_evidence: Vec<RetryEvidence>,
    pub receipts: Vec<Receipt>,
    pub provider: ProviderFence,
    pub mode: ProviderMode,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub proposal_digest: Digest,
    pub restore_verification: RestoreVerification,
    pub adoption: AdoptionAvailability,
    pub authority: Layer1Authority,
    pub is_restore_success: bool,
}

impl RecoveryReadinessProposal {
    pub fn is_adopted(&self) -> bool {
        false
    }

    pub fn provider_mode(&self) -> ProviderMode {
        self.mode
    }

    fn new(
        state: ReadinessState,
        evidence: RecoveryReadinessEvidence,
        partial_reasons: Vec<PartialReason>,
        retry_evidence: Vec<RetryEvidence>,
        receipts: Vec<Receipt>,
        provider: ProviderFence,
        mode: ProviderMode,
        registration: &MongoDbAtlasRegistration,
    ) -> Self {
        let mut fields = vec![
            format!("{state:?}"),
            registration.registration_digest.as_str().to_owned(),
            registration.provider_digest.as_str().to_owned(),
            registration.scope_digest.as_str().to_owned(),
            evidence.digests.snapshot_digest.as_str().to_owned(),
            evidence.digests.measurement_digest.as_str().to_owned(),
            evidence.digests.cluster_metadata_digest.as_str().to_owned(),
        ];
        fields.extend(partial_reasons.iter().map(|reason| format!("{reason:?}")));
        fields.extend(
            receipts
                .iter()
                .map(|receipt| receipt.digest.as_str().to_owned()),
        );
        Self {
            state,
            evidence,
            partial_reasons,
            retry_evidence,
            receipts,
            provider,
            mode,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            mission_revision: registration.mission_revision,
            project_revision: registration.project_revision,
            proposal_digest: Digest::from_parts(
                "mongodb-atlas-recovery-readiness-proposal",
                &fields,
            ),
            restore_verification: RestoreVerification::NotPerformedLayer1,
            adoption: AdoptionAvailability::NotAdoptedLayer1,
            authority: Layer1Authority,
            is_restore_success: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReadinessRequest {
    scope_digest: Digest,
    measurement_window: MeasurementWindow,
    max_snapshot_pages: u16,
    snapshot_page_size: u16,
    expected_provider_digest: Digest,
    expected_mission_revision: Revision,
    expected_project_revision: Revision,
    requested_at: DateTime<Utc>,
}

impl RecoveryReadinessRequest {
    pub fn new(
        scope: &MongoDbAtlasScope,
        measurement_window: MeasurementWindow,
        expected_provider_digest: Digest,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::with_bounds(
            scope,
            measurement_window,
            expected_provider_digest,
            requested_at,
            8,
            100,
        )
    }

    pub fn with_bounds(
        scope: &MongoDbAtlasScope,
        measurement_window: MeasurementWindow,
        expected_provider_digest: Digest,
        requested_at: DateTime<Utc>,
        max_snapshot_pages: u16,
        snapshot_page_size: u16,
    ) -> Result<Self, ModelError> {
        if max_snapshot_pages == 0 || max_snapshot_pages > crate::model::MAX_SNAPSHOT_PAGES {
            return Err(ModelError::InvalidSnapshotBounds);
        }
        if snapshot_page_size == 0 || snapshot_page_size > crate::model::MAX_SNAPSHOT_PAGE_SIZE {
            return Err(ModelError::InvalidSnapshotPageSize);
        }
        Ok(Self {
            scope_digest: scope.digest().clone(),
            measurement_window,
            max_snapshot_pages,
            snapshot_page_size,
            expected_provider_digest,
            expected_mission_revision: scope.mission_revision(),
            expected_project_revision: scope.project_revision(),
            requested_at,
        })
    }

    pub fn with_revision_fences(
        mut self,
        mission_revision: Revision,
        project_revision: Revision,
    ) -> Self {
        self.expected_mission_revision = mission_revision;
        self.expected_project_revision = project_revision;
        self
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn measurement_window(&self) -> &MeasurementWindow {
        &self.measurement_window
    }

    pub const fn max_snapshot_pages(&self) -> u16 {
        self.max_snapshot_pages
    }

    pub const fn snapshot_page_size(&self) -> u16 {
        self.snapshot_page_size
    }

    pub fn expected_provider_digest(&self) -> &Digest {
        &self.expected_provider_digest
    }

    pub const fn expected_mission_revision(&self) -> Revision {
        self.expected_mission_revision
    }

    pub const fn expected_project_revision(&self) -> Revision {
        self.expected_project_revision
    }

    pub const fn requested_at(&self) -> DateTime<Utc> {
        self.requested_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKind {
    CreateSnapshot,
    DeleteSnapshot,
    RestoreCluster,
    MutateAtlas,
    QueryDatabase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEffectRequest {
    pub kind: EffectKind,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub proposal_digest: Digest,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EffectError {
    #[error("Layer 1 has no Atlas effect authority; Layer 2 is required")]
    Layer2Required,
    #[error("effect is not permitted by this read-only contract")]
    NotPermitted,
}

pub trait EffectAuthority {
    fn submit(&mut self, request: &RecoveryEffectRequest) -> Result<Receipt, EffectError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Layer1EffectBoundary;

impl EffectAuthority for Layer1EffectBoundary {
    fn submit(&mut self, _request: &RecoveryEffectRequest) -> Result<Receipt, EffectError> {
        Err(EffectError::Layer2Required)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReadBackError {
    #[error("native receipt read-back is Layer 2 authority")]
    Layer2Required,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadBackRecord {
    pub receipt_digest: Digest,
    pub verified: bool,
    pub native: bool,
}

pub trait ReceiptReadBack {
    fn read_back(&self, receipt: &Receipt) -> Result<ReadBackRecord, ReadBackError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Layer1ReadBackBoundary;

impl ReceiptReadBack for Layer1ReadBackBoundary {
    fn read_back(&self, _receipt: &Receipt) -> Result<ReadBackRecord, ReadBackError> {
        Err(ReadBackError::Layer2Required)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MongoDbAtlasBackupResultServiceError {
    #[error("MongoDB Atlas service registration is revoked")]
    Revoked,
    #[error("secret reference does not match the governed scope")]
    SecretScopeMismatch,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("provider definition does not match the expected digest")]
    ProviderDigestMismatch,
    #[error("Mission revision fence is stale")]
    MissionRevisionMismatch,
    #[error("Project revision fence is stale")]
    ProjectRevisionMismatch,
    #[error("consent is expired or revoked")]
    ConsentInvalid,
    #[error("request scope does not match service scope")]
    ScopeMismatch,
    #[error("provider response scope is stale")]
    ResponseScopeMismatch,
    #[error("provider response project or cluster is outside scope")]
    ResponseResourceMismatch,
    #[error("provider response process is outside scope")]
    ResponseProcessMismatch,
    #[error("provider response measurement window is outside request")]
    ResponseWindowMismatch,
    #[error("provider response digest does not match its immutable fields")]
    ResponseDigestMismatch,
    #[error("provider returned more snapshots than the requested page bound")]
    SnapshotPageOverflow,
    #[error("transport failed for {operation}: {error}")]
    Transport {
        operation: AtlasOperation,
        error: TransportError,
    },
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
}

#[derive(Debug)]
pub struct MongoDbAtlasBackupResultService<T = crate::provider::BlockedEnvTransport> {
    scope: MongoDbAtlasScope,
    secret: SecretReference,
    provider: MongoDbAtlasProvider<T>,
    registration: MongoDbAtlasRegistration,
    retry_policy: RetryPolicy,
    active: bool,
}

impl<T: MongoDbAtlasTransport> MongoDbAtlasBackupResultService<T> {
    pub fn new(
        scope: MongoDbAtlasScope,
        secret: SecretReference,
        provider: MongoDbAtlasProvider<T>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, MongoDbAtlasBackupResultServiceError> {
        if secret.scope_digest() != scope.digest() {
            return Err(MongoDbAtlasBackupResultServiceError::SecretScopeMismatch);
        }
        if secret.is_revoked() {
            return Err(MongoDbAtlasBackupResultServiceError::SecretRevoked);
        }
        let definition = provider.definition();
        let required = [
            AtlasCapability::BackupSnapshotRead,
            AtlasCapability::ProcessMeasurementRead,
            AtlasCapability::ClusterMetadataRead,
        ];
        if required
            .iter()
            .any(|capability| !definition.supports(*capability))
        {
            return Err(MongoDbAtlasBackupResultServiceError::ProviderDigestMismatch);
        }
        let registration = MongoDbAtlasRegistration::new(
            MONGODB_ATLAS_BACKUP_RESULT_SERVICE_VERSION,
            definition.provider_id.clone(),
            definition.provider_version.clone(),
            definition.provider_digest.clone(),
            definition.capabilities.digest(),
            &scope,
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            retry_policy,
            active: true,
        })
    }

    pub fn scope(&self) -> &MongoDbAtlasScope {
        &self.scope
    }

    pub fn provider(&self) -> &MongoDbAtlasProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut MongoDbAtlasProvider<T> {
        &mut self.provider
    }

    pub fn definition(&self) -> MongoDbAtlasBackupResultServiceDefinition {
        MongoDbAtlasBackupResultServiceDefinition::default()
    }

    pub fn registration(&self) -> &MongoDbAtlasRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), MongoDbAtlasBackupResultServiceError> {
        if !self.active {
            return Err(MongoDbAtlasBackupResultServiceError::Revoked);
        }
        self.active = false;
        self.registration.revoke()?;
        Ok(())
    }

    pub fn propose(
        &mut self,
        request: RecoveryReadinessRequest,
    ) -> Result<RecoveryReadinessProposal, MongoDbAtlasBackupResultServiceError> {
        self.validate_request(&request)?;
        let provider = self.provider.definition().clone();
        let mut receipts = Vec::new();
        let mut retry_evidence = Vec::new();

        let (pages, snapshot_failure) =
            self.collect_snapshots(&request, &mut receipts, &mut retry_evidence)?;
        if let Some((attempt, error)) = snapshot_failure {
            return Ok(self.failure_proposal(
                failure_state(AtlasOperation::ListBackupSnapshots, &error),
                PartialReason::from_transport(&error),
                Receipt::failure(
                    AtlasOperation::ListBackupSnapshots,
                    &ListBackupSnapshotsRequest::new(&self.scope, 1, request.snapshot_page_size())?
                        .request_digest()
                        .clone(),
                    self.scope.digest(),
                    attempt,
                    transport_status(&error),
                ),
                receipts,
                retry_evidence,
                provider,
                request.measurement_window().clone(),
            ));
        }

        let pages = pages.unwrap_or_default();
        let snapshots = pages
            .iter()
            .flat_map(|page| page.snapshots().iter().cloned())
            .collect::<Vec<_>>();
        let snapshot_evidence = SnapshotEvidence::new(&pages, snapshots);

        let measurement_request =
            GetProcessMeasurementsRequest::new(&self.scope, request.measurement_window().clone())?;
        let (measurement_response, measurement_failure) =
            self.call_measurements(&measurement_request, &mut receipts, &mut retry_evidence);
        if let Some((attempt, error)) = measurement_failure {
            return Ok(self.failure_proposal(
                failure_state(AtlasOperation::GetProcessMeasurements, &error),
                PartialReason::from_transport(&error),
                Receipt::failure(
                    AtlasOperation::GetProcessMeasurements,
                    measurement_request.request_digest(),
                    self.scope.digest(),
                    attempt,
                    transport_status(&error),
                ),
                receipts,
                retry_evidence,
                provider,
                request.measurement_window().clone(),
            ));
        }
        let measurement_response = measurement_response.expect("successful measurement response");
        validate_measurement_response(&self.scope, &measurement_request, &measurement_response)?;
        receipts.push(Receipt::result(&AtlasResultReceipt::new(
            AtlasOperation::GetProcessMeasurements,
            measurement_response.digest(),
            self.scope.digest().clone(),
            "ok",
            retry_evidence
                .last()
                .map_or(1, |evidence| evidence.attempts),
        )));
        let measurement_evidence = MeasurementEvidence::new(&measurement_response);

        let cluster_request = GetClusterMetadataRequest::new(&self.scope)?;
        let (cluster_response, cluster_failure) =
            self.call_cluster(&cluster_request, &mut receipts, &mut retry_evidence);
        if let Some((attempt, error)) = cluster_failure {
            return Ok(self.failure_proposal(
                failure_state(AtlasOperation::GetClusterMetadata, &error),
                PartialReason::from_transport(&error),
                Receipt::failure(
                    AtlasOperation::GetClusterMetadata,
                    cluster_request.request_digest(),
                    self.scope.digest(),
                    attempt,
                    transport_status(&error),
                ),
                receipts,
                retry_evidence,
                provider,
                request.measurement_window().clone(),
            ));
        }
        let cluster_response = cluster_response.expect("successful cluster response");
        validate_cluster_response(&self.scope, &cluster_request, &cluster_response)?;
        receipts.push(Receipt::result(&AtlasResultReceipt::new(
            AtlasOperation::GetClusterMetadata,
            cluster_response.digest(),
            self.scope.digest().clone(),
            "ok",
            retry_evidence
                .last()
                .map_or(1, |evidence| evidence.attempts),
        )));
        let cluster_evidence = ClusterEvidence::new(cluster_response.metadata());

        let mut partial_reasons = Vec::new();
        let state = readiness_state(
            &snapshot_evidence,
            &measurement_evidence,
            &cluster_evidence,
            &mut partial_reasons,
            pages.last().is_some_and(BackupSnapshotPage::more_pages),
        );
        let evidence = RecoveryReadinessEvidence::new(
            &self.scope,
            &provider,
            snapshot_evidence,
            measurement_evidence,
            cluster_evidence,
        );
        Ok(RecoveryReadinessProposal::new(
            state,
            evidence,
            partial_reasons,
            retry_evidence,
            receipts,
            ProviderFence {
                provider_id: provider.provider_id,
                provider_version: provider.provider_version,
                provider_digest: provider.provider_digest,
            },
            provider.mode,
            &self.registration,
        ))
    }

    fn validate_request(
        &self,
        request: &RecoveryReadinessRequest,
    ) -> Result<(), MongoDbAtlasBackupResultServiceError> {
        if !self.active || !self.registration.is_active() {
            return Err(MongoDbAtlasBackupResultServiceError::Revoked);
        }
        if self.secret.is_revoked() {
            return Err(MongoDbAtlasBackupResultServiceError::SecretRevoked);
        }
        if self.secret.scope_digest() != self.scope.digest()
            || request.scope_digest() != self.scope.digest()
        {
            return Err(MongoDbAtlasBackupResultServiceError::ScopeMismatch);
        }
        if request.expected_provider_digest() != &self.provider.definition().provider_digest {
            return Err(MongoDbAtlasBackupResultServiceError::ProviderDigestMismatch);
        }
        if request.expected_mission_revision() != self.scope.mission_revision() {
            return Err(MongoDbAtlasBackupResultServiceError::MissionRevisionMismatch);
        }
        if request.expected_project_revision() != self.scope.project_revision() {
            return Err(MongoDbAtlasBackupResultServiceError::ProjectRevisionMismatch);
        }
        if !self.scope.consent().is_valid_at(request.requested_at()) {
            return Err(MongoDbAtlasBackupResultServiceError::ConsentInvalid);
        }
        Ok(())
    }

    fn collect_snapshots(
        &mut self,
        request: &RecoveryReadinessRequest,
        receipts: &mut Vec<Receipt>,
        retry_evidence: &mut Vec<RetryEvidence>,
    ) -> Result<
        (
            Option<Vec<BackupSnapshotPage>>,
            Option<(u8, TransportError)>,
        ),
        MongoDbAtlasBackupResultServiceError,
    > {
        let mut pages = Vec::new();
        for page_num in 1..=request.max_snapshot_pages() {
            let page_request = ListBackupSnapshotsRequest::new(
                &self.scope,
                page_num,
                request.snapshot_page_size(),
            )?;
            let (response, failure) = self.call_snapshots(&page_request, receipts, retry_evidence);
            if let Some(failure) = failure {
                return Ok((Some(pages), Some(failure)));
            }
            let response = response.expect("successful snapshot response");
            validate_snapshot_response(&self.scope, &page_request, &response)?;
            if response.snapshots().len() > usize::from(request.snapshot_page_size()) {
                return Err(MongoDbAtlasBackupResultServiceError::SnapshotPageOverflow);
            }
            receipts.push(Receipt::result(&AtlasResultReceipt::new(
                AtlasOperation::ListBackupSnapshots,
                response.digest(),
                self.scope.digest().clone(),
                "ok",
                retry_evidence
                    .last()
                    .map_or(1, |evidence| evidence.attempts),
            )));
            let more_pages = response.more_pages();
            pages.push(response);
            if !more_pages {
                break;
            }
        }
        Ok((Some(pages), None))
    }

    fn call_snapshots(
        &mut self,
        request: &ListBackupSnapshotsRequest,
        receipts: &mut Vec<Receipt>,
        retry_evidence: &mut Vec<RetryEvidence>,
    ) -> (Option<BackupSnapshotPage>, Option<(u8, TransportError)>) {
        let mut attempt = 1;
        let mut rate_limit_retries = 0;
        loop {
            receipts.push(Receipt::request(&request.receipt(), attempt));
            match self.provider.list_backup_snapshots(request) {
                Ok(response) => {
                    retry_evidence.push(RetryEvidence {
                        operation: AtlasOperation::ListBackupSnapshots,
                        attempts: attempt,
                        rate_limit_retries,
                    });
                    return (Some(response), None);
                }
                Err(error) if self.retry_policy.should_retry(&error, attempt) => {
                    if matches!(error, TransportError::RateLimited { .. }) {
                        rate_limit_retries = rate_limit_retries.saturating_add(1);
                    }
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    retry_evidence.push(RetryEvidence {
                        operation: AtlasOperation::ListBackupSnapshots,
                        attempts: attempt,
                        rate_limit_retries,
                    });
                    return (None, Some((attempt, error)));
                }
            }
        }
    }

    fn call_measurements(
        &mut self,
        request: &GetProcessMeasurementsRequest,
        receipts: &mut Vec<Receipt>,
        retry_evidence: &mut Vec<RetryEvidence>,
    ) -> (
        Option<ProcessMeasurementsResponse>,
        Option<(u8, TransportError)>,
    ) {
        let mut attempt = 1;
        let mut rate_limit_retries = 0;
        loop {
            receipts.push(Receipt::request(&request.receipt(), attempt));
            match self.provider.get_process_measurements(request) {
                Ok(response) => {
                    retry_evidence.push(RetryEvidence {
                        operation: AtlasOperation::GetProcessMeasurements,
                        attempts: attempt,
                        rate_limit_retries,
                    });
                    return (Some(response), None);
                }
                Err(error) if self.retry_policy.should_retry(&error, attempt) => {
                    if matches!(error, TransportError::RateLimited { .. }) {
                        rate_limit_retries = rate_limit_retries.saturating_add(1);
                    }
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    retry_evidence.push(RetryEvidence {
                        operation: AtlasOperation::GetProcessMeasurements,
                        attempts: attempt,
                        rate_limit_retries,
                    });
                    return (None, Some((attempt, error)));
                }
            }
        }
    }

    fn call_cluster(
        &mut self,
        request: &GetClusterMetadataRequest,
        receipts: &mut Vec<Receipt>,
        retry_evidence: &mut Vec<RetryEvidence>,
    ) -> (
        Option<crate::provider::ClusterMetadataResponse>,
        Option<(u8, TransportError)>,
    ) {
        let mut attempt = 1;
        let mut rate_limit_retries = 0;
        loop {
            receipts.push(Receipt::request(&request.receipt(), attempt));
            match self.provider.get_cluster_metadata(request) {
                Ok(response) => {
                    retry_evidence.push(RetryEvidence {
                        operation: AtlasOperation::GetClusterMetadata,
                        attempts: attempt,
                        rate_limit_retries,
                    });
                    return (Some(response), None);
                }
                Err(error) if self.retry_policy.should_retry(&error, attempt) => {
                    if matches!(error, TransportError::RateLimited { .. }) {
                        rate_limit_retries = rate_limit_retries.saturating_add(1);
                    }
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    retry_evidence.push(RetryEvidence {
                        operation: AtlasOperation::GetClusterMetadata,
                        attempts: attempt,
                        rate_limit_retries,
                    });
                    return (None, Some((attempt, error)));
                }
            }
        }
    }

    fn failure_proposal(
        &self,
        state: ReadinessState,
        reason: PartialReason,
        failure_receipt: Receipt,
        mut receipts: Vec<Receipt>,
        retry_evidence: Vec<RetryEvidence>,
        provider: MongoDbAtlasProviderDefinition,
        measurement_window: MeasurementWindow,
    ) -> RecoveryReadinessProposal {
        receipts.push(failure_receipt);
        let evidence = RecoveryReadinessEvidence::new(
            &self.scope,
            &provider,
            SnapshotEvidence::empty(),
            MeasurementEvidence::empty(measurement_window, self.scope.process().id().digest()),
            ClusterEvidence::empty(&self.scope),
        );
        RecoveryReadinessProposal::new(
            state,
            evidence,
            vec![reason],
            retry_evidence,
            receipts,
            ProviderFence {
                provider_id: provider.provider_id,
                provider_version: provider.provider_version,
                provider_digest: provider.provider_digest,
            },
            provider.mode,
            &self.registration,
        )
    }
}

fn validate_snapshot_response(
    scope: &MongoDbAtlasScope,
    request: &ListBackupSnapshotsRequest,
    response: &BackupSnapshotPage,
) -> Result<(), MongoDbAtlasBackupResultServiceError> {
    if response.scope_digest() != scope.digest() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseScopeMismatch);
    }
    if response.project_id() != scope.project_id()
        || response.cluster_name() != scope.cluster_name()
        || response.page_num() != request.page_num()
    {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseResourceMismatch);
    }
    if response.digest() != *response.declared_digest() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseDigestMismatch);
    }
    Ok(())
}

fn validate_measurement_response(
    scope: &MongoDbAtlasScope,
    request: &GetProcessMeasurementsRequest,
    response: &ProcessMeasurementsResponse,
) -> Result<(), MongoDbAtlasBackupResultServiceError> {
    if response.scope_digest() != scope.digest() || response.project_id() != scope.project_id() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseScopeMismatch);
    }
    if response.process_digest() != &request.process_digest() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseProcessMismatch);
    }
    if response.window() != request.window() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseWindowMismatch);
    }
    if response.measurements().len() > crate::model::MAX_MEASUREMENT_SERIES {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseWindowMismatch);
    }
    for series in response.measurements() {
        if series.points.len() > request.window().max_points() as usize
            || series.points.iter().any(|point| {
                point.timestamp < request.window().start()
                    || point.timestamp > request.window().end()
            })
        {
            return Err(MongoDbAtlasBackupResultServiceError::ResponseWindowMismatch);
        }
    }
    if response.digest() != *response.declared_digest() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseDigestMismatch);
    }
    Ok(())
}

fn validate_cluster_response(
    scope: &MongoDbAtlasScope,
    request: &GetClusterMetadataRequest,
    response: &crate::provider::ClusterMetadataResponse,
) -> Result<(), MongoDbAtlasBackupResultServiceError> {
    if response.scope_digest() != scope.digest() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseScopeMismatch);
    }
    if response.project_id() != request.project_id()
        || response.cluster_name() != request.cluster_name()
        || response.metadata().project_id != *scope.project_id()
        || response.metadata().cluster_name != *scope.cluster_name()
    {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseResourceMismatch);
    }
    if response.digest() != *response.declared_digest() {
        return Err(MongoDbAtlasBackupResultServiceError::ResponseDigestMismatch);
    }
    Ok(())
}

fn readiness_state(
    snapshots: &SnapshotEvidence,
    measurements: &MeasurementEvidence,
    cluster: &ClusterEvidence,
    partial_reasons: &mut Vec<PartialReason>,
    page_bound_reached: bool,
) -> ReadinessState {
    if page_bound_reached {
        partial_reasons.push(PartialReason::PageBoundReached);
        return ReadinessState::Partial;
    }
    if !cluster.metadata.backup_enabled || !cluster.metadata.point_in_time_enabled {
        partial_reasons.push(PartialReason::ClusterBackupDisabled);
        return ReadinessState::RetentionGap;
    }
    if snapshots.snapshots.is_empty() {
        partial_reasons.push(PartialReason::NoSnapshotInBound);
        return ReadinessState::RetentionGap;
    }
    if !measurements.complete || measurements.state != ProcessEvidenceState::Observed {
        partial_reasons.push(PartialReason::MeasurementWindowIncomplete);
        return ReadinessState::Partial;
    }
    let statuses = snapshots
        .snapshots
        .iter()
        .map(|snapshot| snapshot.status)
        .collect::<Vec<_>>();
    if statuses
        .iter()
        .any(|status| matches!(status, SnapshotStatus::Failed))
    {
        return ReadinessState::Failed;
    }
    if statuses
        .iter()
        .all(|status| matches!(status, SnapshotStatus::Expired))
    {
        return ReadinessState::Expired;
    }
    if statuses
        .iter()
        .any(|status| matches!(status, SnapshotStatus::Queued))
    {
        return ReadinessState::Queued;
    }
    if statuses
        .iter()
        .any(|status| matches!(status, SnapshotStatus::InProgress))
    {
        return ReadinessState::InProgress;
    }
    if statuses
        .iter()
        .any(|status| matches!(status, SnapshotStatus::Unknown))
    {
        return ReadinessState::Partial;
    }
    ReadinessState::Completed
}

fn failure_state(operation: AtlasOperation, error: &TransportError) -> ReadinessState {
    match error {
        TransportError::AccessLost => ReadinessState::AccessLoss,
        TransportError::ProviderUnknown(_) | TransportError::BlockedEnv { .. } => {
            ReadinessState::ProviderUnknown
        }
        TransportError::NotFound if matches!(operation, AtlasOperation::ListBackupSnapshots) => {
            ReadinessState::RetentionGap
        }
        TransportError::RateLimited { .. } | TransportError::NotFound => ReadinessState::Partial,
        TransportError::InvalidResponse => ReadinessState::ProviderUnknown,
    }
}

impl PartialReason {
    fn from_transport(error: &TransportError) -> Self {
        match error {
            TransportError::RateLimited { .. } => Self::TransportRateLimited,
            TransportError::NotFound => Self::TransportNotFound,
            TransportError::AccessLost => Self::TransportAccessLost,
            _ => Self::TransportUnknown,
        }
    }
}

fn transport_status(error: &TransportError) -> &str {
    match error {
        TransportError::RateLimited { .. } => "rate_limited",
        TransportError::AccessLost => "access_lost",
        TransportError::NotFound => "not_found",
        TransportError::InvalidResponse => "invalid_response",
        TransportError::ProviderUnknown(_) => "provider_unknown",
        TransportError::BlockedEnv { .. } => "BLOCKED_ENV",
    }
}
