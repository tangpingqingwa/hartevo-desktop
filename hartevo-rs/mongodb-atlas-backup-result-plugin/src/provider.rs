use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::model::{
    AtlasCapability, CapabilitySet, ClusterMetadata, ClusterName, Digest, MeasurementSeries,
    MeasurementWindow, ModelError, MongoDbAtlasScope, ProcessId, ProjectId, ProviderId,
    ProviderMode, Snapshot, all_read_capabilities,
};
use crate::{
    MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION, MONGODB_ATLAS_BACKUP_RESULT_PROVIDER_ID,
    MONGODB_ATLAS_BACKUP_RESULT_SCHEMA_VERSION,
};

pub const ATLAS_ADMIN_API_VERSION: &str = "2025-03-12";
pub const SNAPSHOT_OPERATION_PATH: &str =
    "/api/atlas/v2/groups/{groupId}/clusters/{clusterName}/backup/snapshots";
pub const PROCESS_MEASUREMENTS_OPERATION_PATH: &str =
    "/api/atlas/v2/groups/{groupId}/processes/{processId}/measurements";
pub const CLUSTER_METADATA_OPERATION_PATH: &str =
    "/api/atlas/v2/groups/{groupId}/clusters/{clusterName}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtlasOperation {
    ListBackupSnapshots,
    GetProcessMeasurements,
    GetClusterMetadata,
}

impl AtlasOperation {
    pub const fn id(self) -> &'static str {
        match self {
            Self::ListBackupSnapshots => "list-backup-snapshots",
            Self::GetProcessMeasurements => "get-process-measurements",
            Self::GetClusterMetadata => "get-cluster-metadata",
        }
    }

    pub const fn method(self) -> &'static str {
        "GET"
    }
}

impl fmt::Display for AtlasOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("Atlas request was rate limited")]
    RateLimited {
        retry_after_seconds: Option<u64>,
        limit: Option<u32>,
        remaining: Option<u32>,
    },
    #[error("Atlas access was lost")]
    AccessLost,
    #[error("Atlas resource was not found")]
    NotFound,
    #[error("Atlas provider returned an invalid bounded response")]
    InvalidResponse,
    #[error("Atlas provider is unknown: {0}")]
    ProviderUnknown(String),
    #[error("native Atlas environment is blocked: {operation}")]
    BlockedEnv { operation: AtlasOperation },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasRequestReceipt {
    pub operation: AtlasOperation,
    pub method: &'static str,
    pub redacted_path: String,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub attempt: u8,
    pub redacted: bool,
    pub native: bool,
}

impl AtlasRequestReceipt {
    fn new(
        operation: AtlasOperation,
        redacted_path: String,
        request_digest: Digest,
        scope_digest: Digest,
    ) -> Self {
        Self {
            operation,
            method: operation.method(),
            redacted_path,
            request_digest,
            scope_digest,
            attempt: 0,
            redacted: true,
            native: false,
        }
    }

    pub fn with_attempt(mut self, attempt: u8) -> Self {
        self.attempt = attempt;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasResultReceipt {
    pub operation: AtlasOperation,
    pub result_digest: Digest,
    pub scope_digest: Digest,
    pub status: &'static str,
    pub attempt: u8,
    pub redacted: bool,
    pub native: bool,
}

impl AtlasResultReceipt {
    pub fn new(
        operation: AtlasOperation,
        result_digest: Digest,
        scope_digest: Digest,
        status: &'static str,
        attempt: u8,
    ) -> Self {
        Self {
            operation,
            result_digest,
            scope_digest,
            status,
            attempt,
            redacted: true,
            native: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListBackupSnapshotsRequest {
    scope_digest: Digest,
    project_id: ProjectId,
    cluster_name: ClusterName,
    page_num: u16,
    items_per_page: u16,
    include_count: bool,
    include_deleted_with_retained_backups: bool,
    request_digest: Digest,
}

impl ListBackupSnapshotsRequest {
    pub fn new(
        scope: &MongoDbAtlasScope,
        page_num: u16,
        items_per_page: u16,
    ) -> Result<Self, ModelError> {
        if page_num == 0 || page_num > crate::model::MAX_SNAPSHOT_PAGES {
            return Err(ModelError::InvalidSnapshotBounds);
        }
        if items_per_page == 0 || items_per_page > crate::model::MAX_SNAPSHOT_PAGE_SIZE {
            return Err(ModelError::InvalidSnapshotPageSize);
        }
        let project_id = scope.project_id().clone();
        let cluster_name = scope.cluster_name().clone();
        let request_digest = Digest::from_parts(
            "mongodb-atlas-list-backup-snapshots-request",
            &[
                scope.digest().as_str().to_owned(),
                project_id.as_str().to_owned(),
                cluster_name.as_str().to_owned(),
                page_num.to_string(),
                items_per_page.to_string(),
                "true".to_owned(),
                "false".to_owned(),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest().clone(),
            project_id,
            cluster_name,
            page_num,
            items_per_page,
            include_count: true,
            include_deleted_with_retained_backups: false,
            request_digest,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn cluster_name(&self) -> &ClusterName {
        &self.cluster_name
    }

    pub const fn page_num(&self) -> u16 {
        self.page_num
    }

    pub const fn items_per_page(&self) -> u16 {
        self.items_per_page
    }

    pub const fn include_count(&self) -> bool {
        self.include_count
    }

    pub const fn include_deleted_with_retained_backups(&self) -> bool {
        self.include_deleted_with_retained_backups
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn redacted_path(&self) -> String {
        format!(
            "{SNAPSHOT_OPERATION_PATH}?includeCount=true&itemsPerPage={}&pageNum={}&includeDeletedWithRetainedBackups=false",
            self.items_per_page, self.page_num
        )
    }

    pub fn receipt(&self) -> AtlasRequestReceipt {
        AtlasRequestReceipt::new(
            AtlasOperation::ListBackupSnapshots,
            self.redacted_path(),
            self.request_digest.clone(),
            self.scope_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetProcessMeasurementsRequest {
    scope_digest: Digest,
    project_id: ProjectId,
    process_id: ProcessId,
    window: MeasurementWindow,
    request_digest: Digest,
}

impl GetProcessMeasurementsRequest {
    pub fn new(scope: &MongoDbAtlasScope, window: MeasurementWindow) -> Result<Self, ModelError> {
        let project_id = scope.project_id().clone();
        let process_id = scope.process_id().clone();
        let request_digest = Digest::from_parts(
            "mongodb-atlas-process-measurements-request",
            &[
                scope.digest().as_str().to_owned(),
                project_id.as_str().to_owned(),
                process_id.digest().as_str().to_owned(),
                window.digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest().clone(),
            project_id,
            process_id,
            window,
            request_digest,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn process_digest(&self) -> Digest {
        self.process_id.digest()
    }

    pub fn process_id_redacted(&self) -> String {
        self.process_id.redacted()
    }

    pub fn window(&self) -> &MeasurementWindow {
        &self.window
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn redacted_path(&self) -> String {
        format!(
            "{PROCESS_MEASUREMENTS_OPERATION_PATH}?granularity={}&start={}&end={}",
            self.window.granularity().as_str(),
            self.window.start().to_rfc3339(),
            self.window.end().to_rfc3339()
        )
    }

    pub fn receipt(&self) -> AtlasRequestReceipt {
        AtlasRequestReceipt::new(
            AtlasOperation::GetProcessMeasurements,
            self.redacted_path(),
            self.request_digest.clone(),
            self.scope_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetClusterMetadataRequest {
    scope_digest: Digest,
    project_id: ProjectId,
    cluster_name: ClusterName,
    request_digest: Digest,
}

impl GetClusterMetadataRequest {
    pub fn new(scope: &MongoDbAtlasScope) -> Result<Self, ModelError> {
        let project_id = scope.project_id().clone();
        let cluster_name = scope.cluster_name().clone();
        let request_digest = Digest::from_parts(
            "mongodb-atlas-cluster-metadata-request",
            &[
                scope.digest().as_str().to_owned(),
                project_id.as_str().to_owned(),
                cluster_name.as_str().to_owned(),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest().clone(),
            project_id,
            cluster_name,
            request_digest,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn cluster_name(&self) -> &ClusterName {
        &self.cluster_name
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn redacted_path(&self) -> String {
        CLUSTER_METADATA_OPERATION_PATH.to_owned()
    }

    pub fn receipt(&self) -> AtlasRequestReceipt {
        AtlasRequestReceipt::new(
            AtlasOperation::GetClusterMetadata,
            self.redacted_path(),
            self.request_digest.clone(),
            self.scope_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSnapshotPage {
    scope_digest: Digest,
    project_id: ProjectId,
    cluster_name: ClusterName,
    page_num: u16,
    total_count: u64,
    snapshots: Vec<Snapshot>,
    more_pages: bool,
    declared_digest: Digest,
}

impl BackupSnapshotPage {
    pub fn new(
        request: &ListBackupSnapshotsRequest,
        snapshots: Vec<Snapshot>,
        total_count: u64,
        more_pages: bool,
    ) -> Self {
        let declared_digest = Self::calculate_digest(
            request.scope_digest(),
            request.project_id(),
            request.cluster_name(),
            request.page_num(),
            total_count,
            &snapshots,
            more_pages,
        );
        Self {
            scope_digest: request.scope_digest().clone(),
            project_id: request.project_id().clone(),
            cluster_name: request.cluster_name().clone(),
            page_num: request.page_num(),
            total_count,
            snapshots,
            more_pages,
            declared_digest,
        }
    }

    pub fn with_declared_digest(
        request: &ListBackupSnapshotsRequest,
        snapshots: Vec<Snapshot>,
        total_count: u64,
        more_pages: bool,
        declared_digest: Digest,
    ) -> Self {
        let mut page = Self::new(request, snapshots, total_count, more_pages);
        page.declared_digest = declared_digest;
        page
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn cluster_name(&self) -> &ClusterName {
        &self.cluster_name
    }

    pub const fn page_num(&self) -> u16 {
        self.page_num
    }

    pub const fn total_count(&self) -> u64 {
        self.total_count
    }

    pub fn snapshots(&self) -> &[Snapshot] {
        &self.snapshots
    }

    pub const fn more_pages(&self) -> bool {
        self.more_pages
    }

    pub fn digest(&self) -> Digest {
        Self::calculate_digest(
            &self.scope_digest,
            &self.project_id,
            &self.cluster_name,
            self.page_num,
            self.total_count,
            &self.snapshots,
            self.more_pages,
        )
    }

    pub fn declared_digest(&self) -> &Digest {
        &self.declared_digest
    }

    fn calculate_digest(
        scope_digest: &Digest,
        project_id: &ProjectId,
        cluster_name: &ClusterName,
        page_num: u16,
        total_count: u64,
        snapshots: &[Snapshot],
        more_pages: bool,
    ) -> Digest {
        let mut fields = vec![
            scope_digest.as_str().to_owned(),
            project_id.as_str().to_owned(),
            cluster_name.as_str().to_owned(),
            page_num.to_string(),
            total_count.to_string(),
            more_pages.to_string(),
        ];
        fields.extend(
            snapshots
                .iter()
                .map(|snapshot| snapshot.digest().as_str().to_owned()),
        );
        Digest::from_parts("mongodb-atlas-backup-snapshot-page", &fields)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProcessMeasurementsResponse {
    scope_digest: Digest,
    project_id: ProjectId,
    process_digest: Digest,
    window: MeasurementWindow,
    measurements: Vec<MeasurementSeries>,
    complete: bool,
    declared_digest: Digest,
}

impl ProcessMeasurementsResponse {
    pub fn new(
        request: &GetProcessMeasurementsRequest,
        measurements: Vec<MeasurementSeries>,
        complete: bool,
    ) -> Self {
        let declared_digest = Self::calculate_digest(
            request.scope_digest(),
            request.project_id(),
            &request.process_digest(),
            request.window(),
            &measurements,
            complete,
        );
        Self {
            scope_digest: request.scope_digest().clone(),
            project_id: request.project_id().clone(),
            process_digest: request.process_digest(),
            window: request.window().clone(),
            measurements,
            complete,
            declared_digest,
        }
    }

    pub fn with_declared_digest(
        request: &GetProcessMeasurementsRequest,
        measurements: Vec<MeasurementSeries>,
        complete: bool,
        declared_digest: Digest,
    ) -> Self {
        let mut response = Self::new(request, measurements, complete);
        response.declared_digest = declared_digest;
        response
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn process_digest(&self) -> &Digest {
        &self.process_digest
    }

    pub fn window(&self) -> &MeasurementWindow {
        &self.window
    }

    pub fn measurements(&self) -> &[MeasurementSeries] {
        &self.measurements
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub fn digest(&self) -> Digest {
        Self::calculate_digest(
            &self.scope_digest,
            &self.project_id,
            &self.process_digest,
            &self.window,
            &self.measurements,
            self.complete,
        )
    }

    pub fn declared_digest(&self) -> &Digest {
        &self.declared_digest
    }

    fn calculate_digest(
        scope_digest: &Digest,
        project_id: &ProjectId,
        process_digest: &Digest,
        window: &MeasurementWindow,
        measurements: &[MeasurementSeries],
        complete: bool,
    ) -> Digest {
        let mut fields = vec![
            scope_digest.as_str().to_owned(),
            project_id.as_str().to_owned(),
            process_digest.as_str().to_owned(),
            window.digest().as_str().to_owned(),
            complete.to_string(),
        ];
        fields.extend(
            measurements
                .iter()
                .map(|measurement| measurement.digest().as_str().to_owned()),
        );
        Digest::from_parts("mongodb-atlas-process-measurements", &fields)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterMetadataResponse {
    scope_digest: Digest,
    project_id: ProjectId,
    cluster_name: ClusterName,
    metadata: ClusterMetadata,
    declared_digest: Digest,
}

impl ClusterMetadataResponse {
    pub fn new(request: &GetClusterMetadataRequest, metadata: ClusterMetadata) -> Self {
        let declared_digest = Self::calculate_digest(
            request.scope_digest(),
            request.project_id(),
            request.cluster_name(),
            &metadata,
        );
        Self {
            scope_digest: request.scope_digest().clone(),
            project_id: request.project_id().clone(),
            cluster_name: request.cluster_name().clone(),
            metadata,
            declared_digest,
        }
    }

    pub fn with_declared_digest(
        request: &GetClusterMetadataRequest,
        metadata: ClusterMetadata,
        declared_digest: Digest,
    ) -> Self {
        let mut response = Self::new(request, metadata);
        response.declared_digest = declared_digest;
        response
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn cluster_name(&self) -> &ClusterName {
        &self.cluster_name
    }

    pub fn metadata(&self) -> &ClusterMetadata {
        &self.metadata
    }

    pub fn digest(&self) -> Digest {
        Self::calculate_digest(
            &self.scope_digest,
            &self.project_id,
            &self.cluster_name,
            &self.metadata,
        )
    }

    pub fn declared_digest(&self) -> &Digest {
        &self.declared_digest
    }

    fn calculate_digest(
        scope_digest: &Digest,
        project_id: &ProjectId,
        cluster_name: &ClusterName,
        metadata: &ClusterMetadata,
    ) -> Digest {
        Digest::from_parts(
            "mongodb-atlas-cluster-metadata-response",
            &[
                scope_digest.as_str().to_owned(),
                project_id.as_str().to_owned(),
                cluster_name.as_str().to_owned(),
                metadata.digest().as_str().to_owned(),
            ],
        )
    }
}

pub trait MongoDbAtlasTransport: fmt::Debug {
    fn list_backup_snapshots(
        &mut self,
        request: &ListBackupSnapshotsRequest,
    ) -> Result<BackupSnapshotPage, TransportError>;

    fn get_process_measurements(
        &mut self,
        request: &GetProcessMeasurementsRequest,
    ) -> Result<ProcessMeasurementsResponse, TransportError>;

    fn get_cluster_metadata(
        &mut self,
        request: &GetClusterMetadataRequest,
    ) -> Result<ClusterMetadataResponse, TransportError>;
}

#[derive(Clone, Debug)]
pub struct MongoDbAtlasProviderDefinition {
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub contract_version: &'static str,
    pub api_version: &'static str,
    pub capabilities: CapabilitySet,
    pub capability_kind: crate::model::CapabilityKind,
    pub mode: ProviderMode,
    pub native: bool,
    pub connected: bool,
    pub provider_digest: Digest,
}

impl MongoDbAtlasProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        mode: ProviderMode,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if provider_version.trim().is_empty() {
            return Err(ModelError::InvalidIdentifier);
        }
        let provider_id = ProviderId::new(MONGODB_ATLAS_BACKUP_RESULT_PROVIDER_ID)?;
        let capabilities = all_read_capabilities();
        let provider_digest = Digest::from_parts(
            "mongodb-atlas-provider-definition",
            &[
                provider_id.as_str().to_owned(),
                provider_version.clone(),
                MONGODB_ATLAS_BACKUP_RESULT_SCHEMA_VERSION.to_owned(),
                MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION.to_owned(),
                ATLAS_ADMIN_API_VERSION.to_owned(),
                capabilities.digest().as_str().to_owned(),
                mode.as_str().to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            provider_version,
            contract_version: MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION,
            api_version: ATLAS_ADMIN_API_VERSION,
            capabilities,
            capability_kind: crate::model::CapabilityKind::ReadOnly,
            mode,
            native: false,
            connected: false,
            provider_digest,
        })
    }

    pub fn supports(&self, capability: AtlasCapability) -> bool {
        self.capabilities.contains(capability)
    }
}

#[derive(Debug)]
pub struct MongoDbAtlasProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: MongoDbAtlasProviderDefinition,
}

impl<T: MongoDbAtlasTransport> MongoDbAtlasProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        mode: ProviderMode,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            transport,
            definition: MongoDbAtlasProviderDefinition::new(provider_version, mode)?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn definition(&self) -> &MongoDbAtlasProviderDefinition {
        &self.definition
    }

    pub fn list_backup_snapshots(
        &mut self,
        request: &ListBackupSnapshotsRequest,
    ) -> Result<BackupSnapshotPage, TransportError> {
        self.transport.list_backup_snapshots(request)
    }

    pub fn get_process_measurements(
        &mut self,
        request: &GetProcessMeasurementsRequest,
    ) -> Result<ProcessMeasurementsResponse, TransportError> {
        self.transport.get_process_measurements(request)
    }

    pub fn get_cluster_metadata(
        &mut self,
        request: &GetClusterMetadataRequest,
    ) -> Result<ClusterMetadataResponse, TransportError> {
        self.transport.get_cluster_metadata(request)
    }
}

impl Default for MongoDbAtlasProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport, "2.0.0", ProviderMode::BlockedEnv)
            .expect("static blocked-environment provider definition")
    }
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    snapshot_responses: VecDeque<Result<BackupSnapshotPage, TransportError>>,
    measurement_responses: VecDeque<Result<ProcessMeasurementsResponse, TransportError>>,
    cluster_responses: VecDeque<Result<ClusterMetadataResponse, TransportError>>,
    requests: Vec<AtlasRequestReceipt>,
}

impl RecordingTransport {
    pub fn push_snapshot_response(&mut self, response: Result<BackupSnapshotPage, TransportError>) {
        self.snapshot_responses.push_back(response);
    }

    pub fn push_snapshot_response_front(
        &mut self,
        response: Result<BackupSnapshotPage, TransportError>,
    ) {
        self.snapshot_responses.push_front(response);
    }

    pub fn push_measurement_response(
        &mut self,
        response: Result<ProcessMeasurementsResponse, TransportError>,
    ) {
        self.measurement_responses.push_back(response);
    }

    pub fn push_cluster_response(
        &mut self,
        response: Result<ClusterMetadataResponse, TransportError>,
    ) {
        self.cluster_responses.push_back(response);
    }

    pub fn requests(&self) -> &[AtlasRequestReceipt] {
        &self.requests
    }

    fn pop_or_unknown<T>(
        queue: &mut VecDeque<Result<T, TransportError>>,
        operation: AtlasOperation,
    ) -> Result<T, TransportError> {
        queue.pop_front().unwrap_or_else(|| {
            Err(TransportError::ProviderUnknown(format!(
                "no response for {operation}"
            )))
        })
    }
}

impl MongoDbAtlasTransport for RecordingTransport {
    fn list_backup_snapshots(
        &mut self,
        request: &ListBackupSnapshotsRequest,
    ) -> Result<BackupSnapshotPage, TransportError> {
        self.requests.push(request.receipt());
        Self::pop_or_unknown(
            &mut self.snapshot_responses,
            AtlasOperation::ListBackupSnapshots,
        )
    }

    fn get_process_measurements(
        &mut self,
        request: &GetProcessMeasurementsRequest,
    ) -> Result<ProcessMeasurementsResponse, TransportError> {
        self.requests.push(request.receipt());
        Self::pop_or_unknown(
            &mut self.measurement_responses,
            AtlasOperation::GetProcessMeasurements,
        )
    }

    fn get_cluster_metadata(
        &mut self,
        request: &GetClusterMetadataRequest,
    ) -> Result<ClusterMetadataResponse, TransportError> {
        self.requests.push(request.receipt());
        Self::pop_or_unknown(
            &mut self.cluster_responses,
            AtlasOperation::GetClusterMetadata,
        )
    }
}

#[derive(Debug)]
pub struct FixtureTransport {
    inner: RecordingTransport,
}

impl FixtureTransport {
    pub fn healthy(
        scope: &MongoDbAtlasScope,
        window: &MeasurementWindow,
    ) -> Result<Self, ModelError> {
        let snapshot_request = ListBackupSnapshotsRequest::new(scope, 1, 10)?;
        let measurement_request = GetProcessMeasurementsRequest::new(scope, window.clone())?;
        let cluster_request = GetClusterMetadataRequest::new(scope)?;
        let created_at = parse_time("2026-08-14T00:00:00Z");
        let expires_at = parse_time("2026-08-21T00:00:00Z");
        let snapshot = Snapshot::new(
            "32b6e34b3d91647abb20e7b8",
            crate::model::SnapshotStatus::Completed,
            created_at,
            Some(expires_at),
            "onDemand",
            Some(42),
        )?;
        let points = vec![
            crate::model::MeasurementPoint::new(window.start(), 12.0)?,
            crate::model::MeasurementPoint::new(window.end(), 14.0)?,
        ];
        let measurement = MeasurementSeries::new("NORMALIZED_CPU_USER", "PERCENT", points)?;
        let metadata = ClusterMetadata::new(
            scope.project_id().clone(),
            scope.cluster_name().clone(),
            true,
            true,
            false,
            Some("8.0.0".to_owned()),
            Some("REPLICASET".to_owned()),
        );
        let mut inner = RecordingTransport::default();
        inner.push_snapshot_response(Ok(BackupSnapshotPage::new(
            &snapshot_request,
            vec![snapshot],
            1,
            false,
        )));
        inner.push_measurement_response(Ok(ProcessMeasurementsResponse::new(
            &measurement_request,
            vec![measurement],
            true,
        )));
        inner.push_cluster_response(Ok(ClusterMetadataResponse::new(&cluster_request, metadata)));
        Ok(Self { inner })
    }

    pub fn requests(&self) -> &[AtlasRequestReceipt] {
        self.inner.requests()
    }
}

impl MongoDbAtlasTransport for FixtureTransport {
    fn list_backup_snapshots(
        &mut self,
        request: &ListBackupSnapshotsRequest,
    ) -> Result<BackupSnapshotPage, TransportError> {
        self.inner.list_backup_snapshots(request)
    }

    fn get_process_measurements(
        &mut self,
        request: &GetProcessMeasurementsRequest,
    ) -> Result<ProcessMeasurementsResponse, TransportError> {
        self.inner.get_process_measurements(request)
    }

    fn get_cluster_metadata(
        &mut self,
        request: &GetClusterMetadataRequest,
    ) -> Result<ClusterMetadataResponse, TransportError> {
        self.inner.get_cluster_metadata(request)
    }
}

#[derive(Debug)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn deterministic(
        scope: &MongoDbAtlasScope,
        window: &MeasurementWindow,
    ) -> Result<Self, ModelError> {
        let fixture = FixtureTransport::healthy(scope, window)?;
        Ok(Self {
            inner: fixture.inner,
        })
    }

    pub fn requests(&self) -> &[AtlasRequestReceipt] {
        self.inner.requests()
    }
}

impl MongoDbAtlasTransport for LoopbackTransport {
    fn list_backup_snapshots(
        &mut self,
        request: &ListBackupSnapshotsRequest,
    ) -> Result<BackupSnapshotPage, TransportError> {
        self.inner.list_backup_snapshots(request)
    }

    fn get_process_measurements(
        &mut self,
        request: &GetProcessMeasurementsRequest,
    ) -> Result<ProcessMeasurementsResponse, TransportError> {
        self.inner.get_process_measurements(request)
    }

    fn get_cluster_metadata(
        &mut self,
        request: &GetClusterMetadataRequest,
    ) -> Result<ClusterMetadataResponse, TransportError> {
        self.inner.get_cluster_metadata(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl MongoDbAtlasTransport for BlockedEnvTransport {
    fn list_backup_snapshots(
        &mut self,
        _request: &ListBackupSnapshotsRequest,
    ) -> Result<BackupSnapshotPage, TransportError> {
        Err(TransportError::BlockedEnv {
            operation: AtlasOperation::ListBackupSnapshots,
        })
    }

    fn get_process_measurements(
        &mut self,
        _request: &GetProcessMeasurementsRequest,
    ) -> Result<ProcessMeasurementsResponse, TransportError> {
        Err(TransportError::BlockedEnv {
            operation: AtlasOperation::GetProcessMeasurements,
        })
    }

    fn get_cluster_metadata(
        &mut self,
        _request: &GetClusterMetadataRequest,
    ) -> Result<ClusterMetadataResponse, TransportError> {
        Err(TransportError::BlockedEnv {
            operation: AtlasOperation::GetClusterMetadata,
        })
    }
}

fn parse_time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("static fixture timestamp")
        .with_timezone(&Utc)
}
