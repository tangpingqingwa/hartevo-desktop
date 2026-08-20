//! Metadata-only AWS Backup provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client, restore API, delete API, or backup-byte path in this Layer-1 crate.

use std::{collections::VecDeque, fmt, fmt::Write as _};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::{AwsBackupRecoveryError, AwsBackupTransportError, Result};
use crate::model::{
    AwsBackupRecoveryScope, Cursor, Digest, RecoveryPointFilter, RecoveryPointMetadata,
    RecoveryPointMetadataInput, RecoveryPointStatus, StorageClass, TransportProvenance,
    validate_response_bytes,
};
use crate::service::AwsBackupRecoveryRegistration;
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

pub const LIST_RECOVERY_POINTS_OPERATION_PATH: &str =
    "/backup-vaults/{backupVaultName}/recovery-points/";
pub const DESCRIBE_RECOVERY_POINT_OPERATION_PATH: &str =
    "/backup-vaults/{backupVaultName}/recovery-points/{recoveryPointArn}";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsBackupOperation {
    ListRecoveryPointsByBackupVault,
    DescribeRecoveryPoint,
}

impl AwsBackupOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListRecoveryPointsByBackupVault => "ListRecoveryPointsByBackupVault",
            Self::DescribeRecoveryPoint => "DescribeRecoveryPoint",
        }
    }
}

/// The only provider transport trait exposed by Layer 1.
pub trait AwsBackupTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_recovery_points(
        &mut self,
        request: &ListRecoveryPointsRequest,
    ) -> std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError>;

    fn describe_recovery_point(
        &mut self,
        request: &DescribeRecoveryPointRequest,
    ) -> std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsBackupOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListRecoveryPointsRequest {
    scope: AwsBackupRecoveryScope,
    filter: RecoveryPointFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListRecoveryPointsRequest {
    pub fn new(
        scope: &AwsBackupRecoveryScope,
        filter: RecoveryPointFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        let request_digest = Digest::from_parts(
            "aws-backup-list-recovery-points-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsBackupRecoveryScope {
        &self.scope
    }

    pub fn filter(&self) -> &RecoveryPointFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor
            .as_ref()
            .map_or(1, |cursor| cursor.page_number())
    }

    /// The next-token value is deliberately a digest placeholder. The raw
    /// provider cursor never enters a request receipt or evidence projection.
    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            (
                "backupVaultAccountId".to_owned(),
                self.scope.account().as_str().to_owned(),
            ),
            (
                "backupPlanId".to_owned(),
                self.filter.backup_plan_id().to_owned(),
            ),
            (
                "maxResults".to_owned(),
                self.filter.max_results().to_string(),
            ),
            (
                "resourceArn".to_owned(),
                self.filter.resource_arn().as_str().to_owned(),
            ),
            (
                "resourceType".to_owned(),
                self.filter.resource_type().as_str().to_owned(),
            ),
        ];
        if let Some(created_after) = self.filter.created_after() {
            query.push(("createdAfter".to_owned(), created_after.to_rfc3339()));
        }
        if let Some(created_before) = self.filter.created_before() {
            query.push(("createdBefore".to_owned(), created_before.to_rfc3339()));
        }
        if let Some(cursor) = &self.cursor {
            query.push((
                "nextToken".to_owned(),
                cursor.token_digest().as_str().to_owned(),
            ));
        }
        let query = query
            .into_iter()
            .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!(
            "/backup-vaults/{}/recovery-points/?{query}",
            percent_encode(self.scope.vault().name().as_str())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsBackupOperation::ListRecoveryPointsByBackupVault,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListRecoveryPointsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListRecoveryPointsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeRecoveryPointRequest {
    scope: AwsBackupRecoveryScope,
    request_digest: Digest,
}

impl DescribeRecoveryPointRequest {
    pub fn for_scope(scope: &AwsBackupRecoveryScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-backup-describe-recovery-point-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "recovery_point",
                        scope.recovery_point().digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsBackupRecoveryScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/backup-vaults/{}/recovery-points/{}?backupVaultAccountId={}",
            percent_encode(self.scope.vault().name().as_str()),
            percent_encode(self.scope.recovery_point().arn().as_str()),
            percent_encode(self.scope.account().as_str()),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsBackupOperation::DescribeRecoveryPoint,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribeRecoveryPointRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeRecoveryPointRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRecoveryPointsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub recovery_points: Vec<RecoveryPointMetadata>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListRecoveryPointsResponse {
    pub fn new(
        request: &ListRecoveryPointsRequest,
        recovery_points: Vec<RecoveryPointMetadata>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if recovery_points.len() > request.filter.max_results() as usize {
            return Err(AwsBackupRecoveryError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsBackupRecoveryError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            recovery_points,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-backup-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListRecoveryPointsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.recovery_points.len() > request.filter.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.clone().is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsBackupRecoveryError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsBackupRecoveryError::CursorMismatch);
            }
        }
        for point in &self.recovery_points {
            point.validate_list_item_against(request.scope())?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-list-recovery-points-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "points",
                    self.recovery_points
                        .iter()
                        .map(RecoveryPointMetadata::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeRecoveryPointResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: RecoveryPointMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeRecoveryPointResponse {
    pub fn new(
        request: &DescribeRecoveryPointRequest,
        metadata: RecoveryPointMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-backup-describe-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribeRecoveryPointRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.clone().is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsBackupRecoveryError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-describe-recovery-point-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwsBackupProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsBackupProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsBackupRecoveryError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-backup-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-backup-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsBackupRecoveryError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsBackupProviderDefinition {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AwsBackupProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub struct AwsBackupProvider<T> {
    transport: T,
    definition: AwsBackupProviderDefinition,
}

impl<T: AwsBackupTransport> fmt::Debug for AwsBackupProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsBackupProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsBackupTransport> AwsBackupProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsBackupProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsBackupProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_recovery_points(
        &mut self,
        request: &ListRecoveryPointsRequest,
    ) -> std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError> {
        let response = self.transport.list_recovery_points(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsBackupTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsBackupTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn describe_recovery_point(
        &mut self,
        request: &DescribeRecoveryPointRequest,
    ) -> std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError> {
        let response = self.transport.describe_recovery_point(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsBackupTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsBackupTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsBackupProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS Backup provider definition")
    }
}

impl<T: AwsBackupTransport> AwsBackupProvider<T> {
    pub fn from_registration(
        registration: &AwsBackupRecoveryRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsBackupRecoveryError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError>>,
    describe_responses:
        VecDeque<std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            describe_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_describe_response(
        &mut self,
        response: std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsBackupTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance.clone()
    }

    fn list_recovery_points(
        &mut self,
        request: &ListRecoveryPointsRequest,
    ) -> std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsBackupTransportError::InvalidResponse))
    }

    fn describe_recovery_point(
        &mut self,
        request: &DescribeRecoveryPointRequest,
    ) -> std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_responses
            .pop_front()
            .unwrap_or(Err(AwsBackupTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsBackupRecoveryScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsBackupRecoveryScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn metadata(&self) -> Result<RecoveryPointMetadata> {
        RecoveryPointMetadata::new(
            &self.scope,
            RecoveryPointMetadataInput {
                status: RecoveryPointStatus::Completed,
                creation_date: self.observed_at - Duration::hours(1),
                initiation_date: Some(self.observed_at - Duration::hours(2)),
                completion_date: Some(self.observed_at - Duration::minutes(30)),
                lifecycle: crate::model::LifecycleMetadata::new(
                    None,
                    Some(self.observed_at + Duration::days(30)),
                    None,
                    Some(30),
                    None,
                    false,
                )?,
                size_bytes: 4_096,
                encryption: crate::model::EncryptionMetadata::new(
                    true,
                    crate::model::EncryptionKeyType::CustomerManagedKmsKey,
                    Some("arn:aws:kms:us-east-1:123456789012:key/fixture"),
                )?,
                storage_class: StorageClass::Warm,
                status_message: None,
                parent_recovery_point_arn: None,
            },
        )
    }
}

impl AwsBackupTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_recovery_points(
        &mut self,
        request: &ListRecoveryPointsRequest,
    ) -> std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError> {
        let metadata = self
            .metadata()
            .map_err(|_| AwsBackupTransportError::InvalidResponse)?;
        ListRecoveryPointsResponse::new(
            request,
            vec![metadata],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsBackupTransportError::InvalidResponse)
    }

    fn describe_recovery_point(
        &mut self,
        request: &DescribeRecoveryPointRequest,
    ) -> std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError> {
        let metadata = self
            .metadata()
            .map_err(|_| AwsBackupTransportError::InvalidResponse)?;
        DescribeRecoveryPointResponse::new(request, metadata, 512, TransportProvenance::Fixture)
            .map_err(|_| AwsBackupTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsBackupRecoveryScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsBackupTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_recovery_points(
        &mut self,
        request: &ListRecoveryPointsRequest,
    ) -> std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError> {
        let metadata = self
            .inner
            .metadata()
            .map_err(|_| AwsBackupTransportError::InvalidResponse)?;
        ListRecoveryPointsResponse::new(
            request,
            vec![metadata],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsBackupTransportError::InvalidResponse)
    }

    fn describe_recovery_point(
        &mut self,
        request: &DescribeRecoveryPointRequest,
    ) -> std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError> {
        let metadata = self
            .inner
            .metadata()
            .map_err(|_| AwsBackupTransportError::InvalidResponse)?;
        DescribeRecoveryPointResponse::new(request, metadata, 512, TransportProvenance::Loopback)
            .map_err(|_| AwsBackupTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsBackupTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_recovery_points(
        &mut self,
        _request: &ListRecoveryPointsRequest,
    ) -> std::result::Result<ListRecoveryPointsResponse, AwsBackupTransportError> {
        Err(AwsBackupTransportError::BlockedEnv)
    }

    fn describe_recovery_point(
        &mut self,
        _request: &DescribeRecoveryPointRequest,
    ) -> std::result::Result<DescribeRecoveryPointResponse, AwsBackupTransportError> {
        Err(AwsBackupTransportError::BlockedEnv)
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            let _ = write!(encoded, "{byte:02X}");
        }
    }
    encoded
}
