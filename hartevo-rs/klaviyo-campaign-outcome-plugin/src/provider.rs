use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION, KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION,
    KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID, KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_IMPLEMENTATION,
    KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION,
    model::{
        AccountId, CampaignFlowMetadata, Digest, KlaviyoPermission, KlaviyoScope, MetricSelection,
        ModelError, PermissionFence, RedactionEvidence, ReportKind, ReportPage, ReportWindow,
        ResourceId, Revision, SecretKind, SecretReference, VariationSelector,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty or too long")]
    InvalidVersion,
    #[error("Klaviyo API revision is not pinned")]
    InvalidApiRevision,
    #[error("Layer 1 cannot register a native or first-party provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KlaviyoProviderDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub implementation: String,
    pub api_revision: String,
    pub implementation_digest: Digest,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub campaign_metadata_read: bool,
    pub flow_metadata_read: bool,
    pub values_report_read: bool,
    pub series_report_read: bool,
    pub writes: bool,
    pub native: bool,
    pub first_party: bool,
}

impl KlaviyoProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        api_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        let api_revision = api_revision.into();
        if provider_version.is_empty() || provider_version.len() > 32 {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        if api_revision != KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION {
            return Err(ProviderDefinitionError::InvalidApiRevision);
        }
        if provenance.connected() || provenance.is_native() || provenance.first_party() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let implementation_digest = Digest::from_fields(
            "klaviyo-provider-implementation/v1",
            &[
                KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_IMPLEMENTATION.to_owned(),
                provider_version.clone(),
                api_revision.clone(),
            ],
        );
        let capability_digest = Digest::from_fields(
            "klaviyo-provider-capability/v1",
            &[
                KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION.to_owned(),
                KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION.to_owned(),
                KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                api_revision.clone(),
                format!("{provenance:?}"),
                "campaign_metadata_read=true".to_owned(),
                "flow_metadata_read=true".to_owned(),
                "values_report_read=true".to_owned(),
                "series_report_read=true".to_owned(),
                "writes=false".to_owned(),
                "native=false".to_owned(),
                "first_party=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION.to_owned(),
            contract_version: KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION.to_owned(),
            provider_id: KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID.to_owned(),
            provider_version,
            implementation: KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_IMPLEMENTATION.to_owned(),
            api_revision,
            implementation_digest,
            capability_digest,
            provenance,
            campaign_metadata_read: true,
            flow_metadata_read: true,
            values_report_read: true,
            series_report_read: true,
            writes: false,
            native: false,
            first_party: false,
        })
    }

    pub fn layer1(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            provider_version,
            KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION,
            provenance,
        )
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.implementation.clone(),
                self.api_revision.clone(),
                self.implementation_digest.as_str().to_owned(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.campaign_metadata_read.to_string(),
                self.flow_metadata_read.to_string(),
                self.values_report_read.to_string(),
                self.series_report_read.to_string(),
                self.writes.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION
            || self.contract_version != KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION
            || self.provider_id != KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID
            || self.implementation != KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_IMPLEMENTATION
            || self.provider_version.is_empty()
            || self.api_revision.is_empty()
            || !self.campaign_metadata_read
            || !self.flow_metadata_read
            || !self.values_report_read
            || !self.series_report_read
            || self.writes
            || self.native
            || self.first_party
        {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let expected_implementation_digest = Digest::from_fields(
            "klaviyo-provider-implementation/v1",
            &[
                self.implementation.clone(),
                self.provider_version.clone(),
                self.api_revision.clone(),
            ],
        );
        if self.implementation_digest != expected_implementation_digest {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("Klaviyo provider transport returned {kind:?}")]
pub struct TransportError {
    pub kind: crate::ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub retry_after_seconds: Option<u64>,
    diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(kind: crate::ProviderErrorKind, diagnostic: impl AsRef<[u8]>) -> Self {
        Self {
            kind,
            status_code: kind.status_code(),
            retryable: kind.retryable(),
            blocked_env: kind == crate::ProviderErrorKind::BlockedEnv,
            retry_after_seconds: None,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    pub fn unauthorized() -> Self {
        Self::new(crate::ProviderErrorKind::Unauthorized401, "401")
    }

    pub fn forbidden() -> Self {
        Self::new(crate::ProviderErrorKind::Forbidden403, "403")
    }

    pub fn not_found() -> Self {
        Self::new(crate::ProviderErrorKind::NotFound404, "404")
    }

    pub fn conflict() -> Self {
        Self::new(crate::ProviderErrorKind::Conflict409, "409")
    }

    pub fn rate_limited() -> Self {
        Self::new(crate::ProviderErrorKind::RateLimited429, "429")
    }

    pub fn server_failure(status_code: u16) -> Self {
        let mut error = Self::new(crate::ProviderErrorKind::Server5xx, status_code.to_string());
        error.status_code = Some(status_code);
        error
    }

    pub fn timeout() -> Self {
        Self::new(crate::ProviderErrorKind::Timeout, "timeout")
    }

    pub fn blocked_env() -> Self {
        Self::new(crate::ProviderErrorKind::BlockedEnv, "BLOCKED_ENV")
    }

    pub fn invalid_response() -> Self {
        Self::new(
            crate::ProviderErrorKind::InvalidResponse,
            "invalid-response",
        )
    }

    pub(crate) fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignMetadataRequest {
    pub account_id: AccountId,
    pub resource: ResourceId,
    pub api_revision: String,
    pub observed_fence: PermissionFence,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: SecretKind,
    pub request_digest: Digest,
}

impl CampaignMetadataRequest {
    pub(crate) fn from_scope(scope: &KlaviyoScope, secret: &SecretReference) -> Self {
        let mut request = Self {
            account_id: scope.account_id.clone(),
            resource: scope.resource.clone(),
            api_revision: scope.api_revision.clone(),
            observed_fence: scope.fence(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            auth_kind: secret.kind(),
            request_digest: Digest::from_text("uninitialized-metadata-request"),
        };
        request.request_digest = request.compute_digest();
        request
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-campaign-metadata-request/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.resource.kind().label().to_owned(),
                self.resource.id().to_owned(),
                self.api_revision.clone(),
                serde_json::to_string(&self.observed_fence).expect("metadata fence serializes"),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                self.auth_kind.label().to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.request_digest != self.compute_digest() {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRequest {
    pub account_id: AccountId,
    pub resource: ResourceId,
    pub report_kind: ReportKind,
    pub api_revision: String,
    pub metrics: MetricSelection,
    pub window: ReportWindow,
    pub variation: VariationSelector,
    pub page_size: u16,
    pub max_pages: u8,
    pub page_number: u8,
    pub page_cursor_digest: Option<Digest>,
    pub observed_fence: PermissionFence,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: SecretKind,
    pub report_digest: Digest,
    pub request_digest: Digest,
}

impl ReportRequest {
    pub(crate) fn from_scope(
        scope: &KlaviyoScope,
        secret: &SecretReference,
        report_kind: ReportKind,
        page_size: u16,
        max_pages: u8,
    ) -> Result<Self, ModelError> {
        if page_size == 0
            || page_size > crate::model::MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > crate::model::MAX_PAGES
        {
            return Err(ModelError::InvalidReport);
        }
        let mut request = Self {
            account_id: scope.account_id.clone(),
            resource: scope.resource.clone(),
            report_kind,
            api_revision: scope.api_revision.clone(),
            metrics: scope.metrics.clone(),
            window: scope.window.clone(),
            variation: scope.variation.clone(),
            page_size,
            max_pages,
            page_number: 1,
            page_cursor_digest: None,
            observed_fence: scope.fence(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            auth_kind: secret.kind(),
            report_digest: Digest::from_text("uninitialized-report"),
            request_digest: Digest::from_text("uninitialized-report-request"),
        };
        request.report_digest = request.compute_report_digest();
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub(crate) fn next_page(&self, page_number: u8, cursor: Digest) -> Self {
        let mut request = self.clone();
        request.page_number = page_number;
        request.page_cursor_digest = Some(cursor);
        request.request_digest = request.compute_digest();
        request
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.metrics.validate()?;
        self.window.validate()?;
        if self.page_number == 0
            || self.page_number > self.max_pages
            || self.page_size == 0
            || self.page_size > crate::model::MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > crate::model::MAX_PAGES
            || self.report_digest != self.compute_report_digest()
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn page_number(&self) -> u8 {
        self.page_number
    }

    pub fn report_digest(&self) -> &Digest {
        &self.report_digest
    }

    fn compute_report_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-report-query/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.resource.kind().label().to_owned(),
                self.resource.id().to_owned(),
                format!("{:?}", self.report_kind),
                self.api_revision.clone(),
                self.metrics.metric_digest.as_str().to_owned(),
                self.window.window_digest.as_str().to_owned(),
                self.variation.digest().as_str().to_owned(),
                self.observed_fence.scope_digest.as_str().to_owned(),
                self.observed_fence.permission_digest.as_str().to_owned(),
                serde_json::to_string(&self.observed_fence).expect("report fence serializes"),
            ],
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-report-request/v1",
            &[
                self.report_digest.as_str().to_owned(),
                self.page_size.to_string(),
                self.max_pages.to_string(),
                self.page_number.to_string(),
                self.page_cursor_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                self.auth_kind.label().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignMetadataResponse {
    pub account_id: AccountId,
    pub metadata: CampaignFlowMetadata,
    pub observed_fence: PermissionFence,
    pub redaction: RedactionEvidence,
    pub response_digest: Digest,
}

impl CampaignMetadataResponse {
    pub fn new(
        account_id: AccountId,
        metadata: CampaignFlowMetadata,
        observed_fence: PermissionFence,
        redaction: RedactionEvidence,
    ) -> Self {
        let response_digest = Digest::from_fields(
            "klaviyo-campaign-metadata-response/v1",
            &[
                account_id.as_str().to_owned(),
                metadata.metadata_digest.as_str().to_owned(),
                serde_json::to_string(&observed_fence).expect("metadata fence serializes"),
                redaction.redaction_digest.as_str().to_owned(),
            ],
        );
        Self {
            account_id,
            metadata,
            observed_fence,
            redaction,
            response_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.metadata.validate()?;
        self.redaction.validate()?;
        let expected = Digest::from_fields(
            "klaviyo-campaign-metadata-response/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.metadata.metadata_digest.as_str().to_owned(),
                serde_json::to_string(&self.observed_fence).expect("metadata fence serializes"),
                self.redaction.redaction_digest.as_str().to_owned(),
            ],
        );
        if self.response_digest != expected {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

pub trait KlaviyoTransport: fmt::Debug {
    fn read_campaign_or_flow_metadata(
        &mut self,
        request: &CampaignMetadataRequest,
    ) -> Result<CampaignMetadataResponse, TransportError>;

    fn query_values(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError>;

    fn query_series(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError>;
}

pub trait KlaviyoProviderPort: fmt::Debug {
    fn definition(&self) -> &KlaviyoProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn read_campaign_or_flow_metadata(
        &mut self,
        request: &CampaignMetadataRequest,
    ) -> Result<CampaignMetadataResponse, TransportError>;

    fn query_values(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError>;

    fn query_series(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError>;
}

#[derive(Debug)]
pub struct KlaviyoProvider<T> {
    transport: T,
    definition: KlaviyoProviderDefinition,
}

impl<T: KlaviyoTransport> KlaviyoProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::with_api_revision(
            transport,
            provider_version,
            KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION,
            provenance,
        )
    }

    pub fn with_api_revision(
        transport: T,
        provider_version: impl Into<String>,
        api_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: KlaviyoProviderDefinition::new(provider_version, api_revision, provenance)?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: KlaviyoTransport> KlaviyoProviderPort for KlaviyoProvider<T> {
    fn definition(&self) -> &KlaviyoProviderDefinition {
        &self.definition
    }

    fn read_campaign_or_flow_metadata(
        &mut self,
        request: &CampaignMetadataRequest,
    ) -> Result<CampaignMetadataResponse, TransportError> {
        self.transport.read_campaign_or_flow_metadata(request)
    }

    fn query_values(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError> {
        self.transport.query_values(request)
    }

    fn query_series(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError> {
        self.transport.query_series(request)
    }
}

#[derive(Debug, Default)]
pub struct RecordingKlaviyoTransport {
    metadata_responses: VecDeque<Result<CampaignMetadataResponse, TransportError>>,
    values_responses: VecDeque<Result<ReportPage, TransportError>>,
    series_responses: VecDeque<Result<ReportPage, TransportError>>,
    metadata_calls: usize,
    values_calls: usize,
    series_calls: usize,
    last_request_digest: Option<Digest>,
}

impl RecordingKlaviyoTransport {
    pub fn push_metadata_response(
        &mut self,
        response: Result<CampaignMetadataResponse, TransportError>,
    ) {
        self.metadata_responses.push_back(response);
    }

    pub fn push_values_response(&mut self, response: Result<ReportPage, TransportError>) {
        self.values_responses.push_back(response);
    }

    pub fn push_series_response(&mut self, response: Result<ReportPage, TransportError>) {
        self.series_responses.push_back(response);
    }

    pub const fn metadata_calls(&self) -> usize {
        self.metadata_calls
    }

    pub const fn values_calls(&self) -> usize {
        self.values_calls
    }

    pub const fn series_calls(&self) -> usize {
        self.series_calls
    }

    pub fn last_request_digest(&self) -> Option<&Digest> {
        self.last_request_digest.as_ref()
    }

    fn pop_or_blocked<T>(
        queue: &mut VecDeque<Result<T, TransportError>>,
    ) -> Result<T, TransportError> {
        queue
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }
}

impl KlaviyoTransport for RecordingKlaviyoTransport {
    fn read_campaign_or_flow_metadata(
        &mut self,
        request: &CampaignMetadataRequest,
    ) -> Result<CampaignMetadataResponse, TransportError> {
        self.metadata_calls = self.metadata_calls.saturating_add(1);
        self.last_request_digest = Some(request.request_digest.clone());
        Self::pop_or_blocked(&mut self.metadata_responses)
    }

    fn query_values(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError> {
        self.values_calls = self.values_calls.saturating_add(1);
        self.last_request_digest = Some(request.request_digest.clone());
        Self::pop_or_blocked(&mut self.values_responses)
    }

    fn query_series(&mut self, request: &ReportRequest) -> Result<ReportPage, TransportError> {
        self.series_calls = self.series_calls.saturating_add(1);
        self.last_request_digest = Some(request.request_digest.clone());
        Self::pop_or_blocked(&mut self.series_responses)
    }
}

pub type FakeKlaviyoTransport = RecordingKlaviyoTransport;
pub type LoopbackKlaviyoTransport = RecordingKlaviyoTransport;
pub type LoopbackTransport = RecordingKlaviyoTransport;

#[derive(Debug, Default)]
pub struct BlockedEnvTransport;

impl KlaviyoTransport for BlockedEnvTransport {
    fn read_campaign_or_flow_metadata(
        &mut self,
        _request: &CampaignMetadataRequest,
    ) -> Result<CampaignMetadataResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn query_values(&mut self, _request: &ReportRequest) -> Result<ReportPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn query_series(&mut self, _request: &ReportRequest) -> Result<ReportPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

impl From<TransportError> for crate::ProviderErrorEvidence {
    fn from(error: TransportError) -> Self {
        Self::new(
            error.kind,
            error.status_code,
            error.retryable,
            1,
            error.blocked_env,
            error.diagnostic_digest(),
        )
    }
}

#[allow(dead_code)]
fn _keep_allowlisted_permission_names() -> [KlaviyoPermission; 3] {
    [
        KlaviyoPermission::CampaignsRead,
        KlaviyoPermission::FlowsRead,
        KlaviyoPermission::MetricsRead,
    ]
}

#[allow(dead_code)]
fn _keep_report_request_types_visible(
    _selection: MetricSelection,
    _window: ReportWindow,
    _variation: VariationSelector,
    _resource: ResourceId,
    _account: AccountId,
) {
}
