use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::Serialize;

use crate::model::{
    ClusterProjection, ClusterState, HealthPosture, HealthProjection, SettingsMetadataProjection,
    SettingsPosture, SqlActivityPosture, SqlActivityProjection, validate_bounded_counts,
    validate_revision_fence,
};
use crate::{
    CockroachCloudPage, CockroachCloudReadRequest, CockroachCloudResultError, CockroachCloudScope,
    CockroachCloudTransportError, MAX_PAGES, TransportProvenance, api_digest, provider_digest,
};

/// Content-free provider call audit. It never stores a URL, cursor token,
/// credential, SQL string, raw result, or provider body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudCall {
    pub page: u16,
    pub scope_digest: crate::Digest,
    pub revision_fence_digest: crate::Digest,
    pub query_digest: crate::Digest,
    pub request_digest: crate::Digest,
    pub cursor_digest: Option<crate::Digest>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

/// Immutable provider definition bound into registration and evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudProviderDefinition {
    pub provider_id: String,
    pub provider_revision: String,
    pub api_revision: String,
    pub provider_digest: crate::Digest,
    pub api_digest: crate::Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub operations: Vec<String>,
}

impl CockroachCloudProviderDefinition {
    pub fn baseline() -> Self {
        Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_revision: crate::API_REVISION.to_owned(),
            api_revision: crate::API_REVISION.to_owned(),
            provider_digest: provider_digest(),
            api_digest: api_digest(),
            connected: false,
            native: false,
            first_party: false,
            operations: vec![
                "GET organization".to_owned(),
                "GET cloud project".to_owned(),
                "GET cluster".to_owned(),
                "GET cluster health".to_owned(),
                "GET settings metadata".to_owned(),
                "GET SQL activity posture".to_owned(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), CockroachCloudResultError> {
        let baseline = Self::baseline();
        if self != &baseline {
            Err(CockroachCloudResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

/// Fixture/recording boundary used by the typed provider. A Layer-2 host may
/// implement this trait later, but Layer 1 ships no native implementation.
pub trait CockroachCloudTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_page(
        &mut self,
        request: &CockroachCloudReadRequest,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError>;
}

/// Typed provider wrapper that binds a transport to the fixed non-native
/// provider manifest and retains only digest-only call/receipt metadata.
pub struct CockroachCloudProvider<T: CockroachCloudTransport> {
    transport: T,
    definition: CockroachCloudProviderDefinition,
    calls: Vec<CockroachCloudCall>,
    recorded_receipts: BTreeSet<crate::Digest>,
}

impl<T: CockroachCloudTransport> fmt::Debug for CockroachCloudProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CockroachCloudProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .field("call_count", &self.calls.len())
            .field("recorded_receipt_count", &self.recorded_receipts.len())
            .finish()
    }
}

impl<T: CockroachCloudTransport> CockroachCloudProvider<T> {
    pub fn new(transport: T) -> Result<Self, CockroachCloudResultError> {
        let definition = CockroachCloudProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            calls: Vec::new(),
            recorded_receipts: BTreeSet::new(),
        })
    }

    pub fn definition(&self) -> &CockroachCloudProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn calls(&self) -> &[CockroachCloudCall] {
        &self.calls
    }

    pub fn read_page(
        &mut self,
        request: &CockroachCloudReadRequest,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError> {
        let result = self.transport.read_page(request);
        if let Ok(page) = &result {
            if page.provenance != self.provenance()
                || page.provenance.connected()
                || page.provenance.native()
                || page.provenance.first_party()
                || page.page > MAX_PAGES
            {
                return Err(CockroachCloudTransportError::InvalidResponse);
            }
            page.validate_for(request)
                .map_err(|_| CockroachCloudTransportError::InvalidResponse)?;
            validate_revision_fence(&request.scope, page)
                .map_err(|_| CockroachCloudTransportError::InvalidResponse)?;
            validate_bounded_counts(
                page.settings
                    .as_ref()
                    .map_or(0, |settings| usize::from(settings.entry_count)),
                page.sql_activity.len(),
                page.response_bytes,
            )
            .map_err(|_| CockroachCloudTransportError::InvalidResponse)?;
            self.calls.push(CockroachCloudCall {
                page: page.page,
                scope_digest: page.scope_digest.clone(),
                revision_fence_digest: page.revision_fence_digest.clone(),
                query_digest: request.query_digest.clone(),
                request_digest: request.request_digest.clone(),
                cursor_digest: request.cursor_digest().cloned(),
                provenance: page.provenance,
                connected: false,
                native: false,
                first_party: false,
            });
        }
        result
    }

    /// Retain only a redacted receipt digest in the recording provider.
    pub fn record_receipt_digest(&mut self, receipt_digest: crate::Digest) -> bool {
        self.recorded_receipts.insert(receipt_digest)
    }

    pub fn verify_receipt_digest(&self, receipt_digest: &crate::Digest) -> bool {
        self.recorded_receipts.contains(receipt_digest)
    }
}

impl Default for CockroachCloudProvider<BlockedEnvCockroachCloudTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvCockroachCloudTransport).expect("blocked provider definition")
    }
}

/// A deterministic recording transport. Pages are supplied as already typed,
/// digest-bound projections; no raw provider body is accepted.
pub struct RecordingCockroachCloudTransport {
    provenance: TransportProvenance,
    pages: VecDeque<Result<CockroachCloudPage, CockroachCloudTransportError>>,
    requests: Vec<CockroachCloudReadRequest>,
    fault: Option<CockroachCloudTransportError>,
}

impl fmt::Debug for RecordingCockroachCloudTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingCockroachCloudTransport")
            .field("provenance", &self.provenance)
            .field("queued_page_count", &self.pages.len())
            .field("request_count", &self.requests.len())
            .field("fault", &self.fault)
            .finish()
    }
}

impl Default for RecordingCockroachCloudTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingCockroachCloudTransport {
    pub fn new() -> Self {
        Self::with_provenance(TransportProvenance::Recording)
    }

    pub fn with_provenance(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            pages: VecDeque::new(),
            requests: Vec::new(),
            fault: None,
        }
    }

    pub fn push_page(&mut self, page: Result<CockroachCloudPage, CockroachCloudTransportError>) {
        self.pages.push_back(page);
    }

    pub fn set_fault(&mut self, fault: CockroachCloudTransportError) {
        self.fault = Some(fault);
    }

    pub fn clear_fault(&mut self) {
        self.fault = None;
    }

    pub fn requests(&self) -> &[CockroachCloudReadRequest] {
        &self.requests
    }
}

impl CockroachCloudTransport for RecordingCockroachCloudTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read_page(
        &mut self,
        request: &CockroachCloudReadRequest,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError> {
        self.requests.push(request.clone());
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        self.pages
            .pop_front()
            .unwrap_or(Err(CockroachCloudTransportError::NoRecordedPage))
    }
}

/// Deterministic fixture page generator. It creates provider-reported
/// metadata only and never represents a native Cloud read.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixtureCockroachCloudTransport;

impl FixtureCockroachCloudTransport {
    pub fn new() -> Self {
        Self
    }

    pub fn for_scope(_scope: &CockroachCloudScope, _observed_at: u64) -> Self {
        Self
    }

    fn page(
        request: &CockroachCloudReadRequest,
        provenance: TransportProvenance,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError> {
        let cluster = ClusterProjection::for_scope(&request.scope, ClusterState::Running);
        let health = HealthProjection::for_scope(
            &request.scope,
            HealthPosture::ProviderHealthy,
            1,
            "fixture-provider-health",
        )
        .map_err(|_| CockroachCloudTransportError::InvalidResponse)?;
        let settings = SettingsMetadataProjection::for_scope(
            &request.scope,
            3,
            "fixture-provider-settings-names",
            SettingsPosture::Current,
        )
        .map_err(|_| CockroachCloudTransportError::InvalidResponse)?;
        let sql_activity = if request.include_sql_activity {
            vec![
                SqlActivityProjection::for_statement(
                    &request.scope,
                    "SELECT 1 /* retained as digest only */",
                    SqlActivityPosture::Quiet,
                    1,
                    4,
                    8,
                )
                .map_err(|_| CockroachCloudTransportError::InvalidResponse)?,
            ]
        } else {
            Vec::new()
        };
        CockroachCloudPage::new(
            request,
            Some(cluster),
            Some(health),
            Some(settings),
            sql_activity,
            None,
            512,
            provenance,
        )
        .map_err(|_| CockroachCloudTransportError::InvalidResponse)
    }
}

impl CockroachCloudTransport for FixtureCockroachCloudTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_page(
        &mut self,
        request: &CockroachCloudReadRequest,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError> {
        Self::page(request, self.provenance())
    }
}

/// A fake deterministic transport with the same redaction and authority
/// boundary as the fixture transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct FakeCockroachCloudTransport;

impl FakeCockroachCloudTransport {
    pub fn new() -> Self {
        Self
    }

    pub fn for_scope(_scope: &CockroachCloudScope, _observed_at: u64) -> Self {
        Self
    }
}

impl CockroachCloudTransport for FakeCockroachCloudTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read_page(
        &mut self,
        request: &CockroachCloudReadRequest,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError> {
        FixtureCockroachCloudTransport::page(request, self.provenance())
    }
}

/// A loopback transport for local deterministic composition tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackCockroachCloudTransport;

impl LoopbackCockroachCloudTransport {
    pub fn new() -> Self {
        Self
    }

    pub fn for_scope(_scope: &CockroachCloudScope, _observed_at: u64) -> Self {
        Self
    }
}

impl CockroachCloudTransport for LoopbackCockroachCloudTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_page(
        &mut self,
        request: &CockroachCloudReadRequest,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError> {
        FixtureCockroachCloudTransport::page(request, self.provenance())
    }
}

/// Native resolution is intentionally blocked in Layer 1.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCockroachCloudTransport;

impl CockroachCloudTransport for BlockedEnvCockroachCloudTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_page(
        &mut self,
        _request: &CockroachCloudReadRequest,
    ) -> Result<CockroachCloudPage, CockroachCloudTransportError> {
        Err(CockroachCloudTransportError::BlockedEnv)
    }
}

pub type RecordingTransport = RecordingCockroachCloudTransport;
pub type FixtureTransport = FixtureCockroachCloudTransport;
pub type FakeTransport = FakeCockroachCloudTransport;
pub type LoopbackTransport = LoopbackCockroachCloudTransport;
pub type BlockedEnvTransport = BlockedEnvCockroachCloudTransport;
