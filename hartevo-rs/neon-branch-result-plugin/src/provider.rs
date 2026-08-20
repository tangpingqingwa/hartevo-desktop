use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    error::NeonProviderError,
    model::{
        AdoptionProposalReceipt, BranchProposal, BranchProposalReceipt, CapabilityProbeRequest,
        ControlPlaneObservation, DatabaseResultAdoptionProposal, Digest, EvidenceSource,
        NativeStatus, NeonProviderManifest, QueryProposal, QueryReceipt, QueryResultObservation,
        QueryTransportProtocol, TransportMode,
    },
};

/// Control-plane transport seam. Implementations may be fixture, loopback, or
/// a future native HTTP adapter; Layer 1 only ships the first two modes.
pub trait NeonControlPlaneTransport: fmt::Debug + Send + Sync {
    /// Return a typed capability observation without creating or mutating a
    /// live branch or endpoint.
    fn probe(
        &self,
        request: &CapabilityProbeRequest,
    ) -> Result<ControlPlaneObservation, NeonProviderError>;

    /// Identify the seam mode without claiming native connectivity.
    fn mode(&self) -> TransportMode;
}

/// Postgres/HTTP query transport seam. Layer 1 implementations return a
/// deterministic observation and never expose a connection string.
pub trait PostgresQueryTransport: fmt::Debug + Send + Sync {
    /// Return a typed query observation for a proposal.
    fn execute(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryResultObservation, NeonProviderError>;

    /// Identify the seam mode without claiming native connectivity.
    fn mode(&self) -> TransportMode;

    /// Identify whether a future transport would speak Postgres or HTTP.
    fn protocol(&self) -> QueryTransportProtocol;
}

/// Typed provider boundary used by the service and Mission consumer.
pub trait NeonBranchResultProvider: fmt::Debug + Send + Sync {
    /// Return the immutable provider manifest.
    fn manifest(&self) -> NeonProviderManifest;

    /// Probe the separate control-plane seam.
    fn capability_probe(
        &self,
        request: &CapabilityProbeRequest,
    ) -> Result<ControlPlaneObservation, NeonProviderError>;

    /// Record a branch proposal without creating a live branch.
    fn record_branch_proposal(
        &self,
        proposal: &BranchProposal,
    ) -> Result<BranchProposalReceipt, NeonProviderError>;

    /// Execute through the separate query seam. In Layer 1 this means a
    /// fixture/loopback observation, not a native database read.
    fn execute_query(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryResultObservation, NeonProviderError>;

    /// Record an independently computed query receipt.
    fn record_query_receipt(
        &self,
        proposal: &QueryProposal,
        receipt: &QueryReceipt,
    ) -> Result<QueryReceipt, NeonProviderError>;

    /// Verify that a receipt is the exact independent receipt retained by the
    /// provider seam, rather than a caller-rewritten transport response.
    fn verify_query_receipt(
        &self,
        proposal: &QueryProposal,
        receipt: &QueryReceipt,
    ) -> Result<(), NeonProviderError>;

    /// Record an adoption proposal without durable Work Product adoption.
    fn record_adoption_proposal(
        &self,
        proposal: &DatabaseResultAdoptionProposal,
    ) -> Result<AdoptionProposalReceipt, NeonProviderError>;

    /// Return the control-plane seam mode.
    fn control_plane_mode(&self) -> TransportMode;

    /// Return the query seam mode.
    fn query_transport_mode(&self) -> TransportMode;

    /// Native execution authority is permanently absent in Layer 1.
    fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }
}

/// Content-free provider call record. No SQL, parameters, rows, passwords, or
/// connection strings are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NeonProviderCall {
    CapabilityProbe {
        scope_digest: Digest,
        branch_fence_digest: Digest,
    },
    BranchProposal {
        proposal_digest: Digest,
        scope_digest: Digest,
        branch_fence_digest: Digest,
    },
    QueryExecution {
        proposal_digest: Digest,
        scope_digest: Digest,
        branch_fence_digest: Digest,
        query_digest: Digest,
        parameter_digest: Digest,
        protocol: QueryTransportProtocol,
    },
    QueryReceipt {
        proposal_digest: Digest,
        receipt_digest: Digest,
        row_count: u32,
        result_bytes: u64,
    },
    AdoptionProposal {
        proposal_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
    },
}

#[derive(Debug, Default)]
struct RecordingProviderState {
    calls: Vec<NeonProviderCall>,
    last_query_receipt: Option<QueryReceipt>,
    query_receipts: BTreeMap<Digest, QueryReceipt>,
    last_adoption_receipt: Option<AdoptionProposalReceipt>,
    adoption_receipts: BTreeMap<Digest, AdoptionProposalReceipt>,
    fault: Option<NeonProviderError>,
}

/// Deterministic control-plane fixture/loopback seam.
#[derive(Clone, Debug)]
pub struct RecordingNeonControlPlaneTransport {
    observation: Arc<Mutex<Option<ControlPlaneObservation>>>,
    fault: Arc<Mutex<Option<NeonProviderError>>>,
    mode: TransportMode,
}

impl Default for RecordingNeonControlPlaneTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingNeonControlPlaneTransport {
    /// Create a fixture seam with a request-derived ready observation.
    pub fn new() -> Self {
        Self::with_mode(TransportMode::Fixture)
    }

    /// Create a recording seam with explicit fixture/loopback/blocked mode.
    pub fn with_mode(mode: TransportMode) -> Self {
        Self {
            observation: Arc::new(Mutex::new(None)),
            fault: Arc::new(Mutex::new(None)),
            mode,
        }
    }

    /// Create a seam with a fixed observation, useful for state fixtures.
    pub fn with_observation(observation: ControlPlaneObservation) -> Self {
        let transport = Self::new();
        transport.set_observation(observation);
        transport
    }

    /// Set a fixed observation. Validation is deferred to the service so
    /// tamper and scope-drift fixtures remain testable.
    pub fn set_observation(&self, observation: ControlPlaneObservation) {
        *self
            .observation
            .lock()
            .expect("control-plane observation lock") = Some(observation);
    }

    /// Set a typed fault for deterministic rate-limit/access-loss tests.
    pub fn set_fault(&self, fault: NeonProviderError) {
        *self.fault.lock().expect("control-plane fault lock") = Some(fault);
    }

    /// Clear a previously configured fixture fault.
    pub fn clear_fault(&self) {
        *self.fault.lock().expect("control-plane fault lock") = None;
    }
}

impl NeonControlPlaneTransport for RecordingNeonControlPlaneTransport {
    fn probe(
        &self,
        request: &CapabilityProbeRequest,
    ) -> Result<ControlPlaneObservation, NeonProviderError> {
        if let Some(fault) = *self.fault.lock().expect("control-plane fault lock") {
            return Err(fault);
        }
        if let Some(observation) = self
            .observation
            .lock()
            .expect("control-plane observation lock")
            .clone()
        {
            return Ok(observation);
        }
        Ok(ControlPlaneObservation {
            scope: request.scope.clone(),
            point_in_time: request.point_in_time.clone(),
            branch_state: crate::BranchState::Ready,
            endpoint_state: crate::EndpointState::Ready,
            eventual_consistency: crate::EventualConsistencyState::Stable,
            observed_branch_digest: request.scope.digest(),
            observed_endpoint_digest: crate::canonical_digest(&request.scope.endpoint_id),
            evidence_source: EvidenceSource::Fixture,
            native_status: NativeStatus::BlockedEnv,
        })
    }

    fn mode(&self) -> TransportMode {
        self.mode
    }
}

/// Deterministic Postgres/HTTP query fixture seam.
#[derive(Clone)]
pub struct RecordingPostgresQueryTransport {
    observation: Arc<Mutex<Option<QueryResultObservation>>>,
    fault: Arc<Mutex<Option<NeonProviderError>>>,
    mode: TransportMode,
    protocol: QueryTransportProtocol,
}

impl fmt::Debug for RecordingPostgresQueryTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let has_observation = self
            .observation
            .lock()
            .expect("query observation lock")
            .is_some();
        formatter
            .debug_struct("RecordingPostgresQueryTransport")
            .field("mode", &self.mode)
            .field("protocol", &self.protocol)
            .field("has_observation", &has_observation)
            .finish_non_exhaustive()
    }
}

impl Default for RecordingPostgresQueryTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingPostgresQueryTransport {
    /// Create an HTTP fixture seam with a deterministic request-derived row.
    pub fn new() -> Self {
        Self::with_mode_and_protocol(TransportMode::Fixture, QueryTransportProtocol::Http)
    }

    /// Create a recording query seam with explicit mode and protocol metadata.
    pub fn with_mode_and_protocol(mode: TransportMode, protocol: QueryTransportProtocol) -> Self {
        Self {
            observation: Arc::new(Mutex::new(None)),
            fault: Arc::new(Mutex::new(None)),
            mode,
            protocol,
        }
    }

    /// Create a seam with a fixed observation.
    pub fn with_observation(observation: QueryResultObservation) -> Self {
        let transport = Self::new();
        transport.set_observation(observation);
        transport
    }

    /// Set a fixed observation; validation remains a service concern.
    pub fn set_observation(&self, observation: QueryResultObservation) {
        *self.observation.lock().expect("query observation lock") = Some(observation);
    }

    /// Set a typed fault for rate-limit, timeout, and permission fixtures.
    pub fn set_fault(&self, fault: NeonProviderError) {
        *self.fault.lock().expect("query fault lock") = Some(fault);
    }

    /// Clear a configured query fault.
    pub fn clear_fault(&self) {
        *self.fault.lock().expect("query fault lock") = None;
    }

    fn default_observation(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryResultObservation, NeonProviderError> {
        let schema = crate::QuerySchema::new(vec![
            crate::QueryColumn::new("result", "text", true)
                .map_err(|_| NeonProviderError::InvalidResponse { field: "schema" })?,
        ])
        .map_err(|_| NeonProviderError::InvalidResponse { field: "schema" })?;
        let rows = vec![crate::QueryRow(vec![crate::QueryValue::Text {
            value: String::from("fixture-row"),
        }])];
        QueryResultObservation::new(
            proposal.scope.clone(),
            proposal.branch_fence.clone(),
            schema,
            rows,
            1,
            self.protocol,
            EvidenceSource::Fixture,
        )
        .map_err(|_| NeonProviderError::InvalidResponse {
            field: "query_result",
        })
    }
}

impl PostgresQueryTransport for RecordingPostgresQueryTransport {
    fn execute(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryResultObservation, NeonProviderError> {
        if let Some(fault) = *self.fault.lock().expect("query fault lock") {
            return Err(fault);
        }
        self.observation
            .lock()
            .expect("query observation lock")
            .clone()
            .map_or_else(|| self.default_observation(proposal), Ok)
    }

    fn mode(&self) -> TransportMode {
        self.mode
    }

    fn protocol(&self) -> QueryTransportProtocol {
        self.protocol
    }
}

/// Recording provider that composes separate control-plane and query seams.
/// It never contacts Neon and stores only typed digest metadata in its calls.
#[derive(Clone, Debug)]
pub struct RecordingNeonBranchResultProvider {
    manifest: Arc<Mutex<NeonProviderManifest>>,
    control_plane: RecordingNeonControlPlaneTransport,
    query_transport: RecordingPostgresQueryTransport,
    state: Arc<Mutex<RecordingProviderState>>,
    secret_reference: Option<crate::SecretReference>,
}

impl RecordingNeonBranchResultProvider {
    /// Construct a fixture provider from a validated or intentionally drifted
    /// manifest. Service construction performs the authoritative validation.
    pub fn new(manifest: NeonProviderManifest) -> Self {
        let control_plane =
            RecordingNeonControlPlaneTransport::with_mode(manifest.control_plane_mode);
        let query_transport = RecordingPostgresQueryTransport::with_mode_and_protocol(
            manifest.query_transport_mode,
            manifest.query_transport_protocol,
        );
        Self {
            manifest: Arc::new(Mutex::new(manifest)),
            control_plane,
            query_transport,
            state: Arc::new(Mutex::new(RecordingProviderState::default())),
            secret_reference: None,
        }
    }

    /// Construct a provider with explicitly configured recording seams.
    pub fn with_transports(
        manifest: NeonProviderManifest,
        control_plane: RecordingNeonControlPlaneTransport,
        query_transport: RecordingPostgresQueryTransport,
    ) -> Self {
        Self {
            manifest: Arc::new(Mutex::new(manifest)),
            control_plane,
            query_transport,
            state: Arc::new(Mutex::new(RecordingProviderState::default())),
            secret_reference: None,
        }
    }

    /// Attach an opaque reference at the provider boundary only.
    #[must_use]
    pub fn with_secret_reference(mut self, reference: crate::SecretReference) -> Self {
        self.secret_reference = Some(reference);
        self
    }

    /// Replace the manifest to exercise drift fencing.
    pub fn set_manifest(&self, manifest: NeonProviderManifest) {
        *self.manifest.lock().expect("manifest lock") = manifest;
    }

    /// Set a provider-level typed fault.
    pub fn set_fault(&self, fault: NeonProviderError) {
        self.state.lock().expect("provider state lock").fault = Some(fault);
    }

    /// Clear a provider-level fault.
    pub fn clear_fault(&self) {
        self.state.lock().expect("provider state lock").fault = None;
    }

    /// Configure the control-plane observation.
    pub fn set_control_plane_observation(&self, observation: ControlPlaneObservation) {
        self.control_plane.set_observation(observation);
    }

    /// Configure the query observation.
    pub fn set_query_observation(&self, observation: QueryResultObservation) {
        self.query_transport.set_observation(observation);
    }

    /// Configure a fault at the control-plane seam.
    pub fn set_control_plane_fault(&self, fault: NeonProviderError) {
        self.control_plane.set_fault(fault);
    }

    /// Configure a fault at the query seam.
    pub fn set_query_fault(&self, fault: NeonProviderError) {
        self.query_transport.set_fault(fault);
    }

    /// Borrow the configured control-plane recording seam.
    pub fn control_plane_transport(&self) -> &RecordingNeonControlPlaneTransport {
        &self.control_plane
    }

    /// Borrow the configured query recording seam.
    pub fn query_transport(&self) -> &RecordingPostgresQueryTransport {
        &self.query_transport
    }

    /// Return content-free provider calls.
    pub fn calls(&self) -> Vec<NeonProviderCall> {
        self.state
            .lock()
            .expect("provider state lock")
            .calls
            .clone()
    }

    /// Return the last independently recorded query receipt.
    pub fn last_query_receipt(&self) -> Option<QueryReceipt> {
        self.state
            .lock()
            .expect("provider state lock")
            .last_query_receipt
            .clone()
    }

    /// Return the last locally recorded adoption proposal receipt.
    pub fn last_adoption_receipt(&self) -> Option<AdoptionProposalReceipt> {
        self.state
            .lock()
            .expect("provider state lock")
            .last_adoption_receipt
            .clone()
    }

    fn fault(&self) -> Option<NeonProviderError> {
        self.state.lock().expect("provider state lock").fault
    }

    fn checked_manifest(&self) -> Result<NeonProviderManifest, NeonProviderError> {
        let manifest = self.manifest();
        manifest
            .validate()
            .map_err(|_| NeonProviderError::ManifestMismatch)?;
        Ok(manifest)
    }

    fn check_scope(
        &self,
        scope: &crate::NeonScope,
    ) -> Result<NeonProviderManifest, NeonProviderError> {
        let manifest = self.checked_manifest()?;
        if &manifest.scope != scope {
            return Err(NeonProviderError::ScopeMismatch);
        }
        Ok(manifest)
    }

    fn check_fault(&self) -> Result<(), NeonProviderError> {
        self.fault().map_or(Ok(()), Err)
    }
}

impl NeonBranchResultProvider for RecordingNeonBranchResultProvider {
    fn manifest(&self) -> NeonProviderManifest {
        self.manifest.lock().expect("manifest lock").clone()
    }

    fn capability_probe(
        &self,
        request: &CapabilityProbeRequest,
    ) -> Result<ControlPlaneObservation, NeonProviderError> {
        self.check_fault()?;
        self.check_scope(&request.scope)?;
        let observation = self.control_plane.probe(request)?;
        self.state.lock().expect("provider state lock").calls.push(
            NeonProviderCall::CapabilityProbe {
                scope_digest: request.scope.digest(),
                branch_fence_digest: request
                    .branch_fence()
                    .map_err(|_| NeonProviderError::InvalidResponse {
                        field: "branch_fence",
                    })?
                    .digest(),
            },
        );
        Ok(observation)
    }

    fn record_branch_proposal(
        &self,
        proposal: &BranchProposal,
    ) -> Result<BranchProposalReceipt, NeonProviderError> {
        self.check_fault()?;
        let manifest = self.check_scope(&proposal.scope)?;
        proposal
            .validate()
            .map_err(|_| NeonProviderError::InvalidResponse { field: "proposal" })?;
        if proposal.provider_manifest_digest != manifest.digest() {
            return Err(NeonProviderError::ManifestMismatch);
        }
        let receipt = BranchProposalReceipt::from_proposal(proposal, &manifest)
            .map_err(|_| NeonProviderError::InvalidResponse { field: "receipt" })?;
        self.state.lock().expect("provider state lock").calls.push(
            NeonProviderCall::BranchProposal {
                proposal_digest: proposal.proposal_digest.clone(),
                scope_digest: proposal.scope.digest(),
                branch_fence_digest: proposal.branch_fence.digest(),
            },
        );
        Ok(receipt)
    }

    fn execute_query(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryResultObservation, NeonProviderError> {
        self.check_fault()?;
        self.check_scope(&proposal.scope)?;
        proposal
            .validate()
            .map_err(|_| NeonProviderError::InvalidResponse { field: "proposal" })?;
        let observation = self.query_transport.execute(proposal)?;
        self.state.lock().expect("provider state lock").calls.push(
            NeonProviderCall::QueryExecution {
                proposal_digest: proposal.proposal_digest.clone(),
                scope_digest: proposal.scope.digest(),
                branch_fence_digest: proposal.branch_fence.digest(),
                query_digest: proposal.query.query_digest.clone(),
                parameter_digest: proposal.query.parameter_digest.clone(),
                protocol: self.query_transport.protocol(),
            },
        );
        Ok(observation)
    }

    fn record_query_receipt(
        &self,
        proposal: &QueryProposal,
        receipt: &QueryReceipt,
    ) -> Result<QueryReceipt, NeonProviderError> {
        self.check_fault()?;
        let manifest = self.check_scope(&proposal.scope)?;
        proposal
            .validate()
            .map_err(|_| NeonProviderError::InvalidResponse { field: "proposal" })?;
        receipt
            .matches_proposal(proposal)
            .map_err(|_| NeonProviderError::ReceiptMismatch)?;
        if receipt.provider_manifest_digest != manifest.digest() {
            return Err(NeonProviderError::ManifestMismatch);
        }
        let mut state = self.state.lock().expect("provider state lock");
        if let Some(existing) = state.query_receipts.get(&proposal.proposal_digest) {
            if existing == receipt {
                return Ok(existing.clone());
            }
            return Err(NeonProviderError::DuplicateFingerprint);
        }
        state
            .query_receipts
            .insert(proposal.proposal_digest.clone(), receipt.clone());
        state.last_query_receipt = Some(receipt.clone());
        state.calls.push(NeonProviderCall::QueryReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            row_count: receipt.row_count,
            result_bytes: receipt.result_bytes,
        });
        Ok(receipt.clone())
    }

    fn verify_query_receipt(
        &self,
        proposal: &QueryProposal,
        receipt: &QueryReceipt,
    ) -> Result<(), NeonProviderError> {
        self.check_fault()?;
        let manifest = self.check_scope(&proposal.scope)?;
        receipt
            .matches_proposal(proposal)
            .map_err(|_| NeonProviderError::ReceiptMismatch)?;
        if receipt.provider_manifest_digest != manifest.digest() {
            return Err(NeonProviderError::ManifestMismatch);
        }
        let expected = self
            .state
            .lock()
            .expect("provider state lock")
            .query_receipts
            .get(&proposal.proposal_digest)
            .cloned()
            .ok_or(NeonProviderError::ReceiptMismatch)?;
        if expected != *receipt {
            return Err(NeonProviderError::ReceiptMismatch);
        }
        Ok(())
    }

    fn record_adoption_proposal(
        &self,
        proposal: &DatabaseResultAdoptionProposal,
    ) -> Result<AdoptionProposalReceipt, NeonProviderError> {
        self.check_fault()?;
        let manifest = self.check_scope(&proposal.scope)?;
        proposal
            .validate()
            .map_err(|_| NeonProviderError::InvalidResponse { field: "proposal" })?;
        if proposal.provider_manifest_digest != manifest.digest() {
            return Err(NeonProviderError::ManifestMismatch);
        }
        let receipt = AdoptionProposalReceipt::from_proposal(proposal, &manifest)
            .map_err(|_| NeonProviderError::InvalidResponse { field: "receipt" })?;
        let mut state = self.state.lock().expect("provider state lock");
        if let Some(existing) = state.adoption_receipts.get(&proposal.proposal_digest) {
            if existing == &receipt {
                return Ok(existing.clone());
            }
            return Err(NeonProviderError::DuplicateFingerprint);
        }
        state
            .adoption_receipts
            .insert(proposal.proposal_digest.clone(), receipt.clone());
        state.calls.push(NeonProviderCall::AdoptionProposal {
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope.digest(),
            registration_digest: proposal.registration_digest.clone(),
        });
        state.last_adoption_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    fn control_plane_mode(&self) -> TransportMode {
        self.control_plane.mode()
    }

    fn query_transport_mode(&self) -> TransportMode {
        self.query_transport.mode()
    }

    fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }
}
