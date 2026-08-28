use crate::model::{
    ApiServerEndpoint, ClusterDescription, DeploymentIdentity, DeploymentSnapshot,
    EvidenceProvenance, KubernetesRolloutScope, ModelError, RolloutReadRequest, SecretReference,
};
use crate::service::{ImageUpdateProposal, KubernetesRolloutError, KubernetesRolloutRegistration};
use crate::{
    KUBERNETES_API_REVISION, PROVIDER_ID, digest_json, valid_identifier, valid_sha256_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Error)]
pub enum KubernetesApiError {
    #[error("Kubernetes API returned HTTP status {status}")]
    HttpStatus {
        status: u16,
        request_id: Option<String>,
    },
    #[error("Kubernetes watch history was compacted")]
    WatchCompacted { request_id: Option<String> },
    #[error("Kubernetes API request timed out")]
    Timeout,
    #[error("Kubernetes Layer-1 native transport is unavailable: {operation}")]
    BlockedEnv { operation: String },
    #[error("Kubernetes provider returned malformed bounded evidence: {0}")]
    MalformedEvidence(String),
}

impl KubernetesApiError {
    pub const fn retryable(&self) -> bool {
        match self {
            Self::HttpStatus { status, .. } => {
                *status == 409 || *status == 429 || (*status >= 500 && *status <= 599)
            }
            Self::WatchCompacted { .. } | Self::Timeout => true,
            Self::BlockedEnv { .. } | Self::MalformedEvidence(_) => false,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            Self::WatchCompacted { .. } => Some(410),
            Self::Timeout | Self::BlockedEnv { .. } | Self::MalformedEvidence(_) => None,
        }
    }

    pub fn http(status: u16, request_id: Option<impl Into<String>>) -> Self {
        Self::HttpStatus {
            status,
            request_id: request_id.map(Into::into),
        }
    }

    pub fn blocked(operation: impl Into<String>) -> Self {
        Self::BlockedEnv {
            operation: operation.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum KubernetesProviderError {
    #[error(transparent)]
    Api(#[from] KubernetesApiError),
    #[error("provider registration drifted")]
    RegistrationDrift,
    #[error("provider authentication reference is not bound to the rollout scope")]
    AuthScopeMismatch,
    #[error("provider returned trust or provenance evidence outside the registered fence")]
    TrustOrProvenanceMismatch,
    #[error("provider evidence is invalid: {0}")]
    Evidence(String),
    #[error("provider API revision is not the registered apps/v1 revision")]
    ApiRevisionMismatch,
}

impl KubernetesProviderError {
    pub fn api_error(&self) -> KubernetesApiError {
        match self {
            Self::Api(error) => error.clone(),
            Self::RegistrationDrift
            | Self::AuthScopeMismatch
            | Self::TrustOrProvenanceMismatch
            | Self::Evidence(_)
            | Self::ApiRevisionMismatch => KubernetesApiError::MalformedEvidence(self.to_string()),
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Api(error) if error.retryable())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderReadResponse {
    pub snapshot: DeploymentSnapshot,
    pub provenance: EvidenceProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDryRunResponse {
    pub evidence: DryRunEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DryRunProposal {
    pub proposal_version: String,
    pub scope_digest: String,
    pub registration_digest: String,
    pub api_server: ApiServerEndpoint,
    pub object: DeploymentIdentity,
    pub expected_resource_version: String,
    pub expected_generation: u64,
    pub field_manager: String,
    pub dry_run_parameter: String,
    pub proposal_digest: String,
    pub desired_image_digests: BTreeMap<String, String>,
    pub idempotency_fingerprint: String,
    pub connected: bool,
    pub native: bool,
}

impl DryRunProposal {
    pub(crate) fn from_apply_proposal(
        proposal: &ImageUpdateProposal,
        api_server: ApiServerEndpoint,
        field_manager: String,
    ) -> Self {
        Self {
            proposal_version: "kubernetes-rollout-dry-run-proposal/v1".into(),
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            api_server,
            object: proposal.object.clone(),
            expected_resource_version: proposal.expected_resource_version.clone(),
            expected_generation: proposal.expected_generation,
            field_manager,
            dry_run_parameter: "All".into(),
            proposal_digest: proposal.proposal_digest.clone(),
            desired_image_digests: proposal.desired_image_digests.clone(),
            idempotency_fingerprint: proposal.idempotency_fingerprint.clone(),
            connected: false,
            native: false,
        }
    }

    pub fn validate(&self) -> Result<(), KubernetesRolloutError> {
        if self.proposal_version != "kubernetes-rollout-dry-run-proposal/v1"
            || !valid_sha256_digest(&self.scope_digest)
            || !valid_sha256_digest(&self.registration_digest)
            || self.api_server.validate().is_err()
            || self.object.validate().is_err()
            || !valid_identifier(&self.expected_resource_version, 128)
            || self.expected_generation == 0
            || !valid_identifier(&self.field_manager, 128)
            || self.dry_run_parameter != "All"
            || !valid_sha256_digest(&self.proposal_digest)
            || !crate::valid_digest_map(&self.desired_image_digests)
            || !valid_sha256_digest(&self.idempotency_fingerprint)
            || self.connected
            || self.native
        {
            return Err(KubernetesRolloutError::TamperedProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunStatus {
    Accepted,
    Rejected,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DryRunTransportEvidence {
    pub status: DryRunStatus,
    pub response_digest: Option<String>,
    pub generated_fields_digest: Option<String>,
    pub request_id: Option<String>,
}

impl DryRunTransportEvidence {
    pub fn blocked() -> Self {
        Self {
            status: DryRunStatus::BlockedEnv,
            response_digest: None,
            generated_fields_digest: None,
            request_id: None,
        }
    }

    pub fn accepted(
        response_digest: impl Into<String>,
        generated_fields_digest: Option<String>,
        request_id: Option<String>,
    ) -> Result<Self, KubernetesProviderError> {
        let evidence = Self {
            status: DryRunStatus::Accepted,
            response_digest: Some(response_digest.into()),
            generated_fields_digest,
            request_id,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn rejected(
        response_digest: impl Into<String>,
        request_id: Option<String>,
    ) -> Result<Self, KubernetesProviderError> {
        let evidence = Self {
            status: DryRunStatus::Rejected,
            response_digest: Some(response_digest.into()),
            generated_fields_digest: None,
            request_id,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), KubernetesProviderError> {
        if self.status != DryRunStatus::BlockedEnv
            && self
                .response_digest
                .as_deref()
                .is_none_or(|digest| !valid_sha256_digest(digest))
        {
            return Err(KubernetesProviderError::Evidence(
                "dry-run response digest".into(),
            ));
        }
        if self
            .generated_fields_digest
            .as_deref()
            .is_some_and(|digest| !valid_sha256_digest(digest))
            || self
                .request_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, 256))
        {
            return Err(KubernetesProviderError::Evidence(
                "dry-run bounded fields".into(),
            ));
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DryRunEvidence {
    pub evidence_version: String,
    pub scope_digest: String,
    pub registration_digest: String,
    pub proposal_digest: String,
    pub object: DeploymentIdentity,
    pub expected_resource_version: String,
    pub expected_generation: u64,
    pub status: DryRunStatus,
    pub response_digest: Option<String>,
    pub generated_fields_digest: Option<String>,
    pub request_id: Option<String>,
    pub desired_image_digests: BTreeMap<String, String>,
    pub idempotency_fingerprint: String,
    pub provenance: EvidenceProvenance,
    pub dry_run_is_not_write_receipt: bool,
    pub write_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub evidence_digest: String,
}

impl DryRunEvidence {
    fn from_transport(
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        proposal: &DryRunProposal,
        transport: DryRunTransportEvidence,
        provenance: EvidenceProvenance,
    ) -> Result<Self, KubernetesProviderError> {
        transport.validate()?;
        let mut evidence = Self {
            evidence_version: "kubernetes-rollout-dry-run-evidence/v1".into(),
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            object: proposal.object.clone(),
            expected_resource_version: proposal.expected_resource_version.clone(),
            expected_generation: proposal.expected_generation,
            status: transport.status,
            response_digest: transport.response_digest,
            generated_fields_digest: transport.generated_fields_digest,
            request_id: transport.request_id,
            desired_image_digests: proposal.desired_image_digests.clone(),
            idempotency_fingerprint: proposal.idempotency_fingerprint.clone(),
            provenance,
            dry_run_is_not_write_receipt: true,
            write_receipt: false,
            connected: false,
            native: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), KubernetesRolloutError> {
        if self.evidence_version != "kubernetes-rollout-dry-run-evidence/v1"
            || !valid_sha256_digest(&self.scope_digest)
            || !valid_sha256_digest(&self.registration_digest)
            || !valid_sha256_digest(&self.proposal_digest)
            || self.object.validate().is_err()
            || !valid_identifier(&self.expected_resource_version, 128)
            || self.expected_generation == 0
            || !crate::valid_digest_map(&self.desired_image_digests)
            || !valid_sha256_digest(&self.idempotency_fingerprint)
            || self
                .response_digest
                .as_deref()
                .is_some_and(|value| !valid_sha256_digest(value))
            || self
                .generated_fields_digest
                .as_deref()
                .is_some_and(|value| !valid_sha256_digest(value))
            || self
                .request_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, 256))
            || !self.dry_run_is_not_write_receipt
            || self.write_receipt
            || self.connected
            || self.native
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.evidence_digest != self.compute_digest()
        {
            return Err(KubernetesRolloutError::TamperedReceipt);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            evidence_version: &'a str,
            scope_digest: &'a str,
            registration_digest: &'a str,
            proposal_digest: &'a str,
            object: &'a DeploymentIdentity,
            expected_resource_version: &'a str,
            expected_generation: u64,
            status: DryRunStatus,
            response_digest: &'a Option<String>,
            generated_fields_digest: &'a Option<String>,
            request_id: &'a Option<String>,
            desired_image_digests: &'a BTreeMap<String, String>,
            idempotency_fingerprint: &'a str,
            provenance: EvidenceProvenance,
            dry_run_is_not_write_receipt: bool,
            write_receipt: bool,
        }
        digest_json(&Material {
            evidence_version: &self.evidence_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            proposal_digest: &self.proposal_digest,
            object: &self.object,
            expected_resource_version: &self.expected_resource_version,
            expected_generation: self.expected_generation,
            status: self.status,
            response_digest: &self.response_digest,
            generated_fields_digest: &self.generated_fields_digest,
            request_id: &self.request_id,
            desired_image_digests: &self.desired_image_digests,
            idempotency_fingerprint: &self.idempotency_fingerprint,
            provenance: self.provenance,
            dry_run_is_not_write_receipt: self.dry_run_is_not_write_receipt,
            write_receipt: self.write_receipt,
        })
    }
}

pub trait KubernetesApiTransport: fmt::Debug {
    fn provenance(&self) -> EvidenceProvenance;

    fn describe(
        &mut self,
        scope: &KubernetesRolloutScope,
        auth_reference: &SecretReference,
    ) -> Result<ClusterDescription, KubernetesApiError>;

    fn read_rollout(
        &mut self,
        request: &RolloutReadRequest,
        auth_reference: &SecretReference,
    ) -> Result<DeploymentSnapshot, KubernetesApiError>;

    fn dry_run(
        &mut self,
        request: &DryRunTransportRequest,
        auth_reference: &SecretReference,
    ) -> Result<DryRunTransportEvidence, KubernetesApiError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DryRunTransportRequest {
    pub scope_digest: String,
    pub registration_digest: String,
    pub api_server: ApiServerEndpoint,
    pub object: DeploymentIdentity,
    pub expected_resource_version: String,
    pub expected_generation: u64,
    pub field_manager: String,
    pub proposal_digest: String,
    pub dry_run_parameter: String,
    pub desired_image_digests: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedRequestKind {
    Describe,
    ReadRollout,
    DryRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    pub kind: RecordedRequestKind,
    pub scope_digest: String,
    pub auth_reference_digest: String,
    pub proposal_or_request_digest: String,
}

#[derive(Clone, Debug)]
pub struct BlockedEnvTransport;

impl Default for BlockedEnvTransport {
    fn default() -> Self {
        Self
    }
}

impl KubernetesApiTransport for BlockedEnvTransport {
    fn provenance(&self) -> EvidenceProvenance {
        EvidenceProvenance::BlockedEnv
    }

    fn describe(
        &mut self,
        _scope: &KubernetesRolloutScope,
        _auth_reference: &SecretReference,
    ) -> Result<ClusterDescription, KubernetesApiError> {
        Err(KubernetesApiError::blocked("describe_rollout"))
    }

    fn read_rollout(
        &mut self,
        _request: &RolloutReadRequest,
        _auth_reference: &SecretReference,
    ) -> Result<DeploymentSnapshot, KubernetesApiError> {
        Err(KubernetesApiError::blocked("read_rollout_evidence"))
    }

    fn dry_run(
        &mut self,
        _request: &DryRunTransportRequest,
        _auth_reference: &SecretReference,
    ) -> Result<DryRunTransportEvidence, KubernetesApiError> {
        Ok(DryRunTransportEvidence::blocked())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: EvidenceProvenance,
    description: Option<Result<ClusterDescription, KubernetesApiError>>,
    reads: VecDeque<Result<DeploymentSnapshot, KubernetesApiError>>,
    dry_runs: VecDeque<Result<DryRunTransportEvidence, KubernetesApiError>>,
    requests: Vec<RecordedRequest>,
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::recording()
    }
}

impl RecordingTransport {
    pub fn new(provenance: EvidenceProvenance) -> Self {
        Self {
            provenance,
            description: None,
            reads: VecDeque::new(),
            dry_runs: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn recording() -> Self {
        Self::new(EvidenceProvenance::Recording)
    }

    pub fn fixture() -> Self {
        Self::new(EvidenceProvenance::Fixture)
    }

    pub fn loopback() -> Self {
        Self::new(EvidenceProvenance::Loopback)
    }

    pub fn set_description(&mut self, result: Result<ClusterDescription, KubernetesApiError>) {
        self.description = Some(result);
    }

    pub fn push_read(&mut self, result: Result<DeploymentSnapshot, KubernetesApiError>) {
        self.reads.push_back(result);
    }

    pub fn push_dry_run(&mut self, result: Result<DryRunTransportEvidence, KubernetesApiError>) {
        self.dry_runs.push_back(result);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn record(
        &mut self,
        kind: RecordedRequestKind,
        scope_digest: &str,
        auth: &SecretReference,
        material: &impl serde::Serialize,
    ) {
        self.requests.push(RecordedRequest {
            kind,
            scope_digest: scope_digest.into(),
            auth_reference_digest: auth.reference_digest().into(),
            proposal_or_request_digest: crate::digest_json(material),
        });
    }
}

impl KubernetesApiTransport for RecordingTransport {
    fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }

    fn describe(
        &mut self,
        scope: &KubernetesRolloutScope,
        auth_reference: &SecretReference,
    ) -> Result<ClusterDescription, KubernetesApiError> {
        self.record(
            RecordedRequestKind::Describe,
            &scope.digest(),
            auth_reference,
            &scope.digest(),
        );
        self.description
            .take()
            .unwrap_or_else(|| Err(KubernetesApiError::blocked("recording describe")))
    }

    fn read_rollout(
        &mut self,
        request: &RolloutReadRequest,
        auth_reference: &SecretReference,
    ) -> Result<DeploymentSnapshot, KubernetesApiError> {
        self.record(
            RecordedRequestKind::ReadRollout,
            &request.scope_digest,
            auth_reference,
            request,
        );
        self.reads
            .pop_front()
            .unwrap_or_else(|| Err(KubernetesApiError::blocked("recording read")))
    }

    fn dry_run(
        &mut self,
        request: &DryRunTransportRequest,
        auth_reference: &SecretReference,
    ) -> Result<DryRunTransportEvidence, KubernetesApiError> {
        self.record(
            RecordedRequestKind::DryRun,
            &request.scope_digest,
            auth_reference,
            request,
        );
        self.dry_runs
            .pop_front()
            .unwrap_or_else(|| Ok(DryRunTransportEvidence::blocked()))
    }
}

#[derive(Debug)]
pub struct KubernetesApiRolloutProvider<T = BlockedEnvTransport> {
    transport: T,
    api_revision: String,
}

impl<T> KubernetesApiRolloutProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            api_revision: KUBERNETES_API_REVISION.into(),
        }
    }

    #[must_use]
    pub fn with_api_revision(mut self, api_revision: impl Into<String>) -> Self {
        self.api_revision = api_revision.into();
        self
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl KubernetesApiRolloutProvider<BlockedEnvTransport> {
    pub fn blocked_env() -> Self {
        Self::new(BlockedEnvTransport)
    }
}

impl Default for KubernetesApiRolloutProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::blocked_env()
    }
}

impl<T> KubernetesApiRolloutProvider<T> {
    pub fn definition() -> crate::KubernetesRolloutProviderDefinition {
        crate::KubernetesRolloutProviderDefinition {
            provider_id: PROVIDER_ID.into(),
            kubernetes_api_revision: KUBERNETES_API_REVISION.into(),
            transport: "typed_https_api_seam".into(),
            native_connected_claim: false,
        }
    }
}

pub trait KubernetesRolloutProvider: fmt::Debug {
    fn provenance(&self) -> EvidenceProvenance;

    fn describe_rollout(
        &mut self,
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        auth_reference: &SecretReference,
    ) -> Result<ClusterDescription, KubernetesProviderError>;

    fn read_rollout_evidence(
        &mut self,
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        auth_reference: &SecretReference,
        request: &RolloutReadRequest,
    ) -> Result<ProviderReadResponse, KubernetesProviderError>;

    fn dry_run(
        &mut self,
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        auth_reference: &SecretReference,
        proposal: &DryRunProposal,
    ) -> Result<ProviderDryRunResponse, KubernetesProviderError>;
}

impl<T: KubernetesApiTransport> KubernetesApiRolloutProvider<T> {
    fn ensure_bound(
        &self,
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        auth_reference: &SecretReference,
    ) -> Result<(), KubernetesProviderError> {
        if self.api_revision != KUBERNETES_API_REVISION {
            return Err(KubernetesProviderError::ApiRevisionMismatch);
        }
        registration
            .validate(scope)
            .map_err(|_| KubernetesProviderError::RegistrationDrift)?;
        auth_reference
            .validate_for_scope(&scope.digest())
            .map_err(|_| KubernetesProviderError::AuthScopeMismatch)
    }
}

impl<T: KubernetesApiTransport> KubernetesRolloutProvider for KubernetesApiRolloutProvider<T> {
    fn provenance(&self) -> EvidenceProvenance {
        self.transport.provenance()
    }

    fn describe_rollout(
        &mut self,
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        auth_reference: &SecretReference,
    ) -> Result<ClusterDescription, KubernetesProviderError> {
        self.ensure_bound(scope, registration, auth_reference)?;
        let description = self.transport.describe(scope, auth_reference)?;
        if description.provenance != self.provenance()
            || description.connected
            || description.native
            || self.provenance().is_connected()
            || self.provenance().is_native()
        {
            return Err(KubernetesProviderError::TrustOrProvenanceMismatch);
        }
        Ok(description)
    }

    fn read_rollout_evidence(
        &mut self,
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        auth_reference: &SecretReference,
        request: &RolloutReadRequest,
    ) -> Result<ProviderReadResponse, KubernetesProviderError> {
        self.ensure_bound(scope, registration, auth_reference)?;
        request
            .validate_against(scope)
            .map_err(|error| KubernetesProviderError::Evidence(error.to_string()))?;
        let snapshot = self.transport.read_rollout(request, auth_reference)?;
        snapshot
            .validate()
            .map_err(|error| KubernetesProviderError::Evidence(error.to_string()))?;
        Ok(ProviderReadResponse {
            snapshot,
            provenance: self.provenance(),
        })
    }

    fn dry_run(
        &mut self,
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        auth_reference: &SecretReference,
        proposal: &DryRunProposal,
    ) -> Result<ProviderDryRunResponse, KubernetesProviderError> {
        self.ensure_bound(scope, registration, auth_reference)?;
        proposal
            .validate()
            .map_err(|error| KubernetesProviderError::Evidence(error.to_string()))?;
        let request = DryRunTransportRequest {
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
            api_server: scope.api_server.clone(),
            object: proposal.object.clone(),
            expected_resource_version: proposal.expected_resource_version.clone(),
            expected_generation: proposal.expected_generation,
            field_manager: scope.field_manager.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            dry_run_parameter: "All".into(),
            desired_image_digests: proposal.desired_image_digests.clone(),
        };
        let transport = self.transport.dry_run(&request, auth_reference)?;
        let evidence = DryRunEvidence::from_transport(
            scope,
            registration,
            proposal,
            transport,
            self.provenance(),
        )?;
        Ok(ProviderDryRunResponse { evidence })
    }
}

impl From<ModelError> for KubernetesProviderError {
    fn from(error: ModelError) -> Self {
        Self::Evidence(error.to_string())
    }
}
