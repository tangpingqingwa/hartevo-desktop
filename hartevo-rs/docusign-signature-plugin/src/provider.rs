use std::{collections::BTreeSet, fmt};

use hartevo_connector_sdk::SecretReference;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DOCUSIGN_PROVIDER_ID, Digest, DocuSignPluginRegistration, DocuSignReceipt, DocuSignScope,
    EnvelopeProposal, ModelError, NativeOperation, NonConnectedEvidence, ProviderProvenance,
    ProviderVersion, RecordedEnvelopeObservation,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocuSignHttpRequest {
    operation: NativeOperation,
    method: HttpMethod,
    path: String,
    request_digest: Digest,
}

impl DocuSignHttpRequest {
    pub(crate) fn for_operation(operation: NativeOperation, request_digest: Digest) -> Self {
        let (method, path) = match operation {
            NativeOperation::EnvelopeCreate => (HttpMethod::Post, "/v2.1/envelopes"),
            NativeOperation::EnvelopeSend => (HttpMethod::Post, "/v2.1/envelopes/{id}"),
            NativeOperation::SigningCeremony => (HttpMethod::Get, "/v2.1/envelopes/{id}/views"),
            NativeOperation::EnvelopeIdAndUrlReceipt => (HttpMethod::Get, "/v2.1/envelopes/{id}"),
            NativeOperation::BoundedStatusReconciliation => {
                (HttpMethod::Get, "/v2.1/envelopes/{id}")
            }
            NativeOperation::IndependentDocumentReadback => {
                (HttpMethod::Get, "/v2.1/envelopes/{id}/documents")
            }
            NativeOperation::ConnectVerification => (HttpMethod::Post, "/connect"),
            NativeOperation::AmbiguousCreateRecovery => (HttpMethod::Get, "/v2.1/envelopes"),
        };
        Self {
            operation,
            method,
            path: path.to_owned(),
            request_digest,
        }
    }

    pub const fn operation(&self) -> NativeOperation {
        self.operation
    }

    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocuSignHttpResponse {
    status_code: u16,
    response_digest: Digest,
}

impl DocuSignHttpResponse {
    pub fn new(status_code: u16, response_digest: Digest) -> Self {
        Self {
            status_code,
            response_digest,
        }
    }

    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DocuSignTransportError {
    #[error("Layer-2 DocuSign operation is intentionally unavailable in Layer 1: {0:?}")]
    Layer2Gap(NativeOperation),
    #[error("DocuSign native transport is blocked by {0}")]
    BlockedEnv(String),
    #[error("DocuSign credentials are unavailable")]
    MissingCredentials,
    #[error("DocuSign account scope does not match")]
    AccountMismatch,
    #[error("DocuSign provider returned an unsupported status")]
    UnsupportedStatus,
    #[error("DocuSign provider rate-limited the request")]
    RateLimited,
    #[error("DocuSign provider request timed out")]
    Timeout,
    #[error("DocuSign provider is eventually consistent")]
    EventualConsistency,
}

impl DocuSignTransportError {
    pub fn non_connected_evidence(&self) -> NonConnectedEvidence {
        match self {
            Self::Layer2Gap(operation) => NonConnectedEvidence::NativeLayer2Gap {
                operation: *operation,
            },
            Self::BlockedEnv(_) => NonConnectedEvidence::BlockedEnv,
            Self::MissingCredentials => NonConnectedEvidence::MissingCredentials,
            Self::AccountMismatch => NonConnectedEvidence::AccountMismatch,
            Self::UnsupportedStatus => NonConnectedEvidence::UnsupportedStatus,
            Self::RateLimited => NonConnectedEvidence::RateLimited {
                retry_after_seconds: 0,
            },
            Self::Timeout => NonConnectedEvidence::Timeout,
            Self::EventualConsistency => NonConnectedEvidence::EventualConsistency {
                retry_after_seconds: 0,
            },
        }
    }
}

/// HTTPS/OAuth 2.0 seam for the future native provider.
///
/// The Layer-1 service never calls this method. A transport receives only the
/// opaque Connector SDK SecretReference, never access or refresh token bytes.
pub trait DocuSignTransport {
    fn provenance(&self) -> ProviderProvenance;

    fn execute(
        &mut self,
        request: &DocuSignHttpRequest,
        secret_reference: &SecretReference,
    ) -> Result<DocuSignHttpResponse, DocuSignTransportError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FixtureDocuSignTransport;

impl DocuSignTransport for FixtureDocuSignTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &DocuSignHttpRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DocuSignHttpResponse, DocuSignTransportError> {
        Err(DocuSignTransportError::Layer2Gap(request.operation()))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackDocuSignTransport;

impl DocuSignTransport for LoopbackDocuSignTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &DocuSignHttpRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DocuSignHttpResponse, DocuSignTransportError> {
        Err(DocuSignTransportError::Layer2Gap(request.operation()))
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvDocuSignTransport {
    environment_variable: String,
}

impl BlockedEnvDocuSignTransport {
    pub fn new(environment_variable: impl Into<String>) -> Self {
        Self {
            environment_variable: environment_variable.into(),
        }
    }

    pub fn environment_variable(&self) -> &str {
        &self.environment_variable
    }
}

impl DocuSignTransport for BlockedEnvDocuSignTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &DocuSignHttpRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DocuSignHttpResponse, DocuSignTransportError> {
        Err(DocuSignTransportError::BlockedEnv(
            self.environment_variable.clone(),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct NativeOptInDocuSignTransport {
    environment_variable: String,
    enabled: bool,
}

impl NativeOptInDocuSignTransport {
    pub fn from_env(environment_variable: impl Into<String>) -> Self {
        let environment_variable = environment_variable.into();
        let enabled = std::env::var(&environment_variable)
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        Self {
            environment_variable,
            enabled,
        }
    }

    pub fn new(environment_variable: impl Into<String>, enabled: bool) -> Self {
        Self {
            environment_variable: environment_variable.into(),
            enabled,
        }
    }

    pub fn environment_variable(&self) -> &str {
        &self.environment_variable
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

impl DocuSignTransport for NativeOptInDocuSignTransport {
    fn provenance(&self) -> ProviderProvenance {
        if self.enabled {
            ProviderProvenance::NativeLayer2Gap {
                operation: NativeOperation::EnvelopeCreate,
            }
        } else {
            ProviderProvenance::BlockedEnv
        }
    }

    fn execute(
        &mut self,
        request: &DocuSignHttpRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DocuSignHttpResponse, DocuSignTransportError> {
        if self.enabled {
            Err(DocuSignTransportError::Layer2Gap(request.operation()))
        } else {
            Err(DocuSignTransportError::BlockedEnv(
                self.environment_variable.clone(),
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ProviderError {
    #[error("DocuSign provider version is invalid")]
    InvalidProviderVersion,
    #[error("DocuSign provider registration digest is invalid")]
    InvalidRegistration,
    #[error("DocuSign SecretReference does not match account/project/provider scope")]
    SecretScopeMismatch,
    #[error("DocuSign proposal does not match provider scope")]
    ScopeMismatch,
    #[error("DocuSign proposal does not match provider version or registration digest")]
    RegistrationMismatch,
    #[error("DocuSign receipt fingerprint was already recorded")]
    DuplicateFingerprint,
    #[error("DocuSign observation does not match the proposal")]
    ObservationMismatch,
    #[error("DocuSign model rejected the recording: {0}")]
    Model(#[from] ModelError),
    #[error("Layer-2 operation remains unavailable in Layer 1: {0:?}")]
    Layer2Gap(NativeOperation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAvailability {
    provenance: ProviderProvenance,
    evidence: NonConnectedEvidence,
}

impl ProviderAvailability {
    pub fn from_evidence(provenance: ProviderProvenance, evidence: NonConnectedEvidence) -> Self {
        Self {
            provenance,
            evidence,
        }
    }

    pub fn provenance(&self) -> &ProviderProvenance {
        &self.provenance
    }

    pub const fn evidence(&self) -> NonConnectedEvidence {
        self.evidence
    }

    pub const fn claims_connected(&self) -> bool {
        false
    }

    pub const fn claims_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PollPlan {
    max_attempts: u8,
    initial_delay_seconds: u64,
    max_delay_seconds: u64,
}

impl PollPlan {
    pub fn new(
        max_attempts: u8,
        initial_delay_seconds: u64,
        max_delay_seconds: u64,
    ) -> Result<Self, PollPlanError> {
        if max_attempts == 0
            || max_attempts > 12
            || initial_delay_seconds == 0
            || max_delay_seconds < initial_delay_seconds
            || max_delay_seconds > 3_600
        {
            return Err(PollPlanError::Invalid);
        }
        Ok(Self {
            max_attempts,
            initial_delay_seconds,
            max_delay_seconds,
        })
    }

    pub const fn max_attempts(&self) -> u8 {
        self.max_attempts
    }

    pub fn delay_seconds(&self, attempt: u8) -> u64 {
        let shift = if attempt > 63 { 63 } else { attempt };
        let multiplier = 1_u64 << shift;
        let delay = self.initial_delay_seconds.saturating_mul(multiplier);
        if delay > self.max_delay_seconds {
            self.max_delay_seconds
        } else {
            delay
        }
    }

    pub fn delays(&self) -> Vec<u64> {
        (0..self.max_attempts)
            .map(|attempt| self.delay_seconds(attempt))
            .collect()
    }
}

impl Default for PollPlan {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay_seconds: 2,
            max_delay_seconds: 60,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum PollPlanError {
    #[error("poll plan must be bounded, positive, and no slower than one hour")]
    Invalid,
}

/// Concrete typed DocuSign provider. It records supplied observations only.
pub struct DocuSignSignatureProvider<T> {
    scope: DocuSignScope,
    provider_version: ProviderVersion,
    registration_digest: Digest,
    secret_reference: SecretReference,
    transport: T,
    recorded_fingerprints: BTreeSet<Digest>,
}

impl<T> fmt::Debug for DocuSignSignatureProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocuSignSignatureProvider")
            .field("scope_digest", &self.scope.digest())
            .field("provider_id", &DOCUSIGN_PROVIDER_ID)
            .field("provider_version", &self.provider_version)
            .field("registration_digest", &self.registration_digest)
            .field(
                "recorded_fingerprint_count",
                &self.recorded_fingerprints.len(),
            )
            .finish_non_exhaustive()
    }
}

impl<T: DocuSignTransport> DocuSignSignatureProvider<T> {
    pub fn new(
        scope: DocuSignScope,
        provider_version: ProviderVersion,
        registration_digest: Digest,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderError> {
        scope.validate().map_err(ProviderError::from)?;
        provider_version
            .validate()
            .map_err(|_| ProviderError::InvalidProviderVersion)?;
        if !registration_digest.is_valid() {
            return Err(ProviderError::InvalidRegistration);
        }
        if !scope.matches_secret(&secret_reference) {
            return Err(ProviderError::SecretScopeMismatch);
        }
        Ok(Self {
            scope,
            provider_version,
            registration_digest,
            secret_reference,
            transport,
            recorded_fingerprints: BTreeSet::new(),
        })
    }

    pub fn from_registration(
        registration: &DocuSignPluginRegistration,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderError> {
        Self::new(
            registration.scope().clone(),
            registration.version(),
            registration.registration_digest().clone(),
            secret_reference,
            transport,
        )
    }

    pub fn scope(&self) -> &DocuSignScope {
        &self.scope
    }

    pub const fn provider_version(&self) -> ProviderVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn availability(&self) -> ProviderAvailability {
        let provenance = self.transport.provenance();
        let evidence = match &provenance {
            ProviderProvenance::Fixture => NonConnectedEvidence::Fixture,
            ProviderProvenance::Loopback => NonConnectedEvidence::Loopback,
            ProviderProvenance::BlockedEnv => NonConnectedEvidence::BlockedEnv,
            ProviderProvenance::NativeLayer2Gap { operation } => {
                NonConnectedEvidence::NativeLayer2Gap {
                    operation: *operation,
                }
            }
        };
        ProviderAvailability::from_evidence(provenance, evidence)
    }

    pub fn availability_for_evidence(
        &self,
        evidence: NonConnectedEvidence,
    ) -> ProviderAvailability {
        ProviderAvailability::from_evidence(self.transport.provenance(), evidence)
    }

    pub fn record_receipt(
        &mut self,
        proposal: &EnvelopeProposal,
        observation: &RecordedEnvelopeObservation,
    ) -> Result<DocuSignReceipt, ProviderError> {
        if proposal.scope() != &self.scope {
            return Err(ProviderError::ScopeMismatch);
        }
        if proposal.provider_version() != self.provider_version
            || proposal.registration_digest() != &self.registration_digest
        {
            return Err(ProviderError::RegistrationMismatch);
        }
        if observation.scope() != &self.scope
            || observation.proposal_fingerprint() != proposal.fingerprint()
            || observation.revision_fence() != proposal.revision_fence()
            || observation.provider_version() != self.provider_version
            || observation.registration_digest() != &self.registration_digest
        {
            return Err(ProviderError::ObservationMismatch);
        }
        let receipt =
            DocuSignReceipt::from_projection(proposal, observation).map_err(ProviderError::from)?;
        if !self
            .recorded_fingerprints
            .insert(proposal.fingerprint().clone())
        {
            return Err(ProviderError::DuplicateFingerprint);
        }
        Ok(receipt)
    }

    pub fn prepare_layer2_request(
        &self,
        operation: NativeOperation,
        request_digest: Digest,
    ) -> DocuSignHttpRequest {
        DocuSignHttpRequest::for_operation(operation, request_digest)
    }

    /// Explicitly fails closed. The transport is a Layer-2 seam and is not
    /// invoked by Layer 1, including when native opt-in is enabled.
    pub fn execute_layer2(
        &mut self,
        request: &DocuSignHttpRequest,
    ) -> Result<DocuSignHttpResponse, ProviderError> {
        Err(ProviderError::Layer2Gap(request.operation()))
    }

    pub fn recorded_fingerprint_count(&self) -> usize {
        self.recorded_fingerprints.len()
    }
}

pub trait SignatureProvider {
    fn scope(&self) -> &DocuSignScope;
    fn provider_version(&self) -> ProviderVersion;
    fn registration_digest(&self) -> &Digest;
    fn record_receipt(
        &mut self,
        proposal: &EnvelopeProposal,
        observation: &RecordedEnvelopeObservation,
    ) -> Result<DocuSignReceipt, ProviderError>;
    fn availability(&self) -> ProviderAvailability;
    fn poll_plan(&self) -> PollPlan;
    fn prepare_layer2_request(
        &self,
        operation: NativeOperation,
        request_digest: Digest,
    ) -> DocuSignHttpRequest;
}

impl<T: DocuSignTransport> SignatureProvider for DocuSignSignatureProvider<T> {
    fn scope(&self) -> &DocuSignScope {
        self.scope()
    }

    fn provider_version(&self) -> ProviderVersion {
        self.provider_version()
    }

    fn registration_digest(&self) -> &Digest {
        self.registration_digest()
    }

    fn record_receipt(
        &mut self,
        proposal: &EnvelopeProposal,
        observation: &RecordedEnvelopeObservation,
    ) -> Result<DocuSignReceipt, ProviderError> {
        self.record_receipt(proposal, observation)
    }

    fn availability(&self) -> ProviderAvailability {
        self.availability()
    }

    fn poll_plan(&self) -> PollPlan {
        PollPlan::default()
    }

    fn prepare_layer2_request(
        &self,
        operation: NativeOperation,
        request_digest: Digest,
    ) -> DocuSignHttpRequest {
        self.prepare_layer2_request(operation, request_digest)
    }
}
