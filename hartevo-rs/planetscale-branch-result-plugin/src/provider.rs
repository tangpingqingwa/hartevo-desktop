use std::{collections::BTreeMap, fmt};

use crate::{
    BranchResultEvidence, BranchResultProposal, BranchResultReceipt, BranchResultRecord, Digest,
    EvidenceSource, MAX_RESPONSE_BYTES, NativeStatus, PageCursor, PlanetScaleProviderManifest,
    PlanetScaleRegistration, PlanetScaleScope, PostureObservation, PostureRead, PostureRequest,
    RegistrationReceipt, SecretReference, TransportMode, VerificationResult,
    error::{PlanetScaleBranchResultError, PlanetScaleProviderError},
};

/// A transport response whose optional body remains provider-private. The
/// public representation exposes only status, a bounded typed observation, and
/// a body digest through Debug; it cannot serialize raw API payloads.
#[derive(Clone, Eq, PartialEq)]
pub struct PostureResponse {
    status_code: u16,
    body_digest: Digest,
    body_bytes: usize,
    observation: Option<PostureObservation>,
    source: EvidenceSource,
}

impl fmt::Debug for PostureResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostureResponse")
            .field("status_code", &self.status_code)
            .field("body_digest", &self.body_digest)
            .field("body_bytes", &self.body_bytes)
            .field("has_observation", &self.observation.is_some())
            .field("source", &self.source)
            .finish()
    }
}

impl PostureResponse {
    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics only if the typed observation cannot be serialized. Contract
    /// observations use only serializable bounded fields.
    pub fn from_observation(observation: PostureObservation) -> Self {
        let body = serde_json::to_vec(&observation).expect("PlanetScale fixture serializes");
        let source = observation.source;
        Self {
            status_code: 200,
            body_digest: crate::sha256_digest(&body),
            body_bytes: body.len(),
            observation: Some(observation),
            source,
        }
    }

    #[must_use]
    pub fn status(status_code: u16, source: EvidenceSource) -> Self {
        Self {
            status_code,
            body_digest: crate::sha256_digest(&[]),
            body_bytes: 0,
            observation: None,
            source,
        }
    }

    /// Build an adversarial response. The supplied body is immediately
    /// reduced to a digest and byte count, so raw fixture payloads are not
    /// retained by the provider seam.
    #[must_use]
    pub fn new(
        status_code: u16,
        body: impl AsRef<[u8]>,
        observation: Option<PostureObservation>,
        source: EvidenceSource,
    ) -> Self {
        let body = body.as_ref();
        Self {
            status_code,
            body_digest: crate::sha256_digest(body),
            body_bytes: body.len(),
            observation,
            source,
        }
    }

    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    #[must_use]
    pub const fn body_bytes(&self) -> usize {
        self.body_bytes
    }

    #[must_use]
    pub fn body_digest(&self) -> Digest {
        self.body_digest.clone()
    }

    fn observation(&self) -> Option<&PostureObservation> {
        self.observation.as_ref()
    }

    fn source(&self) -> EvidenceSource {
        self.source
    }
}

/// Layer 1 transport seam. Implementations may replay bounded fixtures, but
/// this crate never provides a native HTTPS/API implementation.
pub trait PlanetScaleTransport: fmt::Debug {
    fn mode(&self) -> TransportMode;

    fn read(
        &mut self,
        request: &PostureRequest,
    ) -> Result<PostureResponse, PlanetScaleProviderError>;
}

#[derive(Clone, Debug)]
pub struct FixturePlanetScaleTransport {
    response: PostureResponse,
}

impl FixturePlanetScaleTransport {
    #[must_use]
    pub fn new(response: PostureResponse) -> Self {
        Self { response }
    }
}

impl PlanetScaleTransport for FixturePlanetScaleTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Fixture
    }

    fn read(
        &mut self,
        _request: &PostureRequest,
    ) -> Result<PostureResponse, PlanetScaleProviderError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingPlanetScaleTransport {
    response: PostureResponse,
    requests: Vec<PostureRequest>,
    fault: Option<PlanetScaleProviderError>,
}

impl RecordingPlanetScaleTransport {
    #[must_use]
    pub fn new(response: PostureResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
            fault: None,
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[PostureRequest] {
        &self.requests
    }

    pub fn set_response(&mut self, response: PostureResponse) {
        self.response = response;
    }

    pub fn set_fault(&mut self, fault: PlanetScaleProviderError) {
        self.fault = Some(fault);
    }

    pub fn clear_fault(&mut self) {
        self.fault = None;
    }
}

impl PlanetScaleTransport for RecordingPlanetScaleTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Recording
    }

    fn read(
        &mut self,
        request: &PostureRequest,
    ) -> Result<PostureResponse, PlanetScaleProviderError> {
        self.requests.push(request.clone());
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakePlanetScaleTransport {
    response: PostureResponse,
    requests: Vec<PostureRequest>,
}

impl FakePlanetScaleTransport {
    #[must_use]
    pub fn new(response: PostureResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[PostureRequest] {
        &self.requests
    }
}

impl PlanetScaleTransport for FakePlanetScaleTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Fake
    }

    fn read(
        &mut self,
        request: &PostureRequest,
    ) -> Result<PostureResponse, PlanetScaleProviderError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackPlanetScaleTransport {
    response: PostureResponse,
    requests: Vec<PostureRequest>,
}

impl LoopbackPlanetScaleTransport {
    #[must_use]
    pub fn new(response: PostureResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[PostureRequest] {
        &self.requests
    }
}

impl PlanetScaleTransport for LoopbackPlanetScaleTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Loopback
    }

    fn read(
        &mut self,
        request: &PostureRequest,
    ) -> Result<PostureResponse, PlanetScaleProviderError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvPlanetScaleTransport;

impl PlanetScaleTransport for BlockedEnvPlanetScaleTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &PostureRequest,
    ) -> Result<PostureResponse, PlanetScaleProviderError> {
        Err(PlanetScaleProviderError::BlockedEnv)
    }
}

/// Typed PlanetScale provider. The provider owns only an opaque reference and
/// a replaceable non-native transport; its record map is in-memory and
/// digest-bound for deterministic Layer 1 replay.
pub struct PlanetScaleProvider<T: PlanetScaleTransport> {
    manifest: PlanetScaleProviderManifest,
    registration: PlanetScaleRegistration,
    transport: T,
    receipts: BTreeMap<Digest, BranchResultReceipt>,
}

impl<T: PlanetScaleTransport> fmt::Debug for PlanetScaleProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanetScaleProvider")
            .field("manifest", &self.manifest)
            .field("registration", &self.registration)
            .field("transport_mode", &self.transport.mode())
            .field("receipt_count", &self.receipts.len())
            .finish()
    }
}

impl<T: PlanetScaleTransport> PlanetScaleProvider<T> {
    pub fn new(
        scope: PlanetScaleScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        let manifest = PlanetScaleProviderManifest::layer1(scope.clone(), transport.mode())?;
        let registration =
            PlanetScaleRegistration::new(manifest.clone(), scope, secret_reference, 1)?;
        Ok(Self {
            manifest,
            registration,
            transport,
            receipts: BTreeMap::new(),
        })
    }

    pub fn with_registration(
        registration: PlanetScaleRegistration,
        transport: T,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        registration.validate()?;
        if registration.manifest.transport_mode != transport.mode() {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "transport_mode",
            });
        }
        Ok(Self {
            manifest: registration.manifest.clone(),
            registration,
            transport,
            receipts: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &PlanetScaleProviderManifest {
        &self.manifest
    }

    #[must_use]
    pub fn registration(&self) -> &PlanetScaleRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut PlanetScaleRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &PlanetScaleScope {
        &self.registration.scope
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn transport_mode(&self) -> TransportMode {
        self.transport.mode()
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> Digest {
        self.registration.secret_reference_digest()
    }

    pub fn build_request(
        &self,
        read: PostureRead,
        page_size: u16,
        cursor: Option<&PageCursor>,
        idempotency_key: &crate::IdempotencyKey,
    ) -> Result<PostureRequest, PlanetScaleBranchResultError> {
        self.ensure_active()?;
        PostureRequest::new(
            self.scope().clone(),
            read,
            page_size,
            cursor,
            idempotency_key,
            &self.registration_secret_reference(),
            self.manifest.digest(),
        )
    }

    pub fn read_posture(
        &mut self,
        request: &PostureRequest,
    ) -> Result<PostureObservation, PlanetScaleProviderError> {
        self.ensure_provider()
            .map_err(|_| PlanetScaleProviderError::ManifestMismatch)?;
        if self.registration.revoked {
            return Err(PlanetScaleProviderError::RegistrationRevoked);
        }
        request
            .validate()
            .map_err(|_| PlanetScaleProviderError::InvalidRequest)?;
        if request.scope != self.manifest.scope {
            return Err(PlanetScaleProviderError::ScopeMismatch);
        }
        if request.provider_manifest_digest != self.manifest.digest()
            || request.secret_reference_digest != self.secret_reference_digest()
        {
            return Err(PlanetScaleProviderError::ManifestMismatch);
        }
        let response = self.transport.read(request)?;
        if response.body_bytes() > MAX_RESPONSE_BYTES as usize {
            return Err(PlanetScaleProviderError::ResponseTooLarge);
        }
        if !(200..300).contains(&response.status_code()) {
            return Err(provider_error_for_status(response.status_code()));
        }
        let observation =
            response
                .observation()
                .ok_or(PlanetScaleProviderError::InvalidResponse {
                    field: "observation",
                })?;
        observation
            .validate()
            .map_err(|_| PlanetScaleProviderError::InvalidResponse {
                field: "observation",
            })?;
        if observation.scope != request.scope || observation.read != request.read {
            return Err(PlanetScaleProviderError::ScopeMismatch);
        }
        if observation.source != response.source()
            || observation.source != self.transport.mode().evidence_source()
            || observation.native_status.is_native()
            || observation.source.is_native()
        {
            return Err(PlanetScaleProviderError::InvalidResponse {
                field: "evidence_source",
            });
        }
        Ok(observation.clone())
    }

    pub fn record(
        &mut self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
    ) -> Result<BranchResultReceipt, PlanetScaleBranchResultError> {
        self.ensure_active()?;
        proposal.validate()?;
        evidence.validate_against(proposal)?;
        if proposal.scope != self.manifest.scope
            || proposal.provider_manifest_digest != self.manifest.digest()
            || proposal.registration_digest != self.registration.registration_digest
        {
            return Err(PlanetScaleBranchResultError::RegistrationMismatch);
        }
        if let Some(existing) = self.receipts.get(&proposal.idempotency_digest) {
            if existing.proposal_digest == proposal.proposal_digest
                && existing.evidence_digest == evidence.evidence_digest
            {
                return Ok(existing.clone());
            }
            return Err(PlanetScaleBranchResultError::Provider(
                PlanetScaleProviderError::DuplicateIdempotency,
            ));
        }
        let record = BranchResultRecord::from_evidence(proposal, evidence)?;
        let receipt = BranchResultReceipt::from_record(proposal, evidence, &record)?;
        self.receipts
            .insert(proposal.idempotency_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn verify(
        &self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
        receipt: &BranchResultReceipt,
    ) -> Result<VerificationResult, PlanetScaleBranchResultError> {
        self.ensure_provider()?;
        self.registration.ensure_active()?;
        proposal.validate()?;
        evidence.validate_against(proposal)?;
        receipt.validate_against(
            proposal,
            evidence,
            &BranchResultRecord::from_evidence(proposal, evidence)?,
        )?;
        let stored = self
            .receipts
            .get(&proposal.idempotency_digest)
            .ok_or(PlanetScaleBranchResultError::TamperedReceipt)?;
        if stored != receipt {
            return Err(PlanetScaleBranchResultError::TamperedReceipt);
        }
        Ok(VerificationResult {
            verified: true,
            state: receipt.state,
            receipt_digest: receipt.receipt_digest.clone(),
        })
    }

    pub fn registration_receipt(
        &self,
    ) -> Result<RegistrationReceipt, PlanetScaleBranchResultError> {
        RegistrationReceipt::from_registration(&self.registration, 1)
    }

    #[must_use]
    pub const fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    fn registration_secret_reference(&self) -> SecretReference {
        // The opaque reference is cloned only inside the provider boundary;
        // no public response or receipt can serialize it.
        self.registration.secret_reference_clone_for_provider()
    }

    fn ensure_active(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.registration.ensure_active()
    }

    fn ensure_provider(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.manifest.validate()?;
        self.registration.validate()?;
        if self.registration.manifest.digest() != self.manifest.digest()
            || self.transport.mode() != self.manifest.transport_mode
            || self.transport.mode().is_native()
        {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "provider.binding",
            });
        }
        Ok(())
    }
}

fn provider_error_for_status(status: u16) -> PlanetScaleProviderError {
    match status {
        401 | 403 => PlanetScaleProviderError::PermissionDenied,
        404 => PlanetScaleProviderError::NotFound,
        409 | 412 => PlanetScaleProviderError::Conflict,
        408 | 504 => PlanetScaleProviderError::TimedOut,
        429 => PlanetScaleProviderError::RateLimited {
            retry_after_ms: 1_000,
        },
        400..=499 => PlanetScaleProviderError::InvalidResponse {
            field: "provider_status",
        },
        _ => PlanetScaleProviderError::ProviderUnknown,
    }
}

// The secret reference remains private on PlanetScaleRegistration. This
// narrow crate-private helper avoids exposing it through public serialization.
impl PlanetScaleRegistration {
    pub(crate) fn secret_reference_clone_for_provider(&self) -> SecretReference {
        self.secret_reference.clone()
    }
}
