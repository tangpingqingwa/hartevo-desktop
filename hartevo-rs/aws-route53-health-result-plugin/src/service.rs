//! Route 53 health-check service, registration, evidence, and verification.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_ROUTE53_HEALTH_API_REVISION, AWS_ROUTE53_HEALTH_CONTRACT_VERSION,
    AWS_ROUTE53_HEALTH_PLUGIN_VERSION, AWS_ROUTE53_HEALTH_PROVIDER_VERSION, contract_digest,
    model::{
        AwsRoute53HealthEvidence, AwsRoute53HealthReadRequest, AwsRoute53HealthScope, Digest,
        EvidenceState, GetHealthCheckResponse, GetHealthCheckStatusResponse,
        HealthCheckObservation, HealthCheckSummary, ModelError, PartialReason, PermissionFence,
        ProviderErrorEvidence, ProviderId, ProviderRevision, ReadBounds, ReadOperation, Revision,
        SecretReference, TransportProvenance,
    },
    provider::{
        AwsRoute53HealthProvider, AwsRoute53HealthTransport, AwsRoute53ProviderIdentity,
        GetHealthCheckRequest, GetHealthCheckStatusRequest, ListHealthChecksRequest, ProviderError,
        TransportError, TransportFailure, is_access_loss,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("Route 53 registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("Route 53 registration permission fence is incomplete")]
    PermissionFence,
    #[error("Route 53 registration secret region does not match the scope")]
    SecretRegionMismatch,
    #[error("Route 53 registration revision overflow")]
    RevisionOverflow,
    #[error("Route 53 registration is already revoked")]
    AlreadyRevoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsRoute53HealthServiceError {
    #[error("Route 53 service model error: {0}")]
    Model(#[from] ModelError),
    #[error("Route 53 provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("Route 53 registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("Route 53 registration is revoked")]
    RegistrationRevoked,
    #[error("Route 53 registration has drifted")]
    RegistrationDrift,
    #[error("Route 53 scope or permission fence mismatch: {0}")]
    ScopeMismatch(&'static str),
    #[error("Route 53 evidence is stale or tampered")]
    EvidenceTampered,
    #[error("Route 53 proposal is stale or tampered")]
    ProposalTampered,
    #[error("Route 53 record receipt is stale or tampered")]
    RecordTampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub plugin_version: &'static str,
    pub provider_version: &'static str,
    pub api_revision: &'static str,
    pub operations: Vec<&'static str>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_receipt: bool,
    pub calculated_checks_supported: bool,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_observations: u16,
}

impl AwsRoute53HealthCapabilities {
    pub fn baseline() -> Self {
        Self {
            service_id: crate::AWS_ROUTE53_HEALTH_SERVICE_ID,
            provider_id: crate::AWS_ROUTE53_HEALTH_PROVIDER_ID,
            plugin_version: AWS_ROUTE53_HEALTH_PLUGIN_VERSION,
            provider_version: AWS_ROUTE53_HEALTH_PROVIDER_VERSION,
            api_revision: AWS_ROUTE53_HEALTH_API_REVISION,
            operations: vec![
                "ListHealthChecks",
                "GetHealthCheck",
                "GetHealthCheckStatus",
                "register",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            durable_receipt: false,
            calculated_checks_supported: false,
            max_pages: crate::model::MAX_PAGES,
            page_size: crate::model::PAGE_SIZE,
            max_observations: crate::model::MAX_OBSERVATIONS as u16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationEvidence {
    pub previous_registration_digest: Digest,
    pub revocation_revision: Revision,
    pub reason_digest: Digest,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthRegistration {
    pub state: RegistrationState,
    pub plugin_version: String,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub health_check_revision: Revision,
    pub evidence_digest: Digest,
    pub registration_revision: Revision,
    pub revocation: Option<RevocationEvidence>,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody {
    state: RegistrationState,
    plugin_version: String,
    provider_id: ProviderId,
    provider_version: String,
    provider_revision: ProviderRevision,
    provider_digest: Digest,
    api_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    scope_digest: Digest,
    permission_digest: Digest,
    secret_reference_digest: Digest,
    health_check_revision: Revision,
    evidence_digest: Digest,
    registration_revision: Revision,
    revocation: Option<RevocationDigestBody>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RevocationDigestBody {
    previous_registration_digest: Digest,
    revocation_revision: Revision,
    reason_digest: Digest,
}

impl From<&RevocationEvidence> for RevocationDigestBody {
    fn from(value: &RevocationEvidence) -> Self {
        Self {
            previous_registration_digest: value.previous_registration_digest.clone(),
            revocation_revision: value.revocation_revision,
            reason_digest: value.reason_digest.clone(),
        }
    }
}

impl AwsRoute53HealthRegistration {
    pub fn new(
        scope: &AwsRoute53HealthScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsRoute53ProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        if !permission.is_complete_read_only() {
            return Err(RegistrationError::PermissionFence);
        }
        if secret_reference.region() != &scope.region {
            return Err(RegistrationError::SecretRegionMismatch);
        }
        let evidence_digest = Digest::from_parts(
            "hartevo-aws-route53-health-registration-evidence/v1",
            &[
                scope.digest().to_string(),
                permission.digest().to_string(),
                provider.provider_digest.to_string(),
                provider.api_digest.to_string(),
            ],
        );
        let mut registration = Self {
            state: RegistrationState::Active,
            plugin_version: AWS_ROUTE53_HEALTH_PLUGIN_VERSION.to_owned(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            contract_version: AWS_ROUTE53_HEALTH_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope_digest: scope.digest(),
            permission_digest: permission.digest(),
            secret_reference_digest: secret_reference.digest().clone(),
            health_check_revision: scope.health_check.revision,
            evidence_digest,
            registration_revision: Revision::new(1)?,
            revocation: None,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_registration_body(&RegistrationBody {
            state: self.state,
            plugin_version: self.plugin_version.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version.clone(),
            provider_revision: self.provider_revision.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            secret_reference_digest: self.secret_reference_digest.clone(),
            health_check_revision: self.health_check_revision,
            evidence_digest: self.evidence_digest.clone(),
            registration_revision: self.registration_revision,
            revocation: self.revocation.as_ref().map(RevocationDigestBody::from),
        })
    }

    pub fn validate(
        &self,
        scope: &AwsRoute53HealthScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsRoute53ProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.registration_digest != self.recomputed_digest()
            || self.plugin_version != AWS_ROUTE53_HEALTH_PLUGIN_VERSION
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.contract_version != AWS_ROUTE53_HEALTH_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.scope_digest != scope.digest()
            || self.permission_digest != permission.digest()
            || self.secret_reference_digest != *secret_reference.digest()
            || self.health_check_revision != scope.health_check.revision
        {
            return Err(RegistrationError::Model(ModelError::ScopeMismatch {
                field: "Route 53 registration binding",
            }));
        }
        if !permission.is_complete_read_only() {
            return Err(RegistrationError::PermissionFence);
        }
        if secret_reference.region() != &scope.region {
            return Err(RegistrationError::SecretRegionMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RevocationEvidence, RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        let next_revision = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)
            .and_then(|value| {
                Revision::new(value).map_err(|_| RegistrationError::RevisionOverflow)
            })?;
        self.state = RegistrationState::Revoked;
        self.registration_revision = next_revision;
        let reason_digest = Digest::from_text("registration-revoked-by-local-boundary");
        let mut revocation = RevocationEvidence {
            previous_registration_digest,
            revocation_revision: next_revision,
            reason_digest,
            registration_digest: Digest::zero(),
        };
        self.revocation = Some(revocation.clone());
        self.registration_digest = self.recomputed_digest();
        revocation.registration_digest = self.registration_digest.clone();
        self.revocation = Some(revocation.clone());
        self.registration_digest = self.recomputed_digest();
        Ok(revocation)
    }
}

fn digest_registration_body(body: &RegistrationBody) -> Digest {
    Digest::from_parts(
        "hartevo-aws-route53-health-registration/v1",
        &[digest_serialized(body).to_string()],
    )
}

fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    crate::model::digest_serializable(value).unwrap_or_else(|_| Digest::zero())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53ReadResult {
    pub request: AwsRoute53HealthReadRequest,
    pub evidence: AwsRoute53HealthEvidence,
}

pub type AwsRoute53HealthReadResult = AwsRoute53ReadResult;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthProposal {
    pub state: EvidenceState,
    pub evidence: AwsRoute53HealthEvidence,
    pub registration_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub proposal_digest: Digest,
}

pub type AwsRoute53Proposal = AwsRoute53HealthProposal;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    state: EvidenceState,
    evidence: &'a AwsRoute53HealthEvidence,
    registration_digest: &'a Digest,
    read_only: bool,
    proposal_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    certification_claim: bool,
    adopted_outcome: bool,
    truth_authority: bool,
}

impl AwsRoute53HealthProposal {
    fn new(
        evidence: AwsRoute53HealthEvidence,
        registration_digest: Digest,
    ) -> Result<Self, AwsRoute53HealthServiceError> {
        evidence
            .validate()
            .map_err(|_| AwsRoute53HealthServiceError::EvidenceTampered)?;
        let mut proposal = Self {
            state: evidence.state,
            evidence,
            registration_digest,
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            certification_claim: false,
            adopted_outcome: false,
            truth_authority: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        Ok(proposal)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ProposalBody {
            state: self.state,
            evidence: &self.evidence,
            registration_digest: &self.registration_digest,
            read_only: self.read_only,
            proposal_only: self.proposal_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            certification_claim: self.certification_claim,
            adopted_outcome: self.adopted_outcome,
            truth_authority: self.truth_authority,
        })
    }

    pub fn validate(&self) -> Result<(), AwsRoute53HealthServiceError> {
        if self.proposal_digest != self.recomputed_digest()
            || self.state != self.evidence.state
            || !self.read_only
            || !self.proposal_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.certification_claim
            || self.adopted_outcome
            || self.truth_authority
        {
            return Err(AwsRoute53HealthServiceError::ProposalTampered);
        }
        self.evidence
            .validate()
            .map_err(|_| AwsRoute53HealthServiceError::ProposalTampered)
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthRecordReceipt {
    pub recorded: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded_at: DateTime<Utc>,
    pub raw_provider_payload_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    recorded_at: DateTime<Utc>,
    raw_provider_payload_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsRoute53HealthRecordReceipt {
    fn new(proposal: &AwsRoute53HealthProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recorded_at,
            raw_provider_payload_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            record_digest: Digest::zero(),
        };
        receipt.record_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RecordBody {
            recorded: self.recorded,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            recorded_at: self.recorded_at,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate(&self) -> Result<(), AwsRoute53HealthServiceError> {
        if !self.recorded
            || self.record_digest != self.recomputed_digest()
            || self.raw_provider_payload_retained
            || self.durable_receipt
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(AwsRoute53HealthServiceError::RecordTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthVerifiedRecord {
    pub verified: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub record_digest: Digest,
    pub registration_digest: Digest,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub connected: bool,
    pub native: bool,
}

pub struct AwsRoute53HealthService<T: AwsRoute53HealthTransport> {
    scope: AwsRoute53HealthScope,
    secret_reference: SecretReference,
    permission: PermissionFence,
    provider: AwsRoute53HealthProvider<T>,
    registration: AwsRoute53HealthRegistration,
}

impl<T: AwsRoute53HealthTransport> std::fmt::Debug for AwsRoute53HealthService<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwsRoute53HealthService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("permission", &self.permission)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: AwsRoute53HealthTransport> AwsRoute53HealthService<T> {
    pub fn new(
        scope: AwsRoute53HealthScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsRoute53HealthProvider<T>,
    ) -> Result<Self, AwsRoute53HealthServiceError> {
        scope.validate()?;
        permission
            .is_complete_read_only()
            .then_some(())
            .ok_or(RegistrationError::PermissionFence)?;
        let registration = AwsRoute53HealthRegistration::new(
            &scope,
            &secret_reference,
            &permission,
            provider.identity(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            permission,
            provider,
            registration,
        })
    }

    pub fn register(
        scope: AwsRoute53HealthScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsRoute53HealthProvider<T>,
    ) -> Result<Self, AwsRoute53HealthServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn describe_capabilities(&self) -> AwsRoute53HealthCapabilities {
        AwsRoute53HealthCapabilities::baseline()
    }

    pub fn scope(&self) -> &AwsRoute53HealthScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn registration(&self) -> &AwsRoute53HealthRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &AwsRoute53HealthProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsRoute53HealthProvider<T> {
        &mut self.provider
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RevocationEvidence, AwsRoute53HealthServiceError> {
        self.ensure_registration()?;
        Ok(self.registration.revoke()?)
    }

    pub fn request(
        &self,
        bounds: ReadBounds,
        as_of: DateTime<Utc>,
    ) -> Result<AwsRoute53HealthReadRequest, AwsRoute53HealthServiceError> {
        Ok(AwsRoute53HealthReadRequest::new(
            &self.scope,
            bounds,
            as_of,
            None,
        )?)
    }

    pub fn default_request(
        &self,
        as_of: DateTime<Utc>,
    ) -> Result<AwsRoute53HealthReadRequest, AwsRoute53HealthServiceError> {
        self.request(ReadBounds::default(), as_of)
    }

    pub fn read(
        &mut self,
        request: AwsRoute53HealthReadRequest,
    ) -> Result<AwsRoute53ReadResult, AwsRoute53HealthServiceError> {
        self.ensure_registration()?;
        request.validate_against(&self.scope)?;
        let evidence = self.read_evidence(&request)?;
        Ok(AwsRoute53ReadResult { request, evidence })
    }

    pub fn read_bounded(
        &mut self,
        request: AwsRoute53HealthReadRequest,
    ) -> Result<AwsRoute53ReadResult, AwsRoute53HealthServiceError> {
        self.read(request)
    }

    pub fn propose(
        &mut self,
        request: AwsRoute53HealthReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsRoute53HealthProposal, AwsRoute53HealthServiceError> {
        let request = request.with_as_of(observed_at)?;
        let read = self.read(request)?;
        AwsRoute53HealthProposal::new(read.evidence, self.registration.registration_digest.clone())
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsRoute53HealthProposal,
    ) -> Result<(), AwsRoute53HealthServiceError> {
        self.ensure_registration()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
        {
            return Err(AwsRoute53HealthServiceError::ScopeMismatch(
                "proposal registration, scope, or permission digest",
            ));
        }
        Ok(())
    }

    pub fn record(
        &self,
        proposal: &AwsRoute53HealthProposal,
    ) -> Result<AwsRoute53HealthRecordReceipt, AwsRoute53HealthServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsRoute53HealthProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsRoute53HealthRecordReceipt, AwsRoute53HealthServiceError> {
        self.verify_proposal(proposal)?;
        Ok(AwsRoute53HealthRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsRoute53HealthRecordReceipt,
    ) -> Result<AwsRoute53HealthVerifiedRecord, AwsRoute53HealthServiceError> {
        self.ensure_registration()?;
        receipt.validate()?;
        if receipt.registration_digest != self.registration.registration_digest {
            return Err(AwsRoute53HealthServiceError::ScopeMismatch(
                "record registration digest",
            ));
        }
        Ok(AwsRoute53HealthVerifiedRecord {
            verified: true,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            record_digest: receipt.record_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            adopted_outcome: false,
            truth_authority: false,
            connected: false,
            native: false,
        })
    }

    pub fn consumer(
        &self,
    ) -> Result<crate::consumer::MissionAwsRoute53Consumer, crate::consumer::ConsumerError> {
        crate::consumer::MissionAwsRoute53Consumer::new(
            self.scope.clone(),
            self.registration.clone(),
        )
    }

    fn ensure_registration(&self) -> Result<(), AwsRoute53HealthServiceError> {
        if !self.registration.is_active() {
            return Err(AwsRoute53HealthServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                &self.permission,
                self.provider.identity(),
            )
            .map_err(|_| AwsRoute53HealthServiceError::RegistrationDrift)
    }

    fn read_evidence(
        &mut self,
        request: &AwsRoute53HealthReadRequest,
    ) -> Result<AwsRoute53HealthEvidence, AwsRoute53HealthServiceError> {
        let identity = self.provider.identity().clone();
        let provenance = identity.provenance;
        let window_start = request.as_of - Duration::seconds(request.observation_window_seconds);
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut provider_errors = Vec::new();
        let mut list_page_digests = Vec::new();
        let mut health_checks = Vec::new();
        let mut list_complete = false;
        let mut list_page_count = 0_u16;
        let mut partial_reason = None;
        let mut terminal_state = None;
        let mut response_bytes = 0_usize;
        let mut marker = request.initial_marker.clone();
        let mut seen_markers = BTreeSet::new();

        loop {
            if request_count >= request.max_requests_per_read {
                partial_reason = Some(PartialReason::PaginationBudget);
                break;
            }
            if list_page_count >= request.max_pages {
                partial_reason = Some(PartialReason::PaginationBudget);
                break;
            }
            let list_request = ListHealthChecksRequest::new(&self.scope, request, marker.clone())?;
            request_count += 1;
            match self.provider.list_health_checks(&list_request) {
                Ok(page) => {
                    if page.page_number != list_page_count + 1 {
                        return Err(AwsRoute53HealthServiceError::Provider(
                            ProviderError::ResponseBinding,
                        ));
                    }
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    if response_bytes > request.max_response_bytes {
                        partial_reason = Some(PartialReason::ResponseTooLarge);
                        break;
                    }
                    list_page_count += 1;
                    if health_checks.len() + page.health_checks.len()
                        > usize::from(request.max_health_checks)
                    {
                        partial_reason = Some(PartialReason::HealthCheckLimit);
                        break;
                    }
                    health_checks.extend(page.health_checks.clone());
                    list_page_digests.push(page.page_digest.clone());
                    marker.clone_from(&page.next_marker);
                    let Some(next_marker) = &marker else {
                        list_complete = true;
                        break;
                    };
                    if !seen_markers.insert(next_marker.token_digest().clone()) {
                        partial_reason = Some(PartialReason::PaginationLoop);
                        break;
                    }
                    if list_page_count >= request.max_pages {
                        partial_reason = Some(PartialReason::PaginationBudget);
                        break;
                    }
                }
                Err(ProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence(ReadOperation::ListHealthChecks));
                    if error.failure.retryable() && retry_count < request.max_retries {
                        retry_count += 1;
                        continue;
                    }
                    terminal_state = Some(state_for_transport(&error));
                    if matches!(error.failure, TransportFailure::Conflict) {
                        partial_reason = Some(PartialReason::ProviderConflict);
                    }
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        let target = health_checks
            .iter()
            .find(|health_check| health_check.id == self.scope.health_check.id)
            .cloned();
        let Some(list_target) = target else {
            let state = terminal_state.unwrap_or({
                if list_complete {
                    EvidenceState::NotFound
                } else {
                    EvidenceState::Partial
                }
            });
            let reason = partial_reason.or({
                if list_complete {
                    Some(PartialReason::MissingHealthCheck)
                } else {
                    Some(PartialReason::PaginationBudget)
                }
            });
            return Ok(self.make_evidence(
                request,
                state,
                reason,
                None,
                Vec::new(),
                list_page_count,
                list_complete,
                request_count,
                retry_count,
                response_bytes,
                window_start,
                list_page_digests,
                None,
                None,
                provider_errors,
                provenance,
                &identity,
            ));
        };
        if list_target.revision != self.scope.health_check.revision {
            return Ok(self.make_evidence(
                request,
                EvidenceState::Partial,
                Some(PartialReason::HealthCheckRevisionDrift),
                Some(list_target),
                Vec::new(),
                list_page_count,
                list_complete,
                request_count,
                retry_count,
                response_bytes,
                window_start,
                list_page_digests,
                None,
                None,
                provider_errors,
                provenance,
                &identity,
            ));
        }

        if !list_complete
            && matches!(
                partial_reason,
                Some(
                    PartialReason::PaginationBudget
                        | PartialReason::PaginationLoop
                        | PartialReason::HealthCheckLimit
                        | PartialReason::ResponseTooLarge
                )
            )
        {
            return Ok(self.make_evidence(
                request,
                EvidenceState::Partial,
                partial_reason,
                Some(list_target),
                Vec::new(),
                list_page_count,
                list_complete,
                request_count,
                retry_count,
                response_bytes,
                window_start,
                list_page_digests,
                None,
                None,
                provider_errors,
                provenance,
                &identity,
            ));
        }

        let get_request = GetHealthCheckRequest::new(&self.scope, request)?;
        let get_response = match self.read_get_with_retries(
            &get_request,
            request,
            &mut request_count,
            &mut retry_count,
            &mut provider_errors,
        )? {
            Some(response) => response,
            None => {
                let state = provider_errors
                    .last()
                    .and_then(|error| state_for_category(&error.category))
                    .unwrap_or(EvidenceState::ProviderUnknown);
                return Ok(self.make_evidence(
                    request,
                    state,
                    Some(PartialReason::PartialStatus),
                    Some(list_target),
                    Vec::new(),
                    list_page_count,
                    list_complete,
                    request_count,
                    retry_count,
                    response_bytes,
                    window_start,
                    list_page_digests,
                    None,
                    None,
                    provider_errors,
                    provenance,
                    &identity,
                ));
            }
        };
        response_bytes = response_bytes.saturating_add(get_response.response_bytes);
        if response_bytes > request.max_response_bytes {
            return Ok(self.make_evidence(
                request,
                EvidenceState::Partial,
                Some(PartialReason::ResponseTooLarge),
                Some(get_response.health_check),
                Vec::new(),
                list_page_count,
                list_complete,
                request_count,
                retry_count,
                response_bytes,
                window_start,
                list_page_digests,
                None,
                None,
                provider_errors,
                provenance,
                &identity,
            ));
        }
        let health_check = get_response.health_check.clone();
        if health_check.id != self.scope.health_check.id {
            return Err(AwsRoute53HealthServiceError::ScopeMismatch(
                "GetHealthCheck returned an unexpected health-check id",
            ));
        }
        if health_check.revision != self.scope.health_check.revision {
            return Ok(self.make_evidence(
                request,
                EvidenceState::Partial,
                Some(PartialReason::HealthCheckRevisionDrift),
                Some(health_check),
                Vec::new(),
                list_page_count,
                list_complete,
                request_count,
                retry_count,
                response_bytes,
                window_start,
                list_page_digests,
                Some(get_response.response_digest),
                None,
                provider_errors,
                provenance,
                &identity,
            ));
        }
        if health_check.configuration.target != self.scope.health_check.target {
            return Err(AwsRoute53HealthServiceError::ScopeMismatch(
                "health-check endpoint, CloudWatch alarm, or calculated target",
            ));
        }
        if health_check.configuration.check_type.is_calculated() {
            return Ok(self.make_evidence(
                request,
                EvidenceState::Unsupported,
                Some(PartialReason::CalculatedCheckUnsupported),
                Some(health_check),
                Vec::new(),
                list_page_count,
                list_complete,
                request_count,
                retry_count,
                response_bytes,
                window_start,
                list_page_digests,
                Some(get_response.response_digest),
                None,
                provider_errors,
                provenance,
                &identity,
            ));
        }

        let status_request = GetHealthCheckStatusRequest::new(&self.scope, request)?;
        let status_response = match self.read_status_with_retries(
            &status_request,
            request,
            &mut request_count,
            &mut retry_count,
            &mut provider_errors,
        )? {
            Some(response) => response,
            None => {
                let state = provider_errors
                    .last()
                    .and_then(|error| state_for_category(&error.category))
                    .unwrap_or(EvidenceState::ProviderUnknown);
                return Ok(self.make_evidence(
                    request,
                    state,
                    Some(PartialReason::PartialStatus),
                    Some(health_check),
                    Vec::new(),
                    list_page_count,
                    list_complete,
                    request_count,
                    retry_count,
                    response_bytes,
                    window_start,
                    list_page_digests,
                    Some(get_response.response_digest),
                    None,
                    provider_errors,
                    provenance,
                    &identity,
                ));
            }
        };
        response_bytes = response_bytes.saturating_add(status_response.response_bytes);
        if response_bytes > request.max_response_bytes {
            return Ok(self.make_evidence(
                request,
                EvidenceState::Partial,
                Some(PartialReason::ResponseTooLarge),
                Some(health_check),
                status_response.observations,
                list_page_count,
                list_complete,
                request_count,
                retry_count,
                response_bytes,
                window_start,
                list_page_digests,
                Some(get_response.response_digest),
                Some(status_response.response_digest),
                provider_errors,
                provenance,
                &identity,
            ));
        }
        let mut observations = status_response.observations;
        let mut observation_digests = BTreeSet::new();
        let mut observation_issue = None;
        for observation in &observations {
            if !health_check
                .configuration
                .regions
                .contains(&observation.region)
                && observation.region != self.scope.region
            {
                return Err(AwsRoute53HealthServiceError::ScopeMismatch(
                    "status observation region",
                ));
            }
            if !observation_digests.insert(observation.observation_digest.clone()) {
                observation_issue = Some(PartialReason::DuplicateObservation);
            }
            if observation.checked_at < status_request.since
                || observation.checked_at > status_request.until
            {
                observation_issue = Some(PartialReason::StaleObservation);
            }
        }
        if observations.len() > request.max_observations as usize {
            observations.truncate(request.max_observations as usize);
            observation_issue = Some(PartialReason::PartialStatus);
        }
        let state = if let Some(reason) = observation_issue {
            partial_reason = Some(reason);
            EvidenceState::Partial
        } else if observations.is_empty() {
            partial_reason = Some(PartialReason::MissingObservation);
            EvidenceState::InsufficientData
        } else if observations.iter().any(|observation| {
            matches!(
                observation.status,
                crate::model::ObservationStatus::Unhealthy
            )
        }) {
            EvidenceState::Unhealthy
        } else if observations.iter().any(|observation| {
            matches!(observation.status, crate::model::ObservationStatus::Unknown)
        }) {
            partial_reason = Some(PartialReason::PartialStatus);
            EvidenceState::Partial
        } else {
            EvidenceState::Healthy
        };
        let final_state = if partial_reason.is_some()
            && matches!(state, EvidenceState::Healthy | EvidenceState::Unhealthy)
        {
            EvidenceState::Partial
        } else {
            terminal_state.unwrap_or(state)
        };
        Ok(self.make_evidence(
            request,
            final_state,
            partial_reason,
            Some(health_check),
            observations,
            list_page_count,
            list_complete,
            request_count,
            retry_count,
            response_bytes,
            window_start,
            list_page_digests,
            Some(get_response.response_digest),
            Some(status_response.response_digest),
            provider_errors,
            provenance,
            &identity,
        ))
    }

    fn read_get_with_retries(
        &mut self,
        request: &GetHealthCheckRequest,
        read_request: &AwsRoute53HealthReadRequest,
        request_count: &mut u16,
        retry_count: &mut u8,
        provider_errors: &mut Vec<ProviderErrorEvidence>,
    ) -> Result<Option<GetHealthCheckResponse>, AwsRoute53HealthServiceError> {
        loop {
            if *request_count >= read_request.max_requests_per_read {
                return Ok(None);
            }
            *request_count += 1;
            match self.provider.get_health_check(request) {
                Ok(response) => return Ok(Some(response)),
                Err(ProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence(ReadOperation::GetHealthCheck));
                    if error.failure.retryable() && *retry_count < read_request.max_retries {
                        *retry_count += 1;
                        continue;
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn read_status_with_retries(
        &mut self,
        request: &GetHealthCheckStatusRequest,
        read_request: &AwsRoute53HealthReadRequest,
        request_count: &mut u16,
        retry_count: &mut u8,
        provider_errors: &mut Vec<ProviderErrorEvidence>,
    ) -> Result<Option<GetHealthCheckStatusResponse>, AwsRoute53HealthServiceError> {
        loop {
            if *request_count >= read_request.max_requests_per_read {
                return Ok(None);
            }
            *request_count += 1;
            match self.provider.get_health_check_status(request) {
                Ok(response) => return Ok(Some(response)),
                Err(ProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence(ReadOperation::GetHealthCheckStatus));
                    if error.failure.retryable() && *retry_count < read_request.max_retries {
                        *retry_count += 1;
                        continue;
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_evidence(
        &self,
        request: &AwsRoute53HealthReadRequest,
        state: EvidenceState,
        partial_reason: Option<PartialReason>,
        health_check: Option<HealthCheckSummary>,
        observations: Vec<HealthCheckObservation>,
        list_page_count: u16,
        list_complete: bool,
        request_count: u16,
        retry_count: u8,
        response_bytes: usize,
        observation_window_start: DateTime<Utc>,
        list_page_digests: Vec<Digest>,
        get_response_digest: Option<Digest>,
        status_response_digest: Option<Digest>,
        provider_errors: Vec<ProviderErrorEvidence>,
        provenance: TransportProvenance,
        identity: &AwsRoute53ProviderIdentity,
    ) -> AwsRoute53HealthEvidence {
        let mut evidence = AwsRoute53HealthEvidence {
            state,
            partial_reason,
            health_check,
            observations,
            list_page_count,
            list_complete,
            request_count,
            retry_count,
            response_bytes,
            observation_window_start,
            observation_window_end: request.as_of,
            request_digest: request.request_digest.clone(),
            list_page_digests,
            get_response_digest,
            status_response_digest,
            scope_digest: self.scope.digest(),
            permission_digest: self.permission.digest(),
            provider_id: identity.provider_id.clone(),
            provider_revision: identity.api_revision.clone(),
            provider_digest: identity.provider_digest.clone(),
            api_digest: identity.api_digest.clone(),
            contract_digest: contract_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_errors,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            durable_receipt: false,
            certification_claim: false,
            adopted_outcome: false,
            truth_authority: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }
}

fn state_for_transport(error: &TransportError) -> EvidenceState {
    if is_access_loss(error) {
        EvidenceState::AccessLoss
    } else {
        match error.failure {
            TransportFailure::Throttled => EvidenceState::Throttled,
            TransportFailure::Timeout => EvidenceState::Timeout,
            TransportFailure::Conflict => EvidenceState::Partial,
            TransportFailure::BadRequest
            | TransportFailure::Server
            | TransportFailure::BlockedEnv
            | TransportFailure::Malformed => EvidenceState::ProviderUnknown,
            TransportFailure::Unauthorized
            | TransportFailure::AccessDenied
            | TransportFailure::NotFound => EvidenceState::AccessLoss,
        }
    }
}

fn state_for_category(category: &str) -> Option<EvidenceState> {
    Some(match category {
        "unauthorized" | "access_denied" | "not_found" => EvidenceState::AccessLoss,
        "throttled" => EvidenceState::Throttled,
        "timeout" => EvidenceState::Timeout,
        "conflict" => EvidenceState::Partial,
        _ => EvidenceState::ProviderUnknown,
    })
}
