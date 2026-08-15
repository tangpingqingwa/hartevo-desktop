//! Read, proposal, recording, and verification seams for Opsgenie evidence.

use std::fmt;

use thiserror::Error;

use crate::{
    Digest, EvidenceClassification, EvidenceState, ModelError, ObservationFailure,
    OpsgenieIncidentResult, OpsgenieIncidentResultEvidence, OpsgenieIncidentResultProposal,
    OpsgenieIncidentResultRecommendation, OpsgenieIncidentResultRegistration,
    OpsgenieIncidentResultScope, OpsgenieObservationReceipt, OpsgenieProvider,
    OpsgenieProviderError, OpsgenieProviderRead, OpsgenieRateLimitReceipt, OpsgenieReadbackReceipt,
    OpsgenieRegistration, OpsgenieTransport, RecommendationDisposition, RegistrationState,
    TransportProvenance, canonical_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OpsgenieIncidentResultServiceError {
    #[error("Opsgenie registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Opsgenie SecretReference is revoked")]
    SecretRevoked,
    #[error("Opsgenie permission snapshot is missing a required read permission")]
    MissingPermission,
    #[error("Opsgenie exact scope does not match")]
    ScopeMismatch,
    #[error("Opsgenie consent is denied or stale")]
    ConsentMismatch,
    #[error("Opsgenie evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error("Opsgenie proposal replay was rejected")]
    ReplayDetected,
    #[error(transparent)]
    Provider(#[from] OpsgenieProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpsgenieIncidentResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
    pub external_writes: bool,
}

impl Default for OpsgenieIncidentResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::OPSGENIE_INCIDENT_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::OPSGENIE_INCIDENT_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::OPSGENIE_INCIDENT_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::OPSGENIE_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_OPSGENIE_INCIDENT_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
            external_writes: false,
        }
    }
}

/// Typed Layer-1 service. It never resolves credentials, opens native HTTPS,
/// mutates Opsgenie, creates a durable native receipt, or adopts Outcome.
pub struct OpsgenieIncidentResultService<T: OpsgenieTransport> {
    provider: OpsgenieProvider<T>,
    definition: OpsgenieIncidentResultServiceDefinition,
}

impl<T: OpsgenieTransport> fmt::Debug for OpsgenieIncidentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpsgenieIncidentResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: OpsgenieTransport> OpsgenieIncidentResultService<T> {
    pub fn new(provider: OpsgenieProvider<T>) -> Result<Self, OpsgenieIncidentResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| OpsgenieIncidentResultServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition: OpsgenieIncidentResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: OpsgenieProvider<T>) -> Self {
        Self {
            provider,
            definition: OpsgenieIncidentResultServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &OpsgenieProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut OpsgenieProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &OpsgenieIncidentResultScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &OpsgenieRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &OpsgenieIncidentResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> crate::ConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(
        &mut self,
    ) -> Result<OpsgenieIncidentResultEvidence, OpsgenieIncidentResultServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(&consent)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<OpsgenieIncidentResultEvidence, OpsgenieIncidentResultServiceError> {
        if consent != self.scope().consent() {
            return Err(OpsgenieIncidentResultServiceError::ConsentMismatch);
        }
        match self.provider.read() {
            Ok(read) => Ok(success_evidence(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                read,
            )),
            Err(OpsgenieProviderError::RegistrationRevoked) => {
                Err(OpsgenieIncidentResultServiceError::RegistrationRevoked)
            }
            Err(OpsgenieProviderError::SecretRevoked) => {
                Err(OpsgenieIncidentResultServiceError::SecretRevoked)
            }
            Err(OpsgenieProviderError::MissingPermission) => {
                Err(OpsgenieIncidentResultServiceError::MissingPermission)
            }
            Err(OpsgenieProviderError::ScopeMismatch) => {
                Err(OpsgenieIncidentResultServiceError::ScopeMismatch)
            }
            Err(error) => Ok(failure_evidence(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                self.provider.transport_provenance(),
                &error,
            )),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<OpsgenieIncidentResultProposal, OpsgenieIncidentResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_incident_result_proposal(
        &mut self,
    ) -> Result<OpsgenieIncidentResultProposal, OpsgenieIncidentResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<OpsgenieIncidentResultProposal, OpsgenieIncidentResultServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: OpsgenieIncidentResultEvidence,
    ) -> Result<OpsgenieIncidentResultProposal, OpsgenieIncidentResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let recommendation = recommendation_for(&evidence);
        let source_evidence_digest = evidence.digest();
        let mut proposal = OpsgenieIncidentResultProposal {
            scope: self.scope().clone(),
            evidence,
            source_evidence_digest,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            permission_snapshot_digest: self.scope().permission_digest(),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
            recommendation,
            proposal_digest: Digest::from_text("unsealed-opsgenie-proposal"),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &OpsgenieIncidentResultProposal,
    ) -> Result<(), OpsgenieIncidentResultServiceError> {
        self.ensure_registration()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.adopts_outcome
            || proposal.adopts_work_product
            || proposal.scope != *self.scope()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.permission_snapshot_digest != self.scope().permission_digest()
            || proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.proposal_digest != proposal.digest()
        {
            return Err(OpsgenieIncidentResultServiceError::EvidenceMismatch);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn record_observation(
        &self,
        proposal: &OpsgenieIncidentResultProposal,
    ) -> Result<OpsgenieObservationReceipt, OpsgenieIncidentResultServiceError> {
        self.verify_proposal(proposal)?;
        Ok(OpsgenieObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recorded: true,
            durable: false,
            native: false,
            connected: false,
        })
    }

    pub fn read_back(
        &self,
        proposal: &OpsgenieIncidentResultProposal,
    ) -> Result<OpsgenieReadbackReceipt, OpsgenieIncidentResultServiceError> {
        self.verify_proposal(proposal)?;
        Ok(OpsgenieReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_proposal".to_owned(),
            independent_native_readback: false,
            native: false,
            connected: false,
        })
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, OpsgenieIncidentResultServiceError> {
        self.provider.revoke().map_err(map_provider_error)
    }

    pub fn restore(&mut self) -> Result<(), OpsgenieIncidentResultServiceError> {
        self.provider.restore().map_err(map_provider_error)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, OpsgenieIncidentResultServiceError> {
        self.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<(), OpsgenieIncidentResultServiceError> {
        self.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<(), OpsgenieIncidentResultServiceError> {
        self.provider.revoke_secret().map_err(map_provider_error)
    }

    pub fn restore_secret(&mut self) -> Result<(), OpsgenieIncidentResultServiceError> {
        self.provider.restore_secret().map_err(map_provider_error)
    }

    fn ensure_registration(&self) -> Result<(), OpsgenieIncidentResultServiceError> {
        if self.registration().is_active() {
            self.registration()
                .validate(
                    self.scope(),
                    self.provider.secret_reference(),
                    &self.provider.provider_digest(),
                )
                .map_err(|_| OpsgenieIncidentResultServiceError::RegistrationRevoked)
        } else {
            Err(OpsgenieIncidentResultServiceError::RegistrationRevoked)
        }
    }

    fn verify_evidence(
        &self,
        evidence: &OpsgenieIncidentResultEvidence,
    ) -> Result<(), OpsgenieIncidentResultServiceError> {
        let digests = &evidence.digests;
        if evidence.proposal_only
            && !evidence.native
            && !evidence.connected
            && !evidence.first_party
            && !evidence.outcome_authority
            && evidence.provenance == self.provider.transport_provenance()
            && digests.plugin_version_digest
                == Digest::from_text(crate::OPSGENIE_INCIDENT_RESULT_PLUGIN_VERSION)
            && digests.contract_digest == crate::contract_digest()
            && digests.provider_digest == self.provider.provider_digest()
            && digests.permission_snapshot_digest == self.scope().permission_digest()
            && digests.consent_digest == *self.scope().consent().digest()
            && digests.scope_digest == self.scope().digest().clone()
            && digests.revision_digest == *self.scope().revision_digest()
            && digests.project_digest == self.scope().project().digest()
            && digests.mission_digest == self.scope().mission().digest()
            && digests.work_product_digest == self.scope().work_product().digest()
            && digests.registration_digest == self.registration().registration_digest
            && evidence.evidence_digest == evidence.digest()
        {
            Ok(())
        } else {
            Err(OpsgenieIncidentResultServiceError::EvidenceMismatch)
        }
    }
}

pub type OpsgenieIncidentResultServiceResult<T> = OpsgenieIncidentResultService<T>;
pub type OpsgenieServiceError = OpsgenieIncidentResultServiceError;
pub type RegistrationStatus = crate::RegistrationState;

fn success_evidence(
    scope: &OpsgenieIncidentResultScope,
    registration: &OpsgenieIncidentResultRegistration,
    provider_digest: Digest,
    read: OpsgenieProviderRead,
) -> OpsgenieIncidentResultEvidence {
    let state = if read.result.is_empty() {
        EvidenceState::Empty
    } else if !read.timeline_complete {
        EvidenceState::Partial
    } else {
        EvidenceState::Complete
    };
    let result = read.result;
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        &result,
        read.response_digest,
    );
    let mut evidence = OpsgenieIncidentResultEvidence {
        state,
        classification: EvidenceClassification::BoundedRead,
        result,
        request_receipts: read.request_receipts,
        response_bytes: read.response_bytes,
        rate_limit: read.rate_limit,
        provenance: read.provenance,
        digests,
        failures: Vec::new(),
        proposal_only: true,
        native: false,
        connected: false,
        first_party: false,
        outcome_authority: false,
        evidence_digest: Digest::from_text("unsealed-opsgenie-evidence"),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

fn failure_evidence(
    scope: &OpsgenieIncidentResultScope,
    registration: &OpsgenieIncidentResultRegistration,
    provider_digest: Digest,
    provenance: TransportProvenance,
    error: &OpsgenieProviderError,
) -> OpsgenieIncidentResultEvidence {
    let failure = failure_for(error);
    let state = failure.state();
    let result = OpsgenieIncidentResult {
        alert: None,
        timeline: None,
        incident: None,
        schedule: None,
        escalation: None,
    };
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        &result,
        Digest::from_text(format!("opsgenie-failure:{error:?}")),
    );
    let mut evidence = OpsgenieIncidentResultEvidence {
        state,
        classification: EvidenceClassification::Failure,
        result,
        request_receipts: Vec::new(),
        response_bytes: 0,
        rate_limit: OpsgenieRateLimitReceipt::default(),
        provenance,
        digests,
        failures: vec![failure],
        proposal_only: true,
        native: false,
        connected: false,
        first_party: false,
        outcome_authority: false,
        evidence_digest: Digest::from_text("unsealed-opsgenie-failure-evidence"),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

fn evidence_digests(
    scope: &OpsgenieIncidentResultScope,
    registration: &OpsgenieIncidentResultRegistration,
    provider_digest: Digest,
    result: &OpsgenieIncidentResult,
    response_digest: Digest,
) -> crate::OpsgenieEvidenceDigests {
    crate::OpsgenieEvidenceDigests {
        plugin_version_digest: Digest::from_text(crate::OPSGENIE_INCIDENT_RESULT_PLUGIN_VERSION),
        contract_digest: crate::contract_digest(),
        provider_digest,
        permission_snapshot_digest: scope.permission_digest(),
        consent_digest: scope.consent().digest().clone(),
        scope_digest: scope.digest(),
        revision_digest: scope.revision_digest().clone(),
        project_digest: scope.project().digest(),
        mission_digest: scope.mission().digest(),
        work_product_digest: scope.work_product().digest(),
        registration_digest: registration.registration_digest.clone(),
        alert_digest: result.alert.as_ref().map(|value| canonical_digest(value)),
        incident_digest: result
            .incident
            .as_ref()
            .map(|value| canonical_digest(value)),
        schedule_digest: result
            .schedule
            .as_ref()
            .map(|value| canonical_digest(value)),
        escalation_digest: result
            .escalation
            .as_ref()
            .map(|value| canonical_digest(value)),
        timeline_digest: result
            .timeline
            .as_ref()
            .map(|value| canonical_digest(value)),
        response_digest,
    }
}

fn recommendation_for(
    evidence: &OpsgenieIncidentResultEvidence,
) -> OpsgenieIncidentResultRecommendation {
    let disposition = match evidence.state {
        EvidenceState::Complete => RecommendationDisposition::ReviewIncidentState,
        EvidenceState::Empty => RecommendationDisposition::NoRecommendationEmpty,
        EvidenceState::Partial => RecommendationDisposition::NoRecommendationPartial,
        EvidenceState::RateLimited => RecommendationDisposition::NoRecommendationRateLimited,
        EvidenceState::AccessLoss | EvidenceState::Denied => {
            RecommendationDisposition::NoRecommendationAccessLoss
        }
        EvidenceState::ProviderUnknown
        | EvidenceState::NotFound
        | EvidenceState::Stale
        | EvidenceState::Tampered
        | EvidenceState::RegistrationRevoked => {
            RecommendationDisposition::NoRecommendationProviderUnknown
        }
    };
    OpsgenieIncidentResultRecommendation {
        disposition,
        provider_reported_only: true,
        non_mutating: true,
        claims_remediation: false,
        claims_service_health: false,
        rationale_digest: canonical_digest(&(
            evidence.state,
            &evidence.failures,
            &evidence.digests,
        )),
    }
}

fn failure_for(error: &OpsgenieProviderError) -> ObservationFailure {
    match error {
        OpsgenieProviderError::RateLimited { rate_limit, .. } => ObservationFailure::RateLimited {
            retry_after_seconds: rate_limit.retry_after_seconds.unwrap_or(0),
        },
        OpsgenieProviderError::HttpStatus { status, .. } => match status {
            401 => ObservationFailure::Denied,
            403 => ObservationFailure::AccessLoss,
            404 => ObservationFailure::NotFound,
            409 => ObservationFailure::Stale,
            500..=599 => ObservationFailure::ProviderUnknown,
            _ => ObservationFailure::ProviderUnknown,
        },
        OpsgenieProviderError::ResponseTooLarge { .. } => ObservationFailure::ResponseTooLarge,
        OpsgenieProviderError::MalformedResponse { .. }
        | OpsgenieProviderError::InvalidRateLimitReceipt
        | OpsgenieProviderError::InvalidTimeline => ObservationFailure::MalformedResponse,
        OpsgenieProviderError::Transport { error, .. } => match error {
            crate::OpsgenieTransportError::BlockedEnv => ObservationFailure::BlockedEnv,
            crate::OpsgenieTransportError::Timeout
            | crate::OpsgenieTransportError::ProviderUnknown => ObservationFailure::ProviderUnknown,
        },
        OpsgenieProviderError::RegistrationRevoked => ObservationFailure::RegistrationRevoked,
        OpsgenieProviderError::SecretRevoked
        | OpsgenieProviderError::MissingPermission
        | OpsgenieProviderError::ScopeMismatch
        | OpsgenieProviderError::Model(_) => ObservationFailure::ProviderUnknown,
    }
}

fn map_provider_error(error: OpsgenieProviderError) -> OpsgenieIncidentResultServiceError {
    match error {
        OpsgenieProviderError::RegistrationRevoked => {
            OpsgenieIncidentResultServiceError::RegistrationRevoked
        }
        OpsgenieProviderError::SecretRevoked => OpsgenieIncidentResultServiceError::SecretRevoked,
        OpsgenieProviderError::MissingPermission => {
            OpsgenieIncidentResultServiceError::MissingPermission
        }
        OpsgenieProviderError::ScopeMismatch => OpsgenieIncidentResultServiceError::ScopeMismatch,
        other => OpsgenieIncidentResultServiceError::Provider(other),
    }
}

// Keep the public aliases used by earlier result slices available to callers.
pub type OpsgenieIncidentResultProposalModel = OpsgenieIncidentResultProposal;
pub type OpsgenieIncidentResultEvidenceModel = OpsgenieIncidentResultEvidence;
pub type OpsgenieIncidentResultRegistrationModel = OpsgenieIncidentResultRegistration;
pub type OpsgenieService<T> = OpsgenieIncidentResultService<T>;
pub type OpsgenieIncidentResultRequest = ();
pub type OpsgenieIncidentResultState = EvidenceState;
pub type OpsgenieIncidentResultRegistrationStatus = RegistrationState;
pub type OpsgenieProviderReadModel = OpsgenieProviderRead;
pub type OpsgenieTimelineResult = crate::OpsgenieTimelineObservation;
pub type OpsgenieReadReceipt = crate::OpsgenieRequestReceipt;
pub type OpsgenieTransportProvenance = TransportProvenance;
pub type OpsgenieResult = OpsgenieIncidentResult;
pub type OpsgenieResultProposal = OpsgenieIncidentResultProposal;
pub type OpsgenieResultEvidence = OpsgenieIncidentResultEvidence;
pub type OpsgenieResultRegistration = OpsgenieIncidentResultRegistration;
pub type OpsgenieResultRecommendation = OpsgenieIncidentResultRecommendation;
pub type OpsgenieResultRegistrationReceipt = crate::RegistrationRevocationReceipt;
pub type OpsgenieRegistrationType = OpsgenieRegistration;
pub type OpsgenieProviderFailure = OpsgenieProviderError;
pub type OpsgenieResultError = OpsgenieIncidentResultServiceError;
pub type OpsgenieResultDigest = Digest;
pub type OpsgenieResultProvenance = TransportProvenance;
pub type OpsgenieResultModel = OpsgenieIncidentResult;
pub type OpsgenieResultScope = OpsgenieIncidentResultScope;
pub type OpsgenieResultScopeSpec = crate::OpsgenieIncidentResultScopeSpec;
pub type OpsgenieResultTransport = dyn OpsgenieTransport;
pub type OpsgenieResultStatus = EvidenceState;
pub type OpsgenieResultDisposition = RecommendationDisposition;
pub type OpsgenieResultFailure = ObservationFailure;
pub type OpsgenieResultReceipt = OpsgenieObservationReceipt;
pub type OpsgenieResultReadback = OpsgenieReadbackReceipt;
pub type OpsgenieResultProvider = OpsgenieProvider<crate::BlockedEnvOpsgenieTransport>;
pub type OpsgenieResultService<T> = OpsgenieIncidentResultService<T>;
pub type OpsgenieResultConsumer<T> = crate::MissionOpsgenieIncidentConsumer<T>;
pub type OpsgenieResultPermission = crate::OpsgeniePermission;
pub type OpsgenieResultRegion = crate::OpsgenieRegion;
pub type OpsgenieResultRevision = crate::Revision;
pub type OpsgenieResultSecret = crate::SecretReference;
