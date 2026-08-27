//! Read-only Azure Resource Health service, proposal, record, and verification
//! seams.

use std::fmt;

use thiserror::Error;

use crate::model::{
    AzureResourceHealthEvidence, AzureResourceHealthOperation, AzureResourceHealthRegistration,
    AzureResourceHealthScope, Digest, EvidenceState, ModelError, ProviderResponseReceipt,
    RegistrationRevocation, TransportProvenance, api_digest,
};
use crate::provider::{
    AzureResourceHealthProvider, AzureResourceHealthProviderError, AzureResourceHealthTransport,
    AzureResourceHealthTransportError,
};
use crate::{
    AZURE_RESOURCE_HEALTH_API_REVISION, AZURE_RESOURCE_HEALTH_API_VERSION,
    AZURE_RESOURCE_HEALTH_CONTRACT_VERSION, AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT,
    AZURE_RESOURCE_HEALTH_PROVIDER_ID, AZURE_RESOURCE_HEALTH_SERVICE_ID,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureResourceHealthServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub version: String,
    pub contract_digest: Digest,
    pub api_version: String,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub outcome_authority: bool,
}

impl Default for AzureResourceHealthServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::AZURE_RESOURCE_HEALTH_SCHEMA_VERSION.to_owned(),
            contract_version: AZURE_RESOURCE_HEALTH_CONTRACT_VERSION.to_owned(),
            service_id: AZURE_RESOURCE_HEALTH_SERVICE_ID.to_owned(),
            provider_id: AZURE_RESOURCE_HEALTH_PROVIDER_ID.to_owned(),
            version: AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT.to_owned(),
            contract_digest: crate::contract_digest(),
            api_version: AZURE_RESOURCE_HEALTH_API_VERSION.to_owned(),
            read_only: true,
            live_execution: false,
            external_writes: false,
            outcome_authority: false,
        }
    }
}

impl AzureResourceHealthServiceDefinition {
    pub fn validate(&self) -> Result<(), AzureResourceHealthServiceError> {
        if self != &Self::default()
            || !self.read_only
            || self.live_execution
            || self.external_writes
            || self.outcome_authority
        {
            Err(AzureResourceHealthServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureResourceHealthServiceError {
    #[error("Azure Resource Health registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Azure Resource Health SecretReference is revoked")]
    SecretRevoked,
    #[error("Azure Resource Health scope does not match")]
    ScopeMismatch,
    #[error("Azure Resource Health service definition drifted")]
    DefinitionDrift,
    #[error("Azure Resource Health evidence or proposal digest verification failed")]
    EvidenceMismatch,
    #[error("Azure Resource Health proposal replay was rejected")]
    ReplayDetected,
    #[error("Azure Resource Health provider failed before safe evidence could be built: {0}")]
    Provider(#[from] AzureResourceHealthProviderError),
    #[error("Azure Resource Health model is invalid: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthProposal {
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub api_version: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub tenant_digest: Digest,
    pub resource_digest: Digest,
    pub resource_revision: crate::Revision,
    pub event_window_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub state: EvidenceState,
    pub evidence: AzureResourceHealthEvidence,
    pub proposal_only: bool,
    pub read_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub causal_authority: bool,
    pub recovery_authority: bool,
    pub outcome_authority: bool,
    pub decision_ready: bool,
    pub proposal_digest: Digest,
}

impl AzureResourceHealthProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        crate::canonical_digest(&(
            "azure-resource-health-proposal/v1",
            (
                &self.plugin_version,
                &self.version_digest,
                &self.contract_version,
                &self.contract_digest,
                &self.service_id,
                &self.provider_id,
                &self.provider_digest,
                &self.api_version,
                &self.api_digest,
                &self.permission_digest,
                &self.scope_digest,
                &self.tenant_digest,
                &self.resource_digest,
                self.resource_revision,
                &self.event_window_digest,
            ),
            (
                &self.registration_digest,
                &self.evidence_binding_digest,
                &self.evidence_digest,
                self.provenance,
                self.state,
                &self.evidence,
                self.proposal_only,
                self.read_only,
                self.native_provider,
                self.connected,
                self.external_write_performed,
                self.causal_authority,
                self.recovery_authority,
                self.outcome_authority,
                self.decision_ready,
            ),
        ))
    }

    pub fn verify_integrity(&self) -> Result<(), AzureResourceHealthServiceError> {
        if self.proposal_digest != self.digest()
            || self.evidence_digest != self.evidence.evidence_digest
            || self.state != self.evidence.state
            || !self.proposal_only
            || !self.read_only
            || self.native_provider
            || self.connected
            || self.external_write_performed
            || self.causal_authority
            || self.recovery_authority
            || self.outcome_authority
        {
            return Err(AzureResourceHealthServiceError::EvidenceMismatch);
        }
        self.evidence.verify_integrity()?;
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthRecord {
    pub record_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: EvidenceState,
    pub recorded: bool,
    pub durable_native_receipt: bool,
    pub native: bool,
    pub connected: bool,
    pub outcome_authority: bool,
}

impl AzureResourceHealthRecord {
    #[must_use]
    pub fn digest(&self) -> Digest {
        crate::canonical_digest(&(
            "azure-resource-health-record/v1",
            &self.proposal_digest,
            &self.evidence_digest,
            &self.registration_digest,
            &self.scope_digest,
            self.state,
            self.recorded,
            self.durable_native_receipt,
            self.native,
            self.connected,
            self.outcome_authority,
        ))
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthVerification {
    pub verification_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub verified: bool,
    pub independent_native_readback: bool,
    pub native: bool,
    pub connected: bool,
    pub causal_authority: bool,
    pub outcome_authority: bool,
}

impl AzureResourceHealthVerification {
    #[must_use]
    pub fn digest(&self) -> Digest {
        crate::canonical_digest(&(
            "azure-resource-health-verification/v1",
            &self.proposal_digest,
            &self.evidence_digest,
            self.verified,
            self.independent_native_readback,
            self.native,
            self.connected,
            self.causal_authority,
            self.outcome_authority,
        ))
    }
}

/// Typed Layer-1 service. The generic transport is a fixture/recording/
/// loopback/BLOCKED_ENV seam only; no native provider is supplied here.
pub struct AzureResourceHealthService<T: AzureResourceHealthTransport> {
    provider: AzureResourceHealthProvider<T>,
    definition: AzureResourceHealthServiceDefinition,
}

impl<T: AzureResourceHealthTransport> fmt::Debug for AzureResourceHealthService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureResourceHealthService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: AzureResourceHealthTransport> AzureResourceHealthService<T> {
    pub fn new(
        provider: AzureResourceHealthProvider<T>,
    ) -> Result<Self, AzureResourceHealthServiceError> {
        let definition = AzureResourceHealthServiceDefinition::default();
        definition.validate()?;
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
                provider.api_digest(),
            )
            .map_err(|_| AzureResourceHealthServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition,
        })
    }

    #[must_use]
    pub fn from_provider(provider: AzureResourceHealthProvider<T>) -> Self {
        Self {
            provider,
            definition: AzureResourceHealthServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &AzureResourceHealthProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AzureResourceHealthProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &AzureResourceHealthScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &AzureResourceHealthRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn register(&self) -> &AzureResourceHealthRegistration {
        self.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &AzureResourceHealthServiceDefinition {
        &self.definition
    }

    pub fn read(&mut self) -> Result<AzureResourceHealthEvidence, AzureResourceHealthServiceError> {
        self.ensure_registration()?;
        match self.provider.read() {
            Ok(evidence) => Ok(evidence),
            Err(
                error @ (AzureResourceHealthProviderError::RegistrationRevoked
                | AzureResourceHealthProviderError::SecretRevoked
                | AzureResourceHealthProviderError::ScopeMismatch),
            ) => Err(map_provider_error(error)),
            Err(error) => Ok(self.failure_evidence(&error)),
        }
    }

    pub fn read_availability_status(
        &mut self,
    ) -> Result<crate::AvailabilityObservation, AzureResourceHealthServiceError> {
        self.ensure_registration()?;
        self.provider
            .read_availability_status()
            .map(|read| read.observation)
            .map_err(map_provider_error)
    }

    pub fn read_event_list(
        &mut self,
    ) -> Result<crate::EventListRead, AzureResourceHealthServiceError> {
        self.ensure_registration()?;
        self.provider
            .read_event_list(None)
            .map_err(map_provider_error)
    }

    pub fn read_events(&mut self) -> Result<crate::EventListRead, AzureResourceHealthServiceError> {
        self.read_event_list()
    }

    pub fn propose(
        &mut self,
    ) -> Result<AzureResourceHealthProposal, AzureResourceHealthServiceError> {
        let evidence = self.read()?;
        self.propose_from_evidence(evidence)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AzureResourceHealthProposal, AzureResourceHealthServiceError> {
        self.propose()
    }

    pub fn propose_from_evidence(
        &self,
        evidence: AzureResourceHealthEvidence,
    ) -> Result<AzureResourceHealthProposal, AzureResourceHealthServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let mut proposal = AzureResourceHealthProposal {
            plugin_version: AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest: Digest::from_text(AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT),
            contract_version: AZURE_RESOURCE_HEALTH_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_id: AZURE_RESOURCE_HEALTH_SERVICE_ID.to_owned(),
            provider_id: AZURE_RESOURCE_HEALTH_PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            api_version: AZURE_RESOURCE_HEALTH_API_VERSION.to_owned(),
            api_digest: self.provider.api_digest().clone(),
            permission_digest: self.scope().permission_digest().clone(),
            scope_digest: self.scope().scope_digest().clone(),
            tenant_digest: self.scope().tenant_digest().clone(),
            resource_digest: self.scope().resource_digest().clone(),
            resource_revision: self.scope().resource_revision(),
            event_window_digest: self.scope().event_window().digest().clone(),
            registration_digest: self.registration().registration_digest.clone(),
            evidence_binding_digest: self
                .registration()
                .evidence_binding_digest(&evidence.evidence_digest),
            evidence_digest: evidence.evidence_digest.clone(),
            provenance: evidence.provenance,
            state: evidence.state,
            decision_ready: evidence.state.is_decision_ready()
                && evidence
                    .availability
                    .as_ref()
                    .is_some_and(crate::AvailabilityObservation::is_known),
            evidence,
            proposal_only: true,
            read_only: true,
            native_provider: false,
            connected: false,
            external_write_performed: false,
            causal_authority: false,
            recovery_authority: false,
            outcome_authority: false,
            proposal_digest: Digest::from_text(b"azure-resource-health-proposal-uninitialized"),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: AzureResourceHealthEvidence,
    ) -> Result<AzureResourceHealthProposal, AzureResourceHealthServiceError> {
        self.propose_from_evidence(evidence)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AzureResourceHealthProposal,
    ) -> Result<AzureResourceHealthVerification, AzureResourceHealthServiceError> {
        self.ensure_registration()?;
        if proposal.plugin_version != AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT
            || proposal.version_digest
                != Digest::from_text(AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT)
            || proposal.contract_version != AZURE_RESOURCE_HEALTH_CONTRACT_VERSION
            || proposal.contract_digest != crate::contract_digest()
            || proposal.service_id != AZURE_RESOURCE_HEALTH_SERVICE_ID
            || proposal.provider_id != AZURE_RESOURCE_HEALTH_PROVIDER_ID
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.api_version != AZURE_RESOURCE_HEALTH_API_VERSION
            || proposal.api_digest != *self.provider.api_digest()
            || proposal.permission_digest != *self.scope().permission_digest()
            || proposal.scope_digest != *self.scope().scope_digest()
            || proposal.tenant_digest != *self.scope().tenant_digest()
            || proposal.resource_digest != *self.scope().resource_digest()
            || proposal.resource_revision != self.scope().resource_revision()
            || proposal.event_window_digest != *self.scope().event_window().digest()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.evidence_digest != proposal.evidence.evidence_digest
            || proposal.evidence_binding_digest
                != self
                    .registration()
                    .evidence_binding_digest(&proposal.evidence_digest)
            || proposal.provenance != proposal.evidence.provenance
        {
            return Err(AzureResourceHealthServiceError::EvidenceMismatch);
        }
        proposal.verify_integrity()?;
        let mut verification = AzureResourceHealthVerification {
            verification_digest: Digest::from_text(
                b"azure-resource-health-verification-uninitialized",
            ),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            verified: true,
            independent_native_readback: false,
            native: false,
            connected: false,
            causal_authority: false,
            outcome_authority: false,
        };
        verification.verification_digest = verification.digest();
        Ok(verification)
    }

    pub fn verify(
        &self,
        proposal: &AzureResourceHealthProposal,
    ) -> Result<AzureResourceHealthVerification, AzureResourceHealthServiceError> {
        self.verify_proposal(proposal)
    }

    pub fn record(
        &self,
        proposal: &AzureResourceHealthProposal,
    ) -> Result<AzureResourceHealthRecord, AzureResourceHealthServiceError> {
        self.verify_proposal(proposal)?;
        let mut record = AzureResourceHealthRecord {
            record_digest: Digest::from_text(b"azure-resource-health-record-uninitialized"),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            recorded: true,
            durable_native_receipt: false,
            native: false,
            connected: false,
            outcome_authority: false,
        };
        record.record_digest = record.digest();
        Ok(record)
    }

    pub fn record_proposal(
        &self,
        proposal: &AzureResourceHealthProposal,
    ) -> Result<AzureResourceHealthRecord, AzureResourceHealthServiceError> {
        self.record(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, AzureResourceHealthServiceError> {
        self.provider.revoke().map_err(map_provider_error)
    }

    pub fn restore_registration(&mut self) -> Result<(), AzureResourceHealthServiceError> {
        self.provider.restore().map_err(map_provider_error)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AzureResourceHealthServiceError> {
        self.provider.revoke_secret().map_err(map_provider_error)
    }

    fn ensure_registration(&self) -> Result<(), AzureResourceHealthServiceError> {
        self.definition.validate()?;
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
                self.provider.api_digest(),
            )
            .map_err(|_| AzureResourceHealthServiceError::RegistrationRevoked)
    }

    fn verify_evidence(
        &self,
        evidence: &AzureResourceHealthEvidence,
    ) -> Result<(), AzureResourceHealthServiceError> {
        if evidence.plugin_version != AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT
            || evidence.version_digest
                != Digest::from_text(AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT)
            || evidence.contract_version != AZURE_RESOURCE_HEALTH_CONTRACT_VERSION
            || evidence.contract_digest != crate::contract_digest()
            || evidence.provider_id != AZURE_RESOURCE_HEALTH_PROVIDER_ID
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.api_version != AZURE_RESOURCE_HEALTH_API_VERSION
            || evidence.api_digest != *self.provider.api_digest()
            || evidence.permission_digest != *self.scope().permission_digest()
            || evidence.scope_digest != *self.scope().scope_digest()
            || evidence.tenant_digest != *self.scope().tenant_digest()
            || evidence.subscription_id != self.scope().subscription_id()
            || evidence.resource_digest != *self.scope().resource_digest()
            || evidence.resource_revision != self.scope().resource_revision()
            || evidence.event_window_digest != *self.scope().event_window().digest()
            || evidence.registration_digest != self.registration().registration_digest
        {
            return Err(AzureResourceHealthServiceError::EvidenceMismatch);
        }
        evidence.verify_integrity()?;
        Ok(())
    }

    fn failure_evidence(
        &self,
        error: &AzureResourceHealthProviderError,
    ) -> AzureResourceHealthEvidence {
        let state = failure_state(error);
        let operation = error
            .operation()
            .unwrap_or(AzureResourceHealthOperation::AvailabilityStatus);
        let request_digest = error
            .request_digest()
            .cloned()
            .unwrap_or_else(|| Digest::from_text(b"azure-resource-health-no-request"));
        let (response_digest, response_bytes, status_code) = error.response_metadata().unwrap_or((
            Digest::from_text(b"azure-resource-health-no-response"),
            0,
            None,
        ));
        let receipt = ProviderResponseReceipt {
            operation,
            request_digest: request_digest.clone(),
            request_path_digest: request_digest,
            api_version: AZURE_RESOURCE_HEALTH_API_VERSION.to_owned(),
            status_code,
            response_bytes,
            response_digest,
            provider_revision: AZURE_RESOURCE_HEALTH_API_REVISION.to_owned(),
            cursor_digest: None,
            raw_response_retained: false,
            raw_descriptions_retained: false,
            raw_recommendations_retained: false,
            raw_tags_retained: false,
            credential_material_retained: false,
            native: false,
            connected: false,
        };
        let mut evidence = AzureResourceHealthEvidence {
            plugin_version: AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest: Digest::from_text(AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT),
            contract_version: AZURE_RESOURCE_HEALTH_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: AZURE_RESOURCE_HEALTH_PROVIDER_ID.to_owned(),
            provider_digest: self.provider.provider_digest(),
            api_version: AZURE_RESOURCE_HEALTH_API_VERSION.to_owned(),
            api_digest: self.provider.api_digest().clone(),
            permission_digest: self.scope().permission_digest().clone(),
            scope_digest: self.scope().scope_digest().clone(),
            tenant_digest: self.scope().tenant_digest().clone(),
            subscription_id: self.scope().subscription_id().to_owned(),
            resource_digest: self.scope().resource_digest().clone(),
            resource_revision: self.scope().resource_revision(),
            event_window_digest: self.scope().event_window().digest().clone(),
            registration_digest: self.registration().registration_digest.clone(),
            provenance: self.provider.transport_provenance(),
            state,
            availability_state: state,
            event_list_state: state,
            availability: None,
            events: Vec::new(),
            next_cursor_digest: None,
            receipts: vec![receipt],
            read_only: true,
            native_provider: false,
            connected: false,
            external_write_performed: false,
            causal_authority: false,
            recovery_authority: false,
            outcome_authority: false,
            raw_provider_payload_retained: false,
            evidence_digest: Digest::from_text(b"azure-resource-health-failure-uninitialized"),
        };
        evidence.evidence_digest = evidence.digest();
        evidence
    }
}

fn map_provider_error(error: AzureResourceHealthProviderError) -> AzureResourceHealthServiceError {
    match error {
        AzureResourceHealthProviderError::RegistrationRevoked => {
            AzureResourceHealthServiceError::RegistrationRevoked
        }
        AzureResourceHealthProviderError::SecretRevoked => {
            AzureResourceHealthServiceError::SecretRevoked
        }
        AzureResourceHealthProviderError::ScopeMismatch => {
            AzureResourceHealthServiceError::ScopeMismatch
        }
        other => AzureResourceHealthServiceError::Provider(other),
    }
}

fn failure_state(error: &AzureResourceHealthProviderError) -> EvidenceState {
    match error {
        AzureResourceHealthProviderError::Transport {
            error: AzureResourceHealthTransportError::BlockedEnv,
            ..
        } => EvidenceState::AccessLost,
        AzureResourceHealthProviderError::Transport {
            error: AzureResourceHealthTransportError::Timeout,
            ..
        } => EvidenceState::TimedOut,
        AzureResourceHealthProviderError::Transport {
            error: AzureResourceHealthTransportError::ProviderUnknown,
            ..
        } => EvidenceState::ProviderUnknown,
        AzureResourceHealthProviderError::HttpStatus { status_code, .. } => match status_code {
            401 | 403 => EvidenceState::AccessLost,
            404 => EvidenceState::NotFound,
            409 => EvidenceState::Conflict,
            408 => EvidenceState::TimedOut,
            429 => EvidenceState::Throttled,
            500..=599 => EvidenceState::ProviderUnknown,
            _ => EvidenceState::Unknown,
        },
        AzureResourceHealthProviderError::ResponseTooLarge { .. }
        | AzureResourceHealthProviderError::MalformedResponse { .. }
        | AzureResourceHealthProviderError::EventWindowMismatch { .. }
        | AzureResourceHealthProviderError::CursorMismatch { .. }
        | AzureResourceHealthProviderError::BoundExceeded { .. }
        | AzureResourceHealthProviderError::Model(_) => EvidenceState::Unknown,
        AzureResourceHealthProviderError::ResourceRevisionMismatch { .. } => {
            EvidenceState::Conflict
        }
        AzureResourceHealthProviderError::RegistrationRevoked
        | AzureResourceHealthProviderError::SecretRevoked
        | AzureResourceHealthProviderError::ScopeMismatch => EvidenceState::Revoked,
    }
}

pub(crate) fn _service_api_digest() -> Digest {
    api_digest()
}
