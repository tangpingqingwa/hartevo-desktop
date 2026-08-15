//! Service, registration, proposal, and local-recording seams for Layer 1.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, EvidenceStatus, GitGuardianEvidence, GitGuardianIncident, GitGuardianOccurrence,
    GitGuardianScope, GitGuardianSecretReference, IncidentStatus, MAX_REQUESTS_PER_READ,
    MAX_RESPONSE_BYTES, ModelError, OpaqueCursor, RedactedRateReceipt, RedactedRequestReceipt,
    Revision, SecretReference,
};
use crate::provider::{
    GitGuardianHealth, GitGuardianProvider, GitGuardianProviderDefinition, GitGuardianRequest,
    GitGuardianResponse, GitGuardianTransport, ProviderError, ProviderErrorKind,
};
use crate::{
    CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

impl RegistrationState {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    #[must_use]
    pub const fn is_reversed(self) -> bool {
        matches!(self, Self::Reversed)
    }

    #[must_use]
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationTransition {
    Reversed,
    Restored,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionReceipt {
    pub transition: RegistrationTransition,
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitGuardianRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: Revision,
    pub provider_digest: Digest,
    pub api_revision: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

pub type Registration = GitGuardianRegistration;
pub type GitGuardianSecretResultRegistration = GitGuardianRegistration;

impl GitGuardianRegistration {
    pub fn new(
        scope: &GitGuardianScope,
        secret: &SecretReference,
        provider: &GitGuardianProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self, ServiceError> {
        scope.validate().map_err(ServiceError::from)?;
        secret
            .validate_for_scope(scope)
            .map_err(ServiceError::from)?;
        if secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest.clone(),
            api_revision: provider.api_revision.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: provider.permission_digest.clone(),
            scope_digest: scope.digest(),
            query_digest: scope.query_digest(),
            evidence_policy_digest: scope.evidence_policy_digest.clone(),
            evidence_digest: scope.evidence_binding_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate(scope, secret, provider)?;
        Ok(registration)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    #[must_use]
    pub const fn is_reversed(&self) -> bool {
        self.state.is_reversed()
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.state.is_revoked()
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision.get() == 0
            || self.registration_revision.get() == 0
            || self.provider_digest.validate().is_err()
            || self.api_digest.validate().is_err()
            || self.permission_digest.validate().is_err()
            || self.scope_digest.validate().is_err()
            || self.query_digest.validate().is_err()
            || self.evidence_policy_digest.validate().is_err()
            || self.evidence_digest.validate().is_err()
            || self.secret_reference_digest.validate().is_err()
            || self.registration_digest != self.computed_digest()
        {
            Err(ServiceError::RegistrationTampered)
        } else {
            Ok(())
        }
    }

    pub fn validate(
        &self,
        scope: &GitGuardianScope,
        secret: &SecretReference,
        provider: &GitGuardianProviderDefinition,
    ) -> Result<(), ServiceError> {
        scope.validate().map_err(ServiceError::from)?;
        secret
            .validate_for_scope(scope)
            .map_err(ServiceError::from)?;
        provider
            .validate(&scope.permissions)
            .map_err(|_| ServiceError::ProviderDrift)?;
        let expected = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest.clone(),
            api_revision: provider.api_revision.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permissions.digest(),
            scope_digest: scope.digest(),
            query_digest: scope.query_digest(),
            evidence_policy_digest: scope.evidence_policy_digest.clone(),
            evidence_digest: scope.evidence_binding_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision: self.registration_revision,
            state: self.state,
            registration_digest: Digest::zero(),
        };
        if self.plugin_id != expected.plugin_id
            || self.plugin_version != expected.plugin_version
            || self.contract_version != expected.contract_version
            || self.contract_digest != expected.contract_digest
            || self.provider_id != expected.provider_id
            || self.provider_version != expected.provider_version
            || self.provider_revision != expected.provider_revision
            || self.provider_digest != expected.provider_digest
            || self.api_revision != expected.api_revision
            || self.api_digest != expected.api_digest
            || self.permission_digest != expected.permission_digest
            || self.scope_digest != expected.scope_digest
            || self.query_digest != expected.query_digest
            || self.evidence_policy_digest != expected.evidence_policy_digest
            || self.evidence_digest != expected.evidence_digest
            || self.secret_reference_digest != expected.secret_reference_digest
            || self.registration_revision.get() == 0
            || self.registration_digest != self.computed_digest()
        {
            Err(ServiceError::RegistrationTampered)
        } else {
            Ok(())
        }
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        if !self.state.is_active() {
            return Err(if self.state.is_revoked() {
                ServiceError::RegistrationRevoked
            } else {
                ServiceError::RegistrationNotReversible
            });
        }
        self.transition(
            RegistrationTransition::Reversed,
            RegistrationState::Reversed,
        )
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        if !self.state.is_reversed() {
            return Err(if self.state.is_revoked() {
                ServiceError::RegistrationRevoked
            } else {
                ServiceError::RegistrationNotReversible
            });
        }
        self.transition(RegistrationTransition::Restored, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        if self.state.is_revoked() {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.transition(RegistrationTransition::Revoked, RegistrationState::Revoked)
    }

    fn transition(
        &mut self,
        transition: RegistrationTransition,
        new_state: RegistrationState,
    ) -> Result<RegistrationTransitionReceipt, ServiceError> {
        let previous_state = self.state;
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(ServiceError::from)?;
        self.state = new_state;
        self.registration_digest = self.computed_digest();
        let transition_digest = Digest::from_serialized(&(
            transition,
            previous_state,
            new_state,
            &self.registration_digest,
            self.registration_revision,
        ));
        Ok(RegistrationTransitionReceipt {
            transition,
            previous_state,
            new_state,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_parts(
            "gitguardian-registration/v1",
            [
                self.plugin_id.clone(),
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.provider_revision.get().to_string(),
                self.provider_digest.to_string(),
                self.api_revision.clone(),
                self.api_digest.to_string(),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
                self.query_digest.to_string(),
                self.evidence_policy_digest.to_string(),
                self.evidence_digest.to_string(),
                self.secret_reference_digest.to_string(),
                self.registration_revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadLimits {
    pub max_pages: u16,
    pub max_requests: usize,
    pub max_response_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_pages: crate::model::MAX_PAGES,
            max_requests: MAX_REQUESTS_PER_READ,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitGuardianCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub accepts_opaque_secret_reference: bool,
    pub evidence_states: Vec<EvidenceStatus>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("scope is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is not reversible in its current state")]
    RegistrationNotReversible,
    #[error("registration is tampered")]
    RegistrationTampered,
    #[error("registration/provider drift detected")]
    ProviderDrift,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("scope or mission binding drift detected")]
    ScopeDrift,
    #[error("provider access was denied or lost")]
    Denied,
    #[error("provider rate limit requires backoff")]
    RateLimited,
    #[error("provider returned an unknown result")]
    ProviderUnknown,
    #[error("provider returned partial evidence")]
    PartialEvidence,
    #[error("provider evidence failed integrity verification")]
    TamperedEvidence,
    #[error("provider cursor repeated")]
    CursorLoop,
    #[error("provider response was stale for the registered scope")]
    StaleState,
    #[error("provider request budget was exceeded")]
    RequestBudgetExceeded,
    #[error("local recording idempotency key conflicts with another proposal")]
    IdempotencyConflict,
    #[error("local recording is invalid")]
    InvalidRecording,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitGuardianRemediationDecision {
    Review,
    RevokeOutsideLayer1,
    RotateOutsideLayer1,
    IgnoreWithJustification,
    NoAction,
    NeedsAccess,
}

impl GitGuardianRemediationDecision {
    #[must_use]
    pub const fn creates_effect(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianSecretResultProposal {
    pub mission_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence: GitGuardianEvidence,
    pub decision: GitGuardianRemediationDecision,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_kernel_outcome: bool,
    pub proposal_digest: Digest,
}

pub type GitGuardianProposal = GitGuardianSecretResultProposal;
pub type Proposal = GitGuardianSecretResultProposal;

impl GitGuardianSecretResultProposal {
    pub fn new(
        scope: &GitGuardianScope,
        registration: &GitGuardianRegistration,
        evidence: GitGuardianEvidence,
        decision: GitGuardianRemediationDecision,
    ) -> Result<Self, ServiceError> {
        evidence
            .validate_integrity(scope)
            .map_err(ServiceError::from)?;
        let mut proposal = Self {
            mission_id: scope.mission_id.as_str().to_owned(),
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
            evidence,
            decision,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_kernel_outcome: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        Ok(proposal)
    }

    pub fn validate(
        &self,
        scope: &GitGuardianScope,
        registration: &GitGuardianRegistration,
    ) -> Result<(), ServiceError> {
        if self.scope_digest != scope.digest()
            || self.registration_digest != registration.registration_digest
            || !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.adopts_kernel_outcome
            || self.proposal_digest != self.computed_digest()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        self.evidence
            .validate_integrity(scope)
            .map_err(ServiceError::from)
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.mission_id,
            &self.scope_digest,
            &self.registration_digest,
            &self.evidence,
            self.decision,
            self.read_only,
            self.proposal_only,
            self.connected,
            self.native,
            self.first_party,
            self.adopts_kernel_outcome,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianRecordReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_key: Digest,
    pub recording_digest: Digest,
    pub recorded: bool,
    pub provider_mutated: bool,
    pub durable_provider_receipt: bool,
    pub provider_readback_performed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type GitGuardianSecretResultRecording = GitGuardianRecordReceipt;
pub type GitGuardianSecretResultRecordReceipt = GitGuardianRecordReceipt;
pub type Recording = GitGuardianRecordReceipt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitGuardianVerifiedRecord {
    pub recording_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub integrity_valid: bool,
    pub provider_readback_performed: bool,
    pub security_certification_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type VerifiedRecord = GitGuardianVerifiedRecord;

#[derive(Debug)]
pub struct GitGuardianSecretResultService<T: GitGuardianTransport> {
    scope: GitGuardianScope,
    secret_reference: GitGuardianSecretReference,
    provider: GitGuardianProvider<T>,
    registration: GitGuardianRegistration,
    recordings: BTreeMap<Digest, GitGuardianRecordReceipt>,
}

pub type GitGuardianService<T> = GitGuardianSecretResultService<T>;
pub type GitGuardianResultService<T> = GitGuardianSecretResultService<T>;

impl<T: GitGuardianTransport> GitGuardianSecretResultService<T> {
    pub fn new(
        scope: GitGuardianScope,
        secret_reference: GitGuardianSecretReference,
        provider: GitGuardianProvider<T>,
    ) -> Result<Self, ServiceError> {
        let registration = GitGuardianRegistration::new(
            &scope,
            &secret_reference,
            provider.definition(),
            Revision::new(1).map_err(ServiceError::from)?,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            recordings: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GitGuardianScope {
        &self.scope
    }

    #[must_use]
    pub fn provider(&self) -> &GitGuardianProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GitGuardianProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &GitGuardianRegistration {
        &self.registration
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> GitGuardianCapabilityDescription {
        GitGuardianCapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            accepts_opaque_secret_reference: true,
            evidence_states: vec![
                EvidenceStatus::Open,
                EvidenceStatus::Resolved,
                EvidenceStatus::Ignored,
                EvidenceStatus::Unknown,
                EvidenceStatus::Partial,
                EvidenceStatus::Denied,
                EvidenceStatus::RateLimited,
                EvidenceStatus::ProviderUnknown,
                EvidenceStatus::Tampered,
            ],
        }
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        self.registration.validate_integrity()?;
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        self.registration.validate_integrity()?;
        self.registration.restore()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        self.registration.validate_integrity()?;
        let receipt = self.registration.revoke()?;
        self.secret_reference.revoke().map_err(ServiceError::from)?;
        Ok(receipt)
    }

    pub fn read_incident(&mut self) -> Result<GitGuardianIncident, ServiceError> {
        self.ensure_active()?;
        let request = GitGuardianRequest::get_incident(&self.scope).map_err(map_provider_error)?;
        let response = self
            .provider
            .read(&self.scope, &request)
            .map_err(map_provider_error)?;
        match response {
            GitGuardianResponse::Incident(response) => {
                Self::ensure_rate_receipt(&response.rate_receipt)?;
                if response.incident.incident_id != self.scope.incident_id {
                    Err(ServiceError::StaleState)
                } else {
                    Ok(response.incident)
                }
            }
            _ => Err(ServiceError::ProviderUnknown),
        }
    }

    pub fn read_detector(&mut self) -> Result<crate::model::GitGuardianDetector, ServiceError> {
        self.ensure_active()?;
        let request = GitGuardianRequest::get_detector(&self.scope).map_err(map_provider_error)?;
        let response = self
            .provider
            .read(&self.scope, &request)
            .map_err(map_provider_error)?;
        match response {
            GitGuardianResponse::Detector(response) => {
                Self::ensure_rate_receipt(&response.rate_receipt)?;
                Ok(response.detector)
            }
            _ => Err(ServiceError::ProviderUnknown),
        }
    }

    pub fn read_status(&mut self) -> Result<GitGuardianHealth, ServiceError> {
        self.ensure_active()?;
        let request = GitGuardianRequest::get_status(&self.scope).map_err(map_provider_error)?;
        let response = self
            .provider
            .read(&self.scope, &request)
            .map_err(map_provider_error)?;
        match response {
            GitGuardianResponse::Status(response) => {
                Self::ensure_rate_receipt(&response.rate_receipt)?;
                Ok(response.health)
            }
            _ => Err(ServiceError::ProviderUnknown),
        }
    }

    pub fn read_incident_evidence(&mut self) -> Result<GitGuardianEvidence, ServiceError> {
        self.ensure_active()?;
        let request = GitGuardianRequest::get_incident(&self.scope).map_err(map_provider_error)?;
        let response = self
            .provider
            .read(&self.scope, &request)
            .map_err(map_provider_error)?;
        let (incident, receipt, rate_receipt) = match response {
            GitGuardianResponse::Incident(response) => {
                Self::ensure_rate_receipt(&response.rate_receipt)?;
                let response_variant = GitGuardianResponse::Incident(response.clone());
                (
                    response.incident,
                    self.redacted_receipt(&request, &response_variant),
                    response.rate_receipt,
                )
            }
            _ => return Err(ServiceError::ProviderUnknown),
        };
        GitGuardianEvidence::new(
            &self.scope,
            incident,
            None,
            None,
            vec![receipt],
            vec![rate_receipt],
            self.provider.provenance(),
        )
        .map_err(ServiceError::from)
    }

    pub fn read_occurrence_evidence(&mut self) -> Result<GitGuardianEvidence, ServiceError> {
        self.read_evidence()
    }

    pub fn read_evidence(&mut self) -> Result<GitGuardianEvidence, ServiceError> {
        self.ensure_active()?;
        let mut receipts = Vec::new();
        let mut rate_receipts = Vec::new();
        let incident_request =
            GitGuardianRequest::get_incident(&self.scope).map_err(map_provider_error)?;
        let incident_response = self
            .provider
            .read(&self.scope, &incident_request)
            .map_err(map_provider_error)?;
        let incident = match incident_response {
            GitGuardianResponse::Incident(response) => {
                let response = GitGuardianResponse::Incident(response);
                receipts.push(self.redacted_receipt(&incident_request, &response));
                rate_receipts.push(response.rate_receipt().clone());
                match response {
                    GitGuardianResponse::Incident(response) => response.incident,
                    _ => unreachable!("response variant is fixed"),
                }
            }
            _ => return Err(ServiceError::ProviderUnknown),
        };

        let mut occurrences = Vec::new();
        let mut page = 1;
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        loop {
            if receipts.len() >= MAX_REQUESTS_PER_READ {
                return Err(ServiceError::RequestBudgetExceeded);
            }
            let request = GitGuardianRequest::list_occurrences(&self.scope, page, cursor.clone())
                .map_err(map_provider_error)?;
            let response = self
                .provider
                .read(&self.scope, &request)
                .map_err(map_provider_error)?;
            let response = match response {
                GitGuardianResponse::OccurrencePage(response) => response,
                _ => return Err(ServiceError::ProviderUnknown),
            };
            Self::ensure_rate_receipt(&response.rate_receipt)?;
            let response_variant = GitGuardianResponse::OccurrencePage(response.clone());
            receipts.push(self.redacted_receipt(&request, &response_variant));
            rate_receipts.push(response.rate_receipt.clone());
            occurrences.extend(
                response
                    .items
                    .into_iter()
                    .filter(|occurrence| occurrence.occurrence_id == self.scope.occurrence_id),
            );
            let next_cursor = response.next_cursor;
            let Some(next_cursor_value) = next_cursor else {
                break;
            };
            let cursor_key = next_cursor_value.token_digest().clone();
            if !seen_cursors.insert(cursor_key) {
                return Err(ServiceError::CursorLoop);
            }
            if page >= self.scope.query.max_pages || page >= crate::model::MAX_PAGES {
                return Err(ServiceError::PartialEvidence);
            }
            cursor = Some(next_cursor_value);
            page += 1;
        }

        if occurrences.len() > 1 {
            return Err(ServiceError::TamperedEvidence);
        }
        let occurrence = occurrences.pop();

        if receipts.len() >= MAX_REQUESTS_PER_READ {
            return Err(ServiceError::RequestBudgetExceeded);
        }
        let detector_request =
            GitGuardianRequest::get_detector(&self.scope).map_err(map_provider_error)?;
        let detector_response = self
            .provider
            .read(&self.scope, &detector_request)
            .map_err(map_provider_error)?;
        let detector = match detector_response {
            GitGuardianResponse::Detector(response) => {
                Self::ensure_rate_receipt(&response.rate_receipt)?;
                let response = GitGuardianResponse::Detector(response);
                receipts.push(self.redacted_receipt(&detector_request, &response));
                rate_receipts.push(response.rate_receipt().clone());
                match response {
                    GitGuardianResponse::Detector(response) => Some(response.detector),
                    _ => unreachable!("response variant is fixed"),
                }
            }
            _ => return Err(ServiceError::ProviderUnknown),
        };

        GitGuardianEvidence::new(
            &self.scope,
            incident,
            occurrence,
            detector,
            receipts,
            rate_receipts,
            self.provider.provenance(),
        )
        .map_err(ServiceError::from)
    }

    pub fn propose(
        &mut self,
        mission_id: impl Into<String>,
    ) -> Result<GitGuardianSecretResultProposal, ServiceError> {
        self.ensure_active()?;
        let mission_id = mission_id.into();
        if mission_id != self.scope.mission_id.as_str() {
            return Err(ServiceError::ScopeDrift);
        }
        let evidence = self.read_evidence()?;
        GitGuardianSecretResultProposal::new(
            &self.scope,
            &self.registration,
            evidence,
            GitGuardianRemediationDecision::Review,
        )
    }

    pub fn record(
        &mut self,
        proposal: &GitGuardianSecretResultProposal,
    ) -> Result<GitGuardianRecordReceipt, ServiceError> {
        self.ensure_active()?;
        proposal.validate(&self.scope, &self.registration)?;
        let idempotency_key = Digest::from_parts(
            "gitguardian-recording-idempotency/v1",
            [
                proposal.proposal_digest.to_string(),
                proposal.evidence.digest().to_string(),
                self.registration.registration_digest.to_string(),
            ],
        );
        if let Some(existing) = self.recordings.get(&idempotency_key) {
            if existing.proposal_digest == proposal.proposal_digest {
                return Ok(existing.clone());
            }
            return Err(ServiceError::IdempotencyConflict);
        }
        let recording_digest = Digest::from_parts(
            "gitguardian-local-recording/v1",
            [
                proposal.proposal_digest.to_string(),
                proposal.evidence.digest().to_string(),
                idempotency_key.to_string(),
            ],
        );
        let receipt = GitGuardianRecordReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digest().clone(),
            idempotency_key: idempotency_key.clone(),
            recording_digest,
            recorded: true,
            provider_mutated: false,
            durable_provider_receipt: false,
            provider_readback_performed: false,
            connected: false,
            native: false,
            first_party: false,
        };
        self.recordings.insert(idempotency_key, receipt.clone());
        Ok(receipt)
    }

    pub fn verify_recording(
        &self,
        proposal: &GitGuardianSecretResultProposal,
        recording: &GitGuardianRecordReceipt,
    ) -> Result<GitGuardianVerifiedRecord, ServiceError> {
        proposal.validate(&self.scope, &self.registration)?;
        let expected_key = Digest::from_parts(
            "gitguardian-recording-idempotency/v1",
            [
                proposal.proposal_digest.to_string(),
                proposal.evidence.digest().to_string(),
                self.registration.registration_digest.to_string(),
            ],
        );
        if recording.idempotency_key != expected_key
            || recording.proposal_digest != proposal.proposal_digest
            || recording.evidence_digest != *proposal.evidence.digest()
            || !recording.recorded
            || recording.provider_mutated
            || recording.durable_provider_receipt
            || recording.provider_readback_performed
            || recording.connected
            || recording.native
            || recording.first_party
        {
            return Err(ServiceError::InvalidRecording);
        }
        Ok(GitGuardianVerifiedRecord {
            recording_digest: recording.recording_digest.clone(),
            proposal_digest: recording.proposal_digest.clone(),
            evidence_digest: recording.evidence_digest.clone(),
            integrity_valid: true,
            provider_readback_performed: false,
            security_certification_authority: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    fn ensure_active(&self) -> Result<(), ServiceError> {
        self.registration.validate(
            &self.scope,
            &self.secret_reference,
            self.provider.definition(),
        )?;
        if self.secret_reference.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        if self.registration.is_revoked() {
            Err(ServiceError::RegistrationRevoked)
        } else if !self.registration.is_active() {
            Err(ServiceError::RegistrationInactive)
        } else {
            Ok(())
        }
    }

    fn redacted_receipt(
        &self,
        request: &GitGuardianRequest,
        response: &GitGuardianResponse,
    ) -> RedactedRequestReceipt {
        RedactedRequestReceipt::new(
            request.method(),
            request.endpoint_digest.clone(),
            request.request_digest.clone(),
            response.response_digest().clone(),
            Some(200),
            response.response_bytes(),
            self.provider.provenance(),
        )
        .expect("provider response is bounded and request is GET")
    }

    fn ensure_rate_receipt(receipt: &RedactedRateReceipt) -> Result<(), ServiceError> {
        if receipt.limited {
            Err(ServiceError::RateLimited)
        } else {
            Ok(())
        }
    }
}

fn map_provider_error(error: ProviderError) -> ServiceError {
    match error.kind {
        ProviderErrorKind::Unauthorized
        | ProviderErrorKind::Forbidden
        | ProviderErrorKind::NotFound => ServiceError::Denied,
        ProviderErrorKind::RateLimited => ServiceError::RateLimited,
        ProviderErrorKind::Partial => ServiceError::PartialEvidence,
        ProviderErrorKind::CursorLoop => ServiceError::CursorLoop,
        ProviderErrorKind::Tampered => ServiceError::TamperedEvidence,
        ProviderErrorKind::ProviderUnknown
        | ProviderErrorKind::ServiceUnavailable
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::FixtureExhausted
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::Unprocessable
        | ProviderErrorKind::InvalidRequest => ServiceError::ProviderUnknown,
    }
}

impl From<ProviderErrorKind> for ServiceError {
    fn from(kind: ProviderErrorKind) -> Self {
        map_provider_error(ProviderError::new(kind, "provider_error"))
    }
}

impl fmt::Display for GitGuardianSecretResultProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitGuardian proposal state={:?} evidence_digest={}",
            self.evidence.state,
            self.evidence.digest()
        )
    }
}

pub type GitGuardianSecretResultServiceDefinition = GitGuardianCapabilityDescription;
pub type ServiceDefinition = GitGuardianCapabilityDescription;
pub type GitGuardianServiceError = ServiceError;
pub type GitGuardianRecord = GitGuardianRecordReceipt;
pub type GitGuardianVerifiedRecording = GitGuardianVerifiedRecord;
pub type GitGuardianResultProposal = GitGuardianSecretResultProposal;
pub type GitGuardianDecision = GitGuardianRemediationDecision;

// Kept public for callers that want to classify a typed provider error before
// handing it to a service. It does not expose any provider payload.
pub fn classify_provider_error(kind: ProviderErrorKind) -> EvidenceStatus {
    match kind {
        ProviderErrorKind::Unauthorized
        | ProviderErrorKind::Forbidden
        | ProviderErrorKind::NotFound => EvidenceStatus::Denied,
        ProviderErrorKind::RateLimited => EvidenceStatus::RateLimited,
        ProviderErrorKind::Tampered => EvidenceStatus::Tampered,
        ProviderErrorKind::Partial | ProviderErrorKind::CursorLoop => EvidenceStatus::Partial,
        _ => EvidenceStatus::ProviderUnknown,
    }
}

#[allow(dead_code)]
fn _keep_typed_values_visible(
    _incident_status: IncidentStatus,
    _occurrence: Option<GitGuardianOccurrence>,
    _cursor: Option<OpaqueCursor>,
    _rate: RedactedRateReceipt,
) {
}
