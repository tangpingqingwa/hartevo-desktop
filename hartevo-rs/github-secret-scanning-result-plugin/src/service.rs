//! Service, registration, proposal, and recording seams for Layer 1.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, GithubSecretScanningEvidence, GithubSecretScanningScope, MAX_ALERTS, MAX_LOCATIONS,
    MAX_PAGES, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, RedactedRequestReceipt, Revision,
    SecretReference,
};
use crate::provider::{
    AlertTarget, GithubSecretScanningPage, GithubSecretScanningProvider,
    GithubSecretScanningProviderDefinition, GithubSecretScanningRequest,
    GithubSecretScanningTransport, ProviderError, ProviderErrorKind,
};
use crate::{
    CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

impl RegistrationState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub const fn is_reversed(self) -> bool {
        matches!(self, Self::Reversed)
    }

    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionState {
    Complete,
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
pub struct GithubSecretScanningRegistration {
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

pub type Registration = GithubSecretScanningRegistration;

impl GithubSecretScanningRegistration {
    pub fn new(
        scope: &GithubSecretScanningScope,
        secret: &SecretReference,
        provider: &GithubSecretScanningProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        secret.validate_for_scope(scope)?;
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
            scope_digest: scope.digest().clone(),
            query_digest: scope.query_digest().clone(),
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

    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn is_reversed(&self) -> bool {
        self.state.is_reversed()
    }

    pub fn is_revoked(&self) -> bool {
        self.state.is_revoked()
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.api_revision != crate::PROVIDER_API_REVISION
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
        scope: &GithubSecretScanningScope,
        secret: &SecretReference,
        provider: &GithubSecretScanningProviderDefinition,
    ) -> Result<(), ServiceError> {
        scope.validate()?;
        secret.validate_for_scope(scope)?;
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
            permission_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest().clone(),
            query_digest: scope.query_digest().clone(),
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
        self.registration_revision = Revision::new(self.registration_revision.get() + 1)?;
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
            "github-secret-scanning-registration/v1",
            &[
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
    pub page_size: u16,
    pub max_alerts: usize,
    pub max_locations: usize,
    pub max_requests: usize,
    pub max_response_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: crate::model::MAX_PAGE_SIZE,
            max_alerts: MAX_ALERTS,
            max_locations: MAX_LOCATIONS,
            max_requests: MAX_REQUESTS_PER_READ,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn validate(self) -> Result<(), ServiceError> {
        if self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > crate::model::MAX_PAGE_SIZE
            || self.max_alerts == 0
            || self.max_alerts > MAX_ALERTS
            || self.max_locations == 0
            || self.max_locations > MAX_LOCATIONS
            || self.max_requests == 0
            || self.max_requests > MAX_REQUESTS_PER_READ
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            Err(ServiceError::InvalidBounds)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubSecretScanningCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub repository_list: bool,
    pub organization_list: bool,
    pub repository_single_alert: bool,
    pub organization_single_alert_from_bounded_list: bool,
    pub hide_secret: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub kernel_outcome_authority: bool,
}

#[derive(Clone, Debug)]
pub struct GithubSecretScanningServiceDefinition {
    pub capability: GithubSecretScanningCapabilityDescription,
}

pub type GithubSecretScanningServiceDefinitionAlias = GithubSecretScanningServiceDefinition;

impl GithubSecretScanningServiceDefinition {
    pub fn layer1() -> Result<Self, ServiceError> {
        let definition = Self {
            capability: GithubSecretScanningCapabilityDescription {
                service_id: SERVICE_ID.to_owned(),
                provider_id: PROVIDER_ID.to_owned(),
                contract_version: CONTRACT_VERSION.to_owned(),
                read_only: true,
                proposal_only: true,
                live_execution: false,
                repository_list: true,
                organization_list: true,
                repository_single_alert: true,
                organization_single_alert_from_bounded_list: true,
                hide_secret: true,
                external_writes: false,
                connected: false,
                native: false,
                first_party: false,
                truth_authority: false,
                kernel_outcome_authority: false,
            },
        };
        if definition.capability.service_id != SERVICE_ID
            || definition.capability.provider_id != PROVIDER_ID
            || definition.capability.contract_version != CONTRACT_VERSION
            || !definition.capability.read_only
            || !definition.capability.proposal_only
            || definition.capability.live_execution
            || definition.capability.external_writes
            || definition.capability.connected
            || definition.capability.native
            || definition.capability.first_party
        {
            Err(ServiceError::DefinitionInvalid)
        } else {
            Ok(definition)
        }
    }

    pub fn capability(&self) -> &GithubSecretScanningCapabilityDescription {
        &self.capability
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] crate::model::ModelError),
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("GitHub SecretReference has been revoked")]
    SecretRevoked,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration has been revoked")]
    RegistrationRevoked,
    #[error("registration is not reversible in its current state")]
    RegistrationNotReversible,
    #[error("registration integrity or binding drifted")]
    RegistrationTampered,
    #[error("provider or API definition drifted")]
    ProviderDrift,
    #[error("permission binding drifted")]
    PermissionDrift,
    #[error("installation binding drifted")]
    InstallationDrift,
    #[error("repository or organization binding drifted")]
    RepositoryDrift,
    #[error("query binding drifted")]
    QueryDrift,
    #[error("alert state is stale")]
    StaleAlertState,
    #[error("alert validity is stale")]
    StaleValidity,
    #[error("alert identity drifted")]
    AlertDrift,
    #[error("pagination cursor loop detected")]
    CursorLoop,
    #[error("duplicate alert evidence detected")]
    DuplicateAlert,
    #[error("provider response is partial or location evidence is incomplete")]
    PartialEvidence,
    #[error("provider access was lost")]
    AccessLoss,
    #[error("provider rejected the bounded read")]
    ProviderRejected,
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("provider response was not found")]
    AlertNotFound,
    #[error("read bounds are invalid")]
    InvalidBounds,
    #[error("service definition is invalid")]
    DefinitionInvalid,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("proposal integrity or registration binding is stale")]
    StaleProposal,
    #[error("recording integrity or registration binding is stale")]
    StaleRecording,
    #[error("unsupported provider response")]
    UnsupportedResponse,
}

pub type GithubSecretScanningServiceError = ServiceError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubSecretScanningProposal {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence: GithubSecretScanningEvidence,
    pub idempotency_key_digest: Digest,
    pub proposed_at: DateTime<Utc>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_kernel_outcome: bool,
    pub proposal_digest: Digest,
}

pub type GithubSecretScanningResultProposal = GithubSecretScanningProposal;

impl GithubSecretScanningProposal {
    fn new(
        scope: &GithubSecretScanningScope,
        registration: &GithubSecretScanningRegistration,
        evidence: GithubSecretScanningEvidence,
        idempotency_key: &str,
        proposed_at: DateTime<Utc>,
    ) -> Self {
        let idempotency_key_digest = Digest::from_parts(
            "github-secret-scanning-idempotency/v1",
            &[idempotency_key.to_owned(), scope.digest().to_string()],
        );
        let mut proposal = Self {
            scope_digest: scope.digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            evidence,
            idempotency_key_digest,
            proposed_at,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_kernel_outcome: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn validate_integrity(
        &self,
        scope: &GithubSecretScanningScope,
        registration: &GithubSecretScanningRegistration,
    ) -> Result<(), ServiceError> {
        if self.scope_digest != *scope.digest()
            || self.registration_digest != registration.registration_digest
            || !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.adopts_kernel_outcome
            || self.evidence.validate(scope).is_err()
            || self.proposal_digest != self.computed_digest()
        {
            Err(ServiceError::StaleProposal)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.registration_digest,
            &self.evidence,
            &self.idempotency_key_digest,
            self.proposed_at,
            self.read_only,
            self.proposal_only,
            self.connected,
            self.native,
            self.first_party,
            self.adopts_kernel_outcome,
        ))
    }

    pub fn recomputed_digest_for_consumer(&self) -> Digest {
        self.computed_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubSecretScanningRecordReceipt {
    pub recorded: bool,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub recorded_at: DateTime<Utc>,
    pub durable_provider_receipt: bool,
    pub provider_mutated: bool,
    pub record_digest: Digest,
}

pub type GithubSecretScanningRecording = GithubSecretScanningRecordReceipt;

impl GithubSecretScanningRecordReceipt {
    fn from_proposal(proposal: &GithubSecretScanningProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            recorded_at,
            durable_provider_receipt: false,
            provider_mutated: false,
            record_digest: Digest::zero(),
        };
        receipt.record_digest = receipt.computed_digest();
        receipt
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if !self.recorded
            || self.durable_provider_receipt
            || self.provider_mutated
            || self.proposal_digest.is_zero()
            || self.evidence_digest.is_zero()
            || self.record_digest != self.computed_digest()
        {
            Err(ServiceError::StaleRecording)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.record_digest
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.recorded,
            &self.proposal_digest,
            &self.registration_digest,
            &self.evidence_digest,
            self.recorded_at,
            self.durable_provider_receipt,
            self.provider_mutated,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubSecretScanningVerifiedRecord {
    pub record_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub integrity_valid: bool,
    pub provider_readback_performed: bool,
    pub security_certification_authority: bool,
    pub kernel_outcome_authority: bool,
}

#[derive(Clone, Debug)]
pub struct GithubSecretScanningService<T> {
    scope: GithubSecretScanningScope,
    secret: SecretReference,
    provider: GithubSecretScanningProvider<T>,
    definition: GithubSecretScanningServiceDefinition,
    registration: GithubSecretScanningRegistration,
    limits: ReadLimits,
}

pub type GithubSecretScanningResultService<T> = GithubSecretScanningService<T>;

impl<T: GithubSecretScanningTransport> GithubSecretScanningService<T> {
    pub fn new(
        scope: GithubSecretScanningScope,
        secret: SecretReference,
        provider: GithubSecretScanningProvider<T>,
    ) -> Result<Self, ServiceError> {
        Self::with_limits(scope, secret, provider, ReadLimits::default())
    }

    pub fn with_limits(
        scope: GithubSecretScanningScope,
        secret: SecretReference,
        provider: GithubSecretScanningProvider<T>,
        limits: ReadLimits,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        secret.validate_for_scope(&scope)?;
        if secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        limits.validate()?;
        provider
            .definition()
            .validate(&scope.permissions)
            .map_err(|_| ServiceError::ProviderDrift)?;
        let definition = GithubSecretScanningServiceDefinition::layer1()?;
        let registration = GithubSecretScanningRegistration::new(
            &scope,
            &secret,
            provider.definition(),
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret,
            provider,
            definition,
            registration,
            limits,
        })
    }

    pub fn scope(&self) -> &GithubSecretScanningScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn provider(&self) -> &GithubSecretScanningProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GithubSecretScanningProvider<T> {
        &mut self.provider
    }

    pub fn provider_definition(&self) -> &GithubSecretScanningProviderDefinition {
        self.provider.definition()
    }

    pub fn definition(&self) -> &GithubSecretScanningServiceDefinition {
        &self.definition
    }

    pub fn capabilities(&self) -> &GithubSecretScanningCapabilityDescription {
        self.definition.capability()
    }

    pub fn registration(&self) -> &GithubSecretScanningRegistration {
        &self.registration
    }

    pub fn limits(&self) -> ReadLimits {
        self.limits
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        self.registration.restore()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionReceipt, ServiceError> {
        self.secret
            .revoke()
            .map_err(|_| ServiceError::SecretRevoked)?;
        self.registration.revoke()
    }

    pub fn read_evidence(&mut self) -> Result<GithubSecretScanningEvidence, ServiceError> {
        self.read_repository_evidence()
    }

    pub fn read_bounded(
        &mut self,
        target: AlertTarget,
    ) -> Result<GithubSecretScanningEvidence, ServiceError> {
        match target {
            AlertTarget::Repository => self.read_repository_evidence(),
            AlertTarget::Organization => self.read_organization_evidence(),
        }
    }

    pub fn read_repository_evidence(
        &mut self,
    ) -> Result<GithubSecretScanningEvidence, ServiceError> {
        self.ensure_active()?;
        let (summary, mut receipts) = self.find_in_pages(AlertTarget::Repository)?;
        let summary = summary.ok_or(ServiceError::AlertNotFound)?;
        let detail = self
            .provider
            .get_repository_alert(&self.scope, self.scope.alert_number)
            .map_err(map_provider_error)?;
        receipts.push(self.receipt_for_alert(&detail));
        if detail.alert.digest() != summary.digest() {
            return Err(ServiceError::AlertDrift);
        }
        self.finish_evidence(detail.alert, receipts)
    }

    pub fn read_organization_evidence(
        &mut self,
    ) -> Result<GithubSecretScanningEvidence, ServiceError> {
        self.ensure_active()?;
        let (summary, receipts) = self.find_in_pages(AlertTarget::Organization)?;
        let summary = summary.ok_or(ServiceError::AlertNotFound)?;
        self.finish_evidence(summary, receipts)
    }

    pub fn read_organization_alert(
        &mut self,
    ) -> Result<GithubSecretScanningEvidence, ServiceError> {
        self.read_organization_evidence()
    }

    pub fn compile_proposal(
        &mut self,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GithubSecretScanningProposal, ServiceError> {
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.len() > crate::model::MAX_IDENTIFIER_BYTES
            || idempotency_key.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ServiceError::InvalidIdempotencyKey);
        }
        let evidence = self.read_evidence()?;
        Ok(GithubSecretScanningProposal::new(
            &self.scope,
            &self.registration,
            evidence,
            idempotency_key,
            Utc::now(),
        ))
    }

    pub fn propose(
        &mut self,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GithubSecretScanningProposal, ServiceError> {
        self.compile_proposal(idempotency_key)
    }

    pub fn record_proposal(
        &self,
        proposal: &GithubSecretScanningProposal,
    ) -> Result<GithubSecretScanningRecordReceipt, ServiceError> {
        self.ensure_active()?;
        self.registration
            .validate(&self.scope, &self.secret, self.provider.definition())?;
        proposal.validate_integrity(&self.scope, &self.registration)?;
        Ok(GithubSecretScanningRecordReceipt::from_proposal(
            proposal,
            Utc::now(),
        ))
    }

    pub fn record(
        &self,
        proposal: &GithubSecretScanningProposal,
    ) -> Result<GithubSecretScanningRecordReceipt, ServiceError> {
        self.record_proposal(proposal)
    }

    pub fn verify_recording(
        &self,
        proposal: &GithubSecretScanningProposal,
        recording: &GithubSecretScanningRecordReceipt,
    ) -> Result<GithubSecretScanningVerifiedRecord, ServiceError> {
        self.ensure_active()?;
        self.registration
            .validate(&self.scope, &self.secret, self.provider.definition())?;
        proposal.validate_integrity(&self.scope, &self.registration)?;
        recording.validate_integrity()?;
        if recording.proposal_digest != *proposal.digest()
            || recording.registration_digest != self.registration.registration_digest
            || recording.evidence_digest != *proposal.evidence.digest()
        {
            return Err(ServiceError::StaleRecording);
        }
        Ok(GithubSecretScanningVerifiedRecord {
            record_digest: recording.record_digest.clone(),
            registration_digest: recording.registration_digest.clone(),
            evidence_digest: recording.evidence_digest.clone(),
            integrity_valid: true,
            provider_readback_performed: false,
            security_certification_authority: false,
            kernel_outcome_authority: false,
        })
    }

    fn ensure_active(&self) -> Result<(), ServiceError> {
        if self.secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        if !self.registration.is_active() {
            return if self.registration.is_revoked() {
                Err(ServiceError::RegistrationRevoked)
            } else {
                Err(ServiceError::RegistrationInactive)
            };
        }
        self.registration
            .validate(&self.scope, &self.secret, self.provider.definition())
    }

    fn find_in_pages(
        &mut self,
        target: AlertTarget,
    ) -> Result<
        (
            Option<crate::model::SecretScanningAlert>,
            Vec<RedactedRequestReceipt>,
        ),
        ServiceError,
    > {
        let mut page_number = 1_u16;
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_alerts = BTreeSet::new();
        let mut receipts = Vec::new();
        let mut found = None;
        loop {
            if page_number > self.limits.max_pages || receipts.len() >= self.limits.max_requests {
                return Err(ServiceError::PartialEvidence);
            }
            let request = match target {
                AlertTarget::Repository => GithubSecretScanningRequest::list_repository(
                    &self.scope,
                    page_number,
                    cursor.clone(),
                ),
                AlertTarget::Organization => GithubSecretScanningRequest::list_organization(
                    &self.scope,
                    page_number,
                    cursor.clone(),
                ),
            }
            .map_err(ServiceError::Provider)?;
            let page = match target {
                AlertTarget::Repository => {
                    self.provider
                        .list_repository_alerts(&self.scope, page_number, cursor.clone())
                }
                AlertTarget::Organization => {
                    self.provider
                        .list_organization_alerts(&self.scope, page_number, cursor.clone())
                }
            }
            .map_err(map_provider_error)?;
            let receipt = Self::receipt_for_page(&request, &page)?;
            receipts.push(receipt);
            if page.items.len() > self.limits.max_alerts {
                return Err(ServiceError::PartialEvidence);
            }
            for alert in page.items {
                if !seen_alerts.insert(alert.number) {
                    return Err(ServiceError::DuplicateAlert);
                }
                if seen_alerts.len() > self.limits.max_alerts {
                    return Err(ServiceError::PartialEvidence);
                }
                if alert.number != self.scope.alert_number {
                    continue;
                }
                self.validate_alert_binding(&alert, target)?;
                if found.replace(alert).is_some() {
                    return Err(ServiceError::DuplicateAlert);
                }
            }
            match page.next_cursor {
                Some(next) => {
                    let digest = next.digest();
                    if !seen_cursors.insert(digest.clone()) {
                        return Err(ServiceError::CursorLoop);
                    }
                    cursor = Some(next);
                    page_number += 1;
                }
                None => break,
            }
        }
        Ok((found, receipts))
    }

    fn validate_alert_binding(
        &self,
        alert: &crate::model::SecretScanningAlert,
        target: AlertTarget,
    ) -> Result<(), ServiceError> {
        if alert.number != self.scope.alert_number {
            return Ok(());
        }
        if alert.state != self.scope.expected_alert_state {
            return Err(ServiceError::StaleAlertState);
        }
        if alert.validity != self.scope.expected_validity {
            return Err(ServiceError::StaleValidity);
        }
        if alert.installation_digest != self.scope.installation_digest() {
            return Err(ServiceError::InstallationDrift);
        }
        if alert.organization_digest != self.scope.organization_digest() {
            return Err(ServiceError::RepositoryDrift);
        }
        if target == AlertTarget::Repository
            && alert.repository_digest != self.scope.repository_digest()
            || (target == AlertTarget::Organization
                && alert.repository_digest != self.scope.repository_digest())
        {
            return Err(ServiceError::RepositoryDrift);
        }
        if alert.ref_digest != self.scope.ref_digest()
            || alert.commit_digest != self.scope.commit_digest()
        {
            return Err(ServiceError::AlertDrift);
        }
        if !self.scope.query.allows(
            alert.state,
            alert.validity,
            &alert.secret_type.secret_type_digest,
        ) {
            return Err(ServiceError::QueryDrift);
        }
        if alert.locations.is_empty()
            || alert.has_more_locations
            || alert.locations.len() > self.limits.max_locations
        {
            return Err(ServiceError::PartialEvidence);
        }
        if alert.locations.iter().any(|location| {
            location.commit_digest != self.scope.commit_digest()
                || location.ref_digest != self.scope.ref_digest()
        }) {
            return Err(ServiceError::AlertDrift);
        }
        Ok(())
    }

    fn receipt_for_page(
        request: &GithubSecretScanningRequest,
        page: &GithubSecretScanningPage,
    ) -> Result<RedactedRequestReceipt, ServiceError> {
        RedactedRequestReceipt::new(
            request.operation,
            request.endpoint_digest.clone(),
            request.query_digest.clone(),
            request.page,
            request
                .cursor
                .as_ref()
                .map(crate::model::OpaqueCursor::digest),
            page.status,
            page.response_digest.clone(),
            page.rate.clone(),
        )
        .map_err(ServiceError::Model)
    }

    fn receipt_for_alert(
        &self,
        response: &crate::provider::GithubSecretScanningAlertResponse,
    ) -> RedactedRequestReceipt {
        let request =
            GithubSecretScanningRequest::get_repository(&self.scope, self.scope.alert_number)
                .expect("scope alert request is valid");
        RedactedRequestReceipt::new(
            request.operation,
            request.endpoint_digest,
            request.query_digest,
            request.page,
            None,
            response.status,
            response.response_digest.clone(),
            response.rate.clone(),
        )
        .expect("bounded provider receipt is valid")
    }

    fn finish_evidence(
        &self,
        alert: crate::model::SecretScanningAlert,
        receipts: Vec<RedactedRequestReceipt>,
    ) -> Result<GithubSecretScanningEvidence, ServiceError> {
        self.validate_alert_binding(&alert, AlertTarget::Repository)?;
        if receipts.len() > self.limits.max_requests {
            return Err(ServiceError::PartialEvidence);
        }
        GithubSecretScanningEvidence::new(&self.scope, alert, receipts, self.provider.provenance())
            .map_err(ServiceError::Model)
    }
}

fn map_provider_error(error: ProviderError) -> ServiceError {
    match error.kind {
        ProviderErrorKind::Unauthorized
        | ProviderErrorKind::Forbidden
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::AccessLoss => ServiceError::AccessLoss,
        ProviderErrorKind::Conflict
        | ProviderErrorKind::Unprocessable
        | ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServiceUnavailable
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::ScriptExhausted => ServiceError::ProviderRejected,
        ProviderErrorKind::CursorLoop => ServiceError::CursorLoop,
        ProviderErrorKind::Partial => ServiceError::PartialEvidence,
        ProviderErrorKind::Tampered | ProviderErrorKind::ResponseTooLarge => {
            ServiceError::TamperedEvidence
        }
        ProviderErrorKind::BlockedEnv => ServiceError::AccessLoss,
        ProviderErrorKind::InvalidRequest => ServiceError::ProviderRejected,
    }
}

impl fmt::Display for GithubSecretScanningProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GithubSecretScanningProposal({})",
            self.proposal_digest
        )
    }
}

pub type GithubSecretScanningReadResult = GithubSecretScanningEvidence;
pub type GithubSecretScanningRecord = GithubSecretScanningRecordReceipt;
pub type GithubSecretScanningServiceDefinitionPublic = GithubSecretScanningServiceDefinition;
