use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AccessDecision, DevicePostureProjection, Digest, EvidenceClassification, EvidenceState,
    IdempotencyKey, ModelError, PolicyProjection, PostureState, Revision, SecretReference,
    TailscaleNetworkPostureScope, TailscaleOperation, TailscaleReadRequest,
    TailscaleRedactedReceipt, TransportProvenance, canonical_digest, domain_digest,
};
use crate::provider::{
    TailscaleProvider, TailscaleProviderDefinition, TailscaleProviderError, TailscaleTransport,
    TransportError,
};
use crate::{
    CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
    SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TailscaleNetworkPostureResultServiceError {
    #[error("Tailscale registration is revoked")]
    RegistrationRevoked,
    #[error("Tailscale registration is reversed")]
    RegistrationReversed,
    #[error("Tailscale secret reference is revoked")]
    SecretRevoked,
    #[error("Tailscale consent scope is denied or stale")]
    ConsentMismatch,
    #[error("Tailscale scope does not match the registered Mission/Work Product scope")]
    ScopeMismatch,
    #[error("Tailscale revision fence failed")]
    RevisionMismatch,
    #[error("Tailscale evidence or proposal digest fence failed")]
    EvidenceTampered,
    #[error("Tailscale proposal replay was rejected")]
    ReplayDetected,
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("Tailscale provider definition drifted")]
    DefinitionDrift,
    #[error("Tailscale registration integrity is invalid")]
    InvalidRegistration,
    #[error("Tailscale proposal is invalid for Mission consumption")]
    InvalidProposal,
    #[error("Layer-1 Tailscale operation is read-only: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error(transparent)]
    Provider(Box<TailscaleProviderError>),
    #[error(transparent)]
    Model(#[from] ModelError),
}

pub type ServiceError = TailscaleNetworkPostureResultServiceError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransition {
    pub from: RegistrationState,
    pub to: RegistrationState,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reason_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_api_revision: String,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub device_digest: Digest,
    pub posture_digest: Digest,
    pub policy_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type TailscaleNetworkPostureResultRegistration = TailscaleRegistration;

impl TailscaleRegistration {
    #[must_use]
    pub fn bind(
        scope: &TailscaleNetworkPostureScope,
        secret: &SecretReference,
        definition: &TailscaleProviderDefinition,
    ) -> Self {
        let mut registration = Self {
            plugin_id: crate::PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: definition.provider_version.clone(),
            provider_api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_digest: definition.digest(),
            scope_digest: scope.digest(),
            revision_fence_digest: scope.revision_fence_digest(),
            device_digest: scope.device_digest(),
            posture_digest: scope.posture_digest(),
            policy_digest: scope.policy_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest(),
            secret_reference_digest: secret.digest(),
            registration_revision: Revision::new(1).expect("registration revision"),
            registration_digest: String::new(),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
            connected: false,
            native: false,
            first_party: false,
        };
        registration.registration_digest = registration.calculate_digest();
        registration
    }

    #[must_use]
    pub fn state(&self) -> RegistrationState {
        self.state
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.registration_digest.clear();
        domain_digest("hartevo:tailscale-network-posture:registration:v1", &copy)
    }

    pub fn validate(
        &self,
        scope: &TailscaleNetworkPostureScope,
        secret: &SecretReference,
        definition: &TailscaleProviderDefinition,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.plugin_id != crate::PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_version != definition.provider_version
            || self.provider_api_revision != PROVIDER_API_REVISION
            || self.provider_digest != definition.digest()
            || self.scope_digest != scope.digest()
            || self.revision_fence_digest != scope.revision_fence_digest()
            || self.device_digest != scope.device_digest()
            || self.posture_digest != scope.posture_digest()
            || self.policy_digest != scope.policy_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.consent_digest != scope.consent_digest()
            || self.secret_reference_digest != secret.digest()
            || !self.reversible
            || !self.revocable
            || self.connected
            || self.native
            || self.first_party
            || self.registration_digest != self.calculate_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    fn transition(
        &mut self,
        to: RegistrationState,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition, ModelError> {
        let from = self.state;
        if from == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        if from == to {
            return Err(ModelError::InvalidScope("registration transition"));
        }
        if to == RegistrationState::Active && from != RegistrationState::Reversed {
            return Err(ModelError::NotRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = to;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransition {
            from,
            to,
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reason_digest: domain_digest(
                "hartevo:tailscale-network-posture:registration-reason:v1",
                &reason.as_ref(),
            ),
            reversible: self.reversible,
            revocable: self.revocable,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn reverse(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.transition(RegistrationState::Reversed, reason)
    }

    pub fn restore(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition, ModelError> {
        self.transition(RegistrationState::Active, reason)
    }

    pub fn revoke(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.transition(RegistrationState::Revoked, reason)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_provider_payload_dropped: bool,
    pub raw_node_addresses_dropped: bool,
    pub raw_tailnet_name_dropped: bool,
    pub raw_tag_values_dropped: bool,
    pub raw_acl_expressions_dropped: bool,
    pub raw_grant_principals_dropped: bool,
    pub raw_secret_dropped: bool,
}

impl RedactionSummary {
    #[must_use]
    pub const fn layer_one() -> Self {
        Self {
            raw_provider_payload_dropped: true,
            raw_node_addresses_dropped: true,
            raw_tailnet_name_dropped: true,
            raw_tag_values_dropped: true,
            raw_acl_expressions_dropped: true,
            raw_grant_principals_dropped: true,
            raw_secret_dropped: true,
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.raw_provider_payload_dropped
            && self.raw_node_addresses_dropped
            && self.raw_tailnet_name_dropped
            && self.raw_tag_values_dropped
            && self.raw_acl_expressions_dropped
            && self.raw_grant_principals_dropped
            && self.raw_secret_dropped
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Denied,
    Expired,
    Unknown,
    Partial,
    RateLimited,
    ProviderUnknown,
    Tamper,
    AccessLoss,
}

impl From<EvidenceState> for Option<FailureKind> {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Allowed => None,
            EvidenceState::Denied => Some(FailureKind::Denied),
            EvidenceState::Expired => Some(FailureKind::Expired),
            EvidenceState::Unknown => Some(FailureKind::Unknown),
            EvidenceState::Partial => Some(FailureKind::Partial),
            EvidenceState::RateLimited => Some(FailureKind::RateLimited),
            EvidenceState::ProviderUnknown => Some(FailureKind::ProviderUnknown),
            EvidenceState::Tamper => Some(FailureKind::Tamper),
            EvidenceState::AccessLoss => Some(FailureKind::AccessLoss),
            EvidenceState::RegistrationRevoked => Some(FailureKind::ProviderUnknown),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub kind: FailureKind,
    pub state: EvidenceState,
    pub provider_provenance: TransportProvenance,
    pub response_digest: Option<Digest>,
    pub response_bytes: usize,
    pub retry_after_seconds: Option<u32>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    #[must_use]
    pub fn new(
        state: EvidenceState,
        provenance: TransportProvenance,
        response_digest: Option<Digest>,
        response_bytes: usize,
        retry_after_seconds: Option<u32>,
    ) -> Self {
        let kind = <Option<FailureKind>>::from(state).expect("failure state has a failure kind");
        let failure_digest = domain_digest(
            "hartevo:tailscale-network-posture:failure:v1",
            &(
                kind,
                state,
                provenance,
                &response_digest,
                response_bytes,
                retry_after_seconds,
            ),
        );
        Self {
            kind,
            state,
            provider_provenance: provenance,
            response_digest,
            response_bytes,
            retry_after_seconds,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleNetworkPostureEvidence {
    pub evidence_level: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub provider_api_revision: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub device_digest: Digest,
    pub posture_digest: Digest,
    pub policy_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub response_digest: Option<Digest>,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub classification: EvidenceClassification,
    pub access_decision: AccessDecision,
    pub provenance: TransportProvenance,
    pub device: Option<DevicePostureProjection>,
    pub posture: Option<PostureState>,
    pub policy: Option<PolicyProjection>,
    pub grant: Option<PolicyProjection>,
    pub failure: Option<FailureEvidence>,
    pub receipts: Vec<TailscaleRedactedReceipt>,
    pub redactions: RedactionSummary,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub network_reachability_claim: bool,
    pub effective_authorization_claim: bool,
    pub access_certification_claim: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

impl TailscaleNetworkPostureEvidence {
    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.evidence_digest.clear();
        domain_digest("hartevo:tailscale-network-posture:evidence:v1", &copy)
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if !self.redactions.is_complete()
            || self.connected
            || self.native
            || self.first_party
            || self.network_reachability_claim
            || self.effective_authorization_claim
            || self.access_certification_claim
            || self.outcome_authority
            || self.work_product_adopted
            || self
                .receipts
                .iter()
                .any(|receipt| receipt.validate_integrity().is_err())
            || self.evidence_digest != self.calculate_digest()
        {
            Err(ServiceError::EvidenceTampered)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        !self.connected
            && !self.native
            && !self.first_party
            && !self.access_certification_claim
            && !self.outcome_authority
            && !self.work_product_adopted
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

pub type TailscaleNetworkPostureReadEvidence = TailscaleNetworkPostureEvidence;
pub type TailscaleNetworkPostureReadResult = TailscaleNetworkPostureEvidence;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleNetworkPostureProposal {
    pub request: TailscaleReadRequest,
    pub evidence: TailscaleNetworkPostureEvidence,
    pub state: EvidenceState,
    pub request_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type TailscaleNetworkPostureResult = TailscaleNetworkPostureProposal;
pub type TailscaleNetworkPostureResultProposal = TailscaleNetworkPostureProposal;

impl TailscaleNetworkPostureProposal {
    #[must_use]
    pub fn new(
        request: TailscaleReadRequest,
        evidence: TailscaleNetworkPostureEvidence,
        replayed: bool,
    ) -> Self {
        let mut proposal = Self {
            state: evidence.state,
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest.clone(),
            request,
            evidence,
            proposal_digest: String::new(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        domain_digest("hartevo:tailscale-network-posture:proposal:v1", &copy)
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.state != self.evidence.state
            || self.request_digest != self.request.request_digest()
            || self.idempotency_key_digest != self.request.idempotency_key_digest
            || self.connected
            || self.native
            || self.first_party
            || self.evidence.validate_integrity().is_err()
            || self.proposal_digest != self.calculate_digest()
        {
            Err(ServiceError::EvidenceTampered)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        self.evidence.is_review_only()
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordDisposition {
    New,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleRecordReceipt {
    pub proposal_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub record_digest: Digest,
    pub disposition: RecordDisposition,
    pub durable: bool,
    pub provider_receipt: bool,
    pub independent_native_reread: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub work_product_adopted: bool,
}

impl TailscaleRecordReceipt {
    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.record_digest.clear();
        domain_digest("hartevo:tailscale-network-posture:record:v1", &copy)
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.durable
            || self.provider_receipt
            || self.independent_native_reread
            || self.connected
            || self.native
            || self.first_party
            || self.work_product_adopted
            || self.record_digest != self.calculate_digest()
        {
            Err(ServiceError::EvidenceTampered)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    ProposalTampered,
    RegistrationDrift,
    ScopeDrift,
    RevisionDrift,
    ProviderDrift,
    NonLayerOneAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerification {
    pub valid: bool,
    pub review_eligible: bool,
    pub failure: Option<VerificationFailure>,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
}

pub type TailscaleVerificationReport = EvidenceVerification;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleCapabilities {
    pub evidence_level: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub device_mutation: bool,
    pub acl_mutation: bool,
    pub grant_mutation: bool,
    pub key_mutation: bool,
    pub network_reachability: bool,
    pub effective_authorization: bool,
    pub access_certification: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
    pub allowed_operations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleNetworkPostureResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub evidence_level: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub first_party: bool,
    pub access_certification: bool,
    pub outcome_authority: bool,
    pub external_writes: bool,
}

pub type TailscaleNetworkPostureServiceDefinition = TailscaleNetworkPostureResultServiceDefinition;

impl Default for TailscaleNetworkPostureResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            contract_digest: contract_digest(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            native_provider: false,
            connected: false,
            first_party: false,
            access_certification: false,
            outcome_authority: false,
            external_writes: false,
        }
    }
}

impl TailscaleNetworkPostureResultServiceDefinition {
    pub fn validate(&self) -> Result<(), ServiceError> {
        if self != &Self::default()
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.native_provider
            || self.connected
            || self.first_party
            || self.access_certification
            || self.outcome_authority
            || self.external_writes
        {
            Err(ServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }
}

pub struct TailscaleNetworkPostureResultService<T: TailscaleTransport> {
    scope: TailscaleNetworkPostureScope,
    secret_reference: SecretReference,
    provider: TailscaleProvider<T>,
    registration: TailscaleRegistration,
    definition: TailscaleNetworkPostureResultServiceDefinition,
    proposals: BTreeMap<Digest, TailscaleNetworkPostureProposal>,
    records: BTreeMap<Digest, TailscaleRecordReceipt>,
}

pub type TailscaleNetworkPostureService<T> = TailscaleNetworkPostureResultService<T>;

impl<T: TailscaleTransport> fmt::Debug for TailscaleNetworkPostureResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TailscaleNetworkPostureResultService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("proposal_count", &self.proposals.len())
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: TailscaleTransport> TailscaleNetworkPostureResultService<T> {
    pub fn new(
        scope: TailscaleNetworkPostureScope,
        secret_reference: SecretReference,
        provider: TailscaleProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        if secret_reference.scope_digest() != &scope.digest()
            || secret_reference.revision() != scope.scope_revision
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let definition = TailscaleNetworkPostureResultServiceDefinition::default();
        definition.validate()?;
        provider
            .definition()
            .validate()
            .map_err(|error| ServiceError::Provider(Box::new(error)))?;
        let registration =
            TailscaleRegistration::bind(&scope, &secret_reference, provider.definition());
        registration
            .validate(&scope, &secret_reference, provider.definition())
            .map_err(|_| ServiceError::InvalidRegistration)?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            definition,
            proposals: BTreeMap::new(),
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &TailscaleNetworkPostureScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn provider(&self) -> &TailscaleProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut TailscaleProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &TailscaleRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut TailscaleRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn service_definition(&self) -> &TailscaleNetworkPostureResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.registration.state == RegistrationState::Active && !self.secret_reference.revoked()
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> TailscaleCapabilities {
        TailscaleCapabilities {
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            device_mutation: false,
            acl_mutation: false,
            grant_mutation: false,
            key_mutation: false,
            network_reachability: false,
            effective_authorization: false,
            access_certification: false,
            outcome_adoption: false,
            work_product_adoption: false,
            allowed_operations: vec![
                TailscaleOperation::Devices.path().to_owned(),
                TailscaleOperation::DevicePosture.path().to_owned(),
                TailscaleOperation::AclPolicy.path().to_owned(),
                TailscaleOperation::Grants.path().to_owned(),
            ],
        }
    }

    pub fn default_request(&self) -> Result<TailscaleReadRequest, ServiceError> {
        let key = IdempotencyKey::new("tailscale-network-posture-default")?;
        TailscaleReadRequest::device_posture(&self.scope, &key).map_err(ServiceError::from)
    }

    fn validate_ready(&self, request: &TailscaleReadRequest) -> Result<(), ServiceError> {
        if self.registration.state == RegistrationState::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        if self.registration.state == RegistrationState::Reversed {
            return Err(ServiceError::RegistrationReversed);
        }
        if self.secret_reference.revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        self.scope.validate()?;
        if self.secret_reference.scope_digest() != &self.scope.digest()
            || self.secret_reference.revision() != self.scope.scope_revision
        {
            return Err(ServiceError::ScopeMismatch);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.definition(),
            )
            .map_err(|_| ServiceError::InvalidRegistration)?;
        request.validate(&self.scope).map_err(|error| match error {
            ModelError::InvalidRequest => ServiceError::ScopeMismatch,
            ModelError::InvalidDigest => ServiceError::RevisionMismatch,
            other => ServiceError::Model(other),
        })
    }

    pub fn read(
        &mut self,
        request: TailscaleReadRequest,
    ) -> Result<TailscaleNetworkPostureEvidence, ServiceError> {
        Ok(self.propose(request)?.evidence)
    }

    pub fn read_bounded(
        &mut self,
        request: TailscaleReadRequest,
    ) -> Result<TailscaleNetworkPostureEvidence, ServiceError> {
        self.read(request)
    }

    pub fn read_request(
        &mut self,
        request: &TailscaleReadRequest,
    ) -> Result<TailscaleNetworkPostureEvidence, ServiceError> {
        self.read(request.clone())
    }

    pub fn propose(
        &mut self,
        request: TailscaleReadRequest,
    ) -> Result<TailscaleNetworkPostureProposal, ServiceError> {
        self.validate_ready(&request)?;
        let request_digest = request.request_digest();
        if let Some(existing) = self.proposals.get(&request.idempotency_key_digest) {
            if existing.request_digest != request_digest {
                return Err(ServiceError::IdempotencyConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }

        let evidence = match self.provider.read(&request) {
            Ok(response) => match self.success_evidence(&request, &response) {
                Ok(evidence) => evidence,
                Err(ServiceError::Provider(error)) => {
                    self.failure_evidence(&request, error.as_ref(), self.provider.provenance())
                }
                Err(ServiceError::EvidenceTampered) => {
                    self.tamper_evidence(&request, self.provider.provenance(), None, 0)
                }
                Err(error) => return Err(error),
            },
            Err(error) => {
                if error.evidence_state().is_some() {
                    self.failure_evidence(&request, &error, self.provider.provenance())
                } else {
                    return Err(ServiceError::Provider(Box::new(error)));
                }
            }
        };
        let proposal = TailscaleNetworkPostureProposal::new(request, evidence, false);
        proposal.validate_integrity()?;
        self.proposals
            .insert(proposal.idempotency_key_digest.clone(), proposal.clone());
        Ok(proposal)
    }

    pub fn register(&self) -> Result<TailscaleRegistration, ServiceError> {
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.definition(),
            )
            .map_err(|_| ServiceError::InvalidRegistration)?;
        Ok(self.registration.clone())
    }

    pub fn reverse_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition, ServiceError> {
        self.registration
            .reverse(reason)
            .map_err(ServiceError::from)
    }

    pub fn restore_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition, ServiceError> {
        self.registration
            .restore(reason)
            .map_err(ServiceError::from)
    }

    pub fn revoke_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition, ServiceError> {
        self.registration.revoke(reason).map_err(ServiceError::from)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.revoke().map_err(ServiceError::from)
    }

    pub fn restore_secret_reference(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.restore().map_err(ServiceError::from)
    }

    pub fn record(
        &mut self,
        proposal: &TailscaleNetworkPostureProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<TailscaleRecordReceipt, ServiceError> {
        proposal.validate_integrity()?;
        let key = IdempotencyKey::new(idempotency_key)?;
        if let Some(existing) = self.records.get(key.digest()) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ServiceError::IdempotencyConflict);
            }
            let mut replay = existing.clone();
            replay.disposition = RecordDisposition::Replay;
            replay.record_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let mut receipt = TailscaleRecordReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key_digest: key.digest().clone(),
            record_digest: String::new(),
            disposition: RecordDisposition::New,
            durable: false,
            provider_receipt: false,
            independent_native_reread: false,
            connected: false,
            native: false,
            first_party: false,
            work_product_adopted: false,
        };
        receipt.record_digest = receipt.calculate_digest();
        receipt.validate_integrity()?;
        self.records
            .insert(receipt.idempotency_key_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn verify(&self, proposal: &TailscaleNetworkPostureProposal) -> EvidenceVerification {
        let valid = proposal.validate_integrity().is_ok()
            && proposal.request.validate(&self.scope).is_ok()
            && proposal.evidence.registration_digest == self.registration.registration_digest
            && proposal.evidence.scope_digest == self.scope.digest()
            && proposal.evidence.revision_fence_digest == self.scope.revision_fence_digest()
            && self.registration.state == RegistrationState::Active
            && !self.secret_reference.revoked();
        EvidenceVerification {
            valid,
            review_eligible: valid && proposal.evidence.is_review_only(),
            failure: (!valid).then_some(VerificationFailure::ProposalTampered),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
        }
    }

    pub fn verify_record(&self, receipt: &TailscaleRecordReceipt) -> Result<(), ServiceError> {
        receipt.validate_integrity()?;
        if self.records.get(&receipt.idempotency_key_digest) != Some(receipt) {
            return Err(ServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn consumer(
        &self,
    ) -> Result<crate::consumer::MissionTailscaleNetworkConsumer, ServiceError> {
        crate::consumer::MissionTailscaleNetworkConsumer::new(
            self.scope.clone(),
            self.registration.clone(),
        )
        .map_err(|_| ServiceError::InvalidRegistration)
    }

    fn success_evidence(
        &self,
        request: &TailscaleReadRequest,
        response: &crate::TailscaleResponse,
    ) -> Result<TailscaleNetworkPostureEvidence, ServiceError> {
        let value = response.json_value().map_err(|_| {
            ServiceError::Provider(Box::new(TailscaleProviderError::MalformedResponse {
                request: request.clone(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
            }))
        })?;
        let parsed = match self.parse_payload(request, &value) {
            Ok(parsed) => parsed,
            Err(ServiceError::EvidenceTampered) => {
                return Err(ServiceError::Provider(Box::new(
                    TailscaleProviderError::ResponseTamper {
                        request: request.clone(),
                        response_digest: response.response_digest(),
                        response_bytes: response.response_bytes(),
                    },
                )));
            }
            Err(error) => return Err(error),
        };
        let receipt = TailscaleRedactedReceipt::new(request, response, self.provider.provenance());
        let mut evidence = self.make_evidence_base(
            request,
            Some(response.response_digest()),
            parsed.state,
            parsed.classification,
            parsed.access_decision,
            parsed.device,
            parsed.posture,
            parsed.policy,
            parsed.grant,
            None,
            vec![receipt],
            self.provider.provenance(),
            response.status() == 206,
        );
        evidence.evidence_digest = evidence.calculate_digest();
        Ok(evidence)
    }

    fn make_evidence_base(
        &self,
        request: &TailscaleReadRequest,
        response_digest: Option<Digest>,
        state: EvidenceState,
        classification: EvidenceClassification,
        access_decision: AccessDecision,
        device: Option<DevicePostureProjection>,
        posture: Option<PostureState>,
        policy: Option<PolicyProjection>,
        grant: Option<PolicyProjection>,
        failure: Option<FailureEvidence>,
        receipts: Vec<TailscaleRedactedReceipt>,
        provenance: TransportProvenance,
        partial: bool,
    ) -> TailscaleNetworkPostureEvidence {
        TailscaleNetworkPostureEvidence {
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_digest: self.provider.definition().digest(),
            provider_api_revision: PROVIDER_API_REVISION.to_owned(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            revision_fence_digest: self.scope.revision_fence_digest(),
            device_digest: self.scope.device_digest(),
            posture_digest: self.scope.posture_digest(),
            policy_digest: self.scope.policy_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            consent_digest: self.scope.consent_digest(),
            request_digest: request.request_digest(),
            idempotency_key_digest: request.idempotency_key_digest.clone(),
            response_digest,
            evidence_digest: String::new(),
            state,
            classification,
            access_decision,
            provenance,
            device,
            posture,
            policy,
            grant,
            failure,
            receipts,
            redactions: RedactionSummary::layer_one(),
            partial,
            connected: false,
            native: false,
            first_party: false,
            network_reachability_claim: false,
            effective_authorization_claim: false,
            access_certification_claim: false,
            outcome_authority: false,
            work_product_adopted: false,
        }
    }

    fn failure_evidence(
        &self,
        request: &TailscaleReadRequest,
        error: &TailscaleProviderError,
        provenance: TransportProvenance,
    ) -> TailscaleNetworkPostureEvidence {
        let state = error
            .evidence_state()
            .unwrap_or(EvidenceState::ProviderUnknown);
        let (response_digest, response_bytes, retry_after_seconds) = provider_metadata(error);
        let failure = FailureEvidence::new(
            state,
            provenance,
            response_digest.clone(),
            response_bytes,
            retry_after_seconds,
        );
        let classification = failure_classification(state, provenance);
        let mut evidence = self.make_evidence_base(
            request,
            response_digest,
            state,
            classification,
            AccessDecision::Unknown,
            None,
            None,
            None,
            None,
            Some(failure),
            Vec::new(),
            provenance,
            matches!(state, EvidenceState::Partial),
        );
        evidence.evidence_digest = evidence.calculate_digest();
        evidence
    }

    fn tamper_evidence(
        &self,
        request: &TailscaleReadRequest,
        provenance: TransportProvenance,
        response_digest: Option<Digest>,
        response_bytes: usize,
    ) -> TailscaleNetworkPostureEvidence {
        let failure = FailureEvidence::new(
            EvidenceState::Tamper,
            provenance,
            response_digest.clone(),
            response_bytes,
            None,
        );
        let mut evidence = self.make_evidence_base(
            request,
            response_digest,
            EvidenceState::Tamper,
            EvidenceClassification::Tamper,
            AccessDecision::Unknown,
            None,
            None,
            None,
            None,
            Some(failure),
            Vec::new(),
            provenance,
            false,
        );
        evidence.evidence_digest = evidence.calculate_digest();
        evidence
    }

    fn parse_payload(
        &self,
        request: &TailscaleReadRequest,
        value: &Value,
    ) -> Result<ParsedPayload, ServiceError> {
        let mut parsed = ParsedPayload {
            state: EvidenceState::Unknown,
            classification: self.provider.provenance().into(),
            access_decision: AccessDecision::Unknown,
            device: None,
            posture: None,
            policy: None,
            grant: None,
        };
        match request.operation {
            TailscaleOperation::Devices => {
                let items = array_at(value, &["devices", "nodes"]);
                let (device_count, tag_count, tag_digest, posture) =
                    device_summary(items, &self.scope, false)?;
                parsed.posture = Some(posture);
                parsed.device = Some(DevicePostureProjection::new(
                    &self.scope,
                    posture,
                    device_count,
                    tag_count,
                    tag_digest,
                )?);
                parsed.state = posture_state(posture);
                parsed.classification =
                    classification_for_success(parsed.state, self.provider.provenance());
            }
            TailscaleOperation::DevicePosture => {
                validate_target_and_revision(
                    value,
                    self.scope.device.id(),
                    self.scope.device.revision,
                    "device",
                )?;
                let posture_items = value
                    .get("devices")
                    .and_then(Value::as_array)
                    .map_or_else(|| std::slice::from_ref(value), Vec::as_slice);
                let (device_count, tag_count, tag_digest, posture) =
                    device_summary(posture_items, &self.scope, true)?;
                parsed.posture = Some(posture);
                parsed.device = Some(DevicePostureProjection::new(
                    &self.scope,
                    posture,
                    device_count,
                    tag_count,
                    tag_digest,
                )?);
                parsed.state = posture_state(posture);
                parsed.classification =
                    classification_for_success(parsed.state, self.provider.provenance());
            }
            TailscaleOperation::AclPolicy => {
                validate_target_and_revision(
                    value,
                    self.scope.acl.id(),
                    self.scope.acl.revision,
                    "acl_policy",
                )?;
                let policy = policy_summary(value, &self.scope, false)?;
                parsed.access_decision = policy.access_decision;
                parsed.state = decision_state(policy.access_decision);
                parsed.classification =
                    classification_for_success(parsed.state, self.provider.provenance());
                parsed.policy = Some(policy);
            }
            TailscaleOperation::Grants => {
                validate_target_and_revision(
                    value,
                    self.scope.grant.id(),
                    self.scope.grant.revision,
                    "grant",
                )?;
                let policy = policy_summary(value, &self.scope, true)?;
                parsed.access_decision = policy.access_decision;
                parsed.state = decision_state(policy.access_decision);
                parsed.classification =
                    classification_for_success(parsed.state, self.provider.provenance());
                parsed.grant = Some(policy);
            }
        }
        if parsed.state == EvidenceState::Unknown
            && value.get("partial").and_then(Value::as_bool) == Some(true)
        {
            parsed.state = EvidenceState::Partial;
            parsed.classification = EvidenceClassification::Partial;
        }
        Ok(parsed)
    }
}

struct ParsedPayload {
    state: EvidenceState,
    classification: EvidenceClassification,
    access_decision: AccessDecision,
    device: Option<DevicePostureProjection>,
    posture: Option<PostureState>,
    policy: Option<PolicyProjection>,
    grant: Option<PolicyProjection>,
}

fn provider_metadata(error: &TailscaleProviderError) -> (Option<Digest>, usize, Option<u32>) {
    match error {
        TailscaleProviderError::ResponseTooLarge {
            response_digest,
            response_bytes,
            ..
        }
        | TailscaleProviderError::HttpStatus {
            response_digest,
            response_bytes,
            ..
        }
        | TailscaleProviderError::MalformedResponse {
            response_digest,
            response_bytes,
            ..
        } => (Some(response_digest.clone()), *response_bytes, None),
        TailscaleProviderError::RateLimited {
            response_digest,
            response_bytes,
            rate_limit,
            ..
        } => (
            Some(response_digest.clone()),
            *response_bytes,
            rate_limit.retry_after_seconds,
        ),
        TailscaleProviderError::Transport { error, .. } => (
            None,
            0,
            match error {
                TransportError::RateLimited {
                    retry_after_seconds,
                } => Some(*retry_after_seconds),
                _ => None,
            },
        ),
        TailscaleProviderError::ResponseTamper { .. }
        | TailscaleProviderError::ScopeMismatch
        | TailscaleProviderError::ProviderDrift
        | TailscaleProviderError::NotAllowlisted
        | TailscaleProviderError::InvalidRateLimitReceipt
        | TailscaleProviderError::Model(_) => (None, 0, None),
    }
}

fn failure_classification(
    state: EvidenceState,
    provenance: TransportProvenance,
) -> EvidenceClassification {
    match state {
        EvidenceState::Denied => EvidenceClassification::Denied,
        EvidenceState::Expired => EvidenceClassification::Expired,
        EvidenceState::Unknown | EvidenceState::RegistrationRevoked => {
            EvidenceClassification::Unknown
        }
        EvidenceState::Partial => EvidenceClassification::Partial,
        EvidenceState::RateLimited => EvidenceClassification::RateLimited,
        EvidenceState::ProviderUnknown => {
            if provenance == TransportProvenance::BlockedEnv {
                EvidenceClassification::BlockedEnv
            } else {
                EvidenceClassification::ProviderUnknown
            }
        }
        EvidenceState::Tamper => EvidenceClassification::Tamper,
        EvidenceState::AccessLoss => EvidenceClassification::AccessLoss,
        EvidenceState::Allowed => provenance.into(),
    }
}

fn classification_for_success(
    state: EvidenceState,
    provenance: TransportProvenance,
) -> EvidenceClassification {
    if state == EvidenceState::Partial {
        EvidenceClassification::Partial
    } else {
        provenance.into()
    }
}

fn posture_state(posture: PostureState) -> EvidenceState {
    match posture {
        PostureState::Compliant => EvidenceState::Allowed,
        PostureState::NonCompliant => EvidenceState::Denied,
        PostureState::Expired => EvidenceState::Expired,
        PostureState::Unknown => EvidenceState::Unknown,
        PostureState::Partial => EvidenceState::Partial,
    }
}

fn decision_state(decision: AccessDecision) -> EvidenceState {
    match decision {
        AccessDecision::Allowed => EvidenceState::Allowed,
        AccessDecision::Denied => EvidenceState::Denied,
        AccessDecision::Expired => EvidenceState::Expired,
        AccessDecision::Unknown => EvidenceState::Unknown,
    }
}

fn array_at<'a>(value: &'a Value, names: &[&str]) -> &'a [Value] {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_array))
        .map_or(&[], Vec::as_slice)
}

fn device_summary(
    items: &[Value],
    scope: &TailscaleNetworkPostureScope,
    require_target: bool,
) -> Result<(usize, usize, Digest, PostureState), ServiceError> {
    if items.len() > crate::MAX_DEVICES {
        return Err(ServiceError::Model(ModelError::CountExceeded));
    }
    let mut target_seen = false;
    let mut tag_digests = Vec::new();
    let mut posture = PostureState::Unknown;
    for item in items {
        if let Some(revision) = numeric_revision(item) {
            if revision != scope.device.revision.get() {
                return Err(ServiceError::EvidenceTampered);
            }
        } else if item.get("revision").is_some() {
            return Err(ServiceError::EvidenceTampered);
        }
        if let Some(id) = text_field(item, &["id", "deviceId", "nodeId"]) {
            let candidate = crate::DeviceId::new(id).map_err(|_| ServiceError::EvidenceTampered)?;
            if candidate.digest() == scope.device.id_digest() {
                target_seen = true;
            }
        }
        if let Some(tags) = item.get("tags").and_then(Value::as_array) {
            if tags.len() > crate::MAX_TAGS {
                return Err(ServiceError::Model(ModelError::CountExceeded));
            }
            for tag in tags.iter().filter_map(Value::as_str) {
                tag_digests.push(domain_digest(
                    "hartevo:tailscale-network-posture:tag-value:v1",
                    &tag,
                ));
            }
        }
        let item_posture = parse_posture(item);
        if item_posture != PostureState::Unknown {
            posture = item_posture;
        }
    }
    if require_target && !items.is_empty() && !target_seen {
        return Err(ServiceError::EvidenceTampered);
    }
    if !items.is_empty()
        && !target_seen
        && items
            .iter()
            .any(|item| text_field(item, &["id", "deviceId", "nodeId"]).is_some())
    {
        return Err(ServiceError::EvidenceTampered);
    }
    tag_digests.sort_unstable();
    let tag_digest = canonical_digest(&tag_digests);
    Ok((items.len(), tag_digests.len(), tag_digest, posture))
}

fn policy_summary(
    value: &Value,
    scope: &TailscaleNetworkPostureScope,
    grants: bool,
) -> Result<PolicyProjection, ServiceError> {
    let acl_count = array_at(value, &["acls", "rules", "acl"]).len();
    let grant_count = array_at(value, &["grants", "grant"]).len();
    if acl_count > crate::MAX_ACL_RULES || grant_count > crate::MAX_GRANTS {
        return Err(ServiceError::Model(ModelError::CountExceeded));
    }
    PolicyProjection::new(
        scope,
        acl_count,
        grant_count,
        posture_condition_count(value),
        parse_decision(value),
    )
    .map_err(ServiceError::from)
    .map(|mut projection| {
        if grants && projection.grant_count == 0 {
            projection.grant_count = u16::try_from(grant_count).unwrap_or(u16::MAX);
        }
        projection
    })
}

fn validate_target_and_revision(
    value: &Value,
    expected_id: &crate::Identifier,
    expected_revision: Revision,
    label: &'static str,
) -> Result<(), ServiceError> {
    if let Some(id) = text_field(value, &["id", "deviceId", "nodeId", "policyId", "grantId"]) {
        let candidate = crate::Identifier::new(id).map_err(|_| ServiceError::EvidenceTampered)?;
        if candidate.digest() != expected_id.digest() {
            return Err(ServiceError::EvidenceTampered);
        }
    }
    if let Some(revision) = numeric_revision(value) {
        if revision != expected_revision.get() {
            return Err(ServiceError::EvidenceTampered);
        }
    } else if value.get("revision").is_some() {
        return Err(ServiceError::EvidenceTampered);
    }
    let _ = label;
    Ok(())
}

fn text_field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
}

fn numeric_revision(value: &Value) -> Option<u64> {
    value
        .get("revision")
        .and_then(Value::as_u64)
        .or_else(|| value.get("revision").and_then(Value::as_str)?.parse().ok())
}

fn parse_posture(value: &Value) -> PostureState {
    if value.get("postureCompliant").and_then(Value::as_bool) == Some(true) {
        return PostureState::Compliant;
    }
    if value.get("postureCompliant").and_then(Value::as_bool) == Some(false) {
        return PostureState::NonCompliant;
    }
    let posture = text_field(value, &["posture", "postureState", "status"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    match posture.as_str() {
        "compliant" | "healthy" | "pass" | "passed" | "ok" | "ready" => PostureState::Compliant,
        "non_compliant" | "noncompliant" | "unhealthy" | "fail" | "failed" | "deny" => {
            PostureState::NonCompliant
        }
        "expired" => PostureState::Expired,
        "partial" => PostureState::Partial,
        _ => PostureState::Unknown,
    }
}

fn parse_decision(value: &Value) -> AccessDecision {
    if value.get("allow").and_then(Value::as_bool) == Some(true) {
        return AccessDecision::Allowed;
    }
    if value.get("allow").and_then(Value::as_bool) == Some(false) {
        return AccessDecision::Denied;
    }
    let decision = text_field(value, &["decision", "action", "access"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    match decision.as_str() {
        "allow" | "allowed" | "accept" | "accepted" | "permit" | "permitted" => {
            AccessDecision::Allowed
        }
        "deny" | "denied" | "reject" | "rejected" => AccessDecision::Denied,
        "expired" => AccessDecision::Expired,
        _ => AccessDecision::Unknown,
    }
}

fn posture_condition_count(value: &Value) -> usize {
    let mut count = 0;
    count_posture_conditions(value, &mut count);
    count.min(crate::MAX_ACL_RULES)
}

fn count_posture_conditions(value: &Value, count: &mut usize) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "srcPosture" | "src_posture" | "postureCondition"
                ) {
                    *count = count.saturating_add(1);
                }
                count_posture_conditions(child, count);
            }
        }
        Value::Array(items) => {
            for item in items {
                count_posture_conditions(item, count);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
