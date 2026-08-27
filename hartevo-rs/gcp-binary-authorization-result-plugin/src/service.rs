use std::{collections::BTreeSet, fmt};

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId as RuntimeServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_ID, GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_SCHEMA,
    GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_JSON,
    GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION,
    GCP_BINARY_AUTHORIZATION_RESULT_PLUGIN_VERSION_TEXT,
    GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID, GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_SCHEMA,
    GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_ID, GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_NAME,
    GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_SCHEMA, contract_digest,
    model::{
        AdversarialFinding, AttestationOccurrenceReference, AttestorSummary, Digest,
        EvidenceCompleteness, EvidenceDigests, GcpBinaryAuthorizationRegistration,
        GcpBinaryAuthorizationScope, Layer1EvidenceAuthority, ModelError, PolicySummary,
        ProviderErrorEvidence, ProviderErrorKind, ProviderFence, RegistrationState, Revision,
        SecretReference, ValidationDecision, ValidationReason,
    },
    provider::{
        AttestorGetRequest, GcpBinaryAuthorizationProviderApi,
        GcpBinaryAuthorizationProviderDefinition, PolicyGetRequest, ProviderError,
        ProviderProvenance, TransportError, ValidateAttestationOccurrenceRequest,
        ValidationResponse,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpBinaryAuthorizationOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    GetPolicy,
    GetAttestor,
    ProposeValidateAttestationOccurrence,
    RecordValidateAttestationOccurrence,
    VerifyValidateAttestationOccurrence,
    ConsumeObservation,
}

impl GcpBinaryAuthorizationOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::GetPolicy,
        Self::GetAttestor,
        Self::ProposeValidateAttestationOccurrence,
        Self::RecordValidateAttestationOccurrence,
        Self::VerifyValidateAttestationOccurrence,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpBinaryAuthorizationCapability {
    pub capability_id: String,
    pub operation: GcpBinaryAuthorizationOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
    pub bypasses_consent_effect: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpBinaryAuthorizationServiceDefinition {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<GcpBinaryAuthorizationCapability>,
}

impl Default for GcpBinaryAuthorizationServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpBinaryAuthorizationServiceDefinition {
    pub fn new() -> Self {
        let capability_names = [
            (
                "gcp.binary-authorization.result.register",
                GcpBinaryAuthorizationOperation::Register,
            ),
            (
                "gcp.binary-authorization.result.revoke_registration",
                GcpBinaryAuthorizationOperation::RevokeRegistration,
            ),
            (
                "gcp.binary-authorization.result.get_policy",
                GcpBinaryAuthorizationOperation::GetPolicy,
            ),
            (
                "gcp.binary-authorization.result.get_attestor",
                GcpBinaryAuthorizationOperation::GetAttestor,
            ),
            (
                "gcp.binary-authorization.result.propose_validateAttestationOccurrence",
                GcpBinaryAuthorizationOperation::ProposeValidateAttestationOccurrence,
            ),
            (
                "gcp.binary-authorization.result.record_validateAttestationOccurrence",
                GcpBinaryAuthorizationOperation::RecordValidateAttestationOccurrence,
            ),
            (
                "gcp.binary-authorization.result.verify_validateAttestationOccurrence",
                GcpBinaryAuthorizationOperation::VerifyValidateAttestationOccurrence,
            ),
            (
                "gcp.binary-authorization.result.consume_observation",
                GcpBinaryAuthorizationOperation::ConsumeObservation,
            ),
        ];
        let capabilities = capability_names
            .into_iter()
            .map(
                |(capability_id, operation)| GcpBinaryAuthorizationCapability {
                    capability_id: capability_id.to_owned(),
                    operation,
                    read_only: true,
                    mutates_provider: false,
                    native_evidence: false,
                    bypasses_consent_effect: false,
                },
            )
            .collect();
        Self {
            service_id: GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_ID.to_owned(),
            service_name: GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[GcpBinaryAuthorizationCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<GcpBinaryAuthorizationCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(
        &self,
    ) -> Result<ServiceDefinition, GcpBinaryAuthorizationServiceError> {
        let service_id = RuntimeServiceId::new(self.service_id.clone())?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(GcpBinaryAuthorizationServiceError::Plugin)
    }

    pub fn validate(&self) -> Result<(), GcpBinaryAuthorizationServiceError> {
        if self.service_id != GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_ID
            || self.service_name != GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native_evidence
                    || capability.bypasses_consent_effect
            })
        {
            return Err(GcpBinaryAuthorizationServiceError::InvalidServiceDefinition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpBinaryAuthorizationServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("provider transport returned {0:?}")]
    Transport(TransportError),
    #[error("provider definition is invalid: {0}")]
    ProviderDefinition(#[from] crate::provider::ProviderDefinitionError),
    #[error("service definition is invalid")]
    InvalidServiceDefinition,
    #[error("the registration is revoked")]
    Revoked,
    #[error("the proposal, record, or evidence is bound to a different registration")]
    RegistrationMismatch,
    #[error("the proposal, record, or evidence is bound to a different scope")]
    ScopeMismatch,
    #[error("the validation record is a replay of a different proposal")]
    ReplayDetected,
    #[error("the validation record or response was tampered with")]
    TamperDetected,
    #[error("the response image digest does not match the scoped image")]
    ImageDigestMismatch,
    #[error("a revoked attestor cannot yield an allow decision")]
    RevokedAttestorAllowed,
    #[error("the response policy or attestor summary is invalid")]
    InvalidProviderSummary,
    #[error("plugin runtime rejected the contribution: {0}")]
    Plugin(#[from] hartevo_plugin_runtime::PluginError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReadEvidence {
    pub policy: PolicySummary,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub authority: Layer1EvidenceAuthority,
}

impl PolicyReadEvidence {
    fn new(
        policy: PolicySummary,
        request: &PolicyGetRequest,
        response_digest: Digest,
        provider_digest: Digest,
        provenance: ProviderProvenance,
    ) -> Self {
        let evidence_digest = Digest::from_fields(
            "gcp-binary-authorization-policy-read-evidence/v1",
            &[
                request.request_digest().as_str().to_owned(),
                response_digest.as_str().to_owned(),
                policy.policy_content_digest().as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                request.scope_digest.as_str().to_owned(),
                request.permission_digest.as_str().to_owned(),
                request.consent_digest.as_str().to_owned(),
            ],
        );
        Self {
            policy,
            request_digest: request.request_digest(),
            response_digest,
            provider_digest,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            consent_digest: request.consent_digest.clone(),
            provenance,
            evidence_digest,
            authority: Layer1EvidenceAuthority,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBinaryAuthorizationProposal {
    pub request: ValidateAttestationOccurrenceRequest,
    pub policy: PolicySummary,
    pub attestor: AttestorSummary,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub proposal_digest: Digest,
}

impl GcpBinaryAuthorizationProposal {
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn status_scope_digest(&self) -> &Digest {
        &self.request.scope_digest
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-validation-proposal/v1",
            &[
                self.request.request_digest.as_str().to_owned(),
                self.policy.policy_content_digest().as_str().to_owned(),
                self.attestor.attestor_digest().as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                self.provider_digest.as_str().to_owned(),
                self.version_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
            ],
        )
    }

    fn validate_digest(&self) -> Result<(), GcpBinaryAuthorizationServiceError> {
        if self.proposal_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(GcpBinaryAuthorizationServiceError::TamperDetected)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBinaryAuthorizationRecord {
    pub proposal: GcpBinaryAuthorizationProposal,
    pub response: ValidationResponse,
    pub provenance: ProviderProvenance,
    pub record_digest: Digest,
}

impl GcpBinaryAuthorizationRecord {
    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-validation-record/v1",
            &[
                self.proposal.proposal_digest.as_str().to_owned(),
                self.response.response_digest.as_str().to_owned(),
                self.response.request_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
            ],
        )
    }

    pub fn record_digest(&self) -> &Digest {
        &self.record_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationEvidence {
    pub decision: ValidationDecision,
    pub reason: ValidationReason,
    pub completeness: EvidenceCompleteness,
    pub findings: BTreeSet<AdversarialFinding>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub policy_digest: Digest,
    pub policy_content_digest: Option<Digest>,
    pub attestor_digest: Digest,
    pub attestor_content_digest: Option<Digest>,
    pub image_digest: crate::ImageDigest,
    pub occurrence_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub provider_error: Option<ProviderErrorEvidence>,
    pub provenance: ProviderProvenance,
    pub digests: EvidenceDigests,
    pub authority: Layer1EvidenceAuthority,
    pub adopted_outcome: bool,
    pub durable_receipt: bool,
}

impl ValidationEvidence {
    fn build(record: &GcpBinaryAuthorizationRecord, provider_digest: &Digest) -> Self {
        let response = &record.response;
        let proposal = &record.proposal;
        let mut digests = EvidenceDigests {
            version_digest: proposal.version_digest.clone(),
            contract_digest: proposal.contract_digest.clone(),
            provider_digest: provider_digest.clone(),
            permission_digest: response.observed_fence.permission_digest().clone(),
            scope_digest: response.observed_fence.scope_digest().clone(),
            policy_digest: response.policy_digest.clone(),
            attestor_digest: proposal.request.attestor_scope_digest.clone(),
            image_digest: response.image_digest.digest(),
            occurrence_digest: response.occurrence_digest.clone(),
            request_digest: response.request_digest.clone(),
            response_digest: response.response_digest.clone(),
            evidence_digest: Digest::from_text("evidence-placeholder"),
        };
        digests.evidence_digest = digests.recompute();
        Self {
            decision: response.decision,
            reason: response.reason,
            completeness: response.completeness,
            findings: response.findings.clone(),
            scope_digest: response.observed_fence.scope_digest().clone(),
            permission_digest: response.observed_fence.permission_digest().clone(),
            consent_digest: response.observed_fence.consent_digest().clone(),
            policy_digest: response.policy_digest.clone(),
            policy_content_digest: response.policy_content_digest.clone(),
            attestor_digest: proposal.request.attestor_scope_digest.clone(),
            attestor_content_digest: response.attestor_digest.clone(),
            image_digest: response.image_digest.clone(),
            occurrence_digest: response.occurrence_digest.clone(),
            request_digest: response.request_digest.clone(),
            response_digest: response.response_digest.clone(),
            provider_error: response.provider_error.clone(),
            provenance: record.provenance,
            digests,
            authority: Layer1EvidenceAuthority,
            adopted_outcome: false,
            durable_receipt: false,
        }
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub const fn is_adopted(&self) -> bool {
        self.adopted_outcome
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBinaryAuthorizationVerification {
    pub evidence: ValidationEvidence,
    pub structurally_valid: bool,
}

impl GcpBinaryAuthorizationVerification {
    pub fn decision(&self) -> ValidationDecision {
        self.evidence.decision
    }

    pub fn evidence_digest(&self) -> &Digest {
        self.evidence.evidence_digest()
    }
}

pub struct GcpBinaryAuthorizationService<P> {
    scope: GcpBinaryAuthorizationScope,
    secret_reference: SecretReference,
    provider: P,
    service_definition: GcpBinaryAuthorizationServiceDefinition,
    registration: GcpBinaryAuthorizationRegistration,
}

impl<P: GcpBinaryAuthorizationProviderApi> fmt::Debug for GcpBinaryAuthorizationService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpBinaryAuthorizationService")
            .field("scope_digest", self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<P: GcpBinaryAuthorizationProviderApi> GcpBinaryAuthorizationService<P> {
    pub fn new(
        scope: GcpBinaryAuthorizationScope,
        secret_reference: SecretReference,
        provider: P,
    ) -> Result<Self, GcpBinaryAuthorizationServiceError> {
        if secret_reference.scope_digest() != scope.scope_digest() || secret_reference.is_revoked()
        {
            return Err(GcpBinaryAuthorizationServiceError::ScopeMismatch);
        }
        provider.definition().validate()?;
        let service_definition = GcpBinaryAuthorizationServiceDefinition::new();
        service_definition.validate()?;
        let registration = GcpBinaryAuthorizationRegistration::new(
            &scope,
            &secret_reference,
            provider.definition().provider_digest(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition,
            registration,
        })
    }

    pub fn scope(&self) -> &GcpBinaryAuthorizationScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn service_definition(&self) -> &GcpBinaryAuthorizationServiceDefinition {
        &self.service_definition
    }

    pub fn registration(&self) -> &GcpBinaryAuthorizationRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut GcpBinaryAuthorizationRegistration {
        &mut self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn revoke_registration(&mut self) -> Result<(), GcpBinaryAuthorizationServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn get_policy(&mut self) -> Result<PolicyReadEvidence, GcpBinaryAuthorizationServiceError> {
        self.ensure_active()?;
        let fence = self.scope.provider_fence(&self.secret_reference)?;
        let request = PolicyGetRequest::new(&self.scope, &fence)?;
        let response = self
            .provider
            .get_policy(&request)
            .map_err(GcpBinaryAuthorizationServiceError::Transport)?;
        response.validate_digest()?;
        if response.request_digest != request.request_digest() || response.observed_fence != fence {
            return Err(GcpBinaryAuthorizationServiceError::ReplayDetected);
        }
        response.policy.validate_for(&self.scope)?;
        Ok(PolicyReadEvidence::new(
            response.policy,
            &request,
            response.response_digest,
            self.provider.definition().provider_digest(),
            self.provider.provenance(),
        ))
    }

    pub fn get_attestor(
        &mut self,
        attestor_id: crate::AttestorId,
    ) -> Result<crate::provider::AttestorGetResponse, GcpBinaryAuthorizationServiceError> {
        self.ensure_active()?;
        let fence = self.scope.provider_fence(&self.secret_reference)?;
        let request = AttestorGetRequest::new(&self.scope, &fence, attestor_id)?;
        let response = self
            .provider
            .get_attestor(&request)
            .map_err(GcpBinaryAuthorizationServiceError::Transport)?;
        response.validate_digest()?;
        if response.request_digest != request.request_digest() || response.observed_fence != fence {
            return Err(GcpBinaryAuthorizationServiceError::ReplayDetected);
        }
        response.attestor.validate_for(&self.scope)?;
        Ok(response)
    }

    pub fn propose_validate_attestation_occurrence(
        &self,
        policy: PolicySummary,
        attestor: AttestorSummary,
        occurrence_digest: Digest,
    ) -> Result<GcpBinaryAuthorizationProposal, GcpBinaryAuthorizationServiceError> {
        let occurrence = AttestationOccurrenceReference::new(
            occurrence_digest,
            self.scope.image_digest().clone(),
            attestor.attestor_id().clone(),
        )?;
        self.propose_validate_attestation_occurrence_reference(policy, attestor, occurrence)
    }

    pub fn propose_validate_attestation_occurrence_reference(
        &self,
        policy: PolicySummary,
        attestor: AttestorSummary,
        occurrence: AttestationOccurrenceReference,
    ) -> Result<GcpBinaryAuthorizationProposal, GcpBinaryAuthorizationServiceError> {
        self.ensure_active()?;
        policy.validate_for(&self.scope)?;
        attestor.validate_for(&self.scope)?;
        if attestor.attestor_id() != occurrence.attestor_id()
            || occurrence.image_digest() != self.scope.image_digest()
        {
            return Err(GcpBinaryAuthorizationServiceError::ImageDigestMismatch);
        }
        let fence = self.scope.provider_fence(&self.secret_reference)?;
        let request = ValidateAttestationOccurrenceRequest::new(
            &self.scope,
            &fence,
            &policy,
            &attestor,
            occurrence,
        )?;
        let version_digest = Digest::from_text("gcp-binary-authorization-result-plugin/1.0.0");
        let mut proposal = GcpBinaryAuthorizationProposal {
            request,
            policy,
            attestor,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_digest: self.provider.definition().provider_digest(),
            version_digest,
            contract_digest: contract_digest(),
            proposal_digest: Digest::from_text("gcp-binary-authorization-proposal-placeholder"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn record_validate_attestation_occurrence(
        &mut self,
        proposal: GcpBinaryAuthorizationProposal,
    ) -> Result<GcpBinaryAuthorizationRecord, GcpBinaryAuthorizationServiceError> {
        self.ensure_active()?;
        self.validate_proposal(&proposal)?;
        let response = match self
            .provider
            .validate_attestation_occurrence(&proposal.request)
        {
            Ok(response) => response,
            Err(error) => {
                let evidence = error.evidence();
                if matches!(
                    error.kind,
                    ProviderErrorKind::Partial
                        | ProviderErrorKind::AccessLost
                        | ProviderErrorKind::Unknown
                ) {
                    ValidationResponse::unknown(&proposal.request, evidence)
                } else {
                    ValidationResponse::error(&proposal.request, evidence)
                }
            }
        };
        self.record_validate_attestation_occurrence_response(proposal, response)
    }

    pub fn record_validate_attestation_occurrence_response(
        &self,
        proposal: GcpBinaryAuthorizationProposal,
        response: ValidationResponse,
    ) -> Result<GcpBinaryAuthorizationRecord, GcpBinaryAuthorizationServiceError> {
        self.ensure_active()?;
        self.validate_proposal(&proposal)?;
        response
            .validate_digest()
            .map_err(|_| GcpBinaryAuthorizationServiceError::TamperDetected)?;
        if response.request_digest != proposal.request.request_digest {
            return Err(GcpBinaryAuthorizationServiceError::ReplayDetected);
        }
        if response.image_digest != *self.scope.image_digest()
            || response.occurrence_digest != *proposal.request.occurrence.occurrence_digest()
        {
            return Err(GcpBinaryAuthorizationServiceError::ImageDigestMismatch);
        }
        let mut record = GcpBinaryAuthorizationRecord {
            proposal,
            response,
            provenance: self.provider.provenance(),
            record_digest: Digest::from_text("gcp-binary-authorization-record-placeholder"),
        };
        record.record_digest = record.compute_digest();
        Ok(record)
    }

    pub fn verify_validate_attestation_occurrence(
        &self,
        record: &GcpBinaryAuthorizationRecord,
    ) -> Result<GcpBinaryAuthorizationVerification, GcpBinaryAuthorizationServiceError> {
        self.ensure_active()?;
        if record.record_digest != record.compute_digest() {
            return Err(GcpBinaryAuthorizationServiceError::TamperDetected);
        }
        self.validate_proposal(&record.proposal)?;
        if record.response.request_digest != record.proposal.request.request_digest {
            return Err(GcpBinaryAuthorizationServiceError::ReplayDetected);
        }
        record
            .response
            .validate_digest()
            .map_err(|_| GcpBinaryAuthorizationServiceError::TamperDetected)?;
        if record.response.observed_fence != ProviderFence::from_request(&record.proposal.request)
            || record.response.image_digest != *self.scope.image_digest()
            || record.response.occurrence_digest
                != *record.proposal.request.occurrence.occurrence_digest()
            || record.response.policy_digest != *self.scope.policy_digest()
            || record.response.attestor_id != *record.proposal.attestor.attestor_id()
        {
            return Err(GcpBinaryAuthorizationServiceError::ScopeMismatch);
        }
        record.proposal.policy.validate_for(&self.scope)?;
        record.proposal.attestor.validate_for(&self.scope)?;
        if record.response.decision == ValidationDecision::Allow
            && (record.proposal.attestor.revoked()
                || record
                    .response
                    .findings
                    .contains(&AdversarialFinding::Revocation))
        {
            return Err(GcpBinaryAuthorizationServiceError::RevokedAttestorAllowed);
        }
        if record.response.completeness == EvidenceCompleteness::Partial
            && record.response.decision != ValidationDecision::Unknown
        {
            return Err(GcpBinaryAuthorizationServiceError::InvalidProviderSummary);
        }
        if record.response.completeness == EvidenceCompleteness::AccessLost
            && record.response.decision != ValidationDecision::Unknown
        {
            return Err(GcpBinaryAuthorizationServiceError::InvalidProviderSummary);
        }
        Ok(GcpBinaryAuthorizationVerification {
            evidence: ValidationEvidence::build(
                record,
                &self.provider.definition().provider_digest(),
            ),
            structurally_valid: true,
        })
    }

    fn validate_proposal(
        &self,
        proposal: &GcpBinaryAuthorizationProposal,
    ) -> Result<(), GcpBinaryAuthorizationServiceError> {
        proposal.validate_digest()?;
        if !self.is_active()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.provider_digest != self.provider.definition().provider_digest()
            || proposal.version_digest
                != Digest::from_text("gcp-binary-authorization-result-plugin/1.0.0")
            || proposal.contract_digest != contract_digest()
            || proposal.request.scope_digest != *self.scope.scope_digest()
            || proposal.request.permission_digest != *self.scope.permission_digest()
            || proposal.request.consent_digest != *self.scope.consent_digest()
            || proposal.request.image_digest != *self.scope.image_digest()
            || proposal.request.policy_digest != *self.scope.policy_digest()
            || proposal.request.attestor_scope_digest != *self.scope.attestor_digest()
            || proposal.request.authority.effect_requested()
            || proposal.request.authority.effect_receipt_digest().is_some()
        {
            if proposal.registration_digest != self.registration.registration_digest
                || proposal.registration_revision != self.registration.revision
            {
                return Err(GcpBinaryAuthorizationServiceError::RegistrationMismatch);
            }
            return Err(GcpBinaryAuthorizationServiceError::ScopeMismatch);
        }
        proposal
            .request
            .validate_digest()
            .map_err(|_| GcpBinaryAuthorizationServiceError::TamperDetected)?;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), GcpBinaryAuthorizationServiceError> {
        if self.is_active() && self.registration.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(GcpBinaryAuthorizationServiceError::Revoked)
        }
    }
}

pub type GcpBinaryAuthorizationResultService<P> = GcpBinaryAuthorizationService<P>;
pub type GcpBinaryAuthorizationOutcomeService<P> = GcpBinaryAuthorizationService<P>;
pub type ValidateAttestationOccurrenceProposal = GcpBinaryAuthorizationProposal;
pub type ValidateAttestationOccurrenceRecord = GcpBinaryAuthorizationRecord;
pub type ValidateAttestationOccurrenceVerification = GcpBinaryAuthorizationVerification;

impl ProviderFence {
    pub(crate) fn from_request(request: &ValidateAttestationOccurrenceRequest) -> Self {
        Self::from_parts(
            request.scope_digest.clone(),
            request.permission_digest.clone(),
            request.consent_digest.clone(),
            request.secret_reference_digest.clone(),
            request.credential_revision,
            request.auth_kind,
            request.authority.clone(),
        )
    }
}

impl<P: GcpBinaryAuthorizationProviderApi> GcpBinaryAuthorizationService<P> {
    pub fn runtime_service_definition(
        &self,
    ) -> Result<ServiceDefinition, GcpBinaryAuthorizationServiceError> {
        self.service_definition.runtime_definition()
    }

    pub fn provider_definition(&self) -> &GcpBinaryAuthorizationProviderDefinition {
        self.provider.definition()
    }
}

#[allow(dead_code)]
fn _service_contract_markers() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION,
        GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_ID,
        GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_SCHEMA,
        GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_JSON,
    )
}

#[allow(dead_code)]
fn _service_provider_markers() -> (&'static str, &'static str, &'static str) {
    (
        GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID,
        GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_SCHEMA,
        GCP_BINARY_AUTHORIZATION_RESULT_PLUGIN_VERSION_TEXT,
    )
}
