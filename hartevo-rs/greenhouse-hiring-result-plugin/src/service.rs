use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::GreenhouseError;
use crate::model::{
    ConsentReceipt, Digest, EffectIntent, EffectOperation, GreenhouseHiringEvidence,
    GreenhouseScope, HiringDecision, Layer1Recording, ProposalRequest, ProposalResult,
    ReadBackRequest, ReadBackResult, RegistrationState, Revision, SecretReference,
};
use crate::provider::GreenhouseHarvestProviderDefinition;
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION,
    PROVIDER_ID, SERVICE_ID, digest_serialized,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOperation {
    DescribeCapabilities,
    RegisterScope,
    ReadHiringEvidence,
    CompileResultProposal,
    RecordResult,
    ReadBackRecordedResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GreenhouseHiringResultServiceDefinition {
    pub service_type: String,
    pub service_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub layer: u8,
    pub read_only: bool,
    pub live_execution: bool,
    pub operations: Vec<ServiceOperation>,
}

impl GreenhouseHiringResultServiceDefinition {
    pub fn validate(&self) -> Result<(), GreenhouseError> {
        if self.service_id != SERVICE_ID
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.layer != 1
            || !self.read_only
            || self.live_execution
            || self.operations.len() != 6
        {
            Err(GreenhouseError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

/// A local registration binds every authority-relevant revision and digest.
/// It contains only a SecretReference digest, never the opaque reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GreenhouseRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub capability_digest: Digest,
    pub scope: GreenhouseScope,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GreenhouseRegistration {
    pub fn new(
        scope: GreenhouseScope,
        provider: &GreenhouseHarvestProviderDefinition,
        secret: &SecretReference,
    ) -> Result<Self, GreenhouseError> {
        scope.validate()?;
        provider.validate()?;
        if secret.is_revoked() {
            return Err(GreenhouseError::SecretRevoked);
        }
        let mut registration = Self {
            plugin_id: String::from(PLUGIN_ID),
            plugin_version: String::from(PLUGIN_VERSION),
            contract_version: String::from(CONTRACT_VERSION),
            contract_digest: Digest::parse(CONTRACT_DIGEST)?,
            provider_id: String::from(PROVIDER_ID),
            provider_revision: String::from(PROVIDER_API_REVISION),
            capability_digest: provider.capability_digest().clone(),
            scope_digest: scope.digest(),
            scope,
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("unsealed-greenhouse-registration"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), GreenhouseError> {
        self.scope.validate()?;
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_id != PROVIDER_ID
            || self.provider_revision != PROVIDER_API_REVISION
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(GreenhouseError::InvalidRegistration);
        }
        self.capability_digest.validate()?;
        self.secret_reference_digest.validate()?;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn reverse(&mut self) -> Result<(), GreenhouseError> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn revoke(&mut self) -> Result<(), GreenhouseError> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn ensure_active(&self) -> Result<(), GreenhouseError> {
        self.validate()?;
        match self.state {
            RegistrationState::Active => Ok(()),
            RegistrationState::Reversed => Err(GreenhouseError::RegistrationReversed),
            RegistrationState::Revoked => Err(GreenhouseError::RegistrationRevoked),
        }
    }

    pub fn ensure_scope(&self, scope: &GreenhouseScope) -> Result<(), GreenhouseError> {
        if self.scope_digest != scope.digest() || self.scope != *scope {
            Err(GreenhouseError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    pub fn ensure_provider(
        &self,
        provider: &GreenhouseHarvestProviderDefinition,
        secret: &SecretReference,
    ) -> Result<(), GreenhouseError> {
        provider.validate()?;
        if provider.provider_id().as_str() != self.provider_id
            || provider.api_revision() != self.provider_revision
            || provider.capability_digest() != &self.capability_digest
            || secret.reference_digest() != &self.secret_reference_digest
            || secret.credential_revision() != self.credential_revision
            || secret.is_revoked()
        {
            Err(GreenhouseError::RegistrationDrift)
        } else {
            Ok(())
        }
    }

    fn transition(&mut self, state: RegistrationState) -> Result<(), GreenhouseError> {
        self.validate()?;
        if !self.is_active() {
            return Err(GreenhouseError::RegistrationTransitionNotAllowed);
        }
        self.registration_revision =
            Revision::new(self.registration_revision.get().checked_add(1).ok_or(
                GreenhouseError::InvalidRevision {
                    field: "registrationRevision",
                },
            )?)?;
        self.state = state;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        digest_serialized(&(
            self.plugin_id.clone(),
            self.plugin_version.clone(),
            self.contract_version.clone(),
            self.contract_digest.clone(),
            self.provider_id.clone(),
            self.provider_revision.clone(),
            self.capability_digest.clone(),
            self.scope_digest.clone(),
            self.secret_reference_digest.clone(),
            self.credential_revision,
            self.registration_revision,
            self.state,
        ))
    }
}

#[derive(Debug, Default)]
pub struct GreenhouseHiringResultService {
    definition: GreenhouseHiringResultServiceDefinition,
    recordings: BTreeMap<Digest, Layer1Recording>,
}

impl GreenhouseHiringResultService {
    pub fn new() -> Result<Self, GreenhouseError> {
        let definition = GreenhouseHiringResultServiceDefinition::default();
        definition.validate()?;
        Ok(Self {
            definition,
            recordings: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &GreenhouseHiringResultServiceDefinition {
        &self.definition
    }

    pub fn register_scope(
        &self,
        scope: GreenhouseScope,
        provider: &GreenhouseHarvestProviderDefinition,
        secret: &SecretReference,
    ) -> Result<GreenhouseRegistration, GreenhouseError> {
        GreenhouseRegistration::new(scope, provider, secret)
    }

    pub fn compile_result_proposal(
        &self,
        registration: &GreenhouseRegistration,
        evidence: &GreenhouseHiringEvidence,
        request: &ProposalRequest,
    ) -> Result<ProposalResult, GreenhouseError> {
        registration.ensure_active()?;
        registration.ensure_scope(&registration.scope)?;
        evidence.validate_integrity()?;
        if evidence.scope_digest != registration.scope_digest {
            return Err(GreenhouseError::ScopeMismatch);
        }
        if !request
            .consent
            .is_usable_for(&registration.scope, request.now_epoch_seconds)
        {
            return Err(GreenhouseError::ConsentUnavailable);
        }
        if let Some(expected) = request.expected_provider_revision
            && expected != evidence.provider_revision
        {
            return Err(GreenhouseError::RevisionMismatch {
                expected: expected.get(),
                actual: evidence.provider_revision.get(),
            });
        }
        if let Some(expected) = &request.expected_evidence_digest
            && expected != &evidence.evidence_digest
        {
            return Err(GreenhouseError::StaleSnapshot);
        }
        let decision = match evidence.state {
            crate::ApplicationState::AccessLost => HiringDecision::EscalateAccessReview,
            crate::ApplicationState::ProviderUnknown | crate::ApplicationState::Incomplete => {
                HiringDecision::HoldForEvidence
            }
            crate::ApplicationState::Hired
                if !evidence.is_hiring_success_claim()
                    || evidence.completeness != crate::EvidenceCompleteness::Complete =>
            {
                HiringDecision::HoldForEvidence
            }
            crate::ApplicationState::Rejected => HiringDecision::DoNotAdvance,
            crate::ApplicationState::Active
            | crate::ApplicationState::Converted
            | crate::ApplicationState::Stalled
            | crate::ApplicationState::Hired => HiringDecision::RecommendHumanReview,
        };
        let operation = match decision {
            HiringDecision::DoNotAdvance => EffectOperation::RejectApplication,
            _ => EffectOperation::HumanReviewRecommendation,
        };
        let effect = EffectIntent::proposal_only(
            operation,
            registration.scope.application_id.clone(),
            registration.scope_digest.clone(),
            request.consent.consent_digest.clone(),
            registration.registration_revision,
        );
        Ok(ProposalResult {
            mission_id: registration.scope.mission_id.clone(),
            project_id: registration.scope.project_id.clone(),
            work_product_id: registration.scope.work_product_id.clone(),
            scope_digest: registration.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            provider_revision: evidence.provider_revision,
            registration_revision: registration.registration_revision,
            objective_digest: request.objective.digest.clone(),
            decision,
            effect,
            consent_digest: request.consent.consent_digest.clone(),
            proposal_digest: Digest::from_text("unsealed-greenhouse-proposal"),
            connected: false,
            native: false,
            adopted_outcome: false,
        }
        .seal())
    }

    pub fn record_result(
        &mut self,
        registration: &GreenhouseRegistration,
        evidence: GreenhouseHiringEvidence,
        proposal: ProposalResult,
    ) -> Result<Layer1Recording, GreenhouseError> {
        registration.ensure_active()?;
        evidence.validate_integrity()?;
        proposal.validate_integrity()?;
        if evidence.scope_digest != registration.scope_digest
            || proposal.scope_digest != registration.scope_digest
            || proposal.evidence_digest != evidence.evidence_digest
            || proposal.registration_revision != registration.registration_revision
        {
            return Err(GreenhouseError::DigestMismatch);
        }
        let request_digest = digest_serialized(&evidence.request_receipts);
        let result_digest = digest_serialized(&(&evidence, &proposal));
        let receipt_id = digest_serialized(&(
            registration.scope_digest.clone(),
            evidence.evidence_digest.clone(),
            proposal.proposal_digest.clone(),
            registration.registration_revision,
        ));
        let receipt = crate::EvidenceReceipt {
            receipt_id: receipt_id.clone(),
            provider_id: String::from(PROVIDER_ID),
            scope_digest: registration.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            request_digest,
            result_digest,
            registration_revision: registration.registration_revision,
            provenance: evidence
                .request_receipts
                .first()
                .map_or(crate::TransportProvenance::Recording, |item| {
                    item.provenance
                }),
            redacted: true,
            connected: false,
            native: false,
            durable_native_receipt: false,
        };
        let recording = Layer1Recording {
            receipt,
            evidence,
            proposal,
        };
        recording.validate()?;
        if let Some(existing) = self.recordings.get(&receipt_id) {
            if existing.receipt.result_digest == recording.receipt.result_digest {
                return Ok(existing.clone());
            }
            return Err(GreenhouseError::ReplayConflict);
        }
        self.recordings.insert(receipt_id, recording.clone());
        Ok(recording)
    }

    pub fn read_back_recorded_result(
        &self,
        request: &ReadBackRequest,
    ) -> Result<ReadBackResult, GreenhouseError> {
        let recording = self
            .recordings
            .get(&request.receipt_id)
            .ok_or(GreenhouseError::ReceiptMismatch)?;
        if recording.receipt.scope_digest != request.scope_digest
            || recording.receipt.evidence_digest != request.expected_evidence_digest
            || recording.receipt.registration_revision != request.registration_revision
        {
            return Err(GreenhouseError::ReceiptMismatch);
        }
        Ok(ReadBackResult {
            recording: recording.clone(),
            verified: true,
            independent_provider_read_back: false,
        })
    }

    pub fn record(
        &mut self,
        registration: &GreenhouseRegistration,
        evidence: GreenhouseHiringEvidence,
        proposal: ProposalResult,
    ) -> Result<Layer1Recording, GreenhouseError> {
        self.record_result(registration, evidence, proposal)
    }

    pub fn read_back(&self, request: &ReadBackRequest) -> Result<ReadBackResult, GreenhouseError> {
        self.read_back_recorded_result(request)
    }

    pub fn can_execute_effect(&self, _effect: &EffectIntent) -> Result<(), GreenhouseError> {
        Err(GreenhouseError::MutationNotAvailable {
            operation: "Greenhouse hiring effect",
        })
    }

    pub fn consent_is_scope_bound(
        &self,
        scope: &GreenhouseScope,
        consent: &ConsentReceipt,
    ) -> bool {
        consent.is_usable_for(scope, consent.expires_at_epoch_seconds)
    }
}

impl Default for GreenhouseHiringResultServiceDefinition {
    fn default() -> Self {
        Self {
            service_type: String::from("GreenhouseHiringResultService"),
            service_id: String::from(SERVICE_ID),
            plugin_id: String::from(PLUGIN_ID),
            plugin_version: String::from(PLUGIN_VERSION),
            contract_version: String::from(CONTRACT_VERSION),
            contract_digest: Digest::parse(CONTRACT_DIGEST).expect("contract digest"),
            layer: 1,
            read_only: true,
            live_execution: false,
            operations: vec![
                ServiceOperation::DescribeCapabilities,
                ServiceOperation::RegisterScope,
                ServiceOperation::ReadHiringEvidence,
                ServiceOperation::CompileResultProposal,
                ServiceOperation::RecordResult,
                ServiceOperation::ReadBackRecordedResult,
            ],
        }
    }
}
