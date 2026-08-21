//! Mission/Project/Consent/Work Product projection for OneTrust evidence.
//!
//! The consumer creates only a canonical, non-mutating adoption proposal. It
//! does not adopt a Work Product, change Consent, issue an Effect, or grant
//! kernel Truth/Outcome authority.

use std::{fmt, sync::Arc};

use thiserror::Error;

use crate::model::{
    ConsentEvidenceStatus, Digest, OneTrustConsentScope, OneTrustEvidenceProposal,
    OneTrustRegistration, RegistrationUseFence, Revision, TransportProvenance,
};
use crate::provider::OneTrustProviderDefinition;
use crate::{ONETRUST_PLUGIN_VERSION_TEXT, contract_digest};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OneTrustConsumerError {
    #[error("Mission OneTrust consent consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Project/Consent/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    StaleProposal,
    #[error("proposal was not produced by the governed OneTrust service")]
    InvalidProposal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionConsentDecision {
    PendingDecision,
    Layer2AdoptionRequired,
    FailClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneTrustConsentAdoptionProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_implementation: String,
    pub provider_version: String,
    pub provider_revision: crate::ProviderRevision,
    pub provider_digest: Digest,
    pub provenance: TransportProvenance,
    pub tenant: crate::TenantId,
    pub region: crate::Region,
    pub purpose_id: crate::PurposeId,
    pub purpose_version: crate::PurposeVersion,
    pub collection_point: crate::CollectionPointId,
    pub consent_window: crate::ConsentWindow,
    pub subject_reference: crate::SubjectReferenceHash,
    pub policy_revision: crate::PolicyRevision,
    pub permission_digest: Digest,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub consent_id: crate::ConsentId,
    pub consent_revision: Revision,
    pub consent_digest: Digest,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub status: ConsentEvidenceStatus,
    pub decision: MissionConsentDecision,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub evidence_digest: Digest,
    pub source_proposal_digest: Digest,
    pub canonical_digest: Digest,
    pub adopted: bool,
    pub mutates_consent: bool,
    pub creates_effect: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
}

pub struct MissionOneTrustConsentConsumer {
    scope: OneTrustConsentScope,
    registration_digest: Digest,
    registration_revision: Revision,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_implementation: String,
    provider_version: String,
    provider_revision: crate::ProviderRevision,
    provider_digest: Digest,
    provenance: TransportProvenance,
    registration_fence: Arc<RegistrationUseFence>,
    active: bool,
}

impl fmt::Debug for MissionOneTrustConsentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionOneTrustConsentConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_implementation", &self.provider_implementation)
            .field("provider_version", &self.provider_version)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("provenance", &self.provenance)
            .field("registration_fence", &"<shared>")
            .field("active", &self.is_active())
            .finish()
    }
}

impl MissionOneTrustConsentConsumer {
    pub fn new(
        scope: OneTrustConsentScope,
        registration: &OneTrustRegistration,
    ) -> Result<Self, OneTrustConsumerError> {
        let definition = OneTrustProviderDefinition::baseline();
        if !registration.is_active()
            || registration
                .validate_identity(
                    &scope,
                    &definition.provider_id,
                    &definition.implementation,
                    &definition.version,
                    &definition.provider_revision,
                    &definition.provider_digest,
                    &contract_digest(),
                    registration.provenance,
                )
                .is_err()
        {
            return Err(OneTrustConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            contract_version: registration.contract_version.clone(),
            contract_digest: registration.contract_digest.clone(),
            provider_id: registration.provider_id.clone(),
            provider_implementation: registration.provider_implementation.clone(),
            provider_version: registration.provider_version.clone(),
            provider_revision: registration.provider_revision.clone(),
            provider_digest: registration.provider_digest.clone(),
            provenance: registration.provenance,
            registration_fence: registration.active_use_fence(),
            active: true,
        })
    }

    pub fn scope(&self) -> &OneTrustConsentScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn is_active(&self) -> bool {
        self.active && self.registration_fence.is_active()
    }

    pub fn revoke(&mut self) -> Result<(), OneTrustConsumerError> {
        if !self.is_active() {
            return Err(OneTrustConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    /// Compile the canonical non-mutating adoption proposal. A later host
    /// layer may decide whether to adopt it; this method itself never does.
    pub fn propose_adoption(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<OneTrustConsentAdoptionProposal, OneTrustConsumerError> {
        self.validate_proposal(proposal)?;
        let status = proposal.projection.status;
        let decision = match status {
            ConsentEvidenceStatus::Granted
            | ConsentEvidenceStatus::Denied
            | ConsentEvidenceStatus::Pending => MissionConsentDecision::PendingDecision,
            ConsentEvidenceStatus::Partial
            | ConsentEvidenceStatus::AccessLost
            | ConsentEvidenceStatus::Stale
            | ConsentEvidenceStatus::ProviderUnknown => MissionConsentDecision::FailClosed,
            ConsentEvidenceStatus::Withdrawn
            | ConsentEvidenceStatus::Expired
            | ConsentEvidenceStatus::NoRecord => MissionConsentDecision::Layer2AdoptionRequired,
        };
        let canonical_digest = self.adoption_canonical_digest(proposal, status, decision);
        Ok(OneTrustConsentAdoptionProposal {
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_id: self.provider_id.clone(),
            provider_implementation: self.provider_implementation.clone(),
            provider_version: self.provider_version.clone(),
            provider_revision: self.provider_revision.clone(),
            provider_digest: self.provider_digest.clone(),
            provenance: self.provenance,
            tenant: self.scope.tenant.clone(),
            region: self.scope.region.clone(),
            purpose_id: self.scope.purpose_id.clone(),
            purpose_version: self.scope.purpose_version.clone(),
            collection_point: self.scope.collection_point.clone(),
            consent_window: self.scope.consent_window.clone(),
            subject_reference: self.scope.subject_reference.clone(),
            policy_revision: self.scope.policy_revision.clone(),
            permission_digest: self.scope.permission_digest.clone(),
            mission_id: self.scope.mission.id.clone(),
            mission_revision: self.scope.mission.revision,
            project_id: self.scope.project.id.clone(),
            project_revision: self.scope.project.revision,
            consent_id: self.scope.consent.id.clone(),
            consent_revision: self.scope.consent.revision,
            consent_digest: self.scope.consent.digest.clone(),
            work_product_id: self.scope.work_product.id.clone(),
            work_product_revision: self.scope.work_product.revision,
            status,
            decision,
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            registration_revision: proposal.registration_revision,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            source_proposal_digest: proposal.proposal_digest.clone(),
            canonical_digest,
            adopted: false,
            mutates_consent: false,
            creates_effect: false,
            kernel_authority: false,
            outcome_authority: false,
        })
    }

    fn adoption_canonical_digest(
        &self,
        proposal: &OneTrustEvidenceProposal,
        status: ConsentEvidenceStatus,
        decision: MissionConsentDecision,
    ) -> Digest {
        Digest::from_fields([
            "hartevo-onetrust-adoption-proposal-v1".to_owned(),
            self.contract_version.clone(),
            self.contract_digest.as_str().to_owned(),
            self.provider_id.clone(),
            self.provider_implementation.clone(),
            self.provider_version.clone(),
            self.provider_revision.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            format!("{:?}", self.provenance),
            self.scope.tenant.as_str().to_owned(),
            self.scope.region.as_str().to_owned(),
            self.scope.purpose_id.as_str().to_owned(),
            self.scope.purpose_version.as_str().to_owned(),
            self.scope.collection_point.as_str().to_owned(),
            self.scope.consent_window.start.to_rfc3339(),
            self.scope.consent_window.end.to_rfc3339(),
            self.scope
                .subject_reference
                .scope_digest()
                .as_str()
                .to_owned(),
            self.scope.subject_reference.digest().as_str().to_owned(),
            self.scope.policy_revision.as_str().to_owned(),
            self.scope.permission_digest.as_str().to_owned(),
            self.scope.mission.id.as_str().to_owned(),
            self.scope.mission.revision.get().to_string(),
            self.scope.project.id.as_str().to_owned(),
            self.scope.project.revision.get().to_string(),
            self.scope.consent.id.as_str().to_owned(),
            self.scope.consent.revision.get().to_string(),
            self.scope.consent.digest.as_str().to_owned(),
            self.scope.work_product.id.as_str().to_owned(),
            self.scope.work_product.revision.get().to_string(),
            format!("{status:?}"),
            format!("{decision:?}"),
            proposal.scope_digest.as_str().to_owned(),
            proposal.registration_digest.as_str().to_owned(),
            proposal.registration_revision.get().to_string(),
            proposal.evidence.evidence_digest.as_str().to_owned(),
            proposal.proposal_digest.as_str().to_owned(),
            "adopted:false".to_owned(),
            "mutates_consent:false".to_owned(),
            "creates_effect:false".to_owned(),
            "kernel_authority:false".to_owned(),
            "outcome_authority:false".to_owned(),
        ])
    }

    pub fn consume(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<OneTrustConsentAdoptionProposal, OneTrustConsumerError> {
        self.propose_adoption(proposal)
    }

    fn validate_proposal(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<(), OneTrustConsumerError> {
        if !self.is_active() {
            return Err(OneTrustConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration_digest
            || proposal.registration_revision != self.registration_revision
        {
            return Err(OneTrustConsumerError::RegistrationMismatch);
        }
        if proposal.plugin_version != ONETRUST_PLUGIN_VERSION_TEXT
            || proposal.contract_version != self.contract_version
            || proposal.contract_digest != self.contract_digest
            || proposal.provider_id != self.provider_id
            || proposal.provider_implementation != self.provider_implementation
            || proposal.provider_version != self.provider_version
            || proposal.provider_revision != self.provider_revision
            || proposal.provider_digest != self.provider_digest
            || proposal.provenance != self.provenance
        {
            return Err(OneTrustConsumerError::InvalidProposal);
        }
        if proposal.scope_digest != self.scope.scope_digest()
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.subject_reference != self.scope.subject_reference
            || proposal.permission_digest != self.scope.permission_digest
            || proposal.mission_revision != self.scope.mission.revision
            || proposal.project_revision != self.scope.project.revision
            || proposal.consent_revision != self.scope.consent.revision
            || proposal.work_product_revision != self.scope.work_product.revision
        {
            return Err(OneTrustConsumerError::ScopeMismatch);
        }
        if proposal.validate_integrity(&self.scope).is_err() {
            return Err(OneTrustConsumerError::StaleProposal);
        }
        if proposal.proposal_digest
            != proposal
                .recompute_digest()
                .map_err(|_| OneTrustConsumerError::StaleProposal)?
            || proposal.native
            || proposal.connected
            || proposal.adopted_by_kernel
        {
            return Err(OneTrustConsumerError::InvalidProposal);
        }
        if proposal.consent_receipt_created
            || proposal.consent_withdrawn
            || proposal.preference_updated
            || !proposal.read_only
            || !proposal.proposal_only
        {
            return Err(OneTrustConsumerError::InvalidProposal);
        }
        Ok(())
    }
}
