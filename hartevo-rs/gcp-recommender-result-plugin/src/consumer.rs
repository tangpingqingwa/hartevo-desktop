use std::collections::BTreeSet;

use thiserror::Error;

use crate::{
    Digest, GCP_RECOMMENDER_RESULT_CONSUMER_ID, GCP_RECOMMENDER_RESULT_CONTRACT_VERSION,
    GcpRecommenderEvidence, GcpRecommenderProposal, GcpRecommenderProviderApi, GcpRecommenderScope,
    GcpRecommenderService, GcpRecommenderServiceError, Layer1Authority, ProviderProvenance,
    ResultProjection,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGcpRecommendationState {
    Complete,
    Empty,
    Partial,
    RateLimited,
    AccessLost,
    ProviderUnknown,
    FinalError,
    BlockedEnv,
}

impl From<ResultProjection> for MissionGcpRecommendationState {
    fn from(projection: ResultProjection) -> Self {
        match projection {
            ResultProjection::Complete => Self::Complete,
            ResultProjection::Empty => Self::Empty,
            ResultProjection::Partial => Self::Partial,
            ResultProjection::RateLimited => Self::RateLimited,
            ResultProjection::AccessLost => Self::AccessLost,
            ResultProjection::ProviderUnknown => Self::ProviderUnknown,
            ResultProjection::FinalError => Self::FinalError,
            ResultProjection::BlockedEnv => Self::BlockedEnv,
        }
    }
}

pub type MissionResultState = MissionGcpRecommendationState;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGcpRecommendationConsumerError {
    #[error("Mission GCP Recommender consumer scope does not match the proposal")]
    ScopeMismatch,
    #[error("Mission GCP Recommender proposal has already been consumed")]
    Replay,
    #[error("Mission GCP Recommender proposal or evidence digest is invalid")]
    Tampered,
    #[error("Mission GCP Recommender proposal contract or authority drifted")]
    ContractDrift,
    #[error("Mission GCP Recommender consumer is revoked")]
    Revoked,
    #[error("Mission GCP Recommender service failed: {0}")]
    Service(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGcpRecommendationResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub project: crate::ProjectBinding,
    pub mission: crate::MissionBinding,
    pub work_product: crate::WorkProductBinding,
    pub state: MissionGcpRecommendationState,
    pub proposal_digest: Digest,
    pub evidence: GcpRecommenderEvidence,
    pub proposal: GcpRecommenderProposal,
    pub authority: Layer1Authority,
    pub adopted_work_product: bool,
    pub outcome_authority: bool,
    pub marks_recommendation: bool,
    pub executes_operation_group: bool,
    pub provider_provenance: ProviderProvenance,
}

pub type MissionGcpRecommendationEvidence = MissionGcpRecommendationResult;

#[derive(Debug)]
pub struct MissionGcpRecommendationConsumer {
    scope: GcpRecommenderScope,
    registration_digest: Option<Digest>,
    consumed: BTreeSet<Digest>,
    active: bool,
}

impl MissionGcpRecommendationConsumer {
    pub fn new(scope: GcpRecommenderScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            consumed: BTreeSet::new(),
            active: true,
        }
    }

    pub fn new_bound(scope: GcpRecommenderScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest: Some(registration_digest),
            consumed: BTreeSet::new(),
            active: true,
        }
    }

    pub fn scope(&self) -> &GcpRecommenderScope {
        &self.scope
    }

    pub const fn consumer_id(&self) -> &'static str {
        GCP_RECOMMENDER_RESULT_CONSUMER_ID
    }

    pub const fn contract_version(&self) -> &'static str {
        GCP_RECOMMENDER_RESULT_CONTRACT_VERSION
    }

    pub fn contract_digest(&self) -> Digest {
        crate::contract_digest()
    }

    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn has_consumed(&self, proposal_digest: &Digest) -> bool {
        self.consumed.contains(proposal_digest)
    }

    pub fn revoke(&mut self) -> Result<(), MissionGcpRecommendationConsumerError> {
        if self.active {
            self.active = false;
            Ok(())
        } else {
            Err(MissionGcpRecommendationConsumerError::Revoked)
        }
    }

    pub fn restore(&mut self) -> Result<(), MissionGcpRecommendationConsumerError> {
        if self.active {
            Err(MissionGcpRecommendationConsumerError::ContractDrift)
        } else {
            self.active = true;
            Ok(())
        }
    }

    pub fn consume(
        &mut self,
        proposal: GcpRecommenderProposal,
    ) -> Result<MissionGcpRecommendationResult, MissionGcpRecommendationConsumerError> {
        if !self.active {
            return Err(MissionGcpRecommendationConsumerError::Revoked);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.scope.permission().digest()
            || proposal.evidence.consent_digest != self.scope.consent().digest()
            || proposal.evidence.query_digest != proposal.query_digest
            || proposal.evidence.filter_digest != proposal.filter_digest
            || proposal.evidence.registration_digest != proposal.registration_digest
            || proposal.evidence.provider_digest != proposal.provider_digest
            || proposal.evidence.result_kind != *self.scope.result_kind()
            || proposal.evidence.project_revision != self.scope.project().revision()
            || proposal.evidence.mission_revision != self.scope.mission().revision()
            || proposal.evidence.work_product_revision != self.scope.work_product().revision()
        {
            return Err(MissionGcpRecommendationConsumerError::ScopeMismatch);
        }
        if self
            .registration_digest
            .as_ref()
            .is_some_and(|digest| digest != &proposal.registration_digest)
        {
            return Err(MissionGcpRecommendationConsumerError::ScopeMismatch);
        }
        if proposal.contract_version != GCP_RECOMMENDER_RESULT_CONTRACT_VERSION
            || proposal.contract_digest != crate::contract_digest()
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || !proposal.proposal_only
            || !proposal.read_only
            || proposal.marks_recommendation
            || proposal.executes_operation_group
            || proposal.adopts_outcome
        {
            return Err(MissionGcpRecommendationConsumerError::ContractDrift);
        }
        if proposal.evidence.provider_provenance.is_native()
            || proposal.evidence.provider_provenance.is_connected()
            || proposal.evidence.provider_provenance.is_first_party()
            || proposal.evidence.raw_descriptions
            || proposal.evidence.custom_struct_payloads
            || proposal.evidence.principals
            || proposal.evidence.operation_plans
            || proposal.evidence.projected_savings
        {
            return Err(MissionGcpRecommendationConsumerError::ContractDrift);
        }
        if proposal.evidence.records.len() > 500 || proposal.evidence.page_count > 16 {
            return Err(MissionGcpRecommendationConsumerError::Tampered);
        }
        for record in &proposal.evidence.records {
            if record.validate_digest().is_err()
                || record.result_kind != *self.scope.result_kind()
                || record
                    .target_resource_fingerprints
                    .iter()
                    .any(|fingerprint| {
                        !self
                            .scope
                            .target_resource_fingerprints()
                            .contains(fingerprint)
                    })
            {
                return Err(MissionGcpRecommendationConsumerError::Tampered);
            }
        }
        proposal
            .evidence
            .validate_digest()
            .map_err(|_| MissionGcpRecommendationConsumerError::Tampered)?;
        proposal
            .validate_digest()
            .map_err(|_| MissionGcpRecommendationConsumerError::Tampered)?;
        if self.consumed.contains(&proposal.proposal_digest) {
            return Err(MissionGcpRecommendationConsumerError::Replay);
        }
        if self.registration_digest.is_none() {
            self.registration_digest = Some(proposal.registration_digest.clone());
        }
        let result = MissionGcpRecommendationResult {
            consumer_id: GCP_RECOMMENDER_RESULT_CONSUMER_ID.to_owned(),
            contract_version: GCP_RECOMMENDER_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            state: proposal.evidence.projection.into(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence: proposal.evidence.clone(),
            proposal: proposal.clone(),
            authority: Layer1Authority,
            adopted_work_product: false,
            outcome_authority: false,
            marks_recommendation: false,
            executes_operation_group: false,
            provider_provenance: proposal.evidence.provider_provenance,
        };
        self.consumed.insert(proposal.proposal_digest);
        Ok(result)
    }

    pub fn read<P: GcpRecommenderProviderApi>(
        &mut self,
        service: &mut GcpRecommenderService<P>,
    ) -> Result<MissionGcpRecommendationResult, MissionGcpRecommendationConsumerError> {
        if service.scope().digest() != self.scope.digest() {
            return Err(MissionGcpRecommendationConsumerError::ScopeMismatch);
        }
        self.bind_registration(service);
        let proposal = service.propose_list().map_err(map_service_error)?;
        self.consume(proposal)
    }

    pub fn read_get<P: GcpRecommenderProviderApi>(
        &mut self,
        service: &mut GcpRecommenderService<P>,
        result_id: crate::ResultId,
        expected: Option<crate::ResultVersionFence>,
    ) -> Result<MissionGcpRecommendationResult, MissionGcpRecommendationConsumerError> {
        if service.scope().digest() != self.scope.digest() {
            return Err(MissionGcpRecommendationConsumerError::ScopeMismatch);
        }
        self.bind_registration(service);
        let proposal = service
            .propose_get(result_id, expected)
            .map_err(map_service_error)?;
        self.consume(proposal)
    }

    fn bind_registration<P: GcpRecommenderProviderApi>(
        &mut self,
        service: &GcpRecommenderService<P>,
    ) {
        if self.registration_digest.is_none() {
            self.registration_digest = Some(service.registration().registration_digest.clone());
        }
    }
}

fn map_service_error(error: GcpRecommenderServiceError) -> MissionGcpRecommendationConsumerError {
    match error {
        GcpRecommenderServiceError::ScopeMismatch
        | GcpRecommenderServiceError::MissingReadPermission
        | GcpRecommenderServiceError::ConsentMismatch
        | GcpRecommenderServiceError::RegistrationRevoked
        | GcpRecommenderServiceError::SecretRevoked
        | GcpRecommenderServiceError::QueryMismatch => {
            MissionGcpRecommendationConsumerError::ScopeMismatch
        }
        other => MissionGcpRecommendationConsumerError::Service(other.to_string()),
    }
}
