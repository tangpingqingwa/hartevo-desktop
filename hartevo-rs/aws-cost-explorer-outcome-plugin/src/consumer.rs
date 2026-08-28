use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_COST_EXPLORER_CONSUMER_ID, AWS_COST_EXPLORER_CONTRACT_VERSION,
    model::{
        AwsCostExplorerRegistration, AwsCostExplorerScope, Digest, EvidenceState, ModelError,
        RegistrationRevocation, Revision,
    },
    service::{
        AwsCostExplorerProposal, AwsCostExplorerServiceError, CostUsageProposal,
        DimensionValuesProposal, UsageForecastProposal,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Cost Explorer consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS Cost Explorer proposal was tampered with")]
    TamperedProposal,
    #[error("proposal scope does not match the Mission consumer")]
    ScopeMismatch,
    #[error("proposal contains a stale Mission revision")]
    StaleMissionRevision,
    #[error("proposal registration does not match the consumer registration")]
    RegistrationMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Service(#[from] AwsCostExplorerServiceError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsumerRegistration {
    pub consumer_id: String,
    pub contract_version: String,
    pub project_id: crate::model::ProjectId,
    pub mission_id: crate::model::MissionId,
    pub work_product_id: crate::model::WorkProductId,
    pub mission_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub revoked: bool,
}

impl ConsumerRegistration {
    pub fn new(scope: &AwsCostExplorerScope, registration: &AwsCostExplorerRegistration) -> Self {
        Self {
            consumer_id: AWS_COST_EXPLORER_CONSUMER_ID.to_owned(),
            contract_version: AWS_COST_EXPLORER_CONTRACT_VERSION.to_owned(),
            project_id: scope.project_id().clone(),
            mission_id: scope.mission_id().clone(),
            work_product_id: scope.work_product_id().clone(),
            mission_revision: scope.mission_revision(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            revoked: false,
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ConsumerError> {
        if self.revoked {
            Err(ConsumerError::RegistrationRevoked)
        } else {
            self.revoked = true;
            Ok(RegistrationRevocation {
                registration_digest: self.registration_digest.clone(),
                revision: self.mission_revision,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextMissionStep {
    ReviewSpendEvidence,
    ReviewSpendAndForecast,
    ReviewDimensionEvidence,
    RequestBoundedRerun,
    UseHistoricalSpendOnly,
    ReauthorizeAwsAccess,
    RetryProviderEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionAwsCostDecision {
    pub scope_digest: Digest,
    pub mission_revision: Revision,
    pub evidence_proposal_digest: Digest,
    pub forecast_proposal_digest: Option<Digest>,
    pub evidence_state: EvidenceState,
    pub next_step: NextMissionStep,
    pub requires_review: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

impl MissionAwsCostDecision {
    pub fn is_adopted_outcome(&self) -> bool {
        self.adopted_outcome
    }

    pub fn decision_digest(&self) -> &Digest {
        &self.decision_digest
    }
}

pub type MissionAwsCostProposal = AwsCostExplorerProposal;

pub struct MissionAwsCostConsumer {
    registration: ConsumerRegistration,
    consumed: BTreeMap<Digest, MissionAwsCostDecision>,
}

impl fmt::Debug for MissionAwsCostConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCostConsumer")
            .field("registration", &self.registration)
            .field("consumed_count", &self.consumed.len())
            .finish()
    }
}

impl MissionAwsCostConsumer {
    pub fn new(scope: &AwsCostExplorerScope, registration: &AwsCostExplorerRegistration) -> Self {
        Self {
            registration: ConsumerRegistration::new(scope, registration),
            consumed: BTreeMap::new(),
        }
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ConsumerError> {
        self.registration.revoke()
    }

    pub fn consume(
        &mut self,
        proposal: &MissionAwsCostProposal,
    ) -> Result<MissionAwsCostDecision, ConsumerError> {
        match proposal {
            AwsCostExplorerProposal::CostAndUsage(proposal) => self.consume_cost_usage(proposal),
            AwsCostExplorerProposal::UsageForecast(proposal) => {
                self.consume_usage_forecast(proposal)
            }
            AwsCostExplorerProposal::DimensionValues(proposal) => {
                self.consume_dimension_values(proposal)
            }
        }
    }

    pub fn consume_cost_usage(
        &mut self,
        proposal: &CostUsageProposal,
    ) -> Result<MissionAwsCostDecision, ConsumerError> {
        self.validate_common(
            &proposal.evidence.scope_digest,
            proposal.evidence.mission_revision,
            &proposal.registration_digest,
            proposal.proposal_digest(),
            proposal.validate_integrity(),
        )?;
        self.make_decision(
            proposal.proposal_digest().clone(),
            None,
            proposal.evidence.state,
        )
    }

    pub fn consume_with_forecast(
        &mut self,
        cost_proposal: &CostUsageProposal,
        forecast_proposal: Option<&UsageForecastProposal>,
    ) -> Result<MissionAwsCostDecision, ConsumerError> {
        self.validate_common(
            &cost_proposal.evidence.scope_digest,
            cost_proposal.evidence.mission_revision,
            &cost_proposal.registration_digest,
            cost_proposal.proposal_digest(),
            cost_proposal.validate_integrity(),
        )?;
        let forecast_digest = if let Some(forecast) = forecast_proposal {
            self.validate_common(
                &forecast.evidence.scope_digest,
                forecast.evidence.mission_revision,
                &forecast.registration_digest,
                forecast.proposal_digest(),
                forecast.validate_integrity(),
            )?;
            Some(forecast.proposal_digest().clone())
        } else {
            None
        };
        let state = combined_state(cost_proposal.evidence.state, forecast_proposal);
        self.make_decision(
            cost_proposal.proposal_digest().clone(),
            forecast_digest,
            state,
        )
    }

    pub fn consume_usage_forecast(
        &mut self,
        proposal: &UsageForecastProposal,
    ) -> Result<MissionAwsCostDecision, ConsumerError> {
        self.validate_common(
            &proposal.evidence.scope_digest,
            proposal.evidence.mission_revision,
            &proposal.registration_digest,
            proposal.proposal_digest(),
            proposal.validate_integrity(),
        )?;
        self.make_decision(
            proposal.proposal_digest().clone(),
            None,
            proposal.evidence.state,
        )
    }

    pub fn consume_dimension_values(
        &mut self,
        proposal: &DimensionValuesProposal,
    ) -> Result<MissionAwsCostDecision, ConsumerError> {
        self.validate_common(
            &proposal.evidence.scope_digest,
            proposal.evidence.mission_revision,
            &proposal.registration_digest,
            proposal.proposal_digest(),
            proposal.validate_integrity(),
        )?;
        self.make_decision(
            proposal.proposal_digest().clone(),
            None,
            proposal.evidence.state,
        )
    }

    fn validate_common(
        &self,
        scope_digest: &Digest,
        mission_revision: Revision,
        registration_digest: &Digest,
        proposal_digest: &Digest,
        integrity: Result<(), AwsCostExplorerServiceError>,
    ) -> Result<(), ConsumerError> {
        if self.registration.revoked {
            return Err(ConsumerError::RegistrationRevoked);
        }
        integrity.map_err(|_| ConsumerError::TamperedProposal)?;
        if scope_digest != &self.registration.scope_digest {
            return Err(ConsumerError::ScopeMismatch);
        }
        if mission_revision != self.registration.mission_revision {
            return Err(ConsumerError::StaleMissionRevision);
        }
        if registration_digest != &self.registration.registration_digest {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal_digest.as_str().is_empty() {
            return Err(ConsumerError::TamperedProposal);
        }
        Ok(())
    }

    fn make_decision(
        &mut self,
        evidence_proposal_digest: Digest,
        forecast_proposal_digest: Option<Digest>,
        evidence_state: EvidenceState,
    ) -> Result<MissionAwsCostDecision, ConsumerError> {
        let dedupe_key = Digest::from_fields(
            "aws-mission-decision-input/v1",
            &[
                evidence_proposal_digest.as_str().to_owned(),
                forecast_proposal_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                self.registration.registration_digest.as_str().to_owned(),
            ],
        );
        if let Some(existing) = self.consumed.get(&dedupe_key) {
            return Ok(existing.clone());
        }
        let next_step = if forecast_proposal_digest.is_some()
            && matches!(
                evidence_state,
                EvidenceState::Complete | EvidenceState::Estimated
            ) {
            NextMissionStep::ReviewSpendAndForecast
        } else {
            match evidence_state {
                EvidenceState::Complete | EvidenceState::Estimated => {
                    NextMissionStep::ReviewSpendEvidence
                }
                EvidenceState::Partial => NextMissionStep::RequestBoundedRerun,
                EvidenceState::ForecastUnavailable => NextMissionStep::UseHistoricalSpendOnly,
                EvidenceState::AccessLoss => NextMissionStep::ReauthorizeAwsAccess,
                EvidenceState::ProviderUnknown => NextMissionStep::RetryProviderEvidence,
            }
        };
        let decision_digest = Digest::from_fields(
            "aws-mission-decision/v1",
            &[
                self.registration.scope_digest.as_str().to_owned(),
                self.registration.mission_revision.get().to_string(),
                evidence_proposal_digest.as_str().to_owned(),
                forecast_proposal_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                format!("{evidence_state:?}"),
                format!("{next_step:?}"),
                self.registration.registration_digest.as_str().to_owned(),
            ],
        );
        let decision = MissionAwsCostDecision {
            scope_digest: self.registration.scope_digest.clone(),
            mission_revision: self.registration.mission_revision,
            evidence_proposal_digest,
            forecast_proposal_digest,
            evidence_state,
            next_step,
            requires_review: true,
            adopted_outcome: false,
            truth_authority: false,
            decision_digest,
        };
        self.consumed.insert(dedupe_key, decision.clone());
        Ok(decision)
    }
}

fn combined_state(
    cost_state: EvidenceState,
    forecast_proposal: Option<&UsageForecastProposal>,
) -> EvidenceState {
    match cost_state {
        EvidenceState::AccessLoss | EvidenceState::ProviderUnknown | EvidenceState::Partial => {
            cost_state
        }
        EvidenceState::Complete | EvidenceState::Estimated => {
            forecast_proposal.map_or(cost_state, |forecast| match forecast.evidence.state {
                EvidenceState::AccessLoss => EvidenceState::AccessLoss,
                EvidenceState::ProviderUnknown => EvidenceState::ProviderUnknown,
                EvidenceState::ForecastUnavailable => EvidenceState::ForecastUnavailable,
                EvidenceState::Partial => EvidenceState::Partial,
                EvidenceState::Complete | EvidenceState::Estimated => cost_state,
            })
        }
        EvidenceState::ForecastUnavailable => EvidenceState::ForecastUnavailable,
    }
}
