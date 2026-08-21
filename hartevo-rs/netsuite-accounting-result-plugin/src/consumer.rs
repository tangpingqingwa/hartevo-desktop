//! Mission-scoped consumer for bounded NetSuite accounting evidence.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    model::{Digest, NetSuiteScope, SecretReference},
    provider::NetSuiteTransportProvenance,
    service::{
        NetSuiteAccountingProposal, NetSuiteAccountingStatus, NetSuiteRegistration,
        NetSuiteServiceError, NetSuiteSuiteQlProposal,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionNetSuiteAccountingState {
    Observed,
    Partial,
    ProviderUnknown,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("NetSuite Mission consumer registration is invalid")]
    InvalidRegistration,
    #[error("NetSuite Mission consumer received stale or tampered evidence")]
    StaleEvidence,
    #[error("NetSuite Mission consumer received a duplicate proposal")]
    DuplicateProposal,
    #[error(transparent)]
    Service(#[from] NetSuiteServiceError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionNetSuiteAccountingResult {
    pub project_id: crate::ProjectId,
    pub project_revision: crate::Revision,
    pub mission_id: crate::MissionId,
    pub mission_revision: crate::Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: crate::Revision,
    pub state: MissionNetSuiteAccountingState,
    pub status: NetSuiteAccountingStatus,
    pub provenance: NetSuiteTransportProvenance,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native_evidence: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub result_digest: Digest,
}

impl MissionNetSuiteAccountingResult {
    fn new(proposal: &NetSuiteAccountingProposal, scope: &NetSuiteScope) -> Self {
        let state = match proposal.status {
            NetSuiteAccountingStatus::Observed => MissionNetSuiteAccountingState::Observed,
            NetSuiteAccountingStatus::Partial => MissionNetSuiteAccountingState::Partial,
            NetSuiteAccountingStatus::ProviderUnknown => {
                MissionNetSuiteAccountingState::ProviderUnknown
            }
        };
        let result_digest = Digest::from_fields(
            "netsuite-mission-accounting-result/v1",
            &[
                proposal.scope_digest.as_str().to_owned(),
                proposal.proposal_digest().as_str().to_owned(),
                proposal.evidence.evidence_digest.as_str().to_owned(),
                format!("{state:?}"),
                format!("{:?}", proposal.evidence.provenance),
                "connected=false".to_owned(),
                "native=false".to_owned(),
                "outcome_authority=false".to_owned(),
                "work_product_adoption=false".to_owned(),
            ],
        );
        Self {
            project_id: scope.project_id().clone(),
            project_revision: scope.project_revision(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            state,
            status: proposal.status,
            provenance: proposal.evidence.provenance,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest().clone(),
            connected: false,
            native_evidence: false,
            outcome_authority: false,
            work_product_adoption: false,
            result_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionNetSuiteSuiteQlResult {
    pub project_id: crate::ProjectId,
    pub mission_id: crate::MissionId,
    pub work_product_id: crate::WorkProductId,
    pub proposal_digest: Digest,
    pub statement_digest: Digest,
    pub provenance: NetSuiteTransportProvenance,
    pub recorded_at: DateTime<Utc>,
    pub executed: bool,
    pub connected: bool,
    pub native: bool,
    pub result_digest: Digest,
}

#[derive(Clone)]
pub struct MissionNetSuiteAccountingConsumer {
    scope: NetSuiteScope,
    secret_reference: SecretReference,
    registration: NetSuiteRegistration,
}

impl fmt::Debug for MissionNetSuiteAccountingConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionNetSuiteAccountingConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .finish()
    }
}

impl MissionNetSuiteAccountingConsumer {
    pub fn new(
        scope: NetSuiteScope,
        registration: NetSuiteRegistration,
    ) -> Result<Self, ConsumerError> {
        let secret_reference = registration.bound_secret_reference().clone();
        Self::new_with_secret(scope, secret_reference, registration)
    }

    pub fn new_with_secret(
        scope: NetSuiteScope,
        secret_reference: SecretReference,
        registration: NetSuiteRegistration,
    ) -> Result<Self, ConsumerError> {
        registration
            .validate_canonical(&scope, &secret_reference)
            .map_err(|_| ConsumerError::InvalidRegistration)?;
        Ok(Self {
            scope,
            secret_reference,
            registration,
        })
    }

    pub fn validate_only(
        &self,
        proposal: &NetSuiteAccountingProposal,
    ) -> Result<(), ConsumerError> {
        self.registration
            .validate_canonical(&self.scope, &self.secret_reference)
            .map_err(|_| ConsumerError::InvalidRegistration)?;
        proposal
            .validate_bindings(&self.scope, &self.registration)
            .map_err(|error| match error {
                NetSuiteServiceError::StaleEvidence => ConsumerError::StaleEvidence,
                other => ConsumerError::Service(other),
            })
    }

    pub fn consume(
        &mut self,
        proposal: NetSuiteAccountingProposal,
    ) -> Result<MissionNetSuiteAccountingResult, ConsumerError> {
        self.validate_only(&proposal)?;
        if !self
            .registration
            .claim_proposal(proposal.proposal_digest())
            .map_err(ConsumerError::Service)?
        {
            return Err(ConsumerError::DuplicateProposal);
        }
        Ok(MissionNetSuiteAccountingResult::new(&proposal, &self.scope))
    }

    pub fn validate_suiteql_only(
        &self,
        proposal: &NetSuiteSuiteQlProposal,
    ) -> Result<(), ConsumerError> {
        self.registration
            .validate_canonical(&self.scope, &self.secret_reference)
            .map_err(|_| ConsumerError::InvalidRegistration)?;
        proposal
            .validate_bindings(&self.scope, &self.registration)
            .map_err(|error| match error {
                NetSuiteServiceError::StaleEvidence => ConsumerError::StaleEvidence,
                other => ConsumerError::Service(other),
            })
    }

    pub fn consume_suiteql_proposal(
        &mut self,
        proposal: &NetSuiteSuiteQlProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<MissionNetSuiteSuiteQlResult, ConsumerError> {
        self.validate_suiteql_only(proposal)?;
        if !self.scope.observation_window().contains(recorded_at) {
            return Err(ConsumerError::StaleEvidence);
        }
        if !self
            .registration
            .claim_proposal(proposal.proposal_digest())
            .map_err(ConsumerError::Service)?
        {
            return Err(ConsumerError::DuplicateProposal);
        }
        let result_digest = Digest::from_fields(
            "netsuite-mission-suiteql-result/v1",
            &[
                self.scope.digest().as_str().to_owned(),
                proposal.proposal_digest().as_str().to_owned(),
                proposal.statement.query_digest().as_str().to_owned(),
                recorded_at.to_rfc3339(),
                "executed=false".to_owned(),
                "connected=false".to_owned(),
                "native=false".to_owned(),
            ],
        );
        Ok(MissionNetSuiteSuiteQlResult {
            project_id: self.scope.project_id().clone(),
            mission_id: self.scope.mission_id().clone(),
            work_product_id: self.scope.work_product_id().clone(),
            proposal_digest: proposal.proposal_digest().clone(),
            statement_digest: proposal.statement.query_digest().clone(),
            provenance: proposal.provenance,
            recorded_at,
            executed: false,
            connected: false,
            native: false,
            result_digest,
        })
    }
}
