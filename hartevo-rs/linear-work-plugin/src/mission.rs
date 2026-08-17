use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest_hex;
use crate::ids::{
    LinearCycleId, LinearIdError, LinearIssueId, LinearMissionId, LinearOrganizationId,
    LinearProjectId, LinearTeamId, LinearWorkflowStateId,
};
use crate::provider::{LINEAR_PROVIDER_ID, LINEAR_PROVIDER_VERSION, LinearProviderProvenance};

pub const EXTERNAL_WORK_GRAPH_SERVICE_ID: &str = "external.work.graph";
pub const LINEAR_PLUGIN_ID: &str = "linear.oauth.work";
pub const LINEAR_PLUGIN_VERSION: u64 = 1;
pub const LINEAR_MISSION_CONSUMER_ID: &str = "mission.external.work.linear";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalWorkGraphOperation {
    OauthProbe,
    ReadIssues,
    ReadProjects,
    ReadCycles,
    VerifyWebhook,
    Propose,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalWorkGraphService {
    pub id: String,
    pub version: u64,
    pub operations: BTreeSet<ExternalWorkGraphOperation>,
    pub authority: String,
    pub source_of_truth: String,
}

impl ExternalWorkGraphService {
    pub fn baseline() -> Self {
        Self {
            id: EXTERNAL_WORK_GRAPH_SERVICE_ID.to_owned(),
            version: LINEAR_PLUGIN_VERSION,
            operations: [
                ExternalWorkGraphOperation::OauthProbe,
                ExternalWorkGraphOperation::ReadIssues,
                ExternalWorkGraphOperation::ReadProjects,
                ExternalWorkGraphOperation::ReadCycles,
                ExternalWorkGraphOperation::VerifyWebhook,
                ExternalWorkGraphOperation::Propose,
            ]
            .into_iter()
            .collect(),
            authority: "read_and_propose_only".to_owned(),
            source_of_truth: "mission".to_owned(),
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearProviderDefinition {
    pub id: String,
    pub version: u64,
    pub api: String,
    pub graphql_endpoint: String,
    pub agent_session_developer_preview: bool,
    pub scope_bindings: Vec<String>,
    pub reversible: bool,
    pub has_store_authority: bool,
    pub has_keyring_authority: bool,
    pub has_browser_profile_authority: bool,
    pub has_effect_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearMissionConsumerDefinition {
    pub id: String,
    pub proposal_kinds: Vec<String>,
    pub mutating_graphql_operations: bool,
    pub adoptable_result: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearPluginDefinition {
    pub plugin_id: String,
    pub version: u64,
    pub contract_digest: String,
    pub service: ExternalWorkGraphService,
    pub provider: LinearProviderDefinition,
    pub mission_consumer: LinearMissionConsumerDefinition,
}

impl LinearPluginDefinition {
    pub fn baseline() -> Self {
        Self {
            plugin_id: LINEAR_PLUGIN_ID.to_owned(),
            version: LINEAR_PLUGIN_VERSION,
            contract_digest: crate::contract_digest(),
            service: ExternalWorkGraphService::baseline(),
            provider: LinearProviderDefinition {
                id: LINEAR_PROVIDER_ID.to_owned(),
                version: u64::from(LINEAR_PROVIDER_VERSION),
                api: "stable_graphql".to_owned(),
                graphql_endpoint: crate::graphql::LINEAR_GRAPHQL_ENDPOINT.to_owned(),
                agent_session_developer_preview: false,
                scope_bindings: [
                    "organization",
                    "team_set",
                    "actor",
                    "app_identity",
                    "oauth_scope",
                    "token_expiry",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                reversible: true,
                has_store_authority: false,
                has_keyring_authority: false,
                has_browser_profile_authority: false,
                has_effect_authority: false,
            },
            mission_consumer: LinearMissionConsumerDefinition {
                id: LINEAR_MISSION_CONSUMER_ID.to_owned(),
                proposal_kinds: ["issue", "comment", "status"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                mutating_graphql_operations: false,
                adoptable_result: true,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearCapabilityComposition {
    pub organization_id: LinearOrganizationId,
    pub team_ids: BTreeSet<LinearTeamId>,
    pub provider_id: String,
    pub provider_version: u64,
    pub provider_provenance: LinearProviderProvenance,
    pub scope_digest: String,
}

impl LinearCapabilityComposition {
    pub fn new(
        organization_id: LinearOrganizationId,
        team_ids: impl IntoIterator<Item = LinearTeamId>,
        provider_provenance: LinearProviderProvenance,
    ) -> Result<Self, LinearMissionConsumerError> {
        let team_ids = team_ids.into_iter().collect::<BTreeSet<_>>();
        if team_ids.is_empty() {
            return Err(LinearMissionConsumerError::EmptyTeamScope);
        }
        let scope_digest = digest_hex(
            &serde_json::to_vec(&(&organization_id, &team_ids))
                .map_err(|error| LinearMissionConsumerError::Serialization(error.to_string()))?,
        );
        Ok(Self {
            organization_id,
            team_ids,
            provider_id: LINEAR_PROVIDER_ID.to_owned(),
            provider_version: u64::from(LINEAR_PROVIDER_VERSION),
            provider_provenance,
            scope_digest,
        })
    }

    pub fn contains_team(&self, team_id: &LinearTeamId) -> bool {
        self.team_ids.contains(team_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LinearIssueProposalField {
    Title,
    Description,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LinearProposalKind {
    Issue {
        issue_id: LinearIssueId,
        field: LinearIssueProposalField,
        value: String,
    },
    Comment {
        issue_id: LinearIssueId,
        body: String,
    },
    Status {
        issue_id: LinearIssueId,
        state_id: LinearWorkflowStateId,
    },
}

impl LinearProposalKind {
    fn validate(&self) -> Result<(), LinearMissionConsumerError> {
        match self {
            Self::Issue { value, .. } => validate_text(value, 16_384, "issue value"),
            Self::Comment { body, .. } => validate_text(body, 16_384, "comment body"),
            Self::Status { .. } => Ok(()),
        }
    }

    pub fn issue_id(&self) -> &LinearIssueId {
        match self {
            Self::Issue { issue_id, .. }
            | Self::Comment { issue_id, .. }
            | Self::Status { issue_id, .. } => issue_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearMissionWorkRequest {
    pub mission_id: LinearMissionId,
    pub objective: String,
    pub capability: LinearCapabilityComposition,
    pub team_id: LinearTeamId,
    pub proposal: LinearProposalKind,
}

impl LinearMissionWorkRequest {
    pub fn new(
        mission_id: LinearMissionId,
        objective: impl Into<String>,
        capability: LinearCapabilityComposition,
        team_id: LinearTeamId,
        proposal: LinearProposalKind,
    ) -> Result<Self, LinearMissionConsumerError> {
        let request = Self {
            mission_id,
            objective: objective.into(),
            capability,
            team_id,
            proposal,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), LinearMissionConsumerError> {
        validate_text(&self.objective, 4_096, "objective")?;
        if !self.capability.contains_team(&self.team_id) {
            return Err(LinearMissionConsumerError::TeamOutOfScope(
                self.team_id.to_string(),
            ));
        }
        self.proposal.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearWorkProposal {
    pub proposal_version: u64,
    pub mission_id: LinearMissionId,
    pub objective: String,
    pub capability: LinearCapabilityComposition,
    pub team_id: LinearTeamId,
    pub kind: LinearProposalKind,
    pub non_mutating: bool,
    pub external_mutation_performed: bool,
    pub canonical_digest: String,
}

impl LinearWorkProposal {
    pub const VERSION: u64 = 1;

    pub fn is_adoptable(&self) -> bool {
        self.non_mutating && !self.external_mutation_performed
    }

    pub fn adoptable_result(&self) -> LinearAdoptableWorkResult {
        LinearAdoptableWorkResult {
            mission_id: self.mission_id.clone(),
            proposal_digest: self.canonical_digest.clone(),
            status: LinearAdoptionStatus::AwaitingApproval,
            external_mutation_performed: false,
            mission_truth_source: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearAdoptableWorkResult {
    pub mission_id: LinearMissionId,
    pub proposal_digest: String,
    pub status: LinearAdoptionStatus,
    pub external_mutation_performed: bool,
    pub mission_truth_source: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearAdoptionStatus {
    AwaitingApproval,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinearMissionWorkConsumer;

impl LinearMissionWorkConsumer {
    pub const fn new() -> Self {
        Self
    }

    pub fn propose(
        &self,
        request: LinearMissionWorkRequest,
    ) -> Result<LinearWorkProposal, LinearMissionConsumerError> {
        request.validate()?;
        let canonical = CanonicalProposal {
            proposal_version: LinearWorkProposal::VERSION,
            mission_id: &request.mission_id,
            objective: &request.objective,
            capability: &request.capability,
            team_id: &request.team_id,
            kind: &request.proposal,
            non_mutating: true,
            external_mutation_performed: false,
        };
        let canonical_digest = digest_hex(
            &serde_json::to_vec(&canonical)
                .map_err(|error| LinearMissionConsumerError::Serialization(error.to_string()))?,
        );
        Ok(LinearWorkProposal {
            proposal_version: LinearWorkProposal::VERSION,
            mission_id: request.mission_id,
            objective: request.objective,
            capability: request.capability,
            team_id: request.team_id,
            kind: request.proposal,
            non_mutating: true,
            external_mutation_performed: false,
            canonical_digest,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalProposal<'a> {
    proposal_version: u64,
    mission_id: &'a LinearMissionId,
    objective: &'a str,
    capability: &'a LinearCapabilityComposition,
    team_id: &'a LinearTeamId,
    kind: &'a LinearProposalKind,
    non_mutating: bool,
    external_mutation_performed: bool,
}

fn validate_text(
    value: &str,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<(), LinearMissionConsumerError> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control)
    {
        return Err(LinearMissionConsumerError::InvalidText { field });
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearMissionConsumerError {
    #[error("Linear Mission objective or proposal text is invalid: {field}")]
    InvalidText { field: &'static str },
    #[error("Linear Mission capability must bind at least one team")]
    EmptyTeamScope,
    #[error("Linear Mission team {0} is outside the capability scope")]
    TeamOutOfScope(String),
    #[error("Linear Mission proposal serialization failed: {0}")]
    Serialization(String),
    #[error("Linear identifier is invalid: {0}")]
    InvalidIdentifier(#[from] LinearIdError),
    #[error("Linear work proposal contains unsupported resource {0}")]
    UnsupportedResource(String),
    #[error("Linear cycle {0} is outside the capability scope")]
    CycleOutOfScope(LinearCycleId),
    #[error("Linear project {0} is outside the capability scope")]
    ProjectOutOfScope(LinearProjectId),
}
