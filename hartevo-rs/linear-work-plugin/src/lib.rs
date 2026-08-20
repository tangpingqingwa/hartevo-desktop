//! Layer 1 Linear work graph capability.
//!
//! The crate owns a typed `ExternalWorkGraphService`, a stable GraphQL
//! `LinearOAuthWorkProvider`, and a Mission-scoped consumer that emits one
//! canonical, non-mutating proposal.  It deliberately has no Store, keyring,
//! Browser Profile, Effect Broker, or AgentSession dependency.

#![forbid(unsafe_code)]

mod graphql;
mod ids;
mod mission;
mod oauth;
mod provider;
mod webhook;

pub use graphql::{
    LINEAR_CYCLES_QUERY, LINEAR_GRAPHQL_ENDPOINT, LINEAR_ISSUES_QUERY, LINEAR_OAUTH_PROBE_QUERY,
    LINEAR_PROJECTS_QUERY, LinearCycle, LinearCyclePage, LinearGraphQlData,
    LinearGraphQlDecodeError, LinearGraphQlErrorItem, LinearGraphQlRequest,
    LinearGraphQlRequestError, LinearGraphQlResponse, LinearGraphQlTransport,
    LinearHttpsGraphQlTransport, LinearIssue, LinearIssuePage, LinearPageInfo, LinearPageRequest,
    LinearProject, LinearProjectPage, LinearProjectReference, LinearProjectState,
    LinearRateLimitReceipt, LinearReadPage, LinearReadReceipt, LinearResourceKind,
    LinearResourcePage, LinearTeam, LinearTransportError, LinearWorkflowState,
};
pub use ids::{
    LinearAppId, LinearCursor, LinearCycleId, LinearIdError, LinearIssueId, LinearMissionId,
    LinearOrganizationId, LinearProjectId, LinearScope, LinearScopeSet, LinearTeamId, LinearUserId,
    LinearWorkflowStateId,
};
pub use mission::{
    EXTERNAL_WORK_GRAPH_SERVICE_ID, ExternalWorkGraphOperation, ExternalWorkGraphService,
    LINEAR_MISSION_CONSUMER_ID, LINEAR_PLUGIN_ID, LINEAR_PLUGIN_VERSION, LinearAdoptableWorkResult,
    LinearCapabilityComposition, LinearIssueProposalField, LinearMissionConsumerDefinition,
    LinearMissionConsumerError, LinearMissionWorkConsumer, LinearMissionWorkRequest,
    LinearPluginDefinition, LinearProposalKind, LinearProviderDefinition, LinearWorkProposal,
};
pub use oauth::{
    LINEAR_OAUTH_AUTHORIZE_ENDPOINT, LINEAR_OAUTH_TOKEN_ENDPOINT, LinearAccessToken,
    LinearActorIdentity, LinearAppIdentity, LinearEnvProbe, LinearOAuthApp, LinearOAuthError,
    LinearOAuthInstallation, LinearOAuthProbeReceipt,
};
pub use provider::{
    LinearCapabilityState, LinearOAuthWorkProvider, LinearProviderError, LinearProviderProvenance,
    LinearRevocationReason,
};
pub use webhook::{
    LINEAR_DELIVERY_HEADER, LINEAR_EVENT_HEADER, LINEAR_SIGNATURE_HEADER, LINEAR_TIMESTAMP_HEADER,
    LinearReplayFence, LinearWebhookError, LinearWebhookEvent, LinearWebhookEventKind,
    LinearWebhookHeaders, LinearWebhookOutcome, VerifiedLinearWebhook,
};

pub const LINEAR_WORK_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/linear-work/manifest.v1.json");
pub const LINEAR_WORK_SCHEMA_VERSION: &str = "hartevo-linear-work-plugin-contract/v1";
pub const LINEAR_WORK_CONTRACT_VERSION: &str = "linear-work-e1/v1";

/// The Layer 1 contract document is embedded so the service and provider can
/// be checked against the exact manifest shipped with the plugin.
pub fn contract_digest() -> String {
    digest_hex(LINEAR_WORK_CONTRACT_JSON.as_bytes())
}

pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex::encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        EXTERNAL_WORK_GRAPH_SERVICE_ID, LINEAR_MISSION_CONSUMER_ID, LINEAR_PLUGIN_ID,
        LINEAR_PLUGIN_VERSION, LINEAR_WORK_CONTRACT_JSON, LINEAR_WORK_CONTRACT_VERSION,
        LINEAR_WORK_SCHEMA_VERSION, contract_digest,
    };

    #[test]
    fn embedded_contract_declares_the_layer_one_authority_boundary() {
        let document: Value =
            serde_json::from_str(LINEAR_WORK_CONTRACT_JSON).expect("valid Linear work contract");
        assert_eq!(
            document["properties"]["schemaVersion"]["const"],
            LINEAR_WORK_SCHEMA_VERSION
        );
        assert_eq!(
            document["properties"]["contractVersion"]["const"],
            LINEAR_WORK_CONTRACT_VERSION
        );
        assert_eq!(
            document["properties"]["service"]["properties"]["id"]["const"],
            EXTERNAL_WORK_GRAPH_SERVICE_ID
        );
        assert_eq!(
            document["properties"]["provider"]["properties"]["id"]["const"],
            LINEAR_PLUGIN_ID
        );
        assert_eq!(
            document["properties"]["provider"]["properties"]["version"]["const"],
            LINEAR_PLUGIN_VERSION
        );
        assert_eq!(
            document["properties"]["missionConsumer"]["properties"]["id"]["const"],
            LINEAR_MISSION_CONSUMER_ID
        );
        assert_eq!(
            document["properties"]["provider"]["properties"]["agentSessionDeveloperPreview"]["const"],
            false
        );
        assert_eq!(
            document["properties"]["missionConsumer"]["properties"]["mutatingGraphqlOperations"]["const"],
            false
        );
        assert_ne!(contract_digest(), "");
    }
}
