//! Layer-1 governed Google Cloud Deploy release, rollout, and job-run result
//! evidence. This crate is deliberately read-only and non-native: it never
//! resolves credentials, opens HTTPS, mutates a deployment, adopts a Work
//! Product, or grants kernel Outcome authority.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    AdoptionAvailability, ConsumerError, ConsumerRegistration, MissionGcpCloudDeployConsumer,
    MissionGcpCloudDeployResult, MissionResultState,
};
pub use model::{
    CloudDeployPhase, CloudDeployStatus, CommitId, ConsentPurpose, ConsentScope, Digest,
    EvidenceProjection, GcpCloudDeployApiVersion, GcpCloudDeployPermission, GcpCloudDeployScope,
    JobRunId, JobRunIdentity, JobRunPage, JobRunPhase, JobRunSnapshot, JobRunStatus, ListOperation,
    LocationId, MissionId, MissionScope, ModelError, PageCursor, PermissionScope, PipelineId,
    ProjectId, ProjectScope, ProviderErrorKind, ProviderErrorSummary, ProviderProvenance,
    ReleaseId, ReleaseIdentity, ReleasePage, ReleasePhase, ReleaseSnapshot, ReleaseStatus,
    Revision, RolloutId, RolloutIdentity, RolloutPage, RolloutPhase, RolloutSnapshot,
    RolloutStatus, SecretKind, SecretReference, TargetId, Timestamp, WorkProductId,
    WorkProductScope,
};
pub use provider::{
    BlockedEnvGcpCloudDeployTransport, FakeGcpCloudDeployTransport, FixtureGcpCloudDeployTransport,
    GcpCloudDeployProvider, GcpCloudDeployProviderDefinition, GcpCloudDeployProviderError,
    GcpCloudDeployReadOperation, GcpCloudDeployReadRequest, GcpCloudDeployResponse,
    GcpCloudDeployTransport, GcpCloudDeployTransportError, LoopbackGcpCloudDeployTransport,
    RecordingGcpCloudDeployTransport,
};
pub use service::{
    GcpCloudDeployEvidence, GcpCloudDeployProposal, GcpCloudDeployRecord,
    GcpCloudDeployRegistration, GcpCloudDeployService, GcpCloudDeployServiceDefinition,
    GcpCloudDeployServiceError, GcpCloudDeployVerification, RegistrationRevocation,
    RegistrationState, VerificationStatus,
};

pub const GCP_CLOUD_DEPLOY_SCHEMA_VERSION: &str = "hartevo-gcp-cloud-deploy-result-contract/v1";
pub const GCP_CLOUD_DEPLOY_CONTRACT_VERSION: &str = "gcp-cloud-deploy-result-e1/v1";
pub const GCP_CLOUD_DEPLOY_EVIDENCE_LEVEL: &str = "E1";
pub const GCP_CLOUD_DEPLOY_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const GCP_CLOUD_DEPLOY_SERVICE_ID: &str = "gcp.cloud.deploy.result";
pub const GCP_CLOUD_DEPLOY_PROVIDER_ID: &str = "gcp.cloud-deploy.v1.read";
pub const GCP_CLOUD_DEPLOY_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const GCP_CLOUD_DEPLOY_CONSUMER_ID: &str = "mission.gcp.cloud-deploy.result.consumer";
pub const GCP_CLOUD_DEPLOY_API_VERSION: &str = "v1";
pub const GCP_CLOUD_DEPLOY_API_ORIGIN: &str = "https://clouddeploy.googleapis.com";
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_ROLLOUTS_PER_PAGE: usize = 100;
pub const MAX_JOB_RUNS_PER_PAGE: usize = 100;
pub const MAX_ROLLOUTS_PER_PROPOSAL: usize = 100;
pub const MAX_JOB_RUNS_PER_PROPOSAL: usize = 100;
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_RETRY_ATTEMPTS: u8 = 0;
pub const GCP_CLOUD_DEPLOY_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-cloud-deploy-result/gcp-cloud-deploy-result.v1.json"
);

pub(crate) fn contract_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_DEPLOY_CONTRACT_JSON)
}

/// Layer-1 authority is intentionally negative. A proposal is bounded
/// evidence for a later decision; it is not a connected provider or Truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcpCloudDeployLayer1Authority;

impl GcpCloudDeployLayer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn https_transport() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn independent_readback() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

pub type Layer1ResultAuthority = GcpCloudDeployLayer1Authority;

pub fn validate_contract() -> Result<(), String> {
    let document = serde_json::from_str::<serde_json::Value>(GCP_CLOUD_DEPLOY_CONTRACT_JSON)
        .map_err(|error| format!("contract JSON: {error}"))?;
    let checks = [
        (
            "/schemaVersion",
            serde_json::Value::String(GCP_CLOUD_DEPLOY_SCHEMA_VERSION.to_owned()),
        ),
        (
            "/contractVersion",
            serde_json::Value::String(GCP_CLOUD_DEPLOY_CONTRACT_VERSION.to_owned()),
        ),
        (
            "/evidenceLevel",
            serde_json::Value::String(GCP_CLOUD_DEPLOY_EVIDENCE_LEVEL.to_owned()),
        ),
        (
            "/service/id",
            serde_json::Value::String(GCP_CLOUD_DEPLOY_SERVICE_ID.to_owned()),
        ),
        (
            "/provider/id",
            serde_json::Value::String(GCP_CLOUD_DEPLOY_PROVIDER_ID.to_owned()),
        ),
        (
            "/provider/apiVersion",
            serde_json::Value::String(GCP_CLOUD_DEPLOY_API_VERSION.to_owned()),
        ),
    ];
    for (path, expected) in checks {
        if document.pointer(path) != Some(&expected) {
            return Err(format!("contract value drift at {path}"));
        }
    }
    for path in [
        "/service/readOnly",
        "/provider/native",
        "/provider/httpsTransport",
        "/provider/readback",
        "/nativeClaims/connected",
        "/nativeClaims/nativeProvider",
        "/nativeClaims/httpsTransport",
        "/nativeClaims/durableReceipt",
        "/nativeClaims/independentReadback",
        "/nativeClaims/adoptedWorkProduct",
        "/nativeClaims/adoptedOutcome",
        "/nativeClaims/deploymentSuccessClaimed",
        "/nativeClaims/blockedEnvironmentIsNative",
    ] {
        if document.pointer(path) != Some(&serde_json::Value::Bool(false))
            && path != "/service/readOnly"
        {
            return Err(format!("contract native claim drift at {path}"));
        }
    }
    if document.pointer("/service/readOnly") != Some(&serde_json::Value::Bool(true))
        || document.pointer("/service/liveExecution") != Some(&serde_json::Value::Bool(false))
        || document.pointer("/layer") != Some(&serde_json::Value::Number(1.into()))
    {
        return Err("contract service or layer boundary drift".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        GCP_CLOUD_DEPLOY_CONTRACT_JSON, GCP_CLOUD_DEPLOY_CONTRACT_VERSION,
        GCP_CLOUD_DEPLOY_EVIDENCE_LEVEL, GCP_CLOUD_DEPLOY_PROVIDER_ID,
        GCP_CLOUD_DEPLOY_SCHEMA_VERSION, GcpCloudDeployLayer1Authority, validate_contract,
    };

    #[test]
    fn contract_document_matches_the_typed_boundary() {
        validate_contract().expect("Cloud Deploy contract");
        let document: serde_json::Value =
            serde_json::from_str(GCP_CLOUD_DEPLOY_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], GCP_CLOUD_DEPLOY_SCHEMA_VERSION);
        assert_eq!(
            document["contractVersion"],
            GCP_CLOUD_DEPLOY_CONTRACT_VERSION
        );
        assert_eq!(document["evidenceLevel"], GCP_CLOUD_DEPLOY_EVIDENCE_LEVEL);
        assert_eq!(document["provider"]["id"], GCP_CLOUD_DEPLOY_PROVIDER_ID);
        assert!(!GcpCloudDeployLayer1Authority::connected());
        assert!(!GcpCloudDeployLayer1Authority::native_provider());
        assert!(!GcpCloudDeployLayer1Authority::https_transport());
        assert!(!GcpCloudDeployLayer1Authority::durable_receipt());
        assert!(!GcpCloudDeployLayer1Authority::independent_readback());
        assert!(!GcpCloudDeployLayer1Authority::work_product_adoption());
        assert!(!GcpCloudDeployLayer1Authority::outcome_adoption());
        assert!(!GcpCloudDeployLayer1Authority::truth_authority());
    }
}
