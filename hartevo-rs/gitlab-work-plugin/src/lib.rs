//! GitLab Work Layer-1 provider vertical slice.
//!
//! This standalone crate is intentionally read/proposal/recording only.  It
//! composes a typed GitLab service, provider and Mission consumer while
//! keeping provider state below Hartevo Effect/Receipt/Verification/Outcome
//! authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod transport;
pub mod webhook;

pub use consumer::MissionGitLabWorkConsumer;
pub use model::*;
pub use provider::{
    GitLabWorkError, GitLabWorkProvider, MergeRequestRead, PaginationBounds, PipelineResultRead,
    ProviderRead, RegistrationProbe, RegistrationProbeStatus,
};
pub use transport::{
    BlockedEnvTransport, FakeGitLabWorkTransport, GitLabWorkTransport, RecordingTransport,
    RequestOperation, TransportError, TransportRequest, TransportResponse,
};
pub use webhook::{RecordingWebhookVerifier, WebhookSignatureVerifier, WebhookVerifierError};

pub const GITLAB_WORK_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/gitlab-work/gitlab-work.v1.json");

pub fn contract_digest() -> Digest {
    sha256_digest(GITLAB_WORK_CONTRACT_JSON.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONTRACT_VERSION, EVIDENCE_LEVEL, GITLAB_WORK_CONTRACT_JSON, PROVIDER_ID, SERVICE_ID,
        contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        service_id: String,
        provider_id: String,
        layer: u8,
        evidence_level: String,
        read_only: bool,
        mutating_provider_operations: Vec<String>,
        hartevo_authority: Authority,
        honest_native_gap: String,
    }

    #[derive(Debug, Deserialize)]
    #[allow(clippy::struct_excessive_bools)]
    #[serde(rename_all = "camelCase")]
    struct Authority {
        effect: bool,
        receipt: bool,
        verification: bool,
        outcome: bool,
        work_product_adoption: bool,
        connected_claim: bool,
        native_evidence_claim: bool,
        live_webhook_acceptance: bool,
    }

    #[test]
    fn checked_contract_is_layer_one_and_below_hartevo_authority() {
        let document = serde_json::from_str::<ContractDocument>(GITLAB_WORK_CONTRACT_JSON)
            .expect("GitLab Work contract JSON");
        assert_eq!(document.schema_version, "hartevo-gitlab-work-contract/v1");
        assert_eq!(document.contract_version, CONTRACT_VERSION);
        assert_eq!(document.service_id, SERVICE_ID);
        assert_eq!(document.provider_id, PROVIDER_ID);
        assert_eq!(document.layer, 1);
        assert_eq!(document.evidence_level, EVIDENCE_LEVEL);
        assert!(document.read_only);
        assert!(document.mutating_provider_operations.is_empty());
        assert!(!document.hartevo_authority.effect);
        assert!(!document.hartevo_authority.receipt);
        assert!(!document.hartevo_authority.verification);
        assert!(!document.hartevo_authority.outcome);
        assert!(!document.hartevo_authority.work_product_adoption);
        assert!(!document.hartevo_authority.connected_claim);
        assert!(!document.hartevo_authority.native_evidence_claim);
        assert!(!document.hartevo_authority.live_webhook_acceptance);
        assert!(document.honest_native_gap.contains("Layer-2/BLOCKED_ENV"));
        assert_eq!(contract_digest().as_str().len(), 64);
    }
}
