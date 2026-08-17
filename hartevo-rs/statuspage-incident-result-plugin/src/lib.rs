#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::float_cmp)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionStatuspageIncidentConsumer, MissionStatuspageIncidentConsumerError,
    MissionStatuspageIncidentResult, MissionStatuspageIncidentResultState,
    MissionStatuspageIncidentState,
};
pub use model::{
    ComponentBinding, ComponentGroupBinding, ComponentGroupId, ComponentGroupRevision, ComponentId,
    ComponentRevision, ComponentStatus, ConsentScope, Digest, EvidenceClassification,
    EvidenceState, Identifier, IncidentId, IncidentImpact, IncidentStatus, MAX_COMPONENT_GROUPS,
    MAX_COMPONENTS, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES, MAX_INCIDENTS,
    MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS, MAX_TEXT_BYTES,
    MAX_UPDATES, MAX_WINDOW_DAYS, MaintenanceState, MissionBinding, MissionId, MissionRevision,
    ModelError, ObservationReceipt, OrganizationBinding, OrganizationId, OrganizationRevision,
    PageBinding, PageId, PageRevision, ProjectBinding, ProjectId, RecommendationDisposition,
    RegistrationRevocationReceipt, RegistrationState, ResourceBinding, Revision, SecretReference,
    StatuspageAcl, StatuspageAffectedComponent, StatuspageComponentGroupObservation,
    StatuspageComponentObservation, StatuspageEvidenceDigests, StatuspageHttpMethod,
    StatuspageIncidentObservation, StatuspageIncidentResult, StatuspageIncidentResultEvidence,
    StatuspageIncidentResultProposal, StatuspageIncidentResultRecommendation,
    StatuspageIncidentResultRegistration, StatuspageIncidentResultScope,
    StatuspageIncidentResultScope as StatuspageScope, StatuspageIncidentResultScopeSpec,
    StatuspageIncidentResultScopeSpec as StatuspageScopeSpec, StatuspageIncidentUpdate,
    StatuspageMaintenanceObservation, StatuspagePageProfile, StatuspagePermission,
    StatuspageRateLimitReceipt, StatuspageReadSeam, StatuspageReadbackReceipt,
    StatuspageRegistration, StatuspageRequest, StatuspageRequestReceipt, TimeWindow,
    TransportProvenance, UpdateId, WorkProductBinding, WorkProductId, WorkProductRevision,
    canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvStatuspageTransport, FixtureStatuspageTransport, LoopbackStatuspageTransport,
    RecordingStatuspageTransport, StatuspageIncidentResultProvider, StatuspageProvider,
    StatuspageProvider as StatuspageIncidentProvider, StatuspageProviderDefinition,
    StatuspageProviderError, StatuspageProviderRead, StatuspageResponse, StatuspageTransport,
    StatuspageTransportError,
};
pub use service::{
    StatuspageIncidentResultService, StatuspageIncidentResultServiceDefinition,
    StatuspageIncidentResultServiceError, StatuspageServiceError,
};

pub const STATUSPAGE_INCIDENT_RESULT_SCHEMA_VERSION: &str = "hartevo.statuspage-incident-result/v1";
pub const STATUSPAGE_INCIDENT_RESULT_CONTRACT_VERSION: &str = "statuspage-incident-result-e1/v1";
pub const STATUSPAGE_INCIDENT_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const STATUSPAGE_INCIDENT_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/statuspage-incident-result/statuspage-incident-result.v1.json";
pub const STATUSPAGE_INCIDENT_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/statuspage-incident-result/statuspage-incident-result.v1.json"
);
pub const STATUSPAGE_INCIDENT_RESULT_SERVICE_ID: &str = "statuspage.incident-result";
pub const STATUSPAGE_PROVIDER_ID: &str = "statuspage.incident";
pub const STATUSPAGE_PROVIDER_VERSION: &str = "1.0.0";
pub const STATUSPAGE_API_REVISION: &str = "statuspage-api-v1";
pub const MISSION_STATUSPAGE_INCIDENT_CONSUMER_ID: &str = "mission.statuspage.incident";
pub const STATUSPAGE_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub type StatuspageIncidentResultServiceResult<T> = StatuspageIncidentResultService<T>;
pub type StatuspageIncidentResultEvidenceModel = StatuspageIncidentResultEvidence;
pub type StatuspageIncidentResultProposalModel = StatuspageIncidentResultProposal;

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(STATUSPAGE_INCIDENT_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately reports no native, Connected, first-party, or kernel
/// authority. Host wiring and any future effects remain outside this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        Layer1Authority, MISSION_STATUSPAGE_INCIDENT_CONSUMER_ID, STATUSPAGE_API_REVISION,
        STATUSPAGE_INCIDENT_RESULT_CONTRACT_JSON, STATUSPAGE_INCIDENT_RESULT_CONTRACT_VERSION,
        STATUSPAGE_INCIDENT_RESULT_SCHEMA_VERSION, STATUSPAGE_INCIDENT_RESULT_SERVICE_ID,
        STATUSPAGE_PROVIDER_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_authority_is_honest() {
        let document: Value = serde_json::from_str(STATUSPAGE_INCIDENT_RESULT_CONTRACT_JSON)
            .expect("Statuspage contract JSON");
        assert_eq!(
            document["schemaVersion"],
            STATUSPAGE_INCIDENT_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            STATUSPAGE_INCIDENT_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            STATUSPAGE_INCIDENT_RESULT_SERVICE_ID
        );
        assert_eq!(document["provider"]["id"], STATUSPAGE_PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], STATUSPAGE_API_REVISION);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_STATUSPAGE_INCIDENT_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["firstParty"], false);
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
