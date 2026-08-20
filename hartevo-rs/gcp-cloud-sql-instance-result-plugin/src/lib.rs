//! Standalone Layer-1 governed GCP Cloud SQL instance result plugin.
//!
//! The crate exposes only bounded, redacted provider evidence and a reversible
//! Mission-scoped proposal/recording seam. It never resolves native
//! credentials, executes SQL, performs a Cloud SQL mutation, emits a Hartevo
//! Receipt, claims Connected/native/first-party evidence, or adopts Truth,
//! Consent, Effect, Verification, Outcome, or Work Product authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionGcpCloudSqlInstanceConsumer, MissionGcpCloudSqlInstanceResult, ProposalDisposition,
};
pub use model::*;
pub use provider::{
    BlockedEnvGcpCloudSqlTransport, BlockedEnvTransport, FakeGcpCloudSqlTransport, FakeTransport,
    FixtureGcpCloudSqlTransport, FixtureTransport, GcpCloudSqlAdminOperation,
    GcpCloudSqlAdminProvider, GcpCloudSqlAdminProviderDefinition, GcpCloudSqlAdminProviderError,
    GcpCloudSqlAdminProviderIdentity, GcpCloudSqlAdminTransport, GcpCloudSqlAdminTransportError,
    GcpCloudSqlProviderDefinition, GetInstanceRequest, GetInstanceResponse, GetOperationRequest,
    GetOperationResponse, ListInstancesRequest, ListInstancesResponse,
    LoopbackGcpCloudSqlTransport, LoopbackTransport, ProviderDefinitionError, RecordedRequest,
    RecordingGcpCloudSqlTransport, RecordingTransport, TransportError,
};
pub use service::{
    GcpCloudSqlCapabilities, GcpCloudSqlInstanceEvidence, GcpCloudSqlInstanceReadRequest,
    GcpCloudSqlInstanceRecord, GcpCloudSqlInstanceRegistration, GcpCloudSqlInstanceResultProposal,
    GcpCloudSqlInstanceResultService, GcpCloudSqlInstanceResultServiceDefinition,
    GcpCloudSqlInstanceResultServiceError, GcpCloudSqlLocalRecord, GcpCloudSqlServiceDefinition,
    GcpCloudSqlServiceError, LocalRecord, RegistrationError, RegistrationState,
    RegistrationTransitionEvidence, ScopeProjection, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.gcp-cloud-sql-instance-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-GCP-CLOUD-SQL-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PLUGIN_ID: &str = "gcp.cloud-sql.instance.result";
pub const SERVICE_ID: &str = "gcp.cloud-sql.instance.result.read";
pub const PROVIDER_ID: &str = "gcp.cloud-sql.admin.recording";
pub const CONSUMER_ID: &str = "mission.gcp-cloud-sql-instance.consumer";
pub const API_REVISION: &str = "sqladmin-instances-get-list-operations-get-v1beta4-r1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.gcp-cloud-sql-instance-result/v1|layer=1|service=gcp.cloud-sql.instance.result.read|provider=gcp.cloud-sql.admin.recording|consumer=mission.gcp-cloud-sql-instance.consumer|api=sqladmin-instances-get-list-operations-get-v1beta4-r1";
pub const CONTRACT_DIGEST: &str =
    "42c63ccdaea04f0752a0bb7d6eea2c4051e97f533b82258ff37d48a961270c5b";
pub const EVIDENCE_DIGEST_BINDING: &str = "gcp-cloud-sql-evidence/v1";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "cloudsql.instances.get",
    "cloudsql.instances.list",
    "cloudsql.operations.get",
    "mission.scope",
];
pub const MAX_IDENTIFIER_BYTES: usize = model::MAX_IDENTIFIER_BYTES;
pub const MAX_PAGE_SIZE: u16 = model::MAX_PAGE_SIZE;
pub const MAX_PAGES: u16 = model::MAX_PAGES;
pub const MAX_RESPONSE_BYTES: u64 = model::MAX_RESPONSE_BYTES;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/gcp-cloud-sql-instance-result/contract.v1.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn consent_authority() -> bool {
        false
    }

    pub const fn effect_authority() -> bool {
        false
    }

    pub const fn verification_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudSqlContract {
    value: serde_json::Value,
}

impl GcpCloudSqlContract {
    pub fn baseline() -> Result<Self, GcpCloudSqlInstanceResultServiceError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| GcpCloudSqlInstanceResultServiceError::TamperedEvidence)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        Digest::parse(CONTRACT_DIGEST).expect("contract digest constant is valid")
    }

    pub fn validate(&self) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        let object = self
            .value
            .as_object()
            .ok_or(GcpCloudSqlInstanceResultServiceError::TamperedEvidence)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "apiBasis",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "projection",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_SCHEMA)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || Digest::from_text(CONTRACT_DIGEST_INPUT).as_str() != CONTRACT_DIGEST
        {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        let api_basis = object
            .get("apiBasis")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpCloudSqlInstanceResultServiceError::TamperedEvidence)?;
        for (key, value) in [
            (
                "instancesGet",
                "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances/get",
            ),
            (
                "instancesList",
                "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances/list",
            ),
            (
                "operationsGet",
                "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/operations/get",
            ),
        ] {
            if api_basis.get(key).and_then(serde_json::Value::as_str) != Some(value) {
                return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
            }
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpCloudSqlInstanceResultServiceError::TamperedEvidence)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpCloudSqlInstanceResultServiceError::TamperedEvidence)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpCloudSqlInstanceResultServiceError::TamperedEvidence)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        for forbidden in [
            "execute_sql",
            "instances.insert",
            "instances.patch",
            "instances.delete",
            "instances.restart",
            "instances.failover",
            "backupRuns.create",
            "backupRuns.restore",
            "users.create",
            "sslCerts.create",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
            }
        }
        Ok(())
    }
}

pub type Contract = GcpCloudSqlContract;

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_and_authority_boundary_are_honest() {
        GcpCloudSqlContract::baseline().expect("valid Cloud SQL contract");
        assert_eq!(
            Digest::from_text(CONTRACT_DIGEST_INPUT).as_str(),
            CONTRACT_DIGEST
        );
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::outcome_adoption());
    }
}
