//! Standalone Layer-1 AWS GuardDuty finding-result boundary.
//!
//! This crate owns only a bounded, typed detector/list/get/statistics seam and
//! a Mission-scoped proposal/record/verify surface. It never resolves or
//! serializes credentials, retains raw GuardDuty payloads, mutates findings or
//! detectors, performs incident response, exports raw data, claims connected,
//! native, or first-party evidence, or adopts Hartevo authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
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

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsGuardDutyConsumer, MissionAwsGuardDutyObservation, MissionAwsGuardDutyResult,
};
pub use model::*;
pub use provider::{
    AwsGuardDutyProvider, AwsGuardDutyProviderDefinition, AwsGuardDutyTransport,
    BlockedEnvTransport, CostReceipt, FixtureTransport, GetFindingsRequest, GetFindingsResponse,
    ListDetectorsRequest, ListDetectorsResponse, ListFindingsRequest, ListFindingsResponse,
    LoopbackTransport, Operation, RecordedRequest, RecordingTransport, RequestReceipt,
    ScriptedTransport, StatisticsRequest, StatisticsResponse, TransportError, TransportFailure,
};
pub use service::{
    AwsGuardDutyFindingProposal, AwsGuardDutyFindingRecord, AwsGuardDutyFindingService,
    AwsGuardDutyRegistration, Capability, RegistrationRequest, RegistrationStatus,
    ServiceOperation, VerificationReport,
};

pub const AWS_GUARDDUTY_SCHEMA_VERSION: &str = "hartevo.aws-guardduty-finding-result-contract/v1";
pub const AWS_GUARDDUTY_CONTRACT_VERSION: &str = "aws-guardduty-finding-result/v1";
pub const AWS_GUARDDUTY_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_GUARDDUTY_PLUGIN_ID: &str = "aws-guardduty-finding-result";
pub const AWS_GUARDDUTY_API_VERSION: &str = "2017-11-28";
pub const AWS_GUARDDUTY_PROVIDER_REVISION: &str =
    "guardduty-list-detectors-list-findings-get-findings-statistics-r1";
pub const AWS_GUARDDUTY_SERVICE_ID: &str = "aws.guardduty.finding-result";
pub const AWS_GUARDDUTY_PROVIDER_ID: &str = "aws.guardduty.finding-result";
pub const AWS_GUARDDUTY_CONSUMER_ID: &str = "mission.aws.guardduty.finding-result";
pub const AWS_GUARDDUTY_SERVICE_NAME: &str = "AwsGuardDutyFindingService";
pub const AWS_GUARDDUTY_PROVIDER_NAME: &str = "AwsGuardDutyProvider";
pub const AWS_GUARDDUTY_CONSUMER_NAME: &str = "MissionAwsGuardDutyConsumer";
pub const AWS_GUARDDUTY_SERVICE_SCHEMA: &str = "hartevo.aws-guardduty-finding-result-service/v1";
pub const AWS_GUARDDUTY_PROVIDER_SCHEMA: &str = "hartevo.aws-guardduty-provider/v1";
pub const AWS_GUARDDUTY_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-guardduty-finding-result-consumer/v1";
pub const AWS_GUARDDUTY_LIST_DETECTORS_PERMISSION: &str = "guardduty:ListDetectors";
pub const AWS_GUARDDUTY_LIST_FINDINGS_PERMISSION: &str = "guardduty:ListFindings";
pub const AWS_GUARDDUTY_GET_FINDINGS_PERMISSION: &str = "guardduty:GetFindings";
pub const AWS_GUARDDUTY_GET_STATISTICS_PERMISSION: &str = "guardduty:GetFindingsStatistics";
pub const AWS_GUARDDUTY_CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-guardduty-finding-result-contract/v1|layer=1|service=aws.guardduty.finding-result|provider=aws.guardduty.finding-result|consumer=mission.aws.guardduty.finding-result";
pub const AWS_GUARDDUTY_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-guardduty-finding-result/aws-guardduty-finding-result.v1.json"
);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsGuardDutyFindingResultError {
    #[error(transparent)]
    Model(#[from] model::ModelError),
    #[error(transparent)]
    Plugin(#[from] PluginError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("the GuardDuty registration is missing")]
    RegistrationMissing,
    #[error("the GuardDuty registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("the GuardDuty SigV4 secret reference is revoked")]
    SecretRevoked,
    #[error("the GuardDuty registration is invalid or drifted")]
    InvalidRegistration,
    #[error("the GuardDuty detector or mission scope drifted")]
    ScopeDrift,
    #[error("the GuardDuty detector discovery drifted")]
    DetectorDrift,
    #[error("the GuardDuty query or criteria drifted")]
    QueryDrift,
    #[error("the GuardDuty opaque pagination cursor was replayed")]
    PaginationReplay,
    #[error("the GuardDuty ListFindings criteria were replayed")]
    CriteriaReplay,
    #[error("the GuardDuty GetFindings batch is outside the list allowlist")]
    FindingOutOfAllowlist,
    #[error("the GuardDuty provider page binding drifted")]
    PageBindingMismatch,
    #[error("the GuardDuty response exceeded its configured bound")]
    ResponseBoundExceeded,
    #[error("the GuardDuty evidence is stale")]
    StaleEvidence,
    #[error("the GuardDuty evidence is archived or otherwise non-actionable")]
    ArchivedEvidence,
    #[error("the GuardDuty evidence is unknown or malformed")]
    UnknownEvidence,
    #[error("the GuardDuty evidence digest or projection was tampered with")]
    TamperedEvidence,
    #[error("the GuardDuty contract document is invalid: {0}")]
    InvalidContract(String),
}

pub type Result<T> = std::result::Result<T, AwsGuardDutyFindingResultError>;

pub fn contract_digest() -> Digest {
    Digest::from_text(AWS_GUARDDUTY_CONTRACT_DIGEST_INPUT)
}

pub fn version_digest() -> Digest {
    Digest::from_fields(
        "hartevo.aws-guardduty-version/v1",
        &[
            AWS_GUARDDUTY_PLUGIN_ID.to_owned(),
            AWS_GUARDDUTY_PLUGIN_VERSION.to_owned(),
        ],
    )
}

pub fn api_digest() -> Digest {
    Digest::from_fields(
        "hartevo.aws-guardduty-api/v1",
        &[
            AWS_GUARDDUTY_API_VERSION.to_owned(),
            AWS_GUARDDUTY_PROVIDER_REVISION.to_owned(),
            "ListDetectors".to_owned(),
            "ListFindings".to_owned(),
            "GetFindings".to_owned(),
            "GetFindingsStatistics".to_owned(),
        ],
    )
}

pub fn permission_digest() -> Digest {
    Digest::from_fields(
        "hartevo.aws-guardduty-permissions/v1",
        &[
            AWS_GUARDDUTY_LIST_DETECTORS_PERMISSION.to_owned(),
            AWS_GUARDDUTY_LIST_FINDINGS_PERMISSION.to_owned(),
            AWS_GUARDDUTY_GET_FINDINGS_PERMISSION.to_owned(),
            AWS_GUARDDUTY_GET_STATISTICS_PERMISSION.to_owned(),
            "mission.scope".to_owned(),
        ],
    )
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Validate the checked-in machine contract and its non-authoritative boundary.
pub fn validate_contract_document() -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(AWS_GUARDDUTY_CONTRACT_JSON)
        .map_err(|error| AwsGuardDutyFindingResultError::InvalidContract(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        AwsGuardDutyFindingResultError::InvalidContract("root is not an object".to_owned())
    })?;
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AwsGuardDutyFindingResultError::InvalidContract(format!("missing {name}"))
            })
    };
    if string_field("schemaVersion")? != AWS_GUARDDUTY_SCHEMA_VERSION
        || string_field("contractVersion")? != AWS_GUARDDUTY_CONTRACT_VERSION
        || string_field("pluginVersion")? != AWS_GUARDDUTY_PLUGIN_VERSION
        || string_field("contractDigestInput")? != AWS_GUARDDUTY_CONTRACT_DIGEST_INPUT
        || string_field("contractDigest")? != contract_digest().as_str()
        || string_field("layer")? != "Layer-1"
    {
        return Err(AwsGuardDutyFindingResultError::InvalidContract(
            "contract identity or digest drifted".to_owned(),
        ));
    }
    for section_name in ["service", "provider", "consumer"] {
        if object
            .get(section_name)
            .and_then(serde_json::Value::as_object)
            .is_none()
        {
            return Err(AwsGuardDutyFindingResultError::InvalidContract(format!(
                "missing {section_name}"
            )));
        }
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AwsGuardDutyFindingResultError::InvalidContract("missing provider".to_owned())
        })?;
    for field in [
        "native",
        "connected",
        "firstParty",
        "liveCredentialResolution",
        "externalWrites",
    ] {
        if provider.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(AwsGuardDutyFindingResultError::InvalidContract(format!(
                "provider.{field} must be false"
            )));
        }
    }
    let transport = object
        .get("transport")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AwsGuardDutyFindingResultError::InvalidContract("missing transport".to_owned())
        })?;
    if transport
        .get("liveHttps")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
        || transport
            .get("liveSigV4Resolution")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(AwsGuardDutyFindingResultError::InvalidContract(
            "live transport must be false".to_owned(),
        ));
    }
    let authority = object
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            AwsGuardDutyFindingResultError::InvalidContract("missing authority".to_owned())
        })?;
    for field in [
        "externalWrites",
        "archiveFinding",
        "muteFinding",
        "updateFinding",
        "detectorConfiguration",
        "threatListMutation",
        "sampleGeneration",
        "rawExport",
        "incidentResponseEffect",
        "truthAuthority",
        "consentAuthority",
        "effectAuthority",
        "receiptAuthority",
        "verificationAuthority",
        "outcomeAuthority",
        "productionCertification",
        "connected",
        "native",
        "firstParty",
    ] {
        if authority.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(AwsGuardDutyFindingResultError::InvalidContract(format!(
                "authority.{field} must be false"
            )));
        }
    }
    Ok(())
}

/// Build the host-mountable descriptor set. Mounting and outcome adoption stay
/// outside this Layer-1 crate.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition> {
    validate_contract_document()?;
    let plugin_id = PluginId::new(AWS_GUARDDUTY_PLUGIN_ID)?;
    let service_id = ServiceId::new(AWS_GUARDDUTY_SERVICE_ID)?;
    let provider_id = ProviderId::new(AWS_GUARDDUTY_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(AWS_GUARDDUTY_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_GUARDDUTY_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_GUARDDUTY_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(AWS_GUARDDUTY_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        validate_contract_document().expect("checked GuardDuty contract");
        assert_eq!(contract_digest().as_str().len(), 64);
        assert_eq!(api_digest().as_str().len(), 64);
        assert_eq!(permission_digest().as_str().len(), 64);
    }
}
