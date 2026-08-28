//! Layer-1 ServiceNow change and approval provider contract.
//!
//! The crate is intentionally standalone.  It owns no ServiceNow credentials,
//! no HTTP client, no kernel event authority, and no mutation path.  A typed
//! provider consumes recording/fake/BLOCKED_ENV transports, validates an exact
//! instance and schema binding, and emits bounded projections or proposals
//! that remain below the Domain Kernel's Truth/Consent/Effect/Receipt/
//! Verification/Outcome authority.

#![forbid(unsafe_code)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ApprovalProposal, ApprovalProposalOperation, ApprovalProposalRequest, ChangeProposal,
    ChangeProposalRequest, ChangeResultProposal, ChangeResultRequest, CorrelationBinding,
    FutureWriteGate, MissionServiceNowChangeConsumer, ProposalOperation,
};
pub use model::{
    ApprovalFieldMapping, ApprovalProjection, ApprovalRecordIdentity, AuditFieldMapping,
    AuditProjection, ChangeFieldMapping, ChangeProjection, ChangeRecordIdentity, ConsentReference,
    DomainIdentity, EvidenceProvenance, FieldName, InstanceIdentity, MissionScope,
    NormalizedOrigin, ProviderIdentity, ProviderRevision, ReleaseIdentity, SchemaMapping,
    SchemaMappingReceipt, ServiceNowScope, ServiceNowScopeReceipt, StateMappingEntry, SysId,
    TableName,
};
pub use provider::{
    AclEvidence, AclProbe, InstanceProbe, ProbeReceipt, ProbeStatus, ProviderPage,
    ProviderPageRequest, ProviderProbeResponse, RawFieldValue, RawRecord, SchemaEvidence,
    SchemaProbe, ServiceNowChangeProvider, ServiceNowTransport, TransportError,
};
pub use service::{
    CapabilityDescription, CompiledQuery, QueryBounds, QueryKind, RegistrationId,
    RegistrationRegistry, RegistrationStatus, ServiceNowChangeService, ServiceNowRegistration,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use hartevo_connector_sdk::{ConnectorScope, SecretReference};
pub use hartevo_domain_kernel::{ConsentRecordId, MissionId, ProjectId, TenantId, WorkProductId};

pub const PLUGIN_ID: &str = "servicenow.change";
pub const PLUGIN_VERSION: &str = "servicenow-change-01/v1";
pub const CONTRACT_VERSION: &str = "servicenow-change-01-readonly/v1";
pub const SCHEMA_VERSION: &str = "hartevo-servicenow-change-contract/v1";
pub const PROVIDER_ID: &str = "servicenow.table-api.readonly";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/servicenow-change/contract.v1.json");

/// Return the digest of the checked-in contract document.
pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_JSON.as_bytes())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn canonical_json_digest<T: Serialize>(
    value: &T,
) -> std::result::Result<String, serde_json::Error> {
    serde_json::to_vec(value).map(|bytes| sha256_hex(&bytes))
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

pub(crate) fn valid_non_empty(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

/// Errors are deliberately typed around fail-closed boundaries.  No variant
/// carries an OAuth token, cookie, raw provider payload, journal body, or
/// other unbounded provider data.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ServiceNowChangeError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid normalized HTTPS origin")]
    InvalidOrigin,
    #[error("invalid sys_id")]
    InvalidSysId,
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("scope is not exact or the OAuth SecretReference scope does not match")]
    ScopeMismatch,
    #[error("consent reference is outside the Mission/Project/Work Product scope")]
    ConsentScopeMismatch,
    #[error("schema mapping is invalid: {0}")]
    InvalidSchemaMapping(String),
    #[error("schema mapping digest does not match its contents")]
    SchemaMappingDigestMismatch,
    #[error("provider identity is invalid")]
    InvalidProviderIdentity,
    #[error("registration binding is invalid")]
    InvalidRegistration,
    #[error("registration is not active")]
    RegistrationNotActive,
    #[error("registration was not found")]
    RegistrationNotFound,
    #[error("registration probe is required")]
    ProbeRequired,
    #[error("registration probe is BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("instance identity mismatch: {0}")]
    InstanceMismatch(String),
    #[error("ACL visibility is not explicit for field {field}")]
    AclNotVisible { field: String },
    #[error("schema drift: {0}")]
    SchemaDrift(String),
    #[error("provider record identity mismatch")]
    RecordIdentityMismatch,
    #[error("provider field is omitted or null: {0}")]
    FieldNotVisible(String),
    #[error("provider state is not in the configured mapping")]
    StateMappingDrift,
    #[error("provider revision is stale or missing")]
    StaleProviderRevision,
    #[error("duplicate or missing approval record")]
    ApprovalSetMismatch,
    #[error("caller-supplied encoded queries are not accepted")]
    CallerQueryNotAllowed,
    #[error("compiled query binding is invalid")]
    QueryBindingMismatch,
    #[error("pagination exceeded a configured bound")]
    PaginationBound,
    #[error("pagination cursor repeated")]
    PaginationLoop,
    #[error("response exceeded the configured byte bound")]
    ResponseTooLarge,
    #[error("proposal is invalid: {0}")]
    InvalidProposal(String),
    #[error("future writes require a configured correlation field")]
    MissingCorrelation,
    #[error("future writes require exact readback")]
    ExactReadbackRequired,
    #[error("ambiguous future write must fail closed")]
    AmbiguousWrite,
    #[error("provider transport failed: {0}")]
    Transport(String),
    #[error("contract document is invalid: {0}")]
    InvalidContract(String),
}

pub type Result<T> = std::result::Result<T, ServiceNowChangeError>;

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{CONTRACT_JSON, CONTRACT_VERSION, PLUGIN_ID, SCHEMA_VERSION, contract_digest};

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        layer: String,
        read_only: bool,
        connected: bool,
        native_evidence: bool,
        first_party_evidence: bool,
    }

    #[test]
    fn contract_is_layer_one_read_only_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked ServiceNow contract");
        assert_eq!(contract.schema_version, SCHEMA_VERSION);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, "layer_1");
        assert!(contract.read_only);
        assert!(!contract.connected);
        assert!(!contract.native_evidence);
        assert!(!contract.first_party_evidence);
        assert!(super::is_sha256(&contract_digest()));
    }
}
