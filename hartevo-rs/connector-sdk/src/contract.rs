use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

use super::{
    CONNECTOR_SDK_SCHEMA_VERSION, MAX_AUTH_SESSION_TTL_SECONDS, MAX_CREDENTIAL_LEASE_TTL_SECONDS,
    MAX_PROBE_TTL_SECONDS, MAX_WORKER_LEASE_TTL_SECONDS, ProviderAdapterOperation,
    ProviderEvidenceClass, ProviderProvenanceClass, WorkerLeaseState,
};

const CONNECTOR_CONTRACT_JSON: &str =
    include_str!("../../../contracts/providers/connector-sdk.v1.json");
const CONTRACT_VERSION: &str = "connector-sdk-e1/v1";
const PROVIDER_ADAPTER_CONTRACT_VERSION: &str = "provider-adapter-e1/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorContract {
    schema_version: String,
    contract_version: String,
    provider_adapter_contract_version: String,
    authority: ContractAuthority,
    secret_material: SecretMaterial,
    operations: Vec<ProviderAdapterOperation>,
    evidence_classes: Vec<ProviderEvidenceClass>,
    provenance_classes: Vec<ProviderProvenanceClass>,
    operation_evidence_bindings: BTreeMap<ProviderAdapterOperation, ProviderEvidenceClass>,
    task_states: Vec<ContractTaskState>,
    worker_states: Vec<WorkerLeaseState>,
    webhook_ordering: WebhookOrdering,
    cursor_binding: Vec<CursorBinding>,
    freshness_seconds: FreshnessSeconds,
    registrations: Vec<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ContractAuthority {
    ConnectorWorkerBoundary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SecretMaterial {
    OpaqueReferenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum ContractTaskState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WebhookOrdering {
    StrictContiguousSequence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum CursorBinding {
    ScopeDigest,
    RequestDigest,
    Sequence,
    TokenDigest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FreshnessSeconds {
    credential_lease: i64,
    auth_session: i64,
    probe: i64,
    worker_lease: i64,
    webhook: i64,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConnectorContractError {
    #[error("connector contract JSON is invalid: {0}")]
    InvalidDocument(String),
    #[error("connector contract schema version is invalid")]
    InvalidSchemaVersion,
    #[error("connector contract version is invalid")]
    InvalidContractVersion,
    #[error("provider adapter contract version is invalid")]
    InvalidProviderAdapterContractVersion,
    #[error("connector contract authority is invalid")]
    InvalidAuthority,
    #[error("connector contract secret material policy is invalid")]
    InvalidSecretMaterial,
    #[error("connector contract operations are invalid")]
    InvalidOperations,
    #[error("connector contract evidence classes are invalid")]
    InvalidEvidenceClasses,
    #[error("connector contract provenance classes are invalid")]
    InvalidProvenanceClasses,
    #[error("connector contract operation/evidence bindings are invalid")]
    InvalidOperationEvidenceBindings,
    #[error("connector contract task states are invalid")]
    InvalidTaskStates,
    #[error("connector contract worker states are invalid")]
    InvalidWorkerStates,
    #[error("connector contract webhook ordering is invalid")]
    InvalidWebhookOrdering,
    #[error("connector contract cursor binding is invalid")]
    InvalidCursorBinding,
    #[error("connector contract freshness bounds are invalid")]
    InvalidFreshness,
    #[error("connector contract contains registrations")]
    NonEmptyRegistrations,
}

impl ConnectorContract {
    pub fn baseline() -> Result<Self, ConnectorContractError> {
        Self::from_json(CONNECTOR_CONTRACT_JSON)
    }

    pub fn from_json(document: &str) -> Result<Self, ConnectorContractError> {
        let contract: Self = serde_json::from_str(document)
            .map_err(|error| ConnectorContractError::InvalidDocument(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn operations(&self) -> &[ProviderAdapterOperation] {
        &self.operations
    }

    pub fn evidence_classes(&self) -> &[ProviderEvidenceClass] {
        &self.evidence_classes
    }

    pub fn provenance_classes(&self) -> &[ProviderProvenanceClass] {
        &self.provenance_classes
    }

    pub fn registrations(&self) -> &[serde_json::Value] {
        &self.registrations
    }

    fn validate(&self) -> Result<(), ConnectorContractError> {
        if self.schema_version != CONNECTOR_SDK_SCHEMA_VERSION {
            return Err(ConnectorContractError::InvalidSchemaVersion);
        }
        if self.contract_version != CONTRACT_VERSION {
            return Err(ConnectorContractError::InvalidContractVersion);
        }
        if self.provider_adapter_contract_version != PROVIDER_ADAPTER_CONTRACT_VERSION {
            return Err(ConnectorContractError::InvalidProviderAdapterContractVersion);
        }
        if self.authority != ContractAuthority::ConnectorWorkerBoundary {
            return Err(ConnectorContractError::InvalidAuthority);
        }
        if self.secret_material != SecretMaterial::OpaqueReferenceOnly {
            return Err(ConnectorContractError::InvalidSecretMaterial);
        }
        if !exact_set(&self.operations, ProviderAdapterOperation::ALL) {
            return Err(ConnectorContractError::InvalidOperations);
        }
        if !exact_set(&self.evidence_classes, ProviderEvidenceClass::ALL) {
            return Err(ConnectorContractError::InvalidEvidenceClasses);
        }
        if !exact_set(&self.provenance_classes, ProviderProvenanceClass::ALL) {
            return Err(ConnectorContractError::InvalidProvenanceClasses);
        }
        if self.operation_evidence_bindings.len() != ProviderAdapterOperation::ALL.len()
            || self.operations.iter().any(|operation| {
                self.operation_evidence_bindings.get(operation).copied()
                    != Some(expected_evidence(*operation))
            })
        {
            return Err(ConnectorContractError::InvalidOperationEvidenceBindings);
        }
        if !exact_set(
            &self.task_states,
            &[
                ContractTaskState::Queued,
                ContractTaskState::Running,
                ContractTaskState::Succeeded,
                ContractTaskState::Failed,
                ContractTaskState::Canceled,
            ],
        ) {
            return Err(ConnectorContractError::InvalidTaskStates);
        }
        if !exact_set(
            &self.worker_states,
            &[
                WorkerLeaseState::Active,
                WorkerLeaseState::Canceled,
                WorkerLeaseState::Expired,
            ],
        ) {
            return Err(ConnectorContractError::InvalidWorkerStates);
        }
        if self.webhook_ordering != WebhookOrdering::StrictContiguousSequence {
            return Err(ConnectorContractError::InvalidWebhookOrdering);
        }
        if !exact_set(
            &self.cursor_binding,
            &[
                CursorBinding::ScopeDigest,
                CursorBinding::RequestDigest,
                CursorBinding::Sequence,
                CursorBinding::TokenDigest,
            ],
        ) {
            return Err(ConnectorContractError::InvalidCursorBinding);
        }
        if self.freshness_seconds.credential_lease != MAX_CREDENTIAL_LEASE_TTL_SECONDS
            || self.freshness_seconds.auth_session != MAX_AUTH_SESSION_TTL_SECONDS
            || self.freshness_seconds.probe != MAX_PROBE_TTL_SECONDS
            || self.freshness_seconds.worker_lease != MAX_WORKER_LEASE_TTL_SECONDS
            || self.freshness_seconds.webhook != 86_400
        {
            return Err(ConnectorContractError::InvalidFreshness);
        }
        if !self.registrations.is_empty() {
            return Err(ConnectorContractError::NonEmptyRegistrations);
        }
        Ok(())
    }
}

fn exact_set<T: Ord + Copy>(actual: &[T], expected: &[T]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            == expected
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
}

fn expected_evidence(operation: ProviderAdapterOperation) -> ProviderEvidenceClass {
    match operation {
        ProviderAdapterOperation::Probe => ProviderEvidenceClass::ProbeObservation,
        ProviderAdapterOperation::BeginAuth | ProviderAdapterOperation::Refresh => {
            ProviderEvidenceClass::Authentication
        }
        ProviderAdapterOperation::Read => ProviderEvidenceClass::ReadObservation,
        ProviderAdapterOperation::PrepareEffect => ProviderEvidenceClass::PreparedEffect,
        ProviderAdapterOperation::Execute => ProviderEvidenceClass::ReceiptCandidate,
        ProviderAdapterOperation::Reconcile => ProviderEvidenceClass::ReconciliationObservation,
        ProviderAdapterOperation::Verify => ProviderEvidenceClass::VerificationObservation,
        ProviderAdapterOperation::HandleWebhook => ProviderEvidenceClass::WebhookObservation,
        ProviderAdapterOperation::Revoke => ProviderEvidenceClass::RevocationObservation,
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectorContract, ConnectorContractError};

    #[test]
    fn checked_in_contract_is_typed_and_empty() {
        let contract = ConnectorContract::baseline().expect("checked-in contract");
        assert!(contract.registrations().is_empty());
        assert_eq!(contract.operations().len(), 10);
        assert_eq!(contract.evidence_classes().len(), 9);
    }

    #[test]
    fn unknown_and_tampered_fields_fail_closed() {
        let baseline = include_str!("../../../contracts/providers/connector-sdk.v1.json");
        let unknown = baseline.replace(
            "\"registrations\": []",
            "\"registrations\": [], \"unknown\": true",
        );
        assert!(matches!(
            ConnectorContract::from_json(&unknown),
            Err(ConnectorContractError::InvalidDocument(_))
        ));
        let tampered = baseline.replace("\"execute\"", "\"execute_tampered\"");
        assert!(matches!(
            ConnectorContract::from_json(&tampered),
            Err(ConnectorContractError::InvalidDocument(_))
        ));
    }

    #[test]
    fn duplicate_and_missing_contract_entries_fail_closed() {
        let baseline = include_str!("../../../contracts/providers/connector-sdk.v1.json");
        let duplicate = baseline.replace(
            "\"probe\",\n    \"begin_auth\"",
            "\"probe\",\n    \"probe\"",
        );
        assert_eq!(
            ConnectorContract::from_json(&duplicate),
            Err(ConnectorContractError::InvalidOperations)
        );
        let missing = baseline.replace("  \"authority\": \"connector_worker_boundary\",\n", "");
        assert!(matches!(
            ConnectorContract::from_json(&missing),
            Err(ConnectorContractError::InvalidDocument(_))
        ));
    }
}
