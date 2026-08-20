//! Service, registration, proposal, recording, and verification boundaries.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AlloyDbReadOperation, AuthorityBoundary, ClusterPosture, Digest, EvidenceDigests,
    EvidenceState, GcpAlloyDbClusterScope, GcpAlloyDbTarget, InstancePosture, MAX_RESPONSE_BYTES,
    MissionBinding, ModelError, PaginationEvidence, ProviderProvenance, RedactionSummary, Revision,
    SecretReference, digest_serializable,
};
use crate::provider::{
    GcpAlloyDbAdminProvider, GcpAlloyDbProviderDefinition, GcpAlloyDbTransport, GetClusterRequest,
    GetInstanceRequest, ProviderError, ProviderRequestReceipt, TransportError,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, GCP_ALLOYDB_PROVIDER_ID,
    GCP_ALLOYDB_PROVIDER_VERSION, PLUGIN_VERSION, SERVICE_ID, contract_digest,
    evidence_binding_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractDocumentError {
    #[error("AlloyDB contract JSON is invalid")]
    InvalidJson,
    #[error("AlloyDB contract metadata drifted")]
    Drift,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpAlloyDbClusterResultContract {
    value: serde_json::Value,
}

impl GcpAlloyDbClusterResultContract {
    pub fn baseline() -> Result<Self, ContractDocumentError> {
        let value = serde_json::from_str::<serde_json::Value>(crate::CONTRACT_JSON)
            .map_err(|_| ContractDocumentError::InvalidJson)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), ContractDocumentError> {
        let object = self.value.as_object().ok_or(ContractDocumentError::Drift)?;
        for key in [
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "officialReferences",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "bounds",
            "evidence",
            "redaction",
            "authority",
            "honesty",
            "forbidden",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(ContractDocumentError::Drift);
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(crate::SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(ContractDocumentError::Drift);
        }
        let references = object
            .get("officialReferences")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractDocumentError::Drift)?;
        if references
            != &[
                serde_json::Value::String(crate::OFFICIAL_CLUSTER_GET.to_owned()),
                serde_json::Value::String(crate::OFFICIAL_INSTANCE_GET.to_owned()),
                serde_json::Value::String(crate::OFFICIAL_REST_REFERENCE.to_owned()),
            ]
        {
            return Err(ContractDocumentError::Drift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Drift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("GcpAlloyDbClusterResultService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Drift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Drift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(GCP_ALLOYDB_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("GcpAlloyDbAdminProvider")
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Drift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Drift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionGcpAlloyDbClusterConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Drift);
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Drift)?;
        for key in [
            "externalWrites",
            "create",
            "patch",
            "delete",
            "restart",
            "failover",
            "promote",
            "backup",
            "restore",
            "export",
            "import",
            "sql",
            "userMutation",
            "iamMutation",
            "connected",
            "native",
            "firstParty",
            "durableProviderReceipt",
            "truthAuthority",
            "consentAuthority",
            "effectAuthority",
            "receiptAuthority",
            "verificationAuthority",
            "outcomeAuthority",
            "workProductAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractDocumentError::Drift);
            }
        }
        for required in [
            "create_cluster",
            "patch_cluster",
            "delete_cluster",
            "restart_cluster",
            "failover_cluster",
            "promote_instance",
            "execute_sql",
            "read_sql_rows",
            "mutate_users",
            "mutate_iam",
            "read_connection_info",
            "read_endpoints",
            "read_credentials",
            "claim_connected",
            "claim_native",
            "claim_first_party",
            "claim_durable_provider_receipt",
            "adopt_work_product",
        ] {
            if !object
                .get("forbidden")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(required)))
            {
                return Err(ContractDocumentError::Drift);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is terminally reversed")]
    Reversed,
    #[error("registration is already active")]
    AlreadyActive,
    #[error("registration digest or binding drifted")]
    Tampered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbRegistration {
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

impl GcpAlloyDbRegistration {
    pub fn new(
        scope: &GcpAlloyDbClusterScope,
        secret: &SecretReference,
        provider: &GcpAlloyDbProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self, RegistrationError> {
        let mut value = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest().clone(),
            evidence_digest: evidence_binding_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
            registration_digest: Digest::from_text("unsealed-gcp-alloydb-registration"),
        };
        value.registration_digest = value.calculate_digest();
        value.validate(scope, provider, secret)?;
        Ok(value)
    }

    pub fn validate(
        &self,
        scope: &GcpAlloyDbClusterScope,
        provider: &GcpAlloyDbProviderDefinition,
        secret: &SecretReference,
    ) -> Result<(), RegistrationError> {
        let mut expected = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest().clone(),
            evidence_digest: evidence_binding_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision: self.registration_revision,
            state: self.state,
            reversible: true,
            revocable: true,
            registration_digest: Digest::from_text("unsealed-gcp-alloydb-registration"),
        };
        expected.registration_digest = expected.calculate_digest();
        if self != &expected || self.registration_digest != self.calculate_digest() {
            return Err(RegistrationError::Tampered);
        }
        Ok(())
    }

    pub fn validate_digest_only(&self) -> Result<(), RegistrationError> {
        let baseline_provider = GcpAlloyDbProviderDefinition::baseline();
        if self.plugin_version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != GCP_ALLOYDB_PROVIDER_ID
            || self.provider_version != GCP_ALLOYDB_PROVIDER_VERSION
            || self.provider_revision != API_REVISION
            || self.provider_digest != baseline_provider.provider_digest
            || self.api_digest != baseline_provider.api_digest
            || self.evidence_digest != evidence_binding_digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.calculate_digest()
        {
            return Err(RegistrationError::Tampered);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        if self.state == RegistrationState::Reversed {
            return Err(RegistrationError::Reversed);
        }
        self.transition_to(RegistrationState::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if self.state == RegistrationState::Active {
            return Err(RegistrationError::AlreadyActive);
        }
        if self.state == RegistrationState::Reversed {
            return Err(RegistrationError::Reversed);
        }
        self.transition_to(RegistrationState::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if self.state == RegistrationState::Reversed {
            return Err(RegistrationError::Reversed);
        }
        self.transition_to(RegistrationState::Reversed)
    }

    fn transition_to(
        &mut self,
        new_state: RegistrationState,
    ) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        let previous_state = self.state;
        self.state = new_state;
        self.registration_digest = self.calculate_digest();
        let transition_digest = Digest::from_parts(
            "gcp-alloydb-registration-transition/v1",
            &[
                ("previous", format!("{previous_state:?}")),
                ("new", format!("{new_state:?}")),
                ("registration", self.registration_digest.as_str().to_owned()),
            ],
        );
        Ok(RegistrationTransitionEvidence {
            previous_state,
            new_state,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-registration/v1",
            &[
                ("plugin", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("provider_revision", self.provider_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.value().to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                ("reversible", self.reversible.to_string()),
                ("revocable", self.revocable.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbReadRequest {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub max_response_bytes: usize,
    pub max_pages_per_operation: usize,
    pub request_digest: Digest,
}

impl GcpAlloyDbReadRequest {
    pub fn new(
        scope: &GcpAlloyDbClusterScope,
        registration: &GcpAlloyDbRegistration,
        provider: &GcpAlloyDbProviderDefinition,
        secret: &SecretReference,
    ) -> Self {
        let mut value = Self {
            scope_digest: scope.digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permissions.digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_pages_per_operation: 1,
            request_digest: Digest::from_text("unsealed-gcp-alloydb-read-request"),
        };
        value.request_digest = value.calculate_digest();
        value
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.max_response_bytes != MAX_RESPONSE_BYTES
            || self.max_pages_per_operation != 1
            || self.request_digest != self.calculate_digest()
        {
            return Err(ServiceError::RequestDrift);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-read-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("max_bytes", self.max_response_bytes.to_string()),
                ("max_pages", self.max_pages_per_operation.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub operation: Option<AlloyDbReadOperation>,
    pub category: String,
    pub status_code: Option<u16>,
    pub detail_digest: Option<Digest>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn new(
        operation: Option<AlloyDbReadOperation>,
        category: &str,
        status_code: Option<u16>,
        detail_digest: Option<Digest>,
    ) -> Self {
        let failure_digest = Digest::from_parts(
            "gcp-alloydb-failure/v1",
            &[
                (
                    "operation",
                    operation.map_or_else(String::new, |value| value.api_operation().to_owned()),
                ),
                ("category", category.to_owned()),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "detail",
                    detail_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        Self {
            operation,
            category: category.to_owned(),
            status_code,
            detail_digest,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbClusterResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub mission: MissionBinding,
    pub target: GcpAlloyDbTarget,
    pub state: EvidenceState,
    pub cluster: Option<ClusterPosture>,
    pub instance: Option<InstancePosture>,
    pub failure: Option<FailureEvidence>,
    pub pagination: PaginationEvidence,
    pub redaction: RedactionSummary,
    pub evidence: EvidenceDigests,
    pub request_receipts: Vec<ProviderRequestReceipt>,
    pub provenance: ProviderProvenance,
    pub authority: AuthorityBoundary,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub durable_provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl GcpAlloyDbClusterResultProposal {
    fn new(
        registration: &GcpAlloyDbRegistration,
        scope: &GcpAlloyDbClusterScope,
        request: &GcpAlloyDbReadRequest,
        state: EvidenceState,
        cluster: Option<ClusterPosture>,
        instance: Option<InstancePosture>,
        failure: Option<FailureEvidence>,
        pagination: PaginationEvidence,
        request_receipts: Vec<ProviderRequestReceipt>,
        provenance: ProviderProvenance,
        cluster_response_digest: Option<Digest>,
        instance_response_digest: Option<Digest>,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            api_digest: registration.api_digest.clone(),
            permission_digest: registration.permission_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            evidence_binding_digest: registration.evidence_digest.clone(),
            secret_reference_digest: registration.secret_reference_digest.clone(),
            cluster_response_digest,
            instance_response_digest,
            evidence_digest: Digest::from_text("unsealed-gcp-alloydb-evidence"),
        };
        let authority = AuthorityBoundary::layer_one();
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            request.digest(),
            state,
            cluster.as_ref(),
            instance.as_ref(),
            failure.as_ref(),
            &pagination,
            &request_receipts,
            provenance,
            authority,
        );
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.digest().clone(),
            request_digest: request.digest().clone(),
            mission: scope.mission.clone(),
            target: scope.target.clone(),
            state,
            cluster,
            instance,
            failure,
            pagination,
            redaction: RedactionSummary::complete(),
            evidence,
            request_receipts,
            provenance,
            authority,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            durable_provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-gcp-alloydb-proposal"),
        };
        value.proposal_digest = value.calculate_digest();
        value
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.durable_provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || !self.redaction.is_complete()
            || !self.authority.is_below_kernel_authority()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self
                .request_receipts
                .iter()
                .any(|receipt| !receipt.validate())
        {
            return Err(ServiceError::TamperedEvidence);
        }
        if self.state == EvidenceState::Ready {
            if self.cluster.is_none() || self.instance.is_none() || self.failure.is_some() {
                return Err(ServiceError::TamperedEvidence);
            }
            if !self.pagination.complete {
                return Err(ServiceError::TamperedEvidence);
            }
        } else if self.cluster.is_some() || self.instance.is_some() {
            return Err(ServiceError::TamperedEvidence);
        }
        if self.evidence.evidence_digest
            != calculate_evidence_digest(
                &self.evidence,
                &self.request_digest,
                self.state,
                self.cluster.as_ref(),
                self.instance.as_ref(),
                self.failure.as_ref(),
                &self.pagination,
                &self.request_receipts,
                self.provenance,
                self.authority,
            )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_eligible(&self) -> bool {
        matches!(self.state, EvidenceState::Ready)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-cluster-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission binding serializes"),
                ),
                (
                    "target",
                    serde_json::to_string(&self.target).expect("target serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "cluster",
                    self.cluster.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("cluster posture serializes")
                    }),
                ),
                (
                    "instance",
                    self.instance.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("instance posture serializes")
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure evidence serializes")
                    }),
                ),
                (
                    "pagination",
                    serde_json::to_string(&self.pagination)
                        .expect("pagination evidence serializes"),
                ),
                (
                    "redaction",
                    serde_json::to_string(&self.redaction).expect("redaction summary serializes"),
                ),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).expect("evidence digests serialize"),
                ),
                (
                    "receipts",
                    self.request_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    request_digest: &Digest,
    state: EvidenceState,
    cluster: Option<&ClusterPosture>,
    instance: Option<&InstancePosture>,
    failure: Option<&FailureEvidence>,
    pagination: &PaginationEvidence,
    request_receipts: &[ProviderRequestReceipt],
    provenance: ProviderProvenance,
    authority: AuthorityBoundary,
) -> Digest {
    let material = vec![
        evidence.plugin_version_digest.as_str().to_owned(),
        evidence.contract_digest.as_str().to_owned(),
        evidence.provider_digest.as_str().to_owned(),
        evidence.api_digest.as_str().to_owned(),
        evidence.permission_digest.as_str().to_owned(),
        evidence.scope_digest.as_str().to_owned(),
        evidence.evidence_binding_digest.as_str().to_owned(),
        evidence.secret_reference_digest.as_str().to_owned(),
        evidence
            .cluster_response_digest
            .as_ref()
            .map_or_else(String::new, |digest| digest.as_str().to_owned()),
        evidence
            .instance_response_digest
            .as_ref()
            .map_or_else(String::new, |digest| digest.as_str().to_owned()),
        request_digest.as_str().to_owned(),
        format!("{state:?}"),
        cluster.map_or_else(String::new, |value| {
            serde_json::to_string(value).expect("cluster posture serializes")
        }),
        instance.map_or_else(String::new, |value| {
            serde_json::to_string(value).expect("instance posture serializes")
        }),
        failure.map_or_else(String::new, |value| {
            serde_json::to_string(value).expect("failure evidence serializes")
        }),
        serde_json::to_string(pagination).expect("pagination evidence serializes"),
        serde_json::to_string(request_receipts).expect("request receipts serialize"),
        provenance.as_str().to_owned(),
        serde_json::to_string(&authority).expect("authority boundary serializes"),
    ];
    digest_serializable(&material).expect("bounded evidence digest material serializes")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbRecordReceipt {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub local_recording: bool,
    pub provider_receipt: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl GcpAlloyDbRecordReceipt {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &GcpAlloyDbClusterResultProposal,
        replayed: bool,
    ) -> Self {
        let mut value = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            recording_digest: Digest::from_text("unsealed-gcp-alloydb-recording"),
            replayed,
            local_recording: true,
            provider_receipt: false,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        };
        value.recording_digest = value.calculate_digest();
        value
    }

    pub(crate) fn new_for_consumer(
        idempotency_key_digest: Digest,
        proposal: &GcpAlloyDbClusterResultProposal,
    ) -> Self {
        Self::new(idempotency_key_digest, proposal, false)
    }

    pub fn validate(&self) -> bool {
        self.local_recording
            && !self.provider_receipt
            && !self.durable_provider_receipt
            && !self.connected
            && !self.native
            && !self.first_party
            && self.recording_digest == self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-local-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub issue: Option<String>,
    pub proposal_digest: Digest,
    pub authority_safe: bool,
    pub provider_receipt: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("AlloyDB contract metadata drifted")]
    ContractDrift,
    #[error("provider definition drifted")]
    ProviderDefinitionDrift,
    #[error("registration is required")]
    RegistrationRequired,
    #[error("registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("registration binding was tampered")]
    RegistrationTampered,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("scope digest or exact target drifted")]
    ScopeMismatch,
    #[error("permission digest drifted")]
    PermissionMismatch,
    #[error("provider or API revision drifted")]
    ApiRevisionMismatch,
    #[error("request digest drifted")]
    RequestDrift,
    #[error("provider response was stale for the exact requested revision")]
    StaleRevision,
    #[error("provider response was tampered")]
    TamperedEvidence,
    #[error("provider response was truncated")]
    ResponseTruncated,
    #[error("provider returned an unexpected pagination loop")]
    PaginationLoop,
    #[error("recording idempotency key conflicts with an existing record")]
    ReplayConflict,
    #[error("invalid bounded request")]
    InvalidRequest,
    #[error(transparent)]
    Contract(#[from] ContractDocumentError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Registration(#[from] RegistrationError),
}

pub struct GcpAlloyDbClusterResultService<T> {
    scope: GcpAlloyDbClusterScope,
    secret: SecretReference,
    provider: GcpAlloyDbAdminProvider<T>,
    registration: GcpAlloyDbRegistration,
    records: BTreeMap<Digest, GcpAlloyDbRecordReceipt>,
}

impl<T: GcpAlloyDbTransport> fmt::Debug for GcpAlloyDbClusterResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpAlloyDbClusterResultService")
            .field("scope_digest", self.scope.digest())
            .field("secret", &self.secret)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: GcpAlloyDbTransport> GcpAlloyDbClusterResultService<T> {
    pub fn new(
        scope: GcpAlloyDbClusterScope,
        secret: SecretReference,
        provider: GcpAlloyDbAdminProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        secret
            .ensure_active()
            .map_err(|_| ServiceError::SecretRevoked)?;
        if secret.scope_digest() != scope.digest() {
            return Err(ServiceError::ScopeMismatch);
        }
        provider
            .definition()
            .validate()
            .map_err(|_| ServiceError::ProviderDefinitionDrift)?;
        GcpAlloyDbClusterResultContract::baseline()?;
        let registration = GcpAlloyDbRegistration::new(
            &scope,
            &secret,
            provider.definition(),
            Revision::new(1).map_err(ServiceError::Model)?,
        )?;
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn describe_capabilities(&self) -> GcpAlloyDbCapabilities {
        GcpAlloyDbCapabilities {
            service_id: SERVICE_ID.to_owned(),
            provider_id: GCP_ALLOYDB_PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: AlloyDbReadOperation::ALL
                .iter()
                .map(|operation| operation.api_operation().to_owned())
                .collect(),
            permissions: AlloyDbReadOperation::ALL
                .iter()
                .map(|operation| format!("GET {}", operation.api_operation()))
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &GcpAlloyDbClusterScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn provider(&self) -> &GcpAlloyDbAdminProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GcpAlloyDbAdminProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &GcpAlloyDbRegistration {
        &self.registration
    }

    pub fn default_request(&self) -> Result<GcpAlloyDbReadRequest, ServiceError> {
        self.ensure_operational_bindings()?;
        Ok(GcpAlloyDbReadRequest::new(
            &self.scope,
            &self.registration,
            self.provider.definition(),
            &self.secret,
        ))
    }

    pub fn read_bounded(&mut self) -> Result<GcpAlloyDbClusterResultProposal, ServiceError> {
        self.propose()
    }

    pub fn propose(&mut self) -> Result<GcpAlloyDbClusterResultProposal, ServiceError> {
        let request = self.default_request()?;
        self.propose_with(request)
    }

    pub fn read_bounded_with(
        &mut self,
        request: GcpAlloyDbReadRequest,
    ) -> Result<GcpAlloyDbClusterResultProposal, ServiceError> {
        self.propose_with(request)
    }

    pub fn propose_with(
        &mut self,
        request: GcpAlloyDbReadRequest,
    ) -> Result<GcpAlloyDbClusterResultProposal, ServiceError> {
        self.validate_request(&request)?;
        let provenance = self.provider.transport().provenance();
        let cluster_request = GetClusterRequest::new(
            &self.scope,
            &self.secret,
            &self.registration.registration_digest,
            API_REVISION,
        )?;
        let mut receipts = Vec::new();
        let cluster_response = match self.provider.get_cluster(&cluster_request) {
            Ok(response) => {
                receipts.push(ProviderRequestReceipt::from_response(
                    AlloyDbReadOperation::GetCluster,
                    cluster_request.digest(),
                    &response.response_digest,
                    response.response_bytes,
                ));
                if let Some(token) = &response.next_page_token {
                    return Ok(self.failure_proposal(
                        &request,
                        EvidenceState::PaginationLoop,
                        FailureEvidence::new(
                            Some(AlloyDbReadOperation::GetCluster),
                            "pagination_loop",
                            None,
                            Some(token.digest().clone()),
                        ),
                        receipts,
                        provenance,
                        None,
                        None,
                    ));
                }
                if response.target != self.scope.target {
                    return Ok(self.failure_proposal(
                        &request,
                        EvidenceState::ScopeDrift,
                        FailureEvidence::new(
                            Some(AlloyDbReadOperation::GetCluster),
                            "scope_drift",
                            None,
                            Some(response.target.digest()),
                        ),
                        receipts,
                        provenance,
                        None,
                        None,
                    ));
                }
                if response.posture.resource_revision != self.scope.resource_revision() {
                    return Ok(self.failure_proposal(
                        &request,
                        EvidenceState::StaleRevision,
                        FailureEvidence::new(
                            Some(AlloyDbReadOperation::GetCluster),
                            "stale_revision",
                            None,
                            Some(response.posture.digest()),
                        ),
                        receipts,
                        provenance,
                        None,
                        None,
                    ));
                }
                response
            }
            Err(error) => {
                receipts.push(ProviderRequestReceipt::failure(
                    AlloyDbReadOperation::GetCluster,
                    cluster_request.digest(),
                ));
                let (state, failure) =
                    map_provider_failure(AlloyDbReadOperation::GetCluster, &error);
                return Ok(self
                    .failure_proposal(&request, state, failure, receipts, provenance, None, None));
            }
        };

        let instance_request = GetInstanceRequest::new(
            &self.scope,
            &self.secret,
            &self.registration.registration_digest,
            API_REVISION,
        )?;
        let instance_response = match self.provider.get_instance(&instance_request) {
            Ok(response) => {
                receipts.push(ProviderRequestReceipt::from_response(
                    AlloyDbReadOperation::GetInstance,
                    instance_request.digest(),
                    &response.response_digest,
                    response.response_bytes,
                ));
                if let Some(token) = &response.next_page_token {
                    return Ok(self.failure_proposal(
                        &request,
                        EvidenceState::PaginationLoop,
                        FailureEvidence::new(
                            Some(AlloyDbReadOperation::GetInstance),
                            "pagination_loop",
                            None,
                            Some(token.digest().clone()),
                        ),
                        receipts,
                        provenance,
                        None,
                        None,
                    ));
                }
                if response.target != self.scope.target {
                    return Ok(self.failure_proposal(
                        &request,
                        EvidenceState::ScopeDrift,
                        FailureEvidence::new(
                            Some(AlloyDbReadOperation::GetInstance),
                            "scope_drift",
                            None,
                            Some(response.target.digest()),
                        ),
                        receipts,
                        provenance,
                        None,
                        None,
                    ));
                }
                if response.posture.resource_revision != self.scope.resource_revision() {
                    return Ok(self.failure_proposal(
                        &request,
                        EvidenceState::StaleRevision,
                        FailureEvidence::new(
                            Some(AlloyDbReadOperation::GetInstance),
                            "stale_revision",
                            None,
                            Some(response.posture.digest()),
                        ),
                        receipts,
                        provenance,
                        None,
                        None,
                    ));
                }
                response
            }
            Err(error) => {
                receipts.push(ProviderRequestReceipt::failure(
                    AlloyDbReadOperation::GetInstance,
                    instance_request.digest(),
                ));
                let (state, failure) =
                    map_provider_failure(AlloyDbReadOperation::GetInstance, &error);
                return Ok(self
                    .failure_proposal(&request, state, failure, receipts, provenance, None, None));
            }
        };

        Ok(GcpAlloyDbClusterResultProposal::new(
            &self.registration,
            &self.scope,
            &request,
            EvidenceState::Ready,
            Some(cluster_response.posture),
            Some(instance_response.posture),
            None,
            PaginationEvidence::complete(),
            receipts,
            provenance,
            Some(cluster_response.response_digest),
            Some(instance_response.response_digest),
        ))
    }

    pub fn record(
        &mut self,
        proposal: &GcpAlloyDbClusterResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GcpAlloyDbRecordReceipt, ServiceError> {
        self.validate_proposal(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::model::MAX_IDENTIFIER_BYTES {
            return Err(ServiceError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ServiceError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let receipt = GcpAlloyDbRecordReceipt::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn verify(
        &self,
        proposal: &GcpAlloyDbClusterResultProposal,
    ) -> GcpAlloyDbVerificationReport {
        match self.validate_proposal(proposal) {
            Ok(()) => GcpAlloyDbVerificationReport {
                valid: true,
                review_eligible: proposal.is_review_eligible(),
                issue: None,
                proposal_digest: proposal.proposal_digest.clone(),
                authority_safe: true,
                provider_receipt: false,
            },
            Err(error) => GcpAlloyDbVerificationReport {
                valid: false,
                review_eligible: false,
                issue: Some(error.to_string()),
                proposal_digest: proposal.proposal_digest.clone(),
                authority_safe: false,
                provider_receipt: false,
            },
        }
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence, ServiceError> {
        self.ensure_registration_integrity()?;
        Ok(self.registration.revoke()?)
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence, ServiceError> {
        self.ensure_registration_integrity()?;
        Ok(self.registration.restore()?)
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence, ServiceError> {
        self.ensure_registration_integrity()?;
        Ok(self.registration.reverse()?)
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret.revoke();
    }

    pub fn consumer(
        &self,
    ) -> Result<crate::consumer::MissionGcpAlloyDbClusterConsumer, crate::consumer::ConsumerError>
    {
        crate::consumer::MissionGcpAlloyDbClusterConsumer::new(
            self.scope.clone(),
            self.registration.clone(),
        )
    }

    fn validate_request(&self, request: &GcpAlloyDbReadRequest) -> Result<(), ServiceError> {
        self.ensure_operational_bindings()?;
        request.validate()?;
        if request.scope_digest != *self.scope.digest()
            || request.registration_digest != self.registration.registration_digest
            || request.provider_digest != self.provider.definition().provider_digest
            || request.api_digest != self.provider.definition().api_digest
            || request.permission_digest != *self.scope.permissions.digest()
            || request.secret_reference_digest != *self.secret.reference_digest()
        {
            return Err(ServiceError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_registration_integrity(&self) -> Result<(), ServiceError> {
        self.registration
            .validate(&self.scope, self.provider.definition(), &self.secret)
            .map_err(|_| ServiceError::RegistrationTampered)
    }

    fn ensure_operational_bindings(&self) -> Result<(), ServiceError> {
        self.scope.validate()?;
        self.secret
            .ensure_active()
            .map_err(|_| ServiceError::SecretRevoked)?;
        if self.secret.scope_digest() != self.scope.digest() {
            return Err(ServiceError::ScopeMismatch);
        }
        self.provider
            .definition()
            .validate()
            .map_err(|_| ServiceError::ProviderDefinitionDrift)?;
        self.ensure_registration_integrity()?;
        if !self.registration.is_active() {
            return Err(ServiceError::RegistrationRevoked);
        }
        Ok(())
    }

    fn validate_proposal(
        &self,
        proposal: &GcpAlloyDbClusterResultProposal,
    ) -> Result<(), ServiceError> {
        self.ensure_operational_bindings()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != *self.scope.digest()
            || proposal.mission != self.scope.mission
            || proposal.target != self.scope.target
            || proposal.evidence.plugin_version_digest != self.registration.version_digest
            || proposal.evidence.contract_digest != self.registration.contract_digest
            || proposal.evidence.provider_digest != self.registration.provider_digest
            || proposal.evidence.api_digest != self.registration.api_digest
            || proposal.evidence.permission_digest != *self.scope.permissions.digest()
            || proposal.evidence.scope_digest != *self.scope.digest()
            || proposal.evidence.evidence_binding_digest != self.registration.evidence_digest
            || proposal.evidence.secret_reference_digest != *self.secret.reference_digest()
        {
            return Err(ServiceError::ScopeMismatch);
        }
        Ok(())
    }

    fn failure_proposal(
        &self,
        request: &GcpAlloyDbReadRequest,
        state: EvidenceState,
        failure: FailureEvidence,
        receipts: Vec<ProviderRequestReceipt>,
        provenance: ProviderProvenance,
        cluster_response_digest: Option<Digest>,
        instance_response_digest: Option<Digest>,
    ) -> GcpAlloyDbClusterResultProposal {
        GcpAlloyDbClusterResultProposal::new(
            &self.registration,
            &self.scope,
            request,
            state,
            None,
            None,
            Some(failure),
            PaginationEvidence {
                cluster_pages: usize::from(
                    receipts
                        .iter()
                        .any(|receipt| receipt.operation == AlloyDbReadOperation::GetCluster),
                ),
                instance_pages: usize::from(
                    receipts
                        .iter()
                        .any(|receipt| receipt.operation == AlloyDbReadOperation::GetInstance),
                ),
                complete: false,
                continuation_token_digests: Vec::new(),
            },
            receipts,
            provenance,
            cluster_response_digest,
            instance_response_digest,
        )
    }
}

fn map_provider_failure(
    operation: AlloyDbReadOperation,
    error: &ProviderError,
) -> (EvidenceState, FailureEvidence) {
    match error {
        ProviderError::Transport(TransportError::AccessDenied { status_code }) => (
            EvidenceState::AccessLoss,
            FailureEvidence::new(Some(operation), "access_loss", *status_code, None),
        ),
        ProviderError::Transport(TransportError::BlockedEnv) => (
            EvidenceState::ProviderUnknown,
            FailureEvidence::new(Some(operation), "blocked_env", None, None),
        ),
        ProviderError::Transport(TransportError::Truncated { response_bytes })
        | ProviderError::ResponseTruncated { response_bytes } => (
            EvidenceState::Truncated,
            FailureEvidence::new(
                Some(operation),
                "truncated",
                None,
                Some(Digest::from_text(&response_bytes.to_string())),
            ),
        ),
        ProviderError::Transport(TransportError::Pagination { token_digest })
        | ProviderError::PaginationLoop { token_digest } => (
            EvidenceState::PaginationLoop,
            FailureEvidence::new(
                Some(operation),
                "pagination_loop",
                None,
                Some(token_digest.clone()),
            ),
        ),
        ProviderError::ResponseTampered => (
            EvidenceState::Tampered,
            FailureEvidence::new(Some(operation), "tampered", None, None),
        ),
        ProviderError::Transport(TransportError::RawBody {
            status_code,
            body_digest,
        }) => (
            EvidenceState::ProviderUnknown,
            FailureEvidence::new(
                Some(operation),
                "raw_body_redacted",
                *status_code,
                Some(body_digest.clone()),
            ),
        ),
        ProviderError::RequestDrift
        | ProviderError::DefinitionDrift
        | ProviderError::ProvenanceDrift => (
            EvidenceState::ScopeDrift,
            FailureEvidence::new(Some(operation), "scope_drift", error.status_code(), None),
        ),
        ProviderError::Transport(TransportError::NotFound { status_code }) => (
            EvidenceState::ProviderUnknown,
            FailureEvidence::new(Some(operation), "provider_unknown", *status_code, None),
        ),
        ProviderError::Transport(transport_error) => (
            EvidenceState::ProviderUnknown,
            FailureEvidence::new(
                Some(operation),
                "provider_unknown",
                transport_error.status_code(),
                None,
            ),
        ),
        ProviderError::Model(_) => (
            EvidenceState::ScopeDrift,
            FailureEvidence::new(Some(operation), "scope_drift", None, None),
        ),
    }
}

// Keep these imports visible in the public module's generated documentation;
// they are also useful aliases for callers that only need the result type.
pub type GcpAlloyDbReadResult = GcpAlloyDbClusterResultProposal;
pub type GcpAlloyDbService<T> = GcpAlloyDbClusterResultService<T>;
