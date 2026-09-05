//! Bounded read, proposal, recording, verification, and reversible
//! registration for AWS RAM resource-share evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::{
    AWS_RAM_API_REVISION, AWS_RAM_CONTRACT_VERSION, AWS_RAM_PLUGIN_VERSION, AWS_RAM_PROVIDER_ID,
    AWS_RAM_PROVIDER_VERSION, AWS_RAM_SCHEMA_VERSION, AWS_RAM_SERVICE_ID, contract_digest,
    model::{
        AssociationState, AwsRamScope, Digest, EvidenceDigests, InvitationProjection,
        InvitationStatus, MAX_ITEMS, MAX_PAGES, MissionBinding, ModelError, PaginationEvidence,
        PermissionProjection, PermissionSnapshot, PrincipalProjection, RamEvidenceState,
        RamFailureCategory, RamOperation, RamPageItems, RamProviderFailure, RamReadPage,
        RamReadRequest, RequestReceipt, ResourceProjection, ResourceShareProjection,
        ResourceShareStatus, Revision, SecretReference, TransportError, TransportProvenance,
    },
    provider::{AwsRamProvider, AwsRamProviderError, AwsRamProviderIdentity, AwsRamTransport},
};

use crate::model::digest_serializable;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-ram-registration-transition/v1",
            &[
                format!("{previous_status:?}"),
                format!("{new_status:?}"),
                registration_digest.as_str().to_owned(),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("AWS RAM registration is invalid")]
    Invalid,
    #[error("AWS RAM registration is already active")]
    AlreadyActive,
    #[error("AWS RAM registration is already revoked or reversed")]
    AlreadyTerminal,
}

/// Version/API/provider/permission/scope/evidence/secret-bound registration.
/// The secret handle and all scoped identifiers are retained only as digests.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsRamRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: String,
    api_revision: String,
    api_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    evidence_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for AwsRamRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRamRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("api_revision", &self.api_revision)
            .field("api_digest", &self.api_digest)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsRamRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("AwsRamRegistration", 16)?;
        object.serialize_field("id", &self.id)?;
        object.serialize_field("pluginVersion", &self.plugin_version)?;
        object.serialize_field("contractVersion", &self.contract_version)?;
        object.serialize_field("contractDigest", &self.contract_digest)?;
        object.serialize_field("providerId", &self.provider_id)?;
        object.serialize_field("providerVersion", &self.provider_version)?;
        object.serialize_field("apiRevision", &self.api_revision)?;
        object.serialize_field("apiDigest", &self.api_digest)?;
        object.serialize_field("providerDigest", &self.provider_digest)?;
        object.serialize_field("permissionDigest", &self.permission_digest)?;
        object.serialize_field("scopeDigest", &self.scope_digest)?;
        object.serialize_field("evidenceDigest", &self.evidence_digest)?;
        object.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        object.serialize_field("registrationRevision", &self.registration_revision)?;
        object.serialize_field("status", &self.status)?;
        object.serialize_field("registrationDigest", &self.registration_digest)?;
        object.end()
    }
}

impl AwsRamRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: &AwsRamScope,
        secret: &SecretReference,
        permission: &PermissionSnapshot,
        provider: &AwsRamProviderIdentity,
        registration_revision: Revision,
    ) -> Result<Self, RegistrationError> {
        let id = id.into();
        if id.is_empty() || id.chars().any(char::is_control) {
            return Err(RegistrationError::Invalid);
        }
        let evidence_digest = Digest::from_parts(
            "aws-ram-evidence-baseline/v1",
            &[
                contract_digest().as_str().to_owned(),
                provider.provider_digest.as_str().to_owned(),
                permission.permission_digest.as_str().to_owned(),
                scope.scope_digest.as_str().to_owned(),
            ],
        );
        let mut registration = Self {
            id,
            plugin_version: AWS_RAM_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_RAM_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            api_revision: provider.api_revision.clone(),
            api_digest: provider.api_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: permission.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            evidence_digest,
            secret_reference_digest: secret.reference_digest(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aws-ram-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration
            .validate()
            .map_err(|_| RegistrationError::Invalid)?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ram-registration/v1",
            &[
                self.id.clone(),
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.api_revision.clone(),
                self.api_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.registration_revision.value().to_string(),
                format!("{:?}", self.status),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), RegistrationError> {
        if self.plugin_version != AWS_RAM_PLUGIN_VERSION
            || self.contract_version != AWS_RAM_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != AWS_RAM_PROVIDER_ID
            || self.provider_version != AWS_RAM_PROVIDER_VERSION
            || self.api_revision != AWS_RAM_API_REVISION
            || self.registration_digest != self.calculate_digest()
        {
            return Err(RegistrationError::Invalid);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(RegistrationError::AlreadyTerminal);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(RegistrationError::AlreadyTerminal);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if matches!(self.status, RegistrationStatus::Active) {
            return Err(RegistrationError::AlreadyActive);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsRamCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub operations: Vec<RamOperation>,
    pub registration_reversible: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractDocumentError {
    #[error("AWS RAM contract is not valid JSON")]
    InvalidJson,
    #[error("AWS RAM contract identity drifted")]
    IdentityDrift,
    #[error("AWS RAM contract escalates Layer-1 authority")]
    AuthorityEscalation,
}

#[derive(Clone, Debug)]
pub struct AwsRamContract {
    value: serde_json::Value,
}

impl AwsRamContract {
    pub fn baseline() -> Result<Self, ContractDocumentError> {
        let value = serde_json::from_str::<serde_json::Value>(crate::AWS_RAM_CONTRACT_JSON)
            .map_err(|_| ContractDocumentError::InvalidJson)?;
        let contract = Self { value };
        contract
            .validate()?
            .then_some(contract)
            .ok_or(ContractDocumentError::IdentityDrift)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<bool, ContractDocumentError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractDocumentError::InvalidJson)?;
        let required = [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "bounds",
            "pagination",
            "evidence",
            "provenance",
            "authorityBoundary",
            "honesty",
            "forbidden",
        ];
        if required.iter().any(|key| !object.contains_key(*key))
            || object
                .get("schemaVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_RAM_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_RAM_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_RAM_PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str)
                != Some(crate::AWS_RAM_PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(ContractDocumentError::IdentityDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::IdentityDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_RAM_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsRamResourceShareService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::AuthorityEscalation);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::IdentityDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(AWS_RAM_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsRamProvider")
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::AuthorityEscalation);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::IdentityDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(crate::AWS_RAM_CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("effectiveAuthorization") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::AuthorityEscalation);
        }
        let honesty = object
            .get("honesty")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::AuthorityEscalation)?;
        for key in [
            "blockedEnvironmentIsNative",
            "fixtureIsNative",
            "recordingIsNative",
            "loopbackIsNative",
            "connected",
            "native",
            "firstParty",
            "independentReadback",
            "durableProviderReceipt",
        ] {
            if honesty.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractDocumentError::AuthorityEscalation);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_account_identifiers_redacted: bool,
    pub raw_arns_redacted: bool,
    pub raw_principals_redacted: bool,
    pub raw_permission_policy_redacted: bool,
    pub raw_tags_redacted: bool,
    pub raw_next_tokens_redacted: bool,
    pub secret_material_redacted: bool,
    pub error_messages_redacted: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            raw_account_identifiers_redacted: true,
            raw_arns_redacted: true,
            raw_principals_redacted: true,
            raw_permission_policy_redacted: true,
            raw_tags_redacted: true,
            raw_next_tokens_redacted: true,
            secret_material_redacted: true,
            error_messages_redacted: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub effective_authorization: bool,
    pub adopts_outcome: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsRamEvidence {
    pub operation: RamOperation,
    pub mission: MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub state: RamEvidenceState,
    pub resource_shares: Vec<ResourceShareProjection>,
    pub resources: Vec<ResourceProjection>,
    pub principals: Vec<PrincipalProjection>,
    pub permissions: Vec<PermissionProjection>,
    pub invitations: Vec<InvitationProjection>,
    pub pagination: PaginationEvidence,
    pub association_revision: Revision,
    pub provider_provenance: TransportProvenance,
    pub failure: Option<RamProviderFailure>,
    pub redaction: RedactionSummary,
    pub authority: AuthorityBoundary,
    pub digests: EvidenceDigests,
}

impl AwsRamEvidence {
    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            self.operation,
            &self.mission,
            &self.project,
            &self.work_product,
            self.state,
            &self.resource_shares,
            &self.resources,
            &self.principals,
            &self.permissions,
            &self.invitations,
            &self.pagination,
            self.association_revision,
            self.provider_provenance,
            &self.failure,
        ))
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.digests.evidence_digest != self.calculate_digest()? {
            return Err(ServiceError::TamperedEvidence);
        }
        if self.authority.connected
            || self.authority.native
            || self.authority.first_party
            || self.authority.provider_receipt
            || self.authority.truth_authority
            || self.authority.effective_authorization
            || self.authority.adopts_outcome
        {
            return Err(ServiceError::AuthorityEscalation);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsRamProposal {
    pub operation: RamOperation,
    pub mission: MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub state: RamEvidenceState,
    pub evidence: AwsRamEvidence,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
    pub request_receipts: Vec<RequestReceipt>,
    pub failure: Option<RamProviderFailure>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub proposal_digest: Digest,
}

impl AwsRamProposal {
    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        Ok(Digest::from_parts(
            "aws-ram-proposal/v1",
            &[
                self.operation.as_str().to_owned(),
                serde_json::to_string(&self.mission).map_err(|_| ModelError::Invalid {
                    field: "proposal mission",
                })?,
                serde_json::to_string(&self.project).map_err(|_| ModelError::Invalid {
                    field: "proposal project",
                })?,
                serde_json::to_string(&self.work_product).map_err(|_| ModelError::Invalid {
                    field: "proposal work product",
                })?,
                state_as_str(self.state).to_owned(),
                self.evidence.evidence_digest().as_str().to_owned(),
                self.version_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
                digest_serializable(&self.request_receipts)?
                    .as_str()
                    .to_owned(),
                serde_json::to_string(&self.failure).map_err(|_| ModelError::Invalid {
                    field: "proposal failure",
                })?,
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
                self.provider_receipt.to_string(),
            ],
        ))
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.proposal_digest != self.calculate_digest()? {
            return Err(ServiceError::TamperedEvidence);
        }
        self.evidence.verify()
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsRamReadResult {
    pub operation: RamOperation,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub state: RamEvidenceState,
    pub complete: bool,
    pub pages_observed: u16,
    pub items_observed: usize,
    pub cursor_digests: Vec<Digest>,
    pub request_receipts: Vec<RequestReceipt>,
    pub failure: Option<RamProviderFailure>,
    pub read_digest: Digest,
    #[serde(skip)]
    pub pages: Vec<RamReadPage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsRamVerification {
    pub valid: bool,
    pub review_eligible: bool,
    pub state: RamEvidenceState,
    pub reason_codes: Vec<String>,
    pub verification_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsRamRecordReceipt {
    pub idempotency_digest: Digest,
    pub evidence_digest: Digest,
    pub state: RamEvidenceState,
    pub recorded: bool,
    pub replayed: bool,
    pub provider_receipt: bool,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("AWS RAM registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("AWS RAM SigV4 SecretReference is revoked or stale")]
    SecretRevoked,
    #[error("AWS RAM scope or request digest does not verify")]
    ScopeMismatch,
    #[error("AWS RAM permission fence does not cover the requested operation")]
    PermissionLoss,
    #[error("AWS RAM association revision is stale")]
    StaleEvidence,
    #[error("AWS RAM pagination loop or bound was rejected")]
    PaginationRejected,
    #[error("AWS RAM evidence is incomplete")]
    IncompleteEvidence,
    #[error("AWS RAM evidence was tampered")]
    TamperedEvidence,
    #[error("Layer-1 authority flags were escalated")]
    AuthorityEscalation,
    #[error("AWS RAM record idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error(transparent)]
    Provider(#[from] AwsRamProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Contract(#[from] ContractDocumentError),
    #[error(transparent)]
    Registration(#[from] RegistrationError),
}

impl From<TransportError> for ServiceError {
    fn from(value: TransportError) -> Self {
        Self::Provider(AwsRamProviderError::Transport(value))
    }
}

pub struct AwsRamResourceShareService<T>
where
    T: AwsRamTransport,
{
    scope: AwsRamScope,
    secret_reference: SecretReference,
    permission: PermissionSnapshot,
    provider: AwsRamProvider<T>,
    registration: AwsRamRegistration,
    recorded: BTreeMap<Digest, AwsRamRecordReceipt>,
}

impl<T> fmt::Debug for AwsRamResourceShareService<T>
where
    T: AwsRamTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRamResourceShareService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("permission", &self.permission)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recorded_count", &self.recorded.len())
            .finish()
    }
}

impl<T> AwsRamResourceShareService<T>
where
    T: AwsRamTransport,
{
    pub fn new(
        scope: AwsRamScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AwsRamProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        permission.validate()?;
        secret_reference
            .validate(&scope)
            .map_err(|_| ServiceError::SecretRevoked)?;
        for operation in RamOperation::ALL {
            if !permission.contains(operation) {
                return Err(ServiceError::PermissionLoss);
            }
        }
        AwsRamContract::baseline()?;
        let registration = AwsRamRegistration::new(
            "aws-ram-registration-1",
            &scope,
            &secret_reference,
            &permission,
            provider.identity(),
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            permission,
            provider,
            registration,
            recorded: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsRamScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    pub fn provider(&self) -> &AwsRamProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsRamProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsRamRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn describe_capabilities(&self) -> AwsRamCapabilities {
        AwsRamCapabilities {
            service_id: AWS_RAM_SERVICE_ID.to_owned(),
            provider_id: AWS_RAM_PROVIDER_ID.to_owned(),
            provider_version: AWS_RAM_PROVIDER_VERSION.to_owned(),
            api_revision: AWS_RAM_API_REVISION.to_owned(),
            operations: RamOperation::ALL.to_vec(),
            registration_reversible: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence, ServiceError> {
        Ok(self.registration.revoke()?)
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence, ServiceError> {
        Ok(self.registration.reverse()?)
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence, ServiceError> {
        Ok(self.registration.restore()?)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, ServiceError> {
        self.revoke_registration()
    }

    pub fn read_bounded(
        &mut self,
        request: RamReadRequest,
    ) -> Result<AwsRamReadResult, ServiceError> {
        self.ensure_request(&request)?;
        let mut current_request = request.clone();
        let mut pages = Vec::new();
        let mut request_receipts = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut state = RamEvidenceState::Absent;
        let mut complete = false;
        let mut failure = None;

        for _ in 0..MAX_PAGES {
            let page = match self.provider.read(&current_request) {
                Ok(page) => page,
                Err(error) => {
                    let transport = match &error {
                        AwsRamProviderError::Transport(value) => value.clone(),
                        AwsRamProviderError::Model(_) => TransportError::MalformedResponse,
                        AwsRamProviderError::PageBinding
                        | AwsRamProviderError::ProviderRevision => TransportError::ProviderUnknown,
                    };
                    let retry = match transport {
                        TransportError::RateLimited {
                            retry_after_seconds,
                        } => crate::model::RetryRateReceipt::new(1, true, retry_after_seconds)?,
                        _ => crate::model::RetryRateReceipt::new(1, false, None)?,
                    };
                    request_receipts.push(RequestReceipt::new(&current_request, 0, retry)?);
                    failure = Some(RamProviderFailure::from_transport(&transport));
                    state = state_for_transport(&transport, !pages.is_empty());
                    break;
                }
            };
            if page.association_revision != self.scope.association_revision {
                failure = Some(RamProviderFailure {
                    category: RamFailureCategory::ProviderUnknown,
                    retry_after_seconds: None,
                    failure_digest: Digest::from_text("aws-ram-stale-association-revision"),
                });
                state = RamEvidenceState::Stale;
                break;
            }
            let receipt =
                RequestReceipt::new(&current_request, page.response_bytes, page.retry.clone())?;
            request_receipts.push(receipt);
            if let Some(next) = &page.next_token {
                let digest = next.token_digest().clone();
                if !seen_cursors.insert(digest.clone()) {
                    state = RamEvidenceState::Tamper;
                    failure = Some(RamProviderFailure {
                        category: RamFailureCategory::ProviderUnknown,
                        retry_after_seconds: None,
                        failure_digest: Digest::from_text("aws-ram-pagination-loop"),
                    });
                    break;
                }
                cursor_digests.push(digest);
            }
            if page.items.is_empty() {
                state = RamEvidenceState::Absent;
            } else {
                state = RamEvidenceState::Present;
            }
            pages.push(page);
            let next = pages.last().and_then(|page| page.next_token.clone());
            match next {
                Some(next) if pages.len() < MAX_PAGES as usize => {
                    current_request = current_request.with_cursor(next)?;
                }
                Some(_) => {
                    state = RamEvidenceState::Partial;
                    break;
                }
                None => {
                    complete = true;
                    break;
                }
            }
        }

        let items_observed = pages.iter().map(|page| page.items.len()).sum::<usize>();
        if items_observed > MAX_ITEMS {
            state = RamEvidenceState::Partial;
            complete = false;
        }
        let read_digest = Digest::from_parts(
            "aws-ram-read-result/v1",
            &[
                request.operation.as_str().to_owned(),
                request.request_digest.as_str().to_owned(),
                state_as_str(state).to_owned(),
                pages.len().to_string(),
                items_observed.to_string(),
                cursor_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                failure.as_ref().map_or_else(String::new, |value| {
                    value.failure_digest.as_str().to_owned()
                }),
            ],
        );
        Ok(AwsRamReadResult {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            state,
            complete,
            pages_observed: pages.len() as u16,
            items_observed,
            cursor_digests,
            request_receipts,
            failure,
            read_digest,
            pages,
        })
    }

    pub fn read(&mut self, request: RamReadRequest) -> Result<AwsRamReadResult, ServiceError> {
        self.read_bounded(request)
    }

    pub fn propose(&mut self, request: RamReadRequest) -> Result<AwsRamProposal, ServiceError> {
        let read = self.read_bounded(request)?;
        let evidence = self.evidence_from_read(&read)?;
        let provider = self.provider.identity();
        let version_digest = Digest::from_parts(
            "aws-ram-version/v1",
            &[
                AWS_RAM_PLUGIN_VERSION.to_owned(),
                AWS_RAM_SCHEMA_VERSION.to_owned(),
                AWS_RAM_CONTRACT_VERSION.to_owned(),
                AWS_RAM_API_REVISION.to_owned(),
            ],
        );
        let mut proposal = AwsRamProposal {
            operation: read.operation,
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            state: evidence.state,
            evidence,
            version_digest,
            contract_digest: contract_digest(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: self.permission.permission_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            secret_reference_digest: self.secret_reference.reference_digest(),
            request_digest: read.request_digest.clone(),
            request_receipts: read.request_receipts.clone(),
            failure: read.failure.clone(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            proposal_digest: Digest::from_text("unsealed-aws-ram-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest()?;
        Ok(proposal)
    }

    pub fn verify(&self, proposal: &AwsRamProposal) -> AwsRamVerification {
        let mut reasons = Vec::new();
        let mut state = proposal.state;
        let mut valid = true;
        if !self.is_active() {
            valid = false;
            state = RamEvidenceState::Revoked;
            reasons.push("registration_revoked".to_owned());
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.permission_digest != self.permission.permission_digest
            || proposal.secret_reference_digest != self.secret_reference.reference_digest()
        {
            valid = false;
            state = RamEvidenceState::Stale;
            reasons.push("binding_drift".to_owned());
        }
        if proposal.validate_integrity().is_err() {
            valid = false;
            state = RamEvidenceState::Tamper;
            reasons.push("digest_mismatch".to_owned());
        }
        if !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt
        {
            // These are explicit Layer-1 invariants; a true flag is handled below.
        } else {
            valid = false;
            state = RamEvidenceState::Tamper;
            reasons.push("authority_escalation".to_owned());
        }
        if matches!(
            state,
            RamEvidenceState::Partial
                | RamEvidenceState::AccessLoss
                | RamEvidenceState::ProviderUnknown
                | RamEvidenceState::Tamper
                | RamEvidenceState::Stale
                | RamEvidenceState::Revoked
        ) {
            reasons.push(state_as_str(state).to_owned());
        }
        let review_eligible = valid && state.can_be_reviewed();
        let verification_digest = Digest::from_parts(
            "aws-ram-verification/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                valid.to_string(),
                review_eligible.to_string(),
                state_as_str(state).to_owned(),
                reasons.join(","),
            ],
        );
        AwsRamVerification {
            valid,
            review_eligible,
            state,
            reason_codes: reasons,
            verification_digest,
        }
    }

    pub fn record(
        &mut self,
        proposal: &AwsRamProposal,
        idempotency_key: &str,
    ) -> Result<AwsRamRecordReceipt, ServiceError> {
        if idempotency_key.is_empty() || idempotency_key.chars().any(char::is_control) {
            return Err(ServiceError::InvalidIdempotencyKey);
        }
        let verification = self.verify(proposal);
        if !verification.valid
            || matches!(
                verification.state,
                RamEvidenceState::Tamper | RamEvidenceState::Revoked
            )
        {
            return Err(if verification.state == RamEvidenceState::Revoked {
                ServiceError::RegistrationRevoked
            } else {
                ServiceError::TamperedEvidence
            });
        }
        let idempotency_digest = Digest::from_text(idempotency_key);
        if let Some(previous) = self.recorded.get(&idempotency_digest) {
            let mut replay = previous.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let record_digest = Digest::from_parts(
            "aws-ram-record/v1",
            &[
                idempotency_digest.as_str().to_owned(),
                proposal.evidence.evidence_digest().as_str().to_owned(),
                state_as_str(proposal.state).to_owned(),
            ],
        );
        let receipt = AwsRamRecordReceipt {
            idempotency_digest: idempotency_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            state: proposal.state,
            recorded: true,
            replayed: false,
            provider_receipt: false,
            record_digest,
        };
        self.recorded.insert(idempotency_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn consumer(&self) -> crate::consumer::MissionAwsRamConsumer {
        let mut consumer = crate::consumer::MissionAwsRamConsumer::with_permission(
            &self.scope,
            self.permission.permission_digest.clone(),
        );
        let _ = consumer.bind_registration(&self.registration);
        consumer
    }

    fn ensure_request(&self, request: &RamReadRequest) -> Result<(), ServiceError> {
        if !self.registration.is_active() {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.secret_reference
            .validate(&self.scope)
            .map_err(|_| ServiceError::SecretRevoked)?;
        request.validate()?;
        if request.scope.scope_digest != self.scope.scope_digest {
            return Err(ServiceError::ScopeMismatch);
        }
        if !self.permission.contains(request.operation) {
            return Err(ServiceError::PermissionLoss);
        }
        Ok(())
    }

    fn evidence_from_read(&self, read: &AwsRamReadResult) -> Result<AwsRamEvidence, ServiceError> {
        let mut resource_shares = Vec::new();
        let mut resources = Vec::new();
        let mut principals = Vec::new();
        let mut permissions = Vec::new();
        let mut invitations = Vec::new();
        let mut invitation_states = Vec::new();
        let mut association_revision = self.scope.association_revision;
        for page in &read.pages {
            association_revision = page.association_revision;
            match &page.items {
                RamPageItems::ResourceShares(items) => {
                    for item in items {
                        if self.scope.resource_share_arns.is_empty()
                            || self.scope.contains_resource_share(&item.resource_share_arn)
                        {
                            resource_shares.push(ResourceShareProjection {
                                resource_share_arn_digest: item.resource_share_arn.digest(),
                                name_digest: item.name.digest(),
                                owning_account_digest: item.owning_account.digest(),
                                status: item.status,
                                allow_external_principals: item.allow_external_principals,
                                feature_set_digest: item
                                    .feature_set
                                    .as_deref()
                                    .map(Digest::from_text),
                                creation_time: item.creation_time,
                                last_updated_time: item.last_updated_time,
                                retain_sharing_on_account_leave_organization: item
                                    .retain_sharing_on_account_leave_organization,
                                association_revision: item.association_revision,
                                state: share_state(item.status),
                            });
                        }
                    }
                }
                RamPageItems::Resources(items) => {
                    for item in items {
                        if self.scope.resource_arns.is_empty()
                            || self.scope.contains_resource(&item.arn)
                        {
                            resources.push(ResourceProjection {
                                resource_arn_digest: item.arn.digest(),
                                resource_share_arn_digest: item.resource_share_arn.digest(),
                                resource_type_digest: item.resource_type.digest(),
                                resource_region_scope: item.resource_region_scope,
                                status: item.status,
                                resource_group_arn_digest: item
                                    .resource_group_arn
                                    .as_ref()
                                    .map(crate::model::ResourceArn::digest),
                                creation_time: item.creation_time,
                                last_updated_time: item.last_updated_time,
                                association_revision: item.association_revision,
                                state: if matches!(
                                    item.status,
                                    crate::model::AssociationStatus::Associated
                                ) {
                                    AssociationState::Present
                                } else {
                                    AssociationState::Absent
                                },
                            });
                        }
                    }
                }
                RamPageItems::Principals(items) => {
                    for item in items {
                        if self.scope.principals.is_empty()
                            || self.scope.contains_principal(&item.id)
                        {
                            principals.push(PrincipalProjection {
                                principal_digest: item.id.digest(),
                                resource_share_arn_digest: item.resource_share_arn.digest(),
                                external: item.external,
                                creation_time: item.creation_time,
                                last_updated_time: item.last_updated_time,
                                association_revision: item.association_revision,
                                state: AssociationState::Present,
                            });
                        }
                    }
                }
                RamPageItems::Permissions(items) => {
                    for item in items {
                        if self.scope.permission_arns.is_empty()
                            || self.scope.contains_permission(&item.permission_arn)
                        {
                            permissions.push(PermissionProjection {
                                permission_arn_digest: item.permission_arn.digest(),
                                version: item.version,
                                default_version: item.default_version,
                                resource_type_digest: item.resource_type.digest(),
                                customer_managed: item.customer_managed,
                                association_revision: item.association_revision,
                                state: AssociationState::Present,
                            });
                        }
                    }
                }
                RamPageItems::Invitations(items) => {
                    for item in items {
                        if self.scope.invitation_arns.is_empty()
                            || self.scope.contains_invitation(&item.invitation_arn)
                        {
                            invitation_states.push(item.status);
                            invitations.push(InvitationProjection {
                                invitation_arn_digest: item.invitation_arn.digest(),
                                resource_share_arn_digest: item.resource_share_arn.digest(),
                                sender_account_digest: item.sender_account.digest(),
                                receiver_account_digest: item.receiver_account.digest(),
                                status: item.status,
                                creation_time: item.creation_time,
                                expiration_time: item.expiration_time,
                                association_revision: item.association_revision,
                                state: invitation_state(item.status),
                            });
                        }
                    }
                }
            }
        }
        let state = aggregate_state(
            read.state,
            read.complete,
            read.operation,
            resource_shares.len()
                + resources.len()
                + principals.len()
                + permissions.len()
                + invitations.len(),
            &invitation_states,
        );
        let pagination = PaginationEvidence {
            pages_observed: read.pages_observed,
            items_observed: read.items_observed,
            complete: read.complete,
            cursor_digests: read.cursor_digests.clone(),
            filter_digest: read.request_receipts.first().map_or_else(
                || Digest::from_text("missing-filter"),
                |value| value.filter_digest.clone(),
            ),
            loop_rejected: matches!(read.state, RamEvidenceState::Tamper),
        };
        let provider = self.provider.identity();
        let mut digests = EvidenceDigests {
            plugin_version_digest: Digest::from_text(AWS_RAM_PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: self.permission.permission_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            request_digest: read.request_digest.clone(),
            cursor_digest: read.cursor_digests.last().cloned(),
            share_digest: crate::model::digest_serializable(&resource_shares)?,
            resource_digest: crate::model::digest_serializable(&resources)?,
            principal_digest: crate::model::digest_serializable(&principals)?,
            permission_metadata_digest: crate::model::digest_serializable(&permissions)?,
            invitation_digest: crate::model::digest_serializable(&invitations)?,
            evidence_digest: Digest::from_text("unsealed-aws-ram-evidence"),
        };
        let mut evidence = AwsRamEvidence {
            operation: read.operation,
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            state,
            resource_shares,
            resources,
            principals,
            permissions,
            invitations,
            pagination,
            association_revision,
            provider_provenance: provider.provenance,
            failure: read.failure.clone(),
            redaction: RedactionSummary::default(),
            authority: AuthorityBoundary::default(),
            digests,
        };
        digests = evidence.digests.clone();
        digests.evidence_digest = evidence.calculate_digest()?;
        evidence.digests = digests;
        Ok(evidence)
    }
}

fn state_for_transport(error: &TransportError, had_pages: bool) -> RamEvidenceState {
    match error {
        TransportError::AccessLoss | TransportError::Unauthorized => RamEvidenceState::AccessLoss,
        TransportError::RateLimited { .. }
        | TransportError::Unavailable
        | TransportError::BlockedEnvironment
        | TransportError::MalformedResponse
        | TransportError::InvalidRequest
        | TransportError::ProviderUnknown => {
            if had_pages {
                RamEvidenceState::Partial
            } else {
                RamEvidenceState::ProviderUnknown
            }
        }
    }
}

fn aggregate_state(
    state: RamEvidenceState,
    complete: bool,
    operation: RamOperation,
    item_count: usize,
    invitations: &[InvitationStatus],
) -> RamEvidenceState {
    if !complete && matches!(state, RamEvidenceState::Present | RamEvidenceState::Absent) {
        return RamEvidenceState::Partial;
    }
    if !matches!(state, RamEvidenceState::Present | RamEvidenceState::Absent) {
        return state;
    }
    if matches!(operation, RamOperation::GetResourceShareInvitations) {
        let mut statuses = invitations.iter().copied().collect::<BTreeSet<_>>();
        return match statuses.len() {
            0 => RamEvidenceState::Absent,
            1 => match statuses.pop_first().unwrap_or(InvitationStatus::Pending) {
                InvitationStatus::Pending => RamEvidenceState::Pending,
                InvitationStatus::Accepted => RamEvidenceState::Accepted,
                InvitationStatus::Declined => RamEvidenceState::Declined,
            },
            _ => RamEvidenceState::Partial,
        };
    }
    if item_count == 0 {
        RamEvidenceState::Absent
    } else {
        RamEvidenceState::Present
    }
}

fn share_state(status: ResourceShareStatus) -> AssociationState {
    match status {
        ResourceShareStatus::Pending => AssociationState::Pending,
        ResourceShareStatus::Active => AssociationState::Present,
        ResourceShareStatus::Failed
        | ResourceShareStatus::Deleting
        | ResourceShareStatus::Deleted => AssociationState::Absent,
    }
}

fn invitation_state(status: InvitationStatus) -> AssociationState {
    match status {
        InvitationStatus::Pending => AssociationState::Pending,
        InvitationStatus::Accepted => AssociationState::Accepted,
        InvitationStatus::Declined => AssociationState::Declined,
    }
}

fn state_as_str(state: RamEvidenceState) -> &'static str {
    match state {
        RamEvidenceState::Present => "present",
        RamEvidenceState::Absent => "absent",
        RamEvidenceState::Pending => "pending",
        RamEvidenceState::Accepted => "accepted",
        RamEvidenceState::Declined => "declined",
        RamEvidenceState::Partial => "partial",
        RamEvidenceState::AccessLoss => "access_loss",
        RamEvidenceState::ProviderUnknown => "provider_unknown",
        RamEvidenceState::Tamper => "tamper",
        RamEvidenceState::Stale => "stale",
        RamEvidenceState::Revoked => "revoked",
    }
}
