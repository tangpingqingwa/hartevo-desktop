//! Typed registration, proposal, record, and verification service.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_KMS_API_REVISION, AWS_KMS_API_VERSION, AWS_KMS_KEY_POSTURE_CONSUMER_ID,
    AWS_KMS_KEY_POSTURE_CONTRACT_VERSION, AWS_KMS_KEY_POSTURE_PLUGIN_VERSION,
    AWS_KMS_KEY_POSTURE_PROVIDER_ID, AWS_KMS_KEY_POSTURE_SCHEMA_VERSION,
    AWS_KMS_KEY_POSTURE_SERVICE_ID, AWS_KMS_PROVIDER_VERSION, contract_digest,
    model::{
        AuthorityBoundary as ModelAuthorityBoundary, AwsKmsReadOperation, AwsKmsScope, CostReceipt,
        Digest, EvidenceStatus, KeyPostureProjection, KmsKeyReference, ModelError, PermissionFence,
        ProviderProvenance, RedactedRequestReceipt, Revision, SecretReference,
    },
    provider::{
        AwsKmsDescribeKeyRecord, AwsKmsListAliasesRecord, AwsKmsListGrantsRecord,
        AwsKmsListKeysRecord, AwsKmsProvider, AwsKmsProviderError, AwsKmsReadRecord,
        AwsKmsTransport, DescribeKeyRequest, GetKeyRotationStatusRequest, KmsReadBounds,
        ListAliasesRequest, ListGrantsRequest, ListKeysRequest,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("AWS KMS service contract drifted")]
    ContractDrift,
    #[error("AWS KMS service registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("AWS KMS SigV4 SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS KMS scope or permission digest does not verify")]
    ScopeMismatch,
    #[error("AWS KMS permission was lost or changed")]
    PermissionLoss,
    #[error("AWS KMS key is outside the exact scope")]
    KeyScopeDrift,
    #[error("AWS KMS key posture is disabled, pending deletion, unknown, or unsafe")]
    UnsafeKeyState,
    #[error("AWS KMS evidence is partial or eventually consistent")]
    PartialEvidence,
    #[error("AWS KMS request or proposal was replayed")]
    Replay,
    #[error("AWS KMS request or proposal digest drifted")]
    RequestDrift,
    #[error("AWS KMS evidence or record was tampered")]
    TamperedEvidence,
    #[error("AWS KMS record is incomplete")]
    IncompleteRecord,
    #[error("AWS KMS provider error: {0}")]
    Provider(AwsKmsProviderError),
    #[error("AWS KMS model error: {0}")]
    Model(ModelError),
}

impl From<ModelError> for ServiceError {
    fn from(value: ModelError) -> Self {
        match value {
            ModelError::ScopeMismatch | ModelError::PermissionMismatch => Self::ScopeMismatch,
            ModelError::KeyOutOfScope => Self::KeyScopeDrift,
            ModelError::UnsafeKeyState => Self::UnsafeKeyState,
            ModelError::EventualConsistency | ModelError::PartialEvidence => Self::PartialEvidence,
            ModelError::Revoked => Self::SecretRevoked,
            other => Self::Model(other),
        }
    }
}

impl From<AwsKmsProviderError> for ServiceError {
    fn from(value: AwsKmsProviderError) -> Self {
        match value {
            AwsKmsProviderError::Transport(error) => match error.failure {
                crate::provider::TransportFailure::Unauthorized
                | crate::provider::TransportFailure::AccessDenied
                | crate::provider::TransportFailure::NotFound => Self::PermissionLoss,
                crate::provider::TransportFailure::EventualConsistency => Self::PartialEvidence,
                crate::provider::TransportFailure::BadRequest
                | crate::provider::TransportFailure::Throttled
                | crate::provider::TransportFailure::Server
                | crate::provider::TransportFailure::Timeout
                | crate::provider::TransportFailure::BlockedEnv
                | crate::provider::TransportFailure::Malformed => {
                    Self::Provider(AwsKmsProviderError::Transport(error))
                }
            },
            AwsKmsProviderError::ScopeDrift => Self::ScopeMismatch,
            AwsKmsProviderError::PermissionLoss => Self::PermissionLoss,
            AwsKmsProviderError::KeyDrift => Self::KeyScopeDrift,
            AwsKmsProviderError::MarkerLoop | AwsKmsProviderError::PaginationIncomplete => {
                Self::PartialEvidence
            }
            AwsKmsProviderError::Partial => Self::PartialEvidence,
            AwsKmsProviderError::RecordTampered => Self::TamperedEvidence,
            other => Self::Provider(other),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub api_operations: [&'static str; 5],
    pub service_operations: [&'static str; 9],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub cryptographic_operations: bool,
    pub key_policy_export: bool,
    pub key_mutation: bool,
    pub outcome_authority: bool,
}

impl AwsKmsCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: AWS_KMS_KEY_POSTURE_SERVICE_ID,
            provider_id: AWS_KMS_KEY_POSTURE_PROVIDER_ID,
            consumer_id: AWS_KMS_KEY_POSTURE_CONSUMER_ID,
            api_operations: [
                "ListKeys",
                "DescribeKey",
                "GetKeyRotationStatus",
                "ListAliases",
                "ListGrants",
            ],
            service_operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "reverse_registration",
                "propose",
                "record",
                "verify",
                "read_key_posture",
                "consume_mission_proposal",
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            cryptographic_operations: false,
            key_policy_export: false,
            key_mutation: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsKmsKeyPostureRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub key_scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
struct RegistrationDigestMaterial<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a str,
    provider_revision: &'a str,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    key_scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    reversible: bool,
    revocable: bool,
    state: RegistrationState,
}

impl AwsKmsKeyPostureRegistration {
    fn new(
        scope: &AwsKmsScope,
        permission: &PermissionFence,
        secret: &SecretReference,
        provider: &crate::provider::AwsKmsProviderDefinition,
    ) -> Result<Self, ServiceError> {
        let evidence_digest = Digest::from_parts(
            "aws-kms-key-posture-evidence-policy/v1",
            &[
                ("version", AWS_KMS_KEY_POSTURE_PLUGIN_VERSION.to_owned()),
                ("max_pages", KmsReadBounds::default().max_pages.to_string()),
                ("max_keys", KmsReadBounds::default().max_keys.to_string()),
                (
                    "max_aliases",
                    KmsReadBounds::default().max_aliases.to_string(),
                ),
                (
                    "max_grants",
                    KmsReadBounds::default().max_grants.to_string(),
                ),
                ("raw_key_material", "false".to_owned()),
                ("raw_policy_json", "false".to_owned()),
                ("grant_principals", "false".to_owned()),
                ("cryptographic_outputs", "false".to_owned()),
            ],
        );
        let mut registration = Self {
            plugin_version: AWS_KMS_KEY_POSTURE_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_KMS_KEY_POSTURE_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            key_scope_digest: Digest::from_parts(
                "aws-kms-key-scope-registration/v1",
                &[("scope", scope.scope_digest.as_str().to_owned())],
            ),
            evidence_digest,
            secret_reference_digest: secret.digest(),
            registration_revision: Revision::new(1)?,
            reversible: true,
            revocable: true,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&RegistrationDigestMaterial {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            key_scope_digest: &self.key_scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsKmsScope,
        permission: &PermissionFence,
        secret: &SecretReference,
        provider: &crate::provider::AwsKmsProviderDefinition,
    ) -> Result<(), ServiceError> {
        if self.plugin_version != AWS_KMS_KEY_POSTURE_PLUGIN_VERSION
            || self.contract_version != AWS_KMS_KEY_POSTURE_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != permission.permission_digest
            || self.scope_digest != scope.scope_digest
            || self.key_scope_digest
                != Digest::from_parts(
                    "aws-kms-key-scope-registration/v1",
                    &[("scope", scope.scope_digest.as_str().to_owned())],
                )
            || self.secret_reference_digest != secret.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.recomputed_digest()
        {
            Err(ServiceError::RequestDrift)
        } else {
            Ok(())
        }
    }

    fn transition(&mut self, state: RegistrationState) -> Result<(), ServiceError> {
        if self.state == RegistrationState::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        if self.state == RegistrationState::Reversed {
            return Err(ServiceError::RegistrationRevoked);
        }
        let revision = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(ServiceError::RequestDrift)?;
        self.registration_revision = Revision::new(revision)?;
        self.state = state;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsKmsReadRequest {
    ListKeys(ListKeysRequest),
    DescribeKey(DescribeKeyRequest),
    GetKeyRotationStatus(GetKeyRotationStatusRequest),
    ListAliases(ListAliasesRequest),
    ListGrants(ListGrantsRequest),
    KeyPosture(KmsKeyReference),
}

impl AwsKmsReadRequest {
    pub fn operation(&self) -> AwsKmsReadOperation {
        match self {
            Self::ListKeys(_) => AwsKmsReadOperation::ListKeys,
            Self::DescribeKey(_) => AwsKmsReadOperation::DescribeKey,
            Self::GetKeyRotationStatus(_) => AwsKmsReadOperation::GetKeyRotationStatus,
            Self::ListAliases(_) => AwsKmsReadOperation::ListAliases,
            Self::ListGrants(_) => AwsKmsReadOperation::ListGrants,
            Self::KeyPosture(_) => AwsKmsReadOperation::KeyPosture,
        }
    }

    pub fn request_digest(&self) -> Digest {
        match self {
            Self::ListKeys(request) => request.request_digest(),
            Self::DescribeKey(request) => request.request_digest(),
            Self::GetKeyRotationStatus(request) => request.request_digest(),
            Self::ListAliases(request) => request.request_digest(),
            Self::ListGrants(request) => request.request_digest(),
            Self::KeyPosture(key) => Digest::from_parts(
                "aws-kms-key-posture-request/v1",
                &[("key", key.digest().as_str().to_owned())],
            ),
        }
    }

    fn scope_digest(&self) -> &Digest {
        match self {
            Self::ListKeys(request) => &request.scope_digest,
            Self::DescribeKey(request) => &request.scope_digest,
            Self::GetKeyRotationStatus(request) => &request.scope_digest,
            Self::ListAliases(request) => &request.scope_digest,
            Self::ListGrants(request) => &request.scope_digest,
            Self::KeyPosture(_) => panic!("key posture request scope is checked by the service"),
        }
    }

    fn permission_digest(&self) -> Option<&Digest> {
        match self {
            Self::ListKeys(request) => Some(&request.permission_digest),
            Self::DescribeKey(request) => Some(&request.permission_digest),
            Self::GetKeyRotationStatus(request) => Some(&request.permission_digest),
            Self::ListAliases(request) => Some(&request.permission_digest),
            Self::ListGrants(request) => Some(&request.permission_digest),
            Self::KeyPosture(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsKeyPostureProposal {
    pub operation: AwsKmsReadOperation,
    pub request: AwsKmsReadRequest,
    pub mission: crate::model::MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub key_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub proposal_digest: Digest,
}

impl AwsKmsKeyPostureProposal {
    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            self.operation,
            &self.request.request_digest(),
            &self.mission,
            &self.project,
            &self.work_product,
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.key_digest,
            &self.registration_digest,
            self.registration_revision,
        ))
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.operation != self.request.operation()
            || self.proposal_digest != self.compute_digest()
        {
            Err(ServiceError::RequestDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub key_material_retained: bool,
    pub plaintext_retained: bool,
    pub raw_key_policy_json_retained: bool,
    pub grant_principals_retained: bool,
    pub raw_tokens_retained: bool,
    pub cryptographic_outputs_retained: bool,
    pub raw_provider_payload_retained: bool,
}

pub type AuthorityBoundary = ModelAuthorityBoundary;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsKeyPostureEvidence {
    pub status: EvidenceStatus,
    pub mission: crate::model::MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub key: KeyPostureProjection,
    pub pagination: Vec<crate::model::PaginationSummary>,
    pub redaction: RedactionSummary,
    pub receipts: Vec<RedactedRequestReceipt>,
    pub cost: CostReceipt,
    pub authority: AuthorityBoundary,
    pub provenance: ProviderProvenance,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub digests: crate::service::EvidenceDigests,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    status: EvidenceStatus,
    mission: &'a crate::model::MissionBinding,
    project: &'a crate::model::ProjectBinding,
    work_product: &'a crate::model::WorkProductBinding,
    key: &'a KeyPostureProjection,
    pagination: &'a [crate::model::PaginationSummary],
    redaction: &'a RedactionSummary,
    receipts: &'a [RedactedRequestReceipt],
    cost: &'a CostReceipt,
    authority: &'a AuthorityBoundary,
    provenance: ProviderProvenance,
    proposal_digest: &'a Digest,
    registration_digest: &'a Digest,
    version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    key_digest: &'a Digest,
}

impl AwsKmsKeyPostureEvidence {
    fn compute_evidence_digest(&self) -> Digest {
        digest_serializable(&EvidenceDigestMaterial {
            status: self.status,
            mission: &self.mission,
            project: &self.project,
            work_product: &self.work_product,
            key: &self.key,
            pagination: &self.pagination,
            redaction: &self.redaction,
            receipts: &self.receipts,
            cost: &self.cost,
            authority: &self.authority,
            provenance: self.provenance.clone(),
            proposal_digest: &self.proposal_digest,
            registration_digest: &self.registration_digest,
            version_digest: &self.digests.plugin_version_digest,
            contract_digest: &self.digests.contract_digest,
            provider_digest: &self.digests.provider_digest,
            api_digest: &self.digests.api_digest,
            permission_digest: &self.digests.permission_digest,
            scope_digest: &self.digests.scope_digest,
            key_digest: &self.digests.key_digest,
        })
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.status != EvidenceStatus::Complete
            || !self.redaction_is_safe()
            || self.authority.connected
            || self.authority.native
            || self.authority.first_party
            || self.authority.cryptographic_verification_authority
            || self.authority.key_mutation_authority
            || self.authority.policy_authority
            || self.authority.outcome_authority
            || self.authority.durable_receipt
            || self.digests.evidence_digest != self.compute_evidence_digest()
        {
            Err(ServiceError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn redaction_is_safe(&self) -> bool {
        !self.redaction.key_material_retained
            && !self.redaction.plaintext_retained
            && !self.redaction.raw_key_policy_json_retained
            && !self.redaction.grant_principals_retained
            && !self.redaction.raw_tokens_retained
            && !self.redaction.cryptographic_outputs_retained
            && !self.redaction.raw_provider_payload_retained
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsKeyPostureRecord {
    pub list_keys: AwsKmsListKeysRecord,
    pub describe_key: AwsKmsDescribeKeyRecord,
    pub rotation: crate::provider::AwsKmsRotationRecord,
    pub aliases: AwsKmsListAliasesRecord,
    pub grants: AwsKmsListGrantsRecord,
    pub request_digest: Digest,
    pub key_digest: Digest,
    pub provider_digest: Digest,
    pub record_digest: Digest,
}

impl AwsKmsKeyPostureRecord {
    fn new(
        list_keys: AwsKmsListKeysRecord,
        describe_key: AwsKmsDescribeKeyRecord,
        rotation: crate::provider::AwsKmsRotationRecord,
        aliases: AwsKmsListAliasesRecord,
        grants: AwsKmsListGrantsRecord,
        request_digest: Digest,
        key_digest: Digest,
        provider_digest: Digest,
    ) -> Self {
        let record_digest = digest_serializable(&(
            &list_keys.record_digest,
            &describe_key.record_digest,
            &rotation.record_digest,
            &aliases.record_digest,
            &grants.record_digest,
            &request_digest,
            &key_digest,
            &provider_digest,
        ));
        Self {
            list_keys,
            describe_key,
            rotation,
            aliases,
            grants,
            request_digest,
            key_digest,
            provider_digest,
            record_digest,
        }
    }

    fn verify(&self) -> Result<(), ServiceError> {
        self.list_keys.verify()?;
        self.describe_key.verify()?;
        self.rotation.verify()?;
        self.aliases.verify()?;
        self.grants.verify()?;
        if self.record_digest
            != digest_serializable(&(
                &self.list_keys.record_digest,
                &self.describe_key.record_digest,
                &self.rotation.record_digest,
                &self.aliases.record_digest,
                &self.grants.record_digest,
                &self.request_digest,
                &self.key_digest,
                &self.provider_digest,
            ))
        {
            return Err(ServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn receipts(&self) -> Vec<RedactedRequestReceipt> {
        self.list_keys
            .receipts
            .iter()
            .chain(std::iter::once(&self.describe_key.receipt))
            .chain(std::iter::once(&self.rotation.receipt))
            .chain(self.aliases.receipts.iter())
            .chain(self.grants.receipts.iter())
            .cloned()
            .collect()
    }

    fn cost(&self) -> CostReceipt {
        let receipts = self.receipts();
        CostReceipt::new(
            receipts.len() as u32,
            receipts.iter().map(|receipt| receipt.response_bytes).sum(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsKmsReadRecordEnvelope {
    Single(Box<AwsKmsReadRecord>),
    KeyPosture(Box<AwsKmsKeyPostureRecord>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsKeyPostureReadResult {
    pub proposal: AwsKmsKeyPostureProposal,
    pub record: AwsKmsKeyPostureRecord,
    pub evidence: AwsKmsKeyPostureEvidence,
}

pub struct AwsKmsKeyPostureService<T = crate::provider::BlockedEnvAwsKmsTransport> {
    scope: AwsKmsScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsKmsProvider<T>,
    registration: AwsKmsKeyPostureRegistration,
    version_digest: Digest,
    used_proposals: BTreeSet<Digest>,
}

impl<T: AwsKmsTransport> fmt::Debug for AwsKmsKeyPostureService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsKmsKeyPostureService")
            .field("scope_digest", &self.scope.scope_digest)
            .field("permission_digest", &self.permission.permission_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provider", self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: AwsKmsTransport> AwsKmsKeyPostureService<T> {
    pub fn new(
        scope: AwsKmsScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsKmsProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.verify()?;
        permission.verify()?;
        secret_reference.ensure_active()?;
        if secret_reference.scope_digest() != &scope.scope_digest
            || permission.permission_digest != scope.permission_digest
        {
            return Err(ServiceError::ScopeMismatch);
        }
        provider.validate()?;
        let version_digest = Digest::from_parts(
            "aws-kms-key-posture-version/v1",
            &[
                ("schema", AWS_KMS_KEY_POSTURE_SCHEMA_VERSION.to_owned()),
                ("contract", AWS_KMS_KEY_POSTURE_CONTRACT_VERSION.to_owned()),
                ("api", AWS_KMS_API_VERSION.to_owned()),
                ("api_revision", AWS_KMS_API_REVISION.to_owned()),
                ("provider", AWS_KMS_PROVIDER_VERSION.to_owned()),
            ],
        );
        let registration = AwsKmsKeyPostureRegistration::new(
            &scope,
            &permission,
            &secret_reference,
            provider.definition(),
        )?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
            version_digest,
            used_proposals: BTreeSet::new(),
        })
    }

    pub fn capabilities(&self) -> AwsKmsCapabilities {
        AwsKmsCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsKmsScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsKmsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsKmsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsKmsKeyPostureRegistration {
        &self.registration
    }

    pub fn service_id(&self) -> &'static str {
        AWS_KMS_KEY_POSTURE_SERVICE_ID
    }

    pub fn revoke_registration(&mut self) -> Result<(), ServiceError> {
        self.ensure_fences()?;
        self.registration.transition(RegistrationState::Revoked)
    }

    pub fn reverse_registration(&mut self) -> Result<(), ServiceError> {
        self.ensure_fences()?;
        self.registration.transition(RegistrationState::Reversed)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.revoke().map_err(ServiceError::from)
    }

    pub fn propose_list_keys(&self) -> Result<AwsKmsKeyPostureProposal, ServiceError> {
        let request = ListKeysRequest::new(&self.scope, self.provider.bounds())?;
        self.propose(AwsKmsReadRequest::ListKeys(request))
    }

    pub fn propose_key_posture(
        &self,
        key: KmsKeyReference,
    ) -> Result<AwsKmsKeyPostureProposal, ServiceError> {
        if !self.scope.contains_key(&key) {
            return Err(ServiceError::KeyScopeDrift);
        }
        self.propose(AwsKmsReadRequest::KeyPosture(key))
    }

    pub fn propose_describe_key(
        &self,
        key: KmsKeyReference,
    ) -> Result<AwsKmsKeyPostureProposal, ServiceError> {
        self.propose(AwsKmsReadRequest::DescribeKey(DescribeKeyRequest::new(
            &self.scope,
            key,
        )))
    }

    pub fn propose_get_key_rotation_status(
        &self,
        key: KmsKeyReference,
    ) -> Result<AwsKmsKeyPostureProposal, ServiceError> {
        self.propose(AwsKmsReadRequest::GetKeyRotationStatus(
            GetKeyRotationStatusRequest::new(&self.scope, key),
        ))
    }

    pub fn propose_list_aliases(
        &self,
        key: KmsKeyReference,
    ) -> Result<AwsKmsKeyPostureProposal, ServiceError> {
        let request = ListAliasesRequest::new(&self.scope, key, self.provider.bounds())?;
        self.propose(AwsKmsReadRequest::ListAliases(request))
    }

    pub fn propose_list_grants(
        &self,
        key: KmsKeyReference,
    ) -> Result<AwsKmsKeyPostureProposal, ServiceError> {
        let request = ListGrantsRequest::new(&self.scope, key, self.provider.bounds())?;
        self.propose(AwsKmsReadRequest::ListGrants(request))
    }

    pub fn propose(
        &self,
        request: AwsKmsReadRequest,
    ) -> Result<AwsKmsKeyPostureProposal, ServiceError> {
        self.ensure_fences()?;
        let operation = request.operation();
        if operation == AwsKmsReadOperation::KeyPosture {
            for api_operation in AwsKmsReadOperation::API {
                if !self.permission.permits(api_operation) {
                    return Err(ServiceError::PermissionLoss);
                }
            }
        } else if !self.permission.permits(operation) {
            return Err(ServiceError::PermissionLoss);
        }
        if operation != AwsKmsReadOperation::ListKeys {
            let key = match &request {
                AwsKmsReadRequest::DescribeKey(request) => &request.key,
                AwsKmsReadRequest::GetKeyRotationStatus(request) => &request.key,
                AwsKmsReadRequest::ListAliases(request) => &request.key,
                AwsKmsReadRequest::ListGrants(request) => &request.key,
                AwsKmsReadRequest::KeyPosture(key) => key,
                AwsKmsReadRequest::ListKeys(_) => unreachable!(),
            };
            if !self.scope.contains_key(key) {
                return Err(ServiceError::KeyScopeDrift);
            }
        }
        if operation.is_api()
            && (request.scope_digest() != &self.scope.scope_digest
                || request.permission_digest() != Some(&self.permission.permission_digest))
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let key_digest = match &request {
            AwsKmsReadRequest::ListKeys(_) => Digest::zero(),
            AwsKmsReadRequest::DescribeKey(request) => request.key.digest(),
            AwsKmsReadRequest::GetKeyRotationStatus(request) => request.key.digest(),
            AwsKmsReadRequest::ListAliases(request) => request.key.digest(),
            AwsKmsReadRequest::ListGrants(request) => request.key.digest(),
            AwsKmsReadRequest::KeyPosture(key) => key.digest(),
        };
        let mut proposal = AwsKmsKeyPostureProposal {
            operation,
            request,
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            version_digest: self.version_digest.clone(),
            contract_digest: contract_digest(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: self.provider.definition().api_digest.clone(),
            permission_digest: self.permission.permission_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            key_digest,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsKmsKeyPostureProposal,
    ) -> Result<AwsKmsReadRecordEnvelope, ServiceError> {
        self.ensure_proposal_fences(proposal)?;
        if self.used_proposals.contains(&proposal.proposal_digest) {
            return Err(ServiceError::Replay);
        }
        let result = match proposal.request.clone() {
            AwsKmsReadRequest::ListKeys(request) => Ok(AwsKmsReadRecordEnvelope::Single(Box::new(
                AwsKmsReadRecord::ListKeys(self.provider.list_keys(request)?),
            ))),
            AwsKmsReadRequest::DescribeKey(request) => {
                Ok(AwsKmsReadRecordEnvelope::Single(Box::new(
                    AwsKmsReadRecord::DescribeKey(self.provider.describe_key(request)?),
                )))
            }
            AwsKmsReadRequest::GetKeyRotationStatus(request) => Ok(
                AwsKmsReadRecordEnvelope::Single(Box::new(AwsKmsReadRecord::GetKeyRotationStatus(
                    self.provider.get_key_rotation_status(request)?,
                ))),
            ),
            AwsKmsReadRequest::ListAliases(request) => {
                Ok(AwsKmsReadRecordEnvelope::Single(Box::new(
                    AwsKmsReadRecord::ListAliases(self.provider.list_aliases(request)?),
                )))
            }
            AwsKmsReadRequest::ListGrants(request) => {
                Ok(AwsKmsReadRecordEnvelope::Single(Box::new(
                    AwsKmsReadRecord::ListGrants(self.provider.list_grants(request)?),
                )))
            }
            AwsKmsReadRequest::KeyPosture(key) => {
                let list_keys_request = ListKeysRequest::new(&self.scope, self.provider.bounds())?;
                let describe_request = DescribeKeyRequest::new(&self.scope, key.clone());
                let rotation_request = GetKeyRotationStatusRequest::new(&self.scope, key.clone());
                let aliases_request =
                    ListAliasesRequest::new(&self.scope, key.clone(), self.provider.bounds())?;
                let grants_request =
                    ListGrantsRequest::new(&self.scope, key.clone(), self.provider.bounds())?;
                let list_keys = self.provider.list_keys(list_keys_request)?;
                let describe_key = self.provider.describe_key(describe_request)?;
                let rotation = self.provider.get_key_rotation_status(rotation_request)?;
                let aliases = self.provider.list_aliases(aliases_request)?;
                let grants = self.provider.list_grants(grants_request)?;
                Ok(AwsKmsReadRecordEnvelope::KeyPosture(Box::new(
                    AwsKmsKeyPostureRecord::new(
                        list_keys,
                        describe_key,
                        rotation,
                        aliases,
                        grants,
                        proposal.request.request_digest(),
                        key.digest(),
                        self.provider.definition().provider_digest.clone(),
                    ),
                )))
            }
        };
        if result.is_ok() {
            self.used_proposals.insert(proposal.proposal_digest.clone());
        }
        result
    }

    pub fn verify_key_posture(
        &self,
        proposal: &AwsKmsKeyPostureProposal,
        envelope: &AwsKmsReadRecordEnvelope,
    ) -> Result<AwsKmsKeyPostureEvidence, ServiceError> {
        self.ensure_proposal_fences(proposal)?;
        proposal.verify()?;
        let record = match envelope {
            AwsKmsReadRecordEnvelope::KeyPosture(record) => record,
            AwsKmsReadRecordEnvelope::Single(_) => return Err(ServiceError::RequestDrift),
        };
        record.verify()?;
        if proposal.operation != AwsKmsReadOperation::KeyPosture
            || record.request_digest != proposal.request.request_digest()
            || record.key_digest != proposal.key_digest
            || record.provider_digest != self.provider.definition().provider_digest
        {
            return Err(ServiceError::RequestDrift);
        }
        let key = match &proposal.request {
            AwsKmsReadRequest::KeyPosture(key) => key,
            _ => return Err(ServiceError::RequestDrift),
        };
        if !record.list_keys.key_items().any(|summary| {
            summary.key_id_digest == key.key_id_digest()
                && key
                    .key_arn_digest()
                    .is_none_or(|arn| summary.key_arn_digest.as_ref() == Some(&arn))
        }) {
            return Err(ServiceError::KeyScopeDrift);
        }
        if record.describe_key.key_digest != key.digest()
            || record.rotation.key_digest != key.digest()
            || record
                .aliases
                .pages
                .iter()
                .any(|page| page.key_digest != key.digest())
            || record
                .grants
                .pages
                .iter()
                .any(|page| page.key_digest != key.digest())
        {
            return Err(ServiceError::KeyScopeDrift);
        }
        record.describe_key.metadata.validate_posture()?;
        record.rotation.status.validate()?;
        let metadata = &record.describe_key.metadata;
        let alias_items = record.aliases.alias_items().cloned().collect::<Vec<_>>();
        let grant_items = record.grants.grant_items().cloned().collect::<Vec<_>>();
        let alias_digest = Digest::from_parts(
            "aws-kms-alias-set/v1",
            &[
                ("count", alias_items.len().to_string()),
                (
                    "items",
                    alias_items
                        .iter()
                        .map(KmsAliasDigest::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        let grant_digest = Digest::from_parts(
            "aws-kms-grant-set/v1",
            &[
                ("count", grant_items.len().to_string()),
                (
                    "items",
                    grant_items
                        .iter()
                        .map(KmsGrantDigest::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        let key_projection = KeyPostureProjection {
            key_id_digest: metadata.key_id_digest.clone(),
            key_arn_digest: metadata.key_arn_digest.clone(),
            state: metadata.state,
            spec: metadata.spec,
            usage: metadata.usage,
            origin: metadata.origin,
            multi_region: metadata.multi_region,
            alias_count: alias_items.len(),
            alias_digest,
            grant_count: grant_items.len(),
            grant_digest,
            rotation_enabled: record.rotation.status.enabled,
            rotation_period_days: record.rotation.status.period_days,
            rotation_next_date: record.rotation.status.next_rotation_date,
        };
        let pagination = vec![
            crate::model::PaginationSummary {
                pages_observed: record.list_keys.pages.len() as u16,
                items_observed: record.list_keys.item_count,
                complete: record.list_keys.complete,
                marker_digests: record.list_keys.marker_digests(),
            },
            crate::model::PaginationSummary {
                pages_observed: record.aliases.pages.len() as u16,
                items_observed: record.aliases.item_count,
                complete: record.aliases.complete,
                marker_digests: record.aliases.marker_digests(),
            },
            crate::model::PaginationSummary {
                pages_observed: record.grants.pages.len() as u16,
                items_observed: record.grants.item_count,
                complete: record.grants.complete,
                marker_digests: record.grants.marker_digests(),
            },
        ];
        if pagination.iter().any(|page| !page.complete) {
            return Err(ServiceError::IncompleteRecord);
        }
        let receipts = record.receipts();
        let cost = record.cost();
        let redaction = RedactionSummary::default();
        let authority = AuthorityBoundary::default();
        let mut evidence = AwsKmsKeyPostureEvidence {
            status: EvidenceStatus::Complete,
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            key: key_projection,
            pagination,
            redaction,
            receipts,
            cost,
            authority,
            provenance: self.provider.provenance(),
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(AWS_KMS_KEY_POSTURE_PLUGIN_VERSION),
                contract_digest: contract_digest(),
                provider_digest: self.provider.definition().provider_digest.clone(),
                api_digest: self.provider.definition().api_digest.clone(),
                permission_digest: self.permission.permission_digest.clone(),
                scope_digest: self.scope.scope_digest.clone(),
                key_digest: proposal.key_digest.clone(),
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: Digest::zero(),
            },
        };
        evidence.digests.evidence_digest = evidence.compute_evidence_digest();
        evidence.verify()?;
        Ok(evidence)
    }

    pub fn read_key_posture(
        &mut self,
        key: KmsKeyReference,
    ) -> Result<AwsKmsKeyPostureReadResult, ServiceError> {
        let proposal = self.propose_key_posture(key)?;
        let envelope = self.record(&proposal)?;
        let record = match envelope {
            AwsKmsReadRecordEnvelope::KeyPosture(record) => *record,
            AwsKmsReadRecordEnvelope::Single(_) => return Err(ServiceError::RequestDrift),
        };
        let evidence = self.verify_key_posture(
            &proposal,
            &AwsKmsReadRecordEnvelope::KeyPosture(Box::new(record.clone())),
        )?;
        Ok(AwsKmsKeyPostureReadResult {
            proposal,
            record,
            evidence,
        })
    }

    pub fn read(
        &mut self,
        key: KmsKeyReference,
    ) -> Result<AwsKmsKeyPostureReadResult, ServiceError> {
        self.read_key_posture(key)
    }

    pub fn verify(
        &self,
        proposal: &AwsKmsKeyPostureProposal,
        envelope: &AwsKmsReadRecordEnvelope,
    ) -> Result<AwsKmsKeyPostureEvidence, ServiceError> {
        self.verify_key_posture(proposal, envelope)
    }

    fn ensure_fences(&self) -> Result<(), ServiceError> {
        self.scope.verify()?;
        self.permission.verify()?;
        self.provider.validate()?;
        self.registration.validate(
            &self.scope,
            &self.permission,
            &self.secret_reference,
            self.provider.definition(),
        )?;
        if !self.registration.is_active() {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.secret_reference.ensure_active()?;
        if self.secret_reference.scope_digest() != &self.scope.scope_digest {
            return Err(ServiceError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_proposal_fences(
        &self,
        proposal: &AwsKmsKeyPostureProposal,
    ) -> Result<(), ServiceError> {
        self.ensure_fences()?;
        proposal.verify()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.permission_digest != self.permission.permission_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.provider_digest != self.provider.definition().provider_digest
            || proposal.api_digest != self.provider.definition().api_digest
            || proposal.contract_digest != contract_digest()
        {
            return Err(ServiceError::RequestDrift);
        }
        Ok(())
    }
}

trait KmsAliasDigest {
    fn digest(&self) -> Digest;
}

impl KmsAliasDigest for crate::model::KmsAliasSummary {
    fn digest(&self) -> Digest {
        self.digest()
    }
}

trait KmsGrantDigest {
    fn digest(&self) -> Digest;
}

impl KmsGrantDigest for crate::model::KmsGrantSummary {
    fn digest(&self) -> Digest {
        self.digest()
    }
}

fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    Digest::from_text(serde_json::to_vec(value).expect("KMS digest input is serializable"))
}
