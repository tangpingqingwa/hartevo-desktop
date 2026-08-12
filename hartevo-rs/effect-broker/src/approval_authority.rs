//! Human and Provider evidence required to authorize recording one Effect approval.
//!
//! This module deliberately stops before Domain approval persistence and before
//! execution. The checked-in human issuer and Provider adapter registries are
//! empty, so the production constructor cannot currently produce an
//! [`ApprovalAuthority`].

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    AccountId, ActorId, ConnectionId, Effect, EffectId, EffectStatus, Mission, MissionId,
    ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::provider_auth::{
    AuthSession, ConnectedAuthorization, CredentialLease, PROVIDER_AUTH_PROBE_CONTRACT_VERSION,
    PROVIDER_AUTH_PROBE_SCHEMA_VERSION, ProbeResult, ProviderAuthProbeError,
    ProviderAuthProbePolicy, SecretReference,
};
use crate::provider_contract::{
    PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION, PROVIDER_ADAPTER_CONTRACT_VERSION,
    ProviderAdapterIdentity, ProviderAdapterRegistry, ProviderCapabilityKey,
};
use crate::{EffectPolicy, PermissionEvidence};

pub const PROVIDER_APPROVAL_AUTHORITY_SCHEMA_VERSION: &str =
    "hartevo-provider-approval-authority-contract/v1";
pub const PROVIDER_APPROVAL_AUTHORITY_CONTRACT_VERSION: &str = "provider-approval-authority-e1/v1";
pub const HUMAN_OPERATION_AUTHORITY_SCHEMA_VERSION: &str =
    "hartevo-human-operation-authority-contract/v1";
pub const HUMAN_OPERATION_AUTHORITY_CONTRACT_VERSION: &str = "human-operation-authority-e1/v1";
pub const PROVIDER_APPROVAL_AUTHORITY_CONTRACT_JSON: &str =
    include_str!("../../../contracts/providers/approval-authority.v1.json");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ContractEvidenceLevel {
    #[serde(rename = "E1")]
    E1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAuthorityKind {
    EffectApprovalRecordOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApprovalSecretMaterialPolicy {
    OpaqueReferenceAndDigestOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanOperationKind {
    ApproveProviderEffect,
}

impl HumanOperationKind {
    const ALL: [Self; 1] = [Self::ApproveProviderEffect];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanOperationDecision {
    Approve,
}

impl HumanOperationDecision {
    const ALL: [Self; 1] = [Self::Approve];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanAssuranceLevel {
    Reauthenticated,
    MultiFactor,
    HardwareBound,
}

impl HumanAssuranceLevel {
    const ALL: [Self; 3] = [
        Self::Reauthenticated,
        Self::MultiFactor,
        Self::HardwareBound,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanStepUpMethod {
    PasswordReauthentication,
    Totp,
    Webauthn,
    PlatformBiometric,
}

impl HumanStepUpMethod {
    const ALL: [Self; 4] = [
        Self::PasswordReauthentication,
        Self::Totp,
        Self::Webauthn,
        Self::PlatformBiometric,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SingleUseIntentPolicy {
    RequestBoundByValueConsume,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ForbiddenSerializedMaterial {
    RawToken,
    MfaCode,
    BiometricSample,
}

impl ForbiddenSerializedMaterial {
    const ALL: [Self; 3] = [Self::RawToken, Self::MfaCode, Self::BiometricSample];
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanAuthorityIssuerIdentity {
    issuer_id: String,
    issuer_version: u32,
}

impl HumanAuthorityIssuerIdentity {
    pub fn new(
        issuer_id: impl Into<String>,
        issuer_version: u32,
    ) -> Result<Self, ApprovalAuthorityError> {
        let identity = Self {
            issuer_id: issuer_id.into(),
            issuer_version,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub const fn issuer_version(&self) -> u32 {
        self.issuer_version
    }

    fn validate(&self) -> Result<(), ApprovalAuthorityError> {
        if !valid_namespaced_id(&self.issuer_id) || self.issuer_version == 0 {
            return Err(ApprovalAuthorityError::InvalidHumanIssuer);
        }
        Ok(())
    }
}

impl fmt::Debug for HumanAuthorityIssuerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanAuthorityIssuerIdentity")
            .field("issuer_version", &self.issuer_version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HumanAuthorityIssuerRegistration {
    identity: HumanAuthorityIssuerIdentity,
    operation_kinds: Vec<HumanOperationKind>,
    assurance_levels: Vec<HumanAssuranceLevel>,
    max_actor_authorization_ttl_seconds: u64,
    max_session_ttl_seconds: u64,
    max_step_up_ttl_seconds: u64,
}

impl HumanAuthorityIssuerRegistration {
    fn validate(&self) -> Result<(), ApprovalAuthorityError> {
        self.identity.validate()?;
        validate_nonempty_unique_subset(
            &self.operation_kinds,
            &HumanOperationKind::ALL,
            "issuer operation kinds",
        )?;
        validate_nonempty_unique_subset(
            &self.assurance_levels,
            &HumanAssuranceLevel::ALL,
            "issuer assurance levels",
        )?;
        if self.max_actor_authorization_ttl_seconds == 0
            || self.max_session_ttl_seconds == 0
            || self.max_step_up_ttl_seconds == 0
            || self.max_session_ttl_seconds > self.max_actor_authorization_ttl_seconds
            || self.max_step_up_ttl_seconds > self.max_session_ttl_seconds
        {
            return Err(ApprovalAuthorityError::InvalidHumanIssuer);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HumanOperationAuthorityContract {
    schema_version: String,
    contract_version: String,
    contract_digest: String,
    operation_kinds: Vec<HumanOperationKind>,
    decisions: Vec<HumanOperationDecision>,
    assurance_levels: Vec<HumanAssuranceLevel>,
    step_up_methods: Vec<HumanStepUpMethod>,
    single_use_intent: SingleUseIntentPolicy,
    forbidden_serialized_material: Vec<ForbiddenSerializedMaterial>,
    issuer_registrations: Vec<HumanAuthorityIssuerRegistration>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HumanOperationAuthorityDigestMaterial<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    operation_kinds: &'a [HumanOperationKind],
    decisions: &'a [HumanOperationDecision],
    assurance_levels: &'a [HumanAssuranceLevel],
    step_up_methods: &'a [HumanStepUpMethod],
    single_use_intent: SingleUseIntentPolicy,
    forbidden_serialized_material: &'a [ForbiddenSerializedMaterial],
    issuer_registrations: &'a [HumanAuthorityIssuerRegistration],
}

impl HumanOperationAuthorityContract {
    fn canonical_digest(&self) -> Result<String, ApprovalAuthorityError> {
        digest_json(&HumanOperationAuthorityDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            operation_kinds: &self.operation_kinds,
            decisions: &self.decisions,
            assurance_levels: &self.assurance_levels,
            step_up_methods: &self.step_up_methods,
            single_use_intent: self.single_use_intent,
            forbidden_serialized_material: &self.forbidden_serialized_material,
            issuer_registrations: &self.issuer_registrations,
        })
    }

    fn validate(&self) -> Result<(), ApprovalAuthorityError> {
        if self.schema_version != HUMAN_OPERATION_AUTHORITY_SCHEMA_VERSION
            || self.contract_version != HUMAN_OPERATION_AUTHORITY_CONTRACT_VERSION
            || !is_sha256(&self.contract_digest)
            || self.contract_digest != self.canonical_digest()?
        {
            return Err(ApprovalAuthorityError::InvalidHumanContractClosure);
        }
        validate_exact_set(
            &self.operation_kinds,
            &HumanOperationKind::ALL,
            "human operation kinds",
        )?;
        validate_exact_set(
            &self.decisions,
            &HumanOperationDecision::ALL,
            "human decisions",
        )?;
        validate_exact_set(
            &self.assurance_levels,
            &HumanAssuranceLevel::ALL,
            "human assurance levels",
        )?;
        validate_exact_set(
            &self.step_up_methods,
            &HumanStepUpMethod::ALL,
            "step-up methods",
        )?;
        validate_exact_set(
            &self.forbidden_serialized_material,
            &ForbiddenSerializedMaterial::ALL,
            "forbidden serialized material",
        )?;
        if self.single_use_intent != SingleUseIntentPolicy::RequestBoundByValueConsume
            || !self.issuer_registrations.is_empty()
        {
            return Err(ApprovalAuthorityError::InvalidHumanAuthorityBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HumanOperationAuthorityReference {
    schema_version: String,
    contract_version: String,
    contract_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RegistrySource {
    ProviderAdapterRegistry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EmptyRegistryBehavior {
    DenyApprovalAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdapterClaimAuthority {
    MetadataBindingOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderAdapterContractReference {
    schema_version: String,
    contract_version: String,
    registry_source: RegistrySource,
    empty_registry_behavior: EmptyRegistryBehavior,
    claim_authority: AdapterClaimAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConnectedAuthorityReference {
    ConnectionStateOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FreshnessRevalidation {
    SameOperationAt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderAuthProbeContractReference {
    schema_version: String,
    contract_version: String,
    connected_authority: ConnectedAuthorityReference,
    freshness_revalidation: FreshnessRevalidation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequiredApprovalBinding {
    ActorAuthorization,
    ActorSession,
    RequestBoundStepUp,
    MissionRevision,
    EffectApprovalDigest,
    ProviderCapabilityMetadata,
    ProviderAuthProbeLiveChain,
    EffectPolicy,
    PermissionEvidence,
    AllDeadlines,
}

impl RequiredApprovalBinding {
    const ALL: [Self; 10] = [
        Self::ActorAuthorization,
        Self::ActorSession,
        Self::RequestBoundStepUp,
        Self::MissionRevision,
        Self::EffectApprovalDigest,
        Self::ProviderCapabilityMetadata,
        Self::ProviderAuthProbeLiveChain,
        Self::EffectPolicy,
        Self::PermissionEvidence,
        Self::AllDeadlines,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApprovalDeadlineSource {
    ApprovalPolicy,
    EffectExpiry,
    ContractExpiry,
    ActorAuthorizationExpiry,
    ActorSessionExpiry,
    StepUpExpiry,
    ProviderProbeExpiry,
}

impl ApprovalDeadlineSource {
    const ALL: [Self; 7] = [
        Self::ApprovalPolicy,
        Self::EffectExpiry,
        Self::ContractExpiry,
        Self::ActorAuthorizationExpiry,
        Self::ActorSessionExpiry,
        Self::StepUpExpiry,
        Self::ProviderProbeExpiry,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ForbiddenApprovalAuthority {
    RuntimeLocalApproval,
    ConnectedUpgrade,
    ProviderExecution,
    ProviderReceipt,
    BusinessVerification,
    E4,
}

impl ForbiddenApprovalAuthority {
    const ALL: [Self; 6] = [
        Self::RuntimeLocalApproval,
        Self::ConnectedUpgrade,
        Self::ProviderExecution,
        Self::ProviderReceipt,
        Self::BusinessVerification,
        Self::E4,
    ];
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderApprovalAuthorityPolicy {
    schema_version: String,
    contract_version: String,
    contract_digest: String,
    evidence_level: ContractEvidenceLevel,
    authority: ApprovalAuthorityKind,
    secret_material: ApprovalSecretMaterialPolicy,
    decision: HumanOperationDecision,
    human_operation_authority: HumanOperationAuthorityContract,
    human_operation_authority_reference: HumanOperationAuthorityReference,
    provider_adapter_contract: ProviderAdapterContractReference,
    provider_auth_probe_contract: ProviderAuthProbeContractReference,
    required_bindings: Vec<RequiredApprovalBinding>,
    deadline_sources: Vec<ApprovalDeadlineSource>,
    forbidden_authorities: Vec<ForbiddenApprovalAuthority>,
}

impl fmt::Debug for ProviderApprovalAuthorityPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderApprovalAuthorityPolicy")
            .field("contract_version", &self.contract_version)
            .field("evidence_level", &self.evidence_level)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderApprovalAuthorityDigestMaterial<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    evidence_level: ContractEvidenceLevel,
    authority: ApprovalAuthorityKind,
    secret_material: ApprovalSecretMaterialPolicy,
    decision: HumanOperationDecision,
    human_operation_authority: &'a HumanOperationAuthorityContract,
    human_operation_authority_reference: &'a HumanOperationAuthorityReference,
    provider_adapter_contract: &'a ProviderAdapterContractReference,
    provider_auth_probe_contract: &'a ProviderAuthProbeContractReference,
    required_bindings: &'a [RequiredApprovalBinding],
    deadline_sources: &'a [ApprovalDeadlineSource],
    forbidden_authorities: &'a [ForbiddenApprovalAuthority],
}

impl ProviderApprovalAuthorityPolicy {
    pub fn contract_baseline() -> Result<Self, ApprovalAuthorityError> {
        Self::from_contract_json(PROVIDER_APPROVAL_AUTHORITY_CONTRACT_JSON)
    }

    pub fn from_contract_json(contract_json: &str) -> Result<Self, ApprovalAuthorityError> {
        let policy = serde_json::from_str::<Self>(contract_json)
            .map_err(|_| ApprovalAuthorityError::InvalidContractDocument)?;
        policy.validate()?;
        Ok(policy)
    }

    pub const fn authority(&self) -> ApprovalAuthorityKind {
        ApprovalAuthorityKind::EffectApprovalRecordOnly
    }

    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }

    fn canonical_digest(&self) -> Result<String, ApprovalAuthorityError> {
        digest_json(&ProviderApprovalAuthorityDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            evidence_level: self.evidence_level,
            authority: self.authority,
            secret_material: self.secret_material,
            decision: self.decision,
            human_operation_authority: &self.human_operation_authority,
            human_operation_authority_reference: &self.human_operation_authority_reference,
            provider_adapter_contract: &self.provider_adapter_contract,
            provider_auth_probe_contract: &self.provider_auth_probe_contract,
            required_bindings: &self.required_bindings,
            deadline_sources: &self.deadline_sources,
            forbidden_authorities: &self.forbidden_authorities,
        })
    }

    pub fn validate(&self) -> Result<(), ApprovalAuthorityError> {
        self.human_operation_authority.validate()?;
        if self.schema_version != PROVIDER_APPROVAL_AUTHORITY_SCHEMA_VERSION
            || self.contract_version != PROVIDER_APPROVAL_AUTHORITY_CONTRACT_VERSION
            || !is_sha256(&self.contract_digest)
            || self.contract_digest != self.canonical_digest()?
        {
            return Err(ApprovalAuthorityError::InvalidProviderContractClosure);
        }
        if self.evidence_level != ContractEvidenceLevel::E1
            || self.authority != ApprovalAuthorityKind::EffectApprovalRecordOnly
            || self.secret_material != ApprovalSecretMaterialPolicy::OpaqueReferenceAndDigestOnly
            || self.decision != HumanOperationDecision::Approve
        {
            return Err(ApprovalAuthorityError::InvalidAuthorityBoundary);
        }
        let human = &self.human_operation_authority;
        let human_reference = &self.human_operation_authority_reference;
        if human_reference.schema_version != human.schema_version
            || human_reference.contract_version != human.contract_version
            || human_reference.contract_digest != human.contract_digest
        {
            return Err(ApprovalAuthorityError::InvalidHumanContractClosure);
        }
        let adapter = &self.provider_adapter_contract;
        if adapter.schema_version != PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION
            || adapter.contract_version != PROVIDER_ADAPTER_CONTRACT_VERSION
            || adapter.registry_source != RegistrySource::ProviderAdapterRegistry
            || adapter.empty_registry_behavior != EmptyRegistryBehavior::DenyApprovalAuthority
            || adapter.claim_authority != AdapterClaimAuthority::MetadataBindingOnly
        {
            return Err(ApprovalAuthorityError::InvalidProviderContractClosure);
        }
        let auth_probe = &self.provider_auth_probe_contract;
        if auth_probe.schema_version != PROVIDER_AUTH_PROBE_SCHEMA_VERSION
            || auth_probe.contract_version != PROVIDER_AUTH_PROBE_CONTRACT_VERSION
            || auth_probe.connected_authority != ConnectedAuthorityReference::ConnectionStateOnly
            || auth_probe.freshness_revalidation != FreshnessRevalidation::SameOperationAt
        {
            return Err(ApprovalAuthorityError::InvalidProviderAuthClosure);
        }
        validate_exact_set(
            &self.required_bindings,
            &RequiredApprovalBinding::ALL,
            "required approval bindings",
        )?;
        validate_exact_set(
            &self.deadline_sources,
            &ApprovalDeadlineSource::ALL,
            "approval deadline sources",
        )?;
        validate_exact_set(
            &self.forbidden_authorities,
            &ForbiddenApprovalAuthority::ALL,
            "forbidden approval authorities",
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HumanAuthoritySubject {
    tenant_id: TenantId,
    project_id: ProjectId,
    actor_id: ActorId,
    issuer: HumanAuthorityIssuerIdentity,
    authority_revision: u64,
}

impl fmt::Debug for HumanAuthoritySubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanAuthoritySubject")
            .field("authority_revision", &self.authority_revision)
            .finish_non_exhaustive()
    }
}

impl HumanAuthoritySubject {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        actor_id: ActorId,
        issuer: HumanAuthorityIssuerIdentity,
        authority_revision: u64,
    ) -> Result<Self, ApprovalAuthorityError> {
        let subject = Self {
            tenant_id,
            project_id,
            actor_id,
            issuer,
            authority_revision,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub const fn issuer(&self) -> &HumanAuthorityIssuerIdentity {
        &self.issuer
    }

    pub const fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    fn validate(&self) -> Result<(), ApprovalAuthorityError> {
        self.issuer.validate()?;
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.actor_id.as_str().trim().is_empty()
            || self.authority_revision == 0
        {
            return Err(ApprovalAuthorityError::InvalidHumanSubject);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanEvidenceWindow {
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl HumanEvidenceWindow {
    pub fn new(
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ApprovalAuthorityError> {
        if expires_at <= issued_at {
            return Err(ApprovalAuthorityError::InvalidHumanEvidenceWindow);
        }
        Ok(Self {
            issued_at,
            expires_at,
        })
    }

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn ttl_seconds(&self) -> Result<u64, ApprovalAuthorityError> {
        u64::try_from((self.expires_at - self.issued_at).num_seconds())
            .map_err(|_| ApprovalAuthorityError::InvalidHumanEvidenceWindow)
    }

    fn validate_live(
        &self,
        revoked_at: Option<DateTime<Utc>>,
        operation_at: DateTime<Utc>,
    ) -> Result<(), ApprovalAuthorityError> {
        if operation_at < self.issued_at
            || operation_at >= self.expires_at
            || revoked_at.is_some_and(|revoked| revoked <= operation_at)
        {
            return Err(ApprovalAuthorityError::HumanEvidenceStaleOrRevoked);
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq)]
pub struct HumanActorAuthorization {
    authorization_id: String,
    subject: HumanAuthoritySubject,
    operation_kind: HumanOperationKind,
    scope_digest: String,
    assurance: HumanAssuranceLevel,
    window: HumanEvidenceWindow,
    revoked_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for HumanActorAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanActorAuthorization")
            .field("operation_kind", &self.operation_kind)
            .field("assurance", &self.assurance)
            .field("window", &self.window)
            .field("revoked", &self.revoked_at.is_some())
            .finish_non_exhaustive()
    }
}

impl HumanActorAuthorization {
    pub fn new(
        authorization_id: impl Into<String>,
        subject: HumanAuthoritySubject,
        operation_kind: HumanOperationKind,
        scope_digest: impl Into<String>,
        assurance: HumanAssuranceLevel,
        window: HumanEvidenceWindow,
    ) -> Result<Self, ApprovalAuthorityError> {
        let authorization = Self {
            authorization_id: authorization_id.into(),
            subject,
            operation_kind,
            scope_digest: scope_digest.into(),
            assurance,
            window,
            revoked_at: None,
        };
        authorization.validate_structure()?;
        Ok(authorization)
    }

    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }

    pub const fn subject(&self) -> &HumanAuthoritySubject {
        &self.subject
    }

    pub const fn assurance(&self) -> HumanAssuranceLevel {
        self.assurance
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.window.expires_at
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ApprovalAuthorityError> {
        if revoked_at < self.window.issued_at {
            return Err(ApprovalAuthorityError::InvalidRevocation);
        }
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ApprovalAuthorityError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), ApprovalAuthorityError> {
        self.subject.validate()?;
        if !valid_opaque_id(&self.authorization_id, "human-authorization-")
            || !is_sha256(&self.scope_digest)
            || self.operation_kind != HumanOperationKind::ApproveProviderEffect
        {
            return Err(ApprovalAuthorityError::InvalidActorAuthorization);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HumanSessionIdentity {
    session_id: String,
    actor_authorization_id: String,
    session_revision: u64,
}

impl fmt::Debug for HumanSessionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanSessionIdentity")
            .field("session_revision", &self.session_revision)
            .finish_non_exhaustive()
    }
}

impl HumanSessionIdentity {
    pub fn new(
        session_id: impl Into<String>,
        actor_authorization_id: impl Into<String>,
        session_revision: u64,
    ) -> Result<Self, ApprovalAuthorityError> {
        let identity = Self {
            session_id: session_id.into(),
            actor_authorization_id: actor_authorization_id.into(),
            session_revision,
        };
        if !valid_opaque_id(&identity.session_id, "human-session-")
            || !valid_opaque_id(&identity.actor_authorization_id, "human-authorization-")
            || identity.session_revision == 0
        {
            return Err(ApprovalAuthorityError::InvalidActorSession);
        }
        Ok(identity)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub const fn session_revision(&self) -> u64 {
        self.session_revision
    }
}

#[derive(Eq, PartialEq)]
pub struct HumanActorSession {
    identity: HumanSessionIdentity,
    subject: HumanAuthoritySubject,
    assurance: HumanAssuranceLevel,
    authenticated_at: DateTime<Utc>,
    window: HumanEvidenceWindow,
    evidence_digest: String,
    revoked_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for HumanActorSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanActorSession")
            .field("assurance", &self.assurance)
            .field("authenticated_at", &self.authenticated_at)
            .field("window", &self.window)
            .field("revoked", &self.revoked_at.is_some())
            .finish_non_exhaustive()
    }
}

impl HumanActorSession {
    pub fn new(
        identity: HumanSessionIdentity,
        subject: HumanAuthoritySubject,
        assurance: HumanAssuranceLevel,
        authenticated_at: DateTime<Utc>,
        window: HumanEvidenceWindow,
        evidence_digest: impl Into<String>,
    ) -> Result<Self, ApprovalAuthorityError> {
        let session = Self {
            identity,
            subject,
            assurance,
            authenticated_at,
            window,
            evidence_digest: evidence_digest.into(),
            revoked_at: None,
        };
        session.validate_structure()?;
        Ok(session)
    }

    pub const fn identity(&self) -> &HumanSessionIdentity {
        &self.identity
    }

    pub const fn subject(&self) -> &HumanAuthoritySubject {
        &self.subject
    }

    pub const fn assurance(&self) -> HumanAssuranceLevel {
        self.assurance
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.window.expires_at
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ApprovalAuthorityError> {
        if revoked_at < self.window.issued_at {
            return Err(ApprovalAuthorityError::InvalidRevocation);
        }
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ApprovalAuthorityError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), ApprovalAuthorityError> {
        self.subject.validate()?;
        if self.authenticated_at > self.window.issued_at || !is_sha256(&self.evidence_digest) {
            return Err(ApprovalAuthorityError::InvalidActorSession);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HumanStepUpIntentIdentity {
    intent_id: String,
    intent_revision: u64,
}

impl fmt::Debug for HumanStepUpIntentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanStepUpIntentIdentity")
            .field("intent_revision", &self.intent_revision)
            .finish_non_exhaustive()
    }
}

impl HumanStepUpIntentIdentity {
    pub fn new(
        intent_id: impl Into<String>,
        intent_revision: u64,
    ) -> Result<Self, ApprovalAuthorityError> {
        let identity = Self {
            intent_id: intent_id.into(),
            intent_revision,
        };
        if !valid_opaque_id(&identity.intent_id, "step-up-intent-") || identity.intent_revision == 0
        {
            return Err(ApprovalAuthorityError::InvalidStepUpIntent);
        }
        Ok(identity)
    }
}

#[derive(Eq, PartialEq)]
pub struct HumanStepUpIntent {
    identity: HumanStepUpIntentIdentity,
    subject: HumanAuthoritySubject,
    session_identity: HumanSessionIdentity,
    operation_kind: HumanOperationKind,
    decision: HumanOperationDecision,
    method: HumanStepUpMethod,
    assurance: HumanAssuranceLevel,
    exact_target_digest: String,
    window: HumanEvidenceWindow,
}

impl fmt::Debug for HumanStepUpIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanStepUpIntent")
            .field("operation_kind", &self.operation_kind)
            .field("decision", &self.decision)
            .field("method", &self.method)
            .field("assurance", &self.assurance)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl HumanStepUpIntent {
    pub fn new(
        identity: HumanStepUpIntentIdentity,
        actor_session: &HumanActorSession,
        method: HumanStepUpMethod,
        assurance: HumanAssuranceLevel,
        exact_target_digest: impl Into<String>,
        window: HumanEvidenceWindow,
    ) -> Result<Self, ApprovalAuthorityError> {
        let intent = Self {
            identity,
            subject: actor_session.subject.clone(),
            session_identity: actor_session.identity.clone(),
            operation_kind: HumanOperationKind::ApproveProviderEffect,
            decision: HumanOperationDecision::Approve,
            method,
            assurance,
            exact_target_digest: exact_target_digest.into(),
            window,
        };
        intent.validate_structure()?;
        Ok(intent)
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.window.expires_at
    }

    fn validate_structure(&self) -> Result<(), ApprovalAuthorityError> {
        self.subject.validate()?;
        if !is_sha256(&self.exact_target_digest)
            || self.operation_kind != HumanOperationKind::ApproveProviderEffect
            || self.decision != HumanOperationDecision::Approve
        {
            return Err(ApprovalAuthorityError::InvalidStepUpIntent);
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq)]
pub struct RequestBoundStepUpAssertion {
    assertion_id: String,
    intent_id: String,
    intent_revision: u64,
    issuer: HumanAuthorityIssuerIdentity,
    actor_id: ActorId,
    session_id: String,
    session_revision: u64,
    request_digest: String,
    verified_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    evidence_digest: String,
    binding_digest: String,
    revoked_at: Option<DateTime<Utc>>,
}

impl RequestBoundStepUpAssertion {
    pub fn new(
        assertion_id: impl Into<String>,
        request: &ApprovalRequest,
        verified_at: DateTime<Utc>,
        evidence_digest: impl Into<String>,
    ) -> Result<Self, ApprovalAuthorityError> {
        let mut assertion = Self {
            assertion_id: assertion_id.into(),
            intent_id: request.step_up_intent.identity.intent_id.clone(),
            intent_revision: request.step_up_intent.identity.intent_revision,
            issuer: request.human_issuer.clone(),
            actor_id: request.approving_actor_id.clone(),
            session_id: request.actor_session_id.clone(),
            session_revision: request.actor_session_revision,
            request_digest: request.request_digest.clone(),
            verified_at,
            expires_at: request.step_up_intent.window.expires_at,
            evidence_digest: evidence_digest.into(),
            binding_digest: String::new(),
            revoked_at: None,
        };
        assertion.binding_digest = assertion.canonical_binding_digest();
        assertion.validate_structure()?;
        Ok(assertion)
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ApprovalAuthorityError> {
        if revoked_at < self.verified_at {
            return Err(ApprovalAuthorityError::InvalidRevocation);
        }
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ApprovalAuthorityError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), ApprovalAuthorityError> {
        self.issuer.validate()?;
        if !valid_opaque_id(&self.assertion_id, "step-up-assertion-")
            || !valid_opaque_id(&self.intent_id, "step-up-intent-")
            || !valid_opaque_id(&self.session_id, "human-session-")
            || self.intent_revision == 0
            || self.session_revision == 0
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.binding_digest)
            || self.expires_at <= self.verified_at
        {
            return Err(ApprovalAuthorityError::InvalidStepUpAssertion);
        }
        if self.binding_digest != self.canonical_binding_digest() {
            return Err(ApprovalAuthorityError::StepUpAssertionMismatch);
        }
        Ok(())
    }

    fn canonical_binding_digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_field(&mut digest, "hartevo-request-bound-step-up-assertion/v1");
        hash_field(&mut digest, &self.assertion_id);
        hash_field(&mut digest, &self.intent_id);
        hash_field(&mut digest, &self.intent_revision.to_string());
        hash_field(&mut digest, self.issuer.issuer_id());
        hash_field(&mut digest, &self.issuer.issuer_version().to_string());
        hash_field(&mut digest, self.actor_id.as_str());
        hash_field(&mut digest, &self.session_id);
        hash_field(&mut digest, &self.session_revision.to_string());
        hash_field(&mut digest, &self.request_digest);
        hash_time(&mut digest, self.verified_at);
        hash_time(&mut digest, self.expires_at);
        hash_field(&mut digest, &self.evidence_digest);
        format!("{:x}", digest.finalize())
    }
}

impl fmt::Debug for RequestBoundStepUpAssertion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBoundStepUpAssertion")
            .field("request_digest", &short_digest(&self.request_digest))
            .field("binding_digest", &short_digest(&self.binding_digest))
            .field("verified_at", &self.verified_at)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked_at.is_some())
            .finish_non_exhaustive()
    }
}

pub struct ProviderEffectApprovalContext<'a> {
    mission: &'a Mission,
    effect_id: &'a EffectId,
    effect_policy: &'a EffectPolicy,
    permission_evidence: &'a PermissionEvidence,
}

impl<'a> ProviderEffectApprovalContext<'a> {
    pub const fn new(
        mission: &'a Mission,
        effect_id: &'a EffectId,
        effect_policy: &'a EffectPolicy,
        permission_evidence: &'a PermissionEvidence,
    ) -> Self {
        Self {
            mission,
            effect_id,
            effect_policy,
            permission_evidence,
        }
    }
}

impl fmt::Debug for ProviderEffectApprovalContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEffectApprovalContext")
            .finish_non_exhaustive()
    }
}

pub struct ProviderApprovalEvidence<'a> {
    auth_probe_policy: &'a ProviderAuthProbePolicy,
    secret_reference: &'a SecretReference,
    credential_lease: &'a CredentialLease,
    auth_session: &'a AuthSession,
    probe_result: &'a ProbeResult,
}

impl fmt::Debug for ProviderApprovalEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderApprovalEvidence")
            .finish_non_exhaustive()
    }
}

impl<'a> ProviderApprovalEvidence<'a> {
    pub const fn new(
        auth_probe_policy: &'a ProviderAuthProbePolicy,
        secret_reference: &'a SecretReference,
        credential_lease: &'a CredentialLease,
        auth_session: &'a AuthSession,
        probe_result: &'a ProbeResult,
    ) -> Self {
        Self {
            auth_probe_policy,
            secret_reference,
            credential_lease,
            auth_session,
            probe_result,
        }
    }

    fn authorize(
        self,
        operation_at: DateTime<Utc>,
    ) -> Result<ConnectedApprovalBinding, ApprovalAuthorityError> {
        let Self {
            auth_probe_policy,
            secret_reference,
            credential_lease,
            auth_session,
            probe_result,
        } = self;
        let connected = auth_probe_policy.authorize_connected(
            secret_reference,
            credential_lease,
            auth_session,
            probe_result,
            operation_at,
        )?;
        ConnectedApprovalBinding::from_live_chain(
            &connected,
            secret_reference,
            credential_lease,
            auth_session,
        )
    }
}

pub struct HumanApprovalRequestEvidence<'a> {
    actor_authorization: &'a HumanActorAuthorization,
    actor_session: &'a HumanActorSession,
    step_up_intent: Box<HumanStepUpIntent>,
}

impl fmt::Debug for HumanApprovalRequestEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanApprovalRequestEvidence")
            .finish_non_exhaustive()
    }
}

impl<'a> HumanApprovalRequestEvidence<'a> {
    pub fn new(
        actor_authorization: &'a HumanActorAuthorization,
        actor_session: &'a HumanActorSession,
        step_up_intent: HumanStepUpIntent,
    ) -> Self {
        Self {
            actor_authorization,
            actor_session,
            step_up_intent: Box::new(step_up_intent),
        }
    }
}

pub struct HumanApprovalIssuanceEvidence<'a> {
    actor_authorization: &'a HumanActorAuthorization,
    actor_session: &'a HumanActorSession,
    step_up_assertion: Box<RequestBoundStepUpAssertion>,
}

impl fmt::Debug for HumanApprovalIssuanceEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanApprovalIssuanceEvidence")
            .finish_non_exhaustive()
    }
}

impl<'a> HumanApprovalIssuanceEvidence<'a> {
    pub fn new(
        actor_authorization: &'a HumanActorAuthorization,
        actor_session: &'a HumanActorSession,
        step_up_assertion: RequestBoundStepUpAssertion,
    ) -> Self {
        Self {
            actor_authorization,
            actor_session,
            step_up_assertion: Box::new(step_up_assertion),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectedApprovalBinding {
    tenant_id: TenantId,
    project_id: ProjectId,
    provider_id: String,
    account_id: AccountId,
    leased_scopes: Vec<String>,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    probe_revision: u64,
    evidence_digest: String,
    opaque_chain_digest: String,
    observed_valid_until: DateTime<Utc>,
}

#[derive(Clone, Copy)]
struct ApprovalRegistryView<'a> {
    adapter_registry: &'a ProviderAdapterRegistry,
    human_issuers: &'a [HumanAuthorityIssuerRegistration],
}

impl ConnectedApprovalBinding {
    fn from_live_chain(
        connected: &ConnectedAuthorization,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        auth_session: &AuthSession,
    ) -> Result<Self, ApprovalAuthorityError> {
        let scope = connected.scope();
        let mut digest = Sha256::new();
        hash_field(&mut digest, "hartevo-provider-approval-opaque-chain/v1");
        hash_field(&mut digest, secret_reference.reference_id());
        hash_field(&mut digest, credential_lease.lease_id());
        hash_field(&mut digest, auth_session.session_id());
        hash_field(
            &mut digest,
            &secret_reference.credential_revision().to_string(),
        );
        hash_field(&mut digest, &connected.lease_revision().to_string());
        hash_field(&mut digest, &connected.auth_revision().to_string());
        hash_field(&mut digest, &connected.probe_revision().to_string());
        let binding = Self {
            tenant_id: scope.tenant_id().clone(),
            project_id: scope.project_id().clone(),
            provider_id: scope.provider_id().to_owned(),
            account_id: scope.account_id().clone(),
            leased_scopes: scope.scopes().to_vec(),
            adapter: connected.adapter().clone(),
            credential_revision: connected.credential_revision(),
            lease_revision: connected.lease_revision(),
            auth_revision: connected.auth_revision(),
            probe_revision: connected.probe_revision(),
            evidence_digest: connected.evidence_digest().to_owned(),
            opaque_chain_digest: format!("{:x}", digest.finalize()),
            observed_valid_until: connected.observed_valid_until(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), ApprovalAuthorityError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.provider_id.trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.leased_scopes.is_empty()
            || self.leased_scopes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.credential_revision == 0
            || self.lease_revision == 0
            || self.auth_revision == 0
            || self.probe_revision == 0
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.opaque_chain_digest)
        {
            return Err(ApprovalAuthorityError::InvalidProviderBinding);
        }
        Ok(())
    }
}

/// Non-authoritative request material for one exact human step-up decision.
///
/// It intentionally supports neither cloning nor serde round-trips. A caller
/// may expose only [`ApprovalRequest::request_digest`] to a step-up adapter.
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRequest;
///
/// fn request_is_not_cloneable(value: &ApprovalRequest) {
///     let _: ApprovalRequest = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRequest;
///
/// fn request_is_not_serializable(value: &ApprovalRequest) {
///     let _ = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRequest;
///
/// fn request_is_not_deserializable() {
///     let _: ApprovalRequest = serde_json::from_str("{}").unwrap();
/// }
/// ```
#[derive(Eq, PartialEq)]
pub struct ApprovalRequest {
    contract_version: String,
    contract_digest: String,
    operation_kind: HumanOperationKind,
    decision: HumanOperationDecision,
    requested_at: DateTime<Utc>,
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    effect_id: EffectId,
    requesting_actor_id: ActorId,
    approving_actor_id: ActorId,
    connection_id: ConnectionId,
    provider_id: String,
    account_id: AccountId,
    capability_id: String,
    required_scopes: BTreeSet<String>,
    leased_scopes: Vec<String>,
    adapter_registry_version: String,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    probe_revision: u64,
    provider_evidence_digest: String,
    provider_opaque_chain_digest: String,
    provider_probe_expires_at: DateTime<Utc>,
    effect_approval_digest: String,
    payload_digest: String,
    policy_digest: String,
    permission_evidence_digest: String,
    permission_authorization_digest: String,
    approval_policy_validity_seconds: u64,
    effect_expires_at: DateTime<Utc>,
    contract_expires_at: DateTime<Utc>,
    human_issuer: HumanAuthorityIssuerIdentity,
    actor_authorization_id: String,
    actor_authority_revision: u64,
    actor_authorization_scope_digest: String,
    actor_authorization_assurance: HumanAssuranceLevel,
    actor_authorization_expires_at: DateTime<Utc>,
    actor_session_id: String,
    actor_session_revision: u64,
    actor_session_assurance: HumanAssuranceLevel,
    actor_session_evidence_digest: String,
    actor_session_expires_at: DateTime<Utc>,
    step_up_intent: HumanStepUpIntent,
    request_digest: String,
}

impl fmt::Debug for ApprovalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalRequest")
            .field("operation_kind", &self.operation_kind)
            .field("decision", &self.decision)
            .field("requested_at", &self.requested_at)
            .field("mission_revision", &self.mission_revision)
            .field(
                "effect_approval_digest",
                &short_digest(&self.effect_approval_digest),
            )
            .field("request_digest", &short_digest(&self.request_digest))
            .field("effect_expires_at", &self.effect_expires_at)
            .field("contract_expires_at", &self.contract_expires_at)
            .field("provider_probe_expires_at", &self.provider_probe_expires_at)
            .finish_non_exhaustive()
    }
}

impl ApprovalRequest {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn effect_id(&self) -> &EffectId {
        &self.effect_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn decision(&self) -> HumanOperationDecision {
        HumanOperationDecision::Approve
    }

    fn canonical_digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_field(&mut digest, "hartevo-provider-approval-request/v1");
        hash_field(&mut digest, &self.contract_version);
        hash_field(&mut digest, &self.contract_digest);
        hash_field(&mut digest, human_operation_name(self.operation_kind));
        hash_field(&mut digest, human_decision_name(self.decision));
        hash_time(&mut digest, self.requested_at);
        hash_field(&mut digest, self.tenant_id.as_str());
        hash_field(&mut digest, self.project_id.as_str());
        hash_field(&mut digest, self.mission_id.as_str());
        hash_field(&mut digest, &self.mission_revision.to_string());
        hash_field(&mut digest, self.effect_id.as_str());
        hash_field(&mut digest, self.requesting_actor_id.as_str());
        hash_field(&mut digest, self.approving_actor_id.as_str());
        hash_field(&mut digest, self.connection_id.as_str());
        hash_field(&mut digest, &self.provider_id);
        hash_field(&mut digest, self.account_id.as_str());
        hash_field(&mut digest, &self.capability_id);
        for scope in &self.required_scopes {
            hash_field(&mut digest, scope);
        }
        hash_field(&mut digest, "leased_scopes");
        for scope in &self.leased_scopes {
            hash_field(&mut digest, scope);
        }
        hash_field(&mut digest, &self.adapter_registry_version);
        hash_field(&mut digest, self.adapter.adapter_id());
        hash_field(&mut digest, &self.adapter.adapter_version().to_string());
        hash_field(&mut digest, &self.credential_revision.to_string());
        hash_field(&mut digest, &self.lease_revision.to_string());
        hash_field(&mut digest, &self.auth_revision.to_string());
        hash_field(&mut digest, &self.probe_revision.to_string());
        hash_field(&mut digest, &self.provider_evidence_digest);
        hash_field(&mut digest, &self.provider_opaque_chain_digest);
        hash_time(&mut digest, self.provider_probe_expires_at);
        hash_field(&mut digest, &self.effect_approval_digest);
        hash_field(&mut digest, &self.payload_digest);
        hash_field(&mut digest, &self.policy_digest);
        hash_field(&mut digest, &self.permission_evidence_digest);
        hash_field(&mut digest, &self.permission_authorization_digest);
        hash_field(
            &mut digest,
            &self.approval_policy_validity_seconds.to_string(),
        );
        hash_time(&mut digest, self.effect_expires_at);
        hash_time(&mut digest, self.contract_expires_at);
        hash_field(&mut digest, self.human_issuer.issuer_id());
        hash_field(&mut digest, &self.human_issuer.issuer_version().to_string());
        hash_field(&mut digest, &self.actor_authorization_id);
        hash_field(&mut digest, &self.actor_authority_revision.to_string());
        hash_field(&mut digest, &self.actor_authorization_scope_digest);
        hash_field(
            &mut digest,
            human_assurance_name(self.actor_authorization_assurance),
        );
        hash_time(&mut digest, self.actor_authorization_expires_at);
        hash_field(&mut digest, &self.actor_session_id);
        hash_field(&mut digest, &self.actor_session_revision.to_string());
        hash_field(
            &mut digest,
            human_assurance_name(self.actor_session_assurance),
        );
        hash_field(&mut digest, &self.actor_session_evidence_digest);
        hash_time(&mut digest, self.actor_session_expires_at);
        hash_step_up_intent(&mut digest, &self.step_up_intent);
        format!("{:x}", digest.finalize())
    }

    fn validate_digest(&self) -> Result<(), ApprovalAuthorityError> {
        if !is_sha256(&self.request_digest) || self.request_digest != self.canonical_digest() {
            return Err(ApprovalAuthorityError::RequestDigestMismatch);
        }
        Ok(())
    }
}

impl ProviderApprovalAuthorityPolicy {
    pub fn prepare_request(
        &self,
        context: &ProviderEffectApprovalContext<'_>,
        approving_actor_id: ActorId,
        human: HumanApprovalRequestEvidence<'_>,
        provider: ProviderApprovalEvidence<'_>,
        requested_at: DateTime<Utc>,
    ) -> Result<ApprovalRequest, ApprovalAuthorityError> {
        self.validate()?;
        let connected = provider.authorize(requested_at)?;
        let adapter_registry = ProviderAdapterRegistry::contract_baseline()
            .map_err(|_| ApprovalAuthorityError::InvalidAdapterRegistry)?;
        self.prepare_request_against_registries(
            context,
            approving_actor_id,
            human,
            &connected,
            ApprovalRegistryView {
                adapter_registry: &adapter_registry,
                human_issuers: &self.human_operation_authority.issuer_registrations,
            },
            requested_at,
        )
    }

    fn prepare_request_against_registries(
        &self,
        context: &ProviderEffectApprovalContext<'_>,
        approving_actor_id: ActorId,
        human: HumanApprovalRequestEvidence<'_>,
        connected: &ConnectedApprovalBinding,
        registries: ApprovalRegistryView<'_>,
        requested_at: DateTime<Utc>,
    ) -> Result<ApprovalRequest, ApprovalAuthorityError> {
        let HumanApprovalRequestEvidence {
            actor_authorization,
            actor_session,
            step_up_intent,
        } = human;
        let effect = validate_effect_context(context, requested_at)?;
        validate_connected_for_effect(connected, effect, requested_at)?;
        let adapter_registry_version = validate_provider_capability_metadata(
            registries.adapter_registry,
            effect,
            &connected.adapter,
        )?;
        validate_human_request_evidence(&HumanRequestValidation {
            actor_authorization,
            actor_session,
            step_up_intent: step_up_intent.as_ref(),
            human_issuers: registries.human_issuers,
            effect,
            context,
            approving_actor_id: &approving_actor_id,
            requested_at,
        })?;
        let permission_evidence_digest = context.permission_evidence.digest(effect)?;
        let policy_digest = context.effect_policy.canonical_digest();
        let permission_authorization_digest = context
            .effect_policy
            .authorization_digest(&permission_evidence_digest);
        let connection_id = effect
            .connection_id
            .clone()
            .ok_or(ApprovalAuthorityError::ProviderScopeMismatch)?;
        let account_id = effect
            .account_id
            .clone()
            .ok_or(ApprovalAuthorityError::ProviderScopeMismatch)?;
        let mut request = ApprovalRequest {
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            operation_kind: HumanOperationKind::ApproveProviderEffect,
            decision: HumanOperationDecision::Approve,
            requested_at,
            tenant_id: effect.tenant_id.clone(),
            project_id: effect.project_id.clone(),
            mission_id: effect.mission_id.clone(),
            mission_revision: context.mission.revision,
            effect_id: effect.id.clone(),
            requesting_actor_id: effect.actor_id.clone(),
            approving_actor_id,
            connection_id,
            provider_id: effect.provider.clone(),
            account_id,
            capability_id: effect.capability.clone(),
            required_scopes: effect.required_scopes.clone(),
            leased_scopes: connected.leased_scopes.clone(),
            adapter_registry_version,
            adapter: connected.adapter.clone(),
            credential_revision: connected.credential_revision,
            lease_revision: connected.lease_revision,
            auth_revision: connected.auth_revision,
            probe_revision: connected.probe_revision,
            provider_evidence_digest: connected.evidence_digest.clone(),
            provider_opaque_chain_digest: connected.opaque_chain_digest.clone(),
            provider_probe_expires_at: connected.observed_valid_until,
            effect_approval_digest: effect.approval_digest(),
            payload_digest: effect.payload_digest.clone(),
            policy_digest,
            permission_evidence_digest,
            permission_authorization_digest,
            approval_policy_validity_seconds: context
                .mission
                .contract
                .approval_policy
                .validity_seconds,
            effect_expires_at: effect.expires_at,
            contract_expires_at: context.mission.contract.valid_until,
            human_issuer: actor_authorization.subject.issuer.clone(),
            actor_authorization_id: actor_authorization.authorization_id.clone(),
            actor_authority_revision: actor_authorization.subject.authority_revision,
            actor_authorization_scope_digest: actor_authorization.scope_digest.clone(),
            actor_authorization_assurance: actor_authorization.assurance,
            actor_authorization_expires_at: actor_authorization.window.expires_at,
            actor_session_id: actor_session.identity.session_id.clone(),
            actor_session_revision: actor_session.identity.session_revision,
            actor_session_assurance: actor_session.assurance,
            actor_session_evidence_digest: actor_session.evidence_digest.clone(),
            actor_session_expires_at: actor_session.window.expires_at,
            step_up_intent: *step_up_intent,
            request_digest: String::new(),
        };
        request.request_digest = request.canonical_digest();
        request.validate_digest()?;
        Ok(request)
    }

    pub fn issue(
        &self,
        request: Box<ApprovalRequest>,
        context: &ProviderEffectApprovalContext<'_>,
        human: HumanApprovalIssuanceEvidence<'_>,
        provider: ProviderApprovalEvidence<'_>,
        operation_at: DateTime<Utc>,
    ) -> Result<ApprovalAuthority, ApprovalAuthorityError> {
        self.validate()?;
        // This is deliberately re-run here, at the exact issuance timestamp.
        // A cached Connected projection is never accepted as approval evidence.
        let connected = provider.authorize(operation_at)?;
        let adapter_registry = ProviderAdapterRegistry::contract_baseline()
            .map_err(|_| ApprovalAuthorityError::InvalidAdapterRegistry)?;
        self.issue_against_registries(
            request,
            context,
            human,
            &connected,
            ApprovalRegistryView {
                adapter_registry: &adapter_registry,
                human_issuers: &self.human_operation_authority.issuer_registrations,
            },
            operation_at,
        )
    }

    fn issue_against_registries(
        &self,
        request: Box<ApprovalRequest>,
        context: &ProviderEffectApprovalContext<'_>,
        human: HumanApprovalIssuanceEvidence<'_>,
        connected: &ConnectedApprovalBinding,
        registries: ApprovalRegistryView<'_>,
        operation_at: DateTime<Utc>,
    ) -> Result<ApprovalAuthority, ApprovalAuthorityError> {
        let HumanApprovalIssuanceEvidence {
            actor_authorization,
            actor_session,
            step_up_assertion,
        } = human;
        request.validate_digest()?;
        if operation_at < request.requested_at {
            return Err(ApprovalAuthorityError::InvalidOperationTime);
        }
        let effect = validate_effect_context(context, operation_at)?;
        validate_connected_for_effect(connected, effect, operation_at)?;
        let registry_version = validate_provider_capability_metadata(
            registries.adapter_registry,
            effect,
            &connected.adapter,
        )?;
        validate_request_against_live_context(&LiveRequestValidation {
            policy: self,
            request: request.as_ref(),
            context,
            effect,
            connected,
            registry_version: &registry_version,
            actor_authorization,
            actor_session,
        })?;
        validate_human_chain(
            actor_authorization,
            actor_session,
            &request.step_up_intent,
            registries.human_issuers,
            effect,
            &request.approving_actor_id,
            operation_at,
        )?;
        validate_step_up_assertion(step_up_assertion.as_ref(), request.as_ref(), operation_at)?;

        let validity_seconds = i64::try_from(request.approval_policy_validity_seconds)
            .map_err(|_| ApprovalAuthorityError::InvalidApprovalDeadline)?;
        let approval_policy_deadline = operation_at
            .checked_add_signed(Duration::seconds(validity_seconds))
            .ok_or(ApprovalAuthorityError::InvalidApprovalDeadline)?;
        let approval_record_valid_until = [
            approval_policy_deadline,
            request.effect_expires_at,
            request.contract_expires_at,
            request.actor_authorization_expires_at,
            request.actor_session_expires_at,
            step_up_assertion.expires_at,
            connected.observed_valid_until,
        ]
        .into_iter()
        .min()
        .ok_or(ApprovalAuthorityError::InvalidApprovalDeadline)?;
        if validity_seconds <= 0 || approval_record_valid_until <= operation_at {
            return Err(ApprovalAuthorityError::InvalidApprovalDeadline);
        }
        let authority_digest = authority_digest(
            request.as_ref(),
            step_up_assertion.as_ref(),
            operation_at,
            approval_policy_deadline,
            approval_record_valid_until,
        );
        Ok(ApprovalAuthority {
            authority: ApprovalAuthorityKind::EffectApprovalRecordOnly,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            request_digest: request.request_digest,
            authority_digest,
            effect_approval_digest: request.effect_approval_digest,
            policy_digest: request.policy_digest,
            permission_authorization_digest: request.permission_authorization_digest,
            effect_id: request.effect_id,
            mission_revision: request.mission_revision,
            approving_actor_id: request.approving_actor_id,
            operation_at,
            approval_record_valid_until,
        })
    }
}

/// Sealed authority to record one exact Provider Effect approval.
///
/// It cannot be cloned or serialized, has no public constructor, and grants no
/// Provider execution authority. The only supported transition consumes it by
/// value into an [`ApprovalRecordAuthorization`].
///
/// ```compile_fail
/// use hartevo_effect_broker::{ApprovalAuthority, ConnectedAuthorization};
///
/// fn connected_is_not_approval(value: ConnectedAuthorization) -> ApprovalAuthority {
///     value.into()
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalAuthority;
/// use hartevo_domain_kernel::Approval;
///
/// fn authority_is_not_domain_approval(value: ApprovalAuthority) -> Approval {
///     value.into()
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::{ApprovalAuthority, ExecutionLease};
///
/// fn authority_is_not_execution(value: ApprovalAuthority) -> ExecutionLease {
///     value.into()
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalAuthority;
/// use hartevo_domain_kernel::{Receipt, Verification};
///
/// fn authority_is_neither_receipt_nor_verification(value: ApprovalAuthority) {
///     let _: Receipt = value.into();
///     let _: Verification = value.into();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalAuthority;
///
/// fn authority_is_not_cloneable(value: &ApprovalAuthority) {
///     let _: ApprovalAuthority = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalAuthority;
///
/// fn authority_is_not_serializable(value: &ApprovalAuthority) {
///     let _ = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalAuthority;
///
/// fn authority_is_not_deserializable() {
///     let _: ApprovalAuthority = serde_json::from_str("{}").unwrap();
/// }
/// ```
pub struct ApprovalAuthority {
    authority: ApprovalAuthorityKind,
    contract_version: String,
    contract_digest: String,
    request_digest: String,
    authority_digest: String,
    effect_approval_digest: String,
    policy_digest: String,
    permission_authorization_digest: String,
    effect_id: EffectId,
    mission_revision: u64,
    approving_actor_id: ActorId,
    operation_at: DateTime<Utc>,
    approval_record_valid_until: DateTime<Utc>,
}

impl ApprovalAuthority {
    pub const fn authority(&self) -> ApprovalAuthorityKind {
        ApprovalAuthorityKind::EffectApprovalRecordOnly
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }

    pub const fn approval_record_valid_until(&self) -> DateTime<Utc> {
        self.approval_record_valid_until
    }

    pub fn consume_for_approval_record(self) -> ApprovalRecordAuthorization {
        ApprovalRecordAuthorization {
            authority: self.authority,
            contract_version: self.contract_version,
            contract_digest: self.contract_digest,
            request_digest: self.request_digest,
            authority_digest: self.authority_digest,
            effect_approval_digest: self.effect_approval_digest,
            policy_digest: self.policy_digest,
            permission_authorization_digest: self.permission_authorization_digest,
            effect_id: self.effect_id,
            mission_revision: self.mission_revision,
            approving_actor_id: self.approving_actor_id,
            operation_at: self.operation_at,
            approval_record_valid_until: self.approval_record_valid_until,
        }
    }
}

impl fmt::Debug for ApprovalAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalAuthority")
            .field("authority", &self.authority)
            .field("request_digest", &short_digest(&self.request_digest))
            .field("authority_digest", &short_digest(&self.authority_digest))
            .field("mission_revision", &self.mission_revision)
            .field(
                "approval_record_valid_until",
                &self.approval_record_valid_until,
            )
            .finish_non_exhaustive()
    }
}

/// Consumed, record-only authorization for a future durable approval writer.
///
/// This remains distinct from the existing Domain `Approval`; the Core/Storage
/// cutover, durable single-use event, and execution-time CAS are later units.
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRecordAuthorization;
///
/// fn record_authorization_is_not_cloneable(value: &ApprovalRecordAuthorization) {
///     let _: ApprovalRecordAuthorization = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRecordAuthorization;
///
/// fn record_authorization_is_not_copyable(value: ApprovalRecordAuthorization) {
///     let first = value;
///     let second = value;
///     drop(first);
///     drop(second);
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRecordAuthorization;
///
/// fn record_authorization_is_not_serializable(value: &ApprovalRecordAuthorization) {
///     let _ = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRecordAuthorization;
///
/// fn record_authorization_is_not_deserializable() {
///     let _: ApprovalRecordAuthorization = serde_json::from_str("{}").unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRecordAuthorization;
///
/// fn caller_cannot_construct_record_authorization() {
///     let _ = ApprovalRecordAuthorization::new();
/// }
/// ```
///
/// ```compile_fail
/// use hartevo_effect_broker::ApprovalRecordAuthorization;
///
/// fn caller_cannot_populate_private_record_fields() {
///     let _ = ApprovalRecordAuthorization {
///         authority: todo!(),
///         contract_version: todo!(),
///         contract_digest: todo!(),
///         request_digest: todo!(),
///         authority_digest: todo!(),
///         effect_approval_digest: todo!(),
///         policy_digest: todo!(),
///         permission_authorization_digest: todo!(),
///         effect_id: todo!(),
///         mission_revision: todo!(),
///         approving_actor_id: todo!(),
///         operation_at: todo!(),
///         approval_record_valid_until: todo!(),
///     };
/// }
/// ```
pub struct ApprovalRecordAuthorization {
    authority: ApprovalAuthorityKind,
    contract_version: String,
    contract_digest: String,
    request_digest: String,
    authority_digest: String,
    effect_approval_digest: String,
    policy_digest: String,
    permission_authorization_digest: String,
    effect_id: EffectId,
    mission_revision: u64,
    approving_actor_id: ActorId,
    operation_at: DateTime<Utc>,
    approval_record_valid_until: DateTime<Utc>,
}

impl ApprovalRecordAuthorization {
    pub const fn authority(&self) -> ApprovalAuthorityKind {
        ApprovalAuthorityKind::EffectApprovalRecordOnly
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }

    pub fn effect_approval_digest(&self) -> &str {
        &self.effect_approval_digest
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn permission_authorization_digest(&self) -> &str {
        &self.permission_authorization_digest
    }

    pub const fn effect_id(&self) -> &EffectId {
        &self.effect_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn approving_actor_id(&self) -> &ActorId {
        &self.approving_actor_id
    }

    pub const fn operation_at(&self) -> DateTime<Utc> {
        self.operation_at
    }

    pub const fn approval_record_valid_until(&self) -> DateTime<Utc> {
        self.approval_record_valid_until
    }
}

impl fmt::Debug for ApprovalRecordAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalRecordAuthorization")
            .field("authority", &self.authority)
            .field("request_digest", &short_digest(&self.request_digest))
            .field("authority_digest", &short_digest(&self.authority_digest))
            .field("mission_revision", &self.mission_revision)
            .field(
                "approval_record_valid_until",
                &self.approval_record_valid_until,
            )
            .finish_non_exhaustive()
    }
}

fn validate_effect_context<'a>(
    context: &'a ProviderEffectApprovalContext<'_>,
    operation_at: DateTime<Utc>,
) -> Result<&'a Effect, ApprovalAuthorityError> {
    let effect = context
        .mission
        .effect(context.effect_id)
        .map_err(|_| ApprovalAuthorityError::UnknownEffect)?;
    if context.mission.revision == 0
        || effect.status != EffectStatus::Proposed
        || effect.tenant_id != context.mission.tenant_id
        || effect.project_id != context.mission.project_id
        || effect.mission_id != context.mission.id
        || effect.connection_id.is_none()
        || effect.account_id.is_none()
        || effect.required_scopes.is_empty()
        || operation_at >= effect.expires_at
        || operation_at >= context.mission.contract.valid_until
    {
        return Err(ApprovalAuthorityError::InvalidEffectScope);
    }
    context
        .effect_policy
        .permits(effect)
        .map_err(|error| ApprovalAuthorityError::EffectPolicy(error.to_string()))?;
    context.permission_evidence.validate_for_effect(effect)?;
    Ok(effect)
}

fn validate_connected_for_effect(
    connected: &ConnectedApprovalBinding,
    effect: &Effect,
    operation_at: DateTime<Utc>,
) -> Result<(), ApprovalAuthorityError> {
    connected.validate()?;
    let required_scopes = effect.required_scopes.iter().collect::<BTreeSet<_>>();
    let leased_scopes = connected.leased_scopes.iter().collect::<BTreeSet<_>>();
    if connected.tenant_id != effect.tenant_id
        || connected.project_id != effect.project_id
        || connected.provider_id != effect.provider
        || effect.account_id.as_ref() != Some(&connected.account_id)
        || !required_scopes.is_subset(&leased_scopes)
        || operation_at >= connected.observed_valid_until
    {
        return Err(ApprovalAuthorityError::ProviderScopeMismatch);
    }
    Ok(())
}

fn validate_provider_capability_metadata(
    registry: &ProviderAdapterRegistry,
    effect: &Effect,
    connected_adapter: &ProviderAdapterIdentity,
) -> Result<String, ApprovalAuthorityError> {
    registry
        .validate()
        .map_err(|_| ApprovalAuthorityError::InvalidAdapterRegistry)?;
    let key = ProviderCapabilityKey::new(effect.provider.clone(), effect.capability.clone())
        .map_err(|_| ApprovalAuthorityError::InvalidProviderCapabilityKey)?;
    let registration = registry
        .registrations()
        .iter()
        .find(|registration| registration.key() == &key)
        .ok_or(ApprovalAuthorityError::UnregisteredProviderCapability)?;
    if registration.adapter() != connected_adapter {
        return Err(ApprovalAuthorityError::ProviderAdapterMismatch);
    }
    Ok(registry.registry_version().to_owned())
}

struct HumanRequestValidation<'a, 'context> {
    actor_authorization: &'a HumanActorAuthorization,
    actor_session: &'a HumanActorSession,
    step_up_intent: &'a HumanStepUpIntent,
    human_issuers: &'a [HumanAuthorityIssuerRegistration],
    effect: &'a Effect,
    context: &'a ProviderEffectApprovalContext<'context>,
    approving_actor_id: &'a ActorId,
    requested_at: DateTime<Utc>,
}

fn validate_human_request_evidence(
    validation: &HumanRequestValidation<'_, '_>,
) -> Result<(), ApprovalAuthorityError> {
    validate_human_chain(
        validation.actor_authorization,
        validation.actor_session,
        validation.step_up_intent,
        validation.human_issuers,
        validation.effect,
        validation.approving_actor_id,
        validation.requested_at,
    )?;
    if validation.step_up_intent.exact_target_digest != validation.effect.approval_digest()
        || validation.step_up_intent.window.expires_at > validation.actor_session.window.expires_at
        || validation
            .context
            .mission
            .contract
            .approval_policy
            .validity_seconds
            == 0
    {
        return Err(ApprovalAuthorityError::StepUpTargetMismatch);
    }
    Ok(())
}

fn validate_human_chain(
    actor_authorization: &HumanActorAuthorization,
    actor_session: &HumanActorSession,
    step_up_intent: &HumanStepUpIntent,
    human_issuers: &[HumanAuthorityIssuerRegistration],
    effect: &Effect,
    approving_actor_id: &ActorId,
    operation_at: DateTime<Utc>,
) -> Result<(), ApprovalAuthorityError> {
    actor_authorization.validate_structure()?;
    actor_session.validate_structure()?;
    step_up_intent.validate_structure()?;
    let registration = human_issuers
        .iter()
        .find(|registration| registration.identity == actor_authorization.subject.issuer)
        .ok_or(ApprovalAuthorityError::UnregisteredHumanIssuer)?;
    registration.validate()?;
    if !registration
        .operation_kinds
        .contains(&HumanOperationKind::ApproveProviderEffect)
        || !registration
            .assurance_levels
            .contains(&actor_authorization.assurance)
        || !registration
            .assurance_levels
            .contains(&actor_session.assurance)
        || !registration
            .assurance_levels
            .contains(&step_up_intent.assurance)
    {
        return Err(ApprovalAuthorityError::HumanIssuerScopeMismatch);
    }
    actor_authorization
        .window
        .validate_live(actor_authorization.revoked_at, operation_at)?;
    actor_session
        .window
        .validate_live(actor_session.revoked_at, operation_at)?;
    step_up_intent.window.validate_live(None, operation_at)?;
    if actor_authorization.window.ttl_seconds()? > registration.max_actor_authorization_ttl_seconds
        || actor_session.window.ttl_seconds()? > registration.max_session_ttl_seconds
        || step_up_intent.window.ttl_seconds()? > registration.max_step_up_ttl_seconds
    {
        return Err(ApprovalAuthorityError::HumanEvidenceTtlExceeded);
    }
    let subject = &actor_authorization.subject;
    let expected_scope_digest = human_actor_scope_digest(effect, approving_actor_id);
    if subject.tenant_id != effect.tenant_id
        || subject.project_id != effect.project_id
        || &subject.actor_id != approving_actor_id
        || actor_session.subject != *subject
        || step_up_intent.subject != *subject
        || actor_session.identity.actor_authorization_id != actor_authorization.authorization_id
        || step_up_intent.session_identity != actor_session.identity
        || actor_session.window.expires_at > actor_authorization.window.expires_at
        || actor_session.assurance < actor_authorization.assurance
        || step_up_intent.assurance < actor_session.assurance
        || actor_authorization.scope_digest != expected_scope_digest
        || step_up_intent.exact_target_digest != effect.approval_digest()
    {
        return Err(ApprovalAuthorityError::HumanEvidenceScopeMismatch);
    }
    Ok(())
}

fn human_actor_scope_digest(effect: &Effect, approving_actor_id: &ActorId) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "hartevo-human-provider-approval-scope/v1");
    hash_field(&mut digest, effect.tenant_id.as_str());
    hash_field(&mut digest, effect.project_id.as_str());
    hash_field(&mut digest, effect.mission_id.as_str());
    hash_field(&mut digest, effect.id.as_str());
    hash_field(&mut digest, approving_actor_id.as_str());
    hash_field(
        &mut digest,
        human_operation_name(HumanOperationKind::ApproveProviderEffect),
    );
    hash_field(&mut digest, &effect.approval_digest());
    format!("{:x}", digest.finalize())
}

struct LiveRequestValidation<'a, 'context> {
    policy: &'a ProviderApprovalAuthorityPolicy,
    request: &'a ApprovalRequest,
    context: &'a ProviderEffectApprovalContext<'context>,
    effect: &'a Effect,
    connected: &'a ConnectedApprovalBinding,
    registry_version: &'a str,
    actor_authorization: &'a HumanActorAuthorization,
    actor_session: &'a HumanActorSession,
}

fn validate_request_against_live_context(
    live: &LiveRequestValidation<'_, '_>,
) -> Result<(), ApprovalAuthorityError> {
    let policy = live.policy;
    let request = live.request;
    let context = live.context;
    let effect = live.effect;
    let connected = live.connected;
    let registry_version = live.registry_version;
    let actor_authorization = live.actor_authorization;
    let actor_session = live.actor_session;
    let permission_evidence_digest = context.permission_evidence.digest(effect)?;
    let policy_digest = context.effect_policy.canonical_digest();
    let permission_authorization_digest = context
        .effect_policy
        .authorization_digest(&permission_evidence_digest);
    let connection_matches = effect.connection_id.as_ref() == Some(&request.connection_id);
    let account_matches = effect.account_id.as_ref() == Some(&request.account_id);
    if request.contract_version != policy.contract_version
        || request.contract_digest != policy.contract_digest
        || request.operation_kind != HumanOperationKind::ApproveProviderEffect
        || request.decision != HumanOperationDecision::Approve
        || request.tenant_id != effect.tenant_id
        || request.project_id != effect.project_id
        || request.mission_id != effect.mission_id
        || request.mission_revision != context.mission.revision
        || request.effect_id != effect.id
        || request.requesting_actor_id != effect.actor_id
        || &request.approving_actor_id != actor_authorization.subject.actor_id()
        || !connection_matches
        || request.provider_id != effect.provider
        || !account_matches
        || request.capability_id != effect.capability
        || request.required_scopes != effect.required_scopes
        || request.leased_scopes != connected.leased_scopes
        || request.adapter_registry_version != registry_version
        || request.adapter != connected.adapter
        || request.credential_revision != connected.credential_revision
        || request.lease_revision != connected.lease_revision
        || request.auth_revision != connected.auth_revision
        || request.probe_revision != connected.probe_revision
        || request.provider_evidence_digest != connected.evidence_digest
        || request.provider_opaque_chain_digest != connected.opaque_chain_digest
        || request.provider_probe_expires_at != connected.observed_valid_until
        || request.effect_approval_digest != effect.approval_digest()
        || request.payload_digest != effect.payload_digest
        || request.policy_digest != policy_digest
        || request.permission_evidence_digest != permission_evidence_digest
        || request.permission_authorization_digest != permission_authorization_digest
        || request.approval_policy_validity_seconds
            != context.mission.contract.approval_policy.validity_seconds
        || request.effect_expires_at != effect.expires_at
        || request.contract_expires_at != context.mission.contract.valid_until
        || request.human_issuer != actor_authorization.subject.issuer
        || request.actor_authorization_id != actor_authorization.authorization_id
        || request.actor_authority_revision != actor_authorization.subject.authority_revision
        || request.actor_authorization_scope_digest != actor_authorization.scope_digest
        || request.actor_authorization_assurance != actor_authorization.assurance
        || request.actor_authorization_expires_at != actor_authorization.window.expires_at
        || request.actor_session_id != actor_session.identity.session_id
        || request.actor_session_revision != actor_session.identity.session_revision
        || request.actor_session_assurance != actor_session.assurance
        || request.actor_session_evidence_digest != actor_session.evidence_digest
        || request.actor_session_expires_at != actor_session.window.expires_at
    {
        return Err(ApprovalAuthorityError::RequestContextChanged);
    }
    request.validate_digest()
}

fn validate_step_up_assertion(
    assertion: &RequestBoundStepUpAssertion,
    request: &ApprovalRequest,
    operation_at: DateTime<Utc>,
) -> Result<(), ApprovalAuthorityError> {
    assertion.validate_structure()?;
    if assertion
        .revoked_at
        .is_some_and(|revoked| revoked <= operation_at)
        || operation_at < assertion.verified_at
        || operation_at >= assertion.expires_at
        || assertion.verified_at < request.step_up_intent.window.issued_at
        || assertion.verified_at < request.requested_at
        || assertion.intent_id != request.step_up_intent.identity.intent_id
        || assertion.intent_revision != request.step_up_intent.identity.intent_revision
        || assertion.issuer != request.human_issuer
        || assertion.actor_id != request.approving_actor_id
        || assertion.session_id != request.actor_session_id
        || assertion.session_revision != request.actor_session_revision
        || assertion.request_digest != request.request_digest
        || assertion.expires_at != request.step_up_intent.window.expires_at
    {
        return Err(ApprovalAuthorityError::StepUpAssertionMismatch);
    }
    Ok(())
}

fn authority_digest(
    request: &ApprovalRequest,
    assertion: &RequestBoundStepUpAssertion,
    operation_at: DateTime<Utc>,
    approval_policy_deadline: DateTime<Utc>,
    approval_record_valid_until: DateTime<Utc>,
) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "hartevo-provider-approval-authority/v1");
    hash_field(&mut digest, &request.request_digest);
    hash_field(&mut digest, &assertion.assertion_id);
    hash_field(&mut digest, &assertion.evidence_digest);
    hash_time(&mut digest, assertion.verified_at);
    hash_time(&mut digest, assertion.expires_at);
    hash_time(&mut digest, operation_at);
    hash_time(&mut digest, approval_policy_deadline);
    hash_time(&mut digest, approval_record_valid_until);
    format!("{:x}", digest.finalize())
}

fn hash_step_up_intent(digest: &mut Sha256, intent: &HumanStepUpIntent) {
    hash_field(digest, &intent.identity.intent_id);
    hash_field(digest, &intent.identity.intent_revision.to_string());
    hash_field(digest, intent.subject.tenant_id.as_str());
    hash_field(digest, intent.subject.project_id.as_str());
    hash_field(digest, intent.subject.actor_id.as_str());
    hash_field(digest, intent.subject.issuer.issuer_id());
    hash_field(digest, &intent.subject.issuer.issuer_version().to_string());
    hash_field(digest, &intent.subject.authority_revision.to_string());
    hash_field(digest, &intent.session_identity.session_id);
    hash_field(
        digest,
        &intent.session_identity.session_revision.to_string(),
    );
    hash_field(digest, human_operation_name(intent.operation_kind));
    hash_field(digest, human_decision_name(intent.decision));
    hash_field(digest, step_up_method_name(intent.method));
    hash_field(digest, human_assurance_name(intent.assurance));
    hash_field(digest, &intent.exact_target_digest);
    hash_time(digest, intent.window.issued_at);
    hash_time(digest, intent.window.expires_at);
}

fn human_operation_name(value: HumanOperationKind) -> &'static str {
    match value {
        HumanOperationKind::ApproveProviderEffect => "approve_provider_effect",
    }
}

fn human_decision_name(value: HumanOperationDecision) -> &'static str {
    match value {
        HumanOperationDecision::Approve => "approve",
    }
}

fn human_assurance_name(value: HumanAssuranceLevel) -> &'static str {
    match value {
        HumanAssuranceLevel::Reauthenticated => "reauthenticated",
        HumanAssuranceLevel::MultiFactor => "multi_factor",
        HumanAssuranceLevel::HardwareBound => "hardware_bound",
    }
}

fn step_up_method_name(value: HumanStepUpMethod) -> &'static str {
    match value {
        HumanStepUpMethod::PasswordReauthentication => "password_reauthentication",
        HumanStepUpMethod::Totp => "totp",
        HumanStepUpMethod::Webauthn => "webauthn",
        HumanStepUpMethod::PlatformBiometric => "platform_biometric",
    }
}

fn hash_time(digest: &mut Sha256, value: DateTime<Utc>) {
    hash_field(digest, &value.to_rfc3339());
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_be_bytes());
    digest.update(value.as_bytes());
}

fn digest_json(value: &impl Serialize) -> Result<String, ApprovalAuthorityError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| ApprovalAuthorityError::InvalidContractDocument)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_exact_set<T>(
    actual: &[T],
    expected: &[T],
    label: &'static str,
) -> Result<(), ApprovalAuthorityError>
where
    T: Ord,
{
    let actual_set = actual.iter().collect::<BTreeSet<_>>();
    let expected_set = expected.iter().collect::<BTreeSet<_>>();
    if actual_set.len() != actual.len() {
        return Err(ApprovalAuthorityError::DuplicateContractValue(label));
    }
    if actual_set != expected_set {
        return Err(ApprovalAuthorityError::ContractSetMismatch(label));
    }
    Ok(())
}

fn validate_nonempty_unique_subset<T>(
    actual: &[T],
    allowed: &[T],
    label: &'static str,
) -> Result<(), ApprovalAuthorityError>
where
    T: Ord,
{
    if actual.is_empty() {
        return Err(ApprovalAuthorityError::ContractSetMismatch(label));
    }
    let actual_set = actual.iter().collect::<BTreeSet<_>>();
    let allowed_set = allowed.iter().collect::<BTreeSet<_>>();
    if actual_set.len() != actual.len() {
        return Err(ApprovalAuthorityError::DuplicateContractValue(label));
    }
    if !actual_set.is_subset(&allowed_set) {
        return Err(ApprovalAuthorityError::ContractSetMismatch(label));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn short_digest(value: &str) -> &str {
    value.get(..12).unwrap_or("[invalid]")
}

fn valid_namespaced_id(value: &str) -> bool {
    let len = value.len();
    (2..=96).contains(&len)
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
        })
}

fn valid_opaque_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[derive(Error)]
pub enum ApprovalAuthorityError {
    #[error("Provider approval authority contract JSON is malformed or incomplete")]
    InvalidContractDocument,
    #[error("Provider approval authority contract version/digest closure is invalid")]
    InvalidProviderContractClosure,
    #[error("human operation authority contract version/digest closure is invalid")]
    InvalidHumanContractClosure,
    #[error("Provider auth/probe contract reference is invalid")]
    InvalidProviderAuthClosure,
    #[error("approval authority boundary is invalid")]
    InvalidAuthorityBoundary,
    #[error("human operation authority boundary is invalid")]
    InvalidHumanAuthorityBoundary,
    #[error("contract repeats a value in {0}")]
    DuplicateContractValue(&'static str),
    #[error("contract does not declare the exact {0} set")]
    ContractSetMismatch(&'static str),
    #[error("human authority issuer identity is invalid")]
    InvalidHumanIssuer,
    #[error("human authority subject is invalid")]
    InvalidHumanSubject,
    #[error("human evidence window is invalid")]
    InvalidHumanEvidenceWindow,
    #[error("human actor authorization is invalid")]
    InvalidActorAuthorization,
    #[error("human actor session is invalid")]
    InvalidActorSession,
    #[error("step-up intent is invalid")]
    InvalidStepUpIntent,
    #[error("step-up assertion is invalid")]
    InvalidStepUpAssertion,
    #[error("revocation timestamp is invalid")]
    InvalidRevocation,
    #[error("evidence was already revoked at another time")]
    AlreadyRevoked,
    #[error("human authority issuer is not registered")]
    UnregisteredHumanIssuer,
    #[error("human authority issuer does not support this operation or assurance")]
    HumanIssuerScopeMismatch,
    #[error("human evidence is stale or revoked")]
    HumanEvidenceStaleOrRevoked,
    #[error("human evidence TTL exceeds the registered issuer boundary")]
    HumanEvidenceTtlExceeded,
    #[error("human actor/session/step-up scope or revision does not match")]
    HumanEvidenceScopeMismatch,
    #[error("step-up intent does not bind the exact Effect target")]
    StepUpTargetMismatch,
    #[error("step-up assertion does not bind the exact approval request")]
    StepUpAssertionMismatch,
    #[error("Provider auth/probe validation failed: {0}")]
    ProviderAuth(#[from] ProviderAuthProbeError),
    #[error("Provider adapter registry is invalid")]
    InvalidAdapterRegistry,
    #[error("Provider/capability key is invalid")]
    InvalidProviderCapabilityKey,
    #[error("Provider/capability is not registered")]
    UnregisteredProviderCapability,
    #[error("Provider capability metadata names another adapter identity/version")]
    ProviderAdapterMismatch,
    #[error("Provider auth/probe binding does not match the exact Effect scope")]
    ProviderScopeMismatch,
    #[error("Provider auth/probe binding is invalid")]
    InvalidProviderBinding,
    #[error("Effect is missing, stale, already decided, expired, or not Provider scoped")]
    InvalidEffectScope,
    #[error("Effect was not found in the owning Mission")]
    UnknownEffect,
    #[error("Effect policy rejected approval preparation: {0}")]
    EffectPolicy(String),
    #[error("permission evidence rejected approval preparation: {0}")]
    PermissionEvidence(String),
    #[error("approval request digest was modified")]
    RequestDigestMismatch,
    #[error("live Mission/Effect/Policy/Permission/A2 context changed after the request")]
    RequestContextChanged,
    #[error("approval operation time is before the request")]
    InvalidOperationTime,
    #[error("approval record deadline is invalid or not strictly after operation_at")]
    InvalidApprovalDeadline,
}

impl fmt::Debug for ApprovalAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalAuthorityError(redacted)")
    }
}

impl From<crate::PermissionFailure> for ApprovalAuthorityError {
    fn from(error: crate::PermissionFailure) -> Self {
        Self::PermissionEvidence(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        CurrencyCode, EffectClass, EffectRisk, EffectSpec, MissionContract, Money,
    };
    use proptest::prelude::*;
    use serde_json::{Value, json};

    use super::*;
    use crate::provider_auth::{ProbeObservation, ProbeStatus, ProviderAuthScope};
    use crate::provider_contract::{
        ProviderAdapterOperation, ProviderCapabilitySupport, ProviderEvidenceClass,
        ProviderEvidenceSupport, ProviderProvenanceClass,
    };
    use crate::{EffectRateLimit, PermissionFence};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("valid test time")
    }

    struct SyntheticState {
        mission: Mission,
        effect_id: EffectId,
        effect_policy: EffectPolicy,
        permission_evidence: PermissionEvidence,
        actor_authorization: HumanActorAuthorization,
        actor_session: HumanActorSession,
        connected: ConnectedApprovalBinding,
        adapter_registry: ProviderAdapterRegistry,
        human_issuers: Vec<HumanAuthorityIssuerRegistration>,
    }

    fn synthetic_state() -> SyntheticState {
        let (mission, effect_id) = synthetic_mission();
        let effect_policy = synthetic_effect_policy();
        let permission_evidence = synthetic_permission_evidence();
        let (connected, adapter_registry) = synthetic_provider_registry();
        let (actor_authorization, actor_session, human_issuers) =
            synthetic_human_authority(&mission, &effect_id);
        SyntheticState {
            mission,
            effect_id,
            effect_policy,
            permission_evidence,
            actor_authorization,
            actor_session,
            connected,
            adapter_registry,
            human_issuers,
        }
    }

    fn synthetic_mission() -> (Mission, EffectId) {
        let mut contract = MissionContract::bootstrap(
            "Approve an exact Provider effect",
            ["channel.preview".into()],
            now(),
        );
        contract.approval_policy.validity_seconds = 60;
        let mut mission = Mission::compile(
            TenantId::from("tenant-a3"),
            MissionId::from("mission-a3"),
            ProjectId::from("project-a3"),
            "Provider approval",
            contract,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("start mission");
        let effect_id = mission
            .propose_effect(
                EffectSpec {
                    id: EffectId::from("effect-a3"),
                    actor_id: ActorId::from("requesting-actor-a3"),
                    capability: "channel.preview".into(),
                    provider: "fixture-provider".into(),
                    connection_id: Some(ConnectionId::from("connection-a3")),
                    account_id: Some(AccountId::from("account-a3")),
                    required_scopes: BTreeSet::from(["preview.publish".into()]),
                    effect_class: EffectClass::ExternalWrite,
                    description: "Publish exact preview".into(),
                    target_resource: "preview/a3".into(),
                    audience_digest: Some("b".repeat(64)),
                    payload_digest: "a".repeat(64),
                    asset_digests: BTreeSet::from(["c".repeat(64)]),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent: hartevo_domain_kernel::ConsentState::NotRequired,
                    consent_record_id: None,
                    consent_requirement: None,
                    conversation_guard: None,
                    creator_contact_guard: None,
                    policy_version: "policy-a3-v1".into(),
                    risk: EffectRisk::Low,
                    idempotency_key: "mission-a3:effect-a3:v1".into(),
                    amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                    expires_at: now() + Duration::hours(1),
                },
                now(),
            )
            .expect("effect");
        (mission, effect_id)
    }

    fn synthetic_effect_policy() -> EffectPolicy {
        EffectPolicy {
            version: "policy-a3-v1".into(),
            allowed_capabilities: BTreeSet::from(["channel.preview".into()]),
            allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
            max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("USD").expect("USD"), 0)]),
            rate_limits: vec![EffectRateLimit {
                rule_id: "fixture-preview-per-minute".into(),
                provider: "fixture-provider".into(),
                capability: "channel.preview".into(),
                max_executions: 1,
                window_seconds: 60,
            }],
        }
    }

    fn synthetic_permission_evidence() -> PermissionEvidence {
        PermissionEvidence {
            connection_evidence_digest: Some("d".repeat(64)),
            consent_evidence_digest: None,
            conversation_evidence_digest: None,
            creator_contact_evidence_digest: None,
            fences: BTreeSet::from([PermissionFence::Connection {
                connection_id: ConnectionId::from("connection-a3"),
                revision: 7,
            }]),
        }
    }

    fn synthetic_provider_registry() -> (ConnectedApprovalBinding, ProviderAdapterRegistry) {
        let adapter = ProviderAdapterIdentity::new("adapter.fixture", 3).expect("adapter");
        let connected = ConnectedApprovalBinding {
            tenant_id: TenantId::from("tenant-a3"),
            project_id: ProjectId::from("project-a3"),
            provider_id: "fixture-provider".into(),
            account_id: AccountId::from("account-a3"),
            leased_scopes: vec!["preview.publish".into()],
            adapter: adapter.clone(),
            credential_revision: 11,
            lease_revision: 12,
            auth_revision: 13,
            probe_revision: 14,
            evidence_digest: "e".repeat(64),
            opaque_chain_digest: "f".repeat(64),
            observed_valid_until: now() + Duration::seconds(90),
        };
        let support = ProviderEvidenceSupport::new(
            ProviderAdapterOperation::PrepareEffect,
            ProviderEvidenceClass::PreparedEffect,
            ProviderProvenanceClass::ProductionProvider,
        )
        .expect("support");
        let registration = ProviderCapabilitySupport::new(
            ProviderCapabilityKey::new("fixture-provider", "channel.preview").expect("key"),
            adapter,
            [support],
        )
        .expect("registration");
        let adapter_registry =
            ProviderAdapterRegistry::new("synthetic-a3-registry-v1", [registration])
                .expect("registry");
        (connected, adapter_registry)
    }

    fn synthetic_human_authority(
        mission: &Mission,
        effect_id: &EffectId,
    ) -> (
        HumanActorAuthorization,
        HumanActorSession,
        Vec<HumanAuthorityIssuerRegistration>,
    ) {
        let issuer = HumanAuthorityIssuerIdentity::new("human.fixture", 2).expect("issuer");
        let subject = HumanAuthoritySubject::new(
            TenantId::from("tenant-a3"),
            ProjectId::from("project-a3"),
            ActorId::from("approving-actor-a3"),
            issuer.clone(),
            21,
        )
        .expect("subject");
        let scope_digest = human_actor_scope_digest(
            mission.effect(effect_id).expect("effect"),
            subject.actor_id(),
        );
        let actor_authorization = HumanActorAuthorization::new(
            "human-authorization-a3",
            subject.clone(),
            HumanOperationKind::ApproveProviderEffect,
            scope_digest,
            HumanAssuranceLevel::MultiFactor,
            HumanEvidenceWindow::new(now() - Duration::minutes(1), now() + Duration::minutes(10))
                .expect("actor window"),
        )
        .expect("actor authorization");
        let actor_session = HumanActorSession::new(
            HumanSessionIdentity::new(
                "human-session-a3",
                actor_authorization.authorization_id(),
                22,
            )
            .expect("session identity"),
            subject,
            HumanAssuranceLevel::MultiFactor,
            now() - Duration::seconds(40),
            HumanEvidenceWindow::new(now() - Duration::seconds(30), now() + Duration::minutes(5))
                .expect("session window"),
            "1".repeat(64),
        )
        .expect("actor session");
        let human_issuers = vec![HumanAuthorityIssuerRegistration {
            identity: issuer,
            operation_kinds: vec![HumanOperationKind::ApproveProviderEffect],
            assurance_levels: HumanAssuranceLevel::ALL.to_vec(),
            max_actor_authorization_ttl_seconds: 900,
            max_session_ttl_seconds: 600,
            max_step_up_ttl_seconds: 300,
        }];
        (actor_authorization, actor_session, human_issuers)
    }

    fn synthetic_request(
        policy: &ProviderApprovalAuthorityPolicy,
        state: &SyntheticState,
    ) -> ApprovalRequest {
        let target_digest = state
            .mission
            .effect(&state.effect_id)
            .expect("effect")
            .approval_digest();
        let intent = HumanStepUpIntent::new(
            HumanStepUpIntentIdentity::new("step-up-intent-a3", 23).expect("intent identity"),
            &state.actor_session,
            HumanStepUpMethod::Webauthn,
            HumanAssuranceLevel::HardwareBound,
            target_digest,
            HumanEvidenceWindow::new(now() - Duration::seconds(5), now() + Duration::seconds(80))
                .expect("intent window"),
        )
        .expect("intent");
        policy
            .prepare_request_against_registries(
                &ProviderEffectApprovalContext::new(
                    &state.mission,
                    &state.effect_id,
                    &state.effect_policy,
                    &state.permission_evidence,
                ),
                ActorId::from("approving-actor-a3"),
                HumanApprovalRequestEvidence::new(
                    &state.actor_authorization,
                    &state.actor_session,
                    intent,
                ),
                &state.connected,
                ApprovalRegistryView {
                    adapter_registry: &state.adapter_registry,
                    human_issuers: &state.human_issuers,
                },
                now(),
            )
            .expect("synthetic request")
    }

    fn issue_synthetic(
        policy: &ProviderApprovalAuthorityPolicy,
        state: &SyntheticState,
        request: ApprovalRequest,
        operation_at: DateTime<Utc>,
    ) -> Result<ApprovalAuthority, ApprovalAuthorityError> {
        let assertion = RequestBoundStepUpAssertion::new(
            "step-up-assertion-a3",
            &request,
            now() + Duration::seconds(1),
            "2".repeat(64),
        )?;
        issue_synthetic_with_assertion(policy, state, request, assertion, operation_at)
    }

    fn issue_synthetic_with_assertion(
        policy: &ProviderApprovalAuthorityPolicy,
        state: &SyntheticState,
        request: ApprovalRequest,
        assertion: RequestBoundStepUpAssertion,
        operation_at: DateTime<Utc>,
    ) -> Result<ApprovalAuthority, ApprovalAuthorityError> {
        policy.issue_against_registries(
            Box::new(request),
            &ProviderEffectApprovalContext::new(
                &state.mission,
                &state.effect_id,
                &state.effect_policy,
                &state.permission_evidence,
            ),
            HumanApprovalIssuanceEvidence::new(
                &state.actor_authorization,
                &state.actor_session,
                assertion,
            ),
            &state.connected,
            ApprovalRegistryView {
                adapter_registry: &state.adapter_registry,
                human_issuers: &state.human_issuers,
            },
            operation_at,
        )
    }

    #[test]
    fn checked_in_contract_fully_parses_and_closes_embedded_human_digest() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        assert_eq!(
            policy.authority(),
            ApprovalAuthorityKind::EffectApprovalRecordOnly
        );
        assert!(
            policy
                .human_operation_authority
                .issuer_registrations
                .is_empty()
        );
        assert_eq!(
            policy.contract_digest(),
            policy.canonical_digest().expect("digest")
        );
        assert_eq!(
            policy.human_operation_authority.contract_digest,
            policy
                .human_operation_authority
                .canonical_digest()
                .expect("human digest")
        );
        assert_eq!(
            policy.human_operation_authority_reference.contract_digest,
            policy.human_operation_authority.contract_digest
        );
    }

    #[test]
    fn unknown_missing_and_registered_issuer_json_fail_closed() {
        let baseline: Value =
            serde_json::from_str(PROVIDER_APPROVAL_AUTHORITY_CONTRACT_JSON).expect("JSON");
        let mutations = [
            json!({"unexpected": true}),
            json!({"humanOperationAuthority": {"unexpected": true}}),
        ];
        for insertion in mutations {
            let mut candidate = baseline.clone();
            if insertion.get("humanOperationAuthority").is_some() {
                candidate["humanOperationAuthority"]["unexpected"] = json!(true);
            } else {
                candidate["unexpected"] = json!(true);
            }
            assert_contract_rejected(&candidate);
        }
        let mut missing = baseline.clone();
        missing
            .as_object_mut()
            .expect("object")
            .remove("requiredBindings");
        assert_contract_rejected(&missing);
        let mut registration = baseline;
        registration["humanOperationAuthority"]["issuerRegistrations"] = json!([{
            "identity": {"issuerId": "human.fixture", "issuerVersion": 1},
            "operationKinds": ["approve_provider_effect"],
            "assuranceLevels": ["multi_factor"],
            "maxActorAuthorizationTtlSeconds": 300,
            "maxSessionTtlSeconds": 200,
            "maxStepUpTtlSeconds": 100
        }]);
        assert_contract_rejected(&registration);
    }

    #[test]
    fn contract_version_reference_set_and_digest_tamper_fail_closed() {
        let baseline: Value =
            serde_json::from_str(PROVIDER_APPROVAL_AUTHORITY_CONTRACT_JSON).expect("JSON");
        let paths = [
            "/schemaVersion",
            "/contractVersion",
            "/contractDigest",
            "/authority",
            "/secretMaterial",
            "/decision",
            "/humanOperationAuthority/contractVersion",
            "/humanOperationAuthority/contractDigest",
            "/humanOperationAuthorityReference/contractDigest",
            "/providerAdapterContract/contractVersion",
            "/providerAuthProbeContract/contractVersion",
            "/requiredBindings/0",
            "/deadlineSources/0",
            "/forbiddenAuthorities/0",
        ];
        for path in paths {
            let mut candidate = baseline.clone();
            *candidate.pointer_mut(path).expect("path") = json!("tampered");
            assert_contract_rejected(&candidate);
        }
    }

    #[test]
    fn duplicate_and_missing_typed_sets_fail_even_with_refreshed_digests() {
        let mut duplicate = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        duplicate
            .required_bindings
            .push(RequiredApprovalBinding::ActorAuthorization);
        refresh_contract_digests(&mut duplicate);
        assert!(matches!(
            duplicate.validate(),
            Err(ApprovalAuthorityError::DuplicateContractValue(_))
        ));

        let mut missing = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        missing.deadline_sources.pop();
        refresh_contract_digests(&mut missing);
        assert!(matches!(
            missing.validate(),
            Err(ApprovalAuthorityError::ContractSetMismatch(_))
        ));

        let mut human_duplicate =
            ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        human_duplicate
            .human_operation_authority
            .assurance_levels
            .push(HumanAssuranceLevel::MultiFactor);
        refresh_contract_digests(&mut human_duplicate);
        assert!(matches!(
            human_duplicate.validate(),
            Err(ApprovalAuthorityError::DuplicateContractValue(_))
        ));
    }

    #[test]
    fn checked_in_empty_provider_registry_keeps_public_positive_path_unreachable() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let adapter_registry = ProviderAdapterRegistry::contract_baseline().expect("A1 registry");
        assert!(adapter_registry.is_empty());
        assert!(
            policy
                .human_operation_authority
                .issuer_registrations
                .is_empty()
        );
        let state = synthetic_state();
        let intent = HumanStepUpIntent::new(
            HumanStepUpIntentIdentity::new("step-up-intent-public", 1).expect("identity"),
            &state.actor_session,
            HumanStepUpMethod::Webauthn,
            HumanAssuranceLevel::HardwareBound,
            state
                .mission
                .effect(&state.effect_id)
                .expect("effect")
                .approval_digest(),
            HumanEvidenceWindow::new(now(), now() + Duration::seconds(30)).expect("window"),
        )
        .expect("intent");
        let (auth_policy, secret, lease, auth_session, probe) = live_a2_chain();
        let result = policy.prepare_request(
            &ProviderEffectApprovalContext::new(
                &state.mission,
                &state.effect_id,
                &state.effect_policy,
                &state.permission_evidence,
            ),
            ActorId::from("approving-actor-a3"),
            HumanApprovalRequestEvidence::new(
                &state.actor_authorization,
                &state.actor_session,
                intent,
            ),
            ProviderApprovalEvidence::new(&auth_policy, &secret, &lease, &auth_session, &probe),
            now(),
        );
        assert!(matches!(
            result,
            Err(ApprovalAuthorityError::ProviderAuth(
                ProviderAuthProbeError::UnknownAdapter
            ))
        ));
    }

    #[test]
    fn checked_in_empty_registries_also_keep_public_issue_unreachable() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let state = synthetic_state();
        let request = synthetic_request(&policy, &state);
        let assertion = RequestBoundStepUpAssertion::new(
            "step-up-assertion-public",
            &request,
            now() + Duration::seconds(1),
            "2".repeat(64),
        )
        .expect("assertion");
        let (auth_policy, secret, lease, auth_session, probe) = live_a2_chain();
        let result = policy.issue(
            Box::new(request),
            &ProviderEffectApprovalContext::new(
                &state.mission,
                &state.effect_id,
                &state.effect_policy,
                &state.permission_evidence,
            ),
            HumanApprovalIssuanceEvidence::new(
                &state.actor_authorization,
                &state.actor_session,
                assertion,
            ),
            ProviderApprovalEvidence::new(&auth_policy, &secret, &lease, &auth_session, &probe),
            now() + Duration::seconds(2),
        );
        assert!(matches!(
            result,
            Err(ApprovalAuthorityError::ProviderAuth(
                ProviderAuthProbeError::UnknownAdapter
            ))
        ));
    }

    #[test]
    fn private_synthetic_path_issues_only_record_authority_and_consumes_by_value() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let state = synthetic_state();
        let request = synthetic_request(&policy, &state);
        let authority = issue_synthetic(&policy, &state, request, now() + Duration::seconds(2))
            .expect("synthetic authority");
        assert_eq!(
            authority.authority(),
            ApprovalAuthorityKind::EffectApprovalRecordOnly
        );
        assert_eq!(
            authority.approval_record_valid_until(),
            now() + Duration::seconds(62)
        );
        let record = authority.consume_for_approval_record();
        assert_eq!(record.effect_id(), &state.effect_id);
        assert_eq!(record.mission_revision(), state.mission.revision);
        assert!(is_sha256(record.request_digest()));
        assert!(is_sha256(record.authority_digest()));
    }

    #[test]
    fn record_writer_getters_match_the_same_validated_live_context() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let state = synthetic_state();
        let effect = state.mission.effect(&state.effect_id).expect("effect");
        let expected_effect_approval_digest = effect.approval_digest();
        let expected_policy_digest = state.effect_policy.canonical_digest();
        let permission_evidence_digest = state
            .permission_evidence
            .digest(effect)
            .expect("permission evidence");
        let expected_permission_authorization_digest = state
            .effect_policy
            .authorization_digest(&permission_evidence_digest);
        let request = synthetic_request(&policy, &state);
        assert_eq!(
            request.effect_approval_digest,
            expected_effect_approval_digest
        );
        assert_eq!(request.policy_digest, expected_policy_digest);
        assert_eq!(
            request.permission_authorization_digest,
            expected_permission_authorization_digest
        );

        let authority = issue_synthetic(&policy, &state, request, now() + Duration::seconds(2))
            .expect("synthetic authority");
        let record = authority.consume_for_approval_record();
        assert_eq!(
            record.effect_approval_digest(),
            expected_effect_approval_digest
        );
        assert_eq!(record.policy_digest(), expected_policy_digest);
        assert_eq!(
            record.permission_authorization_digest(),
            expected_permission_authorization_digest
        );
        let debug = format!("{record:?}");
        assert!(!debug.contains(record.effect_approval_digest()));
        assert!(!debug.contains(record.policy_digest()));
        assert!(!debug.contains(record.permission_authorization_digest()));
    }

    #[test]
    fn record_writer_field_drift_changes_both_digests_and_fails_live_closure() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let state = synthetic_state();
        let operation_at = now() + Duration::seconds(2);
        let approval_policy_deadline = operation_at + Duration::seconds(60);
        let approval_record_valid_until = approval_policy_deadline;
        let baseline_request = synthetic_request(&policy, &state);
        let baseline_assertion = RequestBoundStepUpAssertion::new(
            "step-up-assertion-field-binding",
            &baseline_request,
            now() + Duration::seconds(1),
            "2".repeat(64),
        )
        .expect("baseline assertion");
        let baseline_request_digest = baseline_request.request_digest.clone();
        let baseline_authority_digest = authority_digest(
            &baseline_request,
            &baseline_assertion,
            operation_at,
            approval_policy_deadline,
            approval_record_valid_until,
        );

        for field in 0..3 {
            let mut changed_request = synthetic_request(&policy, &state);
            tamper_record_writer_field(&mut changed_request, field);
            changed_request.request_digest = changed_request.canonical_digest();
            assert_ne!(changed_request.request_digest, baseline_request_digest);
            let changed_assertion = RequestBoundStepUpAssertion::new(
                "step-up-assertion-field-binding",
                &changed_request,
                now() + Duration::seconds(1),
                "2".repeat(64),
            )
            .expect("changed assertion");
            let changed_authority_digest = authority_digest(
                &changed_request,
                &changed_assertion,
                operation_at,
                approval_policy_deadline,
                approval_record_valid_until,
            );
            assert_ne!(changed_authority_digest, baseline_authority_digest);
            assert!(matches!(
                issue_synthetic_with_assertion(
                    &policy,
                    &state,
                    changed_request,
                    changed_assertion,
                    operation_at,
                ),
                Err(ApprovalAuthorityError::RequestContextChanged)
            ));
        }
    }

    #[test]
    fn every_public_a3_debug_surface_is_enumerated_and_redacted() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let state = synthetic_state();
        let request = synthetic_request(&policy, &state);
        let mut surfaces = BTreeMap::new();
        record_public_human_debug_surfaces(&policy, &state, &mut surfaces);
        record_public_evidence_debug_surfaces(&state, &request, &mut surfaces);
        record_public_debug(&mut surfaces, "ApprovalRequest", &request);
        let authority = issue_synthetic(&policy, &state, request, now() + Duration::seconds(2))
            .expect("authority");
        record_public_debug(&mut surfaces, "ApprovalAuthority", &authority);
        let record = authority.consume_for_approval_record();
        record_public_debug(&mut surfaces, "ApprovalRecordAuthorization", &record);
        let error = ApprovalAuthorityError::EffectPolicy(
            "Publish exact preview raw_token mfa_code biometric_sample".into(),
        );
        record_public_debug(&mut surfaces, "ApprovalAuthorityError", &error);

        assert_eq!(
            surfaces.keys().copied().collect::<BTreeSet<_>>(),
            public_a3_type_names(),
            "every newly exported A3 type must make an explicit Debug decision"
        );
        for debug in surfaces.values() {
            assert_debug_redacted(debug);
        }
    }

    #[test]
    fn stale_revoked_wrong_scope_unknown_adapter_and_deadline_equality_fail_closed() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");

        let mut revoked = synthetic_state();
        let request = synthetic_request(&policy, &revoked);
        revoked
            .actor_authorization
            .revoke(now() + Duration::seconds(2))
            .expect("revoke");
        assert!(matches!(
            issue_synthetic(&policy, &revoked, request, now() + Duration::seconds(2)),
            Err(ApprovalAuthorityError::HumanEvidenceStaleOrRevoked)
        ));

        let mut wrong_scope = synthetic_state();
        wrong_scope.connected.account_id = AccountId::from("other-account");
        assert_prepare_rejected(
            &policy,
            &wrong_scope,
            ApprovalAuthorityErrorKind::ProviderScope,
        );

        let mut unknown_adapter = synthetic_state();
        unknown_adapter.connected.adapter =
            ProviderAdapterIdentity::new("adapter.other", 1).expect("adapter");
        assert_prepare_rejected(
            &policy,
            &unknown_adapter,
            ApprovalAuthorityErrorKind::Adapter,
        );

        let mut equality = synthetic_state();
        equality.connected.observed_valid_until = now();
        assert_prepare_rejected(
            &policy,
            &equality,
            ApprovalAuthorityErrorKind::ProviderScope,
        );
    }

    proptest! {
        #[test]
        fn any_single_request_field_tamper_breaks_its_original_digest(field in 0usize..19) {
            let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
            let state = synthetic_state();
            let mut request = synthetic_request(&policy, &state);
            tamper_request(&mut request, field);
            let result = issue_synthetic(
                &policy,
                &state,
                request,
                now() + Duration::seconds(2),
            );
            prop_assert!(matches!(
                result,
                Err(ApprovalAuthorityError::RequestDigestMismatch)
            ));
        }

        #[test]
        fn rehashed_single_request_field_drift_hits_live_context_closure(field in 0usize..19) {
            let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
            let state = synthetic_state();
            let mut request = synthetic_request(&policy, &state);
            tamper_request(&mut request, field);
            request.request_digest = request.canonical_digest();
            let result = issue_synthetic(
                &policy,
                &state,
                request,
                now() + Duration::seconds(2),
            );
            prop_assert!(matches!(
                result,
                Err(ApprovalAuthorityError::RequestContextChanged)
            ));
        }
    }

    #[test]
    fn request_bound_step_up_exact_fields_reject_structurally_valid_drift() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        for field in 0..7 {
            let state = synthetic_state();
            let request = synthetic_request(&policy, &state);
            let mut assertion = RequestBoundStepUpAssertion::new(
                "step-up-assertion-binding",
                &request,
                now() + Duration::seconds(1),
                "2".repeat(64),
            )
            .expect("assertion");
            tamper_step_up_assertion(&mut assertion, field);
            assertion.binding_digest = assertion.canonical_binding_digest();
            assertion
                .validate_structure()
                .expect("tampered assertion remains structurally valid");
            let result = issue_synthetic_with_assertion(
                &policy,
                &state,
                request,
                assertion,
                now() + Duration::seconds(3),
            );
            assert!(matches!(
                result,
                Err(ApprovalAuthorityError::StepUpAssertionMismatch)
            ));
        }
    }

    #[test]
    fn request_bound_step_up_binding_digest_tamper_is_rejected() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let state = synthetic_state();
        let request = synthetic_request(&policy, &state);
        let mut assertion = RequestBoundStepUpAssertion::new(
            "step-up-assertion-digest",
            &request,
            now() + Duration::seconds(1),
            "2".repeat(64),
        )
        .expect("assertion");
        assertion.binding_digest = "3".repeat(64);

        let result = issue_synthetic_with_assertion(
            &policy,
            &state,
            request,
            assertion,
            now() + Duration::seconds(3),
        );
        assert!(matches!(
            result,
            Err(ApprovalAuthorityError::StepUpAssertionMismatch)
        ));
    }

    #[test]
    fn request_bound_step_up_rejects_verified_at_before_request() {
        let policy = ProviderApprovalAuthorityPolicy::contract_baseline().expect("contract");
        let state = synthetic_state();
        let request = synthetic_request(&policy, &state);
        let assertion = RequestBoundStepUpAssertion::new(
            "step-up-assertion-backdated",
            &request,
            request.requested_at - Duration::seconds(1),
            "2".repeat(64),
        )
        .expect("structurally valid assertion with an exact binding digest");

        let result = issue_synthetic_with_assertion(
            &policy,
            &state,
            request,
            assertion,
            now() + Duration::seconds(3),
        );
        assert!(matches!(
            result,
            Err(ApprovalAuthorityError::StepUpAssertionMismatch)
        ));
    }

    fn record_public_human_debug_surfaces(
        policy: &ProviderApprovalAuthorityPolicy,
        state: &SyntheticState,
        surfaces: &mut BTreeMap<&'static str, String>,
    ) {
        record_public_debug(
            surfaces,
            "ApprovalAuthorityKind",
            &ApprovalAuthorityKind::EffectApprovalRecordOnly,
        );
        record_public_debug(
            surfaces,
            "HumanOperationKind",
            &HumanOperationKind::ApproveProviderEffect,
        );
        record_public_debug(
            surfaces,
            "HumanOperationDecision",
            &HumanOperationDecision::Approve,
        );
        record_public_debug(
            surfaces,
            "HumanAssuranceLevel",
            &HumanAssuranceLevel::HardwareBound,
        );
        record_public_debug(surfaces, "HumanStepUpMethod", &HumanStepUpMethod::Webauthn);
        record_public_debug(surfaces, "ProviderApprovalAuthorityPolicy", policy);
        let authorization = &state.actor_authorization;
        record_public_debug(
            surfaces,
            "HumanAuthorityIssuerIdentity",
            authorization.subject().issuer(),
        );
        record_public_debug(surfaces, "HumanAuthoritySubject", authorization.subject());
        record_public_debug(surfaces, "HumanActorAuthorization", authorization);
        record_public_debug(
            surfaces,
            "HumanSessionIdentity",
            state.actor_session.identity(),
        );
        record_public_debug(surfaces, "HumanActorSession", &state.actor_session);
        let window =
            HumanEvidenceWindow::new(now() - Duration::seconds(1), now() + Duration::seconds(30))
                .expect("window");
        record_public_debug(surfaces, "HumanEvidenceWindow", &window);
        let intent_identity =
            HumanStepUpIntentIdentity::new("step-up-intent-debug", 31).expect("identity");
        record_public_debug(surfaces, "HumanStepUpIntentIdentity", &intent_identity);
        let intent = HumanStepUpIntent::new(
            intent_identity,
            &state.actor_session,
            HumanStepUpMethod::Webauthn,
            HumanAssuranceLevel::HardwareBound,
            state
                .mission
                .effect(&state.effect_id)
                .expect("effect")
                .approval_digest(),
            window,
        )
        .expect("intent");
        record_public_debug(surfaces, "HumanStepUpIntent", &intent);
    }

    fn record_public_evidence_debug_surfaces(
        state: &SyntheticState,
        request: &ApprovalRequest,
        surfaces: &mut BTreeMap<&'static str, String>,
    ) {
        let context = ProviderEffectApprovalContext::new(
            &state.mission,
            &state.effect_id,
            &state.effect_policy,
            &state.permission_evidence,
        );
        record_public_debug(surfaces, "ProviderEffectApprovalContext", &context);
        let (auth_policy, secret, lease, auth_session, probe) = live_a2_chain();
        let provider =
            ProviderApprovalEvidence::new(&auth_policy, &secret, &lease, &auth_session, &probe);
        record_public_debug(surfaces, "ProviderApprovalEvidence", &provider);
        let target_digest = state
            .mission
            .effect(&state.effect_id)
            .expect("effect")
            .approval_digest();
        let intent = HumanStepUpIntent::new(
            HumanStepUpIntentIdentity::new("step-up-intent-wrapper", 32).expect("identity"),
            &state.actor_session,
            HumanStepUpMethod::Webauthn,
            HumanAssuranceLevel::HardwareBound,
            target_digest,
            HumanEvidenceWindow::new(now() - Duration::seconds(1), now() + Duration::seconds(30))
                .expect("window"),
        )
        .expect("intent");
        let request_evidence = HumanApprovalRequestEvidence::new(
            &state.actor_authorization,
            &state.actor_session,
            intent,
        );
        record_public_debug(surfaces, "HumanApprovalRequestEvidence", &request_evidence);
        let assertion = RequestBoundStepUpAssertion::new(
            "step-up-assertion-debug",
            request,
            now() + Duration::seconds(1),
            "2".repeat(64),
        )
        .expect("assertion");
        record_public_debug(surfaces, "RequestBoundStepUpAssertion", &assertion);
        let issuance_evidence = HumanApprovalIssuanceEvidence::new(
            &state.actor_authorization,
            &state.actor_session,
            assertion,
        );
        record_public_debug(
            surfaces,
            "HumanApprovalIssuanceEvidence",
            &issuance_evidence,
        );
    }

    fn record_public_debug<T: std::fmt::Debug + ?Sized>(
        surfaces: &mut BTreeMap<&'static str, String>,
        type_name: &'static str,
        value: &T,
    ) {
        assert!(surfaces.insert(type_name, format!("{value:?}")).is_none());
    }

    fn public_a3_type_names() -> BTreeSet<&'static str> {
        include_str!("approval_authority.rs")
            .lines()
            .filter_map(|line| {
                line.strip_prefix("pub struct ")
                    .or_else(|| line.strip_prefix("pub enum "))
            })
            .filter_map(|declaration| {
                declaration
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .next()
            })
            .collect()
    }

    fn tamper_request(request: &mut ApprovalRequest, field: usize) {
        match field {
            0 => request.contract_version = "tampered-contract".into(),
            1 => request.mission_revision += 1,
            2 => request.effect_approval_digest = "3".repeat(64),
            3 => request.approving_actor_id = ActorId::from("other-approver"),
            4 => request.requesting_actor_id = ActorId::from("other-requester"),
            5 => request.provider_id = "other-provider".into(),
            6 => request.account_id = AccountId::from("other-account"),
            7 => request.capability_id = "other.capability".into(),
            8 => {
                request.required_scopes.insert("extra.scope".into());
            }
            9 => request.credential_revision += 1,
            10 => request.lease_revision += 1,
            11 => request.auth_revision += 1,
            12 => request.probe_revision += 1,
            13 => request.adapter = ProviderAdapterIdentity::new("adapter.other", 1).expect("id"),
            14 => request.payload_digest = "4".repeat(64),
            15 => request.policy_digest = "5".repeat(64),
            16 => request.permission_evidence_digest = "6".repeat(64),
            17 => request.permission_authorization_digest = "7".repeat(64),
            _ => request.provider_probe_expires_at += Duration::seconds(1),
        }
    }

    fn tamper_record_writer_field(request: &mut ApprovalRequest, field: usize) {
        match field {
            0 => request.effect_approval_digest = "3".repeat(64),
            1 => request.policy_digest = "5".repeat(64),
            _ => request.permission_authorization_digest = "7".repeat(64),
        }
    }

    fn tamper_step_up_assertion(assertion: &mut RequestBoundStepUpAssertion, field: usize) {
        match field {
            0 => assertion.request_digest = "3".repeat(64),
            1 => assertion.intent_id = "step-up-intent-other".into(),
            2 => assertion.intent_revision += 1,
            3 => assertion.session_id = "human-session-other".into(),
            4 => assertion.session_revision += 1,
            5 => assertion.actor_id = ActorId::from("other-approver"),
            _ => assertion.expires_at -= Duration::seconds(1),
        }
    }

    fn live_a2_chain() -> (
        ProviderAuthProbePolicy,
        SecretReference,
        CredentialLease,
        AuthSession,
        ProbeResult,
    ) {
        let policy = ProviderAuthProbePolicy::contract_baseline().expect("A2 policy");
        let scope = ProviderAuthScope::new(
            TenantId::from("tenant-a3"),
            ProjectId::from("project-a3"),
            "fixture-provider",
            AccountId::from("account-a3"),
            ["preview.publish".into()],
        )
        .expect("scope");
        let secret = SecretReference::new("secret-ref-a3", scope, 11).expect("secret");
        let lease = policy
            .issue_credential_lease(
                &secret,
                ProviderAdapterIdentity::new("adapter.fixture", 3).expect("adapter"),
                "credential-lease-a3",
                12,
                now() - Duration::seconds(10),
                now() + Duration::minutes(5),
            )
            .expect("lease");
        let session = policy
            .begin_auth_session(
                &secret,
                &lease,
                "auth-session-a3",
                13,
                now() - Duration::seconds(5),
                now() + Duration::minutes(3),
            )
            .expect("auth session");
        let probe = policy
            .record_probe(
                &secret,
                &lease,
                &session,
                ProbeObservation::new(
                    "probe-result-a3",
                    14,
                    ProbeStatus::Reachable,
                    ProviderProvenanceClass::ProductionProvider,
                    now(),
                    now() + Duration::seconds(90),
                    "e".repeat(64),
                ),
            )
            .expect("probe");
        (policy, secret, lease, session, probe)
    }

    fn assert_contract_rejected(value: &Value) {
        assert!(
            ProviderApprovalAuthorityPolicy::from_contract_json(
                &serde_json::to_string(value).expect("serialize")
            )
            .is_err()
        );
    }

    fn assert_debug_redacted(debug: &str) {
        let normalized = debug.to_ascii_lowercase();
        for forbidden in [
            "secret-ref-",
            "credential-lease-",
            "auth-session-",
            "probe-result-",
            "human-authorization-",
            "human-session-",
            "step-up-intent-",
            "step-up-assertion-",
            "tenant-a3",
            "project-a3",
            "mission-a3",
            "effect-a3",
            "account-a3",
            "requesting-actor-a3",
            "approving-actor-a3",
            "fixture-provider",
            "preview.publish",
            "provider approval",
            "publish exact preview",
            "preview/a3",
            "raw_token",
            "mfa_code",
            "biometric_sample",
        ] {
            assert!(!normalized.contains(forbidden), "leaked {forbidden}");
        }
        assert!(
            !normalized
                .as_bytes()
                .windows(64)
                .any(|window| window.iter().all(u8::is_ascii_hexdigit)),
            "Debug output exposed a complete digest"
        );
    }

    fn refresh_contract_digests(policy: &mut ProviderApprovalAuthorityPolicy) {
        policy.human_operation_authority.contract_digest = policy
            .human_operation_authority
            .canonical_digest()
            .expect("human digest");
        policy.human_operation_authority_reference.contract_digest =
            policy.human_operation_authority.contract_digest.clone();
        policy.contract_digest = policy.canonical_digest().expect("contract digest");
    }

    #[derive(Clone, Copy)]
    enum ApprovalAuthorityErrorKind {
        ProviderScope,
        Adapter,
    }

    fn assert_prepare_rejected(
        policy: &ProviderApprovalAuthorityPolicy,
        state: &SyntheticState,
        expected: ApprovalAuthorityErrorKind,
    ) {
        let target = state
            .mission
            .effect(&state.effect_id)
            .expect("effect")
            .approval_digest();
        let intent = HumanStepUpIntent::new(
            HumanStepUpIntentIdentity::new("step-up-intent-rejected", 1).expect("identity"),
            &state.actor_session,
            HumanStepUpMethod::Webauthn,
            HumanAssuranceLevel::HardwareBound,
            target,
            HumanEvidenceWindow::new(now(), now() + Duration::seconds(30)).expect("window"),
        )
        .expect("intent");
        let result = policy.prepare_request_against_registries(
            &ProviderEffectApprovalContext::new(
                &state.mission,
                &state.effect_id,
                &state.effect_policy,
                &state.permission_evidence,
            ),
            ActorId::from("approving-actor-a3"),
            HumanApprovalRequestEvidence::new(
                &state.actor_authorization,
                &state.actor_session,
                intent,
            ),
            &state.connected,
            ApprovalRegistryView {
                adapter_registry: &state.adapter_registry,
                human_issuers: &state.human_issuers,
            },
            now(),
        );
        match expected {
            ApprovalAuthorityErrorKind::ProviderScope => assert!(matches!(
                result,
                Err(ApprovalAuthorityError::ProviderScopeMismatch)
            )),
            ApprovalAuthorityErrorKind::Adapter => assert!(matches!(
                result,
                Err(ApprovalAuthorityError::ProviderAdapterMismatch)
            )),
        }
    }
}
