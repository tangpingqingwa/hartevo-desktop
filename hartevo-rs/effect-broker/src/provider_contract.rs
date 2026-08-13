//! Non-secret Provider adapter identity and capability-support metadata.
//!
//! This E1 contract deliberately grants no Provider execution, connection,
//! receipt, verification, or E4 authority. The checked-in registry contains
//! only the current E1 metadata bindings; validation proves that metadata
//! exactly matches an explicitly supplied registration.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION: &str = "hartevo-provider-adapter-contract/v1";
pub const PROVIDER_ADAPTER_CONTRACT_VERSION: &str = "provider-adapter-e1/v1";
pub const PROVIDER_ADAPTER_BASELINE_REGISTRY_VERSION: &str = "desktop-2026-08-13-signal01-a1";
pub const PROVIDER_ADAPTER_CONTRACT_JSON: &str =
    include_str!("../../../contracts/providers/adapter-contract.v1.json");

const PROVIDER_ID_RULE: &str = "1..64 lowercase ASCII letters, digits, or internal hyphens";
const CAPABILITY_ID_RULE: &str =
    "2..96 lowercase dot-separated segments using letters, digits, hyphens, or underscores";
const ADAPTER_ID_RULE: &str =
    "2..96 lowercase dot-separated segments using letters, digits, hyphens, or underscores";
const ADAPTER_VERSION_RULE: &str = "positive integer";
const EVIDENCE_DIGEST_RULE: &str = "64 lowercase hexadecimal characters";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderCapabilityKey {
    provider_id: String,
    capability_id: String,
}

impl ProviderCapabilityKey {
    pub fn new(
        provider_id: impl Into<String>,
        capability_id: impl Into<String>,
    ) -> Result<Self, ProviderContractError> {
        let key = Self {
            provider_id: provider_id.into(),
            capability_id: capability_id.into(),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        if !valid_provider_id(&self.provider_id) {
            return Err(ProviderContractError::InvalidProviderId);
        }
        if !valid_namespaced_id(&self.capability_id) {
            return Err(ProviderContractError::InvalidCapabilityId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAdapterIdentity {
    adapter_id: String,
    adapter_version: u32,
}

impl ProviderAdapterIdentity {
    pub fn new(
        adapter_id: impl Into<String>,
        adapter_version: u32,
    ) -> Result<Self, ProviderContractError> {
        let identity = Self {
            adapter_id: adapter_id.into(),
            adapter_version,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub const fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        if !valid_namespaced_id(&self.adapter_id) {
            return Err(ProviderContractError::InvalidAdapterId);
        }
        if self.adapter_version == 0 {
            return Err(ProviderContractError::InvalidAdapterVersion);
        }
        Ok(())
    }
}

macro_rules! provider_contract_enum {
    (
        $(#[$metadata:meta])*
        pub enum $name:ident {
            $($variant:ident),+ $(,)?
        }
    ) => {
        $(#[$metadata])*
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}

provider_contract_enum! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ProviderAdapterOperation {
        Probe,
        BeginAuth,
        Refresh,
        Read,
        PrepareEffect,
        Execute,
        Reconcile,
        Verify,
        HandleWebhook,
        Revoke,
    }
}

provider_contract_enum! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ProviderEvidenceClass {
        ProbeObservation,
        Authentication,
        ReadObservation,
        PreparedEffect,
        ReceiptCandidate,
        ReconciliationObservation,
        VerificationObservation,
        WebhookObservation,
        RevocationObservation,
    }
}

provider_contract_enum! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ProviderProvenanceClass {
        Fixture,
        ComponentHarness,
        ControlledProvider,
        ProductionProvider,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum ProviderContractEvidenceLevel {
    #[serde(rename = "E1")]
    E1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ProviderSecretMaterialPolicy {
    Forbidden,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
struct ProviderClaimGrant(bool);

impl ProviderClaimGrant {
    const fn is_denied(&self) -> bool {
        !self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderClaimAuthority {
    connected: ProviderClaimGrant,
    provider_execution: ProviderClaimGrant,
    provider_receipt: ProviderClaimGrant,
    business_verification: ProviderClaimGrant,
    e4: ProviderClaimGrant,
}

impl ProviderClaimAuthority {
    const fn is_metadata_only(&self) -> bool {
        self.connected.is_denied()
            && self.provider_execution.is_denied()
            && self.provider_receipt.is_denied()
            && self.business_verification.is_denied()
            && self.e4.is_denied()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderIdentifierRules {
    provider_id: String,
    capability_id: String,
    adapter_id: String,
    adapter_version: String,
    evidence_digest: String,
}

impl ProviderIdentifierRules {
    fn validate(&self) -> Result<(), ProviderContractError> {
        if self.provider_id != PROVIDER_ID_RULE
            || self.capability_id != CAPABILITY_ID_RULE
            || self.adapter_id != ADAPTER_ID_RULE
            || self.adapter_version != ADAPTER_VERSION_RULE
            || self.evidence_digest != EVIDENCE_DIGEST_RULE
        {
            return Err(ProviderContractError::InvalidIdentifierRules);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProviderOperationEvidenceBindings {
    probe: ProviderEvidenceClass,
    begin_auth: ProviderEvidenceClass,
    refresh: ProviderEvidenceClass,
    read: ProviderEvidenceClass,
    prepare_effect: ProviderEvidenceClass,
    execute: ProviderEvidenceClass,
    reconcile: ProviderEvidenceClass,
    verify: ProviderEvidenceClass,
    handle_webhook: ProviderEvidenceClass,
    revoke: ProviderEvidenceClass,
}

impl ProviderOperationEvidenceBindings {
    const fn entries(
        &self,
    ) -> [(ProviderAdapterOperation, ProviderEvidenceClass); ProviderAdapterOperation::ALL.len()]
    {
        [
            (ProviderAdapterOperation::Probe, self.probe),
            (ProviderAdapterOperation::BeginAuth, self.begin_auth),
            (ProviderAdapterOperation::Refresh, self.refresh),
            (ProviderAdapterOperation::Read, self.read),
            (ProviderAdapterOperation::PrepareEffect, self.prepare_effect),
            (ProviderAdapterOperation::Execute, self.execute),
            (ProviderAdapterOperation::Reconcile, self.reconcile),
            (ProviderAdapterOperation::Verify, self.verify),
            (ProviderAdapterOperation::HandleWebhook, self.handle_webhook),
            (ProviderAdapterOperation::Revoke, self.revoke),
        ]
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        for (operation, evidence_class) in self.entries() {
            if expected_evidence_class(operation) != evidence_class {
                return Err(ProviderContractError::InvalidEvidenceBinding);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderAdapterContractDocument {
    schema_version: String,
    contract_version: String,
    registry_version: String,
    evidence_level: ProviderContractEvidenceLevel,
    secret_material: ProviderSecretMaterialPolicy,
    validation_authority: ProviderEvidenceAuthority,
    claim_authority: ProviderClaimAuthority,
    identifier_rules: ProviderIdentifierRules,
    operations: Vec<ProviderAdapterOperation>,
    evidence_classes: Vec<ProviderEvidenceClass>,
    provenance_classes: Vec<ProviderProvenanceClass>,
    operation_evidence_bindings: ProviderOperationEvidenceBindings,
    registrations: Vec<ProviderCapabilitySupport>,
}

impl ProviderAdapterContractDocument {
    fn into_registry(self) -> Result<ProviderAdapterRegistry, ProviderContractError> {
        self.validate()?;
        let registry = ProviderAdapterRegistry {
            schema_version: self.schema_version,
            contract_version: self.contract_version,
            registry_version: self.registry_version,
            registrations: self.registrations,
        };
        registry.validate()?;
        Ok(registry)
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        if self.schema_version != PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION {
            return Err(ProviderContractError::InvalidSchemaVersion);
        }
        if self.contract_version != PROVIDER_ADAPTER_CONTRACT_VERSION {
            return Err(ProviderContractError::InvalidContractVersion);
        }
        if self.evidence_level != ProviderContractEvidenceLevel::E1 {
            return Err(ProviderContractError::InvalidEvidenceLevel);
        }
        if self.secret_material != ProviderSecretMaterialPolicy::Forbidden {
            return Err(ProviderContractError::InvalidSecretMaterialPolicy);
        }
        if self.validation_authority != ProviderEvidenceAuthority::MetadataBindingOnly {
            return Err(ProviderContractError::InvalidValidationAuthority);
        }
        if !self.claim_authority.is_metadata_only() {
            return Err(ProviderContractError::InvalidClaimAuthority);
        }
        self.identifier_rules.validate()?;
        validate_exact_contract_set(
            &self.operations,
            ProviderAdapterOperation::ALL,
            "operations",
        )?;
        validate_exact_contract_set(
            &self.evidence_classes,
            ProviderEvidenceClass::ALL,
            "evidence classes",
        )?;
        validate_exact_contract_set(
            &self.provenance_classes,
            ProviderProvenanceClass::ALL,
            "provenance classes",
        )?;
        let binding_entries = self.operation_evidence_bindings.entries();
        let binding_operations = binding_entries
            .iter()
            .map(|(operation, _)| *operation)
            .collect::<BTreeSet<_>>();
        let binding_evidence = binding_entries
            .iter()
            .map(|(_, evidence_class)| *evidence_class)
            .collect::<BTreeSet<_>>();
        let declared_operations = self.operations.iter().copied().collect::<BTreeSet<_>>();
        let declared_evidence = self
            .evidence_classes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if binding_operations != declared_operations || binding_evidence != declared_evidence {
            return Err(ProviderContractError::InvalidOperationEvidenceClosure);
        }
        self.operation_evidence_bindings.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderEvidenceSupport {
    operation: ProviderAdapterOperation,
    evidence_class: ProviderEvidenceClass,
    provenance_class: ProviderProvenanceClass,
}

impl ProviderEvidenceSupport {
    pub fn new(
        operation: ProviderAdapterOperation,
        evidence_class: ProviderEvidenceClass,
        provenance_class: ProviderProvenanceClass,
    ) -> Result<Self, ProviderContractError> {
        let support = Self {
            operation,
            evidence_class,
            provenance_class,
        };
        support.validate()?;
        Ok(support)
    }

    pub const fn operation(&self) -> ProviderAdapterOperation {
        self.operation
    }

    pub const fn evidence_class(&self) -> ProviderEvidenceClass {
        self.evidence_class
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        if expected_evidence_class(self.operation) != self.evidence_class {
            return Err(ProviderContractError::InvalidEvidenceBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderCapabilitySupport {
    key: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    evidence_support: Vec<ProviderEvidenceSupport>,
}

impl ProviderCapabilitySupport {
    pub fn new(
        key: ProviderCapabilityKey,
        adapter: ProviderAdapterIdentity,
        evidence_support: impl IntoIterator<Item = ProviderEvidenceSupport>,
    ) -> Result<Self, ProviderContractError> {
        let registration = Self {
            key,
            adapter,
            evidence_support: evidence_support.into_iter().collect(),
        };
        registration.validate()?;
        Ok(registration)
    }

    pub const fn key(&self) -> &ProviderCapabilityKey {
        &self.key
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub fn evidence_support(&self) -> &[ProviderEvidenceSupport] {
        &self.evidence_support
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        self.key.validate()?;
        self.adapter.validate()?;
        if self.evidence_support.is_empty() {
            return Err(ProviderContractError::EmptySupportSurface);
        }
        if self.evidence_support.iter().collect::<BTreeSet<_>>().len()
            != self.evidence_support.len()
        {
            return Err(ProviderContractError::DuplicateEvidenceSupport);
        }
        for support in &self.evidence_support {
            support.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderCapabilityEvidenceClaim {
    contract_version: String,
    registry_version: String,
    key: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    support: ProviderEvidenceSupport,
    evidence_digest: String,
}

impl ProviderCapabilityEvidenceClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_version: impl Into<String>,
        registry_version: impl Into<String>,
        key: ProviderCapabilityKey,
        adapter: ProviderAdapterIdentity,
        operation: ProviderAdapterOperation,
        evidence_class: ProviderEvidenceClass,
        provenance_class: ProviderProvenanceClass,
        evidence_digest: impl Into<String>,
    ) -> Result<Self, ProviderContractError> {
        let claim = Self {
            contract_version: contract_version.into(),
            registry_version: registry_version.into(),
            key,
            adapter,
            support: ProviderEvidenceSupport::new(operation, evidence_class, provenance_class)?,
            evidence_digest: evidence_digest.into(),
        };
        claim.validate()?;
        Ok(claim)
    }

    pub const fn key(&self) -> &ProviderCapabilityKey {
        &self.key
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn support(&self) -> &ProviderEvidenceSupport {
        &self.support
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        if self.contract_version != PROVIDER_ADAPTER_CONTRACT_VERSION {
            return Err(ProviderContractError::InvalidContractVersion);
        }
        if !valid_registry_version(&self.registry_version) {
            return Err(ProviderContractError::InvalidRegistryVersion);
        }
        self.key.validate()?;
        self.adapter.validate()?;
        self.support.validate()?;
        if !is_canonical_sha256(&self.evidence_digest) {
            return Err(ProviderContractError::InvalidEvidenceDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAdapterRegistry {
    schema_version: String,
    contract_version: String,
    registry_version: String,
    registrations: Vec<ProviderCapabilitySupport>,
}

impl ProviderAdapterRegistry {
    pub fn contract_baseline() -> Result<Self, ProviderContractError> {
        Self::from_contract_json(PROVIDER_ADAPTER_CONTRACT_JSON)
    }

    pub fn from_contract_json(contract_json: &str) -> Result<Self, ProviderContractError> {
        serde_json::from_str::<ProviderAdapterContractDocument>(contract_json)
            .map_err(|_| ProviderContractError::InvalidContractDocument)?
            .into_registry()
    }

    pub fn new(
        registry_version: impl Into<String>,
        registrations: impl IntoIterator<Item = ProviderCapabilitySupport>,
    ) -> Result<Self, ProviderContractError> {
        let registry = Self {
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION.into(),
            contract_version: PROVIDER_ADAPTER_CONTRACT_VERSION.into(),
            registry_version: registry_version.into(),
            registrations: registrations.into_iter().collect(),
        };
        registry.validate()?;
        Ok(registry)
    }

    pub fn registry_version(&self) -> &str {
        &self.registry_version
    }

    pub fn registrations(&self) -> &[ProviderCapabilitySupport] {
        &self.registrations
    }

    pub const fn authority(&self) -> ProviderEvidenceAuthority {
        ProviderEvidenceAuthority::MetadataBindingOnly
    }

    pub const fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.schema_version != PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION {
            return Err(ProviderContractError::InvalidSchemaVersion);
        }
        if self.contract_version != PROVIDER_ADAPTER_CONTRACT_VERSION {
            return Err(ProviderContractError::InvalidContractVersion);
        }
        if !valid_registry_version(&self.registry_version) {
            return Err(ProviderContractError::InvalidRegistryVersion);
        }
        let mut keys = BTreeSet::new();
        for registration in &self.registrations {
            registration.validate()?;
            if !keys.insert(registration.key.clone()) {
                return Err(ProviderContractError::DuplicateCapabilityKey);
            }
        }
        Ok(())
    }

    pub fn validate_evidence(
        &self,
        claim: &ProviderCapabilityEvidenceClaim,
    ) -> Result<ValidatedProviderEvidenceBinding, ProviderContractError> {
        self.validate()?;
        claim.validate()?;
        if claim.registry_version != self.registry_version {
            return Err(ProviderContractError::RegistryVersionMismatch);
        }
        let registration = self
            .registrations
            .iter()
            .find(|registration| registration.key == claim.key)
            .ok_or(ProviderContractError::UnregisteredCapability)?;
        if registration.adapter != claim.adapter {
            return Err(ProviderContractError::AdapterIdentityMismatch);
        }
        if !registration.evidence_support.contains(&claim.support) {
            return Err(ProviderContractError::UnsupportedEvidence);
        }
        Ok(ValidatedProviderEvidenceBinding {
            claim: claim.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEvidenceAuthority {
    MetadataBindingOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProviderEvidenceBinding {
    claim: ProviderCapabilityEvidenceClaim,
}

impl ValidatedProviderEvidenceBinding {
    pub const fn authority(&self) -> ProviderEvidenceAuthority {
        ProviderEvidenceAuthority::MetadataBindingOnly
    }

    pub const fn key(&self) -> &ProviderCapabilityKey {
        &self.claim.key
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.claim.adapter
    }

    pub const fn support(&self) -> &ProviderEvidenceSupport {
        &self.claim.support
    }

    pub fn evidence_digest(&self) -> &str {
        &self.claim.evidence_digest
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderContractError {
    #[error("Provider adapter contract schema version is not supported")]
    InvalidSchemaVersion,
    #[error("Provider adapter contract version is not supported")]
    InvalidContractVersion,
    #[error("Provider adapter contract JSON is malformed, incomplete, duplicated, or unknown")]
    InvalidContractDocument,
    #[error("Provider adapter contract evidence level is not supported")]
    InvalidEvidenceLevel,
    #[error("Provider adapter contract secret-material policy is not supported")]
    InvalidSecretMaterialPolicy,
    #[error("Provider adapter contract validation authority is not supported")]
    InvalidValidationAuthority,
    #[error("Provider adapter contract claim authority must deny product authority")]
    InvalidClaimAuthority,
    #[error("Provider adapter contract identifier rules do not match the validator")]
    InvalidIdentifierRules,
    #[error("Provider adapter contract repeats a value in {0}")]
    DuplicateContractValue(&'static str),
    #[error("Provider adapter contract does not declare the exact {0} set")]
    ContractSetMismatch(&'static str),
    #[error("Provider adapter operation/evidence bindings are not a closed exact mapping")]
    InvalidOperationEvidenceClosure,
    #[error("Provider adapter registry version is invalid")]
    InvalidRegistryVersion,
    #[error("Provider adapter evidence targets another registry version")]
    RegistryVersionMismatch,
    #[error("Provider id is invalid")]
    InvalidProviderId,
    #[error("Provider capability id is invalid")]
    InvalidCapabilityId,
    #[error("Provider adapter id is invalid")]
    InvalidAdapterId,
    #[error("Provider adapter version must be positive")]
    InvalidAdapterVersion,
    #[error("Provider operation and evidence class are incompatible")]
    InvalidEvidenceBinding,
    #[error("Provider capability support surface is empty")]
    EmptySupportSurface,
    #[error("Provider capability support surface contains duplicate evidence metadata")]
    DuplicateEvidenceSupport,
    #[error("Provider capability is registered more than once")]
    DuplicateCapabilityKey,
    #[error("Provider evidence digest is not canonical SHA-256")]
    InvalidEvidenceDigest,
    #[error("Provider capability has no registered adapter")]
    UnregisteredCapability,
    #[error("Provider adapter identity or version does not match the registry")]
    AdapterIdentityMismatch,
    #[error("Provider evidence or provenance class is outside the registered support surface")]
    UnsupportedEvidence,
}

fn validate_exact_contract_set<T: Copy + Ord>(
    values: &[T],
    expected: &[T],
    label: &'static str,
) -> Result<(), ProviderContractError> {
    let actual = values.iter().copied().collect::<BTreeSet<_>>();
    if actual.len() != values.len() {
        return Err(ProviderContractError::DuplicateContractValue(label));
    }
    if actual != expected.iter().copied().collect::<BTreeSet<_>>() {
        return Err(ProviderContractError::ContractSetMismatch(label));
    }
    Ok(())
}

const fn expected_evidence_class(operation: ProviderAdapterOperation) -> ProviderEvidenceClass {
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

fn valid_provider_id(value: &str) -> bool {
    bounded_identifier(value, 64, |byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
    }) && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_namespaced_id(value: &str) -> bool {
    if value.len() < 2 || value.len() > 96 {
        return false;
    }
    let mut segment_count = 0_usize;
    for segment in value.split('.') {
        if !bounded_identifier(segment, 64, |byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        }) || matches!(segment.as_bytes().first().copied(), Some(b'-' | b'_'))
            || matches!(segment.as_bytes().last().copied(), Some(b'-' | b'_'))
        {
            return false;
        }
        segment_count += 1;
    }
    segment_count >= 2
}

fn valid_registry_version(value: &str) -> bool {
    bounded_identifier(value, 96, |byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'_' | b'.' | b'/')
    })
}

fn bounded_identifier(value: &str, max_len: usize, allowed: impl Fn(u8) -> bool) -> bool {
    !value.is_empty() && value.len() <= max_len && value.is_ascii() && value.bytes().all(allowed)
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn contract_value() -> Value {
        serde_json::from_str(PROVIDER_ADAPTER_CONTRACT_JSON).expect("checked-in contract JSON")
    }

    fn parse_tampered_contract(
        tamper: impl FnOnce(&mut Value),
    ) -> Result<ProviderAdapterRegistry, ProviderContractError> {
        let mut value = contract_value();
        tamper(&mut value);
        ProviderAdapterRegistry::from_contract_json(
            &serde_json::to_string(&value).expect("tampered contract JSON"),
        )
    }

    fn registration_value() -> Value {
        json!({
            "key": {
                "providerId": "github",
                "capabilityId": "publication.verify"
            },
            "adapter": {
                "adapterId": "hartevo.github",
                "adapterVersion": 1
            },
            "evidenceSupport": [{
                "operation": "read",
                "evidenceClass": "read_observation",
                "provenanceClass": "controlled_provider"
            }]
        })
    }

    fn key() -> ProviderCapabilityKey {
        ProviderCapabilityKey::new("github", "publication.verify").expect("key")
    }

    fn adapter(version: u32) -> ProviderAdapterIdentity {
        ProviderAdapterIdentity::new("hartevo.github", version).expect("adapter")
    }

    fn read_support(provenance: ProviderProvenanceClass) -> ProviderEvidenceSupport {
        ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
            provenance,
        )
        .expect("support")
    }

    fn registry() -> ProviderAdapterRegistry {
        ProviderAdapterRegistry::new(
            "fixture-registry/v1",
            [ProviderCapabilitySupport::new(
                key(),
                adapter(1),
                [read_support(ProviderProvenanceClass::ControlledProvider)],
            )
            .expect("registration")],
        )
        .expect("registry")
    }

    fn claim() -> ProviderCapabilityEvidenceClaim {
        ProviderCapabilityEvidenceClaim::new(
            PROVIDER_ADAPTER_CONTRACT_VERSION,
            "fixture-registry/v1",
            key(),
            adapter(1),
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
            ProviderProvenanceClass::ControlledProvider,
            "a".repeat(64),
        )
        .expect("claim")
    }

    #[test]
    fn checked_in_contract_is_e1_metadata_with_signal_registrations() {
        let baseline = ProviderAdapterRegistry::contract_baseline().expect("typed contract");
        baseline.validate().expect("baseline");
        assert!(!baseline.is_empty());
        assert_eq!(
            baseline.registry_version(),
            PROVIDER_ADAPTER_BASELINE_REGISTRY_VERSION
        );
        assert_eq!(
            baseline.schema_version,
            PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION
        );
        assert_eq!(baseline.contract_version, PROVIDER_ADAPTER_CONTRACT_VERSION);
        assert_eq!(
            baseline.authority(),
            ProviderEvidenceAuthority::MetadataBindingOnly
        );
    }

    #[test]
    fn empty_registry_fails_closed_for_all_evidence() {
        let baseline = ProviderAdapterRegistry::contract_baseline().expect("typed contract");
        let registry_version = baseline.registry_version().to_owned();
        let error = baseline
            .validate_evidence(
                &ProviderCapabilityEvidenceClaim::new(
                    PROVIDER_ADAPTER_CONTRACT_VERSION,
                    registry_version,
                    key(),
                    adapter(1),
                    ProviderAdapterOperation::Read,
                    ProviderEvidenceClass::ReadObservation,
                    ProviderProvenanceClass::ControlledProvider,
                    "a".repeat(64),
                )
                .expect("claim"),
            )
            .expect_err("unregistered evidence must fail");
        assert_eq!(error, ProviderContractError::UnregisteredCapability);
    }

    #[test]
    fn exact_registered_metadata_binding_validates_without_product_authority() {
        let validated = registry().validate_evidence(&claim()).expect("binding");
        let expected_digest = "a".repeat(64);
        assert_eq!(validated.key(), &key());
        assert_eq!(validated.adapter(), &adapter(1));
        assert_eq!(validated.evidence_digest(), expected_digest.as_str());
        assert_eq!(
            validated.authority(),
            ProviderEvidenceAuthority::MetadataBindingOnly
        );
    }

    #[test]
    fn provider_tamper_is_rejected() {
        let mut tampered = claim();
        tampered.key.provider_id = "gitlab".into();
        assert_eq!(
            registry().validate_evidence(&tampered),
            Err(ProviderContractError::UnregisteredCapability)
        );
    }

    #[test]
    fn capability_tamper_is_rejected() {
        let mut tampered = claim();
        tampered.key.capability_id = "publication.publish".into();
        assert_eq!(
            registry().validate_evidence(&tampered),
            Err(ProviderContractError::UnregisteredCapability)
        );
    }

    #[test]
    fn adapter_identity_and_version_tamper_are_rejected() {
        let mut identity_tampered = claim();
        identity_tampered.adapter.adapter_id = "hartevo.gitlab".into();
        assert_eq!(
            registry().validate_evidence(&identity_tampered),
            Err(ProviderContractError::AdapterIdentityMismatch)
        );

        let mut adapter_tampered = claim();
        adapter_tampered.adapter.adapter_version = 2;
        assert_eq!(
            registry().validate_evidence(&adapter_tampered),
            Err(ProviderContractError::AdapterIdentityMismatch)
        );
    }

    #[test]
    fn contract_and_registry_version_tamper_are_rejected() {
        let mut contract_tampered = claim();
        contract_tampered.contract_version = "provider-adapter-e1/v2".into();
        assert_eq!(
            registry().validate_evidence(&contract_tampered),
            Err(ProviderContractError::InvalidContractVersion)
        );

        let mut registry_tampered = claim();
        registry_tampered.registry_version = "fixture-registry/v2".into();
        assert_eq!(
            registry().validate_evidence(&registry_tampered),
            Err(ProviderContractError::RegistryVersionMismatch)
        );
    }

    #[test]
    fn evidence_and_provenance_tamper_are_rejected() {
        let mut evidence_tampered = claim();
        evidence_tampered.support.evidence_class = ProviderEvidenceClass::VerificationObservation;
        assert_eq!(
            registry().validate_evidence(&evidence_tampered),
            Err(ProviderContractError::InvalidEvidenceBinding)
        );

        let mut provenance_tampered = claim();
        provenance_tampered.support.provenance_class = ProviderProvenanceClass::ProductionProvider;
        assert_eq!(
            registry().validate_evidence(&provenance_tampered),
            Err(ProviderContractError::UnsupportedEvidence)
        );

        let mut digest_tampered = claim();
        digest_tampered.evidence_digest = "A".repeat(64);
        assert_eq!(
            registry().validate_evidence(&digest_tampered),
            Err(ProviderContractError::InvalidEvidenceDigest)
        );
    }

    #[test]
    fn duplicate_keys_and_empty_support_fail_closed() {
        let registration = ProviderCapabilitySupport::new(
            key(),
            adapter(1),
            [read_support(ProviderProvenanceClass::ControlledProvider)],
        )
        .expect("registration");
        assert_eq!(
            ProviderAdapterRegistry::new(
                "duplicate-registry/v1",
                [registration.clone(), registration]
            ),
            Err(ProviderContractError::DuplicateCapabilityKey)
        );
        assert_eq!(
            ProviderCapabilitySupport::new(
                key(),
                adapter(1),
                std::iter::empty::<ProviderEvidenceSupport>(),
            ),
            Err(ProviderContractError::EmptySupportSurface)
        );
    }

    #[test]
    fn top_level_unknown_missing_and_duplicate_fields_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value
                    .as_object_mut()
                    .expect("contract object")
                    .insert("unknownField".into(), json!(true));
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value
                    .as_object_mut()
                    .expect("contract object")
                    .remove("registrations");
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );

        let duplicate_schema = PROVIDER_ADAPTER_CONTRACT_JSON.replacen(
            "{\n",
            "{\n  \"schemaVersion\": \"hartevo-provider-adapter-contract/v1\",\n",
            1,
        );
        assert_eq!(
            ProviderAdapterRegistry::from_contract_json(&duplicate_schema),
            Err(ProviderContractError::InvalidContractDocument)
        );
    }

    #[test]
    fn schema_contract_and_authority_tamper_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["schemaVersion"] = json!("hartevo-provider-adapter-contract/v2");
            }),
            Err(ProviderContractError::InvalidSchemaVersion)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["contractVersion"] = json!("provider-adapter-e1/v2");
            }),
            Err(ProviderContractError::InvalidContractVersion)
        );
        for field_and_value in [
            ("evidenceLevel", "E4"),
            ("secretMaterial", "allowed"),
            ("validationAuthority", "connected"),
        ] {
            assert_eq!(
                parse_tampered_contract(|value| {
                    value[field_and_value.0] = json!(field_and_value.1);
                }),
                Err(ProviderContractError::InvalidContractDocument)
            );
        }
        assert_eq!(
            parse_tampered_contract(|value| {
                value["claimAuthority"]["connected"] = json!(true);
            }),
            Err(ProviderContractError::InvalidClaimAuthority)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["identifierRules"]["providerId"] = json!("any string");
            }),
            Err(ProviderContractError::InvalidIdentifierRules)
        );
    }

    #[test]
    fn operation_set_duplicate_missing_and_unknown_values_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["operations"]
                    .as_array_mut()
                    .expect("operations")
                    .push(json!("probe"));
            }),
            Err(ProviderContractError::DuplicateContractValue("operations"))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["operations"]
                    .as_array_mut()
                    .expect("operations")
                    .pop();
            }),
            Err(ProviderContractError::ContractSetMismatch("operations"))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["operations"][0] = json!("unknown_operation");
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );
    }

    #[test]
    fn evidence_set_duplicate_missing_and_unknown_values_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["evidenceClasses"]
                    .as_array_mut()
                    .expect("evidence classes")
                    .push(json!("probe_observation"));
            }),
            Err(ProviderContractError::DuplicateContractValue(
                "evidence classes"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["evidenceClasses"]
                    .as_array_mut()
                    .expect("evidence classes")
                    .pop();
            }),
            Err(ProviderContractError::ContractSetMismatch(
                "evidence classes"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["evidenceClasses"][0] = json!("unknown_evidence");
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );
    }

    #[test]
    fn provenance_set_duplicate_missing_and_unknown_values_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["provenanceClasses"]
                    .as_array_mut()
                    .expect("provenance classes")
                    .push(json!("fixture"));
            }),
            Err(ProviderContractError::DuplicateContractValue(
                "provenance classes"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["provenanceClasses"]
                    .as_array_mut()
                    .expect("provenance classes")
                    .pop();
            }),
            Err(ProviderContractError::ContractSetMismatch(
                "provenance classes"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["provenanceClasses"][0] = json!("unknown_provenance");
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );
    }

    #[test]
    fn operation_evidence_binding_closure_and_exact_mapping_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["operationEvidenceBindings"]["execute"] = json!("read_observation");
            }),
            Err(ProviderContractError::InvalidOperationEvidenceClosure)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["operationEvidenceBindings"]["read"] = json!("receipt_candidate");
                value["operationEvidenceBindings"]["execute"] = json!("read_observation");
            }),
            Err(ProviderContractError::InvalidEvidenceBinding)
        );
    }

    #[test]
    fn operation_evidence_binding_unknown_missing_and_duplicate_fields_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["operationEvidenceBindings"]
                    .as_object_mut()
                    .expect("bindings")
                    .insert("unknown_operation".into(), json!("read_observation"));
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["operationEvidenceBindings"]
                    .as_object_mut()
                    .expect("bindings")
                    .remove("verify");
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );

        let duplicate_binding = PROVIDER_ADAPTER_CONTRACT_JSON.replacen(
            "    \"probe\": \"probe_observation\",\n",
            concat!(
                "    \"probe\": \"probe_observation\",\n",
                "    \"probe\": \"probe_observation\",\n"
            ),
            1,
        );
        assert_eq!(
            ProviderAdapterRegistry::from_contract_json(&duplicate_binding),
            Err(ProviderContractError::InvalidContractDocument)
        );
    }

    #[test]
    fn registrations_are_fully_typed_and_duplicate_metadata_fails_closed() {
        let parsed = parse_tampered_contract(|value| {
            value["registrations"]
                .as_array_mut()
                .expect("registrations")
                .push(registration_value());
        })
        .expect("typed E1 registration");
        let baseline_count = ProviderAdapterRegistry::contract_baseline()
            .expect("baseline")
            .registrations()
            .len();
        assert_eq!(parsed.registrations().len(), baseline_count + 1);
        assert_eq!(
            parsed.authority(),
            ProviderEvidenceAuthority::MetadataBindingOnly
        );

        assert_eq!(
            parse_tampered_contract(|value| {
                let registrations = value["registrations"]
                    .as_array_mut()
                    .expect("registrations");
                registrations.push(registration_value());
                registrations.push(registration_value());
            }),
            Err(ProviderContractError::DuplicateCapabilityKey)
        );

        let mut duplicate_support = registration_value();
        let support = duplicate_support["evidenceSupport"][0].clone();
        duplicate_support["evidenceSupport"]
            .as_array_mut()
            .expect("evidence support")
            .push(support);
        assert_eq!(
            parse_tampered_contract(|value| {
                value["registrations"]
                    .as_array_mut()
                    .expect("registrations")
                    .push(duplicate_support);
            }),
            Err(ProviderContractError::DuplicateEvidenceSupport)
        );
    }

    #[test]
    fn registration_unknown_and_missing_fields_fail_closed() {
        let mut unknown = registration_value();
        unknown["key"]
            .as_object_mut()
            .expect("key")
            .insert("unknownField".into(), json!(true));
        assert_eq!(
            parse_tampered_contract(|value| {
                value["registrations"]
                    .as_array_mut()
                    .expect("registrations")
                    .push(unknown);
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );

        let mut missing = registration_value();
        missing["adapter"]
            .as_object_mut()
            .expect("adapter")
            .remove("adapterVersion");
        assert_eq!(
            parse_tampered_contract(|value| {
                value["registrations"]
                    .as_array_mut()
                    .expect("registrations")
                    .push(missing);
            }),
            Err(ProviderContractError::InvalidContractDocument)
        );
    }
}
