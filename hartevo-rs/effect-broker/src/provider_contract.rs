//! Non-secret Provider adapter identity and capability-support metadata.
//!
//! This E1 contract deliberately grants no Provider execution, connection,
//! receipt, verification, or E4 authority. The checked-in registry is empty;
//! validation only proves that metadata exactly matches an explicitly supplied
//! registration.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION: &str = "hartevo-provider-adapter-contract/v1";
pub const PROVIDER_ADAPTER_CONTRACT_VERSION: &str = "provider-adapter-e1/v1";
pub const PROVIDER_ADAPTER_BASELINE_REGISTRY_VERSION: &str = "desktop-2026-08-12-a1";
pub const PROVIDER_ADAPTER_CONTRACT_JSON: &str =
    include_str!("../../../contracts/providers/adapter-contract.v1.json");

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenanceClass {
    Fixture,
    ComponentHarness,
    ControlledProvider,
    ProductionProvider,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct ProviderCapabilitySupport {
    key: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    evidence_support: BTreeSet<ProviderEvidenceSupport>,
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

    pub const fn evidence_support(&self) -> &BTreeSet<ProviderEvidenceSupport> {
        &self.evidence_support
    }

    fn validate(&self) -> Result<(), ProviderContractError> {
        self.key.validate()?;
        self.adapter.validate()?;
        if self.evidence_support.is_empty() {
            return Err(ProviderContractError::EmptySupportSurface);
        }
        for support in &self.evidence_support {
            support.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct ProviderAdapterRegistry {
    schema_version: String,
    contract_version: String,
    registry_version: String,
    registrations: Vec<ProviderCapabilitySupport>,
}

impl ProviderAdapterRegistry {
    pub fn contract_baseline() -> Self {
        Self {
            schema_version: PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION.into(),
            contract_version: PROVIDER_ADAPTER_CONTRACT_VERSION.into(),
            registry_version: PROVIDER_ADAPTER_BASELINE_REGISTRY_VERSION.into(),
            registrations: Vec::new(),
        }
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
    fn checked_in_contract_is_e1_metadata_with_an_empty_registry() {
        let baseline = ProviderAdapterRegistry::contract_baseline();
        baseline.validate().expect("baseline");
        assert!(baseline.is_empty());
        assert_eq!(
            baseline.authority(),
            ProviderEvidenceAuthority::MetadataBindingOnly
        );
        assert!(PROVIDER_ADAPTER_CONTRACT_JSON.contains("\"evidenceLevel\": \"E1\""));
        assert!(PROVIDER_ADAPTER_CONTRACT_JSON.contains("\"registrations\": []"));
        assert!(PROVIDER_ADAPTER_CONTRACT_JSON.contains("\"connected\": false"));
        assert!(PROVIDER_ADAPTER_CONTRACT_JSON.contains("\"e4\": false"));
    }

    #[test]
    fn empty_registry_fails_closed_for_all_evidence() {
        let error = ProviderAdapterRegistry::contract_baseline()
            .validate_evidence(
                &ProviderCapabilityEvidenceClaim::new(
                    PROVIDER_ADAPTER_CONTRACT_VERSION,
                    PROVIDER_ADAPTER_BASELINE_REGISTRY_VERSION,
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
}
