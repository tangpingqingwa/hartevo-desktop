//! Current-commit provenance and release-evidence binding for plugin mounts.
//!
//! The composition kernel proves that typed service, provider, and consumer
//! descriptors can be mounted for one Mission. This module adds the smaller
//! supply-chain seam needed to explain exactly what was mounted: source
//! commit, target, plugin version, artifact digest, and toolchain. It produces
//! content-free durable receipts and a contract-verification receipt, never a
//! signed, notarized, native, or releasable claim.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest, PluginDefinitionHandle,
    PluginError, PluginVersion, ProviderCardinality, ProviderDefinition, ProviderId,
    RegistrationReceipt, ServiceDefinition, ServiceId,
};

pub const PLUGIN_PROVENANCE_SCHEMA: &str = "hartevo.plugin-provenance/v1";
pub const PLUGIN_EVIDENCE_RECEIPT_SCHEMA: &str = "hartevo.plugin-evidence-receipt/v1";
pub const PLUGIN_VERIFICATION_RECEIPT_SCHEMA: &str = "hartevo.plugin-verification-receipt/v1";
pub const PLUGIN_EVIDENCE_SERVICE_SCHEMA: &str = "hartevo.plugin-evidence-service/v1";
pub const PLUGIN_EVIDENCE_SERVICE_ID: &str = "plugin.evidence.release";
pub const PLUGIN_EVIDENCE_PROVIDER_ID: &str = "plugin.evidence.verifier";
pub const PLUGIN_EVIDENCE_CONSUMER_ID: &str = "plugin.evidence.release-gate";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PluginEvidenceError {
    #[error("plugin runtime rejected the evidence binding: {0}")]
    Plugin(PluginError),
    #[error("source commit must be a lowercase 40- or 64-character hexadecimal object id")]
    InvalidSourceCommit,
    #[error("target triple is invalid")]
    InvalidTarget,
    #[error("toolchain identity is invalid")]
    InvalidToolchain,
    #[error("digest is invalid")]
    InvalidDigest,
    #[error("provenance schema is invalid")]
    InvalidProvenanceSchema,
    #[error("evidence receipt schema is invalid")]
    InvalidReceiptSchema,
    #[error("verification receipt schema is invalid")]
    InvalidVerificationSchema,
    #[error("evidence binding is invalid")]
    InvalidBinding,
    #[error("evidence receipt integrity check failed")]
    ReceiptDigestMismatch,
    #[error("verification receipt integrity check failed")]
    VerificationDigestMismatch,
    #[error("evidence receipt is not bound to the expected current provenance")]
    ProvenanceMismatch,
    #[error("evidence receipt is not bound to the current provider implementation")]
    ProviderMismatch,
    #[error("plugin evidence has been revoked")]
    Revoked,
    #[error("revocation record does not match the evidence receipt")]
    RevocationMismatch,
    #[error("release honesty fields were changed")]
    HonestyViolation,
    #[error("durable evidence JSON is invalid: {0}")]
    InvalidDocument(String),
}

impl From<PluginError> for PluginEvidenceError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignatureStatus {
    UnsignedGenerated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeEvidence {
    NotProven,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseDecision {
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationDecision {
    BlockedReleaseFalse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    ContractVerifiedOnly,
}

/// Immutable build identity carried by a plugin evidence receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildProvenance {
    source_commit: String,
    target_triple: String,
    plugin_version: PluginVersion,
    artifact_digest: Digest,
    toolchain: String,
    toolchain_digest: Digest,
    provenance_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuildProvenanceBody<'a> {
    source_commit: &'a str,
    target_triple: &'a str,
    plugin_version: PluginVersion,
    artifact_digest: &'a Digest,
    toolchain: &'a str,
    toolchain_digest: &'a Digest,
}

impl BuildProvenance {
    pub fn new(
        source_commit: impl Into<String>,
        target_triple: impl Into<String>,
        plugin_version: PluginVersion,
        artifact_digest: Digest,
        toolchain: impl Into<String>,
    ) -> Result<Self, PluginEvidenceError> {
        let source_commit = source_commit.into();
        let target_triple = target_triple.into();
        let toolchain = toolchain.into();
        let mut provenance = Self {
            source_commit,
            target_triple,
            plugin_version,
            artifact_digest,
            toolchain_digest: Digest::from_text(toolchain.as_bytes()),
            toolchain,
            provenance_digest: Digest::from_text("pending-plugin-provenance"),
        };
        provenance.validate_without_digest()?;
        provenance.provenance_digest = provenance.computed_digest();
        provenance.validate()?;
        Ok(provenance)
    }

    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    pub const fn plugin_version(&self) -> PluginVersion {
        self.plugin_version
    }

    pub fn artifact_digest(&self) -> &Digest {
        &self.artifact_digest
    }

    pub fn toolchain(&self) -> &str {
        &self.toolchain
    }

    pub fn toolchain_digest(&self) -> &Digest {
        &self.toolchain_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.provenance_digest
    }

    pub fn verify(&self) -> Result<(), PluginEvidenceError> {
        self.validate()
    }

    fn validate_without_digest(&self) -> Result<(), PluginEvidenceError> {
        if !valid_commit(&self.source_commit) {
            return Err(PluginEvidenceError::InvalidSourceCommit);
        }
        if !valid_target(&self.target_triple) {
            return Err(PluginEvidenceError::InvalidTarget);
        }
        if self.toolchain.is_empty()
            || self.toolchain.len() > 256
            || self.toolchain.trim() != self.toolchain
            || self.toolchain.chars().any(char::is_control)
        {
            return Err(PluginEvidenceError::InvalidToolchain);
        }
        self.artifact_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        self.toolchain_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        if self.toolchain_digest != Digest::from_text(self.toolchain.as_bytes()) {
            return Err(PluginEvidenceError::InvalidDigest);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), PluginEvidenceError> {
        self.validate_without_digest()?;
        if self.provenance_digest != self.computed_digest() {
            return Err(PluginEvidenceError::InvalidDigest);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&BuildProvenanceBody {
            source_commit: &self.source_commit,
            target_triple: &self.target_triple,
            plugin_version: self.plugin_version,
            artifact_digest: &self.artifact_digest,
            toolchain: &self.toolchain,
            toolchain_digest: &self.toolchain_digest,
        })
    }
}

/// The typed identities needed by the evidence service/provider/consumer
/// loop. Only digests are persisted; descriptor names and private payloads do
/// not enter the durable receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginEvidenceBinding {
    plugin_id_digest: Digest,
    plugin_version: PluginVersion,
    plugin_digest: Digest,
    scope_digest: Digest,
    registration_receipt_digest: Digest,
    service_id_digest: Digest,
    provider_id_digest: Digest,
    consumer_id_digest: Digest,
    binding_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginEvidenceBindingBody<'a> {
    plugin_id_digest: &'a Digest,
    plugin_version: PluginVersion,
    plugin_digest: &'a Digest,
    scope_digest: &'a Digest,
    registration_receipt_digest: &'a Digest,
    service_id_digest: &'a Digest,
    provider_id_digest: &'a Digest,
    consumer_id_digest: &'a Digest,
}

impl PluginEvidenceBinding {
    pub fn from_mounted_plugin(
        handle: &PluginDefinitionHandle,
        receipt: &RegistrationReceipt,
        service_id: &ServiceId,
        provider_id: &ProviderId,
        consumer_id: &ConsumerId,
    ) -> Result<Self, PluginEvidenceError> {
        receipt.validate()?;
        if receipt.plugin_digest() != handle.digest()
            || receipt.scope_digest() != handle.scope().digest()
        {
            return Err(PluginEvidenceError::InvalidBinding);
        }
        let mut binding = Self {
            plugin_id_digest: Digest::from_text(handle.plugin_id().as_str()),
            plugin_version: handle.version(),
            plugin_digest: handle.digest().clone(),
            scope_digest: handle.scope().digest(),
            registration_receipt_digest: receipt.digest().clone(),
            service_id_digest: Digest::from_text(service_id.as_str()),
            provider_id_digest: Digest::from_text(provider_id.as_str()),
            consumer_id_digest: Digest::from_text(consumer_id.as_str()),
            binding_digest: Digest::from_text("pending-plugin-evidence-binding"),
        };
        binding.validate_without_digest()?;
        binding.binding_digest = binding.computed_digest();
        binding.validate()?;
        Ok(binding)
    }

    pub fn plugin_id_digest(&self) -> &Digest {
        &self.plugin_id_digest
    }

    pub const fn plugin_version(&self) -> PluginVersion {
        self.plugin_version
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.plugin_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn registration_receipt_digest(&self) -> &Digest {
        &self.registration_receipt_digest
    }

    pub fn service_id_digest(&self) -> &Digest {
        &self.service_id_digest
    }

    pub fn provider_id_digest(&self) -> &Digest {
        &self.provider_id_digest
    }

    pub fn consumer_id_digest(&self) -> &Digest {
        &self.consumer_id_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn verify(&self) -> Result<(), PluginEvidenceError> {
        self.validate()
    }

    fn validate_without_digest(&self) -> Result<(), PluginEvidenceError> {
        for digest in [
            &self.plugin_id_digest,
            &self.plugin_digest,
            &self.scope_digest,
            &self.registration_receipt_digest,
            &self.service_id_digest,
            &self.provider_id_digest,
            &self.consumer_id_digest,
        ] {
            digest
                .validate()
                .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), PluginEvidenceError> {
        self.validate_without_digest()?;
        if self.binding_digest != self.computed_digest() {
            return Err(PluginEvidenceError::InvalidBinding);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&PluginEvidenceBindingBody {
            plugin_id_digest: &self.plugin_id_digest,
            plugin_version: self.plugin_version,
            plugin_digest: &self.plugin_digest,
            scope_digest: &self.scope_digest,
            registration_receipt_digest: &self.registration_receipt_digest,
            service_id_digest: &self.service_id_digest,
            provider_id_digest: &self.provider_id_digest,
            consumer_id_digest: &self.consumer_id_digest,
        })
    }
}

/// Service definition for the release-evidence provider. It is read-only:
/// consuming this service can verify a candidate but cannot promote it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PluginEvidenceService;

impl PluginEvidenceService {
    pub const ID: &'static str = PLUGIN_EVIDENCE_SERVICE_ID;

    pub fn definition() -> Result<ServiceDefinition, PluginEvidenceError> {
        ServiceDefinition::read_only(
            ServiceId::new(Self::ID)?,
            PluginVersion::new(1, 0, 0),
            Digest::from_text(PLUGIN_EVIDENCE_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::Exact,
        )
        .map_err(PluginEvidenceError::from)
    }
}

/// Provider that produces unsigned, current-commit-bound evidence. Signing
/// and notarization are deliberately outside this in-process contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginEvidenceProvider {
    id: ProviderId,
    version: PluginVersion,
    implementation_digest: Digest,
}

impl Default for PluginEvidenceProvider {
    fn default() -> Self {
        Self::new(
            ProviderId::new(PLUGIN_EVIDENCE_PROVIDER_ID)
                .expect("the built-in evidence provider id is valid"),
            PluginVersion::new(1, 0, 0),
            Digest::from_text(PLUGIN_PROVENANCE_SCHEMA),
        )
        .expect("the built-in evidence provider is valid")
    }
}

impl PluginEvidenceProvider {
    pub fn new(
        id: ProviderId,
        version: PluginVersion,
        implementation_digest: Digest,
    ) -> Result<Self, PluginEvidenceError> {
        id.validate()?;
        implementation_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        Ok(Self {
            id,
            version,
            implementation_digest,
        })
    }

    pub fn id(&self) -> &ProviderId {
        &self.id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn definition(&self) -> Result<ProviderDefinition, PluginEvidenceError> {
        Ok(ProviderDefinition::new(
            self.id.clone(),
            ServiceId::new(PluginEvidenceService::ID)?,
            self.version,
            self.implementation_digest.clone(),
        )?)
    }

    pub fn generate(
        &self,
        binding: &PluginEvidenceBinding,
        provenance: &BuildProvenance,
    ) -> Result<PluginEvidenceReceipt, PluginEvidenceError> {
        binding.validate()?;
        provenance.validate()?;
        if binding.plugin_version() != provenance.plugin_version() {
            return Err(PluginEvidenceError::ProvenanceMismatch);
        }
        let mut receipt = PluginEvidenceReceipt {
            schema: PLUGIN_EVIDENCE_RECEIPT_SCHEMA.to_owned(),
            receipt_digest: Digest::from_text("pending-plugin-evidence-receipt"),
            binding: binding.clone(),
            provenance: provenance.clone(),
            evidence_provider_id_digest: Digest::from_text(self.id.as_str()),
            provider_implementation_digest: self.implementation_digest.clone(),
            signature_status: SignatureStatus::UnsignedGenerated,
            native_evidence: NativeEvidence::NotProven,
            release_decision: ReleaseDecision::NotEvaluated,
            release_ready: false,
            deployment: false,
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate()?;
        Ok(receipt)
    }
}

/// Consumer used by a release-promotion/evaluation gate. It can verify
/// integrity and provenance, but its successful result remains blocked from
/// release because no detached signature or native evidence is claimed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginEvidenceConsumer {
    id: ConsumerId,
    version: PluginVersion,
    descriptor_digest: Digest,
    evidence_provider_id_digest: Digest,
    provider_implementation_digest: Digest,
}

impl Default for PluginEvidenceConsumer {
    fn default() -> Self {
        Self::new(
            ConsumerId::new(PLUGIN_EVIDENCE_CONSUMER_ID)
                .expect("the built-in evidence consumer id is valid"),
            PluginVersion::new(1, 0, 0),
            Digest::from_text(PLUGIN_EVIDENCE_RECEIPT_SCHEMA),
            &ProviderId::new(PLUGIN_EVIDENCE_PROVIDER_ID)
                .expect("the built-in evidence provider id is valid"),
            Digest::from_text(PLUGIN_PROVENANCE_SCHEMA),
        )
        .expect("the built-in evidence consumer is valid")
    }
}

impl PluginEvidenceConsumer {
    pub fn new(
        id: ConsumerId,
        version: PluginVersion,
        descriptor_digest: Digest,
        evidence_provider_id: &ProviderId,
        provider_implementation_digest: Digest,
    ) -> Result<Self, PluginEvidenceError> {
        id.validate()?;
        descriptor_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        evidence_provider_id.validate()?;
        provider_implementation_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        Ok(Self {
            id,
            version,
            descriptor_digest,
            evidence_provider_id_digest: Digest::from_text(evidence_provider_id.as_str()),
            provider_implementation_digest,
        })
    }

    pub fn id(&self) -> &ConsumerId {
        &self.id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn descriptor_digest(&self) -> &Digest {
        &self.descriptor_digest
    }

    pub fn definition(&self) -> Result<ConsumerDefinition, PluginEvidenceError> {
        Ok(ConsumerDefinition::tool(
            self.id.clone(),
            ServiceId::new(PluginEvidenceService::ID)?,
            self.version,
            self.descriptor_digest.clone(),
        )?)
    }

    pub fn verify(
        &self,
        receipt: &PluginEvidenceReceipt,
        current_provenance: &BuildProvenance,
        revocation: Option<&PluginEvidenceRevocation>,
    ) -> Result<PluginVerificationReceipt, PluginEvidenceError> {
        receipt.validate()?;
        current_provenance.validate()?;
        if receipt.provenance != *current_provenance {
            return Err(PluginEvidenceError::ProvenanceMismatch);
        }
        if receipt.evidence_provider_id_digest != self.evidence_provider_id_digest
            || receipt.provider_implementation_digest != self.provider_implementation_digest
        {
            return Err(PluginEvidenceError::ProviderMismatch);
        }
        if let Some(revocation) = revocation {
            revocation.validate()?;
            if revocation.plugin_digest() != receipt.binding.plugin_digest()
                || revocation.scope_digest() != receipt.binding.scope_digest()
            {
                return Err(PluginEvidenceError::RevocationMismatch);
            }
            return Err(PluginEvidenceError::Revoked);
        }
        let mut verification = PluginVerificationReceipt {
            schema: PLUGIN_VERIFICATION_RECEIPT_SCHEMA.to_owned(),
            verification_digest: Digest::from_text("pending-plugin-verification-receipt"),
            evidence_receipt_digest: receipt.digest().clone(),
            provenance_digest: current_provenance.digest().clone(),
            consumer_id_digest: Digest::from_text(self.id.as_str()),
            revocation_digest: None,
            status: VerificationStatus::ContractVerifiedOnly,
            decision: VerificationDecision::BlockedReleaseFalse,
            release_ready: false,
            native_evidence: NativeEvidence::NotProven,
        };
        verification.verification_digest = verification.computed_digest();
        verification.verify()?;
        Ok(verification)
    }

    pub fn revoke(
        &self,
        binding: &PluginEvidenceBinding,
        revocation_epoch: u64,
        reason_code: impl Into<String>,
    ) -> Result<PluginEvidenceRevocation, PluginEvidenceError> {
        let _ = self;
        PluginEvidenceRevocation::new(binding, revocation_epoch, reason_code)
    }
}

/// Durable, content-free revocation state. An exact plugin and scope match is
/// required; a mismatched or tampered revocation record is rejected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginEvidenceRevocation {
    plugin_digest: Digest,
    scope_digest: Digest,
    revocation_epoch: u64,
    reason_code: String,
    revocation_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginEvidenceRevocationBody<'a> {
    plugin_digest: &'a Digest,
    scope_digest: &'a Digest,
    revocation_epoch: u64,
    reason_code: &'a str,
}

impl PluginEvidenceRevocation {
    pub fn new(
        binding: &PluginEvidenceBinding,
        revocation_epoch: u64,
        reason_code: impl Into<String>,
    ) -> Result<Self, PluginEvidenceError> {
        binding.validate()?;
        let reason_code = reason_code.into();
        if revocation_epoch == 0 || !valid_reason_code(&reason_code) {
            return Err(PluginEvidenceError::InvalidBinding);
        }
        let mut revocation = Self {
            plugin_digest: binding.plugin_digest().clone(),
            scope_digest: binding.scope_digest().clone(),
            revocation_epoch,
            reason_code,
            revocation_digest: Digest::from_text("pending-plugin-revocation"),
        };
        revocation.revocation_digest = revocation.computed_digest();
        revocation.validate()?;
        Ok(revocation)
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.plugin_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }

    pub fn digest(&self) -> &Digest {
        &self.revocation_digest
    }

    pub fn verify(&self) -> Result<(), PluginEvidenceError> {
        self.validate()
    }

    fn validate(&self) -> Result<(), PluginEvidenceError> {
        self.plugin_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        self.scope_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        if self.revocation_epoch == 0 || !valid_reason_code(&self.reason_code) {
            return Err(PluginEvidenceError::InvalidBinding);
        }
        if self.revocation_digest != self.computed_digest() {
            return Err(PluginEvidenceError::InvalidDigest);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&PluginEvidenceRevocationBody {
            plugin_digest: &self.plugin_digest,
            scope_digest: &self.scope_digest,
            revocation_epoch: self.revocation_epoch,
            reason_code: &self.reason_code,
        })
    }
}

/// Durable provider output. It contains only identity and digest metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginEvidenceReceipt {
    schema: String,
    receipt_digest: Digest,
    binding: PluginEvidenceBinding,
    provenance: BuildProvenance,
    evidence_provider_id_digest: Digest,
    provider_implementation_digest: Digest,
    signature_status: SignatureStatus,
    native_evidence: NativeEvidence,
    release_decision: ReleaseDecision,
    release_ready: bool,
    deployment: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginEvidenceReceiptBody<'a> {
    schema: &'a str,
    binding: &'a PluginEvidenceBinding,
    provenance: &'a BuildProvenance,
    evidence_provider_id_digest: &'a Digest,
    provider_implementation_digest: &'a Digest,
    signature_status: SignatureStatus,
    native_evidence: NativeEvidence,
    release_decision: ReleaseDecision,
    release_ready: bool,
    deployment: bool,
}

impl PluginEvidenceReceipt {
    pub fn from_json(document: &str) -> Result<Self, PluginEvidenceError> {
        let receipt: Self = serde_json::from_str(document)
            .map_err(|error| PluginEvidenceError::InvalidDocument(error.to_string()))?;
        receipt.verify()?;
        Ok(receipt)
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn binding(&self) -> &PluginEvidenceBinding {
        &self.binding
    }

    pub fn provenance(&self) -> &BuildProvenance {
        &self.provenance
    }

    pub fn evidence_provider_id_digest(&self) -> &Digest {
        &self.evidence_provider_id_digest
    }

    pub const fn signature_status(&self) -> SignatureStatus {
        self.signature_status
    }

    pub const fn native_evidence(&self) -> NativeEvidence {
        self.native_evidence
    }

    pub const fn release_decision(&self) -> ReleaseDecision {
        self.release_decision
    }

    pub const fn release_ready(&self) -> bool {
        self.release_ready
    }

    pub const fn deployment(&self) -> bool {
        self.deployment
    }

    pub fn verify(&self) -> Result<(), PluginEvidenceError> {
        self.validate()
    }

    fn validate(&self) -> Result<(), PluginEvidenceError> {
        if self.schema != PLUGIN_EVIDENCE_RECEIPT_SCHEMA {
            return Err(PluginEvidenceError::InvalidReceiptSchema);
        }
        self.binding.validate()?;
        self.provenance.validate()?;
        self.evidence_provider_id_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        self.provider_implementation_digest
            .validate()
            .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        if self.signature_status != SignatureStatus::UnsignedGenerated
            || self.native_evidence != NativeEvidence::NotProven
            || self.release_decision != ReleaseDecision::NotEvaluated
            || self.release_ready
            || self.deployment
        {
            return Err(PluginEvidenceError::HonestyViolation);
        }
        if self.receipt_digest != self.computed_digest() {
            return Err(PluginEvidenceError::ReceiptDigestMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&PluginEvidenceReceiptBody {
            schema: &self.schema,
            binding: &self.binding,
            provenance: &self.provenance,
            evidence_provider_id_digest: &self.evidence_provider_id_digest,
            provider_implementation_digest: &self.provider_implementation_digest,
            signature_status: self.signature_status,
            native_evidence: self.native_evidence,
            release_decision: self.release_decision,
            release_ready: self.release_ready,
            deployment: self.deployment,
        })
    }
}

/// Durable consumer output. `ContractVerifiedOnly` is intentionally weaker
/// than a detached-signature or native release result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginVerificationReceipt {
    schema: String,
    verification_digest: Digest,
    evidence_receipt_digest: Digest,
    provenance_digest: Digest,
    consumer_id_digest: Digest,
    revocation_digest: Option<Digest>,
    status: VerificationStatus,
    decision: VerificationDecision,
    release_ready: bool,
    native_evidence: NativeEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginVerificationReceiptBody<'a> {
    schema: &'a str,
    evidence_receipt_digest: &'a Digest,
    provenance_digest: &'a Digest,
    consumer_id_digest: &'a Digest,
    revocation_digest: Option<&'a Digest>,
    status: VerificationStatus,
    decision: VerificationDecision,
    release_ready: bool,
    native_evidence: NativeEvidence,
}

impl PluginVerificationReceipt {
    pub fn from_json(document: &str) -> Result<Self, PluginEvidenceError> {
        let receipt: Self = serde_json::from_str(document)
            .map_err(|error| PluginEvidenceError::InvalidDocument(error.to_string()))?;
        receipt.verify()?;
        Ok(receipt)
    }

    pub fn digest(&self) -> &Digest {
        &self.verification_digest
    }

    pub fn evidence_receipt_digest(&self) -> &Digest {
        &self.evidence_receipt_digest
    }

    pub fn provenance_digest(&self) -> &Digest {
        &self.provenance_digest
    }

    pub const fn status(&self) -> VerificationStatus {
        self.status
    }

    pub const fn decision(&self) -> VerificationDecision {
        self.decision
    }

    pub const fn release_ready(&self) -> bool {
        self.release_ready
    }

    pub const fn native_evidence(&self) -> NativeEvidence {
        self.native_evidence
    }

    pub fn verify(&self) -> Result<(), PluginEvidenceError> {
        if self.schema != PLUGIN_VERIFICATION_RECEIPT_SCHEMA {
            return Err(PluginEvidenceError::InvalidVerificationSchema);
        }
        for digest in [
            &self.evidence_receipt_digest,
            &self.provenance_digest,
            &self.consumer_id_digest,
        ] {
            digest
                .validate()
                .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        }
        if let Some(revocation_digest) = &self.revocation_digest {
            revocation_digest
                .validate()
                .map_err(|_| PluginEvidenceError::InvalidDigest)?;
        }
        if self.status != VerificationStatus::ContractVerifiedOnly
            || self.decision != VerificationDecision::BlockedReleaseFalse
            || self.release_ready
            || self.native_evidence != NativeEvidence::NotProven
        {
            return Err(PluginEvidenceError::HonestyViolation);
        }
        if self.verification_digest != self.computed_digest() {
            return Err(PluginEvidenceError::VerificationDigestMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&PluginVerificationReceiptBody {
            schema: &self.schema,
            evidence_receipt_digest: &self.evidence_receipt_digest,
            provenance_digest: &self.provenance_digest,
            consumer_id_digest: &self.consumer_id_digest,
            revocation_digest: self.revocation_digest.as_ref(),
            status: self.status,
            decision: self.decision,
            release_ready: self.release_ready,
            native_evidence: self.native_evidence,
        })
    }
}

fn valid_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::{
        BuildProvenance, NativeEvidence, PluginEvidenceConsumer, PluginEvidenceError,
        PluginEvidenceProvider, PluginEvidenceRevocation, PluginEvidenceService, ReleaseDecision,
        SignatureStatus, VerificationDecision, VerificationStatus,
    };
    use crate::{
        ConsumerId, Digest, PluginError, PluginRuntime, PluginVersion, ProviderId, ServiceId,
        sample::SampleReadOnlyPlugin,
    };

    fn mounted() -> (
        PluginRuntime,
        crate::PluginDefinitionHandle,
        crate::RegistrationReceipt,
    ) {
        let scope = SampleReadOnlyPlugin::default_scope().expect("scope");
        let definition = SampleReadOnlyPlugin::definition(scope, PluginVersion::new(1, 0, 0))
            .expect("definition");
        let mut runtime = PluginRuntime::new();
        let handle = runtime.define(definition).expect("define");
        let receipt = runtime.mount(&handle).expect("mount");
        (runtime, handle, receipt)
    }

    fn provenance(version: PluginVersion) -> BuildProvenance {
        BuildProvenance::new(
            "114abe2bc04d77d1eca4efea64092b37a0b0fb06",
            "aarch64-apple-darwin",
            version,
            Digest::from_text("sample-artifact"),
            "rustc 1.95.0 (contract-test)",
        )
        .expect("provenance")
    }

    #[test]
    fn typed_service_provider_consumer_bind_current_commit_and_emit_honest_receipts() {
        let (_runtime, handle, mount_receipt) = mounted();
        let service = PluginEvidenceService::definition().expect("service");
        let provider = PluginEvidenceProvider::default();
        let consumer = PluginEvidenceConsumer::default();
        assert_eq!(service.id().as_str(), PluginEvidenceService::ID);
        assert_eq!(
            provider.definition().expect("provider").service_id(),
            service.id()
        );
        assert_eq!(
            consumer.definition().expect("consumer").service_id(),
            service.id()
        );

        let binding = super::PluginEvidenceBinding::from_mounted_plugin(
            &handle,
            &mount_receipt,
            &ServiceId::new("sample.read").expect("service id"),
            &ProviderId::new("sample.read.provider").expect("provider id"),
            &ConsumerId::new("sample.read.tool").expect("consumer id"),
        )
        .expect("binding");
        let build = provenance(handle.version());
        let evidence = provider.generate(&binding, &build).expect("evidence");
        assert_eq!(
            evidence.signature_status(),
            SignatureStatus::UnsignedGenerated
        );
        assert_eq!(evidence.native_evidence(), NativeEvidence::NotProven);
        assert_eq!(evidence.release_decision(), ReleaseDecision::NotEvaluated);
        assert!(!evidence.release_ready());
        let verification = consumer.verify(&evidence, &build, None).expect("verify");
        assert_eq!(
            verification.status(),
            VerificationStatus::ContractVerifiedOnly
        );
        assert_eq!(
            verification.decision(),
            VerificationDecision::BlockedReleaseFalse
        );
        assert!(!verification.release_ready());
        assert_eq!(verification.native_evidence(), NativeEvidence::NotProven);
    }

    #[test]
    fn tampered_durable_receipt_fails_closed() {
        let (_runtime, handle, mount_receipt) = mounted();
        let binding = super::PluginEvidenceBinding::from_mounted_plugin(
            &handle,
            &mount_receipt,
            &ServiceId::new("sample.read").expect("service id"),
            &ProviderId::new("sample.read.provider").expect("provider id"),
            &ConsumerId::new("sample.read.tool").expect("consumer id"),
        )
        .expect("binding");
        let evidence = PluginEvidenceProvider::default()
            .generate(&binding, &provenance(handle.version()))
            .expect("evidence");
        let mut document = serde_json::to_value(&evidence).expect("json");
        document["providerImplementationDigest"] =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        let tampered: super::PluginEvidenceReceipt =
            serde_json::from_value(document).expect("decode tampered receipt");
        assert_eq!(
            tampered.verify(),
            Err(PluginEvidenceError::ReceiptDigestMismatch)
        );
        assert!(
            PluginEvidenceError::from(PluginError::InvalidReceipt)
                .to_string()
                .contains("plugin runtime")
        );
    }

    #[test]
    fn current_commit_target_drift_and_revocation_fail_closed() {
        let (_runtime, handle, mount_receipt) = mounted();
        let binding = super::PluginEvidenceBinding::from_mounted_plugin(
            &handle,
            &mount_receipt,
            &ServiceId::new("sample.read").expect("service id"),
            &ProviderId::new("sample.read.provider").expect("provider id"),
            &ConsumerId::new("sample.read.tool").expect("consumer id"),
        )
        .expect("binding");
        let provider = PluginEvidenceProvider::default();
        let consumer = PluginEvidenceConsumer::default();
        let build = provenance(handle.version());
        let evidence = provider.generate(&binding, &build).expect("evidence");
        let drifted = provenance_with_commit("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            consumer.verify(&evidence, &drifted, None),
            Err(PluginEvidenceError::ProvenanceMismatch)
        );
        let revocation =
            PluginEvidenceRevocation::new(&binding, 2, "key-revoked").expect("revocation");
        assert_eq!(
            consumer.verify(&evidence, &build, Some(&revocation)),
            Err(PluginEvidenceError::Revoked)
        );
        let mut tampered_revocation = serde_json::to_value(&revocation).expect("json");
        tampered_revocation["revocationEpoch"] = serde_json::json!(3);
        let tampered_revocation: super::PluginEvidenceRevocation =
            serde_json::from_value(tampered_revocation).expect("decode tampered revocation");
        assert_eq!(
            tampered_revocation.verify(),
            Err(PluginEvidenceError::InvalidDigest)
        );
    }

    fn provenance_with_commit(commit: &str) -> BuildProvenance {
        BuildProvenance::new(
            commit,
            "aarch64-apple-darwin",
            PluginVersion::new(1, 0, 0),
            Digest::from_text("sample-artifact"),
            "rustc 1.95.0 (contract-test)",
        )
        .expect("provenance")
    }
}
