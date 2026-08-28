//! Typed read/proposal/record/verify service surface.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, SecretReference, VaultGovernanceEvidence, VaultReadRequest, VaultScope,
    digest_serializable,
};
use crate::provider::{
    VaultProvider, VaultProviderDefinition, VaultRegistration, validate_lifecycle_generation,
};
use crate::transport::VaultTransport;
use crate::{
    MISSION_VAULT_GOVERNANCE_CONSUMER_ID, VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION,
    VAULT_GOVERNANCE_RESULT_SERVICE_ID, VAULT_GOVERNANCE_RESULT_SERVICE_SCHEMA,
    VaultGovernanceError, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultGovernanceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ProposeGovernanceRead,
    RecordEvidence,
    VerifyEvidence,
    ConsumeObservation,
}

impl VaultGovernanceOperation {
    pub const ALL: [Self; 7] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ProposeGovernanceRead,
        Self::RecordEvidence,
        Self::VerifyEvidence,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultGovernanceCapability {
    pub capability_id: String,
    pub operation: VaultGovernanceOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultGovernanceResultService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<VaultGovernanceCapability>,
}

impl Default for VaultGovernanceResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultGovernanceResultService {
    pub fn new() -> Self {
        let capabilities = [
            (
                "vault.governance.result.register",
                VaultGovernanceOperation::Register,
            ),
            (
                "vault.governance.result.revoke_registration",
                VaultGovernanceOperation::RevokeRegistration,
            ),
            (
                "vault.governance.result.propose_governance_read",
                VaultGovernanceOperation::ProposeGovernanceRead,
            ),
            (
                "vault.governance.result.record_evidence",
                VaultGovernanceOperation::RecordEvidence,
            ),
            (
                "vault.governance.result.verify_evidence",
                VaultGovernanceOperation::VerifyEvidence,
            ),
            (
                "vault.governance.result.consume_observation",
                VaultGovernanceOperation::ConsumeObservation,
            ),
        ]
        .into_iter()
        .map(|(capability_id, operation)| VaultGovernanceCapability {
            capability_id: capability_id.to_owned(),
            operation,
            read_only: true,
            mutates_provider: false,
            native_evidence: false,
        })
        .collect();
        Self {
            service_id: VAULT_GOVERNANCE_RESULT_SERVICE_ID.to_owned(),
            service_name: "VaultGovernanceResultService".to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[VaultGovernanceCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<VaultGovernanceCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, VaultGovernanceError> {
        let service_id = ServiceId::new(self.service_id.clone())?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(VAULT_GOVERNANCE_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(VaultGovernanceError::from)
    }

    pub fn validate(&self) -> Result<(), VaultGovernanceError> {
        if self.service_id != VAULT_GOVERNANCE_RESULT_SERVICE_ID
            || self.service_name != "VaultGovernanceResultService"
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(VaultGovernanceError::Contract(
                "Vault service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn register<T: VaultTransport>(
        &self,
        scope: VaultScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<VaultProvider<T>, VaultGovernanceError> {
        self.validate()?;
        Ok(VaultProvider::new(scope, secret_reference, transport)?)
    }

    pub fn revoke_registration<T: VaultTransport>(
        &self,
        provider: &mut VaultProvider<T>,
        at_unix_seconds: u64,
    ) -> Result<(), VaultGovernanceError> {
        self.validate()?;
        provider.revoke_registration(at_unix_seconds)?;
        Ok(())
    }

    pub fn propose<T: VaultTransport>(
        &self,
        provider: &mut VaultProvider<T>,
        request: &VaultReadRequest,
    ) -> Result<VaultGovernanceProposal, VaultGovernanceError> {
        self.validate()?;
        let evidence = provider.read(request)?;
        Ok(VaultGovernanceProposal::new(evidence))
    }

    pub fn read<T: VaultTransport>(
        &self,
        provider: &mut VaultProvider<T>,
        request: &VaultReadRequest,
    ) -> Result<VaultGovernanceProposal, VaultGovernanceError> {
        self.propose(provider, request)
    }

    pub fn record(
        &self,
        proposal: VaultGovernanceProposal,
    ) -> Result<VaultGovernanceRecord, VaultGovernanceError> {
        self.validate()?;
        proposal.validate()?;
        Ok(VaultGovernanceRecord::new(proposal.evidence))
    }

    pub fn verify(
        &self,
        record: &VaultGovernanceRecord,
        scope: &VaultScope,
    ) -> Result<VaultVerification, VaultGovernanceError> {
        self.validate()?;
        record.validate()?;
        let evidence = record.evidence();
        validate_lifecycle_generation(
            &evidence.registration_digest,
            evidence.lifecycle_generation,
        )?;
        if evidence.scope_digest != scope.scope_digest()
            || !scope.is_secret_bound()
            || evidence.secret_reference_digest
                != *scope
                    .secret_reference_digest()
                    .ok_or(VaultGovernanceError::ScopeMismatch)?
            || evidence.credential_revision
                != scope
                    .credential_revision()
                    .ok_or(VaultGovernanceError::ScopeMismatch)?
            || evidence.secret_role
                != scope
                    .secret_role()
                    .ok_or(VaultGovernanceError::ScopeMismatch)?
            || evidence.valid_from_unix_seconds
                != scope
                    .valid_from_unix_seconds()
                    .ok_or(VaultGovernanceError::ScopeMismatch)?
            || evidence.valid_until_unix_seconds
                != scope
                    .valid_until_unix_seconds()
                    .ok_or(VaultGovernanceError::ScopeMismatch)?
            || evidence.contract_digest != contract_digest()
            || evidence.provider_revision != crate::VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION
        {
            return Err(VaultGovernanceError::ScopeMismatch);
        }
        let provider_definition =
            VaultProviderDefinition::new(evidence.provider_version.clone(), evidence.provenance)
                .map_err(|error| VaultGovernanceError::Provider(error.into()))?;
        if provider_definition.provider_digest != evidence.provider_digest {
            return Err(VaultGovernanceError::EvidenceDigestMismatch);
        }
        let expected_registration = VaultRegistration::expected_registration_digest(
            scope,
            &provider_definition.provider_digest,
            &evidence.secret_reference_digest,
            evidence.credential_revision.get(),
            evidence.secret_role,
            evidence.valid_from_unix_seconds,
            evidence.valid_until_unix_seconds,
        );
        if expected_registration != evidence.registration_digest {
            return Err(VaultGovernanceError::EvidenceDigestMismatch);
        }
        Ok(VaultVerification {
            verified: true,
            contract_digest: record.evidence.contract_digest.clone(),
            provider_digest: record.evidence.provider_digest.clone(),
            scope_digest: record.evidence.scope_digest.clone(),
            evidence_digest: record.evidence.evidence_digest.clone(),
            lifecycle_generation: evidence.lifecycle_generation,
            native_authority: false,
            truth_authority: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &VaultGovernanceEvidence,
        scope: &VaultScope,
    ) -> Result<VaultVerification, VaultGovernanceError> {
        let record = VaultGovernanceRecord::new(evidence.clone());
        self.verify(&record, scope)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VaultGovernanceProposal {
    evidence: VaultGovernanceEvidence,
    proposal_digest: Digest,
    lifecycle_generation: u64,
}

impl VaultGovernanceProposal {
    fn new(evidence: VaultGovernanceEvidence) -> Self {
        let lifecycle_generation = evidence.lifecycle_generation;
        let proposal_digest = digest_serializable(&(
            &evidence,
            lifecycle_generation,
            "vault-governance-proposal/v1",
        ));
        Self {
            evidence,
            proposal_digest,
            lifecycle_generation,
        }
    }

    pub fn validate(&self) -> Result<(), VaultGovernanceError> {
        self.evidence.validate()?;
        validate_lifecycle_generation(
            &self.evidence.registration_digest,
            self.lifecycle_generation,
        )?;
        if self.evidence.lifecycle_generation != self.lifecycle_generation
            || digest_serializable(&(
                &self.evidence,
                self.lifecycle_generation,
                "vault-governance-proposal/v1",
            )) != self.proposal_digest
        {
            return Err(VaultGovernanceError::EvidenceDigestMismatch);
        }
        Ok(())
    }

    pub fn evidence(&self) -> &VaultGovernanceEvidence {
        &self.evidence
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VaultGovernanceRecord {
    evidence: VaultGovernanceEvidence,
    record_digest: Digest,
    lifecycle_generation: u64,
}

impl VaultGovernanceRecord {
    fn new(evidence: VaultGovernanceEvidence) -> Self {
        let lifecycle_generation = evidence.lifecycle_generation;
        let record_digest = digest_serializable(&(
            &evidence,
            lifecycle_generation,
            "vault-governance-record/v1",
        ));
        Self {
            evidence,
            record_digest,
            lifecycle_generation,
        }
    }

    pub fn validate(&self) -> Result<(), VaultGovernanceError> {
        self.evidence.validate()?;
        validate_lifecycle_generation(
            &self.evidence.registration_digest,
            self.lifecycle_generation,
        )?;
        if self.evidence.lifecycle_generation != self.lifecycle_generation
            || digest_serializable(&(
                &self.evidence,
                self.lifecycle_generation,
                "vault-governance-record/v1",
            )) != self.record_digest
        {
            return Err(VaultGovernanceError::EvidenceDigestMismatch);
        }
        Ok(())
    }

    pub fn evidence(&self) -> &VaultGovernanceEvidence {
        &self.evidence
    }

    pub fn record_digest(&self) -> &Digest {
        &self.record_digest
    }

    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultVerification {
    pub verified: bool,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub lifecycle_generation: u64,
    pub native_authority: bool,
    pub truth_authority: bool,
    pub adopted_outcome: bool,
}

pub const fn service_contract_version() -> &'static str {
    VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION
}

pub const fn service_consumer_id() -> &'static str {
    MISSION_VAULT_GOVERNANCE_CONSUMER_ID
}

pub fn service_contract_digest() -> Digest {
    contract_digest()
}
