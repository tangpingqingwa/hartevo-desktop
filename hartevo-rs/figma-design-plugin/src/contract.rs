use serde::Deserialize;
use thiserror::Error;

use crate::types::{
    FigmaEvidenceClass, FigmaProviderMode, MAX_EXPORT_BYTES, MAX_NODE_IDS, MAX_RETRY_ATTEMPTS,
    MAX_VERSION_PAGE_SIZE, MAX_VERSION_PAGES, Sha256Digest,
};

pub const FIGMA_DESIGN_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/figma-design/figma-design.v1.json");
pub const FIGMA_DESIGN_SCHEMA_VERSION: &str = "hartevo.figma-design-plugin-contract/v1";
pub const FIGMA_DESIGN_CONTRACT_VERSION: &str = "figma-design-layer1/v1";
pub const FIGMA_DESIGN_EVIDENCE_LEVEL: &str = "E1";

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FigmaContractError {
    #[error("contract JSON could not be decoded: {0}")]
    Decode(String),
    #[error("contract schema version is not the Layer-1 baseline")]
    SchemaVersion,
    #[error("contract version is not the Layer-1 baseline")]
    ContractVersion,
    #[error("contract authority is not read-only and non-native")]
    Authority,
    #[error("contract secret material policy is not opaque-reference-only")]
    SecretMaterial,
    #[error("contract operation set is not exact")]
    Operations,
    #[error("contract scope binding set is not exact")]
    ScopeBindings,
    #[error("contract provider mode set is not exact")]
    ProviderModes,
    #[error("contract limit set is not exact")]
    Limits,
    #[error("contract Layer-2 gap set is not exact")]
    Layer2Gaps,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SecretMaterialPolicy {
    OpaqueReferenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ContractOperation {
    FileMetadata,
    VersionHistory,
    NodeMetadata,
    BoundedExportMetadata,
    DesignResultRecord,
    AdoptionProposal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScopeBinding {
    Tenant,
    HartevoProject,
    Mission,
    Team,
    FigmaProject,
    File,
    Node,
    Version,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Layer2Gap {
    FileCommentBranchVariablePermissionWrites,
    WebhookRegistrationAndReconciliation,
    DurableExternalExportReceipt,
    IndependentProviderReadback,
    VerifiedWorkProductAdoption,
    NativeConnectedEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct FigmaContractLimits {
    max_node_ids: usize,
    max_version_pages: usize,
    max_version_page_size: usize,
    max_export_bytes: u64,
    max_retry_attempts: u8,
}

impl FigmaContractLimits {
    #[must_use]
    pub const fn max_node_ids(&self) -> usize {
        self.max_node_ids
    }

    #[must_use]
    pub const fn max_version_pages(&self) -> usize {
        self.max_version_pages
    }

    #[must_use]
    pub const fn max_version_page_size(&self) -> usize {
        self.max_version_page_size
    }

    #[must_use]
    pub const fn max_export_bytes(&self) -> u64 {
        self.max_export_bytes
    }

    #[must_use]
    pub const fn max_retry_attempts(&self) -> u8 {
        self.max_retry_attempts
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FigmaDesignContract {
    #[serde(rename = "$schema")]
    schema_uri: String,
    #[serde(rename = "$id")]
    contract_uri: String,
    title: String,
    description: String,
    schema_version: String,
    contract_version: String,
    evidence_level: String,
    read_only: bool,
    connected: bool,
    native: bool,
    secret_material: SecretMaterialPolicy,
    operations: Vec<ContractOperation>,
    scope_bindings: Vec<ScopeBinding>,
    provider_modes: Vec<FigmaProviderMode>,
    limits: FigmaContractLimits,
    layer2_gaps: Vec<Layer2Gap>,
}

impl FigmaDesignContract {
    pub fn baseline() -> Result<Self, FigmaContractError> {
        Self::from_json(FIGMA_DESIGN_CONTRACT_JSON)
    }

    pub fn from_json(value: &str) -> Result<Self, FigmaContractError> {
        let contract = serde_json::from_str::<Self>(value)
            .map_err(|error| FigmaContractError::Decode(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), FigmaContractError> {
        if self.schema_uri.is_empty()
            || self.contract_uri.is_empty()
            || self.title.is_empty()
            || self.description.is_empty()
        {
            return Err(FigmaContractError::Decode(
                "missing contract metadata".into(),
            ));
        }
        if self.schema_version != FIGMA_DESIGN_SCHEMA_VERSION {
            return Err(FigmaContractError::SchemaVersion);
        }
        if self.contract_version != FIGMA_DESIGN_CONTRACT_VERSION
            || self.evidence_level != FIGMA_DESIGN_EVIDENCE_LEVEL
        {
            return Err(FigmaContractError::ContractVersion);
        }
        if !self.read_only || self.connected || self.native {
            return Err(FigmaContractError::Authority);
        }
        if self.secret_material != SecretMaterialPolicy::OpaqueReferenceOnly {
            return Err(FigmaContractError::SecretMaterial);
        }
        if self.operations
            != vec![
                ContractOperation::FileMetadata,
                ContractOperation::VersionHistory,
                ContractOperation::NodeMetadata,
                ContractOperation::BoundedExportMetadata,
                ContractOperation::DesignResultRecord,
                ContractOperation::AdoptionProposal,
            ]
        {
            return Err(FigmaContractError::Operations);
        }
        if self.scope_bindings
            != vec![
                ScopeBinding::Tenant,
                ScopeBinding::HartevoProject,
                ScopeBinding::Mission,
                ScopeBinding::Team,
                ScopeBinding::FigmaProject,
                ScopeBinding::File,
                ScopeBinding::Node,
                ScopeBinding::Version,
            ]
        {
            return Err(FigmaContractError::ScopeBindings);
        }
        if self.provider_modes
            != vec![
                FigmaProviderMode::Fixture,
                FigmaProviderMode::Loopback,
                FigmaProviderMode::BlockedEnv,
            ]
        {
            return Err(FigmaContractError::ProviderModes);
        }
        if self.limits.max_node_ids != MAX_NODE_IDS
            || self.limits.max_version_pages != MAX_VERSION_PAGES
            || self.limits.max_version_page_size != MAX_VERSION_PAGE_SIZE
            || self.limits.max_export_bytes != MAX_EXPORT_BYTES
            || self.limits.max_retry_attempts != MAX_RETRY_ATTEMPTS
        {
            return Err(FigmaContractError::Limits);
        }
        if self.layer2_gaps
            != vec![
                Layer2Gap::FileCommentBranchVariablePermissionWrites,
                Layer2Gap::WebhookRegistrationAndReconciliation,
                Layer2Gap::DurableExternalExportReceipt,
                Layer2Gap::IndependentProviderReadback,
                Layer2Gap::VerifiedWorkProductAdoption,
                Layer2Gap::NativeConnectedEvidence,
            ]
        {
            return Err(FigmaContractError::Layer2Gaps);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(FIGMA_DESIGN_CONTRACT_JSON.as_bytes())
    }

    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn evidence_level(&self) -> &str {
        &self.evidence_level
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub fn limits(&self) -> &FigmaContractLimits {
        &self.limits
    }

    #[must_use]
    pub fn provider_modes(&self) -> &[FigmaProviderMode] {
        &self.provider_modes
    }

    #[must_use]
    pub const fn evidence_class_for_mode(mode: FigmaProviderMode) -> FigmaEvidenceClass {
        FigmaEvidenceClass::for_mode(mode)
    }
}
