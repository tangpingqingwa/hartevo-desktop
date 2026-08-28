use serde::{Deserialize, Serialize};

use crate::{
    error::{MicrosoftGraphSharePointProviderError, SharePointKnowledgeResultError},
    model::{
        DriveItemChildrenEvidence, DriveItemDeltaEvidence, DriveItemMetadataEvidence,
        DriveItemReadRequest, DriveItemSearchEvidence, DriveItemVersionsEvidence,
        MissionWorkProduct, SharePointCapability, SharePointKnowledgeEvidence,
        SharePointKnowledgeReadRequest, SharePointKnowledgeResultProposal,
        SharePointKnowledgeScope, SharePointPluginRegistration, SharePointScopeDescription,
        SharePointSearchRequest,
    },
    provider::{EntraCredentialResolver, MicrosoftGraphSharePointProvider},
    transport::MicrosoftGraphSharePointTransport,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharePointKnowledgeResultOperation {
    DescribeScope,
    ReadDriveItemMetadata,
    ReadDriveItemChildren,
    SearchDriveItems,
    ReadDriveItemVersions,
    ReadDriveItemDelta,
    CompileKnowledgeResult,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointKnowledgeResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub operations: Vec<SharePointKnowledgeResultOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub durable_native_receipts: bool,
    pub independent_readback: bool,
    pub kernel_outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl SharePointKnowledgeResultServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: crate::SHAREPOINT_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::SHAREPOINT_CONTRACT_VERSION.to_owned(),
            service_id: crate::SHAREPOINT_SERVICE_ID.to_owned(),
            provider_id: crate::SHAREPOINT_PROVIDER_ID.to_owned(),
            consumer_id: crate::SHAREPOINT_MISSION_CONSUMER_ID.to_owned(),
            plugin_id: crate::SHAREPOINT_PLUGIN_ID.to_owned(),
            plugin_version: crate::SHAREPOINT_PLUGIN_VERSION.to_owned(),
            operations: vec![
                SharePointKnowledgeResultOperation::DescribeScope,
                SharePointKnowledgeResultOperation::ReadDriveItemMetadata,
                SharePointKnowledgeResultOperation::ReadDriveItemChildren,
                SharePointKnowledgeResultOperation::SearchDriveItems,
                SharePointKnowledgeResultOperation::ReadDriveItemVersions,
                SharePointKnowledgeResultOperation::ReadDriveItemDelta,
                SharePointKnowledgeResultOperation::CompileKnowledgeResult,
            ],
            read_only: true,
            external_writes: false,
            durable_native_receipts: false,
            independent_readback: false,
            kernel_outcome_authority: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        let expected = Self::layer1();
        if self != &expected {
            return Err(SharePointKnowledgeResultError::ExternalWriteAuthority);
        }
        Ok(())
    }
}

/// Typed Layer 1 service. It exposes bounded projections and a redacted
/// non-mutating proposal only; receipts/readback/adoption belong to Layer 2.
pub struct SharePointKnowledgeResultService<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    provider: MicrosoftGraphSharePointProvider<T, R>,
    definition: SharePointKnowledgeResultServiceDefinition,
    bound_registration_digest: String,
}

impl<T, R> std::fmt::Debug for SharePointKnowledgeResultService<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharePointKnowledgeResultService")
            .field("bound_registration_digest", &self.bound_registration_digest)
            .field("definition", &self.definition)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T, R> SharePointKnowledgeResultService<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    pub fn new(
        provider: MicrosoftGraphSharePointProvider<T, R>,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        let definition = SharePointKnowledgeResultServiceDefinition::layer1();
        definition.validate()?;
        provider
            .registration()
            .validate(&provider.registration().scope, provider.provider_manifest())?;
        Ok(Self {
            bound_registration_digest: provider.registration().registration_digest.clone(),
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &SharePointKnowledgeResultServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &MicrosoftGraphSharePointProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut MicrosoftGraphSharePointProvider<T, R> {
        &mut self.provider
    }

    pub fn registration(&self) -> &SharePointPluginRegistration {
        self.provider.registration()
    }

    pub fn describe_scope(
        &mut self,
    ) -> Result<SharePointScopeDescription, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        self.provider.describe_scope()
    }

    pub fn read_drive_item_metadata(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemMetadataEvidence, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemMetadata)?;
        self.provider.read_drive_item_metadata(request)
    }

    pub fn read_drive_item_children(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemChildrenEvidence, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemChildren)?;
        self.provider.read_drive_item_children(request)
    }

    pub fn search_drive_items(
        &mut self,
        request: &SharePointSearchRequest,
    ) -> Result<DriveItemSearchEvidence, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        Self::ensure_capability(&request.scope, SharePointCapability::SearchDriveItems)?;
        self.provider.search_drive_items(request)
    }

    pub fn read_drive_item_versions(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemVersionsEvidence, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemVersions)?;
        self.provider.read_drive_item_versions(request)
    }

    pub fn read_drive_item_delta(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemDeltaEvidence, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemDelta)?;
        self.provider.read_drive_item_delta(request)
    }

    pub fn read_knowledge_evidence(
        &mut self,
        request: &SharePointKnowledgeReadRequest,
    ) -> Result<SharePointKnowledgeEvidence, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        self.provider.read_knowledge_evidence(request)
    }

    pub fn compile_knowledge_result(
        &mut self,
        evidence: &SharePointKnowledgeEvidence,
        work_product: MissionWorkProduct,
    ) -> Result<SharePointKnowledgeResultProposal, SharePointKnowledgeResultError> {
        self.ensure_binding()?;
        Self::ensure_capability(
            &evidence.scope,
            SharePointCapability::CompileKnowledgeResult,
        )?;
        self.provider
            .compile_knowledge_result(evidence, work_product)
    }

    fn ensure_capability(
        scope: &SharePointKnowledgeScope,
        capability: SharePointCapability,
    ) -> Result<(), SharePointKnowledgeResultError> {
        if !scope.permits(capability) {
            return Err(SharePointKnowledgeResultError::ConsentRequired { capability });
        }
        Ok(())
    }

    fn ensure_binding(&mut self) -> Result<(), SharePointKnowledgeResultError> {
        if self.provider.registration().registration_digest != self.bound_registration_digest {
            return Err(SharePointKnowledgeResultError::RegistrationDigestMismatch);
        }
        if !self.provider.registration().active {
            return Err(SharePointKnowledgeResultError::RegistrationRevoked);
        }
        self.provider
            .registration()
            .validate(
                &self.provider.registration().scope,
                self.provider.provider_manifest(),
            )
            .map_err(|_| SharePointKnowledgeResultError::ProviderManifestDrift)
    }
}

#[allow(dead_code)]
fn _service_layer2_markers(
    _definition: &SharePointKnowledgeResultServiceDefinition,
    _request: &SharePointKnowledgeReadRequest,
) {
    let _ = MicrosoftGraphSharePointProviderError::RegistrationRevoked;
}
