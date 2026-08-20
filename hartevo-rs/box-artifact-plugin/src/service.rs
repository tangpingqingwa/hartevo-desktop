use serde::{Deserialize, Serialize};

use crate::consumer::MissionArtifactResultConsumer;
use crate::error::BoxArtifactError;
use crate::model::{
    ArtifactAdoptionProposal, ArtifactProposalRequest, BoxArtifactScope, BoxProviderProbe,
    ContentReadProjection, ContentReadRequest, FileReadProjection, FolderItemsProjection,
    FolderItemsRequest, FolderReadProjection, MissionArtifactResult, UserReadProjection,
    VersionPageProjection, VersionReadRequest, digest_parts,
};
use crate::provider::{BoxArtifactProvider, BoxCredentialResolver};
use crate::transport::BoxArtifactTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxArtifactServiceOperation {
    ProbeUser,
    ReadUserMetadata,
    ReadFolderMetadata,
    ListFolderItems,
    ReadFileMetadata,
    ListFileVersions,
    ReadBoundedContent,
    ProposeArtifactResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxArtifactServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: u64,
    pub operations: Vec<BoxArtifactServiceOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub durable_readback: bool,
}

impl BoxArtifactServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: crate::BOX_ARTIFACT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::BOX_ARTIFACT_CONTRACT_VERSION.to_owned(),
            service_id: crate::BOX_ARTIFACT_SERVICE_ID.to_owned(),
            provider_id: crate::BOX_ARTIFACT_PROVIDER_ID.to_owned(),
            consumer_id: crate::BOX_ARTIFACT_MISSION_CONSUMER_ID.to_owned(),
            plugin_id: crate::BOX_ARTIFACT_PLUGIN_ID.to_owned(),
            plugin_version: crate::BOX_ARTIFACT_PLUGIN_VERSION,
            operations: vec![
                BoxArtifactServiceOperation::ProbeUser,
                BoxArtifactServiceOperation::ReadUserMetadata,
                BoxArtifactServiceOperation::ReadFolderMetadata,
                BoxArtifactServiceOperation::ListFolderItems,
                BoxArtifactServiceOperation::ReadFileMetadata,
                BoxArtifactServiceOperation::ListFileVersions,
                BoxArtifactServiceOperation::ReadBoundedContent,
                BoxArtifactServiceOperation::ProposeArtifactResult,
            ],
            read_only: true,
            external_writes: false,
            durable_readback: false,
        }
    }

    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        if self.schema_version != crate::BOX_ARTIFACT_SCHEMA_VERSION
            || self.contract_version != crate::BOX_ARTIFACT_CONTRACT_VERSION
            || self.service_id != crate::BOX_ARTIFACT_SERVICE_ID
            || self.provider_id != crate::BOX_ARTIFACT_PROVIDER_ID
            || self.consumer_id != crate::BOX_ARTIFACT_MISSION_CONSUMER_ID
            || self.plugin_id != crate::BOX_ARTIFACT_PLUGIN_ID
            || self.plugin_version != crate::BOX_ARTIFACT_PLUGIN_VERSION
            || self.operations.len() != 8
            || !self.read_only
            || self.external_writes
            || self.durable_readback
        {
            return Err(BoxArtifactError::WriteNotAvailable {
                operation: "invalid service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> crate::ContentDigest {
        digest_parts([
            self.schema_version.as_str(),
            self.contract_version.as_str(),
            self.service_id.as_str(),
            self.provider_id.as_str(),
            self.consumer_id.as_str(),
            self.plugin_id.as_str(),
            &self.plugin_version.to_string(),
            &serde_json::to_string(&self.operations).unwrap_or_default(),
            &self.read_only.to_string(),
            &self.external_writes.to_string(),
            &self.durable_readback.to_string(),
        ])
    }
}

#[derive(Debug)]
pub struct BoxArtifactService<T, R>
where
    T: BoxArtifactTransport,
    R: BoxCredentialResolver,
{
    provider: BoxArtifactProvider<T, R>,
    consumer: MissionArtifactResultConsumer,
    definition: BoxArtifactServiceDefinition,
}

impl<T, R> BoxArtifactService<T, R>
where
    T: BoxArtifactTransport,
    R: BoxCredentialResolver,
{
    pub fn new(provider: BoxArtifactProvider<T, R>) -> Result<Self, BoxArtifactError> {
        let registration = provider.registration();
        let consumer = MissionArtifactResultConsumer::new(
            registration.scope.clone(),
            registration.provider_version,
            registration.registration_digest.clone(),
        )?;
        let definition = BoxArtifactServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            consumer,
            definition,
        })
    }

    pub fn definition(&self) -> &BoxArtifactServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &BoxArtifactProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut BoxArtifactProvider<T, R> {
        &mut self.provider
    }

    pub fn consumer(&self) -> &MissionArtifactResultConsumer {
        &self.consumer
    }

    pub fn probe(&mut self) -> Result<BoxProviderProbe, BoxArtifactError> {
        self.provider.probe()
    }

    pub fn read_user(&mut self) -> Result<UserReadProjection, BoxArtifactError> {
        self.provider.read_user()
    }

    pub fn read_folder(
        &mut self,
        scope: &BoxArtifactScope,
        folder_id: &crate::FolderId,
    ) -> Result<FolderReadProjection, BoxArtifactError> {
        self.provider.read_folder(scope, folder_id)
    }

    pub fn list_folder_items(
        &mut self,
        request: &FolderItemsRequest,
    ) -> Result<FolderItemsProjection, BoxArtifactError> {
        self.provider.list_folder_items(request)
    }

    pub fn read_file(
        &mut self,
        request: &crate::FileReadRequest,
    ) -> Result<FileReadProjection, BoxArtifactError> {
        self.provider.read_file(request)
    }

    pub fn read_versions(
        &mut self,
        request: &VersionReadRequest,
    ) -> Result<VersionPageProjection, BoxArtifactError> {
        self.provider.read_versions(request)
    }

    pub fn read_content(
        &mut self,
        request: &ContentReadRequest,
    ) -> Result<ContentReadProjection, BoxArtifactError> {
        self.provider.read_content(request)
    }

    pub fn propose_artifact_result(
        &mut self,
        request: ArtifactProposalRequest,
    ) -> Result<MissionArtifactResult, BoxArtifactError> {
        request.validate()?;
        let file_request =
            crate::FileReadRequest::new(request.scope.clone(), request.revision.file_id.clone())?;
        let file = self.provider.read_file(&file_request)?;
        let FileReadProjection {
            availability,
            metadata,
            ..
        } = file;
        let metadata = metadata.ok_or(match availability {
            crate::ArtifactAvailability::AccessLost => BoxArtifactError::AccessLost,
            crate::ArtifactAvailability::Deleted | crate::ArtifactAvailability::NotFound => {
                BoxArtifactError::Deleted
            }
            crate::ArtifactAvailability::Trashed => BoxArtifactError::Trashed,
            crate::ArtifactAvailability::ProviderUnknown | crate::ArtifactAvailability::Present => {
                BoxArtifactError::ProviderUnknown
            }
        })?;
        let content_request =
            ContentReadRequest::new(request.scope, request.revision, request.range)?;
        let content = self.provider.read_content(&content_request)?;
        self.consumer.consume(&request.source, metadata, content)
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<(), BoxArtifactError> {
        Err(BoxArtifactError::WriteNotAvailable { operation })
    }
}

/// Narrow service-level name retained for callers that want the proposed
/// record without going through the Mission result envelope.
pub type BoxArtifactProposal = ArtifactAdoptionProposal;
