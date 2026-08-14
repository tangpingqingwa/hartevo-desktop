//! Typed Layer-1 Fivetran service facade.

use serde::{Deserialize, Serialize};

use crate::model::{
    ConnectionListProjection, ConnectionListRequest, FivetranConnectionProjection,
    FivetranConnectionStateProjection, FivetranError, FivetranSchemaTableProjection,
    FivetranSyncEvidence, FivetranSyncRecording, FivetranSyncResultProposal,
    RegistrationTransition, VerificationReport,
};
use crate::provider::{FivetranProvider, FivetranProviderState};
use crate::transport::FivetranTransport;
use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID,
    Result, SERVICE_ID,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FivetranOperation {
    DescribeConnection,
    ReadConnectionState,
    ListConnectionsBounded,
    ReadSchemaTableMetadata,
    ReadSyncEvidence,
    CompileSyncResultProposal,
    RecordSyncProjection,
    VerifySyncResult,
    Register,
    Unmount,
    Remount,
    Revoke,
    Reverse,
}

impl FivetranOperation {
    pub const fn is_read_or_recording(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: crate::Version,
    pub layer: u8,
    pub operations: Vec<FivetranOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub durable_receipts: bool,
    pub webhook_ingestion: bool,
    pub destination_read_back: bool,
    pub generic_connector_registry: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl FivetranServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            layer: 1,
            operations: vec![
                FivetranOperation::DescribeConnection,
                FivetranOperation::ReadConnectionState,
                FivetranOperation::ListConnectionsBounded,
                FivetranOperation::ReadSchemaTableMetadata,
                FivetranOperation::ReadSyncEvidence,
                FivetranOperation::CompileSyncResultProposal,
                FivetranOperation::RecordSyncProjection,
                FivetranOperation::VerifySyncResult,
                FivetranOperation::Register,
                FivetranOperation::Unmount,
                FivetranOperation::Remount,
                FivetranOperation::Revoke,
                FivetranOperation::Reverse,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            durable_receipts: false,
            webhook_ingestion: false,
            destination_read_back: false,
            generic_connector_registry: false,
            kernel_authority: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::layer1();
        if self != &expected {
            return Err(FivetranError::TamperDetected {
                subject: "service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> crate::Digest {
        crate::Digest::from_serializable(self)
    }
}

/// Typed Layer-1 facade. It owns only an ephemeral provider and no Hartevo
/// Store, keyring, desktop, application, domain, catalog, or kernel authority.
pub struct FivetranSyncResultService<T>
where
    T: FivetranTransport,
{
    provider: FivetranProvider<T>,
    definition: FivetranServiceDefinition,
}

impl<T> std::fmt::Debug for FivetranSyncResultService<T>
where
    T: FivetranTransport,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FivetranSyncResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T> FivetranSyncResultService<T>
where
    T: FivetranTransport,
{
    pub fn new(provider: FivetranProvider<T>) -> Result<Self> {
        let definition = FivetranServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn provider(&self) -> &FivetranProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut FivetranProvider<T> {
        &mut self.provider
    }

    pub fn definition(&self) -> &FivetranServiceDefinition {
        &self.definition
    }

    pub const fn state(&self) -> FivetranProviderState {
        self.provider.state()
    }

    pub fn describe_connection(&mut self) -> Result<FivetranConnectionProjection> {
        self.provider.describe_connection()
    }

    pub fn read_connection_state(&mut self) -> Result<FivetranConnectionStateProjection> {
        self.provider.read_connection_state()
    }

    pub fn list_connections_bounded(
        &mut self,
        request: &ConnectionListRequest,
    ) -> Result<ConnectionListProjection> {
        self.provider.list_connections_bounded(request)
    }

    pub fn read_schema_table_metadata(&mut self) -> Result<FivetranSchemaTableProjection> {
        self.provider.read_schema_table_metadata()
    }

    pub fn read_sync_evidence(&mut self) -> Result<FivetranSyncEvidence> {
        self.provider.read_sync_evidence()
    }

    pub fn read_evidence(&mut self) -> Result<FivetranSyncEvidence> {
        self.read_sync_evidence()
    }

    pub fn compile_sync_result_proposal(
        &self,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncResultProposal> {
        self.provider.compile_sync_result_proposal(evidence)
    }

    pub fn compile_result_proposal(
        &self,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncResultProposal> {
        self.compile_sync_result_proposal(evidence)
    }

    pub fn record_sync_projection(
        &mut self,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncRecording> {
        self.provider.record_sync_projection(evidence)
    }

    pub fn record_evidence(
        &mut self,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncRecording> {
        self.record_sync_projection(evidence)
    }

    pub fn verify_sync_result(
        &self,
        proposal: &FivetranSyncResultProposal,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncResultProposal> {
        self.provider.verify_sync_result(proposal, evidence)
    }

    pub fn verify_sync_result_report(
        &self,
        proposal: &FivetranSyncResultProposal,
        evidence: &FivetranSyncEvidence,
    ) -> VerificationReport {
        self.provider.verify_sync_result_report(proposal, evidence)
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransition> {
        self.provider.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransition> {
        self.provider.remount()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        self.provider.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        self.provider.reverse()
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        self.provider.reject_write(operation)
    }
}
