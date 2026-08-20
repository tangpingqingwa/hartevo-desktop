//! Typed read/proposal/record/verify service surface.

use hartevo_plugin_runtime::{PluginDefinition, PluginScope};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, GcpIamAnalysisEvidence, GcpIamReadRequest, GcpIamScope, digest_serializable,
};
use crate::provider::{GcpCloudAssetProvider, GcpCloudAssetProviderError, GcpIamRegistration};
use crate::transport::GcpCloudAssetTransport;
use crate::{
    GCP_IAM_ANALYSIS_CONTRACT_VERSION, GCP_IAM_ANALYSIS_SERVICE_ID, GCP_IAM_ANALYSIS_SERVICE_NAME,
    GCP_IAM_ANALYSIS_SERVICE_SCHEMA, GCP_IAM_ANALYSIS_SERVICE_VERSION, GcpIamAnalysisContract,
    GcpIamAnalysisError, contract_digest, plugin_definition,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpIamAnalysisOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ProposeIamAnalysis,
    RecordEvidence,
    VerifyEvidence,
    ConsumeObservation,
}

impl GcpIamAnalysisOperation {
    pub const ALL: [Self; 7] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ProposeIamAnalysis,
        Self::RecordEvidence,
        Self::VerifyEvidence,
        Self::ConsumeObservation,
    ];

    #[must_use]
    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpIamAnalysisCapability {
    pub capability_id: String,
    pub operation: GcpIamAnalysisOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

/// Layer-1 service descriptor and lifecycle owner for the GCP IAM analysis
/// result slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamAnalysisService {
    service_id: String,
    service_name: String,
    version: String,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<GcpIamAnalysisCapability>,
}

impl Default for GcpIamAnalysisService {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpIamAnalysisService {
    #[must_use]
    pub fn new() -> Self {
        let capabilities = [
            (
                "gcp.iam-analysis.result.describe_capabilities",
                GcpIamAnalysisOperation::DescribeCapabilities,
            ),
            (
                "gcp.iam-analysis.result.register",
                GcpIamAnalysisOperation::Register,
            ),
            (
                "gcp.iam-analysis.result.revoke_registration",
                GcpIamAnalysisOperation::RevokeRegistration,
            ),
            (
                "gcp.iam-analysis.result.propose_iam_analysis",
                GcpIamAnalysisOperation::ProposeIamAnalysis,
            ),
            (
                "gcp.iam-analysis.result.record_evidence",
                GcpIamAnalysisOperation::RecordEvidence,
            ),
            (
                "gcp.iam-analysis.result.verify_evidence",
                GcpIamAnalysisOperation::VerifyEvidence,
            ),
            (
                "gcp.iam-analysis.result.consume_observation",
                GcpIamAnalysisOperation::ConsumeObservation,
            ),
        ]
        .into_iter()
        .map(|(capability_id, operation)| GcpIamAnalysisCapability {
            capability_id: capability_id.to_owned(),
            operation,
            read_only: true,
            mutates_provider: false,
            native_evidence: false,
        })
        .collect();
        Self {
            service_id: GCP_IAM_ANALYSIS_SERVICE_ID.to_owned(),
            service_name: GCP_IAM_ANALYSIS_SERVICE_NAME.to_owned(),
            version: GCP_IAM_ANALYSIS_SERVICE_VERSION.to_owned(),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    #[must_use]
    pub fn capabilities(&self) -> &[GcpIamAnalysisCapability] {
        &self.capabilities
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<GcpIamAnalysisCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(
        &self,
        scope: PluginScope,
    ) -> Result<PluginDefinition, GcpIamAnalysisError> {
        plugin_definition(scope)
    }

    pub fn validate(&self) -> Result<(), GcpIamAnalysisError> {
        GcpIamAnalysisContract::baseline()?;
        if self.service_id != GCP_IAM_ANALYSIS_SERVICE_ID
            || self.service_name != GCP_IAM_ANALYSIS_SERVICE_NAME
            || self.version != GCP_IAM_ANALYSIS_SERVICE_VERSION
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native_evidence
                    || !capability.operation.is_read_only()
            })
        {
            return Err(GcpIamAnalysisError::Contract(
                "GCP IAM analysis service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn register<T: GcpCloudAssetTransport>(
        &self,
        scope: GcpIamScope,
        secret_reference: crate::SecretReference,
        transport: T,
    ) -> Result<GcpCloudAssetProvider<T>, GcpIamAnalysisError> {
        self.validate()?;
        Ok(GcpCloudAssetProvider::new(
            scope,
            secret_reference,
            transport,
        )?)
    }

    pub fn revoke_registration<T: GcpCloudAssetTransport>(
        &self,
        provider: &mut GcpCloudAssetProvider<T>,
        at_unix_seconds: u64,
    ) -> Result<(), GcpIamAnalysisError> {
        self.validate()?;
        provider.revoke_registration(at_unix_seconds)?;
        Ok(())
    }

    pub fn propose<T: GcpCloudAssetTransport>(
        &self,
        provider: &mut GcpCloudAssetProvider<T>,
        request: &GcpIamReadRequest,
    ) -> Result<GcpIamAnalysisProposal, GcpIamAnalysisError> {
        self.validate()?;
        let evidence = provider.read(request)?;
        Ok(GcpIamAnalysisProposal::new(evidence))
    }

    pub fn read<T: GcpCloudAssetTransport>(
        &self,
        provider: &mut GcpCloudAssetProvider<T>,
        request: &GcpIamReadRequest,
    ) -> Result<GcpIamAnalysisProposal, GcpIamAnalysisError> {
        self.propose(provider, request)
    }

    pub fn record(
        &self,
        proposal: GcpIamAnalysisProposal,
    ) -> Result<GcpIamAnalysisRecord, GcpIamAnalysisError> {
        self.validate()?;
        proposal.validate()?;
        Ok(GcpIamAnalysisRecord::new(proposal.evidence))
    }

    pub fn verify(
        &self,
        record: &GcpIamAnalysisRecord,
        scope: &GcpIamScope,
    ) -> Result<GcpIamAnalysisVerification, GcpIamAnalysisError> {
        self.validate()?;
        record.validate()?;
        record
            .evidence
            .validate_for_scope(scope, None)
            .map_err(|_| GcpIamAnalysisError::StaleEvidence)?;
        Ok(GcpIamAnalysisVerification {
            verified: true,
            contract_digest: record.evidence.contract_digest.clone(),
            provider_digest: record.evidence.provider_digest.clone(),
            permission_digest: record.evidence.permission_digest.clone(),
            scope_digest: record.evidence.scope_digest.clone(),
            policy_digest: record.evidence.policy_digest.clone(),
            query_digest: record.evidence.query_digest.clone(),
            evidence_digest: record.evidence.evidence_digest.clone(),
            partial: record.evidence.partial,
            access_loss: record.evidence.access_loss,
            native_authority: false,
            truth_authority: false,
            effective_authorization: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &GcpIamAnalysisEvidence,
        scope: &GcpIamScope,
    ) -> Result<GcpIamAnalysisVerification, GcpIamAnalysisError> {
        let record = GcpIamAnalysisRecord::new(evidence.clone());
        self.verify(&record, scope)
    }

    #[must_use]
    pub fn contract_digest(&self) -> Digest {
        contract_digest()
    }

    #[must_use]
    pub fn contract_version(&self) -> &'static str {
        GCP_IAM_ANALYSIS_CONTRACT_VERSION
    }

    #[must_use]
    pub fn service_schema(&self) -> &'static str {
        GCP_IAM_ANALYSIS_SERVICE_SCHEMA
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpIamAnalysisProposal {
    pub evidence: GcpIamAnalysisEvidence,
    pub proposal_digest: Digest,
}

impl GcpIamAnalysisProposal {
    fn new(evidence: GcpIamAnalysisEvidence) -> Self {
        let proposal_digest = digest_serializable(&(&evidence, "gcp-iam-analysis-proposal/v1"));
        Self {
            evidence,
            proposal_digest,
        }
    }

    pub fn validate(&self) -> Result<(), GcpIamAnalysisError> {
        self.evidence
            .verify_digest()
            .map_err(|_| GcpIamAnalysisError::EvidenceDigestMismatch)?;
        if digest_serializable(&(&self.evidence, "gcp-iam-analysis-proposal/v1"))
            != self.proposal_digest
        {
            return Err(GcpIamAnalysisError::EvidenceDigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn evidence(&self) -> &GcpIamAnalysisEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpIamAnalysisRecord {
    pub evidence: GcpIamAnalysisEvidence,
    pub record_digest: Digest,
}

impl GcpIamAnalysisRecord {
    fn new(evidence: GcpIamAnalysisEvidence) -> Self {
        let record_digest = digest_serializable(&(&evidence, "gcp-iam-analysis-record/v1"));
        Self {
            evidence,
            record_digest,
        }
    }

    pub fn validate(&self) -> Result<(), GcpIamAnalysisError> {
        self.evidence
            .verify_digest()
            .map_err(|_| GcpIamAnalysisError::EvidenceDigestMismatch)?;
        if digest_serializable(&(&self.evidence, "gcp-iam-analysis-record/v1"))
            != self.record_digest
        {
            return Err(GcpIamAnalysisError::EvidenceDigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn evidence(&self) -> &GcpIamAnalysisEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpIamAnalysisVerification {
    pub verified: bool,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
    pub partial: bool,
    pub access_loss: bool,
    pub native_authority: bool,
    pub truth_authority: bool,
    pub effective_authorization: bool,
    pub adopted_outcome: bool,
}

pub const fn service_contract_version() -> &'static str {
    GCP_IAM_ANALYSIS_CONTRACT_VERSION
}

pub const fn service_id() -> &'static str {
    GCP_IAM_ANALYSIS_SERVICE_ID
}

pub fn service_contract_digest() -> Digest {
    contract_digest()
}

#[allow(dead_code)]
fn _registration_type_is_explicit(_: Option<GcpIamRegistration>) -> bool {
    true
}

#[allow(dead_code)]
fn _provider_error_is_explicit(_: Option<GcpCloudAssetProviderError>) -> bool {
    true
}
