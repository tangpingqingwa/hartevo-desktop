//! Read/proposal/record/verify service boundary for normalized CodeBuild
//! evidence. None of these types is a native provider receipt or a kernel
//! Truth, Outcome, or Work Product authority.

use serde::{Deserialize, Serialize};

use crate::model::{
    CodeBuildEvidence, Digest, EvidenceStatus, ProviderProvenance, RedactionSummary,
};
use crate::{
    AWS_CODEBUILD_CONTRACT_VERSION, AWS_CODEBUILD_PLUGIN_VERSION, AWS_CODEBUILD_SERVICE_ID,
    AWS_CODEBUILD_SERVICE_NAME, AwsCodeBuildError, Result, api_digest, contract_digest,
    evidence_schema_digest, plugin_definition, version_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCodeBuildResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadListBuildsForProject,
    ReadBatchGetBuilds,
    ReadBatchGetProjects,
    Propose,
    Record,
    Verify,
}

impl AwsCodeBuildResultOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadListBuildsForProject,
        Self::ReadBatchGetBuilds,
        Self::ReadBatchGetProjects,
        Self::Propose,
        Self::Record,
        Self::Verify,
    ];

    pub const fn is_read_only(self) -> bool {
        !matches!(self, Self::Register | Self::RevokeRegistration)
    }
}

pub type CodeBuildResultOperation = AwsCodeBuildResultOperation;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodeBuildCapability {
    pub operation: AwsCodeBuildResultOperation,
    pub read_only: bool,
    pub bounded: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
}

#[derive(Clone, Debug, Default)]
pub struct AwsCodeBuildResultService;

impl AwsCodeBuildResultService {
    pub const fn new() -> Self {
        Self
    }

    pub fn service_id(&self) -> &str {
        AWS_CODEBUILD_SERVICE_ID
    }

    pub fn service_name(&self) -> &str {
        AWS_CODEBUILD_SERVICE_NAME
    }

    pub fn version(&self) -> hartevo_plugin_runtime::PluginVersion {
        hartevo_plugin_runtime::PluginVersion::new(1, 0, 0)
    }

    pub const fn read_only(&self) -> bool {
        true
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn capabilities(&self) -> Vec<AwsCodeBuildCapability> {
        AwsCodeBuildResultOperation::ALL
            .into_iter()
            .map(|operation| AwsCodeBuildCapability {
                operation,
                read_only: operation.is_read_only(),
                bounded: true,
                native: false,
                connected: false,
                external_writes: false,
            })
            .collect()
    }

    pub fn describe_capabilities(&self) -> Vec<AwsCodeBuildCapability> {
        self.capabilities()
    }

    pub fn runtime_definition(
        &self,
        scope: hartevo_plugin_runtime::PluginScope,
    ) -> Result<hartevo_plugin_runtime::PluginDefinition> {
        plugin_definition(scope)
    }

    pub fn validate(&self) -> Result<()> {
        crate::validate_contract_document()
    }

    pub fn propose(&self, evidence: CodeBuildEvidence) -> Result<AwsCodeBuildProposal> {
        evidence.validate_integrity()?;
        AwsCodeBuildProposal::new(evidence).map_err(AwsCodeBuildError::from)
    }

    pub fn record(&self, proposal: &AwsCodeBuildProposal) -> Result<AwsCodeBuildRecord> {
        proposal.validate()?;
        AwsCodeBuildRecord::new(proposal).map_err(AwsCodeBuildError::from)
    }

    pub fn verify(&self, record: &AwsCodeBuildRecord) -> Result<AwsCodeBuildVerification> {
        record.validate()?;
        Ok(AwsCodeBuildVerification::verified(
            record.evidence_digest.clone(),
            record.record_digest.clone(),
        ))
    }

    pub fn verify_for(
        &self,
        record: &AwsCodeBuildRecord,
        scope_digest: &Digest,
        registration_digest: &Digest,
    ) -> Result<AwsCodeBuildVerification> {
        record.validate()?;
        if &record.scope_digest != scope_digest
            || &record.registration_digest != registration_digest
        {
            return Err(AwsCodeBuildError::TamperedEvidence);
        }
        Ok(AwsCodeBuildVerification::verified(
            record.evidence_digest.clone(),
            record.record_digest.clone(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodeBuildObservationReceipt {
    pub schema: String,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub status: EvidenceStatus,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub connected: bool,
    pub durable_native_receipt: bool,
    pub independent_artifact_readback: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub receipt_digest: Digest,
}

pub type AwsCodeBuildResultReceipt = AwsCodeBuildObservationReceipt;

impl AwsCodeBuildObservationReceipt {
    pub fn from_evidence(evidence: &CodeBuildEvidence) -> Result<Self> {
        evidence.validate_integrity()?;
        let mut receipt = Self {
            schema: "hartevo.aws-codebuild-observation-receipt/v1".to_owned(),
            evidence_digest: evidence.digests.evidence_digest.clone(),
            scope_digest: evidence.digests.scope_digest.clone(),
            registration_digest: evidence.digests.registration_digest.clone(),
            status: evidence.status,
            provenance: evidence.provenance,
            native: false,
            connected: false,
            durable_native_receipt: false,
            independent_artifact_readback: false,
            outcome_authority: false,
            work_product_adoption: false,
            receipt_digest: Digest::from_text("pending-codebuild-observation-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-observation-receipt/v1",
            &[
                self.schema.clone(),
                self.evidence_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                format!("{:?}", self.status),
                format!("{:?}", self.provenance),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != "hartevo.aws-codebuild-observation-receipt/v1"
            || self.native
            || self.connected
            || self.durable_native_receipt
            || self.independent_artifact_readback
            || self.outcome_authority
            || self.work_product_adoption
            || self.receipt_digest != self.compute_digest()
        {
            return Err(AwsCodeBuildError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodeBuildProposal {
    pub evidence: CodeBuildEvidence,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
}

pub type AwsCodeBuildResultProposal = AwsCodeBuildProposal;

impl AwsCodeBuildProposal {
    pub fn new(evidence: CodeBuildEvidence) -> std::result::Result<Self, crate::model::ModelError> {
        evidence.validate_integrity()?;
        let evidence_digest = evidence.digests.evidence_digest.clone();
        let scope_digest = evidence.digests.scope_digest.clone();
        let registration_digest = evidence.digests.registration_digest.clone();
        let proposal_digest = Digest::from_fields(
            "hartevo.aws-codebuild-proposal/v1",
            &[
                evidence_digest.as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                registration_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            evidence,
            evidence_digest,
            scope_digest,
            registration_digest,
            proposal_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.evidence_digest != self.evidence.digests.evidence_digest
            || self.scope_digest != self.evidence.digests.scope_digest
            || self.registration_digest != self.evidence.digests.registration_digest
            || self.proposal_digest
                != Digest::from_fields(
                    "hartevo.aws-codebuild-proposal/v1",
                    &[
                        self.evidence_digest.as_str().to_owned(),
                        self.scope_digest.as_str().to_owned(),
                        self.registration_digest.as_str().to_owned(),
                    ],
                )
        {
            return Err(AwsCodeBuildError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodeBuildRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub record_digest: Digest,
    pub redacted_receipt: AwsCodeBuildObservationReceipt,
}

pub type AwsCodeBuildResultRecord = AwsCodeBuildRecord;

impl AwsCodeBuildRecord {
    pub fn new(
        proposal: &AwsCodeBuildProposal,
    ) -> std::result::Result<Self, crate::model::ModelError> {
        proposal
            .validate()
            .map_err(|_| crate::model::ModelError::InvalidValue {
                field: "CodeBuild proposal",
            })?;
        let redacted_receipt = AwsCodeBuildObservationReceipt::from_evidence(&proposal.evidence)
            .map_err(|_| crate::model::ModelError::InvalidValue {
                field: "CodeBuild observation receipt",
            })?;
        let record_digest = Digest::from_fields(
            "hartevo.aws-codebuild-record/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                proposal.evidence_digest.as_str().to_owned(),
                redacted_receipt.receipt_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            record_digest,
            redacted_receipt,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.redacted_receipt.validate()?;
        if self.evidence_digest != self.redacted_receipt.evidence_digest
            || self.scope_digest != self.redacted_receipt.scope_digest
            || self.registration_digest != self.redacted_receipt.registration_digest
            || self.record_digest
                != Digest::from_fields(
                    "hartevo.aws-codebuild-record/v1",
                    &[
                        self.proposal_digest.as_str().to_owned(),
                        self.evidence_digest.as_str().to_owned(),
                        self.redacted_receipt.receipt_digest.as_str().to_owned(),
                    ],
                )
        {
            return Err(AwsCodeBuildError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodeBuildVerification {
    pub status: VerificationStatus,
    pub evidence_digest: Digest,
    pub record_digest: Digest,
    pub checks: Vec<String>,
    pub native: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

pub type AwsCodeBuildResultVerification = AwsCodeBuildVerification;

impl AwsCodeBuildVerification {
    fn verified(evidence_digest: Digest, record_digest: Digest) -> Self {
        Self {
            status: VerificationStatus::Verified,
            evidence_digest,
            record_digest,
            checks: vec![
                "evidence_digest".to_owned(),
                "redaction_boundary".to_owned(),
                "registration_and_scope_digest".to_owned(),
            ],
            native: false,
            connected: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.status != VerificationStatus::Verified
            || self.native
            || self.connected
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(AwsCodeBuildError::TamperedEvidence);
        }
        Ok(())
    }
}

pub type AwsCodeBuildResultServiceDefinition = AwsCodeBuildCapability;

#[allow(dead_code)]
fn _service_constants_are_bound() -> (&'static str, &'static str, Digest, Digest, Digest, Digest) {
    (
        AWS_CODEBUILD_CONTRACT_VERSION,
        AWS_CODEBUILD_PLUGIN_VERSION,
        version_digest(),
        contract_digest(),
        api_digest(),
        evidence_schema_digest(),
    )
}

#[allow(dead_code)]
fn _layer1_redaction_is_closed() -> RedactionSummary {
    RedactionSummary::layer1()
}
