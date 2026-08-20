//! Read-only AWS Batch result service and proposal/record/verify seams.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{BatchEvidence, Digest, EvidenceStatus, ProviderProvenance, RedactionSummary};
use crate::{
    AWS_BATCH_JOB_RESULT_SERVICE_ID, AWS_BATCH_JOB_RESULT_SERVICE_NAME,
    AWS_BATCH_JOB_RESULT_SERVICE_SCHEMA, AwsBatchError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsBatchJobResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadDescribeJobs,
    ReadListJobs,
    ReadArrayChildren,
    ReadMnpNodes,
    Propose,
    Record,
    Verify,
}

impl AwsBatchJobResultOperation {
    pub const ALL: [Self; 10] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadDescribeJobs,
        Self::ReadListJobs,
        Self::ReadArrayChildren,
        Self::ReadMnpNodes,
        Self::Propose,
        Self::Record,
        Self::Verify,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AwsBatchCapability {
    pub capability_id: String,
    pub operation: AwsBatchJobResultOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
    pub workload_correctness_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsBatchJobResultService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<AwsBatchCapability>,
}

impl Default for AwsBatchJobResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsBatchJobResultService {
    pub fn new() -> Self {
        let capabilities = AwsBatchJobResultOperation::ALL
            .into_iter()
            .map(|operation| AwsBatchCapability {
                capability_id: format!(
                    "aws.batch.job-result.{}",
                    serde_json::to_string(&operation)
                        .expect("operation serializes")
                        .trim_matches('"')
                ),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
                workload_correctness_authority: false,
            })
            .collect();
        Self {
            service_id: AWS_BATCH_JOB_RESULT_SERVICE_ID.to_owned(),
            service_name: AWS_BATCH_JOB_RESULT_SERVICE_NAME.to_owned(),
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

    pub fn capabilities(&self) -> &[AwsBatchCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<AwsBatchCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, AwsBatchError> {
        ServiceDefinition::read_only(
            ServiceId::new(self.service_id.clone())?,
            self.version,
            RuntimeDigest::from_text(AWS_BATCH_JOB_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(AwsBatchError::from)
    }

    pub fn validate(&self) -> Result<(), AwsBatchError> {
        if self.service_id != AWS_BATCH_JOB_RESULT_SERVICE_ID
            || self.service_name != AWS_BATCH_JOB_RESULT_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.len() != AwsBatchJobResultOperation::ALL.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native_evidence
                    || capability.workload_correctness_authority
            })
        {
            return Err(AwsBatchError::ContractDrift);
        }
        Ok(())
    }

    pub fn propose(&self, evidence: BatchEvidence) -> Result<AwsBatchProposal, AwsBatchError> {
        evidence
            .validate()
            .map_err(|_| AwsBatchError::TamperedEvidence)?;
        AwsBatchProposal::new(evidence).map_err(AwsBatchError::from)
    }

    pub fn record(&self, proposal: &AwsBatchProposal) -> Result<AwsBatchRecord, AwsBatchError> {
        proposal
            .validate()
            .map_err(|_| AwsBatchError::TamperedEvidence)?;
        AwsBatchRecord::new(proposal).map_err(|_| AwsBatchError::TamperedEvidence)
    }

    pub fn verify(
        &self,
        record: &AwsBatchRecord,
        evidence: &BatchEvidence,
    ) -> Result<AwsBatchVerification, AwsBatchError> {
        evidence
            .validate()
            .map_err(|_| AwsBatchError::TamperedEvidence)?;
        record
            .validate()
            .map_err(|_| AwsBatchError::TamperedEvidence)?;
        let expected_record = AwsBatchRecord::new(&AwsBatchProposal::new(evidence.clone())?)?;
        if expected_record.record_digest != record.record_digest
            || record.evidence_digest != evidence.evidence_digest
            || record.scope_digest != evidence.scope_digest
            || record.registration_digest != evidence.registration_digest
        {
            return Err(AwsBatchError::TamperedEvidence);
        }
        AwsBatchVerification::from_record(record, evidence).map_err(AwsBatchError::from)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsBatchObservationReceipt {
    pub schema: String,
    pub receipt_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provenance: ProviderProvenance,
    pub evidence_status: EvidenceStatus,
    pub redaction: RedactionSummary,
    pub durable_provider_receipt: bool,
    pub raw_provider_response_retained: bool,
    pub independent_output_readback: bool,
}

impl AwsBatchObservationReceipt {
    fn expected_digest(
        evidence_digest: &Digest,
        scope_digest: &Digest,
        registration_digest: &Digest,
        provenance: ProviderProvenance,
        evidence_status: &EvidenceStatus,
    ) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-observation-receipt/v1",
            &[
                evidence_digest.as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                registration_digest.as_str().to_owned(),
                format!("{provenance:?}"),
                format!("{evidence_status:?}"),
            ],
        )
    }

    pub fn from_evidence(evidence: &BatchEvidence) -> Result<Self, AwsBatchError> {
        evidence
            .validate()
            .map_err(|_| AwsBatchError::TamperedEvidence)?;
        let redaction = evidence.redaction.clone();
        let receipt_digest = Self::expected_digest(
            &evidence.evidence_digest,
            &evidence.scope_digest,
            &evidence.registration_digest,
            evidence.provenance,
            &evidence.status,
        );
        Ok(Self {
            schema: "hartevo.aws-batch-observation-receipt/v1".to_owned(),
            receipt_digest,
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            provenance: evidence.provenance,
            evidence_status: evidence.status.clone(),
            redaction,
            durable_provider_receipt: false,
            raw_provider_response_retained: false,
            independent_output_readback: false,
        })
    }

    pub fn validate(&self) -> Result<(), AwsBatchError> {
        if self.schema != "hartevo.aws-batch-observation-receipt/v1"
            || self.durable_provider_receipt
            || self.raw_provider_response_retained
            || self.independent_output_readback
            || self.redaction.raw_provider_payload_retained
            || self.receipt_digest
                != Self::expected_digest(
                    &self.evidence_digest,
                    &self.scope_digest,
                    &self.registration_digest,
                    self.provenance,
                    &self.evidence_status,
                )
        {
            return Err(AwsBatchError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AwsBatchProposal {
    pub evidence: BatchEvidence,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub workload_correctness_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl AwsBatchProposal {
    pub fn new(evidence: BatchEvidence) -> Result<Self, crate::model::ModelError> {
        evidence.validate()?;
        let proposal_digest = Digest::from_fields(
            "hartevo.aws-batch-proposal/v1",
            &[
                evidence.evidence_digest.as_str().to_owned(),
                evidence.scope_digest.as_str().to_owned(),
                evidence.registration_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            evidence,
            proposal_digest,
            read_only: true,
            native: false,
            connected: false,
            workload_correctness_authority: false,
            outcome_authority: false,
            work_product_adoption: false,
        })
    }

    pub fn validate(&self) -> Result<(), crate::model::ModelError> {
        self.evidence.validate()?;
        let expected = Digest::from_fields(
            "hartevo.aws-batch-proposal/v1",
            &[
                self.evidence.evidence_digest.as_str().to_owned(),
                self.evidence.scope_digest.as_str().to_owned(),
                self.evidence.registration_digest.as_str().to_owned(),
            ],
        );
        if self.proposal_digest != expected
            || !self.read_only
            || self.native
            || self.connected
            || self.workload_correctness_authority
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(crate::model::ModelError::InvalidValue {
                field: "batch proposal authority",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsBatchRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub receipt: AwsBatchObservationReceipt,
    pub record_digest: Digest,
    pub durable: bool,
    pub verified: bool,
    pub adopted: bool,
}

impl AwsBatchRecord {
    pub fn new(proposal: &AwsBatchProposal) -> Result<Self, crate::model::ModelError> {
        proposal.validate()?;
        let receipt = AwsBatchObservationReceipt::from_evidence(&proposal.evidence)
            .map_err(|_| crate::model::ModelError::InvalidValue { field: "receipt" })?;
        let mut record = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            registration_digest: proposal.evidence.registration_digest.clone(),
            receipt,
            record_digest: Digest::from_text("pending-record-digest"),
            durable: false,
            verified: false,
            adopted: false,
        };
        record.record_digest = record.compute_digest()?;
        Ok(record)
    }

    fn compute_digest(&self) -> Result<Digest, crate::model::ModelError> {
        crate::model::digest_serializable(&(
            &self.proposal_digest,
            &self.evidence_digest,
            &self.scope_digest,
            &self.registration_digest,
            &self.receipt,
            self.durable,
            self.verified,
            self.adopted,
        ))
    }

    pub fn validate(&self) -> Result<(), crate::model::ModelError> {
        self.receipt
            .validate()
            .map_err(|_| crate::model::ModelError::InvalidValue { field: "receipt" })?;
        if self.durable
            || self.verified
            || self.adopted
            || self.receipt.evidence_digest != self.evidence_digest
            || self.receipt.scope_digest != self.scope_digest
            || self.receipt.registration_digest != self.registration_digest
            || self.record_digest != self.compute_digest()?
        {
            return Err(crate::model::ModelError::InvalidDigest {
                field: "batch record",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    VerifiedReadOnly,
    PartialEvidence,
    AccessLost,
    Tampered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AwsBatchVerification {
    pub record_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub status: VerificationStatus,
    pub accepted: bool,
    pub independent_output_readback: bool,
    pub native: bool,
    pub connected: bool,
    pub workload_correctness_authority: bool,
    pub outcome_authority: bool,
}

impl AwsBatchVerification {
    pub fn from_record(
        record: &AwsBatchRecord,
        evidence: &BatchEvidence,
    ) -> Result<Self, crate::model::ModelError> {
        evidence.validate()?;
        record
            .validate()
            .map_err(|_| crate::model::ModelError::InvalidValue {
                field: "batch record",
            })?;
        if record.evidence_digest != evidence.evidence_digest
            || record.scope_digest != evidence.scope_digest
            || record.registration_digest != evidence.registration_digest
        {
            return Err(crate::model::ModelError::InvalidValue {
                field: "record evidence fence",
            });
        }
        let (status, accepted) = match evidence.status {
            EvidenceStatus::Complete => (VerificationStatus::VerifiedReadOnly, true),
            EvidenceStatus::Partial => (VerificationStatus::PartialEvidence, false),
            EvidenceStatus::AccessLost => (VerificationStatus::AccessLost, false),
        };
        Ok(Self {
            record_digest: record.record_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            status,
            accepted,
            independent_output_readback: false,
            native: false,
            connected: false,
            workload_correctness_authority: false,
            outcome_authority: false,
        })
    }
}

pub type AwsBatchJobResultProposal = AwsBatchProposal;
pub type AwsBatchJobResultRecord = AwsBatchRecord;
pub type AwsBatchJobResultVerification = AwsBatchVerification;
pub type AwsBatchJobResultReceipt = AwsBatchObservationReceipt;
