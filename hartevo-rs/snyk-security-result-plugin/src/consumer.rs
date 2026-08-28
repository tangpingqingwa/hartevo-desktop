//! Mission-scoped redacted proposal and deterministic recording seam.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, FindingStatus, MissionId, ProjectId, ProjectionCompleteness, SnykScope,
    TransportProvenance, WorkProductId,
};
use crate::provider::ProjectSnapshotProjection;
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, Result, SERVICE_ID, SnykSecurityResultError, validate_text,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    Truncated,
}

/// A redacted, below-kernel security-result proposal. It contains counts and
/// digests only; it is not a Receipt, Verification, or Outcome.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityResultProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub snapshot_digest: Digest,
    pub projection_digest: Digest,
    pub vulnerability_count: u32,
    pub license_count: u32,
    pub iac_count: u32,
    pub status_counts: BTreeMap<FindingStatus, u32>,
    pub disposition: ProposalDisposition,
    pub completeness: ProjectionCompleteness,
    pub provenance: TransportProvenance,
    pub idempotency_key_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

impl SecurityResultProposal {
    fn from_projection(
        scope: &SnykScope,
        projection: &ProjectSnapshotProjection,
        idempotency_key: &str,
    ) -> Result<Self> {
        let mut status_counts = BTreeMap::new();
        for evidence in &projection.evidence {
            let status = match evidence {
                crate::Evidence::Vulnerability(value) => value.status,
                crate::Evidence::License(value) => value.status,
                crate::Evidence::Iac(value) => value.status,
            };
            *status_counts.entry(status).or_insert(0) += 1;
        }
        let mut proposal = Self {
            proposal_version: format!("{CONTRACT_VERSION}/proposal"),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: scope.digest(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            project_id: scope.project_id().clone(),
            project_revision: scope.project_revision(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            snapshot_digest: projection.snapshot_digest.clone(),
            projection_digest: projection.projection_digest.clone(),
            vulnerability_count: u32::try_from(projection.vulnerability_count())
                .map_err(|_| SnykSecurityResultError::InvalidProposal)?,
            license_count: u32::try_from(projection.license_count())
                .map_err(|_| SnykSecurityResultError::InvalidProposal)?,
            iac_count: u32::try_from(projection.iac_count())
                .map_err(|_| SnykSecurityResultError::InvalidProposal)?,
            status_counts,
            disposition: if projection.is_complete() {
                ProposalDisposition::ReviewOnly
            } else {
                ProposalDisposition::Truncated
            },
            completeness: projection.completeness,
            provenance: projection.provenance,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            connected: false,
            native: false,
            outcome_adopted: false,
            proposal_digest: Digest::from_text("unsealed-snyk-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.snapshot_digest.validate()?;
        self.projection_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        if self.proposal_version != format!("{CONTRACT_VERSION}/proposal")
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.outcome_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(SnykSecurityResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "snyk-security-result-proposal/v1",
            &[
                ("proposal_version", self.proposal_version.clone()),
                ("service_id", self.service_id.clone()),
                ("consumer_id", self.consumer_id.clone()),
                ("scope_digest", self.scope_digest.as_str().to_owned()),
                ("mission_id", self.mission_id.as_str().to_owned()),
                ("mission_revision", self.mission_revision.to_string()),
                ("project_id", self.project_id.as_str().to_owned()),
                ("project_revision", self.project_revision.to_string()),
                ("work_product_id", self.work_product_id.as_str().to_owned()),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                ("snapshot_digest", self.snapshot_digest.as_str().to_owned()),
                (
                    "projection_digest",
                    self.projection_digest.as_str().to_owned(),
                ),
                ("vulnerability_count", self.vulnerability_count.to_string()),
                ("license_count", self.license_count.to_string()),
                ("iac_count", self.iac_count.to_string()),
                (
                    "status_counts",
                    serde_json::to_string(&self.status_counts).expect("status counts serialize"),
                ),
                ("disposition", format!("{:?}", self.disposition)),
                ("completeness", format!("{:?}", self.completeness)),
                ("provenance", format!("{:?}", self.provenance)),
                (
                    "idempotency_key_digest",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedSecurityResult {
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub disposition: ProposalDisposition,
    pub completeness: ProjectionCompleteness,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedSecurityResult {
    fn from_proposal(proposal: &SecurityResultProposal, replayed: bool) -> Self {
        let mut result = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            disposition: proposal.disposition,
            completeness: proposal.completeness,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            recording_digest: Digest::from_text("unsealed-snyk-recording"),
        };
        result.recording_digest = Digest::from_serialized(&(
            &result.proposal_digest,
            &result.scope_digest,
            result.disposition,
            result.completeness,
            result.provenance,
        ));
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.proposal_digest.validate()?;
        self.scope_digest.validate()?;
        if self.connected || self.native || self.provider_receipt || self.outcome_adopted {
            return Err(SnykSecurityResultError::TamperedEvidence);
        }
        let expected = Digest::from_serialized(&(
            &self.proposal_digest,
            &self.scope_digest,
            self.disposition,
            self.completeness,
            self.provenance,
        ));
        if self.recording_digest != expected {
            return Err(SnykSecurityResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct SecurityResultRecordingLog {
    records: BTreeMap<Digest, RecordedSecurityResult>,
}

impl SecurityResultRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedSecurityResult> {
        self.records.get(idempotency_key_digest)
    }

    fn record(&mut self, proposal: &SecurityResultProposal) -> Result<RecordedSecurityResult> {
        proposal.validate_integrity()?;
        if let Some(existing) = self.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(SnykSecurityResultError::ReplayConflict);
            }
            let replay = RecordedSecurityResult::from_proposal(proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedSecurityResult::from_proposal(proposal, false);
        result.validate_integrity()?;
        self.records
            .insert(proposal.idempotency_key_digest.clone(), result.clone());
        Ok(result)
    }
}

/// A Mission consumer bound to one exact Snyk and Hartevo scope. It emits only
/// a review proposal and a safe recording; it never adopts an Outcome.
#[derive(Clone, Debug)]
pub struct MissionSnykSecurityConsumer {
    scope: SnykScope,
}

impl MissionSnykSecurityConsumer {
    pub fn new(scope: SnykScope) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &SnykScope {
        &self.scope
    }

    pub fn compile_security_result_proposal(
        &self,
        projection: &ProjectSnapshotProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<SecurityResultProposal> {
        self.scope.validate()?;
        projection.validate_integrity()?;
        if projection.scope != self.scope {
            return Err(SnykSecurityResultError::ScopeMismatch);
        }
        let idempotency_key = idempotency_key.into();
        validate_text(&idempotency_key, "idempotencyKey", 256)?;
        SecurityResultProposal::from_projection(&self.scope, projection, &idempotency_key)
    }

    pub fn compile_proposal(
        &self,
        projection: &ProjectSnapshotProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<SecurityResultProposal> {
        self.compile_security_result_proposal(projection, idempotency_key)
    }

    pub fn record_security_result(
        &self,
        proposal: &SecurityResultProposal,
        log: &mut SecurityResultRecordingLog,
    ) -> Result<RecordedSecurityResult> {
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_id != *self.scope.mission_id()
            || proposal.mission_revision != self.scope.mission_revision()
            || proposal.project_id != *self.scope.project_id()
            || proposal.project_revision != self.scope.project_revision()
            || proposal.work_product_id != *self.scope.work_product_id()
            || proposal.work_product_revision != self.scope.work_product_revision()
        {
            return Err(SnykSecurityResultError::ScopeMismatch);
        }
        log.record(proposal)
    }

    pub fn record(
        &self,
        proposal: &SecurityResultProposal,
        log: &mut SecurityResultRecordingLog,
    ) -> Result<RecordedSecurityResult> {
        self.record_security_result(proposal, log)
    }
}
