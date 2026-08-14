//! Mission-scoped proposal and recording consumer for Buildkite evidence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{BuildkitePipelineResultEvidence, BuildkiteScope, Digest, TransportProvenance};
use crate::provider::{BuildkiteProvider, BuildkiteProviderError, BuildkiteTransport};
use crate::{
    BuildkitePipelineResultError, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION,
    Result, contract_digest,
};

/// A below-kernel proposal containing only typed projection digests and
/// bounded provenance.  It is review-only and never adoptable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct BuildkitePipelineResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub builds_digest: Digest,
    pub jobs_digest: Digest,
    pub annotations_digest: Digest,
    pub artifacts_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub provenance: TransportProvenance,
    pub response_truncated: bool,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

impl BuildkitePipelineResultProposal {
    fn from_evidence(
        evidence: &BuildkitePipelineResultEvidence,
        idempotency_key: &str,
    ) -> Result<Self> {
        evidence.validate_integrity()?;
        let mut proposal = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST)?,
            consumer_id: CONSUMER_ID.to_owned(),
            consumer_version: PLUGIN_VERSION.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            builds_digest: evidence.builds.projection_digest.clone(),
            jobs_digest: evidence.jobs.projection_digest.clone(),
            annotations_digest: evidence.annotations.projection_digest.clone(),
            artifacts_digest: evidence.artifacts.projection_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            idempotency_key_digest: Digest::from_text(idempotency_key),
            provenance: evidence.provenance,
            response_truncated: evidence.response_truncated,
            review_only: true,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            proposal_digest: Digest::from_text("unsealed-buildkite-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != contract_digest()
            || self.consumer_id != CONSUMER_ID
            || self.consumer_version != PLUGIN_VERSION
            || self.scope_digest.validate().is_err()
            || self.builds_digest.validate().is_err()
            || self.jobs_digest.validate().is_err()
            || self.annotations_digest.validate().is_err()
            || self.artifacts_digest.validate().is_err()
            || self.evidence_digest.validate().is_err()
            || self.idempotency_key_digest.validate().is_err()
            || !self.review_only
            || self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::InvalidProposal);
        }
        Ok(())
    }

    pub fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-pipeline-result-proposal/v1",
            &[
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("consumer", self.consumer_id.clone()),
                ("consumer_version", self.consumer_version.clone()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("builds", self.builds_digest.as_str().to_owned()),
                ("jobs", self.jobs_digest.as_str().to_owned()),
                ("annotations", self.annotations_digest.as_str().to_owned()),
                ("artifacts", self.artifacts_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("truncated", self.response_truncated.to_string()),
                ("review_only", self.review_only.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecordedBuildkitePipelineResult {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedBuildkitePipelineResult {
    fn from_proposal(proposal: &BuildkitePipelineResultProposal, replayed: bool) -> Self {
        let mut recorded = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            idempotency_key_digest: proposal.idempotency_key_digest.clone(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            recording_digest: Digest::from_text("unsealed-buildkite-recording"),
        };
        recorded.recording_digest = Digest::from_serialized(&(
            &recorded.proposal_digest,
            &recorded.evidence_digest,
            &recorded.idempotency_key_digest,
            recorded.provenance,
            recorded.replayed,
            recorded.connected,
            recorded.native,
            recorded.provider_receipt,
            recorded.outcome_adopted,
        ));
        recorded
    }

    pub fn validate(&self) -> Result<()> {
        if self.proposal_digest.validate().is_err()
            || self.evidence_digest.validate().is_err()
            || self.idempotency_key_digest.validate().is_err()
            || self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_adopted
            || self.recording_digest
                != Digest::from_serialized(&(
                    &self.proposal_digest,
                    &self.evidence_digest,
                    &self.idempotency_key_digest,
                    self.provenance,
                    self.replayed,
                    self.connected,
                    self.native,
                    self.provider_receipt,
                    self.outcome_adopted,
                ))
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub type RecordedPipelineResult = RecordedBuildkitePipelineResult;

#[derive(Clone, Debug, Default)]
pub struct BuildkitePipelineResultRecordingLog {
    records: BTreeMap<Digest, RecordedBuildkitePipelineResult>,
}

impl BuildkitePipelineResultRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedBuildkitePipelineResult> {
        self.records.get(idempotency_key_digest)
    }
}

/// Consumer fenced to one exact Buildkite and Mission scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionBuildkitePipelineConsumer {
    scope: BuildkiteScope,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
}

impl MissionBuildkitePipelineConsumer {
    pub fn new(scope: BuildkiteScope) -> Self {
        Self {
            scope,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST).expect("checked contract digest"),
        }
    }

    pub fn scope(&self) -> &BuildkiteScope {
        &self.scope
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn consume_evidence(
        &self,
        evidence: BuildkitePipelineResultEvidence,
    ) -> Result<BuildkitePipelineResultEvidence> {
        evidence.validate_integrity()?;
        if evidence.scope_digest != self.scope.digest()
            || evidence.contract_digest != self.contract_digest
            || evidence.contract_version != self.contract_version
        {
            return Err(BuildkitePipelineResultError::ScopeMismatch);
        }
        Ok(evidence)
    }

    pub fn compile_proposal(
        &self,
        evidence: &BuildkitePipelineResultEvidence,
        idempotency_key: &str,
    ) -> Result<BuildkitePipelineResultProposal> {
        let evidence = self.consume_evidence(evidence.clone())?;
        if idempotency_key.trim().is_empty() {
            return Err(BuildkitePipelineResultError::InvalidProposal);
        }
        BuildkitePipelineResultProposal::from_evidence(&evidence, idempotency_key)
    }

    pub fn record(
        &self,
        log: &mut BuildkitePipelineResultRecordingLog,
        proposal: &BuildkitePipelineResultProposal,
    ) -> Result<RecordedBuildkitePipelineResult> {
        proposal.validate()?;
        if proposal.scope_digest != self.scope.digest() {
            return Err(BuildkitePipelineResultError::ScopeMismatch);
        }
        match log.records.get(&proposal.idempotency_key_digest) {
            Some(existing) if existing.proposal_digest == proposal.proposal_digest => {
                let replay = RecordedBuildkitePipelineResult::from_proposal(proposal, true);
                replay.validate()?;
                Ok(replay)
            }
            Some(_) => Err(BuildkitePipelineResultError::ReplayConflict),
            None => {
                let recorded = RecordedBuildkitePipelineResult::from_proposal(proposal, false);
                recorded.validate()?;
                log.records
                    .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
                Ok(recorded)
            }
        }
    }

    pub fn read<T: BuildkiteTransport>(
        &self,
        provider: &mut BuildkiteProvider<T>,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<BuildkitePipelineResultEvidence, BuildkiteProviderError> {
        if provider.registration().scope() != &self.scope {
            return Err(BuildkiteProviderError::ScopeMismatch);
        }
        provider.read_pipeline_result(page_size, idempotency_key)
    }
}
