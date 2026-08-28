//! Mission-bound result consumer. This is a projection consumer only; it has
//! no Truth, Effect, Receipt, Verification, Outcome, or Work Product adoption
//! authority.

use serde::{Deserialize, Serialize};

use crate::{
    AnthropicMessageResultError, Result,
    model::{
        AnthropicMessageResultEvidence, AnthropicScope, Digest, Layer1Authority, MissionId,
        ProjectId, ProviderProvenance, ResultStatus, StopReason, UsageProjection, WorkProductId,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAnthropicResult {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub result_fingerprint: Digest,
    pub status: ResultStatus,
    pub stop_reason: Option<StopReason>,
    pub usage: Option<UsageProjection>,
    pub latency_ms: u64,
    pub refusal: Option<crate::RefusalProjection>,
    pub citation_count: usize,
    pub content_digest: Digest,
    pub provenance: ProviderProvenance,
    pub authority: Layer1Authority,
    pub adopted_outcome: bool,
}

impl MissionAnthropicResult {
    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub const fn has_kernel_authority(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct MissionAnthropicResultConsumer {
    scope: AnthropicScope,
    consumer_digest: Digest,
}

impl MissionAnthropicResultConsumer {
    pub fn new(scope: AnthropicScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope,
            consumer_digest: Digest::from_text(crate::CONSUMER_ID),
        })
    }

    pub fn from_scope(scope: &AnthropicScope) -> Result<Self> {
        Self::new(scope.clone())
    }

    pub fn scope(&self) -> &AnthropicScope {
        &self.scope
    }

    pub fn consumer_digest(&self) -> &Digest {
        &self.consumer_digest
    }

    pub fn consume(
        &self,
        evidence: &AnthropicMessageResultEvidence,
    ) -> Result<MissionAnthropicResult> {
        self.consume_at_revisions(
            evidence,
            self.scope.project.revision,
            self.scope.mission.revision,
            self.scope.work_product.revision,
        )
    }

    pub fn consume_at_revisions(
        &self,
        evidence: &AnthropicMessageResultEvidence,
        project_revision: u64,
        mission_revision: u64,
        work_product_revision: u64,
    ) -> Result<MissionAnthropicResult> {
        evidence.verify_integrity()?;
        if evidence.scope != self.scope
            || evidence.scope_digest != self.scope.digest()
            || evidence.provenance.connected()
            || evidence.provenance.native()
            || !evidence.authority.is_non_authoritative()
        {
            return Err(AnthropicMessageResultError::ScopeMismatch);
        }
        if project_revision != self.scope.project.revision {
            return Err(AnthropicMessageResultError::StaleProjectRevision);
        }
        if mission_revision != self.scope.mission.revision {
            return Err(AnthropicMessageResultError::StaleMissionRevision);
        }
        if work_product_revision != self.scope.work_product.revision {
            return Err(AnthropicMessageResultError::StaleWorkProductRevision);
        }
        Ok(MissionAnthropicResult {
            project_id: self.scope.project.project_id.clone(),
            mission_id: self.scope.mission.mission_id.clone(),
            work_product_id: self.scope.work_product.work_product_id.clone(),
            project_revision,
            mission_revision,
            work_product_revision,
            request_digest: evidence.request_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            result_fingerprint: evidence.result_fingerprint(),
            status: evidence.status,
            stop_reason: evidence.stop_reason,
            usage: evidence.usage.clone(),
            latency_ms: evidence.latency_ms,
            refusal: evidence.refusal.clone(),
            citation_count: evidence.citations.len(),
            content_digest: evidence.content_digest.clone(),
            provenance: evidence.provenance,
            authority: Layer1Authority::layer_one(),
            adopted_outcome: false,
        })
    }

    pub fn consume_result(
        &self,
        evidence: &AnthropicMessageResultEvidence,
    ) -> Result<MissionAnthropicResult> {
        self.consume(evidence)
    }
}
