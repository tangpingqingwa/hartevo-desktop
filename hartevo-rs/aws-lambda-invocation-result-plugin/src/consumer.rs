//! Mission-scoped execution-result proposal and idempotent recording seam.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::Result;
use crate::model::{
    AwsLambdaScope, Digest, FailureCode, InputId, InvocationProposal, InvocationResultProjection,
    InvocationStatus, InvocationType, ProjectionCompleteness, RetryPolicy, TransportProvenance,
    VerificationFailure, VerificationReport, WorkProductIdentity,
};
use crate::{
    AwsLambdaInvocationResultError, CONSUMER_ID, MAX_IDENTIFIER_BYTES, SERVICE_ID, validate_text,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Accepted,
    Queued,
    Running,
    Succeeded,
    FunctionError,
    Throttled,
    Timeout,
    Partial,
    ProviderUnknown,
}

impl ProposalDisposition {
    pub const fn from_status(status: InvocationStatus) -> Self {
        match status {
            InvocationStatus::Accepted => Self::Accepted,
            InvocationStatus::Queued => Self::Queued,
            InvocationStatus::Running => Self::Running,
            InvocationStatus::Succeeded => Self::Succeeded,
            InvocationStatus::FunctionError => Self::FunctionError,
            InvocationStatus::Throttled => Self::Throttled,
            InvocationStatus::Timeout => Self::Timeout,
            InvocationStatus::Partial => Self::Partial,
            InvocationStatus::ProviderUnknown => Self::ProviderUnknown,
        }
    }

    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Succeeded)
    }
}

/// Canonical digest-fenced proposal for the next Mission decision. This is a
/// review-only record and cannot adopt a Work Product or Outcome.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLambdaInvocationResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub function: crate::model::FunctionTarget,
    pub invocation_type: InvocationType,
    pub input_id: InputId,
    pub input_revision: u64,
    pub input_digest: Digest,
    pub config_id: crate::model::ConfigId,
    pub config_revision: u64,
    pub config_digest: Digest,
    pub retry: RetryPolicy,
    pub retry_digest: Digest,
    pub mission: crate::model::MissionIdentity,
    pub project: crate::model::ProjectIdentity,
    pub work_product: WorkProductIdentity,
    pub status: InvocationStatus,
    pub disposition: ProposalDisposition,
    pub failure_code: Option<FailureCode>,
    pub completeness: ProjectionCompleteness,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub usage_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl AwsLambdaInvocationResultProposal {
    pub fn new(
        scope: &AwsLambdaScope,
        projection: &InvocationResultProjection,
        idempotency_key: &str,
    ) -> Result<Self> {
        validate_text(
            idempotency_key,
            "idempotencyKey",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        scope.validate()?;
        projection.validate_integrity()?;
        if projection.scope_digest != scope.digest()
            || projection.function != scope.function
            || projection.invocation_type != scope.invocation_type
            || projection.input_digest != scope.input.input_digest
            || projection.input_revision != scope.input.revision
            || projection.config_digest != scope.config.digest()
            || projection.config_revision != scope.config.revision
            || projection.retry_revision != scope.retry.revision
            || projection.mission != scope.mission
            || projection.project != scope.project
            || projection.work_product != scope.work_product
        {
            return Err(AwsLambdaInvocationResultError::ScopeMismatch);
        }
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: projection.registration_digest.clone(),
            scope_digest: projection.scope_digest.clone(),
            request_digest: projection.request_digest.clone(),
            function: projection.function.clone(),
            invocation_type: projection.invocation_type,
            input_id: scope.input.id.clone(),
            input_revision: projection.input_revision,
            input_digest: projection.input_digest.clone(),
            config_id: scope.config.id.clone(),
            config_revision: projection.config_revision,
            config_digest: projection.config_digest.clone(),
            retry: scope.retry.clone(),
            retry_digest: projection.retry_digest.clone(),
            mission: projection.mission.clone(),
            project: projection.project.clone(),
            work_product: projection.work_product.clone(),
            status: projection.status,
            disposition: ProposalDisposition::from_status(projection.status),
            failure_code: projection.failure_code,
            completeness: projection.completeness,
            output_digest: projection.output_digest.clone(),
            error_digest: projection.error_digest.clone(),
            usage_digest: projection.usage.digest(),
            evidence_digest: projection.evidence_digest.clone(),
            provenance: projection.provenance,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            proposal_digest: Digest::from_text("unsealed-aws-lambda-result-proposal"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.function.validate()?;
        self.input_id.validate()?;
        self.input_digest.validate()?;
        self.config_id.validate()?;
        self.config_digest.validate()?;
        self.retry.validate()?;
        self.retry_digest.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.output_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.error_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.usage_digest.validate()?;
        self.evidence_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-execution-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("function", self.function.digest().as_str().to_owned()),
                ("invocation_type", self.invocation_type.as_str().to_owned()),
                ("input_id", self.input_id.id.clone()),
                ("input_revision", self.input_revision.to_string()),
                ("input", self.input_digest.as_str().to_owned()),
                ("config_id", self.config_id.id.clone()),
                ("config_revision", self.config_revision.to_string()),
                ("config", self.config_digest.as_str().to_owned()),
                ("retry", self.retry_digest.as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("status", self.status.as_str().to_owned()),
                ("disposition", format!("{:?}", self.disposition)),
                ("failure", format!("{:?}", self.failure_code)),
                ("completeness", format!("{:?}", self.completeness)),
                (
                    "output",
                    self.output_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "error",
                    self.error_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("usage", self.usage_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsLambdaResult {
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub status: InvocationStatus,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsLambdaResult {
    fn from_proposal(proposal: &AwsLambdaInvocationResultProposal, replayed: bool) -> Self {
        let mut result = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            status: proposal.status,
            disposition: proposal.disposition,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aws-lambda-result-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.proposal_digest.validate()?;
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-result-recording/v1",
            &[
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                ("disposition", format!("{:?}", self.disposition)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct AwsLambdaResultRecordingLog {
    records: BTreeMap<Digest, RecordedAwsLambdaResult>,
}

impl AwsLambdaResultRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedAwsLambdaResult> {
        self.records.get(idempotency_key_digest)
    }
}

/// Mission consumer scoped to one exact Lambda registration fence.
#[derive(Clone, Debug)]
pub struct MissionAwsLambdaResultConsumer {
    scope: AwsLambdaScope,
}

impl MissionAwsLambdaResultConsumer {
    pub fn new(scope: AwsLambdaScope) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &AwsLambdaScope {
        &self.scope
    }

    pub fn compile_proposal(
        &self,
        projection: &InvocationResultProjection,
        idempotency_key: &str,
    ) -> Result<AwsLambdaInvocationResultProposal> {
        self.compile_proposal_at_revision(projection, idempotency_key, self.scope.mission.revision)
    }

    pub fn compile_proposal_at_revision(
        &self,
        projection: &InvocationResultProjection,
        idempotency_key: &str,
        current_mission_revision: u64,
    ) -> Result<AwsLambdaInvocationResultProposal> {
        if current_mission_revision != self.scope.mission.revision {
            return Err(AwsLambdaInvocationResultError::StaleMissionRevision);
        }
        AwsLambdaInvocationResultProposal::new(&self.scope, projection, idempotency_key)
    }

    pub fn record(
        &self,
        proposal: &AwsLambdaInvocationResultProposal,
        log: &mut AwsLambdaResultRecordingLog,
    ) -> Result<RecordedAwsLambdaResult> {
        proposal.validate_integrity()?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission != self.scope.mission
            || proposal.project != self.scope.project
            || proposal.work_product != self.scope.work_product
            || proposal.function != self.scope.function
            || proposal.input_digest != self.scope.input.input_digest
            || proposal.config_digest != self.scope.config.digest()
            || proposal.retry_digest != self.scope.retry.digest()
        {
            return Err(AwsLambdaInvocationResultError::ScopeMismatch);
        }
        if let Some(existing) = log.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsLambdaInvocationResultError::ReplayConflict);
            }
            return Ok(RecordedAwsLambdaResult::from_proposal(proposal, true));
        }
        let recorded = RecordedAwsLambdaResult::from_proposal(proposal, false);
        log.records
            .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
        Ok(recorded)
    }

    pub fn record_with_key(
        &self,
        proposal: &AwsLambdaInvocationResultProposal,
        idempotency_key: &str,
        log: &mut AwsLambdaResultRecordingLog,
    ) -> Result<RecordedAwsLambdaResult> {
        validate_text(
            idempotency_key,
            "idempotencyKey",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        if proposal.idempotency_key_digest != Digest::from_text(idempotency_key) {
            return Err(AwsLambdaInvocationResultError::ReplayConflict);
        }
        self.record(proposal, log)
    }

    #[allow(clippy::too_many_lines)]
    pub fn verify(
        &self,
        invocation: &InvocationProposal,
        projection: &InvocationResultProjection,
        proposal: &AwsLambdaInvocationResultProposal,
        registration_digest: &Digest,
    ) -> Result<VerificationReport> {
        let mut failures = Vec::new();
        if !self.scope_matches_invocation(invocation) {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if invocation.registration_digest != *registration_digest
            || projection.registration_digest != *registration_digest
            || proposal.registration_digest != *registration_digest
        {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if invocation.request_digest != projection.request_digest
            || proposal.request_digest != invocation.request_digest
        {
            failures.push(VerificationFailure::RequestDigestMismatch);
        }
        if projection.scope_digest != self.scope.digest()
            || proposal.scope_digest != self.scope.digest()
        {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if projection.function.function_arn != self.scope.function.function_arn {
            failures.push(VerificationFailure::FunctionArnMismatch);
        }
        if projection.function.version != self.scope.function.version {
            failures.push(VerificationFailure::FunctionVersionMismatch);
        }
        if projection.function.alias != self.scope.function.alias {
            failures.push(VerificationFailure::FunctionAliasMismatch);
        }
        if projection.function.code_sha256 != self.scope.function.code_sha256 {
            failures.push(VerificationFailure::FunctionCodeShaMismatch);
        }
        if projection.function.revision != self.scope.function.revision {
            failures.push(VerificationFailure::FunctionRevisionMismatch);
        }
        if projection.input_digest != self.scope.input.input_digest {
            failures.push(VerificationFailure::InputDigestMismatch);
        }
        if projection.config_digest != self.scope.config.digest() {
            failures.push(VerificationFailure::ConfigDigestMismatch);
        }
        if projection.retry_digest != self.scope.retry.digest() {
            failures.push(VerificationFailure::RetryDigestMismatch);
        }
        if projection.mission.revision != self.scope.mission.revision
            || proposal.mission.revision != self.scope.mission.revision
        {
            failures.push(VerificationFailure::MissionRevisionMismatch);
        }
        if projection.project.revision != self.scope.project.revision
            || proposal.project.revision != self.scope.project.revision
        {
            failures.push(VerificationFailure::ProjectRevisionMismatch);
        }
        if projection.work_product.revision != self.scope.work_product.revision
            || proposal.work_product.revision != self.scope.work_product.revision
        {
            failures.push(VerificationFailure::WorkProductRevisionMismatch);
        }
        if proposal.output_digest != projection.output_digest {
            failures.push(VerificationFailure::OutputDigestMismatch);
        }
        if proposal.error_digest != projection.error_digest {
            failures.push(VerificationFailure::ErrorDigestMismatch);
        }
        if proposal.usage_digest != projection.usage.digest() {
            failures.push(VerificationFailure::UsageDigestMismatch);
        }
        if proposal.evidence_digest != projection.evidence_digest
            || projection.calculate_evidence_digest() != projection.evidence_digest
        {
            failures.push(VerificationFailure::EvidenceDigestMismatch);
        }
        if projection.completeness == ProjectionCompleteness::Partial {
            failures.push(VerificationFailure::PartialEvidence);
        }
        if projection.status == InvocationStatus::ProviderUnknown {
            failures.push(VerificationFailure::ProviderUnknown);
        }
        if invocation.connected || projection.connected || proposal.connected {
            failures.push(VerificationFailure::ConnectedClaim);
        }
        if invocation.native || projection.native || proposal.native {
            failures.push(VerificationFailure::NativeClaim);
        }
        if invocation.first_party || projection.first_party || proposal.first_party {
            failures.push(VerificationFailure::FirstPartyClaim);
        }
        if invocation.validate_integrity().is_err()
            || projection.validate_integrity().is_err()
            || proposal.validate_integrity().is_err()
        {
            failures.push(VerificationFailure::EvidenceDigestMismatch);
        }
        failures.sort_unstable();
        failures.dedup();
        Ok(VerificationReport {
            verified: failures.is_empty(),
            failures,
        })
    }

    fn scope_matches_invocation(&self, invocation: &InvocationProposal) -> bool {
        invocation.scope_digest == self.scope.digest()
            && invocation.function == self.scope.function
            && invocation.invocation_type == self.scope.invocation_type
            && invocation.input == self.scope.input
            && invocation.config == self.scope.config
            && invocation.retry == self.scope.retry
            && invocation.mission == self.scope.mission
            && invocation.project == self.scope.project
            && invocation.work_product == self.scope.work_product
    }
}

pub type AwsLambdaExecutionResultProposal = AwsLambdaInvocationResultProposal;
pub type MissionAwsLambdaInvocationResultConsumer = MissionAwsLambdaResultConsumer;
