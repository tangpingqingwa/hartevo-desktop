use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{ArgoCdDeploymentError, Result};
use crate::model::{
    ArgoApplicationProjection, ArgoCdDeploymentScope, ArgoCdDeploymentState,
    ArgoOperationProjection, ArgoRequestReceipt, ArgoResourceTreeProjection,
    ArgoSyncStatusProjection, Digest, MissionProjection, ProjectProjection, ProviderProvenance,
    WorkProductProjection,
};
use crate::service::{ArgoCdDeploymentProposal, ArgoCdDeploymentRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
}

impl From<ArgoCdDeploymentState> for ProposalDisposition {
    fn from(_: ArgoCdDeploymentState) -> Self {
        Self::ReviewOnly
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionArgoCdDeploymentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub application: Option<ArgoApplicationProjection>,
    pub resource_tree: Option<ArgoResourceTreeProjection>,
    pub sync_status: Option<ArgoSyncStatusProjection>,
    pub operation: Option<ArgoOperationProjection>,
    pub state: ArgoCdDeploymentState,
    pub disposition: ProposalDisposition,
    pub partial: bool,
    pub request_receipts: Vec<ArgoRequestReceipt>,
    pub provenance: ProviderProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub result_digest: Digest,
}

impl MissionArgoCdDeploymentResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self
                .request_receipts
                .iter()
                .any(|receipt| !receipt.redacted)
            || self.result_digest != self.compute_digest()
        {
            return Err(ArgoCdDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "argocd-mission-result/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project serializes"),
                ),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).expect("work product serializes"),
                ),
                (
                    "application",
                    serde_json::to_string(&self.application).expect("application serializes"),
                ),
                (
                    "resource_tree",
                    serde_json::to_string(&self.resource_tree).expect("resource tree serializes"),
                ),
                (
                    "sync_status",
                    serde_json::to_string(&self.sync_status).expect("sync status serializes"),
                ),
                (
                    "operation",
                    serde_json::to_string(&self.operation).expect("operation serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("partial", self.partial.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipts",
                    self.request_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedArgoCdDeploymentResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub result: MissionArgoCdDeploymentResult,
    pub replayed: bool,
    pub recording_digest: Digest,
}

impl RecordedArgoCdDeploymentResult {
    fn new(
        idempotency_key_digest: Digest,
        result: MissionArgoCdDeploymentResult,
        replayed: bool,
    ) -> Self {
        let recording_digest = Digest::from_parts(
            "argocd-recording/v1",
            &[
                ("key", idempotency_key_digest.as_str().to_owned()),
                ("proposal", result.proposal_digest.as_str().to_owned()),
                ("result", result.result_digest.as_str().to_owned()),
                ("replayed", replayed.to_string()),
            ],
        );
        Self {
            idempotency_key_digest,
            proposal_digest: result.proposal_digest.clone(),
            result,
            replayed,
            recording_digest,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.result.validate_integrity()?;
        if self.proposal_digest != self.result.proposal_digest
            || self.recording_digest
                != Digest::from_parts(
                    "argocd-recording/v1",
                    &[
                        ("key", self.idempotency_key_digest.as_str().to_owned()),
                        ("proposal", self.proposal_digest.as_str().to_owned()),
                        ("result", self.result.result_digest.as_str().to_owned()),
                        ("replayed", self.replayed.to_string()),
                    ],
                )
        {
            return Err(ArgoCdDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Mission consumer bound to one exact registration and one exact Argo CD
/// scope. It is an idempotent recording seam, not a generic deployment store.
pub struct MissionArgoCdDeploymentConsumer {
    scope: ArgoCdDeploymentScope,
    registration: ArgoCdDeploymentRegistration,
    records: BTreeMap<Digest, RecordedArgoCdDeploymentResult>,
}

impl fmt::Debug for MissionArgoCdDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionArgoCdDeploymentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionArgoCdDeploymentConsumer {
    pub fn new(
        scope: ArgoCdDeploymentScope,
        registration: ArgoCdDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(ArgoCdDeploymentError::RegistrationInactive);
        }
        if registration.scope().digest() != scope.digest() {
            return Err(ArgoCdDeploymentError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &ArgoCdDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &ArgoCdDeploymentProposal,
    ) -> Result<MissionArgoCdDeploymentResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(ArgoCdDeploymentError::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.project.id_digest != self.scope.project_context().id().digest()
            || proposal.project.revision != self.scope.project_context().revision()
            || proposal.mission.id_digest != self.scope.mission().id().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.work_product.id_digest != self.scope.work_product().id().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            return Err(ArgoCdDeploymentError::ScopeMismatch);
        }
        let mut result = MissionArgoCdDeploymentResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            application: proposal.application.clone(),
            resource_tree: proposal.resource_tree.clone(),
            sync_status: proposal.sync_status.clone(),
            operation: proposal.operation.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            partial: proposal.partial,
            request_receipts: proposal.request_receipts.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            result_digest: Digest::pending(),
        };
        result.result_digest = result.compute_digest();
        result.validate_integrity()?;
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &ArgoCdDeploymentProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedArgoCdDeploymentResult> {
        let result = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::model::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(ArgoCdDeploymentError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.evidence_digest {
                return Err(ArgoCdDeploymentError::RecordingConflict);
            }
            let replay =
                RecordedArgoCdDeploymentResult::new(key_digest, existing.result.clone(), true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let recording = RecordedArgoCdDeploymentResult::new(key_digest.clone(), result, false);
        recording.validate_integrity()?;
        self.records.insert(key_digest, recording.clone());
        Ok(recording)
    }
}
