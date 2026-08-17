use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID, PLUGIN_VERSION,
    error::{AwsNeptuneGraphResultError, Result},
    model::{
        AwsNeptuneGraphScope, Digest, NeptuneEvidenceState, NeptuneGraphEvidence,
        TransportProvenance,
    },
    service::{
        AwsNeptuneGraphResultProposal, AwsNeptuneGraphResultRegistration, RegistrationState,
    },
};

/// Shared service-registration fence used to close already-issued consumers
/// when the owning service revokes, reverses, or supersedes a registration.
#[derive(Debug)]
pub(crate) struct RegistrationFence {
    revision: AtomicU64,
    active: AtomicBool,
}

impl RegistrationFence {
    pub(crate) fn new(registration: &AwsNeptuneGraphResultRegistration) -> Self {
        Self {
            revision: AtomicU64::new(registration.registration_revision),
            active: AtomicBool::new(registration.is_active()),
        }
    }

    pub(crate) fn sync(&self, registration: &AwsNeptuneGraphResultRegistration) {
        self.revision
            .store(registration.registration_revision, Ordering::Release);
        self.active
            .store(registration.is_active(), Ordering::Release);
    }

    pub(crate) fn matches(&self, registration: &AwsNeptuneGraphResultRegistration) -> bool {
        self.active.load(Ordering::Acquire) == registration.is_active()
            && self.revision.load(Ordering::Acquire) == registration.registration_revision
    }
}

/// Mission consumer failures are fail-closed and digest-oriented.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionAwsNeptuneConsumerError {
    #[error("Mission Neptune consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Project/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale or tampered")]
    FenceMismatch,
    #[error("idempotency key was replayed with another proposal")]
    ReplayConflict,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error(transparent)]
    Plugin(#[from] AwsNeptuneGraphResultError),
}

/// A Mission-facing review-only result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsNeptuneResult {
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub state: NeptuneEvidenceState,
    pub evidence: NeptuneGraphEvidence,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsNeptuneResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// Redacted idempotent recording receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsNeptuneResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: NeptuneEvidenceState,
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

impl RecordedAwsNeptuneResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsNeptuneGraphResultProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-neptune-recording"),
        };
        result.recording_digest = recording_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
            || self.recording_digest != recording_digest(self)
        {
            return Err(AwsNeptuneGraphResultError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()?;
        self.scope_digest.validate()
    }
}

fn recording_digest(result: &RecordedAwsNeptuneResult) -> Digest {
    Digest::from_parts(
        "aws-neptune-recording/v1",
        &[
            (
                "idempotency",
                result.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("scope", result.scope_digest.as_str().to_owned()),
            ("state", format!("{:?}", result.state)),
            ("provenance", result.provenance.as_str().to_owned()),
            ("replayed", result.replayed.to_string()),
        ],
    )
}

/// Mission consumer bound to one exact registration and graph scope.
pub struct MissionAwsNeptuneConsumer {
    scope: AwsNeptuneGraphScope,
    registration: AwsNeptuneGraphResultRegistration,
    registration_fence: Arc<RegistrationFence>,
    records: BTreeMap<Digest, RecordedAwsNeptuneResult>,
    active: bool,
}

impl fmt::Debug for MissionAwsNeptuneConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsNeptuneConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl MissionAwsNeptuneConsumer {
    pub fn new(
        scope: AwsNeptuneGraphScope,
        registration: AwsNeptuneGraphResultRegistration,
    ) -> std::result::Result<Self, MissionAwsNeptuneConsumerError> {
        let registration_fence = Arc::new(RegistrationFence::new(&registration));
        Self::new_with_fence(scope, registration, registration_fence)
    }

    pub(crate) fn new_with_fence(
        scope: AwsNeptuneGraphScope,
        registration: AwsNeptuneGraphResultRegistration,
        registration_fence: Arc<RegistrationFence>,
    ) -> std::result::Result<Self, MissionAwsNeptuneConsumerError> {
        registration.validate()?;
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || !registration_fence.matches(&registration)
        {
            return Err(MissionAwsNeptuneConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration,
            registration_fence,
            records: BTreeMap::new(),
            active: true,
        })
    }

    pub fn registration(&self) -> &AwsNeptuneGraphResultRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsNeptuneGraphScope {
        &self.scope
    }

    pub fn is_active(&self) -> bool {
        self.active && self.registration_fence.matches(&self.registration)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke(&mut self) -> std::result::Result<(), MissionAwsNeptuneConsumerError> {
        if !self.active {
            Err(MissionAwsNeptuneConsumerError::Revoked)
        } else {
            self.active = false;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: &AwsNeptuneGraphResultProposal,
    ) -> std::result::Result<MissionAwsNeptuneResult, MissionAwsNeptuneConsumerError> {
        if !self.active || !self.registration_fence.matches(&self.registration) {
            return Err(MissionAwsNeptuneConsumerError::Revoked);
        }
        proposal.validate_integrity()?;
        if !self.registration_fence.matches(&self.registration) {
            return Err(MissionAwsNeptuneConsumerError::Revoked);
        }
        if proposal.service_id != crate::SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
        {
            return Err(MissionAwsNeptuneConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.account_digest != self.scope.account().digest()
            || proposal.region_digest != self.scope.region().digest()
            || proposal.vpc_endpoint_digest != self.scope.vpc_endpoint().digest()
            || proposal.cluster_digest != self.scope.cluster().digest()
            || proposal.graph_digest != self.scope.graph().digest()
            || proposal.query_template_digest != *self.scope.query_template_digest()
            || proposal.parameter_digest != *self.scope.parameter_digest()
            || proposal.mission_digest != self.scope.mission().digest()
            || proposal.project_digest != self.scope.project().digest()
            || proposal.work_product_digest != self.scope.work_product().digest()
            || proposal.evidence.digests.permission_digest != self.registration.permission_digest
            || proposal.evidence.digests.contract_digest != self.registration.contract_digest
            || proposal.evidence.digests.provider_digest != self.registration.provider_digest
            || proposal.evidence.digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || matches!(
                proposal.state,
                NeptuneEvidenceState::Tampered | NeptuneEvidenceState::Revoked
            )
        {
            return Err(MissionAwsNeptuneConsumerError::FenceMismatch);
        }
        Ok(MissionAwsNeptuneResult {
            mission_digest: proposal.mission_digest.clone(),
            project_digest: proposal.project_digest.clone(),
            work_product_digest: proposal.work_product_digest.clone(),
            state: proposal.state,
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsNeptuneGraphResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<RecordedAwsNeptuneResult, MissionAwsNeptuneConsumerError> {
        self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
            return Err(MissionAwsNeptuneConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(MissionAwsNeptuneConsumerError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let receipt = RecordedAwsNeptuneResult::new(key_digest.clone(), proposal, false);
        receipt.validate_integrity()?;
        self.records.insert(key_digest, receipt.clone());
        Ok(receipt)
    }
}

pub type MissionAwsNeptuneResultConsumer = MissionAwsNeptuneConsumer;
