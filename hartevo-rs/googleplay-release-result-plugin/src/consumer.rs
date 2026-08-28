//! Mission/Project/Work Product proposal and below-kernel recording consumer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, EvidenceCompleteness, GooglePlayReleaseEvidence, GooglePlayReleaseScope,
    ReleaseResultStatus,
};
use crate::service::GooglePlayRegistration;
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, GooglePlayReleaseResultError, PLUGIN_VERSION, Result,
    contract_digest, validate_text,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct GooglePlayReleaseProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub status: ReleaseResultStatus,
    pub completeness: EvidenceCompleteness,
    pub release_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_write_performed: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl GooglePlayReleaseProposal {
    fn from_evidence(evidence: &GooglePlayReleaseEvidence, idempotency_key: &str) -> Result<Self> {
        evidence.validate()?;
        validate_text(idempotency_key, "idempotency key", 256, false)?;
        if evidence.completeness != EvidenceCompleteness::Complete
            || evidence.status.is_provider_state()
            || matches!(evidence.status, ReleaseResultStatus::Halted)
            || !evidence
                .releases
                .iter()
                .any(|release| release.artifact_binding_matches)
        {
            return Err(GooglePlayReleaseResultError::NonAdoptableProposal);
        }
        let release = evidence
            .releases
            .iter()
            .find(|release| release.artifact_binding_matches)
            .ok_or(GooglePlayReleaseResultError::NonAdoptableProposal)?;
        let mut proposal = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: CONSUMER_ID.to_owned(),
            consumer_version: PLUGIN_VERSION.to_owned(),
            registration_digest: evidence.registration_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            project_id: evidence.project.id.clone(),
            project_revision: evidence.project.revision,
            mission_id: evidence.mission.id.clone(),
            mission_revision: evidence.mission.revision,
            work_product_id: evidence.work_product.id.clone(),
            work_product_revision: evidence.work_product.revision,
            status: evidence.status,
            completeness: evidence.completeness.clone(),
            release_digest: release.release_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            idempotency_key_digest: Digest::from_text(idempotency_key),
            review_only: true,
            connected: false,
            native: false,
            external_write_performed: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-googleplay-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.consumer_id != CONSUMER_ID
            || self.consumer_version != PLUGIN_VERSION
            || !self.review_only
            || self.connected
            || self.native
            || self.external_write_performed
            || self.outcome_adopted
            || self.work_product_adopted
            || self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(GooglePlayReleaseResultError::TamperedEvidence);
        }
        for digest in [
            &self.contract_digest,
            &self.registration_digest,
            &self.scope_digest,
            &self.release_digest,
            &self.evidence_digest,
            &self.idempotency_key_digest,
            &self.proposal_digest,
        ] {
            if !digest.is_sha256() {
                return Err(GooglePlayReleaseResultError::TamperedEvidence);
            }
        }
        Ok(())
    }

    pub const fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "googleplay-release-result/proposal/v1",
            [
                ("contract".to_owned(), self.contract_version.clone()),
                (
                    "contract_digest".to_owned(),
                    self.contract_digest.as_str().to_owned(),
                ),
                ("consumer".to_owned(), self.consumer_id.clone()),
                ("consumer_version".to_owned(), self.consumer_version.clone()),
                (
                    "registration".to_owned(),
                    self.registration_digest.as_str().to_owned(),
                ),
                ("scope".to_owned(), self.scope_digest.as_str().to_owned()),
                ("project".to_owned(), self.project_id.clone()),
                (
                    "project_revision".to_owned(),
                    self.project_revision.to_string(),
                ),
                ("mission".to_owned(), self.mission_id.clone()),
                (
                    "mission_revision".to_owned(),
                    self.mission_revision.to_string(),
                ),
                ("work_product".to_owned(), self.work_product_id.clone()),
                (
                    "work_product_revision".to_owned(),
                    self.work_product_revision.to_string(),
                ),
                ("status".to_owned(), self.status.as_str().to_owned()),
                (
                    "completeness".to_owned(),
                    format!("{:?}", self.completeness),
                ),
                (
                    "release".to_owned(),
                    self.release_digest.as_str().to_owned(),
                ),
                (
                    "evidence".to_owned(),
                    self.evidence_digest.as_str().to_owned(),
                ),
                (
                    "idempotency".to_owned(),
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecordedGooglePlayReleaseResult {
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub release_digest: Digest,
    pub evidence_digest: Digest,
    pub status: ReleaseResultStatus,
    pub completeness: EvidenceCompleteness,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub external_write_performed: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedGooglePlayReleaseResult {
    fn from_proposal(proposal: &GooglePlayReleaseProposal, replayed: bool) -> Self {
        let mut recorded = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            release_digest: proposal.release_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            status: proposal.status,
            completeness: proposal.completeness.clone(),
            replayed,
            connected: false,
            native: false,
            external_write_performed: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-googleplay-recording"),
        };
        recorded.recording_digest = recorded.calculate_digest();
        recorded
    }

    pub fn validate(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.external_write_performed
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(GooglePlayReleaseResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "googleplay-release-result/recording/v1",
            [
                (
                    "proposal".to_owned(),
                    self.proposal_digest.as_str().to_owned(),
                ),
                (
                    "registration".to_owned(),
                    self.registration_digest.as_str().to_owned(),
                ),
                ("scope".to_owned(), self.scope_digest.as_str().to_owned()),
                (
                    "release".to_owned(),
                    self.release_digest.as_str().to_owned(),
                ),
                (
                    "evidence".to_owned(),
                    self.evidence_digest.as_str().to_owned(),
                ),
                ("status".to_owned(), self.status.as_str().to_owned()),
                (
                    "completeness".to_owned(),
                    format!("{:?}", self.completeness),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct GooglePlayReleaseRecordingLog {
    records: BTreeMap<Digest, RecordedGooglePlayReleaseResult>,
}

impl GooglePlayReleaseRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedGooglePlayReleaseResult> {
        self.records.get(idempotency_key_digest)
    }
}

/// Mission consumer fenced to one exact Project/Mission/Work Product
/// revision tuple and one exact Google Play registration.
#[derive(Clone, Debug)]
pub struct MissionAndroidReleaseConsumer {
    registration_digest: Digest,
    scope: GooglePlayReleaseScope,
}

impl MissionAndroidReleaseConsumer {
    pub fn new(registration: &GooglePlayRegistration) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(match registration.status {
                crate::GooglePlayRegistrationStatus::Revoked => {
                    GooglePlayReleaseResultError::RegistrationRevoked
                }
                crate::GooglePlayRegistrationStatus::Reversed => {
                    GooglePlayReleaseResultError::RegistrationReversed
                }
                crate::GooglePlayRegistrationStatus::Active => {
                    GooglePlayReleaseResultError::InvalidRegistration
                }
            });
        }
        Ok(Self {
            registration_digest: registration.registration_digest().clone(),
            scope: registration.scope().clone(),
        })
    }

    pub fn scope(&self) -> &GooglePlayReleaseScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn compile_release_proposal(
        &self,
        evidence: &GooglePlayReleaseEvidence,
        idempotency_key: &str,
    ) -> Result<GooglePlayReleaseProposal> {
        if evidence.registration_digest != self.registration_digest
            || evidence.scope_digest != self.scope.digest()
        {
            return Err(GooglePlayReleaseResultError::ScopeMismatch);
        }
        GooglePlayReleaseProposal::from_evidence(evidence, idempotency_key)
    }

    pub fn compile_proposal(
        &self,
        evidence: &GooglePlayReleaseEvidence,
        idempotency_key: &str,
    ) -> Result<GooglePlayReleaseProposal> {
        self.compile_release_proposal(evidence, idempotency_key)
    }

    pub fn record(
        &self,
        proposal: &GooglePlayReleaseProposal,
        log: &mut GooglePlayReleaseRecordingLog,
    ) -> Result<RecordedGooglePlayReleaseResult> {
        proposal.validate()?;
        if proposal.registration_digest != self.registration_digest
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(GooglePlayReleaseResultError::ScopeMismatch);
        }
        if let Some(existing) = log.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(GooglePlayReleaseResultError::ReplayConflict);
            }
            return Ok(RecordedGooglePlayReleaseResult::from_proposal(
                proposal, true,
            ));
        }
        let recorded = RecordedGooglePlayReleaseResult::from_proposal(proposal, false);
        log.records
            .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
        Ok(recorded)
    }

    pub fn verify(
        &self,
        evidence: &GooglePlayReleaseEvidence,
        proposal: &GooglePlayReleaseProposal,
    ) -> Result<bool> {
        evidence.validate()?;
        proposal.validate()?;
        Ok(evidence.registration_digest == self.registration_digest
            && evidence.scope_digest == self.scope.digest()
            && proposal.registration_digest == self.registration_digest
            && proposal.scope_digest == self.scope.digest()
            && proposal.evidence_digest == evidence.evidence_digest
            && !evidence.connected
            && !evidence.native
            && !proposal.connected
            && !proposal.native)
    }
}

#[allow(dead_code)]
fn _consumer_scope_digest(scope: &GooglePlayReleaseScope) -> Digest {
    scope.digest()
}
