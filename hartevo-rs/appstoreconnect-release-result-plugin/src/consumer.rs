//! Mission-scoped below-kernel proposal and evidence recording consumer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{AppStoreConnectScope, Digest};
use crate::provider::{AppStoreConnectResultProjection, ProjectionCompleteness, ProjectionStatus};
use crate::service::AppStoreConnectRegistration;
use crate::{
    AppStoreConnectReleaseResultError, CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, Result,
    contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MobileReleaseEvidenceProposal {
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
    pub team_id: String,
    pub app_id: String,
    pub bundle_id: String,
    pub platform: crate::Platform,
    pub pre_release_version_id: String,
    pub build_id: String,
    pub app_store_version_id: String,
    pub beta_group_id: Option<String>,
    pub review_id: Option<String>,
    pub release_id: String,
    pub artifact_digest: Digest,
    pub result_digest: Digest,
    pub status: ProjectionStatus,
    pub completeness: ProjectionCompleteness,
    pub provenance: crate::TransportProvenance,
    pub idempotency_key_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl MobileReleaseEvidenceProposal {
    fn from_projection(
        projection: &AppStoreConnectResultProjection,
        idempotency_key: &str,
    ) -> Result<Self> {
        projection.validate_integrity()?;
        crate::validate_text(idempotency_key, "idempotency key", 256, false)?;
        let scope = &projection.scope;
        let mut proposal = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: CONSUMER_ID.to_owned(),
            consumer_version: PLUGIN_VERSION.to_owned(),
            registration_digest: projection.registration_digest.clone(),
            scope_digest: projection.scope_digest.clone(),
            project_id: scope.project.id.as_str().to_owned(),
            project_revision: scope.project.revision,
            mission_id: scope.mission.id.as_str().to_owned(),
            mission_revision: scope.mission.revision,
            work_product_id: scope.work_product.id.as_str().to_owned(),
            work_product_revision: scope.work_product.revision,
            team_id: scope.team.id.as_str().to_owned(),
            app_id: scope.app.id.as_str().to_owned(),
            bundle_id: scope.app.bundle_id.as_str().to_owned(),
            platform: scope.platform,
            pre_release_version_id: scope.pre_release_version.id.as_str().to_owned(),
            build_id: scope.build.id.as_str().to_owned(),
            app_store_version_id: scope.app_store_version.id.as_str().to_owned(),
            beta_group_id: scope.beta_group.id.as_ref().map(ToString::to_string),
            review_id: scope.review.id.as_ref().map(ToString::to_string),
            release_id: scope.release.id.as_str().to_owned(),
            artifact_digest: scope.artifact.digest.clone(),
            result_digest: projection.evidence_digest.clone(),
            status: projection.status,
            completeness: projection.completeness,
            provenance: projection.provenance,
            idempotency_key_digest: Digest::from_text(idempotency_key)?,
            review_only: true,
            connected: false,
            native: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-appstoreconnect-proposal")?,
        };
        proposal.proposal_digest = proposal.calculate_digest();
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
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AppStoreConnectReleaseResultError::InvalidProposal);
        }
        self.contract_digest.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.artifact_digest.validate()?;
        self.result_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }

    pub const fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "appstoreconnect-release-result/proposal/v1",
            [
                ("contract".to_owned(), self.contract_version.clone()),
                (
                    "contract_digest".to_owned(),
                    self.contract_digest.to_string(),
                ),
                ("consumer".to_owned(), self.consumer_id.clone()),
                ("consumer_version".to_owned(), self.consumer_version.clone()),
                (
                    "registration".to_owned(),
                    self.registration_digest.to_string(),
                ),
                ("scope".to_owned(), self.scope_digest.to_string()),
                ("project".to_owned(), self.project_id.clone()),
                ("mission".to_owned(), self.mission_id.clone()),
                ("work_product".to_owned(), self.work_product_id.clone()),
                ("team".to_owned(), self.team_id.clone()),
                ("app".to_owned(), self.app_id.clone()),
                ("bundle".to_owned(), self.bundle_id.clone()),
                ("platform".to_owned(), self.platform.as_str().to_owned()),
                (
                    "pre_release_version".to_owned(),
                    self.pre_release_version_id.clone(),
                ),
                ("build".to_owned(), self.build_id.clone()),
                (
                    "app_store_version".to_owned(),
                    self.app_store_version_id.clone(),
                ),
                (
                    "beta_group".to_owned(),
                    self.beta_group_id.clone().unwrap_or_default(),
                ),
                (
                    "review".to_owned(),
                    self.review_id.clone().unwrap_or_default(),
                ),
                ("release".to_owned(), self.release_id.clone()),
                ("artifact".to_owned(), self.artifact_digest.to_string()),
                ("result".to_owned(), self.result_digest.to_string()),
                ("status".to_owned(), self.status.as_str().to_owned()),
                (
                    "completeness".to_owned(),
                    format!("{:?}", self.completeness),
                ),
                ("provenance".to_owned(), self.provenance.as_str().to_owned()),
                (
                    "idempotency".to_owned(),
                    self.idempotency_key_digest.to_string(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedMobileReleaseEvidence {
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub result_digest: Digest,
    pub status: ProjectionStatus,
    pub completeness: ProjectionCompleteness,
    pub provenance: crate::TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedMobileReleaseEvidence {
    fn from_proposal(proposal: &MobileReleaseEvidenceProposal, replayed: bool) -> Self {
        let mut recorded = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            result_digest: proposal.result_digest.clone(),
            status: proposal.status,
            completeness: proposal.completeness,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-appstoreconnect-recording")
                .expect("digest"),
        };
        recorded.recording_digest = recorded.calculate_digest();
        recorded
    }

    pub fn validate(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
        }
        self.proposal_digest.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.result_digest.validate()?;
        self.recording_digest.validate()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "appstoreconnect-release-result/recording/v1",
            [
                ("proposal".to_owned(), self.proposal_digest.to_string()),
                (
                    "registration".to_owned(),
                    self.registration_digest.to_string(),
                ),
                ("scope".to_owned(), self.scope_digest.to_string()),
                ("result".to_owned(), self.result_digest.to_string()),
                ("status".to_owned(), self.status.as_str().to_owned()),
                (
                    "completeness".to_owned(),
                    format!("{:?}", self.completeness),
                ),
                ("provenance".to_owned(), self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct MobileReleaseRecordingLog {
    records: BTreeMap<Digest, RecordedMobileReleaseEvidence>,
}

impl MobileReleaseRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedMobileReleaseEvidence> {
        self.records.get(idempotency_key_digest)
    }
}

/// Mission consumer fenced to one exact App Store Connect registration and
/// the exact Project/Mission/Work Product target represented in its scope.
#[derive(Clone, Debug)]
pub struct MissionMobileReleaseConsumer {
    registration_digest: Digest,
    scope: AppStoreConnectScope,
}

impl MissionMobileReleaseConsumer {
    pub fn new(registration: &AppStoreConnectRegistration) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(match registration.status {
                crate::AppStoreConnectRegistrationStatus::Revoked => {
                    AppStoreConnectReleaseResultError::RegistrationRevoked
                }
                crate::AppStoreConnectRegistrationStatus::Reversed => {
                    AppStoreConnectReleaseResultError::RegistrationReversed
                }
                crate::AppStoreConnectRegistrationStatus::Active => {
                    AppStoreConnectReleaseResultError::InvalidRegistration
                }
            });
        }
        Ok(Self {
            registration_digest: registration.registration_digest.clone(),
            scope: registration.scope.clone(),
        })
    }

    pub fn scope(&self) -> &AppStoreConnectScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn compile_proposal(
        &self,
        projection: &AppStoreConnectResultProjection,
        idempotency_key: &str,
    ) -> Result<MobileReleaseEvidenceProposal> {
        if projection.registration_digest != self.registration_digest
            || projection.scope != self.scope
        {
            return Err(AppStoreConnectReleaseResultError::ScopeMismatch);
        }
        MobileReleaseEvidenceProposal::from_projection(projection, idempotency_key)
    }

    pub fn record(
        &self,
        proposal: &MobileReleaseEvidenceProposal,
        log: &mut MobileReleaseRecordingLog,
    ) -> Result<RecordedMobileReleaseEvidence> {
        proposal.validate()?;
        if proposal.registration_digest != self.registration_digest
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(AppStoreConnectReleaseResultError::ScopeMismatch);
        }
        if let Some(existing) = log.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AppStoreConnectReleaseResultError::ReplayConflict);
            }
            return Ok(RecordedMobileReleaseEvidence::from_proposal(proposal, true));
        }
        let recorded = RecordedMobileReleaseEvidence::from_proposal(proposal, false);
        log.records
            .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
        Ok(recorded)
    }

    pub fn verify(
        &self,
        projection: &AppStoreConnectResultProjection,
        proposal: &MobileReleaseEvidenceProposal,
    ) -> Result<bool> {
        projection.validate_integrity()?;
        proposal.validate()?;
        Ok(projection.registration_digest == self.registration_digest
            && projection.scope == self.scope
            && projection.scope_digest == self.scope.digest()
            && proposal.registration_digest == self.registration_digest
            && proposal.scope_digest == self.scope.digest()
            && proposal.result_digest == projection.evidence_digest
            && !projection.connected
            && !projection.native
            && !proposal.connected
            && !proposal.native
            && !proposal.outcome_adopted
            && !proposal.work_product_adopted)
    }
}
