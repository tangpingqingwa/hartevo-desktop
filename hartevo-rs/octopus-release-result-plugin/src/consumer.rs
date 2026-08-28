//! Mission-scoped below-kernel proposal and recording consumer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{Digest, OctopusScope};
use crate::provider::{OctopusResultProjection, ProjectionCompleteness, ProjectionStatus};
use crate::service::OctopusRegistration;
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, OctopusReleaseResultError, PLUGIN_VERSION, Result,
    contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OctopusReleaseResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub result_digest: Digest,
    pub status: ProjectionStatus,
    pub completeness: ProjectionCompleteness,
    pub provenance: crate::TransportProvenance,
    pub idempotency_key_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl OctopusReleaseResultProposal {
    fn from_projection(
        projection: &OctopusResultProjection,
        idempotency_key: &str,
    ) -> Result<Self> {
        projection.validate_integrity()?;
        crate::validate_text(idempotency_key, "idempotency key", 256, false)?;
        let mut proposal = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: CONSUMER_ID.to_owned(),
            consumer_version: PLUGIN_VERSION.to_owned(),
            registration_digest: projection.registration_digest.clone(),
            scope_digest: projection.scope_digest.clone(),
            result_digest: projection.evidence_digest.clone(),
            status: projection.status,
            completeness: projection.completeness,
            provenance: projection.provenance,
            idempotency_key_digest: Digest::from_text(idempotency_key)?,
            review_only: true,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-octopus-result-proposal")?,
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
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(OctopusReleaseResultError::InvalidProposal);
        }
        self.contract_digest.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.result_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()?;
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
            "octopus-release-result/proposal/v1",
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
                ("result".to_owned(), self.result_digest.as_str().to_owned()),
                ("status".to_owned(), self.status.as_str().to_owned()),
                (
                    "completeness".to_owned(),
                    format!("{:?}", self.completeness),
                ),
                ("provenance".to_owned(), self.provenance.as_str().to_owned()),
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
pub struct RecordedOctopusReleaseResult {
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

impl RecordedOctopusReleaseResult {
    fn from_proposal(proposal: &OctopusReleaseResultProposal, replayed: bool) -> Self {
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
            recording_digest: Digest::from_text("unsealed-octopus-result-recording")
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
            return Err(OctopusReleaseResultError::TamperedEvidence);
        }
        self.proposal_digest.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.result_digest.validate()?;
        self.recording_digest.validate()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "octopus-release-result/recording/v1",
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
                ("result".to_owned(), self.result_digest.as_str().to_owned()),
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
pub struct OctopusReleaseResultRecordingLog {
    records: BTreeMap<Digest, RecordedOctopusReleaseResult>,
}

impl OctopusReleaseResultRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedOctopusReleaseResult> {
        self.records.get(idempotency_key_digest)
    }
}

/// Consumer fenced to one exact registration and one exact Mission/Project/
/// Consent plus Octopus resource scope.
#[derive(Clone, Debug)]
pub struct MissionOctopusReleaseConsumer {
    registration_digest: Digest,
    scope: OctopusScope,
}

impl MissionOctopusReleaseConsumer {
    pub fn new(registration: &OctopusRegistration) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(match registration.status {
                crate::OctopusRegistrationStatus::Revoked => {
                    OctopusReleaseResultError::RegistrationRevoked
                }
                crate::OctopusRegistrationStatus::Reversed => {
                    OctopusReleaseResultError::RegistrationReversed
                }
                crate::OctopusRegistrationStatus::Active => {
                    OctopusReleaseResultError::InvalidRegistration
                }
            });
        }
        Ok(Self {
            registration_digest: registration.registration_digest.clone(),
            scope: registration.scope.clone(),
        })
    }

    pub fn scope(&self) -> &OctopusScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn compile_proposal(
        &self,
        projection: &OctopusResultProjection,
        idempotency_key: &str,
    ) -> Result<OctopusReleaseResultProposal> {
        if projection.registration_digest != self.registration_digest
            || projection.scope != self.scope
        {
            return Err(OctopusReleaseResultError::ScopeMismatch);
        }
        OctopusReleaseResultProposal::from_projection(projection, idempotency_key)
    }

    pub fn record(
        &self,
        proposal: &OctopusReleaseResultProposal,
        log: &mut OctopusReleaseResultRecordingLog,
    ) -> Result<RecordedOctopusReleaseResult> {
        proposal.validate()?;
        if proposal.registration_digest != self.registration_digest
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(OctopusReleaseResultError::ScopeMismatch);
        }
        if let Some(existing) = log.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(OctopusReleaseResultError::ReplayConflict);
            }
            return Ok(RecordedOctopusReleaseResult::from_proposal(proposal, true));
        }
        let recorded = RecordedOctopusReleaseResult::from_proposal(proposal, false);
        log.records
            .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
        Ok(recorded)
    }

    pub fn verify(
        &self,
        projection: &OctopusResultProjection,
        proposal: &OctopusReleaseResultProposal,
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
            && !proposal.native)
    }
}
