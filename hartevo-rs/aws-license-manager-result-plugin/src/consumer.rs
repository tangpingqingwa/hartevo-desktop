//! Mission-scoped, non-authoritative AWS License Manager evidence consumer.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::AWS_LICENSE_MANAGER_CONSUMER_ID;
use crate::error::{AwsLicenseManagerError, Result};
use crate::model::{AwsLicenseManagerScope, Digest, EvidenceState, QuotaState};
use crate::service::{
    AwsLicenseManagerProposal, AwsLicenseManagerRecord, AwsLicenseManagerRegistration,
    RegistrationState,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseManagerDecisionState {
    ReviewRequired,
    WithinLimit,
    AtLimit,
    QuotaExceeded,
    Partial,
    Drifted,
    AccessLoss,
    NotFound,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<EvidenceState> for LicenseManagerDecisionState {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Complete => LicenseManagerDecisionState::ReviewRequired,
            EvidenceState::Partial => LicenseManagerDecisionState::Partial,
            EvidenceState::QuotaExceeded => LicenseManagerDecisionState::QuotaExceeded,
            EvidenceState::Drifted => LicenseManagerDecisionState::Drifted,
            EvidenceState::AccessLoss => LicenseManagerDecisionState::AccessLoss,
            EvidenceState::NotFound => LicenseManagerDecisionState::NotFound,
            EvidenceState::Throttled => LicenseManagerDecisionState::Throttled,
            EvidenceState::ProviderUnknown => LicenseManagerDecisionState::ProviderUnknown,
            EvidenceState::RegistrationRevoked => LicenseManagerDecisionState::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsLicenseManagerResult {
    pub consumer_id: &'static str,
    pub decision_state: LicenseManagerDecisionState,
    pub observed_state: EvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub license_count: Option<u64>,
    pub consumed_licenses: u64,
    pub quota_state: QuotaState,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub decision_digest: Digest,
}

pub struct MissionAwsLicenseManagerConsumer {
    scope: AwsLicenseManagerScope,
    registration: AwsLicenseManagerRegistration,
    records: BTreeMap<Digest, AwsLicenseManagerRecord>,
}

impl std::fmt::Debug for MissionAwsLicenseManagerConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsLicenseManagerConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsLicenseManagerConsumer {
    pub fn new(
        scope: AwsLicenseManagerScope,
        registration: AwsLicenseManagerRegistration,
    ) -> Result<Self> {
        if registration.state() != RegistrationState::Active
            || registration.scope_digest() != &scope.digest()
            || registration.validate().is_err()
        {
            return Err(AwsLicenseManagerError::InvalidRegistration);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsLicenseManagerScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsLicenseManagerRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsLicenseManagerProposal,
    ) -> Result<MissionAwsLicenseManagerResult> {
        if !self.registration.is_active() {
            return Err(AwsLicenseManagerError::RegistrationRevoked);
        }
        proposal.validate_integrity()?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.evidence.permission_digest != *self.registration.permission_digest()
            || proposal.evidence.evidence_binding_digest
                != *self.registration.evidence_binding_digest()
        {
            return Err(AwsLicenseManagerError::StaleEvidence);
        }
        let decision_state = if proposal.state == EvidenceState::Complete {
            match proposal.evidence.usage.quota_state {
                QuotaState::WithinLimit => LicenseManagerDecisionState::WithinLimit,
                QuotaState::AtLimit => LicenseManagerDecisionState::AtLimit,
                QuotaState::Exceeded => LicenseManagerDecisionState::QuotaExceeded,
                QuotaState::Unknown => LicenseManagerDecisionState::ProviderUnknown,
            }
        } else {
            proposal.state.into()
        };
        let decision_digest = Digest::from_fields(
            "hartevo-mission-aws-license-manager-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest().to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsLicenseManagerResult {
            consumer_id: AWS_LICENSE_MANAGER_CONSUMER_ID,
            decision_state,
            observed_state: proposal.state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            license_count: proposal
                .evidence
                .configuration
                .as_ref()
                .map(|configuration| configuration.license_count),
            consumed_licenses: proposal.evidence.usage.consumed_licenses,
            quota_state: proposal.evidence.usage.quota_state,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &crate::service::AwsLicenseManagerEvidence,
    ) -> Result<()> {
        if !self.registration.is_active() {
            return Err(AwsLicenseManagerError::RegistrationRevoked);
        }
        if evidence.scope_digest != self.scope.digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.permission_digest != *self.registration.permission_digest()
            || evidence.evidence_binding_digest != *self.registration.evidence_binding_digest()
        {
            return Err(AwsLicenseManagerError::StaleEvidence);
        }
        evidence.validate_integrity()
    }

    pub fn record(
        &mut self,
        proposal: &AwsLicenseManagerProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsLicenseManagerRecord> {
        if !self.registration.is_active() {
            return Err(AwsLicenseManagerError::RegistrationRevoked);
        }
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(AwsLicenseManagerError::StaleEvidence);
        }
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsLicenseManagerError::ReplayConflict);
            }
            return Ok(AwsLicenseManagerRecord::new(proposal, key_digest, true));
        }
        let record = AwsLicenseManagerRecord::new(proposal, key_digest.clone(), false);
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }
}

pub type MissionAwsLicenseManagerResultConsumer = MissionAwsLicenseManagerConsumer;
