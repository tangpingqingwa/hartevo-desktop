//! Mission-facing consumer below Truth, Effect, Receipt, and Outcome authority.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::{
    AWS_FIREWALL_MANAGER_CONSUMER_ID,
    error::{AwsFirewallManagerError, Result},
    model::{
        AwsFirewallManagerScope, Digest, EvidenceState, MissionBinding, ProjectBinding,
        WorkProductBinding,
    },
    service::{
        AwsFirewallManagerEvidence, AwsFirewallManagerProposal, AwsFirewallManagerRecord,
        AwsFirewallManagerRegistration, RegistrationState,
    },
};

pub type ConsumerError = AwsFirewallManagerError;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsFirewallManagerDecisionState {
    Accepted,
    ReviewOnly,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsFirewallManagerResult {
    pub consumer_id: String,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub evidence: AwsFirewallManagerEvidence,
    pub decision_state: MissionAwsFirewallManagerDecisionState,
    pub accepted: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub truth_authority: bool,
    pub effect_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub result_digest: Digest,
}

pub type MissionAwsFirewallManagerConsumerResult = MissionAwsFirewallManagerResult;
pub type MissionAwsFirewallManagerDecisionProposal = MissionAwsFirewallManagerResult;

pub struct MissionAwsFirewallManagerConsumer {
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    scope_digest: Digest,
    permission_digest: Digest,
    policy_allowlist_digest: Digest,
    registration_digest: Option<Digest>,
    revoked: bool,
    records: BTreeMap<Digest, AwsFirewallManagerRecord>,
}

impl fmt::Debug for MissionAwsFirewallManagerConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsFirewallManagerConsumer")
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("policy_allowlist_digest", &self.policy_allowlist_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsFirewallManagerConsumer {
    pub fn new(scope: &AwsFirewallManagerScope) -> Self {
        Self {
            mission: scope.mission().clone(),
            project: scope.project().clone(),
            work_product: scope.work_product().clone(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permissions().digest().clone(),
            policy_allowlist_digest: scope.policy_allowlist_digest().clone(),
            registration_digest: None,
            revoked: false,
            records: BTreeMap::new(),
        }
    }

    pub fn from_bindings(
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        scope_digest: Digest,
        permission_digest: Digest,
        policy_allowlist_digest: Digest,
    ) -> Self {
        Self {
            mission,
            project,
            work_product,
            scope_digest,
            permission_digest,
            policy_allowlist_digest,
            registration_digest: None,
            revoked: false,
            records: BTreeMap::new(),
        }
    }

    pub fn bind_registration(
        &mut self,
        registration: &AwsFirewallManagerRegistration,
    ) -> Result<()> {
        if registration.state() != RegistrationState::Active {
            return Err(AwsFirewallManagerError::RegistrationInactive);
        }
        registration.validate()?;
        if registration.scope_digest() != &self.scope_digest
            || registration.permission_digest() != &self.permission_digest
            || registration.policy_allowlist_digest() != &self.policy_allowlist_digest
        {
            return Err(AwsFirewallManagerError::StaleMission);
        }
        self.registration_digest = Some(registration.registration_digest().clone());
        Ok(())
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(AwsFirewallManagerError::RegistrationInactive);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: &AwsFirewallManagerProposal,
    ) -> Result<MissionAwsFirewallManagerResult> {
        proposal.validate_integrity()?;
        self.consume_evidence(&proposal.evidence)
    }

    pub fn consume_evidence(
        &self,
        evidence: &AwsFirewallManagerEvidence,
    ) -> Result<MissionAwsFirewallManagerResult> {
        if self.revoked {
            return Err(AwsFirewallManagerError::RegistrationInactive);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &evidence.registration_digest
        {
            return Err(AwsFirewallManagerError::RegistrationMismatch);
        }
        if evidence.scope_digest != self.scope_digest
            || evidence.mission != self.mission
            || evidence.project != self.project
            || evidence.work_product != self.work_product
        {
            return Err(AwsFirewallManagerError::StaleMission);
        }
        if evidence.evidence.permission_digest != self.permission_digest
            || evidence.evidence.policy_allowlist_digest != self.policy_allowlist_digest
        {
            return Err(AwsFirewallManagerError::PermissionDrift);
        }
        evidence.validate_integrity()?;
        if evidence.connected
            || evidence.native
            || evidence.first_party
            || evidence.provider_receipt
            || evidence.remediation_authority
            || evidence.effect_authority
            || evidence.outcome_adopted
            || evidence.work_product_adopted
        {
            return Err(AwsFirewallManagerError::AuthorityViolation);
        }
        if evidence.state != EvidenceState::Complete || !evidence.pagination.complete {
            return Err(AwsFirewallManagerError::NonAdoptableEvidence);
        }
        let mut result = MissionAwsFirewallManagerResult {
            consumer_id: AWS_FIREWALL_MANAGER_CONSUMER_ID.to_owned(),
            mission: self.mission.clone(),
            project: self.project.clone(),
            work_product: self.work_product.clone(),
            evidence: evidence.clone(),
            decision_state: MissionAwsFirewallManagerDecisionState::Accepted,
            accepted: true,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            effect_authority: false,
            connected: false,
            native: false,
            first_party: false,
            result_digest: Digest::zero(),
        };
        result.result_digest = result.compute_digest();
        Ok(result)
    }

    pub fn propose_review(
        &self,
        evidence: &AwsFirewallManagerEvidence,
    ) -> Result<MissionAwsFirewallManagerResult> {
        if self.revoked {
            return Err(AwsFirewallManagerError::RegistrationInactive);
        }
        if evidence.scope_digest != self.scope_digest
            || evidence.mission != self.mission
            || evidence.project != self.project
            || evidence.work_product != self.work_product
        {
            return Err(AwsFirewallManagerError::StaleMission);
        }
        evidence.validate_integrity()?;
        let mut result = MissionAwsFirewallManagerResult {
            consumer_id: AWS_FIREWALL_MANAGER_CONSUMER_ID.to_owned(),
            mission: self.mission.clone(),
            project: self.project.clone(),
            work_product: self.work_product.clone(),
            evidence: evidence.clone(),
            decision_state: MissionAwsFirewallManagerDecisionState::ReviewOnly,
            accepted: false,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            effect_authority: false,
            connected: false,
            native: false,
            first_party: false,
            result_digest: Digest::zero(),
        };
        result.result_digest = result.compute_digest();
        Ok(result)
    }

    pub fn verify_proposal(&self, proposal: &AwsFirewallManagerProposal) -> Result<()> {
        proposal.validate_integrity()?;
        if proposal.evidence.scope_digest != self.scope_digest
            || proposal.evidence.mission != self.mission
            || proposal.evidence.project != self.project
            || proposal.evidence.work_product != self.work_product
        {
            return Err(AwsFirewallManagerError::StaleMission);
        }
        if proposal.evidence.evidence.permission_digest != self.permission_digest
            || proposal.evidence.evidence.policy_allowlist_digest != self.policy_allowlist_digest
        {
            return Err(AwsFirewallManagerError::PermissionDrift);
        }
        Ok(())
    }

    pub fn record(
        &mut self,
        proposal: &AwsFirewallManagerProposal,
        key: impl Into<String>,
    ) -> Result<AwsFirewallManagerRecord> {
        self.verify_proposal(proposal)?;
        let key_digest = Digest::from_text(key.into());
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != *proposal.digest() {
                return Err(AwsFirewallManagerError::ReplayMismatch);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = Digest::from_parts(
                "aws-fms-recording/v1",
                &[
                    ("key", replay.record_key_digest.to_string()),
                    ("proposal", replay.proposal_digest.to_string()),
                    ("evidence", replay.evidence_digest.to_string()),
                    ("replayed", "true".to_owned()),
                ],
            );
            return Ok(replay);
        }
        let mut record = AwsFirewallManagerRecord {
            record_key_digest: key_digest,
            proposal_digest: proposal.digest().clone(),
            evidence_digest: proposal.evidence.evidence.evidence_digest.clone(),
            recording_digest: Digest::zero(),
            replayed: false,
            provider_receipt: false,
            native: false,
            connected: false,
        };
        record.recording_digest = Digest::from_parts(
            "aws-fms-recording/v1",
            &[
                ("key", record.record_key_digest.to_string()),
                ("proposal", record.proposal_digest.to_string()),
                ("evidence", record.evidence_digest.to_string()),
                ("replayed", "false".to_owned()),
            ],
        );
        record.validate_integrity()?;
        self.records
            .insert(record.record_key_digest.clone(), record.clone());
        Ok(record)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl MissionAwsFirewallManagerResult {
    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-mission-result/v1",
            &[
                ("consumer", self.consumer_id.clone()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).unwrap_or_default(),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).unwrap_or_default(),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).unwrap_or_default(),
                ),
                ("evidence", self.evidence.digest().to_string()),
                ("state", format!("{:?}", self.decision_state)),
                ("accepted", self.accepted.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.consumer_id != AWS_FIREWALL_MANAGER_CONSUMER_ID
            || self.adopted_outcome
            || self.adopted_work_product
            || self.truth_authority
            || self.effect_authority
            || self.connected
            || self.native
            || self.first_party
            || self.result_digest != self.compute_digest()
        {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

pub type RecordedAwsFirewallManagerResult = MissionAwsFirewallManagerResult;
