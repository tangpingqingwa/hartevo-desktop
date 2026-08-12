use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, ActorId, ConnectionId, CreatorHiring, CreatorHiringAward, CreatorId,
    CreatorMilestoneId, CreatorTaskId, DeliverableId, EffectClass, EffectId, EffectStatus, Mission,
    MissionId, Money, PayoutId, ProjectId, ReviewId, TenantId, VerificationStatus,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorTaskSpec {
    pub id: CreatorTaskId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: CreatorId,
    pub hiring_award: CreatorHiringAward,
    pub title: String,
    pub brief: String,
    pub acceptance_criteria: Vec<String>,
    pub deliverable_requirements: Vec<String>,
    pub bounty: Money,
    pub milestones: Vec<CreatorMilestoneSpec>,
    pub revision_limit: u16,
    pub usage_rights: UsageRights,
    pub due_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorMilestoneSpec {
    pub id: CreatorMilestoneId,
    pub title: String,
    pub amount: Money,
    pub due_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageRights {
    pub license: String,
    pub territories: Vec<String>,
    pub channels: Vec<String>,
    pub exclusivity: String,
    pub disclosure_required: bool,
    pub source_manifest_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorTaskStatus {
    Draft,
    Published,
    Accepted,
    InProgress,
    Submitted,
    RevisionRequested,
    SettlementPending,
    PartiallyPaid,
    Paid,
    Rejected,
    Disputed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorMilestoneStatus {
    Draft,
    Open,
    AcceptedByCreator,
    InProgress,
    Submitted,
    RevisionRequested,
    SettlementPending,
    Paid,
    Rejected,
    Disputed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorMilestone {
    pub id: CreatorMilestoneId,
    pub title: String,
    pub amount: Money,
    pub due_at: DateTime<Utc>,
    pub status: CreatorMilestoneStatus,
    pub revisions_used: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FundingReservation {
    pub provider: String,
    pub external_id: String,
    pub connection_id: ConnectionId,
    pub payer_account_id: AccountId,
    pub amount: Money,
    pub contract_revision: u64,
    pub contract_digest: String,
    pub reserved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub request_digest: String,
    pub provider_receipt_digest: String,
    pub verification_evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorEligibility {
    pub creator_id: CreatorId,
    pub connected_account_id: AccountId,
    pub connection_id: ConnectionId,
    pub kyc_verified: bool,
    pub payouts_enabled: bool,
    pub region_supported: bool,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verification_evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorAcceptance {
    pub creator_id: CreatorId,
    pub connected_account_id: AccountId,
    pub connection_id: ConnectionId,
    pub contract_revision: u64,
    pub contract_digest: String,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorDeliverableInput {
    pub id: DeliverableId,
    pub milestone_id: CreatorMilestoneId,
    pub artifact_uri: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub content_digest: String,
    pub uploaded_at: DateTime<Utc>,
    pub assessment: DeliverableAssessment,
    pub rights: RightsAttestation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverableAssessment {
    pub scanner: String,
    pub clean: bool,
    pub assessed_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RightsAttestation {
    pub ownership_or_license: String,
    pub source_manifest_digest: String,
    pub permitted_use: String,
    pub verified: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverableStatus {
    ReadyForReview,
    Accepted,
    Superseded,
    Rejected,
    Disputed,
}

/// User access and contracted usage rights are deliberately separate. A clean
/// upload can be inspected for review, but the contracted usage rights become
/// active only after the exact accepted deliverable has a verified payout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverableEntitlementStatus {
    EvaluationOnly,
    AcceptedAwaitingVerifiedPayout,
    ContractUsageGranted,
    Superseded,
    Rejected,
    Disputed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorDeliverable {
    pub id: DeliverableId,
    pub task_id: CreatorTaskId,
    pub milestone_id: CreatorMilestoneId,
    pub revision: u32,
    pub artifact_uri: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub content_digest: String,
    pub uploaded_at: DateTime<Utc>,
    pub assessment: DeliverableAssessment,
    pub rights: RightsAttestation,
    pub status: DeliverableStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Accept,
    RequestRevision,
    Reject,
    Dispute,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptanceCheck {
    pub requirement: String,
    pub satisfied: bool,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverableReviewInput {
    pub id: ReviewId,
    pub reviewer_id: ActorId,
    pub decision: ReviewDecision,
    pub acceptance_checks: Vec<AcceptanceCheck>,
    pub notes: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverableReview {
    pub id: ReviewId,
    pub task_id: CreatorTaskId,
    pub deliverable_id: DeliverableId,
    pub deliverable_digest: String,
    pub reviewer_id: ActorId,
    pub decision: ReviewDecision,
    pub acceptance_checks: Vec<AcceptanceCheck>,
    pub notes: String,
    pub reviewed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayoutAuthorization {
    pub payout_id: PayoutId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub task_id: CreatorTaskId,
    pub milestone_id: CreatorMilestoneId,
    pub creator_id: CreatorId,
    pub connected_account_id: AccountId,
    pub connection_id: ConnectionId,
    pub contract_revision: u64,
    pub contract_digest: String,
    pub deliverable_id: DeliverableId,
    pub deliverable_digest: String,
    pub review_id: ReviewId,
    pub amount: Money,
    pub funding_provider: String,
    pub funding_reservation_id: String,
    pub payer_account_id: AccountId,
    pub idempotency_key: String,
    pub scope_digest: String,
    pub authorized_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorPayoutConfirmation {
    pub effect_id: EffectId,
    pub effect_approval_digest: String,
    pub approved_payload_digest: String,
    pub provider: String,
    pub external_id: String,
    pub request_digest: String,
    pub response_digest: String,
    pub verification_evidence_digest: String,
    pub executed_at: DateTime<Utc>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorPayoutRecord {
    pub authorization: PayoutAuthorization,
    pub confirmation: CreatorPayoutConfirmation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorTask {
    pub id: CreatorTaskId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: CreatorId,
    pub hiring_award: CreatorHiringAward,
    pub title: String,
    pub brief: String,
    pub acceptance_criteria: Vec<String>,
    pub deliverable_requirements: Vec<String>,
    pub bounty: Money,
    pub milestones: Vec<CreatorMilestone>,
    pub revision_limit: u16,
    pub usage_rights: UsageRights,
    pub due_at: DateTime<Utc>,
    pub contract_revision: u64,
    pub state_revision: u64,
    pub accepted_revision: Option<u64>,
    pub status: CreatorTaskStatus,
    pub funding_reservation: Option<FundingReservation>,
    pub acceptance: Option<CreatorAcceptance>,
    pub deliverables: Vec<CreatorDeliverable>,
    pub reviews: Vec<DeliverableReview>,
    pub payout_authorizations: Vec<PayoutAuthorization>,
    pub payouts: Vec<CreatorPayoutRecord>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CreatorTask {
    pub fn create(spec: CreatorTaskSpec, now: DateTime<Utc>) -> Result<Self, CreatorWorkError> {
        validate_spec(&spec, now)?;
        Ok(Self {
            id: spec.id,
            tenant_id: spec.tenant_id,
            project_id: spec.project_id,
            mission_id: spec.mission_id,
            creator_id: spec.creator_id,
            hiring_award: spec.hiring_award,
            title: spec.title.trim().into(),
            brief: spec.brief.trim().into(),
            acceptance_criteria: normalized_nonempty(spec.acceptance_criteria),
            deliverable_requirements: normalized_nonempty(spec.deliverable_requirements),
            bounty: spec.bounty,
            milestones: spec
                .milestones
                .into_iter()
                .map(|milestone| CreatorMilestone {
                    id: milestone.id,
                    title: milestone.title.trim().into(),
                    amount: milestone.amount,
                    due_at: milestone.due_at,
                    status: CreatorMilestoneStatus::Draft,
                    revisions_used: 0,
                })
                .collect(),
            revision_limit: spec.revision_limit,
            usage_rights: UsageRights {
                license: spec.usage_rights.license.trim().into(),
                territories: normalized_set(spec.usage_rights.territories),
                channels: normalized_set(spec.usage_rights.channels),
                exclusivity: spec.usage_rights.exclusivity.trim().into(),
                disclosure_required: spec.usage_rights.disclosure_required,
                source_manifest_required: spec.usage_rights.source_manifest_required,
            },
            due_at: spec.due_at,
            contract_revision: 1,
            state_revision: 1,
            accepted_revision: None,
            status: CreatorTaskStatus::Draft,
            funding_reservation: None,
            acceptance: None,
            deliverables: Vec::new(),
            reviews: Vec::new(),
            payout_authorizations: Vec::new(),
            payouts: Vec::new(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn contract_digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_field(&mut digest, self.id.as_str());
        hash_field(&mut digest, self.tenant_id.as_str());
        hash_field(&mut digest, self.project_id.as_str());
        hash_field(&mut digest, self.mission_id.as_str());
        hash_field(&mut digest, self.creator_id.as_str());
        hash_field(&mut digest, self.hiring_award.hiring_id.as_str());
        hash_field(&mut digest, self.hiring_award.partner_id.as_str());
        hash_field(&mut digest, self.hiring_award.application_id.as_str());
        hash_field(&mut digest, &self.hiring_award.offer_digest);
        hash_field(&mut digest, &self.hiring_award.selection_evidence_digest);
        hash_field(&mut digest, &self.hiring_award.selected_at.to_rfc3339());
        hash_field(&mut digest, &self.title);
        hash_field(&mut digest, &self.brief);
        hash_field(&mut digest, &self.contract_revision.to_string());
        hash_field(&mut digest, &self.revision_limit.to_string());
        hash_field(&mut digest, &self.bounty.amount_minor.to_string());
        hash_field(&mut digest, self.bounty.currency.as_str());
        hash_field(&mut digest, &self.due_at.to_rfc3339());
        for criterion in &self.acceptance_criteria {
            hash_field(&mut digest, criterion);
        }
        for requirement in &self.deliverable_requirements {
            hash_field(&mut digest, requirement);
        }
        for milestone in &self.milestones {
            hash_field(&mut digest, milestone.id.as_str());
            hash_field(&mut digest, &milestone.title);
            hash_field(&mut digest, &milestone.amount.amount_minor.to_string());
            hash_field(&mut digest, milestone.amount.currency.as_str());
            hash_field(&mut digest, &milestone.due_at.to_rfc3339());
        }
        hash_field(&mut digest, &self.usage_rights.license);
        for territory in &self.usage_rights.territories {
            hash_field(&mut digest, territory);
        }
        for channel in &self.usage_rights.channels {
            hash_field(&mut digest, channel);
        }
        hash_field(&mut digest, &self.usage_rights.exclusivity);
        hash_field(
            &mut digest,
            &self.usage_rights.disclosure_required.to_string(),
        );
        hash_field(
            &mut digest,
            &self.usage_rights.source_manifest_required.to_string(),
        );
        format!("{:x}", digest.finalize())
    }

    /// Derives the user-visible entitlement from immutable deliverable,
    /// review, and verified payout history. This does not treat a provider
    /// acceptance or an unverified receipt as a rights grant.
    pub fn deliverable_entitlement(
        &self,
        deliverable_id: &DeliverableId,
    ) -> Result<DeliverableEntitlementStatus, CreatorWorkError> {
        let deliverable = self
            .deliverables
            .iter()
            .find(|deliverable| &deliverable.id == deliverable_id)
            .ok_or_else(|| CreatorWorkError::UnknownDeliverable(deliverable_id.clone()))?;
        Ok(match deliverable.status {
            DeliverableStatus::ReadyForReview => DeliverableEntitlementStatus::EvaluationOnly,
            DeliverableStatus::Accepted => {
                let verified_payout = self.payouts.iter().any(|payout| {
                    payout.authorization.deliverable_id == deliverable.id
                        && payout.authorization.deliverable_digest == deliverable.content_digest
                        && payout.confirmation.verified_at >= payout.confirmation.executed_at
                        && is_sha256(&payout.confirmation.verification_evidence_digest)
                });
                if verified_payout {
                    DeliverableEntitlementStatus::ContractUsageGranted
                } else {
                    DeliverableEntitlementStatus::AcceptedAwaitingVerifiedPayout
                }
            }
            DeliverableStatus::Superseded => DeliverableEntitlementStatus::Superseded,
            DeliverableStatus::Rejected => DeliverableEntitlementStatus::Rejected,
            DeliverableStatus::Disputed => DeliverableEntitlementStatus::Disputed,
        })
    }

    /// Validates the complete creator work snapshot, including the immutable
    /// user award, deliverable/review chain, and every verified payout against
    /// the Mission's exact Effect, Receipt, and independent Verification.
    pub fn validate_snapshot(
        &self,
        hiring: &CreatorHiring,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorWorkError> {
        hiring
            .validate_awarded_snapshot(mission, now)
            .map_err(|_| CreatorWorkError::InvalidSnapshot)?;
        validate_creator_task_contract(self, hiring, mission, now)?;
        validate_creator_task_children(self, mission, now)?;
        validate_creator_task_state(self)
    }

    /// Returns true only when `self` can be reproduced by exactly one legal
    /// domain command from `previous`. This is the CAS contract used by the
    /// encrypted CreatorWork projector.
    pub fn follows(
        &self,
        previous: &Self,
        hiring: &CreatorHiring,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<bool, CreatorWorkError> {
        previous.validate_snapshot(hiring, mission, now)?;
        self.validate_snapshot(hiring, mission, now)?;
        if !same_creator_task_contract(previous, self)
            || previous.state_revision.checked_add(1) != Some(self.state_revision)
            || self.updated_at < previous.updated_at
        {
            return Ok(false);
        }
        Ok(replay_creator_task_transition(previous, self))
    }

    pub fn publish(
        &mut self,
        reservation: FundingReservation,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorWorkError> {
        self.ensure_touch(now)?;
        self.require_status(&[CreatorTaskStatus::Draft], "publish")?;
        if reservation.amount != self.bounty {
            return Err(CreatorWorkError::FundingAmountMismatch);
        }
        let contract_digest = self.contract_digest();
        if reservation.provider.trim().is_empty()
            || reservation.external_id.trim().is_empty()
            || reservation.connection_id.as_str().trim().is_empty()
            || reservation.payer_account_id.as_str().trim().is_empty()
            || reservation.contract_revision != self.contract_revision
            || reservation.contract_digest != contract_digest
            || !is_sha256(&reservation.request_digest)
            || !is_sha256(&reservation.provider_receipt_digest)
            || !is_sha256(&reservation.verification_evidence_digest)
            || reservation.reserved_at > now
            || reservation.expires_at <= self.due_at
        {
            return Err(CreatorWorkError::InvalidFundingReservation);
        }
        self.funding_reservation = Some(reservation);
        self.status = CreatorTaskStatus::Published;
        for milestone in &mut self.milestones {
            milestone.status = CreatorMilestoneStatus::Open;
        }
        self.touch(now)?;
        Ok(())
    }

    pub fn creator_accept(
        &mut self,
        eligibility: &CreatorEligibility,
        contract_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorWorkError> {
        self.ensure_touch(now)?;
        self.require_status(&[CreatorTaskStatus::Published], "creator_accept")?;
        if eligibility.creator_id != self.creator_id
            || !eligibility.kyc_verified
            || !eligibility.payouts_enabled
            || !eligibility.region_supported
            || eligibility.connected_account_id.as_str().trim().is_empty()
            || eligibility.connection_id.as_str().trim().is_empty()
            || eligibility.verified_at > now
            || eligibility.expires_at <= now
            || !is_sha256(&eligibility.verification_evidence_digest)
        {
            return Err(CreatorWorkError::CreatorNotEligible);
        }
        let current_digest = self.contract_digest();
        if contract_digest != current_digest {
            return Err(CreatorWorkError::ContractDigestMismatch);
        }
        self.accepted_revision = Some(self.contract_revision);
        self.acceptance = Some(CreatorAcceptance {
            creator_id: self.creator_id.clone(),
            connected_account_id: eligibility.connected_account_id.clone(),
            connection_id: eligibility.connection_id.clone(),
            contract_revision: self.contract_revision,
            contract_digest: current_digest,
            accepted_at: now,
        });
        self.status = CreatorTaskStatus::Accepted;
        for milestone in &mut self.milestones {
            milestone.status = CreatorMilestoneStatus::AcceptedByCreator;
        }
        self.touch(now)?;
        Ok(())
    }

    pub fn start_work(&mut self, now: DateTime<Utc>) -> Result<(), CreatorWorkError> {
        self.ensure_touch(now)?;
        self.require_status(&[CreatorTaskStatus::Accepted], "start_work")?;
        self.status = CreatorTaskStatus::InProgress;
        for milestone in &mut self.milestones {
            if milestone.status == CreatorMilestoneStatus::AcceptedByCreator {
                milestone.status = CreatorMilestoneStatus::InProgress;
            }
        }
        self.touch(now)?;
        Ok(())
    }

    pub fn submit_deliverable(
        &mut self,
        input: CreatorDeliverableInput,
        now: DateTime<Utc>,
    ) -> Result<DeliverableId, CreatorWorkError> {
        self.ensure_touch(now)?;
        self.require_status(
            &[
                CreatorTaskStatus::Accepted,
                CreatorTaskStatus::InProgress,
                CreatorTaskStatus::Submitted,
                CreatorTaskStatus::RevisionRequested,
                CreatorTaskStatus::SettlementPending,
                CreatorTaskStatus::PartiallyPaid,
            ],
            "submit_deliverable",
        )?;
        validate_deliverable(&input, &self.usage_rights, now)?;
        if self.deliverables.iter().any(|item| item.id == input.id) {
            return Err(CreatorWorkError::DuplicateDeliverable(input.id));
        }
        let milestone_index = self
            .milestones
            .iter()
            .position(|milestone| milestone.id == input.milestone_id)
            .ok_or_else(|| CreatorWorkError::UnknownMilestone(input.milestone_id.clone()))?;
        let milestone = &self.milestones[milestone_index];
        if !matches!(
            milestone.status,
            CreatorMilestoneStatus::AcceptedByCreator
                | CreatorMilestoneStatus::InProgress
                | CreatorMilestoneStatus::RevisionRequested
        ) {
            return Err(CreatorWorkError::MilestoneNotSubmittable(
                milestone.status.clone(),
            ));
        }
        let revision_count = self
            .deliverables
            .iter()
            .filter(|item| item.milestone_id == input.milestone_id)
            .count();
        let revision =
            u32::try_from(revision_count + 1).map_err(|_| CreatorWorkError::RevisionOverflow)?;
        let deliverable_id = input.id.clone();
        self.deliverables.push(CreatorDeliverable {
            id: input.id,
            task_id: self.id.clone(),
            milestone_id: input.milestone_id,
            revision,
            artifact_uri: input.artifact_uri,
            media_type: input.media_type,
            size_bytes: input.size_bytes,
            content_digest: input.content_digest,
            uploaded_at: input.uploaded_at,
            assessment: input.assessment,
            rights: input.rights,
            status: DeliverableStatus::ReadyForReview,
        });
        self.milestones[milestone_index].status = CreatorMilestoneStatus::Submitted;
        self.recompute_status_from_milestones();
        self.touch(now)?;
        Ok(deliverable_id)
    }

    pub fn review_deliverable(
        &mut self,
        deliverable_id: &DeliverableId,
        review: DeliverableReviewInput,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorWorkError> {
        self.ensure_touch(now)?;
        if matches!(
            self.status,
            CreatorTaskStatus::Draft
                | CreatorTaskStatus::Published
                | CreatorTaskStatus::Cancelled
                | CreatorTaskStatus::Paid
        ) {
            return Err(CreatorWorkError::InvalidTransition {
                from: self.status.clone(),
                action: "review_deliverable",
            });
        }
        if self.reviews.iter().any(|item| item.id == review.id) {
            return Err(CreatorWorkError::DuplicateReview(review.id));
        }
        let deliverable_index = self
            .deliverables
            .iter()
            .position(|item| &item.id == deliverable_id)
            .ok_or_else(|| CreatorWorkError::UnknownDeliverable(deliverable_id.clone()))?;
        if self.deliverables[deliverable_index].status != DeliverableStatus::ReadyForReview {
            return Err(CreatorWorkError::DeliverableNotReviewable);
        }
        let milestone_id = self.deliverables[deliverable_index].milestone_id.clone();
        let deliverable_digest = self.deliverables[deliverable_index].content_digest.clone();
        let milestone_index = self
            .milestones
            .iter()
            .position(|milestone| milestone.id == milestone_id)
            .ok_or_else(|| CreatorWorkError::UnknownMilestone(milestone_id.clone()))?;
        if self.milestones[milestone_index].status != CreatorMilestoneStatus::Submitted {
            return Err(CreatorWorkError::DeliverableNotReviewable);
        }
        validate_acceptance_checks(
            &self.acceptance_criteria,
            &self.deliverable_requirements,
            &review.decision,
            &review.acceptance_checks,
        )?;

        match review.decision {
            ReviewDecision::Accept => {
                self.deliverables[deliverable_index].status = DeliverableStatus::Accepted;
                self.milestones[milestone_index].status = CreatorMilestoneStatus::SettlementPending;
            }
            ReviewDecision::RequestRevision => {
                if self.milestones[milestone_index].revisions_used >= self.revision_limit {
                    return Err(CreatorWorkError::RevisionLimitReached);
                }
                self.milestones[milestone_index].revisions_used += 1;
                self.milestones[milestone_index].status = CreatorMilestoneStatus::RevisionRequested;
                self.deliverables[deliverable_index].status = DeliverableStatus::Superseded;
            }
            ReviewDecision::Reject => {
                self.milestones[milestone_index].status = CreatorMilestoneStatus::Rejected;
                self.deliverables[deliverable_index].status = DeliverableStatus::Rejected;
            }
            ReviewDecision::Dispute => {
                self.milestones[milestone_index].status = CreatorMilestoneStatus::Disputed;
                self.deliverables[deliverable_index].status = DeliverableStatus::Disputed;
            }
        }
        self.reviews.push(DeliverableReview {
            id: review.id,
            task_id: self.id.clone(),
            deliverable_id: deliverable_id.clone(),
            deliverable_digest,
            reviewer_id: review.reviewer_id,
            decision: review.decision,
            acceptance_checks: review.acceptance_checks,
            notes: review.notes,
            reviewed_at: now,
        });
        self.recompute_status_from_milestones();
        self.touch(now)?;
        Ok(())
    }

    pub fn payout_authorization(
        &mut self,
        payout_id: PayoutId,
        milestone_id: &CreatorMilestoneId,
        eligibility: &CreatorEligibility,
        now: DateTime<Utc>,
    ) -> Result<PayoutAuthorization, CreatorWorkError> {
        self.ensure_touch(now)?;
        let reservation = validate_payout_eligibility(self, eligibility, now)?;
        let (milestone, deliverable, review) = accepted_payout_basis(self, milestone_id)?;

        let mut authorization = PayoutAuthorization {
            payout_id,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            mission_id: self.mission_id.clone(),
            task_id: self.id.clone(),
            milestone_id: milestone.id.clone(),
            creator_id: self.creator_id.clone(),
            connected_account_id: eligibility.connected_account_id.clone(),
            connection_id: eligibility.connection_id.clone(),
            contract_revision: self.contract_revision,
            contract_digest: self.contract_digest(),
            deliverable_id: deliverable.id.clone(),
            deliverable_digest: deliverable.content_digest.clone(),
            review_id: review.id.clone(),
            amount: milestone.amount.clone(),
            funding_provider: reservation.provider.clone(),
            funding_reservation_id: reservation.external_id.clone(),
            payer_account_id: reservation.payer_account_id.clone(),
            idempotency_key: format!(
                "creator-task:{}:milestone:{}:contract:{}:deliverable:{}",
                self.id, milestone.id, self.contract_revision, deliverable.content_digest
            ),
            scope_digest: String::new(),
            authorized_at: now,
            expires_at: reservation.expires_at,
        };
        authorization.scope_digest = payout_scope_digest(&authorization);
        self.payout_authorizations.push(authorization.clone());
        self.touch(now)?;
        Ok(authorization)
    }

    pub fn record_verified_payout(
        &mut self,
        authorization: PayoutAuthorization,
        confirmation: CreatorPayoutConfirmation,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorWorkError> {
        self.ensure_touch(now)?;
        if self
            .payouts
            .iter()
            .any(|payout| payout.authorization.payout_id == authorization.payout_id)
        {
            return Err(CreatorWorkError::DuplicatePayout);
        }
        if confirmation.effect_id.as_str().trim().is_empty()
            || !is_sha256(&confirmation.effect_approval_digest)
            || confirmation.approved_payload_digest != authorization.scope_digest
            || confirmation.request_digest != confirmation.effect_approval_digest
            || confirmation.provider.trim().is_empty()
            || confirmation.external_id.trim().is_empty()
            || !is_sha256(&confirmation.response_digest)
            || !is_sha256(&confirmation.verification_evidence_digest)
            || authorization.scope_digest != payout_scope_digest(&authorization)
            || confirmation.executed_at < authorization.authorized_at
            || confirmation.executed_at >= authorization.expires_at
            || confirmation.verified_at < confirmation.executed_at
            || confirmation.verified_at > now
        {
            return Err(CreatorWorkError::PayoutConfirmationMismatch);
        }
        let milestone_index = self
            .milestones
            .iter()
            .position(|milestone| milestone.id == authorization.milestone_id)
            .ok_or_else(|| {
                CreatorWorkError::UnknownMilestone(authorization.milestone_id.clone())
            })?;
        if !self
            .payout_authorizations
            .iter()
            .any(|stored| stored == &authorization)
        {
            return Err(CreatorWorkError::PayoutConfirmationMismatch);
        }
        let milestone = &self.milestones[milestone_index];
        if milestone.status != CreatorMilestoneStatus::SettlementPending
            || milestone.amount != authorization.amount
            || authorization.task_id != self.id
            || authorization.tenant_id != self.tenant_id
            || authorization.project_id != self.project_id
            || authorization.mission_id != self.mission_id
            || authorization.creator_id != self.creator_id
            || authorization.contract_revision != self.contract_revision
            || authorization.contract_digest != self.contract_digest()
        {
            return Err(CreatorWorkError::PayoutConfirmationMismatch);
        }
        let review_matches = self.reviews.iter().any(|review| {
            review.id == authorization.review_id
                && review.deliverable_id == authorization.deliverable_id
                && review.deliverable_digest == authorization.deliverable_digest
                && review.decision == ReviewDecision::Accept
        });
        if !review_matches {
            return Err(CreatorWorkError::ReviewDigestMismatch);
        }
        let acceptance = self
            .acceptance
            .as_ref()
            .ok_or(CreatorWorkError::MissingCreatorAcceptance)?;
        let reservation = self
            .funding_reservation
            .as_ref()
            .ok_or(CreatorWorkError::MissingFundingReservation)?;
        if authorization.connected_account_id != acceptance.connected_account_id
            || authorization.connection_id != acceptance.connection_id
            || authorization.funding_provider != reservation.provider
            || authorization.funding_reservation_id != reservation.external_id
            || authorization.connection_id != reservation.connection_id
            || authorization.payer_account_id != reservation.payer_account_id
        {
            return Err(CreatorWorkError::PayoutConfirmationMismatch);
        }
        self.milestones[milestone_index].status = CreatorMilestoneStatus::Paid;
        self.payouts.push(CreatorPayoutRecord {
            authorization,
            confirmation,
        });
        self.recompute_status_from_milestones();
        self.touch(now)?;
        Ok(())
    }

    fn recompute_status_from_milestones(&mut self) {
        let has = |status: CreatorMilestoneStatus| {
            self.milestones
                .iter()
                .any(|milestone| milestone.status == status)
        };
        self.status = if self
            .milestones
            .iter()
            .all(|milestone| milestone.status == CreatorMilestoneStatus::Paid)
        {
            CreatorTaskStatus::Paid
        } else if has(CreatorMilestoneStatus::Disputed) {
            CreatorTaskStatus::Disputed
        } else if has(CreatorMilestoneStatus::Submitted) {
            CreatorTaskStatus::Submitted
        } else if has(CreatorMilestoneStatus::RevisionRequested) {
            CreatorTaskStatus::RevisionRequested
        } else if has(CreatorMilestoneStatus::SettlementPending) {
            CreatorTaskStatus::SettlementPending
        } else if has(CreatorMilestoneStatus::Paid) {
            CreatorTaskStatus::PartiallyPaid
        } else if has(CreatorMilestoneStatus::InProgress) {
            CreatorTaskStatus::InProgress
        } else if has(CreatorMilestoneStatus::AcceptedByCreator) {
            CreatorTaskStatus::Accepted
        } else if has(CreatorMilestoneStatus::Open) {
            CreatorTaskStatus::Published
        } else if has(CreatorMilestoneStatus::Rejected) {
            CreatorTaskStatus::Rejected
        } else if has(CreatorMilestoneStatus::Cancelled) {
            CreatorTaskStatus::Cancelled
        } else {
            CreatorTaskStatus::Draft
        };
    }

    fn require_status(
        &self,
        allowed: &[CreatorTaskStatus],
        action: &'static str,
    ) -> Result<(), CreatorWorkError> {
        if allowed.contains(&self.status) {
            Ok(())
        } else {
            Err(CreatorWorkError::InvalidTransition {
                from: self.status.clone(),
                action,
            })
        }
    }

    fn touch(&mut self, now: DateTime<Utc>) -> Result<(), CreatorWorkError> {
        if now < self.updated_at {
            return Err(CreatorWorkError::InvalidTimestamp);
        }
        self.state_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(CreatorWorkError::StateRevisionOverflow)?;
        self.updated_at = now;
        Ok(())
    }

    fn ensure_touch(&self, now: DateTime<Utc>) -> Result<(), CreatorWorkError> {
        if now < self.updated_at {
            return Err(CreatorWorkError::InvalidTimestamp);
        }
        self.state_revision
            .checked_add(1)
            .ok_or(CreatorWorkError::StateRevisionOverflow)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CreatorWorkError {
    #[error(
        "creator task title, brief, acceptance criteria and deliverable requirements are required"
    )]
    IncompleteTaskContract,
    #[error("creator task bounty and every milestone amount must be positive")]
    NonPositiveBounty,
    #[error("creator task milestone identifiers must be unique")]
    DuplicateMilestone,
    #[error("creator task state revision overflow")]
    StateRevisionOverflow,
    #[error(
        "creator task milestone amounts must use the bounty currency and sum exactly to the bounty"
    )]
    MilestoneAmountMismatch,
    #[error(
        "creator task and milestone due dates must be in the future and milestones may not end after the task"
    )]
    InvalidDueDate,
    #[error("creator task must allow at least one explicit revision decision")]
    InvalidRevisionLimit,
    #[error("creator task usage rights are incomplete")]
    IncompleteUsageRights,
    #[error("invalid creator task transition from {from:?} for {action}")]
    InvalidTransition {
        from: CreatorTaskStatus,
        action: &'static str,
    },
    #[error("funding reservation amount does not match the task bounty")]
    FundingAmountMismatch,
    #[error(
        "funding reservation is missing provider evidence or expires before the task can be reviewed"
    )]
    InvalidFundingReservation,
    #[error("creator identity, KYC, payout account or region is not eligible")]
    CreatorNotEligible,
    #[error("creator task is not bound to an exact user-selected hiring award")]
    InvalidHiringAward,
    #[error("creator accepted a task digest that is not the current contract")]
    ContractDigestMismatch,
    #[error("creator has not accepted the current contract revision")]
    ContractNotCurrentlyAccepted,
    #[error("creator acceptance is missing")]
    MissingCreatorAcceptance,
    #[error("duplicate deliverable {0}")]
    DuplicateDeliverable(DeliverableId),
    #[error("unknown deliverable {0}")]
    UnknownDeliverable(DeliverableId),
    #[error("unknown milestone {0}")]
    UnknownMilestone(CreatorMilestoneId),
    #[error("milestone in {0:?} cannot receive a deliverable")]
    MilestoneNotSubmittable(CreatorMilestoneStatus),
    #[error("deliverable metadata, digest, scanner evidence or rights statement is incomplete")]
    InvalidDeliverable,
    #[error("deliverable failed malware or content safety assessment")]
    UnsafeDeliverable,
    #[error("deliverable rights are missing or do not satisfy the task contract")]
    MissingDeliverableRights,
    #[error("deliverable revision counter overflow")]
    RevisionOverflow,
    #[error("duplicate review {0}")]
    DuplicateReview(ReviewId),
    #[error("deliverable is not ready for review")]
    DeliverableNotReviewable,
    #[error(
        "deliverable review checklist must match every frozen acceptance criterion and requirement exactly once"
    )]
    ReviewChecklistMismatch,
    #[error(
        "an accepted deliverable must satisfy every frozen acceptance criterion and requirement"
    )]
    AcceptedUnsatisfiedChecklist,
    #[error("creator task revision limit has been reached")]
    RevisionLimitReached,
    #[error("payout is forbidden before an accepted deliverable")]
    PayoutBeforeAcceptance,
    #[error("funding reservation is missing")]
    MissingFundingReservation,
    #[error("funding reservation expired before payout")]
    FundingReservationExpired,
    #[error("the accepted review no longer matches the deliverable digest")]
    ReviewDigestMismatch,
    #[error("duplicate creator payout")]
    DuplicatePayout,
    #[error("payout receipt or independent verification does not match the approved scope")]
    PayoutConfirmationMismatch,
    #[error("creator task event timestamp moved backwards")]
    InvalidTimestamp,
    #[error("creator work snapshot is incomplete, forged, or not linked to verified evidence")]
    InvalidSnapshot,
}

fn validate_creator_task_contract(
    task: &CreatorTask,
    hiring: &CreatorHiring,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkError> {
    let selected_award = hiring
        .award
        .as_ref()
        .ok_or(CreatorWorkError::InvalidSnapshot)?;
    if task.id.as_str().trim().is_empty()
        || task.tenant_id != hiring.tenant_id
        || task.project_id != hiring.project_id
        || task.mission_id != hiring.mission_id
        || mission.tenant_id != task.tenant_id
        || mission.project_id != task.project_id
        || mission.id != task.mission_id
        || &task.hiring_award != selected_award
        || task.creator_id != selected_award.creator_id
        || task.bounty != selected_award.bounty
        || task.contract_revision != 1
        || task.state_revision == 0
        || task.created_at < selected_award.selected_at
        || task.updated_at < task.created_at
        || task.updated_at > now
    {
        return Err(CreatorWorkError::InvalidSnapshot);
    }
    let initial = CreatorTask::create(
        CreatorTaskSpec {
            id: task.id.clone(),
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            hiring_award: task.hiring_award.clone(),
            title: task.title.clone(),
            brief: task.brief.clone(),
            acceptance_criteria: task.acceptance_criteria.clone(),
            deliverable_requirements: task.deliverable_requirements.clone(),
            bounty: task.bounty.clone(),
            milestones: task
                .milestones
                .iter()
                .map(|milestone| CreatorMilestoneSpec {
                    id: milestone.id.clone(),
                    title: milestone.title.clone(),
                    amount: milestone.amount.clone(),
                    due_at: milestone.due_at,
                })
                .collect(),
            revision_limit: task.revision_limit,
            usage_rights: task.usage_rights.clone(),
            due_at: task.due_at,
        },
        task.created_at,
    )?;
    if !same_creator_task_contract(&initial, task) {
        return Err(CreatorWorkError::InvalidSnapshot);
    }
    let recorded_actions = u64::from(task.funding_reservation.is_some())
        + u64::from(task.acceptance.is_some())
        + u64::try_from(task.deliverables.len()).map_err(|_| CreatorWorkError::InvalidSnapshot)?
        + u64::try_from(task.reviews.len()).map_err(|_| CreatorWorkError::InvalidSnapshot)?
        + u64::try_from(task.payout_authorizations.len())
            .map_err(|_| CreatorWorkError::InvalidSnapshot)?
        + u64::try_from(task.payouts.len()).map_err(|_| CreatorWorkError::InvalidSnapshot)?;
    let minimum_revision = 1_u64
        .checked_add(recorded_actions)
        .ok_or(CreatorWorkError::InvalidSnapshot)?;
    let start_work_revision = minimum_revision.saturating_add(1);
    if task.state_revision != minimum_revision
        && (task.state_revision != start_work_revision
            || task.acceptance.is_none()
            || task.status == CreatorTaskStatus::Accepted)
    {
        return Err(CreatorWorkError::InvalidSnapshot);
    }
    Ok(())
}

fn same_creator_task_contract(left: &CreatorTask, right: &CreatorTask) -> bool {
    left.id == right.id
        && left.tenant_id == right.tenant_id
        && left.project_id == right.project_id
        && left.mission_id == right.mission_id
        && left.creator_id == right.creator_id
        && left.hiring_award == right.hiring_award
        && left.title == right.title
        && left.brief == right.brief
        && left.acceptance_criteria == right.acceptance_criteria
        && left.deliverable_requirements == right.deliverable_requirements
        && left.bounty == right.bounty
        && left.revision_limit == right.revision_limit
        && left.usage_rights == right.usage_rights
        && left.due_at == right.due_at
        && left.contract_revision == right.contract_revision
        && left.created_at == right.created_at
        && left.milestones.len() == right.milestones.len()
        && left
            .milestones
            .iter()
            .zip(&right.milestones)
            .all(|(left, right)| {
                left.id == right.id
                    && left.title == right.title
                    && left.amount == right.amount
                    && left.due_at == right.due_at
            })
}

fn validate_creator_task_children(
    task: &CreatorTask,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkError> {
    validate_funding_and_acceptance(task)?;
    validate_deliverable_and_review_history(task, now)?;
    validate_payout_history(task, mission, now)
}

fn validate_funding_and_acceptance(task: &CreatorTask) -> Result<(), CreatorWorkError> {
    match &task.funding_reservation {
        Some(reservation)
            if reservation.provider.trim().is_empty()
                || reservation.external_id.trim().is_empty()
                || reservation.connection_id.as_str().trim().is_empty()
                || reservation.payer_account_id.as_str().trim().is_empty()
                || reservation.amount != task.bounty
                || reservation.contract_revision != task.contract_revision
                || reservation.contract_digest != task.contract_digest()
                || reservation.reserved_at < task.created_at
                || reservation.reserved_at > task.updated_at
                || reservation.expires_at <= task.due_at
                || !is_sha256(&reservation.request_digest)
                || !is_sha256(&reservation.provider_receipt_digest)
                || !is_sha256(&reservation.verification_evidence_digest) =>
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
        None if task.status != CreatorTaskStatus::Draft => {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
        _ => {}
    }
    match &task.acceptance {
        Some(acceptance)
            if task.accepted_revision != Some(task.contract_revision)
                || acceptance.creator_id != task.creator_id
                || acceptance.connected_account_id.as_str().trim().is_empty()
                || acceptance.connection_id.as_str().trim().is_empty()
                || acceptance.contract_revision != task.contract_revision
                || acceptance.contract_digest != task.contract_digest()
                || acceptance.accepted_at < task.created_at
                || acceptance.accepted_at > task.updated_at =>
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
        None if task.accepted_revision.is_some()
            || !matches!(
                task.status,
                CreatorTaskStatus::Draft | CreatorTaskStatus::Published
            ) =>
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
        _ => {}
    }
    Ok(())
}

fn validate_deliverable_and_review_history(
    task: &CreatorTask,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkError> {
    let mut deliverable_ids = HashSet::new();
    let mut milestone_revisions = std::collections::HashMap::new();
    for deliverable in &task.deliverables {
        let input = CreatorDeliverableInput {
            id: deliverable.id.clone(),
            milestone_id: deliverable.milestone_id.clone(),
            artifact_uri: deliverable.artifact_uri.clone(),
            media_type: deliverable.media_type.clone(),
            size_bytes: deliverable.size_bytes,
            content_digest: deliverable.content_digest.clone(),
            uploaded_at: deliverable.uploaded_at,
            assessment: deliverable.assessment.clone(),
            rights: deliverable.rights.clone(),
        };
        let next_revision = milestone_revisions
            .entry(deliverable.milestone_id.clone())
            .and_modify(|revision: &mut u32| *revision = revision.saturating_add(1))
            .or_insert(1);
        if deliverable.task_id != task.id
            || !deliverable_ids.insert(deliverable.id.clone())
            || !task
                .milestones
                .iter()
                .any(|milestone| milestone.id == deliverable.milestone_id)
            || deliverable.revision != *next_revision
            || deliverable.uploaded_at < task.created_at
            || validate_deliverable(&input, &task.usage_rights, now).is_err()
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
    }

    let mut review_ids = HashSet::new();
    let mut reviewed_deliverables = HashSet::new();
    for review in &task.reviews {
        let deliverable = task
            .deliverables
            .iter()
            .find(|deliverable| deliverable.id == review.deliverable_id)
            .ok_or(CreatorWorkError::InvalidSnapshot)?;
        if review.task_id != task.id
            || review.reviewer_id.as_str().trim().is_empty()
            || !review_ids.insert(review.id.clone())
            || !reviewed_deliverables.insert(review.deliverable_id.clone())
            || review.deliverable_digest != deliverable.content_digest
            || review.reviewed_at < deliverable.uploaded_at
            || review.reviewed_at > task.updated_at
            || validate_acceptance_checks(
                &task.acceptance_criteria,
                &task.deliverable_requirements,
                &review.decision,
                &review.acceptance_checks,
            )
            .is_err()
            || !review_matches_deliverable_status(review, deliverable)
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
    }
    if task.deliverables.iter().any(|deliverable| {
        (deliverable.status == DeliverableStatus::ReadyForReview)
            == reviewed_deliverables.contains(&deliverable.id)
    }) {
        return Err(CreatorWorkError::InvalidSnapshot);
    }
    Ok(())
}

fn review_matches_deliverable_status(
    review: &DeliverableReview,
    deliverable: &CreatorDeliverable,
) -> bool {
    matches!(
        (&review.decision, &deliverable.status),
        (ReviewDecision::Accept, DeliverableStatus::Accepted)
            | (
                ReviewDecision::RequestRevision,
                DeliverableStatus::Superseded
            )
            | (ReviewDecision::Reject, DeliverableStatus::Rejected)
            | (ReviewDecision::Dispute, DeliverableStatus::Disputed)
    )
}

fn validate_payout_history(
    task: &CreatorTask,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkError> {
    let mut payout_ids = HashSet::new();
    let mut payout_milestones = HashSet::new();
    for authorization in &task.payout_authorizations {
        if authorization.payout_id.as_str().trim().is_empty()
            || !payout_ids.insert(authorization.payout_id.clone())
            || !payout_milestones.insert(authorization.milestone_id.clone())
            || !valid_payout_authorization(task, authorization)
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
    }

    let mut confirmed_payouts = HashSet::new();
    for payout in &task.payouts {
        if !task
            .payout_authorizations
            .iter()
            .any(|authorization| authorization == &payout.authorization)
            || !confirmed_payouts.insert(payout.authorization.payout_id.clone())
            || !valid_payout_confirmation(task, payout, mission, now)
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
    }
    Ok(())
}

fn valid_payout_authorization(task: &CreatorTask, authorization: &PayoutAuthorization) -> bool {
    let Some(acceptance) = &task.acceptance else {
        return false;
    };
    let Some(reservation) = &task.funding_reservation else {
        return false;
    };
    let Some(milestone) = task
        .milestones
        .iter()
        .find(|milestone| milestone.id == authorization.milestone_id)
    else {
        return false;
    };
    let Some(deliverable) = task
        .deliverables
        .iter()
        .find(|deliverable| deliverable.id == authorization.deliverable_id)
    else {
        return false;
    };
    let review_matches = task.reviews.iter().any(|review| {
        review.id == authorization.review_id
            && review.deliverable_id == deliverable.id
            && review.deliverable_digest == deliverable.content_digest
            && review.decision == ReviewDecision::Accept
    });
    authorization.tenant_id == task.tenant_id
        && authorization.project_id == task.project_id
        && authorization.mission_id == task.mission_id
        && authorization.task_id == task.id
        && authorization.creator_id == task.creator_id
        && authorization.connected_account_id == acceptance.connected_account_id
        && authorization.connection_id == acceptance.connection_id
        && authorization.contract_revision == task.contract_revision
        && authorization.contract_digest == task.contract_digest()
        && authorization.deliverable_digest == deliverable.content_digest
        && deliverable.milestone_id == milestone.id
        && deliverable.status == DeliverableStatus::Accepted
        && authorization.amount == milestone.amount
        && authorization.funding_provider == reservation.provider
        && authorization.funding_reservation_id == reservation.external_id
        && authorization.payer_account_id == reservation.payer_account_id
        && authorization.idempotency_key
            == format!(
                "creator-task:{}:milestone:{}:contract:{}:deliverable:{}",
                task.id, milestone.id, task.contract_revision, deliverable.content_digest
            )
        && authorization.scope_digest == payout_scope_digest(authorization)
        && authorization.authorized_at >= review_reviewed_at(task, &authorization.review_id)
        && authorization.authorized_at <= task.updated_at
        && authorization.expires_at == reservation.expires_at
        && authorization.expires_at > authorization.authorized_at
        && review_matches
}

fn review_reviewed_at(task: &CreatorTask, review_id: &ReviewId) -> DateTime<Utc> {
    task.reviews
        .iter()
        .find(|review| &review.id == review_id)
        .map_or(task.created_at, |review| review.reviewed_at)
}

fn valid_payout_confirmation(
    task: &CreatorTask,
    payout: &CreatorPayoutRecord,
    mission: &Mission,
    now: DateTime<Utc>,
) -> bool {
    let authorization = &payout.authorization;
    let confirmation = &payout.confirmation;
    let Some(effect) = mission
        .effects
        .iter()
        .find(|effect| effect.id == confirmation.effect_id)
    else {
        return false;
    };
    let Some(receipt) = &effect.receipt else {
        return false;
    };
    let Some(verification) = &effect.verification else {
        return false;
    };
    let milestone_paid = task.milestones.iter().any(|milestone| {
        milestone.id == authorization.milestone_id
            && milestone.status == CreatorMilestoneStatus::Paid
    });
    milestone_paid
        && effect.status == EffectStatus::Verified
        && effect.effect_class == EffectClass::Payment
        && effect.capability == "settlement.payout"
        && effect.provider == authorization.funding_provider
        && effect.connection_id.as_ref() == Some(&authorization.connection_id)
        && effect.account_id.as_ref() == Some(&authorization.connected_account_id)
        && effect.payload_digest == authorization.scope_digest
        && effect.idempotency_key == authorization.idempotency_key
        && effect.amount == authorization.amount
        && confirmation.effect_approval_digest == effect.approval_digest()
        && confirmation.approved_payload_digest == effect.payload_digest
        && confirmation.provider == receipt.provider
        && confirmation.provider == effect.provider
        && confirmation.external_id == receipt.external_id
        && confirmation.request_digest == receipt.request_digest
        && confirmation.request_digest == effect.approval_digest()
        && confirmation.response_digest == receipt.response_digest
        && confirmation.executed_at == receipt.accepted_at
        && confirmation.verified_at == verification.observed_at
        && confirmation.verification_evidence_digest == verification.evidence_digest
        && verification.status == VerificationStatus::Confirmed
        && verification.independent
        && verification.receipt_id == receipt.id
        && verification.observed_at >= receipt.accepted_at
        && confirmation.verified_at <= now
        && confirmation.verified_at <= task.updated_at
}

fn validate_creator_task_state(task: &CreatorTask) -> Result<(), CreatorWorkError> {
    let mut recomputed = task.clone();
    recomputed.recompute_status_from_milestones();
    if recomputed.status != task.status {
        return Err(CreatorWorkError::InvalidSnapshot);
    }
    for milestone in &task.milestones {
        let deliverables = task
            .deliverables
            .iter()
            .filter(|deliverable| deliverable.milestone_id == milestone.id)
            .collect::<Vec<_>>();
        let expected_revisions = task
            .reviews
            .iter()
            .filter(|review| {
                review.decision == ReviewDecision::RequestRevision
                    && deliverables
                        .iter()
                        .any(|deliverable| deliverable.id == review.deliverable_id)
            })
            .count();
        if usize::from(milestone.revisions_used) != expected_revisions
            || !milestone_history_matches_status(task, milestone, &deliverables)
        {
            return Err(CreatorWorkError::InvalidSnapshot);
        }
    }
    Ok(())
}

fn milestone_history_matches_status(
    task: &CreatorTask,
    milestone: &CreatorMilestone,
    deliverables: &[&CreatorDeliverable],
) -> bool {
    let latest = deliverables.last().copied();
    match milestone.status {
        CreatorMilestoneStatus::Draft
        | CreatorMilestoneStatus::Open
        | CreatorMilestoneStatus::AcceptedByCreator
        | CreatorMilestoneStatus::InProgress
        | CreatorMilestoneStatus::Cancelled => latest.is_none(),
        CreatorMilestoneStatus::Submitted => {
            latest.is_some_and(|item| item.status == DeliverableStatus::ReadyForReview)
        }
        CreatorMilestoneStatus::RevisionRequested => {
            latest.is_some_and(|item| item.status == DeliverableStatus::Superseded)
        }
        CreatorMilestoneStatus::SettlementPending => latest.is_some_and(|item| {
            item.status == DeliverableStatus::Accepted
                && !task
                    .payouts
                    .iter()
                    .any(|payout| payout.authorization.milestone_id == milestone.id)
        }),
        CreatorMilestoneStatus::Paid => latest.is_some_and(|item| {
            item.status == DeliverableStatus::Accepted
                && task
                    .payouts
                    .iter()
                    .any(|payout| payout.authorization.milestone_id == milestone.id)
        }),
        CreatorMilestoneStatus::Rejected => {
            latest.is_some_and(|item| item.status == DeliverableStatus::Rejected)
        }
        CreatorMilestoneStatus::Disputed => {
            latest.is_some_and(|item| item.status == DeliverableStatus::Disputed)
        }
    }
}

fn replay_creator_task_transition(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    replay_publish(previous, expected)
        || replay_accept(previous, expected)
        || replay_start(previous, expected)
        || replay_deliverable(previous, expected)
        || replay_review(previous, expected)
        || replay_payout_authorization(previous, expected)
        || replay_payout_confirmation(previous, expected)
}

fn replay_publish(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    let Some(reservation) = expected.funding_reservation.clone() else {
        return false;
    };
    let mut candidate = previous.clone();
    candidate
        .publish(reservation, expected.updated_at)
        .is_ok_and(|()| candidate == *expected)
}

fn replay_accept(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    let Some(acceptance) = expected.acceptance.as_ref() else {
        return false;
    };
    let eligibility = synthetic_eligibility(
        &expected.creator_id,
        &acceptance.connected_account_id,
        &acceptance.connection_id,
        expected.updated_at,
    );
    let mut candidate = previous.clone();
    candidate
        .creator_accept(
            &eligibility,
            &acceptance.contract_digest,
            expected.updated_at,
        )
        .is_ok_and(|()| candidate == *expected)
}

fn replay_start(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    let mut candidate = previous.clone();
    candidate
        .start_work(expected.updated_at)
        .is_ok_and(|()| candidate == *expected)
}

fn replay_deliverable(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    if expected.deliverables.len() != previous.deliverables.len().saturating_add(1)
        || !expected.deliverables.starts_with(&previous.deliverables)
    {
        return false;
    }
    let Some(deliverable) = expected.deliverables.last() else {
        return false;
    };
    let mut candidate = previous.clone();
    candidate
        .submit_deliverable(
            CreatorDeliverableInput {
                id: deliverable.id.clone(),
                milestone_id: deliverable.milestone_id.clone(),
                artifact_uri: deliverable.artifact_uri.clone(),
                media_type: deliverable.media_type.clone(),
                size_bytes: deliverable.size_bytes,
                content_digest: deliverable.content_digest.clone(),
                uploaded_at: deliverable.uploaded_at,
                assessment: deliverable.assessment.clone(),
                rights: deliverable.rights.clone(),
            },
            expected.updated_at,
        )
        .is_ok_and(|_| candidate == *expected)
}

fn replay_review(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    if expected.reviews.len() != previous.reviews.len().saturating_add(1)
        || !expected.reviews.starts_with(&previous.reviews)
    {
        return false;
    }
    let Some(review) = expected.reviews.last() else {
        return false;
    };
    let mut candidate = previous.clone();
    candidate
        .review_deliverable(
            &review.deliverable_id,
            DeliverableReviewInput {
                id: review.id.clone(),
                reviewer_id: review.reviewer_id.clone(),
                decision: review.decision.clone(),
                acceptance_checks: review.acceptance_checks.clone(),
                notes: review.notes.clone(),
            },
            expected.updated_at,
        )
        .is_ok_and(|()| candidate == *expected)
}

fn replay_payout_authorization(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    if expected.payout_authorizations.len()
        != previous.payout_authorizations.len().saturating_add(1)
        || !expected
            .payout_authorizations
            .starts_with(&previous.payout_authorizations)
    {
        return false;
    }
    let Some(authorization) = expected.payout_authorizations.last() else {
        return false;
    };
    let eligibility = synthetic_eligibility(
        &expected.creator_id,
        &authorization.connected_account_id,
        &authorization.connection_id,
        expected.updated_at,
    );
    let mut candidate = previous.clone();
    candidate
        .payout_authorization(
            authorization.payout_id.clone(),
            &authorization.milestone_id,
            &eligibility,
            expected.updated_at,
        )
        .is_ok_and(|created| created == *authorization && candidate == *expected)
}

fn replay_payout_confirmation(previous: &CreatorTask, expected: &CreatorTask) -> bool {
    if expected.payouts.len() != previous.payouts.len().saturating_add(1)
        || !expected.payouts.starts_with(&previous.payouts)
    {
        return false;
    }
    let Some(payout) = expected.payouts.last() else {
        return false;
    };
    let mut candidate = previous.clone();
    candidate
        .record_verified_payout(
            payout.authorization.clone(),
            payout.confirmation.clone(),
            expected.updated_at,
        )
        .is_ok_and(|()| candidate == *expected)
}

fn synthetic_eligibility(
    creator_id: &CreatorId,
    connected_account_id: &AccountId,
    connection_id: &ConnectionId,
    now: DateTime<Utc>,
) -> CreatorEligibility {
    CreatorEligibility {
        creator_id: creator_id.clone(),
        connected_account_id: connected_account_id.clone(),
        connection_id: connection_id.clone(),
        kyc_verified: true,
        payouts_enabled: true,
        region_supported: true,
        verified_at: now,
        expires_at: now + chrono::Duration::days(1),
        verification_evidence_digest: "0".repeat(64),
    }
}

fn validate_spec(spec: &CreatorTaskSpec, now: DateTime<Utc>) -> Result<(), CreatorWorkError> {
    if !spec.hiring_award.validates_task_scope(
        &spec.tenant_id,
        &spec.project_id,
        &spec.mission_id,
        &spec.creator_id,
        &spec.bounty,
        now,
    ) {
        return Err(CreatorWorkError::InvalidHiringAward);
    }
    if spec.title.trim().is_empty()
        || spec.brief.trim().is_empty()
        || !has_nonempty(&spec.acceptance_criteria)
        || !has_nonempty(&spec.deliverable_requirements)
        || spec.milestones.is_empty()
    {
        return Err(CreatorWorkError::IncompleteTaskContract);
    }
    if !spec.bounty.is_positive()
        || spec
            .milestones
            .iter()
            .any(|item| !item.amount.is_positive())
    {
        return Err(CreatorWorkError::NonPositiveBounty);
    }
    let mut total = Money::zero(spec.bounty.currency.clone());
    let mut milestone_ids = HashSet::new();
    for milestone in &spec.milestones {
        if !milestone_ids.insert(milestone.id.clone()) {
            return Err(CreatorWorkError::DuplicateMilestone);
        }
        total = total
            .checked_add(&milestone.amount)
            .map_err(|_| CreatorWorkError::MilestoneAmountMismatch)?;
        if milestone.title.trim().is_empty()
            || milestone.due_at <= now
            || milestone.due_at > spec.due_at
        {
            return Err(CreatorWorkError::InvalidDueDate);
        }
    }
    if total != spec.bounty {
        return Err(CreatorWorkError::MilestoneAmountMismatch);
    }
    if spec.due_at <= now {
        return Err(CreatorWorkError::InvalidDueDate);
    }
    if spec.revision_limit == 0 {
        return Err(CreatorWorkError::InvalidRevisionLimit);
    }
    if spec.usage_rights.license.trim().is_empty()
        || !has_nonempty(&spec.usage_rights.territories)
        || !has_nonempty(&spec.usage_rights.channels)
        || spec.usage_rights.exclusivity.trim().is_empty()
    {
        return Err(CreatorWorkError::IncompleteUsageRights);
    }
    Ok(())
}

fn validate_deliverable(
    input: &CreatorDeliverableInput,
    usage_rights: &UsageRights,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkError> {
    if input.artifact_uri.trim().is_empty()
        || !(input.artifact_uri.starts_with("artifact://")
            || input.artifact_uri.starts_with("cas://"))
        || input.artifact_uri.contains("../")
        || input.media_type.trim().is_empty()
        || input.size_bytes == 0
        || !is_sha256(&input.content_digest)
        || input.uploaded_at > now
        || input.assessment.scanner.trim().is_empty()
        || input.assessment.assessed_at < input.uploaded_at
        || input.assessment.assessed_at > now
        || !is_sha256(&input.assessment.evidence_digest)
    {
        return Err(CreatorWorkError::InvalidDeliverable);
    }
    if !input.assessment.clean {
        return Err(CreatorWorkError::UnsafeDeliverable);
    }
    if !input.rights.verified
        || input.rights.ownership_or_license.trim().is_empty()
        || input.rights.permitted_use.trim() != usage_rights.license
        || (usage_rights.source_manifest_required
            && !is_sha256(&input.rights.source_manifest_digest))
    {
        return Err(CreatorWorkError::MissingDeliverableRights);
    }
    Ok(())
}

fn validate_payout_eligibility(
    task: &CreatorTask,
    eligibility: &CreatorEligibility,
    now: DateTime<Utc>,
) -> Result<FundingReservation, CreatorWorkError> {
    if task.status == CreatorTaskStatus::Disputed {
        return Err(CreatorWorkError::PayoutBeforeAcceptance);
    }
    if eligibility.creator_id != task.creator_id
        || !eligibility.kyc_verified
        || !eligibility.payouts_enabled
        || !eligibility.region_supported
        || eligibility.connection_id.as_str().trim().is_empty()
        || eligibility.verified_at > now
        || eligibility.expires_at <= now
        || !is_sha256(&eligibility.verification_evidence_digest)
    {
        return Err(CreatorWorkError::CreatorNotEligible);
    }
    let acceptance = task
        .acceptance
        .as_ref()
        .ok_or(CreatorWorkError::MissingCreatorAcceptance)?;
    if acceptance.contract_revision != task.contract_revision
        || task.accepted_revision != Some(task.contract_revision)
        || acceptance.connected_account_id != eligibility.connected_account_id
        || acceptance.connection_id != eligibility.connection_id
    {
        return Err(CreatorWorkError::ContractNotCurrentlyAccepted);
    }
    let reservation = task
        .funding_reservation
        .as_ref()
        .ok_or(CreatorWorkError::MissingFundingReservation)?;
    if reservation.expires_at <= now {
        return Err(CreatorWorkError::FundingReservationExpired);
    }
    if reservation.connection_id != eligibility.connection_id {
        return Err(CreatorWorkError::CreatorNotEligible);
    }
    Ok(reservation.clone())
}

fn accepted_payout_basis(
    task: &CreatorTask,
    milestone_id: &CreatorMilestoneId,
) -> Result<(CreatorMilestone, CreatorDeliverable, DeliverableReview), CreatorWorkError> {
    let milestone = task
        .milestones
        .iter()
        .find(|milestone| &milestone.id == milestone_id)
        .ok_or_else(|| CreatorWorkError::UnknownMilestone(milestone_id.clone()))?;
    if milestone.status != CreatorMilestoneStatus::SettlementPending {
        return Err(CreatorWorkError::PayoutBeforeAcceptance);
    }
    if task
        .payouts
        .iter()
        .any(|payout| payout.authorization.milestone_id == *milestone_id)
        || task
            .payout_authorizations
            .iter()
            .any(|authorization| authorization.milestone_id == *milestone_id)
    {
        return Err(CreatorWorkError::DuplicatePayout);
    }
    let deliverable = task
        .deliverables
        .iter()
        .rev()
        .find(|deliverable| {
            deliverable.milestone_id == *milestone_id
                && deliverable.status == DeliverableStatus::Accepted
        })
        .ok_or(CreatorWorkError::PayoutBeforeAcceptance)?;
    let review = task
        .reviews
        .iter()
        .rev()
        .find(|review| {
            review.deliverable_id == deliverable.id
                && review.deliverable_digest == deliverable.content_digest
                && review.decision == ReviewDecision::Accept
        })
        .ok_or(CreatorWorkError::ReviewDigestMismatch)?;
    Ok((milestone.clone(), deliverable.clone(), review.clone()))
}

fn validate_acceptance_checks(
    acceptance_criteria: &[String],
    deliverable_requirements: &[String],
    decision: &ReviewDecision,
    checks: &[AcceptanceCheck],
) -> Result<(), CreatorWorkError> {
    let expected = acceptance_criteria
        .iter()
        .chain(deliverable_requirements)
        .map(|value| value.trim())
        .collect::<HashSet<_>>();
    let actual = checks
        .iter()
        .map(|check| check.requirement.trim())
        .collect::<HashSet<_>>();
    if expected.len() != acceptance_criteria.len() + deliverable_requirements.len()
        || actual.len() != checks.len()
        || actual != expected
        || checks.iter().any(|check| check.evidence.trim().is_empty())
    {
        return Err(CreatorWorkError::ReviewChecklistMismatch);
    }
    if *decision == ReviewDecision::Accept && checks.iter().any(|check| !check.satisfied) {
        return Err(CreatorWorkError::AcceptedUnsatisfiedChecklist);
    }
    Ok(())
}

fn normalized_nonempty(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalized_set(values: Vec<String>) -> Vec<String> {
    let mut values = normalized_nonempty(values);
    values.sort();
    values.dedup();
    values
}

fn has_nonempty(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_be_bytes());
    digest.update(value.as_bytes());
}

fn payout_scope_digest(authorization: &PayoutAuthorization) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, authorization.payout_id.as_str());
    hash_field(&mut digest, authorization.tenant_id.as_str());
    hash_field(&mut digest, authorization.project_id.as_str());
    hash_field(&mut digest, authorization.mission_id.as_str());
    hash_field(&mut digest, authorization.task_id.as_str());
    hash_field(&mut digest, authorization.milestone_id.as_str());
    hash_field(&mut digest, authorization.creator_id.as_str());
    hash_field(&mut digest, authorization.connected_account_id.as_str());
    hash_field(&mut digest, authorization.connection_id.as_str());
    hash_field(&mut digest, &authorization.contract_revision.to_string());
    hash_field(&mut digest, &authorization.contract_digest);
    hash_field(&mut digest, authorization.deliverable_id.as_str());
    hash_field(&mut digest, &authorization.deliverable_digest);
    hash_field(&mut digest, authorization.review_id.as_str());
    hash_field(&mut digest, &authorization.amount.amount_minor.to_string());
    hash_field(&mut digest, authorization.amount.currency.as_str());
    hash_field(&mut digest, &authorization.funding_provider);
    hash_field(&mut digest, &authorization.funding_reservation_id);
    hash_field(&mut digest, authorization.payer_account_id.as_str());
    hash_field(&mut digest, &authorization.idempotency_key);
    hash_field(&mut digest, &authorization.authorized_at.to_rfc3339());
    hash_field(&mut digest, &authorization.expires_at.to_rfc3339());
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use proptest::prelude::*;

    use super::*;
    use crate::{CreatorApplicationId, CreatorHiringId, CurrencyCode, PartnerId};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn task() -> CreatorTask {
        let usd = CurrencyCode::parse("USD").expect("USD");
        let bounty = Money::new(50_000, usd.clone());
        CreatorTask::create(
            CreatorTaskSpec {
                id: CreatorTaskId::from("creator-task-1"),
                tenant_id: TenantId::from("tenant-1"),
                project_id: ProjectId::from("project-1"),
                mission_id: MissionId::from("mission-vm06"),
                creator_id: CreatorId::from("creator-1"),
                hiring_award: hiring_award(bounty.clone()),
                title: "Create a verified product demonstration".into(),
                brief: "Deliver an original vertical video and source project.".into(),
                acceptance_criteria: vec!["Shows the verified product workflow".into()],
                deliverable_requirements: vec!["MP4 plus source file".into()],
                bounty,
                milestones: vec![CreatorMilestoneSpec {
                    id: CreatorMilestoneId::from("milestone-1"),
                    title: "Final delivery".into(),
                    amount: Money::new(50_000, usd),
                    due_at: now() + Duration::days(7),
                }],
                revision_limit: 2,
                usage_rights: UsageRights {
                    license: "exclusive campaign license".into(),
                    territories: vec!["US".into()],
                    channels: vec!["owned_social".into()],
                    exclusivity: "30_days".into(),
                    disclosure_required: true,
                    source_manifest_required: true,
                },
                due_at: now() + Duration::days(10),
            },
            now(),
        )
        .expect("creator task")
    }

    fn reservation(task: &CreatorTask) -> FundingReservation {
        FundingReservation {
            provider: "stripe-connect".into(),
            external_id: "reservation-1".into(),
            connection_id: ConnectionId::from("connection-stripe-1"),
            payer_account_id: AccountId::from("acct-user-1"),
            amount: task.bounty.clone(),
            contract_revision: task.contract_revision,
            contract_digest: task.contract_digest(),
            reserved_at: now(),
            expires_at: now() + Duration::days(30),
            request_digest: "d".repeat(64),
            provider_receipt_digest: "e".repeat(64),
            verification_evidence_digest: "f".repeat(64),
        }
    }

    fn eligibility() -> CreatorEligibility {
        CreatorEligibility {
            creator_id: CreatorId::from("creator-1"),
            connected_account_id: AccountId::from("acct-creator-1"),
            connection_id: ConnectionId::from("connection-stripe-1"),
            kyc_verified: true,
            payouts_enabled: true,
            region_supported: true,
            verified_at: now(),
            expires_at: now() + Duration::days(30),
            verification_evidence_digest: "9".repeat(64),
        }
    }

    fn hiring_award(bounty: Money) -> CreatorHiringAward {
        CreatorHiringAward {
            hiring_id: CreatorHiringId::from("hiring-1"),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-vm06"),
            creator_id: CreatorId::from("creator-1"),
            partner_id: PartnerId::from("partner-1"),
            application_id: CreatorApplicationId::from("application-1"),
            offer_digest: "4".repeat(64),
            bounty,
            selected_by: ActorId::from("user-1"),
            selection_evidence_digest: "5".repeat(64),
            selected_at: now(),
        }
    }

    fn deliverable() -> CreatorDeliverableInput {
        CreatorDeliverableInput {
            id: DeliverableId::from("deliverable-1"),
            milestone_id: CreatorMilestoneId::from("milestone-1"),
            artifact_uri: "artifact://creator-task-1/deliverable-1.mp4".into(),
            media_type: "video/mp4".into(),
            size_bytes: 1_024,
            content_digest: "a".repeat(64),
            uploaded_at: now() + Duration::days(5),
            assessment: DeliverableAssessment {
                scanner: "fixture-scanner".into(),
                clean: true,
                assessed_at: now() + Duration::days(5),
                evidence_digest: "b".repeat(64),
            },
            rights: RightsAttestation {
                ownership_or_license: "creator owns all submitted media".into(),
                source_manifest_digest: "c".repeat(64),
                permitted_use: "exclusive campaign license".into(),
                verified: true,
            },
        }
    }

    fn accepted_task() -> CreatorTask {
        let mut task = task();
        let funding = reservation(&task);
        task.publish(funding, now()).expect("publish");
        let digest = task.contract_digest();
        task.creator_accept(&eligibility(), &digest, now())
            .expect("creator acceptance");
        task.start_work(now()).expect("start work");
        task
    }

    fn accepted_multi_milestone_task() -> CreatorTask {
        let usd = CurrencyCode::parse("USD").expect("USD");
        let bounty = Money::new(50_000, usd.clone());
        let mut task = CreatorTask::create(
            CreatorTaskSpec {
                id: CreatorTaskId::from("creator-task-multi"),
                tenant_id: TenantId::from("tenant-1"),
                project_id: ProjectId::from("project-1"),
                mission_id: MissionId::from("mission-vm06"),
                creator_id: CreatorId::from("creator-1"),
                hiring_award: hiring_award(bounty.clone()),
                title: "Two-stage creator campaign".into(),
                brief: "Deliver a concept and a final edit.".into(),
                acceptance_criteria: vec!["Shows the verified product workflow".into()],
                deliverable_requirements: vec!["MP4 plus source file".into()],
                bounty,
                milestones: vec![
                    CreatorMilestoneSpec {
                        id: CreatorMilestoneId::from("milestone-1"),
                        title: "Concept".into(),
                        amount: Money::new(20_000, usd.clone()),
                        due_at: now() + Duration::days(4),
                    },
                    CreatorMilestoneSpec {
                        id: CreatorMilestoneId::from("milestone-2"),
                        title: "Final edit".into(),
                        amount: Money::new(30_000, usd),
                        due_at: now() + Duration::days(7),
                    },
                ],
                revision_limit: 2,
                usage_rights: UsageRights {
                    license: "exclusive campaign license".into(),
                    territories: vec!["US".into()],
                    channels: vec!["owned_social".into()],
                    exclusivity: "30_days".into(),
                    disclosure_required: true,
                    source_manifest_required: true,
                },
                due_at: now() + Duration::days(10),
            },
            now(),
        )
        .expect("multi milestone task");
        let funding = reservation(&task);
        task.publish(funding, now()).expect("publish");
        let digest = task.contract_digest();
        task.creator_accept(&eligibility(), &digest, now())
            .expect("creator acceptance");
        task.start_work(now()).expect("start work");
        task
    }

    fn review_checks(satisfied: bool) -> Vec<AcceptanceCheck> {
        vec![
            AcceptanceCheck {
                requirement: "Shows the verified product workflow".into(),
                satisfied,
                evidence: "review-frame-120".into(),
            },
            AcceptanceCheck {
                requirement: "MP4 plus source file".into(),
                satisfied,
                evidence: "source-manifest".into(),
            },
        ]
    }

    fn model_deliverable(index: usize, at: DateTime<Utc>) -> CreatorDeliverableInput {
        CreatorDeliverableInput {
            id: DeliverableId::from_stable(format!("deliverable-model-{index}")),
            milestone_id: CreatorMilestoneId::from("milestone-1"),
            artifact_uri: format!("cas://creator-task-1/deliverable-model-{index}"),
            media_type: "video/mp4".into(),
            size_bytes: 1_024,
            content_digest: format!("{:064x}", index + 1),
            uploaded_at: at,
            assessment: DeliverableAssessment {
                scanner: "fixture-scanner".into(),
                clean: true,
                assessed_at: at,
                evidence_digest: "b".repeat(64),
            },
            rights: RightsAttestation {
                ownership_or_license: "creator owns all submitted media".into(),
                source_manifest_digest: "c".repeat(64),
                permitted_use: "exclusive campaign license".into(),
                verified: true,
            },
        }
    }

    fn advance_creator_model(
        task: &mut CreatorTask,
        index: usize,
        at: DateTime<Utc>,
    ) -> Result<(), CreatorWorkError> {
        match task.status {
            CreatorTaskStatus::Draft => task.publish(reservation(task), at),
            CreatorTaskStatus::Published => {
                task.creator_accept(&eligibility(), &task.contract_digest(), at)
            }
            CreatorTaskStatus::Accepted
            | CreatorTaskStatus::Paid
            | CreatorTaskStatus::Rejected
            | CreatorTaskStatus::Disputed
            | CreatorTaskStatus::Cancelled => task.start_work(at),
            CreatorTaskStatus::InProgress | CreatorTaskStatus::RevisionRequested => task
                .submit_deliverable(model_deliverable(index, at), at)
                .map(|_| ()),
            CreatorTaskStatus::Submitted => {
                let deliverable_id = task
                    .deliverables
                    .iter()
                    .rev()
                    .find(|deliverable| deliverable.status == DeliverableStatus::ReadyForReview)
                    .map(|deliverable| deliverable.id.clone())
                    .ok_or(CreatorWorkError::DeliverableNotReviewable)?;
                task.review_deliverable(
                    &deliverable_id,
                    DeliverableReviewInput {
                        id: ReviewId::from_stable(format!("review-model-{index}")),
                        reviewer_id: ActorId::from("user-1"),
                        decision: ReviewDecision::Accept,
                        acceptance_checks: review_checks(true),
                        notes: "Accepted by model reviewer".into(),
                    },
                    at,
                )
            }
            CreatorTaskStatus::SettlementPending | CreatorTaskStatus::PartiallyPaid => {
                if task.payout_authorizations.is_empty() {
                    task.payout_authorization(
                        PayoutId::from_stable(format!("payout-model-{index}")),
                        &CreatorMilestoneId::from("milestone-1"),
                        &eligibility(),
                        at,
                    )
                    .map(|_| ())
                } else if task.payouts.is_empty() {
                    let authorization = task
                        .payout_authorizations
                        .last()
                        .expect("authorization exists")
                        .clone();
                    task.record_verified_payout(
                        authorization.clone(),
                        CreatorPayoutConfirmation {
                            effect_id: EffectId::from_stable(format!("effect-model-{index}")),
                            effect_approval_digest: "7".repeat(64),
                            approved_payload_digest: authorization.scope_digest.clone(),
                            provider: authorization.funding_provider.clone(),
                            external_id: format!("transfer-model-{index}"),
                            request_digest: "7".repeat(64),
                            response_digest: "d".repeat(64),
                            verification_evidence_digest: "e".repeat(64),
                            executed_at: at,
                            verified_at: at,
                        },
                        at,
                    )
                } else {
                    task.start_work(at)
                }
            }
        }
    }

    #[test]
    fn payout_is_impossible_before_real_deliverable_review() {
        let mut task = accepted_task();
        let result = task.payout_authorization(
            PayoutId::from("payout-1"),
            &CreatorMilestoneId::from("milestone-1"),
            &eligibility(),
            now() + Duration::days(6),
        );
        assert_eq!(result, Err(CreatorWorkError::PayoutBeforeAcceptance));
    }

    #[test]
    fn unsafe_or_unlicensed_deliverable_cannot_reach_review() {
        let mut task = accepted_task();
        let mut unsafe_input = deliverable();
        unsafe_input.assessment.clean = false;
        assert_eq!(
            task.submit_deliverable(unsafe_input, now() + Duration::days(5)),
            Err(CreatorWorkError::UnsafeDeliverable)
        );
        let mut unlicensed = deliverable();
        unlicensed.rights.verified = false;
        assert_eq!(
            task.submit_deliverable(unlicensed, now() + Duration::days(5)),
            Err(CreatorWorkError::MissingDeliverableRights)
        );
    }

    #[test]
    fn accepted_digest_produces_one_verified_payout() {
        let mut task = accepted_task();
        let deliverable_id = task
            .submit_deliverable(deliverable(), now() + Duration::days(5))
            .expect("deliverable");
        assert_eq!(
            task.deliverable_entitlement(&deliverable_id),
            Ok(DeliverableEntitlementStatus::EvaluationOnly)
        );
        task.review_deliverable(
            &deliverable_id,
            DeliverableReviewInput {
                id: ReviewId::from("review-1"),
                reviewer_id: ActorId::from("user-1"),
                decision: ReviewDecision::Accept,
                acceptance_checks: review_checks(true),
                notes: "Meets the frozen acceptance criteria".into(),
            },
            now() + Duration::days(6),
        )
        .expect("review");
        assert_eq!(
            task.deliverable_entitlement(&deliverable_id),
            Ok(DeliverableEntitlementStatus::AcceptedAwaitingVerifiedPayout)
        );
        let authorization = task
            .payout_authorization(
                PayoutId::from("payout-1"),
                &CreatorMilestoneId::from("milestone-1"),
                &eligibility(),
                now() + Duration::days(6),
            )
            .expect("payout authorization");
        let confirmation = CreatorPayoutConfirmation {
            effect_id: EffectId::from("effect-payout-1"),
            effect_approval_digest: "7".repeat(64),
            approved_payload_digest: authorization.scope_digest.clone(),
            provider: "stripe-connect".into(),
            external_id: "transfer-1".into(),
            request_digest: "7".repeat(64),
            response_digest: "d".repeat(64),
            verification_evidence_digest: "e".repeat(64),
            executed_at: now() + Duration::days(6),
            verified_at: now() + Duration::days(6),
        };
        task.record_verified_payout(
            authorization.clone(),
            confirmation.clone(),
            now() + Duration::days(6),
        )
        .expect("verified payout");
        assert_eq!(task.status, CreatorTaskStatus::Paid);
        assert_eq!(task.payouts.len(), 1);
        assert_eq!(
            task.deliverable_entitlement(&deliverable_id),
            Ok(DeliverableEntitlementStatus::ContractUsageGranted)
        );
        assert_eq!(
            task.record_verified_payout(authorization, confirmation, now() + Duration::days(6)),
            Err(CreatorWorkError::DuplicatePayout)
        );
    }

    #[test]
    fn revision_request_never_unlocks_payment() {
        let mut task = accepted_task();
        let deliverable_id = task
            .submit_deliverable(deliverable(), now() + Duration::days(5))
            .expect("deliverable");
        task.review_deliverable(
            &deliverable_id,
            DeliverableReviewInput {
                id: ReviewId::from("review-1"),
                reviewer_id: ActorId::from("user-1"),
                decision: ReviewDecision::RequestRevision,
                acceptance_checks: review_checks(false),
                notes: "CTA is missing".into(),
            },
            now() + Duration::days(6),
        )
        .expect("revision request");
        let result = task.payout_authorization(
            PayoutId::from("payout-1"),
            &CreatorMilestoneId::from("milestone-1"),
            &eligibility(),
            now() + Duration::days(6),
        );
        assert_eq!(result, Err(CreatorWorkError::PayoutBeforeAcceptance));
    }

    #[test]
    fn accepting_one_milestone_does_not_block_other_milestone_delivery() {
        let mut task = accepted_multi_milestone_task();
        let mut first = deliverable();
        first.uploaded_at = now() + Duration::days(3);
        first.assessment.assessed_at = now() + Duration::days(3);
        let first_id = task
            .submit_deliverable(first, now() + Duration::days(3))
            .expect("first deliverable");
        task.review_deliverable(
            &first_id,
            DeliverableReviewInput {
                id: ReviewId::from("review-1"),
                reviewer_id: ActorId::from("user-1"),
                decision: ReviewDecision::Accept,
                acceptance_checks: review_checks(true),
                notes: "Concept accepted".into(),
            },
            now() + Duration::days(3),
        )
        .expect("first review");
        assert_eq!(task.status, CreatorTaskStatus::SettlementPending);

        let mut second = deliverable();
        second.id = DeliverableId::from("deliverable-2");
        second.milestone_id = CreatorMilestoneId::from("milestone-2");
        second.content_digest = "4".repeat(64);
        let second_id = task
            .submit_deliverable(second, now() + Duration::days(6))
            .expect("second milestone remains deliverable");
        task.review_deliverable(
            &second_id,
            DeliverableReviewInput {
                id: ReviewId::from("review-2"),
                reviewer_id: ActorId::from("user-1"),
                decision: ReviewDecision::Accept,
                acceptance_checks: review_checks(true),
                notes: "Final accepted".into(),
            },
            now() + Duration::days(6),
        )
        .expect("second review");
        assert!(
            task.payout_authorization(
                PayoutId::from("payout-1"),
                &CreatorMilestoneId::from("milestone-1"),
                &eligibility(),
                now() + Duration::days(6),
            )
            .is_ok()
        );
        assert!(
            task.payout_authorization(
                PayoutId::from("payout-2"),
                &CreatorMilestoneId::from("milestone-2"),
                &eligibility(),
                now() + Duration::days(6),
            )
            .is_ok()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_creator_commands_are_atomic_and_never_grant_usage_before_verified_payout(
            actions in prop::collection::vec(0_u8..4, 1..64),
        ) {
            let initial = task();
            let initial_contract_digest = initial.contract_digest();
            let mut task = initial.clone();

            for (index, action) in actions.into_iter().enumerate() {
                let before = task.clone();
                let at = if action == 1 {
                    before.updated_at - Duration::seconds(1)
                } else {
                    before.updated_at + Duration::minutes(1)
                };
                let result = if action == 2 {
                    let mut invalid_reservation = reservation(&task);
                    invalid_reservation.contract_digest = "0".repeat(64);
                    task.publish(invalid_reservation, at)
                } else {
                    advance_creator_model(&mut task, index, at)
                };

                if result.is_ok() {
                    prop_assert_eq!(task.state_revision, before.state_revision + 1);
                    prop_assert_eq!(task.updated_at, at);
                } else {
                    prop_assert_eq!(task.clone(), before);
                }
                prop_assert_eq!(task.contract_digest(), initial_contract_digest.clone());
                prop_assert!(same_creator_task_contract(&initial, &task));
                prop_assert!(validate_creator_task_state(&task).is_ok());

                for deliverable in &task.deliverables {
                    let entitlement = task
                        .deliverable_entitlement(&deliverable.id)
                        .expect("known deliverable");
                    if entitlement == DeliverableEntitlementStatus::ContractUsageGranted {
                        let has_matching_payout = task.payouts.iter().any(|payout| {
                            payout.authorization.deliverable_id == deliverable.id
                                && payout.authorization.deliverable_digest
                                    == deliverable.content_digest
                        });
                        prop_assert!(has_matching_payout);
                    } else if task.payouts.is_empty() {
                        prop_assert_ne!(
                            entitlement,
                            DeliverableEntitlementStatus::ContractUsageGranted,
                        );
                    }
                }
            }
        }
    }
}
