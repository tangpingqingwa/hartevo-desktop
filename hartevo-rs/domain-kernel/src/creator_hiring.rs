use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, ActorId, ConnectionId, ContactPermission, CreatorApplicationId, CreatorHiringId,
    CreatorId, Effect, EffectClass, EffectId, EffectStatus, Mission, MissionId, Money, Partner,
    PartnerId, PartnerSupplyClass, PersonId, ProjectId, ReceiptId, TenantId, VerificationId,
    VerificationStatus,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorHiringSpec {
    pub id: CreatorHiringId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub title: String,
    /// Digest of the exact brief shown to candidates. The private brief body stays in a Work Product.
    pub brief_digest: String,
    pub bounty: Money,
    pub market: String,
    pub application_deadline: DateTime<Utc>,
    pub due_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorHiringStatus {
    Draft,
    Recruiting,
    SelectionPending,
    Awarded,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorCandidateStatus {
    ResearchOnly,
    Contactable,
    InvitationPrepared,
    Invited,
    Applied,
    Awarded,
    NotSelected,
    Withdrawn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorCandidate {
    pub creator_id: CreatorId,
    pub partner_id: PartnerId,
    pub person_id: Option<PersonId>,
    pub supply_class: PartnerSupplyClass,
    pub contact_permission: ContactPermission,
    pub permission_evidence_digest: Option<String>,
    pub identity_evidence_digest: String,
    pub fit_evidence_digest: String,
    pub status: CreatorCandidateStatus,
    pub added_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorExternalProof {
    pub effect_id: EffectId,
    pub receipt_id: ReceiptId,
    pub verification_id: VerificationId,
    pub provider: String,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub scope_digest: String,
    pub provider_receipt_digest: String,
    pub verification_evidence_digest: String,
    pub occurred_at: DateTime<Utc>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorListingPublication {
    pub proof: CreatorExternalProof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorInvitation {
    pub creator_id: CreatorId,
    pub effect_id: EffectId,
    pub scope_digest: String,
    pub prepared_at: DateTime<Utc>,
    pub proof: Option<CreatorExternalProof>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "effect_id")]
pub enum CreatorApplicationOrigin {
    VerifiedInvitation(EffectId),
    VerifiedListing(EffectId),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorApplicationStatus {
    Active,
    Withdrawn,
    Awarded,
    NotSelected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorApplicationInput {
    pub id: CreatorApplicationId,
    pub creator_id: CreatorId,
    pub partner_id: PartnerId,
    pub origin: CreatorApplicationOrigin,
    pub offer_digest: String,
    pub proposed_amount: Money,
    pub proposal_digest: String,
    pub rights_acknowledgement_digest: String,
    pub submitted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorApplication {
    pub id: CreatorApplicationId,
    pub creator_id: CreatorId,
    pub partner_id: PartnerId,
    pub origin: CreatorApplicationOrigin,
    pub offer_digest: String,
    pub proposed_amount: Money,
    pub proposal_digest: String,
    pub rights_acknowledgement_digest: String,
    pub submitted_at: DateTime<Utc>,
    pub status: CreatorApplicationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorHiringAward {
    pub hiring_id: CreatorHiringId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: CreatorId,
    pub partner_id: PartnerId,
    pub application_id: CreatorApplicationId,
    pub offer_digest: String,
    pub bounty: Money,
    pub selected_by: ActorId,
    pub selection_evidence_digest: String,
    pub selected_at: DateTime<Utc>,
}

impl CreatorHiringAward {
    pub fn validates_task_scope(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        mission_id: &MissionId,
        creator_id: &CreatorId,
        bounty: &Money,
        now: DateTime<Utc>,
    ) -> bool {
        !self.hiring_id.as_str().trim().is_empty()
            && self.tenant_id == *tenant_id
            && self.project_id == *project_id
            && self.mission_id == *mission_id
            && self.creator_id == *creator_id
            && self.bounty == *bounty
            && !self.selected_by.as_str().trim().is_empty()
            && is_sha256(&self.offer_digest)
            && is_sha256(&self.selection_evidence_digest)
            && self.selected_at <= now
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorHiring {
    pub id: CreatorHiringId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub title: String,
    pub brief_digest: String,
    pub bounty: Money,
    pub market: String,
    pub application_deadline: DateTime<Utc>,
    pub due_at: DateTime<Utc>,
    pub status: CreatorHiringStatus,
    pub candidates: Vec<CreatorCandidate>,
    pub listing: Option<CreatorListingPublication>,
    pub invitations: Vec<CreatorInvitation>,
    pub applications: Vec<CreatorApplication>,
    pub award: Option<CreatorHiringAward>,
    pub state_revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CreatorHiring {
    pub fn create(spec: CreatorHiringSpec, now: DateTime<Utc>) -> Result<Self, CreatorHiringError> {
        if spec.id.as_str().trim().is_empty()
            || spec.tenant_id.as_str().trim().is_empty()
            || spec.project_id.as_str().trim().is_empty()
            || spec.mission_id.as_str().trim().is_empty()
            || spec.title.trim().is_empty()
            || !is_sha256(&spec.brief_digest)
            || spec.bounty.amount_minor <= 0
            || spec.market.trim().is_empty()
            || spec.application_deadline <= now
            || spec.due_at <= spec.application_deadline
        {
            return Err(CreatorHiringError::InvalidHiringContract);
        }
        Ok(Self {
            id: spec.id,
            tenant_id: spec.tenant_id,
            project_id: spec.project_id,
            mission_id: spec.mission_id,
            title: spec.title.trim().to_owned(),
            brief_digest: spec.brief_digest,
            bounty: spec.bounty,
            market: spec.market.trim().to_owned(),
            application_deadline: spec.application_deadline,
            due_at: spec.due_at,
            status: CreatorHiringStatus::Draft,
            candidates: Vec::new(),
            listing: None,
            invitations: Vec::new(),
            applications: Vec::new(),
            award: None,
            state_revision: 1,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn offer_digest(&self) -> String {
        let mut digest = Sha256::new();
        for value in [
            self.id.as_str(),
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            &self.title,
            &self.brief_digest,
            self.bounty.currency.as_str(),
            &self.market,
        ] {
            hash_field(&mut digest, value);
        }
        hash_field(&mut digest, &self.bounty.amount_minor.to_string());
        hash_field(&mut digest, &self.application_deadline.to_rfc3339());
        hash_field(&mut digest, &self.due_at.to_rfc3339());
        format!("{:x}", digest.finalize())
    }

    pub fn listing_scope_digest(&self) -> String {
        scoped_digest("creator_listing", &[self.id.as_str(), &self.offer_digest()])
    }

    pub fn invitation_scope_digest(&self, creator_id: &CreatorId) -> String {
        scoped_digest(
            "creator_invitation",
            &[self.id.as_str(), creator_id.as_str(), &self.offer_digest()],
        )
    }

    /// Validates a self-contained awarded hiring snapshot before it can cross a
    /// device or Cell trust boundary. The selected application, candidate,
    /// external publication/invitation proof, and Mission Effect evidence must
    /// all describe the same frozen offer.
    pub fn validate_awarded_snapshot(
        &self,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorHiringError> {
        validate_awarded_hiring_contract(self, mission, now)?;
        validate_hiring_candidates(self)?;
        validate_hiring_external_paths(self, mission, now)?;
        validate_hiring_applications_and_award(self, now)
    }

    pub fn open(&mut self, now: DateTime<Utc>) -> Result<(), CreatorHiringError> {
        self.require_status(&[CreatorHiringStatus::Draft], "open")?;
        if now >= self.application_deadline {
            return Err(CreatorHiringError::ApplicationWindowClosed);
        }
        self.status = CreatorHiringStatus::Recruiting;
        self.touch(now)
    }

    pub fn shortlist(
        &mut self,
        partner: &Partner,
        creator_id: CreatorId,
        identity_evidence_digest: String,
        fit_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorHiringError> {
        self.require_status(
            &[CreatorHiringStatus::Draft, CreatorHiringStatus::Recruiting],
            "shortlist",
        )?;
        if partner.tenant_id != self.tenant_id
            || partner.project_id != self.project_id
            || creator_id.as_str().trim().is_empty()
            || !is_sha256(&identity_evidence_digest)
            || !is_sha256(&fit_evidence_digest)
            || self.candidates.iter().any(|candidate| {
                candidate.creator_id == creator_id || candidate.partner_id == partner.id
            })
        {
            return Err(CreatorHiringError::InvalidCandidate);
        }
        let status = if partner.can_contact() {
            CreatorCandidateStatus::Contactable
        } else {
            CreatorCandidateStatus::ResearchOnly
        };
        self.candidates.push(CreatorCandidate {
            creator_id,
            partner_id: partner.id.clone(),
            person_id: partner.person_id.clone(),
            supply_class: partner.supply_class.clone(),
            contact_permission: partner.contact_permission.clone(),
            permission_evidence_digest: partner.permission_evidence_digest.clone(),
            identity_evidence_digest,
            fit_evidence_digest,
            status,
            added_at: now,
        });
        self.touch(now)
    }

    pub fn record_verified_listing(
        &mut self,
        proof: CreatorExternalProof,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorHiringError> {
        self.require_status(
            &[CreatorHiringStatus::Recruiting],
            "record_verified_listing",
        )?;
        if self.listing.is_some()
            || proof.scope_digest != self.listing_scope_digest()
            || !proof.is_valid(now)
        {
            return Err(CreatorHiringError::ExternalProofMismatch);
        }
        self.listing = Some(CreatorListingPublication { proof });
        self.touch(now)
    }

    pub fn prepare_invitation(
        &mut self,
        creator_id: &CreatorId,
        effect_id: EffectId,
        scope_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorHiringError> {
        self.require_status(&[CreatorHiringStatus::Recruiting], "prepare_invitation")?;
        let expected_scope = self.invitation_scope_digest(creator_id);
        if effect_id.as_str().trim().is_empty()
            || scope_digest != expected_scope
            || self.invitations.iter().any(|invitation| {
                invitation.creator_id == *creator_id || invitation.effect_id == effect_id
            })
        {
            return Err(CreatorHiringError::InvalidInvitation);
        }
        let candidate = self.candidate_mut(creator_id)?;
        if candidate.status != CreatorCandidateStatus::Contactable {
            return Err(CreatorHiringError::ContactNotPermitted);
        }
        candidate.status = CreatorCandidateStatus::InvitationPrepared;
        self.invitations.push(CreatorInvitation {
            creator_id: creator_id.clone(),
            effect_id,
            scope_digest,
            prepared_at: now,
            proof: None,
        });
        self.touch(now)
    }

    pub fn record_verified_invitation(
        &mut self,
        creator_id: &CreatorId,
        proof: CreatorExternalProof,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorHiringError> {
        self.require_status(
            &[CreatorHiringStatus::Recruiting],
            "record_verified_invitation",
        )?;
        let invitation_index = self
            .invitations
            .iter()
            .position(|invitation| invitation.creator_id == *creator_id)
            .ok_or(CreatorHiringError::InvalidInvitation)?;
        let invitation = &self.invitations[invitation_index];
        if invitation.proof.is_some()
            || proof.effect_id != invitation.effect_id
            || proof.scope_digest != invitation.scope_digest
            || proof.scope_digest != self.invitation_scope_digest(creator_id)
            || !proof.is_valid(now)
        {
            return Err(CreatorHiringError::ExternalProofMismatch);
        }
        self.invitations[invitation_index].proof = Some(proof);
        self.candidate_mut(creator_id)?.status = CreatorCandidateStatus::Invited;
        self.touch(now)
    }

    pub fn apply(
        &mut self,
        input: CreatorApplicationInput,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorHiringError> {
        self.require_status(
            &[
                CreatorHiringStatus::Recruiting,
                CreatorHiringStatus::SelectionPending,
            ],
            "apply",
        )?;
        if now > self.application_deadline
            || input.submitted_at > now
            || input.submitted_at > self.application_deadline
        {
            return Err(CreatorHiringError::ApplicationWindowClosed);
        }
        if input.id.as_str().trim().is_empty()
            || input.offer_digest != self.offer_digest()
            || input.proposed_amount != self.bounty
            || !is_sha256(&input.proposal_digest)
            || !is_sha256(&input.rights_acknowledgement_digest)
            || self.applications.iter().any(|application| {
                application.id == input.id
                    || (application.creator_id == input.creator_id
                        && application.status == CreatorApplicationStatus::Active)
            })
        {
            return Err(CreatorHiringError::InvalidApplication);
        }
        let candidate_index = self
            .candidates
            .iter()
            .position(|candidate| {
                candidate.creator_id == input.creator_id && candidate.partner_id == input.partner_id
            })
            .ok_or(CreatorHiringError::InvalidCandidate)?;
        self.validate_application_origin(candidate_index, &input.origin)?;
        self.candidates[candidate_index].status = CreatorCandidateStatus::Applied;
        self.applications.push(CreatorApplication {
            id: input.id,
            creator_id: input.creator_id,
            partner_id: input.partner_id,
            origin: input.origin,
            offer_digest: input.offer_digest,
            proposed_amount: input.proposed_amount,
            proposal_digest: input.proposal_digest,
            rights_acknowledgement_digest: input.rights_acknowledgement_digest,
            submitted_at: input.submitted_at,
            status: CreatorApplicationStatus::Active,
        });
        self.status = CreatorHiringStatus::SelectionPending;
        self.touch(now)
    }

    pub fn withdraw_application(
        &mut self,
        application_id: &CreatorApplicationId,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorHiringError> {
        self.require_status(
            &[
                CreatorHiringStatus::Recruiting,
                CreatorHiringStatus::SelectionPending,
            ],
            "withdraw_application",
        )?;
        let index = self
            .applications
            .iter()
            .position(|application| application.id == *application_id)
            .ok_or(CreatorHiringError::InvalidApplication)?;
        if self.applications[index].status != CreatorApplicationStatus::Active {
            return Err(CreatorHiringError::InvalidApplication);
        }
        let creator_id = self.applications[index].creator_id.clone();
        self.applications[index].status = CreatorApplicationStatus::Withdrawn;
        self.candidate_mut(&creator_id)?.status = CreatorCandidateStatus::Withdrawn;
        if !self
            .applications
            .iter()
            .any(|application| application.status == CreatorApplicationStatus::Active)
        {
            self.status = CreatorHiringStatus::Recruiting;
        }
        self.touch(now)
    }

    pub fn award(
        &mut self,
        application_id: &CreatorApplicationId,
        selected_by: ActorId,
        selection_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<CreatorHiringAward, CreatorHiringError> {
        self.require_status(&[CreatorHiringStatus::SelectionPending], "award")?;
        if self.award.is_some()
            || selected_by.as_str().trim().is_empty()
            || !is_sha256(&selection_evidence_digest)
        {
            return Err(CreatorHiringError::InvalidAward);
        }
        let selected_index = self
            .applications
            .iter()
            .position(|application| {
                application.id == *application_id
                    && application.status == CreatorApplicationStatus::Active
            })
            .ok_or(CreatorHiringError::InvalidApplication)?;
        let selected = self.applications[selected_index].clone();
        for application in &mut self.applications {
            application.status = if application.id == *application_id {
                CreatorApplicationStatus::Awarded
            } else if application.status == CreatorApplicationStatus::Active {
                CreatorApplicationStatus::NotSelected
            } else {
                application.status.clone()
            };
        }
        for candidate in &mut self.candidates {
            if candidate.creator_id == selected.creator_id {
                candidate.status = CreatorCandidateStatus::Awarded;
            } else if candidate.status == CreatorCandidateStatus::Applied {
                candidate.status = CreatorCandidateStatus::NotSelected;
            }
        }
        let award = CreatorHiringAward {
            hiring_id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            mission_id: self.mission_id.clone(),
            creator_id: selected.creator_id,
            partner_id: selected.partner_id,
            application_id: selected.id,
            offer_digest: selected.offer_digest,
            bounty: selected.proposed_amount,
            selected_by,
            selection_evidence_digest,
            selected_at: now,
        };
        self.award = Some(award.clone());
        self.status = CreatorHiringStatus::Awarded;
        self.touch(now)?;
        Ok(award)
    }

    pub fn cancel(&mut self, now: DateTime<Utc>) -> Result<(), CreatorHiringError> {
        self.require_status(
            &[
                CreatorHiringStatus::Draft,
                CreatorHiringStatus::Recruiting,
                CreatorHiringStatus::SelectionPending,
            ],
            "cancel",
        )?;
        self.status = CreatorHiringStatus::Cancelled;
        self.touch(now)
    }

    fn validate_application_origin(
        &self,
        candidate_index: usize,
        origin: &CreatorApplicationOrigin,
    ) -> Result<(), CreatorHiringError> {
        let candidate = &self.candidates[candidate_index];
        match origin {
            CreatorApplicationOrigin::VerifiedInvitation(effect_id) => self
                .invitations
                .iter()
                .any(|invitation| {
                    invitation.creator_id == candidate.creator_id
                        && invitation.effect_id == *effect_id
                        && invitation.proof.is_some()
                })
                .then_some(())
                .ok_or(CreatorHiringError::UnverifiedApplicationOrigin),
            CreatorApplicationOrigin::VerifiedListing(effect_id) => {
                let listing_matches = self
                    .listing
                    .as_ref()
                    .is_some_and(|listing| listing.proof.effect_id == *effect_id);
                let source_can_self_apply = matches!(
                    candidate.supply_class,
                    PartnerSupplyClass::HartevoOptIn
                        | PartnerSupplyClass::OfficialAuthorizedNetwork
                );
                if listing_matches && source_can_self_apply {
                    Ok(())
                } else {
                    Err(CreatorHiringError::UnverifiedApplicationOrigin)
                }
            }
        }
    }

    fn candidate_mut(
        &mut self,
        creator_id: &CreatorId,
    ) -> Result<&mut CreatorCandidate, CreatorHiringError> {
        self.candidates
            .iter_mut()
            .find(|candidate| candidate.creator_id == *creator_id)
            .ok_or(CreatorHiringError::InvalidCandidate)
    }

    fn require_status(
        &self,
        allowed: &[CreatorHiringStatus],
        action: &'static str,
    ) -> Result<(), CreatorHiringError> {
        if allowed.contains(&self.status) {
            Ok(())
        } else {
            Err(CreatorHiringError::InvalidTransition {
                from: self.status.clone(),
                action,
            })
        }
    }

    fn touch(&mut self, now: DateTime<Utc>) -> Result<(), CreatorHiringError> {
        if now < self.updated_at {
            return Err(CreatorHiringError::InvalidTimestamp);
        }
        self.state_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(CreatorHiringError::RevisionOverflow)?;
        self.updated_at = now;
        Ok(())
    }
}

impl CreatorExternalProof {
    fn is_valid(&self, now: DateTime<Utc>) -> bool {
        !self.effect_id.as_str().trim().is_empty()
            && !self.receipt_id.as_str().trim().is_empty()
            && !self.verification_id.as_str().trim().is_empty()
            && !self.provider.trim().is_empty()
            && !self.connection_id.as_str().trim().is_empty()
            && !self.account_id.as_str().trim().is_empty()
            && is_sha256(&self.scope_digest)
            && is_sha256(&self.provider_receipt_digest)
            && is_sha256(&self.verification_evidence_digest)
            && self.occurred_at <= self.verified_at
            && self.verified_at <= now
    }
}

fn validate_awarded_hiring_contract(
    hiring: &CreatorHiring,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), CreatorHiringError> {
    if hiring.id.as_str().trim().is_empty()
        || hiring.tenant_id.as_str().trim().is_empty()
        || hiring.project_id.as_str().trim().is_empty()
        || hiring.mission_id.as_str().trim().is_empty()
        || hiring.title.trim().is_empty()
        || !is_sha256(&hiring.brief_digest)
        || !hiring.bounty.is_positive()
        || hiring.market.trim().is_empty()
        || hiring.application_deadline <= hiring.created_at
        || hiring.due_at <= hiring.application_deadline
        || hiring.updated_at < hiring.created_at
        || hiring.updated_at > now
        || hiring.state_revision < 2
        || hiring.status != CreatorHiringStatus::Awarded
        || mission.tenant_id != hiring.tenant_id
        || mission.project_id != hiring.project_id
        || mission.id != hiring.mission_id
    {
        return Err(CreatorHiringError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_hiring_candidates(hiring: &CreatorHiring) -> Result<(), CreatorHiringError> {
    let mut creator_ids = HashSet::new();
    let mut partner_ids = HashSet::new();
    for candidate in &hiring.candidates {
        let permission_shape_valid = match candidate.supply_class {
            PartnerSupplyClass::PublicCandidate => {
                candidate.contact_permission == ContactPermission::ResearchOnly
                    && candidate.permission_evidence_digest.is_none()
                    && candidate.status == CreatorCandidateStatus::ResearchOnly
            }
            PartnerSupplyClass::OfficialAuthorizedNetwork => {
                valid_non_public_permission(candidate, &ContactPermission::NetworkAuthorized)
            }
            PartnerSupplyClass::HartevoOptIn => {
                valid_non_public_permission(candidate, &ContactPermission::ExplicitOptIn)
            }
            PartnerSupplyClass::TenantPrivate => {
                valid_non_public_permission(candidate, &ContactPermission::TenantOwnedRelationship)
            }
        };
        if candidate.creator_id.as_str().trim().is_empty()
            || candidate.partner_id.as_str().trim().is_empty()
            || !creator_ids.insert(candidate.creator_id.clone())
            || !partner_ids.insert(candidate.partner_id.clone())
            || !is_sha256(&candidate.identity_evidence_digest)
            || !is_sha256(&candidate.fit_evidence_digest)
            || candidate.added_at < hiring.created_at
            || candidate.added_at > hiring.updated_at
            || !permission_shape_valid
        {
            return Err(CreatorHiringError::InvalidSnapshot);
        }
    }
    Ok(())
}

fn valid_non_public_permission(candidate: &CreatorCandidate, expected: &ContactPermission) -> bool {
    let evidence_valid = candidate
        .permission_evidence_digest
        .as_deref()
        .is_some_and(is_sha256);
    (&candidate.contact_permission == expected && evidence_valid)
        || (candidate.contact_permission == ContactPermission::Withdrawn
            && evidence_valid
            && candidate.status != CreatorCandidateStatus::InvitationPrepared)
}

fn validate_hiring_external_paths(
    hiring: &CreatorHiring,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), CreatorHiringError> {
    if let Some(listing) = &hiring.listing {
        validate_external_proof_against_effect(
            &listing.proof,
            mission,
            "creator.task.publish",
            &EffectClass::ExternalWrite,
            &hiring.listing_scope_digest(),
            now,
        )?;
    }

    let mut invited_creators = HashSet::new();
    let mut invitation_effects = HashSet::new();
    for invitation in &hiring.invitations {
        let candidate = hiring
            .candidates
            .iter()
            .find(|candidate| candidate.creator_id == invitation.creator_id)
            .ok_or(CreatorHiringError::InvalidSnapshot)?;
        let expected_scope = hiring.invitation_scope_digest(&invitation.creator_id);
        if invitation.creator_id.as_str().trim().is_empty()
            || invitation.effect_id.as_str().trim().is_empty()
            || invitation.scope_digest != expected_scope
            || invitation.prepared_at < candidate.added_at
            || invitation.prepared_at > hiring.updated_at
            || !invited_creators.insert(invitation.creator_id.clone())
            || !invitation_effects.insert(invitation.effect_id.clone())
            || candidate.supply_class == PartnerSupplyClass::PublicCandidate
        {
            return Err(CreatorHiringError::InvalidSnapshot);
        }
        validate_invitation_effect(hiring, candidate, invitation, mission)?;
        if let Some(proof) = &invitation.proof {
            validate_external_proof_against_effect(
                proof,
                mission,
                "partner.engage",
                &EffectClass::Outreach,
                &expected_scope,
                now,
            )?;
        }
    }
    Ok(())
}

fn validate_invitation_effect(
    hiring: &CreatorHiring,
    candidate: &CreatorCandidate,
    invitation: &CreatorInvitation,
    mission: &Mission,
) -> Result<(), CreatorHiringError> {
    let effect = mission
        .effects
        .iter()
        .find(|effect| effect.id == invitation.effect_id)
        .ok_or(CreatorHiringError::ExternalProofMismatch)?;
    let guard = effect
        .creator_contact_guard
        .as_ref()
        .ok_or(CreatorHiringError::ExternalProofMismatch)?;
    if effect.capability != "partner.engage"
        || effect.effect_class != EffectClass::Outreach
        || effect.payload_digest != invitation.scope_digest
        || guard.hiring_id != hiring.id
        || guard.creator_id != candidate.creator_id
        || guard.partner_id != candidate.partner_id
        || guard.scope_digest != invitation.scope_digest
        || candidate.permission_evidence_digest.as_ref() != Some(&guard.permission_evidence_digest)
    {
        return Err(CreatorHiringError::ExternalProofMismatch);
    }
    Ok(())
}

fn validate_hiring_applications_and_award(
    hiring: &CreatorHiring,
    now: DateTime<Utc>,
) -> Result<(), CreatorHiringError> {
    let mut application_ids = HashSet::new();
    let mut awarded_applications = Vec::new();
    for application in &hiring.applications {
        let candidate = hiring
            .candidates
            .iter()
            .find(|candidate| {
                candidate.creator_id == application.creator_id
                    && candidate.partner_id == application.partner_id
            })
            .ok_or(CreatorHiringError::InvalidSnapshot)?;
        if application.id.as_str().trim().is_empty()
            || !application_ids.insert(application.id.clone())
            || application.offer_digest != hiring.offer_digest()
            || application.proposed_amount != hiring.bounty
            || !is_sha256(&application.proposal_digest)
            || !is_sha256(&application.rights_acknowledgement_digest)
            || application.submitted_at < candidate.added_at
            || application.submitted_at > hiring.application_deadline
            || application.submitted_at > hiring.updated_at
            || application.status == CreatorApplicationStatus::Active
            || !valid_application_origin(hiring, candidate, application)
        {
            return Err(CreatorHiringError::InvalidSnapshot);
        }
        if application.status == CreatorApplicationStatus::Awarded {
            awarded_applications.push(application);
        }
    }
    let award = hiring
        .award
        .as_ref()
        .ok_or(CreatorHiringError::InvalidSnapshot)?;
    if awarded_applications.len() != 1 {
        return Err(CreatorHiringError::InvalidSnapshot);
    }
    let selected = awarded_applications[0];
    let selected_candidate = hiring
        .candidates
        .iter()
        .find(|candidate| candidate.creator_id == selected.creator_id)
        .ok_or(CreatorHiringError::InvalidSnapshot)?;
    if !award.validates_task_scope(
        &hiring.tenant_id,
        &hiring.project_id,
        &hiring.mission_id,
        &selected.creator_id,
        &hiring.bounty,
        now,
    ) || award.hiring_id != hiring.id
        || award.partner_id != selected.partner_id
        || award.application_id != selected.id
        || award.offer_digest != hiring.offer_digest()
        || award.offer_digest != selected.offer_digest
        || award.selected_at < selected.submitted_at
        || award.selected_at > hiring.updated_at
        || selected_candidate.status != CreatorCandidateStatus::Awarded
        || hiring.candidates.iter().any(|candidate| {
            candidate.creator_id != selected.creator_id
                && candidate.status == CreatorCandidateStatus::Awarded
        })
    {
        return Err(CreatorHiringError::InvalidSnapshot);
    }
    Ok(())
}

fn valid_application_origin(
    hiring: &CreatorHiring,
    candidate: &CreatorCandidate,
    application: &CreatorApplication,
) -> bool {
    match &application.origin {
        CreatorApplicationOrigin::VerifiedInvitation(effect_id) => {
            hiring.invitations.iter().any(|invitation| {
                invitation.creator_id == application.creator_id
                    && invitation.effect_id == *effect_id
                    && invitation.proof.is_some()
            })
        }
        CreatorApplicationOrigin::VerifiedListing(effect_id) => {
            hiring.listing.as_ref().is_some_and(|listing| {
                listing.proof.effect_id == *effect_id
                    && matches!(
                        candidate.supply_class,
                        PartnerSupplyClass::HartevoOptIn
                            | PartnerSupplyClass::OfficialAuthorizedNetwork
                    )
            })
        }
    }
}

fn validate_external_proof_against_effect(
    proof: &CreatorExternalProof,
    mission: &Mission,
    expected_capability: &str,
    expected_class: &EffectClass,
    expected_scope: &str,
    now: DateTime<Utc>,
) -> Result<(), CreatorHiringError> {
    let effect = mission
        .effects
        .iter()
        .find(|effect| effect.id == proof.effect_id)
        .ok_or(CreatorHiringError::ExternalProofMismatch)?;
    if !proof.is_valid(now)
        || effect.tenant_id != mission.tenant_id
        || effect.project_id != mission.project_id
        || effect.mission_id != mission.id
        || effect.status != EffectStatus::Verified
        || effect.capability != expected_capability
        || &effect.effect_class != expected_class
        || effect.payload_digest != expected_scope
        || effect.connection_id.as_ref() != Some(&proof.connection_id)
        || effect.account_id.as_ref() != Some(&proof.account_id)
    {
        return Err(CreatorHiringError::ExternalProofMismatch);
    }
    validate_external_receipt_and_verification(proof, effect)
}

fn validate_external_receipt_and_verification(
    proof: &CreatorExternalProof,
    effect: &Effect,
) -> Result<(), CreatorHiringError> {
    let receipt = effect
        .receipt
        .as_ref()
        .ok_or(CreatorHiringError::ExternalProofMismatch)?;
    let verification = effect
        .verification
        .as_ref()
        .ok_or(CreatorHiringError::ExternalProofMismatch)?;
    if receipt.id != proof.receipt_id
        || receipt.provider != effect.provider
        || receipt.provider != proof.provider
        || receipt.request_digest != effect.approval_digest()
        || receipt.accepted_at != proof.occurred_at
        || provider_receipt_event_digest(receipt) != proof.provider_receipt_digest
        || verification.id != proof.verification_id
        || verification.status != VerificationStatus::Confirmed
        || !verification.independent
        || verification.receipt_id != receipt.id
        || verification.observed_at != proof.verified_at
        || verification.observed_at < receipt.accepted_at
        || verification.evidence_digest != proof.verification_evidence_digest
    {
        return Err(CreatorHiringError::ExternalProofMismatch);
    }
    Ok(())
}

fn provider_receipt_event_digest(receipt: &crate::Receipt) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}:{}:{}",
                receipt.provider, receipt.external_id, receipt.response_digest
            )
            .as_bytes()
        )
    )
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CreatorHiringError {
    #[error("creator hiring title, brief, bounty, market or deadline contract is invalid")]
    InvalidHiringContract,
    #[error("invalid creator hiring transition from {from:?} for {action}")]
    InvalidTransition {
        from: CreatorHiringStatus,
        action: &'static str,
    },
    #[error("creator candidate identity, scope, evidence or uniqueness is invalid")]
    InvalidCandidate,
    #[error("public or withdrawn candidate contact is not permitted")]
    ContactNotPermitted,
    #[error("creator invitation is missing or not bound to the exact offer scope")]
    InvalidInvitation,
    #[error("provider receipt or independent verification does not match the external action")]
    ExternalProofMismatch,
    #[error("creator application is invalid, duplicated or changes the frozen offer")]
    InvalidApplication,
    #[error("creator application did not originate from a verified invitation or listing")]
    UnverifiedApplicationOrigin,
    #[error("creator application window is closed")]
    ApplicationWindowClosed,
    #[error("creator award is missing exact user selection evidence")]
    InvalidAward,
    #[error("creator hiring state revision overflow")]
    RevisionOverflow,
    #[error("creator hiring event timestamp moved backwards")]
    InvalidTimestamp,
    #[error("creator hiring snapshot is incomplete, forged, or not linked to verified effects")]
    InvalidSnapshot,
}

fn scoped_digest(kind: &str, values: &[&str]) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, kind);
    for value in values {
        hash_field(&mut digest, value);
    }
    format!("{:x}", digest.finalize())
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_le_bytes());
    digest.update(value.as_bytes());
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn hiring() -> CreatorHiring {
        let mut hiring = CreatorHiring::create(
            CreatorHiringSpec {
                id: CreatorHiringId::from("hiring-1"),
                tenant_id: TenantId::from("tenant-1"),
                project_id: ProjectId::from("project-1"),
                mission_id: MissionId::from("mission-1"),
                title: "Original launch video".into(),
                brief_digest: "1".repeat(64),
                bounty: Money::new(50_000, crate::CurrencyCode::parse("USD").expect("USD")),
                market: "US".into(),
                application_deadline: now() + Duration::days(3),
                due_at: now() + Duration::days(10),
            },
            now(),
        )
        .expect("hiring");
        hiring.open(now()).expect("open");
        hiring
    }

    fn partner(id: &str, supply: PartnerSupplyClass) -> Partner {
        let (permission, evidence) = match supply {
            PartnerSupplyClass::PublicCandidate => (ContactPermission::ResearchOnly, None),
            PartnerSupplyClass::HartevoOptIn => {
                (ContactPermission::ExplicitOptIn, Some("2".repeat(64)))
            }
            PartnerSupplyClass::OfficialAuthorizedNetwork => {
                (ContactPermission::NetworkAuthorized, Some("2".repeat(64)))
            }
            PartnerSupplyClass::TenantPrivate => (
                ContactPermission::TenantOwnedRelationship,
                Some("2".repeat(64)),
            ),
        };
        Partner::create(
            PartnerId::from(id),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            Some(PersonId::from(format!("person-{id}").as_str())),
            None,
            id,
            supply,
            permission,
            evidence,
        )
        .expect("partner")
    }

    fn proof(effect_id: &str, scope_digest: String, at: DateTime<Utc>) -> CreatorExternalProof {
        CreatorExternalProof {
            effect_id: EffectId::from(effect_id),
            receipt_id: ReceiptId::from(format!("receipt-{effect_id}").as_str()),
            verification_id: VerificationId::from(format!("verify-{effect_id}").as_str()),
            provider: "hartevo-opt-in".into(),
            connection_id: ConnectionId::from("connection-1"),
            account_id: AccountId::from("account-1"),
            scope_digest,
            provider_receipt_digest: "3".repeat(64),
            verification_evidence_digest: "4".repeat(64),
            occurred_at: at,
            verified_at: at,
        }
    }

    fn application(
        hiring: &CreatorHiring,
        origin: CreatorApplicationOrigin,
    ) -> CreatorApplicationInput {
        CreatorApplicationInput {
            id: CreatorApplicationId::from("application-1"),
            creator_id: CreatorId::from("creator-1"),
            partner_id: PartnerId::from("partner-1"),
            origin,
            offer_digest: hiring.offer_digest(),
            proposed_amount: hiring.bounty.clone(),
            proposal_digest: "5".repeat(64),
            rights_acknowledgement_digest: "6".repeat(64),
            submitted_at: now() + Duration::hours(2),
        }
    }

    #[test]
    fn public_candidate_is_research_only_and_cannot_be_invited() {
        let mut hiring = hiring();
        hiring
            .shortlist(
                &partner("partner-1", PartnerSupplyClass::PublicCandidate),
                CreatorId::from("creator-1"),
                "7".repeat(64),
                "8".repeat(64),
                now(),
            )
            .expect("research shortlist");
        let scope = hiring.invitation_scope_digest(&CreatorId::from("creator-1"));
        assert_eq!(
            hiring.prepare_invitation(
                &CreatorId::from("creator-1"),
                EffectId::from("invite-1"),
                scope,
                now() + Duration::minutes(1),
            ),
            Err(CreatorHiringError::ContactNotPermitted)
        );
    }

    #[test]
    fn verified_invitation_application_and_user_award_are_one_exact_chain() {
        let mut hiring = hiring();
        let creator_id = CreatorId::from("creator-1");
        hiring
            .shortlist(
                &partner("partner-1", PartnerSupplyClass::HartevoOptIn),
                creator_id.clone(),
                "7".repeat(64),
                "8".repeat(64),
                now(),
            )
            .expect("shortlist");
        let scope = hiring.invitation_scope_digest(&creator_id);
        hiring
            .prepare_invitation(
                &creator_id,
                EffectId::from("invite-1"),
                scope.clone(),
                now() + Duration::minutes(1),
            )
            .expect("prepare");
        hiring
            .record_verified_invitation(
                &creator_id,
                proof("invite-1", scope, now() + Duration::minutes(2)),
                now() + Duration::minutes(2),
            )
            .expect("verified invite");
        hiring
            .apply(
                application(
                    &hiring,
                    CreatorApplicationOrigin::VerifiedInvitation(EffectId::from("invite-1")),
                ),
                now() + Duration::hours(2),
            )
            .expect("application");
        let award = hiring
            .award(
                &CreatorApplicationId::from("application-1"),
                ActorId::from("user-1"),
                "9".repeat(64),
                now() + Duration::hours(3),
            )
            .expect("award");
        assert_eq!(hiring.status, CreatorHiringStatus::Awarded);
        assert_eq!(award.creator_id, creator_id);
        assert_eq!(award.offer_digest, hiring.offer_digest());
    }

    #[test]
    fn self_application_requires_verified_listing_and_authorized_supply() {
        let mut hiring = hiring();
        hiring
            .shortlist(
                &partner("partner-1", PartnerSupplyClass::HartevoOptIn),
                CreatorId::from("creator-1"),
                "7".repeat(64),
                "8".repeat(64),
                now(),
            )
            .expect("shortlist");
        let input = application(
            &hiring,
            CreatorApplicationOrigin::VerifiedListing(EffectId::from("listing-1")),
        );
        assert_eq!(
            hiring.apply(input.clone(), now() + Duration::hours(2)),
            Err(CreatorHiringError::UnverifiedApplicationOrigin)
        );
        let scope = hiring.listing_scope_digest();
        hiring
            .record_verified_listing(
                proof("listing-1", scope, now() + Duration::minutes(1)),
                now() + Duration::minutes(1),
            )
            .expect("listing");
        hiring
            .apply(input, now() + Duration::hours(2))
            .expect("self application");
    }

    #[test]
    fn changed_offer_or_unverified_external_proof_is_rejected() {
        let mut hiring = hiring();
        hiring
            .shortlist(
                &partner("partner-1", PartnerSupplyClass::HartevoOptIn),
                CreatorId::from("creator-1"),
                "7".repeat(64),
                "8".repeat(64),
                now(),
            )
            .expect("shortlist");
        let scope = hiring.listing_scope_digest();
        let mut wrong = proof("listing-1", scope, now() + Duration::minutes(1));
        wrong.verification_evidence_digest = "not-a-digest".into();
        assert_eq!(
            hiring.record_verified_listing(wrong, now() + Duration::minutes(1)),
            Err(CreatorHiringError::ExternalProofMismatch)
        );
        let valid = proof(
            "listing-1",
            hiring.listing_scope_digest(),
            now() + Duration::minutes(1),
        );
        hiring
            .record_verified_listing(valid, now() + Duration::minutes(1))
            .expect("listing");
        let mut changed = application(
            &hiring,
            CreatorApplicationOrigin::VerifiedListing(EffectId::from("listing-1")),
        );
        changed.offer_digest = "a".repeat(64);
        assert_eq!(
            hiring.apply(changed, now() + Duration::hours(2)),
            Err(CreatorHiringError::InvalidApplication)
        );
    }
}
