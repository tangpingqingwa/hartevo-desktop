use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AccountId, ActorId, CompanyId, ConsentRecordId, CreatorCandidate, IdentityLinkId, PartnerId,
    PersonId, ProjectId, TenantId,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactChannel {
    Email,
    Phone,
    SocialDirectMessage,
    Chat,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactPoint {
    pub channel: ContactChannel,
    pub encrypted_value_ref: String,
    pub value_digest: String,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub id: PersonId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub display_name: String,
    pub company_id: Option<CompanyId>,
    pub contacts: Vec<ContactPoint>,
    pub revision: u64,
}

impl Person {
    pub fn create(
        id: PersonId,
        tenant_id: TenantId,
        project_id: ProjectId,
        display_name: impl Into<String>,
        company_id: Option<CompanyId>,
        contacts: Vec<ContactPoint>,
    ) -> Result<Self, IdentityError> {
        let person = Self {
            id,
            tenant_id,
            project_id,
            display_name: display_name.into().trim().to_owned(),
            company_id,
            contacts,
            revision: 1,
        };
        person.validate()?;
        Ok(person)
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        let contact_digests = self
            .contacts
            .iter()
            .map(|contact| contact.value_digest.as_str())
            .collect::<BTreeSet<_>>();
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.display_name.trim().is_empty()
            || self.revision == 0
            || self.contacts.iter().any(ContactPoint::is_invalid)
            || contact_digests.len() != self.contacts.len()
        {
            return Err(IdentityError::InvalidPerson);
        }
        Ok(())
    }
}

impl ContactPoint {
    fn is_invalid(&self) -> bool {
        (!self.encrypted_value_ref.starts_with("ciphertext://")
            && !self.encrypted_value_ref.starts_with("secret://"))
            || !is_sha256(&self.value_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Company {
    pub id: CompanyId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub legal_name: String,
    pub market: String,
    pub revision: u64,
}

impl Company {
    pub fn create(
        id: CompanyId,
        tenant_id: TenantId,
        project_id: ProjectId,
        legal_name: impl Into<String>,
        market: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        let company = Self {
            id,
            tenant_id,
            project_id,
            legal_name: legal_name.into().trim().to_owned(),
            market: market.into().trim().to_owned(),
            revision: 1,
        };
        company.validate()?;
        Ok(company)
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.legal_name.trim().is_empty()
            || self.market.trim().is_empty()
            || self.revision == 0
        {
            return Err(IdentityError::InvalidCompany);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartnerSupplyClass {
    OfficialAuthorizedNetwork,
    HartevoOptIn,
    TenantPrivate,
    PublicCandidate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactPermission {
    ResearchOnly,
    NetworkAuthorized,
    ExplicitOptIn,
    TenantOwnedRelationship,
    Withdrawn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Partner {
    pub id: PartnerId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub person_id: Option<PersonId>,
    pub company_id: Option<CompanyId>,
    pub display_name: String,
    pub supply_class: PartnerSupplyClass,
    pub contact_permission: ContactPermission,
    pub permission_evidence_digest: Option<String>,
    pub revision: u64,
}

/// Identity records required to preserve a CreatorHiring candidate across an
/// encrypted device/Cell projection. Contact values remain opaque references.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorIdentitySnapshot {
    pub partner: Partner,
    pub person: Option<Person>,
    pub company: Option<Company>,
}

/// Identity records required to preserve a Conversation without relying on
/// device-local demo state or an out-of-band CRM lookup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationIdentitySnapshot {
    pub person: Person,
    pub company: Option<Company>,
}

impl ConversationIdentitySnapshot {
    pub fn validate_for(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        person_id: &PersonId,
        company_id: Option<&CompanyId>,
    ) -> Result<(), IdentityError> {
        self.person.validate()?;
        if self.person.tenant_id != *tenant_id
            || self.person.project_id != *project_id
            || self.person.id != *person_id
            || self.person.company_id.as_ref() != company_id
            || self.company.as_ref().map(|company| &company.id) != company_id
        {
            return Err(IdentityError::InvalidPerson);
        }
        if let Some(company) = &self.company {
            company.validate()?;
            if company.tenant_id != *tenant_id || company.project_id != *project_id {
                return Err(IdentityError::InvalidCompany);
            }
        }
        Ok(())
    }
}

impl CreatorIdentitySnapshot {
    pub fn validate_for_candidate(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        candidate: &CreatorCandidate,
    ) -> Result<(), IdentityError> {
        self.partner.validate()?;
        if self.partner.tenant_id != *tenant_id
            || self.partner.project_id != *project_id
            || self.partner.id != candidate.partner_id
            || self.partner.person_id != candidate.person_id
            || self.partner.supply_class != candidate.supply_class
            || (self.partner.contact_permission != ContactPermission::Withdrawn
                && (self.partner.contact_permission != candidate.contact_permission
                    || self.partner.permission_evidence_digest
                        != candidate.permission_evidence_digest))
            || self.partner.person_id.as_ref() != self.person.as_ref().map(|person| &person.id)
        {
            return Err(IdentityError::InvalidPartner);
        }
        if let Some(person) = &self.person {
            person.validate()?;
            if person.tenant_id != *tenant_id || person.project_id != *project_id {
                return Err(IdentityError::InvalidPerson);
            }
        }
        let person_company_id = self
            .person
            .as_ref()
            .and_then(|person| person.company_id.as_ref());
        if self.partner.company_id.is_some()
            && person_company_id.is_some()
            && self.partner.company_id.as_ref() != person_company_id
        {
            return Err(IdentityError::InvalidPartner);
        }
        let expected_company_id = self.partner.company_id.as_ref().or(person_company_id);
        if expected_company_id != self.company.as_ref().map(|company| &company.id) {
            return Err(IdentityError::InvalidPartner);
        }
        if let Some(company) = &self.company {
            company.validate()?;
            if company.tenant_id != *tenant_id || company.project_id != *project_id {
                return Err(IdentityError::InvalidCompany);
            }
        }
        Ok(())
    }
}

impl Partner {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: PartnerId,
        tenant_id: TenantId,
        project_id: ProjectId,
        person_id: Option<PersonId>,
        company_id: Option<CompanyId>,
        display_name: impl Into<String>,
        supply_class: PartnerSupplyClass,
        contact_permission: ContactPermission,
        permission_evidence_digest: Option<String>,
    ) -> Result<Self, IdentityError> {
        let partner = Self {
            id,
            tenant_id,
            project_id,
            person_id,
            company_id,
            display_name: display_name.into().trim().to_owned(),
            supply_class,
            contact_permission,
            permission_evidence_digest,
            revision: 1,
        };
        partner.validate()?;
        Ok(partner)
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.display_name.trim().is_empty()
            || self.revision == 0
        {
            return Err(IdentityError::InvalidPartner);
        }
        let evidence_is_valid = self
            .permission_evidence_digest
            .as_deref()
            .is_some_and(is_sha256);
        let permission_shape_valid = if self.contact_permission == ContactPermission::Withdrawn {
            self.supply_class != PartnerSupplyClass::PublicCandidate && evidence_is_valid
        } else {
            match self.supply_class {
                PartnerSupplyClass::PublicCandidate => {
                    self.contact_permission == ContactPermission::ResearchOnly
                        && self.permission_evidence_digest.is_none()
                }
                PartnerSupplyClass::OfficialAuthorizedNetwork => {
                    self.contact_permission == ContactPermission::NetworkAuthorized
                        && evidence_is_valid
                }
                PartnerSupplyClass::HartevoOptIn => {
                    self.contact_permission == ContactPermission::ExplicitOptIn && evidence_is_valid
                }
                PartnerSupplyClass::TenantPrivate => {
                    self.contact_permission == ContactPermission::TenantOwnedRelationship
                        && evidence_is_valid
                }
            }
        };
        if !permission_shape_valid {
            return Err(IdentityError::InvalidPartner);
        }
        Ok(())
    }

    pub fn can_contact(&self) -> bool {
        match self.supply_class {
            PartnerSupplyClass::PublicCandidate => false,
            PartnerSupplyClass::OfficialAuthorizedNetwork => {
                self.contact_permission == ContactPermission::NetworkAuthorized
                    && self
                        .permission_evidence_digest
                        .as_deref()
                        .is_some_and(is_sha256)
            }
            PartnerSupplyClass::HartevoOptIn => {
                self.contact_permission == ContactPermission::ExplicitOptIn
                    && self
                        .permission_evidence_digest
                        .as_deref()
                        .is_some_and(is_sha256)
            }
            PartnerSupplyClass::TenantPrivate => {
                self.contact_permission == ContactPermission::TenantOwnedRelationship
                    && self
                        .permission_evidence_digest
                        .as_deref()
                        .is_some_and(is_sha256)
            }
        }
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, IdentityError> {
        self.validate()?;
        previous.validate()?;
        let immutable_scope_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.person_id == previous.person_id
            && self.company_id == previous.company_id
            && self.display_name == previous.display_name
            && self.supply_class == previous.supply_class
            && previous.revision.checked_add(1) == Some(self.revision);
        if !immutable_scope_matches {
            return Ok(false);
        }
        let Some(evidence_digest) = self.permission_evidence_digest.clone() else {
            return Ok(false);
        };
        let mut candidate = previous.clone();
        Ok(candidate
            .withdraw_contact_permission(evidence_digest)
            .is_ok()
            && candidate == *self)
    }

    pub fn withdraw_contact_permission(
        &mut self,
        evidence_digest: impl Into<String>,
    ) -> Result<(), IdentityError> {
        let evidence_digest = evidence_digest.into();
        if !self.can_contact() || !is_sha256(&evidence_digest) {
            return Err(IdentityError::InvalidPartner);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(IdentityError::RevisionOverflow)?;
        let mut next = self.clone();
        next.contact_permission = ContactPermission::Withdrawn;
        next.permission_evidence_digest = Some(evidence_digest);
        next.revision = next_revision;
        next.validate()?;
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySubject {
    Person(PersonId),
    Company(CompanyId),
    Partner(PartnerId),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalIdentity {
    pub provider: String,
    pub account_id: AccountId,
    pub external_subject_digest: String,
    pub encrypted_subject_ref: String,
    pub evidence_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityLinkStatus {
    Proposed,
    Confirmed,
    Conflicted,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityLinkDecision {
    pub from: IdentityLinkStatus,
    pub to: IdentityLinkStatus,
    pub decided_by: ActorId,
    pub evidence_digest: String,
    pub decided_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityLink {
    pub id: IdentityLinkId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub subject: IdentitySubject,
    pub identities: BTreeSet<ExternalIdentity>,
    pub confidence: Decimal,
    pub status: IdentityLinkStatus,
    #[serde(default)]
    pub decisions: Vec<IdentityLinkDecision>,
    pub revision: u64,
}

impl IdentityLink {
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        id: IdentityLinkId,
        tenant_id: TenantId,
        project_id: ProjectId,
        subject: IdentitySubject,
        identities: impl IntoIterator<Item = ExternalIdentity>,
        confidence: Decimal,
    ) -> Result<Self, IdentityError> {
        let identities = identities.into_iter().collect::<BTreeSet<_>>();
        if id.as_str().trim().is_empty()
            || tenant_id.as_str().trim().is_empty()
            || project_id.as_str().trim().is_empty()
            || identities.is_empty()
            || confidence < Decimal::ZERO
            || confidence > Decimal::ONE
            || identities.iter().any(invalid_external_identity)
        {
            return Err(IdentityError::InvalidIdentityLink);
        }
        Ok(Self {
            id,
            tenant_id,
            project_id,
            subject,
            identities,
            confidence,
            status: IdentityLinkStatus::Proposed,
            decisions: Vec::new(),
            revision: 1,
        })
    }

    pub fn confirm(
        &mut self,
        actor: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        if self.confidence < Decimal::new(9, 1) {
            return Err(IdentityError::InsufficientConfirmationEvidence);
        }
        self.decide(IdentityLinkStatus::Confirmed, actor, evidence_digest, now)
    }

    pub fn mark_conflicted(
        &mut self,
        actor: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        self.decide(IdentityLinkStatus::Conflicted, actor, evidence_digest, now)
    }

    pub fn reject(
        &mut self,
        actor: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        self.decide(IdentityLinkStatus::Rejected, actor, evidence_digest, now)
    }

    fn decide(
        &mut self,
        to: IdentityLinkStatus,
        actor: ActorId,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityError> {
        self.validate()?;
        let evidence_digest = evidence_digest.into();
        if actor.as_str().trim().is_empty() || !is_sha256(&evidence_digest) {
            return Err(IdentityError::InvalidIdentityLinkDecision);
        }
        if !identity_link_transition_allowed(self.status, to) {
            return Err(IdentityError::InvalidIdentityLinkTransition);
        }
        if self
            .decisions
            .last()
            .is_some_and(|decision| now < decision.decided_at)
        {
            return Err(IdentityError::IdentityLinkTimestampRegression);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(IdentityError::RevisionOverflow)?;
        let mut next = self.clone();
        next.decisions.push(IdentityLinkDecision {
            from: self.status,
            to,
            decided_by: actor,
            evidence_digest,
            decided_at: now,
        });
        next.status = to;
        next.revision = next_revision;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        let subject_is_valid = match &self.subject {
            IdentitySubject::Person(id) => !id.as_str().trim().is_empty(),
            IdentitySubject::Company(id) => !id.as_str().trim().is_empty(),
            IdentitySubject::Partner(id) => !id.as_str().trim().is_empty(),
        };
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !subject_is_valid
            || self.identities.is_empty()
            || self.confidence < Decimal::ZERO
            || self.confidence > Decimal::ONE
            || self.identities.iter().any(invalid_external_identity)
            || self.revision == 0
        {
            return Err(IdentityError::InvalidIdentityLink);
        }
        let expected_revision = u64::try_from(self.decisions.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(IdentityError::RevisionOverflow)?;
        if self.revision != expected_revision {
            return Err(IdentityError::InvalidIdentityLink);
        }
        let mut expected_status = IdentityLinkStatus::Proposed;
        let mut previous_decided_at = None;
        for decision in &self.decisions {
            if decision.from != expected_status
                || !identity_link_transition_allowed(decision.from, decision.to)
                || decision.decided_by.as_str().trim().is_empty()
                || !is_sha256(&decision.evidence_digest)
                || previous_decided_at.is_some_and(|previous| decision.decided_at < previous)
                || (decision.to == IdentityLinkStatus::Confirmed
                    && self.confidence < Decimal::new(9, 1))
            {
                return Err(IdentityError::InvalidIdentityLink);
            }
            expected_status = decision.to;
            previous_decided_at = Some(decision.decided_at);
        }
        if expected_status != self.status {
            return Err(IdentityError::InvalidIdentityLink);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, IdentityError> {
        self.validate()?;
        previous.validate()?;
        let immutable_scope_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.subject == previous.subject
            && self.identities == previous.identities
            && self.confidence == previous.confidence;
        let history_is_one_append = self.decisions.len() == previous.decisions.len() + 1
            && self.decisions.starts_with(&previous.decisions);
        Ok(immutable_scope_matches
            && previous.revision.checked_add(1) == Some(self.revision)
            && history_is_one_append)
    }

    pub fn last_confirmation(&self) -> Option<&IdentityLinkDecision> {
        self.decisions
            .iter()
            .rev()
            .find(|decision| decision.to == IdentityLinkStatus::Confirmed)
    }

    pub fn confirms_external_identity(&self, provider: &str, account_id: &AccountId) -> bool {
        self.status == IdentityLinkStatus::Confirmed
            && self
                .identities
                .iter()
                .any(|identity| identity.provider == provider && identity.account_id == *account_id)
    }
}

fn identity_link_transition_allowed(from: IdentityLinkStatus, to: IdentityLinkStatus) -> bool {
    matches!(
        (from, to),
        (
            IdentityLinkStatus::Proposed,
            IdentityLinkStatus::Confirmed
                | IdentityLinkStatus::Conflicted
                | IdentityLinkStatus::Rejected,
        ) | (
            IdentityLinkStatus::Confirmed,
            IdentityLinkStatus::Conflicted,
        ) | (
            IdentityLinkStatus::Conflicted,
            IdentityLinkStatus::Confirmed | IdentityLinkStatus::Rejected,
        )
    )
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPurpose {
    EmailMarketing,
    DirectOutreach,
    AutomatedReply,
    PartnerContact,
    DataSync,
    Attribution,
}

/// The exact relationship scope an external effect is allowed to use.
///
/// Keeping this scope on the Effect prevents a broad "consent exists" flag from
/// being reused for another person, channel, purpose, or market.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentRequirement {
    pub person_id: PersonId,
    pub purpose: ConsentPurpose,
    pub channel: ContactChannel,
    pub market: String,
}

impl ConsentRequirement {
    pub fn validate(&self) -> bool {
        !self.person_id.as_str().trim().is_empty() && !self.market.trim().is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalBasis {
    ExplicitConsent,
    Contract,
    LegitimateInterest,
    LegalObligation,
    NotRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    Granted,
    Denied,
    Withdrawn,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentRecord {
    pub id: ConsentRecordId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub person_id: PersonId,
    pub purpose: ConsentPurpose,
    pub channel: ContactChannel,
    pub market: String,
    pub legal_basis: LegalBasis,
    pub status: ConsentStatus,
    pub source: String,
    pub evidence_digest: String,
    pub granted_at: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub revision: u64,
}

impl ConsentRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        id: ConsentRecordId,
        tenant_id: TenantId,
        project_id: ProjectId,
        person_id: PersonId,
        purpose: ConsentPurpose,
        channel: ContactChannel,
        market: impl Into<String>,
        legal_basis: LegalBasis,
        source: impl Into<String>,
        evidence_digest: impl Into<String>,
        granted_at: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, IdentityError> {
        let market = market.into().trim().to_owned();
        let source = source.into().trim().to_owned();
        let evidence_digest = evidence_digest.into();
        if id.as_str().trim().is_empty()
            || tenant_id.as_str().trim().is_empty()
            || project_id.as_str().trim().is_empty()
            || person_id.as_str().trim().is_empty()
            || market.is_empty()
            || source.is_empty()
            || !is_sha256(&evidence_digest)
            || valid_until.is_some_and(|until| until <= granted_at)
        {
            return Err(IdentityError::InvalidConsentRecord);
        }
        Ok(Self {
            id,
            tenant_id,
            project_id,
            person_id,
            purpose,
            channel,
            market,
            legal_basis,
            status: ConsentStatus::Granted,
            source,
            evidence_digest,
            granted_at: Some(granted_at),
            valid_until,
            withdrawn_at: None,
            revision: 1,
        })
    }

    pub fn permits(
        &self,
        person_id: &PersonId,
        purpose: &ConsentPurpose,
        channel: &ContactChannel,
        market: &str,
        now: DateTime<Utc>,
    ) -> bool {
        self.person_id == *person_id
            && self.purpose == *purpose
            && self.channel == *channel
            && self.market.eq_ignore_ascii_case(market)
            && self.status == ConsentStatus::Granted
            && self.granted_at.is_some_and(|granted| granted <= now)
            && self.valid_until.is_none_or(|until| until > now)
            && self.withdrawn_at.is_none()
    }

    /// Revalidates a persisted/synchronized consent record without treating a
    /// public contact point or a stale timestamp as authorization.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.person_id.as_str().trim().is_empty()
            || self.market.trim().is_empty()
            || self.source.trim().is_empty()
            || !is_sha256(&self.evidence_digest)
            || self.revision == 0
            || self
                .granted_at
                .zip(self.valid_until)
                .is_some_and(|(granted, until)| until <= granted)
        {
            return Err(IdentityError::InvalidConsentRecord);
        }
        let state_shape_is_valid = match self.status {
            ConsentStatus::Granted => self.granted_at.is_some() && self.withdrawn_at.is_none(),
            ConsentStatus::Withdrawn => {
                self.granted_at
                    .zip(self.withdrawn_at)
                    .is_some_and(|(granted, withdrawn)| withdrawn >= granted)
                    && self.revision >= 2
            }
            ConsentStatus::Expired => {
                self.granted_at.is_some()
                    && self.valid_until.is_some()
                    && self.withdrawn_at.is_none()
                    && self.revision >= 2
            }
            ConsentStatus::Denied => {
                self.granted_at.is_none()
                    && self.valid_until.is_none()
                    && self.withdrawn_at.is_none()
            }
        };
        if state_shape_is_valid {
            Ok(())
        } else {
            Err(IdentityError::InvalidConsentRecord)
        }
    }

    pub fn is_initial_snapshot(&self) -> Result<bool, IdentityError> {
        self.validate()?;
        Ok(self.status == ConsentStatus::Granted
            && self.granted_at.is_some()
            && self.withdrawn_at.is_none()
            && self.revision == 1)
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, IdentityError> {
        self.validate()?;
        previous.validate()?;
        let immutable_scope_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.person_id == previous.person_id
            && self.purpose == previous.purpose
            && self.channel == previous.channel
            && self.market == previous.market
            && self.legal_basis == previous.legal_basis
            && self.source == previous.source
            && self.evidence_digest == previous.evidence_digest
            && self.granted_at == previous.granted_at
            && self.valid_until == previous.valid_until
            && previous.revision.checked_add(1) == Some(self.revision);
        if !immutable_scope_matches {
            return Ok(false);
        }
        let mut candidate = previous.clone();
        match self.status {
            ConsentStatus::Withdrawn => {
                let Some(withdrawn_at) = self.withdrawn_at else {
                    return Ok(false);
                };
                Ok(candidate.withdraw(withdrawn_at).is_ok() && candidate == *self)
            }
            ConsentStatus::Expired => {
                let Some(valid_until) = self.valid_until else {
                    return Ok(false);
                };
                Ok(candidate.expire(valid_until).is_ok() && candidate == *self)
            }
            ConsentStatus::Granted | ConsentStatus::Denied => Ok(false),
        }
    }

    pub fn permits_requirement(
        &self,
        requirement: &ConsentRequirement,
        now: DateTime<Utc>,
    ) -> bool {
        self.permits(
            &requirement.person_id,
            &requirement.purpose,
            &requirement.channel,
            &requirement.market,
            now,
        )
    }

    pub fn withdraw(&mut self, now: DateTime<Utc>) -> Result<(), IdentityError> {
        self.validate()?;
        if self.status != ConsentStatus::Granted {
            return Err(IdentityError::ConsentNotActive);
        }
        if self.granted_at.is_none_or(|granted_at| now < granted_at) {
            return Err(IdentityError::InvalidConsentRecord);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(IdentityError::RevisionOverflow)?;
        let mut next = self.clone();
        next.status = ConsentStatus::Withdrawn;
        next.withdrawn_at = Some(now);
        next.revision = next_revision;
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Materializes time-based expiry as an auditable state revision. Merely
    /// observing an expired `valid_until` already makes `permits` false, but a
    /// persisted Expired status must only be produced by this exact command.
    pub fn expire(&mut self, now: DateTime<Utc>) -> Result<(), IdentityError> {
        self.validate()?;
        if self.status != ConsentStatus::Granted {
            return Err(IdentityError::ConsentNotActive);
        }
        if self.valid_until.is_none_or(|valid_until| now < valid_until) {
            return Err(IdentityError::InvalidConsentRecord);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(IdentityError::RevisionOverflow)?;
        let mut next = self.clone();
        next.status = ConsentStatus::Expired;
        next.revision = next_revision;
        next.validate()?;
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error("person identity, contact encryption reference, or digest is invalid")]
    InvalidPerson,
    #[error("company identity, legal name, or market is invalid")]
    InvalidCompany,
    #[error("partner supply class, permission, evidence, or identity is invalid")]
    InvalidPartner,
    #[error("identity link scope, confidence, provider identity, or evidence is invalid")]
    InvalidIdentityLink,
    #[error("identity link lacks the evidence required for explicit confirmation")]
    InsufficientConfirmationEvidence,
    #[error("identity link decision actor or evidence is invalid")]
    InvalidIdentityLinkDecision,
    #[error("identity link decision is not allowed from the current state")]
    InvalidIdentityLinkTransition,
    #[error("identity link decision timestamp moved backwards")]
    IdentityLinkTimestampRegression,
    #[error("consent record scope, evidence, or validity is invalid")]
    InvalidConsentRecord,
    #[error("consent record is not active")]
    ConsentNotActive,
    #[error("identity or consent state revision overflow")]
    RevisionOverflow,
}

fn invalid_external_identity(identity: &ExternalIdentity) -> bool {
    identity.provider.trim().is_empty()
        || identity.account_id.as_str().trim().is_empty()
        || !is_sha256(&identity.external_subject_digest)
        || identity.encrypted_subject_ref.trim().is_empty()
        || !is_sha256(&identity.evidence_digest)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use proptest::prelude::*;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn identity_link(confidence: Decimal) -> IdentityLink {
        IdentityLink::propose(
            IdentityLinkId::from("identity-model"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            IdentitySubject::Person(PersonId::from("person-1")),
            [ExternalIdentity {
                provider: "commerce-fixture".into(),
                account_id: AccountId::from("account-1"),
                external_subject_digest: "c".repeat(64),
                encrypted_subject_ref: "ciphertext://identity/person-1".into(),
                evidence_digest: "d".repeat(64),
            }],
            confidence,
        )
        .expect("identity link")
    }

    #[test]
    fn identity_link_conflict_resolution_is_append_only_and_rejection_is_terminal() {
        let mut link = identity_link(Decimal::ONE);
        let proposed = link.clone();
        link.confirm(ActorId::from("reviewer-1"), "e".repeat(64), now())
            .expect("confirm");
        assert!(link.follows(&proposed).expect("confirmation follows"));
        assert!(link.confirms_external_identity("commerce-fixture", &AccountId::from("account-1")));

        let confirmed = link.clone();
        link.mark_conflicted(
            ActorId::from("reviewer-2"),
            "f".repeat(64),
            now() + Duration::minutes(1),
        )
        .expect("counterevidence");
        assert!(link.follows(&confirmed).expect("conflict follows"));
        assert!(
            !link.confirms_external_identity("commerce-fixture", &AccountId::from("account-1"))
        );

        let conflicted = link.clone();
        link.confirm(
            ActorId::from("reviewer-3"),
            "a".repeat(64),
            now() + Duration::minutes(2),
        )
        .expect("resolve conflict");
        assert!(link.follows(&conflicted).expect("resolution follows"));

        let mut rejected = identity_link(Decimal::ONE);
        rejected
            .reject(ActorId::from("reviewer-4"), "b".repeat(64), now())
            .expect("reject proposal");
        let terminal = rejected.clone();
        assert_eq!(
            rejected.mark_conflicted(
                ActorId::from("reviewer-5"),
                "c".repeat(64),
                now() + Duration::minutes(1),
            ),
            Err(IdentityError::InvalidIdentityLinkTransition)
        );
        assert_eq!(rejected, terminal);

        let mut forged = identity_link(Decimal::ONE);
        forged.status = IdentityLinkStatus::Conflicted;
        assert_eq!(forged.validate(), Err(IdentityError::InvalidIdentityLink));
    }

    #[test]
    fn public_partner_candidate_is_research_only_even_with_a_public_contact() {
        let partner = Partner {
            id: PartnerId::from("partner-1"),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            person_id: Some(PersonId::from("person-1")),
            company_id: None,
            display_name: "Public creator".into(),
            supply_class: PartnerSupplyClass::PublicCandidate,
            contact_permission: ContactPermission::ExplicitOptIn,
            permission_evidence_digest: Some("a".repeat(64)),
            revision: 1,
        };
        assert!(!partner.can_contact());
        assert_eq!(partner.validate(), Err(IdentityError::InvalidPartner));
        let safe = Partner::create(
            PartnerId::from("partner-public-safe"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            Some(PersonId::from("person-1")),
            None,
            "Public creator",
            PartnerSupplyClass::PublicCandidate,
            ContactPermission::ResearchOnly,
            None,
        )
        .expect("research-only candidate");
        assert!(!safe.can_contact());
    }

    #[test]
    fn person_rejects_duplicate_contact_identity_digest() {
        let contact = ContactPoint {
            channel: ContactChannel::Email,
            encrypted_value_ref: "ciphertext://contact/1".into(),
            value_digest: "b".repeat(64),
            verified_at: Some(now()),
        };
        assert!(
            Person::create(
                PersonId::from("person-1"),
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                "Creator",
                None,
                vec![contact.clone()],
            )
            .is_ok()
        );
        assert_eq!(
            Person::create(
                PersonId::from("person-2"),
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                "Duplicate",
                None,
                vec![contact.clone(), contact],
            ),
            Err(IdentityError::InvalidPerson)
        );
    }

    #[test]
    fn consent_is_exact_to_person_purpose_channel_market_and_time() {
        let person_id = PersonId::from("person-1");
        let mut consent = ConsentRecord::grant(
            ConsentRecordId::from("consent-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            person_id.clone(),
            ConsentPurpose::EmailMarketing,
            ContactChannel::Email,
            "DE",
            LegalBasis::ExplicitConsent,
            "double-opt-in",
            "b".repeat(64),
            now(),
            Some(now() + Duration::days(30)),
        )
        .expect("consent");
        assert!(consent.permits(
            &person_id,
            &ConsentPurpose::EmailMarketing,
            &ContactChannel::Email,
            "DE",
            now() + Duration::days(1)
        ));
        assert!(!consent.permits(
            &person_id,
            &ConsentPurpose::DirectOutreach,
            &ContactChannel::Email,
            "DE",
            now() + Duration::days(1)
        ));
        consent
            .withdraw(now() + Duration::days(2))
            .expect("withdraw");
        assert!(!consent.permits(
            &person_id,
            &ConsentPurpose::EmailMarketing,
            &ContactChannel::Email,
            "DE",
            now() + Duration::days(3)
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn partner_supply_and_permission_matrix_never_authorizes_public_candidates(
            supply in 0_u8..4,
            permission in 0_u8..5,
            evidence_shape in 0_u8..3,
        ) {
            let supply_class = match supply {
                0 => PartnerSupplyClass::OfficialAuthorizedNetwork,
                1 => PartnerSupplyClass::HartevoOptIn,
                2 => PartnerSupplyClass::TenantPrivate,
                _ => PartnerSupplyClass::PublicCandidate,
            };
            let contact_permission = match permission {
                0 => ContactPermission::ResearchOnly,
                1 => ContactPermission::NetworkAuthorized,
                2 => ContactPermission::ExplicitOptIn,
                3 => ContactPermission::TenantOwnedRelationship,
                _ => ContactPermission::Withdrawn,
            };
            let permission_evidence_digest = match evidence_shape {
                0 => None,
                1 => Some("a".repeat(64)),
                _ => Some("not-a-digest".into()),
            };
            let partner = Partner {
                id: PartnerId::from("partner-model"),
                tenant_id: TenantId::from("tenant-1"),
                project_id: ProjectId::from("project-1"),
                person_id: Some(PersonId::from("person-1")),
                company_id: None,
                display_name: "Creator".into(),
                supply_class: supply_class.clone(),
                contact_permission: contact_permission.clone(),
                permission_evidence_digest,
                revision: 1,
            };
            let evidence_valid = evidence_shape == 1;
            let expected_valid = match (&supply_class, &contact_permission) {
                (PartnerSupplyClass::PublicCandidate, ContactPermission::ResearchOnly) => {
                    evidence_shape == 0
                }
                (PartnerSupplyClass::OfficialAuthorizedNetwork, ContactPermission::NetworkAuthorized)
                | (PartnerSupplyClass::HartevoOptIn, ContactPermission::ExplicitOptIn)
                | (PartnerSupplyClass::TenantPrivate, ContactPermission::TenantOwnedRelationship) => {
                    evidence_valid
                }
                (
                    PartnerSupplyClass::OfficialAuthorizedNetwork
                    | PartnerSupplyClass::HartevoOptIn
                    | PartnerSupplyClass::TenantPrivate,
                    ContactPermission::Withdrawn,
                ) => evidence_valid,
                _ => false,
            };
            let expected_contact = matches!(
                (&supply_class, &contact_permission),
                (PartnerSupplyClass::OfficialAuthorizedNetwork, ContactPermission::NetworkAuthorized)
                    | (PartnerSupplyClass::HartevoOptIn, ContactPermission::ExplicitOptIn)
                    | (PartnerSupplyClass::TenantPrivate, ContactPermission::TenantOwnedRelationship)
            ) && evidence_valid;
            prop_assert_eq!(partner.validate().is_ok(), expected_valid);
            prop_assert_eq!(partner.can_contact(), expected_contact);
            if supply_class == PartnerSupplyClass::PublicCandidate {
                prop_assert!(!partner.can_contact());
            }
        }

        #[test]
        fn arbitrary_consent_time_and_terminal_actions_are_atomic_and_scope_exact(
            actions in prop::collection::vec((0_u8..5, 0_i64..4), 1..64),
        ) {
            let person_id = PersonId::from("person-model");
            let valid_until = now() + Duration::minutes(10);
            let mut consent = ConsentRecord::grant(
                ConsentRecordId::from("consent-model"),
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                person_id.clone(),
                ConsentPurpose::EmailMarketing,
                ContactChannel::Email,
                "DE",
                LegalBasis::ExplicitConsent,
                "double-opt-in",
                "b".repeat(64),
                now(),
                Some(valid_until),
            ).expect("consent");
            let mut cursor = now();

            for (action, advance_minutes) in actions {
                cursor += Duration::minutes(advance_minutes);
                let before = consent.clone();
                let result = match action {
                    0 => consent.withdraw(cursor),
                    1 => consent.expire(cursor),
                    2 => consent.withdraw(now() - Duration::seconds(1)),
                    3 => {
                        let mut overflow = consent.clone();
                        overflow.revision = u64::MAX;
                        let overflow_before = overflow.clone();
                        let result = overflow.withdraw(cursor);
                        prop_assert!(result.is_err());
                        prop_assert_eq!(overflow, overflow_before);
                        Ok(())
                    }
                    _ => Ok(()),
                };
                if action <= 2 {
                    if result.is_ok() {
                        prop_assert_eq!(consent.revision, before.revision + 1);
                        prop_assert!(consent.validate().is_ok());
                        prop_assert!(consent.follows(&before).expect("consent transition"));
                    } else {
                        prop_assert_eq!(consent.clone(), before);
                    }
                }

                let should_permit = consent.status == ConsentStatus::Granted
                    && cursor >= now()
                    && cursor < valid_until;
                prop_assert_eq!(
                    consent.permits(
                        &person_id,
                        &ConsentPurpose::EmailMarketing,
                        &ContactChannel::Email,
                        "de",
                        cursor,
                    ),
                    should_permit,
                );
                prop_assert!(!consent.permits(
                    &PersonId::from("other-person"),
                    &ConsentPurpose::EmailMarketing,
                    &ContactChannel::Email,
                    "DE",
                    cursor,
                ));
                prop_assert!(!consent.permits(
                    &person_id,
                    &ConsentPurpose::DirectOutreach,
                    &ContactChannel::Email,
                    "DE",
                    cursor,
                ));
                prop_assert!(!consent.permits(
                    &person_id,
                    &ConsentPurpose::EmailMarketing,
                    &ContactChannel::SocialDirectMessage,
                    "DE",
                    cursor,
                ));
                prop_assert!(!consent.permits(
                    &person_id,
                    &ConsentPurpose::EmailMarketing,
                    &ContactChannel::Email,
                    "US",
                    cursor,
                ));
            }
        }

        #[test]
        fn arbitrary_identity_link_decisions_are_atomic_append_only_and_fail_closed(
            confidence_basis_points in 0_i64..101,
            actions in prop::collection::vec((0_u8..8, 0_i64..4), 1..64),
        ) {
            let confidence = Decimal::new(confidence_basis_points, 2);
            let mut link = identity_link(confidence);
            let initial = link.clone();
            let mut cursor = now();

            for (action, advance_minutes) in actions {
                cursor += Duration::minutes(advance_minutes);
                let before = link.clone();
                let mut command_targets_link = true;
                let result = match action {
                    0 => link.confirm(
                        ActorId::from("reviewer-model"),
                        "1".repeat(64),
                        cursor,
                    ),
                    1 => link.mark_conflicted(
                        ActorId::from("reviewer-model"),
                        "2".repeat(64),
                        cursor,
                    ),
                    2 => link.reject(
                        ActorId::from("reviewer-model"),
                        "3".repeat(64),
                        cursor,
                    ),
                    3 => match link.status {
                        IdentityLinkStatus::Proposed => link.mark_conflicted(
                            ActorId::from(""),
                            "4".repeat(64),
                            cursor,
                        ),
                        IdentityLinkStatus::Confirmed => link.mark_conflicted(
                            ActorId::from("reviewer-model"),
                            "4".repeat(64),
                            link.decisions.last().expect("decision").decided_at
                                - Duration::seconds(1),
                        ),
                        IdentityLinkStatus::Conflicted => link.reject(
                            ActorId::from("reviewer-model"),
                            "4".repeat(64),
                            link.decisions.last().expect("decision").decided_at
                                - Duration::seconds(1),
                        ),
                        IdentityLinkStatus::Rejected => link.mark_conflicted(
                            ActorId::from("reviewer-model"),
                            "4".repeat(64),
                            cursor,
                        ),
                    },
                    4 => {
                        command_targets_link = false;
                        let mut forged = link.clone();
                        forged.revision = forged.revision.saturating_add(2);
                        prop_assert!(forged.validate().is_err());
                        Ok(())
                    }
                    5 => {
                        command_targets_link = false;
                        let mut forged = link.clone();
                        forged.status = match forged.status {
                            IdentityLinkStatus::Proposed => IdentityLinkStatus::Conflicted,
                            _ => IdentityLinkStatus::Proposed,
                        };
                        prop_assert!(forged.validate().is_err());
                        Ok(())
                    }
                    6 => link.mark_conflicted(
                        ActorId::from("reviewer-model"),
                        "not-a-digest",
                        cursor,
                    ),
                    _ => link.mark_conflicted(
                        ActorId::from(""),
                        "5".repeat(64),
                        cursor,
                    ),
                };

                if command_targets_link && result.is_ok() {
                    prop_assert_eq!(link.revision, before.revision + 1);
                    prop_assert!(link.follows(&before).expect("decision append"));
                } else {
                    prop_assert_eq!(link.clone(), before);
                }
                prop_assert!(link.validate().is_ok());
                prop_assert_eq!(link.id.clone(), initial.id.clone());
                prop_assert_eq!(link.tenant_id.clone(), initial.tenant_id.clone());
                prop_assert_eq!(link.project_id.clone(), initial.project_id.clone());
                prop_assert_eq!(link.subject.clone(), initial.subject.clone());
                prop_assert_eq!(link.identities.clone(), initial.identities.clone());
                prop_assert_eq!(link.confidence, initial.confidence);
                let confirms_exact_identity = link.confirms_external_identity(
                    "commerce-fixture",
                    &AccountId::from("account-1"),
                );
                prop_assert_eq!(
                    confirms_exact_identity,
                    link.status == IdentityLinkStatus::Confirmed,
                );
                if link.status == IdentityLinkStatus::Rejected {
                    let terminal = link.clone();
                    prop_assert!(link.mark_conflicted(
                        ActorId::from("reviewer-model"),
                        "6".repeat(64),
                        cursor,
                    ).is_err());
                    prop_assert_eq!(link.clone(), terminal);
                }
            }
        }
    }
}
