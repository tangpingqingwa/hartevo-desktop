//! Mission-scoped credit accounting with an append-only reservation ledger.
//!
//! A reservation is created against the exact Mission revision and immutable
//! Effect scope digest that authorized the work. Commit requires a durable
//! Receipt-bearing Effect state; release requires an explicit non-uncertain
//! terminal reason. An uncertain provider result is never silently released or
//! retried by this ledger.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CreditGrantId, CurrencyCode, EffectId, EffectStatus, MissionId, Money, ProjectId, ReceiptId,
    TenantId, UsageEntryId, UsageReservationId,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReservationStatus {
    Reserved,
    Committed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionUsageReservation {
    pub id: UsageReservationId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub effect_id: EffectId,
    pub mission_revision: u64,
    pub effect_scope_digest: String,
    pub amount: Money,
    pub idempotency_key: String,
    pub reserved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: UsageReservationStatus,
}

impl MissionUsageReservation {
    pub fn validate(&self, ledger_currency: &CurrencyCode) -> Result<(), UsageLedgerError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.effect_id.as_str().trim().is_empty()
            || self.mission_revision == 0
            || self.effect_scope_digest.len() != 64
            || !self
                .effect_scope_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !self.amount.is_positive()
            || self.amount.currency != *ledger_currency
            || self.idempotency_key.trim().is_empty()
            || self.reserved_at.timestamp() < 0
            || self.expires_at <= self.reserved_at
            || self.status != UsageReservationStatus::Reserved
        {
            return Err(UsageLedgerError::InvalidReservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageCommitEvidence {
    pub receipt_id: ReceiptId,
    pub effect_status: EffectStatus,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReleaseReason {
    EffectCancelled,
    ProviderRejected,
    ReconciledNotExecuted,
    ReservationExpired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReleaseEvidence {
    pub reason: UsageReleaseReason,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum MissionUsageEntryKind {
    CreditGranted {
        grant_id: CreditGrantId,
        billing_fact_digest: String,
        amount: Money,
    },
    Reserved {
        reservation: MissionUsageReservation,
    },
    Committed {
        reservation_id: UsageReservationId,
        evidence: UsageCommitEvidence,
    },
    Released {
        reservation_id: UsageReservationId,
        evidence: UsageReleaseEvidence,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionUsageEntry {
    pub id: UsageEntryId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub revision: u64,
    pub kind: MissionUsageEntryKind,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageLedgerMutation<T> {
    Applied(T),
    Replayed(T),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionUsageLedger {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub currency: CurrencyCode,
    pub revision: u64,
    pub entries: Vec<MissionUsageEntry>,
}

impl MissionUsageLedger {
    pub fn new(tenant_id: TenantId, project_id: ProjectId, currency: CurrencyCode) -> Self {
        Self {
            tenant_id,
            project_id,
            currency,
            revision: 0,
            entries: Vec::new(),
        }
    }

    pub fn from_entries(
        tenant_id: TenantId,
        project_id: ProjectId,
        currency: CurrencyCode,
        entries: Vec<MissionUsageEntry>,
    ) -> Result<Self, UsageLedgerError> {
        let mut ledger = Self::new(tenant_id, project_id, currency);
        for entry in entries {
            ledger.apply_existing_entry(entry)?;
        }
        Ok(ledger)
    }

    pub fn available(&self) -> Result<Money, UsageLedgerError> {
        let mut balance = Money::zero(self.currency.clone());
        for entry in &self.entries {
            match &entry.kind {
                MissionUsageEntryKind::CreditGranted { amount, .. } => {
                    balance = balance.checked_add(amount)?;
                }
                MissionUsageEntryKind::Reserved { reservation } => {
                    balance = balance.checked_sub(&reservation.amount)?;
                }
                MissionUsageEntryKind::Released { reservation_id, .. } => {
                    let reservation = self
                        .reservation(reservation_id)
                        .ok_or(UsageLedgerError::UnknownReservation(reservation_id.clone()))?;
                    balance = balance.checked_add(&reservation.amount)?;
                }
                MissionUsageEntryKind::Committed { .. } => {}
            }
        }
        if balance.amount_minor < 0 {
            return Err(UsageLedgerError::NegativeAvailableBalance);
        }
        Ok(balance)
    }

    pub fn reserved(&self) -> Result<Money, UsageLedgerError> {
        self.total_for_status(UsageReservationStatus::Reserved)
    }

    pub fn committed(&self) -> Result<Money, UsageLedgerError> {
        self.total_for_status(UsageReservationStatus::Committed)
    }

    pub fn reservation(
        &self,
        reservation_id: &UsageReservationId,
    ) -> Option<MissionUsageReservation> {
        let mut current = None;
        for entry in &self.entries {
            match &entry.kind {
                MissionUsageEntryKind::Reserved { reservation }
                    if &reservation.id == reservation_id =>
                {
                    current = Some(reservation.clone());
                }
                MissionUsageEntryKind::Committed {
                    reservation_id: id, ..
                } if id == reservation_id => {
                    if let Some(reservation) = current.as_mut() {
                        reservation.status = UsageReservationStatus::Committed;
                    }
                }
                MissionUsageEntryKind::Released {
                    reservation_id: id, ..
                } if id == reservation_id => {
                    if let Some(reservation) = current.as_mut() {
                        reservation.status = UsageReservationStatus::Released;
                    }
                }
                _ => {}
            }
        }
        current
    }

    pub fn reservations(&self) -> Vec<MissionUsageReservation> {
        let mut ids = BTreeSet::new();
        self.entries
            .iter()
            .filter_map(|entry| match &entry.kind {
                MissionUsageEntryKind::Reserved { reservation }
                    if ids.insert(reservation.id.clone()) =>
                {
                    self.reservation(&reservation.id)
                }
                _ => None,
            })
            .collect()
    }

    pub fn reserve(
        &mut self,
        reservation: MissionUsageReservation,
    ) -> Result<UsageLedgerMutation<MissionUsageReservation>, UsageLedgerError> {
        reservation.validate(&self.currency)?;
        if let Some(existing) = self.reservation(&reservation.id) {
            if existing == reservation {
                return Ok(UsageLedgerMutation::Replayed(existing));
            }
            return Err(UsageLedgerError::ReservationConflict);
        }
        if self.entries.iter().any(|entry| {
            matches!(
                &entry.kind,
                MissionUsageEntryKind::Reserved { reservation: candidate }
                    if candidate.idempotency_key == reservation.idempotency_key
            )
        }) {
            return Err(UsageLedgerError::IdempotencyConflict);
        }
        if self.available()?.amount_minor < reservation.amount.amount_minor {
            return Err(UsageLedgerError::InsufficientCredits);
        }
        let entry = self.new_entry(
            UsageEntryId::from_stable(format!("reservation:{}", reservation.id)),
            MissionUsageEntryKind::Reserved {
                reservation: reservation.clone(),
            },
            reservation.reserved_at,
        )?;
        self.entries.push(entry);
        Ok(UsageLedgerMutation::Applied(reservation))
    }

    pub fn commit(
        &mut self,
        reservation_id: &UsageReservationId,
        mission_revision: u64,
        effect_scope_digest: &str,
        evidence: UsageCommitEvidence,
    ) -> Result<UsageLedgerMutation<MissionUsageReservation>, UsageLedgerError> {
        validate_effect_fence(mission_revision, effect_scope_digest)?;
        validate_commit_evidence(&evidence)?;
        let reservation = self
            .reservation(reservation_id)
            .ok_or_else(|| UsageLedgerError::UnknownReservation(reservation_id.clone()))?;
        if reservation.mission_revision != mission_revision
            || reservation.effect_scope_digest != effect_scope_digest
        {
            return Err(UsageLedgerError::RevisionFenceMismatch);
        }
        match reservation.status {
            UsageReservationStatus::Committed => {
                return Ok(UsageLedgerMutation::Replayed(reservation));
            }
            UsageReservationStatus::Released => return Err(UsageLedgerError::ReservationTerminal),
            UsageReservationStatus::Reserved => {}
        }
        if evidence.observed_at < reservation.reserved_at
            || evidence.observed_at > reservation.expires_at
        {
            return Err(UsageLedgerError::EvidenceOutsideReservationWindow);
        }
        let observed_at = evidence.observed_at;
        let entry = self.new_entry(
            UsageEntryId::from_stable(format!("commit:{}", reservation.id)),
            MissionUsageEntryKind::Committed {
                reservation_id: reservation.id.clone(),
                evidence,
            },
            observed_at,
        )?;
        self.entries.push(entry);
        let mut committed = reservation;
        committed.status = UsageReservationStatus::Committed;
        Ok(UsageLedgerMutation::Applied(committed))
    }

    pub fn release(
        &mut self,
        reservation_id: &UsageReservationId,
        mission_revision: u64,
        effect_scope_digest: &str,
        evidence: UsageReleaseEvidence,
    ) -> Result<UsageLedgerMutation<MissionUsageReservation>, UsageLedgerError> {
        validate_effect_fence(mission_revision, effect_scope_digest)?;
        validate_release_evidence(&evidence)?;
        let reservation = self
            .reservation(reservation_id)
            .ok_or_else(|| UsageLedgerError::UnknownReservation(reservation_id.clone()))?;
        if reservation.mission_revision != mission_revision
            || reservation.effect_scope_digest != effect_scope_digest
        {
            return Err(UsageLedgerError::RevisionFenceMismatch);
        }
        match reservation.status {
            UsageReservationStatus::Released => {
                return Ok(UsageLedgerMutation::Replayed(reservation));
            }
            UsageReservationStatus::Committed => return Err(UsageLedgerError::ReservationTerminal),
            UsageReservationStatus::Reserved => {}
        }
        if evidence.observed_at < reservation.reserved_at {
            return Err(UsageLedgerError::EvidenceOutsideReservationWindow);
        }
        let observed_at = evidence.observed_at;
        let entry = self.new_entry(
            UsageEntryId::from_stable(format!("release:{}", reservation.id)),
            MissionUsageEntryKind::Released {
                reservation_id: reservation.id.clone(),
                evidence,
            },
            observed_at,
        )?;
        self.entries.push(entry);
        let mut released = reservation;
        released.status = UsageReservationStatus::Released;
        Ok(UsageLedgerMutation::Applied(released))
    }

    pub fn grant_credit(
        &mut self,
        grant_id: CreditGrantId,
        billing_fact_digest: impl Into<String>,
        amount: Money,
        recorded_at: DateTime<Utc>,
    ) -> Result<UsageLedgerMutation<MissionUsageEntry>, UsageLedgerError> {
        let billing_fact_digest = billing_fact_digest.into();
        if grant_id.as_str().trim().is_empty()
            || billing_fact_digest.len() != 64
            || !billing_fact_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !amount.is_positive()
            || amount.currency != self.currency
        {
            return Err(UsageLedgerError::InvalidCreditGrant);
        }
        if let Some(existing) = self.entries.iter().find(|entry| {
            matches!(
                &entry.kind,
                MissionUsageEntryKind::CreditGranted {
                    grant_id: existing_id,
                    billing_fact_digest: existing_digest,
                    amount: existing_amount,
                } if existing_id == &grant_id
                    && existing_digest == &billing_fact_digest
                    && existing_amount == &amount
            )
        }) {
            return Ok(UsageLedgerMutation::Replayed(existing.clone()));
        }
        if self.entries.iter().any(|entry| {
            matches!(
                &entry.kind,
                MissionUsageEntryKind::CreditGranted { grant_id: existing_id, .. }
                    if existing_id == &grant_id
            )
        }) {
            return Err(UsageLedgerError::CreditGrantConflict);
        }
        let entry = self.new_entry(
            UsageEntryId::from_stable(format!("credit:{grant_id}")),
            MissionUsageEntryKind::CreditGranted {
                grant_id,
                billing_fact_digest,
                amount,
            },
            recorded_at,
        )?;
        self.entries.push(entry.clone());
        Ok(UsageLedgerMutation::Applied(entry))
    }

    fn total_for_status(&self, status: UsageReservationStatus) -> Result<Money, UsageLedgerError> {
        let mut total = Money::zero(self.currency.clone());
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if let MissionUsageEntryKind::Reserved { reservation } = &entry.kind
                && let Some(current) = self.reservation(&reservation.id)
                && current.status == status
                && seen.insert(reservation.id.clone())
            {
                total = total.checked_add(&current.amount)?;
            }
        }
        Ok(total)
    }

    fn new_entry(
        &mut self,
        id: UsageEntryId,
        kind: MissionUsageEntryKind,
        recorded_at: DateTime<Utc>,
    ) -> Result<MissionUsageEntry, UsageLedgerError> {
        if recorded_at.timestamp() < 0 {
            return Err(UsageLedgerError::InvalidTimestamp);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(UsageLedgerError::RevisionOverflow)?;
        self.revision = revision;
        Ok(MissionUsageEntry {
            id,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            revision,
            kind,
            recorded_at,
        })
    }

    fn apply_existing_entry(&mut self, entry: MissionUsageEntry) -> Result<(), UsageLedgerError> {
        if entry.tenant_id != self.tenant_id
            || entry.project_id != self.project_id
            || entry.revision != self.revision.saturating_add(1)
            || self.entries.iter().any(|existing| existing.id == entry.id)
        {
            return Err(UsageLedgerError::LedgerIntegrityFailure);
        }
        match &entry.kind {
            MissionUsageEntryKind::CreditGranted {
                grant_id,
                billing_fact_digest,
                amount,
            } => {
                if grant_id.as_str().trim().is_empty()
                    || billing_fact_digest.len() != 64
                    || !billing_fact_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    || amount.currency != self.currency
                    || !amount.is_positive()
                {
                    return Err(UsageLedgerError::InvalidCreditGrant);
                }
                if self.entries.iter().any(|existing| {
                    matches!(
                        &existing.kind,
                        MissionUsageEntryKind::CreditGranted {
                            grant_id: existing_id,
                            ..
                        } if existing_id == grant_id
                    )
                }) {
                    return Err(UsageLedgerError::CreditGrantConflict);
                }
            }
            MissionUsageEntryKind::Reserved { reservation } => {
                reservation.validate(&self.currency)?;
                if self.reservation(&reservation.id).is_some() {
                    return Err(UsageLedgerError::ReservationConflict);
                }
            }
            MissionUsageEntryKind::Committed {
                reservation_id,
                evidence,
            } => {
                validate_commit_evidence(evidence)?;
                let reservation = self
                    .reservation(reservation_id)
                    .ok_or_else(|| UsageLedgerError::UnknownReservation(reservation_id.clone()))?;
                if reservation.status != UsageReservationStatus::Reserved
                    || evidence.observed_at < reservation.reserved_at
                    || evidence.observed_at > reservation.expires_at
                {
                    return Err(UsageLedgerError::LedgerIntegrityFailure);
                }
            }
            MissionUsageEntryKind::Released {
                reservation_id,
                evidence,
            } => {
                validate_release_evidence(evidence)?;
                let reservation = self
                    .reservation(reservation_id)
                    .ok_or_else(|| UsageLedgerError::UnknownReservation(reservation_id.clone()))?;
                if reservation.status != UsageReservationStatus::Reserved
                    || evidence.observed_at < reservation.reserved_at
                {
                    return Err(UsageLedgerError::LedgerIntegrityFailure);
                }
            }
        }
        self.revision = entry.revision;
        self.entries.push(entry);
        Ok(())
    }
}

fn validate_effect_fence(
    mission_revision: u64,
    effect_scope_digest: &str,
) -> Result<(), UsageLedgerError> {
    if mission_revision == 0
        || effect_scope_digest.len() != 64
        || !effect_scope_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(UsageLedgerError::RevisionFenceMismatch);
    }
    Ok(())
}

fn validate_commit_evidence(evidence: &UsageCommitEvidence) -> Result<(), UsageLedgerError> {
    if evidence.receipt_id.as_str().trim().is_empty()
        || !matches!(
            evidence.effect_status,
            EffectStatus::ReceiptRecorded | EffectStatus::Verified
        )
        || evidence.evidence_digest.len() != 64
        || !evidence
            .evidence_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || evidence.observed_at.timestamp() < 0
    {
        return Err(UsageLedgerError::CommitRequiresReceipt);
    }
    Ok(())
}

fn validate_release_evidence(evidence: &UsageReleaseEvidence) -> Result<(), UsageLedgerError> {
    if evidence.evidence_digest.len() != 64
        || !evidence
            .evidence_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || evidence.observed_at.timestamp() < 0
    {
        return Err(UsageLedgerError::InvalidReleaseEvidence);
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UsageLedgerError {
    #[error("usage reservation is invalid")]
    InvalidReservation,
    #[error("usage reservation conflicts with an existing reservation")]
    ReservationConflict,
    #[error("usage reservation idempotency key conflicts with an existing reservation")]
    IdempotencyConflict,
    #[error("usage ledger has insufficient available credits")]
    InsufficientCredits,
    #[error("usage reservation revision or Effect scope fence does not match")]
    RevisionFenceMismatch,
    #[error("usage reservation is already terminal")]
    ReservationTerminal,
    #[error("usage reservation does not exist")]
    UnknownReservation(UsageReservationId),
    #[error("usage commit requires a durable ReceiptRecorded or Verified Effect")]
    CommitRequiresReceipt,
    #[error("usage release evidence is invalid")]
    InvalidReleaseEvidence,
    #[error("usage evidence falls outside the reservation window")]
    EvidenceOutsideReservationWindow,
    #[error("usage credit grant is invalid")]
    InvalidCreditGrant,
    #[error("usage credit grant conflicts with an existing grant")]
    CreditGrantConflict,
    #[error("usage ledger available balance would become negative")]
    NegativeAvailableBalance,
    #[error("usage ledger revision overflowed")]
    RevisionOverflow,
    #[error("usage ledger timestamp is invalid")]
    InvalidTimestamp,
    #[error("usage ledger integrity validation failed")]
    LedgerIntegrityFailure,
    #[error(transparent)]
    Money(#[from] crate::MoneyError),
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 2, 0, 0)
            .single()
            .expect("time")
    }

    fn ledger() -> MissionUsageLedger {
        let mut ledger = MissionUsageLedger::new(
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
            CurrencyCode::parse("USD").expect("USD"),
        );
        ledger
            .grant_credit(
                CreditGrantId::from("grant-1"),
                "a".repeat(64),
                Money::new(1_000, CurrencyCode::parse("USD").expect("USD")),
                now(),
            )
            .expect("credit grant");
        ledger
    }

    fn reservation() -> MissionUsageReservation {
        MissionUsageReservation {
            id: UsageReservationId::from("reservation-1"),
            tenant_id: TenantId::from("tenant-money"),
            project_id: ProjectId::from("project-money"),
            mission_id: MissionId::from("mission-money"),
            effect_id: EffectId::from("effect-money"),
            mission_revision: 7,
            effect_scope_digest: "b".repeat(64),
            amount: Money::new(400, CurrencyCode::parse("USD").expect("USD")),
            idempotency_key: "usage-reservation-1".into(),
            reserved_at: now(),
            expires_at: now() + chrono::Duration::minutes(10),
            status: UsageReservationStatus::Reserved,
        }
    }

    #[test]
    fn reserve_commit_and_release_are_exact_and_currency_safe() {
        let mut ledger = ledger();
        let reservation = reservation();
        assert!(matches!(
            ledger.reserve(reservation.clone()),
            Ok(UsageLedgerMutation::Applied(_))
        ));
        assert_eq!(ledger.available().expect("available").amount_minor, 600);
        let evidence = UsageCommitEvidence {
            receipt_id: ReceiptId::from("receipt-money"),
            effect_status: EffectStatus::Verified,
            evidence_digest: "c".repeat(64),
            observed_at: now() + chrono::Duration::minutes(1),
        };
        let committed = ledger
            .commit(
                &reservation.id,
                reservation.mission_revision,
                &reservation.effect_scope_digest,
                evidence.clone(),
            )
            .expect("commit");
        assert!(matches!(committed, UsageLedgerMutation::Applied(_)));
        assert_eq!(ledger.committed().expect("committed").amount_minor, 400);
        assert!(matches!(
            ledger.commit(
                &reservation.id,
                reservation.mission_revision,
                &reservation.effect_scope_digest,
                evidence,
            ),
            Ok(UsageLedgerMutation::Replayed(_))
        ));
        assert_eq!(ledger.available().expect("available").amount_minor, 600);
    }

    #[test]
    fn uncertain_effect_cannot_commit_or_release_usage() {
        let mut ledger = ledger();
        let reservation = reservation();
        ledger.reserve(reservation.clone()).expect("reserve");
        let evidence = UsageCommitEvidence {
            receipt_id: ReceiptId::from("receipt-money"),
            effect_status: EffectStatus::VerificationRequired,
            evidence_digest: "c".repeat(64),
            observed_at: now(),
        };
        assert_eq!(
            ledger.commit(
                &reservation.id,
                reservation.mission_revision,
                &reservation.effect_scope_digest,
                evidence,
            ),
            Err(UsageLedgerError::CommitRequiresReceipt)
        );
        let release = UsageReleaseEvidence {
            reason: UsageReleaseReason::ReconciledNotExecuted,
            evidence_digest: "d".repeat(64),
            observed_at: now(),
        };
        ledger
            .release(
                &reservation.id,
                reservation.mission_revision,
                &reservation.effect_scope_digest,
                release,
            )
            .expect("explicit not-executed release");
        assert_eq!(ledger.available().expect("available").amount_minor, 1_000);
    }

    #[test]
    fn idempotent_reservation_replay_does_not_consume_twice() {
        let mut ledger = ledger();
        let reservation = reservation();
        ledger.reserve(reservation.clone()).expect("reserve");
        assert!(matches!(
            ledger.reserve(reservation),
            Ok(UsageLedgerMutation::Replayed(_))
        ));
        assert_eq!(ledger.revision, 2);
        assert_eq!(ledger.available().expect("available").amount_minor, 600);
    }
}
