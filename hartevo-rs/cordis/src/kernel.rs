//! Copy-free Domain Kernel facts for the host-side DomainSurface.
//!
//! Cordis does not reimplement Domain Kernel. These DTOs mirror the live
//! consent/approval facts desktop/data-plane already own so the host can bind
//! them without taking `hartevo-domain-kernel` as a crate dependency.

use chrono::{DateTime, Utc};

use crate::surface::DomainSurface;

/// Live consent state as Domain Kernel records it on an Effect / Mission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelConsentState {
    NotRequired,
    Confirmed,
    Missing,
    Withdrawn,
}

/// Live consent record status. Missing is absence of a live record, not a
/// `ConsentStatus` variant — Domain Kernel never stores Missing on a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelConsentStatus {
    Granted,
    Denied,
    Withdrawn,
    Expired,
}

/// Live consent record fields the host needs. Never copies person/market/source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelConsentRecord {
    pub status: KernelConsentStatus,
    pub granted_at: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
}

/// Live approval decision as Domain Kernel records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelApprovalDecision {
    Approved,
    Rejected,
}

/// Live approval fields the host needs. Scope/permission digests stay in kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelApproval {
    pub decision: KernelApprovalDecision,
    pub valid_until: DateTime<Utc>,
}

impl KernelConsentRecord {
    /// A live Granted record is still inside its window and has not been withdrawn.
    #[must_use]
    pub fn is_live_granted(self, now: DateTime<Utc>) -> bool {
        self.status == KernelConsentStatus::Granted
            && self.withdrawn_at.is_none()
            && self.granted_at.is_some_and(|granted| granted <= now)
            && self.valid_until.is_none_or(|until| until > now)
    }
}

impl KernelApproval {
    /// An Approved decision is live only while `now` is still inside `valid_until`.
    #[must_use]
    pub fn is_live_approved(self, now: DateTime<Utc>) -> bool {
        self.decision == KernelApprovalDecision::Approved && now < self.valid_until
    }
}

impl DomainSurface {
    /// Bind live Domain Kernel facts onto the host-side DomainSurface.
    ///
    /// `consent` is true only from [`KernelConsentState::Confirmed`] or a live
    /// [`KernelConsentRecord`] with [`KernelConsentStatus::Granted`]. `approved`
    /// is true only from a live [`KernelApproval`] with
    /// [`KernelApprovalDecision::Approved`] still inside `valid_until`.
    /// Everything else stays fail-closed (`false`). Owner, local-first,
    /// SQLCipher, and eval remain Hartevo production defaults.
    #[must_use]
    pub fn from_kernel(
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            consent: live_consent(consent, record, now),
            approved: approval.is_some_and(|approval| approval.is_live_approved(now)),
            ..Self::default()
        }
    }
}

/// Same binding as [`DomainSurface::from_kernel`], keeping any already-mounted
/// DomainSurface owner / local-first / sqlcipher / eval flags.
#[must_use]
pub fn bind_domain_kernel_facts(
    mounted: DomainSurface,
    consent: KernelConsentState,
    record: Option<KernelConsentRecord>,
    approval: Option<KernelApproval>,
    now: DateTime<Utc>,
) -> DomainSurface {
    DomainSurface {
        consent: live_consent(consent, record, now),
        approved: approval.is_some_and(|approval| approval.is_live_approved(now)),
        ..mounted
    }
}

fn live_consent(
    consent: KernelConsentState,
    record: Option<KernelConsentRecord>,
    now: DateTime<Utc>,
) -> bool {
    consent == KernelConsentState::Confirmed
        || record.is_some_and(|record| record.is_live_granted(now))
}
