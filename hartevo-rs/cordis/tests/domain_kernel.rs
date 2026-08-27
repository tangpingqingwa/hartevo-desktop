use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    DomainSurface, KernelApproval, KernelApprovalDecision, KernelConsentRecord, KernelConsentState,
    KernelConsentStatus, SurfaceOwner, bind_domain_kernel_facts,
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
}

fn granted(valid_until: chrono::DateTime<Utc>) -> KernelConsentRecord {
    KernelConsentRecord {
        status: KernelConsentStatus::Granted,
        granted_at: Some(now()),
        valid_until: Some(valid_until),
        withdrawn_at: None,
    }
}

fn approved(valid_until: chrono::DateTime<Utc>) -> KernelApproval {
    KernelApproval {
        decision: KernelApprovalDecision::Approved,
        valid_until,
    }
}

#[test]
fn confirmed_or_live_granted_record_sets_consent_true() {
    let from_state = DomainSurface::from_kernel(KernelConsentState::Confirmed, None, None, now());
    assert!(from_state.consent);
    assert!(!from_state.approved);
    assert_eq!(from_state.owner, SurfaceOwner::Hartevo);
    assert!(from_state.local_first && from_state.sqlcipher && from_state.eval_gate);

    let from_record = DomainSurface::from_kernel(
        KernelConsentState::NotRequired,
        Some(granted(now() + Duration::days(30))),
        None,
        now() + Duration::hours(1),
    );
    assert!(from_record.consent);
    assert!(!from_record.approved);
}

#[test]
fn missing_withdrawn_denied_expired_and_future_grant_stay_false() {
    for (state, record) in [
        (KernelConsentState::Missing, None),
        (KernelConsentState::Withdrawn, None),
        (KernelConsentState::NotRequired, None),
        (
            KernelConsentState::NotRequired,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Denied,
                granted_at: None,
                valid_until: None,
                withdrawn_at: None,
            }),
        ),
        (
            KernelConsentState::NotRequired,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Expired,
                granted_at: Some(now() - Duration::days(2)),
                valid_until: Some(now() - Duration::days(1)),
                withdrawn_at: None,
            }),
        ),
        (
            KernelConsentState::Withdrawn,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Withdrawn,
                granted_at: Some(now()),
                valid_until: Some(now() + Duration::days(30)),
                withdrawn_at: Some(now() + Duration::hours(1)),
            }),
        ),
        (
            KernelConsentState::NotRequired,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Granted,
                granted_at: Some(now() + Duration::hours(1)),
                valid_until: Some(now() + Duration::days(30)),
                withdrawn_at: None,
            }),
        ),
        (
            KernelConsentState::NotRequired,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Granted,
                granted_at: Some(now() - Duration::days(2)),
                valid_until: Some(now() - Duration::seconds(1)),
                withdrawn_at: None,
            }),
        ),
    ] {
        let domain = DomainSurface::from_kernel(state, record, None, now());
        assert!(
            !domain.consent,
            "consent must stay false for {state:?} / {record:?}"
        );
    }
}

#[test]
fn approved_is_true_only_inside_valid_until() {
    let live = DomainSurface::from_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(approved(now() + Duration::minutes(5))),
        now(),
    );
    assert!(live.approved);

    let expired = DomainSurface::from_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(approved(now())),
        now(),
    );
    assert!(!expired.approved);

    let rejected = DomainSurface::from_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(KernelApproval {
            decision: KernelApprovalDecision::Rejected,
            valid_until: now() + Duration::minutes(5),
        }),
        now(),
    );
    assert!(!rejected.approved);
}

#[test]
fn bind_preserves_mounted_owner_and_gates() {
    let mounted = DomainSurface {
        owner: SurfaceOwner::Hartevo,
        consent: false,
        approved: false,
        local_first: true,
        sqlcipher: true,
        eval_gate: true,
    };
    let bound = bind_domain_kernel_facts(
        mounted,
        KernelConsentState::Confirmed,
        None,
        Some(approved(now() + Duration::minutes(5))),
        now(),
    );
    assert!(bound.consent);
    assert!(bound.approved);
    assert_eq!(bound.owner, mounted.owner);
    assert_eq!(bound.local_first, mounted.local_first);
    assert_eq!(bound.sqlcipher, mounted.sqlcipher);
    assert_eq!(bound.eval_gate, mounted.eval_gate);
}
