//! One-call-site Cordis mount for the desktop shell.
//!
//! The live loop is [`hartevo_cordis::CordisHost::step`] → `run_agent_step`
//! after `enforce_invariants`. OpenInterpreter may occupy
//! `RuntimeSurface.plugin`; it is never the loop and never owns Domain or
//! Effect. Consent/approval are bound from Domain Kernel facts after boot.

use chrono::{DateTime, Utc};
use hartevo_cordis::{
    AgentStep, AgentStepResult, CordisError, CordisHost, KernelApproval, KernelApprovalDecision,
    KernelConsentRecord, KernelConsentState, KernelConsentStatus, desktop_surfaces,
    host_is_cordis_loop,
};
use hartevo_domain_kernel::{
    Approval, ApprovalDecision, ConsentRecord, ConsentState, ConsentStatus,
};

use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

/// Whether OpenInterpreter is configured as an optional runtime adapter.
#[must_use]
fn openinterpreter_runtime_plugin(runtime: &DesktopRuntimeProjection) -> bool {
    matches!(
        runtime.status,
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
            | DesktopRuntimeAvailabilityStatus::ReadyDistribution
    )
}

/// Boot SurfaceMapping + AgentLoop + InvariantGate for this desktop process.
///
/// Production mount is fail-closed: consent/approval stay false until
/// [`bind_live_domain_kernel`] reads live Domain Kernel facts.
pub fn mount_cordis_host(runtime: &DesktopRuntimeProjection) -> Result<CordisHost, CordisError> {
    let host = CordisHost::boot(desktop_surfaces(openinterpreter_runtime_plugin(runtime)))?;
    host_is_cordis_loop(&host)?;
    Ok(host)
}

/// Map a Domain Kernel [`ConsentState`] onto the host-side DTO.
#[must_use]
fn kernel_consent_state(state: &ConsentState) -> KernelConsentState {
    match state {
        ConsentState::NotRequired => KernelConsentState::NotRequired,
        ConsentState::Confirmed => KernelConsentState::Confirmed,
        ConsentState::Missing => KernelConsentState::Missing,
        ConsentState::Withdrawn => KernelConsentState::Withdrawn,
    }
}

/// Map a live Domain Kernel [`ConsentRecord`] onto the host-side DTO.
#[must_use]
fn kernel_consent_record(record: &ConsentRecord) -> KernelConsentRecord {
    KernelConsentRecord {
        status: match record.status {
            ConsentStatus::Granted => KernelConsentStatus::Granted,
            ConsentStatus::Denied => KernelConsentStatus::Denied,
            ConsentStatus::Withdrawn => KernelConsentStatus::Withdrawn,
            ConsentStatus::Expired => KernelConsentStatus::Expired,
        },
        granted_at: record.granted_at,
        valid_until: record.valid_until,
        withdrawn_at: record.withdrawn_at,
    }
}

/// Map a live Domain Kernel [`Approval`] onto the host-side DTO.
#[must_use]
fn kernel_approval(approval: &Approval) -> KernelApproval {
    KernelApproval {
        decision: match approval.decision {
            ApprovalDecision::Approved => KernelApprovalDecision::Approved,
            ApprovalDecision::Rejected => KernelApprovalDecision::Rejected,
        },
        valid_until: approval.valid_until,
    }
}

/// Bind live Domain Kernel consent/approval onto the mounted DomainSurface.
///
/// Production desktop reads kernel types here; it never hardcodes `true`.
pub fn bind_live_domain_kernel(
    host: &mut CordisHost,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
) -> Result<(), CordisError> {
    host.bind_domain_kernel(
        kernel_consent_state(consent),
        record.map(kernel_consent_record),
        approval.map(kernel_approval),
        now,
    )
}

/// Fail-closed Domain Kernel facts for one Project/Mission. Absence, expiry,
/// withdrawal, and rejection stay `None`; this never invents `true`.
#[derive(Debug, Clone)]
pub struct LiveDomainKernelFacts {
    pub consent: ConsentState,
    pub record: Option<ConsentRecord>,
    pub approval: Option<Approval>,
}

impl LiveDomainKernelFacts {
    #[must_use]
    pub fn missing() -> Self {
        Self {
            consent: ConsentState::Missing,
            record: None,
            approval: None,
        }
    }
}

/// Bind whatever live facts exist, then run one Cordis-hosted step.
pub fn step_with_live_domain_kernel(
    host: &mut CordisHost,
    facts: &LiveDomainKernelFacts,
    step: AgentStep,
    now: DateTime<Utc>,
) -> Result<AgentStepResult, CordisError> {
    bind_live_domain_kernel(
        host,
        &facts.consent,
        facts.record.as_ref(),
        facts.approval.as_ref(),
        now,
    )?;
    host.step(step)
}

/// Bind whatever live facts exist, then take the Effect write path.
pub fn apply_effect_with_live_domain_kernel(
    host: &mut CordisHost,
    facts: &LiveDomainKernelFacts,
    now: DateTime<Utc>,
) -> Result<(), CordisError> {
    bind_live_domain_kernel(
        host,
        &facts.consent,
        facts.record.as_ref(),
        facts.approval.as_ref(),
        now,
    )?;
    host.apply_effect()
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use hartevo_cordis::{
        AgentStep, CordisError, DomainSurface, OPENINTERPRETER, SurfaceOwner, desktop_surfaces,
        enforce_invariants, host_is_cordis_loop, invariant_missing, keys,
    };
    use hartevo_domain_kernel::{
        ActorId, Approval, ApprovalDecision, ApprovalId, ConsentPurpose, ConsentRecord,
        ConsentRecordId, ConsentState, ConsentStatus, ContactChannel, LegalBasis, PersonId,
        ProjectId, TenantId,
    };
    use hartevo_runtime_adapter::OPENINTERPRETER_RELEASE;

    use super::{
        LiveDomainKernelFacts, apply_effect_with_live_domain_kernel, bind_live_domain_kernel,
        mount_cordis_host, openinterpreter_runtime_plugin, step_with_live_domain_kernel,
    };
    use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

    fn projection(status: DesktopRuntimeAvailabilityStatus) -> DesktopRuntimeProjection {
        DesktopRuntimeProjection {
            status,
            target: Some("aarch64-apple-darwin".into()),
            release: OPENINTERPRETER_RELEASE.into(),
            program_sha256: None,
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
    }

    fn granted_record(valid_until: chrono::DateTime<Utc>) -> ConsentRecord {
        ConsentRecord::grant(
            ConsentRecordId::from("consent-desktop"),
            TenantId::from("tenant-desktop"),
            ProjectId::from("project-desktop"),
            PersonId::from("person-desktop"),
            ConsentPurpose::DirectOutreach,
            ContactChannel::Email,
            "US",
            LegalBasis::ExplicitConsent,
            "signed desktop consent",
            "e".repeat(64),
            now(),
            Some(valid_until),
        )
        .expect("granted consent")
    }

    fn approved(valid_until: chrono::DateTime<Utc>) -> Approval {
        Approval {
            id: ApprovalId::from("approval-desktop"),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("user-desktop"),
            decided_at: now(),
            valid_until,
            scope_digest: "a".repeat(64),
            permission_digest: "b".repeat(64),
        }
    }

    #[test]
    fn production_desktop_surfaces_do_not_pre_grant_consent_or_approval() {
        for openinterpreter in [false, true] {
            let surfaces = desktop_surfaces(openinterpreter);
            assert!(!surfaces.domain.consent);
            assert!(!surfaces.domain.approved);
            assert_eq!(surfaces.domain.owner, SurfaceOwner::Hartevo);
            assert!(surfaces.domain.local_first);
            assert!(surfaces.domain.sqlcipher);
            assert!(surfaces.domain.eval_gate);
            assert!(!surfaces.effect_broker.receipt_is_verification);
        }
    }

    #[test]
    fn not_configured_runtime_does_not_name_openinterpreter_plugin() {
        assert!(!openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::NotConfigured
        )));
        let host = mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
            .unwrap();
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(host.runtime_plugin(), None);
        let domain = host.context().domain::<DomainSurface>().unwrap();
        assert_eq!(domain.owner, SurfaceOwner::Hartevo);
        assert!(!domain.consent);
        assert!(!domain.approved);
        assert!(host.context().get::<String>(OPENINTERPRETER).is_none());
    }

    #[test]
    fn ready_runtime_keeps_openinterpreter_as_optional_plugin_without_pre_grant() {
        let mut host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
        ))
        .unwrap();
        assert!(openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment
        )));
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
        assert_eq!(
            host.context()
                .runtime::<hartevo_cordis::RuntimeSurface>()
                .unwrap()
                .owner,
            SurfaceOwner::Hartevo
        );
        assert_eq!(
            enforce_invariants(host.context()).unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        enforce_invariants(host.context()).unwrap();
        host.apply_effect().unwrap();
    }

    #[test]
    fn desktop_step_fails_closed_until_kernel_facts_are_bound() {
        let mut host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDistribution,
        ))
        .unwrap();
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-desktop", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        bind_live_domain_kernel(&mut host, &ConsentState::Confirmed, None, None, now()).unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-desktop", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        let out = host
            .step(AgentStep::new("mission-desktop", "plan"))
            .unwrap();
        assert_eq!(out.id, "mission-desktop");
        for key in [
            keys::TOOLS,
            keys::LLM,
            keys::AGENTS,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
        ] {
            assert!(host.context().has(key), "{key} must stay mounted");
        }
    }

    fn denied_record() -> ConsentRecord {
        let denied = ConsentRecord {
            id: ConsentRecordId::from("consent-denied"),
            tenant_id: TenantId::from("tenant-desktop"),
            project_id: ProjectId::from("project-desktop"),
            person_id: PersonId::from("person-desktop"),
            purpose: ConsentPurpose::DirectOutreach,
            channel: ContactChannel::Email,
            market: "US".into(),
            legal_basis: LegalBasis::ExplicitConsent,
            status: ConsentStatus::Denied,
            source: "signed desktop consent".into(),
            evidence_digest: "e".repeat(64),
            granted_at: None,
            valid_until: None,
            withdrawn_at: None,
            revision: 1,
        };
        denied.validate().expect("denied record");
        denied
    }

    #[test]
    fn withdrawn_missing_denied_and_expired_consent_fail_closed() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let mut withdrawn = granted_record(now() + Duration::days(30));
        withdrawn.withdraw(now() + Duration::hours(1)).unwrap();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Withdrawn,
            Some(&withdrawn),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::hours(2),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-withdrawn", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Missing,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        let mut expired_record = granted_record(now() + Duration::seconds(1));
        expired_record
            .expire(now() + Duration::seconds(2))
            .expect("expire");
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&expired_record),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::seconds(3),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-expired-record", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        let denied = denied_record();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&denied),
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
    }

    #[test]
    fn expired_or_rejected_approval_fails_closed_and_granted_record_allows_step() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() - Duration::seconds(1))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-expired", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );

        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&Approval {
                id: ApprovalId::from("approval-rejected"),
                decision: ApprovalDecision::Rejected,
                decided_by: ActorId::from("user-desktop"),
                decided_at: now(),
                valid_until: now() + Duration::minutes(5),
                scope_digest: "a".repeat(64),
                permission_digest: "b".repeat(64),
            }),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-rejected", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );

        let live = granted_record(now() + Duration::days(30));
        assert_eq!(live.status, ConsentStatus::Granted);
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&live),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::minutes(1),
        )
        .unwrap();
        host.step(AgentStep::new("mission-granted-record", "plan"))
            .unwrap();
    }

    #[test]
    fn missing_live_facts_keep_step_and_effect_fail_closed() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        assert_eq!(
            step_with_live_domain_kernel(
                &mut host,
                &LiveDomainKernelFacts::missing(),
                AgentStep::new("mission-missing", "plan"),
                now(),
            )
            .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        assert_eq!(
            apply_effect_with_live_domain_kernel(
                &mut host,
                &LiveDomainKernelFacts::missing(),
                now(),
            )
            .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
    }
}
