use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use hartevo_capability_gateway::{
    CapabilityClass, CapabilityDegradationError, CapabilityDegradationService,
    CapabilityFallbackComposition, CapabilityFallbackLog, CapabilityFallbackPolicy,
    CapabilityFallbackResult, CapabilityProviderBinding, CostLimit,
    DegradationCapabilityVersion as CapabilityVersion, DegradationInvocation, Digest,
    FallbackDecisionLogEventKind, FallbackDecisionState, FallbackLeaseStatus,
    FallbackRecoveryDisposition, FallbackResultDisposition, MemoryCapabilityFallbackLog, MissionId,
    MissionScope, ProjectId, ProjectScope, ProviderEffectState, ProviderLifecycle, ProviderOutcome,
    ProviderOutcomeDisposition, TenantId,
};
use proptest::prelude::*;

fn digest(value: &str) -> Digest {
    Digest::from_text(value)
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .single()
        .expect("fixed test timestamp")
}

fn cost(amount_minor: i64) -> CostLimit {
    CostLimit {
        amount_minor,
        currency: "USD".into(),
    }
}

fn project(project_id: &str) -> ProjectScope {
    ProjectScope {
        tenant_id: TenantId::from_stable("tenant-a"),
        project_id: ProjectId::from_stable(project_id),
        workspace_digest: digest("workspace-a"),
        resource_scope_digest: digest("resources-a"),
    }
}

fn mission(project: &ProjectScope, generation: u64) -> MissionScope {
    MissionScope {
        tenant_id: project.tenant_id.clone(),
        project_id: project.project_id.clone(),
        mission_id: MissionId::from_stable("mission-a"),
        task_id: None,
        worker_id: None,
        worker_lease_id: None,
        context_workspace_id: None,
        context_capsule_id: None,
        context_branch_id: None,
        generation,
        contract_revision: 11,
        scope_digest: digest(&format!("scope-{generation}")),
    }
}

fn invocation(
    class: CapabilityClass,
    generation: u64,
    invocation_revision: u64,
    idempotency: &str,
) -> DegradationInvocation {
    let project = project("project-a");
    DegradationInvocation::new(
        digest("capability.maps.read"),
        digest("service.maps.query"),
        CapabilityVersion::new(1, 2, 0),
        CapabilityVersion::new(3, 1, 0),
        class,
        project.clone(),
        mission(&project, generation),
        digest("authority-v1"),
        digest("policy-v1"),
        invocation_revision,
        digest(&format!("invocation-{generation}-{invocation_revision}")),
        digest(idempotency),
        cost(100),
    )
    .expect("valid invocation")
}

fn binding(invocation: DegradationInvocation, provider: &str) -> CapabilityProviderBinding {
    CapabilityProviderBinding::new(
        invocation,
        digest(provider),
        CapabilityVersion::new(5, 0, 0),
        digest(&format!("{provider}-implementation")),
        digest("provider-schema-v1"),
        1,
        digest(&format!("{provider}-revocation-v1")),
    )
    .expect("valid provider binding")
}

fn make_composition(class: CapabilityClass) -> CapabilityFallbackComposition {
    let primary = binding(
        invocation(class, 7, 4, "idempotency-once"),
        "primary-provider",
    );
    let alternate = binding(primary.invocation.clone(), "alternate-provider");
    let policy = CapabilityFallbackPolicy::new(
        primary.invocation.policy_digest.clone(),
        primary.invocation.authority_digest.clone(),
        BTreeSet::from([alternate.provider_digest.clone()]),
        primary.invocation.cost_ceiling.clone(),
    )
    .expect("valid fallback policy");
    CapabilityFallbackComposition::new(primary, alternate, policy)
        .expect("valid fallback composition")
}

fn primary_unavailable(composition: &CapabilityFallbackComposition) -> ProviderOutcome {
    ProviderOutcome::unavailable(
        &composition.primary,
        digest("primary-unavailable-result"),
        cost(10),
        now(),
    )
    .expect("valid unavailable outcome")
}

fn fallback_read_result(
    lease: &hartevo_capability_gateway::CapabilityFallbackLease,
    result: &str,
    amount: i64,
) -> CapabilityFallbackResult {
    CapabilityFallbackResult::new(
        lease.decision_digest().clone(),
        &lease.composition.alternate,
        FallbackResultDisposition::Completed,
        ProviderEffectState::NoEffect,
        digest(result),
        None,
        None,
        None,
        cost(amount),
        now(),
    )
    .expect("valid fallback result")
}

#[test]
fn read_fallback_is_single_use_and_durably_logged() {
    let composition = make_composition(CapabilityClass::Read);
    let outcome = primary_unavailable(&composition);
    let service = CapabilityDegradationService::new();
    let mut log = MemoryCapabilityFallbackLog::default();

    let mut lease = service
        .select_fallback(&composition, &outcome, &mut log, now())
        .expect("typed unavailability selects the policy alternate");
    assert_eq!(lease.status, FallbackLeaseStatus::Active);
    assert_eq!(log.len(), 1);
    assert_eq!(
        log.state_for(&composition.primary.invocation.key())
            .expect("memory log query"),
        Some(FallbackDecisionState::Selected)
    );

    let result = fallback_read_result(&lease, "alternate-read-result", 20);
    let receipt = service
        .complete_fallback(&mut lease, &result, &mut log, now())
        .expect("read fallback completes");
    assert_eq!(
        receipt.status,
        hartevo_capability_gateway::FallbackReceiptStatus::Completed
    );
    assert_eq!(lease.status, FallbackLeaseStatus::Completed);
    assert_eq!(log.len(), 2);
    assert_eq!(
        log.events_for(&composition.primary.invocation.key())[1].kind,
        FallbackDecisionLogEventKind::Completed
    );

    assert_eq!(
        service.complete_fallback(&mut lease, &result, &mut log, now()),
        Err(CapabilityDegradationError::LeaseClosed)
    );
    assert_eq!(
        service.select_fallback(&composition, &outcome, &mut log, now()),
        Err(CapabilityDegradationError::DuplicateFallback)
    );
}

#[test]
fn only_typed_unavailable_revoked_or_quota_outcomes_select() {
    let composition = make_composition(CapabilityClass::Read);
    let succeeded = ProviderOutcome::new(
        &composition.primary,
        ProviderOutcomeDisposition::Succeeded,
        ProviderEffectState::NoEffect,
        digest("primary-success"),
        None,
        None,
        None,
        cost(1),
        now(),
    )
    .expect("valid success outcome");
    let mut log = MemoryCapabilityFallbackLog::default();
    assert_eq!(
        CapabilityDegradationService::new().select_fallback(
            &composition,
            &succeeded,
            &mut log,
            now(),
        ),
        Err(CapabilityDegradationError::PrimaryOutcomeNotFallbackable)
    );
    assert!(log.is_empty());

    let mut revoked_primary = binding(
        invocation(CapabilityClass::Read, 7, 4, "revoked-once"),
        "primary-provider",
    );
    revoked_primary = revoked_primary
        .with_lifecycle(ProviderLifecycle::Revoked, digest("primary-revoked-v2"))
        .expect("valid revoked binding");
    let alternate = binding(revoked_primary.invocation.clone(), "alternate-provider");
    let policy = CapabilityFallbackPolicy::new(
        revoked_primary.invocation.policy_digest.clone(),
        revoked_primary.invocation.authority_digest.clone(),
        BTreeSet::from([alternate.provider_digest.clone()]),
        cost(100),
    )
    .expect("valid policy");
    let revoked_composition =
        CapabilityFallbackComposition::new(revoked_primary, alternate, policy)
            .expect("revoked primary can degrade");
    let revoked = ProviderOutcome::revoked(
        &revoked_composition.primary,
        digest("primary-revoked-result"),
        cost(2),
        now(),
    )
    .expect("valid revoked outcome");
    let mut revoked_log = MemoryCapabilityFallbackLog::default();
    assert!(
        CapabilityDegradationService::new()
            .select_fallback(&revoked_composition, &revoked, &mut revoked_log, now())
            .is_ok()
    );

    let quota_composition = make_composition(CapabilityClass::Read);
    let quota = ProviderOutcome::quota_exceeded(
        &quota_composition.primary,
        digest("primary-quota-result"),
        cost(2),
        now(),
    )
    .expect("valid quota outcome");
    let mut quota_log = MemoryCapabilityFallbackLog::default();
    assert!(
        CapabilityDegradationService::new()
            .select_fallback(&quota_composition, &quota, &mut quota_log, now())
            .is_ok()
    );
}

#[test]
fn policy_scope_version_and_provider_tamper_fail_closed() {
    let original = make_composition(CapabilityClass::Read);
    let mut tampered = original.clone();
    tampered.alternate.provider_version = CapabilityVersion::new(5, 1, 0);
    assert_eq!(
        tampered.validate(),
        Err(CapabilityDegradationError::StaleFallback)
    );

    let mut disallowed = original.clone();
    disallowed.policy.allowed_provider_digests = BTreeSet::from([digest("other-provider")]);
    assert_eq!(
        disallowed.validate(),
        Err(CapabilityDegradationError::AlternateProviderNotAllowed)
    );

    let primary = binding(
        invocation(CapabilityClass::Read, 7, 4, "same-provider-once"),
        "same-provider",
    );
    let same = binding(primary.invocation.clone(), "same-provider");
    let policy = CapabilityFallbackPolicy::new(
        primary.invocation.policy_digest.clone(),
        primary.invocation.authority_digest.clone(),
        BTreeSet::from([same.provider_digest.clone()]),
        cost(100),
    )
    .expect("valid policy");
    assert_eq!(
        CapabilityFallbackComposition::new(primary, same, policy),
        Err(CapabilityDegradationError::InvalidComposition)
    );

    let revoked_alternate = original
        .alternate
        .clone()
        .with_lifecycle(ProviderLifecycle::Revoked, digest("alternate-revoked-v2"))
        .expect("valid revoked alternate");
    let revoked_policy = CapabilityFallbackPolicy::new(
        original.primary.invocation.policy_digest.clone(),
        original.primary.invocation.authority_digest.clone(),
        BTreeSet::from([revoked_alternate.provider_digest.clone()]),
        cost(100),
    )
    .expect("valid revoked policy envelope");
    assert_eq!(
        CapabilityFallbackComposition::new(
            original.primary.clone(),
            revoked_alternate,
            revoked_policy,
        ),
        Err(CapabilityDegradationError::InvalidComposition)
    );

    let stale_outcome =
        ProviderOutcome::unavailable(&original.primary, digest("stale-outcome"), cost(1), now())
            .expect("valid outcome");
    let mut changed = original.clone();
    changed.primary.invocation.invocation_revision += 1;
    let mut log = MemoryCapabilityFallbackLog::default();
    assert_eq!(
        CapabilityDegradationService::new().select_fallback(
            &changed,
            &stale_outcome,
            &mut log,
            now(),
        ),
        Err(CapabilityDegradationError::InvalidComposition)
    );
}

#[test]
fn uncertain_primary_write_never_selects_a_fallback() {
    let composition = make_composition(CapabilityClass::ExternalEffect);
    let uncertain = ProviderOutcome::new(
        &composition.primary,
        ProviderOutcomeDisposition::Unavailable,
        ProviderEffectState::Uncertain,
        digest("primary-uncertain-result"),
        Some(digest("effect-1")),
        None,
        Some(digest("reconcile-1")),
        cost(10),
        now(),
    )
    .expect("typed uncertain provider outcome");
    let mut log = MemoryCapabilityFallbackLog::default();
    assert_eq!(
        CapabilityDegradationService::new().select_fallback(
            &composition,
            &uncertain,
            &mut log,
            now(),
        ),
        Err(CapabilityDegradationError::Recovery(
            FallbackRecoveryDisposition::UncertainExternalEffect {
                effect_digest: digest("effect-1"),
                reconciliation_digest: digest("reconcile-1"),
            }
        ))
    );
    assert!(log.is_empty());
}

#[test]
fn uncertain_alternate_is_terminal_and_cannot_be_replayed() {
    let composition = make_composition(CapabilityClass::ExternalEffect);
    let outcome = primary_unavailable(&composition);
    let service = CapabilityDegradationService::new();
    let mut log = MemoryCapabilityFallbackLog::default();
    let mut lease = service
        .select_fallback(&composition, &outcome, &mut log, now())
        .expect("select alternate");
    let uncertain = CapabilityFallbackResult::new(
        lease.decision_digest().clone(),
        &lease.composition.alternate,
        FallbackResultDisposition::UncertainExternalEffect,
        ProviderEffectState::Uncertain,
        digest("alternate-uncertain-result"),
        Some(digest("effect-2")),
        None,
        Some(digest("reconcile-2")),
        cost(20),
        now(),
    )
    .expect("valid uncertain fallback result");
    assert_eq!(
        service.complete_fallback(&mut lease, &uncertain, &mut log, now()),
        Err(CapabilityDegradationError::Recovery(
            FallbackRecoveryDisposition::UncertainExternalEffect {
                effect_digest: digest("effect-2"),
                reconciliation_digest: digest("reconcile-2"),
            }
        ))
    );
    assert_eq!(lease.status, FallbackLeaseStatus::UncertainExternalEffect);
    assert_eq!(log.len(), 2);
    assert_eq!(
        service.complete_fallback(&mut lease, &uncertain, &mut log, now()),
        Err(CapabilityDegradationError::LeaseClosed)
    );
}

#[test]
fn cumulative_cost_ceiling_is_not_expanded() {
    let composition = make_composition(CapabilityClass::Read);
    let outcome = ProviderOutcome::unavailable(
        &composition.primary,
        digest("expensive-primary-unavailable"),
        cost(80),
        now(),
    )
    .expect("primary cost within ceiling");
    let service = CapabilityDegradationService::new();
    let mut log = MemoryCapabilityFallbackLog::default();
    let mut lease = service
        .select_fallback(&composition, &outcome, &mut log, now())
        .expect("primary can select fallback");
    let result = fallback_read_result(&lease, "over-ceiling-fallback", 30);
    assert_eq!(
        service.complete_fallback(&mut lease, &result, &mut log, now()),
        Err(CapabilityDegradationError::CostExceeded)
    );
    assert_eq!(lease.status, FallbackLeaseStatus::Active);
    assert_eq!(log.len(), 1);
}

#[test]
fn stale_or_replayed_result_cannot_complete_a_live_lease() {
    let composition = make_composition(CapabilityClass::Read);
    let outcome = primary_unavailable(&composition);
    let service = CapabilityDegradationService::new();
    let mut log = MemoryCapabilityFallbackLog::default();
    let mut lease = service
        .select_fallback(&composition, &outcome, &mut log, now())
        .expect("select alternate");
    let mut stale = fallback_read_result(&lease, "stale-result", 10);
    stale.decision_digest = digest("other-decision");
    assert_eq!(
        service.complete_fallback(&mut lease, &stale, &mut log, now()),
        Err(CapabilityDegradationError::StaleFallback)
    );
    assert_eq!(lease.status, FallbackLeaseStatus::Active);

    let result = fallback_read_result(&lease, "valid-result", 10);
    service
        .complete_fallback(&mut lease, &result, &mut log, now())
        .expect("valid result still completes once");
    assert_eq!(lease.status, FallbackLeaseStatus::Completed);
}

#[test]
fn log_roundtrip_and_debug_are_content_free() {
    let composition = make_composition(CapabilityClass::Read);
    let outcome = primary_unavailable(&composition);
    let service = CapabilityDegradationService::new();
    let mut log = MemoryCapabilityFallbackLog::default();
    let lease = service
        .select_fallback(&composition, &outcome, &mut log, now())
        .expect("select alternate");
    let entry = log.events_for(&composition.primary.invocation.key())[0].clone();
    assert_eq!(entry.validate(), Ok(()));
    let encoded = serde_json::to_vec(&log).expect("serialize durable log");
    let decoded: MemoryCapabilityFallbackLog =
        serde_json::from_slice(&encoded).expect("deserialize durable log");
    assert_eq!(decoded, log);
    let debug = format!("{lease:?} {entry:?} {:?}", composition.primary.invocation);
    assert!(!debug.contains("tenant-a"));
    assert!(!debug.contains("project-a"));
    assert!(!debug.contains("mission-a"));
    assert!(!debug.contains("primary-provider"));
    assert!(debug.contains("binding_digest"));
    assert!(debug.contains("decision_digest"));
}

proptest! {
    #[test]
    fn equal_inputs_produce_equal_decision_and_event_digests(
        generation in 1_u64..100,
        invocation_revision in 1_u64..100,
    ) {
        let first = {
            let primary = binding(
                invocation(CapabilityClass::Read, generation, invocation_revision, "property-idempotency"),
                "primary-provider",
            );
            let alternate = binding(primary.invocation.clone(), "alternate-provider");
            let policy = CapabilityFallbackPolicy::new(
                primary.invocation.policy_digest.clone(),
                primary.invocation.authority_digest.clone(),
                BTreeSet::from([alternate.provider_digest.clone()]),
                cost(100),
            ).expect("valid policy");
            CapabilityFallbackComposition::new(primary, alternate, policy).expect("valid composition")
        };
        let second = first.clone();
        let outcome_one = primary_unavailable(&first);
        let outcome_two = primary_unavailable(&second);
        let service = CapabilityDegradationService::new();
        let mut log_one = MemoryCapabilityFallbackLog::default();
        let mut log_two = MemoryCapabilityFallbackLog::default();
        let lease_one = service.select_fallback(&first, &outcome_one, &mut log_one, now()).expect("select one");
        let lease_two = service.select_fallback(&second, &outcome_two, &mut log_two, now()).expect("select two");
        prop_assert_eq!(lease_one.decision_digest(), lease_two.decision_digest());
        prop_assert_eq!(
            log_one.events_for(&first.primary.invocation.key())[0].event_digest.clone(),
            log_two.events_for(&second.primary.invocation.key())[0].event_digest.clone(),
        );
    }
}
