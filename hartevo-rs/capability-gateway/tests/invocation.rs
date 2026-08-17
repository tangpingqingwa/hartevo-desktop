use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use hartevo_capability_gateway::{
    CapabilityClass, CapabilityDegradationService, CapabilityFallbackComposition,
    CapabilityFallbackInvocationConsumer, CapabilityFallbackInvocationError,
    CapabilityFallbackPolicy, CapabilityFallbackResult, CapabilityProviderBinding, CostLimit,
    DegradationCapabilityVersion as CapabilityVersion, DegradationInvocation, Digest,
    FallbackDispatchError, FallbackInvocationClaim, FallbackInvocationDispatcher,
    FallbackInvocationEventKind, FallbackInvocationLedger, FallbackInvocationReceiptStatus,
    FallbackInvocationRecoveryDisposition, FallbackInvocationRequest, FallbackInvocationSnapshot,
    FallbackInvocationState, FallbackLeaseStatus, FallbackResultDisposition,
    MemoryCapabilityFallbackLog, MemoryFallbackInvocationLedger, MissionId, MissionScope,
    ProjectId, ProjectScope, ProviderEffectState, ProviderLifecycle, ProviderOutcome,
    ProviderOutcomeDisposition, TenantId,
};

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

fn project() -> ProjectScope {
    ProjectScope {
        tenant_id: TenantId::from_stable("tenant-a"),
        project_id: ProjectId::from_stable("project-a"),
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

fn invocation(class: CapabilityClass, idempotency: &str) -> DegradationInvocation {
    let project = project();
    DegradationInvocation::new(
        digest("capability.maps.read"),
        digest("service.maps.query"),
        CapabilityVersion::new(1, 2, 0),
        CapabilityVersion::new(3, 1, 0),
        class,
        project.clone(),
        mission(&project, 7),
        digest("authority-v1"),
        digest("policy-v1"),
        4,
        digest("invocation-v4"),
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

fn composition(class: CapabilityClass, idempotency: &str) -> CapabilityFallbackComposition {
    let primary = binding(invocation(class, idempotency), "primary-provider");
    let alternate = binding(primary.invocation.clone(), "alternate-provider");
    let policy = CapabilityFallbackPolicy::new(
        primary.invocation.policy_digest.clone(),
        primary.invocation.authority_digest.clone(),
        BTreeSet::from([alternate.provider_digest.clone()]),
        primary.invocation.cost_ceiling.clone(),
    )
    .expect("valid policy");
    CapabilityFallbackComposition::new(primary, alternate, policy).expect("valid composition")
}

fn selected(
    class: CapabilityClass,
    idempotency: &str,
    primary_cost: i64,
) -> (
    hartevo_capability_gateway::CapabilityFallbackLease,
    ProviderOutcome,
    MemoryCapabilityFallbackLog,
) {
    let composition = composition(class, idempotency);
    let outcome = ProviderOutcome::unavailable(
        &composition.primary,
        digest(&format!("primary-unavailable-{idempotency}")),
        cost(primary_cost),
        now(),
    )
    .expect("valid primary outcome");
    let mut log = MemoryCapabilityFallbackLog::default();
    let lease = CapabilityDegradationService::new()
        .select_fallback(&composition, &outcome, &mut log, now())
        .expect("select fallback");
    (lease, outcome, log)
}

fn snapshot(
    lease: &hartevo_capability_gateway::CapabilityFallbackLease,
    quota: &str,
    budget_revision: u64,
) -> FallbackInvocationSnapshot {
    FallbackInvocationSnapshot::new(lease, digest(quota), budget_revision)
        .expect("valid invocation snapshot")
}

fn result(
    lease: &hartevo_capability_gateway::CapabilityFallbackLease,
    class: CapabilityClass,
    result_label: &str,
    cost_used: i64,
) -> CapabilityFallbackResult {
    let external = class == CapabilityClass::ExternalEffect;
    CapabilityFallbackResult::new(
        lease.decision_digest().clone(),
        &lease.composition.alternate,
        FallbackResultDisposition::Completed,
        if external {
            ProviderEffectState::Verified
        } else {
            ProviderEffectState::NoEffect
        },
        digest(result_label),
        external.then(|| digest("effect-digest")),
        external.then(|| digest("effect-receipt")),
        None,
        cost(cost_used),
        now(),
    )
    .expect("valid fallback result")
}

#[derive(Clone)]
enum DispatcherResponse {
    Result(Box<CapabilityFallbackResult>),
    Error(FallbackDispatchError),
}

struct MockDispatcher {
    response: DispatcherResponse,
    calls: usize,
    requests: Vec<FallbackInvocationRequest>,
}

impl MockDispatcher {
    fn responding(response: DispatcherResponse) -> Self {
        Self {
            response,
            calls: 0,
            requests: Vec::new(),
        }
    }
}

impl FallbackInvocationDispatcher for MockDispatcher {
    fn dispatch(
        &mut self,
        request: &FallbackInvocationRequest,
    ) -> Result<CapabilityFallbackResult, FallbackDispatchError> {
        self.calls += 1;
        self.requests.push(request.clone());
        match &self.response {
            DispatcherResponse::Result(result) => Ok((**result).clone()),
            DispatcherResponse::Error(error) => Err(error.clone()),
        }
    }
}

fn claim_selection(
    lease: &hartevo_capability_gateway::CapabilityFallbackLease,
    ledger: &mut MemoryFallbackInvocationLedger,
) -> FallbackInvocationClaim {
    CapabilityFallbackInvocationConsumer::new()
        .claim(lease, &snapshot(lease, "quota-v1", 3), ledger, now())
        .expect("claim exact selection")
}

#[test]
fn claim_dispatches_exact_selection_once_and_records_receipt() {
    let (lease, primary_outcome, _degradation_log) = selected(CapabilityClass::Read, "once", 10);
    assert_eq!(lease.status, FallbackLeaseStatus::Active);
    let fallback_result = result(&lease, CapabilityClass::Read, "alternate-read", 20);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let mut claim = claim_selection(&lease, &mut ledger);
    let replay_claim = claim.clone();
    let mut dispatcher =
        MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));

    let receipt = CapabilityFallbackInvocationConsumer::new()
        .dispatch_once(
            &mut claim,
            &primary_outcome,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        )
        .expect("dispatch selected fallback once");

    assert_eq!(receipt.status, FallbackInvocationReceiptStatus::Completed);
    assert_eq!(receipt.fallback_attempt, 1);
    assert_eq!(
        claim.status,
        hartevo_capability_gateway::FallbackInvocationClaimStatus::Terminal
    );
    assert_eq!(dispatcher.calls, 1);
    assert_eq!(dispatcher.requests.len(), 1);
    assert_eq!(dispatcher.requests[0].fallback_attempt, 1);
    assert_eq!(
        dispatcher.requests[0].primary_outcome,
        lease.primary_outcome
    );
    assert_eq!(
        dispatcher.requests[0].alternate,
        lease.composition.alternate
    );
    assert_eq!(ledger.len(), 3);
    assert_eq!(
        ledger
            .state_for(lease.decision_digest())
            .expect("ledger state"),
        Some(FallbackInvocationState::Completed)
    );
    assert_eq!(
        CapabilityFallbackInvocationConsumer::new().dispatch_once(
            &mut claim,
            &primary_outcome,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::ClaimClosed)
    );

    assert_eq!(
        CapabilityFallbackInvocationConsumer::new().dispatch_once(
            &mut replay_claim.clone(),
            &primary_outcome,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::DuplicateDispatch)
    );
    assert_eq!(dispatcher.calls, 1);
}

#[test]
fn duplicate_claim_and_replayed_selection_fail_closed() {
    let (lease, _primary_outcome, _degradation_log) = selected(CapabilityClass::Read, "claim", 1);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let _claim = claim_selection(&lease, &mut ledger);
    assert_eq!(
        CapabilityFallbackInvocationConsumer::new().claim(
            &lease,
            &snapshot(&lease, "quota-v1", 3),
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::DuplicateClaim)
    );

    let mut tampered = lease.clone();
    tampered.decision.decision_digest = digest("replayed-selection");
    assert_eq!(
        CapabilityFallbackInvocationConsumer::new().claim(
            &tampered,
            &snapshot(&lease, "quota-v1", 3),
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::StaleSelection)
    );
}

#[test]
fn policy_quota_and_cost_revision_drift_is_logged_before_dispatch() {
    let service = CapabilityFallbackInvocationConsumer::new();
    for (label, expected) in [
        ("policy", CapabilityFallbackInvocationError::StalePolicy),
        ("quota", CapabilityFallbackInvocationError::QuotaDrift),
        ("cost", CapabilityFallbackInvocationError::CostDrift),
    ] {
        let (lease, primary_outcome, _degradation_log) =
            selected(CapabilityClass::Read, &format!("drift-{label}"), 10);
        let mut ledger = MemoryFallbackInvocationLedger::default();
        let mut claim = claim_selection(&lease, &mut ledger);
        let mut current_snapshot = snapshot(&lease, "quota-v1", 3);
        match label {
            "policy" => current_snapshot.policy_digest = digest("policy-v2"),
            "quota" => current_snapshot.quota_digest = digest("quota-v2"),
            "cost" => current_snapshot.cost_ceiling = cost(90),
            _ => unreachable!("test case is enumerated above"),
        }
        let fallback_result = result(&lease, CapabilityClass::Read, "never-dispatched", 1);
        let mut dispatcher =
            MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));
        assert_eq!(
            service.dispatch_once(
                &mut claim,
                &primary_outcome,
                &lease.composition.alternate,
                &current_snapshot,
                &mut dispatcher,
                &mut ledger,
                now(),
            ),
            Err(expected)
        );
        assert_eq!(dispatcher.calls, 0);
        assert_eq!(
            claim.status,
            hartevo_capability_gateway::FallbackInvocationClaimStatus::Terminal
        );
        assert_eq!(ledger.len(), 2);
        assert_eq!(
            ledger.events_for(lease.decision_digest())[1].kind,
            FallbackInvocationEventKind::Failed
        );
    }
}

#[test]
fn recovered_primary_and_revoked_or_changed_alternate_fail_before_dispatch() {
    let service = CapabilityFallbackInvocationConsumer::new();
    let (lease, _primary_outcome, _degradation_log) =
        selected(CapabilityClass::Read, "recovery", 1);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let mut claim = claim_selection(&lease, &mut ledger);
    let recovered = ProviderOutcome::new(
        &lease.composition.primary,
        ProviderOutcomeDisposition::Succeeded,
        ProviderEffectState::NoEffect,
        digest("primary-recovered"),
        None,
        None,
        None,
        cost(1),
        now(),
    )
    .expect("valid recovered primary");
    let fallback_result = result(&lease, CapabilityClass::Read, "never-dispatched", 1);
    let mut dispatcher =
        MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));
    assert_eq!(
        service.dispatch_once(
            &mut claim,
            &recovered,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::RecoveredPrimaryProvider)
    );
    assert_eq!(dispatcher.calls, 0);

    let (lease, primary_outcome, _degradation_log) = selected(CapabilityClass::Read, "revoke", 1);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let mut claim = claim_selection(&lease, &mut ledger);
    let revoked_alternate = lease
        .composition
        .alternate
        .clone()
        .with_lifecycle(ProviderLifecycle::Revoked, digest("alternate-revoked"))
        .expect("valid revoked alternate");
    let fallback_result = result(&lease, CapabilityClass::Read, "never-dispatched", 1);
    let mut dispatcher =
        MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));
    assert_eq!(
        service.dispatch_once(
            &mut claim,
            &primary_outcome,
            &revoked_alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::AlternateProviderRevoked)
    );
    assert_eq!(dispatcher.calls, 0);

    let (lease, primary_outcome, _degradation_log) =
        selected(CapabilityClass::Read, "changed-alternate", 1);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let mut claim = claim_selection(&lease, &mut ledger);
    let changed_alternate = binding(
        lease.composition.primary.invocation.clone(),
        "different-provider",
    );
    let fallback_result = result(&lease, CapabilityClass::Read, "never-dispatched", 1);
    let mut dispatcher =
        MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));
    assert_eq!(
        service.dispatch_once(
            &mut claim,
            &primary_outcome,
            &changed_alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::StaleSelection)
    );
    assert_eq!(dispatcher.calls, 0);
}

#[test]
fn cumulative_cost_drift_fails_after_dispatch_and_is_terminal() {
    let (lease, primary_outcome, _degradation_log) =
        selected(CapabilityClass::Read, "cost-result", 80);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let mut claim = claim_selection(&lease, &mut ledger);
    let fallback_result = result(&lease, CapabilityClass::Read, "over-budget-result", 30);
    let mut dispatcher =
        MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));
    assert_eq!(
        CapabilityFallbackInvocationConsumer::new().dispatch_once(
            &mut claim,
            &primary_outcome,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::CostDrift)
    );
    assert_eq!(dispatcher.calls, 1);
    assert_eq!(
        claim.status,
        hartevo_capability_gateway::FallbackInvocationClaimStatus::Terminal
    );
    assert_eq!(ledger.len(), 3);
    assert_eq!(
        ledger
            .state_for(lease.decision_digest())
            .expect("ledger state"),
        Some(FallbackInvocationState::Failed)
    );
}

#[test]
fn typed_alternate_unavailable_revoked_or_quota_result_is_terminal() {
    let service = CapabilityFallbackInvocationConsumer::new();
    for (label, disposition) in [
        ("unavailable", FallbackResultDisposition::Unavailable),
        ("revoked", FallbackResultDisposition::Revoked),
        ("quota", FallbackResultDisposition::QuotaExceeded),
    ] {
        let (lease, primary_outcome, _degradation_log) =
            selected(CapabilityClass::Read, &format!("typed-{label}"), 1);
        let result_digest = digest(&format!("alternate-{label}"));
        let fallback_result = CapabilityFallbackResult::new(
            lease.decision_digest().clone(),
            &lease.composition.alternate,
            disposition,
            ProviderEffectState::NoEffect,
            result_digest.clone(),
            None,
            None,
            None,
            cost(1),
            now(),
        )
        .expect("valid typed alternate terminal result");
        let mut ledger = MemoryFallbackInvocationLedger::default();
        let mut claim = claim_selection(&lease, &mut ledger);
        let replay_claim = claim.clone();
        let mut dispatcher =
            MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));
        assert_eq!(
            service.dispatch_once(
                &mut claim,
                &primary_outcome,
                &lease.composition.alternate,
                &snapshot(&lease, "quota-v1", 3),
                &mut dispatcher,
                &mut ledger,
                now(),
            ),
            Err(CapabilityFallbackInvocationError::Recovery(
                FallbackInvocationRecoveryDisposition::NoFurtherFallback { result_digest },
            ))
        );
        assert_eq!(dispatcher.calls, 1);
        assert_eq!(ledger.len(), 3);
        assert_eq!(
            ledger
                .state_for(lease.decision_digest())
                .expect("ledger state"),
            Some(FallbackInvocationState::Failed)
        );
        assert_eq!(
            service.dispatch_once(
                &mut replay_claim.clone(),
                &primary_outcome,
                &lease.composition.alternate,
                &snapshot(&lease, "quota-v1", 3),
                &mut dispatcher,
                &mut ledger,
                now(),
            ),
            Err(CapabilityFallbackInvocationError::DuplicateDispatch)
        );
        assert_eq!(dispatcher.calls, 1);
    }
}

fn assert_receipt_identity(
    receipt: &hartevo_capability_gateway::CapabilityFallbackInvocationReceipt,
    lease: &hartevo_capability_gateway::CapabilityFallbackLease,
) {
    assert_eq!(receipt.fallback_attempt, 1);
    assert_eq!(
        receipt.capability_digest,
        lease.composition.primary.invocation.capability_digest
    );
    assert_eq!(
        receipt.service_digest,
        lease.composition.primary.invocation.service_digest
    );
    assert_eq!(
        receipt.primary_binding_digest,
        lease.composition.primary.digest()
    );
    assert_eq!(
        receipt.primary_provider_digest,
        lease.composition.primary.provider_digest
    );
    assert_eq!(
        receipt.alternate_provider_digest,
        lease.composition.alternate.provider_digest
    );
    assert_eq!(
        receipt.prior_result_digest,
        lease.primary_outcome.result_digest
    );
    assert_eq!(
        receipt.policy_digest,
        lease.composition.primary.invocation.policy_digest
    );
    assert_eq!(receipt.mission_generation, 7);
    assert_eq!(receipt.mission_revision, 11);
    assert_eq!(receipt.invocation_revision, 4);
}

#[test]
fn uncertain_external_dispatch_is_reconcile_only_and_never_retried() {
    let (lease, primary_outcome, _degradation_log) =
        selected(CapabilityClass::ExternalEffect, "external-once", 10);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let mut claim = claim_selection(&lease, &mut ledger);
    let replay_claim = claim.clone();
    let mut dispatcher = MockDispatcher::responding(DispatcherResponse::Error(
        FallbackDispatchError::UncertainExternalEffect {
            effect_digest: digest("effect-uncertain"),
            reconciliation_digest: digest("reconcile-uncertain"),
        },
    ));
    assert_eq!(
        CapabilityFallbackInvocationConsumer::new().dispatch_once(
            &mut claim,
            &primary_outcome,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::Recovery(
            FallbackInvocationRecoveryDisposition::UncertainExternalEffect {
                effect_digest: digest("effect-uncertain"),
                reconciliation_digest: digest("reconcile-uncertain"),
            },
        ))
    );
    assert_eq!(
        claim.status,
        hartevo_capability_gateway::FallbackInvocationClaimStatus::Terminal
    );
    assert_eq!(dispatcher.calls, 1);
    assert_eq!(
        ledger
            .state_for(lease.decision_digest())
            .expect("ledger state"),
        Some(FallbackInvocationState::UncertainExternalEffect)
    );
    assert_eq!(
        CapabilityFallbackInvocationConsumer::new().dispatch_once(
            &mut replay_claim.clone(),
            &primary_outcome,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        ),
        Err(CapabilityFallbackInvocationError::DuplicateDispatch)
    );
    assert_eq!(dispatcher.calls, 1);
}

#[test]
fn invocation_ledger_roundtrip_is_content_free_and_preserves_exact_receipt_refs() {
    let (lease, primary_outcome, _degradation_log) =
        selected(CapabilityClass::Read, "roundtrip", 2);
    let mut ledger = MemoryFallbackInvocationLedger::default();
    let mut claim = claim_selection(&lease, &mut ledger);
    let fallback_result = result(&lease, CapabilityClass::Read, "roundtrip-result", 3);
    let mut dispatcher =
        MockDispatcher::responding(DispatcherResponse::Result(Box::new(fallback_result)));
    let receipt = CapabilityFallbackInvocationConsumer::new()
        .dispatch_once(
            &mut claim,
            &primary_outcome,
            &lease.composition.alternate,
            &snapshot(&lease, "quota-v1", 3),
            &mut dispatcher,
            &mut ledger,
            now(),
        )
        .expect("complete fallback invocation");
    assert_eq!(receipt.validate(), Ok(()));
    let receipt_roundtrip =
        serde_json::from_slice::<hartevo_capability_gateway::CapabilityFallbackInvocationReceipt>(
            &serde_json::to_vec(&receipt).expect("serialize invocation receipt"),
        )
        .expect("deserialize invocation receipt");
    assert_eq!(receipt_roundtrip, receipt);
    let encoded = serde_json::to_vec(&ledger).expect("serialize invocation ledger");
    let decoded: MemoryFallbackInvocationLedger =
        serde_json::from_slice(&encoded).expect("deserialize invocation ledger");
    assert_eq!(decoded, ledger);
    let events = decoded.events_for(lease.decision_digest());
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, FallbackInvocationEventKind::Claimed);
    assert_eq!(events[1].kind, FallbackInvocationEventKind::DispatchStarted);
    assert_eq!(events[2].kind, FallbackInvocationEventKind::Completed);
    assert_eq!(events[2].fallback_attempt, 1);
    assert_receipt_identity(&receipt, &lease);
    assert_eq!(
        events[2].alternate_binding_digest,
        lease.composition.alternate.digest()
    );
    assert_eq!(
        events[2].prior_outcome_digest,
        lease.primary_outcome.digest()
    );
    assert_eq!(events[2].result_digest, Some(receipt.result_digest.clone()));
    assert_eq!(
        receipt.project_digest,
        digest(
            lease
                .composition
                .primary
                .invocation
                .project
                .project_id
                .as_str()
        )
    );
    assert_eq!(
        receipt.mission_digest,
        digest(
            lease
                .composition
                .primary
                .invocation
                .mission
                .mission_id
                .as_str()
        )
    );
    assert_eq!(
        events[2].scope_digest.clone(),
        lease.composition.primary.invocation.mission.scope_digest
    );
    let debug = format!("{decoded:?} {receipt:?} {:?}", events[2]);
    assert!(!debug.contains("tenant-a"));
    assert!(!debug.contains("project-a"));
    assert!(!debug.contains("primary-provider"));
    assert!(debug.contains("selection_digest"));
    assert!(debug.contains("alternate_binding_digest"));
}
