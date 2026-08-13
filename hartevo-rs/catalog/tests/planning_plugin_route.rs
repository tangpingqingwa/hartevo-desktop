use std::collections::BTreeSet;

use chrono::{Duration, TimeZone, Utc};
use hartevo_catalog::{
    CapabilityRouteProposal, MissionPlanningConsumer, PlanDeclineReason, PlanLogEvent,
    PlanReplanReason, PlanningCancellation, PlanningError, PlanningObjective, PlanningProvider,
    PlanningProviderDescriptor, PlanningProviderError, PlanningProviderRegistration,
    PlanningProviderRoute, PlanningReplanRequest, PlanningRouteStep, PlanningScope,
    PlanningService, ProviderLifecycleState, ScopedProviderRegistry,
};

const IMPLEMENTATION_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MISSION_CONTRACT_DIGEST: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Debug)]
struct TestPlanningProvider {
    descriptor: PlanningProviderDescriptor,
    estimated_budget_units: u32,
}

impl PlanningProvider for TestPlanningProvider {
    fn descriptor(&self) -> PlanningProviderDescriptor {
        self.descriptor.clone()
    }

    fn propose_route(
        &self,
        objective: &PlanningObjective,
        _registration: &PlanningProviderRegistration,
    ) -> Result<PlanningProviderRoute, PlanningProviderError> {
        let step = PlanningRouteStep::new(
            "observe-0",
            0,
            objective.requested_capability.clone(),
            "observe",
        )
        .map_err(|_| PlanningProviderError::InvalidRoute)?;
        PlanningProviderRoute::new(
            "read-only-observation",
            objective.requested_capability.clone(),
            vec![step],
            self.estimated_budget_units,
        )
        .map_err(|_| PlanningProviderError::InvalidRoute)
    }
}

struct Fixture {
    now: chrono::DateTime<Utc>,
    scope: PlanningScope,
    provider: TestPlanningProvider,
    registry: ScopedProviderRegistry,
    registration: PlanningProviderRegistration,
    objective: PlanningObjective,
    service: PlanningService,
}

fn fixture() -> Fixture {
    let now = Utc
        .with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
        .single()
        .expect("fixed test timestamp");
    let capability = capability("mission.observe");
    let scope = PlanningScope::new("project-01", "mission-01", 7, MISSION_CONTRACT_DIGEST)
        .expect("valid planning scope");
    let descriptor = PlanningProviderDescriptor::new(
        "planning-provider-01",
        "1.2.3",
        IMPLEMENTATION_DIGEST,
        BTreeSet::from([capability.clone()]),
    )
    .expect("valid provider descriptor");
    let provider = TestPlanningProvider {
        descriptor,
        estimated_budget_units: 3,
    };
    let mut registry = ScopedProviderRegistry::new(scope.clone()).expect("valid registry");
    let registration = registry
        .register_provider(&provider, now)
        .expect("provider registration");
    let objective = PlanningObjective::new(
        "objective-01",
        scope.clone(),
        "private objective text must never enter the durable planning log",
        capability,
        now + Duration::minutes(5),
        10,
    )
    .expect("valid objective");
    let service = PlanningService::new(scope.clone()).expect("planning service");
    Fixture {
        now,
        scope,
        provider,
        registry,
        registration,
        objective,
        service,
    }
}

fn capability(value: &str) -> hartevo_catalog::PlanningCapabilityId {
    hartevo_catalog::PlanningCapabilityId::new(value).expect("valid capability")
}

fn plan(fixture: &mut Fixture) -> CapabilityRouteProposal {
    fixture
        .service
        .plan(
            &fixture.objective,
            &fixture.registry,
            &fixture.provider,
            &PlanningCancellation::active(),
            fixture.now,
        )
        .expect("bounded route proposal")
}

#[test]
fn objective_provider_consumer_closes_a_revision_bound_durable_route() {
    let mut fixture = fixture();
    let proposal = plan(&mut fixture);
    assert_eq!(proposal.scope.mission_revision, 7);
    assert_eq!(proposal.provider_version, "1.2.3");
    assert_eq!(proposal.provider_registration_digest.len(), 64);
    assert!(
        proposal
            .capability_availability_snapshot
            .contains(&proposal.capability_id)
    );
    assert!(proposal.steps.iter().all(|step| step.read_only));
    let proposal_wire = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!proposal_wire.contains("effectAuthority"));

    let mut log = fixture.service.into_plan_log();
    assert_eq!(log.entries.len(), 2);
    log.validate().expect("valid durable planning log");
    let wire = serde_json::to_string(&log).expect("planning log JSON");
    assert!(!wire.contains("private objective text"));
    let round_trip: hartevo_catalog::DurablePlanLog =
        serde_json::from_str(&wire).expect("planning log round trip");
    assert_eq!(round_trip, log);

    let dispatch = MissionPlanningConsumer
        .dispatch(
            &proposal,
            &fixture.scope,
            &fixture.registry,
            &mut log,
            fixture.now,
        )
        .expect("Mission accepts proposal");
    assert!(!dispatch.replayed);
    assert_eq!(dispatch.scope, fixture.scope);
    assert_eq!(
        dispatch.capability_snapshot_digest,
        proposal.capability_availability_snapshot.snapshot_digest
    );
    assert_eq!(log.entries.len(), 3);
    assert!(matches!(
        log.entries.last().map(|entry| &entry.event),
        Some(PlanLogEvent::PlanAccepted { record, .. })
            if record.provider_version == "1.2.3"
                && record.provider_implementation_digest == IMPLEMENTATION_DIGEST
                && record.mission_revision == 7
    ));
    log.validate().expect("dispatch is durably chained");
}

#[test]
fn planning_and_dispatch_replay_are_idempotent_and_deduplicated() {
    let mut fixture = fixture();
    let first = plan(&mut fixture);
    let second = plan(&mut fixture);
    assert_eq!(first, second);
    let mut log = fixture.service.into_plan_log();
    assert_eq!(log.entries.len(), 2);

    let consumer = MissionPlanningConsumer;
    let initial = consumer
        .dispatch(
            &first,
            &fixture.scope,
            &fixture.registry,
            &mut log,
            fixture.now,
        )
        .expect("initial dispatch");
    let replay = consumer
        .dispatch(
            &first,
            &fixture.scope,
            &fixture.registry,
            &mut log,
            fixture.now,
        )
        .expect("idempotent dispatch replay");
    assert!(!initial.replayed);
    assert!(replay.replayed);
    assert_eq!(initial.dispatch_id, replay.dispatch_id);
    assert_eq!(log.entries.len(), 3);
    log.validate().expect("replay remains durably valid");
}

#[test]
fn unmount_revoke_and_crash_fence_old_proposals() {
    let transitions = [
        (
            ProviderLifecycleState::Unmounted,
            ScopedProviderRegistry::unmount_provider
                as fn(
                    &mut ScopedProviderRegistry,
                    &str,
                    u64,
                    chrono::DateTime<Utc>,
                ) -> Result<PlanningProviderRegistration, PlanningError>,
        ),
        (
            ProviderLifecycleState::Revoked,
            ScopedProviderRegistry::revoke_provider,
        ),
        (
            ProviderLifecycleState::Crashed,
            ScopedProviderRegistry::crash_provider,
        ),
    ];

    for (expected_state, transition) in transitions {
        let mut fixture = fixture();
        let proposal = plan(&mut fixture);
        let mut log = fixture.service.into_plan_log();
        transition(
            &mut fixture.registry,
            &fixture.registration.registration_id,
            fixture.registration.lifecycle_revision,
            fixture.now + Duration::seconds(1),
        )
        .expect("lifecycle transition");
        let result = MissionPlanningConsumer.dispatch(
            &proposal,
            &fixture.scope,
            &fixture.registry,
            &mut log,
            fixture.now + Duration::seconds(1),
        );
        assert!(matches!(
            result,
            Err(PlanningError::CapabilityAvailabilityDrift)
        ));
        assert_eq!(log.entries.len(), 3);
        assert!(matches!(
            log.entries.last().map(|entry| &entry.event),
            Some(PlanLogEvent::PlanDeclined { record, .. })
                if record.reason == PlanDeclineReason::CapabilityAvailabilityDrift
                    && expected_state != ProviderLifecycleState::Active
        ));
    }
}

#[test]
fn unknown_capability_and_provider_descriptor_drift_fail_closed() {
    let mut fixture = fixture();
    fixture.objective = PlanningObjective::new(
        "objective-unknown",
        fixture.scope.clone(),
        "private unknown capability request",
        capability("mission.not-registered"),
        fixture.now + Duration::minutes(5),
        10,
    )
    .expect("valid unknown capability objective");
    let unknown = fixture.service.plan(
        &fixture.objective,
        &fixture.registry,
        &fixture.provider,
        &PlanningCancellation::active(),
        fixture.now,
    );
    assert!(matches!(
        unknown,
        Err(PlanningError::UnknownCapability(capability)) if capability == "mission.not-registered"
    ));

    let mut drifted_provider = fixture.provider.clone();
    drifted_provider.descriptor.provider_version = "2.0.0".into();
    fixture.objective = PlanningObjective::new(
        "objective-drifted-provider",
        fixture.scope.clone(),
        "private provider version drift",
        capability("mission.observe"),
        fixture.now + Duration::minutes(5),
        10,
    )
    .expect("valid provider drift objective");
    let drift = fixture.service.plan(
        &fixture.objective,
        &fixture.registry,
        &drifted_provider,
        &PlanningCancellation::active(),
        fixture.now,
    );
    assert!(matches!(
        drift,
        Err(PlanningError::ProviderDescriptorMismatch)
    ));
}

#[test]
fn capability_disappearance_records_decline_and_replan_replays_replacement() {
    let mut fixture = fixture();
    let previous = plan(&mut fixture);
    let mut log = fixture.service.clone().into_plan_log();
    fixture
        .registry
        .unmount_provider(
            &fixture.registration.registration_id,
            fixture.registration.lifecycle_revision,
            fixture.now + Duration::seconds(1),
        )
        .expect("provider disappearance");

    let declined = MissionPlanningConsumer.dispatch(
        &previous,
        &fixture.scope,
        &fixture.registry,
        &mut log,
        fixture.now + Duration::seconds(1),
    );
    assert!(matches!(
        declined,
        Err(PlanningError::CapabilityAvailabilityDrift)
    ));
    assert!(matches!(
        log.entries.last().map(|entry| &entry.event),
        Some(PlanLogEvent::PlanDeclined { record, .. })
            if record.reason == PlanDeclineReason::CapabilityAvailabilityDrift
    ));

    let mut replacement_provider = fixture.provider.clone();
    replacement_provider.descriptor.provider_version = "2.0.0".into();
    replacement_provider.descriptor.implementation_digest = "c".repeat(64);
    fixture
        .registry
        .register_provider(&replacement_provider, fixture.now + Duration::seconds(2))
        .expect("replacement provider registration");

    let mut service = PlanningService::from_plan_log(log).expect("restore durable planning log");
    let request = PlanningReplanRequest {
        objective: &fixture.objective,
        previous_proposal: &previous,
        cancellation: &PlanningCancellation::active(),
        reason: PlanReplanReason::CapabilityAvailabilityChanged,
        now: fixture.now + Duration::seconds(2),
    };
    let replacement = service
        .replan(&request, &fixture.registry, &replacement_provider)
        .expect("replacement route proposal");
    assert_ne!(replacement.proposal_id, previous.proposal_id);
    assert_eq!(replacement.provider_version, "2.0.0");
    assert_ne!(
        replacement.capability_availability_snapshot.snapshot_digest,
        previous.capability_availability_snapshot.snapshot_digest
    );

    let replay = service
        .plan(
            &fixture.objective,
            &fixture.registry,
            &replacement_provider,
            &PlanningCancellation::active(),
            fixture.now + Duration::seconds(2),
        )
        .expect("replan replay");
    assert_eq!(replay, replacement);

    let mut log = service.into_plan_log();
    assert!(log.entries.iter().any(|entry| {
        matches!(
            &entry.event,
            PlanLogEvent::PlanReplanned { record, .. }
                if record.previous_proposal_id == previous.proposal_id
                    && record.replacement_proposal_id == replacement.proposal_id
        )
    }));
    let accepted = MissionPlanningConsumer
        .dispatch(
            &replacement,
            &fixture.scope,
            &fixture.registry,
            &mut log,
            fixture.now + Duration::seconds(2),
        )
        .expect("replacement plan acceptance");
    assert!(!accepted.replayed);
    let wire = serde_json::to_string(&log).expect("durable replan log JSON");
    assert!(!wire.contains("effectAuthority"));
    log.validate().expect("valid decline/replan/acceptance log");
}

#[test]
fn consumer_rechecks_provider_binding_and_mission_revision_before_replay() {
    let mut binding_fixture = fixture();
    let proposal = plan(&mut binding_fixture);
    let mut log = binding_fixture.service.clone().into_plan_log();
    binding_fixture
        .registry
        .registrations
        .get_mut(&binding_fixture.registration.registration_id)
        .expect("registered provider")
        .descriptor
        .provider_version = "9.9.9".into();
    let binding_drift = MissionPlanningConsumer.dispatch(
        &proposal,
        &binding_fixture.scope,
        &binding_fixture.registry,
        &mut log,
        binding_fixture.now,
    );
    assert!(matches!(
        binding_drift,
        Err(PlanningError::RegistrationDigestMismatch)
    ));
    assert!(matches!(
        log.entries.last().map(|entry| &entry.event),
        Some(PlanLogEvent::PlanDeclined { record, .. })
            if record.reason == PlanDeclineReason::ProviderBindingDrift
    ));

    let mut revision_fixture = fixture();
    let proposal = plan(&mut revision_fixture);
    let mut revision_scope = revision_fixture.scope.clone();
    revision_scope.mission_revision += 1;
    let mut revision_log = revision_fixture.service.clone().into_plan_log();
    let revision_drift = MissionPlanningConsumer.dispatch(
        &proposal,
        &revision_scope,
        &revision_fixture.registry,
        &mut revision_log,
        revision_fixture.now,
    );
    assert!(matches!(
        revision_drift,
        Err(PlanningError::ScopeMismatch { .. })
    ));
    assert!(matches!(
        revision_log.entries.last().map(|entry| &entry.event),
        Some(PlanLogEvent::PlanDeclined { record, .. })
            if record.reason == PlanDeclineReason::MissionRevisionDrift
    ));
}

#[test]
fn route_drift_scope_drift_deadline_budget_and_cancel_are_fenced() {
    let mut first_fixture = fixture();
    let mut proposal = plan(&mut first_fixture);
    let mut log = first_fixture.service.clone().into_plan_log();
    proposal.steps[0].operation = "mutated-route".into();
    let route_drift = MissionPlanningConsumer.dispatch(
        &proposal,
        &first_fixture.scope,
        &first_fixture.registry,
        &mut log,
        first_fixture.now,
    );
    assert!(matches!(route_drift, Err(PlanningError::RouteDrift)));
    assert!(matches!(
        log.entries.last().map(|entry| &entry.event),
        Some(PlanLogEvent::PlanDeclined { record, .. })
            if record.reason == PlanDeclineReason::RouteDrift
    ));

    let mut revision_drift = first_fixture.scope.clone();
    revision_drift.mission_revision += 1;
    let original = plan(&mut first_fixture);
    let mut original_log = first_fixture.service.into_plan_log();
    let scope_drift = MissionPlanningConsumer.dispatch(
        &original,
        &revision_drift,
        &first_fixture.registry,
        &mut original_log,
        first_fixture.now,
    );
    assert!(matches!(
        scope_drift,
        Err(PlanningError::ScopeMismatch { .. })
    ));

    let mut expired = fixture();
    expired.objective = PlanningObjective::new(
        "objective-expired",
        expired.scope.clone(),
        "private expired request",
        capability("mission.observe"),
        expired.now - Duration::seconds(1),
        10,
    )
    .expect("expired objective shape");
    let deadline = expired.service.plan(
        &expired.objective,
        &expired.registry,
        &expired.provider,
        &PlanningCancellation::active(),
        expired.now,
    );
    assert!(matches!(deadline, Err(PlanningError::DeadlineExceeded)));

    let mut cancelled = fixture();
    let cancel = cancelled.service.plan(
        &cancelled.objective,
        &cancelled.registry,
        &cancelled.provider,
        &PlanningCancellation::cancelled(4),
        cancelled.now,
    );
    assert!(matches!(
        cancel,
        Err(PlanningError::Cancelled { revision: 4 })
    ));

    let mut over_budget = fixture();
    over_budget.provider.estimated_budget_units = 11;
    let budget = over_budget.service.plan(
        &over_budget.objective,
        &over_budget.registry,
        &over_budget.provider,
        &PlanningCancellation::active(),
        over_budget.now,
    );
    assert!(matches!(budget, Err(PlanningError::BudgetExceeded)));
}
