use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_datadog_slo_outcome_plugin::{
    AccessMode, AllowlistedMonitorTag, BlockedEnvDatadogSloTransport, CorrectionMetadata,
    CorrectionPolicy, DATADOG_SLO_OUTCOME_CONTRACT_JSON, DATADOG_SLO_OUTCOME_SCHEMA_VERSION,
    DATADOG_SLO_PROVIDER_ID, DatadogPermission, DatadogReadOperation, DatadogSloError,
    DatadogSloOutcomePluginDefinition, DatadogSloProvider, DatadogSloScope, DatadogSloScopeSpec,
    DatadogSloState, DatadogSloTransport, DatadogTransportError, DowntimeMetadata, DowntimePolicy,
    EvidenceError, EvidenceProjection, FakeDatadogSloTransport, FixtureDatadogSloTransport,
    LoopbackDatadogSloTransport, MISSION_SLO_OUTCOME_CONSUMER_ID, MissionSloOutcomeConsumer,
    MonitorDetail, MonitorTransition, MonitorTransitionEvidence, MonitorTransitionState,
    ObservationReceiptStatus, ObservationWindow, PermissionSnapshot, PluginVersion, RecordedFault,
    RecordingDatadogSloTransport, RegistrationStatus, SLO_OUTCOME_EVIDENCE_SERVICE_ID, SliPoint,
    SliPointState, SloDefinition, SloHistory, SloQueryForm, SloSnapshot, SloStatusSnapshot,
    SloThreshold, SloTimeframe, SloType, TransportProvenance, sha256_digest,
};

const SITE: &str = "us1";
const API_HOST: &str = "https://api.datadoghq.com";
const ORGANIZATION: &str = "org-test";
const SLO_ID: &str = "slo-release-health";

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

fn window() -> ObservationWindow {
    ObservationWindow::closed(at("2026-08-14T00:00:00Z"), at("2026-08-14T00:15:00Z"))
        .expect("closed window")
}

fn fingerprint(label: &str) -> String {
    sha256_digest(label.as_bytes())
}

fn snapshot_for(slo_type: SloType) -> SloSnapshot {
    let definition = match slo_type {
        SloType::Metric => SloDefinition::Metric {
            numerator_fingerprint: fingerprint("metric-numerator"),
            denominator_fingerprint: fingerprint("metric-denominator"),
            group_by: vec!["service".into(), "env".into()],
        },
        SloType::Monitor => SloDefinition::Monitor {
            monitor_ids: vec!["monitor-1".into()],
            group_ids: vec!["group-prod".into()],
        },
        SloType::TimeSlice => SloDefinition::TimeSlice {
            good_slice_fingerprint: fingerprint("good-time-slice"),
            bad_slice_fingerprint: fingerprint("bad-time-slice"),
        },
    };
    SloSnapshot::new(
        SITE,
        API_HOST,
        ORGANIZATION,
        SLO_ID,
        Some(fingerprint("slo-name")),
        definition,
        99.0,
        Some(99.5),
        vec![SloThreshold::new(SloTimeframe::ThirtyDays, 99.0, Some(99.5)).expect("threshold")],
    )
    .expect("snapshot")
}

fn scope_for(
    slo_type: SloType,
) -> (
    DatadogSloScope,
    hartevo_datadog_slo_outcome_plugin::SecretReference,
) {
    let snapshot = snapshot_for(slo_type);
    let secret = hartevo_datadog_slo_outcome_plugin::SecretReference::oauth(
        "opaque-datadog-secret-handle",
        7,
    )
    .expect("opaque secret reference");
    let permissions = PermissionSnapshot::least_privilege(
        &secret,
        SITE,
        API_HOST,
        ORGANIZATION,
        slo_type == SloType::Monitor,
    )
    .expect("permission snapshot");
    let scope = DatadogSloScope::new(
        DatadogSloScopeSpec {
            site: SITE.into(),
            api_host: API_HOST.into(),
            organization_id: ORGANIZATION.into(),
            slo_id: SLO_ID.into(),
            slo_type,
            definition_digest: snapshot.definition_digest,
            query: snapshot.definition.as_query_form(),
            target: 99.0,
            warning: Some(99.5),
            error_budget_timeframe: SloTimeframe::ThirtyDays,
            error_budget_target: 99.0,
            correction_policy: CorrectionPolicy::Exclude,
            downtime_policy: DowntimePolicy::Surface,
            project_id: "project-release".into(),
            deployment: hartevo_datadog_slo_outcome_plugin::DeploymentBinding::new(
                "deployment-2026-08-14",
                4,
            )
            .expect("deployment"),
            release: hartevo_datadog_slo_outcome_plugin::ReleaseBinding::new(
                "release-2026-08-14",
                9,
            )
            .expect("release"),
            mission: hartevo_datadog_slo_outcome_plugin::MissionBinding::new("mission-1", 12)
                .expect("mission"),
            policy_revision: 3,
            permission_snapshot: permissions,
        },
        &secret,
    )
    .expect("scope");
    (scope, secret)
}

fn monitor_details(snapshot: &SloSnapshot) -> Vec<MonitorDetail> {
    snapshot
        .monitor_ids()
        .into_iter()
        .map(|monitor_id| {
            MonitorDetail::new(
                monitor_id,
                "metric_alert",
                fingerprint("monitor-query"),
                snapshot.group_ids(),
                vec![AllowlistedMonitorTag::new("service", "checkout").expect("tag")],
                MonitorTransitionState::Uptime,
            )
            .expect("monitor detail")
        })
        .collect()
}

fn response_for(
    snapshot: &SloSnapshot,
    observation_window: &ObservationWindow,
    state: DatadogSloState,
    expected_points: u32,
    points: Vec<SliPoint>,
    history_errors: Vec<EvidenceError>,
    transitions: Vec<MonitorTransition>,
    correction_policy: CorrectionPolicy,
    corrected: bool,
    downtime_policy: DowntimePolicy,
    downtime_ids: Vec<String>,
) -> hartevo_datadog_slo_outcome_plugin::DatadogSloReadResponse {
    let history = SloHistory::new(
        observation_window.clone(),
        expected_points,
        points,
        history_errors.clone(),
        corrected,
    )
    .expect("history");
    let status = SloStatusSnapshot::new(
        observation_window.clone(),
        state,
        Some(99.9),
        60,
        SloTimeframe::ThirtyDays,
        Some(88.0),
        Some(86_400.0),
        snapshot.target,
        snapshot.warning,
        history_errors,
    )
    .expect("status");
    let monitor_transitions = MonitorTransitionEvidence::new(
        observation_window.clone(),
        transitions,
        snapshot.monitor_ids(),
        snapshot.group_ids(),
    )
    .expect("transitions");
    let corrections = CorrectionMetadata::new(
        correction_policy,
        corrected,
        if corrected {
            vec!["correction-1".into()]
        } else {
            Vec::new()
        },
        observation_window.clone(),
    )
    .expect("corrections");
    let downtime = DowntimeMetadata::new(
        downtime_policy,
        !downtime_ids.is_empty(),
        downtime_ids,
        observation_window.clone(),
    )
    .expect("downtime");
    hartevo_datadog_slo_outcome_plugin::DatadogSloReadResponse::new(
        snapshot.clone(),
        history,
        status,
        monitor_details(snapshot),
        monitor_transitions,
        corrections,
        downtime,
    )
    .expect("response")
}

fn healthy_points(observation_window: &ObservationWindow) -> Vec<SliPoint> {
    vec![
        SliPoint::new(
            observation_window.from,
            SliPointState::Good,
            Some(99.9),
            None,
            None,
        )
        .expect("point"),
    ]
}

fn provider_for(
    slo_type: SloType,
    response: hartevo_datadog_slo_outcome_plugin::DatadogSloReadResponse,
) -> (
    DatadogSloProvider<LoopbackDatadogSloTransport>,
    DatadogSloScope,
    ObservationWindow,
) {
    let (scope, secret) = scope_for(slo_type);
    let transport = LoopbackDatadogSloTransport::from_response(response);
    let provider = DatadogSloProvider::new(transport, scope.clone(), secret, 1)
        .expect("provider registration");
    (provider, scope, window())
}

#[test]
fn contract_and_registration_are_version_digest_scope_bound_and_reversible() {
    let definition = DatadogSloOutcomePluginDefinition::layer1().expect("definition");
    assert_eq!(
        definition.schema_version,
        DATADOG_SLO_OUTCOME_SCHEMA_VERSION
    );
    assert_eq!(definition.version, PluginVersion::V1);
    assert_eq!(definition.plugin_id, DATADOG_SLO_PROVIDER_ID);
    assert_eq!(definition.service.id, SLO_OUTCOME_EVIDENCE_SERVICE_ID);
    assert_eq!(definition.service.access, AccessMode::ReadOnly);
    assert_eq!(definition.consumer.id, MISSION_SLO_OUTCOME_CONSUMER_ID);
    assert!(!definition.writes);
    assert!(!definition.arbitrary_queries);
    assert!(!definition.native);
    assert_eq!(
        definition.contract_digest,
        sha256_digest(DATADOG_SLO_OUTCOME_CONTRACT_JSON.as_bytes())
    );

    let (scope, secret) = scope_for(SloType::Metric);
    let registration = definition.bind(scope.clone(), 11).expect("registration");
    registration
        .validate(&definition, &scope)
        .expect("registration validates");
    assert_eq!(registration.status, RegistrationStatus::Active);
    assert_eq!(registration.scope_digest, scope.digest());
    assert_eq!(
        registration.permission_digest,
        scope.permission_snapshot.digest()
    );
    assert_eq!(
        secret.kind(),
        hartevo_datadog_slo_outcome_plugin::SecretKind::OAuth
    );

    let revoked = {
        let mut registration = registration;
        registration.revoke()
    };
    assert_eq!(revoked.status, RegistrationStatus::Revoked);
    assert_eq!(revoked.registration_revision, 11);
}

#[test]
fn opaque_secret_and_monitor_tag_boundaries_never_serialize_raw_handles() {
    let secret =
        hartevo_datadog_slo_outcome_plugin::SecretReference::app_key("opaque-app-key-handle", 2)
            .expect("app key");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-app-key-handle"));
    assert!(debug.contains("redacted"));
    assert_eq!(
        secret.kind(),
        hartevo_datadog_slo_outcome_plugin::SecretKind::ApplicationKey
    );

    assert!(AllowlistedMonitorTag::new("query", "raw metric query").is_err());
    let tag = AllowlistedMonitorTag::new("env", "production").expect("allowlisted tag");
    let serialized = serde_json::to_string(&tag).expect("tag serializes");
    assert!(serialized.contains("production"));
    assert!(!serialized.contains("raw metric query"));
}

#[test]
fn metric_time_slice_and_monitor_query_forms_are_typed_and_bounded() {
    for slo_type in [SloType::Metric, SloType::Monitor, SloType::TimeSlice] {
        let snapshot = snapshot_for(slo_type);
        snapshot.validate().expect("snapshot validates");
        assert_eq!(snapshot.slo_type, slo_type);
        assert_eq!(snapshot.query_digest, snapshot.definition.query_digest());
        assert_eq!(snapshot.definition.as_query_form().slo_type(), slo_type);
    }

    let arbitrary = SloQueryForm::TimeSlice {
        good_slice_fingerprint: "not-a-digest".into(),
        bad_slice_fingerprint: fingerprint("bad"),
    };
    assert!(arbitrary.validate().is_err());
}

#[test]
fn metric_vertical_slice_compiles_reads_records_verifies_and_proposes_mission_evidence() {
    let snapshot = snapshot_for(SloType::Metric);
    let observation_window = window();
    let response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (provider, scope, _) = provider_for(SloType::Metric, response);
    let proposal = provider
        .compile_observation_proposal(observation_window)
        .expect("observation proposal");
    let evidence = provider.read_slo_evidence(&proposal).expect("evidence");
    assert_eq!(evidence.projection, EvidenceProjection::Healthy);
    assert_eq!(
        evidence.classification,
        hartevo_datadog_slo_outcome_plugin::EvidenceClassification::Loopback
    );
    assert!(!evidence.native);
    assert!(!evidence.connected);
    assert!(!evidence.absence_is_success);

    let receipt = provider
        .record_observation_receipt(evidence)
        .expect("recorded receipt");
    assert_eq!(receipt.status, ObservationReceiptStatus::Recorded);
    assert!(!receipt.durable);
    let verification = provider
        .verify_outcome_evidence(&receipt)
        .expect("verification");
    assert!(verification.verified);
    assert!(!verification.native);
    assert!(!verification.connected);
    assert!(!verification.adoptable);

    let consumer = MissionSloOutcomeConsumer;
    let outcome = consumer
        .consume(&receipt, &verification)
        .expect("Mission proposal");
    outcome.validate().expect("outcome proposal");
    assert_eq!(outcome.projection, EvidenceProjection::Healthy);
    assert_eq!(outcome.mission.id, scope.mission.id);
    assert!(!outcome.absence_is_success);
    assert!(!outcome.native);
    assert!(!outcome.connected);
}

#[test]
fn monitor_without_transitions_is_no_data_not_healthy() {
    let snapshot = snapshot_for(SloType::Monitor);
    let observation_window = window();
    let response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (provider, _, _) = provider_for(SloType::Monitor, response);
    let proposal = provider
        .compile_observation_proposal(observation_window)
        .expect("proposal");
    let evidence = provider.read_slo_evidence(&proposal).expect("evidence");
    assert_eq!(evidence.projection, EvidenceProjection::NoData);
    assert!(evidence.sli.no_data);
    assert!(!evidence.sli.complete);
}

#[test]
fn monitor_transition_correction_and_downtime_projections_remain_explicit() {
    let snapshot = snapshot_for(SloType::Monitor);
    let observation_window = window();
    let uptime_transition = vec![
        MonitorTransition::new(
            "monitor-1",
            Some("group-prod".into()),
            observation_window.from,
            MonitorTransitionState::Uptime,
        )
        .expect("uptime transition"),
    ];
    let corrected_response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        uptime_transition.clone(),
        CorrectionPolicy::Apply,
        true,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (mut scope, secret) = scope_for(SloType::Monitor);
    scope.correction_policy = CorrectionPolicy::Apply;
    let provider = DatadogSloProvider::new(
        LoopbackDatadogSloTransport::from_response(corrected_response),
        scope,
        secret,
        1,
    )
    .expect("corrected provider");
    let proposal = provider
        .compile_observation_proposal(observation_window.clone())
        .expect("proposal");
    let evidence = provider
        .read_slo_evidence(&proposal)
        .expect("corrected evidence");
    assert_eq!(evidence.projection, EvidenceProjection::Corrected);
    assert!(evidence.corrections.applied);
    assert!(evidence.monitor_transitions.has_observation());

    let downtime_response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        vec![
            MonitorTransition::new(
                "monitor-1",
                Some("group-prod".into()),
                observation_window.from,
                MonitorTransitionState::Downtime,
            )
            .expect("downtime transition"),
        ],
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        vec!["downtime-1".into()],
    );
    let (provider, _, _) = provider_for(SloType::Monitor, downtime_response);
    let proposal = provider
        .compile_observation_proposal(observation_window)
        .expect("proposal");
    let evidence = provider
        .read_slo_evidence(&proposal)
        .expect("downtime evidence");
    assert_eq!(evidence.projection, EvidenceProjection::Downtime);
    assert!(evidence.downtime.active);
}

#[test]
fn no_data_partial_and_error_bearing_history_never_become_healthy() {
    let snapshot = snapshot_for(SloType::Metric);
    let observation_window = window();

    let no_data_response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::NoData,
        1,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (provider, _, _) = provider_for(SloType::Metric, no_data_response);
    let proposal = provider
        .compile_observation_proposal(observation_window.clone())
        .expect("proposal");
    assert_eq!(
        provider
            .read_slo_evidence(&proposal)
            .expect("no-data evidence")
            .projection,
        EvidenceProjection::NoData
    );

    let partial_response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        2,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (provider, _, _) = provider_for(SloType::Metric, partial_response);
    let proposal = provider
        .compile_observation_proposal(observation_window.clone())
        .expect("proposal");
    assert_eq!(
        provider
            .read_slo_evidence(&proposal)
            .expect("partial evidence")
            .projection,
        EvidenceProjection::Partial
    );

    let error =
        EvidenceError::new("history_partial", Some(200), "provider detail").expect("bounded error");
    let error_response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        vec![error],
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (provider, _, _) = provider_for(SloType::Metric, error_response);
    let proposal = provider
        .compile_observation_proposal(observation_window)
        .expect("proposal");
    assert_eq!(
        provider
            .read_slo_evidence(&proposal)
            .expect("error evidence")
            .projection,
        EvidenceProjection::Partial
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn target_warning_and_error_budget_mismatches_fail_closed() {
    let snapshot = snapshot_for(SloType::Metric);
    let observation_window = window();
    let base = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );

    let mismatched_target = SloStatusSnapshot::new(
        observation_window.clone(),
        DatadogSloState::Ok,
        Some(99.9),
        60,
        SloTimeframe::ThirtyDays,
        Some(88.0),
        Some(86_400.0),
        98.0,
        snapshot.warning,
        Vec::new(),
    )
    .expect("mismatched target status");
    let response = replace_status(base, mismatched_target);
    let (provider, _, _) = provider_for(SloType::Metric, response);
    let proposal = provider
        .compile_observation_proposal(observation_window.clone())
        .expect("proposal");
    assert_eq!(
        provider.read_slo_evidence(&proposal).unwrap_err(),
        DatadogSloError::TargetMismatch
    );

    let base = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let mismatched_warning = SloStatusSnapshot::new(
        observation_window.clone(),
        DatadogSloState::Ok,
        Some(99.9),
        60,
        SloTimeframe::ThirtyDays,
        Some(88.0),
        Some(86_400.0),
        snapshot.target,
        None,
        Vec::new(),
    )
    .expect("mismatched warning status");
    let response = replace_status(base, mismatched_warning);
    let (provider, _, _) = provider_for(SloType::Metric, response);
    let proposal = provider
        .compile_observation_proposal(observation_window.clone())
        .expect("proposal");
    assert_eq!(
        provider.read_slo_evidence(&proposal).unwrap_err(),
        DatadogSloError::WarningMismatch
    );

    let base = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let mismatched_budget = SloStatusSnapshot::new(
        observation_window.clone(),
        DatadogSloState::Ok,
        Some(99.9),
        60,
        SloTimeframe::SevenDays,
        Some(88.0),
        Some(86_400.0),
        snapshot.target,
        snapshot.warning,
        Vec::new(),
    )
    .expect("mismatched budget status");
    let response = replace_status(base, mismatched_budget);
    let (provider, _, _) = provider_for(SloType::Metric, response);
    let proposal = provider
        .compile_observation_proposal(observation_window)
        .expect("proposal");
    assert_eq!(
        provider.read_slo_evidence(&proposal).unwrap_err(),
        DatadogSloError::ErrorBudgetMismatch
    );
}

fn replace_status(
    response: hartevo_datadog_slo_outcome_plugin::DatadogSloReadResponse,
    status: SloStatusSnapshot,
) -> hartevo_datadog_slo_outcome_plugin::DatadogSloReadResponse {
    hartevo_datadog_slo_outcome_plugin::DatadogSloReadResponse::new(
        response.snapshot,
        response.history,
        status,
        response.monitors,
        response.monitor_transitions,
        response.corrections,
        response.downtime,
    )
    .expect("response replacement")
}

#[test]
fn response_tamper_and_registration_revocation_fail_closed() {
    let snapshot = snapshot_for(SloType::Metric);
    let observation_window = window();
    let response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    )
    .tampered();
    let (provider, _, _) = provider_for(SloType::Metric, response);
    let proposal = provider
        .compile_observation_proposal(observation_window.clone())
        .expect("proposal");
    assert_eq!(
        provider.read_slo_evidence(&proposal).unwrap_err(),
        DatadogSloError::ResponseTampered
    );

    let response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (provider, _, _) = provider_for(SloType::Metric, response);
    provider.revoke().expect("revocation");
    assert_eq!(
        provider
            .compile_observation_proposal(observation_window)
            .unwrap_err(),
        DatadogSloError::RegistrationRevoked
    );
}

#[test]
fn receipt_tamper_and_mission_consumer_binding_fail_closed() {
    let snapshot = snapshot_for(SloType::Metric);
    let observation_window = window();
    let response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (provider, _, _) = provider_for(SloType::Metric, response);
    let proposal = provider
        .compile_observation_proposal(observation_window)
        .expect("proposal");
    let evidence = provider.read_slo_evidence(&proposal).expect("evidence");
    let mut receipt = provider
        .record_observation_receipt(evidence)
        .expect("receipt");
    receipt.receipt_digest = "0".repeat(64);
    assert_eq!(
        provider.verify_outcome_evidence(&receipt).unwrap_err(),
        DatadogSloError::ReceiptTampered
    );
}

#[test]
fn transport_faults_are_explicit_and_can_project_provider_unknown() {
    let faults = vec![
        (
            RecordedFault::Unauthorized401,
            DatadogTransportError::Unauthorized401,
        ),
        (
            RecordedFault::Forbidden403,
            DatadogTransportError::Forbidden403,
        ),
        (
            RecordedFault::NotFound404,
            DatadogTransportError::NotFound404,
        ),
        (
            RecordedFault::RateLimited429 {
                retry_after_seconds: Some(9),
            },
            DatadogTransportError::RateLimited429 {
                retry_after_seconds: Some(9),
            },
        ),
        (RecordedFault::Timeout, DatadogTransportError::Timeout),
        (
            RecordedFault::Server5xx { status: 503 },
            DatadogTransportError::Server5xx { status: 503 },
        ),
        (
            RecordedFault::SiteMismatch,
            DatadogTransportError::SiteMismatch,
        ),
        (
            RecordedFault::PublicBetaDrift,
            DatadogTransportError::PublicBetaDrift,
        ),
    ];

    for (fault, expected) in faults {
        let (scope, secret) = scope_for(SloType::Metric);
        let transport = LoopbackDatadogSloTransport::empty();
        transport.push_fault(fault);
        let provider = DatadogSloProvider::new(transport, scope, secret, 1).expect("provider");
        let proposal = provider
            .compile_observation_proposal(window())
            .expect("proposal");
        assert_eq!(
            provider.read_slo_evidence(&proposal).unwrap_err(),
            DatadogSloError::Transport(expected.clone())
        );
        let unknown = MissionSloOutcomeConsumer
            .provider_unknown(
                &proposal,
                provider
                    .registration()
                    .expect("registration")
                    .registration_digest,
                &expected,
            )
            .expect("provider unknown proposal");
        assert_eq!(unknown.projection, EvidenceProjection::ProviderUnknown);
        assert!(!unknown.native);
        assert!(!unknown.connected);
        assert!(unknown.blocker_code.is_some());
    }
}

#[test]
fn blocked_env_and_recording_family_never_claim_connected_or_native() {
    let snapshot = snapshot_for(SloType::Metric);
    let observation_window = window();
    let response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );

    let provenances = [
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Fixture,
        TransportProvenance::Loopback,
    ];
    assert!(
        provenances
            .iter()
            .all(|provenance| { !provenance.is_native() && !provenance.is_connected() })
    );
    assert!(!BlockedEnvDatadogSloTransport.provenance().is_native());
    assert!(!BlockedEnvDatadogSloTransport.provenance().is_connected());

    let transports = [
        RecordingDatadogSloTransport::from_response(response.clone()).provenance(),
        FakeDatadogSloTransport::from_response(response.clone()).provenance(),
        FixtureDatadogSloTransport::from_response(response.clone()).provenance(),
        LoopbackDatadogSloTransport::from_response(response).provenance(),
    ];
    assert!(
        transports
            .iter()
            .all(|provenance| !provenance.is_native() && !provenance.is_connected())
    );

    let (scope, secret) = scope_for(SloType::Metric);
    let provider = DatadogSloProvider::new(BlockedEnvDatadogSloTransport, scope, secret, 1)
        .expect("blocked-env provider");
    let proposal = provider
        .compile_observation_proposal(observation_window)
        .expect("blocked-env proposal");
    assert_eq!(
        provider.read_slo_evidence(&proposal).unwrap_err(),
        DatadogSloError::Transport(DatadogTransportError::BlockedEnv)
    );
}

#[test]
fn read_request_is_exactly_site_org_slo_query_monitor_and_window_fenced() {
    let snapshot = snapshot_for(SloType::Metric);
    let observation_window = window();
    let response = response_for(
        &snapshot,
        &observation_window,
        DatadogSloState::Ok,
        1,
        healthy_points(&observation_window),
        Vec::new(),
        Vec::new(),
        CorrectionPolicy::Exclude,
        false,
        DowntimePolicy::Surface,
        Vec::new(),
    );
    let (scope, secret) = scope_for(SloType::Metric);
    let transport = RecordingDatadogSloTransport::from_response(response);
    let provider =
        DatadogSloProvider::new(transport.clone(), scope.clone(), secret, 1).expect("provider");
    let proposal = provider
        .compile_observation_proposal(observation_window.clone())
        .expect("proposal");
    provider.read_slo_evidence(&proposal).expect("evidence");
    let request = transport.requests().pop().expect("recorded request");
    request.validate().expect("request validates");
    assert_eq!(request.operation, DatadogReadOperation::ReadSloEvidence);
    assert_eq!(request.site, scope.site);
    assert_eq!(request.api_host, scope.api_host);
    assert_eq!(request.organization_id, scope.organization_id);
    assert_eq!(request.slo_id, scope.slo_id);
    assert_eq!(request.definition_digest, scope.definition_digest);
    assert_eq!(request.query_digest, scope.query_digest);
    assert_eq!(request.window, Some(observation_window));
    assert!(request.monitor_ids.is_empty());
    assert!(request.group_ids.is_empty());
}

#[test]
fn permission_snapshot_is_least_privilege_and_monitor_reads_need_monitor_permission() {
    let secret =
        hartevo_datadog_slo_outcome_plugin::SecretReference::oauth("secret", 1).expect("secret");
    let permissions = PermissionSnapshot::new(
        secret.kind(),
        BTreeSet::from([DatadogPermission::SlosRead]),
        SITE,
        API_HOST,
        ORGANIZATION,
        1,
    )
    .expect("metric permissions");
    assert!(permissions.has(DatadogPermission::SlosRead));
    assert!(!permissions.has(DatadogPermission::MonitorsRead));

    let snapshot = snapshot_for(SloType::Monitor);
    let result = DatadogSloScope::new(
        DatadogSloScopeSpec {
            site: SITE.into(),
            api_host: API_HOST.into(),
            organization_id: ORGANIZATION.into(),
            slo_id: SLO_ID.into(),
            slo_type: SloType::Monitor,
            definition_digest: snapshot.definition_digest,
            query: snapshot.definition.as_query_form(),
            target: 99.0,
            warning: Some(99.5),
            error_budget_timeframe: SloTimeframe::ThirtyDays,
            error_budget_target: 99.0,
            correction_policy: CorrectionPolicy::Exclude,
            downtime_policy: DowntimePolicy::Surface,
            project_id: "project".into(),
            deployment: hartevo_datadog_slo_outcome_plugin::DeploymentBinding::new("deploy", 1)
                .expect("deployment"),
            release: hartevo_datadog_slo_outcome_plugin::ReleaseBinding::new("release", 1)
                .expect("release"),
            mission: hartevo_datadog_slo_outcome_plugin::MissionBinding::new("mission", 1)
                .expect("mission"),
            policy_revision: 1,
            permission_snapshot: permissions,
        },
        &secret,
    );
    assert!(matches!(
        result,
        Err(DatadogSloError::InvalidPermissionSnapshot)
    ));
}
