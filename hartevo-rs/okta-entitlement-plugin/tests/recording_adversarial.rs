use std::collections::BTreeSet;

use chrono::{Duration, TimeZone, Utc};
use hartevo_okta_entitlement_plugin::{
    AccessChangeOperation, AccessChangeProposal, AdminResourceSet, AssignmentKind, AssignmentState,
    AssignmentTarget, CapabilityOperation, CapabilityRegistration, ConsentReference,
    EntitlementBinding, EntitlementEvidenceStatus, EntitlementSnapshot, LogAvailability,
    MissionOktaEntitlementConsumer, OAuthServiceAppGrant, OktaApplicationId, OktaApplicationRecord,
    OktaEntitlementError, OktaEntitlementEvidenceService, OktaEntitlementProvider, OktaGroupId,
    OktaGroupRecord, OktaScope, OktaTargetId, OktaUserId, OktaUserRecord, PROVIDER_API_REVISION,
    PROVIDER_ID, Provenance, ReadBounds, RecordingDataset, RecordingFault, SecretReference,
    ServiceAppAuthentication, SystemLogEvent, SystemLogWindowRequest,
};

fn at_start() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
        .single()
        .expect("fixture time")
}

fn digest(letter: char) -> String {
    std::iter::repeat_n(letter, 64).collect()
}

fn full_scopes() -> BTreeSet<String> {
    BTreeSet::from([
        "okta.apps.read".to_owned(),
        "okta.groups.read".to_owned(),
        "okta.logs.read".to_owned(),
        "okta.users.read".to_owned(),
    ])
}

fn fixture_scope() -> OktaScope {
    OktaScope::new(
        "org-okta-fixture-1",
        "https://example.okta.com/",
        "client-okta-fixture-1",
        full_scopes(),
        digest('a'),
        "project-okta-1",
        "mission-okta-1",
        7,
        ConsentReference::new("consent-okta-1", 3).expect("consent"),
    )
    .expect("scope")
}

fn fixture_grant(scope: &OktaScope) -> OAuthServiceAppGrant {
    let secret = SecretReference::new("secret-ref-okta-fixture-1", scope.digest(), 1)
        .expect("opaque secret reference");
    OAuthServiceAppGrant::new(
        scope.service_app_client_id.clone(),
        scope.granted_scopes.clone(),
        AdminResourceSet::new(
            "resource-set-okta-1",
            scope.admin_resource_set_digest.clone(),
        )
        .expect("resource set"),
        PROVIDER_API_REVISION,
        ServiceAppAuthentication::private_key_jwt(secret),
    )
    .expect("grant")
}

fn fixture_service(
    fault: Option<RecordingFault>,
) -> (
    OktaEntitlementEvidenceService,
    OktaScope,
    chrono::DateTime<Utc>,
) {
    let scope = fixture_scope();
    let now = at_start();
    let mut dataset = RecordingDataset::for_scope(&scope, now);
    dataset.assignments = vec![fixture_assignment(now)];
    let dataset = fault.map_or(dataset.clone(), |fault| dataset.with_fault(fault));
    let provider = OktaEntitlementProvider::from_recording(dataset).expect("recording provider");
    let service = OktaEntitlementEvidenceService::register(
        provider,
        "registration-okta-fixture-1",
        scope.clone(),
        fixture_grant(&scope),
    )
    .expect("registered service");
    (service, scope, now)
}

fn fixture_user() -> OktaUserRecord {
    OktaUserRecord::new(
        OktaUserId::new("00u-fixture-user-1").expect("user id"),
        "ACTIVE",
        digest('b'),
    )
    .expect("user")
}

fn fixture_group() -> OktaGroupRecord {
    OktaGroupRecord::new(
        OktaGroupId::new("00g-fixture-group-1").expect("group id"),
        digest('c'),
    )
    .expect("group")
}

fn fixture_application() -> OktaApplicationRecord {
    OktaApplicationRecord::new(
        OktaApplicationId::new("0oa-fixture-app-1").expect("application id"),
        "ACTIVE",
        digest('d'),
    )
    .expect("application")
}

fn fixture_assignment(now: chrono::DateTime<Utc>) -> EntitlementBinding {
    EntitlementBinding::new(
        OktaApplicationId::new("0oa-fixture-app-1").expect("application id"),
        OktaTargetId::User(OktaUserId::new("00u-fixture-user-1").expect("user id")),
        AssignmentKind::Direct,
        AssignmentState::Assigned,
        PROVIDER_API_REVISION,
        now,
        digest('e'),
    )
    .expect("assignment")
}

fn fixture_event(now: chrono::DateTime<Utc>, id: &str) -> SystemLogEvent {
    SystemLogEvent::new(
        id,
        "application.user_assignment.add",
        now - Duration::minutes(5),
        now - Duration::minutes(4),
        vec![OktaTargetId::User(
            OktaUserId::new("00u-fixture-user-1").expect("user id"),
        )],
        hartevo_okta_entitlement_plugin::LogOutcome::Success,
        digest('f'),
    )
    .expect("System Log event")
}

#[test]
fn contract_and_typed_seams_are_external_evidence_only() {
    let contract: serde_json::Value =
        serde_json::from_str(hartevo_okta_entitlement_plugin::CONTRACT_JSON).expect("contract");
    assert_eq!(
        contract["pluginId"],
        hartevo_okta_entitlement_plugin::PLUGIN_ID
    );
    assert_eq!(contract["connected"], false);
    assert_eq!(contract["native"], false);
    assert_eq!(contract["authentication"]["sswsConstruction"], false);

    let (service, _, _) = fixture_service(None);
    let description = service.describe_capabilities();
    assert!(description.read_only);
    assert!(!description.connected);
    assert!(!description.native);
    assert!(!description.mutation_authority);
    assert_eq!(description.provider_id, PROVIDER_ID);
    assert!(
        description
            .operations
            .contains(&CapabilityOperation::ReadEntitlementSnapshot)
    );
    assert_eq!(Provenance::Recording.status(), "recording_evidence");
    assert!(!Provenance::Recording.is_connected());
    assert!(!Provenance::Recording.is_native());
}

#[test]
fn private_key_jwt_is_opaque_and_ssws_construction_is_rejected() {
    let scope = fixture_scope();
    let secret = SecretReference::new("secret-ref-okta-debug-1", scope.digest(), 9)
        .expect("secret reference");
    let auth = ServiceAppAuthentication::private_key_jwt(secret);
    assert_eq!(auth.method(), "private_key_jwt");
    assert!(ServiceAppAuthentication::try_from_ssws_token("ssws-secret-value").is_err());

    let grant = fixture_grant(&scope);
    let debug = format!("{grant:?}");
    assert!(!debug.contains("ssws-secret-value"));
    assert!(!debug.contains("private-jwk-bytes"));
    assert!(!debug.contains("jwt-assertion-bytes"));
    assert!(debug.contains("secret-ref-okta-fixture-1"));
}

#[test]
fn names_and_emails_cannot_be_used_as_immutable_provider_ids() {
    assert!(OktaUserId::new("alice@example.com").is_err());
    assert!(OktaUserId::new("alice").is_err());
    assert!(OktaGroupId::new("Engineering").is_err());
    assert!(OktaApplicationId::new("Payroll").is_err());
    assert!(OktaUserId::new("00u-real-immutable-id").is_ok());
}

#[test]
fn registration_is_scope_grant_digest_bound_reversible_and_revocable() {
    let (mut service, _, now) = fixture_service(None);
    assert!(service.registration().is_active());
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service.registration().state,
        hartevo_okta_entitlement_plugin::RegistrationState::Reversed
    );
    assert!(matches!(
        service.read_entitlement_snapshot(now),
        Err(OktaEntitlementError::RegistrationInactive)
    ));
    service.restore_registration().expect("restore");
    service
        .read_entitlement_snapshot(now)
        .expect("restored registration reads");
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.registration().state,
        hartevo_okta_entitlement_plugin::RegistrationState::Revoked
    );
    assert!(service.restore_registration().is_err());
}

#[test]
fn recording_snapshot_is_immutable_id_based_and_canonical_across_reordering() {
    let scope = fixture_scope();
    let now = at_start();
    let mut first_dataset = RecordingDataset::for_scope(&scope, now);
    first_dataset.users = vec![fixture_user()];
    first_dataset.groups = vec![fixture_group()];
    first_dataset.applications = vec![fixture_application()];
    first_dataset.assignments = vec![fixture_assignment(now)];
    let mut second_dataset = first_dataset.clone();
    second_dataset.fault = Some(RecordingFault::ReorderedAssignments);

    let service = |dataset| {
        OktaEntitlementEvidenceService::register(
            OktaEntitlementProvider::from_recording(dataset).expect("provider"),
            "registration-okta-order-1",
            scope.clone(),
            fixture_grant(&scope),
        )
        .expect("service")
    };
    let mut first = service(first_dataset);
    let mut second = service(second_dataset);
    let first_snapshot = first
        .read_entitlement_snapshot(now)
        .expect("first snapshot");
    let second_snapshot = second
        .read_entitlement_snapshot(now)
        .expect("reordered snapshot");
    assert_eq!(
        first_snapshot.snapshot_digest,
        second_snapshot.snapshot_digest
    );
    assert!(first_snapshot.current_state_is_direct_read());
    assert_eq!(
        first_snapshot.direct_read.direct_read_revision,
        "direct-read-1"
    );
    assert_eq!(first_snapshot.users[0].id.as_str(), "00u-fixture-user-1");
    let serialized = serde_json::to_string(&first_snapshot).expect("snapshot JSON");
    assert!(!serialized.contains("alice@example.com"));
    assert!(!serialized.contains("rawProfile"));
}

#[test]
fn pagination_and_additive_schema_fields_are_safe_and_bounded() {
    let scope = fixture_scope();
    let now = at_start();
    let mut dataset = RecordingDataset::for_scope(&scope, now);
    dataset.users = (0..101)
        .map(|index| {
            OktaUserRecord::new(
                OktaUserId::new(format!("00u-page-user-{index:03}")).expect("user id"),
                "ACTIVE",
                digest('b'),
            )
            .expect("user")
        })
        .collect();
    let mut paged_service = OktaEntitlementEvidenceService::register(
        OktaEntitlementProvider::from_recording(dataset.clone()).expect("provider"),
        "registration-okta-pagination-1",
        scope.clone(),
        fixture_grant(&scope),
    )
    .expect("service");
    let snapshot = paged_service
        .read_entitlement_snapshot(now)
        .expect("two-page snapshot");
    assert_eq!(snapshot.users.len(), 101);
    assert_eq!(snapshot.direct_read.pages, 2);

    let additive_dataset = dataset.with_fault(RecordingFault::AdditiveField);
    let mut additive_service = OktaEntitlementEvidenceService::register(
        OktaEntitlementProvider::from_recording(additive_dataset).expect("provider"),
        "registration-okta-additive-1",
        scope.clone(),
        fixture_grant(&scope),
    )
    .expect("service");
    assert_eq!(
        additive_service
            .read_entitlement_snapshot(now)
            .expect("additive fields tolerated")
            .users
            .len(),
        101
    );

    let bounded_error = paged_service.read_entitlement_snapshot_with_bounds(
        now,
        ReadBounds {
            page_size: 1,
            max_pages: 1,
            ..ReadBounds::default()
        },
    );
    assert_eq!(
        bounded_error.expect_err("page bound ignored"),
        OktaEntitlementError::BoundsExceeded
    );
}

#[test]
fn registration_and_grant_digest_tampering_is_detected() {
    let scope = fixture_scope();
    let grant = fixture_grant(&scope);
    let mut registration =
        CapabilityRegistration::new("registration-okta-tamper-1", scope.clone(), &grant)
            .expect("registration");
    registration.scope_digest = digest('z');
    assert!(registration.verify_integrity().is_err());

    let mut altered_grant = fixture_grant(&scope);
    altered_grant
        .granted_scopes
        .insert("okta.profile.read".to_owned());
    assert!(
        CapabilityRegistration::new("registration-okta-grant-tamper-1", scope, &altered_grant,)
            .is_err()
    );
}

#[test]
fn duplicate_disagreement_stale_and_response_bound_recordings_fail_closed() {
    for (fault, expected) in [
        (
            RecordingFault::DuplicateAssignment,
            OktaEntitlementError::DuplicateAssignment,
        ),
        (
            RecordingFault::AssignmentDisagreement,
            OktaEntitlementError::AssignmentDisagreement,
        ),
        (
            RecordingFault::StaleDirectRead,
            OktaEntitlementError::DirectReadRevisionDrift,
        ),
        (
            RecordingFault::ResponseTooLarge,
            OktaEntitlementError::BoundsExceeded,
        ),
    ] {
        let (mut service, _, now) = fixture_service(Some(fault));
        let result = service.read_entitlement_snapshot(now);
        assert_eq!(
            result.expect_err("adversarial recording succeeded"),
            expected
        );
    }
}

#[test]
fn permission_rate_schema_and_cross_org_recordings_are_typed_provider_errors() {
    for fault in [
        RecordingFault::PermissionDenied,
        RecordingFault::RateLimited {
            retry_after_seconds: 3,
        },
        RecordingFault::RequiredFieldDrift {
            field: "assignments".to_owned(),
        },
        RecordingFault::CrossOrgRedirect,
    ] {
        let (mut service, _, now) = fixture_service(Some(fault.clone()));
        let error = service
            .probe_registration(now)
            .expect_err("provider fault was not surfaced");
        match (fault, error) {
            (
                RecordingFault::PermissionDenied
                | RecordingFault::RateLimited { .. }
                | RecordingFault::RequiredFieldDrift { .. }
                | RecordingFault::CrossOrgRedirect,
                OktaEntitlementError::Provider(_),
            ) => {}
            _ => panic!("unexpected provider error shape"),
        }
    }
}

#[test]
fn system_log_is_bounded_historical_supplemental_and_retention_safe() {
    let scope = fixture_scope();
    let now = at_start();
    let mut dataset = RecordingDataset::for_scope(&scope, now);
    dataset.system_log_events = vec![fixture_event(now, "event-okta-1")];
    let mut service = OktaEntitlementEvidenceService::register(
        OktaEntitlementProvider::from_recording(dataset).expect("provider"),
        "registration-okta-log-1",
        scope.clone(),
        fixture_grant(&scope),
    )
    .expect("service");
    let snapshot = service.read_entitlement_snapshot(now).expect("snapshot");
    let request = SystemLogWindowRequest::bounded(&scope, now - Duration::hours(1), now);
    let log = service
        .read_system_log_window(request)
        .expect("bounded log");
    assert_eq!(log.events.len(), 1);
    assert!(log.is_supplemental_only());
    let evidence = service
        .verify_entitlement_evidence(snapshot, Some(log))
        .expect("evidence");
    evidence.verify_integrity().expect("evidence digest");
    assert_eq!(
        evidence.status,
        EntitlementEvidenceStatus::DirectReadWithSupplementalLog
    );
    assert_eq!(evidence.current_state_source, "direct_entitlement_read");
    assert!(evidence.system_log_is_supplemental);
    assert!(!evidence.connected);
    assert!(!evidence.native);

    let old_request =
        SystemLogWindowRequest::bounded(&scope, now - Duration::days(30), now - Duration::days(29));
    let unavailable = service
        .read_system_log_window(old_request)
        .expect("retention gap is evidence, not an error");
    assert!(matches!(
        unavailable.availability,
        LogAvailability::Unavailable { .. }
    ));
}

#[test]
fn polling_since_and_bounded_provider_after_are_distinct_and_cursor_is_opaque() {
    let scope = fixture_scope();
    let now = at_start();
    let mut dataset = RecordingDataset::for_scope(&scope, now);
    dataset.system_log_events = vec![
        fixture_event(now, "event-okta-1"),
        fixture_event(now, "event-okta-2"),
    ];
    let mut provider = OktaEntitlementProvider::from_recording(dataset).expect("provider");
    let bounded = SystemLogWindowRequest::bounded(&scope, now - Duration::hours(1), now)
        .with_bounds(1, hartevo_okta_entitlement_plugin::MAX_RESPONSE_BYTES);
    let page = provider
        .read_system_log_page(&bounded)
        .expect("bounded page");
    let after = page.next_after.as_ref().expect("provider after cursor");
    let polling_with_bounded_cursor =
        SystemLogWindowRequest::polling(&scope, now - Duration::hours(1)).with_after(after);
    assert!(matches!(
        provider.read_system_log_page(&polling_with_bounded_cursor),
        Err(hartevo_okta_entitlement_plugin::ProviderError::CursorInvalid)
    ));
    assert!(after.digest().len() == 64);
}

#[test]
fn opaque_cursor_tampering_and_missing_page_are_not_silently_recovered() {
    for fault in [
        RecordingFault::OpaqueCursorTampered,
        RecordingFault::MissingPage,
    ] {
        let scope = fixture_scope();
        let now = at_start();
        let mut dataset = RecordingDataset::for_scope(&scope, now).with_fault(fault.clone());
        dataset.system_log_events = vec![
            fixture_event(now, "event-okta-1"),
            fixture_event(now, "event-okta-2"),
        ];
        let mut service = OktaEntitlementEvidenceService::register(
            OktaEntitlementProvider::from_recording(dataset).expect("provider"),
            "registration-okta-cursor-1",
            scope.clone(),
            fixture_grant(&scope),
        )
        .expect("service");
        let request = SystemLogWindowRequest::bounded(&scope, now - Duration::hours(1), now)
            .with_bounds(1, hartevo_okta_entitlement_plugin::MAX_RESPONSE_BYTES);
        let result = service.read_system_log_window(request);
        match fault {
            RecordingFault::OpaqueCursorTampered => assert!(matches!(
                result,
                Err(OktaEntitlementError::Provider(
                    hartevo_okta_entitlement_plugin::ProviderError::CursorInvalid
                ))
            )),
            RecordingFault::MissingPage => {
                assert_eq!(
                    result.expect_err("missing page silently accepted"),
                    OktaEntitlementError::IncompleteSnapshot
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn access_change_proposal_is_canonical_non_mutating_and_mission_fenced() {
    let (mut service, scope, now) = fixture_service(None);
    let snapshot = service.read_entitlement_snapshot(now).expect("snapshot");
    let proposal = service
        .compile_access_change_proposal(
            AccessChangeOperation::Assign {
                application_id: OktaApplicationId::new("0oa-fixture-app-1").expect("app"),
                target: AssignmentTarget::User(
                    OktaUserId::new("00u-fixture-user-1").expect("user"),
                ),
            },
            snapshot.snapshot_digest.clone(),
        )
        .expect("proposal");
    assert!(proposal.is_non_mutating());
    proposal.verify_integrity().expect("proposal digest");
    assert!(!proposal.provider_execution);
    assert!(proposal.requires_layer2_effect);
    assert_eq!(proposal.scope_digest, scope.digest());

    let proposal_again = service
        .compile_access_change_proposal(
            AccessChangeOperation::Assign {
                application_id: OktaApplicationId::new("0oa-fixture-app-1").expect("app"),
                target: AssignmentTarget::User(
                    OktaUserId::new("00u-fixture-user-1").expect("user"),
                ),
            },
            snapshot.snapshot_digest,
        )
        .expect("same proposal");
    assert_eq!(proposal.fingerprint, proposal_again.fingerprint);

    let bad_mission = hartevo_okta_entitlement_plugin::MissionScope::new(
        scope.project_id.clone(),
        scope.mission_id.clone(),
        scope.mission_revision + 1,
        scope.consent.clone(),
    )
    .expect("different mission revision");
    let mut consumer = MissionOktaEntitlementConsumer::new(service);
    assert!(matches!(
        consumer.inspect_entitlements(&bad_mission, now),
        Err(OktaEntitlementError::MissionScopeMismatch)
    ));
    assert!(!consumer.is_connected());
    assert!(!consumer.is_native());
}

#[test]
fn blocked_env_provenance_never_becomes_connected_or_native() {
    let scope = fixture_scope();
    let provider = OktaEntitlementProvider::blocked_env("real Okta service app is unavailable");
    let service = OktaEntitlementEvidenceService::register(
        provider,
        "registration-okta-blocked-1",
        scope.clone(),
        fixture_grant(&scope),
    )
    .expect("service registration is local");
    let description = service.describe_capabilities();
    assert_eq!(description.provenance, Provenance::BlockedEnv);
    assert!(!description.connected);
    assert!(!description.native);
    let error = service.provider().provenance();
    assert_eq!(error, Provenance::BlockedEnv);
}

#[test]
fn bounds_reject_unbounded_pages_and_contract_has_no_mutation_surface() {
    let (mut service, _, now) = fixture_service(None);
    assert!(
        ReadBounds {
            page_size: 101,
            ..ReadBounds::default()
        }
        .validate()
        .is_err()
    );
    let error = service
        .read_entitlement_snapshot_with_bounds(
            now,
            ReadBounds {
                page_size: 101,
                ..ReadBounds::default()
            },
        )
        .expect_err("unbounded page accepted");
    assert!(matches!(error, OktaEntitlementError::Model(_)));
    let contract = hartevo_okta_entitlement_plugin::CONTRACT_JSON;
    assert!(!contract.contains("assign_user"));
    assert!(!contract.contains("mint_live_token\": true"));
}

#[allow(dead_code)]
fn _typed_api_smoke(_proposal: AccessChangeProposal, _snapshot: EntitlementSnapshot) {}
