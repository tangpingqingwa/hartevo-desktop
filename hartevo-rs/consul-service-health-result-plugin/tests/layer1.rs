use hartevo_consul_service_health_result_plugin::{
    AuthorityBoundary, BlockedEnvTransport, CheckStatus, ConsulHealthProvider, ConsulHttpResponse,
    ConsulServiceHealthResultService, Digest, EvidenceStatus, FixtureTransport,
    MissionConsulServiceHealthConsumer, PermissionScope, Project, ProviderDefinition,
    ProviderProvenance, RawCatalogServiceEntry, RawCheck, RawHealthServiceEntry, RawNode,
    RawService, ReadBounds, Revision, Scope, SecretReference, ServiceError, TransportError,
    TransportFailure, VerificationState, WorkProduct,
};

fn scope() -> Scope {
    let project = Project::new("project-consul-layer1", 3).expect("project");
    let mission = hartevo_consul_service_health_result_plugin::Mission::new("mission-consul", 7)
        .expect("mission");
    let work_product = WorkProduct::new("work-product-consul", 2).expect("work product");
    Scope::new(
        "https://consul.example.invalid:8501",
        "dc1",
        "default",
        "payments",
        project,
        mission,
        work_product,
        PermissionScope::for_layer_one(),
    )
    .expect("scope")
    .with_tag("stable")
    .expect("tag scope")
}

fn entries(scope: &Scope, status: &str) -> (RawHealthServiceEntry, RawCatalogServiceEntry) {
    let mut node = RawNode::new(
        "node-a",
        "payments-a",
        "10.0.0.7",
        scope.datacenter.as_str(),
    );
    node.tagged_addresses
        .insert("lan".to_owned(), "10.0.0.7".to_owned());
    node.meta
        .insert("classification".to_owned(), "secret".to_owned());
    node.create_index = 10;
    node.modify_index = 11;

    let mut service = RawService::new(
        "payments-instance-a",
        scope.service.as_str(),
        vec!["stable".to_owned(), "zone-a".to_owned()],
        "10.0.0.8",
        8443,
    );
    scope.namespace.as_str().clone_into(&mut service.namespace);
    scope
        .admin_partition
        .as_str()
        .clone_into(&mut service.partition);
    service
        .meta
        .insert("owner".to_owned(), "sensitive-owner".to_owned());
    service
        .tagged_addresses
        .insert("wan".to_owned(), "10.0.0.8".to_owned());

    let mut check = RawCheck::new("check-http", "HTTP health", status);
    "do not expose this note".clone_into(&mut check.notes);
    "private output".clone_into(&mut check.output);
    check.service_id.clone_from(&service.id);
    check.service_name.clone_from(&service.service);
    check.service_tags.clone_from(&service.tags);
    check.create_index = 10;
    check.modify_index = 11;

    let health = RawHealthServiceEntry::new(node.clone(), service.clone(), vec![check]);
    let catalog = RawCatalogServiceEntry::new(node, service);
    (health, catalog)
}

fn fixture_service(
    scope: Scope,
    health: ConsulHttpResponse,
    catalog: ConsulHttpResponse,
) -> ConsulServiceHealthResultService<FixtureTransport> {
    let transport = FixtureTransport::with_responses([Ok(health), Ok(catalog)]);
    let definition =
        ProviderDefinition::new(&scope, ProviderProvenance::Fixture).expect("provider definition");
    let provider = ConsulHealthProvider::new(transport, definition).expect("provider");
    ConsulServiceHealthResultService::new(scope, provider).expect("service")
}

#[test]
fn bounded_read_is_deterministic_redacted_and_get_only() {
    let scope = scope();
    let (health_entry, catalog_entry) = entries(&scope, "passing");
    let health = ConsulHttpResponse::health(vec![health_entry], 42);
    let catalog = ConsulHttpResponse::catalog(vec![catalog_entry], 42);
    let mut service = fixture_service(scope.clone(), health, catalog);
    let first = service
        .read(ReadBounds::default(), 1_700_000_000)
        .expect("read");

    assert_eq!(first.evidence.status, EvidenceStatus::Passing);
    assert_eq!(first.evidence.instances.len(), 1);
    assert!(first.evidence.is_review_complete());
    assert_eq!(first.evidence.authority, AuthorityBoundary::layer_one());
    assert!(!first.evidence.connected);
    assert!(!first.evidence.native);
    assert!(!first.evidence.first_party);
    assert!(first.evidence.redaction.addresses_and_ports_redacted);
    assert!(first.evidence.redaction.notes_and_output_redacted);
    assert!(first.evidence.redaction.metadata_values_redacted);
    assert_eq!(
        first.evidence.instances[0].checks[0].status,
        CheckStatus::Passing
    );

    let serialized = serde_json::to_string(&first.evidence).expect("redacted evidence JSON");
    assert!(!serialized.contains("10.0.0.8"));
    assert!(!serialized.contains("8443"));
    assert!(!serialized.contains("do not expose this note"));
    assert!(!serialized.contains("sensitive-owner"));
    assert!(
        !first
            .proposal
            .evidence
            .instances
            .iter()
            .any(|instance| instance.tags.iter().any(|tag| tag == "private output"))
    );

    let calls = service.provider().transport().calls();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|call| call.method == hartevo_consul_service_health_result_plugin::HttpMethod::Get));
    assert!(calls.iter().all(|call| !call.contains_secret_material()));
    assert_eq!(calls[0].path, "/v1/health/service/payments");
    assert_eq!(calls[1].path, "/v1/catalog/service/payments");
    assert!(calls[0].query_string().contains("dc=dc1"));
    assert!(calls[0].query_string().contains("partition=default"));
    assert!(calls[0].query_string().contains("ns=default"));
    assert!(calls[0].query_string().contains("tag=stable"));
}

#[test]
fn secret_reference_is_opaque_and_registration_is_bound_reversible_and_revocable() {
    let scope = scope();
    let secret = SecretReference::new(
        "keyring/consul/acl-token",
        &scope,
        Revision::new(4).unwrap(),
    )
    .expect("opaque secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("keyring/consul/acl-token"));
    assert!(debug.contains(secret.reference_digest().as_str()));
    assert!(secret.validate_for_scope(&scope).is_ok());
    assert!(
        serde_json::to_string(&scope)
            .unwrap()
            .contains("scopeDigest")
    );

    let (health_entry, catalog_entry) = entries(&scope, "passing");
    let mut service = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry], 8),
        ConsulHttpResponse::catalog(vec![catalog_entry], 8),
    );
    let original_registration_digest = service.registration().registration_digest.clone();
    let result = service.read(ReadBounds::default(), 10).expect("read");
    assert_ne!(
        service.registration().registration_digest,
        original_registration_digest
    );
    assert_eq!(
        service.registration().evidence_digest,
        Some(result.evidence.evidence_digest.clone())
    );
    service.revoke().expect("revoke");
    assert_eq!(
        service.registration().state,
        hartevo_consul_service_health_result_plugin::RegistrationState::Revoked
    );
    service.restore().expect("restore");
    assert!(service.is_active());
    assert_ne!(
        service.registration().registration_digest,
        original_registration_digest
    );
}

#[test]
fn consumer_keeps_partial_review_only_and_rejects_stale_replay_and_revocation() {
    let scope = scope();
    let (health_entry, catalog_entry) = entries(&scope, "passing");
    let mut service = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry], 13),
        ConsulHttpResponse::catalog(vec![catalog_entry], 13),
    );
    let result = service.read(ReadBounds::default(), 20).expect("read");
    let mut consumer =
        MissionConsulServiceHealthConsumer::new(scope.clone(), service.registration())
            .expect("consumer");
    let consumed = consumer.consume(&result).expect("consume");
    assert!(consumed.accepted);
    assert!(!consumed.adopted);
    assert!(!consumed.authority.connected);
    assert!(!consumed.authority.truth);
    assert!(!consumed.authority.outcome);
    assert!(matches!(
        consumer.consume(&result),
        Err(hartevo_consul_service_health_result_plugin::ConsumerError::Replay)
    ));
    assert!(matches!(
        consumer.consume_at(&result, Revision::new(21).unwrap()),
        Err(hartevo_consul_service_health_result_plugin::ConsumerError::StaleMission)
    ));

    let (warning_health, warning_catalog) = entries(&scope, "warning");
    let mut service_for_record = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![warning_health], 14),
        ConsulHttpResponse::catalog(vec![warning_catalog], 14),
    );
    let record_result = service_for_record
        .read(ReadBounds::default(), 21)
        .expect("second read");
    let mut recording_consumer =
        MissionConsulServiceHealthConsumer::new(scope, service_for_record.registration())
            .expect("recording consumer");
    let consumed_record = recording_consumer
        .record(&record_result, "idempotency-key")
        .expect("record");
    let record = consumed_record.record.clone().expect("local record");
    assert_eq!(
        recording_consumer.verify(&record).state,
        VerificationState::Verified
    );
    let replay = recording_consumer
        .record(&record_result, "idempotency-key")
        .expect("idempotent replay");
    assert_eq!(replay.status, EvidenceStatus::Replay);
    recording_consumer.revoke().expect("consumer revoke");
    assert_eq!(
        recording_consumer.verify(&record).state,
        VerificationState::Revoked
    );
}

#[test]
fn bounds_acl_filter_and_absent_are_explicit() {
    let scope = scope();
    let (mut health_entry, catalog_entry) = entries(&scope, "warning");
    health_entry.service.tags = std::iter::once("stable".to_owned())
        .chain((0..9).map(|index| format!("tag-{index}")))
        .collect();
    health_entry.checks = (0..4)
        .map(|index| RawCheck::new(format!("check-{index}"), "bounded", "passing"))
        .collect();
    let mut bounded = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry], 50),
        ConsulHttpResponse::catalog(vec![catalog_entry], 50),
    );
    let bounds = ReadBounds::new(1, 2, 3, 1_048_576).unwrap();
    let bounded_result = bounded.read(bounds, 30).expect("bounded read");
    assert_eq!(bounded_result.evidence.status, EvidenceStatus::Partial);
    assert!(bounded_result.evidence.truncated);
    assert_eq!(bounded_result.evidence.instances[0].tags.len(), 3);
    assert_eq!(bounded_result.evidence.instances[0].checks.len(), 2);

    let (health_entry, catalog_entry) = entries(&scope, "passing");
    let mut acl = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry], 51).with_acl_filtered(true),
        ConsulHttpResponse::catalog(vec![catalog_entry], 51),
    );
    let acl_result = acl
        .read(ReadBounds::default(), 31)
        .expect("ACL filtered read");
    assert_eq!(acl_result.evidence.status, EvidenceStatus::AclFiltered);
    assert!(!acl_result.evidence.is_review_complete());

    let mut empty = fixture_service(
        scope,
        ConsulHttpResponse::health(Vec::new(), 52),
        ConsulHttpResponse::catalog(Vec::new(), 52),
    );
    let empty_result = empty.read(ReadBounds::default(), 32).expect("empty read");
    assert_eq!(empty_result.evidence.status, EvidenceStatus::Empty);
}

#[test]
fn transport_failures_and_revision_drift_are_not_claimed_as_health() {
    for (failure, expected) in [
        (TransportFailure::Unauthorized, EvidenceStatus::AccessLost),
        (TransportFailure::Forbidden, EvidenceStatus::AccessLost),
        (
            TransportFailure::BadRequest,
            EvidenceStatus::ProviderUnknown,
        ),
        (TransportFailure::NotFound, EvidenceStatus::ProviderUnknown),
        (
            TransportFailure::TooManyRequests,
            EvidenceStatus::ProviderUnknown,
        ),
        (TransportFailure::Server, EvidenceStatus::ProviderUnknown),
        (TransportFailure::Timeout, EvidenceStatus::ProviderUnknown),
        (TransportFailure::Partial, EvidenceStatus::Partial),
    ] {
        let local_scope = scope();
        let transport = FixtureTransport::with_responses([Err(TransportError::new(
            failure,
            "bounded diagnostic",
        ))]);
        let definition =
            ProviderDefinition::new(&local_scope, ProviderProvenance::Fixture).unwrap();
        let provider = ConsulHealthProvider::new(transport, definition).unwrap();
        let mut service =
            ConsulServiceHealthResultService::new(local_scope, provider).expect("service");
        let result = service
            .read(ReadBounds::default(), 40)
            .expect("failure evidence");
        assert_eq!(result.evidence.status, expected);
        assert!(result.evidence.instances.is_empty());
        assert!(result.failure.is_some());
        assert!(!result.evidence.connected);
        assert!(!result.evidence.native);
        assert!(!result.evidence.first_party);
    }

    let local_scope = scope();
    let (health_entry, catalog_entry) = entries(&local_scope, "passing");
    let mut service = fixture_service(
        local_scope.clone(),
        ConsulHttpResponse::health(vec![health_entry], 60),
        ConsulHttpResponse::catalog(vec![catalog_entry], 61),
    );
    let drift = service
        .read(ReadBounds::default(), 41)
        .expect("drift evidence");
    assert_eq!(drift.evidence.status, EvidenceStatus::ProviderUnknown);

    let blocked_definition =
        ProviderDefinition::new(&local_scope, ProviderProvenance::BlockedEnv).unwrap();
    let blocked_provider =
        ConsulHealthProvider::new(BlockedEnvTransport::new(), blocked_definition).unwrap();
    let mut blocked_service =
        ConsulServiceHealthResultService::new(local_scope, blocked_provider).unwrap();
    let blocked = blocked_service
        .read(ReadBounds::default(), 42)
        .expect("blocked environment evidence");
    assert_eq!(blocked.evidence.status, EvidenceStatus::ProviderUnknown);
    assert_eq!(blocked.evidence.provenance, ProviderProvenance::BlockedEnv);
    assert!(!blocked.evidence.authority.connected);
}

#[test]
fn duplicate_identity_and_tamper_are_rejected_deterministically() {
    let scope = scope();
    let (health_entry, catalog_entry) = entries(&scope, "critical");
    let mut service = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry.clone(), health_entry], 70),
        ConsulHttpResponse::catalog(vec![catalog_entry.clone()], 70),
    );
    assert!(matches!(
        service.read(ReadBounds::default(), 50),
        Err(ServiceError::DuplicateIdentity)
    ));

    let (health_entry, catalog_entry) = entries(&scope, "critical");
    let mut service = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry], 71),
        ConsulHttpResponse::catalog(vec![catalog_entry], 71),
    );
    let result = service.read(ReadBounds::default(), 51).expect("read");
    let mut record = service.record(&result).expect("local record");
    record.record_digest = Digest::from_text("tampered");
    assert_eq!(service.verify(&record).state, VerificationState::Tampered);
}

#[test]
fn contract_and_request_digests_are_stable() {
    let scope = scope();
    let (health_entry, catalog_entry) = entries(&scope, "maintenance");
    let mut first = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry.clone()], 80),
        ConsulHttpResponse::catalog(vec![catalog_entry.clone()], 80),
    );
    let mut second = fixture_service(
        scope.clone(),
        ConsulHttpResponse::health(vec![health_entry], 80),
        ConsulHttpResponse::catalog(vec![catalog_entry], 80),
    );
    let first_result = first.read(ReadBounds::default(), 60).unwrap();
    let second_result = second.read(ReadBounds::default(), 60).unwrap();
    assert_eq!(
        first_result.evidence.evidence_digest,
        second_result.evidence.evidence_digest
    );
    assert_eq!(
        first_result.proposal.proposal_digest,
        second_result.proposal.proposal_digest
    );
    assert_eq!(
        hartevo_consul_service_health_result_plugin::contract_digest(),
        Digest::from_text(hartevo_consul_service_health_result_plugin::CONTRACT_JSON)
    );
}

#[test]
fn raw_fixture_fields_are_not_part_of_digest_only_local_record() {
    let scope = scope();
    let (health_entry, catalog_entry) = entries(&scope, "passing");
    let mut service = fixture_service(
        scope,
        ConsulHttpResponse::health(vec![health_entry], 90),
        ConsulHttpResponse::catalog(vec![catalog_entry], 90),
    );
    let result = service.read(ReadBounds::default(), 70).unwrap();
    let record = service.record(&result).unwrap();
    let json = serde_json::to_string(&record).unwrap();
    assert!(!json.contains("10.0.0.8"));
    assert!(!json.contains("do not expose"));
    assert!(json.contains("evidenceDigest"));
    assert_eq!(record.validate(), Ok(()));
}

#[test]
fn every_layer_one_provenance_stays_below_native_and_kernel_authority() {
    let scope = scope();
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Fake,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        let definition = ProviderDefinition::new(&scope, provenance).expect("definition");
        assert!(!definition.connected);
        assert!(!definition.native);
        assert!(!definition.first_party);
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    let authority = AuthorityBoundary::layer_one();
    assert!(!authority.connected());
    assert!(!authority.native());
    assert!(!authority.first_party());
    assert!(!authority.truth_authority());
    assert!(!authority.consent_authority());
    assert!(!authority.effect_authority());
    assert!(!authority.receipt_authority());
    assert!(!authority.verification_authority());
    assert!(!authority.outcome_authority());
}

#[test]
fn consul_wire_payload_uses_official_uppercase_identity_fields() {
    let payload = r#"
      [{
        "Node": {
          "ID": "node-wire",
          "Node": "node-wire-name",
          "Address": "10.0.0.9",
          "Datacenter": "dc1",
          "Meta": {"private": "value"}
        },
        "Service": {
          "ID": "service-wire",
          "Service": "payments",
          "Tags": ["stable"],
          "Address": "10.0.0.10",
          "Port": 8443
        },
        "Checks": [{
          "CheckID": "check-wire",
          "Name": "wire check",
          "Status": "passing",
          "Notes": "private",
          "Output": "private"
        }]
      }]
    "#;
    let entries: Vec<RawHealthServiceEntry> =
        serde_json::from_str(payload).expect("official Consul health payload");
    assert_eq!(entries[0].node.id, "node-wire");
    assert_eq!(entries[0].service.id, "service-wire");
    assert_eq!(entries[0].checks[0].check_id, "check-wire");
}
