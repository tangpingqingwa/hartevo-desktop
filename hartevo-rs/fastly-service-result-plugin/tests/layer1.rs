use fastly::{
    BlockedEnvTransport, ConsentScope, Digest, FastlyEnvironmentState, FastlyFixtureSet,
    FastlyProvider, FastlyServiceResultError, FastlyServiceResultScope, FastlyServiceResultService,
    FastlyServiceResultState, FastlyTransportError, FastlyValidationState, FixtureTransport,
    Layer1Authority, Mission, MissionFastlyServiceConsumer, PermissionSnapshot, Project,
    RecordingTransport, Revision, SecretKind, SecretReference, TransportProvenance, WorkProduct,
};
use hartevo_fastly_service_result_plugin as fastly;

const RAW_ACCOUNT: &str = "account-770";
const RAW_SERVICE: &str = "service-770";
const RAW_VERSION: &str = "version-17";
const RAW_ENVIRONMENT: &str = "staging";
const RAW_DOMAIN: &str = "www.example.invalid";
const RAW_TOKEN: &str = "fastly-api-token-must-not-escape";
const RAW_CONFIG: &str = "backend default { .host = \"origin.example.invalid\" }";

fn scope() -> FastlyServiceResultScope {
    FastlyServiceResultScope::new(
        RAW_ACCOUNT,
        RAW_SERVICE,
        RAW_VERSION,
        RAW_ENVIRONMENT,
        RAW_DOMAIN,
        Project::new("project-770", 2).expect("Project"),
        Mission::new("mission-770", 3).expect("Mission"),
        WorkProduct::new("work-product-770", 4).expect("Work Product"),
    )
    .expect("scope")
}

fn secret(scope: &FastlyServiceResultScope) -> SecretReference {
    SecretReference::api_token(RAW_TOKEN, scope, 7).expect("opaque API token")
}

fn registered<T: fastly::FastlyTransport>(
    scope: &FastlyServiceResultScope,
    transport: T,
) -> FastlyServiceResultService<T> {
    let provider = FastlyProvider::new(transport, scope.clone(), secret(scope)).expect("provider");
    FastlyServiceResultService::register(
        provider,
        "registration-770",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-770", 1, 100).expect("consent"),
        1,
    )
    .expect("registration")
}

fn fixture_service() -> FastlyServiceResultService<FixtureTransport> {
    let scope = scope();
    registered(&scope, FixtureTransport::for_scope(&scope))
}

#[test]
fn contract_and_typed_authority_are_layer_one_honest() {
    let contract = fastly::FastlyServiceResultContract::baseline().expect("contract");
    assert_eq!(
        contract.value()["contractVersion"],
        fastly::FASTLY_SERVICE_RESULT_CONTRACT_VERSION
    );
    assert_eq!(contract.value()["contractDigest"], fastly::CONTRACT_DIGEST);
    assert_eq!(fastly::contract_digest(), fastly::CONTRACT_DIGEST);
    assert_eq!(
        fastly::FASTLY_OFFICIAL_API,
        "https://www.fastly.com/documentation/reference/api/"
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::first_party_provider());
    assert!(!Layer1Authority::external_writes());
    assert!(!Layer1Authority::durable_provider_receipt());
    assert!(!Layer1Authority::independent_native_readback());
    assert!(!Layer1Authority::kernel_authority());
    assert!(!Layer1Authority::outcome_authority());
    assert!(!Layer1Authority::work_product_adoption());
}

#[test]
fn ready_fixture_separates_active_version_from_staging_environment() {
    let mut service = fixture_service();
    let evidence = service.read(10).expect("bounded fixture read");
    assert_eq!(evidence.state, FastlyServiceResultState::Present);
    assert!(!evidence.partial);
    assert_eq!(evidence.request_receipts.len(), 5);
    assert_eq!(
        evidence.version.as_ref().expect("version").state,
        fastly::FastlyVersionState::Active
    );
    assert!(evidence.version.as_ref().expect("version").active);
    assert_eq!(
        evidence.environment.as_ref().expect("environment").state,
        FastlyEnvironmentState::Staging
    );
    assert!(evidence.environment.as_ref().expect("environment").staging);
    assert!(evidence.validation.is_some());
    assert!(evidence.request_receipts.iter().all(|receipt| {
        receipt.redacted && !receipt.connected && !receipt.native && !receipt.first_party
    }));
    evidence.validate_integrity().expect("evidence integrity");

    let proposal = service
        .compile_proposal_from_evidence(evidence.clone())
        .expect("proposal");
    let report = service.verify_proposal(&proposal).expect("verification");
    assert!(report.verified());
    assert!(report.review_eligible);
    assert!(!report.can_be_adopted);
    let receipt = service
        .record_observation(&proposal, "idempotency-770")
        .expect("recording receipt");
    receipt.validate_integrity().expect("receipt integrity");
    assert!(!receipt.durable_provider_receipt);
    let replay = service
        .record_observation(&proposal, "idempotency-770")
        .expect("idempotent replay");
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);

    let mut consumer = MissionFastlyServiceConsumer::new(scope(), service.registration().clone())
        .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    result
        .validate_integrity()
        .expect("Mission result integrity");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let consumer_receipt = consumer
        .record(&proposal, "mission-idempotency-770")
        .expect("Mission recording");
    consumer_receipt
        .validate_integrity()
        .expect("Mission receipt integrity");
    assert!(!consumer_receipt.replayed);
    assert!(
        consumer
            .record(&proposal, "mission-idempotency-770")
            .expect("Mission replay")
            .replayed
    );

    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let evidence_json = serde_json::to_string(&evidence).expect("evidence JSON");
    let debug = format!("{service:?}");
    for raw in [RAW_TOKEN, RAW_CONFIG] {
        assert!(
            !registration_json.contains(raw),
            "registration leaked {raw}"
        );
        assert!(!evidence_json.contains(raw), "evidence leaked {raw}");
        assert!(!debug.contains(raw), "debug leaked {raw}");
    }
}

#[test]
fn api_token_secret_reference_is_opaque_and_non_serializing() {
    let scope = scope();
    let mut reference = secret(&scope);
    assert_eq!(reference.kind(), SecretKind::ApiToken);
    assert_eq!(reference.scope_digest(), &scope.digest());
    assert!(!format!("{reference:?}").contains(RAW_TOKEN));
    assert!(serde_json::to_string(&reference).is_err());
    reference.revoke();
    assert!(reference.is_revoked());
    assert_eq!(
        FastlyProvider::new(FixtureTransport::for_scope(&scope), scope, reference,)
            .expect_err("revoked reference must not register")
            .to_string(),
        "secret reference is revoked"
    );
}

#[test]
fn deterministic_provenances_never_claim_connected_native_or_first_party() {
    let scope = scope();
    let transports: Vec<Box<dyn fastly::FastlyTransport>> = vec![
        Box::new(FixtureTransport::for_scope(&scope)),
        Box::new(RecordingTransport::default()),
        Box::new(fastly::FakeTransport::default()),
        Box::new(fastly::LoopbackTransport::default()),
        Box::new(BlockedEnvTransport),
    ];
    for transport in transports {
        let provenance = transport.provenance();
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }

    let mut service = registered(&scope, BlockedEnvTransport);
    let evidence = service.read(4).expect("blocked evidence");
    assert_eq!(evidence.state, FastlyServiceResultState::ProviderUnknown);
    assert_eq!(
        service.provider().provenance(),
        TransportProvenance::BlockedEnv
    );
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
}

#[test]
fn rate_limit_retry_receipts_are_bounded_and_get_only() {
    let scope = scope();
    let fixture = FastlyFixtureSet::for_scope(&scope);
    let mut transport = RecordingTransport::default();
    transport.push_error(FastlyTransportError::RateLimited {
        retry_after_seconds: Some(3600),
    });
    for response in fixture.responses() {
        transport.push_response(response);
    }
    let mut service = registered(&scope, transport);
    let evidence = service.read(4).expect("rate-limited read");
    assert_eq!(evidence.state, FastlyServiceResultState::Present);
    assert_eq!(evidence.request_receipts.len(), 6);
    assert_eq!(
        evidence
            .rate_limit
            .as_ref()
            .expect("rate-limit receipt")
            .retry_after_seconds,
        fastly::MAX_BACKOFF_SECONDS
    );
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .all(|request| request.is_get() && request.is_allowlisted())
    );
}

#[test]
fn pagination_validation_failure_and_empty_are_explicit() {
    let scope = scope();
    let mut fixture = FastlyFixtureSet::for_scope(&scope);
    let mut second_page = fixture.domain_pages[0].clone();
    second_page.page = 2;
    second_page.total_pages = 2;
    second_page.entries[0].domain_digest = Digest::from_text("second-domain");
    second_page.entries[0].metadata_digest = Digest::from_text("second-domain-metadata");
    fixture.domain_pages[0].total_pages = 2;
    fixture.domain_pages.push(second_page);
    let mut service = registered(&scope, FixtureTransport::from_fixture(fixture));
    let evidence = service.read(4).expect("paged read");
    assert_eq!(evidence.state, FastlyServiceResultState::Present);
    assert_eq!(evidence.domains.len(), 2);

    let mut invalid = FastlyFixtureSet::for_scope(&scope);
    invalid.validation.state = FastlyValidationState::Failed;
    invalid.validation.error_count = 1;
    let mut failed = registered(&scope, FixtureTransport::from_fixture(invalid));
    assert_eq!(
        failed.read(4).expect("validation failure evidence").state,
        FastlyServiceResultState::ValidationFailed
    );

    let mut empty = FastlyFixtureSet::for_scope(&scope);
    empty.domain_pages[0].entries.clear();
    let mut empty_service = registered(&scope, FixtureTransport::from_fixture(empty));
    assert_eq!(
        empty_service.read(4).expect("empty evidence").state,
        FastlyServiceResultState::Empty
    );
}

#[test]
fn page_limit_is_bounded_without_consuming_unbounded_pages() {
    let scope = scope();
    let mut fixture = FastlyFixtureSet::for_scope(&scope);
    fixture.domain_pages[0].total_pages = 5;
    let mut second_page = fixture.domain_pages[0].clone();
    second_page.page = 2;
    second_page.total_pages = 5;
    second_page.entries[0].domain_digest = Digest::from_text("page-two-domain");
    fixture.domain_pages.push(second_page);
    let mut service = registered(&scope, FixtureTransport::from_fixture(fixture));
    let evidence = service.read(2).expect("bounded pages");
    assert_eq!(evidence.state, FastlyServiceResultState::Partial);
    assert!(evidence.partial);
    assert_eq!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .filter(|request| request.endpoint.name() == "domain")
            .count(),
        2
    );
}

#[test]
fn access_loss_timeout_server_error_and_tamper_fail_closed() {
    let scope = scope();
    for (error, state) in [
        (
            FastlyTransportError::AccessLoss,
            FastlyServiceResultState::AccessLoss,
        ),
        (
            FastlyTransportError::Timeout,
            FastlyServiceResultState::Timeout,
        ),
        (
            FastlyTransportError::ServerError { status: 503 },
            FastlyServiceResultState::ServerError,
        ),
    ] {
        let mut transport = RecordingTransport::default();
        transport.push_error(error);
        let mut service = registered(&scope, transport);
        assert_eq!(service.read(4).expect("failure evidence").state, state);
    }

    let fixture = FastlyFixtureSet::for_scope(&scope);
    let mut responses = fixture.responses();
    responses[0] = responses[0]
        .clone()
        .with_declared_digest(Digest::from_text("tampered"));
    let mut service = registered(&scope, RecordingTransport::from_responses(responses));
    assert_eq!(
        service.read(4).expect("tamper evidence").state,
        FastlyServiceResultState::Tampered
    );
}

#[test]
fn stale_revision_revocation_reversal_and_forbidden_effects_are_visible() {
    let scope = scope();
    let mut service = fixture_service();
    let mut request = fastly::FastlyReadRequest::new(
        &scope,
        service.registration().permission_digest(),
        service.registration().consent_digest(),
    );
    request.mission_revision = Revision::new(99).expect("revision");
    assert_eq!(
        service.read_with_fence(&request),
        Err(FastlyServiceResultError::StaleRevision)
    );

    let before = service.registration().registration_digest().clone();
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(revoked.previous_status, fastly::RegistrationState::Active);
    assert_eq!(revoked.new_status, fastly::RegistrationState::Revoked);
    assert_ne!(before, *service.registration().registration_digest());
    assert_eq!(
        service.read(4),
        Err(FastlyServiceResultError::RegistrationRevoked)
    );
    service.restore_registration().expect("restore");
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service.read(4),
        Err(FastlyServiceResultError::RegistrationReversed)
    );

    for operation in [
        "activate_version",
        "deactivate_version",
        "clone_version",
        "lock_version",
        "upload_vcl",
        "upload_config",
        "purge_cache",
        "domain_mutation",
        "dns_mutation",
        "tls_mutation",
        "traffic_control",
        "raw_vcl_read",
        "raw_config_read",
    ] {
        assert!(matches!(
            service.provider().reject_write(operation),
            Err(FastlyServiceResultError::MutationForbidden { .. })
        ));
    }
}

#[test]
fn contract_scope_contains_exact_typed_names_and_no_live_http_surface() {
    let contract = fastly::FastlyServiceResultContract::baseline().expect("contract");
    let exact_scope = contract.value()["exactScope"].as_array().expect("scope");
    for name in [
        "account",
        "service",
        "version",
        "environment",
        "domain",
        "Project",
        "Mission",
        "Work Product",
    ] {
        assert!(exact_scope.iter().any(|value| value == name), "{name}");
    }
    assert!(
        contract.value()["allowlist"]["writes"]
            .as_array()
            .expect("writes")
            .is_empty()
    );
    assert!(
        !contract.value()["authority"]["externalWrites"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !contract.value()["authentication"]["rawCredentialSerialized"]
            .as_bool()
            .unwrap()
    );
}
