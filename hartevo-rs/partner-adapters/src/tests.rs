use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_connector_sdk::{
    BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorScope, ConnectorWorker,
    ProbeRequest, ProviderAdapterOperation, ProviderAdapterRegistry, ProviderCapabilityKey,
    ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{Mission, MissionContract, MissionId, ProjectId, TenantId};

use crate::awin::{AwinAdapter, AwinFixtureWorld};
use crate::cj::{CjAdapter, CjFixtureWorld};
use crate::contract::TypedPartnerNetworkAdapter;
use crate::impact::{
    ImpactAdapter, ImpactApi, ImpactApiError, ImpactCredentialResolver, ImpactCredentials,
    ImpactFixtureWorld, ImpactHttpExecutor, ImpactHttpResponse, ImpactProbeResponse,
    ImpactReadResponse,
};
use crate::{
    ActionState, AuthorizationState, CallbackChannel, CallbackDisposition, CallbackRequest,
    CallbackSignatureScheme, CommissionState, ConnectorAdapterBridge, ConversionState,
    DurablePartnerReadCursor, FixtureScenario, ImpactProgramReadRequest,
    ImpactProgramReadServiceDefinition, NetworkAccountId, NetworkProbeRequest, NetworkProbeStatus,
    NetworkProvenance, NetworkReadData, NetworkReadRequest, NetworkResource, NetworkScope,
    PartnerNetworkError, PartnerReadBudget, PartnerReadClassification, PartnerReadConnectionState,
    PartnerReadError, PartnerReadScope, ProgramId, ReportSettlementState, ReversalState,
};

#[derive(Clone, Debug)]
struct ProductionPaginatedImpactApi {
    inner: ImpactFixtureWorld,
}

impl ImpactApi for ProductionPaginatedImpactApi {
    fn probe(
        &self,
        authorization: &crate::OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ImpactProbeResponse, ImpactApiError> {
        let mut response = self.inner.probe(authorization, request)?;
        response.provenance = NetworkProvenance::ProductionProvider;
        Ok(response)
    }

    fn read(
        &self,
        authorization: &crate::OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ImpactReadResponse, ImpactApiError> {
        let mut response = self.inner.read(authorization, request)?;
        response.provenance = NetworkProvenance::ProductionProvider;
        response.page.next_cursor = if request.cursor.is_none() {
            Some(crate::ReadCursor::new("page:2").expect("valid page cursor"))
        } else {
            None
        };
        response.page.has_more = request.cursor.is_none();
        Ok(response)
    }
}

#[derive(Clone, Debug, Default)]
struct TestImpactCredentialResolver;

impl ImpactCredentialResolver for TestImpactCredentialResolver {
    fn resolve(
        &self,
        _authorization: &crate::OpaqueSecretReference,
        _account_id: &NetworkAccountId,
    ) -> Result<ImpactCredentials, ImpactApiError> {
        ImpactCredentials::new("impact-account-1", "test-only-token")
    }
}

#[derive(Clone, Debug, Default)]
struct RecordingImpactHttpExecutor;

impl ImpactHttpExecutor for RecordingImpactHttpExecutor {
    fn get(
        &self,
        url: &str,
        credentials: &ImpactCredentials,
    ) -> Result<ImpactHttpResponse, ImpactApiError> {
        assert_eq!(
            url,
            "https://api.impact.com/Mediapartners/impact-account-1/Campaigns?Page=1&PageSize=100"
        );
        assert_eq!(credentials.account_sid(), "impact-account-1");
        Ok(ImpactHttpResponse {
            status: 200,
            body: r#"{"@numpages":"2","@nextpageuri":"/Mediapartners/impact-account-1/Campaigns?Page=2","Campaigns":[{"CampaignId":"impact-program-1","State":"ACTIVE"}]}"#.into(),
            retry_after_seconds: None,
        })
    }
}

fn observed_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
        .single()
        .expect("valid fixture timestamp")
}

#[test]
fn impact_http_api_uses_the_official_account_campaigns_read_and_production_class() {
    let at = observed_at();
    let api = crate::impact::ImpactHttpApi::with_executor(
        TestImpactCredentialResolver,
        RecordingImpactHttpExecutor,
    );
    let scope = NetworkScope::account_scope(
        "tenant-http-test",
        "project-http-test",
        NetworkAccountId::from_stable("impact-account-1"),
    )
    .expect("valid account scope");
    let request = NetworkReadRequest::new(scope, NetworkResource::Programs, at);
    let authorization = crate::OpaqueSecretReference::new("secret-ref-impact-http", 1)
        .expect("valid opaque reference");
    let response = api
        .read(&authorization, &request)
        .expect("fake official response is typed");

    assert_eq!(response.provenance, NetworkProvenance::ProductionProvider);
    assert_eq!(response.page.item_count, 1);
    assert_eq!(
        response
            .page
            .next_cursor
            .expect("official pagination metadata")
            .as_str(),
        "page:2"
    );
    assert!(matches!(response.data, NetworkReadData::Programs { .. }));
}

#[test]
fn empty_registry_is_disconnected_and_fixture_can_never_complete_read()
-> Result<(), Box<dyn std::error::Error>> {
    let at = observed_at();
    let definition = ImpactProgramReadServiceDefinition::new(at).expect("static definition");
    let empty = ProviderAdapterRegistry::contract_baseline().expect("checked baseline");
    assert_eq!(
        definition.connection_state(&empty),
        PartnerReadConnectionState::Disconnected
    );
    assert!(definition.connection_state(&empty).is_disconnected());

    let world = ImpactFixtureWorld::default_fixture(at);
    let network_scope = world.scope();
    let read_scope = PartnerReadScope::new(
        "tenant-fixture",
        "project-partner-fixture",
        "mission-fixture",
        network_scope.account_id.clone(),
        network_scope.program_id.clone(),
    )?;
    let sdk_scope = read_scope.connector_scope()?;
    let bridge = ConnectorAdapterBridge::with_program_expectation(
        ImpactAdapter::new(world.clone()),
        world.current_program_expectation(),
    )?;
    let descriptor = bridge.descriptor().clone();
    let registry = ProviderAdapterRegistry::new(
        "partner-fixture-read-1",
        descriptor.registrations().to_vec(),
    )?;
    let mut worker = ConnectorWorker::new(
        "worker-impact-fixture-read",
        bridge,
        registry,
        sdk_scope.clone(),
        at,
        at + Duration::minutes(5),
    )?;
    let secret = SecretReference::new("secret-ref-impact-fixture-read", sdk_scope.clone(), 1)?;
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        descriptor.identity().clone(),
        "credential-lease-impact-fixture-read",
        1,
        at,
        at + Duration::minutes(5),
    )?;
    let dispatch = worker.dispatch_fence();
    let session = worker.begin_auth(BeginAuthRequest {
        dispatch: dispatch.clone(),
        scope: sdk_scope.clone(),
        secret_reference: secret.clone(),
        credential_lease: lease.clone(),
        auth_revision: 1,
        issued_at: at,
        expires_at: at + Duration::minutes(5),
    })?;
    let probe = worker.probe(ProbeRequest {
        dispatch,
        scope: sdk_scope,
        secret_reference: secret,
        credential_lease: lease,
        session,
        probe_revision: 1,
        result_id: "probe-result-impact-fixture-read".to_owned(),
        at: at + Duration::seconds(1),
    })?;
    let mission = Mission::compile(
        TenantId::from("tenant-fixture"),
        MissionId::from("mission-fixture"),
        ProjectId::from("project-partner-fixture"),
        "fixture read mission",
        MissionContract::bootstrap(
            "read partner programs",
            [crate::read::PARTNER_PROGRAM_READ_MISSION_CAPABILITY.to_owned()],
            at,
        ),
        at,
    )?;
    let request = ImpactProgramReadRequest::new(read_scope, at + Duration::seconds(1))?;
    assert!(matches!(
        definition.read_mission(&mut worker, &mission, &probe, &request),
        Err(PartnerReadError::NonProductionEvidence(
            PartnerReadClassification::Fixture
        ))
    ));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn impact_authenticated_mission_read_emits_production_receipt_and_durable_page_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let network_scope = world.scope();
    let read_scope = PartnerReadScope::new(
        "tenant-production",
        "project-production",
        "mission-production",
        network_scope.account_id.clone(),
        network_scope.program_id.clone(),
    )?;
    let sdk_scope = read_scope.connector_scope()?;
    let bridge = ConnectorAdapterBridge::with_program_expectation(
        ImpactAdapter::new(ProductionPaginatedImpactApi {
            inner: world.clone(),
        }),
        world.current_program_expectation(),
    )?;
    let descriptor = bridge.descriptor().clone();
    let registry = ProviderAdapterRegistry::new(
        "partner-production-read-1",
        descriptor.registrations().to_vec(),
    )?;
    let definition = ImpactProgramReadServiceDefinition::new(at)?;
    assert_eq!(
        definition.connection_state(&registry),
        PartnerReadConnectionState::Registered
    );
    let mut worker = ConnectorWorker::new(
        "worker-impact-production-read",
        bridge,
        registry,
        sdk_scope.clone(),
        at,
        at + Duration::minutes(5),
    )?;
    let secret = SecretReference::new("secret-ref-impact-production-read", sdk_scope.clone(), 1)?;
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        descriptor.identity().clone(),
        "credential-lease-impact-production-read",
        1,
        at,
        at + Duration::minutes(5),
    )?;
    let dispatch = worker.dispatch_fence();
    let session = worker.begin_auth(BeginAuthRequest {
        dispatch: dispatch.clone(),
        scope: sdk_scope.clone(),
        secret_reference: secret.clone(),
        credential_lease: lease.clone(),
        auth_revision: 1,
        issued_at: at,
        expires_at: at + Duration::minutes(5),
    })?;
    let probe = worker.probe(ProbeRequest {
        dispatch,
        scope: sdk_scope,
        secret_reference: secret,
        credential_lease: lease,
        session,
        probe_revision: 1,
        result_id: "probe-result-impact-production-read".to_owned(),
        at: at + Duration::seconds(1),
    })?;
    assert_eq!(
        probe.provenance_class(),
        ProviderProvenanceClass::ProductionProvider
    );

    let mission = Mission::compile(
        TenantId::from("tenant-production"),
        MissionId::from("mission-production"),
        ProjectId::from("project-production"),
        "production partner read mission",
        MissionContract::bootstrap(
            "read partner programs",
            [crate::read::PARTNER_PROGRAM_READ_MISSION_CAPABILITY.to_owned()],
            at,
        ),
        at,
    )?;
    let first_request =
        ImpactProgramReadRequest::new(read_scope.clone(), at + Duration::seconds(1))?
            .with_budget(PartnerReadBudget::new(2, at + Duration::minutes(1), 2, 2)?);
    let first = definition.read_mission(&mut worker, &mission, &probe, &first_request)?;
    first.validate()?;
    assert_eq!(
        first.classification,
        PartnerReadClassification::ProductionAuthenticated
    );
    assert_eq!(first.page_sequence, 1);
    assert_eq!(first.item_count, 1);
    assert_eq!(first.cost.units, 1);
    assert!(first.source_uri.contains("api.impact.com/Mediapartners/"));
    let cursor = first
        .next_cursor
        .clone()
        .expect("first page has next cursor");
    assert_eq!(cursor.page(), 2);
    assert_eq!(cursor.provider_cursor(), "page:2");
    assert_eq!(cursor.scope_digest, read_scope.digest());

    let second_request = first_request
        .with_cursor(cursor.clone())
        .with_budget(PartnerReadBudget::new(2, at + Duration::minutes(1), 2, 2)?);
    let second = definition.read_mission(&mut worker, &mission, &probe, &second_request)?;
    second.validate()?;
    assert_eq!(second.page_sequence, 2);
    assert!(second.next_cursor.is_none());
    assert_eq!(second.scope, read_scope);
    Ok(())
}

#[test]
fn durable_cursor_scope_query_and_receipt_digest_are_tamper_evident() -> Result<(), PartnerReadError>
{
    let at = observed_at();
    let scope = PartnerReadScope::new(
        "tenant-cursor",
        "project-cursor",
        "mission-cursor",
        NetworkAccountId::from_stable("impact-account-1"),
        Some(ProgramId::from_stable("impact-program-1")),
    )?;
    let service = ImpactProgramReadServiceDefinition::new(at)?;
    let query_digest = crate::contract::digest_bytes(b"programs-query-v1");
    let cursor = DurablePartnerReadCursor::new(
        service.service_id.clone(),
        &scope,
        query_digest.clone(),
        2,
        "page:2",
        crate::contract::digest_bytes(b"page-1"),
    )?;
    assert!(
        cursor
            .validate_for(&service.service_id, &scope, &query_digest)
            .is_ok()
    );
    let mut tampered = cursor.clone();
    tampered.scope_digest = PartnerReadScope::new(
        "other-tenant",
        "project-cursor",
        "mission-cursor",
        NetworkAccountId::from_stable("impact-account-1"),
        Some(ProgramId::from_stable("impact-program-1")),
    )?
    .digest();
    assert_eq!(
        tampered.validate_for(&service.service_id, &scope, &query_digest),
        Err(PartnerReadError::InvalidCursor)
    );
    Ok(())
}

#[test]
fn partner_read_budget_rejects_quota_and_cost_before_provider_dispatch() {
    let at = observed_at();
    let cost = crate::PartnerReadCost::new(1, None, "impact-official-api/v1", at)
        .expect("valid read cost");
    let quota =
        PartnerReadBudget::new(1, at + Duration::minutes(1), 0, 1).expect("valid quota boundary");
    assert_eq!(quota.check(&cost, at), Err(PartnerReadError::QuotaExceeded));
    let cost_boundary =
        PartnerReadBudget::new(1, at + Duration::minutes(1), 1, 0).expect("valid cost boundary");
    assert_eq!(
        cost_boundary.check(&cost, at),
        Err(PartnerReadError::CostLimitExceeded)
    );
}

fn all_resources() -> [NetworkResource; 11] {
    [
        NetworkResource::Programs,
        NetworkResource::Partners,
        NetworkResource::Contracts,
        NetworkResource::Links,
        NetworkResource::Clicks,
        NetworkResource::Conversions,
        NetworkResource::Actions,
        NetworkResource::Commissions,
        NetworkResource::Reversals,
        NetworkResource::Payouts,
        NetworkResource::Reports,
    ]
}

fn assert_fixture_adapter(
    adapter: &mut dyn TypedPartnerNetworkAdapter,
    scope: &NetworkScope,
    authorization: crate::AuthorizationGrant,
    expectation: &crate::ProgramExpectation,
    at: DateTime<Utc>,
) {
    let authorization_observation = adapter
        .authorize(authorization, at)
        .expect("fixture authorization is valid");
    assert_eq!(authorization_observation.state, AuthorizationState::Granted);

    let probe = adapter
        .probe(NetworkProbeRequest::for_program(
            scope.clone(),
            expectation.clone(),
            at + Duration::minutes(5),
        ))
        .expect("fixture probe succeeds");
    assert_eq!(probe.status, NetworkProbeStatus::Reachable);
    assert!(!probe.can_claim_connected());

    for resource in all_resources() {
        let read = adapter
            .read(NetworkReadRequest::for_program(
                scope.clone(),
                resource,
                expectation.clone(),
                at + Duration::minutes(5),
            ))
            .expect("fixture read succeeds");
        assert_eq!(read.request, resource);
        assert_eq!(read.page.item_count as usize, read.data.item_count());
        read.validate().expect("fixture read evidence validates");
    }
}

#[test]
fn impact_awin_and_cj_share_the_typed_network_contract() {
    let at = observed_at();
    let impact_world = ImpactFixtureWorld::default_fixture(at);
    let awin_world = AwinFixtureWorld::default_fixture(at);
    let cj_world = CjFixtureWorld::default_fixture(at);

    let mut impact = ImpactAdapter::new(impact_world.clone());
    let impact_scope = impact_world.scope();
    let impact_expectation = impact_world.current_program_expectation();
    assert_fixture_adapter(
        &mut impact,
        &impact_scope,
        impact_world.authorization(),
        &impact_expectation,
        at,
    );

    let mut awin = AwinAdapter::new(awin_world.clone());
    let awin_scope = awin_world.scope();
    let awin_expectation = awin_world.current_program_expectation();
    assert_fixture_adapter(
        &mut awin,
        &awin_scope,
        awin_world.authorization(),
        &awin_expectation,
        at,
    );

    let mut cj = CjAdapter::new(cj_world.clone());
    let cj_scope = cj_world.scope();
    let cj_expectation = cj_world.current_program_expectation();
    assert_fixture_adapter(
        &mut cj,
        &cj_scope,
        cj_world.authorization(),
        &cj_expectation,
        at,
    );
}

#[test]
fn merged_connector_sdk_bridge_keeps_fixture_probe_out_of_connected_authority()
-> Result<(), hartevo_connector_sdk::ConnectorError> {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let network_scope = world.scope();
    let sdk_scope = ConnectorScope::new(
        network_scope.tenant_id.clone(),
        network_scope.project_id.clone(),
        "impact",
        network_scope.account_id.as_str(),
        [
            "partner.read".to_owned(),
            format!(
                "program:{}",
                network_scope.program_id.as_ref().expect("program").as_str()
            ),
        ],
    )?;
    let bridge = ConnectorAdapterBridge::with_program_expectation(
        ImpactAdapter::new(world.clone()),
        world.current_program_expectation(),
    )?;
    let descriptor = bridge.descriptor().clone();
    let registry =
        ProviderAdapterRegistry::new("partner-fixture-sdk-1", descriptor.registrations().to_vec())?;
    let mut worker = ConnectorWorker::new(
        "worker-impact-sdk",
        bridge,
        registry,
        sdk_scope.clone(),
        at,
        at + Duration::minutes(5),
    )?;
    let secret = SecretReference::new("secret-ref-impact-fixture", sdk_scope.clone(), 1)?;
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        descriptor.identity().clone(),
        "credential-lease-impact-fixture",
        1,
        at,
        at + Duration::minutes(5),
    )?;
    let dispatch = worker.dispatch_fence();
    let session = worker.begin_auth(BeginAuthRequest {
        dispatch: dispatch.clone(),
        scope: sdk_scope.clone(),
        secret_reference: secret.clone(),
        credential_lease: lease.clone(),
        auth_revision: 1,
        issued_at: at,
        expires_at: at + Duration::minutes(5),
    })?;
    let probe = worker.probe(ProbeRequest {
        dispatch,
        scope: sdk_scope,
        secret_reference: secret,
        credential_lease: lease,
        session,
        probe_revision: 1,
        result_id: "probe-result-impact-fixture".to_owned(),
        at: at + Duration::seconds(1),
    })?;
    assert_eq!(probe.provenance_class(), ProviderProvenanceClass::Fixture);
    assert_eq!(
        probe.status(),
        hartevo_connector_sdk::ProbeStatus::Reachable
    );
    assert_eq!(
        worker.authorize_probe(&probe, at + Duration::seconds(1)),
        Err(hartevo_connector_sdk::ConnectorError::UnsupportedProvenance)
    );
    let conversion_key = ProviderCapabilityKey::new("impact", "partner.conversion.read")?;
    assert!(worker.descriptor().supports(
        &conversion_key,
        ProviderAdapterOperation::Read,
        ProviderProvenanceClass::Fixture,
    ));
    Ok(())
}

#[test]
fn missing_commercial_authorization_is_not_connected_or_e4() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let scope = world.scope();
    let expectation = world.current_program_expectation();
    let adapter = ImpactAdapter::without_authorization();

    let probe = adapter
        .probe(NetworkProbeRequest::for_program(
            scope.clone(),
            expectation.clone(),
            at,
        ))
        .expect("missing auth is a probe outcome");
    assert_eq!(probe.status, NetworkProbeStatus::AuthorizationRequired);
    assert!(!probe.can_claim_connected());
    assert!(matches!(
        probe.provenance,
        crate::NetworkProvenance::Fixture
    ));

    let read = adapter.read(NetworkReadRequest::for_program(
        scope,
        NetworkResource::Partners,
        expectation,
        at,
    ));
    assert!(matches!(
        read,
        Err(PartnerNetworkError::AuthorizationRequired { .. })
    ));
}

#[test]
fn authorized_but_unconfigured_transport_is_blocked_env() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let scope = world.scope();
    let expectation = world.current_program_expectation();
    let mut adapter = ImpactAdapter::without_authorization();
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture grant is valid");

    let probe = adapter
        .probe(NetworkProbeRequest::for_program(scope, expectation, at))
        .expect("blocked transport is a probe outcome");
    assert_eq!(probe.status, NetworkProbeStatus::BlockedEnv);
    assert!(!probe.can_claim_connected());
}

#[test]
fn impact_signed_callbacks_dedupe_conversions_and_preserve_out_of_order_events() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let scope = world.scope();
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture grant is valid");

    let first_body = world.callback_body(
        "impact-event-1",
        "conversion.recorded",
        at - Duration::hours(1),
        Some("impact-conversion-1"),
        Some("impact-order-1"),
        Some("impact-action-1"),
        Some("impact-commission-1"),
        None,
        None,
        Some(10_000),
    );
    let first_signature =
        world.sign_callback(CallbackSignatureScheme::ImpactHookHmacSha1, &first_body);
    let first = adapter
        .handle_callback(CallbackRequest {
            scope: scope.clone(),
            channel: CallbackChannel::Webhook,
            body: &first_body,
            signature: &first_signature,
            signature_key: ImpactFixtureWorld::callback_key(),
            scheme: CallbackSignatureScheme::ImpactHookHmacSha1,
            received_at: at,
        })
        .expect("signed callback is accepted");
    assert_eq!(first.disposition, CallbackDisposition::Accepted);
    assert!(first.signature_verified);

    let duplicate_body = world.callback_body(
        "impact-event-2",
        "conversion.recorded",
        at - Duration::minutes(50),
        Some("impact-conversion-1"),
        Some("impact-order-1"),
        Some("impact-action-1"),
        Some("impact-commission-1"),
        None,
        None,
        Some(10_000),
    );
    let duplicate_signature =
        world.sign_callback(CallbackSignatureScheme::FixtureHmacSha256, &duplicate_body);
    let duplicate = adapter
        .handle_callback(CallbackRequest {
            scope: scope.clone(),
            channel: CallbackChannel::Postback,
            body: &duplicate_body,
            signature: &duplicate_signature,
            signature_key: ImpactFixtureWorld::callback_key(),
            scheme: CallbackSignatureScheme::FixtureHmacSha256,
            received_at: at,
        })
        .expect("duplicate callback is safely classified");
    assert_eq!(duplicate.disposition, CallbackDisposition::Duplicate);
    assert_eq!(adapter.accepted_callbacks().len(), 1);

    let out_of_order_body = world.callback_body(
        "impact-event-3",
        "conversion.recorded",
        at - Duration::hours(2),
        Some("impact-conversion-2"),
        Some("impact-order-2"),
        Some("impact-action-2"),
        Some("impact-commission-2"),
        None,
        None,
        Some(5_000),
    );
    let out_of_order_signature = world.sign_callback(
        CallbackSignatureScheme::FixtureHmacSha256,
        &out_of_order_body,
    );
    let out_of_order = adapter
        .handle_callback(CallbackRequest {
            scope,
            channel: CallbackChannel::Webhook,
            body: &out_of_order_body,
            signature: &out_of_order_signature,
            signature_key: ImpactFixtureWorld::callback_key(),
            scheme: CallbackSignatureScheme::FixtureHmacSha256,
            received_at: at,
        })
        .expect("out-of-order callback is retained with disposition");
    assert_eq!(out_of_order.disposition, CallbackDisposition::OutOfOrder);
    assert_eq!(adapter.accepted_callbacks().len(), 2);
}

#[test]
fn impact_production_detached_jws_requires_an_injected_verifier() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture grant is valid");
    let body = world.callback_body(
        "impact-jws-event-1",
        "conversion.recorded",
        at - Duration::minutes(1),
        Some("impact-conversion-jws"),
        Some("impact-order-jws"),
        Some("impact-action-jws"),
        Some("impact-commission-jws"),
        None,
        None,
        Some(10_000),
    );
    let result = adapter.handle_callback(CallbackRequest {
        scope: world.scope(),
        channel: CallbackChannel::Webhook,
        body: &body,
        signature: "detached-jws-header..signature",
        signature_key: b"jwks-key-reference",
        scheme: CallbackSignatureScheme::ImpactHookJwsDetached,
        received_at: at,
    });
    assert!(matches!(
        result,
        Err(PartnerNetworkError::BlockedEnv {
            provider: crate::NetworkProvider::Impact,
            reason: crate::BlockedEnvironmentReason::ProductionCallbackVerifierRequired,
        })
    ));
}

#[test]
fn settlement_fixtures_keep_refunds_reversals_and_payouts_explicit() {
    let at = observed_at();

    let refund_world = ImpactFixtureWorld::new(FixtureScenario::CrossPeriodRefund, at);
    let mut refund_adapter = ImpactAdapter::new(refund_world.clone());
    refund_adapter
        .authorize(refund_world.authorization(), at)
        .expect("fixture grant is valid");
    let refund_report = refund_adapter
        .read(NetworkReadRequest::for_program(
            refund_world.scope(),
            NetworkResource::Reports,
            refund_world.current_program_expectation(),
            at,
        ))
        .expect("cross-period refund report reads");
    let NetworkReadData::Reports { records } = refund_report.data else {
        panic!("expected reports");
    };
    assert_eq!(
        records[0].settlement_state,
        ReportSettlementState::RecalculationRequired
    );
    assert!(records[0].period.started_at > records[0].commissions[0].occurred_at);
    assert_eq!(records[0].reversals[0].state, ReversalState::Applied);
    assert_eq!(records[0].commissions[0].state, CommissionState::Reversed);
    let refund_conversions = refund_adapter
        .read(NetworkReadRequest::for_program(
            refund_world.scope(),
            NetworkResource::Conversions,
            refund_world.current_program_expectation(),
            at,
        ))
        .expect("refunded conversion reads");
    let NetworkReadData::Conversions { records } = refund_conversions.data else {
        panic!("expected conversions");
    };
    assert_eq!(records[0].state, ConversionState::Refunded);

    let reversal_world = AwinFixtureWorld::new(FixtureScenario::CommissionReversal, at);
    let mut reversal_adapter = AwinAdapter::new(reversal_world.clone());
    reversal_adapter
        .authorize(reversal_world.authorization(), at)
        .expect("fixture grant is valid");
    let action_read = reversal_adapter
        .read(NetworkReadRequest::for_program(
            reversal_world.scope(),
            NetworkResource::Actions,
            reversal_world.current_program_expectation(),
            at,
        ))
        .expect("reversed action reads");
    let NetworkReadData::Actions { records } = action_read.data else {
        panic!("expected actions");
    };
    assert_eq!(records[0].state, ActionState::Reversed);
    let reversal_read = reversal_adapter
        .read(NetworkReadRequest::for_program(
            reversal_world.scope(),
            NetworkResource::Reversals,
            reversal_world.current_program_expectation(),
            at,
        ))
        .expect("reversal reads");
    let NetworkReadData::Reversals { records } = reversal_read.data else {
        panic!("expected reversals");
    };
    assert_eq!(records[0].state, ReversalState::Applied);

    let payout_world = CjFixtureWorld::new(FixtureScenario::DelayedPayout, at);
    let mut payout_adapter = CjAdapter::new(payout_world.clone());
    payout_adapter
        .authorize(payout_world.authorization(), at)
        .expect("fixture grant is valid");
    let payout_read = payout_adapter
        .read(NetworkReadRequest::for_program(
            payout_world.scope(),
            NetworkResource::Reports,
            payout_world.current_program_expectation(),
            at,
        ))
        .expect("delayed payout report reads");
    let NetworkReadData::Reports { records } = payout_read.data else {
        panic!("expected reports");
    };
    assert_eq!(
        records[0].settlement_state,
        ReportSettlementState::Outstanding
    );
    assert_eq!(records[0].payouts[0].state, crate::PayoutState::Pending);
    let payout_list = payout_adapter
        .read(NetworkReadRequest::for_program(
            payout_world.scope(),
            NetworkResource::Payouts,
            payout_world.current_program_expectation(),
            at,
        ))
        .expect("pending payout list reads");
    let NetworkReadData::Payouts { records } = payout_list.data else {
        panic!("expected payouts");
    };
    assert_eq!(records[0].state, crate::PayoutState::Pending);
}

#[test]
fn scope_revoke_and_program_drift_are_distinct_outcomes() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture grant is valid");
    adapter
        .revoke(&world.account_scope(), at + Duration::minutes(1))
        .expect("account scope can be revoked");
    let revoked_probe = adapter
        .probe(NetworkProbeRequest::for_program(
            world.scope(),
            world.current_program_expectation(),
            at + Duration::minutes(1),
        ))
        .expect("revocation is a probe outcome");
    assert_eq!(revoked_probe.status, NetworkProbeStatus::ScopeRevoked);
    assert!(matches!(
        adapter.read(NetworkReadRequest::for_program(
            world.scope(),
            NetworkResource::Partners,
            world.current_program_expectation(),
            at + Duration::minutes(1),
        )),
        Err(PartnerNetworkError::ScopeRevoked)
    ));

    let drift_world = CjFixtureWorld::new(FixtureScenario::ProgramDrift, at);
    let mut drift_adapter = CjAdapter::new(drift_world.clone());
    drift_adapter
        .authorize(drift_world.authorization(), at)
        .expect("fixture grant is valid");
    let drift_probe = drift_adapter
        .probe(NetworkProbeRequest::for_program(
            drift_world.scope(),
            drift_world.original_program_expectation(),
            at,
        ))
        .expect("program drift is a probe outcome");
    assert_eq!(drift_probe.status, NetworkProbeStatus::ProgramDrift);
    assert!(matches!(
        drift_adapter.read(NetworkReadRequest::for_program(
            drift_world.scope(),
            NetworkResource::Programs,
            drift_world.original_program_expectation(),
            at,
        )),
        Err(PartnerNetworkError::ProgramDrift)
    ));
}

#[test]
fn duplicate_conversion_fixture_is_rejected_as_duplicate_identity() {
    let at = observed_at();
    let world = ImpactFixtureWorld::new(FixtureScenario::DuplicateConversion, at);
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture grant is valid");
    assert!(matches!(
        adapter.read(NetworkReadRequest::for_program(
            world.scope(),
            NetworkResource::Conversions,
            world.current_program_expectation(),
            at,
        )),
        Err(PartnerNetworkError::DuplicateIdentity)
    ));
}

#[test]
fn typed_identities_and_scope_coverage_reject_ambiguous_authority() {
    assert!(NetworkAccountId::parse(" ").is_err());
    assert!(ProgramId::parse("program\n1").is_err());
    assert!(crate::OpaqueSecretReference::new("opaque", 0).is_err());

    let account = NetworkScope::account_scope(
        "tenant",
        "project",
        NetworkAccountId::from_stable("account-1"),
    )
    .expect("account scope");
    let program = NetworkScope::program_scope(
        "tenant",
        "project",
        NetworkAccountId::from_stable("account-1"),
        ProgramId::from_stable("program-1"),
    )
    .expect("program scope");
    assert!(account.covers(&program));
    assert!(!program.covers(&account));
}

#[test]
fn program_scoped_authorization_does_not_cover_the_account() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(world.clone());
    let mut grant = world.authorization();
    grant.scope = world.scope();
    adapter
        .authorize(grant, at)
        .expect("program-scoped fixture grant is valid");

    let program_probe = adapter
        .probe(NetworkProbeRequest::for_program(
            world.scope(),
            world.current_program_expectation(),
            at,
        ))
        .expect("program scope is authorized");
    assert_eq!(program_probe.status, NetworkProbeStatus::Reachable);

    let account_probe = adapter
        .probe(NetworkProbeRequest::new(world.account_scope(), at))
        .expect("account denial is a probe outcome");
    assert_eq!(
        account_probe.status,
        NetworkProbeStatus::AuthorizationRequired
    );
    assert!(matches!(
        adapter.read(NetworkReadRequest::new(
            world.account_scope(),
            NetworkResource::Partners,
            at,
        )),
        Err(PartnerNetworkError::AuthorizationRequired { .. })
    ));
}
