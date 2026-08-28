use chrono::{DateTime, Duration, Utc};
use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginRuntime, PluginScope as RuntimePluginScope,
    ProjectId as RuntimeProjectId,
};
use serde_json::to_string;

use hartevo_shippo_fulfillment_result_plugin::{
    BlockedEnvCredentialResolver, FulfillmentStatus, MissionShippoFulfillmentConsumer,
    NativeProbeStatus, ProviderRevision, ProviderTrackingStatus, RecordingShippoTransport,
    SecretReference, SecretReferenceResolver, ShippoCredential, ShippoEndpoint,
    ShippoFulfillmentError, ShippoFulfillmentResultContract, ShippoHttpRequest, ShippoHttpResponse,
    ShippoObjectState, ShippoProvider, ShippoReadRequest, ShippoResponseBody, ShippoScope,
    ShippoScopeInput, ShippoShipmentPayload, ShippoTrackingEventPayload, ShippoTrackingPayload,
    ShippoTransactionPayload, TransactionId, TransactionStatus, TransportProvenance,
    contract_digest, native_probe_from_environment, plugin_definition, sha256_digest,
};

#[derive(Clone, Debug)]
struct FixtureResolver {
    token: String,
}

impl SecretReferenceResolver for FixtureResolver {
    fn resolve(
        &self,
        secret_reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<
        hartevo_shippo_fulfillment_result_plugin::CredentialLease,
        hartevo_shippo_fulfillment_result_plugin::CredentialError,
    > {
        ShippoCredential::new(self.token.clone()).and_then(|credential| {
            hartevo_shippo_fulfillment_result_plugin::CredentialLease::new(
                "fixture-lease",
                secret_reference.clone(),
                secret_reference.credential_revision(),
                at,
                at + Duration::minutes(5),
                credential,
            )
        })
    }
}

fn at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .expect("fixed test time")
        .with_timezone(&Utc)
}

fn scope() -> ShippoScope {
    ShippoScope::new(ShippoScopeInput {
        account_id: "account-1".to_owned(),
        organization_id: "fulfillment-team".to_owned(),
        carrier: "usps".to_owned(),
        shipment_id: "shipment-1".to_owned(),
        transaction_id: Some("transaction-1".to_owned()),
        tracking_number: Some("9400111899223856928499".to_owned()),
        project_id: "project-1".to_owned(),
        project_revision: 4,
        mission_id: "mission-1".to_owned(),
        mission_revision: 7,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 3,
        consent_scope: "fulfillment-status-read".to_owned(),
        consent_revision: 2,
    })
    .expect("scope")
}

fn response(
    endpoint: ShippoEndpoint,
    request: &ShippoReadRequest,
    status: u16,
    body: ShippoResponseBody,
) -> ShippoHttpResponse {
    let http_request = ShippoHttpRequest::new(endpoint, request, 0).expect("request");
    ShippoHttpResponse::new(
        &http_request,
        status,
        "2018-02-08",
        body,
        128,
        sha256_digest(b"fixture-provider-response"),
        ProviderRevision::parse("shippo-rest-2018-02-08-r1").expect("provider revision"),
        None,
    )
    .expect("response")
}

fn provider(at: DateTime<Utc>) -> ShippoProvider<RecordingShippoTransport, FixtureResolver> {
    let scope = scope();
    let request = ShippoReadRequest::new();
    let shipment = ShippoShipmentPayload {
        shipment_id: hartevo_shippo_fulfillment_result_plugin::ShipmentId::parse("shipment-1")
            .expect("shipment id"),
        account_id: Some(
            hartevo_shippo_fulfillment_result_plugin::AccountId::parse("account-1")
                .expect("account id"),
        ),
        object_state: Some(ShippoObjectState::Valid),
        parcel_count: 1,
        has_origin_address: true,
        has_destination_address: true,
        has_customs_data: false,
        revision: 11,
    };
    let transaction = ShippoTransactionPayload {
        transaction_id: TransactionId::parse("transaction-1").expect("transaction id"),
        account_id: Some(
            hartevo_shippo_fulfillment_result_plugin::AccountId::parse("account-1")
                .expect("account id"),
        ),
        shipment_id: Some(
            hartevo_shippo_fulfillment_result_plugin::ShipmentId::parse("shipment-1")
                .expect("shipment id"),
        ),
        status: TransactionStatus::Success,
        tracking_number: Some(
            hartevo_shippo_fulfillment_result_plugin::TrackingNumber::parse(
                "9400111899223856928499",
            )
            .expect("tracking number"),
        ),
        tracking_status: Some(ProviderTrackingStatus::Delivered),
        revision: 12,
    };
    let tracking = ShippoTrackingPayload {
        carrier: hartevo_shippo_fulfillment_result_plugin::CarrierCode::parse("usps")
            .expect("carrier"),
        tracking_number: hartevo_shippo_fulfillment_result_plugin::TrackingNumber::parse(
            "9400111899223856928499",
        )
        .expect("tracking number"),
        latest_status: Some(ProviderTrackingStatus::Delivered),
        events: vec![ShippoTrackingEventPayload {
            status: ProviderTrackingStatus::Delivered,
            status_at: Some(at - Duration::hours(1)),
            location_present: true,
            status_detail_present: true,
            action_required: false,
        }],
        eta: Some(at),
        original_eta: Some(at - Duration::days(1)),
        has_sender_address: true,
        has_recipient_address: true,
        service_level_present: true,
        revision: 13,
    };
    let responses = [
        Ok(response(
            ShippoEndpoint::shipment("shipment-1").expect("endpoint"),
            &request,
            200,
            ShippoResponseBody::Shipment(shipment),
        )),
        Ok(response(
            ShippoEndpoint::transaction("transaction-1").expect("endpoint"),
            &request,
            200,
            ShippoResponseBody::Transaction(transaction),
        )),
        Ok(response(
            ShippoEndpoint::tracking("usps", "9400111899223856928499").expect("endpoint"),
            &request,
            200,
            ShippoResponseBody::Tracking(tracking),
        )),
    ];
    ShippoProvider::new(
        scope,
        SecretReference::new("host/shippo/account-1", 5).expect("secret reference"),
        RecordingShippoTransport::fixture(responses),
        FixtureResolver {
            token: "fixture-token".to_owned(),
        },
        at,
    )
    .expect("provider")
}

#[test]
fn contract_definition_and_native_gap_are_closed() {
    let contract = ShippoFulfillmentResultContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(contract.api_version, "2018-02-08");
    assert!(contract.read_only);
    assert!(contract.mutating_provider_operations.is_empty());
    assert!(!contract.authority.connected);
    assert!(!contract.authority.recipient_pii);
    assert!(!contract.authority.raw_tracking_payload);

    let runtime_scope = RuntimePluginScope::new(
        RuntimeProjectId::new("project-1").expect("runtime project"),
        RuntimeMissionId::new("mission-1").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = plugin_definition(runtime_scope.clone()).expect("definition");
    assert_eq!(definition.scope(), &runtime_scope);
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition).expect("define");
    runtime.mount(&handle).expect("mount");
    runtime.revoke(&handle).expect("revoke");
}

#[test]
fn bounded_read_normalizes_tracking_and_compiles_inert_proposal() {
    let at = at();
    let mut provider = provider(at);
    let consumer = MissionShippoFulfillmentConsumer::new(scope());
    let result = consumer
        .read(&mut provider, &ShippoReadRequest::new(), at)
        .expect("read");
    result.validate(&scope()).expect("result validation");
    assert_eq!(result.evidence.status, FulfillmentStatus::Delivered);
    assert_eq!(
        result
            .evidence
            .shipment
            .as_ref()
            .expect("shipment")
            .revision,
        11
    );
    assert_eq!(
        result
            .evidence
            .tracking
            .as_ref()
            .expect("tracking")
            .event_count,
        1
    );
    assert!(!result.evidence.native_evidence);
    assert!(!result.evidence.connected);
    assert!(!result.evidence.external_write_performed);
    assert!(!result.evidence.outcome_authority);
    assert!(result.proposal.requested_effects.is_empty());
    assert!(
        result
            .proposal
            .forbidden_effects
            .iter()
            .any(|effect| effect == "purchase_label")
    );
    assert_eq!(
        consumer
            .consume_evidence(result.evidence.clone())
            .expect_err("duplicate evidence must be rejected"),
        ShippoFulfillmentError::StaleEvidence
    );
    assert!(provider.transport().requests().iter().all(|request| {
        request.method == "GET"
            && request.api_version == "2018-02-08"
            && request.path_and_query().expect("path").starts_with('/')
    }));
    assert_eq!(provider.transport().requests().len(), 3);

    let serialized = to_string(&result).expect("result JSON");
    assert!(!serialized.contains("fixture-token"));
    assert!(!serialized.contains("recipient@example.com"));
    assert!(!serialized.contains("123 Main Street"));
    assert!(!serialized.contains("label_url"));
    assert!(!serialized.contains("raw tracking"));
}

#[test]
fn absence_of_tracking_events_is_a_retention_gap_not_delivery() {
    let at = at();
    let scope = scope();
    let request = ShippoReadRequest::new();
    let shipment = ShippoShipmentPayload {
        shipment_id: hartevo_shippo_fulfillment_result_plugin::ShipmentId::parse("shipment-1")
            .expect("shipment"),
        account_id: None,
        object_state: Some(ShippoObjectState::Valid),
        parcel_count: 1,
        has_origin_address: false,
        has_destination_address: false,
        has_customs_data: false,
        revision: 1,
    };
    let tracking = ShippoTrackingPayload {
        carrier: hartevo_shippo_fulfillment_result_plugin::CarrierCode::parse("usps")
            .expect("carrier"),
        tracking_number: hartevo_shippo_fulfillment_result_plugin::TrackingNumber::parse(
            "9400111899223856928499",
        )
        .expect("tracking"),
        latest_status: None,
        events: Vec::new(),
        eta: None,
        original_eta: None,
        has_sender_address: false,
        has_recipient_address: false,
        service_level_present: false,
        revision: 1,
    };
    let transaction = ShippoTransactionPayload {
        transaction_id: TransactionId::parse("transaction-1").expect("transaction"),
        account_id: None,
        shipment_id: Some(
            hartevo_shippo_fulfillment_result_plugin::ShipmentId::parse("shipment-1")
                .expect("shipment"),
        ),
        status: TransactionStatus::Success,
        tracking_number: None,
        tracking_status: None,
        revision: 1,
    };
    let responses = [
        Ok(response(
            ShippoEndpoint::shipment("shipment-1").expect("endpoint"),
            &request,
            200,
            ShippoResponseBody::Shipment(shipment),
        )),
        Ok(response(
            ShippoEndpoint::transaction("transaction-1").expect("endpoint"),
            &request,
            200,
            ShippoResponseBody::Transaction(transaction),
        )),
        Ok(response(
            ShippoEndpoint::tracking("usps", "9400111899223856928499").expect("endpoint"),
            &request,
            200,
            ShippoResponseBody::Tracking(tracking),
        )),
    ];
    let mut provider = ShippoProvider::new(
        scope.clone(),
        SecretReference::new("host/shippo/account-1", 5).expect("secret"),
        RecordingShippoTransport::fixture(responses),
        FixtureResolver {
            token: "fixture-token".to_owned(),
        },
        at,
    )
    .expect("provider");
    let evidence = provider.read(&request, at).expect("read");
    assert_eq!(evidence.status, FulfillmentStatus::RetentionGap);
    assert!(!evidence.status.is_delivery_claim());
    assert!(
        evidence
            .status_reasons
            .iter()
            .any(|reason| reason.contains("absence of tracking events"))
    );
}

#[test]
fn blocked_env_never_executes_transport_and_provenance_is_not_native() {
    let at = at();
    let scope = scope();
    let mut provider = ShippoProvider::new(
        scope,
        SecretReference::new("host/shippo/account-1", 5).expect("secret"),
        RecordingShippoTransport::fixture(Vec::<
            Result<
                ShippoHttpResponse,
                hartevo_shippo_fulfillment_result_plugin::ShippoTransportError,
            >,
        >::new()),
        BlockedEnvCredentialResolver,
        at,
    )
    .expect("provider");
    assert_eq!(
        provider
            .read(&ShippoReadRequest::new(), at)
            .expect_err("blocked env"),
        ShippoFulfillmentError::BlockedEnv
    );
    assert!(provider.transport().requests().is_empty());
    assert_eq!(
        native_probe_from_environment().status,
        NativeProbeStatus::BlockedEnv
    );
    assert!(!native_probe_from_environment().native_connected_claim);
    assert!(!TransportProvenance::Fixture.is_native());
    assert!(!TransportProvenance::Recording.is_connected());
    assert!(!TransportProvenance::Loopback.is_native());
    assert!(!TransportProvenance::BlockedEnv.is_connected());
}

#[test]
fn access_loss_is_normalized_without_retaining_provider_payload() {
    let at = at();
    let request = ShippoReadRequest::new();
    let response = response(
        ShippoEndpoint::shipment("shipment-1").expect("endpoint"),
        &request,
        403,
        ShippoResponseBody::Empty,
    );
    let mut provider = ShippoProvider::new(
        scope(),
        SecretReference::new("host/shippo/account-1", 5).expect("secret"),
        RecordingShippoTransport::fixture([Ok(response)]),
        FixtureResolver {
            token: "fixture-token".to_owned(),
        },
        at,
    )
    .expect("provider");
    let evidence = provider.read(&request, at).expect("access-loss evidence");
    assert_eq!(evidence.status, FulfillmentStatus::AccessLost);
    assert!(evidence.shipment.is_none());
    assert!(evidence.receipts.iter().all(|receipt| {
        !receipt.raw_payload_retained
            && !receipt.raw_tracking_payload_retained
            && !receipt.recipient_pii_retained
            && !receipt.credential_material_retained
    }));
}

#[test]
fn secret_reference_and_recordings_do_not_expose_credential_material() {
    let reference = SecretReference::new("vault/shippo/account-1", 9).expect("reference");
    assert!(!format!("{reference:?}").contains("vault/shippo/account-1"));
    let json = to_string(&reference).expect("reference JSON");
    assert!(json.contains("vault/shippo/account-1"));
    assert!(!json.contains("fixture-token"));
    let transport = RecordingShippoTransport::fixture(Vec::<
        Result<ShippoHttpResponse, hartevo_shippo_fulfillment_result_plugin::ShippoTransportError>,
    >::new());
    assert!(!format!("{transport:?}").contains("fixture-token"));
}
