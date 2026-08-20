use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_connector_sdk::{
    BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorScope, ConnectorWorker,
    ProbeRequest, ProviderAdapterOperation, ProviderAdapterRegistry, ProviderCapabilityKey,
    ProviderProvenanceClass, SecretReference, WebhookEnvelope, WebhookRequest, WebhookSigningKey,
};
use serde_json::Value;

use crate::awin::{AwinAdapter, AwinFixtureWorld};
use crate::cj_legacy::{CjAdapter, CjFixtureWorld};
use crate::contract::TypedPartnerNetworkAdapter;
use crate::impact::{
    ImpactAdapter, ImpactApi, ImpactApiError, ImpactFixtureWorld, ImpactProbeResponse,
    ImpactReadResponse,
};
use crate::{
    ActionState, AuthorizationState, CallbackChannel, CallbackDisposition, CallbackKeyLease,
    CallbackRequest, CallbackSignatureScheme, CommissionState, ConnectorAdapterBridge,
    ConversionState, FixtureScenario, MissionOutcomeBinding, NetworkAccountId, NetworkProbeRequest,
    NetworkProbeStatus, NetworkReadData, NetworkReadRequest, NetworkResource, NetworkScope,
    OpaqueSecretReference, PartnerMissionConsumer, PartnerNetworkError, ProgramId, ReadCursor,
    ReportSettlementState, ReversalState, SettlementPeriod, deserialize_partner_read_observation,
    native_canary_plan, validate_published_partner_schema,
};

fn observed_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn fixture_callback_key(
    at: DateTime<Utc>,
    scope: &NetworkScope,
    scheme: CallbackSignatureScheme,
) -> CallbackKeyLease {
    CallbackKeyLease::bound(
        OpaqueSecretReference::fixture(),
        ImpactFixtureWorld::callback_key(),
        at + Duration::hours(1),
        crate::NetworkProvider::Impact,
        scope.clone(),
        crate::NetworkProvenance::Fixture,
        scheme,
    )
    .expect("fixture callback key lease")
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
#[allow(clippy::too_many_lines)]
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
        scope: sdk_scope.clone(),
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
    let outcome_key = ProviderCapabilityKey::new("impact", "outcome.ingest")?;
    assert!(worker.descriptor().supports(
        &outcome_key,
        hartevo_connector_sdk::ProviderAdapterOperation::HandleWebhook,
        ProviderProvenanceClass::Fixture,
    ));
    let webhook_key = WebhookSigningKey::new(b"partner-generic-webhook-key")?;
    let envelope = WebhookEnvelope::sign(
        &sdk_scope,
        descriptor.identity().clone(),
        "webhook-event-impact-1",
        1,
        at + Duration::seconds(2),
        at + Duration::seconds(2),
        crate::contract::digest_bytes(b"generic-webhook-payload"),
        &webhook_key,
    )?;
    let webhook = worker.handle_webhook(
        WebhookRequest {
            dispatch: worker.dispatch_fence(),
            scope: sdk_scope.clone(),
            envelope,
            at: at + Duration::seconds(2),
        },
        &webhook_key,
    )?;
    assert_eq!(webhook.event_id(), "webhook-event-impact-1");
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
    let key_lease = fixture_callback_key(at, &scope, CallbackSignatureScheme::ImpactHookHmacSha1);

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
            signature_key: &key_lease,
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
    let duplicate_key_lease =
        fixture_callback_key(at, &scope, CallbackSignatureScheme::FixtureHmacSha256);
    let duplicate = adapter
        .handle_callback(CallbackRequest {
            scope: scope.clone(),
            channel: CallbackChannel::Postback,
            body: &duplicate_body,
            signature: &duplicate_signature,
            signature_key: &duplicate_key_lease,
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
    let out_of_order_key_lease =
        fixture_callback_key(at, &scope, CallbackSignatureScheme::FixtureHmacSha256);
    let out_of_order = adapter
        .handle_callback(CallbackRequest {
            scope,
            channel: CallbackChannel::Webhook,
            body: &out_of_order_body,
            signature: &out_of_order_signature,
            signature_key: &out_of_order_key_lease,
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
    let key_lease = fixture_callback_key(
        at,
        &world.scope(),
        CallbackSignatureScheme::ImpactHookJwsDetached,
    );
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
        signature_key: &key_lease,
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

#[derive(Clone, Debug)]
struct ProductionClaimingImpactApi {
    world: ImpactFixtureWorld,
}

impl ImpactApi for ProductionClaimingImpactApi {
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ImpactProbeResponse, ImpactApiError> {
        let mut response = ImpactApi::probe(&self.world, authorization, request)?;
        response.provenance = crate::NetworkProvenance::ProductionProvider;
        Ok(response)
    }

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ImpactReadResponse, ImpactApiError> {
        let mut response = ImpactApi::read(&self.world, authorization, request)?;
        response.provenance = crate::NetworkProvenance::ProductionProvider;
        Ok(response)
    }
}

#[test]
fn provider_returned_production_provenance_is_sealed_without_native_canary() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(ProductionClaimingImpactApi {
        world: world.clone(),
    });
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture authorization is valid");
    let result = adapter.probe(NetworkProbeRequest::for_program(
        world.scope(),
        world.current_program_expectation(),
        at,
    ));
    assert!(matches!(
        result,
        Err(PartnerNetworkError::BlockedEnv {
            provider: crate::NetworkProvider::Impact,
            reason: crate::BlockedEnvironmentReason::OfficialApiCapabilityNotEnabled,
        })
    ));
}

#[test]
fn caller_supplied_production_grant_is_sealed_at_authorize() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut grant = serde_json::to_value(world.authorization()).expect("grant JSON");
    grant["provenance"] = Value::String("production_provider".into());
    let production: crate::AuthorizationGrant = serde_json::from_value(grant)
        .expect("typed production input is parseable but not authorized");
    let mut adapter = ImpactAdapter::without_authorization();
    assert!(matches!(
        adapter.authorize(production, at),
        Err(PartnerNetworkError::BlockedEnv {
            provider: crate::NetworkProvider::Impact,
            reason: crate::BlockedEnvironmentReason::OfficialApiCapabilityNotEnabled,
        })
    ));
}

#[test]
fn raw_unattested_production_read_observation_is_rejected() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture authorization is valid");
    let mut observation = adapter
        .read(NetworkReadRequest::for_program(
            world.scope(),
            NetworkResource::Reports,
            world.current_program_expectation(),
            at,
        ))
        .expect("fixture read");
    observation.provenance = crate::NetworkProvenance::ProductionProvider;
    observation.evidence_digest = crate::contract::read_observation_evidence_digest(&observation)
        .expect("rebound raw evidence");
    assert!(matches!(
        observation.validate(),
        Err(PartnerNetworkError::NativeCanaryRequired)
    ));
}

#[test]
fn layer_two_canary_plan_has_executable_blocked_transition() {
    let plan = native_canary_plan();
    assert_eq!(plan.required_steps.len(), 5);
    assert_eq!(plan.acceptance.len(), 5);
    assert_eq!(plan.blocked_transition, "NOT_PROVEN/BLOCKED_ENV");
    let receipt = crate::NativeCanaryReceipt::blocked(1, observed_at())
        .expect("blocked canary receipt is typed");
    assert_eq!(receipt.status, crate::NativeCanaryStatus::NotProven);
    assert!(!receipt.is_attested());
}

#[test]
fn mission_consumer_requires_program_window_and_preserves_fixture_honesty() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture authorization is valid");
    let window = SettlementPeriod::new(at - Duration::days(30), at).expect("window");
    let request = NetworkReadRequest::for_program(
        world.scope(),
        NetworkResource::Reports,
        world.current_program_expectation(),
        at,
    )
    .with_window(window.clone())
    .expect("valid window");
    let observation = adapter.read(request).expect("fixture report read");
    let binding = MissionOutcomeBinding::new(
        observation.authorization_revision,
        observation.authorization_generation.clone(),
        observation.adapter_version,
        observation.registration_identity.clone(),
        observation.registration_digest.clone(),
    )
    .expect("exact Mission authority binding");
    let consumer = PartnerMissionConsumer::new(
        crate::NetworkProvider::Impact,
        world.scope(),
        world.current_program_expectation(),
        window,
        binding,
    )
    .expect("exact Mission binding");
    let receipt = consumer.consume(&observation).expect("Mission evidence");
    assert_eq!(
        receipt.classification,
        crate::MissionOutcomeClassification::FixtureEvidence
    );
    assert!(!receipt.claim_connected);
    assert_eq!(receipt.source_digest, observation.source_digest);
    assert!(!receipt.evidence_digest.is_empty());
}

#[test]
fn strict_contract_deserialization_rejects_unknown_fields_and_invalid_ids() {
    let extra_reference = r#"{"referenceId":"opaque","revision":1,"extra":true}"#;
    assert!(crate::deserialize_partner_contract::<OpaqueSecretReference>(extra_reference).is_err());
    let invalid_id = r"";
    assert!(crate::deserialize_partner_contract::<crate::ProgramId>(invalid_id).is_err());
    assert!(crate::PARTNER_NETWORK_CONTRACT_SCHEMA.contains("additionalProperties"));
}

#[test]
fn published_schema_round_trip_and_adversarial_drift_fail_closed() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture authorization is valid");
    let observation = adapter
        .read(NetworkReadRequest::for_program(
            world.scope(),
            NetworkResource::Reports,
            world.current_program_expectation(),
            at,
        ))
        .expect("fixture read");
    let json = serde_json::to_string(&observation).expect("observation JSON");
    validate_published_partner_schema(&json).expect("published schema accepts typed envelope");
    assert_eq!(
        deserialize_partner_read_observation(&json).expect("schema-to-serde round trip"),
        observation
    );

    let mut unknown: Value = serde_json::from_str(&json).expect("observation value");
    unknown
        .as_object_mut()
        .expect("observation object")
        .insert("futureField".into(), Value::Bool(true));
    let unknown_json = serde_json::to_string(&unknown).expect("unknown field JSON");
    assert!(validate_published_partner_schema(&unknown_json).is_err());

    let mut missing: Value = serde_json::from_str(&json).expect("observation value");
    missing
        .as_object_mut()
        .expect("observation object")
        .remove("evidenceDigest");
    let missing_json = serde_json::to_string(&missing).expect("missing field JSON");
    assert!(validate_published_partner_schema(&missing_json).is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn durable_state_reopens_replay_and_rotation_fences_old_cursor() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let state_path = std::env::temp_dir().join(format!(
        "hartevo-partner-state-{}-{}.json",
        std::process::id(),
        "impact-repair"
    ));
    let _ = std::fs::remove_file(&state_path);
    let mut adapter = ImpactAdapter::with_state_file(world.clone(), state_path.clone())
        .expect("durable adapter state opens");
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture authorization is valid");
    let body = world.callback_body(
        "impact-durable-event-1",
        "conversion.recorded",
        at - Duration::minutes(1),
        Some("impact-durable-conversion"),
        Some("impact-durable-order"),
        Some("impact-durable-action"),
        Some("impact-durable-commission"),
        None,
        None,
        Some(10_000),
    );
    let signature = world.sign_callback(CallbackSignatureScheme::FixtureHmacSha256, &body);
    let key_lease = fixture_callback_key(
        at,
        &world.scope(),
        CallbackSignatureScheme::FixtureHmacSha256,
    );
    let first = adapter
        .handle_callback(CallbackRequest {
            scope: world.scope(),
            channel: CallbackChannel::Postback,
            body: &body,
            signature: &signature,
            signature_key: &key_lease,
            scheme: CallbackSignatureScheme::FixtureHmacSha256,
            received_at: at,
        })
        .expect("callback is durable");
    assert_eq!(first.disposition, CallbackDisposition::Accepted);
    assert!(adapter.durable_receipts().len() >= 2);
    drop(adapter);

    let mut reopened = ImpactAdapter::with_state_file(world.clone(), state_path.clone())
        .expect("durable state reopens");
    let reopened_key_lease = fixture_callback_key(
        at,
        &world.scope(),
        CallbackSignatureScheme::FixtureHmacSha256,
    );
    let duplicate = reopened
        .handle_callback(CallbackRequest {
            scope: world.scope(),
            channel: CallbackChannel::Postback,
            body: &body,
            signature: &signature,
            signature_key: &reopened_key_lease,
            scheme: CallbackSignatureScheme::FixtureHmacSha256,
            received_at: at + Duration::minutes(1),
        })
        .expect("replayed callback is classified");
    assert_eq!(duplicate.disposition, CallbackDisposition::Duplicate);
    assert_eq!(reopened.accepted_callbacks().len(), 1);

    let generation = "grant:fixture:opaque-secret-reference:1";
    let cursor = ReadCursor::bound(
        &world.scope(),
        NetworkResource::Reports,
        Some(&world.current_program_expectation()),
        None,
        generation,
        1,
        "provider-page-token",
    )
    .expect("bound cursor");
    let mut cursor_request = NetworkReadRequest::for_program(
        world.scope(),
        NetworkResource::Reports,
        world.current_program_expectation(),
        at,
    )
    .with_authorization_generation(generation);
    cursor_request.cursor = Some(cursor);
    reopened
        .read(cursor_request.clone())
        .expect("current credential accepts its cursor");
    assert!(
        reopened
            .durable_receipts()
            .iter()
            .any(|receipt| receipt.kind == "read.budget")
    );

    let mut rotated = world.authorization();
    rotated.secret_reference =
        OpaqueSecretReference::new("rotated-reference", 2).expect("rotated opaque reference");
    reopened
        .authorize(rotated, at + Duration::minutes(2))
        .expect("credential rotation is recorded");
    assert!(matches!(
        reopened.read(cursor_request),
        Err(PartnerNetworkError::CursorBindingMismatch)
    ));
    reopened.unmount().expect("unmount removes durable state");
    assert!(!state_path.exists());
}

#[test]
fn replay_and_durable_receipts_enforce_explicit_bounds() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut replay = crate::replay::ReplayGuard::default();
    let mut rate_limited = false;
    let max_events = u32::try_from(crate::replay::MAX_REPLAY_EVENTS_PER_SCOPE)
        .expect("replay bound fits fixture index");
    for index in 0..=max_events {
        let body = world.callback_body(
            &format!("impact-rate-{index}"),
            "conversion.recorded",
            at - Duration::minutes(1),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let event = crate::callback::parse_callback(crate::NetworkProvider::Impact, &body)
            .expect("bounded replay event");
        if matches!(
            replay.ingest(&world.scope(), event, at),
            Err(PartnerNetworkError::ReplayRateLimited)
        ) {
            rate_limited = true;
            break;
        }
    }
    assert!(rate_limited, "replay rate policy must be executable");
    replay
        .validate()
        .expect("rate-limited replay remains bounded");

    let state = crate::state::AdapterState::new(crate::NetworkProvider::Impact);
    let event_digest = crate::contract::digest_bytes(b"bounded-event");
    let evidence_digest = crate::contract::digest_bytes(b"bounded-evidence");
    for _ in 0..2_000 {
        state
            .record_read_receipt(
                &world.scope(),
                1,
                event_digest.clone(),
                at,
                evidence_digest.clone(),
            )
            .expect("bounded durable receipt");
    }
    assert_eq!(state.durable_receipts().len(), 1_024);
}

#[test]
fn callback_debug_never_exposes_borrowed_key_material() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let key_lease = fixture_callback_key(
        at,
        &world.scope(),
        CallbackSignatureScheme::FixtureHmacSha256,
    );
    let request = CallbackRequest {
        scope: world.scope(),
        channel: CallbackChannel::Webhook,
        body: b"payload",
        signature: "signature",
        signature_key: &key_lease,
        scheme: CallbackSignatureScheme::FixtureHmacSha256,
        received_at: at,
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("super-secret-callback-key"));
    assert!(debug.contains("signature_key_present"));
}

#[test]
fn callback_lease_tuple_mismatch_and_unbound_keys_fail_closed() {
    let at = observed_at();
    let world = ImpactFixtureWorld::default_fixture(at);
    let mut adapter = ImpactAdapter::new(world.clone());
    adapter
        .authorize(world.authorization(), at)
        .expect("fixture authorization is valid");
    let body = world.callback_body(
        "impact-lease-fence",
        "conversion.recorded",
        at - Duration::minutes(1),
        Some("impact-lease-conversion"),
        Some("impact-lease-order"),
        Some("impact-lease-action"),
        Some("impact-lease-commission"),
        None,
        None,
        Some(100),
    );
    let signature = world.sign_callback(CallbackSignatureScheme::FixtureHmacSha256, &body);
    let unbound = CallbackKeyLease::new(
        OpaqueSecretReference::fixture(),
        ImpactFixtureWorld::callback_key(),
        at + Duration::hours(1),
    )
    .expect("unbound key material");
    assert!(matches!(
        adapter.handle_callback(CallbackRequest {
            scope: world.scope(),
            channel: CallbackChannel::Webhook,
            body: &body,
            signature: &signature,
            signature_key: &unbound,
            scheme: CallbackSignatureScheme::FixtureHmacSha256,
            received_at: at,
        }),
        Err(PartnerNetworkError::InvalidCallbackLease)
    ));

    let mismatched_scheme = fixture_callback_key(
        at,
        &world.scope(),
        CallbackSignatureScheme::ImpactHookHmacSha1,
    );
    assert!(matches!(
        adapter.handle_callback(CallbackRequest {
            scope: world.scope(),
            channel: CallbackChannel::Webhook,
            body: &body,
            signature: &signature,
            signature_key: &mismatched_scheme,
            scheme: CallbackSignatureScheme::FixtureHmacSha256,
            received_at: at,
        }),
        Err(PartnerNetworkError::InvalidCallbackLease)
    ));
}
