use chrono::{DateTime, Duration, TimeZone, Utc};

use crate::awin::{AwinAdapter, AwinFixtureWorld};
use crate::cj::{CjAdapter, CjFixtureWorld};
use crate::impact::{ImpactAdapter, ImpactFixtureWorld};
use crate::{
    ActionState, AuthorizationState, CallbackChannel, CallbackDisposition, CallbackRequest,
    CallbackSignatureScheme, CommissionState, ConversionState, FixtureScenario, NetworkAccountId,
    NetworkProbeRequest, NetworkProbeStatus, NetworkReadData, NetworkReadRequest, NetworkResource,
    NetworkScope, PartnerNetworkAdapter, PartnerNetworkError, ProgramId, ReportSettlementState,
    ReversalState,
};

fn observed_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
        .single()
        .expect("valid fixture timestamp")
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
    adapter: &mut dyn PartnerNetworkAdapter,
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
