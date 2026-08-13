use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{CurrencyCode, Money};
use ring::hmac;
use serde_json::json;

use crate::callback::CallbackSignatureScheme;
use crate::contract::{
    ActionRecord, ActionState, ClickRecord, CommissionRecord, CommissionState, ContractRecord,
    ContractState, ConversionRecord, ConversionState, FixtureScenario, NetworkProvider,
    NetworkReadData, NetworkResource, NetworkScope, PartnerNetworkError, PartnerRecord,
    PartnerRelationshipState, PayoutRecord, PayoutState, ProgramExpectation, ProgramRecord,
    ProgramState, ReadPage, ReportRecord, ReportRow, ReportSettlementState, ReversalRecord,
    ReversalState, SettlementPeriod, TrackingLinkRecord, canonical_digest, fixture_digest,
};
use crate::ids::{
    ActionId, ClickId, CommissionId, ContractId, ConversionId, LinkId, NetworkAccountId,
    NetworkOrderId, PartnerId, PayoutId, ProgramId, ReportId, ReversalId,
};

pub(crate) const FIXTURE_CALLBACK_KEY: &[u8] = b"hartevo-partner-fixture-callback-key-v1";

#[derive(Clone, Debug)]
pub(crate) struct PartnerFixtureWorld {
    pub(crate) scenario: FixtureScenario,
    pub(crate) account_id: NetworkAccountId,
    pub(crate) program_id: ProgramId,
    pub(crate) current_program_revision: u64,
    pub(crate) original_terms_digest: String,
    pub(crate) current_terms_digest: String,
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) data: Vec<(NetworkResource, NetworkReadData)>,
}

impl PartnerFixtureWorld {
    pub(crate) fn new(
        provider: NetworkProvider,
        scenario: FixtureScenario,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let account_id = NetworkAccountId::from_stable(format!("{}-account-1", provider.as_str()));
        let program_id = ProgramId::from_stable(format!("{}-program-1", provider.as_str()));
        let original_terms_digest = fixture_digest(&format!("{}-terms-v1", provider.as_str()));
        let (current_program_revision, current_terms_digest) =
            if scenario == FixtureScenario::ProgramDrift {
                (
                    2,
                    fixture_digest(&format!("{}-terms-v2", provider.as_str())),
                )
            } else {
                (1, original_terms_digest.clone())
            };
        let data = build_data(
            provider,
            &scenario,
            &account_id,
            &program_id,
            current_program_revision,
            &current_terms_digest,
            observed_at,
        );
        Self {
            scenario,
            account_id,
            program_id,
            current_program_revision,
            original_terms_digest,
            current_terms_digest,
            observed_at,
            data,
        }
    }

    pub(crate) fn account_scope(&self) -> NetworkScope {
        NetworkScope::account_scope(
            "tenant-fixture",
            "project-partner-fixture",
            self.account_id.clone(),
        )
        .expect("fixture account scope")
    }

    pub(crate) fn program_scope(&self) -> NetworkScope {
        NetworkScope::program_scope(
            "tenant-fixture",
            "project-partner-fixture",
            self.account_id.clone(),
            self.program_id.clone(),
        )
        .expect("fixture program scope")
    }

    pub(crate) fn current_program_expectation(&self) -> ProgramExpectation {
        ProgramExpectation::new(
            self.program_id.clone(),
            self.current_program_revision,
            self.current_terms_digest.clone(),
        )
        .expect("fixture current program expectation")
    }

    pub(crate) fn original_program_expectation(&self) -> ProgramExpectation {
        ProgramExpectation::new(
            self.program_id.clone(),
            1,
            self.original_terms_digest.clone(),
        )
        .expect("fixture original program expectation")
    }

    pub(crate) fn read(
        &self,
        resource: NetworkResource,
    ) -> Result<(NetworkReadData, ReadPage), PartnerNetworkError> {
        let data = self
            .data
            .iter()
            .find(|(candidate, _)| *candidate == resource)
            .map(|(_, data)| data.clone())
            .ok_or(PartnerNetworkError::ProviderUnavailable)?;
        let item_count = u32::try_from(data.item_count())
            .map_err(|_| PartnerNetworkError::ReadScopeOrEvidenceMismatch)?;
        Ok((
            data,
            ReadPage {
                cursor: None,
                next_cursor: None,
                has_more: false,
                item_count,
            },
        ))
    }

    pub(crate) fn is_scope_revoked(&self) -> bool {
        self.scenario == FixtureScenario::ScopeRevoked
    }

    pub(crate) fn source_digest(&self, resource: NetworkResource) -> String {
        self.data
            .iter()
            .find(|(candidate, _)| *candidate == resource)
            .and_then(|(_, data)| canonical_digest(data).ok())
            .unwrap_or_else(|| fixture_digest("missing-fixture-resource"))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn callback_body(
        &self,
        event_id: &str,
        event_type: &str,
        occurred_at: DateTime<Utc>,
        conversion_id: Option<&str>,
        order_id: Option<&str>,
        action_id: Option<&str>,
        commission_id: Option<&str>,
        reversal_id: Option<&str>,
        payout_id: Option<&str>,
        amount_minor: Option<i64>,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "eventId": event_id,
            "eventType": event_type,
            "programId": self.program_id.as_str(),
            "conversionId": conversion_id,
            "orderId": order_id,
            "clickId": "click-1",
            "actionId": action_id,
            "commissionId": commission_id,
            "reversalId": reversal_id,
            "payoutId": payout_id,
            "amountMinor": amount_minor,
            "occurredAt": occurred_at,
        }))
        .expect("fixture callback JSON")
    }

    pub(crate) fn callback_key() -> &'static [u8] {
        FIXTURE_CALLBACK_KEY
    }
}

#[allow(clippy::too_many_lines)]
fn build_data(
    provider: NetworkProvider,
    scenario: &FixtureScenario,
    account_id: &NetworkAccountId,
    program_id: &ProgramId,
    program_revision: u64,
    terms_digest: &str,
    observed_at: DateTime<Utc>,
) -> Vec<(NetworkResource, NetworkReadData)> {
    let currency = CurrencyCode::parse("USD").expect("fixture currency");
    let amount = Money::new(10_000, currency.clone());
    let commission_amount = Money::new(1_000, currency.clone());
    let program = ProgramRecord {
        account_id: account_id.clone(),
        id: program_id.clone(),
        revision: program_revision,
        state: if program_revision == 1 {
            ProgramState::Active
        } else {
            ProgramState::Paused
        },
        terms_digest: terms_digest.into(),
        observed_at,
        source_digest: fixture_digest(&format!("{}-program", provider.as_str())),
    };
    let partner_id = PartnerId::from_stable(format!("{}-partner-1", provider.as_str()));
    let contract_id = ContractId::from_stable(format!("{}-contract-1", provider.as_str()));
    let link_id = LinkId::from_stable(format!("{}-link-1", provider.as_str()));
    let click_id = ClickId::from_stable(format!("{}-click-1", provider.as_str()));
    let conversion_id = ConversionId::from_stable(format!("{}-conversion-1", provider.as_str()));
    let order_id = NetworkOrderId::from_stable(format!("{}-order-1", provider.as_str()));
    let action_id = ActionId::from_stable(format!("{}-action-1", provider.as_str()));
    let commission_id = CommissionId::from_stable(format!("{}-commission-1", provider.as_str()));
    let reversal_id = ReversalId::from_stable(format!("{}-reversal-1", provider.as_str()));
    let payout_id = PayoutId::from_stable(format!("{}-payout-1", provider.as_str()));
    let report_id = ReportId::from_stable(format!("{}-report-1", provider.as_str()));
    let conversion_at = observed_at - Duration::days(2);
    let refund_at = observed_at - Duration::hours(4);
    let period_start = if matches!(scenario, FixtureScenario::CrossPeriodRefund) {
        observed_at - Duration::days(1)
    } else {
        observed_at - Duration::days(30)
    };
    let period = SettlementPeriod::new(period_start, observed_at).expect("fixture period");
    let partner = PartnerRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: partner_id.clone(),
        relationship: PartnerRelationshipState::Active,
        display_name_digest: fixture_digest(&format!("{}-partner-name", provider.as_str())),
        observed_at,
        source_digest: fixture_digest(&format!("{}-partner", provider.as_str())),
    };
    let contract = ContractRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: contract_id,
        partner_id: partner_id.clone(),
        state: ContractState::Active,
        currency: currency.clone(),
        terms_digest: terms_digest.into(),
        effective_at: observed_at - Duration::days(90),
        expires_at: None,
        observed_at,
        source_digest: fixture_digest(&format!("{}-contract", provider.as_str())),
    };
    let link = TrackingLinkRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: link_id.clone(),
        partner_id: partner_id.clone(),
        destination_digest: fixture_digest(&format!("{}-destination", provider.as_str())),
        tracking_reference_digest: fixture_digest(&format!(
            "{}-tracking-reference",
            provider.as_str()
        )),
        active: true,
        observed_at,
        source_digest: fixture_digest(&format!("{}-link", provider.as_str())),
    };
    let click = ClickRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: click_id.clone(),
        link_id,
        occurred_at: conversion_at - Duration::hours(2),
        observed_at,
        source_digest: fixture_digest(&format!("{}-click", provider.as_str())),
    };
    let conversion = ConversionRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: conversion_id.clone(),
        order_id: order_id.clone(),
        partner_id: partner_id.clone(),
        click_id: Some(click_id.clone()),
        action_id: Some(action_id.clone()),
        state: if matches!(scenario, FixtureScenario::CrossPeriodRefund) {
            ConversionState::Refunded
        } else {
            ConversionState::Approved
        },
        amount: amount.clone(),
        occurred_at: conversion_at,
        observed_at,
        source_digest: fixture_digest(&format!("{}-conversion", provider.as_str())),
    };
    let action = ActionRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: action_id.clone(),
        conversion_id: conversion_id.clone(),
        order_id: order_id.clone(),
        partner_id: partner_id.clone(),
        click_id: Some(click_id),
        state: if matches!(scenario, FixtureScenario::CommissionReversal) {
            ActionState::Reversed
        } else {
            ActionState::Approved
        },
        commission_id: Some(commission_id.clone()),
        amount: amount.clone(),
        occurred_at: conversion_at,
        observed_at,
        source_digest: fixture_digest(&format!("{}-action", provider.as_str())),
    };
    let commission = CommissionRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: commission_id.clone(),
        action_id: action.id.clone(),
        order_id: order_id.clone(),
        partner_id: partner_id.clone(),
        state: if matches!(
            scenario,
            FixtureScenario::CommissionReversal | FixtureScenario::CrossPeriodRefund
        ) {
            CommissionState::Reversed
        } else {
            CommissionState::Accrued
        },
        amount: commission_amount.clone(),
        occurred_at: conversion_at,
        observed_at,
        source_digest: fixture_digest(&format!("{}-commission", provider.as_str())),
    };
    let reversal = ReversalRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: reversal_id,
        commission_id: commission.id.clone(),
        action_id: action.id.clone(),
        order_id: order_id.clone(),
        partner_id: partner_id.clone(),
        state: ReversalState::Applied,
        amount: commission_amount.clone(),
        reason_digest: fixture_digest("fixture-refund-or-reversal"),
        occurred_at: if matches!(scenario, FixtureScenario::CrossPeriodRefund) {
            refund_at
        } else {
            observed_at - Duration::days(1)
        },
        observed_at,
        source_digest: fixture_digest(&format!("{}-reversal", provider.as_str())),
    };
    let payout = PayoutRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: payout_id,
        partner_id,
        state: if matches!(scenario, FixtureScenario::DelayedPayout) {
            PayoutState::Pending
        } else {
            PayoutState::Completed
        },
        amount: commission_amount,
        period: period.clone(),
        occurred_at: observed_at - Duration::hours(1),
        observed_at,
        source_digest: fixture_digest(&format!("{}-payout", provider.as_str())),
    };
    let include_reversal = matches!(
        scenario,
        FixtureScenario::CommissionReversal | FixtureScenario::CrossPeriodRefund
    );
    let include_payout = true;
    let settlement_state = match scenario {
        FixtureScenario::CrossPeriodRefund => ReportSettlementState::RecalculationRequired,
        FixtureScenario::DelayedPayout => ReportSettlementState::Outstanding,
        _ => ReportSettlementState::Paid,
    };
    let report = ReportRecord {
        account_id: account_id.clone(),
        program_id: program_id.clone(),
        id: report_id,
        period,
        settlement_state,
        rows: vec![ReportRow {
            action_id: Some(action.id.clone()),
            conversion_id: Some(conversion_id),
            commission_id: Some(commission.id.clone()),
            reversal_id: include_reversal.then(|| reversal.id.clone()),
            payout_id: include_payout.then(|| payout.id.clone()),
            amount: Some(action.amount.clone()),
            occurred_at: action.occurred_at,
            source_digest: fixture_digest(&format!("{}-report-row", provider.as_str())),
        }],
        commissions: vec![commission.clone()],
        reversals: include_reversal
            .then_some(reversal.clone())
            .into_iter()
            .collect(),
        payouts: include_payout
            .then_some(payout.clone())
            .into_iter()
            .collect(),
        observed_at,
        source_digest: fixture_digest(&format!("{}-report", provider.as_str())),
    };

    vec![
        (
            NetworkResource::Programs,
            NetworkReadData::Programs {
                records: vec![program],
            },
        ),
        (
            NetworkResource::Partners,
            NetworkReadData::Partners {
                records: vec![partner],
            },
        ),
        (
            NetworkResource::Contracts,
            NetworkReadData::Contracts {
                records: vec![contract],
            },
        ),
        (
            NetworkResource::Links,
            NetworkReadData::Links {
                records: vec![link],
            },
        ),
        (
            NetworkResource::Clicks,
            NetworkReadData::Clicks {
                records: vec![click],
            },
        ),
        (
            NetworkResource::Conversions,
            NetworkReadData::Conversions {
                records: vec![conversion],
            },
        ),
        (
            NetworkResource::Actions,
            NetworkReadData::Actions {
                records: vec![action],
            },
        ),
        (
            NetworkResource::Commissions,
            NetworkReadData::Commissions {
                records: vec![commission.clone()],
            },
        ),
        (
            NetworkResource::Reversals,
            NetworkReadData::Reversals {
                records: include_reversal
                    .then(|| reversal.clone())
                    .into_iter()
                    .collect(),
            },
        ),
        (
            NetworkResource::Payouts,
            NetworkReadData::Payouts {
                records: include_payout.then(|| payout.clone()).into_iter().collect(),
            },
        ),
        (
            NetworkResource::Reports,
            NetworkReadData::Reports {
                records: vec![report],
            },
        ),
    ]
}

pub(crate) fn sign_body(scheme: CallbackSignatureScheme, body: &[u8]) -> String {
    let algorithm = match scheme {
        CallbackSignatureScheme::ImpactHookHmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        CallbackSignatureScheme::FixtureHmacSha256 => hmac::HMAC_SHA256,
    };
    let signature = hmac::sign(&hmac::Key::new(algorithm, FIXTURE_CALLBACK_KEY), body);
    hex::encode(signature.as_ref())
}
