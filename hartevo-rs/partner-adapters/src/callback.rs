use chrono::{DateTime, Utc};
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::contract::{
    NetworkProvider, NetworkScope, PartnerNetworkError, canonical_digest, digest_bytes, is_sha256,
};
use crate::ids::{
    ActionId, CallbackEventId, ClickId, CommissionId, ConversionId, NetworkOrderId, PayoutId,
    ProgramId, ReversalId,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackChannel {
    Webhook,
    Postback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackSignatureScheme {
    ImpactHookJwsDetached,
    ImpactHookHmacSha1,
    FixtureHmacSha256,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackDisposition {
    Accepted,
    Duplicate,
    OutOfOrder,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackEventKind {
    ConversionRecorded,
    ConversionRefunded,
    CommissionAccrued,
    CommissionReversed,
    PayoutCompleted,
    ProgramChanged,
    Unknown,
}

impl CallbackEventKind {
    fn parse(value: &str) -> Self {
        match value {
            "conversion.recorded" | "action.created" | "action.updated" => Self::ConversionRecorded,
            "conversion.refunded" | "refund.created" => Self::ConversionRefunded,
            "commission.accrued" | "action.approved" => Self::CommissionAccrued,
            "commission.reversed" | "action.reversed" => Self::CommissionReversed,
            "payout.completed" | "payment.completed" => Self::PayoutCompleted,
            "program.changed" | "campaign.updated" => Self::ProgramChanged,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallbackEvent {
    pub id: CallbackEventId,
    pub provider: NetworkProvider,
    pub kind: CallbackEventKind,
    pub program_id: ProgramId,
    pub conversion_id: Option<ConversionId>,
    pub order_id: Option<NetworkOrderId>,
    pub click_id: Option<ClickId>,
    pub action_id: Option<ActionId>,
    pub commission_id: Option<CommissionId>,
    pub reversal_id: Option<ReversalId>,
    pub payout_id: Option<PayoutId>,
    pub amount_minor: Option<i64>,
    pub occurred_at: DateTime<Utc>,
    pub raw_payload_digest: String,
}

#[derive(Clone, Debug)]
pub struct CallbackRequest<'a> {
    pub scope: NetworkScope,
    pub channel: CallbackChannel,
    pub body: &'a [u8],
    pub signature: &'a str,
    pub signature_key: &'a [u8],
    pub scheme: CallbackSignatureScheme,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallbackObservation {
    pub provider: NetworkProvider,
    pub channel: CallbackChannel,
    pub event: CallbackEvent,
    pub disposition: CallbackDisposition,
    pub signature_verified: bool,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallbackPayload {
    event_id: String,
    event_type: String,
    program_id: String,
    conversion_id: Option<String>,
    order_id: Option<String>,
    click_id: Option<String>,
    action_id: Option<String>,
    commission_id: Option<String>,
    reversal_id: Option<String>,
    payout_id: Option<String>,
    amount_minor: Option<i64>,
    occurred_at: DateTime<Utc>,
}

pub(crate) fn parse_callback(
    provider: NetworkProvider,
    body: &[u8],
) -> Result<CallbackEvent, PartnerNetworkError> {
    let payload = serde_json::from_slice::<CallbackPayload>(body)
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let id = CallbackEventId::parse(payload.event_id)
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let program_id =
        ProgramId::parse(payload.program_id).map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let conversion_id = payload
        .conversion_id
        .map(ConversionId::parse)
        .transpose()
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let order_id = payload
        .order_id
        .map(NetworkOrderId::parse)
        .transpose()
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let click_id = payload
        .click_id
        .map(ClickId::parse)
        .transpose()
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let action_id = payload
        .action_id
        .map(ActionId::parse)
        .transpose()
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let commission_id = payload
        .commission_id
        .map(CommissionId::parse)
        .transpose()
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let reversal_id = payload
        .reversal_id
        .map(ReversalId::parse)
        .transpose()
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    let payout_id = payload
        .payout_id
        .map(PayoutId::parse)
        .transpose()
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    if payload.amount_minor.is_some_and(|amount| amount <= 0) {
        return Err(PartnerNetworkError::MalformedCallback);
    }
    Ok(CallbackEvent {
        id,
        provider,
        kind: CallbackEventKind::parse(&payload.event_type),
        program_id,
        conversion_id,
        order_id,
        click_id,
        action_id,
        commission_id,
        reversal_id,
        payout_id,
        amount_minor: payload.amount_minor,
        occurred_at: payload.occurred_at,
        raw_payload_digest: digest_bytes(body),
    })
}

pub(crate) fn verify_signature(
    scheme: CallbackSignatureScheme,
    key: &[u8],
    body: &[u8],
    signature: &str,
) -> Result<(), PartnerNetworkError> {
    if scheme == CallbackSignatureScheme::ImpactHookJwsDetached {
        return Err(PartnerNetworkError::BlockedEnv {
            provider: NetworkProvider::Impact,
            reason: crate::BlockedEnvironmentReason::ProductionCallbackVerifierRequired,
        });
    }
    if key.is_empty() || signature.trim().is_empty() {
        return Err(PartnerNetworkError::InvalidSignature);
    }
    let decoded =
        hex::decode(signature.trim()).map_err(|_| PartnerNetworkError::InvalidSignature)?;
    let algorithm = match scheme {
        CallbackSignatureScheme::ImpactHookJwsDetached => unreachable!("handled above"),
        CallbackSignatureScheme::ImpactHookHmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        CallbackSignatureScheme::FixtureHmacSha256 => hmac::HMAC_SHA256,
    };
    hmac::verify(&hmac::Key::new(algorithm, key), body, &decoded)
        .map_err(|_| PartnerNetworkError::InvalidSignature)
}

pub fn callback_evidence_digest(
    provider: NetworkProvider,
    channel: CallbackChannel,
    event: &CallbackEvent,
    disposition: CallbackDisposition,
) -> Result<String, PartnerNetworkError> {
    let value = (&provider, &channel, event, &disposition);
    let digest = canonical_digest(&value)?;
    if !is_sha256(&digest) {
        return Err(PartnerNetworkError::MalformedCallback);
    }
    Ok(digest)
}
