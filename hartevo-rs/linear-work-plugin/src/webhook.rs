use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::digest_hex;
use crate::ids::{LinearAppId, LinearOrganizationId, LinearTeamId};

pub const LINEAR_WEBHOOK_REPLAY_WINDOW_MS: u64 = 60_000;
pub const LINEAR_SIGNATURE_HEADER: &str = "Linear-Signature";
pub const LINEAR_DELIVERY_HEADER: &str = "Linear-Delivery";
pub const LINEAR_EVENT_HEADER: &str = "Linear-Event";
pub const LINEAR_TIMESTAMP_HEADER: &str = "Linear-Timestamp";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearWebhookHeaders {
    pub signature: String,
    pub delivery_id: String,
    pub event: String,
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
}

impl LinearWebhookHeaders {
    pub fn new(
        signature: impl Into<String>,
        delivery_id: impl Into<String>,
        event: impl Into<String>,
        timestamp_ms: Option<u64>,
    ) -> Result<Self, LinearWebhookError> {
        let headers = Self {
            signature: signature.into(),
            delivery_id: delivery_id.into(),
            event: event.into(),
            timestamp_ms,
        };
        if headers.signature.trim().is_empty()
            || headers.delivery_id.trim().is_empty()
            || headers.event.trim().is_empty()
        {
            return Err(LinearWebhookError::InvalidHeaders);
        }
        if hex::decode(headers.signature.trim()).is_err() {
            return Err(LinearWebhookError::InvalidSignature);
        }
        Ok(headers)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LinearWebhookEventKind {
    Issue,
    Comment,
    Project,
    Cycle,
    OAuthRevoked,
    OAuthAuthorization,
    PermissionChange,
    Unknown { name: String },
}

impl LinearWebhookEventKind {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().replace([' ', '_'], "").as_str() {
            "issue" => Self::Issue,
            "comment" | "issuecomment" => Self::Comment,
            "project" => Self::Project,
            "cycle" => Self::Cycle,
            "oauthapprevoked" | "oauthrevoked" => Self::OAuthRevoked,
            "oauthauthorization" => Self::OAuthAuthorization,
            "permissionchange" => Self::PermissionChange,
            _ => Self::Unknown {
                name: value.to_owned(),
            },
        }
    }

    pub fn is_revocation_event(&self) -> bool {
        matches!(
            self,
            Self::OAuthRevoked | Self::PermissionChange | Self::OAuthAuthorization
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearWebhookEvent {
    pub kind: LinearWebhookEventKind,
    pub action: Option<String>,
    pub organization_id: Option<LinearOrganizationId>,
    pub oauth_client_id: Option<LinearAppId>,
    pub team_id: Option<LinearTeamId>,
    pub payload: Value,
}

impl LinearWebhookEvent {
    pub fn is_revocation(&self) -> bool {
        self.kind.is_revocation_event()
            && match &self.kind {
                LinearWebhookEventKind::OAuthAuthorization => {
                    self.action.as_deref().is_none_or(|action| {
                        matches!(
                            action.to_ascii_lowercase().as_str(),
                            "revoke" | "revoked" | "remove" | "removed" | "delete" | "deleted"
                        )
                    })
                }
                _ => true,
            }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedLinearWebhook {
    pub headers: LinearWebhookHeaders,
    pub event: LinearWebhookEvent,
    pub webhook_timestamp_ms: u64,
    pub raw_body_sha256: String,
}

impl VerifiedLinearWebhook {
    pub fn delivery_id(&self) -> &str {
        &self.headers.delivery_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinearWebhookOutcome {
    Accepted(VerifiedLinearWebhook),
    Duplicate { delivery_id: String },
    Ignored(VerifiedLinearWebhook),
}

#[derive(Clone, Debug)]
pub struct LinearReplayFence {
    capacity: usize,
    order: VecDeque<String>,
    deliveries: BTreeMap<String, String>,
}

impl LinearReplayFence {
    pub fn new(capacity: usize) -> Result<Self, LinearWebhookError> {
        if capacity == 0 {
            return Err(LinearWebhookError::InvalidReplayFence);
        }
        Ok(Self {
            capacity,
            order: VecDeque::new(),
            deliveries: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn accept(
        &mut self,
        delivery_id: &str,
        body_digest: &str,
        timestamp_ms: u64,
        now_ms: u64,
        tolerance_ms: u64,
    ) -> Result<bool, LinearWebhookError> {
        if let Some(previous_digest) = self.deliveries.get(delivery_id) {
            if previous_digest == body_digest {
                return Ok(true);
            }
            return Err(LinearWebhookError::DeliveryConflict {
                delivery_id: delivery_id.to_owned(),
            });
        }
        if now_ms.abs_diff(timestamp_ms) > tolerance_ms {
            return Err(LinearWebhookError::ReplayWindow {
                timestamp_ms,
                now_ms,
                tolerance_ms,
            });
        }
        if self.order.len() == self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.deliveries.remove(&evicted);
        }
        self.order.push_back(delivery_id.to_owned());
        self.deliveries
            .insert(delivery_id.to_owned(), body_digest.to_owned());
        Ok(false)
    }
}

pub fn verify_linear_webhook(
    raw_body: &[u8],
    headers: LinearWebhookHeaders,
    signing_secret: &[u8],
) -> Result<VerifiedLinearWebhook, LinearWebhookError> {
    let signature =
        hex::decode(headers.signature.trim()).map_err(|_| LinearWebhookError::InvalidSignature)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, signing_secret);
    hmac::verify(&key, raw_body, &signature).map_err(|_| LinearWebhookError::InvalidSignature)?;
    let parsed = serde_json::from_slice::<RawLinearWebhook>(raw_body)
        .map_err(|error| LinearWebhookError::MalformedBody(error.to_string()))?;
    let webhook_timestamp_ms = parsed
        .webhook_timestamp
        .ok_or(LinearWebhookError::MissingTimestamp)?;
    if headers
        .timestamp_ms
        .is_some_and(|timestamp| timestamp != webhook_timestamp_ms)
    {
        return Err(LinearWebhookError::TimestampHeaderMismatch);
    }
    if parsed
        .webhook_id
        .as_deref()
        .is_some_and(|delivery_id| delivery_id != headers.delivery_id)
    {
        return Err(LinearWebhookError::DeliveryHeaderMismatch);
    }
    let event_name = parsed
        .event_type
        .as_deref()
        .unwrap_or(headers.event.as_str());
    let event = LinearWebhookEvent {
        kind: LinearWebhookEventKind::parse(event_name),
        action: parsed.action,
        organization_id: first_id(
            parsed.organization_id,
            parsed
                .data
                .as_ref()
                .and_then(|data| data.get("organizationId").and_then(Value::as_str)),
        ),
        oauth_client_id: first_app_id(
            parsed.oauth_client_id,
            parsed
                .data
                .as_ref()
                .and_then(|data| data.get("oauthClientId").and_then(Value::as_str)),
        ),
        team_id: first_team_id(
            parsed
                .data
                .as_ref()
                .and_then(|data| data.get("teamId").and_then(Value::as_str)),
        ),
        payload: Value::Object(parsed.data.unwrap_or_default()),
    };
    Ok(VerifiedLinearWebhook {
        headers,
        event,
        webhook_timestamp_ms,
        raw_body_sha256: digest_hex(raw_body),
    })
}

pub fn verify_and_fence_linear_webhook(
    raw_body: &[u8],
    headers: LinearWebhookHeaders,
    signing_secret: &[u8],
    replay_fence: &mut LinearReplayFence,
    now_ms: u64,
) -> Result<LinearWebhookOutcome, LinearWebhookError> {
    let verified = verify_linear_webhook(raw_body, headers, signing_secret)?;
    let duplicate = replay_fence.accept(
        verified.delivery_id(),
        &verified.raw_body_sha256,
        verified.webhook_timestamp_ms,
        now_ms,
        LINEAR_WEBHOOK_REPLAY_WINDOW_MS,
    )?;
    if duplicate {
        return Ok(LinearWebhookOutcome::Duplicate {
            delivery_id: verified.headers.delivery_id,
        });
    }
    Ok(LinearWebhookOutcome::Accepted(verified))
}

fn first_id(primary: Option<String>, fallback: Option<&str>) -> Option<LinearOrganizationId> {
    primary
        .or_else(|| fallback.map(str::to_owned))
        .and_then(|value| LinearOrganizationId::new(value).ok())
}

fn first_app_id(primary: Option<String>, fallback: Option<&str>) -> Option<LinearAppId> {
    primary
        .or_else(|| fallback.map(str::to_owned))
        .and_then(|value| LinearAppId::new(value).ok())
}

fn first_team_id(value: Option<&str>) -> Option<LinearTeamId> {
    value.and_then(|value| LinearTeamId::new(value.to_owned()).ok())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RawLinearWebhook {
    #[serde(default)]
    action: Option<String>,
    #[serde(rename = "type", default)]
    event_type: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    oauth_client_id: Option<String>,
    #[serde(default)]
    webhook_timestamp: Option<u64>,
    #[serde(default)]
    webhook_id: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Map<String, Value>>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearWebhookError {
    #[error("Linear webhook headers are invalid")]
    InvalidHeaders,
    #[error("Linear webhook signature is invalid")]
    InvalidSignature,
    #[error("Linear webhook body is malformed: {0}")]
    MalformedBody(String),
    #[error("Linear webhook body has no timestamp")]
    MissingTimestamp,
    #[error("Linear webhook timestamp header does not match body")]
    TimestampHeaderMismatch,
    #[error("Linear webhook delivery header does not match body")]
    DeliveryHeaderMismatch,
    #[error("Linear webhook replay fence capacity must be positive")]
    InvalidReplayFence,
    #[error(
        "Linear webhook is outside the replay window: timestamp {timestamp_ms}, now {now_ms}, tolerance {tolerance_ms}"
    )]
    ReplayWindow {
        timestamp_ms: u64,
        now_ms: u64,
        tolerance_ms: u64,
    },
    #[error("Linear webhook delivery {delivery_id} was reused with a different body")]
    DeliveryConflict { delivery_id: String },
}

impl fmt::Display for LinearWebhookOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(delivery) => write!(formatter, "accepted:{}", delivery.delivery_id()),
            Self::Duplicate { delivery_id } => write!(formatter, "duplicate:{delivery_id}"),
            Self::Ignored(delivery) => write!(formatter, "ignored:{}", delivery.delivery_id()),
        }
    }
}
