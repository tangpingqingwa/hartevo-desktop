//! Typed PagerDuty incident models used by the Layer-1 provider seam.
//!
//! The model intentionally contains identifiers, timestamps, bounded
//! projections, and digests only.  Raw note bodies, alert bodies, and
//! responder details are accepted by the recording transport but are never
//! serializable projection fields.

use std::{fmt, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_DIGEST_BYTES: usize = 64;
pub const DEFAULT_MAX_ALERTS: usize = 100;
pub const DEFAULT_MAX_ASSIGNMENTS: usize = 100;
pub const DEFAULT_MAX_TIMELINE_PAGES: usize = 20;
pub const DEFAULT_MAX_TIMELINE_ITEMS: usize = 500;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_TIMELINE_WINDOW_SECONDS: i64 = 2_592_000;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{kind} identifier is empty or invalid")]
    InvalidIdentifier { kind: &'static str },
    #[error("digest must be exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("timestamp must be a positive Unix timestamp")]
    InvalidTimestamp,
    #[error("revision must be greater than zero")]
    InvalidRevision,
    #[error("scope field is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("secret reference kind is not valid for this operation")]
    InvalidSecretKind,
    #[error("consent reference does not match its Mission/Project scope")]
    ConsentScopeMismatch,
    #[error("incident projection contains too many alerts or assignments")]
    ProjectionBoundExceeded,
    #[error("timeline bounds are invalid")]
    InvalidTimelineBounds,
    #[error("timeline window exceeds its configured bound")]
    TimelineWindowExceeded,
    #[error("raw incident state transition is inconsistent")]
    InvalidIncidentTransition,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != MAX_DIGEST_BYTES
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed PagerDuty values serialize");
    Digest::from_bytes(&bytes)
}

macro_rules! typed_identifier {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { kind: $label })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
}

typed_identifier!(AccountId, "account");
typed_identifier!(TeamId, "team");
typed_identifier!(ServiceId, "service");
typed_identifier!(EscalationPolicyId, "escalation policy");
typed_identifier!(IncidentId, "incident");
typed_identifier!(WebhookSubscriptionId, "webhook subscription");
typed_identifier!(MissionId, "Mission");
typed_identifier!(ProjectId, "Project");
typed_identifier!(ConsentId, "Consent");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiRegion {
    Us,
    Eu,
}

impl ApiRegion {
    pub const fn host(self) -> &'static str {
        match self {
            Self::Us => "api.pagerduty.com",
            Self::Eu => "api.eu.pagerduty.com",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn new(value: i64) -> Result<Self, ModelError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidTimestamp)
        }
    }

    pub const fn unix_seconds(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
    OAuthAccessToken,
    WebhookSigningSecret,
}

/// An opaque pointer to material managed outside the plugin.
///
/// This type deliberately contains no token bytes and therefore is safe to
/// put in registration digests and non-secret receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_id: String,
    kind: SecretKind,
    credential_revision: u64,
    scope_digest: Digest,
    revoked_at: Option<Timestamp>,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        kind: SecretKind,
        credential_revision: u64,
        scope_digest: Digest,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id)
            || !reference_id.starts_with("secret-ref-")
            || credential_revision == 0
        {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_id,
            kind,
            credential_revision,
            scope_digest,
            revoked_at: None,
        })
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub const fn kind(&self) -> &SecretKind {
        &self.kind
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revoked_at(&self) -> Option<Timestamp> {
        self.revoked_at
    }

    pub fn revoke(&mut self, at: Timestamp) -> Result<(), ModelError> {
        if self.revoked_at.is_some() {
            return Err(ModelError::InvalidSecretReference);
        }
        self.revoked_at = Some(at);
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// In-memory-only webhook key used by the verification seam.
///
/// It has no `Serialize` implementation and its `Debug` output is always
/// redacted.  Layer 1 never resolves an API token or webhook secret from a
/// `SecretReference`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WebhookSecretMaterial(Vec<u8>);

impl WebhookSecretMaterial {
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self(value.as_ref().to_vec())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for WebhookSecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebhookSecretMaterial(REDACTED)")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReference {
    consent_id: ConsentId,
    revision: u64,
    mission_id: MissionId,
    project_id: ProjectId,
}

impl ConsentReference {
    pub fn new(
        consent_id: ConsentId,
        revision: u64,
        mission_id: MissionId,
        project_id: ProjectId,
    ) -> Result<Self, ModelError> {
        if revision == 0 {
            return Err(ModelError::InvalidRevision);
        }
        Ok(Self {
            consent_id,
            revision,
            mission_id,
            project_id,
        })
    }

    pub fn consent_id(&self) -> &ConsentId {
        &self.consent_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncidentIdentity {
    pub id: IncidentId,
    pub number: u64,
}

impl IncidentIdentity {
    pub fn new(id: IncidentId, number: u64) -> Result<Self, ModelError> {
        if number == 0 {
            return Err(ModelError::InvalidIdentifier {
                kind: "incident number",
            });
        }
        Ok(Self { id, number })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PagerDutyScope {
    pub api_region: ApiRegion,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub service_id: ServiceId,
    pub escalation_policy_id: EscalationPolicyId,
    pub incident: IncidentIdentity,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub consent: ConsentReference,
    pub webhook_subscription_id: WebhookSubscriptionId,
}

impl PagerDutyScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_region: ApiRegion,
        account_id: AccountId,
        team_id: TeamId,
        service_id: ServiceId,
        escalation_policy_id: EscalationPolicyId,
        incident: IncidentIdentity,
        mission_id: MissionId,
        project_id: ProjectId,
        consent: ConsentReference,
        webhook_subscription_id: WebhookSubscriptionId,
    ) -> Result<Self, ModelError> {
        if consent.mission_id() != &mission_id || consent.project_id() != &project_id {
            return Err(ModelError::ConsentScopeMismatch);
        }
        Ok(Self {
            api_region,
            account_id,
            team_id,
            service_id,
            escalation_policy_id,
            incident,
            mission_id,
            project_id,
            consent,
            webhook_subscription_id,
        })
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Triggered,
    Acknowledged,
    Resolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Triggered,
    Acknowledged,
    Resolved,
    Retriggered,
    Reopened,
}

impl IncidentState {
    pub const fn provider_status(self) -> IncidentStatus {
        match self {
            Self::Triggered | Self::Retriggered => IncidentStatus::Triggered,
            Self::Acknowledged | Self::Reopened => IncidentStatus::Acknowledged,
            Self::Resolved => IncidentStatus::Resolved,
        }
    }

    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::Resolved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderIncidentTransition {
    None,
    Retriggered,
    Reopened,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Triggered,
    Resolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKind {
    IncidentCreated,
    StatusChanged,
    AssignmentChanged,
    Escalation,
    Alert,
    Note,
    Responder,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl Provenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionBounds {
    pub max_alerts: usize,
    pub max_assignments: usize,
    pub max_timeline_pages: usize,
    pub max_timeline_items: usize,
    pub max_response_bytes: usize,
    pub max_timeline_window_seconds: i64,
}

impl Default for ProjectionBounds {
    fn default() -> Self {
        Self {
            max_alerts: DEFAULT_MAX_ALERTS,
            max_assignments: DEFAULT_MAX_ASSIGNMENTS,
            max_timeline_pages: DEFAULT_MAX_TIMELINE_PAGES,
            max_timeline_items: DEFAULT_MAX_TIMELINE_ITEMS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_timeline_window_seconds: DEFAULT_MAX_TIMELINE_WINDOW_SECONDS,
        }
    }
}

impl ProjectionBounds {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.max_alerts == 0
            || self.max_assignments == 0
            || self.max_timeline_pages == 0
            || self.max_timeline_items == 0
            || self.max_response_bytes == 0
            || self.max_timeline_window_seconds <= 0
        {
            return Err(ModelError::InvalidTimelineBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineWindow {
    pub from: Timestamp,
    pub to: Timestamp,
}

impl TimelineWindow {
    pub fn new(from: Timestamp, to: Timestamp, max_seconds: i64) -> Result<Self, ModelError> {
        let duration = to.unix_seconds() - from.unix_seconds();
        if duration < 0 {
            return Err(ModelError::InvalidTimelineBounds);
        }
        if duration > max_seconds {
            return Err(ModelError::TimelineWindowExceeded);
        }
        Ok(Self { from, to })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineBounds {
    pub page_size: usize,
    pub max_pages: usize,
    pub max_items: usize,
    pub max_response_bytes: usize,
    pub window: TimelineWindow,
}

impl TimelineBounds {
    pub fn validate(&self, contract: &ProjectionBounds) -> Result<(), ModelError> {
        if self.page_size == 0
            || self.page_size > contract.max_timeline_items
            || self.max_pages == 0
            || self.max_pages > contract.max_timeline_pages
            || self.max_items == 0
            || self.max_items > contract.max_timeline_items
            || self.max_response_bytes == 0
            || self.max_response_bytes > contract.max_response_bytes
        {
            return Err(ModelError::InvalidTimelineBounds);
        }
        let duration = self.window.to.unix_seconds() - self.window.from.unix_seconds();
        if duration < 0 || duration > contract.max_timeline_window_seconds {
            return Err(ModelError::TimelineWindowExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RawAssignmentPayload {
    pub assignment_id: String,
    pub assignee_reference: String,
    pub team_id: TeamId,
    pub escalation_policy_id: EscalationPolicyId,
    pub assigned_at: Timestamp,
}

impl fmt::Debug for RawAssignmentPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawAssignmentPayload")
            .field("assignment_id", &self.assignment_id)
            .field("assignee_reference", &"<redacted>")
            .field("team_id", &self.team_id)
            .field("escalation_policy_id", &self.escalation_policy_id)
            .field("assigned_at", &self.assigned_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RawAlertPayload {
    pub alert_id: String,
    pub status: AlertStatus,
    pub deduplication_key: String,
    pub triggered_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub raw_body: Vec<u8>,
}

impl fmt::Debug for RawAlertPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawAlertPayload")
            .field("alert_id", &self.alert_id)
            .field("status", &self.status)
            .field("deduplication_key", &"<redacted>")
            .field("triggered_at", &self.triggered_at)
            .field("resolved_at", &self.resolved_at)
            .field("raw_body", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RawIncidentPayload {
    pub api_region: ApiRegion,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub service_id: ServiceId,
    pub escalation_policy_id: EscalationPolicyId,
    pub incident: IncidentIdentity,
    pub status: IncidentStatus,
    pub transition: ProviderIncidentTransition,
    pub provider_revision: u64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_status_change_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub priority: Option<String>,
    pub urgency: Option<String>,
    pub assignments: Vec<RawAssignmentPayload>,
    pub alerts: Vec<RawAlertPayload>,
}

impl fmt::Debug for RawIncidentPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawIncidentPayload")
            .field("api_region", &self.api_region)
            .field("account_id", &self.account_id)
            .field("team_id", &self.team_id)
            .field("service_id", &self.service_id)
            .field("escalation_policy_id", &self.escalation_policy_id)
            .field("incident", &self.incident)
            .field("status", &self.status)
            .field("transition", &self.transition)
            .field("provider_revision", &self.provider_revision)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_status_change_at", &self.last_status_change_at)
            .field("resolved_at", &self.resolved_at)
            .field("priority", &self.priority)
            .field("urgency", &self.urgency)
            .field("assignments", &self.assignments)
            .field("alerts", &self.alerts)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RawTimelineEntryPayload {
    pub entry_id: String,
    pub kind: TimelineKind,
    pub occurred_at: Timestamp,
    pub actor_reference: String,
    pub content: Vec<u8>,
}

impl fmt::Debug for RawTimelineEntryPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawTimelineEntryPayload")
            .field("entry_id", &self.entry_id)
            .field("kind", &self.kind)
            .field("occurred_at", &self.occurred_at)
            .field("actor_reference", &"<redacted>")
            .field("content", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentProjection {
    pub assignment_id: String,
    pub assignee_reference_digest: Digest,
    pub team_id: TeamId,
    pub escalation_policy_id: EscalationPolicyId,
    pub assigned_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlertProjection {
    pub alert_id: String,
    pub status: AlertStatus,
    pub deduplication_key_digest: Digest,
    pub triggered_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncidentProjection {
    pub scope_digest: Digest,
    pub api_region: ApiRegion,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub service_id: ServiceId,
    pub escalation_policy_id: EscalationPolicyId,
    pub incident: IncidentIdentity,
    pub state: IncidentState,
    pub provider_status: IncidentStatus,
    pub provider_revision: u64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_status_change_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub priority: Option<String>,
    pub urgency: Option<String>,
    pub assignments: Vec<AssignmentProjection>,
    pub alerts: Vec<AlertProjection>,
    pub incident_digest: Digest,
    pub provenance: Provenance,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IncidentProjectionMaterial<'a> {
    scope_digest: &'a Digest,
    api_region: ApiRegion,
    account_id: &'a AccountId,
    team_id: &'a TeamId,
    service_id: &'a ServiceId,
    escalation_policy_id: &'a EscalationPolicyId,
    incident: &'a IncidentIdentity,
    state: IncidentState,
    provider_status: IncidentStatus,
    provider_revision: u64,
    created_at: Timestamp,
    updated_at: Timestamp,
    last_status_change_at: Timestamp,
    resolved_at: Option<Timestamp>,
    priority: &'a Option<String>,
    urgency: &'a Option<String>,
    assignments: &'a [AssignmentProjection],
    alerts: &'a [AlertProjection],
}

impl IncidentProjection {
    pub fn from_raw(
        scope: &PagerDutyScope,
        raw: &RawIncidentPayload,
        previous: Option<&Self>,
        provenance: Provenance,
        bounds: &ProjectionBounds,
    ) -> Result<Self, ModelError> {
        bounds.validate()?;
        if raw.assignments.len() > bounds.max_assignments || raw.alerts.len() > bounds.max_alerts {
            return Err(ModelError::ProjectionBoundExceeded);
        }
        if raw.provider_revision == 0 {
            return Err(ModelError::InvalidRevision);
        }
        if raw.status == IncidentStatus::Resolved && raw.resolved_at.is_none() {
            return Err(ModelError::InvalidIncidentTransition);
        }
        let state = incident_state(raw, previous)?;
        let assignments = raw
            .assignments
            .iter()
            .map(|assignment| AssignmentProjection {
                assignment_id: assignment.assignment_id.clone(),
                assignee_reference_digest: Digest::from_text(&assignment.assignee_reference),
                team_id: assignment.team_id.clone(),
                escalation_policy_id: assignment.escalation_policy_id.clone(),
                assigned_at: assignment.assigned_at,
            })
            .collect::<Vec<_>>();
        let alerts = raw
            .alerts
            .iter()
            .map(|alert| AlertProjection {
                alert_id: alert.alert_id.clone(),
                status: alert.status,
                deduplication_key_digest: Digest::from_text(&alert.deduplication_key),
                triggered_at: alert.triggered_at,
                resolved_at: alert.resolved_at,
            })
            .collect::<Vec<_>>();
        let material = IncidentProjectionMaterial {
            scope_digest: &scope.digest(),
            api_region: raw.api_region,
            account_id: &raw.account_id,
            team_id: &raw.team_id,
            service_id: &raw.service_id,
            escalation_policy_id: &raw.escalation_policy_id,
            incident: &raw.incident,
            state,
            provider_status: raw.status,
            provider_revision: raw.provider_revision,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            last_status_change_at: raw.last_status_change_at,
            resolved_at: raw.resolved_at,
            priority: &raw.priority,
            urgency: &raw.urgency,
            assignments: &assignments,
            alerts: &alerts,
        };
        let scope_digest = scope.digest();
        let incident_digest = canonical_digest(&material);
        Ok(Self {
            scope_digest,
            api_region: raw.api_region,
            account_id: raw.account_id.clone(),
            team_id: raw.team_id.clone(),
            service_id: raw.service_id.clone(),
            escalation_policy_id: raw.escalation_policy_id.clone(),
            incident: raw.incident.clone(),
            state,
            provider_status: raw.status,
            provider_revision: raw.provider_revision,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            last_status_change_at: raw.last_status_change_at,
            resolved_at: raw.resolved_at,
            priority: raw.priority.clone(),
            urgency: raw.urgency.clone(),
            assignments,
            alerts,
            incident_digest,
            provenance,
        })
    }
}

fn incident_state(
    raw: &RawIncidentPayload,
    previous: Option<&IncidentProjection>,
) -> Result<IncidentState, ModelError> {
    let explicit = match raw.transition {
        ProviderIncidentTransition::None => None,
        ProviderIncidentTransition::Retriggered if raw.status == IncidentStatus::Triggered => {
            Some(IncidentState::Retriggered)
        }
        ProviderIncidentTransition::Reopened if raw.status == IncidentStatus::Acknowledged => {
            Some(IncidentState::Reopened)
        }
        _ => return Err(ModelError::InvalidIncidentTransition),
    };
    if let Some(state) = explicit {
        return Ok(state);
    }
    if previous.is_some_and(|projection| projection.state.is_resolved()) {
        return match raw.status {
            IncidentStatus::Triggered => Ok(IncidentState::Retriggered),
            IncidentStatus::Acknowledged => Ok(IncidentState::Reopened),
            IncidentStatus::Resolved => Ok(IncidentState::Resolved),
        };
    }
    Ok(match raw.status {
        IncidentStatus::Triggered => IncidentState::Triggered,
        IncidentStatus::Acknowledged => IncidentState::Acknowledged,
        IncidentStatus::Resolved => IncidentState::Resolved,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineEntryProjection {
    pub entry_id: String,
    pub kind: TimelineKind,
    pub occurred_at: Timestamp,
    pub actor_reference_digest: Digest,
    pub content_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineStopReason {
    Complete,
    PageLimit,
    ItemLimit,
    ResponseBytesLimit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitReceipt {
    pub request_id: Option<String>,
    pub limit: Option<u32>,
    pub remaining: Option<u32>,
    pub reset_at: Option<Timestamp>,
    pub response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelinePageReceipt {
    pub page_index: usize,
    pub cursor_digest: Option<Digest>,
    pub item_count: usize,
    pub response_bytes: usize,
    pub next_cursor_digest: Option<Digest>,
    pub rate_limit: RateLimitReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineReceipt {
    pub page_count: usize,
    pub item_count: usize,
    pub response_bytes: usize,
    pub complete: bool,
    pub stop_reason: TimelineStopReason,
    pub reordered: bool,
    pub pages: Vec<TimelinePageReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineProjection {
    pub scope_digest: Digest,
    pub incident: IncidentIdentity,
    pub provider_revision: u64,
    pub entries: Vec<TimelineEntryProjection>,
    pub receipt: TimelineReceipt,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseIntent {
    Acknowledge,
    Reassign {
        team_id: TeamId,
        escalation_policy_id: EscalationPolicyId,
    },
    AddResponder {
        responder_reference_digest: Digest,
    },
    Resolve {
        resolution_evidence_digest: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub exact_scope_fields: Vec<String>,
    pub read_only: bool,
    pub executes_mutations: bool,
    pub accepts_live_webhooks: bool,
    pub adopts_outcomes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseProposal {
    pub scope_digest: Digest,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub mission_revision: u64,
    pub consent: ConsentReference,
    pub incident: IncidentIdentity,
    pub expected_state: IncidentState,
    pub expected_provider_revision: u64,
    pub intent: ResponseIntent,
    pub idempotency_fingerprint: Digest,
    pub proposal_digest: Digest,
    pub mutating_effect_allowed: bool,
    pub executed: bool,
    pub exact_readback_required: bool,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedTimelineEvidence {
    pub entry_id: String,
    pub occurred_at: Timestamp,
    pub content_digest: Digest,
    pub actor_reference_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolutionEvidenceProposal {
    pub scope_digest: Digest,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub mission_revision: u64,
    pub consent: ConsentReference,
    pub incident: IncidentIdentity,
    pub incident_digest: Digest,
    pub incident_state: IncidentState,
    pub provider_revision: u64,
    pub resolved_at: Timestamp,
    pub assignment_digests: Vec<Digest>,
    pub selected_timeline: Vec<SelectedTimelineEvidence>,
    pub evidence_digest: Digest,
    pub adopted_outcome: bool,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct _PhantomModelType<T>(PhantomData<T>);
