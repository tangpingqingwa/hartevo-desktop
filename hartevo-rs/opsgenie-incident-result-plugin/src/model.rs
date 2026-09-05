//! Typed, bounded, and redacted Opsgenie Layer-1 models.
//!
//! The model keeps provider identifiers and revisions explicit while making
//! credential material impossible to serialize. Provider response bodies are
//! parsed in `provider.rs` and are never carried by evidence or proposals.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_TIMELINE_PAGES: usize = 4;
pub const MAX_TIMELINE_ITEMS: usize = 100;
pub const MAX_ALERTS: usize = 8;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub type Result<T> = std::result::Result<T, ModelError>;

/// A lowercase SHA-256 digest used as a stable, non-secret binding.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Opsgenie value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is empty, malformed, or too long")]
    InvalidText { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("region is not an Opsgenie API region")]
    InvalidRegion,
    #[error("consent scope is invalid")]
    InvalidConsent,
    #[error("permission snapshot is invalid")]
    InvalidPermissions,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("opaque secret reference is invalid")]
    InvalidSecretReference,
    #[error("provider response is malformed or outside the Layer-1 bound")]
    InvalidProviderResponse,
    #[error("provider response contains duplicate or unbounded timeline data")]
    InvalidTimeline,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str, allow_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_whitespace || !value.chars().any(char::is_whitespace))
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || b"-_.:/@+$".contains(&byte)
                || (allow_whitespace && byte == b' ')
        })
}

fn validate_revision(value: u64, label: &'static str) -> Result<()> {
    if value == 0 {
        Err(ModelError::InvalidRevision { label })
    } else {
        Ok(())
    }
}

macro_rules! typed_identifier {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value, false) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { label: $label })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                canonical_digest(self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

typed_identifier!(OpsgenieAccountId, "Opsgenie account");
typed_identifier!(OpsgenieTeamId, "Opsgenie team");
typed_identifier!(OpsgenieServiceId, "Opsgenie service");
typed_identifier!(OpsgenieAlertId, "Opsgenie alert");
typed_identifier!(OpsgenieIncidentId, "Opsgenie incident");
typed_identifier!(OpsgenieScheduleId, "Opsgenie schedule");
typed_identifier!(OpsgenieEscalationId, "Opsgenie escalation");
typed_identifier!(OpsgenieTimelineId, "Opsgenie timeline");

/// An alert alias can contain spaces in Opsgenie, but still has no control
/// characters and is bounded before it is included in a scope digest.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpsgenieAlertAlias(String);

impl OpsgenieAlertAlias {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value, true) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier {
                label: "Opsgenie alert alias",
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl fmt::Display for OpsgenieAlertAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub type AccountId = OpsgenieAccountId;
pub type TeamId = OpsgenieTeamId;
pub type ServiceId = OpsgenieServiceId;
pub type AlertId = OpsgenieAlertId;
pub type AlertAlias = OpsgenieAlertAlias;
pub type IncidentId = OpsgenieIncidentId;
pub type ScheduleId = OpsgenieScheduleId;
pub type EscalationId = OpsgenieEscalationId;
pub type TimelineId = OpsgenieTimelineId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type ProjectRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    id: String,
    revision: Revision,
}

impl IdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, false) {
            return Err(ModelError::InvalidIdentifier { label: "identity" });
        }
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn id_digest(&self) -> Digest {
        sha256_digest(self.id.as_bytes())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type ProjectIdentity = IdentityBinding;
pub type MissionIdentity = IdentityBinding;
pub type WorkProductIdentity = IdentityBinding;
pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;
pub type ProjectId = String;
pub type MissionId = String;
pub type WorkProductId = String;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsgenieRegion {
    Us,
    Eu,
}

impl OpsgenieRegion {
    pub fn parse(value: impl AsRef<str>) -> Result<Self> {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "us" | "us-east" | "us-east-1" => Ok(Self::Us),
            "eu" | "eu-west" | "eu-west-1" => Ok(Self::Eu),
            _ => Err(ModelError::InvalidRegion),
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::Eu => "eu",
        }
    }

    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::Us => "https://api.opsgenie.com",
            Self::Eu => "https://api.eu.opsgenie.com",
        }
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        sha256_digest(self.code().as_bytes())
    }
}

pub type ApiRegion = OpsgenieRegion;
pub type OpsgenieApiRegion = OpsgenieRegion;
pub type Region = OpsgenieRegion;

/// An opaque pointer to host-owned credential material. The identifier is
/// retained only in memory for digesting and is never serialized or debugged.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_id: String,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_id = opaque_id.into();
        if !valid_identifier(&opaque_id, false) {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            opaque_id,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn api_token(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(opaque_id, revision)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "hartevo-opsgenie-secret-reference/v1|{}|{}",
                self.opaque_id,
                self.revision.get()
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Redacted<'a> {
            secret_reference_digest: &'a Digest,
            revision: Revision,
            revoked: bool,
        }
        Redacted {
            secret_reference_digest: &self.digest(),
            revision: self.revision,
            revoked: self.revoked,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
}

impl ConsentScope {
    pub fn new(reference: impl Into<String>, revision: u64) -> Result<Self> {
        let reference = reference.into();
        if !valid_identifier(&reference, true) {
            return Err(ModelError::InvalidConsent);
        }
        Ok(Self {
            consent_digest: sha256_digest(
                format!("hartevo-opsgenie-consent/v1|{reference}").as_bytes(),
            ),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn validate(&self) -> Result<()> {
        if !is_digest(self.consent_digest.as_str()) {
            return Err(ModelError::InvalidConsent);
        }
        validate_revision(self.revision.get(), "consent")
    }
}

pub type ConsentReference = ConsentScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsgeniePermission {
    AlertsRead,
    IncidentsRead,
    SchedulesRead,
    EscalationsRead,
}

impl OpsgeniePermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AlertsRead => "opsgenie:alerts:read",
            Self::IncidentsRead => "opsgenie:incidents:read",
            Self::SchedulesRead => "opsgenie:schedules:read",
            Self::EscalationsRead => "opsgenie:escalations:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgeniePermissionSnapshot {
    permissions: BTreeSet<OpsgeniePermission>,
    revision: Revision,
}

impl OpsgeniePermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = OpsgeniePermission>,
        revision: u64,
    ) -> Result<Self> {
        let snapshot = Self {
            permissions: permissions.into_iter().collect(),
            revision: Revision::new(revision)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn least_privilege(revision: u64) -> Result<Self> {
        Self::new(
            [
                OpsgeniePermission::AlertsRead,
                OpsgeniePermission::IncidentsRead,
                OpsgeniePermission::SchedulesRead,
                OpsgeniePermission::EscalationsRead,
            ],
            revision,
        )
    }

    pub fn validate(&self) -> Result<()> {
        validate_revision(self.revision.get(), "permission snapshot")?;
        if self.permissions.len() != 4
            || !self.permissions.contains(&OpsgeniePermission::AlertsRead)
            || !self
                .permissions
                .contains(&OpsgeniePermission::IncidentsRead)
            || !self
                .permissions
                .contains(&OpsgeniePermission::SchedulesRead)
            || !self
                .permissions
                .contains(&OpsgeniePermission::EscalationsRead)
        {
            return Err(ModelError::InvalidPermissions);
        }
        Ok(())
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<OpsgeniePermission> {
        &self.permissions
    }

    #[must_use]
    pub fn has(&self, permission: OpsgeniePermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type PermissionSnapshot = OpsgeniePermissionSnapshot;
pub type OpsgenieAcl = OpsgeniePermissionSnapshot;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsgenieReadSeam {
    Alert,
    AlertTimeline,
    Incident,
    Schedule,
    Escalation,
}

impl OpsgenieReadSeam {
    #[must_use]
    pub const fn path_prefix(self) -> &'static str {
        match self {
            Self::Alert => "/v2/alerts/",
            Self::AlertTimeline => "/v2/alerts/",
            Self::Incident => "/v1/incidents/",
            Self::Schedule => "/v2/schedules/",
            Self::Escalation => "/v2/escalations/",
        }
    }

    #[must_use]
    pub const fn is_timeline(self) -> bool {
        matches!(self, Self::AlertTimeline)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OpsgenieHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieRateLimitReceipt {
    pub limit: Option<u16>,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl Default for OpsgenieRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit: Some(MAX_REQUESTS_PER_MINUTE),
            remaining: Some(MAX_REQUESTS_PER_MINUTE),
            retry_after_seconds: None,
            throttled: false,
        }
    }
}

impl OpsgenieRateLimitReceipt {
    pub fn validate(&self) -> Result<()> {
        if self
            .limit
            .is_some_and(|value| value > MAX_REQUESTS_PER_MINUTE)
            || self
                .retry_after_seconds
                .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
            || self.throttled && self.retry_after_seconds.is_none()
        {
            return Err(ModelError::InvalidProviderResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieRequestReceipt {
    pub method: OpsgenieHttpMethod,
    pub seam: OpsgenieReadSeam,
    pub endpoint: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentResultScopeSpec {
    pub account: OpsgenieAccountId,
    pub region: OpsgenieRegion,
    pub team: OpsgenieTeamId,
    pub service: OpsgenieServiceId,
    pub alert: OpsgenieAlertId,
    pub alias: OpsgenieAlertAlias,
    pub incident: OpsgenieIncidentId,
    pub schedule: OpsgenieScheduleId,
    pub escalation: OpsgenieEscalationId,
    pub timeline: OpsgenieTimelineId,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub permission_snapshot: OpsgeniePermissionSnapshot,
}

#[allow(clippy::too_many_arguments)]
impl OpsgenieIncidentResultScopeSpec {
    #[must_use]
    pub fn new(
        account: OpsgenieAccountId,
        region: OpsgenieRegion,
        team: OpsgenieTeamId,
        service: OpsgenieServiceId,
        alert: OpsgenieAlertId,
        alias: OpsgenieAlertAlias,
        incident: OpsgenieIncidentId,
        schedule: OpsgenieScheduleId,
        escalation: OpsgenieEscalationId,
        timeline: OpsgenieTimelineId,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
        permission_snapshot: OpsgeniePermissionSnapshot,
    ) -> Self {
        Self {
            account,
            region,
            team,
            service,
            alert,
            alias,
            incident,
            schedule,
            escalation,
            timeline,
            project,
            mission,
            work_product,
            consent,
            permission_snapshot,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentResultScope {
    pub account: OpsgenieAccountId,
    pub region: OpsgenieRegion,
    pub team: OpsgenieTeamId,
    pub service: OpsgenieServiceId,
    pub alert: OpsgenieAlertId,
    pub alias: OpsgenieAlertAlias,
    pub incident: OpsgenieIncidentId,
    pub schedule: OpsgenieScheduleId,
    pub escalation: OpsgenieEscalationId,
    pub timeline: OpsgenieTimelineId,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub permission_snapshot: OpsgeniePermissionSnapshot,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
}

pub type OpsgenieScope = OpsgenieIncidentResultScope;
pub type OpsgenieScopeSpec = OpsgenieIncidentResultScopeSpec;
impl OpsgenieIncidentResultScope {
    pub fn new(spec: OpsgenieIncidentResultScopeSpec) -> Result<Self> {
        spec.consent.validate()?;
        spec.permission_snapshot.validate()?;
        let scope = Self {
            account: spec.account,
            region: spec.region,
            team: spec.team,
            service: spec.service,
            alert: spec.alert,
            alias: spec.alias,
            incident: spec.incident,
            schedule: spec.schedule,
            escalation: spec.escalation,
            timeline: spec.timeline,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            consent: spec.consent,
            permission_snapshot: spec.permission_snapshot,
            scope_digest: Digest::from_text("unsealed-opsgenie-scope"),
            revision_digest: Digest::from_text("unsealed-opsgenie-revision"),
        };
        scope.validate_identities()?;
        let mut scope = scope;
        scope.scope_digest = scope.calculate_scope_digest();
        scope.revision_digest = scope.calculate_revision_digest();
        Ok(scope)
    }

    fn validate_identities(&self) -> Result<()> {
        for (value, label) in [
            (self.account.as_str(), "account"),
            (self.team.as_str(), "team"),
            (self.service.as_str(), "service"),
            (self.alert.as_str(), "alert"),
            (self.incident.as_str(), "incident"),
            (self.schedule.as_str(), "schedule"),
            (self.escalation.as_str(), "escalation"),
            (self.timeline.as_str(), "timeline"),
        ] {
            if !valid_identifier(value, false) {
                return Err(ModelError::InvalidScope(label));
            }
        }
        for (binding, label) in [
            (&self.project, "project"),
            (&self.mission, "mission"),
            (&self.work_product, "work product"),
        ] {
            if !valid_identifier(binding.id(), false) {
                return Err(ModelError::InvalidScope(label));
            }
            validate_revision(binding.revision().get(), label)?;
        }
        Ok(())
    }

    fn calculate_scope_digest(&self) -> Digest {
        canonical_digest(&(
            "hartevo-opsgenie-incident-result-scope/v1",
            self.account.digest(),
            self.region,
            self.team.digest(),
            self.service.digest(),
            self.alert.digest(),
            self.alias.digest(),
            self.incident.digest(),
            self.schedule.digest(),
            self.escalation.digest(),
            self.timeline.digest(),
            self.project.digest(),
            self.mission.digest(),
            self.work_product.digest(),
            self.consent.digest(),
            self.permission_snapshot.digest(),
        ))
    }

    fn calculate_revision_digest(&self) -> Digest {
        canonical_digest(&(
            "hartevo-opsgenie-incident-result-revisions/v1",
            self.project.revision(),
            self.mission.revision(),
            self.work_product.revision(),
            self.consent.revision(),
            self.permission_snapshot.revision(),
        ))
    }

    pub fn validate(&self) -> Result<()> {
        self.consent.validate()?;
        self.permission_snapshot.validate()?;
        self.validate_identities()?;
        if self.scope_digest != self.calculate_scope_digest() {
            return Err(ModelError::InvalidScope("scope digest"));
        }
        if self.revision_digest != self.calculate_revision_digest() {
            return Err(ModelError::InvalidScope("revision digest"));
        }
        Ok(())
    }

    #[must_use]
    pub fn spec(&self) -> OpsgenieIncidentResultScopeSpec {
        OpsgenieIncidentResultScopeSpec {
            account: self.account.clone(),
            region: self.region,
            team: self.team.clone(),
            service: self.service.clone(),
            alert: self.alert.clone(),
            alias: self.alias.clone(),
            incident: self.incident.clone(),
            schedule: self.schedule.clone(),
            escalation: self.escalation.clone(),
            timeline: self.timeline.clone(),
            project: self.project.clone(),
            mission: self.mission.clone(),
            work_product: self.work_product.clone(),
            consent: self.consent.clone(),
            permission_snapshot: self.permission_snapshot.clone(),
        }
    }

    #[must_use]
    pub fn account(&self) -> &OpsgenieAccountId {
        &self.account
    }

    #[must_use]
    pub fn account_id(&self) -> &OpsgenieAccountId {
        self.account()
    }

    #[must_use]
    pub const fn region(&self) -> OpsgenieRegion {
        self.region
    }

    #[must_use]
    pub fn team(&self) -> &OpsgenieTeamId {
        &self.team
    }

    #[must_use]
    pub fn team_id(&self) -> &OpsgenieTeamId {
        self.team()
    }

    #[must_use]
    pub fn service(&self) -> &OpsgenieServiceId {
        &self.service
    }

    #[must_use]
    pub fn service_id(&self) -> &OpsgenieServiceId {
        self.service()
    }

    #[must_use]
    pub fn alert(&self) -> &OpsgenieAlertId {
        &self.alert
    }

    #[must_use]
    pub fn alert_id(&self) -> &OpsgenieAlertId {
        self.alert()
    }

    #[must_use]
    pub fn alias(&self) -> &OpsgenieAlertAlias {
        &self.alias
    }

    #[must_use]
    pub fn alert_alias(&self) -> &OpsgenieAlertAlias {
        self.alias()
    }

    #[must_use]
    pub fn incident(&self) -> &OpsgenieIncidentId {
        &self.incident
    }

    #[must_use]
    pub fn incident_id(&self) -> &OpsgenieIncidentId {
        self.incident()
    }

    #[must_use]
    pub fn schedule(&self) -> &OpsgenieScheduleId {
        &self.schedule
    }

    #[must_use]
    pub fn schedule_id(&self) -> &OpsgenieScheduleId {
        self.schedule()
    }

    #[must_use]
    pub fn escalation(&self) -> &OpsgenieEscalationId {
        &self.escalation
    }

    #[must_use]
    pub fn escalation_id(&self) -> &OpsgenieEscalationId {
        self.escalation()
    }

    #[must_use]
    pub fn timeline(&self) -> &OpsgenieTimelineId {
        &self.timeline
    }

    #[must_use]
    pub fn timeline_id(&self) -> &OpsgenieTimelineId {
        self.timeline()
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &OpsgeniePermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsgenieAlertStatus {
    Open,
    Acknowledged,
    Closed,
    Snoozed,
    Unknown,
}

impl OpsgenieAlertStatus {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "open" | "unacked" => Self::Open,
            "acknowledged" | "acked" => Self::Acknowledged,
            "closed" => Self::Closed,
            "snoozed" => Self::Snoozed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsgenieIncidentStatus {
    Open,
    Resolved,
    Unknown,
}

impl OpsgenieIncidentStatus {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "open" | "ongoing" => Self::Open,
            "resolved" | "closed" => Self::Resolved,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsgenieTimelineKind {
    Created,
    Acknowledged,
    Closed,
    Escalated,
    Note,
    Other,
}

impl OpsgenieTimelineKind {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "created" | "alert_created" => Self::Created,
            "acknowledged" | "acked" => Self::Acknowledged,
            "closed" => Self::Closed,
            "escalated" => Self::Escalated,
            "note" => Self::Note,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieAlertObservation {
    pub alert_id: OpsgenieAlertId,
    pub alias_digest: Digest,
    pub status: OpsgenieAlertStatus,
    pub priority: Option<String>,
    pub team_digest: Digest,
    pub service_digest: Digest,
    pub incident_digest: Option<Digest>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieTimelineObservation {
    pub timeline_id: OpsgenieTimelineId,
    pub entry_count: usize,
    pub page_count: usize,
    pub complete: bool,
    pub item_digest: Digest,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentObservation {
    pub incident_id: OpsgenieIncidentId,
    pub status: OpsgenieIncidentStatus,
    pub alert_count: usize,
    pub team_digest: Digest,
    pub service_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieScheduleObservation {
    pub schedule_id: OpsgenieScheduleId,
    pub enabled: bool,
    pub escalation_count: usize,
    pub schedule_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieEscalationObservation {
    pub escalation_id: OpsgenieEscalationId,
    pub schedule_digest: Digest,
    pub level_count: usize,
    pub escalation_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentResult {
    pub alert: Option<OpsgenieAlertObservation>,
    pub timeline: Option<OpsgenieTimelineObservation>,
    pub incident: Option<OpsgenieIncidentObservation>,
    pub schedule: Option<OpsgenieScheduleObservation>,
    pub escalation: Option<OpsgenieEscalationObservation>,
}

impl OpsgenieIncidentResult {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.alert.is_none()
            && self.timeline.is_none()
            && self.incident.is_none()
            && self.schedule.is_none()
            && self.escalation.is_none()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Empty,
    Partial,
    Denied,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    NotFound,
    Stale,
    Tampered,
    RegistrationRevoked,
}

impl EvidenceState {
    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

pub type OpsgenieResultState = EvidenceState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    BoundedRead,
    Failure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "details")]
pub enum ObservationFailure {
    Denied,
    AccessLoss,
    RateLimited { retry_after_seconds: u32 },
    ProviderUnknown,
    NotFound,
    Stale,
    Partial,
    MalformedResponse,
    ResponseTooLarge,
    BlockedEnv,
    RegistrationRevoked,
}

impl ObservationFailure {
    #[must_use]
    pub const fn state(&self) -> EvidenceState {
        match self {
            Self::Denied => EvidenceState::Denied,
            Self::AccessLoss => EvidenceState::AccessLoss,
            Self::RateLimited { .. } => EvidenceState::RateLimited,
            Self::ProviderUnknown | Self::BlockedEnv => EvidenceState::ProviderUnknown,
            Self::NotFound => EvidenceState::NotFound,
            Self::Stale => EvidenceState::Stale,
            Self::Partial => EvidenceState::Partial,
            Self::MalformedResponse | Self::ResponseTooLarge => EvidenceState::Tampered,
            Self::RegistrationRevoked => EvidenceState::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_snapshot_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub registration_digest: Digest,
    pub alert_digest: Option<Digest>,
    pub incident_digest: Option<Digest>,
    pub schedule_digest: Option<Digest>,
    pub escalation_digest: Option<Digest>,
    pub timeline_digest: Option<Digest>,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentResultEvidence {
    pub state: EvidenceState,
    pub classification: EvidenceClassification,
    pub result: OpsgenieIncidentResult,
    pub request_receipts: Vec<OpsgenieRequestReceipt>,
    pub response_bytes: usize,
    pub rate_limit: OpsgenieRateLimitReceipt,
    pub provenance: TransportProvenance,
    pub digests: OpsgenieEvidenceDigests,
    pub failures: Vec<ObservationFailure>,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub evidence_digest: Digest,
}

impl OpsgenieIncidentResultEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.state,
            self.classification,
            &self.result,
            &self.request_receipts,
            self.response_bytes,
            &self.rate_limit,
            self.provenance,
            &self.digests,
            &self.failures,
            self.proposal_only,
            self.native,
            self.connected,
            self.first_party,
            self.outcome_authority,
        ))
    }

    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(self.state, EvidenceState::Complete)
            && !self.result.is_empty()
            && self.failures.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewIncidentState,
    ReviewAlertTimeline,
    ReviewScheduleCoverage,
    ReviewEscalationCoverage,
    NoRecommendationEmpty,
    NoRecommendationPartial,
    NoRecommendationRateLimited,
    NoRecommendationAccessLoss,
    NoRecommendationProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentResultRecommendation {
    pub disposition: RecommendationDisposition,
    pub provider_reported_only: bool,
    pub non_mutating: bool,
    pub claims_remediation: bool,
    pub claims_service_health: bool,
    pub rationale_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentResultProposal {
    pub scope: OpsgenieIncidentResultScope,
    pub evidence: OpsgenieIncidentResultEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_snapshot_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub recommendation: OpsgenieIncidentResultRecommendation,
    pub proposal_digest: Digest,
}

impl OpsgenieIncidentResultProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.evidence,
            &self.source_evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.permission_snapshot_digest,
            self.proposal_only,
            self.native,
            self.connected,
            self.first_party,
            self.adopts_outcome,
            self.adopts_work_product,
            &self.recommendation,
        ))
    }

    #[must_use]
    pub fn state(&self) -> EvidenceState {
        self.evidence.state
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieIncidentResultRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_snapshot_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

pub type OpsgenieRegistration = OpsgenieIncidentResultRegistration;

impl OpsgenieIncidentResultRegistration {
    #[must_use]
    pub fn bind(
        scope: &OpsgenieIncidentResultScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::OPSGENIE_INCIDENT_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::OPSGENIE_INCIDENT_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::OPSGENIE_PROVIDER_ID.to_owned(),
            provider_version: crate::OPSGENIE_PROVIDER_VERSION.to_owned(),
            provider_revision: crate::OPSGENIE_API_REVISION.to_owned(),
            provider_digest,
            scope_digest: scope.digest(),
            revision_digest: scope.revision_digest().clone(),
            permission_snapshot_digest: scope.permission_digest(),
            consent_digest: scope.consent().digest().clone(),
            secret_reference_digest: secret_reference.digest(),
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            registration_revision: Revision::new(1).expect("registration revision"),
            registration_digest: Digest::from_text("unsealed-opsgenie-registration"),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        matches!(self.state, RegistrationState::Revoked)
    }

    pub fn validate(
        &self,
        scope: &OpsgenieIncidentResultScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<()> {
        scope.validate()?;
        if !self.is_active() {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        if secret_reference.is_revoked() {
            return Err(ModelError::InvalidSecretReference);
        }
        if self.plugin_version != crate::OPSGENIE_INCIDENT_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::OPSGENIE_INCIDENT_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::OPSGENIE_PROVIDER_ID
            || self.provider_version != crate::OPSGENIE_PROVIDER_VERSION
            || self.provider_revision != crate::OPSGENIE_API_REVISION
            || &self.provider_digest != provider_digest
            || self.scope_digest != scope.digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_snapshot_digest != scope.permission_digest()
            || self.consent_digest != *scope.consent().digest()
            || self.secret_reference_digest != secret_reference.digest()
            || self.project_revision != scope.project().revision()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt> {
        if !self.revocable || self.is_revoked() {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            native: false,
            connected: false,
        })
    }

    pub fn restore(&mut self) -> Result<()> {
        if !self.reversible {
            return Err(ModelError::InvalidScope("registration is not reversible"));
        }
        if !self.is_revoked() {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "domain": "hartevo-opsgenie-registration/v1",
            "pluginVersion": &self.plugin_version,
            "contractVersion": &self.contract_version,
            "contractDigest": &self.contract_digest,
            "providerId": &self.provider_id,
            "providerVersion": &self.provider_version,
            "providerRevision": &self.provider_revision,
            "providerDigest": &self.provider_digest,
            "scopeDigest": &self.scope_digest,
            "revisionDigest": &self.revision_digest,
            "permissionSnapshotDigest": &self.permission_snapshot_digest,
            "consentDigest": &self.consent_digest,
            "secretReferenceDigest": &self.secret_reference_digest,
            "projectRevision": self.project_revision,
            "missionRevision": self.mission_revision,
            "workProductRevision": self.work_product_revision,
            "registrationRevision": self.registration_revision,
            "state": self.state,
            "reversible": self.reversible,
            "revocable": self.revocable,
        }))
    }
}
