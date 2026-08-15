use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT, RUDDERSTACK_MAX_AGGREGATE_COUNT,
    RUDDERSTACK_MAX_CURSOR_BYTES, RUDDERSTACK_MAX_DIAGNOSTIC_BYTES, RUDDERSTACK_MAX_EVENT_NAMES,
    RUDDERSTACK_MAX_IDENTIFIER_BYTES, RUDDERSTACK_MAX_PAGE_SIZE, RUDDERSTACK_MAX_PROPERTIES,
    RUDDERSTACK_MAX_REQUESTS_PER_MINUTE, RUDDERSTACK_MAX_RESPONSE_BYTES,
    RUDDERSTACK_MAX_WINDOW_DAYS, RUDDERSTACK_PRIVACY_POLICY_VERSION,
};

pub type SchemaDigest = Digest;
pub type EventName = EventNameDigest;
pub type PropertyName = PropertyNameDigest;

/// A lowercase SHA-256 digest.  Digests are the only retained representation
/// of event names, property names, cursors, provider bodies, and diagnostics.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
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
        self.0.fmt(formatter)
    }
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("RudderStack typed value serializes");
    Digest::from_bytes(&bytes)
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is empty, contains control characters, or exceeds the bound")]
    InvalidText { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("date must be a valid ISO calendar date")]
    InvalidDate,
    #[error("date window is unordered or exceeds the Layer-1 bound")]
    InvalidDateWindow,
    #[error("the value exceeds a Layer-1 bound")]
    BoundExceeded,
    #[error("the value must be unique")]
    DuplicateValue,
    #[error("the permission set must contain only allowlisted read permissions")]
    InvalidPermissionSet,
    #[error("the privacy policy is not the required strict redaction policy")]
    InvalidPrivacyPolicy,
    #[error("the scope is invalid")]
    InvalidScope,
    #[error("the rate limit receipt is invalid")]
    InvalidRateLimit,
    #[error("the cursor receipt is invalid")]
    InvalidCursor,
    #[error("the aggregate metric is invalid")]
    InvalidMetric,
    #[error("the registration is invalid")]
    InvalidRegistration,
    #[error("the registration is already revoked")]
    AlreadyRevoked,
    #[error("the registration or secret is not revoked")]
    NotRevoked,
    #[error("the registration revision overflowed")]
    RevisionOverflow,
    #[error("the immutable digest does not match")]
    DigestMismatch,
}

fn valid_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > RUDDERSTACK_MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)))
    {
        Err(ModelError::InvalidIdentifier { field })
    } else {
        Ok(())
    }
}

fn valid_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ModelError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validate_revision(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::InvalidRevision { field })
    } else {
        Ok(())
    }
}

macro_rules! identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                valid_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields(
                    concat!("rudderstack-", stringify!($name), "/v1"),
                    std::slice::from_ref(&self.0),
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .finish()
            }
        }
    };
}

identifier!(OrganizationId, "organization id");
identifier!(WorkspaceId, "workspace id");
identifier!(SourceId, "source id");
identifier!(DestinationId, "destination id");
identifier!(TrackingPlanId, "tracking plan id");
identifier!(ViolationId, "violation id");
identifier!(ProjectId, "Project id");
identifier!(MissionId, "Mission id");
identifier!(WorkProductId, "Work Product id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn new(seconds: i64) -> Result<Self, ModelError> {
        if seconds < 0 {
            Err(ModelError::InvalidText { field: "timestamp" })
        } else {
            Ok(Self(seconds))
        }
    }

    pub const fn seconds(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UtcDate(String);

impl UtcDate {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_date(&value) {
            return Err(ModelError::InvalidDate);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn ordinal(&self) -> i64 {
        days_from_civil(
            self.0[0..4].parse::<i32>().expect("validated date year"),
            self.0[5..7].parse::<u32>().expect("validated date month"),
            self.0[8..10].parse::<u32>().expect("validated date day"),
        )
    }
}

fn valid_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<i32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u32>() else {
        return false;
    };
    year >= 1970 && (1..=12).contains(&month) && (1..=days_in_month(year, month)).contains(&day)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i32::try_from(month).expect("month fits i32");
    let day = i32::try_from(day).expect("day fits i32");
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era * 146_097 + day_of_era - 719_468)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateWindow {
    from: UtcDate,
    to: UtcDate,
}

impl DateWindow {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Result<Self, ModelError> {
        let window = Self {
            from: UtcDate::new(from)?,
            to: UtcDate::new(to)?,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn from_date(&self) -> &UtcDate {
        &self.from
    }

    pub fn to_date(&self) -> &UtcDate {
        &self.to
    }

    pub fn days(&self) -> u16 {
        u16::try_from(self.to.ordinal() - self.from.ordinal() + 1)
            .expect("validated date window fits u16")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let days = self.to.ordinal() - self.from.ordinal() + 1;
        if !(1..=RUDDERSTACK_MAX_WINDOW_DAYS).contains(&days) {
            Err(ModelError::InvalidDateWindow)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "rudderstack-date-window/v1",
            &[self.from.as_str().to_owned(), self.to.as_str().to_owned()],
        )
    }
}

/// Hash-only event and property labels.  The constructors accept a label for
/// fixture generation and immediately discard it; no raw label is retained.
macro_rules! digest_only_label {
    ($name:ident, $domain:literal, $label:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                valid_text(&value, $label, 128)?;
                Ok(Self(Digest::from_fields($domain, &[value])))
            }

            pub fn from_digest(value: Digest) -> Result<Self, ModelError> {
                Digest::parse(value.as_str().to_owned())?;
                Ok(Self(value))
            }

            pub fn digest(&self) -> Digest {
                self.0.clone()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.0)
                    .finish()
            }
        }
    };
}

digest_only_label!(EventNameDigest, "rudderstack-event-name/v1", "event name");
digest_only_label!(
    PropertyNameDigest,
    "rudderstack-property-name/v1",
    "property name"
);

macro_rules! scoped_binding {
    ($name:ident, $id:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
                Ok(Self {
                    id: $id::new(id)?,
                    revision: Revision::new(revision)?,
                })
            }

            pub fn id(&self) -> &$id {
                &self.id
            }

            pub const fn revision(&self) -> Revision {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                canonical_digest(self)
            }
        }
    };
}

scoped_binding!(OrganizationScope, OrganizationId, "organization id");
scoped_binding!(WorkspaceScope, WorkspaceId, "workspace id");
scoped_binding!(SourceScope, SourceId, "source id");
scoped_binding!(DestinationScope, DestinationId, "destination id");
scoped_binding!(TrackingPlanScope, TrackingPlanId, "tracking plan id");
scoped_binding!(ProjectScope, ProjectId, "Project id");
scoped_binding!(MissionScope, MissionId, "Mission id");
scoped_binding!(WorkProductScope, WorkProductId, "Work Product id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaViolationKind {
    UnplannedEvent,
    MissingRequiredProperty,
    DatatypeMismatch,
    AdditionalProperty,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ViolationScope {
    pub revision: Revision,
    pub allowed: BTreeSet<SchemaViolationKind>,
}

impl ViolationScope {
    pub fn new<I>(revision: u64, allowed: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = SchemaViolationKind>,
    {
        let allowed = allowed.into_iter().collect::<BTreeSet<_>>();
        if allowed.is_empty() || allowed.len() > 5 {
            return Err(ModelError::InvalidScope);
        }
        Ok(Self {
            revision: Revision::new(revision)?,
            allowed,
        })
    }

    pub fn all(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            revision,
            [
                SchemaViolationKind::UnplannedEvent,
                SchemaViolationKind::MissingRequiredProperty,
                SchemaViolationKind::DatatypeMismatch,
                SchemaViolationKind::AdditionalProperty,
                SchemaViolationKind::Unknown,
            ],
        )
    }

    pub fn contains(&self, kind: SchemaViolationKind) -> bool {
        self.allowed.contains(&kind)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RudderStackPermission {
    SourceMetadataRead,
    TrackingPlanVersionsRead,
    SchemaViolationsRead,
    DeliveryHealthRead,
    GovernanceMetricsRead,
}

impl RudderStackPermission {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SourceMetadataRead => "source_metadata.read",
            Self::TrackingPlanVersionsRead => "tracking_plan_versions.read",
            Self::SchemaViolationsRead => "schema_violations.read",
            Self::DeliveryHealthRead => "delivery_health.read",
            Self::GovernanceMetricsRead => "governance_metrics.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackPermissionSet {
    pub permissions: BTreeSet<RudderStackPermission>,
    pub revision: Revision,
}

impl RudderStackPermissionSet {
    pub fn new<I>(revision: u64, permissions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = RudderStackPermission>,
    {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions.is_empty() {
            return Err(ModelError::InvalidPermissionSet);
        }
        Ok(Self {
            permissions,
            revision: Revision::new(revision)?,
        })
    }

    pub fn least_privilege(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            revision,
            [
                RudderStackPermission::SourceMetadataRead,
                RudderStackPermission::TrackingPlanVersionsRead,
                RudderStackPermission::SchemaViolationsRead,
                RudderStackPermission::DeliveryHealthRead,
                RudderStackPermission::GovernanceMetricsRead,
            ],
        )
    }

    pub fn has(&self, permission: RudderStackPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyPolicy {
    pub version: String,
    pub raw_events_dropped: bool,
    pub raw_payloads_dropped: bool,
    pub identities_dropped: bool,
    pub secret_material_dropped: bool,
    pub raw_cursors_dropped: bool,
    pub max_response_bytes: usize,
}

impl PrivacyPolicy {
    pub fn strict_v1() -> Self {
        Self {
            version: RUDDERSTACK_PRIVACY_POLICY_VERSION.to_owned(),
            raw_events_dropped: true,
            raw_payloads_dropped: true,
            identities_dropped: true,
            secret_material_dropped: true,
            raw_cursors_dropped: true,
            max_response_bytes: RUDDERSTACK_MAX_RESPONSE_BYTES,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.version != RUDDERSTACK_PRIVACY_POLICY_VERSION
            || !self.raw_events_dropped
            || !self.raw_payloads_dropped
            || !self.identities_dropped
            || !self.secret_material_dropped
            || !self.raw_cursors_dropped
            || self.max_response_bytes == 0
            || self.max_response_bytes > RUDDERSTACK_MAX_RESPONSE_BYTES
        {
            Err(ModelError::InvalidPrivacyPolicy)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackScope {
    pub organization: OrganizationScope,
    pub workspace: WorkspaceScope,
    pub source: SourceScope,
    pub destination: Option<DestinationScope>,
    pub tracking_plan: Option<TrackingPlanScope>,
    pub violation: ViolationScope,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub window: DateWindow,
    pub permissions: RudderStackPermissionSet,
    pub privacy_policy: PrivacyPolicy,
}

impl RudderStackScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationScope,
        workspace: WorkspaceScope,
        source: SourceScope,
        destination: Option<DestinationScope>,
        tracking_plan: Option<TrackingPlanScope>,
        violation: ViolationScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        window: DateWindow,
        permissions: RudderStackPermissionSet,
        privacy_policy: PrivacyPolicy,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            organization,
            workspace,
            source,
            destination,
            tracking_plan,
            violation,
            project,
            mission,
            work_product,
            window,
            permissions,
            privacy_policy,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.window.validate()?;
        self.privacy_policy.validate()?;
        if self.permissions.permissions.is_empty() || self.violation.allowed.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        self.permissions.digest()
    }

    pub fn privacy_digest(&self) -> Digest {
        self.privacy_policy.digest()
    }

    pub fn revision_digest(&self) -> Digest {
        canonical_digest(&(
            self.organization.revision,
            self.workspace.revision,
            self.source.revision,
            self.destination.as_ref().map(DestinationScope::revision),
            self.tracking_plan.as_ref().map(TrackingPlanScope::revision),
            self.violation.revision,
            self.project.revision,
            self.mission.revision,
            self.work_product.revision,
            self.permissions.revision,
        ))
    }
}

pub type RudderStackEventQualityScope = RudderStackScope;
pub type ProjectBinding = ProjectScope;
pub type MissionBinding = MissionScope;
pub type WorkProductBinding = WorkProductScope;

/// An opaque API-token reference.  Deliberately does not implement
/// `Serialize` or `Deserialize`; only its digest can cross a receipt boundary.
pub struct SecretReference {
    opaque_id: String,
    revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            opaque_id: self.opaque_id.clone(),
            revision: self.revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.opaque_id == other.opaque_id
            && self.revision == other.revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

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

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let opaque_id = opaque_id.into();
        valid_text(
            &opaque_id,
            "opaque API-token reference",
            RUDDERSTACK_MAX_IDENTIFIER_BYTES,
        )?;
        Ok(Self {
            opaque_id,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn api_token(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::new(opaque_id, revision)
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "rudderstack-secret-reference/v1",
            &[
                self.opaque_id.clone(),
                self.revision.get().to_string(),
                self.revoked.to_string(),
            ],
        )
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackRegistration {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub privacy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl RudderStackRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_version_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        privacy_digest: Digest,
        secret_reference_digest: Digest,
    ) -> Result<Self, ModelError> {
        for digest in [
            &plugin_version_digest,
            &contract_digest,
            &provider_digest,
            &permission_digest,
            &scope_digest,
            &privacy_digest,
            &secret_reference_digest,
        ] {
            Digest::parse(digest.as_str().to_owned())?;
        }
        let mut registration = Self {
            plugin_version_digest,
            contract_digest,
            provider_digest,
            permission_digest,
            scope_digest,
            privacy_digest,
            secret_reference_digest,
            evidence_digest: Digest::zero(),
            revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.refresh_digest();
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.privacy_digest,
            &self.secret_reference_digest,
            &self.evidence_digest,
            &self.registration_digest,
        ] {
            Digest::parse(digest.as_str().to_owned())?;
        }
        let expected = self.compute_digest();
        if expected != self.registration_digest {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn bind_evidence(&mut self, evidence_digest: Digest) -> Result<(), ModelError> {
        Digest::parse(evidence_digest.as_str().to_owned())?;
        if self.evidence_digest == evidence_digest {
            return Ok(());
        }
        self.evidence_digest = evidence_digest;
        self.bump_revision()?;
        self.refresh_digest();
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.bump_revision()?;
        self.refresh_digest();
        Ok(RegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            revision: self.revision,
            state: self.state,
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.state = RegistrationState::Active;
        self.bump_revision()?;
        self.refresh_digest();
        Ok(RegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            revision: self.revision,
            state: self.state,
        })
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    fn bump_revision(&mut self) -> Result<(), ModelError> {
        self.revision = Revision::new(
            self.revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        Ok(())
    }

    fn refresh_digest(&mut self) {
        self.registration_digest = self.compute_digest();
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.privacy_digest,
            &self.secret_reference_digest,
            &self.evidence_digest,
            self.revision,
            self.state,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

pub type Registration = RudderStackRegistration;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

pub type ProviderProvenance = TransportProvenance;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    Empty,
    RateLimited,
    AccessLost,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Normalized,
    Empty,
    Partial,
    RateLimited,
    AccessLost,
    BlockedEnv,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: u16,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
    pub receipt_digest: Digest,
}

impl Default for RateLimitReceipt {
    fn default() -> Self {
        Self::new(60, Some(60), None, false).expect("default rate receipt is valid")
    }
}

impl RateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self, ModelError> {
        if limit_per_minute == 0
            || limit_per_minute > RUDDERSTACK_MAX_REQUESTS_PER_MINUTE
            || remaining.is_some_and(|value| value > limit_per_minute)
            || retry_after_seconds.is_some_and(|value| value > 3_600)
            || throttled != retry_after_seconds.is_some()
        {
            return Err(ModelError::InvalidRateLimit);
        }
        let mut receipt = Self {
            limit_per_minute,
            remaining: remaining.unwrap_or(0),
            retry_after_seconds,
            throttled,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit_per_minute == 0
            || self.limit_per_minute > RUDDERSTACK_MAX_REQUESTS_PER_MINUTE
            || self.remaining > self.limit_per_minute
            || self.retry_after_seconds.is_some_and(|value| value > 3_600)
            || self.throttled != self.retry_after_seconds.is_some()
            || self.receipt_digest != self.compute_digest()
        {
            Err(ModelError::InvalidRateLimit)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        self.receipt_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            self.limit_per_minute,
            self.remaining,
            self.retry_after_seconds,
            self.throttled,
        ))
    }
}

/// A cursor receipt retains only a digest of the provider cursor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorReceipt {
    pub cursor_digest: Option<Digest>,
    pub page: u32,
    pub page_size: u16,
    pub has_more: bool,
    pub request_digest: Digest,
    pub receipt_digest: Digest,
}

impl CursorReceipt {
    pub fn from_opaque(
        cursor: Option<&str>,
        page: u32,
        page_size: u16,
        has_more: bool,
        request_digest: Digest,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || usize::from(page_size) > RUDDERSTACK_MAX_PAGE_SIZE {
            return Err(ModelError::InvalidCursor);
        }
        if cursor.is_some_and(|value| {
            value.is_empty()
                || value.len() > RUDDERSTACK_MAX_CURSOR_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(ModelError::InvalidCursor);
        }
        let cursor_digest = cursor.map(|value| Digest::from_text(value.as_bytes()));
        let mut receipt = Self {
            cursor_digest,
            page,
            page_size,
            has_more,
            request_digest,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    pub fn none(page_size: u16, request_digest: Digest) -> Result<Self, ModelError> {
        Self::from_opaque(None, 0, page_size, false, request_digest)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_size == 0
            || usize::from(self.page_size) > RUDDERSTACK_MAX_PAGE_SIZE
            || self.receipt_digest != self.compute_digest()
        {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        self.receipt_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.cursor_digest,
            self.page,
            self.page_size,
            self.has_more,
            &self.request_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_events_dropped: bool,
    pub raw_payloads_dropped: bool,
    pub identities_dropped: bool,
    pub secret_material_dropped: bool,
    pub raw_cursors_dropped: bool,
    pub diagnostic_bytes_dropped: usize,
    pub policy_digest: Digest,
}

impl RedactionSummary {
    pub fn strict(policy: &PrivacyPolicy) -> Self {
        Self {
            raw_events_dropped: true,
            raw_payloads_dropped: true,
            identities_dropped: true,
            secret_material_dropped: true,
            raw_cursors_dropped: true,
            diagnostic_bytes_dropped: RUDDERSTACK_MAX_DIAGNOSTIC_BYTES,
            policy_digest: policy.digest(),
        }
    }

    pub fn is_strict(&self) -> bool {
        self.raw_events_dropped
            && self.raw_payloads_dropped
            && self.identities_dropped
            && self.secret_material_dropped
            && self.raw_cursors_dropped
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    JavaScript,
    Mobile,
    Server,
    Cloud,
    Warehouse,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackSourceMetadata {
    pub source: SourceId,
    pub revision: Revision,
    pub source_type: SourceType,
    pub state: SourceState,
    pub event_model_count: u32,
    pub destination_count: u16,
    pub tracking_plan_count: u16,
    pub metadata_digest: Digest,
}

impl RudderStackSourceMetadata {
    pub fn new(
        source: impl Into<String>,
        revision: u64,
        source_type: SourceType,
        state: SourceState,
        event_model_count: u32,
        destination_count: u16,
        tracking_plan_count: u16,
    ) -> Result<Self, ModelError> {
        if u64::from(event_model_count) > RUDDERSTACK_MAX_AGGREGATE_COUNT
            || u64::from(destination_count) > RUDDERSTACK_MAX_AGGREGATE_COUNT
            || u64::from(tracking_plan_count) > RUDDERSTACK_MAX_AGGREGATE_COUNT
        {
            return Err(ModelError::BoundExceeded);
        }
        let mut metadata = Self {
            source: SourceId::new(source)?,
            revision: Revision::new(revision)?,
            source_type,
            state,
            event_model_count,
            destination_count,
            tracking_plan_count,
            metadata_digest: Digest::zero(),
        };
        metadata.metadata_digest = metadata.compute_digest();
        Ok(metadata)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.metadata_digest != self.compute_digest()
            || u64::from(self.event_model_count) > RUDDERSTACK_MAX_AGGREGATE_COUNT
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        self.metadata_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.source,
            self.revision,
            self.source_type,
            self.state,
            self.event_model_count,
            self.destination_count,
            self.tracking_plan_count,
        ))
    }
}

pub type SourceMetadata = RudderStackSourceMetadata;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingPlanState {
    Draft,
    Published,
    Archived,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackTrackingPlanVersion {
    pub tracking_plan: TrackingPlanId,
    pub version: u32,
    pub revision: Revision,
    pub state: TrackingPlanState,
    pub event_name_digests: Vec<EventNameDigest>,
    pub property_digests: Vec<PropertyNameDigest>,
    pub schema_digest: SchemaDigest,
    pub version_digest: Digest,
}

impl RudderStackTrackingPlanVersion {
    pub fn new<I, P>(
        tracking_plan: impl Into<String>,
        version: u32,
        revision: u64,
        state: TrackingPlanState,
        event_names: I,
        properties: P,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = String>,
        P: IntoIterator<Item = String>,
    {
        let event_name_digests = event_names
            .into_iter()
            .map(EventNameDigest::new)
            .collect::<Result<Vec<_>, _>>()?;
        let property_digests = properties
            .into_iter()
            .map(PropertyNameDigest::new)
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_digests(
            tracking_plan,
            version,
            revision,
            state,
            event_name_digests,
            property_digests,
        )
    }

    pub fn from_digests(
        tracking_plan: impl Into<String>,
        version: u32,
        revision: u64,
        state: TrackingPlanState,
        mut event_name_digests: Vec<EventNameDigest>,
        mut property_digests: Vec<PropertyNameDigest>,
    ) -> Result<Self, ModelError> {
        if version == 0
            || event_name_digests.is_empty()
            || event_name_digests.len() > RUDDERSTACK_MAX_EVENT_NAMES
            || property_digests.len() > RUDDERSTACK_MAX_PROPERTIES
        {
            return Err(ModelError::BoundExceeded);
        }
        event_name_digests.sort();
        property_digests.sort();
        if event_name_digests.windows(2).any(|pair| pair[0] == pair[1])
            || property_digests.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ModelError::DuplicateValue);
        }
        let schema_digest = canonical_digest(&(
            "rudderstack-schema/v1",
            &event_name_digests,
            &property_digests,
        ));
        let tracking_plan = TrackingPlanId::new(tracking_plan)?;
        let mut value = Self {
            tracking_plan,
            version,
            revision: Revision::new(revision)?,
            state,
            event_name_digests,
            property_digests,
            schema_digest,
            version_digest: Digest::zero(),
        };
        value.version_digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.version == 0
            || self.event_name_digests.is_empty()
            || self.event_name_digests.len() > RUDDERSTACK_MAX_EVENT_NAMES
            || self.property_digests.len() > RUDDERSTACK_MAX_PROPERTIES
            || self
                .event_name_digests
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || self
                .property_digests
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || self.version_digest != self.compute_digest()
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        self.version_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.tracking_plan,
            self.version,
            self.revision,
            self.state,
            &self.event_name_digests,
            &self.property_digests,
            &self.schema_digest,
        ))
    }
}

pub type TrackingPlanVersion = RudderStackTrackingPlanVersion;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackSchemaViolationAggregate {
    pub violation_kind: SchemaViolationKind,
    pub event_name_digest: Option<EventNameDigest>,
    pub property_name_digest: Option<PropertyNameDigest>,
    pub tracking_plan: Option<TrackingPlanId>,
    pub tracking_plan_version: Option<u32>,
    pub count: u64,
    pub violation_digest: Digest,
}

impl RudderStackSchemaViolationAggregate {
    pub fn new(
        violation_kind: SchemaViolationKind,
        event_name: Option<String>,
        property_name: Option<String>,
        tracking_plan: Option<String>,
        tracking_plan_version: Option<u32>,
        count: u64,
    ) -> Result<Self, ModelError> {
        let event_name_digest = event_name.map(EventNameDigest::new).transpose()?;
        let property_name_digest = property_name.map(PropertyNameDigest::new).transpose()?;
        let tracking_plan = tracking_plan.map(TrackingPlanId::new).transpose()?;
        Self::from_digests(
            violation_kind,
            event_name_digest,
            property_name_digest,
            tracking_plan,
            tracking_plan_version,
            count,
        )
    }

    pub fn for_event(
        violation_kind: SchemaViolationKind,
        event_name: impl Into<String>,
        count: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            violation_kind,
            Some(event_name.into()),
            None,
            None,
            None,
            count,
        )
    }

    pub fn from_digests(
        violation_kind: SchemaViolationKind,
        event_name_digest: Option<EventNameDigest>,
        property_name_digest: Option<PropertyNameDigest>,
        tracking_plan: Option<TrackingPlanId>,
        tracking_plan_version: Option<u32>,
        count: u64,
    ) -> Result<Self, ModelError> {
        if count == 0 || count > RUDDERSTACK_MAX_AGGREGATE_COUNT {
            return Err(ModelError::BoundExceeded);
        }
        if tracking_plan_version.is_some_and(|version| version == 0) {
            return Err(ModelError::InvalidRevision {
                field: "tracking plan version",
            });
        }
        if matches!(violation_kind, SchemaViolationKind::UnplannedEvent)
            && property_name_digest.is_some()
        {
            return Err(ModelError::InvalidMetric);
        }
        let mut value = Self {
            violation_kind,
            event_name_digest,
            property_name_digest,
            tracking_plan,
            tracking_plan_version,
            count,
            violation_digest: Digest::zero(),
        };
        value.violation_digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.count == 0
            || self.count > RUDDERSTACK_MAX_AGGREGATE_COUNT
            || self
                .tracking_plan_version
                .is_some_and(|version| version == 0)
            || self.violation_digest != self.compute_digest()
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        self.violation_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            self.violation_kind,
            &self.event_name_digest,
            &self.property_name_digest,
            &self.tracking_plan,
            self.tracking_plan_version,
            self.count,
        ))
    }
}

pub type SchemaViolationAggregate = RudderStackSchemaViolationAggregate;
pub type SchemaViolation = RudderStackSchemaViolationAggregate;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackDeliveryHealthAggregate {
    pub destination: DestinationId,
    pub revision: Revision,
    pub delivered: u64,
    pub failed: u64,
    pub retried: u64,
    pub dropped: u64,
    pub health_digest: Digest,
}

impl RudderStackDeliveryHealthAggregate {
    pub fn new(
        destination: impl Into<String>,
        revision: u64,
        delivered: u64,
        failed: u64,
        retried: u64,
        dropped: u64,
    ) -> Result<Self, ModelError> {
        if [delivered, failed, retried, dropped]
            .into_iter()
            .any(|value| value > RUDDERSTACK_MAX_AGGREGATE_COUNT)
        {
            return Err(ModelError::BoundExceeded);
        }
        let mut value = Self {
            destination: DestinationId::new(destination)?,
            revision: Revision::new(revision)?,
            delivered,
            failed,
            retried,
            dropped,
            health_digest: Digest::zero(),
        };
        value.health_digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if [self.delivered, self.failed, self.retried, self.dropped]
            .into_iter()
            .any(|value| value > RUDDERSTACK_MAX_AGGREGATE_COUNT)
            || self.health_digest != self.compute_digest()
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        self.health_digest.clone()
    }

    pub fn attempted(&self) -> u64 {
        self.delivered
            .saturating_add(self.failed)
            .saturating_add(self.dropped)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.destination,
            self.revision,
            self.delivered,
            self.failed,
            self.retried,
            self.dropped,
        ))
    }
}

pub type DeliveryHealthAggregate = RudderStackDeliveryHealthAggregate;
pub type DeliveryHealth = RudderStackDeliveryHealthAggregate;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackGovernanceMetrics {
    pub window: DateWindow,
    pub events_validated: u64,
    pub events_with_violations: u64,
    pub events_dropped: u64,
    pub events_forwarded: u64,
    pub events_delivered: u64,
    pub delivery_failures: u64,
    pub violation_counts: BTreeMap<SchemaViolationKind, u64>,
    pub metrics_digest: Digest,
}

impl RudderStackGovernanceMetrics {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window: DateWindow,
        events_validated: u64,
        events_with_violations: u64,
        events_dropped: u64,
        events_forwarded: u64,
        events_delivered: u64,
        delivery_failures: u64,
        violation_counts: BTreeMap<SchemaViolationKind, u64>,
    ) -> Result<Self, ModelError> {
        window.validate()?;
        let values = [
            events_validated,
            events_with_violations,
            events_dropped,
            events_forwarded,
            events_delivered,
            delivery_failures,
        ];
        if values
            .into_iter()
            .any(|value| value > RUDDERSTACK_MAX_AGGREGATE_COUNT)
            || violation_counts.len() > 5
            || violation_counts
                .values()
                .any(|value| *value > RUDDERSTACK_MAX_AGGREGATE_COUNT)
        {
            return Err(ModelError::BoundExceeded);
        }
        let mut value = Self {
            window,
            events_validated,
            events_with_violations,
            events_dropped,
            events_forwarded,
            events_delivered,
            delivery_failures,
            violation_counts,
            metrics_digest: Digest::zero(),
        };
        value.metrics_digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.window.validate()?;
        if self.metrics_digest != self.compute_digest()
            || self.violation_counts.len() > 5
            || self
                .violation_counts
                .values()
                .any(|value| *value > RUDDERSTACK_MAX_AGGREGATE_COUNT)
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        self.metrics_digest.clone()
    }

    pub fn violation_rate_basis(&self) -> (u64, u64) {
        (self.events_with_violations, self.events_validated)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.window,
            self.events_validated,
            self.events_with_violations,
            self.events_dropped,
            self.events_forwarded,
            self.events_delivered,
            self.delivery_failures,
            &self.violation_counts,
        ))
    }
}

pub type GovernanceMetrics = RudderStackGovernanceMetrics;
pub type AggregateGovernanceMetrics = RudderStackGovernanceMetrics;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub privacy_digest: Digest,
    pub response_digest: Digest,
    pub source_metadata_digest: Digest,
    pub tracking_plan_digest: Digest,
    pub violations_digest: Digest,
    pub delivery_digest: Digest,
    pub governance_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackEventQualityEvidence {
    pub state: EvidenceState,
    pub classification: EvidenceClassification,
    pub provenance: TransportProvenance,
    pub source_metadata: Option<RudderStackSourceMetadata>,
    pub tracking_plan_versions: Vec<RudderStackTrackingPlanVersion>,
    pub violations: Vec<RudderStackSchemaViolationAggregate>,
    pub delivery_health: Vec<RudderStackDeliveryHealthAggregate>,
    pub governance_metrics: Option<RudderStackGovernanceMetrics>,
    pub cursor_receipts: Vec<CursorReceipt>,
    pub rate_limit_receipts: Vec<RateLimitReceipt>,
    pub response_digests: Vec<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub privacy_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub page_count: u16,
    pub complete_pagination: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub redaction: RedactionSummary,
    pub digests: RudderStackEvidenceDigests,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestInput<'a> {
    state: EvidenceState,
    classification: EvidenceClassification,
    provenance: TransportProvenance,
    source_metadata: &'a Option<RudderStackSourceMetadata>,
    tracking_plan_versions: &'a Vec<RudderStackTrackingPlanVersion>,
    violations: &'a Vec<RudderStackSchemaViolationAggregate>,
    delivery_health: &'a Vec<RudderStackDeliveryHealthAggregate>,
    governance_metrics: &'a Option<RudderStackGovernanceMetrics>,
    cursor_receipts: &'a Vec<CursorReceipt>,
    rate_limit_receipts: &'a Vec<RateLimitReceipt>,
    response_digests: &'a Vec<Digest>,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    privacy_digest: &'a Digest,
    provider_digest: &'a Digest,
    page_count: u16,
    complete_pagination: bool,
    proposal_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    redaction: &'a RedactionSummary,
    digests: &'a RudderStackEvidenceDigests,
}

impl RudderStackEventQualityEvidence {
    pub fn digest(&self) -> Digest {
        self.compute_digest()
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.evidence_digest == self.compute_digest()
            && self.redaction.is_strict()
            && !self.connected
            && !self.native
            && !self.first_party
            && self.proposal_only
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self.state, EvidenceState::Complete | EvidenceState::Partial)
    }

    pub fn has_raw_event_or_payload_path(&self) -> bool {
        false
    }

    pub(crate) fn from_parts(
        state: EvidenceState,
        classification: EvidenceClassification,
        provenance: TransportProvenance,
        mut source_metadata: Option<RudderStackSourceMetadata>,
        mut tracking_plan_versions: Vec<RudderStackTrackingPlanVersion>,
        mut violations: Vec<RudderStackSchemaViolationAggregate>,
        mut delivery_health: Vec<RudderStackDeliveryHealthAggregate>,
        mut governance_metrics: Option<RudderStackGovernanceMetrics>,
        mut cursor_receipts: Vec<CursorReceipt>,
        mut rate_limit_receipts: Vec<RateLimitReceipt>,
        mut response_digests: Vec<Digest>,
        scope: &RudderStackScope,
        provider_digest: Digest,
        registration_digest: Digest,
        page_count: u16,
        complete_pagination: bool,
    ) -> Self {
        tracking_plan_versions.sort_by_key(RudderStackTrackingPlanVersion::digest);
        violations.sort_by_key(RudderStackSchemaViolationAggregate::digest);
        delivery_health.sort_by_key(RudderStackDeliveryHealthAggregate::digest);
        cursor_receipts.sort_by_key(CursorReceipt::digest);
        rate_limit_receipts.sort_by_key(RateLimitReceipt::digest);
        response_digests.sort();
        response_digests.dedup();
        let source_metadata_digest = source_metadata
            .as_ref()
            .map_or_else(Digest::zero, RudderStackSourceMetadata::digest);
        let tracking_plan_digest = canonical_digest(&tracking_plan_versions);
        let violations_digest = canonical_digest(&violations);
        let delivery_digest = canonical_digest(&delivery_health);
        let governance_digest = governance_metrics
            .as_ref()
            .map_or_else(Digest::zero, RudderStackGovernanceMetrics::digest);
        let response_digest = canonical_digest(&response_digests);
        let digests = RudderStackEvidenceDigests {
            plugin_version_digest: Digest::from_text(RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT),
            contract_digest: crate::contract_digest(),
            provider_digest: provider_digest.clone(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.digest(),
            privacy_digest: scope.privacy_digest(),
            response_digest,
            source_metadata_digest,
            tracking_plan_digest,
            violations_digest,
            delivery_digest,
            governance_digest,
        };
        let redaction = RedactionSummary::strict(&scope.privacy_policy);
        let mut evidence = Self {
            state,
            classification,
            provenance,
            source_metadata: source_metadata.take(),
            tracking_plan_versions,
            violations,
            delivery_health,
            governance_metrics: governance_metrics.take(),
            cursor_receipts,
            rate_limit_receipts,
            response_digests,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest(),
            privacy_digest: scope.privacy_digest(),
            provider_digest,
            registration_digest,
            page_count,
            complete_pagination,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            redaction,
            digests,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&EvidenceDigestInput {
            state: self.state,
            classification: self.classification,
            provenance: self.provenance,
            source_metadata: &self.source_metadata,
            tracking_plan_versions: &self.tracking_plan_versions,
            violations: &self.violations,
            delivery_health: &self.delivery_health,
            governance_metrics: &self.governance_metrics,
            cursor_receipts: &self.cursor_receipts,
            rate_limit_receipts: &self.rate_limit_receipts,
            response_digests: &self.response_digests,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            privacy_digest: &self.privacy_digest,
            provider_digest: &self.provider_digest,
            page_count: self.page_count,
            complete_pagination: self.complete_pagination,
            proposal_only: self.proposal_only,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            redaction: &self.redaction,
            digests: &self.digests,
        })
    }
}

pub type RudderStackEvidence = RudderStackEventQualityEvidence;
pub type EventQualityEvidence = RudderStackEventQualityEvidence;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewTrackingPlanCompliance,
    ReviewSchemaViolations,
    ReviewDeliveryHealth,
    NoRecommendationPartial,
    NoRecommendationEmpty,
    NoRecommendationRateLimited,
    NoRecommendationAccessLost,
    NoRecommendationProviderUnknown,
    NoRecommendationTamper,
    NoRecommendationStale,
    NoRecommendationRevoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackEventQualityRecommendation {
    pub disposition: RecommendationDisposition,
    pub provider_reported_only: bool,
    pub non_mutating: bool,
    pub claims_event_quality: bool,
    pub claims_schema_truth: bool,
    pub claims_delivery_success: bool,
    pub claims_business_success: bool,
    pub rationale_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackEventQualityProposal {
    pub scope: RudderStackScope,
    pub evidence: RudderStackEventQualityEvidence,
    pub recommendation: RudderStackEventQualityRecommendation,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_work_product: bool,
    pub adopts_outcome: bool,
    pub truth_authority: bool,
    pub proposal_digest: Digest,
}

impl RudderStackEventQualityProposal {
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.evidence,
            &self.recommendation,
            &self.evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.permission_digest,
            self.proposal_only,
            self.connected,
            self.native,
            self.first_party,
            self.adopts_work_product,
            self.adopts_outcome,
            self.truth_authority,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.proposal_digest == self.digest()
            && self.evidence_digest == self.evidence.digest()
            && self.proposal_only
            && !self.connected
            && !self.native
            && !self.first_party
            && !self.adopts_work_product
            && !self.adopts_outcome
            && !self.truth_authority
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

pub type RudderStackProposal = RudderStackEventQualityProposal;
pub type EventQualityProposal = RudderStackEventQualityProposal;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

impl RudderStackObservationReceipt {
    pub(crate) fn new(proposal: &RudderStackEventQualityProposal) -> Self {
        let mut receipt = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recorded: true,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = canonical_digest(&(
            &receipt.proposal_digest,
            &receipt.evidence_digest,
            &receipt.registration_digest,
            receipt.recorded,
            receipt.durable,
            receipt.connected,
            receipt.native,
            receipt.first_party,
        ));
        receipt
    }
}

pub type ObservationReceipt = RudderStackObservationReceipt;
pub type RecordReceipt = RudderStackObservationReceipt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackVerificationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub verified: bool,
    pub independent_native_readback: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verification_digest: Digest,
}

impl RudderStackVerificationReceipt {
    pub(crate) fn new(proposal: &RudderStackEventQualityProposal) -> Self {
        let mut receipt = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            verified: true,
            independent_native_readback: false,
            connected: false,
            native: false,
            first_party: false,
            verification_digest: Digest::zero(),
        };
        receipt.verification_digest = canonical_digest(&(
            &receipt.proposal_digest,
            &receipt.evidence_digest,
            receipt.verified,
            receipt.independent_native_readback,
            receipt.connected,
            receipt.native,
            receipt.first_party,
        ));
        receipt
    }
}

pub type VerificationReceipt = RudderStackVerificationReceipt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type ReadbackReceipt = RudderStackReadbackReceipt;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    DecisionReady,
    PartialEvidence,
    EmptyEvidence,
    RateLimited,
    AccessLost,
    ProviderUnknown,
    TamperDetected,
    StaleEvidence,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRudderStackEventResult {
    pub state: MissionResultState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub truth_authority: bool,
    pub result_digest: Digest,
}

impl MissionRudderStackEventResult {
    pub(crate) fn new(
        state: MissionResultState,
        proposal: &RudderStackEventQualityProposal,
    ) -> Self {
        let mut result = Self {
            state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            truth_authority: false,
            result_digest: Digest::zero(),
        };
        result.result_digest = canonical_digest(&(
            result.state,
            &result.proposal_digest,
            &result.evidence_digest,
            result.proposal_only,
            result.connected,
            result.native,
            result.first_party,
            result.adopts_outcome,
            result.truth_authority,
        ));
        result
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq)]
pub enum ProviderErrorKind {
    #[error("blocked environment")]
    BlockedEnv,
    #[error("access lost")]
    AccessLost,
    #[error("rate limited")]
    RateLimited,
    #[error("provider unknown")]
    ProviderUnknown,
    #[error("response tamper")]
    Tamper,
    #[error("stale revision")]
    Stale,
    #[error("permission denied")]
    PermissionDenied,
    #[error("malformed response")]
    MalformedResponse,
    #[error("response too large")]
    ResponseTooLarge,
}

pub type RudderStackProviderErrorKind = ProviderErrorKind;
