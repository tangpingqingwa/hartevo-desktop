use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PLUGIN_VERSION, PROVIDER_ID};

pub const MAX_IDENTIFIER_BYTES: usize = 254;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES_PER_OPERATION: u16 = 8;
pub const MAX_REQUESTS_PER_READ: u16 = 24;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PLAN_EVENT_SPECS: usize = 256;
pub const MAX_HISTORY_ENTRIES: usize = 256;
pub const MAX_DIAGNOSTICS: usize = 16;
pub const MAX_DIAGNOSTIC_BYTES: usize = 64;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Snowplow typed value serializes");
    sha256_digest(&bytes)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_digest(value: &str) -> Result<(), SnowplowModelError> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(SnowplowModelError::InvalidDigest)
    }
}

fn valid_text(value: &str, max_bytes: usize, allow_spaces: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_spaces || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SnowplowModelError {
    #[error("Snowplow identifier is empty, malformed, or too long: {0}")]
    InvalidIdentifier(&'static str),
    #[error("Snowplow text is empty, malformed, or too long: {0}")]
    InvalidText(&'static str),
    #[error("Snowplow digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Snowplow revision is outside the allowed range")]
    InvalidRevision,
    #[error("Snowplow permission set is not least privilege")]
    InvalidPermissionSet,
    #[error("Snowplow consent scope is invalid")]
    InvalidConsent,
    #[error("Snowplow scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Snowplow page size is outside the Layer-1 bound")]
    InvalidPageSize,
    #[error("Snowplow page count is outside the Layer-1 bound")]
    InvalidPageCount,
    #[error("Snowplow response is outside the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("Snowplow rate-limit receipt is invalid")]
    InvalidRateLimitReceipt,
    #[error("Snowplow registration is already revoked")]
    AlreadyRevoked,
    #[error("Snowplow registration is not revoked")]
    NotRevoked,
    #[error("Snowplow registration revision overflowed")]
    RevisionOverflow,
    #[error("Snowplow registration is inactive")]
    RegistrationInactive,
}

/// Resource identifiers are accepted only at construction time. They have no
/// serializer, no raw accessor, and a redacted Debug implementation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SnowplowResourceId(String);

impl SnowplowResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, SnowplowModelError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(SnowplowModelError::InvalidIdentifier("resource id"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(format!("snowplow-resource-id/v1|{}", self.0).as_bytes())
    }

    #[must_use]
    pub fn redacted(&self) -> String {
        format!("resource:{}", &self.digest()[..16])
    }
}

impl fmt::Debug for SnowplowResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SnowplowResourceId")
            .field(&self.redacted())
            .finish()
    }
}

pub type OrganizationId = SnowplowResourceId;
pub type TrackingPlanId = SnowplowResourceId;
pub type EventSpecId = SnowplowResourceId;

#[derive(Clone, Eq, PartialEq)]
pub struct SnowplowIdentityBinding {
    id: SnowplowResourceId,
    revision: u64,
}

impl SnowplowIdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, SnowplowModelError> {
        if revision == 0 {
            return Err(SnowplowModelError::InvalidRevision);
        }
        Ok(Self {
            id: SnowplowResourceId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(&self.id.digest(), self.revision))
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for SnowplowIdentityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowplowIdentityBinding")
            .field("id_digest", &self.id.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

pub type ProjectBinding = SnowplowIdentityBinding;
pub type MissionBinding = SnowplowIdentityBinding;
pub type WorkProductBinding = SnowplowIdentityBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowPermission {
    TrackingPlanRead,
    EventSpecRead,
    TrackingPlanHistoryRead,
}

impl SnowplowPermission {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrackingPlanRead => "snowplow.tracking_plan.read",
            Self::EventSpecRead => "snowplow.event_spec.read",
            Self::TrackingPlanHistoryRead => "snowplow.tracking_plan.history.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowPermissionSet {
    permissions: BTreeSet<SnowplowPermission>,
    revision: u64,
}

impl SnowplowPermissionSet {
    pub fn read_only(revision: u64) -> Result<Self, SnowplowModelError> {
        Self::new(
            [
                SnowplowPermission::TrackingPlanRead,
                SnowplowPermission::EventSpecRead,
                SnowplowPermission::TrackingPlanHistoryRead,
            ],
            revision,
        )
    }

    pub fn new(
        permissions: impl IntoIterator<Item = SnowplowPermission>,
        revision: u64,
    ) -> Result<Self, SnowplowModelError> {
        if revision == 0 {
            return Err(SnowplowModelError::InvalidRevision);
        }
        let permission_set = Self {
            permissions: permissions.into_iter().collect(),
            revision,
        };
        permission_set.validate()?;
        Ok(permission_set)
    }

    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        let expected = LAYER1_PERMISSIONS.iter().copied().collect::<BTreeSet<_>>();
        let actual = self
            .permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect::<BTreeSet<_>>();
        if actual != expected || self.revision == 0 {
            return Err(SnowplowModelError::InvalidPermissionSet);
        }
        Ok(())
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<SnowplowPermission> {
        &self.permissions
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowConsentScope {
    consent_digest: Digest,
    revision: u64,
}

impl SnowplowConsentScope {
    pub fn new(reference: impl Into<String>, revision: u64) -> Result<Self, SnowplowModelError> {
        let reference = reference.into();
        if !valid_text(&reference, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            return Err(SnowplowModelError::InvalidConsent);
        }
        Ok(Self {
            consent_digest: sha256_digest(format!("snowplow-consent/v1|{reference}").as_bytes()),
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        validate_digest(&self.consent_digest)?;
        if self.revision == 0 {
            return Err(SnowplowModelError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnowplowTrackingPlanScopeSpec {
    pub organization: OrganizationId,
    pub tracking_plan: TrackingPlanId,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: SnowplowConsentScope,
    pub permissions: SnowplowPermissionSet,
}

impl SnowplowTrackingPlanScopeSpec {
    pub fn new(
        organization: impl Into<String>,
        tracking_plan: impl Into<String>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: SnowplowConsentScope,
    ) -> Result<Self, SnowplowModelError> {
        Ok(Self {
            organization: SnowplowResourceId::new(organization)?,
            tracking_plan: SnowplowResourceId::new(tracking_plan)?,
            project,
            mission,
            work_product,
            consent,
            permissions: SnowplowPermissionSet::read_only(1)?,
        })
    }

    #[must_use]
    pub fn with_permissions(mut self, permissions: SnowplowPermissionSet) -> Self {
        self.permissions = permissions;
        self
    }
}

/// Exact provider/Mission scope. Its raw resource IDs never serialize.
#[derive(Clone, Eq, PartialEq)]
pub struct SnowplowTrackingPlanScope {
    organization: OrganizationId,
    tracking_plan: TrackingPlanId,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    consent: SnowplowConsentScope,
    permissions: SnowplowPermissionSet,
    scope_digest: Digest,
    revision_digest: Digest,
    privacy_digest: Digest,
}

impl fmt::Debug for SnowplowTrackingPlanScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowplowTrackingPlanScope")
            .field("scope_digest", &self.scope_digest)
            .field("revision_digest", &self.revision_digest)
            .field("privacy_digest", &self.privacy_digest)
            .finish_non_exhaustive()
    }
}

impl SnowplowTrackingPlanScope {
    pub fn new(spec: SnowplowTrackingPlanScopeSpec) -> Result<Self, SnowplowModelError> {
        spec.permissions.validate()?;
        spec.consent.validate()?;
        if spec.project.revision() == 0
            || spec.mission.revision() == 0
            || spec.work_product.revision() == 0
        {
            return Err(SnowplowModelError::InvalidScope("binding revision"));
        }
        let scope_digest = canonical_digest(&(
            spec.organization.digest(),
            spec.tracking_plan.digest(),
            spec.project.digest(),
            spec.mission.digest(),
            spec.work_product.digest(),
            spec.permissions.digest(),
            spec.consent.digest(),
        ));
        let revision_digest = canonical_digest(&(
            spec.project.revision(),
            spec.mission.revision(),
            spec.work_product.revision(),
            spec.permissions.revision(),
            spec.consent.revision(),
        ));
        let privacy_digest = canonical_digest(&(
            "snowplow-privacy/v1",
            "digest_only_resource_ids",
            "digest_only_schema_revisions",
            "drop_raw_telemetry",
            "drop_raw_identity",
        ));
        Ok(Self {
            organization: spec.organization,
            tracking_plan: spec.tracking_plan,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            consent: spec.consent,
            permissions: spec.permissions,
            scope_digest,
            revision_digest,
            privacy_digest,
        })
    }

    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        self.permissions.validate()?;
        self.consent.validate()?;
        let expected = canonical_digest(&(
            self.organization.digest(),
            self.tracking_plan.digest(),
            self.project.digest(),
            self.mission.digest(),
            self.work_product.digest(),
            self.permissions.digest(),
            self.consent.digest(),
        ));
        if expected != self.scope_digest {
            return Err(SnowplowModelError::InvalidScope("scope digest"));
        }
        let expected_revision = canonical_digest(&(
            self.project.revision(),
            self.mission.revision(),
            self.work_product.revision(),
            self.permissions.revision(),
            self.consent.revision(),
        ));
        if expected_revision != self.revision_digest {
            return Err(SnowplowModelError::InvalidScope("revision digest"));
        }
        if !valid_digest(&self.privacy_digest) {
            return Err(SnowplowModelError::InvalidScope("privacy digest"));
        }
        Ok(())
    }

    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    #[must_use]
    pub fn tracking_plan(&self) -> &TrackingPlanId {
        &self.tracking_plan
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
    pub fn consent(&self) -> &SnowplowConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn permissions(&self) -> &SnowplowPermissionSet {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn privacy_digest(&self) -> &Digest {
        &self.privacy_digest
    }
}

/// An opaque credential handle. The raw handle has no serializer, no raw
/// accessor, and is only used to compute its digest for Layer-1 evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_id: String,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self, SnowplowModelError> {
        let opaque_id = opaque_id.into();
        if !valid_text(&opaque_id, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            return Err(SnowplowModelError::InvalidIdentifier("secret reference"));
        }
        Ok(Self {
            opaque_id,
            revision,
            revoked: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "snowplow-secret-reference/v1|{}|{}",
                self.opaque_id, self.revision
            )
            .as_bytes(),
        )
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), SnowplowModelError> {
        if self.revoked {
            Err(SnowplowModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), SnowplowModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(SnowplowModelError::NotRevoked)
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowTrackingPlanStatus {
    Draft,
    Active,
    Archived,
}

impl SnowplowTrackingPlanStatus {
    pub fn parse(value: &str) -> Result<Self, SnowplowModelError> {
        match value.to_ascii_lowercase().as_str() {
            "draft" => Ok(Self::Draft),
            "active" | "published" => Ok(Self::Active),
            "archived" | "deprecated" | "deleted" => Ok(Self::Archived),
            _ => Err(SnowplowModelError::InvalidText("tracking plan status")),
        }
    }
}

impl From<SnowplowTrackingPlanStatus> for SnowplowEvidenceState {
    fn from(status: SnowplowTrackingPlanStatus) -> Self {
        match status {
            SnowplowTrackingPlanStatus::Draft => Self::Draft,
            SnowplowTrackingPlanStatus::Active => Self::Active,
            SnowplowTrackingPlanStatus::Archived => Self::Archived,
        }
    }
}

pub type SnowplowEventSpecStatus = SnowplowTrackingPlanStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowEvidenceState {
    Draft,
    Active,
    Archived,
    Missing,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowTransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl SnowplowTransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowHistoryOrder {
    Asc,
    #[default]
    Desc,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowCursor {
    #[serde(skip)]
    pub(crate) token: String,
    pub cursor_digest: Digest,
    pub scope_digest: Digest,
    pub page_number: u16,
}

impl SnowplowCursor {
    pub fn from_opaque(
        token: impl Into<String>,
        scope_digest: &Digest,
        page_number: u16,
    ) -> Result<Self, SnowplowModelError> {
        Self::from_token(token, scope_digest, page_number)
    }

    pub(crate) fn from_token(
        token: impl Into<String>,
        scope_digest: &Digest,
        page_number: u16,
    ) -> Result<Self, SnowplowModelError> {
        let token = token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true) || page_number < 2 {
            return Err(SnowplowModelError::InvalidIdentifier("cursor"));
        }
        Ok(Self {
            cursor_digest: sha256_digest(
                format!("snowplow-cursor/v1|{scope_digest}|{token}").as_bytes(),
            ),
            scope_digest: scope_digest.clone(),
            token,
            page_number,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.cursor_digest
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate(&self, scope_digest: &Digest) -> Result<(), SnowplowModelError> {
        if &self.scope_digest != scope_digest || self.page_number < 2 {
            return Err(SnowplowModelError::InvalidScope("cursor scope"));
        }
        let expected =
            sha256_digest(format!("snowplow-cursor/v1|{scope_digest}|{}", self.token).as_bytes());
        if expected != self.cursor_digest {
            return Err(SnowplowModelError::InvalidScope("cursor digest"));
        }
        Ok(())
    }
}

impl fmt::Debug for SnowplowCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowplowCursor")
            .field("cursor_digest", &self.cursor_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl Default for SnowplowRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: 60,
            remaining: Some(60),
            retry_after_seconds: None,
            throttled: false,
        }
    }
}

impl SnowplowRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self, SnowplowModelError> {
        let receipt = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            throttled,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        if self.limit_per_minute == 0
            || self.limit_per_minute > 600
            || self
                .remaining
                .is_some_and(|value| value > self.limit_per_minute)
            || self
                .retry_after_seconds
                .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
            || self.throttled != self.retry_after_seconds.is_some()
        {
            return Err(SnowplowModelError::InvalidRateLimitReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowPageReceipt {
    pub operation: String,
    pub page_number: u16,
    pub returned: u16,
    pub has_more: bool,
    pub cursor_digest: Option<Digest>,
    pub response_digest: Digest,
    pub status_code: u16,
    pub redacted: bool,
}

impl SnowplowPageReceipt {
    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        if !valid_identifier(&self.operation)
            || self.page_number == 0
            || self.returned > MAX_PAGE_SIZE
            || self.status_code == 0
            || !self.redacted
        {
            return Err(SnowplowModelError::InvalidScope("page receipt"));
        }
        validate_digest(&self.response_digest)?;
        if let Some(cursor_digest) = &self.cursor_digest {
            validate_digest(cursor_digest)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowDiagnostic {
    BlockedEnv,
    AccessLoss,
    Missing,
    RateLimited,
    ProviderUnknown,
    MalformedResponse,
    ResponseTooLarge,
    Tamper,
    StaleCursor,
    StaleRevision,
    RegistrationRevoked,
    PartialPages,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowTrackingPlanProjection {
    pub id_digest: Digest,
    pub status: SnowplowTrackingPlanStatus,
    pub revision: u64,
    pub schema_digest: Digest,
    pub revision_digest: Digest,
    pub event_spec_digests: Vec<Digest>,
}

impl SnowplowTrackingPlanProjection {
    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        validate_digest(&self.id_digest)?;
        validate_digest(&self.schema_digest)?;
        validate_digest(&self.revision_digest)?;
        if self.event_spec_digests.len() > MAX_PLAN_EVENT_SPECS {
            return Err(SnowplowModelError::InvalidScope("plan event specs"));
        }
        for digest in &self.event_spec_digests {
            validate_digest(digest)?;
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
pub struct SnowplowEventSpecProjection {
    pub id_digest: Digest,
    pub tracking_plan_digest: Option<Digest>,
    pub status: SnowplowEventSpecStatus,
    pub revision: u64,
    pub schema_digest: Digest,
    pub revision_digest: Digest,
}

impl SnowplowEventSpecProjection {
    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        validate_digest(&self.id_digest)?;
        if let Some(digest) = &self.tracking_plan_digest {
            validate_digest(digest)?;
        }
        validate_digest(&self.schema_digest)?;
        validate_digest(&self.revision_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowHistoryProjection {
    pub resource_digest: Digest,
    pub revision: u64,
    pub status: SnowplowTrackingPlanStatus,
    pub schema_digest: Digest,
    pub revision_digest: Digest,
    pub change_digest: Digest,
}

impl SnowplowHistoryProjection {
    pub fn validate(&self) -> Result<(), SnowplowModelError> {
        validate_digest(&self.resource_digest)?;
        validate_digest(&self.schema_digest)?;
        validate_digest(&self.revision_digest)?;
        validate_digest(&self.change_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowEvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub privacy_digest: Digest,
    pub schema_digest: Digest,
    pub revision_digest: Digest,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowTrackingPlanEvidence {
    pub service_id: String,
    pub provider_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: SnowplowEvidenceState,
    pub plan: Option<SnowplowTrackingPlanProjection>,
    pub event_specs: Vec<SnowplowEventSpecProjection>,
    pub history: Vec<SnowplowHistoryProjection>,
    pub page_receipts: Vec<SnowplowPageReceipt>,
    pub rate_limit_receipts: Vec<SnowplowRateLimitReceipt>,
    pub diagnostics: Vec<SnowplowDiagnostic>,
    pub provenance: SnowplowTransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digests: SnowplowEvidenceDigests,
}

impl SnowplowTrackingPlanEvidence {
    pub fn validate_integrity(&self) -> Result<(), SnowplowModelError> {
        if self.service_id != crate::SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.scope_digest != self.evidence_digests.scope_digest
            || self.connected
            || self.native
            || self.first_party
            || self.event_specs.len() > MAX_PLAN_EVENT_SPECS
            || self.history.len() > MAX_HISTORY_ENTRIES
            || self.diagnostics.len() > MAX_DIAGNOSTICS
        {
            return Err(SnowplowModelError::InvalidScope("evidence boundary"));
        }
        validate_digest(&self.registration_digest)?;
        if let Some(plan) = &self.plan {
            plan.validate()?;
        }
        for event_spec in &self.event_specs {
            event_spec.validate()?;
        }
        for history in &self.history {
            history.validate()?;
        }
        for receipt in &self.page_receipts {
            receipt.validate()?;
        }
        for receipt in &self.rate_limit_receipts {
            receipt.validate()?;
        }
        for digest in [
            &self.evidence_digests.version_digest,
            &self.evidence_digests.contract_digest,
            &self.evidence_digests.provider_digest,
            &self.evidence_digests.permission_digest,
            &self.evidence_digests.scope_digest,
            &self.evidence_digests.privacy_digest,
            &self.evidence_digests.schema_digest,
            &self.evidence_digests.revision_digest,
            &self.evidence_digests.response_digest,
            &self.evidence_digests.evidence_digest,
        ] {
            validate_digest(digest)?;
        }
        if self.evidence_digests.evidence_digest != self.calculate_digest() {
            return Err(SnowplowModelError::InvalidScope("evidence digest"));
        }
        Ok(())
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!([
            &self.service_id,
            &self.provider_id,
            &self.scope_digest,
            self.state,
            &self.plan,
            &self.event_specs,
            &self.history,
            &self.page_receipts,
            &self.rate_limit_receipts,
            &self.diagnostics,
            self.provenance,
            self.connected,
            self.native,
            self.first_party,
            &self.evidence_digests.version_digest,
            &self.evidence_digests.contract_digest,
            &self.evidence_digests.provider_digest,
            &self.evidence_digests.permission_digest,
            &self.evidence_digests.scope_digest,
            &self.evidence_digests.privacy_digest,
            &self.evidence_digests.schema_digest,
            &self.evidence_digests.revision_digest,
            &self.evidence_digests.response_digest,
        ]))
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digests.evidence_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowObservationReceipt {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: SnowplowEvidenceState,
    pub provenance: SnowplowTransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowRegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub privacy_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub state: SnowplowRegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl SnowplowRegistration {
    #[must_use]
    pub fn bind(
        scope: &SnowplowTrackingPlanScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_digest,
            permission_digest: scope.permissions().digest(),
            scope_digest: scope.digest().clone(),
            privacy_digest: scope.privacy_digest().clone(),
            evidence_digest: sha256_digest(b"snowplow-no-evidence/v1"),
            secret_reference_digest: secret_reference.digest(),
            registration_revision: 1,
            registration_digest: String::new(),
            state: SnowplowRegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!([
            "snowplow-registration/v1",
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.privacy_digest,
            &self.evidence_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            self.state,
            self.reversible,
            self.revocable,
        ]))
    }

    pub fn validate(
        &self,
        scope: &SnowplowTrackingPlanScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), SnowplowModelError> {
        scope.validate()?;
        validate_digest(&self.evidence_digest)?;
        if self.state != SnowplowRegistrationState::Active {
            return Err(SnowplowModelError::RegistrationInactive);
        }
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.permission_digest != scope.permissions().digest()
            || self.scope_digest != *scope.digest()
            || self.privacy_digest != *scope.privacy_digest()
            || self.secret_reference_digest != secret_reference.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_revision == 0
            || self.registration_digest != self.compute_digest()
        {
            return Err(SnowplowModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn validate_for_consumer(
        &self,
        scope: &SnowplowTrackingPlanScope,
        provider_digest: &Digest,
    ) -> Result<(), SnowplowModelError> {
        scope.validate()?;
        if self.state != SnowplowRegistrationState::Active
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.permission_digest != scope.permissions().digest()
            || self.scope_digest != *scope.digest()
            || self.privacy_digest != *scope.privacy_digest()
            || !self.reversible
            || !self.revocable
            || self.registration_revision == 0
            || self.registration_digest != self.compute_digest()
        {
            return Err(SnowplowModelError::InvalidScope("consumer registration"));
        }
        validate_digest(&self.evidence_digest)?;
        validate_digest(&self.secret_reference_digest)?;
        Ok(())
    }

    pub fn bind_evidence_digest(
        &mut self,
        evidence_digest: Digest,
    ) -> Result<(), SnowplowModelError> {
        validate_digest(&evidence_digest)?;
        if self.state != SnowplowRegistrationState::Active {
            return Err(SnowplowModelError::RegistrationInactive);
        }
        if self.evidence_digest != evidence_digest {
            self.registration_revision = self
                .registration_revision
                .checked_add(1)
                .ok_or(SnowplowModelError::RevisionOverflow)?;
            self.evidence_digest = evidence_digest;
            self.registration_digest = self.compute_digest();
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<SnowplowRegistrationRevocationReceipt, SnowplowModelError> {
        if !self.revocable {
            return Err(SnowplowModelError::InvalidScope(
                "registration not revocable",
            ));
        }
        if self.state == SnowplowRegistrationState::Revoked {
            return Err(SnowplowModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(SnowplowModelError::RevisionOverflow)?;
        self.state = SnowplowRegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(SnowplowRegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), SnowplowModelError> {
        if !self.reversible {
            return Err(SnowplowModelError::InvalidScope(
                "registration not reversible",
            ));
        }
        if self.state != SnowplowRegistrationState::Revoked {
            return Err(SnowplowModelError::NotRevoked);
        }
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(SnowplowModelError::RevisionOverflow)?;
        self.state = SnowplowRegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}
