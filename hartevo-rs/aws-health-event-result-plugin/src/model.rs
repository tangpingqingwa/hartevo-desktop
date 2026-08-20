use std::{collections::BTreeSet, fmt, marker::PhantomData};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_HEALTH_EVENT_RESULT_CONSUMER_ID, AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION,
    AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION, AWS_HEALTH_EVENT_RESULT_PROVIDER_ID,
    AWS_HEALTH_EVENT_RESULT_SCHEMA_VERSION, AWS_HEALTH_EVENT_RESULT_SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_EVENTS: usize = 100;
pub const MAX_EVENT_TYPE_CODES: usize = 8;
pub const MAX_STATUSES: usize = 4;
pub const MAX_FAILED_SET: usize = 100;
pub const MAX_AFFECTED_ENTITIES: usize = 256;
pub const MAX_TIME_WINDOW_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const MAX_CURSOR_BYTES: usize = 4 * 1024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("AWS account id must contain exactly twelve digits")]
    InvalidAccountId,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("time window is empty, reversed, or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("event status filter contains too many values")]
    TooManyStatuses,
    #[error("event type filter contains too many values")]
    TooManyEventTypes,
    #[error("required AWS Health permission is missing")]
    MissingPermission,
    #[error("affected-entity consent is missing")]
    MissingEntityConsent,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("secret reference is invalid or revoked")]
    InvalidSecretReference,
    #[error("opaque cursor is empty, contains whitespace, or is too large")]
    InvalidCursor,
    #[error("event metadata is invalid")]
    InvalidEvent,
    #[error("affected entity reference is invalid")]
    InvalidAffectedEntity,
    #[error("response exceeds a Layer-1 bound")]
    ResponseBoundExceeded,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
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

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
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

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str, allow_colon_and_slash: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.')
                || (allow_colon_and_slash && matches!(byte, b':' | b'/'))
        })
}

macro_rules! identifier_type {
    ($name:ident, $allow_colon_and_slash:expr) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value, $allow_colon_and_slash) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_fields(stringify!($name), std::slice::from_ref(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

identifier_type!(AwsRegion, false);
identifier_type!(AwsServiceCode, false);
identifier_type!(AwsEventArn, true);
identifier_type!(AwsEventTypeCode, false);
identifier_type!(ProjectId, false);
identifier_type!(MissionId, false);
identifier_type!(WorkProductId, false);
identifier_type!(EntityType, false);

pub type AwsHealthRegion = AwsRegion;
pub type AwsHealthServiceCode = AwsServiceCode;
pub type AwsHealthEventArn = AwsEventArn;
pub type AwsHealthEventTypeCode = AwsEventTypeCode;
pub type AwsHealthProjectId = ProjectId;
pub type AwsHealthMissionId = MissionId;
pub type AwsHealthWorkProductId = WorkProductId;

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidAccountId)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields("aws-account/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthTimeWindow {
    start_time: i64,
    end_time: i64,
    window_digest: Digest,
}

impl AwsHealthTimeWindow {
    pub fn new(start_time: i64, end_time: i64) -> Result<Self, ModelError> {
        let duration = end_time
            .checked_sub(start_time)
            .ok_or(ModelError::InvalidTimeWindow)?;
        if start_time < 0 || duration <= 0 || duration > MAX_TIME_WINDOW_SECONDS {
            return Err(ModelError::InvalidTimeWindow);
        }
        let window_digest = Digest::from_fields(
            "aws-health-time-window/v1",
            &[
                start_time.to_string(),
                end_time.to_string(),
                duration.to_string(),
            ],
        );
        Ok(Self {
            start_time,
            end_time,
            window_digest,
        })
    }

    #[must_use]
    pub const fn start_time(&self) -> i64 {
        self.start_time
    }

    #[must_use]
    pub const fn end_time(&self) -> i64 {
        self.end_time
    }

    #[must_use]
    pub const fn duration_seconds(&self) -> i64 {
        self.end_time - self.start_time
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.window_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if Self::new(self.start_time, self.end_time)?.window_digest == self.window_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

pub type AwsHealthEventTimeWindow = AwsHealthTimeWindow;
pub type TimeWindow = AwsHealthTimeWindow;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsHealthEventStatus {
    Upcoming,
    Open,
    Closed,
}

impl AwsHealthEventStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upcoming => "upcoming",
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

pub type EventStatus = AwsHealthEventStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsHealthActionability {
    ActionRequired,
    Informational,
    NoAction,
    Unknown,
}

impl AwsHealthActionability {
    #[must_use]
    pub const fn is_provider_reported(self) -> bool {
        true
    }
}

pub type Actionability = AwsHealthActionability;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsHealthPermission {
    DescribeEvents,
    DescribeEventDetails,
    DescribeAffectedEntities,
}

impl AwsHealthPermission {
    #[must_use]
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::DescribeEvents => "health:DescribeEvents",
            Self::DescribeEventDetails => "health:DescribeEventDetails",
            Self::DescribeAffectedEntities => "health:DescribeAffectedEntities",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthPermissionFence {
    permissions: BTreeSet<AwsHealthPermission>,
    permission_digest: Digest,
}

impl AwsHealthPermissionFence {
    pub fn new(
        permissions: impl IntoIterator<Item = AwsHealthPermission>,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&AwsHealthPermission::DescribeEvents)
            || !permissions.contains(&AwsHealthPermission::DescribeEventDetails)
        {
            return Err(ModelError::MissingPermission);
        }
        let permission_digest = Digest::from_fields(
            "aws-health-permission-fence/v1",
            &permissions
                .iter()
                .map(|permission| permission.api_name().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new([
            AwsHealthPermission::DescribeEvents,
            AwsHealthPermission::DescribeEventDetails,
        ])
        .expect("required AWS Health read permissions are valid")
    }

    #[must_use]
    pub fn with_affected_entities() -> Self {
        Self::new([
            AwsHealthPermission::DescribeEvents,
            AwsHealthPermission::DescribeEventDetails,
            AwsHealthPermission::DescribeAffectedEntities,
        ])
        .expect("required AWS Health read permissions are valid")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<AwsHealthPermission> {
        &self.permissions
    }

    #[must_use]
    pub fn contains(&self, permission: AwsHealthPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.permissions.iter().copied())?;
        if rebuilt.permission_digest == self.permission_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

pub type PermissionFence = AwsHealthPermissionFence;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthConsentScope {
    purpose_digest: Digest,
    allows_affected_entities: bool,
    consent_digest: Digest,
}

impl AwsHealthConsentScope {
    pub fn new(
        purpose: impl AsRef<[u8]>,
        allows_affected_entities: bool,
    ) -> Result<Self, ModelError> {
        if purpose.as_ref().is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let purpose_digest = Digest::from_text(purpose);
        let consent_digest = Digest::from_fields(
            "aws-health-consent/v1",
            &[
                purpose_digest.as_str().to_owned(),
                allows_affected_entities.to_string(),
                "writes=false".to_owned(),
            ],
        );
        Ok(Self {
            purpose_digest,
            allows_affected_entities,
            consent_digest,
        })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new("aws-health-event-evidence", false).expect("default AWS Health consent is valid")
    }

    #[must_use]
    pub fn with_affected_entities() -> Self {
        Self::new("aws-health-event-evidence-with-entities", true)
            .expect("default AWS Health entity consent is valid")
    }

    #[must_use]
    pub fn allows_affected_entities(&self) -> bool {
        self.allows_affected_entities
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "aws-health-consent/v1",
            &[
                self.purpose_digest.as_str().to_owned(),
                self.allows_affected_entities.to_string(),
                "writes=false".to_owned(),
            ],
        );
        if expected == self.consent_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

pub type ConsentScope = AwsHealthConsentScope;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeBinding<I> {
    id: I,
    revision: Revision,
    binding_digest: Digest,
    #[serde(skip)]
    marker: PhantomData<I>,
}

impl<I> ScopeBinding<I>
where
    I: Clone + fmt::Debug + Serialize,
{
    fn new_with_domain(id: I, revision: Revision, domain: &str) -> Self {
        let binding_digest = Digest::from_fields(
            domain,
            &[
                serde_json::to_string(&id).expect("typed id serializes"),
                revision.get().to_string(),
            ],
        );
        Self {
            id,
            revision,
            binding_digest,
            marker: PhantomData,
        }
    }

    #[must_use]
    pub fn id(&self) -> &I {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.binding_digest
    }
}

pub type ProjectBinding = ScopeBinding<ProjectId>;
pub type MissionBinding = ScopeBinding<MissionId>;
pub type WorkProductBinding = ScopeBinding<WorkProductId>;
pub type AwsHealthProjectBinding = ProjectBinding;
pub type AwsHealthMissionBinding = MissionBinding;
pub type AwsHealthWorkProductBinding = WorkProductBinding;

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self::new_with_domain(id, revision, "aws-health-project/v1")
    }
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self::new_with_domain(id, revision, "aws-health-mission/v1")
    }
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self::new_with_domain(id, revision, "aws-health-work-product/v1")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthEventScope {
    account_id: AwsAccountId,
    region: AwsRegion,
    service_code: AwsServiceCode,
    event_arn: Option<AwsEventArn>,
    event_type_codes: BTreeSet<AwsEventTypeCode>,
    statuses: BTreeSet<AwsHealthEventStatus>,
    time_window: AwsHealthTimeWindow,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    permission_fence: AwsHealthPermissionFence,
    consent: AwsHealthConsentScope,
    include_affected_entities: bool,
    scope_digest: Digest,
}

impl AwsHealthEventScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        service_code: AwsServiceCode,
        event_arn: Option<AwsEventArn>,
        event_type_code: Option<AwsEventTypeCode>,
        statuses: impl IntoIterator<Item = AwsHealthEventStatus>,
        time_window: AwsHealthTimeWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission_fence: AwsHealthPermissionFence,
        consent: AwsHealthConsentScope,
    ) -> Result<Self, ModelError> {
        let statuses = statuses.into_iter().collect::<BTreeSet<_>>();
        let event_type_codes = event_type_code.into_iter().collect::<BTreeSet<_>>();
        if statuses.len() > MAX_STATUSES {
            return Err(ModelError::TooManyStatuses);
        }
        if event_type_codes.len() > MAX_EVENT_TYPE_CODES {
            return Err(ModelError::TooManyEventTypes);
        }
        let scope = Self {
            account_id,
            region,
            service_code,
            event_arn,
            event_type_codes,
            statuses,
            time_window,
            project,
            mission,
            work_product,
            permission_fence,
            consent,
            include_affected_entities: false,
            scope_digest: Digest::from_text("uninitialized"),
        };
        scope.with_recomputed_digest()
    }

    #[must_use]
    pub fn with_affected_entities(mut self, enabled: bool) -> Self {
        self.include_affected_entities = enabled;
        self.scope_digest = self.compute_digest();
        self
    }

    fn with_recomputed_digest(mut self) -> Result<Self, ModelError> {
        self.time_window.validate()?;
        self.permission_fence.validate()?;
        self.consent.validate()?;
        if self.include_affected_entities
            && (!self
                .permission_fence
                .contains(AwsHealthPermission::DescribeAffectedEntities)
                || !self.consent.allows_affected_entities())
        {
            return Err(ModelError::MissingEntityConsent);
        }
        self.scope_digest = self.compute_digest();
        Ok(self)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-health-event-scope/v1",
            &[
                self.event_filter_digest().as_str().to_owned(),
                self.project.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.permission_fence.digest().as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
                self.include_affected_entities.to_string(),
            ],
        )
    }

    #[must_use]
    pub fn account_id(&self) -> &AwsAccountId {
        &self.account_id
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn service_code(&self) -> &AwsServiceCode {
        &self.service_code
    }

    #[must_use]
    pub fn event_arn(&self) -> Option<&AwsEventArn> {
        self.event_arn.as_ref()
    }

    #[must_use]
    pub fn event_type_code(&self) -> Option<&AwsEventTypeCode> {
        self.event_type_codes.iter().next()
    }

    #[must_use]
    pub fn event_type_codes(&self) -> &BTreeSet<AwsEventTypeCode> {
        &self.event_type_codes
    }

    #[must_use]
    pub fn statuses(&self) -> &BTreeSet<AwsHealthEventStatus> {
        &self.statuses
    }

    #[must_use]
    pub fn time_window(&self) -> &AwsHealthTimeWindow {
        &self.time_window
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
    pub fn permission_fence(&self) -> &AwsHealthPermissionFence {
        &self.permission_fence
    }

    #[must_use]
    pub fn consent(&self) -> &AwsHealthConsentScope {
        &self.consent
    }

    #[must_use]
    pub const fn includes_affected_entities(&self) -> bool {
        self.include_affected_entities
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn event_filter_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-health-event-filter/v1",
            &[
                self.account_id.digest().as_str().to_owned(),
                self.region.digest().as_str().to_owned(),
                self.service_code.digest().as_str().to_owned(),
                self.event_arn
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), AwsEventArn::digest_as_string),
                self.event_type_codes
                    .iter()
                    .map(DigestString::digest_as_string)
                    .collect::<Vec<_>>()
                    .join(","),
                self.statuses
                    .iter()
                    .map(|status| status.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                self.time_window.digest().as_str().to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.event_type_codes.len() > MAX_EVENT_TYPE_CODES {
            return Err(ModelError::TooManyEventTypes);
        }
        if self.compute_digest() == self.scope_digest {
            self.time_window.validate()?;
            self.permission_fence.validate()?;
            self.consent.validate()?;
            if self.include_affected_entities
                && (!self
                    .permission_fence
                    .contains(AwsHealthPermission::DescribeAffectedEntities)
                    || !self.consent.allows_affected_entities())
            {
                return Err(ModelError::MissingEntityConsent);
            }
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

trait DigestString {
    fn digest_as_string(&self) -> String;
}

impl DigestString for AwsEventArn {
    fn digest_as_string(&self) -> String {
        self.digest().as_str().to_owned()
    }
}

impl DigestString for AwsEventTypeCode {
    fn digest_as_string(&self) -> String {
        self.digest().as_str().to_owned()
    }
}

pub type AwsHealthScope = AwsHealthEventScope;
pub type Scope = AwsHealthEventScope;

/// Opaque host-keyring reference for a future SigV4 resolver. The raw handle
/// is deliberately not serialized, printed, or exposed by this crate.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AwsHealthEventScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id, false) {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let reference_digest = Digest::from_fields(
            "aws-health-sigv4-secret-reference/v1",
            &[
                reference_id,
                scope.scope_digest().as_str().to_owned(),
                credential_revision.get().to_string(),
                "AWS4-HMAC-SHA256".to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.scope_digest().clone(),
            credential_revision,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

pub type AwsSigV4SecretReference = SecretReference;
pub type AwsHealthSecretReference = SecretReference;

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
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsHealthOperation {
    DescribeEvents,
    DescribeEventDetails,
    DescribeAffectedEntities,
}

impl AwsHealthOperation {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DescribeEvents => "DescribeEvents",
            Self::DescribeEventDetails => "DescribeEventDetails",
            Self::DescribeAffectedEntities => "DescribeAffectedEntities",
        }
    }

    #[must_use]
    pub const fn required_permission(self) -> AwsHealthPermission {
        match self {
            Self::DescribeEvents => AwsHealthPermission::DescribeEvents,
            Self::DescribeEventDetails => AwsHealthPermission::DescribeEventDetails,
            Self::DescribeAffectedEntities => AwsHealthPermission::DescribeAffectedEntities,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsHealthFailureKind {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    ServerFailure,
    Timeout,
    BlockedEnv,
    MalformedResponse,
    ScopeMismatch,
    RevisionDrift,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsHealthEvidenceState {
    Complete,
    Empty,
    PartialFailure,
    RateLimited,
    AccessLost,
    Stale,
    ProviderUnknown,
}

impl AwsHealthEvidenceState {
    #[must_use]
    pub const fn decision_ready(self) -> bool {
        matches!(self, Self::Complete | Self::Empty)
    }
}

pub type EvidenceState = AwsHealthEvidenceState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsHealthEvidenceClassification {
    Normalized,
    Empty,
    PartialFailure,
    RateLimited,
    AccessLost,
    Stale,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthEventRecord {
    event_arn: AwsEventArn,
    event_type_code: AwsEventTypeCode,
    service_code: AwsServiceCode,
    region: AwsRegion,
    status: AwsHealthEventStatus,
    actionability: AwsHealthActionability,
    started_at: i64,
    ended_at: Option<i64>,
    last_updated_at: i64,
    event_revision: Revision,
    event_digest: Digest,
}

impl AwsHealthEventRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_arn: AwsEventArn,
        event_type_code: AwsEventTypeCode,
        service_code: AwsServiceCode,
        region: AwsRegion,
        status: AwsHealthEventStatus,
        actionability: AwsHealthActionability,
        started_at: i64,
        ended_at: Option<i64>,
        last_updated_at: i64,
        event_revision: Revision,
    ) -> Result<Self, ModelError> {
        if started_at < 0
            || last_updated_at < started_at
            || ended_at.is_some_and(|ended| ended < started_at || ended < last_updated_at)
        {
            return Err(ModelError::InvalidEvent);
        }
        let event_digest = Self::compute_digest(
            &event_arn,
            &event_type_code,
            &service_code,
            &region,
            status,
            actionability,
            started_at,
            ended_at,
            last_updated_at,
            event_revision,
        );
        Ok(Self {
            event_arn,
            event_type_code,
            service_code,
            region,
            status,
            actionability,
            started_at,
            ended_at,
            last_updated_at,
            event_revision,
            event_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        event_arn: &AwsEventArn,
        event_type_code: &AwsEventTypeCode,
        service_code: &AwsServiceCode,
        region: &AwsRegion,
        status: AwsHealthEventStatus,
        actionability: AwsHealthActionability,
        started_at: i64,
        ended_at: Option<i64>,
        last_updated_at: i64,
        event_revision: Revision,
    ) -> Digest {
        Digest::from_fields(
            "aws-health-event-record/v1",
            &[
                event_arn.digest().as_str().to_owned(),
                event_type_code.digest().as_str().to_owned(),
                service_code.digest().as_str().to_owned(),
                region.digest().as_str().to_owned(),
                status.as_str().to_owned(),
                format!("{actionability:?}"),
                started_at.to_string(),
                ended_at.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                last_updated_at.to_string(),
                event_revision.get().to_string(),
            ],
        )
    }

    #[must_use]
    pub fn event_arn(&self) -> &AwsEventArn {
        &self.event_arn
    }

    #[must_use]
    pub fn event_type_code(&self) -> &AwsEventTypeCode {
        &self.event_type_code
    }

    #[must_use]
    pub fn service_code(&self) -> &AwsServiceCode {
        &self.service_code
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub const fn status(&self) -> AwsHealthEventStatus {
        self.status
    }

    #[must_use]
    pub const fn actionability(&self) -> AwsHealthActionability {
        self.actionability
    }

    #[must_use]
    pub const fn started_at(&self) -> i64 {
        self.started_at
    }

    #[must_use]
    pub const fn ended_at(&self) -> Option<i64> {
        self.ended_at
    }

    #[must_use]
    pub const fn last_updated_at(&self) -> i64 {
        self.last_updated_at
    }

    #[must_use]
    pub const fn event_revision(&self) -> Revision {
        self.event_revision
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::compute_digest(
            &self.event_arn,
            &self.event_type_code,
            &self.service_code,
            &self.region,
            self.status,
            self.actionability,
            self.started_at,
            self.ended_at,
            self.last_updated_at,
            self.event_revision,
        );
        if expected == self.event_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

pub type AwsHealthEvent = AwsHealthEventRecord;
pub type EventRecord = AwsHealthEventRecord;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthEventDetail {
    record: AwsHealthEventRecord,
    detail_digest: Digest,
}

impl AwsHealthEventDetail {
    pub fn new(record: AwsHealthEventRecord) -> Self {
        let detail_digest = Digest::from_fields(
            "aws-health-event-detail/v1",
            &[record.digest().as_str().to_owned()],
        );
        Self {
            record,
            detail_digest,
        }
    }

    #[must_use]
    pub fn record(&self) -> &AwsHealthEventRecord {
        &self.record
    }

    #[must_use]
    pub fn event_arn(&self) -> &AwsEventArn {
        self.record.event_arn()
    }

    #[must_use]
    pub fn event_revision(&self) -> Revision {
        self.record.event_revision()
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.detail_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.record.validate()?;
        if Self::new(self.record.clone()).detail_digest == self.detail_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AffectedEntityReference {
    entity_id_digest: Digest,
    entity_type: EntityType,
    status: Option<String>,
    last_updated_at: Option<i64>,
    reference_digest: Digest,
}

impl AffectedEntityReference {
    pub fn new(
        entity_id: impl AsRef<str>,
        entity_type: EntityType,
        status: Option<String>,
        last_updated_at: Option<i64>,
    ) -> Result<Self, ModelError> {
        let entity_id = entity_id.as_ref();
        if !valid_identifier(entity_id, true)
            || status
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, false))
            || last_updated_at.is_some_and(|value| value < 0)
        {
            return Err(ModelError::InvalidAffectedEntity);
        }
        let entity_id_digest =
            Digest::from_fields("aws-health-affected-entity-id/v1", &[entity_id.to_owned()]);
        let reference_digest = Digest::from_fields(
            "aws-health-affected-entity-reference/v1",
            &[
                entity_id_digest.as_str().to_owned(),
                entity_type.digest().as_str().to_owned(),
                status.clone().unwrap_or_default(),
                last_updated_at.map_or_else(String::new, |value| value.to_string()),
            ],
        );
        Ok(Self {
            entity_id_digest,
            entity_type,
            status,
            last_updated_at,
            reference_digest,
        })
    }

    #[must_use]
    pub fn entity_id_digest(&self) -> &Digest {
        &self.entity_id_digest
    }

    #[must_use]
    pub fn entity_type(&self) -> &EntityType {
        &self.entity_type
    }

    #[must_use]
    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    #[must_use]
    pub const fn last_updated_at(&self) -> Option<i64> {
        self.last_updated_at
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !is_digest(self.entity_id_digest.as_str()) || !is_digest(self.reference_digest.as_str())
        {
            return Err(ModelError::InvalidAffectedEntity);
        }
        let expected = Digest::from_fields(
            "aws-health-affected-entity-reference/v1",
            &[
                self.entity_id_digest.as_str().to_owned(),
                self.entity_type.digest().as_str().to_owned(),
                self.status.clone().unwrap_or_default(),
                self.last_updated_at
                    .map_or_else(String::new, |value| value.to_string()),
            ],
        );
        if expected == self.reference_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthFailedEvent {
    event_arn_digest: Option<Digest>,
    kind: AwsHealthFailureKind,
    status_code: Option<u16>,
    diagnostic_digest: Digest,
}

impl AwsHealthFailedEvent {
    #[must_use]
    pub fn new(
        event_arn: Option<&AwsEventArn>,
        kind: AwsHealthFailureKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            event_arn_digest: event_arn.map(AwsEventArn::digest),
            kind,
            status_code,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    #[must_use]
    pub fn event_arn_digest(&self) -> Option<&Digest> {
        self.event_arn_digest.as_ref()
    }

    #[must_use]
    pub const fn kind(&self) -> AwsHealthFailureKind {
        self.kind
    }

    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    #[must_use]
    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

pub type FailedEvent = AwsHealthFailedEvent;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthEvidenceDigests {
    pub contract_digest: Digest,
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub event_filter_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub events_digest: Digest,
    pub details_digest: Digest,
    pub affected_entities_digest: Digest,
    pub failed_set_digest: Digest,
}

#[must_use]
pub fn evidence_policy_digest() -> Digest {
    Digest::from_fields(
        "aws-health-evidence-policy/v1",
        &[
            crate::contract_digest().as_str().to_owned(),
            "raw_event_description=false".to_owned(),
            "raw_account_pii=false".to_owned(),
            "raw_event_metadata_maps=false".to_owned(),
            "raw_affected_entity_identifiers=false".to_owned(),
            "unbounded_entity_lists=false".to_owned(),
            "outage_causality=false".to_owned(),
            "operational_truth=false".to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthEventEvidence {
    pub state: AwsHealthEvidenceState,
    pub classification: AwsHealthEvidenceClassification,
    pub provenance: TransportProvenance,
    pub operations: BTreeSet<AwsHealthOperation>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub events: Vec<AwsHealthEventRecord>,
    pub details: Vec<AwsHealthEventDetail>,
    pub affected_entities: Vec<AffectedEntityReference>,
    pub failed_events: Vec<AwsHealthFailedEvent>,
    pub digests: AwsHealthEvidenceDigests,
    pub provider_reported_only: bool,
    pub outage_causality: bool,
    pub operational_truth: bool,
    pub native: bool,
    pub connected: bool,
    pub evidence_digest: Digest,
}

impl AwsHealthEventEvidence {
    #[must_use]
    pub fn decision_ready(&self) -> bool {
        self.state.decision_ready()
            && self.failed_events.is_empty()
            && !self.outage_causality
            && !self.operational_truth
            && !self.native
            && !self.connected
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.events.len() > MAX_EVENTS
            || self.details.len() > MAX_EVENTS
            || self.affected_entities.len() > MAX_AFFECTED_ENTITIES
            || self.failed_events.len() > MAX_FAILED_SET
            || !self.provider_reported_only
            || self.outage_causality
            || self.operational_truth
            || self.native
            || self.connected
        {
            return Err(ModelError::ResponseBoundExceeded);
        }
        for event in &self.events {
            event.validate()?;
        }
        for detail in &self.details {
            detail.validate()?;
        }
        for entity in &self.affected_entities {
            entity.validate()?;
        }
        let expected = self.compute_digest();
        if expected == self.evidence_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub(crate) fn compute_digest(&self) -> Digest {
        let events = serde_json::to_string(&self.events).expect("typed event records serialize");
        let details = serde_json::to_string(&self.details).expect("typed event details serialize");
        let entities = serde_json::to_string(&self.affected_entities)
            .expect("typed entity references serialize");
        let failures =
            serde_json::to_string(&self.failed_events).expect("typed failed events serialize");
        Digest::from_fields(
            "aws-health-event-evidence/v1",
            &[
                format!("{:?}", self.state),
                format!("{:?}", self.classification),
                self.provenance.label().to_owned(),
                self.operations
                    .iter()
                    .map(|operation| operation.label())
                    .collect::<Vec<_>>()
                    .join(","),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                events,
                details,
                entities,
                failures,
                serde_json::to_string(&self.digests).expect("evidence digests serialize"),
                self.provider_reported_only.to_string(),
                self.outage_causality.to_string(),
                self.operational_truth.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
            ],
        )
    }
}

/// Opaque cursor forwarded only inside a transport seam. Evidence retains
/// its digest and never serializes the provider token.
pub struct OpaqueCursor(String);

impl Clone for OpaqueCursor {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for OpaqueCursor {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for OpaqueCursor {}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest())
            .finish()
    }
}

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CURSOR_BYTES
            || value.chars().any(char::is_whitespace)
        {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields("aws-health-cursor/v1", std::slice::from_ref(&self.0))
    }
}

pub type OpaquePageToken = OpaqueCursor;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsHealthRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: AwsServiceCode,
    pub provider_id: AwsServiceCode,
    pub consumer_id: AwsServiceCode,
    pub provider_version: String,
    pub api_revision: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub event_filter_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

impl AwsHealthRegistration {
    pub(crate) fn new(
        scope: &AwsHealthEventScope,
        provider_version: &str,
        api_revision: &str,
        provider_digest: Digest,
    ) -> Result<Self, ModelError> {
        let service_id = AwsServiceCode::new(AWS_HEALTH_EVENT_RESULT_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let provider_id = AwsServiceCode::new(AWS_HEALTH_EVENT_RESULT_PROVIDER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = AwsServiceCode::new(AWS_HEALTH_EVENT_RESULT_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        if provider_version.is_empty() || api_revision.is_empty() {
            return Err(ModelError::InvalidRegistration);
        }
        let revision = Revision::new(1)?;
        let mut registration = Self {
            schema_version: AWS_HEALTH_EVENT_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION.to_owned(),
            service_id,
            provider_id,
            consumer_id,
            provider_version: provider_version.to_owned(),
            api_revision: api_revision.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            scope_digest: scope.scope_digest().clone(),
            event_filter_digest: scope.event_filter_digest(),
            evidence_policy_digest: evidence_policy_digest(),
            permission_digest: scope.permission_fence().digest().clone(),
            consent_digest: scope.consent().digest().clone(),
            registration_digest: Digest::from_text("uninitialized"),
            revision,
            state: RegistrationState::Active,
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn validate(
        &self,
        scope: &AwsHealthEventScope,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.contract_digest != crate::contract_digest()
            || self.provider_digest != *provider_digest
            || self.scope_digest != *scope.scope_digest()
            || self.event_filter_digest != scope.event_filter_digest()
            || self.evidence_policy_digest != evidence_policy_digest()
            || self.permission_digest != *scope.permission_fence().digest()
            || self.consent_digest != *scope.consent().digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        self.ensure_active()?;
        let previous_registration_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.revision = Revision::new(
            self.revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.registration_digest = self.compute_digest();
        let revocation_digest = Digest::from_fields(
            "aws-health-registration-revocation/v1",
            &[
                previous_registration_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.is_active() {
            return Err(ModelError::NotRevoked);
        }
        self.state = RegistrationState::Active;
        self.revision = Revision::new(
            self.revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-health-registration/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.plugin_version.clone(),
                self.service_id.as_str().to_owned(),
                self.provider_id.as_str().to_owned(),
                self.consumer_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.api_revision.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.event_filter_digest.as_str().to_owned(),
                self.evidence_policy_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }
}

pub type Registration = AwsHealthRegistration;
