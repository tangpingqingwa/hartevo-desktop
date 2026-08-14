//! Typed, bounded CloudTrail control-plane projections.
//!
//! This module intentionally has no model for `CloudTrailEvent`.  A provider
//! seam may receive an event-shaped fixture, but it must immediately project it
//! into [`RedactedEventMetadata`].  The projection contains only digests,
//! management-event selectors, timestamps, and bounded outcome metadata.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION, AWS_CLOUDTRAIL_AUDIT_PLUGIN_VERSION_TEXT,
    AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_EVENT_SOURCE_BYTES: usize = 256;
pub const MAX_EVENT_NAME_BYTES: usize = 256;
pub const MAX_RESOURCE_TYPE_BYTES: usize = 128;
pub const MAX_EVENT_ID_BYTES: usize = 256;
pub const MAX_ERROR_CODE_BYTES: usize = 128;
pub const MAX_LOOKBACK_SECONDS: i64 = 90 * 24 * 60 * 60;
pub const MAX_EVENTS_PER_PAGE: usize = 50;
pub const MAX_TOTAL_EVENTS: usize = 200;
pub const MAX_PAGES: u16 = 4;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("CloudTrail time window is invalid or exceeds 90 days")]
    InvalidTimeWindow,
    #[error("CloudTrail time window does not contain the event")]
    EventOutsideTimeWindow,
    #[error("CloudTrail bounds exceed the Layer-1 limit")]
    InvalidBounds,
}

fn validate_text(
    value: &str,
    field: &'static str,
    maximum: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

/// A SHA-256 digest used as a content-free binding.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded CloudTrail values serialize");
        Self::from_bytes(bytes)
    }

    pub fn parse(value: impl Into<String>, field: &'static str) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest { field });
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
        self.0.fmt(formatter)
    }
}

macro_rules! bounded_text {
    ($name:ident, $field:literal, $maximum:expr, $whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $maximum, $whitespace)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_text!(AwsRegion, "AWS region", MAX_IDENTIFIER_BYTES, false);
bounded_text!(EventSource, "event source", MAX_EVENT_SOURCE_BYTES, false);
bounded_text!(EventName, "event name", MAX_EVENT_NAME_BYTES, false);
bounded_text!(
    ResourceType,
    "resource type",
    MAX_RESOURCE_TYPE_BYTES,
    false
);

/// AWS account identifiers are retained only as the exact 12-digit scope.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AwsAccountId {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        if end <= start || end - start > Duration::seconds(MAX_LOOKBACK_SECONDS) {
            return Err(ModelError::InvalidTimeWindow);
        }
        Ok(Self { start, end })
    }

    pub fn contains(&self, value: DateTime<Utc>) -> bool {
        value >= self.start && value <= self.end
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    Create,
    Update,
    Delete,
    Deploy,
    Other,
}

/// The external effect is a binding, never an effect authority.  The opaque
/// effect handle is hashed and discarded at construction time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectScope {
    pub effect_digest: Digest,
    pub kind: EffectKind,
    pub revision: Revision,
}

impl EffectScope {
    pub fn new(
        opaque_effect_reference: impl AsRef<str>,
        kind: EffectKind,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let opaque = opaque_effect_reference.as_ref();
        validate_text(
            opaque,
            "opaque effect reference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        let effect_digest = Digest::from_serializable(&(
            "hartevo:aws-cloudtrail-effect-reference:v1",
            opaque,
            kind,
            revision,
        ));
        Ok(Self {
            effect_digest,
            kind,
            revision,
        })
    }
}

/// Resource identity is stored as a digest.  The provider can therefore
/// prove exact resource matching without retaining an ARN, name, or PII.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceScope {
    pub resource_type: ResourceType,
    pub resource_digest: Digest,
}

impl ResourceScope {
    pub fn new(
        resource_type: impl Into<String>,
        opaque_resource_identifier: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let resource_type = ResourceType::new(resource_type)?;
        let identifier = opaque_resource_identifier.as_ref();
        validate_text(
            identifier,
            "opaque resource identifier",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let resource_digest = Digest::from_serializable(&(
            "hartevo:aws-cloudtrail-resource-reference:v1",
            resource_type.as_str(),
            identifier,
        ));
        Ok(Self {
            resource_type,
            resource_digest,
        })
    }
}

macro_rules! scoped_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: String,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
                let id = id.into();
                validate_text(&id, $field, MAX_IDENTIFIER_BYTES, false)?;
                Ok(Self { id, revision })
            }
        }
    };
}

scoped_identifier!(MissionScope, "Mission id");
scoped_identifier!(ProjectScope, "Project id");
scoped_identifier!(DeploymentScope, "Deployment id");
scoped_identifier!(WorkProductScope, "Work Product id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    CloudTrailLookupEvents,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionBinding {
    pub actions: Vec<PermissionAction>,
    pub resource_boundary_digest: Digest,
}

impl PermissionBinding {
    pub fn cloudtrail_lookup_events() -> Self {
        Self {
            actions: vec![PermissionAction::CloudTrailLookupEvents],
            resource_boundary_digest: Digest::from_text(
                "hartevo:aws-cloudtrail-lookup-events-resource-boundary:v1",
            ),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Exact CloudTrail control-plane audit scope.  Every field participates in
/// the scope digest and therefore in registration, proposal, and evidence
/// verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCloudTrailAuditScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub time_window: TimeWindow,
    pub event_source: EventSource,
    pub event_name: EventName,
    pub resource: ResourceScope,
    pub effect: EffectScope,
    pub mission: MissionScope,
    pub project: ProjectScope,
    pub deployment: DeploymentScope,
    pub work_product: WorkProductScope,
    pub permission: PermissionBinding,
}

impl AwsCloudTrailAuditScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        time_window: TimeWindow,
        event_source: EventSource,
        event_name: EventName,
        resource: ResourceScope,
        effect: EffectScope,
        mission: MissionScope,
        project: ProjectScope,
        deployment: DeploymentScope,
        work_product: WorkProductScope,
        permission: PermissionBinding,
    ) -> Self {
        Self {
            account_id,
            region,
            time_window,
            event_source,
            event_name,
            resource,
            effect,
            mission,
            project,
            deployment,
            work_product,
            permission,
        }
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }
}

/// The opaque SigV4 credential binding.  It deliberately implements neither
/// `Serialize` nor `Deserialize`.  The supplied host handle is hashed and
/// dropped; no access key, secret key, session token, or handle is retained.
#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    reference_digest: Digest,
    account_digest: Option<Digest>,
    region_digest: Option<Digest>,
    revision: Revision,
    revoked: bool,
}

impl SigV4SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        account_id: impl AsRef<str>,
        region: impl AsRef<str>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let account_id = AwsAccountId::new(account_id.as_ref())?;
        let region = AwsRegion::new(region.as_ref())?;
        Self::build(
            opaque_reference.as_ref(),
            Some(&account_id),
            Some(&region),
            revision,
        )
    }

    pub fn unbound(
        opaque_reference: impl AsRef<str>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::build(opaque_reference.as_ref(), None, None, revision)
    }

    pub fn for_scope(
        opaque_reference: impl AsRef<str>,
        scope: &AwsCloudTrailAuditScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(
            opaque_reference,
            scope.account_id.as_str(),
            scope.region.as_str(),
            revision,
        )
    }

    fn build(
        opaque_reference: &str,
        account_id: Option<&AwsAccountId>,
        region: Option<&AwsRegion>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_text(
            opaque_reference,
            "opaque SigV4 secret reference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let account_digest = account_id.map(|value| Digest::from_text(value.as_str()));
        let region_digest = region.map(|value| Digest::from_text(value.as_str()));
        let reference_digest = Digest::from_serializable(&(
            "hartevo:aws-sigv4-secret-reference:v1",
            opaque_reference,
            &account_digest,
            &region_digest,
            revision,
        ));
        Ok(Self {
            reference_digest,
            account_digest,
            region_digest,
            revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn account_digest(&self) -> Option<&Digest> {
        self.account_digest.as_ref()
    }

    pub fn region_digest(&self) -> Option<&Digest> {
        self.region_digest.as_ref()
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("account_digest", &self.account_digest)
            .field("region_digest", &self.region_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

pub type SecretReference = SigV4SecretReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupAttribute {
    EventName,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_events: u16,
}

impl AuditBounds {
    pub fn new(max_pages: u16, page_size: u16, max_events: u16) -> Result<Self, ModelError> {
        if !(1..=MAX_PAGES).contains(&max_pages)
            || !(1..=u16::try_from(MAX_EVENTS_PER_PAGE).expect("page bound fits u16"))
                .contains(&page_size)
            || !(1..=u16::try_from(MAX_TOTAL_EVENTS).expect("event bound fits u16"))
                .contains(&max_events)
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_pages,
            page_size,
            max_events,
        })
    }
}

impl Default for AuditBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: u16::try_from(MAX_EVENTS_PER_PAGE).expect("page bound fits u16"),
            max_events: u16::try_from(MAX_TOTAL_EVENTS).expect("event bound fits u16"),
        }
    }
}

/// The safe query binding sent to the provider.  The full scope is represented
/// by exact IDs and digests; no opaque secret or resource string is present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditQuery {
    pub scope_digest: Digest,
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub time_window: TimeWindow,
    pub lookup_attribute: LookupAttribute,
    pub event_source: EventSource,
    pub event_name: EventName,
    pub resource_type: ResourceType,
    pub resource_digest: Digest,
    pub effect_digest: Digest,
    pub mission: MissionScope,
    pub project: ProjectScope,
    pub deployment: DeploymentScope,
    pub work_product: WorkProductScope,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub bounds: AuditBounds,
    pub query_digest: Digest,
}

impl AuditQuery {
    pub fn new(
        scope: &AwsCloudTrailAuditScope,
        permission_digest: Digest,
        secret_reference_digest: Digest,
        bounds: AuditBounds,
    ) -> Self {
        let mut query = Self {
            scope_digest: scope.scope_digest(),
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            time_window: scope.time_window.clone(),
            lookup_attribute: LookupAttribute::EventName,
            event_source: scope.event_source.clone(),
            event_name: scope.event_name.clone(),
            resource_type: scope.resource.resource_type.clone(),
            resource_digest: scope.resource.resource_digest.clone(),
            effect_digest: scope.effect.effect_digest.clone(),
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            deployment: scope.deployment.clone(),
            work_product: scope.work_product.clone(),
            permission_digest,
            secret_reference_digest,
            bounds,
            query_digest: Digest::from_text("placeholder"),
        };
        query.query_digest = query.compute_digest();
        query
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!({
            "scopeDigest": &self.scope_digest,
            "accountId": &self.account_id,
            "region": &self.region,
            "timeWindow": &self.time_window,
            "lookupAttribute": self.lookup_attribute,
            "eventSource": &self.event_source,
            "eventName": &self.event_name,
            "resourceType": &self.resource_type,
            "resourceDigest": &self.resource_digest,
            "effectDigest": &self.effect_digest,
            "mission": &self.mission,
            "project": &self.project,
            "deployment": &self.deployment,
            "workProduct": &self.work_product,
            "permissionDigest": &self.permission_digest,
            "secretReferenceDigest": &self.secret_reference_digest,
            "bounds": &self.bounds,
        }))
    }

    pub fn verify_digest(&self) -> bool {
        self.query_digest == self.compute_digest()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedIdentityClass {
    Root,
    IamUser,
    IamRole,
    AssumedRole,
    AwsService,
    Federated,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum EventOutcome {
    Success,
    Failed { error_code: String },
}

impl EventOutcome {
    pub fn failed(error_code: impl Into<String>) -> Result<Self, ModelError> {
        let error_code = error_code.into();
        validate_text(
            &error_code,
            "redacted error code",
            MAX_ERROR_CODE_BYTES,
            false,
        )?;
        Ok(Self::Failed { error_code })
    }
}

/// Input to the one-way redaction boundary.  It has no fields for source IP,
/// request parameters, response bodies, user ARN, or other raw provider data.
pub struct EventMetadataInput {
    pub event_id: String,
    pub event_time: DateTime<Utc>,
    pub event_source: EventSource,
    pub event_name: EventName,
    pub resource_type: ResourceType,
    pub resource_identifier: String,
    pub outcome: EventOutcome,
    pub identity_class: RedactedIdentityClass,
}

impl fmt::Debug for EventMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventMetadataInput")
            .field("event_id_digest", &Digest::from_text(&self.event_id))
            .field("event_time", &self.event_time)
            .field("event_source", &self.event_source)
            .field("event_name", &self.event_name)
            .field("resource_type", &self.resource_type)
            .field(
                "resource_digest",
                &Digest::from_serializable(&(
                    "hartevo:aws-cloudtrail-resource-reference:v1",
                    self.resource_type.as_str(),
                    &self.resource_identifier,
                )),
            )
            .field("outcome", &self.outcome)
            .field("identity_class", &self.identity_class)
            .finish()
    }
}

impl EventMetadataInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: impl Into<String>,
        event_time: DateTime<Utc>,
        event_source: EventSource,
        event_name: EventName,
        resource_type: ResourceType,
        resource_identifier: impl Into<String>,
        outcome: EventOutcome,
        identity_class: RedactedIdentityClass,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            event_time,
            event_source,
            event_name,
            resource_type,
            resource_identifier: resource_identifier.into(),
            outcome,
            identity_class,
        }
    }
}

/// Safe event metadata retained by the provider and exposed to a Mission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedEventMetadata {
    pub event_id_digest: Digest,
    pub event_time: DateTime<Utc>,
    pub event_source: EventSource,
    pub event_name: EventName,
    pub resource_type: ResourceType,
    pub resource_digest: Digest,
    pub outcome: EventOutcome,
    pub identity_class: RedactedIdentityClass,
    pub event_digest: Digest,
}

impl RedactedEventMetadata {
    pub fn from_input(input: EventMetadataInput) -> Result<Self, ModelError> {
        validate_text(
            &input.event_id,
            "CloudTrail event id",
            MAX_EVENT_ID_BYTES,
            false,
        )?;
        validate_text(
            &input.resource_identifier,
            "opaque resource identifier",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let event_id_digest =
            Digest::from_serializable(&("hartevo:aws-cloudtrail-event-id:v1", &input.event_id));
        let resource_digest = Digest::from_serializable(&(
            "hartevo:aws-cloudtrail-resource-reference:v1",
            input.resource_type.as_str(),
            &input.resource_identifier,
        ));
        let mut event = Self {
            event_id_digest,
            event_time: input.event_time,
            event_source: input.event_source,
            event_name: input.event_name,
            resource_type: input.resource_type,
            resource_digest,
            outcome: input.outcome,
            identity_class: input.identity_class,
            event_digest: Digest::from_text("placeholder"),
        };
        event.event_digest = event.compute_digest();
        Ok(event)
    }

    fn canonical(
        &self,
    ) -> (
        &Digest,
        DateTime<Utc>,
        &EventSource,
        &EventName,
        &ResourceType,
        &Digest,
        &EventOutcome,
        RedactedIdentityClass,
    ) {
        (
            &self.event_id_digest,
            self.event_time,
            &self.event_source,
            &self.event_name,
            &self.resource_type,
            &self.resource_digest,
            &self.outcome,
            self.identity_class,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self) -> bool {
        self.event_digest == self.compute_digest()
    }

    pub fn matches_scope(&self, scope: &AwsCloudTrailAuditScope) -> bool {
        self.event_source == scope.event_source
            && self.event_name == scope.event_name
            && self.resource_type == scope.resource.resource_type
            && self.resource_digest == scope.resource.resource_digest
            && scope.time_window.contains(self.event_time)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageCap,
    EventCap,
    RateLimited,
    ProviderWarning,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProjection {
    Complete,
    Partial(PartialReason),
    RetentionUnavailable,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAnomaly {
    ReplayDetected,
    DuplicateEvent,
    OrderNormalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectObservation {
    NoExternalEffectClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEvidenceDigests {
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
}

/// Bounded evidence that a Mission may independently observe.  The list is
/// sorted by event time and event-id digest and is deduplicated by event-id
/// digest.  It never contains the raw CloudTrail event or raw transport body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub page_count: u16,
    pub raw_event_count: u16,
    pub unique_event_count: u16,
    pub duplicate_event_count: u16,
    pub projection: AuditProjection,
    pub events: Vec<RedactedEventMetadata>,
    pub record_digests: Vec<Digest>,
    pub cursor_chain_digest: Digest,
    pub anomalies: Vec<AuditAnomaly>,
    pub effect_observation: EffectObservation,
    pub provider_failure_digest: Option<Digest>,
    pub digests: AuditEvidenceDigests,
}

impl AuditEvidence {
    pub fn compute_evidence_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!({
            "schemaVersion": &self.schema_version,
            "contractVersion": &self.contract_version,
            "pluginVersion": &self.plugin_version,
            "scopeDigest": &self.scope_digest,
            "registrationDigest": &self.registration_digest,
            "registrationRevision": self.registration_revision,
            "providerId": &self.provider_id,
            "providerVersion": &self.provider_version,
            "providerRevision": &self.provider_revision,
            "pageCount": self.page_count,
            "rawEventCount": self.raw_event_count,
            "uniqueEventCount": self.unique_event_count,
            "duplicateEventCount": self.duplicate_event_count,
            "projection": self.projection,
            "events": &self.events,
            "recordDigests": &self.record_digests,
            "cursorChainDigest": &self.cursor_chain_digest,
            "anomalies": &self.anomalies,
            "effectObservation": self.effect_observation,
            "providerFailureDigest": &self.provider_failure_digest,
        }))
    }

    pub fn verify_integrity(&self) -> bool {
        self.events.iter().all(RedactedEventMetadata::verify_digest)
            && self.events.windows(2).all(|pair| {
                (pair[0].event_time, &pair[0].event_id_digest)
                    <= (pair[1].event_time, &pair[1].event_id_digest)
            })
            && self
                .events
                .windows(2)
                .all(|pair| pair[0].event_id_digest != pair[1].event_id_digest)
            && self.digests.evidence_digest == self.compute_evidence_digest()
    }

    pub fn version_digest(&self) -> Digest {
        self.digests.version_digest.clone()
    }

    pub fn contract_digest(&self) -> Digest {
        self.digests.contract_digest.clone()
    }
}

pub fn contract_version_digest() -> Digest {
    Digest::from_text(AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION)
}

pub fn plugin_version_digest() -> Digest {
    Digest::from_text(AWS_CLOUDTRAIL_AUDIT_PLUGIN_VERSION_TEXT)
}

pub fn schema_version_digest() -> Digest {
    Digest::from_text(AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION)
}
