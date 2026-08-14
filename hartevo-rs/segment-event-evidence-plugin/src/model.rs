use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    SEGMENT_EVENT_EVIDENCE_CONTRACT_VERSION, SEGMENT_EVENT_EVIDENCE_PROVIDER_ID,
    SEGMENT_EVENT_EVIDENCE_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 256;
pub(crate) const MAX_WINDOW_SECONDS: i64 = 7_776_000;
pub(crate) const MAX_PAGES: u16 = 32;
pub(crate) const MAX_PAGE_SIZE: u16 = 100;
pub(crate) const MAX_VIOLATION_SAMPLES: usize = 32;
pub(crate) const MAX_CURSOR_BYTES: usize = 4 * 1024;
pub(crate) const MAX_EVENT_SPECS: usize = 512;
pub(crate) const MAX_SOURCES: usize = 128;
pub(crate) const MAX_DESTINATIONS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("value is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("the evidence window must be closed, positive, and bounded")]
    InvalidWindow,
    #[error("the evidence bounds are empty or exceed the Layer-1 ceiling")]
    InvalidBounds,
    #[error("the read-only permission snapshot is empty or over-privileged")]
    InvalidPermissionSnapshot,
    #[error("the opaque cursor is empty or exceeds the redaction bound")]
    InvalidCursor,
    #[error("the tracking-plan scope is invalid")]
    InvalidScope,
    #[error("the violation sample list exceeded the Layer-1 bound")]
    TooManyViolationSamples,
    #[error("a bounded collection exceeded its Layer-1 bound")]
    BoundExceeded,
    #[error("an immutable digest did not match its fields")]
    DigestMismatch,
    #[error("the registration is invalid")]
    InvalidRegistration,
    #[error("the registration is already revoked")]
    AlreadyRevoked,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_fields<I, S>(domain: &str, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field.as_ref());
        }
        Self::from_bytes(&bytes)
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

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            #[must_use]
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
    };
}

string_identifier!(WorkspaceId);
string_identifier!(SourceId);
string_identifier!(TrackingPlanId);
string_identifier!(EventSpecId);
string_identifier!(DestinationId);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
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
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn new(raw_cursor: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let raw_cursor = raw_cursor.as_ref();
        if raw_cursor.is_empty() || raw_cursor.len() > MAX_CURSOR_BYTES {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            digest: Digest::from_bytes(raw_cursor),
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    PublicApiToken,
    OAuthAccess,
}

/// An opaque reference into host credential storage.
///
/// The reference identifier is hashed at construction and is never retained,
/// serialized, or printed. Layer 1 only carries the digest and a scope fence.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
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
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &SegmentScope,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest.clone();
        let reference_digest = Digest::from_fields(
            "segment-secret-reference/v1",
            [
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
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
    pub const fn kind(&self) -> SecretKind {
        self.kind
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    WorkspaceRead,
    TrackingPlanRead,
    EventSchemaRead,
    ViolationsRead,
    SourcesRead,
    DestinationsRead,
    DeliveryRead,
    TrackingPlanWrite,
    EventSchemaWrite,
    SourceWrite,
    DestinationWrite,
    EventSend,
    EventReplay,
    IdentityRead,
    PersonaRead,
}

impl Permission {
    #[must_use]
    pub const fn is_allowlisted_read(self) -> bool {
        matches!(
            self,
            Self::WorkspaceRead
                | Self::TrackingPlanRead
                | Self::EventSchemaRead
                | Self::ViolationsRead
                | Self::SourcesRead
                | Self::DestinationsRead
                | Self::DeliveryRead
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<Permission>,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(permissions: impl IntoIterator<Item = Permission>) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions.is_empty() || permissions.iter().any(|value| !value.is_allowlisted_read()) {
            return Err(ModelError::InvalidPermissionSnapshot);
        }
        let permission_digest = Digest::from_fields(
            "segment-permissions/v1",
            permissions
                .iter()
                .map(|permission| format!("{permission:?}")),
        );
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new([
            Permission::WorkspaceRead,
            Permission::TrackingPlanRead,
            Permission::EventSchemaRead,
            Permission::ViolationsRead,
            Permission::SourcesRead,
            Permission::DestinationsRead,
            Permission::DeliveryRead,
        ])
        .expect("the built-in Segment read-only permission set is valid")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceWindow {
    start_unix_seconds: i64,
    end_unix_seconds: i64,
}

impl EvidenceWindow {
    pub fn new(start_unix_seconds: i64, end_unix_seconds: i64) -> Result<Self, ModelError> {
        let duration = end_unix_seconds
            .checked_sub(start_unix_seconds)
            .ok_or(ModelError::InvalidWindow)?;
        if start_unix_seconds < 0 || duration <= 0 || duration > MAX_WINDOW_SECONDS {
            return Err(ModelError::InvalidWindow);
        }
        Ok(Self {
            start_unix_seconds,
            end_unix_seconds,
        })
    }

    #[must_use]
    pub const fn start_unix_seconds(self) -> i64 {
        self.start_unix_seconds
    }

    #[must_use]
    pub const fn end_unix_seconds(self) -> i64 {
        self.end_unix_seconds
    }

    #[must_use]
    pub const fn duration_seconds(self) -> i64 {
        self.end_unix_seconds - self.start_unix_seconds
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessState {
    Fresh,
    Stale,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionState {
    Complete,
    Gap,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Conforming,
    Violation,
    DeliveryDegraded,
    Stale,
    Partial,
    Empty,
    Unavailable,
    ProviderUnknown,
    Tampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceBounds {
    max_pages: u16,
    max_page_size: u16,
    max_violation_samples: usize,
    max_cursor_bytes: usize,
}

impl EvidenceBounds {
    pub fn new(
        max_pages: u16,
        max_page_size: u16,
        max_violation_samples: usize,
        max_cursor_bytes: usize,
    ) -> Result<Self, ModelError> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_page_size == 0
            || max_page_size > MAX_PAGE_SIZE
            || max_violation_samples > MAX_VIOLATION_SAMPLES
            || max_cursor_bytes == 0
            || max_cursor_bytes > MAX_CURSOR_BYTES
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_pages,
            max_page_size,
            max_violation_samples,
            max_cursor_bytes,
        })
    }

    #[must_use]
    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    #[must_use]
    pub const fn max_page_size(&self) -> u16 {
        self.max_page_size
    }

    #[must_use]
    pub const fn max_violation_samples(&self) -> usize {
        self.max_violation_samples
    }

    #[must_use]
    pub const fn max_cursor_bytes(&self) -> usize {
        self.max_cursor_bytes
    }
}

impl Default for EvidenceBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_page_size: MAX_PAGE_SIZE,
            max_violation_samples: MAX_VIOLATION_SAMPLES,
            max_cursor_bytes: MAX_CURSOR_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentScope {
    workspace_id: WorkspaceId,
    source_id: SourceId,
    tracking_plan_id: TrackingPlanId,
    plan_revision: Revision,
    event_spec_id: EventSpecId,
    destination_id: DestinationId,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    scope_digest: Digest,
}

impl SegmentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        source_id: SourceId,
        tracking_plan_id: TrackingPlanId,
        plan_revision: Revision,
        event_spec_id: EventSpecId,
        destination_id: DestinationId,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        if !is_digest(permission_digest.as_str()) {
            return Err(ModelError::InvalidDigest);
        }
        let scope_digest = Digest::from_fields(
            "segment-scope/v1",
            [
                workspace_id.as_str().to_owned(),
                source_id.as_str().to_owned(),
                tracking_plan_id.as_str().to_owned(),
                plan_revision.get().to_string(),
                event_spec_id.as_str().to_owned(),
                destination_id.as_str().to_owned(),
                project_id.as_str().to_owned(),
                project_revision.get().to_string(),
                mission_id.as_str().to_owned(),
                mission_revision.get().to_string(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            workspace_id,
            source_id,
            tracking_plan_id,
            plan_revision,
            event_spec_id,
            destination_id,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            permission_digest,
            scope_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_only(
        workspace_id: WorkspaceId,
        source_id: SourceId,
        tracking_plan_id: TrackingPlanId,
        plan_revision: Revision,
        event_spec_id: EventSpecId,
        destination_id: DestinationId,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
    ) -> Self {
        Self::new(
            workspace_id,
            source_id,
            tracking_plan_id,
            plan_revision,
            event_spec_id,
            destination_id,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            PermissionSnapshot::read_only().digest().clone(),
        )
        .expect("the built-in Segment read-only scope is valid")
    }

    #[must_use]
    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    #[must_use]
    pub fn tracking_plan_id(&self) -> &TrackingPlanId {
        &self.tracking_plan_id
    }

    #[must_use]
    pub const fn plan_revision(&self) -> Revision {
        self.plan_revision
    }

    #[must_use]
    pub fn event_spec_id(&self) -> &EventSpecId {
        &self.event_spec_id
    }

    #[must_use]
    pub fn destination_id(&self) -> &DestinationId {
        &self.destination_id
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    #[must_use]
    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    #[must_use]
    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    #[must_use]
    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    #[must_use]
    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryHealth {
    Healthy,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationCategory {
    MissingEvent,
    UnknownEvent,
    MissingProperty,
    UnexpectedProperty,
    InvalidProperty,
    TypeMismatch,
    BlockedEvent,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrackingPlanEvidence {
    pub tracking_plan_id: TrackingPlanId,
    pub plan_revision: Revision,
    pub event_spec_count: u16,
    pub schema_digest: Digest,
    pub plan_digest: Digest,
}

impl TrackingPlanEvidence {
    pub fn new(
        tracking_plan_id: TrackingPlanId,
        plan_revision: Revision,
        event_spec_count: u16,
        schema_digest: Digest,
    ) -> Result<Self, ModelError> {
        if usize::from(event_spec_count) > MAX_EVENT_SPECS {
            return Err(ModelError::BoundExceeded);
        }
        let plan_digest = Digest::from_fields(
            "segment-tracking-plan/v1",
            [
                tracking_plan_id.as_str().to_owned(),
                plan_revision.get().to_string(),
                event_spec_count.to_string(),
                schema_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            tracking_plan_id,
            plan_revision,
            event_spec_count,
            schema_digest,
            plan_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventSchemaEvidence {
    pub event_spec_id: EventSpecId,
    pub plan_revision: Revision,
    pub schema_digest: Digest,
    pub field_count: u16,
}

impl EventSchemaEvidence {
    #[must_use]
    pub fn new(
        event_spec_id: EventSpecId,
        plan_revision: Revision,
        schema_digest: Digest,
        field_count: u16,
    ) -> Self {
        Self {
            event_spec_id,
            plan_revision,
            schema_digest,
            field_count,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "segment-event-schema/v1",
            [
                self.event_spec_id.as_str().to_owned(),
                self.plan_revision.get().to_string(),
                self.schema_digest.as_str().to_owned(),
                self.field_count.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceEvidence {
    pub source_id: SourceId,
    pub status: ConnectionStatus,
    pub tracking_plan_digest: Digest,
    pub plan_revision: Revision,
}

impl SourceEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "segment-source-evidence/v1",
            [
                self.source_id.as_str().to_owned(),
                format!("{:?}", self.status),
                self.tracking_plan_digest.as_str().to_owned(),
                self.plan_revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DestinationEvidence {
    pub destination_id: DestinationId,
    pub status: ConnectionStatus,
    pub source_id: SourceId,
    pub delivery_digest: Digest,
}

impl DestinationEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "segment-destination-evidence/v1",
            [
                self.destination_id.as_str().to_owned(),
                format!("{:?}", self.status),
                self.source_id.as_str().to_owned(),
                self.delivery_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ViolationEvidence {
    pub category: ViolationCategory,
    pub count: u64,
    pub sample_digests: Vec<Digest>,
}

impl ViolationEvidence {
    pub fn new(
        category: ViolationCategory,
        count: u64,
        sample_digests: Vec<Digest>,
    ) -> Result<Self, ModelError> {
        if sample_digests.len() > MAX_VIOLATION_SAMPLES {
            return Err(ModelError::TooManyViolationSamples);
        }
        Ok(Self {
            category,
            count,
            sample_digests,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut fields = vec![format!("{:?}", self.category), self.count.to_string()];
        fields.extend(
            self.sample_digests
                .iter()
                .map(|digest| digest.as_str().to_owned()),
        );
        Digest::from_fields("segment-violation/v1", fields)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeliveryEvidence {
    pub destination_id: DestinationId,
    pub health: DeliveryHealth,
    pub delivered_count: u64,
    pub failed_count: u64,
    pub observed_at_unix_seconds: i64,
    pub freshness: FreshnessState,
    pub retention: RetentionState,
    pub delivery_digest: Digest,
}

impl DeliveryEvidence {
    #[must_use]
    pub fn new(
        destination_id: DestinationId,
        health: DeliveryHealth,
        delivered_count: u64,
        failed_count: u64,
        observed_at_unix_seconds: i64,
        freshness: FreshnessState,
        retention: RetentionState,
    ) -> Self {
        let delivery_digest = Digest::from_fields(
            "segment-delivery-evidence/v1",
            [
                destination_id.as_str().to_owned(),
                format!("{health:?}"),
                delivered_count.to_string(),
                failed_count.to_string(),
                observed_at_unix_seconds.to_string(),
                format!("{freshness:?}"),
                format!("{retention:?}"),
            ],
        );
        Self {
            destination_id,
            health,
            delivered_count,
            failed_count,
            observed_at_unix_seconds,
            freshness,
            retention,
            delivery_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SegmentRegistration {
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub provider_version: PluginVersion,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub evidence_digest: Digest,
    pub revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

impl SegmentRegistration {
    pub fn new(
        provider_version: PluginVersion,
        api_revision: impl Into<String>,
        provider_digest: Digest,
        scope: &SegmentScope,
        contract_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let service_id = ServiceId::new(SEGMENT_EVENT_EVIDENCE_SERVICE_ID)?;
        let provider_id = ProviderId::new(SEGMENT_EVENT_EVIDENCE_PROVIDER_ID)?;
        let api_revision = api_revision.into();
        if !valid_identifier(&api_revision) {
            return Err(ModelError::InvalidIdentifier);
        }
        let contract_version = SEGMENT_EVENT_EVIDENCE_CONTRACT_VERSION.to_owned();
        let evidence_digest = Digest::from_fields(
            "segment-registration-evidence/v1",
            [
                scope.scope_digest.as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                provider_version.to_string(),
                revision.get().to_string(),
            ],
        );
        let registration_digest = Digest::from_fields(
            "segment-registration/v1",
            [
                service_id.as_str().to_owned(),
                provider_id.as_str().to_owned(),
                provider_version.to_string(),
                api_revision.clone(),
                provider_digest.as_str().to_owned(),
                contract_version.clone(),
                contract_digest.as_str().to_owned(),
                scope.scope_digest.as_str().to_owned(),
                scope.permission_digest.as_str().to_owned(),
                evidence_digest.as_str().to_owned(),
                revision.get().to_string(),
            ],
        );
        Ok(Self {
            service_id,
            provider_id,
            provider_version,
            api_revision,
            provider_digest,
            contract_version,
            contract_digest,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
            evidence_digest,
            revision,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> SegmentScope {
        SegmentScope::read_only(
            WorkspaceId::new("workspace").unwrap(),
            SourceId::new("source").unwrap(),
            TrackingPlanId::new("plan").unwrap(),
            Revision::new(1).unwrap(),
            EventSpecId::new("event-spec").unwrap(),
            DestinationId::new("destination").unwrap(),
            ProjectId::new("project").unwrap(),
            Revision::new(1).unwrap(),
            MissionId::new("mission").unwrap(),
            Revision::new(1).unwrap(),
            WorkProductId::new("work-product").unwrap(),
            Revision::new(1).unwrap(),
        )
    }

    #[test]
    fn digest_is_deterministic_and_length_prefixed() {
        assert_eq!(Digest::from_text("a"), Digest::from_text("a"));
        assert_ne!(
            Digest::from_fields("d", ["ab", "c"]),
            Digest::from_fields("d", ["a", "bc"])
        );
    }

    #[test]
    fn secret_reference_debug_is_redacted_and_revocable() {
        let scope = ids();
        let mut secret =
            SecretReference::new("keyring-alias", &scope, 1, SecretKind::PublicApiToken).unwrap();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("keyring-alias"));
        assert!(!secret.is_revoked());
        secret.revoke().unwrap();
        assert!(secret.is_revoked());
    }

    #[test]
    fn bounds_reject_unbounded_values() {
        assert!(EvidenceBounds::new(MAX_PAGES + 1, 1, 1, 1).is_err());
        assert!(EvidenceWindow::new(0, MAX_WINDOW_SECONDS + 1).is_err());
        assert!(PermissionSnapshot::new([Permission::EventSend]).is_err());
        let cursor = OpaqueCursor::new("opaque-segment-cursor").unwrap();
        assert_ne!(cursor.digest().as_str(), "opaque-segment-cursor");
        assert!(OpaqueCursor::new("").is_err());
        assert!(OpaqueCursor::new(vec![b'x'; MAX_CURSOR_BYTES + 1]).is_err());
    }

    #[test]
    fn scope_digest_carries_all_revisions() {
        let first = ids();
        let second = SegmentScope::read_only(
            WorkspaceId::new("workspace").unwrap(),
            SourceId::new("source").unwrap(),
            TrackingPlanId::new("plan").unwrap(),
            Revision::new(2).unwrap(),
            EventSpecId::new("event-spec").unwrap(),
            DestinationId::new("destination").unwrap(),
            ProjectId::new("project").unwrap(),
            Revision::new(1).unwrap(),
            MissionId::new("mission").unwrap(),
            Revision::new(1).unwrap(),
            WorkProductId::new("work-product").unwrap(),
            Revision::new(1).unwrap(),
        );
        assert_ne!(first.scope_digest(), second.scope_digest());
    }
}
