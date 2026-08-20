use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GCP_CLOUD_LOGGING_RESULT_CONSUMER_ID, GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION,
    GCP_CLOUD_LOGGING_RESULT_SCHEMA_VERSION, GCP_CLOUD_LOGGING_RESULT_SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAGE_SIZE: u32 = 1_000;
pub const MAX_RESULT_PAGES: u8 = 16;
pub const MAX_RESULT_ENTRIES: usize = 4_096;
pub const MAX_METADATA_SAMPLES: usize = 64;
pub const MAX_METADATA_BYTES: usize = 8 * 1024;
pub const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_TIME_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_RETRIES: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("the provider-resource scope must have non-empty allowlists")]
    InvalidScope,
    #[error("the Project identity must match the provider project resource")]
    ProjectMismatch,
    #[error("time window is empty, reversed, or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("filter template is not an allowlisted single-resource/single-log filter")]
    InvalidFilter,
    #[error("arbitrary filter text is not accepted by Layer 1")]
    ArbitraryFilterRejected,
    #[error("the permission fence does not include logging.entries.list")]
    InvalidPermission,
    #[error("page size is empty or exceeds the Layer-1 ceiling")]
    InvalidPageSize,
    #[error("opaque page token is empty, too large, or contains control data")]
    InvalidPageToken,
    #[error("log entry aggregate is malformed or outside the governed scope")]
    InvalidEntry,
    #[error("page is malformed, out of scope, or exceeds a Layer-1 bound")]
    InvalidPage,
    #[error("metadata digest does not match immutable fields")]
    DigestMismatch,
    #[error("registration is invalid or drifted")]
    InvalidRegistration,
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("registration lifecycle transition is invalid")]
    InvalidLifecycle,
}

/// A deterministic, length-framed SHA-256 digest used for every binding.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
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

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
    bytes.extend_from_slice(&length.to_be_bytes());
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
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_resource_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'$')
        })
        && !value.starts_with('/')
        && !value.ends_with('/')
}

fn valid_opaque_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

macro_rules! string_identifier {
    ($name:ident, $validator:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
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
    };
}

string_identifier!(OrganizationId, valid_identifier);
string_identifier!(FolderId, valid_identifier);
string_identifier!(ProjectId, valid_identifier);
string_identifier!(Location, valid_identifier);
string_identifier!(BucketId, valid_identifier);
string_identifier!(ViewId, valid_identifier);
string_identifier!(LogId, valid_resource_component);
string_identifier!(ResourceType, valid_identifier);
string_identifier!(MissionId, valid_identifier);
string_identifier!(WorkProductId, valid_identifier);
string_identifier!(ServiceId, valid_identifier);
string_identifier!(ProviderId, valid_identifier);
string_identifier!(ConsumerId, valid_identifier);

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

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAuthKind {
    OAuth,
    ServiceAccount,
}

/// An opaque host-owned OAuth/service-account reference.
///
/// The caller's reference identifier is hashed at construction time and is
/// never retained, serialized, or emitted in Debug output. Layer 1 has no
/// credential resolver and never turns this into native provider access.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GoogleAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference", &"<opaque>")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GcpCloudLoggingScope,
        credential_revision: u64,
        auth_kind: GoogleAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_opaque_reference(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "gcp-cloud-logging-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GoogleAuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub const fn is_opaque(&self) -> bool {
        true
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogSeverity {
    Default,
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Project {
    pub id: ProjectId,
    pub revision: Revision,
    pub digest: Digest,
}

impl Project {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        let digest = Digest::from_fields(
            "gcp-cloud-logging-project/v1",
            &[id.as_str().to_owned(), revision.get().to_string()],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "gcp-cloud-logging-project/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Mission {
    pub id: MissionId,
    pub revision: Revision,
    pub digest: Digest,
}

impl Mission {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        let digest = Digest::from_fields(
            "gcp-cloud-logging-mission/v1",
            &[id.as_str().to_owned(), revision.get().to_string()],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "gcp-cloud-logging-mission/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub revision: Revision,
    pub digest: Digest,
}

impl WorkProduct {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        let digest = Digest::from_fields(
            "gcp-cloud-logging-work-product/v1",
            &[id.as_str().to_owned(), revision.get().to_string()],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "gcp-cloud-logging-work-product/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimeWindow {
    start_time: i64,
    end_time: i64,
    digest: Digest,
}

impl TimeWindow {
    pub fn new(start_time: i64, end_time: i64) -> Result<Self, ModelError> {
        let duration = end_time
            .checked_sub(start_time)
            .ok_or(ModelError::InvalidTimeWindow)?;
        if start_time < 0 || duration <= 0 || duration > MAX_TIME_WINDOW_SECONDS {
            return Err(ModelError::InvalidTimeWindow);
        }
        let digest = Digest::from_fields(
            "gcp-cloud-logging-time-window/v1",
            &[
                start_time.to_string(),
                end_time.to_string(),
                duration.to_string(),
            ],
        );
        Ok(Self {
            start_time,
            end_time,
            digest,
        })
    }

    pub fn from_end_and_range(end_time: i64, range_seconds: i64) -> Result<Self, ModelError> {
        let start_time = end_time
            .checked_sub(range_seconds)
            .ok_or(ModelError::InvalidTimeWindow)?;
        Self::new(start_time, end_time)
    }

    pub const fn start_time(&self) -> i64 {
        self.start_time
    }

    pub const fn end_time(&self) -> i64 {
        self.end_time
    }

    pub const fn duration_seconds(&self) -> i64 {
        self.end_time - self.start_time
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.start_time, self.end_time)?;
        if rebuilt.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpLoggingPermission {
    LogEntriesList,
}

impl GcpLoggingPermission {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::LogEntriesList => "logging.logEntries.list",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionFence {
    permissions: BTreeSet<GcpLoggingPermission>,
    digest: Digest,
}

impl PermissionFence {
    pub fn new(
        permissions: impl IntoIterator<Item = GcpLoggingPermission>,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&GcpLoggingPermission::LogEntriesList) {
            return Err(ModelError::InvalidPermission);
        }
        let digest = Digest::from_fields(
            "gcp-cloud-logging-permission-fence/v1",
            &permissions
                .iter()
                .map(|permission| permission.api_name().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            digest,
        })
    }

    pub fn least_privilege() -> Self {
        Self::new([GcpLoggingPermission::LogEntriesList])
            .expect("the required Layer-1 permission is always valid")
    }

    pub fn permissions(&self) -> &BTreeSet<GcpLoggingPermission> {
        &self.permissions
    }

    pub fn contains(&self, permission: GcpLoggingPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.permissions.iter().copied())?;
        if rebuilt.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderResourceScope {
    pub organization: OrganizationId,
    pub folder: FolderId,
    pub project: ProjectId,
    pub location: Location,
    pub bucket: BucketId,
    pub view: ViewId,
    pub allowlisted_logs: BTreeSet<LogId>,
    pub allowlisted_resource_types: BTreeSet<ResourceType>,
    digest: Digest,
}

pub type GcpCloudLoggingResourceScope = ProviderResourceScope;

impl ProviderResourceScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationId,
        folder: FolderId,
        project: ProjectId,
        location: Location,
        bucket: BucketId,
        view: ViewId,
        allowlisted_logs: impl IntoIterator<Item = LogId>,
        allowlisted_resource_types: impl IntoIterator<Item = ResourceType>,
    ) -> Result<Self, ModelError> {
        let allowlisted_logs = allowlisted_logs.into_iter().collect::<BTreeSet<_>>();
        let allowlisted_resource_types = allowlisted_resource_types
            .into_iter()
            .collect::<BTreeSet<_>>();
        if allowlisted_logs.is_empty() || allowlisted_resource_types.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let digest = Self::compute_digest(
            &organization,
            &folder,
            &project,
            &location,
            &bucket,
            &view,
            &allowlisted_logs,
            &allowlisted_resource_types,
        );
        Ok(Self {
            organization,
            folder,
            project,
            location,
            bucket,
            view,
            allowlisted_logs,
            allowlisted_resource_types,
            digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn view_resource_name(&self) -> String {
        format!(
            "projects/{}/locations/{}/buckets/{}/views/{}",
            self.project.as_str(),
            self.location.as_str(),
            self.bucket.as_str(),
            self.view.as_str()
        )
    }

    pub fn contains(&self, log_id: &LogId, resource_type: &ResourceType) -> bool {
        self.allowlisted_logs.contains(log_id)
            && self.allowlisted_resource_types.contains(resource_type)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.allowlisted_logs.is_empty() || self.allowlisted_resource_types.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let expected = Self::compute_digest(
            &self.organization,
            &self.folder,
            &self.project,
            &self.location,
            &self.bucket,
            &self.view,
            &self.allowlisted_logs,
            &self.allowlisted_resource_types,
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        organization: &OrganizationId,
        folder: &FolderId,
        project: &ProjectId,
        location: &Location,
        bucket: &BucketId,
        view: &ViewId,
        logs: &BTreeSet<LogId>,
        resource_types: &BTreeSet<ResourceType>,
    ) -> Digest {
        Digest::from_fields(
            "gcp-cloud-logging-provider-resource-scope/v1",
            &[
                organization.as_str().to_owned(),
                folder.as_str().to_owned(),
                project.as_str().to_owned(),
                location.as_str().to_owned(),
                bucket.as_str().to_owned(),
                view.as_str().to_owned(),
                logs.iter().map(LogId::as_str).collect::<Vec<_>>().join(","),
                resource_types
                    .iter()
                    .map(ResourceType::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilterTemplate {
    resource_type: ResourceType,
    log_id: LogId,
    severity_at_least: Option<LogSeverity>,
    digest: Digest,
}

impl FilterTemplate {
    pub fn new(
        resource_type: ResourceType,
        log_id: LogId,
        severity_at_least: Option<LogSeverity>,
    ) -> Result<Self, ModelError> {
        let digest = Digest::from_fields(
            "gcp-cloud-logging-filter-template/v1",
            &[
                resource_type.as_str().to_owned(),
                log_id.as_str().to_owned(),
                severity_at_least.map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
                "single_resource_type=true".to_owned(),
                "single_log=true".to_owned(),
                "arbitrary_text=false".to_owned(),
                "unbounded=false".to_owned(),
            ],
        );
        Ok(Self {
            resource_type,
            log_id,
            severity_at_least,
            digest,
        })
    }

    /// Layer 1 deliberately has no raw-filter parser or passthrough.
    pub fn try_from_raw(_raw_filter: impl AsRef<str>) -> Result<Self, ModelError> {
        Err(ModelError::ArbitraryFilterRejected)
    }

    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    pub fn log_id(&self) -> &LogId {
        &self.log_id
    }

    pub const fn severity_at_least(&self) -> Option<LogSeverity> {
        self.severity_at_least
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.resource_type.clone(),
            self.log_id.clone(),
            self.severity_at_least,
        )?;
        if rebuilt.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilterAst {
    pub template: FilterTemplate,
    pub time_window: TimeWindow,
    pub scope_digest: Digest,
    pub digest: Digest,
}

impl FilterAst {
    pub fn compile(
        scope: &GcpCloudLoggingScope,
        template: FilterTemplate,
        time_window: TimeWindow,
    ) -> Result<Self, ModelError> {
        if template != scope.filter_template || time_window != scope.time_window {
            return Err(ModelError::InvalidFilter);
        }
        template.validate()?;
        time_window.validate()?;
        if !scope
            .resource
            .contains(template.log_id(), template.resource_type())
        {
            return Err(ModelError::InvalidFilter);
        }
        let digest = Digest::from_fields(
            "gcp-cloud-logging-filter-ast/v1",
            &[
                template.digest().as_str().to_owned(),
                time_window.digest().as_str().to_owned(),
                scope.digest().as_str().to_owned(),
                "mandatory_time_bound=true".to_owned(),
                "single_resource_type=true".to_owned(),
                "single_log=true".to_owned(),
            ],
        );
        Ok(Self {
            template,
            time_window,
            scope_digest: scope.digest(),
            digest,
        })
    }

    pub fn for_scope(scope: &GcpCloudLoggingScope) -> Result<Self, ModelError> {
        Self::compile(
            scope,
            scope.filter_template.clone(),
            scope.time_window.clone(),
        )
    }

    pub fn validate(&self, scope: &GcpCloudLoggingScope) -> Result<(), ModelError> {
        let rebuilt = Self::compile(scope, self.template.clone(), self.time_window.clone())?;
        if rebuilt.digest == self.digest && self.scope_digest == scope.digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcpCloudLoggingScope {
    pub resource: ProviderResourceScope,
    pub filter_template: FilterTemplate,
    pub time_window: TimeWindow,
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub permission: PermissionFence,
    digest: Digest,
}

pub type Scope = GcpCloudLoggingScope;

impl GcpCloudLoggingScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: ProviderResourceScope,
        filter_template: FilterTemplate,
        time_window: TimeWindow,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        permission: PermissionFence,
    ) -> Result<Self, ModelError> {
        resource.validate()?;
        filter_template.validate()?;
        time_window.validate()?;
        project.validate()?;
        mission.validate()?;
        work_product.validate()?;
        permission.validate()?;
        if resource.project != project.id {
            return Err(ModelError::ProjectMismatch);
        }
        if !resource.contains(filter_template.log_id(), filter_template.resource_type()) {
            return Err(ModelError::InvalidFilter);
        }
        let digest = Digest::from_fields(
            "gcp-cloud-logging-scope/v1",
            &[
                resource.digest().as_str().to_owned(),
                filter_template.digest().as_str().to_owned(),
                time_window.digest().as_str().to_owned(),
                project.digest.as_str().to_owned(),
                mission.digest.as_str().to_owned(),
                work_product.digest.as_str().to_owned(),
                permission.digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            resource,
            filter_template,
            time_window,
            project,
            mission,
            work_product,
            permission,
            digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub fn filter_digest(&self) -> &Digest {
        self.filter_template.digest()
    }

    pub fn time_window_digest(&self) -> &Digest {
        self.time_window.digest()
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission.digest()
    }

    pub fn provider_resource_digest(&self) -> &Digest {
        self.resource.digest()
    }

    pub fn filter_ast(&self) -> Result<FilterAst, ModelError> {
        FilterAst::for_scope(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.resource.clone(),
            self.filter_template.clone(),
            self.time_window.clone(),
            self.project.clone(),
            self.mission.clone(),
            self.work_product.clone(),
            self.permission.clone(),
        )?;
        if rebuilt.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

/// A page token never retains the provider token. It is only a digest plus a
/// binding to the exact provider-resource/filter/permission scope.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaquePageToken {
    pub fn new(raw_token: impl AsRef<str>) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        if raw_token.is_empty()
            || raw_token.len() > MAX_PAGE_TOKEN_BYTES
            || raw_token.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self {
            token_digest: Digest::from_text(raw_token),
            binding_digest: None,
        })
    }

    #[must_use]
    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn is_bound(&self) -> bool {
        self.binding_digest.is_some()
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnv,
    Unknown,
}

impl ProviderErrorKind {
    pub const fn from_status(status_code: u16) -> Self {
        match status_code {
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::RateLimited,
            500..=599 => Self::ServerFailure,
            _ => Self::Unknown,
        }
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }

    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Conflict | Self::RateLimited | Self::ServerFailure | Self::Timeout
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub blocked_env: bool,
}

impl ProviderErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            diagnostic_digest: Digest::from_text(diagnostic),
            blocked_env: matches!(kind, ProviderErrorKind::BlockedEnv),
        }
    }

    pub fn from_status(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(
            ProviderErrorKind::from_status(status_code),
            Some(status_code),
            diagnostic,
        )
    }

    pub fn timeout(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(ProviderErrorKind::Timeout, None, diagnostic)
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryEvidence {
    pub operation: String,
    pub failed_attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

impl RetryEvidence {
    pub fn from_error(failed_attempt: u8, error: &ProviderErrorEvidence) -> Self {
        Self {
            operation: "entries.list".to_owned(),
            failed_attempt,
            kind: error.kind,
            status_code: error.status_code,
            diagnostic_digest: error.diagnostic_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LogEntryAggregate {
    pub timestamp_seconds: i64,
    pub severity: LogSeverity,
    pub resource_type: ResourceType,
    pub log_id: LogId,
    pub metadata_digest: Digest,
}

impl LogEntryAggregate {
    /// Hashes the caller-owned metadata immediately. The metadata itself is
    /// not retained, serialized, or present in Debug output.
    pub fn from_metadata(
        timestamp_seconds: i64,
        severity: LogSeverity,
        resource_type: ResourceType,
        log_id: LogId,
        metadata: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        let metadata = metadata.as_ref();
        if timestamp_seconds < 0 || metadata.len() > MAX_METADATA_BYTES {
            return Err(ModelError::InvalidEntry);
        }
        Ok(Self {
            timestamp_seconds,
            severity,
            resource_type,
            log_id,
            metadata_digest: Digest::from_text(metadata),
        })
    }

    pub fn from_digest(
        timestamp_seconds: i64,
        severity: LogSeverity,
        resource_type: ResourceType,
        log_id: LogId,
        metadata_digest: Digest,
    ) -> Result<Self, ModelError> {
        if timestamp_seconds < 0 {
            return Err(ModelError::InvalidEntry);
        }
        Ok(Self {
            timestamp_seconds,
            severity,
            resource_type,
            log_id,
            metadata_digest,
        })
    }

    pub fn validate_for(&self, scope: &GcpCloudLoggingScope) -> Result<(), ModelError> {
        if self.timestamp_seconds < scope.time_window.start_time()
            || self.timestamp_seconds >= scope.time_window.end_time()
            || !scope.resource.contains(&self.log_id, &self.resource_type)
        {
            Err(ModelError::InvalidEntry)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-logging-entry-aggregate/v1",
            &[
                self.timestamp_seconds.to_string(),
                format!("{:?}", self.severity),
                self.resource_type.as_str().to_owned(),
                self.log_id.as_str().to_owned(),
                self.metadata_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PageSummary {
    pub page_number: u8,
    pub page_digest: Digest,
    pub entry_count: usize,
    pub next_page_token_digest: Option<Digest>,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Marker type for the intentionally non-authoritative Layer-1 boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceAuthority;

impl EvidenceAuthority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn truth(self) -> bool {
        false
    }

    pub const fn consent(self) -> bool {
        false
    }

    pub const fn effect(self) -> bool {
        false
    }

    pub const fn receipt(self) -> bool {
        false
    }

    pub const fn verification(self) -> bool {
        false
    }

    pub const fn outcome(self) -> bool {
        false
    }
}

pub fn expected_identity_digests() -> (Digest, Digest, Digest) {
    (
        Digest::from_text(crate::GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION),
        Digest::from_bytes(crate::GCP_CLOUD_LOGGING_RESULT_CONTRACT_JSON.as_bytes()),
        Digest::from_fields(
            "gcp-cloud-logging-identity/v1",
            &[
                GCP_CLOUD_LOGGING_RESULT_SCHEMA_VERSION.to_owned(),
                GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION.to_owned(),
                GCP_CLOUD_LOGGING_RESULT_SERVICE_ID.to_owned(),
                GCP_CLOUD_LOGGING_RESULT_CONSUMER_ID.to_owned(),
            ],
        ),
    )
}
