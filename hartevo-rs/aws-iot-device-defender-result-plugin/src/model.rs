//! Typed and redacted AWS IoT Device Defender Layer-1 boundary models.
//!
//! The model deliberately has no raw finding, certificate, role, additional
//! information, device payload, credential, or mutation type. Provider
//! adapters can only hand the service bounded pages made from these types.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    MAX_CHECKS, MAX_FINDINGS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESOURCES, MAX_RESPONSE_BYTES,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is outside the retention window")]
    RetentionExpired { field: &'static str },
    #[error("the opaque SecretReference is invalid or revoked")]
    InvalidSecretReference,
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

pub type Result<T> = std::result::Result<T, ModelError>;

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*#?%".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, parts: &[String]) -> Self {
        let mut input = Vec::new();
        append_length_prefixed(&mut input, domain);
        for part in parts {
            append_length_prefixed(&mut input, part);
        }
        Self::from_bytes(&input)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub const fn zero() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_digest(&self.0, "digest")
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

fn append_length_prefixed(input: &mut Vec<u8>, value: &str) {
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value.as_bytes());
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-iot-device-defender-", $field, "/v1"),
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

bounded_identifier!(AuditTaskId, "audit-task");
bounded_identifier!(CheckName, "check");
bounded_identifier!(ResourceId, "resource");
bounded_identifier!(ResourceType, "resource-type");
bounded_identifier!(MissionId, "mission");
bounded_identifier!(ProjectId, "project");
bounded_identifier!(WorkProductId, "work-product");
bounded_identifier!(PermissionId, "permission");
bounded_identifier!(ProviderId, "provider");
bounded_identifier!(ProviderRevision, "provider-revision");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-account/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "AWS region", 64)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-region/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for AwsRegion {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTaskStatus {
    InProgress,
    Complete,
    Failed,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Compliant,
    NonCompliant,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvidenceState {
    Complete,
    Partial,
    Unknown,
    AccessLoss,
    NotFound,
    RetentionExpired,
    TaskDrift,
    CheckDrift,
    ResourceDrift,
    PaginationLoop,
    ProviderUnknown,
    Throttled,
}

impl AuditEvidenceState {
    pub const fn review_eligible(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn adoptable(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    ListAuditTasks,
    DescribeAuditTask,
    ListAuditFindings,
    MissionScope,
}

impl PermissionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListAuditTasks => "iot:ListAuditTasks",
            Self::DescribeAuditTask => "iot:DescribeAuditTask",
            Self::ListAuditFindings => "iot:ListAuditFindings",
            Self::MissionScope => "mission.scope",
        }
    }

    pub const fn all() -> [Self; 4] {
        [
            Self::ListAuditTasks,
            Self::DescribeAuditTask,
            Self::ListAuditFindings,
            Self::MissionScope,
        ]
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AuditTaskBinding {
    pub id: AuditTaskId,
    pub revision: Revision,
}

impl AuditTaskBinding {
    pub fn new(id: AuditTaskId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-audit-task-binding/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CheckBinding {
    pub name: CheckName,
    pub revision: Revision,
}

impl CheckBinding {
    pub fn new(name: CheckName, revision: Revision) -> Self {
        Self { name, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-check-binding/v1",
            &[
                self.name.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ResourceBinding {
    pub resource_type: ResourceType,
    pub resource_id: ResourceId,
    pub revision: Revision,
}

impl ResourceBinding {
    pub fn new(resource_type: ResourceType, resource_id: ResourceId, revision: Revision) -> Self {
        Self {
            resource_type,
            resource_id,
            revision,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-resource-binding/v1",
            &[
                self.resource_type.digest().to_string(),
                self.resource_id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub fn resource_type_digest(&self) -> Digest {
        self.resource_type.digest()
    }

    pub fn resource_id_digest(&self) -> Digest {
        self.resource_id.digest()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-mission-binding/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-project-binding/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-work-product-binding/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsIotDeviceDefenderScope {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub audit_task: AuditTaskBinding,
    pub checks: Vec<CheckBinding>,
    pub resources: Vec<ResourceBinding>,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub retention_until: DateTime<Utc>,
    pub scope_digest: Digest,
}

impl AwsIotDeviceDefenderScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        region: AwsRegion,
        audit_task: AuditTaskBinding,
        checks: impl IntoIterator<Item = CheckBinding>,
        resources: impl IntoIterator<Item = ResourceBinding>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        retention_until: DateTime<Utc>,
    ) -> Result<Self> {
        let checks = normalize_checks(checks.into_iter().collect())?;
        let resources = normalize_resources(resources.into_iter().collect())?;
        if retention_until <= DateTime::<Utc>::UNIX_EPOCH {
            return Err(ModelError::Invalid {
                field: "retention until",
            });
        }
        let mut scope = Self {
            account_id,
            region,
            audit_task,
            checks,
            resources,
            mission,
            project,
            work_product,
            retention_until,
            scope_digest: Digest::zero(),
        };
        scope.scope_digest = scope.recomputed_digest();
        Ok(scope)
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn audit_task_digest(&self) -> Digest {
        self.audit_task.digest()
    }

    pub fn checks_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-check-allowlist/v1",
            &self
                .checks
                .iter()
                .map(|check| check.digest().to_string())
                .collect::<Vec<_>>(),
        )
    }

    pub fn resources_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-resource-allowlist/v1",
            &self
                .resources
                .iter()
                .map(|resource| resource.digest().to_string())
                .collect::<Vec<_>>(),
        )
    }

    pub fn allows_check(&self, check: &CheckBinding) -> bool {
        self.checks.contains(check)
    }

    pub fn allows_resource(&self, resource: &ResourceBinding) -> bool {
        self.resources.contains(resource)
    }

    pub fn resource_revision(
        &self,
        resource_type: &ResourceType,
        resource_id: &ResourceId,
    ) -> Option<Revision> {
        self.resources
            .iter()
            .find(|resource| {
                &resource.resource_type == resource_type && &resource.resource_id == resource_id
            })
            .map(|resource| resource.revision)
    }

    pub fn validate(&self) -> Result<()> {
        if self.checks.is_empty() {
            return Err(ModelError::Invalid {
                field: "check allowlist",
            });
        }
        if self.resources.is_empty() {
            return Err(ModelError::Invalid {
                field: "resource allowlist",
            });
        }
        if self.recomputed_digest() != self.scope_digest {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        if self.retention_until <= DateTime::<Utc>::UNIX_EPOCH {
            return Err(ModelError::Invalid {
                field: "retention until",
            });
        }
        Ok(())
    }

    pub fn is_retained_at(&self, observed_at: DateTime<Utc>) -> bool {
        observed_at < self.retention_until
    }

    fn recomputed_digest(&self) -> Digest {
        let mut parts = vec![
            self.account_id.digest().to_string(),
            self.region.digest().to_string(),
            self.audit_task.digest().to_string(),
            self.checks_digest().to_string(),
            self.resources_digest().to_string(),
            self.mission.digest().to_string(),
            self.project.digest().to_string(),
            self.work_product.digest().to_string(),
            self.retention_until.to_rfc3339(),
        ];
        parts.sort_by(|left, right| left.cmp(right).then_with(|| left.len().cmp(&right.len())));
        Digest::from_parts("aws-iot-device-defender-scope/v1", &parts)
    }
}

fn normalize_checks(mut checks: Vec<CheckBinding>) -> Result<Vec<CheckBinding>> {
    if checks.len() > MAX_CHECKS {
        return Err(ModelError::TooMany { field: "checks" });
    }
    checks.sort();
    if checks.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ModelError::Duplicate { field: "checks" });
    }
    Ok(checks)
}

fn normalize_resources(mut resources: Vec<ResourceBinding>) -> Result<Vec<ResourceBinding>> {
    if resources.len() > MAX_RESOURCES {
        return Err(ModelError::TooMany { field: "resources" });
    }
    resources.sort();
    if resources.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ModelError::Duplicate { field: "resources" });
    }
    Ok(resources)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub actions: BTreeSet<PermissionAction>,
    pub permission_digest: Digest,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self> {
        let actions = PermissionAction::all().into_iter().collect();
        let mut permission = Self {
            id,
            revision,
            actions,
            permission_digest: Digest::zero(),
        };
        permission.permission_digest = permission.recomputed_digest();
        Ok(permission)
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self> {
        let actions: BTreeSet<_> = actions.into_iter().collect();
        if actions.is_empty() {
            return Err(ModelError::Invalid {
                field: "permissions",
            });
        }
        let mut permission = Self {
            id,
            revision,
            actions,
            permission_digest: Digest::zero(),
        };
        permission.permission_digest = permission.recomputed_digest();
        Ok(permission)
    }

    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn validate(&self) -> Result<()> {
        if self.permission_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-permission/v1",
            &[
                self.id.digest().to_string(),
                self.revision.get().to_string(),
                self.actions
                    .iter()
                    .map(|action| action.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsentBinding {
    pub id_digest: Digest,
    pub revision: Revision,
    pub expires_at: DateTime<Utc>,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

impl ConsentBinding {
    pub fn for_read_only(
        id: impl AsRef<str>,
        revision: Revision,
        expires_at: DateTime<Utc>,
        permission: &PermissionFence,
    ) -> Result<Self> {
        validate_text(id.as_ref(), "consent id", MAX_IDENTIFIER_BYTES)?;
        let mut consent = Self {
            id_digest: Digest::from_text(id.as_ref()),
            revision,
            expires_at,
            permission_digest: permission.digest(),
            consent_digest: Digest::zero(),
        };
        consent.consent_digest = consent.recomputed_digest();
        Ok(consent)
    }

    pub fn digest(&self) -> Digest {
        self.consent_digest.clone()
    }

    pub fn validate(&self, permission: &PermissionFence, observed_at: DateTime<Utc>) -> Result<()> {
        if self.permission_digest != permission.digest()
            || self.consent_digest != self.recomputed_digest()
            || self.expires_at <= observed_at
        {
            return Err(ModelError::ScopeMismatch { field: "consent" });
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-consent/v1",
            &[
                self.id_digest.to_string(),
                self.revision.get().to_string(),
                self.expires_at.to_rfc3339(),
                self.permission_digest.to_string(),
            ],
        )
    }
}

/// An opaque handle to a host-owned SigV4 secret. The handle is never
/// serialized, displayed, or returned through a provider request.
pub struct SecretReference {
    opaque_handle: String,
    scope_digest: Digest,
    region: AwsRegion,
    credential_revision: Revision,
    reference_digest: Digest,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &AwsIotDeviceDefenderScope,
        credential_revision: u64,
    ) -> Result<Self> {
        let opaque_handle = opaque_handle.into();
        validate_text(
            &opaque_handle,
            "opaque SecretReference handle",
            MAX_IDENTIFIER_BYTES,
        )?;
        let credential_revision = Revision::new(credential_revision)?;
        let mut reference = Self {
            opaque_handle,
            scope_digest: scope.digest(),
            region: scope.region.clone(),
            credential_revision,
            reference_digest: Digest::zero(),
            revoked: false,
        };
        reference.reference_digest = reference.recomputed_digest();
        Ok(reference)
    }

    pub fn for_sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsIotDeviceDefenderScope,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, 1)
    }

    pub fn for_device_defender(
        opaque_handle: impl Into<String>,
        scope: &AwsIotDeviceDefenderScope,
    ) -> Result<Self> {
        Self::for_sigv4(opaque_handle, scope)
    }

    pub fn for_iot_device_defender(
        opaque_handle: impl Into<String>,
        scope: &AwsIotDeviceDefenderScope,
    ) -> Result<Self> {
        Self::for_sigv4(opaque_handle, scope)
    }

    pub fn reference_digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    pub fn digest(&self) -> Digest {
        self.reference_digest()
    }

    pub fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self, scope: &AwsIotDeviceDefenderScope) -> Result<()> {
        if self.revoked
            || self.scope_digest != scope.digest()
            || self.region != scope.region
            || self.reference_digest != self.recomputed_digest()
        {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-secret-reference/v1",
            &[
                Digest::from_text(self.opaque_handle.as_bytes()).to_string(),
                self.scope_digest.to_string(),
                self.region.digest().to_string(),
                self.credential_revision.get().to_string(),
                self.revoked.to_string(),
            ],
        )
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            opaque_handle: self.opaque_handle.clone(),
            scope_digest: self.scope_digest.clone(),
            region: self.region.clone(),
            credential_revision: self.credential_revision,
            reference_digest: self.reference_digest.clone(),
            revoked: self.revoked,
        }
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.opaque_handle.zeroize();
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("region", &self.region)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

/// A cursor contains only a redacted token digest in serialized/debug forms.
#[derive(Eq, PartialEq)]
pub struct OpaqueCursor {
    token: String,
    token_digest: Digest,
    binding_digest: Digest,
    page: u16,
}

impl OpaqueCursor {
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() || token.len() > MAX_CURSOR_BYTES || token.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor { field: "cursor" });
        }
        Ok(Self {
            token_digest: Digest::from_text(token.as_bytes()),
            token,
            binding_digest: Digest::zero(),
            page: 0,
        })
    }

    pub(crate) fn bind_to(&self, binding_digest: &Digest, page: u16) -> Self {
        Self {
            token: self.token.clone(),
            token_digest: self.token_digest.clone(),
            binding_digest: binding_digest.clone(),
            page,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-cursor/v1",
            &[
                self.token_digest.to_string(),
                self.binding_digest.to_string(),
                self.page.to_string(),
            ],
        )
    }

    pub fn token_digest(&self) -> Digest {
        self.token_digest.clone()
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page(&self) -> u16 {
        self.page
    }

    pub fn is_unbound(&self) -> bool {
        self.binding_digest.is_zero()
    }
}

impl Clone for OpaqueCursor {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            token_digest: self.token_digest.clone(),
            binding_digest: self.binding_digest.clone(),
            page: self.page,
        }
    }
}

impl Drop for OpaqueCursor {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page", &self.page)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueCursor", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ListAuditTasksRequest {
    pub scope_digest: Digest,
    pub audit_task_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub request_digest: Digest,
}

impl ListAuditTasksRequest {
    pub fn new(
        scope: &AwsIotDeviceDefenderScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        validate_page_bounds(page_size, max_pages)?;
        let query_digest = Digest::from_parts(
            "aws-iot-device-defender-list-audit-tasks-request/v1",
            &[
                scope.digest().to_string(),
                scope.audit_task_digest().to_string(),
                page_size.to_string(),
                max_pages.to_string(),
            ],
        );
        let cursor = bind_cursor(cursor, &query_digest, 2)?;
        Ok(Self {
            scope_digest: scope.digest(),
            audit_task_digest: scope.audit_task_digest(),
            page_size,
            max_pages,
            cursor,
            request_digest: query_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.request_digest.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescribeAuditTaskRequest {
    pub scope_digest: Digest,
    pub audit_task_digest: Digest,
    pub request_digest: Digest,
}

impl DescribeAuditTaskRequest {
    pub fn for_scope(scope: &AwsIotDeviceDefenderScope) -> Self {
        let request_digest = Digest::from_parts(
            "aws-iot-device-defender-describe-audit-task-request/v1",
            &[
                scope.digest().to_string(),
                scope.audit_task_digest().to_string(),
            ],
        );
        Self {
            scope_digest: scope.digest(),
            audit_task_digest: scope.audit_task_digest(),
            request_digest,
        }
    }

    pub fn digest(&self) -> Digest {
        self.request_digest.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ListAuditFindingsRequest {
    pub scope_digest: Digest,
    pub audit_task_digest: Digest,
    pub check_allowlist_digest: Digest,
    pub resource_allowlist_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub request_digest: Digest,
}

impl ListAuditFindingsRequest {
    pub fn for_scope(
        scope: &AwsIotDeviceDefenderScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        validate_page_bounds(page_size, max_pages)?;
        let query_digest = Digest::from_parts(
            "aws-iot-device-defender-list-audit-findings-request/v1",
            &[
                scope.digest().to_string(),
                scope.audit_task_digest().to_string(),
                scope.checks_digest().to_string(),
                scope.resources_digest().to_string(),
                page_size.to_string(),
                max_pages.to_string(),
            ],
        );
        let cursor = bind_cursor(cursor, &query_digest, 2)?;
        Ok(Self {
            scope_digest: scope.digest(),
            audit_task_digest: scope.audit_task_digest(),
            check_allowlist_digest: scope.checks_digest(),
            resource_allowlist_digest: scope.resources_digest(),
            page_size,
            max_pages,
            cursor,
            request_digest: query_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.request_digest.clone()
    }
}

fn validate_page_bounds(page_size: u16, max_pages: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(ModelError::Invalid { field: "page size" });
    }
    if max_pages == 0 || max_pages > MAX_PAGES {
        return Err(ModelError::Invalid { field: "max pages" });
    }
    Ok(())
}

fn bind_cursor(
    cursor: Option<OpaqueCursor>,
    query_digest: &Digest,
    next_page: u16,
) -> Result<Option<OpaqueCursor>> {
    cursor
        .map(|cursor| {
            if cursor.is_unbound() {
                Ok(cursor.bind_to(query_digest, next_page))
            } else if cursor.binding_digest() != query_digest || cursor.page() < 2 {
                Err(ModelError::ScopeMismatch {
                    field: "cursor binding",
                })
            } else {
                Ok(cursor)
            }
        })
        .transpose()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditTaskMetadata {
    pub task: AuditTaskBinding,
    pub status: AuditTaskStatus,
    pub observed_at: DateTime<Utc>,
    pub task_digest: Digest,
}

impl AuditTaskMetadata {
    pub fn new(
        task: AuditTaskBinding,
        status: AuditTaskStatus,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let task_digest = Digest::from_parts(
            "aws-iot-device-defender-audit-task-metadata/v1",
            &[
                task.digest().to_string(),
                format!("{status:?}"),
                observed_at.to_rfc3339(),
            ],
        );
        Self {
            task,
            status,
            observed_at,
            task_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected =
            Self::new(self.task.clone(), self.status.clone(), self.observed_at).task_digest;
        if self.task_digest != expected {
            Err(ModelError::ScopeMismatch {
                field: "audit task digest",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditCheckSummary {
    pub check: CheckBinding,
    pub state: CheckState,
    pub severity: Severity,
    pub finding_count: u16,
    pub suppressed_count: u16,
    pub check_digest: Digest,
}

impl AuditCheckSummary {
    pub fn new(
        check: CheckBinding,
        state: CheckState,
        severity: Severity,
        finding_count: u16,
        suppressed_count: u16,
    ) -> Result<Self> {
        if suppressed_count > finding_count {
            return Err(ModelError::Invalid {
                field: "suppressed finding count",
            });
        }
        let check_digest = Digest::from_parts(
            "aws-iot-device-defender-audit-check-summary/v1",
            &[
                check.digest().to_string(),
                format!("{state:?}"),
                format!("{severity:?}"),
                finding_count.to_string(),
                suppressed_count.to_string(),
            ],
        );
        Ok(Self {
            check,
            state,
            severity,
            finding_count,
            suppressed_count,
            check_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.suppressed_count > self.finding_count
            || self.check_digest
                != Self::new(
                    self.check.clone(),
                    self.state,
                    self.severity,
                    self.finding_count,
                    self.suppressed_count,
                )?
                .check_digest
        {
            Err(ModelError::ScopeMismatch {
                field: "check digest",
            })
        } else {
            Ok(())
        }
    }
}

/// A finding contains only the allowlist identity and redacted classification
/// needed for evidence. It has no raw AWS finding payload or provider text.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct AuditFinding {
    pub check: CheckBinding,
    pub resource: ResourceBinding,
    pub severity: Severity,
    pub suppressed: bool,
    pub observed_at: DateTime<Utc>,
    pub finding_digest: Digest,
}

impl AuditFinding {
    pub fn new(
        check: CheckBinding,
        resource: ResourceBinding,
        severity: Severity,
        suppressed: bool,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let finding_digest = Digest::from_parts(
            "aws-iot-device-defender-audit-finding/v1",
            &[
                check.digest().to_string(),
                resource.digest().to_string(),
                format!("{severity:?}"),
                suppressed.to_string(),
                observed_at.to_rfc3339(),
            ],
        );
        Self {
            check,
            resource,
            severity,
            suppressed,
            observed_at,
            finding_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.check.clone(),
            self.resource.clone(),
            self.severity,
            self.suppressed,
            self.observed_at,
        )
        .finding_digest;
        if self.finding_digest != expected {
            Err(ModelError::ScopeMismatch {
                field: "finding digest",
            })
        } else {
            Ok(())
        }
    }

    pub fn resource_type_digest(&self) -> Digest {
        self.resource.resource_type_digest()
    }

    pub fn resource_id_digest(&self) -> Digest {
        self.resource.resource_id_digest()
    }
}

impl fmt::Debug for AuditFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditFinding")
            .field("check_digest", &self.check.digest())
            .field("resource_digest", &self.resource.digest())
            .field("severity", &self.severity)
            .field("suppressed", &self.suppressed)
            .field("observed_at", &self.observed_at)
            .field("finding_digest", &self.finding_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditCheckEvidence {
    pub check_digest: Digest,
    pub state: CheckState,
    pub severity: Severity,
    pub finding_count: u16,
    pub suppressed_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditFindingEvidence {
    pub finding_digest: Digest,
    pub check_digest: Digest,
    pub resource_type_digest: Digest,
    pub resource_id_digest: Digest,
    pub severity: Severity,
    pub suppressed: bool,
}

impl AuditFindingEvidence {
    pub fn from_finding(finding: &AuditFinding) -> Self {
        Self {
            finding_digest: finding.finding_digest.clone(),
            check_digest: finding.check.digest(),
            resource_type_digest: finding.resource_type_digest(),
            resource_id_digest: finding.resource_id_digest(),
            severity: finding.severity,
            suppressed: finding.suppressed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FailureEvidence {
    pub operation: String,
    pub category: String,
    pub status_code: Option<u16>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    pub fn new(
        operation: impl Into<String>,
        category: impl Into<String>,
        status_code: Option<u16>,
    ) -> Self {
        let operation = operation.into();
        let category = category.into();
        let failure_digest = Digest::from_parts(
            "aws-iot-device-defender-failure/v1",
            &[
                operation.clone(),
                category.clone(),
                status_code.map_or_else(String::new, |code| code.to_string()),
            ],
        );
        Self {
            operation,
            category,
            status_code,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsIotDeviceDefenderEvidence {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub audit_task_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub task_status: AuditTaskStatus,
    pub state: AuditEvidenceState,
    pub checks: Vec<AuditCheckEvidence>,
    pub findings: Vec<AuditFindingEvidence>,
    pub list_audit_tasks_digest: Option<Digest>,
    pub describe_audit_task_digest: Option<Digest>,
    pub list_audit_findings_digest: Option<Digest>,
    pub cursor_digests: Vec<Digest>,
    pub list_pages: u16,
    pub describe_read: bool,
    pub findings_pages: u16,
    pub list_complete: bool,
    pub findings_complete: bool,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_finding_data_retained: bool,
    pub evidence_digest: Digest,
}

impl AwsIotDeviceDefenderEvidence {
    pub fn recomputed_digest(&self) -> Digest {
        let mut parts = vec![
            self.scope_digest.to_string(),
            self.registration_digest.to_string(),
            self.account_digest.to_string(),
            self.region_digest.to_string(),
            self.audit_task_digest.to_string(),
            self.mission_digest.to_string(),
            self.project_digest.to_string(),
            self.work_product_digest.to_string(),
            format!("{:?}", self.task_status),
            format!("{:?}", self.state),
            self.list_audit_tasks_digest
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            self.describe_audit_task_digest
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            self.list_audit_findings_digest
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            self.list_pages.to_string(),
            self.describe_read.to_string(),
            self.findings_pages.to_string(),
            self.list_complete.to_string(),
            self.findings_complete.to_string(),
            self.observed_at.to_rfc3339(),
            self.expires_at.to_rfc3339(),
            self.provenance.as_str().to_owned(),
            self.connected.to_string(),
            self.native.to_string(),
            self.first_party.to_string(),
            self.provider_receipt.to_string(),
            self.raw_finding_data_retained.to_string(),
            self.failure
                .as_ref()
                .map_or_else(String::new, |failure| failure.failure_digest.to_string()),
        ];
        parts.extend(self.checks.iter().flat_map(|check| {
            [
                check.check_digest.to_string(),
                format!("{:?}", check.state),
                format!("{:?}", check.severity),
                check.finding_count.to_string(),
                check.suppressed_count.to_string(),
            ]
        }));
        parts.extend(self.findings.iter().flat_map(|finding| {
            [
                finding.finding_digest.to_string(),
                finding.check_digest.to_string(),
                finding.resource_type_digest.to_string(),
                finding.resource_id_digest.to_string(),
                format!("{:?}", finding.severity),
                finding.suppressed.to_string(),
            ]
        }));
        parts.extend(self.cursor_digests.iter().map(ToString::to_string));
        Digest::from_parts("aws-iot-device-defender-evidence/v1", &parts)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for digest in [
            &self.scope_digest,
            &self.registration_digest,
            &self.account_digest,
            &self.region_digest,
            &self.audit_task_digest,
            &self.mission_digest,
            &self.project_digest,
            &self.work_product_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self.checks.len() > MAX_CHECKS
            || self.findings.len() > MAX_FINDINGS
            || self.list_pages > MAX_PAGES
            || self.findings_pages > MAX_PAGES
            || (self.expires_at <= self.observed_at
                && !matches!(self.state, AuditEvidenceState::RetentionExpired))
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.raw_finding_data_retained
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "evidence integrity",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn max_response_bytes() -> usize {
    MAX_RESPONSE_BYTES
}
