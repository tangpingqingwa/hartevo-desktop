//! Typed, bounded AWS Audit Manager scope, request, response, and evidence models.
//!
//! Provider identifiers are kept only behind digesting opaque wrappers.  The
//! public evidence model has no field for report bytes, raw evidence, account
//! email, role ARN, provider annotations, or credentials.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsAuditManagerError, Result};
use crate::{
    AWS_AUDIT_MANAGER_API_REVISION, AWS_AUDIT_MANAGER_CONTRACT_VERSION,
    AWS_AUDIT_MANAGER_PLUGIN_VERSION, AWS_AUDIT_MANAGER_PROVIDER_ID, CONTRACT_DIGEST,
    LAYER1_PERMISSIONS, MAX_CONTROL_SETS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_REPORTS, MAX_RESPONSE_BYTES, MAX_RESULT_DIGESTS,
};

pub const MAX_CONTROL_COUNT: u32 = 10_000;
pub const MAX_STATUS_FILTERS: usize = 4;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsAuditManagerError::InvalidDigest)
        }
    }

    pub const fn zero() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(&self.0) {
            Ok(())
        } else {
            Err(AwsAuditManagerError::InvalidDigest)
        }
    }
}

impl Default for Digest {
    fn default() -> Self {
        Self::zero()
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
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
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

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    Digest::from_bytes(&bytes)
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

macro_rules! opaque_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsAuditManagerError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-audit-manager-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsAuditManagerError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

opaque_text!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
opaque_text!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
opaque_text!(AssessmentId, "assessment", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
opaque_text!(FrameworkId, "framework", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
opaque_text!(ControlSetId, "control-set", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
opaque_text!(ReportId, "report", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));

pub type AssessmentArn = AssessmentId;
pub type FrameworkArn = FrameworkId;
pub type ControlSetArn = ControlSetId;
pub type AssessmentReportId = ReportId;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Existing,
    Unregistered,
    NewCustomer,
}

pub type AwsAuditManagerTenantStatus = TenantStatus;

#[derive(Clone, Eq, PartialEq)]
pub struct AssessmentIdentity {
    id: AssessmentId,
    revision: u64,
}

impl AssessmentIdentity {
    pub fn new(id: AssessmentId, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(AwsAuditManagerError::InvalidScope);
        }
        id.validate()?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &AssessmentId {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-assessment-identity/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

impl Serialize for AssessmentIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AssessmentIdentity", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

impl fmt::Debug for AssessmentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentIdentity")
            .field("id_digest", &self.id.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

macro_rules! revision_identity {
    ($name:ident, $id_type:ident, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            id: $id_type,
            revision: u64,
        }

        impl $name {
            pub fn new(id: $id_type, revision: u64) -> Result<Self> {
                if revision == 0 {
                    return Err(AwsAuditManagerError::InvalidScope);
                }
                id.validate()?;
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &$id_type {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("idDigest", &self.id.digest())?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }
    };
}

revision_identity!(
    FrameworkIdentity,
    FrameworkId,
    "aws-audit-manager-framework-identity/v1"
);
revision_identity!(
    ControlSetIdentity,
    ControlSetId,
    "aws-audit-manager-control-set-identity/v1"
);
revision_identity!(
    ReportIdentity,
    ReportId,
    "aws-audit-manager-report-identity/v1"
);

macro_rules! mission_identity {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsAuditManagerError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.clone()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AwsAuditManagerError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &Digest::from_text(&self.id))
                    .field("revision", &self.revision)
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }
    };
}

mission_identity!(MissionIdentity, "aws-audit-manager-mission/v1");
mission_identity!(ProjectIdentity, "aws-audit-manager-project/v1");
mission_identity!(WorkProductIdentity, "aws-audit-manager-work-product/v1");

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidencePeriod {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl EvidencePeriod {
    pub fn new(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        if start >= end || expires_at < end {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        Ok(Self {
            start,
            end,
            expires_at,
        })
    }

    pub fn is_expired(&self, at: DateTime<Utc>) -> bool {
        at > self.expires_at
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-evidence-period/v1",
            &[
                ("start", self.start.to_rfc3339()),
                ("end", self.end.to_rfc3339()),
                ("expires_at", self.expires_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentStatus {
    Active,
    Inactive,
    UnderReview,
    Unknown,
}

pub type AuditManagerAssessmentStatus = AssessmentStatus;

impl AssessmentStatus {
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportStatus {
    Complete,
    InProgress,
    Failed,
    Unknown,
}

pub type AuditManagerReportStatus = ReportStatus;

impl ReportStatus {
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatusFilter {
    All,
    Active,
    Inactive,
}

impl AssessmentStatusFilter {
    pub const fn accepts(self, status: AssessmentStatus) -> bool {
        match self {
            Self::All => true,
            Self::Active => matches!(status, AssessmentStatus::Active),
            Self::Inactive => matches!(status, AssessmentStatus::Inactive),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatusFilter {
    All,
    Complete,
    InProgress,
    Failed,
}

impl ReportStatusFilter {
    pub const fn accepts(self, status: ReportStatus) -> bool {
        match self {
            Self::All => true,
            Self::Complete => matches!(status, ReportStatus::Complete),
            Self::InProgress => matches!(status, ReportStatus::InProgress),
            Self::Failed => matches!(status, ReportStatus::Failed),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if revision == 0
            || permissions.is_empty()
            || permissions.len() > 16
            || permissions
                .iter()
                .any(|permission| !valid_identifier(permission, 128))
        {
            return Err(AwsAuditManagerError::InvalidPermissionSnapshot);
        }
        let permission_digest = Digest::from_parts(
            "aws-audit-manager-permission-snapshot/v1",
            &permissions
                .iter()
                .map(|permission| ("permission", permission.clone()))
                .chain(std::iter::once(("revision", revision.to_string())))
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            revision,
            permissions,
            permission_digest,
        })
    }

    pub fn for_existing_tenant(revision: u64) -> Result<Self> {
        Self::new(revision, LAYER1_PERMISSIONS)
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn permits(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.revision, self.permissions.clone())?;
        if expected.permission_digest != self.permission_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new(id: impl Into<String>, revision: u64, expires_at: DateTime<Utc>) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsAuditManagerError::InvalidConsent);
        }
        Ok(Self {
            id,
            revision,
            expires_at,
            revoked: false,
        })
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, expires_at)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-consent/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) || self.revision == 0 {
            return Err(AwsAuditManagerError::InvalidConsent);
        }
        if self.revoked {
            return Err(AwsAuditManagerError::ConsentRevoked);
        }
        if now > self.expires_at {
            return Err(AwsAuditManagerError::ConsentExpired);
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for ConsentScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConsentScope", 4)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

/// An opaque credential-store handle.  The supplied handle is hashed and
/// zeroized immediately; it is intentionally neither serializable nor
/// deserializable.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsAuditManagerError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-audit-manager-sigv4-reference/v1",
            &[
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest: Digest::from_text("unbound-audit-manager-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsAuditManagerScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-audit-manager-sigv4-reference-bound/v1",
            &[
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate_for(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        if self.revoked || self.revision == 0 || self.scope_digest != scope.digest() {
            return Err(AwsAuditManagerError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsAuditManagerScope {
    account: AwsAccountId,
    region: AwsRegion,
    assessment: AssessmentIdentity,
    framework: FrameworkIdentity,
    control_set: ControlSetIdentity,
    report: ReportIdentity,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
    tenant_status: TenantStatus,
    scope_digest: Digest,
}

impl AwsAuditManagerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        assessment: AssessmentIdentity,
        framework: FrameworkIdentity,
        control_set: ControlSetIdentity,
        report: ReportIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        Self::with_tenant_status(
            account,
            region,
            assessment,
            framework,
            control_set,
            report,
            mission,
            project,
            work_product,
            TenantStatus::Existing,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_tenant_status(
        account: AwsAccountId,
        region: AwsRegion,
        assessment: AssessmentIdentity,
        framework: FrameworkIdentity,
        control_set: ControlSetIdentity,
        report: ReportIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        tenant_status: TenantStatus,
    ) -> Result<Self> {
        account.validate()?;
        region.validate()?;
        let mut scope = Self {
            account,
            region,
            assessment,
            framework,
            control_set,
            report,
            mission,
            project,
            work_product,
            tenant_status,
            scope_digest: Digest::zero(),
        };
        scope.validate()?;
        scope.scope_digest = scope.recompute_digest();
        Ok(scope)
    }

    pub fn for_existing_tenant(
        account: AwsAccountId,
        region: AwsRegion,
        assessment: AssessmentIdentity,
        framework: FrameworkIdentity,
        control_set: ControlSetIdentity,
        report: ReportIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        Self::new(
            account,
            region,
            assessment,
            framework,
            control_set,
            report,
            mission,
            project,
            work_product,
        )
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn account_id(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn assessment(&self) -> &AssessmentIdentity {
        &self.assessment
    }

    pub fn framework(&self) -> &FrameworkIdentity {
        &self.framework
    }

    pub fn control_set(&self) -> &ControlSetIdentity {
        &self.control_set
    }

    pub fn report(&self) -> &ReportIdentity {
        &self.report
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub const fn tenant_status(&self) -> TenantStatus {
        self.tenant_status
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.assessment.id().validate()?;
        self.framework.id().validate()?;
        self.control_set.id().validate()?;
        self.report.id().validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if self.scope_digest != Digest::zero() && self.scope_digest != self.recompute_digest() {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-scope/v1",
            &[
                ("account", self.account.as_str().to_owned()),
                ("region", self.region.as_str().to_owned()),
                ("tenant", format!("{:?}", self.tenant_status)),
                ("assessment", self.assessment.digest().as_str().to_owned()),
                ("framework", self.framework.digest().as_str().to_owned()),
                ("control_set", self.control_set.digest().as_str().to_owned()),
                ("report", self.report.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }
}

impl fmt::Debug for AwsAuditManagerScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAuditManagerScope")
            .field("account_digest", &self.account.digest())
            .field("region_digest", &self.region.digest())
            .field("assessment", &self.assessment)
            .field("framework", &self.framework)
            .field("control_set", &self.control_set)
            .field("report", &self.report)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("tenant_status", &self.tenant_status)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl Serialize for AwsAuditManagerScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAuditManagerScope", 10)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("assessment", &self.assessment)?;
        state.serialize_field("framework", &self.framework)?;
        state.serialize_field("controlSet", &self.control_set)?;
        state.serialize_field("report", &self.report)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("tenantStatus", &self.tenant_status)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    page: u16,
}

pub type Cursor = OpaqueCursor;
pub type OpaquePageToken = OpaqueCursor;

impl OpaqueCursor {
    pub fn new(token: impl AsRef<str>) -> Result<Self> {
        let token = token.as_ref();
        if !valid_text(token, MAX_IDENTIFIER_BYTES * 4, false) {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        Ok(Self {
            token_digest: Digest::from_text(token),
            binding_digest: None,
            page: 1,
        })
    }

    pub fn for_request(token: impl AsRef<str>, request_digest: Digest, page: u16) -> Result<Self> {
        if page == 0 {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        let mut cursor = Self::new(token)?;
        cursor.binding_digest = Some(request_digest);
        cursor.page = page;
        Ok(cursor)
    }

    pub fn bound(request_digest: Digest, page: u16) -> Self {
        Self {
            token_digest: Digest::from_parts(
                "aws-audit-manager-cursor-token/v1",
                &[
                    ("request", request_digest.as_str().to_owned()),
                    ("page", page.to_string()),
                ],
            ),
            binding_digest: Some(request_digest),
            page,
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-cursor/v1",
            &[
                ("token", self.token_digest.as_str().to_owned()),
                (
                    "binding",
                    self.binding_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("page", self.page.to_string()),
            ],
        )
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn page(&self) -> u16 {
        self.page
    }

    fn validate_for(&self, request_digest: &Digest) -> Result<()> {
        if self.page == 0
            || self
                .binding_digest
                .as_ref()
                .is_some_and(|binding| binding != request_digest)
        {
            return Err(AwsAuditManagerError::CursorMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page", &self.page)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaqueCursor", 3)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("page", &self.page)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssessmentsRequest {
    pub scope_digest: Digest,
    pub status_filter: AssessmentStatusFilter,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub request_digest: Digest,
}

impl ListAssessmentsRequest {
    pub fn new(
        scope: &AwsAuditManagerScope,
        status_filter: AssessmentStatusFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        let scope_digest = scope.digest();
        let binding_digest = request_digest(
            "aws-audit-manager-list-assessments-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("status", format!("{status_filter:?}")),
                ("page_size", page_size.to_string()),
                ("max_pages", max_pages.to_string()),
            ],
        );
        if let Some(cursor) = &cursor {
            cursor.validate_for(&binding_digest)?;
        }
        let request_digest = if cursor.is_none() {
            binding_digest.clone()
        } else {
            request_digest(
                "aws-audit-manager-list-assessments-request-bound/v1",
                &[
                    ("binding", binding_digest.as_str().to_owned()),
                    ("cursor", cursor_digest(cursor.as_ref())),
                ],
            )
        };
        Ok(Self {
            scope_digest,
            status_filter,
            page_size,
            max_pages,
            cursor,
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsAuditManagerScope) -> Result<Self> {
        Self::new(
            scope,
            AssessmentStatusFilter::All,
            MAX_PAGE_SIZE,
            MAX_PAGES,
            None,
        )
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        Self::new(
            &scope_from_digest(&self.scope_digest),
            self.status_filter,
            self.page_size,
            self.max_pages,
            cursor,
        )
    }

    pub fn validate_against(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(AwsAuditManagerError::ScopeMismatch);
        }
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
        {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        if let Some(cursor) = &self.cursor {
            if cursor
                .binding_digest()
                .is_some_and(|binding| binding != &self.binding_digest())
            {
                return Err(AwsAuditManagerError::CursorMismatch);
            }
        }
        if self.recomputed_digest() != self.request_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        let binding_digest = self.binding_digest();
        if self.cursor.is_none() {
            binding_digest
        } else {
            request_digest(
                "aws-audit-manager-list-assessments-request-bound/v1",
                &[
                    ("binding", binding_digest.as_str().to_owned()),
                    ("cursor", cursor_digest(self.cursor.as_ref())),
                ],
            )
        }
    }

    pub(crate) fn binding_digest(&self) -> Digest {
        request_digest(
            "aws-audit-manager-list-assessments-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status_filter)),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssessmentRequest {
    pub scope_digest: Digest,
    pub assessment_digest: Digest,
    pub request_digest: Digest,
}

impl GetAssessmentRequest {
    pub fn new(scope: &AwsAuditManagerScope) -> Result<Self> {
        let scope_digest = scope.digest();
        let assessment_digest = scope.assessment().digest();
        let request_digest = request_digest(
            "aws-audit-manager-get-assessment-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("assessment", assessment_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope_digest,
            assessment_digest,
            request_digest,
        })
    }

    pub fn validate_against(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        let expected = Self::new(scope)?;
        if self != &expected {
            return Err(AwsAuditManagerError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssessmentReportsRequest {
    pub scope_digest: Digest,
    pub status_filter: ReportStatusFilter,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub request_digest: Digest,
}

impl ListAssessmentReportsRequest {
    pub fn new(
        scope: &AwsAuditManagerScope,
        status_filter: ReportStatusFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        let scope_digest = scope.digest();
        let binding_digest = request_digest(
            "aws-audit-manager-list-assessment-reports-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("status", format!("{status_filter:?}")),
                ("page_size", page_size.to_string()),
                ("max_pages", max_pages.to_string()),
            ],
        );
        if let Some(cursor) = &cursor {
            cursor.validate_for(&binding_digest)?;
        }
        let request_digest = if cursor.is_none() {
            binding_digest.clone()
        } else {
            request_digest(
                "aws-audit-manager-list-assessment-reports-request-bound/v1",
                &[
                    ("binding", binding_digest.as_str().to_owned()),
                    ("cursor", cursor_digest(cursor.as_ref())),
                ],
            )
        };
        Ok(Self {
            scope_digest,
            status_filter,
            page_size,
            max_pages,
            cursor,
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsAuditManagerScope) -> Result<Self> {
        Self::new(
            scope,
            ReportStatusFilter::All,
            MAX_PAGE_SIZE,
            MAX_PAGES,
            None,
        )
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        let scope = scope_from_digest(&self.scope_digest);
        Self::new(
            &scope,
            self.status_filter,
            self.page_size,
            self.max_pages,
            cursor,
        )
    }

    pub fn validate_against(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(AwsAuditManagerError::ScopeMismatch);
        }
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
        {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        if let Some(cursor) = &self.cursor {
            if cursor
                .binding_digest()
                .is_some_and(|binding| binding != &self.binding_digest())
            {
                return Err(AwsAuditManagerError::CursorMismatch);
            }
        }
        if self.recomputed_digest() != self.request_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        let binding_digest = self.binding_digest();
        if self.cursor.is_none() {
            binding_digest
        } else {
            request_digest(
                "aws-audit-manager-list-assessment-reports-request-bound/v1",
                &[
                    ("binding", binding_digest.as_str().to_owned()),
                    ("cursor", cursor_digest(self.cursor.as_ref())),
                ],
            )
        }
    }

    pub(crate) fn binding_digest(&self) -> Digest {
        request_digest(
            "aws-audit-manager-list-assessment-reports-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status_filter)),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAuditManagerEvidenceRequest {
    pub list_assessments: ListAssessmentsRequest,
    pub get_assessment: GetAssessmentRequest,
    pub list_assessment_reports: ListAssessmentReportsRequest,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

pub type AuditManagerEvidenceRequest = AwsAuditManagerEvidenceRequest;

impl AwsAuditManagerEvidenceRequest {
    pub fn new(
        scope: &AwsAuditManagerScope,
        assessment_status: AssessmentStatusFilter,
        report_status: ReportStatusFilter,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let list_assessments =
            ListAssessmentsRequest::new(scope, assessment_status, page_size, max_pages, None)?;
        let get_assessment = GetAssessmentRequest::new(scope)?;
        let list_assessment_reports =
            ListAssessmentReportsRequest::new(scope, report_status, page_size, max_pages, None)?;
        let request_digest = request_digest(
            "aws-audit-manager-evidence-request/v1",
            &[
                ("list", list_assessments.request_digest.as_str().to_owned()),
                ("get", get_assessment.request_digest.as_str().to_owned()),
                (
                    "reports",
                    list_assessment_reports.request_digest.as_str().to_owned(),
                ),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            list_assessments,
            get_assessment,
            list_assessment_reports,
            observed_at,
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsAuditManagerScope, observed_at: DateTime<Utc>) -> Result<Self> {
        Self::new(
            scope,
            AssessmentStatusFilter::All,
            ReportStatusFilter::All,
            MAX_PAGE_SIZE,
            MAX_PAGES,
            observed_at,
        )
    }

    pub fn validate_against(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        self.list_assessments.validate_against(scope)?;
        self.get_assessment.validate_against(scope)?;
        self.list_assessment_reports.validate_against(scope)?;
        if self.recomputed_digest() != self.request_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        request_digest(
            "aws-audit-manager-evidence-request/v1",
            &[
                (
                    "list",
                    self.list_assessments.request_digest.as_str().to_owned(),
                ),
                (
                    "get",
                    self.get_assessment.request_digest.as_str().to_owned(),
                ),
                (
                    "reports",
                    self.list_assessment_reports
                        .request_digest
                        .as_str()
                        .to_owned(),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentSummaryInput {
    pub assessment: AssessmentIdentity,
    pub status: AssessmentStatus,
    pub framework: FrameworkIdentity,
    pub control_set: ControlSetIdentity,
    pub evidence_period: EvidencePeriod,
    pub control_result_digest: Digest,
    pub observed_at: DateTime<Utc>,
}

impl AssessmentSummaryInput {
    pub fn new(
        assessment: AssessmentIdentity,
        status: AssessmentStatus,
        framework: FrameworkIdentity,
        control_set: ControlSetIdentity,
        evidence_period: EvidencePeriod,
        control_result_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        control_result_digest.validate()?;
        Ok(Self {
            assessment,
            status,
            framework,
            control_set,
            evidence_period,
            control_result_digest,
            observed_at,
        })
    }

    /// Accept provider-only metadata and immediately discard it.  This keeps
    /// fixtures useful for redaction tests without giving the public model a
    /// field in which PII or an ARN could survive.
    pub fn with_provider_metadata(
        self,
        assessment_name: Option<String>,
        account_email: Option<String>,
        role_arn: Option<String>,
    ) -> Self {
        drop((assessment_name, account_email, role_arn));
        self
    }

    pub fn from_raw_evidence(
        assessment: AssessmentIdentity,
        status: AssessmentStatus,
        framework: FrameworkIdentity,
        control_set: ControlSetIdentity,
        evidence_period: EvidencePeriod,
        raw_evidence: impl AsRef<[u8]>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let control_result_digest = Digest::from_bytes(raw_evidence.as_ref());
        Self::new(
            assessment,
            status,
            framework,
            control_set,
            evidence_period,
            control_result_digest,
            observed_at,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentSummary {
    pub assessment: AssessmentIdentity,
    pub status: AssessmentStatus,
    pub framework: FrameworkIdentity,
    pub control_set: ControlSetIdentity,
    pub evidence_period: EvidencePeriod,
    pub control_result_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub assessment_digest: Digest,
}

impl AssessmentSummary {
    pub fn new(scope: &AwsAuditManagerScope, input: AssessmentSummaryInput) -> Result<Self> {
        input.assessment.id().validate()?;
        input.framework.id().validate()?;
        input.control_set.id().validate()?;
        input.control_result_digest.validate()?;
        let mut value = Self {
            assessment: input.assessment,
            status: input.status,
            framework: input.framework,
            control_set: input.control_set,
            evidence_period: input.evidence_period,
            control_result_digest: input.control_result_digest,
            observed_at: input.observed_at,
            assessment_digest: Digest::zero(),
        };
        value.assessment_digest = value.recompute_digest(scope);
        Ok(value)
    }

    pub fn for_scope(
        scope: &AwsAuditManagerScope,
        status: AssessmentStatus,
        evidence_period: EvidencePeriod,
        control_result_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            scope,
            AssessmentSummaryInput::new(
                scope.assessment.clone(),
                status,
                scope.framework.clone(),
                scope.control_set.clone(),
                evidence_period,
                control_result_digest,
                observed_at,
            )?,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.assessment_digest
    }

    fn recompute_digest(&self, scope: &AwsAuditManagerScope) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-assessment-summary/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("assessment", self.assessment.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("framework", self.framework.digest().as_str().to_owned()),
                ("control_set", self.control_set.digest().as_str().to_owned()),
                ("period", self.evidence_period.digest().as_str().to_owned()),
                (
                    "control_result",
                    self.control_result_digest.as_str().to_owned(),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        self.assessment.id().validate()?;
        self.framework.id().validate()?;
        self.control_set.id().validate()?;
        self.control_result_digest.validate()?;
        if self.assessment_digest != self.recompute_digest(scope) {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlSetSummary {
    pub control_set: ControlSetIdentity,
    pub control_count: u32,
    pub control_result_digest: Digest,
    pub control_set_digest: Digest,
}

impl ControlSetSummary {
    pub fn new(
        scope: &AwsAuditManagerScope,
        control_set: ControlSetIdentity,
        control_count: u32,
        control_result_digest: Digest,
    ) -> Result<Self> {
        if control_count > MAX_CONTROL_COUNT {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        control_result_digest.validate()?;
        let control_set_digest = Digest::from_parts(
            "aws-audit-manager-control-set-summary/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("control_set", control_set.digest().as_str().to_owned()),
                ("control_count", control_count.to_string()),
                ("results", control_result_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            control_set,
            control_count,
            control_result_digest,
            control_set_digest,
        })
    }

    pub(crate) fn validate(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        if self.control_count > MAX_CONTROL_COUNT {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        self.control_set.id().validate()?;
        self.control_result_digest.validate()?;
        let expected = Self::new(
            scope,
            self.control_set.clone(),
            self.control_count,
            self.control_result_digest.clone(),
        )?;
        if expected.control_set_digest != self.control_set_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentDetail {
    pub summary: AssessmentSummary,
    pub control_sets: Vec<ControlSetSummary>,
    pub assessment_detail_digest: Digest,
}

impl AssessmentDetail {
    pub fn new(
        scope: &AwsAuditManagerScope,
        summary: AssessmentSummary,
        control_sets: Vec<ControlSetSummary>,
    ) -> Result<Self> {
        summary.validate(scope)?;
        if control_sets.is_empty() || control_sets.len() > MAX_CONTROL_SETS {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        if control_sets
            .iter()
            .any(|control_set| control_set.control_set.id() != scope.control_set.id())
        {
            return Err(AwsAuditManagerError::ControlSetReplaced);
        }
        let assessment_detail_digest = Digest::from_parts(
            "aws-audit-manager-assessment-detail/v1",
            &[
                ("summary", summary.digest().as_str().to_owned()),
                (
                    "control_sets",
                    control_sets
                        .iter()
                        .map(|value| value.control_set_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Ok(Self {
            summary,
            control_sets,
            assessment_detail_digest,
        })
    }

    pub(crate) fn validate(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        self.summary.validate(scope)?;
        if self.control_sets.is_empty() || self.control_sets.len() > MAX_CONTROL_SETS {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        for control_set in &self.control_sets {
            control_set.validate(scope)?;
            if control_set.control_set.id() != scope.control_set().id()
                || control_set.control_set.revision() != scope.control_set().revision()
            {
                return Err(AwsAuditManagerError::ControlSetReplaced);
            }
        }
        let expected = Self::new(scope, self.summary.clone(), self.control_sets.clone())?;
        if expected.assessment_detail_digest != self.assessment_detail_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentReportInput {
    pub report: ReportIdentity,
    pub status: ReportStatus,
    pub assessment: AssessmentIdentity,
    pub evidence_period: EvidencePeriod,
    pub report_digest: Digest,
    pub generated_at: DateTime<Utc>,
}

impl AssessmentReportInput {
    pub fn new(
        report: ReportIdentity,
        status: ReportStatus,
        assessment: AssessmentIdentity,
        evidence_period: EvidencePeriod,
        report_digest: Digest,
        generated_at: DateTime<Utc>,
    ) -> Result<Self> {
        report_digest.validate()?;
        Ok(Self {
            report,
            status,
            assessment,
            evidence_period,
            report_digest,
            generated_at,
        })
    }

    pub fn from_report_bytes(
        report: ReportIdentity,
        status: ReportStatus,
        assessment: AssessmentIdentity,
        evidence_period: EvidencePeriod,
        report_bytes: impl AsRef<[u8]>,
        generated_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            report,
            status,
            assessment,
            evidence_period,
            Digest::from_bytes(report_bytes.as_ref()),
            generated_at,
        )
    }

    pub fn with_provider_metadata(
        self,
        report_name: Option<String>,
        account_email: Option<String>,
        role_arn: Option<String>,
    ) -> Self {
        drop((report_name, account_email, role_arn));
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentReportSummary {
    pub report: ReportIdentity,
    pub status: ReportStatus,
    pub assessment: AssessmentIdentity,
    pub evidence_period: EvidencePeriod,
    pub report_digest: Digest,
    pub generated_at: DateTime<Utc>,
    pub report_summary_digest: Digest,
}

impl AssessmentReportSummary {
    pub fn new(scope: &AwsAuditManagerScope, input: AssessmentReportInput) -> Result<Self> {
        input.report.id().validate()?;
        input.assessment.id().validate()?;
        input.report_digest.validate()?;
        let report_summary_digest = Digest::from_parts(
            "aws-audit-manager-report-summary/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("report", input.report.digest().as_str().to_owned()),
                ("status", format!("{:?}", input.status)),
                ("assessment", input.assessment.digest().as_str().to_owned()),
                ("period", input.evidence_period.digest().as_str().to_owned()),
                ("report_digest", input.report_digest.as_str().to_owned()),
                ("generated_at", input.generated_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            report: input.report,
            status: input.status,
            assessment: input.assessment,
            evidence_period: input.evidence_period,
            report_digest: input.report_digest,
            generated_at: input.generated_at,
            report_summary_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.report_summary_digest
    }

    pub(crate) fn validate(&self, scope: &AwsAuditManagerScope) -> Result<()> {
        if self.report.id().as_str().is_empty() || self.assessment.id().as_str().is_empty() {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        let expected = Self::new(
            scope,
            AssessmentReportInput::new(
                self.report.clone(),
                self.status,
                self.assessment.clone(),
                self.evidence_period.clone(),
                self.report_digest.clone(),
                self.generated_at,
            )?,
        )?;
        if expected.report_summary_digest != self.report_summary_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderFailure {
    pub operation: AuditManagerOperation,
    pub category: String,
    pub status_code: Option<u16>,
    pub retryable: bool,
}

impl ProviderFailure {
    pub fn from_transport(
        operation: AuditManagerOperation,
        error: &crate::error::AwsAuditManagerTransportError,
    ) -> Self {
        Self {
            operation,
            category: error.category().to_owned(),
            status_code: error.status_code(),
            retryable: matches!(
                error,
                crate::error::AwsAuditManagerTransportError::RateLimited { .. }
                    | crate::error::AwsAuditManagerTransportError::ServerError { .. }
                    | crate::error::AwsAuditManagerTransportError::Timeout
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AuditManagerOperation {
    ListAssessments,
    GetAssessment,
    ListAssessmentReports,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

pub type TransportProvenance = ProviderProvenance;

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn provider_receipt(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditManagerEvidenceState {
    Complete,
    InProgress,
    Partial,
    Expired,
    AccessLoss,
    NotFound,
    Throttled,
    ProviderUnknown,
    UnregisteredAccount,
    AssessmentDrift,
    FrameworkDrift,
    ControlSetDrift,
    ReportDrift,
    RegistrationRevoked,
}

pub type EvidenceState = AuditManagerEvidenceState;

impl AuditManagerEvidenceState {
    pub const fn is_adoptable(&self) -> bool {
        false
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditManagerEvidence {
    pub state: AuditManagerEvidenceState,
    pub assessment_status: Option<AssessmentStatus>,
    pub report_status: Option<ReportStatus>,
    pub assessment_revision: u64,
    pub framework_revision: u64,
    pub control_set_revision: u64,
    pub report_revision: u64,
    pub evidence_period: Option<EvidencePeriod>,
    pub list_digest: Digest,
    pub assessment_digest: Digest,
    pub control_result_digest: Digest,
    pub report_digest: Digest,
    pub evidence_digest: Digest,
    pub list_pages: u16,
    pub report_pages: u16,
    pub pagination_complete: bool,
    pub provenance: ProviderProvenance,
    pub failure: Option<ProviderFailure>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AuditManagerEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: AuditManagerEvidenceState,
        assessment_status: Option<AssessmentStatus>,
        report_status: Option<ReportStatus>,
        assessment_revision: u64,
        framework_revision: u64,
        control_set_revision: u64,
        report_revision: u64,
        evidence_period: Option<EvidencePeriod>,
        list_digest: Digest,
        assessment_digest: Digest,
        control_result_digest: Digest,
        report_digest: Digest,
        list_pages: u16,
        report_pages: u16,
        pagination_complete: bool,
        provenance: ProviderProvenance,
        failure: Option<ProviderFailure>,
    ) -> Result<Self> {
        for digest in [
            &list_digest,
            &assessment_digest,
            &control_result_digest,
            &report_digest,
        ] {
            digest.validate()?;
        }
        let mut evidence = Self {
            state,
            assessment_status,
            report_status,
            assessment_revision,
            framework_revision,
            control_set_revision,
            report_revision,
            evidence_period,
            list_digest,
            assessment_digest,
            control_result_digest,
            report_digest,
            evidence_digest: Digest::zero(),
            list_pages,
            report_pages,
            pagination_complete,
            provenance,
            failure,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        evidence.evidence_digest = evidence.recompute_digest();
        Ok(evidence)
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.evidence_digest != self.recompute_digest()
        {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        for digest in [
            &self.list_digest,
            &self.assessment_digest,
            &self.control_result_digest,
            &self.report_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                (
                    "assessment_status",
                    self.assessment_status
                        .map_or_else(String::new, |status| format!("{status:?}")),
                ),
                (
                    "report_status",
                    self.report_status
                        .map_or_else(String::new, |status| format!("{status:?}")),
                ),
                ("assessment_revision", self.assessment_revision.to_string()),
                ("framework_revision", self.framework_revision.to_string()),
                (
                    "control_set_revision",
                    self.control_set_revision.to_string(),
                ),
                ("report_revision", self.report_revision.to_string()),
                (
                    "period",
                    self.evidence_period
                        .as_ref()
                        .map_or_else(String::new, |period| period.digest().as_str().to_owned()),
                ),
                ("list", self.list_digest.as_str().to_owned()),
                ("assessment", self.assessment_digest.as_str().to_owned()),
                (
                    "control_result",
                    self.control_result_digest.as_str().to_owned(),
                ),
                ("report", self.report_digest.as_str().to_owned()),
                ("list_pages", self.list_pages.to_string()),
                ("report_pages", self.report_pages.to_string()),
                ("pagination_complete", self.pagination_complete.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |failure| {
                        format!(
                            "{}:{}:{:?}",
                            failure.operation as u8, failure.category, failure.status_code
                        )
                    }),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssessmentsResponse {
    pub request_digest: Digest,
    pub assessments: Vec<AssessmentSummary>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub page_digest: Digest,
    pub provenance: ProviderProvenance,
}

impl ListAssessmentsResponse {
    pub fn new(
        request: &ListAssessmentsRequest,
        assessments: Vec<AssessmentSummary>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if assessments.len() > request.page_size as usize || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsAuditManagerError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            if cursor.binding_digest() != Some(&request.binding_digest())
                || cursor.page() != request.cursor.as_ref().map_or(1, OpaqueCursor::page) + 1
            {
                return Err(AwsAuditManagerError::CursorMismatch);
            }
        }
        let page_digest = Digest::from_parts(
            "aws-audit-manager-list-assessments-page/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                (
                    "items",
                    assessments
                        .iter()
                        .map(|assessment| assessment.digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("bytes", response_bytes.to_string()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            assessments,
            next_cursor,
            response_bytes,
            page_digest,
            provenance,
        })
    }

    pub(crate) fn validate(&self, request: &ListAssessmentsRequest) -> Result<()> {
        let scope = scope_from_digest(&request.scope_digest);
        request.validate_against(&scope)?;
        if self.request_digest != request.request_digest
            || self.assessments.len() > request.page_size as usize
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        for assessment in &self.assessments {
            assessment.validate(&scope)?;
        }
        if let Some(cursor) = &self.next_cursor {
            if cursor.binding_digest() != Some(&request.binding_digest()) {
                return Err(AwsAuditManagerError::CursorMismatch);
            }
        }
        let expected_page_digest = Digest::from_parts(
            "aws-audit-manager-list-assessments-page/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                (
                    "items",
                    self.assessments
                        .iter()
                        .map(|assessment| assessment.digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("bytes", self.response_bytes.to_string()),
            ],
        );
        if expected_page_digest != self.page_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssessmentResponse {
    pub request_digest: Digest,
    pub assessment: AssessmentDetail,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub provenance: ProviderProvenance,
}

impl GetAssessmentResponse {
    pub fn new(
        request: &GetAssessmentRequest,
        assessment: AssessmentDetail,
        response_bytes: u64,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsAuditManagerError::PartialEvidence);
        }
        let response_digest = Digest::from_parts(
            "aws-audit-manager-get-assessment-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                (
                    "assessment",
                    assessment.assessment_detail_digest.as_str().to_owned(),
                ),
                ("bytes", response_bytes.to_string()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            assessment,
            response_bytes,
            response_digest,
            provenance,
        })
    }

    pub(crate) fn validate(&self, request: &GetAssessmentRequest) -> Result<()> {
        if self.request_digest != request.request_digest || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        let expected_response_digest = Digest::from_parts(
            "aws-audit-manager-get-assessment-response/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                (
                    "assessment",
                    self.assessment.assessment_detail_digest.as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
            ],
        );
        if expected_response_digest != self.response_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssessmentReportsResponse {
    pub request_digest: Digest,
    pub reports: Vec<AssessmentReportSummary>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub page_digest: Digest,
    pub provenance: ProviderProvenance,
}

impl ListAssessmentReportsResponse {
    pub fn new(
        request: &ListAssessmentReportsRequest,
        reports: Vec<AssessmentReportSummary>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if reports.len() > request.page_size as usize
            || reports.len() > MAX_REPORTS
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsAuditManagerError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            if cursor.binding_digest() != Some(&request.binding_digest())
                || cursor.page() != request.cursor.as_ref().map_or(1, OpaqueCursor::page) + 1
            {
                return Err(AwsAuditManagerError::CursorMismatch);
            }
        }
        let page_digest = Digest::from_parts(
            "aws-audit-manager-list-assessment-reports-page/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                (
                    "items",
                    reports
                        .iter()
                        .map(|report| report.digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("bytes", response_bytes.to_string()),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            reports,
            next_cursor,
            response_bytes,
            page_digest,
            provenance,
        })
    }

    pub(crate) fn validate(&self, request: &ListAssessmentReportsRequest) -> Result<()> {
        if self.request_digest != request.request_digest
            || self.reports.len() > request.page_size as usize
            || self.reports.len() > MAX_REPORTS
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            if cursor.binding_digest() != Some(&request.binding_digest()) {
                return Err(AwsAuditManagerError::CursorMismatch);
            }
        }
        let scope = scope_from_digest(&request.scope_digest);
        for report in &self.reports {
            report.validate(&scope)?;
        }
        let expected_page_digest = Digest::from_parts(
            "aws-audit-manager-list-assessment-reports-page/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                (
                    "items",
                    self.reports
                        .iter()
                        .map(|report| report.digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("bytes", self.response_bytes.to_string()),
            ],
        );
        if expected_page_digest != self.page_digest {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderReadEvidence {
    pub operation: AuditManagerOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub page_digest: Option<Digest>,
    pub provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "operation", content = "response")]
pub enum AwsAuditManagerReadResult {
    ListAssessments(ListAssessmentsResponse),
    GetAssessment(GetAssessmentResponse),
    ListAssessmentReports(ListAssessmentReportsResponse),
}

impl AwsAuditManagerReadResult {
    pub const fn operation(&self) -> AuditManagerOperation {
        match self {
            Self::ListAssessments(_) => AuditManagerOperation::ListAssessments,
            Self::GetAssessment(_) => AuditManagerOperation::GetAssessment,
            Self::ListAssessmentReports(_) => AuditManagerOperation::ListAssessmentReports,
        }
    }
}

fn request_digest(domain: &str, fields: &[(&str, String)]) -> Digest {
    Digest::from_parts(domain, fields)
}

fn cursor_digest(cursor: Option<&OpaqueCursor>) -> String {
    cursor.map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned())
}

// A request contains only a digest, so this helper is used for the ergonomic
// `with_cursor` API.  The service never uses it to authorize a request; it
// validates against its real scope before any provider call.
pub(crate) fn scope_from_digest(scope_digest: &Digest) -> AwsAuditManagerScope {
    let account = AwsAccountId::new("000000000000").expect("static account");
    let region = AwsRegion::new("invalid-placeholder").expect("static region");
    let assessment = AssessmentIdentity::new(
        AssessmentId::new("placeholder-assessment").expect("static assessment"),
        1,
    )
    .expect("static assessment identity");
    let framework = FrameworkIdentity::new(
        FrameworkId::new("placeholder-framework").expect("static framework"),
        1,
    )
    .expect("static framework identity");
    let control_set = ControlSetIdentity::new(
        ControlSetId::new("placeholder-control-set").expect("static control set"),
        1,
    )
    .expect("static control set identity");
    let report = ReportIdentity::new(
        ReportId::new("placeholder-report").expect("static report"),
        1,
    )
    .expect("static report identity");
    let mission = MissionIdentity::new("placeholder-mission", 1).expect("static mission");
    let project = ProjectIdentity::new("placeholder-project", 1).expect("static project");
    let work_product =
        WorkProductIdentity::new("placeholder-work-product", 1).expect("static work product");
    let mut scope = AwsAuditManagerScope::with_tenant_status(
        account,
        region,
        assessment,
        framework,
        control_set,
        report,
        mission,
        project,
        work_product,
        TenantStatus::Existing,
    )
    .expect("static scope");
    scope.scope_digest = scope_digest.clone();
    scope
}

pub(crate) fn expected_registration_digest(
    id: &str,
    scope: &AwsAuditManagerScope,
    secret: &SecretReference,
    permission: &PermissionSnapshot,
    consent: &ConsentScope,
    provider_digest: &Digest,
    evidence_binding: &Digest,
    revision: u64,
    status: &str,
) -> Digest {
    Digest::from_parts(
        "aws-audit-manager-registration/v1",
        &[
            ("id", id.to_owned()),
            ("plugin", AWS_AUDIT_MANAGER_PLUGIN_VERSION.to_owned()),
            ("contract", AWS_AUDIT_MANAGER_CONTRACT_VERSION.to_owned()),
            ("contract_digest", CONTRACT_DIGEST.to_owned()),
            ("provider", AWS_AUDIT_MANAGER_PROVIDER_ID.to_owned()),
            (
                "provider_revision",
                AWS_AUDIT_MANAGER_API_REVISION.to_owned(),
            ),
            ("provider_digest", provider_digest.as_str().to_owned()),
            ("permission", permission.digest().as_str().to_owned()),
            ("consent", consent.digest().as_str().to_owned()),
            ("scope", scope.digest().as_str().to_owned()),
            (
                "assessment",
                scope.assessment().digest().as_str().to_owned(),
            ),
            ("framework", scope.framework().digest().as_str().to_owned()),
            (
                "control_set",
                scope.control_set().digest().as_str().to_owned(),
            ),
            ("report", scope.report().digest().as_str().to_owned()),
            ("mission", scope.mission().digest().as_str().to_owned()),
            ("project", scope.project().digest().as_str().to_owned()),
            (
                "work_product",
                scope.work_product().digest().as_str().to_owned(),
            ),
            ("secret", secret.reference_digest().as_str().to_owned()),
            ("evidence", evidence_binding.as_str().to_owned()),
            ("revision", revision.to_string()),
            ("status", status.to_owned()),
        ],
    )
}

pub(crate) fn evidence_binding_digest(
    scope: &AwsAuditManagerScope,
    provider_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "aws-audit-manager-evidence-binding/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            ("provider", provider_digest.as_str().to_owned()),
            ("api", AWS_AUDIT_MANAGER_API_REVISION.to_owned()),
            ("result_digests", MAX_RESULT_DIGESTS.to_string()),
        ],
    )
}
