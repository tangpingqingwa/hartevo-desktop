//! Typed Snyk identities, exact scope, opaque credentials, and allowlisted
//! redacted evidence.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    MAX_IDENTIFIER_BYTES, MAX_TEXT_BYTES, Result, SnykSecurityResultError, digest_serialized,
    sha256_hex, validate_digest, validate_identifier, validate_text,
};

/// A SHA-256 digest used as a safe binding, never as a container for a raw
/// provider payload or secret.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_hex(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(value.as_ref()))
    }

    pub(crate) fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub(crate) fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(64 + values.len() * 24);
        canonical.push_str(label);
        for (name, value) in values {
            canonical.push('|');
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
        }
        Self::from_text(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
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
        formatter.write_str(&self.0)
    }
}

macro_rules! define_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $field)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

define_identifier!(RegionId, "regionId");
define_identifier!(OrganizationId, "organizationId");
define_identifier!(GroupId, "groupId");
define_identifier!(TargetId, "targetId");
define_identifier!(SnykProjectId, "snykProjectId");
define_identifier!(SnapshotId, "snapshotId");
define_identifier!(IssueId, "issueId");
define_identifier!(PackageId, "packageId");
define_identifier!(PathId, "pathId");
define_identifier!(CommitId, "commitId");
define_identifier!(MissionId, "missionId");
define_identifier!(ProjectId, "projectId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(RegistrationId, "registrationId");

/// Semantic version bound to a registration, independent of crate packaging.
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

    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split('.');
        let parsed = [parts.next(), parts.next(), parts.next()];
        if parts.next().is_some() || parsed.iter().any(Option::is_none) {
            return Err(SnykSecurityResultError::InvalidIdentifier {
                field: "pluginVersion",
            });
        }
        let mut numbers = [0_u16; 3];
        for (index, part) in parsed.into_iter().enumerate() {
            numbers[index] = part
                .expect("checked version part")
                .parse::<u16>()
                .map_err(|_| SnykSecurityResultError::InvalidIdentifier {
                    field: "pluginVersion",
                })?;
        }
        Ok(Self {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// An opaque API-token or OAuth handle. Raw credentials never enter this
/// type, and the type intentionally does not implement `Serialize`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
    OAuth,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn api_token(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::ApiToken, opaque_id, revision)
    }

    pub fn oauth(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::OAuth, opaque_id, revision)
    }

    pub fn new(kind: SecretKind, opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_id = opaque_id.into();
        validate_text(&opaque_id, "secretReference", MAX_IDENTIFIER_BYTES)?;
        if revision == 0 {
            return Err(SnykSecurityResultError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            reference_digest: Digest::from_parts(
                "snyk-opaque-secret-reference/v1",
                &[
                    ("kind", format!("{kind:?}")),
                    ("opaque_id", opaque_id),
                    ("revision", revision.to_string()),
                ],
            ),
            revision,
            revoked: false,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
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

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate()?;
        if self.revision == 0 {
            return Err(SnykSecurityResultError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegionIdentity {
    pub id: RegionId,
    pub https_host: String,
    pub revision: u64,
}

impl RegionIdentity {
    pub fn new(
        id: impl Into<String>,
        https_host: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        let identity = Self {
            id: RegionId::new(id)?,
            https_host: https_host.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        validate_text(&self.https_host, "regionHttpsHost", MAX_TEXT_BYTES)?;
        if !self.https_host.starts_with("https://")
            || self.https_host[8..].contains('/')
            || self.https_host[8..].is_empty()
        {
            return Err(SnykSecurityResultError::InvalidRegionHost);
        }
        if self.revision == 0 {
            return Err(SnykSecurityResultError::InvalidScope);
        }
        Ok(())
    }
}

macro_rules! define_identity {
    ($name:ident, $id:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let identity = Self {
                    id: $id::new(id)?,
                    revision,
                };
                identity.validate()?;
                Ok(identity)
            }

            pub fn validate(&self) -> Result<()> {
                self.id.validate()?;
                if self.revision == 0 {
                    return Err(SnykSecurityResultError::InvalidScope);
                }
                Ok(())
            }
        }
    };
}

define_identity!(OrganizationIdentity, OrganizationId, "organization");
define_identity!(GroupIdentity, GroupId, "group");
define_identity!(TargetIdentity, TargetId, "target");
define_identity!(ProjectIdentity, SnykProjectId, "snykProject");
define_identity!(SnapshotIdentity, SnapshotId, "snapshot");
define_identity!(IssueIdentity, IssueId, "issue");
define_identity!(PackageIdentity, PackageId, "package");
define_identity!(PathIdentity, PathId, "path");
define_identity!(CommitIdentity, CommitId, "commit");
define_identity!(MissionIdentity, MissionId, "mission");
define_identity!(ProjectContextIdentity, ProjectId, "project");
define_identity!(WorkProductIdentity, WorkProductId, "workProduct");

/// The complete cross-authority fence for every Snyk read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnykScope {
    pub region: RegionIdentity,
    pub organization: OrganizationIdentity,
    pub group: GroupIdentity,
    pub target: TargetIdentity,
    pub project: ProjectIdentity,
    pub snapshot: SnapshotIdentity,
    pub issue: IssueIdentity,
    pub package: PackageIdentity,
    pub path: PathIdentity,
    pub commit: CommitIdentity,
    pub mission: MissionIdentity,
    pub hartevo_project: ProjectContextIdentity,
    pub work_product: WorkProductIdentity,
}

impl SnykScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        region: RegionIdentity,
        organization: OrganizationIdentity,
        group: GroupIdentity,
        target: TargetIdentity,
        project: ProjectIdentity,
        snapshot: SnapshotIdentity,
        issue: IssueIdentity,
        package: PackageIdentity,
        path: PathIdentity,
        commit: CommitIdentity,
        mission: MissionIdentity,
        hartevo_project: ProjectContextIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            region,
            organization,
            group,
            target,
            project,
            snapshot,
            issue,
            package,
            path,
            commit,
            mission,
            hartevo_project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Convenience fixture constructor. All identity revisions are explicitly
    /// bound to revision 1; callers needing another revision should use `new`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        region_id: impl Into<String>,
        region_host: impl Into<String>,
        organization_id: impl Into<String>,
        group_id: impl Into<String>,
        target_id: impl Into<String>,
        snyk_project_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        issue_id: impl Into<String>,
        package_id: impl Into<String>,
        path_id: impl Into<String>,
        commit_id: impl Into<String>,
        mission_id: impl Into<String>,
        project_id: impl Into<String>,
        work_product_id: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            RegionIdentity::new(region_id, region_host, 1)?,
            OrganizationIdentity::new(organization_id, 1)?,
            GroupIdentity::new(group_id, 1)?,
            TargetIdentity::new(target_id, 1)?,
            ProjectIdentity::new(snyk_project_id, 1)?,
            SnapshotIdentity::new(snapshot_id, 1)?,
            IssueIdentity::new(issue_id, 1)?,
            PackageIdentity::new(package_id, 1)?,
            PathIdentity::new(path_id, 1)?,
            CommitIdentity::new(commit_id, 1)?,
            MissionIdentity::new(mission_id, 1)?,
            ProjectContextIdentity::new(project_id, 1)?,
            WorkProductIdentity::new(work_product_id, 1)?,
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission.id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission.revision
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.hartevo_project.id
    }

    pub const fn project_revision(&self) -> u64 {
        self.hartevo_project.revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product.id
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product.revision
    }

    pub fn validate(&self) -> Result<()> {
        self.region.validate()?;
        self.organization.validate()?;
        self.group.validate()?;
        self.target.validate()?;
        self.project.validate()?;
        self.snapshot.validate()?;
        self.issue.validate()?;
        self.package.validate()?;
        self.path.validate()?;
        self.commit.validate()?;
        self.mission.validate()?;
        self.hartevo_project.validate()?;
        self.work_product.validate()
    }
}

/// Read-only permissions are an explicit allowlist. Mutation-like or raw-data
/// permissions are rejected rather than merely omitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn read_only(revision: u64) -> Result<Self> {
        Self::new(
            revision,
            [
                "region.read",
                "organization.read",
                "group.read",
                "target.read",
                "project.read",
                "snapshot.read",
                "issue.read",
                "package.read",
                "path.read",
                "commit.read",
                "vulnerability.read",
                "license.read",
                "iac.read",
                "evidence.read",
            ]
            .into_iter()
            .map(str::to_owned),
        )
    }

    pub fn new(revision: u64, permissions: impl IntoIterator<Item = String>) -> Result<Self> {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn is_read_only(&self) -> bool {
        self.validate().is_ok()
    }

    pub fn validate(&self) -> Result<()> {
        const ALLOWED: &[&str] = &[
            "region.read",
            "organization.read",
            "group.read",
            "target.read",
            "project.read",
            "snapshot.read",
            "issue.read",
            "package.read",
            "path.read",
            "commit.read",
            "vulnerability.read",
            "license.read",
            "iac.read",
            "evidence.read",
        ];
        const FORBIDDEN: &[&str] = &[
            "ignore.write",
            "unignore.write",
            "remediation.write",
            "project.import",
            "project.delete",
            "source.export",
            "dependency.graph.read",
            "security.registry.write",
        ];
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !ALLOWED.contains(&permission.as_str()))
            || self
                .permissions
                .iter()
                .any(|permission| FORBIDDEN.contains(&permission.as_str()))
        {
            return Err(SnykSecurityResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

/// Statuses are descriptive evidence, not commands. Ignored findings are read
/// as provider state; this crate has no ignore/unignore operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Fixed,
    Ignored,
    Introduced,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IaCSeverity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixAvailability {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseRisk {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixMetadata {
    pub availability: FixAvailability,
    pub fixed_version_digest: Option<Digest>,
    pub remediation_path_digest: Option<Digest>,
}

impl FixMetadata {
    pub fn unavailable() -> Self {
        Self {
            availability: FixAvailability::Unavailable,
            fixed_version_digest: None,
            remediation_path_digest: None,
        }
    }

    pub fn available(fixed_version: impl AsRef<[u8]>, remediation_path: impl AsRef<[u8]>) -> Self {
        Self {
            availability: FixAvailability::Available,
            fixed_version_digest: Some(Digest::from_text(fixed_version)),
            remediation_path_digest: Some(Digest::from_text(remediation_path)),
        }
    }

    pub fn unknown() -> Self {
        Self {
            availability: FixAvailability::Unknown,
            fixed_version_digest: None,
            remediation_path_digest: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.availability == FixAvailability::Available
            && (self.fixed_version_digest.is_none() || self.remediation_path_digest.is_none())
        {
            return Err(SnykSecurityResultError::RedactedEvidence);
        }
        if let Some(digest) = &self.fixed_version_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.remediation_path_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

/// Only redacted, allowlisted vulnerability fields are representable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VulnerabilityEvidence {
    pub issue_id: IssueId,
    pub package_id: PackageId,
    pub path_id: PathId,
    pub commit_id: CommitId,
    pub vulnerability_id: String,
    pub title_digest: Digest,
    pub severity: Severity,
    pub status: FindingStatus,
    pub fix: FixMetadata,
}

impl VulnerabilityEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issue_id: IssueId,
        package_id: PackageId,
        path_id: PathId,
        commit_id: CommitId,
        vulnerability_id: impl Into<String>,
        title: impl AsRef<[u8]>,
        severity: Severity,
        status: FindingStatus,
        fix: FixMetadata,
    ) -> Result<Self> {
        let evidence = Self {
            issue_id,
            package_id,
            path_id,
            commit_id,
            vulnerability_id: vulnerability_id.into(),
            title_digest: Digest::from_text(title),
            severity,
            status,
            fix,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        self.issue_id.validate()?;
        self.package_id.validate()?;
        self.path_id.validate()?;
        self.commit_id.validate()?;
        validate_text(
            &self.vulnerability_id,
            "vulnerabilityId",
            MAX_IDENTIFIER_BYTES,
        )?;
        self.title_digest.validate()?;
        self.fix.validate()
    }
}

/// Only redacted license metadata is representable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LicenseEvidence {
    pub issue_id: IssueId,
    pub package_id: PackageId,
    pub path_id: PathId,
    pub commit_id: CommitId,
    pub license_id: String,
    pub license_name_digest: Digest,
    pub risk: LicenseRisk,
    pub status: FindingStatus,
}

impl LicenseEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issue_id: IssueId,
        package_id: PackageId,
        path_id: PathId,
        commit_id: CommitId,
        license_id: impl Into<String>,
        license_name: impl AsRef<[u8]>,
        risk: LicenseRisk,
        status: FindingStatus,
    ) -> Result<Self> {
        let evidence = Self {
            issue_id,
            package_id,
            path_id,
            commit_id,
            license_id: license_id.into(),
            license_name_digest: Digest::from_text(license_name),
            risk,
            status,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        self.issue_id.validate()?;
        self.package_id.validate()?;
        self.path_id.validate()?;
        self.commit_id.validate()?;
        validate_text(&self.license_id, "licenseId", MAX_IDENTIFIER_BYTES)?;
        self.license_name_digest.validate()
    }
}

/// Only redacted IaC rule/resource metadata is representable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IacEvidence {
    pub issue_id: IssueId,
    pub path_id: PathId,
    pub commit_id: CommitId,
    pub rule_id: String,
    pub resource_type_digest: Digest,
    pub message_digest: Digest,
    pub severity: IaCSeverity,
    pub status: FindingStatus,
    pub fix: FixMetadata,
}

impl IacEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issue_id: IssueId,
        path_id: PathId,
        commit_id: CommitId,
        rule_id: impl Into<String>,
        resource_type: impl AsRef<[u8]>,
        message: impl AsRef<[u8]>,
        severity: IaCSeverity,
        status: FindingStatus,
        fix: FixMetadata,
    ) -> Result<Self> {
        let evidence = Self {
            issue_id,
            path_id,
            commit_id,
            rule_id: rule_id.into(),
            resource_type_digest: Digest::from_text(resource_type),
            message_digest: Digest::from_text(message),
            severity,
            status,
            fix,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        self.issue_id.validate()?;
        self.path_id.validate()?;
        self.commit_id.validate()?;
        validate_text(&self.rule_id, "ruleId", MAX_IDENTIFIER_BYTES)?;
        self.resource_type_digest.validate()?;
        self.message_digest.validate()?;
        self.fix.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Vulnerability,
    License,
    Iac,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
pub enum Evidence {
    Vulnerability(VulnerabilityEvidence),
    License(LicenseEvidence),
    Iac(IacEvidence),
}

impl Evidence {
    pub const fn kind(&self) -> EvidenceKind {
        match self {
            Self::Vulnerability(_) => EvidenceKind::Vulnerability,
            Self::License(_) => EvidenceKind::License,
            Self::Iac(_) => EvidenceKind::Iac,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Vulnerability(value) => value.validate(),
            Self::License(value) => value.validate(),
            Self::Iac(value) => value.validate(),
        }
    }

    pub fn validate_for_scope(&self, scope: &SnykScope) -> Result<()> {
        self.validate()?;
        let matches = match self {
            Self::Vulnerability(value) => {
                value.issue_id == scope.issue.id
                    && value.package_id == scope.package.id
                    && value.path_id == scope.path.id
                    && value.commit_id == scope.commit.id
            }
            Self::License(value) => {
                value.issue_id == scope.issue.id
                    && value.package_id == scope.package.id
                    && value.path_id == scope.path.id
                    && value.commit_id == scope.commit.id
            }
            Self::Iac(value) => {
                value.issue_id == scope.issue.id
                    && value.path_id == scope.path.id
                    && value.commit_id == scope.commit.id
            }
        };
        if matches {
            Ok(())
        } else {
            Err(SnykSecurityResultError::ScopeMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Open,
    Completed,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Truncated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn claims_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}
