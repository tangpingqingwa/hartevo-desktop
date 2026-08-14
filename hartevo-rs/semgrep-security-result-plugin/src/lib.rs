#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 Semgrep security-result plugin."]
//!
//! This crate is deliberately a bounded read/proposal/recording boundary. It
//! models the Semgrep AppSec Platform v1 read surface for projects, scans,
//! Code/Supply Chain findings, and Secrets findings without becoming a
//! scanner registry, remediation authority, or Hartevo kernel authority.
//!
//! The transport trait has no mutation methods. Fixture, fake, recording,
//! loopback, and `BLOCKED_ENV` transports are always projected as
//! `connected=false`, `native=false`, and `first_party=false`. Raw source,
//! secret values, bearer credentials, finding triage writes, PR/Jira writes,
//! code mutation, tool execution, and Outcome adoption have no representation
//! in the public API.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.semgrep-security-result/v1";
pub const SERVICE_ID: &str = "security.semgrep.result.read";
pub const PROVIDER_ID: &str = "semgrep";
pub const SERVICE_VERSION: Version = Version::new(0, 1, 0);
pub const SEMGREP_API_V1: &str = "v1";
pub const DEFAULT_API_HOST: &str = "semgrep.dev";

pub const MAX_HOST_BYTES: usize = 256;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_REF_BYTES: usize = 512;
pub const MAX_FINDING_IDS: usize = 256;
pub const MAX_RULE_IDS: usize = 256;
pub const MAX_FINDING_TYPES: usize = 3;
pub const MAX_FINDINGS: usize = 4_096;
pub const MAX_PAGE_COUNT: usize = 32;
pub const MAX_PAGE_ITEMS: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RULE_NAME_BYTES: usize = 256;
pub const MAX_LOCATION_LINES: u32 = 10_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

/// A lower-case SHA-256 digest used for scope, payload, evidence, and
/// proposal fences.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("contract values must serialize");
        Self::from_bytes(&bytes)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepApiVersion {
    V1,
}

impl SemgrepApiVersion {
    pub const fn as_str(self) -> &'static str {
        SEMGREP_API_V1
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryIdentity {
    pub provider: String,
    pub owner: String,
    pub name: String,
    pub url: String,
}

impl RepositoryIdentity {
    pub fn new(
        provider: impl Into<String>,
        owner: impl Into<String>,
        name: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<Self, SemgrepError> {
        let identity = Self {
            provider: provider.into(),
            owner: owner.into(),
            name: name.into(),
            url: url.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), SemgrepError> {
        validate_identifier("repository provider", &self.provider, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("repository owner", &self.owner, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("repository name", &self.name, MAX_IDENTIFIER_BYTES)?;
        validate_bounded_text("repository URL", &self.url, MAX_REF_BYTES)?;
        if !(self.url.starts_with("https://") || self.url.starts_with("ssh://")) {
            return Err(SemgrepError::InvalidInput("repository URL"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScopeBinding {
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub policy_digest: Digest,
    pub consent_digest: Digest,
}

impl MissionScopeBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        project_revision: u64,
        mission_revision: u64,
        work_product_revision: u64,
        policy_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, SemgrepError> {
        let binding = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            work_product_id: work_product_id.into(),
            project_revision,
            mission_revision,
            work_product_revision,
            policy_digest,
            consent_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), SemgrepError> {
        validate_identifier("Hartevo Project", &self.project_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("Hartevo Mission", &self.mission_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(
            "Hartevo Work Product",
            &self.work_product_id,
            MAX_IDENTIFIER_BYTES,
        )?;
        if self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
        {
            return Err(SemgrepError::InvalidInput("scope revision"));
        }
        if !self.policy_digest.is_valid() || !self.consent_digest.is_valid() {
            return Err(SemgrepError::InvalidDigest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SemgrepFindingType {
    #[serde(rename = "sast")]
    Sast,
    #[serde(rename = "secrets")]
    Secrets,
    #[serde(rename = "sca")]
    Sca,
}

impl SemgrepFindingType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sast => "sast",
            Self::Secrets => "secrets",
            Self::Sca => "sca",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SemgrepPermission {
    #[serde(rename = "organization:read")]
    OrganizationRead,
    #[serde(rename = "project:read")]
    ProjectRead,
    #[serde(rename = "scan:read")]
    ScanRead,
    #[serde(rename = "finding:read")]
    FindingRead,
    #[serde(rename = "rule:read")]
    RuleRead,
    #[serde(rename = "secrets:read")]
    SecretsRead,
}

impl SemgrepPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrganizationRead => "organization:read",
            Self::ProjectRead => "project:read",
            Self::ScanRead => "scan:read",
            Self::FindingRead => "finding:read",
            Self::RuleRead => "rule:read",
            Self::SecretsRead => "secrets:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemgrepSecurityScope {
    pub api_version: SemgrepApiVersion,
    pub api_host: String,
    pub organization_id: String,
    pub organization_slug: String,
    pub project_id: String,
    pub repository: RepositoryIdentity,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub scan_id: String,
    pub finding_ids: Vec<String>,
    pub rule_ids: Vec<String>,
    pub rule_revision_digest: Digest,
    pub commit_sha: String,
    pub finding_types: BTreeSet<SemgrepFindingType>,
    pub mission: MissionScopeBinding,
    pub permissions: BTreeSet<SemgrepPermission>,
}

impl SemgrepSecurityScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_version: SemgrepApiVersion,
        api_host: impl Into<String>,
        organization_id: impl Into<String>,
        organization_slug: impl Into<String>,
        project_id: impl Into<String>,
        repository: RepositoryIdentity,
        git_ref: impl Into<String>,
        scan_id: impl Into<String>,
        commit_sha: impl Into<String>,
        finding_ids: impl IntoIterator<Item = String>,
        rule_ids: impl IntoIterator<Item = String>,
        finding_types: impl IntoIterator<Item = SemgrepFindingType>,
        mission: MissionScopeBinding,
        permissions: impl IntoIterator<Item = SemgrepPermission>,
    ) -> Result<Self, SemgrepError> {
        let canonical_rule_ids = canonical_strings(rule_ids, MAX_RULE_IDS, MAX_IDENTIFIER_BYTES)?;
        let scope = Self {
            api_version,
            api_host: api_host.into(),
            organization_id: organization_id.into(),
            organization_slug: organization_slug.into(),
            project_id: project_id.into(),
            repository,
            git_ref: git_ref.into(),
            scan_id: scan_id.into(),
            finding_ids: canonical_strings(finding_ids, MAX_FINDING_IDS, MAX_IDENTIFIER_BYTES)?,
            rule_ids: canonical_rule_ids.clone(),
            rule_revision_digest: Digest::from_serializable(&canonical_rule_ids),
            commit_sha: commit_sha.into(),
            finding_types: finding_types.into_iter().collect(),
            mission,
            permissions: permissions.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_rule_revision_digest(mut self, digest: Digest) -> Result<Self, SemgrepError> {
        self.rule_revision_digest = digest;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SemgrepError> {
        if self.api_version != SemgrepApiVersion::V1 {
            return Err(SemgrepError::UnsupportedApiVersion);
        }
        validate_host(&self.api_host)?;
        validate_identifier(
            "Semgrep organization",
            &self.organization_id,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_identifier(
            "Semgrep organization slug",
            &self.organization_slug,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_identifier("Semgrep project", &self.project_id, MAX_IDENTIFIER_BYTES)?;
        self.repository.validate()?;
        validate_bounded_text("git ref", &self.git_ref, MAX_REF_BYTES)?;
        validate_identifier("Semgrep scan", &self.scan_id, MAX_IDENTIFIER_BYTES)?;
        validate_commit_sha(&self.commit_sha)?;
        validate_string_list(&self.finding_ids, MAX_FINDING_IDS, MAX_IDENTIFIER_BYTES)?;
        validate_string_list(&self.rule_ids, MAX_RULE_IDS, MAX_IDENTIFIER_BYTES)?;
        if !self.rule_revision_digest.is_valid() {
            return Err(SemgrepError::InvalidDigest);
        }
        if self.finding_types.is_empty() || self.finding_types.len() > MAX_FINDING_TYPES {
            return Err(SemgrepError::InvalidInput("finding types"));
        }
        self.mission.validate()?;
        let required = [
            SemgrepPermission::OrganizationRead,
            SemgrepPermission::ProjectRead,
            SemgrepPermission::ScanRead,
            SemgrepPermission::FindingRead,
            SemgrepPermission::RuleRead,
        ];
        if required
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(SemgrepError::PermissionDrift);
        }
        if self.finding_types.contains(&SemgrepFindingType::Secrets)
            && !self.permissions.contains(&SemgrepPermission::SecretsRead)
        {
            return Err(SemgrepError::PermissionDrift);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn organization_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.organization_id, &self.organization_slug))
    }

    pub fn project_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.project_id, self.mission.project_revision))
    }

    pub fn repository_digest(&self) -> Digest {
        self.repository.digest()
    }

    pub fn ref_digest(&self) -> Digest {
        Digest::from_text(&self.git_ref)
    }

    pub fn scan_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.scan_id, &self.git_ref, &self.commit_sha))
    }

    pub fn finding_digest(&self) -> Digest {
        Digest::from_serializable(&self.finding_ids)
    }

    pub fn rule_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.rule_ids, &self.rule_revision_digest))
    }

    pub fn commit_digest(&self) -> Digest {
        Digest::from_text(&self.commit_sha)
    }

    pub fn permission_digest(&self) -> Digest {
        Digest::from_serializable(&self.permissions)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    ApiToken,
    Oidc,
}

/// Opaque reference to a credential held outside this crate. No raw token,
/// OIDC assertion, or credential bytes can be constructed or serialized here.
pub struct SecretReference {
    kind: SecretReferenceKind,
    scope_digest: Digest,
    generation: u64,
    reference_digest: Digest,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            scope_digest: self.scope_digest.clone(),
            generation: self.generation,
            reference_digest: self.reference_digest.clone(),
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.scope_digest == other.scope_digest
            && self.generation == other.generation
            && self.reference_digest == other.reference_digest
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("reference_digest", &self.reference_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    /// Creates an opaque API-token reference. The `reference_id` is hashed
    /// immediately and is never retained in raw form.
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &SemgrepSecurityScope,
        generation: u64,
    ) -> Result<Self, SemgrepError> {
        Self::new_with_kind(
            reference_id,
            SecretReferenceKind::ApiToken,
            scope,
            generation,
        )
    }

    pub fn new_with_kind(
        reference_id: impl AsRef<str>,
        kind: SecretReferenceKind,
        scope: &SemgrepSecurityScope,
        generation: u64,
    ) -> Result<Self, SemgrepError> {
        let reference_id = reference_id.as_ref();
        validate_identifier("secret reference", reference_id, MAX_IDENTIFIER_BYTES)?;
        if generation == 0 {
            return Err(SemgrepError::InvalidSecretReference);
        }
        let scope_digest = scope.scope_digest();
        let reference_digest =
            Digest::from_serializable(&(reference_id, kind, &scope_digest, generation));
        Ok(Self {
            kind,
            scope_digest,
            generation,
            reference_digest,
            revoked: false,
        })
    }

    pub fn api_token(
        reference_id: impl AsRef<str>,
        scope: &SemgrepSecurityScope,
        generation: u64,
    ) -> Result<Self, SemgrepError> {
        Self::new(reference_id, scope, generation)
    }

    pub fn oidc(
        reference_id: impl AsRef<str>,
        scope: &SemgrepSecurityScope,
        generation: u64,
    ) -> Result<Self, SemgrepError> {
        Self::new_with_kind(reference_id, SecretReferenceKind::Oidc, scope, generation)
    }

    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn reference_digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    fn is_bound_to(&self, scope: &SemgrepSecurityScope) -> bool {
        !self.revoked && self.scope_digest == scope.scope_digest()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemgrepRegistration {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_host_digest: Digest,
    pub organization_digest: Digest,
    pub project_digest: Digest,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub scan_digest: Digest,
    pub finding_digest: Digest,
    pub rule_digest: Digest,
    pub commit_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub credential_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
    pub status: RegistrationStatus,
}

#[derive(Serialize)]
struct RegistrationDigestInput<'a> {
    version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_host_digest: &'a Digest,
    organization_digest: &'a Digest,
    project_digest: &'a Digest,
    repository_digest: &'a Digest,
    ref_digest: &'a Digest,
    scan_digest: &'a Digest,
    finding_digest: &'a Digest,
    rule_digest: &'a Digest,
    commit_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    credential_digest: &'a Digest,
    reversible: bool,
    revocable: bool,
}

impl SemgrepRegistration {
    pub fn new(
        scope: &SemgrepSecurityScope,
        secret_reference: &SecretReference,
    ) -> Result<Self, SemgrepError> {
        scope.validate()?;
        if !secret_reference.is_bound_to(scope) {
            return Err(if secret_reference.is_revoked() {
                SemgrepError::SecretRevoked
            } else {
                SemgrepError::SecretScopeMismatch
            });
        }
        let mut registration = Self {
            version_digest: Digest::from_serializable(&SERVICE_VERSION),
            contract_digest: Digest::from_text(CONTRACT_SCHEMA),
            provider_digest: Digest::from_text(PROVIDER_ID),
            api_host_digest: Digest::from_text(&scope.api_host),
            organization_digest: scope.organization_digest(),
            project_digest: scope.project_digest(),
            repository_digest: scope.repository_digest(),
            ref_digest: scope.ref_digest(),
            scan_digest: scope.scan_digest(),
            finding_digest: scope.finding_digest(),
            rule_digest: scope.rule_digest(),
            commit_digest: scope.commit_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            credential_digest: secret_reference.reference_digest(),
            registration_digest: Digest::from_text("uncomputed"),
            reversible: true,
            revocable: true,
            status: RegistrationStatus::Active,
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&RegistrationDigestInput {
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            api_host_digest: &self.api_host_digest,
            organization_digest: &self.organization_digest,
            project_digest: &self.project_digest,
            repository_digest: &self.repository_digest,
            ref_digest: &self.ref_digest,
            scan_digest: &self.scan_digest,
            finding_digest: &self.finding_digest,
            rule_digest: &self.rule_digest,
            commit_digest: &self.commit_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            credential_digest: &self.credential_digest,
            reversible: self.reversible,
            revocable: self.revocable,
        })
    }

    pub fn validate_binding(
        &self,
        scope: &SemgrepSecurityScope,
        secret_reference: &SecretReference,
    ) -> Result<(), SemgrepError> {
        if self.status == RegistrationStatus::Revoked {
            return Err(SemgrepError::RegistrationRevoked);
        }
        if self.registration_digest != self.compute_digest() {
            return Err(SemgrepError::RegistrationTampered);
        }
        let expected = Self::new(scope, secret_reference)?;
        if self.version_digest != expected.version_digest
            || self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.api_host_digest != expected.api_host_digest
            || self.organization_digest != expected.organization_digest
            || self.project_digest != expected.project_digest
            || self.repository_digest != expected.repository_digest
            || self.ref_digest != expected.ref_digest
            || self.scan_digest != expected.scan_digest
            || self.finding_digest != expected.finding_digest
            || self.rule_digest != expected.rule_digest
            || self.commit_digest != expected.commit_digest
            || self.permission_digest != expected.permission_digest
            || self.scope_digest != expected.scope_digest
            || self.credential_digest != expected.credential_digest
        {
            return Err(SemgrepError::RegistrationBindingDrift);
        }
        Ok(())
    }

    pub fn unmount(&mut self) -> Result<(), SemgrepError> {
        match self.status {
            RegistrationStatus::Active => {
                self.status = RegistrationStatus::Unmounted;
                Ok(())
            }
            RegistrationStatus::Unmounted => Ok(()),
            RegistrationStatus::Revoked => Err(SemgrepError::RegistrationRevoked),
        }
    }

    pub fn remount(&mut self) -> Result<(), SemgrepError> {
        if self.status == RegistrationStatus::Revoked {
            return Err(SemgrepError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Active;
        Ok(())
    }

    pub fn revoke(&mut self, secret_reference: &mut SecretReference) -> RevocationReceipt {
        self.status = RegistrationStatus::Revoked;
        secret_reference.revoke();
        RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            credential_digest: self.credential_digest.clone(),
            status: self.status,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub credential_digest: Digest,
    pub status: RegistrationStatus,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepSecurityOperation {
    DescribeOrganizationProject,
    ReadScanEvidence,
    CompileSecurityDecisionProposal,
    RecordSecurityReceipt,
    VerifySecurityResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct SemgrepSecurityServiceDefinition {
    pub schema_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub version: Version,
    pub layer: u8,
    pub operations: BTreeSet<SemgrepSecurityOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub forbidden_effects: Vec<String>,
}

impl SemgrepSecurityServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.into(),
            service_id: SERVICE_ID.into(),
            provider_id: PROVIDER_ID.into(),
            version: SERVICE_VERSION,
            layer: 1,
            operations: [
                SemgrepSecurityOperation::DescribeOrganizationProject,
                SemgrepSecurityOperation::ReadScanEvidence,
                SemgrepSecurityOperation::CompileSecurityDecisionProposal,
                SemgrepSecurityOperation::RecordSecurityReceipt,
                SemgrepSecurityOperation::VerifySecurityResult,
            ]
            .into_iter()
            .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            forbidden_effects: vec![
                "triage_finding".into(),
                "ignore_finding".into(),
                "mutate_code".into(),
                "write_pull_request".into(),
                "write_jira".into(),
                "export_raw_source".into(),
                "export_unbounded_findings".into(),
                "execute_tool".into(),
                "adopt_kernel_outcome".into(),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportKind {
    pub const fn is_layer1(self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum FindingStatus {
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "reviewing")]
    Reviewing,
    #[serde(rename = "to_fix")]
    ToFix,
    #[serde(rename = "fixed")]
    Fixed,
    #[serde(rename = "ignored")]
    Ignored,
    #[serde(rename = "removed")]
    Removed,
    #[serde(rename = "provisionally_ignored")]
    ProvisionallyIgnored,
    #[serde(rename = "unknown")]
    Unknown,
}

impl FindingStatus {
    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::Open | Self::Reviewing | Self::ToFix)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Fixed | Self::Ignored | Self::Removed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    pub const fn is_high_or_critical(self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    Reachable,
    AlwaysReachable,
    ConditionallyReachable,
    Unreachable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretValidationState {
    ConfirmedValid,
    ConfirmedInvalid,
    ValidationError,
    NoValidator,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    Security,
    Correctness,
    Secrets,
    SupplyChain,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Completed,
    Partial,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProjection {
    NoFindings,
    FindingsPresent,
    Incomplete,
    AccessLoss,
    ProviderUnknown,
    Stale,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityDecision {
    Allow,
    Block,
    Review,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDisposition {
    Layer2Required,
    BlockedByProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleMetadata {
    pub rule_id: String,
    pub revision_digest: Digest,
    pub category: RuleCategory,
    pub severity: Severity,
    pub name_digest: Digest,
    pub description_digest: Digest,
}

impl RuleMetadata {
    pub fn new(
        rule_id: impl Into<String>,
        revision_digest: Digest,
        category: RuleCategory,
        severity: Severity,
        name_digest: Digest,
        description_digest: Digest,
    ) -> Result<Self, SemgrepError> {
        let metadata = Self {
            rule_id: rule_id.into(),
            revision_digest,
            category,
            severity,
            name_digest,
            description_digest,
        };
        metadata.validate_shape()?;
        Ok(metadata)
    }

    pub fn for_scope(
        scope: &SemgrepSecurityScope,
        rule_id: impl Into<String>,
        category: RuleCategory,
        severity: Severity,
    ) -> Result<Self, SemgrepError> {
        let rule_id = rule_id.into();
        validate_identifier("Semgrep rule", &rule_id, MAX_IDENTIFIER_BYTES)?;
        Self::new(
            rule_id.clone(),
            scope.rule_revision_digest.clone(),
            category,
            severity,
            Digest::from_text(&rule_id),
            Digest::from_serializable(&(rule_id, category)),
        )
    }

    fn validate_shape(&self) -> Result<(), SemgrepError> {
        validate_identifier("Semgrep rule", &self.rule_id, MAX_IDENTIFIER_BYTES)?;
        if !self.revision_digest.is_valid()
            || !self.name_digest.is_valid()
            || !self.description_digest.is_valid()
        {
            return Err(SemgrepError::InvalidDigest);
        }
        Ok(())
    }

    pub fn validate(&self, scope: &SemgrepSecurityScope) -> Result<(), SemgrepError> {
        self.validate_shape()?;
        if (!scope.rule_ids.is_empty() && !scope.rule_ids.contains(&self.rule_id))
            || self.revision_digest != scope.rule_revision_digest
        {
            return Err(SemgrepError::RuleMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingLocation {
    pub path_digest: Digest,
    pub start_line: u32,
    pub end_line: u32,
}

impl FindingLocation {
    pub fn new(path_digest: Digest, start_line: u32, end_line: u32) -> Result<Self, SemgrepError> {
        let location = Self {
            path_digest,
            start_line,
            end_line,
        };
        location.validate()?;
        Ok(location)
    }

    fn validate(&self) -> Result<(), SemgrepError> {
        if !self.path_digest.is_valid()
            || self.start_line == 0
            || self.end_line < self.start_line
            || self.end_line > MAX_LOCATION_LINES
        {
            return Err(SemgrepError::InvalidLocation);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    pub finding_id: String,
    pub finding_type: SemgrepFindingType,
    pub status: FindingStatus,
    pub severity: Severity,
    pub repository: RepositoryIdentity,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub scan_id: String,
    pub commit_sha: String,
    pub rule: RuleMetadata,
    pub location: FindingLocation,
    pub reachability: Option<Reachability>,
    pub secret_validation: Option<SecretValidationState>,
    pub fingerprint: Digest,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        finding_id: impl Into<String>,
        finding_type: SemgrepFindingType,
        status: FindingStatus,
        severity: Severity,
        repository: RepositoryIdentity,
        git_ref: impl Into<String>,
        scan_id: impl Into<String>,
        commit_sha: impl Into<String>,
        rule: RuleMetadata,
        location: FindingLocation,
        reachability: Option<Reachability>,
        secret_validation: Option<SecretValidationState>,
        fingerprint: Digest,
    ) -> Result<Self, SemgrepError> {
        let finding = Self {
            finding_id: finding_id.into(),
            finding_type,
            status,
            severity,
            repository,
            git_ref: git_ref.into(),
            scan_id: scan_id.into(),
            commit_sha: commit_sha.into(),
            rule,
            location,
            reachability,
            secret_validation,
            fingerprint,
        };
        finding.validate_shape()?;
        Ok(finding)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_scope(
        scope: &SemgrepSecurityScope,
        finding_id: impl Into<String>,
        finding_type: SemgrepFindingType,
        status: FindingStatus,
        severity: Severity,
        rule_id: impl Into<String>,
        location_path_digest: Digest,
        reachability: Option<Reachability>,
    ) -> Result<Self, SemgrepError> {
        let rule =
            RuleMetadata::for_scope(scope, rule_id, category_for_type(finding_type), severity)?;
        let location = FindingLocation::new(location_path_digest, 1, 1)?;
        let finding_id = finding_id.into();
        Self::new(
            finding_id.clone(),
            finding_type,
            status,
            severity,
            scope.repository.clone(),
            scope.git_ref.clone(),
            scope.scan_id.clone(),
            scope.commit_sha.clone(),
            rule,
            location,
            reachability,
            (finding_type == SemgrepFindingType::Secrets).then_some(SecretValidationState::Unknown),
            Digest::from_serializable(&(
                finding_id,
                finding_type,
                &scope.git_ref,
                &scope.commit_sha,
            )),
        )
    }

    fn validate_shape(&self) -> Result<(), SemgrepError> {
        validate_identifier("Semgrep finding", &self.finding_id, MAX_IDENTIFIER_BYTES)?;
        self.repository.validate()?;
        validate_bounded_text("finding ref", &self.git_ref, MAX_REF_BYTES)?;
        validate_identifier("finding scan", &self.scan_id, MAX_IDENTIFIER_BYTES)?;
        validate_commit_sha(&self.commit_sha)?;
        self.location.validate()?;
        if !self.fingerprint.is_valid() {
            return Err(SemgrepError::InvalidDigest);
        }
        if self.finding_type == SemgrepFindingType::Sca && self.reachability.is_none() {
            return Err(SemgrepError::InvalidInput("SCA reachability"));
        }
        if self.finding_type != SemgrepFindingType::Sca && self.reachability.is_some() {
            return Err(SemgrepError::InvalidInput("non-SCA reachability"));
        }
        if self.finding_type == SemgrepFindingType::Secrets && self.secret_validation.is_none() {
            return Err(SemgrepError::InvalidInput("Secrets validation state"));
        }
        Ok(())
    }

    pub fn validate(&self, scope: &SemgrepSecurityScope) -> Result<(), SemgrepError> {
        self.validate_shape()?;
        if !scope.finding_types.contains(&self.finding_type) {
            return Err(SemgrepError::FindingTypeMismatch);
        }
        if !scope.finding_ids.is_empty() && !scope.finding_ids.contains(&self.finding_id) {
            return Err(SemgrepError::FindingMismatch);
        }
        if self.repository != scope.repository {
            return Err(SemgrepError::RepositoryMismatch);
        }
        if self.git_ref != scope.git_ref {
            return Err(SemgrepError::RefMismatch);
        }
        if self.scan_id != scope.scan_id {
            return Err(SemgrepError::ScanMismatch);
        }
        if self.commit_sha != scope.commit_sha {
            return Err(SemgrepError::CommitMismatch);
        }
        self.rule.validate(scope)?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSnapshot {
    pub organization_id: String,
    pub organization_slug: String,
    pub project_id: String,
    pub repository: RepositoryIdentity,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub commit_sha: String,
    pub permissions: BTreeSet<SemgrepPermission>,
    pub project_revision: u64,
    pub project_digest: Digest,
}

#[derive(Serialize)]
struct ProjectDigestInput<'a> {
    organization_id: &'a str,
    organization_slug: &'a str,
    project_id: &'a str,
    repository: &'a RepositoryIdentity,
    git_ref: &'a str,
    commit_sha: &'a str,
    permissions: &'a BTreeSet<SemgrepPermission>,
    project_revision: u64,
}

impl ProjectSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: impl Into<String>,
        organization_slug: impl Into<String>,
        project_id: impl Into<String>,
        repository: RepositoryIdentity,
        git_ref: impl Into<String>,
        commit_sha: impl Into<String>,
        permissions: impl IntoIterator<Item = SemgrepPermission>,
        project_revision: u64,
    ) -> Result<Self, SemgrepError> {
        let mut snapshot = Self {
            organization_id: organization_id.into(),
            organization_slug: organization_slug.into(),
            project_id: project_id.into(),
            repository,
            git_ref: git_ref.into(),
            commit_sha: commit_sha.into(),
            permissions: permissions.into_iter().collect(),
            project_revision,
            project_digest: Digest::from_text("uncomputed"),
        };
        snapshot.validate_shape()?;
        snapshot.project_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn for_scope(scope: &SemgrepSecurityScope) -> Result<Self, SemgrepError> {
        Self::new(
            scope.organization_id.clone(),
            scope.organization_slug.clone(),
            scope.project_id.clone(),
            scope.repository.clone(),
            scope.git_ref.clone(),
            scope.commit_sha.clone(),
            scope.permissions.clone(),
            scope.mission.project_revision,
        )
    }

    fn validate_shape(&self) -> Result<(), SemgrepError> {
        validate_identifier(
            "project organization",
            &self.organization_id,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_identifier(
            "project organization slug",
            &self.organization_slug,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_identifier("project id", &self.project_id, MAX_IDENTIFIER_BYTES)?;
        self.repository.validate()?;
        validate_bounded_text("project ref", &self.git_ref, MAX_REF_BYTES)?;
        validate_commit_sha(&self.commit_sha)?;
        if self.project_revision == 0 {
            return Err(SemgrepError::InvalidInput("project revision"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ProjectDigestInput {
            organization_id: &self.organization_id,
            organization_slug: &self.organization_slug,
            project_id: &self.project_id,
            repository: &self.repository,
            git_ref: &self.git_ref,
            commit_sha: &self.commit_sha,
            permissions: &self.permissions,
            project_revision: self.project_revision,
        })
    }

    pub fn validate(&self, scope: &SemgrepSecurityScope) -> Result<(), SemgrepError> {
        self.validate_shape()?;
        if self.project_digest != self.compute_digest() {
            return Err(SemgrepError::PayloadTampered);
        }
        if self.organization_id != scope.organization_id
            || self.organization_slug != scope.organization_slug
        {
            return Err(SemgrepError::OrganizationMismatch);
        }
        if self.project_id != scope.project_id {
            return Err(SemgrepError::ProjectMismatch);
        }
        if self.repository != scope.repository {
            return Err(SemgrepError::RepositoryMismatch);
        }
        if self.git_ref != scope.git_ref {
            return Err(SemgrepError::RefMismatch);
        }
        if self.commit_sha != scope.commit_sha {
            return Err(SemgrepError::CommitMismatch);
        }
        if self.permissions != scope.permissions {
            return Err(SemgrepError::PermissionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanSnapshot {
    pub scan_id: String,
    pub project_id: String,
    pub repository: RepositoryIdentity,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub commit_sha: String,
    pub rule_revision_digest: Digest,
    pub finding_types: BTreeSet<SemgrepFindingType>,
    pub status: ScanStatus,
    pub scan_revision_digest: Digest,
    pub scan_digest: Digest,
}

#[derive(Serialize)]
struct ScanDigestInput<'a> {
    scan_id: &'a str,
    project_id: &'a str,
    repository: &'a RepositoryIdentity,
    git_ref: &'a str,
    commit_sha: &'a str,
    rule_revision_digest: &'a Digest,
    finding_types: &'a BTreeSet<SemgrepFindingType>,
    status: ScanStatus,
    scan_revision_digest: &'a Digest,
}

impl ScanSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scan_id: impl Into<String>,
        project_id: impl Into<String>,
        repository: RepositoryIdentity,
        git_ref: impl Into<String>,
        commit_sha: impl Into<String>,
        rule_revision_digest: Digest,
        finding_types: impl IntoIterator<Item = SemgrepFindingType>,
        status: ScanStatus,
    ) -> Result<Self, SemgrepError> {
        let scan_id = scan_id.into();
        let project_id = project_id.into();
        let git_ref = git_ref.into();
        let commit_sha = commit_sha.into();
        let finding_types = finding_types.into_iter().collect();
        let scan_revision_digest = Digest::from_serializable(&(
            &scan_id,
            &project_id,
            &repository,
            &git_ref,
            &commit_sha,
            &rule_revision_digest,
            &finding_types,
        ));
        let mut snapshot = Self {
            scan_id,
            project_id,
            repository,
            git_ref,
            commit_sha,
            rule_revision_digest,
            finding_types,
            status,
            scan_revision_digest,
            scan_digest: Digest::from_text("uncomputed"),
        };
        snapshot.validate_shape()?;
        snapshot.scan_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn for_scope(
        scope: &SemgrepSecurityScope,
        status: ScanStatus,
    ) -> Result<Self, SemgrepError> {
        Self::new(
            scope.scan_id.clone(),
            scope.project_id.clone(),
            scope.repository.clone(),
            scope.git_ref.clone(),
            scope.commit_sha.clone(),
            scope.rule_revision_digest.clone(),
            scope.finding_types.clone(),
            status,
        )
    }

    fn validate_shape(&self) -> Result<(), SemgrepError> {
        validate_identifier("scan id", &self.scan_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("scan project", &self.project_id, MAX_IDENTIFIER_BYTES)?;
        self.repository.validate()?;
        validate_bounded_text("scan ref", &self.git_ref, MAX_REF_BYTES)?;
        validate_commit_sha(&self.commit_sha)?;
        if !self.rule_revision_digest.is_valid() || !self.scan_revision_digest.is_valid() {
            return Err(SemgrepError::InvalidDigest);
        }
        if self.finding_types.is_empty() || self.finding_types.len() > MAX_FINDING_TYPES {
            return Err(SemgrepError::InvalidInput("scan finding types"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ScanDigestInput {
            scan_id: &self.scan_id,
            project_id: &self.project_id,
            repository: &self.repository,
            git_ref: &self.git_ref,
            commit_sha: &self.commit_sha,
            rule_revision_digest: &self.rule_revision_digest,
            finding_types: &self.finding_types,
            status: self.status,
            scan_revision_digest: &self.scan_revision_digest,
        })
    }

    pub fn validate(&self, scope: &SemgrepSecurityScope) -> Result<(), SemgrepError> {
        self.validate_shape()?;
        if self.scan_digest != self.compute_digest() {
            return Err(SemgrepError::PayloadTampered);
        }
        if self.scan_id != scope.scan_id {
            return Err(SemgrepError::ScanMismatch);
        }
        if self.project_id != scope.project_id {
            return Err(SemgrepError::ProjectMismatch);
        }
        if self.repository != scope.repository {
            return Err(SemgrepError::RepositoryMismatch);
        }
        if self.git_ref != scope.git_ref {
            return Err(SemgrepError::RefMismatch);
        }
        if self.commit_sha != scope.commit_sha {
            return Err(SemgrepError::CommitMismatch);
        }
        if self.rule_revision_digest != scope.rule_revision_digest {
            return Err(SemgrepError::RuleMismatch);
        }
        if self.finding_types != scope.finding_types {
            return Err(SemgrepError::FindingTypeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemgrepPayload<T> {
    pub payload: T,
    pub response_bytes: usize,
    pub payload_digest: Digest,
    pub redacted: bool,
    pub truncated: bool,
}

impl<T: Serialize> SemgrepPayload<T> {
    pub fn new(payload: T) -> Self {
        let response_bytes = serialized_size(&payload);
        Self {
            payload_digest: Digest::from_serializable(&payload),
            payload,
            response_bytes,
            redacted: true,
            truncated: false,
        }
    }

    pub fn with_transport_metadata(
        payload: T,
        response_bytes: usize,
        payload_digest: Digest,
        redacted: bool,
        truncated: bool,
    ) -> Self {
        Self {
            payload,
            response_bytes,
            payload_digest,
            redacted,
            truncated,
        }
    }

    #[must_use]
    pub fn with_metadata(
        mut self,
        response_bytes: usize,
        payload_digest: Digest,
        redacted: bool,
        truncated: bool,
    ) -> Self {
        self.response_bytes = response_bytes;
        self.payload_digest = payload_digest;
        self.redacted = redacted;
        self.truncated = truncated;
        self
    }

    fn verify(&self, limits: ReadLimits) -> Result<(), SemgrepError> {
        if self.truncated {
            return Err(SemgrepError::PayloadTruncated);
        }
        if !self.redacted {
            return Err(SemgrepError::PayloadNotRedacted);
        }
        if self.response_bytes > limits.max_response_bytes {
            return Err(SemgrepError::ResponseTooLarge);
        }
        if self.payload_digest != Digest::from_serializable(&self.payload) {
            return Err(SemgrepError::PayloadTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemgrepPage<T> {
    pub page: usize,
    pub page_size: usize,
    pub previous_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub next_page: Option<usize>,
    pub items: Vec<T>,
    pub response_bytes: usize,
    pub page_digest: Digest,
    pub redacted: bool,
    pub truncated: bool,
}

impl<T: Serialize> SemgrepPage<T> {
    pub fn new(
        page: usize,
        previous_cursor: Option<String>,
        next_cursor: Option<String>,
        items: Vec<T>,
    ) -> Self {
        let page_size = items.len();
        let page_digest = Self::compute_digest_for(
            page,
            page_size,
            previous_cursor.as_deref(),
            next_cursor.as_deref(),
            None,
            &items,
        );
        let response_bytes = serialized_size(&items);
        Self {
            page,
            page_size,
            previous_cursor,
            next_cursor,
            next_page: None,
            items,
            response_bytes,
            page_digest,
            redacted: true,
            truncated: false,
        }
    }

    #[must_use]
    pub fn with_next_page(mut self, next_page: Option<usize>) -> Self {
        self.next_page = next_page;
        self.page_digest = self.compute_digest();
        self
    }

    #[must_use]
    pub fn with_transport_metadata(
        mut self,
        response_bytes: usize,
        page_digest: Digest,
        redacted: bool,
        truncated: bool,
    ) -> Self {
        self.response_bytes = response_bytes;
        self.page_digest = page_digest;
        self.redacted = redacted;
        self.truncated = truncated;
        self
    }

    fn compute_digest_for(
        page: usize,
        page_size: usize,
        previous_cursor: Option<&str>,
        next_cursor: Option<&str>,
        next_page: Option<usize>,
        items: &[T],
    ) -> Digest {
        Digest::from_serializable(&(
            page,
            page_size,
            previous_cursor,
            next_cursor,
            next_page,
            items,
        ))
    }

    fn compute_digest(&self) -> Digest {
        Self::compute_digest_for(
            self.page,
            self.page_size,
            self.previous_cursor.as_deref(),
            self.next_cursor.as_deref(),
            self.next_page,
            &self.items,
        )
    }

    fn verify(
        &self,
        expected_page: usize,
        expected_cursor: Option<&str>,
        limits: ReadLimits,
    ) -> Result<(), SemgrepError> {
        if self.truncated {
            return Err(SemgrepError::PayloadTruncated);
        }
        if !self.redacted {
            return Err(SemgrepError::PayloadNotRedacted);
        }
        if self.response_bytes > limits.max_response_bytes {
            return Err(SemgrepError::ResponseTooLarge);
        }
        if self.page != expected_page || self.previous_cursor.as_deref() != expected_cursor {
            return Err(SemgrepError::PaginationDrift);
        }
        if self.page_size != self.items.len() || self.page_size > limits.max_page_items {
            return Err(SemgrepError::PageTooLarge);
        }
        if self.page_digest != self.compute_digest() {
            return Err(SemgrepError::PayloadTampered);
        }
        if self
            .next_page
            .is_some_and(|next_page| next_page <= self.page)
        {
            return Err(SemgrepError::PaginationDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadLimits {
    pub max_response_bytes: usize,
    pub max_page_items: usize,
    pub max_pages: usize,
    pub max_total_findings: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_page_items: MAX_PAGE_ITEMS,
            max_pages: MAX_PAGE_COUNT,
            max_total_findings: MAX_FINDINGS,
        }
    }
}

impl ReadLimits {
    fn validate(self) -> Result<Self, SemgrepError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_page_items == 0
            || self.max_page_items > MAX_PAGE_ITEMS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGE_COUNT
            || self.max_total_findings == 0
            || self.max_total_findings > MAX_FINDINGS
        {
            return Err(SemgrepError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    DescribeOrganizationProject,
    ReadScan,
    ReadFindings,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemgrepReadRequest {
    pub operation: ReadOperation,
    pub api_version: SemgrepApiVersion,
    pub api_host: String,
    pub organization_id: String,
    pub organization_slug: String,
    pub project_id: String,
    pub repository_digest: Digest,
    #[serde(rename = "refDigest")]
    pub git_ref_digest: Digest,
    pub scan_id: String,
    pub finding_type: Option<SemgrepFindingType>,
    pub page: Option<usize>,
    pub cursor: Option<String>,
    pub page_size: usize,
}

impl SemgrepReadRequest {
    fn for_scope(
        scope: &SemgrepSecurityScope,
        operation: ReadOperation,
        finding_type: Option<SemgrepFindingType>,
        page: Option<usize>,
        cursor: Option<String>,
        page_size: usize,
    ) -> Self {
        Self {
            operation,
            api_version: scope.api_version,
            api_host: scope.api_host.clone(),
            organization_id: scope.organization_id.clone(),
            organization_slug: scope.organization_slug.clone(),
            project_id: scope.project_id.clone(),
            repository_digest: scope.repository_digest(),
            git_ref_digest: scope.ref_digest(),
            scan_id: scope.scan_id.clone(),
            finding_type,
            page,
            cursor,
            page_size,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemgrepRequestAudit {
    pub operation: ReadOperation,
    pub api_host: String,
    pub organization_id: String,
    pub organization_slug: String,
    pub project_id: String,
    pub repository_digest: Digest,
    #[serde(rename = "refDigest")]
    pub git_ref_digest: Digest,
    pub scan_id: String,
    pub finding_type: Option<SemgrepFindingType>,
    pub page: Option<usize>,
    pub cursor: Option<String>,
    pub page_size: usize,
    pub secret_reference_digest: Digest,
    pub transport: TransportKind,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl SemgrepRequestAudit {
    fn from_request(
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
        transport: TransportKind,
    ) -> Self {
        Self {
            operation: request.operation.clone(),
            api_host: request.api_host.clone(),
            organization_id: request.organization_id.clone(),
            organization_slug: request.organization_slug.clone(),
            project_id: request.project_id.clone(),
            repository_digest: request.repository_digest.clone(),
            git_ref_digest: request.git_ref_digest.clone(),
            scan_id: request.scan_id.clone(),
            finding_type: request.finding_type,
            page: request.page,
            cursor: request.cursor.clone(),
            page_size: request.page_size,
            secret_reference_digest: secret_reference.reference_digest(),
            transport,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SemgrepTransportError {
    #[error("Semgrep HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("Semgrep transport timed out")]
    Timeout,
    #[error("Semgrep live environment is blocked")]
    BlockedEnv,
    #[error("recorded Semgrep response queue is exhausted")]
    RecordingExhausted,
    #[error("recorded Semgrep response kind was unexpected")]
    UnexpectedResponse,
}

pub trait SemgrepTransport {
    fn kind(&self) -> TransportKind;

    fn describe_project(
        &mut self,
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<SemgrepPayload<ProjectSnapshot>, SemgrepTransportError>;

    fn read_scan(
        &mut self,
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<SemgrepPayload<ScanSnapshot>, SemgrepTransportError>;

    fn read_findings(
        &mut self,
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<SemgrepPage<Finding>, SemgrepTransportError>;
}

enum RecordedResponse {
    Project(Result<SemgrepPayload<ProjectSnapshot>, SemgrepTransportError>),
    Scan(Result<SemgrepPayload<ScanSnapshot>, SemgrepTransportError>),
    Findings(Result<SemgrepPage<Finding>, SemgrepTransportError>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordedResponseKind {
    Project,
    Scan,
    Findings,
}

impl RecordedResponse {
    const fn kind(&self) -> RecordedResponseKind {
        match self {
            Self::Project(_) => RecordedResponseKind::Project,
            Self::Scan(_) => RecordedResponseKind::Scan,
            Self::Findings(_) => RecordedResponseKind::Findings,
        }
    }
}

pub struct RecordingSemgrepTransport {
    kind: TransportKind,
    responses: VecDeque<RecordedResponse>,
    requests: Vec<SemgrepRequestAudit>,
    forced_error: Option<SemgrepTransportError>,
}

impl fmt::Debug for RecordingSemgrepTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingSemgrepTransport")
            .field("kind", &self.kind)
            .field("queued_responses", &self.responses.len())
            .field("requests", &self.requests)
            .field("forced_error", &self.forced_error)
            .finish()
    }
}

impl RecordingSemgrepTransport {
    pub fn new(kind: TransportKind) -> Result<Self, SemgrepError> {
        if kind == TransportKind::BlockedEnv {
            return Ok(Self::blocked_env());
        }
        Ok(Self {
            kind,
            responses: VecDeque::new(),
            requests: Vec::new(),
            forced_error: None,
        })
    }

    pub fn fixture() -> Self {
        Self::new(TransportKind::Fixture).expect("fixture transport kind is valid")
    }

    pub fn recording() -> Self {
        Self::new(TransportKind::Recording).expect("recording transport kind is valid")
    }

    pub fn fake() -> Self {
        Self::new(TransportKind::Fake).expect("fake transport kind is valid")
    }

    pub fn loopback() -> Self {
        Self::new(TransportKind::Loopback).expect("loopback transport kind is valid")
    }

    pub fn blocked_env() -> Self {
        Self {
            kind: TransportKind::BlockedEnv,
            responses: VecDeque::new(),
            requests: Vec::new(),
            forced_error: Some(SemgrepTransportError::BlockedEnv),
        }
    }

    pub fn fail_with(&mut self, error: SemgrepTransportError) {
        self.forced_error = Some(error);
    }

    pub fn push_project_response(
        &mut self,
        response: Result<SemgrepPayload<ProjectSnapshot>, SemgrepTransportError>,
    ) {
        self.responses
            .push_back(RecordedResponse::Project(response));
    }

    pub fn push_scan_response(
        &mut self,
        response: Result<SemgrepPayload<ScanSnapshot>, SemgrepTransportError>,
    ) {
        self.responses.push_back(RecordedResponse::Scan(response));
    }

    pub fn push_findings_response(
        &mut self,
        response: Result<SemgrepPage<Finding>, SemgrepTransportError>,
    ) {
        self.responses
            .push_back(RecordedResponse::Findings(response));
    }

    pub fn requests(&self) -> &[SemgrepRequestAudit] {
        &self.requests
    }

    fn take(
        &mut self,
        expected: RecordedResponseKind,
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<RecordedResponse, SemgrepTransportError> {
        self.requests.push(SemgrepRequestAudit::from_request(
            request,
            secret_reference,
            self.kind,
        ));
        if let Some(error) = self.forced_error {
            return Err(error);
        }
        let response = self
            .responses
            .pop_front()
            .ok_or(SemgrepTransportError::RecordingExhausted)?;
        if response.kind() == expected {
            Ok(response)
        } else {
            Err(SemgrepTransportError::UnexpectedResponse)
        }
    }
}

impl SemgrepTransport for RecordingSemgrepTransport {
    fn kind(&self) -> TransportKind {
        self.kind
    }

    fn describe_project(
        &mut self,
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<SemgrepPayload<ProjectSnapshot>, SemgrepTransportError> {
        match self.take(RecordedResponseKind::Project, request, secret_reference)? {
            RecordedResponse::Project(response) => response,
            _ => Err(SemgrepTransportError::UnexpectedResponse),
        }
    }

    fn read_scan(
        &mut self,
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<SemgrepPayload<ScanSnapshot>, SemgrepTransportError> {
        match self.take(RecordedResponseKind::Scan, request, secret_reference)? {
            RecordedResponse::Scan(response) => response,
            _ => Err(SemgrepTransportError::UnexpectedResponse),
        }
    }

    fn read_findings(
        &mut self,
        request: &SemgrepReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<SemgrepPage<Finding>, SemgrepTransportError> {
        match self.take(RecordedResponseKind::Findings, request, secret_reference)? {
            RecordedResponse::Findings(response) => response,
            _ => Err(SemgrepTransportError::UnexpectedResponse),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PagedFindings {
    pub items: Vec<Finding>,
    pub pages_read: usize,
    pub total_items: usize,
}

#[derive(Clone, Debug)]
pub struct SemgrepProvider<T> {
    transport: T,
    limits: ReadLimits,
}

impl<T: SemgrepTransport> SemgrepProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            limits: ReadLimits::default(),
        }
    }

    pub fn with_limits(transport: T, limits: ReadLimits) -> Result<Self, SemgrepError> {
        Ok(Self {
            transport,
            limits: limits.validate()?,
        })
    }

    pub fn transport_kind(&self) -> TransportKind {
        self.transport.kind()
    }

    pub fn limits(&self) -> ReadLimits {
        self.limits
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_project(
        &mut self,
        scope: &SemgrepSecurityScope,
        secret_reference: &SecretReference,
    ) -> Result<ProjectSnapshot, SemgrepError> {
        Self::validate_secret(scope, secret_reference)?;
        let request = SemgrepReadRequest::for_scope(
            scope,
            ReadOperation::DescribeOrganizationProject,
            None,
            None,
            None,
            self.limits.max_page_items,
        );
        let response = self
            .transport
            .describe_project(&request, secret_reference)
            .map_err(SemgrepError::from_transport)?;
        response.verify(self.limits)?;
        response.payload.validate(scope)?;
        Ok(response.payload)
    }

    pub fn read_scan(
        &mut self,
        scope: &SemgrepSecurityScope,
        secret_reference: &SecretReference,
    ) -> Result<ScanSnapshot, SemgrepError> {
        Self::validate_secret(scope, secret_reference)?;
        let request = SemgrepReadRequest::for_scope(
            scope,
            ReadOperation::ReadScan,
            None,
            None,
            None,
            self.limits.max_page_items,
        );
        let response = self
            .transport
            .read_scan(&request, secret_reference)
            .map_err(SemgrepError::from_transport)?;
        response.verify(self.limits)?;
        response.payload.validate(scope)?;
        Ok(response.payload)
    }

    pub fn read_findings(
        &mut self,
        scope: &SemgrepSecurityScope,
        secret_reference: &SecretReference,
    ) -> Result<PagedFindings, SemgrepError> {
        Self::validate_secret(scope, secret_reference)?;
        let mut items = Vec::new();
        let mut pages_read = 0;
        let mut seen_ids = BTreeSet::new();
        let mut seen_fingerprints = BTreeSet::new();

        for finding_type in &scope.finding_types {
            let mut page = 0;
            let mut cursor: Option<String> = None;
            let mut seen_cursors = BTreeSet::new();
            loop {
                if pages_read >= self.limits.max_pages {
                    return Err(SemgrepError::PaginationLimit);
                }
                if let Some(cursor_value) = &cursor
                    && !seen_cursors.insert(Some(cursor_value.clone()))
                {
                    return Err(SemgrepError::PaginationRepeatedCursor);
                }
                let request = SemgrepReadRequest::for_scope(
                    scope,
                    ReadOperation::ReadFindings,
                    Some(*finding_type),
                    Some(page),
                    cursor.clone(),
                    self.limits.max_page_items,
                );
                let response = self
                    .transport
                    .read_findings(&request, secret_reference)
                    .map_err(SemgrepError::from_transport)?;
                response.verify(page, cursor.as_deref(), self.limits)?;
                for finding in &response.items {
                    finding.validate(scope)?;
                    if finding.finding_type != *finding_type {
                        return Err(SemgrepError::FindingTypeMismatch);
                    }
                    if !seen_ids.insert(finding.finding_id.clone())
                        || !seen_fingerprints.insert(finding.fingerprint.clone())
                    {
                        return Err(SemgrepError::DuplicateFinding);
                    }
                }
                if items.len().saturating_add(response.items.len()) > self.limits.max_total_findings
                {
                    return Err(SemgrepError::EvidenceTooLarge);
                }
                items.extend(response.items);
                pages_read += 1;

                let next_page = response.next_page;
                let next_cursor = response.next_cursor;
                if next_page.is_none() && next_cursor.is_none() {
                    break;
                }
                if let Some(next) = next_page {
                    page = next;
                } else {
                    page = page.saturating_add(1);
                }
                if let Some(next) = next_cursor {
                    if seen_cursors.contains(&Some(next.clone())) {
                        return Err(SemgrepError::PaginationRepeatedCursor);
                    }
                    cursor = Some(next);
                } else {
                    cursor = None;
                }
            }
        }

        Ok(PagedFindings {
            total_items: items.len(),
            items,
            pages_read,
        })
    }

    pub fn list_findings(
        &mut self,
        scope: &SemgrepSecurityScope,
        secret_reference: &SecretReference,
    ) -> Result<PagedFindings, SemgrepError> {
        self.read_findings(scope, secret_reference)
    }

    fn validate_secret(
        scope: &SemgrepSecurityScope,
        secret_reference: &SecretReference,
    ) -> Result<(), SemgrepError> {
        if !secret_reference.is_bound_to(scope) {
            return if secret_reference.is_revoked() {
                Err(SemgrepError::SecretRevoked)
            } else {
                Err(SemgrepError::SecretScopeMismatch)
            };
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOrigin {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl From<TransportKind> for EvidenceOrigin {
    fn from(kind: TransportKind) -> Self {
        match kind {
            TransportKind::Fixture => Self::Fixture,
            TransportKind::Recording => Self::Recording,
            TransportKind::Fake => Self::Fake,
            TransportKind::Loopback => Self::Loopback,
            TransportKind::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct EvidenceProvenance {
    pub origin: EvidenceOrigin,
    pub recording_only: bool,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl EvidenceProvenance {
    fn layer1(kind: TransportKind) -> Self {
        Self {
            origin: kind.into(),
            recording_only: true,
            redacted: true,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingSummary {
    pub total_findings: usize,
    pub by_type: BTreeMap<SemgrepFindingType, usize>,
    pub by_status: BTreeMap<FindingStatus, usize>,
    pub by_severity: BTreeMap<Severity, usize>,
    pub high_risk_actionable: usize,
    pub uncertain_reachability: usize,
    pub summary_digest: Digest,
}

impl FindingSummary {
    fn from_items(items: &[Finding]) -> Self {
        let mut summary = Self {
            total_findings: items.len(),
            by_type: BTreeMap::new(),
            by_status: BTreeMap::new(),
            by_severity: BTreeMap::new(),
            high_risk_actionable: 0,
            uncertain_reachability: 0,
            summary_digest: Digest::from_text("uncomputed"),
        };
        for finding in items {
            *summary.by_type.entry(finding.finding_type).or_default() += 1;
            *summary.by_status.entry(finding.status).or_default() += 1;
            *summary.by_severity.entry(finding.severity).or_default() += 1;
            if finding.status.is_actionable() && finding.severity.is_high_or_critical() {
                summary.high_risk_actionable += 1;
            }
            if finding.reachability.is_some_and(|value| {
                matches!(
                    value,
                    Reachability::ConditionallyReachable | Reachability::Unknown
                )
            }) {
                summary.uncertain_reachability += 1;
            }
        }
        summary.summary_digest = Digest::from_serializable(&(
            summary.total_findings,
            &summary.by_type,
            &summary.by_status,
            &summary.by_severity,
            summary.high_risk_actionable,
            summary.uncertain_reachability,
        ));
        summary
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityEvidence {
    pub schema_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectSnapshot,
    pub scan: ScanSnapshot,
    pub findings: Vec<Finding>,
    pub summary: FindingSummary,
    pub pages_read: usize,
    pub observed_at_epoch_seconds: u64,
    pub projection: SecurityProjection,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    schema_version: &'a str,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    project: &'a ProjectSnapshot,
    scan: &'a ScanSnapshot,
    findings: &'a [Finding],
    summary: &'a FindingSummary,
    pages_read: usize,
    observed_at_epoch_seconds: u64,
    projection: SecurityProjection,
    provenance: &'a EvidenceProvenance,
}

impl SecurityEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &SemgrepRegistration,
        scope: &SemgrepSecurityScope,
        project: ProjectSnapshot,
        scan: ScanSnapshot,
        findings: Vec<Finding>,
        pages_read: usize,
        observed_at_epoch_seconds: u64,
        transport_kind: TransportKind,
    ) -> Result<Self, SemgrepError> {
        if findings.len() > MAX_FINDINGS || pages_read > MAX_PAGE_COUNT {
            return Err(SemgrepError::EvidenceTooLarge);
        }
        let summary = FindingSummary::from_items(&findings);
        let projection = if scan.status != ScanStatus::Completed {
            SecurityProjection::Incomplete
        } else if findings.is_empty() {
            SecurityProjection::NoFindings
        } else {
            SecurityProjection::FindingsPresent
        };
        let provenance = EvidenceProvenance::layer1(transport_kind);
        let mut evidence = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.scope_digest(),
            project,
            scan,
            findings,
            summary,
            pages_read,
            observed_at_epoch_seconds,
            projection,
            provenance,
            evidence_digest: Digest::from_text("uncomputed"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceDigestInput {
            schema_version: &self.schema_version,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            project: &self.project,
            scan: &self.scan,
            findings: &self.findings,
            summary: &self.summary,
            pages_read: self.pages_read,
            observed_at_epoch_seconds: self.observed_at_epoch_seconds,
            projection: self.projection,
            provenance: &self.provenance,
        })
    }

    pub fn validate(
        &self,
        scope: &SemgrepSecurityScope,
        registration: &SemgrepRegistration,
    ) -> Result<(), SemgrepError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != scope.scope_digest()
            || self.evidence_digest != self.compute_digest()
            || !self.provenance.recording_only
            || !self.provenance.redacted
            || self.provenance.connected
            || self.provenance.native
            || self.provenance.first_party
        {
            return Err(SemgrepError::EvidenceTampered);
        }
        if self.findings.len() > MAX_FINDINGS || self.pages_read > MAX_PAGE_COUNT {
            return Err(SemgrepError::EvidenceTooLarge);
        }
        self.project.validate(scope)?;
        self.scan.validate(scope)?;
        for finding in &self.findings {
            finding.validate(scope)?;
        }
        if self.summary != FindingSummary::from_items(&self.findings) {
            return Err(SemgrepError::EvidenceTampered);
        }
        let expected_projection = if self.scan.status != ScanStatus::Completed {
            SecurityProjection::Incomplete
        } else if self.findings.is_empty() {
            SecurityProjection::NoFindings
        } else {
            SecurityProjection::FindingsPresent
        };
        if self.projection != expected_projection {
            return Err(SemgrepError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecurityDecisionProposal {
    pub schema_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub mission: MissionScopeBinding,
    pub decision: SecurityDecision,
    pub reason_digest: Digest,
    pub summary: FindingSummary,
    pub adoption: AdoptionDisposition,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProposalDigestInput<'a> {
    schema_version: &'a str,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    mission: &'a MissionScopeBinding,
    decision: SecurityDecision,
    reason_digest: &'a Digest,
    summary: &'a FindingSummary,
    adoption: AdoptionDisposition,
    redacted: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl SecurityDecisionProposal {
    fn from_evidence(
        evidence: &SecurityEvidence,
        scope: &SemgrepSecurityScope,
        registration: &SemgrepRegistration,
    ) -> Result<Self, SemgrepError> {
        evidence.validate(scope, registration)?;
        let decision = decision_for_evidence(evidence);
        let reason_digest = Digest::from_serializable(&(
            decision,
            evidence.projection,
            &evidence.summary,
            &evidence.scan.scan_revision_digest,
        ));
        let mut proposal = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.scope_digest(),
            evidence_digest: evidence.evidence_digest.clone(),
            mission: scope.mission.clone(),
            decision,
            reason_digest,
            summary: evidence.summary.clone(),
            adoption: if matches!(
                evidence.projection,
                SecurityProjection::NoFindings | SecurityProjection::FindingsPresent
            ) {
                AdoptionDisposition::Layer2Required
            } else {
                AdoptionDisposition::BlockedByProjection
            },
            redacted: true,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest: Digest::from_text("uncomputed"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalDigestInput {
            schema_version: &self.schema_version,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            mission: &self.mission,
            decision: self.decision,
            reason_digest: &self.reason_digest,
            summary: &self.summary,
            adoption: self.adoption,
            redacted: self.redacted,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate(
        &self,
        scope: &SemgrepSecurityScope,
        registration: &SemgrepRegistration,
    ) -> Result<(), SemgrepError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != scope.scope_digest()
            || self.mission != scope.mission
            || self.proposal_digest != self.compute_digest()
            || !self.redacted
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(SemgrepError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityReceiptArtifactKind {
    Evidence,
    Proposal,
}

pub trait SecurityReceiptArtifact {
    fn artifact_kind(&self) -> SecurityReceiptArtifactKind;
    fn artifact_digest(&self) -> &Digest;
    fn evidence_digest(&self) -> &Digest;
    fn proposal_digest(&self) -> Option<&Digest>;
    fn registration_digest(&self) -> &Digest;
    fn scope_digest(&self) -> &Digest;
    fn validate_for_receipt(
        &self,
        scope: &SemgrepSecurityScope,
        registration: &SemgrepRegistration,
    ) -> Result<(), SemgrepError>;
}

impl SecurityReceiptArtifact for SecurityEvidence {
    fn artifact_kind(&self) -> SecurityReceiptArtifactKind {
        SecurityReceiptArtifactKind::Evidence
    }

    fn artifact_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn proposal_digest(&self) -> Option<&Digest> {
        None
    }

    fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    fn validate_for_receipt(
        &self,
        scope: &SemgrepSecurityScope,
        registration: &SemgrepRegistration,
    ) -> Result<(), SemgrepError> {
        self.validate(scope, registration)
    }
}

impl SecurityReceiptArtifact for SecurityDecisionProposal {
    fn artifact_kind(&self) -> SecurityReceiptArtifactKind {
        SecurityReceiptArtifactKind::Proposal
    }

    fn artifact_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn proposal_digest(&self) -> Option<&Digest> {
        Some(&self.proposal_digest)
    }

    fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    fn validate_for_receipt(
        &self,
        scope: &SemgrepSecurityScope,
        registration: &SemgrepRegistration,
    ) -> Result<(), SemgrepError> {
        self.validate(scope, registration)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingDisposition {
    Fresh,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecurityReceiptRecording {
    pub schema_version: String,
    pub artifact_kind: SecurityReceiptArtifactKind,
    pub artifact_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Option<Digest>,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub disposition: RecordingDisposition,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

impl SecurityReceiptRecording {
    fn new<A: SecurityReceiptArtifact>(artifact: &A, disposition: RecordingDisposition) -> Self {
        let mut recording = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            artifact_kind: artifact.artifact_kind(),
            artifact_digest: artifact.artifact_digest().clone(),
            evidence_digest: artifact.evidence_digest().clone(),
            proposal_digest: artifact.proposal_digest().cloned(),
            registration_digest: artifact.registration_digest().clone(),
            scope_digest: artifact.scope_digest().clone(),
            disposition,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::from_text("uncomputed"),
        };
        recording.receipt_digest = recording.compute_digest();
        recording
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.schema_version,
            self.artifact_kind,
            &self.artifact_digest,
            &self.evidence_digest,
            &self.proposal_digest,
            &self.registration_digest,
            &self.scope_digest,
            self.durable,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate(&self) -> Result<(), SemgrepError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.receipt_digest != self.compute_digest()
            || !self.artifact_digest.is_valid()
            || !self.evidence_digest.is_valid()
            || self
                .proposal_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_valid())
            || !self.registration_digest.is_valid()
            || !self.scope_digest.is_valid()
            || self.durable
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(SemgrepError::RecordingTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConsumptionDisposition {
    Fresh,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MissionSecurityResult {
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub proposal_digest: Digest,
    pub decision: SecurityDecision,
    pub disposition: MissionConsumptionDisposition,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug)]
pub struct MissionSemgrepSecurityConsumer {
    binding: MissionScopeBinding,
    scope_digest: Digest,
    consumed: BTreeSet<Digest>,
    active: bool,
}

impl MissionSemgrepSecurityConsumer {
    pub fn new(scope: &SemgrepSecurityScope) -> Result<Self, SemgrepError> {
        scope.validate()?;
        Ok(Self {
            binding: scope.mission.clone(),
            scope_digest: scope.scope_digest(),
            consumed: BTreeSet::new(),
            active: true,
        })
    }

    pub fn binding(&self) -> &MissionScopeBinding {
        &self.binding
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn unmount(&mut self) {
        self.active = false;
    }

    pub fn remount(&mut self) {
        self.active = true;
    }

    pub fn revoke(&mut self) {
        self.active = false;
    }

    pub fn consume(
        &mut self,
        proposal: &SecurityDecisionProposal,
    ) -> Result<MissionSecurityResult, SemgrepError> {
        if !self.active {
            return Err(SemgrepError::ConsumerInactive);
        }
        if proposal.mission.project_id != self.binding.project_id
            || proposal.mission.mission_id != self.binding.mission_id
            || proposal.mission.work_product_id != self.binding.work_product_id
        {
            return Err(SemgrepError::MissionScopeMismatch);
        }
        if proposal.mission.project_revision != self.binding.project_revision
            || proposal.mission.mission_revision != self.binding.mission_revision
            || proposal.mission.work_product_revision != self.binding.work_product_revision
        {
            return Err(SemgrepError::StaleMissionRevision);
        }
        if proposal.scope_digest != self.scope_digest {
            return Err(SemgrepError::MissionScopeMismatch);
        }
        if proposal.schema_version != CONTRACT_SCHEMA
            || proposal.proposal_digest != proposal.compute_digest()
            || !proposal.redacted
            || proposal.connected
            || proposal.native
            || proposal.first_party
        {
            return Err(SemgrepError::ProposalTampered);
        }
        let disposition = if self.consumed.insert(proposal.proposal_digest.clone()) {
            MissionConsumptionDisposition::Fresh
        } else {
            MissionConsumptionDisposition::Replay
        };
        Ok(MissionSecurityResult {
            project_id: self.binding.project_id.clone(),
            mission_id: self.binding.mission_id.clone(),
            work_product_id: self.binding.work_product_id.clone(),
            project_revision: self.binding.project_revision,
            mission_revision: self.binding.mission_revision,
            work_product_revision: self.binding.work_product_revision,
            proposal_digest: proposal.proposal_digest.clone(),
            decision: proposal.decision,
            disposition,
            adopted: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemgrepSecurityReadRequest {
    pub scan_id: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub commit_sha: String,
    pub observed_at_epoch_seconds: u64,
}

impl SemgrepSecurityReadRequest {
    pub fn new(
        scan_id: impl Into<String>,
        git_ref: impl Into<String>,
        commit_sha: impl Into<String>,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, SemgrepError> {
        let request = Self {
            scan_id: scan_id.into(),
            git_ref: git_ref.into(),
            commit_sha: commit_sha.into(),
            observed_at_epoch_seconds,
        };
        request.validate_shape()?;
        Ok(request)
    }

    pub fn for_scope(
        scope: &SemgrepSecurityScope,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, SemgrepError> {
        Self::new(
            scope.scan_id.clone(),
            scope.git_ref.clone(),
            scope.commit_sha.clone(),
            observed_at_epoch_seconds,
        )
    }

    fn validate_shape(&self) -> Result<(), SemgrepError> {
        validate_identifier("read scan", &self.scan_id, MAX_IDENTIFIER_BYTES)?;
        validate_bounded_text("read ref", &self.git_ref, MAX_REF_BYTES)?;
        validate_commit_sha(&self.commit_sha)
    }

    fn validate_against(&self, scope: &SemgrepSecurityScope) -> Result<(), SemgrepError> {
        self.validate_shape()?;
        if self.scan_id != scope.scan_id {
            return Err(SemgrepError::ScanMismatch);
        }
        if self.git_ref != scope.git_ref {
            return Err(SemgrepError::RefMismatch);
        }
        if self.commit_sha != scope.commit_sha {
            return Err(SemgrepError::CommitMismatch);
        }
        Ok(())
    }
}

impl From<u64> for SemgrepSecurityReadRequest {
    fn from(observed_at_epoch_seconds: u64) -> Self {
        Self {
            scan_id: String::new(),
            git_ref: String::new(),
            commit_sha: String::new(),
            observed_at_epoch_seconds,
        }
    }
}

pub type SecurityReadRequest = SemgrepSecurityReadRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerificationProjection {
    pub verified: bool,
    pub projection: SecurityProjection,
    pub adoption: AdoptionDisposition,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub struct SemgrepSecurityResultService<T> {
    provider: SemgrepProvider<T>,
    scope: SemgrepSecurityScope,
    secret_reference: SecretReference,
    registration: SemgrepRegistration,
    recorded_artifacts: BTreeSet<Digest>,
}

impl<T: SemgrepTransport> fmt::Debug for SemgrepSecurityResultService<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemgrepSecurityResultService")
            .field("provider", &self.provider)
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("registration", &self.registration)
            .field("recorded_artifacts", &self.recorded_artifacts)
            .finish()
    }
}

impl<T: SemgrepTransport> SemgrepSecurityResultService<T> {
    pub fn new(
        provider: SemgrepProvider<T>,
        scope: SemgrepSecurityScope,
        secret_reference: SecretReference,
    ) -> Result<Self, SemgrepError> {
        let registration = SemgrepRegistration::new(&scope, &secret_reference)?;
        Ok(Self {
            provider,
            scope,
            secret_reference,
            registration,
            recorded_artifacts: BTreeSet::new(),
        })
    }

    pub fn definition() -> SemgrepSecurityServiceDefinition {
        SemgrepSecurityServiceDefinition::layer1()
    }

    pub fn scope(&self) -> &SemgrepSecurityScope {
        &self.scope
    }

    pub fn registration(&self) -> &SemgrepRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &SemgrepProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SemgrepProvider<T> {
        &mut self.provider
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn describe_organization_project(&mut self) -> Result<ProjectSnapshot, SemgrepError> {
        self.ensure_active()?;
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)?;
        self.provider
            .describe_project(&self.scope, &self.secret_reference)
    }

    pub fn describe_project(&mut self) -> Result<ProjectSnapshot, SemgrepError> {
        self.describe_organization_project()
    }

    pub fn read_security_evidence<R: Into<SemgrepSecurityReadRequest>>(
        &mut self,
        request: R,
    ) -> Result<SecurityEvidence, SemgrepError> {
        self.ensure_active()?;
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)?;
        let mut request = request.into();
        if request.scan_id.is_empty() && request.git_ref.is_empty() && request.commit_sha.is_empty()
        {
            request = SemgrepSecurityReadRequest::for_scope(
                &self.scope,
                request.observed_at_epoch_seconds,
            )?;
        }
        request.validate_against(&self.scope)?;
        let project = self
            .provider
            .describe_project(&self.scope, &self.secret_reference)?;
        let scan = self
            .provider
            .read_scan(&self.scope, &self.secret_reference)?;
        let findings = self
            .provider
            .read_findings(&self.scope, &self.secret_reference)?;
        SecurityEvidence::new(
            &self.registration,
            &self.scope,
            project,
            scan,
            findings.items,
            findings.pages_read,
            request.observed_at_epoch_seconds,
            self.provider.transport_kind(),
        )
    }

    pub fn read_scan_evidence<R: Into<SemgrepSecurityReadRequest>>(
        &mut self,
        request: R,
    ) -> Result<SecurityEvidence, SemgrepError> {
        self.read_security_evidence(request)
    }

    pub fn compile_security_decision_proposal(
        &self,
        evidence: &SecurityEvidence,
    ) -> Result<SecurityDecisionProposal, SemgrepError> {
        self.ensure_active()?;
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)?;
        SecurityDecisionProposal::from_evidence(evidence, &self.scope, &self.registration)
    }

    pub fn compile_proposal(
        &self,
        evidence: &SecurityEvidence,
    ) -> Result<SecurityDecisionProposal, SemgrepError> {
        self.compile_security_decision_proposal(evidence)
    }

    pub fn record_security_receipt<A: SecurityReceiptArtifact>(
        &mut self,
        artifact: &A,
    ) -> Result<SecurityReceiptRecording, SemgrepError> {
        self.ensure_active()?;
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)?;
        artifact.validate_for_receipt(&self.scope, &self.registration)?;
        let digest = artifact.artifact_digest().clone();
        let disposition = if self.recorded_artifacts.insert(digest) {
            RecordingDisposition::Fresh
        } else {
            RecordingDisposition::Replay
        };
        Ok(SecurityReceiptRecording::new(artifact, disposition))
    }

    pub fn record_receipt<A: SecurityReceiptArtifact>(
        &mut self,
        artifact: &A,
    ) -> Result<SecurityReceiptRecording, SemgrepError> {
        self.record_security_receipt(artifact)
    }

    pub fn verify_security_result(
        &self,
        evidence: &SecurityEvidence,
    ) -> Result<VerificationProjection, SemgrepError> {
        self.ensure_active()?;
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)?;
        evidence.validate(&self.scope, &self.registration)?;
        let verified = matches!(
            evidence.projection,
            SecurityProjection::NoFindings | SecurityProjection::FindingsPresent
        );
        Ok(VerificationProjection {
            verified,
            projection: evidence.projection,
            adoption: if verified {
                AdoptionDisposition::Layer2Required
            } else {
                AdoptionDisposition::BlockedByProjection
            },
            evidence_digest: evidence.evidence_digest.clone(),
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn projection_for_error(&self, error: &SemgrepError) -> SecurityProjection {
        match error {
            SemgrepError::AccessLoss { .. } => SecurityProjection::AccessLoss,
            SemgrepError::RegistrationRevoked | SemgrepError::SecretRevoked => {
                SecurityProjection::Revoked
            }
            SemgrepError::StaleMissionRevision
            | SemgrepError::CommitMismatch
            | SemgrepError::RefMismatch
            | SemgrepError::RuleMismatch
            | SemgrepError::ScanMismatch
            | SemgrepError::ProjectMismatch
            | SemgrepError::RepositoryMismatch => SecurityProjection::Stale,
            SemgrepError::PayloadTampered
            | SemgrepError::PayloadNotRedacted
            | SemgrepError::PayloadTruncated
            | SemgrepError::PaginationDrift
            | SemgrepError::PaginationLimit
            | SemgrepError::PaginationRepeatedCursor
            | SemgrepError::PageTooLarge
            | SemgrepError::EvidenceTooLarge
            | SemgrepError::EvidenceTampered => SecurityProjection::Incomplete,
            _ => SecurityProjection::ProviderUnknown,
        }
    }

    pub fn unmount(&mut self) -> Result<(), SemgrepError> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<(), SemgrepError> {
        self.registration.remount()
    }

    pub fn revoke(&mut self) -> RevocationReceipt {
        self.registration.revoke(&mut self.secret_reference)
    }

    fn ensure_active(&self) -> Result<(), SemgrepError> {
        if self.registration.status == RegistrationStatus::Revoked
            || self.secret_reference.is_revoked()
        {
            return Err(SemgrepError::RegistrationRevoked);
        }
        if !self.registration.is_active() {
            return Err(SemgrepError::RegistrationInactive);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SemgrepError {
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    #[error("invalid digest")]
    InvalidDigest,
    #[error("unsupported Semgrep API version")]
    UnsupportedApiVersion,
    #[error("invalid secret reference")]
    InvalidSecretReference,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("secret reference is bound to a different scope")]
    SecretScopeMismatch,
    #[error("Semgrep permission scope drift")]
    PermissionDrift,
    #[error("registration was tampered with")]
    RegistrationTampered,
    #[error("registration binding drift")]
    RegistrationBindingDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is unmounted")]
    RegistrationInactive,
    #[error("Semgrep organization mismatch")]
    OrganizationMismatch,
    #[error("Semgrep project mismatch")]
    ProjectMismatch,
    #[error("repository mismatch")]
    RepositoryMismatch,
    #[error("ref mismatch")]
    RefMismatch,
    #[error("scan mismatch")]
    ScanMismatch,
    #[error("finding mismatch")]
    FindingMismatch,
    #[error("finding type mismatch")]
    FindingTypeMismatch,
    #[error("rule revision or identity mismatch")]
    RuleMismatch,
    #[error("commit mismatch")]
    CommitMismatch,
    #[error("invalid finding location")]
    InvalidLocation,
    #[error("finding was duplicated")]
    DuplicateFinding,
    #[error("payload was tampered with")]
    PayloadTampered,
    #[error("payload was not redacted")]
    PayloadNotRedacted,
    #[error("payload was truncated")]
    PayloadTruncated,
    #[error("response exceeded the byte bound")]
    ResponseTooLarge,
    #[error("page exceeded the item bound")]
    PageTooLarge,
    #[error("evidence exceeded the item bound")]
    EvidenceTooLarge,
    #[error("pagination cursor or page drifted")]
    PaginationDrift,
    #[error("pagination limit was exceeded")]
    PaginationLimit,
    #[error("pagination repeated a cursor")]
    PaginationRepeatedCursor,
    #[error("recording was tampered with")]
    RecordingTampered,
    #[error("evidence was tampered with")]
    EvidenceTampered,
    #[error("proposal was tampered with")]
    ProposalTampered,
    #[error("mission/project/work-product scope mismatch")]
    MissionScopeMismatch,
    #[error("mission revision is stale")]
    StaleMissionRevision,
    #[error("mission consumer is inactive")]
    ConsumerInactive,
    #[error("Semgrep access was lost with HTTP status {status}")]
    AccessLoss { status: u16 },
    #[error("Semgrep resource was not found")]
    NotFound,
    #[error("Semgrep provider returned a conflict")]
    Conflict,
    #[error("Semgrep provider rate limited the read")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Semgrep provider returned a server error")]
    ProviderUnavailable { status: u16 },
    #[error("Semgrep provider read timed out")]
    Timeout,
    #[error("live Semgrep environment is blocked")]
    BlockedEnv,
    #[error("Semgrep recording response queue is exhausted")]
    RecordingExhausted,
    #[error("Semgrep recording response kind was unexpected")]
    UnexpectedResponse,
    #[error("Semgrep read limits are invalid")]
    InvalidLimits,
}

impl SemgrepError {
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::AccessLoss { status } | Self::ProviderUnavailable { status } => Some(status),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }

    fn from_transport(error: SemgrepTransportError) -> Self {
        match error {
            SemgrepTransportError::HttpStatus {
                status,
                retry_after_seconds,
            } => match status {
                401 | 403 => Self::AccessLoss { status },
                404 => Self::NotFound,
                409 => Self::Conflict,
                429 => Self::RateLimited {
                    retry_after_seconds,
                },
                _ => Self::ProviderUnavailable { status },
            },
            SemgrepTransportError::Timeout => Self::Timeout,
            SemgrepTransportError::BlockedEnv => Self::BlockedEnv,
            SemgrepTransportError::RecordingExhausted => Self::RecordingExhausted,
            SemgrepTransportError::UnexpectedResponse => Self::UnexpectedResponse,
        }
    }
}

fn decision_for_evidence(evidence: &SecurityEvidence) -> SecurityDecision {
    if !matches!(
        evidence.projection,
        SecurityProjection::NoFindings | SecurityProjection::FindingsPresent
    ) {
        return SecurityDecision::Unknown;
    }
    if evidence.summary.high_risk_actionable > 0 {
        return SecurityDecision::Block;
    }
    if evidence.summary.uncertain_reachability > 0
        || evidence
            .summary
            .by_status
            .keys()
            .any(|status| matches!(status, FindingStatus::Reviewing | FindingStatus::Unknown))
        || evidence
            .summary
            .by_status
            .contains_key(&FindingStatus::ProvisionallyIgnored)
        || evidence
            .summary
            .by_status
            .keys()
            .any(|status| status.is_actionable())
    {
        return SecurityDecision::Review;
    }
    SecurityDecision::Allow
}

fn category_for_type(finding_type: SemgrepFindingType) -> RuleCategory {
    match finding_type {
        SemgrepFindingType::Sast => RuleCategory::Security,
        SemgrepFindingType::Secrets => RuleCategory::Secrets,
        SemgrepFindingType::Sca => RuleCategory::SupplyChain,
    }
}

fn validate_host(value: &str) -> Result<(), SemgrepError> {
    validate_bounded_text("API host", value, MAX_HOST_BYTES)?;
    if value.contains('/') || value.contains('@') || value.contains("://") {
        return Err(SemgrepError::InvalidInput("API host"));
    }
    Ok(())
}

fn validate_identifier(
    name: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), SemgrepError> {
    validate_bounded_text(name, value, max_bytes)?;
    if value.trim() != value || value.is_empty() {
        return Err(SemgrepError::InvalidInput(name));
    }
    Ok(())
}

fn validate_bounded_text(
    name: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), SemgrepError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(SemgrepError::InvalidInput(name));
    }
    Ok(())
}

fn validate_string_list(
    values: &[String],
    max_items: usize,
    max_bytes: usize,
) -> Result<(), SemgrepError> {
    if values.len() > max_items {
        return Err(SemgrepError::InvalidInput("bounded identifier list"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_identifier("bounded identifier", value, max_bytes)?;
        if !seen.insert(value) {
            return Err(SemgrepError::InvalidInput("duplicate identifier"));
        }
    }
    Ok(())
}

fn canonical_strings<I>(
    values: I,
    max_items: usize,
    max_bytes: usize,
) -> Result<Vec<String>, SemgrepError>
where
    I: IntoIterator<Item = String>,
{
    let mut values: Vec<String> = values.into_iter().collect();
    if values.len() > max_items {
        return Err(SemgrepError::InvalidInput("bounded identifier list"));
    }
    values.sort();
    values.dedup();
    validate_string_list(&values, max_items, max_bytes)?;
    Ok(values)
}

fn validate_commit_sha(value: &str) -> Result<(), SemgrepError> {
    let valid_length = value.len() == 40 || value.len() == 64;
    if !valid_length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SemgrepError::InvalidInput("commit SHA"));
    }
    Ok(())
}

fn serialized_size<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .expect("contract values must serialize")
        .len()
}
