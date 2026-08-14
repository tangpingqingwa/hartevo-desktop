#![allow(clippy::struct_excessive_bools)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION,
    SCHEMA_VERSION, SERVICE_ID, digest_bytes, digest_json, digest_text, valid_cursor, valid_digest,
    valid_identifier,
};
use crate::{ModelError, PulumiDeploymentResultError};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SOURCE_BYTES: usize = 512;
pub const MAX_PROVIDER_REQUEST_ID_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_JOBS: usize = 32;
pub const MAX_STEPS: usize = 128;
pub const MAX_STATUS_TRANSITIONS: usize = 64;
pub const MAX_UPDATES: usize = 64;
pub const MAX_AUDIT_ENTRIES: usize = 128;
pub const MAX_PAGES: usize = 8;

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(digest_bytes(bytes))
    }

    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        Self(digest_json(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if valid_digest(self.as_str()) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest("sha256".into()))
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PluginVersion {
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

    pub const fn is_valid(self) -> bool {
        self.major > 0 || self.minor > 0 || self.patch > 0
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    AccessToken,
    Oidc,
}

/// Opaque identity for a Pulumi access token or OIDC credential supplied by a
/// host. The actual credential is never stored, serialized, or included in a
/// provider request record.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Option<Digest>,
    credential_revision: u64,
    kind: AuthKind,
    revoked: bool,
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

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::with_kind(reference_id, credential_revision, AuthKind::AccessToken)
    }

    pub fn for_access_token(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::with_kind(reference_id, credential_revision, AuthKind::AccessToken)
    }

    pub fn for_oidc(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::with_kind(reference_id, credential_revision, AuthKind::Oidc)
    }

    pub fn for_scope(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
        scope_digest: impl AsRef<str>,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::with_scope(
            reference_id,
            credential_revision,
            AuthKind::AccessToken,
            scope_digest,
        )
    }

    pub fn for_oidc_scope(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
        scope_digest: impl AsRef<str>,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::with_scope(
            reference_id,
            credential_revision,
            AuthKind::Oidc,
            scope_digest,
        )
    }

    fn with_kind(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
        kind: AuthKind,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let reference_id = reference_id.as_ref();
        if !valid_identifier(reference_id, MAX_IDENTIFIER_BYTES) || credential_revision == 0 {
            return Err(PulumiDeploymentResultError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: Digest::from_text(reference_id),
            scope_digest: None,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    fn with_scope(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
        kind: AuthKind,
        scope_digest: impl AsRef<str>,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let mut reference = Self::with_kind(reference_id, credential_revision, kind)?;
        let scope_digest = Digest(scope_digest.as_ref().to_owned());
        scope_digest
            .validate()
            .map_err(PulumiDeploymentResultError::from)?;
        reference.scope_digest = Some(scope_digest);
        Ok(reference)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn kind(&self) -> AuthKind {
        self.kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate_for_scope(&self, scope_digest: &Digest) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::CredentialRevoked);
        }
        if self.scope_digest() != Some(scope_digest) {
            return Err(ModelError::AuthScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiCloudEndpoint {
    pub base_url: String,
}

impl PulumiCloudEndpoint {
    pub fn new(base_url: impl Into<String>) -> Result<Self, PulumiDeploymentResultError> {
        let endpoint = Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let lower = self.base_url.to_ascii_lowercase();
        let authority = lower
            .strip_prefix("https://")
            .and_then(|value| value.split(['/', '?', '#']).next())
            .unwrap_or_default();
        if !lower.starts_with("https://")
            || authority.is_empty()
            || self.base_url.chars().any(char::is_whitespace)
            || self.base_url.contains('?')
            || self.base_url.contains('#')
        {
            return Err(ModelError::InvalidEndpoint);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiSourceScope {
    pub repository: String,
    pub branch: Option<String>,
    pub directory: Option<String>,
    pub commit_sha: String,
}

impl PulumiSourceScope {
    pub fn new(
        repository: impl Into<String>,
        branch: Option<String>,
        directory: Option<String>,
        commit_sha: impl Into<String>,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let source = Self {
            repository: repository.into(),
            branch,
            directory,
            commit_sha: commit_sha.into(),
        };
        source.validate()?;
        Ok(source)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.repository, MAX_SOURCE_BYTES)
            || self.repository.contains(' ')
            || self.commit_sha.is_empty()
            || !valid_identifier(&self.commit_sha, MAX_SOURCE_BYTES)
            || self
                .branch
                .as_ref()
                .is_some_and(|value| !valid_identifier(value, MAX_SOURCE_BYTES))
            || self
                .directory
                .as_ref()
                .is_some_and(|value| !valid_identifier(value, MAX_SOURCE_BYTES))
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiUpdateScope {
    pub update_id: String,
    pub version: u64,
}

impl PulumiUpdateScope {
    pub fn new(
        update_id: impl Into<String>,
        version: u64,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let update = Self {
            update_id: update_id.into(),
            version,
        };
        update.validate()?;
        Ok(update)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.update_id, MAX_IDENTIFIER_BYTES) || self.version == 0 {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiPolicyScope {
    pub policy_digest: Digest,
    pub policy_revision: u64,
}

impl PulumiPolicyScope {
    pub fn new(
        policy_digest: impl Into<String>,
        policy_revision: u64,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let policy = Self {
            policy_digest: Digest(policy_digest.into()),
            policy_revision,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.policy_digest.validate()?;
        if self.policy_revision == 0 {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCapability {
    ReadOrganization,
    ReadProject,
    ReadStack,
    ReadDeployment,
    ReadUpdates,
    ReadPolicy,
    ReadAudit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub revision: String,
    pub capabilities: BTreeSet<PermissionCapability>,
    pub snapshot_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        revision: impl Into<String>,
        capabilities: impl IntoIterator<Item = PermissionCapability>,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let mut snapshot = Self {
            revision: revision.into(),
            capabilities: capabilities.into_iter().collect(),
            snapshot_digest: Digest::from_text("pending"),
        };
        snapshot.validate_without_digest()?;
        snapshot.snapshot_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn read_only_default(
        revision: impl Into<String>,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::new(
            revision,
            [
                PermissionCapability::ReadOrganization,
                PermissionCapability::ReadProject,
                PermissionCapability::ReadStack,
                PermissionCapability::ReadDeployment,
                PermissionCapability::ReadUpdates,
                PermissionCapability::ReadPolicy,
                PermissionCapability::ReadAudit,
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_without_digest()?;
        if self.snapshot_digest != self.compute_digest() {
            return Err(ModelError::PermissionDrift);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    fn validate_without_digest(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.revision, MAX_IDENTIFIER_BYTES) || self.capabilities.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Material<'a> {
            revision: &'a str,
            capabilities: &'a BTreeSet<PermissionCapability>,
        }
        Digest::from_serializable(&Material {
            revision: &self.revision,
            capabilities: &self.capabilities,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiDeploymentScope {
    pub endpoint: PulumiCloudEndpoint,
    pub organization: String,
    pub organization_revision: u64,
    pub pulumi_project: String,
    pub pulumi_project_revision: u64,
    pub stack: String,
    pub stack_revision: u64,
    pub deployment_id: String,
    pub source: PulumiSourceScope,
    pub update: PulumiUpdateScope,
    pub policy: PulumiPolicyScope,
    pub hartevo_project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub consent_revision: u64,
    pub permissions: PermissionSnapshot,
}

impl PulumiDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: PulumiCloudEndpoint,
        organization: impl Into<String>,
        organization_revision: u64,
        pulumi_project: impl Into<String>,
        pulumi_project_revision: u64,
        stack: impl Into<String>,
        stack_revision: u64,
        deployment_id: impl Into<String>,
        source: PulumiSourceScope,
        update: PulumiUpdateScope,
        policy: PulumiPolicyScope,
        hartevo_project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        mission_revision: u64,
        work_product_revision: u64,
        consent_revision: u64,
        permissions: PermissionSnapshot,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let scope = Self {
            endpoint,
            organization: organization.into(),
            organization_revision,
            pulumi_project: pulumi_project.into(),
            pulumi_project_revision,
            stack: stack.into(),
            stack_revision,
            deployment_id: deployment_id.into(),
            source,
            update,
            policy,
            hartevo_project_id: hartevo_project_id.into(),
            mission_id: mission_id.into(),
            work_product_id: work_product_id.into(),
            mission_revision,
            work_product_revision,
            consent_revision,
            permissions,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.endpoint.validate()?;
        for value in [
            self.organization.as_str(),
            self.pulumi_project.as_str(),
            self.stack.as_str(),
            self.deployment_id.as_str(),
            self.hartevo_project_id.as_str(),
            self.mission_id.as_str(),
            self.work_product_id.as_str(),
        ] {
            if !valid_identifier(value, MAX_IDENTIFIER_BYTES) {
                return Err(ModelError::InvalidScope);
            }
        }
        if self.organization_revision == 0
            || self.pulumi_project_revision == 0
            || self.stack_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || self.consent_revision == 0
        {
            return Err(ModelError::InvalidScope);
        }
        self.source.validate()?;
        self.update.validate()?;
        self.policy.validate()?;
        self.permissions.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
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
pub struct PulumiDeploymentResultRegistration {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub adapter_revision: String,
    pub scope: PulumiDeploymentScope,
    pub permission_snapshot_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub auth_kind: AuthKind,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl PulumiDeploymentResultRegistration {
    pub fn new(
        scope: &PulumiDeploymentScope,
        secret_reference: &SecretReference,
        adapter_revision: impl Into<String>,
        registration_revision: u64,
    ) -> Result<Self, PulumiDeploymentResultError> {
        scope.validate()?;
        secret_reference.validate_for_scope(&scope.digest())?;
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest(crate::contract_digest()),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION,
            adapter_revision: adapter_revision.into(),
            scope: scope.clone(),
            permission_snapshot_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            auth_kind: secret_reference.kind(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("pending"),
        };
        registration.validate_without_digest()?;
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn validate(
        &self,
        scope: &PulumiDeploymentScope,
        secret_reference: &SecretReference,
    ) -> Result<(), PulumiDeploymentResultError> {
        scope.validate()?;
        if self.state == RegistrationState::Active {
            secret_reference.validate_for_scope(&scope.digest())?;
        }
        self.validate_without_digest()?;
        if self.scope_digest != scope.digest()
            || self.scope != *scope
            || self.permission_snapshot_digest != *scope.permissions.digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.auth_kind != secret_reference.kind()
            || self.contract_digest.as_str() != crate::contract_digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(PulumiDeploymentResultError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn revoke(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<RegistrationRevocation, PulumiDeploymentResultError> {
        if self.state == RegistrationState::Revoked {
            return Err(PulumiDeploymentResultError::RegistrationRevoked);
        }
        self.validate_without_digest()?;
        if self.registration_digest != self.compute_digest() {
            return Err(PulumiDeploymentResultError::RegistrationDrift);
        }
        let before = self.registration_digest.clone();
        let reason = reason.into();
        if !valid_identifier(&reason, MAX_IDENTIFIER_BYTES) {
            return Err(PulumiDeploymentResultError::InvalidIdentifier(
                "revocation reason".into(),
            ));
        }
        self.state = RegistrationState::Revoked;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(PulumiDeploymentResultError::InvalidRegistration)?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocation {
            registration_digest_before: before,
            registration_digest_after: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reason,
            reversible: true,
        })
    }

    pub fn reissue(
        &self,
        scope: &PulumiDeploymentScope,
        secret_reference: &SecretReference,
        adapter_revision: impl Into<String>,
        registration_revision: u64,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::new(
            scope,
            secret_reference,
            adapter_revision,
            registration_revision,
        )
    }

    fn validate_without_digest(&self) -> Result<(), PulumiDeploymentResultError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || !valid_digest(self.contract_digest.as_str())
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || !valid_identifier(&self.adapter_revision, MAX_IDENTIFIER_BYTES)
            || self.scope.validate().is_err()
            || !valid_digest(self.permission_snapshot_digest.as_str())
            || !valid_digest(self.scope_digest.as_str())
            || !valid_digest(self.secret_reference_digest.as_str())
            || self.registration_revision == 0
        {
            return Err(PulumiDeploymentResultError::InvalidRegistration);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Material<'a> {
            plugin_id: &'a str,
            plugin_version: PluginVersion,
            contract_version: &'a str,
            contract_digest: &'a Digest,
            provider_id: &'a str,
            provider_version: PluginVersion,
            adapter_revision: &'a str,
            permission_snapshot_digest: &'a Digest,
            scope_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
            auth_kind: AuthKind,
            registration_revision: u64,
            state: RegistrationState,
        }
        Digest::from_serializable(&Material {
            plugin_id: &self.plugin_id,
            plugin_version: self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: self.provider_version,
            adapter_revision: &self.adapter_revision,
            permission_snapshot_digest: &self.permission_snapshot_digest,
            scope_digest: &self.scope_digest,
            secret_reference_digest: &self.secret_reference_digest,
            auth_kind: self.auth_kind,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest_before: Digest,
    pub registration_digest_after: Digest,
    pub registration_revision: u64,
    pub reason: String,
    pub reversible: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl EvidenceProvenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PulumiDeploymentStatus {
    NotStarted,
    Accepted,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
    Drift,
    Partial,
    ProviderUnknown,
}

impl PulumiDeploymentStatus {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "not-started" => Self::NotStarted,
            "accepted" => Self::Accepted,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "skipped" => Self::Skipped,
            "cancelled" | "canceled" => Self::Cancelled,
            "drift" | "drift-detected" | "remediate-drift" => Self::Drift,
            "partial" => Self::Partial,
            _ => Self::ProviderUnknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Skipped
                | Self::Cancelled
                | Self::Drift
                | Self::Partial
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PulumiStepStatus {
    NotStarted,
    Accepted,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
    ProviderUnknown,
}

impl PulumiStepStatus {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "not-started" => Self::NotStarted,
            "accepted" => Self::Accepted,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "skipped" => Self::Skipped,
            "cancelled" | "canceled" => Self::Cancelled,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PulumiOperation {
    Preview,
    Update,
    Refresh,
    DetectDrift,
    RemediateDrift,
    Destroy,
    ProviderUnknown,
}

impl PulumiOperation {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "preview" => Self::Preview,
            "update" => Self::Update,
            "refresh" => Self::Refresh,
            "detect-drift" => Self::DetectDrift,
            "remediate-drift" => Self::RemediateDrift,
            "destroy" => Self::Destroy,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PulumiUpdateStatus {
    NotStarted,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Drift,
    Partial,
    Skipped,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PulumiPolicyStatus {
    Passed,
    Failed,
    Skipped,
    NotApplicable,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusTransition {
    pub from: PulumiDeploymentStatus,
    pub to: PulumiDeploymentStatus,
    pub occurred_at: u64,
}

impl StatusTransition {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.occurred_at == 0 || self.from == self.to {
            return Err(ModelError::InvalidStatusTransition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiStepEvidence {
    pub step_id: String,
    pub name: String,
    pub status: PulumiStepStatus,
    pub started_at: Option<u64>,
    pub last_updated_at: u64,
    pub message_digest: Option<Digest>,
    pub redacted: bool,
}

impl PulumiStepEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.step_id, MAX_IDENTIFIER_BYTES)
            || !valid_identifier(&self.name, MAX_IDENTIFIER_BYTES)
            || self.last_updated_at == 0
            || self
                .started_at
                .is_some_and(|started_at| started_at > self.last_updated_at)
            || self
                .message_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(ModelError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiJobEvidence {
    pub job_id: String,
    pub status: PulumiDeploymentStatus,
    pub started_at: Option<u64>,
    pub last_updated_at: u64,
    pub steps: Vec<PulumiStepEvidence>,
}

impl PulumiJobEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.job_id, MAX_IDENTIFIER_BYTES)
            || self.last_updated_at == 0
            || self
                .started_at
                .is_some_and(|started_at| started_at > self.last_updated_at)
            || self.steps.len() > MAX_STEPS
        {
            return Err(ModelError::InvalidEvidence);
        }
        for step in &self.steps {
            step.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiUpdateEvidence {
    pub update_id: String,
    pub version: u64,
    pub status: PulumiUpdateStatus,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub resource_change_counts: BTreeMap<String, u64>,
    pub result_digest: Option<Digest>,
}

impl PulumiUpdateEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.update_id, MAX_IDENTIFIER_BYTES)
            || self.version == 0
            || self
                .started_at
                .zip(self.finished_at)
                .is_some_and(|(started, finished)| finished < started)
            || self.resource_change_counts.len() > MAX_IDENTIFIER_BYTES / 8
            || self
                .resource_change_counts
                .keys()
                .any(|key| !valid_identifier(key, 64))
            || self
                .result_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(ModelError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiPolicyEvidence {
    pub policy_digest: Digest,
    pub policy_revision: u64,
    pub status: PulumiPolicyStatus,
    pub policy_pack_count: u32,
    pub violation_count: u32,
    pub findings_digest: Option<Digest>,
    pub evaluated_at: u64,
    pub redacted: bool,
}

impl PulumiPolicyEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        self.policy_digest.validate()?;
        if self.policy_revision == 0
            || self.evaluated_at == 0
            || self
                .findings_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || (self.status == PulumiPolicyStatus::Failed && self.violation_count == 0)
        {
            return Err(ModelError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn passed(&self) -> bool {
        matches!(
            self.status,
            PulumiPolicyStatus::Passed | PulumiPolicyStatus::Skipped
        ) && self.violation_count == 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiAuditEvidence {
    pub audit_id: String,
    pub event: String,
    pub occurred_at: u64,
    pub actor_digest: Digest,
    pub provider_request_id: Option<String>,
    pub details_digest: Option<Digest>,
    pub redacted: bool,
}

impl PulumiAuditEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.audit_id, MAX_IDENTIFIER_BYTES)
            || !valid_identifier(&self.event, MAX_IDENTIFIER_BYTES)
            || self.occurred_at == 0
            || self.actor_digest.validate().is_err()
            || self
                .provider_request_id
                .as_ref()
                .is_some_and(|id| !valid_identifier(id, MAX_PROVIDER_REQUEST_ID_BYTES))
            || self
                .details_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(ModelError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiStackApiRecord {
    pub organization: String,
    pub organization_revision: u64,
    pub pulumi_project: String,
    pub pulumi_project_revision: u64,
    pub stack: String,
    pub stack_revision: u64,
    pub deployment_settings_revision: Option<u64>,
    pub permissions: PermissionSnapshot,
    pub provider_request_id: Option<String>,
}

impl PulumiStackApiRecord {
    pub fn validate(&self) -> Result<(), ModelError> {
        for value in [
            self.organization.as_str(),
            self.pulumi_project.as_str(),
            self.stack.as_str(),
        ] {
            if !valid_identifier(value, MAX_IDENTIFIER_BYTES) {
                return Err(ModelError::InvalidEvidence);
            }
        }
        if self.organization_revision == 0
            || self.pulumi_project_revision == 0
            || self.stack_revision == 0
            || self
                .deployment_settings_revision
                .is_some_and(|revision| revision == 0)
            || self
                .provider_request_id
                .as_ref()
                .is_some_and(|id| !valid_identifier(id, MAX_PROVIDER_REQUEST_ID_BYTES))
        {
            return Err(ModelError::InvalidEvidence);
        }
        self.permissions.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiDeploymentApiRecord {
    pub provider_request_id: String,
    pub deployment_id: String,
    pub organization: String,
    pub pulumi_project: String,
    pub stack: String,
    pub status: PulumiDeploymentStatus,
    pub operation: PulumiOperation,
    pub created_at: u64,
    pub modified_at: u64,
    pub version: u64,
    pub latest_version: u64,
    pub source: PulumiSourceScope,
    pub update: PulumiUpdateScope,
    pub jobs: Vec<PulumiJobEvidence>,
    pub status_transitions: Vec<StatusTransition>,
    pub redacted_fields: BTreeSet<String>,
    pub truncated: bool,
}

impl PulumiDeploymentApiRecord {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.provider_request_id, MAX_PROVIDER_REQUEST_ID_BYTES)
            || !valid_identifier(&self.deployment_id, MAX_IDENTIFIER_BYTES)
            || !valid_identifier(&self.organization, MAX_IDENTIFIER_BYTES)
            || !valid_identifier(&self.pulumi_project, MAX_IDENTIFIER_BYTES)
            || !valid_identifier(&self.stack, MAX_IDENTIFIER_BYTES)
            || self.created_at == 0
            || self.modified_at < self.created_at
            || self.version == 0
            || self.latest_version < self.version
            || self.jobs.len() > MAX_JOBS
            || self.status_transitions.len() > MAX_STATUS_TRANSITIONS
            || self.redacted_fields.len() > MAX_IDENTIFIER_BYTES / 2
            || self
                .redacted_fields
                .iter()
                .any(|field| !valid_identifier(field, MAX_IDENTIFIER_BYTES))
        {
            return Err(ModelError::InvalidEvidence);
        }
        self.source.validate()?;
        self.update.validate()?;
        for job in &self.jobs {
            job.validate()?;
        }
        for transition in &self.status_transitions {
            transition.validate()?;
        }
        if self
            .status_transitions
            .windows(2)
            .any(|window| window[1].occurred_at < window[0].occurred_at)
        {
            return Err(ModelError::InvalidStatusTransition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiUpdatePage {
    pub items: Vec<PulumiUpdateEvidence>,
    pub next_cursor: Option<String>,
}

impl PulumiUpdatePage {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.items.len() > MAX_UPDATES
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| !valid_cursor(cursor))
        {
            return Err(ModelError::InvalidPage);
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiAuditPage {
    pub items: Vec<PulumiAuditEvidence>,
    pub next_cursor: Option<String>,
}

impl PulumiAuditPage {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.items.len() > MAX_AUDIT_ENTRIES
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| !valid_cursor(cursor))
        {
            return Err(ModelError::InvalidPage);
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiStackDescription {
    pub scope: PulumiDeploymentScope,
    pub deployment_settings_revision: Option<u64>,
    pub permissions: PermissionSnapshot,
    pub provider_request_id: Option<String>,
    pub provenance: EvidenceProvenance,
    pub connected: bool,
    pub native: bool,
    pub description_digest: Digest,
}

impl PulumiStackDescription {
    pub(crate) fn from_record(
        scope: PulumiDeploymentScope,
        record: PulumiStackApiRecord,
        provenance: EvidenceProvenance,
    ) -> Result<Self, PulumiDeploymentResultError> {
        record.validate()?;
        let description = Self {
            scope,
            deployment_settings_revision: record.deployment_settings_revision,
            permissions: record.permissions,
            provider_request_id: record.provider_request_id,
            provenance,
            connected: false,
            native: false,
            description_digest: Digest::from_text("pending"),
        };
        let mut description = description;
        description.description_digest = description.compute_digest();
        description.validate()?;
        Ok(description)
    }

    pub fn validate(&self) -> Result<(), PulumiDeploymentResultError> {
        self.scope.validate()?;
        self.permissions.validate()?;
        if self
            .deployment_settings_revision
            .is_some_and(|revision| revision == 0)
            || self
                .provider_request_id
                .as_ref()
                .is_some_and(|id| !valid_identifier(id, MAX_PROVIDER_REQUEST_ID_BYTES))
            || self.connected
            || self.native
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.permissions != self.scope.permissions
            || self.description_digest != self.compute_digest()
        {
            return Err(PulumiDeploymentResultError::InvalidEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Material<'a> {
            scope_digest: Digest,
            deployment_settings_revision: Option<u64>,
            permissions: &'a PermissionSnapshot,
            provider_request_id: &'a Option<String>,
            provenance: EvidenceProvenance,
            connected: bool,
            native: bool,
        }
        Digest::from_serializable(&Material {
            scope_digest: self.scope.digest(),
            deployment_settings_revision: self.deployment_settings_revision,
            permissions: &self.permissions,
            provider_request_id: &self.provider_request_id,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiDeploymentEvidence {
    pub scope: PulumiDeploymentScope,
    pub provider_request_id: String,
    pub deployment_id: String,
    pub organization: String,
    pub pulumi_project: String,
    pub stack: String,
    pub status: PulumiDeploymentStatus,
    pub operation: PulumiOperation,
    pub created_at: u64,
    pub modified_at: u64,
    pub version: u64,
    pub latest_version: u64,
    pub source: PulumiSourceScope,
    pub update: PulumiUpdateScope,
    pub jobs: Vec<PulumiJobEvidence>,
    pub status_transitions: Vec<StatusTransition>,
    pub updates: Vec<PulumiUpdateEvidence>,
    pub policy: PulumiPolicyEvidence,
    pub audit: Vec<PulumiAuditEvidence>,
    pub pages_read: u8,
    pub redacted_fields: BTreeSet<String>,
    pub truncated: bool,
    pub provenance: EvidenceProvenance,
    pub connected: bool,
    pub native: bool,
    pub evidence_digest: Digest,
}

impl PulumiDeploymentEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        scope: PulumiDeploymentScope,
        record: PulumiDeploymentApiRecord,
        updates: Vec<PulumiUpdateEvidence>,
        policy: PulumiPolicyEvidence,
        audit: Vec<PulumiAuditEvidence>,
        pages_read: u8,
        provenance: EvidenceProvenance,
    ) -> Result<Self, PulumiDeploymentResultError> {
        record.validate()?;
        policy.validate()?;
        for update in &updates {
            update.validate()?;
        }
        for entry in &audit {
            entry.validate()?;
        }
        let mut evidence = Self {
            scope,
            provider_request_id: record.provider_request_id,
            deployment_id: record.deployment_id,
            organization: record.organization,
            pulumi_project: record.pulumi_project,
            stack: record.stack,
            status: record.status,
            operation: record.operation,
            created_at: record.created_at,
            modified_at: record.modified_at,
            version: record.version,
            latest_version: record.latest_version,
            source: record.source,
            update: record.update,
            jobs: record.jobs,
            status_transitions: record.status_transitions,
            updates,
            policy,
            audit,
            pages_read,
            redacted_fields: record.redacted_fields,
            truncated: record.truncated,
            provenance,
            connected: false,
            native: false,
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence.validate_against_scope(&evidence.scope)?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), PulumiDeploymentResultError> {
        self.validate_against_scope(&self.scope)
    }

    pub fn validate_against_scope(
        &self,
        scope: &PulumiDeploymentScope,
    ) -> Result<(), PulumiDeploymentResultError> {
        scope.validate()?;
        if self.scope.digest() != scope.digest()
            || self.deployment_id != scope.deployment_id
            || self.organization != scope.organization
            || self.pulumi_project != scope.pulumi_project
            || self.stack != scope.stack
            || self.source != scope.source
            || self.update != scope.update
            || self.policy.policy_digest != scope.policy.policy_digest
            || self.policy.policy_revision != scope.policy.policy_revision
        {
            return Err(PulumiDeploymentResultError::ScopeMismatch);
        }
        if !valid_identifier(&self.provider_request_id, MAX_PROVIDER_REQUEST_ID_BYTES)
            || self.created_at == 0
            || self.modified_at < self.created_at
            || self.version == 0
            || self.latest_version < self.version
            || self.jobs.len() > MAX_JOBS
            || self.status_transitions.len() > MAX_STATUS_TRANSITIONS
            || self.updates.len() > MAX_UPDATES
            || self.audit.len() > MAX_AUDIT_ENTRIES
            || self.pages_read == 0
            || usize::from(self.pages_read) > MAX_PAGES * 2 + 1
            || self.redacted_fields.len() > MAX_IDENTIFIER_BYTES / 2
            || self
                .redacted_fields
                .iter()
                .any(|field| !valid_identifier(field, MAX_IDENTIFIER_BYTES))
            || self.connected
            || self.native
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.evidence_digest != self.compute_digest()
        {
            return Err(PulumiDeploymentResultError::InvalidEvidence);
        }
        for job in &self.jobs {
            job.validate()?;
        }
        for transition in &self.status_transitions {
            transition.validate()?;
        }
        for update in &self.updates {
            update.validate()?;
        }
        self.policy.validate()?;
        for entry in &self.audit {
            entry.validate()?;
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Digest {
        self.evidence_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Material<'a> {
            scope_digest: Digest,
            provider_request_id: &'a str,
            deployment_id: &'a str,
            organization: &'a str,
            pulumi_project: &'a str,
            stack: &'a str,
            status: PulumiDeploymentStatus,
            operation: PulumiOperation,
            created_at: u64,
            modified_at: u64,
            version: u64,
            latest_version: u64,
            source: &'a PulumiSourceScope,
            update: &'a PulumiUpdateScope,
            jobs: &'a [PulumiJobEvidence],
            status_transitions: &'a [StatusTransition],
            updates: &'a [PulumiUpdateEvidence],
            policy: &'a PulumiPolicyEvidence,
            audit: &'a [PulumiAuditEvidence],
            pages_read: u8,
            redacted_fields: &'a BTreeSet<String>,
            truncated: bool,
            provenance: EvidenceProvenance,
            connected: bool,
            native: bool,
        }
        Digest::from_serializable(&Material {
            scope_digest: self.scope.digest(),
            provider_request_id: &self.provider_request_id,
            deployment_id: &self.deployment_id,
            organization: &self.organization,
            pulumi_project: &self.pulumi_project,
            stack: &self.stack,
            status: self.status,
            operation: self.operation,
            created_at: self.created_at,
            modified_at: self.modified_at,
            version: self.version,
            latest_version: self.latest_version,
            source: &self.source,
            update: &self.update,
            jobs: &self.jobs,
            status_transitions: &self.status_transitions,
            updates: &self.updates,
            policy: &self.policy,
            audit: &self.audit,
            pages_read: self.pages_read,
            redacted_fields: &self.redacted_fields,
            truncated: self.truncated,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiDeploymentReceipt {
    pub scope_digest: Digest,
    pub deployment_id: String,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub receipt_digest: Digest,
    pub provenance: EvidenceProvenance,
    pub write_receipt: bool,
    pub durable_readback: bool,
    pub native_connected: bool,
    pub external_effect_performed: bool,
    pub outcome_adoption: bool,
}

impl PulumiDeploymentReceipt {
    pub(crate) fn from_evidence(
        evidence: &PulumiDeploymentEvidence,
        registration_digest: Digest,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let mut receipt = Self {
            scope_digest: evidence.scope.digest(),
            deployment_id: evidence.deployment_id.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest,
            receipt_digest: Digest::from_text("pending"),
            provenance: evidence.provenance,
            write_receipt: false,
            durable_readback: false,
            native_connected: false,
            external_effect_performed: false,
            outcome_adoption: false,
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), PulumiDeploymentResultError> {
        if !valid_digest(self.scope_digest.as_str())
            || !valid_identifier(&self.deployment_id, MAX_IDENTIFIER_BYTES)
            || !valid_digest(self.evidence_digest.as_str())
            || !valid_digest(self.registration_digest.as_str())
            || self.write_receipt
            || self.durable_readback
            || self.native_connected
            || self.external_effect_performed
            || self.outcome_adoption
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.receipt_digest != self.compute_digest()
        {
            return Err(PulumiDeploymentResultError::InvalidEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Material<'a> {
            scope_digest: &'a Digest,
            deployment_id: &'a str,
            evidence_digest: &'a Digest,
            registration_digest: &'a Digest,
            provenance: EvidenceProvenance,
            write_receipt: bool,
            durable_readback: bool,
            native_connected: bool,
            external_effect_performed: bool,
            outcome_adoption: bool,
        }
        Digest::from_serializable(&Material {
            scope_digest: &self.scope_digest,
            deployment_id: &self.deployment_id,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            provenance: self.provenance,
            write_receipt: self.write_receipt,
            durable_readback: self.durable_readback,
            native_connected: self.native_connected,
            external_effect_performed: self.external_effect_performed,
            outcome_adoption: self.outcome_adoption,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultVerificationStatus {
    Verified,
    Pending,
    Failed,
    ProviderUnknown,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiDeploymentResultProposal {
    pub scope: PulumiDeploymentScope,
    pub deployment_id: String,
    pub status: PulumiDeploymentStatus,
    pub operation: PulumiOperation,
    pub source: PulumiSourceScope,
    pub update: PulumiUpdateScope,
    pub policy: PulumiPolicyEvidence,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub registration_digest: Digest,
    pub result_digest: Digest,
    pub verification_status: ResultVerificationStatus,
    pub provenance: EvidenceProvenance,
    pub connected: bool,
    pub native: bool,
    pub external_effect_performed: bool,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub authority: String,
}

impl PulumiDeploymentResultProposal {
    pub(crate) fn from_verified(
        evidence: &PulumiDeploymentEvidence,
        receipt: &PulumiDeploymentReceipt,
        verification_status: ResultVerificationStatus,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let mut proposal = Self {
            scope: evidence.scope.clone(),
            deployment_id: evidence.deployment_id.clone(),
            status: evidence.status,
            operation: evidence.operation,
            source: evidence.source.clone(),
            update: evidence.update.clone(),
            policy: evidence.policy.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            result_digest: Digest::from_text("pending"),
            verification_status,
            provenance: evidence.provenance,
            connected: false,
            native: false,
            external_effect_performed: false,
            durable_adoption: false,
            kernel_authority: false,
            outcome_adoption: false,
            authority: "mission_result_proposal".into(),
        };
        proposal.result_digest = proposal.compute_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), PulumiDeploymentResultError> {
        self.scope.validate()?;
        self.policy.validate()?;
        if self.deployment_id != self.scope.deployment_id
            || self.source != self.scope.source
            || self.update != self.scope.update
            || self.policy.policy_digest != self.scope.policy.policy_digest
            || self.policy.policy_revision != self.scope.policy.policy_revision
            || !valid_digest(self.evidence_digest.as_str())
            || !valid_digest(self.receipt_digest.as_str())
            || !valid_digest(self.registration_digest.as_str())
            || self.connected
            || self.native
            || self.external_effect_performed
            || self.durable_adoption
            || self.kernel_authority
            || self.outcome_adoption
            || self.authority != "mission_result_proposal"
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.result_digest != self.compute_digest()
        {
            return Err(PulumiDeploymentResultError::InvalidEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Material<'a> {
            scope_digest: Digest,
            deployment_id: &'a str,
            status: PulumiDeploymentStatus,
            operation: PulumiOperation,
            source: &'a PulumiSourceScope,
            update: &'a PulumiUpdateScope,
            policy: &'a PulumiPolicyEvidence,
            evidence_digest: &'a Digest,
            receipt_digest: &'a Digest,
            registration_digest: &'a Digest,
            verification_status: ResultVerificationStatus,
            provenance: EvidenceProvenance,
            connected: bool,
            native: bool,
            external_effect_performed: bool,
            durable_adoption: bool,
            kernel_authority: bool,
            outcome_adoption: bool,
            authority: &'a str,
        }
        Digest::from_serializable(&Material {
            scope_digest: self.scope.digest(),
            deployment_id: &self.deployment_id,
            status: self.status,
            operation: self.operation,
            source: &self.source,
            update: &self.update,
            policy: &self.policy,
            evidence_digest: &self.evidence_digest,
            receipt_digest: &self.receipt_digest,
            registration_digest: &self.registration_digest,
            verification_status: self.verification_status,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            external_effect_performed: self.external_effect_performed,
            durable_adoption: self.durable_adoption,
            kernel_authority: self.kernel_authority,
            outcome_adoption: self.outcome_adoption,
            authority: &self.authority,
        })
    }
}

/// A compile-time authority marker used by tests and audits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn browser_profile() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn raw_logs() -> bool {
        false
    }

    pub const fn raw_state() -> bool {
        false
    }

    pub const fn raw_secrets() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }
}

/// Keep these imports in this module's public API documentation and make the
/// registration fields visibly bound to the three typed seam identities.
#[allow(dead_code)]
const _SEAM_IDENTITIES: (&str, &str, &str, &str) =
    (SERVICE_ID, PROVIDER_ID, CONSUMER_ID, SCHEMA_VERSION);

#[allow(dead_code)]
fn _canonical_scope_text(scope: &PulumiDeploymentScope) -> String {
    digest_text(scope.digest().as_str())
}

#[allow(dead_code)]
fn _contract_version_is_stable() -> bool {
    !CONTRACT_VERSION.is_empty() && PLUGIN_VERSION.is_valid() && PROVIDER_VERSION.is_valid()
}

#[allow(dead_code)]
fn _scope_map(scope: &PulumiDeploymentScope) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("organization", scope.organization.clone()),
        ("project", scope.pulumi_project.clone()),
        ("stack", scope.stack.clone()),
        ("deployment", scope.deployment_id.clone()),
    ])
}
