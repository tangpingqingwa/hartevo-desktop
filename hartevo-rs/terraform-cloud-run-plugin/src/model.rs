use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use url::Url;

use crate::error::TerraformCloudRunError;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_SOURCE_BYTES: usize = 256;
pub const MAX_STATUS_TRANSITIONS: usize = 64;
pub const MAX_PROVIDER_REQUEST_ID_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub const SCHEMA_VERSION: &str = "hartevo.terraform-cloud-run/v1";
pub const CONTRACT_VERSION: &str = "EXT-TFC-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.terraform-cloud-run";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const PROVIDER_ID: &str = "terraform-cloud-run";
pub const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const SERVICE_ID: &str = "TerraformCloudRunService";
pub const CONSUMER_ID: &str = "MissionTerraformRunConsumer";
pub const API_BASE_URL: &str = "https://app.terraform.io/api/v2";

/// A lowercase hexadecimal SHA-256 digest used for all durable fences.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Terraform Cloud contract values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn pending() -> Self {
        Self::from_bytes(b"pending-terraform-cloud-digest")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        if self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(TerraformCloudRunError::InvalidDigest)
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
        formatter.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = TerraformCloudRunError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let digest = Self(value.to_ascii_lowercase());
        digest.validate()?;
        Ok(digest)
    }
}

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TerraformCloudRunError> {
                let value = value.into();
                validate_identifier(&value, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
                validate_identifier(&self.0, $kind)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = TerraformCloudRunError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(OrganizationId, "organization");
identifier_type!(TerraformProjectId, "terraform_project");
identifier_type!(WorkspaceId, "workspace");
identifier_type!(WorkspaceRevision, "workspace_revision");
identifier_type!(LockIdentity, "workspace_lock_identity");
identifier_type!(ConfigurationVersionId, "configuration_version");
identifier_type!(RunId, "run");
identifier_type!(PlanId, "plan");
identifier_type!(ApplyId, "apply");
identifier_type!(PolicyEvaluationId, "policy_evaluation");
identifier_type!(PolicySetId, "policy_set");
identifier_type!(HartevoProjectId, "hartevo_project");
identifier_type!(MissionId, "mission");
identifier_type!(WorkProductId, "work_product");

fn validate_identifier(value: &str, kind: &'static str) -> Result<(), TerraformCloudRunError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        Err(TerraformCloudRunError::InvalidIdentifier { kind })
    } else {
        Ok(())
    }
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), TerraformCloudRunError> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        Err(TerraformCloudRunError::InvalidInput {
            field,
            reason: "must be bounded, non-empty, and whitespace-free",
        })
    } else {
        Ok(())
    }
}

/// Canonical hostname identity. A scope carries the hostname only; scheme,
/// path, query, fragment, userinfo, and port are never part of its identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct HcpTerraformHostname(String);

impl HcpTerraformHostname {
    pub fn parse(value: impl Into<String>) -> Result<Self, TerraformCloudRunError> {
        let value = value.into();
        let candidate = if value.contains("://") {
            value.clone()
        } else {
            format!("https://{value}")
        };
        let parsed = Url::parse(&candidate).map_err(|_| TerraformCloudRunError::InvalidHostname)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.port().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(TerraformCloudRunError::InvalidHostname);
        }
        let hostname = parsed
            .host_str()
            .ok_or(TerraformCloudRunError::InvalidHostname)?
            .to_ascii_lowercase();
        validate_bounded_text(&hostname, "hostname", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(hostname))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn base_url(&self) -> String {
        format!("https://{}/api/v2", self.0)
    }
}

impl fmt::Display for HcpTerraformHostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for HcpTerraformHostname {
    type Err = TerraformCloudRunError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Version carried by the manifest and all registration/proposal fences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn validate(self) -> Result<(), TerraformCloudRunError> {
        if self.major == 0 {
            Err(TerraformCloudRunError::InvalidInput {
                field: "version",
                reason: "major version must be non-zero",
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Evidence states intentionally keep provider claims below Hartevo kernel
/// Truth/Consent/Effect/Receipt/Verification/Outcome authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    OfficialHttps,
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        matches!(self, Self::OfficialHttps)
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerraformCloudRunCapability {
    WorkspaceDescription,
    BoundedRunEvidence,
    ConfigurationUploadProposal,
    RunCreateProposal,
    ApplyProposal,
    RunReceiptRecording,
    RunResultFingerprintVerification,
    ReversibleRegistration,
}

/// Capability metadata is part of the registration digest and cannot be
/// broadened by a provider implementation after registration.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerraformCloudRunCapabilitySnapshot {
    pub capabilities: BTreeSet<TerraformCloudRunCapability>,
    pub read_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub native_status: NativeStatus,
}

impl TerraformCloudRunCapabilitySnapshot {
    pub fn layer1() -> Self {
        Self {
            capabilities: BTreeSet::from([
                TerraformCloudRunCapability::WorkspaceDescription,
                TerraformCloudRunCapability::BoundedRunEvidence,
                TerraformCloudRunCapability::ConfigurationUploadProposal,
                TerraformCloudRunCapability::RunCreateProposal,
                TerraformCloudRunCapability::ApplyProposal,
                TerraformCloudRunCapability::RunReceiptRecording,
                TerraformCloudRunCapability::RunResultFingerprintVerification,
                TerraformCloudRunCapability::ReversibleRegistration,
            ]),
            read_only: true,
            external_writes: false,
            kernel_authority: false,
            native_status: NativeStatus::BlockedEnv,
        }
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        if *self == Self::layer1() {
            Ok(())
        } else {
            Err(TerraformCloudRunError::InvalidRegistration)
        }
    }
}

/// Exact HCP Terraform plus Hartevo Mission scope. Resource IDs are optional
/// until a read/proposal binds them; when present they are exact fences.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerraformCloudScope {
    pub hostname: HcpTerraformHostname,
    pub organization: OrganizationId,
    pub terraform_project: TerraformProjectId,
    pub workspace: WorkspaceId,
    pub workspace_revision: WorkspaceRevision,
    pub lock_identity: LockIdentity,
    pub hartevo_project: HartevoProjectId,
    pub mission: MissionId,
    pub work_product: WorkProductId,
    pub resources: TerraformResourceFence,
}

impl TerraformCloudScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hostname: impl Into<String>,
        organization: impl Into<String>,
        terraform_project: impl Into<String>,
        workspace: impl Into<String>,
        workspace_revision: impl Into<String>,
        lock_identity: impl Into<String>,
        hartevo_project: impl Into<String>,
        mission: impl Into<String>,
        work_product: impl Into<String>,
    ) -> Result<Self, TerraformCloudRunError> {
        let scope = Self {
            hostname: HcpTerraformHostname::parse(hostname)?,
            organization: OrganizationId::new(organization)?,
            terraform_project: TerraformProjectId::new(terraform_project)?,
            workspace: WorkspaceId::new(workspace)?,
            workspace_revision: WorkspaceRevision::new(workspace_revision)?,
            lock_identity: LockIdentity::new(lock_identity)?,
            hartevo_project: HartevoProjectId::new(hartevo_project)?,
            mission: MissionId::new(mission)?,
            work_product: WorkProductId::new(work_product)?,
            resources: TerraformResourceFence::default(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_resources(
        mut self,
        resources: TerraformResourceFence,
    ) -> Result<Self, TerraformCloudRunError> {
        resources.validate()?;
        self.resources = resources;
        self.validate()?;
        Ok(self)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.organization.validate()?;
        self.terraform_project.validate()?;
        self.workspace.validate()?;
        self.workspace_revision.validate()?;
        self.lock_identity.validate()?;
        self.hartevo_project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.resources.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerraformResourceFence {
    pub configuration_version: Option<ConfigurationVersionId>,
    pub run: Option<RunId>,
    pub plan: Option<PlanId>,
    pub apply: Option<ApplyId>,
    pub policy_evaluation: Option<PolicyEvaluationId>,
    pub policy_set: Option<PolicySetId>,
}

impl TerraformResourceFence {
    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        if self.plan.is_some() && self.run.is_none()
            || self.apply.is_some() && self.run.is_none()
            || self.policy_evaluation.is_some() && self.run.is_none()
        {
            return Err(TerraformCloudRunError::InvalidInput {
                field: "resource fence",
                reason: "plan, apply, and policy evaluation require a run",
            });
        }
        Ok(())
    }
}

/// Opaque identity for a team/user token held by the host. Token bytes are
/// intentionally absent and cannot be serialized by this type.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_id: String,
    pub scope_digest: Digest,
    pub credential_revision: u64,
    pub auth_method: AuthMethod,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &"<redacted>")
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &TerraformCloudScope,
        credential_revision: u64,
    ) -> Result<Self, TerraformCloudRunError> {
        let reference = Self {
            reference_id: reference_id.into(),
            scope_digest: scope.digest(),
            credential_revision,
            auth_method: AuthMethod::TeamUserToken,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        if !self.reference_id.starts_with("secret-ref-")
            || self.reference_id.len() > MAX_IDENTIFIER_BYTES
            || self.credential_revision == 0
        {
            return Err(TerraformCloudRunError::InvalidInput {
                field: "secret reference",
                reason: "must use a bounded secret-ref id and non-zero revision",
            });
        }
        self.scope_digest.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    TeamUserToken,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerraformCloudRunRegistration {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub adapter_revision: u64,
    pub capability_snapshot: TerraformCloudRunCapabilitySnapshot,
    pub scope: TerraformCloudScope,
    pub secret_reference: SecretReference,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl TerraformCloudRunRegistration {
    pub fn new(
        scope: TerraformCloudScope,
        secret_reference: SecretReference,
    ) -> Result<Self, TerraformCloudRunError> {
        let registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            adapter_revision: 1,
            capability_snapshot: TerraformCloudRunCapabilitySnapshot::layer1(),
            scope,
            secret_reference,
            registration_revision: 1,
            status: RegistrationStatus::Active,
            registration_digest: Digest::pending(),
        };
        let mut registration = registration;
        registration.registration_digest = registration.computed_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.adapter_revision == 0
            || self.registration_revision == 0
        {
            return Err(TerraformCloudRunError::InvalidRegistration);
        }
        self.plugin_version.validate()?;
        self.contract_digest.validate()?;
        self.capability_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.secret_reference.scope_digest != self.scope.digest()
            || self.registration_digest != self.computed_digest()
        {
            return Err(TerraformCloudRunError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.registration_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, TerraformCloudRunError> {
        self.validate()?;
        if self.status != RegistrationStatus::Active {
            return Err(TerraformCloudRunError::RegistrationRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(TerraformCloudRunError::InvalidRegistration)?;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            previous_digest,
            revoked_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: true,
        })
    }
}

pub type TerraformCloudRunPluginRegistration = TerraformCloudRunRegistration;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_digest: Digest,
    pub revoked_digest: Digest,
    pub registration_revision: u64,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProductBinding {
    pub project_id: HartevoProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: u64,
    pub work_product_revision: u64,
}

impl MissionWorkProductBinding {
    pub fn new(
        scope: &TerraformCloudScope,
        mission_revision: u64,
        work_product_revision: u64,
    ) -> Result<Self, TerraformCloudRunError> {
        let binding = Self {
            project_id: scope.hartevo_project.clone(),
            mission_id: scope.mission.clone(),
            work_product_id: scope.work_product.clone(),
            mission_revision,
            work_product_revision,
        };
        binding.validate_for(scope)?;
        Ok(binding)
    }

    pub fn validate_for(&self, scope: &TerraformCloudScope) -> Result<(), TerraformCloudRunError> {
        if self.project_id != scope.hartevo_project
            || self.mission_id != scope.mission
            || self.work_product_id != scope.work_product
            || self.mission_revision == 0
            || self.work_product_revision == 0
        {
            Err(TerraformCloudRunError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Pending,
    Granted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub consent_revision: u64,
    pub policy_revision: u64,
    pub state: ConsentState,
}

impl ConsentBinding {
    pub const fn pending(consent_revision: u64, policy_revision: u64) -> Self {
        Self {
            consent_revision,
            policy_revision,
            state: ConsentState::Pending,
        }
    }

    pub const fn granted(consent_revision: u64, policy_revision: u64) -> Self {
        Self {
            consent_revision,
            policy_revision,
            state: ConsentState::Granted,
        }
    }

    pub fn validate(self) -> Result<(), TerraformCloudRunError> {
        if self.consent_revision == 0 || self.policy_revision == 0 {
            Err(TerraformCloudRunError::InvalidInput {
                field: "consent binding",
                reason: "consent and policy revisions must be non-zero",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationSource {
    VersionControl,
    GeneratedArchive,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationVersionFence {
    pub id: ConfigurationVersionId,
    pub source: ConfigurationSource,
    pub source_ref: String,
    pub commit_sha: Option<String>,
    pub archive_digest: Digest,
}

impl ConfigurationVersionFence {
    pub fn new(
        id: impl Into<String>,
        source: ConfigurationSource,
        source_ref: impl Into<String>,
        commit_sha: Option<String>,
        archive_digest: Digest,
    ) -> Result<Self, TerraformCloudRunError> {
        let fence = Self {
            id: ConfigurationVersionId::new(id)?,
            source,
            source_ref: source_ref.into(),
            commit_sha,
            archive_digest,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.id.validate()?;
        validate_bounded_text(&self.source_ref, "configuration source", MAX_SOURCE_BYTES)?;
        if let Some(commit_sha) = &self.commit_sha {
            validate_bounded_text(commit_sha, "commit SHA", MAX_IDENTIFIER_BYTES)?;
        }
        self.archive_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationProposalRequest {
    pub scope: TerraformCloudScope,
    pub configuration: ConfigurationVersionFence,
    pub binding: MissionWorkProductBinding,
    pub consent: ConsentBinding,
}

impl ConfigurationProposalRequest {
    pub fn new(
        scope: TerraformCloudScope,
        configuration: ConfigurationVersionFence,
        mission_revision: u64,
        work_product_revision: u64,
        consent: ConsentBinding,
    ) -> Result<Self, TerraformCloudRunError> {
        let request = Self {
            binding: MissionWorkProductBinding::new(
                &scope,
                mission_revision,
                work_product_revision,
            )?,
            scope,
            configuration,
            consent,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.configuration.validate()?;
        self.binding.validate_for(&self.scope)?;
        self.consent.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Speculative,
    Normal,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationProposal {
    pub proposal_id: String,
    pub proposal_digest: Digest,
    pub scope: TerraformCloudScope,
    pub configuration: ConfigurationVersionFence,
    pub binding: MissionWorkProductBinding,
    pub consent: ConsentBinding,
    pub operation: String,
    pub upload_performed: bool,
    pub external_effect_created: bool,
    pub kernel_authority: bool,
    pub idempotency_fingerprint: Digest,
}

impl ConfigurationProposal {
    pub fn from_request(
        request: ConfigurationProposalRequest,
    ) -> Result<Self, TerraformCloudRunError> {
        request.validate()?;
        let idempotency_fingerprint = canonical_digest(&(
            &request.scope,
            &request.configuration,
            &request.binding,
            &request.consent,
        ));
        let mut proposal = Self {
            proposal_id: format!(
                "tfc-config-proposal-{}",
                &idempotency_fingerprint.as_str()[..24]
            ),
            proposal_digest: Digest::pending(),
            scope: request.scope,
            configuration: request.configuration,
            binding: request.binding,
            consent: request.consent,
            operation: "configuration_upload_proposal".to_owned(),
            upload_performed: false,
            external_effect_created: false,
            kernel_authority: false,
            idempotency_fingerprint,
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.configuration.validate()?;
        self.binding.validate_for(&self.scope)?;
        self.consent.validate()?;
        self.idempotency_fingerprint.validate()?;
        if self.operation != "configuration_upload_proposal"
            || self.upload_performed
            || self.external_effect_created
            || self.kernel_authority
            || self.proposal_digest != self.computed_digest()
        {
            return Err(TerraformCloudRunError::MutationForbidden {
                operation: "configuration upload",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunProposalRequest {
    pub configuration_proposal: ConfigurationProposal,
    pub run_id: Option<RunId>,
    pub mode: RunMode,
    pub auto_apply: bool,
    pub consent: ConsentBinding,
}

impl RunProposalRequest {
    pub fn new(
        configuration_proposal: ConfigurationProposal,
        run_id: Option<RunId>,
        mode: RunMode,
        auto_apply: bool,
        consent: ConsentBinding,
    ) -> Result<Self, TerraformCloudRunError> {
        let request = Self {
            configuration_proposal,
            run_id,
            mode,
            auto_apply,
            consent,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.configuration_proposal.validate()?;
        self.consent.validate()?;
        if self.consent != self.configuration_proposal.consent {
            return Err(TerraformCloudRunError::ScopeMismatch);
        }
        if self.mode == RunMode::Speculative && self.auto_apply {
            return Err(TerraformCloudRunError::SpeculativeApply);
        }
        if self.auto_apply && self.consent.state != ConsentState::Granted {
            return Err(TerraformCloudRunError::ConsentRequired);
        }
        if let Some(run_id) = &self.run_id {
            run_id.validate()?;
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunProposal {
    pub proposal_id: String,
    pub proposal_digest: Digest,
    pub scope: TerraformCloudScope,
    pub configuration_proposal_digest: Digest,
    pub configuration: ConfigurationVersionFence,
    pub binding: MissionWorkProductBinding,
    pub consent: ConsentBinding,
    pub run_id: Option<RunId>,
    pub mode: RunMode,
    pub auto_apply: bool,
    pub operation: String,
    pub run_create_performed: bool,
    pub external_effect_created: bool,
    pub kernel_authority: bool,
    pub idempotency_fingerprint: Digest,
}

impl RunProposal {
    pub fn from_request(request: RunProposalRequest) -> Result<Self, TerraformCloudRunError> {
        request.validate()?;
        let config = &request.configuration_proposal;
        let idempotency_fingerprint = canonical_digest(&(
            &config.proposal_digest,
            &request.run_id,
            request.mode,
            request.auto_apply,
            &request.consent,
        ));
        let mut proposal = Self {
            proposal_id: format!(
                "tfc-run-proposal-{}",
                &idempotency_fingerprint.as_str()[..24]
            ),
            proposal_digest: Digest::pending(),
            scope: config.scope.clone(),
            configuration_proposal_digest: config.proposal_digest.clone(),
            configuration: config.configuration.clone(),
            binding: config.binding.clone(),
            consent: request.consent,
            run_id: request.run_id,
            mode: request.mode,
            auto_apply: request.auto_apply,
            operation: "run_create_proposal".to_owned(),
            run_create_performed: false,
            external_effect_created: false,
            kernel_authority: false,
            idempotency_fingerprint,
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.configuration.validate()?;
        self.binding.validate_for(&self.scope)?;
        self.consent.validate()?;
        self.configuration_proposal_digest.validate()?;
        self.idempotency_fingerprint.validate()?;
        if self.operation != "run_create_proposal"
            || self.run_create_performed
            || self.external_effect_created
            || self.kernel_authority
            || (self.mode == RunMode::Speculative && self.auto_apply)
            || self.proposal_digest != self.computed_digest()
        {
            return Err(TerraformCloudRunError::MutationForbidden {
                operation: "run create",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerraformRunStatus {
    Pending,
    Planning,
    Planned,
    Applying,
    Applied,
    Errored,
    Canceled,
    Discarded,
    ProviderUnknown,
}

impl TerraformRunStatus {
    pub fn from_provider(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" | "queuing" | "queued" => Self::Pending,
            "planning" => Self::Planning,
            "planned" | "planned_and_finished" => Self::Planned,
            "applying" => Self::Applying,
            "applied" => Self::Applied,
            "errored" | "error" => Self::Errored,
            "canceled" | "cancelled" => Self::Canceled,
            "discarded" => Self::Discarded,
            _ => Self::ProviderUnknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Applied | Self::Errored | Self::Canceled | Self::Discarded
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Pending,
    Running,
    Finished,
    Errored,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    NotCreated,
    Pending,
    Applying,
    Finished,
    Errored,
    Canceled,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyResult {
    Passed,
    Failed,
    OverrideRequired,
    NotEvaluated,
    ProviderUnknown,
}

impl PolicyResult {
    pub const fn blocks_apply(self) -> bool {
        matches!(self, Self::Failed | Self::OverrideRequired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CostAvailability {
    Available,
    Partial,
    Unavailable,
    NotRequested,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusTransition {
    pub from: Option<TerraformRunStatus>,
    pub to: TerraformRunStatus,
    pub observed_at: String,
}

impl StatusTransition {
    pub fn new(
        from: Option<TerraformRunStatus>,
        to: TerraformRunStatus,
        observed_at: impl Into<String>,
    ) -> Result<Self, TerraformCloudRunError> {
        let transition = Self {
            from,
            to,
            observed_at: observed_at.into(),
        };
        transition.validate()?;
        Ok(transition)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        validate_timestamp(&self.observed_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanEvidence {
    pub id: PlanId,
    pub status: PlanStatus,
    pub has_changes: Option<bool>,
    pub summary_digest: Digest,
    pub observed_at: String,
}

impl PlanEvidence {
    pub fn new(
        id: PlanId,
        status: PlanStatus,
        has_changes: Option<bool>,
        summary_digest: Digest,
        observed_at: impl Into<String>,
    ) -> Result<Self, TerraformCloudRunError> {
        let evidence = Self {
            id,
            status,
            has_changes,
            summary_digest,
            observed_at: observed_at.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.id.validate()?;
        self.summary_digest.validate()?;
        validate_timestamp(&self.observed_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyEvidence {
    pub evaluation_id: PolicyEvaluationId,
    pub policy_set_id: Option<PolicySetId>,
    pub result: PolicyResult,
    pub override_required: bool,
    pub summary_digest: Digest,
    pub observed_at: String,
}

impl PolicyEvidence {
    pub fn new(
        evaluation_id: PolicyEvaluationId,
        policy_set_id: Option<PolicySetId>,
        result: PolicyResult,
        summary_digest: Digest,
        observed_at: impl Into<String>,
    ) -> Result<Self, TerraformCloudRunError> {
        let evidence = Self {
            evaluation_id,
            policy_set_id,
            result,
            override_required: result == PolicyResult::OverrideRequired,
            summary_digest,
            observed_at: observed_at.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.evaluation_id.validate()?;
        self.summary_digest.validate()?;
        if self.override_required != (self.result == PolicyResult::OverrideRequired) {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        validate_timestamp(&self.observed_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CostEvidence {
    pub estimate_id: Option<String>,
    pub availability: CostAvailability,
    pub summary_digest: Option<Digest>,
    pub observed_at: String,
}

impl CostEvidence {
    pub fn new(
        estimate_id: Option<String>,
        availability: CostAvailability,
        summary_digest: Option<Digest>,
        observed_at: impl Into<String>,
    ) -> Result<Self, TerraformCloudRunError> {
        let evidence = Self {
            estimate_id,
            availability,
            summary_digest,
            observed_at: observed_at.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        if let Some(estimate_id) = &self.estimate_id {
            validate_bounded_text(estimate_id, "cost estimate", MAX_IDENTIFIER_BYTES)?;
        }
        if let Some(summary_digest) = &self.summary_digest {
            summary_digest.validate()?;
        }
        if self.availability == CostAvailability::Available && self.summary_digest.is_none() {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        validate_timestamp(&self.observed_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyEvidence {
    pub id: ApplyId,
    pub status: ApplyStatus,
    pub summary_digest: Option<Digest>,
    pub observed_at: String,
}

impl ApplyEvidence {
    pub fn new(
        id: ApplyId,
        status: ApplyStatus,
        summary_digest: Option<Digest>,
        observed_at: impl Into<String>,
    ) -> Result<Self, TerraformCloudRunError> {
        let evidence = Self {
            id,
            status,
            summary_digest,
            observed_at: observed_at.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.id.validate()?;
        if let Some(summary_digest) = &self.summary_digest {
            summary_digest.validate()?;
        }
        validate_timestamp(&self.observed_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEvidence {
    pub scope: TerraformCloudScope,
    pub configuration: ConfigurationVersionFence,
    pub run_id: RunId,
    pub status: TerraformRunStatus,
    pub mode: RunMode,
    pub has_changes: Option<bool>,
    pub speculative: bool,
    pub auto_apply: bool,
    pub provider_request_id: Option<String>,
    pub status_transitions: Vec<StatusTransition>,
    pub plan: Option<PlanEvidence>,
    pub apply: Option<ApplyEvidence>,
    pub policy: Option<PolicyEvidence>,
    pub cost: Option<CostEvidence>,
    pub observed_at: String,
    pub evidence_digest: Digest,
}

impl RunEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: TerraformCloudScope,
        configuration: ConfigurationVersionFence,
        run_id: RunId,
        status: TerraformRunStatus,
        mode: RunMode,
        has_changes: Option<bool>,
        auto_apply: bool,
        provider_request_id: Option<String>,
        status_transitions: Vec<StatusTransition>,
        plan: Option<PlanEvidence>,
        apply: Option<ApplyEvidence>,
        policy: Option<PolicyEvidence>,
        cost: Option<CostEvidence>,
        observed_at: impl Into<String>,
    ) -> Result<Self, TerraformCloudRunError> {
        let mut evidence = Self {
            scope,
            configuration,
            run_id,
            status,
            mode,
            has_changes,
            speculative: mode == RunMode::Speculative,
            auto_apply,
            provider_request_id,
            status_transitions,
            plan,
            apply,
            policy,
            cost,
            observed_at: observed_at.into(),
            evidence_digest: Digest::pending(),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn fingerprint(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.configuration.validate()?;
        self.run_id.validate()?;
        if self.configuration.id
            != self
                .scope
                .resources
                .configuration_version
                .clone()
                .unwrap_or_else(|| self.configuration.id.clone())
        {
            return Err(TerraformCloudRunError::StaleConfiguration);
        }
        if let Some(bound_run) = &self.scope.resources.run
            && bound_run != &self.run_id
        {
            return Err(TerraformCloudRunError::StaleRun);
        }
        if self.speculative != (self.mode == RunMode::Speculative) {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        if self.mode == RunMode::Speculative && self.auto_apply {
            return Err(TerraformCloudRunError::SpeculativeApply);
        }
        if let Some(provider_request_id) = &self.provider_request_id {
            validate_bounded_text(
                provider_request_id,
                "provider request id",
                MAX_PROVIDER_REQUEST_ID_BYTES,
            )?;
        }
        if self.status_transitions.len() > MAX_STATUS_TRANSITIONS {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        for transition in &self.status_transitions {
            transition.validate()?;
        }
        if let Some(plan) = &self.plan {
            plan.validate()?;
            if let Some(bound_plan) = &self.scope.resources.plan
                && bound_plan != &plan.id
            {
                return Err(TerraformCloudRunError::StaleRun);
            }
        }
        if let Some(apply) = &self.apply {
            apply.validate()?;
            if let Some(bound_apply) = &self.scope.resources.apply
                && bound_apply != &apply.id
            {
                return Err(TerraformCloudRunError::StaleRun);
            }
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
            if let Some(bound_policy) = &self.scope.resources.policy_evaluation
                && bound_policy != &policy.evaluation_id
            {
                return Err(TerraformCloudRunError::StaleRun);
            }
            if let Some(bound_set) = &self.scope.resources.policy_set
                && policy.policy_set_id.as_ref() != Some(bound_set)
            {
                return Err(TerraformCloudRunError::StaleRun);
            }
        }
        if let Some(cost) = &self.cost {
            cost.validate()?;
        }
        validate_timestamp(&self.observed_at)?;
        self.evidence_digest.validate()?;
        if self.evidence_digest != self.computed_digest() {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn outcome(&self) -> RunOutcome {
        if self.status == TerraformRunStatus::ProviderUnknown
            || self
                .plan
                .as_ref()
                .is_some_and(|plan| plan.status == PlanStatus::ProviderUnknown)
            || self
                .apply
                .as_ref()
                .is_some_and(|apply| apply.status == ApplyStatus::ProviderUnknown)
            || self
                .policy
                .as_ref()
                .is_some_and(|policy| policy.result == PolicyResult::ProviderUnknown)
            || self
                .cost
                .as_ref()
                .is_some_and(|cost| cost.availability == CostAvailability::ProviderUnknown)
        {
            return RunOutcome::ProviderUnknown;
        }
        if self
            .policy
            .as_ref()
            .is_some_and(|policy| policy.result.blocks_apply())
        {
            return RunOutcome::PolicyBlocked;
        }
        if self
            .apply
            .as_ref()
            .is_some_and(|apply| apply.status == ApplyStatus::Applying)
            || self.status == TerraformRunStatus::Applying
        {
            return RunOutcome::Applying;
        }
        if self.status.is_terminal()
            || self.apply.as_ref().is_some_and(|apply| {
                matches!(
                    apply.status,
                    ApplyStatus::Finished | ApplyStatus::Errored | ApplyStatus::Canceled
                )
            })
        {
            return RunOutcome::Terminal;
        }
        if self.speculative {
            return if self.has_changes == Some(false) {
                RunOutcome::SpeculativeNoChanges
            } else {
                RunOutcome::SpeculativeChanges
            };
        }
        if self.has_changes == Some(false) {
            return RunOutcome::NoChange;
        }
        if self
            .cost
            .as_ref()
            .is_some_and(|cost| cost.availability == CostAvailability::Available)
            && self
                .policy
                .as_ref()
                .is_some_and(|policy| policy.result == PolicyResult::Passed)
            && self.has_changes == Some(true)
        {
            return RunOutcome::Applyable;
        }
        if self.cost.as_ref().is_some_and(|cost| {
            matches!(
                cost.availability,
                CostAvailability::Available | CostAvailability::Partial
            )
        }) {
            return RunOutcome::CostEstimated;
        }
        RunOutcome::Planned
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    SpeculativeNoChanges,
    SpeculativeChanges,
    Planned,
    NoChange,
    PolicyBlocked,
    CostEstimated,
    Applyable,
    Applying,
    Terminal,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthority {
    ProviderMetadataOnly,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReceipt {
    pub receipt_id: String,
    pub receipt_digest: Digest,
    pub registration_digest: Digest,
    pub provider_version: PluginVersion,
    pub scope: TerraformCloudScope,
    pub configuration: ConfigurationVersionFence,
    pub run_id: RunId,
    pub evidence_digest: Digest,
    pub provider_request_id: Option<String>,
    pub status: TerraformRunStatus,
    pub mode: RunMode,
    pub has_changes: Option<bool>,
    pub speculative: bool,
    pub auto_apply: bool,
    pub status_transitions: Vec<StatusTransition>,
    pub plan: Option<PlanEvidence>,
    pub apply: Option<ApplyEvidence>,
    pub policy: Option<PolicyEvidence>,
    pub cost: Option<CostEvidence>,
    pub observed_at: String,
    pub independent: bool,
    pub truncated: bool,
    pub authority: EvidenceAuthority,
}

impl RunReceipt {
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_evidence(
        evidence: &RunEvidence,
        registration_digest: Digest,
    ) -> Result<Self, TerraformCloudRunError> {
        evidence.validate()?;
        registration_digest.validate()?;
        let mut receipt = Self {
            receipt_id: format!(
                "tfc-run-receipt-{}",
                &evidence.evidence_digest.as_str()[..24]
            ),
            receipt_digest: Digest::pending(),
            registration_digest: registration_digest.clone(),
            provider_version: PROVIDER_VERSION,
            scope: evidence.scope.clone(),
            configuration: evidence.configuration.clone(),
            run_id: evidence.run_id.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            provider_request_id: evidence.provider_request_id.clone(),
            status: evidence.status,
            mode: evidence.mode,
            has_changes: evidence.has_changes,
            speculative: evidence.speculative,
            auto_apply: evidence.auto_apply,
            status_transitions: evidence.status_transitions.clone(),
            plan: evidence.plan.clone(),
            apply: evidence.apply.clone(),
            policy: evidence.policy.clone(),
            cost: evidence.cost.clone(),
            observed_at: evidence.observed_at.clone(),
            independent: true,
            truncated: false,
            authority: EvidenceAuthority::ProviderMetadataOnly,
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate_against(evidence, &registration_digest)?;
        Ok(receipt)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.receipt_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate_against(
        &self,
        evidence: &RunEvidence,
        registration_digest: &Digest,
    ) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.configuration.validate()?;
        self.evidence_digest.validate()?;
        self.receipt_digest.validate()?;
        self.registration_digest.validate()?;
        if self.registration_digest != *registration_digest
            || self.provider_version != PROVIDER_VERSION
            || self.scope != evidence.scope
            || self.configuration != evidence.configuration
            || self.run_id != evidence.run_id
            || self.evidence_digest != evidence.evidence_digest
            || self.provider_request_id != evidence.provider_request_id
            || self.status != evidence.status
            || self.mode != evidence.mode
            || self.has_changes != evidence.has_changes
            || self.speculative != evidence.speculative
            || self.auto_apply != evidence.auto_apply
            || self.status_transitions != evidence.status_transitions
            || self.plan != evidence.plan
            || self.apply != evidence.apply
            || self.policy != evidence.policy
            || self.cost != evidence.cost
            || self.observed_at != evidence.observed_at
            || self.receipt_digest != self.computed_digest()
            || !self.independent
            || self.truncated
            || self.authority != EvidenceAuthority::ProviderMetadataOnly
        {
            return Err(TerraformCloudRunError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyProposalRequest {
    pub run_proposal: RunProposal,
    pub evidence: RunEvidence,
    pub consent: ConsentBinding,
}

impl ApplyProposalRequest {
    pub fn new(
        run_proposal: RunProposal,
        evidence: RunEvidence,
        consent: ConsentBinding,
    ) -> Result<Self, TerraformCloudRunError> {
        let request = Self {
            run_proposal,
            evidence,
            consent,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.run_proposal.validate()?;
        self.evidence.validate()?;
        self.consent.validate()?;
        if self.run_proposal.mode == RunMode::Speculative || self.evidence.speculative {
            return Err(TerraformCloudRunError::SpeculativeApply);
        }
        if self.consent != self.run_proposal.consent
            || self.evidence.scope != self.run_proposal.scope
            || self.evidence.configuration != self.run_proposal.configuration
        {
            return Err(TerraformCloudRunError::ScopeMismatch);
        }
        if self.consent.state != ConsentState::Granted {
            return Err(TerraformCloudRunError::ConsentRequired);
        }
        if self.evidence.speculative {
            return Err(TerraformCloudRunError::SpeculativeApply);
        }
        if self
            .evidence
            .policy
            .as_ref()
            .is_none_or(|policy| policy.result != PolicyResult::Passed)
        {
            return Err(TerraformCloudRunError::PolicyBlocked);
        }
        match self.evidence.cost.as_ref().map(|cost| cost.availability) {
            Some(CostAvailability::Available) => {}
            Some(CostAvailability::Partial) => return Err(TerraformCloudRunError::CostPartial),
            _ => return Err(TerraformCloudRunError::CostUnavailable),
        }
        if self.evidence.outcome() != RunOutcome::Applyable {
            return Err(TerraformCloudRunError::StaleRun);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyProposal {
    pub proposal_id: String,
    pub proposal_digest: Digest,
    pub run_proposal_digest: Digest,
    pub scope: TerraformCloudScope,
    pub configuration: ConfigurationVersionFence,
    pub binding: MissionWorkProductBinding,
    pub consent: ConsentBinding,
    pub run_id: RunId,
    pub evidence_digest: Digest,
    pub operation: String,
    pub apply_performed: bool,
    pub external_effect_created: bool,
    pub kernel_authority: bool,
}

impl ApplyProposal {
    pub fn from_request(request: ApplyProposalRequest) -> Result<Self, TerraformCloudRunError> {
        request.validate()?;
        let fingerprint = canonical_digest(&(
            &request.run_proposal.proposal_digest,
            &request.evidence.evidence_digest,
            &request.consent,
        ));
        let mut proposal = Self {
            proposal_id: format!("tfc-apply-proposal-{}", &fingerprint.as_str()[..24]),
            proposal_digest: Digest::pending(),
            run_proposal_digest: request.run_proposal.proposal_digest,
            scope: request.run_proposal.scope,
            configuration: request.run_proposal.configuration,
            binding: request.run_proposal.binding,
            consent: request.consent,
            run_id: request.evidence.run_id,
            evidence_digest: request.evidence.evidence_digest,
            operation: "apply_proposal".to_owned(),
            apply_performed: false,
            external_effect_created: false,
            kernel_authority: false,
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.configuration.validate()?;
        self.binding.validate_for(&self.scope)?;
        self.consent.validate()?;
        self.run_id.validate()?;
        self.evidence_digest.validate()?;
        if self.operation != "apply_proposal"
            || self.apply_performed
            || self.external_effect_created
            || self.kernel_authority
            || self.proposal_digest != self.computed_digest()
        {
            return Err(TerraformCloudRunError::MutationForbidden { operation: "apply" });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultVerificationStatus {
    ProviderFingerprintMatch,
    NotVerified,
    ProviderUnknown,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerraformRunResultProposal {
    pub result_id: String,
    pub result_digest: Digest,
    pub status: String,
    pub scope: TerraformCloudScope,
    pub binding: MissionWorkProductBinding,
    pub consent: ConsentBinding,
    pub configuration: ConfigurationVersionFence,
    pub run_id: RunId,
    pub run_proposal_digest: Digest,
    pub receipt_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub outcome: RunOutcome,
    pub run_status: TerraformRunStatus,
    pub has_changes: Option<bool>,
    pub speculative: bool,
    pub auto_apply: bool,
    pub plan: Option<PlanEvidence>,
    pub apply: Option<ApplyEvidence>,
    pub policy: Option<PolicyEvidence>,
    pub cost: Option<CostEvidence>,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub external_effect_performed: bool,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub verification_status: ResultVerificationStatus,
}

impl TerraformRunResultProposal {
    pub fn from_receipt(
        run_proposal: &RunProposal,
        receipt: &RunReceipt,
        provenance: ProviderProvenance,
        native_transport: bool,
    ) -> Result<Self, TerraformCloudRunError> {
        run_proposal.validate()?;
        receipt.validate_against(
            &RunEvidence {
                scope: receipt.scope.clone(),
                configuration: receipt.configuration.clone(),
                run_id: receipt.run_id.clone(),
                status: receipt.status,
                mode: receipt.mode,
                has_changes: receipt.has_changes,
                speculative: receipt.speculative,
                auto_apply: receipt.auto_apply,
                provider_request_id: receipt.provider_request_id.clone(),
                status_transitions: receipt.status_transitions.clone(),
                plan: receipt.plan.clone(),
                apply: receipt.apply.clone(),
                policy: receipt.policy.clone(),
                cost: receipt.cost.clone(),
                observed_at: receipt.observed_at.clone(),
                evidence_digest: receipt.evidence_digest.clone(),
            },
            &receipt.registration_digest,
        )?;
        if receipt.scope != run_proposal.scope
            || receipt.configuration != run_proposal.configuration
            || receipt.provider_version != PROVIDER_VERSION
        {
            return Err(TerraformCloudRunError::ScopeMismatch);
        }
        if let Some(run_id) = &run_proposal.run_id
            && run_id != &receipt.run_id
        {
            return Err(TerraformCloudRunError::StaleRun);
        }
        let binding = run_proposal.binding.clone();
        let consent = run_proposal.consent;
        let mut proposal = Self {
            result_id: format!("tfc-run-result-{}", &receipt.receipt_digest.as_str()[..24]),
            result_digest: Digest::pending(),
            status: "proposed".to_owned(),
            scope: receipt.scope.clone(),
            binding,
            consent,
            configuration: receipt.configuration.clone(),
            run_id: receipt.run_id.clone(),
            run_proposal_digest: run_proposal.proposal_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            outcome: receipt_outcome(receipt),
            run_status: receipt.status,
            has_changes: receipt.has_changes,
            speculative: receipt.speculative,
            auto_apply: receipt.auto_apply,
            plan: receipt.plan.clone(),
            apply: receipt.apply.clone(),
            policy: receipt.policy.clone(),
            cost: receipt.cost.clone(),
            provenance,
            native_transport,
            native_connected: false,
            external_effect_performed: false,
            durable_adoption: false,
            kernel_authority: false,
            verification_status: ResultVerificationStatus::ProviderFingerprintMatch,
        };
        proposal.result_digest = proposal.computed_digest();
        proposal.validate_for_registration(&receipt.registration_digest)?;
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.result_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate_for_registration(
        &self,
        registration_digest: &Digest,
    ) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.binding.validate_for(&self.scope)?;
        self.consent.validate()?;
        self.configuration.validate()?;
        self.run_id.validate()?;
        self.run_proposal_digest.validate()?;
        self.receipt_digest.validate()?;
        self.evidence_digest.validate()?;
        self.registration_digest.validate()?;
        if self.status != "proposed"
            || self.native_connected
            || self.external_effect_performed
            || self.durable_adoption
            || self.kernel_authority
            || self.verification_status != ResultVerificationStatus::ProviderFingerprintMatch
            || self.result_digest != self.computed_digest()
            || self.outcome == RunOutcome::ProviderUnknown
        {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        if !registration_digest.as_str().is_empty() {
            registration_digest.validate()?;
        }
        if self.registration_digest != *registration_digest {
            return Err(TerraformCloudRunError::RegistrationDigestMismatch);
        }
        Ok(())
    }
}

fn receipt_outcome(receipt: &RunReceipt) -> RunOutcome {
    let evidence = RunEvidence {
        scope: receipt.scope.clone(),
        configuration: receipt.configuration.clone(),
        run_id: receipt.run_id.clone(),
        status: receipt.status,
        mode: receipt.mode,
        has_changes: receipt.has_changes,
        speculative: receipt.speculative,
        auto_apply: receipt.auto_apply,
        provider_request_id: receipt.provider_request_id.clone(),
        status_transitions: receipt.status_transitions.clone(),
        plan: receipt.plan.clone(),
        apply: receipt.apply.clone(),
        policy: receipt.policy.clone(),
        cost: receipt.cost.clone(),
        observed_at: receipt.observed_at.clone(),
        evidence_digest: receipt.evidence_digest.clone(),
    };
    evidence.outcome()
}

fn validate_timestamp(value: &str) -> Result<(), TerraformCloudRunError> {
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_control) {
        Err(TerraformCloudRunError::InvalidInput {
            field: "timestamp",
            reason: "must be a bounded provider timestamp",
        })
    } else {
        Ok(())
    }
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value)
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceDescription {
    pub scope: TerraformCloudScope,
    pub workspace_id: WorkspaceId,
    pub workspace_revision: WorkspaceRevision,
    pub lock_identity: LockIdentity,
    pub locked: bool,
    pub execution_mode: String,
    pub terraform_version: Option<String>,
    pub configuration_version: Option<ConfigurationVersionId>,
    pub current_run: Option<RunId>,
    pub proposal_capable: bool,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: Digest,
}

impl WorkspaceDescription {
    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.scope.validate()?;
        self.workspace_id.validate()?;
        self.workspace_revision.validate()?;
        self.lock_identity.validate()?;
        self.read_digest.validate()?;
        if self.workspace_id != self.scope.workspace
            || self.workspace_revision != self.scope.workspace_revision
            || self.lock_identity != self.scope.lock_identity
            || self.native_connected
            || self.provenance.is_connected()
        {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        Ok(())
    }
}
