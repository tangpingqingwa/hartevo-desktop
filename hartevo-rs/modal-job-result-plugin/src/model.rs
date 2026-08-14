//! Exact Modal scope, bounded job/result evidence, and safe identities.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::provider::ProviderCallResponse;
use crate::{
    MAX_BACKOFF_MILLIS, MAX_CAPTURED_RESULT_BYTES, MAX_EVIDENCE_BYTES, MAX_FUNCTION_TIMEOUT_MILLIS,
    MAX_IDENTIFIER_BYTES, MAX_POLL_ATTEMPTS, MAX_REPORTED_RESULT_BYTES, MAX_RETRY_ATTEMPTS,
    MAX_RUNTIME_MILLIS, MAX_SERIALIZED_INPUT_BYTES, MAX_SERIALIZED_RESULT_BYTES,
    ModalJobResultError, Result, digest_serialized, sha256_hex, validate_digest,
    validate_identifier, validate_text,
};

/// A SHA-256 digest used as a binding; it is never a container for a raw body
/// or secret.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
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

macro_rules! define_revision_identity {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: String,
            pub revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                validate_identifier(&id, $field)?;
                if revision == 0 {
                    return Err(ModalJobResultError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.id, $field)?;
                if self.revision == 0 {
                    Err(ModalJobResultError::InvalidScope)
                } else {
                    Ok(())
                }
            }

            pub fn as_str(&self) -> &str {
                &self.id
            }

            pub fn digest(&self) -> Digest {
                Digest::from_serialized(self)
            }
        }
    };
}

define_revision_identity!(WorkspaceIdentity, "workspaceId");
define_revision_identity!(RegistrationId, "registrationId");
define_revision_identity!(FunctionIdentity, "functionId");
define_revision_identity!(EnvironmentIdentity, "environmentId");
define_revision_identity!(FunctionCallIdentity, "callId");
define_revision_identity!(MissionIdentity, "missionId");
define_revision_identity!(ProjectIdentity, "projectId");
define_revision_identity!(WorkProductIdentity, "workProductId");

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
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

/// The exact Modal API host and revision used by the registration.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentity {
    pub id: String,
    pub https_host: String,
    pub revision: u64,
}

impl HostIdentity {
    pub fn new(
        id: impl Into<String>,
        https_host: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        let https_host = https_host.into();
        validate_identifier(&id, "hostId")?;
        let https_host = normalize_https_host(&https_host)?;
        if revision == 0 {
            return Err(ModalJobResultError::InvalidScope);
        }
        Ok(Self {
            id,
            https_host,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(&self.id, &self.https_host, self.revision)?;
        if expected == *self {
            Ok(())
        } else {
            Err(ModalJobResultError::InvalidScope)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

fn normalize_https_host(value: &str) -> Result<String> {
    validate_text(value, "httpsHost", MAX_IDENTIFIER_BYTES)?;
    if !value.starts_with("https://")
        || value.ends_with('/')
        || value[8..].is_empty()
        || value[8..].contains(['/', '?', '#'])
    {
        return Err(ModalJobResultError::InvalidHttpsHost);
    }
    Ok(value.to_owned())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppDeploymentKind {
    Deployed,
    Ephemeral,
}

/// App identity includes the exact deployment and app revision. Ephemeral
/// Apps remain representable for a refusal test but cannot be looked up.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppIdentity {
    pub id: String,
    pub deployment_id: String,
    pub revision: u64,
    pub deployment_kind: AppDeploymentKind,
}

impl AppIdentity {
    pub fn new(
        id: impl Into<String>,
        deployment_id: impl Into<String>,
        revision: u64,
        deployment_kind: AppDeploymentKind,
    ) -> Result<Self> {
        let id = id.into();
        let deployment_id = deployment_id.into();
        validate_identifier(&id, "appId")?;
        validate_identifier(&deployment_id, "deploymentId")?;
        if revision == 0 {
            return Err(ModalJobResultError::InvalidScope);
        }
        Ok(Self {
            id,
            deployment_id,
            revision,
            deployment_kind,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            &self.id,
            &self.deployment_id,
            self.revision,
            self.deployment_kind,
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub const fn is_deployed(&self) -> bool {
        matches!(self.deployment_kind, AppDeploymentKind::Deployed)
    }
}

/// Serialized input identity. Only its digest and bounded size are retained.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputIdentity {
    pub id: String,
    pub revision: u64,
    pub serialized_digest: Digest,
    pub serialized_bytes: u64,
}

impl InputIdentity {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        serialized_digest: Digest,
        serialized_bytes: u64,
    ) -> Result<Self> {
        let id = id.into();
        validate_identifier(&id, "inputId")?;
        if revision == 0 {
            return Err(ModalJobResultError::InvalidScope);
        }
        serialized_digest.validate()?;
        if serialized_bytes == 0 || serialized_bytes > MAX_SERIALIZED_INPUT_BYTES {
            return Err(ModalJobResultError::SerializationLimit);
        }
        Ok(Self {
            id,
            revision,
            serialized_digest,
            serialized_bytes,
        })
    }

    pub fn from_bounded_bytes(id: impl Into<String>, revision: u64, bytes: &[u8]) -> Result<Self> {
        let serialized_bytes =
            u64::try_from(bytes.len()).map_err(|_| ModalJobResultError::SerializationLimit)?;
        Self::new(id, revision, Digest::from_text(bytes), serialized_bytes)
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            &self.id,
            self.revision,
            self.serialized_digest.clone(),
            self.serialized_bytes,
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Provider retry and bounded polling revision bound to the Mission.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub revision: u64,
    pub max_attempts: u8,
    pub timeout_millis: u64,
    pub max_polls: u8,
    pub poll_backoff_base_millis: u64,
    pub poll_backoff_max_millis: u64,
}

impl RetryPolicy {
    pub fn new(
        revision: u64,
        max_attempts: u8,
        timeout_millis: u64,
        max_polls: u8,
        poll_backoff_base_millis: u64,
        poll_backoff_max_millis: u64,
    ) -> Result<Self> {
        if revision == 0
            || max_attempts == 0
            || max_attempts > MAX_RETRY_ATTEMPTS
            || timeout_millis == 0
            || timeout_millis > MAX_FUNCTION_TIMEOUT_MILLIS
            || max_polls == 0
            || max_polls > MAX_POLL_ATTEMPTS
            || poll_backoff_base_millis == 0
            || poll_backoff_base_millis > poll_backoff_max_millis
            || poll_backoff_max_millis > MAX_BACKOFF_MILLIS
        {
            return Err(ModalJobResultError::InvalidScope);
        }
        Ok(Self {
            revision,
            max_attempts,
            timeout_millis,
            max_polls,
            poll_backoff_base_millis,
            poll_backoff_max_millis,
        })
    }

    pub fn default_for_revision(revision: u64) -> Result<Self> {
        Self::new(revision, 3, 30_000, MAX_POLL_ATTEMPTS, 250, 8_000)
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.revision,
            self.max_attempts,
            self.timeout_millis,
            self.max_polls,
            self.poll_backoff_base_millis,
            self.poll_backoff_max_millis,
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    /// Exponential poll backoff clamped to the exact registered maximum.
    pub fn poll_delay_millis(&self, poll_index: u8) -> u64 {
        let mut delay = self.poll_backoff_base_millis;
        for _ in 0..poll_index.min(32) {
            delay = delay.saturating_mul(2).min(self.poll_backoff_max_millis);
        }
        delay.min(self.poll_backoff_max_millis)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            revision: 1,
            max_attempts: 3,
            timeout_millis: 30_000,
            max_polls: MAX_POLL_ATTEMPTS,
            poll_backoff_base_millis: 250,
            poll_backoff_max_millis: 8_000,
        }
    }
}

/// Opaque Modal token/workspace reference. The opaque host handle is never
/// serializable, displayable, or included in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revision: u64,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ModalApiToken,
    WorkspaceToken,
}

impl SecretReference {
    pub fn modal_api_token(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::ModalApiToken, opaque_handle, revision)
    }

    pub fn modal_token(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        Self::modal_api_token(opaque_handle, revision)
    }

    pub fn workspace_token(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::WorkspaceToken, opaque_handle, revision)
    }

    pub fn new(kind: SecretKind, opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_handle = opaque_handle.into();
        validate_text(&opaque_handle, "secretReference", MAX_IDENTIFIER_BYTES)?;
        if revision == 0 {
            return Err(ModalJobResultError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            reference_digest: Digest::from_parts(
                "modal-opaque-secret-reference/v1",
                &[
                    ("kind", format!("{kind:?}")),
                    ("opaque_handle", opaque_handle),
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
            Err(ModalJobResultError::InvalidSecretReference)
        } else {
            Ok(())
        }
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

/// Exact host/Workspace/App deployment/Function/Environment/FunctionCall,
/// input/retry, and Mission/Project/Work Product fence.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModalScope {
    pub host: HostIdentity,
    pub workspace: WorkspaceIdentity,
    pub app: AppIdentity,
    pub function: FunctionIdentity,
    pub environment: EnvironmentIdentity,
    pub call: FunctionCallIdentity,
    pub input: InputIdentity,
    pub retry: RetryPolicy,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub work_product: WorkProductIdentity,
}

impl ModalScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: HostIdentity,
        workspace: WorkspaceIdentity,
        app: AppIdentity,
        function: FunctionIdentity,
        environment: EnvironmentIdentity,
        call: FunctionCallIdentity,
        input: InputIdentity,
        retry: RetryPolicy,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            host,
            workspace,
            app,
            function,
            environment,
            call,
            input,
            retry,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.host.validate()?;
        self.workspace.validate()?;
        self.app.validate()?;
        self.function.validate()?;
        self.environment.validate()?;
        self.call.validate()?;
        self.input.validate()?;
        self.retry.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn for_fixture() -> Self {
        let input = InputIdentity::from_bounded_bytes("input-1", 1, br#"{"value":42}"#)
            .expect("bounded fixture input");
        Self::new(
            HostIdentity::new("modal-api", "https://api.modal.com", 1).expect("host"),
            WorkspaceIdentity::new("workspace-1", 1).expect("workspace"),
            AppIdentity::new("app-1", "deployment-1", 7, AppDeploymentKind::Deployed).expect("app"),
            FunctionIdentity::new("function-1", 7).expect("function"),
            EnvironmentIdentity::new("environment-1", 3).expect("environment"),
            FunctionCallIdentity::new("fc-1", 1).expect("call"),
            input,
            RetryPolicy::default_for_revision(4).expect("retry"),
            MissionIdentity::new("mission-1", 9).expect("mission"),
            ProjectIdentity::new("project-1", 2).expect("project"),
            WorkProductIdentity::new("work-product-1", 5).expect("work product"),
        )
        .expect("scope")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn matches_provider_identities(
        &self,
        host: &HostIdentity,
        workspace: &WorkspaceIdentity,
        app: &AppIdentity,
        function: &FunctionIdentity,
        environment: &EnvironmentIdentity,
        call: &FunctionCallIdentity,
        input: &InputIdentity,
        retry: &RetryPolicy,
    ) -> Result<()> {
        if &self.host != host {
            return Err(ModalJobResultError::HostDrift);
        }
        if &self.workspace != workspace {
            return Err(ModalJobResultError::WorkspaceDrift);
        }
        if &self.app != app {
            return Err(ModalJobResultError::AppDrift);
        }
        if &self.function != function {
            return Err(ModalJobResultError::FunctionDrift);
        }
        if &self.environment != environment {
            return Err(ModalJobResultError::EnvironmentDrift);
        }
        if &self.call != call {
            return Err(ModalJobResultError::CallDrift);
        }
        if &self.input != input {
            return Err(ModalJobResultError::InputDrift);
        }
        if &self.retry != retry {
            return Err(ModalJobResultError::RetryDrift);
        }
        Ok(())
    }
}

impl fmt::Debug for ModalScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModalScope")
            .field("scope_digest", &self.digest())
            .field("host", &self.host)
            .field("workspace", &self.workspace)
            .field("app", &self.app)
            .field("function", &self.function)
            .field("environment", &self.environment)
            .field("call", &self.call)
            .field("input", &self.input)
            .field("retry", &self.retry)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

/// Closed read-only permission set bound into registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<String>,
    revision: u64,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only(revision: u64) -> Result<Self> {
        Self::new(
            Self::expected_permissions().into_iter().map(str::to_owned),
            revision,
        )
    }

    pub fn new(permissions: impl IntoIterator<Item = String>, revision: u64) -> Result<Self> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let expected = Self::expected_permissions()
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if revision == 0
            || permissions != expected
            || permissions.iter().any(|permission| {
                permission.is_empty()
                    || permission.len() > MAX_IDENTIFIER_BYTES
                    || permission.chars().any(char::is_control)
            })
        {
            return Err(ModalJobResultError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "modal-permission-snapshot/v1",
            &[
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    fn expected_permissions() -> [&'static str; 7] {
        [
            "workspace.read",
            "app.read",
            "function.read",
            "environment.read",
            "function_call.read",
            "function_call.result.read",
            "usage.read",
        ]
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.permissions.iter().cloned(), self.revision)?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(ModalJobResultError::InvalidPermissionSnapshot)
        }
    }
}

/// Layer-1 transport provenance. None of these variants can claim native,
/// connected, or first-party evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Canceled,
    Expired,
    ProviderUnknown,
}

impl JobStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Canceled | Self::Expired
        )
    }

    pub const fn is_intermediate(self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::ProviderUnknown)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Expired => "expired",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
    Truncated,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerError,
    Timeout,
    AccessLoss,
    SerializationLimit,
    ResultTooLarge,
    OutputExpired,
    EphemeralApp,
    ProviderUnknown,
}

/// Bounded usage metadata. It intentionally contains no provider receipt or
/// billing claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageEvidence {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub runtime_millis: Option<u64>,
    pub provider_retry_count: u8,
    pub poll_count: u8,
}

impl UsageEvidence {
    pub fn new(
        input_bytes: u64,
        output_bytes: u64,
        runtime_millis: Option<u64>,
        provider_retry_count: u8,
        poll_count: u8,
    ) -> Result<Self> {
        if input_bytes > MAX_EVIDENCE_BYTES
            || output_bytes > MAX_EVIDENCE_BYTES
            || runtime_millis.is_some_and(|value| value > MAX_RUNTIME_MILLIS)
            || provider_retry_count > MAX_RETRY_ATTEMPTS
            || poll_count > MAX_POLL_ATTEMPTS
        {
            return Err(ModalJobResultError::ResultTooLarge);
        }
        Ok(Self {
            input_bytes,
            output_bytes,
            runtime_millis,
            provider_retry_count,
            poll_count,
        })
    }

    pub fn for_input(input: &InputIdentity, poll_count: u8) -> Result<Self> {
        Self::new(input.serialized_bytes, 0, None, 0, poll_count)
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.input_bytes,
            self.output_bytes,
            self.runtime_millis,
            self.provider_retry_count,
            self.poll_count,
        )
        .map(|_| ())
    }
}

/// Result metadata with no result body. A successful result has a digest and
/// bounded captured/serialized sizes; redacted or truncated evidence remains
/// explicit and non-adoptable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultEvidence {
    pub result_digest: Option<Digest>,
    pub captured_bytes: u64,
    pub reported_bytes: Option<u64>,
    pub serialized: bool,
    pub serialization_digest: Option<Digest>,
    pub serialization_bytes: Option<u64>,
    pub error_code: Option<FailureCode>,
    pub error_digest: Option<Digest>,
    pub expires_at_epoch_seconds: Option<u64>,
    pub truncated: bool,
    pub redacted: bool,
    pub usage: UsageEvidence,
}

impl ResultEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn metadata(
        result_digest: Option<Digest>,
        captured_bytes: u64,
        reported_bytes: Option<u64>,
        serialized: bool,
        serialization_digest: Option<Digest>,
        serialization_bytes: Option<u64>,
        error_code: Option<FailureCode>,
        error_digest: Option<Digest>,
        expires_at_epoch_seconds: Option<u64>,
        truncated: bool,
        redacted: bool,
        usage: UsageEvidence,
    ) -> Result<Self> {
        if captured_bytes > MAX_CAPTURED_RESULT_BYTES
            || reported_bytes
                .is_some_and(|value| value > MAX_REPORTED_RESULT_BYTES || value < captured_bytes)
        {
            return Err(ModalJobResultError::ResultTooLarge);
        }
        if serialization_bytes.is_some_and(|value| value > MAX_SERIALIZED_RESULT_BYTES)
            || (serialized && (serialization_digest.is_none() || serialization_bytes.is_none()))
            || (!serialized && (serialization_digest.is_some() || serialization_bytes.is_some()))
        {
            return Err(ModalJobResultError::SerializationLimit);
        }
        if (truncated && reported_bytes.is_none() && !redacted)
            || expires_at_epoch_seconds.is_some_and(|value| value == 0)
        {
            return Err(ModalJobResultError::ResultTooLarge);
        }
        if let Some(digest) = &result_digest {
            digest.validate()?;
        }
        if let Some(digest) = &serialization_digest {
            digest.validate()?;
        }
        if let Some(digest) = &error_digest {
            digest.validate()?;
        }
        usage.validate()?;
        Ok(Self {
            result_digest,
            captured_bytes,
            reported_bytes,
            serialized,
            serialization_digest,
            serialization_bytes,
            error_code,
            error_digest,
            expires_at_epoch_seconds,
            truncated,
            redacted,
            usage,
        })
    }

    pub fn from_bounded_bytes(
        bytes: &[u8],
        expires_at_epoch_seconds: u64,
        usage: UsageEvidence,
    ) -> Result<Self> {
        let bytes_len =
            u64::try_from(bytes.len()).map_err(|_| ModalJobResultError::ResultTooLarge)?;
        if bytes_len > MAX_CAPTURED_RESULT_BYTES || bytes_len > MAX_SERIALIZED_RESULT_BYTES {
            return Err(ModalJobResultError::ResultTooLarge);
        }
        Self::metadata(
            Some(Digest::from_text(bytes)),
            bytes_len,
            Some(bytes_len),
            true,
            Some(Digest::from_text(bytes)),
            Some(bytes_len),
            None,
            None,
            Some(expires_at_epoch_seconds),
            false,
            false,
            usage,
        )
    }

    pub fn failure(
        code: FailureCode,
        error_digest: Option<Digest>,
        usage: UsageEvidence,
    ) -> Result<Self> {
        Self::metadata(
            None,
            0,
            None,
            false,
            None,
            None,
            Some(code),
            error_digest,
            None,
            false,
            true,
            usage,
        )
    }

    pub fn redacted(usage: UsageEvidence) -> Result<Self> {
        Self::metadata(
            None, 0, None, false, None, None, None, None, None, false, true, usage,
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        Self::metadata(
            self.result_digest.clone(),
            self.captured_bytes,
            self.reported_bytes,
            self.serialized,
            self.serialization_digest.clone(),
            self.serialization_bytes,
            self.error_code,
            self.error_digest.clone(),
            self.expires_at_epoch_seconds,
            self.truncated,
            self.redacted,
            self.usage,
        )
        .map(|_| ())
    }

    pub fn is_complete(&self) -> bool {
        !self.truncated && !self.redacted
    }

    pub fn is_non_adoptable(&self) -> bool {
        self.truncated || self.redacted
    }
}

/// The safe projection returned by one bounded FunctionCall observation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionCallProjection {
    pub scope_digest: Digest,
    pub host: HostIdentity,
    pub workspace: WorkspaceIdentity,
    pub app: AppIdentity,
    pub function: FunctionIdentity,
    pub environment: EnvironmentIdentity,
    pub call: FunctionCallIdentity,
    pub input: InputIdentity,
    pub retry: RetryPolicy,
    pub status: JobStatus,
    pub attempt_number: u8,
    pub poll_count: u8,
    pub next_poll_delay_millis: u64,
    pub result: Option<ResultEvidence>,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub observed_at_epoch_seconds: u64,
    pub provider_request_id_digest: Option<Digest>,
    pub failure_code: Option<FailureCode>,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl FunctionCallProjection {
    pub(crate) fn from_response(
        scope: &ModalScope,
        response: &ProviderCallResponse,
        provenance: TransportProvenance,
        next_poll_delay_millis: u64,
    ) -> Result<Self> {
        response.validate_integrity()?;
        scope.matches_provider_identities(
            &response.host,
            &response.workspace,
            &response.app,
            &response.function,
            &response.environment,
            &response.call,
            &response.input,
            &response.retry,
        )?;
        if response.poll_count > scope.retry.max_polls {
            return Err(ModalJobResultError::PollLimitExceeded);
        }
        if next_poll_delay_millis > MAX_BACKOFF_MILLIS {
            return Err(ModalJobResultError::PollBackoffExceeded);
        }
        if let Some(result) = &response.result {
            result.validate_integrity()?;
        }
        let status = if response.status == JobStatus::Succeeded
            && response.result.as_ref().is_some_and(|result| {
                result
                    .expires_at_epoch_seconds
                    .is_some_and(|expiry| expiry <= response.observed_at_epoch_seconds)
            }) {
            JobStatus::Expired
        } else {
            response.status
        };
        let response_truncated = response.response_truncated
            || response
                .result
                .as_ref()
                .is_some_and(|result| result.truncated);
        let completeness = if status == JobStatus::ProviderUnknown {
            ProjectionCompleteness::Unavailable
        } else if response_truncated {
            ProjectionCompleteness::Truncated
        } else if response
            .result
            .as_ref()
            .is_some_and(ResultEvidence::is_non_adoptable)
        {
            ProjectionCompleteness::Partial
        } else {
            ProjectionCompleteness::Complete
        };
        let mut projection = Self {
            scope_digest: scope.digest(),
            host: response.host.clone(),
            workspace: response.workspace.clone(),
            app: response.app.clone(),
            function: response.function.clone(),
            environment: response.environment.clone(),
            call: response.call.clone(),
            input: response.input.clone(),
            retry: response.retry.clone(),
            status,
            attempt_number: response.attempt_number,
            poll_count: response.poll_count,
            next_poll_delay_millis,
            result: response.result.clone(),
            completeness,
            response_truncated,
            observed_at_epoch_seconds: response.observed_at_epoch_seconds,
            provider_request_id_digest: response.provider_request_id_digest.clone(),
            failure_code: response
                .result
                .as_ref()
                .and_then(|result| result.error_code),
            provenance,
            replayed: false,
            evidence_digest: Digest::from_text("unsealed-modal-function-call-evidence"),
            connected: false,
            native: false,
            first_party: false,
        };
        projection.evidence_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub(crate) fn provider_unknown(
        scope: &ModalScope,
        poll_count: u8,
        observed_at_epoch_seconds: u64,
        failure_code: FailureCode,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let usage = UsageEvidence::for_input(&scope.input, poll_count)?;
        let response = ProviderCallResponse::for_scope(
            scope,
            JobStatus::ProviderUnknown,
            observed_at_epoch_seconds,
            poll_count,
            usage,
        )?
        .with_failure_code(failure_code);
        Self::from_response(
            scope,
            &response,
            provenance,
            scope.retry.poll_delay_millis(poll_count),
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.host.validate()?;
        self.workspace.validate()?;
        self.app.validate()?;
        self.function.validate()?;
        self.environment.validate()?;
        self.call.validate()?;
        self.input.validate()?;
        self.retry.validate()?;
        if self.attempt_number == 0
            || self.poll_count > self.retry.max_polls
            || self.next_poll_delay_millis > MAX_BACKOFF_MILLIS
            || self.observed_at_epoch_seconds == 0
            || self.connected
            || self.native
            || self.first_party
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(ModalJobResultError::TamperedEvidence);
        }
        if let Some(result) = &self.result {
            result.validate_integrity()?;
        }
        if let Some(digest) = &self.provider_request_id_digest {
            digest.validate()?;
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &ModalScope) -> bool {
        self.scope_digest == scope.digest()
            && self.host == scope.host
            && self.workspace == scope.workspace
            && self.app == scope.app
            && self.function == scope.function
            && self.environment == scope.environment
            && self.call == scope.call
            && self.input == scope.input
            && self.retry == scope.retry
    }

    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    pub fn is_non_adoptable(&self) -> bool {
        self.status == JobStatus::ProviderUnknown
            || self.completeness != ProjectionCompleteness::Complete
            || self.response_truncated
            || self
                .result
                .as_ref()
                .is_some_and(ResultEvidence::is_non_adoptable)
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "modal-function-call-projection/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("host", serde_json::to_string(&self.host).expect("identity")),
                (
                    "workspace",
                    serde_json::to_string(&self.workspace).expect("identity"),
                ),
                ("app", serde_json::to_string(&self.app).expect("identity")),
                (
                    "function",
                    serde_json::to_string(&self.function).expect("identity"),
                ),
                (
                    "environment",
                    serde_json::to_string(&self.environment).expect("identity"),
                ),
                ("call", serde_json::to_string(&self.call).expect("identity")),
                (
                    "input",
                    serde_json::to_string(&self.input).expect("identity"),
                ),
                ("retry", serde_json::to_string(&self.retry).expect("policy")),
                ("status", self.status.as_str().to_owned()),
                ("attempt", self.attempt_number.to_string()),
                ("poll", self.poll_count.to_string()),
                ("next_delay", self.next_poll_delay_millis.to_string()),
                (
                    "result",
                    serde_json::to_string(&self.result).expect("result metadata"),
                ),
                ("completeness", format!("{:?}", self.completeness)),
                ("truncated", self.response_truncated.to_string()),
                ("observed_at", self.observed_at_epoch_seconds.to_string()),
                (
                    "provider_request",
                    self.provider_request_id_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "failure",
                    self.failure_code
                        .map_or_else(String::new, |code| format!("{code:?}")),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}
