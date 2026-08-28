#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 Prefect flow-run result plugin."]
//!
//! This crate is a bounded read/proposal boundary for Prefect. It binds one
//! exact server host, account, workspace, flow, deployment, flow run, task
//! run, state filter, and Hartevo Project/Mission/Work Product scope. It has
//! no native HTTP client, credential resolver, flow/state/deployment/worker
//! mutation API, raw log/result representation, workflow-registry authority,
//! durable provider receipt, or Work Product adoption authority.
//!
//! Fixture, recording, fake, loopback, and BLOCKED_ENV transports are typed
//! evidence sources. They never claim connected, native, or first-party
//! evidence.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.prefect-flow-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-PREFECT-01-L1/v1";
pub const PLUGIN_ID: &str = "prefect.flow-result";
pub const SERVICE_ID: &str = "PrefectFlowResultService";
pub const PROVIDER_ID: &str = "PrefectProvider";
pub const CONSUMER_ID: &str = "MissionPrefectFlowConsumer";
pub const PREFECT_API_REVISION: &str = "prefect-rest-api-v3";
pub const PREFECT_API_BASE_PATH: &str = "/api";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/prefect-flow-result/service.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_PAGE_ITEMS: usize = 256;
pub const MAX_PAGES: usize = 32;
pub const MAX_TASK_RUNS: usize = 4_096;
pub const MAX_HISTORY_POINTS: usize = 4_096;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_FILTER_VALUES: usize = 16;
pub const MAX_RETRY_COUNT: u32 = 1_000_000;

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

pub const PLUGIN_VERSION: Version = Version::new(1, 0, 0);

/// Lowercase SHA-256 over canonical typed values. Raw provider payloads never
/// enter this type.
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

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded contract values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectServerHostIdentity {
    pub origin: String,
    pub host_id: String,
    pub api_revision: String,
    pub revision: u64,
}

impl PrefectServerHostIdentity {
    pub fn new(
        origin: impl Into<String>,
        host_id: impl Into<String>,
        api_revision: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        let identity = Self {
            origin: origin.into(),
            host_id: host_id.into(),
            api_revision: api_revision.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<()> {
        validate_origin(&self.origin)?;
        validate_identifier("server host id", &self.host_id)?;
        validate_identifier("API revision", &self.api_revision)?;
        if self.api_revision != PREFECT_API_REVISION {
            return Err(PrefectError::ApiRevisionMismatch);
        }
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

macro_rules! define_revisioned_identity {
    ($type_name:ident, $field:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $type_name {
            pub $field: String,
            pub revision: u64,
        }

        impl $type_name {
            pub fn new(value: impl Into<String>, revision: u64) -> Result<Self> {
                let identity = Self {
                    $field: value.into(),
                    revision,
                };
                identity.validate()?;
                Ok(identity)
            }

            fn validate(&self) -> Result<()> {
                validate_identifier($label, &self.$field)?;
                validate_revision(self.revision)
            }

            pub fn digest(&self) -> Digest {
                Digest::from_serializable(self)
            }
        }
    };
}

define_revisioned_identity!(PrefectAccountIdentity, account_id, "account id");
define_revisioned_identity!(PrefectWorkspaceIdentity, workspace_id, "workspace id");
define_revisioned_identity!(PrefectFlowIdentity, flow_id, "flow id");
define_revisioned_identity!(PrefectDeploymentIdentity, deployment_id, "deployment id");
define_revisioned_identity!(PrefectFlowRunIdentity, flow_run_id, "flow run id");
define_revisioned_identity!(PrefectTaskRunIdentity, task_run_id, "task run id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefectState {
    Scheduled,
    Pending,
    Running,
    Completed,
    Failed,
    Crashed,
    Cancelled,
    Paused,
    Late,
    ProviderUnknown,
}

impl PrefectState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::Crashed
                | Self::Cancelled
                | Self::ProviderUnknown
        )
    }

    pub const fn projection(self) -> PrefectRunProjection {
        match self {
            Self::Scheduled => PrefectRunProjection::Scheduled,
            Self::Pending => PrefectRunProjection::Pending,
            Self::Running => PrefectRunProjection::Running,
            Self::Completed => PrefectRunProjection::Completed,
            Self::Failed => PrefectRunProjection::Failed,
            Self::Crashed => PrefectRunProjection::Crashed,
            Self::Cancelled => PrefectRunProjection::Cancelled,
            Self::Paused => PrefectRunProjection::Paused,
            Self::Late => PrefectRunProjection::Late,
            Self::ProviderUnknown => PrefectRunProjection::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectStateScope {
    pub allowlisted_states: BTreeSet<PrefectState>,
    pub revision: u64,
}

impl PrefectStateScope {
    pub fn new(states: impl IntoIterator<Item = PrefectState>, revision: u64) -> Result<Self> {
        let state = Self {
            allowlisted_states: states.into_iter().collect(),
            revision,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<()> {
        validate_revision(self.revision)?;
        if self.allowlisted_states.is_empty() || self.allowlisted_states.len() > MAX_FILTER_VALUES {
            return Err(PrefectError::InvalidInput("allowlisted Prefect states"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn contains(&self, state: PrefectState) -> bool {
        self.allowlisted_states.contains(&state)
    }
}

/// The Hartevo Project/Mission/Work Product fence carried by every proposal.
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
    ) -> Result<Self> {
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

    fn validate(&self) -> Result<()> {
        validate_identifier("Project", &self.project_id)?;
        validate_identifier("Mission", &self.mission_id)?;
        validate_identifier("Work Product", &self.work_product_id)?;
        validate_revision(self.project_revision)?;
        validate_revision(self.mission_revision)?;
        validate_revision(self.work_product_revision)?;
        if !self.policy_digest.is_valid() || !self.consent_digest.is_valid() {
            return Err(PrefectError::InvalidDigest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrefectPermission {
    ServerHostRead,
    AccountRead,
    WorkspaceRead,
    FlowRead,
    DeploymentRead,
    FlowRunRead,
    TaskRunRead,
    StateRead,
    MissionScope,
}

impl PrefectPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerHostRead => "server-host:read",
            Self::AccountRead => "account:read",
            Self::WorkspaceRead => "workspace:read",
            Self::FlowRead => "flow:read",
            Self::DeploymentRead => "deployment:read",
            Self::FlowRunRead => "flow-run:read",
            Self::TaskRunRead => "task-run:read",
            Self::StateRead => "state:read",
            Self::MissionScope => "mission:scope",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectScope {
    pub server_host: PrefectServerHostIdentity,
    pub account: PrefectAccountIdentity,
    pub workspace: PrefectWorkspaceIdentity,
    pub flow: PrefectFlowIdentity,
    pub deployment: PrefectDeploymentIdentity,
    pub flow_run: PrefectFlowRunIdentity,
    pub task_run: PrefectTaskRunIdentity,
    pub state: PrefectStateScope,
    pub mission: MissionScopeBinding,
    pub permissions: BTreeSet<PrefectPermission>,
}

impl PrefectScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_host: PrefectServerHostIdentity,
        account: PrefectAccountIdentity,
        workspace: PrefectWorkspaceIdentity,
        flow: PrefectFlowIdentity,
        deployment: PrefectDeploymentIdentity,
        flow_run: PrefectFlowRunIdentity,
        task_run: PrefectTaskRunIdentity,
        state: PrefectStateScope,
        mission: MissionScopeBinding,
        permissions: impl IntoIterator<Item = PrefectPermission>,
    ) -> Result<Self> {
        let scope = Self {
            server_host,
            account,
            workspace,
            flow,
            deployment,
            flow_run,
            task_run,
            state,
            mission,
            permissions: permissions.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.server_host.validate()?;
        self.account.validate()?;
        self.workspace.validate()?;
        self.flow.validate()?;
        self.deployment.validate()?;
        self.flow_run.validate()?;
        self.task_run.validate()?;
        self.state.validate()?;
        self.mission.validate()?;
        let required = [
            PrefectPermission::ServerHostRead,
            PrefectPermission::AccountRead,
            PrefectPermission::WorkspaceRead,
            PrefectPermission::FlowRead,
            PrefectPermission::DeploymentRead,
            PrefectPermission::FlowRunRead,
            PrefectPermission::TaskRunRead,
            PrefectPermission::StateRead,
            PrefectPermission::MissionScope,
        ];
        if required
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(PrefectError::PermissionDrift);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn server_host_digest(&self) -> Digest {
        self.server_host.digest()
    }

    pub fn host_digest(&self) -> Digest {
        self.server_host_digest()
    }

    pub fn account_digest(&self) -> Digest {
        self.account.digest()
    }

    pub fn workspace_digest(&self) -> Digest {
        self.workspace.digest()
    }

    pub fn flow_digest(&self) -> Digest {
        self.flow.digest()
    }

    pub fn deployment_digest(&self) -> Digest {
        self.deployment.digest()
    }

    pub fn flow_run_digest(&self) -> Digest {
        self.flow_run.digest()
    }

    pub fn run_digest(&self) -> Digest {
        self.flow_run_digest()
    }

    pub fn task_run_digest(&self) -> Digest {
        self.task_run.digest()
    }

    pub fn task_digest(&self) -> Digest {
        self.task_run_digest()
    }

    pub fn state_digest(&self) -> Digest {
        self.state.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        let permissions: Vec<&str> = self
            .permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect();
        Digest::from_serializable(&permissions)
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.server_host.revision,
            self.account.revision,
            self.workspace.revision,
            self.flow.revision,
            self.deployment.revision,
            self.flow_run.revision,
            self.task_run.revision,
            self.state.revision,
            self.mission.project_revision,
            self.mission.mission_revision,
            self.mission.work_product_revision,
        ))
    }

    pub fn api_digest(&self) -> Digest {
        Digest::from_text(self.server_host.api_revision.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
}

/// Opaque reference to a credential held outside this crate. The reference
/// identifier is deliberately excluded from serialization and Debug output.
pub struct SecretReference {
    reference_id: String,
    kind: SecretKind,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            kind: self.kind,
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.kind == other.kind
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("kind", &self.kind)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecretReference", 5)?;
        state.serialize_field("referenceDigest", &self.reference_digest())?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        kind: SecretKind,
        scope: &PrefectScope,
        credential_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        let reference = Self {
            reference_id: reference_id.into(),
            kind,
            scope_digest: scope.scope_digest(),
            credential_revision,
            revoked: false,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn api_key(
        reference_id: impl Into<String>,
        scope: &PrefectScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(reference_id, SecretKind::ApiKey, scope, credential_revision)
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.reference_id,
            self.kind,
            &self.scope_digest,
            self.credential_revision,
        ))
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn is_bound_to(&self, scope: &PrefectScope) -> bool {
        !self.revoked && self.scope_digest == scope.scope_digest()
    }

    fn validate(&self) -> Result<()> {
        if !self.reference_id.starts_with("secret-ref-") {
            return Err(PrefectError::InvalidSecretReference);
        }
        validate_identifier("SecretReference", &self.reference_id)?;
        if self.credential_revision == 0 || !self.scope_digest.is_valid() {
            return Err(PrefectError::InvalidSecretReference);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectRegistration {
    pub status: RegistrationStatus,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub server_host_digest: Digest,
    pub account_digest: Digest,
    pub workspace_digest: Digest,
    pub flow_digest: Digest,
    pub deployment_digest: Digest,
    pub flow_run_digest: Digest,
    pub task_run_digest: Digest,
    pub state_digest: Digest,
    pub mission_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub scope_digest: Digest,
    pub credential_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub status: RegistrationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub credential_digest: Digest,
    pub revocation_digest: Digest,
}

impl PrefectRegistration {
    pub fn new(scope: &PrefectScope, secret_reference: &SecretReference) -> Result<Self> {
        scope.validate()?;
        if !secret_reference.is_bound_to(scope) {
            return if secret_reference.is_revoked() {
                Err(PrefectError::SecretRevoked)
            } else {
                Err(PrefectError::SecretScopeMismatch)
            };
        }
        let registration = Self {
            status: RegistrationStatus::Active,
            version_digest: Digest::from_serializable(&PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: Digest::from_serializable(&(PROVIDER_ID, PLUGIN_VERSION)),
            api_digest: scope.api_digest(),
            server_host_digest: scope.server_host_digest(),
            account_digest: scope.account_digest(),
            workspace_digest: scope.workspace_digest(),
            flow_digest: scope.flow_digest(),
            deployment_digest: scope.deployment_digest(),
            flow_run_digest: scope.flow_run_digest(),
            task_run_digest: scope.task_run_digest(),
            state_digest: scope.state_digest(),
            mission_digest: scope.mission_digest(),
            permission_digest: scope.permission_digest(),
            revision_digest: scope.revision_digest(),
            scope_digest: scope.scope_digest(),
            credential_digest: secret_reference.reference_digest(),
            registration_digest: Digest::from_text("uncomputed"),
            reversible: true,
            revocable: true,
        };
        let mut registration = registration;
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_text(format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.version_digest.as_str(),
            self.contract_digest.as_str(),
            self.provider_digest.as_str(),
            self.api_digest.as_str(),
            self.server_host_digest.as_str(),
            self.account_digest.as_str(),
            self.workspace_digest.as_str(),
            self.flow_digest.as_str(),
            self.deployment_digest.as_str(),
            self.flow_run_digest.as_str(),
            self.task_run_digest.as_str(),
            self.state_digest.as_str(),
            self.mission_digest.as_str(),
            self.permission_digest.as_str(),
            self.revision_digest.as_str(),
            self.scope_digest.as_str(),
            self.credential_digest.as_str(),
            self.reversible,
            self.revocable
        ))
    }

    pub fn validate_binding(
        &self,
        scope: &PrefectScope,
        secret_reference: &SecretReference,
    ) -> Result<()> {
        scope.validate()?;
        if self.compute_digest() != self.registration_digest {
            return Err(PrefectError::RegistrationTampered);
        }
        if !self.reversible || !self.revocable {
            return Err(PrefectError::RegistrationTampered);
        }
        if self.scope_digest != scope.scope_digest()
            || self.api_digest != scope.api_digest()
            || self.server_host_digest != scope.server_host_digest()
            || self.account_digest != scope.account_digest()
            || self.workspace_digest != scope.workspace_digest()
            || self.flow_digest != scope.flow_digest()
            || self.deployment_digest != scope.deployment_digest()
            || self.flow_run_digest != scope.flow_run_digest()
            || self.task_run_digest != scope.task_run_digest()
            || self.state_digest != scope.state_digest()
            || self.mission_digest != scope.mission_digest()
            || self.permission_digest != scope.permission_digest()
            || self.revision_digest != scope.revision_digest()
            || self.credential_digest != secret_reference.reference_digest()
        {
            return Err(PrefectError::RegistrationBindingDrift);
        }
        if secret_reference.is_revoked() {
            return Err(PrefectError::SecretRevoked);
        }
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(PrefectError::SecretScopeMismatch);
        }
        Ok(())
    }

    pub fn registration_id(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        self.status.is_active()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Unmounted)
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Unmounted {
            return Err(PrefectError::RegistrationInactive);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn revoke(&mut self, secret_reference: &mut SecretReference) -> Result<RevocationReceipt> {
        if !self.revocable {
            return Err(PrefectError::RegistrationRevoked);
        }
        if !self.status.is_active() && self.status != RegistrationStatus::Unmounted {
            return Err(PrefectError::RegistrationRevoked);
        }
        if self.credential_digest != secret_reference.reference_digest() {
            return Err(PrefectError::RegistrationBindingDrift);
        }
        let revocation_digest = Digest::from_serializable(&(
            &self.registration_digest,
            &self.credential_digest,
            self.status,
            "revoke",
        ));
        secret_reference.revoke();
        self.status = RegistrationStatus::Revoked;
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            credential_digest: self.credential_digest.clone(),
            revocation_digest,
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Revoked {
            return Err(PrefectError::RegistrationRevoked);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(&mut self, to: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let from = self.status;
        let allowed = matches!(
            (from, to),
            (
                RegistrationStatus::Active,
                RegistrationStatus::Unmounted | RegistrationStatus::Reversed
            ) | (
                RegistrationStatus::Unmounted,
                RegistrationStatus::Active | RegistrationStatus::Reversed
            )
        );
        if !allowed {
            return Err(if from == RegistrationStatus::Revoked {
                PrefectError::RegistrationRevoked
            } else {
                PrefectError::RegistrationInactive
            });
        }
        self.status = to;
        let transition_digest = Digest::from_serializable(&(&self.registration_digest, from, to));
        Ok(RegistrationTransitionEvidence {
            from,
            to,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }
}

#[derive(Default)]
pub struct PrefectRegistrationRegistry {
    registrations: BTreeMap<String, PrefectRegistration>,
}

impl fmt::Debug for PrefectRegistrationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrefectRegistrationRegistry")
            .field("registration_count", &self.registrations.len())
            .finish()
    }
}

impl PrefectRegistrationRegistry {
    pub fn register(&mut self, registration: PrefectRegistration) -> Result<RegistrationReceipt> {
        if registration.compute_digest() != registration.registration_digest {
            return Err(PrefectError::RegistrationTampered);
        }
        let key = registration.registration_digest.as_str().to_owned();
        if self.registrations.contains_key(&key) {
            return Err(PrefectError::DuplicateEvidence);
        }
        let receipt = RegistrationReceipt {
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            status: registration.status,
        };
        self.registrations.insert(key, registration);
        Ok(receipt)
    }

    pub fn get(&self, registration_digest: &Digest) -> Option<&PrefectRegistration> {
        self.registrations.get(registration_digest.as_str())
    }

    pub fn get_mut(&mut self, registration_digest: &Digest) -> Option<&mut PrefectRegistration> {
        self.registrations.get_mut(registration_digest.as_str())
    }

    pub fn revoke(
        &mut self,
        registration_digest: &Digest,
        secret_reference: &mut SecretReference,
    ) -> Result<RevocationReceipt> {
        self.get_mut(registration_digest)
            .ok_or(PrefectError::RegistrationBindingDrift)?
            .revoke(secret_reference)
    }

    pub fn restore(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence> {
        self.get_mut(registration_digest)
            .ok_or(PrefectError::RegistrationBindingDrift)?
            .remount()
    }

    pub fn reverse(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence> {
        self.get_mut(registration_digest)
            .ok_or(PrefectError::RegistrationBindingDrift)?
            .reverse()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PrefectError {
    #[error("invalid Layer-1 Prefect input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid opaque API-key SecretReference")]
    InvalidSecretReference,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("SecretReference is bound to a different exact scope")]
    SecretScopeMismatch,
    #[error("registration binding drifted")]
    RegistrationBindingDrift,
    #[error("registration digest was tampered")]
    RegistrationTampered,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("permission digest or required read-only permission drifted")]
    PermissionDrift,
    #[error("Prefect API revision does not match the Layer-1 REST contract")]
    ApiRevisionMismatch,
    #[error("Prefect server-host identity does not match the exact scope")]
    ServerHostMismatch,
    #[error("Prefect account identity does not match the exact scope")]
    AccountMismatch,
    #[error("Prefect workspace identity does not match the exact scope")]
    WorkspaceMismatch,
    #[error("Prefect flow identity does not match the exact scope")]
    FlowMismatch,
    #[error("Prefect deployment identity does not match the exact scope")]
    DeploymentMismatch,
    #[error("Prefect flow-run identity does not match the exact scope")]
    FlowRunMismatch,
    #[error("Prefect task-run identity does not match the exact scope")]
    TaskRunMismatch,
    #[error("Prefect state is outside the allowlisted exact scope")]
    StateMismatch,
    #[error("Mission/Project/Work Product scope does not match")]
    MissionScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("revision fence is stale")]
    StaleRevision,
    #[error("Prefect run state transition is invalid")]
    InvalidStateTransition,
    #[error("payload was truncated")]
    PayloadTruncated,
    #[error("payload was marked partial")]
    PartialResponse,
    #[error("payload exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("payload response digest did not verify")]
    PayloadTampered,
    #[error("evidence, page, or provenance digest was tampered")]
    EvidenceTampered,
    #[error("proposal digest or provenance was tampered")]
    ProposalTampered,
    #[error("redaction boundary was violated")]
    RedactionViolation,
    #[error("bounded page item limit exceeded")]
    PageTooLarge,
    #[error("bounded evidence item limit exceeded")]
    EvidenceTooLarge,
    #[error("pagination cursor or page limit exceeded")]
    PaginationLimit,
    #[error("pagination response drifted from the requested page")]
    PaginationDrift,
    #[error("pagination cursor repeated")]
    PaginationRepeated,
    #[error("duplicate evidence fingerprint")]
    DuplicateEvidence,
    #[error("consumer is inactive")]
    ConsumerInactive,
    #[error("time filter is outside the exact scope")]
    TimeFilterOutOfScope,
    #[error("HTTP {status} projected as {projection:?}")]
    HttpStatus {
        status: u16,
        projection: PrefectRunProjection,
    },
    #[error("Prefect read timed out")]
    Timeout,
    #[error("Prefect environment is blocked")]
    BlockedEnv,
    #[error("Prefect provider returned an unknown or unusable result")]
    ProviderUnknown,
    #[error("recording has no response for the requested typed operation")]
    RecordingExhausted,
    #[error("recording response has the wrong typed operation")]
    UnexpectedResponse,
    #[error("only allowlisted read operations are allowed in Layer 1")]
    ReadMethodForbidden,
}

impl PrefectError {
    fn from_transport(error: &PrefectTransportError) -> Self {
        match error {
            PrefectTransportError::HttpStatus { status, .. } => Self::HttpStatus {
                status: *status,
                projection: projection_for_http_status(*status),
            },
            PrefectTransportError::Timeout => Self::Timeout,
            PrefectTransportError::BlockedEnv => Self::BlockedEnv,
            PrefectTransportError::MalformedResponse => Self::PartialResponse,
            PrefectTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            PrefectTransportError::RecordingExhausted => Self::RecordingExhausted,
            PrefectTransportError::UnexpectedOperation => Self::UnexpectedResponse,
        }
    }

    pub const fn projection(&self) -> PrefectRunProjection {
        match self {
            Self::HttpStatus { projection, .. } => *projection,
            Self::SecretRevoked
            | Self::SecretScopeMismatch
            | Self::RegistrationRevoked
            | Self::RegistrationInactive => PrefectRunProjection::AccessLoss,
            Self::StaleMissionRevision | Self::StaleRevision | Self::InvalidStateTransition => {
                PrefectRunProjection::Stale
            }
            Self::InvalidInput(_)
            | Self::InvalidDigest
            | Self::InvalidSecretReference
            | Self::RegistrationBindingDrift
            | Self::RegistrationTampered
            | Self::PermissionDrift
            | Self::ApiRevisionMismatch
            | Self::ServerHostMismatch
            | Self::AccountMismatch
            | Self::WorkspaceMismatch
            | Self::FlowMismatch
            | Self::DeploymentMismatch
            | Self::FlowRunMismatch
            | Self::TaskRunMismatch
            | Self::StateMismatch
            | Self::MissionScopeMismatch
            | Self::PayloadTruncated
            | Self::PartialResponse
            | Self::ResponseTooLarge
            | Self::PayloadTampered
            | Self::EvidenceTampered
            | Self::ProposalTampered
            | Self::RedactionViolation
            | Self::PageTooLarge
            | Self::EvidenceTooLarge
            | Self::PaginationLimit
            | Self::PaginationDrift
            | Self::PaginationRepeated
            | Self::DuplicateEvidence
            | Self::ConsumerInactive
            | Self::TimeFilterOutOfScope
            | Self::ReadMethodForbidden
            | Self::Timeout
            | Self::BlockedEnv
            | Self::ProviderUnknown
            | Self::RecordingExhausted
            | Self::UnexpectedResponse => PrefectRunProjection::ProviderUnknown,
        }
    }

    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

fn projection_for_http_status(status: u16) -> PrefectRunProjection {
    match status {
        401 | 403 => PrefectRunProjection::AccessLoss,
        404 | 409 => PrefectRunProjection::Stale,
        _ => PrefectRunProjection::ProviderUnknown,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectServerHostDescription {
    pub server_host: PrefectServerHostIdentity,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub read_only: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl PrefectServerHostDescription {
    fn for_scope(scope: &PrefectScope) -> Self {
        Self {
            server_host: scope.server_host.clone(),
            api_digest: scope.api_digest(),
            scope_digest: scope.scope_digest(),
            read_only: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &PrefectScope) -> Result<()> {
        self.server_host.validate()?;
        if self.server_host != scope.server_host
            || self.api_digest != scope.api_digest()
            || self.scope_digest != scope.scope_digest()
            || !self.read_only
            || self.native_connected
            || self.first_party
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectAccountDescription {
    pub account: PrefectAccountIdentity,
    pub scope_digest: Digest,
    pub read_only: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl PrefectAccountDescription {
    fn for_scope(scope: &PrefectScope) -> Self {
        Self {
            account: scope.account.clone(),
            scope_digest: scope.scope_digest(),
            read_only: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &PrefectScope) -> Result<()> {
        if self.account != scope.account
            || self.scope_digest != scope.scope_digest()
            || !self.read_only
            || self.native_connected
            || self.first_party
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectWorkspaceDescription {
    pub workspace: PrefectWorkspaceIdentity,
    pub scope_digest: Digest,
    pub read_only: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl PrefectWorkspaceDescription {
    fn for_scope(scope: &PrefectScope) -> Self {
        Self {
            workspace: scope.workspace.clone(),
            scope_digest: scope.scope_digest(),
            read_only: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &PrefectScope) -> Result<()> {
        if self.workspace != scope.workspace
            || self.scope_digest != scope.scope_digest()
            || !self.read_only
            || self.native_connected
            || self.first_party
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectFlowDescription {
    pub flow: PrefectFlowIdentity,
    pub scope_digest: Digest,
    pub stable_rest_read: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl PrefectFlowDescription {
    fn for_scope(scope: &PrefectScope) -> Self {
        Self {
            flow: scope.flow.clone(),
            scope_digest: scope.scope_digest(),
            stable_rest_read: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &PrefectScope) -> Result<()> {
        if self.flow != scope.flow
            || self.scope_digest != scope.scope_digest()
            || !self.stable_rest_read
            || self.native_connected
            || self.first_party
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectDeploymentDescription {
    pub deployment: PrefectDeploymentIdentity,
    pub scope_digest: Digest,
    pub read_only: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl PrefectDeploymentDescription {
    fn for_scope(scope: &PrefectScope) -> Self {
        Self {
            deployment: scope.deployment.clone(),
            scope_digest: scope.scope_digest(),
            read_only: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &PrefectScope) -> Result<()> {
        if self.deployment != scope.deployment
            || self.scope_digest != scope.scope_digest()
            || !self.read_only
            || self.native_connected
            || self.first_party
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

/// Allowlisted fields from a Prefect flow-run response. Raw parameters,
/// context, logs, result locations, and arbitrary response fields are absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectFlowRunRecord {
    pub flow: PrefectFlowIdentity,
    pub deployment: PrefectDeploymentIdentity,
    pub flow_run: PrefectFlowRunIdentity,
    pub state: PrefectState,
    pub expected_start_time: Option<String>,
    pub next_scheduled_start_time: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub retry_count: u32,
    pub late: bool,
}

impl PrefectFlowRunRecord {
    pub fn new(
        flow: PrefectFlowIdentity,
        deployment: PrefectDeploymentIdentity,
        flow_run: PrefectFlowRunIdentity,
        state: PrefectState,
    ) -> Result<Self> {
        let record = Self {
            flow,
            deployment,
            flow_run,
            state,
            expected_start_time: None,
            next_scheduled_start_time: None,
            start_time: None,
            end_time: None,
            retry_count: 0,
            late: false,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn with_timestamps(
        mut self,
        expected_start_time: Option<String>,
        next_scheduled_start_time: Option<String>,
        start_time: Option<String>,
        end_time: Option<String>,
    ) -> Result<Self> {
        self.expected_start_time = expected_start_time;
        self.next_scheduled_start_time = next_scheduled_start_time;
        self.start_time = start_time;
        self.end_time = end_time;
        self.validate()?;
        Ok(self)
    }

    pub fn with_retry_late(mut self, retry_count: u32, late: bool) -> Result<Self> {
        self.retry_count = retry_count;
        self.late = late;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.flow.validate()?;
        self.deployment.validate()?;
        self.flow_run.validate()?;
        if self.retry_count > MAX_RETRY_COUNT {
            return Err(PrefectError::InvalidInput("flow-run retry count"));
        }
        for timestamp in [
            self.expected_start_time.as_deref(),
            self.next_scheduled_start_time.as_deref(),
            self.start_time.as_deref(),
            self.end_time.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_timestamp(timestamp)?;
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &PrefectScope) -> Result<()> {
        self.validate()?;
        if self.flow != scope.flow {
            return Err(PrefectError::FlowMismatch);
        }
        if self.deployment != scope.deployment {
            return Err(PrefectError::DeploymentMismatch);
        }
        if self.flow_run != scope.flow_run {
            return Err(PrefectError::FlowRunMismatch);
        }
        if !scope.state.contains(self.state) {
            return Err(PrefectError::StateMismatch);
        }
        Ok(())
    }

    pub fn metadata_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Allowlisted fields from Prefect task-run projections. Result values,
/// result storage locations, logs, parameters, and task inputs are absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectTaskRunRecord {
    pub flow: PrefectFlowIdentity,
    pub deployment: PrefectDeploymentIdentity,
    pub flow_run: PrefectFlowRunIdentity,
    pub task_run: PrefectTaskRunIdentity,
    pub state: PrefectState,
    pub expected_start_time: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub retry_count: u32,
    pub late: bool,
}

impl PrefectTaskRunRecord {
    pub fn new(
        flow: PrefectFlowIdentity,
        deployment: PrefectDeploymentIdentity,
        flow_run: PrefectFlowRunIdentity,
        task_run: PrefectTaskRunIdentity,
        state: PrefectState,
    ) -> Result<Self> {
        let record = Self {
            flow,
            deployment,
            flow_run,
            task_run,
            state,
            expected_start_time: None,
            start_time: None,
            end_time: None,
            retry_count: 0,
            late: false,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn with_timestamps(
        mut self,
        expected_start_time: Option<String>,
        start_time: Option<String>,
        end_time: Option<String>,
    ) -> Result<Self> {
        self.expected_start_time = expected_start_time;
        self.start_time = start_time;
        self.end_time = end_time;
        self.validate()?;
        Ok(self)
    }

    pub fn with_retry_late(mut self, retry_count: u32, late: bool) -> Result<Self> {
        self.retry_count = retry_count;
        self.late = late;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.flow.validate()?;
        self.deployment.validate()?;
        self.flow_run.validate()?;
        self.task_run.validate()?;
        if self.retry_count > MAX_RETRY_COUNT {
            return Err(PrefectError::InvalidInput("task-run retry count"));
        }
        for timestamp in [
            self.expected_start_time.as_deref(),
            self.start_time.as_deref(),
            self.end_time.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_timestamp(timestamp)?;
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &PrefectScope) -> Result<()> {
        self.validate()?;
        if self.flow != scope.flow {
            return Err(PrefectError::FlowMismatch);
        }
        if self.deployment != scope.deployment {
            return Err(PrefectError::DeploymentMismatch);
        }
        if self.flow_run != scope.flow_run {
            return Err(PrefectError::FlowRunMismatch);
        }
        if self.task_run != scope.task_run {
            return Err(PrefectError::TaskRunMismatch);
        }
        if !scope.state.contains(self.state) {
            return Err(PrefectError::StateMismatch);
        }
        Ok(())
    }

    pub fn metadata_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Digest-only state history data. Prefect state messages and raw response
/// bodies are intentionally not retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectStateHistoryRecord {
    pub flow_run: PrefectFlowRunIdentity,
    pub state: PrefectState,
    pub timestamp: String,
    pub occurrences: u32,
    pub retry_count: u32,
    pub late: bool,
    pub state_digest: Digest,
}

impl PrefectStateHistoryRecord {
    pub fn new(
        flow_run: PrefectFlowRunIdentity,
        state: PrefectState,
        timestamp: impl Into<String>,
        occurrences: u32,
        retry_count: u32,
        late: bool,
    ) -> Result<Self> {
        let timestamp = timestamp.into();
        validate_timestamp(&timestamp)?;
        if occurrences == 0 || occurrences > 4_096 || retry_count > MAX_RETRY_COUNT {
            return Err(PrefectError::InvalidInput("state history bounds"));
        }
        flow_run.validate()?;
        let state_digest = Digest::from_serializable(&(
            &flow_run,
            state,
            &timestamp,
            occurrences,
            retry_count,
            late,
        ));
        Ok(Self {
            flow_run,
            state,
            timestamp,
            occurrences,
            retry_count,
            late,
            state_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.flow_run.validate()?;
        validate_timestamp(&self.timestamp)?;
        if self.occurrences == 0
            || self.occurrences > 4_096
            || self.retry_count > MAX_RETRY_COUNT
            || self.state_digest
                != Digest::from_serializable(&(
                    &self.flow_run,
                    self.state,
                    &self.timestamp,
                    self.occurrences,
                    self.retry_count,
                    self.late,
                ))
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &PrefectScope) -> Result<()> {
        self.validate()?;
        if self.flow_run != scope.flow_run {
            return Err(PrefectError::FlowRunMismatch);
        }
        if !scope.state.contains(self.state) {
            return Err(PrefectError::StateMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectPage<T> {
    pub items: Vec<T>,
    pub total_entries: usize,
    pub offset: usize,
    pub limit: usize,
    pub partial: bool,
}

impl<T> PrefectPage<T> {
    pub fn new(
        items: Vec<T>,
        total_entries: usize,
        offset: usize,
        limit: usize,
        partial: bool,
    ) -> Self {
        Self {
            items,
            total_entries,
            offset,
            limit,
            partial,
        }
    }

    pub fn page_digest(&self) -> Digest
    where
        T: Serialize,
    {
        Digest::from_serializable(self)
    }
}

pub type PrefectTaskRunPage = PrefectPage<PrefectTaskRunRecord>;
pub type PrefectFlowRunPage = PrefectPage<PrefectFlowRunRecord>;
pub type PrefectStateHistoryPage = PrefectPage<PrefectStateHistoryRecord>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefectRunProjection {
    Scheduled,
    Pending,
    Running,
    Completed,
    Failed,
    Crashed,
    Cancelled,
    Paused,
    Late,
    Partial,
    Stale,
    AccessLoss,
    ProviderUnknown,
}

impl PrefectRunProjection {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::Crashed
                | Self::Cancelled
                | Self::Stale
                | Self::AccessLoss
                | Self::ProviderUnknown
        )
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(self, Self::AccessLoss)
    }

    /// Evidence is monotonic for one exact flow run. A terminal observation
    /// cannot regress to an active or different terminal state.
    pub const fn can_follow(self, next: Self) -> bool {
        if self as u8 == next as u8 {
            return true;
        }
        match self {
            Self::Scheduled => matches!(
                next,
                Self::Pending
                    | Self::Running
                    | Self::Completed
                    | Self::Failed
                    | Self::Crashed
                    | Self::Cancelled
                    | Self::Paused
                    | Self::Late
                    | Self::Partial
                    | Self::Stale
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Pending => matches!(
                next,
                Self::Running
                    | Self::Completed
                    | Self::Failed
                    | Self::Crashed
                    | Self::Cancelled
                    | Self::Paused
                    | Self::Late
                    | Self::Partial
                    | Self::Stale
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Running | Self::Paused | Self::Late | Self::Partial => matches!(
                next,
                Self::Running
                    | Self::Completed
                    | Self::Failed
                    | Self::Crashed
                    | Self::Cancelled
                    | Self::Paused
                    | Self::Late
                    | Self::Partial
                    | Self::Stale
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Completed
            | Self::Failed
            | Self::Crashed
            | Self::Cancelled
            | Self::Stale
            | Self::AccessLoss
            | Self::ProviderUnknown => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefectOperation {
    GetFlowRun,
    ListTaskRuns,
    GetTaskRun,
    ReadFlowRunHistory,
    ReadStateHistory,
    FilterFlowRuns,
}

impl PrefectOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetFlowRun => "read_flow_run",
            Self::ListTaskRuns => "read_task_runs",
            Self::GetTaskRun => "read_task_run",
            Self::ReadFlowRunHistory | Self::ReadStateHistory => "read_state_history",
            Self::FilterFlowRuns => "filter_flow_runs",
        }
    }

    pub const fn method(self) -> &'static str {
        match self {
            Self::GetFlowRun | Self::GetTaskRun => "GET",
            Self::ListTaskRuns
            | Self::ReadFlowRunHistory
            | Self::ReadStateHistory
            | Self::FilterFlowRuns => "POST",
        }
    }

    pub fn endpoint_path(self, scope: &PrefectScope) -> String {
        let prefix = format!(
            "{PREFECT_API_BASE_PATH}/accounts/{}/workspaces/{}",
            scope.account.account_id, scope.workspace.workspace_id
        );
        match self {
            Self::GetFlowRun => format!("{prefix}/flow_runs/{}", scope.flow_run.flow_run_id),
            Self::ListTaskRuns => format!("{prefix}/task_runs/filter"),
            Self::GetTaskRun => format!("{prefix}/task_runs/{}", scope.task_run.task_run_id),
            Self::ReadFlowRunHistory | Self::ReadStateHistory => {
                format!("{prefix}/flow_runs/history")
            }
            Self::FilterFlowRuns => format!("{prefix}/flow_runs/filter"),
        }
    }
}

pub fn flow_run_endpoint_path(scope: &PrefectScope) -> String {
    PrefectOperation::GetFlowRun.endpoint_path(scope)
}

pub fn task_runs_endpoint_path(scope: &PrefectScope) -> String {
    PrefectOperation::ListTaskRuns.endpoint_path(scope)
}

pub fn task_run_endpoint_path(scope: &PrefectScope) -> String {
    PrefectOperation::GetTaskRun.endpoint_path(scope)
}

pub fn flow_run_history_endpoint_path(scope: &PrefectScope) -> String {
    PrefectOperation::ReadFlowRunHistory.endpoint_path(scope)
}

pub fn state_history_endpoint_path(scope: &PrefectScope) -> String {
    PrefectOperation::ReadStateHistory.endpoint_path(scope)
}

pub fn flow_run_filter_endpoint_path(scope: &PrefectScope) -> String {
    PrefectOperation::FilterFlowRuns.endpoint_path(scope)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectReadRequest {
    pub operation: PrefectOperation,
    pub offset: usize,
    pub limit: usize,
    pub history_start: Option<String>,
    pub history_end: Option<String>,
    pub states: BTreeSet<PrefectState>,
}

impl PrefectReadRequest {
    pub fn new(
        operation: PrefectOperation,
        offset: usize,
        limit: usize,
        history_start: Option<String>,
        history_end: Option<String>,
        states: impl IntoIterator<Item = PrefectState>,
    ) -> Result<Self> {
        let request = Self {
            operation,
            offset,
            limit,
            history_start,
            history_end,
            states: states.into_iter().collect(),
        };
        request.validate(&ReadLimits::default())?;
        Ok(request)
    }

    pub fn for_flow_run() -> Self {
        Self {
            operation: PrefectOperation::GetFlowRun,
            offset: 0,
            limit: 1,
            history_start: None,
            history_end: None,
            states: BTreeSet::new(),
        }
    }

    pub fn for_task_runs(offset: usize, limit: usize) -> Result<Self> {
        Self::new(
            PrefectOperation::ListTaskRuns,
            offset,
            limit,
            None,
            None,
            [],
        )
    }

    pub fn for_task_run() -> Self {
        Self {
            operation: PrefectOperation::GetTaskRun,
            offset: 0,
            limit: 1,
            history_start: None,
            history_end: None,
            states: BTreeSet::new(),
        }
    }

    pub fn for_state_history(
        history_start: impl Into<String>,
        history_end: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            PrefectOperation::ReadStateHistory,
            0,
            MAX_PAGE_ITEMS,
            Some(history_start.into()),
            Some(history_end.into()),
            [],
        )
    }

    pub fn for_flow_run_history(
        history_start: impl Into<String>,
        history_end: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            PrefectOperation::ReadFlowRunHistory,
            0,
            MAX_PAGE_ITEMS,
            Some(history_start.into()),
            Some(history_end.into()),
            [],
        )
    }

    pub fn for_filter_flow_runs(offset: usize, limit: usize) -> Result<Self> {
        Self::new(
            PrefectOperation::FilterFlowRuns,
            offset,
            limit,
            None,
            None,
            [],
        )
    }

    pub fn with_time_bounds(
        mut self,
        history_start: Option<String>,
        history_end: Option<String>,
    ) -> Result<Self> {
        self.history_start = history_start;
        self.history_end = history_end;
        self.validate(&ReadLimits::default())?;
        Ok(self)
    }

    pub fn with_states(mut self, states: impl IntoIterator<Item = PrefectState>) -> Result<Self> {
        self.states = states.into_iter().collect();
        self.validate(&ReadLimits::default())?;
        Ok(self)
    }

    pub fn validate(&self, limits: &ReadLimits) -> Result<()> {
        if self.limit == 0
            || self.limit > limits.max_page_items
            || self.offset > limits.max_task_runs
            || self.states.len() > limits.max_filter_values
        {
            return Err(PrefectError::PaginationLimit);
        }
        if matches!(
            self.operation,
            PrefectOperation::ReadFlowRunHistory | PrefectOperation::ReadStateHistory
        ) {
            let (Some(start), Some(end)) = (&self.history_start, &self.history_end) else {
                return Err(PrefectError::InvalidInput("history time bounds"));
            };
            validate_timestamp(start)?;
            validate_timestamp(end)?;
            if start > end {
                return Err(PrefectError::TimeFilterOutOfScope);
            }
        } else if self.history_start.is_some() || self.history_end.is_some() {
            return Err(PrefectError::InvalidInput(
                "history bounds on non-history read",
            ));
        }
        if matches!(
            self.operation,
            PrefectOperation::GetFlowRun | PrefectOperation::GetTaskRun
        ) && (self.offset != 0 || self.limit != 1)
        {
            return Err(PrefectError::PaginationDrift);
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &PrefectScope, limits: &ReadLimits) -> Result<()> {
        scope.validate()?;
        self.validate(limits)?;
        if self
            .states
            .iter()
            .any(|state| !scope.state.contains(*state))
        {
            return Err(PrefectError::StateMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub fields: BTreeSet<String>,
    pub digest: Digest,
}

impl RedactionEvidence {
    pub fn standard() -> Self {
        Self::new([
            "api_key",
            "authorization",
            "cookies",
            "raw_headers",
            "raw_payload",
            "raw_logs",
            "raw_results",
            "parameters",
            "filter_dsl",
            "workflow_registry",
        ])
    }

    pub fn new<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let fields: BTreeSet<String> = fields.into_iter().map(Into::into).collect();
        let digest = Digest::from_serializable(&fields);
        Self { fields, digest }
    }

    pub fn validate(&self) -> Result<()> {
        if self.fields.is_empty()
            || self.fields.iter().any(|field| {
                field.is_empty()
                    || field.len() > MAX_IDENTIFIER_BYTES
                    || field.bytes().any(|byte| byte.is_ascii_control())
            })
            || self.digest != Digest::from_serializable(&self.fields)
        {
            return Err(PrefectError::RedactionViolation);
        }
        let required = [
            "api_key",
            "raw_payload",
            "raw_logs",
            "raw_results",
            "filter_dsl",
        ];
        if required.iter().any(|field| !self.fields.contains(*field)) {
            return Err(PrefectError::RedactionViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectRequestAudit {
    pub operation: PrefectOperation,
    pub method: String,
    pub endpoint_digest: Digest,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub redaction: RedactionEvidence,
}

impl PrefectRequestAudit {
    pub fn for_scope(scope: &PrefectScope, request: &PrefectReadRequest) -> Self {
        Self {
            operation: request.operation,
            method: request.operation.method().to_owned(),
            endpoint_digest: Digest::from_text(request.operation.endpoint_path(scope)),
            request_digest: Digest::from_serializable(request),
            scope_digest: scope.scope_digest(),
            redaction: RedactionEvidence::standard(),
        }
    }

    pub fn validate(&self, scope: &PrefectScope, request: &PrefectReadRequest) -> Result<()> {
        request.validate_for_scope(scope, &ReadLimits::default())?;
        let operation_matches = self.operation == request.operation
            || (matches!(
                self.operation,
                PrefectOperation::ReadFlowRunHistory | PrefectOperation::ReadStateHistory
            ) && matches!(
                request.operation,
                PrefectOperation::ReadFlowRunHistory | PrefectOperation::ReadStateHistory
            ));
        if !operation_matches
            || self.method != request.operation.method()
            || self.endpoint_digest != Digest::from_text(request.operation.endpoint_path(scope))
            || self.request_digest != Digest::from_serializable(request)
            || self.scope_digest != scope.scope_digest()
        {
            return Err(PrefectError::EvidenceTampered);
        }
        self.redaction.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub transport: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl EvidenceProvenance {
    pub fn for_transport(transport: TransportProvenance) -> Self {
        Self {
            transport,
            connected: transport.connected(),
            native: transport.native(),
            first_party: transport.first_party(),
        }
    }

    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    pub const fn is_native(&self) -> bool {
        self.native
    }

    pub const fn is_first_party(&self) -> bool {
        self.first_party
    }

    pub fn validate(&self) -> Result<()> {
        if self.connected != self.transport.connected()
            || self.native != self.transport.native()
            || self.first_party != self.transport.first_party()
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadLimits {
    pub max_response_bytes: usize,
    pub max_page_items: usize,
    pub max_pages: usize,
    pub max_task_runs: usize,
    pub max_history_points: usize,
    pub max_filter_values: usize,
    pub max_timestamp_bytes: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_page_items: MAX_PAGE_ITEMS,
            max_pages: MAX_PAGES,
            max_task_runs: MAX_TASK_RUNS,
            max_history_points: MAX_HISTORY_POINTS,
            max_filter_values: MAX_FILTER_VALUES,
            max_timestamp_bytes: MAX_TIMESTAMP_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn validate(self) -> Result<Self> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_page_items == 0
            || self.max_page_items > MAX_PAGE_ITEMS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_task_runs == 0
            || self.max_task_runs > MAX_TASK_RUNS
            || self.max_history_points == 0
            || self.max_history_points > MAX_HISTORY_POINTS
            || self.max_filter_values == 0
            || self.max_filter_values > MAX_FILTER_VALUES
            || self.max_timestamp_bytes == 0
            || self.max_timestamp_bytes > MAX_TIMESTAMP_BYTES
        {
            return Err(PrefectError::InvalidInput("read limits"));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectPayload<T> {
    pub operation: PrefectOperation,
    pub offset: usize,
    pub limit: usize,
    pub partial: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub redaction: RedactionEvidence,
    pub provenance: EvidenceProvenance,
    pub value: T,
}

impl<T: Serialize> PrefectPayload<T> {
    pub fn new(
        operation: PrefectOperation,
        offset: usize,
        limit: usize,
        partial: bool,
        value: T,
    ) -> Self {
        let response_bytes = serde_json::to_vec(&value)
            .expect("bounded Prefect response serializes")
            .len();
        let redaction = RedactionEvidence::standard();
        let provenance = EvidenceProvenance::for_transport(TransportProvenance::Recording);
        let response_digest = Self::compute_response_digest(
            operation,
            offset,
            limit,
            partial,
            response_bytes,
            &redaction,
            &provenance,
            &value,
        );
        Self {
            operation,
            offset,
            limit,
            partial,
            response_bytes,
            response_digest,
            redaction,
            provenance,
            value,
        }
    }

    pub fn recording(operation: PrefectOperation, offset: usize, limit: usize, value: T) -> Self {
        Self::new(operation, offset, limit, false, value)
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self.response_digest = self.compute_digest_for_self();
        self
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: EvidenceProvenance) -> Self {
        self.provenance = provenance;
        self.response_digest = self.compute_digest_for_self();
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.response_digest = self.compute_digest_for_self();
        self
    }

    pub fn compute_digest(&self) -> Digest {
        self.compute_digest_for_self()
    }

    fn compute_digest_for_self(&self) -> Digest {
        Self::compute_response_digest(
            self.operation,
            self.offset,
            self.limit,
            self.partial,
            self.response_bytes,
            &self.redaction,
            &self.provenance,
            &self.value,
        )
    }

    fn compute_response_digest(
        operation: PrefectOperation,
        offset: usize,
        limit: usize,
        partial: bool,
        response_bytes: usize,
        redaction: &RedactionEvidence,
        provenance: &EvidenceProvenance,
        value: &T,
    ) -> Digest {
        Digest::from_serializable(&(
            operation,
            offset,
            limit,
            partial,
            response_bytes,
            redaction,
            provenance,
            value,
        ))
    }

    pub fn verify(&self, request: &PrefectReadRequest, limits: &ReadLimits) -> Result<()> {
        request.validate(limits)?;
        let operation_matches = self.operation == request.operation
            || matches!(
                (self.operation, request.operation),
                (
                    PrefectOperation::ReadFlowRunHistory,
                    PrefectOperation::ReadStateHistory
                ) | (
                    PrefectOperation::ReadStateHistory,
                    PrefectOperation::ReadFlowRunHistory
                )
            );
        let limit_matches = match request.operation {
            PrefectOperation::GetFlowRun | PrefectOperation::GetTaskRun => {
                self.limit == request.limit
            }
            PrefectOperation::ListTaskRuns
            | PrefectOperation::ReadFlowRunHistory
            | PrefectOperation::ReadStateHistory
            | PrefectOperation::FilterFlowRuns => self.limit > 0 && self.limit <= request.limit,
        };
        if !operation_matches
            || self.offset != request.offset
            || !limit_matches
            || self.response_bytes > limits.max_response_bytes
        {
            return Err(if self.response_bytes > limits.max_response_bytes {
                PrefectError::ResponseTooLarge
            } else {
                PrefectError::PaginationDrift
            });
        }
        self.redaction.validate()?;
        self.provenance.validate()?;
        if self.response_digest != self.compute_digest_for_self() {
            return Err(PrefectError::PayloadTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PrefectTransportError {
    #[error("Prefect returned HTTP {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("Prefect read timed out")]
    Timeout,
    #[error("Prefect environment is blocked")]
    BlockedEnv,
    #[error("Prefect response was malformed or partial")]
    MalformedResponse,
    #[error("Prefect response exceeded the local bound")]
    ResponseTooLarge,
    #[error("recording has no response for the typed operation")]
    RecordingExhausted,
    #[error("recording response has the wrong typed operation")]
    UnexpectedOperation,
}

pub trait PrefectTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_flow_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectFlowRunRecord>, PrefectTransportError>;

    fn list_task_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectTaskRunPage>, PrefectTransportError>;

    fn get_task_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectTaskRunRecord>, PrefectTransportError>;

    fn read_state_history(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectStateHistoryPage>, PrefectTransportError>;

    fn filter_flow_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectFlowRunPage>, PrefectTransportError>;
}

#[derive(Debug)]
pub struct RecordingPrefectTransport {
    provenance: TransportProvenance,
    flow_runs:
        VecDeque<std::result::Result<PrefectPayload<PrefectFlowRunRecord>, PrefectTransportError>>,
    task_pages:
        VecDeque<std::result::Result<PrefectPayload<PrefectTaskRunPage>, PrefectTransportError>>,
    task_runs:
        VecDeque<std::result::Result<PrefectPayload<PrefectTaskRunRecord>, PrefectTransportError>>,
    history_pages: VecDeque<
        std::result::Result<PrefectPayload<PrefectStateHistoryPage>, PrefectTransportError>,
    >,
    filtered_flow_runs:
        VecDeque<std::result::Result<PrefectPayload<PrefectFlowRunPage>, PrefectTransportError>>,
}

impl RecordingPrefectTransport {
    fn empty(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            flow_runs: VecDeque::new(),
            task_pages: VecDeque::new(),
            task_runs: VecDeque::new(),
            history_pages: VecDeque::new(),
            filtered_flow_runs: VecDeque::new(),
        }
    }

    pub fn recording(flow_run: PrefectFlowRunRecord, task_page: PrefectTaskRunPage) -> Self {
        Self::recording_with_history(flow_run, [task_page], [], [])
    }

    pub fn recording_with_history<I, H, F>(
        flow_run: PrefectFlowRunRecord,
        task_pages: I,
        history_pages: H,
        filtered_flow_runs: F,
    ) -> Self
    where
        I: IntoIterator<Item = PrefectTaskRunPage>,
        H: IntoIterator<Item = PrefectStateHistoryPage>,
        F: IntoIterator<Item = PrefectFlowRunPage>,
    {
        let mut transport = Self::empty(TransportProvenance::Recording);
        transport.push_flow_run(flow_run);
        for page in task_pages {
            if let Some(task_run) = page.items.first().cloned() {
                transport.push_task_run(task_run);
            }
            transport.push_task_page(page);
        }
        for page in history_pages {
            transport.push_history_page(page);
        }
        for page in filtered_flow_runs {
            transport.push_filtered_flow_runs(page);
        }
        transport
    }

    pub fn recording_with_pages<I>(flow_run: PrefectFlowRunRecord, task_pages: I) -> Self
    where
        I: IntoIterator<Item = PrefectTaskRunPage>,
    {
        Self::recording_with_history(flow_run, task_pages, [], [])
    }

    pub fn fixture(flow_run: PrefectFlowRunRecord, task_page: PrefectTaskRunPage) -> Self {
        let mut transport = Self::recording(flow_run, task_page);
        transport.provenance = TransportProvenance::Fixture;
        transport.relabel_provenance();
        transport
    }

    pub fn fake(flow_run: PrefectFlowRunRecord, task_page: PrefectTaskRunPage) -> Self {
        let mut transport = Self::recording(flow_run, task_page);
        transport.provenance = TransportProvenance::Fake;
        transport.relabel_provenance();
        transport
    }

    pub fn loopback(flow_run: PrefectFlowRunRecord, task_page: PrefectTaskRunPage) -> Self {
        let mut transport = Self::recording(flow_run, task_page);
        transport.provenance = TransportProvenance::Loopback;
        transport.relabel_provenance();
        transport
    }

    pub fn blocked_env() -> BlockedEnvPrefectTransport {
        BlockedEnvPrefectTransport
    }

    pub fn with_http_error(provenance: TransportProvenance, status: u16) -> Self {
        let mut transport = Self::empty(provenance);
        let error = PrefectTransportError::HttpStatus {
            status,
            retry_after_seconds: None,
        };
        transport.flow_runs.push_back(Err(error.clone()));
        transport.task_pages.push_back(Err(error.clone()));
        transport.task_runs.push_back(Err(error.clone()));
        transport.history_pages.push_back(Err(error.clone()));
        transport.filtered_flow_runs.push_back(Err(error));
        transport
    }

    pub fn with_transport_error(
        provenance: TransportProvenance,
        error: PrefectTransportError,
    ) -> Self {
        let mut transport = Self::empty(provenance);
        transport.flow_runs.push_back(Err(error.clone()));
        transport.task_pages.push_back(Err(error.clone()));
        transport.task_runs.push_back(Err(error.clone()));
        transport.history_pages.push_back(Err(error.clone()));
        transport.filtered_flow_runs.push_back(Err(error));
        transport
    }

    pub fn push_flow_run(&mut self, flow_run: PrefectFlowRunRecord) {
        self.flow_runs.push_back(Ok(PrefectPayload::recording(
            PrefectOperation::GetFlowRun,
            0,
            1,
            flow_run,
        )
        .with_provenance(EvidenceProvenance::for_transport(self.provenance))));
    }

    pub fn push_task_page(&mut self, page: PrefectTaskRunPage) {
        self.task_pages.push_back(Ok(PrefectPayload::recording(
            PrefectOperation::ListTaskRuns,
            page.offset,
            page.limit,
            page,
        )
        .with_provenance(EvidenceProvenance::for_transport(self.provenance))));
    }

    pub fn push_task_run(&mut self, task_run: PrefectTaskRunRecord) {
        self.task_runs.push_back(Ok(PrefectPayload::recording(
            PrefectOperation::GetTaskRun,
            0,
            1,
            task_run,
        )
        .with_provenance(EvidenceProvenance::for_transport(self.provenance))));
    }

    pub fn push_history_page(&mut self, page: PrefectStateHistoryPage) {
        self.history_pages.push_back(Ok(PrefectPayload::recording(
            PrefectOperation::ReadStateHistory,
            page.offset,
            page.limit,
            page,
        )
        .with_provenance(EvidenceProvenance::for_transport(self.provenance))));
    }

    pub fn push_filtered_flow_runs(&mut self, page: PrefectFlowRunPage) {
        self.filtered_flow_runs
            .push_back(Ok(PrefectPayload::recording(
                PrefectOperation::FilterFlowRuns,
                page.offset,
                page.limit,
                page,
            )
            .with_provenance(EvidenceProvenance::for_transport(self.provenance))));
    }

    fn relabel_provenance(&mut self) {
        relabel_queue(&mut self.flow_runs, self.provenance);
        relabel_queue(&mut self.task_pages, self.provenance);
        relabel_queue(&mut self.task_runs, self.provenance);
        relabel_queue(&mut self.history_pages, self.provenance);
        relabel_queue(&mut self.filtered_flow_runs, self.provenance);
    }
}

fn relabel_queue<T: Clone + Serialize>(
    queue: &mut VecDeque<std::result::Result<PrefectPayload<T>, PrefectTransportError>>,
    provenance: TransportProvenance,
) {
    for payload in queue.iter_mut().flatten() {
        *payload = payload
            .clone()
            .with_provenance(EvidenceProvenance::for_transport(provenance));
    }
}

impl PrefectTransport for RecordingPrefectTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_flow_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectFlowRunRecord>, PrefectTransportError> {
        if request.operation != PrefectOperation::GetFlowRun {
            return Err(PrefectTransportError::UnexpectedOperation);
        }
        self.flow_runs
            .pop_front()
            .unwrap_or(Err(PrefectTransportError::RecordingExhausted))
    }

    fn list_task_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectTaskRunPage>, PrefectTransportError> {
        if request.operation != PrefectOperation::ListTaskRuns {
            return Err(PrefectTransportError::UnexpectedOperation);
        }
        self.task_pages
            .pop_front()
            .unwrap_or(Err(PrefectTransportError::RecordingExhausted))
    }

    fn get_task_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectTaskRunRecord>, PrefectTransportError> {
        if request.operation != PrefectOperation::GetTaskRun {
            return Err(PrefectTransportError::UnexpectedOperation);
        }
        self.task_runs
            .pop_front()
            .unwrap_or(Err(PrefectTransportError::RecordingExhausted))
    }

    fn read_state_history(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectStateHistoryPage>, PrefectTransportError> {
        if !matches!(
            request.operation,
            PrefectOperation::ReadFlowRunHistory | PrefectOperation::ReadStateHistory
        ) {
            return Err(PrefectTransportError::UnexpectedOperation);
        }
        self.history_pages
            .pop_front()
            .unwrap_or(Err(PrefectTransportError::RecordingExhausted))
    }

    fn filter_flow_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectFlowRunPage>, PrefectTransportError> {
        if request.operation != PrefectOperation::FilterFlowRuns {
            return Err(PrefectTransportError::UnexpectedOperation);
        }
        self.filtered_flow_runs
            .pop_front()
            .unwrap_or(Err(PrefectTransportError::RecordingExhausted))
    }
}

pub type PrefectFakeTransport = RecordingPrefectTransport;
pub type PrefectFixtureTransport = RecordingPrefectTransport;
pub type PrefectLoopbackTransport = RecordingPrefectTransport;

#[derive(Debug)]
pub struct BlockedEnvPrefectTransport;

impl PrefectTransport for BlockedEnvPrefectTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_flow_run(
        &mut self,
        _request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectFlowRunRecord>, PrefectTransportError> {
        Err(PrefectTransportError::BlockedEnv)
    }

    fn list_task_runs(
        &mut self,
        _request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectTaskRunPage>, PrefectTransportError> {
        Err(PrefectTransportError::BlockedEnv)
    }

    fn get_task_run(
        &mut self,
        _request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectTaskRunRecord>, PrefectTransportError> {
        Err(PrefectTransportError::BlockedEnv)
    }

    fn read_state_history(
        &mut self,
        _request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectStateHistoryPage>, PrefectTransportError> {
        Err(PrefectTransportError::BlockedEnv)
    }

    fn filter_flow_runs(
        &mut self,
        _request: &PrefectReadRequest,
    ) -> std::result::Result<PrefectPayload<PrefectFlowRunPage>, PrefectTransportError> {
        Err(PrefectTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectRetryMarker {
    pub run_id: String,
    pub task_run_id: Option<String>,
    pub retry_count: u32,
    pub late: bool,
    pub marker_digest: Digest,
}

impl PrefectRetryMarker {
    fn from_flow_run(record: &PrefectFlowRunRecord) -> Self {
        let run_id = record.flow_run.flow_run_id.clone();
        let marker_digest = Digest::from_serializable(&(&run_id, record.retry_count, record.late));
        Self {
            run_id,
            task_run_id: None,
            retry_count: record.retry_count,
            late: record.late,
            marker_digest,
        }
    }

    fn from_task_run(record: &PrefectTaskRunRecord) -> Self {
        let run_id = record.flow_run.flow_run_id.clone();
        let task_run_id = Some(record.task_run.task_run_id.clone());
        let marker_digest =
            Digest::from_serializable(&(&run_id, &task_run_id, record.retry_count, record.late));
        Self {
            run_id,
            task_run_id,
            retry_count: record.retry_count,
            late: record.late,
            marker_digest,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_identifier("retry marker flow run", &self.run_id)?;
        if let Some(task_run_id) = &self.task_run_id {
            validate_identifier("retry marker task run", task_run_id)?;
        }
        if self.retry_count > MAX_RETRY_COUNT {
            return Err(PrefectError::EvidenceTampered);
        }
        let expected = if let Some(task_run_id) = &self.task_run_id {
            Digest::from_serializable(&(
                &self.run_id,
                &Some(task_run_id.clone()),
                self.retry_count,
                self.late,
            ))
        } else {
            Digest::from_serializable(&(&self.run_id, self.retry_count, self.late))
        };
        if self.marker_digest != expected {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectRunEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub request: PrefectReadRequest,
    pub request_audit: PrefectRequestAudit,
    pub flow_run: PrefectFlowRunRecord,
    pub task_runs: Vec<PrefectTaskRunRecord>,
    pub state_history: Vec<PrefectStateHistoryRecord>,
    pub filtered_flow_runs: Vec<PrefectFlowRunRecord>,
    pub retry_markers: Vec<PrefectRetryMarker>,
    pub page_digests: Vec<Digest>,
    pub pages_read: usize,
    pub complete: bool,
    pub projection: PrefectRunProjection,
    pub redaction: RedactionEvidence,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

impl PrefectRunEvidence {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        scope: &PrefectScope,
        registration: &PrefectRegistration,
        request: PrefectReadRequest,
        flow_run: PrefectFlowRunRecord,
        task_runs: Vec<PrefectTaskRunRecord>,
        state_history: Vec<PrefectStateHistoryRecord>,
        filtered_flow_runs: Vec<PrefectFlowRunRecord>,
        page_digests: Vec<Digest>,
        pages_read: usize,
        complete: bool,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        flow_run.validate_for_scope(scope)?;
        for task_run in &task_runs {
            task_run.validate_for_scope(scope)?;
        }
        for point in &state_history {
            point.validate_for_scope(scope)?;
        }
        for filtered in &filtered_flow_runs {
            filtered.validate_for_scope(scope)?;
        }
        let request_audit = PrefectRequestAudit::for_scope(scope, &request);
        let redaction = RedactionEvidence::standard();
        let provenance = EvidenceProvenance::for_transport(provenance);
        let retry_markers = retry_markers(&flow_run, &task_runs);
        let projection = derive_projection(
            flow_run.state,
            &task_runs,
            &state_history,
            &filtered_flow_runs,
            complete,
            flow_run.late,
        );
        let evidence_digest = Self::compute_digest(
            &request,
            &request_audit,
            &flow_run,
            &task_runs,
            &state_history,
            &filtered_flow_runs,
            &retry_markers,
            &page_digests,
            pages_read,
            complete,
            projection,
            &redaction,
            &provenance,
            &scope.scope_digest(),
            &registration.registration_digest,
        );
        Ok(Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: scope.scope_digest(),
            registration_digest: registration.registration_digest.clone(),
            request,
            request_audit,
            flow_run,
            task_runs,
            state_history,
            filtered_flow_runs,
            retry_markers,
            page_digests,
            pages_read,
            complete,
            projection,
            redaction,
            provenance,
            evidence_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        request: &PrefectReadRequest,
        request_audit: &PrefectRequestAudit,
        flow_run: &PrefectFlowRunRecord,
        task_runs: &[PrefectTaskRunRecord],
        state_history: &[PrefectStateHistoryRecord],
        filtered_flow_runs: &[PrefectFlowRunRecord],
        retry_markers: &[PrefectRetryMarker],
        page_digests: &[Digest],
        pages_read: usize,
        complete: bool,
        projection: PrefectRunProjection,
        redaction: &RedactionEvidence,
        provenance: &EvidenceProvenance,
        scope_digest: &Digest,
        registration_digest: &Digest,
    ) -> Digest {
        Digest::from_serializable(&(
            request,
            request_audit,
            flow_run,
            task_runs,
            state_history,
            filtered_flow_runs,
            retry_markers,
            page_digests,
            pages_read,
            complete,
            projection,
            redaction,
            provenance,
            scope_digest,
            registration_digest,
        ))
    }

    pub fn compute_digest_value(&self) -> Digest {
        Self::compute_digest(
            &self.request,
            &self.request_audit,
            &self.flow_run,
            &self.task_runs,
            &self.state_history,
            &self.filtered_flow_runs,
            &self.retry_markers,
            &self.page_digests,
            self.pages_read,
            self.complete,
            self.projection,
            &self.redaction,
            &self.provenance,
            &self.scope_digest,
            &self.registration_digest,
        )
    }

    pub fn validate(
        &self,
        scope: &PrefectScope,
        registration: &PrefectRegistration,
        limits: &ReadLimits,
    ) -> Result<()> {
        scope.validate()?;
        self.request.validate_for_scope(scope, limits)?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
        {
            return Err(PrefectError::MissionScopeMismatch);
        }
        if registration.compute_digest() != registration.registration_digest {
            return Err(PrefectError::RegistrationTampered);
        }
        self.request_audit.validate(scope, &self.request)?;
        self.flow_run.validate_for_scope(scope)?;
        for task_run in &self.task_runs {
            task_run.validate_for_scope(scope)?;
        }
        for point in &self.state_history {
            point.validate_for_scope(scope)?;
        }
        for filtered in &self.filtered_flow_runs {
            filtered.validate_for_scope(scope)?;
        }
        if self.pages_read == 0
            || self.pages_read > limits.max_pages
            || self.page_digests.len() != self.pages_read
            || self.task_runs.len() > limits.max_task_runs
            || self.state_history.len() > limits.max_history_points
            || self.filtered_flow_runs.len() > limits.max_page_items
        {
            return Err(PrefectError::EvidenceTooLarge);
        }
        if self.page_digests.iter().any(|digest| !digest.is_valid()) {
            return Err(PrefectError::EvidenceTampered);
        }
        if self.complete == (self.projection == PrefectRunProjection::Partial) {
            return Err(PrefectError::EvidenceTampered);
        }
        if self.projection
            != derive_projection(
                self.flow_run.state,
                &self.task_runs,
                &self.state_history,
                &self.filtered_flow_runs,
                self.complete,
                self.flow_run.late,
            )
        {
            return Err(PrefectError::EvidenceTampered);
        }
        let expected_markers = retry_markers(&self.flow_run, &self.task_runs);
        if self.retry_markers != expected_markers {
            return Err(PrefectError::EvidenceTampered);
        }
        for marker in &self.retry_markers {
            marker.validate()?;
        }
        self.redaction.validate()?;
        self.provenance.validate()?;
        if self.evidence_digest != self.compute_digest_value() {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn is_review_only(&self) -> bool {
        true
    }
}

pub type PrefectFlowRunEvidence = PrefectRunEvidence;
pub type PrefectFlowResultEvidence = PrefectRunEvidence;

fn retry_markers(
    flow_run: &PrefectFlowRunRecord,
    task_runs: &[PrefectTaskRunRecord],
) -> Vec<PrefectRetryMarker> {
    let mut markers = vec![PrefectRetryMarker::from_flow_run(flow_run)];
    markers.extend(task_runs.iter().map(PrefectRetryMarker::from_task_run));
    markers
}

fn derive_projection(
    flow_state: PrefectState,
    task_runs: &[PrefectTaskRunRecord],
    history: &[PrefectStateHistoryRecord],
    filtered_flow_runs: &[PrefectFlowRunRecord],
    complete: bool,
    flow_late: bool,
) -> PrefectRunProjection {
    if !complete {
        return PrefectRunProjection::Partial;
    }
    if flow_late
        || task_runs.iter().any(|task| task.late)
        || history.iter().any(|point| point.late)
        || filtered_flow_runs.iter().any(|run| run.late)
    {
        return PrefectRunProjection::Late;
    }
    for state in [
        PrefectState::Failed,
        PrefectState::Crashed,
        PrefectState::Cancelled,
        PrefectState::Running,
        PrefectState::Paused,
        PrefectState::Pending,
        PrefectState::Scheduled,
    ] {
        if task_runs.iter().any(|task| task.state == state)
            || history.iter().any(|point| point.state == state)
            || filtered_flow_runs.iter().any(|run| run.state == state)
        {
            return state.projection();
        }
    }
    flow_state.projection()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectFailureEvidence {
    pub schema_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub request: PrefectReadRequest,
    pub projection: PrefectRunProjection,
    pub status: Option<u16>,
    pub error_digest: Digest,
    pub redaction: RedactionEvidence,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

impl PrefectFailureEvidence {
    fn from_error(
        scope: &PrefectScope,
        registration: &PrefectRegistration,
        request: &PrefectReadRequest,
        error: &PrefectError,
        provenance: TransportProvenance,
    ) -> Self {
        let redaction = RedactionEvidence::standard();
        let provenance = EvidenceProvenance::for_transport(provenance);
        let error_digest = Digest::from_text(error.to_string());
        let evidence_digest = Digest::from_serializable(&(
            &scope.scope_digest(),
            &registration.registration_digest,
            request,
            error.projection(),
            error.status(),
            &error_digest,
            &redaction,
            &provenance,
        ));
        Self {
            schema_version: CONTRACT_SCHEMA.into(),
            scope_digest: scope.scope_digest(),
            registration_digest: registration.registration_digest.clone(),
            request: request.clone(),
            projection: error.projection(),
            status: error.status(),
            error_digest,
            redaction,
            provenance,
            evidence_digest,
        }
    }

    pub fn validate(&self, scope: &PrefectScope, registration: &PrefectRegistration) -> Result<()> {
        self.request
            .validate_for_scope(scope, &ReadLimits::default())?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || !self.error_digest.is_valid()
        {
            return Err(PrefectError::EvidenceTampered);
        }
        self.redaction.validate()?;
        self.provenance.validate()?;
        let expected_digest = Digest::from_serializable(&(
            &self.scope_digest,
            &self.registration_digest,
            &self.request,
            self.projection,
            self.status,
            &self.error_digest,
            &self.redaction,
            &self.provenance,
        ));
        if self.evidence_digest != expected_digest {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
pub enum PrefectReadOutcome {
    Evidence(PrefectRunEvidence),
    Failure(PrefectFailureEvidence),
}

impl fmt::Debug for PrefectReadOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(evidence) => formatter.debug_tuple("Evidence").field(evidence).finish(),
            Self::Failure(failure) => formatter.debug_tuple("Failure").field(failure).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefectAdoptionDisposition {
    Layer2Required,
    BlockedByProjection,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectFlowResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub flow_run_id: String,
    pub projection: PrefectRunProjection,
    pub evidence_digest: Digest,
    pub provenance: EvidenceProvenance,
    pub adoption: PrefectAdoptionDisposition,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub workflow_registry_authority: bool,
    pub kernel_authority: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl PrefectFlowResultProposal {
    fn from_evidence(evidence: &PrefectRunEvidence) -> Self {
        let adoption = if matches!(
            evidence.projection,
            PrefectRunProjection::Completed
                | PrefectRunProjection::Failed
                | PrefectRunProjection::Crashed
                | PrefectRunProjection::Cancelled
        ) && evidence.complete
        {
            PrefectAdoptionDisposition::Layer2Required
        } else {
            PrefectAdoptionDisposition::BlockedByProjection
        };
        let mut proposal = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            flow_run_id: evidence.flow_run.flow_run.flow_run_id.clone(),
            projection: evidence.projection,
            evidence_digest: evidence.evidence_digest.clone(),
            provenance: evidence.provenance.clone(),
            adoption,
            connected: false,
            native: false,
            first_party: false,
            workflow_registry_authority: false,
            kernel_authority: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("uncomputed"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.schema_version,
            &self.contract_version,
            &self.scope_digest,
            &self.registration_digest,
            &self.flow_run_id,
            self.projection,
            &self.evidence_digest,
            &self.provenance,
            self.adoption,
            self.connected,
            self.native,
            self.first_party,
            self.workflow_registry_authority,
            self.kernel_authority,
            self.work_product_adopted,
        ))
    }

    pub fn validate_integrity(
        &self,
        scope: &PrefectScope,
        registration: &PrefectRegistration,
    ) -> Result<()> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || self.provenance.connected != self.connected
            || self.provenance.native != self.native
            || self.provenance.first_party != self.first_party
            || self.workflow_registry_authority
            || self.kernel_authority
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(PrefectError::ProposalTampered);
        }
        validate_identifier("flow run id", &self.flow_run_id)
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

pub type PrefectRunResultProposal = PrefectFlowResultProposal;
pub type PrefectFlowProposal = PrefectFlowResultProposal;

#[derive(Clone, Debug)]
pub struct PrefectProvider<T> {
    scope: PrefectScope,
    secret_reference: SecretReference,
    registration: PrefectRegistration,
    transport: T,
    limits: ReadLimits,
}

impl<T: PrefectTransport> PrefectProvider<T> {
    pub fn new(
        scope: PrefectScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        let registration = PrefectRegistration::new(&scope, &secret_reference)?;
        Self::with_registration(scope, registration, secret_reference, transport)
    }

    pub fn with_registration(
        scope: PrefectScope,
        registration: PrefectRegistration,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        registration.validate_binding(&scope, &secret_reference)?;
        Ok(Self {
            scope,
            secret_reference,
            registration,
            transport,
            limits: ReadLimits::default(),
        })
    }

    pub fn with_limits(mut self, limits: ReadLimits) -> Result<Self> {
        self.limits = limits.validate()?;
        Ok(self)
    }

    pub fn scope(&self) -> &PrefectScope {
        &self.scope
    }

    pub fn registration(&self) -> &PrefectRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut PrefectRegistration {
        &mut self.registration
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
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

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn connected(&self) -> bool {
        self.provenance().connected()
    }

    pub fn native(&self) -> bool {
        self.provenance().native()
    }

    pub fn first_party(&self) -> bool {
        self.provenance().first_party()
    }

    pub fn describe_server_host(&self) -> Result<PrefectServerHostDescription> {
        self.ensure_active()?;
        Ok(PrefectServerHostDescription::for_scope(&self.scope))
    }

    pub fn describe_host(&self) -> Result<PrefectServerHostDescription> {
        self.describe_server_host()
    }

    pub fn describe_account(&self) -> Result<PrefectAccountDescription> {
        self.ensure_active()?;
        Ok(PrefectAccountDescription::for_scope(&self.scope))
    }

    pub fn describe_workspace(&self) -> Result<PrefectWorkspaceDescription> {
        self.ensure_active()?;
        Ok(PrefectWorkspaceDescription::for_scope(&self.scope))
    }

    pub fn describe_flow(&self) -> Result<PrefectFlowDescription> {
        self.ensure_active()?;
        Ok(PrefectFlowDescription::for_scope(&self.scope))
    }

    pub fn describe_deployment(&self) -> Result<PrefectDeploymentDescription> {
        self.ensure_active()?;
        Ok(PrefectDeploymentDescription::for_scope(&self.scope))
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.remount()
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt> {
        self.registration.revoke(&mut self.secret_reference)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn read_flow_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectFlowRunRecord>> {
        self.ensure_active()?;
        if request.operation != PrefectOperation::GetFlowRun {
            return Err(PrefectError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .get_flow_run(request)
            .map_err(|error| PrefectError::from_transport(&error))?;
        self.validate_payload_provenance(&payload.provenance)?;
        payload.verify(request, &self.limits)?;
        payload.value.validate_for_scope(&self.scope)?;
        Ok(payload)
    }

    pub fn read_task_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectTaskRunPage>> {
        self.ensure_active()?;
        if request.operation != PrefectOperation::ListTaskRuns {
            return Err(PrefectError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .list_task_runs(request)
            .map_err(|error| PrefectError::from_transport(&error))?;
        self.validate_payload_provenance(&payload.provenance)?;
        payload.verify(request, &self.limits)?;
        validate_task_page(&payload.value, request, &self.limits)?;
        for task_run in &payload.value.items {
            validate_task_for_scope(task_run, &self.scope)?;
        }
        Ok(payload)
    }

    pub fn read_task_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectTaskRunRecord>> {
        self.ensure_active()?;
        if request.operation != PrefectOperation::GetTaskRun {
            return Err(PrefectError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .get_task_run(request)
            .map_err(|error| PrefectError::from_transport(&error))?;
        self.validate_payload_provenance(&payload.provenance)?;
        payload.verify(request, &self.limits)?;
        payload.value.validate_for_scope(&self.scope)?;
        Ok(payload)
    }

    pub fn read_state_history(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectStateHistoryPage>> {
        self.ensure_active()?;
        if !matches!(
            request.operation,
            PrefectOperation::ReadFlowRunHistory | PrefectOperation::ReadStateHistory
        ) {
            return Err(PrefectError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .read_state_history(request)
            .map_err(|error| PrefectError::from_transport(&error))?;
        self.validate_payload_provenance(&payload.provenance)?;
        payload.verify(request, &self.limits)?;
        validate_history_page(&payload.value, request, &self.limits)?;
        for point in &payload.value.items {
            point.validate_for_scope(&self.scope)?;
        }
        Ok(payload)
    }

    pub fn filter_flow_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectFlowRunPage>> {
        self.ensure_active()?;
        if request.operation != PrefectOperation::FilterFlowRuns {
            return Err(PrefectError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .filter_flow_runs(request)
            .map_err(|error| PrefectError::from_transport(&error))?;
        self.validate_payload_provenance(&payload.provenance)?;
        payload.verify(request, &self.limits)?;
        validate_flow_page(&payload.value, request, &self.limits)?;
        for flow_run in &payload.value.items {
            flow_run.validate_for_scope(&self.scope)?;
        }
        Ok(payload)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_evidence(&mut self, request: PrefectReadRequest) -> Result<PrefectRunEvidence> {
        self.ensure_active()?;
        request.validate_for_scope(&self.scope, &self.limits)?;

        let flow_request = PrefectReadRequest::for_flow_run();
        let flow_payload = self.read_flow_run(&flow_request)?;
        let flow_run = flow_payload.value;
        let mut page_digests = vec![flow_payload.response_digest];
        let mut task_runs = Vec::new();
        let mut state_history = Vec::new();
        let mut filtered_flow_runs = Vec::new();
        let (pages_read, complete) = match request.operation {
            PrefectOperation::GetFlowRun => (1, !flow_payload.partial),
            PrefectOperation::GetTaskRun => {
                let payload = self.read_task_run(&request)?;
                page_digests.push(payload.response_digest);
                task_runs.push(payload.value);
                (2, !payload.partial)
            }
            PrefectOperation::ListTaskRuns => {
                let mut current_offset = request.offset;
                let mut pages_read = 0;
                let mut last_key: Option<String> = None;
                let mut seen = BTreeSet::new();
                let complete = loop {
                    if pages_read >= self.limits.max_pages {
                        return Err(PrefectError::PaginationLimit);
                    }
                    let page_request = PrefectReadRequest {
                        operation: PrefectOperation::ListTaskRuns,
                        offset: current_offset,
                        limit: request.limit,
                        history_start: None,
                        history_end: None,
                        states: request.states.clone(),
                    };
                    let payload = self.read_task_runs(&page_request)?;
                    let page = payload.value;
                    page_digests.push(payload.response_digest);
                    pages_read += 1;
                    let item_count = page.items.len();
                    let page_limit = page.limit;
                    let page_total = page.total_entries;
                    if page.partial {
                        break false;
                    }
                    for task_run in page.items {
                        let key = task_run.task_run.task_run_id.clone();
                        if let Some(previous) = &last_key
                            && key < *previous
                        {
                            return Err(PrefectError::PaginationDrift);
                        }
                        last_key = Some(key);
                        if task_run.task_run == self.scope.task_run {
                            if !seen.insert(task_run.metadata_digest()) {
                                return Err(PrefectError::DuplicateEvidence);
                            }
                            task_runs.push(task_run);
                        }
                    }
                    let next_offset = current_offset
                        .checked_add(item_count)
                        .ok_or(PrefectError::PaginationLimit)?;
                    if next_offset >= page_total {
                        break true;
                    }
                    if item_count == 0 || next_offset <= current_offset || item_count < page_limit {
                        return Err(PrefectError::PaginationDrift);
                    }
                    current_offset = next_offset;
                };
                (pages_read + 1, complete && !task_runs.is_empty())
            }
            PrefectOperation::ReadFlowRunHistory | PrefectOperation::ReadStateHistory => {
                let payload = self.read_state_history(&request)?;
                page_digests.push(payload.response_digest);
                let page = payload.value;
                let complete = !page.partial;
                let mut last_timestamp: Option<String> = None;
                for point in page.items {
                    if let Some(previous) = &last_timestamp
                        && point.timestamp < *previous
                    {
                        return Err(PrefectError::PaginationDrift);
                    }
                    last_timestamp = Some(point.timestamp.clone());
                    state_history.push(point);
                }
                (2, complete && !state_history.is_empty())
            }
            PrefectOperation::FilterFlowRuns => {
                let payload = self.filter_flow_runs(&request)?;
                page_digests.push(payload.response_digest);
                let page = payload.value;
                let mut matched = false;
                for flow in page.items {
                    if flow.flow_run == self.scope.flow_run {
                        matched = true;
                        filtered_flow_runs.push(flow);
                    }
                }
                (2, !page.partial && matched)
            }
        };
        if task_runs.len() > self.limits.max_task_runs
            || state_history.len() > self.limits.max_history_points
        {
            return Err(PrefectError::EvidenceTooLarge);
        }
        PrefectRunEvidence::from_parts(
            &self.scope,
            &self.registration,
            request,
            flow_run,
            task_runs,
            state_history,
            filtered_flow_runs,
            page_digests,
            pages_read,
            complete,
            self.provenance(),
        )
    }

    pub fn read_flow_result(&mut self, request: PrefectReadRequest) -> Result<PrefectRunEvidence> {
        self.read_evidence(request)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn read_evidence_projected(&mut self, request: PrefectReadRequest) -> PrefectReadOutcome {
        match self.read_evidence(request.clone()) {
            Ok(evidence) => PrefectReadOutcome::Evidence(evidence),
            Err(error) => PrefectReadOutcome::Failure(PrefectFailureEvidence::from_error(
                &self.scope,
                &self.registration,
                &request,
                &error,
                self.provenance(),
            )),
        }
    }

    fn validate_payload_provenance(&self, provenance: &EvidenceProvenance) -> Result<()> {
        provenance.validate()?;
        if provenance.transport != self.provenance() {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<()> {
        self.scope.validate()?;
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)?;
        match self.registration.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Unmounted => Err(PrefectError::RegistrationInactive),
            RegistrationStatus::Revoked | RegistrationStatus::Reversed => {
                Err(PrefectError::RegistrationRevoked)
            }
        }
    }
}

fn validate_task_page(
    page: &PrefectTaskRunPage,
    request: &PrefectReadRequest,
    limits: &ReadLimits,
) -> Result<()> {
    if page.items.len() > limits.max_page_items
        || page.items.len() > page.limit
        || page.total_entries > limits.max_task_runs
        || page.offset != request.offset
        || page.limit != request.limit
        || (page.total_entries > 0 && page.offset > page.total_entries)
    {
        return Err(PrefectError::PageTooLarge);
    }
    Ok(())
}

fn validate_history_page(
    page: &PrefectStateHistoryPage,
    request: &PrefectReadRequest,
    limits: &ReadLimits,
) -> Result<()> {
    if page.items.len() > limits.max_page_items
        || page.items.len() > page.limit
        || page.total_entries > limits.max_history_points
        || page.offset != request.offset
        || page.limit == 0
        || page.limit > request.limit
    {
        return Err(PrefectError::PageTooLarge);
    }
    Ok(())
}

fn validate_flow_page(
    page: &PrefectFlowRunPage,
    request: &PrefectReadRequest,
    limits: &ReadLimits,
) -> Result<()> {
    if page.items.len() > limits.max_page_items
        || page.items.len() > page.limit
        || page.total_entries > limits.max_task_runs
        || page.offset != request.offset
        || page.limit != request.limit
    {
        return Err(PrefectError::PageTooLarge);
    }
    Ok(())
}

fn validate_task_for_scope(task_run: &PrefectTaskRunRecord, scope: &PrefectScope) -> Result<()> {
    task_run.validate()?;
    if task_run.flow != scope.flow {
        return Err(PrefectError::FlowMismatch);
    }
    if task_run.deployment != scope.deployment {
        return Err(PrefectError::DeploymentMismatch);
    }
    if task_run.flow_run != scope.flow_run {
        return Err(PrefectError::FlowRunMismatch);
    }
    if !scope.state.contains(task_run.state) {
        return Err(PrefectError::StateMismatch);
    }
    Ok(())
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefectServiceDefinition {
    pub schema_version: &'static str,
    pub contract_version: &'static str,
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub layer: u8,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub operations: Vec<PrefectOperation>,
    pub forbidden_effects: Vec<&'static str>,
    pub allowed_provenance: Vec<TransportProvenance>,
}

impl PrefectServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA,
            contract_version: CONTRACT_VERSION,
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            layer: 1,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            operations: vec![
                PrefectOperation::GetFlowRun,
                PrefectOperation::ListTaskRuns,
                PrefectOperation::GetTaskRun,
                PrefectOperation::ReadStateHistory,
                PrefectOperation::FilterFlowRuns,
            ],
            forbidden_effects: vec![
                "create_flow_run",
                "set_flow_run_state",
                "cancel_flow_run",
                "mutate_deployment",
                "mutate_worker",
                "read_raw_logs",
                "read_raw_results",
                "read_arbitrary_filter_dsl",
                "control_workflow_registry",
                "resolve_native_secret",
                "retain_raw_payload",
                "adopt_kernel_truth",
                "adopt_work_product",
            ],
            allowed_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fixture,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.layer != 1
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(PrefectError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PrefectFlowResultService<T> {
    provider: PrefectProvider<T>,
    recordings: BTreeMap<String, Digest>,
    observed_status: BTreeMap<String, PrefectRunProjection>,
}

impl<T: PrefectTransport> PrefectFlowResultService<T> {
    pub fn new(provider: PrefectProvider<T>) -> Result<Self> {
        provider.scope.validate()?;
        Ok(Self {
            provider,
            recordings: BTreeMap::new(),
            observed_status: BTreeMap::new(),
        })
    }

    pub fn from_transport(
        scope: PrefectScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        Self::new(PrefectProvider::new(scope, secret_reference, transport)?)
    }

    pub fn definition() -> PrefectServiceDefinition {
        PrefectServiceDefinition::layer1()
    }

    pub fn scope(&self) -> &PrefectScope {
        self.provider.scope()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.provider.secret_reference()
    }

    pub fn registration(&self) -> &PrefectRegistration {
        self.provider.registration()
    }

    pub fn provider(&self) -> &PrefectProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut PrefectProvider<T> {
        &mut self.provider
    }

    pub fn describe_server_host(&self) -> Result<PrefectServerHostDescription> {
        self.provider.describe_server_host()
    }

    pub fn describe_host(&self) -> Result<PrefectServerHostDescription> {
        self.describe_server_host()
    }

    pub fn describe_account(&self) -> Result<PrefectAccountDescription> {
        self.provider.describe_account()
    }

    pub fn describe_workspace(&self) -> Result<PrefectWorkspaceDescription> {
        self.provider.describe_workspace()
    }

    pub fn describe_flow(&self) -> Result<PrefectFlowDescription> {
        self.provider.describe_flow()
    }

    pub fn describe_deployment(&self) -> Result<PrefectDeploymentDescription> {
        self.provider.describe_deployment()
    }

    pub fn read_flow_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectFlowRunRecord>> {
        self.provider.read_flow_run(request)
    }

    pub fn read_task_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectTaskRunPage>> {
        self.provider.read_task_runs(request)
    }

    pub fn read_task_run(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectTaskRunRecord>> {
        self.provider.read_task_run(request)
    }

    pub fn read_state_history(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectStateHistoryPage>> {
        self.provider.read_state_history(request)
    }

    pub fn filter_flow_runs(
        &mut self,
        request: &PrefectReadRequest,
    ) -> Result<PrefectPayload<PrefectFlowRunPage>> {
        self.provider.filter_flow_runs(request)
    }

    pub fn read_evidence(&mut self, request: PrefectReadRequest) -> Result<PrefectRunEvidence> {
        let evidence = self.provider.read_evidence(request)?;
        let run_id = evidence.flow_run.flow_run.flow_run_id.clone();
        if let Some(previous) = self.observed_status.get(&run_id)
            && !previous.can_follow(evidence.projection)
        {
            return Err(PrefectError::InvalidStateTransition);
        }
        self.observed_status.insert(run_id, evidence.projection);
        Ok(evidence)
    }

    pub fn read_flow_result(&mut self, request: PrefectReadRequest) -> Result<PrefectRunEvidence> {
        self.read_evidence(request)
    }

    pub fn read_evidence_projected(&mut self, request: PrefectReadRequest) -> PrefectReadOutcome {
        self.provider.read_evidence_projected(request)
    }

    /// Record only an in-memory evidence fingerprint. This is not a durable
    /// provider receipt and carries no provider payload.
    pub fn record_flow_evidence(
        &mut self,
        evidence: &PrefectRunEvidence,
    ) -> Result<PrefectEvidenceRecording> {
        self.validate_evidence(evidence)?;
        let run_id = evidence.flow_run.flow_run.flow_run_id.clone();
        if let Some(existing) = self.recordings.get(&run_id) {
            if existing != &evidence.evidence_digest {
                return Err(PrefectError::DuplicateEvidence);
            }
            return Ok(PrefectEvidenceRecording {
                run_id,
                evidence_digest: evidence.evidence_digest.clone(),
                replayed: true,
            });
        }
        self.recordings
            .insert(run_id.clone(), evidence.evidence_digest.clone());
        Ok(PrefectEvidenceRecording {
            run_id,
            evidence_digest: evidence.evidence_digest.clone(),
            replayed: false,
        })
    }

    pub fn compile_flow_result_proposal(
        &self,
        evidence: &PrefectRunEvidence,
    ) -> Result<PrefectFlowResultProposal> {
        self.validate_evidence(evidence)?;
        Ok(PrefectFlowResultProposal::from_evidence(evidence))
    }

    pub fn compile_run_result_proposal(
        &self,
        evidence: &PrefectRunEvidence,
    ) -> Result<PrefectFlowResultProposal> {
        self.compile_flow_result_proposal(evidence)
    }

    pub fn verify_flow_run_evidence(
        &self,
        evidence: &PrefectRunEvidence,
    ) -> Result<PrefectVerificationProjection> {
        self.validate_evidence(evidence)?;
        Ok(PrefectVerificationProjection::from_evidence(evidence))
    }

    pub fn verify_run_evidence(
        &self,
        evidence: &PrefectRunEvidence,
    ) -> Result<PrefectVerificationProjection> {
        self.verify_flow_run_evidence(evidence)
    }

    pub fn verify_proposal(
        &self,
        proposal: &PrefectFlowResultProposal,
        evidence: &PrefectRunEvidence,
    ) -> Result<PrefectVerificationProjection> {
        self.validate_evidence(evidence)?;
        proposal.validate_integrity(self.scope(), self.registration())?;
        if proposal.evidence_digest != evidence.evidence_digest
            || proposal.projection != evidence.projection
        {
            return Err(PrefectError::ProposalTampered);
        }
        Ok(PrefectVerificationProjection::from_evidence(evidence))
    }

    pub fn projection_for_error(&self, error: &PrefectError) -> PrefectRunProjection {
        error.projection()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.provider.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.provider.remount()
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt> {
        self.provider.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.provider.reverse()
    }

    fn validate_evidence(&self, evidence: &PrefectRunEvidence) -> Result<()> {
        self.provider
            .registration
            .validate_binding(&self.provider.scope, &self.provider.secret_reference)?;
        if !self.provider.registration.is_active() {
            return Err(PrefectError::RegistrationInactive);
        }
        evidence.validate(
            &self.provider.scope,
            &self.provider.registration,
            &self.provider.limits,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectEvidenceRecording {
    pub run_id: String,
    pub evidence_digest: Digest,
    pub replayed: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrefectVerificationProjection {
    pub schema_version: String,
    pub flow_run_id: String,
    pub projection: PrefectRunProjection,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub bounded_evidence_verified: bool,
    pub adoption: PrefectAdoptionDisposition,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub workflow_registry_authority: bool,
    pub kernel_authority: bool,
    pub work_product_adopted: bool,
}

impl PrefectVerificationProjection {
    fn from_evidence(evidence: &PrefectRunEvidence) -> Self {
        let bounded_evidence_verified = evidence.complete
            && matches!(
                evidence.projection,
                PrefectRunProjection::Completed
                    | PrefectRunProjection::Failed
                    | PrefectRunProjection::Crashed
                    | PrefectRunProjection::Cancelled
            );
        Self {
            schema_version: CONTRACT_SCHEMA.into(),
            flow_run_id: evidence.flow_run.flow_run.flow_run_id.clone(),
            projection: evidence.projection,
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            bounded_evidence_verified,
            adoption: if bounded_evidence_verified {
                PrefectAdoptionDisposition::Layer2Required
            } else {
                PrefectAdoptionDisposition::BlockedByProjection
            },
            connected: false,
            native: false,
            first_party: false,
            workflow_registry_authority: false,
            kernel_authority: false,
            work_product_adopted: false,
        }
    }

    pub const fn verified(&self) -> bool {
        self.bounded_evidence_verified
    }
}

pub type Result<T> = std::result::Result<T, PrefectError>;
pub const SCHEMA_VERSION: &str = CONTRACT_SCHEMA;
pub const PROVIDER_VERSION: Version = PLUGIN_VERSION;
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native Prefect API-key resolution, bounded live reads, durable provider receipts, independent read-back, and verified Work Product adoption remain Layer 2 gaps";

#[derive(Debug)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_writes() -> bool {
        false
    }

    pub const fn create_flow_run() -> bool {
        false
    }

    pub const fn set_flow_run_state() -> bool {
        false
    }

    pub const fn cancel_flow_run() -> bool {
        false
    }

    pub const fn mutate_deployment() -> bool {
        false
    }

    pub const fn mutate_worker() -> bool {
        false
    }

    pub const fn raw_logs() -> bool {
        false
    }

    pub const fn raw_results() -> bool {
        false
    }

    pub const fn arbitrary_filter_dsl() -> bool {
        false
    }

    pub const fn workflow_registry_authority() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn provider_receipt() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }
}

pub type Authority = ReadOnlyAuthority;

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_JSON)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConsumptionDisposition {
    Fresh,
    Replay,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionPrefectFlow {
    pub schema_version: String,
    pub scope_digest: Digest,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub flow_id: String,
    pub deployment_id: String,
    pub flow_run_id: String,
    pub task_run_id: String,
    pub projection: PrefectRunProjection,
    pub proposal_digest: Digest,
    pub disposition: MissionConsumptionDisposition,
    pub adopted: bool,
    pub workflow_registry_authority: bool,
    pub kernel_authority: bool,
    pub work_product_adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub struct MissionPrefectFlowConsumer {
    binding: MissionScopeBinding,
    scope_digest: Digest,
    registration_digest: Digest,
    flow_id: String,
    deployment_id: String,
    flow_run_id: String,
    task_run_id: String,
    consumed: BTreeMap<String, Digest>,
    active: bool,
}

impl fmt::Debug for MissionPrefectFlowConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionPrefectFlowConsumer")
            .field("scope_digest", &self.scope_digest)
            .field("registration_digest", &self.registration_digest)
            .field("binding", &self.binding)
            .field("consumed_count", &self.consumed.len())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl MissionPrefectFlowConsumer {
    pub fn new(scope: &PrefectScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            binding: scope.mission.clone(),
            scope_digest: scope.scope_digest(),
            registration_digest: Digest::from_text("unbound-registration"),
            flow_id: scope.flow.flow_id.clone(),
            deployment_id: scope.deployment.deployment_id.clone(),
            flow_run_id: scope.flow_run.flow_run_id.clone(),
            task_run_id: scope.task_run.task_run_id.clone(),
            consumed: BTreeMap::new(),
            active: true,
        })
    }

    pub fn from_registration(
        registration: &PrefectRegistration,
        scope: &PrefectScope,
    ) -> Result<Self> {
        scope.validate()?;
        if registration.compute_digest() != registration.registration_digest
            || registration.scope_digest != scope.scope_digest()
            || !registration.reversible
            || !registration.revocable
        {
            return Err(PrefectError::RegistrationTampered);
        }
        if !registration.is_active() {
            return if matches!(
                registration.status,
                RegistrationStatus::Revoked | RegistrationStatus::Reversed
            ) {
                Err(PrefectError::RegistrationRevoked)
            } else {
                Err(PrefectError::RegistrationInactive)
            };
        }
        let mut consumer = Self::new(scope)?;
        consumer.registration_digest = registration.registration_digest.clone();
        Ok(consumer)
    }

    pub fn binding(&self) -> &MissionScopeBinding {
        &self.binding
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

    pub fn consume(&mut self, proposal: &PrefectFlowResultProposal) -> Result<MissionPrefectFlow> {
        if !self.active {
            return Err(PrefectError::ConsumerInactive);
        }
        let expected_registration = if self.registration_digest.is_valid() {
            &self.registration_digest
        } else {
            &proposal.registration_digest
        };
        proposal.validate_for_scope_view(
            &PrefectScopeForConsumer {
                scope_digest: self.scope_digest.clone(),
                mission: self.binding.clone(),
                flow_id: &self.flow_id,
                deployment_id: &self.deployment_id,
                flow_run_id: &self.flow_run_id,
                task_run_id: &self.task_run_id,
            },
            expected_registration,
        )?;
        if !self.registration_digest.is_valid() {
            self.registration_digest = proposal.registration_digest.clone();
        }
        self.consume_validated(proposal)
    }

    pub fn consume_result(
        &mut self,
        proposal: &PrefectFlowResultProposal,
    ) -> Result<MissionPrefectFlow> {
        self.consume(proposal)
    }

    pub fn consume_at_revision(
        &mut self,
        proposal: &PrefectFlowResultProposal,
        current_binding: &MissionScopeBinding,
    ) -> Result<MissionPrefectFlow> {
        if current_binding.project_id != self.binding.project_id
            || current_binding.mission_id != self.binding.mission_id
            || current_binding.work_product_id != self.binding.work_product_id
        {
            return Err(PrefectError::MissionScopeMismatch);
        }
        if current_binding != &self.binding {
            return Err(PrefectError::StaleMissionRevision);
        }
        self.consume(proposal)
    }

    fn consume_validated(
        &mut self,
        proposal: &PrefectFlowResultProposal,
    ) -> Result<MissionPrefectFlow> {
        let disposition = match self.consumed.get(&proposal.flow_run_id) {
            None => {
                self.consumed.insert(
                    proposal.flow_run_id.clone(),
                    proposal.proposal_digest.clone(),
                );
                MissionConsumptionDisposition::Fresh
            }
            Some(existing) if existing == &proposal.proposal_digest => {
                MissionConsumptionDisposition::Replay
            }
            Some(_) => return Err(PrefectError::DuplicateEvidence),
        };
        Ok(MissionPrefectFlow {
            schema_version: CONTRACT_SCHEMA.into(),
            scope_digest: self.scope_digest.clone(),
            project_id: self.binding.project_id.clone(),
            mission_id: self.binding.mission_id.clone(),
            work_product_id: self.binding.work_product_id.clone(),
            project_revision: self.binding.project_revision,
            mission_revision: self.binding.mission_revision,
            work_product_revision: self.binding.work_product_revision,
            flow_id: self.flow_id.clone(),
            deployment_id: self.deployment_id.clone(),
            flow_run_id: proposal.flow_run_id.clone(),
            task_run_id: self.task_run_id.clone(),
            projection: proposal.projection,
            proposal_digest: proposal.proposal_digest.clone(),
            disposition,
            adopted: false,
            workflow_registry_authority: false,
            kernel_authority: false,
            work_product_adopted: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

struct PrefectScopeForConsumer<'a> {
    scope_digest: Digest,
    mission: MissionScopeBinding,
    flow_id: &'a str,
    deployment_id: &'a str,
    flow_run_id: &'a str,
    task_run_id: &'a str,
}

impl PrefectScopeForConsumer<'_> {
    fn validate(&self) -> Result<()> {
        if !self.scope_digest.is_valid() {
            return Err(PrefectError::MissionScopeMismatch);
        }
        self.mission.validate()
    }
}

impl PrefectFlowResultProposal {
    fn validate_for_scope_view(
        &self,
        scope: &PrefectScopeForConsumer<'_>,
        registration_digest: &Digest,
    ) -> Result<()> {
        scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest
            || self.registration_digest != *registration_digest
            || self.flow_run_id != scope.flow_run_id
            || self.proposal_digest != self.compute_digest()
            || self.workflow_registry_authority
            || self.kernel_authority
            || self.work_product_adopted
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected
            || self.provenance.native
            || self.provenance.first_party
        {
            return Err(PrefectError::ProposalTampered);
        }
        validate_identifier("flow id", scope.flow_id)?;
        validate_identifier("deployment id", scope.deployment_id)?;
        validate_identifier("task run id", scope.task_run_id)
    }
}

fn validate_revision(revision: u64) -> Result<()> {
    if revision == 0 {
        Err(PrefectError::InvalidInput("revision"))
    } else {
        Ok(())
    }
}

fn validate_origin(origin: &str) -> Result<()> {
    if origin.len() > MAX_IDENTIFIER_BYTES
        || !(origin.starts_with("https://") || origin.starts_with("http://"))
        || origin
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        Err(PrefectError::InvalidInput("server origin"))
    } else {
        Ok(())
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'?' | b':' | b'#' | b' '))
    {
        Err(PrefectError::InvalidInput(field))
    } else {
        Ok(())
    }
}

fn validate_timestamp(value: &str) -> Result<()> {
    if value.len() < 20 || value.len() > MAX_TIMESTAMP_BYTES {
        return Err(PrefectError::InvalidInput("timestamp"));
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !(0..4).all(|index| bytes[index].is_ascii_digit())
        || !(5..7).all(|index| bytes[index].is_ascii_digit())
        || !(8..10).all(|index| bytes[index].is_ascii_digit())
        || !(11..13).all(|index| bytes[index].is_ascii_digit())
        || !(14..16).all(|index| bytes[index].is_ascii_digit())
        || !(17..19).all(|index| bytes[index].is_ascii_digit())
    {
        return Err(PrefectError::InvalidInput("timestamp"));
    }
    let suffix = &value[19..];
    if !(suffix == "Z"
        || (suffix.len() >= 6
            && matches!(suffix.as_bytes().first(), Some(b'+' | b'-'))
            && suffix.as_bytes().get(3) == Some(&b':')
            && suffix[1..3].bytes().all(|byte| byte.is_ascii_digit())
            && suffix[4..6].bytes().all(|byte| byte.is_ascii_digit())))
    {
        return Err(PrefectError::InvalidInput("timestamp timezone"));
    }
    Ok(())
}
