use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 256;
pub(crate) const MAX_CURSOR_BYTES: usize = 512;
pub(crate) const MAX_PAGES: u32 = 16;
pub(crate) const MAX_PAGE_SIZE: u32 = 100;
pub(crate) const MAX_STEPS: usize = 256;
pub(crate) const MAX_RETRIES: usize = 16;
pub(crate) const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const READ_RATE_PER_MINUTE: u16 = 60;
pub(crate) const MAX_RETRY_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("step scope is empty, duplicated, or exceeds the bound")]
    InvalidStepScope,
    #[error("consent is invalid")]
    InvalidConsent,
    #[error("permission scope is invalid")]
    InvalidPermission,
    #[error("cursor or offset is empty or too large")]
    InvalidCursor,
    #[error("page bounds are outside the Layer-1 ceiling")]
    InvalidBounds,
    #[error("retry identity is ambiguous")]
    InvalidRetryIdentity,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked or reversed")]
    RegistrationTerminal,
    #[error("secret reference is empty, revoked, or out of scope")]
    InvalidSecret,
}

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

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if Self::is_valid_text(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        Self::is_valid_text(&self.0)
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    fn is_valid_text(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
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
string_identifier!(WorkatoProjectId);
string_identifier!(FolderId);
string_identifier!(RecipeId);
string_identifier!(RecipeVersionId);
string_identifier!(JobHandle);
string_identifier!(StepId);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

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
pub enum SecretKind {
    ApiToken,
    OAuthClient,
}

/// An opaque reference into a host-owned keyring.
///
/// The caller-supplied reference is immediately reduced to a digest and is
/// never retained, serialized, formatted, or passed to a transport.
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
        scope: &WorkatoScope,
        credential_revision: Revision,
        kind: SecretKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if reference_id.is_empty()
            || reference_id.len() > MAX_IDENTIFIER_BYTES
            || reference_id.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidSecret);
        }
        Ok(Self {
            reference_digest: Digest::from_text(reference_id),
            scope_digest: scope.scope_digest(),
            credential_revision,
            kind,
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

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::RegistrationTerminal)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkatoOperation {
    GetRecipe,
    ListRecipeVersions,
    GetRecipeVersion,
    ListJobs,
    GetJob,
}

impl WorkatoOperation {
    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionScope {
    lease_revision: Revision,
    permission_digest: Digest,
    allowed_operations: BTreeSet<WorkatoOperation>,
}

impl PermissionScope {
    pub fn read_only(lease_revision: Revision) -> Self {
        let allowed_operations = BTreeSet::from([
            WorkatoOperation::GetRecipe,
            WorkatoOperation::ListRecipeVersions,
            WorkatoOperation::GetRecipeVersion,
            WorkatoOperation::ListJobs,
            WorkatoOperation::GetJob,
        ]);
        let permission_digest = Digest::from_fields(
            "workato-permission/v1",
            &[
                lease_revision.get().to_string(),
                format!("{allowed_operations:?}"),
            ],
        );
        Self {
            lease_revision,
            permission_digest,
            allowed_operations,
        }
    }

    pub fn new(
        lease_revision: Revision,
        allowed_operations: BTreeSet<WorkatoOperation>,
    ) -> Result<Self, ModelError> {
        if allowed_operations.is_empty() || allowed_operations.iter().any(|op| !op.is_read_only()) {
            return Err(ModelError::InvalidPermission);
        }
        let permission_digest = Digest::from_fields(
            "workato-permission/v1",
            &[
                lease_revision.get().to_string(),
                format!("{allowed_operations:?}"),
            ],
        );
        Ok(Self {
            lease_revision,
            permission_digest,
            allowed_operations,
        })
    }

    pub const fn lease_revision(&self) -> Revision {
        self.lease_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn allows(&self, operation: WorkatoOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsentScope {
    revision: Revision,
    digest: Digest,
    read_proposal: bool,
    external_effects: bool,
}

impl ConsentScope {
    pub fn read_only(revision: Revision) -> Self {
        let digest = Digest::from_fields(
            "workato-read-proposal-consent/v1",
            &[revision.get().to_string(), "read_proposal=true".to_owned()],
        );
        Self {
            revision,
            digest,
            read_proposal: true,
            external_effects: false,
        }
    }

    pub fn new(revision: Revision, digest: Digest) -> Result<Self, ModelError> {
        if !digest.is_valid() {
            return Err(ModelError::InvalidConsent);
        }
        Ok(Self {
            revision,
            digest,
            read_proposal: true,
            external_effects: false,
        })
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn read_proposal(&self) -> bool {
        self.read_proposal
    }

    pub const fn external_effects(&self) -> bool {
        self.external_effects
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionScope {
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    objective_digest: Digest,
    consent: ConsentScope,
}

impl MissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        objective_digest: Digest,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        if !objective_digest.is_valid() || !consent.read_proposal() || consent.external_effects() {
            return Err(ModelError::InvalidScope);
        }
        Ok(Self {
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            objective_digest,
            consent,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn objective_digest(&self) -> &Digest {
        &self.objective_digest
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workato-mission-scope/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.mission_id.as_str().to_owned(),
                self.mission_revision.get().to_string(),
                self.work_product_id.as_str().to_owned(),
                self.work_product_revision.get().to_string(),
                self.objective_digest.as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecipeVersionBinding {
    version_id: RecipeVersionId,
    version_number: u64,
    revision: Revision,
}

impl RecipeVersionBinding {
    pub fn new(
        version_id: RecipeVersionId,
        version_number: u64,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        if version_number == 0 {
            return Err(ModelError::InvalidScope);
        }
        Ok(Self {
            version_id,
            version_number,
            revision,
        })
    }

    pub fn version_id(&self) -> &RecipeVersionId {
        &self.version_id
    }

    pub const fn version_number(&self) -> u64 {
        self.version_number
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workato-recipe-version-binding/v1",
            &[
                self.version_id.as_str().to_owned(),
                self.version_number.to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryIdentity {
    root_job_handle: JobHandle,
    retry_number: u32,
    parent_job_handle: Option<JobHandle>,
}

impl RetryIdentity {
    pub fn initial(job_handle: JobHandle) -> Self {
        Self {
            root_job_handle: job_handle,
            retry_number: 0,
            parent_job_handle: None,
        }
    }

    pub fn new(
        root_job_handle: JobHandle,
        retry_number: u32,
        parent_job_handle: Option<JobHandle>,
    ) -> Result<Self, ModelError> {
        if retry_number > 0 && parent_job_handle.is_none() {
            return Err(ModelError::InvalidRetryIdentity);
        }
        if retry_number == 0 && parent_job_handle.is_some() {
            return Err(ModelError::InvalidRetryIdentity);
        }
        Ok(Self {
            root_job_handle,
            retry_number,
            parent_job_handle,
        })
    }

    pub fn root_job_handle(&self) -> &JobHandle {
        &self.root_job_handle
    }

    pub const fn retry_number(&self) -> u32 {
        self.retry_number
    }

    pub fn parent_job_handle(&self) -> Option<&JobHandle> {
        self.parent_job_handle.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workato-retry-identity/v1",
            &[
                self.root_job_handle.as_str().to_owned(),
                self.retry_number.to_string(),
                self.parent_job_handle
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobIdentity {
    job_handle: JobHandle,
    retry: RetryIdentity,
}

impl JobIdentity {
    pub fn new(job_handle: JobHandle, retry: RetryIdentity) -> Result<Self, ModelError> {
        if retry.retry_number() == 0 && retry.root_job_handle() != &job_handle {
            return Err(ModelError::InvalidRetryIdentity);
        }
        Ok(Self { job_handle, retry })
    }

    pub fn job_handle(&self) -> &JobHandle {
        &self.job_handle
    }

    pub fn retry(&self) -> &RetryIdentity {
        &self.retry
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workato-job-identity/v1",
            &[
                self.job_handle.as_str().to_owned(),
                self.retry.digest().as_str().to_owned(),
            ],
        )
    }

    pub fn retry_key_digest(&self) -> Digest {
        Digest::from_fields(
            "workato-rerun-key/v1",
            &[
                self.retry.root_job_handle().as_str().to_owned(),
                self.retry.retry_number().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StepScope {
    allow_all: bool,
    allowed_steps: Vec<StepId>,
    revision: Revision,
}

impl StepScope {
    pub fn all(revision: Revision) -> Self {
        Self {
            allow_all: true,
            allowed_steps: Vec::new(),
            revision,
        }
    }

    pub fn only(
        allowed_steps: impl IntoIterator<Item = StepId>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let allowed_steps = allowed_steps.into_iter().collect::<BTreeSet<_>>();
        if allowed_steps.is_empty() || allowed_steps.len() > MAX_STEPS {
            return Err(ModelError::InvalidStepScope);
        }
        Ok(Self {
            allow_all: false,
            allowed_steps: allowed_steps.into_iter().collect(),
            revision,
        })
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn allow_all(&self) -> bool {
        self.allow_all
    }

    pub fn allowed_steps(&self) -> &[StepId] {
        &self.allowed_steps
    }

    pub fn allows(&self, step_id: &StepId) -> bool {
        self.allow_all || self.allowed_steps.binary_search(step_id).is_ok()
    }

    pub fn digest(&self) -> Digest {
        let mut fields = vec![self.revision.get().to_string(), self.allow_all.to_string()];
        fields.extend(
            self.allowed_steps
                .iter()
                .map(|step| step.as_str().to_owned()),
        );
        Digest::from_fields("workato-step-scope/v1", &fields)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoScope {
    workspace: WorkspaceId,
    project: WorkatoProjectId,
    folder: FolderId,
    recipe: RecipeId,
    recipe_version: RecipeVersionBinding,
    job: JobIdentity,
    step_scope: StepScope,
    mission: MissionScope,
    permission: PermissionScope,
    scope_digest: Digest,
}

impl WorkatoScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: WorkspaceId,
        project: WorkatoProjectId,
        folder: FolderId,
        recipe: RecipeId,
        recipe_version: RecipeVersionBinding,
        job: JobIdentity,
        step_scope: StepScope,
        mission: MissionScope,
        permission: PermissionScope,
    ) -> Result<Self, ModelError> {
        if !permission.allows(WorkatoOperation::GetRecipe)
            || !permission.allows(WorkatoOperation::GetRecipeVersion)
            || !permission.allows(WorkatoOperation::GetJob)
        {
            return Err(ModelError::InvalidScope);
        }
        let mut scope = Self {
            workspace,
            project,
            folder,
            recipe,
            recipe_version,
            job,
            step_scope,
            mission,
            permission,
            scope_digest: Digest::from_text("uninitialized-workato-scope"),
        };
        scope.scope_digest = scope.compute_digest();
        Ok(scope)
    }

    pub fn workspace(&self) -> &WorkspaceId {
        &self.workspace
    }

    pub fn project(&self) -> &WorkatoProjectId {
        &self.project
    }

    pub fn folder(&self) -> &FolderId {
        &self.folder
    }

    pub fn recipe(&self) -> &RecipeId {
        &self.recipe
    }

    pub fn recipe_version(&self) -> &RecipeVersionBinding {
        &self.recipe_version
    }

    pub fn job(&self) -> &JobIdentity {
        &self.job
    }

    pub fn step_scope(&self) -> &StepScope {
        &self.step_scope
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn permission(&self) -> &PermissionScope {
        &self.permission
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "workato-scope/v1",
            &[
                self.workspace.as_str().to_owned(),
                self.project.as_str().to_owned(),
                self.folder.as_str().to_owned(),
                self.recipe.as_str().to_owned(),
                self.recipe_version.digest().as_str().to_owned(),
                self.job.digest().as_str().to_owned(),
                self.step_scope.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.permission.permission_digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Unmounted,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoRegistration {
    pub state: RegistrationState,
    pub registration_revision: Revision,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub capability_digest: Digest,
    pub workspace_digest: Digest,
    pub project_digest: Digest,
    pub folder_digest: Digest,
    pub recipe_digest: Digest,
    pub recipe_version_digest: Digest,
    pub job_digest: Digest,
    pub retry_digest: Digest,
    pub step_scope_digest: Digest,
    pub mission_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub credential_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl WorkatoRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &WorkatoScope,
        secret: &SecretReference,
        plugin_version_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        capability_digest: Digest,
    ) -> Result<Self, ModelError> {
        if secret.is_revoked() || secret.scope_digest() != &scope.scope_digest() {
            return Err(ModelError::InvalidSecret);
        }
        let scope_digest = scope.scope_digest();
        let fields = vec![
            plugin_version_digest.as_str().to_owned(),
            contract_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
            capability_digest.as_str().to_owned(),
            Digest::from_text(scope.workspace().as_str())
                .as_str()
                .to_owned(),
            Digest::from_text(scope.project().as_str())
                .as_str()
                .to_owned(),
            Digest::from_text(scope.folder().as_str())
                .as_str()
                .to_owned(),
            Digest::from_text(scope.recipe().as_str())
                .as_str()
                .to_owned(),
            scope.recipe_version().digest().as_str().to_owned(),
            scope.job().digest().as_str().to_owned(),
            scope.job().retry().digest().as_str().to_owned(),
            scope.step_scope().digest().as_str().to_owned(),
            scope.mission().digest().as_str().to_owned(),
            scope.permission().permission_digest().as_str().to_owned(),
            scope.mission().consent().digest().as_str().to_owned(),
            secret.reference_digest().as_str().to_owned(),
            scope_digest.as_str().to_owned(),
        ];
        let registration_digest = Digest::from_fields("workato-registration/v1", &fields);
        Ok(Self {
            state: RegistrationState::Active,
            registration_revision: Revision::new(1)?,
            plugin_version_digest,
            contract_digest,
            provider_digest,
            capability_digest,
            workspace_digest: Digest::from_text(scope.workspace().as_str()),
            project_digest: Digest::from_text(scope.project().as_str()),
            folder_digest: Digest::from_text(scope.folder().as_str()),
            recipe_digest: Digest::from_text(scope.recipe().as_str()),
            recipe_version_digest: scope.recipe_version().digest(),
            job_digest: scope.job().digest(),
            retry_digest: scope.job().retry().digest(),
            step_scope_digest: scope.step_scope().digest(),
            mission_digest: scope.mission().digest(),
            permission_digest: scope.permission().permission_digest().clone(),
            consent_digest: scope.mission().consent().digest().clone(),
            credential_digest: secret.reference_digest().clone(),
            scope_digest,
            registration_digest,
            reversible: true,
            revocable: true,
        })
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransition, ModelError> {
        if !self.reversible
            || matches!(
                self.state,
                RegistrationState::Revoked | RegistrationState::Reversed
            )
        {
            return Err(ModelError::RegistrationTerminal);
        }
        self.state = RegistrationState::Unmounted;
        Ok(RegistrationTransition::new(
            self.state,
            &self.registration_digest,
        ))
    }

    pub fn remount(&mut self) -> Result<RegistrationTransition, ModelError> {
        if matches!(
            self.state,
            RegistrationState::Revoked | RegistrationState::Reversed
        ) {
            return Err(ModelError::RegistrationTerminal);
        }
        self.state = RegistrationState::Active;
        Ok(RegistrationTransition::new(
            self.state,
            &self.registration_digest,
        ))
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, ModelError> {
        if !self.revocable
            || matches!(
                self.state,
                RegistrationState::Revoked | RegistrationState::Reversed
            )
        {
            return Err(ModelError::RegistrationTerminal);
        }
        self.state = RegistrationState::Revoked;
        Ok(RegistrationTransition::new(
            self.state,
            &self.registration_digest,
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition, ModelError> {
        if !self.reversible
            || matches!(
                self.state,
                RegistrationState::Revoked | RegistrationState::Reversed
            )
        {
            return Err(ModelError::RegistrationTerminal);
        }
        self.state = RegistrationState::Reversed;
        Ok(RegistrationTransition::new(
            self.state,
            &self.registration_digest,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationTransition {
    pub state: RegistrationState,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationTransition {
    fn new(state: RegistrationState, registration_digest: &Digest) -> Self {
        Self {
            state,
            registration_digest: registration_digest.clone(),
            reversible: true,
            revocable: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Completed,
    Failed,
    Processing,
    Paused,
    Aborted,
    Retried,
    Partial,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Completed,
    Failed,
    Processing,
    Paused,
    Aborted,
    Skipped,
    Retried,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionState {
    Present,
    RetentionGap,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkatoResultStatus {
    Completed,
    Failed,
    Processing,
    Paused,
    Aborted,
    Retried,
    RetentionGap,
    Partial,
    AccessLost,
    ProviderUnknown,
}

impl WorkatoResultStatus {
    pub const fn needs_layer2_adoption(self) -> bool {
        !matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecipeProjection {
    pub recipe_id: RecipeId,
    pub workspace_digest: Digest,
    pub project_digest: Digest,
    pub folder_digest: Digest,
    pub recipe_revision: Revision,
    pub name_digest: Digest,
    pub status_digest: Digest,
    pub provider_revision_digest: Digest,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecipeVersionProjection {
    pub recipe_id: RecipeId,
    pub version_id: RecipeVersionId,
    pub version_number: u64,
    pub revision: Revision,
    pub comment_digest: Digest,
    pub author_digest: Digest,
    pub created_at_digest: Digest,
    pub updated_at_digest: Digest,
    pub provider_revision_digest: Digest,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StepProjection {
    pub step_id: StepId,
    pub ordinal: u32,
    pub status: StepStatus,
    pub kind_digest: Digest,
    pub error_digest: Option<Digest>,
    pub duration_ms: Option<u64>,
    pub retry_number: u32,
    pub runtime_data_redacted: bool,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobProjection {
    pub identity: JobIdentity,
    pub recipe_id: RecipeId,
    pub recipe_version: RecipeVersionBinding,
    pub status: JobStatus,
    pub retention: RetentionState,
    pub started_at_digest: Option<Digest>,
    pub completed_at_digest: Option<Digest>,
    pub duration_ms: Option<u64>,
    pub tasks_used: Option<u64>,
    pub step_count: usize,
    pub failed_step_count: usize,
    pub steps: Vec<StepProjection>,
    pub runtime_data_redacted: bool,
    pub provider_revision_digest: Digest,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryProjection {
    pub identity: RetryIdentity,
    pub job_digest: Digest,
    pub status: JobStatus,
    pub projection_digest: Digest,
}

pub(crate) fn digest_optional(value: Option<&str>) -> Option<Digest> {
    value.map(Digest::from_text)
}

pub(crate) fn scope_identity_matches(scope: &WorkatoScope, identity: &JobIdentity) -> bool {
    scope.job() == identity
}
