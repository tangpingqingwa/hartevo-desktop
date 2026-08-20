//! Typed, bounded and redacted AWS ECS deployment models.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_TASKS: usize = 256;
pub const MAX_DEPLOYMENTS: usize = 32;
pub const MAX_ITEMS_PER_PAGE: usize = 100;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
pub const MAX_RETRIES: u8 = 2;

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
    #[error("{field} contains a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is not allowed by the permission or consent fence")]
    PermissionDenied { field: &'static str },
    #[error("registration or secret reference is revoked")]
    Revoked,
    #[error("secret reference is already revoked")]
    AlreadyRevoked,
}

pub type ModelResult<T> = std::result::Result<T, ModelError>;

fn validate_text(value: &str, field: &'static str, max: usize) -> ModelResult<()> {
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
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> ModelResult<()> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> ModelResult<Self> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-ecs-", $field, "/v1"),
                    std::slice::from_ref(&self.0),
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(DeploymentId, "deployment-id");
bounded_identifier!(MissionId, "mission-id");
bounded_identifier!(ProjectId, "project-id");
bounded_identifier!(WorkProductId, "work-product-id");
bounded_identifier!(ClusterName, "cluster-name");
bounded_identifier!(ServiceName, "service-name");
bounded_identifier!(TaskId, "task-id");
bounded_identifier!(TaskDefinitionFamily, "task-definition-family");
bounded_identifier!(PermissionId, "permission-id");
bounded_identifier!(ConsentId, "consent-id");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
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
        Digest::from_parts("aws-ecs-account/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AccountId")
            .field(&self.digest())
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
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
        Digest::from_parts("aws-ecs-region/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;
pub type AwsAccountId = AccountId;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> ModelResult<Self> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ProviderRevision(String);

impl ProviderRevision {
    pub fn new(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        validate_text(&value, "provider revision", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderRevision")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

/// # Panics
///
/// Panics only if a bounded model unexpectedly fails its `Serialize`
/// implementation. All public model types in this crate are serializable.
pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("bounded ECS values serialize"))
}

macro_rules! binding {
    ($name:ident, $id:ty, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub id: $id,
            pub revision: Revision,
        }

        impl $name {
            pub const fn new(id: $id, revision: Revision) -> Self {
                Self { id, revision }
            }

            pub fn digest(&self) -> Digest {
                digest_serialized(self)
            }

            pub fn validate(&self) -> ModelResult<()> {
                if self.revision.get() == 0 {
                    return Err(ModelError::MustBePositive { field: $field });
                }
                Ok(())
            }
        }
    };
}

binding!(AccountBinding, AccountId, "account revision");
binding!(RegionBinding, AwsRegion, "region revision");
binding!(ClusterBinding, ClusterName, "cluster revision");
binding!(ServiceBinding, ServiceName, "service revision");
binding!(TaskBinding, TaskId, "task revision");
binding!(MissionBinding, MissionId, "Mission revision");
binding!(ProjectBinding, ProjectId, "Project revision");
binding!(WorkProductBinding, WorkProductId, "Work Product revision");

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
    pub generation: u64,
}

impl DeploymentBinding {
    pub fn new(id: DeploymentId, revision: Revision) -> Self {
        Self {
            id,
            generation: revision.get(),
            revision,
        }
    }

    pub fn with_generation(
        id: DeploymentId,
        revision: Revision,
        generation: u64,
    ) -> ModelResult<Self> {
        validate_positive(generation, "deployment generation")?;
        Ok(Self {
            id,
            revision,
            generation,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.revision.get() == 0 || self.generation == 0 {
            return Err(ModelError::MustBePositive {
                field: "deployment revision or generation",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskDefinitionBinding {
    pub family: TaskDefinitionFamily,
    pub revision: Revision,
}

impl TaskDefinitionBinding {
    pub const fn new(family: TaskDefinitionFamily, revision: Revision) -> Self {
        Self { family, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.revision.get() == 0 {
            return Err(ModelError::MustBePositive {
                field: "task-definition revision",
            });
        }
        Ok(())
    }
}

pub type EcsAccount = AccountBinding;
pub type EcsRegion = RegionBinding;
pub type EcsCluster = ClusterBinding;
pub type EcsService = ServiceBinding;
pub type EcsDeployment = DeploymentBinding;
pub type EcsTaskDefinition = TaskDefinitionBinding;
pub type EcsTask = TaskBinding;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReadOperation {
    DescribeServices,
    DescribeTasks,
    DescribeTaskDefinition,
    ListTasks,
}

impl ReadOperation {
    pub const ALL: [Self; 4] = [
        Self::DescribeServices,
        Self::DescribeTasks,
        Self::DescribeTaskDefinition,
        Self::ListTasks,
    ];
}

pub type EcsReadOperation = ReadOperation;
pub type PermissionAction = ReadOperation;
pub type EcsPermissionAction = ReadOperation;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    pub consent_id_digest: Digest,
    pub revision: Revision,
    pub allowed_operations: BTreeSet<ReadOperation>,
    pub consent_digest: Digest,
}

impl ConsentScope {
    pub fn new(
        consent_id: impl AsRef<str>,
        revision: Revision,
        allowed_operations: impl IntoIterator<Item = ReadOperation>,
    ) -> ModelResult<Self> {
        let allowed_operations = allowed_operations.into_iter().collect::<BTreeSet<_>>();
        if allowed_operations.is_empty() {
            return Err(ModelError::Empty {
                field: "consent operation allowlist",
            });
        }
        let mut value = Self {
            consent_id_digest: Digest::from_parts(
                "aws-ecs-consent-id/v1",
                &[consent_id.as_ref().to_owned()],
            ),
            revision,
            allowed_operations,
            consent_digest: Digest::zero(),
        };
        value.consent_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn all(consent_id: impl AsRef<str>, revision: Revision) -> ModelResult<Self> {
        Self::new(consent_id, revision, ReadOperation::ALL)
    }

    pub fn allows(&self, operation: ReadOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.consent_id_digest,
            self.revision,
            &self.allowed_operations,
        ))
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.revision.get() == 0
            || self.allowed_operations.is_empty()
            || self.consent_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "consent scope",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionScope {
    pub account: AccountBinding,
    pub revision: Revision,
    pub allowed_operations: BTreeSet<ReadOperation>,
    pub consent_digest: Digest,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        account: AccountBinding,
        revision: Revision,
        allowed_operations: impl IntoIterator<Item = ReadOperation>,
        consent: &ConsentScope,
    ) -> ModelResult<Self> {
        let allowed_operations = allowed_operations.into_iter().collect::<BTreeSet<_>>();
        if allowed_operations.is_empty()
            || allowed_operations
                .iter()
                .any(|operation| !consent.allows(*operation))
        {
            return Err(ModelError::PermissionDenied {
                field: "permission operation allowlist",
            });
        }
        let mut value = Self {
            account,
            revision,
            allowed_operations,
            consent_digest: consent.consent_digest.clone(),
            permission_digest: Digest::zero(),
        };
        value.permission_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn readonly(
        account: AccountBinding,
        revision: Revision,
        consent: &ConsentScope,
    ) -> ModelResult<Self> {
        Self::new(account, revision, ReadOperation::ALL, consent)
    }

    pub fn allows(&self, operation: ReadOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.account,
            self.revision,
            &self.allowed_operations,
            &self.consent_digest,
        ))
    }

    pub fn validate(&self, consent: &ConsentScope) -> ModelResult<()> {
        consent.validate()?;
        if self.account.validate().is_err()
            || self.revision.get() == 0
            || self.allowed_operations.is_empty()
            || self.consent_digest != consent.consent_digest
            || self
                .allowed_operations
                .iter()
                .any(|operation| !consent.allows(*operation))
            || self.permission_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "permission scope",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }
}

pub type PermissionFence = PermissionScope;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsDeploymentScope {
    pub account: AccountBinding,
    pub region: RegionBinding,
    pub cluster: ClusterBinding,
    pub service: ServiceBinding,
    pub deployment: DeploymentBinding,
    pub task_definition: TaskDefinitionBinding,
    pub tasks: Vec<TaskBinding>,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub permission: PermissionScope,
    pub consent: ConsentScope,
    pub scope_digest: Digest,
}

impl EcsDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AccountBinding,
        region: RegionBinding,
        cluster: ClusterBinding,
        service: ServiceBinding,
        deployment: DeploymentBinding,
        task_definition: TaskDefinitionBinding,
        tasks: impl IntoIterator<Item = TaskBinding>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permission: PermissionScope,
        consent: ConsentScope,
    ) -> ModelResult<Self> {
        let mut tasks = tasks.into_iter().collect::<Vec<_>>();
        tasks.sort();
        let scope = Self {
            account,
            region,
            cluster,
            service,
            deployment,
            task_definition,
            tasks,
            mission,
            project,
            work_product,
            permission,
            consent,
            scope_digest: Digest::zero(),
        };
        scope.validate_fields()?;
        let scope_digest = scope.recomputed_digest();
        Ok(Self {
            scope_digest,
            ..scope
        })
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.account,
            &self.region,
            &self.cluster,
            &self.service,
            &self.deployment,
            &self.task_definition,
            &self.tasks,
            &self.mission,
            &self.project,
            &self.work_product,
            &self.permission,
            &self.consent,
        ))
    }

    fn validate_fields(&self) -> ModelResult<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.cluster.validate()?;
        self.service.validate()?;
        self.deployment.validate()?;
        self.task_definition.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if self.tasks.len() > MAX_TASKS {
            return Err(ModelError::TooMany {
                field: "task allowlist",
            });
        }
        for task in &self.tasks {
            task.validate()?;
        }
        for pair in self.tasks.windows(2) {
            if pair[0] == pair[1] {
                return Err(ModelError::Duplicate {
                    field: "task allowlist",
                });
            }
        }
        self.consent.validate()?;
        self.permission.validate(&self.consent)?;
        if self.permission.account.id != self.account.id {
            return Err(ModelError::ScopeMismatch {
                field: "permission account",
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.validate_fields()?;
        if self.scope_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "scope digest",
            });
        }
        Ok(())
    }

    pub fn contains_task(&self, task: &TaskBinding) -> bool {
        self.tasks.iter().any(|candidate| candidate == task)
    }

    pub fn task_revision(&self, task: &TaskId) -> Option<Revision> {
        self.tasks
            .iter()
            .find(|candidate| candidate.id == *task)
            .map(|candidate| candidate.revision)
    }
}

pub type AwsEcsScope = EcsDeploymentScope;
pub type EcsScope = EcsDeploymentScope;

/// Opaque SigV4 reference. The caller's handle is retained only inside this
/// non-serializing type so it can be zeroized on drop and hashed into a fence.
#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    region: AwsRegion,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_id", &"<opaque>")
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        region: impl Into<String>,
        scope_digest: Digest,
        revision: Revision,
    ) -> ModelResult<Self> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "SigV4 secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        let region = AwsRegion::new(region.into())?;
        Ok(Self {
            reference_id,
            region,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &EcsDeploymentScope,
        revision: Revision,
    ) -> ModelResult<Self> {
        Self::new(
            reference_id,
            scope.region.id.as_str().to_owned(),
            scope.scope_digest.clone(),
            revision,
        )
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ecs-opaque-sigv4-reference/v1",
            &[
                self.reference_id.clone(),
                self.region.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub fn digest(&self) -> Digest {
        self.reference_digest()
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> ModelResult<()> {
        if self.revoked {
            Err(ModelError::Revoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> ModelResult<()> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.reference_id.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    page_number: u16,
}

pub type OpaquePageToken = OpaqueCursor;

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> ModelResult<Self> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor {
                field: "next token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts("aws-ecs-next-token/v1", &[value.to_owned()]),
            binding_digest: None,
            page_number: 0,
        })
    }

    #[must_use]
    pub fn bind(&self, binding_digest: &Digest, page_number: u16) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
            page_number,
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn digest(&self) -> Digest {
        self.token_digest.clone()
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("OpaqueCursor", 3)?;
        value.serialize_field("opaque", &true)?;
        value.serialize_field("tokenDigest", &self.token_digest)?;
        value.serialize_field("bindingDigest", &self.binding_digest)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceStatus {
    Active,
    Draining,
    Inactive,
    Provisioning,
    Deregistering,
    Unknown,
}

impl ServiceStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "ACTIVE" => Self::Active,
            "DRAINING" => Self::Draining,
            "INACTIVE" => Self::Inactive,
            "PROVISIONING" => Self::Provisioning,
            "DEREGISTERING" => Self::Deregistering,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentRolloutState {
    InProgress,
    Completed,
    Failed,
    Unknown,
}

impl DeploymentRolloutState {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "IN_PROGRESS" => Self::InProgress,
            "COMPLETED" => Self::Completed,
            "FAILED" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

impl TaskHealth {
    pub fn parse_api(value: Option<&str>) -> Self {
        match value {
            Some("HEALTHY") => Self::Healthy,
            Some("UNHEALTHY") => Self::Unhealthy,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskLastStatus {
    Provisioning,
    Pending,
    Activating,
    Running,
    Deactivating,
    Stopping,
    Stopped,
    Deprovisioning,
    Unknown,
}

impl TaskLastStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "PROVISIONING" => Self::Provisioning,
            "PENDING" => Self::Pending,
            "ACTIVATING" => Self::Activating,
            "RUNNING" => Self::Running,
            "DEACTIVATING" => Self::Deactivating,
            "STOPPING" => Self::Stopping,
            "STOPPED" => Self::Stopped,
            "DEPROVISIONING" => Self::Deprovisioning,
            _ => Self::Unknown,
        }
    }
}

pub type TaskHealthStatus = TaskHealth;
pub type TaskLifecycleStatus = TaskLastStatus;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskFilter {
    pub desired_status: Option<TaskLastStatus>,
    pub task_definition: Option<TaskDefinitionBinding>,
}

impl TaskFilter {
    pub const fn all() -> Self {
        Self {
            desired_status: None,
            task_definition: None,
        }
    }

    #[must_use]
    pub fn with_desired_status(mut self, desired_status: TaskLastStatus) -> Self {
        self.desired_status = Some(desired_status);
        self
    }

    #[must_use]
    pub fn with_task_definition(mut self, task_definition: TaskDefinitionBinding) -> Self {
        self.task_definition = Some(task_definition);
        self
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        if let Some(task_definition) = &self.task_definition
            && task_definition != &scope.task_definition
        {
            return Err(ModelError::ScopeMismatch {
                field: "task-definition filter",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBounds {
    pub max_pages: u16,
    pub max_items: usize,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub max_requests: u16,
    pub max_retries: u8,
}

impl ReadBounds {
    pub fn new(
        max_pages: u16,
        max_items: usize,
        page_size: u16,
        max_response_bytes: usize,
        max_requests: u16,
        max_retries: u8,
    ) -> ModelResult<Self> {
        let bounds = Self {
            max_pages,
            max_items,
            page_size,
            max_response_bytes,
            max_requests,
            max_retries,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_items == 0
            || self.max_items > MAX_TASKS
            || self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_requests == 0
            || self.max_requests > MAX_REQUESTS_PER_READ
            || self.max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        Ok(())
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_items: MAX_TASKS,
            page_size: PAGE_SIZE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_requests: MAX_REQUESTS_PER_READ,
            max_retries: MAX_RETRIES,
        }
    }
}

fn validate_request_binding(
    operation: ReadOperation,
    request_scope: &Digest,
    request_permission: &Digest,
    request_consent: &Digest,
    scope: &EcsDeploymentScope,
) -> ModelResult<()> {
    if request_scope != &scope.scope_digest {
        return Err(ModelError::ScopeMismatch {
            field: "scope digest",
        });
    }
    if request_permission != &scope.permission.permission_digest {
        return Err(ModelError::ScopeMismatch {
            field: "permission digest",
        });
    }
    if request_consent != &scope.consent.consent_digest {
        return Err(ModelError::ScopeMismatch {
            field: "consent digest",
        });
    }
    if !scope.permission.allows(operation) || !scope.consent.allows(operation) {
        return Err(ModelError::PermissionDenied {
            field: "ECS read operation",
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServicesRequest {
    pub operation: ReadOperation,
    pub cluster: ClusterBinding,
    pub service: ServiceBinding,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub bounds: ReadBounds,
}

impl DescribeServicesRequest {
    pub fn for_scope(scope: &EcsDeploymentScope, bounds: ReadBounds) -> ModelResult<Self> {
        bounds.validate()?;
        Ok(Self {
            operation: ReadOperation::DescribeServices,
            cluster: scope.cluster.clone(),
            service: scope.service.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission.permission_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
            bounds,
        })
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.cluster,
            &self.service,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.bounds,
        ))
    }

    pub fn request_digest(&self) -> Digest {
        self.query_digest()
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        self.bounds.validate()?;
        validate_request_binding(
            self.operation,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            scope,
        )?;
        if self.cluster != scope.cluster || self.service != scope.service {
            return Err(ModelError::ScopeMismatch {
                field: "cluster or service",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTasksRequest {
    pub operation: ReadOperation,
    pub cluster: ClusterBinding,
    pub tasks: Vec<TaskBinding>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub bounds: ReadBounds,
}

impl DescribeTasksRequest {
    pub fn for_scope(scope: &EcsDeploymentScope, bounds: ReadBounds) -> ModelResult<Self> {
        bounds.validate()?;
        Ok(Self {
            operation: ReadOperation::DescribeTasks,
            cluster: scope.cluster.clone(),
            tasks: scope.tasks.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission.permission_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
            bounds,
        })
    }

    pub fn new(
        scope: &EcsDeploymentScope,
        tasks: impl IntoIterator<Item = TaskBinding>,
        bounds: ReadBounds,
    ) -> ModelResult<Self> {
        let mut request = Self::for_scope(scope, bounds)?;
        request.tasks = tasks.into_iter().collect();
        request.validate_against(scope)?;
        Ok(request)
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.cluster,
            &self.tasks,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.bounds,
        ))
    }

    pub fn request_digest(&self) -> Digest {
        self.query_digest()
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        self.bounds.validate()?;
        validate_request_binding(
            self.operation,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            scope,
        )?;
        if self.cluster != scope.cluster || self.tasks.len() > self.bounds.max_items {
            return Err(ModelError::ScopeMismatch {
                field: "cluster or task bound",
            });
        }
        let mut seen = BTreeSet::new();
        for task in &self.tasks {
            if !scope.contains_task(task) || !seen.insert(task) {
                return Err(ModelError::ScopeMismatch {
                    field: "task allowlist",
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTaskDefinitionRequest {
    pub operation: ReadOperation,
    pub family: TaskDefinitionFamily,
    pub revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub bounds: ReadBounds,
}

impl DescribeTaskDefinitionRequest {
    pub fn for_scope(scope: &EcsDeploymentScope, bounds: ReadBounds) -> ModelResult<Self> {
        bounds.validate()?;
        Ok(Self {
            operation: ReadOperation::DescribeTaskDefinition,
            family: scope.task_definition.family.clone(),
            revision: scope.task_definition.revision,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission.permission_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
            bounds,
        })
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.family,
            self.revision,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.bounds,
        ))
    }

    pub fn request_digest(&self) -> Digest {
        self.query_digest()
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        self.bounds.validate()?;
        validate_request_binding(
            self.operation,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            scope,
        )?;
        if self.family != scope.task_definition.family
            || self.revision != scope.task_definition.revision
        {
            return Err(ModelError::ScopeMismatch {
                field: "task-definition family or revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTasksRequest {
    pub operation: ReadOperation,
    pub cluster: ClusterBinding,
    pub service: ServiceBinding,
    pub filter: TaskFilter,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_items: usize,
    pub max_response_bytes: usize,
    pub max_requests: u16,
    pub max_retries: u8,
    pub cursor: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

impl ListTasksRequest {
    pub fn for_scope(
        scope: &EcsDeploymentScope,
        filter: TaskFilter,
        bounds: ReadBounds,
    ) -> ModelResult<Self> {
        bounds.validate()?;
        filter.validate_against(scope)?;
        Ok(Self {
            operation: ReadOperation::ListTasks,
            cluster: scope.cluster.clone(),
            service: scope.service.clone(),
            filter,
            page_size: bounds.page_size,
            max_pages: bounds.max_pages,
            max_items: bounds.max_items,
            max_response_bytes: bounds.max_response_bytes,
            max_requests: bounds.max_requests,
            max_retries: bounds.max_retries,
            cursor: None,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission.permission_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
        })
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.cluster,
            &self.service,
            &self.filter,
            self.page_size,
            self.max_pages,
            self.max_items,
            self.max_response_bytes,
            self.max_requests,
            self.max_retries,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
        ))
    }

    pub fn request_digest(&self) -> Digest {
        digest_serialized(&(
            &self.query_digest(),
            self.cursor.as_ref().map(OpaqueCursor::digest),
        ))
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> ModelResult<Self> {
        let mut next = self.clone();
        next.cursor = cursor.map(|cursor| cursor.bind(&self.query_digest(), 0));
        next.validate_cursor()?;
        Ok(next)
    }

    pub fn with_next_token(&self, cursor: Option<OpaqueCursor>) -> ModelResult<Self> {
        self.with_cursor(cursor)
    }

    fn validate_cursor(&self) -> ModelResult<()> {
        if let Some(cursor) = &self.cursor
            && cursor.binding_digest() != Some(&self.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor query binding",
            });
        }
        Ok(())
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        if self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_items == 0
            || self.max_items > MAX_TASKS
            || self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_requests == 0
            || self.max_requests > MAX_REQUESTS_PER_READ
            || self.max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        validate_request_binding(
            self.operation,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            scope,
        )?;
        if self.cluster != scope.cluster || self.service != scope.service {
            return Err(ModelError::ScopeMismatch {
                field: "cluster or service",
            });
        }
        self.filter.validate_against(scope)?;
        self.validate_cursor()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EcsReadRequest {
    DescribeServices(DescribeServicesRequest),
    DescribeTasks(DescribeTasksRequest),
    DescribeTaskDefinition(DescribeTaskDefinitionRequest),
    ListTasks(ListTasksRequest),
}

impl EcsReadRequest {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::DescribeServices(_) => ReadOperation::DescribeServices,
            Self::DescribeTasks(_) => ReadOperation::DescribeTasks,
            Self::DescribeTaskDefinition(_) => ReadOperation::DescribeTaskDefinition,
            Self::ListTasks(_) => ReadOperation::ListTasks,
        }
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        match self {
            Self::DescribeServices(request) => request.validate_against(scope),
            Self::DescribeTasks(request) => request.validate_against(scope),
            Self::DescribeTaskDefinition(request) => request.validate_against(scope),
            Self::ListTasks(request) => request.validate_against(scope),
        }
    }

    pub fn request_digest(&self) -> Digest {
        match self {
            Self::DescribeServices(request) => request.request_digest(),
            Self::DescribeTasks(request) => request.request_digest(),
            Self::DescribeTaskDefinition(request) => request.request_digest(),
            Self::ListTasks(request) => request.request_digest(),
        }
    }
}

impl From<DescribeServicesRequest> for EcsReadRequest {
    fn from(value: DescribeServicesRequest) -> Self {
        Self::DescribeServices(value)
    }
}

impl From<DescribeTasksRequest> for EcsReadRequest {
    fn from(value: DescribeTasksRequest) -> Self {
        Self::DescribeTasks(value)
    }
}

impl From<DescribeTaskDefinitionRequest> for EcsReadRequest {
    fn from(value: DescribeTaskDefinitionRequest) -> Self {
        Self::DescribeTaskDefinition(value)
    }
}

impl From<ListTasksRequest> for EcsReadRequest {
    fn from(value: ListTasksRequest) -> Self {
        Self::ListTasks(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDeploymentObservation {
    pub deployment: DeploymentBinding,
    pub status: ServiceStatus,
    pub rollout_state: DeploymentRolloutState,
    pub desired_count: u32,
    pub running_count: u32,
    pub pending_count: u32,
    pub task_definition: TaskDefinitionBinding,
    pub observation_digest: Digest,
}

impl ServiceDeploymentObservation {
    pub fn new(
        deployment: DeploymentBinding,
        status: ServiceStatus,
        rollout_state: DeploymentRolloutState,
        desired_count: u32,
        running_count: u32,
        pending_count: u32,
        task_definition: TaskDefinitionBinding,
    ) -> Self {
        let mut value = Self {
            deployment,
            status,
            rollout_state,
            desired_count,
            running_count,
            pending_count,
            task_definition,
            observation_digest: Digest::zero(),
        };
        value.observation_digest = value.recomputed_digest();
        value
    }

    pub fn from_api(
        deployment: DeploymentBinding,
        status: &str,
        rollout_state: &str,
        desired_count: u32,
        running_count: u32,
        pending_count: u32,
        task_definition: TaskDefinitionBinding,
    ) -> Self {
        Self::new(
            deployment,
            ServiceStatus::parse_api(status),
            DeploymentRolloutState::parse_api(rollout_state),
            desired_count,
            running_count,
            pending_count,
            task_definition,
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.deployment,
            self.status,
            self.rollout_state,
            self.desired_count,
            self.running_count,
            self.pending_count,
            &self.task_definition,
        ))
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.deployment.validate()?;
        self.task_definition.validate()?;
        if self.observation_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "service deployment observation digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceObservation {
    pub service: ServiceBinding,
    pub status: ServiceStatus,
    pub deployment_status: DeploymentRolloutState,
    pub desired_count: u32,
    pub running_count: u32,
    pub pending_count: u32,
    pub task_definition: TaskDefinitionBinding,
    pub deployment_generation: u64,
    pub deployments: Vec<ServiceDeploymentObservation>,
    pub observation_digest: Digest,
}

impl ServiceObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service: ServiceBinding,
        status: ServiceStatus,
        deployment_status: DeploymentRolloutState,
        desired_count: u32,
        running_count: u32,
        pending_count: u32,
        task_definition: TaskDefinitionBinding,
        deployment_generation: u64,
        deployments: impl IntoIterator<Item = ServiceDeploymentObservation>,
    ) -> ModelResult<Self> {
        validate_positive(deployment_generation, "deployment generation")?;
        let deployments = deployments.into_iter().collect::<Vec<_>>();
        if deployments.len() > MAX_DEPLOYMENTS {
            return Err(ModelError::TooMany {
                field: "service deployments",
            });
        }
        let mut value = Self {
            service,
            status,
            deployment_status,
            desired_count,
            running_count,
            pending_count,
            task_definition,
            deployment_generation,
            deployments,
            observation_digest: Digest::zero(),
        };
        value.observation_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn from_api(
        service: ServiceBinding,
        status: &str,
        deployment_status: &str,
        desired_count: u32,
        running_count: u32,
        pending_count: u32,
        task_definition: TaskDefinitionBinding,
        deployment_generation: u64,
        deployments: impl IntoIterator<Item = ServiceDeploymentObservation>,
    ) -> ModelResult<Self> {
        Self::new(
            service,
            ServiceStatus::parse_api(status),
            DeploymentRolloutState::parse_api(deployment_status),
            desired_count,
            running_count,
            pending_count,
            task_definition,
            deployment_generation,
            deployments,
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.service,
            self.status,
            self.deployment_status,
            self.desired_count,
            self.running_count,
            self.pending_count,
            &self.task_definition,
            self.deployment_generation,
            &self.deployments,
        ))
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        self.service.validate()?;
        self.task_definition.validate()?;
        if self.service != scope.service
            || self.task_definition != scope.task_definition
            || self.deployment_generation != scope.deployment.generation
            || self.observation_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "service deployment or task-definition revision",
            });
        }
        for deployment in &self.deployments {
            deployment.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskObservation {
    pub task: TaskBinding,
    pub task_definition: TaskDefinitionBinding,
    pub health: TaskHealth,
    pub last_status: TaskLastStatus,
    pub stopped_reason_digest: Option<Digest>,
    pub observation_digest: Digest,
}

impl TaskObservation {
    pub fn new(
        task: TaskBinding,
        task_definition: TaskDefinitionBinding,
        health: TaskHealth,
        last_status: TaskLastStatus,
        stopped_reason: Option<String>,
    ) -> ModelResult<Self> {
        let stopped_reason_digest =
            stopped_reason.map(|reason| Digest::from_parts("aws-ecs-stopped-reason/v1", &[reason]));
        let mut value = Self {
            task,
            task_definition,
            health,
            last_status,
            stopped_reason_digest,
            observation_digest: Digest::zero(),
        };
        value.observation_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn from_api(
        task: TaskBinding,
        task_definition: TaskDefinitionBinding,
        health: Option<&str>,
        last_status: &str,
        stopped_reason: Option<&str>,
    ) -> ModelResult<Self> {
        Self::new(
            task,
            task_definition,
            TaskHealth::parse_api(health),
            TaskLastStatus::parse_api(last_status),
            stopped_reason.map(str::to_owned),
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.task,
            &self.task_definition,
            self.health,
            self.last_status,
            &self.stopped_reason_digest,
        ))
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        self.task.validate()?;
        self.task_definition.validate()?;
        if !scope.contains_task(&self.task)
            || self.task_definition != scope.task_definition
            || self.observation_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "task or task-definition revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskDefinitionObservation {
    pub task_definition: TaskDefinitionBinding,
    pub status: ServiceStatus,
    pub observation_digest: Digest,
}

impl TaskDefinitionObservation {
    pub fn new(task_definition: TaskDefinitionBinding, status: ServiceStatus) -> Self {
        let mut value = Self {
            task_definition,
            status,
            observation_digest: Digest::zero(),
        };
        value.observation_digest = value.recomputed_digest();
        value
    }

    pub fn from_api(task_definition: TaskDefinitionBinding, status: &str) -> Self {
        Self::new(task_definition, ServiceStatus::parse_api(status))
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(&self.task_definition, self.status))
    }

    pub fn validate_against(&self, scope: &EcsDeploymentScope) -> ModelResult<()> {
        self.task_definition.validate()?;
        if self.task_definition != scope.task_definition
            || self.observation_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "task-definition family or revision",
            });
        }
        Ok(())
    }
}

fn bind_cursor(
    cursor: Option<OpaqueCursor>,
    query_digest: &Digest,
    page_number: u16,
) -> ModelResult<Option<OpaqueCursor>> {
    cursor
        .map(|cursor| {
            if let Some(existing) = cursor.binding_digest()
                && existing != query_digest
            {
                return Err(ModelError::ScopeMismatch {
                    field: "cursor query binding",
                });
            }
            Ok(cursor.bind(query_digest, page_number))
        })
        .transpose()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServicesPage {
    pub operation: ReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub services: Vec<ServiceObservation>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

impl DescribeServicesPage {
    pub fn new(
        request: &DescribeServicesRequest,
        page_number: u16,
        services: Vec<ServiceObservation>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> ModelResult<Self> {
        let query_digest = request.query_digest();
        let next_cursor = bind_cursor(next_cursor, &query_digest, page_number + 1)?;
        let mut value = Self {
            operation: ReadOperation::DescribeServices,
            query_digest,
            page_number,
            services,
            next_cursor,
            response_bytes,
            provider_revision,
            page_digest: Digest::zero(),
        };
        value.page_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.query_digest,
            self.page_number,
            &self.services,
            &self.next_cursor,
            self.response_bytes,
            &self.provider_revision,
        ))
    }

    pub fn validate_for(&self, request: &DescribeServicesRequest) -> ModelResult<()> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.services.len() > MAX_ITEMS_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > request.bounds.max_response_bytes
        {
            return Err(ModelError::Invalid {
                field: "DescribeServices page binding",
            });
        }
        if let Some(cursor) = &self.next_cursor
            && cursor.binding_digest() != Some(&request.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeServices cursor binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTasksPage {
    pub operation: ReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub tasks: Vec<TaskObservation>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

impl DescribeTasksPage {
    pub fn new(
        request: &DescribeTasksRequest,
        page_number: u16,
        tasks: Vec<TaskObservation>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> ModelResult<Self> {
        let mut value = Self {
            operation: ReadOperation::DescribeTasks,
            query_digest: request.query_digest(),
            page_number,
            tasks,
            next_cursor: None,
            response_bytes,
            provider_revision,
            page_digest: Digest::zero(),
        };
        value.page_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.query_digest,
            self.page_number,
            &self.tasks,
            self.response_bytes,
            &self.provider_revision,
        ))
    }

    pub fn validate_for(&self, request: &DescribeTasksRequest) -> ModelResult<()> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.tasks.len() > MAX_ITEMS_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > request.bounds.max_response_bytes
            || self.next_cursor.is_some()
        {
            return Err(ModelError::Invalid {
                field: "DescribeTasks page binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTaskDefinitionPage {
    pub operation: ReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub task_definition: TaskDefinitionObservation,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

impl DescribeTaskDefinitionPage {
    pub fn new(
        request: &DescribeTaskDefinitionRequest,
        page_number: u16,
        task_definition: TaskDefinitionObservation,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> ModelResult<Self> {
        let mut value = Self {
            operation: ReadOperation::DescribeTaskDefinition,
            query_digest: request.query_digest(),
            page_number,
            task_definition,
            response_bytes,
            provider_revision,
            page_digest: Digest::zero(),
        };
        value.page_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.query_digest,
            self.page_number,
            &self.task_definition,
            self.response_bytes,
            &self.provider_revision,
        ))
    }

    pub fn validate_for(&self, request: &DescribeTaskDefinitionRequest) -> ModelResult<()> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.response_bytes == 0
            || self.response_bytes > request.bounds.max_response_bytes
        {
            return Err(ModelError::Invalid {
                field: "DescribeTaskDefinition page binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTasksPage {
    pub operation: ReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub tasks: Vec<TaskObservation>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

impl ListTasksPage {
    pub fn new(
        request: &ListTasksRequest,
        page_number: u16,
        tasks: Vec<TaskObservation>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> ModelResult<Self> {
        let query_digest = request.query_digest();
        let next_cursor = bind_cursor(next_cursor, &query_digest, page_number + 1)?;
        let mut value = Self {
            operation: ReadOperation::ListTasks,
            query_digest,
            page_number,
            tasks,
            next_cursor,
            response_bytes,
            provider_revision,
            page_digest: Digest::zero(),
        };
        value.page_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.query_digest,
            self.page_number,
            &self.tasks,
            &self.next_cursor,
            self.response_bytes,
            &self.provider_revision,
        ))
    }

    pub fn validate_for(&self, request: &ListTasksRequest) -> ModelResult<()> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.tasks.len() > MAX_ITEMS_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
        {
            return Err(ModelError::Invalid {
                field: "ListTasks page binding",
            });
        }
        if let Some(cursor) = &self.next_cursor
            && cursor.binding_digest() != Some(&request.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "ListTasks cursor binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    AccessLoss,
    NotFound,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_non_adoptable(self) -> bool {
        !self.is_complete()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    RequestBudget,
    ItemBudget,
    ResponseTooLarge,
    CursorReplay,
    CursorBindingMismatch,
    DuplicateItem,
    StaleDeploymentGeneration,
    StaleTaskDefinitionRevision,
    UnknownLifecycleState,
    ProviderConflict,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
    pub retryable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn native(self) -> bool {
        false
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub requests_observed: u16,
    pub items_observed: usize,
    pub complete: bool,
    pub truncated: bool,
    pub cursor_digests: Vec<Digest>,
    pub filter_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub stopped_reasons_redacted: bool,
    pub raw_next_tokens_redacted: bool,
    pub raw_provider_payload_redacted: bool,
    pub task_definition_payload_redacted: bool,
    pub environment_values_redacted: bool,
    pub secret_material_redacted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_adopted: bool,
}

impl AuthorityBoundary {
    pub const fn layer_one() -> Self {
        Self {
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_receipt: false,
            kernel_authority: false,
            outcome_adopted: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub page_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsDeploymentEvidence {
    pub operation: ReadOperation,
    pub state: EvidenceState,
    pub services: Vec<ServiceObservation>,
    pub tasks: Vec<TaskObservation>,
    pub task_definition: Option<TaskDefinitionObservation>,
    pub pagination: PaginationEvidence,
    pub redaction: RedactionSummary,
    pub authority: AuthorityBoundary,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub digests: EvidenceDigests,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    operation: ReadOperation,
    state: EvidenceState,
    services: &'a [ServiceObservation],
    tasks: &'a [TaskObservation],
    task_definition: &'a Option<TaskDefinitionObservation>,
    pagination: &'a PaginationEvidence,
    redaction: &'a RedactionSummary,
    authority: &'a AuthorityBoundary,
    provider_errors: &'a [ProviderErrorEvidence],
    plugin_version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    scope_digest: &'a Digest,
    filter_digest: &'a Digest,
    cursor_digest: &'a Option<Digest>,
    page_digests: &'a [Digest],
}

impl EcsDeploymentEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: ReadOperation,
        state: EvidenceState,
        services: Vec<ServiceObservation>,
        tasks: Vec<TaskObservation>,
        task_definition: Option<TaskDefinitionObservation>,
        pagination: PaginationEvidence,
        provider_errors: Vec<ProviderErrorEvidence>,
        plugin_version_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        api_digest: Digest,
        provider_revision: ProviderRevision,
        permission_digest: Digest,
        consent_digest: Digest,
        scope_digest: Digest,
        filter_digest: Digest,
        cursor_digest: Option<Digest>,
        page_digests: Vec<Digest>,
    ) -> Self {
        let redaction = RedactionSummary {
            stopped_reasons_redacted: true,
            raw_next_tokens_redacted: true,
            raw_provider_payload_redacted: true,
            task_definition_payload_redacted: true,
            environment_values_redacted: true,
            secret_material_redacted: true,
        };
        let authority = AuthorityBoundary::layer_one();
        let digests = EvidenceDigests {
            plugin_version_digest,
            contract_digest,
            provider_digest,
            api_digest,
            provider_revision,
            permission_digest,
            consent_digest,
            scope_digest,
            filter_digest,
            cursor_digest,
            page_digests,
            evidence_digest: Digest::zero(),
        };
        let mut evidence = Self {
            operation,
            state,
            services,
            tasks,
            task_definition,
            pagination,
            redaction,
            authority,
            provider_errors,
            digests,
        };
        evidence.digests.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            operation: self.operation,
            state: self.state,
            services: &self.services,
            tasks: &self.tasks,
            task_definition: &self.task_definition,
            pagination: &self.pagination,
            redaction: &self.redaction,
            authority: &self.authority,
            provider_errors: &self.provider_errors,
            plugin_version_digest: &self.digests.plugin_version_digest,
            contract_digest: &self.digests.contract_digest,
            provider_digest: &self.digests.provider_digest,
            api_digest: &self.digests.api_digest,
            provider_revision: &self.digests.provider_revision,
            permission_digest: &self.digests.permission_digest,
            consent_digest: &self.digests.consent_digest,
            scope_digest: &self.digests.scope_digest,
            filter_digest: &self.digests.filter_digest,
            cursor_digest: &self.digests.cursor_digest,
            page_digests: &self.digests.page_digests,
        })
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.services.len() + self.tasks.len() > MAX_TASKS
            || self.pagination.pages_observed > MAX_PAGES
            || self.digests.evidence_digest != self.recomputed_digest()
            || self.authority.connected
            || self.authority.native
            || self.authority.first_party
            || self.authority.durable_receipt
            || self.authority.kernel_authority
            || self.authority.outcome_adopted
            || !self.redaction.stopped_reasons_redacted
            || !self.redaction.raw_next_tokens_redacted
            || !self.redaction.raw_provider_payload_redacted
            || !self.redaction.task_definition_payload_redacted
            || !self.redaction.environment_values_redacted
            || !self.redaction.secret_material_redacted
        {
            return Err(ModelError::Invalid {
                field: "ECS evidence digest or authority boundary",
            });
        }
        for service in &self.services {
            if service.observation_digest != service.recomputed_digest() {
                return Err(ModelError::InvalidDigest {
                    field: "service observation digest",
                });
            }
        }
        for task in &self.tasks {
            if task.observation_digest != task.recomputed_digest() {
                return Err(ModelError::InvalidDigest {
                    field: "task observation digest",
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

pub fn mission_projection(value: &MissionBinding) -> MissionProjection {
    MissionProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

pub fn project_projection(value: &ProjectBinding) -> ProjectProjection {
    ProjectProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

pub fn work_product_projection(value: &WorkProductBinding) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}
