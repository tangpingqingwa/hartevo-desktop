//! Exact AWS CodePipeline/Mission identities and bounded redacted models.
//!
//! Raw artifact bytes, raw error messages, raw logs, provider response bodies,
//! and credential material have no representation in this module. Values
//! which identify external resources are bound into digests and revisions.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    AwsCodePipelineReleaseError, AwsCodePipelineTransportError, MAX_ACTION_EXECUTIONS,
    MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_PIPELINE_EXECUTIONS, Result, digest_serialized,
    sha256_hex, validate_identifier, validate_revision, validate_text,
};

/// SHA-256 digest used for all external identity, request, and tamper fences.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if crate::valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsCodePipelineReleaseError::InvalidDigest { field: "digest" })
        }
    }

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(sha256_hex(value))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(64 + values.len() * 32);
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

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if crate::valid_digest(&self.0) {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::InvalidDigest { field: "digest" })
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! define_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-codepipeline-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $field)
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
                formatter.write_str(&self.0)
            }
        }
    };
}

define_identifier!(PipelineName, "pipelineName");
define_identifier!(ExecutionId, "executionId");
define_identifier!(StageName, "stageName");
define_identifier!(ActionName, "actionName");
define_identifier!(MissionId, "missionId");
define_identifier!(ProjectId, "projectId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(RegistrationId, "registrationId");

pub type PipelineId = PipelineName;
pub type StageId = StageName;
pub type ActionId = ActionName;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(AwsCodePipelineReleaseError::InvalidIdentifier { field: "accountId" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-codepipeline-account/v1", &[("value", self.0.clone())])
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAccountId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "region", 64, false)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(AwsCodePipelineReleaseError::InvalidIdentifier { field: "region" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-codepipeline-region/v1", &[("value", self.0.clone())])
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! define_revision_identity {
    ($name:ident, $value_type:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub value: $value_type,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(value: $value_type, revision: u64) -> Result<Self> {
                let revision = Revision::new(revision)?;
                value.validate()?;
                Ok(Self { value, revision })
            }

            pub fn as_str(&self) -> &str {
                self.value.as_str()
            }

            pub const fn revision(&self) -> Revision {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("value", self.value.as_str().to_owned()),
                        ("revision", self.revision.get().to_string()),
                    ],
                )
            }

            pub fn validate(&self) -> Result<()> {
                self.value.validate()?;
                validate_revision(self.revision.get(), $field)
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
    };
}

define_revision_identity!(
    AccountIdentity,
    AwsAccountId,
    "accountRevision",
    "aws-codepipeline-account-identity/v1"
);
define_revision_identity!(
    RegionIdentity,
    AwsRegion,
    "regionRevision",
    "aws-codepipeline-region-identity/v1"
);
define_revision_identity!(
    PipelineIdentity,
    PipelineName,
    "pipelineRevision",
    "aws-codepipeline-pipeline/v1"
);
define_revision_identity!(
    ExecutionIdentity,
    ExecutionId,
    "executionRevision",
    "aws-codepipeline-execution/v1"
);
define_revision_identity!(
    StageIdentity,
    StageName,
    "stageRevision",
    "aws-codepipeline-stage/v1"
);
define_revision_identity!(
    ActionIdentity,
    ActionName,
    "actionRevision",
    "aws-codepipeline-action/v1"
);
define_revision_identity!(
    MissionIdentity,
    MissionId,
    "missionRevision",
    "aws-codepipeline-mission/v1"
);
define_revision_identity!(
    ProjectIdentity,
    ProjectId,
    "projectRevision",
    "aws-codepipeline-project/v1"
);
define_revision_identity!(
    WorkProductIdentity,
    WorkProductId,
    "workProductRevision",
    "aws-codepipeline-work-product/v1"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: value.value.digest(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: value.value.digest(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(value: &WorkProductIdentity) -> Self {
        Self {
            id_digest: value.value.digest(),
            revision: value.revision,
        }
    }
}

/// Exact CodePipeline and Mission/Project/Work Product binding.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodePipelineScope {
    pub account: AccountIdentity,
    pub region: RegionIdentity,
    pub pipeline: PipelineIdentity,
    pub execution: ExecutionIdentity,
    pub stage: StageIdentity,
    pub action: ActionIdentity,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub work_product: WorkProductIdentity,
    pub scope_digest: Digest,
}

impl fmt::Debug for AwsCodePipelineScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodePipelineScope")
            .field("account", &self.account)
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("pipeline", &self.pipeline)
            .field("execution", &self.execution)
            .field("stage", &self.stage)
            .field("action", &self.action)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl AwsCodePipelineScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AccountIdentity,
        region: RegionIdentity,
        pipeline: PipelineIdentity,
        execution: ExecutionIdentity,
        stage: StageIdentity,
        action: ActionIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let mut scope = Self {
            account,
            region,
            pipeline,
            execution,
            stage,
            action,
            mission,
            project,
            work_product,
            scope_digest: Digest::from_text("unsealed-aws-codepipeline-scope"),
        };
        scope.validate_parts()?;
        scope.scope_digest = scope.calculate_digest();
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        account: impl Into<String>,
        account_revision: u64,
        region: impl Into<String>,
        region_revision: u64,
        pipeline: impl Into<String>,
        pipeline_revision: u64,
        execution: impl Into<String>,
        execution_revision: u64,
        stage: impl Into<String>,
        stage_revision: u64,
        action: impl Into<String>,
        action_revision: u64,
        mission: impl Into<String>,
        mission_revision: u64,
        project: impl Into<String>,
        project_revision: u64,
        work_product: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self> {
        Self::new(
            AccountIdentity::new(AwsAccountId::new(account)?, account_revision)?,
            RegionIdentity::new(AwsRegion::new(region)?, region_revision)?,
            PipelineIdentity::new(PipelineName::new(pipeline)?, pipeline_revision)?,
            ExecutionIdentity::new(ExecutionId::new(execution)?, execution_revision)?,
            StageIdentity::new(StageName::new(stage)?, stage_revision)?,
            ActionIdentity::new(ActionName::new(action)?, action_revision)?,
            MissionIdentity::new(MissionId::new(mission)?, mission_revision)?,
            ProjectIdentity::new(ProjectId::new(project)?, project_revision)?,
            WorkProductIdentity::new(WorkProductId::new(work_product)?, work_product_revision)?,
        )
    }

    pub fn account(&self) -> &AccountIdentity {
        &self.account
    }

    pub fn region(&self) -> &RegionIdentity {
        &self.region
    }

    pub fn pipeline(&self) -> &PipelineIdentity {
        &self.pipeline
    }

    pub fn execution(&self) -> &ExecutionIdentity {
        &self.execution
    }

    pub fn stage(&self) -> &StageIdentity {
        &self.stage
    }

    pub fn action(&self) -> &ActionIdentity {
        &self.action
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

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_parts()?;
        if self.scope_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::ScopeMismatch)
        }
    }

    fn validate_parts(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.pipeline.validate()?;
        self.execution.validate()?;
        self.stage.validate()?;
        self.action.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                ("execution", self.execution.digest().as_str().to_owned()),
                ("stage", self.stage.digest().as_str().to_owned()),
                ("action", self.action.digest().as_str().to_owned()),
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

/// SecretReference deliberately does not implement Serialize or Deserialize.
/// Only a digest and revision can cross a registration/evidence boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    SigV4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretStatus {
    Active,
    Revoked,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revision: Revision,
    status: SecretStatus,
}

impl SecretReference {
    pub fn sigv4(opaque_reference: impl AsRef<str>, revision: u64) -> Result<Self> {
        let opaque_reference = opaque_reference.as_ref();
        validate_text(
            opaque_reference,
            "sigv4 SecretReference",
            crate::MAX_SECRET_REFERENCE_BYTES,
            false,
        )?;
        Ok(Self {
            kind: SecretKind::SigV4,
            reference_digest: Digest::from_parts(
                "aws-codepipeline-sigv4-secret/v1",
                &[("opaque_reference", opaque_reference.to_owned())],
            ),
            revision: Revision::new(revision)?,
            status: SecretStatus::Active,
        })
    }

    pub fn new_sigv4(opaque_reference: impl AsRef<str>, revision: u64) -> Result<Self> {
        Self::sigv4(opaque_reference, revision)
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn is_revoked(&self) -> bool {
        matches!(self.status, SecretStatus::Revoked)
    }

    pub fn revoke(&mut self) {
        self.status = SecretStatus::Revoked;
    }

    pub fn restore(&mut self) {
        self.status = SecretStatus::Active;
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind != SecretKind::SigV4
            || self.reference_digest.validate().is_err()
            || self.revision.get() == 0
        {
            Err(AwsCodePipelineReleaseError::InvalidSecretReference)
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
            .field("revision", &self.revision)
            .field("reference_digest", &self.reference_digest)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub provider_revision: Revision,
    pub provider_release: String,
    pub api_revision: String,
    pub provider_digest: Digest,
}

pub type AwsCodePipelineProviderIdentity = ProviderIdentity;

impl ProviderIdentity {
    pub fn new(provider_revision: u64, provider_release: impl Into<String>) -> Result<Self> {
        let provider_release = provider_release.into();
        validate_text(&provider_release, "providerRelease", 128, false)?;
        let provider_revision = Revision::new(provider_revision)?;
        let mut identity = Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_revision,
            provider_release,
            api_revision: crate::PROVIDER_API_REVISION.to_owned(),
            provider_digest: Digest::from_text("unsealed-aws-codepipeline-provider"),
        };
        identity.provider_digest = identity.calculate_digest();
        Ok(identity)
    }

    pub fn layer_one() -> Self {
        Self::new(1, "recording-r1").expect("static provider identity is valid")
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != crate::PROVIDER_ID
            || self.api_revision != crate::PROVIDER_API_REVISION
            || self.provider_revision.get() == 0
            || self.provider_release.is_empty()
            || self.provider_digest != self.calculate_digest()
        {
            Err(AwsCodePipelineReleaseError::ProviderDrift)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-provider/v1",
            &[
                ("id", self.provider_id.clone()),
                ("revision", self.provider_revision.get().to_string()),
                ("release", self.provider_release.clone()),
                ("api", self.api_revision.clone()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    permissions: BTreeSet<String>,
    pub revision: Revision,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(permissions: I, revision: u64) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions.into_iter().map(Into::into).collect();
        let revision = Revision::new(revision)?;
        let mut snapshot = Self {
            permissions,
            revision,
            permission_digest: Digest::from_text("unsealed-aws-codepipeline-permissions"),
        };
        snapshot.permission_digest = snapshot.calculate_digest();
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read_only(revision: u64) -> Result<Self> {
        Self::new(
            [
                "codepipeline:GetPipelineState",
                "codepipeline:GetPipelineExecution",
                "codepipeline:ListPipelineExecutions",
                "codepipeline:ListActionExecutions",
                "mission.scope",
            ],
            revision,
        )
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self {
            permissions: self.permissions.clone(),
            revision: self.revision,
            permission_digest: self.calculate_digest(),
        };
        if self.permissions == expected.permissions
            && self.revision.get() != 0
            && self.permission_digest == expected.permission_digest
            && self.permissions
                == [
                    "codepipeline:GetPipelineExecution".to_owned(),
                    "codepipeline:GetPipelineState".to_owned(),
                    "codepipeline:ListActionExecutions".to_owned(),
                    "codepipeline:ListPipelineExecutions".to_owned(),
                    "mission.scope".to_owned(),
                ]
                .into_iter()
                .collect()
        {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::InvalidPermissionSnapshot)
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-permissions/v1",
            &[
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

/// Every Layer-1 transport is explicitly non-native and non-connected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn claims_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineExecutionStatus {
    Queued,
    InProgress,
    Succeeded,
    Failed,
    Stopped,
    Superseded,
    Canceled,
    Unknown,
}

impl PipelineExecutionStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Stopped | Self::Superseded | Self::Canceled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageExecutionStatus {
    NotStarted,
    InProgress,
    Succeeded,
    Failed,
    Skipped,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionExecutionStatus {
    Queued,
    InProgress,
    Succeeded,
    Failed,
    Abandoned,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryState {
    NotRetried,
    Retryable,
    Exhausted,
    SucceededAfterRetry,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Queued,
    InProgress,
    Succeeded,
    Failed,
    Stopped,
    Superseded,
    Canceled,
    Partial,
    Unknown,
    AccessLoss,
    Retryable,
    ExecutionReplaced,
    StageActionReplaced,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::Complete
                | Self::Succeeded
                | Self::Failed
                | Self::Stopped
                | Self::Superseded
                | Self::Canceled
        )
    }

    pub const fn is_partial(self) -> bool {
        matches!(
            self,
            Self::Partial
                | Self::Unknown
                | Self::AccessLoss
                | Self::Retryable
                | Self::ExecutionReplaced
                | Self::StageActionReplaced
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Client,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    Server,
    Timeout,
    AccessLoss,
    Partial,
    InvalidResponse,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub raw_artifact_content_retained: bool,
    pub raw_artifact_location_retained: bool,
    pub raw_error_message_retained: bool,
    pub raw_logs_retained: bool,
    pub redaction_digest: Digest,
}

impl RedactionEvidence {
    pub fn standard() -> Self {
        let mut evidence = Self {
            raw_artifact_content_retained: false,
            raw_artifact_location_retained: false,
            raw_error_message_retained: false,
            raw_logs_retained: false,
            redaction_digest: Digest::from_text("unsealed-aws-codepipeline-redaction"),
        };
        evidence.redaction_digest = evidence.calculate_digest();
        evidence
    }

    pub fn validate(&self) -> Result<()> {
        if self.raw_artifact_content_retained
            || self.raw_artifact_location_retained
            || self.raw_error_message_retained
            || self.raw_logs_retained
            || self.redaction_digest != self.calculate_digest()
        {
            Err(AwsCodePipelineReleaseError::RedactionViolation)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-redaction/v1",
            &[
                (
                    "artifact_content",
                    self.raw_artifact_content_retained.to_string(),
                ),
                (
                    "artifact_location",
                    self.raw_artifact_location_retained.to_string(),
                ),
                ("error_message", self.raw_error_message_retained.to_string()),
                ("logs", self.raw_logs_retained.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub artifact_name_digest: Digest,
    pub revision_digest: Option<Digest>,
    pub location_digest: Option<Digest>,
    pub size_bytes: Option<u64>,
    pub redaction: RedactionEvidence,
    pub metadata_digest: Digest,
}

impl ArtifactMetadata {
    pub fn from_values(
        artifact_name: impl AsRef<str>,
        revision: Option<impl AsRef<str>>,
        location: Option<impl AsRef<str>>,
        size_bytes: Option<u64>,
    ) -> Result<Self> {
        let artifact_name = artifact_name.as_ref();
        validate_text(artifact_name, "artifactName", MAX_IDENTIFIER_BYTES, true)?;
        let revision_digest = revision
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                validate_text(&value, "artifactRevision", MAX_IDENTIFIER_BYTES, true)?;
                Ok::<Digest, AwsCodePipelineReleaseError>(Digest::from_parts(
                    "aws-codepipeline-artifact-revision/v1",
                    &[("value", value)],
                ))
            })
            .transpose()?;
        let location_digest = location
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                validate_text(&value, "artifactLocation", MAX_IDENTIFIER_BYTES, true)?;
                Ok::<Digest, AwsCodePipelineReleaseError>(Digest::from_parts(
                    "aws-codepipeline-artifact-location/v1",
                    &[("value", value)],
                ))
            })
            .transpose()?;
        Self::from_digests(
            Digest::from_parts(
                "aws-codepipeline-artifact-name/v1",
                &[("value", artifact_name.to_owned())],
            ),
            revision_digest,
            location_digest,
            size_bytes,
        )
    }

    pub fn from_digests(
        artifact_name_digest: Digest,
        revision_digest: Option<Digest>,
        location_digest: Option<Digest>,
        size_bytes: Option<u64>,
    ) -> Result<Self> {
        artifact_name_digest.validate()?;
        if let Some(digest) = &revision_digest {
            digest.validate()?;
        }
        if let Some(digest) = &location_digest {
            digest.validate()?;
        }
        let mut metadata = Self {
            artifact_name_digest,
            revision_digest,
            location_digest,
            size_bytes,
            redaction: RedactionEvidence::standard(),
            metadata_digest: Digest::from_text("unsealed-aws-codepipeline-artifact"),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        Ok(metadata)
    }

    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::from_values(
            scope.action.as_str(),
            Some(scope.execution.as_str()),
            None::<&str>,
            Some(0),
        )
        .expect("bounded artifact fixture")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.artifact_name_digest.validate()?;
        if let Some(digest) = &self.revision_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.location_digest {
            digest.validate()?;
        }
        self.redaction.validate()?;
        if self.metadata_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-artifact-metadata/v1",
            &[
                ("name", self.artifact_name_digest.as_str().to_owned()),
                (
                    "revision",
                    self.revision_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "location",
                    self.location_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "size",
                    self.size_bytes
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorMetadata {
    pub category: ErrorCategory,
    pub status_code: Option<u16>,
    pub message_digest: Option<Digest>,
    pub redaction: RedactionEvidence,
    pub error_digest: Digest,
}

impl ErrorMetadata {
    pub fn from_values(
        category: ErrorCategory,
        status_code: Option<u16>,
        message: Option<impl AsRef<str>>,
    ) -> Result<Self> {
        let message_digest = message
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                validate_text(&value, "errorMessage", MAX_IDENTIFIER_BYTES, true)?;
                Ok::<Digest, AwsCodePipelineReleaseError>(Digest::from_parts(
                    "aws-codepipeline-error-message/v1",
                    &[("message", value)],
                ))
            })
            .transpose()?;
        Self::from_digests(category, status_code, message_digest)
    }

    pub fn from_digests(
        category: ErrorCategory,
        status_code: Option<u16>,
        message_digest: Option<Digest>,
    ) -> Result<Self> {
        if let Some(digest) = &message_digest {
            digest.validate()?;
        }
        let mut error = Self {
            category,
            status_code,
            message_digest,
            redaction: RedactionEvidence::standard(),
            error_digest: Digest::from_text("unsealed-aws-codepipeline-error"),
        };
        error.error_digest = error.calculate_digest();
        Ok(error)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if let Some(digest) = &self.message_digest {
            digest.validate()?;
        }
        self.redaction.validate()?;
        if self.error_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-error-metadata/v1",
            &[
                ("category", format!("{:?}", self.category)),
                (
                    "status",
                    self.status_code
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "message",
                    self.message_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryEvidence {
    pub state: RetryState,
    pub attempt: u8,
    pub max_retries: u8,
    pub retry_after_seconds: Option<u64>,
    pub reason_digest: Option<Digest>,
    pub retry_identity_digest: Digest,
}

impl RetryEvidence {
    pub fn none(request_digest: &Digest) -> Self {
        Self::new(RetryState::NotRetried, 0, None, None, request_digest)
    }

    pub fn retryable(
        attempt: u8,
        retry_after_seconds: Option<u64>,
        reason: &str,
        request_digest: &Digest,
    ) -> Self {
        Self::new(
            RetryState::Retryable,
            attempt,
            retry_after_seconds,
            Some(Digest::from_text(reason)),
            request_digest,
        )
    }

    pub fn exhausted(attempt: u8, reason: &str, request_digest: &Digest) -> Self {
        Self::new(
            RetryState::Exhausted,
            attempt,
            None,
            Some(Digest::from_text(reason)),
            request_digest,
        )
    }

    fn new(
        state: RetryState,
        attempt: u8,
        retry_after_seconds: Option<u64>,
        reason_digest: Option<Digest>,
        request_digest: &Digest,
    ) -> Self {
        let retry_identity_digest = Digest::from_parts(
            "aws-codepipeline-retry-identity/v1",
            &[
                ("request", request_digest.as_str().to_owned()),
                ("attempt", attempt.to_string()),
                ("state", format!("{state:?}")),
                (
                    "retry_after",
                    retry_after_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "reason",
                    reason_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        Self {
            state,
            attempt,
            max_retries: crate::MAX_RETRIES,
            retry_after_seconds,
            reason_digest,
            retry_identity_digest,
        }
    }

    pub fn validate(&self, request_digest: &Digest) -> Result<()> {
        if let Some(reason_digest) = &self.reason_digest {
            reason_digest.validate()?;
        }
        let expected = Self::new(
            self.state,
            self.attempt,
            self.retry_after_seconds,
            self.reason_digest.clone(),
            request_digest,
        );
        if self.retry_identity_digest == expected.retry_identity_digest
            && self.attempt <= self.max_retries.saturating_add(1)
            && self.max_retries == crate::MAX_RETRIES
        {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    GetPipelineState,
    GetPipelineExecution,
    ListPipelineExecutions,
    ListActionExecutions,
}

impl ReadOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetPipelineState => "GetPipelineState",
            Self::GetPipelineExecution => "GetPipelineExecution",
            Self::ListPipelineExecutions => "ListPipelineExecutions",
            Self::ListActionExecutions => "ListActionExecutions",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureMetadata {
    pub operation: ReadOperation,
    pub status_code: Option<u16>,
    pub category: ErrorCategory,
    pub retry_after_seconds: Option<u64>,
    pub diagnostic_digest: Digest,
    pub redaction: RedactionEvidence,
}

impl FailureMetadata {
    pub fn from_transport(operation: ReadOperation, error: &AwsCodePipelineTransportError) -> Self {
        let category = match error {
            AwsCodePipelineTransportError::BlockedEnv => ErrorCategory::BlockedEnv,
            AwsCodePipelineTransportError::ClientError { .. }
            | AwsCodePipelineTransportError::BadRequest => ErrorCategory::Client,
            AwsCodePipelineTransportError::Unauthorized => ErrorCategory::Unauthorized,
            AwsCodePipelineTransportError::Forbidden => ErrorCategory::Forbidden,
            AwsCodePipelineTransportError::NotFound => ErrorCategory::NotFound,
            AwsCodePipelineTransportError::Conflict => ErrorCategory::Conflict,
            AwsCodePipelineTransportError::RateLimited { .. } => ErrorCategory::Throttled,
            AwsCodePipelineTransportError::ServerError { .. } => ErrorCategory::Server,
            AwsCodePipelineTransportError::Timeout => ErrorCategory::Timeout,
            AwsCodePipelineTransportError::AccessLost => ErrorCategory::AccessLoss,
            AwsCodePipelineTransportError::Partial => ErrorCategory::Partial,
            AwsCodePipelineTransportError::InvalidResponse
            | AwsCodePipelineTransportError::Unavailable => ErrorCategory::InvalidResponse,
        };
        let retry_after_seconds = match error {
            AwsCodePipelineTransportError::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        };
        let diagnostic_digest = Digest::from_parts(
            "aws-codepipeline-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", format!("{category:?}")),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            operation,
            status_code: error.status_code(),
            category,
            retry_after_seconds,
            diagnostic_digest,
            redaction: RedactionEvidence::standard(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.diagnostic_digest.validate()?;
        self.redaction.validate()?;
        let expected = Self::from_transport(
            self.operation,
            &transport_for_metadata(self.category, self.status_code, self.retry_after_seconds),
        );
        if self.diagnostic_digest == expected.diagnostic_digest {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }
}

fn transport_for_metadata(
    category: ErrorCategory,
    status_code: Option<u16>,
    retry_after_seconds: Option<u64>,
) -> AwsCodePipelineTransportError {
    match category {
        ErrorCategory::BlockedEnv => AwsCodePipelineTransportError::BlockedEnv,
        ErrorCategory::Client => status_code
            .map_or(AwsCodePipelineTransportError::BadRequest, |status| {
                AwsCodePipelineTransportError::ClientError { status }
            }),
        ErrorCategory::Unauthorized => AwsCodePipelineTransportError::Unauthorized,
        ErrorCategory::Forbidden => AwsCodePipelineTransportError::Forbidden,
        ErrorCategory::NotFound => AwsCodePipelineTransportError::NotFound,
        ErrorCategory::Conflict => AwsCodePipelineTransportError::Conflict,
        ErrorCategory::Throttled => AwsCodePipelineTransportError::RateLimited {
            retry_after_seconds,
        },
        ErrorCategory::Server => AwsCodePipelineTransportError::ServerError {
            status: status_code.unwrap_or(500),
        },
        ErrorCategory::Timeout => AwsCodePipelineTransportError::Timeout,
        ErrorCategory::AccessLoss => AwsCodePipelineTransportError::AccessLost,
        ErrorCategory::Partial => AwsCodePipelineTransportError::Partial,
        ErrorCategory::InvalidResponse | ErrorCategory::Unknown => {
            AwsCodePipelineTransportError::InvalidResponse
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineStateRecord {
    pub pipeline: PipelineIdentity,
    pub execution: ExecutionIdentity,
    pub stage: StageIdentity,
    pub action: ActionIdentity,
    pub execution_status: PipelineExecutionStatus,
    pub stage_status: StageExecutionStatus,
    pub action_status: ActionExecutionStatus,
    pub artifacts: Vec<ArtifactMetadata>,
    pub error: Option<ErrorMetadata>,
    pub observed_at: u64,
    pub record_digest: Digest,
}

impl PipelineStateRecord {
    pub fn new(
        scope: &AwsCodePipelineScope,
        execution_status: PipelineExecutionStatus,
        stage_status: StageExecutionStatus,
        action_status: ActionExecutionStatus,
        artifacts: Vec<ArtifactMetadata>,
        error: Option<ErrorMetadata>,
        observed_at: u64,
    ) -> Result<Self> {
        if artifacts.len() > 64 {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        let mut record = Self {
            pipeline: scope.pipeline.clone(),
            execution: scope.execution.clone(),
            stage: scope.stage.clone(),
            action: scope.action.clone(),
            execution_status,
            stage_status,
            action_status,
            artifacts,
            error,
            observed_at,
            record_digest: Digest::from_text("unsealed-aws-codepipeline-state"),
        };
        record.record_digest = record.calculate_digest();
        record.validate_integrity()?;
        Ok(record)
    }

    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::new(
            scope,
            PipelineExecutionStatus::Succeeded,
            StageExecutionStatus::Succeeded,
            ActionExecutionStatus::Succeeded,
            vec![ArtifactMetadata::for_scope(scope)],
            None,
            1_744_550_400,
        )
        .expect("bounded pipeline state fixture")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.pipeline.validate()?;
        self.execution.validate()?;
        self.stage.validate()?;
        self.action.validate()?;
        for artifact in &self.artifacts {
            artifact.validate_integrity()?;
        }
        if let Some(error) = &self.error {
            error.validate_integrity()?;
        }
        if self.artifacts.len() <= 64 && self.record_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    pub fn matches_scope(&self, scope: &AwsCodePipelineScope) -> bool {
        self.pipeline == scope.pipeline
            && self.execution == scope.execution
            && self.stage == scope.stage
            && self.action == scope.action
    }

    pub fn transition_from(&self, previous: &Self) -> Result<StageActionTransition> {
        self.validate_integrity()?;
        previous.validate_integrity()?;
        if self.pipeline != previous.pipeline || self.execution != previous.execution {
            return Err(AwsCodePipelineReleaseError::ExecutionReplaced);
        }
        if self.stage != previous.stage || self.action != previous.action {
            return Err(AwsCodePipelineReleaseError::StageActionReplaced);
        }
        let kind = if self.action_status != previous.action_status {
            StageActionTransitionKind::ActionAdvanced
        } else if self.stage_status != previous.stage_status {
            StageActionTransitionKind::StageAdvanced
        } else if self.execution_status != previous.execution_status {
            StageActionTransitionKind::ExecutionAdvanced
        } else {
            StageActionTransitionKind::Stable
        };
        Ok(StageActionTransition {
            kind,
            previous_digest: previous.record_digest.clone(),
            current_digest: self.record_digest.clone(),
        })
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-state-record/v1",
            &[
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                ("execution", self.execution.digest().as_str().to_owned()),
                ("stage", self.stage.digest().as_str().to_owned()),
                ("action", self.action.digest().as_str().to_owned()),
                ("execution_status", format!("{:?}", self.execution_status)),
                ("stage_status", format!("{:?}", self.stage_status)),
                ("action_status", format!("{:?}", self.action_status)),
                (
                    "artifacts",
                    serde_json::to_string(&self.artifacts)
                        .expect("bounded artifact metadata serializes"),
                ),
                (
                    "error",
                    self.error.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("bounded error metadata serializes")
                    }),
                ),
                ("observed_at", self.observed_at.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineExecutionRecord {
    pub pipeline: PipelineIdentity,
    pub execution: ExecutionIdentity,
    pub status: PipelineExecutionStatus,
    pub artifacts: Vec<ArtifactMetadata>,
    pub error: Option<ErrorMetadata>,
    pub observed_at: u64,
    pub record_digest: Digest,
}

impl PipelineExecutionRecord {
    pub fn new(
        scope: &AwsCodePipelineScope,
        status: PipelineExecutionStatus,
        artifacts: Vec<ArtifactMetadata>,
        error: Option<ErrorMetadata>,
        observed_at: u64,
    ) -> Result<Self> {
        if artifacts.len() > 64 {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        let mut record = Self {
            pipeline: scope.pipeline.clone(),
            execution: scope.execution.clone(),
            status,
            artifacts,
            error,
            observed_at,
            record_digest: Digest::from_text("unsealed-aws-codepipeline-execution"),
        };
        record.record_digest = record.calculate_digest();
        record.validate_integrity()?;
        Ok(record)
    }

    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::new(
            scope,
            PipelineExecutionStatus::Succeeded,
            vec![ArtifactMetadata::for_scope(scope)],
            None,
            1_744_550_400,
        )
        .expect("bounded execution fixture")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.pipeline.validate()?;
        self.execution.validate()?;
        for artifact in &self.artifacts {
            artifact.validate_integrity()?;
        }
        if let Some(error) = &self.error {
            error.validate_integrity()?;
        }
        if self.artifacts.len() <= 64 && self.record_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    pub fn matches_pipeline(&self, scope: &AwsCodePipelineScope) -> bool {
        self.pipeline == scope.pipeline
    }

    pub fn matches_execution(&self, scope: &AwsCodePipelineScope) -> bool {
        self.matches_pipeline(scope) && self.execution == scope.execution
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-execution-record/v1",
            &[
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                ("execution", self.execution.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "artifacts",
                    serde_json::to_string(&self.artifacts)
                        .expect("bounded artifact metadata serializes"),
                ),
                (
                    "error",
                    self.error.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("bounded error metadata serializes")
                    }),
                ),
                ("observed_at", self.observed_at.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionExecutionRecord {
    pub pipeline: PipelineIdentity,
    pub execution: ExecutionIdentity,
    pub stage: StageIdentity,
    pub action: ActionIdentity,
    pub status: ActionExecutionStatus,
    pub retry_state: RetryState,
    pub artifacts: Vec<ArtifactMetadata>,
    pub error: Option<ErrorMetadata>,
    pub observed_at: u64,
    pub record_digest: Digest,
}

impl ActionExecutionRecord {
    pub fn new(
        scope: &AwsCodePipelineScope,
        status: ActionExecutionStatus,
        retry_state: RetryState,
        artifacts: Vec<ArtifactMetadata>,
        error: Option<ErrorMetadata>,
        observed_at: u64,
    ) -> Result<Self> {
        if artifacts.len() > 64 {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        let mut record = Self {
            pipeline: scope.pipeline.clone(),
            execution: scope.execution.clone(),
            stage: scope.stage.clone(),
            action: scope.action.clone(),
            status,
            retry_state,
            artifacts,
            error,
            observed_at,
            record_digest: Digest::from_text("unsealed-aws-codepipeline-action"),
        };
        record.record_digest = record.calculate_digest();
        record.validate_integrity()?;
        Ok(record)
    }

    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::new(
            scope,
            ActionExecutionStatus::Succeeded,
            RetryState::NotRetried,
            vec![ArtifactMetadata::for_scope(scope)],
            None,
            1_744_550_400,
        )
        .expect("bounded action fixture")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.pipeline.validate()?;
        self.execution.validate()?;
        self.stage.validate()?;
        self.action.validate()?;
        for artifact in &self.artifacts {
            artifact.validate_integrity()?;
        }
        if let Some(error) = &self.error {
            error.validate_integrity()?;
        }
        if self.artifacts.len() <= 64 && self.record_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    pub fn matches_scope(&self, scope: &AwsCodePipelineScope) -> bool {
        self.pipeline == scope.pipeline
            && self.execution == scope.execution
            && self.stage == scope.stage
            && self.action == scope.action
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-action-record/v1",
            &[
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                ("execution", self.execution.digest().as_str().to_owned()),
                ("stage", self.stage.digest().as_str().to_owned()),
                ("action", self.action.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("retry", format!("{:?}", self.retry_state)),
                (
                    "artifacts",
                    serde_json::to_string(&self.artifacts)
                        .expect("bounded artifact metadata serializes"),
                ),
                (
                    "error",
                    self.error.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("bounded error metadata serializes")
                    }),
                ),
                ("observed_at", self.observed_at.to_string()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageActionTransitionKind {
    Stable,
    ExecutionAdvanced,
    StageAdvanced,
    ActionAdvanced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageActionTransition {
    pub kind: StageActionTransitionKind,
    pub previous_digest: Digest,
    pub current_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PipelineExecutionFilter {
    pub pipeline_digest: Digest,
    pub pipeline_revision: Revision,
    pub target_execution_digest: Option<Digest>,
    pub status: Option<PipelineExecutionStatus>,
    pub filter_digest: Digest,
}

impl PipelineExecutionFilter {
    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::new(scope.pipeline.clone(), Some(scope.execution.digest()), None)
            .expect("scope filter is valid")
    }

    pub fn for_pipeline(scope: &AwsCodePipelineScope) -> Self {
        Self::new(scope.pipeline.clone(), None, None).expect("pipeline filter is valid")
    }

    pub fn new(
        pipeline: PipelineIdentity,
        target_execution_digest: Option<Digest>,
        status: Option<PipelineExecutionStatus>,
    ) -> Result<Self> {
        pipeline.validate()?;
        if let Some(digest) = &target_execution_digest {
            digest.validate()?;
        }
        let mut filter = Self {
            pipeline_digest: pipeline.digest(),
            pipeline_revision: pipeline.revision(),
            target_execution_digest,
            status,
            filter_digest: Digest::from_text("unsealed-aws-codepipeline-execution-filter"),
        };
        filter.filter_digest = filter.calculate_digest();
        Ok(filter)
    }

    pub fn digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn validate_against(&self, scope: &AwsCodePipelineScope) -> Result<()> {
        if self.pipeline_digest != scope.pipeline.digest()
            || self.pipeline_revision != scope.pipeline.revision()
            || self
                .target_execution_digest
                .as_ref()
                .is_some_and(|value| value != &scope.execution.digest())
            || self.filter_digest != self.calculate_digest()
        {
            Err(AwsCodePipelineReleaseError::FilterMismatch)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-execution-filter/v1",
            &[
                ("pipeline", self.pipeline_digest.as_str().to_owned()),
                ("revision", self.pipeline_revision.get().to_string()),
                (
                    "execution",
                    self.target_execution_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "status",
                    self.status
                        .map_or_else(String::new, |value| format!("{value:?}")),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionExecutionFilter {
    pub pipeline_digest: Digest,
    pub execution_digest: Digest,
    pub stage_digest: Digest,
    pub action_digest: Digest,
    pub filter_digest: Digest,
}

impl ActionExecutionFilter {
    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        let mut filter = Self {
            pipeline_digest: scope.pipeline.digest(),
            execution_digest: scope.execution.digest(),
            stage_digest: scope.stage.digest(),
            action_digest: scope.action.digest(),
            filter_digest: Digest::from_text("unsealed-aws-codepipeline-action-filter"),
        };
        filter.filter_digest = filter.calculate_digest();
        filter
    }

    pub fn digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn validate_against(&self, scope: &AwsCodePipelineScope) -> Result<()> {
        if self.pipeline_digest != scope.pipeline.digest()
            || self.execution_digest != scope.execution.digest()
            || self.stage_digest != scope.stage.digest()
            || self.action_digest != scope.action.digest()
            || self.filter_digest != self.calculate_digest()
        {
            Err(AwsCodePipelineReleaseError::FilterMismatch)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-action-filter/v1",
            &[
                ("pipeline", self.pipeline_digest.as_str().to_owned()),
                ("execution", self.execution_digest.as_str().to_owned()),
                ("stage", self.stage_digest.as_str().to_owned()),
                ("action", self.action_digest.as_str().to_owned()),
            ],
        )
    }
}

/// A provider cursor stores only a digest of the opaque token and its filter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cursor {
    pub token_digest: Digest,
    pub filter_digest: Digest,
}

impl Cursor {
    pub fn new(token: impl AsRef<str>, filter_digest: Digest) -> Result<Self> {
        let token = token.as_ref();
        validate_text(token, "cursor", MAX_CURSOR_BYTES, false)?;
        filter_digest.validate()?;
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-codepipeline-cursor-token/v1",
                &[("token", token.to_owned())],
            ),
            filter_digest,
        })
    }

    pub fn for_filter(token: impl AsRef<str>, filter: &PipelineExecutionFilter) -> Result<Self> {
        Self::new(token, filter.filter_digest.clone())
    }

    pub fn for_action_filter(
        token: impl AsRef<str>,
        filter: &ActionExecutionFilter,
    ) -> Result<Self> {
        Self::new(token, filter.filter_digest.clone())
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn validate_for(&self, filter_digest: &Digest) -> Result<()> {
        self.token_digest.validate()?;
        filter_digest.validate()?;
        if &self.filter_digest == filter_digest {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::CursorMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineExecutionsProjection {
    pub executions: Vec<PipelineExecutionRecord>,
    pub pages_read: u16,
    pub complete: bool,
    pub truncated: bool,
    pub cursor_digest: Option<Digest>,
    pub projection_digest: Digest,
}

impl PipelineExecutionsProjection {
    pub fn new(
        executions: Vec<PipelineExecutionRecord>,
        pages_read: u16,
        complete: bool,
        truncated: bool,
        cursor_digest: Option<Digest>,
    ) -> Result<Self> {
        if pages_read == 0
            || pages_read as usize > crate::MAX_PAGES
            || executions.len() > MAX_PIPELINE_EXECUTIONS
        {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        if let Some(digest) = &cursor_digest {
            digest.validate()?;
        }
        for execution in &executions {
            execution.validate_integrity()?;
        }
        let mut projection = Self {
            executions,
            pages_read,
            complete,
            truncated,
            cursor_digest,
            projection_digest: Digest::from_text("unsealed-aws-codepipeline-executions"),
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.pages_read == 0
            || self.pages_read as usize > crate::MAX_PAGES
            || self.executions.len() > MAX_PIPELINE_EXECUTIONS
        {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        for execution in &self.executions {
            execution.validate_integrity()?;
        }
        if self.projection_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-executions-projection/v1",
            &[
                (
                    "executions",
                    self.executions
                        .iter()
                        .map(|value| value.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_read.to_string()),
                ("complete", self.complete.to_string()),
                ("truncated", self.truncated.to_string()),
                (
                    "cursor",
                    self.cursor_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionExecutionsProjection {
    pub actions: Vec<ActionExecutionRecord>,
    pub pages_read: u16,
    pub complete: bool,
    pub truncated: bool,
    pub cursor_digest: Option<Digest>,
    pub projection_digest: Digest,
}

impl ActionExecutionsProjection {
    pub fn new(
        actions: Vec<ActionExecutionRecord>,
        pages_read: u16,
        complete: bool,
        truncated: bool,
        cursor_digest: Option<Digest>,
    ) -> Result<Self> {
        if pages_read == 0
            || pages_read as usize > crate::MAX_PAGES
            || actions.len() > MAX_ACTION_EXECUTIONS
        {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        if let Some(digest) = &cursor_digest {
            digest.validate()?;
        }
        for action in &actions {
            action.validate_integrity()?;
        }
        let mut projection = Self {
            actions,
            pages_read,
            complete,
            truncated,
            cursor_digest,
            projection_digest: Digest::from_text("unsealed-aws-codepipeline-actions"),
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.pages_read == 0
            || self.pages_read as usize > crate::MAX_PAGES
            || self.actions.len() > MAX_ACTION_EXECUTIONS
        {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        for action in &self.actions {
            action.validate_integrity()?;
        }
        if self.projection_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-actions-projection/v1",
            &[
                (
                    "actions",
                    self.actions
                        .iter()
                        .map(|value| value.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_read.to_string()),
                ("complete", self.complete.to_string()),
                ("truncated", self.truncated.to_string()),
                (
                    "cursor",
                    self.cursor_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}
