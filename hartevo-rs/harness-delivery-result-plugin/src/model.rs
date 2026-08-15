use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{HarnessDeliveryResultError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_METADATA_ITEMS};

pub const MAX_COMMIT_BYTES: usize = 256;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
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
            Err(HarnessDeliveryResultError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(HarnessDeliveryResultError::InvalidDigest)
        }
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

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_commit(value: &str) -> bool {
    valid_text(value, MAX_COMMIT_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        })
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(HarnessDeliveryResultError::InvalidIdentifier { field: $field })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("harness-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            #[must_use]
            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.0) {
                    Ok(())
                } else {
                    Err(HarnessDeliveryResultError::InvalidIdentifier { field: $field })
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
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.redacted())
            }
        }
    };
}

redacted_identifier!(HarnessAccountId, "account");
redacted_identifier!(HarnessOrgId, "org");
redacted_identifier!(HarnessProjectId, "project");
redacted_identifier!(HarnessPipelineId, "pipeline");
redacted_identifier!(HarnessExecutionId, "execution");
redacted_identifier!(HarnessStageId, "stage");
redacted_identifier!(HarnessServiceId, "service");
redacted_identifier!(HarnessEnvironmentId, "environment");
redacted_identifier!(HarnessDeploymentId, "deployment");

pub type AccountId = HarnessAccountId;
pub type OrgId = HarnessOrgId;
pub type PipelineId = HarnessPipelineId;
pub type ExecutionId = HarnessExecutionId;
pub type StageId = HarnessStageId;
pub type ServiceId = HarnessServiceId;
pub type EnvironmentId = HarnessEnvironmentId;
pub type DeploymentId = HarnessDeploymentId;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitReference(String);

impl CommitReference {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_commit(&value) {
            Ok(Self(value))
        } else {
            Err(HarnessDeliveryResultError::InvalidText { field: "commit" })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts("harness-commit/v1", &[("value", self.0.clone())])
    }
}

impl fmt::Debug for CommitReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CommitReference")
            .field(&format!("commit:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

impl Serialize for CommitReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.digest().serialize(serializer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    id_digest: Digest,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id) || revision == 0 {
            return Err(HarnessDeliveryResultError::InvalidScope);
        }
        Ok(Self {
            id_digest: Digest::from_parts("harness-mission/v1", &[("id", id)]),
            revision,
        })
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "harness-mission-binding/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    id_digest: Digest,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id) || revision == 0 {
            return Err(HarnessDeliveryResultError::InvalidScope);
        }
        Ok(Self {
            id_digest: Digest::from_parts("hartevo-project/v1", &[("id", id)]),
            revision,
        })
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-project-binding/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductIdentity {
    id_digest: Digest,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id) || revision == 0 {
            return Err(HarnessDeliveryResultError::InvalidScope);
        }
        Ok(Self {
            id_digest: Digest::from_parts("hartevo-work-product/v1", &[("id", id)]),
            revision,
        })
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-work-product-binding/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

pub type MissionBinding = MissionIdentity;
pub type ProjectBinding = ProjectIdentity;
pub type WorkProductBinding = WorkProductIdentity;
pub type MissionProjection = MissionIdentity;
pub type ProjectProjection = ProjectIdentity;
pub type WorkProductProjection = WorkProductIdentity;

#[derive(Clone, Eq, PartialEq)]
pub struct HarnessDeliveryScope {
    account: HarnessAccountId,
    org: HarnessOrgId,
    harness_project: HarnessProjectId,
    pipeline: HarnessPipelineId,
    execution: Option<HarnessExecutionId>,
    stage: Option<HarnessStageId>,
    service: Option<HarnessServiceId>,
    environment: Option<HarnessEnvironmentId>,
    commit: Option<CommitReference>,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl HarnessDeliveryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: HarnessAccountId,
        org: HarnessOrgId,
        harness_project: HarnessProjectId,
        pipeline: HarnessPipelineId,
        execution: Option<HarnessExecutionId>,
        stage: Option<HarnessStageId>,
        service: Option<HarnessServiceId>,
        environment: Option<HarnessEnvironmentId>,
        commit: Option<CommitReference>,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            org,
            harness_project,
            pipeline,
            execution,
            stage,
            service,
            environment,
            commit,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_pipeline(
        account: HarnessAccountId,
        org: HarnessOrgId,
        harness_project: HarnessProjectId,
        pipeline: HarnessPipelineId,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        Self::new(
            account,
            org,
            harness_project,
            pipeline,
            None,
            None,
            None,
            None,
            None,
            mission,
            project,
            work_product,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        account: impl Into<String>,
        org: impl Into<String>,
        harness_project: impl Into<String>,
        pipeline: impl Into<String>,
        execution: Option<String>,
        stage: Option<String>,
        service: Option<String>,
        environment: Option<String>,
        commit: Option<String>,
        mission: impl Into<String>,
        mission_revision: u64,
        project: impl Into<String>,
        project_revision: u64,
        work_product: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self> {
        Self::new(
            HarnessAccountId::new(account)?,
            HarnessOrgId::new(org)?,
            HarnessProjectId::new(harness_project)?,
            HarnessPipelineId::new(pipeline)?,
            execution.map(HarnessExecutionId::new).transpose()?,
            stage.map(HarnessStageId::new).transpose()?,
            service.map(HarnessServiceId::new).transpose()?,
            environment.map(HarnessEnvironmentId::new).transpose()?,
            commit.map(CommitReference::new).transpose()?,
            MissionIdentity::new(mission, mission_revision)?,
            ProjectIdentity::new(project, project_revision)?,
            WorkProductIdentity::new(work_product, work_product_revision)?,
        )
    }

    pub fn with_execution(
        &self,
        execution: HarnessExecutionId,
        stage: Option<HarnessStageId>,
        service: Option<HarnessServiceId>,
        environment: Option<HarnessEnvironmentId>,
        commit: Option<CommitReference>,
    ) -> Result<Self> {
        Self::new(
            self.account.clone(),
            self.org.clone(),
            self.harness_project.clone(),
            self.pipeline.clone(),
            Some(execution),
            stage,
            service,
            environment,
            commit,
            self.mission.clone(),
            self.project.clone(),
            self.work_product.clone(),
        )
    }

    #[must_use]
    pub fn account(&self) -> &HarnessAccountId {
        &self.account
    }

    #[must_use]
    pub fn org(&self) -> &HarnessOrgId {
        &self.org
    }

    #[must_use]
    pub fn harness_project(&self) -> &HarnessProjectId {
        &self.harness_project
    }

    #[must_use]
    pub fn pipeline(&self) -> &HarnessPipelineId {
        &self.pipeline
    }

    #[must_use]
    pub fn execution(&self) -> Option<&HarnessExecutionId> {
        self.execution.as_ref()
    }

    #[must_use]
    pub fn stage(&self) -> Option<&HarnessStageId> {
        self.stage.as_ref()
    }

    #[must_use]
    pub fn service(&self) -> Option<&HarnessServiceId> {
        self.service.as_ref()
    }

    #[must_use]
    pub fn environment(&self) -> Option<&HarnessEnvironmentId> {
        self.environment.as_ref()
    }

    #[must_use]
    pub fn commit(&self) -> Option<&CommitReference> {
        self.commit.as_ref()
    }

    #[must_use]
    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    #[must_use]
    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "harness-delivery-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("org", self.org.digest().as_str().to_owned()),
                (
                    "harness_project",
                    self.harness_project.digest().as_str().to_owned(),
                ),
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                (
                    "execution",
                    self.execution
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "stage",
                    self.stage
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "service",
                    self.service
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "environment",
                    self.environment
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "commit",
                    self.commit
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.org.validate()?;
        self.harness_project.validate()?;
        self.pipeline.validate()?;
        self.execution
            .as_ref()
            .map(HarnessExecutionId::validate)
            .transpose()?;
        self.stage
            .as_ref()
            .map(HarnessStageId::validate)
            .transpose()?;
        self.service
            .as_ref()
            .map(HarnessServiceId::validate)
            .transpose()?;
        self.environment
            .as_ref()
            .map(HarnessEnvironmentId::validate)
            .transpose()?;
        self.commit
            .as_ref()
            .map(|value| {
                if valid_commit(value.as_str()) {
                    Ok(())
                } else {
                    Err(HarnessDeliveryResultError::InvalidText { field: "commit" })
                }
            })
            .transpose()?;
        if self.stage.is_some() && self.execution.is_none() {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for HarnessDeliveryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessDeliveryScope")
            .field("digest", &self.digest())
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
}

/// A non-serializing, digest-only reference to Layer-2 API-key material.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_digest: Digest,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_reference: impl Into<String>, revision: u64) -> Result<Self> {
        let mut opaque_reference = opaque_reference.into();
        if !valid_text(&opaque_reference, MAX_IDENTIFIER_BYTES, false) || revision == 0 {
            opaque_reference.zeroize();
            return Err(HarnessDeliveryResultError::InvalidSecretReference);
        }
        let opaque_digest = Digest::from_parts(
            "harness-api-key-reference/v1",
            &[
                ("kind", "api_key".to_owned()),
                ("opaque_reference", opaque_reference.clone()),
                ("revision", revision.to_string()),
            ],
        );
        opaque_reference.zeroize();
        let mut reference = Self {
            kind: SecretKind::ApiKey,
            opaque_digest: opaque_digest.clone(),
            reference_digest: opaque_digest,
            scope_digest: Digest::from_text("unbound-harness-secret-scope"),
            revision,
            revoked: false,
        };
        reference.reference_digest = reference.calculate_digest();
        Ok(reference)
    }

    pub fn api_key(
        opaque_reference: impl Into<String>,
        scope: &HarnessDeliveryScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_reference, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = reference.calculate_digest();
        Ok(reference)
    }

    pub fn new_api_key(
        opaque_reference: impl Into<String>,
        scope: &HarnessDeliveryScope,
        revision: u64,
    ) -> Result<Self> {
        Self::api_key(opaque_reference, scope, revision)
    }

    pub fn opaque_api_key(opaque_reference: impl Into<String>) -> Result<Self> {
        Self::new(opaque_reference, 1)
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(HarnessDeliveryResultError::InvalidSecretReference);
        }
        self.revoked = true;
        self.reference_digest = self.calculate_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        if !self.revoked {
            return Err(HarnessDeliveryResultError::InvalidSecretReference);
        }
        self.revoked = false;
        self.reference_digest = self.calculate_digest();
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "harness-api-key-reference-bound/v1",
            &[
                ("kind", format!("{:?}", self.kind)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("reference", self.opaque_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &HarnessDeliveryScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::ApiKey)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
            || self.reference_digest != self.calculate_digest()
        {
            return Err(HarnessDeliveryResultError::InvalidSecretReference);
        }
        self.opaque_digest.validate()?;
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    permissions: BTreeSet<String>,
    digest: Digest,
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
            || permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(HarnessDeliveryResultError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "harness-permissions/v1",
            &[
                ("revision", revision.to_string()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join("\n"),
                ),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self::new(revision, LAYER1_PERMISSIONS.iter().copied()).expect("static Layer-1 permissions")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.digest
                != Digest::from_parts(
                    "harness-permissions/v1",
                    &[
                        ("revision", self.revision.to_string()),
                        (
                            "permissions",
                            self.permissions
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join("\n"),
                        ),
                    ],
                )
        {
            return Err(HarnessDeliveryResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    id_digest: Digest,
    revision: u64,
    expires_at: DateTime<Utc>,
    permissions: BTreeSet<String>,
    revoked: bool,
    digest: Digest,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.into();
        if !valid_identifier(&id) || revision == 0 {
            return Err(HarnessDeliveryResultError::InvalidConsent);
        }
        let permission_snapshot = PermissionSnapshot::new(revision, permissions)?;
        let permissions = permission_snapshot.permissions.clone();
        let id_digest = Digest::from_parts("harness-consent-id/v1", &[("id", id)]);
        let digest = consent_digest(&id_digest, revision, expires_at, &permissions, false);
        Ok(Self {
            id_digest,
            revision,
            expires_at,
            permissions,
            revoked: false,
            digest,
        })
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS.iter().copied(), expires_at)
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn is_active_at(&self, observed_at: DateTime<Utc>) -> bool {
        !self.revoked && observed_at <= self.expires_at
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(HarnessDeliveryResultError::ConsentRevoked);
        }
        self.revoked = true;
        self.digest = consent_digest(
            &self.id_digest,
            self.revision,
            self.expires_at,
            &self.permissions,
            self.revoked,
        );
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.digest
                != consent_digest(
                    &self.id_digest,
                    self.revision,
                    self.expires_at,
                    &self.permissions,
                    self.revoked,
                )
        {
            return Err(HarnessDeliveryResultError::InvalidConsent);
        }
        Ok(())
    }
}

fn consent_digest(
    id_digest: &Digest,
    revision: u64,
    expires_at: DateTime<Utc>,
    permissions: &BTreeSet<String>,
    revoked: bool,
) -> Digest {
    Digest::from_parts(
        "harness-consent/v1",
        &[
            ("id", id_digest.as_str().to_owned()),
            ("revision", revision.to_string()),
            ("expires_at", expires_at.to_rfc3339()),
            (
                "permissions",
                permissions.iter().cloned().collect::<Vec<_>>().join("\n"),
            ),
            ("revoked", revoked.to_string()),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessRunStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessEvidenceState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    BlockedEnv,
    Tampered,
    AccessLoss,
    RegistrationRevoked,
}

pub type DeliveryEvidenceState = HarnessEvidenceState;

impl HarnessEvidenceState {
    #[must_use]
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    #[must_use]
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueCursor {
    scope_digest: Digest,
    request_digest: Digest,
    page: u16,
    token_digest: Digest,
}

impl OpaqueCursor {
    pub fn new(
        opaque_token: impl Into<String>,
        scope: &HarnessDeliveryScope,
        request_digest: Digest,
        page: u16,
    ) -> Result<Self> {
        let mut opaque_token = opaque_token.into();
        if !valid_text(&opaque_token, MAX_IDENTIFIER_BYTES, false)
            || page == 0
            || request_digest.validate().is_err()
        {
            opaque_token.zeroize();
            return Err(HarnessDeliveryResultError::InvalidRequest);
        }
        let token_digest = Digest::from_parts(
            "harness-opaque-cursor-token/v1",
            &[("token", opaque_token.clone())],
        );
        opaque_token.zeroize();
        Ok(Self {
            scope_digest: scope.digest(),
            request_digest,
            page,
            token_digest,
        })
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub const fn page(&self) -> u16 {
        self.page
    }

    #[must_use]
    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub(crate) fn validate_against(
        &self,
        scope: &HarnessDeliveryScope,
        request_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest() || &self.request_digest != request_digest {
            return Err(HarnessDeliveryResultError::CursorMismatch);
        }
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.token_digest.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "harness-cursor/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page.to_string()),
                ("token", self.token_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    request_digests: Vec<Digest>,
    cursor_digest: Option<Digest>,
    pages: u16,
    complete: bool,
    digest: Digest,
}

impl PaginationEvidence {
    pub fn new(
        request_digests: Vec<Digest>,
        cursor_digest: Option<Digest>,
        pages: u16,
        complete: bool,
    ) -> Result<Self> {
        if pages == 0 || pages > crate::MAX_PAGES || request_digests.is_empty() {
            return Err(HarnessDeliveryResultError::InvalidRequest);
        }
        for digest in &request_digests {
            digest.validate()?;
        }
        if let Some(digest) = &cursor_digest {
            digest.validate()?;
        }
        let digest = Digest::from_parts(
            "harness-pagination/v1",
            &[
                (
                    "requests",
                    request_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    cursor_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("pages", pages.to_string()),
                ("complete", complete.to_string()),
            ],
        );
        Ok(Self {
            request_digests,
            cursor_digest,
            pages,
            complete,
            digest,
        })
    }

    #[must_use]
    pub fn request_digests(&self) -> &[Digest] {
        &self.request_digests
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor_digest.as_ref()
    }

    #[must_use]
    pub const fn pages(&self) -> u16 {
        self.pages
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineMetadata {
    identifier: HarnessPipelineId,
    revision: u64,
    status: HarnessRunStatus,
    observed_at: DateTime<Utc>,
    metadata_digest: Digest,
}

impl PipelineMetadata {
    pub fn new(
        scope: &HarnessDeliveryScope,
        identifier: HarnessPipelineId,
        revision: u64,
        status: HarnessRunStatus,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if identifier != *scope.pipeline() || revision == 0 {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        let metadata_digest = Digest::from_parts(
            "harness-pipeline-metadata/v1",
            &[
                ("identifier", identifier.digest().as_str().to_owned()),
                ("revision", revision.to_string()),
                ("status", format!("{status:?}")),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            identifier,
            revision,
            status,
            observed_at,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn identifier(&self) -> &HarnessPipelineId {
        &self.identifier
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn status(&self) -> HarnessRunStatus {
        self.status
    }

    #[must_use]
    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub(crate) fn validate(&self, scope: &HarnessDeliveryScope) -> Result<()> {
        let expected = Self::new(
            scope,
            self.identifier.clone(),
            self.revision,
            self.status,
            self.observed_at,
        )?;
        if expected.metadata_digest != self.metadata_digest {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionMetadata {
    identifier: HarnessExecutionId,
    pipeline: HarnessPipelineId,
    commit_digest: Option<Digest>,
    status: HarnessRunStatus,
    observed_at: DateTime<Utc>,
    metadata_digest: Digest,
}

impl ExecutionMetadata {
    pub fn new(
        scope: &HarnessDeliveryScope,
        identifier: HarnessExecutionId,
        pipeline: HarnessPipelineId,
        commit: Option<CommitReference>,
        status: HarnessRunStatus,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if pipeline != *scope.pipeline()
            || scope
                .execution()
                .is_some_and(|expected| *expected != identifier)
        {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        let commit_digest = commit.map(|value| value.digest());
        let metadata_digest = Digest::from_parts(
            "harness-execution-metadata/v1",
            &[
                ("identifier", identifier.digest().as_str().to_owned()),
                ("pipeline", pipeline.digest().as_str().to_owned()),
                (
                    "commit",
                    commit_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{status:?}")),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            identifier,
            pipeline,
            commit_digest,
            status,
            observed_at,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn identifier(&self) -> &HarnessExecutionId {
        &self.identifier
    }

    #[must_use]
    pub fn pipeline(&self) -> &HarnessPipelineId {
        &self.pipeline
    }

    #[must_use]
    pub fn commit_digest(&self) -> Option<&Digest> {
        self.commit_digest.as_ref()
    }

    #[must_use]
    pub const fn status(&self) -> HarnessRunStatus {
        self.status
    }

    #[must_use]
    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub(crate) fn validate(&self, scope: &HarnessDeliveryScope) -> Result<()> {
        if scope
            .execution()
            .is_some_and(|expected| *expected != self.identifier)
            || self.pipeline != *scope.pipeline()
        {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        let expected = Self::new(
            scope,
            self.identifier.clone(),
            self.pipeline.clone(),
            self.commit_digest
                .as_ref()
                .map(|digest| CommitReference(digest.as_str().to_owned())),
            self.status,
            self.observed_at,
        );
        if expected.is_err() {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        // The constructor above cannot reconstruct the original commit value
        // from its digest. Validate the digest-bearing projection directly.
        let expected_digest = Digest::from_parts(
            "harness-execution-metadata/v1",
            &[
                ("identifier", self.identifier.digest().as_str().to_owned()),
                ("pipeline", self.pipeline.digest().as_str().to_owned()),
                (
                    "commit",
                    self.commit_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{:?}", self.status)),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected_digest != self.metadata_digest {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageMetadata {
    identifier: HarnessStageId,
    execution_digest: Digest,
    service_digest: Option<Digest>,
    environment_digest: Option<Digest>,
    status: HarnessRunStatus,
    observed_at: DateTime<Utc>,
    metadata_digest: Digest,
}

impl StageMetadata {
    pub fn new(
        scope: &HarnessDeliveryScope,
        identifier: HarnessStageId,
        execution: &HarnessExecutionId,
        service: Option<HarnessServiceId>,
        environment: Option<HarnessEnvironmentId>,
        status: HarnessRunStatus,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if scope.execution() != Some(execution)
            || scope.stage() != Some(&identifier)
            || scope
                .service()
                .is_some_and(|expected| service.as_ref() != Some(expected))
            || scope
                .environment()
                .is_some_and(|expected| environment.as_ref() != Some(expected))
        {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        let execution_digest = execution.digest();
        let service_digest = service.as_ref().map(HarnessServiceId::digest);
        let environment_digest = environment.as_ref().map(HarnessEnvironmentId::digest);
        let metadata_digest = Digest::from_parts(
            "harness-stage-metadata/v1",
            &[
                ("identifier", identifier.digest().as_str().to_owned()),
                ("execution", execution_digest.as_str().to_owned()),
                (
                    "service",
                    service_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "environment",
                    environment_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{status:?}")),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            identifier,
            execution_digest,
            service_digest,
            environment_digest,
            status,
            observed_at,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn identifier(&self) -> &HarnessStageId {
        &self.identifier
    }

    #[must_use]
    pub fn execution_digest(&self) -> &Digest {
        &self.execution_digest
    }

    #[must_use]
    pub fn service_digest(&self) -> Option<&Digest> {
        self.service_digest.as_ref()
    }

    #[must_use]
    pub fn environment_digest(&self) -> Option<&Digest> {
        self.environment_digest.as_ref()
    }

    #[must_use]
    pub const fn status(&self) -> HarnessRunStatus {
        self.status
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub(crate) fn validate(&self, scope: &HarnessDeliveryScope) -> Result<()> {
        if scope.stage() != Some(&self.identifier) {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        let expected = Digest::from_parts(
            "harness-stage-metadata/v1",
            &[
                ("identifier", self.identifier.digest().as_str().to_owned()),
                ("execution", self.execution_digest.as_str().to_owned()),
                (
                    "service",
                    self.service_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "environment",
                    self.environment_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{:?}", self.status)),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected != self.metadata_digest {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceMetadata {
    identifier: HarnessServiceId,
    environment_digest: Option<Digest>,
    deployment_digest: Option<Digest>,
    commit_digest: Option<Digest>,
    status: HarnessRunStatus,
    observed_at: DateTime<Utc>,
    metadata_digest: Digest,
}

impl ServiceMetadata {
    pub fn new(
        scope: &HarnessDeliveryScope,
        identifier: HarnessServiceId,
        environment: Option<HarnessEnvironmentId>,
        deployment: Option<HarnessDeploymentId>,
        commit: Option<CommitReference>,
        status: HarnessRunStatus,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if scope.service() != Some(&identifier)
            || scope
                .environment()
                .is_some_and(|expected| environment.as_ref() != Some(expected))
        {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        let environment_digest = environment.as_ref().map(HarnessEnvironmentId::digest);
        let deployment_digest = deployment.as_ref().map(HarnessDeploymentId::digest);
        let commit_digest = commit.map(|value| value.digest());
        let metadata_digest = Digest::from_parts(
            "harness-service-metadata/v1",
            &[
                ("identifier", identifier.digest().as_str().to_owned()),
                (
                    "environment",
                    environment_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "deployment",
                    deployment_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "commit",
                    commit_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{status:?}")),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            identifier,
            environment_digest,
            deployment_digest,
            commit_digest,
            status,
            observed_at,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn identifier(&self) -> &HarnessServiceId {
        &self.identifier
    }

    #[must_use]
    pub fn environment_digest(&self) -> Option<&Digest> {
        self.environment_digest.as_ref()
    }

    #[must_use]
    pub fn deployment_digest(&self) -> Option<&Digest> {
        self.deployment_digest.as_ref()
    }

    #[must_use]
    pub fn commit_digest(&self) -> Option<&Digest> {
        self.commit_digest.as_ref()
    }

    #[must_use]
    pub const fn status(&self) -> HarnessRunStatus {
        self.status
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub(crate) fn validate(&self, scope: &HarnessDeliveryScope) -> Result<()> {
        if scope.service() != Some(&self.identifier) {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        let expected = Digest::from_parts(
            "harness-service-metadata/v1",
            &[
                ("identifier", self.identifier.digest().as_str().to_owned()),
                (
                    "environment",
                    self.environment_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "deployment",
                    self.deployment_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "commit",
                    self.commit_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{:?}", self.status)),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected != self.metadata_digest {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentMetadata {
    identifier: HarnessDeploymentId,
    service_digest: Digest,
    environment_digest: Digest,
    commit_digest: Option<Digest>,
    status: HarnessRunStatus,
    observed_at: DateTime<Utc>,
    metadata_digest: Digest,
}

impl DeploymentMetadata {
    pub fn new(
        scope: &HarnessDeliveryScope,
        identifier: HarnessDeploymentId,
        service: HarnessServiceId,
        environment: HarnessEnvironmentId,
        commit: Option<CommitReference>,
        status: HarnessRunStatus,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if scope.service() != Some(&service) || scope.environment() != Some(&environment) {
            return Err(HarnessDeliveryResultError::ExecutionBindingMismatch);
        }
        let service_digest = service.digest();
        let environment_digest = environment.digest();
        let commit_digest = commit.map(|value| value.digest());
        let metadata_digest = Digest::from_parts(
            "harness-deployment-metadata/v1",
            &[
                ("identifier", identifier.digest().as_str().to_owned()),
                ("service", service_digest.as_str().to_owned()),
                ("environment", environment_digest.as_str().to_owned()),
                (
                    "commit",
                    commit_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{status:?}")),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            identifier,
            service_digest,
            environment_digest,
            commit_digest,
            status,
            observed_at,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn identifier(&self) -> &HarnessDeploymentId {
        &self.identifier
    }

    #[must_use]
    pub fn service_digest(&self) -> &Digest {
        &self.service_digest
    }

    #[must_use]
    pub fn environment_digest(&self) -> &Digest {
        &self.environment_digest
    }

    #[must_use]
    pub fn commit_digest(&self) -> Option<&Digest> {
        self.commit_digest.as_ref()
    }

    #[must_use]
    pub const fn status(&self) -> HarnessRunStatus {
        self.status
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub(crate) fn validate(&self, _scope: &HarnessDeliveryScope) -> Result<()> {
        self.identifier.validate()?;
        let expected = Digest::from_parts(
            "harness-deployment-metadata/v1",
            &[
                ("identifier", self.identifier.digest().as_str().to_owned()),
                ("service", self.service_digest.as_str().to_owned()),
                ("environment", self.environment_digest.as_str().to_owned()),
                (
                    "commit",
                    self.commit_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("status", format!("{:?}", self.status)),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected != self.metadata_digest {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub pagination_digest: Digest,
    pub pipeline_digest: Option<Digest>,
    pub execution_digest: Option<Digest>,
    pub stage_digest: Option<Digest>,
    pub service_digest: Option<Digest>,
    pub deployment_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.scope_digest.validate()?;
        self.pagination_digest.validate()?;
        for digest in [
            self.pipeline_digest.as_ref(),
            self.execution_digest.as_ref(),
            self.stage_digest.as_ref(),
            self.service_digest.as_ref(),
            self.deployment_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        self.evidence_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessDeliveryEvidence {
    pub pipeline: Option<PipelineMetadata>,
    pub execution: Option<ExecutionMetadata>,
    pub stages: Vec<StageMetadata>,
    pub services: Vec<ServiceMetadata>,
    pub deployments: Vec<DeploymentMetadata>,
    pub state: HarnessEvidenceState,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub observed_at: DateTime<Utc>,
    pub backoff: Option<crate::service::BackoffHint>,
}

impl HarnessDeliveryEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &HarnessDeliveryScope,
        provider_digest: Digest,
        permission_digest: Digest,
        consent_digest: Digest,
        pagination: PaginationEvidence,
        pipeline: Option<PipelineMetadata>,
        execution: Option<ExecutionMetadata>,
        stages: Vec<StageMetadata>,
        services: Vec<ServiceMetadata>,
        deployments: Vec<DeploymentMetadata>,
        state: HarnessEvidenceState,
        provenance: TransportProvenance,
        observed_at: DateTime<Utc>,
        backoff: Option<crate::service::BackoffHint>,
    ) -> Result<Self> {
        if provider_digest.validate().is_err()
            || permission_digest.validate().is_err()
            || consent_digest.validate().is_err()
        {
            return Err(HarnessDeliveryResultError::InvalidDigest);
        }
        if stages.len() > MAX_METADATA_ITEMS
            || services.len() > MAX_METADATA_ITEMS
            || deployments.len() > MAX_METADATA_ITEMS
        {
            return Err(HarnessDeliveryResultError::PartialEvidence);
        }
        if let Some(value) = &pipeline {
            value.validate(scope)?;
        }
        if let Some(value) = &execution {
            value.validate(scope)?;
        }
        for value in &stages {
            value.validate(scope)?;
        }
        for value in &services {
            value.validate(scope)?;
        }
        for value in &deployments {
            value.validate(scope)?;
        }
        let pipeline_digest = pipeline.as_ref().map(|value| value.digest().clone());
        let execution_digest = execution.as_ref().map(|value| value.digest().clone());
        let stage_digest = nonempty_digests(
            "harness-stage-page/v1",
            stages.iter().map(StageMetadata::digest),
        );
        let service_digest = nonempty_digests(
            "harness-service-page/v1",
            services.iter().map(ServiceMetadata::digest),
        );
        let deployment_digest = nonempty_digests(
            "harness-deployment-page/v1",
            deployments.iter().map(DeploymentMetadata::digest),
        );
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest,
            consent_digest,
            scope_digest: scope.digest(),
            pagination_digest: pagination.digest().clone(),
            pipeline_digest,
            execution_digest,
            stage_digest,
            service_digest,
            deployment_digest,
            evidence_digest: Digest::from_text("unsealed-harness-delivery-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(&evidence, state, provenance);
        Ok(Self {
            pipeline,
            execution,
            stages,
            services,
            deployments,
            state,
            evidence,
            provenance,
            observed_at,
            backoff,
        })
    }

    pub fn validate_integrity(&self, scope: &HarnessDeliveryScope) -> Result<()> {
        self.evidence.validate()?;
        if self.evidence.scope_digest != scope.digest()
            || self.evidence.contract_digest != crate::contract_digest()
        {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        if let Some(value) = &self.pipeline {
            value.validate(scope)?;
        }
        if let Some(value) = &self.execution {
            value.validate(scope)?;
        }
        for value in &self.stages {
            value.validate(scope)?;
        }
        for value in &self.services {
            value.validate(scope)?;
        }
        for value in &self.deployments {
            value.validate(scope)?;
        }
        let expected = calculate_evidence_digest(&self.evidence, self.state, self.provenance);
        if expected != self.evidence.evidence_digest {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

fn nonempty_digests<'a>(domain: &str, values: impl Iterator<Item = &'a Digest>) -> Option<Digest> {
    let values = values
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| Digest::from_parts(domain, &[("items", values.join("\n"))]))
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: HarnessEvidenceState,
    provenance: TransportProvenance,
) -> Digest {
    Digest::from_parts(
        "harness-delivery-evidence/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("pagination", evidence.pagination_digest.as_str().to_owned()),
            (
                "pipeline",
                evidence
                    .pipeline_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "execution",
                evidence
                    .execution_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "stage",
                evidence
                    .stage_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "service",
                evidence
                    .service_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "deployment",
                evidence
                    .deployment_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("provenance", format!("{provenance:?}")),
        ],
    )
}
