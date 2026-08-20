//! Typed scope, digest, credential, continuation, and bounded projection
//! models for the Azure Data Factory Layer-1 plugin.

use std::{collections::BTreeSet, fmt};

use crate::{
    API_REVISION, AzureDataFactoryPipelineResultError, MAX_ACTIVITY_TYPE_DIGESTS,
    MAX_ACTIVITY_WINDOW_DAYS, MAX_CONTINUATION_BYTES, MAX_IDENTIFIER_BYTES, Result,
    digest_serialized,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// A lowercase SHA-256 digest. Raw provider identifiers and payloads cross
/// the public evidence boundary only through this type.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(crate::sha256_hex(bytes))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(domain.len() + fields.len() * 32);
        canonical.push_str(domain);
        for (name, value) in fields {
            canonical.push('|');
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
        }
        Self::from_text(canonical)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AzureDataFactoryPipelineResultError::InvalidDigest { field: "digest" })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if valid_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::InvalidDigest { field: "digest" })
        }
    }

    #[must_use]
    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        digest_serialized(value)
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

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_internal_whitespace: bool,
) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
        || (!allow_internal_whitespace && value.chars().any(char::is_whitespace))
    {
        Err(AzureDataFactoryPipelineResultError::InvalidText { field })
    } else {
        Ok(())
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
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES, false)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_text(&self.0, $field, MAX_IDENTIFIER_BYTES, false)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

define_identifier!(SubscriptionId, "subscriptionId");
define_identifier!(ResourceGroupName, "resourceGroupName");
define_identifier!(FactoryName, "factoryName");
define_identifier!(PipelineName, "pipelineName");
define_identifier!(PipelineRunId, "pipelineRunId");
define_identifier!(ProjectId, "projectId");
define_identifier!(MissionId, "missionId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(RegistrationId, "registrationId");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AzureDataFactoryPipelineResultError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureDataFactoryPermission {
    PipelinesRead,
    PipelineRunsRead,
    ActivityRunsQuery,
}

impl AzureDataFactoryPermission {
    #[must_use]
    pub const fn api_action(self) -> &'static str {
        match self {
            Self::PipelinesRead => "Microsoft.DataFactory/factories/pipelines/read",
            Self::PipelineRunsRead => "Microsoft.DataFactory/factories/pipelineruns/read",
            Self::ActivityRunsQuery => {
                "Microsoft.DataFactory/factories/pipelineruns/queryActivityRuns/action"
            }
        }
    }
}

pub type Permission = AzureDataFactoryPermission;

/// Immutable least-privilege permission evidence bound into a registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    permissions: BTreeSet<AzureDataFactoryPermission>,
    permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(permissions: impl IntoIterator<Item = AzureDataFactoryPermission>) -> Result<Self> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&AzureDataFactoryPermission::PipelinesRead)
            || !permissions.contains(&AzureDataFactoryPermission::PipelineRunsRead)
            || !permissions.contains(&AzureDataFactoryPermission::ActivityRunsQuery)
        {
            return Err(AzureDataFactoryPipelineResultError::MissingPermission);
        }
        let actions = permissions
            .iter()
            .map(|permission| permission.api_action())
            .collect::<Vec<_>>();
        let permission_digest =
            Digest::from_serialized(&("azure-data-factory-permission-scope/v1", actions));
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    #[must_use]
    pub fn least_privilege() -> Self {
        Self::new([
            AzureDataFactoryPermission::PipelinesRead,
            AzureDataFactoryPermission::PipelineRunsRead,
            AzureDataFactoryPermission::ActivityRunsQuery,
        ])
        .expect("the three required Azure Data Factory permissions are valid")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<AzureDataFactoryPermission> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn contains(&self, permission: AzureDataFactoryPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn validate(&self) -> Result<()> {
        let rebuilt = Self::new(self.permissions.iter().copied())?;
        if rebuilt.permission_digest == self.permission_digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::PermissionDigestMismatch)
        }
    }
}

pub type PermissionFence = PermissionScope;

/// A host-owned credential handle. This intentionally implements neither
/// `Serialize` nor `Deserialize`; only stable digests and a revision are
/// observable. The opaque reference and tenant identifier are never stored.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    tenant_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl Into<String>,
        tenant_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self> {
        let opaque_reference = opaque_reference.into();
        let tenant_id = tenant_id.into();
        validate_text(
            &opaque_reference,
            "secretReference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        validate_text(&tenant_id, "tenantId", MAX_IDENTIFIER_BYTES, false)?;
        let credential_revision = Revision::new(credential_revision)?;
        let tenant_digest = Digest::from_text(tenant_id);
        let reference_digest = Digest::from_serialized(&(
            "azure-data-factory-opaque-secret-reference/v1",
            &opaque_reference,
            &tenant_digest,
            credential_revision,
        ));
        Ok(Self {
            reference_digest,
            tenant_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn for_tenant(
        opaque_reference: impl Into<String>,
        tenant_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_reference, tenant_id, credential_revision)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn tenant_digest(&self) -> &Digest {
        &self.tenant_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(&(
            "azure-data-factory-secret-reference-state/v1",
            &self.reference_digest,
            &self.tenant_digest,
            self.credential_revision,
            self.revoked,
        ))
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn restore(&mut self) {
        self.revoked = false;
    }

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate()?;
        self.tenant_digest.validate()?;
        if self.credential_revision.get() == 0 {
            return Err(AzureDataFactoryPipelineResultError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("tenant_digest", &self.tenant_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
    pub digest: Digest,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = ProjectId::new(id)?;
        let revision = Revision::new(revision)?;
        let digest =
            Digest::from_serialized(&("azure-data-factory-project-binding/v1", &id, revision));
        Ok(Self {
            id,
            revision,
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
    pub digest: Digest,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = MissionId::new(id)?;
        let revision = Revision::new(revision)?;
        let digest =
            Digest::from_serialized(&("azure-data-factory-mission-binding/v1", &id, revision));
        Ok(Self {
            id,
            revision,
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
    pub digest: Digest,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = WorkProductId::new(id)?;
        let revision = Revision::new(revision)?;
        let digest =
            Digest::from_serialized(&("azure-data-factory-work-product-binding/v1", &id, revision));
        Ok(Self {
            id,
            revision,
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    digest: Digest,
}

impl ActivityWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self> {
        let duration = end
            .signed_duration_since(start)
            .to_std()
            .map_err(|_| AzureDataFactoryPipelineResultError::InvalidActivityWindow)?;
        if duration.is_zero()
            || duration > std::time::Duration::from_secs((MAX_ACTIVITY_WINDOW_DAYS * 86_400) as u64)
        {
            return Err(AzureDataFactoryPipelineResultError::InvalidActivityWindow);
        }
        let digest =
            Digest::from_serialized(&("azure-data-factory-activity-window/v1", start, end));
        Ok(Self { start, end, digest })
    }

    #[must_use]
    pub const fn start(&self) -> DateTime<Utc> {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> DateTime<Utc> {
        self.end
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        if Self::new(self.start, self.end)?.digest == self.digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::Tampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureDataFactoryScopeInput {
    pub tenant_id: String,
    pub subscription_id: String,
    pub resource_group_name: String,
    pub factory_name: String,
    pub pipeline_name: String,
    pub pipeline_run_id: String,
    pub pipeline_revision: u64,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub activity_window: ActivityWindow,
    pub permissions: PermissionScope,
}

/// Exact ADF resource plus Project/Mission/Work Product binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureDataFactoryScope {
    tenant_digest: Digest,
    subscription_id: SubscriptionId,
    resource_group_name: ResourceGroupName,
    factory_name: FactoryName,
    pipeline_name: PipelineName,
    pipeline_run_id: PipelineRunId,
    pipeline_revision: Revision,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    activity_window: ActivityWindow,
    permissions: PermissionScope,
    scope_digest: Digest,
}

impl AzureDataFactoryScope {
    pub fn new(input: AzureDataFactoryScopeInput) -> Result<Self> {
        validate_text(&input.tenant_id, "tenantId", MAX_IDENTIFIER_BYTES, false)?;
        let tenant_digest = Digest::from_text(input.tenant_id);
        let subscription_id = SubscriptionId::new(input.subscription_id)?;
        let resource_group_name = ResourceGroupName::new(input.resource_group_name)?;
        let factory_name = FactoryName::new(input.factory_name)?;
        let pipeline_name = PipelineName::new(input.pipeline_name)?;
        let pipeline_run_id = PipelineRunId::new(input.pipeline_run_id)?;
        let pipeline_revision = Revision::new(input.pipeline_revision)?;
        input.project.id.validate()?;
        input.mission.id.validate()?;
        input.work_product.id.validate()?;
        input.activity_window.validate()?;
        input.permissions.validate()?;
        let scope_digest = Digest::from_serialized(&(
            "azure-data-factory-scope/v1",
            &tenant_digest,
            &subscription_id,
            &resource_group_name,
            &factory_name,
            &pipeline_name,
            &pipeline_run_id,
            pipeline_revision,
            &input.project.digest,
            &input.mission.digest,
            &input.work_product.digest,
            input.activity_window.digest(),
            input.permissions.digest(),
        ));
        Ok(Self {
            tenant_digest,
            subscription_id,
            resource_group_name,
            factory_name,
            pipeline_name,
            pipeline_run_id,
            pipeline_revision,
            project: input.project,
            mission: input.mission,
            work_product: input.work_product,
            activity_window: input.activity_window,
            permissions: input.permissions,
            scope_digest,
        })
    }

    #[must_use]
    pub fn tenant_digest(&self) -> &Digest {
        &self.tenant_digest
    }

    #[must_use]
    pub fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }

    #[must_use]
    pub fn resource_group_name(&self) -> &ResourceGroupName {
        &self.resource_group_name
    }

    #[must_use]
    pub fn factory_name(&self) -> &FactoryName {
        &self.factory_name
    }

    #[must_use]
    pub fn pipeline_name(&self) -> &PipelineName {
        &self.pipeline_name
    }

    #[must_use]
    pub fn pipeline_run_id(&self) -> &PipelineRunId {
        &self.pipeline_run_id
    }

    #[must_use]
    pub const fn pipeline_revision(&self) -> Revision {
        self.pipeline_revision
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn activity_window(&self) -> &ActivityWindow {
        &self.activity_window
    }

    #[must_use]
    pub fn permissions(&self) -> &PermissionScope {
        &self.permissions
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn validate(&self) -> Result<()> {
        // The tenant's raw value is intentionally unavailable after
        // construction, so rebuild the digest from the stored tenant digest.
        self.tenant_digest.validate()?;
        self.subscription_id.validate()?;
        self.resource_group_name.validate()?;
        self.factory_name.validate()?;
        self.pipeline_name.validate()?;
        self.pipeline_run_id.validate()?;
        if self.project.digest
            != Digest::from_serialized(&(
                "azure-data-factory-project-binding/v1",
                &self.project.id,
                self.project.revision,
            ))
            || self.mission.digest
                != Digest::from_serialized(&(
                    "azure-data-factory-mission-binding/v1",
                    &self.mission.id,
                    self.mission.revision,
                ))
            || self.work_product.digest
                != Digest::from_serialized(&(
                    "azure-data-factory-work-product-binding/v1",
                    &self.work_product.id,
                    self.work_product.revision,
                ))
        {
            return Err(AzureDataFactoryPipelineResultError::InvalidScope);
        }
        self.activity_window.validate()?;
        self.permissions.validate()?;
        let expected_scope_digest = Digest::from_serialized(&(
            "azure-data-factory-scope/v1",
            &self.tenant_digest,
            &self.subscription_id,
            &self.resource_group_name,
            &self.factory_name,
            &self.pipeline_name,
            &self.pipeline_run_id,
            self.pipeline_revision,
            &self.project.digest,
            &self.mission.digest,
            &self.work_product.digest,
            self.activity_window.digest(),
            self.permissions.digest(),
        ));
        if expected_scope_digest == self.scope_digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::InvalidScope)
        }
    }

    #[must_use]
    pub fn project_digest(&self) -> &Digest {
        &self.project.digest
    }

    #[must_use]
    pub fn mission_digest(&self) -> &Digest {
        &self.mission.digest
    }

    #[must_use]
    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum PipelineStatus {
    Queued,
    InProgress,
    Succeeded,
    Failed,
    Canceling,
    Cancelled,
    Paused,
    TimedOut,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl PipelineStatus {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "Queued" => Self::Queued,
            "InProgress" => Self::InProgress,
            "Succeeded" => Self::Succeeded,
            "Failed" => Self::Failed,
            "Canceling" => Self::Canceling,
            "Cancelled" => Self::Cancelled,
            "Paused" => Self::Paused,
            "TimedOut" => Self::TimedOut,
            "Partial" => Self::Partial,
            "Expired" => Self::Expired,
            "AccessLost" => Self::AccessLost,
            "Tampered" => Self::Tampered,
            "Revoked" => Self::Revoked,
            _ => Self::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::TimedOut
                | Self::Expired
                | Self::AccessLost
                | Self::ProviderUnknown
                | Self::Tampered
                | Self::Revoked
        )
    }
}

/// Continuation binding without a serialized or retained token value.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueContinuation {
    digest: Digest,
    binding_digest: Digest,
    page: usize,
}

impl OpaqueContinuation {
    pub fn new(
        raw_token: impl Into<String>,
        scope: &AzureDataFactoryScope,
        page: usize,
    ) -> Result<Self> {
        let raw_token = raw_token.into();
        validate_text(
            &raw_token,
            "continuationToken",
            MAX_CONTINUATION_BYTES,
            true,
        )?;
        if page == 0 || page > crate::MAX_PAGES {
            return Err(AzureDataFactoryPipelineResultError::PaginationLimit);
        }
        let digest = Digest::from_text(raw_token);
        let binding_digest = Digest::from_serialized(&(
            "azure-data-factory-continuation-binding/v1",
            scope.scope_digest(),
            scope.factory_name().as_str(),
            scope.pipeline_run_id().as_str(),
            scope.activity_window.digest(),
            &digest,
            page,
        ));
        Ok(Self {
            digest,
            binding_digest,
            page,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    #[must_use]
    pub const fn page(&self) -> usize {
        self.page
    }

    pub fn validate(&self, scope: &AzureDataFactoryScope) -> Result<()> {
        self.digest.validate()?;
        self.binding_digest.validate()?;
        if self.page == 0 || self.page > crate::MAX_PAGES {
            return Err(AzureDataFactoryPipelineResultError::PaginationLimit);
        }
        // A continuation's binding digest is the only check possible without
        // retaining the provider token. Providers must construct it through
        // `new`, and request scope/query drift is checked separately.
        let expected_binding = Digest::from_serialized(&(
            "azure-data-factory-continuation-binding/v1",
            scope.scope_digest(),
            scope.factory_name().as_str(),
            scope.pipeline_run_id().as_str(),
            scope.activity_window.digest(),
            &self.digest,
            self.page,
        ));
        if self.binding_digest == expected_binding {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::ContinuationMismatch)
        }
    }
}

impl fmt::Debug for OpaqueContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueContinuation")
            .field("digest", &self.digest)
            .field("binding_digest", &self.binding_digest)
            .field("page", &self.page)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PipelineMetadata {
    pub pipeline_name_digest: Digest,
    pub description_digest: Option<Digest>,
    pub activity_type_digests: Vec<Digest>,
    pub parameter_count: usize,
    pub variable_count: usize,
    pub etag_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub metadata_digest: Digest,
}

impl PipelineMetadata {
    pub fn new(
        scope: &AzureDataFactoryScope,
        description: Option<&str>,
        activity_types: impl IntoIterator<Item = String>,
        parameter_count: usize,
        variable_count: usize,
        etag: Option<&str>,
        observed_at: DateTime<Utc>,
        response_bytes: usize,
    ) -> Result<Self> {
        if response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        let activity_type_digests = activity_types
            .into_iter()
            .map(Digest::from_text)
            .collect::<Vec<_>>();
        if activity_type_digests.len() > MAX_ACTIVITY_TYPE_DIGESTS {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        let description_digest = description.map(Digest::from_text);
        let etag_digest = etag.map(Digest::from_text);
        let pipeline_name_digest = Digest::from_text(scope.pipeline_name().as_str());
        let response_digest = Digest::from_serialized(&(
            "azure-data-factory-pipeline-response/v1",
            &pipeline_name_digest,
            &description_digest,
            &activity_type_digests,
            parameter_count,
            variable_count,
            &etag_digest,
            observed_at,
            response_bytes,
        ));
        let metadata_digest = Digest::from_serialized(&(
            "azure-data-factory-pipeline-metadata/v1",
            &pipeline_name_digest,
            &description_digest,
            &activity_type_digests,
            parameter_count,
            variable_count,
            &etag_digest,
            observed_at,
            response_bytes,
            &response_digest,
        ));
        Ok(Self {
            pipeline_name_digest,
            description_digest,
            activity_type_digests,
            parameter_count,
            variable_count,
            etag_digest,
            observed_at,
            response_bytes,
            response_digest,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn fixture(scope: &AzureDataFactoryScope, observed_at: DateTime<Utc>) -> Self {
        Self::new(
            scope,
            Some("fixture pipeline description"),
            ["Copy".to_owned(), "ForEach".to_owned()],
            2,
            1,
            Some("fixture-etag"),
            observed_at,
            512,
        )
        .expect("ADF pipeline fixture is bounded")
    }

    pub fn validate(&self) -> Result<()> {
        if self.activity_type_digests.len() > MAX_ACTIVITY_TYPE_DIGESTS
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
        {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        for digest in self
            .activity_type_digests
            .iter()
            .chain(self.description_digest.iter())
            .chain(self.etag_digest.iter())
        {
            digest.validate()?;
        }
        let response_digest = Digest::from_serialized(&(
            "azure-data-factory-pipeline-response/v1",
            &self.pipeline_name_digest,
            &self.description_digest,
            &self.activity_type_digests,
            self.parameter_count,
            self.variable_count,
            &self.etag_digest,
            self.observed_at,
            self.response_bytes,
        ));
        let metadata_digest = Digest::from_serialized(&(
            "azure-data-factory-pipeline-metadata/v1",
            &self.pipeline_name_digest,
            &self.description_digest,
            &self.activity_type_digests,
            self.parameter_count,
            self.variable_count,
            &self.etag_digest,
            self.observed_at,
            self.response_bytes,
            &self.response_digest,
        ));
        if self.response_digest == response_digest && self.metadata_digest == metadata_digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::Tampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PipelineRunMetadata {
    pub pipeline_run_id_digest: Digest,
    pub pipeline_name_digest: Digest,
    pub status: PipelineStatus,
    pub run_start: Option<DateTime<Utc>>,
    pub run_end: Option<DateTime<Utc>>,
    pub duration_in_ms: Option<u64>,
    pub run_group_id_digest: Option<Digest>,
    pub invoked_by_digest: Option<Digest>,
    pub parameter_names_digest: Option<Digest>,
    pub message_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub metadata_digest: Digest,
}

impl PipelineRunMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AzureDataFactoryScope,
        status: &str,
        run_start: Option<DateTime<Utc>>,
        run_end: Option<DateTime<Utc>>,
        duration_in_ms: Option<u64>,
        run_group_id: Option<&str>,
        invoked_by: Option<&str>,
        parameter_names: Option<Vec<String>>,
        message: Option<&str>,
        observed_at: DateTime<Utc>,
        response_bytes: usize,
    ) -> Result<Self> {
        if response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        if let (Some(start), Some(end)) = (run_start, run_end)
            && end < start
        {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        let pipeline_run_id_digest = Digest::from_text(scope.pipeline_run_id().as_str());
        let pipeline_name_digest = Digest::from_text(scope.pipeline_name().as_str());
        let run_group_id_digest = run_group_id.map(Digest::from_text);
        let invoked_by_digest = invoked_by.map(Digest::from_text);
        let parameter_names_digest = parameter_names.map(|names| {
            let mut names = names;
            names.sort();
            Digest::from_serialized(&("azure-data-factory-parameter-names/v1", names))
        });
        let message_digest = message.map(Digest::from_text);
        let response_digest = Digest::from_serialized(&(
            "azure-data-factory-pipeline-run-response/v1",
            &pipeline_run_id_digest,
            &pipeline_name_digest,
            status,
            run_start,
            run_end,
            duration_in_ms,
            &run_group_id_digest,
            &invoked_by_digest,
            &parameter_names_digest,
            &message_digest,
            observed_at,
            response_bytes,
        ));
        let normalized_status = PipelineStatus::parse(status);
        let metadata_digest = Digest::from_serialized(&(
            "azure-data-factory-pipeline-run-metadata/v1",
            &pipeline_run_id_digest,
            &pipeline_name_digest,
            normalized_status,
            run_start,
            run_end,
            duration_in_ms,
            &run_group_id_digest,
            &invoked_by_digest,
            &parameter_names_digest,
            &message_digest,
            observed_at,
            response_bytes,
            &response_digest,
        ));
        Ok(Self {
            pipeline_run_id_digest,
            pipeline_name_digest,
            status: normalized_status,
            run_start,
            run_end,
            duration_in_ms,
            run_group_id_digest,
            invoked_by_digest,
            parameter_names_digest,
            message_digest,
            observed_at,
            response_bytes,
            response_digest,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn fixture(scope: &AzureDataFactoryScope, observed_at: DateTime<Utc>) -> Self {
        Self::new(
            scope,
            "Succeeded",
            Some(observed_at - Duration::minutes(3)),
            Some(observed_at),
            Some(180_000),
            Some("fixture-group"),
            Some("Manual"),
            Some(vec!["input".to_owned(), "mode".to_owned()]),
            Some("fixture message"),
            observed_at,
            768,
        )
        .expect("ADF pipeline-run fixture is bounded")
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [&self.pipeline_run_id_digest, &self.pipeline_name_digest] {
            digest.validate()?;
        }
        for digest in self
            .run_group_id_digest
            .iter()
            .chain(self.invoked_by_digest.iter())
            .chain(self.parameter_names_digest.iter())
            .chain(self.message_digest.iter())
        {
            digest.validate()?;
        }
        if self.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        // The original status spelling is intentionally not retained; the
        // normalized status is the evidence boundary and is sealed below.
        let metadata_digest = Digest::from_serialized(&(
            "azure-data-factory-pipeline-run-metadata/v1",
            &self.pipeline_run_id_digest,
            &self.pipeline_name_digest,
            self.status,
            self.run_start,
            self.run_end,
            self.duration_in_ms,
            &self.run_group_id_digest,
            &self.invoked_by_digest,
            &self.parameter_names_digest,
            &self.message_digest,
            self.observed_at,
            self.response_bytes,
            &self.response_digest,
        ));
        if self.response_digest.validate().is_err() {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        if self.metadata_digest == metadata_digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::Tampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityRunMetadata {
    pub activity_run_id_digest: Digest,
    pub activity_name_digest: Digest,
    pub activity_type_digest: Digest,
    pub status: PipelineStatus,
    pub run_start: Option<DateTime<Utc>>,
    pub run_end: Option<DateTime<Utc>>,
    pub duration_in_ms: Option<u64>,
    pub input_digest: Option<Digest>,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub metadata_digest: Digest,
}

impl ActivityRunMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activity_run_id: &str,
        activity_name: &str,
        activity_type: &str,
        status: &str,
        run_start: Option<DateTime<Utc>>,
        run_end: Option<DateTime<Utc>>,
        duration_in_ms: Option<u64>,
        input: Option<&str>,
        output: Option<&str>,
        error: Option<&str>,
        response_bytes: usize,
    ) -> Result<Self> {
        validate_text(
            activity_run_id,
            "activityRunId",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        validate_text(activity_name, "activityName", MAX_IDENTIFIER_BYTES, true)?;
        validate_text(activity_type, "activityType", MAX_IDENTIFIER_BYTES, false)?;
        if response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        if let (Some(start), Some(end)) = (run_start, run_end)
            && end < start
        {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        let activity_run_id_digest = Digest::from_text(activity_run_id);
        let activity_name_digest = Digest::from_text(activity_name);
        let activity_type_digest = Digest::from_text(activity_type);
        let input_digest = input.map(Digest::from_text);
        let output_digest = output.map(Digest::from_text);
        let error_digest = error.map(Digest::from_text);
        let normalized_status = PipelineStatus::parse(status);
        let response_digest = Digest::from_serialized(&(
            "azure-data-factory-activity-run-response/v1",
            &activity_run_id_digest,
            &activity_name_digest,
            &activity_type_digest,
            status,
            run_start,
            run_end,
            duration_in_ms,
            &input_digest,
            &output_digest,
            &error_digest,
            response_bytes,
        ));
        let metadata_digest = Digest::from_serialized(&(
            "azure-data-factory-activity-run-metadata/v1",
            &activity_run_id_digest,
            &activity_name_digest,
            &activity_type_digest,
            normalized_status,
            run_start,
            run_end,
            duration_in_ms,
            &input_digest,
            &output_digest,
            &error_digest,
            response_bytes,
            &response_digest,
        ));
        Ok(Self {
            activity_run_id_digest,
            activity_name_digest,
            activity_type_digest,
            status: normalized_status,
            run_start,
            run_end,
            duration_in_ms,
            input_digest,
            output_digest,
            error_digest,
            response_bytes,
            response_digest,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn fixture(index: usize, observed_at: DateTime<Utc>) -> Self {
        Self::new(
            &format!("activity-run-{index}"),
            if index == 0 {
                "CopyActivity"
            } else {
                "ForEachActivity"
            },
            if index == 0 { "Copy" } else { "ForEach" },
            "Succeeded",
            Some(observed_at - Duration::seconds(30)),
            Some(observed_at),
            Some(30_000),
            Some("private activity input"),
            Some("private activity output"),
            None,
            256,
        )
        .expect("ADF activity fixture is bounded")
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.activity_run_id_digest,
            &self.activity_name_digest,
            &self.activity_type_digest,
        ] {
            digest.validate()?;
        }
        for digest in self.input_digest.iter().chain(self.output_digest.iter()) {
            digest.validate()?;
        }
        if let Some(digest) = &self.error_digest {
            digest.validate()?;
        }
        if self.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        let metadata_digest = Digest::from_serialized(&(
            "azure-data-factory-activity-run-metadata/v1",
            &self.activity_run_id_digest,
            &self.activity_name_digest,
            &self.activity_type_digest,
            self.status,
            self.run_start,
            self.run_end,
            self.duration_in_ms,
            &self.input_digest,
            &self.output_digest,
            &self.error_digest,
            self.response_bytes,
            &self.response_digest,
        ));
        if self.response_digest.validate().is_err() {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        if self.metadata_digest == metadata_digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::Tampered)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderResponseReceipt {
    pub operation: String,
    pub method: String,
    pub path_template: String,
    pub api_version: String,
    pub provider_revision: String,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub continuation_digest: Option<Digest>,
    pub request_digest: Digest,
    pub response_status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
    pub redacted: bool,
}

impl ProviderResponseReceipt {
    pub fn validate(&self) -> Result<()> {
        if !self.redacted
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.scope_digest.validate().is_err()
            || self.permission_digest.validate().is_err()
            || self.request_digest.validate().is_err()
            || self.response_digest.validate().is_err()
            || self
                .continuation_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
        {
            Err(AzureDataFactoryPipelineResultError::RedactionViolation)
        } else {
            Ok(())
        }
    }
}

#[must_use]
pub fn provider_digest() -> Digest {
    Digest::from_serialized(&(
        "azure-data-factory-provider/v1",
        crate::PROVIDER_ID,
        crate::PROVIDER_VERSION,
        API_REVISION,
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ))
}

#[must_use]
pub fn api_digest() -> Digest {
    Digest::from_serialized(&(
        "azure-data-factory-api/v1",
        crate::API_VERSION,
        API_REVISION,
        "Pipelines - Get",
        "Pipeline Runs - Get",
        "Activity Runs - Query By Pipeline Run",
    ))
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    Digest::from_text(crate::PLUGIN_VERSION)
}

#[must_use]
pub fn evidence_policy_digest() -> Digest {
    Digest::from_serialized(&(
        "azure-data-factory-evidence-policy/v1",
        crate::MAX_PAGES,
        crate::MAX_PAGE_SIZE,
        crate::MAX_ACTIVITIES,
        crate::MAX_RESPONSE_BYTES,
        false,
        false,
        false,
    ))
}

#[must_use]
pub fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    digest_serialized(value)
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}
