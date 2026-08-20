use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::error::{RedisCloudDatabaseResultError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_REGIONS};

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
            Err(ModelError::InvalidDigest.into())
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
            Err(ModelError::InvalidDigest.into())
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

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_numeric_id(value: &str) -> bool {
    (1..=32).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { field: $field }.into())
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("redis-cloud-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(ModelError::InvalidIdentifier { field: $field }.into())
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format!("{}:{}", $field, &self.digest().as_str()[..16]))
                    .finish()
            }
        }
    };
}

redacted_identifier!(RedisCloudAccountId, "account-id", valid_numeric_id);
redacted_identifier!(
    RedisCloudSubscriptionId,
    "subscription-id",
    valid_numeric_id
);
redacted_identifier!(RedisCloudDatabaseId, "database-id", valid_numeric_id);

#[derive(Clone, Eq, PartialEq)]
pub struct MissionBinding {
    id_digest: Digest,
    revision: u64,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new_named(id, revision, "mission-id")
    }

    fn new_named(id: impl Into<String>, revision: u64, field: &'static str) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(ModelError::InvalidBinding { field }.into());
        }
        Ok(Self {
            id_digest: Digest::from_parts(
                "redis-cloud-binding/v1",
                &[("field", field.to_owned()), ("id", id)],
            ),
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

    pub(crate) fn validate(&self, field: &'static str) -> Result<()> {
        if self.revision == 0 {
            return Err(ModelError::InvalidBinding { field }.into());
        }
        self.id_digest.validate()
    }

    fn digest(&self, field: &'static str) -> Digest {
        Digest::from_parts(
            "redis-cloud-scope-binding/v1",
            &[
                ("field", field.to_owned()),
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

impl fmt::Debug for MissionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBinding")
            .field("id_digest", &self.id_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

pub type ProjectBinding = MissionBinding;
pub type WorkProductBinding = MissionBinding;
pub type MissionIdentity = MissionBinding;
pub type ProjectIdentity = ProjectBinding;
pub type WorkProductIdentity = WorkProductBinding;

#[derive(Clone, Eq, PartialEq)]
pub struct RedisCloudDatabaseScope {
    account: RedisCloudAccountId,
    subscription: RedisCloudSubscriptionId,
    database: RedisCloudDatabaseId,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    expected_subscription_revision: Option<Digest>,
    expected_database_revision: Option<Digest>,
}

impl RedisCloudDatabaseScope {
    pub fn new(
        account: RedisCloudAccountId,
        subscription: RedisCloudSubscriptionId,
        database: RedisCloudDatabaseId,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        let scope = Self {
            account,
            subscription,
            database,
            mission,
            project,
            work_product,
            expected_subscription_revision: None,
            expected_database_revision: None,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_expected_subscription_revision(mut self, revision: Digest) -> Result<Self> {
        revision.validate()?;
        self.expected_subscription_revision = Some(revision);
        self.validate()?;
        Ok(self)
    }

    pub fn with_expected_database_revision(mut self, revision: Digest) -> Result<Self> {
        revision.validate()?;
        self.expected_database_revision = Some(revision);
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn account(&self) -> &RedisCloudAccountId {
        &self.account
    }
    #[must_use]
    pub fn subscription(&self) -> &RedisCloudSubscriptionId {
        &self.subscription
    }
    #[must_use]
    pub fn database(&self) -> &RedisCloudDatabaseId {
        &self.database
    }
    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }
    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }
    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }
    #[must_use]
    pub fn expected_subscription_revision(&self) -> Option<&Digest> {
        self.expected_subscription_revision.as_ref()
    }
    #[must_use]
    pub fn expected_database_revision(&self) -> Option<&Digest> {
        self.expected_database_revision.as_ref()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-database-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                (
                    "subscription",
                    self.subscription.digest().as_str().to_owned(),
                ),
                ("database", self.database.digest().as_str().to_owned()),
                (
                    "mission",
                    self.mission.digest("mission").as_str().to_owned(),
                ),
                (
                    "project",
                    self.project.digest("project").as_str().to_owned(),
                ),
                (
                    "work_product",
                    self.work_product.digest("work_product").as_str().to_owned(),
                ),
                (
                    "subscription_revision",
                    self.expected_subscription_revision
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "database_revision",
                    self.expected_database_revision
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.subscription.validate()?;
        self.database.validate()?;
        self.mission.validate("mission-id")?;
        self.project.validate("project-id")?;
        self.work_product.validate("work-product-id")?;
        self.expected_subscription_revision
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.expected_database_revision
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.digest().validate()
    }
}

impl fmt::Debug for RedisCloudDatabaseScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisCloudDatabaseScope")
            .field("account", &self.account)
            .field("subscription", &self.subscription)
            .field("database", &self.database)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

impl Serialize for RedisCloudDatabaseScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("RedisCloudDatabaseScope", 9)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("subscriptionDigest", &self.subscription.digest())?;
        state.serialize_field("databaseDigest", &self.database.digest())?;
        state.serialize_field("missionIdDigest", self.mission.id_digest())?;
        state.serialize_field("missionRevision", &self.mission.revision())?;
        state.serialize_field("projectIdDigest", self.project.id_digest())?;
        state.serialize_field("projectRevision", &self.project.revision())?;
        state.serialize_field("workProductIdDigest", self.work_product.id_digest())?;
        state.serialize_field("workProductRevision", &self.work_product.revision())?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AccountApiKey,
}

/// Opaque, non-serializing reference to a Layer-2 secret handle.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &RedisCloudDatabaseScope,
        revision: u64,
    ) -> Result<Self> {
        let mut handle = opaque_handle.into();
        scope.validate()?;
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(ModelError::InvalidSecretReference.into());
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "redis-cloud-opaque-account-api-key-reference/v1",
            &[
                ("kind", "account_api_key".to_owned()),
                ("handle", handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        let reference = Self {
            kind: SecretKind::AccountApiKey,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        };
        reference.validate(scope)?;
        Ok(reference)
    }

    #[must_use]
    pub fn kind(&self) -> SecretKind {
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

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &RedisCloudDatabaseScope) -> Result<()> {
        if self.kind != SecretKind::AccountApiKey
            || self.revision == 0
            || self.scope_digest != scope.digest()
            || self.revoked && self.reference_digest.as_str().is_empty()
        {
            return Err(ModelError::InvalidSecretReference.into());
        }
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

pub type TransportProvenance = ProviderProvenance;

impl ProviderProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
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
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-permissions/v1",
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
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.len() != LAYER1_PERMISSIONS.len()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || LAYER1_PERMISSIONS
                .iter()
                .any(|permission| !self.permissions.contains(*permission))
        {
            Err(ModelError::InvalidPermissionSnapshot.into())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisCloudResourceStatus {
    Active,
    Creating,
    Updating,
    Deleting,
    Suspended,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisCloudPlanTier {
    Essentials,
    Pro,
    Payg,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudPlanPosture {
    pub plan_digest: Digest,
    pub tier: RedisCloudPlanTier,
}

impl RedisCloudPlanPosture {
    pub fn new(plan_identifier: impl Into<String>, tier: RedisCloudPlanTier) -> Result<Self> {
        let mut identifier = plan_identifier.into();
        if !valid_identifier(&identifier, MAX_IDENTIFIER_BYTES) {
            identifier.zeroize();
            return Err(ModelError::InvalidIdentifier { field: "plan-id" }.into());
        }
        let plan_digest =
            Digest::from_parts("redis-cloud-plan/v1", &[("identifier", identifier.clone())]);
        identifier.zeroize();
        Ok(Self { plan_digest, tier })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.plan_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudRegionPosture {
    pub region_digest: Digest,
}

impl RedisCloudRegionPosture {
    pub fn new(region: impl Into<String>) -> Result<Self> {
        let mut region = region.into();
        if !valid_identifier(&region, MAX_IDENTIFIER_BYTES) {
            region.zeroize();
            return Err(ModelError::InvalidIdentifier { field: "region" }.into());
        }
        let digest = Digest::from_parts("redis-cloud-region/v1", &[("region", region.clone())]);
        region.zeroize();
        Ok(Self {
            region_digest: digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisCloudReplicationMode {
    None,
    SingleZone,
    MultiZone,
    ActiveActive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudReplicationPosture {
    pub enabled: bool,
    pub mode: RedisCloudReplicationMode,
    pub replica_count: Option<u16>,
}

impl RedisCloudReplicationPosture {
    pub fn new(
        enabled: bool,
        mode: RedisCloudReplicationMode,
        replica_count: Option<u16>,
    ) -> Result<Self> {
        let posture = Self {
            enabled,
            mode,
            replica_count,
        };
        posture.validate()?;
        Ok(posture)
    }

    pub(crate) fn validate(self) -> Result<()> {
        if !self.enabled && self.replica_count.is_some_and(|count| count > 0) {
            Err(ModelError::InvalidPosture {
                field: "replica-count",
            }
            .into())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudShardingPosture {
    pub enabled: bool,
    pub shard_count: Option<u32>,
    pub cluster_api_enabled: bool,
}

impl RedisCloudShardingPosture {
    pub fn new(enabled: bool, shard_count: Option<u32>, cluster_api_enabled: bool) -> Result<Self> {
        let posture = Self {
            enabled,
            shard_count,
            cluster_api_enabled,
        };
        posture.validate()?;
        Ok(posture)
    }

    pub(crate) fn validate(self) -> Result<()> {
        if self.enabled {
            if self.shard_count.is_none_or(|count| count == 0) {
                return Err(ModelError::InvalidPosture { field: "sharding" }.into());
            }
        } else if self.shard_count.is_some_and(|count| count > 0) || self.cluster_api_enabled {
            return Err(ModelError::InvalidPosture { field: "sharding" }.into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudEndpointPosture {
    pub endpoint_count: u16,
    pub private_endpoint_present: bool,
    pub public_endpoint_present: bool,
    pub tls_required: bool,
    pub endpoint_digests: Vec<Digest>,
}

impl RedisCloudEndpointPosture {
    pub fn from_raw<I, S>(
        endpoints: I,
        private_endpoint_present: bool,
        public_endpoint_present: bool,
        tls_required: bool,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut endpoint_digests = Vec::new();
        for endpoint in endpoints {
            let mut endpoint = endpoint.into();
            if !valid_text(&endpoint, 2_048, false) {
                endpoint.zeroize();
                return Err(ModelError::InvalidPosture { field: "endpoint" }.into());
            }
            endpoint_digests.push(Digest::from_parts(
                "redis-cloud-endpoint/v1",
                &[("endpoint", endpoint.clone())],
            ));
            endpoint.zeroize();
        }
        let posture = Self {
            endpoint_count: endpoint_digests.len() as u16,
            private_endpoint_present,
            public_endpoint_present,
            tls_required,
            endpoint_digests,
        };
        posture.validate()?;
        Ok(posture)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if usize::from(self.endpoint_count) != self.endpoint_digests.len()
            || self
                .endpoint_digests
                .iter()
                .any(|digest| digest.validate().is_err())
            || self.endpoint_digests.is_empty()
                && (self.private_endpoint_present || self.public_endpoint_present)
        {
            Err(ModelError::InvalidPosture {
                field: "endpoint-count",
            }
            .into())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudSubscriptionPosture {
    pub account_digest: Digest,
    pub subscription_digest: Digest,
    pub status: RedisCloudResourceStatus,
    pub plan: RedisCloudPlanPosture,
    pub region_digests: Vec<Digest>,
    pub replication: RedisCloudReplicationPosture,
    pub revision_digest: Digest,
    pub metadata_digest: Digest,
}

impl RedisCloudSubscriptionPosture {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &RedisCloudDatabaseScope,
        status: RedisCloudResourceStatus,
        plan_identifier: impl Into<String>,
        plan_tier: RedisCloudPlanTier,
        regions: impl IntoIterator<Item = String>,
        replication: RedisCloudReplicationPosture,
        revision_token: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let plan = RedisCloudPlanPosture::new(plan_identifier, plan_tier)?;
        let region_digests = digest_regions(regions)?;
        let posture = Self {
            account_digest: scope.account().digest(),
            subscription_digest: scope.subscription().digest(),
            status,
            plan,
            region_digests,
            replication,
            revision_digest: Digest::from_bytes(revision_token.as_ref()),
            metadata_digest: Digest::from_text("unsealed-redis-cloud-subscription"),
        };
        let mut posture = posture;
        posture.metadata_digest = posture.calculate_metadata_digest();
        posture.validate()?;
        Ok(posture)
    }

    fn calculate_metadata_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-subscription-posture/v1",
            &[
                ("account", self.account_digest.as_str().to_owned()),
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("plan", self.plan.plan_digest.as_str().to_owned()),
                ("regions", join_digests(&self.region_digests)),
                ("replication", format!("{:?}", self.replication)),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account_digest.validate()?;
        self.subscription_digest.validate()?;
        self.plan.validate()?;
        self.replication.validate()?;
        validate_digest_list(&self.region_digests, MAX_REGIONS)?;
        self.revision_digest.validate()?;
        if self.metadata_digest != self.calculate_metadata_digest() {
            return Err(ModelError::InvalidPosture {
                field: "metadata-digest",
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn validate_against(&self, scope: &RedisCloudDatabaseScope) -> Result<()> {
        self.validate()?;
        if self.account_digest != scope.account().digest()
            || self.subscription_digest != scope.subscription().digest()
        {
            return Err(RedisCloudDatabaseResultError::ScopeDrift);
        }
        if scope
            .expected_subscription_revision()
            .is_some_and(|expected| expected != &self.revision_digest)
        {
            return Err(RedisCloudDatabaseResultError::StaleState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudDatabasePosture {
    pub account_digest: Digest,
    pub subscription_digest: Digest,
    pub database_digest: Digest,
    pub status: RedisCloudResourceStatus,
    pub plan: RedisCloudPlanPosture,
    pub region_digests: Vec<Digest>,
    pub sharding: RedisCloudShardingPosture,
    pub replication: RedisCloudReplicationPosture,
    pub endpoint_posture: RedisCloudEndpointPosture,
    pub revision_digest: Digest,
    pub metadata_digest: Digest,
}

impl RedisCloudDatabasePosture {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &RedisCloudDatabaseScope,
        status: RedisCloudResourceStatus,
        plan_identifier: impl Into<String>,
        plan_tier: RedisCloudPlanTier,
        regions: impl IntoIterator<Item = String>,
        sharding: RedisCloudShardingPosture,
        replication: RedisCloudReplicationPosture,
        endpoint_posture: RedisCloudEndpointPosture,
        revision_token: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let plan = RedisCloudPlanPosture::new(plan_identifier, plan_tier)?;
        let posture = Self {
            account_digest: scope.account().digest(),
            subscription_digest: scope.subscription().digest(),
            database_digest: scope.database().digest(),
            status,
            plan,
            region_digests: digest_regions(regions)?,
            sharding,
            replication,
            endpoint_posture,
            revision_digest: Digest::from_bytes(revision_token.as_ref()),
            metadata_digest: Digest::from_text("unsealed-redis-cloud-database"),
        };
        let mut posture = posture;
        posture.metadata_digest = posture.calculate_metadata_digest();
        posture.validate()?;
        Ok(posture)
    }

    fn calculate_metadata_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-database-posture/v1",
            &[
                ("account", self.account_digest.as_str().to_owned()),
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("database", self.database_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("plan", self.plan.plan_digest.as_str().to_owned()),
                ("regions", join_digests(&self.region_digests)),
                ("sharding", format!("{:?}", self.sharding)),
                ("replication", format!("{:?}", self.replication)),
                ("endpoint_posture", format!("{:?}", self.endpoint_posture)),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account_digest.validate()?;
        self.subscription_digest.validate()?;
        self.database_digest.validate()?;
        self.plan.validate()?;
        validate_digest_list(&self.region_digests, MAX_REGIONS)?;
        self.sharding.validate()?;
        self.replication.validate()?;
        self.endpoint_posture.validate()?;
        self.revision_digest.validate()?;
        if self.metadata_digest != self.calculate_metadata_digest() {
            return Err(ModelError::InvalidPosture {
                field: "metadata-digest",
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn validate_against(&self, scope: &RedisCloudDatabaseScope) -> Result<()> {
        self.validate()?;
        if self.account_digest != scope.account().digest()
            || self.subscription_digest != scope.subscription().digest()
            || self.database_digest != scope.database().digest()
        {
            return Err(RedisCloudDatabaseResultError::ScopeDrift);
        }
        if scope
            .expected_database_revision()
            .is_some_and(|expected| expected != &self.revision_digest)
        {
            return Err(RedisCloudDatabaseResultError::StaleState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum RedisCloudResponsePayload {
    Account { account_digest: Digest },
    Subscription(RedisCloudSubscriptionPosture),
    Database(RedisCloudDatabasePosture),
}

impl RedisCloudResponsePayload {
    pub(crate) fn validate_against(&self, scope: &RedisCloudDatabaseScope) -> Result<()> {
        match self {
            Self::Account { account_digest } => {
                account_digest.validate()?;
                if account_digest != &scope.account().digest() {
                    return Err(RedisCloudDatabaseResultError::ScopeDrift);
                }
            }
            Self::Subscription(posture) => posture.validate_against(scope)?,
            Self::Database(posture) => posture.validate_against(scope)?,
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisCloudEvidenceState {
    Ready,
    Partial,
    Stale,
    PaginationRejected,
    Truncated,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    ReplayConflict,
    RegistrationRevoked,
    RegistrationReversed,
}

impl RedisCloudEvidenceState {
    #[must_use]
    pub const fn can_be_adopted(self) -> bool {
        false
    }
    #[must_use]
    pub const fn is_review_eligible(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub redacted: bool,
}

impl RequestReceipt {
    pub fn new(
        operation: impl Into<String>,
        request_digest: Digest,
        path_digest: Digest,
        scope_digest: Digest,
    ) -> Result<Self> {
        let operation = operation.into();
        if !valid_identifier(&operation, MAX_IDENTIFIER_BYTES) {
            return Err(ModelError::InvalidText { field: "operation" }.into());
        }
        request_digest.validate()?;
        path_digest.validate()?;
        scope_digest.validate()?;
        Ok(Self {
            operation,
            request_digest,
            path_digest,
            scope_digest,
            redacted: true,
        })
    }

    pub(crate) fn validate(&self, scope: &RedisCloudDatabaseScope) -> Result<()> {
        if !self.redacted
            || !valid_identifier(&self.operation, MAX_IDENTIFIER_BYTES)
            || self.scope_digest != scope.digest()
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        self.request_digest.validate()?;
        self.path_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u16,
    pub cost_digest: Digest,
    pub estimate_only: bool,
    pub durable_provider_receipt: bool,
    pub redacted: bool,
}

impl CostReceipt {
    pub fn new(operation: impl Into<String>, response_bytes: u64) -> Result<Self> {
        let operation = operation.into();
        if !valid_identifier(&operation, MAX_IDENTIFIER_BYTES)
            || response_bytes > crate::MAX_RESPONSE_BYTES
        {
            return Err(if response_bytes > crate::MAX_RESPONSE_BYTES {
                RedisCloudDatabaseResultError::TruncatedEvidence
            } else {
                ModelError::InvalidText { field: "operation" }.into()
            });
        }
        let cost_digest = Digest::from_parts(
            "redis-cloud-cost-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("response_bytes", response_bytes.to_string()),
            ],
        );
        Ok(Self {
            operation,
            response_bytes,
            bounded_request_units: 1,
            cost_digest,
            estimate_only: true,
            durable_provider_receipt: false,
            redacted: true,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !self.redacted
            || !self.estimate_only
            || self.durable_provider_receipt
            || !valid_identifier(&self.operation, MAX_IDENTIFIER_BYTES)
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.bounded_request_units == 0
            || self.cost_digest
                != Digest::from_parts(
                    "redis-cloud-cost-receipt/v1",
                    &[
                        ("operation", self.operation.clone()),
                        ("response_bytes", self.response_bytes.to_string()),
                    ],
                )
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaquePageToken {
    pub token_digest: Digest,
    pub scope_digest: Digest,
    pub operation_digest: Digest,
    pub page_number: u16,
}

impl OpaquePageToken {
    pub fn new(
        opaque_token: impl Into<String>,
        scope: &RedisCloudDatabaseScope,
        operation: &str,
        page_number: u16,
    ) -> Result<Self> {
        let mut token = opaque_token.into();
        scope.validate()?;
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true)
            || page_number < 2
            || !valid_identifier(operation, MAX_IDENTIFIER_BYTES)
        {
            token.zeroize();
            return Err(RedisCloudDatabaseResultError::CursorMismatch);
        }
        let cursor = Self {
            token_digest: Digest::from_parts(
                "redis-cloud-opaque-page-token/v1",
                &[
                    ("token", token.clone()),
                    ("scope", scope.digest().as_str().to_owned()),
                    ("operation", operation.to_owned()),
                    ("page", page_number.to_string()),
                ],
            ),
            scope_digest: scope.digest(),
            operation_digest: Digest::from_text(operation),
            page_number,
        };
        token.zeroize();
        cursor.validate(scope, operation)?;
        Ok(cursor)
    }

    pub(crate) fn validate(&self, scope: &RedisCloudDatabaseScope, operation: &str) -> Result<()> {
        if self.page_number < 2
            || self.scope_digest != scope.digest()
            || self.operation_digest != Digest::from_text(operation)
        {
            return Err(RedisCloudDatabaseResultError::CursorMismatch);
        }
        self.token_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub page_number: u16,
    pub page_size: u16,
    pub next_cursor: Option<OpaquePageToken>,
    pub truncated: bool,
}

impl PageInfo {
    pub fn first(page_size: u16) -> Result<Self> {
        if page_size == 0 || page_size > crate::MAX_PAGE_SIZE {
            return Err(RedisCloudDatabaseResultError::CursorMismatch);
        }
        Ok(Self {
            page_number: 1,
            page_size,
            next_cursor: None,
            truncated: false,
        })
    }

    pub(crate) fn validate(&self, scope: &RedisCloudDatabaseScope, operation: &str) -> Result<()> {
        if self.page_number == 0
            || self.page_size == 0
            || self.page_size > crate::MAX_PAGE_SIZE
            || self.page_number > crate::MAX_PAGES
        {
            return Err(RedisCloudDatabaseResultError::PaginationRejected);
        }
        if let Some(cursor) = self.next_cursor.as_ref() {
            cursor.validate(scope, operation)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Redis Cloud identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Redis Cloud scope binding is invalid: {field}")]
    InvalidBinding { field: &'static str },
    #[error("opaque Redis Cloud SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Redis Cloud permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Redis Cloud posture metadata is invalid: {field}")]
    InvalidPosture { field: &'static str },
}

fn digest_regions(regions: impl IntoIterator<Item = String>) -> Result<Vec<Digest>> {
    let mut digests = Vec::new();
    for region in regions {
        digests.push(RedisCloudRegionPosture::new(region)?.region_digest);
    }
    if digests.is_empty() || digests.len() > MAX_REGIONS {
        return Err(ModelError::InvalidPosture { field: "regions" }.into());
    }
    Ok(digests)
}

fn validate_digest_list(values: &[Digest], max: usize) -> Result<()> {
    if values.is_empty()
        || values.len() > max
        || values.iter().any(|value| value.validate().is_err())
    {
        return Err(ModelError::InvalidPosture {
            field: "digest-list",
        }
        .into());
    }
    Ok(())
}

#[must_use]
pub(crate) fn join_digests<'a>(values: impl IntoIterator<Item = &'a Digest>) -> String {
    values
        .into_iter()
        .map(Digest::as_str)
        .collect::<Vec<_>>()
        .join("|")
}
