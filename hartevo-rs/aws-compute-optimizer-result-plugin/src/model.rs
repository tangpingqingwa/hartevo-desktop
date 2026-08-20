//! Typed, bounded, redacted Compute Optimizer evidence models.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
    PROVIDER_VERSION, REQUIRED_PERMISSIONS,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESOURCES: usize = 128;
pub const MAX_RECOMMENDATIONS_PER_PAGE: usize = 64;
pub const MAX_RECOMMENDATIONS: usize = 256;
pub const MAX_RESULT_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_RECOMMENDATION_WINDOW_SECONDS: i64 = 31 * 24 * 60 * 60;
pub const MAX_RECOMMENDATION_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_RETRY_AFTER_SECONDS: u64 = 3_600;
pub const MAX_LOOKBACK_DAYS: u16 = 90;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{0} is empty, malformed, or too long")]
    InvalidIdentifier(&'static str),
    #[error("AWS account id must contain exactly twelve digits")]
    InvalidAccountId,
    #[error("AWS region is invalid")]
    InvalidRegion,
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("the recommendation window is invalid or unbounded")]
    InvalidRecommendationWindow,
    #[error("the Compute Optimizer scope is invalid")]
    InvalidScope,
    #[error("the permission snapshot is invalid or over-privileged")]
    InvalidPermissions,
    #[error("the opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("the SecretReference does not belong to this scope")]
    SecretScopeMismatch,
    #[error("the SecretReference is revoked")]
    SecretRevoked,
    #[error("the SecretReference is already revoked")]
    AlreadyRevoked,
    #[error("the SecretReference is already active")]
    AlreadyActive,
    #[error("a bounded evidence collection exceeded its limit")]
    BoundsExceeded,
    #[error("the opaque pagination cursor is invalid or not bound to this request")]
    InvalidCursor,
    #[error("a duplicate resource or recommendation was returned")]
    DuplicateResource,
    #[error("a resource is not in the exact scope allowlist")]
    ResourceNotAllowlisted,
    #[error("the resource kind does not match the allowlisted operation")]
    ResourceKindMismatch,
    #[error("the evidence digest does not match immutable fields")]
    DigestMismatch,
    #[error("the timestamp is outside the closed recommendation window")]
    TimestampOutsideWindow,
    #[error("the recommendation is too old for the freshness fence")]
    RecommendationStale,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/+=@-~".contains(&byte))
}

pub(crate) fn valid_identifier_for_provider(value: &str) -> bool {
    valid_identifier(value)
}

fn valid_opaque_input(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| !byte.is_ascii_whitespace())
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        bytes.extend_from_slice(domain.as_bytes());
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
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

macro_rules! digest_identifier {
    ($name:ident, $domain:literal, $label:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier($label))
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_fields($domain, std::slice::from_ref(&self.0))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.digest().as_str())
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
    };
}

digest_identifier!(ProjectId, "aws-compute-optimizer-project/v1", "Project id");
digest_identifier!(MissionId, "aws-compute-optimizer-mission/v1", "Mission id");
digest_identifier!(
    WorkProductId,
    "aws-compute-optimizer-work-product/v1",
    "Work Product id"
);
digest_identifier!(
    ResourceId,
    "aws-compute-optimizer-resource-id/v1",
    "resource identifier"
);
digest_identifier!(
    RecommendationId,
    "aws-compute-optimizer-recommendation-id/v1",
    "recommendation identifier"
);

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidAccountId)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-account/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl Serialize for AwsAccountId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.digest().as_str())
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if (3..=63).contains(&value.len())
            && value.starts_with(|character: char| character.is_ascii_lowercase())
            && value.ends_with(|character: char| character.is_ascii_digit())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRegion)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! binding_type {
    ($name:ident, $id:ident, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            id: $id,
            revision: Revision,
        }

        impl $name {
            pub fn new(id: $id, revision: Revision) -> Self {
                Self { id, revision }
            }

            #[must_use]
            pub fn id(&self) -> &$id {
                &self.id
            }

            #[must_use]
            pub const fn revision(&self) -> Revision {
                self.revision
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_fields(
                    $domain,
                    &[
                        self.id.digest().as_str().to_owned(),
                        self.revision.get().to_string(),
                    ],
                )
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("idDigest", self.id.digest().as_str())?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }
    };
}

binding_type!(
    ProjectBinding,
    ProjectId,
    "aws-compute-optimizer-project-binding/v1"
);
binding_type!(
    MissionBinding,
    MissionId,
    "aws-compute-optimizer-mission-binding/v1"
);
binding_type!(
    WorkProductBinding,
    WorkProductId,
    "aws-compute-optimizer-work-product-binding/v1"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Granted,
    Withdrawn,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    pub consent_digest: Digest,
    pub revision: Revision,
    pub state: ConsentState,
}

impl ConsentScope {
    pub fn new(
        consent_digest: Digest,
        revision: Revision,
        state: ConsentState,
    ) -> Result<Self, ModelError> {
        if !valid_digest(consent_digest.as_str()) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            consent_digest,
            revision,
            state,
        })
    }

    pub fn for_layer_one(label: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        Self::new(
            Digest::from_text(label.as_ref()),
            Revision::new(revision)?,
            ConsentState::Granted,
        )
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, ConsentState::Granted)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if valid_digest(self.consent_digest.as_str()) && self.is_active() {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-consent/v1",
            &[
                self.consent_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    permissions: Vec<String>,
    revision: Revision,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(permissions: I, revision: Revision) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut permissions = permissions.into_iter().map(Into::into).collect::<Vec<_>>();
        permissions.sort_unstable();
        permissions.dedup();
        if permissions.is_empty()
            || permissions.iter().any(|permission| {
                permission.is_empty()
                    || permission.len() > MAX_IDENTIFIER_BYTES
                    || permission.chars().any(char::is_control)
            })
        {
            return Err(ModelError::InvalidPermissions);
        }
        let permission_digest = Digest::from_fields(
            "aws-compute-optimizer-permissions/v1",
            &permissions
                .iter()
                .cloned()
                .chain(std::iter::once(revision.get().to_string()))
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            revision,
            permission_digest,
        })
    }

    pub fn compute_optimizer_read(revision: Revision) -> Result<Self, ModelError> {
        Self::new(REQUIRED_PERMISSIONS.iter().copied(), revision)
    }

    #[must_use]
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn contains(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|candidate| candidate == permission)
    }

    #[must_use]
    pub fn contains_all_required(&self) -> bool {
        REQUIRED_PERMISSIONS
            .iter()
            .all(|permission| self.contains(permission))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.permissions.clone(), self.revision)?;
        if expected.permission_digest == self.permission_digest && self.contains_all_required() {
            Ok(())
        } else {
            Err(ModelError::InvalidPermissions)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Ec2Instance,
    AutoScalingGroup,
}

impl ResourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ec2Instance => "ec2_instance",
            Self::AutoScalingGroup => "auto_scaling_group",
        }
    }
}

pub type RecommendationResourceKind = ResourceKind;
pub type ResourceType = ResourceKind;
pub type AwsComputeOptimizerResourceKind = ResourceKind;

#[derive(Clone, Eq, PartialEq)]
pub struct ResourceSelector {
    kind: ResourceKind,
    id: ResourceId,
}

impl ResourceSelector {
    pub fn new(kind: ResourceKind, id: ResourceId) -> Self {
        Self { kind, id }
    }

    pub fn from_raw(kind: ResourceKind, id: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::new(kind, ResourceId::new(id)?))
    }

    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    #[must_use]
    pub fn id(&self) -> &ResourceId {
        &self.id
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-resource-selector/v1",
            &[
                self.kind.as_str().to_owned(),
                self.id.digest().as_str().to_owned(),
            ],
        )
    }
}

impl Serialize for ResourceSelector {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ResourceSelector", 2)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("resourceDigest", self.digest().as_str())?;
        state.end()
    }
}

impl fmt::Debug for ResourceSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceSelector")
            .field("kind", &self.kind)
            .field("resource_digest", &self.digest())
            .finish()
    }
}

pub type ResourceAllowlist = Vec<ResourceSelector>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendationWindow {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub window_digest: Digest,
}

impl RecommendationWindow {
    pub fn closed(from: DateTime<Utc>, to: DateTime<Utc>) -> Result<Self, ModelError> {
        let seconds = to.signed_duration_since(from).num_seconds();
        if seconds <= 0 || seconds > MAX_RECOMMENDATION_WINDOW_SECONDS {
            return Err(ModelError::InvalidRecommendationWindow);
        }
        let window_digest = Digest::from_fields(
            "aws-compute-optimizer-recommendation-window/v1",
            &[from.to_rfc3339(), to.to_rfc3339()],
        );
        Ok(Self {
            from,
            to,
            window_digest,
        })
    }

    #[must_use]
    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.from && timestamp <= self.to
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::closed(self.from, self.to)?;
        if expected.window_digest == self.window_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsComputeOptimizerScope {
    account: AwsAccountId,
    region: AwsRegion,
    resources: Vec<ResourceSelector>,
    recommendation_window: RecommendationWindow,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    work_product_revision: Revision,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    max_recommendation_age_seconds: i64,
    scope_digest: Digest,
}

impl AwsComputeOptimizerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        mut resources: Vec<ResourceSelector>,
        recommendation_window: RecommendationWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        work_product_revision: Revision,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        max_recommendation_age: Duration,
    ) -> Result<Self, ModelError> {
        resources.sort_by_key(ResourceSelector::digest);
        if resources.is_empty() || resources.len() > MAX_RESOURCES {
            return Err(ModelError::BoundsExceeded);
        }
        let mut seen = BTreeSet::new();
        if resources
            .iter()
            .any(|resource| !seen.insert(resource.digest()))
        {
            return Err(ModelError::DuplicateResource);
        }
        recommendation_window.validate()?;
        let max_recommendation_age_seconds = max_recommendation_age.num_seconds();
        if !(1..=MAX_RECOMMENDATION_AGE_SECONDS).contains(&max_recommendation_age_seconds) {
            return Err(ModelError::InvalidRecommendationWindow);
        }
        permission_snapshot.validate()?;
        consent.validate()?;
        let scope_digest = Digest::from_fields(
            "aws-compute-optimizer-scope/v1",
            &[
                account.digest().as_str().to_owned(),
                region.as_str().to_owned(),
                resources
                    .iter()
                    .map(ResourceSelector::digest)
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
                recommendation_window.window_digest.as_str().to_owned(),
                project.digest().as_str().to_owned(),
                mission.digest().as_str().to_owned(),
                work_product.digest().as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_snapshot.permission_digest().as_str().to_owned(),
                consent.digest().as_str().to_owned(),
                max_recommendation_age_seconds.to_string(),
            ],
        );
        Ok(Self {
            account,
            region,
            resources,
            recommendation_window,
            project,
            mission,
            work_product,
            work_product_revision,
            permission_snapshot,
            consent,
            max_recommendation_age_seconds,
            scope_digest,
        })
    }

    #[must_use]
    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn resources(&self) -> &[ResourceSelector] {
        &self.resources
    }

    #[must_use]
    pub fn resource_allowlist(&self) -> &[ResourceSelector] {
        &self.resources
    }

    #[must_use]
    pub fn resource_allowlist_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-resource-allowlist/v1",
            &self
                .resources
                .iter()
                .map(ResourceSelector::digest)
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[must_use]
    pub fn contains_resource(&self, resource: &ResourceSelector) -> bool {
        self.resources.iter().any(|candidate| candidate == resource)
    }

    #[must_use]
    pub fn recommendation_window(&self) -> &RecommendationWindow {
        &self.recommendation_window
    }

    #[must_use]
    pub const fn max_recommendation_age_seconds(&self) -> i64 {
        self.max_recommendation_age_seconds
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
    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.account.clone(),
            self.region.clone(),
            self.resources.clone(),
            self.recommendation_window.clone(),
            self.project.clone(),
            self.mission.clone(),
            self.work_product.clone(),
            self.work_product_revision,
            self.permission_snapshot.clone(),
            self.consent.clone(),
            Duration::seconds(self.max_recommendation_age_seconds),
        )?;
        if expected.scope_digest == self.scope_digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

impl Serialize for AwsComputeOptimizerScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsComputeOptimizerScope", 13)?;
        state.serialize_field("accountDigest", self.account.digest().as_str())?;
        state.serialize_field("region", &self.region)?;
        state.serialize_field("resourceAllowlist", &self.resources)?;
        state.serialize_field("recommendationWindow", &self.recommendation_window)?;
        state.serialize_field("projectDigest", self.project.digest().as_str())?;
        state.serialize_field("missionDigest", self.mission.digest().as_str())?;
        state.serialize_field("workProductDigest", self.work_product.digest().as_str())?;
        state.serialize_field("workProductRevision", &self.work_product_revision)?;
        state.serialize_field(
            "permissionDigest",
            self.permission_snapshot.permission_digest(),
        )?;
        state.serialize_field("consentDigest", &self.consent.digest())?;
        state.serialize_field(
            "maxRecommendationAgeSeconds",
            &self.max_recommendation_age_seconds,
        )?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigV4SigningService {
    ComputeOptimizer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretReferenceState {
    Active,
    Revoked,
}

/// Opaque host-owned SigV4 reference. It intentionally has no `Serialize`,
/// `Deserialize`, or `Display` implementation and stores only a digest.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    signing_service: SigV4SigningService,
    state: SecretReferenceState,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl AsRef<str>,
        scope: &AwsComputeOptimizerScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let opaque_handle = opaque_handle.as_ref();
        if !valid_opaque_input(opaque_handle) {
            return Err(ModelError::InvalidSecretReference);
        }
        scope.validate()?;
        Ok(Self {
            reference_digest: Digest::from_fields(
                "aws-compute-optimizer-secret-reference/v1",
                &[
                    opaque_handle.to_owned(),
                    scope.scope_digest().as_str().to_owned(),
                    revision.get().to_string(),
                ],
            ),
            scope_digest: scope.scope_digest().clone(),
            revision,
            signing_service: SigV4SigningService::ComputeOptimizer,
            state: SecretReferenceState::Active,
        })
    }

    pub fn sigv4(
        opaque_handle: impl AsRef<str>,
        scope: &AwsComputeOptimizerScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_handle, scope, revision)
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
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn signing_service(&self) -> SigV4SigningService {
        self.signing_service
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SecretReferenceState::Active)
    }

    pub fn validate_for_scope(&self, scope: &AwsComputeOptimizerScope) -> Result<(), ModelError> {
        scope.validate()?;
        if !self.is_active() {
            return Err(ModelError::SecretRevoked);
        }
        if self.scope_digest != *scope.scope_digest()
            || !valid_digest(self.reference_digest.as_str())
        {
            return Err(ModelError::SecretScopeMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if !self.is_active() {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = SecretReferenceState::Revoked;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.is_active() {
            return Err(ModelError::AlreadyActive);
        }
        self.state = SecretReferenceState::Active;
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("signing_service", &self.signing_service)
            .field("active", &self.is_active())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
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

impl Serialize for TransportProvenance {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

pub type ProviderProvenance = TransportProvenance;

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageCursor {
    token_digest: Digest,
    scope_digest: Digest,
    resource_kind: ResourceKind,
    page_number: u16,
}

impl OpaquePageCursor {
    pub fn new(
        opaque_token: impl AsRef<str>,
        scope: &AwsComputeOptimizerScope,
        resource_kind: ResourceKind,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        if !valid_opaque_input(opaque_token.as_ref())
            || !(2..=MAX_RESULT_PAGES).contains(&page_number)
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            token_digest: Digest::from_fields(
                "aws-compute-optimizer-page-token/v1",
                &[
                    opaque_token.as_ref().to_owned(),
                    scope.scope_digest().as_str().to_owned(),
                    resource_kind.as_str().to_owned(),
                ],
            ),
            scope_digest: scope.scope_digest().clone(),
            resource_kind,
            page_number,
        })
    }

    #[must_use]
    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        scope: &AwsComputeOptimizerScope,
        resource_kind: ResourceKind,
    ) -> Result<(), ModelError> {
        if self.scope_digest == *scope.scope_digest()
            && self.resource_kind == resource_kind
            && (2..=MAX_RESULT_PAGES).contains(&self.page_number)
            && valid_digest(self.token_digest.as_str())
        {
            Ok(())
        } else {
            Err(ModelError::InvalidCursor)
        }
    }
}

impl Serialize for OpaquePageCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaquePageCursor", 4)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("resourceKind", &self.resource_kind)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

impl fmt::Debug for OpaquePageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageCursor")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("resource_kind", &self.resource_kind)
            .field("page_number", &self.page_number)
            .finish()
    }
}

pub type PageCursor = OpaquePageCursor;
pub type OpaqueCursor = OpaquePageCursor;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationStatus {
    Optimized,
    Overprovisioned,
    Underprovisioned,
    NotOptimized,
    NotAvailable,
    Unknown,
}

impl RecommendationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Optimized => "optimized",
            Self::Overprovisioned => "overprovisioned",
            Self::Underprovisioned => "underprovisioned",
            Self::NotOptimized => "not_optimized",
            Self::NotAvailable => "not_available",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeOptimizerRecommendation {
    pub scope_digest: Digest,
    pub resource: ResourceSelector,
    pub recommendation_id: Digest,
    pub status: RecommendationStatus,
    pub observed_at: DateTime<Utc>,
    pub lookback_days: u16,
    pub current_configuration_digest: Digest,
    pub recommended_configuration_digest: Digest,
    pub recommendation_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl ComputeOptimizerRecommendation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsComputeOptimizerScope,
        resource: ResourceSelector,
        recommendation_id: RecommendationId,
        status: RecommendationStatus,
        observed_at: DateTime<Utc>,
        lookback_days: u16,
        current_configuration_digest: Digest,
        recommended_configuration_digest: Digest,
    ) -> Result<Self, ModelError> {
        if !scope.contains_resource(&resource) {
            return Err(ModelError::ResourceNotAllowlisted);
        }
        if !(1..=MAX_LOOKBACK_DAYS).contains(&lookback_days)
            || !valid_digest(current_configuration_digest.as_str())
            || !valid_digest(recommended_configuration_digest.as_str())
        {
            return Err(ModelError::BoundsExceeded);
        }
        let mut recommendation = Self {
            scope_digest: scope.scope_digest().clone(),
            resource,
            recommendation_id: recommendation_id.digest(),
            status,
            observed_at,
            lookback_days,
            current_configuration_digest,
            recommended_configuration_digest,
            recommendation_digest: Digest::from_text("unsealed-compute-optimizer-recommendation"),
            connected: false,
            native: false,
            provider_receipt: false,
        };
        recommendation.recommendation_digest = recommendation.calculate_digest();
        Ok(recommendation)
    }

    pub fn from_raw_id(
        scope: &AwsComputeOptimizerScope,
        resource: ResourceSelector,
        raw_recommendation_id: impl AsRef<str>,
        status: RecommendationStatus,
        observed_at: DateTime<Utc>,
        lookback_days: u16,
        current_configuration: impl AsRef<str>,
        recommended_configuration: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            resource,
            RecommendationId::new(raw_recommendation_id.as_ref().to_owned())?,
            status,
            observed_at,
            lookback_days,
            Digest::from_text(current_configuration.as_ref()),
            Digest::from_text(recommended_configuration.as_ref()),
        )
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.recommendation_digest
    }

    #[must_use]
    pub fn resource_digest(&self) -> Digest {
        self.resource.digest()
    }

    #[must_use]
    pub fn has_capacity_change_signal(&self) -> bool {
        matches!(
            self.status,
            RecommendationStatus::Overprovisioned
                | RecommendationStatus::Underprovisioned
                | RecommendationStatus::NotOptimized
        )
    }

    pub fn validate_integrity(&self, scope: &AwsComputeOptimizerScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || !scope.contains_resource(&self.resource)
            || !valid_digest(self.recommendation_id.as_str())
            || !valid_digest(self.current_configuration_digest.as_str())
            || !valid_digest(self.recommended_configuration_digest.as_str())
            || !(1..=MAX_LOOKBACK_DAYS).contains(&self.lookback_days)
            || self.connected
            || self.native
            || self.provider_receipt
            || self.recommendation_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-recommendation/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.resource.digest().as_str().to_owned(),
                self.recommendation_id.as_str().to_owned(),
                self.status.as_str().to_owned(),
                self.observed_at.to_rfc3339(),
                self.lookback_days.to_string(),
                self.current_configuration_digest.as_str().to_owned(),
                self.recommended_configuration_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    Stale,
    ResourceNotFound,
    AccessLost,
    Throttled,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
    Timeout,
    AccessLost,
    BlockedEnv,
    InvalidResponse,
    Partial,
    Stale,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub class: FailureClass,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub diagnostic_digest: Digest,
    pub blocked_env: bool,
}

impl FailureEvidence {
    #[must_use]
    pub fn new(
        class: FailureClass,
        status_code: Option<u16>,
        retry_after_seconds: Option<u64>,
        diagnostic: impl AsRef<[u8]>,
        blocked_env: bool,
    ) -> Self {
        Self {
            class,
            status_code,
            retry_after_seconds: retry_after_seconds
                .map(|value| value.min(MAX_RETRY_AFTER_SECONDS)),
            diagnostic_digest: Digest::from_text(diagnostic),
            blocked_env,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsComputeOptimizerEvidence {
    pub scope_digest: Digest,
    pub recommendation_window: RecommendationWindow,
    pub recommendations: Vec<ComputeOptimizerRecommendation>,
    pub recommendation_digest: Digest,
    pub pages_read: u16,
    pub status: RecommendationStatus,
    pub state: EvidenceState,
    pub provenance: TransportProvenance,
    pub failure: Option<FailureEvidence>,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl AwsComputeOptimizerEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsComputeOptimizerScope,
        recommendations: Vec<ComputeOptimizerRecommendation>,
        pages_read: u16,
        status: RecommendationStatus,
        state: EvidenceState,
        provenance: TransportProvenance,
        failure: Option<FailureEvidence>,
    ) -> Result<Self, ModelError> {
        if recommendations.len() > MAX_RECOMMENDATIONS || pages_read > MAX_RESULT_PAGES * 2 {
            return Err(ModelError::BoundsExceeded);
        }
        if state == EvidenceState::Complete && failure.is_some() {
            return Err(ModelError::DigestMismatch);
        }
        for recommendation in &recommendations {
            recommendation.validate_integrity(scope)?;
            if !scope
                .recommendation_window
                .contains(recommendation.observed_at)
            {
                return Err(ModelError::TimestampOutsideWindow);
            }
        }
        let mut evidence = Self {
            scope_digest: scope.scope_digest().clone(),
            recommendation_window: scope.recommendation_window.clone(),
            recommendations,
            recommendation_digest: Digest::from_text("unsealed-compute-optimizer-recommendations"),
            pages_read,
            status,
            state,
            provenance,
            failure,
            evidence_digest: Digest::from_text("unsealed-compute-optimizer-evidence"),
            connected: false,
            native: false,
            provider_receipt: false,
        };
        evidence.recommendation_digest = evidence.calculate_recommendation_digest();
        evidence.evidence_digest = evidence.calculate_digest();
        Ok(evidence)
    }

    #[must_use]
    pub fn has_capacity_change_signal(&self) -> bool {
        self.recommendations
            .iter()
            .any(ComputeOptimizerRecommendation::has_capacity_change_signal)
    }

    pub fn validate_integrity(&self, scope: &AwsComputeOptimizerScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || self.recommendation_window != scope.recommendation_window
            || self.recommendations.len() > MAX_RECOMMENDATIONS
            || self.pages_read > MAX_RESULT_PAGES * 2
            || self.provenance.is_native()
            || self.connected
            || self.native
            || self.provider_receipt
            || self.recommendation_digest != self.calculate_recommendation_digest()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        for recommendation in &self.recommendations {
            recommendation.validate_integrity(scope)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-evidence/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.recommendation_window.window_digest.as_str().to_owned(),
                self.recommendations
                    .iter()
                    .map(|recommendation| recommendation.digest().as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.recommendation_digest.as_str().to_owned(),
                self.pages_read.to_string(),
                self.status.as_str().to_owned(),
                format!("{:?}", self.state),
                self.provenance.as_str().to_owned(),
                self.failure.as_ref().map_or_else(String::new, |failure| {
                    Digest::from_fields(
                        "aws-compute-optimizer-failure/v1",
                        &[
                            format!("{:?}", failure.class),
                            failure
                                .status_code
                                .map_or_else(String::new, |value| value.to_string()),
                            failure
                                .retry_after_seconds
                                .map_or_else(String::new, |value| value.to_string()),
                            failure.diagnostic_digest.as_str().to_owned(),
                            failure.blocked_env.to_string(),
                        ],
                    )
                    .as_str()
                    .to_owned()
                }),
            ],
        )
    }

    #[must_use]
    pub fn recommendation_digest(&self) -> &Digest {
        &self.recommendation_digest
    }

    fn calculate_recommendation_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-recommendations/v1",
            &self
                .recommendations
                .iter()
                .map(|recommendation| recommendation.digest().as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    #[must_use]
    pub fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_fields(
            "aws-compute-optimizer-registration-transition/v1",
            &[
                format!("{previous_status:?}"),
                format!("{new_status:?}"),
                registration_digest.as_str().to_owned(),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsComputeOptimizerObservationReceipt {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub receipt_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl AwsComputeOptimizerObservationReceipt {
    #[must_use]
    pub fn new(
        idempotency_key_digest: Digest,
        proposal_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
        provenance: TransportProvenance,
        replayed: bool,
    ) -> Self {
        let receipt_digest = Digest::from_fields(
            "aws-compute-optimizer-observation-receipt/v1",
            &[
                idempotency_key_digest.as_str().to_owned(),
                proposal_digest.as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                registration_digest.as_str().to_owned(),
                provenance.as_str().to_owned(),
                replayed.to_string(),
            ],
        );
        Self {
            idempotency_key_digest,
            proposal_digest,
            scope_digest,
            registration_digest,
            provenance,
            replayed,
            receipt_digest,
            connected: false,
            native: false,
            provider_receipt: false,
        }
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.idempotency_key_digest.clone(),
            self.proposal_digest.clone(),
            self.scope_digest.clone(),
            self.registration_digest.clone(),
            self.provenance,
            self.replayed,
        );
        if self.connected
            || self.native
            || self.provider_receipt
            || self.receipt_digest != expected.receipt_digest
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn as_replayed(&self) -> Self {
        Self::new(
            self.idempotency_key_digest.clone(),
            self.proposal_digest.clone(),
            self.scope_digest.clone(),
            self.registration_digest.clone(),
            self.provenance,
            true,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsComputeOptimizerProposal {
    pub scope_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: AwsComputeOptimizerEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub savings_guarantee: bool,
    pub resource_resize: bool,
    pub outcome_adopted: bool,
}

impl AwsComputeOptimizerProposal {
    #[must_use]
    pub fn new(
        scope: &AwsComputeOptimizerScope,
        registration_digest: Digest,
        evidence: AwsComputeOptimizerEvidence,
        proposed_at: DateTime<Utc>,
    ) -> Self {
        let mut proposal = Self {
            scope_digest: scope.scope_digest().clone(),
            project: scope.project().clone(),
            mission: scope.mission().clone(),
            work_product: scope.work_product().clone(),
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::from_text("unsealed-compute-optimizer-proposal"),
            review_only: true,
            read_only: true,
            connected: false,
            native: false,
            savings_guarantee: false,
            resource_resize: false,
            outcome_adopted: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    #[must_use]
    pub fn state(&self) -> EvidenceState {
        self.evidence.state
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        self.review_only
    }

    #[must_use]
    pub fn review_eligible(&self) -> bool {
        self.evidence.state == EvidenceState::Complete
            && self.evidence.failure.is_none()
            && self.review_only
            && self.read_only
    }

    pub fn validate_integrity(&self, scope: &AwsComputeOptimizerScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || self.project != *scope.project()
            || self.mission != *scope.mission()
            || self.work_product != *scope.work_product()
            || !self.review_only
            || !self.read_only
            || self.connected
            || self.native
            || self.savings_guarantee
            || self.resource_resize
            || self.outcome_adopted
            || self.evidence.validate_integrity(scope).is_err()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-proposal/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.project.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.evidence.evidence_digest.as_str().to_owned(),
                self.proposed_at.to_rfc3339(),
                self.registration_digest.as_str().to_owned(),
                self.review_only.to_string(),
                self.read_only.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
                self.savings_guarantee.to_string(),
                self.resource_resize.to_string(),
                self.outcome_adopted.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsComputeOptimizerVerificationReport {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub verification_digest: Digest,
    pub state: EvidenceState,
    pub valid: bool,
    pub connected: bool,
    pub native: bool,
    pub outcome_adopted: bool,
}

impl AwsComputeOptimizerVerificationReport {
    #[must_use]
    pub fn from_proposal(proposal: &AwsComputeOptimizerProposal) -> Self {
        let valid = proposal.review_eligible();
        let verification_digest = Digest::from_fields(
            "aws-compute-optimizer-verification/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                proposal.evidence.evidence_digest.as_str().to_owned(),
                format!("{:?}", proposal.state()),
                valid.to_string(),
            ],
        );
        Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            verification_digest,
            state: proposal.state(),
            valid,
            connected: false,
            native: false,
            outcome_adopted: false,
        }
    }
}

/// Public aliases retained for callers that prefer shorter names.
pub type Recommendation = ComputeOptimizerRecommendation;
pub type AwsComputeOptimizerRecommendation = ComputeOptimizerRecommendation;
pub type Ec2InstanceRecommendation = ComputeOptimizerRecommendation;
pub type AutoScalingGroupRecommendation = ComputeOptimizerRecommendation;
pub type Evidence = AwsComputeOptimizerEvidence;
pub type Proposal = AwsComputeOptimizerProposal;
pub type ObservationReceipt = AwsComputeOptimizerObservationReceipt;
pub type VerificationReport = AwsComputeOptimizerVerificationReport;

// Keep these imports used by generated registration/debug consumers and make
// the binding visible in one place for contract auditors.
#[allow(dead_code)]
fn _contract_binding_material() -> [&'static str; 7] {
    [
        CONSUMER_ID,
        CONTRACT_VERSION,
        PLUGIN_VERSION,
        PROVIDER_API_REVISION,
        PROVIDER_ID,
        PROVIDER_VERSION,
        REQUIRED_PERMISSIONS[0],
    ]
}
