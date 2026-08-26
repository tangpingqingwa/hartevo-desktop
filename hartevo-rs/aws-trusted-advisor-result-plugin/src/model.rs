use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::REQUIRED_PERMISSIONS;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CHECK_DEFINITIONS: usize = 64;
pub const MAX_RESULT_PAGES: u16 = 4;
pub const MAX_FLAGGED_RESOURCES_PER_PAGE: usize = 64;
pub const MAX_FLAGGED_RESOURCES: usize = 128;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_RETRY_AFTER_SECONDS: u64 = 3600;
pub const MAX_REFRESH_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const DEFAULT_REFRESH_AGE_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{0} is empty, malformed, or too long")]
    InvalidIdentifier(&'static str),
    #[error("AWS account id must contain exactly twelve digits")]
    InvalidAccountId,
    #[error("AWS Support endpoint region must be us-east-1")]
    InvalidSupportEndpointRegion,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid or consent is not active")]
    InvalidScope,
    #[error("permission snapshot is invalid or incomplete")]
    InvalidPermissions,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("SecretReference does not belong to this scope")]
    SecretScopeMismatch,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("SecretReference is already revoked")]
    AlreadyRevoked,
    #[error("SecretReference is already active")]
    AlreadyActive,
    #[error("response or collection exceeds a Layer-1 bound")]
    BoundsExceeded,
    #[error("timestamp is invalid or outside the bounded observation window")]
    InvalidTimestamp,
    #[error("page cursor does not match the requested scope or check")]
    InvalidCursor,
    #[error("duplicate flagged-resource digest")]
    DuplicateFlaggedResource,
    #[error("digest does not match immutable evidence fields")]
    DigestMismatch,
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
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
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

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_opaque_input(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

macro_rules! digest_identifier {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier(stringify!($name)))
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

digest_identifier!(CheckId, "aws-trusted-advisor-check-id/v1");
digest_identifier!(ProjectId, "aws-trusted-advisor-project-id/v1");
digest_identifier!(MissionId, "aws-trusted-advisor-mission-id/v1");
digest_identifier!(WorkProductId, "aws-trusted-advisor-work-product-id/v1");

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
            "aws-trusted-advisor-account/v1",
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
        let valid = (3..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_lowercase())
            && value
                .chars()
                .last()
                .is_some_and(|character| character.is_ascii_digit());
        if valid {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier("AWS region"))
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportPlan {
    Basic,
    Developer,
    Business,
    EnterpriseOnRamp,
    Enterprise,
    Unknown,
}

impl SupportPlan {
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(
            self,
            Self::Business | Self::EnterpriseOnRamp | Self::Enterprise
        )
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Developer => "developer",
            Self::Business => "business",
            Self::EnterpriseOnRamp => "enterprise_on_ramp",
            Self::Enterprise => "enterprise",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedAdvisorCategory {
    CostOptimizing,
    Performance,
    Security,
    FaultTolerance,
    ServiceLimits,
    OperationalExcellence,
}

impl TrustedAdvisorCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CostOptimizing => "cost_optimizing",
            Self::Performance => "performance",
            Self::Security => "security",
            Self::FaultTolerance => "fault_tolerance",
            Self::ServiceLimits => "service_limits",
            Self::OperationalExcellence => "operational_excellence",
        }
    }

    #[must_use]
    pub const fn impact_class(self) -> ImpactClass {
        match self {
            Self::CostOptimizing => ImpactClass::Cost,
            Self::Security => ImpactClass::Security,
            Self::FaultTolerance => ImpactClass::Reliability,
            Self::Performance => ImpactClass::Performance,
            Self::ServiceLimits => ImpactClass::ServiceLimits,
            Self::OperationalExcellence => ImpactClass::OperationalExcellence,
        }
    }
}

pub type AwsTrustedAdvisorCategory = TrustedAdvisorCategory;
pub type CheckCategory = TrustedAdvisorCategory;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactClass {
    Cost,
    Security,
    Reliability,
    Performance,
    ServiceLimits,
    OperationalExcellence,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationStatus {
    Ok,
    Warning,
    Error,
    NotAvailable,
    Unknown,
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

binding_type!(ProjectBinding, ProjectId, "aws-trusted-advisor-project/v1");
binding_type!(MissionBinding, MissionId, "aws-trusted-advisor-mission/v1");
binding_type!(
    WorkProductBinding,
    WorkProductId,
    "aws-trusted-advisor-work-product/v1"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Granted,
    Withdrawn,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
        if !is_digest(consent_digest.as_str()) {
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
        if !is_digest(self.consent_digest.as_str()) || !self.is_active() {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-consent/v1",
            &[
                self.consent_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
                    || permission.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(ModelError::InvalidPermissions);
        }
        let permission_digest = Digest::from_fields(
            "aws-trusted-advisor-permissions/v1",
            &permissions
                .iter()
                .chain(std::iter::once(&revision.get().to_string()))
                .cloned()
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            revision,
            permission_digest,
        })
    }

    pub fn trusted_advisor_read(revision: Revision) -> Result<Self, ModelError> {
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
        if expected.permission_digest != self.permission_digest || !self.contains_all_required() {
            Err(ModelError::InvalidPermissions)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsTrustedAdvisorScope {
    account: AwsAccountId,
    support_plan: SupportPlan,
    region: AwsRegion,
    check_id: CheckId,
    category: TrustedAdvisorCategory,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    work_product_revision: Revision,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    max_refresh_age_seconds: i64,
    scope_digest: Digest,
}

impl AwsTrustedAdvisorScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        support_plan: SupportPlan,
        region: AwsRegion,
        check_id: CheckId,
        category: TrustedAdvisorCategory,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        work_product_revision: Revision,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        max_refresh_age: Duration,
    ) -> Result<Self, ModelError> {
        let max_refresh_age_seconds = max_refresh_age.num_seconds();
        if region.as_str() != "us-east-1" {
            return Err(ModelError::InvalidSupportEndpointRegion);
        }
        if !(1..=MAX_REFRESH_AGE_SECONDS).contains(&max_refresh_age_seconds) {
            return Err(ModelError::InvalidTimestamp);
        }
        permission_snapshot.validate()?;
        consent.validate()?;
        let scope_digest = Digest::from_fields(
            "aws-trusted-advisor-scope/v1",
            &[
                account.digest().as_str().to_owned(),
                support_plan.as_str().to_owned(),
                region.as_str().to_owned(),
                check_id.digest().as_str().to_owned(),
                category.as_str().to_owned(),
                project.digest().as_str().to_owned(),
                mission.digest().as_str().to_owned(),
                work_product.digest().as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_snapshot.permission_digest().as_str().to_owned(),
                consent.digest().as_str().to_owned(),
                max_refresh_age_seconds.to_string(),
            ],
        );
        Ok(Self {
            account,
            support_plan,
            region,
            check_id,
            category,
            project,
            mission,
            work_product,
            work_product_revision,
            permission_snapshot,
            consent,
            max_refresh_age_seconds,
            scope_digest,
        })
    }

    #[must_use]
    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    #[must_use]
    pub const fn support_plan(&self) -> SupportPlan {
        self.support_plan
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn check_id(&self) -> &CheckId {
        &self.check_id
    }

    #[must_use]
    pub const fn category(&self) -> TrustedAdvisorCategory {
        self.category
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
    pub const fn max_refresh_age_seconds(&self) -> i64 {
        self.max_refresh_age_seconds
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.region.as_str() != "us-east-1"
            || !(1..=MAX_REFRESH_AGE_SECONDS).contains(&self.max_refresh_age_seconds)
            || self.scope_digest
                != Self::new(
                    self.account.clone(),
                    self.support_plan,
                    self.region.clone(),
                    self.check_id.clone(),
                    self.category,
                    self.project.clone(),
                    self.mission.clone(),
                    self.work_product.clone(),
                    self.work_product_revision,
                    self.permission_snapshot.clone(),
                    self.consent.clone(),
                    Duration::seconds(self.max_refresh_age_seconds),
                )?
                .scope_digest
        {
            return Err(ModelError::InvalidScope);
        }
        self.permission_snapshot.validate()?;
        self.consent.validate()
    }
}

impl Serialize for AwsTrustedAdvisorScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsTrustedAdvisorScope", 12)?;
        state.serialize_field("accountDigest", self.account.digest().as_str())?;
        state.serialize_field("supportPlan", &self.support_plan)?;
        state.serialize_field("supportEndpointRegion", &self.region)?;
        state.serialize_field("checkId", &self.check_id)?;
        state.serialize_field("category", &self.category)?;
        state.serialize_field("projectDigest", self.project.digest().as_str())?;
        state.serialize_field("missionDigest", self.mission.digest().as_str())?;
        state.serialize_field("workProductDigest", self.work_product.digest().as_str())?;
        state.serialize_field("workProductRevision", &self.work_product_revision)?;
        state.serialize_field(
            "permissionDigest",
            self.permission_snapshot.permission_digest(),
        )?;
        state.serialize_field("consentDigest", &self.consent.digest())?;
        state.serialize_field("maxRefreshAgeSeconds", &self.max_refresh_age_seconds)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigV4SigningService {
    AwsSupport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretReferenceState {
    Active,
    Revoked,
}

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
        scope: &AwsTrustedAdvisorScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let opaque_handle = opaque_handle.as_ref();
        if !valid_opaque_input(opaque_handle) {
            return Err(ModelError::InvalidSecretReference);
        }
        scope.validate()?;
        Ok(Self {
            reference_digest: Digest::from_fields(
                "aws-trusted-advisor-secret-reference/v1",
                &[
                    opaque_handle.to_owned(),
                    scope.scope_digest().as_str().to_owned(),
                    revision.get().to_string(),
                ],
            ),
            scope_digest: scope.scope_digest().clone(),
            revision,
            signing_service: SigV4SigningService::AwsSupport,
            state: SecretReferenceState::Active,
        })
    }

    pub fn sigv4(
        opaque_handle: impl AsRef<str>,
        scope: &AwsTrustedAdvisorScope,
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

    pub fn validate_for_scope(&self, scope: &AwsTrustedAdvisorScope) -> Result<(), ModelError> {
        scope.validate()?;
        if !self.is_active() {
            return Err(ModelError::SecretRevoked);
        }
        if self.scope_digest != *scope.scope_digest() {
            return Err(ModelError::SecretScopeMismatch);
        }
        if !is_digest(self.reference_digest.as_str()) {
            return Err(ModelError::InvalidSecretReference);
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
pub struct PageCursor {
    token_digest: Digest,
    scope_digest: Digest,
    check_digest: Digest,
    page_number: u16,
}

impl PageCursor {
    pub fn new(
        opaque_token: impl AsRef<str>,
        scope: &AwsTrustedAdvisorScope,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        if !valid_opaque_input(opaque_token.as_ref())
            || !(2..=MAX_RESULT_PAGES).contains(&page_number)
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            token_digest: Digest::from_fields(
                "aws-trusted-advisor-page-token/v1",
                &[
                    opaque_token.as_ref().to_owned(),
                    scope.scope_digest().as_str().to_owned(),
                ],
            ),
            scope_digest: scope.scope_digest().clone(),
            check_digest: scope.check_id().digest(),
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
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(&self, scope: &AwsTrustedAdvisorScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || self.check_digest != scope.check_id().digest()
            || !(2..=MAX_RESULT_PAGES).contains(&self.page_number)
        {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(())
        }
    }
}

impl Serialize for PageCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PageCursor", 4)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("checkDigest", &self.check_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("check_digest", &self.check_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

pub type OpaquePageToken = PageCursor;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshState {
    NotRunning,
    Enqueued,
    InProgress,
    Complete,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategorySummary {
    pub category: TrustedAdvisorCategory,
    pub status: RecommendationStatus,
    pub impact: ImpactClass,
    pub flagged_count: u32,
    pub resource_count: u32,
}

impl CategorySummary {
    pub fn new(
        category: TrustedAdvisorCategory,
        status: RecommendationStatus,
        flagged_count: u32,
        resource_count: u32,
    ) -> Result<Self, ModelError> {
        if flagged_count > 128 || resource_count > 1_000_000 {
            return Err(ModelError::BoundsExceeded);
        }
        Ok(Self {
            category,
            status,
            impact: category.impact_class(),
            flagged_count,
            resource_count,
        })
    }

    pub fn empty(category: TrustedAdvisorCategory) -> Self {
        Self {
            category,
            status: RecommendationStatus::Unknown,
            impact: category.impact_class(),
            flagged_count: 0,
            resource_count: 0,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.flagged_count > 128
            || self.resource_count > 1_000_000
            || self.impact != self.category.impact_class()
        {
            Err(ModelError::BoundsExceeded)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-category-summary/v1",
            &[
                self.category.as_str().to_owned(),
                format!("{:?}", self.status),
                format!("{:?}", self.impact),
                self.flagged_count.to_string(),
                self.resource_count.to_string(),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FlaggedResourceDigest {
    resource_digest: Digest,
    region: AwsRegion,
}

impl FlaggedResourceDigest {
    pub fn new(
        resource_identifier: impl AsRef<str>,
        region: AwsRegion,
    ) -> Result<Self, ModelError> {
        if !valid_opaque_input(resource_identifier.as_ref()) {
            return Err(ModelError::InvalidIdentifier("flagged resource identifier"));
        }
        Ok(Self {
            resource_digest: Digest::from_fields(
                "aws-trusted-advisor-flagged-resource/v1",
                &[
                    resource_identifier.as_ref().to_owned(),
                    region.as_str().to_owned(),
                ],
            ),
            region,
        })
    }

    pub fn from_digest(resource_digest: Digest, region: AwsRegion) -> Result<Self, ModelError> {
        if !is_digest(resource_digest.as_str()) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            resource_digest,
            region,
        })
    }

    #[must_use]
    pub fn resource_digest(&self) -> &Digest {
        &self.resource_digest
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-flagged-resource-entry/v1",
            &[
                self.resource_digest.as_str().to_owned(),
                self.region.as_str().to_owned(),
            ],
        )
    }
}

impl Serialize for FlaggedResourceDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("FlaggedResourceDigest", 2)?;
        state.serialize_field("resourceDigest", &self.resource_digest)?;
        state.serialize_field("region", &self.region)?;
        state.end()
    }
}

impl fmt::Debug for FlaggedResourceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlaggedResourceDigest")
            .field("resource_digest", &self.resource_digest)
            .field("region", &self.region)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedAdvisorCheckDefinition {
    pub scope_digest: Digest,
    pub check_id: CheckId,
    pub category: TrustedAdvisorCategory,
    pub definition_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl TrustedAdvisorCheckDefinition {
    pub fn new(
        scope: &AwsTrustedAdvisorScope,
        definition_digest: Digest,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        Self::for_check(
            scope,
            scope.check_id().clone(),
            scope.category(),
            definition_digest,
            response_bytes,
            provenance,
        )
    }

    pub fn for_check(
        scope: &AwsTrustedAdvisorScope,
        check_id: CheckId,
        category: TrustedAdvisorCategory,
        definition_digest: Digest,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        validate_response_bytes(response_bytes)?;
        if !is_digest(definition_digest.as_str()) {
            return Err(ModelError::InvalidDigest);
        }
        let mut definition = Self {
            scope_digest: scope.scope_digest().clone(),
            check_id,
            category,
            definition_digest,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-trusted-advisor-definition"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        definition.evidence_digest = definition.calculate_digest();
        Ok(definition)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, scope: &AwsTrustedAdvisorScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || !is_digest(self.definition_digest.as_str())
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-check-definition/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.check_id.digest().as_str().to_owned(),
                self.category.as_str().to_owned(),
                self.definition_digest.as_str().to_owned(),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedAdvisorRefreshStatus {
    pub scope_digest: Digest,
    pub check_id: CheckId,
    pub category: TrustedAdvisorCategory,
    pub state: RefreshState,
    pub last_refresh_at: Option<DateTime<Utc>>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl TrustedAdvisorRefreshStatus {
    pub fn new(
        scope: &AwsTrustedAdvisorScope,
        state: RefreshState,
        last_refresh_at: Option<DateTime<Utc>>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        validate_response_bytes(response_bytes)?;
        if matches!(state, RefreshState::Complete) && last_refresh_at.is_none() {
            return Err(ModelError::InvalidTimestamp);
        }
        let response_digest = Digest::from_fields(
            "aws-trusted-advisor-refresh-status-response/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                scope.check_id().digest().as_str().to_owned(),
                scope.category().as_str().to_owned(),
                format!("{state:?}"),
                last_refresh_at.map_or_else(String::new, |value| value.to_rfc3339()),
                response_bytes.to_string(),
                provenance.as_str().to_owned(),
            ],
        );
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            check_id: scope.check_id().clone(),
            category: scope.category(),
            state,
            last_refresh_at,
            response_bytes,
            provenance,
            response_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate_integrity(&self, scope: &AwsTrustedAdvisorScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || self.check_id != *scope.check_id()
            || self.category != scope.category()
            || (matches!(self.state, RefreshState::Complete) && self.last_refresh_at.is_none())
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.response_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-refresh-status-response/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.check_id.digest().as_str().to_owned(),
                self.category.as_str().to_owned(),
                format!("{:?}", self.state),
                self.last_refresh_at
                    .map_or_else(String::new, |value| value.to_rfc3339()),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedAdvisorCheckResult {
    pub scope_digest: Digest,
    pub check_id: CheckId,
    pub category: TrustedAdvisorCategory,
    pub status: RecommendationStatus,
    pub result_timestamp: DateTime<Utc>,
    pub summary: CategorySummary,
    pub flagged_resources: Vec<FlaggedResourceDigest>,
    pub next_page: Option<PageCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub result_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl TrustedAdvisorCheckResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsTrustedAdvisorScope,
        status: RecommendationStatus,
        result_timestamp: DateTime<Utc>,
        summary: CategorySummary,
        flagged_resources: Vec<FlaggedResourceDigest>,
        next_page: Option<PageCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        validate_response_bytes(response_bytes)?;
        summary.validate()?;
        if summary.category != scope.category()
            || flagged_resources.len() > MAX_FLAGGED_RESOURCES_PER_PAGE
        {
            return Err(ModelError::BoundsExceeded);
        }
        if let Some(cursor) = &next_page {
            cursor.validate_against(scope)?;
        }
        let mut seen = BTreeSet::new();
        for resource in &flagged_resources {
            if !seen.insert(resource.digest()) {
                return Err(ModelError::DuplicateFlaggedResource);
            }
        }
        let mut result = Self {
            scope_digest: scope.scope_digest().clone(),
            check_id: scope.check_id().clone(),
            category: scope.category(),
            status,
            result_timestamp,
            summary,
            flagged_resources,
            next_page,
            response_bytes,
            provenance,
            result_digest: Digest::from_text("unsealed-aws-trusted-advisor-result"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        result.result_digest = result.calculate_digest();
        Ok(result)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, result_digest: Digest) -> Self {
        self.result_digest = result_digest;
        self
    }

    #[must_use]
    pub fn has_more(&self) -> bool {
        self.next_page.is_some()
    }

    pub fn validate_integrity(&self, scope: &AwsTrustedAdvisorScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || self.check_id != *scope.check_id()
            || self.category != scope.category()
            || self.flagged_resources.len() > MAX_FLAGGED_RESOURCES_PER_PAGE
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.result_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        self.summary.validate()?;
        if let Some(cursor) = &self.next_page {
            cursor.validate_against(scope)?;
        }
        let mut seen = BTreeSet::new();
        for resource in &self.flagged_resources {
            if !seen.insert(resource.digest()) {
                return Err(ModelError::DuplicateFlaggedResource);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-check-result/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.check_id.digest().as_str().to_owned(),
                self.category.as_str().to_owned(),
                format!("{:?}", self.status),
                self.result_timestamp.to_rfc3339(),
                self.summary.digest().as_str().to_owned(),
                self.flagged_resources
                    .iter()
                    .map(FlaggedResourceDigest::digest)
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.next_page.as_ref().map_or_else(String::new, |cursor| {
                    cursor.token_digest().as_str().to_owned()
                }),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

fn validate_response_bytes(response_bytes: u64) -> Result<(), ModelError> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(ModelError::BoundsExceeded)
    } else {
        Ok(())
    }
}
