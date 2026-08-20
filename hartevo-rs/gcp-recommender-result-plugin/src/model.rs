use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GCP_RECOMMENDER_RESULT_CONSUMER_ID, GCP_RECOMMENDER_RESULT_CONTRACT_VERSION,
    GCP_RECOMMENDER_RESULT_SCHEMA_VERSION, GCP_RECOMMENDER_RESULT_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_TARGET_FINGERPRINTS: usize = 32;
pub(crate) const MAX_FILTER_VALUES: usize = 8;
pub(crate) const MAX_SUBTYPES: usize = 16;
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 4096;
pub(crate) const MAX_PAGE_SIZE: u32 = 100;
pub(crate) const MAX_PAGES: u8 = 16;
pub(crate) const MAX_RESULTS: u32 = 500;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("timestamp must be non-negative")]
    InvalidTimestamp,
    #[error("scope is empty, duplicated, or exceeds a Layer-1 bound")]
    InvalidScope,
    #[error("filter contains too many values or an invalid subtype")]
    InvalidFilter,
    #[error("opaque page token is empty, oversized, or contains whitespace")]
    InvalidPageToken,
    #[error("record contains an invalid or duplicated target fingerprint")]
    InvalidRecord,
    #[error("record etag is invalid")]
    InvalidEtag,
    #[error("metadata digest does not match immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("read permission is not granted for this result kind")]
    MissingReadPermission,
    #[error("consent is invalid for bounded evidence")]
    InvalidConsent,
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
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn len(&self) -> usize {
        64
    }

    pub const fn is_empty(&self) -> bool {
        false
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
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

            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
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

string_identifier!(OrganizationId);
string_identifier!(FolderId);
string_identifier!(GcpProjectId);
string_identifier!(BillingAccountId);
string_identifier!(Location);
string_identifier!(RecommenderId);
string_identifier!(InsightTypeId);
string_identifier!(ResultId);
string_identifier!(RecommendationSubtype);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

pub type CloudProjectId = GcpProjectId;
pub type RecommendationId = ResultId;
pub type InsightId = ResultId;

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

    pub fn next(self) -> Result<Self, ModelError> {
        Self::new(self.0.checked_add(1).ok_or(ModelError::RevisionOverflow)?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn new(seconds: i64) -> Result<Self, ModelError> {
        if seconds < 0 {
            Err(ModelError::InvalidTimestamp)
        } else {
            Ok(Self(seconds))
        }
    }

    pub const fn seconds(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAuthKind {
    OAuth,
    ServiceAccount,
}

/// A non-serializing, non-printing reference into host credential storage.
/// The raw reference identifier is intentionally hashed during construction
/// and is never retained by the Layer-1 crate.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GoogleAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GcpRecommenderScope,
        credential_revision: u64,
        auth_kind: GoogleAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "gcp-recommender-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GoogleAuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    project_id: ProjectId,
    revision: Revision,
}

impl ProjectBinding {
    pub fn new(project_id: ProjectId, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            project_id,
            revision: Revision::new(revision)?,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-project-binding/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    mission_id: MissionId,
    revision: Revision,
}

impl MissionBinding {
    pub fn new(mission_id: MissionId, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            mission_id,
            revision: Revision::new(revision)?,
        })
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-mission-binding/v1",
            &[
                self.mission_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    work_product_id: WorkProductId,
    revision: Revision,
}

impl WorkProductBinding {
    pub fn new(work_product_id: WorkProductId, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            work_product_id,
            revision: Revision::new(revision)?,
        })
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-work-product-binding/v1",
            &[
                self.work_product_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
    read_only: bool,
    optimization_effects_allowed: bool,
}

impl ConsentScope {
    pub fn new(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_IDENTIFIER_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidConsent);
        }
        let consent = Self {
            consent_digest: Digest::from_text(reference),
            revision: Revision::new(revision)?,
            read_only: true,
            optimization_effects_allowed: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.read_only
            || self.optimization_effects_allowed
            || !is_digest(self.consent_digest.as_str())
        {
            Err(ModelError::InvalidConsent)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-consent/v1",
            &[
                self.consent_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                self.read_only.to_string(),
                self.optimization_effects_allowed.to_string(),
            ],
        )
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    permission_digest: Digest,
    revision: Revision,
    recommendations_list: bool,
    recommendations_get: bool,
    insights_list: bool,
    insights_get: bool,
    mutation_allowed: bool,
    operation_group_execution_allowed: bool,
}

impl PermissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reference: impl AsRef<str>,
        revision: u64,
        recommendations_list: bool,
        recommendations_get: bool,
        insights_list: bool,
        insights_get: bool,
        mutation_allowed: bool,
        operation_group_execution_allowed: bool,
    ) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_IDENTIFIER_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidScope);
        }
        let permission = Self {
            permission_digest: Digest::from_text(reference),
            revision: Revision::new(revision)?,
            recommendations_list,
            recommendations_get,
            insights_list,
            insights_get,
            mutation_allowed,
            operation_group_execution_allowed,
        };
        permission.validate()?;
        Ok(permission)
    }

    pub fn read_only(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        Self::new(reference, revision, true, true, true, true, false, false)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !is_digest(self.permission_digest.as_str())
            || self.mutation_allowed
            || self.operation_group_execution_allowed
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-permission-scope/v1",
            &[
                self.permission_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                self.recommendations_list.to_string(),
                self.recommendations_get.to_string(),
                self.insights_list.to_string(),
                self.insights_get.to_string(),
                self.mutation_allowed.to_string(),
                self.operation_group_execution_allowed.to_string(),
            ],
        )
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn mutation_allowed(&self) -> bool {
        self.mutation_allowed
    }

    pub const fn operation_group_execution_allowed(&self) -> bool {
        self.operation_group_execution_allowed
    }

    pub fn allows(&self, kind: GcpResultKind, operation: ReadOperation) -> bool {
        match (kind, operation) {
            (GcpResultKind::Recommendation(_), ReadOperation::List) => self.recommendations_list,
            (GcpResultKind::Recommendation(_), ReadOperation::Get) => self.recommendations_get,
            (GcpResultKind::Insight(_), ReadOperation::List) => self.insights_list,
            (GcpResultKind::Insight(_), ReadOperation::Get) => self.insights_get,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    List,
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpParent {
    Organization(OrganizationId),
    Folder(FolderId),
    Project(GcpProjectId),
    BillingAccount(BillingAccountId),
}

impl GcpParent {
    pub fn organization(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Organization(OrganizationId::new(value)?))
    }

    pub fn folder(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Folder(FolderId::new(value)?))
    }

    pub fn project(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Project(GcpProjectId::new(value)?))
    }

    pub fn billing_account(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::BillingAccount(BillingAccountId::new(value)?))
    }

    pub fn resource_name(&self) -> String {
        match self {
            Self::Organization(id) => format!("organizations/{}", id.as_str()),
            Self::Folder(id) => format!("folders/{}", id.as_str()),
            Self::Project(id) => format!("projects/{}", id.as_str()),
            Self::BillingAccount(id) => format!("billingAccounts/{}", id.as_str()),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields("gcp-recommender-parent/v1", &[self.resource_name()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpResultKind {
    Recommendation(RecommenderId),
    Insight(InsightTypeId),
}

impl GcpResultKind {
    pub fn resource_name(&self, parent: &GcpParent, location: &Location) -> String {
        match self {
            Self::Recommendation(id) => format!(
                "{}/locations/{}/recommenders/{}",
                parent.resource_name(),
                location.as_str(),
                id.as_str()
            ),
            Self::Insight(id) => format!(
                "{}/locations/{}/insightTypes/{}",
                parent.resource_name(),
                location.as_str(),
                id.as_str()
            ),
        }
    }

    pub const fn is_recommendation(&self) -> bool {
        matches!(self, Self::Recommendation(_))
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields("gcp-recommender-result-kind/v1", &[format!("{self:?}")])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderScopeSpec {
    pub parent: GcpParent,
    pub location: Location,
    pub result_kind: GcpResultKind,
    pub target_resource_fingerprints: Vec<Digest>,
    pub allowed_subtypes: Vec<RecommendationSubtype>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permission: PermissionScope,
    pub consent: ConsentScope,
}

impl GcpRecommenderScopeSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: GcpParent,
        location: Location,
        result_kind: GcpResultKind,
        target_resource_fingerprints: Vec<Digest>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission: PermissionScope,
        consent: ConsentScope,
    ) -> Self {
        Self {
            parent,
            location,
            result_kind,
            target_resource_fingerprints,
            allowed_subtypes: Vec::new(),
            project,
            mission,
            work_product,
            permission,
            consent,
        }
    }

    #[must_use]
    pub fn with_allowed_subtypes(
        mut self,
        allowed_subtypes: impl IntoIterator<Item = RecommendationSubtype>,
    ) -> Self {
        self.allowed_subtypes = allowed_subtypes.into_iter().collect();
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderScope {
    parent: GcpParent,
    location: Location,
    result_kind: GcpResultKind,
    target_resource_fingerprints: Vec<Digest>,
    allowed_subtypes: BTreeSet<RecommendationSubtype>,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    permission: PermissionScope,
    consent: ConsentScope,
    scope_digest: Digest,
}

impl GcpRecommenderScope {
    pub fn new(spec: GcpRecommenderScopeSpec) -> Result<Self, ModelError> {
        if spec.target_resource_fingerprints.is_empty()
            || spec.target_resource_fingerprints.len() > MAX_TARGET_FINGERPRINTS
            || spec
                .target_resource_fingerprints
                .iter()
                .any(|digest| !is_digest(digest.as_str()))
        {
            return Err(ModelError::InvalidScope);
        }
        let unique_targets = spec
            .target_resource_fingerprints
            .iter()
            .collect::<BTreeSet<_>>();
        if unique_targets.len() != spec.target_resource_fingerprints.len()
            || spec.allowed_subtypes.len() > MAX_SUBTYPES
        {
            return Err(ModelError::InvalidScope);
        }
        spec.permission.validate()?;
        spec.consent.validate()?;
        let allowed_subtypes = spec.allowed_subtypes.into_iter().collect::<BTreeSet<_>>();
        let scope_digest = compute_scope_digest(
            &spec.parent,
            &spec.location,
            &spec.result_kind,
            &spec.target_resource_fingerprints,
            &allowed_subtypes,
            &spec.project,
            &spec.mission,
            &spec.work_product,
            &spec.permission,
            &spec.consent,
        );
        Ok(Self {
            parent: spec.parent,
            location: spec.location,
            result_kind: spec.result_kind,
            target_resource_fingerprints: spec.target_resource_fingerprints,
            allowed_subtypes,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            permission: spec.permission,
            consent: spec.consent,
            scope_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if compute_scope_digest(
            &self.parent,
            &self.location,
            &self.result_kind,
            &self.target_resource_fingerprints,
            &self.allowed_subtypes,
            &self.project,
            &self.mission,
            &self.work_product,
            &self.permission,
            &self.consent,
        ) != self.scope_digest
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn spec(&self) -> GcpRecommenderScopeSpec {
        GcpRecommenderScopeSpec {
            parent: self.parent.clone(),
            location: self.location.clone(),
            result_kind: self.result_kind.clone(),
            target_resource_fingerprints: self.target_resource_fingerprints.clone(),
            allowed_subtypes: self.allowed_subtypes.iter().cloned().collect(),
            project: self.project.clone(),
            mission: self.mission.clone(),
            work_product: self.work_product.clone(),
            permission: self.permission.clone(),
            consent: self.consent.clone(),
        }
    }

    pub fn parent(&self) -> &GcpParent {
        &self.parent
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn result_kind(&self) -> &GcpResultKind {
        &self.result_kind
    }

    pub fn target_resource_fingerprints(&self) -> &[Digest] {
        &self.target_resource_fingerprints
    }

    pub fn allowed_subtypes(&self) -> &BTreeSet<RecommendationSubtype> {
        &self.allowed_subtypes
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn permission(&self) -> &PermissionScope {
        &self.permission
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.digest(),
            permission_digest: self.permission.digest(),
            consent_digest: self.consent.digest(),
            project_revision: self.project.revision(),
            mission_revision: self.mission.revision(),
            work_product_revision: self.work_product.revision(),
        }
    }
}

pub type GcpScope = GcpRecommenderScope;
pub type RecommenderScope = GcpRecommenderScope;

fn compute_scope_digest(
    parent: &GcpParent,
    location: &Location,
    result_kind: &GcpResultKind,
    target_resource_fingerprints: &[Digest],
    allowed_subtypes: &BTreeSet<RecommendationSubtype>,
    project: &ProjectBinding,
    mission: &MissionBinding,
    work_product: &WorkProductBinding,
    permission: &PermissionScope,
    consent: &ConsentScope,
) -> Digest {
    Digest::from_fields(
        "gcp-recommender-scope/v1",
        &[
            parent.resource_name(),
            location.as_str().to_owned(),
            format!("{result_kind:?}"),
            target_resource_fingerprints
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            allowed_subtypes
                .iter()
                .map(|subtype| subtype.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            project.digest().as_str().to_owned(),
            mission.digest().as_str().to_owned(),
            work_product.digest().as_str().to_owned(),
            permission.digest().as_str().to_owned(),
            consent.digest().as_str().to_owned(),
        ],
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationState {
    Active,
    Dismissed,
    Claimed,
    Failed,
    Succeeded,
}

pub type ResultState = RecommendationState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationPriority {
    P1,
    P2,
    P3,
    P4,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactCategory {
    Cost,
    Performance,
    Reliability,
    Security,
    Sustainability,
    Availability,
    Operations,
    Unknown,
}

pub type ImpactClass = ImpactCategory;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultFilters {
    states: BTreeSet<RecommendationState>,
    priorities: BTreeSet<RecommendationPriority>,
    subtypes: BTreeSet<RecommendationSubtype>,
}

impl ResultFilters {
    pub fn new(
        states: impl IntoIterator<Item = RecommendationState>,
        priorities: impl IntoIterator<Item = RecommendationPriority>,
        subtypes: impl IntoIterator<Item = RecommendationSubtype>,
    ) -> Result<Self, ModelError> {
        let filters = Self {
            states: states.into_iter().collect(),
            priorities: priorities.into_iter().collect(),
            subtypes: subtypes.into_iter().collect(),
        };
        filters.validate()?;
        Ok(filters)
    }

    pub fn empty() -> Self {
        Self {
            states: BTreeSet::new(),
            priorities: BTreeSet::new(),
            subtypes: BTreeSet::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.states.len() > MAX_FILTER_VALUES
            || self.priorities.len() > MAX_FILTER_VALUES
            || self.subtypes.len() > MAX_FILTER_VALUES
            || self
                .subtypes
                .iter()
                .any(|subtype| !valid_identifier(subtype.as_str()))
        {
            Err(ModelError::InvalidFilter)
        } else {
            Ok(())
        }
    }

    pub fn states(&self) -> &BTreeSet<RecommendationState> {
        &self.states
    }

    pub fn priorities(&self) -> &BTreeSet<RecommendationPriority> {
        &self.priorities
    }

    pub fn subtypes(&self) -> &BTreeSet<RecommendationSubtype> {
        &self.subtypes
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-filter/v1",
            &[
                self.states
                    .iter()
                    .map(|state| format!("{state:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                self.priorities
                    .iter()
                    .map(|priority| format!("{priority:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                self.subtypes
                    .iter()
                    .map(|subtype| subtype.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }

    pub(crate) fn matches(&self, record: &GcpRecommenderRecord) -> bool {
        (self.states.is_empty() || self.states.contains(&record.state))
            && (self.priorities.is_empty()
                || record
                    .priority
                    .is_some_and(|priority| self.priorities.contains(&priority)))
            && (self.subtypes.is_empty() || self.subtypes.contains(&record.subtype))
    }
}

impl Default for ResultFilters {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderQuery {
    filters: ResultFilters,
    page_size: u32,
    max_pages: u8,
    max_results: u32,
    query_digest: Digest,
}

impl GcpRecommenderQuery {
    pub fn new(
        filters: ResultFilters,
        page_size: u32,
        max_pages: u8,
        max_results: u32,
    ) -> Result<Self, ModelError> {
        filters.validate()?;
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_results == 0
            || max_results > MAX_RESULTS
        {
            return Err(ModelError::InvalidFilter);
        }
        let query_digest = compute_query_digest(&filters, page_size, max_pages, max_results);
        Ok(Self {
            filters,
            page_size,
            max_pages,
            max_results,
            query_digest,
        })
    }

    pub fn bounded(filters: ResultFilters) -> Result<Self, ModelError> {
        Self::new(filters, 100, 16, 500)
    }

    pub fn filters(&self) -> &ResultFilters {
        &self.filters
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub const fn max_pages(&self) -> u8 {
        self.max_pages
    }

    pub const fn max_results(&self) -> u32 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        self.query_digest.clone()
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if compute_query_digest(
            &self.filters,
            self.page_size,
            self.max_pages,
            self.max_results,
        ) != self.query_digest
        {
            Err(ModelError::DigestMismatch)
        } else {
            self.filters.validate()
        }
    }

    pub fn validate_against(&self, scope: &GcpRecommenderScope) -> Result<(), ModelError> {
        self.validate()?;
        if self
            .filters
            .subtypes()
            .iter()
            .any(|subtype| !scope.allowed_subtypes.contains(subtype))
        {
            Err(ModelError::InvalidFilter)
        } else {
            Ok(())
        }
    }
}

impl Default for GcpRecommenderQuery {
    fn default() -> Self {
        Self::bounded(ResultFilters::empty()).expect("default GCP query is bounded")
    }
}

fn compute_query_digest(
    filters: &ResultFilters,
    page_size: u32,
    max_pages: u8,
    max_results: u32,
) -> Digest {
    Digest::from_fields(
        "gcp-recommender-query/v1",
        &[
            filters.digest().as_str().to_owned(),
            page_size.to_string(),
            max_pages.to_string(),
            max_results.to_string(),
        ],
    )
}

/// Opaque provider cursor. The underlying token is never serialized or
/// displayed; only its digest may enter evidence or request metadata.
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PAGE_TOKEN_BYTES
            || value.chars().any(char::is_whitespace)
        {
            Err(ModelError::InvalidPageToken)
        } else {
            Ok(Self(value))
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-page-token/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl Clone for OpaquePageToken {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for OpaquePageToken {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for OpaquePageToken {}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageTokenBinding {
    token: OpaquePageToken,
    scope_digest: Digest,
    query_digest: Digest,
    filter_digest: Digest,
    page_number: u8,
    binding_digest: Digest,
}

impl PageTokenBinding {
    pub fn new(
        token: OpaquePageToken,
        scope_digest: Digest,
        query_digest: Digest,
        filter_digest: Digest,
        page_number: u8,
    ) -> Self {
        let binding_digest = Digest::from_fields(
            "gcp-recommender-page-token-binding/v1",
            &[
                token.digest().as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                query_digest.as_str().to_owned(),
                filter_digest.as_str().to_owned(),
                page_number.to_string(),
            ],
        );
        Self {
            token,
            scope_digest,
            query_digest,
            filter_digest,
            page_number,
            binding_digest,
        }
    }

    pub fn token_digest(&self) -> Digest {
        self.token.digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn page_number(&self) -> u8 {
        self.page_number
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn validate(
        &self,
        scope_digest: &Digest,
        query_digest: &Digest,
        filter_digest: &Digest,
        expected_page_number: u8,
    ) -> Result<(), ModelError> {
        let expected = Self::new(
            self.token.clone(),
            scope_digest.clone(),
            query_digest.clone(),
            filter_digest.clone(),
            expected_page_number,
        );
        if expected.binding_digest == self.binding_digest
            && self.scope_digest == *scope_digest
            && self.query_digest == *query_digest
            && self.filter_digest == *filter_digest
            && self.page_number == expected_page_number
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

pub type GcpImpactCategory = ImpactCategory;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderRecord {
    pub result_kind: GcpResultKind,
    pub result_id: ResultId,
    pub priority: Option<RecommendationPriority>,
    pub subtype: RecommendationSubtype,
    pub state: RecommendationState,
    pub category: ImpactCategory,
    pub impact_class: ImpactCategory,
    pub last_refresh: Timestamp,
    pub observed_at: Timestamp,
    pub target_resource_fingerprints: Vec<Digest>,
    pub content_digest: Digest,
    pub etag_digest: Digest,
    pub revision: Revision,
    pub record_digest: Digest,
}

impl GcpRecommenderRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_kind: GcpResultKind,
        result_id: ResultId,
        priority: Option<RecommendationPriority>,
        subtype: RecommendationSubtype,
        state: RecommendationState,
        category: ImpactCategory,
        impact_class: ImpactCategory,
        last_refresh: Timestamp,
        observed_at: Timestamp,
        target_resource_fingerprints: Vec<Digest>,
        content_digest: Digest,
        etag_digest: Digest,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let revision = Revision::new(revision)?;
        if target_resource_fingerprints.is_empty()
            || target_resource_fingerprints.len() > MAX_TARGET_FINGERPRINTS
            || target_resource_fingerprints
                .iter()
                .any(|digest| !is_digest(digest.as_str()))
            || target_resource_fingerprints
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != target_resource_fingerprints.len()
            || !is_digest(content_digest.as_str())
            || !is_digest(etag_digest.as_str())
        {
            return Err(ModelError::InvalidRecord);
        }
        let record_digest = compute_record_digest(
            &result_kind,
            &result_id,
            priority,
            &subtype,
            state,
            category,
            impact_class,
            last_refresh,
            observed_at,
            &target_resource_fingerprints,
            &content_digest,
            &etag_digest,
            revision,
        );
        Ok(Self {
            result_kind,
            result_id,
            priority,
            subtype,
            state,
            category,
            impact_class,
            last_refresh,
            observed_at,
            target_resource_fingerprints,
            content_digest,
            etag_digest,
            revision,
            record_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if compute_record_digest(
            &self.result_kind,
            &self.result_id,
            self.priority,
            &self.subtype,
            self.state,
            self.category,
            self.impact_class,
            self.last_refresh,
            self.observed_at,
            &self.target_resource_fingerprints,
            &self.content_digest,
            &self.etag_digest,
            self.revision,
        ) == self.record_digest
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn version_fence(&self) -> ResultVersionFence {
        ResultVersionFence {
            etag_digest: self.etag_digest.clone(),
            revision: self.revision,
        }
    }
}

pub type RecommendationRecord = GcpRecommenderRecord;
pub type InsightRecord = GcpRecommenderRecord;

fn compute_record_digest(
    result_kind: &GcpResultKind,
    result_id: &ResultId,
    priority: Option<RecommendationPriority>,
    subtype: &RecommendationSubtype,
    state: RecommendationState,
    category: ImpactCategory,
    impact_class: ImpactCategory,
    last_refresh: Timestamp,
    observed_at: Timestamp,
    target_resource_fingerprints: &[Digest],
    content_digest: &Digest,
    etag_digest: &Digest,
    revision: Revision,
) -> Digest {
    Digest::from_fields(
        "gcp-recommender-record/v1",
        &[
            format!("{result_kind:?}"),
            result_id.as_str().to_owned(),
            priority.map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
            subtype.as_str().to_owned(),
            format!("{state:?}"),
            format!("{category:?}"),
            format!("{impact_class:?}"),
            last_refresh.seconds().to_string(),
            observed_at.seconds().to_string(),
            target_resource_fingerprints
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            content_digest.as_str().to_owned(),
            etag_digest.as_str().to_owned(),
            revision.get().to_string(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResultVersionFence {
    pub etag_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    EtagDrift,
    RevisionDrift,
    ScopeMismatch,
    FilterMismatch,
    Tampered,
    Truncated,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub attempt: u8,
    pub blocked_env: bool,
    pub diagnostic_digest: Digest,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub(crate) fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        attempt: u8,
        blocked_env: bool,
        diagnostic_digest: Digest,
    ) -> Self {
        let error_digest = Digest::from_fields(
            "gcp-recommender-provider-error/v1",
            &[
                format!("{kind:?}"),
                status_code.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                retryable.to_string(),
                attempt.to_string(),
                blocked_env.to_string(),
                diagnostic_digest.as_str().to_owned(),
            ],
        );
        Self {
            kind,
            status_code,
            retryable,
            attempt,
            blocked_env,
            diagnostic_digest,
            error_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn operation_group_execution() -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjection {
    Complete,
    Empty,
    Partial,
    RateLimited,
    AccessLost,
    ProviderUnknown,
    FinalError,
    BlockedEnv,
}

impl ResultProjection {
    pub const fn is_decision_ready(self) -> bool {
        matches!(self, Self::Complete | Self::Empty)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageCap,
    ResultCap,
    MissingPageToken,
    ProviderError,
    TruncatedPage,
    RevisionDrift,
    EtagDrift,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcpRecommenderRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub contract_digest: Digest,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub provider_version: String,
    pub api_version: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

pub type Registration = GcpRecommenderRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub native: bool,
    pub connected: bool,
}

impl GcpRecommenderRegistration {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind(
        scope: &GcpRecommenderScope,
        query: &GcpRecommenderQuery,
        provider_id: &str,
        provider_version: &str,
        api_version: &str,
        provider_digest: Digest,
        secret_reference_digest: Digest,
        evidence_policy_digest: Digest,
    ) -> Result<Self, ModelError> {
        let service_id = ServiceId::new(GCP_RECOMMENDER_RESULT_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let provider_id =
            ProviderId::new(provider_id).map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = ConsumerId::new(GCP_RECOMMENDER_RESULT_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let registration_revision = Revision::new(1)?;
        let mut registration = Self {
            schema_version: GCP_RECOMMENDER_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_RECOMMENDER_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: crate::GCP_RECOMMENDER_RESULT_PLUGIN_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_id,
            provider_id,
            consumer_id,
            provider_version: provider_version.to_owned(),
            api_version: api_version.to_owned(),
            provider_digest,
            permission_digest: scope.permission().digest(),
            query_digest: query.digest(),
            scope_digest: scope.digest(),
            evidence_policy_digest,
            secret_reference_digest,
            registration_revision,
            registration_digest: Digest::from_text("registration-placeholder"),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        if provider_version.is_empty() || api_version.is_empty() {
            return Err(ModelError::InvalidRegistration);
        }
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-registration/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.plugin_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.service_id.as_str().to_owned(),
                self.provider_id.as_str().to_owned(),
                self.consumer_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.api_version.clone(),
                self.provider_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.query_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.evidence_policy_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                format!("{:?}", self.state),
                self.reversible.to_string(),
                self.revocable.to_string(),
            ],
        )
    }

    pub fn validate(
        &self,
        scope: &GcpRecommenderScope,
        query: &GcpRecommenderQuery,
        provider_id: &str,
        provider_version: &str,
        api_version: &str,
        provider_digest: &Digest,
        secret_reference_digest: &Digest,
        evidence_policy_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        query.validate()?;
        if self.schema_version != GCP_RECOMMENDER_RESULT_SCHEMA_VERSION
            || self.contract_version != GCP_RECOMMENDER_RESULT_CONTRACT_VERSION
            || self.plugin_version != crate::GCP_RECOMMENDER_RESULT_PLUGIN_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_id.as_str() != GCP_RECOMMENDER_RESULT_SERVICE_ID
            || self.provider_id.as_str() != provider_id
            || self.consumer_id.as_str() != GCP_RECOMMENDER_RESULT_CONSUMER_ID
            || self.provider_version != provider_version
            || self.api_version != api_version
            || &self.provider_digest != provider_digest
            || self.permission_digest != scope.permission().digest()
            || self.query_digest != query.digest()
            || self.scope_digest != scope.digest()
            || &self.evidence_policy_digest != evidence_policy_digest
            || &self.secret_reference_digest != secret_reference_digest
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.compute_digest()
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        if !self.revocable {
            return Err(ModelError::InvalidRegistration);
        }
        self.ensure_active()?;
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self.registration_revision.next()?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            native: false,
            connected: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.reversible {
            return Err(ModelError::InvalidRegistration);
        }
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = self.registration_revision.next()?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderResponseFence {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub filter_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
}
