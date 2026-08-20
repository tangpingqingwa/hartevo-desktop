use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{MAX_IDENTIFIER_BYTES, MAX_ITEMS, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES};

pub const MAX_SCOPE_DIMENSION: usize = 64;
pub const MAX_TRANSACTION_COUNT: u32 = 1_000_000;
pub const MAX_MONEY_MINOR_UNITS: i64 = 9_000_000_000_000_000;
pub const MAX_QUERY_WINDOW_DAYS: i64 = 366;
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} revision is invalid")]
    InvalidRevision { field: &'static str },
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} has an invalid relationship")]
    InvalidRelationship { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("consent is expired")]
    ConsentExpired,
    #[error("registration or secret reference is revoked")]
    Revoked,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already reversed")]
    AlreadyReversed,
    #[error("money value is invalid")]
    InvalidMoney,
    #[error("time window is invalid or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("query configuration is invalid or exceeds the Layer-1 bound")]
    InvalidQueryConfig,
    #[error("page cursor is invalid or bound to a different query")]
    InvalidCursor,
    #[error("provider observation is invalid or outside the bounded scope")]
    InvalidObservation,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

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
        let mut material = Vec::new();
        append_field(&mut material, domain);
        for (name, value) in fields {
            append_field(&mut material, name);
            append_field(&mut material, value);
        }
        Self::from_bytes(&material)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.0[..12]
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.0, "digest")
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(material: &mut Vec<u8>, value: &str) {
    material.extend_from_slice(&(value.len() as u64).to_be_bytes());
    material.extend_from_slice(value.as_bytes());
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

macro_rules! opaque_identifier {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            #[must_use]
            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, self.digest().prefix())
            }

            pub fn validate(&self) -> Result<(), ModelError> {
                validate_identifier(&self.0, $field)
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
    };
}

opaque_identifier!(OrganizationId, "organization", "brex-organization/v1");
opaque_identifier!(UserId, "user", "brex-user/v1");
opaque_identifier!(CardId, "card", "brex-card/v1");
opaque_identifier!(TransactionId, "transaction", "brex-transaction/v1");
opaque_identifier!(LimitId, "limit", "brex-limit/v1");
opaque_identifier!(PolicyId, "policy", "brex-policy/v1");
opaque_identifier!(ProjectId, "project", "brex-project/v1");
opaque_identifier!(MissionId, "mission", "brex-mission/v1");
opaque_identifier!(WorkProductId, "work-product", "brex-work-product/v1");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RevisionId(String);

impl RevisionId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn from_number(value: u64) -> Self {
        Self(value.to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<u64> for RevisionId {
    fn from(value: u64) -> Self {
        Self::from_number(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectBinding {
    id: ProjectId,
    revision: RevisionId,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::with_revision(ProjectId::new(id)?, RevisionId::from_number(revision))
    }

    pub fn with_revision(id: ProjectId, revision: RevisionId) -> Result<Self, ModelError> {
        id.validate()?;
        Ok(Self { id, revision })
    }

    #[must_use]
    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        &self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "brex-project-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for ProjectBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectBinding")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for ProjectBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ProjectBinding", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionBinding {
    id: MissionId,
    revision: RevisionId,
    consent_digest: Digest,
}

impl MissionBinding {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::with_revision(
            MissionId::new(id)?,
            RevisionId::from_number(revision),
            consent_digest,
        )
    }

    pub fn with_revision(
        id: MissionId,
        revision: RevisionId,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        id.validate()?;
        consent_digest.validate()?;
        Ok(Self {
            id,
            revision,
            consent_digest,
        })
    }

    #[must_use]
    pub fn id(&self) -> &MissionId {
        &self.id
    }

    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        &self.revision
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "brex-mission-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for MissionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBinding")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("consent_digest", &self.consent_digest)
            .finish()
    }
}

impl Serialize for MissionBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("MissionBinding", 3)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductBinding {
    id: WorkProductId,
    revision: RevisionId,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::with_revision(WorkProductId::new(id)?, RevisionId::from_number(revision))
    }

    pub fn with_revision(id: WorkProductId, revision: RevisionId) -> Result<Self, ModelError> {
        id.validate()?;
        Ok(Self { id, revision })
    }

    #[must_use]
    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        &self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "brex-work-product-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for WorkProductBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductBinding")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for WorkProductBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("WorkProductBinding", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

pub type ProjectIdentity = ProjectBinding;
pub type MissionIdentity = MissionBinding;
pub type WorkProductIdentity = WorkProductBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendOperation {
    ReadSpend,
    ReadLimits,
    ReadPolicies,
}

impl SpendOperation {
    pub const ALL: [Self; 3] = [Self::ReadSpend, Self::ReadLimits, Self::ReadPolicies];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadSpend => "read_spend",
            Self::ReadLimits => "read_limits",
            Self::ReadPolicies => "read_policies",
        }
    }

    #[must_use]
    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentScope {
    consent_digest: Digest,
    consent_revision: RevisionId,
    expires_at: DateTime<Utc>,
}

impl ConsentScope {
    pub fn new(
        consent_id: impl Into<String>,
        consent_revision: impl Into<RevisionId>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let consent_id = consent_id.into();
        validate_text(&consent_id, "consent", MAX_IDENTIFIER_BYTES)?;
        let scope = Self {
            consent_digest: Digest::from_parts("brex-consent-id/v1", &[("id", consent_id)]),
            consent_revision: consent_revision.into(),
            expires_at,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_digest(
        consent_digest: Digest,
        consent_revision: RevisionId,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        consent_digest.validate()?;
        let scope = Self {
            consent_digest,
            consent_revision,
            expires_at,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_layer_one(
        consent_id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new(consent_id, RevisionId::from_number(revision), expires_at)
    }

    #[must_use]
    pub fn consent_id_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub fn consent_revision(&self) -> &RevisionId {
        &self.consent_revision
    }

    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "brex-consent-binding/v1",
            &[
                ("consent", self.consent_digest.as_str().to_owned()),
                ("revision", self.consent_revision.as_str().to_owned()),
                ("expires_at", self.expires_at.to_rfc3339()),
            ],
        )
    }

    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    pub fn ensure_active(&self, now: DateTime<Utc>) -> Result<(), ModelError> {
        self.validate()?;
        if self.is_expired(now) {
            Err(ModelError::ConsentExpired)
        } else {
            Ok(())
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.consent_digest.validate()?;
        if self.consent_revision.as_str().is_empty() {
            return Err(ModelError::InvalidRevision { field: "consent" });
        }
        Ok(())
    }
}

impl Serialize for ConsentScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConsentScope", 3)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("consentRevision", &self.consent_revision)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.end()
    }
}

pub type ConsentBinding = ConsentScope;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionOperation {
    ReadSpend,
    ReadLimits,
    ReadPolicies,
}

impl PermissionOperation {
    #[must_use]
    pub const fn operation(self) -> SpendOperation {
        match self {
            Self::ReadSpend => SpendOperation::ReadSpend,
            Self::ReadLimits => SpendOperation::ReadLimits,
            Self::ReadPolicies => SpendOperation::ReadPolicies,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PermissionScope {
    organization_digest: Digest,
    allowed_operations: BTreeSet<SpendOperation>,
    permission_revision: RevisionId,
    consent_digest: Digest,
    permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        organization: &OrganizationId,
        allowed_operations: BTreeSet<SpendOperation>,
        permission_revision: RevisionId,
        consent: &ConsentScope,
    ) -> Result<Self, ModelError> {
        if allowed_operations.is_empty() {
            return Err(ModelError::Empty {
                field: "Brex read operations",
            });
        }
        let scope = Self {
            organization_digest: organization.digest(),
            allowed_operations,
            permission_revision,
            consent_digest: consent.digest(),
            permission_digest: Digest::from_text("pending-permission-digest"),
        };
        let permission_digest = scope.compute_digest();
        Ok(Self {
            permission_digest,
            ..scope
        })
    }

    pub fn all(
        organization: &OrganizationId,
        permission_revision: impl Into<RevisionId>,
        consent: &ConsentScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            organization,
            SpendOperation::ALL.into_iter().collect(),
            permission_revision.into(),
            consent,
        )
    }

    #[must_use]
    pub fn organization_digest(&self) -> &Digest {
        &self.organization_digest
    }

    #[must_use]
    pub fn allowed_operations(&self) -> &BTreeSet<SpendOperation> {
        &self.allowed_operations
    }

    #[must_use]
    pub fn permission_revision(&self) -> &RevisionId {
        &self.permission_revision
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn permits(&self, operation: SpendOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "brex-permission-scope/v1",
            &[
                ("organization", self.organization_digest.as_str().to_owned()),
                (
                    "operations",
                    self.allowed_operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("revision", self.permission_revision.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        self.organization_digest.validate()?;
        self.consent_digest.validate()?;
        if self.allowed_operations.is_empty() || self.compute_digest() != self.permission_digest {
            return Err(ModelError::InvalidDigest {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for PermissionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionScope")
            .field("organization_digest", &self.organization_digest)
            .field("allowed_operations", &self.allowed_operations)
            .field("permission_revision", &self.permission_revision)
            .field("consent_digest", &self.consent_digest)
            .field("permission_digest", &self.permission_digest)
            .finish()
    }
}

impl Serialize for PermissionScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PermissionScope", 5)?;
        state.serialize_field("organizationDigest", &self.organization_digest)?;
        state.serialize_field("allowedOperations", &self.allowed_operations)?;
        state.serialize_field("permissionRevision", &self.permission_revision)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.end()
    }
}

pub type PermissionSnapshot = PermissionScope;

#[derive(Clone, Eq, PartialEq)]
pub struct BrexSpendScope {
    pub organization_id: OrganizationId,
    pub users: Vec<UserId>,
    pub cards: Vec<CardId>,
    pub transactions: Vec<TransactionId>,
    pub limits: Vec<LimitId>,
    pub policies: Vec<PolicyId>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub scope_revision: RevisionId,
    pub consent: ConsentScope,
    pub permissions: PermissionScope,
    pub scope_digest: Digest,
}

struct ScopeDigestMaterial {
    organization_digest: Digest,
    users: Vec<Digest>,
    cards: Vec<Digest>,
    transactions: Vec<Digest>,
    limits: Vec<Digest>,
    policies: Vec<Digest>,
    project_digest: Digest,
    mission_digest: Digest,
    work_product_digest: Digest,
    scope_revision: RevisionId,
    consent_digest: Digest,
    permission_digest: Digest,
}

impl Serialize for ScopeDigestMaterial {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ScopeDigestMaterial", 12)?;
        state.serialize_field("organizationDigest", &self.organization_digest)?;
        state.serialize_field("users", &self.users)?;
        state.serialize_field("cards", &self.cards)?;
        state.serialize_field("transactions", &self.transactions)?;
        state.serialize_field("limits", &self.limits)?;
        state.serialize_field("policies", &self.policies)?;
        state.serialize_field("projectDigest", &self.project_digest)?;
        state.serialize_field("missionDigest", &self.mission_digest)?;
        state.serialize_field("workProductDigest", &self.work_product_digest)?;
        state.serialize_field("scopeRevision", &self.scope_revision)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.end()
    }
}

impl BrexSpendScope {
    pub fn new(
        organization_id: OrganizationId,
        mut users: Vec<UserId>,
        mut cards: Vec<CardId>,
        mut transactions: Vec<TransactionId>,
        mut limits: Vec<LimitId>,
        mut policies: Vec<PolicyId>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        scope_revision: RevisionId,
        consent: ConsentScope,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        organization_id.validate()?;
        validate_and_sort_ids(&mut users, "user scope", |id| id.digest())?;
        validate_and_sort_ids(&mut cards, "card scope", |id| id.digest())?;
        validate_and_sort_ids(&mut transactions, "transaction scope", |id| id.digest())?;
        validate_and_sort_ids(&mut limits, "limit scope", |id| id.digest())?;
        validate_and_sort_ids(&mut policies, "policy scope", |id| id.digest())?;
        if permissions.organization_digest() != &organization_id.digest() {
            return Err(ModelError::InvalidRelationship {
                field: "permission organization",
            });
        }
        if permissions.consent_digest() != &consent.digest()
            || mission.consent_digest() != &consent.digest()
        {
            return Err(ModelError::InvalidRelationship {
                field: "scope consent",
            });
        }
        let mut scope = Self {
            organization_id,
            users,
            cards,
            transactions,
            limits,
            policies,
            project,
            mission,
            work_product,
            scope_revision,
            consent,
            permissions,
            scope_digest: Digest::from_text("pending-scope-digest"),
        };
        scope.scope_digest = scope.compute_digest();
        Ok(scope)
    }

    pub fn for_layer_one(
        organization_id: OrganizationId,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        scope_revision: impl Into<RevisionId>,
        consent: ConsentScope,
        permission_revision: impl Into<RevisionId>,
    ) -> Result<Self, ModelError> {
        let permissions = PermissionScope::all(&organization_id, permission_revision, &consent)?;
        Self::new(
            organization_id,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            project,
            mission,
            work_product,
            scope_revision.into(),
            consent,
            permissions,
        )
    }

    fn material(&self) -> ScopeDigestMaterial {
        ScopeDigestMaterial {
            organization_digest: self.organization_id.digest(),
            users: self.users.iter().map(UserId::digest).collect(),
            cards: self.cards.iter().map(CardId::digest).collect(),
            transactions: self
                .transactions
                .iter()
                .map(TransactionId::digest)
                .collect(),
            limits: self.limits.iter().map(LimitId::digest).collect(),
            policies: self.policies.iter().map(PolicyId::digest).collect(),
            project_digest: self.project.digest(),
            mission_digest: self.mission.digest(),
            work_product_digest: self.work_product.digest(),
            scope_revision: self.scope_revision.clone(),
            consent_digest: self.consent.digest(),
            permission_digest: self.permissions.permission_digest().clone(),
        }
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&self.material()).expect("scope digest material serializes")
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn scope_revision(&self) -> &RevisionId {
        &self.scope_revision
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn permissions(&self) -> &PermissionScope {
        &self.permissions
    }

    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.organization_id
    }

    #[must_use]
    pub fn contains_user(&self, id: &UserId) -> bool {
        contains_digest(&self.users, &id.digest())
    }

    #[must_use]
    pub fn contains_card(&self, id: &CardId) -> bool {
        contains_digest(&self.cards, &id.digest())
    }

    #[must_use]
    pub fn contains_transaction(&self, id: &TransactionId) -> bool {
        contains_digest(&self.transactions, &id.digest())
    }

    #[must_use]
    pub fn contains_limit(&self, id: &LimitId) -> bool {
        contains_digest(&self.limits, &id.digest())
    }

    #[must_use]
    pub fn contains_policy(&self, id: &PolicyId) -> bool {
        contains_digest(&self.policies, &id.digest())
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.organization_id.validate()?;
        self.consent.validate()?;
        self.permissions.verify()?;
        if self.permissions.organization_digest() != &self.organization_id.digest()
            || self.permissions.consent_digest() != &self.consent.digest()
            || self.mission.consent_digest() != &self.consent.digest()
            || self.compute_digest() != self.scope_digest
        {
            return Err(ModelError::InvalidDigest {
                field: "scope digest",
            });
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        self.validate()
    }
}

impl fmt::Debug for BrexSpendScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrexSpendScope")
            .field("organization_id", &self.organization_id)
            .field("users", &self.users)
            .field("cards", &self.cards)
            .field("transactions", &self.transactions)
            .field("limits", &self.limits)
            .field("policies", &self.policies)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("scope_revision", &self.scope_revision)
            .field("consent", &self.consent)
            .field("permissions", &self.permissions)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl Serialize for BrexSpendScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("BrexSpendScope", 13)?;
        state.serialize_field("organizationDigest", &self.organization_id.digest())?;
        state.serialize_field(
            "userScopeDigests",
            &self.users.iter().map(UserId::digest).collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "cardScopeDigests",
            &self.cards.iter().map(CardId::digest).collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "transactionScopeDigests",
            &self
                .transactions
                .iter()
                .map(TransactionId::digest)
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "limitScopeDigests",
            &self.limits.iter().map(LimitId::digest).collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "policyScopeDigests",
            &self
                .policies
                .iter()
                .map(PolicyId::digest)
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("scopeRevision", &self.scope_revision)?;
        state.serialize_field("consent", &self.consent)?;
        state.serialize_field("permissions", &self.permissions)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

fn validate_and_sort_ids<T, F>(
    values: &mut [T],
    field: &'static str,
    digest: F,
) -> Result<(), ModelError>
where
    T: Ord,
    F: Fn(&T) -> Digest,
{
    if values.len() > MAX_SCOPE_DIMENSION {
        return Err(ModelError::BoundExceeded { field });
    }
    values.sort_by_key(|value| digest(value));
    for pair in values.windows(2) {
        if digest(&pair[0]) == digest(&pair[1]) {
            return Err(ModelError::Duplicate { field });
        }
    }
    Ok(())
}

// The generic helper above cannot infer a method on an arbitrary identifier;
// these small typed checks keep the raw identifier private to the scope.
fn contains_digest<T>(values: &[T], digest: &Digest) -> bool
where
    T: Digestable,
{
    values.iter().any(|value| value.digest() == *digest)
}

trait Digestable {
    fn digest(&self) -> Digest;
}

impl Digestable for UserId {
    fn digest(&self) -> Digest {
        UserId::digest(self)
    }
}
impl Digestable for CardId {
    fn digest(&self) -> Digest {
        CardId::digest(self)
    }
}
impl Digestable for TransactionId {
    fn digest(&self) -> Digest {
        TransactionId::digest(self)
    }
}
impl Digestable for LimitId {
    fn digest(&self) -> Digest {
        LimitId::digest(self)
    }
}
impl Digestable for PolicyId {
    fn digest(&self) -> Digest {
        PolicyId::digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(ModelError::InvalidMoney);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Money {
    pub currency: CurrencyCode,
    pub minor_units: i64,
}

impl Money {
    pub fn new(currency: impl Into<String>, minor_units: i64) -> Result<Self, ModelError> {
        if minor_units.unsigned_abs() > MAX_MONEY_MINOR_UNITS as u64 {
            return Err(ModelError::InvalidMoney);
        }
        Ok(Self {
            currency: CurrencyCode::new(currency)?,
            minor_units,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.currency.as_str(), self.minor_units).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Observed,
    Denied,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendObservation {
    pub scope_digest: Digest,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub amount: Money,
    pub transaction_count: u32,
    pub user_digest: Option<Digest>,
    pub card_digest: Option<Digest>,
    pub transaction_digest: Option<Digest>,
    pub merchant_digest: Option<Digest>,
    pub status: ObservationStatus,
    pub observation_digest: Digest,
}

impl SpendObservation {
    pub fn new(
        scope: &BrexSpendScope,
        amount: Money,
        transaction_count: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::aggregate(
            &scope.scope_digest,
            None,
            None,
            None,
            None,
            observed_at - Duration::hours(24),
            observed_at,
            amount,
            transaction_count,
            ObservationStatus::Observed,
        )
    }

    pub fn aggregate(
        scope_digest: &Digest,
        user: Option<&UserId>,
        card: Option<&CardId>,
        transaction: Option<&TransactionId>,
        merchant: Option<&str>,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        amount: Money,
        transaction_count: u32,
        status: ObservationStatus,
    ) -> Result<Self, ModelError> {
        scope_digest.validate()?;
        amount.validate()?;
        if period_end <= period_start
            || period_end - period_start > Duration::days(MAX_QUERY_WINDOW_DAYS)
        {
            return Err(ModelError::InvalidTimeWindow);
        }
        if transaction_count > MAX_TRANSACTION_COUNT {
            return Err(ModelError::BoundExceeded {
                field: "transaction count",
            });
        }
        let merchant_digest = merchant
            .map(|value| {
                validate_text(value, "merchant", MAX_IDENTIFIER_BYTES).map(|()| {
                    Digest::from_parts("brex-merchant/v1", &[("value", value.to_owned())])
                })
            })
            .transpose()?;
        let mut observation = Self {
            scope_digest: scope_digest.clone(),
            period_start,
            period_end,
            amount,
            transaction_count,
            user_digest: user.map(UserId::digest),
            card_digest: card.map(CardId::digest),
            transaction_digest: transaction.map(TransactionId::digest),
            merchant_digest,
            status,
            observation_digest: Digest::from_text("pending-spend-observation"),
        };
        observation.observation_digest = observation.compute_digest();
        Ok(observation)
    }

    pub fn for_digests(
        scope_digest: Digest,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        amount: Money,
        transaction_count: u32,
        status: ObservationStatus,
    ) -> Result<Self, ModelError> {
        Self::aggregate(
            &scope_digest,
            None,
            None,
            None,
            None,
            period_start,
            period_end,
            amount,
            transaction_count,
            status,
        )
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            &self.scope_digest,
            self.period_start,
            self.period_end,
            &self.amount,
            self.transaction_count,
            &self.user_digest,
            &self.card_digest,
            &self.transaction_digest,
            &self.merchant_digest,
            self.status,
        ))
        .expect("spend observation digest material serializes")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.scope_digest.validate()?;
        self.amount.validate()?;
        if self.period_end <= self.period_start
            || self.period_end - self.period_start > Duration::days(MAX_QUERY_WINDOW_DAYS)
            || self.transaction_count > MAX_TRANSACTION_COUNT
            || self.compute_digest() != self.observation_digest
        {
            return Err(ModelError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LimitObservation {
    pub scope_digest: Digest,
    pub limit_digest: Digest,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub limit: Money,
    pub spent: Money,
    pub remaining: Money,
    pub status: ObservationStatus,
    pub observation_digest: Digest,
}

impl LimitObservation {
    pub fn new(
        scope: &BrexSpendScope,
        limit: Option<&LimitId>,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        value: Money,
        spent: Money,
        remaining: Money,
        status: ObservationStatus,
    ) -> Result<Self, ModelError> {
        Self::for_digests(
            scope.scope_digest.clone(),
            limit.map_or_else(
                || Digest::from_text("brex-limit-observation/default"),
                LimitId::digest,
            ),
            period_start,
            period_end,
            value,
            spent,
            remaining,
            status,
        )
    }

    pub fn for_digests(
        scope_digest: Digest,
        limit_digest: Digest,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        limit: Money,
        spent: Money,
        remaining: Money,
        status: ObservationStatus,
    ) -> Result<Self, ModelError> {
        scope_digest.validate()?;
        limit_digest.validate()?;
        limit.validate()?;
        spent.validate()?;
        remaining.validate()?;
        if limit.currency != spent.currency
            || limit.currency != remaining.currency
            || period_end <= period_start
            || period_end - period_start > Duration::days(MAX_QUERY_WINDOW_DAYS)
        {
            return Err(ModelError::InvalidObservation);
        }
        let mut observation = Self {
            scope_digest,
            limit_digest,
            period_start,
            period_end,
            limit,
            spent,
            remaining,
            status,
            observation_digest: Digest::from_text("pending-limit-observation"),
        };
        observation.observation_digest = observation.compute_digest();
        Ok(observation)
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            &self.scope_digest,
            &self.limit_digest,
            self.period_start,
            self.period_end,
            &self.limit,
            &self.spent,
            &self.remaining,
            self.status,
        ))
        .expect("limit observation digest material serializes")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.scope_digest.validate()?;
        self.limit_digest.validate()?;
        self.limit.validate()?;
        self.spent.validate()?;
        self.remaining.validate()?;
        if self.compute_digest() != self.observation_digest {
            return Err(ModelError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Active,
    Inactive,
    Denied,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyObservation {
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub policy_revision_digest: Digest,
    pub status: PolicyStatus,
    pub rule_count: u16,
    pub observation_digest: Digest,
}

impl PolicyObservation {
    pub fn new(
        scope: &BrexSpendScope,
        policy: Option<&PolicyId>,
        policy_revision_digest: Digest,
        status: PolicyStatus,
        rule_count: u16,
    ) -> Result<Self, ModelError> {
        Self::for_digests(
            scope.scope_digest.clone(),
            policy.map_or_else(
                || Digest::from_text("brex-policy-observation/default"),
                PolicyId::digest,
            ),
            policy_revision_digest,
            status,
            rule_count,
        )
    }

    pub fn for_digests(
        scope_digest: Digest,
        policy_digest: Digest,
        policy_revision_digest: Digest,
        status: PolicyStatus,
        rule_count: u16,
    ) -> Result<Self, ModelError> {
        scope_digest.validate()?;
        policy_digest.validate()?;
        policy_revision_digest.validate()?;
        if rule_count > 512 {
            return Err(ModelError::BoundExceeded {
                field: "policy rule count",
            });
        }
        let mut observation = Self {
            scope_digest,
            policy_digest,
            policy_revision_digest,
            status,
            rule_count,
            observation_digest: Digest::from_text("pending-policy-observation"),
        };
        observation.observation_digest = observation.compute_digest();
        Ok(observation)
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            &self.scope_digest,
            &self.policy_digest,
            &self.policy_revision_digest,
            self.status,
            self.rule_count,
        ))
        .expect("policy observation digest material serializes")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.scope_digest.validate()?;
        self.policy_digest.validate()?;
        self.policy_revision_digest.validate()?;
        if self.rule_count > 512 || self.compute_digest() != self.observation_digest {
            return Err(ModelError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrexSpendObservation {
    Spend(SpendObservation),
    Limit(LimitObservation),
    Policy(PolicyObservation),
}

impl BrexSpendObservation {
    #[must_use]
    pub const fn operation(&self) -> SpendOperation {
        match self {
            Self::Spend(_) => SpendOperation::ReadSpend,
            Self::Limit(_) => SpendOperation::ReadLimits,
            Self::Policy(_) => SpendOperation::ReadPolicies,
        }
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::Spend(value) => &value.scope_digest,
            Self::Limit(value) => &value.scope_digest,
            Self::Policy(value) => &value.scope_digest,
        }
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        match self {
            Self::Spend(value) => &value.observation_digest,
            Self::Limit(value) => &value.observation_digest,
            Self::Policy(value) => &value.observation_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Spend(value) => value.validate(),
            Self::Limit(value) => value.validate(),
            Self::Policy(value) => value.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendEvidenceState {
    Complete,
    Denied,
    Expired,
    Partial,
    ProviderUnknown,
    RateLimited,
    Tampered,
    RegistrationRevoked,
}

impl SpendEvidenceState {
    #[must_use]
    pub const fn is_adoptable(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_terminal_failure(self) -> bool {
        !matches!(self, Self::Complete | Self::Partial)
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_id: String,
    scope_digest: Digest,
    consent_digest: Digest,
    revision: RevisionId,
    expires_at: Option<DateTime<Utc>>,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        consent_digest: Digest,
        revision: impl Into<RevisionId>,
    ) -> Result<Self, ModelError> {
        Self::with_expiry(reference_id, scope_digest, consent_digest, revision, None)
    }

    pub fn with_expiry(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        consent_digest: Digest,
        revision: impl Into<RevisionId>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(&reference_id, "SecretReference", MAX_IDENTIFIER_BYTES)?;
        if reference_id.chars().any(char::is_whitespace) {
            return Err(ModelError::InvalidText {
                field: "SecretReference",
            });
        }
        scope_digest.validate()?;
        consent_digest.validate()?;
        let reference = Self {
            reference_id,
            scope_digest,
            consent_digest,
            revision: revision.into(),
            expires_at,
            revoked: false,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &BrexSpendScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope.scope_digest.clone(),
            scope.consent.digest(),
            scope.scope_revision.clone(),
        )
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        &self.revision
    }

    #[must_use]
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    #[must_use]
    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "brex-secret-reference/v1",
            &[
                ("reference", self.reference_id.clone()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("revision", self.revision.as_str().to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self, now: DateTime<Utc>) -> Result<(), ModelError> {
        self.validate()?;
        if self.revoked {
            return Err(ModelError::Revoked);
        }
        if self.expires_at.is_some_and(|expires_at| now >= expires_at) {
            return Err(ModelError::ConsentExpired);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(&self.reference_id, "SecretReference", MAX_IDENTIFIER_BYTES)?;
        self.scope_digest.validate()?;
        self.consent_digest.validate()?;
        if self.revision.as_str().is_empty() {
            return Err(ModelError::InvalidRevision {
                field: "SecretReference",
            });
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &"<opaque>")
            .field("scope_digest", &self.scope_digest)
            .field("consent_digest", &self.consent_digest)
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.reference_id.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendRegistration {
    pub status: RegistrationStatus,
    pub reversible: bool,
    pub revocable: bool,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: RevisionId,
    pub registration_digest: Digest,
}

impl BrexSpendRegistration {
    pub fn new(
        provider_digest: Digest,
        permission_digest: Digest,
        consent_digest: Digest,
        scope_digest: Digest,
        secret_reference_digest: Digest,
        registration_revision: RevisionId,
    ) -> Result<Self, ModelError> {
        let mut registration = Self {
            status: RegistrationStatus::Active,
            reversible: true,
            revocable: true,
            plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest,
            consent_digest,
            scope_digest,
            secret_reference_digest,
            registration_revision,
            registration_digest: Digest::from_text("pending-registration-digest"),
        };
        registration.registration_digest = registration.compute_digest();
        registration.validate()?;
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            self.status,
            self.reversible,
            self.revocable,
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.secret_reference_digest,
            &self.registration_revision,
        ))
        .expect("registration digest material serializes")
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(ModelError::Revoked)
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.scope_digest.validate()?;
        self.secret_reference_digest.validate()?;
        if !self.reversible || !self.revocable || self.compute_digest() != self.registration_digest
        {
            return Err(ModelError::InvalidDigest {
                field: "registration digest",
            });
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.status != RegistrationStatus::Active {
            return Err(ModelError::AlreadyRevoked);
        }
        let prior_registration_digest = self.registration_digest.clone();
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocation {
            prior_registration_digest,
            revocation_digest: self.registration_digest.clone(),
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(ModelError::AlreadyReversed);
        }
        let prior_registration_digest = self.registration_digest.clone();
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocation {
            prior_registration_digest,
            revocation_digest: self.registration_digest.clone(),
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(ModelError::AlreadyReversed);
        }
        let prior_registration_digest = self.registration_digest.clone();
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocation {
            prior_registration_digest,
            revocation_digest: self.registration_digest.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub prior_registration_digest: Digest,
    pub revocation_digest: Digest,
}

pub type Registration = BrexSpendRegistration;

// Keep these aliases discoverable for callers using the sibling result-plugin
// vocabulary.
pub type BrexScope = BrexSpendScope;
pub type SpendScope = BrexSpendScope;
pub type Revision = RevisionId;
pub type EvidenceState = SpendEvidenceState;
pub type ProviderProvenance = TransportProvenance;

// Compile-time references keep the bounds visible to the module when the
// provider implementation changes them independently.
const _: usize = MAX_PAGE_SIZE;
const _: usize = MAX_ITEMS;
const _: usize = MAX_RESPONSE_BYTES;
