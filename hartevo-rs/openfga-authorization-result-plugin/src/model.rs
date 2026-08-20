use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use zeroize::Zeroize;

use crate::error::{OpenFgaAuthorizationResultError, Result};

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self(crate::sha256_hex(value.as_ref().as_bytes()))
    }

    #[must_use]
    pub(crate) fn from_parts(domain: &str, parts: &[(&str, String)]) -> Self {
        let mut input = String::from(domain);
        for (key, value) in parts {
            input.push('|');
            input.push_str(key);
            input.push('=');
            input.push_str(value);
        }
        Self::from_text(input)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(OpenFgaAuthorizationResultError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_digest(&self.0) {
            Ok(())
        } else {
            Err(OpenFgaAuthorizationResultError::InvalidDigest)
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        Self::new_labeled(value, "revision")
    }

    pub(crate) fn new_labeled(value: u64, label: &'static str) -> Result<Self> {
        if value == 0 {
            Err(OpenFgaAuthorizationResultError::InvalidRevision { label })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An identifier retains its value only inside the provider boundary. Its
/// serialization and Debug representation are always the digest.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RedactedIdentifier {
    raw: String,
    digest: Digest,
}

impl RedactedIdentifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Self::new_labeled(value, "identifier")
    }

    pub(crate) fn new_labeled(value: impl Into<String>, label: &'static str) -> Result<Self> {
        let value = value.into();
        if !valid_text(&value, crate::MAX_IDENTIFIER_BYTES) {
            return Err(OpenFgaAuthorizationResultError::InvalidIdentifier { label });
        }
        Ok(Self {
            digest: Digest::from_parts(
                "openfga-identifier/v1",
                &[("label", label.to_owned()), ("value", value.clone())],
            ),
            raw: value,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub(crate) fn raw(&self) -> &str {
        &self.raw
    }
}

impl Serialize for RedactedIdentifier {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest.as_str())
    }
}

impl fmt::Debug for RedactedIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedIdentifier")
            .field("digest", &self.digest)
            .finish()
    }
}

pub type StoreId = RedactedIdentifier;
pub type AuthorizationModelId = RedactedIdentifier;
pub type UserRef = RedactedIdentifier;
pub type ObjectRef = RedactedIdentifier;
pub type RelationName = RedactedIdentifier;
pub type ProjectId = RedactedIdentifier;
pub type MissionId = RedactedIdentifier;
pub type WorkProductId = RedactedIdentifier;
pub type OpenFgaStoreId = StoreId;
pub type OpenFgaModelId = AuthorizationModelId;
pub type OpenFgaUser = UserRef;
pub type OpenFgaObject = ObjectRef;
pub type OpenFgaRelation = RelationName;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreIdentity {
    id: StoreId,
    revision: Revision,
}

impl StoreIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: StoreId::new_labeled(id, "store")?,
            revision: Revision::new_labeled(revision, "store")?,
        })
    }

    #[must_use]
    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-store/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationModelIdentity {
    id: AuthorizationModelId,
    revision: Revision,
}

pub type OpenFgaModelIdentity = AuthorizationModelIdentity;

impl AuthorizationModelIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: AuthorizationModelId::new_labeled(id, "authorization model")?,
            revision: Revision::new_labeled(revision, "authorization model")?,
        })
    }

    #[must_use]
    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-authorization-model/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

macro_rules! mission_identity {
    ($name:ident, $alias:ty, $label:literal, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            id: $alias,
            revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                Ok(Self {
                    id: <$alias>::new_labeled(id, $label)?,
                    revision: Revision::new_labeled(revision, $label)?,
                })
            }

            #[must_use]
            pub fn id_digest(&self) -> Digest {
                self.id.digest()
            }

            #[must_use]
            pub const fn revision(&self) -> Revision {
                self.revision
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.digest().to_string()),
                        ("revision", self.revision.get().to_string()),
                    ],
                )
            }
        }
    };
}

mission_identity!(ProjectIdentity, ProjectId, "project", "openfga-project/v1");
mission_identity!(MissionIdentity, MissionId, "mission", "openfga-mission/v1");
mission_identity!(
    WorkProductIdentity,
    WorkProductId,
    "work product",
    "openfga-work-product/v1"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenFgaScope {
    store: StoreIdentity,
    authorization_model: AuthorizationModelIdentity,
    project: ProjectIdentity,
    mission: MissionIdentity,
    work_product: WorkProductIdentity,
}

impl OpenFgaScope {
    pub fn new(
        store: StoreIdentity,
        authorization_model: AuthorizationModelIdentity,
        project: ProjectIdentity,
        mission: MissionIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            store,
            authorization_model,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_parts(
        store_id: impl Into<String>,
        store_revision: u64,
        model_id: impl Into<String>,
        model_revision: u64,
        project_id: impl Into<String>,
        project_revision: u64,
        mission_id: impl Into<String>,
        mission_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self> {
        Self::new(
            StoreIdentity::new(store_id, store_revision)?,
            AuthorizationModelIdentity::new(model_id, model_revision)?,
            ProjectIdentity::new(project_id, project_revision)?,
            MissionIdentity::new(mission_id, mission_revision)?,
            WorkProductIdentity::new(work_product_id, work_product_revision)?,
        )
    }

    #[must_use]
    pub fn store(&self) -> &StoreIdentity {
        &self.store
    }

    #[must_use]
    pub fn authorization_model(&self) -> &AuthorizationModelIdentity {
        &self.authorization_model
    }

    #[must_use]
    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-scope/v1",
            &[
                ("store", self.store.digest().to_string()),
                (
                    "authorization_model",
                    self.authorization_model.digest().to_string(),
                ),
                ("project", self.project.digest().to_string()),
                ("mission", self.mission.digest().to_string()),
                ("work_product", self.work_product.digest().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.store.revision().get() == 0
            || self.authorization_model.revision().get() == 0
            || self.project.revision().get() == 0
            || self.mission.revision().get() == 0
            || self.work_product.revision().get() == 0
        {
            return Err(OpenFgaAuthorizationResultError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeEvidence {
    pub scope_digest: Digest,
    pub store_digest: Digest,
    pub model_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
}

impl ScopeEvidence {
    #[must_use]
    pub fn from_scope(scope: &OpenFgaScope) -> Self {
        Self {
            scope_digest: scope.digest(),
            store_digest: scope.store.digest(),
            model_digest: scope.authorization_model.digest(),
            project_digest: scope.project.digest(),
            mission_digest: scope.mission.digest(),
            work_product_digest: scope.work_product.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationCheckScope {
    pub user: UserRef,
    pub object: ObjectRef,
    pub relation: RelationName,
    pub revision: Revision,
}

pub type OpenFgaAuthorizationCheckScope = AuthorizationCheckScope;

impl AuthorizationCheckScope {
    pub fn new(
        user: impl Into<String>,
        relation: impl Into<String>,
        object: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        Ok(Self {
            user: UserRef::new_labeled(user, "user")?,
            object: ObjectRef::new_labeled(object, "object")?,
            relation: RelationName::new_labeled(relation, "relation")?,
            revision: Revision::new_labeled(revision, "authorization check")?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-authorization-check-scope/v1",
            &[
                ("user", self.user.digest().to_string()),
                ("object", self.object.digest().to_string()),
                ("relation", self.relation.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TupleScope {
    pub user: UserRef,
    pub object: ObjectRef,
    pub relation: RelationName,
    pub revision: Revision,
}

pub type OpenFgaTupleScope = TupleScope;

impl TupleScope {
    pub fn new(
        user: impl Into<String>,
        relation: impl Into<String>,
        object: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        Ok(Self {
            user: UserRef::new_labeled(user, "user")?,
            object: ObjectRef::new_labeled(object, "object")?,
            relation: RelationName::new_labeled(relation, "relation")?,
            revision: Revision::new_labeled(revision, "tuple")?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-tuple-scope/v1",
            &[
                ("user", self.user.digest().to_string()),
                ("object", self.object.digest().to_string()),
                ("relation", self.relation.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TupleKey {
    pub user: UserRef,
    pub object: ObjectRef,
    pub relation: RelationName,
}

impl TupleKey {
    pub fn new(
        user: impl Into<String>,
        relation: impl Into<String>,
        object: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            user: UserRef::new_labeled(user, "user")?,
            object: ObjectRef::new_labeled(object, "object")?,
            relation: RelationName::new_labeled(relation, "relation")?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-tuple-key/v1",
            &[
                ("user", self.user.digest().to_string()),
                ("object", self.object.digest().to_string()),
                ("relation", self.relation.digest().to_string()),
            ],
        )
    }

    pub(crate) fn matches(&self, scope: &TupleScope) -> bool {
        self.user.digest() == scope.user.digest()
            && self.object.digest() == scope.object.digest()
            && self.relation.digest() == scope.relation.digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    consent_id_digest: Digest,
    revision: Revision,
    expires_at: DateTime<Utc>,
    scope_digest: Digest,
}

impl ConsentScope {
    pub fn for_layer_one(
        consent_id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let consent_id = RedactedIdentifier::new_labeled(consent_id, "consent")?;
        Ok(Self {
            consent_id_digest: consent_id.digest(),
            revision: Revision::new_labeled(revision, "consent")?,
            expires_at,
            scope_digest: Digest::from_text("unbound-openfga-consent-scope"),
        })
    }

    pub fn for_scope(
        consent_id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
        scope: &OpenFgaScope,
    ) -> Result<Self> {
        let mut consent = Self::for_layer_one(consent_id, revision, expires_at)?;
        consent.scope_digest = scope.digest();
        Ok(consent)
    }

    pub fn bind_scope(mut self, scope: &OpenFgaScope) -> Result<Self> {
        if self.scope_digest != Digest::from_text("unbound-openfga-consent-scope")
            && self.scope_digest != scope.digest()
        {
            return Err(OpenFgaAuthorizationResultError::ScopeMismatch);
        }
        self.scope_digest = scope.digest();
        Ok(self)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-consent/v1",
            &[
                ("id", self.consent_id_digest.to_string()),
                ("revision", self.revision.get().to_string()),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("scope", self.scope_digest.to_string()),
            ],
        )
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }

    pub(crate) fn validate(&self, scope: &OpenFgaScope, now: DateTime<Utc>) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(OpenFgaAuthorizationResultError::ScopeMismatch);
        }
        if !self.is_active_at(now) {
            return Err(OpenFgaAuthorizationResultError::ConsentExpired);
        }
        self.digest().validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OpenFgaCredential,
}

/// An opaque, non-serializing SecretReference. The supplied handle is hashed
/// and zeroized immediately; no credential material is retained by Layer-1.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, crate::MAX_IDENTIFIER_BYTES) {
            handle.zeroize();
            return Err(OpenFgaAuthorizationResultError::InvalidSecretReference);
        }
        let revision = match Revision::new_labeled(revision, "secret reference") {
            Ok(revision) => revision,
            Err(error) => {
                handle.zeroize();
                return Err(error);
            }
        };
        let reference_digest = Digest::from_parts(
            "openfga-opaque-secret-reference/v1",
            &[
                ("kind", "openfga_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.get().to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::OpenFgaCredential,
            reference_digest,
            scope_digest: Digest::from_text("unbound-openfga-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn openfga(
        opaque_handle: impl Into<String>,
        scope: &OpenFgaScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_handle, revision)?.bind_scope(scope)
    }

    pub fn bind_scope(mut self, scope: &OpenFgaScope) -> Result<Self> {
        if self.scope_digest != Digest::from_text("unbound-openfga-secret-scope")
            && self.scope_digest != scope.digest()
        {
            return Err(OpenFgaAuthorizationResultError::ScopeMismatch);
        }
        self.scope_digest = scope.digest();
        self.reference_digest = Digest::from_parts(
            "openfga-opaque-secret-reference/v1",
            &[
                ("kind", "openfga_credential".to_owned()),
                ("reference", self.reference_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        );
        Ok(self)
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
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(OpenFgaAuthorizationResultError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(OpenFgaAuthorizationResultError::NotRevoked)
        }
    }

    pub(crate) fn validate(&self, scope: &OpenFgaScope) -> Result<()> {
        if self.kind != SecretKind::OpenFgaCredential
            || self.revoked
            || self.scope_digest != scope.digest()
            || self.revision.get() == 0
        {
            return Err(OpenFgaAuthorizationResultError::InvalidSecretReference);
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
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
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
pub enum OpenFgaEvidenceState {
    Ready,
    Denied,
    Partial,
    Stale,
    Tampered,
    ProviderUnknown,
    RateLimited,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    TimedOut,
    ConsentExpired,
    RegistrationRevoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allowed,
    Denied,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelEvidence {
    pub model_digest: Digest,
    pub model_revision_digest: Digest,
    pub type_count: u16,
    pub relation_count: u16,
    pub rules_digest: Digest,
    pub response_bytes: u64,
    pub evidence_digest: Digest,
}

impl ModelEvidence {
    pub(crate) fn new(
        model_digest: Digest,
        model_revision_digest: Digest,
        type_count: u16,
        relation_count: u16,
        rules_digest: Digest,
        response_bytes: u64,
    ) -> Self {
        let evidence_digest = Digest::from_parts(
            "openfga-model-evidence/v1",
            &[
                ("model", model_digest.to_string()),
                ("revision", model_revision_digest.to_string()),
                ("types", type_count.to_string()),
                ("relations", relation_count.to_string()),
                ("rules", rules_digest.to_string()),
                ("bytes", response_bytes.to_string()),
            ],
        );
        Self {
            model_digest,
            model_revision_digest,
            type_count,
            relation_count,
            rules_digest,
            response_bytes,
            evidence_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.model_digest,
            &self.model_revision_digest,
            &self.rules_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self.type_count > crate::MAX_MODEL_TYPES
            || self.relation_count > crate::MAX_MODEL_RELATIONS
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.evidence_digest
                != Digest::from_parts(
                    "openfga-model-evidence/v1",
                    &[
                        ("model", self.model_digest.to_string()),
                        ("revision", self.model_revision_digest.to_string()),
                        ("types", self.type_count.to_string()),
                        ("relations", self.relation_count.to_string()),
                        ("rules", self.rules_digest.to_string()),
                        ("bytes", self.response_bytes.to_string()),
                    ],
                )
        {
            return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckEvidence {
    pub decision: AuthorizationDecision,
    pub user_digest: Digest,
    pub object_digest: Digest,
    pub relation_digest: Digest,
    pub model_digest: Digest,
    pub check_revision_digest: Digest,
    pub check_digest: Digest,
}

impl CheckEvidence {
    pub(crate) fn new(
        decision: AuthorizationDecision,
        user_digest: Digest,
        object_digest: Digest,
        relation_digest: Digest,
        model_digest: Digest,
        check_revision_digest: Digest,
    ) -> Self {
        let check_digest = Digest::from_parts(
            "openfga-check-evidence/v1",
            &[
                ("decision", format!("{decision:?}")),
                ("user", user_digest.to_string()),
                ("object", object_digest.to_string()),
                ("relation", relation_digest.to_string()),
                ("model", model_digest.to_string()),
                ("revision", check_revision_digest.to_string()),
            ],
        );
        Self {
            decision,
            user_digest,
            object_digest,
            relation_digest,
            model_digest,
            check_revision_digest,
            check_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.user_digest,
            &self.object_digest,
            &self.relation_digest,
            &self.model_digest,
            &self.check_revision_digest,
            &self.check_digest,
        ] {
            digest.validate()?;
        }
        if self.check_digest
            != Digest::from_parts(
                "openfga-check-evidence/v1",
                &[
                    ("decision", format!("{:?}", self.decision)),
                    ("user", self.user_digest.to_string()),
                    ("object", self.object_digest.to_string()),
                    ("relation", self.relation_digest.to_string()),
                    ("model", self.model_digest.to_string()),
                    ("revision", self.check_revision_digest.to_string()),
                ],
            )
        {
            return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TupleEvidence {
    pub tuple_digest: Digest,
    pub user_digest: Digest,
    pub object_digest: Digest,
    pub relation_digest: Digest,
    pub tuple_revision_digest: Digest,
    pub evidence_digest: Digest,
}

impl TupleEvidence {
    pub(crate) fn new(tuple: &TupleKey, tuple_revision: Revision) -> Self {
        let tuple_digest = tuple.digest();
        let tuple_revision_digest = Digest::from_text(format!(
            "openfga-tuple-revision/v1|{}",
            tuple_revision.get()
        ));
        let evidence_digest = Digest::from_parts(
            "openfga-tuple-evidence/v1",
            &[
                ("tuple", tuple_digest.to_string()),
                ("user", tuple.user.digest().to_string()),
                ("object", tuple.object.digest().to_string()),
                ("relation", tuple.relation.digest().to_string()),
                ("revision", tuple_revision_digest.to_string()),
            ],
        );
        Self {
            tuple_digest,
            user_digest: tuple.user.digest(),
            object_digest: tuple.object.digest(),
            relation_digest: tuple.relation.digest(),
            tuple_revision_digest,
            evidence_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.tuple_digest,
            &self.user_digest,
            &self.object_digest,
            &self.relation_digest,
            &self.tuple_revision_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        let expected = Digest::from_parts(
            "openfga-tuple-evidence/v1",
            &[
                ("tuple", self.tuple_digest.to_string()),
                ("user", self.user_digest.to_string()),
                ("object", self.object_digest.to_string()),
                ("relation", self.relation_digest.to_string()),
                ("revision", self.tuple_revision_digest.to_string()),
            ],
        );
        if expected != self.evidence_digest {
            return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
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
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub model_digest: Digest,
    pub check_digest: Digest,
    pub tuple_digest: Digest,
    pub revision_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn new(
        provider_digest: Digest,
        scope_digest: Digest,
        consent_digest: Digest,
        registration_digest: Digest,
        model_digest: Digest,
        check_digest: Digest,
        tuple_digest: Digest,
        revision_digest: Digest,
    ) -> Self {
        let permission_digest = Digest::from_parts(
            "openfga-layer1-permissions/v1",
            &[
                ("read_model", "openfga:ReadAuthorizationModel".to_owned()),
                ("check", "openfga:Check".to_owned()),
                ("read", "openfga:Read".to_owned()),
                ("mission", "mission.scope".to_owned()),
            ],
        );
        let api_digest = Digest::from_text(crate::PROVIDER_API_REVISION);
        let contract_digest = Digest::from_text(crate::CONTRACT_DIGEST_INPUT);
        let plugin_version_digest = Digest::from_text(crate::PLUGIN_VERSION);
        let evidence_digest = Digest::from_parts(
            "openfga-evidence/v1",
            &[
                ("plugin", plugin_version_digest.to_string()),
                ("contract", contract_digest.to_string()),
                ("provider", provider_digest.to_string()),
                ("api", api_digest.to_string()),
                ("permission", permission_digest.to_string()),
                ("scope", scope_digest.to_string()),
                ("consent", consent_digest.to_string()),
                ("registration", registration_digest.to_string()),
                ("model", model_digest.to_string()),
                ("check", check_digest.to_string()),
                ("tuple", tuple_digest.to_string()),
                ("revision", revision_digest.to_string()),
            ],
        );
        Self {
            plugin_version_digest,
            contract_digest,
            provider_digest,
            api_digest,
            permission_digest,
            scope_digest,
            consent_digest,
            registration_digest,
            model_digest,
            check_digest,
            tuple_digest,
            revision_digest,
            evidence_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.consent_digest,
            &self.registration_digest,
            &self.model_digest,
            &self.check_digest,
            &self.tuple_digest,
            &self.revision_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        let expected = Self::new(
            self.provider_digest.clone(),
            self.scope_digest.clone(),
            self.consent_digest.clone(),
            self.registration_digest.clone(),
            self.model_digest.clone(),
            self.check_digest.clone(),
            self.tuple_digest.clone(),
            self.revision_digest.clone(),
        );
        if expected != *self {
            return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub model_digest: Digest,
    pub check_digest: Digest,
    pub tuple_query_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub redacted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u16,
    pub cost_digest: Digest,
    pub redacted: bool,
    pub estimate_only: bool,
    pub durable_provider_receipt: bool,
}
