//! Redacted Sift scope, registration, projection, and provenance models.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{
    Deserialize, Serialize, Serializer,
    ser::{Error as SerError, SerializeStruct},
};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{Result, SiftFraudResultError};
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, PLUGIN_VERSION};

pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_ABUSE_TYPES: usize = 4;
pub const MAX_WORKFLOW_STATUSES: usize = 8;
pub const MAX_REVIEW_RECORDS: usize = 8;

/// A lowercase SHA-256 digest used as the boundary's stable redaction value.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

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
            Err(SiftFraudResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(SiftFraudResultError::InvalidDigest)
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("canonical value serializes"))
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
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        })
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value, MAX_IDENTIFIER_BYTES) {
                    Ok(Self(value))
                } else {
                    Err(SiftFraudResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("sift-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.0, MAX_IDENTIFIER_BYTES) {
                    Ok(())
                } else {
                    Err(SiftFraudResultError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
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
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

redacted_identifier!(SiftAccountId, "account-id");
redacted_identifier!(SiftUserId, "user-id");
redacted_identifier!(SiftOrderId, "order-id");
redacted_identifier!(SiftDecisionId, "decision-id");
redacted_identifier!(SiftScoreId, "score-id");
redacted_identifier!(SiftReviewId, "review-id");

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: String,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identity(&id, revision, "project")?;
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts("sift-project-id/v1", &[("id", self.id.clone())])
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-project/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identity(&self.id, self.revision, "project")
    }
}

impl fmt::Debug for ProjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentity")
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for ProjectIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ProjectIdentity", 3)?;
        state.serialize_field("idDigest", &self.id_digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("digest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: String,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identity(&id, revision, "mission")?;
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts("sift-mission-id/v1", &[("id", self.id.clone())])
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-mission/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identity(&self.id, self.revision, "mission")
    }
}

impl fmt::Debug for MissionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIdentity")
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for MissionIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("MissionIdentity", 3)?;
        state.serialize_field("idDigest", &self.id_digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("digest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: String,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identity(&id, revision, "work-product")?;
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts("sift-work-product-id/v1", &[("id", self.id.clone())])
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-work-product/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identity(&self.id, self.revision, "work-product")
    }
}

impl fmt::Debug for WorkProductIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductIdentity")
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for WorkProductIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("WorkProductIdentity", 3)?;
        state.serialize_field("idDigest", &self.id_digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("digest", &self.digest())?;
        state.end()
    }
}

fn validate_identity(id: &str, revision: u64, field: &'static str) -> Result<()> {
    if !valid_identifier(id, MAX_IDENTIFIER_BYTES) {
        return Err(SiftFraudResultError::InvalidIdentifier { field });
    }
    if revision == 0 {
        return Err(SiftFraudResultError::InvalidRevision { field });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
    pub digest: Digest,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: value.id_digest(),
            revision: value.revision,
            digest: value.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
    pub digest: Digest,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: value.id_digest(),
            revision: value.revision,
            digest: value.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
    pub digest: Digest,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(value: &WorkProductIdentity) -> Self {
        Self {
            id_digest: value.id_digest(),
            revision: value.revision,
            digest: value.digest(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SiftFraudResultScope {
    account: SiftAccountId,
    user: SiftUserId,
    order: SiftOrderId,
    decision: SiftDecisionId,
    score: SiftScoreId,
    review: SiftReviewId,
    project: ProjectIdentity,
    mission: MissionIdentity,
    work_product: WorkProductIdentity,
}

impl SiftFraudResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: SiftAccountId,
        user: SiftUserId,
        order: SiftOrderId,
        decision: SiftDecisionId,
        score: SiftScoreId,
        review: SiftReviewId,
        project: ProjectIdentity,
        mission: MissionIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            user,
            order,
            decision,
            score,
            review,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &SiftAccountId {
        &self.account
    }

    pub fn user(&self) -> &SiftUserId {
        &self.user
    }

    pub fn order(&self) -> &SiftOrderId {
        &self.order
    }

    pub fn decision(&self) -> &SiftDecisionId {
        &self.decision
    }

    pub fn score(&self) -> &SiftScoreId {
        &self.score
    }

    pub fn review(&self) -> &SiftReviewId {
        &self.review
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn entity_digest(&self) -> Digest {
        Digest::from_parts(
            "sift-entity/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("user", self.user.digest().as_str().to_owned()),
                ("order", self.order.digest().as_str().to_owned()),
            ],
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-fraud-result-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("user", self.user.digest().as_str().to_owned()),
                ("order", self.order.digest().as_str().to_owned()),
                ("decision", self.decision.digest().as_str().to_owned()),
                ("score", self.score.digest().as_str().to_owned()),
                ("review", self.review.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.user.validate()?;
        self.order.validate()?;
        self.decision.validate()?;
        self.score.validate()?;
        self.review.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        Ok(())
    }
}

impl fmt::Debug for SiftFraudResultScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiftFraudResultScope")
            .field("scope_digest", &self.digest())
            .field("project_revision", &self.project.revision)
            .field("mission_revision", &self.mission.revision)
            .field("work_product_revision", &self.work_product.revision)
            .finish()
    }
}

impl Serialize for SiftFraudResultScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SiftFraudResultScope", 10)?;
        state.serialize_field("account", &self.account.digest())?;
        state.serialize_field("user", &self.user.digest())?;
        state.serialize_field("order", &self.order.digest())?;
        state.serialize_field("decision", &self.decision.digest())?;
        state.serialize_field("score", &self.score.digest())?;
        state.serialize_field("review", &self.review.digest())?;
        state.serialize_field("project", &ProjectProjection::from(&self.project))?;
        state.serialize_field("mission", &MissionProjection::from(&self.mission))?;
        state.serialize_field(
            "workProduct",
            &WorkProductProjection::from(&self.work_product),
        )?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    pub reference_digest: Digest,
    pub revision: u64,
    pub expires_at: DateTime<Utc>,
    pub layer: u8,
}

impl ConsentScope {
    pub fn for_layer_one(
        reference: impl AsRef<str>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let reference = reference.as_ref();
        if !valid_text(reference, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            return Err(SiftFraudResultError::InvalidConsent);
        }
        Ok(Self {
            reference_digest: Digest::from_parts(
                "sift-consent-reference/v1",
                &[("reference", reference.to_owned())],
            ),
            revision,
            expires_at,
            layer: 1,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-consent/v1",
            &[
                ("reference", self.reference_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("layer", self.layer.to_string()),
            ],
        )
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        self.reference_digest.validate()?;
        if self.revision == 0 || self.layer != 1 || self.expires_at <= now {
            return Err(SiftFraudResultError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftPermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

impl SiftPermissionSnapshot {
    pub fn for_layer_one(revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(SiftFraudResultError::InvalidRevision {
                field: "permission snapshot",
            });
        }
        let permissions = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        let digest = Digest::from_parts(
            "sift-permissions/v1",
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

    pub fn validate(&self) -> Result<()> {
        let expected = Self::for_layer_one(self.revision)?;
        if expected.permissions != self.permissions || expected.digest != self.digest {
            return Err(SiftFraudResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

/// An opaque API-key handle. The raw handle cannot be serialized or printed.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_handle: String,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_handle = opaque_handle.into();
        if !valid_text(&opaque_handle, MAX_SECRET_REFERENCE_BYTES, false) || revision == 0 {
            return Err(SiftFraudResultError::InvalidSecretReference);
        }
        Ok(Self {
            opaque_handle,
            revision,
            revoked: false,
        })
    }

    pub fn api_key(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(opaque_handle, revision)
    }

    pub fn sift(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(opaque_handle, revision)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn reference_digest(&self) -> Digest {
        self.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-api-key-reference/v1",
            &[
                ("opaque_handle", self.opaque_handle.clone()),
                ("revision", self.revision.to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(SiftFraudResultError::RegistrationAlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        if !self.revoked {
            return Err(SiftFraudResultError::RegistrationNotRevoked);
        }
        self.revoked = false;
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_text(&self.opaque_handle, MAX_SECRET_REFERENCE_BYTES, false) && self.revision > 0 {
            Ok(())
        } else {
            Err(SiftFraudResultError::InvalidSecretReference)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.digest())
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error> {
        Err(S::Error::custom(
            "SecretReference is intentionally non-serializing",
        ))
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.opaque_handle.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub before_status: RegistrationStatus,
    pub after_status: RegistrationStatus,
    pub before_digest: Digest,
    pub after_digest: Digest,
    pub registration_revision: u64,
    pub transition_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SiftFraudResultRegistration {
    registration_id: String,
    scope_digest: Digest,
    provider_digest: Digest,
    provider_revision: String,
    permission_snapshot: SiftPermissionSnapshot,
    consent: ConsentScope,
    secret_reference_digest: Digest,
    project_revision: u64,
    mission_revision: u64,
    work_product_revision: u64,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

pub type SiftRegistration = SiftFraudResultRegistration;

impl fmt::Debug for SiftFraudResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiftFraudResultRegistration")
            .field("registration_digest", &self.registration_digest)
            .field("scope_digest", &self.scope_digest)
            .field("status", &self.status)
            .field("registration_revision", &self.registration_revision)
            .finish()
    }
}

impl Serialize for SiftFraudResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SiftFraudResultRegistration", 12)?;
        state.serialize_field(
            "registrationIdDigest",
            &Digest::from_text(&self.registration_id),
        )?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("consent", &self.consent)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("projectRevision", &self.project_revision)?;
        state.serialize_field("missionRevision", &self.mission_revision)?;
        state.serialize_field("workProductRevision", &self.work_product_revision)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl SiftFraudResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: impl Into<String>,
        scope: &SiftFraudResultScope,
        secret_reference: &SecretReference,
        permission_snapshot: SiftPermissionSnapshot,
        consent: ConsentScope,
        provider_revision: impl Into<String>,
        provider_digest: &Digest,
        registration_revision: u64,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration_id = registration_id.into();
        let provider_revision = provider_revision.into();
        if !valid_identifier(&registration_id, MAX_IDENTIFIER_BYTES)
            || provider_revision.is_empty()
            || registration_revision == 0
        {
            return Err(SiftFraudResultError::InvalidRequest);
        }
        scope.validate()?;
        secret_reference.validate()?;
        if secret_reference.is_revoked() {
            return Err(SiftFraudResultError::InvalidSecretReference);
        }
        permission_snapshot.validate()?;
        consent.validate(registration_time)?;
        provider_digest.validate()?;
        let mut registration = Self {
            registration_id,
            scope_digest: scope.digest(),
            provider_digest: provider_digest.clone(),
            provider_revision,
            permission_snapshot,
            consent,
            secret_reference_digest: secret_reference.digest(),
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-sift-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    pub fn registration_id(&self) -> &str {
        &self.registration_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn permission_snapshot(&self) -> &SiftPermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_snapshot.digest
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub const fn is_revoked(&self) -> bool {
        matches!(self.status, RegistrationStatus::Revoked)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.registration_id, MAX_IDENTIFIER_BYTES)
            || self.provider_revision.is_empty()
            || self.registration_revision == 0
        {
            return Err(SiftFraudResultError::InvalidRequest);
        }
        self.scope_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_snapshot.validate()?;
        self.consent.reference_digest.validate()?;
        self.secret_reference_digest.validate()?;
        if self.registration_digest != self.calculate_digest() {
            return Err(SiftFraudResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !self.is_active() {
            return Err(SiftFraudResultError::RegistrationAlreadyRevoked);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !self.is_revoked() {
            return Err(SiftFraudResultError::RegistrationNotRevoked);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(SiftFraudResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(&mut self, status: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let before_status = self.status;
        let before_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(SiftFraudResultError::RegistrationRevisionOverflow)?;
        self.status = status;
        self.registration_digest = self.calculate_digest();
        let after_digest = self.registration_digest.clone();
        let transition_digest = Digest::from_parts(
            "sift-registration-transition/v1",
            &[
                ("before", before_digest.as_str().to_owned()),
                ("after", after_digest.as_str().to_owned()),
                ("before_status", format!("{before_status:?}")),
                ("after_status", format!("{status:?}")),
                ("revision", self.registration_revision.to_string()),
            ],
        );
        Ok(RegistrationTransitionEvidence {
            before_status,
            after_status: status,
            before_digest,
            after_digest,
            registration_revision: self.registration_revision,
            transition_digest,
        })
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "sift-fraud-result-registration/v1",
            &[
                ("id", self.registration_id.clone()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("provider_revision", self.provider_revision.clone()),
                (
                    "permission",
                    self.permission_snapshot.digest.as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                ("project_revision", self.project_revision.to_string()),
                ("mission_revision", self.mission_revision.to_string()),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("status", format!("{:?}", self.status)),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                (
                    "contract_digest",
                    crate::contract_digest().as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn provider_receipt(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        self.connected()
    }

    pub const fn is_native(self) -> bool {
        self.native()
    }

    pub const fn is_first_party(self) -> bool {
        self.first_party()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiftDecisionDisposition {
    Allow,
    Deny,
    Review,
    Unknown,
}

impl SiftDecisionDisposition {
    pub fn from_provider(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "accept" | "allow" | "approved" => Self::Allow,
            "block" | "deny" | "decline" | "rejected" => Self::Deny,
            "watch" | "review" | "manual_review" | "pending" => Self::Review,
            _ => Self::Unknown,
        }
    }

    pub const fn is_actionable(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiftReviewState {
    Pending,
    Approved,
    Rejected,
    Unknown,
}

impl SiftReviewState {
    pub fn from_provider(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" | "queued" | "running" => Self::Pending,
            "approved" | "accept" | "accepted" => Self::Approved,
            "rejected" | "deny" | "declined" => Self::Rejected,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiftWorkflowState {
    Running,
    Finished,
    Failed,
    Unknown,
}

impl SiftWorkflowState {
    pub fn from_provider(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "running" | "in_progress" | "pending" => Self::Running,
            "finished" | "complete" | "completed" => Self::Finished,
            "failed" | "error" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiftFraudResultState {
    Allow,
    Deny,
    Review,
    Unknown,
    Partial,
    Denied,
    RateLimited,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    StaleRevision,
    NotFound,
    RegistrationRevoked,
}

impl SiftFraudResultState {
    pub const fn can_be_adopted(self) -> bool {
        false
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftDecisionProjection {
    pub entity_digest: Digest,
    pub decision_digest: Digest,
    pub abuse_type_digest: Digest,
    pub disposition: SiftDecisionDisposition,
    pub applied_at: Option<DateTime<Utc>>,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftScoreProjection {
    pub entity_digest: Digest,
    pub score_digest: Digest,
    pub abuse_type_digest: Digest,
    pub score: u8,
    pub observed_at: Option<DateTime<Utc>>,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftReviewProjection {
    pub review_digest: Digest,
    pub queue_digest: Digest,
    pub state: SiftReviewState,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftWorkflowProjection {
    pub workflow_digest: Digest,
    pub decision_digest: Option<Digest>,
    pub review_digest: Option<Digest>,
    pub state: SiftWorkflowState,
    pub revision: u64,
}
