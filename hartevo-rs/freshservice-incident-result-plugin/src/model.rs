//! Redacted Freshservice scope, metadata, consent, and provenance models.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::Error as SerError};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::MAX_IDENTIFIER_BYTES;
use crate::error::{FreshserviceIncidentResultError, Result};

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
            Err(FreshserviceIncidentResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(FreshserviceIncidentResultError::InvalidDigest)
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

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
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
                    Err(FreshserviceIncidentResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("freshservice-", $field, "/v1"),
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
                    Err(FreshserviceIncidentResultError::InvalidIdentifier { field: $field })
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
    };
}

redacted_identifier!(FreshserviceAccountId, "account-id");
redacted_identifier!(FreshserviceAgentId, "agent-id");
redacted_identifier!(FreshserviceGroupId, "group-id");
redacted_identifier!(FreshserviceIncidentId, "incident-id");
redacted_identifier!(FreshserviceChangeId, "change-id");
redacted_identifier!(FreshserviceAssetId, "asset-id");

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: String,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identity_revision(&id, revision, "project")?;
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts("freshservice-project-id/v1", &[("id", self.id.clone())])
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-project/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identity_revision(&self.id, self.revision, "project")
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

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: String,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identity_revision(&id, revision, "mission")?;
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts("freshservice-mission-id/v1", &[("id", self.id.clone())])
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-mission/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identity_revision(&self.id, self.revision, "mission")
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

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: String,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identity_revision(&id, revision, "work-product")?;
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-work-product-id/v1",
            &[("id", self.id.clone())],
        )
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-work-product/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identity_revision(&self.id, self.revision, "work-product")
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

fn validate_identity_revision(id: &str, revision: u64, field: &'static str) -> Result<()> {
    if !valid_identifier(id, MAX_IDENTIFIER_BYTES) {
        return Err(FreshserviceIncidentResultError::InvalidIdentifier { field });
    }
    if revision == 0 {
        return Err(FreshserviceIncidentResultError::InvalidRevision { field });
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
pub struct FreshserviceIncidentResultScope {
    account: FreshserviceAccountId,
    agent: FreshserviceAgentId,
    group: FreshserviceGroupId,
    incident: FreshserviceIncidentId,
    change: FreshserviceChangeId,
    asset: FreshserviceAssetId,
    project: ProjectIdentity,
    mission: MissionIdentity,
    work_product: WorkProductIdentity,
}

impl FreshserviceIncidentResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: FreshserviceAccountId,
        agent: FreshserviceAgentId,
        group: FreshserviceGroupId,
        incident: FreshserviceIncidentId,
        change: FreshserviceChangeId,
        asset: FreshserviceAssetId,
        project: ProjectIdentity,
        mission: MissionIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            agent,
            group,
            incident,
            change,
            asset,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &FreshserviceAccountId {
        &self.account
    }

    pub fn agent(&self) -> &FreshserviceAgentId {
        &self.agent
    }

    pub fn group(&self) -> &FreshserviceGroupId {
        &self.group
    }

    pub fn incident(&self) -> &FreshserviceIncidentId {
        &self.incident
    }

    pub fn change(&self) -> &FreshserviceChangeId {
        &self.change
    }

    pub fn asset(&self) -> &FreshserviceAssetId {
        &self.asset
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

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-incident-result-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("agent", self.agent.digest().as_str().to_owned()),
                ("group", self.group.digest().as_str().to_owned()),
                ("incident", self.incident.digest().as_str().to_owned()),
                ("change", self.change.digest().as_str().to_owned()),
                ("asset", self.asset.digest().as_str().to_owned()),
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
        self.agent.validate()?;
        self.group.validate()?;
        self.incident.validate()?;
        self.change.validate()?;
        self.asset.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        Ok(())
    }
}

impl fmt::Debug for FreshserviceIncidentResultScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshserviceIncidentResultScope")
            .field("scope_digest", &self.digest())
            .field("project_revision", &self.project.revision())
            .field("mission_revision", &self.mission.revision())
            .field("work_product_revision", &self.work_product.revision())
            .finish()
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
            return Err(FreshserviceIncidentResultError::InvalidConsent);
        }
        Ok(Self {
            reference_digest: Digest::from_parts(
                "freshservice-consent-reference/v1",
                &[("reference", reference.to_owned())],
            ),
            revision,
            expires_at,
            layer: 1,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-consent/v1",
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
            return Err(FreshserviceIncidentResultError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshservicePermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

impl FreshservicePermissionSnapshot {
    pub fn for_layer_one(revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRevision {
                field: "permission snapshot",
            });
        }
        let permissions = [
            "freshservice:incidents:read",
            "freshservice:changes:read",
            "freshservice:assets:read",
            "mission.scope",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let digest = Digest::from_parts(
            "freshservice-permissions/v1",
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
            return Err(FreshserviceIncidentResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

/// An opaque credential handle. The handle is never serializable or printed.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_handle: String,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_handle = opaque_handle.into();
        if !valid_text(&opaque_handle, MAX_IDENTIFIER_BYTES, false) || revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidSecretReference);
        }
        Ok(Self {
            opaque_handle,
            revision,
            revoked: false,
        })
    }

    pub fn freshservice(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(opaque_handle, revision)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-secret-reference/v1",
            &[
                ("opaque_handle", self.opaque_handle.clone()),
                ("revision", self.revision.to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(FreshserviceIncidentResultError::RegistrationAlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        if !self.revoked {
            return Err(FreshserviceIncidentResultError::RegistrationNotRevoked);
        }
        self.revoked = false;
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(S::Error::custom(
            "SecretReference is opaque and non-serializing",
        ))
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.opaque_handle.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
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
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Pending,
    Resolved,
    Closed,
    OnHold,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentPriority {
    Low,
    Medium,
    High,
    Urgent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStatus {
    Planned,
    Open,
    Implement,
    Completed,
    Failed,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRisk {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetLifecycle {
    Active,
    InStock,
    Retired,
    Disposed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentMetadata {
    pub agent_digest: Option<Digest>,
    pub group_digest: Option<Digest>,
}

impl AssignmentMetadata {
    pub fn from_scope(scope: &FreshserviceIncidentResultScope) -> Self {
        Self {
            agent_digest: Some(scope.agent().digest()),
            group_digest: Some(scope.group().digest()),
        }
    }

    pub fn new(agent: Option<&FreshserviceAgentId>, group: Option<&FreshserviceGroupId>) -> Self {
        Self {
            agent_digest: agent.map(FreshserviceAgentId::digest),
            group_digest: group.map(FreshserviceGroupId::digest),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.agent_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.group_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentMetadata {
    pub id_digest: Digest,
    pub status: IncidentStatus,
    pub priority: IncidentPriority,
    pub assignment: AssignmentMetadata,
    pub updated_at: DateTime<Utc>,
    pub revision: u64,
}

impl IncidentMetadata {
    pub fn new(
        scope: &FreshserviceIncidentResultScope,
        status: IncidentStatus,
        priority: IncidentPriority,
        updated_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self> {
        Self::for_incident(
            scope.incident(),
            status,
            priority,
            AssignmentMetadata::from_scope(scope),
            updated_at,
            revision,
        )
    }

    pub fn for_incident(
        id: &FreshserviceIncidentId,
        status: IncidentStatus,
        priority: IncidentPriority,
        assignment: AssignmentMetadata,
        updated_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self> {
        if revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRevision { field: "incident" });
        }
        assignment.validate()?;
        Ok(Self {
            id_digest: id.digest(),
            status,
            priority,
            assignment,
            updated_at,
            revision,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.assignment.validate()?;
        if self.revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRevision { field: "incident" });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeWindowMetadata {
    pub planned_start: Option<DateTime<Utc>>,
    pub planned_end: Option<DateTime<Utc>>,
    pub actual_start: Option<DateTime<Utc>>,
    pub actual_end: Option<DateTime<Utc>>,
}

impl ChangeWindowMetadata {
    pub fn new(
        planned_start: Option<DateTime<Utc>>,
        planned_end: Option<DateTime<Utc>>,
        actual_start: Option<DateTime<Utc>>,
        actual_end: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        if planned_start
            .zip(planned_end)
            .is_some_and(|(start, end)| start > end)
            || actual_start
                .zip(actual_end)
                .is_some_and(|(start, end)| start > end)
        {
            return Err(FreshserviceIncidentResultError::InvalidRequest);
        }
        Ok(Self {
            planned_start,
            planned_end,
            actual_start,
            actual_end,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(
            self.planned_start,
            self.planned_end,
            self.actual_start,
            self.actual_end,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMetadata {
    pub id_digest: Digest,
    pub status: ChangeStatus,
    pub risk: ChangeRisk,
    pub assignment: AssignmentMetadata,
    pub window: ChangeWindowMetadata,
    pub updated_at: DateTime<Utc>,
    pub revision: u64,
}

impl ChangeMetadata {
    pub fn new(
        scope: &FreshserviceIncidentResultScope,
        status: ChangeStatus,
        risk: ChangeRisk,
        window: ChangeWindowMetadata,
        updated_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self> {
        Self::for_change(
            scope.change(),
            status,
            risk,
            AssignmentMetadata::from_scope(scope),
            window,
            updated_at,
            revision,
        )
    }

    pub fn for_change(
        id: &FreshserviceChangeId,
        status: ChangeStatus,
        risk: ChangeRisk,
        assignment: AssignmentMetadata,
        window: ChangeWindowMetadata,
        updated_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self> {
        if revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRevision { field: "change" });
        }
        assignment.validate()?;
        window.validate()?;
        Ok(Self {
            id_digest: id.digest(),
            status,
            risk,
            assignment,
            window,
            updated_at,
            revision,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.assignment.validate()?;
        self.window.validate()?;
        if self.revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRevision { field: "change" });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetMetadata {
    pub id_digest: Digest,
    pub lifecycle: AssetLifecycle,
    pub asset_type_digest: Option<Digest>,
    pub assignment: AssignmentMetadata,
    pub updated_at: DateTime<Utc>,
    pub revision: u64,
}

impl AssetMetadata {
    pub fn new(
        scope: &FreshserviceIncidentResultScope,
        lifecycle: AssetLifecycle,
        asset_type: Option<impl AsRef<str>>,
        updated_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self> {
        let asset_type_digest = asset_type
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_parts(
                        "freshservice-asset-type/v1",
                        &[("value", value)],
                    ))
                } else {
                    Err(FreshserviceIncidentResultError::InvalidIdentifier {
                        field: "asset-type",
                    })
                }
            })
            .transpose()?;
        Self::for_asset(
            scope.asset(),
            lifecycle,
            asset_type_digest,
            AssignmentMetadata::from_scope(scope),
            updated_at,
            revision,
        )
    }

    pub fn for_asset(
        id: &FreshserviceAssetId,
        lifecycle: AssetLifecycle,
        asset_type_digest: Option<Digest>,
        assignment: AssignmentMetadata,
        updated_at: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self> {
        if revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRevision { field: "asset" });
        }
        assignment.validate()?;
        asset_type_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        Ok(Self {
            id_digest: id.digest(),
            lifecycle,
            asset_type_digest,
            assignment,
            updated_at,
            revision,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id_digest.validate()?;
        self.asset_type_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.assignment.validate()?;
        if self.revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRevision { field: "asset" });
        }
        Ok(())
    }
}
