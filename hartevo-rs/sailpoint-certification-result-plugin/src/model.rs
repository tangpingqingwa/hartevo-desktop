//! Typed SailPoint certification scope, redacted evidence, and lifecycle
//! models. Provider payloads are reduced to immutable identifiers, typed
//! states, counts, privileged flags, timestamps, and cryptographic receipts.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    SAILPOINT_CONTRACT_VERSION, SAILPOINT_MAX_IDENTIFIER_BYTES, SAILPOINT_MAX_LIMIT,
    SAILPOINT_MAX_OFFSET, SAILPOINT_MAX_RESPONSE_BYTES, SAILPOINT_PLUGIN_VERSION_TEXT,
    SAILPOINT_PROVIDER_ID, SAILPOINT_PROVIDER_IMPLEMENTATION, SAILPOINT_PROVIDER_REVISION_TEXT,
};

pub const MAX_SECRET_REFERENCE_BYTES: usize = 4_096;
pub const MAX_RECORDS: usize = 256;

/// Errors raised while constructing or validating typed Layer-1 values.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SailPointModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("the SailPoint API base is not the exact HTTPS tenant origin")]
    InvalidApiBase,
    #[error("the SailPoint access type is not ROLE, ACCESS_PROFILE, or ENTITLEMENT")]
    InvalidAccessType,
    #[error("the SailPoint campaign or decision state is not recognized")]
    InvalidState,
    #[error("the SailPoint response is not a bounded allowlisted shape: {0}")]
    InvalidResponse(String),
    #[error("the bounded {field} list exceeded its maximum")]
    TooMany { field: &'static str },
    #[error("the SailPoint endpoint is incompatible with the registered scope")]
    ScopeMismatch,
    #[error("the response contains duplicate immutable identifiers")]
    DuplicateIdentifier,
    #[error("the response campaign revision is stale")]
    StaleCampaignRevision,
    #[error("the response entitlement revision is stale")]
    StaleEntitlementRevision,
    #[error("the registration is already revoked")]
    AlreadyRevoked,
    #[error("the canonical SailPoint value could not be serialized: {0}")]
    Serialization(String),
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), SailPointModelError> {
    if value.is_empty() {
        return Err(SailPointModelError::Empty { field });
    }
    if value.len() > max {
        return Err(SailPointModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(SailPointModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(SailPointModelError::InvalidCharacters { field });
    }
    if value.chars().any(|character| {
        !(character.is_ascii_alphanumeric()
            || "-_.:/@".contains(character)
            || allow_internal_whitespace && character.is_whitespace())
    }) {
        return Err(SailPointModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), SailPointModelError> {
    if value == 0 {
        Err(SailPointModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, SailPointModelError> {
                let value = value.into();
                validate_text(&value, $field, SAILPOINT_MAX_IDENTIFIER_BYTES, false)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = SailPointModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_identifier!(TenantId, "tenant id");
bounded_identifier!(CertificationId, "certification id");
bounded_identifier!(CampaignId, "campaign id");
bounded_identifier!(ReviewerId, "reviewer id");
bounded_identifier!(IdentityId, "identity id");
bounded_identifier!(EntitlementId, "entitlement id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(ConsentId, "Consent id");
bounded_identifier!(ProviderRevision, "provider revision");

/// Lowercase SHA-256 digest used for all cross-boundary bindings.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hasher = Sha256::new();
        for field in fields {
            let value = field.as_ref();
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
        Self(hex_encode(hasher.finalize().as_slice()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, SailPointModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(SailPointModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, SailPointModelError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| SailPointModelError::Serialization(error.to_string()))?;
    Ok(sha256_digest(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretKind {
    #[serde(rename = "PAT")]
    Pat,
    #[serde(rename = "OAUTH")]
    OAuth,
}

/// Opaque reference to host-owned PAT/OAuth material.
///
/// The constructor hashes and discards the supplied reference string. No
/// token, secret path, or credential material is retained by this crate.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revoked: bool,
}

impl SecretReference {
    /// Construct the default PAT-shaped opaque reference.
    pub fn new(reference: impl AsRef<str>) -> Result<Self, SailPointModelError> {
        Self::pat(reference)
    }

    pub fn pat(reference: impl AsRef<str>) -> Result<Self, SailPointModelError> {
        Self::with_kind(SecretKind::Pat, reference)
    }

    pub fn oauth(reference: impl AsRef<str>) -> Result<Self, SailPointModelError> {
        Self::with_kind(SecretKind::OAuth, reference)
    }

    pub fn with_kind(
        kind: SecretKind,
        reference: impl AsRef<str>,
    ) -> Result<Self, SailPointModelError> {
        let reference = reference.as_ref();
        if reference.is_empty() {
            return Err(SailPointModelError::Empty {
                field: "secret reference",
            });
        }
        if reference.len() > MAX_SECRET_REFERENCE_BYTES {
            return Err(SailPointModelError::TooLong {
                field: "secret reference",
            });
        }
        if reference.chars().any(char::is_control) {
            return Err(SailPointModelError::ControlCharacter {
                field: "secret reference",
            });
        }
        Ok(Self {
            kind,
            reference_digest: Digest::from_text(reference),
            revoked: false,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            SecretKind::Pat => "PAT",
            SecretKind::OAuth => "OAUTH",
        }
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), SailPointModelError> {
        if self.revoked {
            return Err(SailPointModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 4)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("opaque", &true)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("opaque", &true)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessType {
    Role,
    AccessProfile,
    Entitlement,
}

impl AccessType {
    pub const ALL: [Self; 3] = [Self::Role, Self::AccessProfile, Self::Entitlement];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Role => "ROLE",
            Self::AccessProfile => "ACCESS_PROFILE",
            Self::Entitlement => "ENTITLEMENT",
        }
    }

    pub fn parse(value: &str) -> Result<Self, SailPointModelError> {
        match value.to_ascii_uppercase().as_str() {
            "ROLE" => Ok(Self::Role),
            "ACCESS_PROFILE" | "ACCESSPROFILE" => Ok(Self::AccessProfile),
            "ENTITLEMENT" => Ok(Self::Entitlement),
            _ => Err(SailPointModelError::InvalidAccessType),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignState {
    Active,
    Completed,
    Remediation,
    Expired,
    Unknown,
}

impl CampaignState {
    pub const fn is_fail_closed(self) -> bool {
        matches!(self, Self::Expired | Self::Unknown)
    }

    pub fn from_wire(
        raw: Option<&str>,
        completed: bool,
        remediation_required: bool,
        due_at: Option<DateTime<Utc>>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let normalized = raw.map(str::to_ascii_uppercase);
        if matches!(normalized.as_deref(), Some("UNKNOWN" | "UNAVAILABLE")) {
            return Self::Unknown;
        }
        if matches!(normalized.as_deref(), Some("EXPIRED"))
            || (!completed && due_at.is_some_and(|due| due < observed_at))
        {
            return Self::Expired;
        }
        if remediation_required
            || matches!(
                normalized.as_deref(),
                Some("REMEDIATION" | "REMEDIATION_REQUIRED")
            )
        {
            return Self::Remediation;
        }
        if completed || matches!(normalized.as_deref(), Some("COMPLETED" | "CLOSED")) {
            return Self::Completed;
        }
        if raw.is_none()
            || matches!(
                normalized.as_deref(),
                Some("ACTIVE" | "OPEN" | "IN_PROGRESS")
            )
        {
            return Self::Active;
        }
        Self::Unknown
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    Approved,
    Revoked,
    Pending,
    Partial,
}

impl DecisionState {
    pub const fn is_fail_closed(self) -> bool {
        matches!(self, Self::Pending | Self::Partial)
    }

    pub fn from_wire(raw: Option<&str>, completed: bool) -> Self {
        match raw.map(str::to_ascii_uppercase).as_deref() {
            Some("APPROVED" | "ALLOW" | "CERTIFIED") => Self::Approved,
            Some("REVOKED" | "REJECTED" | "DENIED") => Self::Revoked,
            Some("PENDING" | "OPEN" | "IN_PROGRESS") => Self::Pending,
            Some("PARTIAL" | "MIXED") => Self::Partial,
            Some(_) => Self::Partial,
            None if !completed => Self::Pending,
            None => Self::Partial,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

impl RegistrationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// Allowlisted read permissions for the three official V3 GET seams.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SailPointPermission {
    CertificationRead,
    CampaignRead,
    AccessSummaryRead,
}

impl SailPointPermission {
    pub const ALL: [Self; 3] = [
        Self::CertificationRead,
        Self::CampaignRead,
        Self::AccessSummaryRead,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CertificationRead => "certification_read",
            Self::CampaignRead => "campaign_read",
            Self::AccessSummaryRead => "access_summary_read",
        }
    }

    fn parse(value: &str) -> Result<Self, SailPointModelError> {
        match value {
            "certification_read" => Ok(Self::CertificationRead),
            "campaign_read" => Ok(Self::CampaignRead),
            "access_summary_read" => Ok(Self::AccessSummaryRead),
            _ => Err(SailPointModelError::Invalid {
                field: "permission",
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<SailPointPermission>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only() -> Self {
        Self::from_permissions(SailPointPermission::ALL)
    }

    pub fn from_permissions<I>(permissions: I) -> Self
    where
        I: IntoIterator<Item = SailPointPermission>,
    {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let fields = permissions.iter().map(|permission| permission.as_str());
        let digest = Digest::from_fields(fields);
        Self {
            permissions,
            digest,
        }
    }

    pub fn from_names<I, S>(permissions: I) -> Result<Self, SailPointModelError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let permissions = permissions
            .into_iter()
            .map(|permission| SailPointPermission::parse(permission.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_permissions(permissions))
    }

    pub fn permissions(&self) -> &BTreeSet<SailPointPermission> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn allows(&self, permission: SailPointPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn is_exact_read_only(&self) -> bool {
        self.permissions == SailPointPermission::ALL.into_iter().collect()
    }
}

/// The exact tenant/API origin pair bound to a registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointApiBase {
    tenant: TenantId,
    origin: String,
}

impl SailPointApiBase {
    pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, SailPointModelError> {
        let value = value.into();
        let expected_origin = format!("https://{}.api.identitynow.com", tenant.as_str());
        let canonical_origin = value.strip_suffix("/v3").unwrap_or(&value);
        if canonical_origin != expected_origin
            || value.contains('?')
            || value.contains('#')
            || value.ends_with('/')
        {
            return Err(SailPointModelError::InvalidApiBase);
        }
        Ok(Self {
            tenant,
            origin: expected_origin,
        })
    }

    pub fn for_tenant(tenant: TenantId) -> Self {
        let origin = format!("https://{}.api.identitynow.com", tenant.as_str());
        Self { tenant, origin }
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn v3_base(&self) -> String {
        format!("{}/v3", self.origin)
    }
}

#[derive(Clone, Debug)]
pub struct SailPointCertificationScopeInput {
    pub tenant: String,
    pub api_base: String,
    pub certification_id: String,
    pub campaign_id: String,
    pub access_type: AccessType,
    pub reviewer_id: String,
    pub identity_id: String,
    pub entitlement_id: Option<String>,
    pub campaign_revision: u64,
    pub entitlement_revision: Option<u64>,
    pub mission_id: String,
    pub mission_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub consent_id: String,
    pub consent_revision: u64,
    pub permission_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointCertificationScope {
    tenant: TenantId,
    api_base: SailPointApiBase,
    certification_id: CertificationId,
    campaign_id: CampaignId,
    access_type: AccessType,
    reviewer_id: ReviewerId,
    identity_id: IdentityId,
    entitlement_id: Option<EntitlementId>,
    campaign_revision: Revision,
    entitlement_revision: Option<Revision>,
    mission_id: MissionId,
    mission_revision: Revision,
    project_id: ProjectId,
    project_revision: Revision,
    consent_id: ConsentId,
    consent_revision: Revision,
    permission_digest: Digest,
    scope_digest: Digest,
}

impl SailPointCertificationScope {
    pub fn new(input: SailPointCertificationScopeInput) -> Result<Self, SailPointModelError> {
        let tenant = TenantId::new(input.tenant)?;
        let api_base = SailPointApiBase::new(tenant.clone(), input.api_base)?;
        let certification_id = CertificationId::new(input.certification_id)?;
        let campaign_id = CampaignId::new(input.campaign_id)?;
        let reviewer_id = ReviewerId::new(input.reviewer_id)?;
        let identity_id = IdentityId::new(input.identity_id)?;
        let entitlement_id = input.entitlement_id.map(EntitlementId::new).transpose()?;
        let campaign_revision = Revision::new(input.campaign_revision)?;
        let entitlement_revision = input.entitlement_revision.map(Revision::new).transpose()?;
        let mission_id = MissionId::new(input.mission_id)?;
        let mission_revision = Revision::new(input.mission_revision)?;
        let project_id = ProjectId::new(input.project_id)?;
        let project_revision = Revision::new(input.project_revision)?;
        let consent_id = ConsentId::new(input.consent_id)?;
        let consent_revision = Revision::new(input.consent_revision)?;
        Digest::parse(input.permission_digest.as_str().to_owned())?;
        if matches!(input.access_type, AccessType::Entitlement) != entitlement_id.is_some() {
            return Err(SailPointModelError::ScopeMismatch);
        }
        if entitlement_id.is_some() && entitlement_revision.is_none() {
            return Err(SailPointModelError::ScopeMismatch);
        }
        let mut scope = Self {
            tenant,
            api_base,
            certification_id,
            campaign_id,
            access_type: input.access_type,
            reviewer_id,
            identity_id,
            entitlement_id,
            campaign_revision,
            entitlement_revision,
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            consent_id,
            consent_revision,
            permission_digest: input.permission_digest,
            scope_digest: Digest::zero(),
        };
        scope.scope_digest = scope.recompute_scope_digest();
        Ok(scope)
    }

    fn recompute_scope_digest(&self) -> Digest {
        let api_base = self.api_base.v3_base();
        let campaign_revision = self.campaign_revision.get().to_string();
        let entitlement_revision = self
            .entitlement_revision
            .map_or(0, Revision::get)
            .to_string();
        let mission_revision = self.mission_revision.get().to_string();
        let project_revision = self.project_revision.get().to_string();
        let consent_revision = self.consent_revision.get().to_string();
        Digest::from_fields([
            self.tenant.as_str(),
            api_base.as_str(),
            self.certification_id.as_str(),
            self.campaign_id.as_str(),
            self.access_type.as_str(),
            self.reviewer_id.as_str(),
            self.identity_id.as_str(),
            self.entitlement_id
                .as_ref()
                .map_or("", EntitlementId::as_str),
            campaign_revision.as_str(),
            entitlement_revision.as_str(),
            self.mission_id.as_str(),
            mission_revision.as_str(),
            self.project_id.as_str(),
            project_revision.as_str(),
            self.consent_id.as_str(),
            consent_revision.as_str(),
            self.permission_digest.as_str(),
        ])
    }

    pub fn validate(&self) -> Result<(), SailPointModelError> {
        if self.scope_digest != self.recompute_scope_digest() {
            return Err(SailPointModelError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn api_base(&self) -> &SailPointApiBase {
        &self.api_base
    }

    pub fn certification_id(&self) -> &CertificationId {
        &self.certification_id
    }

    pub fn campaign_id(&self) -> &CampaignId {
        &self.campaign_id
    }

    pub const fn access_type(&self) -> AccessType {
        self.access_type
    }

    pub fn reviewer_id(&self) -> &ReviewerId {
        &self.reviewer_id
    }

    pub fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }

    pub fn entitlement_id(&self) -> Option<&EntitlementId> {
        self.entitlement_id.as_ref()
    }

    pub const fn campaign_revision(&self) -> Revision {
        self.campaign_revision
    }

    pub const fn entitlement_revision(&self) -> Option<Revision> {
        self.entitlement_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn consent_id(&self) -> &ConsentId {
        &self.consent_id
    }

    pub const fn consent_revision(&self) -> Revision {
        self.consent_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, SailPointModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CampaignSnapshot {
    pub id: CampaignId,
    pub revision: Revision,
    pub state: CampaignState,
    pub identities_completed: u32,
    pub identities_total: u32,
    pub decision_counts: DecisionCounts,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub due_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CertificationRecord {
    pub id: CertificationId,
    pub campaign: CampaignSnapshot,
    pub reviewer_id: ReviewerId,
    pub identity_id: IdentityId,
    pub decision_state: DecisionState,
    pub decision_counts: DecisionCounts,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub due_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DecisionCounts {
    pub approved: u32,
    pub revoked: u32,
    pub pending: u32,
    pub partial: u32,
    pub total: u32,
}

impl DecisionCounts {
    pub fn decision_state(&self) -> DecisionState {
        if self.partial > 0 {
            DecisionState::Partial
        } else if self.pending > 0 {
            if self.approved == 0 && self.revoked == 0 {
                DecisionState::Pending
            } else {
                DecisionState::Partial
            }
        } else if self.approved > 0 && self.revoked == 0 {
            DecisionState::Approved
        } else if self.revoked > 0 && self.approved == 0 {
            DecisionState::Revoked
        } else if self.approved > 0 && self.revoked > 0 {
            DecisionState::Partial
        } else {
            DecisionState::Pending
        }
    }

    pub fn add_decision(&mut self, state: DecisionState) {
        match state {
            DecisionState::Approved => self.approved = self.approved.saturating_add(1),
            DecisionState::Revoked => self.revoked = self.revoked.saturating_add(1),
            DecisionState::Pending => self.pending = self.pending.saturating_add(1),
            DecisionState::Partial => self.partial = self.partial.saturating_add(1),
        }
        self.total = self.total.saturating_add(1);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AccessSummary {
    pub id: EntitlementId,
    pub access_type: AccessType,
    pub reviewer_id: ReviewerId,
    pub identity_id: IdentityId,
    pub entitlement_id: Option<EntitlementId>,
    pub campaign_revision: Revision,
    pub entitlement_revision: Option<Revision>,
    pub decision_state: DecisionState,
    pub privileged: bool,
    pub decision_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum SailPointResponseBody {
    Certification(CertificationRecord),
    Campaigns(Vec<CertificationRecord>),
    AccessSummaries(Vec<AccessSummary>),
}

impl SailPointResponseBody {
    pub fn certification(record: CertificationRecord) -> Self {
        Self::Certification(record)
    }

    pub fn campaigns(records: Vec<CertificationRecord>) -> Result<Self, SailPointModelError> {
        let body = Self::Campaigns(records);
        body.normalized()
    }

    pub fn access_summaries(records: Vec<AccessSummary>) -> Result<Self, SailPointModelError> {
        let body = Self::AccessSummaries(records);
        body.normalized()
    }

    pub fn normalized(&self) -> Result<Self, SailPointModelError> {
        match self {
            Self::Certification(record) => Ok(Self::Certification(record.clone())),
            Self::Campaigns(records) => {
                if records.len() > MAX_RECORDS {
                    return Err(SailPointModelError::TooMany { field: "campaigns" });
                }
                let mut sorted = records.clone();
                sorted.sort_by(|left, right| {
                    left.id
                        .cmp(&right.id)
                        .then_with(|| left.reviewer_id.cmp(&right.reviewer_id))
                        .then_with(|| left.identity_id.cmp(&right.identity_id))
                });
                if sorted.windows(2).any(|window| window[0].id == window[1].id) {
                    return Err(SailPointModelError::DuplicateIdentifier);
                }
                Ok(Self::Campaigns(sorted))
            }
            Self::AccessSummaries(records) => {
                if records.len() > MAX_RECORDS {
                    return Err(SailPointModelError::TooMany {
                        field: "access summaries",
                    });
                }
                let mut sorted = records.clone();
                sorted.sort_by(|left, right| {
                    left.access_type
                        .as_str()
                        .cmp(right.access_type.as_str())
                        .then_with(|| left.id.cmp(&right.id))
                        .then_with(|| left.identity_id.cmp(&right.identity_id))
                });
                if sorted.windows(2).any(|window| {
                    window[0].id == window[1].id
                        && window[0].access_type == window[1].access_type
                        && window[0].identity_id == window[1].identity_id
                }) {
                    return Err(SailPointModelError::DuplicateIdentifier);
                }
                Ok(Self::AccessSummaries(sorted))
            }
        }
    }

    pub fn endpoint_matches(&self, endpoint: &SailPointEndpoint) -> bool {
        matches!(
            (self, endpoint),
            (
                Self::Certification(_),
                SailPointEndpoint::Certification { .. }
            ) | (Self::Campaigns(_), SailPointEndpoint::Campaigns)
                | (
                    Self::AccessSummaries(_),
                    SailPointEndpoint::AccessSummaries { .. }
                )
        )
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Certification(_) => 1,
            Self::Campaigns(records) => records.len(),
            Self::AccessSummaries(records) => records.len(),
        }
    }

    pub const fn is_empty(&self) -> bool {
        match self {
            Self::Certification(_) => false,
            Self::Campaigns(records) => records.is_empty(),
            Self::AccessSummaries(records) => records.is_empty(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum SailPointEndpoint {
    Certification {
        certification_id: CertificationId,
    },
    Campaigns,
    AccessSummaries {
        certification_id: CertificationId,
        access_type: AccessType,
    },
}

impl SailPointEndpoint {
    pub const fn operation_name(&self) -> &'static str {
        match self {
            Self::Certification { .. } => "get_identity_certification",
            Self::Campaigns => "get_identity_certifications",
            Self::AccessSummaries { .. } => "get_identity_access_summaries",
        }
    }

    pub const fn method(&self) -> &'static str {
        "GET"
    }

    pub fn path_and_query(&self, limit: u32, offset: u32) -> String {
        match self {
            Self::Certification { certification_id } => {
                format!("/v3/certifications/{}", certification_id.as_str())
            }
            Self::Campaigns => {
                format!("/v3/certifications?limit={limit}&offset={offset}&count=false&sorters=name")
            }
            Self::AccessSummaries {
                certification_id,
                access_type,
            } => format!(
                "/v3/certifications/{}/access-summaries/{}?limit={limit}&offset={offset}&count=false&sorters=access.name",
                certification_id.as_str(),
                access_type.as_str()
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointReadRequest {
    pub endpoint: SailPointEndpoint,
    pub tenant: TenantId,
    pub api_base: SailPointApiBase,
    pub limit: u32,
    pub offset: u32,
    pub expected_campaign_revision: Revision,
    pub expected_entitlement_revision: Option<Revision>,
    pub scope_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl SailPointReadRequest {
    pub fn new(
        endpoint: SailPointEndpoint,
        scope: &SailPointCertificationScope,
        limit: u32,
        offset: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, SailPointModelError> {
        scope.validate()?;
        if limit == 0 || limit > SAILPOINT_MAX_LIMIT || offset > SAILPOINT_MAX_OFFSET {
            return Err(SailPointModelError::Invalid {
                field: "pagination",
            });
        }
        match &endpoint {
            SailPointEndpoint::Certification { certification_id }
            | SailPointEndpoint::AccessSummaries {
                certification_id, ..
            } if certification_id != scope.certification_id() => {
                return Err(SailPointModelError::ScopeMismatch);
            }
            SailPointEndpoint::AccessSummaries { access_type, .. }
                if *access_type != scope.access_type() =>
            {
                return Err(SailPointModelError::ScopeMismatch);
            }
            _ => {}
        }
        let path_and_query = endpoint.path_and_query(limit, offset);
        let api_base = scope.api_base().v3_base();
        let campaign_revision = scope.campaign_revision().get().to_string();
        let entitlement_revision = scope
            .entitlement_revision()
            .map_or(0, Revision::get)
            .to_string();
        let request_digest = Digest::from_fields([
            endpoint.operation_name(),
            endpoint.method(),
            scope.tenant().as_str(),
            api_base.as_str(),
            path_and_query.as_str(),
            &limit.to_string(),
            &offset.to_string(),
            campaign_revision.as_str(),
            entitlement_revision.as_str(),
            scope.scope_digest().as_str(),
            &observed_at.to_rfc3339(),
        ]);
        Ok(Self {
            endpoint,
            tenant: scope.tenant().clone(),
            api_base: scope.api_base().clone(),
            limit,
            offset,
            expected_campaign_revision: scope.campaign_revision(),
            expected_entitlement_revision: scope.entitlement_revision(),
            scope_digest: scope.scope_digest().clone(),
            observed_at,
            request_digest,
        })
    }

    pub fn http_request(&self) -> SailPointHttpRequest {
        SailPointHttpRequest::from_read(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointHttpRequest {
    pub method: String,
    pub origin: String,
    pub path_and_query: String,
    pub endpoint: SailPointEndpoint,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub limit: u32,
    pub offset: u32,
    pub expected_campaign_revision: Revision,
    pub expected_entitlement_revision: Option<Revision>,
    pub observed_at: DateTime<Utc>,
}

impl SailPointHttpRequest {
    pub fn from_read(request: &SailPointReadRequest) -> Self {
        Self {
            method: request.endpoint.method().to_owned(),
            origin: request.api_base.origin().to_owned(),
            path_and_query: request
                .endpoint
                .path_and_query(request.limit, request.offset),
            endpoint: request.endpoint.clone(),
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            limit: request.limit,
            offset: request.offset,
            expected_campaign_revision: request.expected_campaign_revision,
            expected_entitlement_revision: request.expected_entitlement_revision,
            observed_at: request.observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointRequestReceipt {
    pub operation: String,
    pub method: String,
    pub origin_digest: Digest,
    pub path_digest: Digest,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub limit: u32,
    pub offset: u32,
}

impl SailPointRequestReceipt {
    pub fn from_request(request: &SailPointHttpRequest) -> Self {
        Self {
            operation: request.endpoint.operation_name().to_owned(),
            method: request.method.clone(),
            origin_digest: Digest::from_text(&request.origin),
            path_digest: Digest::from_text(&request.path_and_query),
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            limit: request.limit,
            offset: request.offset,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointResponseReceipt {
    pub status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub request_digest: Digest,
    pub total_count: Option<u32>,
}

impl SailPointResponseReceipt {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointHttpResponse {
    pub endpoint: SailPointEndpoint,
    pub body: SailPointResponseBody,
    pub receipt: SailPointResponseReceipt,
}

impl SailPointHttpResponse {
    pub fn from_body(
        request: &SailPointHttpRequest,
        body: SailPointResponseBody,
        provider_revision: ProviderRevision,
        total_count: Option<u32>,
    ) -> Result<Self, SailPointModelError> {
        if !body.endpoint_matches(&request.endpoint) {
            return Err(SailPointModelError::ScopeMismatch);
        }
        let body = body.normalized()?;
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| SailPointModelError::Serialization(error.to_string()))?;
        if bytes.len() > SAILPOINT_MAX_RESPONSE_BYTES {
            return Err(SailPointModelError::TooLong {
                field: "response body",
            });
        }
        Ok(Self {
            endpoint: request.endpoint.clone(),
            body,
            receipt: SailPointResponseReceipt {
                status: 200,
                response_bytes: bytes.len(),
                response_digest: sha256_digest(&bytes),
                provider_revision,
                request_digest: request.request_digest.clone(),
                total_count,
            },
        })
    }

    pub fn body(&self) -> &SailPointResponseBody {
        &self.body
    }

    pub fn receipt(&self) -> &SailPointResponseReceipt {
        &self.receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointReadEvidence {
    pub endpoint: SailPointEndpoint,
    pub body: SailPointResponseBody,
    pub request_receipt: SailPointRequestReceipt,
    pub response_receipt: SailPointResponseReceipt,
    pub provenance: TransportProvenance,
    pub source_digest: Digest,
    pub evidence_digest: Digest,
    pub partial: bool,
}

impl SailPointReadEvidence {
    pub fn new(
        request: &SailPointHttpRequest,
        response: SailPointHttpResponse,
        provenance: TransportProvenance,
    ) -> Result<Self, SailPointModelError> {
        let request_receipt = SailPointRequestReceipt::from_request(request);
        let body = response.body.normalized()?;
        let source_digest = Digest::from_fields([
            request_receipt.digest().as_str(),
            response.receipt.response_digest.as_str(),
            response.receipt.provider_revision.as_str(),
        ]);
        let evidence_digest = digest_serializable(&(
            &response.endpoint,
            &body,
            &request_receipt,
            &response.receipt,
            provenance,
        ))?;
        let partial = response
            .receipt
            .total_count
            .is_some_and(|total| total > request.offset.saturating_add(body.len() as u32));
        Ok(Self {
            endpoint: response.endpoint,
            body,
            request_receipt,
            response_receipt: response.receipt,
            provenance,
            source_digest,
            evidence_digest,
            partial,
        })
    }

    pub fn recompute_digest(&self) -> Result<Digest, SailPointModelError> {
        digest_serializable(&(
            &self.endpoint,
            &self.body,
            &self.request_receipt,
            &self.response_receipt,
            self.provenance,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointRegistration {
    pub state: RegistrationState,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_implementation: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
}

impl SailPointRegistration {
    pub fn new(
        scope: &SailPointCertificationScope,
        contract_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
        evidence_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            state: RegistrationState::Active,
            plugin_version: SAILPOINT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: SAILPOINT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: SAILPOINT_PROVIDER_ID.to_owned(),
            provider_implementation: SAILPOINT_PROVIDER_IMPLEMENTATION.to_owned(),
            provider_version: SAILPOINT_PLUGIN_VERSION_TEXT.to_owned(),
            provider_revision: ProviderRevision::new(SAILPOINT_PROVIDER_REVISION_TEXT)
                .expect("static provider revision is valid"),
            provider_digest,
            permission_digest,
            scope_digest: scope.scope_digest().clone(),
            evidence_digest,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recompute_digest();
        registration
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn revoke(&mut self) -> Result<(), SailPointModelError> {
        if !self.is_active() {
            return Err(SailPointModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recompute_digest();
        Ok(())
    }

    pub fn recompute_digest(&self) -> Digest {
        Digest::from_fields([
            self.state.as_str(),
            &self.plugin_version,
            &self.contract_version,
            self.contract_digest.as_str(),
            &self.provider_id,
            &self.provider_implementation,
            &self.provider_version,
            self.provider_revision.as_str(),
            self.provider_digest.as_str(),
            self.permission_digest.as_str(),
            self.scope_digest.as_str(),
            self.evidence_digest.as_str(),
        ])
    }

    pub fn validate(&self, scope: &SailPointCertificationScope) -> Result<(), SailPointModelError> {
        scope.validate()?;
        if self.scope_digest != *scope.scope_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.registration_digest != self.recompute_digest()
            || self.plugin_version != SAILPOINT_PLUGIN_VERSION_TEXT
            || self.contract_version != SAILPOINT_CONTRACT_VERSION
            || self.provider_id != SAILPOINT_PROVIDER_ID
            || self.provider_implementation != SAILPOINT_PROVIDER_IMPLEMENTATION
            || self.provider_revision.as_str() != SAILPOINT_PROVIDER_REVISION_TEXT
            || self.provider_version != SAILPOINT_PLUGIN_VERSION_TEXT
        {
            return Err(SailPointModelError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointCertificationEvidence {
    pub certification: Option<CertificationRecord>,
    pub campaign_records: Vec<CertificationRecord>,
    pub access_summaries: Vec<AccessSummary>,
    pub read_receipts: Vec<SailPointResponseReceipt>,
    pub provider_revision: ProviderRevision,
    pub source_digest: Digest,
    pub evidence_digest: Digest,
    pub raw_identity_payload_retained: bool,
    pub raw_access_payload_retained: bool,
    pub reviewer_pii_retained: bool,
    pub identity_pii_retained: bool,
    pub entitlement_descriptions_retained: bool,
    pub reviewer_comments_retained: bool,
}

impl SailPointCertificationEvidence {
    pub fn recompute_digest(&self) -> Result<Digest, SailPointModelError> {
        digest_serializable(&(
            &self.certification,
            &self.campaign_records,
            &self.access_summaries,
            &self.read_receipts,
            &self.provider_revision,
            &self.source_digest,
            self.raw_identity_payload_retained,
            self.raw_access_payload_retained,
            self.reviewer_pii_retained,
            self.identity_pii_retained,
            self.entitlement_descriptions_retained,
            self.reviewer_comments_retained,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointCertificationProjection {
    pub campaign_state: CampaignState,
    pub decision_state: DecisionState,
    pub partial: bool,
    pub access_lost: bool,
    pub provider_unknown: bool,
    pub stale_revision: bool,
    pub duplicate_detected: bool,
    pub access_safety_claim: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointEvidenceProposal {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub campaign_revision: Revision,
    pub evidence: SailPointCertificationEvidence,
    pub projection: SailPointCertificationProjection,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub certification_approved: bool,
    pub certification_revoked: bool,
    pub certification_finalized: bool,
    pub access_request_submitted: bool,
    pub identity_mutated: bool,
    pub entitlement_mutated: bool,
    pub adopted_by_kernel: bool,
    pub proposal_digest: Digest,
}

impl SailPointEvidenceProposal {
    pub fn recompute_digest(&self) -> Result<Digest, SailPointModelError> {
        let evidence_digest = self.evidence.recompute_digest()?;
        let projection_digest = digest_serializable(&self.projection)?;
        Ok(Digest::from_fields([
            self.scope_digest.as_str(),
            self.registration_digest.as_str(),
            &self.campaign_revision.get().to_string(),
            evidence_digest.as_str(),
            projection_digest.as_str(),
            if self.read_only {
                "read_only"
            } else {
                "not_read_only"
            },
            if self.proposal_only {
                "proposal_only"
            } else {
                "not_proposal_only"
            },
            if self.native { "native" } else { "not_native" },
            if self.connected {
                "connected"
            } else {
                "not_connected"
            },
            if self.first_party {
                "first_party"
            } else {
                "not_first_party"
            },
            if self.certification_approved {
                "certification_approved"
            } else {
                "not_certification_approved"
            },
            if self.certification_revoked {
                "certification_revoked"
            } else {
                "not_certification_revoked"
            },
            if self.certification_finalized {
                "certification_finalized"
            } else {
                "not_certification_finalized"
            },
            if self.access_request_submitted {
                "access_request_submitted"
            } else {
                "not_access_request_submitted"
            },
            if self.identity_mutated {
                "identity_mutated"
            } else {
                "not_identity_mutated"
            },
            if self.entitlement_mutated {
                "entitlement_mutated"
            } else {
                "not_entitlement_mutated"
            },
            if self.adopted_by_kernel {
                "adopted_by_kernel"
            } else {
                "not_adopted_by_kernel"
            },
        ]))
    }

    pub fn campaign_state(&self) -> CampaignState {
        self.projection.campaign_state
    }

    pub fn decision_state(&self) -> DecisionState {
        self.projection.decision_state
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointRecordingReceipt {
    pub recorded: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_mutated: bool,
    pub raw_provider_payload_retained: bool,
    pub credential_material_retained: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointVerification {
    pub verified: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_readback_performed: bool,
    pub certification_decision_authority: bool,
    pub access_safety_authority: bool,
    pub consent_authority: bool,
    pub outcome_authority: bool,
}
