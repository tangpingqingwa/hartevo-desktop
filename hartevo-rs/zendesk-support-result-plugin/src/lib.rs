#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 Zendesk support-result evidence plugin."]
//!
//! This crate owns a narrow, read/proposal/recording boundary for Zendesk
//! Support. It binds one account, ticket, requester, organization, SLA target,
//! metric, audit revision, customer-resolution objective, and exact Hartevo
//! Project/Mission/Work Product scope. It deliberately contains no HTTP
//! client, native credential resolver, comment sender, ticket mutator, Inbox
//! authority, durable provider receipt, or Outcome adoption authority.
//!
//! Recording, fake, loopback, and `BLOCKED_ENV` transports are deterministic
//! evidence sources. Every one of them reports `connected = false`,
//! `native = false`, and `first_party = false`.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.zendesk-support-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-ZENDESK-01-L1/v1";
pub const PLUGIN_ID: &str = "zendesk.support-result";
pub const SERVICE_ID: &str = "ZendeskSupportResultService";
pub const PROVIDER_ID: &str = "ZendeskProvider";
pub const CONSUMER_ID: &str = "MissionZendeskSupportConsumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const ZENDESK_API_V2_PATH: &str = "/api/v2";
pub const TICKET_PATH: &str = "/api/v2/tickets/{ticket_id}";
pub const TICKET_METRICS_PATH: &str = "/api/v2/tickets/{ticket_id}/metrics";
pub const SATISFACTION_PATH: &str = "/api/v2/tickets/{ticket_id}/satisfaction_rating";
pub const TICKET_AUDITS_PATH: &str = "/api/v2/tickets/{ticket_id}/audits";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_ITEMS: usize = 100;
pub const MAX_PAGES: usize = 32;
pub const MAX_AUDIT_TRANSITIONS: usize = 1_024;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_METRIC_VALUE: u64 = 10_000_000;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/zendesk-support-result/service.v1.json");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

pub const PLUGIN_VERSION: Version = Version::new(1, 0, 0);

/// A lowercase SHA-256 digest. Raw Zendesk response bodies, comments,
/// attachments, and credential material are never represented by this type.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded contract values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ZendeskError {
    #[error("invalid Layer-1 Zendesk input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid digest")]
    InvalidDigest,
    #[error("required Zendesk read permission is missing or drifted")]
    PermissionDrift,
    #[error("Zendesk subdomain does not match the bound scope")]
    SubdomainMismatch,
    #[error("Zendesk account does not match the bound scope")]
    AccountMismatch,
    #[error("Zendesk ticket does not match the bound scope")]
    TicketMismatch,
    #[error("Zendesk requester does not match the bound scope")]
    RequesterMismatch,
    #[error("Zendesk organization does not match the bound scope")]
    OrganizationMismatch,
    #[error("Zendesk SLA target does not match the bound scope")]
    SlaMismatch,
    #[error("Zendesk ticket metric does not match the bound scope")]
    MetricMismatch,
    #[error("Zendesk ticket audit does not match the bound scope")]
    AuditMismatch,
    #[error("customer-resolution objective does not match the bound scope")]
    ObjectiveMismatch,
    #[error("Mission, Project, or Work Product scope does not match")]
    MissionScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("opaque SecretReference is not bound to this scope")]
    SecretScopeMismatch,
    #[error("opaque SecretReference has been revoked")]
    SecretRevoked,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration has been revoked or reversed")]
    RegistrationRevoked,
    #[error("registration binding or digest drifted")]
    RegistrationDrift,
    #[error("consumer is inactive")]
    ConsumerInactive,
    #[error("ticket revision drifted")]
    RevisionDrift,
    #[error("ticket recording was replayed with different evidence")]
    DuplicateTicket,
    #[error("audit event was replayed with different content")]
    DuplicateAudit,
    #[error("invalid ticket status transition")]
    InvalidStateTransition,
    #[error("pagination cursor repeated")]
    PaginationRepeatedCursor,
    #[error("pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider returned a malformed response")]
    MalformedResponse,
    #[error("provider returned a partial response")]
    PartialResponse,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider response retained forbidden raw data")]
    RedactionViolation,
    #[error("provider payload or evidence digest was tampered")]
    EvidenceTampered,
    #[error("support proposal digest or binding was tampered")]
    ProposalTampered,
    #[error("recording digest or binding was tampered")]
    RecordingTampered,
    #[error("provider is unavailable in the blocked environment")]
    BlockedEnv,
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("provider returned an unknown transport error")]
    ProviderUnknown,
    #[error("recording transport has no response queued")]
    MissingRecordedResponse,
    #[error("invalid read limits")]
    InvalidLimits,
}

impl ZendeskError {
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn projection(&self) -> ZendeskTicketStatus {
        match self {
            Self::HttpStatus {
                status: 401 | 403, ..
            }
            | Self::SecretRevoked
            | Self::SecretScopeMismatch
            | Self::RegistrationRevoked
            | Self::RegistrationInactive => ZendeskTicketStatus::AccessLoss,
            Self::PartialResponse
            | Self::MalformedResponse
            | Self::ResponseTooLarge
            | Self::RedactionViolation
            | Self::EvidenceTampered
            | Self::RevisionDrift => ZendeskTicketStatus::Partial,
            Self::Timeout
            | Self::ProviderUnknown
            | Self::BlockedEnv
            | Self::HttpStatus {
                status: 404 | 409 | 429 | 500..=599,
                ..
            } => ZendeskTicketStatus::ProviderUnknown,
            _ => ZendeskTicketStatus::Unknown,
        }
    }
}

fn validate_text(field: &'static str, value: &str, max_bytes: usize) -> Result<(), ZendeskError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ZendeskError::InvalidInput(field));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ZendeskError> {
    validate_text(field, value, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ZendeskError::InvalidInput(field));
    }
    Ok(())
}

fn validate_revision(revision: u64) -> Result<(), ZendeskError> {
    if revision == 0 {
        Err(ZendeskError::InvalidInput("revision"))
    } else {
        Ok(())
    }
}

fn validate_id(field: &'static str, value: u64) -> Result<(), ZendeskError> {
    if value == 0 {
        Err(ZendeskError::InvalidInput(field))
    } else {
        Ok(())
    }
}

fn validate_digest(digest: &Digest) -> Result<(), ZendeskError> {
    if digest.is_valid() {
        Ok(())
    } else {
        Err(ZendeskError::InvalidDigest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskAccountIdentity {
    pub subdomain: String,
    pub account_id: String,
    pub revision: u64,
}

impl ZendeskAccountIdentity {
    pub fn new(
        subdomain: impl Into<String>,
        account_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ZendeskError> {
        let identity = Self {
            subdomain: subdomain.into(),
            account_id: account_id.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        validate_text("subdomain", &self.subdomain, MAX_IDENTIFIER_BYTES)?;
        if !self
            .subdomain
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ZendeskError::InvalidInput("subdomain"));
        }
        validate_identifier("account id", &self.account_id)?;
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

macro_rules! revisioned_id {
    ($name:ident, $field:ident, $label:literal, $ty:ty) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub $field: $ty,
            pub revision: u64,
        }

        impl $name {
            pub fn new(value: $ty, revision: u64) -> Result<Self, ZendeskError> {
                let identity = Self {
                    $field: value,
                    revision,
                };
                identity.validate()?;
                Ok(identity)
            }

            fn validate(&self) -> Result<(), ZendeskError> {
                validate_id($label, self.$field)?;
                validate_revision(self.revision)
            }

            pub fn digest(&self) -> Digest {
                Digest::from_serializable(self)
            }
        }
    };
}

revisioned_id!(ZendeskTicketIdentity, ticket_id, "ticket id", u64);
revisioned_id!(ZendeskRequesterIdentity, requester_id, "requester id", u64);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskOrganizationIdentity {
    pub organization_id: Option<u64>,
    pub revision: u64,
}

impl ZendeskOrganizationIdentity {
    pub fn new(organization_id: Option<u64>, revision: u64) -> Result<Self, ZendeskError> {
        if let Some(id) = organization_id {
            validate_id("organization id", id)?;
        }
        validate_revision(revision)?;
        Ok(Self {
            organization_id,
            revision,
        })
    }

    pub fn unscoped(revision: u64) -> Result<Self, ZendeskError> {
        Self::new(None, revision)
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        Self::new(self.organization_id, self.revision).map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskSlaIdentity {
    pub target_id: Option<u64>,
    pub revision: u64,
}

impl ZendeskSlaIdentity {
    pub fn new(target_id: Option<u64>, revision: u64) -> Result<Self, ZendeskError> {
        if let Some(id) = target_id {
            validate_id("SLA target id", id)?;
        }
        validate_revision(revision)?;
        Ok(Self {
            target_id,
            revision,
        })
    }

    pub fn unavailable(revision: u64) -> Result<Self, ZendeskError> {
        Self::new(None, revision)
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        Self::new(self.target_id, self.revision).map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskMetricIdentity {
    pub metric_id: u64,
    pub revision: u64,
}

impl ZendeskMetricIdentity {
    pub fn new(metric_id: u64, revision: u64) -> Result<Self, ZendeskError> {
        validate_id("metric id", metric_id)?;
        validate_revision(revision)?;
        Ok(Self {
            metric_id,
            revision,
        })
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        Self::new(self.metric_id, self.revision).map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskAuditIdentity {
    pub audit_id: Option<u64>,
    pub revision: u64,
}

impl ZendeskAuditIdentity {
    pub fn new(audit_id: Option<u64>, revision: u64) -> Result<Self, ZendeskError> {
        if let Some(id) = audit_id {
            validate_id("audit id", id)?;
        }
        validate_revision(revision)?;
        Ok(Self { audit_id, revision })
    }

    pub fn all_for_revision(revision: u64) -> Result<Self, ZendeskError> {
        Self::new(None, revision)
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        Self::new(self.audit_id, self.revision).map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScopeBinding {
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub policy_digest: Digest,
    pub consent_digest: Digest,
}

impl MissionScopeBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        project_revision: u64,
        mission_revision: u64,
        work_product_revision: u64,
        policy_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ZendeskError> {
        let binding = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            work_product_id: work_product_id.into(),
            project_revision,
            mission_revision,
            work_product_revision,
            policy_digest,
            consent_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        validate_identifier("Project", &self.project_id)?;
        validate_identifier("Mission", &self.mission_id)?;
        validate_identifier("Work Product", &self.work_product_id)?;
        validate_revision(self.project_revision)?;
        validate_revision(self.mission_revision)?;
        validate_revision(self.work_product_revision)?;
        validate_digest(&self.policy_digest)?;
        validate_digest(&self.consent_digest)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomerResolutionObjective {
    pub objective_id: String,
    pub revision: u64,
    pub objective_digest: Digest,
}

impl CustomerResolutionObjective {
    pub fn new(objective_id: impl Into<String>, revision: u64) -> Result<Self, ZendeskError> {
        let objective_id = objective_id.into();
        validate_identifier("customer-resolution objective", &objective_id)?;
        validate_revision(revision)?;
        let objective_digest = Digest::from_serializable(&(objective_id.as_str(), revision));
        Ok(Self {
            objective_id,
            revision,
            objective_digest,
        })
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        validate_identifier("customer-resolution objective", &self.objective_id)?;
        validate_revision(self.revision)?;
        if self.objective_digest
            != Digest::from_serializable(&(self.objective_id.as_str(), self.revision))
        {
            return Err(ZendeskError::ObjectiveMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZendeskPermission {
    AccountRead,
    TicketRead,
    RequesterRead,
    OrganizationRead,
    SlaRead,
    MetricRead,
    AuditRead,
    SatisfactionRead,
    MissionScope,
}

impl ZendeskPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountRead => "account:read",
            Self::TicketRead => "ticket:read",
            Self::RequesterRead => "requester:read",
            Self::OrganizationRead => "organization:read",
            Self::SlaRead => "sla:read",
            Self::MetricRead => "metric:read",
            Self::AuditRead => "audit:read",
            Self::SatisfactionRead => "satisfaction:read",
            Self::MissionScope => "mission:scope",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskSupportScope {
    pub account: ZendeskAccountIdentity,
    pub ticket: ZendeskTicketIdentity,
    pub requester: ZendeskRequesterIdentity,
    pub organization: ZendeskOrganizationIdentity,
    pub sla: ZendeskSlaIdentity,
    pub metric: ZendeskMetricIdentity,
    pub audit: ZendeskAuditIdentity,
    pub objective: CustomerResolutionObjective,
    pub mission: MissionScopeBinding,
    pub permissions: BTreeSet<ZendeskPermission>,
}

impl ZendeskSupportScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: ZendeskAccountIdentity,
        ticket: ZendeskTicketIdentity,
        requester: ZendeskRequesterIdentity,
        organization: ZendeskOrganizationIdentity,
        sla: ZendeskSlaIdentity,
        metric: ZendeskMetricIdentity,
        audit: ZendeskAuditIdentity,
        objective: CustomerResolutionObjective,
        mission: MissionScopeBinding,
        permissions: impl IntoIterator<Item = ZendeskPermission>,
    ) -> Result<Self, ZendeskError> {
        let scope = Self {
            account,
            ticket,
            requester,
            organization,
            sla,
            metric,
            audit,
            objective,
            mission,
            permissions: permissions.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.account.validate()?;
        self.ticket.validate()?;
        self.requester.validate()?;
        self.organization.validate()?;
        self.sla.validate()?;
        self.metric.validate()?;
        self.audit.validate()?;
        self.objective.validate()?;
        self.mission.validate()?;
        let required = [
            ZendeskPermission::AccountRead,
            ZendeskPermission::TicketRead,
            ZendeskPermission::RequesterRead,
            ZendeskPermission::OrganizationRead,
            ZendeskPermission::SlaRead,
            ZendeskPermission::MetricRead,
            ZendeskPermission::AuditRead,
            ZendeskPermission::SatisfactionRead,
            ZendeskPermission::MissionScope,
        ];
        if required
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(ZendeskError::PermissionDrift);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn account_digest(&self) -> Digest {
        self.account.digest()
    }

    pub fn ticket_digest(&self) -> Digest {
        self.ticket.digest()
    }

    pub fn requester_digest(&self) -> Digest {
        self.requester.digest()
    }

    pub fn organization_digest(&self) -> Digest {
        self.organization.digest()
    }

    pub fn sla_digest(&self) -> Digest {
        self.sla.digest()
    }

    pub fn metric_digest(&self) -> Digest {
        self.metric.digest()
    }

    pub fn audit_digest(&self) -> Digest {
        self.audit.digest()
    }

    pub fn objective_digest(&self) -> Digest {
        self.objective.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        let permissions: Vec<&str> = self
            .permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect();
        Digest::from_serializable(&permissions)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    OAuth,
    ApiToken,
}

/// An opaque credential handle. The caller-provided reference is immediately
/// reduced to a digest and is never stored, serialized, formatted, or sent to
/// a transport.
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SecretReference", 4)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.end()
    }
}

impl fmt::Display for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretReference(opaque)")
    }
}

impl SecretReference {
    pub fn new(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        scope: &ZendeskSupportScope,
        credential_revision: u64,
    ) -> Result<Self, ZendeskError> {
        let reference = opaque_reference.as_ref();
        validate_text("SecretReference", reference, MAX_IDENTIFIER_BYTES)?;
        validate_revision(credential_revision)?;
        Ok(Self {
            kind,
            reference_digest: Digest::from_text(reference),
            scope_digest: scope.scope_digest(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        scope: &ZendeskSupportScope,
        credential_revision: u64,
    ) -> Result<Self, ZendeskError> {
        Self::new(
            SecretReferenceKind::OAuth,
            opaque_reference,
            scope,
            credential_revision,
        )
    }

    pub fn api_token(
        opaque_reference: impl AsRef<str>,
        scope: &ZendeskSupportScope,
        credential_revision: u64,
    ) -> Result<Self, ZendeskError> {
        Self::new(
            SecretReferenceKind::ApiToken,
            opaque_reference,
            scope,
            credential_revision,
        )
    }

    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskRegistration {
    pub status: RegistrationStatus,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub account_digest: Digest,
    pub ticket_digest: Digest,
    pub requester_digest: Digest,
    pub organization_digest: Digest,
    pub sla_digest: Digest,
    pub metric_digest: Digest,
    pub audit_digest: Digest,
    pub objective_digest: Digest,
    pub mission_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub credential_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_digest: Digest,
    pub status: RegistrationStatus,
    pub transition: RegistrationTransitionEvidence,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub transition: RegistrationTransitionEvidence,
    pub secret_revoked: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl ZendeskRegistration {
    pub fn new(
        scope: &ZendeskSupportScope,
        secret: &SecretReference,
    ) -> Result<Self, ZendeskError> {
        scope.validate()?;
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(ZendeskError::SecretScopeMismatch);
        }
        let mut registration = Self {
            status: RegistrationStatus::Active,
            version_digest: Digest::from_serializable(&PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: Digest::from_text(PROVIDER_ID),
            account_digest: scope.account_digest(),
            ticket_digest: scope.ticket_digest(),
            requester_digest: scope.requester_digest(),
            organization_digest: scope.organization_digest(),
            sla_digest: scope.sla_digest(),
            metric_digest: scope.metric_digest(),
            audit_digest: scope.audit_digest(),
            objective_digest: scope.objective_digest(),
            mission_digest: scope.mission_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            credential_digest: secret.reference_digest().clone(),
            registration_digest: Digest::from_text("unsealed"),
            reversible: true,
            revocable: true,
        };
        registration.seal();
        Ok(registration)
    }

    fn digest_input(&self) -> (&str, &Digest, &Digest, RegistrationStatus) {
        (
            CONTRACT_SCHEMA,
            &self.scope_digest,
            &self.credential_digest,
            self.status,
        )
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.digest_input(),
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.account_digest,
            &self.ticket_digest,
            &self.requester_digest,
            &self.organization_digest,
            &self.sla_digest,
            &self.metric_digest,
            &self.audit_digest,
            &self.objective_digest,
            &self.mission_digest,
            &self.permission_digest,
        ))
    }

    fn seal(&mut self) {
        self.registration_digest = self.expected_digest();
    }

    pub fn validate_binding(
        &self,
        scope: &ZendeskSupportScope,
        secret: &SecretReference,
    ) -> Result<(), ZendeskError> {
        if self.registration_digest != self.expected_digest()
            || self.version_digest != Digest::from_serializable(&PLUGIN_VERSION)
            || self.contract_digest != contract_digest()
            || self.provider_digest != Digest::from_text(PROVIDER_ID)
            || self.scope_digest != scope.scope_digest()
            || self.credential_digest != *secret.reference_digest()
            || secret.scope_digest() != &scope.scope_digest()
        {
            return Err(ZendeskError::RegistrationDrift);
        }
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        self.status.is_active()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence, ZendeskError> {
        if self.status != RegistrationStatus::Active || !self.reversible {
            return Err(ZendeskError::RegistrationInactive);
        }
        Ok(self.transition(RegistrationStatus::Unmounted))
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence, ZendeskError> {
        if self.status != RegistrationStatus::Unmounted || !self.reversible {
            return Err(ZendeskError::RegistrationInactive);
        }
        Ok(self.transition(RegistrationStatus::Active))
    }

    pub fn revoke(
        &mut self,
        secret: &mut SecretReference,
    ) -> Result<RevocationReceipt, ZendeskError> {
        if !self.revocable
            || matches!(
                self.status,
                RegistrationStatus::Revoked | RegistrationStatus::Reversed
            )
        {
            return Err(ZendeskError::RegistrationRevoked);
        }
        let transition = self.transition(RegistrationStatus::Revoked);
        secret.revoke();
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            transition,
            secret_revoked: secret.is_revoked(),
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, ZendeskError> {
        if self.status != RegistrationStatus::Revoked || !self.reversible {
            return Err(ZendeskError::RegistrationRevoked);
        }
        Ok(self.transition(RegistrationStatus::Reversed))
    }

    fn transition(&mut self, to: RegistrationStatus) -> RegistrationTransitionEvidence {
        let from = self.status;
        self.status = to;
        self.seal();
        RegistrationTransitionEvidence {
            from,
            to,
            transition_digest: Digest::from_serializable(&(
                CONTRACT_SCHEMA,
                from,
                to,
                &self.registration_digest,
            )),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ZendeskRegistrationRegistry {
    registrations: BTreeMap<String, ZendeskRegistration>,
}

impl ZendeskRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: ZendeskRegistration,
    ) -> Result<RegistrationReceipt, ZendeskError> {
        let id = registration.registration_digest.as_str().to_owned();
        if self.registrations.contains_key(&id) {
            return Err(ZendeskError::RevisionDrift);
        }
        let status = registration.status;
        self.registrations.insert(id.clone(), registration);
        Ok(RegistrationReceipt {
            registration_digest: Digest(id),
            status,
            transition: RegistrationTransitionEvidence {
                from: RegistrationStatus::Unmounted,
                to: status,
                transition_digest: Digest::from_text("registration-created"),
            },
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn get(&self, digest: &Digest) -> Option<&ZendeskRegistration> {
        self.registrations.get(digest.as_str())
    }

    pub fn get_mut(&mut self, digest: &Digest) -> Option<&mut ZendeskRegistration> {
        self.registrations.get_mut(digest.as_str())
    }

    pub fn restore(
        &mut self,
        digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence, ZendeskError> {
        self.registrations
            .get_mut(digest.as_str())
            .ok_or(ZendeskError::RevisionDrift)?
            .remount()
    }

    pub fn revoke(
        &mut self,
        digest: &Digest,
        secret: &mut SecretReference,
    ) -> Result<RevocationReceipt, ZendeskError> {
        self.registrations
            .get_mut(digest.as_str())
            .ok_or(ZendeskError::RevisionDrift)?
            .revoke(secret)
    }

    pub fn reverse(
        &mut self,
        digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence, ZendeskError> {
        self.registrations
            .get_mut(digest.as_str())
            .ok_or(ZendeskError::RevisionDrift)?
            .reverse()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZendeskTicketStatus {
    New,
    Open,
    Pending,
    Hold,
    Solved,
    Closed,
    Reopened,
    Unknown,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

impl ZendeskTicketStatus {
    pub fn can_follow(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::New => matches!(
                next,
                Self::Open
                    | Self::Pending
                    | Self::Hold
                    | Self::Solved
                    | Self::Closed
                    | Self::Reopened
                    | Self::Unknown
                    | Self::Partial
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Open | Self::Pending | Self::Hold => matches!(
                next,
                Self::Open
                    | Self::Pending
                    | Self::Hold
                    | Self::Solved
                    | Self::Closed
                    | Self::Reopened
                    | Self::Unknown
                    | Self::Partial
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Solved | Self::Closed => matches!(
                next,
                Self::Reopened
                    | Self::Closed
                    | Self::Unknown
                    | Self::Partial
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Reopened => matches!(
                next,
                Self::New
                    | Self::Open
                    | Self::Pending
                    | Self::Hold
                    | Self::Solved
                    | Self::Closed
                    | Self::Unknown
                    | Self::Partial
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Unknown | Self::Partial | Self::AccessLoss | Self::ProviderUnknown => true,
        }
    }

    pub const fn is_customer_resolution_terminal(self) -> bool {
        matches!(self, Self::Solved | Self::Closed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZendeskPriority {
    Low,
    Normal,
    High,
    Urgent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZendeskTicketType {
    Question,
    Incident,
    Problem,
    Task,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskTicketMetadata {
    pub created_at_epoch_seconds: u64,
    pub updated_at_epoch_seconds: u64,
    pub channel: String,
    pub custom_field_count: u16,
    pub tag_digest: Option<Digest>,
    pub subject_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl ZendeskTicketMetadata {
    pub fn new(
        created_at_epoch_seconds: u64,
        updated_at_epoch_seconds: u64,
        channel: impl Into<String>,
        custom_field_count: u16,
        tag_digest: Option<Digest>,
        subject_digest: Option<Digest>,
    ) -> Result<Self, ZendeskError> {
        let metadata = Self {
            created_at_epoch_seconds,
            updated_at_epoch_seconds,
            channel: channel.into(),
            custom_field_count,
            tag_digest,
            subject_digest,
            metadata_digest: Digest::from_text("unsealed-ticket-metadata"),
        };
        metadata.validate_shape()?;
        Ok(Self {
            metadata_digest: metadata.expected_digest(),
            ..metadata
        })
    }

    pub fn minimal() -> Self {
        Self::new(1, 1, "unknown", 0, None, None).expect("minimal metadata is valid")
    }

    fn validate_shape(&self) -> Result<(), ZendeskError> {
        if self.updated_at_epoch_seconds < self.created_at_epoch_seconds {
            return Err(ZendeskError::InvalidInput("ticket metadata time"));
        }
        validate_identifier("ticket channel", &self.channel)?;
        if let Some(digest) = &self.tag_digest {
            validate_digest(digest)?;
        }
        if let Some(digest) = &self.subject_digest {
            validate_digest(digest)?;
        }
        Ok(())
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.created_at_epoch_seconds,
            self.updated_at_epoch_seconds,
            &self.channel,
            self.custom_field_count,
            &self.tag_digest,
            &self.subject_digest,
        ))
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.validate_shape()?;
        if self.metadata_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskTicketSnapshot {
    pub account: ZendeskAccountIdentity,
    pub ticket: ZendeskTicketIdentity,
    pub requester: ZendeskRequesterIdentity,
    pub organization: ZendeskOrganizationIdentity,
    pub status: ZendeskTicketStatus,
    pub priority: ZendeskPriority,
    pub ticket_type: ZendeskTicketType,
    pub metadata: ZendeskTicketMetadata,
    pub ticket_digest: Digest,
}

impl ZendeskTicketSnapshot {
    pub fn new(
        account: ZendeskAccountIdentity,
        ticket: ZendeskTicketIdentity,
        requester: ZendeskRequesterIdentity,
        organization: ZendeskOrganizationIdentity,
        status: ZendeskTicketStatus,
        priority: ZendeskPriority,
        ticket_type: ZendeskTicketType,
        metadata: ZendeskTicketMetadata,
    ) -> Result<Self, ZendeskError> {
        let snapshot = Self {
            account,
            ticket,
            requester,
            organization,
            status,
            priority,
            ticket_type,
            metadata,
            ticket_digest: Digest::from_text("unsealed-ticket"),
        };
        snapshot.validate_shape()?;
        Ok(Self {
            ticket_digest: snapshot.expected_digest(),
            ..snapshot
        })
    }

    pub fn for_scope(scope: &ZendeskSupportScope, status: ZendeskTicketStatus) -> Self {
        Self::new(
            scope.account.clone(),
            scope.ticket.clone(),
            scope.requester.clone(),
            scope.organization.clone(),
            status,
            ZendeskPriority::Normal,
            ZendeskTicketType::Question,
            ZendeskTicketMetadata::minimal(),
        )
        .expect("scope fixture is valid")
    }

    fn validate_shape(&self) -> Result<(), ZendeskError> {
        self.account.validate()?;
        self.ticket.validate()?;
        self.requester.validate()?;
        self.organization.validate()?;
        self.metadata.validate()
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.account,
            &self.ticket,
            &self.requester,
            &self.organization,
            self.status,
            self.priority,
            self.ticket_type,
            &self.metadata,
        ))
    }

    pub fn reseal(&mut self) {
        self.ticket_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.validate_shape()?;
        if self.ticket_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaTargetState {
    Active,
    Breached,
    Paused,
    Satisfied,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskSlaTargetSnapshot {
    pub account: ZendeskAccountIdentity,
    pub ticket: ZendeskTicketIdentity,
    pub sla: ZendeskSlaIdentity,
    pub state: SlaTargetState,
    pub target_minutes: Option<u64>,
    pub elapsed_minutes: Option<u64>,
    pub paused_at_epoch_seconds: Option<u64>,
    pub breached_at_epoch_seconds: Option<u64>,
    pub sla_digest: Digest,
}

impl ZendeskSlaTargetSnapshot {
    pub fn new(
        account: ZendeskAccountIdentity,
        ticket: ZendeskTicketIdentity,
        sla: ZendeskSlaIdentity,
        state: SlaTargetState,
        target_minutes: Option<u64>,
        elapsed_minutes: Option<u64>,
        paused_at_epoch_seconds: Option<u64>,
        breached_at_epoch_seconds: Option<u64>,
    ) -> Result<Self, ZendeskError> {
        for value in [target_minutes, elapsed_minutes].into_iter().flatten() {
            if value > MAX_METRIC_VALUE {
                return Err(ZendeskError::InvalidInput("SLA minutes"));
            }
        }
        let snapshot = Self {
            account,
            ticket,
            sla,
            state,
            target_minutes,
            elapsed_minutes,
            paused_at_epoch_seconds,
            breached_at_epoch_seconds,
            sla_digest: Digest::from_text("unsealed-sla"),
        };
        snapshot.validate_shape()?;
        Ok(Self {
            sla_digest: snapshot.expected_digest(),
            ..snapshot
        })
    }

    pub fn for_scope(scope: &ZendeskSupportScope, state: SlaTargetState) -> Self {
        Self::new(
            scope.account.clone(),
            scope.ticket.clone(),
            scope.sla.clone(),
            state,
            Some(60),
            Some(15),
            None,
            None,
        )
        .expect("scope fixture is valid")
    }

    fn validate_shape(&self) -> Result<(), ZendeskError> {
        self.account.validate()?;
        self.ticket.validate()?;
        self.sla.validate()?;
        for value in [self.target_minutes, self.elapsed_minutes]
            .into_iter()
            .flatten()
        {
            if value > MAX_METRIC_VALUE {
                return Err(ZendeskError::InvalidInput("SLA minutes"));
            }
        }
        Ok(())
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.account,
            &self.ticket,
            &self.sla,
            self.state,
            self.target_minutes,
            self.elapsed_minutes,
            self.paused_at_epoch_seconds,
            self.breached_at_epoch_seconds,
        ))
    }

    pub fn reseal(&mut self) {
        self.sla_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.validate_shape()?;
        if self.sla_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricDuration {
    pub business: Option<u64>,
    pub calendar: Option<u64>,
}

impl MetricDuration {
    pub fn new(business: Option<u64>, calendar: Option<u64>) -> Result<Self, ZendeskError> {
        for value in [business, calendar].into_iter().flatten() {
            if value > MAX_METRIC_VALUE {
                return Err(ZendeskError::InvalidInput("metric duration"));
            }
        }
        Ok(Self { business, calendar })
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        Self::new(self.business, self.calendar).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskTicketMetric {
    pub account: ZendeskAccountIdentity,
    pub ticket: ZendeskTicketIdentity,
    pub metric: ZendeskMetricIdentity,
    pub agent_wait_time: MetricDuration,
    pub requester_wait_time: MetricDuration,
    pub first_reply_time: MetricDuration,
    pub first_resolution_time: MetricDuration,
    pub full_resolution_time: MetricDuration,
    pub on_hold_time: MetricDuration,
    pub replies: u32,
    pub reopens: u32,
    pub assignee_stations: u32,
    pub group_stations: u32,
    pub recorded_at_epoch_seconds: u64,
    pub metric_digest: Digest,
}

impl ZendeskTicketMetric {
    pub fn new(
        account: ZendeskAccountIdentity,
        ticket: ZendeskTicketIdentity,
        metric: ZendeskMetricIdentity,
    ) -> Result<Self, ZendeskError> {
        let metric_value = Self {
            account,
            ticket,
            metric,
            agent_wait_time: MetricDuration::default(),
            requester_wait_time: MetricDuration::default(),
            first_reply_time: MetricDuration::default(),
            first_resolution_time: MetricDuration::default(),
            full_resolution_time: MetricDuration::default(),
            on_hold_time: MetricDuration::default(),
            replies: 0,
            reopens: 0,
            assignee_stations: 0,
            group_stations: 0,
            recorded_at_epoch_seconds: 1,
            metric_digest: Digest::from_text("unsealed-metric"),
        };
        metric_value.validate_shape()?;
        Ok(Self {
            metric_digest: metric_value.expected_digest(),
            ..metric_value
        })
    }

    pub fn for_scope(scope: &ZendeskSupportScope) -> Self {
        Self::new(
            scope.account.clone(),
            scope.ticket.clone(),
            scope.metric.clone(),
        )
        .expect("scope fixture is valid")
    }

    fn validate_shape(&self) -> Result<(), ZendeskError> {
        self.account.validate()?;
        self.ticket.validate()?;
        self.metric.validate()?;
        for duration in [
            &self.agent_wait_time,
            &self.requester_wait_time,
            &self.first_reply_time,
            &self.first_resolution_time,
            &self.full_resolution_time,
            &self.on_hold_time,
        ] {
            duration.validate()?;
        }
        for value in [
            u64::from(self.replies),
            u64::from(self.reopens),
            u64::from(self.assignee_stations),
            u64::from(self.group_stations),
        ] {
            if value > MAX_METRIC_VALUE {
                return Err(ZendeskError::InvalidInput("metric count"));
            }
        }
        Ok(())
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.account,
            &self.ticket,
            &self.metric,
            &self.agent_wait_time,
            &self.requester_wait_time,
            &self.first_reply_time,
            &self.first_resolution_time,
            &self.full_resolution_time,
            &self.on_hold_time,
            self.replies,
            self.reopens,
            self.assignee_stations,
            self.group_stations,
            self.recorded_at_epoch_seconds,
        ))
    }

    pub fn reseal(&mut self) {
        self.metric_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.validate_shape()?;
        if self.metric_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTransitionKind {
    TicketCreated,
    StatusChanged,
    Reopened,
    SlaTargetChanged,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskAuditTransition {
    pub account: ZendeskAccountIdentity,
    pub ticket: ZendeskTicketIdentity,
    pub audit_id: u64,
    pub event_id: u64,
    pub audit_revision: u64,
    pub occurred_at_epoch_seconds: u64,
    pub kind: AuditTransitionKind,
    pub from_status: Option<ZendeskTicketStatus>,
    pub to_status: Option<ZendeskTicketStatus>,
    pub sla_state: Option<SlaTargetState>,
    pub field_digest: Option<Digest>,
    pub redacted: bool,
    pub transition_digest: Digest,
}

impl ZendeskAuditTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: ZendeskAccountIdentity,
        ticket: ZendeskTicketIdentity,
        audit_id: u64,
        event_id: u64,
        audit_revision: u64,
        occurred_at_epoch_seconds: u64,
        kind: AuditTransitionKind,
        from_status: Option<ZendeskTicketStatus>,
        to_status: Option<ZendeskTicketStatus>,
        sla_state: Option<SlaTargetState>,
        field_digest: Option<Digest>,
    ) -> Result<Self, ZendeskError> {
        validate_id("audit id", audit_id)?;
        validate_id("audit event id", event_id)?;
        validate_revision(audit_revision)?;
        if let Some(digest) = &field_digest {
            validate_digest(digest)?;
        }
        let transition = Self {
            account,
            ticket,
            audit_id,
            event_id,
            audit_revision,
            occurred_at_epoch_seconds,
            kind,
            from_status,
            to_status,
            sla_state,
            field_digest,
            redacted: true,
            transition_digest: Digest::from_text("unsealed-audit-transition"),
        };
        transition.validate_shape()?;
        Ok(Self {
            transition_digest: transition.expected_digest(),
            ..transition
        })
    }

    pub fn status_change(
        scope: &ZendeskSupportScope,
        audit_id: u64,
        event_id: u64,
        from_status: ZendeskTicketStatus,
        to_status: ZendeskTicketStatus,
    ) -> Result<Self, ZendeskError> {
        Self::new(
            scope.account.clone(),
            scope.ticket.clone(),
            audit_id,
            event_id,
            scope.audit.revision,
            1,
            AuditTransitionKind::StatusChanged,
            Some(from_status),
            Some(to_status),
            None,
            None,
        )
    }

    fn validate_shape(&self) -> Result<(), ZendeskError> {
        self.account.validate()?;
        self.ticket.validate()?;
        validate_id("audit id", self.audit_id)?;
        validate_id("audit event id", self.event_id)?;
        validate_revision(self.audit_revision)?;
        if let Some(digest) = &self.field_digest {
            validate_digest(digest)?;
        }
        if !self.redacted {
            return Err(ZendeskError::RedactionViolation);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.account,
            &self.ticket,
            self.audit_id,
            self.event_id,
            self.audit_revision,
            self.occurred_at_epoch_seconds,
            self.kind,
            self.from_status,
            self.to_status,
            self.sla_state,
            &self.field_digest,
            self.redacted,
        ))
    }

    pub fn reseal(&mut self) {
        self.transition_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.validate_shape()?;
        if self.transition_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskAuditEvidence {
    pub account: ZendeskAccountIdentity,
    pub ticket: ZendeskTicketIdentity,
    pub audit: ZendeskAuditIdentity,
    pub pages_read: u16,
    pub incremental: bool,
    pub transitions: Vec<ZendeskAuditTransition>,
    pub duplicate_events_dropped: u32,
    pub complete: bool,
    pub audit_digest: Digest,
}

impl ZendeskAuditEvidence {
    fn new(
        scope: &ZendeskSupportScope,
        pages_read: usize,
        incremental: bool,
        transitions: Vec<ZendeskAuditTransition>,
        duplicate_events_dropped: usize,
        complete: bool,
    ) -> Result<Self, ZendeskError> {
        if pages_read == 0 || pages_read > usize::from(u16::MAX) {
            return Err(ZendeskError::PaginationLimit);
        }
        if transitions.len() > MAX_AUDIT_TRANSITIONS || duplicate_events_dropped > u32::MAX as usize
        {
            return Err(ZendeskError::PaginationLimit);
        }
        let audit = Self {
            account: scope.account.clone(),
            ticket: scope.ticket.clone(),
            audit: scope.audit.clone(),
            pages_read: u16::try_from(pages_read).map_err(|_| ZendeskError::PaginationLimit)?,
            incremental,
            transitions,
            duplicate_events_dropped: u32::try_from(duplicate_events_dropped)
                .map_err(|_| ZendeskError::PaginationLimit)?,
            complete,
            audit_digest: Digest::from_text("unsealed-audit-evidence"),
        };
        audit.validate_shape()?;
        Ok(Self {
            audit_digest: audit.expected_digest(),
            ..audit
        })
    }

    fn validate_shape(&self) -> Result<(), ZendeskError> {
        self.account.validate()?;
        self.ticket.validate()?;
        self.audit.validate()?;
        if self.pages_read == 0 || self.transitions.len() > MAX_AUDIT_TRANSITIONS {
            return Err(ZendeskError::PaginationLimit);
        }
        let mut seen = BTreeSet::new();
        for transition in &self.transitions {
            transition.validate()?;
            if transition.account != self.account || transition.ticket != self.ticket {
                return Err(ZendeskError::AuditMismatch);
            }
            if transition.audit_revision != self.audit.revision {
                return Err(ZendeskError::RevisionDrift);
            }
            if let Some(audit_id) = self.audit.audit_id
                && transition.audit_id != audit_id
            {
                return Err(ZendeskError::AuditMismatch);
            }
            if !seen.insert(transition.event_id) {
                return Err(ZendeskError::DuplicateAudit);
            }
        }
        Ok(())
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.account,
            &self.ticket,
            &self.audit,
            self.pages_read,
            self.incremental,
            &self.transitions,
            self.duplicate_events_dropped,
            self.complete,
        ))
    }

    pub fn reseal(&mut self) {
        self.audit_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.validate_shape()?;
        if self.audit_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SatisfactionAvailability {
    Offered,
    Unoffered,
    Received,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SatisfactionScore {
    Good,
    Bad,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskSatisfactionSummary {
    pub account: ZendeskAccountIdentity,
    pub ticket: ZendeskTicketIdentity,
    pub requester: ZendeskRequesterIdentity,
    pub organization: ZendeskOrganizationIdentity,
    pub availability: SatisfactionAvailability,
    pub score: Option<SatisfactionScore>,
    pub rating_id: Option<u64>,
    pub comment_present: bool,
    pub received_at_epoch_seconds: Option<u64>,
    pub satisfaction_revision: u64,
    pub satisfaction_digest: Digest,
}

impl ZendeskSatisfactionSummary {
    pub fn new(
        account: ZendeskAccountIdentity,
        ticket: ZendeskTicketIdentity,
        requester: ZendeskRequesterIdentity,
        organization: ZendeskOrganizationIdentity,
        availability: SatisfactionAvailability,
        score: Option<SatisfactionScore>,
        rating_id: Option<u64>,
        comment_present: bool,
        received_at_epoch_seconds: Option<u64>,
        satisfaction_revision: u64,
    ) -> Result<Self, ZendeskError> {
        if let Some(rating_id) = rating_id {
            validate_id("satisfaction rating id", rating_id)?;
        }
        validate_revision(satisfaction_revision)?;
        let summary = Self {
            account,
            ticket,
            requester,
            organization,
            availability,
            score,
            rating_id,
            comment_present,
            received_at_epoch_seconds,
            satisfaction_revision,
            satisfaction_digest: Digest::from_text("unsealed-satisfaction"),
        };
        summary.validate_shape()?;
        Ok(Self {
            satisfaction_digest: summary.expected_digest(),
            ..summary
        })
    }

    pub fn for_scope(scope: &ZendeskSupportScope, availability: SatisfactionAvailability) -> Self {
        Self::new(
            scope.account.clone(),
            scope.ticket.clone(),
            scope.requester.clone(),
            scope.organization.clone(),
            availability,
            None,
            None,
            false,
            None,
            scope.ticket.revision,
        )
        .expect("scope fixture is valid")
    }

    fn validate_shape(&self) -> Result<(), ZendeskError> {
        self.account.validate()?;
        self.ticket.validate()?;
        self.requester.validate()?;
        self.organization.validate()?;
        validate_revision(self.satisfaction_revision)?;
        if let Some(rating_id) = self.rating_id {
            validate_id("satisfaction rating id", rating_id)?;
        }
        if self.availability == SatisfactionAvailability::Received && self.score.is_none() {
            return Err(ZendeskError::MalformedResponse);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.account,
            &self.ticket,
            &self.requester,
            &self.organization,
            self.availability,
            self.score,
            self.rating_id,
            self.comment_present,
            self.received_at_epoch_seconds,
            self.satisfaction_revision,
        ))
    }

    pub fn reseal(&mut self) {
        self.satisfaction_digest = self.expected_digest();
    }

    pub fn validate(&self) -> Result<(), ZendeskError> {
        self.validate_shape()?;
        if self.satisfaction_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZendeskOperation {
    ReadTicket,
    ReadSlaTarget,
    ReadTicketMetric,
    ReadAuditEvents,
    ReadSatisfaction,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub raw_comments_retained: bool,
    pub raw_attachments_retained: bool,
    pub raw_pii_retained: bool,
    pub fields_truncated: bool,
}

impl RedactionEvidence {
    fn validate(&self) -> Result<(), ZendeskError> {
        if self.raw_comments_retained || self.raw_attachments_retained || self.raw_pii_retained {
            Err(ZendeskError::RedactionViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadLimits {
    pub max_response_bytes: usize,
    pub max_page_items: usize,
    pub max_pages: usize,
    pub max_audit_transitions: usize,
    pub max_metadata_bytes: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_page_items: MAX_PAGE_ITEMS,
            max_pages: MAX_PAGES,
            max_audit_transitions: MAX_AUDIT_TRANSITIONS,
            max_metadata_bytes: MAX_METADATA_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn validate(self) -> Result<Self, ZendeskError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_page_items == 0
            || self.max_page_items > MAX_PAGE_ITEMS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_audit_transitions == 0
            || self.max_audit_transitions > MAX_AUDIT_TRANSITIONS
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > MAX_METADATA_BYTES
        {
            return Err(ZendeskError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskPayload<T> {
    pub operation: ZendeskOperation,
    pub value: T,
    pub response_bytes: usize,
    pub complete: bool,
    pub redaction: RedactionEvidence,
    pub payload_digest: Digest,
}

impl<T: Serialize> ZendeskPayload<T> {
    pub fn new(operation: ZendeskOperation, value: T) -> Self {
        let payload_digest = Digest::from_serializable(&value);
        Self {
            operation,
            value,
            response_bytes: 1,
            complete: true,
            redaction: RedactionEvidence::default(),
            payload_digest,
        }
    }

    #[must_use]
    pub fn with_metadata(
        mut self,
        response_bytes: usize,
        complete: bool,
        redaction: RedactionEvidence,
    ) -> Self {
        self.response_bytes = response_bytes;
        self.complete = complete;
        self.redaction = redaction;
        self
    }

    fn verify(&self, limits: &ReadLimits) -> Result<(), ZendeskError>
    where
        T: PartialEq,
    {
        if self.response_bytes > limits.max_response_bytes {
            return Err(ZendeskError::ResponseTooLarge);
        }
        self.redaction.validate()?;
        if !self.complete {
            return Err(ZendeskError::PartialResponse);
        }
        if self.payload_digest != Digest::from_serializable(&self.value) {
            return Err(ZendeskError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskPage<T> {
    pub operation: ZendeskOperation,
    pub page_index: usize,
    pub cursor_in: Option<String>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub end_of_stream: bool,
    pub incremental: bool,
    pub items: Vec<T>,
    pub response_bytes: usize,
    pub complete: bool,
    pub redaction: RedactionEvidence,
    pub page_digest: Digest,
}

impl<T: Serialize> ZendeskPage<T> {
    pub fn new(
        operation: ZendeskOperation,
        page_index: usize,
        cursor_in: Option<String>,
        next_cursor: Option<String>,
        items: Vec<T>,
    ) -> Self {
        let has_more = next_cursor.is_some();
        let page_digest = Digest::from_serializable(&(
            operation,
            page_index,
            &cursor_in,
            &next_cursor,
            has_more,
            !has_more,
            false,
            &items,
        ));
        Self {
            operation,
            page_index,
            cursor_in,
            next_cursor,
            has_more,
            end_of_stream: !has_more,
            incremental: false,
            items,
            response_bytes: 1,
            complete: true,
            redaction: RedactionEvidence::default(),
            page_digest,
        }
    }

    #[must_use]
    pub fn with_metadata(
        mut self,
        response_bytes: usize,
        complete: bool,
        redaction: RedactionEvidence,
    ) -> Self {
        self.response_bytes = response_bytes;
        self.complete = complete;
        self.redaction = redaction;
        self
    }

    #[must_use]
    pub fn with_incremental(mut self, incremental: bool) -> Self {
        self.incremental = incremental;
        self.page_digest = self.expected_digest();
        self
    }

    #[must_use]
    pub fn with_pagination(mut self, has_more: bool, end_of_stream: bool) -> Self {
        self.has_more = has_more;
        self.end_of_stream = end_of_stream;
        self.page_digest = self.expected_digest();
        self
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.operation,
            self.page_index,
            &self.cursor_in,
            &self.next_cursor,
            self.has_more,
            self.end_of_stream,
            self.incremental,
            &self.items,
        ))
    }

    fn verify(&self, limits: &ReadLimits) -> Result<(), ZendeskError>
    where
        T: PartialEq,
    {
        if self.response_bytes > limits.max_response_bytes {
            return Err(ZendeskError::ResponseTooLarge);
        }
        if self.items.len() > limits.max_page_items {
            return Err(ZendeskError::PaginationLimit);
        }
        if self
            .cursor_in
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_CURSOR_BYTES)
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.len() > MAX_CURSOR_BYTES)
        {
            return Err(ZendeskError::InvalidInput("pagination cursor"));
        }
        self.redaction.validate()?;
        if !self.complete {
            return Err(ZendeskError::PartialResponse);
        }
        if self.page_digest != self.expected_digest() {
            return Err(ZendeskError::EvidenceTampered);
        }
        if self.has_more != self.next_cursor.is_some() || self.end_of_stream == self.has_more {
            return Err(ZendeskError::MalformedResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskReadRequest {
    pub ticket_id: u64,
    pub ticket_revision: u64,
    pub observed_at_epoch_seconds: u64,
    pub incremental_start_time: Option<u64>,
}

impl ZendeskReadRequest {
    pub fn new(
        ticket_id: u64,
        ticket_revision: u64,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, ZendeskError> {
        validate_id("ticket id", ticket_id)?;
        validate_revision(ticket_revision)?;
        Ok(Self {
            ticket_id,
            ticket_revision,
            observed_at_epoch_seconds,
            incremental_start_time: None,
        })
    }

    pub fn for_scope(scope: &ZendeskSupportScope, observed_at_epoch_seconds: u64) -> Self {
        Self {
            ticket_id: scope.ticket.ticket_id,
            ticket_revision: scope.ticket.revision,
            observed_at_epoch_seconds,
            incremental_start_time: None,
        }
    }

    #[must_use]
    pub fn incremental_since(mut self, start_time_epoch_seconds: u64) -> Self {
        self.incremental_start_time = Some(start_time_epoch_seconds);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskAuditReadRequest {
    pub ticket_id: u64,
    pub ticket_revision: u64,
    pub cursor: Option<String>,
    pub incremental_start_time: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ZendeskTransportError {
    #[error("HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("timeout")]
    Timeout,
    #[error("malformed response")]
    MalformedResponse,
    #[error("partial response")]
    PartialResponse,
    #[error("response too large")]
    ResponseTooLarge,
    #[error("redaction violation")]
    RedactionViolation,
    #[error("revision drift")]
    RevisionDrift,
    #[error("blocked environment")]
    BlockedEnv,
    #[error("no response recorded")]
    MissingResponse,
}

impl ZendeskError {
    fn from_transport(error: ZendeskTransportError) -> Self {
        match error {
            ZendeskTransportError::HttpStatus {
                status,
                retry_after_seconds,
            } => Self::HttpStatus {
                status,
                retry_after_seconds,
            },
            ZendeskTransportError::Timeout => Self::Timeout,
            ZendeskTransportError::MalformedResponse => Self::MalformedResponse,
            ZendeskTransportError::PartialResponse => Self::PartialResponse,
            ZendeskTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            ZendeskTransportError::RedactionViolation => Self::RedactionViolation,
            ZendeskTransportError::RevisionDrift => Self::RevisionDrift,
            ZendeskTransportError::BlockedEnv => Self::BlockedEnv,
            ZendeskTransportError::MissingResponse => Self::MissingRecordedResponse,
        }
    }
}

pub trait ZendeskTransport {
    fn provenance(&self) -> TransportProvenance;

    fn read_ticket(
        &mut self,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskTicketSnapshot>, ZendeskTransportError>;

    fn read_sla_target(
        &mut self,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskSlaTargetSnapshot>, ZendeskTransportError>;

    fn read_metric(
        &mut self,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskTicketMetric>, ZendeskTransportError>;

    fn read_audit_page(
        &mut self,
        request: &ZendeskAuditReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskPage<ZendeskAuditTransition>, ZendeskTransportError>;

    fn read_satisfaction(
        &mut self,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskSatisfactionSummary>, ZendeskTransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingZendeskTransport {
    provenance: TransportProvenance,
    ticket_responses:
        VecDeque<Result<ZendeskPayload<ZendeskTicketSnapshot>, ZendeskTransportError>>,
    sla_responses:
        VecDeque<Result<ZendeskPayload<ZendeskSlaTargetSnapshot>, ZendeskTransportError>>,
    metric_responses: VecDeque<Result<ZendeskPayload<ZendeskTicketMetric>, ZendeskTransportError>>,
    audit_pages: VecDeque<Result<ZendeskPage<ZendeskAuditTransition>, ZendeskTransportError>>,
    satisfaction_responses:
        VecDeque<Result<ZendeskPayload<ZendeskSatisfactionSummary>, ZendeskTransportError>>,
    failure: Option<ZendeskTransportError>,
}

impl RecordingZendeskTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            ticket_responses: VecDeque::new(),
            sla_responses: VecDeque::new(),
            metric_responses: VecDeque::new(),
            audit_pages: VecDeque::new(),
            satisfaction_responses: VecDeque::new(),
            failure: None,
        }
    }

    pub fn recording() -> Self {
        Self::new(TransportProvenance::Recording)
    }

    pub fn fake() -> Self {
        Self::new(TransportProvenance::Fake)
    }

    pub fn loopback() -> Self {
        Self::new(TransportProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportProvenance::BlockedEnv).with_failure(ZendeskTransportError::BlockedEnv)
    }

    #[must_use]
    pub fn with_failure(mut self, failure: ZendeskTransportError) -> Self {
        self.failure = Some(failure);
        self
    }

    pub fn fail_with(&mut self, failure: ZendeskTransportError) {
        self.failure = Some(failure);
    }

    pub fn push_ticket_response(
        &mut self,
        response: Result<ZendeskPayload<ZendeskTicketSnapshot>, ZendeskTransportError>,
    ) {
        self.ticket_responses.push_back(response);
    }

    pub fn push_sla_response(
        &mut self,
        response: Result<ZendeskPayload<ZendeskSlaTargetSnapshot>, ZendeskTransportError>,
    ) {
        self.sla_responses.push_back(response);
    }

    pub fn push_metric_response(
        &mut self,
        response: Result<ZendeskPayload<ZendeskTicketMetric>, ZendeskTransportError>,
    ) {
        self.metric_responses.push_back(response);
    }

    pub fn push_audit_page(
        &mut self,
        response: Result<ZendeskPage<ZendeskAuditTransition>, ZendeskTransportError>,
    ) {
        self.audit_pages.push_back(response);
    }

    pub fn push_satisfaction_response(
        &mut self,
        response: Result<ZendeskPayload<ZendeskSatisfactionSummary>, ZendeskTransportError>,
    ) {
        self.satisfaction_responses.push_back(response);
    }

    fn pop<T>(
        queue: &mut VecDeque<Result<T, ZendeskTransportError>>,
        failure: Option<&ZendeskTransportError>,
    ) -> Result<T, ZendeskTransportError> {
        queue.pop_front().unwrap_or_else(|| {
            failure
                .copied()
                .map_or(Err(ZendeskTransportError::MissingResponse), Err)
        })
    }
}

impl ZendeskTransport for RecordingZendeskTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read_ticket(
        &mut self,
        _request: &ZendeskReadRequest,
        _secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskTicketSnapshot>, ZendeskTransportError> {
        Self::pop(&mut self.ticket_responses, self.failure.as_ref())
    }

    fn read_sla_target(
        &mut self,
        _request: &ZendeskReadRequest,
        _secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskSlaTargetSnapshot>, ZendeskTransportError> {
        Self::pop(&mut self.sla_responses, self.failure.as_ref())
    }

    fn read_metric(
        &mut self,
        _request: &ZendeskReadRequest,
        _secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskTicketMetric>, ZendeskTransportError> {
        Self::pop(&mut self.metric_responses, self.failure.as_ref())
    }

    fn read_audit_page(
        &mut self,
        _request: &ZendeskAuditReadRequest,
        _secret: &SecretReference,
    ) -> Result<ZendeskPage<ZendeskAuditTransition>, ZendeskTransportError> {
        Self::pop(&mut self.audit_pages, self.failure.as_ref())
    }

    fn read_satisfaction(
        &mut self,
        _request: &ZendeskReadRequest,
        _secret: &SecretReference,
    ) -> Result<ZendeskPayload<ZendeskSatisfactionSummary>, ZendeskTransportError> {
        Self::pop(&mut self.satisfaction_responses, self.failure.as_ref())
    }
}

pub type FakeZendeskTransport = RecordingZendeskTransport;
pub type LoopbackZendeskTransport = RecordingZendeskTransport;
pub type BlockedEnvTransport = RecordingZendeskTransport;

#[derive(Clone, Debug)]
pub struct ZendeskProvider<T> {
    transport: T,
    limits: ReadLimits,
}

impl<T: ZendeskTransport> ZendeskProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            limits: ReadLimits::default(),
        }
    }

    pub fn with_limits(transport: T, limits: ReadLimits) -> Result<Self, ZendeskError> {
        Ok(Self {
            transport,
            limits: limits.validate()?,
        })
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn limits(&self) -> &ReadLimits {
        &self.limits
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn ensure_secret(
        scope: &ZendeskSupportScope,
        secret: &SecretReference,
    ) -> Result<(), ZendeskError> {
        if secret.is_revoked() {
            return Err(ZendeskError::SecretRevoked);
        }
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(ZendeskError::SecretScopeMismatch);
        }
        Ok(())
    }

    fn validate_request(
        scope: &ZendeskSupportScope,
        request: &ZendeskReadRequest,
    ) -> Result<(), ZendeskError> {
        if request.ticket_id != scope.ticket.ticket_id {
            return Err(ZendeskError::TicketMismatch);
        }
        if request.ticket_revision != scope.ticket.revision {
            return Err(ZendeskError::RevisionDrift);
        }
        Ok(())
    }

    pub fn describe_account(
        &self,
        scope: &ZendeskSupportScope,
    ) -> Result<ZendeskAccountIdentity, ZendeskError> {
        scope.validate()?;
        Ok(scope.account.clone())
    }

    pub fn read_ticket(
        &mut self,
        scope: &ZendeskSupportScope,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskTicketSnapshot, ZendeskError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let payload = self
            .transport
            .read_ticket(request, secret)
            .map_err(ZendeskError::from_transport)?;
        payload.verify(&self.limits)?;
        if payload.operation != ZendeskOperation::ReadTicket {
            return Err(ZendeskError::MalformedResponse);
        }
        let ticket = payload.value;
        ticket.validate()?;
        if serde_json::to_vec(&ticket.metadata)
            .map_err(|_| ZendeskError::MalformedResponse)?
            .len()
            > self.limits.max_metadata_bytes
        {
            return Err(ZendeskError::ResponseTooLarge);
        }
        Self::validate_ticket_binding(scope, &ticket).map(|()| ticket)
    }

    pub fn read_sla_target(
        &mut self,
        scope: &ZendeskSupportScope,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskSlaTargetSnapshot, ZendeskError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let payload = self
            .transport
            .read_sla_target(request, secret)
            .map_err(ZendeskError::from_transport)?;
        payload.verify(&self.limits)?;
        if payload.operation != ZendeskOperation::ReadSlaTarget {
            return Err(ZendeskError::MalformedResponse);
        }
        let sla = payload.value;
        sla.validate()?;
        if sla.account != scope.account || sla.ticket != scope.ticket || sla.sla != scope.sla {
            return Err(if sla.account.subdomain != scope.account.subdomain {
                ZendeskError::SubdomainMismatch
            } else if sla.account != scope.account {
                ZendeskError::AccountMismatch
            } else if sla.ticket != scope.ticket {
                ZendeskError::TicketMismatch
            } else {
                ZendeskError::SlaMismatch
            });
        }
        Ok(sla)
    }

    pub fn read_metric(
        &mut self,
        scope: &ZendeskSupportScope,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskTicketMetric, ZendeskError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let payload = self
            .transport
            .read_metric(request, secret)
            .map_err(ZendeskError::from_transport)?;
        payload.verify(&self.limits)?;
        if payload.operation != ZendeskOperation::ReadTicketMetric {
            return Err(ZendeskError::MalformedResponse);
        }
        let metric = payload.value;
        metric.validate()?;
        if metric.account != scope.account || metric.ticket != scope.ticket {
            return Err(if metric.account.subdomain != scope.account.subdomain {
                ZendeskError::SubdomainMismatch
            } else if metric.account != scope.account {
                ZendeskError::AccountMismatch
            } else {
                ZendeskError::TicketMismatch
            });
        }
        if metric.metric != scope.metric {
            return Err(if metric.metric.metric_id == scope.metric.metric_id {
                ZendeskError::RevisionDrift
            } else {
                ZendeskError::MetricMismatch
            });
        }
        Ok(metric)
    }

    pub fn read_audit_evidence(
        &mut self,
        scope: &ZendeskSupportScope,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskAuditEvidence, ZendeskError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let incremental = request.incremental_start_time.is_some();
        let mut cursor = None;
        let mut pages_read = 0usize;
        let mut duplicate_events_dropped = 0usize;
        let mut transitions = BTreeMap::<u64, ZendeskAuditTransition>::new();
        let mut cursors = BTreeSet::new();
        loop {
            if pages_read >= self.limits.max_pages {
                return Err(ZendeskError::PaginationLimit);
            }
            let page_request = ZendeskAuditReadRequest {
                ticket_id: request.ticket_id,
                ticket_revision: request.ticket_revision,
                cursor: cursor.clone(),
                incremental_start_time: request.incremental_start_time,
            };
            let page = self
                .transport
                .read_audit_page(&page_request, secret)
                .map_err(ZendeskError::from_transport)?;
            page.verify(&self.limits)?;
            if page.operation != ZendeskOperation::ReadAuditEvents
                || page.page_index != pages_read
                || page.cursor_in != cursor
                || page.incremental != incremental
            {
                return Err(ZendeskError::MalformedResponse);
            }
            for transition in page.items {
                transition.validate()?;
                Self::validate_audit_binding(scope, &transition)?;
                if let Some(existing) = transitions.get(&transition.event_id) {
                    if existing != &transition {
                        return Err(ZendeskError::DuplicateAudit);
                    }
                    duplicate_events_dropped += 1;
                } else {
                    if transitions.len() >= self.limits.max_audit_transitions {
                        return Err(ZendeskError::PaginationLimit);
                    }
                    transitions.insert(transition.event_id, transition);
                }
            }
            pages_read += 1;
            if !page.has_more {
                break;
            }
            let next_cursor = page.next_cursor.ok_or(ZendeskError::MalformedResponse)?;
            if !cursors.insert(next_cursor.clone()) {
                return Err(ZendeskError::PaginationRepeatedCursor);
            }
            cursor = Some(next_cursor);
        }
        ZendeskAuditEvidence::new(
            scope,
            pages_read,
            incremental,
            transitions.into_values().collect(),
            duplicate_events_dropped,
            true,
        )
    }

    pub fn read_satisfaction(
        &mut self,
        scope: &ZendeskSupportScope,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<ZendeskSatisfactionSummary, ZendeskError> {
        scope.validate()?;
        Self::ensure_secret(scope, secret)?;
        Self::validate_request(scope, request)?;
        let payload = self
            .transport
            .read_satisfaction(request, secret)
            .map_err(ZendeskError::from_transport)?;
        payload.verify(&self.limits)?;
        if payload.operation != ZendeskOperation::ReadSatisfaction {
            return Err(ZendeskError::MalformedResponse);
        }
        let satisfaction = payload.value;
        satisfaction.validate()?;
        if satisfaction.account != scope.account {
            return Err(
                if satisfaction.account.subdomain == scope.account.subdomain {
                    ZendeskError::AccountMismatch
                } else {
                    ZendeskError::SubdomainMismatch
                },
            );
        }
        if satisfaction.ticket != scope.ticket {
            return Err(ZendeskError::TicketMismatch);
        }
        if satisfaction.requester != scope.requester {
            return Err(ZendeskError::RequesterMismatch);
        }
        if satisfaction.organization != scope.organization {
            return Err(ZendeskError::OrganizationMismatch);
        }
        if satisfaction.satisfaction_revision != scope.ticket.revision {
            return Err(ZendeskError::RevisionDrift);
        }
        Ok(satisfaction)
    }

    pub fn read_support_components(
        &mut self,
        scope: &ZendeskSupportScope,
        request: &ZendeskReadRequest,
        secret: &SecretReference,
    ) -> Result<SupportEvidenceComponents, ZendeskError> {
        let ticket = self.read_ticket(scope, request, secret)?;
        let sla = self.read_sla_target(scope, request, secret)?;
        let metric = self.read_metric(scope, request, secret)?;
        let audit = self.read_audit_evidence(scope, request, secret)?;
        let satisfaction = self.read_satisfaction(scope, request, secret)?;
        Ok(SupportEvidenceComponents {
            ticket,
            sla,
            metric,
            audit,
            satisfaction,
        })
    }

    fn validate_ticket_binding(
        scope: &ZendeskSupportScope,
        ticket: &ZendeskTicketSnapshot,
    ) -> Result<(), ZendeskError> {
        if ticket.account.subdomain != scope.account.subdomain {
            return Err(ZendeskError::SubdomainMismatch);
        }
        if ticket.account != scope.account {
            return Err(ZendeskError::AccountMismatch);
        }
        if ticket.ticket != scope.ticket {
            return Err(if ticket.ticket.ticket_id == scope.ticket.ticket_id {
                ZendeskError::RevisionDrift
            } else {
                ZendeskError::TicketMismatch
            });
        }
        if ticket.requester != scope.requester {
            return Err(
                if ticket.requester.requester_id == scope.requester.requester_id {
                    ZendeskError::RevisionDrift
                } else {
                    ZendeskError::RequesterMismatch
                },
            );
        }
        if ticket.organization != scope.organization {
            return Err(
                if ticket.organization.organization_id == scope.organization.organization_id {
                    ZendeskError::RevisionDrift
                } else {
                    ZendeskError::OrganizationMismatch
                },
            );
        }
        Ok(())
    }

    fn validate_audit_binding(
        scope: &ZendeskSupportScope,
        transition: &ZendeskAuditTransition,
    ) -> Result<(), ZendeskError> {
        if transition.account.subdomain != scope.account.subdomain {
            return Err(ZendeskError::SubdomainMismatch);
        }
        if transition.account != scope.account {
            return Err(ZendeskError::AccountMismatch);
        }
        if transition.ticket != scope.ticket {
            return Err(if transition.ticket.ticket_id == scope.ticket.ticket_id {
                ZendeskError::RevisionDrift
            } else {
                ZendeskError::TicketMismatch
            });
        }
        if transition.audit_revision != scope.audit.revision {
            return Err(ZendeskError::RevisionDrift);
        }
        if let Some(audit_id) = scope.audit.audit_id
            && transition.audit_id != audit_id
        {
            return Err(ZendeskError::AuditMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupportEvidenceComponents {
    pub ticket: ZendeskTicketSnapshot,
    pub sla: ZendeskSlaTargetSnapshot,
    pub metric: ZendeskTicketMetric,
    pub audit: ZendeskAuditEvidence,
    pub satisfaction: ZendeskSatisfactionSummary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub transport: TransportProvenance,
    pub response_digest: Digest,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub raw_comments_retained: bool,
    pub raw_attachments_retained: bool,
    pub raw_pii_retained: bool,
}

impl EvidenceProvenance {
    fn for_components(
        transport: TransportProvenance,
        ticket: &ZendeskTicketSnapshot,
        sla: &ZendeskSlaTargetSnapshot,
        metric: &ZendeskTicketMetric,
        audit: &ZendeskAuditEvidence,
        satisfaction: &ZendeskSatisfactionSummary,
    ) -> Self {
        Self {
            transport,
            response_digest: Digest::from_serializable(&(
                &ticket.ticket_digest,
                &sla.sla_digest,
                &metric.metric_digest,
                &audit.audit_digest,
                &satisfaction.satisfaction_digest,
            )),
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            raw_comments_retained: false,
            raw_attachments_retained: false,
            raw_pii_retained: false,
        }
    }

    fn validate(&self) -> Result<(), ZendeskError> {
        if !self.recording_only
            || self.connected
            || self.native
            || self.first_party
            || self.raw_comments_retained
            || self.raw_attachments_retained
            || self.raw_pii_retained
        {
            return Err(ZendeskError::RedactionViolation);
        }
        validate_digest(&self.response_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskSupportEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub objective_digest: Digest,
    pub mission: MissionScopeBinding,
    pub observed_at_epoch_seconds: u64,
    pub ticket: ZendeskTicketSnapshot,
    pub sla: ZendeskSlaTargetSnapshot,
    pub metric: ZendeskTicketMetric,
    pub audit: ZendeskAuditEvidence,
    pub satisfaction: ZendeskSatisfactionSummary,
    pub status: ZendeskTicketStatus,
    pub complete: bool,
    pub partial: bool,
    pub pages_read: u16,
    pub ticket_digest: Digest,
    pub sla_digest: Digest,
    pub metric_digest: Digest,
    pub response_time_digest: Digest,
    pub audit_digest: Digest,
    pub satisfaction_digest: Digest,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    objective_digest: &'a Digest,
    mission: &'a MissionScopeBinding,
    observed_at_epoch_seconds: u64,
    ticket: &'a ZendeskTicketSnapshot,
    sla: &'a ZendeskSlaTargetSnapshot,
    metric: &'a ZendeskTicketMetric,
    audit: &'a ZendeskAuditEvidence,
    satisfaction: &'a ZendeskSatisfactionSummary,
    status: ZendeskTicketStatus,
    complete: bool,
    partial: bool,
    pages_read: u16,
    ticket_digest: &'a Digest,
    sla_digest: &'a Digest,
    metric_digest: &'a Digest,
    response_time_digest: &'a Digest,
    audit_digest: &'a Digest,
    satisfaction_digest: &'a Digest,
    provenance: &'a EvidenceProvenance,
}

impl ZendeskSupportEvidence {
    fn new(
        scope: &ZendeskSupportScope,
        registration: &ZendeskRegistration,
        components: SupportEvidenceComponents,
        observed_at_epoch_seconds: u64,
        transport: TransportProvenance,
    ) -> Result<Self, ZendeskError> {
        let provenance = EvidenceProvenance::for_components(
            transport,
            &components.ticket,
            &components.sla,
            &components.metric,
            &components.audit,
            &components.satisfaction,
        );
        let complete = components.audit.complete;
        let evidence = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: scope.scope_digest(),
            registration_digest: registration.registration_digest.clone(),
            objective_digest: scope.objective_digest(),
            mission: scope.mission.clone(),
            observed_at_epoch_seconds,
            ticket: components.ticket,
            sla: components.sla,
            metric: components.metric,
            audit: components.audit,
            satisfaction: components.satisfaction,
            status: ZendeskTicketStatus::Unknown,
            complete,
            partial: !complete,
            pages_read: 0,
            ticket_digest: Digest::from_text("unsealed-ticket-evidence"),
            sla_digest: Digest::from_text("unsealed-sla-evidence"),
            metric_digest: Digest::from_text("unsealed-metric-evidence"),
            response_time_digest: Digest::from_text("unsealed-response-time"),
            audit_digest: Digest::from_text("unsealed-audit-evidence"),
            satisfaction_digest: Digest::from_text("unsealed-satisfaction-evidence"),
            provenance,
            evidence_digest: Digest::from_text("unsealed-evidence"),
        };
        let mut evidence = evidence;
        evidence.status = evidence.ticket.status;
        evidence.pages_read = evidence.audit.pages_read;
        evidence.ticket_digest = evidence.ticket.ticket_digest.clone();
        evidence.sla_digest = evidence.sla.sla_digest.clone();
        evidence.metric_digest = evidence.metric.metric_digest.clone();
        evidence.response_time_digest = evidence.metric.metric_digest.clone();
        evidence.audit_digest = evidence.audit.audit_digest.clone();
        evidence.satisfaction_digest = evidence.satisfaction.satisfaction_digest.clone();
        evidence.evidence_digest = evidence.expected_digest();
        evidence.validate(scope, registration)?;
        Ok(evidence)
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            objective_digest: &self.objective_digest,
            mission: &self.mission,
            observed_at_epoch_seconds: self.observed_at_epoch_seconds,
            ticket: &self.ticket,
            sla: &self.sla,
            metric: &self.metric,
            audit: &self.audit,
            satisfaction: &self.satisfaction,
            status: self.status,
            complete: self.complete,
            partial: self.partial,
            pages_read: self.pages_read,
            ticket_digest: &self.ticket_digest,
            sla_digest: &self.sla_digest,
            metric_digest: &self.metric_digest,
            response_time_digest: &self.response_time_digest,
            audit_digest: &self.audit_digest,
            satisfaction_digest: &self.satisfaction_digest,
            provenance: &self.provenance,
        })
    }

    pub fn validate(
        &self,
        scope: &ZendeskSupportScope,
        registration: &ZendeskRegistration,
    ) -> Result<(), ZendeskError> {
        scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || self.objective_digest != scope.objective_digest()
            || self.mission != scope.mission
            || self.status != self.ticket.status
            || self.partial == self.complete
            || self.pages_read != self.audit.pages_read
            || self.ticket_digest != self.ticket.ticket_digest
            || self.sla_digest != self.sla.sla_digest
            || self.metric_digest != self.metric.metric_digest
            || self.response_time_digest != self.metric.metric_digest
            || self.audit_digest != self.audit.audit_digest
            || self.satisfaction_digest != self.satisfaction.satisfaction_digest
            || !self.evidence_digest.is_valid()
            || self.evidence_digest != self.expected_digest()
        {
            return Err(ZendeskError::EvidenceTampered);
        }
        if self.ticket.account != scope.account {
            return Err(ZendeskError::AccountMismatch);
        }
        if self.ticket.ticket != scope.ticket {
            return Err(ZendeskError::TicketMismatch);
        }
        if self.ticket.requester != scope.requester {
            return Err(ZendeskError::RequesterMismatch);
        }
        if self.ticket.organization != scope.organization {
            return Err(ZendeskError::OrganizationMismatch);
        }
        if self.sla.account != scope.account
            || self.sla.ticket != scope.ticket
            || self.sla.sla != scope.sla
        {
            return Err(ZendeskError::SlaMismatch);
        }
        if self.metric.account != scope.account
            || self.metric.ticket != scope.ticket
            || self.metric.metric != scope.metric
        {
            return Err(ZendeskError::MetricMismatch);
        }
        if self.audit.account != scope.account
            || self.audit.ticket != scope.ticket
            || self.audit.audit != scope.audit
        {
            return Err(ZendeskError::AuditMismatch);
        }
        if self.satisfaction.account != scope.account
            || self.satisfaction.ticket != scope.ticket
            || self.satisfaction.requester != scope.requester
            || self.satisfaction.organization != scope.organization
            || self.satisfaction.satisfaction_revision != scope.ticket.revision
        {
            return Err(ZendeskError::OrganizationMismatch);
        }
        self.ticket.validate()?;
        self.sla.validate()?;
        self.metric.validate()?;
        self.audit.validate()?;
        self.satisfaction.validate()?;
        self.provenance.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportDecisionDisposition {
    ReviewNextMissionDecision,
    Layer2AdoptionRequired,
    BlockedByProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskSupportOutcomeProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub objective_digest: Digest,
    pub mission: MissionScopeBinding,
    pub ticket_id: u64,
    pub ticket_revision: u64,
    pub requester_id: u64,
    pub organization_id: Option<u64>,
    pub status: ZendeskTicketStatus,
    pub priority: ZendeskPriority,
    pub ticket_type: ZendeskTicketType,
    pub sla_state: SlaTargetState,
    pub satisfaction_availability: SatisfactionAvailability,
    pub satisfaction_score: Option<SatisfactionScore>,
    pub ticket_digest: Digest,
    pub metric_digest: Digest,
    pub response_time_digest: Digest,
    pub audit_digest: Digest,
    pub satisfaction_digest: Digest,
    pub evidence_digest: Digest,
    pub decision: SupportDecisionDisposition,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    objective_digest: &'a Digest,
    mission: &'a MissionScopeBinding,
    ticket_id: u64,
    ticket_revision: u64,
    requester_id: u64,
    organization_id: Option<u64>,
    status: ZendeskTicketStatus,
    priority: ZendeskPriority,
    ticket_type: ZendeskTicketType,
    sla_state: SlaTargetState,
    satisfaction_availability: SatisfactionAvailability,
    satisfaction_score: Option<SatisfactionScore>,
    ticket_digest: &'a Digest,
    metric_digest: &'a Digest,
    response_time_digest: &'a Digest,
    audit_digest: &'a Digest,
    satisfaction_digest: &'a Digest,
    evidence_digest: &'a Digest,
    decision: SupportDecisionDisposition,
    adopted: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl ZendeskSupportOutcomeProposal {
    fn from_evidence(evidence: &ZendeskSupportEvidence, scope: &ZendeskSupportScope) -> Self {
        let decision = if !evidence.complete || evidence.status != ZendeskTicketStatus::Solved {
            SupportDecisionDisposition::BlockedByProjection
        } else {
            SupportDecisionDisposition::ReviewNextMissionDecision
        };
        let proposal = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: scope.scope_digest(),
            registration_digest: evidence.registration_digest.clone(),
            objective_digest: scope.objective_digest(),
            mission: scope.mission.clone(),
            ticket_id: evidence.ticket.ticket.ticket_id,
            ticket_revision: evidence.ticket.ticket.revision,
            requester_id: evidence.ticket.requester.requester_id,
            organization_id: evidence.ticket.organization.organization_id,
            status: evidence.status,
            priority: evidence.ticket.priority,
            ticket_type: evidence.ticket.ticket_type,
            sla_state: evidence.sla.state,
            satisfaction_availability: evidence.satisfaction.availability,
            satisfaction_score: evidence.satisfaction.score,
            ticket_digest: evidence.ticket_digest.clone(),
            metric_digest: evidence.metric_digest.clone(),
            response_time_digest: evidence.response_time_digest.clone(),
            audit_digest: evidence.audit_digest.clone(),
            satisfaction_digest: evidence.satisfaction_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            decision,
            adopted: false,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest: Digest::from_text("unsealed-proposal"),
        };
        let mut proposal = proposal;
        proposal.proposal_digest = proposal.expected_digest();
        proposal
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            objective_digest: &self.objective_digest,
            mission: &self.mission,
            ticket_id: self.ticket_id,
            ticket_revision: self.ticket_revision,
            requester_id: self.requester_id,
            organization_id: self.organization_id,
            status: self.status,
            priority: self.priority,
            ticket_type: self.ticket_type,
            sla_state: self.sla_state,
            satisfaction_availability: self.satisfaction_availability,
            satisfaction_score: self.satisfaction_score,
            ticket_digest: &self.ticket_digest,
            metric_digest: &self.metric_digest,
            response_time_digest: &self.response_time_digest,
            audit_digest: &self.audit_digest,
            satisfaction_digest: &self.satisfaction_digest,
            evidence_digest: &self.evidence_digest,
            decision: self.decision,
            adopted: self.adopted,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    fn validate_integrity(
        &self,
        scope: &ZendeskSupportScope,
        registration: &ZendeskRegistration,
    ) -> Result<(), ZendeskError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || self.objective_digest != scope.objective_digest()
            || self.mission != scope.mission
            || self.ticket_id != scope.ticket.ticket_id
            || self.ticket_revision != scope.ticket.revision
            || self.requester_id != scope.requester.requester_id
            || self.organization_id != scope.organization.organization_id
            || self.adopted
            || self.connected
            || self.native
            || self.first_party
            || !self.ticket_digest.is_valid()
            || !self.metric_digest.is_valid()
            || !self.response_time_digest.is_valid()
            || !self.audit_digest.is_valid()
            || !self.satisfaction_digest.is_valid()
            || !self.evidence_digest.is_valid()
            || self.proposal_digest != self.expected_digest()
        {
            return Err(ZendeskError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZendeskSupportRecording {
    pub schema_version: String,
    pub ticket_id: u64,
    pub ticket_revision: u64,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub ticket_digest: Digest,
    pub metric_digest: Digest,
    pub audit_digest: Digest,
    pub satisfaction_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub replayed: bool,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl ZendeskSupportRecording {
    fn new(
        evidence: &ZendeskSupportEvidence,
        registration: &ZendeskRegistration,
        replayed: bool,
    ) -> Self {
        let mut recording = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            ticket_id: evidence.ticket.ticket.ticket_id,
            ticket_revision: evidence.ticket.ticket.revision,
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            ticket_digest: evidence.ticket_digest.clone(),
            metric_digest: evidence.metric_digest.clone(),
            audit_digest: evidence.audit_digest.clone(),
            satisfaction_digest: evidence.satisfaction_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: Digest::from_text("unsealed-recording"),
            replayed,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
        };
        recording.receipt_digest = recording.expected_digest();
        recording
    }

    fn expected_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.schema_version,
            self.ticket_id,
            self.ticket_revision,
            &self.scope_digest,
            &self.registration_digest,
            &self.ticket_digest,
            &self.metric_digest,
            &self.audit_digest,
            &self.satisfaction_digest,
            &self.evidence_digest,
            self.replayed,
            self.durable,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate(
        &self,
        evidence: &ZendeskSupportEvidence,
        registration: &ZendeskRegistration,
    ) -> Result<(), ZendeskError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.ticket_id != evidence.ticket.ticket.ticket_id
            || self.ticket_revision != evidence.ticket.ticket.revision
            || self.scope_digest != evidence.scope_digest
            || self.registration_digest != registration.registration_digest
            || self.ticket_digest != evidence.ticket_digest
            || self.metric_digest != evidence.metric_digest
            || self.audit_digest != evidence.audit_digest
            || self.satisfaction_digest != evidence.satisfaction_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.durable
            || self.connected
            || self.native
            || self.first_party
            || self.receipt_digest != self.expected_digest()
        {
            return Err(ZendeskError::RecordingTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationProjection {
    pub schema_version: String,
    pub ticket_id: u64,
    pub status: ZendeskTicketStatus,
    pub ticket_digest: Digest,
    pub metric_digest: Digest,
    pub response_time_digest: Digest,
    pub audit_digest: Digest,
    pub satisfaction_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub ticket_verified: bool,
    pub metric_verified: bool,
    pub audit_verified: bool,
    pub satisfaction_verified: bool,
    pub registration_verified: bool,
    pub bounded_evidence_verified: bool,
    pub decision: SupportDecisionDisposition,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZendeskServiceDefinition {
    pub schema_version: &'static str,
    pub contract_version: &'static str,
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub layer: u8,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub operations: Vec<ZendeskOperation>,
    pub forbidden_effects: Vec<&'static str>,
    pub allowed_provenance: Vec<TransportProvenance>,
}

impl ZendeskServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA,
            contract_version: CONTRACT_VERSION,
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            layer: 1,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            operations: vec![
                ZendeskOperation::ReadTicket,
                ZendeskOperation::ReadSlaTarget,
                ZendeskOperation::ReadTicketMetric,
                ZendeskOperation::ReadAuditEvents,
                ZendeskOperation::ReadSatisfaction,
            ],
            forbidden_effects: vec![
                "send_ticket_comment",
                "assign_ticket",
                "mutate_ticket_status",
                "create_webhook",
                "retain_raw_comments",
                "retain_raw_attachments",
                "retain_raw_pii",
                "retain_unbounded_audits",
                "own_inbox",
                "send_human_handoff",
                "adopt_kernel_outcome",
                "resolve_native_secret",
            ],
            allowed_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZendeskSupportResultService<T> {
    provider: ZendeskProvider<T>,
    scope: ZendeskSupportScope,
    secret_reference: SecretReference,
    registration: ZendeskRegistration,
    recordings: BTreeMap<u64, Digest>,
    observed_status: BTreeMap<u64, ZendeskTicketStatus>,
}

impl<T: ZendeskTransport> ZendeskSupportResultService<T> {
    pub fn new(
        provider: ZendeskProvider<T>,
        scope: ZendeskSupportScope,
        secret_reference: SecretReference,
    ) -> Result<Self, ZendeskError> {
        scope.validate()?;
        let registration = ZendeskRegistration::new(&scope, &secret_reference)?;
        Ok(Self {
            provider,
            scope,
            secret_reference,
            registration,
            recordings: BTreeMap::new(),
            observed_status: BTreeMap::new(),
        })
    }

    pub fn from_transport(
        scope: ZendeskSupportScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ZendeskError> {
        Self::new(ZendeskProvider::new(transport), scope, secret_reference)
    }

    pub fn definition() -> ZendeskServiceDefinition {
        ZendeskServiceDefinition::layer1()
    }

    pub fn scope(&self) -> &ZendeskSupportScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &ZendeskRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &ZendeskProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut ZendeskProvider<T> {
        &mut self.provider
    }

    pub fn describe_account(&self) -> Result<ZendeskAccountIdentity, ZendeskError> {
        self.ensure_active()?;
        self.provider.describe_account(&self.scope)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn read_support_evidence(
        &mut self,
        request: ZendeskReadRequest,
    ) -> Result<ZendeskSupportEvidence, ZendeskError> {
        self.ensure_active()?;
        if request.ticket_id != self.scope.ticket.ticket_id {
            return Err(ZendeskError::TicketMismatch);
        }
        if request.ticket_revision != self.scope.ticket.revision {
            return Err(ZendeskError::RevisionDrift);
        }
        let components =
            self.provider
                .read_support_components(&self.scope, &request, &self.secret_reference)?;
        if let Some(previous) = self.observed_status.get(&request.ticket_id)
            && !previous.can_follow(components.ticket.status)
        {
            return Err(ZendeskError::InvalidStateTransition);
        }
        let evidence = ZendeskSupportEvidence::new(
            &self.scope,
            &self.registration,
            components,
            request.observed_at_epoch_seconds,
            self.provider.provenance(),
        )?;
        self.observed_status
            .insert(request.ticket_id, evidence.status);
        Ok(evidence)
    }

    pub fn read_ticket_evidence(
        &mut self,
        request: ZendeskReadRequest,
    ) -> Result<ZendeskSupportEvidence, ZendeskError> {
        self.read_support_evidence(request)
    }

    pub fn read_support_result(
        &mut self,
        request: ZendeskReadRequest,
    ) -> Result<ZendeskSupportEvidence, ZendeskError> {
        self.read_support_evidence(request)
    }

    pub fn compile_support_outcome_proposal(
        &self,
        evidence: &ZendeskSupportEvidence,
    ) -> Result<ZendeskSupportOutcomeProposal, ZendeskError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)?;
        Ok(ZendeskSupportOutcomeProposal::from_evidence(
            evidence,
            &self.scope,
        ))
    }

    pub fn compile_support_result_proposal(
        &self,
        evidence: &ZendeskSupportEvidence,
    ) -> Result<ZendeskSupportOutcomeProposal, ZendeskError> {
        self.compile_support_outcome_proposal(evidence)
    }

    pub fn record_support_receipt(
        &mut self,
        evidence: &ZendeskSupportEvidence,
    ) -> Result<ZendeskSupportRecording, ZendeskError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)?;
        let ticket_id = evidence.ticket.ticket.ticket_id;
        if let Some(existing) = self.recordings.get(&ticket_id) {
            if existing != &evidence.evidence_digest {
                return Err(ZendeskError::DuplicateTicket);
            }
            return Ok(ZendeskSupportRecording::new(
                evidence,
                &self.registration,
                true,
            ));
        }
        self.recordings
            .insert(ticket_id, evidence.evidence_digest.clone());
        Ok(ZendeskSupportRecording::new(
            evidence,
            &self.registration,
            false,
        ))
    }

    pub fn record_support_result(
        &mut self,
        evidence: &ZendeskSupportEvidence,
    ) -> Result<ZendeskSupportRecording, ZendeskError> {
        self.record_support_receipt(evidence)
    }

    pub fn verify_support_evidence(
        &self,
        evidence: &ZendeskSupportEvidence,
    ) -> Result<VerificationProjection, ZendeskError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)?;
        let proposal = ZendeskSupportOutcomeProposal::from_evidence(evidence, &self.scope);
        proposal.validate_integrity(&self.scope, &self.registration)?;
        Ok(VerificationProjection {
            schema_version: CONTRACT_SCHEMA.into(),
            ticket_id: evidence.ticket.ticket.ticket_id,
            status: evidence.status,
            ticket_digest: evidence.ticket_digest.clone(),
            metric_digest: evidence.metric_digest.clone(),
            response_time_digest: evidence.response_time_digest.clone(),
            audit_digest: evidence.audit_digest.clone(),
            satisfaction_digest: evidence.satisfaction_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            ticket_verified: evidence.ticket_digest == evidence.ticket.ticket_digest,
            metric_verified: evidence.metric_digest == evidence.metric.metric_digest,
            audit_verified: evidence.audit_digest == evidence.audit.audit_digest,
            satisfaction_verified: evidence.satisfaction_digest
                == evidence.satisfaction.satisfaction_digest,
            registration_verified: evidence.registration_digest
                == self.registration.registration_digest,
            bounded_evidence_verified: evidence.complete,
            decision: if evidence.complete {
                SupportDecisionDisposition::Layer2AdoptionRequired
            } else {
                SupportDecisionDisposition::BlockedByProjection
            },
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn verify_support_result(
        &self,
        evidence: &ZendeskSupportEvidence,
    ) -> Result<VerificationProjection, ZendeskError> {
        self.verify_support_evidence(evidence)
    }

    pub fn projection_for_error(&self, error: &ZendeskError) -> ZendeskTicketStatus {
        error.projection()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence, ZendeskError> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence, ZendeskError> {
        if self.secret_reference.is_revoked() {
            return Err(ZendeskError::SecretRevoked);
        }
        self.registration.remount()
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt, ZendeskError> {
        self.registration.revoke(&mut self.secret_reference)
    }

    fn ensure_active(&self) -> Result<(), ZendeskError> {
        if self.secret_reference.is_revoked() {
            return Err(ZendeskError::SecretRevoked);
        }
        if !self.registration.is_active() {
            return Err(ZendeskError::RegistrationInactive);
        }
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConsumptionDisposition {
    Fresh,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionZendeskSupport {
    pub schema_version: String,
    pub scope_digest: Digest,
    pub objective_digest: Digest,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub ticket_id: u64,
    pub ticket_revision: u64,
    pub status: ZendeskTicketStatus,
    pub proposal_digest: Digest,
    pub disposition: MissionConsumptionDisposition,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub struct MissionZendeskSupportConsumer {
    binding: MissionScopeBinding,
    objective_digest: Digest,
    scope_digest: Digest,
    ticket_id: u64,
    ticket_revision: u64,
    consumed: BTreeMap<u64, Digest>,
    active: bool,
}

impl fmt::Debug for MissionZendeskSupportConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionZendeskSupportConsumer")
            .field("binding", &self.binding)
            .field("scope_digest", &self.scope_digest)
            .field("objective_digest", &self.objective_digest)
            .field("ticket_id", &self.ticket_id)
            .field("ticket_revision", &self.ticket_revision)
            .field("consumed_count", &self.consumed.len())
            .field("active", &self.active)
            .finish()
    }
}

impl MissionZendeskSupportConsumer {
    pub fn new(scope: &ZendeskSupportScope) -> Result<Self, ZendeskError> {
        scope.validate()?;
        Ok(Self {
            binding: scope.mission.clone(),
            objective_digest: scope.objective_digest(),
            scope_digest: scope.scope_digest(),
            ticket_id: scope.ticket.ticket_id,
            ticket_revision: scope.ticket.revision,
            consumed: BTreeMap::new(),
            active: true,
        })
    }

    pub fn binding(&self) -> &MissionScopeBinding {
        &self.binding
    }

    pub fn unmount(&mut self) {
        self.active = false;
    }

    pub fn remount(&mut self) {
        self.active = true;
    }

    pub fn revoke(&mut self) {
        self.active = false;
    }

    pub fn consume(
        &mut self,
        proposal: &ZendeskSupportOutcomeProposal,
    ) -> Result<MissionZendeskSupport, ZendeskError> {
        if !self.active {
            return Err(ZendeskError::ConsumerInactive);
        }
        if proposal.scope_digest != self.scope_digest
            || proposal.objective_digest != self.objective_digest
            || proposal.ticket_id != self.ticket_id
            || proposal.ticket_revision != self.ticket_revision
        {
            if proposal.mission.project_id == self.binding.project_id
                && proposal.mission.mission_id == self.binding.mission_id
                && proposal.mission.work_product_id == self.binding.work_product_id
            {
                return Err(ZendeskError::StaleMissionRevision);
            }
            return Err(ZendeskError::MissionScopeMismatch);
        }
        if proposal.mission != self.binding {
            if proposal.mission.project_id == self.binding.project_id
                && proposal.mission.mission_id == self.binding.mission_id
                && proposal.mission.work_product_id == self.binding.work_product_id
            {
                return Err(ZendeskError::StaleMissionRevision);
            }
            return Err(ZendeskError::MissionScopeMismatch);
        }
        let disposition = match self.consumed.get(&proposal.ticket_id) {
            None => {
                self.consumed
                    .insert(proposal.ticket_id, proposal.proposal_digest.clone());
                MissionConsumptionDisposition::Fresh
            }
            Some(existing) if existing == &proposal.proposal_digest => {
                MissionConsumptionDisposition::Replay
            }
            Some(_) => return Err(ZendeskError::DuplicateTicket),
        };
        Ok(MissionZendeskSupport {
            schema_version: CONTRACT_SCHEMA.into(),
            scope_digest: self.scope_digest.clone(),
            objective_digest: self.objective_digest.clone(),
            project_id: self.binding.project_id.clone(),
            mission_id: self.binding.mission_id.clone(),
            work_product_id: self.binding.work_product_id.clone(),
            project_revision: self.binding.project_revision,
            mission_revision: self.binding.mission_revision,
            work_product_revision: self.binding.work_product_revision,
            ticket_id: proposal.ticket_id,
            ticket_revision: proposal.ticket_revision,
            status: proposal.status,
            proposal_digest: proposal.proposal_digest.clone(),
            disposition,
            adopted: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn contract_constants_are_layer_one_and_non_native() {
        assert_eq!(CONTRACT_SCHEMA, "hartevo.zendesk-support-result/v1");
        assert_eq!(CONTRACT_VERSION, "EXT-ZENDESK-01-L1/v1");
        assert!(!TransportProvenance::Recording.connected());
        assert!(!TransportProvenance::Loopback.native());
        assert!(!TransportProvenance::Fake.first_party());
        assert!(serde_json::from_str::<serde_json::Value>(CONTRACT_JSON).is_ok());
    }
}
