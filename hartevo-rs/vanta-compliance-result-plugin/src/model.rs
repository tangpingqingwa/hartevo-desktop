//! Typed Vanta scope, normalized evidence, registration, and proposal models.
//!
//! Provider payloads are intentionally absent from these types. The only
//! provider data retained by Layer 1 is bounded status metadata, identifiers
//! already present in the allowlisted scope, and cryptographic digests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    VANTA_CONTRACT_VERSION, VANTA_MAX_PAGES, VANTA_MAX_RESPONSE_BYTES, VANTA_PAGE_SIZE,
    VANTA_PLUGIN_VERSION_TEXT, VANTA_PROVIDER_ID, VANTA_PROVIDER_REVISION_TEXT,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_SCOPE_IDS: usize = 128;
pub const MAX_AUDITS: usize = 16;
pub const MAX_CONTROLS: usize = 128;
pub const MAX_TESTS: usize = 256;
pub const MAX_ISSUES: usize = 128;
pub const MAX_INFORMATION_REQUESTS: usize = 128;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VantaModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported whitespace")]
    InvalidWhitespace { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} exceeds the bounded list size")]
    TooMany { field: &'static str },
    #[error("cannot serialize canonical Vanta value: {0}")]
    Serialization(String),
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), VantaModelError> {
    if value.is_empty() {
        return Err(VantaModelError::Empty { field });
    }
    if value.len() > max {
        return Err(VantaModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(VantaModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(VantaModelError::InvalidWhitespace { field });
    }
    if value.chars().any(|character| {
        !(character.is_ascii_alphanumeric()
            || "-_.:".contains(character)
            || allow_internal_whitespace && character.is_whitespace())
    }) {
        return Err(VantaModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), VantaModelError> {
    if value == 0 {
        Err(VantaModelError::MustBePositive { field })
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
            pub fn new(value: impl Into<String>) -> Result<Self, VantaModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES, false)?;
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
            type Err = VantaModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_identifier!(TenantId, "tenant id");
bounded_identifier!(Region, "region");
bounded_identifier!(AuditId, "audit id");
bounded_identifier!(ControlId, "control id");
bounded_identifier!(TestId, "test id");
bounded_identifier!(IssueId, "issue id");
bounded_identifier!(InformationRequestId, "information request id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(ComplianceObjectiveId, "compliance objective id");
bounded_identifier!(ConsentId, "consent id");
bounded_identifier!(ProviderRevision, "provider revision");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FrameworkId(String);

impl FrameworkId {
    pub fn new(value: impl Into<String>) -> Result<Self, VantaModelError> {
        let value = value.into();
        validate_text(&value, "framework id", MAX_IDENTIFIER_BYTES, true)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FrameworkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FrameworkId").field(&self.0).finish()
    }
}

impl fmt::Display for FrameworkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for FrameworkId {
    type Err = VantaModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

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

    pub fn parse(value: impl Into<String>) -> Result<Self, VantaModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(VantaModelError::InvalidDigest { field: "digest" });
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
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

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, VantaModelError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| VantaModelError::Serialization(error.to_string()))?;
    Ok(sha256_digest(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, VantaModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An opaque, digest-only handle. The supplied reference value is never
/// retained, serialized, displayed, or passed to a transport.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
}

impl SecretReference {
    pub fn new(value: impl AsRef<str>) -> Result<Self, VantaModelError> {
        let value = value.as_ref();
        validate_text(value, "secret reference", MAX_IDENTIFIER_BYTES, false)?;
        Ok(Self {
            digest: sha256_digest(format!("hartevo-vanta-secret:{value}").as_bytes()),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub id: ConsentId,
    pub revision: Revision,
    pub digest: Digest,
}

impl ConsentBinding {
    pub fn new(id: ConsentId, revision: Revision, digest: Digest) -> Self {
        Self {
            id,
            revision,
            digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditBinding {
    pub id: AuditId,
    pub framework_id: FrameworkId,
    pub revision: Revision,
}

impl AuditBinding {
    pub fn new(id: AuditId, framework_id: FrameworkId, revision: Revision) -> Self {
        Self {
            id,
            framework_id,
            revision,
        }
    }

    pub fn digest(&self) -> Result<Digest, VantaModelError> {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComplianceObjective {
    pub id: ComplianceObjectiveId,
    pub revision: Revision,
}

impl ComplianceObjective {
    pub fn new(id: ComplianceObjectiveId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VantaApiFamily {
    Manage,
    Audit,
    ManageAndAudit,
}

impl VantaApiFamily {
    pub const fn allows_manage(self) -> bool {
        matches!(self, Self::Manage | Self::ManageAndAudit)
    }

    pub const fn allows_audit(self) -> bool {
        matches!(self, Self::Audit | Self::ManageAndAudit)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VantaComplianceState {
    Complete,
    Open,
    Overdue,
    Blocked,
    Partial,
    RetentionGap,
    AccessLoss,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VantaRecordKind {
    Audits,
    Controls,
    Tests,
    Issues,
    InformationRequests,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum VantaEndpoint {
    ListAudits { audit_id: AuditId },
    ListControls { audit_id: AuditId },
    ListTests { audit_id: AuditId },
    ListIssues { audit_id: AuditId },
    ListInformationRequests { audit_id: AuditId },
}

impl VantaEndpoint {
    pub fn audit_id(&self) -> &AuditId {
        match self {
            Self::ListAudits { audit_id }
            | Self::ListControls { audit_id }
            | Self::ListTests { audit_id }
            | Self::ListIssues { audit_id }
            | Self::ListInformationRequests { audit_id } => audit_id,
        }
    }

    pub const fn family(&self) -> VantaApiFamily {
        match self {
            Self::ListAudits { .. }
            | Self::ListControls { .. }
            | Self::ListIssues { .. }
            | Self::ListInformationRequests { .. } => VantaApiFamily::Audit,
            Self::ListTests { .. } => VantaApiFamily::Manage,
        }
    }

    pub const fn kind(&self) -> VantaRecordKind {
        match self {
            Self::ListAudits { .. } => VantaRecordKind::Audits,
            Self::ListControls { .. } => VantaRecordKind::Controls,
            Self::ListTests { .. } => VantaRecordKind::Tests,
            Self::ListIssues { .. } => VantaRecordKind::Issues,
            Self::ListInformationRequests { .. } => VantaRecordKind::InformationRequests,
        }
    }

    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::ListAudits { .. } => "list_audits",
            Self::ListControls { .. } => "list_controls",
            Self::ListTests { .. } => "list_tests",
            Self::ListIssues { .. } => "list_issues",
            Self::ListInformationRequests { .. } => "list_information_requests",
        }
    }

    pub fn path_and_query(
        &self,
        page_size: u16,
        cursor: Option<&OpaqueCursor>,
    ) -> Result<String, VantaModelError> {
        if page_size == 0 || page_size > VANTA_PAGE_SIZE {
            return Err(VantaModelError::Invalid { field: "page size" });
        }
        let path = match self {
            Self::ListAudits { .. } => "/v1/audits".to_owned(),
            Self::ListControls { audit_id } => format!("/v1/audits/{}/controls", audit_id.as_str()),
            Self::ListTests { .. } => "/v1/tests".to_owned(),
            Self::ListIssues { audit_id } => {
                format!("/v1/audits/{}/issues/items", audit_id.as_str())
            }
            Self::ListInformationRequests { audit_id } => {
                format!("/v1/audits/{}/information-requests", audit_id.as_str())
            }
        };
        let mut result = format!("{path}?pageSize={page_size}");
        if let Some(cursor) = cursor {
            result.push_str("&pageCursor=");
            result.push_str(cursor.as_str());
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueCursor(String);

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, VantaModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CURSOR_BYTES
            || value.chars().any(char::is_control)
            || value.chars().any(char::is_whitespace)
            || value
                .chars()
                .any(|character| !character.is_ascii_alphanumeric() && !"._~-".contains(character))
        {
            return Err(VantaModelError::InvalidCursor { field: "cursor" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaReadRequest {
    pub endpoint: VantaEndpoint,
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub observed_at: DateTime<Utc>,
}

impl VantaReadRequest {
    pub fn new(
        endpoint: VantaEndpoint,
        scope_digest: Digest,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, VantaModelError> {
        if page_size == 0 || page_size > VANTA_PAGE_SIZE {
            return Err(VantaModelError::Invalid { field: "page size" });
        }
        if max_pages == 0 || max_pages > VANTA_MAX_PAGES {
            return Err(VantaModelError::Invalid { field: "max pages" });
        }
        Ok(Self {
            endpoint,
            scope_digest,
            page_size,
            max_pages,
            max_response_bytes: VANTA_MAX_RESPONSE_BYTES,
            observed_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaProviderIdentity {
    pub id: String,
    pub version: String,
    pub revision: ProviderRevision,
    pub digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaAuditRecord {
    pub audit_id: AuditId,
    pub framework_id: FrameworkId,
    pub revision: Revision,
    pub state: VantaComplianceState,
}

impl VantaAuditRecord {
    pub fn new(
        audit_id: AuditId,
        framework_id: FrameworkId,
        revision: Revision,
        state: VantaComplianceState,
    ) -> Self {
        Self {
            audit_id,
            framework_id,
            revision,
            state,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaControlRecord {
    pub audit_id: AuditId,
    pub control_id: ControlId,
    pub revision: Revision,
    pub state: VantaComplianceState,
}

impl VantaControlRecord {
    pub fn new(
        audit_id: AuditId,
        control_id: ControlId,
        revision: Revision,
        state: VantaComplianceState,
    ) -> Self {
        Self {
            audit_id,
            control_id,
            revision,
            state,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaTestRecord {
    pub audit_id: AuditId,
    pub test_id: TestId,
    pub control_id: Option<ControlId>,
    pub revision: Revision,
    pub state: VantaComplianceState,
}

impl VantaTestRecord {
    pub fn new(
        audit_id: AuditId,
        test_id: TestId,
        control_id: Option<ControlId>,
        revision: Revision,
        state: VantaComplianceState,
    ) -> Self {
        Self {
            audit_id,
            test_id,
            control_id,
            revision,
            state,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaIssueRecord {
    pub audit_id: AuditId,
    pub issue_id: IssueId,
    pub control_id: Option<ControlId>,
    pub revision: Revision,
    pub state: VantaComplianceState,
}

impl VantaIssueRecord {
    pub fn new(
        audit_id: AuditId,
        issue_id: IssueId,
        control_id: Option<ControlId>,
        revision: Revision,
        state: VantaComplianceState,
    ) -> Self {
        Self {
            audit_id,
            issue_id,
            control_id,
            revision,
            state,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaInformationRequestRecord {
    pub audit_id: AuditId,
    pub information_request_id: InformationRequestId,
    pub control_id: Option<ControlId>,
    pub revision: Revision,
    pub state: VantaComplianceState,
}

impl VantaInformationRequestRecord {
    pub fn new(
        audit_id: AuditId,
        information_request_id: InformationRequestId,
        control_id: Option<ControlId>,
        revision: Revision,
        state: VantaComplianceState,
    ) -> Self {
        Self {
            audit_id,
            information_request_id,
            control_id,
            revision,
            state,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "items", rename_all = "snake_case")]
pub enum VantaResponseBody {
    Audits(Vec<VantaAuditRecord>),
    Controls(Vec<VantaControlRecord>),
    Tests(Vec<VantaTestRecord>),
    Issues(Vec<VantaIssueRecord>),
    InformationRequests(Vec<VantaInformationRequestRecord>),
}

impl VantaResponseBody {
    pub const fn kind(&self) -> VantaRecordKind {
        match self {
            Self::Audits(_) => VantaRecordKind::Audits,
            Self::Controls(_) => VantaRecordKind::Controls,
            Self::Tests(_) => VantaRecordKind::Tests,
            Self::Issues(_) => VantaRecordKind::Issues,
            Self::InformationRequests(_) => VantaRecordKind::InformationRequests,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Audits(items) => items.len(),
            Self::Controls(items) => items.len(),
            Self::Tests(items) => items.len(),
            Self::Issues(items) => items.len(),
            Self::InformationRequests(items) => items.len(),
        }
    }

    pub const fn is_empty(&self) -> bool {
        match self {
            Self::Audits(items) => items.is_empty(),
            Self::Controls(items) => items.is_empty(),
            Self::Tests(items) => items.is_empty(),
            Self::Issues(items) => items.is_empty(),
            Self::InformationRequests(items) => items.is_empty(),
        }
    }

    pub fn validate(&self) -> Result<(), VantaModelError> {
        let (length, maximum, field) = match self {
            Self::Audits(items) => (items.len(), MAX_AUDITS, "audits"),
            Self::Controls(items) => (items.len(), MAX_CONTROLS, "controls"),
            Self::Tests(items) => (items.len(), MAX_TESTS, "tests"),
            Self::Issues(items) => (items.len(), MAX_ISSUES, "issues"),
            Self::InformationRequests(items) => (
                items.len(),
                MAX_INFORMATION_REQUESTS,
                "information requests",
            ),
        };
        if length > maximum {
            Err(VantaModelError::TooMany { field })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaResponseReceipt {
    pub request_digest: Digest,
    pub endpoint: VantaEndpoint,
    pub status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub normalized_body_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub next_cursor_present: bool,
    pub raw_provider_payload_retained: bool,
    pub owners_redacted: bool,
    pub evidence_urls_redacted: bool,
    pub comments_redacted: bool,
    pub document_bodies_redacted: bool,
    pub credential_material_retained: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaReadEvidence {
    pub endpoint: VantaEndpoint,
    pub scope_digest: Digest,
    pub pages: Vec<VantaResponseBody>,
    pub receipts: Vec<VantaResponseReceipt>,
    pub page_count: u16,
    pub page_limit_reached: bool,
    pub provenance: TransportProvenance,
    pub provider_revision: ProviderRevision,
    pub evidence_digest: Digest,
}

impl VantaReadEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: VantaEndpoint,
        scope_digest: Digest,
        pages: Vec<VantaResponseBody>,
        receipts: Vec<VantaResponseReceipt>,
        page_limit_reached: bool,
        provenance: TransportProvenance,
        provider_revision: ProviderRevision,
    ) -> Result<Self, VantaModelError> {
        let page_count =
            u16::try_from(pages.len()).map_err(|_| VantaModelError::TooMany { field: "pages" })?;
        let mut evidence = Self {
            endpoint,
            scope_digest,
            pages,
            receipts,
            page_count,
            page_limit_reached,
            provenance,
            provider_revision,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recompute_digest()?;
        Ok(evidence)
    }

    pub fn recompute_digest(&self) -> Result<Digest, VantaModelError> {
        digest_serializable(&(
            &self.endpoint,
            &self.scope_digest,
            &self.pages,
            &self.receipts,
            self.page_count,
            self.page_limit_reached,
            self.provenance,
            &self.provider_revision,
        ))
    }

    pub fn validate(&self) -> Result<(), VantaModelError> {
        if self.pages.len() != usize::from(self.page_count)
            || self.receipts.len() != self.pages.len()
            || self.page_count == 0
            || self.page_count > VANTA_MAX_PAGES
            || self
                .pages
                .iter()
                .any(|page| page.kind() != self.endpoint.kind())
            || self
                .pages
                .iter()
                .zip(&self.receipts)
                .any(|(page, receipt)| {
                    receipt.endpoint != self.endpoint
                        || receipt.status != 200
                        || receipt.response_size > VANTA_MAX_RESPONSE_BYTES
                        || receipt.provider_revision != self.provider_revision
                        || receipt.raw_provider_payload_retained
                        || !receipt.owners_redacted
                        || !receipt.evidence_urls_redacted
                        || !receipt.comments_redacted
                        || !receipt.document_bodies_redacted
                        || receipt.credential_material_retained
                        || receipt.normalized_body_digest
                            != digest_serializable(page).unwrap_or_else(|_| Digest::zero())
                })
            || self.evidence_digest != self.recompute_digest().unwrap_or_else(|_| Digest::zero())
        {
            return Err(VantaModelError::Invalid {
                field: "Vanta read evidence",
            });
        }
        let total_items = self.pages.iter().map(VantaResponseBody::len).sum::<usize>();
        let max_items = match self.endpoint.kind() {
            VantaRecordKind::Audits => MAX_AUDITS,
            VantaRecordKind::Controls => MAX_CONTROLS,
            VantaRecordKind::Tests => MAX_TESTS,
            VantaRecordKind::Issues => MAX_ISSUES,
            VantaRecordKind::InformationRequests => MAX_INFORMATION_REQUESTS,
        };
        if total_items > max_items {
            return Err(VantaModelError::TooMany {
                field: "provider records",
            });
        }
        Ok(())
    }

    pub fn validate_scope(&self, scope: &VantaComplianceScope) -> Result<(), VantaModelError> {
        self.validate()?;
        if self.scope_digest != scope.digest()
            || self.endpoint.audit_id() != &scope.audit.id
            || !scope.api_family.allows(self.endpoint.family())
        {
            return Err(VantaModelError::Invalid {
                field: "scope fence",
            });
        }
        for page in &self.pages {
            match page {
                VantaResponseBody::Audits(items) => {
                    for item in items {
                        if item.audit_id != scope.audit.id
                            || item.framework_id != scope.audit.framework_id
                            || item.revision != scope.audit.revision
                        {
                            return Err(VantaModelError::Invalid {
                                field: "audit fence",
                            });
                        }
                    }
                }
                VantaResponseBody::Controls(items) => {
                    for item in items {
                        if item.audit_id != scope.audit.id
                            || scope.control_revisions.get(&item.control_id) != Some(&item.revision)
                        {
                            return Err(VantaModelError::Invalid {
                                field: "control fence",
                            });
                        }
                    }
                }
                VantaResponseBody::Tests(items) => {
                    for item in items {
                        if item.audit_id != scope.audit.id
                            || scope.test_revisions.get(&item.test_id) != Some(&item.revision)
                            || item
                                .control_id
                                .as_ref()
                                .is_some_and(|id| !scope.controls.contains(id))
                        {
                            return Err(VantaModelError::Invalid {
                                field: "test fence",
                            });
                        }
                    }
                }
                VantaResponseBody::Issues(items) => {
                    for item in items {
                        if item.audit_id != scope.audit.id
                            || scope.issue_revisions.get(&item.issue_id) != Some(&item.revision)
                            || item
                                .control_id
                                .as_ref()
                                .is_some_and(|id| !scope.controls.contains(id))
                        {
                            return Err(VantaModelError::Invalid {
                                field: "issue fence",
                            });
                        }
                    }
                }
                VantaResponseBody::InformationRequests(items) => {
                    for item in items {
                        if item.audit_id != scope.audit.id
                            || scope
                                .information_request_revisions
                                .get(&item.information_request_id)
                                != Some(&item.revision)
                            || item
                                .control_id
                                .as_ref()
                                .is_some_and(|id| !scope.controls.contains(id))
                        {
                            return Err(VantaModelError::Invalid {
                                field: "information request fence",
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VantaReadFailureKind {
    BlockedEnv,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaReadFailure {
    pub endpoint: VantaEndpoint,
    pub state: VantaComplianceState,
    pub kind: VantaReadFailureKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaEvidenceBundle {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub reads: Vec<VantaReadEvidence>,
    pub failures: Vec<VantaReadFailure>,
    pub provenance: TransportProvenance,
    pub bundle_digest: Digest,
}

impl VantaEvidenceBundle {
    pub fn new(
        scope: &VantaComplianceScope,
        registration_digest: Digest,
        provider: &VantaProviderIdentity,
        reads: Vec<VantaReadEvidence>,
        failures: Vec<VantaReadFailure>,
        provenance: TransportProvenance,
    ) -> Result<Self, VantaModelError> {
        let mut bundle = Self {
            scope_digest: scope.digest(),
            registration_digest,
            provider_digest: provider.digest.clone(),
            provider_revision: provider.revision.clone(),
            reads,
            failures,
            provenance,
            bundle_digest: Digest::zero(),
        };
        bundle.bundle_digest = bundle.recompute_digest()?;
        Ok(bundle)
    }

    pub fn recompute_digest(&self) -> Result<Digest, VantaModelError> {
        digest_serializable(&(
            &self.scope_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.provider_revision,
            &self.reads,
            &self.failures,
            self.provenance,
        ))
    }

    pub fn validate(&self, scope: &VantaComplianceScope) -> Result<(), VantaModelError> {
        if self.scope_digest != scope.digest()
            || self.bundle_digest != self.recompute_digest()?
            || self
                .reads
                .iter()
                .any(|read| read.validate_scope(scope).is_err())
        {
            return Err(VantaModelError::Invalid {
                field: "evidence bundle",
            });
        }
        let mut endpoints = BTreeSet::new();
        for read in &self.reads {
            if !endpoints.insert(read.endpoint.operation_name()) {
                return Err(VantaModelError::Invalid {
                    field: "duplicate evidence endpoint",
                });
            }
        }
        for failure in &self.failures {
            if failure.endpoint.audit_id() != &scope.audit.id
                || !scope.api_family.allows(failure.endpoint.family())
                || !scope
                    .expected_endpoints()
                    .iter()
                    .any(|expected| expected.operation_name() == failure.endpoint.operation_name())
                || !endpoints.insert(failure.endpoint.operation_name())
            {
                return Err(VantaModelError::Invalid {
                    field: "duplicate evidence endpoint",
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaComplianceScope {
    pub tenant: TenantId,
    pub region: Region,
    pub api_family: VantaApiFamily,
    pub audit: AuditBinding,
    pub controls: Vec<ControlId>,
    pub tests: Vec<TestId>,
    pub issues: Vec<IssueId>,
    pub information_requests: Vec<InformationRequestId>,
    pub control_revisions: BTreeMap<ControlId, Revision>,
    pub test_revisions: BTreeMap<TestId, Revision>,
    pub issue_revisions: BTreeMap<IssueId, Revision>,
    pub information_request_revisions: BTreeMap<InformationRequestId, Revision>,
    pub objective: ComplianceObjective,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub consent: ConsentBinding,
    pub permission_digest: Digest,
}

impl VantaComplianceScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        region: Region,
        api_family: VantaApiFamily,
        audit: AuditBinding,
        controls: impl IntoIterator<Item = ControlId>,
        tests: impl IntoIterator<Item = TestId>,
        issues: impl IntoIterator<Item = IssueId>,
        information_requests: impl IntoIterator<Item = InformationRequestId>,
        objective: ComplianceObjective,
        mission: MissionBinding,
        project: ProjectBinding,
        consent: ConsentBinding,
        permission_digest: Digest,
    ) -> Result<Self, VantaModelError> {
        let controls = canonical_ids(controls, "controls")?;
        let tests = canonical_ids(tests, "tests")?;
        let issues = canonical_ids(issues, "issues")?;
        let information_requests = canonical_ids(information_requests, "information requests")?;
        let control_revisions = default_revision_fences(&controls)?;
        let test_revisions = default_revision_fences(&tests)?;
        let issue_revisions = default_revision_fences(&issues)?;
        let information_request_revisions = default_revision_fences(&information_requests)?;
        let scope = Self {
            tenant,
            region,
            api_family,
            audit,
            controls,
            tests,
            issues,
            information_requests,
            control_revisions,
            test_revisions,
            issue_revisions,
            information_request_revisions,
            objective,
            mission,
            project,
            consent,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Replace the default revision-1 fences with exact provider revisions.
    /// Every supplied map must cover only the corresponding allowlist.
    pub fn with_revision_fences(
        &mut self,
        control_revisions: impl IntoIterator<Item = (ControlId, Revision)>,
        test_revisions: impl IntoIterator<Item = (TestId, Revision)>,
        issue_revisions: impl IntoIterator<Item = (IssueId, Revision)>,
        information_request_revisions: impl IntoIterator<Item = (InformationRequestId, Revision)>,
    ) -> Result<(), VantaModelError> {
        self.control_revisions = revision_fences(control_revisions, "control revisions")?;
        self.test_revisions = revision_fences(test_revisions, "test revisions")?;
        self.issue_revisions = revision_fences(issue_revisions, "issue revisions")?;
        self.information_request_revisions = revision_fences(
            information_request_revisions,
            "information request revisions",
        )?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), VantaModelError> {
        if self.controls.len() > MAX_SCOPE_IDS
            || self.tests.len() > MAX_SCOPE_IDS
            || self.issues.len() > MAX_SCOPE_IDS
            || self.information_requests.len() > MAX_SCOPE_IDS
        {
            return Err(VantaModelError::TooMany { field: "scope ids" });
        }
        validate_revision_keys(&self.controls, &self.control_revisions, "control revisions")?;
        validate_revision_keys(&self.tests, &self.test_revisions, "test revisions")?;
        validate_revision_keys(&self.issues, &self.issue_revisions, "issue revisions")?;
        validate_revision_keys(
            &self.information_requests,
            &self.information_request_revisions,
            "information request revisions",
        )?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("Vanta scope canonical serialization")
    }

    pub fn audit_digest(&self) -> Digest {
        self.audit
            .digest()
            .expect("Vanta audit canonical serialization")
    }

    pub fn expected_endpoints(&self) -> Vec<VantaEndpoint> {
        let mut endpoints = Vec::new();
        if self.api_family.allows_audit() {
            endpoints.extend([
                VantaEndpoint::ListAudits {
                    audit_id: self.audit.id.clone(),
                },
                VantaEndpoint::ListControls {
                    audit_id: self.audit.id.clone(),
                },
                VantaEndpoint::ListIssues {
                    audit_id: self.audit.id.clone(),
                },
                VantaEndpoint::ListInformationRequests {
                    audit_id: self.audit.id.clone(),
                },
            ]);
        }
        if self.api_family.allows_manage() {
            endpoints.push(VantaEndpoint::ListTests {
                audit_id: self.audit.id.clone(),
            });
        }
        endpoints
    }
}

impl VantaApiFamily {
    pub(crate) fn allows(self, requested: Self) -> bool {
        matches!(
            (self, requested),
            (Self::ManageAndAudit, Self::Manage | Self::Audit)
                | (Self::Manage, Self::Manage)
                | (Self::Audit, Self::Audit)
        )
    }
}

fn canonical_ids<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<Vec<T>, VantaModelError> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    if values.len() > MAX_SCOPE_IDS {
        return Err(VantaModelError::TooMany { field });
    }
    Ok(values)
}

fn default_revision_fences<T: Ord + Clone>(
    ids: &[T],
) -> Result<BTreeMap<T, Revision>, VantaModelError> {
    ids.iter()
        .map(|id| Revision::new(1).map(|revision| (id.clone(), revision)))
        .collect()
}

fn revision_fences<T: Ord>(
    values: impl IntoIterator<Item = (T, Revision)>,
    field: &'static str,
) -> Result<BTreeMap<T, Revision>, VantaModelError> {
    let values = values.into_iter().collect::<BTreeMap<_, _>>();
    if values.len() > MAX_SCOPE_IDS {
        return Err(VantaModelError::TooMany { field });
    }
    Ok(values)
}

fn validate_revision_keys<T: Ord>(
    ids: &[T],
    revisions: &BTreeMap<T, Revision>,
    field: &'static str,
) -> Result<(), VantaModelError> {
    if ids.len() != revisions.len() || ids.iter().any(|id| !revisions.contains_key(id)) {
        return Err(VantaModelError::Invalid { field });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub audit_digest: Digest,
    pub audit_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

impl VantaRegistration {
    pub fn new(
        scope: &VantaComplianceScope,
        secret_reference: &SecretReference,
        provider: &VantaProviderIdentity,
        contract_digest: Digest,
    ) -> Result<Self, VantaModelError> {
        let mut registration = Self {
            plugin_version: VANTA_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: VANTA_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: provider.id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.revision.clone(),
            provider_digest: provider.digest.clone(),
            audit_digest: scope.audit_digest(),
            audit_revision: scope.audit.revision,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            consent_digest: scope.consent.digest.clone(),
            secret_reference_digest: secret_reference.digest().clone(),
            mission_revision: scope.mission.revision,
            project_revision: scope.project.revision,
            registration_revision: Revision::new(1)?,
            registration_digest: Digest::zero(),
            state: RegistrationState::Active,
        };
        registration.registration_digest = registration.recompute_digest()?;
        Ok(registration)
    }

    pub fn recompute_digest(&self) -> Result<Digest, VantaModelError> {
        digest_serializable(&(
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_version,
            &self.provider_revision,
            &self.provider_digest,
            &self.audit_digest,
            self.audit_revision,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            self.mission_revision,
            self.project_revision,
            self.registration_revision,
        ))
    }

    pub fn validate(
        &self,
        scope: &VantaComplianceScope,
        secret_reference: &SecretReference,
        provider: &VantaProviderIdentity,
        contract_digest: &Digest,
    ) -> Result<(), VantaModelError> {
        if self.plugin_version != VANTA_PLUGIN_VERSION_TEXT
            || self.contract_version != VANTA_CONTRACT_VERSION
            || self.contract_digest != *contract_digest
            || self.provider_id != provider.id
            || self.provider_version != provider.version
            || self.provider_revision != provider.revision
            || self.provider_digest != provider.digest
            || self.audit_digest != scope.audit_digest()
            || self.audit_revision != scope.audit.revision
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_digest
            || self.consent_digest != scope.consent.digest
            || self.secret_reference_digest != *secret_reference.digest()
            || self.mission_revision != scope.mission.revision
            || self.project_revision != scope.project.revision
            || self.registration_digest != self.recompute_digest()?
        {
            return Err(VantaModelError::Invalid {
                field: "Vanta registration",
            });
        }
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), VantaModelError> {
        if !self.is_active() {
            return Err(VantaModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaComplianceProjection {
    pub state: VantaComplianceState,
    pub audits: Vec<VantaAuditRecord>,
    pub controls: Vec<VantaControlRecord>,
    pub tests: Vec<VantaTestRecord>,
    pub issues: Vec<VantaIssueRecord>,
    pub information_requests: Vec<VantaInformationRequestRecord>,
    pub observed_read_count: u16,
    pub expected_read_count: u16,
    pub page_limit_reached: bool,
    pub no_issues_is_certification: bool,
    pub certification_claim: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaComplianceResultProposal {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub audit_digest: Digest,
    pub audit_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub objective: ComplianceObjective,
    pub projection: VantaComplianceProjection,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub proposal_digest: Digest,
}

impl VantaComplianceResultProposal {
    pub fn recompute_digest(&self) -> Result<Digest, VantaModelError> {
        digest_serializable(&serde_json::json!([
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_version,
            &self.provider_revision,
            &self.provider_digest,
            &self.registration_digest,
            self.registration_revision,
            &self.audit_digest,
            self.audit_revision,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            self.mission_revision,
            self.project_revision,
            &self.objective,
            &self.projection,
            self.provenance,
            &self.evidence_digest,
            self.read_only,
            self.proposal_only,
            self.native,
            self.connected,
            self.external_write_performed,
            self.certification_claim,
            self.adopted_outcome,
        ]))
    }

    pub fn validate(
        &self,
        scope: &VantaComplianceScope,
        registration: &VantaRegistration,
    ) -> Result<(), VantaModelError> {
        if self.plugin_version != VANTA_PLUGIN_VERSION_TEXT
            || self.contract_version != VANTA_CONTRACT_VERSION
            || self.contract_digest != registration.contract_digest
            || self.provider_id != VANTA_PROVIDER_ID
            || self.provider_id != registration.provider_id
            || self.provider_version != registration.provider_version
            || self.provider_revision.as_str() != VANTA_PROVIDER_REVISION_TEXT
            || self.provider_revision != registration.provider_revision
            || self.provider_digest != registration.provider_digest
            || self.registration_digest != registration.registration_digest
            || self.registration_revision != registration.registration_revision
            || self.audit_digest != scope.audit_digest()
            || self.audit_revision != scope.audit.revision
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_digest
            || self.consent_digest != scope.consent.digest
            || self.mission_revision != scope.mission.revision
            || self.project_revision != scope.project.revision
            || self.objective != scope.objective
            || !self.read_only
            || !self.proposal_only
            || self.native
            || self.connected
            || self.external_write_performed
            || self.certification_claim
            || self.adopted_outcome
            || self.projection.native
            || self.projection.connected
            || self.projection.external_write_performed
            || self.projection.outcome_authority
            || self.projection.certification_claim
            || self.projection.no_issues_is_certification
            || self.proposal_digest != self.recompute_digest()?
        {
            return Err(VantaModelError::Invalid {
                field: "Vanta result proposal",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaRecordingReceipt {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub recorded: bool,
    pub raw_provider_payload_retained: bool,
    pub owners_redacted: bool,
    pub evidence_urls_redacted: bool,
    pub comments_redacted: bool,
    pub document_bodies_redacted: bool,
    pub native: bool,
    pub connected: bool,
    pub certification_claim: bool,
}
