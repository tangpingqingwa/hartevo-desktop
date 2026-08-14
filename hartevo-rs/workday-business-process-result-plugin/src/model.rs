//! Bounded Workday business-process result models.
//!
//! This module deliberately keeps provider payloads separate from the
//! projections that can cross the Mission seam. Worker identifiers, names,
//! comments, attachments, query text, and credential material never appear
//! in the serializable evidence projection.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    WORKDAY_API_VERSION, WORKDAY_MAX_PAGES, WORKDAY_MAX_RESPONSE_BYTES, WORKDAY_MAX_ROWS,
    WORKDAY_MAX_STEPS, WORKDAY_MAX_WINDOW_DAYS, WORKDAY_PAGE_SIZE,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 256;
pub(crate) const MAX_QUERY_BYTES: usize = 2_048;
pub(crate) const MAX_COMMENT_COUNT: usize = 256;
pub(crate) const MAX_ATTACHMENT_COUNT: usize = 256;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("{field} is invalid")]
    InvalidValue { field: &'static str },
    #[error("the time window is empty or exceeds the Layer-1 limit")]
    InvalidTimeWindow,
    #[error("the read bounds are empty or exceed the Layer-1 limit")]
    InvalidBounds,
    #[error("{field} is not allowlisted for Workday result reads")]
    ForbiddenField { field: String },
    #[error("WQL must be a bounded business-process SELECT query")]
    ArbitraryWql,
    #[error("RaaS report is not allowlisted or is an unbounded export")]
    UnboundedRaas,
    #[error("Workday API version must be {expected}")]
    InvalidApiVersion { expected: &'static str },
    #[error("the requested read is outside the registered scope")]
    ScopeMismatch,
    #[error("the requested read is not covered by consent")]
    ConsentMismatch,
    #[error("the provider response exceeded a Layer-1 bound")]
    BoundExceeded,
    #[error("the provider response did not match its request fence")]
    FenceMismatch,
    #[error("the registration is invalid")]
    InvalidRegistration,
    #[error("the registration is already revoked")]
    AlreadyRevoked,
    #[error("the evidence digest does not match its immutable projection")]
    DigestMismatch,
}

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

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest { field: "digest" })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '-' | '_' | '.' | ':' | '/' | '@')
        })
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(TenantId, "Workday tenant id");
identifier_type!(TenantRegion, "Workday region");
identifier_type!(ApiVersion, "Workday API version");
identifier_type!(BusinessProcessId, "business-process id");
identifier_type!(BusinessProcessEventId, "business-process event id");
identifier_type!(BusinessObjectId, "business-object id");
identifier_type!(StepId, "business-process step id");
identifier_type!(ReportId, "RaaS report id");
identifier_type!(MissionId, "Mission id");
identifier_type!(ProjectId, "Project id");
identifier_type!(WorkProductId, "Work Product id");
identifier_type!(ProviderRevision, "provider revision");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadKind {
    Events,
    Raas,
    Wql,
}

impl ReadKind {
    pub const ALL: [Self; 3] = [Self::Events, Self::Raas, Self::Wql];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Raas => "raas",
            Self::Wql => "wql",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkdayEndpoint {
    Events,
    Raas,
    Wql,
}

impl From<ReadKind> for WorkdayEndpoint {
    fn from(value: ReadKind) -> Self {
        match value {
            ReadKind::Events => Self::Events,
            ReadKind::Raas => Self::Raas,
            ReadKind::Wql => Self::Wql,
        }
    }
}

impl WorkdayEndpoint {
    pub const fn read_kind(self) -> ReadKind {
        match self {
            Self::Events => ReadKind::Events,
            Self::Raas => ReadKind::Raas,
            Self::Wql => ReadKind::Wql,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepView {
    InProgress,
    Completed,
    Remaining,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WqlDataSource {
    BusinessProcessEvents,
}

impl WqlDataSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BusinessProcessEvents => "businessProcessEvents",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WorkdayField {
    EventId,
    BusinessProcessId,
    BusinessObjectId,
    WorkerReference,
    StepId,
    StepStatus,
    DueDate,
    CompletionDate,
    EventStatus,
    ProcessRevision,
    Payroll,
    Compensation,
    Comments,
    Attachments,
    WorkerName,
    WorkerEmail,
}

impl WorkdayField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventId => "eventId",
            Self::BusinessProcessId => "businessProcessId",
            Self::BusinessObjectId => "businessObjectId",
            Self::WorkerReference => "workerReference",
            Self::StepId => "stepId",
            Self::StepStatus => "stepStatus",
            Self::DueDate => "dueDate",
            Self::CompletionDate => "completionDate",
            Self::EventStatus => "eventStatus",
            Self::ProcessRevision => "processRevision",
            Self::Payroll => "payroll",
            Self::Compensation => "compensation",
            Self::Comments => "comments",
            Self::Attachments => "attachments",
            Self::WorkerName => "workerName",
            Self::WorkerEmail => "workerEmail",
        }
    }

    pub const fn is_allowlisted(self) -> bool {
        matches!(
            self,
            Self::EventId
                | Self::BusinessProcessId
                | Self::BusinessObjectId
                | Self::WorkerReference
                | Self::StepId
                | Self::StepStatus
                | Self::DueDate
                | Self::CompletionDate
                | Self::EventStatus
                | Self::ProcessRevision
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessProcessStatus {
    Initiated,
    Due,
    InProgress,
    Completed,
    Remaining,
    Cancelled,
    Rescinded,
    ProviderUnknown,
}

impl BusinessProcessStatus {
    pub(crate) fn from_provider(value: &str) -> Self {
        match value
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str()
        {
            "initiated" => Self::Initiated,
            "due" => Self::Due,
            "in_progress" | "inprogress" => Self::InProgress,
            "completed" | "complete" => Self::Completed,
            "remaining" => Self::Remaining,
            "cancelled" | "canceled" | "cancel" => Self::Cancelled,
            "rescinded" | "rescind" => Self::Rescinded,
            _ => Self::ProviderUnknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Rescinded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    Complete,
    Partial,
    AccessLost,
    Redacted,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    Initiated,
    Due,
    InProgress,
    Completed,
    Remaining,
    Cancelled,
    Rescinded,
    Overdue,
    Partial,
    AccessLost,
    Redacted,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BlockedEnv,
    AccessDenied,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    Decode,
    UnexpectedStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Granted,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    max_response_bytes: usize,
    max_rows: u32,
    max_pages: u16,
    page_size: u16,
}

impl ReadBounds {
    pub fn new(
        max_response_bytes: usize,
        max_rows: u32,
        max_pages: u16,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        if max_response_bytes == 0
            || max_response_bytes > WORKDAY_MAX_RESPONSE_BYTES
            || max_rows == 0
            || max_rows > WORKDAY_MAX_ROWS
            || max_pages == 0
            || max_pages > WORKDAY_MAX_PAGES
            || page_size == 0
            || page_size > WORKDAY_PAGE_SIZE
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_response_bytes,
            max_rows,
            max_pages,
            page_size,
        })
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub const fn max_rows(&self) -> u32 {
        self.max_rows
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn is_within(&self, outer: &Self) -> bool {
        self.max_response_bytes <= outer.max_response_bytes
            && self.max_rows <= outer.max_rows
            && self.max_pages <= outer.max_pages
            && self.page_size <= outer.page_size
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self::new(
            WORKDAY_MAX_RESPONSE_BYTES,
            WORKDAY_MAX_ROWS,
            WORKDAY_MAX_PAGES,
            WORKDAY_PAGE_SIZE,
        )
        .expect("Layer-1 bounds are valid")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        if start > end || end.signed_duration_since(start) > Duration::days(WORKDAY_MAX_WINDOW_DAYS)
        {
            Err(ModelError::InvalidTimeWindow)
        } else {
            Ok(Self { start, end })
        }
    }

    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    pub fn end(&self) -> DateTime<Utc> {
        self.end
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workday-time-window/v1",
            &[self.start.to_rfc3339(), self.end.to_rfc3339()],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    permission_digest: Digest,
    consent_digest: Digest,
    consent_revision: Revision,
    allowed_reads: BTreeSet<ReadKind>,
    expires_at: DateTime<Utc>,
}

impl ConsentScope {
    pub fn new(
        permission_digest: Digest,
        consent_digest: Digest,
        consent_revision: Revision,
        allowed_reads: impl IntoIterator<Item = ReadKind>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let allowed_reads = allowed_reads.into_iter().collect::<BTreeSet<_>>();
        if allowed_reads.is_empty() {
            return Err(ModelError::ConsentMismatch);
        }
        Ok(Self {
            permission_digest,
            consent_digest,
            consent_revision,
            allowed_reads,
            expires_at,
        })
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn consent_revision(&self) -> Revision {
        self.consent_revision
    }

    pub fn allowed_reads(&self) -> &BTreeSet<ReadKind> {
        &self.allowed_reads
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn allows(&self, kind: ReadKind, at: DateTime<Utc>) -> bool {
        self.allowed_reads.contains(&kind) && at <= self.expires_at
    }

    pub fn state_at(&self, at: DateTime<Utc>) -> ConsentState {
        if at > self.expires_at {
            ConsentState::Expired
        } else {
            ConsentState::Granted
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workday-consent-scope/v1",
            &[
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.consent_revision.get().to_string(),
                self.allowed_reads
                    .iter()
                    .map(|read| read.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                self.expires_at.to_rfc3339(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerReferenceKind {
    Worker,
    Redacted,
    Unknown,
}

/// A worker reference that contains only a stable digest and a classification.
/// The provider identifier, display name, email, and other PII are discarded.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct WorkerReference {
    reference_digest: Digest,
    kind: WorkerReferenceKind,
}

impl fmt::Debug for WorkerReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerReference")
            .field("reference_digest", &self.reference_digest)
            .field("kind", &self.kind)
            .finish()
    }
}

impl Serialize for WorkerReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SafeWorkerReference<'a> {
            reference_digest: &'a Digest,
            kind: WorkerReferenceKind,
        }
        SafeWorkerReference {
            reference_digest: &self.reference_digest,
            kind: self.kind.clone(),
        }
        .serialize(serializer)
    }
}

impl WorkerReference {
    pub fn new(reference_id: impl Into<String>) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier {
                field: "worker reference",
            });
        }
        Ok(Self {
            reference_digest: Digest::from_fields("workday-worker-reference/v1", &[reference_id]),
            kind: WorkerReferenceKind::Worker,
        })
    }

    pub fn redacted(reference_digest: Digest) -> Self {
        Self {
            reference_digest,
            kind: WorkerReferenceKind::Redacted,
        }
    }

    pub fn unknown(reference_digest: Digest) -> Self {
        Self {
            reference_digest,
            kind: WorkerReferenceKind::Unknown,
        }
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn kind(&self) -> &WorkerReferenceKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BusinessObjectReference {
    id: BusinessObjectId,
    revision: Revision,
}

impl BusinessObjectReference {
    pub fn new(id: BusinessObjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &BusinessObjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepReference {
    id: StepId,
    revision: Revision,
}

impl StepReference {
    pub fn new(id: StepId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &StepId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayScopeInput {
    pub tenant_id: TenantId,
    pub region: TenantRegion,
    pub api_version: ApiVersion,
    pub business_process_id: BusinessProcessId,
    pub event_id: BusinessProcessEventId,
    pub business_object: BusinessObjectReference,
    pub worker_reference: WorkerReference,
    pub allowlisted_report_ids: BTreeSet<ReportId>,
    pub time_window: TimeWindow,
    pub bounds: ReadBounds,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub tenant_revision: Revision,
    pub process_revision: Revision,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub work_product_revision: Revision,
    pub consent: ConsentScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayScope {
    tenant_id: TenantId,
    region: TenantRegion,
    api_version: ApiVersion,
    business_process_id: BusinessProcessId,
    event_id: BusinessProcessEventId,
    business_object: BusinessObjectReference,
    worker_reference: WorkerReference,
    allowlisted_report_ids: BTreeSet<ReportId>,
    time_window: TimeWindow,
    bounds: ReadBounds,
    mission_id: MissionId,
    project_id: ProjectId,
    work_product_id: WorkProductId,
    tenant_revision: Revision,
    process_revision: Revision,
    mission_revision: Revision,
    project_revision: Revision,
    work_product_revision: Revision,
    consent: ConsentScope,
    scope_digest: Digest,
}

impl WorkdayScope {
    pub fn new(input: WorkdayScopeInput) -> Result<Self, ModelError> {
        if input.api_version.as_str() != WORKDAY_API_VERSION
            || input.allowlisted_report_ids.len() > 16
            || !input.bounds.is_within(&ReadBounds::default())
        {
            return Err(ModelError::ScopeMismatch);
        }
        let scope_digest = Digest::from_fields(
            "workday-business-process-scope/v1",
            &[
                input.tenant_id.as_str().to_owned(),
                input.region.as_str().to_owned(),
                input.api_version.as_str().to_owned(),
                input.business_process_id.as_str().to_owned(),
                input.event_id.as_str().to_owned(),
                input.business_object.id().as_str().to_owned(),
                input.business_object.revision().get().to_string(),
                input
                    .worker_reference
                    .reference_digest()
                    .as_str()
                    .to_owned(),
                input
                    .allowlisted_report_ids
                    .iter()
                    .map(ReportId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                input.time_window.digest().as_str().to_owned(),
                input.mission_id.as_str().to_owned(),
                input.project_id.as_str().to_owned(),
                input.work_product_id.as_str().to_owned(),
                input.tenant_revision.get().to_string(),
                input.process_revision.get().to_string(),
                input.mission_revision.get().to_string(),
                input.project_revision.get().to_string(),
                input.work_product_revision.get().to_string(),
                input.consent.digest().as_str().to_owned(),
                input.bounds.max_response_bytes().to_string(),
                input.bounds.max_rows().to_string(),
                input.bounds.max_pages().to_string(),
                input.bounds.page_size().to_string(),
            ],
        );
        Ok(Self {
            tenant_id: input.tenant_id,
            region: input.region,
            api_version: input.api_version,
            business_process_id: input.business_process_id,
            event_id: input.event_id,
            business_object: input.business_object,
            worker_reference: input.worker_reference,
            allowlisted_report_ids: input.allowlisted_report_ids,
            time_window: input.time_window,
            bounds: input.bounds,
            mission_id: input.mission_id,
            project_id: input.project_id,
            work_product_id: input.work_product_id,
            tenant_revision: input.tenant_revision,
            process_revision: input.process_revision,
            mission_revision: input.mission_revision,
            project_revision: input.project_revision,
            work_product_revision: input.work_product_revision,
            consent: input.consent,
            scope_digest,
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn region(&self) -> &TenantRegion {
        &self.region
    }

    pub fn api_version(&self) -> &ApiVersion {
        &self.api_version
    }

    pub fn business_process_id(&self) -> &BusinessProcessId {
        &self.business_process_id
    }

    pub fn event_id(&self) -> &BusinessProcessEventId {
        &self.event_id
    }

    pub fn business_object(&self) -> &BusinessObjectReference {
        &self.business_object
    }

    pub fn worker_reference(&self) -> &WorkerReference {
        &self.worker_reference
    }

    pub fn allowlisted_report_ids(&self) -> &BTreeSet<ReportId> {
        &self.allowlisted_report_ids
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub fn bounds(&self) -> &ReadBounds {
        &self.bounds
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn tenant_revision(&self) -> Revision {
        self.tenant_revision
    }

    pub const fn process_revision(&self) -> Revision {
        self.process_revision
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub(crate) fn accepts_request(
        &self,
        kind: ReadKind,
        bounds: &ReadBounds,
        at: DateTime<Utc>,
    ) -> Result<(), ModelError> {
        if !bounds.is_within(&self.bounds) {
            return Err(ModelError::ScopeMismatch);
        }
        if !self.consent.allows(kind, at) {
            return Err(ModelError::ConsentMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayReadRequest {
    endpoint: WorkdayEndpoint,
    kind: ReadKind,
    tenant_id: TenantId,
    region: TenantRegion,
    api_version: ApiVersion,
    business_process_id: BusinessProcessId,
    event_id: BusinessProcessEventId,
    report_id: Option<ReportId>,
    step_views: BTreeSet<StepView>,
    fields: Vec<WorkdayField>,
    time_window: TimeWindow,
    bounds: ReadBounds,
    scope_digest: Digest,
    consent_digest: Digest,
    consent_revision: Revision,
    mission_revision: Revision,
    project_revision: Revision,
    work_product_revision: Revision,
    query_digest: Digest,
}

impl WorkdayReadRequest {
    pub fn events(scope: &WorkdayScope, bounds: ReadBounds) -> Result<Self, ModelError> {
        scope.accepts_request(ReadKind::Events, &bounds, Utc::now())?;
        let fields = vec![
            WorkdayField::EventId,
            WorkdayField::BusinessProcessId,
            WorkdayField::BusinessObjectId,
            WorkdayField::WorkerReference,
            WorkdayField::StepId,
            WorkdayField::StepStatus,
            WorkdayField::DueDate,
            WorkdayField::CompletionDate,
            WorkdayField::EventStatus,
            WorkdayField::ProcessRevision,
        ];
        Ok(Self::build(
            scope,
            ReadKind::Events,
            None,
            [
                StepView::InProgress,
                StepView::Completed,
                StepView::Remaining,
            ],
            fields,
            bounds,
            Digest::from_fields(
                "workday-events-read/v1",
                &[scope.scope_digest().as_str().to_owned()],
            ),
        ))
    }

    pub fn raas(
        scope: &WorkdayScope,
        report_id: ReportId,
        fields: impl IntoIterator<Item = WorkdayField>,
        bounds: ReadBounds,
    ) -> Result<Self, ModelError> {
        scope.accepts_request(ReadKind::Raas, &bounds, Utc::now())?;
        if !scope.allowlisted_report_ids.contains(&report_id) {
            return Err(ModelError::UnboundedRaas);
        }
        let fields = allowlisted_fields(fields)?;
        let query_digest = Digest::from_fields(
            "workday-raas-read/v1",
            &[
                report_id.as_str().to_owned(),
                fields
                    .iter()
                    .map(|field| field.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                scope.time_window.digest().as_str().to_owned(),
            ],
        );
        Ok(Self::build(
            scope,
            ReadKind::Raas,
            Some(report_id),
            [],
            fields,
            bounds,
            query_digest,
        ))
    }

    pub fn wql(
        scope: &WorkdayScope,
        data_source: WqlDataSource,
        fields: impl IntoIterator<Item = WorkdayField>,
        bounds: ReadBounds,
    ) -> Result<Self, ModelError> {
        scope.accepts_request(ReadKind::Wql, &bounds, Utc::now())?;
        let fields = allowlisted_fields(fields)?;
        let query_digest = Digest::from_fields(
            "workday-wql-read/v1",
            &[
                data_source.as_str().to_owned(),
                fields
                    .iter()
                    .map(|field| field.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                scope.event_id.as_str().to_owned(),
                scope.time_window.digest().as_str().to_owned(),
                bounds.max_rows().to_string(),
            ],
        );
        Ok(Self::build(
            scope,
            ReadKind::Wql,
            None,
            [],
            fields,
            bounds,
            query_digest,
        ))
    }

    /// Accepts only a bounded, business-process WQL SELECT. The query text is
    /// reduced to a digest immediately and is never retained in a request,
    /// receipt, proposal, or Mission result.
    pub fn wql_text(
        scope: &WorkdayScope,
        query: impl AsRef<str>,
        bounds: ReadBounds,
    ) -> Result<Self, ModelError> {
        scope.accepts_request(ReadKind::Wql, &bounds, Utc::now())?;
        validate_wql(query.as_ref(), &scope.event_id, &bounds)?;
        Ok(Self::build(
            scope,
            ReadKind::Wql,
            None,
            [],
            vec![WorkdayField::EventId, WorkdayField::EventStatus],
            bounds,
            Digest::from_fields("workday-wql-text-read/v1", &[query.as_ref().to_owned()]),
        ))
    }

    fn build(
        scope: &WorkdayScope,
        kind: ReadKind,
        report_id: Option<ReportId>,
        step_views: impl IntoIterator<Item = StepView>,
        fields: Vec<WorkdayField>,
        bounds: ReadBounds,
        query_digest: Digest,
    ) -> Self {
        Self {
            endpoint: kind.into(),
            kind,
            tenant_id: scope.tenant_id.clone(),
            region: scope.region.clone(),
            api_version: scope.api_version.clone(),
            business_process_id: scope.business_process_id.clone(),
            event_id: scope.event_id.clone(),
            report_id,
            step_views: step_views.into_iter().collect(),
            fields,
            time_window: scope.time_window.clone(),
            bounds,
            scope_digest: scope.scope_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
            consent_revision: scope.consent.consent_revision,
            mission_revision: scope.mission_revision,
            project_revision: scope.project_revision,
            work_product_revision: scope.work_product_revision,
            query_digest,
        }
    }

    pub const fn endpoint(&self) -> WorkdayEndpoint {
        self.endpoint
    }

    pub const fn kind(&self) -> ReadKind {
        self.kind
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn region(&self) -> &TenantRegion {
        &self.region
    }

    pub fn api_version(&self) -> &ApiVersion {
        &self.api_version
    }

    pub fn business_process_id(&self) -> &BusinessProcessId {
        &self.business_process_id
    }

    pub fn event_id(&self) -> &BusinessProcessEventId {
        &self.event_id
    }

    pub fn report_id(&self) -> Option<&ReportId> {
        self.report_id.as_ref()
    }

    pub fn step_views(&self) -> &BTreeSet<StepView> {
        &self.step_views
    }

    pub fn fields(&self) -> &[WorkdayField] {
        &self.fields
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub fn bounds(&self) -> &ReadBounds {
        &self.bounds
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn consent_revision(&self) -> Revision {
        self.consent_revision
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub(crate) fn path_and_query(&self) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("businessProcess", self.business_process_id.as_str());
        query.append_pair("from", &self.time_window.start.to_rfc3339());
        query.append_pair("to", &self.time_window.end.to_rfc3339());
        query.append_pair("limit", &self.bounds.page_size.to_string());
        query.append_pair("pages", &self.bounds.max_pages.to_string());
        match self.endpoint {
            WorkdayEndpoint::Events => format!(
                "/api/businessProcess/{}/{}/events/{}?{}",
                self.api_version.as_str(),
                self.tenant_id.as_str(),
                self.event_id.as_str(),
                query.finish()
            ),
            WorkdayEndpoint::Raas => format!(
                "/raas/{}/{}?{}",
                self.tenant_id.as_str(),
                self.report_id
                    .as_ref()
                    .map_or("allowlisted".to_owned(), |report| {
                        report.as_str().to_owned()
                    }),
                query.finish()
            ),
            WorkdayEndpoint::Wql => {
                query.append_pair("queryDigest", self.query_digest.as_str());
                format!(
                    "/api/wql/{}/{}/data?{}",
                    self.api_version.as_str(),
                    self.tenant_id.as_str(),
                    query.finish()
                )
            }
        }
    }
}

fn allowlisted_fields(
    fields: impl IntoIterator<Item = WorkdayField>,
) -> Result<Vec<WorkdayField>, ModelError> {
    let fields = fields.into_iter().collect::<Vec<_>>();
    if fields.is_empty() {
        return Err(ModelError::InvalidValue { field: "fields" });
    }
    if let Some(field) = fields.iter().copied().find(|field| !field.is_allowlisted()) {
        return Err(ModelError::ForbiddenField {
            field: field.as_str().to_owned(),
        });
    }
    Ok(fields)
}

fn validate_wql(
    query: &str,
    event_id: &BusinessProcessEventId,
    bounds: &ReadBounds,
) -> Result<(), ModelError> {
    if query.is_empty() || query.len() > MAX_QUERY_BYTES || query.chars().any(char::is_control) {
        return Err(ModelError::ArbitraryWql);
    }
    let normalized = query.to_ascii_lowercase();
    let trimmed = normalized.trim();
    let forbidden = [
        "insert",
        "update",
        "delete",
        "merge",
        "drop",
        "alter",
        "create",
        "truncate",
        "export",
        "payroll",
        "compensation",
        "salary",
        "bonus",
        "comment",
        "attachment",
        "firstname",
        "lastname",
        "email",
        "phone",
        "address",
    ];
    if !trimmed.starts_with("select ")
        || trimmed.contains(';')
        || !trimmed.contains("from businessprocessevents")
        || !trimmed.contains("event")
        || forbidden.iter().any(|word| trimmed.contains(word))
    {
        return Err(ModelError::ArbitraryWql);
    }
    let limit = trimmed
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|window| window[0] == "limit")
        .and_then(|window| window[1].parse::<u32>().ok())
        .ok_or(ModelError::UnboundedRaas)?;
    if limit == 0 || limit > bounds.max_rows() || !trimmed.contains(event_id.as_str()) {
        return Err(ModelError::ArbitraryWql);
    }
    Ok(())
}

/// Host/provider payload for a worker reference. It is intentionally not
/// serializable and its Debug output only exposes digests and presence flags.
#[derive(Clone)]
pub struct WorkdayWorkerPayload {
    pub reference_id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

impl fmt::Debug for WorkdayWorkerPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkdayWorkerPayload")
            .field("reference_digest", &Digest::from_text(&self.reference_id))
            .field("display_name_present", &self.display_name.is_some())
            .field("email_present", &self.email.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub struct WorkdayAttachmentPayload {
    pub attachment_id: String,
    pub filename: Option<String>,
    pub content_digest: Option<Digest>,
}

impl fmt::Debug for WorkdayAttachmentPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkdayAttachmentPayload")
            .field(
                "attachment_id_digest",
                &Digest::from_text(&self.attachment_id),
            )
            .field("filename_present", &self.filename.is_some())
            .field("content_present", &self.content_digest.is_some())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct WorkdayStepPayload {
    pub reference: StepReference,
    pub status: String,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct WorkdayEventPayload {
    pub event_id: BusinessProcessEventId,
    pub event_revision: Revision,
    pub business_process_id: BusinessProcessId,
    pub business_object: BusinessObjectReference,
    pub worker: WorkdayWorkerPayload,
    pub status: String,
    pub initiated_at: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub steps: Vec<WorkdayStepPayload>,
    pub comments: Vec<String>,
    pub attachments: Vec<WorkdayAttachmentPayload>,
    pub provider_partial: bool,
    pub provider_redacted: bool,
}

impl fmt::Debug for WorkdayEventPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkdayEventPayload")
            .field("event_id", &self.event_id)
            .field("event_revision", &self.event_revision)
            .field("business_process_id", &self.business_process_id)
            .field("business_object", &self.business_object)
            .field("worker", &self.worker)
            .field("status", &self.status)
            .field("initiated_at", &self.initiated_at)
            .field("due_at", &self.due_at)
            .field("completed_at", &self.completed_at)
            .field("step_count", &self.steps.len())
            .field("comment_count", &self.comments.len())
            .field("attachment_count", &self.attachments.len())
            .field("provider_partial", &self.provider_partial)
            .field("provider_redacted", &self.provider_redacted)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayStepProjection {
    pub reference: StepReference,
    pub status: BusinessProcessStatus,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayEventProjection {
    pub event_id: BusinessProcessEventId,
    pub event_revision: Revision,
    pub business_process_id: BusinessProcessId,
    pub business_object: BusinessObjectReference,
    pub worker_reference: WorkerReference,
    pub status: BusinessProcessStatus,
    pub initiated_at: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub steps: Vec<WorkdayStepProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub worker_pii_redacted: bool,
    pub comments_redacted: bool,
    pub attachments_redacted: bool,
    pub payroll_and_compensation_redacted: bool,
    pub redacted_field_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayResponseReceipt {
    pub endpoint: WorkdayEndpoint,
    pub request_path_and_query: String,
    pub api_version: ApiVersion,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub observed_at: DateTime<Utc>,
    pub freshness_digest: Digest,
    pub provenance: TransportProvenance,
    pub raw_provider_payload: bool,
    pub credential_material: bool,
    pub native_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayBusinessProcessResultEvidence {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub capability_digest: Digest,
    pub consent_digest: Digest,
    pub consent_revision: Revision,
    pub tenant_revision: Revision,
    pub process_revision: Revision,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub work_product_revision: Revision,
    pub step_revision_digest: Digest,
    pub event: Option<WorkdayEventProjection>,
    pub process_status: BusinessProcessStatus,
    pub quality: EvidenceQuality,
    pub overdue: bool,
    pub redaction: RedactionSummary,
    pub receipt: WorkdayResponseReceipt,
    pub evidence_digest: Digest,
}

impl WorkdayBusinessProcessResultEvidence {
    pub(crate) fn from_payload(
        scope: &WorkdayScope,
        registration_digest: &Digest,
        provider_digest: &Digest,
        capability_digest: &Digest,
        payload: &WorkdayEventPayload,
        receipt: WorkdayResponseReceipt,
    ) -> Result<Self, ModelError> {
        if payload.event_id != scope.event_id
            || payload.business_process_id != scope.business_process_id
            || payload.business_object != scope.business_object
            || Digest::from_fields(
                "workday-worker-reference/v1",
                std::slice::from_ref(&payload.worker.reference_id),
            ) != *scope.worker_reference.reference_digest()
            || payload.event_revision.get() < scope.process_revision.get()
        {
            return Err(ModelError::FenceMismatch);
        }
        if payload.steps.len() > usize::from(WORKDAY_MAX_STEPS)
            || payload.comments.len() > MAX_COMMENT_COUNT
            || payload.attachments.len() > MAX_ATTACHMENT_COUNT
        {
            return Err(ModelError::BoundExceeded);
        }
        let status = BusinessProcessStatus::from_provider(&payload.status);
        let event = WorkdayEventProjection {
            event_id: payload.event_id.clone(),
            event_revision: payload.event_revision,
            business_process_id: payload.business_process_id.clone(),
            business_object: payload.business_object.clone(),
            worker_reference: WorkerReference::redacted(Digest::from_fields(
                "workday-worker-reference/v1",
                std::slice::from_ref(&payload.worker.reference_id),
            )),
            status,
            initiated_at: payload.initiated_at,
            due_at: payload.due_at,
            completed_at: payload.completed_at,
            steps: payload
                .steps
                .iter()
                .map(|step| WorkdayStepProjection {
                    reference: step.reference.clone(),
                    status: BusinessProcessStatus::from_provider(&step.status),
                    due_at: step.due_at,
                    completed_at: step.completed_at,
                })
                .collect(),
        };
        let step_revision_digest = Digest::from_fields(
            "workday-step-revision-fence/v1",
            &payload
                .steps
                .iter()
                .flat_map(|step| {
                    [
                        step.reference.id().as_str().to_owned(),
                        step.reference.revision().get().to_string(),
                    ]
                })
                .collect::<Vec<_>>(),
        );
        let redacted_field_count = u16::from(payload.worker.display_name.is_some())
            + u16::from(payload.worker.email.is_some())
            + u16::try_from(payload.comments.len()).unwrap_or(u16::MAX)
            + u16::try_from(payload.attachments.len()).unwrap_or(u16::MAX);
        let redaction = RedactionSummary {
            worker_pii_redacted: true,
            comments_redacted: true,
            attachments_redacted: true,
            payroll_and_compensation_redacted: true,
            redacted_field_count,
        };
        let quality = if status == BusinessProcessStatus::ProviderUnknown {
            EvidenceQuality::ProviderUnknown
        } else if payload.provider_partial {
            EvidenceQuality::Partial
        } else if payload.provider_redacted
            || payload.worker.display_name.is_some()
            || payload.worker.email.is_some()
            || !payload.comments.is_empty()
            || !payload.attachments.is_empty()
        {
            EvidenceQuality::Redacted
        } else {
            EvidenceQuality::Complete
        };
        let overdue = payload
            .due_at
            .is_some_and(|due_at| due_at < receipt.observed_at && !status.is_terminal());
        let mut evidence = Self {
            scope_digest: scope.scope_digest.clone(),
            registration_digest: registration_digest.clone(),
            provider_digest: provider_digest.clone(),
            capability_digest: capability_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
            consent_revision: scope.consent.consent_revision,
            tenant_revision: scope.tenant_revision,
            process_revision: scope.process_revision,
            mission_revision: scope.mission_revision,
            project_revision: scope.project_revision,
            work_product_revision: scope.work_product_revision,
            step_revision_digest,
            event: Some(event),
            process_status: status,
            quality,
            overdue,
            redaction,
            receipt,
            evidence_digest: Digest::from_text("uncomputed"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub(crate) fn access_lost(
        scope: &WorkdayScope,
        registration_digest: &Digest,
        provider_digest: &Digest,
        capability_digest: &Digest,
        receipt: WorkdayResponseReceipt,
    ) -> Self {
        let mut evidence = Self {
            scope_digest: scope.scope_digest.clone(),
            registration_digest: registration_digest.clone(),
            provider_digest: provider_digest.clone(),
            capability_digest: capability_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
            consent_revision: scope.consent.consent_revision,
            tenant_revision: scope.tenant_revision,
            process_revision: scope.process_revision,
            mission_revision: scope.mission_revision,
            project_revision: scope.project_revision,
            work_product_revision: scope.work_product_revision,
            step_revision_digest: Digest::from_text("no-observed-steps"),
            event: None,
            process_status: BusinessProcessStatus::ProviderUnknown,
            quality: EvidenceQuality::AccessLost,
            overdue: false,
            redaction: RedactionSummary {
                worker_pii_redacted: true,
                comments_redacted: true,
                attachments_redacted: true,
                payroll_and_compensation_redacted: true,
                redacted_field_count: 0,
            },
            receipt,
            evidence_digest: Digest::from_text("uncomputed"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "workday-business-process-evidence/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.capability_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.consent_revision.get().to_string(),
                self.tenant_revision.get().to_string(),
                self.process_revision.get().to_string(),
                self.mission_revision.get().to_string(),
                self.project_revision.get().to_string(),
                self.work_product_revision.get().to_string(),
                self.step_revision_digest.as_str().to_owned(),
                serde_json::to_string(&self.event).unwrap_or_default(),
                format!("{:?}", self.process_status),
                format!("{:?}", self.quality),
                self.overdue.to_string(),
                serde_json::to_string(&self.redaction).unwrap_or_default(),
                serde_json::to_string(&self.receipt).unwrap_or_default(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.evidence_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn mission_state(&self) -> MissionResultState {
        if self.quality == EvidenceQuality::AccessLost {
            MissionResultState::AccessLost
        } else if self.quality == EvidenceQuality::Partial {
            MissionResultState::Partial
        } else if self.quality == EvidenceQuality::ProviderUnknown
            || self.process_status == BusinessProcessStatus::ProviderUnknown
        {
            MissionResultState::ProviderUnknown
        } else if self.overdue {
            MissionResultState::Overdue
        } else if self.quality == EvidenceQuality::Redacted {
            MissionResultState::Redacted
        } else {
            match self.process_status {
                BusinessProcessStatus::Initiated => MissionResultState::Initiated,
                BusinessProcessStatus::Due => MissionResultState::Due,
                BusinessProcessStatus::InProgress => MissionResultState::InProgress,
                BusinessProcessStatus::Completed => MissionResultState::Completed,
                BusinessProcessStatus::Remaining => MissionResultState::Remaining,
                BusinessProcessStatus::Cancelled => MissionResultState::Cancelled,
                BusinessProcessStatus::Rescinded => MissionResultState::Rescinded,
                BusinessProcessStatus::ProviderUnknown => MissionResultState::ProviderUnknown,
            }
        }
    }

    pub fn event(&self) -> Option<&WorkdayEventProjection> {
        self.event.as_ref()
    }

    pub fn receipt(&self) -> &WorkdayResponseReceipt {
        &self.receipt
    }

    pub fn step_revision_digest(&self) -> &Digest {
        &self.step_revision_digest
    }
}

/// An opaque reference into host-owned Workday credentials. It deliberately
/// does not implement Serialize or Deserialize and never retains the input
/// reference id.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &WorkdayScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier {
                field: "secret reference",
            });
        }
        Ok(Self {
            reference_digest: Digest::from_fields(
                "workday-secret-reference/v1",
                &[
                    reference_id,
                    scope.scope_digest.as_str().to_owned(),
                    credential_revision.get().to_string(),
                ],
            ),
            scope_digest: scope.scope_digest.clone(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
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
}
