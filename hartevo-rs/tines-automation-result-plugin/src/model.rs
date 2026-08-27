use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    MAX_AUDIT_LOGS, MAX_IDENTIFIER_BYTES, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES,
    error::{Result, TinesAutomationResultError},
};

pub type Digest = String;

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

/// Returns the SHA-256 digest of the canonical JSON representation.
///
/// # Panics
///
/// Panics if a caller supplies a serializer that fails. All Layer-1 model
/// types use infallible serde implementations.
#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    // Serialization of the closed typed model is infallible in normal use.
    let bytes = serde_json::to_vec(value).expect("typed Tines value serializes");
    sha256_hex(&bytes)
}

fn validate_identifier(label: &'static str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(|character| character.is_control())
        || value.chars().any(char::is_whitespace)
        || value
            .chars()
            .any(|character| matches!(character, '/' | '?' | '#' | '&' | '='))
    {
        return Err(TinesAutomationResultError::InvalidIdentifier { label });
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self> {
                let value = value.as_ref();
                validate_identifier($label, value)?;
                Ok(Self(value.to_owned()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                sha256_hex(self.0.as_bytes())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

identifier_type!(TenantId, "tenant");
identifier_type!(StoryId, "story");
identifier_type!(ActionId, "action");
identifier_type!(StoryRunGuid, "story run");
identifier_type!(EventId, "event");
identifier_type!(CaseId, "case");
identifier_type!(ProjectId, "project");
identifier_type!(MissionId, "mission");
identifier_type!(WorkProductId, "work product");

pub type TinesTenantId = TenantId;
pub type TinesStoryId = StoryId;
pub type TinesActionId = ActionId;
pub type TinesStoryRunId = StoryRunGuid;
pub type TinesEventId = EventId;
pub type TinesCaseId = CaseId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(TinesAutomationResultError::InvalidValue { label: "revision" });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn from_digest(digest: &str) -> Self {
        let mut value = 0_u64;
        for byte in digest.as_bytes().iter().take(16) {
            value = value.wrapping_mul(16).wrapping_add(match byte {
                b'0'..=b'9' => u64::from(byte - b'0'),
                b'a'..=b'f' => u64::from(byte - b'a' + 10),
                b'A'..=b'F' => u64::from(byte - b'A' + 10),
                _ => 0,
            });
        }
        Self(value.max(1))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self> {
        if start >= end || end - start > Duration::days(crate::MAX_TIME_WINDOW_DAYS) {
            return Err(TinesAutomationResultError::InvalidTimeWindow);
        }
        Ok(Self { start, end })
    }

    pub fn from_rfc3339(start: &str, end: &str) -> Result<Self> {
        let start = start
            .parse::<DateTime<Utc>>()
            .map_err(|_| TinesAutomationResultError::InvalidTimeWindow)?;
        let end = end
            .parse::<DateTime<Utc>>()
            .map_err(|_| TinesAutomationResultError::InvalidTimeWindow)?;
        Self::new(start, end)
    }

    #[must_use]
    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }

    #[must_use]
    pub fn start_rfc3339(&self) -> String {
        self.start.to_rfc3339()
    }

    #[must_use]
    pub fn end_rfc3339(&self) -> String {
        self.end.to_rfc3339()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl AsRef<str>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl AsRef<str>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl AsRef<str>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub reference: String,
    pub revision: Revision,
    pub expires_at: DateTime<Utc>,
}

impl ConsentScope {
    pub fn new(
        reference: impl AsRef<str>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let reference = reference.as_ref();
        validate_identifier("consent reference", reference)?;
        Ok(Self {
            reference: reference.to_owned(),
            revision: Revision::new(revision)?,
            expires_at,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        if now > self.expires_at {
            return Err(TinesAutomationResultError::ConsentMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TinesPermission {
    StoriesRead,
    StoryRunsRead,
    ActionsRead,
    EventsRead,
    CasesRead,
    AuditLogsRead,
}

impl TinesPermission {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoriesRead => "stories.read",
            Self::StoryRunsRead => "story_runs.read",
            Self::ActionsRead => "actions.read",
            Self::EventsRead => "events.read",
            Self::CasesRead => "cases.read",
            Self::AuditLogsRead => "audit_logs.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesPermissionSet {
    permissions: BTreeSet<TinesPermission>,
}

impl TinesPermissionSet {
    pub fn read_only() -> Self {
        Self {
            permissions: BTreeSet::from([
                TinesPermission::StoriesRead,
                TinesPermission::StoryRunsRead,
                TinesPermission::ActionsRead,
                TinesPermission::EventsRead,
                TinesPermission::CasesRead,
                TinesPermission::AuditLogsRead,
            ]),
        }
    }

    pub fn new<I>(permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = TinesPermission>,
    {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions.is_empty() {
            return Err(TinesAutomationResultError::InvalidPermissionSet);
        }
        Ok(Self { permissions })
    }

    #[must_use]
    pub fn contains(&self, permission: TinesPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn permissions(&self) -> impl Iterator<Item = TinesPermission> + '_ {
        self.permissions.iter().copied()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate_for_scope(&self, scope: &TinesAutomationScope) -> Result<()> {
        let required = [TinesPermission::StoriesRead, TinesPermission::AuditLogsRead];
        if required
            .iter()
            .any(|permission| !self.contains(*permission))
            || (scope.story_run().is_some() && !self.contains(TinesPermission::StoryRunsRead))
            || (scope.action().is_some() && !self.contains(TinesPermission::ActionsRead))
            || (scope.event().is_some() && !self.contains(TinesPermission::EventsRead))
            || (scope.case_id().is_some() && !self.contains(TinesPermission::CasesRead))
        {
            return Err(TinesAutomationResultError::InvalidPermissionSet);
        }
        Ok(())
    }
}

/// An opaque handle to a host-owned keyring entry. The raw handle is reduced
/// to a digest at construction and is intentionally not serializable or
/// printable, so no Tines token can enter a request, receipt, or proposal.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    revision: Revision,
}

impl SecretReference {
    pub fn new(handle: impl AsRef<str>, revision: u64) -> Result<Self> {
        let handle = handle.as_ref();
        if handle.is_empty() || handle.len() > MAX_IDENTIFIER_BYTES * 4 {
            return Err(TinesAutomationResultError::InvalidSecretReference);
        }
        Ok(Self {
            digest: sha256_hex(format!("tines-secret-reference/v1|{handle}").as_bytes()),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &"<redacted>")
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesAutomationScopeSpec {
    pub tenant: TenantId,
    pub story: StoryId,
    pub action: Option<ActionId>,
    pub story_run: Option<StoryRunGuid>,
    pub event: Option<EventId>,
    pub case_id: Option<CaseId>,
    pub time_window: TimeWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub permissions: TinesPermissionSet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesAutomationScope {
    spec: TinesAutomationScopeSpec,
    digest: Digest,
}

impl TinesAutomationScope {
    pub fn new(spec: TinesAutomationScopeSpec) -> Result<Self> {
        spec.permissions.validate_for_scope_raw(&spec)?;
        let digest = canonical_digest(&spec);
        Ok(Self { spec, digest })
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.digest != canonical_digest(&self.spec) {
            return Err(TinesAutomationResultError::TamperedEvidence);
        }
        self.spec.permissions.validate_for_scope_raw(&self.spec)
    }

    #[must_use]
    pub fn spec(&self) -> &TinesAutomationScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.spec.tenant
    }

    #[must_use]
    pub fn story(&self) -> &StoryId {
        &self.spec.story
    }

    #[must_use]
    pub fn action(&self) -> Option<&ActionId> {
        self.spec.action.as_ref()
    }

    #[must_use]
    pub fn story_run(&self) -> Option<&StoryRunGuid> {
        self.spec.story_run.as_ref()
    }

    #[must_use]
    pub fn event(&self) -> Option<&EventId> {
        self.spec.event.as_ref()
    }

    #[must_use]
    pub fn case_id(&self) -> Option<&CaseId> {
        self.spec.case_id.as_ref()
    }

    #[must_use]
    pub fn time_window(&self) -> &TimeWindow {
        &self.spec.time_window
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.spec.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.spec.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.spec.work_product
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.spec.consent
    }

    #[must_use]
    pub fn permissions(&self) -> &TinesPermissionSet {
        &self.spec.permissions
    }
}

impl TinesPermissionSet {
    fn validate_for_scope_raw(&self, scope: &TinesAutomationScopeSpec) -> Result<()> {
        let required = [TinesPermission::StoriesRead, TinesPermission::AuditLogsRead];
        if required
            .iter()
            .any(|permission| !self.contains(*permission))
            || (scope.story_run.is_some() && !self.contains(TinesPermission::StoryRunsRead))
            || (scope.action.is_some() && !self.contains(TinesPermission::ActionsRead))
            || (scope.event.is_some() && !self.contains(TinesPermission::EventsRead))
            || (scope.case_id.is_some() && !self.contains(TinesPermission::CasesRead))
        {
            return Err(TinesAutomationResultError::InvalidPermissionSet);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TinesReadOperation {
    GetStory,
    GetStoryRunSummary,
    GetAction,
    GetEvent,
    GetCase,
    ListAuditLogs,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TinesHttpMethod {
    Get,
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
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TinesEvidenceState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
    Expired,
    AccessLost,
    RateLimited,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    BoundedObservation,
    Partial,
    AccessLost,
    RateLimited,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesStorySummary {
    pub id: StoryId,
    pub revision: Revision,
    pub mode_digest: Option<Digest>,
    pub published: Option<bool>,
    pub disabled: Option<bool>,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesActionSummary {
    pub id: ActionId,
    pub story_id: StoryId,
    pub revision: Revision,
    pub disabled: Option<bool>,
    pub event_count: Option<u64>,
    pub last_event_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesStoryRunSummary {
    pub guid: StoryRunGuid,
    pub story_id: StoryId,
    pub revision: Revision,
    pub state: TinesEvidenceState,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u64>,
    pub action_count: u64,
    pub event_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesEventSummary {
    pub id: EventId,
    pub action_id: ActionId,
    pub story_run: Option<StoryRunGuid>,
    pub revision: Revision,
    pub observed_at: Option<DateTime<Utc>>,
    pub payload_digest: Digest,
    pub re_emitted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesCaseSummary {
    pub id: CaseId,
    pub revision: Revision,
    pub state_digest: Option<Digest>,
    pub opened_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub item_count: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesAuditLogSummary {
    pub id: String,
    pub revision: Revision,
    pub story_id: Option<StoryId>,
    pub created_at: Option<DateTime<Utc>>,
    pub operation_digest: Digest,
    pub actor_digest: Option<Digest>,
    pub inputs_digest: Option<Digest>,
    pub outputs_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesRateLimitReceipt {
    pub status: u16,
    pub retry_after_seconds: Option<u32>,
    pub response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesAutomationEvidence {
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub request_digests: Vec<Digest>,
    pub response_digests: Vec<Digest>,
    pub story: Option<TinesStorySummary>,
    pub story_run: Option<TinesStoryRunSummary>,
    pub action: Option<TinesActionSummary>,
    pub event: Option<TinesEventSummary>,
    pub case_summary: Option<TinesCaseSummary>,
    pub audit_logs: Vec<TinesAuditLogSummary>,
    pub state: TinesEvidenceState,
    pub classification: EvidenceClassification,
    pub partial: bool,
    pub pages_read: u16,
    pub response_bytes: usize,
    pub rate_limit: Option<TinesRateLimitReceipt>,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl TinesAutomationEvidence {
    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.evidence_digest.clear();
        canonical_digest(&copy)
    }

    #[must_use]
    pub fn seal(mut self) -> Self {
        self.evidence_digest = self.calculate_digest();
        self
    }

    pub fn validate_integrity(
        &self,
        scope: &TinesAutomationScope,
        provider_digest: &str,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.provider_digest != provider_digest
            || self.evidence_digest != self.calculate_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.request_digests.len() > MAX_REQUESTS_PER_READ
            || self.audit_logs.len() > MAX_AUDIT_LOGS
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(TinesAutomationResultError::TamperedEvidence);
        }
        if let Some(story) = &self.story {
            if story.id != *scope.story() {
                return Err(TinesAutomationResultError::ScopeMismatch);
            }
            if let Some(timestamp) = story.observed_at {
                if !scope.time_window().contains(timestamp) {
                    return Err(TinesAutomationResultError::OutOfScopeTime);
                }
            }
        }
        if let Some(run) = &self.story_run {
            if run.story_id != *scope.story()
                || scope
                    .story_run()
                    .is_some_and(|expected| expected != &run.guid)
            {
                return Err(TinesAutomationResultError::ScopeMismatch);
            }
            for timestamp in [run.start_time, run.end_time].into_iter().flatten() {
                if !scope.time_window().contains(timestamp) {
                    return Err(TinesAutomationResultError::OutOfScopeTime);
                }
            }
        }
        if let Some(action) = &self.action {
            if action.story_id != *scope.story()
                || scope
                    .action()
                    .is_some_and(|expected| expected != &action.id)
            {
                return Err(TinesAutomationResultError::ScopeMismatch);
            }
            if let Some(timestamp) = action.last_event_at {
                if !scope.time_window().contains(timestamp) {
                    return Err(TinesAutomationResultError::OutOfScopeTime);
                }
            }
        }
        if let Some(event) = &self.event {
            if scope.event().is_some_and(|expected| expected != &event.id)
                || scope
                    .action()
                    .is_some_and(|expected| expected != &event.action_id)
                || (scope.story_run().is_some() && event.story_run.as_ref() != scope.story_run())
            {
                return Err(TinesAutomationResultError::ScopeMismatch);
            }
            if let Some(timestamp) = event.observed_at {
                if !scope.time_window().contains(timestamp) {
                    return Err(TinesAutomationResultError::OutOfScopeTime);
                }
            }
        }
        if let Some(case_summary) = &self.case_summary {
            if scope
                .case_id()
                .is_some_and(|expected| expected != &case_summary.id)
            {
                return Err(TinesAutomationResultError::ScopeMismatch);
            }
            for timestamp in [case_summary.opened_at, case_summary.closed_at]
                .into_iter()
                .flatten()
            {
                if !scope.time_window().contains(timestamp) {
                    return Err(TinesAutomationResultError::OutOfScopeTime);
                }
            }
        }
        for audit_log in &self.audit_logs {
            if let Some(story_id) = &audit_log.story_id {
                if story_id != scope.story() {
                    return Err(TinesAutomationResultError::ScopeMismatch);
                }
            }
            if let Some(timestamp) = audit_log.created_at {
                if !scope.time_window().contains(timestamp) {
                    return Err(TinesAutomationResultError::OutOfScopeTime);
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesRegistration {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub generation: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl TinesRegistration {
    pub fn new(
        contract_version: &str,
        contract_digest: &str,
        provider_id: &str,
        provider_version: &str,
        provider_digest: &str,
        scope: &TinesAutomationScope,
        secret: &SecretReference,
    ) -> Result<Self> {
        let mut registration = Self {
            contract_version: contract_version.to_owned(),
            contract_digest: contract_digest.to_owned(),
            provider_id: provider_id.to_owned(),
            provider_version: provider_version.to_owned(),
            provider_digest: provider_digest.to_owned(),
            scope_digest: scope.digest(),
            permission_digest: scope.permissions().digest(),
            secret_reference_digest: secret.digest().clone(),
            evidence_binding_digest: sha256_hex(
                format!("tines-evidence-binding/v1|{}", scope.digest()).as_bytes(),
            ),
            generation: 1,
            state: RegistrationState::Active,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.registration_digest.clear();
        canonical_digest(&copy)
    }

    pub fn validate(
        &self,
        scope: &TinesAutomationScope,
        secret: &SecretReference,
        provider_digest: &str,
    ) -> Result<()> {
        if self.registration_digest != self.calculate_digest()
            || self.contract_digest != crate::contract_digest()
            || self.contract_version != crate::CONTRACT_VERSION
            || self.provider_digest != provider_digest
            || self.provider_id != crate::PROVIDER_ID
            || self.provider_version != crate::PROVIDER_VERSION
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permissions().digest()
            || self.secret_reference_digest != *secret.digest()
        {
            return Err(TinesAutomationResultError::TamperedEvidence);
        }
        if !matches!(self.state, RegistrationState::Active) {
            return Err(TinesAutomationResultError::RegistrationInactive);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    fn rotate(&mut self, state: RegistrationState) -> RegistrationRevocationReceipt {
        let previous = self.registration_digest.clone();
        self.generation = self.generation.saturating_add(1);
        self.state = state;
        self.registration_digest = self.calculate_digest();
        RegistrationRevocationReceipt {
            previous_registration_digest: previous,
            registration_digest: self.registration_digest.clone(),
            generation: self.generation,
            reversible: true,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn revoke(&mut self) -> RegistrationRevocationReceipt {
        self.rotate(RegistrationState::Revoked)
    }

    pub fn restore(&mut self) -> RegistrationRevocationReceipt {
        self.rotate(RegistrationState::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub generation: u64,
    pub reversible: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesAutomationProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub state: TinesEvidenceState,
    pub evidence: TinesAutomationEvidence,
    pub review_only: bool,
    pub non_mutating: bool,
    pub claims_external_side_effect: bool,
    pub claims_remediation_success: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl TinesAutomationProposal {
    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        canonical_digest(&copy)
    }

    #[must_use]
    pub fn seal(mut self) -> Self {
        self.proposal_digest = self.calculate_digest();
        self
    }

    pub fn validate_integrity(
        &self,
        scope: &TinesAutomationScope,
        registration: &TinesRegistration,
    ) -> Result<()> {
        if self.proposal_digest != self.calculate_digest()
            || self.contract_digest != crate::contract_digest()
            || self.service_id != crate::SERVICE_ID
            || self.provider_id != crate::PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != scope.digest()
            || self.evidence.scope_digest != scope.digest()
            || self.project != *scope.project()
            || self.mission != *scope.mission()
            || self.work_product != *scope.work_product()
            || self.state != self.evidence.state
            || !self.review_only
            || !self.non_mutating
            || self.claims_external_side_effect
            || self.claims_remediation_success
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(TinesAutomationResultError::TamperedEvidence);
        }
        self.evidence
            .validate_integrity(scope, &registration.provider_digest)
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable: bool,
    pub provider_receipt: bool,
    pub independent_native_readback: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}
