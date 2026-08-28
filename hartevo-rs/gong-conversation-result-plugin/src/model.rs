//! Typed, bounded Gong scope and normalized read evidence.
//!
//! No type in this module can hold an access key, transcript, recording,
//! media URL, participant PII, comment, or raw CRM object. Provider payloads
//! cross the seam only after being reduced to the allowlisted projections.

use std::{fmt, str::FromStr};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GONG_API_VERSION, GONG_CONVERSATION_RESULT_CONTRACT_VERSION,
    GONG_CONVERSATION_RESULT_PLUGIN_VERSION_TEXT, GONG_DAILY_REQUEST_LIMIT, GONG_MAX_ACTION_ITEMS,
    GONG_MAX_CONTEXTS, GONG_MAX_DATE_WINDOW_DAYS, GONG_MAX_PAGES, GONG_MAX_RESPONSE_BYTES,
    GONG_MAX_SCORECARDS, GONG_MAX_TOPICS, GONG_MAX_TRACKERS, GONG_MAX_USERS, GONG_PAGE_SIZE,
    GONG_PROVIDER_REVISION, GONG_REQUESTS_PER_SECOND,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_EXTERNAL_SYSTEM_LENGTH: usize = 128;
pub const MAX_RESPONSE_KIND_LENGTH: usize = 64;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains whitespace")]
    Whitespace { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    Invalid { field: &'static str },
    #[error("{field} exceeds its bounded cardinality")]
    TooMany { field: &'static str },
    #[error("date window is invalid")]
    InvalidDateWindow,
    #[error("date window exceeds {max_days} days")]
    DateWindowTooLarge { max_days: i64 },
    #[error("Gong API version must be {expected}")]
    InvalidApiVersion { expected: &'static str },
    #[error("Gong provider revision must be {expected}")]
    InvalidProviderRevision { expected: &'static str },
    #[error("response exceeds the {max_bytes}-byte bound")]
    ResponseTooLarge { max_bytes: usize },
    #[error("page is outside the 1..={max_pages} bound")]
    InvalidPage { max_pages: u8 },
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Whitespace { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

fn validate_bounded<T>(values: &[T], max: usize, field: &'static str) -> Result<(), ModelError> {
    if values.len() > max {
        Err(ModelError::TooMany { field })
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
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_LENGTH, false)?;
                Ok(Self(value))
            }

            #[must_use]
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
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

bounded_identifier!(AccountId, "Gong account id");
bounded_identifier!(TeamId, "Gong team id");
bounded_identifier!(UserId, "Gong user id");
bounded_identifier!(CallId, "Gong call id");
bounded_identifier!(MeetingId, "Gong meeting id");
bounded_identifier!(DealId, "Gong deal id");
bounded_identifier!(ContextId, "conversation context id");
bounded_identifier!(ScorecardId, "Gong scorecard id");
bounded_identifier!(TrackerId, "Gong tracker id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(ConsentId, "Consent id");
bounded_identifier!(ExternalObjectId, "external object id");

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
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

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest(format!("{:x}", Sha256::digest(bytes)))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded Gong values serialize");
    sha256_digest(&bytes)
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_digest: Digest,
    credential_revision: Revision,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

impl SecretReference {
    /// Creates a reference from a host-owned opaque label. The label is
    /// immediately digested and is never retained, serialized, or exposed.
    pub fn new(
        opaque_reference: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.into();
        validate_text(
            &opaque_reference,
            "opaque Gong secret reference",
            MAX_IDENTIFIER_LENGTH,
            false,
        )?;
        let revision = Revision::new(credential_revision)?;
        let reference_digest =
            sha256_digest(format!("gong-secret-reference/v1:{opaque_reference}").as_bytes());
        Ok(Self {
            reference_digest,
            credential_revision: revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Granted,
    Pending,
    Withdrawn,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::parse(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        MissionId::parse(self.id.as_str())?;
        Revision::new(self.revision.get())?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::parse(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        ProjectId::parse(self.id.as_str())?;
        Revision::new(self.revision.get())?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id: ConsentId,
    pub revision: Revision,
    pub state: ConsentState,
}

impl ConsentScope {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        state: ConsentState,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            id: ConsentId::parse(id)?,
            revision: Revision::new(revision)?,
            state,
        })
    }

    #[must_use]
    pub fn is_granted(&self) -> bool {
        self.state == ConsentState::Granted
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        ConsentId::parse(self.id.as_str())?;
        Revision::new(self.revision.get())?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongConversationScopeInput {
    pub account_id: String,
    pub team_id: String,
    pub user_ids: Vec<String>,
    pub call_id: String,
    pub call_revision: u64,
    pub meeting_id: Option<String>,
    pub deal_id: Option<String>,
    pub context_ids: Vec<String>,
    pub context_revision: u64,
    pub scorecard_ids: Vec<String>,
    pub scorecard_revision: u64,
    pub tracker_ids: Vec<String>,
    pub analysis_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub consent_id: String,
    pub consent_revision: u64,
    pub consent_state: ConsentState,
}

pub type GongConversationScopeSpec = GongConversationScopeInput;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongConversationScope {
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub user_ids: Vec<UserId>,
    pub call_id: CallId,
    pub call_revision: Revision,
    pub meeting_id: Option<MeetingId>,
    pub deal_id: Option<DealId>,
    pub context_ids: Vec<ContextId>,
    pub context_revision: Revision,
    pub scorecard_ids: Vec<ScorecardId>,
    pub scorecard_revision: Revision,
    pub tracker_ids: Vec<TrackerId>,
    pub analysis_revision: Revision,
    pub mission: MissionScope,
    pub project: ProjectScope,
    pub consent: ConsentScope,
}

impl GongConversationScope {
    pub fn new(input: GongConversationScopeInput) -> Result<Self, ModelError> {
        validate_bounded(&input.user_ids, GONG_MAX_USERS, "user ids")?;
        validate_bounded(&input.context_ids, GONG_MAX_CONTEXTS, "context ids")?;
        validate_bounded(&input.scorecard_ids, GONG_MAX_SCORECARDS, "scorecard ids")?;
        validate_bounded(&input.tracker_ids, GONG_MAX_TRACKERS, "tracker ids")?;
        let scope = Self {
            account_id: AccountId::parse(input.account_id)?,
            team_id: TeamId::parse(input.team_id)?,
            user_ids: input
                .user_ids
                .into_iter()
                .map(UserId::parse)
                .collect::<Result<Vec<_>, _>>()?,
            call_id: CallId::parse(input.call_id)?,
            call_revision: Revision::new(input.call_revision)?,
            meeting_id: input.meeting_id.map(MeetingId::parse).transpose()?,
            deal_id: input.deal_id.map(DealId::parse).transpose()?,
            context_ids: input
                .context_ids
                .into_iter()
                .map(ContextId::parse)
                .collect::<Result<Vec<_>, _>>()?,
            context_revision: Revision::new(input.context_revision)?,
            scorecard_ids: input
                .scorecard_ids
                .into_iter()
                .map(ScorecardId::parse)
                .collect::<Result<Vec<_>, _>>()?,
            scorecard_revision: Revision::new(input.scorecard_revision)?,
            tracker_ids: input
                .tracker_ids
                .into_iter()
                .map(TrackerId::parse)
                .collect::<Result<Vec<_>, _>>()?,
            analysis_revision: Revision::new(input.analysis_revision)?,
            mission: MissionScope::new(input.mission_id, input.mission_revision)?,
            project: ProjectScope::new(input.project_id, input.project_revision)?,
            consent: ConsentScope::new(
                input.consent_id,
                input.consent_revision,
                input.consent_state,
            )?,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        AccountId::parse(self.account_id.as_str())?;
        TeamId::parse(self.team_id.as_str())?;
        validate_bounded(&self.user_ids, GONG_MAX_USERS, "user ids")?;
        for user_id in &self.user_ids {
            UserId::parse(user_id.as_str())?;
        }
        CallId::parse(self.call_id.as_str())?;
        if let Some(meeting_id) = &self.meeting_id {
            MeetingId::parse(meeting_id.as_str())?;
        }
        if let Some(deal_id) = &self.deal_id {
            DealId::parse(deal_id.as_str())?;
        }
        validate_bounded(&self.context_ids, GONG_MAX_CONTEXTS, "context ids")?;
        for context_id in &self.context_ids {
            ContextId::parse(context_id.as_str())?;
        }
        validate_bounded(&self.scorecard_ids, GONG_MAX_SCORECARDS, "scorecard ids")?;
        for scorecard_id in &self.scorecard_ids {
            ScorecardId::parse(scorecard_id.as_str())?;
        }
        Revision::new(self.context_revision.get())?;
        Revision::new(self.scorecard_revision.get())?;
        validate_bounded(&self.tracker_ids, GONG_MAX_TRACKERS, "tracker ids")?;
        for tracker_id in &self.tracker_ids {
            TrackerId::parse(tracker_id.as_str())?;
        }
        Revision::new(self.call_revision.get())?;
        Revision::new(self.analysis_revision.get())?;
        self.mission.validate()?;
        self.project.validate()?;
        self.consent.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    #[must_use]
    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    #[must_use]
    pub fn user_ids(&self) -> &[UserId] {
        &self.user_ids
    }

    #[must_use]
    pub fn call_id(&self) -> &CallId {
        &self.call_id
    }

    #[must_use]
    pub const fn call_revision(&self) -> Revision {
        self.call_revision
    }

    #[must_use]
    pub fn meeting_id(&self) -> Option<&MeetingId> {
        self.meeting_id.as_ref()
    }

    #[must_use]
    pub fn deal_id(&self) -> Option<&DealId> {
        self.deal_id.as_ref()
    }

    #[must_use]
    pub fn context_ids(&self) -> &[ContextId] {
        &self.context_ids
    }

    #[must_use]
    pub const fn context_revision(&self) -> Revision {
        self.context_revision
    }

    #[must_use]
    pub fn scorecard_ids(&self) -> &[ScorecardId] {
        &self.scorecard_ids
    }

    #[must_use]
    pub const fn scorecard_revision(&self) -> Revision {
        self.scorecard_revision
    }

    #[must_use]
    pub fn tracker_ids(&self) -> &[TrackerId] {
        &self.tracker_ids
    }

    #[must_use]
    pub const fn analysis_revision(&self) -> Revision {
        self.analysis_revision
    }

    #[must_use]
    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    #[must_use]
    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateWindow {
    pub from: String,
    pub until: String,
}

impl DateWindow {
    pub fn new(from: impl Into<String>, until: impl Into<String>) -> Result<Self, ModelError> {
        let window = Self {
            from: from.into(),
            until: until.into(),
        };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let from = NaiveDate::parse_from_str(&self.from, "%Y-%m-%d")
            .map_err(|_| ModelError::InvalidDateWindow)?;
        let until = NaiveDate::parse_from_str(&self.until, "%Y-%m-%d")
            .map_err(|_| ModelError::InvalidDateWindow)?;
        let days = (until - from).num_days();
        if days < 0 {
            return Err(ModelError::InvalidDateWindow);
        }
        if days > GONG_MAX_DATE_WINDOW_DAYS {
            return Err(ModelError::DateWindowTooLarge {
                max_days: GONG_MAX_DATE_WINDOW_DAYS,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GongReadOperation {
    CallMetadata,
    InteractionMetrics,
    TopicsTrackers,
    ActionItemCounts,
    ScorecardStatus,
    ExternalCrmContextIdentifiers,
}

impl GongReadOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallMetadata => "call_metadata",
            Self::InteractionMetrics => "interaction_metrics",
            Self::TopicsTrackers => "topics_trackers",
            Self::ActionItemCounts => "action_item_counts",
            Self::ScorecardStatus => "scorecard_status",
            Self::ExternalCrmContextIdentifiers => "external_crm_context_identifiers",
        }
    }

    #[must_use]
    pub const fn endpoint_path(self) -> &'static str {
        match self {
            Self::CallMetadata => "/v2/calls",
            Self::InteractionMetrics => "/v2/stats/interaction",
            Self::TopicsTrackers => "/v2/calls/extensive",
            Self::ActionItemCounts => "/v2/calls/extensive",
            Self::ScorecardStatus => "/v2/stats/activity/scorecards",
            Self::ExternalCrmContextIdentifiers => "/v2/crm/entities",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongReadRequest {
    pub operation: GongReadOperation,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub user_ids: Vec<UserId>,
    pub call_id: CallId,
    pub call_revision: Revision,
    pub meeting_id: Option<MeetingId>,
    pub deal_id: Option<DealId>,
    pub context_ids: Vec<ContextId>,
    pub context_revision: Revision,
    pub scorecard_ids: Vec<ScorecardId>,
    pub scorecard_revision: Revision,
    pub tracker_ids: Vec<TrackerId>,
    pub analysis_revision: Revision,
    pub date_window: Option<DateWindow>,
    pub page: u8,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub provider_capability_digest: Digest,
    pub requested_at_epoch_seconds: u64,
    pub request_digest: Digest,
}

impl GongReadRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn bound(
        scope: &GongConversationScope,
        operation: GongReadOperation,
        date_window: Option<DateWindow>,
        secret: &SecretReference,
        registration_digest: &Digest,
        provider_capability_digest: &Digest,
        requested_at_epoch_seconds: u64,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if let Some(window) = &date_window {
            window.validate()?;
        }
        let mut request = Self {
            operation,
            account_id: scope.account_id.clone(),
            team_id: scope.team_id.clone(),
            user_ids: scope.user_ids.clone(),
            call_id: scope.call_id.clone(),
            call_revision: scope.call_revision,
            meeting_id: scope.meeting_id.clone(),
            deal_id: scope.deal_id.clone(),
            context_ids: scope.context_ids.clone(),
            context_revision: scope.context_revision,
            scorecard_ids: scope.scorecard_ids.clone(),
            scorecard_revision: scope.scorecard_revision,
            tracker_ids: scope.tracker_ids.clone(),
            analysis_revision: scope.analysis_revision,
            date_window,
            page: 1,
            page_size: GONG_PAGE_SIZE,
            max_response_bytes: GONG_MAX_RESPONSE_BYTES,
            consent_digest: scope.consent.digest(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret.digest().clone(),
            registration_digest: registration_digest.clone(),
            provider_capability_digest: provider_capability_digest.clone(),
            requested_at_epoch_seconds,
            request_digest: sha256_digest(b"uninitialized-gong-request"),
        };
        request.request_digest = request.computed_digest();
        request.validate_against(
            scope,
            secret,
            registration_digest,
            provider_capability_digest,
        )?;
        Ok(request)
    }

    pub fn for_page(&self, page: u8) -> Result<Self, ModelError> {
        if !(1..=GONG_MAX_PAGES).contains(&page) {
            return Err(ModelError::InvalidPage {
                max_pages: GONG_MAX_PAGES,
            });
        }
        let mut request = self.clone();
        request.page = page;
        request.request_digest = request.computed_digest();
        Ok(request)
    }

    pub fn validate_against(
        &self,
        scope: &GongConversationScope,
        secret: &SecretReference,
        registration_digest: &Digest,
        provider_capability_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        self.date_window
            .as_ref()
            .map(DateWindow::validate)
            .transpose()?;
        if !(1..=GONG_MAX_PAGES).contains(&self.page) || self.page_size != GONG_PAGE_SIZE {
            return Err(ModelError::InvalidPage {
                max_pages: GONG_MAX_PAGES,
            });
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > GONG_MAX_RESPONSE_BYTES {
            return Err(ModelError::ResponseTooLarge {
                max_bytes: GONG_MAX_RESPONSE_BYTES,
            });
        }
        if self.account_id != scope.account_id
            || self.team_id != scope.team_id
            || self.user_ids != scope.user_ids
            || self.call_id != scope.call_id
            || self.call_revision != scope.call_revision
            || self.meeting_id != scope.meeting_id
            || self.deal_id != scope.deal_id
            || self.context_ids != scope.context_ids
            || self.context_revision != scope.context_revision
            || self.scorecard_ids != scope.scorecard_ids
            || self.scorecard_revision != scope.scorecard_revision
            || self.tracker_ids != scope.tracker_ids
            || self.analysis_revision != scope.analysis_revision
            || self.scope_digest != scope.digest()
            || self.consent_digest != scope.consent.digest()
            || self.secret_reference_digest != *secret.digest()
            || self.registration_digest != *registration_digest
            || self.provider_capability_digest != *provider_capability_digest
            || self.request_digest != self.computed_digest()
        {
            return Err(ModelError::Invalid {
                field: "Gong request scope or digest fence",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn endpoint_path(&self) -> &'static str {
        self.operation.endpoint_path()
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        let date_query = self
            .date_window
            .as_ref()
            .map(|window| format!("&fromDateTime={}&toDateTime={}", window.from, window.until))
            .unwrap_or_default();
        format!(
            "{}?page={}&pageSize={}{}&apiVersion={}",
            self.endpoint_path(),
            self.page,
            self.page_size,
            date_query,
            GONG_API_VERSION
        )
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn integrity_digest(&self) -> Digest {
        self.computed_digest()
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&GongReadRequestFingerprint {
            operation: self.operation,
            account_id: &self.account_id,
            team_id: &self.team_id,
            user_ids: &self.user_ids,
            call_id: &self.call_id,
            call_revision: self.call_revision,
            meeting_id: self.meeting_id.as_ref(),
            deal_id: self.deal_id.as_ref(),
            context_ids: &self.context_ids,
            context_revision: self.context_revision,
            scorecard_ids: &self.scorecard_ids,
            scorecard_revision: self.scorecard_revision,
            tracker_ids: &self.tracker_ids,
            analysis_revision: self.analysis_revision,
            date_window: self.date_window.as_ref(),
            page: self.page,
            page_size: self.page_size,
            max_response_bytes: self.max_response_bytes,
            consent_digest: &self.consent_digest,
            scope_digest: &self.scope_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_digest: &self.registration_digest,
            provider_capability_digest: &self.provider_capability_digest,
            requested_at_epoch_seconds: self.requested_at_epoch_seconds,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GongReadRequestFingerprint<'a> {
    operation: GongReadOperation,
    account_id: &'a AccountId,
    team_id: &'a TeamId,
    user_ids: &'a [UserId],
    call_id: &'a CallId,
    call_revision: Revision,
    meeting_id: Option<&'a MeetingId>,
    deal_id: Option<&'a DealId>,
    context_ids: &'a [ContextId],
    context_revision: Revision,
    scorecard_ids: &'a [ScorecardId],
    scorecard_revision: Revision,
    tracker_ids: &'a [TrackerId],
    analysis_revision: Revision,
    date_window: Option<&'a DateWindow>,
    page: u8,
    page_size: u16,
    max_response_bytes: usize,
    consent_digest: &'a Digest,
    scope_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_capability_digest: &'a Digest,
    requested_at_epoch_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GongAnalysisStatus {
    Analyzed,
    Processing,
    RetentionGap,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallMetadata {
    pub call_id: CallId,
    pub meeting_id: Option<MeetingId>,
    pub deal_id: Option<DealId>,
    pub duration_seconds: Option<u32>,
    pub status: GongAnalysisStatus,
    pub call_revision: Revision,
    pub analysis_revision: Revision,
}

impl CallMetadata {
    pub fn validate_against(&self, scope: &GongConversationScope) -> Result<(), ModelError> {
        if self.call_id != scope.call_id
            || self.meeting_id != scope.meeting_id
            || self.deal_id != scope.deal_id
            || self.call_revision != scope.call_revision
            || self.analysis_revision != scope.analysis_revision
            || self
                .duration_seconds
                .is_some_and(|seconds| seconds > 86_400)
        {
            return Err(ModelError::Invalid {
                field: "call metadata scope or bound",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InteractionMetrics {
    pub talk_time_seconds: Option<u32>,
    pub question_count: u16,
    pub interruption_count: u16,
    pub monologue_count: u16,
    pub speaker_count: Option<u16>,
}

impl InteractionMetrics {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self
            .talk_time_seconds
            .is_some_and(|seconds| seconds > 86_400)
            || self.question_count > 10_000
            || self.interruption_count > 10_000
            || self.monologue_count > 10_000
            || self.speaker_count.is_some_and(|count| count > 1_024)
        {
            return Err(ModelError::Invalid {
                field: "interaction metric bound",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TopicTrackerSignal {
    pub tracker_id: TrackerId,
    pub topic_digest: Option<Digest>,
    pub match_count: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TopicsAndTrackers {
    pub signals: Vec<TopicTrackerSignal>,
}

impl TopicsAndTrackers {
    pub fn validate_against(&self, scope: &GongConversationScope) -> Result<(), ModelError> {
        validate_bounded(&self.signals, GONG_MAX_TOPICS, "topic and tracker signals")?;
        for signal in &self.signals {
            if !scope.tracker_ids.contains(&signal.tracker_id)
                || usize::from(signal.match_count) > GONG_MAX_ACTION_ITEMS
            {
                return Err(ModelError::Invalid {
                    field: "topic or tracker signal scope",
                });
            }
            if let Some(digest) = &signal.topic_digest {
                Digest::parse(digest.as_str())?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionItemCounts {
    pub total: u16,
    pub open: u16,
    pub completed: u16,
}

impl ActionItemCounts {
    pub fn validate(&self) -> Result<(), ModelError> {
        if usize::from(self.total) > GONG_MAX_ACTION_ITEMS
            || self.open > self.total
            || self.completed > self.total
            || self.open.saturating_add(self.completed) > self.total
        {
            return Err(ModelError::Invalid {
                field: "action item count",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScorecardEvaluationStatus {
    NotStarted,
    InProgress,
    Complete,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScorecardStatus {
    pub scorecard_id: ScorecardId,
    pub scorecard_revision: Revision,
    pub status: ScorecardEvaluationStatus,
    pub answered_items: u16,
    pub total_items: u16,
}

impl ScorecardStatus {
    pub fn validate_against(&self, scope: &GongConversationScope) -> Result<(), ModelError> {
        if !scope.scorecard_ids.contains(&self.scorecard_id)
            || self.scorecard_revision != scope.scorecard_revision
            || self.answered_items > self.total_items
            || usize::from(self.total_items) > GONG_MAX_ACTION_ITEMS
        {
            return Err(ModelError::Invalid {
                field: "scorecard status scope or bound",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ExternalSystem(String);

impl ExternalSystem {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(
            &value,
            "external CRM system",
            MAX_EXTERNAL_SYSTEM_LENGTH,
            false,
        )?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalCrmContextIdentifier {
    pub context_id: ContextId,
    pub external_system: ExternalSystem,
    pub external_object_id: ExternalObjectId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalCrmContextIdentifiers {
    pub deal_id: DealId,
    pub context_revision: Revision,
    pub identifiers: Vec<ExternalCrmContextIdentifier>,
}

impl ExternalCrmContextIdentifiers {
    pub fn validate_against(&self, scope: &GongConversationScope) -> Result<(), ModelError> {
        let deal_id = scope.deal_id.as_ref().ok_or(ModelError::Invalid {
            field: "deal scope for external CRM identifiers",
        })?;
        if &self.deal_id != deal_id || self.context_revision != scope.context_revision {
            return Err(ModelError::Invalid {
                field: "external CRM deal scope",
            });
        }
        validate_bounded(
            &self.identifiers,
            GONG_MAX_CONTEXTS,
            "external CRM identifiers",
        )?;
        for identifier in &self.identifiers {
            if !scope.context_ids.contains(&identifier.context_id) {
                return Err(ModelError::Invalid {
                    field: "external CRM context scope",
                });
            }
            ExternalSystem::parse(identifier.external_system.as_str())?;
            ExternalObjectId::parse(identifier.external_object_id.as_str())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GongReadPayload {
    CallMetadata(CallMetadata),
    InteractionMetrics(InteractionMetrics),
    TopicsTrackers(TopicsAndTrackers),
    ActionItemCounts(ActionItemCounts),
    ScorecardStatus(ScorecardStatus),
    ExternalCrmContextIdentifiers(ExternalCrmContextIdentifiers),
    Empty,
}

impl GongReadPayload {
    #[must_use]
    pub const fn operation(&self) -> Option<GongReadOperation> {
        match self {
            Self::CallMetadata(_) => Some(GongReadOperation::CallMetadata),
            Self::InteractionMetrics(_) => Some(GongReadOperation::InteractionMetrics),
            Self::TopicsTrackers(_) => Some(GongReadOperation::TopicsTrackers),
            Self::ActionItemCounts(_) => Some(GongReadOperation::ActionItemCounts),
            Self::ScorecardStatus(_) => Some(GongReadOperation::ScorecardStatus),
            Self::ExternalCrmContextIdentifiers(_) => {
                Some(GongReadOperation::ExternalCrmContextIdentifiers)
            }
            Self::Empty => None,
        }
    }

    pub fn validate_against(
        &self,
        operation: GongReadOperation,
        scope: &GongConversationScope,
    ) -> Result<(), ModelError> {
        if let Some(payload_operation) = self.operation()
            && payload_operation != operation
        {
            return Err(ModelError::Invalid {
                field: "Gong response operation",
            });
        }
        match self {
            Self::CallMetadata(value) => value.validate_against(scope),
            Self::InteractionMetrics(value) => value.validate(),
            Self::TopicsTrackers(value) => value.validate_against(scope),
            Self::ActionItemCounts(value) => value.validate(),
            Self::ScorecardStatus(value) => value.validate_against(scope),
            Self::ExternalCrmContextIdentifiers(value) => value.validate_against(scope),
            Self::Empty => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GongReadStatus {
    Analyzed,
    Processing,
    RetentionGap,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongResponseReceipt {
    pub operation: GongReadOperation,
    pub allowlisted_path: String,
    pub request_digest: Digest,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub raw_provider_payload_retained: bool,
    pub transcript_retained: bool,
    pub audio_retained: bool,
    pub media_urls_retained: bool,
    pub participant_pii_retained: bool,
    pub phone_numbers_retained: bool,
    pub comments_retained: bool,
    pub raw_crm_objects_retained: bool,
    pub credential_material_retained: bool,
}

impl GongResponseReceipt {
    pub fn validate(
        &self,
        request: &GongReadRequest,
        response_digest: &Digest,
    ) -> Result<(), ModelError> {
        validate_text(
            &self.allowlisted_path,
            "allowlisted receipt path",
            MAX_RESPONSE_KIND_LENGTH,
            false,
        )?;
        if self.operation != request.operation
            || self.allowlisted_path != request.endpoint_path()
            || self.request_digest != request.request_digest
            || self.response_digest != *response_digest
            || self.response_size > request.max_response_bytes
            || self.provider_revision != GONG_PROVIDER_REVISION
            || self.raw_provider_payload_retained
            || self.transcript_retained
            || self.audio_retained
            || self.media_urls_retained
            || self.participant_pii_retained
            || self.phone_numbers_retained
            || self.comments_retained
            || self.raw_crm_objects_retained
            || self.credential_material_retained
        {
            return Err(ModelError::Invalid {
                field: "redacted Gong response receipt",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongReadResponse {
    pub operation: GongReadOperation,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub provider_capability_digest: Digest,
    pub page: u8,
    pub complete: bool,
    pub status: GongReadStatus,
    pub payload: GongReadPayload,
    pub response_size: usize,
    pub response_digest: Digest,
    pub receipt: GongResponseReceipt,
}

impl GongReadResponse {
    pub fn new(
        request: &GongReadRequest,
        status: GongReadStatus,
        payload: GongReadPayload,
        complete: bool,
    ) -> Result<Self, ModelError> {
        payload.validate_against(request.operation, &scope_from_request(request)?)?;
        let response_size = serde_json::to_vec(&payload)
            .map_err(|_| ModelError::Invalid {
                field: "response payload",
            })?
            .len();
        Self::with_size(request, status, payload, complete, response_size)
    }

    pub fn with_size(
        request: &GongReadRequest,
        status: GongReadStatus,
        payload: GongReadPayload,
        complete: bool,
        response_size: usize,
    ) -> Result<Self, ModelError> {
        if response_size > request.max_response_bytes || response_size > GONG_MAX_RESPONSE_BYTES {
            return Err(ModelError::ResponseTooLarge {
                max_bytes: GONG_MAX_RESPONSE_BYTES,
            });
        }
        let mut response = Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            consent_digest: request.consent_digest.clone(),
            secret_reference_digest: request.secret_reference_digest.clone(),
            registration_digest: request.registration_digest.clone(),
            provider_capability_digest: request.provider_capability_digest.clone(),
            page: request.page,
            complete,
            status,
            payload,
            response_size,
            response_digest: sha256_digest(b"uninitialized-gong-response"),
            receipt: GongResponseReceipt {
                operation: request.operation,
                allowlisted_path: request.endpoint_path().to_owned(),
                request_digest: request.request_digest.clone(),
                response_status: 200,
                response_size,
                response_digest: sha256_digest(b"uninitialized-gong-receipt"),
                provider_revision: GONG_PROVIDER_REVISION.to_owned(),
                raw_provider_payload_retained: false,
                transcript_retained: false,
                audio_retained: false,
                media_urls_retained: false,
                participant_pii_retained: false,
                phone_numbers_retained: false,
                comments_retained: false,
                raw_crm_objects_retained: false,
                credential_material_retained: false,
            },
        };
        response.response_digest = canonical_digest(&GongReadResponseFingerprint {
            operation: response.operation,
            scope_digest: &response.scope_digest,
            consent_digest: &response.consent_digest,
            secret_reference_digest: &response.secret_reference_digest,
            registration_digest: &response.registration_digest,
            provider_capability_digest: &response.provider_capability_digest,
            page: response.page,
            complete: response.complete,
            status: response.status,
            payload: &response.payload,
            response_size: response.response_size,
        });
        response.receipt.response_digest = response.response_digest.clone();
        response
            .receipt
            .validate(request, &response.response_digest)?;
        Ok(response)
    }

    pub fn validate_against(
        &self,
        request: &GongReadRequest,
        scope: &GongConversationScope,
        provider_revision: &str,
    ) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.scope_digest != request.scope_digest
            || self.consent_digest != request.consent_digest
            || self.secret_reference_digest != request.secret_reference_digest
            || self.registration_digest != request.registration_digest
            || self.provider_capability_digest != request.provider_capability_digest
            || self.page != request.page
            || self.response_size > request.max_response_bytes
            || provider_revision != GONG_PROVIDER_REVISION
            || provider_revision != self.receipt.provider_revision
            || self.response_digest != self.computed_digest()
        {
            return Err(ModelError::Invalid {
                field: "Gong response scope or digest fence",
            });
        }
        self.payload.validate_against(self.operation, scope)?;
        self.receipt.validate(request, &self.response_digest)
    }

    pub fn validate_request_binding(
        &self,
        request: &GongReadRequest,
        provider_revision: &str,
    ) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.scope_digest != request.scope_digest
            || self.consent_digest != request.consent_digest
            || self.secret_reference_digest != request.secret_reference_digest
            || self.registration_digest != request.registration_digest
            || self.provider_capability_digest != request.provider_capability_digest
            || self.page != request.page
            || self.response_size > request.max_response_bytes
            || provider_revision != GONG_PROVIDER_REVISION
            || provider_revision != self.receipt.provider_revision
            || self.response_digest != self.computed_digest()
        {
            return Err(ModelError::Invalid {
                field: "Gong response request binding",
            });
        }
        self.receipt.validate(request, &self.response_digest)
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&GongReadResponseFingerprint {
            operation: self.operation,
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_digest: &self.registration_digest,
            provider_capability_digest: &self.provider_capability_digest,
            page: self.page,
            complete: self.complete,
            status: self.status,
            payload: &self.payload,
            response_size: self.response_size,
        })
    }

    #[must_use]
    pub fn is_redacted(&self) -> bool {
        !self.receipt.raw_provider_payload_retained
            && !self.receipt.transcript_retained
            && !self.receipt.audio_retained
            && !self.receipt.media_urls_retained
            && !self.receipt.participant_pii_retained
            && !self.receipt.phone_numbers_retained
            && !self.receipt.comments_retained
            && !self.receipt.raw_crm_objects_retained
            && !self.receipt.credential_material_retained
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GongReadResponseFingerprint<'a> {
    operation: GongReadOperation,
    scope_digest: &'a Digest,
    consent_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_capability_digest: &'a Digest,
    page: u8,
    complete: bool,
    status: GongReadStatus,
    payload: &'a GongReadPayload,
    response_size: usize,
}

/// Reconstructs the scope fields needed to validate a response. The request
/// itself is not a permission authority; this value is used only to verify
/// normalized payload identifiers against the already-bound request.
fn scope_from_request(request: &GongReadRequest) -> Result<GongConversationScope, ModelError> {
    GongConversationScope::new(GongConversationScopeInput {
        account_id: request.account_id.as_str().to_owned(),
        team_id: request.team_id.as_str().to_owned(),
        user_ids: request
            .user_ids
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect(),
        call_id: request.call_id.as_str().to_owned(),
        call_revision: request.call_revision.get(),
        meeting_id: request
            .meeting_id
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        deal_id: request
            .deal_id
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        context_ids: request
            .context_ids
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect(),
        context_revision: request.context_revision.get(),
        scorecard_ids: request
            .scorecard_ids
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect(),
        scorecard_revision: request.scorecard_revision.get(),
        tracker_ids: request
            .tracker_ids
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect(),
        analysis_revision: request.analysis_revision.get(),
        mission_id: "request-mission".to_owned(),
        mission_revision: 1,
        project_id: "request-project".to_owned(),
        project_revision: 1,
        consent_id: "request-consent".to_owned(),
        consent_revision: 1,
        consent_state: ConsentState::Granted,
    })
}

pub fn validate_gong_metadata() -> Result<(), ModelError> {
    if GONG_API_VERSION != "v2"
        || GONG_PROVIDER_REVISION != "gong-api-v2-r1"
        || GONG_CONVERSATION_RESULT_CONTRACT_VERSION != "gong-conversation-result/v1"
        || GONG_CONVERSATION_RESULT_PLUGIN_VERSION_TEXT != "1.0.0"
        || GONG_MAX_RESPONSE_BYTES == 0
        || GONG_MAX_PAGES == 0
        || GONG_PAGE_SIZE == 0
        || GONG_MAX_DATE_WINDOW_DAYS <= 0
        || GONG_REQUESTS_PER_SECOND == 0
        || GONG_DAILY_REQUEST_LIMIT == 0
        || GONG_MAX_USERS == 0
        || GONG_MAX_CONTEXTS == 0
        || GONG_MAX_SCORECARDS == 0
        || GONG_MAX_TRACKERS == 0
        || GONG_MAX_TOPICS == 0
        || GONG_MAX_ACTION_ITEMS == 0
    {
        return Err(ModelError::Invalid {
            field: "Gong metadata",
        });
    }
    Ok(())
}
