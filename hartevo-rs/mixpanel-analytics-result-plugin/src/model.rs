use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION, MIXPANEL_MAX_EVENT_SELECTORS,
    MIXPANEL_MAX_RESPONSE_BYTES, MIXPANEL_PRIVACY_POLICY_VERSION,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_DATE_SUFFIX_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("numeric identifier must be non-zero")]
    InvalidNumericIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("timestamp must be non-negative")]
    InvalidTimestamp,
    #[error("date must be an ISO calendar date")]
    InvalidDate,
    #[error("date suffix is not a bounded Mixpanel timestamp")]
    InvalidDateSuffix,
    #[error("date window must be closed, ordered, and at most 31 days")]
    InvalidDateWindow,
    #[error("at least one event selector is required")]
    EmptyEventSelector,
    #[error("event selector count exceeds the Layer-1 bound")]
    TooManyEventSelectors,
    #[error("event selectors must be unique")]
    DuplicateEventSelector,
    #[error("event selector is not a safe aggregate label")]
    InvalidEventSelector,
    #[error("privacy policy is not the required aggregate-only redaction policy")]
    InvalidPrivacyPolicy,
    #[error("scope digest does not match")]
    ScopeMismatch,
    #[error("secret reference does not match the registered scope")]
    SecretScopeMismatch,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("idempotency key is empty, malformed, or too long")]
    InvalidIdempotencyKey,
    #[error("value exceeds a contract bound")]
    BoundExceeded,
    #[error("digest does not match immutable fields")]
    DigestMismatch,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
            Err(ModelError::InvalidDigest)
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

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
}

fn valid_opaque_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
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
    };
}

string_identifier!(MissionId);
string_identifier!(WorkProductId);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EventName(String);

impl EventName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 96
            || value.trim() != value
            || value.chars().any(char::is_control)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b" ._-".contains(&byte))
        {
            Err(ModelError::InvalidEventSelector)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for EventName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("EventName").field(&self.0).finish()
    }
}

macro_rules! numeric_identifier {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, ModelError> {
                if value == 0 {
                    Err(ModelError::InvalidNumericIdentifier)
                } else {
                    Ok(Self(value))
                }
            }

            pub const fn get(self) -> u64 {
                self.0
            }

            pub fn digest(self) -> Digest {
                Digest::from_fields($domain, &[self.0.to_string()])
            }
        }
    };
}

numeric_identifier!(ProjectId, "mixpanel-project-id/v1");
numeric_identifier!(WorkspaceId, "mixpanel-workspace-id/v1");
numeric_identifier!(ReportId, "mixpanel-report-id/v1");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn new(seconds: i64) -> Result<Self, ModelError> {
        if seconds < 0 {
            Err(ModelError::InvalidTimestamp)
        } else {
            Ok(Self(seconds))
        }
    }

    pub const fn seconds(self) -> i64 {
        self.0
    }

    pub const fn utc_hour(self) -> i64 {
        self.0 / 3_600
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UtcDate(String);

impl UtcDate {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_date(&value) {
            return Err(ModelError::InvalidDate);
        }
        Ok(Self(value))
    }

    pub fn from_api_value(value: &str) -> Result<Self, ModelError> {
        let date = value.get(..10).ok_or(ModelError::InvalidDate)?;
        let result = Self::new(date.to_owned())?;
        if value.len() > 10 {
            let suffix = &value[10..];
            if suffix.len() > MAX_DATE_SUFFIX_BYTES
                || !suffix.starts_with('T')
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+:-.Z".contains(&byte))
            {
                return Err(ModelError::InvalidDateSuffix);
            }
        }
        Ok(result)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn days_since_epoch(&self) -> i64 {
        days_from_civil(
            self.0[0..4].parse::<i32>().expect("validated year"),
            self.0[5..7].parse::<u32>().expect("validated month"),
            self.0[8..10].parse::<u32>().expect("validated day"),
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

fn valid_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return false;
    }
    if !value
        .bytes()
        .enumerate()
        .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<i32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u32>() else {
        return false;
    };
    year >= 1970 && (1..=12).contains(&month) && (1..=days_in_month(year, month)).contains(&day)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's proleptic-Gregorian civil-date calculation, bounded here
// to the validated 1970..9999 date range and used only for a 31-day fence.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i32::try_from(month).expect("month fits i32");
    let day = i32::try_from(day).expect("day fits i32");
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era * 146_097 + day_of_era - 719_468)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateWindow {
    from: UtcDate,
    to: UtcDate,
}

impl DateWindow {
    pub fn new(from: UtcDate, to: UtcDate) -> Result<Self, ModelError> {
        let window = Self { from, to };
        window.validate()?;
        Ok(window)
    }

    pub fn from_date(&self) -> &UtcDate {
        &self.from
    }

    pub fn to_date(&self) -> &UtcDate {
        &self.to
    }

    pub fn days(&self) -> u16 {
        u16::try_from(self.to.days_since_epoch() - self.from.days_since_epoch() + 1)
            .expect("validated date window fits u16")
    }

    pub fn contains(&self, date: &UtcDate) -> bool {
        self.from <= *date && *date <= self.to
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let days = self.to.days_since_epoch() - self.from.days_since_epoch() + 1;
        if !(1..=31).contains(&days) {
            Err(ModelError::InvalidDateWindow)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-date-window/v1",
            &[self.from.as_str().to_owned(), self.to.as_str().to_owned()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EventSelector(Vec<EventName>);

impl EventSelector {
    pub fn new<I>(events: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = EventName>,
    {
        let mut events = events.into_iter().collect::<Vec<_>>();
        if events.is_empty() {
            return Err(ModelError::EmptyEventSelector);
        }
        if events.len() > MIXPANEL_MAX_EVENT_SELECTORS {
            return Err(ModelError::TooManyEventSelectors);
        }
        if events.iter().any(|event| {
            event.as_str().len() > 96
                || event.as_str().chars().any(char::is_control)
                || event.as_str().trim() != event.as_str()
        }) {
            return Err(ModelError::InvalidEventSelector);
        }
        events.sort();
        if events.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::DuplicateEventSelector);
        }
        Ok(Self(events))
    }

    pub fn iter(&self) -> impl Iterator<Item = &EventName> {
        self.0.iter()
    }

    pub fn contains(&self, event: &EventName) -> bool {
        self.0.binary_search(event).is_ok()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-event-selector/v1",
            &self
                .0
                .iter()
                .map(|event| event.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    project_id: ProjectId,
    revision: Revision,
}

impl ProjectScope {
    pub fn new(project_id: u64, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            project_id: ProjectId::new(project_id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-project-scope/v1",
            &[
                self.project_id.get().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    mission_id: MissionId,
    revision: Revision,
}

impl MissionScope {
    pub fn new(mission_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            mission_id: MissionId::new(mission_id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-mission-scope/v1",
            &[
                self.mission_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    work_product_id: WorkProductId,
    revision: Revision,
}

impl WorkProductScope {
    pub fn new(work_product_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            work_product_id: WorkProductId::new(work_product_id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-work-product-scope/v1",
            &[
                self.work_product_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyPolicy {
    version: String,
    raw_api_body_redacted: bool,
    raw_events_redacted: bool,
    user_pii_redacted: bool,
    event_properties_redacted: bool,
    auth_material_redacted: bool,
    max_response_bytes: usize,
}

impl PrivacyPolicy {
    pub fn strict_v1() -> Self {
        Self {
            version: MIXPANEL_PRIVACY_POLICY_VERSION.to_owned(),
            raw_api_body_redacted: true,
            raw_events_redacted: true,
            user_pii_redacted: true,
            event_properties_redacted: true,
            auth_material_redacted: true,
            max_response_bytes: MIXPANEL_MAX_RESPONSE_BYTES,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.version != MIXPANEL_PRIVACY_POLICY_VERSION
            || !self.raw_api_body_redacted
            || !self.raw_events_redacted
            || !self.user_pii_redacted
            || !self.event_properties_redacted
            || !self.auth_material_redacted
            || self.max_response_bytes == 0
            || self.max_response_bytes > MIXPANEL_MAX_RESPONSE_BYTES
        {
            Err(ModelError::InvalidPrivacyPolicy)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-privacy-policy/v1",
            &[
                self.version.clone(),
                self.raw_api_body_redacted.to_string(),
                self.raw_events_redacted.to_string(),
                self.user_pii_redacted.to_string(),
                self.event_properties_redacted.to_string(),
                self.auth_material_redacted.to_string(),
                self.max_response_bytes.to_string(),
            ],
        )
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelAnalyticsScope {
    project: ProjectScope,
    workspace_id: Option<WorkspaceId>,
    report_id: ReportId,
    date_window: DateWindow,
    event_selector: EventSelector,
    mission: MissionScope,
    work_product: WorkProductScope,
    privacy_policy: PrivacyPolicy,
}

impl MixpanelAnalyticsScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectScope,
        workspace_id: Option<WorkspaceId>,
        report_id: ReportId,
        date_window: DateWindow,
        event_selector: EventSelector,
        mission: MissionScope,
        work_product: WorkProductScope,
        privacy_policy: PrivacyPolicy,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project,
            workspace_id,
            report_id,
            date_window,
            event_selector,
            mission,
            work_product,
            privacy_policy,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.date_window.validate()?;
        if self.event_selector.is_empty() {
            return Err(ModelError::EmptyEventSelector);
        }
        self.privacy_policy.validate()?;
        Ok(())
    }

    pub const fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub const fn workspace_id(&self) -> Option<WorkspaceId> {
        self.workspace_id
    }

    pub const fn report_id(&self) -> ReportId {
        self.report_id
    }

    pub const fn date_window(&self) -> &DateWindow {
        &self.date_window
    }

    pub const fn event_selector(&self) -> &EventSelector {
        &self.event_selector
    }

    pub const fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub const fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub const fn privacy_policy(&self) -> &PrivacyPolicy {
        &self.privacy_policy
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-analytics-scope/v1",
            &[
                self.project.digest().as_str().to_owned(),
                self.workspace_id
                    .map_or_else(|| "none".to_owned(), |id| id.get().to_string()),
                self.report_id.get().to_string(),
                self.date_window.digest().as_str().to_owned(),
                self.event_selector.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.privacy_policy.digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
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
pub enum ResultStatus {
    Complete,
    Partial,
    Empty,
    RateLimited,
    Expired,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Expired,
    RateLimited,
    QuotaExhausted,
    BlockedEnv,
    ResponseTooLarge,
    MalformedResponse,
    RawEventOrPii,
    BoundExceeded,
    ScopeDrift,
    Replay,
    Transport,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_api_body_dropped: bool,
    pub raw_events_dropped: bool,
    pub user_pii_dropped: bool,
    pub event_properties_dropped: bool,
    pub auth_material_dropped: bool,
}

impl RedactionSummary {
    pub const fn strict() -> Self {
        Self {
            raw_api_body_dropped: true,
            raw_events_dropped: true,
            user_pii_dropped: true,
            event_properties_dropped: true,
            auth_material_dropped: true,
        }
    }

    pub const fn is_strict(&self) -> bool {
        self.raw_api_body_dropped
            && self.raw_events_dropped
            && self.user_pii_dropped
            && self.event_properties_dropped
            && self.auth_material_dropped
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateBucket {
    pub date: UtcDate,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateSeries {
    pub event: EventName,
    pub buckets: Vec<AggregateBucket>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelRegistration {
    pub revision: Revision,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl MixpanelRegistration {
    pub fn new(
        scope: &MixpanelAnalyticsScope,
        secret: &SecretReference,
        provider_digest: Digest,
        contract_digest: Digest,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.digest() || secret.is_revoked() {
            return Err(ModelError::SecretScopeMismatch);
        }
        let revision = Revision::new(1)?;
        let mut registration = Self {
            revision,
            contract_version: MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_digest,
            scope_digest: scope.digest(),
            secret_reference_digest: secret.digest(),
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("placeholder"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-registration/v1",
            &[
                self.revision.get().to_string(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        let revocation_digest = Digest::from_fields(
            "mixpanel-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    pub const fn is_revoked(&self) -> bool {
        matches!(self.state, RegistrationState::Revoked)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contract_version != MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION
            || self.contract_digest.as_str().len() != 64
            || self.provider_digest.as_str().len() != 64
            || self.scope_digest.as_str().len() != 64
            || self.secret_reference_digest.as_str().len() != 64
            || self.registration_digest != self.compute_digest()
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn project_token(
        opaque_reference: impl AsRef<str>,
        scope: &MixpanelAnalyticsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.as_ref();
        if !valid_opaque_reference(opaque_reference) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        Ok(Self {
            reference_digest: Digest::from_fields(
                "mixpanel-project-token-reference/v1",
                &[opaque_reference.to_owned()],
            ),
            scope_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-secret-reference/v1",
            &[
                self.reference_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                self.revoked.to_string(),
            ],
        )
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

    pub fn matches_scope(&self, scope: &MixpanelAnalyticsScope) -> bool {
        self.scope_digest == scope.digest()
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

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &"project_token")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}
