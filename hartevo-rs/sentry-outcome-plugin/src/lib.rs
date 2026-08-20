//! Layer 1 Sentry error and release outcome-evidence plugin.
//!
//! The crate is deliberately standalone until host wiring is owned by the
//! Integration Manager.  It contributes typed read-only service, provider,
//! and Mission Outcome consumer paths.  It never resolves, assigns, mutes,
//! creates, or updates Sentry resources, and it never treats a fixture,
//! loopback, or blocked environment as native or connected evidence.

#![forbid(unsafe_code)]
#![allow(clippy::struct_excessive_bools)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration as StdDuration,
};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use url::Url;

pub const SENTRY_OUTCOME_SCHEMA_VERSION: &str = "hartevo.sentry-outcome/v1";
pub const SENTRY_OUTCOME_CONTRACT_PATH: &str =
    "contracts/plugins/sentry-outcome/sentry-outcome.v1.json";
pub const SENTRY_OUTCOME_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/sentry-outcome/sentry-outcome.v1.json");

pub const SENTRY_OUTCOME_SERVICE_ID: &str = "sentry.outcome-evidence.read";
pub const SENTRY_OUTCOME_PROVIDER_ID: &str = "sentry.outcome";
pub const MISSION_OUTCOME_EVIDENCE_CONSUMER_ID: &str = "mission.outcome-evidence.consumer";
pub const SENTRY_OUTCOME_PROVIDER_IMPLEMENTATION: &str = "SentryOutcomeProvider";

pub const MAX_QUERY_WINDOW_SECONDS: i64 = 86_400;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 20;
pub const MAX_RESULTS: u64 = 1_000;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RETRIES: u8 = 3;
pub const MAX_BACKOFF_SECONDS: u64 = 30;
pub const MAX_REDACTED_FIELD_BYTES: usize = 16 * 1024;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_FINGERPRINT_BYTES: usize = 256;

pub type Digest = String;

/// Return a lowercase SHA-256 digest without retaining the input.
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    format!("{:x}", Sha256::digest(bytes))
}

/// Serialize a typed value in its declared field order and hash it.
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Sentry value serializes");
    sha256_digest(&bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_scope_token(value: &str, label: &'static str) -> Result<(), SentryOutcomeError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
    {
        return Err(SentryOutcomeError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_query_window(
    from: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<(), SentryOutcomeError> {
    let duration = until.signed_duration_since(from);
    if duration <= Duration::zero() || duration > Duration::seconds(MAX_QUERY_WINDOW_SECONDS) {
        return Err(SentryOutcomeError::InvalidQueryWindow);
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SentryOutcomeError {
    #[error("{label} is empty, invalid, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is not a lowercase SHA-256 digest")]
    InvalidDigest { label: &'static str },
    #[error("Sentry organization, project, environment, release, or Mission scope is invalid")]
    InvalidScope,
    #[error("query window must be positive and no longer than one day")]
    InvalidQueryWindow,
    #[error("query page size or result bound is invalid")]
    InvalidQueryBounds,
    #[error("Sentry cursor is invalid or too large")]
    InvalidCursor,
    #[error("Sentry fingerprint is invalid or too large")]
    InvalidFingerprint,
    #[error("redacted evidence field is too large")]
    RedactionTooLarge,
    #[error("provider definition is invalid")]
    InvalidDefinition,
    #[error("registration is missing")]
    RegistrationRequired,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration does not match the provider, version, digest, or exact scope")]
    RegistrationMismatch,
    #[error("query is not one of the allowlisted Sentry issue, event, or release reads")]
    UnallowlistedQuery,
    #[error("query scope does not match the registered or returned scope")]
    ScopeMismatch,
    #[error("query kind does not match the typed result")]
    QueryKindMismatch,
    #[error("Sentry response or receipt failed its tamper check")]
    ResponseTampered,
    #[error("Sentry issue or event fingerprint failed its independent digest check")]
    FingerprintMismatch,
    #[error("Sentry query returned a duplicate record")]
    DuplicateRecord,
    #[error("Sentry cursor did not advance")]
    NonMonotonicCursor,
    #[error("Sentry query exceeded its bounded page or result budget")]
    PaginationExceeded,
    #[error("Sentry receipt is stale")]
    StaleEvidence,
    #[error("Sentry receipt is ambiguous or internally inconsistent")]
    AmbiguousReceipt,
    #[error("Mission Outcome binding does not match the Sentry scope")]
    BindingMismatch,
    #[error("Mission Outcome evidence cannot promote a non-native source")]
    NativeClassificationMismatch,
    #[error("Sentry transport failed: {0}")]
    Transport(#[from] SentryTransportError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SentryTransportError {
    #[error("Sentry credentials or environment are blocked")]
    BlockedEnv,
    #[error("Sentry authentication was revoked")]
    AuthenticationRevoked,
    #[error("Sentry organization or project scope was denied")]
    ScopeDenied,
    #[error("Sentry rate limit was encountered")]
    RateLimited {
        limit: Option<u64>,
        remaining: Option<u64>,
        retry_after_seconds: Option<u64>,
        reset_at: Option<DateTime<Utc>>,
    },
    #[error("Sentry request timed out")]
    Timeout,
    #[error("Sentry HTTPS endpoint is invalid")]
    InvalidEndpoint,
    #[error("Sentry response was invalid")]
    InvalidResponse,
    #[error("Sentry response exceeded the bounded byte budget")]
    ResponseTooLarge,
    #[error("Sentry request failed without exposing provider payloads")]
    RequestFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDimension {
    Organization,
    Project,
    Environment,
    Release,
    Mission,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryOutcomeEvidenceServiceDefinition {
    pub id: String,
    pub version: PluginVersion,
    pub access: AccessMode,
    pub contract_digest: Digest,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryOutcomeProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub implementation: String,
    pub scope: Vec<ScopeDimension>,
    pub authentication: String,
    pub transport: String,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeEvidenceConsumerDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub kind: String,
    pub exact_binding_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryOutcomePluginDefinition {
    pub schema_version: String,
    pub plugin_id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub service: SentryOutcomeEvidenceServiceDefinition,
    pub provider: SentryOutcomeProviderDefinition,
    pub consumer: MissionOutcomeEvidenceConsumerDefinition,
    pub reversible: bool,
    pub writes: bool,
    pub webhooks: bool,
}

impl SentryOutcomePluginDefinition {
    pub fn layer1() -> Result<Self, SentryOutcomeError> {
        let contract_digest = sha256_digest(SENTRY_OUTCOME_CONTRACT_JSON.as_bytes());
        let definition = Self {
            schema_version: SENTRY_OUTCOME_SCHEMA_VERSION.into(),
            plugin_id: SENTRY_OUTCOME_PROVIDER_ID.into(),
            version: PluginVersion::V1,
            contract_digest: contract_digest.clone(),
            service: SentryOutcomeEvidenceServiceDefinition {
                id: SENTRY_OUTCOME_SERVICE_ID.into(),
                version: PluginVersion::V1,
                access: AccessMode::ReadOnly,
                contract_digest,
                authority: "read_only_observational_evidence".into(),
            },
            provider: SentryOutcomeProviderDefinition {
                id: SENTRY_OUTCOME_PROVIDER_ID.into(),
                service_id: SENTRY_OUTCOME_SERVICE_ID.into(),
                version: PluginVersion::V1,
                implementation: SENTRY_OUTCOME_PROVIDER_IMPLEMENTATION.into(),
                scope: vec![
                    ScopeDimension::Organization,
                    ScopeDimension::Project,
                    ScopeDimension::Environment,
                    ScopeDimension::Release,
                    ScopeDimension::Mission,
                ],
                authentication: "secret_reference".into(),
                transport: "https_only".into(),
                reversible: true,
            },
            consumer: MissionOutcomeEvidenceConsumerDefinition {
                id: MISSION_OUTCOME_EVIDENCE_CONSUMER_ID.into(),
                service_id: SENTRY_OUTCOME_SERVICE_ID.into(),
                version: PluginVersion::V1,
                kind: "mission_outcome".into(),
                exact_binding_fields: vec![
                    "organization_id".into(),
                    "project_id".into(),
                    "environment".into(),
                    "release".into(),
                    "mission_id".into(),
                    "mission_revision".into(),
                    "deployment_id".into(),
                    "deployment_revision".into(),
                    "query_window".into(),
                    "source_result_digest".into(),
                    "provider_version".into(),
                    "registration_digest".into(),
                ],
            },
            reversible: true,
            writes: false,
            webhooks: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), SentryOutcomeError> {
        if self.schema_version != SENTRY_OUTCOME_SCHEMA_VERSION
            || self.plugin_id != SENTRY_OUTCOME_PROVIDER_ID
            || self.version != PluginVersion::V1
            || !is_sha256(&self.contract_digest)
            || self.service.id != SENTRY_OUTCOME_SERVICE_ID
            || self.service.version != PluginVersion::V1
            || self.service.contract_digest != self.contract_digest
            || self.provider.id != SENTRY_OUTCOME_PROVIDER_ID
            || self.provider.service_id != self.service.id
            || self.provider.version != PluginVersion::V1
            || self.provider.implementation != SENTRY_OUTCOME_PROVIDER_IMPLEMENTATION
            || self.provider.scope.len() != 5
            || !self.provider.reversible
            || self.consumer.id != MISSION_OUTCOME_EVIDENCE_CONSUMER_ID
            || self.consumer.service_id != self.service.id
            || self.consumer.version != PluginVersion::V1
            || !self.reversible
            || self.writes
            || self.webhooks
        {
            return Err(SentryOutcomeError::InvalidDefinition);
        }
        Ok(())
    }

    pub fn bind(
        &self,
        scope: SentryScope,
        generation: u64,
    ) -> Result<RegistrationReceipt, SentryOutcomeError> {
        if generation == 0 {
            return Err(SentryOutcomeError::InvalidScope);
        }
        scope.validate()?;
        Ok(RegistrationReceipt::active(self, scope, generation))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryScope {
    pub organization_id: String,
    pub project_id: String,
    pub environment: String,
    pub release: String,
    pub mission_id: String,
    pub mission_revision: u64,
    pub deployment_id: String,
    pub deployment_revision: u64,
}

impl SentryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        release: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
        deployment_id: impl Into<String>,
        deployment_revision: u64,
    ) -> Result<Self, SentryOutcomeError> {
        let scope = Self {
            organization_id: organization_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            release: release.into(),
            mission_id: mission_id.into(),
            mission_revision,
            deployment_id: deployment_id.into(),
            deployment_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), SentryOutcomeError> {
        for (value, label) in [
            (&self.organization_id, "organization_id"),
            (&self.project_id, "project_id"),
            (&self.environment, "environment"),
            (&self.release, "release"),
            (&self.mission_id, "mission_id"),
            (&self.deployment_id, "deployment_id"),
        ] {
            validate_scope_token(value, label)?;
        }
        if self.mission_revision == 0 || self.deployment_revision == 0 {
            return Err(SentryOutcomeError::InvalidScope);
        }
        Ok(())
    }

    pub fn provider_scope(&self) -> SentryProviderScope {
        SentryProviderScope {
            organization_id: self.organization_id.clone(),
            project_id: self.project_id.clone(),
            environment: self.environment.clone(),
            release: self.release.clone(),
        }
    }

    pub fn mission_binding(&self) -> MissionOutcomeBinding {
        MissionOutcomeBinding {
            mission_id: self.mission_id.clone(),
            mission_revision: self.mission_revision,
            deployment_id: self.deployment_id.clone(),
            deployment_revision: self.deployment_revision,
        }
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryProviderScope {
    pub organization_id: String,
    pub project_id: String,
    pub environment: String,
    pub release: String,
}

impl SentryProviderScope {
    pub fn new(
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        release: impl Into<String>,
    ) -> Result<Self, SentryOutcomeError> {
        let scope = Self {
            organization_id: organization_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            release: release.into(),
        };
        for (value, label) in [
            (&scope.organization_id, "organization_id"),
            (&scope.project_id, "project_id"),
            (&scope.environment, "environment"),
            (&scope.release, "release"),
        ] {
            validate_scope_token(value, label)?;
        }
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), SentryOutcomeError> {
        for (value, label) in [
            (&self.organization_id, "organization_id"),
            (&self.project_id, "project_id"),
            (&self.environment, "environment"),
            (&self.release, "release"),
        ] {
            validate_scope_token(value, label)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeBinding {
    pub mission_id: String,
    pub mission_revision: u64,
    pub deployment_id: String,
    pub deployment_revision: u64,
}

impl MissionOutcomeBinding {
    pub fn validate(&self) -> Result<(), SentryOutcomeError> {
        validate_scope_token(&self.mission_id, "mission_id")?;
        validate_scope_token(&self.deployment_id, "deployment_id")?;
        if self.mission_revision == 0 || self.deployment_revision == 0 {
            return Err(SentryOutcomeError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryWindow {
    pub from: DateTime<Utc>,
    pub until: DateTime<Utc>,
}

impl QueryWindow {
    pub fn new(from: DateTime<Utc>, until: DateTime<Utc>) -> Result<Self, SentryOutcomeError> {
        validate_query_window(from, until)?;
        Ok(Self { from, until })
    }

    pub fn duration_seconds(&self) -> i64 {
        self.until.signed_duration_since(self.from).num_seconds()
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Cursor(String);

impl Cursor {
    pub fn new(value: impl Into<String>) -> Result<Self, SentryOutcomeError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CURSOR_BYTES
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(SentryOutcomeError::InvalidCursor);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self, SentryOutcomeError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_FINGERPRINT_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(SentryOutcomeError::InvalidFingerprint);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedValue {
    pub digest: Digest,
    pub byte_len: u64,
}

impl RedactedValue {
    pub fn from_text(value: &str) -> Result<Self, SentryOutcomeError> {
        if value.len() > MAX_REDACTED_FIELD_BYTES {
            return Err(SentryOutcomeError::RedactionTooLarge);
        }
        Ok(Self {
            digest: sha256_digest(value.as_bytes()),
            byte_len: u64::try_from(value.len()).expect("redacted field length fits in u64"),
        })
    }

    pub fn from_bytes(value: &[u8]) -> Result<Self, SentryOutcomeError> {
        if value.len() > MAX_REDACTED_FIELD_BYTES {
            return Err(SentryOutcomeError::RedactionTooLarge);
        }
        Ok(Self {
            digest: sha256_digest(value),
            byte_len: u64::try_from(value.len()).expect("redacted field length fits in u64"),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SentryQueryKind {
    Issues,
    Events,
    Releases,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueQuery {
    pub scope: SentryScope,
    pub window: QueryWindow,
    pub page_size: u16,
    pub cursor: Option<Cursor>,
}

impl IssueQuery {
    pub fn new(
        scope: SentryScope,
        window: QueryWindow,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self, SentryOutcomeError> {
        let query = Self {
            scope,
            window,
            page_size,
            cursor,
        };
        query.validate()?;
        Ok(query)
    }

    fn validate(&self) -> Result<(), SentryOutcomeError> {
        self.scope.validate()?;
        validate_query_window(self.window.from, self.window.until)?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(SentryOutcomeError::InvalidQueryBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventQuery {
    pub scope: SentryScope,
    pub window: QueryWindow,
    pub page_size: u16,
    pub cursor: Option<Cursor>,
    pub fingerprint: Option<Fingerprint>,
}

impl EventQuery {
    pub fn new(
        scope: SentryScope,
        window: QueryWindow,
        page_size: u16,
        cursor: Option<Cursor>,
        fingerprint: Option<Fingerprint>,
    ) -> Result<Self, SentryOutcomeError> {
        let query = Self {
            scope,
            window,
            page_size,
            cursor,
            fingerprint,
        };
        query.validate()?;
        Ok(query)
    }

    fn validate(&self) -> Result<(), SentryOutcomeError> {
        self.scope.validate()?;
        validate_query_window(self.window.from, self.window.until)?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(SentryOutcomeError::InvalidQueryBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseQuery {
    pub scope: SentryScope,
    pub window: QueryWindow,
    pub page_size: u16,
    pub cursor: Option<Cursor>,
}

impl ReleaseQuery {
    pub fn new(
        scope: SentryScope,
        window: QueryWindow,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self, SentryOutcomeError> {
        let query = Self {
            scope,
            window,
            page_size,
            cursor,
        };
        query.validate()?;
        Ok(query)
    }

    fn validate(&self) -> Result<(), SentryOutcomeError> {
        self.scope.validate()?;
        validate_query_window(self.window.from, self.window.until)?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(SentryOutcomeError::InvalidQueryBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "query")]
pub enum SentryQuery {
    Issues(IssueQuery),
    Events(EventQuery),
    Releases(ReleaseQuery),
}

impl SentryQuery {
    pub fn issues(query: IssueQuery) -> Result<Self, SentryOutcomeError> {
        query.validate()?;
        Ok(Self::Issues(query))
    }

    pub fn events(query: EventQuery) -> Result<Self, SentryOutcomeError> {
        query.validate()?;
        Ok(Self::Events(query))
    }

    pub fn releases(query: ReleaseQuery) -> Result<Self, SentryOutcomeError> {
        query.validate()?;
        Ok(Self::Releases(query))
    }

    pub fn kind(&self) -> SentryQueryKind {
        match self {
            Self::Issues(_) => SentryQueryKind::Issues,
            Self::Events(_) => SentryQueryKind::Events,
            Self::Releases(_) => SentryQueryKind::Releases,
        }
    }

    pub fn scope(&self) -> &SentryScope {
        match self {
            Self::Issues(query) => &query.scope,
            Self::Events(query) => &query.scope,
            Self::Releases(query) => &query.scope,
        }
    }

    pub fn window(&self) -> &QueryWindow {
        match self {
            Self::Issues(query) => &query.window,
            Self::Events(query) => &query.window,
            Self::Releases(query) => &query.window,
        }
    }

    pub fn page_size(&self) -> u16 {
        match self {
            Self::Issues(query) => query.page_size,
            Self::Events(query) => query.page_size,
            Self::Releases(query) => query.page_size,
        }
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        match self {
            Self::Issues(query) => query.cursor.as_ref(),
            Self::Events(query) => query.cursor.as_ref(),
            Self::Releases(query) => query.cursor.as_ref(),
        }
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), SentryOutcomeError> {
        match self {
            Self::Issues(query) => query.validate(),
            Self::Events(query) => query.validate(),
            Self::Releases(query) => query.validate(),
        }
    }

    fn with_cursor(&self, cursor: Option<Cursor>) -> Result<Self, SentryOutcomeError> {
        match self {
            Self::Issues(query) => Self::issues(IssueQuery::new(
                query.scope.clone(),
                query.window.clone(),
                query.page_size,
                cursor,
            )?),
            Self::Events(query) => Self::events(EventQuery::new(
                query.scope.clone(),
                query.window.clone(),
                query.page_size,
                cursor,
                query.fingerprint.clone(),
            )?),
            Self::Releases(query) => Self::releases(ReleaseQuery::new(
                query.scope.clone(),
                query.window.clone(),
                query.page_size,
                cursor,
            )?),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub schema_version: String,
    pub plugin_id: String,
    pub provider_version: PluginVersion,
    pub service_id: String,
    pub provider_id: String,
    pub plugin_digest: Digest,
    pub scope: SentryScope,
    pub generation: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub schema_version: String,
    pub registration_digest: Digest,
    pub plugin_digest: Digest,
    pub scope_digest: Digest,
    pub generation: u64,
    pub status: RegistrationStatus,
    pub revocation_digest: Digest,
}

#[derive(Serialize)]
struct RegistrationMaterial<'a> {
    schema_version: &'a str,
    plugin_id: &'a str,
    provider_version: PluginVersion,
    service_id: &'a str,
    provider_id: &'a str,
    plugin_digest: &'a str,
    scope: &'a SentryScope,
    generation: u64,
    status: RegistrationStatus,
}

impl RegistrationReceipt {
    fn active(
        definition: &SentryOutcomePluginDefinition,
        scope: SentryScope,
        generation: u64,
    ) -> Self {
        let mut receipt = Self {
            schema_version: "hartevo.sentry-outcome-registration/v1".into(),
            plugin_id: definition.plugin_id.clone(),
            provider_version: definition.version,
            service_id: definition.service.id.clone(),
            provider_id: definition.provider.id.clone(),
            plugin_digest: definition.digest(),
            scope,
            generation,
            status: RegistrationStatus::Active,
            registration_digest: String::new(),
        };
        receipt.registration_digest = receipt.compute_digest();
        receipt
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&RegistrationMaterial {
            schema_version: &self.schema_version,
            plugin_id: &self.plugin_id,
            provider_version: self.provider_version,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            plugin_digest: &self.plugin_digest,
            scope: &self.scope,
            generation: self.generation,
            status: self.status,
        })
    }

    pub fn validate(
        &self,
        definition: &SentryOutcomePluginDefinition,
    ) -> Result<(), SentryOutcomeError> {
        if self.schema_version != "hartevo.sentry-outcome-registration/v1"
            || self.plugin_id != definition.plugin_id
            || self.provider_version != definition.version
            || self.service_id != definition.service.id
            || self.provider_id != definition.provider.id
            || self.plugin_digest != definition.digest()
            || self.generation == 0
            || !is_sha256(&self.plugin_digest)
            || !is_sha256(&self.registration_digest)
            || self.compute_digest() != self.registration_digest
        {
            return Err(SentryOutcomeError::RegistrationMismatch);
        }
        self.scope.validate()
    }

    pub fn revoke(&self) -> RevocationReceipt {
        let revocation_material = (
            &self.registration_digest,
            &self.plugin_digest,
            &self.scope.digest(),
            self.generation,
            RegistrationStatus::Revoked,
        );
        RevocationReceipt {
            schema_version: "hartevo.sentry-outcome-revocation/v1".into(),
            registration_digest: self.registration_digest.clone(),
            plugin_digest: self.plugin_digest.clone(),
            scope_digest: self.scope.digest(),
            generation: self.generation,
            status: RegistrationStatus::Revoked,
            revocation_digest: canonical_digest(&revocation_material),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryIssueRecord {
    pub id: String,
    pub short_id: String,
    pub scope: SentryProviderScope,
    pub title: RedactedValue,
    pub culprit: Option<RedactedValue>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u64,
    pub fingerprint: Fingerprint,
    pub fingerprint_digest: Digest,
}

impl SentryIssueRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: SentryProviderScope,
        id: impl Into<String>,
        short_id: impl Into<String>,
        title: &str,
        culprit: Option<&str>,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        count: u64,
        fingerprint: Fingerprint,
    ) -> Result<Self, SentryOutcomeError> {
        let id = id.into();
        let short_id = short_id.into();
        validate_scope_token(&id, "issue_id")?;
        validate_scope_token(&short_id, "issue_short_id")?;
        scope.validate()?;
        if last_seen < first_seen {
            return Err(SentryOutcomeError::InvalidScope);
        }
        let title = RedactedValue::from_text(title)?;
        let culprit = culprit.map(RedactedValue::from_text).transpose()?;
        let fingerprint_digest = fingerprint.digest();
        Ok(Self {
            id,
            short_id,
            scope,
            title,
            culprit,
            first_seen,
            last_seen,
            count,
            fingerprint,
            fingerprint_digest,
        })
    }

    fn validate_against(
        &self,
        expected_scope: &SentryProviderScope,
    ) -> Result<(), SentryOutcomeError> {
        validate_scope_token(&self.id, "issue_id")?;
        validate_scope_token(&self.short_id, "issue_short_id")?;
        if &self.scope != expected_scope || self.last_seen < self.first_seen {
            return Err(SentryOutcomeError::ScopeMismatch);
        }
        if !is_sha256(&self.fingerprint_digest)
            || self.fingerprint.digest() != self.fingerprint_digest
        {
            return Err(SentryOutcomeError::FingerprintMismatch);
        }
        Ok(())
    }

    fn record_id(&self) -> &str {
        &self.id
    }

    fn fingerprint_digest(&self) -> &str {
        &self.fingerprint_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryEventRecord {
    pub id: String,
    pub issue_id: Option<String>,
    pub scope: SentryProviderScope,
    pub timestamp: DateTime<Utc>,
    pub fingerprint: Fingerprint,
    pub fingerprint_digest: Digest,
    pub message: Option<RedactedValue>,
    pub stacktrace: Option<RedactedValue>,
}

impl SentryEventRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: SentryProviderScope,
        id: impl Into<String>,
        issue_id: Option<impl Into<String>>,
        timestamp: DateTime<Utc>,
        fingerprint: Fingerprint,
        message: Option<&str>,
        stacktrace: Option<&str>,
    ) -> Result<Self, SentryOutcomeError> {
        let id = id.into();
        validate_scope_token(&id, "event_id")?;
        let issue_id = issue_id.map(Into::into);
        if let Some(issue_id) = &issue_id {
            validate_scope_token(issue_id, "issue_id")?;
        }
        scope.validate()?;
        let message = message.map(RedactedValue::from_text).transpose()?;
        let stacktrace = stacktrace.map(RedactedValue::from_text).transpose()?;
        let fingerprint_digest = fingerprint.digest();
        Ok(Self {
            id,
            issue_id,
            scope,
            timestamp,
            fingerprint,
            fingerprint_digest,
            message,
            stacktrace,
        })
    }

    fn validate_against(
        &self,
        expected_scope: &SentryProviderScope,
        window: &QueryWindow,
    ) -> Result<(), SentryOutcomeError> {
        validate_scope_token(&self.id, "event_id")?;
        if let Some(issue_id) = &self.issue_id {
            validate_scope_token(issue_id, "issue_id")?;
        }
        if &self.scope != expected_scope {
            return Err(SentryOutcomeError::ScopeMismatch);
        }
        if self.timestamp < window.from || self.timestamp > window.until {
            return Err(SentryOutcomeError::StaleEvidence);
        }
        if !is_sha256(&self.fingerprint_digest)
            || self.fingerprint.digest() != self.fingerprint_digest
        {
            return Err(SentryOutcomeError::FingerprintMismatch);
        }
        Ok(())
    }

    fn record_id(&self) -> &str {
        &self.id
    }

    fn fingerprint_digest(&self) -> &str {
        &self.fingerprint_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryReleaseRecord {
    pub id: String,
    pub version: String,
    pub scope: SentryProviderScope,
    pub deployment_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub new_issue_count: u64,
    pub resolved_issue_count: u64,
    pub release_digest: Digest,
}

impl SentryReleaseRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: SentryProviderScope,
        id: impl Into<String>,
        version: impl Into<String>,
        deployment_id: Option<impl Into<String>>,
        created_at: DateTime<Utc>,
        released_at: Option<DateTime<Utc>>,
        new_issue_count: u64,
        resolved_issue_count: u64,
    ) -> Result<Self, SentryOutcomeError> {
        let id = id.into();
        let version = version.into();
        validate_scope_token(&id, "release_id")?;
        validate_scope_token(&version, "release_version")?;
        let deployment_id = deployment_id.map(Into::into);
        if let Some(deployment_id) = &deployment_id {
            validate_scope_token(deployment_id, "deployment_id")?;
        }
        scope.validate()?;
        if version != scope.release || released_at.is_some_and(|released| released < created_at) {
            return Err(SentryOutcomeError::InvalidScope);
        }
        let material = (
            &id,
            &version,
            &scope,
            &deployment_id,
            created_at,
            released_at,
            new_issue_count,
            resolved_issue_count,
        );
        let release_digest = canonical_digest(&material);
        Ok(Self {
            id,
            version,
            scope,
            deployment_id,
            created_at,
            released_at,
            new_issue_count,
            resolved_issue_count,
            release_digest,
        })
    }

    fn validate_against(
        &self,
        expected_scope: &SentryProviderScope,
    ) -> Result<(), SentryOutcomeError> {
        if &self.scope != expected_scope || self.version != expected_scope.release {
            return Err(SentryOutcomeError::ScopeMismatch);
        }
        if self.deployment_id.as_ref().is_some_and(String::is_empty) {
            return Err(SentryOutcomeError::InvalidScope);
        }
        let material = (
            &self.id,
            &self.version,
            &self.scope,
            &self.deployment_id,
            self.created_at,
            self.released_at,
            self.new_issue_count,
            self.resolved_issue_count,
        );
        if !is_sha256(&self.release_digest) || canonical_digest(&material) != self.release_digest {
            return Err(SentryOutcomeError::ResponseTampered);
        }
        Ok(())
    }

    fn record_id(&self) -> &str {
        &self.id
    }

    fn fingerprint_digest(&self) -> &str {
        &self.release_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "records")]
pub enum SentryQueryResult {
    Issues(Vec<SentryIssueRecord>),
    Events(Vec<SentryEventRecord>),
    Releases(Vec<SentryReleaseRecord>),
}

impl SentryQueryResult {
    pub fn kind(&self) -> SentryQueryKind {
        match self {
            Self::Issues(_) => SentryQueryKind::Issues,
            Self::Events(_) => SentryQueryKind::Events,
            Self::Releases(_) => SentryQueryKind::Releases,
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Self::Issues(records) => {
                u64::try_from(records.len()).expect("record count fits in u64")
            }
            Self::Events(records) => {
                u64::try_from(records.len()).expect("record count fits in u64")
            }
            Self::Releases(records) => {
                u64::try_from(records.len()).expect("record count fits in u64")
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate_against(
        &self,
        query_kind: SentryQueryKind,
        expected_scope: &SentryProviderScope,
        window: &QueryWindow,
    ) -> Result<(), SentryOutcomeError> {
        if self.kind() != query_kind || self.len() > u64::from(MAX_PAGE_SIZE) {
            return Err(SentryOutcomeError::QueryKindMismatch);
        }
        match self {
            Self::Issues(records) => {
                for record in records {
                    record.validate_against(expected_scope)?;
                }
            }
            Self::Events(records) => {
                for record in records {
                    record.validate_against(expected_scope, window)?;
                }
            }
            Self::Releases(records) => {
                for record in records {
                    record.validate_against(expected_scope)?;
                }
            }
        }
        Ok(())
    }

    fn extend(&mut self, page: Self) -> Result<(), SentryOutcomeError> {
        match page {
            Self::Issues(mut source) => match self {
                Self::Issues(target) => target.append(&mut source),
                _ => return Err(SentryOutcomeError::QueryKindMismatch),
            },
            Self::Events(mut source) => match self {
                Self::Events(target) => target.append(&mut source),
                _ => return Err(SentryOutcomeError::QueryKindMismatch),
            },
            Self::Releases(mut source) => match self {
                Self::Releases(target) => target.append(&mut source),
                _ => return Err(SentryOutcomeError::QueryKindMismatch),
            },
        }
        if self.len() > MAX_RESULTS {
            return Err(SentryOutcomeError::PaginationExceeded);
        }
        Ok(())
    }

    fn record_ids(&self) -> BTreeSet<String> {
        match self {
            Self::Issues(records) => records
                .iter()
                .map(|record| record.record_id().to_owned())
                .collect(),
            Self::Events(records) => records
                .iter()
                .map(|record| record.record_id().to_owned())
                .collect(),
            Self::Releases(records) => records
                .iter()
                .map(|record| record.record_id().to_owned())
                .collect(),
        }
    }

    fn identity_digests(&self) -> Vec<Digest> {
        let mut digests: Vec<Digest> = match self {
            Self::Issues(records) => records
                .iter()
                .map(|record| record.fingerprint_digest().to_owned())
                .collect(),
            Self::Events(records) => records
                .iter()
                .map(|record| record.fingerprint_digest().to_owned())
                .collect(),
            Self::Releases(records) => records
                .iter()
                .map(|record| record.fingerprint_digest().to_owned())
                .collect(),
        };
        digests.sort();
        digests.dedup();
        digests
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    NativeHttps,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl Provenance {
    pub fn is_native(self) -> bool {
        matches!(self, Self::NativeHttps)
    }

    pub fn is_connected(self) -> bool {
        self.is_native()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Reachable,
    BlockedEnv,
    AuthenticationRevoked,
    ScopeDenied,
    RateLimited,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeObservation {
    pub scope_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub status: ProbeStatus,
    pub provenance: Provenance,
    pub native: bool,
    pub connected: bool,
    pub receipt_digest: Digest,
}

impl ProbeObservation {
    fn reachable(scope: &SentryScope, at: DateTime<Utc>, provenance: Provenance) -> Self {
        let native = provenance.is_native();
        let status = ProbeStatus::Reachable;
        let receipt_digest = canonical_digest(&(&scope.digest(), at, status, provenance));
        Self {
            scope_digest: scope.digest(),
            observed_at: at,
            status,
            provenance,
            native,
            connected: native,
            receipt_digest,
        }
    }

    fn failed(
        scope: &SentryScope,
        at: DateTime<Utc>,
        provenance: Provenance,
        status: ProbeStatus,
    ) -> Self {
        let receipt_digest = canonical_digest(&(&scope.digest(), at, status, provenance));
        Self {
            scope_digest: scope.digest(),
            observed_at: at,
            status,
            provenance,
            native: false,
            connected: false,
            receipt_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitReceipt {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
    pub attempt: u8,
    pub backoff_seconds: u64,
}

impl RateLimitReceipt {
    pub fn none() -> Self {
        Self {
            limit: None,
            remaining: None,
            reset_at: None,
            retry_after_seconds: None,
            attempt: 0,
            backoff_seconds: 0,
        }
    }

    fn has_signal(&self) -> bool {
        self.limit.is_some()
            || self.remaining.is_some()
            || self.reset_at.is_some()
            || self.retry_after_seconds.is_some()
            || self.attempt > 0
            || self.backoff_seconds > 0
    }

    fn validate(&self) -> Result<(), SentryOutcomeError> {
        if self
            .remaining
            .zip(self.limit)
            .is_some_and(|(remaining, limit)| remaining > limit)
            || self.backoff_seconds > MAX_BACKOFF_SECONDS
            || self
                .retry_after_seconds
                .is_some_and(|value| value > MAX_BACKOFF_SECONDS)
        {
            return Err(SentryOutcomeError::AmbiguousReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryTransportPage {
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub window: QueryWindow,
    pub cursor: Option<Cursor>,
    pub next_cursor: Option<Cursor>,
    pub result: SentryQueryResult,
    pub declared_page_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub rate_limit: RateLimitReceipt,
}

#[derive(Serialize)]
struct PageMaterial<'a> {
    query_digest: &'a str,
    scope_digest: &'a str,
    window: &'a QueryWindow,
    cursor: &'a Option<Cursor>,
    next_cursor: &'a Option<Cursor>,
    result: &'a SentryQueryResult,
    observed_at: DateTime<Utc>,
    rate_limit: &'a RateLimitReceipt,
}

impl SentryTransportPage {
    pub fn new(
        query: &SentryQuery,
        result: SentryQueryResult,
        next_cursor: Option<Cursor>,
        observed_at: DateTime<Utc>,
        rate_limit: RateLimitReceipt,
    ) -> Result<Self, SentryOutcomeError> {
        if result.kind() != query.kind() {
            return Err(SentryOutcomeError::QueryKindMismatch);
        }
        if result.len() > u64::from(query.page_size()) {
            return Err(SentryOutcomeError::InvalidQueryBounds);
        }
        rate_limit.validate()?;
        let mut page = Self {
            query_digest: query.digest(),
            scope_digest: query.scope().digest(),
            window: query.window().clone(),
            cursor: query.cursor().cloned(),
            next_cursor,
            result,
            declared_page_digest: String::new(),
            observed_at,
            rate_limit,
        };
        page.declared_page_digest = page.compute_page_digest();
        Ok(page)
    }

    fn compute_page_digest(&self) -> Digest {
        canonical_digest(&PageMaterial {
            query_digest: &self.query_digest,
            scope_digest: &self.scope_digest,
            window: &self.window,
            cursor: &self.cursor,
            next_cursor: &self.next_cursor,
            result: &self.result,
            observed_at: self.observed_at,
            rate_limit: &self.rate_limit,
        })
    }

    fn validate_against(&self, query: &SentryQuery) -> Result<(), SentryOutcomeError> {
        if self.query_digest != query.digest()
            || self.scope_digest != query.scope().digest()
            || self.window != *query.window()
            || self.cursor.as_ref() != query.cursor()
            || self.result.kind() != query.kind()
            || self.result.len() > u64::from(query.page_size())
        {
            return Err(SentryOutcomeError::ScopeMismatch);
        }
        self.rate_limit.validate()?;
        self.result.validate_against(
            query.kind(),
            &query.scope().provider_scope(),
            query.window(),
        )?;
        if self.compute_page_digest() != self.declared_page_digest {
            return Err(SentryOutcomeError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageReceipt {
    pub page_index: u16,
    pub query_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub next_cursor_digest: Option<Digest>,
    pub row_count: u64,
    pub page_digest: Digest,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorReceipt {
    pub page_index: u16,
    pub query_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub next_cursor_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryReceiptStatus {
    Completed,
    NoResults,
    Partial,
    RateLimited,
    BlockedEnv,
    AuthenticationRevoked,
    ScopeDenied,
    Cancelled,
}

impl QueryReceiptStatus {
    fn has_result(self) -> bool {
        matches!(self, Self::Completed | Self::NoResults)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryReceipt {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub plugin_digest: Digest,
    pub registration_digest: Digest,
    pub registration_generation: u64,
    pub query_kind: SentryQueryKind,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub window: QueryWindow,
    pub provenance: Provenance,
    pub status: QueryReceiptStatus,
    pub page_receipts: Vec<PageReceipt>,
    pub cursor_receipts: Vec<CursorReceipt>,
    pub rate_limit_receipts: Vec<RateLimitReceipt>,
    pub source_result_digest: Option<Digest>,
    pub result_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
}

impl QueryReceipt {
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), SentryOutcomeError> {
        let definition = SentryOutcomePluginDefinition::layer1()
            .map_err(|_| SentryOutcomeError::AmbiguousReceipt)?;
        if self.schema_version != "hartevo.sentry-outcome-query-receipt/v1"
            || self.provider_id != SENTRY_OUTCOME_PROVIDER_ID
            || self.provider_version != PluginVersion::V1
            || self.plugin_digest != definition.digest()
            || !is_sha256(&self.registration_digest)
            || self.registration_generation == 0
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.scope_digest)
            || self.page_receipts.len() > usize::from(MAX_PAGES)
            || self.page_receipts.len() != self.cursor_receipts.len()
            || self.source_result_digest != self.result_digest
            || self.status.has_result() != self.result_digest.is_some()
        {
            return Err(SentryOutcomeError::AmbiguousReceipt);
        }
        for rate_limit in &self.rate_limit_receipts {
            rate_limit.validate()?;
        }
        if self.status.has_result() && self.page_receipts.is_empty() {
            return Err(SentryOutcomeError::AmbiguousReceipt);
        }
        Ok(())
    }

    pub fn validate_for(&self, scope: &SentryScope) -> Result<(), SentryOutcomeError> {
        self.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(SentryOutcomeError::ScopeMismatch);
        }
        let definition = SentryOutcomePluginDefinition::layer1()?;
        let expected =
            RegistrationReceipt::active(&definition, scope.clone(), self.registration_generation);
        if expected.registration_digest != self.registration_digest {
            return Err(SentryOutcomeError::RegistrationMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SentryQueryExecution {
    pub query: SentryQuery,
    pub receipt: QueryReceipt,
    pub receipt_digest: Digest,
    pub result: Option<SentryQueryResult>,
    pub provenance: Provenance,
}

impl SentryQueryExecution {
    pub fn is_completed(&self) -> bool {
        self.receipt.status.has_result()
    }

    pub fn is_native(&self) -> bool {
        self.provenance.is_native() && self.is_completed()
    }

    pub fn is_connected(&self) -> bool {
        self.is_native()
    }
}

#[async_trait]
pub trait SentryTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> Provenance;

    #[allow(clippy::unused_async)]
    async fn probe(
        &self,
        scope: &SentryScope,
        at: DateTime<Utc>,
    ) -> Result<ProbeObservation, SentryTransportError>;

    async fn read(&self, query: &SentryQuery) -> Result<SentryTransportPage, SentryTransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub name: String,
}

impl SecretReference {
    pub fn new(name: impl Into<String>) -> Result<Self, SentryOutcomeError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
        {
            return Err(SentryOutcomeError::InvalidIdentifier {
                label: "secret_reference",
            });
        }
        Ok(Self { name })
    }
}

/// Secret material is intentionally not serializable and never includes its
/// value in Debug or provider errors.
pub struct SecretMaterial(String);

impl SecretMaterial {
    fn new(value: String) -> Result<Self, SentryTransportError> {
        if value.is_empty() {
            return Err(SentryTransportError::BlockedEnv);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(REDACTED)")
    }
}

pub trait SecretResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<SecretMaterial, SentryTransportError>;
}

#[derive(Clone, Debug, Default)]
pub struct EnvironmentSecretResolver;

impl SecretResolver for EnvironmentSecretResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<SecretMaterial, SentryTransportError> {
        let value = env::var(&reference.name).map_err(|_| SentryTransportError::BlockedEnv)?;
        SecretMaterial::new(value)
    }
}

#[derive(Clone)]
pub struct HttpsSentryTransport {
    client: Client,
    base_url: Url,
    auth: SecretReference,
    resolver: Arc<dyn SecretResolver>,
}

impl fmt::Debug for HttpsSentryTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpsSentryTransport")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

impl HttpsSentryTransport {
    pub fn new(
        base_url: Url,
        auth: SecretReference,
        resolver: Arc<dyn SecretResolver>,
    ) -> Result<Self, SentryTransportError> {
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(SentryTransportError::InvalidEndpoint);
        }
        let client = Client::builder()
            .timeout(StdDuration::from_secs(15))
            .build()
            .map_err(|_| SentryTransportError::RequestFailed)?;
        Ok(Self {
            client,
            base_url,
            auth,
            resolver,
        })
    }

    pub fn sentry_io(
        auth: SecretReference,
        resolver: Arc<dyn SecretResolver>,
    ) -> Result<Self, SentryTransportError> {
        Self::new(
            Url::parse("https://sentry.io").map_err(|_| SentryTransportError::InvalidEndpoint)?,
            auth,
            resolver,
        )
    }

    fn endpoint(&self, query: &SentryQuery) -> Result<Url, SentryTransportError> {
        let mut endpoint = self.base_url.clone();
        let kind = match query.kind() {
            SentryQueryKind::Issues => "issues",
            SentryQueryKind::Events => "events",
            SentryQueryKind::Releases => "releases",
        };
        {
            let mut segments = endpoint
                .path_segments_mut()
                .map_err(|()| SentryTransportError::InvalidEndpoint)?;
            segments.clear();
            segments.push("api");
            segments.push("0");
            segments.push("organizations");
            segments.push(&query.scope().organization_id);
            segments.push(kind);
        }
        let scope = query.scope();
        let window = query.window();
        let mut pairs = endpoint.query_pairs_mut();
        pairs.append_pair("project", &scope.project_id);
        pairs.append_pair("environment", &scope.environment);
        pairs.append_pair("release", &scope.release);
        pairs.append_pair("start", &window.from.to_rfc3339());
        pairs.append_pair("end", &window.until.to_rfc3339());
        pairs.append_pair("limit", &query.page_size().to_string());
        if let Some(cursor) = query.cursor() {
            pairs.append_pair("cursor", cursor.as_str());
        }
        drop(pairs);
        Ok(endpoint)
    }

    async fn send(
        &self,
        query: &SentryQuery,
    ) -> Result<(Vec<u8>, header::HeaderMap), SentryTransportError> {
        let secret = self.resolver.resolve(&self.auth)?;
        let response = self
            .client
            .get(self.endpoint(query)?)
            .header(header::ACCEPT, "application/json")
            .bearer_auth(secret.expose())
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    SentryTransportError::Timeout
                } else {
                    SentryTransportError::RequestFailed
                }
            })?;
        let status = response.status();
        let headers = response.headers().clone();
        if status == StatusCode::UNAUTHORIZED {
            return Err(SentryTransportError::AuthenticationRevoked);
        }
        if status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND {
            return Err(SentryTransportError::ScopeDenied);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(rate_limit_from_headers(&headers));
        }
        if !status.is_success() {
            return Err(SentryTransportError::RequestFailed);
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| SentryTransportError::RequestFailed)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(SentryTransportError::ResponseTooLarge);
        }
        Ok((body.to_vec(), headers))
    }

    fn decode_page(
        query: &SentryQuery,
        body: &[u8],
        headers: &header::HeaderMap,
    ) -> Result<SentryTransportPage, SentryTransportError> {
        let next_cursor = next_cursor_from_headers(headers)?;
        let observed_at = query.window().until;
        let rate_limit = rate_limit_receipt_from_headers(headers);
        let result = match query.kind() {
            SentryQueryKind::Issues => {
                let raw = parse_raw_list::<RawIssue>(body)?;
                let records = raw
                    .into_iter()
                    .map(|issue| {
                        raw_issue_to_record(&query.scope().provider_scope(), issue, query.window())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                SentryQueryResult::Issues(records)
            }
            SentryQueryKind::Events => {
                let raw = parse_raw_list::<RawEvent>(body)?;
                let records = raw
                    .into_iter()
                    .map(|event| {
                        raw_event_to_record(&query.scope().provider_scope(), event, query.window())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                SentryQueryResult::Events(records)
            }
            SentryQueryKind::Releases => {
                let raw = parse_raw_list::<RawRelease>(body)?;
                let records = raw
                    .into_iter()
                    .map(|release| {
                        raw_release_to_record(
                            &query.scope().provider_scope(),
                            release,
                            query.window(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                SentryQueryResult::Releases(records)
            }
        };
        SentryTransportPage::new(query, result, next_cursor, observed_at, rate_limit)
            .map_err(|_| SentryTransportError::InvalidResponse)
    }
}

#[async_trait]
impl SentryTransport for HttpsSentryTransport {
    fn provenance(&self) -> Provenance {
        Provenance::NativeHttps
    }

    async fn probe(
        &self,
        scope: &SentryScope,
        at: DateTime<Utc>,
    ) -> Result<ProbeObservation, SentryTransportError> {
        let window = QueryWindow::new(at - Duration::seconds(300), at)
            .map_err(|_| SentryTransportError::InvalidResponse)?;
        let query = IssueQuery::new(scope.clone(), window, 1, None)
            .map_err(|_| SentryTransportError::InvalidResponse)
            .and_then(|query| {
                SentryQuery::issues(query).map_err(|_| SentryTransportError::InvalidResponse)
            })?;
        let _ = self.read(&query).await?;
        Ok(ProbeObservation::reachable(
            scope,
            at,
            Provenance::NativeHttps,
        ))
    }

    #[allow(clippy::unused_async)]
    async fn read(&self, query: &SentryQuery) -> Result<SentryTransportPage, SentryTransportError> {
        let (body, headers) = self.send(query).await?;
        Self::decode_page(query, &body, &headers)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawList<T> {
    Items(Vec<T>),
    Wrapped { data: Vec<T> },
}

impl<T> RawList<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::Items(items) => items,
            Self::Wrapped { data } => data,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawCount {
    Number(u64),
    Text(String),
}

impl RawCount {
    fn value(self) -> u64 {
        match self {
            Self::Number(value) => value,
            Self::Text(value) => value.parse().unwrap_or(0),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawFingerprint {
    Many(Vec<String>),
    One(String),
}

impl RawFingerprint {
    fn first(self) -> Option<String> {
        match self {
            Self::Many(values) => values.into_iter().next(),
            Self::One(value) => Some(value),
        }
    }
}

#[derive(Deserialize)]
struct RawIssue {
    id: String,
    #[serde(rename = "shortId", default)]
    short_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    culprit: Option<String>,
    #[serde(rename = "firstSeen", default)]
    first_seen: Option<String>,
    #[serde(rename = "lastSeen", default)]
    last_seen: Option<String>,
    #[serde(default)]
    count: Option<RawCount>,
    #[serde(default)]
    fingerprint: Option<RawFingerprint>,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(rename = "eventID", alias = "id", default)]
    id: Option<String>,
    #[serde(rename = "issueId", default)]
    issue_id: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    fingerprint: Option<RawFingerprint>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    exception: Option<RawException>,
}

#[derive(Deserialize, Serialize)]
struct RawException {
    #[serde(default)]
    values: Vec<RawExceptionValue>,
}

#[derive(Deserialize, Serialize)]
struct RawExceptionValue {
    #[serde(rename = "type", default)]
    type_name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    stacktrace: Option<RawStacktrace>,
}

#[derive(Deserialize, Serialize)]
struct RawStacktrace {
    #[serde(default)]
    frames: Vec<RawStackFrame>,
}

#[derive(Deserialize, Serialize)]
struct RawStackFrame {
    #[serde(default)]
    function: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    lineno: Option<u64>,
    #[serde(default)]
    colno: Option<u64>,
}

#[derive(Deserialize)]
struct RawDeploy {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Deserialize)]
struct RawRelease {
    #[serde(default)]
    id: Option<String>,
    version: String,
    #[serde(rename = "dateCreated", default)]
    date_created: Option<String>,
    #[serde(rename = "dateReleased", default)]
    date_released: Option<String>,
    #[serde(rename = "newGroups", default)]
    new_groups: Option<RawCount>,
    #[serde(rename = "resolvedGroups", default)]
    resolved_groups: Option<RawCount>,
    #[serde(default)]
    deploys: Option<Vec<RawDeploy>>,
}

fn parse_raw_list<T: for<'de> Deserialize<'de>>(
    body: &[u8],
) -> Result<Vec<T>, SentryTransportError> {
    serde_json::from_slice::<RawList<T>>(body)
        .map(RawList::into_vec)
        .map_err(|_| SentryTransportError::InvalidResponse)
}

fn parse_optional_timestamp(
    value: Option<String>,
    fallback: DateTime<Utc>,
) -> Result<DateTime<Utc>, SentryTransportError> {
    value.map_or(Ok(fallback), |value| {
        DateTime::parse_from_rfc3339(&value)
            .map(|parsed| parsed.with_timezone(&Utc))
            .map_err(|_| SentryTransportError::InvalidResponse)
    })
}

fn raw_issue_to_record(
    scope: &SentryProviderScope,
    raw: RawIssue,
    window: &QueryWindow,
) -> Result<SentryIssueRecord, SentryTransportError> {
    let fingerprint = raw
        .fingerprint
        .and_then(RawFingerprint::first)
        .unwrap_or_else(|| format!("issue:{}", raw.id));
    SentryIssueRecord::new(
        scope.clone(),
        raw.id.clone(),
        raw.short_id.unwrap_or_else(|| raw.id.clone()),
        raw.title.as_deref().unwrap_or("[redacted]"),
        raw.culprit.as_deref(),
        parse_optional_timestamp(raw.first_seen, window.from)?,
        parse_optional_timestamp(raw.last_seen, window.until)?,
        raw.count.map_or(0, RawCount::value),
        Fingerprint::new(fingerprint).map_err(|_| SentryTransportError::InvalidResponse)?,
    )
    .map_err(|_| SentryTransportError::InvalidResponse)
}

fn raw_event_to_record(
    scope: &SentryProviderScope,
    raw: RawEvent,
    window: &QueryWindow,
) -> Result<SentryEventRecord, SentryTransportError> {
    let id = raw.id.ok_or(SentryTransportError::InvalidResponse)?;
    let fingerprint = raw
        .fingerprint
        .and_then(RawFingerprint::first)
        .unwrap_or_else(|| format!("event:{id}"));
    let stacktrace = raw
        .exception
        .map(|value| serde_json::to_vec(&value).map_err(|_| SentryTransportError::InvalidResponse))
        .transpose()?
        .map(|bytes| {
            if bytes.len() > MAX_REDACTED_FIELD_BYTES {
                Err(SentryTransportError::ResponseTooLarge)
            } else {
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }
        })
        .transpose()?;
    SentryEventRecord::new(
        scope.clone(),
        id,
        raw.issue_id,
        parse_optional_timestamp(raw.timestamp, window.until)?,
        Fingerprint::new(fingerprint).map_err(|_| SentryTransportError::InvalidResponse)?,
        raw.message.as_deref(),
        stacktrace.as_deref(),
    )
    .map_err(|_| SentryTransportError::InvalidResponse)
}

fn raw_release_to_record(
    scope: &SentryProviderScope,
    raw: RawRelease,
    window: &QueryWindow,
) -> Result<SentryReleaseRecord, SentryTransportError> {
    let id = raw.id.unwrap_or_else(|| format!("release:{}", raw.version));
    let deployment_id = raw
        .deploys
        .and_then(|deploys| deploys.into_iter().find_map(|deploy| deploy.id));
    SentryReleaseRecord::new(
        scope.clone(),
        id,
        raw.version,
        deployment_id,
        parse_optional_timestamp(raw.date_created, window.from)?,
        raw.date_released
            .map(|released| parse_optional_timestamp(Some(released), window.until))
            .transpose()?,
        raw.new_groups.map_or(0, RawCount::value),
        raw.resolved_groups.map_or(0, RawCount::value),
    )
    .map_err(|_| SentryTransportError::InvalidResponse)
}

fn parse_header_u64(headers: &header::HeaderMap, name: header::HeaderName) -> Option<u64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn rate_limit_from_headers(headers: &header::HeaderMap) -> SentryTransportError {
    SentryTransportError::RateLimited {
        limit: parse_header_u64(
            headers,
            header::HeaderName::from_static("x-sentry-rate-limit-limit"),
        ),
        remaining: parse_header_u64(
            headers,
            header::HeaderName::from_static("x-sentry-rate-limit-remaining"),
        ),
        retry_after_seconds: parse_header_u64(headers, header::RETRY_AFTER),
        reset_at: parse_header_u64(
            headers,
            header::HeaderName::from_static("x-sentry-rate-limit-reset"),
        )
        .and_then(|value| i64::try_from(value).ok())
        .and_then(|value| DateTime::from_timestamp(value, 0)),
    }
}

fn rate_limit_receipt_from_headers(headers: &header::HeaderMap) -> RateLimitReceipt {
    RateLimitReceipt {
        limit: parse_header_u64(
            headers,
            header::HeaderName::from_static("x-sentry-rate-limit-limit"),
        ),
        remaining: parse_header_u64(
            headers,
            header::HeaderName::from_static("x-sentry-rate-limit-remaining"),
        ),
        reset_at: parse_header_u64(
            headers,
            header::HeaderName::from_static("x-sentry-rate-limit-reset"),
        )
        .and_then(|value| i64::try_from(value).ok())
        .and_then(|value| DateTime::from_timestamp(value, 0)),
        retry_after_seconds: parse_header_u64(headers, header::RETRY_AFTER),
        attempt: 0,
        backoff_seconds: 0,
    }
}

fn next_cursor_from_headers(
    headers: &header::HeaderMap,
) -> Result<Option<Cursor>, SentryTransportError> {
    let Some(link) = headers
        .get(header::LINK)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    for segment in link.split(',') {
        if !segment.contains("rel=\"next\"") {
            continue;
        }
        let Some(start) = segment.find('<') else {
            return Err(SentryTransportError::InvalidResponse);
        };
        let Some(end) = segment[start + 1..].find('>') else {
            return Err(SentryTransportError::InvalidResponse);
        };
        let url = Url::parse(&segment[start + 1..start + 1 + end])
            .map_err(|_| SentryTransportError::InvalidResponse)?;
        if let Some((_, value)) = url.query_pairs().find(|(key, _)| key == "cursor") {
            return Cursor::new(value.into_owned())
                .map(Some)
                .map_err(|_| SentryTransportError::InvalidResponse);
        }
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackoffPolicy {
    pub max_retries: u8,
    pub base_delay_millis: u64,
    pub max_backoff_seconds: u64,
    pub honor_retry_after: bool,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            max_retries: MAX_RETRIES,
            base_delay_millis: 100,
            max_backoff_seconds: MAX_BACKOFF_SECONDS,
            honor_retry_after: true,
        }
    }
}

impl BackoffPolicy {
    pub fn deterministic() -> Self {
        Self {
            max_retries: MAX_RETRIES,
            base_delay_millis: 0,
            max_backoff_seconds: 0,
            honor_retry_after: false,
        }
    }

    fn validate(self) -> Result<(), SentryOutcomeError> {
        if self.max_retries > MAX_RETRIES || self.max_backoff_seconds > MAX_BACKOFF_SECONDS {
            return Err(SentryOutcomeError::InvalidQueryBounds);
        }
        Ok(())
    }

    fn delay_seconds(self, retry_index: u8, retry_after: Option<u64>) -> u64 {
        let exponential = self
            .base_delay_millis
            .saturating_mul(2_u64.saturating_pow(u32::from(retry_index)))
            .div_ceil(1_000);
        let requested = if self.honor_retry_after {
            retry_after.unwrap_or(exponential)
        } else {
            exponential
        };
        requested.min(self.max_backoff_seconds)
    }
}

#[derive(Clone, Debug, Default)]
pub struct QueryCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl QueryCancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedFault {
    RateLimitedOnce,
    RateLimitedAlways,
    ResponseTampered,
    FingerprintMismatch,
    ScopeMismatch,
    DuplicateRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedSentryPage {
    pub query_kind: SentryQueryKind,
    pub cursor: Option<Cursor>,
    pub next_cursor: Option<Cursor>,
    pub result: SentryQueryResult,
    pub observed_at: DateTime<Utc>,
}

impl RecordedSentryPage {
    pub fn new(
        query_kind: SentryQueryKind,
        cursor: Option<Cursor>,
        next_cursor: Option<Cursor>,
        result: SentryQueryResult,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, SentryOutcomeError> {
        if result.kind() != query_kind || result.len() > u64::from(MAX_PAGE_SIZE) {
            return Err(SentryOutcomeError::QueryKindMismatch);
        }
        Ok(Self {
            query_kind,
            cursor,
            next_cursor,
            result,
            observed_at,
        })
    }
}

#[derive(Clone, Debug)]
struct RecordedSentryTransport {
    pages: BTreeMap<SentryQueryKind, Vec<RecordedSentryPage>>,
    provenance: Provenance,
    fault: Option<RecordedFault>,
    attempts: Arc<Mutex<u32>>,
}

impl RecordedSentryTransport {
    fn new(pages: Vec<RecordedSentryPage>, provenance: Provenance) -> Self {
        let mut grouped: BTreeMap<SentryQueryKind, Vec<RecordedSentryPage>> = BTreeMap::new();
        for page in pages {
            grouped.entry(page.query_kind).or_default().push(page);
        }
        for pages in grouped.values_mut() {
            pages.sort_by_key(|page| page.cursor.clone());
        }
        Self {
            pages: grouped,
            provenance,
            fault: None,
            attempts: Arc::new(Mutex::new(0)),
        }
    }

    fn with_fault(mut self, fault: RecordedFault) -> Self {
        self.fault = Some(fault);
        self
    }

    fn page_for(&self, query: &SentryQuery) -> Result<RecordedSentryPage, SentryTransportError> {
        self.pages
            .get(&query.kind())
            .and_then(|pages| {
                pages
                    .iter()
                    .find(|page| page.cursor.as_ref() == query.cursor())
            })
            .cloned()
            .ok_or(SentryTransportError::InvalidResponse)
    }

    fn rate_limited(&self) -> Result<bool, SentryTransportError> {
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|_| SentryTransportError::RequestFailed)?;
        let should_limit = match self.fault {
            Some(RecordedFault::RateLimitedOnce) => *attempts == 0,
            Some(RecordedFault::RateLimitedAlways) => true,
            _ => false,
        };
        *attempts = attempts.saturating_add(1);
        Ok(should_limit)
    }

    #[allow(clippy::unused_async)]
    async fn probe(
        &self,
        scope: &SentryScope,
        at: DateTime<Utc>,
    ) -> Result<ProbeObservation, SentryTransportError> {
        if matches!(self.fault, Some(RecordedFault::RateLimitedAlways)) {
            return Err(SentryTransportError::RateLimited {
                limit: Some(100),
                remaining: Some(0),
                retry_after_seconds: Some(1),
                reset_at: None,
            });
        }
        Ok(ProbeObservation::reachable(scope, at, self.provenance))
    }

    #[allow(clippy::unused_async)]
    async fn read(&self, query: &SentryQuery) -> Result<SentryTransportPage, SentryTransportError> {
        if self.rate_limited()? {
            return Err(SentryTransportError::RateLimited {
                limit: Some(100),
                remaining: Some(0),
                retry_after_seconds: Some(1),
                reset_at: None,
            });
        }
        let recorded = self.page_for(query)?;
        let mut result = recorded.result;
        if matches!(self.fault, Some(RecordedFault::ScopeMismatch)) {
            let other_scope = SentryProviderScope::new(
                "other-organization",
                "other-project",
                "other-environment",
                "other-release",
            )
            .map_err(|_| SentryTransportError::InvalidResponse)?;
            match &mut result {
                SentryQueryResult::Issues(records) => {
                    if let Some(record) = records.first_mut() {
                        record.scope = other_scope;
                    }
                }
                SentryQueryResult::Events(records) => {
                    if let Some(record) = records.first_mut() {
                        record.scope = other_scope;
                    }
                }
                SentryQueryResult::Releases(records) => {
                    if let Some(record) = records.first_mut() {
                        record.scope = other_scope;
                    }
                }
            }
        }
        if matches!(self.fault, Some(RecordedFault::FingerprintMismatch)) {
            match &mut result {
                SentryQueryResult::Issues(records) => {
                    if let Some(record) = records.first_mut() {
                        record.fingerprint_digest = "f".repeat(64);
                    }
                }
                SentryQueryResult::Events(records) => {
                    if let Some(record) = records.first_mut() {
                        record.fingerprint_digest = "f".repeat(64);
                    }
                }
                SentryQueryResult::Releases(_) => {}
            }
        }
        if matches!(self.fault, Some(RecordedFault::DuplicateRecord)) {
            match &mut result {
                SentryQueryResult::Issues(records) => {
                    if let Some(record) = records.first().cloned() {
                        records.push(record);
                    }
                }
                SentryQueryResult::Events(records) => {
                    if let Some(record) = records.first().cloned() {
                        records.push(record);
                    }
                }
                SentryQueryResult::Releases(records) => {
                    if let Some(record) = records.first().cloned() {
                        records.push(record);
                    }
                }
            }
        }
        let mut page = SentryTransportPage::new(
            query,
            result,
            recorded.next_cursor,
            recorded.observed_at,
            RateLimitReceipt::none(),
        )
        .map_err(|_| SentryTransportError::InvalidResponse)?;
        if matches!(self.fault, Some(RecordedFault::ResponseTampered)) {
            page.declared_page_digest = "f".repeat(64);
        }
        Ok(page)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackSentryTransport {
    inner: RecordedSentryTransport,
}

impl LoopbackSentryTransport {
    pub fn new(pages: Vec<RecordedSentryPage>) -> Result<Self, SentryOutcomeError> {
        Ok(Self {
            inner: RecordedSentryTransport::new(pages, Provenance::Loopback),
        })
    }

    pub fn demo(scope: &SentryScope) -> Result<Self, SentryOutcomeError> {
        Self::new(demo_pages(scope)?)
    }

    #[must_use]
    pub fn with_fault(self, fault: RecordedFault) -> Self {
        Self {
            inner: self.inner.with_fault(fault),
        }
    }
}

#[async_trait]
impl SentryTransport for LoopbackSentryTransport {
    fn provenance(&self) -> Provenance {
        self.inner.provenance
    }

    async fn probe(
        &self,
        scope: &SentryScope,
        at: DateTime<Utc>,
    ) -> Result<ProbeObservation, SentryTransportError> {
        self.inner.probe(scope, at).await
    }

    async fn read(&self, query: &SentryQuery) -> Result<SentryTransportPage, SentryTransportError> {
        self.inner.read(query).await
    }
}

#[derive(Clone, Debug)]
pub struct FixtureSentryTransport {
    inner: RecordedSentryTransport,
}

impl FixtureSentryTransport {
    pub fn new(pages: Vec<RecordedSentryPage>) -> Result<Self, SentryOutcomeError> {
        Ok(Self {
            inner: RecordedSentryTransport::new(pages, Provenance::Fixture),
        })
    }

    pub fn demo(scope: &SentryScope) -> Result<Self, SentryOutcomeError> {
        Self::new(demo_pages(scope)?)
    }
}

#[async_trait]
impl SentryTransport for FixtureSentryTransport {
    fn provenance(&self) -> Provenance {
        self.inner.provenance
    }

    async fn probe(
        &self,
        scope: &SentryScope,
        at: DateTime<Utc>,
    ) -> Result<ProbeObservation, SentryTransportError> {
        self.inner.probe(scope, at).await
    }

    async fn read(&self, query: &SentryQuery) -> Result<SentryTransportPage, SentryTransportError> {
        self.inner.read(query).await
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvSentryTransport;

#[async_trait]
impl SentryTransport for BlockedEnvSentryTransport {
    fn provenance(&self) -> Provenance {
        Provenance::BlockedEnv
    }

    async fn probe(
        &self,
        _scope: &SentryScope,
        _at: DateTime<Utc>,
    ) -> Result<ProbeObservation, SentryTransportError> {
        Err(SentryTransportError::BlockedEnv)
    }

    async fn read(
        &self,
        _query: &SentryQuery,
    ) -> Result<SentryTransportPage, SentryTransportError> {
        Err(SentryTransportError::BlockedEnv)
    }
}

fn demo_pages(scope: &SentryScope) -> Result<Vec<RecordedSentryPage>, SentryOutcomeError> {
    let provider_scope = scope.provider_scope();
    let from = DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .expect("static fixture time")
        .with_timezone(&Utc);
    let until = DateTime::parse_from_rfc3339("2026-08-14T00:05:00Z")
        .expect("static fixture time")
        .with_timezone(&Utc);
    let second = from + Duration::seconds(60);
    let first_issue = SentryIssueRecord::new(
        provider_scope.clone(),
        "issue-001",
        "PROJ-1",
        "redacted issue title",
        Some("redacted culprit"),
        from,
        second,
        3,
        Fingerprint::new("{{ default }}")?,
    )?;
    let second_issue = SentryIssueRecord::new(
        provider_scope.clone(),
        "issue-002",
        "PROJ-2",
        "second redacted issue",
        None,
        second,
        until,
        1,
        Fingerprint::new("{{ default }}:second")?,
    )?;
    let first_event = SentryEventRecord::new(
        provider_scope.clone(),
        "event-001",
        Some("issue-001"),
        second,
        Fingerprint::new("{{ default }}")?,
        Some("token-never-retained"),
        Some("stacktrace-never-retained"),
    )?;
    let release = SentryReleaseRecord::new(
        provider_scope,
        "release-001",
        scope.release.clone(),
        Some(scope.deployment_id.clone()),
        from,
        Some(second),
        2,
        0,
    )?;
    let cursor = Cursor::new("page-2")?;
    Ok(vec![
        RecordedSentryPage::new(
            SentryQueryKind::Issues,
            None,
            Some(cursor),
            SentryQueryResult::Issues(vec![first_issue]),
            until,
        )?,
        RecordedSentryPage::new(
            SentryQueryKind::Issues,
            Some(Cursor::new("page-2")?),
            None,
            SentryQueryResult::Issues(vec![second_issue]),
            until,
        )?,
        RecordedSentryPage::new(
            SentryQueryKind::Events,
            None,
            None,
            SentryQueryResult::Events(vec![first_event]),
            until,
        )?,
        RecordedSentryPage::new(
            SentryQueryKind::Releases,
            None,
            None,
            SentryQueryResult::Releases(vec![release]),
            until,
        )?,
    ])
}

#[derive(Clone, Debug)]
enum RegistrationState {
    Unregistered,
    Active(Box<RegistrationReceipt>),
    Revoked,
}

#[derive(Clone)]
pub struct SentryOutcomeProvider {
    transport: Arc<dyn SentryTransport>,
    backoff: BackoffPolicy,
    definition: SentryOutcomePluginDefinition,
    registration: Arc<Mutex<RegistrationState>>,
}

impl fmt::Debug for SentryOutcomeProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SentryOutcomeProvider")
            .field("transport_provenance", &self.transport.provenance())
            .field("backoff", &self.backoff)
            .field("definition_digest", &self.definition.digest())
            .field("registration", &self.registration.lock().ok())
            .finish()
    }
}

impl SentryOutcomeProvider {
    pub fn new<T>(transport: T) -> Self
    where
        T: SentryTransport + 'static,
    {
        Self {
            transport: Arc::new(transport),
            backoff: BackoffPolicy::default(),
            definition: SentryOutcomePluginDefinition::layer1()
                .expect("embedded Sentry Layer 1 contract is valid"),
            registration: Arc::new(Mutex::new(RegistrationState::Unregistered)),
        }
    }

    pub fn for_scope<T>(
        transport: T,
        scope: SentryScope,
        generation: u64,
    ) -> Result<Self, SentryOutcomeError>
    where
        T: SentryTransport + 'static,
    {
        let provider = Self::new(transport);
        provider.register(scope, generation)?;
        Ok(provider)
    }

    pub fn with_backoff(mut self, backoff: BackoffPolicy) -> Result<Self, SentryOutcomeError> {
        backoff.validate()?;
        self.backoff = backoff;
        Ok(self)
    }

    pub fn register(
        &self,
        scope: SentryScope,
        generation: u64,
    ) -> Result<RegistrationReceipt, SentryOutcomeError> {
        let receipt = self.definition.bind(scope, generation)?;
        let mut state = self
            .registration
            .lock()
            .map_err(|_| SentryOutcomeError::RegistrationMismatch)?;
        *state = RegistrationState::Active(Box::new(receipt.clone()));
        Ok(receipt)
    }

    pub fn attach_registration(
        &self,
        receipt: RegistrationReceipt,
    ) -> Result<(), SentryOutcomeError> {
        receipt.validate(&self.definition)?;
        if receipt.status != RegistrationStatus::Active {
            return Err(SentryOutcomeError::RegistrationRevoked);
        }
        let mut state = self
            .registration
            .lock()
            .map_err(|_| SentryOutcomeError::RegistrationMismatch)?;
        *state = RegistrationState::Active(Box::new(receipt));
        Ok(())
    }

    pub fn registration(&self) -> Result<Option<RegistrationReceipt>, SentryOutcomeError> {
        let state = self
            .registration
            .lock()
            .map_err(|_| SentryOutcomeError::RegistrationMismatch)?;
        Ok(match &*state {
            RegistrationState::Active(receipt) => Some(receipt.as_ref().clone()),
            RegistrationState::Unregistered | RegistrationState::Revoked => None,
        })
    }

    pub fn revoke(&self) -> Result<RevocationReceipt, SentryOutcomeError> {
        let mut state = self
            .registration
            .lock()
            .map_err(|_| SentryOutcomeError::RegistrationMismatch)?;
        let RegistrationState::Active(receipt) = &*state else {
            return Err(SentryOutcomeError::RegistrationRequired);
        };
        let revocation = receipt.revoke();
        *state = RegistrationState::Revoked;
        Ok(revocation)
    }

    fn active_registration(
        &self,
        scope: &SentryScope,
    ) -> Result<RegistrationReceipt, SentryOutcomeError> {
        let state = self
            .registration
            .lock()
            .map_err(|_| SentryOutcomeError::RegistrationMismatch)?;
        match &*state {
            RegistrationState::Unregistered => Err(SentryOutcomeError::RegistrationRequired),
            RegistrationState::Revoked => Err(SentryOutcomeError::RegistrationRevoked),
            RegistrationState::Active(receipt) => {
                receipt.validate(&self.definition)?;
                if receipt.scope != *scope {
                    return Err(SentryOutcomeError::ScopeMismatch);
                }
                Ok(receipt.as_ref().clone())
            }
        }
    }

    pub async fn probe(&self, scope: &SentryScope, at: DateTime<Utc>) -> ProbeObservation {
        if self.active_registration(scope).is_err() {
            return ProbeObservation::failed(
                scope,
                at,
                self.transport.provenance(),
                ProbeStatus::Unknown,
            );
        }
        match self.transport.probe(scope, at).await {
            Ok(observation)
                if observation.scope_digest == scope.digest()
                    && observation.provenance == self.transport.provenance()
                    && observation.native == observation.provenance.is_native()
                    && observation.connected == observation.native =>
            {
                observation
            }
            Ok(_) => ProbeObservation::failed(
                scope,
                at,
                self.transport.provenance(),
                ProbeStatus::Unknown,
            ),
            Err(error) => ProbeObservation::failed(
                scope,
                at,
                if matches!(error, SentryTransportError::BlockedEnv) {
                    Provenance::BlockedEnv
                } else {
                    self.transport.provenance()
                },
                probe_status_from_transport(&error),
            ),
        }
    }

    pub async fn query_issues(
        &self,
        query: IssueQuery,
        cancellation: &QueryCancellationToken,
    ) -> Result<SentryQueryExecution, SentryOutcomeError> {
        self.execute(SentryQuery::issues(query)?, cancellation)
            .await
    }

    pub async fn query_events(
        &self,
        query: EventQuery,
        cancellation: &QueryCancellationToken,
    ) -> Result<SentryQueryExecution, SentryOutcomeError> {
        self.execute(SentryQuery::events(query)?, cancellation)
            .await
    }

    pub async fn query_releases(
        &self,
        query: ReleaseQuery,
        cancellation: &QueryCancellationToken,
    ) -> Result<SentryQueryExecution, SentryOutcomeError> {
        self.execute(SentryQuery::releases(query)?, cancellation)
            .await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn execute(
        &self,
        query: SentryQuery,
        cancellation: &QueryCancellationToken,
    ) -> Result<SentryQueryExecution, SentryOutcomeError> {
        query.validate()?;
        let registration = self.active_registration(query.scope())?;
        let provenance = self.transport.provenance();
        let mut current = query.clone();
        let mut pages = Vec::new();
        let mut page_receipts = Vec::new();
        let mut cursor_receipts = Vec::new();
        let mut rate_limit_receipts = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut seen_cursor_digests = BTreeSet::new();
        let mut aggregate: Option<SentryQueryResult> = None;
        let mut retry_index = 0_u8;

        loop {
            if cancellation.is_cancelled() {
                return Ok(Self::execution_without_result(
                    &query,
                    &registration,
                    provenance,
                    QueryReceiptStatus::Cancelled,
                    page_receipts,
                    cursor_receipts,
                    rate_limit_receipts,
                    pages
                        .last()
                        .map_or(query.window().until, |page: &SentryTransportPage| {
                            page.observed_at
                        }),
                ));
            }

            match self.transport.read(&current).await {
                Ok(page) => {
                    page.validate_against(&current)?;
                    for id in page.result.record_ids() {
                        if !seen_ids.insert(id) {
                            return Err(SentryOutcomeError::DuplicateRecord);
                        }
                    }
                    if page.rate_limit.has_signal() {
                        rate_limit_receipts.push(page.rate_limit.clone());
                    }
                    let page_index = u16::try_from(page_receipts.len())
                        .map_err(|_| SentryOutcomeError::PaginationExceeded)?;
                    let next_cursor = page.next_cursor.clone();
                    page_receipts.push(PageReceipt {
                        page_index,
                        query_digest: page.query_digest.clone(),
                        cursor_digest: page.cursor.as_ref().map(Cursor::digest),
                        next_cursor_digest: next_cursor.as_ref().map(Cursor::digest),
                        row_count: page.result.len(),
                        page_digest: page.declared_page_digest.clone(),
                        observed_at: page.observed_at,
                    });
                    cursor_receipts.push(CursorReceipt {
                        page_index,
                        query_digest: page.query_digest.clone(),
                        cursor_digest: page.cursor.as_ref().map(Cursor::digest),
                        next_cursor_digest: next_cursor.as_ref().map(Cursor::digest),
                    });
                    if let Some(aggregate) = &mut aggregate {
                        aggregate.extend(page.result.clone())?;
                    } else {
                        aggregate = Some(page.result.clone());
                    }
                    let observed_at = page.observed_at;
                    pages.push(page);
                    retry_index = 0;
                    let Some(next_cursor) = next_cursor else {
                        let result = aggregate.ok_or(SentryOutcomeError::AmbiguousReceipt)?;
                        let status = if result.is_empty() {
                            QueryReceiptStatus::NoResults
                        } else {
                            QueryReceiptStatus::Completed
                        };
                        return Ok(Self::execution_with_result(
                            &query,
                            &registration,
                            provenance,
                            status,
                            page_receipts,
                            cursor_receipts,
                            rate_limit_receipts,
                            observed_at,
                            result,
                        ));
                    };
                    if pages.len() >= usize::from(MAX_PAGES) {
                        return Err(SentryOutcomeError::PaginationExceeded);
                    }
                    if current
                        .cursor()
                        .is_some_and(|cursor| cursor == &next_cursor)
                        || !seen_cursor_digests.insert(next_cursor.digest())
                    {
                        return Err(SentryOutcomeError::NonMonotonicCursor);
                    }
                    current = current.with_cursor(Some(next_cursor))?;
                }
                Err(SentryTransportError::RateLimited {
                    limit,
                    remaining,
                    retry_after_seconds,
                    reset_at,
                }) => {
                    let backoff_seconds =
                        self.backoff.delay_seconds(retry_index, retry_after_seconds);
                    rate_limit_receipts.push(RateLimitReceipt {
                        limit,
                        remaining,
                        reset_at,
                        retry_after_seconds,
                        attempt: retry_index.saturating_add(1),
                        backoff_seconds,
                    });
                    if retry_index >= self.backoff.max_retries {
                        return Ok(Self::execution_without_result(
                            &query,
                            &registration,
                            provenance,
                            QueryReceiptStatus::RateLimited,
                            page_receipts,
                            cursor_receipts,
                            rate_limit_receipts,
                            query.window().until,
                        ));
                    }
                    if backoff_seconds > 0 {
                        tokio::time::sleep(StdDuration::from_secs(backoff_seconds)).await;
                    }
                    retry_index = retry_index.saturating_add(1);
                }
                Err(SentryTransportError::BlockedEnv) => {
                    return Ok(Self::execution_without_result(
                        &query,
                        &registration,
                        Provenance::BlockedEnv,
                        QueryReceiptStatus::BlockedEnv,
                        page_receipts,
                        cursor_receipts,
                        rate_limit_receipts,
                        query.window().until,
                    ));
                }
                Err(SentryTransportError::AuthenticationRevoked) => {
                    return Ok(Self::execution_without_result(
                        &query,
                        &registration,
                        provenance,
                        QueryReceiptStatus::AuthenticationRevoked,
                        page_receipts,
                        cursor_receipts,
                        rate_limit_receipts,
                        query.window().until,
                    ));
                }
                Err(SentryTransportError::ScopeDenied) => {
                    return Ok(Self::execution_without_result(
                        &query,
                        &registration,
                        provenance,
                        QueryReceiptStatus::ScopeDenied,
                        page_receipts,
                        cursor_receipts,
                        rate_limit_receipts,
                        query.window().until,
                    ));
                }
                Err(error) => return Err(SentryOutcomeError::Transport(error)),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execution_without_result(
        query: &SentryQuery,
        registration: &RegistrationReceipt,
        provenance: Provenance,
        status: QueryReceiptStatus,
        page_receipts: Vec<PageReceipt>,
        cursor_receipts: Vec<CursorReceipt>,
        rate_limit_receipts: Vec<RateLimitReceipt>,
        observed_at: DateTime<Utc>,
    ) -> SentryQueryExecution {
        let receipt = QueryReceipt {
            schema_version: "hartevo.sentry-outcome-query-receipt/v1".into(),
            provider_id: SENTRY_OUTCOME_PROVIDER_ID.into(),
            provider_version: PluginVersion::V1,
            plugin_digest: SentryOutcomePluginDefinition::layer1()
                .expect("embedded Sentry Layer 1 contract is valid")
                .digest(),
            registration_digest: registration.registration_digest.clone(),
            registration_generation: registration.generation,
            query_kind: query.kind(),
            request_digest: query.digest(),
            scope_digest: query.scope().digest(),
            window: query.window().clone(),
            provenance,
            status,
            page_receipts,
            cursor_receipts,
            rate_limit_receipts,
            source_result_digest: None,
            result_digest: None,
            observed_at,
        };
        let receipt_digest = receipt.digest();
        SentryQueryExecution {
            query: query.clone(),
            receipt,
            receipt_digest,
            result: None,
            provenance,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execution_with_result(
        query: &SentryQuery,
        registration: &RegistrationReceipt,
        provenance: Provenance,
        status: QueryReceiptStatus,
        page_receipts: Vec<PageReceipt>,
        cursor_receipts: Vec<CursorReceipt>,
        rate_limit_receipts: Vec<RateLimitReceipt>,
        observed_at: DateTime<Utc>,
        result: SentryQueryResult,
    ) -> SentryQueryExecution {
        let result_digest = result.digest();
        let receipt = QueryReceipt {
            schema_version: "hartevo.sentry-outcome-query-receipt/v1".into(),
            provider_id: SENTRY_OUTCOME_PROVIDER_ID.into(),
            provider_version: PluginVersion::V1,
            plugin_digest: SentryOutcomePluginDefinition::layer1()
                .expect("embedded Sentry Layer 1 contract is valid")
                .digest(),
            registration_digest: registration.registration_digest.clone(),
            registration_generation: registration.generation,
            query_kind: query.kind(),
            request_digest: query.digest(),
            scope_digest: query.scope().digest(),
            window: query.window().clone(),
            provenance,
            status,
            page_receipts,
            cursor_receipts,
            rate_limit_receipts,
            source_result_digest: Some(result_digest.clone()),
            result_digest: Some(result_digest),
            observed_at,
        };
        let receipt_digest = receipt.digest();
        SentryQueryExecution {
            query: query.clone(),
            receipt,
            receipt_digest,
            result: Some(result),
            provenance,
        }
    }
}

fn probe_status_from_transport(error: &SentryTransportError) -> ProbeStatus {
    match error {
        SentryTransportError::BlockedEnv => ProbeStatus::BlockedEnv,
        SentryTransportError::AuthenticationRevoked => ProbeStatus::AuthenticationRevoked,
        SentryTransportError::ScopeDenied => ProbeStatus::ScopeDenied,
        SentryTransportError::RateLimited { .. } => ProbeStatus::RateLimited,
        SentryTransportError::Timeout
        | SentryTransportError::InvalidEndpoint
        | SentryTransportError::InvalidResponse
        | SentryTransportError::ResponseTooLarge
        | SentryTransportError::RequestFailed => ProbeStatus::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    NativeHttps,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl From<Provenance> for EvidenceClassification {
    fn from(value: Provenance) -> Self {
        match value {
            Provenance::NativeHttps => Self::NativeHttps,
            Provenance::Fixture => Self::Fixture,
            Provenance::Loopback => Self::Loopback,
            Provenance::BlockedEnv => Self::BlockedEnv,
        }
    }
}

impl EvidenceClassification {
    pub fn is_native(self) -> bool {
        matches!(self, Self::NativeHttps)
    }

    pub fn is_connected(self) -> bool {
        self.is_native()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OutcomeObservation {
    RecordsObserved { count: u64 },
    NoMatchingRecords,
    Partial { count: u64 },
    Unavailable { status: QueryReceiptStatus },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeEvidenceRequest {
    pub query_digest: Digest,
    pub query_kind: SentryQueryKind,
    pub scope: SentryScope,
    pub binding: MissionOutcomeBinding,
    pub window: QueryWindow,
    pub proposed_at: DateTime<Utc>,
    pub max_age_seconds: u64,
}

impl MissionOutcomeEvidenceRequest {
    pub fn new(
        query: &SentryQuery,
        binding: MissionOutcomeBinding,
        proposed_at: DateTime<Utc>,
        max_age_seconds: u64,
    ) -> Result<Self, SentryOutcomeError> {
        query.validate()?;
        binding.validate()?;
        if binding != query.scope().mission_binding()
            || max_age_seconds == 0
            || max_age_seconds
                > u64::try_from(MAX_QUERY_WINDOW_SECONDS)
                    .expect("positive query-window bound fits in u64")
        {
            return Err(SentryOutcomeError::BindingMismatch);
        }
        Ok(Self {
            query_digest: query.digest(),
            query_kind: query.kind(),
            scope: query.scope().clone(),
            binding,
            window: query.window().clone(),
            proposed_at,
            max_age_seconds,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeEvidence {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub scope: SentryScope,
    pub binding: MissionOutcomeBinding,
    pub query_kind: SentryQueryKind,
    pub window: QueryWindow,
    pub observed_at: DateTime<Utc>,
    pub query_digest: Digest,
    pub query_receipt_digest: Digest,
    pub cursor_receipt_digest: Digest,
    pub rate_limit_receipt_digest: Digest,
    pub source_result_digest: Option<Digest>,
    pub identity_digests: Vec<Digest>,
    pub evidence_digest: Digest,
    pub observation: OutcomeObservation,
    pub classification: EvidenceClassification,
    pub native: bool,
    pub connected: bool,
    pub health_claim: bool,
    pub absence_is_success: bool,
}

#[derive(Serialize)]
struct EvidenceMaterial<'a> {
    provider_id: &'a str,
    provider_version: PluginVersion,
    registration_digest: &'a str,
    scope: &'a SentryScope,
    binding: &'a MissionOutcomeBinding,
    query_kind: SentryQueryKind,
    window: &'a QueryWindow,
    observed_at: DateTime<Utc>,
    query_digest: &'a str,
    query_receipt_digest: &'a str,
    cursor_receipt_digest: &'a str,
    rate_limit_receipt_digest: &'a str,
    source_result_digest: &'a Option<Digest>,
    identity_digests: &'a [Digest],
    observation: OutcomeObservation,
    classification: EvidenceClassification,
    native: bool,
    connected: bool,
    health_claim: bool,
    absence_is_success: bool,
}

#[derive(Clone, Debug, Default)]
pub struct MissionOutcomeEvidenceConsumer;

impl MissionOutcomeEvidenceConsumer {
    #[allow(clippy::too_many_lines)]
    pub fn consume(
        &self,
        request: &MissionOutcomeEvidenceRequest,
        execution: &SentryQueryExecution,
    ) -> Result<MissionOutcomeEvidence, SentryOutcomeError> {
        request.scope.validate()?;
        request.binding.validate()?;
        if request.binding != request.scope.mission_binding()
            || execution.query.digest() != request.query_digest
            || execution.query.kind() != request.query_kind
            || execution.query.scope() != &request.scope
            || execution.query.window() != &request.window
        {
            return Err(SentryOutcomeError::BindingMismatch);
        }
        if execution.receipt.digest() != execution.receipt_digest {
            return Err(SentryOutcomeError::ResponseTampered);
        }
        execution.receipt.validate_for(&request.scope)?;
        if execution.receipt.request_digest != request.query_digest
            || execution.receipt.scope_digest != request.scope.digest()
            || execution.receipt.query_kind != request.query_kind
            || execution.receipt.window != request.window
            || execution.receipt.provenance != execution.provenance
        {
            return Err(SentryOutcomeError::AmbiguousReceipt);
        }
        let max_age = i64::try_from(request.max_age_seconds)
            .map_err(|_| SentryOutcomeError::StaleEvidence)?;
        if execution.receipt.observed_at > request.proposed_at
            || request
                .proposed_at
                .signed_duration_since(execution.receipt.observed_at)
                > Duration::seconds(max_age)
        {
            return Err(SentryOutcomeError::StaleEvidence);
        }

        if execution.receipt.status.has_result() {
            let result = execution
                .result
                .as_ref()
                .ok_or(SentryOutcomeError::AmbiguousReceipt)?;
            result.validate_against(
                request.query_kind,
                &request.scope.provider_scope(),
                &request.window,
            )?;
            let result_digest = result.digest();
            if execution.receipt.result_digest.as_deref() != Some(result_digest.as_str())
                || execution.receipt.source_result_digest.as_deref() != Some(result_digest.as_str())
            {
                return Err(SentryOutcomeError::ResponseTampered);
            }
            if result.record_ids().len()
                != usize::try_from(result.len())
                    .map_err(|_| SentryOutcomeError::AmbiguousReceipt)?
            {
                return Err(SentryOutcomeError::DuplicateRecord);
            }
        } else if execution.result.is_some() {
            return Err(SentryOutcomeError::AmbiguousReceipt);
        }

        let classification = EvidenceClassification::from(execution.provenance);
        let native = classification.is_native() && execution.receipt.status.has_result();
        let connected = native;
        if native != (classification.is_native() && execution.receipt.status.has_result()) {
            return Err(SentryOutcomeError::NativeClassificationMismatch);
        }
        let identity_digests = execution
            .result
            .as_ref()
            .map_or_else(Vec::new, SentryQueryResult::identity_digests);
        let count = execution.result.as_ref().map_or(0, SentryQueryResult::len);
        let observation = match execution.receipt.status {
            QueryReceiptStatus::Completed => OutcomeObservation::RecordsObserved { count },
            QueryReceiptStatus::NoResults => OutcomeObservation::NoMatchingRecords,
            QueryReceiptStatus::Partial => OutcomeObservation::Partial { count },
            status => OutcomeObservation::Unavailable { status },
        };
        let cursor_receipt_digest = canonical_digest(&execution.receipt.cursor_receipts);
        let rate_limit_receipt_digest = canonical_digest(&execution.receipt.rate_limit_receipts);
        let query_receipt_digest = execution.receipt.digest();
        let source_result_digest = execution.receipt.source_result_digest.clone();
        let material = EvidenceMaterial {
            provider_id: SENTRY_OUTCOME_PROVIDER_ID,
            provider_version: execution.receipt.provider_version,
            registration_digest: &execution.receipt.registration_digest,
            scope: &request.scope,
            binding: &request.binding,
            query_kind: request.query_kind,
            window: &request.window,
            observed_at: execution.receipt.observed_at,
            query_digest: &request.query_digest,
            query_receipt_digest: &query_receipt_digest,
            cursor_receipt_digest: &cursor_receipt_digest,
            rate_limit_receipt_digest: &rate_limit_receipt_digest,
            source_result_digest: &source_result_digest,
            identity_digests: &identity_digests,
            observation,
            classification,
            native,
            connected,
            health_claim: false,
            absence_is_success: false,
        };
        let evidence = MissionOutcomeEvidence {
            schema_version: "hartevo.mission-outcome-evidence/v1".into(),
            provider_id: SENTRY_OUTCOME_PROVIDER_ID.into(),
            provider_version: execution.receipt.provider_version,
            registration_digest: execution.receipt.registration_digest.clone(),
            scope: request.scope.clone(),
            binding: request.binding.clone(),
            query_kind: request.query_kind,
            window: request.window.clone(),
            observed_at: execution.receipt.observed_at,
            query_digest: request.query_digest.clone(),
            query_receipt_digest: query_receipt_digest.clone(),
            cursor_receipt_digest: cursor_receipt_digest.clone(),
            rate_limit_receipt_digest: rate_limit_receipt_digest.clone(),
            source_result_digest: source_result_digest.clone(),
            identity_digests: identity_digests.clone(),
            evidence_digest: canonical_digest(&material),
            observation,
            classification,
            native,
            connected,
            health_claim: false,
            absence_is_success: false,
        };
        if evidence.native
            != (evidence.classification.is_native() && execution.receipt.status.has_result())
            || evidence.connected != evidence.native
            || evidence.health_claim
            || evidence.absence_is_success
        {
            return Err(SentryOutcomeError::NativeClassificationMismatch);
        }
        Ok(evidence)
    }
}

#[derive(Clone, Debug)]
pub struct SentryOutcomeService {
    provider: SentryOutcomeProvider,
    consumer: MissionOutcomeEvidenceConsumer,
}

impl SentryOutcomeService {
    pub fn new(provider: SentryOutcomeProvider) -> Self {
        Self {
            provider,
            consumer: MissionOutcomeEvidenceConsumer,
        }
    }

    pub fn provider(&self) -> &SentryOutcomeProvider {
        &self.provider
    }

    pub async fn read_issues(
        &self,
        query: IssueQuery,
        cancellation: &QueryCancellationToken,
    ) -> Result<SentryQueryExecution, SentryOutcomeError> {
        self.provider.query_issues(query, cancellation).await
    }

    pub async fn read_events(
        &self,
        query: EventQuery,
        cancellation: &QueryCancellationToken,
    ) -> Result<SentryQueryExecution, SentryOutcomeError> {
        self.provider.query_events(query, cancellation).await
    }

    pub async fn read_releases(
        &self,
        query: ReleaseQuery,
        cancellation: &QueryCancellationToken,
    ) -> Result<SentryQueryExecution, SentryOutcomeError> {
        self.provider.query_releases(query, cancellation).await
    }

    pub fn propose_outcome_evidence(
        &self,
        request: &MissionOutcomeEvidenceRequest,
        execution: &SentryQueryExecution,
    ) -> Result<MissionOutcomeEvidence, SentryOutcomeError> {
        self.consumer.consume(request, execution)
    }
}
