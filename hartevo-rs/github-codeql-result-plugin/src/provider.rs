//! Read-only provider definitions, typed requests, bounded pages, and
//! fixture/recording/loopback/BLOCKED_ENV transports.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ALERT_ENDPOINT, ALERTS_ENDPOINT, ANALYSES_ENDPOINT, PROVIDER_API_REVISION, PROVIDER_ID,
    model::{
        AlertFingerprint, AlertNumber, AlertSeverity, AlertState, AnalysisId, AnalysisStatus,
        CodeScanningTool, CommitSha, Digest, GithubCodeqlScope, ModelError, PermissionSnapshot,
        RedactedLocation, RefName, RuleId, Version,
    },
};

pub use crate::model::TransportProvenance as ProviderProvenance;

fn serialized_len<T: Serialize>(value: &T) -> u32 {
    match serde_json::to_vec(value) {
        Ok(bytes) => u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        Err(_) => u32::MAX,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubCodeScanningApiVersion {
    V1,
}

impl GithubCodeScanningApiVersion {
    pub const fn as_str(self) -> &'static str {
        PROVIDER_API_REVISION
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider identity or version is invalid")]
    InvalidIdentity,
    #[error("provider API revision is not the Layer-1 read revision")]
    InvalidApiRevision,
    #[error("provider permission snapshot is not the required read-only set")]
    InvalidPermissions,
    #[error("provider provenance is not an allowed Layer-1 provenance")]
    InvalidProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubCodeScanningProviderDefinition {
    pub provider_id: String,
    pub provider_version: Version,
    pub api_revision: GithubCodeScanningApiVersion,
    pub provenance: ProviderProvenance,
    pub permissions: PermissionSnapshot,
    pub provider_digest: Digest,
    pub api_digest: Digest,
}

pub type GithubProviderDefinition = GithubCodeScanningProviderDefinition;

impl GithubCodeScanningProviderDefinition {
    pub fn new(
        provider_version: Version,
        provenance: ProviderProvenance,
        permissions: PermissionSnapshot,
    ) -> Result<Self, ProviderDefinitionError> {
        permissions
            .validate()
            .map_err(|_| ProviderDefinitionError::InvalidPermissions)?;
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version,
            api_revision: GithubCodeScanningApiVersion::V1,
            provenance,
            permissions,
            provider_digest: Digest::from_text("unsealed-github-codeql-provider"),
            api_digest: Self::expected_api_digest(),
        };
        definition.provider_digest = definition.computed_provider_digest();
        definition.validate()?;
        Ok(definition)
    }

    pub fn layer1(provenance: ProviderProvenance) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            Version::new(0, 1, 0),
            provenance,
            PermissionSnapshot::least_privilege(),
        )
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.provider_id != PROVIDER_ID {
            return Err(ProviderDefinitionError::InvalidIdentity);
        }
        if self.api_revision.as_str() != PROVIDER_API_REVISION {
            return Err(ProviderDefinitionError::InvalidApiRevision);
        }
        if self.api_digest != Self::expected_api_digest() {
            return Err(ProviderDefinitionError::InvalidApiRevision);
        }
        if self.permissions.validate().is_err() {
            return Err(ProviderDefinitionError::InvalidPermissions);
        }
        if self.provenance.connected() || self.provenance.native() || self.provenance.first_party()
        {
            return Err(ProviderDefinitionError::InvalidProvenance);
        }
        if self.provider_digest != self.computed_provider_digest() {
            return Err(ProviderDefinitionError::InvalidIdentity);
        }
        Ok(())
    }

    pub fn computed_provider_digest(&self) -> Digest {
        Digest::from_fields(
            "github-codeql-provider-definition/v1",
            &[
                self.provider_id.clone(),
                self.provider_version.to_string(),
                self.api_revision.as_str().to_owned(),
                self.provenance.as_str().to_owned(),
                self.permissions.digest().as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
            ],
        )
    }

    fn expected_api_digest() -> Digest {
        Digest::from_fields(
            "github-codeql-api/v1",
            &[
                PROVIDER_API_REVISION.to_owned(),
                ALERTS_ENDPOINT.to_owned(),
                ALERT_ENDPOINT.to_owned(),
                ANALYSES_ENDPOINT.to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeqlReadRequest {
    pub scope_digest: Digest,
    pub repository_digest: Digest,
    pub ref_name: RefName,
    pub ref_digest: Digest,
    pub commit_sha: CommitSha,
    pub commit_digest: Digest,
    pub analysis_id: AnalysisId,
    pub page_size: u32,
    pub page_token: Option<OpaquePageToken>,
}

impl CodeqlReadRequest {
    pub fn from_scope(
        scope: &GithubCodeqlScope,
        page_size: u32,
        page_token: Option<OpaquePageToken>,
    ) -> Self {
        Self {
            scope_digest: scope.digest().clone(),
            repository_digest: scope.repository_digest(),
            ref_name: scope.git_ref.clone(),
            ref_digest: scope.ref_digest(),
            commit_sha: scope.commit_sha.clone(),
            commit_digest: scope.commit_digest(),
            analysis_id: scope.analysis_id.clone(),
            page_size,
            page_token,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.scope_digest.validate()?;
        self.repository_digest.validate()?;
        self.ref_digest.validate()?;
        self.commit_digest.validate()?;
        if self.page_size == 0 || self.page_size > crate::model::MAX_PAGE_SIZE {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

pub type ListAnalysesRequest = CodeqlReadRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListAlertsRequest {
    pub read: CodeqlReadRequest,
    pub alert_number: AlertNumber,
    pub alert_state: AlertState,
}

impl ListAlertsRequest {
    pub fn from_scope(
        scope: &GithubCodeqlScope,
        page_size: u32,
        page_token: Option<OpaquePageToken>,
    ) -> Self {
        Self {
            read: CodeqlReadRequest::from_scope(scope, page_size, page_token),
            alert_number: scope.alert_number,
            alert_state: scope.expected_alert_state,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetAlertRequest {
    pub read: CodeqlReadRequest,
    pub alert_number: AlertNumber,
    pub fingerprint: AlertFingerprint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlertSummary {
    pub alert_number: AlertNumber,
    pub fingerprint: AlertFingerprint,
    pub state: AlertState,
    pub severity: AlertSeverity,
    pub tool: CodeScanningTool,
    pub rule_id: RuleId,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_sha: CommitSha,
    pub analysis_id: AnalysisId,
    pub summary_digest: Digest,
}

impl AlertSummary {
    pub fn from_record(record: &AlertRecord) -> Self {
        let mut summary = Self {
            alert_number: record.alert_number,
            fingerprint: record.fingerprint.clone(),
            state: record.state,
            severity: record.severity,
            tool: record.tool,
            rule_id: record.rule_id.clone(),
            repository_digest: record.repository_digest.clone(),
            ref_digest: record.ref_digest.clone(),
            commit_sha: record.commit_sha.clone(),
            analysis_id: record.analysis_id.clone(),
            summary_digest: Digest::from_text("unsealed-github-codeql-alert-summary"),
        };
        summary.summary_digest = summary.computed_digest();
        summary
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.alert_number,
            &self.fingerprint,
            self.state,
            self.severity,
            self.tool,
            &self.rule_id,
            &self.repository_digest,
            &self.ref_digest,
            &self.commit_sha,
            &self.analysis_id,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        if self.summary_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ProviderError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlertRecord {
    pub alert_number: AlertNumber,
    pub fingerprint: AlertFingerprint,
    pub state: AlertState,
    pub severity: AlertSeverity,
    pub tool: CodeScanningTool,
    pub rule_id: RuleId,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_sha: CommitSha,
    pub analysis_id: AnalysisId,
    pub locations: Vec<RedactedLocation>,
    pub response_bytes: u32,
    pub response_digest: Digest,
}

impl AlertRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alert_number: AlertNumber,
        fingerprint: AlertFingerprint,
        state: AlertState,
        severity: AlertSeverity,
        tool: CodeScanningTool,
        rule_id: RuleId,
        repository_digest: Digest,
        ref_digest: Digest,
        commit_sha: CommitSha,
        analysis_id: AnalysisId,
        locations: Vec<RedactedLocation>,
    ) -> Result<Self, ModelError> {
        if locations.len() > crate::model::MAX_LOCATIONS {
            return Err(ModelError::InvalidLocation);
        }
        for location in &locations {
            location.validate()?;
        }
        let mut record = Self {
            alert_number,
            fingerprint,
            state,
            severity,
            tool,
            rule_id,
            repository_digest,
            ref_digest,
            commit_sha,
            analysis_id,
            locations,
            response_bytes: 0,
            response_digest: Digest::from_text("unsealed-github-codeql-alert"),
        };
        record.response_bytes = serialized_len(&(
            record.alert_number,
            &record.fingerprint,
            record.state,
            record.severity,
            record.tool,
            &record.rule_id,
            &record.repository_digest,
            &record.ref_digest,
            &record.commit_sha,
            &record.analysis_id,
            &record.locations,
        ));
        record.response_digest = record.computed_digest();
        record
            .validate_digest()
            .map_err(|_| ModelError::DigestMismatch)?;
        Ok(record)
    }

    pub fn from_scope(
        scope: &GithubCodeqlScope,
        severity: AlertSeverity,
        locations: Vec<RedactedLocation>,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope.alert_number,
            scope.alert_fingerprint.clone(),
            scope.expected_alert_state,
            severity,
            scope.tool,
            scope.rule_id.clone(),
            scope.repository_digest(),
            scope.ref_digest(),
            scope.commit_sha.clone(),
            scope.analysis_id.clone(),
            locations,
        )
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.alert_number,
            &self.fingerprint,
            self.state,
            self.severity,
            self.tool,
            &self.rule_id,
            &self.repository_digest,
            &self.ref_digest,
            &self.commit_sha,
            &self.analysis_id,
            &self.locations,
            self.response_bytes,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        if self.response_bytes > crate::model::MAX_RESPONSE_BYTES
            || self.locations.len() > crate::model::MAX_LOCATIONS
            || self
                .locations
                .iter()
                .any(|location| location.validate().is_err())
        {
            return Err(ProviderError::Truncated);
        }
        if self.response_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ProviderError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisSummary {
    pub analysis_id: AnalysisId,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_sha: CommitSha,
    pub tool: CodeScanningTool,
    pub status: AnalysisStatus,
    pub summary_digest: Digest,
}

impl AnalysisSummary {
    pub fn from_record(record: &AnalysisRecord) -> Self {
        let mut summary = Self {
            analysis_id: record.analysis_id.clone(),
            repository_digest: record.repository_digest.clone(),
            ref_digest: record.ref_digest.clone(),
            commit_sha: record.commit_sha.clone(),
            tool: record.tool,
            status: record.status,
            summary_digest: Digest::from_text("unsealed-github-codeql-analysis-summary"),
        };
        summary.summary_digest = summary.computed_digest();
        summary
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.analysis_id,
            &self.repository_digest,
            &self.ref_digest,
            &self.commit_sha,
            self.tool,
            self.status,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        if self.summary_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ProviderError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisRecord {
    pub analysis_id: AnalysisId,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_sha: CommitSha,
    pub tool: CodeScanningTool,
    pub status: AnalysisStatus,
    pub response_bytes: u32,
    pub response_digest: Digest,
}

impl AnalysisRecord {
    pub fn new(
        analysis_id: AnalysisId,
        repository_digest: Digest,
        ref_digest: Digest,
        commit_sha: CommitSha,
        tool: CodeScanningTool,
        status: AnalysisStatus,
    ) -> Result<Self, ModelError> {
        let mut record = Self {
            analysis_id,
            repository_digest,
            ref_digest,
            commit_sha,
            tool,
            status,
            response_bytes: 0,
            response_digest: Digest::from_text("unsealed-github-codeql-analysis"),
        };
        record.response_bytes = serialized_len(&(
            &record.analysis_id,
            &record.repository_digest,
            &record.ref_digest,
            &record.commit_sha,
            record.tool,
            record.status,
        ));
        record.response_digest = record.computed_digest();
        record
            .validate_digest()
            .map_err(|_| ModelError::DigestMismatch)?;
        Ok(record)
    }

    pub fn from_scope(
        scope: &GithubCodeqlScope,
        status: AnalysisStatus,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope.analysis_id.clone(),
            scope.repository_digest(),
            scope.ref_digest(),
            scope.commit_sha.clone(),
            scope.tool,
            status,
        )
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.analysis_id,
            &self.repository_digest,
            &self.ref_digest,
            &self.commit_sha,
            self.tool,
            self.status,
            self.response_bytes,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        if self.response_bytes > crate::model::MAX_RESPONSE_BYTES {
            return Err(ProviderError::Truncated);
        }
        if self.response_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ProviderError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    token_digest: Digest,
}

impl OpaquePageToken {
    pub fn new(raw_token: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        if raw_token.is_empty() || raw_token.len() > crate::model::MAX_TEXT_BYTES {
            return Err(ModelError::InvalidText);
        }
        Ok(Self {
            token_digest: Digest::from_text(raw_token),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.token_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlertPage {
    pub page: u32,
    pub items: Vec<AlertSummary>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: u32,
    pub truncated: bool,
    pub response_digest: Digest,
}

impl AlertPage {
    pub fn new(
        page: u32,
        items: Vec<AlertSummary>,
        next_page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page == 0 || items.len() > crate::model::MAX_ALERTS {
            return Err(ModelError::InvalidScope);
        }
        let mut value = Self {
            page,
            items,
            next_page_token,
            response_bytes: 0,
            truncated: false,
            response_digest: Digest::from_text("unsealed-github-codeql-alert-page"),
        };
        value.seal();
        Ok(value)
    }

    pub fn seal(&mut self) {
        self.response_bytes = serialized_len(&(
            self.page,
            &self.items,
            &self.next_page_token,
            self.truncated,
        ));
        self.response_digest = self.computed_digest();
    }

    pub fn mark_truncated(&mut self) {
        self.truncated = true;
        self.seal();
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.page,
            &self.items,
            &self.next_page_token,
            self.response_bytes,
            self.truncated,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        if self.response_bytes > crate::model::MAX_RESPONSE_BYTES
            || self.items.len() > crate::model::MAX_ALERTS
        {
            return Err(ProviderError::Truncated);
        }
        for item in &self.items {
            item.validate_digest()?;
        }
        if self.response_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ProviderError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisPage {
    pub page: u32,
    pub items: Vec<AnalysisSummary>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: u32,
    pub truncated: bool,
    pub response_digest: Digest,
}

impl AnalysisPage {
    pub fn new(
        page: u32,
        items: Vec<AnalysisSummary>,
        next_page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page == 0 || items.len() > crate::model::MAX_ALERTS {
            return Err(ModelError::InvalidScope);
        }
        let mut value = Self {
            page,
            items,
            next_page_token,
            response_bytes: 0,
            truncated: false,
            response_digest: Digest::from_text("unsealed-github-codeql-analysis-page"),
        };
        value.seal();
        Ok(value)
    }

    pub fn seal(&mut self) {
        self.response_bytes = serialized_len(&(
            self.page,
            &self.items,
            &self.next_page_token,
            self.truncated,
        ));
        self.response_digest = self.computed_digest();
    }

    pub fn mark_truncated(&mut self) {
        self.truncated = true;
        self.seal();
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.page,
            &self.items,
            &self.next_page_token,
            self.response_bytes,
            self.truncated,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        if self.response_bytes > crate::model::MAX_RESPONSE_BYTES {
            return Err(ProviderError::Truncated);
        }
        for item in &self.items {
            item.validate_digest()?;
        }
        if self.response_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ProviderError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    Unprocessable,
    RateLimited,
    ServerFailure,
    Timeout,
    Truncated,
    TamperedEvidence,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
    pub truncated: bool,
    pub blocked_env: bool,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic),
            truncated: matches!(kind, ProviderErrorKind::Truncated),
            blocked_env: matches!(kind, ProviderErrorKind::BlockedEnv),
        }
    }

    pub fn http(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        let kind = match status_code {
            401 => ProviderErrorKind::Unauthenticated,
            403 => ProviderErrorKind::PermissionDenied,
            404 => ProviderErrorKind::NotFound,
            409 => ProviderErrorKind::Conflict,
            422 => ProviderErrorKind::Unprocessable,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self::new(kind, Some(status_code), diagnostic)
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn blocked_env(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, diagnostic)
    }

    pub fn truncated() -> Self {
        Self::new(ProviderErrorKind::Truncated, None, "truncated")
    }

    pub fn tampered() -> Self {
        Self::new(ProviderErrorKind::TamperedEvidence, None, "tampered")
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self.kind,
            ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("provider response was truncated or exceeded a bound")]
    Truncated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportRequestRecord {
    ListAlerts,
    GetAlert,
    ListAnalyses,
}

#[derive(Clone, Debug, Default)]
pub struct ReadScript {
    pub alert_pages: VecDeque<Result<AlertPage, TransportError>>,
    pub alert_records: VecDeque<Result<AlertRecord, TransportError>>,
    pub analysis_pages: VecDeque<Result<AnalysisPage, TransportError>>,
}

impl ReadScript {
    pub fn new(
        alert_pages: impl IntoIterator<Item = Result<AlertPage, TransportError>>,
        alert_records: impl IntoIterator<Item = Result<AlertRecord, TransportError>>,
        analysis_pages: impl IntoIterator<Item = Result<AnalysisPage, TransportError>>,
    ) -> Self {
        Self {
            alert_pages: alert_pages.into_iter().collect(),
            alert_records: alert_records.into_iter().collect(),
            analysis_pages: analysis_pages.into_iter().collect(),
        }
    }
}

pub trait GithubCodeScanningTransport: fmt::Debug {
    fn list_alerts(&mut self, request: &ListAlertsRequest) -> Result<AlertPage, TransportError>;

    fn get_alert(&mut self, request: &GetAlertRequest) -> Result<AlertRecord, TransportError>;

    fn list_analyses(
        &mut self,
        request: &ListAnalysesRequest,
    ) -> Result<AnalysisPage, TransportError>;
}

macro_rules! scripted_transport {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            script: ReadScript,
            calls: Vec<TransportRequestRecord>,
        }

        impl $name {
            pub fn new(script: ReadScript) -> Self {
                Self {
                    script,
                    calls: Vec::new(),
                }
            }

            pub fn calls(&self) -> &[TransportRequestRecord] {
                &self.calls
            }

            fn next_alert_page(&mut self) -> Result<AlertPage, TransportError> {
                self.script
                    .alert_pages
                    .pop_front()
                    .unwrap_or_else(|| Err(TransportError::blocked_env("fixture page absent")))
            }

            fn next_alert_record(&mut self) -> Result<AlertRecord, TransportError> {
                self.script
                    .alert_records
                    .pop_front()
                    .unwrap_or_else(|| Err(TransportError::blocked_env("fixture alert absent")))
            }

            fn next_analysis_page(&mut self) -> Result<AnalysisPage, TransportError> {
                self.script
                    .analysis_pages
                    .pop_front()
                    .unwrap_or_else(|| Err(TransportError::blocked_env("fixture analysis absent")))
            }
        }

        impl GithubCodeScanningTransport for $name {
            fn list_alerts(
                &mut self,
                _request: &ListAlertsRequest,
            ) -> Result<AlertPage, TransportError> {
                self.calls.push(TransportRequestRecord::ListAlerts);
                self.next_alert_page()
            }

            fn get_alert(
                &mut self,
                _request: &GetAlertRequest,
            ) -> Result<AlertRecord, TransportError> {
                self.calls.push(TransportRequestRecord::GetAlert);
                self.next_alert_record()
            }

            fn list_analyses(
                &mut self,
                _request: &ListAnalysesRequest,
            ) -> Result<AnalysisPage, TransportError> {
                self.calls.push(TransportRequestRecord::ListAnalyses);
                self.next_analysis_page()
            }
        }
    };
}

scripted_transport!(FixtureTransport);
scripted_transport!(RecordingTransport);
scripted_transport!(LoopbackTransport);

#[derive(Clone, Debug)]
pub struct BlockedEnvTransport {
    calls: Vec<TransportRequestRecord>,
}

impl BlockedEnvTransport {
    pub const fn new() -> Self {
        Self { calls: Vec::new() }
    }

    pub fn calls(&self) -> &[TransportRequestRecord] {
        &self.calls
    }
}

impl Default for BlockedEnvTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl GithubCodeScanningTransport for BlockedEnvTransport {
    fn list_alerts(&mut self, _request: &ListAlertsRequest) -> Result<AlertPage, TransportError> {
        self.calls.push(TransportRequestRecord::ListAlerts);
        Err(TransportError::blocked_env(
            "native GitHub credentials unavailable",
        ))
    }

    fn get_alert(&mut self, _request: &GetAlertRequest) -> Result<AlertRecord, TransportError> {
        self.calls.push(TransportRequestRecord::GetAlert);
        Err(TransportError::blocked_env(
            "native GitHub credentials unavailable",
        ))
    }

    fn list_analyses(
        &mut self,
        _request: &ListAnalysesRequest,
    ) -> Result<AnalysisPage, TransportError> {
        self.calls.push(TransportRequestRecord::ListAnalyses);
        Err(TransportError::blocked_env(
            "native GitHub credentials unavailable",
        ))
    }
}

pub struct GithubCodeScanningProvider<T> {
    definition: GithubCodeScanningProviderDefinition,
    transport: T,
}

impl<T: fmt::Debug> fmt::Debug for GithubCodeScanningProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCodeScanningProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: GithubCodeScanningTransport> GithubCodeScanningProvider<T> {
    pub fn new(
        transport: T,
        provider_version: Version,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::with_permissions(
            transport,
            provider_version,
            provenance,
            PermissionSnapshot::least_privilege(),
        )
    }

    pub fn with_permissions(
        transport: T,
        provider_version: Version,
        provenance: ProviderProvenance,
        permissions: PermissionSnapshot,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            definition: GithubCodeScanningProviderDefinition::new(
                provider_version,
                provenance,
                permissions,
            )?,
            transport,
        })
    }

    pub fn definition(&self) -> &GithubCodeScanningProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub fn list_alerts(
        &mut self,
        request: &ListAlertsRequest,
    ) -> Result<AlertPage, TransportError> {
        self.transport.list_alerts(request)
    }

    pub fn get_alert(&mut self, request: &GetAlertRequest) -> Result<AlertRecord, TransportError> {
        self.transport.get_alert(request)
    }

    pub fn list_analyses(
        &mut self,
        request: &ListAnalysesRequest,
    ) -> Result<AnalysisPage, TransportError> {
        self.transport.list_analyses(request)
    }
}
