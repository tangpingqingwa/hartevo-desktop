//! Allowlisted Veracode read seams and deterministic non-native transports.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ApplicationProjection, BuildProjection, Digest, FailureReceipt, FindingProjection,
    MAX_APPLICATIONS, MAX_BUILDS, MAX_CURSOR_BYTES, MAX_FINDINGS, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_POLICIES, MAX_RESPONSE_BYTES, MAX_RETRIES, MAX_SCANS, MAX_TOTAL_RECORDS, ModelError,
    PermissionSnapshot, PolicyProjection, RateLimitReceipt, ReadReceipt, RetryReceipt, Revision,
    ScanProjection, TransportProvenance, VeracodeOperation, VeracodeRead, VeracodeReadPage,
    VeracodeScope,
};
use crate::service::VeracodeRegistration;

pub const APPLICATIONS_PATH: &str = "/appsec/v1/applications";
pub const FINDINGS_PATH_TEMPLATE: &str = "/appsec/v2/applications/{application_guid}/findings";
pub const POLICIES_PATH: &str = "/appsec/v1/policies";
pub const BLOCKED_ENV_PROVIDER_REVISION: &str = "veracode-blocked-env-r1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VeracodeTransportFailure {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl VeracodeTransportFailure {
    #[must_use]
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::Throttled,
            500..=599 => Self::Server,
            _ => Self::Malformed,
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Throttled | Self::Server | Self::Timeout)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("Veracode transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct VeracodeTransportError {
    pub failure: VeracodeTransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
    pub retry: RetryReceipt,
    pub rate_limit: RateLimitReceipt,
}

impl VeracodeTransportError {
    #[must_use]
    pub fn new(failure: VeracodeTransportFailure) -> Self {
        let label = match failure {
            VeracodeTransportFailure::BadRequest => "400",
            VeracodeTransportFailure::Unauthorized => "401",
            VeracodeTransportFailure::AccessDenied => "403",
            VeracodeTransportFailure::NotFound => "404",
            VeracodeTransportFailure::Conflict => "409",
            VeracodeTransportFailure::Throttled => "429",
            VeracodeTransportFailure::Server => "5xx",
            VeracodeTransportFailure::Timeout => "timeout",
            VeracodeTransportFailure::BlockedEnv => "BLOCKED_ENV",
            VeracodeTransportFailure::Malformed => "malformed",
        };
        Self {
            failure,
            status_code: failure.status_code(),
            error_digest: Digest::from_text(label),
            retry: RetryReceipt::first_attempt(VeracodeOperation::GetApplications, 0),
            rate_limit: RateLimitReceipt::default(),
        }
    }

    #[must_use]
    pub fn from_status(status: u16) -> Self {
        Self::new(VeracodeTransportFailure::from_status(status))
    }

    #[must_use]
    pub fn blocked_env() -> Self {
        Self::new(VeracodeTransportFailure::BlockedEnv)
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::new(VeracodeTransportFailure::Timeout)
    }

    #[must_use]
    pub fn with_retry(mut self, retry: RetryReceipt) -> Self {
        self.retry = retry;
        self
    }

    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: RateLimitReceipt) -> Self {
        self.rate_limit = rate_limit;
        self
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VeracodeProviderError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("transport failed: {0}")]
    Transport(#[from] VeracodeTransportError),
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("request scope does not match the registration")]
    ScopeMismatch,
    #[error("request permission digest does not match the registration")]
    PermissionMismatch,
    #[error("request provider or registration revision is stale")]
    StaleRequest,
    #[error("provider definition is invalid")]
    InvalidDefinition,
    #[error("provider response contains duplicate or replayed data")]
    TamperedResponse,
}

pub type ProviderError = VeracodeProviderError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeProviderDefinition {
    pub provider_id: String,
    pub api_revision: String,
    pub provider_revision: Revision,
    pub provider_digest: Digest,
    pub applications_path: String,
    pub findings_path_template: String,
    pub policies_path: String,
    pub allowlisted_operations: Vec<String>,
    pub allowlisted_methods: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl VeracodeProviderDefinition {
    pub fn new() -> Result<Self, VeracodeProviderError> {
        let permissions = PermissionSnapshot::results_read();
        let mut value = Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            api_revision: crate::PROVIDER_API_REVISION.to_owned(),
            provider_revision: Revision::new(1)?,
            provider_digest: Digest::from_text("unsealed-veracode-provider"),
            applications_path: APPLICATIONS_PATH.to_owned(),
            findings_path_template: FINDINGS_PATH_TEMPLATE.to_owned(),
            policies_path: POLICIES_PATH.to_owned(),
            allowlisted_operations: vec![
                "GET_APPLICATIONS".to_owned(),
                "GET_BUILDS".to_owned(),
                "GET_SCANS".to_owned(),
                "GET_FINDINGS".to_owned(),
                "GET_POLICIES".to_owned(),
            ],
            allowlisted_methods: vec!["GET".to_owned()],
            permissions: permissions.permissions,
            read_only: true,
            external_writes: false,
            native: false,
            connected: false,
            first_party: false,
        };
        value.provider_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.provider_id,
            &self.api_revision,
            self.provider_revision,
            &self.applications_path,
            &self.findings_path_template,
            &self.policies_path,
            &self.allowlisted_operations,
            &self.allowlisted_methods,
            &self.permissions,
            self.read_only,
            self.external_writes,
            self.native,
            self.connected,
            self.first_party,
        ))
    }

    pub fn validate(&self) -> Result<(), VeracodeProviderError> {
        let permissions = PermissionSnapshot::new(self.permissions.clone())?;
        if self.provider_id != crate::PROVIDER_ID
            || self.api_revision != crate::PROVIDER_API_REVISION
            || self.provider_revision.get() == 0
            || self.applications_path != APPLICATIONS_PATH
            || self.findings_path_template != FINDINGS_PATH_TEMPLATE
            || self.policies_path != POLICIES_PATH
            || self.allowlisted_methods != ["GET".to_owned()]
            || !self.read_only
            || self.external_writes
            || self.native
            || self.connected
            || self.first_party
            || self.provider_digest != self.calculate_digest()?
        {
            return Err(VeracodeProviderError::InvalidDefinition);
        }
        permissions.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub limit: u16,
    pub max_pages: u16,
    pub max_retries: u8,
    pub max_records: u16,
}

impl ReadBounds {
    pub fn new(
        limit: u16,
        max_pages: u16,
        max_retries: u8,
        max_records: u16,
    ) -> Result<Self, ModelError> {
        let value = Self {
            limit,
            max_pages,
            max_retries,
            max_records,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit == 0
            || self.limit > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_retries > MAX_RETRIES
            || self.max_records == 0
            || usize::from(self.max_records) > MAX_TOTAL_RECORDS
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(())
    }
}

pub type VeracodeReadBounds = ReadBounds;
pub type ApplicationSecurityReadBounds = ReadBounds;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeReadRequest {
    pub scope_digest: Digest,
    pub application_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: Revision,
    pub cursor_digest: Option<Digest>,
    pub bounds: ReadBounds,
}

impl VeracodeReadRequest {
    pub fn for_registration(
        scope: &VeracodeScope,
        registration: &VeracodeRegistration,
        bounds: ReadBounds,
    ) -> Result<Self, VeracodeProviderError> {
        scope.validate()?;
        bounds.validate()?;
        registration
            .validate()
            .map_err(|_| VeracodeProviderError::InvalidDefinition)?;
        if registration.scope_digest() != &scope.digest() || !registration.is_active() {
            return Err(VeracodeProviderError::ScopeMismatch);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            application_digest: scope.application_id.digest(),
            permission_digest: registration.permission_digest(),
            registration_digest: registration.registration_digest().clone(),
            provider_revision: registration.provider_revision(),
            cursor_digest: None,
            bounds,
        })
    }

    #[must_use]
    pub fn with_cursor(&self, cursor_digest: Option<Digest>) -> Self {
        let mut request = self.clone();
        request.cursor_digest = cursor_digest;
        request
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        crate::model::digest_serializable(self).expect("VeracodeReadRequest is serializable")
    }

    pub fn validate(&self) -> Result<(), VeracodeProviderError> {
        self.bounds.validate()?;
        if self.provider_revision.get() == 0
            || !self.scope_digest.is_valid()
            || !self.application_digest.is_valid()
            || !self.permission_digest.is_valid()
            || !self.registration_digest.is_valid()
            || self
                .cursor_digest
                .as_ref()
                .is_some_and(|value| !value.is_valid() || value.as_str().len() > MAX_CURSOR_BYTES)
        {
            return Err(VeracodeProviderError::StaleRequest);
        }
        Ok(())
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "{APPLICATIONS_PATH}?applicationDigest={}&cursorDigest={}&limit={}",
            self.application_digest,
            self.cursor_digest.as_ref().map_or("none", Digest::as_str),
            self.bounds.limit
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeReadResponse {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub next_cursor_digest: Option<Digest>,
    pub applications: Vec<ApplicationProjection>,
    pub builds: Vec<BuildProjection>,
    pub scans: Vec<ScanProjection>,
    pub findings: Vec<FindingProjection>,
    pub policies: Vec<PolicyProjection>,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub rate_limit: RateLimitReceipt,
    pub retry: RetryReceipt,
    pub provenance: TransportProvenance,
}

impl VeracodeReadResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &VeracodeReadRequest,
        applications: Vec<ApplicationProjection>,
        builds: Vec<BuildProjection>,
        scans: Vec<ScanProjection>,
        findings: Vec<FindingProjection>,
        policies: Vec<PolicyProjection>,
        next_cursor_digest: Option<Digest>,
        response_bytes: u64,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
    ) -> Result<Self, VeracodeProviderError> {
        if applications.len() > MAX_APPLICATIONS
            || builds.len() > MAX_BUILDS
            || scans.len() > MAX_SCANS
            || findings.len() > MAX_FINDINGS
            || policies.len() > MAX_POLICIES
            || applications.len() > usize::from(request.bounds.limit)
            || builds.len() > usize::from(request.bounds.limit)
            || scans.len() > usize::from(request.bounds.limit)
            || findings.len() > usize::from(request.bounds.limit)
            || policies.len() > usize::from(request.bounds.limit)
            || response_bytes > MAX_RESPONSE_BYTES
            || next_cursor_digest
                .as_ref()
                .is_some_and(|value| !value.is_valid() || value.as_str().len() > MAX_CURSOR_BYTES)
        {
            return Err(VeracodeProviderError::Model(ModelError::InvalidResponse));
        }
        rate_limit.validate()?;
        for value in &applications {
            value.validate_integrity()?;
        }
        for value in &builds {
            value.validate_integrity()?;
        }
        for value in &scans {
            value.validate_integrity()?;
        }
        for value in &findings {
            value.validate_integrity()?;
        }
        for value in &policies {
            value.validate_integrity()?;
        }
        let response_digest = response_digest(
            request.request_digest(),
            request.scope_digest.clone(),
            request.cursor_digest.clone(),
            next_cursor_digest.clone(),
            &applications,
            &builds,
            &scans,
            &findings,
            &policies,
            response_bytes,
            provenance,
        )?;
        Ok(Self {
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            cursor_digest: request.cursor_digest.clone(),
            next_cursor_digest,
            applications,
            builds,
            scans,
            findings,
            policies,
            response_bytes,
            response_digest,
            rate_limit,
            retry: RetryReceipt::first_attempt(VeracodeOperation::GetApplications, 0),
            provenance,
        })
    }

    #[must_use]
    pub fn with_retry(mut self, retry: RetryReceipt) -> Self {
        self.retry = retry;
        self
    }

    pub fn with_provenance(
        mut self,
        provenance: TransportProvenance,
    ) -> Result<Self, VeracodeProviderError> {
        self.provenance = provenance;
        self.response_digest = response_digest(
            self.request_digest.clone(),
            self.scope_digest.clone(),
            self.cursor_digest.clone(),
            self.next_cursor_digest.clone(),
            &self.applications,
            &self.builds,
            &self.scans,
            &self.findings,
            &self.policies,
            self.response_bytes,
            provenance,
        )?;
        self.validate_integrity()?;
        Ok(self)
    }

    pub fn validate_integrity(&self) -> Result<(), VeracodeProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.applications.len() > MAX_APPLICATIONS
            || self.builds.len() > MAX_BUILDS
            || self.scans.len() > MAX_SCANS
            || self.findings.len() > MAX_FINDINGS
            || self.policies.len() > MAX_POLICIES
            || self.retry.operation != VeracodeOperation::GetApplications
            || self
                .next_cursor_digest
                .as_ref()
                .is_some_and(|value| !value.is_valid())
        {
            return Err(VeracodeProviderError::Model(ModelError::InvalidResponse));
        }
        self.rate_limit.validate()?;
        for value in &self.applications {
            value.validate_integrity()?;
        }
        for value in &self.builds {
            value.validate_integrity()?;
        }
        for value in &self.scans {
            value.validate_integrity()?;
        }
        for value in &self.findings {
            value.validate_integrity()?;
        }
        for value in &self.policies {
            value.validate_integrity()?;
        }
        let expected = response_digest(
            self.request_digest.clone(),
            self.scope_digest.clone(),
            self.cursor_digest.clone(),
            self.next_cursor_digest.clone(),
            &self.applications,
            &self.builds,
            &self.scans,
            &self.findings,
            &self.policies,
            self.response_bytes,
            self.provenance,
        )?;
        if expected != self.response_digest {
            return Err(VeracodeProviderError::TamperedResponse);
        }
        Ok(())
    }

    pub fn into_page(self, page_number: u16) -> Result<VeracodeReadPage, VeracodeProviderError> {
        self.validate_integrity()?;
        let receipt = ReadReceipt {
            operation: VeracodeOperation::GetApplications,
            request_digest: self.request_digest,
            response_digest: self.response_digest,
            cursor_digest: self.cursor_digest.clone(),
            next_cursor_digest: self.next_cursor_digest.clone(),
            retry: self.retry,
            rate_limit: self.rate_limit,
            provenance: self.provenance,
        };
        Ok(VeracodeReadPage::new(
            page_number,
            self.cursor_digest,
            self.next_cursor_digest,
            self.applications,
            self.builds,
            self.scans,
            self.findings,
            self.policies,
            receipt,
        )?)
    }
}

fn response_digest(
    request_digest: Digest,
    scope_digest: Digest,
    cursor_digest: Option<Digest>,
    next_cursor_digest: Option<Digest>,
    applications: &[ApplicationProjection],
    builds: &[BuildProjection],
    scans: &[ScanProjection],
    findings: &[FindingProjection],
    policies: &[PolicyProjection],
    response_bytes: u64,
    provenance: TransportProvenance,
) -> Result<Digest, ModelError> {
    crate::model::digest_serializable(&(
        request_digest,
        scope_digest,
        cursor_digest,
        next_cursor_digest,
        applications
            .iter()
            .map(|value| &value.application_digest)
            .collect::<Vec<_>>(),
        builds
            .iter()
            .map(|value| &value.build_digest)
            .collect::<Vec<_>>(),
        scans
            .iter()
            .map(|value| &value.scan_digest)
            .collect::<Vec<_>>(),
        findings
            .iter()
            .map(|value| &value.finding_digest)
            .collect::<Vec<_>>(),
        policies
            .iter()
            .map(|value| &value.policy_digest)
            .collect::<Vec<_>>(),
        response_bytes,
        provenance,
    ))
}

pub trait VeracodeTransport: Clone + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_page(
        &mut self,
        request: &VeracodeReadRequest,
    ) -> Result<VeracodeReadResponse, VeracodeTransportError>;
}

pub struct VeracodeProvider<T: VeracodeTransport> {
    transport: T,
    registration: VeracodeRegistration,
    definition: VeracodeProviderDefinition,
}

impl<T: VeracodeTransport> fmt::Debug for VeracodeProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VeracodeProvider")
            .field("provenance", &self.transport.provenance())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("provider_digest", &self.definition.provider_digest)
            .finish()
    }
}

impl<T: VeracodeTransport> VeracodeProvider<T> {
    pub fn new(
        transport: T,
        registration: VeracodeRegistration,
    ) -> Result<Self, VeracodeProviderError> {
        registration
            .validate()
            .map_err(|_| VeracodeProviderError::InvalidDefinition)?;
        let definition = VeracodeProviderDefinition::new()?;
        if registration.provider_digest() != &definition.provider_digest {
            return Err(VeracodeProviderError::InvalidDefinition);
        }
        Ok(Self {
            transport,
            registration,
            definition,
        })
    }

    pub fn from_registration(
        registration: VeracodeRegistration,
        transport: T,
    ) -> Result<Self, VeracodeProviderError> {
        Self::new(transport, registration)
    }

    #[must_use]
    pub fn registration(&self) -> &VeracodeRegistration {
        &self.registration
    }

    #[must_use]
    pub fn definition(&self) -> &VeracodeProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn read_page(
        &mut self,
        request: &VeracodeReadRequest,
        max_retries: u8,
    ) -> Result<VeracodeReadResponse, VeracodeProviderError> {
        self.validate_fence(request)?;
        if max_retries > MAX_RETRIES {
            return Err(VeracodeProviderError::Model(ModelError::InvalidBounds));
        }
        let mut retries = 0;
        loop {
            match self.transport.read_page(request) {
                Ok(response) => {
                    response.validate_integrity()?;
                    if response.request_digest != request.request_digest()
                        || response.scope_digest != request.scope_digest
                        || response.cursor_digest != request.cursor_digest
                    {
                        return Err(VeracodeProviderError::TamperedResponse);
                    }
                    let retry = RetryReceipt::new(
                        VeracodeOperation::GetApplications,
                        retries + 1,
                        max_retries,
                        false,
                    )?;
                    return Ok(response.with_retry(retry));
                }
                Err(error) if error.failure.retryable() && retries < max_retries => {
                    retries += 1;
                }
                Err(error) => {
                    let retry = RetryReceipt::new(
                        VeracodeOperation::GetApplications,
                        retries + 1,
                        max_retries,
                        error.failure.retryable(),
                    )?;
                    return Err(VeracodeProviderError::Transport(error.with_retry(retry)));
                }
            }
        }
    }

    pub fn read(
        &mut self,
        request: &VeracodeReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<VeracodeRead, VeracodeProviderError> {
        request.validate()?;
        let mut pages = Vec::new();
        let mut cursor = request.cursor_digest.clone();
        let mut seen_cursors = BTreeSet::new();
        let mut seen_applications = BTreeSet::new();
        let mut seen_builds = BTreeSet::new();
        let mut seen_scans = BTreeSet::new();
        let mut seen_findings = BTreeSet::new();
        let mut seen_policies = BTreeSet::new();
        let mut complete = false;

        for page_number in 1..=request.bounds.max_pages {
            if !seen_cursors.insert(cursor.clone()) {
                return Err(VeracodeProviderError::TamperedResponse);
            }
            let page_request = request.with_cursor(cursor.clone());
            let response = self.read_page(&page_request, request.bounds.max_retries)?;
            let page = response.into_page(page_number)?;
            self.validate_page_scope(&page)?;
            if page
                .applications
                .iter()
                .any(|value| !seen_applications.insert(value.application_id.clone()))
                || page
                    .builds
                    .iter()
                    .any(|value| !seen_builds.insert(value.build_id.clone()))
                || page
                    .scans
                    .iter()
                    .any(|value| !seen_scans.insert(value.scan_id.clone()))
                || page
                    .findings
                    .iter()
                    .any(|value| !seen_findings.insert(value.finding_id.clone()))
                || page
                    .policies
                    .iter()
                    .any(|value| !seen_policies.insert(value.policy_id.clone()))
            {
                return Err(VeracodeProviderError::TamperedResponse);
            }
            let next = page.next_cursor_digest.clone();
            let page_complete = page.complete();
            pages.push(page);
            if page_complete {
                complete = true;
                break;
            }
            if next.is_none() || next == cursor {
                return Err(VeracodeProviderError::TamperedResponse);
            }
            cursor = next;
        }
        if pages.is_empty() {
            return Err(VeracodeProviderError::Model(ModelError::InvalidResponse));
        }
        if pages
            .iter()
            .map(VeracodeReadPage::record_count)
            .sum::<usize>()
            > usize::from(request.bounds.max_records)
        {
            return Err(VeracodeProviderError::Model(ModelError::BoundExceeded {
                field: "total records",
            }));
        }
        Ok(VeracodeRead::new(pages, complete, observed_at)?)
    }

    pub fn read_with_bounds(
        &mut self,
        request: &VeracodeReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<VeracodeRead, VeracodeProviderError> {
        self.read(request, observed_at)
    }

    fn validate_fence(&self, request: &VeracodeReadRequest) -> Result<(), VeracodeProviderError> {
        if !self.registration.is_active() {
            return Err(VeracodeProviderError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.application_digest != self.registration.scope().application_id.digest()
        {
            return Err(VeracodeProviderError::ScopeMismatch);
        }
        if request.permission_digest != self.registration.permission_digest()
            || request.registration_digest != *self.registration.registration_digest()
        {
            return Err(VeracodeProviderError::PermissionMismatch);
        }
        if request.provider_revision != self.registration.provider_revision() {
            return Err(VeracodeProviderError::StaleRequest);
        }
        Ok(())
    }

    fn validate_page_scope(&self, page: &VeracodeReadPage) -> Result<(), VeracodeProviderError> {
        let scope = self.registration.scope();
        if page
            .applications
            .iter()
            .any(|value| value.application_id != scope.application_id)
            || scope
                .build_id
                .as_ref()
                .is_some_and(|id| page.builds.iter().any(|value| value.build_id != *id))
            || scope
                .scan_id
                .as_ref()
                .is_some_and(|id| page.scans.iter().any(|value| value.scan_id != *id))
            || scope
                .policy_id
                .as_ref()
                .is_some_and(|id| page.policies.iter().any(|value| value.policy_id != *id))
            || (!scope.finding_ids.is_empty()
                && page
                    .findings
                    .iter()
                    .any(|value| !scope.finding_ids.contains(&value.finding_id)))
        {
            return Err(VeracodeProviderError::TamperedResponse);
        }
        Ok(())
    }
}

fn response_for_scope(
    request: &VeracodeReadRequest,
    applications: Vec<ApplicationProjection>,
    builds: Vec<BuildProjection>,
    scans: Vec<ScanProjection>,
    findings: Vec<FindingProjection>,
    policies: Vec<PolicyProjection>,
    next_cursor_digest: Option<Digest>,
    provenance: TransportProvenance,
) -> Result<VeracodeReadResponse, VeracodeTransportError> {
    VeracodeReadResponse::new(
        request,
        applications,
        builds,
        scans,
        findings,
        policies,
        next_cursor_digest,
        512,
        RateLimitReceipt::new(60, Some(59), None, false)
            .map_err(|_| VeracodeTransportError::new(VeracodeTransportFailure::Malformed))?,
        provenance,
    )
    .map_err(|_| VeracodeTransportError::new(VeracodeTransportFailure::Malformed))
}

fn cursor_for_page(page_index: usize) -> Digest {
    Digest::from_text(&format!("fixture-veracode-cursor-{page_index}"))
}

fn page_index(cursor: Option<&Digest>) -> Result<usize, VeracodeTransportError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    (0..=usize::from(MAX_PAGES))
        .find(|index| cursor == &cursor_for_page(*index))
        .ok_or_else(|| VeracodeTransportError::new(VeracodeTransportFailure::Malformed))
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    applications: Vec<ApplicationProjection>,
    builds: Vec<BuildProjection>,
    scans: Vec<ScanProjection>,
    findings: Vec<FindingProjection>,
    policies: Vec<PolicyProjection>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &VeracodeScope) -> Result<Self, ModelError> {
        let observed = DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
            .expect("fixture timestamp")
            .with_timezone(&Utc);
        let application = ApplicationProjection::from_sensitive(
            scope.application_id.as_str(),
            "fixture-veracode-application",
            crate::model::BusinessCriticality::High,
            Some(observed),
            Some(observed),
            Some("fixture-policy-001".to_owned()),
            crate::model::PolicyStatus::Violating,
            1,
        )?;
        let build = BuildProjection::from_sensitive(
            scope
                .build_id
                .as_ref()
                .map_or("fixture-build-001", |value| value.as_str()),
            Some("fixture-build-version"),
            crate::model::BuildStatus::Published,
            Some(observed),
            Some(observed),
            1,
        )?;
        let scan = ScanProjection::from_values(
            scope
                .scan_id
                .as_ref()
                .map_or("fixture-scan-001", |value| value.as_str()),
            crate::model::ScanType::Static,
            crate::model::ScanStatus::Published,
            Some(observed),
            Some(observed),
            1,
            1,
        )?;
        let finding = FindingProjection::from_sensitive(
            scope
                .finding_ids
                .first()
                .map_or("fixture-finding-001", |value| value.as_str()),
            crate::model::Severity::High,
            crate::model::FindingStatus::Open,
            "CWE-89",
            crate::model::ScanType::Static,
            true,
            Some(observed),
            Some(observed),
            Some("fixture/source.rs:42"),
            Some("fixture-package@1.0.0"),
            1,
            1,
        )?;
        let policy = PolicyProjection::from_sensitive(
            scope
                .policy_id
                .as_ref()
                .map_or("fixture-policy-001", |value| value.as_str()),
            "fixture-veracode-policy",
            crate::model::PolicyStatus::Violating,
            Some(crate::model::Severity::High),
            1,
            1,
        )?;
        Self::with_resources(
            scope,
            vec![application],
            vec![build],
            vec![scan],
            vec![finding],
            vec![policy],
        )
    }

    pub fn with_resources(
        scope: &VeracodeScope,
        applications: Vec<ApplicationProjection>,
        builds: Vec<BuildProjection>,
        scans: Vec<ScanProjection>,
        findings: Vec<FindingProjection>,
        policies: Vec<PolicyProjection>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if applications.len() > MAX_APPLICATIONS
            || builds.len() > MAX_BUILDS
            || scans.len() > MAX_SCANS
            || findings.len() > MAX_FINDINGS
            || policies.len() > MAX_POLICIES
        {
            return Err(ModelError::BoundExceeded {
                field: "fixture resources",
            });
        }
        for value in &applications {
            value.validate_integrity()?;
        }
        for value in &builds {
            value.validate_integrity()?;
        }
        for value in &scans {
            value.validate_integrity()?;
        }
        for value in &findings {
            value.validate_integrity()?;
        }
        for value in &policies {
            value.validate_integrity()?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            applications,
            builds,
            scans,
            findings,
            policies,
        })
    }

    fn page<T: Clone>(values: &[T], index: usize, limit: usize) -> Vec<T> {
        let start = index.saturating_mul(limit);
        values
            .get(start..start.saturating_add(limit).min(values.len()))
            .unwrap_or_default()
            .to_vec()
    }

    fn has_more(&self, index: usize, limit: usize) -> bool {
        let start = index.saturating_mul(limit);
        self.applications.len() > start.saturating_add(limit)
            || self.builds.len() > start.saturating_add(limit)
            || self.scans.len() > start.saturating_add(limit)
            || self.findings.len() > start.saturating_add(limit)
            || self.policies.len() > start.saturating_add(limit)
    }
}

impl VeracodeTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_page(
        &mut self,
        request: &VeracodeReadRequest,
    ) -> Result<VeracodeReadResponse, VeracodeTransportError> {
        if request.scope_digest != self.scope_digest {
            return Err(VeracodeTransportError::new(
                VeracodeTransportFailure::Conflict,
            ));
        }
        let index = page_index(request.cursor_digest.as_ref())?;
        let limit = usize::from(request.bounds.limit);
        let next = self
            .has_more(index, limit)
            .then(|| cursor_for_page(index + 1));
        response_for_scope(
            request,
            Self::page(&self.applications, index, limit),
            Self::page(&self.builds, index, limit),
            Self::page(&self.scans, index, limit),
            Self::page(&self.findings, index, limit),
            Self::page(&self.policies, index, limit),
            next,
            self.provenance(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub limit: u16,
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    inner: FixtureTransport,
    requests: Vec<RecordedRequest>,
    responses: VecDeque<Result<VeracodeReadResponse, VeracodeTransportError>>,
}

impl RecordingTransport {
    pub fn for_scope(scope: &VeracodeScope) -> Result<Self, ModelError> {
        Ok(Self {
            inner: FixtureTransport::for_scope(scope)?,
            requests: Vec::new(),
            responses: VecDeque::new(),
        })
    }

    pub fn with_resources(
        scope: &VeracodeScope,
        applications: Vec<ApplicationProjection>,
        builds: Vec<BuildProjection>,
        scans: Vec<ScanProjection>,
        findings: Vec<FindingProjection>,
        policies: Vec<PolicyProjection>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            inner: FixtureTransport::with_resources(
                scope,
                applications,
                builds,
                scans,
                findings,
                policies,
            )?,
            requests: Vec::new(),
            responses: VecDeque::new(),
        })
    }

    pub fn push_response(
        &mut self,
        response: Result<VeracodeReadResponse, VeracodeTransportError>,
    ) {
        self.responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        let scope = default_scope();
        Self::for_scope(&scope).expect("recording transport")
    }
}

impl VeracodeTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_page(
        &mut self,
        request: &VeracodeReadRequest,
    ) -> Result<VeracodeReadResponse, VeracodeTransportError> {
        self.requests.push(RecordedRequest {
            request_digest: request.request_digest(),
            cursor_digest: request.cursor_digest.clone(),
            limit: request.bounds.limit,
        });
        self.responses
            .pop_front()
            .unwrap_or_else(|| self.inner.read_page(request))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &VeracodeScope) -> Result<Self, ModelError> {
        Ok(Self {
            inner: FixtureTransport::for_scope(scope)?,
        })
    }
}

impl VeracodeTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_page(
        &mut self,
        request: &VeracodeReadRequest,
    ) -> Result<VeracodeReadResponse, VeracodeTransportError> {
        let response = self.inner.read_page(request)?;
        response
            .with_provenance(self.provenance())
            .map_err(|_| VeracodeTransportError::new(VeracodeTransportFailure::Malformed))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl VeracodeTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_page(
        &mut self,
        _request: &VeracodeReadRequest,
    ) -> Result<VeracodeReadResponse, VeracodeTransportError> {
        Err(VeracodeTransportError::blocked_env())
    }
}

fn default_scope() -> VeracodeScope {
    VeracodeScope::new(
        "recording-application",
        crate::model::VeracodeRegion::Commercial,
        crate::model::ProjectScope::new("recording-project", 1).expect("recording project"),
        crate::model::MissionScope::new("recording-mission", 1).expect("recording mission"),
        crate::model::WorkProductScope::new("recording-work-product", 1)
            .expect("recording work product"),
        1,
    )
    .expect("recording scope")
}

pub type FixtureVeracodeTransport = FixtureTransport;
pub type RecordingVeracodeTransport = RecordingTransport;
pub type LoopbackVeracodeTransport = LoopbackTransport;
pub type BlockedEnvVeracodeTransport = BlockedEnvTransport;

impl VeracodeProviderError {
    #[must_use]
    pub fn failure_receipt(&self, provenance: TransportProvenance) -> Option<FailureReceipt> {
        match self {
            Self::Transport(error) => Some(FailureReceipt {
                operation: error.retry.operation,
                status_code: error.status_code,
                error_digest: error.error_digest.clone(),
                retry: error.retry.clone(),
                rate_limit: error.rate_limit.clone(),
                provenance,
            }),
            _ => None,
        }
    }
}
