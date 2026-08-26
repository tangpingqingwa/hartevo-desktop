//! Bounded, read-only AWS Elastic Beanstalk provider seams.
//!
//! A transport receives one of three typed requests and returns a typed page.
//! There is no signer, credential resolver, HTTP client, write method, raw
//! payload type, log/source path, or arbitrary-operation escape hatch here.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AWS_ELASTIC_BEANSTALK_API_REVISION, AWS_ELASTIC_BEANSTALK_PROVIDER_ID,
    AWS_ELASTIC_BEANSTALK_PROVIDER_VERSION,
    model::{
        AccountId, ApplicationName, AwsElasticBeanstalkDeploymentScope,
        AwsElasticBeanstalkReadOperation, AwsRegion, Digest, EnvironmentId, EnvironmentName,
        EnvironmentRevisionProjection, EnvironmentStatus, EventKind, EventProjection,
        EventSeverity, HealthStatus, ModelError, OpaquePageToken, ProviderId, ProviderRevision,
        ReadBounds, ResourceKind, ResourceProjection,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn native(self) -> bool {
        false
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

pub type TransportProvenance = ProviderProvenance;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("AWS Elastic Beanstalk transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        let label = match failure {
            TransportFailure::BadRequest => "400",
            TransportFailure::Unauthorized => "401",
            TransportFailure::AccessDenied => "403",
            TransportFailure::NotFound => "404",
            TransportFailure::Throttled => "429",
            TransportFailure::Server => "5xx",
            TransportFailure::Timeout => "timeout",
            TransportFailure::BlockedEnv => "BLOCKED_ENV",
            TransportFailure::Malformed => "malformed",
        };
        Self {
            failure,
            status_code: failure.status_code(),
            error_digest: Digest::from_text(label),
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv)
    }

    pub fn malformed() -> Self {
        Self::new(TransportFailure::Malformed)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider model is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("provider definition revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("provider model is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("provider transport failed: {0}")]
    Transport(#[from] TransportError),
    #[error("provider page binding or evidence digest is invalid")]
    PageBinding,
    #[error("provider revision is incompatible")]
    ProviderRevision,
    #[error("provider response is malformed or outside the bound")]
    MalformedResponse,
}

impl ProviderError {
    pub fn is_blocked_env(&self) -> bool {
        matches!(self, Self::Transport(error) if error.failure == TransportFailure::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    pub operation: AwsElasticBeanstalkReadOperation,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub application_name: ApplicationName,
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub permission_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeEnvironmentsRequest {
    account_id: AccountId,
    region: AwsRegion,
    application_name: ApplicationName,
    environment_allowlist: Vec<EnvironmentName>,
    max_items: u16,
    max_pages: u16,
    max_response_bytes: usize,
    page_number: u16,
    page_token: Option<OpaquePageToken>,
    scope_digest: Digest,
    version_digest: Digest,
    permission_digest: Digest,
    request_digest: Digest,
}

impl DescribeEnvironmentsRequest {
    pub fn new(
        scope: &AwsElasticBeanstalkDeploymentScope,
        bounds: &ReadBounds,
    ) -> Result<Self, ModelError> {
        Self::for_page(scope, bounds, 1, None)
    }

    pub fn for_page(
        scope: &AwsElasticBeanstalkDeploymentScope,
        bounds: &ReadBounds,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        scope.verify()?;
        if page_number == 0 || page_number > bounds.max_pages {
            return Err(ModelError::Invalid {
                field: "environment page number",
            });
        }
        let request_digest = digest_request(
            AwsElasticBeanstalkReadOperation::DescribeEnvironments,
            &scope.account_id,
            &scope.region,
            &scope.application_name,
            &scope.environment_allowlist,
            bounds.page_size,
            page_number,
            bounds.max_response_bytes,
            page_token.as_ref(),
            &scope.scope_digest,
            scope.version_digest(),
            &scope.permission_digest,
        );
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            application_name: scope.application_name.clone(),
            environment_allowlist: scope.environment_allowlist.clone(),
            max_items: bounds.page_size,
            max_pages: bounds.max_pages,
            max_response_bytes: bounds.max_response_bytes,
            page_number,
            page_token,
            scope_digest: scope.scope_digest.clone(),
            version_digest: scope.version_digest().clone(),
            permission_digest: scope.permission_digest.clone(),
            request_digest,
        })
    }

    pub fn with_next_token(&self, page_token: Option<OpaquePageToken>) -> Result<Self, ModelError> {
        let mut next = self.clone();
        next.page_number = self.page_number.saturating_add(1);
        if next.page_number > self.max_pages {
            return Err(ModelError::Invalid {
                field: "environment page bound",
            });
        }
        next.page_token = page_token;
        next.request_digest = digest_request(
            AwsElasticBeanstalkReadOperation::DescribeEnvironments,
            &next.account_id,
            &next.region,
            &next.application_name,
            &next.environment_allowlist,
            next.max_items,
            next.page_number,
            next.max_response_bytes,
            next.page_token.as_ref(),
            &next.scope_digest,
            &next.version_digest,
            &next.permission_digest,
        );
        Ok(next)
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn application_name(&self) -> &ApplicationName {
        &self.application_name
    }

    pub fn environment_allowlist(&self) -> &[EnvironmentName] {
        &self.environment_allowlist
    }

    pub const fn max_items(&self) -> u16 {
        self.max_items
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsElasticBeanstalkReadOperation::DescribeEnvironments,
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            application_name: self.application_name.clone(),
            scope_digest: self.scope_digest.clone(),
            version_digest: self.version_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeEnvironmentResourcesRequest {
    account_id: AccountId,
    region: AwsRegion,
    application_name: ApplicationName,
    environment_allowlist: Vec<EnvironmentName>,
    max_items: u16,
    max_pages: u16,
    max_response_bytes: usize,
    page_number: u16,
    page_token: Option<OpaquePageToken>,
    scope_digest: Digest,
    version_digest: Digest,
    permission_digest: Digest,
    request_digest: Digest,
}

impl DescribeEnvironmentResourcesRequest {
    pub fn new(
        scope: &AwsElasticBeanstalkDeploymentScope,
        bounds: &ReadBounds,
    ) -> Result<Self, ModelError> {
        Self::for_page(scope, bounds, 1, None)
    }

    pub fn for_page(
        scope: &AwsElasticBeanstalkDeploymentScope,
        bounds: &ReadBounds,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        scope.verify()?;
        if page_number == 0 || page_number > bounds.max_pages {
            return Err(ModelError::Invalid {
                field: "resource page number",
            });
        }
        let request_digest = digest_request(
            AwsElasticBeanstalkReadOperation::DescribeEnvironmentResources,
            &scope.account_id,
            &scope.region,
            &scope.application_name,
            &scope.environment_allowlist,
            bounds.page_size,
            page_number,
            bounds.max_response_bytes,
            page_token.as_ref(),
            &scope.scope_digest,
            scope.version_digest(),
            &scope.permission_digest,
        );
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            application_name: scope.application_name.clone(),
            environment_allowlist: scope.environment_allowlist.clone(),
            max_items: bounds.page_size,
            max_pages: bounds.max_pages,
            max_response_bytes: bounds.max_response_bytes,
            page_number,
            page_token,
            scope_digest: scope.scope_digest.clone(),
            version_digest: scope.version_digest().clone(),
            permission_digest: scope.permission_digest.clone(),
            request_digest,
        })
    }

    pub fn with_next_token(&self, page_token: Option<OpaquePageToken>) -> Result<Self, ModelError> {
        let mut next = self.clone();
        next.page_number = self.page_number.saturating_add(1);
        if next.page_number > self.max_pages {
            return Err(ModelError::Invalid {
                field: "resource page bound",
            });
        }
        next.page_token = page_token;
        next.request_digest = digest_request(
            AwsElasticBeanstalkReadOperation::DescribeEnvironmentResources,
            &next.account_id,
            &next.region,
            &next.application_name,
            &next.environment_allowlist,
            next.max_items,
            next.page_number,
            next.max_response_bytes,
            next.page_token.as_ref(),
            &next.scope_digest,
            &next.version_digest,
            &next.permission_digest,
        );
        Ok(next)
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn application_name(&self) -> &ApplicationName {
        &self.application_name
    }

    pub fn environment_allowlist(&self) -> &[EnvironmentName] {
        &self.environment_allowlist
    }

    pub const fn max_items(&self) -> u16 {
        self.max_items
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsElasticBeanstalkReadOperation::DescribeEnvironmentResources,
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            application_name: self.application_name.clone(),
            scope_digest: self.scope_digest.clone(),
            version_digest: self.version_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeEventsRequest {
    account_id: AccountId,
    region: AwsRegion,
    application_name: ApplicationName,
    environment_allowlist: Vec<EnvironmentName>,
    max_items: u16,
    max_pages: u16,
    max_response_bytes: usize,
    page_number: u16,
    page_token: Option<OpaquePageToken>,
    scope_digest: Digest,
    version_digest: Digest,
    permission_digest: Digest,
    request_digest: Digest,
}

impl DescribeEventsRequest {
    pub fn new(
        scope: &AwsElasticBeanstalkDeploymentScope,
        bounds: &ReadBounds,
    ) -> Result<Self, ModelError> {
        Self::for_page(scope, bounds, 1, None)
    }

    pub fn for_page(
        scope: &AwsElasticBeanstalkDeploymentScope,
        bounds: &ReadBounds,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        scope.verify()?;
        if page_number == 0 || page_number > bounds.max_pages {
            return Err(ModelError::Invalid {
                field: "event page number",
            });
        }
        let request_digest = digest_request(
            AwsElasticBeanstalkReadOperation::DescribeEvents,
            &scope.account_id,
            &scope.region,
            &scope.application_name,
            &scope.environment_allowlist,
            bounds.page_size,
            page_number,
            bounds.max_response_bytes,
            page_token.as_ref(),
            &scope.scope_digest,
            scope.version_digest(),
            &scope.permission_digest,
        );
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            application_name: scope.application_name.clone(),
            environment_allowlist: scope.environment_allowlist.clone(),
            max_items: bounds.page_size,
            max_pages: bounds.max_pages,
            max_response_bytes: bounds.max_response_bytes,
            page_number,
            page_token,
            scope_digest: scope.scope_digest.clone(),
            version_digest: scope.version_digest().clone(),
            permission_digest: scope.permission_digest.clone(),
            request_digest,
        })
    }

    pub fn with_next_token(&self, page_token: Option<OpaquePageToken>) -> Result<Self, ModelError> {
        let mut next = self.clone();
        next.page_number = self.page_number.saturating_add(1);
        if next.page_number > self.max_pages {
            return Err(ModelError::Invalid {
                field: "event page bound",
            });
        }
        next.page_token = page_token;
        next.request_digest = digest_request(
            AwsElasticBeanstalkReadOperation::DescribeEvents,
            &next.account_id,
            &next.region,
            &next.application_name,
            &next.environment_allowlist,
            next.max_items,
            next.page_number,
            next.max_response_bytes,
            next.page_token.as_ref(),
            &next.scope_digest,
            &next.version_digest,
            &next.permission_digest,
        );
        Ok(next)
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn application_name(&self) -> &ApplicationName {
        &self.application_name
    }

    pub fn environment_allowlist(&self) -> &[EnvironmentName] {
        &self.environment_allowlist
    }

    pub const fn max_items(&self) -> u16 {
        self.max_items
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsElasticBeanstalkReadOperation::DescribeEvents,
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            application_name: self.application_name.clone(),
            scope_digest: self.scope_digest.clone(),
            version_digest: self.version_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

fn digest_request(
    operation: AwsElasticBeanstalkReadOperation,
    account_id: &AccountId,
    region: &AwsRegion,
    application_name: &ApplicationName,
    environments: &[EnvironmentName],
    page_size: u16,
    page_number: u16,
    max_response_bytes: usize,
    page_token: Option<&OpaquePageToken>,
    scope_digest: &Digest,
    version_digest: &Digest,
    permission_digest: &Digest,
) -> Digest {
    let page_token_digest = page_token.map(|token| token.digest().clone());
    Digest::from_parts(
        "hartevo-aws-elastic-beanstalk-request/v1",
        &[
            operation.as_str().to_owned(),
            account_id.as_str().to_owned(),
            region.as_str().to_owned(),
            application_name.as_str().to_owned(),
            environments
                .iter()
                .map(EnvironmentName::as_str)
                .collect::<Vec<_>>()
                .join(","),
            page_size.to_string(),
            page_number.to_string(),
            max_response_bytes.to_string(),
            page_token_digest.map_or_else(String::new, |digest| digest.as_str().to_owned()),
            scope_digest.as_str().to_owned(),
            version_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeEnvironmentsPage {
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub page_number: u16,
    pub environments: Vec<EnvironmentRevisionProjection>,
    pub next_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeEnvironmentsPage {
    pub fn new(
        request: &DescribeEnvironmentsRequest,
        environments: Vec<EnvironmentRevisionProjection>,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
        provenance: ProviderProvenance,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if environments.len() > request.max_items() as usize
            || response_bytes > request.max_response_bytes
        {
            return Err(ModelError::TooMany {
                field: "DescribeEnvironments response",
            });
        }
        let mut page = Self {
            scope_digest: request.scope_digest().clone(),
            version_digest: request.version_digest().clone(),
            permission_digest: request.permission_digest().clone(),
            request_digest: request.request_digest().clone(),
            provider_revision,
            page_number: request.page_number(),
            environments,
            next_token,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        page.evidence_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn validate_for(
        &self,
        request: &DescribeEnvironmentsRequest,
        expected_revision: &ProviderRevision,
    ) -> Result<(), ProviderError> {
        if self.scope_digest != *request.scope_digest()
            || self.version_digest != *request.version_digest()
            || self.permission_digest != *request.permission_digest()
            || self.request_digest != *request.request_digest()
            || self.provider_revision != *expected_revision
            || self.page_number != request.page_number()
            || self.environments.len() > request.max_items() as usize
            || self.response_bytes > request.max_response_bytes
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(ProviderError::PageBinding);
        }
        for environment in &self.environments {
            environment
                .verify()
                .map_err(|_| ProviderError::PageBinding)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        digest_page(
            &self.scope_digest,
            &self.version_digest,
            &self.permission_digest,
            &self.request_digest,
            &self.provider_revision,
            self.page_number,
            &self.environments,
            self.next_token.as_ref(),
            self.response_bytes,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeEnvironmentResourcesPage {
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub page_number: u16,
    pub resources: Vec<ResourceProjection>,
    pub next_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeEnvironmentResourcesPage {
    pub fn new(
        request: &DescribeEnvironmentResourcesRequest,
        resources: Vec<ResourceProjection>,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
        provenance: ProviderProvenance,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if resources.len() > request.max_items() as usize
            || response_bytes > request.max_response_bytes
        {
            return Err(ModelError::TooMany {
                field: "DescribeEnvironmentResources response",
            });
        }
        let mut page = Self {
            scope_digest: request.scope_digest().clone(),
            version_digest: request.version_digest().clone(),
            permission_digest: request.permission_digest().clone(),
            request_digest: request.request_digest().clone(),
            provider_revision,
            page_number: request.page_number(),
            resources,
            next_token,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        page.evidence_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn validate_for(
        &self,
        request: &DescribeEnvironmentResourcesRequest,
        expected_revision: &ProviderRevision,
    ) -> Result<(), ProviderError> {
        if self.scope_digest != *request.scope_digest()
            || self.version_digest != *request.version_digest()
            || self.permission_digest != *request.permission_digest()
            || self.request_digest != *request.request_digest()
            || self.provider_revision != *expected_revision
            || self.page_number != request.page_number()
            || self.resources.len() > request.max_items() as usize
            || self.response_bytes > request.max_response_bytes
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(ProviderError::PageBinding);
        }
        for resource in &self.resources {
            resource.verify().map_err(|_| ProviderError::PageBinding)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        digest_page(
            &self.scope_digest,
            &self.version_digest,
            &self.permission_digest,
            &self.request_digest,
            &self.provider_revision,
            self.page_number,
            &self.resources,
            self.next_token.as_ref(),
            self.response_bytes,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeEventsPage {
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub page_number: u16,
    pub events: Vec<EventProjection>,
    pub next_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeEventsPage {
    pub fn new(
        request: &DescribeEventsRequest,
        events: Vec<EventProjection>,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
        provenance: ProviderProvenance,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if events.len() > request.max_items() as usize
            || response_bytes > request.max_response_bytes
        {
            return Err(ModelError::TooMany {
                field: "DescribeEvents response",
            });
        }
        let mut page = Self {
            scope_digest: request.scope_digest().clone(),
            version_digest: request.version_digest().clone(),
            permission_digest: request.permission_digest().clone(),
            request_digest: request.request_digest().clone(),
            provider_revision,
            page_number: request.page_number(),
            events,
            next_token,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        page.evidence_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn validate_for(
        &self,
        request: &DescribeEventsRequest,
        expected_revision: &ProviderRevision,
    ) -> Result<(), ProviderError> {
        if self.scope_digest != *request.scope_digest()
            || self.version_digest != *request.version_digest()
            || self.permission_digest != *request.permission_digest()
            || self.request_digest != *request.request_digest()
            || self.provider_revision != *expected_revision
            || self.page_number != request.page_number()
            || self.events.len() > request.max_items() as usize
            || self.response_bytes > request.max_response_bytes
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(ProviderError::PageBinding);
        }
        for event in &self.events {
            event.verify().map_err(|_| ProviderError::PageBinding)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        digest_page(
            &self.scope_digest,
            &self.version_digest,
            &self.permission_digest,
            &self.request_digest,
            &self.provider_revision,
            self.page_number,
            &self.events,
            self.next_token.as_ref(),
            self.response_bytes,
        )
    }
}

fn digest_page<T: Serialize>(
    scope_digest: &Digest,
    version_digest: &Digest,
    permission_digest: &Digest,
    request_digest: &Digest,
    provider_revision: &ProviderRevision,
    page_number: u16,
    items: &[T],
    next_token: Option<&OpaquePageToken>,
    response_bytes: usize,
) -> Digest {
    let next_token_digest = next_token.map(|token| token.digest().clone());
    let item_digest = Digest::from_bytes(
        &serde_json::to_vec(items).expect("redacted projection serialization cannot fail"),
    );
    Digest::from_parts(
        "hartevo-aws-elastic-beanstalk-page/v1",
        &[
            scope_digest.as_str().to_owned(),
            version_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            request_digest.as_str().to_owned(),
            provider_revision.as_str().to_owned(),
            page_number.to_string(),
            item_digest.as_str().to_owned(),
            next_token_digest.map_or_else(String::new, |digest| digest.as_str().to_owned()),
            response_bytes.to_string(),
        ],
    )
}

/// The only transport contract exposed by this Layer-1 provider.
pub trait AwsElasticBeanstalkTransport: fmt::Debug + Send {
    fn provenance(&self) -> ProviderProvenance;

    fn describe_environments(
        &mut self,
        request: &DescribeEnvironmentsRequest,
    ) -> Result<DescribeEnvironmentsPage, TransportError>;

    fn describe_environment_resources(
        &mut self,
        request: &DescribeEnvironmentResourcesRequest,
    ) -> Result<DescribeEnvironmentResourcesPage, TransportError>;

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsPage, TransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsElasticBeanstalkProviderDefinition {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub allowlisted_operations: Vec<AwsElasticBeanstalkReadOperation>,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
}

impl AwsElasticBeanstalkProviderDefinition {
    pub fn new() -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(AWS_ELASTIC_BEANSTALK_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(AWS_ELASTIC_BEANSTALK_API_REVISION)?;
        let allowlisted_operations = AwsElasticBeanstalkReadOperation::ALL.to_vec();
        let provider_digest = Digest::from_parts(
            "hartevo-aws-elastic-beanstalk-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                AWS_ELASTIC_BEANSTALK_PROVIDER_VERSION.to_owned(),
                api_revision.as_str().to_owned(),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-aws-elastic-beanstalk-read-allowlist/v1",
            &allowlisted_operations
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            provider_id,
            version: AWS_ELASTIC_BEANSTALK_PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            allowlisted_operations,
            native: false,
            connected: false,
            external_writes: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected = Self::new()?;
        if self != &expected {
            return Err(ProviderDefinitionError::RevisionMismatch);
        }
        Ok(())
    }
}

pub struct AwsElasticBeanstalkProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: AwsElasticBeanstalkProviderDefinition,
    bounds: ReadBounds,
}

impl<T> fmt::Debug for AwsElasticBeanstalkProvider<T>
where
    T: AwsElasticBeanstalkTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsElasticBeanstalkProvider")
            .field("provider_id", &self.definition.provider_id)
            .field("version", &self.definition.version)
            .field("api_revision", &self.definition.api_revision)
            .field("provider_digest", &self.definition.provider_digest)
            .field("api_digest", &self.definition.api_digest)
            .field("provenance", &self.transport.provenance())
            .field("bounds", &self.bounds)
            .finish()
    }
}

impl Default for AwsElasticBeanstalkProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("static provider definition is valid")
    }
}

impl<T> AwsElasticBeanstalkProvider<T>
where
    T: AwsElasticBeanstalkTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            definition: AwsElasticBeanstalkProviderDefinition::new()?,
            transport,
            bounds: ReadBounds::default(),
        })
    }

    pub fn with_bounds(transport: T, bounds: ReadBounds) -> Result<Self, ProviderDefinitionError> {
        bounds.validate().map_err(ProviderDefinitionError::Model)?;
        Ok(Self {
            definition: AwsElasticBeanstalkProviderDefinition::new()?,
            transport,
            bounds,
        })
    }

    pub fn definition(&self) -> &AwsElasticBeanstalkProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &AwsElasticBeanstalkProviderDefinition {
        &self.definition
    }

    pub fn bounds(&self) -> &ReadBounds {
        &self.bounds
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.definition
            .validate()
            .map_err(|_| ProviderError::ProviderRevision)?;
        self.bounds.validate()?;
        Ok(())
    }

    pub fn describe_environments(
        &mut self,
        request: &DescribeEnvironmentsRequest,
    ) -> Result<DescribeEnvironmentsPage, ProviderError> {
        self.validate_request(
            request.scope_digest(),
            request.version_digest(),
            request.permission_digest(),
            AwsElasticBeanstalkReadOperation::DescribeEnvironments,
        )?;
        let page = self.transport.describe_environments(request)?;
        if page.provenance != self.transport.provenance() {
            return Err(ProviderError::PageBinding);
        }
        page.validate_for(request, &self.definition.api_revision)?;
        Ok(page)
    }

    pub fn describe_environment_resources(
        &mut self,
        request: &DescribeEnvironmentResourcesRequest,
    ) -> Result<DescribeEnvironmentResourcesPage, ProviderError> {
        self.validate_request(
            request.scope_digest(),
            request.version_digest(),
            request.permission_digest(),
            AwsElasticBeanstalkReadOperation::DescribeEnvironmentResources,
        )?;
        let page = self.transport.describe_environment_resources(request)?;
        if page.provenance != self.transport.provenance() {
            return Err(ProviderError::PageBinding);
        }
        page.validate_for(request, &self.definition.api_revision)?;
        Ok(page)
    }

    pub fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsPage, ProviderError> {
        self.validate_request(
            request.scope_digest(),
            request.version_digest(),
            request.permission_digest(),
            AwsElasticBeanstalkReadOperation::DescribeEvents,
        )?;
        let page = self.transport.describe_events(request)?;
        if page.provenance != self.transport.provenance() {
            return Err(ProviderError::PageBinding);
        }
        page.validate_for(request, &self.definition.api_revision)?;
        Ok(page)
    }

    fn validate_request(
        &self,
        scope_digest: &Digest,
        version_digest: &Digest,
        permission_digest: &Digest,
        operation: AwsElasticBeanstalkReadOperation,
    ) -> Result<(), ProviderError> {
        if scope_digest == &Digest::zero()
            || version_digest == &Digest::zero()
            || permission_digest == &Digest::zero()
            || !self.definition.allowlisted_operations.contains(&operation)
        {
            return Err(ProviderError::PageBinding);
        }
        Ok(())
    }

    pub fn parse_describe_environments_page(
        request: &DescribeEnvironmentsRequest,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<DescribeEnvironmentsPage, ProviderError> {
        ensure_response(
            status_code,
            body,
            request.max_response_bytes,
            request.max_items() as usize,
        )?;
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| ProviderError::MalformedResponse)?;
        let items = value
            .get("Environments")
            .and_then(Value::as_array)
            .ok_or(ProviderError::MalformedResponse)?;
        let mut environments = Vec::with_capacity(items.len());
        for item in items {
            let environment_id = required_string(item, "EnvironmentId")
                .and_then(|value| EnvironmentId::new(value).map_err(ProviderError::Model))?;
            let environment_name = required_string(item, "EnvironmentName")
                .and_then(|value| EnvironmentName::new(value).map_err(ProviderError::Model))?;
            if !request
                .environment_allowlist()
                .iter()
                .any(|allowed| allowed == &environment_name)
            {
                return Err(ProviderError::Model(ModelError::ScopeMismatch {
                    field: "environment name",
                }));
            }
            let revision = item
                .get("Revision")
                .and_then(Value::as_u64)
                .unwrap_or(u64::from(request.page_number()));
            let revision = crate::model::Revision::new(revision).map_err(ProviderError::Model)?;
            let version_label = item
                .get("VersionLabel")
                .and_then(Value::as_str)
                .unwrap_or("unknown-version");
            let version_digest = Digest::from_parts(
                "hartevo-aws-elastic-beanstalk-version-label/v1",
                &[version_label.to_owned()],
            );
            let updated_at = timestamp_or_epoch(item, "DateUpdated", "LastUpdatedTime")?;
            environments.push(
                EnvironmentRevisionProjection::new(
                    environment_id,
                    environment_name,
                    revision,
                    item.get("Status")
                        .and_then(Value::as_str)
                        .map_or(EnvironmentStatus::Unknown, EnvironmentStatus::parse),
                    item.get("Health")
                        .and_then(Value::as_str)
                        .map_or(HealthStatus::Unknown, HealthStatus::parse),
                    version_digest,
                    updated_at,
                )
                .map_err(ProviderError::Model)?,
            );
        }
        let next_token = next_token(&value)?;
        DescribeEnvironmentsPage::new(
            request,
            environments,
            next_token,
            body.len(),
            ProviderProvenance::Fixture,
            provider_revision,
        )
        .map_err(ProviderError::Model)
    }

    pub fn parse_describe_environment_resources_page(
        request: &DescribeEnvironmentResourcesRequest,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<DescribeEnvironmentResourcesPage, ProviderError> {
        ensure_response(
            status_code,
            body,
            request.max_response_bytes,
            request.max_items() as usize,
        )?;
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| ProviderError::MalformedResponse)?;
        let resources = value
            .get("EnvironmentResources")
            .and_then(Value::as_object)
            .ok_or(ProviderError::MalformedResponse)?;
        let environment_name = resources
            .get("EnvironmentName")
            .and_then(Value::as_str)
            .or_else(|| {
                request
                    .environment_allowlist()
                    .first()
                    .map(EnvironmentName::as_str)
            })
            .ok_or(ProviderError::MalformedResponse)?;
        if !request
            .environment_allowlist()
            .iter()
            .any(|allowed| allowed.as_str() == environment_name)
        {
            return Err(ProviderError::Model(ModelError::ScopeMismatch {
                field: "resource environment name",
            }));
        }
        let environment_id = redacted_environment_id(environment_name)?;
        let mut projections = Vec::new();
        for (field, kind) in [
            ("Instances", ResourceKind::Instance),
            ("AutoScalingGroups", ResourceKind::AutoScalingGroup),
            ("LaunchConfigurations", ResourceKind::LaunchConfiguration),
            ("LoadBalancers", ResourceKind::LoadBalancer),
            ("Queues", ResourceKind::Queue),
            ("Triggers", ResourceKind::Trigger),
        ] {
            if let Some(items) = resources.get(field).and_then(Value::as_array) {
                let resource_digest = Digest::from_bytes(
                    &serde_json::to_vec(items).map_err(|_| ProviderError::MalformedResponse)?,
                );
                projections.push(
                    ResourceProjection::new(
                        environment_id.clone(),
                        kind,
                        u32::try_from(items.len()).map_err(|_| ProviderError::MalformedResponse)?,
                        resource_digest,
                        timestamp_or_epoch(&value, "DateUpdated", "LastUpdatedTime")?,
                    )
                    .map_err(ProviderError::Model)?,
                );
            }
        }
        let next_token = next_token(&value)?;
        DescribeEnvironmentResourcesPage::new(
            request,
            projections,
            next_token,
            body.len(),
            ProviderProvenance::Fixture,
            provider_revision,
        )
        .map_err(ProviderError::Model)
    }

    pub fn parse_describe_events_page(
        request: &DescribeEventsRequest,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<DescribeEventsPage, ProviderError> {
        ensure_response(
            status_code,
            body,
            request.max_response_bytes,
            request.max_items() as usize,
        )?;
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| ProviderError::MalformedResponse)?;
        let items = value
            .get("Events")
            .and_then(Value::as_array)
            .ok_or(ProviderError::MalformedResponse)?;
        let mut events = Vec::with_capacity(items.len());
        for item in items {
            let environment_name = item
                .get("EnvironmentName")
                .and_then(Value::as_str)
                .or_else(|| {
                    request
                        .environment_allowlist()
                        .first()
                        .map(EnvironmentName::as_str)
                })
                .ok_or(ProviderError::MalformedResponse)?;
            if !request
                .environment_allowlist()
                .iter()
                .any(|allowed| allowed.as_str() == environment_name)
            {
                return Err(ProviderError::Model(ModelError::ScopeMismatch {
                    field: "event environment name",
                }));
            }
            let environment_id = redacted_environment_id(environment_name)?;
            let occurred_at = timestamp_or_epoch(item, "EventDate", "DateUpdated")?;
            let message = item
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("<redacted-or-missing>");
            let event_id = item
                .get("EventId")
                .and_then(Value::as_str)
                .unwrap_or(message);
            let revision = crate::model::Revision::new(
                item.get("Revision")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::from(request.page_number())),
            )
            .map_err(ProviderError::Model)?;
            events.push(
                EventProjection::new(
                    environment_id,
                    event_id,
                    revision,
                    occurred_at,
                    item.get("Severity")
                        .and_then(Value::as_str)
                        .map_or(EventSeverity::Unknown, EventSeverity::parse),
                    item.get("EventType")
                        .and_then(Value::as_str)
                        .map_or(EventKind::Other, EventKind::parse),
                    message,
                )
                .map_err(ProviderError::Model)?,
            );
        }
        let next_token = next_token(&value)?;
        DescribeEventsPage::new(
            request,
            events,
            next_token,
            body.len(),
            ProviderProvenance::Fixture,
            provider_revision,
        )
        .map_err(ProviderError::Model)
    }
}

fn ensure_response(
    status_code: u16,
    body: &[u8],
    max_response_bytes: usize,
    max_items: usize,
) -> Result<(), ProviderError> {
    if status_code != 200 || body.is_empty() || body.len() > max_response_bytes || max_items == 0 {
        Err(ProviderError::MalformedResponse)
    } else {
        Ok(())
    }
}

fn required_string<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ProviderError::MalformedResponse)
}

fn timestamp_or_epoch(
    value: &Value,
    primary: &str,
    secondary: &str,
) -> Result<DateTime<Utc>, ProviderError> {
    let timestamp = value
        .get(primary)
        .or_else(|| value.get(secondary))
        .and_then(Value::as_str);
    match timestamp {
        Some(value) => DateTime::parse_from_rfc3339(value)
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .map_err(|_| ProviderError::MalformedResponse),
        None => Ok(Utc.timestamp_opt(0, 0).single().expect("epoch exists")),
    }
}

fn next_token(value: &Value) -> Result<Option<OpaquePageToken>, ProviderError> {
    value
        .get("NextToken")
        .and_then(Value::as_str)
        .map(OpaquePageToken::new)
        .transpose()
        .map_err(ProviderError::Model)
}

fn redacted_environment_id(name: &str) -> Result<EnvironmentId, ProviderError> {
    let digest = Digest::from_parts(
        "hartevo-aws-elastic-beanstalk-environment-name/v1",
        &[name.to_owned()],
    );
    EnvironmentId::new(format!("redacted-{}", &digest.as_str()[..24])).map_err(ProviderError::Model)
}

#[derive(Clone, Debug, Default)]
struct QueueState {
    environments: VecDeque<Result<DescribeEnvironmentsPage, TransportError>>,
    resources: VecDeque<Result<DescribeEnvironmentResourcesPage, TransportError>>,
    events: VecDeque<Result<DescribeEventsPage, TransportError>>,
    calls: Vec<RecordedRequest>,
}

impl QueueState {
    fn describe_environments(
        &mut self,
        request: &DescribeEnvironmentsRequest,
    ) -> Result<DescribeEnvironmentsPage, TransportError> {
        self.calls.push(request.recorded_request());
        self.environments
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::new(TransportFailure::Timeout)))
    }

    fn describe_environment_resources(
        &mut self,
        request: &DescribeEnvironmentResourcesRequest,
    ) -> Result<DescribeEnvironmentResourcesPage, TransportError> {
        self.calls.push(request.recorded_request());
        self.resources
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::new(TransportFailure::Timeout)))
    }

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsPage, TransportError> {
        self.calls.push(request.recorded_request());
        self.events
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::new(TransportFailure::Timeout)))
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            queue: QueueState,
        }

        impl $name {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn push_describe_environments(
                &mut self,
                response: Result<DescribeEnvironmentsPage, TransportError>,
            ) {
                self.queue.environments.push_back(response);
            }

            pub fn push_describe_environment_resources(
                &mut self,
                response: Result<DescribeEnvironmentResourcesPage, TransportError>,
            ) {
                self.queue.resources.push_back(response);
            }

            pub fn push_describe_events(
                &mut self,
                response: Result<DescribeEventsPage, TransportError>,
            ) {
                self.queue.events.push_back(response);
            }

            pub fn calls(&self) -> &[RecordedRequest] {
                &self.queue.calls
            }

            pub fn clear_calls(&mut self) {
                self.queue.calls.clear();
            }
        }

        impl AwsElasticBeanstalkTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }

            fn describe_environments(
                &mut self,
                request: &DescribeEnvironmentsRequest,
            ) -> Result<DescribeEnvironmentsPage, TransportError> {
                self.queue.describe_environments(request)
            }

            fn describe_environment_resources(
                &mut self,
                request: &DescribeEnvironmentResourcesRequest,
            ) -> Result<DescribeEnvironmentResourcesPage, TransportError> {
                self.queue.describe_environment_resources(request)
            }

            fn describe_events(
                &mut self,
                request: &DescribeEventsRequest,
            ) -> Result<DescribeEventsPage, TransportError> {
                self.queue.describe_events(request)
            }
        }
    };
}

queued_transport!(
    RecordingAwsElasticBeanstalkTransport,
    ProviderProvenance::Recording
);
queued_transport!(
    FixtureAwsElasticBeanstalkTransport,
    ProviderProvenance::Fixture
);
queued_transport!(
    LoopbackAwsElasticBeanstalkTransport,
    ProviderProvenance::Loopback
);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsElasticBeanstalkTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn describe_environments(
        &mut self,
        _request: &DescribeEnvironmentsRequest,
    ) -> Result<DescribeEnvironmentsPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_environment_resources(
        &mut self,
        _request: &DescribeEnvironmentResourcesRequest,
    ) -> Result<DescribeEnvironmentResourcesPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_events(
        &mut self,
        _request: &DescribeEventsRequest,
    ) -> Result<DescribeEventsPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type FakeAwsElasticBeanstalkTransport = FixtureAwsElasticBeanstalkTransport;
pub type BlockedEnvAwsElasticBeanstalkTransport = BlockedEnvTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DeploymentBinding, DeploymentVersionBinding, MissionBinding, PermissionFence,
        ProjectBinding, Revision, WorkProductBinding,
    };

    fn scope() -> AwsElasticBeanstalkDeploymentScope {
        let permission = PermissionFence::readonly(
            crate::model::PermissionId::new("permission").expect("permission"),
            Revision::new(1).expect("revision"),
        )
        .expect("permission");
        AwsElasticBeanstalkDeploymentScope::new(
            DeploymentBinding::new(
                crate::model::DeploymentId::new("deployment").expect("deployment"),
                Revision::new(1).expect("revision"),
            ),
            MissionBinding::new(
                crate::model::MissionId::new("mission").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectBinding::new(
                crate::model::ProjectId::new("project").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            WorkProductBinding::new(
                crate::model::WorkProductId::new("work").expect("work"),
                Revision::new(1).expect("revision"),
            ),
            AccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            ApplicationName::new("app").expect("application"),
            vec![EnvironmentName::new("prod").expect("environment")],
            DeploymentVersionBinding::new(
                Revision::new(1).expect("revision"),
                Digest::from_text("version"),
            )
            .expect("version"),
            permission.permission_digest,
        )
        .expect("scope")
    }

    #[test]
    fn parser_discards_raw_event_message_and_unknown_fields() {
        let bounds = ReadBounds::default();
        let request = DescribeEventsRequest::new(&scope(), &bounds).expect("request");
        let body = br#"{"Events":[{"EventId":"e1","EnvironmentName":"prod","EventDate":"2026-01-01T00:00:00Z","Severity":"ERROR","EventType":"DEPLOYMENT","Message":"raw source and secret must disappear","CNAME":"bad.example"}],"NextToken":"opaque-token"}"#;
        let page = AwsElasticBeanstalkProvider::<BlockedEnvTransport>::parse_describe_events_page(
            &request,
            200,
            body,
            ProviderRevision::new(AWS_ELASTIC_BEANSTALK_API_REVISION).expect("revision"),
        )
        .expect("page");
        let json = serde_json::to_string(&page.events).expect("projection json");
        assert!(!json.contains("raw source"));
        assert!(!json.contains("CNAME"));
        assert_eq!(page.next_token.expect("token").digest().as_str().len(), 64);
    }

    #[test]
    fn recording_and_loopback_transport_never_claim_native_or_connected() {
        assert!(!ProviderProvenance::Recording.native());
        assert!(!ProviderProvenance::Recording.connected());
        assert!(!ProviderProvenance::Loopback.first_party());
    }

    #[test]
    fn blocked_environment_is_explicit() {
        let mut provider = AwsElasticBeanstalkProvider::new(BlockedEnvTransport).expect("provider");
        let request =
            DescribeEnvironmentsRequest::new(&scope(), &ReadBounds::default()).expect("request");
        let error = provider
            .describe_environments(&request)
            .expect_err("blocked");
        assert!(error.is_blocked_env());
    }

    #[test]
    fn recorded_request_contains_only_digests_for_opaque_token() {
        let request = DescribeEnvironmentsRequest::new(&scope(), &ReadBounds::default())
            .expect("request")
            .with_next_token(Some(
                OpaquePageToken::new("secret-provider-cursor").expect("token"),
            ))
            .expect("next request");
        let recorded = serde_json::to_string(&request.recorded_request()).expect("recording");
        assert!(!recorded.contains("secret-provider-cursor"));
        assert!(recorded.contains("pageTokenDigest"));
    }

    #[test]
    fn recording_transport_records_each_typed_operation_without_raw_payloads() {
        let scope = scope();
        let bounds = ReadBounds::default();
        let definition = AwsElasticBeanstalkProviderDefinition::new().expect("definition");
        let environment_request =
            DescribeEnvironmentsRequest::new(&scope, &bounds).expect("request");
        let resource_request =
            DescribeEnvironmentResourcesRequest::new(&scope, &bounds).expect("request");
        let event_request = DescribeEventsRequest::new(&scope, &bounds).expect("request");
        let mut transport = RecordingAwsElasticBeanstalkTransport::new();
        transport.push_describe_environments(Ok(DescribeEnvironmentsPage::new(
            &environment_request,
            Vec::new(),
            None,
            1,
            ProviderProvenance::Recording,
            definition.api_revision.clone(),
        )
        .expect("page")));
        transport.push_describe_environment_resources(Ok(DescribeEnvironmentResourcesPage::new(
            &resource_request,
            Vec::new(),
            None,
            1,
            ProviderProvenance::Recording,
            definition.api_revision.clone(),
        )
        .expect("page")));
        transport.push_describe_events(Ok(DescribeEventsPage::new(
            &event_request,
            Vec::new(),
            None,
            1,
            ProviderProvenance::Recording,
            definition.api_revision,
        )
        .expect("page")));
        let mut provider = AwsElasticBeanstalkProvider::new(transport).expect("provider");
        provider
            .describe_environments(&environment_request)
            .expect("environments");
        provider
            .describe_environment_resources(&resource_request)
            .expect("resources");
        provider.describe_events(&event_request).expect("events");
        assert_eq!(provider.transport().calls().len(), 3);
        assert!(
            serde_json::to_string(provider.transport().calls())
                .expect("recordings")
                .contains("DescribeEnvironmentResources")
        );
    }

    #[test]
    fn loopback_transport_is_non_native_and_page_bound_is_enforced() {
        let scope = scope();
        let one_page =
            ReadBounds::new(1, 256, 50, crate::model::MAX_RESPONSE_BYTES).expect("bounds");
        let request = DescribeEnvironmentsRequest::new(&scope, &one_page).expect("request");
        let token = OpaquePageToken::new("next-token").expect("token");
        assert!(request.with_next_token(Some(token)).is_err());
        assert!(
            !LoopbackAwsElasticBeanstalkTransport::default()
                .provenance()
                .native()
        );
        assert!(
            !LoopbackAwsElasticBeanstalkTransport::default()
                .provenance()
                .connected()
        );
    }

    #[test]
    fn parser_rejects_non_success_or_oversized_body() {
        let request =
            DescribeEnvironmentsRequest::new(&scope(), &ReadBounds::default()).expect("request");
        assert!(matches!(
            AwsElasticBeanstalkProvider::<BlockedEnvTransport>::parse_describe_environments_page(
                &request,
                403,
                br"{}",
                ProviderRevision::new(AWS_ELASTIC_BEANSTALK_API_REVISION).expect("revision"),
            ),
            Err(ProviderError::MalformedResponse)
        ));
    }
}
