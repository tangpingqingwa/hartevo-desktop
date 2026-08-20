//! Bounded AWS ACM provider seams.
//!
//! This module intentionally contains no AWS SDK, HTTPS client, SigV4 signer,
//! credential resolver, certificate export, private-key, validation-record,
//! DNS, or email effect. The only transport implementations are deterministic
//! fixture/recording/loopback/blocked-environment seams.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    AcmOperation, AwsAcmCertificateScope, CertificateDescription, CertificateDescriptionInput,
    CertificateSummary, Digest, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, ModelError,
    OpaqueNextToken, TransportProvenance,
};
use crate::{ACM_API_REVISION, ACM_PROVIDER_ID, ACM_PROVIDER_VERSION, LAYER1_PERMISSIONS};

pub const LIST_CERTIFICATES_OPERATION_PATH: &str = "/";
pub const SEARCH_CERTIFICATES_OPERATION_PATH: &str = "/";
pub const DESCRIBE_CERTIFICATE_OPERATION_PATH: &str = "/";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsAcmTransportError {
    #[error("BLOCKED_ENV: AWS ACM native transport is disabled")]
    BlockedEnv,
    #[error("AWS ACM request was invalid")]
    BadRequest,
    #[error("AWS ACM credentials were not authorized")]
    Unauthorized,
    #[error("AWS ACM access was forbidden")]
    Forbidden,
    #[error("AWS ACM certificate was not found")]
    NotFound,
    #[error("AWS ACM request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS ACM provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS ACM transport timed out")]
    Timeout,
    #[error("AWS ACM access was lost while reading evidence")]
    AccessLost,
    #[error("AWS ACM returned a partial response")]
    Partial,
    #[error("AWS ACM response was invalid")]
    InvalidResponse,
}

impl AwsAcmTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError { .. } | Self::Timeout
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS ACM provider provenance is not an allowed Layer-1 provenance")]
    UnsupportedProvenance,
    #[error("AWS ACM provider definition drifted")]
    DefinitionDrift,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsAcmProviderDefinition {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        if provenance.connected() || provenance.native() || provenance.first_party() {
            return Err(ProviderDefinitionError::UnsupportedProvenance);
        }
        let api_digest = Digest::from_text(ACM_API_REVISION);
        let provider_digest = Digest::from_parts(
            "aws-acm-provider/v1",
            &[
                ("provider_id", ACM_PROVIDER_ID.to_owned()),
                ("provider_version", ACM_PROVIDER_VERSION.to_owned()),
                ("api_revision", ACM_API_REVISION.to_owned()),
                ("api_digest", api_digest.as_str().to_owned()),
                ("permissions", LAYER1_PERMISSIONS.join(",")),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: ACM_PROVIDER_ID.to_owned(),
            provider_version: ACM_PROVIDER_VERSION.to_owned(),
            api_revision: ACM_API_REVISION.to_owned(),
            api_digest,
            provider_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected = Self::for_provenance(self.provenance)?;
        if self != &expected {
            return Err(ProviderDefinitionError::DefinitionDrift);
        }
        Ok(())
    }
}

/// A request receipt contains only digests and bounded counters. It never
/// records a raw ARN, raw domain, raw NextToken, request body, or response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AcmOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListCertificatesRequest {
    scope: AwsAcmCertificateScope,
    filter: crate::model::ListCertificatesFilter,
    next_token: Option<OpaqueNextToken>,
    request_digest: Digest,
}

impl ListCertificatesRequest {
    pub fn new(
        scope: &AwsAcmCertificateScope,
        filter: crate::model::ListCertificatesFilter,
        next_token: Option<OpaqueNextToken>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        filter.validate()?;
        if let Some(token) = &next_token {
            token.validate_for(
                AcmOperation::ListCertificates,
                scope,
                &filter.digest(),
                token.page_number(),
            )?;
        }
        let page = next_token.as_ref().map_or(1, OpaqueNextToken::page_number);
        let request_digest = Digest::from_parts(
            "aws-acm-list-certificates-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    next_token.as_ref().map_or_else(String::new, |token| {
                        token.token_digest().as_str().to_owned()
                    }),
                ),
                ("page", page.to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            next_token,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsAcmCertificateScope {
        &self.scope
    }

    pub fn filter(&self) -> &crate::model::ListCertificatesFilter {
        &self.filter
    }

    pub fn next_token(&self) -> Option<&OpaqueNextToken> {
        self.next_token.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        self.next_token
            .as_ref()
            .map_or(1, OpaqueNextToken::page_number)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn with_next_token(&self, next_token: OpaqueNextToken) -> Result<Self, ModelError> {
        Self::new(&self.scope, self.filter.clone(), Some(next_token))
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{}?operation=ListCertificates&scopeDigest={}&filterDigest={}&page={}&nextTokenDigest={}",
            LIST_CERTIFICATES_OPERATION_PATH,
            self.scope.digest().as_str(),
            self.filter.digest().as_str(),
            self.page_number(),
            self.next_token
                .as_ref()
                .map_or_else(String::new, |token| token
                    .token_digest()
                    .as_str()
                    .to_owned())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AcmOperation::ListCertificates,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .next_token
                .as_ref()
                .map(|token| token.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListCertificatesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListCertificatesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("next_token", &self.next_token)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListCertificatesRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("ListCertificatesRequest", 5)?;
        object.serialize_field("scopeDigest", &self.scope.digest())?;
        object.serialize_field("filterDigest", &self.filter.digest())?;
        object.serialize_field("pageNumber", &self.page_number())?;
        object.serialize_field(
            "nextToken",
            &self.next_token.as_ref().map(|token| token.token_digest()),
        )?;
        object.serialize_field("requestDigest", &self.request_digest)?;
        object.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SearchCertificatesRequest {
    scope: AwsAcmCertificateScope,
    filter: crate::model::SearchCertificatesFilter,
    next_token: Option<OpaqueNextToken>,
    request_digest: Digest,
}

impl SearchCertificatesRequest {
    pub fn new(
        scope: &AwsAcmCertificateScope,
        filter: crate::model::SearchCertificatesFilter,
        next_token: Option<OpaqueNextToken>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        filter.validate()?;
        if let Some(token) = &next_token {
            token.validate_for(
                AcmOperation::SearchCertificates,
                scope,
                &filter.digest(),
                token.page_number(),
            )?;
        }
        let page = next_token.as_ref().map_or(1, OpaqueNextToken::page_number);
        let request_digest = Digest::from_parts(
            "aws-acm-search-certificates-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    next_token.as_ref().map_or_else(String::new, |token| {
                        token.token_digest().as_str().to_owned()
                    }),
                ),
                ("page", page.to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            next_token,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsAcmCertificateScope {
        &self.scope
    }

    pub fn filter(&self) -> &crate::model::SearchCertificatesFilter {
        &self.filter
    }

    pub fn next_token(&self) -> Option<&OpaqueNextToken> {
        self.next_token.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        self.next_token
            .as_ref()
            .map_or(1, OpaqueNextToken::page_number)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn with_next_token(&self, next_token: OpaqueNextToken) -> Result<Self, ModelError> {
        Self::new(&self.scope, self.filter.clone(), Some(next_token))
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{}?operation=SearchCertificates&scopeDigest={}&filterDigest={}&page={}&nextTokenDigest={}",
            SEARCH_CERTIFICATES_OPERATION_PATH,
            self.scope.digest().as_str(),
            self.filter.digest().as_str(),
            self.page_number(),
            self.next_token
                .as_ref()
                .map_or_else(String::new, |token| token
                    .token_digest()
                    .as_str()
                    .to_owned())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AcmOperation::SearchCertificates,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .next_token
                .as_ref()
                .map(|token| token.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for SearchCertificatesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchCertificatesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("next_token", &self.next_token)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for SearchCertificatesRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("SearchCertificatesRequest", 5)?;
        object.serialize_field("scopeDigest", &self.scope.digest())?;
        object.serialize_field("filterDigest", &self.filter.digest())?;
        object.serialize_field("pageNumber", &self.page_number())?;
        object.serialize_field(
            "nextToken",
            &self.next_token.as_ref().map(|token| token.token_digest()),
        )?;
        object.serialize_field("requestDigest", &self.request_digest)?;
        object.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeCertificateRequest {
    scope: AwsAcmCertificateScope,
    request_digest: Digest,
}

impl DescribeCertificateRequest {
    pub fn for_scope(scope: &AwsAcmCertificateScope) -> Result<Self, ModelError> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-acm-describe-certificate-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "certificate",
                        scope.certificate_digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsAcmCertificateScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{}?operation=DescribeCertificate&scopeDigest={}&certificateDigest={}",
            DESCRIBE_CERTIFICATE_OPERATION_PATH,
            self.scope.digest().as_str(),
            self.scope.certificate_digest().as_str()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AcmOperation::DescribeCertificate,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribeCertificateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeCertificateRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for DescribeCertificateRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("DescribeCertificateRequest", 3)?;
        object.serialize_field("scopeDigest", &self.scope.digest())?;
        object.serialize_field("certificateDigest", &self.scope.certificate_digest())?;
        object.serialize_field("requestDigest", &self.request_digest)?;
        object.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCertificatesResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub certificates: Vec<CertificateSummary>,
    pub next_token: Option<OpaqueNextToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl ListCertificatesResponse {
    pub fn new(
        request: &ListCertificatesRequest,
        certificates: Vec<CertificateSummary>,
        next_token: Option<OpaqueNextToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        validate_response_bytes(response_bytes)?;
        validate_page_size(certificates.len(), request.filter().page_size)?;
        validate_next_token(
            next_token.as_ref(),
            AcmOperation::ListCertificates,
            request.scope(),
            &request.filter().digest(),
            request.page_number() + 1,
        )?;
        for certificate in &certificates {
            certificate.validate_integrity()?;
        }
        let response_digest = response_digest(
            request.request_digest(),
            request.page_number(),
            &certificates,
            next_token.as_ref(),
            response_bytes,
            provenance,
        );
        Ok(Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            certificates,
            next_token,
            response_bytes,
            provenance,
            response_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate_for(&self, request: &ListCertificatesRequest) -> Result<(), ModelError> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ModelError::ScopeMismatch {
                field: "ListCertificates response binding",
            });
        }
        validate_page_size(self.certificates.len(), request.filter().page_size)?;
        for certificate in &self.certificates {
            certificate.validate_integrity()?;
        }
        validate_next_token(
            self.next_token.as_ref(),
            AcmOperation::ListCertificates,
            request.scope(),
            &request.filter().digest(),
            request.page_number() + 1,
        )?;
        if self.response_digest
            != response_digest(
                request.request_digest(),
                request.page_number(),
                &self.certificates,
                self.next_token.as_ref(),
                self.response_bytes,
                self.provenance,
            )
        {
            return Err(ModelError::Invalid {
                field: "ListCertificates response digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchCertificatesResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub certificates: Vec<CertificateSummary>,
    pub next_token: Option<OpaqueNextToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl SearchCertificatesResponse {
    pub fn new(
        request: &SearchCertificatesRequest,
        certificates: Vec<CertificateSummary>,
        next_token: Option<OpaqueNextToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        validate_response_bytes(response_bytes)?;
        validate_page_size(certificates.len(), request.filter().page_size)?;
        validate_next_token(
            next_token.as_ref(),
            AcmOperation::SearchCertificates,
            request.scope(),
            &request.filter().digest(),
            request.page_number() + 1,
        )?;
        for certificate in &certificates {
            certificate.validate_integrity()?;
        }
        let response_digest = response_digest(
            request.request_digest(),
            request.page_number(),
            &certificates,
            next_token.as_ref(),
            response_bytes,
            provenance,
        );
        Ok(Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            certificates,
            next_token,
            response_bytes,
            provenance,
            response_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate_for(&self, request: &SearchCertificatesRequest) -> Result<(), ModelError> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ModelError::ScopeMismatch {
                field: "SearchCertificates response binding",
            });
        }
        validate_page_size(self.certificates.len(), request.filter().page_size)?;
        for certificate in &self.certificates {
            certificate.validate_integrity()?;
        }
        validate_next_token(
            self.next_token.as_ref(),
            AcmOperation::SearchCertificates,
            request.scope(),
            &request.filter().digest(),
            request.page_number() + 1,
        )?;
        if self.response_digest
            != response_digest(
                request.request_digest(),
                request.page_number(),
                &self.certificates,
                self.next_token.as_ref(),
                self.response_bytes,
                self.provenance,
            )
        {
            return Err(ModelError::Invalid {
                field: "SearchCertificates response digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeCertificateResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub certificate: CertificateDescription,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl DescribeCertificateResponse {
    pub fn new(
        request: &DescribeCertificateRequest,
        certificate: CertificateDescription,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        validate_response_bytes(response_bytes)?;
        certificate.validate_integrity()?;
        let response_digest = Digest::from_parts(
            "aws-acm-describe-certificate-response/v1",
            &[
                ("request", request.request_digest().as_str().to_owned()),
                (
                    "certificate",
                    certificate
                        .projection
                        .certificate_digest
                        .as_str()
                        .to_owned(),
                ),
                ("bytes", response_bytes.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            certificate,
            response_bytes,
            provenance,
            response_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate_for(&self, request: &DescribeCertificateRequest) -> Result<(), ModelError> {
        validate_response_bytes(self.response_bytes)?;
        self.certificate.validate_integrity()?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeCertificate response binding",
            });
        }
        let expected = Digest::from_parts(
            "aws-acm-describe-certificate-response/v1",
            &[
                ("request", request.request_digest().as_str().to_owned()),
                (
                    "certificate",
                    self.certificate
                        .projection
                        .certificate_digest
                        .as_str()
                        .to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        );
        if self.response_digest != expected {
            return Err(ModelError::Invalid {
                field: "DescribeCertificate response digest",
            });
        }
        Ok(())
    }
}

fn validate_response_bytes(bytes: u64) -> Result<(), ModelError> {
    if bytes > MAX_RESPONSE_BYTES {
        Err(ModelError::TooMany {
            field: "provider response bytes",
        })
    } else {
        Ok(())
    }
}

fn validate_page_size(actual: usize, requested: u16) -> Result<(), ModelError> {
    if requested == 0 || requested > MAX_PAGE_SIZE || actual > usize::from(requested) {
        Err(ModelError::TooMany {
            field: "certificates in provider page",
        })
    } else {
        Ok(())
    }
}

fn validate_next_token(
    token: Option<&OpaqueNextToken>,
    operation: AcmOperation,
    scope: &AwsAcmCertificateScope,
    filter_digest: &Digest,
    expected_page: u16,
) -> Result<(), ModelError> {
    if let Some(token) = token {
        if expected_page > MAX_PAGES {
            return Err(ModelError::InvalidCursor {
                field: "provider NextToken page budget",
            });
        }
        token.validate_for(operation, scope, filter_digest, expected_page)?;
    }
    Ok(())
}

fn response_digest(
    request_digest: &Digest,
    page_number: u16,
    certificates: &[CertificateSummary],
    next_token: Option<&OpaqueNextToken>,
    response_bytes: u64,
    provenance: TransportProvenance,
) -> Digest {
    Digest::from_parts(
        "aws-acm-discovery-response/v1",
        &[
            ("request", request_digest.as_str().to_owned()),
            ("page", page_number.to_string()),
            (
                "certificates",
                certificates
                    .iter()
                    .map(|certificate| certificate.projection.certificate_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "next_token",
                next_token.map_or_else(String::new, |token| {
                    token.token_digest().as_str().to_owned()
                }),
            ),
            ("bytes", response_bytes.to_string()),
            ("provenance", provenance.as_str().to_owned()),
        ],
    )
}

/// The only provider transport trait exposed by Layer 1.
pub trait AwsAcmTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_certificates(
        &mut self,
        request: &ListCertificatesRequest,
    ) -> Result<ListCertificatesResponse, AwsAcmTransportError>;

    fn search_certificates(
        &mut self,
        request: &SearchCertificatesRequest,
    ) -> Result<SearchCertificatesResponse, AwsAcmTransportError>;

    fn describe_certificate(
        &mut self,
        request: &DescribeCertificateRequest,
    ) -> Result<DescribeCertificateResponse, AwsAcmTransportError>;
}

pub struct AwsAcmProvider<T: AwsAcmTransport> {
    definition: AwsAcmProviderDefinition,
    transport: T,
}

impl<T: AwsAcmTransport> fmt::Debug for AwsAcmProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAcmProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: AwsAcmTransport> AwsAcmProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let definition = AwsAcmProviderDefinition::for_provenance(transport.provenance())?;
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &AwsAcmProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &AwsAcmProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn list_certificates(
        &mut self,
        request: &ListCertificatesRequest,
    ) -> Result<ListCertificatesResponse, AwsAcmTransportError> {
        self.transport.list_certificates(request)
    }

    pub fn search_certificates(
        &mut self,
        request: &SearchCertificatesRequest,
    ) -> Result<SearchCertificatesResponse, AwsAcmTransportError> {
        self.transport.search_certificates(request)
    }

    pub fn describe_certificate(
        &mut self,
        request: &DescribeCertificateRequest,
    ) -> Result<DescribeCertificateResponse, AwsAcmTransportError> {
        self.transport.describe_certificate(request)
    }
}

impl Default for AwsAcmProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked ACM provider definition")
    }
}

pub type BlockedEnvAwsAcmTransport = BlockedEnvTransport;
pub type RecordingAwsAcmTransport = RecordingTransport;
pub type FixtureAwsAcmTransport = FixtureTransport;
pub type LoopbackAwsAcmTransport = LoopbackTransport;

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsAcmTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_certificates(
        &mut self,
        _request: &ListCertificatesRequest,
    ) -> Result<ListCertificatesResponse, AwsAcmTransportError> {
        Err(AwsAcmTransportError::BlockedEnv)
    }

    fn search_certificates(
        &mut self,
        _request: &SearchCertificatesRequest,
    ) -> Result<SearchCertificatesResponse, AwsAcmTransportError> {
        Err(AwsAcmTransportError::BlockedEnv)
    }

    fn describe_certificate(
        &mut self,
        _request: &DescribeCertificateRequest,
    ) -> Result<DescribeCertificateResponse, AwsAcmTransportError> {
        Err(AwsAcmTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    list_responses: VecDeque<Result<ListCertificatesResponse, AwsAcmTransportError>>,
    search_responses: VecDeque<Result<SearchCertificatesResponse, AwsAcmTransportError>>,
    describe_responses: VecDeque<Result<DescribeCertificateResponse, AwsAcmTransportError>>,
    requests: Vec<RecordedRequest>,
    last_list_error: Option<AwsAcmTransportError>,
    last_search_error: Option<AwsAcmTransportError>,
    last_describe_error: Option<AwsAcmTransportError>,
}

impl RecordingTransport {
    pub fn push_list_response(
        &mut self,
        response: Result<ListCertificatesResponse, AwsAcmTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_search_response(
        &mut self,
        response: Result<SearchCertificatesResponse, AwsAcmTransportError>,
    ) {
        self.search_responses.push_back(response);
    }

    pub fn push_describe_response(
        &mut self,
        response: Result<DescribeCertificateResponse, AwsAcmTransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn clear_requests(&mut self) {
        self.requests.clear();
    }
}

impl AwsAcmTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_certificates(
        &mut self,
        request: &ListCertificatesRequest,
    ) -> Result<ListCertificatesResponse, AwsAcmTransportError> {
        self.requests.push(request.recorded_request());
        let response = self.list_responses.pop_front().unwrap_or_else(|| {
            self.last_list_error
                .clone()
                .map_or(Err(AwsAcmTransportError::InvalidResponse), Err)
        });
        if let Err(error) = &response {
            self.last_list_error = Some(error.clone());
        }
        response
    }

    fn search_certificates(
        &mut self,
        request: &SearchCertificatesRequest,
    ) -> Result<SearchCertificatesResponse, AwsAcmTransportError> {
        self.requests.push(request.recorded_request());
        let response = self.search_responses.pop_front().unwrap_or_else(|| {
            self.last_search_error
                .clone()
                .map_or(Err(AwsAcmTransportError::InvalidResponse), Err)
        });
        if let Err(error) = &response {
            self.last_search_error = Some(error.clone());
        }
        response
    }

    fn describe_certificate(
        &mut self,
        request: &DescribeCertificateRequest,
    ) -> Result<DescribeCertificateResponse, AwsAcmTransportError> {
        self.requests.push(request.recorded_request());
        let response = self.describe_responses.pop_front().unwrap_or_else(|| {
            self.last_describe_error
                .clone()
                .map_or(Err(AwsAcmTransportError::InvalidResponse), Err)
        });
        if let Err(error) = &response {
            self.last_describe_error = Some(error.clone());
        }
        response
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsAcmCertificateScope,
    description: DescribeCertificateResponse,
}

impl FixtureTransport {
    pub fn for_scope(
        scope: &AwsAcmCertificateScope,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let input = CertificateDescriptionInput::issued(
            scope.certificate.arn().as_str(),
            scope.certificate.domain().as_str(),
            [scope.certificate.domain().as_str().to_owned()],
            observed_at,
            scope.certificate_revision,
        )?;
        Self::from_input(scope, input)
    }

    pub fn from_input(
        scope: &AwsAcmCertificateScope,
        input: CertificateDescriptionInput,
    ) -> Result<Self, ModelError> {
        let describe_request = DescribeCertificateRequest::for_scope(scope)?;
        let description = CertificateDescription::from_input(&input)?;
        let response = DescribeCertificateResponse::new(
            &describe_request,
            description,
            512,
            TransportProvenance::Fixture,
        )?;
        Ok(Self {
            scope: scope.clone(),
            description: response,
        })
    }

    fn summary(&self) -> CertificateSummary {
        CertificateSummary {
            projection: self.description.certificate.projection.clone(),
        }
    }

    fn list_response(
        &self,
        request: &ListCertificatesRequest,
    ) -> Result<ListCertificatesResponse, AwsAcmTransportError> {
        ListCertificatesResponse::new(
            request,
            vec![self.summary()],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsAcmTransportError::InvalidResponse)
    }

    fn search_response(
        &self,
        request: &SearchCertificatesRequest,
    ) -> Result<SearchCertificatesResponse, AwsAcmTransportError> {
        SearchCertificatesResponse::new(
            request,
            vec![self.summary()],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsAcmTransportError::InvalidResponse)
    }
}

impl AwsAcmTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_certificates(
        &mut self,
        request: &ListCertificatesRequest,
    ) -> Result<ListCertificatesResponse, AwsAcmTransportError> {
        if request.scope().digest() != self.scope.digest()
            || request.page_number() != 1
            || !request.filter().allows(&self.summary().projection)
        {
            return Err(AwsAcmTransportError::NotFound);
        }
        self.list_response(request)
    }

    fn search_certificates(
        &mut self,
        request: &SearchCertificatesRequest,
    ) -> Result<SearchCertificatesResponse, AwsAcmTransportError> {
        if request.scope().digest() != self.scope.digest()
            || request.page_number() != 1
            || !request.filter().allows(&self.summary().projection)
        {
            return Err(AwsAcmTransportError::NotFound);
        }
        self.search_response(request)
    }

    fn describe_certificate(
        &mut self,
        request: &DescribeCertificateRequest,
    ) -> Result<DescribeCertificateResponse, AwsAcmTransportError> {
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsAcmTransportError::NotFound);
        }
        Ok(self.description.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(
        scope: &AwsAcmCertificateScope,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            fixture: FixtureTransport::for_scope(scope, observed_at)?,
        })
    }
}

impl AwsAcmTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_certificates(
        &mut self,
        request: &ListCertificatesRequest,
    ) -> Result<ListCertificatesResponse, AwsAcmTransportError> {
        let response = self.fixture.list_certificates(request)?;
        ListCertificatesResponse::new(
            request,
            response.certificates,
            response.next_token,
            response.response_bytes,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsAcmTransportError::InvalidResponse)
    }

    fn search_certificates(
        &mut self,
        request: &SearchCertificatesRequest,
    ) -> Result<SearchCertificatesResponse, AwsAcmTransportError> {
        let response = self.fixture.search_certificates(request)?;
        SearchCertificatesResponse::new(
            request,
            response.certificates,
            response.next_token,
            response.response_bytes,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsAcmTransportError::InvalidResponse)
    }

    fn describe_certificate(
        &mut self,
        request: &DescribeCertificateRequest,
    ) -> Result<DescribeCertificateResponse, AwsAcmTransportError> {
        let response = self.fixture.describe_certificate(request)?;
        DescribeCertificateResponse::new(
            request,
            response.certificate,
            response.response_bytes,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsAcmTransportError::InvalidResponse)
    }
}
