use std::{collections::VecDeque, fmt};

use thiserror::Error;

use crate::error::{SodaQualityResultError, SodaTransportError};
use crate::model::{
    Digest, MAX_AGGREGATE_ROWS, MAX_CHECKS, MAX_METRIC_VALUE, MAX_METRICS, MAX_RESPONSE_BYTES,
    ResourceBinding, Revision, SodaCheckProjection, SodaDatasetProjection, SodaEvidenceState,
    SodaOperation, SodaQualityHealthProjection, SodaQualityScope, SodaQualityStatus,
    SodaRequestReceipt, SodaScanProjection, TransportProvenance,
};
use crate::{API_REVISION, CONTRACT_VERSION, PROVIDER_ID};

pub type ProviderResult<T> = std::result::Result<T, SodaProviderError>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaProviderReadKind {
    Dataset,
    Check,
    Scan,
    QualityHealth,
}

impl SodaProviderReadKind {
    #[must_use]
    pub const fn operation(self) -> SodaOperation {
        match self {
            Self::Dataset => SodaOperation::DatasetRead,
            Self::Check => SodaOperation::CheckRead,
            Self::Scan => SodaOperation::ScanRead,
            Self::QualityHealth => SodaOperation::QualityHealthRead,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaReadRequest {
    pub operation: SodaOperation,
    pub scope_digest: Digest,
    pub target_digest: Digest,
    pub revision_digest: Digest,
    pub page_size: u16,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub max_response_bytes: usize,
    pub redacted: bool,
}

impl SodaReadRequest {
    pub fn new(
        scope: &SodaQualityScope,
        operation: SodaOperation,
        target: &ResourceBinding,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        scope.validate()?;
        let target_digest = target.digest();
        let revision_digest = Digest::from_parts(
            "soda-read-revision-fence/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("target", target_digest.as_str().to_owned()),
                ("revision", target.revision().get().to_string()),
            ],
        );
        let request_digest = Digest::from_parts(
            "soda-read-request/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("scope", scope.digest().as_str().to_owned()),
                ("target", target_digest.as_str().to_owned()),
                ("revision", revision_digest.as_str().to_owned()),
                ("page_size", "1".to_owned()),
                ("max_response_bytes", MAX_RESPONSE_BYTES.to_string()),
            ],
        );
        let path_digest = Digest::from_parts(
            "soda-redacted-path/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("target_prefix", target_digest.as_str()[..16].to_owned()),
            ],
        );
        Ok(Self {
            operation,
            scope_digest: scope.digest().clone(),
            target_digest,
            revision_digest,
            page_size: 1,
            request_digest,
            path_digest,
            max_response_bytes: MAX_RESPONSE_BYTES,
            redacted: true,
        })
    }

    pub fn for_dataset(
        scope: &SodaQualityScope,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        Self::new(scope, SodaOperation::DatasetRead, scope.dataset())
    }

    pub fn for_check(
        scope: &SodaQualityScope,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        Self::new(scope, SodaOperation::CheckRead, scope.check())
    }

    pub fn for_scan(scope: &SodaQualityScope) -> std::result::Result<Self, SodaQualityResultError> {
        Self::new(scope, SodaOperation::ScanRead, scope.scan())
    }

    pub fn for_quality_health(
        scope: &SodaQualityScope,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        Self::new(scope, SodaOperation::QualityHealthRead, scope.metric())
    }

    pub(crate) fn validate(
        &self,
        scope: &SodaQualityScope,
        operation: SodaOperation,
    ) -> ProviderResult<()> {
        scope.validate().map_err(SodaProviderError::from_model)?;
        for digest in [
            &self.scope_digest,
            &self.target_digest,
            &self.revision_digest,
            &self.request_digest,
            &self.path_digest,
        ] {
            digest.validate().map_err(SodaProviderError::from_model)?;
        }
        if self.operation != operation
            || self.scope_digest != *scope.digest()
            || self.target_digest
                != match operation {
                    SodaOperation::DatasetRead => scope.dataset().digest(),
                    SodaOperation::CheckRead => scope.check().digest(),
                    SodaOperation::ScanRead => scope.scan().digest(),
                    SodaOperation::QualityHealthRead => scope.metric().digest(),
                }
            || self.page_size == 0
            || self.page_size > 1
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || !self.redacted
            || self.revision_digest != self.calculate_revision_digest(scope, operation)
            || self.request_digest != self.calculate_digest()
            || self.path_digest != self.calculate_path_digest()
        {
            return Err(SodaProviderError::InvalidRequest);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-read-request/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("max_response_bytes", self.max_response_bytes.to_string()),
            ],
        )
    }

    fn calculate_revision_digest(
        &self,
        scope: &SodaQualityScope,
        operation: SodaOperation,
    ) -> Digest {
        let target_revision = match operation {
            SodaOperation::DatasetRead => scope.dataset().revision(),
            SodaOperation::CheckRead => scope.check().revision(),
            SodaOperation::ScanRead => scope.scan().revision(),
            SodaOperation::QualityHealthRead => scope.metric().revision(),
        };
        Digest::from_parts(
            "soda-read-revision-fence/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("revision", target_revision.get().to_string()),
            ],
        )
    }

    fn calculate_path_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-redacted-path/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                (
                    "target_prefix",
                    self.target_digest.as_str()[..16].to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn receipt(
        &self,
        response_digest: Option<Digest>,
        response_bytes: usize,
        status_code: Option<u16>,
    ) -> SodaRequestReceipt {
        SodaRequestReceipt {
            operation: self.operation,
            scope_digest: self.scope_digest.clone(),
            target_digest: self.target_digest.clone(),
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest.clone(),
            response_digest,
            response_bytes,
            status_code,
            redacted: true,
        }
    }
}

pub type SodaDatasetRequest = SodaReadRequest;
pub type SodaCheckRequest = SodaReadRequest;
pub type SodaScanRequest = SodaReadRequest;
pub type SodaQualityHealthRequest = SodaReadRequest;
pub type DatasetRequest = SodaReadRequest;
pub type CheckRequest = SodaReadRequest;
pub type ScanRequest = SodaReadRequest;
pub type QualityHealthRequest = SodaReadRequest;

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaDatasetResponse {
    pub scope_digest: Digest,
    pub target_digest: Digest,
    pub revision_digest: Digest,
    pub row_count: u64,
    pub partition_count: u32,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub declared_digest: Option<Digest>,
    pub complete: bool,
    pub provenance: TransportProvenance,
}

impl SodaDatasetResponse {
    pub fn new(
        request: &SodaReadRequest,
        row_count: u64,
        partition_count: u32,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            target_digest: request.target_digest.clone(),
            revision_digest: request.revision_digest.clone(),
            row_count,
            partition_count,
            response_bytes,
            response_digest: Digest::from_text("unsealed-soda-dataset-response"),
            declared_digest: None,
            complete: true,
            provenance,
        };
        response.response_digest = response.calculate_digest();
        response.validate_for(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-dataset-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("row_count", self.row_count.to_string()),
                ("partition_count", self.partition_count.to_string()),
                ("response_bytes", self.response_bytes.to_string()),
                ("complete", self.complete.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = Some(declared_digest);
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.response_digest = self.calculate_digest();
        self
    }

    pub(crate) fn validate_for(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        validate_response_identity(
            &self.scope_digest,
            &self.target_digest,
            &self.revision_digest,
            &self.response_digest,
            self.declared_digest.as_ref(),
            request,
            self.response_bytes,
            self.complete,
        )?;
        if self.response_digest != self.calculate_digest() {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        if self.partition_count > 1_000_000 || self.row_count > MAX_AGGREGATE_ROWS {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaCheckResponse {
    pub scope_digest: Digest,
    pub target_digest: Digest,
    pub revision_digest: Digest,
    pub status: SodaQualityStatus,
    pub evaluated_rows: u64,
    pub failed_rows: u64,
    pub score_basis_points: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub declared_digest: Option<Digest>,
    pub complete: bool,
    pub provenance: TransportProvenance,
}

impl SodaCheckResponse {
    pub fn new(
        request: &SodaReadRequest,
        status: SodaQualityStatus,
        evaluated_rows: u64,
        failed_rows: u64,
        score_basis_points: u16,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            target_digest: request.target_digest.clone(),
            revision_digest: request.revision_digest.clone(),
            status,
            evaluated_rows,
            failed_rows,
            score_basis_points,
            response_bytes,
            response_digest: Digest::from_text("unsealed-soda-check-response"),
            declared_digest: None,
            complete: true,
            provenance,
        };
        response.response_digest = response.calculate_digest();
        response.validate_for(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-check-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("evaluated_rows", self.evaluated_rows.to_string()),
                ("failed_rows", self.failed_rows.to_string()),
                ("score", self.score_basis_points.to_string()),
                ("response_bytes", self.response_bytes.to_string()),
                ("complete", self.complete.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = Some(declared_digest);
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.response_digest = self.calculate_digest();
        self
    }

    pub(crate) fn validate_for(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        validate_response_identity(
            &self.scope_digest,
            &self.target_digest,
            &self.revision_digest,
            &self.response_digest,
            self.declared_digest.as_ref(),
            request,
            self.response_bytes,
            self.complete,
        )?;
        if self.response_digest != self.calculate_digest() {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        if self.evaluated_rows > MAX_AGGREGATE_ROWS
            || self.failed_rows > self.evaluated_rows
            || self.score_basis_points > 10_000
        {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaScanResponse {
    pub scope_digest: Digest,
    pub target_digest: Digest,
    pub revision_digest: Digest,
    pub status: SodaQualityStatus,
    pub check_count: u16,
    pub completed_at_digest: Digest,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub declared_digest: Option<Digest>,
    pub complete: bool,
    pub provenance: TransportProvenance,
}

impl SodaScanResponse {
    pub fn new(
        request: &SodaReadRequest,
        status: SodaQualityStatus,
        check_count: u16,
        completed_at: impl Into<String>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        let completed_at_digest =
            Digest::from_parts("soda-completed-at/v1", &[("value", completed_at.into())]);
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            target_digest: request.target_digest.clone(),
            revision_digest: request.revision_digest.clone(),
            status,
            check_count,
            completed_at_digest,
            response_bytes,
            response_digest: Digest::from_text("unsealed-soda-scan-response"),
            declared_digest: None,
            complete: true,
            provenance,
        };
        response.response_digest = response.calculate_digest();
        response.validate_for(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-scan-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("check_count", self.check_count.to_string()),
                ("completed_at", self.completed_at_digest.as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("complete", self.complete.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = Some(declared_digest);
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.response_digest = self.calculate_digest();
        self
    }

    pub(crate) fn validate_for(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        validate_response_identity(
            &self.scope_digest,
            &self.target_digest,
            &self.revision_digest,
            &self.response_digest,
            self.declared_digest.as_ref(),
            request,
            self.response_bytes,
            self.complete,
        )?;
        if self.response_digest != self.calculate_digest() {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        if usize::from(self.check_count) > MAX_CHECKS {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaQualityHealthResponse {
    pub scope_digest: Digest,
    pub target_digest: Digest,
    pub revision_digest: Digest,
    pub status: SodaQualityStatus,
    pub metric_value: u64,
    pub threshold: Option<u64>,
    pub metric_count: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub declared_digest: Option<Digest>,
    pub complete: bool,
    pub provenance: TransportProvenance,
}

impl SodaQualityHealthResponse {
    pub fn new(
        request: &SodaReadRequest,
        status: SodaQualityStatus,
        metric_value: u64,
        threshold: Option<u64>,
        metric_count: u16,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, SodaQualityResultError> {
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            target_digest: request.target_digest.clone(),
            revision_digest: request.revision_digest.clone(),
            status,
            metric_value,
            threshold,
            metric_count,
            response_bytes,
            response_digest: Digest::from_text("unsealed-soda-health-response"),
            declared_digest: None,
            complete: true,
            provenance,
        };
        response.response_digest = response.calculate_digest();
        response.validate_for(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-quality-health-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("metric_value", self.metric_value.to_string()),
                (
                    "threshold",
                    self.threshold
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("metric_count", self.metric_count.to_string()),
                ("response_bytes", self.response_bytes.to_string()),
                ("complete", self.complete.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = Some(declared_digest);
        self
    }

    #[must_use]
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self.response_digest = self.calculate_digest();
        self
    }

    pub(crate) fn validate_for(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        validate_response_identity(
            &self.scope_digest,
            &self.target_digest,
            &self.revision_digest,
            &self.response_digest,
            self.declared_digest.as_ref(),
            request,
            self.response_bytes,
            self.complete,
        )?;
        if self.response_digest != self.calculate_digest() {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        if usize::from(self.metric_count) > MAX_METRICS || self.metric_value > MAX_METRIC_VALUE {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

fn validate_response_identity(
    scope_digest: &Digest,
    target_digest: &Digest,
    revision_digest: &Digest,
    response_digest: &Digest,
    declared_digest: Option<&Digest>,
    request: &SodaReadRequest,
    response_bytes: usize,
    complete: bool,
) -> std::result::Result<(), SodaQualityResultError> {
    for digest in [
        scope_digest,
        target_digest,
        revision_digest,
        response_digest,
    ] {
        digest.validate()?;
    }
    if let Some(declared_digest) = declared_digest {
        declared_digest.validate()?;
        if declared_digest != response_digest {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
    }
    if scope_digest != &request.scope_digest
        || target_digest != &request.target_digest
        || revision_digest != &request.revision_digest
    {
        return Err(SodaQualityResultError::ScopeMismatch);
    }
    if response_bytes > request.max_response_bytes {
        return Err(SodaQualityResultError::ResponseTooLarge);
    }
    if !complete {
        return Err(SodaQualityResultError::PartialEvidence);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SodaProviderError {
    #[error("Soda provider request is invalid")]
    InvalidRequest,
    #[error("Soda provider request scope does not match")]
    ScopeMismatch,
    #[error("Soda provider SecretReference is revoked")]
    SecretRevoked,
    #[error("Soda provider response exceeded the byte bound")]
    ResponseTooLarge,
    #[error("Soda provider response was tampered with")]
    TamperedResponse,
    #[error("Soda provider response was partial")]
    PartialResponse,
    #[error("Soda transport failed during {operation:?}: {error}")]
    Transport {
        operation: SodaOperation,
        error: SodaTransportError,
    },
}

impl SodaProviderError {
    fn from_model(error: SodaQualityResultError) -> Self {
        match error {
            SodaQualityResultError::ScopeMismatch => Self::ScopeMismatch,
            SodaQualityResultError::ResponseTooLarge => Self::ResponseTooLarge,
            SodaQualityResultError::TamperedEvidence => Self::TamperedResponse,
            SodaQualityResultError::PartialEvidence => Self::PartialResponse,
            _ => Self::InvalidRequest,
        }
    }

    #[must_use]
    pub fn transport_error(&self) -> Option<&SodaTransportError> {
        match self {
            Self::Transport { error, .. } => Some(error),
            _ => None,
        }
    }
}

pub trait SodaTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_dataset(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaDatasetResponse, SodaTransportError>;

    fn read_check(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaCheckResponse, SodaTransportError>;

    fn read_scan(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaScanResponse, SodaTransportError>;

    fn read_quality_health(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaQualityHealthResponse, SodaTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub operations: Vec<SodaOperation>,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl SodaProviderDefinition {
    #[must_use]
    pub fn baseline() -> Self {
        let operations = vec![
            SodaOperation::DatasetRead,
            SodaOperation::CheckRead,
            SodaOperation::ScanRead,
            SodaOperation::QualityHealthRead,
        ];
        let provider_digest = Digest::from_parts(
            "soda-provider-definition/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_version", "1.0.0".to_owned()),
                ("api_revision", API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: "1.0.0".to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn validate(&self) -> ProviderResult<()> {
        let expected = Self::baseline();
        if self != &expected {
            Err(SodaProviderError::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

pub struct SodaProvider<T: SodaTransport> {
    transport: T,
    definition: SodaProviderDefinition,
    scope: SodaQualityScope,
    scope_digest: Digest,
    secret_reference: crate::SecretReference,
}

impl<T: SodaTransport> fmt::Debug for SodaProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SodaProvider")
            .field("definition", &self.definition)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("transport_provenance", &self.transport.provenance())
            .finish_non_exhaustive()
    }
}

impl<T: SodaTransport> SodaProvider<T> {
    pub fn new(
        transport: T,
        scope: &SodaQualityScope,
        secret_reference: crate::SecretReference,
    ) -> ProviderResult<Self> {
        scope.validate().map_err(SodaProviderError::from_model)?;
        secret_reference
            .validate(scope)
            .map_err(SodaProviderError::from_model)?;
        let definition = SodaProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            scope: scope.clone(),
            scope_digest: scope.digest().clone(),
            secret_reference,
        })
    }

    pub fn from_transport(
        scope: &SodaQualityScope,
        secret_reference: crate::SecretReference,
        transport: T,
    ) -> ProviderResult<Self> {
        Self::new(transport, scope, secret_reference)
    }

    #[must_use]
    pub fn definition(&self) -> &SodaProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn secret_reference(&self) -> &crate::SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn revoke_secret(&mut self) -> std::result::Result<(), SodaQualityResultError> {
        self.secret_reference.revoke()
    }

    pub fn restore_secret(&mut self) -> std::result::Result<(), SodaQualityResultError> {
        self.secret_reference.restore()
    }

    pub fn read_dataset(
        &mut self,
        request: &SodaReadRequest,
    ) -> ProviderResult<SodaDatasetResponse> {
        self.read(request, SodaOperation::DatasetRead, |transport, request| {
            transport.read_dataset(request)
        })
    }

    pub fn read_check(&mut self, request: &SodaReadRequest) -> ProviderResult<SodaCheckResponse> {
        self.read(request, SodaOperation::CheckRead, |transport, request| {
            transport.read_check(request)
        })
    }

    pub fn read_scan(&mut self, request: &SodaReadRequest) -> ProviderResult<SodaScanResponse> {
        self.read(request, SodaOperation::ScanRead, |transport, request| {
            transport.read_scan(request)
        })
    }

    pub fn read_quality_health(
        &mut self,
        request: &SodaReadRequest,
    ) -> ProviderResult<SodaQualityHealthResponse> {
        self.read(
            request,
            SodaOperation::QualityHealthRead,
            SodaTransport::read_quality_health,
        )
    }

    fn read<R, F>(
        &mut self,
        request: &SodaReadRequest,
        operation: SodaOperation,
        read: F,
    ) -> ProviderResult<R>
    where
        F: FnOnce(&mut T, &SodaReadRequest) -> std::result::Result<R, SodaTransportError>,
        R: ResponseValidation,
    {
        request.validate(&self.scope, operation)?;
        if request.scope_digest != self.scope_digest {
            return Err(SodaProviderError::ScopeMismatch);
        }
        if self.secret_reference.is_revoked() {
            return Err(SodaProviderError::SecretRevoked);
        }
        let response = read(&mut self.transport, request)
            .map_err(|error| SodaProviderError::Transport { operation, error })?;
        response
            .validate_for_request(request)
            .map_err(SodaProviderError::from_model)?;
        Ok(response)
    }
}

trait ResponseValidation {
    fn validate_for_request(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError>;
}

impl ResponseValidation for SodaDatasetResponse {
    fn validate_for_request(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        self.validate_for(request)
    }
}

impl ResponseValidation for SodaCheckResponse {
    fn validate_for_request(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        self.validate_for(request)
    }
}

impl ResponseValidation for SodaScanResponse {
    fn validate_for_request(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        self.validate_for(request)
    }
}

impl ResponseValidation for SodaQualityHealthResponse {
    fn validate_for_request(
        &self,
        request: &SodaReadRequest,
    ) -> std::result::Result<(), SodaQualityResultError> {
        self.validate_for(request)
    }
}

#[derive(Clone, Debug)]
struct SyntheticState {
    scope_digest: Digest,
    provenance: TransportProvenance,
    check_status: SodaQualityStatus,
    scan_status: SodaQualityStatus,
    health_status: SodaQualityStatus,
    completed_at: String,
    failures: VecDeque<SodaTransportError>,
    tamper_next: bool,
    partial_next: bool,
}

impl SyntheticState {
    fn new(scope: &SodaQualityScope, provenance: TransportProvenance) -> Self {
        Self {
            scope_digest: scope.digest().clone(),
            provenance,
            check_status: SodaQualityStatus::Pass,
            scan_status: SodaQualityStatus::Pass,
            health_status: SodaQualityStatus::Pass,
            completed_at: "layer1-fixture-time".to_owned(),
            failures: VecDeque::new(),
            tamper_next: false,
            partial_next: false,
        }
    }

    fn before_read(&mut self) -> std::result::Result<(), SodaTransportError> {
        self.failures.pop_front().map_or(Ok(()), Err)
    }

    fn take_tamper(&mut self) -> bool {
        let value = self.tamper_next;
        self.tamper_next = false;
        value
    }

    fn take_partial(&mut self) -> bool {
        let value = self.partial_next;
        self.partial_next = false;
        value
    }

    fn dataset(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaDatasetResponse, SodaTransportError> {
        self.before_read()?;
        let mut response = SodaDatasetResponse::new(request, 10_000, 4, 512, self.provenance)
            .map_err(|_| SodaTransportError::InvalidResponse)?;
        if self.take_partial() {
            response = response.with_complete(false);
        }
        if self.take_tamper() {
            response =
                response.with_declared_digest(Digest::from_text("tampered-dataset-response"));
        }
        Ok(response)
    }

    fn check(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaCheckResponse, SodaTransportError> {
        self.before_read()?;
        let (failed_rows, score) = match self.check_status {
            SodaQualityStatus::Pass => (0, 10_000),
            SodaQualityStatus::Fail => (73, 9_270),
            SodaQualityStatus::Warn => (8, 9_920),
            SodaQualityStatus::Unknown => (0, 0),
        };
        let mut response = SodaCheckResponse::new(
            request,
            self.check_status,
            10_000,
            failed_rows,
            score,
            768,
            self.provenance,
        )
        .map_err(|_| SodaTransportError::InvalidResponse)?;
        if self.take_partial() {
            response = response.with_complete(false);
        }
        if self.take_tamper() {
            response = response.with_declared_digest(Digest::from_text("tampered-check-response"));
        }
        Ok(response)
    }

    fn scan(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaScanResponse, SodaTransportError> {
        self.before_read()?;
        let mut response = SodaScanResponse::new(
            request,
            self.scan_status,
            1,
            self.completed_at.clone(),
            640,
            self.provenance,
        )
        .map_err(|_| SodaTransportError::InvalidResponse)?;
        if self.take_partial() {
            response = response.with_complete(false);
        }
        if self.take_tamper() {
            response = response.with_declared_digest(Digest::from_text("tampered-scan-response"));
        }
        Ok(response)
    }

    fn health(
        &mut self,
        request: &SodaReadRequest,
    ) -> std::result::Result<SodaQualityHealthResponse, SodaTransportError> {
        self.before_read()?;
        let mut response = SodaQualityHealthResponse::new(
            request,
            self.health_status,
            98,
            Some(95),
            1,
            704,
            self.provenance,
        )
        .map_err(|_| SodaTransportError::InvalidResponse)?;
        if self.take_partial() {
            response = response.with_complete(false);
        }
        if self.take_tamper() {
            response = response.with_declared_digest(Digest::from_text("tampered-health-response"));
        }
        Ok(response)
    }
}

macro_rules! synthetic_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            state: SyntheticState,
        }

        impl $name {
            #[must_use]
            pub fn for_scope(scope: &SodaQualityScope) -> Self {
                Self {
                    state: SyntheticState::new(scope, $provenance),
                }
            }

            #[must_use]
            pub fn with_check_status(mut self, status: SodaQualityStatus) -> Self {
                self.state.check_status = status;
                self
            }

            #[must_use]
            pub fn with_scan_status(mut self, status: SodaQualityStatus) -> Self {
                self.state.scan_status = status;
                self
            }

            #[must_use]
            pub fn with_health_status(mut self, status: SodaQualityStatus) -> Self {
                self.state.health_status = status;
                self
            }

            pub fn fail_next(&mut self, error: SodaTransportError) {
                self.state.failures.push_back(error);
            }

            pub fn tamper_next(&mut self) {
                self.state.tamper_next = true;
            }

            pub fn partial_next(&mut self) {
                self.state.partial_next = true;
            }
        }

        impl SodaTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                self.state.provenance
            }

            fn read_dataset(
                &mut self,
                request: &SodaReadRequest,
            ) -> std::result::Result<SodaDatasetResponse, SodaTransportError> {
                if request.scope_digest != self.state.scope_digest {
                    return Err(SodaTransportError::InvalidResponse);
                }
                self.state.dataset(request)
            }

            fn read_check(
                &mut self,
                request: &SodaReadRequest,
            ) -> std::result::Result<SodaCheckResponse, SodaTransportError> {
                if request.scope_digest != self.state.scope_digest {
                    return Err(SodaTransportError::InvalidResponse);
                }
                self.state.check(request)
            }

            fn read_scan(
                &mut self,
                request: &SodaReadRequest,
            ) -> std::result::Result<SodaScanResponse, SodaTransportError> {
                if request.scope_digest != self.state.scope_digest {
                    return Err(SodaTransportError::InvalidResponse);
                }
                self.state.scan(request)
            }

            fn read_quality_health(
                &mut self,
                request: &SodaReadRequest,
            ) -> std::result::Result<SodaQualityHealthResponse, SodaTransportError> {
                if request.scope_digest != self.state.scope_digest {
                    return Err(SodaTransportError::InvalidResponse);
                }
                self.state.health(request)
            }
        }
    };
}

synthetic_transport!(FixtureSodaTransport, TransportProvenance::Fixture);
synthetic_transport!(RecordingSodaTransport, TransportProvenance::Recording);
synthetic_transport!(FakeSodaTransport, TransportProvenance::Fake);
synthetic_transport!(LoopbackSodaTransport, TransportProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvSodaTransport;

impl SodaTransport for BlockedEnvSodaTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_dataset(
        &mut self,
        _request: &SodaReadRequest,
    ) -> std::result::Result<SodaDatasetResponse, SodaTransportError> {
        Err(SodaTransportError::BlockedEnv)
    }

    fn read_check(
        &mut self,
        _request: &SodaReadRequest,
    ) -> std::result::Result<SodaCheckResponse, SodaTransportError> {
        Err(SodaTransportError::BlockedEnv)
    }

    fn read_scan(
        &mut self,
        _request: &SodaReadRequest,
    ) -> std::result::Result<SodaScanResponse, SodaTransportError> {
        Err(SodaTransportError::BlockedEnv)
    }

    fn read_quality_health(
        &mut self,
        _request: &SodaReadRequest,
    ) -> std::result::Result<SodaQualityHealthResponse, SodaTransportError> {
        Err(SodaTransportError::BlockedEnv)
    }
}

pub type FixtureTransport = FixtureSodaTransport;
pub type RecordingTransport = RecordingSodaTransport;
pub type FakeTransport = FakeSodaTransport;
pub type LoopbackTransport = LoopbackSodaTransport;
pub type BlockedEnvTransport = BlockedEnvSodaTransport;

// Keep these projection imports part of the provider's typed surface for
// consumers that build fixture responses directly.
pub type SodaDatasetProjectionResult = SodaDatasetProjection;
pub type SodaCheckProjectionResult = SodaCheckProjection;
pub type SodaScanProjectionResult = SodaScanProjection;
pub type SodaQualityHealthProjectionResult = SodaQualityHealthProjection;
pub type SodaProviderEvidenceState = SodaEvidenceState;
pub type SodaProviderRevision = Revision;
