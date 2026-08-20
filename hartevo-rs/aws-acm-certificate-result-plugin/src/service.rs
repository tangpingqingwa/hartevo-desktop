//! Bounded AWS ACM certificate read/proposal/record/verify service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AcmOperation, AwsAcmCertificateScope, CertificateProjection, Digest, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_REQUESTS_PER_READ, ModelError, PermissionAction, PermissionFence, SecretReference,
    TransportProvenance,
};
use crate::provider::{
    AwsAcmProvider, AwsAcmProviderDefinition, AwsAcmTransport, AwsAcmTransportError,
    DescribeCertificateRequest, DescribeCertificateResponse, ListCertificatesRequest,
    ListCertificatesResponse, SearchCertificatesRequest, SearchCertificatesResponse,
};
use crate::{
    ACM_API_REVISION, ACM_CONSUMER_ID, ACM_PROVIDER_ID, ACM_PROVIDER_VERSION, ACM_SERVICE_ID,
    CONTRACT_DIGEST_INPUT, CONTRACT_SCHEMA, CONTRACT_VERSION, LAYER1_PERMISSIONS, PLUGIN_ID,
    PLUGIN_VERSION, contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractDocumentError {
    #[error("AWS ACM contract document is not valid JSON")]
    InvalidJson,
    #[error("AWS ACM contract document identity drifted")]
    IdentityDrift,
    #[error("AWS ACM contract document escalates Layer-1 authority")]
    AuthorityEscalation,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsAcmServiceError {
    #[error("AWS ACM registration is inactive")]
    RegistrationInactive,
    #[error("AWS ACM registration is revoked")]
    RegistrationRevoked,
    #[error("AWS ACM registration is reversed")]
    RegistrationReversed,
    #[error("AWS ACM SigV4 SecretReference is revoked or mismatched")]
    SecretReferenceRevoked,
    #[error("AWS ACM scope or permission digest does not verify")]
    ScopeMismatch,
    #[error("AWS ACM permission fence does not contain the requested read")]
    PermissionLoss,
    #[error("AWS ACM certificate ARN drifted")]
    ArnDrift,
    #[error("AWS ACM certificate domain or SAN scope drifted")]
    DomainDrift,
    #[error("AWS ACM certificate state is stale or eventually consistent")]
    StaleState,
    #[error("AWS ACM pagination cursor looped or was replayed")]
    PaginationLoop,
    #[error("AWS ACM bounded pagination was truncated")]
    PaginationLimit,
    #[error("AWS ACM provider response was partial")]
    PartialResponse,
    #[error("AWS ACM evidence was tampered")]
    TamperedEvidence,
    #[error("AWS ACM recording key conflicts with a prior proposal")]
    RecordingConflict,
    #[error("AWS ACM contract document drifted")]
    Contract(#[from] ContractDocumentError),
    #[error("AWS ACM provider definition drifted")]
    ProviderDefinition,
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] AwsAcmTransportError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<AcmOperation>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub production_tls_certification: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionReceipt {
    pub from: RegistrationState,
    pub to: RegistrationState,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_schema: String,
    pub contract_version: String,
    pub contract_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_version_digest: Digest,
    pub api_revision: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub certificate_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl AwsAcmRegistration {
    pub fn new(
        scope: &AwsAcmCertificateScope,
        secret: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsAcmProviderDefinition,
    ) -> Result<Self, AwsAcmServiceError> {
        validate_permission_fence(permission)?;
        provider
            .validate()
            .map_err(|_| AwsAcmServiceError::ProviderDefinition)?;
        secret.validate(scope)?;
        if permission.digest() != scope.permission_digest {
            return Err(AwsAcmServiceError::ScopeMismatch);
        }
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_schema: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_version_digest: Digest::from_text(CONTRACT_VERSION),
            contract_digest: contract_digest(),
            provider_id: ACM_PROVIDER_ID.to_owned(),
            provider_version: ACM_PROVIDER_VERSION.to_owned(),
            provider_version_digest: Digest::from_text(ACM_PROVIDER_VERSION),
            api_revision: ACM_API_REVISION.to_owned(),
            api_digest: provider.api_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: permission.digest(),
            scope_digest: scope.digest(),
            certificate_digest: scope.certificate_digest(),
            evidence_digest: Digest::zero(),
            secret_reference_digest: secret.digest().clone(),
            registration_revision: 1,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.evidence_digest = registration.compute_evidence_digest();
        registration.registration_digest = registration.compute_registration_digest();
        Ok(registration)
    }

    fn compute_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-registration-evidence/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                (
                    "contract_version",
                    self.contract_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("certificate", self.certificate_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
            ],
        )
    }

    fn compute_registration_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-registration/v1",
            &[
                ("plugin_id", self.plugin_id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                (
                    "plugin_version_digest",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract_schema", self.contract_schema.clone()),
                ("contract_version", self.contract_version.clone()),
                (
                    "contract_version_digest",
                    self.contract_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                (
                    "provider_version_digest",
                    self.provider_version_digest.as_str().to_owned(),
                ),
                ("api_revision", self.api_revision.clone()),
                ("api", self.api_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("certificate", self.certificate_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("state", format!("{:?}", self.state)),
            ],
        )
    }

    pub fn validate(
        &self,
        scope: &AwsAcmCertificateScope,
        secret: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsAcmProviderDefinition,
    ) -> Result<(), AwsAcmServiceError> {
        validate_permission_fence(permission)?;
        provider
            .validate()
            .map_err(|_| AwsAcmServiceError::ProviderDefinition)?;
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_schema != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.contract_version_digest != Digest::from_text(CONTRACT_VERSION)
            || self.contract_digest != contract_digest()
            || self.provider_id != ACM_PROVIDER_ID
            || self.provider_version != ACM_PROVIDER_VERSION
            || self.provider_version_digest != Digest::from_text(ACM_PROVIDER_VERSION)
            || self.api_revision != ACM_API_REVISION
            || self.api_digest != provider.api_digest
            || self.provider_digest != provider.provider_digest
            || self.permission_digest != permission.digest()
            || self.scope_digest != scope.digest()
            || self.certificate_digest != scope.certificate_digest()
            || self.secret_reference_digest != *secret.digest()
            || self.registration_revision == 0
            || self.evidence_digest != self.compute_evidence_digest()
            || self.registration_digest != self.compute_registration_digest()
        {
            return Err(AwsAcmServiceError::TamperedEvidence);
        }
        secret.validate(scope)?;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn certificate_digest(&self) -> &Digest {
        &self.certificate_digest
    }

    pub fn validate_integrity(&self) -> Result<(), AwsAcmServiceError> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_version_digest,
            &self.contract_digest,
            &self.provider_version_digest,
            &self.api_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.certificate_digest,
            &self.evidence_digest,
            &self.secret_reference_digest,
            &self.registration_digest,
        ] {
            digest.validate()?;
        }
        if self.registration_revision == 0
            || self.evidence_digest != self.compute_evidence_digest()
            || self.registration_digest != self.compute_registration_digest()
        {
            return Err(AwsAcmServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionReceipt, AwsAcmServiceError> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionReceipt, AwsAcmServiceError> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionReceipt, AwsAcmServiceError> {
        if self.state != RegistrationState::Reversed {
            return Err(match self.state {
                RegistrationState::Active => AwsAcmServiceError::RegistrationInactive,
                RegistrationState::Revoked => AwsAcmServiceError::RegistrationRevoked,
                RegistrationState::Reversed => AwsAcmServiceError::RegistrationReversed,
            });
        }
        self.transition(RegistrationState::Active)
    }

    fn transition(
        &mut self,
        next: RegistrationState,
    ) -> Result<RegistrationTransitionReceipt, AwsAcmServiceError> {
        let from = self.state;
        match (from, next) {
            (
                RegistrationState::Active,
                RegistrationState::Revoked | RegistrationState::Reversed,
            )
            | (RegistrationState::Reversed, RegistrationState::Active) => {}
            (RegistrationState::Revoked, _) => {
                return Err(AwsAcmServiceError::RegistrationRevoked);
            }
            (RegistrationState::Reversed, RegistrationState::Reversed) => {
                return Err(AwsAcmServiceError::RegistrationReversed);
            }
            (RegistrationState::Reversed, RegistrationState::Revoked) => {
                return Err(AwsAcmServiceError::RegistrationReversed);
            }
            (RegistrationState::Active, RegistrationState::Active) => {
                return Err(AwsAcmServiceError::RegistrationInactive);
            }
        }
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.state = next;
        self.registration_digest = self.compute_registration_digest();
        let transition_digest = Digest::from_parts(
            "aws-acm-registration-transition/v1",
            &[
                ("from", format!("{from:?}")),
                ("to", format!("{next:?}")),
                ("revision", self.registration_revision.to_string()),
                ("registration", self.registration_digest.as_str().to_owned()),
            ],
        );
        Ok(RegistrationTransitionReceipt {
            from,
            to: next,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
            reversible: true,
            revocable: true,
        })
    }
}

fn validate_permission_fence(permission: &PermissionFence) -> Result<(), AwsAcmServiceError> {
    if permission.revision.get() == 0
        || crate::model::PermissionId::new(permission.id.as_str().to_owned()).is_err()
    {
        return Err(AwsAcmServiceError::PermissionLoss);
    }
    for action in [
        PermissionAction::ListCertificates,
        PermissionAction::SearchCertificates,
        PermissionAction::DescribeCertificate,
    ] {
        if !permission.allows(action) {
            return Err(AwsAcmServiceError::PermissionLoss);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAcmReadRequest {
    List(ListCertificatesRequest),
    Search(SearchCertificatesRequest),
    Describe(DescribeCertificateRequest),
}

impl AwsAcmReadRequest {
    pub fn operation(&self) -> AcmOperation {
        match self {
            Self::List(_) => AcmOperation::ListCertificates,
            Self::Search(_) => AcmOperation::SearchCertificates,
            Self::Describe(_) => AcmOperation::DescribeCertificate,
        }
    }

    pub fn scope_digest(&self) -> Digest {
        match self {
            Self::List(request) => request.scope().digest(),
            Self::Search(request) => request.scope().digest(),
            Self::Describe(request) => request.scope().digest(),
        }
    }

    pub fn request_digest(&self) -> Digest {
        match self {
            Self::List(request) => request.request_digest().clone(),
            Self::Search(request) => request.request_digest().clone(),
            Self::Describe(request) => request.request_digest().clone(),
        }
    }
}

impl From<ListCertificatesRequest> for AwsAcmReadRequest {
    fn from(value: ListCertificatesRequest) -> Self {
        Self::List(value)
    }
}

impl From<SearchCertificatesRequest> for AwsAcmReadRequest {
    fn from(value: SearchCertificatesRequest) -> Self {
        Self::Search(value)
    }
}

impl From<DescribeCertificateRequest> for AwsAcmReadRequest {
    fn from(value: DescribeCertificateRequest) -> Self {
        Self::Describe(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateEvidenceState {
    Complete,
    Partial,
    AccessLoss,
    NotFound,
    ProviderUnknown,
    RegistrationRevoked,
}

impl CertificateEvidenceState {
    pub const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Complete)
    }

    pub const fn is_adoptable(self) -> bool {
        false
    }
}

pub type EvidenceState = CertificateEvidenceState;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    RegistrationRevoked,
    SecretReferenceRevoked,
    ScopeDrift,
    ArnDrift,
    DomainDrift,
    PaginationLoop,
    PaginationLimit,
    StaleState,
    PartialResponse,
    AccessLoss,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnv,
    ProviderUnknown,
    TamperedEvidence,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub reason: FailureReason,
    pub operation: AcmOperation,
    pub status_code: Option<u16>,
    pub attempt_count: u16,
    pub detail_digest: Digest,
}

impl FailureEvidence {
    fn typed(
        reason: FailureReason,
        operation: AcmOperation,
        status_code: Option<u16>,
        attempt_count: u16,
        detail: &str,
    ) -> Self {
        Self {
            reason,
            operation,
            status_code,
            attempt_count,
            detail_digest: Digest::from_text(detail),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub certificate_digest: Digest,
    pub request_digest: Digest,
    pub cost_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmRequestReceipt {
    pub operation: AcmOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub page_count: u16,
    pub request_count: u16,
    pub response_bytes: u64,
    pub raw_request_retained: bool,
    pub raw_response_retained: bool,
    pub raw_next_token_retained: bool,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl AwsAcmRequestReceipt {
    fn new(
        operation: AcmOperation,
        request_digest: Digest,
        response_digest: Digest,
        page_count: u16,
        request_count: u16,
        response_bytes: u64,
    ) -> Self {
        let receipt_digest = Digest::from_parts(
            "aws-acm-request-receipt/v1",
            &[
                ("operation", operation.api_name().to_owned()),
                ("request", request_digest.as_str().to_owned()),
                ("response", response_digest.as_str().to_owned()),
                ("pages", page_count.to_string()),
                ("requests", request_count.to_string()),
                ("bytes", response_bytes.to_string()),
            ],
        );
        Self {
            operation,
            request_digest,
            response_digest,
            page_count,
            request_count,
            response_bytes,
            raw_request_retained: false,
            raw_response_retained: false,
            raw_next_token_retained: false,
            redacted: true,
            receipt_digest,
        }
    }

    fn validate_integrity(&self) -> Result<(), AwsAcmServiceError> {
        if self.raw_request_retained
            || self.raw_response_retained
            || self.raw_next_token_retained
            || !self.redacted
            || self.receipt_digest
                != Digest::from_parts(
                    "aws-acm-request-receipt/v1",
                    &[
                        ("operation", self.operation.api_name().to_owned()),
                        ("request", self.request_digest.as_str().to_owned()),
                        ("response", self.response_digest.as_str().to_owned()),
                        ("pages", self.page_count.to_string()),
                        ("requests", self.request_count.to_string()),
                        ("bytes", self.response_bytes.to_string()),
                    ],
                )
        {
            return Err(AwsAcmServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmCostReceipt {
    pub bounded_read_count: u16,
    pub provider_reported_cost: bool,
    pub estimated_cost_units: u64,
    pub raw_cost_payload_retained: bool,
    pub redacted: bool,
    pub cost_digest: Digest,
}

impl AwsAcmCostReceipt {
    fn new(bounded_read_count: u16) -> Self {
        let cost_digest = Digest::from_parts(
            "aws-acm-cost-receipt/v1",
            &[
                ("read_count", bounded_read_count.to_string()),
                ("provider_reported", "false".to_owned()),
                ("estimated_cost_units", "0".to_owned()),
            ],
        );
        Self {
            bounded_read_count,
            provider_reported_cost: false,
            estimated_cost_units: 0,
            raw_cost_payload_retained: false,
            redacted: true,
            cost_digest,
        }
    }

    fn validate_integrity(&self) -> Result<(), AwsAcmServiceError> {
        if self.bounded_read_count > MAX_REQUESTS_PER_READ
            || self.provider_reported_cost
            || self.estimated_cost_units != 0
            || self.raw_cost_payload_retained
            || !self.redacted
            || self.cost_digest
                != Digest::from_parts(
                    "aws-acm-cost-receipt/v1",
                    &[
                        ("read_count", self.bounded_read_count.to_string()),
                        ("provider_reported", "false".to_owned()),
                        ("estimated_cost_units", "0".to_owned()),
                    ],
                )
        {
            return Err(AwsAcmServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmCertificateEvidence {
    pub service_id: String,
    pub operation: AcmOperation,
    pub state: CertificateEvidenceState,
    pub certificate: Option<CertificateProjection>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub request_receipt: AwsAcmRequestReceipt,
    pub cost_receipt: AwsAcmCostReceipt,
    pub failure: Option<FailureEvidence>,
    pub digests: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub outcome_adopted: bool,
}

impl AwsAcmCertificateEvidence {
    fn new(
        registration: &AwsAcmRegistration,
        provider: &AwsAcmProviderDefinition,
        operation: AcmOperation,
        state: CertificateEvidenceState,
        certificate: Option<CertificateProjection>,
        list_pages: u16,
        list_complete: bool,
        request_receipt: AwsAcmRequestReceipt,
        cost_receipt: AwsAcmCostReceipt,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut digests = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version_digest: Digest::from_text(CONTRACT_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: registration.permission_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            certificate_digest: registration.certificate_digest.clone(),
            request_digest: request_receipt.receipt_digest.clone(),
            cost_digest: cost_receipt.cost_digest.clone(),
            evidence_digest: Digest::zero(),
        };
        digests.evidence_digest = calculate_evidence_digest(
            operation,
            state,
            certificate.as_ref(),
            list_pages,
            list_complete,
            &request_receipt,
            &cost_receipt,
            failure.as_ref(),
            &digests,
            provenance,
        );
        Self {
            service_id: ACM_SERVICE_ID.to_owned(),
            operation,
            state,
            certificate,
            list_pages,
            list_complete,
            request_receipt,
            cost_receipt,
            failure,
            digests,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            outcome_adopted: false,
        }
    }

    pub fn validate_integrity(&self) -> Result<(), AwsAcmServiceError> {
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        if let Some(certificate) = &self.certificate {
            certificate.validate_integrity()?;
        }
        self.digests.contract_digest.validate()?;
        self.digests.plugin_version_digest.validate()?;
        self.digests.contract_version_digest.validate()?;
        self.digests.provider_digest.validate()?;
        self.digests.api_digest.validate()?;
        self.digests.permission_digest.validate()?;
        self.digests.scope_digest.validate()?;
        self.digests.certificate_digest.validate()?;
        self.digests.request_digest.validate()?;
        self.digests.cost_digest.validate()?;
        self.digests.evidence_digest.validate()?;
        if self.service_id != ACM_SERVICE_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.certification_claim
            || self.outcome_adopted
            || self.digests.request_digest != self.request_receipt.receipt_digest
            || self.digests.cost_digest != self.cost_receipt.cost_digest
            || self.digests.evidence_digest
                != calculate_evidence_digest(
                    self.operation,
                    self.state,
                    self.certificate.as_ref(),
                    self.list_pages,
                    self.list_complete,
                    &self.request_receipt,
                    &self.cost_receipt,
                    self.failure.as_ref(),
                    &self.digests,
                    self.provenance,
                )
        {
            return Err(AwsAcmServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

fn calculate_evidence_digest(
    operation: AcmOperation,
    state: CertificateEvidenceState,
    certificate: Option<&CertificateProjection>,
    list_pages: u16,
    list_complete: bool,
    request_receipt: &AwsAcmRequestReceipt,
    cost_receipt: &AwsAcmCostReceipt,
    failure: Option<&FailureEvidence>,
    digests: &EvidenceDigests,
    provenance: TransportProvenance,
) -> Digest {
    Digest::from_parts(
        "aws-acm-certificate-evidence/v1",
        &[
            ("operation", operation.api_name().to_owned()),
            ("state", format!("{state:?}")),
            (
                "certificate",
                certificate.map_or_else(String::new, |value| {
                    value.certificate_digest.as_str().to_owned()
                }),
            ),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            (
                "request_receipt",
                request_receipt.receipt_digest.as_str().to_owned(),
            ),
            ("cost_receipt", cost_receipt.cost_digest.as_str().to_owned()),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    format!(
                        "{:?}:{}:{}",
                        value.reason,
                        value.status_code.map_or(0, u16::from),
                        value.detail_digest.as_str()
                    )
                }),
            ),
            (
                "plugin_version",
                digests.plugin_version_digest.as_str().to_owned(),
            ),
            (
                "contract_version",
                digests.contract_version_digest.as_str().to_owned(),
            ),
            ("contract", digests.contract_digest.as_str().to_owned()),
            ("provider", digests.provider_digest.as_str().to_owned()),
            ("api", digests.api_digest.as_str().to_owned()),
            ("permission", digests.permission_digest.as_str().to_owned()),
            ("scope", digests.scope_digest.as_str().to_owned()),
            (
                "certificate_scope",
                digests.certificate_digest.as_str().to_owned(),
            ),
            ("provenance", provenance.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAcmCertificateProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub certificate_digest: Digest,
    pub mission: crate::model::MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub evidence: AwsAcmCertificateEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub outcome_adopted: bool,
}

impl AwsAcmCertificateProposal {
    fn new(
        registration: &AwsAcmRegistration,
        scope: &AwsAcmCertificateScope,
        evidence: AwsAcmCertificateEvidence,
    ) -> Self {
        let mut proposal = Self {
            service_id: ACM_SERVICE_ID.to_owned(),
            consumer_id: ACM_CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            certificate_digest: registration.certificate_digest.clone(),
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            evidence,
            proposal_digest: Digest::zero(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            outcome_adopted: false,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-certificate-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("certificate", self.certificate_digest.as_str().to_owned()),
                (
                    "mission",
                    format!(
                        "{}:{}",
                        self.mission.id.as_str(),
                        self.mission.revision.get()
                    ),
                ),
                (
                    "project",
                    format!(
                        "{}:{}",
                        self.project.id.as_str(),
                        self.project.revision.get()
                    ),
                ),
                (
                    "work_product",
                    format!(
                        "{}:{}",
                        self.work_product.id.as_str(),
                        self.work_product.revision.get()
                    ),
                ),
                (
                    "evidence",
                    self.evidence.digests.evidence_digest.as_str().to_owned(),
                ),
                ("review_only", self.review_only.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<(), AwsAcmServiceError> {
        self.evidence.validate_integrity()?;
        if self.service_id != ACM_SERVICE_ID
            || self.consumer_id != ACM_CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.certification_claim
            || self.outcome_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(AwsAcmServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn state(&self) -> CertificateEvidenceState {
        self.evidence.state
    }

    pub fn certificate(&self) -> Option<&CertificateProjection> {
        self.evidence.certificate.as_ref()
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ScopeDigestMismatch,
    CertificateDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    ProviderUnknown,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "aws-acm-verification/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct AwsAcmCertificateService<T: AwsAcmTransport> {
    scope: AwsAcmCertificateScope,
    secret_reference: SecretReference,
    permission: PermissionFence,
    provider: AwsAcmProvider<T>,
    registration: AwsAcmRegistration,
    last_observed_at: Option<DateTime<Utc>>,
}

pub type AwsAcmService<T> = AwsAcmCertificateService<T>;

impl<T: AwsAcmTransport> fmt::Debug for AwsAcmCertificateService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAcmCertificateService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("permission_digest", &self.permission.digest())
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("last_observed_at", &self.last_observed_at)
            .finish()
    }
}

impl<T: AwsAcmTransport> AwsAcmCertificateService<T> {
    pub fn new(
        scope: AwsAcmCertificateScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsAcmProvider<T>,
    ) -> Result<Self, AwsAcmServiceError> {
        validate_contract_document()?;
        scope.validate()?;
        validate_permission_fence(&permission)?;
        secret_reference.validate(&scope)?;
        let registration = AwsAcmRegistration::new(
            &scope,
            &secret_reference,
            &permission,
            provider.definition(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            permission,
            provider,
            registration,
            last_observed_at: None,
        })
    }

    pub fn scope(&self) -> &AwsAcmCertificateScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn provider(&self) -> &AwsAcmProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsAcmProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsAcmRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsAcmRegistration {
        &mut self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn describe_capabilities(&self) -> AwsAcmCapabilities {
        AwsAcmCapabilities {
            service_id: ACM_SERVICE_ID.to_owned(),
            provider_id: ACM_PROVIDER_ID.to_owned(),
            consumer_id: ACM_CONSUMER_ID.to_owned(),
            operations: vec![
                AcmOperation::ListCertificates,
                AcmOperation::SearchCertificates,
                AcmOperation::DescribeCertificate,
            ],
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            production_tls_certification: false,
        }
    }

    pub fn describe_scope(&self) -> Digest {
        self.scope.digest()
    }

    pub fn register(&self) -> &AwsAcmRegistration {
        &self.registration
    }

    pub fn register_scope(&self) -> &AwsAcmRegistration {
        &self.registration
    }

    pub fn list_request(
        &self,
        filter: crate::model::ListCertificatesFilter,
    ) -> Result<ListCertificatesRequest, AwsAcmServiceError> {
        Ok(ListCertificatesRequest::new(&self.scope, filter, None)?)
    }

    pub fn search_request(
        &self,
        filter: crate::model::SearchCertificatesFilter,
    ) -> Result<SearchCertificatesRequest, AwsAcmServiceError> {
        Ok(SearchCertificatesRequest::new(&self.scope, filter, None)?)
    }

    pub fn describe_request(&self) -> Result<DescribeCertificateRequest, AwsAcmServiceError> {
        Ok(DescribeCertificateRequest::for_scope(&self.scope)?)
    }

    pub fn default_list_request(&self) -> Result<ListCertificatesRequest, AwsAcmServiceError> {
        self.list_request(crate::model::ListCertificatesFilter::all(MAX_PAGE_SIZE)?)
    }

    pub fn default_search_request(&self) -> Result<SearchCertificatesRequest, AwsAcmServiceError> {
        self.search_request(crate::model::SearchCertificatesFilter::for_domain(
            self.scope.certificate.domain().clone(),
            MAX_PAGE_SIZE,
        )?)
    }

    pub fn list_certificates(
        &mut self,
        filter: crate::model::ListCertificatesFilter,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        let request = self.list_request(filter)?;
        self.propose(request)
    }

    pub fn search_certificates(
        &mut self,
        filter: crate::model::SearchCertificatesFilter,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        let request = self.search_request(filter)?;
        self.propose(request)
    }

    pub fn describe_certificate(
        &mut self,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        let request = self.describe_request()?;
        self.propose(request)
    }

    pub fn read<R: Into<AwsAcmReadRequest>>(
        &mut self,
        request: R,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        self.propose(request)
    }

    pub fn read_bounded<R: Into<AwsAcmReadRequest>>(
        &mut self,
        request: R,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        self.propose(request)
    }

    pub fn propose<R: Into<AwsAcmReadRequest>>(
        &mut self,
        request: R,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        let request = request.into();
        self.validate_request(&request)?;
        if self.registration.state != RegistrationState::Active {
            return Ok(self.failure_proposal(
                &request,
                CertificateEvidenceState::RegistrationRevoked,
                FailureReason::RegistrationRevoked,
                None,
                0,
                self.provider.provenance(),
            ));
        }
        if self.secret_reference.is_revoked() {
            return Ok(self.failure_proposal(
                &request,
                CertificateEvidenceState::RegistrationRevoked,
                FailureReason::SecretReferenceRevoked,
                None,
                0,
                self.provider.provenance(),
            ));
        }
        match request {
            AwsAcmReadRequest::List(request) => self.propose_list(request),
            AwsAcmReadRequest::Search(request) => self.propose_search(request),
            AwsAcmReadRequest::Describe(request) => self.propose_describe(request),
        }
    }

    fn validate_request(&self, request: &AwsAcmReadRequest) -> Result<(), AwsAcmServiceError> {
        if request.scope_digest() != self.scope.digest()
            || request.operation().permission().api_name().is_empty()
        {
            return Err(AwsAcmServiceError::ScopeMismatch);
        }
        if !self.permission.allows(request.operation().permission()) {
            return Err(AwsAcmServiceError::PermissionLoss);
        }
        self.registration.validate(
            &self.scope,
            &self.secret_reference,
            &self.permission,
            self.provider.definition(),
        )?;
        Ok(())
    }

    fn propose_list(
        &mut self,
        request: ListCertificatesRequest,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        self.propose_discovery(AcmOperation::ListCertificates, request.into())
    }

    fn propose_search(
        &mut self,
        request: SearchCertificatesRequest,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        self.propose_discovery(AcmOperation::SearchCertificates, request.into())
    }

    fn propose_discovery(
        &mut self,
        operation: AcmOperation,
        request: AwsAcmReadRequest,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        let mut page_request = request.clone();
        let mut pages = 0_u16;
        let mut request_count = 0_u16;
        let mut total_bytes = 0_u64;
        let mut seen_cursors = BTreeSet::new();
        let mut target: Option<CertificateProjection> = None;
        let mut response_digests = Vec::new();
        let mut list_complete = false;

        loop {
            if request_count >= MAX_REQUESTS_PER_READ {
                let receipt = self.discovery_receipt(
                    operation,
                    &request,
                    &response_digests,
                    pages,
                    request_count,
                    total_bytes,
                );
                return Ok(self.failure_proposal_with_receipt(
                    &request,
                    CertificateEvidenceState::Partial,
                    FailureReason::PaginationLimit,
                    None,
                    pages,
                    list_complete,
                    target,
                    receipt,
                    self.provider.provenance(),
                ));
            }
            request_count = request_count.saturating_add(1);
            let page_result = self.discovery_page(&page_request);
            let page = match page_result {
                Ok(page) => page,
                Err(error) => {
                    if error.is_retryable() && request_count < 3 {
                        continue;
                    }
                    let receipt = self.discovery_receipt(
                        operation,
                        &request,
                        &response_digests,
                        pages,
                        request_count,
                        total_bytes,
                    );
                    let state = if error.is_access_loss() {
                        CertificateEvidenceState::AccessLoss
                    } else if matches!(error, AwsAcmTransportError::NotFound) {
                        CertificateEvidenceState::NotFound
                    } else if matches!(
                        error,
                        AwsAcmTransportError::Partial | AwsAcmTransportError::InvalidResponse
                    ) {
                        CertificateEvidenceState::Partial
                    } else {
                        CertificateEvidenceState::ProviderUnknown
                    };
                    return Ok(self.failure_proposal_with_receipt(
                        &request,
                        state,
                        failure_reason_for_transport(&error),
                        error.status_code(),
                        pages,
                        false,
                        target,
                        receipt,
                        self.provider.provenance(),
                    ));
                }
            };
            pages = pages.saturating_add(1);
            let validation = match (&page_request, &page) {
                (AwsAcmReadRequest::List(request), DiscoveryPage::List(page)) => {
                    if page.provenance != self.provider.provenance() {
                        Err(FailureReason::ScopeDrift)
                    } else {
                        page.validate_for(request)
                            .map_err(|_| FailureReason::PartialResponse)
                    }
                }
                (AwsAcmReadRequest::Search(request), DiscoveryPage::Search(page)) => {
                    if page.provenance != self.provider.provenance() {
                        Err(FailureReason::ScopeDrift)
                    } else {
                        page.validate_for(request)
                            .map_err(|_| FailureReason::PartialResponse)
                    }
                }
                _ => Err(FailureReason::ScopeDrift),
            };
            if let Err(reason) = validation {
                let receipt = self.discovery_receipt(
                    operation,
                    &request,
                    &response_digests,
                    pages,
                    request_count,
                    total_bytes,
                );
                return Ok(self.failure_proposal_with_receipt(
                    &request,
                    CertificateEvidenceState::Partial,
                    reason,
                    None,
                    pages,
                    false,
                    target,
                    receipt,
                    self.provider.provenance(),
                ));
            }
            let (certificates, next_token, response_bytes, response_digest) = match page {
                DiscoveryPage::List(page) => (
                    page.certificates,
                    page.next_token,
                    page.response_bytes,
                    page.response_digest,
                ),
                DiscoveryPage::Search(page) => (
                    page.certificates,
                    page.next_token,
                    page.response_bytes,
                    page.response_digest,
                ),
            };
            total_bytes = total_bytes.saturating_add(response_bytes);
            response_digests.push(response_digest);
            for summary in certificates {
                let projection = summary.projection;
                let arn_matches =
                    projection.certificate_arn_digest == self.scope.certificate.arn_digest();
                if arn_matches {
                    if projection.domain_digest != self.scope.certificate.domain_digest()
                        || projection.san_digests != self.scope.certificate.san_digests()
                    {
                        let receipt = self.discovery_receipt(
                            operation,
                            &request,
                            &response_digests,
                            pages,
                            request_count,
                            total_bytes,
                        );
                        return Ok(self.failure_proposal_with_receipt(
                            &request,
                            CertificateEvidenceState::Partial,
                            FailureReason::DomainDrift,
                            None,
                            pages,
                            false,
                            target,
                            receipt,
                            self.provider.provenance(),
                        ));
                    }
                    if target.is_some() {
                        let receipt = self.discovery_receipt(
                            operation,
                            &request,
                            &response_digests,
                            pages,
                            request_count,
                            total_bytes,
                        );
                        return Ok(self.failure_proposal_with_receipt(
                            &request,
                            CertificateEvidenceState::Partial,
                            FailureReason::Replay,
                            None,
                            pages,
                            false,
                            target,
                            receipt,
                            self.provider.provenance(),
                        ));
                    }
                    target = Some(projection);
                }
            }
            if let Some(next_token) = next_token {
                if !seen_cursors.insert(next_token.token_digest().clone()) {
                    let receipt = self.discovery_receipt(
                        operation,
                        &request,
                        &response_digests,
                        pages,
                        request_count,
                        total_bytes,
                    );
                    return Ok(self.failure_proposal_with_receipt(
                        &request,
                        CertificateEvidenceState::Partial,
                        FailureReason::PaginationLoop,
                        None,
                        pages,
                        false,
                        target,
                        receipt,
                        self.provider.provenance(),
                    ));
                }
                if pages >= MAX_PAGES {
                    let receipt = self.discovery_receipt(
                        operation,
                        &request,
                        &response_digests,
                        pages,
                        request_count,
                        total_bytes,
                    );
                    return Ok(self.failure_proposal_with_receipt(
                        &request,
                        CertificateEvidenceState::Partial,
                        FailureReason::PaginationLimit,
                        None,
                        pages,
                        false,
                        target,
                        receipt,
                        self.provider.provenance(),
                    ));
                }
                page_request = match page_request {
                    AwsAcmReadRequest::List(request) => AwsAcmReadRequest::List(
                        request
                            .with_next_token(next_token)
                            .map_err(AwsAcmServiceError::Model)?,
                    ),
                    AwsAcmReadRequest::Search(request) => AwsAcmReadRequest::Search(
                        request
                            .with_next_token(next_token)
                            .map_err(AwsAcmServiceError::Model)?,
                    ),
                    AwsAcmReadRequest::Describe(_) => unreachable!("discovery cannot describe"),
                };
            } else {
                list_complete = true;
                break;
            }
        }

        let receipt = self.discovery_receipt(
            operation,
            &request,
            &response_digests,
            pages,
            request_count,
            total_bytes,
        );
        let Some(target) = target else {
            return Ok(self.failure_proposal_with_receipt(
                &request,
                CertificateEvidenceState::NotFound,
                FailureReason::NotFound,
                Some(404),
                pages,
                list_complete,
                None,
                receipt,
                self.provider.provenance(),
            ));
        };
        let describe_request = DescribeCertificateRequest::for_scope(&self.scope)?;
        let description = match self.read_describe_response(&describe_request, &mut request_count) {
            Ok(response) => response,
            Err(error) => {
                let receipt = self.discovery_receipt(
                    operation,
                    &request,
                    &response_digests,
                    pages,
                    request_count,
                    total_bytes,
                );
                let state = if error.is_access_loss() {
                    CertificateEvidenceState::AccessLoss
                } else if matches!(error, AwsAcmTransportError::NotFound) {
                    CertificateEvidenceState::NotFound
                } else if matches!(
                    error,
                    AwsAcmTransportError::Partial | AwsAcmTransportError::InvalidResponse
                ) {
                    CertificateEvidenceState::Partial
                } else {
                    CertificateEvidenceState::ProviderUnknown
                };
                return Ok(self.failure_proposal_with_receipt(
                    &request,
                    state,
                    failure_reason_for_transport(&error),
                    error.status_code(),
                    pages,
                    list_complete,
                    Some(target),
                    receipt,
                    self.provider.provenance(),
                ));
            }
        };
        let description = match description.validate_for(&describe_request) {
            Ok(()) => description,
            Err(_) => {
                return Ok(self.failure_proposal_with_receipt(
                    &request,
                    CertificateEvidenceState::Partial,
                    FailureReason::PartialResponse,
                    None,
                    pages,
                    list_complete,
                    Some(target),
                    receipt,
                    self.provider.provenance(),
                ));
            }
        };
        let projected = description.certificate.projection;
        if let Err(reason) = self.validate_projection(&projected, Some(&target)) {
            return Ok(self.failure_proposal_with_receipt(
                &request,
                CertificateEvidenceState::Partial,
                reason,
                None,
                pages,
                list_complete,
                Some(projected),
                receipt,
                self.provider.provenance(),
            ));
        }
        let response_digest = Digest::from_parts(
            "aws-acm-discovery-and-describe/v1",
            &[
                (
                    "discovery",
                    response_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("describe", projected.certificate_digest.as_str().to_owned()),
            ],
        );
        let receipt = Self::discovery_receipt_with_response(
            operation,
            &request,
            response_digest,
            pages,
            request_count,
            total_bytes,
        );
        let cost_receipt = AwsAcmCostReceipt::new(request_count);
        let evidence = AwsAcmCertificateEvidence::new(
            &self.registration,
            self.provider.definition(),
            operation,
            CertificateEvidenceState::Complete,
            Some(projected.clone()),
            pages,
            list_complete,
            receipt,
            cost_receipt,
            None,
            self.provider.provenance(),
        );
        self.last_observed_at = Some(projected.observed_at);
        Ok(AwsAcmCertificateProposal::new(
            &self.registration,
            &self.scope,
            evidence,
        ))
    }

    fn propose_describe(
        &mut self,
        request: DescribeCertificateRequest,
    ) -> Result<AwsAcmCertificateProposal, AwsAcmServiceError> {
        let mut request_count = 0_u16;
        let response = loop {
            request_count = request_count.saturating_add(1);
            match self.provider.describe_certificate(&request) {
                Ok(response) => break response,
                Err(error) if error.is_retryable() && request_count < 3 => {}
                Err(error) => {
                    let receipt = AwsAcmRequestReceipt::new(
                        AcmOperation::DescribeCertificate,
                        request.request_digest().clone(),
                        Digest::from_text("no-response"),
                        0,
                        request_count,
                        0,
                    );
                    let state = if error.is_access_loss() {
                        CertificateEvidenceState::AccessLoss
                    } else if matches!(error, AwsAcmTransportError::NotFound) {
                        CertificateEvidenceState::NotFound
                    } else if matches!(
                        error,
                        AwsAcmTransportError::Partial | AwsAcmTransportError::InvalidResponse
                    ) {
                        CertificateEvidenceState::Partial
                    } else {
                        CertificateEvidenceState::ProviderUnknown
                    };
                    return Ok(self.failure_proposal_with_receipt(
                        &AwsAcmReadRequest::Describe(request.clone()),
                        state,
                        failure_reason_for_transport(&error),
                        error.status_code(),
                        0,
                        true,
                        None,
                        receipt,
                        self.provider.provenance(),
                    ));
                }
            }
        };
        if response.provenance != self.provider.provenance()
            || response.validate_for(&request).is_err()
        {
            let receipt = AwsAcmRequestReceipt::new(
                AcmOperation::DescribeCertificate,
                request.request_digest().clone(),
                response.response_digest.clone(),
                1,
                request_count,
                response.response_bytes,
            );
            return Ok(self.failure_proposal_with_receipt(
                &AwsAcmReadRequest::Describe(request),
                CertificateEvidenceState::Partial,
                FailureReason::PartialResponse,
                None,
                0,
                true,
                None,
                receipt,
                self.provider.provenance(),
            ));
        }
        let projected = response.certificate.projection;
        if let Err(reason) = self.validate_projection(&projected, None) {
            let receipt = AwsAcmRequestReceipt::new(
                AcmOperation::DescribeCertificate,
                request.request_digest().clone(),
                response.response_digest.clone(),
                1,
                request_count,
                response.response_bytes,
            );
            return Ok(self.failure_proposal_with_receipt(
                &AwsAcmReadRequest::Describe(request),
                CertificateEvidenceState::Partial,
                reason,
                None,
                0,
                true,
                Some(projected),
                receipt,
                self.provider.provenance(),
            ));
        }
        let receipt = AwsAcmRequestReceipt::new(
            AcmOperation::DescribeCertificate,
            request.request_digest().clone(),
            response.response_digest,
            1,
            request_count,
            response.response_bytes,
        );
        let cost_receipt = AwsAcmCostReceipt::new(request_count);
        let evidence = AwsAcmCertificateEvidence::new(
            &self.registration,
            self.provider.definition(),
            AcmOperation::DescribeCertificate,
            CertificateEvidenceState::Complete,
            Some(projected.clone()),
            0,
            true,
            receipt,
            cost_receipt,
            None,
            self.provider.provenance(),
        );
        self.last_observed_at = Some(projected.observed_at);
        Ok(AwsAcmCertificateProposal::new(
            &self.registration,
            &self.scope,
            evidence,
        ))
    }

    fn discovery_page(
        &mut self,
        request: &AwsAcmReadRequest,
    ) -> Result<DiscoveryPage, AwsAcmTransportError> {
        match request {
            AwsAcmReadRequest::List(request) => self
                .provider
                .list_certificates(request)
                .map(DiscoveryPage::List),
            AwsAcmReadRequest::Search(request) => self
                .provider
                .search_certificates(request)
                .map(DiscoveryPage::Search),
            AwsAcmReadRequest::Describe(_) => Err(AwsAcmTransportError::InvalidResponse),
        }
    }

    fn read_describe_response(
        &mut self,
        request: &DescribeCertificateRequest,
        request_count: &mut u16,
    ) -> Result<DescribeCertificateResponse, AwsAcmTransportError> {
        if *request_count >= MAX_REQUESTS_PER_READ {
            return Err(AwsAcmTransportError::Partial);
        }
        *request_count = request_count.saturating_add(1);
        loop {
            match self.provider.describe_certificate(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.is_retryable() && *request_count < 3 => {
                    *request_count = request_count.saturating_add(1);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn validate_projection(
        &self,
        projection: &CertificateProjection,
        discovered: Option<&CertificateProjection>,
    ) -> Result<(), FailureReason> {
        projection
            .validate_integrity()
            .map_err(|_| FailureReason::TamperedEvidence)?;
        if projection.certificate_arn_digest != self.scope.certificate.arn_digest() {
            return Err(FailureReason::ArnDrift);
        }
        if projection.domain_digest != self.scope.certificate.domain_digest()
            || projection.san_digests != self.scope.certificate.san_digests()
        {
            return Err(FailureReason::DomainDrift);
        }
        if projection.certificate_revision != self.scope.certificate_revision {
            return Err(FailureReason::StaleState);
        }
        if let Some(discovered) = discovered {
            if projection.certificate_revision != discovered.certificate_revision
                || projection.status != discovered.status
                || projection.certificate_digest != discovered.certificate_digest
            {
                return Err(FailureReason::StaleState);
            }
        }
        if let Some(last_observed_at) = self.last_observed_at
            && projection.observed_at < last_observed_at
        {
            return Err(FailureReason::StaleState);
        }
        Ok(())
    }

    fn discovery_receipt(
        &self,
        operation: AcmOperation,
        request: &AwsAcmReadRequest,
        response_digests: &[Digest],
        pages: u16,
        request_count: u16,
        response_bytes: u64,
    ) -> AwsAcmRequestReceipt {
        Self::discovery_receipt_with_response(
            operation,
            request,
            Digest::from_parts(
                "aws-acm-discovery-responses/v1",
                &[
                    (
                        "responses",
                        response_digests
                            .iter()
                            .map(|digest| digest.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                    (
                        "registration",
                        self.registration.registration_digest.as_str().to_owned(),
                    ),
                ],
            ),
            pages,
            request_count,
            response_bytes,
        )
    }

    fn discovery_receipt_with_response(
        operation: AcmOperation,
        request: &AwsAcmReadRequest,
        response_digest: Digest,
        pages: u16,
        request_count: u16,
        response_bytes: u64,
    ) -> AwsAcmRequestReceipt {
        AwsAcmRequestReceipt::new(
            operation,
            request.request_digest(),
            response_digest,
            pages,
            request_count,
            response_bytes,
        )
    }

    fn failure_proposal(
        &self,
        request: &AwsAcmReadRequest,
        state: CertificateEvidenceState,
        reason: FailureReason,
        status_code: Option<u16>,
        pages: u16,
        provenance: TransportProvenance,
    ) -> AwsAcmCertificateProposal {
        let receipt = AwsAcmRequestReceipt::new(
            request.operation(),
            request.request_digest(),
            Digest::from_text("no-response"),
            pages,
            0,
            0,
        );
        self.failure_proposal_with_receipt(
            request,
            state,
            reason,
            status_code,
            pages,
            false,
            None,
            receipt,
            provenance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_proposal_with_receipt(
        &self,
        request: &AwsAcmReadRequest,
        state: CertificateEvidenceState,
        reason: FailureReason,
        status_code: Option<u16>,
        pages: u16,
        list_complete: bool,
        certificate: Option<CertificateProjection>,
        request_receipt: AwsAcmRequestReceipt,
        provenance: TransportProvenance,
    ) -> AwsAcmCertificateProposal {
        let failure = FailureEvidence::typed(
            reason,
            request.operation(),
            status_code,
            request_receipt.request_count,
            &format!("{reason:?}"),
        );
        let evidence = AwsAcmCertificateEvidence::new(
            &self.registration,
            self.provider.definition(),
            request.operation(),
            state,
            certificate,
            pages,
            list_complete,
            request_receipt,
            AwsAcmCostReceipt::new(0),
            Some(failure),
            provenance,
        );
        AwsAcmCertificateProposal::new(&self.registration, &self.scope, evidence)
    }

    pub fn verify(&self, proposal: &AwsAcmCertificateProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if self.registration.state != RegistrationState::Active {
            failures.push(match self.registration.state {
                RegistrationState::Active => VerificationFailure::RegistrationInactive,
                RegistrationState::Revoked => VerificationFailure::RegistrationRevoked,
                RegistrationState::Reversed => VerificationFailure::RegistrationInactive,
            });
        }
        if proposal.registration_digest != self.registration.registration_digest {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != self.scope.digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.certificate_digest != self.scope.certificate_digest() {
            failures.push(VerificationFailure::CertificateDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state() {
            CertificateEvidenceState::Complete => {}
            CertificateEvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            CertificateEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            CertificateEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationRevoked);
            }
            CertificateEvidenceState::Partial | CertificateEvidenceState::NotFound => {
                failures.push(VerificationFailure::PartialEvidence);
            }
        }
        failures.sort();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state() == CertificateEvidenceState::Complete,
            failures,
        )
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsAcmCertificateProposal,
    ) -> Result<VerificationReport, AwsAcmServiceError> {
        let report = self.verify(proposal);
        if !report.valid {
            return Err(AwsAcmServiceError::TamperedEvidence);
        }
        Ok(report)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, AwsAcmServiceError> {
        self.registration.revoke()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, AwsAcmServiceError> {
        self.registration.reverse()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, AwsAcmServiceError> {
        self.registration.restore()
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }

    pub fn consumer(&self) -> Result<crate::consumer::MissionAwsAcmConsumer, AwsAcmServiceError> {
        crate::consumer::MissionAwsAcmConsumer::new(self.scope.clone(), self.registration.clone())
            .map_err(|_| AwsAcmServiceError::RegistrationInactive)
    }
}

#[derive(Clone, Debug)]
enum DiscoveryPage {
    List(ListCertificatesResponse),
    Search(SearchCertificatesResponse),
}

fn failure_reason_for_transport(error: &AwsAcmTransportError) -> FailureReason {
    match error {
        AwsAcmTransportError::BlockedEnv => FailureReason::BlockedEnv,
        AwsAcmTransportError::BadRequest => FailureReason::BadRequest,
        AwsAcmTransportError::Unauthorized => FailureReason::Unauthorized,
        AwsAcmTransportError::Forbidden => FailureReason::Forbidden,
        AwsAcmTransportError::NotFound => FailureReason::NotFound,
        AwsAcmTransportError::RateLimited { .. } => FailureReason::RateLimited,
        AwsAcmTransportError::ServerError { .. } => FailureReason::ServerFailure,
        AwsAcmTransportError::Timeout => FailureReason::Timeout,
        AwsAcmTransportError::AccessLost => FailureReason::AccessLoss,
        AwsAcmTransportError::Partial | AwsAcmTransportError::InvalidResponse => {
            FailureReason::PartialResponse
        }
    }
}

fn validate_contract_document() -> Result<(), AwsAcmServiceError> {
    let document = serde_json::from_str::<serde_json::Value>(crate::CONTRACT_JSON)
        .map_err(|_| ContractDocumentError::InvalidJson)?;
    let identity = document
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(CONTRACT_SCHEMA)
        && document
            .get("contractVersion")
            .and_then(serde_json::Value::as_str)
            == Some(CONTRACT_VERSION)
        && document.get("pluginId").and_then(serde_json::Value::as_str) == Some(PLUGIN_ID)
        && document
            .get("pluginVersion")
            .and_then(serde_json::Value::as_str)
            == Some(PLUGIN_VERSION)
        && document.get("layer").and_then(serde_json::Value::as_u64) == Some(1)
        && document
            .get("digestInput")
            .and_then(serde_json::Value::as_str)
            == Some(CONTRACT_DIGEST_INPUT)
        && document
            .get("contractDigest")
            .and_then(serde_json::Value::as_str)
            == Some(contract_digest().as_str());
    if !identity {
        return Err(ContractDocumentError::IdentityDrift.into());
    }
    let provider = document
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(ContractDocumentError::AuthorityEscalation)?;
    let consumer = document
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(ContractDocumentError::AuthorityEscalation)?;
    let authority = document
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or(ContractDocumentError::AuthorityEscalation)?;
    let authority_is_below_layer_one = [
        "externalWrites",
        "credentialResolution",
        "certificateRequest",
        "certificateImport",
        "certificateRenewal",
        "certificateDeletion",
        "certificateExport",
        "certificateBytes",
        "privateKeys",
        "validationMutation",
        "dnsMutation",
        "emailValidationEffect",
        "productionTlsCertification",
        "connected",
        "native",
        "firstParty",
        "kernelOutcomeAdoption",
    ]
    .into_iter()
    .all(|key| authority.get(key) == Some(&serde_json::Value::Bool(false)));
    if provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
        || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
        || provider.get("firstPartyEvidence") != Some(&serde_json::Value::Bool(false))
        || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
        || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        || !authority_is_below_layer_one
    {
        return Err(ContractDocumentError::AuthorityEscalation.into());
    }
    Ok(())
}
