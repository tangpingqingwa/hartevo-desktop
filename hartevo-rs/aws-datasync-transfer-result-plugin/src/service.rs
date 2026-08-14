use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsDataSyncTransferError, Result};
use crate::model::{
    AwsDataSyncScope, ConsentScope, Cursor, Digest, ExecutionProjection, PartialReason,
    PermissionSnapshot, ResponseReceipt, SecretReference, TaskProjection, TransferEvidenceState,
    TransportProvenance, contract_version_digest, validate_page_count, validate_page_size,
};
use crate::provider::{
    AwsDataSyncOperation, AwsDataSyncProvider, AwsDataSyncProviderDefinition, AwsDataSyncTransport,
    AwsDataSyncTransportError, DescribeTaskExecutionRequest, DescribeTaskRequest,
    ListTaskExecutionsRequest, ListTasksRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_FAILURES, MAX_PAGES, MAX_RECEIPTS,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-datasync-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

/// Version/contract/provider/API/permission/consent/scope/task/source/
/// destination/secret-bound registration. The secret handle itself is never
/// serialized or retained.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsDataSyncRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_api_revision: String,
    provider_api_digest: Digest,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsDataSyncScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsDataSyncRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsDataSyncScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsDataSyncProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_api_revision: provider.api_revision.clone(),
            provider_api_digest: provider.api_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-aws-datasync-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_api_revision(&self) -> &str {
        &self.provider_api_revision
    }

    pub fn provider_api_digest(&self) -> &Digest {
        &self.provider_api_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsDataSyncScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn task_digest(&self) -> Digest {
        self.scope.task().digest()
    }

    pub fn source_location_digest(&self) -> Digest {
        self.scope.source().digest()
    }

    pub fn destination_location_digest(&self) -> Digest {
        self.scope.destination().digest()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.provider_api_revision != PROVIDER_API_REVISION
            || self.provider_api_digest.validate().is_err()
            || self.provider_digest.validate().is_err()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsDataSyncTransferError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.consent.validate()?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsDataSyncTransferError::InvalidConsent);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDataSyncTransferError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDataSyncTransferError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDataSyncTransferError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-registration/v1",
            &[
                ("id", Digest::from_text(&self.id).as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider_api_revision", self.provider_api_revision.clone()),
                ("provider_api", self.provider_api_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("task", self.task_digest().as_str().to_owned()),
                ("source", self.source_location_digest().as_str().to_owned()),
                (
                    "destination",
                    self.destination_location_digest().as_str().to_owned(),
                ),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type AwsDataSyncTransferRegistration = AwsDataSyncRegistration;

impl fmt::Debug for AwsDataSyncRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDataSyncRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_release", &self.provider_release)
            .field("provider_api_digest", &self.provider_api_digest)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsDataSyncRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsDataSyncRegistration", 19)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerApiDigest", &self.provider_api_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("taskDigest", &self.task_digest())?;
        state.serialize_field("sourceLocationDigest", &self.source_location_digest())?;
        state.serialize_field(
            "destinationLocationDigest",
            &self.destination_location_digest(),
        )?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_execution_digest: Option<Digest>,
    pub max_pages: u16,
    pub page_size: u16,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl TransferEvidenceRequest {
    pub fn new(
        scope: &AwsDataSyncScope,
        expected_execution_digest: Option<Digest>,
        max_pages: u16,
        page_size: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_count(max_pages)?;
        validate_page_size(page_size)?;
        if let Some(digest) = &expected_execution_digest {
            digest.validate()?;
        }
        let request_digest = Digest::from_parts(
            "aws-datasync-transfer-evidence-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                (
                    "execution",
                    expected_execution_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("max_pages", max_pages.to_string()),
                ("page_size", page_size.to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            expected_execution_digest,
            max_pages,
            page_size,
            observed_at,
            request_digest,
        })
    }

    pub fn for_scope(
        scope: &AwsDataSyncScope,
        expected_execution_digest: Option<Digest>,
        max_pages: u16,
        page_size: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            scope,
            expected_execution_digest,
            max_pages,
            page_size,
            observed_at,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn validate_against(&self, scope: &AwsDataSyncScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(AwsDataSyncTransferError::ScopeMismatch);
        }
        validate_page_count(self.max_pages)?;
        validate_page_size(self.page_size)?;
        self.request_digest.validate()?;
        if self.request_digest != self.calculate_digest() {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-transfer-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "execution",
                    self.expected_execution_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("max_pages", self.max_pages.to_string()),
                ("page_size", self.page_size.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerError,
    Timeout,
    BlockedEnv,
    InvalidResponse,
    Transport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsDataSyncOperation,
    pub kind: ProviderFailureKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsDataSyncOperation, error: &AwsDataSyncTransportError) -> Self {
        let kind = match error {
            AwsDataSyncTransportError::BadRequest => ProviderFailureKind::BadRequest,
            AwsDataSyncTransportError::Unauthorized => ProviderFailureKind::Unauthorized,
            AwsDataSyncTransportError::Forbidden => ProviderFailureKind::Forbidden,
            AwsDataSyncTransportError::NotFound => ProviderFailureKind::NotFound,
            AwsDataSyncTransportError::Conflict => ProviderFailureKind::Conflict,
            AwsDataSyncTransportError::RateLimited { .. } => ProviderFailureKind::RateLimited,
            AwsDataSyncTransportError::ServerError { .. } => ProviderFailureKind::ServerError,
            AwsDataSyncTransportError::Timeout => ProviderFailureKind::Timeout,
            AwsDataSyncTransportError::BlockedEnv => ProviderFailureKind::BlockedEnv,
            AwsDataSyncTransportError::InvalidResponse => ProviderFailureKind::InvalidResponse,
            AwsDataSyncTransportError::Transport { .. } => ProviderFailureKind::Transport,
        };
        Self {
            operation,
            kind,
            status_code: error.status_code(),
            retryable: error.retryable(),
            diagnostic_digest: error.diagnostic_digest(),
        }
    }

    fn validate(&self) -> Result<()> {
        if let Some(status) = self.status_code
            && !(100..=599).contains(&status)
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        self.diagnostic_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryEvidence {
    pub operation: AwsDataSyncOperation,
    pub attempt: u8,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl RetryEvidence {
    fn validate(&self) -> Result<()> {
        if self.attempt == 0 {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        self.error_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub contract_digest: Digest,
    pub contract_version_digest: Digest,
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub provider_api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub task_digest: Option<Digest>,
    pub execution_digest: Option<Digest>,
    pub transfer_report_digest: Option<Digest>,
    pub request_digest: Digest,
    pub response_digests: Vec<Digest>,
}

impl EvidenceDigests {
    fn validate(&self) -> Result<()> {
        self.contract_digest.validate()?;
        self.contract_version_digest.validate()?;
        self.plugin_version_digest.validate()?;
        self.provider_digest.validate()?;
        self.provider_api_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.scope_digest.validate()?;
        self.task_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.execution_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.transfer_report_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.request_digest.validate()?;
        if self.response_digests.len() > MAX_RECEIPTS {
            return Err(AwsDataSyncTransferError::ResponseItemBoundExceeded);
        }
        for digest in &self.response_digests {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDataSyncTransferProposal {
    pub state: TransferEvidenceState,
    pub scope_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub request_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provider_api_digest: Digest,
    pub provider_revision: u64,
    pub provenance: TransportProvenance,
    pub task: Option<TaskProjection>,
    pub execution: Option<ExecutionProjection>,
    pub task_list_complete: bool,
    pub execution_list_complete: bool,
    pub task_pages_observed: u16,
    pub execution_pages_observed: u16,
    pub receipts: Vec<ResponseReceipt>,
    pub failures: Vec<FailureEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub evidence_digests: EvidenceDigests,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub adoptable: bool,
}

impl AwsDataSyncTransferProposal {
    pub const fn is_review_only(&self) -> bool {
        !self.adoptable
    }

    pub const fn can_be_adopted(&self) -> bool {
        self.adoptable
    }

    pub const fn status(&self) -> TransferEvidenceState {
        self.state
    }

    pub fn validate(&self, scope: &AwsDataSyncScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.mission_digest != scope.mission().digest()
            || self.project_digest != scope.project().digest()
            || self.work_product_digest != scope.work_product().digest()
            || self.provider_revision == 0
            || self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_authority
            || self.work_product_adoption
            || self.adoptable
            || self.provenance.is_native()
            || self.receipts.len() > MAX_RECEIPTS
            || self.failures.len() > MAX_FAILURES
            || self.retries.len() > MAX_FAILURES
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        self.evidence_digests.validate()?;
        if self.evidence_digests.contract_digest != Digest::from_text(CONTRACT_DIGEST)
            || self.evidence_digests.contract_version_digest != contract_version_digest()
            || self.evidence_digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence_digests.transfer_report_digest
                != self.execution.as_ref().and_then(|execution| {
                    execution
                        .transfer_report
                        .as_ref()
                        .map(|report| report.digest())
                })
            || self.evidence_digests.response_digests
                != self
                    .receipts
                    .iter()
                    .map(|receipt| receipt.response_digest.clone())
                    .collect::<Vec<_>>()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        if self.evidence_digests.scope_digest != self.scope_digest
            || self.evidence_digests.request_digest != self.request_digest
            || self.evidence_digests.provider_digest != self.provider_digest
            || self.evidence_digests.provider_api_digest != self.provider_api_digest
            || self.evidence_digests.task_digest != self.task.as_ref().map(TaskProjection::digest)
            || self.evidence_digests.execution_digest
                != self.execution.as_ref().map(ExecutionProjection::digest)
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        if let Some(task) = &self.task {
            task.validate_against(scope)?;
        }
        if let Some(execution) = &self.execution {
            execution.validate_against(scope)?;
        }
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        for failure in &self.failures {
            failure.validate()?;
        }
        for retry in &self.retries {
            retry.validate()?;
        }
        if self.task_pages_observed > MAX_PAGES || self.execution_pages_observed > MAX_PAGES {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        if matches!(self.state, TransferEvidenceState::Complete)
            && (self.task.is_none()
                || self.execution.is_none()
                || !self.task_list_complete
                || !self.execution_list_complete)
        {
            return Err(AwsDataSyncTransferError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-transfer-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("mission", self.mission_digest.as_str().to_owned()),
                ("project", self.project_digest.as_str().to_owned()),
                ("work_product", self.work_product_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("provider_api", self.provider_api_digest.as_str().to_owned()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "task",
                    self.task
                        .as_ref()
                        .map_or_else(String::new, |task| task.digest().as_str().to_owned()),
                ),
                (
                    "execution",
                    self.execution
                        .as_ref()
                        .map_or_else(String::new, |execution| {
                            execution.digest().as_str().to_owned()
                        }),
                ),
                ("task_complete", self.task_list_complete.to_string()),
                (
                    "execution_complete",
                    self.execution_list_complete.to_string(),
                ),
                ("task_pages", self.task_pages_observed.to_string()),
                ("execution_pages", self.execution_pages_observed.to_string()),
                (
                    "receipts",
                    self.receipts
                        .iter()
                        .map(ResponseReceipt::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "failures",
                    self.failures
                        .iter()
                        .map(|failure| failure.diagnostic_digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "retries",
                    self.retries
                        .iter()
                        .map(|retry| retry.error_digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "contract_digest",
                    self.evidence_digests.contract_digest.as_str().to_owned(),
                ),
                (
                    "contract_version_digest",
                    self.evidence_digests
                        .contract_version_digest
                        .as_str()
                        .to_owned(),
                ),
                (
                    "plugin_version_digest",
                    self.evidence_digests
                        .plugin_version_digest
                        .as_str()
                        .to_owned(),
                ),
                (
                    "permission_digest",
                    self.evidence_digests.permission_digest.as_str().to_owned(),
                ),
                (
                    "consent_digest",
                    self.evidence_digests.consent_digest.as_str().to_owned(),
                ),
                (
                    "transfer_report_digest",
                    self.evidence_digests
                        .transfer_report_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "response_digests",
                    self.evidence_digests
                        .response_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datasync-transfer-proposal/v1",
            &[
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub adoption_authority: bool,
    pub reasons: Vec<Digest>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn valid(proposal: &AwsDataSyncTransferProposal) -> Self {
        Self::from_parts(
            true,
            proposal.state.is_review_eligible(),
            Vec::new(),
            proposal,
        )
    }

    fn invalid(reasons: Vec<Digest>, proposal: &AwsDataSyncTransferProposal) -> Self {
        Self::from_parts(false, false, reasons, proposal)
    }

    fn from_parts(
        valid: bool,
        review_eligible: bool,
        reasons: Vec<Digest>,
        proposal: &AwsDataSyncTransferProposal,
    ) -> Self {
        let verification_digest = Digest::from_parts(
            "aws-datasync-verification/v1",
            &[
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                ("valid", valid.to_string()),
                ("review", review_eligible.to_string()),
                (
                    "reasons",
                    reasons
                        .iter()
                        .map(|reason| reason.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            adoption_authority: false,
            reasons,
            verification_digest,
        }
    }
}

pub struct AwsDataSyncTransferService<T> {
    scope: AwsDataSyncScope,
    secret_reference: SecretReference,
    consent: ConsentScope,
    provider: AwsDataSyncProvider<T>,
    registration: AwsDataSyncRegistration,
}

impl<T: AwsDataSyncTransport> fmt::Debug for AwsDataSyncTransferService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDataSyncTransferService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("consent", &self.consent)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: AwsDataSyncTransport> AwsDataSyncTransferService<T> {
    pub fn new(
        scope: AwsDataSyncScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsDataSyncProvider<T>,
        _observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate(&scope)?;
        consent.validate()?;
        let permission_snapshot = PermissionSnapshot::for_layer_one(1);
        let registration = AwsDataSyncRegistration::new(
            "aws-datasync-transfer-registration",
            scope.clone(),
            secret_reference.clone(),
            permission_snapshot,
            consent.clone(),
            provider.definition(),
            1,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            consent,
            provider,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsDataSyncScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn provider(&self) -> &AwsDataSyncProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsDataSyncProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsDataSyncRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsDataSyncRegistration {
        &mut self.registration
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                AwsDataSyncOperation::DescribeTask.as_str().to_owned(),
                AwsDataSyncOperation::DescribeTaskExecution
                    .as_str()
                    .to_owned(),
                AwsDataSyncOperation::ListTasks.as_str().to_owned(),
                AwsDataSyncOperation::ListTaskExecutions.as_str().to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<TransferEvidenceRequest> {
        TransferEvidenceRequest::new(
            &self.scope,
            None,
            MAX_PAGES,
            crate::MAX_PAGE_SIZE,
            observed_at,
        )
    }

    pub fn request(
        &self,
        expected_execution_digest: Option<Digest>,
        max_pages: u16,
        page_size: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<TransferEvidenceRequest> {
        TransferEvidenceRequest::new(
            &self.scope,
            expected_execution_digest,
            max_pages,
            page_size,
            observed_at,
        )
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.secret_reference.revoke();
        self.registration.secret_reference.revoke();
        Ok(())
    }

    pub fn propose(
        &mut self,
        request: TransferEvidenceRequest,
    ) -> Result<AwsDataSyncTransferProposal> {
        request.validate_against(&self.scope)?;
        if self.secret_reference.is_revoked() {
            return Err(AwsDataSyncTransferError::SecretRevoked);
        }
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsDataSyncTransferError::RegistrationRevoked);
        }
        if !self.consent.is_active_at(request.observed_at) {
            return Err(AwsDataSyncTransferError::InvalidConsent);
        }

        let mut receipts = Vec::new();
        let mut failures = Vec::new();
        let retries = Vec::new();
        let mut task_pages_observed = 0;
        let mut execution_pages_observed = 0;
        let mut task_list_complete = false;
        let mut execution_list_complete = false;
        let mut task: Option<TaskProjection> = None;
        let mut execution: Option<ExecutionProjection> = None;

        let describe_task_request = DescribeTaskRequest::new(&self.scope)?;
        match self.provider.describe_task(&describe_task_request) {
            Ok(response) => {
                receipts.push(receipt_for(
                    AwsDataSyncOperation::DescribeTask,
                    &describe_task_request.recorded_request(),
                    response.response_digest.clone(),
                    response.response_bytes,
                    self.provider.definition().provider_revision,
                    self.provider.provenance(),
                    request.observed_at,
                ));
                task = Some(response.task);
            }
            Err(error) => {
                failures.push(FailureEvidence::from_transport(
                    AwsDataSyncOperation::DescribeTask,
                    &error,
                ));
                return Ok(self.finish_proposal(
                    &request,
                    TransferEvidenceState::from_transport(&error),
                    task,
                    execution,
                    task_list_complete,
                    execution_list_complete,
                    task_pages_observed,
                    execution_pages_observed,
                    receipts,
                    failures,
                    retries,
                ));
            }
        }

        let mut task_cursor: Option<Cursor> = None;
        for _ in 0..request.max_pages {
            task_pages_observed = task_pages_observed.saturating_add(1);
            let list_request =
                ListTasksRequest::new(&self.scope, request.page_size, task_cursor.clone())?;
            match self.provider.list_tasks(&list_request) {
                Ok(response) => {
                    receipts.push(receipt_for(
                        AwsDataSyncOperation::ListTasks,
                        &list_request.recorded_request(),
                        response.response_digest.clone(),
                        response.response_bytes,
                        self.provider.definition().provider_revision,
                        self.provider.provenance(),
                        request.observed_at,
                    ));
                    task_cursor = response.next_cursor.clone();
                    if task_cursor.is_none() {
                        task_list_complete = true;
                        break;
                    }
                }
                Err(error) => {
                    failures.push(FailureEvidence::from_transport(
                        AwsDataSyncOperation::ListTasks,
                        &error,
                    ));
                    return Ok(self.finish_proposal(
                        &request,
                        TransferEvidenceState::from_transport(&error),
                        task,
                        execution,
                        task_list_complete,
                        execution_list_complete,
                        task_pages_observed,
                        execution_pages_observed,
                        receipts,
                        failures,
                        retries,
                    ));
                }
            }
        }

        let mut execution_cursor: Option<Cursor> = None;
        let mut executions = Vec::new();
        for _ in 0..request.max_pages {
            execution_pages_observed = execution_pages_observed.saturating_add(1);
            let list_request = ListTaskExecutionsRequest::new(
                &self.scope,
                request.page_size,
                execution_cursor.clone(),
            )?;
            match self.provider.list_task_executions(&list_request) {
                Ok(response) => {
                    receipts.push(receipt_for(
                        AwsDataSyncOperation::ListTaskExecutions,
                        &list_request.recorded_request(),
                        response.response_digest.clone(),
                        response.response_bytes,
                        self.provider.definition().provider_revision,
                        self.provider.provenance(),
                        request.observed_at,
                    ));
                    executions.extend(response.executions);
                    execution_cursor = response.next_cursor.clone();
                    if execution_cursor.is_none() {
                        execution_list_complete = true;
                        break;
                    }
                }
                Err(error) => {
                    failures.push(FailureEvidence::from_transport(
                        AwsDataSyncOperation::ListTaskExecutions,
                        &error,
                    ));
                    return Ok(self.finish_proposal(
                        &request,
                        TransferEvidenceState::from_transport(&error),
                        task,
                        execution,
                        task_list_complete,
                        execution_list_complete,
                        task_pages_observed,
                        execution_pages_observed,
                        receipts,
                        failures,
                        retries,
                    ));
                }
            }
        }

        let selected_execution = request
            .expected_execution_digest
            .as_ref()
            .and_then(|expected| {
                executions
                    .iter()
                    .find(|candidate| &candidate.execution_digest == expected)
            })
            .or_else(|| executions.first());

        let Some(selected_execution) = selected_execution else {
            return Ok(self.finish_proposal(
                &request,
                if task_list_complete && execution_list_complete {
                    TransferEvidenceState::Partial(PartialReason::MissingExecution)
                } else {
                    TransferEvidenceState::Partial(PartialReason::PageCap)
                },
                task,
                execution,
                task_list_complete,
                execution_list_complete,
                task_pages_observed,
                execution_pages_observed,
                receipts,
                failures,
                retries,
            ));
        };

        let describe_execution_request = DescribeTaskExecutionRequest::from_digest(
            &self.scope,
            selected_execution.execution_digest.clone(),
        )?;
        match self
            .provider
            .describe_task_execution(&describe_execution_request)
        {
            Ok(response) => {
                receipts.push(receipt_for(
                    AwsDataSyncOperation::DescribeTaskExecution,
                    &describe_execution_request.recorded_request(),
                    response.response_digest.clone(),
                    response.response_bytes,
                    self.provider.definition().provider_revision,
                    self.provider.provenance(),
                    request.observed_at,
                ));
                execution = Some(response.execution);
            }
            Err(error) => {
                failures.push(FailureEvidence::from_transport(
                    AwsDataSyncOperation::DescribeTaskExecution,
                    &error,
                ));
                return Ok(self.finish_proposal(
                    &request,
                    TransferEvidenceState::from_transport(&error),
                    task,
                    execution,
                    task_list_complete,
                    execution_list_complete,
                    task_pages_observed,
                    execution_pages_observed,
                    receipts,
                    failures,
                    retries,
                ));
            }
        }

        let state = if !task_list_complete || !execution_list_complete {
            TransferEvidenceState::Partial(PartialReason::PageCap)
        } else if execution
            .as_ref()
            .is_some_and(|value| value.counters.is_truncated())
        {
            TransferEvidenceState::Partial(PartialReason::CounterTruncated)
        } else if execution
            .as_ref()
            .is_some_and(|value| !value.status.is_terminal())
        {
            TransferEvidenceState::Partial(PartialReason::ExecutionInProgress)
        } else {
            TransferEvidenceState::Complete
        };
        Ok(self.finish_proposal(
            &request,
            state,
            task,
            execution,
            task_list_complete,
            execution_list_complete,
            task_pages_observed,
            execution_pages_observed,
            receipts,
            failures,
            retries,
        ))
    }

    pub fn verify(&self, proposal: &AwsDataSyncTransferProposal) -> VerificationReport {
        let mut reasons = Vec::new();
        if proposal.validate(&self.scope).is_err() {
            reasons.push(Digest::from_text("proposal-integrity"));
        }
        if !self.registration.is_active()
            || proposal.registration_digest != *self.registration.registration_digest()
        {
            reasons.push(Digest::from_text("registration-revoked-or-drifted"));
        }
        if self.secret_reference.is_revoked() {
            reasons.push(Digest::from_text("secret-revoked"));
        }
        if proposal.provider_digest != self.provider.definition().provider_digest {
            reasons.push(Digest::from_text("provider-drift"));
        }
        if proposal.provider_api_digest != self.provider.definition().api_digest {
            reasons.push(Digest::from_text("provider-api-drift"));
        }
        if reasons.is_empty() {
            VerificationReport::valid(proposal)
        } else {
            VerificationReport::invalid(reasons, proposal)
        }
    }

    fn finish_proposal(
        &self,
        request: &TransferEvidenceRequest,
        state: TransferEvidenceState,
        task: Option<TaskProjection>,
        execution: Option<ExecutionProjection>,
        task_list_complete: bool,
        execution_list_complete: bool,
        task_pages_observed: u16,
        execution_pages_observed: u16,
        receipts: Vec<ResponseReceipt>,
        failures: Vec<FailureEvidence>,
        retries: Vec<RetryEvidence>,
    ) -> AwsDataSyncTransferProposal {
        let evidence_digests = EvidenceDigests {
            contract_digest: Digest::from_text(CONTRACT_DIGEST),
            contract_version_digest: contract_version_digest(),
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            provider_digest: self.provider.definition().provider_digest.clone(),
            provider_api_digest: self.provider.definition().api_digest.clone(),
            permission_digest: self.registration.permission_digest(),
            consent_digest: self.registration.consent_digest(),
            scope_digest: self.scope.digest(),
            task_digest: task.as_ref().map(TaskProjection::digest),
            execution_digest: execution.as_ref().map(ExecutionProjection::digest),
            transfer_report_digest: execution
                .as_ref()
                .and_then(|value| value.transfer_report.as_ref().map(|report| report.digest())),
            request_digest: request.request_digest.clone(),
            response_digests: receipts
                .iter()
                .map(|receipt| receipt.response_digest.clone())
                .collect(),
        };
        let mut proposal = AwsDataSyncTransferProposal {
            state,
            scope_digest: self.scope.digest(),
            mission_digest: self.scope.mission().digest(),
            project_digest: self.scope.project().digest(),
            work_product_digest: self.scope.work_product().digest(),
            request_digest: request.request_digest.clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            provider_api_digest: self.provider.definition().api_digest.clone(),
            provider_revision: self.provider.definition().provider_revision,
            provenance: self.provider.provenance(),
            task,
            execution,
            task_list_complete,
            execution_list_complete,
            task_pages_observed,
            execution_pages_observed,
            receipts,
            failures,
            retries,
            evidence_digests,
            evidence_digest: Digest::from_text("unsealed-aws-datasync-evidence"),
            proposal_digest: Digest::from_text("unsealed-aws-datasync-proposal"),
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_authority: false,
            work_product_adoption: false,
            adoptable: false,
        };
        proposal.evidence_digest = proposal.calculate_evidence_digest();
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }
}

impl TransferEvidenceState {
    fn from_transport(error: &AwsDataSyncTransportError) -> Self {
        match error {
            AwsDataSyncTransportError::BadRequest => Self::InvalidRequest,
            AwsDataSyncTransportError::Unauthorized | AwsDataSyncTransportError::Forbidden => {
                Self::AccessLoss
            }
            AwsDataSyncTransportError::NotFound => Self::NotFound,
            AwsDataSyncTransportError::Conflict => Self::Conflict,
            AwsDataSyncTransportError::RateLimited { .. } => Self::Throttled,
            AwsDataSyncTransportError::Timeout => Self::Timeout,
            AwsDataSyncTransportError::ServerError { .. }
            | AwsDataSyncTransportError::BlockedEnv
            | AwsDataSyncTransportError::InvalidResponse
            | AwsDataSyncTransportError::Transport { .. } => Self::ProviderUnknown,
        }
    }
}

fn receipt_for(
    operation: AwsDataSyncOperation,
    request: &crate::provider::RecordedRequest,
    response_digest: Digest,
    response_bytes: u64,
    provider_revision: u64,
    provenance: TransportProvenance,
    observed_at: DateTime<Utc>,
) -> ResponseReceipt {
    ResponseReceipt {
        operation: operation.as_str().to_owned(),
        request_digest: request.request_digest.clone(),
        response_digest,
        path_digest: request.path_digest.clone(),
        status: 200,
        response_bytes,
        provider_revision,
        provenance,
        raw_payload_retained: false,
        raw_report_retained: false,
        raw_logs_retained: false,
        credential_material_retained: false,
        observed_at,
    }
}
