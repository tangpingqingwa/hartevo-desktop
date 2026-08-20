//! Service, registration, proposal, recording, and verification seams for
//! the bounded AWS IoT Device Defender Layer-1 slice.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_CHECKS, MAX_FINDINGS,
    MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION, SERVICE_ID,
    consumer::MissionAwsIotDeviceDefenderConsumer,
    error::{AwsIotDeviceDefenderError, AwsIotDeviceDefenderTransportError},
    model::{
        AuditCheckEvidence, AuditEvidenceState, AuditFindingEvidence, AuditTaskMetadata,
        AuditTaskStatus, AwsIotDeviceDefenderEvidence, AwsIotDeviceDefenderScope,
        CapabilityDescription, CheckState, ConsentBinding, Digest, FailureEvidence,
        ListAuditFindingsRequest, ListAuditTasksRequest, ModelError, PermissionAction,
        PermissionFence, SecretReference, TransportProvenance,
    },
    provider::{
        AwsIotDeviceDefenderProvider, AwsIotDeviceDefenderProviderError,
        AwsIotDeviceDefenderTransport,
    },
};

pub type ServiceResult<T> = std::result::Result<T, AwsIotDeviceDefenderError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsIotDeviceDefenderRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub audit_task_digest: Digest,
    pub check_allowlist_digest: Digest,
    pub resource_allowlist_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl AwsIotDeviceDefenderRegistration {
    fn new(
        scope: &AwsIotDeviceDefenderScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        consent: &ConsentBinding,
        provider: &AwsIotDeviceDefenderProviderDefinitionView,
    ) -> Self {
        let evidence_digest = Digest::from_parts(
            "aws-iot-device-defender-evidence-contract-binding/v1",
            &[
                scope.digest().to_string(),
                provider.provider_digest.to_string(),
                provider.api_digest.to_string(),
                permission.digest().to_string(),
                consent.digest().to_string(),
            ],
        );
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            provider_revision: API_REVISION.to_owned(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission.digest(),
            consent_digest: consent.digest(),
            scope_digest: scope.digest(),
            audit_task_digest: scope.audit_task_digest(),
            check_allowlist_digest: scope.checks_digest(),
            resource_allowlist_digest: scope.resources_digest(),
            secret_reference_digest: secret_reference.digest(),
            evidence_digest,
            registration_revision: 1,
            status: RegistrationStatus::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        registration
    }

    pub fn validate(&self) -> ServiceResult<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.provider_revision != API_REVISION
            || self.registration_revision == 0
            || self.registration_digest != self.recomputed_digest()
            || self.secret_reference_digest.is_zero()
            || self.evidence_digest.is_zero()
        {
            return Err(AwsIotDeviceDefenderError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.registration_digest.clone()
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.provider_revision.clone(),
                self.provider_digest.to_string(),
                self.api_digest.to_string(),
                self.permission_digest.to_string(),
                self.consent_digest.to_string(),
                self.scope_digest.to_string(),
                self.audit_task_digest.to_string(),
                self.check_allowlist_digest.to_string(),
                self.resource_allowlist_digest.to_string(),
                self.secret_reference_digest.to_string(),
                self.evidence_digest.to_string(),
                self.registration_revision.to_string(),
                format!("{:?}", self.status),
            ],
        )
    }

    pub fn revoke(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsIotDeviceDefenderError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.digest(),
        })
    }

    pub fn reverse(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsIotDeviceDefenderError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.digest(),
        })
    }

    pub fn restore(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsIotDeviceDefenderError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.digest(),
        })
    }
}

impl Serialize for AwsIotDeviceDefenderRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsIotDeviceDefenderRegistration", 19)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field(
            "providerIdDigest",
            &Digest::from_text(self.provider_id.as_bytes()),
        )?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field(
            "providerRevisionDigest",
            &Digest::from_text(self.provider_revision.as_bytes()),
        )?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("auditTaskDigest", &self.audit_task_digest)?;
        state.serialize_field("checkAllowlistDigest", &self.check_allowlist_digest)?;
        state.serialize_field("resourceAllowlistDigest", &self.resource_allowlist_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AwsIotDeviceDefenderProviderDefinitionView {
    provider_digest: Digest,
    api_digest: Digest,
}

impl From<&crate::provider::AwsIotDeviceDefenderProviderDefinition>
    for AwsIotDeviceDefenderProviderDefinitionView
{
    fn from(provider: &crate::provider::AwsIotDeviceDefenderProviderDefinition) -> Self {
        Self {
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIotDeviceDefenderReadRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl AwsIotDeviceDefenderReadRequest {
    fn new(
        scope: &AwsIotDeviceDefenderScope,
        provider_digest: &Digest,
        registration_digest: &Digest,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsIotDeviceDefenderError::Model(ModelError::Invalid {
                field: "bounded read limits",
            }));
        }
        let request_digest = Digest::from_parts(
            "aws-iot-device-defender-read-request/v1",
            &[
                scope.digest().to_string(),
                provider_digest.to_string(),
                registration_digest.to_string(),
                page_size.to_string(),
                max_pages.to_string(),
                observed_at.to_rfc3339(),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest: provider_digest.clone(),
            expected_registration_digest: registration_digest.clone(),
            page_size,
            max_pages,
            observed_at,
            request_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.request_digest.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIotDeviceDefenderProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub evidence: AwsIotDeviceDefenderEvidence,
    pub state: AuditEvidenceState,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub proposal_digest: Digest,
}

impl AwsIotDeviceDefenderProposal {
    fn new(
        registration: &AwsIotDeviceDefenderRegistration,
        evidence: AwsIotDeviceDefenderEvidence,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.digest(),
            scope_digest: registration.scope_digest.clone(),
            state: evidence.state,
            provenance: evidence.provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            adopted_outcome: false,
            adopted_work_product: false,
            evidence,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    pub fn validate_integrity(&self) -> ServiceResult<()> {
        self.evidence
            .validate_integrity()
            .map_err(|_| AwsIotDeviceDefenderError::EvidenceTampered)?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.state != self.evidence.state
            || self.provenance != self.evidence.provenance
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.adopted_outcome
            || self.adopted_work_product
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsIotDeviceDefenderError::ProposalTampered);
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-proposal/v1",
            &[
                self.service_id.clone(),
                self.consumer_id.clone(),
                self.registration_digest.to_string(),
                self.scope_digest.to_string(),
                self.evidence.evidence_digest.to_string(),
                format!("{:?}", self.state),
                self.provenance.as_str().to_owned(),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
                self.provider_receipt.to_string(),
                self.adopted_outcome.to_string(),
                self.adopted_work_product.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIotDeviceDefenderRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: AuditEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub raw_finding_data_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub receipt_digest: Digest,
}

impl AwsIotDeviceDefenderRecordReceipt {
    fn new(proposal: &AwsIotDeviceDefenderProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            proposal_digest: proposal.digest(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            raw_finding_data_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn validate_integrity(&self) -> ServiceResult<()> {
        if !self.recorded
            || self.raw_finding_data_retained
            || self.durable_receipt
            || self.connected
            || self.native
            || self.receipt_digest != self.recomputed_digest()
        {
            return Err(AwsIotDeviceDefenderError::EvidenceTampered);
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-record-receipt/v1",
            &[
                self.recorded.to_string(),
                self.recorded_at.to_rfc3339(),
                format!("{:?}", self.state),
                self.proposal_digest.to_string(),
                self.evidence_digest.to_string(),
                self.registration_digest.to_string(),
                self.scope_digest.to_string(),
                self.raw_finding_data_retained.to_string(),
                self.durable_receipt.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    ProposalTampered,
    RegistrationRevoked,
    RegistrationMismatch,
    RetentionExpired,
    StateNotReviewEligible,
    ProviderNotNative,
    EvidenceDigestMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub state: AuditEvidenceState,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub failure: Option<VerificationFailure>,
    pub connected: bool,
    pub native: bool,
    pub adopted_work_product: bool,
}

pub struct AwsIotDeviceDefenderService<T>
where
    T: AwsIotDeviceDefenderTransport,
{
    scope: AwsIotDeviceDefenderScope,
    secret_reference: SecretReference,
    permission: PermissionFence,
    consent: ConsentBinding,
    provider: AwsIotDeviceDefenderProvider<T>,
    registration: AwsIotDeviceDefenderRegistration,
}

impl<T> fmt::Debug for AwsIotDeviceDefenderService<T>
where
    T: AwsIotDeviceDefenderTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsIotDeviceDefenderService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("consent_digest", &self.consent.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsIotDeviceDefenderService<T>
where
    T: AwsIotDeviceDefenderTransport,
{
    pub fn new(
        scope: AwsIotDeviceDefenderScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsIotDeviceDefenderProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<Self> {
        let consent = ConsentBinding::for_read_only(
            "aws-iot-device-defender-layer1",
            crate::Revision::new(1)?,
            scope.retention_until,
            &permission,
        )?;
        Self::new_with_consent(
            scope,
            secret_reference,
            permission,
            consent,
            provider,
            observed_at,
        )
    }

    pub fn new_with_consent(
        scope: AwsIotDeviceDefenderScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        consent: ConsentBinding,
        provider: AwsIotDeviceDefenderProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<Self> {
        scope.validate()?;
        permission.validate()?;
        for action in PermissionAction::all() {
            if !permission.allows(action) {
                return Err(AwsIotDeviceDefenderError::PermissionMissing(action));
            }
        }
        secret_reference.validate(&scope)?;
        consent.validate(&permission, observed_at)?;
        provider
            .definition()
            .validate()
            .map_err(|error| AwsIotDeviceDefenderError::ProviderDefinition(error.to_string()))?;
        let provider_view = AwsIotDeviceDefenderProviderDefinitionView::from(provider.definition());
        let registration = AwsIotDeviceDefenderRegistration::new(
            &scope,
            &secret_reference,
            &permission,
            &consent,
            &provider_view,
        );
        registration.validate()?;
        Ok(Self {
            scope,
            secret_reference,
            permission,
            consent,
            provider,
            registration,
        })
    }

    pub fn register(
        scope: AwsIotDeviceDefenderScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsIotDeviceDefenderProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<Self> {
        Self::new(scope, secret_reference, permission, provider, observed_at)
    }

    pub fn register_with_consent(
        scope: AwsIotDeviceDefenderScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        consent: ConsentBinding,
        provider: AwsIotDeviceDefenderProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<Self> {
        Self::new_with_consent(
            scope,
            secret_reference,
            permission,
            consent,
            provider,
            observed_at,
        )
    }

    pub fn scope(&self) -> &AwsIotDeviceDefenderScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn consent(&self) -> &ConsentBinding {
        &self.consent
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsIotDeviceDefenderProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsIotDeviceDefenderProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsIotDeviceDefenderRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "ListAuditTasks".to_owned(),
                "DescribeAuditTask".to_owned(),
                "ListAuditFindings".to_owned(),
            ],
            permissions: LAYER1_PERMISSIONS.iter().map(ToString::to_string).collect(),
            read_only: true,
            proposal_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<AwsIotDeviceDefenderReadRequest> {
        AwsIotDeviceDefenderReadRequest::new(
            &self.scope,
            &self.provider.definition().provider_digest,
            &self.registration.digest(),
            page_size,
            max_pages,
            observed_at,
        )
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<AwsIotDeviceDefenderReadRequest> {
        self.request(MAX_PAGE_SIZE, MAX_PAGES, observed_at)
    }

    pub fn read_bounded(
        &mut self,
        request: &AwsIotDeviceDefenderReadRequest,
    ) -> ServiceResult<AwsIotDeviceDefenderEvidence> {
        self.read(request)
    }

    pub fn read(
        &mut self,
        request: &AwsIotDeviceDefenderReadRequest,
    ) -> ServiceResult<AwsIotDeviceDefenderEvidence> {
        self.validate_request(request)?;
        if request.observed_at >= self.scope.retention_until {
            return Ok(self.empty_evidence(
                request,
                AuditEvidenceState::RetentionExpired,
                Some(FailureEvidence::new("retention", "retention_expired", None)),
            ));
        }

        let (tasks, list_pages, list_complete, list_digest, cursor_digests) =
            match self.read_audit_tasks(request) {
                Ok(value) => value,
                Err(ReadStageFailure::Evidence(error)) => return Err(error),
                Err(ReadStageFailure::State {
                    state,
                    failure,
                    pages,
                    complete,
                    list_digest,
                    cursor_digests,
                }) => {
                    return Ok(self.empty_evidence_with(
                        request,
                        state,
                        failure,
                        pages,
                        false,
                        0,
                        complete,
                        false,
                        list_digest,
                        None,
                        None,
                        cursor_digests,
                        AuditTaskStatus::Unknown,
                    ));
                }
            };
        let list_digest = Some(list_digest);
        if !list_complete {
            return Ok(self.empty_evidence_with(
                request,
                AuditEvidenceState::Partial,
                None,
                list_pages,
                false,
                0,
                false,
                false,
                list_digest,
                None,
                None,
                cursor_digests,
                AuditTaskStatus::Unknown,
            ));
        }

        let task = match select_task(&self.scope, &tasks) {
            Ok(task) => task,
            Err((state, failure)) => {
                return Ok(self.empty_evidence_with(
                    request,
                    state,
                    failure,
                    list_pages,
                    false,
                    0,
                    true,
                    false,
                    list_digest,
                    None,
                    None,
                    cursor_digests,
                    AuditTaskStatus::Unknown,
                ));
            }
        };

        let describe_request = crate::DescribeAuditTaskRequest::for_scope(&self.scope);
        let describe = match self.provider.describe_audit_task(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                return self.error_evidence(
                    request,
                    map_provider_failure("DescribeAuditTask", &error),
                    list_pages,
                    true,
                    0,
                    true,
                    false,
                    list_digest,
                    None,
                    None,
                    cursor_digests,
                    task.status.clone(),
                );
            }
        };
        let describe_digest = describe.response_digest.clone();
        if describe.task.task != self.scope.audit_task
            || describe.task.task_digest != task.task_digest
        {
            return Ok(self.empty_evidence_with(
                request,
                AuditEvidenceState::TaskDrift,
                Some(FailureEvidence::new(
                    "DescribeAuditTask",
                    "task_drift",
                    None,
                )),
                list_pages,
                true,
                0,
                true,
                false,
                list_digest,
                Some(describe_digest),
                None,
                cursor_digests,
                describe.task.status,
            ));
        }
        if describe.checks.len() != self.scope.checks.len()
            || describe
                .checks
                .iter()
                .any(|summary| !self.scope.allows_check(&summary.check))
            || self.scope.checks.iter().any(|check| {
                !describe
                    .checks
                    .iter()
                    .any(|summary| summary.check == *check)
            })
        {
            return Ok(self.empty_evidence_with(
                request,
                AuditEvidenceState::CheckDrift,
                Some(FailureEvidence::new(
                    "DescribeAuditTask",
                    "check_drift",
                    None,
                )),
                list_pages,
                true,
                0,
                true,
                false,
                list_digest,
                Some(describe_digest),
                None,
                cursor_digests,
                describe.task.status,
            ));
        }

        let findings_request = ListAuditFindingsRequest::for_scope(
            &self.scope,
            request.page_size,
            request.max_pages,
            None,
        )?;
        let (findings, findings_pages, findings_complete, findings_digest, finding_cursors) =
            match self.read_audit_findings(&findings_request, request) {
                Ok(value) => value,
                Err(ReadStageFailure::Evidence(error)) => return Err(error),
                Err(ReadStageFailure::State {
                    state,
                    failure,
                    pages,
                    complete,
                    list_digest: findings_digest,
                    cursor_digests: finding_cursors,
                }) => {
                    let mut all_cursors = cursor_digests;
                    all_cursors.extend(finding_cursors);
                    return Ok(self.empty_evidence_with(
                        request,
                        state,
                        failure,
                        list_pages,
                        true,
                        pages,
                        true,
                        complete,
                        list_digest,
                        Some(describe_digest),
                        findings_digest,
                        all_cursors,
                        describe.task.status,
                    ));
                }
            };
        let findings_digest = Some(findings_digest);
        let mut all_cursors = cursor_digests;
        all_cursors.extend(finding_cursors);
        if findings.len() > MAX_FINDINGS {
            return Ok(self.empty_evidence_with(
                request,
                AuditEvidenceState::Partial,
                Some(FailureEvidence::new(
                    "ListAuditFindings",
                    "finding_bound",
                    None,
                )),
                list_pages,
                true,
                findings_pages,
                true,
                findings_complete,
                list_digest,
                Some(describe_digest),
                findings_digest,
                all_cursors,
                describe.task.status,
            ));
        }
        if let Some(finding) = findings.iter().find(|finding| {
            !self.scope.allows_check(&finding.check)
                || !self.scope.allows_resource(&finding.resource)
        }) {
            let state = if !self.scope.allows_check(&finding.check) {
                AuditEvidenceState::CheckDrift
            } else {
                AuditEvidenceState::ResourceDrift
            };
            return Ok(self.empty_evidence_with(
                request,
                state,
                Some(FailureEvidence::new(
                    "ListAuditFindings",
                    "allowlist_drift",
                    None,
                )),
                list_pages,
                true,
                findings_pages,
                true,
                findings_complete,
                list_digest,
                Some(describe_digest),
                findings_digest,
                all_cursors,
                describe.task.status,
            ));
        }

        let checks = describe
            .checks
            .iter()
            .map(|summary| AuditCheckEvidence {
                check_digest: summary.check_digest.clone(),
                state: summary.state,
                severity: summary.severity,
                finding_count: summary.finding_count,
                suppressed_count: summary.suppressed_count,
            })
            .collect::<Vec<_>>();
        let finding_evidence = findings
            .iter()
            .map(AuditFindingEvidence::from_finding)
            .collect::<Vec<_>>();
        let state = aggregate_state(&describe.task, &checks, findings_complete);
        let mut evidence = self.empty_evidence_with(
            request,
            state,
            None,
            list_pages,
            true,
            findings_pages,
            true,
            findings_complete,
            list_digest,
            Some(describe_digest),
            findings_digest,
            all_cursors,
            describe.task.status,
        );
        evidence.checks = checks;
        evidence.findings = finding_evidence;
        evidence.evidence_digest = evidence.recomputed_digest();
        Ok(evidence)
    }

    pub fn propose(
        &mut self,
        request: &AwsIotDeviceDefenderReadRequest,
    ) -> ServiceResult<AwsIotDeviceDefenderProposal> {
        let evidence = self.read(request)?;
        Ok(AwsIotDeviceDefenderProposal::new(
            &self.registration,
            evidence,
        ))
    }

    pub fn record(
        &self,
        proposal: &AwsIotDeviceDefenderProposal,
    ) -> ServiceResult<AwsIotDeviceDefenderRecordReceipt> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsIotDeviceDefenderProposal,
        recorded_at: DateTime<Utc>,
    ) -> ServiceResult<AwsIotDeviceDefenderRecordReceipt> {
        self.validate_proposal_binding(proposal)?;
        let receipt = AwsIotDeviceDefenderRecordReceipt::new(proposal, recorded_at);
        receipt.validate_integrity()?;
        Ok(receipt)
    }

    pub fn verify(&self, proposal: &AwsIotDeviceDefenderProposal) -> VerificationReport {
        self.verify_at(proposal, Utc::now())
    }

    pub fn verify_at(
        &self,
        proposal: &AwsIotDeviceDefenderProposal,
        now: DateTime<Utc>,
    ) -> VerificationReport {
        let base = VerificationReport {
            valid: false,
            review_eligible: false,
            state: proposal.state,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            failure: None,
            connected: false,
            native: false,
            adopted_work_product: false,
        };
        if proposal.validate_integrity().is_err() {
            return VerificationReport {
                failure: Some(VerificationFailure::ProposalTampered),
                ..base
            };
        }
        if !self.registration.is_active() || self.secret_reference.is_revoked() {
            return VerificationReport {
                failure: Some(VerificationFailure::RegistrationRevoked),
                ..base
            };
        }
        if proposal.registration_digest != self.registration.digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            return VerificationReport {
                failure: Some(VerificationFailure::RegistrationMismatch),
                ..base
            };
        }
        if now >= proposal.evidence.expires_at {
            return VerificationReport {
                failure: Some(VerificationFailure::RetentionExpired),
                ..base
            };
        }
        if !proposal.state.review_eligible() {
            return VerificationReport {
                failure: Some(VerificationFailure::StateNotReviewEligible),
                ..base
            };
        }
        VerificationReport {
            valid: true,
            review_eligible: true,
            failure: None,
            ..base
        }
    }

    pub fn verify_proposal(&self, proposal: &AwsIotDeviceDefenderProposal) -> VerificationReport {
        self.verify(proposal)
    }

    pub fn consumer(&self) -> ServiceResult<MissionAwsIotDeviceDefenderConsumer> {
        MissionAwsIotDeviceDefenderConsumer::new(self.scope.clone(), self.registration.clone())
            .map_err(|error| match error {
                crate::consumer::ConsumerError::Service(error) => error,
                _ => AwsIotDeviceDefenderError::RegistrationMismatch,
            })
    }

    pub fn revoke_registration(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }

    fn validate_request(&self, request: &AwsIotDeviceDefenderReadRequest) -> ServiceResult<()> {
        if !self.registration.is_active() {
            return Err(
                if matches!(self.registration.status, RegistrationStatus::Reversed) {
                    AwsIotDeviceDefenderError::RegistrationReversed
                } else {
                    AwsIotDeviceDefenderError::RegistrationRevoked
                },
            );
        }
        if self.secret_reference.is_revoked() {
            return Err(AwsIotDeviceDefenderError::SecretReferenceRevoked);
        }
        if request.scope_digest != self.scope.digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != self.registration.digest()
        {
            return Err(AwsIotDeviceDefenderError::RegistrationMismatch);
        }
        self.scope.validate()?;
        self.permission.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if request.observed_at < self.scope.retention_until {
            self.consent
                .validate(&self.permission, request.observed_at)?;
        }
        Ok(())
    }

    fn validate_proposal_binding(
        &self,
        proposal: &AwsIotDeviceDefenderProposal,
    ) -> ServiceResult<()> {
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.registration.digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.registration_digest != self.registration.digest()
        {
            return Err(AwsIotDeviceDefenderError::RegistrationMismatch);
        }
        Ok(())
    }

    fn read_audit_tasks(
        &mut self,
        request: &AwsIotDeviceDefenderReadRequest,
    ) -> std::result::Result<
        (Vec<AuditTaskMetadata>, u16, bool, Digest, Vec<Digest>),
        ReadStageFailure,
    > {
        let mut cursor = None;
        let mut tasks = Vec::new();
        let mut pages: u16 = 0;
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        loop {
            pages = pages.saturating_add(1);
            let page_request = ListAuditTasksRequest::new(
                &self.scope,
                request.page_size,
                request.max_pages,
                cursor.clone(),
            )
            .map_err(|error| ReadStageFailure::Evidence(error.into()))?;
            let response = match self.provider.list_audit_tasks(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    return Err(stage_failure(
                        "ListAuditTasks",
                        error,
                        pages,
                        false,
                        page_digests.last().cloned(),
                        cursor_digests,
                    ));
                }
            };
            page_digests.push(response.response_digest.clone());
            tasks.extend(response.tasks.clone());
            if tasks.len() > MAX_CHECKS.saturating_mul(2) {
                return Err(ReadStageFailure::State {
                    state: AuditEvidenceState::Partial,
                    failure: Some(FailureEvidence::new("ListAuditTasks", "task_bound", None)),
                    pages,
                    complete: false,
                    list_digest: Some(combine_digests(&page_digests, "list-audit-tasks")),
                    cursor_digests,
                });
            }
            match response.next_cursor {
                None => {
                    return Ok((
                        tasks,
                        pages,
                        true,
                        combine_digests(&page_digests, "list-audit-tasks"),
                        cursor_digests,
                    ));
                }
                Some(next_cursor) => {
                    let token_digest = next_cursor.token_digest();
                    if !seen_tokens.insert(token_digest.clone()) {
                        cursor_digests.push(next_cursor.digest());
                        return Err(ReadStageFailure::State {
                            state: AuditEvidenceState::PaginationLoop,
                            failure: Some(FailureEvidence::new(
                                "ListAuditTasks",
                                "pagination_loop",
                                None,
                            )),
                            pages,
                            complete: false,
                            list_digest: Some(combine_digests(&page_digests, "list-audit-tasks")),
                            cursor_digests,
                        });
                    }
                    cursor_digests.push(next_cursor.digest());
                    if pages >= request.max_pages {
                        return Err(ReadStageFailure::State {
                            state: AuditEvidenceState::Partial,
                            failure: Some(FailureEvidence::new(
                                "ListAuditTasks",
                                "page_bound",
                                None,
                            )),
                            pages,
                            complete: false,
                            list_digest: Some(combine_digests(&page_digests, "list-audit-tasks")),
                            cursor_digests,
                        });
                    }
                    cursor = Some(next_cursor);
                }
            }
        }
    }

    fn read_audit_findings(
        &mut self,
        first_request: &ListAuditFindingsRequest,
        request: &AwsIotDeviceDefenderReadRequest,
    ) -> std::result::Result<
        (Vec<crate::AuditFinding>, u16, bool, Digest, Vec<Digest>),
        ReadStageFailure,
    > {
        let mut cursor = first_request.cursor.clone();
        let mut findings = Vec::new();
        let mut pages: u16 = 0;
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        loop {
            pages = pages.saturating_add(1);
            let page_request = ListAuditFindingsRequest::for_scope(
                &self.scope,
                request.page_size,
                request.max_pages,
                cursor.clone(),
            )
            .map_err(|error| ReadStageFailure::Evidence(error.into()))?;
            let response = match self.provider.list_audit_findings(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    return Err(stage_failure(
                        "ListAuditFindings",
                        error,
                        pages,
                        false,
                        page_digests.last().cloned(),
                        cursor_digests,
                    ));
                }
            };
            page_digests.push(response.response_digest.clone());
            findings.extend(response.findings.clone());
            if findings.len() > MAX_FINDINGS {
                return Err(ReadStageFailure::State {
                    state: AuditEvidenceState::Partial,
                    failure: Some(FailureEvidence::new(
                        "ListAuditFindings",
                        "finding_bound",
                        None,
                    )),
                    pages,
                    complete: false,
                    list_digest: Some(combine_digests(&page_digests, "list-audit-findings")),
                    cursor_digests,
                });
            }
            match response.next_cursor {
                None => {
                    return Ok((
                        findings,
                        pages,
                        true,
                        combine_digests(&page_digests, "list-audit-findings"),
                        cursor_digests,
                    ));
                }
                Some(next_cursor) => {
                    let token_digest = next_cursor.token_digest();
                    if !seen_tokens.insert(token_digest) {
                        cursor_digests.push(next_cursor.digest());
                        return Err(ReadStageFailure::State {
                            state: AuditEvidenceState::PaginationLoop,
                            failure: Some(FailureEvidence::new(
                                "ListAuditFindings",
                                "pagination_loop",
                                None,
                            )),
                            pages,
                            complete: false,
                            list_digest: Some(combine_digests(
                                &page_digests,
                                "list-audit-findings",
                            )),
                            cursor_digests,
                        });
                    }
                    cursor_digests.push(next_cursor.digest());
                    if pages >= request.max_pages {
                        return Err(ReadStageFailure::State {
                            state: AuditEvidenceState::Partial,
                            failure: Some(FailureEvidence::new(
                                "ListAuditFindings",
                                "page_bound",
                                None,
                            )),
                            pages,
                            complete: false,
                            list_digest: Some(combine_digests(
                                &page_digests,
                                "list-audit-findings",
                            )),
                            cursor_digests,
                        });
                    }
                    cursor = Some(next_cursor);
                }
            }
        }
    }

    fn empty_evidence(
        &self,
        request: &AwsIotDeviceDefenderReadRequest,
        state: AuditEvidenceState,
        failure: Option<FailureEvidence>,
    ) -> AwsIotDeviceDefenderEvidence {
        self.empty_evidence_with(
            request,
            state,
            failure,
            0,
            false,
            0,
            false,
            false,
            None,
            None,
            None,
            Vec::new(),
            AuditTaskStatus::Unknown,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn empty_evidence_with(
        &self,
        request: &AwsIotDeviceDefenderReadRequest,
        state: AuditEvidenceState,
        failure: Option<FailureEvidence>,
        list_pages: u16,
        describe_read: bool,
        findings_pages: u16,
        list_complete: bool,
        findings_complete: bool,
        list_digest: Option<Digest>,
        describe_digest: Option<Digest>,
        findings_digest: Option<Digest>,
        cursor_digests: Vec<Digest>,
        task_status: AuditTaskStatus,
    ) -> AwsIotDeviceDefenderEvidence {
        let mut evidence = AwsIotDeviceDefenderEvidence {
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.digest(),
            account_digest: self.scope.account_id.digest(),
            region_digest: self.scope.region.digest(),
            audit_task_digest: self.scope.audit_task_digest(),
            mission_digest: self.scope.mission.digest(),
            project_digest: self.scope.project.digest(),
            work_product_digest: self.scope.work_product.digest(),
            task_status,
            state,
            checks: Vec::new(),
            findings: Vec::new(),
            list_audit_tasks_digest: list_digest,
            describe_audit_task_digest: describe_digest,
            list_audit_findings_digest: findings_digest,
            cursor_digests,
            list_pages,
            describe_read,
            findings_pages,
            list_complete,
            findings_complete,
            observed_at: request.observed_at,
            expires_at: self.scope.retention_until,
            failure,
            provenance: self.provider.definition().provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_finding_data_retained: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    fn error_evidence(
        &self,
        request: &AwsIotDeviceDefenderReadRequest,
        failure: (AuditEvidenceState, FailureEvidence),
        list_pages: u16,
        describe_read: bool,
        findings_pages: u16,
        list_complete: bool,
        findings_complete: bool,
        list_digest: Option<Digest>,
        describe_digest: Option<Digest>,
        findings_digest: Option<Digest>,
        cursor_digests: Vec<Digest>,
        task_status: AuditTaskStatus,
    ) -> ServiceResult<AwsIotDeviceDefenderEvidence> {
        Ok(self.empty_evidence_with(
            request,
            failure.0,
            Some(failure.1),
            list_pages,
            describe_read,
            findings_pages,
            list_complete,
            findings_complete,
            list_digest,
            describe_digest,
            findings_digest,
            cursor_digests,
            task_status,
        ))
    }
}

enum ReadStageFailure {
    State {
        state: AuditEvidenceState,
        failure: Option<FailureEvidence>,
        pages: u16,
        complete: bool,
        list_digest: Option<Digest>,
        cursor_digests: Vec<Digest>,
    },
    Evidence(AwsIotDeviceDefenderError),
}

fn stage_failure(
    operation: &str,
    error: AwsIotDeviceDefenderProviderError,
    pages: u16,
    complete: bool,
    list_digest: Option<Digest>,
    cursor_digests: Vec<Digest>,
) -> ReadStageFailure {
    match error {
        AwsIotDeviceDefenderProviderError::Transport(error) => {
            let (state, failure) = map_transport_failure(operation, &error);
            ReadStageFailure::State {
                state,
                failure: Some(failure),
                pages,
                complete,
                list_digest,
                cursor_digests,
            }
        }
        error => ReadStageFailure::Evidence(error.into()),
    }
}

fn map_provider_failure(
    operation: &str,
    error: &AwsIotDeviceDefenderProviderError,
) -> (AuditEvidenceState, FailureEvidence) {
    match error {
        AwsIotDeviceDefenderProviderError::Transport(error) => {
            map_transport_failure(operation, error)
        }
        _ => (
            AuditEvidenceState::ProviderUnknown,
            FailureEvidence::new(operation, "provider_unknown", None),
        ),
    }
}

fn map_transport_failure(
    operation: &str,
    error: &AwsIotDeviceDefenderTransportError,
) -> (AuditEvidenceState, FailureEvidence) {
    let state = match error {
        AwsIotDeviceDefenderTransportError::Unauthorized
        | AwsIotDeviceDefenderTransportError::Forbidden
        | AwsIotDeviceDefenderTransportError::AccessLost => AuditEvidenceState::AccessLoss,
        AwsIotDeviceDefenderTransportError::NotFound => AuditEvidenceState::NotFound,
        AwsIotDeviceDefenderTransportError::RateLimited { .. } => AuditEvidenceState::Throttled,
        AwsIotDeviceDefenderTransportError::Partial => AuditEvidenceState::Partial,
        AwsIotDeviceDefenderTransportError::BlockedEnv
        | AwsIotDeviceDefenderTransportError::BadRequest
        | AwsIotDeviceDefenderTransportError::ServerFailure { .. }
        | AwsIotDeviceDefenderTransportError::Timeout
        | AwsIotDeviceDefenderTransportError::MalformedResponse => {
            AuditEvidenceState::ProviderUnknown
        }
    };
    (
        state,
        FailureEvidence::new(operation, error.category(), error.status_code()),
    )
}

fn select_task(
    scope: &AwsIotDeviceDefenderScope,
    tasks: &[AuditTaskMetadata],
) -> std::result::Result<AuditTaskMetadata, (AuditEvidenceState, Option<FailureEvidence>)> {
    let matching_id = tasks
        .iter()
        .filter(|task| task.task.id == scope.audit_task.id)
        .collect::<Vec<_>>();
    if matching_id.is_empty() {
        return Err((
            AuditEvidenceState::NotFound,
            Some(FailureEvidence::new(
                "ListAuditTasks",
                "task_not_found",
                Some(404),
            )),
        ));
    }
    if matching_id.len() != 1 || matching_id[0].task.revision != scope.audit_task.revision {
        return Err((
            AuditEvidenceState::TaskDrift,
            Some(FailureEvidence::new("ListAuditTasks", "task_drift", None)),
        ));
    }
    Ok(matching_id[0].clone())
}

fn aggregate_state(
    task: &AuditTaskMetadata,
    checks: &[AuditCheckEvidence],
    findings_complete: bool,
) -> AuditEvidenceState {
    if !findings_complete {
        return AuditEvidenceState::Partial;
    }
    if !matches!(task.status, AuditTaskStatus::Complete) {
        return if matches!(task.status, AuditTaskStatus::InProgress) {
            AuditEvidenceState::Partial
        } else {
            AuditEvidenceState::Unknown
        };
    }
    if checks
        .iter()
        .any(|check| matches!(check.state, CheckState::Unknown))
    {
        AuditEvidenceState::Unknown
    } else {
        AuditEvidenceState::Complete
    }
}

fn combine_digests(digests: &[Digest], domain: &str) -> Digest {
    Digest::from_parts(
        domain,
        &digests.iter().map(ToString::to_string).collect::<Vec<_>>(),
    )
}
