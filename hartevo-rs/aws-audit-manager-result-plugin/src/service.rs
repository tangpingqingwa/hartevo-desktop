//! Service, registration, proposal, recording, and verification seams.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsAuditManagerConsumer;
use crate::error::{AwsAuditManagerError, AwsAuditManagerTransportError, Result};
use crate::model::{
    AssessmentDetail, AssessmentReportSummary, AuditManagerEvidence, AuditManagerEvidenceState,
    AuditManagerOperation, AwsAuditManagerEvidenceRequest, AwsAuditManagerScope, ConsentScope,
    Digest, EvidencePeriod, PermissionSnapshot, ProviderFailure, ProviderProvenance,
    SecretReference,
};
use crate::provider::{
    AwsAuditManagerProvider, AwsAuditManagerReadRequest, AwsAuditManagerTransport, ProviderError,
};
use crate::{
    AWS_AUDIT_MANAGER_API_REVISION, AWS_AUDIT_MANAGER_CONSUMER_ID,
    AWS_AUDIT_MANAGER_CONTRACT_VERSION, AWS_AUDIT_MANAGER_PLUGIN_VERSION,
    AWS_AUDIT_MANAGER_PROVIDER_ID, AWS_AUDIT_MANAGER_SERVICE_ID, CONTRACT_DIGEST,
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES,
};

pub use crate::model::AwsAuditManagerReadResult;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

pub type RegistrationStatus = RegistrationState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationState,
    pub new_status: RegistrationState,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsAuditManagerRegistration {
    id: String,
    scope: AwsAuditManagerScope,
    secret_reference: SecretReference,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    provider_digest: Digest,
    assessment_digest: Digest,
    framework_digest: Digest,
    control_set_digest: Digest,
    report_digest: Digest,
    mission_digest: Digest,
    project_digest: Digest,
    work_product_digest: Digest,
    evidence_binding_digest: Digest,
    registration_revision: u64,
    status: RegistrationState,
    registration_digest: Digest,
}

impl fmt::Debug for AwsAuditManagerRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAuditManagerRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("permission_digest", self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("provider_digest", &self.provider_digest)
            .field("assessment_digest", &self.assessment_digest)
            .field("framework_digest", &self.framework_digest)
            .field("control_set_digest", &self.control_set_digest)
            .field("report_digest", &self.report_digest)
            .field("mission_digest", &self.mission_digest)
            .field("project_digest", &self.project_digest)
            .field("work_product_digest", &self.work_product_digest)
            .field("evidence_binding_digest", &self.evidence_binding_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsAuditManagerRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAuditManagerRegistration", 23)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &AWS_AUDIT_MANAGER_PLUGIN_VERSION)?;
        state.serialize_field("contractVersion", &AWS_AUDIT_MANAGER_CONTRACT_VERSION)?;
        state.serialize_field("contractDigest", &CONTRACT_DIGEST)?;
        state.serialize_field("providerId", &AWS_AUDIT_MANAGER_PROVIDER_ID)?;
        state.serialize_field("providerRevision", &AWS_AUDIT_MANAGER_API_REVISION)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("assessmentDigest", &self.assessment_digest)?;
        state.serialize_field("frameworkDigest", &self.framework_digest)?;
        state.serialize_field("controlSetDigest", &self.control_set_digest)?;
        state.serialize_field("reportDigest", &self.report_digest)?;
        state.serialize_field("missionDigest", &self.mission_digest)?;
        state.serialize_field("projectDigest", &self.project_digest)?;
        state.serialize_field("workProductDigest", &self.work_product_digest)?;
        state.serialize_field("permissionDigest", self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("evidenceBindingDigest", &self.evidence_binding_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl AwsAuditManagerRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsAuditManagerScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider_digest: Digest,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > MAX_IDENTIFIER_BYTES || id.chars().any(char::is_control) {
            return Err(AwsAuditManagerError::InvalidRegistration);
        }
        if scope.tenant_status() != crate::model::TenantStatus::Existing {
            return Err(match scope.tenant_status() {
                crate::model::TenantStatus::Unregistered => {
                    AwsAuditManagerError::UnregisteredAccount
                }
                crate::model::TenantStatus::NewCustomer => {
                    AwsAuditManagerError::NewCustomerNotEligible
                }
                crate::model::TenantStatus::Existing => AwsAuditManagerError::InvalidRegistration,
            });
        }
        scope.validate()?;
        secret_reference.validate_for(&scope)?;
        permission_snapshot.validate()?;
        consent.validate_at(now)?;
        provider_digest.validate()?;
        if LAYER1_PERMISSIONS
            .iter()
            .any(|permission| !permission_snapshot.permits(permission))
        {
            return Err(AwsAuditManagerError::InvalidPermissionSnapshot);
        }
        let evidence_binding_digest =
            crate::model::evidence_binding_digest(&scope, &provider_digest);
        let registration_digest = crate::model::expected_registration_digest(
            &id,
            &scope,
            &secret_reference,
            &permission_snapshot,
            &consent,
            &provider_digest,
            &evidence_binding_digest,
            1,
            "active",
        );
        let assessment_digest = scope.assessment().digest();
        let framework_digest = scope.framework().digest();
        let control_set_digest = scope.control_set().digest();
        let report_digest = scope.report().digest();
        let mission_digest = scope.mission().digest();
        let project_digest = scope.project().digest();
        let work_product_digest = scope.work_product().digest();
        Ok(Self {
            id,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            provider_digest,
            assessment_digest,
            framework_digest,
            control_set_digest,
            report_digest,
            mission_digest,
            project_digest,
            work_product_digest,
            evidence_binding_digest,
            registration_revision: 1,
            status: RegistrationState::Active,
            registration_digest,
        })
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_text(&self.id)
    }

    pub fn scope(&self) -> &AwsAuditManagerScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn assessment_digest(&self) -> &Digest {
        &self.assessment_digest
    }

    pub fn framework_digest(&self) -> &Digest {
        &self.framework_digest
    }

    pub fn control_set_digest(&self) -> &Digest {
        &self.control_set_digest
    }

    pub fn report_digest(&self) -> &Digest {
        &self.report_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }

    pub fn evidence_binding_digest(&self) -> &Digest {
        &self.evidence_binding_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationState {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn receipt(&self) -> AwsAuditManagerRegistrationReceipt {
        AwsAuditManagerRegistrationReceipt {
            registration_digest: self.registration_digest.clone(),
            status: self.status,
            registration_revision: self.registration_revision,
            reversible: true,
            revocable: true,
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationState::Active)
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::expected_registration_digest(
            &self.id,
            &self.scope,
            &self.secret_reference,
            &self.permission_snapshot,
            &self.consent,
            &self.provider_digest,
            &self.evidence_binding_digest,
            self.registration_revision,
            match self.status {
                RegistrationState::Active => "active",
                RegistrationState::Revoked => "revoked",
                RegistrationState::Reversed => "reversed",
            },
        )
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        if self.registration_digest != self.recomputed_digest()
            || self.registration_revision == 0
            || self.scope.tenant_status() != crate::model::TenantStatus::Existing
            || self.assessment_digest != self.scope.assessment().digest()
            || self.framework_digest != self.scope.framework().digest()
            || self.control_set_digest != self.scope.control_set().digest()
            || self.report_digest != self.scope.report().digest()
            || self.mission_digest != self.scope.mission().digest()
            || self.project_digest != self.scope.project().digest()
            || self.work_product_digest != self.scope.work_product().digest()
        {
            return Err(AwsAuditManagerError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.secret_reference.validate_for(&self.scope)?;
        self.permission_snapshot.validate()?;
        if self.is_active() {
            self.consent.validate_at(now)?;
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationState::Reversed {
            return Err(AwsAuditManagerError::RegistrationReversed);
        }
        self.transition(RegistrationState::Active)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.secret_reference.revoke();
        self.transition_digest(RegistrationState::Revoked)
    }

    pub fn revoke_consent(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.consent.revoke();
        self.transition_digest(RegistrationState::Revoked)
    }

    fn transition(
        &mut self,
        new_status: RegistrationState,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationState::Reversed {
            return Err(AwsAuditManagerError::RegistrationReversed);
        }
        if self.status == new_status {
            return Err(match new_status {
                RegistrationState::Revoked => AwsAuditManagerError::RegistrationRevoked,
                RegistrationState::Reversed => AwsAuditManagerError::RegistrationReversed,
                RegistrationState::Active => AwsAuditManagerError::RegistrationInactive,
            });
        }
        self.transition_digest(new_status)
    }

    fn transition_digest(
        &mut self,
        new_status: RegistrationState,
    ) -> Result<RegistrationTransitionEvidence> {
        let previous_status = self.status;
        self.status = new_status;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.recomputed_digest();
        let transition_digest = Digest::from_parts(
            "aws-audit-manager-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("revision", self.registration_revision.to_string()),
                ("registration", self.registration_digest.as_str().to_owned()),
            ],
        );
        Ok(RegistrationTransitionEvidence {
            previous_status,
            new_status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAuditManagerRegistrationReceipt {
    pub registration_digest: Digest,
    pub status: RegistrationState,
    pub registration_revision: u64,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAuditManagerCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub certification_authority: bool,
    pub legal_advice: bool,
    pub outcome_adoption: bool,
}

pub type CapabilityDescription = AwsAuditManagerCapabilities;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationTampered,
    ScopeMismatch,
    ProviderDrift,
    ConsentExpired,
    EvidenceTampered,
    EvidenceExpired,
    PartialEvidence,
    NonAdoptableState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

pub type AwsAuditManagerVerificationReport = VerificationReport;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAuditManagerProposal {
    pub service_id: &'static str,
    pub consumer_id: &'static str,
    pub registration_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub request_digest: Digest,
    pub evidence: AuditManagerEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub legal_advice: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl AwsAuditManagerProposal {
    pub fn evidence_digest(&self) -> &Digest {
        self.evidence.digest()
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub(crate) fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-proposal/v1",
            &[
                ("service", self.service_id.to_owned()),
                ("consumer", self.consumer_id.to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "evidence_binding",
                    self.evidence_binding_digest.as_str().to_owned(),
                ),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("review_only", self.review_only.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        if self.service_id != AWS_AUDIT_MANAGER_SERVICE_ID
            || self.consumer_id != AWS_AUDIT_MANAGER_CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.certification_claim
            || self.legal_advice
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsAuditManagerResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AuditManagerEvidenceState,
    pub provenance: ProviderProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

pub type AwsAuditManagerRecordReceipt = RecordedAwsAuditManagerResult;
pub type AwsAuditManagerResult = AwsAuditManagerProposal;

impl RecordedAwsAuditManagerResult {
    pub(crate) fn new(
        key_digest: Digest,
        proposal: &AwsAuditManagerProposal,
        replayed: bool,
    ) -> Self {
        let mut value = Self {
            idempotency_key_digest: key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            state: proposal.evidence.state.clone(),
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::zero(),
        };
        value.recording_digest = value.recomputed_digest();
        value
    }

    pub(crate) fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-audit-manager-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.recomputed_digest()
        {
            return Err(AwsAuditManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct AwsAuditManagerService<
    T: AwsAuditManagerTransport = crate::provider::BlockedEnvTransport,
> {
    registration: AwsAuditManagerRegistration,
    provider: AwsAuditManagerProvider<T>,
    scope: AwsAuditManagerScope,
    now: DateTime<Utc>,
    recordings: BTreeMap<Digest, RecordedAwsAuditManagerResult>,
}

impl<T: AwsAuditManagerTransport> fmt::Debug for AwsAuditManagerService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAuditManagerService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("recording_count", &self.recordings.len())
            .finish()
    }
}

impl<T: AwsAuditManagerTransport> AwsAuditManagerService<T> {
    pub fn new(
        scope: AwsAuditManagerScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsAuditManagerProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let permission_snapshot = PermissionSnapshot::for_existing_tenant(1)?;
        Self::new_with_permissions(
            scope,
            secret_reference,
            consent,
            permission_snapshot,
            provider,
            now,
        )
    }

    pub fn new_with_permissions(
        scope: AwsAuditManagerScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        permission_snapshot: PermissionSnapshot,
        provider: AwsAuditManagerProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        provider
            .definition()
            .validate()
            .map_err(|_| AwsAuditManagerError::ProviderDrift)?;
        let provider_digest = provider.provider_digest();
        let registration = AwsAuditManagerRegistration::new(
            "aws-audit-manager-registration",
            scope.clone(),
            secret_reference,
            permission_snapshot,
            consent,
            provider_digest,
            now,
        )?;
        Ok(Self {
            registration,
            provider,
            scope,
            now,
            recordings: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsAuditManagerScope {
        &self.scope
    }

    pub fn provider(&self) -> &AwsAuditManagerProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsAuditManagerProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsAuditManagerRegistration {
        &self.registration
    }

    pub fn register(&self) -> AwsAuditManagerRegistrationReceipt {
        self.registration.receipt()
    }

    pub fn registration_receipt(&self) -> AwsAuditManagerRegistrationReceipt {
        self.registration.receipt()
    }

    pub fn describe_capabilities(&self) -> AwsAuditManagerCapabilities {
        AwsAuditManagerCapabilities {
            service_id: AWS_AUDIT_MANAGER_SERVICE_ID,
            provider_id: AWS_AUDIT_MANAGER_PROVIDER_ID,
            consumer_id: AWS_AUDIT_MANAGER_CONSUMER_ID,
            operations: vec![
                "ListAssessments".to_owned(),
                "GetAssessment".to_owned(),
                "ListAssessmentReports".to_owned(),
            ],
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            certification_authority: false,
            legal_advice: false,
            outcome_adoption: false,
        }
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsAuditManagerEvidenceRequest> {
        AwsAuditManagerEvidenceRequest::for_scope(&self.scope, observed_at)
    }

    pub fn read(
        &mut self,
        request: AwsAuditManagerReadRequest,
    ) -> std::result::Result<AwsAuditManagerReadResult, ProviderError> {
        self.ensure_active().map_err(ProviderError::Model)?;
        match &request {
            AwsAuditManagerReadRequest::ListAssessments(value) => value
                .validate_against(&self.scope)
                .map_err(ProviderError::Model)?,
            AwsAuditManagerReadRequest::GetAssessment(value) => value
                .validate_against(&self.scope)
                .map_err(ProviderError::Model)?,
            AwsAuditManagerReadRequest::ListAssessmentReports(value) => value
                .validate_against(&self.scope)
                .map_err(ProviderError::Model)?,
        }
        self.provider.read(&request)
    }

    pub fn read_bounded(
        &mut self,
        request: AwsAuditManagerReadRequest,
    ) -> std::result::Result<AwsAuditManagerReadResult, ProviderError> {
        self.read(request)
    }

    pub fn propose(
        &mut self,
        request: AwsAuditManagerEvidenceRequest,
    ) -> Result<AwsAuditManagerProposal> {
        self.ensure_active()?;
        request.validate_against(&self.scope)?;
        let mut provenance = self.provider.provenance();
        let empty = Digest::from_text("aws-audit-manager-no-evidence");
        let mut state = AuditManagerEvidenceState::InProgress;
        let mut failure: Option<ProviderFailure> = None;
        let mut assessment_status = None;
        let mut report_status = None;
        let mut assessment_revision = self.scope.assessment().revision();
        let mut framework_revision = self.scope.framework().revision();
        let mut control_set_revision = self.scope.control_set().revision();
        let mut report_revision = self.scope.report().revision();
        let mut period: Option<EvidencePeriod> = None;
        let mut list_digest = empty.clone();
        let mut assessment_digest = empty.clone();
        let mut control_result_digest = empty.clone();
        let mut report_digest = empty.clone();
        let mut list_pages = 0;
        let mut report_pages = 0;
        let mut pagination_complete = false;

        let assessments = match self.collect_assessments(&request.list_assessments) {
            Ok(value) => {
                provenance = value.provenance;
                list_pages = value.pages;
                list_digest = value.digest;
                pagination_complete = value.complete;
                value.items
            }
            Err(failed) => {
                failure = Some(failed.failure);
                state = failed.state;
                Vec::new()
            }
        };

        let selected = if failure.is_none() {
            match self.select_assessment(&assessments) {
                Ok(value) => {
                    assessment_status = Some(value.status);
                    assessment_revision = value.assessment.revision();
                    framework_revision = value.framework.revision();
                    control_set_revision = value.control_set.revision();
                    period = Some(value.evidence_period.clone());
                    assessment_digest = value.assessment_digest.clone();
                    control_result_digest = value.control_result_digest.clone();
                    if value.status.is_unknown() {
                        state = AuditManagerEvidenceState::ProviderUnknown;
                    } else if value.evidence_period.is_expired(request.observed_at) {
                        state = AuditManagerEvidenceState::Expired;
                    }
                    Some(value)
                }
                Err(selection) => {
                    state = selection;
                    None
                }
            }
        } else {
            None
        };

        if selected.is_some()
            && failure.is_none()
            && matches!(state, AuditManagerEvidenceState::ProviderUnknown)
        {
            // An unknown status is already a closed result.  It is not safe to
            // continue to a report read whose interpretation is uncertain.
        } else if selected.is_some() && failure.is_none() {
            match self.read_assessment(&request.get_assessment) {
                Ok(detail) => {
                    if let Err(drift) = self.validate_detail(&detail) {
                        state = drift;
                    } else {
                        assessment_digest = detail.assessment_detail_digest.clone();
                        control_result_digest = detail
                            .control_sets
                            .iter()
                            .map(|control_set| control_set.control_result_digest.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                            .pipe_digest();
                        if detail
                            .summary
                            .evidence_period
                            .is_expired(request.observed_at)
                        {
                            state = AuditManagerEvidenceState::Expired;
                        }
                    }
                }
                Err(error) => {
                    state = error.state;
                    failure = Some(error.failure);
                }
            }
        }

        if selected.is_some()
            && failure.is_none()
            && !matches!(
                state,
                AuditManagerEvidenceState::Expired
                    | AuditManagerEvidenceState::ProviderUnknown
                    | AuditManagerEvidenceState::AssessmentDrift
                    | AuditManagerEvidenceState::FrameworkDrift
                    | AuditManagerEvidenceState::ControlSetDrift
            )
        {
            match self.collect_reports(&request.list_assessment_reports) {
                Ok(value) => {
                    provenance = value.provenance;
                    report_pages = value.pages;
                    report_digest = value.digest;
                    pagination_complete &= value.complete;
                    match self.select_report(&value.items) {
                        Ok(report) => {
                            report_status = Some(report.status);
                            report_revision = report.report.revision();
                            report_digest = report.report_summary_digest.clone();
                            if report.assessment.id() != self.scope.assessment().id() {
                                state = AuditManagerEvidenceState::ReportDrift;
                            } else if report.evidence_period.is_expired(request.observed_at) {
                                state = AuditManagerEvidenceState::Expired;
                            } else {
                                match report.status {
                                    crate::model::ReportStatus::Complete => {
                                        state = if pagination_complete {
                                            AuditManagerEvidenceState::Complete
                                        } else {
                                            AuditManagerEvidenceState::Partial
                                        };
                                    }
                                    crate::model::ReportStatus::InProgress => {
                                        state = AuditManagerEvidenceState::InProgress;
                                    }
                                    crate::model::ReportStatus::Failed
                                    | crate::model::ReportStatus::Unknown => {
                                        state = AuditManagerEvidenceState::ProviderUnknown;
                                    }
                                }
                            }
                        }
                        Err(selection) => state = selection,
                    }
                }
                Err(error) => {
                    state = error.state;
                    failure = Some(error.failure);
                }
            }
        }

        let evidence = AuditManagerEvidence::new(
            state,
            assessment_status,
            report_status,
            assessment_revision,
            framework_revision,
            control_set_revision,
            report_revision,
            period,
            list_digest,
            assessment_digest,
            control_result_digest,
            report_digest,
            list_pages,
            report_pages,
            pagination_complete,
            provenance,
            failure,
        )?;
        let mut proposal = AwsAuditManagerProposal {
            service_id: AWS_AUDIT_MANAGER_SERVICE_ID,
            consumer_id: AWS_AUDIT_MANAGER_CONSUMER_ID,
            registration_digest: self.registration.registration_digest().clone(),
            evidence_binding_digest: self.registration.evidence_binding_digest().clone(),
            request_digest: request.request_digest.clone(),
            evidence,
            proposal_digest: Digest::zero(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            legal_advice: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        Ok(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsAuditManagerProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsAuditManagerResult> {
        self.ensure_active()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.evidence_binding_digest != *self.registration.evidence_binding_digest()
        {
            return Err(AwsAuditManagerError::ScopeMismatch);
        }
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > MAX_IDENTIFIER_BYTES || key.chars().any(char::is_control) {
            return Err(AwsAuditManagerError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.recordings.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsAuditManagerError::ReplayDetected);
            }
            let replay = RecordedAwsAuditManagerResult::new(key_digest.clone(), proposal, true);
            self.recordings.insert(key_digest, replay.clone());
            return Ok(replay);
        }
        let result = RecordedAwsAuditManagerResult::new(key_digest.clone(), proposal, false);
        self.recordings.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn verify(&self, proposal: &AwsAuditManagerProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if self.registration.registration_digest() != &self.registration.recomputed_digest() {
            failures.push(VerificationFailure::RegistrationTampered);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.evidence_binding_digest != *self.registration.evidence_binding_digest()
        {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if self.provider.provider_digest() != *self.registration.provider_digest() {
            failures.push(VerificationFailure::ProviderDrift);
        }
        if self.registration.consent().validate_at(self.now).is_err() {
            failures.push(VerificationFailure::ConsentExpired);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::EvidenceTampered);
        }
        if matches!(proposal.evidence.state, AuditManagerEvidenceState::Expired) {
            failures.push(VerificationFailure::EvidenceExpired);
        }
        if !proposal.evidence.pagination_complete {
            failures.push(VerificationFailure::PartialEvidence);
        }
        if !proposal.evidence.state.is_complete() {
            failures.push(VerificationFailure::NonAdoptableState);
        }
        let verification_digest = Digest::from_parts(
            "aws-audit-manager-verification/v1",
            &[
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
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
        VerificationReport {
            valid: failures.is_empty(),
            review_eligible: failures
                .iter()
                .all(|failure| !matches!(failure, VerificationFailure::EvidenceTampered)),
            failures,
            verification_digest,
        }
    }

    pub fn verify_proposal(&self, proposal: &AwsAuditManagerProposal) -> Result<()> {
        let report = self.verify(proposal);
        if report.valid {
            Ok(())
        } else if report
            .failures
            .iter()
            .any(|failure| matches!(failure, VerificationFailure::EvidenceTampered))
        {
            Err(AwsAuditManagerError::TamperedEvidence)
        } else {
            Err(AwsAuditManagerError::PartialEvidence)
        }
    }

    pub fn consumer(&self) -> Result<MissionAwsAuditManagerConsumer> {
        MissionAwsAuditManagerConsumer::new(self.scope.clone(), self.registration.clone()).map_err(
            |error| match error {
                crate::consumer::ConsumerError::Service(error) => error,
                crate::consumer::ConsumerError::RegistrationRevoked
                | crate::consumer::ConsumerError::RegistrationReversed
                | crate::consumer::ConsumerError::ScopeMismatch
                | crate::consumer::ConsumerError::ProposalTampered
                | crate::consumer::ConsumerError::RecordingConflict => {
                    AwsAuditManagerError::RegistrationInactive
                }
            },
        )
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke_registration()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse_registration()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.restore_registration()
    }

    pub fn revoke_secret_reference(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke_secret_reference()
    }

    pub fn revoke_consent(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke_consent()
    }

    pub fn recording_count(&self) -> usize {
        self.recordings.len()
    }

    fn ensure_active(&self) -> Result<()> {
        if self.scope.tenant_status() != crate::model::TenantStatus::Existing {
            return Err(match self.scope.tenant_status() {
                crate::model::TenantStatus::Unregistered => {
                    AwsAuditManagerError::UnregisteredAccount
                }
                crate::model::TenantStatus::NewCustomer => {
                    AwsAuditManagerError::NewCustomerNotEligible
                }
                crate::model::TenantStatus::Existing => AwsAuditManagerError::InvalidScope,
            });
        }
        if !self.registration.is_active() {
            return Err(match self.registration.status() {
                RegistrationState::Revoked => AwsAuditManagerError::RegistrationRevoked,
                RegistrationState::Reversed => AwsAuditManagerError::RegistrationReversed,
                RegistrationState::Active => AwsAuditManagerError::RegistrationInactive,
            });
        }
        self.registration.validate_at(self.now)
    }

    fn collect_assessments(
        &mut self,
        base: &crate::model::ListAssessmentsRequest,
    ) -> std::result::Result<CollectedAssessments, CollectionFailure> {
        let mut request = base.clone();
        let mut items = Vec::new();
        let mut page_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut pages = 0;
        let provenance = self.provider.provenance();
        loop {
            pages += 1;
            if pages > base.max_pages {
                return Err(CollectionFailure::partial(
                    AuditManagerOperation::ListAssessments,
                ));
            }
            let response = self
                .provider
                .read_list_assessments(&request)
                .map_err(|error| {
                    CollectionFailure::from_provider(AuditManagerOperation::ListAssessments, error)
                })?;
            page_digests.push(response.page_digest.clone());
            if response
                .assessments
                .iter()
                .any(|assessment| !base.status_filter.accepts(assessment.status))
            {
                return Err(CollectionFailure::filter(
                    AuditManagerOperation::ListAssessments,
                ));
            }
            if response
                .assessments
                .iter()
                .any(|assessment| assessment.validate(&self.scope).is_err())
            {
                return Err(CollectionFailure::invalid(
                    AuditManagerOperation::ListAssessments,
                ));
            }
            items.extend(response.assessments);
            if items.len() > crate::MAX_RESULT_DIGESTS {
                return Err(CollectionFailure::partial(
                    AuditManagerOperation::ListAssessments,
                ));
            }
            let Some(cursor) = response.next_cursor else {
                break;
            };
            if !seen_cursors.insert(cursor.digest()) {
                return Err(CollectionFailure::looped(
                    AuditManagerOperation::ListAssessments,
                ));
            }
            request = crate::model::ListAssessmentsRequest::new(
                &self.scope,
                base.status_filter,
                base.page_size,
                base.max_pages,
                Some(cursor),
            )
            .map_err(CollectionFailure::model)?;
        }
        Ok(CollectedAssessments {
            items,
            pages,
            complete: true,
            digest: Digest::from_parts(
                "aws-audit-manager-list-assessments-evidence/v1",
                &page_digests
                    .iter()
                    .enumerate()
                    .map(|(index, digest)| ("page", format!("{index}:{}", digest.as_str())))
                    .collect::<Vec<_>>(),
            ),
            provenance,
        })
    }

    fn collect_reports(
        &mut self,
        base: &crate::model::ListAssessmentReportsRequest,
    ) -> std::result::Result<CollectedReports, CollectionFailure> {
        let mut request = base.clone();
        let mut items = Vec::new();
        let mut page_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut pages = 0;
        let provenance = self.provider.provenance();
        loop {
            pages += 1;
            if pages > base.max_pages {
                return Err(CollectionFailure::partial(
                    AuditManagerOperation::ListAssessmentReports,
                ));
            }
            let response = self
                .provider
                .read_list_assessment_reports(&request)
                .map_err(|error| {
                    CollectionFailure::from_provider(
                        AuditManagerOperation::ListAssessmentReports,
                        error,
                    )
                })?;
            page_digests.push(response.page_digest.clone());
            if response
                .reports
                .iter()
                .any(|report| !base.status_filter.accepts(report.status))
            {
                return Err(CollectionFailure::filter(
                    AuditManagerOperation::ListAssessmentReports,
                ));
            }
            if response
                .reports
                .iter()
                .any(|report| report.validate(&self.scope).is_err())
            {
                return Err(CollectionFailure::invalid(
                    AuditManagerOperation::ListAssessmentReports,
                ));
            }
            items.extend(response.reports);
            if items.len() > crate::MAX_REPORTS {
                return Err(CollectionFailure::partial(
                    AuditManagerOperation::ListAssessmentReports,
                ));
            }
            let Some(cursor) = response.next_cursor else {
                break;
            };
            if !seen_cursors.insert(cursor.digest()) {
                return Err(CollectionFailure::looped(
                    AuditManagerOperation::ListAssessmentReports,
                ));
            }
            request = crate::model::ListAssessmentReportsRequest::new(
                &self.scope,
                base.status_filter,
                base.page_size,
                base.max_pages,
                Some(cursor),
            )
            .map_err(CollectionFailure::model)?;
        }
        Ok(CollectedReports {
            items,
            pages,
            complete: true,
            digest: Digest::from_parts(
                "aws-audit-manager-list-assessment-reports-evidence/v1",
                &page_digests
                    .iter()
                    .enumerate()
                    .map(|(index, digest)| ("page", format!("{index}:{}", digest.as_str())))
                    .collect::<Vec<_>>(),
            ),
            provenance,
        })
    }

    fn select_assessment(
        &self,
        items: &[crate::model::AssessmentSummary],
    ) -> std::result::Result<crate::model::AssessmentSummary, AuditManagerEvidenceState> {
        let Some(assessment) = items
            .iter()
            .find(|assessment| assessment.assessment.id() == self.scope.assessment().id())
        else {
            return Err(AuditManagerEvidenceState::NotFound);
        };
        if assessment.assessment.revision() != self.scope.assessment().revision() {
            return Err(AuditManagerEvidenceState::AssessmentDrift);
        }
        if assessment.framework.id() != self.scope.framework().id()
            || assessment.framework.revision() != self.scope.framework().revision()
        {
            return Err(AuditManagerEvidenceState::FrameworkDrift);
        }
        if assessment.control_set.id() != self.scope.control_set().id()
            || assessment.control_set.revision() != self.scope.control_set().revision()
        {
            return Err(AuditManagerEvidenceState::ControlSetDrift);
        }
        Ok(assessment.clone())
    }

    fn read_assessment(
        &mut self,
        request: &crate::model::GetAssessmentRequest,
    ) -> std::result::Result<AssessmentDetail, CollectionFailure> {
        let response = self
            .provider
            .read_get_assessment(request)
            .map_err(|error| {
                CollectionFailure::from_provider(AuditManagerOperation::GetAssessment, error)
            })?;
        response
            .assessment
            .validate(&self.scope)
            .map_err(|_| CollectionFailure::invalid(AuditManagerOperation::GetAssessment))?;
        Ok(response.assessment)
    }

    fn validate_detail(
        &self,
        detail: &AssessmentDetail,
    ) -> std::result::Result<(), AuditManagerEvidenceState> {
        if detail.summary.assessment.id() != self.scope.assessment().id()
            || detail.summary.assessment.revision() != self.scope.assessment().revision()
        {
            return Err(AuditManagerEvidenceState::AssessmentDrift);
        }
        if detail.summary.framework.id() != self.scope.framework().id()
            || detail.summary.framework.revision() != self.scope.framework().revision()
        {
            return Err(AuditManagerEvidenceState::FrameworkDrift);
        }
        if detail.summary.control_set.id() != self.scope.control_set().id()
            || detail.summary.control_set.revision() != self.scope.control_set().revision()
        {
            return Err(AuditManagerEvidenceState::ControlSetDrift);
        }
        if detail.control_sets.iter().any(|control_set| {
            control_set.control_set.id() != self.scope.control_set().id()
                || control_set.control_set.revision() != self.scope.control_set().revision()
        }) {
            return Err(AuditManagerEvidenceState::ControlSetDrift);
        }
        Ok(())
    }

    fn select_report(
        &self,
        items: &[AssessmentReportSummary],
    ) -> std::result::Result<AssessmentReportSummary, AuditManagerEvidenceState> {
        let Some(report) = items
            .iter()
            .find(|report| report.report.id() == self.scope.report().id())
        else {
            return Err(AuditManagerEvidenceState::NotFound);
        };
        if report.validate(&self.scope).is_err() {
            return Err(AuditManagerEvidenceState::ProviderUnknown);
        }
        if report.report.revision() != self.scope.report().revision() {
            return Err(AuditManagerEvidenceState::ReportDrift);
        }
        if report.assessment.id() != self.scope.assessment().id()
            || report.assessment.revision() != self.scope.assessment().revision()
        {
            return Err(AuditManagerEvidenceState::ReportDrift);
        }
        Ok(report.clone())
    }
}

#[derive(Clone, Debug)]
struct CollectedAssessments {
    items: Vec<crate::model::AssessmentSummary>,
    pages: u16,
    complete: bool,
    digest: Digest,
    provenance: ProviderProvenance,
}

#[derive(Clone, Debug)]
struct CollectedReports {
    items: Vec<AssessmentReportSummary>,
    pages: u16,
    complete: bool,
    digest: Digest,
    provenance: ProviderProvenance,
}

#[derive(Clone, Debug)]
struct CollectionFailure {
    state: AuditManagerEvidenceState,
    failure: ProviderFailure,
}

impl CollectionFailure {
    fn from_provider(operation: AuditManagerOperation, error: ProviderError) -> Self {
        match error {
            ProviderError::Transport(transport) => Self {
                state: state_for_transport(&transport),
                failure: ProviderFailure::from_transport(operation, &transport),
            },
            ProviderError::Model(_)
            | ProviderError::DefinitionInvalid
            | ProviderError::DefinitionDrift => Self {
                state: AuditManagerEvidenceState::ProviderUnknown,
                failure: ProviderFailure {
                    operation,
                    category: "invalid_provider_response".to_owned(),
                    status_code: None,
                    retryable: false,
                },
            },
            ProviderError::InvalidRequest
            | ProviderError::InvalidResponse
            | ProviderError::RequestMismatch => Self {
                state: AuditManagerEvidenceState::ProviderUnknown,
                failure: ProviderFailure {
                    operation,
                    category: "invalid_provider_response".to_owned(),
                    status_code: None,
                    retryable: false,
                },
            },
        }
    }

    fn partial(operation: AuditManagerOperation) -> Self {
        Self {
            state: AuditManagerEvidenceState::Partial,
            failure: ProviderFailure {
                operation,
                category: "partial".to_owned(),
                status_code: None,
                retryable: false,
            },
        }
    }

    fn filter(operation: AuditManagerOperation) -> Self {
        Self {
            state: AuditManagerEvidenceState::ProviderUnknown,
            failure: ProviderFailure {
                operation,
                category: "filter_mismatch".to_owned(),
                status_code: None,
                retryable: false,
            },
        }
    }

    fn invalid(operation: AuditManagerOperation) -> Self {
        Self {
            state: AuditManagerEvidenceState::ProviderUnknown,
            failure: ProviderFailure {
                operation,
                category: "invalid_provider_response".to_owned(),
                status_code: None,
                retryable: false,
            },
        }
    }

    fn looped(operation: AuditManagerOperation) -> Self {
        Self {
            state: AuditManagerEvidenceState::Partial,
            failure: ProviderFailure {
                operation,
                category: "pagination_loop".to_owned(),
                status_code: None,
                retryable: false,
            },
        }
    }

    fn model(error: AwsAuditManagerError) -> Self {
        Self {
            state: AuditManagerEvidenceState::ProviderUnknown,
            failure: ProviderFailure {
                operation: AuditManagerOperation::ListAssessments,
                category: format!("model:{error:?}"),
                status_code: None,
                retryable: false,
            },
        }
    }
}

fn state_for_transport(error: &AwsAuditManagerTransportError) -> AuditManagerEvidenceState {
    match error {
        AwsAuditManagerTransportError::Unauthorized
        | AwsAuditManagerTransportError::Forbidden
        | AwsAuditManagerTransportError::AccessLoss => AuditManagerEvidenceState::AccessLoss,
        AwsAuditManagerTransportError::NotFound => AuditManagerEvidenceState::NotFound,
        AwsAuditManagerTransportError::RateLimited { .. } => AuditManagerEvidenceState::Throttled,
        AwsAuditManagerTransportError::Partial => AuditManagerEvidenceState::Partial,
        AwsAuditManagerTransportError::BlockedEnv
        | AwsAuditManagerTransportError::BadRequest
        | AwsAuditManagerTransportError::ServerError { .. }
        | AwsAuditManagerTransportError::Timeout
        | AwsAuditManagerTransportError::InvalidResponse => {
            AuditManagerEvidenceState::ProviderUnknown
        }
    }
}

trait PipeDigest {
    fn pipe_digest(self) -> Digest;
}

impl PipeDigest for String {
    fn pipe_digest(self) -> Digest {
        Digest::from_text(self)
    }
}
