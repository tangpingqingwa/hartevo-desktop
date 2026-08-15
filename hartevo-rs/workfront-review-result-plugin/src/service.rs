//! Typed service, bounded proposal, verification, and reversible registration.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionWorkfrontReviewConsumer;
use crate::error::{Result, WorkfrontReviewResultError, WorkfrontTransportError};
use crate::model::{
    ApprovalProjection, ApprovalSnapshot, ConsentScope, CostReceipt, DecisionKind,
    DecisionTimestamp, Digest, EvidenceDigests, EvidenceState, HostProjectProjection,
    MissionProjection, PermissionSnapshot, ProjectProjection, ProjectSnapshot, RequestReceipt,
    ReviewProjection, ReviewSnapshot, SecretReference, TaskProjection, TaskSnapshot,
    TransportProvenance, WorkProductProjection, WorkfrontReviewScope, mission_projection,
    project_projection, work_product_projection,
};
use crate::provider::{
    WorkfrontOperation, WorkfrontProvider, WorkfrontProviderDefinition, WorkfrontReadRequest,
    WorkfrontTransport,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
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
            "workfront-registration-transition/v1",
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

/// Version/contract/provider/permission/consent/scope/secret-bound
/// registration. Only secret and identifier digests are serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkfrontReviewRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: WorkfrontReviewScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl WorkfrontReviewRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: WorkfrontReviewScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &WorkfrontProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(WorkfrontReviewResultError::InvalidRegistration);
        }
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.provider_release.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-workfront-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
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

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest().clone()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &WorkfrontReviewScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
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
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > crate::MAX_IDENTIFIER_BYTES
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(WorkfrontReviewResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        if self.consent.permission_digest() != self.permission_snapshot.digest() {
            return Err(WorkfrontReviewResultError::InvalidConsent);
        }
        self.secret_reference.validate(&self.scope)?;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(WorkfrontReviewResultError::RegistrationReversed);
        }
        let previous = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(WorkfrontReviewResultError::RegistrationReversed);
        }
        let previous = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse()
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(WorkfrontReviewResultError::RegistrationReversed);
        }
        let previous = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.restore()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
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

impl fmt::Debug for WorkfrontReviewRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkfrontReviewRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for WorkfrontReviewRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("WorkfrontReviewRegistration", 15)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub document_bytes: bool,
    pub approval_effects: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkfrontEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<crate::model::Cursor>,
    pub observed_at: DateTime<Utc>,
}

impl WorkfrontEvidenceRequest {
    pub fn new(
        scope: &WorkfrontReviewScope,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        page_size: u16,
        max_pages: u16,
        cursor: Option<crate::model::Cursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if page_size == 0
            || page_size > crate::MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > crate::MAX_PAGES
        {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        if let Some(cursor) = &cursor
            && cursor.scope_digest() != &scope.digest()
        {
            return Err(WorkfrontReviewResultError::CursorMismatch);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest,
            expected_registration_digest,
            page_size,
            max_pages,
            cursor,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: WorkfrontOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: WorkfrontOperation, error: &WorkfrontTransportError) -> Self {
        let category = match error {
            WorkfrontTransportError::BlockedEnv => "blocked_env",
            WorkfrontTransportError::BadRequest => "bad_request",
            WorkfrontTransportError::Unauthorized => "unauthorized",
            WorkfrontTransportError::Forbidden => "forbidden",
            WorkfrontTransportError::NotFound => "not_found",
            WorkfrontTransportError::Conflict => "conflict",
            WorkfrontTransportError::RateLimited { .. } => "throttled",
            WorkfrontTransportError::ServerError { .. } => "server_error",
            WorkfrontTransportError::Timeout => "timeout",
            WorkfrontTransportError::AccessLost => "access_loss",
            WorkfrontTransportError::Partial => "partial",
            WorkfrontTransportError::Unknown => "provider_unknown",
            WorkfrontTransportError::InvalidResponse => "invalid_response",
            WorkfrontTransportError::Tampered => "tampered",
            WorkfrontTransportError::StaleState => "stale_state",
            WorkfrontTransportError::PaginationLoop => "pagination_loop",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "workfront-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", category.clone()),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |status| status.to_string()),
                ),
            ],
        );
        Self {
            operation,
            status_code: error.status_code(),
            category,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkfrontReviewProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub tenant_digest: Digest,
    pub project_digest: Digest,
    pub task_digest: Digest,
    pub document_digest: Digest,
    pub review_digest: Digest,
    pub approval_digest: Digest,
    pub assignee_digest: Digest,
    pub time_window_digest: Digest,
    pub mission: MissionProjection,
    pub project: HostProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub pages: u16,
    pub pagination_complete: bool,
    pub project_state: Option<ProjectProjection>,
    pub task_state: Option<TaskProjection>,
    pub review_state: Option<ReviewProjection>,
    pub approval_state: Option<ApprovalProjection>,
    pub decision_timestamps: Vec<DecisionTimestamp>,
    pub reviewer_role_digests: Vec<Digest>,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub approval_effect: bool,
    pub document_bytes_retained: bool,
    pub reviewer_pii_retained: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl WorkfrontReviewProposal {
    fn build(
        registration: &WorkfrontReviewRegistration,
        provider: &WorkfrontProviderDefinition,
        request: &WorkfrontEvidenceRequest,
        state: EvidenceState,
        pages: u16,
        pagination_complete: bool,
        project: Option<&ProjectSnapshot>,
        task: Option<&TaskSnapshot>,
        review: Option<&ReviewSnapshot>,
        approval: Option<&ApprovalSnapshot>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            project_read_digest: project.map(ProjectSnapshot::digest),
            task_read_digest: task.map(TaskSnapshot::digest),
            review_read_digest: review.map(ReviewSnapshot::digest),
            approval_read_digest: approval.map(ApprovalSnapshot::digest),
            pagination_digest: Digest::from_parts(
                "workfront-pagination/v1",
                &[
                    ("request", request.digest().as_str().to_owned()),
                    ("pages", pages.to_string()),
                    ("complete", pagination_complete.to_string()),
                ],
            ),
            evidence_digest: Digest::from_text("unsealed-workfront-evidence"),
        };
        evidence.evidence_digest = evidence.calculate_digest(state, pages, pagination_complete);

        let project_state = project.map(ProjectProjection::from_snapshot);
        let task_state = task.map(TaskProjection::from_snapshot);
        let review_state = review.map(ReviewProjection::from_snapshot);
        let approval_state = approval.map(ApprovalProjection::from_snapshot);
        let decision_timestamps = decision_timestamps(review, approval);
        let reviewer_role_digests = reviewer_role_digests(review, approval);
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            tenant_digest: registration.scope.tenant().digest(),
            project_digest: registration.scope.project().digest(),
            task_digest: registration.scope.task().digest(),
            document_digest: registration.scope.document().digest(),
            review_digest: registration.scope.review().digest(),
            approval_digest: registration.scope.approval().digest(),
            assignee_digest: registration.scope.assignee().digest(),
            time_window_digest: registration.scope.time_window().digest(),
            mission: mission_projection(registration.scope.mission()),
            project: project_projection(registration.scope.host_project()),
            work_product: work_product_projection(registration.scope.work_product()),
            state,
            pages,
            pagination_complete,
            project_state,
            task_state,
            review_state,
            approval_state,
            decision_timestamps,
            reviewer_role_digests,
            request_receipts,
            cost_receipts,
            failure,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            approval_effect: false,
            document_bytes_retained: false,
            reviewer_pii_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-workfront-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-review-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("pages", self.pages.to_string()),
                ("complete", self.pagination_complete.to_string()),
                (
                    "project",
                    self.project_state
                        .as_ref()
                        .map_or_else(String::new, |value| format!("{:?}", value.status)),
                ),
                (
                    "task",
                    self.task_state
                        .as_ref()
                        .map_or_else(String::new, |value| format!("{:?}", value.status)),
                ),
                (
                    "review",
                    self.review_state
                        .as_ref()
                        .map_or_else(String::new, |value| format!("{:?}", value.status)),
                ),
                (
                    "approval",
                    self.approval_state
                        .as_ref()
                        .map_or_else(String::new, |value| format!("{:?}", value.status)),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence.contract_digest.as_str() != CONTRACT_DIGEST
            || self.evidence.scope_digest != self.scope_digest
            || self.reviewer_role_digests.len() > crate::MAX_REVIEWER_ROLE_DIGESTS
        {
            return Err(WorkfrontReviewResultError::TamperedEvidence);
        }
        self.evidence.contract_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.consent_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.pagination_digest.validate()?;
        self.evidence.evidence_digest.validate()?;
        for digest in [
            self.evidence.project_read_digest.as_ref(),
            self.evidence.task_read_digest.as_ref(),
            self.evidence.review_read_digest.as_ref(),
            self.evidence.approval_read_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        for receipt in &self.request_receipts {
            if receipt.operation.is_empty()
                || !receipt.redacted
                || receipt.raw_path_retained
                || receipt.authorization_retained
            {
                return Err(WorkfrontReviewResultError::TamperedEvidence);
            }
            receipt.request_digest.validate()?;
            receipt.path_digest.validate()?;
            receipt.scope_digest.validate()?;
            if let Some(cursor) = &receipt.cursor_digest {
                cursor.validate()?;
            }
        }
        for receipt in &self.cost_receipts {
            if receipt.operation.is_empty()
                || receipt.response_bytes == 0
                || receipt.response_bytes > crate::MAX_RESPONSE_BYTES
                || !receipt.redacted
                || !receipt.estimate_only
                || receipt.durable_provider_receipt
            {
                return Err(WorkfrontReviewResultError::TamperedEvidence);
            }
            receipt.cost_digest.validate()?;
        }
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.approval_effect
            || self.document_bytes_retained
            || self.reviewer_pii_retained
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.evidence_digest
                != self
                    .evidence
                    .calculate_digest(self.state, self.pages, self.pagination_complete)
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(WorkfrontReviewResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

fn decision_timestamps(
    review: Option<&ReviewSnapshot>,
    approval: Option<&ApprovalSnapshot>,
) -> Vec<DecisionTimestamp> {
    let mut values = Vec::new();
    if let Some(review) = review.and_then(|value| value.decision_at) {
        values.push(DecisionTimestamp {
            kind: DecisionKind::Review,
            timestamp: review,
        });
    }
    if let Some(approval) = approval.and_then(|value| value.decision_at) {
        values.push(DecisionTimestamp {
            kind: DecisionKind::Approval,
            timestamp: approval,
        });
    }
    values
}

fn reviewer_role_digests(
    review: Option<&ReviewSnapshot>,
    approval: Option<&ApprovalSnapshot>,
) -> Vec<Digest> {
    let mut values = BTreeSet::new();
    if let Some(review) = review {
        values.extend(review.reviewer_role_digests.iter().cloned());
    }
    if let Some(approval) = approval {
        values.extend(approval.reviewer_role_digests.iter().cloned());
    }
    values
        .into_iter()
        .take(crate::MAX_REVIEWER_ROLE_DIGESTS)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationFailure {
    pub code: String,
    pub digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub provider_readback_performed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkfrontRecordReceipt {
    pub proposal_digest: Digest,
    pub recording_digest: Digest,
    pub recorded: bool,
    pub provider_mutated: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

/// Typed Workfront service over one exact registration and provider.
pub struct WorkfrontReviewResultService<T> {
    scope: WorkfrontReviewScope,
    secret_reference: SecretReference,
    consent: ConsentScope,
    provider: WorkfrontProvider<T>,
    registration: WorkfrontReviewRegistration,
    observed_at: DateTime<Utc>,
}

impl<T: WorkfrontTransport> fmt::Debug for WorkfrontReviewResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkfrontReviewResultService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl<T: WorkfrontTransport> WorkfrontReviewResultService<T> {
    pub fn new(
        scope: WorkfrontReviewScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: WorkfrontProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate(&scope)?;
        consent.validate()?;
        provider.definition().validate()?;
        let permission_snapshot = PermissionSnapshot::layer_one();
        let registration = WorkfrontReviewRegistration::new(
            "workfront-registration-1",
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
            observed_at,
        })
    }

    pub fn scope(&self) -> &WorkfrontReviewScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn provider(&self) -> &WorkfrontProvider<T> {
        &self.provider
    }

    pub fn registration(&self) -> &WorkfrontReviewRegistration {
        &self.registration
    }

    pub fn register(&self) -> Result<WorkfrontReviewRegistration> {
        self.registration.validate()?;
        Ok(self.registration.clone())
    }

    pub fn registration_mut(&mut self) -> &mut WorkfrontReviewRegistration {
        &mut self.registration
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "read_project".to_owned(),
                "read_task".to_owned(),
                "read_review".to_owned(),
                "read_approval".to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            document_bytes: false,
            approval_effects: false,
        }
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<WorkfrontEvidenceRequest> {
        self.request(crate::MAX_PAGE_SIZE, crate::MAX_PAGES, observed_at)
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<WorkfrontEvidenceRequest> {
        WorkfrontEvidenceRequest::new(
            &self.scope,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest.clone(),
            page_size,
            max_pages,
            None,
            observed_at,
        )
    }

    pub fn read_project(&mut self, request: &WorkfrontEvidenceRequest) -> Result<ProjectSnapshot> {
        self.ensure_ready(request)?;
        let read_request = self.read_request(
            request,
            WorkfrontOperation::ReadProject,
            1,
            request.cursor.clone(),
        )?;
        let response = self.provider.read_project(&read_request)?;
        response.validate(&read_request)?;
        self.validate_project(&response.project)?;
        Ok(response.project)
    }

    pub fn read_task(&mut self, request: &WorkfrontEvidenceRequest) -> Result<TaskSnapshot> {
        self.ensure_ready(request)?;
        let read_request = self.read_request(
            request,
            WorkfrontOperation::ReadTask,
            1,
            request.cursor.clone(),
        )?;
        let response = self.provider.read_task(&read_request)?;
        response.validate(&read_request)?;
        self.validate_task(&response.task)?;
        Ok(response.task)
    }

    pub fn read_review(&mut self, request: &WorkfrontEvidenceRequest) -> Result<ReviewSnapshot> {
        self.ensure_ready(request)?;
        let read_request = self.read_request(
            request,
            WorkfrontOperation::ReadReview,
            1,
            request.cursor.clone(),
        )?;
        let response = self.provider.read_review(&read_request)?;
        response.validate(&read_request)?;
        self.validate_review(&response.review)?;
        Ok(response.review)
    }

    pub fn read_approval(
        &mut self,
        request: &WorkfrontEvidenceRequest,
    ) -> Result<ApprovalSnapshot> {
        self.ensure_ready(request)?;
        let read_request = self.read_request(
            request,
            WorkfrontOperation::ReadApproval,
            1,
            request.cursor.clone(),
        )?;
        let response = self.provider.read_approval(&read_request)?;
        response.validate(&read_request)?;
        self.validate_approval(&response.approval)?;
        Ok(response.approval)
    }

    pub fn propose(
        &mut self,
        request: WorkfrontEvidenceRequest,
    ) -> Result<WorkfrontReviewProposal> {
        self.ensure_ready(&request)?;
        if !self.scope.time_window().contains(request.observed_at) {
            return Ok(self.build_failure_proposal(
                &request,
                EvidenceState::Expired,
                0,
                true,
                None,
                None,
                None,
                None,
                Some(FailureEvidence {
                    operation: WorkfrontOperation::ReadProject,
                    status_code: None,
                    category: "expired".to_owned(),
                    failure_digest: Digest::from_text("workfront-expired"),
                }),
                Vec::new(),
                Vec::new(),
            ));
        }

        let mut page = 1;
        let mut cursor = request.cursor.clone();
        let mut seen_cursors = BTreeSet::new();
        let mut pagination_complete = false;
        let mut project = None;
        let mut task = None;
        let mut review = None;
        let mut approval = None;
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();

        loop {
            let project_request = self.read_request(
                &request,
                WorkfrontOperation::ReadProject,
                page,
                cursor.clone(),
            )?;
            let project_response = match self.provider.read_project(&project_request) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(self.failure_from_provider_error(
                        &request,
                        page,
                        pagination_complete,
                        project.as_ref(),
                        task.as_ref(),
                        review.as_ref(),
                        approval.as_ref(),
                        WorkfrontOperation::ReadProject,
                        error,
                        request_receipts,
                        cost_receipts,
                    ));
                }
            };
            if let Err(error) = project_response.validate(&project_request) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadProject,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            if let Err(error) = self.validate_project(&project_response.project) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadProject,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            push_receipts(
                &mut request_receipts,
                &mut cost_receipts,
                &project_request,
                project_response.response_bytes,
                &self.scope,
            )?;
            project = Some(project_response.project.clone());

            let task_request =
                self.read_request(&request, WorkfrontOperation::ReadTask, page, cursor.clone())?;
            let task_response = match self.provider.read_task(&task_request) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(self.failure_from_provider_error(
                        &request,
                        page,
                        false,
                        project.as_ref(),
                        task.as_ref(),
                        review.as_ref(),
                        approval.as_ref(),
                        WorkfrontOperation::ReadTask,
                        error,
                        request_receipts,
                        cost_receipts,
                    ));
                }
            };
            if let Err(error) = task_response.validate(&task_request) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadTask,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            if let Err(error) = self.validate_task(&task_response.task) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadTask,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            push_receipts(
                &mut request_receipts,
                &mut cost_receipts,
                &task_request,
                task_response.response_bytes,
                &self.scope,
            )?;
            task = Some(task_response.task.clone());

            let review_request = self.read_request(
                &request,
                WorkfrontOperation::ReadReview,
                page,
                cursor.clone(),
            )?;
            let review_response = match self.provider.read_review(&review_request) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(self.failure_from_provider_error(
                        &request,
                        page,
                        false,
                        project.as_ref(),
                        task.as_ref(),
                        review.as_ref(),
                        approval.as_ref(),
                        WorkfrontOperation::ReadReview,
                        error,
                        request_receipts,
                        cost_receipts,
                    ));
                }
            };
            if let Err(error) = review_response.validate(&review_request) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadReview,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            if let Err(error) = self.validate_review(&review_response.review) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadReview,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            push_receipts(
                &mut request_receipts,
                &mut cost_receipts,
                &review_request,
                review_response.response_bytes,
                &self.scope,
            )?;
            review = Some(review_response.review.clone());

            let approval_request = self.read_request(
                &request,
                WorkfrontOperation::ReadApproval,
                page,
                cursor.clone(),
            )?;
            let approval_response = match self.provider.read_approval(&approval_request) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(self.failure_from_provider_error(
                        &request,
                        page,
                        false,
                        project.as_ref(),
                        task.as_ref(),
                        review.as_ref(),
                        approval.as_ref(),
                        WorkfrontOperation::ReadApproval,
                        error,
                        request_receipts,
                        cost_receipts,
                    ));
                }
            };
            if let Err(error) = approval_response.validate(&approval_request) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadApproval,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            if let Err(error) = self.validate_approval(&approval_response.approval) {
                return Ok(self.failure_from_local(
                    &request,
                    EvidenceState::Tampered,
                    page,
                    false,
                    project.as_ref(),
                    task.as_ref(),
                    review.as_ref(),
                    approval.as_ref(),
                    WorkfrontOperation::ReadApproval,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
            push_receipts(
                &mut request_receipts,
                &mut cost_receipts,
                &approval_request,
                approval_response.response_bytes,
                &self.scope,
            )?;
            approval = Some(approval_response.approval.clone());

            let next = consistent_cursor(&[
                project_response.next_cursor.clone(),
                task_response.next_cursor.clone(),
                review_response.next_cursor.clone(),
                approval_response.next_cursor.clone(),
            ]);
            let next = match next {
                Ok(value) => value,
                Err(error) => {
                    return Ok(self.failure_from_local(
                        &request,
                        EvidenceState::Tampered,
                        page,
                        false,
                        project.as_ref(),
                        task.as_ref(),
                        review.as_ref(),
                        approval.as_ref(),
                        WorkfrontOperation::ReadProject,
                        error,
                        request_receipts,
                        cost_receipts,
                    ));
                }
            };
            if let Some(next) = next {
                if !seen_cursors.insert(next.digest().clone()) {
                    return Ok(self.failure_from_local(
                        &request,
                        EvidenceState::Tampered,
                        page,
                        false,
                        project.as_ref(),
                        task.as_ref(),
                        review.as_ref(),
                        approval.as_ref(),
                        WorkfrontOperation::ReadProject,
                        WorkfrontReviewResultError::PaginationLoop,
                        request_receipts,
                        cost_receipts,
                    ));
                }
                if page >= request.max_pages {
                    pagination_complete = false;
                    break;
                }
                cursor = Some(next);
                page += 1;
            } else {
                pagination_complete = true;
                break;
            }
        }

        let state = derive_state(
            project.as_ref().expect("project after successful reads"),
            task.as_ref().expect("task after successful reads"),
            review.as_ref().expect("review after successful reads"),
            approval.as_ref().expect("approval after successful reads"),
            request.observed_at,
        );
        Ok(WorkfrontReviewProposal::build(
            &self.registration,
            self.provider.definition(),
            &request,
            if pagination_complete {
                state
            } else {
                EvidenceState::Partial
            },
            page,
            pagination_complete,
            project.as_ref(),
            task.as_ref(),
            review.as_ref(),
            approval.as_ref(),
            None,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        ))
    }

    pub fn verify(&self, proposal: &WorkfrontReviewProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if let Err(error) = proposal.validate_integrity() {
            failures.push(verification_failure("proposal_integrity", &error));
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.provider_digest != *self.provider.definition().provider_digest()
        {
            failures.push(VerificationFailure {
                code: "binding_mismatch".to_owned(),
                digest: Digest::from_text("workfront-binding-mismatch"),
            });
        }
        if !self.registration.is_active() {
            failures.push(VerificationFailure {
                code: "registration_revoked".to_owned(),
                digest: Digest::from_text("workfront-registration-revoked"),
            });
        }
        let review_eligible = failures.is_empty()
            && proposal.pagination_complete
            && !matches!(
                proposal.state,
                EvidenceState::Partial
                    | EvidenceState::AccessLost
                    | EvidenceState::ProviderUnknown
                    | EvidenceState::Tampered
                    | EvidenceState::Expired
                    | EvidenceState::Revoked
            );
        VerificationReport {
            valid: failures.is_empty(),
            review_eligible,
            failures,
            provider_readback_performed: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
            work_product_adopted: false,
        }
    }

    pub fn record(&self, proposal: &WorkfrontReviewProposal) -> Result<WorkfrontRecordReceipt> {
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest() {
            return Err(WorkfrontReviewResultError::ScopeMismatch);
        }
        Ok(WorkfrontRecordReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            recording_digest: Digest::from_parts(
                "workfront-recording/v1",
                &[
                    ("proposal", proposal.proposal_digest.as_str().to_owned()),
                    ("scope", proposal.scope_digest.as_str().to_owned()),
                ],
            ),
            recorded: true,
            provider_mutated: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    pub fn consumer(&self) -> Result<MissionWorkfrontReviewConsumer> {
        MissionWorkfrontReviewConsumer::new(self.scope.clone(), self.registration.clone())
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

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke_registration()
    }

    fn ensure_ready(&self, request: &WorkfrontEvidenceRequest) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(WorkfrontReviewResultError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(WorkfrontReviewResultError::SecretRevoked);
        }
        if !self.consent.is_valid_at(request.observed_at) {
            return Err(WorkfrontReviewResultError::ConsentExpired);
        }
        if request.scope_digest != self.scope.digest()
            || request.expected_provider_digest != *self.provider.definition().provider_digest()
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(WorkfrontReviewResultError::ScopeMismatch);
        }
        Ok(())
    }

    fn read_request(
        &self,
        request: &WorkfrontEvidenceRequest,
        operation: WorkfrontOperation,
        page: u16,
        cursor: Option<crate::model::Cursor>,
    ) -> Result<WorkfrontReadRequest> {
        WorkfrontReadRequest::new(
            operation,
            &self.scope,
            &self.registration.registration_digest,
            request.page_size,
            page,
            cursor,
            request.observed_at,
        )
    }

    fn validate_project(&self, snapshot: &ProjectSnapshot) -> Result<()> {
        if snapshot.id != *self.scope.project()
            || snapshot.revision != self.scope.revision_fences().project
        {
            return Err(WorkfrontReviewResultError::StaleState);
        }
        Ok(())
    }

    fn validate_task(&self, snapshot: &TaskSnapshot) -> Result<()> {
        if snapshot.id != *self.scope.task()
            || snapshot.revision != self.scope.revision_fences().task
        {
            return Err(WorkfrontReviewResultError::StaleState);
        }
        Ok(())
    }

    fn validate_review(&self, snapshot: &ReviewSnapshot) -> Result<()> {
        if snapshot.id != *self.scope.review()
            || snapshot.revision != self.scope.revision_fences().review
        {
            return Err(WorkfrontReviewResultError::StaleState);
        }
        Ok(())
    }

    fn validate_approval(&self, snapshot: &ApprovalSnapshot) -> Result<()> {
        if snapshot.id != *self.scope.approval()
            || snapshot.revision != self.scope.revision_fences().approval
        {
            return Err(WorkfrontReviewResultError::StaleState);
        }
        Ok(())
    }

    fn build_failure_proposal(
        &self,
        request: &WorkfrontEvidenceRequest,
        state: EvidenceState,
        pages: u16,
        pagination_complete: bool,
        project: Option<&ProjectSnapshot>,
        task: Option<&TaskSnapshot>,
        review: Option<&ReviewSnapshot>,
        approval: Option<&ApprovalSnapshot>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> WorkfrontReviewProposal {
        WorkfrontReviewProposal::build(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            pages,
            pagination_complete,
            project,
            task,
            review,
            approval,
            failure,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_from_transport(
        &self,
        request: &WorkfrontEvidenceRequest,
        state: EvidenceState,
        pages: u16,
        pagination_complete: bool,
        project: Option<&ProjectSnapshot>,
        task: Option<&TaskSnapshot>,
        review: Option<&ReviewSnapshot>,
        approval: Option<&ApprovalSnapshot>,
        operation: WorkfrontOperation,
        error: WorkfrontTransportError,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> WorkfrontReviewProposal {
        self.build_failure_proposal(
            request,
            state,
            pages,
            pagination_complete,
            project,
            task,
            review,
            approval,
            Some(FailureEvidence::from_transport(operation, &error)),
            request_receipts,
            cost_receipts,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_from_provider_error(
        &self,
        request: &WorkfrontEvidenceRequest,
        pages: u16,
        pagination_complete: bool,
        project: Option<&ProjectSnapshot>,
        task: Option<&TaskSnapshot>,
        review: Option<&ReviewSnapshot>,
        approval: Option<&ApprovalSnapshot>,
        operation: WorkfrontOperation,
        error: WorkfrontReviewResultError,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> WorkfrontReviewProposal {
        match error {
            WorkfrontReviewResultError::Transport(transport) => self.failure_from_transport(
                request,
                EvidenceState::from_transport(&transport),
                pages,
                pagination_complete,
                project,
                task,
                review,
                approval,
                operation,
                transport,
                request_receipts,
                cost_receipts,
            ),
            error => self.failure_from_local(
                request,
                EvidenceState::Tampered,
                pages,
                pagination_complete,
                project,
                task,
                review,
                approval,
                operation,
                error,
                request_receipts,
                cost_receipts,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_from_local(
        &self,
        request: &WorkfrontEvidenceRequest,
        state: EvidenceState,
        pages: u16,
        pagination_complete: bool,
        project: Option<&ProjectSnapshot>,
        task: Option<&TaskSnapshot>,
        review: Option<&ReviewSnapshot>,
        approval: Option<&ApprovalSnapshot>,
        operation: WorkfrontOperation,
        error: WorkfrontReviewResultError,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> WorkfrontReviewProposal {
        let category = match error {
            WorkfrontReviewResultError::PaginationLoop => "pagination_loop",
            WorkfrontReviewResultError::StaleState => "stale_state",
            WorkfrontReviewResultError::TamperedEvidence => "tampered",
            _ => "invalid_response",
        };
        self.build_failure_proposal(
            request,
            state,
            pages,
            pagination_complete,
            project,
            task,
            review,
            approval,
            Some(FailureEvidence {
                operation,
                status_code: None,
                category: category.to_owned(),
                failure_digest: Digest::from_parts(
                    "workfront-failure/v1",
                    &[
                        ("operation", operation.as_str().to_owned()),
                        ("category", category.to_owned()),
                    ],
                ),
            }),
            request_receipts,
            cost_receipts,
        )
    }
}

fn push_receipts(
    request_receipts: &mut Vec<RequestReceipt>,
    cost_receipts: &mut Vec<CostReceipt>,
    request: &WorkfrontReadRequest,
    response_bytes: u64,
    scope: &WorkfrontReviewScope,
) -> Result<()> {
    request_receipts.push(RequestReceipt {
        operation: request.operation.as_str().to_owned(),
        request_digest: request.digest(),
        path_digest: request.path_digest(scope)?,
        scope_digest: request.scope_digest.clone(),
        cursor_digest: request
            .cursor
            .as_ref()
            .map(|cursor| cursor.digest().clone()),
        redacted: true,
        raw_path_retained: false,
        authorization_retained: false,
    });
    cost_receipts.push(CostReceipt {
        operation: request.operation.as_str().to_owned(),
        response_bytes,
        bounded_request_units: 1,
        cost_digest: Digest::from_parts(
            "workfront-cost/v1",
            &[
                ("operation", request.operation.as_str().to_owned()),
                ("bytes", response_bytes.to_string()),
            ],
        ),
        redacted: true,
        estimate_only: true,
        durable_provider_receipt: false,
    });
    Ok(())
}

fn consistent_cursor(
    cursors: &[Option<crate::model::Cursor>],
) -> Result<Option<crate::model::Cursor>> {
    let first = cursors.iter().find_map(Option::as_ref);
    if cursors.iter().any(|cursor| match (first, cursor) {
        (Some(first), Some(cursor)) => first.digest() != cursor.digest(),
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => false,
    }) {
        return Err(WorkfrontReviewResultError::PaginationLoop);
    }
    Ok(first.cloned())
}

fn derive_state(
    project: &ProjectSnapshot,
    task: &TaskSnapshot,
    review: &ReviewSnapshot,
    approval: &ApprovalSnapshot,
    observed_at: DateTime<Utc>,
) -> EvidenceState {
    if matches!(review.status, crate::model::ReviewStatus::Expired)
        || matches!(approval.status, crate::model::ApprovalStatus::Expired)
    {
        return EvidenceState::Expired;
    }
    if matches!(review.status, crate::model::ReviewStatus::ChangesRequested)
        || matches!(
            approval.status,
            crate::model::ApprovalStatus::ChangesRequested
        )
    {
        return EvidenceState::ChangesRequested;
    }
    if matches!(review.status, crate::model::ReviewStatus::Rejected)
        || matches!(approval.status, crate::model::ApprovalStatus::Rejected)
    {
        return EvidenceState::Rejected;
    }
    if matches!(project.status, crate::model::ProjectStatus::Unknown)
        || matches!(task.status, crate::model::TaskStatus::Unknown)
        || matches!(review.status, crate::model::ReviewStatus::Unknown)
        || matches!(approval.status, crate::model::ApprovalStatus::Unknown)
    {
        return EvidenceState::ProviderUnknown;
    }
    if matches!(review.status, crate::model::ReviewStatus::Approved)
        && matches!(approval.status, crate::model::ApprovalStatus::Approved)
    {
        return EvidenceState::Approved;
    }
    if matches!(review.status, crate::model::ReviewStatus::InReview)
        || matches!(approval.status, crate::model::ApprovalStatus::InReview)
    {
        return EvidenceState::InReview;
    }
    if observed_at < review.submitted_at.unwrap_or(observed_at)
        || matches!(review.status, crate::model::ReviewStatus::Pending)
        || matches!(approval.status, crate::model::ApprovalStatus::Pending)
    {
        return EvidenceState::Pending;
    }
    EvidenceState::ProviderUnknown
}

impl EvidenceState {
    fn from_transport(error: &WorkfrontTransportError) -> Self {
        match error {
            WorkfrontTransportError::AccessLost
            | WorkfrontTransportError::Unauthorized
            | WorkfrontTransportError::Forbidden => Self::AccessLost,
            WorkfrontTransportError::Partial => Self::Partial,
            WorkfrontTransportError::Tampered
            | WorkfrontTransportError::InvalidResponse
            | WorkfrontTransportError::PaginationLoop
            | WorkfrontTransportError::StaleState => Self::Tampered,
            WorkfrontTransportError::BlockedEnv
            | WorkfrontTransportError::Unknown
            | WorkfrontTransportError::Timeout
            | WorkfrontTransportError::RateLimited { .. }
            | WorkfrontTransportError::BadRequest
            | WorkfrontTransportError::NotFound
            | WorkfrontTransportError::Conflict
            | WorkfrontTransportError::ServerError { .. } => Self::ProviderUnknown,
        }
    }
}

fn verification_failure(code: &str, error: &WorkfrontReviewResultError) -> VerificationFailure {
    VerificationFailure {
        code: code.to_owned(),
        digest: Digest::from_text(error.to_string()),
    }
}
