//! Registration, proposal, evidence, and fail-closed verification seams.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{Result, SiftFraudResultError, SiftTransportError};
use crate::model::{
    ConsentScope, Digest, MissionProjection, ProjectProjection, RegistrationTransitionEvidence,
    SecretReference, SiftDecisionDisposition, SiftDecisionProjection, SiftFraudResultRegistration,
    SiftFraudResultScope, SiftFraudResultState, SiftPermissionSnapshot, SiftReviewProjection,
    SiftScoreProjection, SiftWorkflowProjection, TransportProvenance, WorkProductProjection,
};
use crate::provider::{
    SiftOperation, SiftProvider, SiftProviderRead, SiftReadReceipt, SiftRequest, SiftTransport,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

pub const SIFT_FRAUD_RESULT_SERVICE_ID: &str = SERVICE_ID;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftFraudResultServiceDefinition {
    pub id: String,
    pub version: String,
    pub access: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub event_ingestion: bool,
    pub decision_mutation: bool,
    pub workflow_mutation: bool,
    pub fraud_certainty: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

impl Default for SiftFraudResultServiceDefinition {
    fn default() -> Self {
        Self {
            id: SERVICE_ID.to_owned(),
            version: "1.0.0".to_owned(),
            access: "read_only".to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "register_scope".to_owned(),
                "read_decision_status".to_owned(),
                "read_score".to_owned(),
                "read_workflow_status".to_owned(),
                "compile_fraud_result_proposal".to_owned(),
                "record_observation".to_owned(),
                "verify_proposal".to_owned(),
                "revoke_registration".to_owned(),
                "restore_registration".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            event_ingestion: false,
            decision_mutation: false,
            workflow_mutation: false,
            fraud_certainty: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub fraud_certainty: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "details")]
pub enum ObservationFailure {
    Denied,
    Partial,
    AccessLoss,
    RateLimited { retry_after_seconds: u32 },
    ProviderUnknown,
    NotFound,
    Unauthorized,
    Forbidden,
    TimedOut,
    Tampered,
    MalformedResponse,
    ResponseTooLarge,
    BlockedEnv,
    StaleRevision,
    RegistrationRevoked,
}

impl ObservationFailure {
    pub const fn state(&self) -> SiftFraudResultState {
        match self {
            Self::Denied | Self::Unauthorized | Self::Forbidden => SiftFraudResultState::Denied,
            Self::Partial => SiftFraudResultState::Partial,
            Self::AccessLoss => SiftFraudResultState::AccessLoss,
            Self::RateLimited { .. } => SiftFraudResultState::RateLimited,
            Self::ProviderUnknown | Self::BlockedEnv | Self::TimedOut => {
                SiftFraudResultState::ProviderUnknown
            }
            Self::NotFound => SiftFraudResultState::NotFound,
            Self::Tampered | Self::MalformedResponse | Self::ResponseTooLarge => {
                SiftFraudResultState::Tampered
            }
            Self::StaleRevision => SiftFraudResultState::StaleRevision,
            Self::RegistrationRevoked => SiftFraudResultState::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftFraudResultEvidence {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub entity_digest: Digest,
    pub decision: Option<SiftDecisionProjection>,
    pub score: Option<SiftScoreProjection>,
    pub review: Option<SiftReviewProjection>,
    pub workflow: Option<SiftWorkflowProjection>,
    pub response_digests: Vec<Digest>,
    pub request_receipts: Vec<SiftReadReceipt>,
    pub failures: Vec<ObservationFailure>,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: Digest,
}

impl SiftFraudResultEvidence {
    fn calculate_digest(&self, state: SiftFraudResultState) -> Digest {
        Digest::from_parts(
            "sift-fraud-result-evidence/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("entity", self.entity_digest.as_str().to_owned()),
                (
                    "decision",
                    serde_json::to_string(&self.decision).expect("decision projection serializes"),
                ),
                (
                    "score",
                    serde_json::to_string(&self.score).expect("score projection serializes"),
                ),
                (
                    "review",
                    serde_json::to_string(&self.review).expect("review projection serializes"),
                ),
                (
                    "workflow",
                    serde_json::to_string(&self.workflow).expect("workflow projection serializes"),
                ),
                (
                    "responses",
                    self.response_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "receipts",
                    serde_json::to_string(&self.request_receipts).expect("receipts serialize"),
                ),
                (
                    "failures",
                    serde_json::to_string(&self.failures).expect("failures serialize"),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
                ("state", format!("{state:?}")),
            ],
        )
    }

    pub fn validate_integrity(&self, state: SiftFraudResultState) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.entity_digest,
        ] {
            digest.validate()?;
        }
        for digest in self
            .response_digests
            .iter()
            .chain(self.request_receipts.iter().flat_map(|receipt| {
                [
                    &receipt.scope_digest,
                    &receipt.entity_digest,
                    &receipt.request_digest,
                    &receipt.path_digest,
                ]
                .into_iter()
                .chain(receipt.response_digest.iter())
            }))
        {
            digest.validate()?;
        }
        for receipt in &self.request_receipts {
            receipt.validate()?;
        }
        if self.response_digests.len() > 3
            || self.request_receipts.len() > 3
            || self.evidence_digest != self.calculate_digest(state)
        {
            return Err(SiftFraudResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftFraudResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub state: SiftFraudResultState,
    pub evidence: SiftFraudResultEvidence,
    pub failures: Vec<ObservationFailure>,
    pub idempotency_digest: Digest,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub fraud_certainty: bool,
    pub event_ingestion: bool,
    pub decision_mutation: bool,
    pub workflow_mutation: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl SiftFraudResultProposal {
    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "sift-fraud-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project serializes"),
                ),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).expect("work product serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failures",
                    serde_json::to_string(&self.failures).expect("failures serialize"),
                ),
                ("idempotency", self.idempotency_digest.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("fraud_certainty", self.fraud_certainty.to_string()),
                ("event_ingestion", self.event_ingestion.to_string()),
                ("decision_mutation", self.decision_mutation.to_string()),
                ("workflow_mutation", self.workflow_mutation.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.idempotency_digest.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.fraud_certainty
            || self.event_ingestion
            || self.decision_mutation
            || self.workflow_mutation
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.validate_integrity(self.state).is_err()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(SiftFraudResultError::TamperedProposal);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
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
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    ProjectRevisionMismatch,
    MissionRevisionMismatch,
    WorkProductRevisionMismatch,
    EntityDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    Denied,
    RateLimited,
    AccessLoss,
    ProviderUnknown,
    StaleRevision,
    RegistrationRevoked,
    Replay,
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
            "sift-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
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

    pub const fn verified(&self) -> bool {
        self.valid
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftFraudResultRequest {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub idempotency_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl SiftFraudResultRequest {
    pub fn new(
        scope: &SiftFraudResultScope,
        registration: &SiftFraudResultRegistration,
        idempotency_key: impl AsRef<str>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(SiftFraudResultError::InvalidRequest);
        }
        let scope_digest = scope.digest();
        let registration_digest = registration.registration_digest().clone();
        let idempotency_digest = Digest::from_parts(
            "sift-idempotency-key/v1",
            &[("key", idempotency_key.to_owned())],
        );
        let request_digest = Digest::from_parts(
            "sift-fraud-result-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("registration", registration_digest.as_str().to_owned()),
                ("project_revision", scope.project().revision().to_string()),
                ("mission_revision", scope.mission().revision().to_string()),
                (
                    "work_product_revision",
                    scope.work_product().revision().to_string(),
                ),
                ("idempotency", idempotency_digest.as_str().to_owned()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest,
            registration_digest,
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            idempotency_digest,
            observed_at,
            request_digest,
        })
    }

    pub fn validate(
        &self,
        scope: &SiftFraudResultScope,
        registration: &SiftFraudResultRegistration,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.registration_digest != *registration.registration_digest()
            || self.project_revision != scope.project().revision()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
        {
            return Err(SiftFraudResultError::RevisionMismatch);
        }
        self.scope_digest.validate()?;
        self.registration_digest.validate()?;
        self.idempotency_digest.validate()?;
        let expected_request_digest = Digest::from_parts(
            "sift-fraud-result-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("project_revision", self.project_revision.to_string()),
                ("mission_revision", self.mission_revision.to_string()),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                ("idempotency", self.idempotency_digest.as_str().to_owned()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if self.request_digest != expected_request_digest {
            return Err(SiftFraudResultError::TamperedEvidence);
        }
        self.request_digest.validate()?;
        Ok(())
    }
}

pub struct SiftFraudResultService<T: SiftTransport> {
    scope: SiftFraudResultScope,
    registration: SiftFraudResultRegistration,
    provider: SiftProvider<T>,
    definition: SiftFraudResultServiceDefinition,
}

impl<T: SiftTransport> fmt::Debug for SiftFraudResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiftFraudResultService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: SiftTransport> SiftFraudResultService<T> {
    pub fn new(
        scope: SiftFraudResultScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: SiftProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = SiftFraudResultRegistration::new(
            "sift-fraud-result-registration",
            &scope,
            &secret_reference,
            SiftPermissionSnapshot::for_layer_one(1)?,
            consent,
            provider.definition().api_revision.clone(),
            &provider.provider_digest(),
            1,
            registration_time,
        )?;
        Self::with_registration(scope, provider, registration)
    }

    pub fn with_registration(
        scope: SiftFraudResultScope,
        provider: SiftProvider<T>,
        registration: SiftFraudResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &scope.digest()
            || registration.provider_digest() != &provider.provider_digest()
            || registration.provider_revision() != provider.definition().api_revision
            || !provider.definition().is_layer_one_honest()
        {
            return Err(SiftFraudResultError::ProviderDefinitionDrift);
        }
        Ok(Self {
            scope,
            registration,
            provider,
            definition: SiftFraudResultServiceDefinition::default(),
        })
    }

    pub fn provider(&self) -> &SiftProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SiftProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &SiftFraudResultScope {
        &self.scope
    }

    pub fn registration(&self) -> &SiftFraudResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut SiftFraudResultRegistration {
        &mut self.registration
    }

    pub fn service_definition(&self) -> &SiftFraudResultServiceDefinition {
        &self.definition
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            operations: vec![
                SiftOperation::DecisionStatus.as_str().to_owned(),
                SiftOperation::Score.as_str().to_owned(),
                SiftOperation::WorkflowStatus.as_str().to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            external_writes: false,
            fraud_certainty: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<SiftFraudResultRequest> {
        self.request("default-sift-observation", observed_at)
    }

    pub fn request(
        &self,
        idempotency_key: impl AsRef<str>,
        observed_at: DateTime<Utc>,
    ) -> Result<SiftFraudResultRequest> {
        SiftFraudResultRequest::new(
            &self.scope,
            &self.registration,
            idempotency_key,
            observed_at,
        )
    }

    pub fn issue_read_consent(&self) -> ConsentScope {
        self.registration.consent().clone()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn consumer(&self) -> Result<crate::MissionSiftFraudConsumer> {
        if !self.registration.is_active() {
            return Err(SiftFraudResultError::RegistrationInactive);
        }
        crate::MissionSiftFraudConsumer::new(self.scope.clone(), self.registration.clone())
    }

    pub fn read(&mut self, request: SiftFraudResultRequest) -> Result<SiftFraudResultEvidence> {
        self.validate_request(&request)?;
        let (evidence, _) = self.collect(request)?;
        Ok(evidence)
    }

    pub fn propose(&mut self, request: SiftFraudResultRequest) -> Result<SiftFraudResultProposal> {
        self.validate_request(&request)?;
        let (evidence, state) = self.collect(request.clone())?;
        let failures = evidence.failures.clone();
        let provenance = self.provider.provenance();
        let mut proposal = SiftFraudResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.scope.digest(),
            project: ProjectProjection::from(self.scope.project()),
            mission: MissionProjection::from(self.scope.mission()),
            work_product: WorkProductProjection::from(self.scope.work_product()),
            state,
            evidence,
            failures,
            idempotency_digest: request.idempotency_digest,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            fraud_certainty: false,
            event_ingestion: false,
            decision_mutation: false,
            workflow_mutation: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-sift-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn compile_proposal(
        &mut self,
        request: SiftFraudResultRequest,
    ) -> Result<SiftFraudResultProposal> {
        self.propose(request)
    }

    pub fn verify(&self, proposal: &SiftFraudResultProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.registration.provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != *self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.project.revision != self.registration.project_revision() {
            failures.push(VerificationFailure::ProjectRevisionMismatch);
        }
        if proposal.mission.revision != self.registration.mission_revision() {
            failures.push(VerificationFailure::MissionRevisionMismatch);
        }
        if proposal.work_product.revision != self.registration.work_product_revision() {
            failures.push(VerificationFailure::WorkProductRevisionMismatch);
        }
        if proposal.evidence.entity_digest != self.scope.entity_digest() {
            failures.push(VerificationFailure::EntityDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
            failures.push(VerificationFailure::ProposalDigestMismatch);
        }
        match proposal.state {
            SiftFraudResultState::Partial => failures.push(VerificationFailure::PartialEvidence),
            SiftFraudResultState::Denied => failures.push(VerificationFailure::Denied),
            SiftFraudResultState::RateLimited => failures.push(VerificationFailure::RateLimited),
            SiftFraudResultState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            SiftFraudResultState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            SiftFraudResultState::StaleRevision => {
                failures.push(VerificationFailure::StaleRevision);
            }
            SiftFraudResultState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationRevoked);
            }
            SiftFraudResultState::Allow
            | SiftFraudResultState::Deny
            | SiftFraudResultState::Review
            | SiftFraudResultState::Unknown
            | SiftFraudResultState::Tampered
            | SiftFraudResultState::NotFound => {}
        }
        let structural_failure = failures.iter().any(|failure| {
            matches!(
                failure,
                VerificationFailure::RegistrationInactive
                    | VerificationFailure::RegistrationDigestMismatch
                    | VerificationFailure::ProviderDigestMismatch
                    | VerificationFailure::PermissionDigestMismatch
                    | VerificationFailure::ConsentDigestMismatch
                    | VerificationFailure::ScopeDigestMismatch
                    | VerificationFailure::ProjectRevisionMismatch
                    | VerificationFailure::MissionRevisionMismatch
                    | VerificationFailure::WorkProductRevisionMismatch
                    | VerificationFailure::EntityDigestMismatch
                    | VerificationFailure::TamperedEvidence
                    | VerificationFailure::ProposalDigestMismatch
                    | VerificationFailure::RegistrationRevoked
            )
        });
        let valid = !structural_failure;
        let review_eligible = valid
            && matches!(
                proposal.state,
                SiftFraudResultState::Allow
                    | SiftFraudResultState::Deny
                    | SiftFraudResultState::Review
                    | SiftFraudResultState::Unknown
            );
        VerificationReport::new(valid, review_eligible, failures)
    }

    pub fn verify_proposal(&self, proposal: &SiftFraudResultProposal) -> VerificationReport {
        self.verify(proposal)
    }

    fn validate_request(&self, request: &SiftFraudResultRequest) -> Result<()> {
        if !self.registration.is_active() {
            return Err(SiftFraudResultError::RegistrationInactive);
        }
        request.validate(&self.scope, &self.registration)?;
        self.registration.consent().validate(request.observed_at)?;
        Ok(())
    }

    fn collect(
        &mut self,
        request: SiftFraudResultRequest,
    ) -> Result<(SiftFraudResultEvidence, SiftFraudResultState)> {
        let mut decision = None;
        let mut score = None;
        let mut workflow = None;
        let mut review = None;
        let mut receipts = Vec::new();
        let mut response_digests = Vec::new();
        let mut failures = Vec::new();
        for operation in [
            SiftOperation::DecisionStatus,
            SiftOperation::Score,
            SiftOperation::WorkflowStatus,
        ] {
            match self.provider.read(&self.scope, operation) {
                Ok(read) => match read {
                    SiftProviderRead::Decision {
                        projection,
                        receipt,
                    } => {
                        response_digests.extend(receipt.response_digest.iter().cloned());
                        receipts.push(receipt);
                        decision = Some(projection);
                    }
                    SiftProviderRead::Score {
                        projection,
                        receipt,
                    } => {
                        response_digests.extend(receipt.response_digest.iter().cloned());
                        receipts.push(receipt);
                        score = Some(projection);
                    }
                    SiftProviderRead::Workflow {
                        workflow: workflow_projection,
                        review: review_projection,
                        receipt,
                    } => {
                        response_digests.extend(receipt.response_digest.iter().cloned());
                        receipts.push(receipt);
                        workflow = Some(workflow_projection);
                        review = Some(review_projection);
                    }
                },
                Err(error) => {
                    let request_record = SiftRequest::new(&self.scope, operation)?;
                    receipts.push(SiftReadReceipt::failure(
                        &request_record,
                        self.provider.provenance(),
                    ));
                    failures.push(failure_for_error(&error));
                }
            }
        }
        let state = result_state(
            decision.as_ref(),
            score.as_ref(),
            workflow.as_ref(),
            &failures,
        );
        let mut evidence = SiftFraudResultEvidence {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: self.provider.provider_digest(),
            api_digest: Digest::from_text(self.provider.definition().api_revision.as_bytes()),
            permission_digest: self.registration.permission_digest().clone(),
            consent_digest: self.registration.consent_digest(),
            scope_digest: self.scope.digest(),
            entity_digest: self.scope.entity_digest(),
            decision,
            score,
            review,
            workflow,
            response_digests,
            request_receipts: receipts,
            failures,
            observed_at: request.observed_at,
            evidence_digest: Digest::from_text("unsealed-sift-evidence"),
        };
        evidence.evidence_digest = evidence.calculate_digest(state);
        Ok((evidence, state))
    }
}

fn failure_for_error(error: &SiftFraudResultError) -> ObservationFailure {
    match error {
        SiftFraudResultError::Provider(transport) => match transport {
            SiftTransportError::Denied => ObservationFailure::Denied,
            SiftTransportError::AccessLoss => ObservationFailure::AccessLoss,
            SiftTransportError::RateLimited {
                retry_after_seconds,
            } => ObservationFailure::RateLimited {
                retry_after_seconds: *retry_after_seconds,
            },
            SiftTransportError::ProviderUnknown => ObservationFailure::ProviderUnknown,
            SiftTransportError::TimedOut => ObservationFailure::TimedOut,
            SiftTransportError::NotFound => ObservationFailure::NotFound,
            SiftTransportError::Unauthorized => ObservationFailure::Unauthorized,
            SiftTransportError::Forbidden => ObservationFailure::Forbidden,
            SiftTransportError::Conflict => ObservationFailure::StaleRevision,
            SiftTransportError::MalformedResponse => ObservationFailure::MalformedResponse,
            SiftTransportError::ResponseTooLarge => ObservationFailure::ResponseTooLarge,
            SiftTransportError::BlockedEnv => ObservationFailure::BlockedEnv,
        },
        SiftFraudResultError::TamperedEvidence | SiftFraudResultError::TamperedProposal => {
            ObservationFailure::Tampered
        }
        SiftFraudResultError::RegistrationInactive
        | SiftFraudResultError::RegistrationAlreadyRevoked
        | SiftFraudResultError::RegistrationNotRevoked
        | SiftFraudResultError::RegistrationReversed => ObservationFailure::RegistrationRevoked,
        SiftFraudResultError::RevisionMismatch | SiftFraudResultError::ConsentMismatch => {
            ObservationFailure::StaleRevision
        }
        SiftFraudResultError::MalformedResponse => ObservationFailure::MalformedResponse,
        SiftFraudResultError::ResponseTooLarge => ObservationFailure::ResponseTooLarge,
        _ => ObservationFailure::ProviderUnknown,
    }
}

fn result_state(
    decision: Option<&SiftDecisionProjection>,
    score: Option<&SiftScoreProjection>,
    workflow: Option<&SiftWorkflowProjection>,
    failures: &[ObservationFailure],
) -> SiftFraudResultState {
    if let Some(failure) = failures.iter().find(|failure| {
        matches!(
            failure,
            ObservationFailure::Tampered
                | ObservationFailure::MalformedResponse
                | ObservationFailure::ResponseTooLarge
        )
    }) {
        return failure.state();
    }
    if let Some(failure) = failures.iter().find(|failure| {
        matches!(
            failure,
            ObservationFailure::RateLimited { .. }
                | ObservationFailure::AccessLoss
                | ObservationFailure::Denied
                | ObservationFailure::Unauthorized
                | ObservationFailure::Forbidden
                | ObservationFailure::BlockedEnv
                | ObservationFailure::ProviderUnknown
                | ObservationFailure::TimedOut
                | ObservationFailure::NotFound
                | ObservationFailure::StaleRevision
        )
    }) {
        if decision.is_some() || score.is_some() || workflow.is_some() {
            return SiftFraudResultState::Partial;
        }
        return failure.state();
    }
    if !failures.is_empty() {
        return SiftFraudResultState::Partial;
    }
    if let Some(workflow) = workflow {
        if matches!(workflow.state, crate::SiftWorkflowState::Running) {
            return SiftFraudResultState::Review;
        }
    }
    decision.map_or(SiftFraudResultState::Unknown, |decision| {
        match decision.disposition {
            SiftDecisionDisposition::Allow => SiftFraudResultState::Allow,
            SiftDecisionDisposition::Deny => SiftFraudResultState::Deny,
            SiftDecisionDisposition::Review => SiftFraudResultState::Review,
            SiftDecisionDisposition::Unknown => SiftFraudResultState::Unknown,
        }
    })
}

pub type SiftRegistration = SiftFraudResultRegistration;
pub type SiftEvidence = SiftFraudResultEvidence;
pub type SiftProposal = SiftFraudResultProposal;
pub type SiftResultState = SiftFraudResultState;
pub type SiftProviderError = SiftFraudResultError;

#[allow(dead_code)]
fn _provider_id_is_frozen() -> &'static str {
    SIFT_FRAUD_RESULT_SERVICE_ID
}
