use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

use crate::{
    BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
    CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, LAYER1_PERMISSIONS, PLUGIN_ID,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
    consumer::MissionOpenFgaAuthorizationConsumer,
    error::{OpenFgaAuthorizationResultError, OpenFgaTransportError, Result},
    model::{
        AuthorizationCheckScope, AuthorizationDecision, CheckEvidence, ConsentScope, CostReceipt,
        Digest, EvidenceDigests, ModelEvidence, OpenFgaEvidenceState, OpenFgaScope, RequestReceipt,
        Revision, ScopeEvidence, SecretReference, TransportProvenance, TupleEvidence, TupleScope,
    },
    provider::{
        AuthorizationCheckRequest, ModelReadRequest, OpenFgaObservation, OpenFgaOperation,
        OpenFgaProvider, OpenFgaProviderFailure, OpenFgaTransport, TupleReadRequest,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub redacted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenFgaAuthorizationResultRegistration {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision_digest: Digest,
    pub registration_revision: Revision,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

pub type OpenFgaRegistration = OpenFgaAuthorizationResultRegistration;

impl OpenFgaAuthorizationResultRegistration {
    pub(crate) fn new(
        scope: &OpenFgaScope,
        secret: &SecretReference,
        consent: &ConsentScope,
        provider_digest: Digest,
        registration_revision: Revision,
    ) -> Result<Self> {
        let permission_digest = Digest::from_parts(
            "openfga-layer1-permissions/v1",
            &[
                ("read_model", LAYER1_PERMISSIONS[0].to_owned()),
                ("check", LAYER1_PERMISSIONS[1].to_owned()),
                ("read", LAYER1_PERMISSIONS[2].to_owned()),
                ("mission", LAYER1_PERMISSIONS[3].to_owned()),
            ],
        );
        let revision_digest = revision_digest(scope, None, None);
        let mut registration = Self {
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::from_text(CONTRACT_DIGEST_INPUT),
            provider_digest,
            api_digest: Digest::from_text(PROVIDER_API_REVISION),
            permission_digest,
            scope_digest: scope.digest(),
            consent_digest: consent.digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            revision_digest,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-openfga-registration"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-registration/v1",
            &[
                ("version", self.version_digest.to_string()),
                ("contract", self.contract_digest.to_string()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                ("permission", self.permission_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("consent", self.consent_digest.to_string()),
                ("secret", self.secret_reference_digest.to_string()),
                ("revision", self.revision_digest.to_string()),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            &self.revision_digest,
            &self.registration_digest,
        ] {
            digest.validate()?;
        }
        if self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_digest != Digest::from_text(CONTRACT_DIGEST_INPUT)
            || self.api_digest != Digest::from_text(PROVIDER_API_REVISION)
            || self.registration_revision.get() == 0
            || self.registration_digest != self.compute_digest()
        {
            return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Active {
            return Err(OpenFgaAuthorizationResultError::AlreadyRevoked);
        }
        let from = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_revision = Revision::new_labeled(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(OpenFgaAuthorizationResultError::RevisionOverflow)?,
            "registration",
        )?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransitionEvidence {
            from,
            to: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            redacted: true,
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Reversed {
            return Err(OpenFgaAuthorizationResultError::NotRevoked);
        }
        let from = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_revision = Revision::new_labeled(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(OpenFgaAuthorizationResultError::RevisionOverflow)?,
            "registration",
        )?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransitionEvidence {
            from,
            to: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub api_revision: String,
    pub operations: Vec<OpenFgaOperation>,
    pub permissions: Vec<String>,
    pub permission_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub tuple_writes: bool,
    pub authorization_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpenFgaEvidenceRequest {
    pub model: ModelReadRequest,
    pub check: AuthorizationCheckRequest,
    pub tuples: TupleReadRequest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub revision_digest: Digest,
    pub requested_at: DateTime<Utc>,
}

impl OpenFgaEvidenceRequest {
    pub fn new(
        scope: &OpenFgaScope,
        registration: &OpenFgaAuthorizationResultRegistration,
        consent: &ConsentScope,
        check: AuthorizationCheckScope,
        tuple_scope: crate::TupleScope,
        page_size: u16,
        requested_at: DateTime<Utc>,
    ) -> Result<Self> {
        let model = ModelReadRequest::for_scope(scope)?;
        let check = AuthorizationCheckRequest::from_scope(scope, check)?;
        let tuples = TupleReadRequest::first(scope, tuple_scope, page_size)?;
        let revision_digest = revision_digest(
            scope,
            Some(check.check().revision),
            Some(tuples.tuple_scope().revision),
        );
        Ok(Self {
            model,
            check,
            tuples,
            scope_digest: scope.digest(),
            consent_digest: consent.digest(),
            registration_digest: registration.registration_digest.clone(),
            revision_digest,
            requested_at,
        })
    }

    pub fn for_scope(
        scope: &OpenFgaScope,
        registration: &OpenFgaAuthorizationResultRegistration,
        consent: &ConsentScope,
        user: impl Into<String>,
        relation: impl Into<String>,
        object: impl Into<String>,
        check_revision: u64,
        tuple_revision: u64,
        page_size: u16,
        requested_at: DateTime<Utc>,
    ) -> Result<Self> {
        let user = user.into();
        let relation = relation.into();
        let object = object.into();
        Self::new(
            scope,
            registration,
            consent,
            AuthorizationCheckScope::new(
                user.clone(),
                relation.clone(),
                object.clone(),
                check_revision,
            )?,
            crate::TupleScope::new(user, relation, object, tuple_revision)?,
            page_size,
            requested_at,
        )
    }

    fn validate(
        &self,
        scope: &OpenFgaScope,
        registration: &OpenFgaAuthorizationResultRegistration,
        consent: &ConsentScope,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.model.scope().digest() != scope.digest()
            || self.check.scope().digest() != scope.digest()
            || self.tuples.scope().digest() != scope.digest()
            || self.consent_digest != consent.digest()
            || self.registration_digest != *registration.registration_digest()
            || self.revision_digest
                != revision_digest(
                    scope,
                    Some(self.check.check().revision),
                    Some(self.tuples.tuple_scope().revision),
                )
        {
            return Err(OpenFgaAuthorizationResultError::ScopeMismatch);
        }
        if self.requested_at >= consent.expires_at() {
            return Err(OpenFgaAuthorizationResultError::ConsentExpired);
        }
        Ok(())
    }
}

impl fmt::Debug for OpenFgaEvidenceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenFgaEvidenceRequest")
            .field("scope_digest", &self.scope_digest)
            .field("consent_digest", &self.consent_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revision_digest", &self.revision_digest)
            .field("requested_at", &self.requested_at)
            .field("model", &self.model)
            .field("check", &self.check)
            .field("tuples", &self.tuples)
            .finish()
    }
}

fn revision_digest(
    scope: &OpenFgaScope,
    check_revision: Option<Revision>,
    tuple_revision: Option<Revision>,
) -> Digest {
    Digest::from_parts(
        "openfga-revision-fence/v1",
        &[
            ("scope", scope.digest().to_string()),
            ("store", scope.store().revision().get().to_string()),
            (
                "model",
                scope.authorization_model().revision().get().to_string(),
            ),
            ("project", scope.project().revision().get().to_string()),
            ("mission", scope.mission().revision().get().to_string()),
            (
                "work_product",
                scope.work_product().revision().get().to_string(),
            ),
            (
                "check",
                check_revision.map_or_else(String::new, |value| value.get().to_string()),
            ),
            (
                "tuple",
                tuple_revision.map_or_else(String::new, |value| value.get().to_string()),
            ),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: OpenFgaOperation,
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub error_digest: Digest,
    pub redacted: bool,
}

impl FailureEvidence {
    fn from_failure(failure: &OpenFgaProviderFailure) -> Self {
        let category = failure.error.category();
        Self {
            operation: failure.operation,
            category: category.to_owned(),
            status_code: failure.error.status_code(),
            retry_after_seconds: failure.error.retry_after_seconds(),
            error_digest: Digest::from_parts(
                "openfga-failure/v1",
                &[
                    ("operation", failure.operation.as_str().to_owned()),
                    ("category", category.to_owned()),
                    (
                        "status",
                        failure
                            .error
                            .status_code()
                            .map_or_else(String::new, |status| status.to_string()),
                    ),
                ],
            ),
            redacted: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    Tampered,
    RegistrationMismatch,
    ScopeMismatch,
    Stale,
    Partial,
    ProviderUnknown,
    RateLimited,
    RegistrationRevoked,
    ConsentExpired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failure: Option<VerificationFailure>,
    pub verified_digest: Digest,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenFgaAuthorizationResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub scope: ScopeEvidence,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub revision_digest: Digest,
    pub state: OpenFgaEvidenceState,
    pub model: Option<ModelEvidence>,
    pub check: Option<CheckEvidence>,
    pub tuples: Vec<TupleEvidence>,
    pub tuple_complete: bool,
    pub observation_digest: Digest,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub failure: Option<FailureEvidence>,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub authorization_granted: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

pub type OpenFgaAuthorizationResult = OpenFgaAuthorizationResultProposal;

impl OpenFgaAuthorizationResultProposal {
    fn from_observation(
        scope: &OpenFgaScope,
        consent: &ConsentScope,
        registration: &OpenFgaAuthorizationResultRegistration,
        observation: OpenFgaObservation,
        revision_digest: Digest,
    ) -> Self {
        let state = match observation.check.decision {
            AuthorizationDecision::Denied => OpenFgaEvidenceState::Denied,
            AuthorizationDecision::Allowed | AuthorizationDecision::Unknown => {
                OpenFgaEvidenceState::Ready
            }
        };
        let tuple_digest = tuple_digest(&observation.tuples, observation.tuple_complete);
        let evidence = EvidenceDigests::new(
            Digest::from_parts(
                "openfga-provider/v1",
                &[
                    ("id", PROVIDER_ID.to_owned()),
                    ("api", PROVIDER_API_REVISION.to_owned()),
                    ("provenance", observation.provenance.as_str().to_owned()),
                ],
            ),
            scope.digest(),
            consent.digest(),
            registration.registration_digest.clone(),
            observation.model.evidence_digest.clone(),
            observation.check.check_digest.clone(),
            tuple_digest,
            revision_digest.clone(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope: ScopeEvidence::from_scope(scope),
            scope_digest: scope.digest(),
            consent_digest: consent.digest(),
            registration_digest: registration.registration_digest.clone(),
            revision_digest,
            state,
            model: Some(observation.model),
            check: Some(observation.check),
            tuples: observation.tuples,
            tuple_complete: observation.tuple_complete,
            observation_digest: observation.evidence_digest,
            evidence,
            provenance: observation.provenance,
            request_receipts: observation.request_receipts,
            cost_receipts: observation.cost_receipts,
            failure: None,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            authorization_granted: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-openfga-proposal"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn from_failure(
        scope: &OpenFgaScope,
        consent: &ConsentScope,
        registration: &OpenFgaAuthorizationResultRegistration,
        request: &OpenFgaEvidenceRequest,
        failure: OpenFgaProviderFailure,
    ) -> Self {
        let state = match &failure.error {
            OpenFgaTransportError::RateLimited { .. } => OpenFgaEvidenceState::RateLimited,
            OpenFgaTransportError::Unauthorized => OpenFgaEvidenceState::Unauthorized,
            OpenFgaTransportError::Forbidden => OpenFgaEvidenceState::Forbidden,
            OpenFgaTransportError::NotFound => OpenFgaEvidenceState::NotFound,
            OpenFgaTransportError::Conflict => OpenFgaEvidenceState::Conflict,
            OpenFgaTransportError::TimedOut => OpenFgaEvidenceState::TimedOut,
            OpenFgaTransportError::Partial => OpenFgaEvidenceState::Partial,
            OpenFgaTransportError::Stale => OpenFgaEvidenceState::Stale,
            OpenFgaTransportError::Malformed => OpenFgaEvidenceState::Tampered,
            OpenFgaTransportError::BlockedEnvironment(_)
            | OpenFgaTransportError::NoRecording
            | OpenFgaTransportError::Unknown(_) => OpenFgaEvidenceState::ProviderUnknown,
        };
        let failure_evidence = FailureEvidence::from_failure(&failure);
        let unavailable = Digest::from_text("openfga-evidence-unavailable");
        let evidence = EvidenceDigests::new(
            Digest::from_parts(
                "openfga-provider/v1",
                &[
                    ("id", PROVIDER_ID.to_owned()),
                    ("api", PROVIDER_API_REVISION.to_owned()),
                    ("provenance", failure.provenance.as_str().to_owned()),
                ],
            ),
            scope.digest(),
            consent.digest(),
            registration.registration_digest.clone(),
            unavailable.clone(),
            unavailable.clone(),
            unavailable.clone(),
            request.revision_digest.clone(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope: ScopeEvidence::from_scope(scope),
            scope_digest: scope.digest(),
            consent_digest: consent.digest(),
            registration_digest: registration.registration_digest.clone(),
            revision_digest: request.revision_digest.clone(),
            state,
            model: None,
            check: None,
            tuples: Vec::new(),
            tuple_complete: false,
            observation_digest: unavailable,
            evidence,
            provenance: failure.provenance,
            request_receipts: failure.request_receipts,
            cost_receipts: failure.cost_receipts,
            failure: Some(failure_evidence),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            authorization_granted: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-openfga-proposal"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        let receipts_digest = Digest::from_text(
            serde_json::to_string(&(self.request_receipts.clone(), self.cost_receipts.clone()))
                .expect("typed receipts serialize"),
        );
        Digest::from_parts(
            "openfga-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("scope", self.scope_digest.to_string()),
                ("consent", self.consent_digest.to_string()),
                ("registration", self.registration_digest.to_string()),
                ("revision", self.revision_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                (
                    "model",
                    self.model
                        .as_ref()
                        .map_or_else(String::new, |value| value.evidence_digest.to_string()),
                ),
                (
                    "check",
                    self.check
                        .as_ref()
                        .map_or_else(String::new, |value| value.check_digest.to_string()),
                ),
                (
                    "tuples",
                    tuple_digest(&self.tuples, self.tuple_complete).to_string(),
                ),
                ("observation", self.observation_digest.to_string()),
                ("evidence", self.evidence.evidence_digest.to_string()),
                ("receipts", receipts_digest.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.scope.scope_digest != self.scope_digest
            || self.evidence.scope_digest != self.scope_digest
            || self.evidence.consent_digest != self.consent_digest
            || self.evidence.registration_digest != self.registration_digest
            || self.evidence.revision_digest != self.revision_digest
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.authorization_granted
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
        }
        self.evidence.validate()?;
        if let Some(model) = self.model.as_ref() {
            model.validate()?;
        }
        if let Some(check) = self.check.as_ref() {
            check.validate()?;
        }
        for tuple in &self.tuples {
            tuple.validate()?;
        }
        if let Some(failure) = self.failure.as_ref() {
            if !failure.redacted {
                return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

fn tuple_digest(tuples: &[TupleEvidence], complete: bool) -> Digest {
    Digest::from_parts(
        "openfga-tuples/v1",
        &[
            (
                "items",
                tuples
                    .iter()
                    .map(|tuple| tuple.evidence_digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("complete", complete.to_string()),
        ],
    )
}

impl fmt::Debug for OpenFgaAuthorizationResultProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenFgaAuthorizationResultProposal")
            .field("state", &self.state)
            .field("scope_digest", &self.scope_digest)
            .field("consent_digest", &self.consent_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revision_digest", &self.revision_digest)
            .field("model", &self.model)
            .field("check", &self.check)
            .field("tuple_count", &self.tuples.len())
            .field("tuple_complete", &self.tuple_complete)
            .field("provenance", &self.provenance)
            .field("proposal_digest", &self.proposal_digest)
            .finish()
    }
}

pub struct OpenFgaAuthorizationResultService<T> {
    scope: OpenFgaScope,
    secret: SecretReference,
    consent: ConsentScope,
    registration: OpenFgaAuthorizationResultRegistration,
    provider: OpenFgaProvider<T>,
    now: DateTime<Utc>,
}

pub type OpenFgaAuthorizationService<T> = OpenFgaAuthorizationResultService<T>;

impl<T: OpenFgaTransport> OpenFgaAuthorizationResultService<T> {
    pub fn new(
        scope: OpenFgaScope,
        secret: SecretReference,
        consent: ConsentScope,
        provider: OpenFgaProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        let secret = secret.bind_scope(&scope)?;
        let consent = consent.bind_scope(&scope)?;
        secret.validate(&scope)?;
        consent.validate(&scope, now)?;
        let registration = OpenFgaAuthorizationResultRegistration::new(
            &scope,
            &secret,
            &consent,
            provider.provider_digest().clone(),
            Revision::new_labeled(1, "registration")?,
        )?;
        registration.validate()?;
        Ok(Self {
            scope,
            secret,
            consent,
            registration,
            provider,
            now,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &OpenFgaScope {
        &self.scope
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn registration(&self) -> &OpenFgaAuthorizationResultRegistration {
        &self.registration
    }

    #[must_use]
    pub fn provider(&self) -> &OpenFgaProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        let permission_digest = Digest::from_parts(
            "openfga-layer1-permissions/v1",
            &[
                ("read_model", LAYER1_PERMISSIONS[0].to_owned()),
                ("check", LAYER1_PERMISSIONS[1].to_owned()),
                ("read", LAYER1_PERMISSIONS[2].to_owned()),
                ("mission", LAYER1_PERMISSIONS[3].to_owned()),
            ],
        );
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                OpenFgaOperation::ReadAuthorizationModel,
                OpenFgaOperation::Check,
                OpenFgaOperation::ReadTuples,
            ],
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            permission_digest,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            tuple_writes: false,
            authorization_authority: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn default_request(&self, requested_at: DateTime<Utc>) -> Result<OpenFgaEvidenceRequest> {
        OpenFgaEvidenceRequest::new(
            &self.scope,
            &self.registration,
            &self.consent,
            AuthorizationCheckScope::new("user:fixture", "viewer", "document:fixture", 1)?,
            TupleScope::new("user:fixture", "viewer", "document:fixture", 1)?,
            25,
            requested_at,
        )
    }

    pub fn propose(
        &mut self,
        request: OpenFgaEvidenceRequest,
    ) -> Result<OpenFgaAuthorizationResultProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(OpenFgaAuthorizationResultError::RegistrationInactive);
        }
        if self.secret.is_revoked() {
            return Err(OpenFgaAuthorizationResultError::InvalidSecretReference);
        }
        self.consent.validate(&self.scope, self.now)?;
        request.validate(&self.scope, &self.registration, &self.consent)?;
        match self
            .provider
            .observe(&request.model, &request.check, &request.tuples)
        {
            Ok(observation) => Ok(OpenFgaAuthorizationResultProposal::from_observation(
                &self.scope,
                &self.consent,
                &self.registration,
                observation,
                request.revision_digest,
            )),
            Err(failure) => Ok(OpenFgaAuthorizationResultProposal::from_failure(
                &self.scope,
                &self.consent,
                &self.registration,
                &request,
                failure,
            )),
        }
    }

    #[must_use]
    pub fn verify(&self, proposal: &OpenFgaAuthorizationResultProposal) -> VerificationReport {
        let verified_digest = Digest::from_text(format!(
            "openfga-verification/v1|{}",
            proposal.proposal_digest
        ));
        let failure = match proposal.validate_integrity() {
            Ok(()) => {
                if proposal.registration_digest != *self.registration.registration_digest() {
                    Some(VerificationFailure::RegistrationMismatch)
                } else if proposal.scope != ScopeEvidence::from_scope(&self.scope)
                    || proposal.scope_digest != self.scope.digest()
                    || proposal.consent_digest != self.consent.digest()
                {
                    Some(VerificationFailure::ScopeMismatch)
                } else if !self.registration.is_active() {
                    Some(VerificationFailure::RegistrationRevoked)
                } else {
                    match proposal.state {
                        OpenFgaEvidenceState::Partial => Some(VerificationFailure::Partial),
                        OpenFgaEvidenceState::Stale => Some(VerificationFailure::Stale),
                        OpenFgaEvidenceState::Tampered => Some(VerificationFailure::Tampered),
                        OpenFgaEvidenceState::ProviderUnknown => {
                            Some(VerificationFailure::ProviderUnknown)
                        }
                        OpenFgaEvidenceState::RateLimited => Some(VerificationFailure::RateLimited),
                        OpenFgaEvidenceState::ConsentExpired => {
                            Some(VerificationFailure::ConsentExpired)
                        }
                        OpenFgaEvidenceState::RegistrationRevoked => {
                            Some(VerificationFailure::RegistrationRevoked)
                        }
                        OpenFgaEvidenceState::Ready
                        | OpenFgaEvidenceState::Denied
                        | OpenFgaEvidenceState::Unauthorized
                        | OpenFgaEvidenceState::Forbidden
                        | OpenFgaEvidenceState::NotFound
                        | OpenFgaEvidenceState::Conflict
                        | OpenFgaEvidenceState::TimedOut => None,
                    }
                }
            }
            Err(_) => Some(VerificationFailure::Tampered),
        };
        VerificationReport {
            valid: failure.is_none(),
            review_eligible: failure.is_none()
                && matches!(
                    proposal.state,
                    OpenFgaEvidenceState::Ready | OpenFgaEvidenceState::Denied
                ),
            failure,
            verified_digest,
        }
    }

    pub fn consumer(&self) -> Result<MissionOpenFgaAuthorizationConsumer> {
        MissionOpenFgaAuthorizationConsumer::new(self.scope.clone(), self.registration.clone())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }
}

impl<T: OpenFgaTransport> fmt::Debug for OpenFgaAuthorizationResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenFgaAuthorizationResultService")
            .field("scope_digest", &self.scope.digest())
            .field("consent_digest", &self.consent.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("provider", &self.provider.definition())
            .field("now", &self.now)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenFgaAuthorizationResultContract {
    value: serde_json::Value,
}

impl OpenFgaAuthorizationResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| OpenFgaAuthorizationResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(CONTRACT_DIGEST_INPUT)
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(OpenFgaAuthorizationResultError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "consent",
            "registration",
            "pagination",
            "projection",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(OpenFgaAuthorizationResultError::ContractDrift);
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_SCHEMA)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || self.digest().as_str() != CONTRACT_DIGEST
        {
            return Err(OpenFgaAuthorizationResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(OpenFgaAuthorizationResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("tupleWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("authorizationAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(OpenFgaAuthorizationResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(OpenFgaAuthorizationResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("tupleWrites") != Some(&serde_json::Value::Bool(false))
            || provider.get("authorizationAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(OpenFgaAuthorizationResultError::ContractDrift);
        }
        let forbidden = object
            .get("forbiddenEffects")
            .and_then(serde_json::Value::as_array)
            .ok_or(OpenFgaAuthorizationResultError::ContractDrift)?;
        for effect in [
            "WriteTuple",
            "WriteAuthorizationModel",
            "authorization.grant",
        ] {
            if !forbidden.iter().any(|value| value.as_str() == Some(effect)) {
                return Err(OpenFgaAuthorizationResultError::ContractDrift);
            }
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(OpenFgaAuthorizationResultError::ContractDrift)?;
        if provenance.get("connected") != Some(&serde_json::Value::Bool(false))
            || provenance.get("native") != Some(&serde_json::Value::Bool(false))
            || provenance.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provenance.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(OpenFgaAuthorizationResultError::ContractDrift);
        }
        let _ = BLOCKED_ENV;
        Ok(())
    }
}

impl<T: OpenFgaTransport> Serialize for OpenFgaAuthorizationResultService<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.describe_capabilities().serialize(serializer)
    }
}
