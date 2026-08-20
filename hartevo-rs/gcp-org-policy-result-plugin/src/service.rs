//! Read, proposal, recording, verification and reversible registration.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AvailableConstraintSummary, Digest, GcpOrgPolicyScope, MissionScope, PaginationEvidence,
    PolicySummary, ReadOperation, RedactionSummary, SecretReference,
};
use crate::provider::{
    GcpOrgPolicyProvider, GcpOrgPolicyProviderDefinition, GcpOrgPolicyReadRecord,
    GcpOrgPolicyTransport, GetEffectivePolicyRequest, GetPolicyRequest,
    ListAvailableConstraintsRequest, ListPoliciesRequest, ProviderError, TransportProvenance,
};
use crate::{
    API_VERSION, CONSUMER_ID, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationState {
    pub const fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpOrgPolicyServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] crate::model::ModelError),
    #[error("provider failed: {0}")]
    Provider(#[from] ProviderError),
    #[error("registration is not active")]
    RegistrationRevoked,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("secret reference is bound to another scope")]
    SecretScopeMismatch,
    #[error("Mission, Project, Work Product or resource scope mismatch")]
    ScopeMismatch,
    #[error("permission digest drifted")]
    PermissionDrift,
    #[error("provider digest drifted")]
    ProviderDrift,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("evidence or proposal integrity check failed")]
    TamperedEvidence,
    #[error("idempotency key conflicts with a different proposal")]
    RecordingConflict,
    #[error("idempotency key is empty or too long")]
    InvalidIdempotencyKey,
    #[error("registration is already terminal")]
    RegistrationAlreadyTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDefinition {
    pub plugin_id: String,
    pub service_id: String,
    pub contract_schema: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<ReadOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub reversible_registration: bool,
    pub external_writes: bool,
}

impl Default for ServiceDefinition {
    fn default() -> Self {
        Self {
            plugin_id: PLUGIN_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            contract_schema: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            api_version: API_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: ReadOperation::ALL.to_vec(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            reversible_registration: true,
            external_writes: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: crate::model::Revision,
    pub reversible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpOrgPolicyRegistration {
    pub service_id: String,
    pub provider_id: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: crate::model::Revision,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: crate::model::Revision,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

impl GcpOrgPolicyRegistration {
    fn new(
        scope: &GcpOrgPolicyScope,
        secret: &SecretReference,
        provider: &GcpOrgPolicyProviderDefinition,
    ) -> Self {
        let api_digest = Digest::from_parts(
            "gcp-org-policy-api/v1",
            &[
                ("version", API_VERSION.to_owned()),
                ("revision", PROVIDER_API_REVISION.to_owned()),
                (
                    "operations",
                    ReadOperation::ALL
                        .iter()
                        .map(|operation| format!("{operation:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        let evidence_digest = Digest::from_parts(
            "gcp-org-policy-evidence-schema/v1",
            &[
                ("plugin_version", PLUGIN_VERSION.to_owned()),
                ("contract", contract_digest().as_str().to_owned()),
                ("level", EVIDENCE_LEVEL.to_owned()),
            ],
        );
        let registration_digest = registration_digest(
            &api_digest,
            provider,
            scope,
            &evidence_digest,
            secret.reference_digest(),
            RegistrationState::Active,
            crate::model::Revision::new(1).expect("constant registration revision"),
        );
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            api_digest,
            provider_digest: provider.provider_digest.clone(),
            provider_revision: provider.provider_revision,
            permission_digest: scope.permissions.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            evidence_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision: crate::model::Revision::new(1)
                .expect("constant registration revision"),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
            registration_digest,
        }
    }

    pub fn validate(
        &self,
        scope: &GcpOrgPolicyScope,
        provider: &GcpOrgPolicyProviderDefinition,
        secret: &SecretReference,
    ) -> Result<(), GcpOrgPolicyServiceError> {
        if self.service_id != SERVICE_ID
            || self.provider_id != provider.provider_id
            || self.provider_digest != provider.provider_digest
            || self.provider_revision != provider.provider_revision
            || self.permission_digest != scope.permissions.permission_digest
            || self.scope_digest != scope.scope_digest
            || self.secret_reference_digest != *secret.reference_digest()
            || !self.reversible
            || !self.revocable
        {
            return Err(GcpOrgPolicyServiceError::TamperedEvidence);
        }
        let expected = registration_digest(
            &self.api_digest,
            provider,
            scope,
            &self.evidence_digest,
            &self.secret_reference_digest,
            self.state,
            self.registration_revision,
        );
        if expected != self.registration_digest {
            return Err(GcpOrgPolicyServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state.active()
    }

    pub fn revoke(
        &mut self,
        scope: &GcpOrgPolicyScope,
        provider: &GcpOrgPolicyProviderDefinition,
        secret: &SecretReference,
    ) -> Result<RegistrationTransition, GcpOrgPolicyServiceError> {
        self.transition(RegistrationState::Revoked, scope, provider, secret)
    }

    pub fn reverse(
        &mut self,
        scope: &GcpOrgPolicyScope,
        provider: &GcpOrgPolicyProviderDefinition,
        secret: &SecretReference,
    ) -> Result<RegistrationTransition, GcpOrgPolicyServiceError> {
        self.transition(RegistrationState::Reversed, scope, provider, secret)
    }

    pub fn restore(
        &mut self,
        scope: &GcpOrgPolicyScope,
        provider: &GcpOrgPolicyProviderDefinition,
        secret: &SecretReference,
    ) -> Result<RegistrationTransition, GcpOrgPolicyServiceError> {
        if !matches!(self.state, RegistrationState::Reversed) {
            return Err(GcpOrgPolicyServiceError::RegistrationAlreadyTerminal);
        }
        self.transition(RegistrationState::Active, scope, provider, secret)
    }

    fn transition(
        &mut self,
        new_state: RegistrationState,
        scope: &GcpOrgPolicyScope,
        provider: &GcpOrgPolicyProviderDefinition,
        secret: &SecretReference,
    ) -> Result<RegistrationTransition, GcpOrgPolicyServiceError> {
        if self.state == new_state || matches!(self.state, RegistrationState::Revoked) {
            return Err(GcpOrgPolicyServiceError::RegistrationAlreadyTerminal);
        }
        self.validate(scope, provider, secret)?;
        let previous_state = self.state;
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision =
            crate::model::Revision::new(self.registration_revision.get() + 1)
                .map_err(GcpOrgPolicyServiceError::Model)?;
        self.state = new_state;
        self.registration_digest = registration_digest(
            &self.api_digest,
            provider,
            scope,
            &self.evidence_digest,
            &self.secret_reference_digest,
            self.state,
            self.registration_revision,
        );
        Ok(RegistrationTransition {
            previous_state,
            new_state,
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
        })
    }
}

fn registration_digest(
    api_digest: &Digest,
    provider: &GcpOrgPolicyProviderDefinition,
    scope: &GcpOrgPolicyScope,
    evidence_digest: &Digest,
    secret_reference_digest: &Digest,
    state: RegistrationState,
    registration_revision: crate::model::Revision,
) -> Digest {
    Digest::from_parts(
        "gcp-org-policy-registration/v1",
        &[
            ("service", SERVICE_ID.to_owned()),
            ("api", api_digest.as_str().to_owned()),
            ("provider", provider.provider_digest.as_str().to_owned()),
            (
                "provider_revision",
                provider.provider_revision.get().to_string(),
            ),
            (
                "permission",
                scope.permissions.permission_digest.as_str().to_owned(),
            ),
            ("scope", scope.scope_digest.as_str().to_owned()),
            ("evidence", evidence_digest.as_str().to_owned()),
            ("secret", secret_reference_digest.as_str().to_owned()),
            ("state", format!("{state:?}")),
            (
                "registration_revision",
                registration_revision.get().to_string(),
            ),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub review_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub effective_authorization: bool,
    pub policy_truth_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl Default for AuthorityBoundary {
    fn default() -> Self {
        Self {
            review_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            durable_provider_receipt: false,
            effective_authorization: false,
            policy_truth_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpOrgPolicyEvidence {
    pub operation: ReadOperation,
    pub resource: crate::model::GcpResource,
    pub policies: Vec<PolicySummary>,
    pub available_constraints: Vec<AvailableConstraintSummary>,
    pub pagination: PaginationEvidence,
    pub redaction: RedactionSummary,
    pub provenance: TransportProvenance,
    pub authority: AuthorityBoundary,
    pub read_digest: Digest,
    pub digests: crate::model::EvidenceDigests,
}

impl GcpOrgPolicyEvidence {
    fn from_record(record: GcpOrgPolicyReadRecord) -> Self {
        let plugin_version_digest = Digest::from_text(PLUGIN_VERSION);
        let contract_digest_value = contract_digest();
        let api_digest = Digest::from_parts(
            "gcp-org-policy-api/v1",
            &[
                ("version", API_VERSION.to_owned()),
                ("revision", PROVIDER_API_REVISION.to_owned()),
                ("operation", format!("{:?}", record.operation)),
            ],
        );
        let evidence_digest = evidence_digest(
            &record,
            &plugin_version_digest,
            &contract_digest_value,
            &api_digest,
        );
        let digests = crate::model::EvidenceDigests {
            plugin_version_digest,
            contract_digest: contract_digest_value,
            api_digest,
            provider_digest: record.provider_digest.clone(),
            permission_digest: record.permission_digest.clone(),
            scope_digest: record.scope_digest.clone(),
            request_digest: record.request_digest.clone(),
            pagination_digest: record.pagination.pagination_digest.clone(),
            evidence_digest,
        };
        Self {
            operation: record.operation,
            resource: record.resource,
            policies: record.policies,
            available_constraints: record.available_constraints,
            pagination: record.pagination,
            redaction: RedactionSummary::default(),
            provenance: record.provenance,
            authority: AuthorityBoundary::default(),
            read_digest: record.read_digest,
            digests,
        }
    }

    pub fn validate_integrity(&self) -> Result<(), GcpOrgPolicyServiceError> {
        for policy in &self.policies {
            policy.validate().map_err(GcpOrgPolicyServiceError::Model)?;
        }
        for constraint in &self.available_constraints {
            constraint
                .validate()
                .map_err(GcpOrgPolicyServiceError::Model)?;
        }
        if self.authority != AuthorityBoundary::default()
            || self.redaction != RedactionSummary::default()
            || self.digests.pagination_digest != self.pagination.pagination_digest
        {
            return Err(GcpOrgPolicyServiceError::TamperedEvidence);
        }
        let record = GcpOrgPolicyReadRecord {
            operation: self.operation,
            resource: self.resource.clone(),
            policies: self.policies.clone(),
            available_constraints: self.available_constraints.clone(),
            pagination: self.pagination.clone(),
            scope_digest: self.digests.scope_digest.clone(),
            permission_digest: self.digests.permission_digest.clone(),
            request_digest: self.digests.request_digest.clone(),
            read_digest: self.read_digest.clone(),
            provider_digest: self.digests.provider_digest.clone(),
            provenance: self.provenance,
        };
        let expected = evidence_digest(
            &record,
            &self.digests.plugin_version_digest,
            &self.digests.contract_digest,
            &self.digests.api_digest,
        );
        if expected != self.digests.evidence_digest {
            return Err(GcpOrgPolicyServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

fn evidence_digest(
    record: &GcpOrgPolicyReadRecord,
    plugin_version_digest: &Digest,
    contract_digest_value: &Digest,
    api_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "gcp-org-policy-evidence/v1",
        &[
            ("plugin", plugin_version_digest.as_str().to_owned()),
            ("contract", contract_digest_value.as_str().to_owned()),
            ("api", api_digest.as_str().to_owned()),
            ("operation", format!("{:?}", record.operation)),
            ("resource", record.resource.canonical_name()),
            (
                "policies",
                record
                    .policies
                    .iter()
                    .map(|policy| policy.policy_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "constraints",
                record
                    .available_constraints
                    .iter()
                    .map(|constraint| constraint.definition_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "pagination",
                record.pagination.pagination_digest.as_str().to_owned(),
            ),
            ("read", record.read_digest.as_str().to_owned()),
            ("provider", record.provider_digest.as_str().to_owned()),
            ("permission", record.permission_digest.as_str().to_owned()),
            ("scope", record.scope_digest.as_str().to_owned()),
            ("request", record.request_digest.as_str().to_owned()),
            ("provenance", record.provenance.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpOrgPolicyReadResult {
    pub service_id: String,
    pub provider_id: String,
    pub scope_digest: Digest,
    pub mission: MissionScope,
    pub evidence: GcpOrgPolicyEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpOrgPolicyProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionScope,
    pub operation: ReadOperation,
    pub evidence: GcpOrgPolicyEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub effective_authorization: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl GcpOrgPolicyProposal {
    fn new(
        registration: &GcpOrgPolicyRegistration,
        scope: &GcpOrgPolicyScope,
        read: &GcpOrgPolicyReadResult,
    ) -> Self {
        let proposal_digest = proposal_digest(registration, scope, read);
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            mission: scope.mission.clone(),
            operation: read.evidence.operation,
            evidence: read.evidence.clone(),
            proposal_digest,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            effective_authorization: false,
            outcome_adopted: false,
            work_product_adopted: false,
        }
    }

    pub fn validate_integrity(&self) -> Result<(), GcpOrgPolicyServiceError> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.effective_authorization
            || self.outcome_adopted
            || self.work_product_adopted
            || self.scope_digest != self.evidence.digests.scope_digest
            || self.operation != self.evidence.operation
        {
            return Err(GcpOrgPolicyServiceError::TamperedEvidence);
        }
        let expected = Digest::from_parts(
            "gcp-org-policy-proposal/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("operation", format!("{:?}", self.operation)),
                (
                    "evidence",
                    self.evidence.digests.evidence_digest.as_str().to_owned(),
                ),
            ],
        );
        if expected != self.proposal_digest {
            return Err(GcpOrgPolicyServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

fn proposal_digest(
    registration: &GcpOrgPolicyRegistration,
    scope: &GcpOrgPolicyScope,
    read: &GcpOrgPolicyReadResult,
) -> Digest {
    Digest::from_parts(
        "gcp-org-policy-proposal/v1",
        &[
            (
                "registration",
                registration.registration_digest.as_str().to_owned(),
            ),
            ("scope", scope.scope_digest.as_str().to_owned()),
            ("mission", scope.mission.digest().as_str().to_owned()),
            ("operation", format!("{:?}", read.evidence.operation)),
            (
                "evidence",
                read.evidence.digests.evidence_digest.as_str().to_owned(),
            ),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub pagination_complete: bool,
    pub review_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedGcpOrgPolicyResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub operation: ReadOperation,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedGcpOrgPolicyResult {
    fn new(idempotency_key_digest: Digest, proposal: &GcpOrgPolicyProposal) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            operation: proposal.operation,
            replayed: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-gcp-org-policy-recording"),
        };
        result.recording_digest = result.recording_digest();
        result
    }

    fn recording_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-org-policy-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("operation", format!("{:?}", self.operation)),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<(), GcpOrgPolicyServiceError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.recording_digest()
        {
            return Err(GcpOrgPolicyServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct GcpOrgPolicyService<T> {
    scope: GcpOrgPolicyScope,
    secret: SecretReference,
    provider: GcpOrgPolicyProvider<T>,
    registration: GcpOrgPolicyRegistration,
    recordings: BTreeMap<Digest, RecordedGcpOrgPolicyResult>,
}

impl<T: GcpOrgPolicyTransport> fmt::Debug for GcpOrgPolicyService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpOrgPolicyService")
            .field("scope_digest", &self.scope.scope_digest)
            .field("secret", &self.secret)
            .field("registration", &self.registration)
            .field("recording_count", &self.recordings.len())
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: GcpOrgPolicyTransport> GcpOrgPolicyService<T> {
    pub fn new(
        scope: GcpOrgPolicyScope,
        secret: SecretReference,
        provider: GcpOrgPolicyProvider<T>,
    ) -> Result<Self, GcpOrgPolicyServiceError> {
        if secret.scope_digest() != scope.digest() {
            return Err(GcpOrgPolicyServiceError::SecretScopeMismatch);
        }
        if secret.is_revoked() {
            return Err(GcpOrgPolicyServiceError::SecretRevoked);
        }
        let registration = GcpOrgPolicyRegistration::new(&scope, &secret, provider.definition());
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            recordings: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> ServiceDefinition {
        ServiceDefinition::default()
    }

    pub fn scope(&self) -> &GcpOrgPolicyScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn provider(&self) -> &GcpOrgPolicyProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GcpOrgPolicyProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &GcpOrgPolicyRegistration {
        &self.registration
    }

    pub fn ensure_registration_active(&self) -> Result<(), GcpOrgPolicyServiceError> {
        self.registration
            .validate(&self.scope, self.provider.definition(), &self.secret)?;
        if !self.registration.is_active() {
            return Err(GcpOrgPolicyServiceError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(GcpOrgPolicyServiceError::SecretRevoked);
        }
        Ok(())
    }

    pub fn read_list_policies(
        &mut self,
    ) -> Result<GcpOrgPolicyReadResult, GcpOrgPolicyServiceError> {
        self.read_list_policies_for_constraint(None)
    }

    pub fn read_list_policies_for_constraint(
        &mut self,
        constraint: Option<crate::model::ConstraintId>,
    ) -> Result<GcpOrgPolicyReadResult, GcpOrgPolicyServiceError> {
        self.ensure_registration_active()?;
        let request =
            ListPoliciesRequest::new(&self.scope, self.provider.bounds(), constraint, None)?;
        let record = self.provider.list_policies(request)?;
        self.read_result(record)
    }

    pub fn read_get_policy(
        &mut self,
        constraint: crate::model::ConstraintId,
    ) -> Result<GcpOrgPolicyReadResult, GcpOrgPolicyServiceError> {
        self.ensure_registration_active()?;
        let request = GetPolicyRequest::new(&self.scope, constraint)?;
        let record = self.provider.get_policy(request)?;
        self.read_result(record)
    }

    pub fn read_get_effective_policy(
        &mut self,
        constraint: crate::model::ConstraintId,
    ) -> Result<GcpOrgPolicyReadResult, GcpOrgPolicyServiceError> {
        self.ensure_registration_active()?;
        let request = GetEffectivePolicyRequest::new(&self.scope, constraint)?;
        let record = self.provider.get_effective_policy(request)?;
        self.read_result(record)
    }

    pub fn read_list_available_constraints(
        &mut self,
    ) -> Result<GcpOrgPolicyReadResult, GcpOrgPolicyServiceError> {
        self.ensure_registration_active()?;
        let request =
            ListAvailableConstraintsRequest::new(&self.scope, self.provider.bounds(), None);
        let record = self.provider.list_available_constraints(request)?;
        self.read_result(record)
    }

    pub fn read_available_constraints(
        &mut self,
    ) -> Result<GcpOrgPolicyReadResult, GcpOrgPolicyServiceError> {
        self.read_list_available_constraints()
    }

    fn read_result(
        &self,
        record: GcpOrgPolicyReadRecord,
    ) -> Result<GcpOrgPolicyReadResult, GcpOrgPolicyServiceError> {
        if record.scope_digest != self.scope.scope_digest
            || record.permission_digest != self.scope.permissions.permission_digest
            || record.provider_digest != self.provider.definition().provider_digest
        {
            return Err(GcpOrgPolicyServiceError::ScopeMismatch);
        }
        let evidence = GcpOrgPolicyEvidence::from_record(record);
        evidence.validate_integrity()?;
        Ok(GcpOrgPolicyReadResult {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            scope_digest: self.scope.scope_digest.clone(),
            mission: self.scope.mission.clone(),
            evidence,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn propose(
        &self,
        read: &GcpOrgPolicyReadResult,
    ) -> Result<GcpOrgPolicyProposal, GcpOrgPolicyServiceError> {
        self.ensure_registration_active()?;
        self.validate_read_binding(read)?;
        Ok(GcpOrgPolicyProposal::new(
            &self.registration,
            &self.scope,
            read,
        ))
    }

    pub fn propose_result(
        &self,
        read: &GcpOrgPolicyReadResult,
    ) -> Result<GcpOrgPolicyProposal, GcpOrgPolicyServiceError> {
        self.propose(read)
    }

    fn validate_read_binding(
        &self,
        read: &GcpOrgPolicyReadResult,
    ) -> Result<(), GcpOrgPolicyServiceError> {
        read.evidence.validate_integrity()?;
        if read.service_id != SERVICE_ID
            || read.provider_id != PROVIDER_ID
            || !read.review_only
            || read.connected
            || read.native
            || read.first_party
            || read.scope_digest != self.scope.scope_digest
            || read.mission.digest() != self.scope.mission.digest()
            || read.evidence.digests.scope_digest != self.scope.scope_digest
            || read.evidence.digests.permission_digest != self.scope.permissions.permission_digest
            || read.evidence.digests.provider_digest != self.provider.definition().provider_digest
        {
            return Err(GcpOrgPolicyServiceError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &GcpOrgPolicyProposal,
    ) -> Result<VerificationReport, GcpOrgPolicyServiceError> {
        self.ensure_registration_active()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.mission.digest() != self.scope.mission.digest()
        {
            return Err(GcpOrgPolicyServiceError::ScopeMismatch);
        }
        Ok(VerificationReport {
            valid: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            pagination_complete: proposal.evidence.pagination.complete,
            review_only: true,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &GcpOrgPolicyProposal,
    ) -> Result<VerificationReport, GcpOrgPolicyServiceError> {
        self.verify(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &GcpOrgPolicyProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedGcpOrgPolicyResult, GcpOrgPolicyServiceError> {
        self.verify(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::model::MAX_IDENTIFIER_BYTES
        {
            return Err(GcpOrgPolicyServiceError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.recordings.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(GcpOrgPolicyServiceError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.recording_digest();
            return Ok(replay);
        }
        let result = RecordedGcpOrgPolicyResult::new(key_digest.clone(), proposal);
        self.recordings.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransition, GcpOrgPolicyServiceError> {
        self.registration
            .revoke(&self.scope, self.provider.definition(), &self.secret)
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransition, GcpOrgPolicyServiceError> {
        self.registration
            .reverse(&self.scope, self.provider.definition(), &self.secret)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransition, GcpOrgPolicyServiceError> {
        self.registration
            .restore(&self.scope, self.provider.definition(), &self.secret)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), GcpOrgPolicyServiceError> {
        self.secret
            .revoke()
            .map_err(GcpOrgPolicyServiceError::Model)
    }
}
