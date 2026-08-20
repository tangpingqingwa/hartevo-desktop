use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
    error::ModelError,
    model::{
        ALL_READ_OPERATIONS, AuthorityBoundary, ConditionType, Digest, EvidenceStatus,
        IssueEventType, IssueState, ObservabilityScope, ObservationState, ReadOperation,
        SecretReference, Severity, TransportProvenance,
    },
    provider::{
        EntityRecord, NewRelicProvider, NewRelicReadRequest, ProviderError, ProviderResponse,
        RetryEvidence, TransportFailure,
    },
};

const EXPECTED_OPERATION_COUNT: u8 = 6;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    pub version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub account_digest: Digest,
    pub entity_digest: Digest,
    pub workload_digest: Digest,
    pub policy_digest: Digest,
    pub condition_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub time_window_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl Registration {
    pub fn new(
        scope: &ObservabilityScope,
        provider_digest: &Digest,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        secret.validate_for(scope)?;
        provider_digest.validate()?;
        let mut registration = Self {
            version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: provider_digest.clone(),
            api_digest: Digest::from_text(API_REVISION),
            account_digest: scope.account().digest(),
            entity_digest: scope.entity().digest().clone(),
            workload_digest: scope.workload().digest().clone(),
            policy_digest: scope.policy().digest().clone(),
            condition_digest: scope.condition().digest().clone(),
            permission_digest: scope.permissions().digest.clone(),
            query_digest: scope.query_policy().digest.clone(),
            time_window_digest: scope.time_window().digest.clone(),
            scope_digest: scope.digest().clone(),
            secret_reference_digest: secret.secret_digest().clone(),
            revision: 1,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("pending-newrelic-registration"),
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "newrelic-registration/v1",
            &[
                ("version", self.version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("entity", self.entity_digest.as_str().to_owned()),
                ("workload", self.workload_digest.as_str().to_owned()),
                ("policy", self.policy_digest.as_str().to_owned()),
                ("condition", self.condition_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("window", self.time_window_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
                ("state", format!("{:?}", self.state)),
                ("reversible", self.reversible.to_string()),
                ("revocable", self.revocable.to_string()),
            ],
        )
    }

    pub fn verify(
        &self,
        scope: &ObservabilityScope,
        provider_digest: &Digest,
        secret: &SecretReference,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        secret.validate_for(scope)?;
        if self.version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_digest != contract_digest()
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.provider_digest != *provider_digest
            || self.account_digest != scope.account().digest()
            || self.entity_digest != *scope.entity().digest()
            || self.workload_digest != *scope.workload().digest()
            || self.policy_digest != *scope.policy().digest()
            || self.condition_digest != *scope.condition().digest()
            || self.permission_digest != scope.permissions().digest
            || self.query_digest != scope.query_policy().digest
            || self.time_window_digest != scope.time_window().digest
            || self.scope_digest != *scope.digest()
            || self.secret_reference_digest != *secret.secret_digest()
            || !self.reversible
            || !self.revocable
            || self.revision == 0
            || self.compute_digest() != self.registration_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    fn transition(&mut self, state: RegistrationState) -> Result<(), ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::InvalidScope);
        }
        if self.state == state {
            return Err(ModelError::InvalidScope);
        }
        if state == RegistrationState::Active && self.state != RegistrationState::Reversed {
            return Err(ModelError::InvalidScope);
        }
        if state == RegistrationState::Reversed && self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope);
        }
        self.revision = self.revision.saturating_add(1);
        self.state = state;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn reverse(&mut self) -> Result<(), ModelError> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        self.transition(RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::InvalidScope);
        }
        self.revision = self.revision.saturating_add(1);
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadPlan {
    pub requests: Vec<NewRelicReadRequest>,
    pub plan_digest: Digest,
    pub bounded: bool,
    pub arbitrary_query: bool,
    pub external_writes: bool,
}

impl ReadPlan {
    fn new(
        requests: Vec<NewRelicReadRequest>,
        scope: &ObservabilityScope,
    ) -> Result<Self, ModelError> {
        if requests.len() != ALL_READ_OPERATIONS.len()
            || requests.iter().any(|request| request.cursor.is_some())
        {
            return Err(ModelError::InvalidBound { field: "read plan" });
        }
        let plan_digest = crate::model::digest_serializable(&requests)?;
        let plan = Self {
            requests,
            plan_digest,
            bounded: true,
            arbitrary_query: false,
            external_writes: false,
        };
        if plan.requests.iter().any(|request| {
            request.scope_digest != *scope.digest()
                || !request.allowlisted
                || request.arbitrary_query
                || !request.redacted
        }) {
            return Err(ModelError::InvalidScope);
        }
        Ok(plan)
    }

    pub fn verify(&self, scope: &ObservabilityScope) -> Result<(), ModelError> {
        if !self.bounded || self.arbitrary_query || self.external_writes {
            return Err(ModelError::InvalidScope);
        }
        for request in &self.requests {
            request.validate(scope)?;
        }
        if self.requests.len() != ALL_READ_OPERATIONS.len()
            || self.plan_digest != crate::model::digest_serializable(&self.requests)?
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservabilityResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub time_window_digest: Digest,
    pub plan: ReadPlan,
    pub proposal_digest: Digest,
    pub native_execution: bool,
    pub authority: AuthorityBoundary,
}

impl ObservabilityResultProposal {
    fn compute_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.service_id,
            &self.provider_id,
            &self.consumer_id,
            &self.contract_version,
            &self.contract_digest,
            &self.registration_digest,
            self.registration_revision,
            &self.provider_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.time_window_digest,
            &self.plan,
            self.native_execution,
            &self.authority,
        ))
    }

    pub fn verify(&self, scope: &ObservabilityScope) -> Result<(), ModelError> {
        self.plan.verify(scope)?;
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.scope_digest != *scope.digest()
            || self.permission_digest != scope.permissions().digest
            || self.query_digest != scope.query_policy().digest
            || self.time_window_digest != scope.time_window().digest
            || self.native_execution
            || self.authority != AuthorityBoundary::layer1()
            || self.compute_digest()? != self.proposal_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn verify_digest(&self) -> Result<(), ModelError> {
        if self.compute_digest()? == self.proposal_digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageEvidence {
    pub operation: ReadOperation,
    pub page: u8,
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub item_count: u16,
    pub response_bytes: usize,
    pub complete: bool,
    pub redacted: bool,
    pub failure_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntityObservation {
    pub entity_digest: Digest,
    pub entity_type_digest: Digest,
    pub reporting: Option<bool>,
    pub alert_severity: Option<Severity>,
    pub state: ObservationState,
    pub observed_at_millis: Option<i64>,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyObservation {
    pub policy_digest: Digest,
    pub enabled: Option<bool>,
    pub condition_count: u16,
    pub revision_digest: Digest,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionObservation {
    pub condition_digest: Digest,
    pub policy_digest: Digest,
    pub condition_type: ConditionType,
    pub enabled: Option<bool>,
    pub revision_digest: Digest,
    pub definition_digest: Digest,
    pub observed_at_millis: Option<i64>,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueObservation {
    pub issue_digest: Digest,
    pub priority: Severity,
    pub state: IssueState,
    pub entity_guid_digests: Vec<Digest>,
    pub entity_type_digests: Vec<Digest>,
    pub title_digest: Digest,
    pub updated_at_millis: Option<i64>,
    pub observation_state: ObservationState,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncidentObservation {
    pub issue_digest: Digest,
    pub priority: Severity,
    pub state: IssueState,
    pub event_type: IssueEventType,
    pub title_digest: Digest,
    pub timestamp_millis: Option<i64>,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Completeness {
    pub expected_operations: u8,
    pub completed_operations: u8,
    pub pages: u16,
    pub max_pages_per_operation: u8,
    pub truncated: bool,
    pub duplicate_detected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservabilityEvidence {
    pub proposal_digest: Digest,
    pub status: EvidenceStatus,
    pub state: ObservationState,
    pub account_digest: Digest,
    pub scope_digest: Digest,
    pub entity_digest: Digest,
    pub workload_digest: Digest,
    pub policy_digest: Digest,
    pub condition_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub time_window_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub page_evidence: Vec<PageEvidence>,
    pub entities: Vec<EntityObservation>,
    pub policies: Vec<PolicyObservation>,
    pub conditions: Vec<ConditionObservation>,
    pub issues: Vec<IssueObservation>,
    pub incidents: Vec<IncidentObservation>,
    pub retries: Vec<RetryEvidence>,
    pub completeness: Completeness,
    pub provenance: TransportProvenance,
    pub authority: AuthorityBoundary,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestMaterial<'a> {
    proposal_digest: &'a Digest,
    status: EvidenceStatus,
    state: ObservationState,
    account_digest: &'a Digest,
    scope_digest: &'a Digest,
    entity_digest: &'a Digest,
    workload_digest: &'a Digest,
    policy_digest: &'a Digest,
    condition_digest: &'a Digest,
    mission_digest: &'a Digest,
    project_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    permission_digest: &'a Digest,
    query_digest: &'a Digest,
    time_window_digest: &'a Digest,
    provider_digest: &'a Digest,
    registration_digest: &'a Digest,
    page_evidence: &'a [PageEvidence],
    entities: &'a [EntityObservation],
    policies: &'a [PolicyObservation],
    conditions: &'a [ConditionObservation],
    issues: &'a [IssueObservation],
    incidents: &'a [IncidentObservation],
    retries: &'a [RetryEvidence],
    completeness: &'a Completeness,
    provenance: TransportProvenance,
    authority: &'a AuthorityBoundary,
}

impl ObservabilityEvidence {
    fn compute_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&EvidenceDigestMaterial {
            proposal_digest: &self.proposal_digest,
            status: self.status,
            state: self.state,
            account_digest: &self.account_digest,
            scope_digest: &self.scope_digest,
            entity_digest: &self.entity_digest,
            workload_digest: &self.workload_digest,
            policy_digest: &self.policy_digest,
            condition_digest: &self.condition_digest,
            mission_digest: &self.mission_digest,
            project_digest: &self.project_digest,
            work_product_digest: &self.work_product_digest,
            consent_digest: &self.consent_digest,
            permission_digest: &self.permission_digest,
            query_digest: &self.query_digest,
            time_window_digest: &self.time_window_digest,
            provider_digest: &self.provider_digest,
            registration_digest: &self.registration_digest,
            page_evidence: &self.page_evidence,
            entities: &self.entities,
            policies: &self.policies,
            conditions: &self.conditions,
            issues: &self.issues,
            incidents: &self.incidents,
            retries: &self.retries,
            completeness: &self.completeness,
            provenance: self.provenance,
            authority: &self.authority,
        })
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        for digest in [
            &self.proposal_digest,
            &self.account_digest,
            &self.scope_digest,
            &self.entity_digest,
            &self.workload_digest,
            &self.policy_digest,
            &self.condition_digest,
            &self.mission_digest,
            &self.project_digest,
            &self.work_product_digest,
            &self.consent_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.time_window_digest,
            &self.provider_digest,
            &self.registration_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self.authority != AuthorityBoundary::layer1()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.compute_digest()? != self.evidence_digest
            || self.page_evidence.iter().any(|page| !page.redacted)
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservabilityResult {
    pub proposal: ObservabilityResultProposal,
    pub evidence: ObservabilityEvidence,
    pub result_digest: Digest,
}

impl ObservabilityResult {
    fn compute_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.proposal.proposal_digest,
            &self.evidence.evidence_digest,
            false,
            false,
            false,
        ))
    }

    pub fn verify(&self, scope: &ObservabilityScope) -> Result<(), ModelError> {
        self.proposal.verify(scope)?;
        self.evidence.verify()?;
        if self.evidence.proposal_digest != self.proposal.proposal_digest
            || self.evidence.scope_digest != *scope.digest()
            || self.compute_digest()? != self.result_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        self.evidence.verify()?;
        self.proposal.verify_digest()?;
        if self.evidence.proposal_digest != self.proposal.proposal_digest
            || self.compute_digest()? != self.result_digest
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(ProviderError),
    #[error("New Relic registration is revoked")]
    RegistrationRevoked,
    #[error("New Relic registration is reversed")]
    RegistrationReversed,
    #[error("New Relic registration or secret binding is stale")]
    RegistrationDrift,
    #[error("New Relic evidence is tampered")]
    TamperedEvidence,
    #[error("New Relic evidence is partial and cannot be consumed as complete")]
    PartialEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct Layer1Capabilities {
    pub service_id: String,
    pub provider_id: String,
    pub api_revision: String,
    pub operations: Vec<ReadOperation>,
    pub allowed_transports: Vec<TransportProvenance>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub arbitrary_query: bool,
    pub external_writes: bool,
    pub raw_telemetry: bool,
    pub native_execution: bool,
    pub connected: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

impl Layer1Capabilities {
    pub fn new() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: ALL_READ_OPERATIONS.to_vec(),
            allowed_transports: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fixture,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
            read_only: true,
            proposal_only: true,
            arbitrary_query: false,
            external_writes: false,
            raw_telemetry: false,
            native_execution: false,
            connected: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
        }
    }
}

impl Default for Layer1Capabilities {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct NewRelicObservabilityReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub status: EvidenceStatus,
    pub observed_at_millis: i64,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub authority: AuthorityBoundary,
}

impl NewRelicObservabilityReceipt {
    fn compute_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.proposal_digest,
            &self.evidence_digest,
            self.status,
            self.observed_at_millis,
            self.durable,
            self.connected,
            self.native,
            self.first_party,
            &self.authority,
        ))
    }

    pub fn verify(&self, result: &ObservabilityResult) -> Result<(), ModelError> {
        if self.proposal_digest != result.proposal.proposal_digest
            || self.evidence_digest != result.evidence.evidence_digest
            || self.status != result.evidence.status
            || self.durable
            || self.connected
            || self.native
            || self.first_party
            || self.authority != AuthorityBoundary::layer1()
            || self.compute_digest()? != self.receipt_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

pub struct NewRelicObservabilityResultService<T> {
    scope: ObservabilityScope,
    secret: SecretReference,
    provider: NewRelicProvider<T>,
    registration: Registration,
}

impl<T: fmt::Debug> fmt::Debug for NewRelicObservabilityResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewRelicObservabilityResultService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

pub type NewRelicObservabilityService<T> = NewRelicObservabilityResultService<T>;

impl<T: crate::provider::NewRelicTransport + fmt::Debug> NewRelicObservabilityResultService<T> {
    pub fn new(
        scope: ObservabilityScope,
        secret: SecretReference,
        provider: NewRelicProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        secret.validate_for(&scope)?;
        provider.definition().validate()?;
        let registration = Registration::new(&scope, provider.provider_digest(), &secret)?;
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
        })
    }

    pub fn describe_capabilities(&self) -> Layer1Capabilities {
        Layer1Capabilities::new()
    }

    pub fn scope(&self) -> &ObservabilityScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn provider(&self) -> &NewRelicProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut NewRelicProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn revoke_registration(&mut self) -> Result<(), ServiceError> {
        self.registration.revoke().map_err(ServiceError::Model)
    }

    pub fn reverse_registration(&mut self) -> Result<(), ServiceError> {
        self.registration.reverse().map_err(ServiceError::Model)
    }

    pub fn restore_registration(&mut self) -> Result<(), ServiceError> {
        self.registration.restore().map_err(ServiceError::Model)
    }

    pub fn revoke_secret(&mut self) -> Result<(), ServiceError> {
        self.secret.revoke()?;
        self.registration.revoke().map_err(ServiceError::Model)
    }

    fn ensure_active(&self) -> Result<(), ServiceError> {
        match self.registration.state {
            RegistrationState::Revoked => Err(ServiceError::RegistrationRevoked),
            RegistrationState::Reversed => Err(ServiceError::RegistrationReversed),
            RegistrationState::Active if self.secret.is_revoked() => {
                Err(ServiceError::RegistrationDrift)
            }
            RegistrationState::Active => Ok(()),
        }
    }

    fn verify_registration(&self) -> Result<(), ServiceError> {
        self.registration
            .verify(&self.scope, self.provider.provider_digest(), &self.secret)
            .map_err(|_| ServiceError::RegistrationDrift)
    }

    pub fn propose(&self) -> Result<ObservabilityResultProposal, ServiceError> {
        self.ensure_active()?;
        self.verify_registration()?;
        let mut requests = Vec::with_capacity(ALL_READ_OPERATIONS.len());
        for operation in ALL_READ_OPERATIONS {
            requests.push(NewRelicReadRequest::first(&self.scope, operation)?);
        }
        let plan = ReadPlan::new(requests, &self.scope)?;
        let mut proposal = ObservabilityResultProposal {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_digest: self.provider.provider_digest().clone(),
            scope_digest: self.scope.digest().clone(),
            permission_digest: self.scope.permissions().digest.clone(),
            query_digest: self.scope.query_policy().digest.clone(),
            time_window_digest: self.scope.time_window().digest.clone(),
            plan,
            proposal_digest: Digest::from_text("pending-newrelic-proposal"),
            native_execution: false,
            authority: AuthorityBoundary::layer1(),
        };
        proposal.proposal_digest = proposal.compute_digest()?;
        Ok(proposal)
    }

    pub fn propose_result(&self) -> Result<ObservabilityResultProposal, ServiceError> {
        self.propose()
    }

    pub fn observe(&mut self) -> Result<ObservabilityResult, ServiceError> {
        let proposal = self.propose()?;
        let mut accumulator = EvidenceAccumulator::default();
        for initial_request in &proposal.plan.requests {
            self.collect_operation(initial_request, &mut accumulator)?;
        }
        let status = accumulator.status();
        let state = accumulator.state(status);
        let evidence = accumulator.finish(
            &proposal,
            &self.scope,
            self.provider.provenance(),
            status,
            state,
        )?;
        let mut result = ObservabilityResult {
            proposal,
            evidence,
            result_digest: Digest::from_text("pending-newrelic-result"),
        };
        result.result_digest = result.compute_digest()?;
        Ok(result)
    }

    pub fn read_and_propose(&mut self) -> Result<ObservabilityResult, ServiceError> {
        self.observe()
    }

    fn collect_operation(
        &mut self,
        initial_request: &NewRelicReadRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<(), ServiceError> {
        let mut request = initial_request.clone();
        let mut seen_cursors = BTreeSet::new();
        let mut page = 1_u8;
        loop {
            let read = match self.provider.read(&request, &self.scope) {
                Ok(read) => read,
                Err(ProviderError::Transport { error, retries }) => {
                    accumulator.add_retries(retries);
                    accumulator.record_failure(
                        request.operation,
                        page,
                        request.request_digest.clone(),
                        error,
                    );
                    return Ok(());
                }
                Err(ProviderError::InvalidRequest(error)) => {
                    return Err(ServiceError::Model(error));
                }
                Err(error) => return Err(ServiceError::Provider(error)),
            };
            accumulator.add_retries(read.retries);
            let next_cursor = read.response.next_cursor().cloned();
            accumulator.record_response(&request, page, &read.response)?;
            if let Some(cursor) = next_cursor {
                if page >= self.scope.query_policy().max_pages
                    || cursor.page() != page.saturating_add(1)
                    || !seen_cursors.insert(cursor.digest().clone())
                {
                    accumulator.mark_partial(true);
                    return Ok(());
                }
                request = request.with_cursor(&self.scope, cursor)?;
                page = page.saturating_add(1);
            } else {
                accumulator.complete_operation();
                return Ok(());
            }
        }
    }

    pub fn record_observation_receipt(
        &self,
        result: &ObservabilityResult,
    ) -> Result<NewRelicObservabilityReceipt, ServiceError> {
        self.verify_result(result)?;
        let mut receipt = NewRelicObservabilityReceipt {
            proposal_digest: result.proposal.proposal_digest.clone(),
            evidence_digest: result.evidence.evidence_digest.clone(),
            receipt_digest: Digest::from_text("pending-newrelic-receipt"),
            status: result.evidence.status,
            observed_at_millis: self.scope.time_window().end_millis,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
            authority: AuthorityBoundary::layer1(),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        Ok(receipt)
    }

    pub fn record_receipt(
        &self,
        result: &ObservabilityResult,
    ) -> Result<NewRelicObservabilityReceipt, ServiceError> {
        self.record_observation_receipt(result)
    }

    pub fn verify_result(&self, result: &ObservabilityResult) -> Result<(), ServiceError> {
        self.ensure_active()?;
        self.verify_registration()?;
        result
            .verify(&self.scope)
            .map_err(|_| ServiceError::TamperedEvidence)?;
        if result.proposal.registration_digest != self.registration.registration_digest
            || result.proposal.registration_revision != self.registration.revision
            || result.proposal.provider_digest != *self.provider.provider_digest()
            || result.evidence.registration_digest != self.registration.registration_digest
            || result.evidence.provider_digest != *self.provider.provider_digest()
        {
            return Err(ServiceError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn verify_receipt(
        &self,
        result: &ObservabilityResult,
        receipt: &NewRelicObservabilityReceipt,
    ) -> Result<(), ServiceError> {
        self.verify_result(result)?;
        receipt
            .verify(result)
            .map_err(|_| ServiceError::TamperedEvidence)
    }
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)]
struct EvidenceAccumulator {
    page_evidence: Vec<PageEvidence>,
    entities: Vec<EntityObservation>,
    policies: Vec<PolicyObservation>,
    conditions: Vec<ConditionObservation>,
    issues: Vec<IssueObservation>,
    incidents: Vec<IncidentObservation>,
    retries: Vec<RetryEvidence>,
    seen_records: BTreeSet<(ReadOperation, Digest)>,
    completed_operations: u8,
    pages: u16,
    successful_pages: u16,
    partial: bool,
    truncated: bool,
    duplicate_detected: bool,
    access_lost: bool,
    provider_unknown: bool,
}

impl EvidenceAccumulator {
    fn add_retries(&mut self, retries: Vec<RetryEvidence>) {
        self.retries.extend(retries);
    }

    fn complete_operation(&mut self) {
        self.completed_operations = self.completed_operations.saturating_add(1);
    }

    fn mark_partial(&mut self, truncated: bool) {
        self.partial = true;
        self.truncated |= truncated;
    }

    fn record_failure(
        &mut self,
        operation: ReadOperation,
        page: u8,
        request_digest: Digest,
        error: crate::provider::TransportError,
    ) {
        self.partial = true;
        match error.failure {
            TransportFailure::Unauthorized
            | TransportFailure::AccessDenied
            | TransportFailure::NotFound
            | TransportFailure::BlockedEnv => self.access_lost = true,
            TransportFailure::Throttled
            | TransportFailure::Server
            | TransportFailure::Timeout
            | TransportFailure::Malformed => self.provider_unknown = true,
        }
        self.page_evidence.push(PageEvidence {
            operation,
            page,
            request_digest,
            response_digest: None,
            cursor_digest: None,
            item_count: 0,
            response_bytes: 0,
            complete: false,
            redacted: true,
            failure_digest: Some(error.diagnostic_digest),
        });
    }

    #[allow(clippy::too_many_lines)]
    fn record_response(
        &mut self,
        request: &NewRelicReadRequest,
        page: u8,
        response: &ProviderResponse,
    ) -> Result<(), ServiceError> {
        self.pages = self.pages.saturating_add(1);
        self.successful_pages = self.successful_pages.saturating_add(1);
        let item_count = response.item_count();
        let item_count = u16::try_from(item_count).map_err(|_| {
            ServiceError::Model(ModelError::InvalidBound {
                field: "provider item count",
            })
        })?;
        self.page_evidence.push(PageEvidence {
            operation: request.operation,
            page,
            request_digest: request.request_digest.clone(),
            response_digest: Some(response.response_digest().clone()),
            cursor_digest: response.next_cursor().map(|value| value.digest().clone()),
            item_count,
            response_bytes: response.response_bytes(),
            complete: response.next_cursor().is_none(),
            redacted: response.redacted(),
            failure_digest: None,
        });
        match response {
            ProviderResponse::Entities(page) | ProviderResponse::EntitySummary(page) => {
                for entity in &page.entities {
                    let record_digest = entity.digest();
                    self.record_seen(request.operation, record_digest.clone());
                    self.entities.push(EntityObservation {
                        entity_digest: entity.guid.digest(),
                        entity_type_digest: entity.entity_type.digest(),
                        reporting: entity.reporting,
                        alert_severity: entity.alert_severity,
                        state: entity_state(entity),
                        observed_at_millis: entity.observed_at_millis,
                        record_digest,
                    });
                }
            }
            ProviderResponse::Policies(page) => {
                for policy in &page.policies {
                    let record_digest = policy.digest();
                    self.record_seen(request.operation, record_digest.clone());
                    self.policies.push(PolicyObservation {
                        policy_digest: policy.id.digest(),
                        enabled: policy.enabled,
                        condition_count: policy.condition_count,
                        revision_digest: policy.revision_digest.clone(),
                        record_digest,
                    });
                }
            }
            ProviderResponse::Conditions(page) => {
                for condition in &page.conditions {
                    let record_digest = condition.digest();
                    self.record_seen(request.operation, record_digest.clone());
                    self.conditions.push(ConditionObservation {
                        condition_digest: condition.id.digest(),
                        policy_digest: condition.policy_id.digest(),
                        condition_type: condition.condition_type,
                        enabled: condition.enabled,
                        revision_digest: condition.revision_digest.clone(),
                        definition_digest: condition.definition_digest.clone(),
                        observed_at_millis: condition.observed_at_millis,
                        record_digest,
                    });
                }
            }
            ProviderResponse::Issues(page) => {
                for issue in &page.issues {
                    let record_digest = issue.digest()?;
                    self.record_seen(request.operation, record_digest.clone());
                    self.issues.push(IssueObservation {
                        issue_digest: issue.id.digest(),
                        priority: issue.priority,
                        state: issue.state,
                        entity_guid_digests: issue.entity_guid_digests.clone(),
                        entity_type_digests: issue.entity_type_digests.clone(),
                        title_digest: issue.title_digest.clone(),
                        updated_at_millis: issue.updated_at_millis,
                        observation_state: if issue.state.is_closed() {
                            ObservationState::Closed
                        } else {
                            ObservationState::Alerting
                        },
                        record_digest,
                    });
                }
            }
            ProviderResponse::IssueEvents(page) => {
                for event in &page.events {
                    let record_digest = event.digest()?;
                    self.record_seen(request.operation, record_digest.clone());
                    self.incidents.push(IncidentObservation {
                        issue_digest: event.issue_id.digest(),
                        priority: event.priority,
                        state: event.state,
                        event_type: event.event_type,
                        title_digest: event.title_digest.clone(),
                        timestamp_millis: event.timestamp_millis,
                        record_digest,
                    });
                }
            }
        }
        Ok(())
    }

    fn record_seen(&mut self, operation: ReadOperation, digest: Digest) {
        if !self.seen_records.insert((operation, digest)) {
            self.duplicate_detected = true;
            self.partial = true;
        }
    }

    fn status(&self) -> EvidenceStatus {
        if self.access_lost && self.successful_pages == 0 {
            EvidenceStatus::AccessLost
        } else if self.provider_unknown && self.successful_pages == 0 {
            EvidenceStatus::ProviderUnknown
        } else if self.partial || self.completed_operations < EXPECTED_OPERATION_COUNT {
            EvidenceStatus::Partial
        } else {
            EvidenceStatus::Complete
        }
    }

    fn state(&self, status: EvidenceStatus) -> ObservationState {
        match status {
            EvidenceStatus::AccessLost => ObservationState::AccessLost,
            EvidenceStatus::ProviderUnknown => ObservationState::ProviderUnknown,
            EvidenceStatus::Partial => ObservationState::Partial,
            EvidenceStatus::Stale => ObservationState::Stale,
            EvidenceStatus::Complete => {
                if self
                    .issues
                    .iter()
                    .any(|issue| !matches!(issue.state, IssueState::Closed))
                {
                    ObservationState::Alerting
                } else if self
                    .entities
                    .iter()
                    .any(|entity| matches!(entity.state, ObservationState::NoTelemetry))
                {
                    ObservationState::NoTelemetry
                } else if !self.issues.is_empty()
                    && self
                        .issues
                        .iter()
                        .all(|issue| matches!(issue.state, IssueState::Closed))
                {
                    ObservationState::Closed
                } else if self
                    .entities
                    .iter()
                    .any(|entity| matches!(entity.state, ObservationState::Alerting))
                {
                    ObservationState::Alerting
                } else if self
                    .entities
                    .iter()
                    .any(|entity| matches!(entity.state, ObservationState::Degraded))
                {
                    ObservationState::Degraded
                } else if self
                    .entities
                    .iter()
                    .any(|entity| matches!(entity.state, ObservationState::Reporting))
                {
                    ObservationState::Reporting
                } else if self.entities.is_empty()
                    && self.issues.is_empty()
                    && self.incidents.is_empty()
                {
                    ObservationState::ProviderUnknown
                } else {
                    ObservationState::Healthy
                }
            }
        }
    }

    fn finish(
        self,
        proposal: &ObservabilityResultProposal,
        scope: &ObservabilityScope,
        provenance: TransportProvenance,
        status: EvidenceStatus,
        state: ObservationState,
    ) -> Result<ObservabilityEvidence, ModelError> {
        let pages = self.pages;
        let mut evidence = ObservabilityEvidence {
            proposal_digest: proposal.proposal_digest.clone(),
            status,
            state,
            account_digest: scope.account().digest(),
            scope_digest: scope.digest().clone(),
            entity_digest: scope.entity().digest().clone(),
            workload_digest: scope.workload().digest().clone(),
            policy_digest: scope.policy().digest().clone(),
            condition_digest: scope.condition().digest().clone(),
            mission_digest: scope.mission().digest.clone(),
            project_digest: scope.project().digest.clone(),
            work_product_digest: scope.work_product().digest.clone(),
            consent_digest: scope.consent().digest.clone(),
            permission_digest: scope.permissions().digest.clone(),
            query_digest: scope.query_policy().digest.clone(),
            time_window_digest: scope.time_window().digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            page_evidence: self.page_evidence,
            entities: self.entities,
            policies: self.policies,
            conditions: self.conditions,
            issues: self.issues,
            incidents: self.incidents,
            retries: self.retries,
            completeness: Completeness {
                expected_operations: EXPECTED_OPERATION_COUNT,
                completed_operations: self.completed_operations,
                pages,
                max_pages_per_operation: scope.query_policy().max_pages,
                truncated: self.truncated,
                duplicate_detected: self.duplicate_detected,
            },
            provenance,
            authority: AuthorityBoundary::layer1(),
            evidence_digest: Digest::from_text("pending-newrelic-evidence"),
        };
        evidence.evidence_digest = evidence.compute_digest()?;
        Ok(evidence)
    }
}

fn entity_state(entity: &EntityRecord) -> ObservationState {
    match entity.reporting {
        Some(false) => ObservationState::NoTelemetry,
        Some(true) => match entity.alert_severity {
            Some(Severity::High | Severity::Critical) => ObservationState::Alerting,
            Some(Severity::Low | Severity::Medium) => ObservationState::Degraded,
            None => ObservationState::Reporting,
        },
        None => ObservationState::ProviderUnknown,
    }
}
