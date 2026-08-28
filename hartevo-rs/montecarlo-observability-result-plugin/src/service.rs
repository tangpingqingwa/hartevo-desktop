use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
    error::ModelError,
    model::{
        ALL_READ_OPERATIONS, AuthorityBoundary, Digest, EvidenceStatus, FreshnessState,
        IncidentState, MonitorState, MonteCarloObservabilityScope, ObservationState, ReadOperation,
        SecretReference, TransportProvenance, VerificationState,
    },
    provider::{
        MonteCarloProvider, MonteCarloReadRequest, MonteCarloTransport, ProviderError,
        ProviderResponse, RetryEvidence, TransportFailure,
    },
};

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
    pub organization_digest: Digest,
    pub project_digest: Digest,
    pub warehouse_digest: Digest,
    pub table_digest: Digest,
    pub incident_digest: Digest,
    pub lineage_digest: Digest,
    pub monitor_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub time_window_digest: Digest,
    pub scope_digest: Digest,
    pub mission_digest: Digest,
    pub project_binding_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub idempotency_digest: Digest,
    pub revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl Registration {
    pub fn new(
        scope: &MonteCarloObservabilityScope,
        provider_digest: &Digest,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        Self::new_at_revision(scope, provider_digest, secret, 1)
    }

    pub fn new_at_revision(
        scope: &MonteCarloObservabilityScope,
        provider_digest: &Digest,
        secret: &SecretReference,
        revision: u64,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        provider_digest.validate()?;
        secret.validate_for(scope)?;
        if revision == 0 {
            return Err(ModelError::InvalidBound {
                field: "registration revision",
            });
        }
        let mut registration = Self {
            version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: provider_digest.clone(),
            api_digest: Digest::from_text(API_REVISION),
            organization_digest: scope.organization().digest(),
            project_digest: scope.monte_carlo_project().digest().clone(),
            warehouse_digest: scope.warehouse().digest().clone(),
            table_digest: scope.table().digest().clone(),
            incident_digest: scope.incident().digest().clone(),
            lineage_digest: scope.lineage().digest().clone(),
            monitor_digest: scope.monitor().digest().clone(),
            permission_digest: scope.permissions().digest.clone(),
            query_digest: scope.query_policy().digest.clone(),
            time_window_digest: scope.time_window().digest.clone(),
            scope_digest: scope.digest().clone(),
            mission_digest: scope.mission().digest.clone(),
            project_binding_digest: scope.project_binding().digest.clone(),
            work_product_digest: scope.work_product().digest.clone(),
            consent_digest: scope.consent().digest.clone(),
            secret_reference_digest: secret.secret_digest().clone(),
            idempotency_digest: Digest::from_parts(
                "montecarlo-registration-idempotency/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("provider", provider_digest.as_str().to_owned()),
                    ("secret", secret.secret_digest().as_str().to_owned()),
                ],
            ),
            revision,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("pending-montecarlo-registration"),
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "montecarlo-registration/v1",
            &[
                ("version", self.version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("organization", self.organization_digest.as_str().to_owned()),
                ("project", self.project_digest.as_str().to_owned()),
                ("warehouse", self.warehouse_digest.as_str().to_owned()),
                ("table", self.table_digest.as_str().to_owned()),
                ("incident", self.incident_digest.as_str().to_owned()),
                ("lineage", self.lineage_digest.as_str().to_owned()),
                ("monitor", self.monitor_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("window", self.time_window_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("mission", self.mission_digest.as_str().to_owned()),
                (
                    "project_binding",
                    self.project_binding_digest.as_str().to_owned(),
                ),
                ("work_product", self.work_product_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("idempotency", self.idempotency_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
                ("state", format!("{:?}", self.state)),
                ("reversible", self.reversible.to_string()),
                ("revocable", self.revocable.to_string()),
            ],
        )
    }

    pub fn verify(
        &self,
        scope: &MonteCarloObservabilityScope,
        provider_digest: &Digest,
        secret: &SecretReference,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        secret.validate_for(scope)?;
        for digest in [
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.organization_digest,
            &self.project_digest,
            &self.warehouse_digest,
            &self.table_digest,
            &self.incident_digest,
            &self.lineage_digest,
            &self.monitor_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.time_window_digest,
            &self.scope_digest,
            &self.mission_digest,
            &self.project_binding_digest,
            &self.work_product_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            &self.idempotency_digest,
            &self.registration_digest,
        ] {
            digest.validate()?;
        }
        if self.version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_digest != contract_digest()
            || self.provider_digest != *provider_digest
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.organization_digest != scope.organization().digest()
            || self.project_digest != *scope.monte_carlo_project().digest()
            || self.warehouse_digest != *scope.warehouse().digest()
            || self.table_digest != *scope.table().digest()
            || self.incident_digest != *scope.incident().digest()
            || self.lineage_digest != *scope.lineage().digest()
            || self.monitor_digest != *scope.monitor().digest()
            || self.permission_digest != scope.permissions().digest
            || self.query_digest != scope.query_policy().digest
            || self.time_window_digest != scope.time_window().digest
            || self.scope_digest != *scope.digest()
            || self.mission_digest != scope.mission().digest
            || self.project_binding_digest != scope.project_binding().digest
            || self.work_product_digest != scope.work_product().digest
            || self.consent_digest != scope.consent().digest
            || self.secret_reference_digest != *secret.secret_digest()
            || self.idempotency_digest
                != Digest::from_parts(
                    "montecarlo-registration-idempotency/v1",
                    &[
                        ("scope", scope.digest().as_str().to_owned()),
                        ("provider", provider_digest.as_str().to_owned()),
                        ("secret", secret.secret_digest().as_str().to_owned()),
                    ],
                )
            || self.revision == 0
            || !self.reversible
            || !self.revocable
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
    pub requests: Vec<MonteCarloReadRequest>,
    pub plan_digest: Digest,
    pub bounded: bool,
    pub arbitrary_query: bool,
    pub external_writes: bool,
    pub warehouse_queries: bool,
    pub monitor_mutations: bool,
}

impl ReadPlan {
    fn new(
        requests: Vec<MonteCarloReadRequest>,
        scope: &MonteCarloObservabilityScope,
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
            warehouse_queries: false,
            monitor_mutations: false,
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

    pub fn verify(&self, scope: &MonteCarloObservabilityScope) -> Result<(), ModelError> {
        if !self.bounded
            || self.arbitrary_query
            || self.external_writes
            || self.warehouse_queries
            || self.monitor_mutations
        {
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
    pub idempotency_digest: Digest,
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
            &self.idempotency_digest,
            &self.plan,
            self.native_execution,
            &self.authority,
        ))
    }

    pub fn verify(&self, scope: &MonteCarloObservabilityScope) -> Result<(), ModelError> {
        self.plan.verify(scope)?;
        for digest in [
            &self.contract_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.time_window_digest,
            &self.idempotency_digest,
            &self.proposal_digest,
        ] {
            digest.validate()?;
        }
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.registration_revision == 0
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
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub item_count: u16,
    pub response_bytes: usize,
    pub retry_count: u8,
    pub redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub operation: ReadOperation,
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub retries: Vec<RetryEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LineageSummary {
    pub lineage_digest: Digest,
    pub table_digest: Digest,
    pub upstream_count: u16,
    pub downstream_count: u16,
    pub graph_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservabilityEvidence {
    pub status: EvidenceStatus,
    pub state: ObservationState,
    pub provenance: TransportProvenance,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub time_window_digest: Digest,
    pub mission_digest: Digest,
    pub project_binding_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub idempotency_digest: Digest,
    pub incidents: Vec<Digest>,
    pub incident_states: Vec<IncidentState>,
    pub freshness: Vec<Digest>,
    pub freshness_states: Vec<FreshnessState>,
    pub lineage: Vec<Digest>,
    pub lineage_summaries: Vec<LineageSummary>,
    pub monitors: Vec<Digest>,
    pub monitor_states: Vec<MonitorState>,
    pub page_evidence: Vec<PageEvidence>,
    pub failures: Vec<FailureEvidence>,
    pub bounded: bool,
    pub redacted: bool,
    pub raw_rows: bool,
    pub raw_lineage: bool,
    pub monitor_mutation: bool,
    pub authority: AuthorityBoundary,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    status: EvidenceStatus,
    state: ObservationState,
    provenance: TransportProvenance,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    permission_digest: &'a Digest,
    query_digest: &'a Digest,
    time_window_digest: &'a Digest,
    mission_digest: &'a Digest,
    project_binding_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    idempotency_digest: &'a Digest,
    incidents: &'a [Digest],
    incident_states: &'a [IncidentState],
    freshness: &'a [Digest],
    freshness_states: &'a [FreshnessState],
    lineage: &'a [Digest],
    lineage_summaries: &'a [LineageSummary],
    monitors: &'a [Digest],
    monitor_states: &'a [MonitorState],
    page_evidence: &'a [PageEvidence],
    failures: &'a [FailureEvidence],
    bounded: bool,
    redacted: bool,
    raw_rows: bool,
    raw_lineage: bool,
    monitor_mutation: bool,
    authority: &'a AuthorityBoundary,
}

impl ObservabilityEvidence {
    fn digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&EvidenceDigestMaterial {
            status: self.status,
            state: self.state,
            provenance: self.provenance,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            permission_digest: &self.permission_digest,
            query_digest: &self.query_digest,
            time_window_digest: &self.time_window_digest,
            mission_digest: &self.mission_digest,
            project_binding_digest: &self.project_binding_digest,
            work_product_digest: &self.work_product_digest,
            consent_digest: &self.consent_digest,
            idempotency_digest: &self.idempotency_digest,
            incidents: &self.incidents,
            incident_states: &self.incident_states,
            freshness: &self.freshness,
            freshness_states: &self.freshness_states,
            lineage: &self.lineage,
            lineage_summaries: &self.lineage_summaries,
            monitors: &self.monitors,
            monitor_states: &self.monitor_states,
            page_evidence: &self.page_evidence,
            failures: &self.failures,
            bounded: self.bounded,
            redacted: self.redacted,
            raw_rows: self.raw_rows,
            raw_lineage: self.raw_lineage,
            monitor_mutation: self.monitor_mutation,
            authority: &self.authority,
        })
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        for digest in [
            &self.scope_digest,
            &self.registration_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.time_window_digest,
            &self.mission_digest,
            &self.project_binding_digest,
            &self.work_product_digest,
            &self.consent_digest,
            &self.idempotency_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if !self.bounded
            || !self.redacted
            || self.raw_rows
            || self.raw_lineage
            || self.monitor_mutation
            || self.authority != AuthorityBoundary::layer1()
            || self.incidents.len() != self.incident_states.len()
            || self.freshness.len() != self.freshness_states.len()
            || self.lineage.len() != self.lineage_summaries.len()
            || self.monitors.len() != self.monitor_states.len()
            || self.status == EvidenceStatus::Tampered
            || self.digest()? != self.evidence_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn is_adoptable(&self) -> bool {
        self.status.adoptable()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservabilityResult {
    pub proposal: ObservabilityResultProposal,
    pub evidence: ObservabilityEvidence,
}

impl ObservabilityResult {
    pub fn verify(&self, scope: &MonteCarloObservabilityScope) -> Result<(), ModelError> {
        self.proposal.verify(scope)?;
        self.evidence.verify()?;
        if self.evidence.scope_digest != *scope.digest()
            || self.evidence.permission_digest != scope.permissions().digest
            || self.evidence.query_digest != scope.query_policy().digest
            || self.evidence.time_window_digest != scope.time_window().digest
            || self.evidence.mission_digest != scope.mission().digest
            || self.evidence.project_binding_digest != scope.project_binding().digest
            || self.evidence.work_product_digest != scope.work_product().digest
            || self.evidence.consent_digest != scope.consent().digest
            || self.evidence.registration_digest != self.proposal.registration_digest
            || self.evidence.idempotency_digest != self.proposal.idempotency_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        self.proposal.verify_digest()?;
        self.evidence.verify()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration or scope drifted")]
    RegistrationDrift,
    #[error("evidence is tampered")]
    TamperedEvidence,
    #[error("duplicate idempotent receipt")]
    DuplicateReceipt,
    #[error("idempotency key was replayed with different evidence")]
    ReplayConflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Layer1Capabilities {
    pub service_id: String,
    pub provider_id: String,
    pub api_revision: String,
    pub operations: Vec<ReadOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub raw_rows: bool,
    pub raw_lineage: bool,
    pub warehouse_queries: bool,
    pub monitor_mutations: bool,
    pub durable_provider_receipt: bool,
    pub outcome_adoption: bool,
}

impl Layer1Capabilities {
    fn new(provenance: TransportProvenance) -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: ALL_READ_OPERATIONS.to_vec(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: provenance.connected(),
            native: provenance.native(),
            raw_rows: false,
            raw_lineage: false,
            warehouse_queries: false,
            monitor_mutations: false,
            durable_provider_receipt: false,
            outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MonteCarloObservabilityReceipt {
    pub service_id: String,
    pub provider_id: String,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub idempotency_digest: Digest,
    pub status: EvidenceStatus,
    pub state: ObservationState,
    pub provenance: TransportProvenance,
    pub page_digests: Vec<Digest>,
    pub evidence_digest: Digest,
    pub response_digest: Digest,
    pub observed_at_millis: i64,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub raw_rows: bool,
    pub raw_lineage: bool,
    pub receipt_digest: Digest,
}

impl MonteCarloObservabilityReceipt {
    fn from_result(
        result: &ObservabilityResult,
        registration: &Registration,
        provenance: TransportProvenance,
        observed_at_millis: i64,
    ) -> Result<Self, ModelError> {
        let page_digests = result
            .evidence
            .page_evidence
            .iter()
            .map(|page| page.response_digest.clone())
            .collect::<Vec<_>>();
        let response_digest = crate::model::digest_serializable(&page_digests)?;
        let mut receipt = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.revision,
            idempotency_digest: result.evidence.idempotency_digest.clone(),
            status: result.evidence.status,
            state: result.evidence.state,
            provenance,
            page_digests,
            evidence_digest: result.evidence.evidence_digest.clone(),
            response_digest,
            observed_at_millis,
            redacted: true,
            connected: false,
            native: false,
            raw_rows: false,
            raw_lineage: false,
            receipt_digest: Digest::from_text("pending-montecarlo-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        Ok(receipt)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&ReceiptDigestMaterial {
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            idempotency_digest: &self.idempotency_digest,
            status: self.status,
            state: self.state,
            provenance: self.provenance,
            page_digests: &self.page_digests,
            evidence_digest: &self.evidence_digest,
            response_digest: &self.response_digest,
            observed_at_millis: self.observed_at_millis,
            redacted: self.redacted,
            connected: self.connected,
            native: self.native,
            raw_rows: self.raw_rows,
            raw_lineage: self.raw_lineage,
        })
    }

    pub fn verify(&self, result: &ObservabilityResult) -> Result<(), ModelError> {
        let expected_pages = result
            .evidence
            .page_evidence
            .iter()
            .map(|page| page.response_digest.clone())
            .collect::<Vec<_>>();
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.registration_digest != result.proposal.registration_digest
            || self.idempotency_digest != result.proposal.idempotency_digest
            || self.status != result.evidence.status
            || self.state != result.evidence.state
            || self.page_digests != expected_pages
            || self.evidence_digest != result.evidence.evidence_digest
            || self.response_digest != crate::model::digest_serializable(&expected_pages)?
            || !self.redacted
            || self.connected
            || self.native
            || self.raw_rows
            || self.raw_lineage
            || self.compute_digest()? != self.receipt_digest
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDigestMaterial<'a> {
    service_id: &'a str,
    provider_id: &'a str,
    registration_digest: &'a Digest,
    registration_revision: u64,
    idempotency_digest: &'a Digest,
    status: EvidenceStatus,
    state: ObservationState,
    provenance: TransportProvenance,
    page_digests: &'a [Digest],
    evidence_digest: &'a Digest,
    response_digest: &'a Digest,
    observed_at_millis: i64,
    redacted: bool,
    connected: bool,
    native: bool,
    raw_rows: bool,
    raw_lineage: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerification {
    pub state: VerificationState,
    pub verified: bool,
    pub receipt_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub idempotency_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adoptable: bool,
    pub verification_digest: Digest,
}

impl EvidenceVerification {
    fn new(receipt: &MonteCarloObservabilityReceipt, evidence: &ObservabilityEvidence) -> Self {
        let verification_digest = Digest::from_parts(
            "montecarlo-evidence-verification/v1",
            &[
                ("receipt", receipt.receipt_digest.as_str().to_owned()),
                ("evidence", evidence.evidence_digest.as_str().to_owned()),
                (
                    "registration",
                    receipt.registration_digest.as_str().to_owned(),
                ),
                (
                    "idempotency",
                    receipt.idempotency_digest.as_str().to_owned(),
                ),
                ("state", "verified".to_owned()),
            ],
        );
        Self {
            state: VerificationState::Verified,
            verified: true,
            receipt_digest: receipt.receipt_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            idempotency_digest: receipt.idempotency_digest.clone(),
            connected: false,
            native: false,
            adoptable: evidence.is_adoptable(),
            verification_digest,
        }
    }
}

pub struct MonteCarloObservabilityResultService<T>
where
    T: MonteCarloTransport,
{
    provider: MonteCarloProvider<T>,
    scope: MonteCarloObservabilityScope,
    secret: SecretReference,
    registration: Registration,
    capabilities: Layer1Capabilities,
    recorded: BTreeMap<Digest, Digest>,
}

impl<T: MonteCarloTransport> fmt::Debug for MonteCarloObservabilityResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonteCarloObservabilityResultService")
            .field("provider", &self.provider)
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("registration", &self.registration)
            .field("capabilities", &self.capabilities)
            .field("recorded", &self.recorded)
            .finish()
    }
}

impl<T: MonteCarloTransport> MonteCarloObservabilityResultService<T> {
    pub fn new(
        scope: MonteCarloObservabilityScope,
        secret: SecretReference,
        provider: MonteCarloProvider<T>,
    ) -> Result<Self, ServiceError> {
        Self::new_at_revision(scope, secret, provider, 1)
    }

    pub fn from_provider(
        provider: MonteCarloProvider<T>,
        scope: MonteCarloObservabilityScope,
        secret: SecretReference,
    ) -> Result<Self, ServiceError> {
        Self::new(scope, secret, provider)
    }

    pub fn new_at_revision(
        scope: MonteCarloObservabilityScope,
        secret: SecretReference,
        provider: MonteCarloProvider<T>,
        revision: u64,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        secret.validate_for(&scope)?;
        provider.definition().validate()?;
        let registration =
            Registration::new_at_revision(&scope, provider.provider_digest(), &secret, revision)?;
        let capabilities = Layer1Capabilities::new(provider.provenance());
        Ok(Self {
            provider,
            scope,
            secret,
            registration,
            capabilities,
            recorded: BTreeMap::new(),
        })
    }

    pub fn provider(&self) -> &MonteCarloProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut MonteCarloProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &MonteCarloObservabilityScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    pub fn capabilities(&self) -> &Layer1Capabilities {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Layer1Capabilities {
        self.capabilities.clone()
    }

    pub fn reverse_registration(&mut self) -> Result<(), ServiceError> {
        self.registration.reverse()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), ServiceError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn revoke_registration(&mut self) -> Result<(), ServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), ServiceError> {
        self.registration
            .verify(&self.scope, self.provider.provider_digest(), &self.secret)
            .map_err(|_| ServiceError::RegistrationDrift)?;
        match self.registration.state {
            RegistrationState::Active => Ok(()),
            RegistrationState::Reversed => Err(ServiceError::RegistrationReversed),
            RegistrationState::Revoked => Err(ServiceError::RegistrationRevoked),
        }
    }

    pub fn propose(&self) -> Result<ObservabilityResultProposal, ServiceError> {
        self.ensure_active()?;
        let requests = ALL_READ_OPERATIONS
            .into_iter()
            .map(|operation| MonteCarloReadRequest::first(&self.scope, operation))
            .collect::<Result<Vec<_>, _>>()?;
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
            idempotency_digest: Digest::from_parts(
                "montecarlo-observation-idempotency/v1",
                &[
                    (
                        "registration",
                        self.registration.registration_digest.as_str().to_owned(),
                    ),
                    ("plan", plan.plan_digest.as_str().to_owned()),
                    ("revision", self.registration.revision.to_string()),
                ],
            ),
            plan,
            proposal_digest: Digest::from_text("pending-montecarlo-proposal"),
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
        for operation in ALL_READ_OPERATIONS {
            let mut request = MonteCarloReadRequest::first(&self.scope, operation)?;
            for page_number in 0..self.scope.query_policy().max_pages {
                match self.provider.read(&request, &self.scope) {
                    Ok(read) => {
                        accumulator.add_response(&read, page_number);
                        if let Some(cursor) = read.response.next_cursor().cloned() {
                            if page_number + 1 >= self.scope.query_policy().max_pages {
                                accumulator.truncated = true;
                                break;
                            }
                            request = request.with_cursor(&self.scope, cursor)?;
                        } else {
                            break;
                        }
                    }
                    Err(error) => {
                        accumulator.add_failure(operation, &error);
                        break;
                    }
                }
            }
        }
        let evidence = accumulator.finish(
            &self.scope,
            &self.registration,
            &proposal,
            self.provider.provenance(),
        )?;
        Ok(ObservabilityResult { proposal, evidence })
    }

    pub fn read_and_propose(&mut self) -> Result<ObservabilityResult, ServiceError> {
        self.observe()
    }

    pub fn record_observation_receipt(
        &mut self,
        result: &ObservabilityResult,
    ) -> Result<MonteCarloObservabilityReceipt, ServiceError> {
        self.verify_result(result)?;
        let key = result.proposal.idempotency_digest.clone();
        if let Some(previous) = self.recorded.get(&key) {
            if previous == &result.evidence.evidence_digest {
                return Err(ServiceError::DuplicateReceipt);
            }
            return Err(ServiceError::ReplayConflict);
        }
        let receipt = MonteCarloObservabilityReceipt::from_result(
            result,
            &self.registration,
            self.provider.provenance(),
            self.scope.time_window().end_millis,
        )?;
        self.recorded
            .insert(key, result.evidence.evidence_digest.clone());
        Ok(receipt)
    }

    pub fn verify_result(&self, result: &ObservabilityResult) -> Result<(), ServiceError> {
        self.ensure_active()?;
        result
            .verify(&self.scope)
            .map_err(|_| ServiceError::TamperedEvidence)?;
        if result.proposal.registration_digest != self.registration.registration_digest
            || result.proposal.registration_revision != self.registration.revision
            || result.proposal.provider_digest != *self.provider.provider_digest()
        {
            return Err(ServiceError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn verify_receipt(
        &self,
        receipt: &MonteCarloObservabilityReceipt,
        result: &ObservabilityResult,
    ) -> Result<EvidenceVerification, ServiceError> {
        self.verify_result(result)?;
        receipt
            .verify(result)
            .map_err(|_| ServiceError::TamperedEvidence)?;
        Ok(EvidenceVerification::new(receipt, &result.evidence))
    }

    pub fn verify(
        &self,
        receipt: &MonteCarloObservabilityReceipt,
        result: &ObservabilityResult,
    ) -> Result<EvidenceVerification, ServiceError> {
        self.verify_receipt(receipt, result)
    }
}

#[derive(Default)]
struct EvidenceAccumulator {
    incidents: Vec<crate::model::IncidentRecord>,
    freshness: Vec<crate::model::FreshnessRecord>,
    lineage: Vec<crate::model::LineageRecord>,
    monitors: Vec<crate::model::MonitorRecord>,
    page_evidence: Vec<PageEvidence>,
    failures: Vec<FailureEvidence>,
    retries: Vec<RetryEvidence>,
    successful_pages: usize,
    truncated: bool,
}

impl EvidenceAccumulator {
    fn add_response(&mut self, read: &crate::provider::ProviderRead, _page_number: u8) {
        self.successful_pages = self.successful_pages.saturating_add(1);
        self.retries.extend(read.retries.clone());
        let page = PageEvidence {
            operation: read.response.operation(),
            request_digest: read.request_digest.clone(),
            response_digest: read.response.response_digest().clone(),
            cursor_digest: read
                .response
                .next_cursor()
                .map(|cursor| cursor.digest().clone()),
            item_count: u16::try_from(read.response.item_count()).unwrap_or(u16::MAX),
            response_bytes: read.response.response_bytes(),
            retry_count: u8::try_from(read.retries.len()).unwrap_or(u8::MAX),
            redacted: read.response.redacted(),
        };
        self.page_evidence.push(page);
        match &read.response {
            ProviderResponse::Incidents(page) => self.incidents.extend(page.incidents.clone()),
            ProviderResponse::Freshness(page) => self.freshness.extend(page.freshness.clone()),
            ProviderResponse::Lineage(page) => self.lineage.extend(page.lineage.clone()),
            ProviderResponse::Monitors(page) => self.monitors.extend(page.monitors.clone()),
        }
    }

    fn add_failure(&mut self, operation: ReadOperation, error: &ProviderError) {
        let (failure, status_code, diagnostic_digest, retries) = match error {
            ProviderError::Transport { error, retries } => (
                error.failure,
                error.status_code,
                error.diagnostic_digest.clone(),
                retries.clone(),
            ),
            ProviderError::InvalidRequest(model_error) => (
                TransportFailure::Malformed,
                None,
                Digest::from_parts(
                    "montecarlo-invalid-request/v1",
                    &[("error", model_error.to_string())],
                ),
                Vec::new(),
            ),
            ProviderError::UnexpectedResponse => (
                TransportFailure::Malformed,
                None,
                Digest::from_text("montecarlo-unexpected-response"),
                Vec::new(),
            ),
        };
        self.retries.extend(retries.clone());
        self.failures.push(FailureEvidence {
            operation,
            failure,
            status_code,
            diagnostic_digest,
            retries,
        });
    }

    fn finish(
        self,
        scope: &MonteCarloObservabilityScope,
        registration: &Registration,
        proposal: &ObservabilityResultProposal,
        provenance: TransportProvenance,
    ) -> Result<ObservabilityEvidence, ModelError> {
        let status = self.status();
        let state = self.state(status);
        let incidents = self
            .incidents
            .iter()
            .map(crate::model::IncidentRecord::digest)
            .collect::<Vec<_>>();
        let incident_states = self
            .incidents
            .iter()
            .map(|record| record.state)
            .collect::<Vec<_>>();
        let freshness = self
            .freshness
            .iter()
            .map(crate::model::FreshnessRecord::digest)
            .collect::<Vec<_>>();
        let freshness_states = self
            .freshness
            .iter()
            .map(|record| record.state)
            .collect::<Vec<_>>();
        let lineage = self
            .lineage
            .iter()
            .map(crate::model::LineageRecord::digest)
            .collect::<Vec<_>>();
        let lineage_summaries = self
            .lineage
            .iter()
            .map(|record| crate::service::LineageSummary {
                lineage_digest: record.lineage_digest.clone(),
                table_digest: record.table_digest.clone(),
                upstream_count: record.upstream_count,
                downstream_count: record.downstream_count,
                graph_digest: record.graph_digest.clone(),
            })
            .collect::<Vec<_>>();
        let monitors = self
            .monitors
            .iter()
            .map(crate::model::MonitorRecord::digest)
            .collect::<Vec<_>>();
        let monitor_states = self
            .monitors
            .iter()
            .map(|record| record.state)
            .collect::<Vec<_>>();
        let mut evidence = ObservabilityEvidence {
            status,
            state,
            provenance,
            scope_digest: scope.digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            permission_digest: scope.permissions().digest.clone(),
            query_digest: scope.query_policy().digest.clone(),
            time_window_digest: scope.time_window().digest.clone(),
            mission_digest: scope.mission().digest.clone(),
            project_binding_digest: scope.project_binding().digest.clone(),
            work_product_digest: scope.work_product().digest.clone(),
            consent_digest: scope.consent().digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            incidents,
            incident_states,
            freshness,
            freshness_states,
            lineage,
            lineage_summaries,
            monitors,
            monitor_states,
            page_evidence: self.page_evidence,
            failures: self.failures,
            bounded: true,
            redacted: true,
            raw_rows: false,
            raw_lineage: false,
            monitor_mutation: false,
            authority: AuthorityBoundary::layer1(),
            evidence_digest: Digest::from_text("pending-montecarlo-evidence"),
        };
        evidence.evidence_digest = evidence.digest()?;
        Ok(evidence)
    }

    fn status(&self) -> EvidenceStatus {
        if self.truncated || (!self.failures.is_empty() && self.successful_pages > 0) {
            return EvidenceStatus::Partial;
        }
        if self.failures.is_empty() {
            return EvidenceStatus::Complete;
        }
        match self.failures[0].failure {
            TransportFailure::Unauthorized | TransportFailure::AccessDenied => {
                EvidenceStatus::Denied
            }
            TransportFailure::AccessLost => EvidenceStatus::AccessLost,
            TransportFailure::RateLimited => EvidenceStatus::RateLimited,
            TransportFailure::NotFound
            | TransportFailure::Server
            | TransportFailure::Timeout
            | TransportFailure::BlockedEnv
            | TransportFailure::Malformed => EvidenceStatus::ProviderUnknown,
        }
    }

    fn state(&self, status: EvidenceStatus) -> ObservationState {
        match status {
            EvidenceStatus::Complete => {
                if self
                    .incidents
                    .iter()
                    .any(|record| record.state == IncidentState::Open)
                {
                    ObservationState::Open
                } else if self
                    .incidents
                    .iter()
                    .any(|record| record.state == IncidentState::Resolved)
                {
                    ObservationState::Resolved
                } else {
                    ObservationState::Unknown
                }
            }
            EvidenceStatus::Partial => ObservationState::Partial,
            EvidenceStatus::AccessLost => ObservationState::AccessLost,
            EvidenceStatus::Denied => ObservationState::Denied,
            EvidenceStatus::RateLimited => ObservationState::RateLimited,
            EvidenceStatus::ProviderUnknown => ObservationState::ProviderUnknown,
            EvidenceStatus::Tampered => ObservationState::Tampered,
        }
    }
}
