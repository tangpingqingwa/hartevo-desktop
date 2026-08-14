use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PROVIDER_ID, SCHEMA_VERSION, SERVICE_ID, SERVICE_VERSION,
    model::{
        AccountId, Digest, ModelBinding, ModelError, OutputEvidence, PredictionId,
        PredictionStatus, ProviderErrorEvidence, ProviderPredictionStatus, RedactionState,
        ReplicateDigestSet, ReplicatePredictionRecord, ReplicateRegistration, ReplicateScope,
        Revision, RuntimeMetrics, SecretReference,
    },
    provider::{
        ProviderListObservation, ProviderObservation, ReplicateProvider, ReplicateProviderError,
        ReplicateTransport, RetryPolicy,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("the Replicate registration is revoked")]
    RegistrationRevoked,
    #[error("the Replicate API-token SecretReference is revoked")]
    SecretRevoked,
    #[error("the Replicate service scope is invalid")]
    ScopeMismatch,
    #[error("the proposal digest or evidence fence is invalid")]
    InvalidProposal,
    #[error("the provider operation failed")]
    Provider(ReplicateProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicateServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub service_version: crate::model::PluginVersion,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl ReplicateServiceDefinition {
    pub fn new(contract_digest: Digest) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            service_version: SERVICE_VERSION,
            contract_digest,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicatePredictionEvidence {
    pub account_id: AccountId,
    pub prediction_id: PredictionId,
    pub model: ModelBinding,
    pub provider_status: Option<ProviderPredictionStatus>,
    pub status: PredictionStatus,
    pub metrics: Option<RuntimeMetrics>,
    pub output: OutputEvidence,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub digests: ReplicateDigestSet,
    pub provider_provenance: crate::provider::ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub response_digest: Digest,
    pub retries: Vec<crate::model::RetryEvidence>,
    pub errors: Vec<ProviderErrorEvidence>,
    pub redaction: RedactionState,
    pub partial: bool,
    pub evidence_digest: Digest,
}

impl ReplicatePredictionEvidence {
    pub fn from_observation(observation: ProviderObservation) -> Self {
        let ProviderObservation {
            record,
            provenance,
            connected,
            native,
            digests,
            retries,
            ..
        } = observation;
        let status = record.status();
        let provider_status = record.provider_status;
        let metrics = record.metrics.clone();
        let response_digest = record.response_digest.clone();
        let partial = record.partial;
        let evidence_digest = evidence_digest(
            &record.account_id,
            &record.prediction_id,
            &record.model,
            Some(provider_status),
            status,
            Some(&metrics),
            &record.output,
            &digests,
            provenance,
            connected,
            native,
            &response_digest,
            &retries,
            &[],
            RedactionState::None,
            partial,
        );
        Self {
            account_id: record.account_id,
            prediction_id: record.prediction_id,
            model: record.model,
            provider_status: Some(provider_status),
            status,
            metrics: Some(metrics),
            output: record.output,
            scope_digest: digests.scope_digest.clone(),
            revision_digest: digests.revision_digest.clone(),
            permission_digest: digests.permission_digest.clone(),
            digests,
            provider_provenance: provenance,
            connected,
            native,
            response_digest,
            retries,
            errors: Vec::new(),
            redaction: RedactionState::None,
            partial,
            evidence_digest,
        }
    }

    pub fn provider_unknown(
        scope: &ReplicateScope,
        digests: ReplicateDigestSet,
        provenance: crate::provider::ProviderProvenance,
        error: ProviderErrorEvidence,
        retries: Vec<crate::model::RetryEvidence>,
    ) -> Self {
        let account_id = scope.account_id().clone();
        let prediction_id = scope.prediction().prediction_id().clone();
        let model = scope.prediction().model().clone();
        let output = OutputEvidence::empty(false);
        let response_digest = error.message_digest.clone();
        let errors = vec![error];
        let evidence_digest = evidence_digest(
            &account_id,
            &prediction_id,
            &model,
            None,
            PredictionStatus::ProviderUnknown,
            None,
            &output,
            &digests,
            provenance,
            false,
            false,
            &response_digest,
            &retries,
            &errors,
            RedactionState::Redacted,
            true,
        );
        Self {
            account_id,
            prediction_id,
            model,
            provider_status: None,
            status: PredictionStatus::ProviderUnknown,
            metrics: None,
            output,
            scope_digest: digests.scope_digest.clone(),
            revision_digest: digests.revision_digest.clone(),
            permission_digest: digests.permission_digest.clone(),
            digests,
            provider_provenance: provenance,
            connected: false,
            native: false,
            response_digest,
            retries,
            errors,
            redaction: RedactionState::Redacted,
            partial: true,
            evidence_digest,
        }
    }

    pub fn verify_digest(&self) -> bool {
        evidence_digest(
            &self.account_id,
            &self.prediction_id,
            &self.model,
            self.provider_status,
            self.status,
            self.metrics.as_ref(),
            &self.output,
            &self.digests,
            self.provider_provenance,
            self.connected,
            self.native,
            &self.response_digest,
            &self.retries,
            &self.errors,
            self.redaction,
            self.partial,
        ) == self.evidence_digest
            && !self.connected
            && !self.native
    }

    pub fn is_non_adoptable(&self) -> bool {
        self.status != PredictionStatus::Succeeded
            || self.output.data_removed
            || self.output.url_expired
            || self.partial
            || !self.errors.is_empty()
            || self.redaction != RedactionState::None
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicatePredictionResultProposal {
    pub service_id: String,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub evidence: ReplicatePredictionEvidence,
    pub proposal_digest: Digest,
}

impl ReplicatePredictionResultProposal {
    fn new(registration: &ReplicateRegistration, evidence: ReplicatePredictionEvidence) -> Self {
        let proposal_digest = Digest::from_fields(
            "replicate-prediction-result-proposal/v1",
            &[
                SERVICE_ID.to_owned(),
                registration.registration_digest().as_str().to_owned(),
                registration.registration_revision().get().to_string(),
                registration.scope().scope_digest().as_str().to_owned(),
                evidence.evidence_digest.as_str().to_owned(),
            ],
        );
        Self {
            service_id: SERVICE_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            registration_revision: registration.registration_revision(),
            scope_digest: registration.scope().scope_digest().clone(),
            evidence,
            proposal_digest,
        }
    }

    pub fn status(&self) -> PredictionStatus {
        self.evidence.status
    }

    pub fn verify_digest(&self) -> bool {
        self.evidence.verify_digest()
            && Digest::from_fields(
                "replicate-prediction-result-proposal/v1",
                &[
                    SERVICE_ID.to_owned(),
                    self.registration_digest.as_str().to_owned(),
                    self.registration_revision.get().to_string(),
                    self.scope_digest.as_str().to_owned(),
                    self.evidence.evidence_digest.as_str().to_owned(),
                ],
            ) == self.proposal_digest
    }

    pub fn is_non_adoptable(&self) -> bool {
        self.evidence.is_non_adoptable()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicatePredictionListProposal {
    pub service_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub records: Vec<ReplicatePredictionRecord>,
    pub pages_observed: u8,
    pub partial: bool,
    pub page_token_digests: Vec<Digest>,
    pub retries: Vec<crate::model::RetryEvidence>,
    pub provider_provenance: crate::provider::ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub proposal_digest: Digest,
}

impl ReplicatePredictionListProposal {
    pub fn verify_digest(&self) -> bool {
        list_proposal_digest(
            &self.registration_digest,
            &self.scope_digest,
            &self.records,
            self.pages_observed,
            self.partial,
            &self.page_token_digests,
            &self.retries,
        ) == self.proposal_digest
            && !self.connected
            && !self.native
    }
}

pub struct ReplicatePredictionResultService<T: ReplicateTransport> {
    scope: ReplicateScope,
    registration: ReplicateRegistration,
    provider: ReplicateProvider<T>,
    definition: ReplicateServiceDefinition,
}

impl<T: ReplicateTransport> fmt::Debug for ReplicatePredictionResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicatePredictionResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: ReplicateTransport> ReplicatePredictionResultService<T> {
    pub fn new(
        scope: ReplicateScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ServiceError> {
        Self::with_retry_policy(scope, secret_reference, transport, RetryPolicy::default())
    }

    pub fn with_retry_policy(
        scope: ReplicateScope,
        secret_reference: SecretReference,
        transport: T,
        retry_policy: RetryPolicy,
    ) -> Result<Self, ServiceError> {
        if secret_reference.is_revoked() || secret_reference.scope_digest() != scope.scope_digest()
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let implementation_digest =
            Digest::from_text("replicate-prediction-result-implementation/v1");
        let registration = ReplicateRegistration::register(
            scope.clone(),
            &secret_reference,
            implementation_digest,
        )?;
        let definition = ReplicateServiceDefinition::new(crate::contract_digest());
        let provider = ReplicateProvider::with_retry_policy(
            registration.clone(),
            secret_reference,
            transport,
            retry_policy,
        )
        .map_err(ServiceError::Model)?;
        Ok(Self {
            scope,
            registration,
            provider,
            definition,
        })
    }

    pub fn scope(&self) -> &ReplicateScope {
        &self.scope
    }

    pub fn registration(&self) -> &ReplicateRegistration {
        &self.registration
    }

    pub fn definition(&self) -> &ReplicateServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &ReplicateProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut ReplicateProvider<T> {
        &mut self.provider
    }

    pub fn revoke(&self) -> Result<crate::model::RevocationReceipt, ServiceError> {
        self.registration.revoke().map_err(ServiceError::Model)
    }

    pub fn get_prediction(&mut self) -> Result<ReplicatePredictionResultProposal, ServiceError> {
        self.propose_prediction()
    }

    pub fn read_prediction(&mut self) -> Result<ReplicatePredictionResultProposal, ServiceError> {
        self.propose_prediction()
    }

    pub fn propose_prediction(
        &mut self,
    ) -> Result<ReplicatePredictionResultProposal, ServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        if self.provider.secret_reference().is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        let evidence = match self.provider.read_prediction() {
            Ok(observation) => ReplicatePredictionEvidence::from_observation(observation),
            Err(error) => ReplicatePredictionEvidence::provider_unknown(
                &self.scope,
                self.registration.provider_definition().digests().clone(),
                self.provider.provenance(),
                error.evidence,
                error.retries,
            ),
        };
        Ok(ReplicatePredictionResultProposal::new(
            &self.registration,
            evidence,
        ))
    }

    pub fn record_prediction(
        &mut self,
        record: ReplicatePredictionRecord,
    ) -> Result<ReplicatePredictionResultProposal, ServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        let observation = self
            .provider
            .record_prediction(record)
            .map_err(ServiceError::Provider)?;
        Ok(ReplicatePredictionResultProposal::new(
            &self.registration,
            ReplicatePredictionEvidence::from_observation(observation),
        ))
    }

    pub fn list_predictions(
        &mut self,
        page_size: u16,
    ) -> Result<ReplicatePredictionListProposal, ServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        let observation = match self.provider.list_predictions(page_size) {
            Ok(observation) => observation,
            Err(error) => {
                let retries = error.retries;
                return Ok(ReplicatePredictionListProposal {
                    service_id: SERVICE_ID.to_owned(),
                    registration_digest: self.registration.registration_digest().clone(),
                    scope_digest: self.scope.scope_digest().clone(),
                    records: Vec::new(),
                    pages_observed: 0,
                    partial: true,
                    page_token_digests: Vec::new(),
                    retries: retries.clone(),
                    provider_provenance: self.provider.provenance(),
                    connected: false,
                    native: false,
                    proposal_digest: list_proposal_digest(
                        self.registration.registration_digest(),
                        self.scope.scope_digest(),
                        &[],
                        0,
                        true,
                        &[],
                        &retries,
                    ),
                });
            }
        };
        Ok(list_proposal(&self.registration, observation))
    }
}

fn list_proposal(
    registration: &ReplicateRegistration,
    observation: ProviderListObservation,
) -> ReplicatePredictionListProposal {
    let proposal_digest = list_proposal_digest(
        registration.registration_digest(),
        registration.scope().scope_digest(),
        &observation.records,
        observation.pages_observed,
        observation.partial,
        &observation.page_token_digests,
        &observation.retries,
    );
    ReplicatePredictionListProposal {
        service_id: SERVICE_ID.to_owned(),
        registration_digest: registration.registration_digest().clone(),
        scope_digest: registration.scope().scope_digest().clone(),
        records: observation.records,
        pages_observed: observation.pages_observed,
        partial: observation.partial,
        page_token_digests: observation.page_token_digests,
        retries: observation.retries,
        provider_provenance: observation.provenance,
        connected: observation.connected,
        native: observation.native,
        proposal_digest,
    }
}

fn list_proposal_digest(
    registration_digest: &Digest,
    scope_digest: &Digest,
    records: &[ReplicatePredictionRecord],
    pages_observed: u8,
    partial: bool,
    page_token_digests: &[Digest],
    retries: &[crate::model::RetryEvidence],
) -> Digest {
    Digest::from_fields(
        "replicate-prediction-list-proposal/v1",
        &[
            SERVICE_ID.to_owned(),
            registration_digest.as_str().to_owned(),
            scope_digest.as_str().to_owned(),
            records
                .iter()
                .map(|record| record.response_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            pages_observed.to_string(),
            partial.to_string(),
            page_token_digests
                .iter()
                .map(Digest::as_str)
                .collect::<Vec<_>>()
                .join(","),
            retries
                .iter()
                .map(|retry| retry.error_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn evidence_digest(
    account_id: &AccountId,
    prediction_id: &PredictionId,
    model: &ModelBinding,
    provider_status: Option<ProviderPredictionStatus>,
    status: PredictionStatus,
    metrics: Option<&RuntimeMetrics>,
    output: &OutputEvidence,
    digests: &ReplicateDigestSet,
    provenance: crate::provider::ProviderProvenance,
    connected: bool,
    native: bool,
    response_digest: &Digest,
    retries: &[crate::model::RetryEvidence],
    errors: &[ProviderErrorEvidence],
    redaction: RedactionState,
    partial: bool,
) -> Digest {
    Digest::from_fields(
        "replicate-prediction-evidence/v1",
        &[
            account_id.as_str().to_owned(),
            prediction_id.as_str().to_owned(),
            model.binding_digest().as_str().to_owned(),
            provider_status.map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
            format!("{status:?}"),
            metrics.map_or_else(
                || "none".to_owned(),
                |value| value.metric_digest.as_str().to_owned(),
            ),
            output.output_digest.as_str().to_owned(),
            digests.provider_digest.as_str().to_owned(),
            digests.api_digest.as_str().to_owned(),
            digests.model_digest.as_str().to_owned(),
            digests.version_or_deployment_digest.as_str().to_owned(),
            digests.permission_digest.as_str().to_owned(),
            digests.scope_digest.as_str().to_owned(),
            digests.revision_digest.as_str().to_owned(),
            format!("{provenance:?}"),
            connected.to_string(),
            native.to_string(),
            response_digest.as_str().to_owned(),
            retries
                .iter()
                .map(|retry| retry.error_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            errors
                .iter()
                .map(|error| error.message_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            format!("{redaction:?}"),
            partial.to_string(),
        ],
    )
}
