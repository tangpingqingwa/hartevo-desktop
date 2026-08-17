//! Service lifecycle for the Azure Cosmos DB container-posture result.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ApiVersion, AzureCosmosContainerPosture, AzureCosmosEvidence, AzureCosmosScope, Digest,
    EvidenceState, MAX_RETRIES, ModelError, PartialReason, PermissionSnapshot, ProviderErrorCode,
    ProviderErrorSummary, SecretReference, ThroughputSummary, ThroughputTarget,
};
use crate::provider::{
    AzureCosmosGetRequest, AzureCosmosOperation, AzureCosmosProviderError,
    AzureCosmosResourceProjection, AzureCosmosResourceProvider, AzureCosmosResourceResponse,
    AzureCosmosTransport,
};
use crate::{
    AZURE_COSMOS_API_VERSION, AZURE_COSMOS_CONTRACT_VERSION, AZURE_COSMOS_PLUGIN_VERSION,
    AZURE_COSMOS_PROVIDER_ID, AZURE_COSMOS_PROVIDER_REVISION, AZURE_COSMOS_SERVICE_ID,
    AzureCosmosContractError, contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureCosmosServiceError {
    #[error("Azure Cosmos model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("Azure Cosmos contract validation failed: {0}")]
    Contract(#[from] AzureCosmosContractError),
    #[error("Azure Cosmos registration is invalid or tampered")]
    RegistrationTampered,
    #[error("Azure Cosmos registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("Azure Cosmos request does not match the registered scope")]
    ScopeMismatch,
    #[error("Azure Cosmos permission snapshot is insufficient")]
    PermissionDenied,
    #[error("Azure Cosmos proposal is tampered")]
    ProposalTampered,
    #[error("Azure Cosmos proposal or record is a replay")]
    ReplayDetected,
    #[error("Azure Cosmos provider returned an unusable result: {0:?}")]
    Provider(AzureCosmosProviderError),
}

pub type AzureCosmosTransportFailure = AzureCosmosProviderError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosReadRequest {
    pub scope_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub throughput_target: ThroughputTarget,
    pub max_response_bytes: usize,
    pub request_digest: Digest,
}

impl AzureCosmosReadRequest {
    pub fn new(scope: &AzureCosmosScope, observed_at: DateTime<Utc>) -> Result<Self, ModelError> {
        Self::with_options(
            scope,
            observed_at,
            scope.throughput_target,
            crate::model::MAX_RESPONSE_BYTES,
        )
    }

    pub fn with_options(
        scope: &AzureCosmosScope,
        observed_at: DateTime<Utc>,
        throughput_target: ThroughputTarget,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        if max_response_bytes == 0 || max_response_bytes > crate::model::MAX_RESPONSE_BYTES {
            return Err(ModelError::OutOfBounds {
                field: "maximum response bytes",
            });
        }
        let mut request = Self {
            scope_digest: scope.digest(),
            observed_at,
            throughput_target,
            max_response_bytes,
            request_digest: Digest::zero(),
        };
        request.request_digest = request.recomputed_digest();
        Ok(request)
    }

    pub fn with_throughput_target(
        &self,
        scope: &AzureCosmosScope,
        throughput_target: ThroughputTarget,
    ) -> Result<Self, ModelError> {
        Self::with_options(
            scope,
            self.observed_at,
            throughput_target,
            self.max_response_bytes,
        )
    }

    pub fn with_observed_at(
        &self,
        scope: &AzureCosmosScope,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::with_options(
            scope,
            observed_at,
            self.throughput_target,
            self.max_response_bytes,
        )
    }

    fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serializable(&(
            &self.scope_digest,
            self.observed_at,
            self.throughput_target,
            self.max_response_bytes,
        ))
        .expect("Cosmos read request is serializable")
    }

    pub fn validate(&self, scope: &AzureCosmosScope) -> Result<(), AzureCosmosServiceError> {
        if self.scope_digest != scope.digest()
            || self.request_digest != self.recomputed_digest()
            || self.max_response_bytes == 0
            || self.max_response_bytes > crate::model::MAX_RESPONSE_BYTES
        {
            return Err(AzureCosmosServiceError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosRegistrationRequest {
    pub scope_digest: Digest,
    pub api_version: ApiVersion,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistrationTransitionEvidence {
    pub transition: String,
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub previous_registration_digest: Digest,
    pub new_registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_version: ApiVersion,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl AzureCosmosRegistration {
    pub fn new<T: AzureCosmosTransport>(
        scope: &AzureCosmosScope,
        secret_reference: &SecretReference,
        permission: &PermissionSnapshot,
        provider: &AzureCosmosResourceProvider<T>,
    ) -> Result<Self, AzureCosmosServiceError> {
        scope.validate()?;
        permission.validate()?;
        if secret_reference.is_revoked()
            || secret_reference.tenant_digest() != &Digest::from_text(scope.tenant_id.as_str())
        {
            return Err(AzureCosmosServiceError::ScopeMismatch);
        }
        provider.definition().validate()?;
        let evidence_binding_digest = crate::model::digest_serializable(&(
            AZURE_COSMOS_PLUGIN_VERSION,
            AZURE_COSMOS_CONTRACT_VERSION,
            contract_digest(),
            provider.identity(),
            &provider.definition().version,
            &provider.definition().api_revision,
            provider.provider_digest(),
            &scope.api_version,
            permission.permission_digest(),
            scope.digest(),
            secret_reference.reference_digest(),
        ))?;
        let mut registration = Self {
            plugin_version: AZURE_COSMOS_PLUGIN_VERSION.to_owned(),
            contract_version: AZURE_COSMOS_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.identity().as_str().to_owned(),
            provider_version: provider.definition().version.clone(),
            provider_revision: provider.definition().api_revision.clone(),
            provider_digest: provider.provider_digest().clone(),
            api_version: scope.api_version.clone(),
            permission_digest: permission.permission_digest().clone(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            evidence_binding_digest,
            registration_revision: 1,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serializable(&(
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_version,
            &self.provider_revision,
            &self.provider_digest,
            &self.api_version,
            &self.permission_digest,
            &self.scope_digest,
            &self.secret_reference_digest,
            &self.evidence_binding_digest,
            self.registration_revision,
            self.state,
        ))
        .expect("registration is serializable")
    }

    pub fn validate<T: AzureCosmosTransport>(
        &self,
        scope: &AzureCosmosScope,
        secret_reference: &SecretReference,
        permission: &PermissionSnapshot,
        provider: &AzureCosmosResourceProvider<T>,
    ) -> Result<(), AzureCosmosServiceError> {
        if self.registration_digest != self.recomputed_digest()
            || self.plugin_version != AZURE_COSMOS_PLUGIN_VERSION
            || self.contract_version != AZURE_COSMOS_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != AZURE_COSMOS_PROVIDER_ID
            || self.provider_version != provider.definition().version
            || self.provider_revision != AZURE_COSMOS_PROVIDER_REVISION
            || self.provider_digest != *provider.provider_digest()
            || self.api_version.as_str() != AZURE_COSMOS_API_VERSION
            || self.permission_digest != *permission.permission_digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || secret_reference.is_revoked()
        {
            return Err(AzureCosmosServiceError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_binding_digest
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, AzureCosmosServiceError> {
        self.transition(RegistrationState::Revoked, "revoke_registration")
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, AzureCosmosServiceError> {
        self.transition(RegistrationState::Reversed, "reverse_registration")
    }

    fn transition(
        &mut self,
        state: RegistrationState,
        transition: &str,
    ) -> Result<RegistrationTransitionEvidence, AzureCosmosServiceError> {
        if !self.is_active() {
            return Err(AzureCosmosServiceError::RegistrationRevoked);
        }
        let previous_state = self.state;
        let previous_registration_digest = self.registration_digest.clone();
        self.state = state;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence {
            transition: transition.to_owned(),
            previous_state,
            new_state: state,
            previous_registration_digest,
            new_registration_digest: self.registration_digest.clone(),
            reversible: true,
            revocable: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub api_version: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub local_record_only: bool,
    pub live_execution: bool,
    pub data_plane: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosContainerProposal {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub evidence: AzureCosmosEvidence,
    pub proposed_at: DateTime<Utc>,
    pub read_only: bool,
    pub external_write_performed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub proposal_digest: Digest,
}

impl AzureCosmosContainerProposal {
    pub fn new(
        registration: &AzureCosmosRegistration,
        evidence: AzureCosmosEvidence,
        proposed_at: DateTime<Utc>,
    ) -> Result<Self, AzureCosmosServiceError> {
        evidence.validate()?;
        let mut proposal = Self {
            plugin_version: AZURE_COSMOS_PLUGIN_VERSION.to_owned(),
            contract_version: AZURE_COSMOS_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            evidence,
            proposed_at,
            read_only: true,
            external_write_performed: false,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        Ok(proposal)
    }

    fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serializable(&(
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.registration_digest,
            &self.scope_digest,
            &self.evidence_digest,
            &self.evidence,
            self.proposed_at,
            self.read_only,
            self.external_write_performed,
            self.connected,
            self.native,
            self.first_party,
            self.adopted_outcome,
        ))
        .expect("Cosmos proposal is serializable")
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(&self) -> Result<(), AzureCosmosServiceError> {
        self.evidence.validate()?;
        if self.proposal_digest != self.recomputed_digest()
            || self.contract_digest != contract_digest()
            || self.plugin_version != AZURE_COSMOS_PLUGIN_VERSION
            || self.contract_version != AZURE_COSMOS_CONTRACT_VERSION
            || self.scope_digest != self.evidence.scope_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || !self.read_only
            || self.external_write_performed
            || self.connected
            || self.native
            || self.first_party
            || self.adopted_outcome
        {
            return Err(AzureCosmosServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosRecordReceipt {
    pub record_id_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub recorded_at: DateTime<Utc>,
    pub local_record: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_write_performed: bool,
    pub record_digest: Digest,
}

impl AzureCosmosRecordReceipt {
    fn new(
        proposal: &AzureCosmosContainerProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, AzureCosmosServiceError> {
        let mut receipt = Self {
            record_id_digest: Digest::from_parts(
                "hartevo-azure-cosmosdb-local-record/v1",
                &[
                    proposal.proposal_digest.as_str().to_owned(),
                    recorded_at.to_rfc3339(),
                ],
            ),
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            recorded_at,
            local_record: true,
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            external_write_performed: false,
            record_digest: Digest::zero(),
        };
        receipt.record_digest = receipt.recomputed_digest();
        Ok(receipt)
    }

    fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serializable(&(
            &self.record_id_digest,
            &self.proposal_digest,
            &self.registration_digest,
            &self.evidence_digest,
            self.recorded_at,
            self.local_record,
            self.durable_receipt,
            self.connected,
            self.native,
            self.first_party,
            self.external_write_performed,
        ))
        .expect("Cosmos record is serializable")
    }

    pub fn validate_integrity(&self) -> Result<(), AzureCosmosServiceError> {
        if self.record_digest != self.recomputed_digest()
            || !self.local_record
            || self.durable_receipt
            || self.connected
            || self.native
            || self.first_party
            || self.external_write_performed
        {
            return Err(AzureCosmosServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceVerificationStatus {
    Verified,
    Tampered,
    Replay,
    Revoked,
    ScopeMismatch,
    RevisionDrift,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosServiceVerificationReport {
    pub status: ServiceVerificationStatus,
    pub verified: bool,
    pub adoptable: bool,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub reason: Option<String>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type ProposalVerification = AzureCosmosServiceVerificationReport;

pub trait ProposalIntegrity {
    fn registration_digest(&self) -> &Digest;
    fn evidence_digest(&self) -> &Digest;
    fn verify_integrity(&self) -> Result<(), AzureCosmosServiceError>;
    fn evidence_state(&self) -> Option<EvidenceState>;
}

impl ProposalIntegrity for AzureCosmosContainerProposal {
    fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn verify_integrity(&self) -> Result<(), AzureCosmosServiceError> {
        self.validate_integrity()
    }

    fn evidence_state(&self) -> Option<EvidenceState> {
        Some(self.evidence.state)
    }
}

impl ProposalIntegrity for AzureCosmosRecordReceipt {
    fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn verify_integrity(&self) -> Result<(), AzureCosmosServiceError> {
        self.validate_integrity()
    }

    fn evidence_state(&self) -> Option<EvidenceState> {
        None
    }
}

#[derive(Debug)]
pub struct AzureCosmosContainerResultService<T: AzureCosmosTransport> {
    scope: AzureCosmosScope,
    permission: PermissionSnapshot,
    secret_reference: SecretReference,
    provider: AzureCosmosResourceProvider<T>,
    registration: AzureCosmosRegistration,
    recorded_proposals: BTreeSet<Digest>,
}

impl<T: AzureCosmosTransport> AzureCosmosContainerResultService<T> {
    pub fn new(
        scope: AzureCosmosScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AzureCosmosResourceProvider<T>,
    ) -> Result<Self, AzureCosmosServiceError> {
        let registration =
            AzureCosmosRegistration::new(&scope, &secret_reference, &permission, &provider)?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
            recorded_proposals: BTreeSet::new(),
        })
    }

    pub fn register(
        scope: AzureCosmosScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AzureCosmosResourceProvider<T>,
    ) -> Result<Self, AzureCosmosServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn describe_capabilities(&self) -> AzureCosmosCapabilities {
        AzureCosmosCapabilities {
            service_id: AZURE_COSMOS_SERVICE_ID.to_owned(),
            provider_id: AZURE_COSMOS_PROVIDER_ID.to_owned(),
            api_version: AZURE_COSMOS_API_VERSION.to_owned(),
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "reverse_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            read_only: true,
            proposal_only: true,
            local_record_only: true,
            live_execution: false,
            data_plane: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        }
    }

    pub fn scope(&self) -> &AzureCosmosScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AzureCosmosResourceProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AzureCosmosResourceProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AzureCosmosRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AzureCosmosRegistration {
        &mut self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn consumer(
        &self,
    ) -> Result<crate::consumer::MissionAzureCosmosContainerConsumer, crate::consumer::ConsumerError>
    {
        crate::consumer::MissionAzureCosmosContainerConsumer::new(
            self.scope.clone(),
            self.registration.clone(),
        )
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AzureCosmosServiceError> {
        self.registration.revoke()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, AzureCosmosServiceError> {
        self.revoke_registration()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AzureCosmosServiceError> {
        self.registration.reverse()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, AzureCosmosServiceError> {
        self.reverse_registration()
    }

    pub fn read_bounded(
        &mut self,
        request: &AzureCosmosReadRequest,
    ) -> Result<AzureCosmosEvidence, AzureCosmosServiceError> {
        request.validate(&self.scope)?;
        self.validate_registration()?;
        if !self.registration.is_active() || self.secret_reference.is_revoked() {
            return Ok(AzureCosmosEvidence::revoked(
                &self.scope,
                &self.permission,
                &self.secret_reference,
                self.provider.provider_digest().clone(),
                request.request_digest.clone(),
                request.observed_at,
            )?);
        }
        let mut account = None;
        let mut database = None;
        let mut container = None;
        let mut throughput = None;
        let mut errors = Vec::new();
        let mut state = None;
        let mut partial_reason = None;
        for operation in [
            AzureCosmosOperation::DatabaseAccountsGet,
            AzureCosmosOperation::SqlDatabasesGet,
            AzureCosmosOperation::SqlContainersGet,
            AzureCosmosOperation::ThroughputSettingsGet,
        ] {
            let get_request = AzureCosmosGetRequest::for_scope(
                &self.scope,
                operation,
                request.throughput_target,
                request.max_response_bytes,
            )?;
            match self.fetch_with_retry(&get_request, operation, &mut errors) {
                Ok(response) => {
                    if response.validate_integrity(&get_request).is_err() {
                        state = Some(EvidenceState::Tampered);
                        partial_reason = None;
                        break;
                    }
                    if let Some(drift) = self.check_revision_drift(operation, &response) {
                        state = Some(EvidenceState::RevisionDrift);
                        partial_reason = Some(drift);
                        break;
                    }
                    match response.resource {
                        AzureCosmosResourceProjection::Account(value) => account = Some(value),
                        AzureCosmosResourceProjection::SqlDatabase(value) => database = Some(value),
                        AzureCosmosResourceProjection::SqlContainer(value) => {
                            container = Some(value);
                        }
                        AzureCosmosResourceProjection::Throughput(value) => {
                            throughput = Some(value);
                        }
                    }
                }
                Err(error) => {
                    if error.access_loss() {
                        state = Some(EvidenceState::AccessLost);
                        break;
                    }
                    if error.not_found() {
                        if operation == AzureCosmosOperation::ThroughputSettingsGet {
                            partial_reason = Some(PartialReason::ThroughputUnavailable);
                        } else {
                            state = Some(EvidenceState::NotFound);
                            partial_reason = Some(match operation {
                                AzureCosmosOperation::DatabaseAccountsGet => {
                                    PartialReason::MissingAccount
                                }
                                AzureCosmosOperation::SqlDatabasesGet => {
                                    PartialReason::MissingDatabase
                                }
                                _ => PartialReason::MissingContainer,
                            });
                            break;
                        }
                    } else if error.revision_drift() {
                        state = Some(EvidenceState::RevisionDrift);
                        partial_reason = Some(PartialReason::RevisionMismatch);
                        break;
                    } else if matches!(
                        error.code(),
                        ProviderErrorCode::MalformedResponse | ProviderErrorCode::ResponseTooLarge
                    ) {
                        state = Some(EvidenceState::Partial);
                        partial_reason =
                            Some(if error.code() == ProviderErrorCode::ResponseTooLarge {
                                PartialReason::ResponseTooLarge
                            } else {
                                PartialReason::MalformedResponse
                            });
                        break;
                    } else {
                        state = Some(EvidenceState::ProviderUnknown);
                        partial_reason = Some(PartialReason::ProviderError);
                        break;
                    }
                }
            }
        }
        let account_missing = account.is_none();
        let database_missing = database.is_none();
        let container_missing = container.is_none();
        let posture = match (account, database, container) {
            (Some(account), Some(database), Some(container)) => {
                let throughput_pair = throughput.as_ref().map(|value| value.resource.clone());
                let throughput_summary = throughput
                    .as_ref()
                    .map_or_else(ThroughputSummary::unknown, |value| value.summary.clone());
                Some(
                    AzureCosmosContainerPosture {
                        account: account.resource,
                        database: database.resource,
                        container: container.resource,
                        throughput: throughput_pair,
                        location: account.location,
                        replication: account.replication,
                        consistency: account.consistency,
                        backup_policy: account.backup_policy,
                        public_network_access: account.public_network_access,
                        network_filter_enabled: account.network_filter_enabled,
                        throughput_summary,
                        indexing_mode: container.indexing_mode,
                        partition_key_digest: container.partition_key_digest,
                        observed_at: request.observed_at,
                    }
                    .pipe_result(),
                )
            }
            _ => None,
        };
        let posture = match posture {
            Some(Ok(value)) => Some(value),
            Some(Err(_)) => {
                state = Some(EvidenceState::Partial);
                partial_reason = Some(PartialReason::ProviderResponseIncomplete);
                None
            }
            None => {
                if state.is_none() {
                    state = Some(EvidenceState::Partial);
                    partial_reason = Some(if account_missing {
                        PartialReason::MissingAccount
                    } else if database_missing {
                        PartialReason::MissingDatabase
                    } else if container_missing {
                        PartialReason::MissingContainer
                    } else {
                        PartialReason::ProviderResponseIncomplete
                    });
                }
                None
            }
        };
        let state = state.unwrap_or_else(|| {
            if partial_reason == Some(PartialReason::ThroughputUnavailable) {
                EvidenceState::DegradedConfiguration
            } else if posture
                .as_ref()
                .is_some_and(AzureCosmosContainerPosture::is_degraded)
            {
                partial_reason = if posture
                    .as_ref()
                    .is_some_and(|value| value.throughput_summary.is_degraded())
                {
                    Some(PartialReason::ThroughputAmbiguous)
                } else {
                    Some(PartialReason::ProviderResponseIncomplete)
                };
                EvidenceState::DegradedConfiguration
            } else {
                EvidenceState::Present
            }
        });
        AzureCosmosEvidence::new(
            AZURE_COSMOS_PLUGIN_VERSION,
            AZURE_COSMOS_CONTRACT_VERSION,
            contract_digest(),
            self.scope.provider_id.clone(),
            self.scope.provider_revision.clone(),
            self.provider.provider_digest().clone(),
            self.scope.api_version.clone(),
            self.scope.digest(),
            self.permission.permission_digest().clone(),
            self.secret_reference.reference_digest().clone(),
            request.request_digest.clone(),
            state,
            partial_reason,
            self.provider.provenance(),
            posture,
            errors,
            request.observed_at,
        )
        .map_err(AzureCosmosServiceError::from)
    }

    pub fn read(
        &mut self,
        request: &AzureCosmosReadRequest,
    ) -> Result<AzureCosmosEvidence, AzureCosmosServiceError> {
        self.read_bounded(request)
    }

    fn validate_registration(&self) -> Result<(), AzureCosmosServiceError> {
        self.registration.validate(
            &self.scope,
            &self.secret_reference,
            &self.permission,
            &self.provider,
        )?;
        if !self.permission.allows_all() {
            return Err(AzureCosmosServiceError::PermissionDenied);
        }
        Ok(())
    }

    fn fetch_with_retry(
        &mut self,
        request: &AzureCosmosGetRequest,
        operation: AzureCosmosOperation,
        errors: &mut Vec<ProviderErrorSummary>,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            match self.provider.get(request) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    if errors.len() < crate::model::MAX_PROVIDER_ERRORS {
                        errors.push(error.summary(operation));
                    }
                    let retry = error.retryable() && attempt < MAX_RETRIES;
                    last_error = Some(error);
                    if !retry {
                        break;
                    }
                }
            }
        }
        Err(last_error.unwrap_or(AzureCosmosProviderError::TransportUnavailable))
    }

    fn check_revision_drift(
        &self,
        operation: AzureCosmosOperation,
        response: &AzureCosmosResourceResponse,
    ) -> Option<PartialReason> {
        let expected = match operation {
            AzureCosmosOperation::DatabaseAccountsGet => &self.scope.account_revision_digest,
            AzureCosmosOperation::SqlDatabasesGet => &self.scope.database_revision_digest,
            AzureCosmosOperation::SqlContainersGet => &self.scope.container_revision_digest,
            AzureCosmosOperation::ThroughputSettingsGet => {
                if let Some(expected) = &self.scope.throughput_revision_digest {
                    expected
                } else {
                    return None;
                }
            }
        };
        (response.resource.resource().revision_digest != *expected)
            .then_some(PartialReason::RevisionMismatch)
    }

    pub fn propose(
        &mut self,
        request: &AzureCosmosReadRequest,
    ) -> Result<AzureCosmosContainerProposal, AzureCosmosServiceError> {
        self.propose_at(request, request.observed_at)
    }

    pub fn propose_at(
        &mut self,
        request: &AzureCosmosReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AzureCosmosContainerProposal, AzureCosmosServiceError> {
        let request = request.with_observed_at(&self.scope, proposed_at)?;
        let evidence = self.read_bounded(&request)?;
        AzureCosmosContainerProposal::new(&self.registration, evidence, proposed_at)
    }

    pub fn record(
        &mut self,
        proposal: &AzureCosmosContainerProposal,
    ) -> Result<AzureCosmosRecordReceipt, AzureCosmosServiceError> {
        self.record_at(proposal, proposal.proposed_at)
    }

    pub fn record_at(
        &mut self,
        proposal: &AzureCosmosContainerProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AzureCosmosRecordReceipt, AzureCosmosServiceError> {
        self.validate_registration()?;
        if self.recorded_proposals.contains(proposal.digest()) {
            return Err(AzureCosmosServiceError::ReplayDetected);
        }
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(AzureCosmosServiceError::ScopeMismatch);
        }
        let receipt = AzureCosmosRecordReceipt::new(proposal, recorded_at)?;
        self.recorded_proposals.insert(proposal.digest().clone());
        Ok(receipt)
    }

    pub fn verify<V: ProposalIntegrity>(&self, value: &V) -> AzureCosmosServiceVerificationReport {
        let registration_digest = value.registration_digest().clone();
        let evidence_digest = value.evidence_digest().clone();
        let base = |status: ServiceVerificationStatus, reason: Option<&str>| {
            AzureCosmosServiceVerificationReport {
                status,
                verified: matches!(status, ServiceVerificationStatus::Verified),
                adoptable: false,
                registration_digest: registration_digest.clone(),
                evidence_digest: evidence_digest.clone(),
                reason: reason.map(str::to_owned),
                connected: false,
                native: false,
                first_party: false,
            }
        };
        if !self.registration.is_active() || self.secret_reference.is_revoked() {
            return base(
                ServiceVerificationStatus::Revoked,
                Some("registration revoked"),
            );
        }
        if self.validate_registration().is_err() {
            return base(
                ServiceVerificationStatus::Tampered,
                Some("registration tampered"),
            );
        }
        if value.verify_integrity().is_err() {
            return base(
                ServiceVerificationStatus::Tampered,
                Some("proposal or record tampered"),
            );
        }
        if value.registration_digest() != self.registration.registration_digest()
            || value.evidence_digest().is_zero()
        {
            return base(
                ServiceVerificationStatus::ScopeMismatch,
                Some("binding mismatch"),
            );
        }
        if let Some(state) = value.evidence_state() {
            let status = match state {
                EvidenceState::Tampered => ServiceVerificationStatus::Tampered,
                EvidenceState::Revoked => ServiceVerificationStatus::Revoked,
                EvidenceState::RevisionDrift => ServiceVerificationStatus::RevisionDrift,
                EvidenceState::ProviderUnknown => ServiceVerificationStatus::ProviderUnknown,
                _ => ServiceVerificationStatus::Verified,
            };
            if status != ServiceVerificationStatus::Verified {
                return base(status, Some("evidence is fail-closed"));
            }
        }
        base(ServiceVerificationStatus::Verified, None)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AzureCosmosContainerProposal,
    ) -> AzureCosmosServiceVerificationReport {
        self.verify(proposal)
    }

    pub fn verify_record(
        &self,
        receipt: &AzureCosmosRecordReceipt,
    ) -> AzureCosmosServiceVerificationReport {
        if !self.recorded_proposals.contains(&receipt.proposal_digest) {
            return AzureCosmosServiceVerificationReport {
                status: ServiceVerificationStatus::Replay,
                verified: false,
                adoptable: false,
                registration_digest: receipt.registration_digest.clone(),
                evidence_digest: receipt.evidence_digest.clone(),
                reason: Some("record is not present in this local recorder".to_owned()),
                connected: false,
                native: false,
                first_party: false,
            };
        }
        self.verify(receipt)
    }

    pub fn recorded_count(&self) -> usize {
        self.recorded_proposals.len()
    }
}

pub type AzureCosmosService<T> = AzureCosmosContainerResultService<T>;

trait PipeResult<T> {
    fn pipe_result(self) -> Result<T, ModelError>;
}

impl PipeResult<AzureCosmosContainerPosture> for AzureCosmosContainerPosture {
    fn pipe_result(self) -> Result<AzureCosmosContainerPosture, ModelError> {
        self.validate()?;
        Ok(self)
    }
}

impl fmt::Display for AzureCosmosServiceVerificationReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.status)
    }
}

// Kept as a type alias for callers that used the provider's older name in
// local fixtures; it does not add any authority or transport capability.
pub type AzureCosmosProvider =
    AzureCosmosResourceProvider<crate::provider::RecordingAzureCosmosTransport>;
