//! Service, registration, proposal, bounded-read, and recording seams.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    CloudSchedulerObservationRecord, CloudSchedulerOperation, CloudSchedulerRequestReceipt, Digest,
    EvidenceState, GcpCloudSchedulerEvidence, GcpCloudSchedulerScope, ReadBounds,
    RegistrationState, Revision, SchedulerJobSummary, SecretReference, TransportProvenance,
};
use crate::provider::{
    CloudSchedulerReadProposal, CloudSchedulerReadRecord, CloudSchedulerReadRequest,
    GcpCloudSchedulerProvider, GcpCloudSchedulerProviderDefinition, GcpCloudSchedulerProviderError,
    GcpCloudSchedulerTransport, OpaquePageToken, ProviderDefinitionError,
};
use crate::{
    GCP_CLOUD_SCHEDULER_API_REVISION, GCP_CLOUD_SCHEDULER_CONTRACT_VERSION,
    GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT, GCP_CLOUD_SCHEDULER_PROVIDER_ID,
    GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT, GCP_CLOUD_SCHEDULER_SCHEMA_VERSION,
    GCP_CLOUD_SCHEDULER_SERVICE_ID, GCP_CLOUD_SCHEDULER_SERVICE_NAME,
    MISSION_GCP_CLOUD_SCHEDULER_CONSUMER_ID, contract_digest,
};

pub const GCP_CLOUD_SCHEDULER_SERVICE_VERSION: &str = "1.0.0";
pub const GCP_CLOUD_SCHEDULER_SERVICE_SCHEMA: &str =
    "hartevo.gcp-cloud-scheduler-result-service/v1";
pub const GCP_CLOUD_SCHEDULER_EVIDENCE_POLICY: &str =
    "cloud-scheduler-v1-job-state-schedule-target-digests";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpCloudSchedulerResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    RestoreRegistration,
    ProposeList,
    ProposeGet,
    ReadList,
    ReadGet,
    RecordObservation,
    VerifyProposal,
    VerifyObservation,
    ConsumeMissionProjection,
}

impl GcpCloudSchedulerResultOperation {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        !matches!(
            self,
            Self::Register | Self::RevokeRegistration | Self::RestoreRegistration
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudSchedulerCapability {
    pub operation: GcpCloudSchedulerResultOperation,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudSchedulerResultServiceDefinition {
    pub service_id: String,
    pub service_name: String,
    pub service_version: String,
    pub schema_version: String,
    pub contract_version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub capabilities: Vec<GcpCloudSchedulerCapability>,
}

impl Default for GcpCloudSchedulerResultServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpCloudSchedulerResultServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        let operations = [
            GcpCloudSchedulerResultOperation::DescribeCapabilities,
            GcpCloudSchedulerResultOperation::Register,
            GcpCloudSchedulerResultOperation::RevokeRegistration,
            GcpCloudSchedulerResultOperation::RestoreRegistration,
            GcpCloudSchedulerResultOperation::ProposeList,
            GcpCloudSchedulerResultOperation::ProposeGet,
            GcpCloudSchedulerResultOperation::ReadList,
            GcpCloudSchedulerResultOperation::ReadGet,
            GcpCloudSchedulerResultOperation::RecordObservation,
            GcpCloudSchedulerResultOperation::VerifyProposal,
            GcpCloudSchedulerResultOperation::VerifyObservation,
            GcpCloudSchedulerResultOperation::ConsumeMissionProjection,
        ];
        Self {
            service_id: GCP_CLOUD_SCHEDULER_SERVICE_ID.to_owned(),
            service_name: GCP_CLOUD_SCHEDULER_SERVICE_NAME.to_owned(),
            service_version: GCP_CLOUD_SCHEDULER_SERVICE_VERSION.to_owned(),
            schema_version: GCP_CLOUD_SCHEDULER_SERVICE_SCHEMA.to_owned(),
            contract_version: GCP_CLOUD_SCHEDULER_CONTRACT_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            external_writes: false,
            capabilities: operations
                .into_iter()
                .map(|operation| GcpCloudSchedulerCapability {
                    read_only: operation.is_read_only(),
                    operation,
                    native: false,
                    connected: false,
                    external_write: false,
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<GcpCloudSchedulerCapability> {
        self.capabilities.clone()
    }

    pub fn validate(&self) -> Result<(), GcpCloudSchedulerResultServiceError> {
        if self.service_id != GCP_CLOUD_SCHEDULER_SERVICE_ID
            || self.service_name != GCP_CLOUD_SCHEDULER_SERVICE_NAME
            || self.service_version != GCP_CLOUD_SCHEDULER_SERVICE_VERSION
            || self.schema_version != GCP_CLOUD_SCHEDULER_SERVICE_SCHEMA
            || self.contract_version != GCP_CLOUD_SCHEDULER_CONTRACT_VERSION
            || !self.read_only
            || !self.proposal_only
            || self.native
            || self.connected
            || self.external_writes
            || self.capabilities.iter().any(|capability| {
                capability.native || capability.connected || capability.external_write
            })
        {
            return Err(GcpCloudSchedulerResultServiceError::ContractDrift);
        }
        Ok(())
    }
}

pub type GcpCloudSchedulerServiceDefinition = GcpCloudSchedulerResultServiceDefinition;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudSchedulerRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub schedule_digest: Digest,
    pub target_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GcpCloudSchedulerRegistration {
    pub fn new(
        scope: &GcpCloudSchedulerScope,
        secret_reference: &SecretReference,
        provider_definition: &GcpCloudSchedulerProviderDefinition,
    ) -> Result<Self, GcpCloudSchedulerResultServiceError> {
        scope.validate()?;
        provider_definition.validate()?;
        if secret_reference.is_revoked() || secret_reference.scope_digest() != &scope.scope_digest()
        {
            return Err(GcpCloudSchedulerResultServiceError::ScopeMismatch);
        }
        let mut registration = Self {
            schema_version: GCP_CLOUD_SCHEDULER_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_CLOUD_SCHEDULER_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest: Digest::from_text(GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT),
            contract_digest: contract_digest(),
            provider_id: provider_definition.provider_id.clone(),
            provider_version: provider_definition.provider_version.clone(),
            provider_revision: provider_definition.provider_revision.clone(),
            provider_digest: provider_definition.provider_digest(),
            api_digest: Digest::from_text(GCP_CLOUD_SCHEDULER_API_REVISION),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            schedule_digest: scope.schedule_digest(),
            target_digest: scope.target_digest(),
            evidence_policy_digest: Digest::from_text(GCP_CLOUD_SCHEDULER_EVIDENCE_POLICY),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.revision(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("placeholder"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Input<'a> {
            schema_version: &'a str,
            contract_version: &'a str,
            plugin_version: &'a str,
            version_digest: &'a Digest,
            contract_digest: &'a Digest,
            provider_id: &'a str,
            provider_version: &'a str,
            provider_revision: &'a str,
            provider_digest: &'a Digest,
            api_digest: &'a Digest,
            permission_digest: &'a Digest,
            scope_digest: &'a Digest,
            schedule_digest: &'a Digest,
            target_digest: &'a Digest,
            evidence_policy_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
            credential_revision: Revision,
            registration_revision: Revision,
            state: RegistrationState,
        }
        Digest::from_serializable(&Input {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            schedule_digest: &self.schedule_digest,
            target_digest: &self.target_digest,
            evidence_policy_digest: &self.evidence_policy_digest,
            secret_reference_digest: &self.secret_reference_digest,
            credential_revision: self.credential_revision,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.registration_digest == self.compute_digest()
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| RegistrationError::RevisionOverflow)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            return Err(RegistrationError::NotRevoked);
        }
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| RegistrationError::RevisionOverflow)?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}

pub type GcpCloudSchedulerResultRegistration = GcpCloudSchedulerRegistration;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpCloudSchedulerResultServiceError {
    #[error("service contract drifted")]
    ContractDrift,
    #[error("registration is revoked or invalid")]
    RegistrationRevoked,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("registration scope does not match the provider scope")]
    ScopeMismatch,
    #[error("proposal was tampered with or is from a stale registration")]
    ProposalTampered,
    #[error("record was tampered with or is from a stale registration")]
    RecordTampered,
    #[error("observation was tampered with or is from a stale registration")]
    ObservationTampered,
    #[error("provider error: {0}")]
    Provider(#[from] GcpCloudSchedulerProviderError),
    #[error("provider definition error: {0}")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("model error: {0}")]
    Model(#[from] crate::ModelError),
}

pub struct GcpCloudSchedulerResultService<T>
where
    T: GcpCloudSchedulerTransport,
{
    definition: GcpCloudSchedulerResultServiceDefinition,
    provider: GcpCloudSchedulerProvider<T>,
    registration: GcpCloudSchedulerRegistration,
    bounds: ReadBounds,
    observation_revision: Revision,
}

impl<T> fmt::Debug for GcpCloudSchedulerResultService<T>
where
    T: GcpCloudSchedulerTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudSchedulerResultService")
            .field("scope_digest", &self.scope().scope_digest())
            .field("registration", &self.registration)
            .field("bounds", &self.bounds)
            .field("observation_revision", &self.observation_revision)
            .finish_non_exhaustive()
    }
}

impl<T> GcpCloudSchedulerResultService<T>
where
    T: GcpCloudSchedulerTransport,
{
    pub fn new(
        provider: GcpCloudSchedulerProvider<T>,
    ) -> Result<Self, GcpCloudSchedulerResultServiceError> {
        let definition = GcpCloudSchedulerResultServiceDefinition::new();
        definition.validate()?;
        let registration = GcpCloudSchedulerRegistration::new(
            provider.scope(),
            provider.secret_reference(),
            provider.definition(),
        )?;
        Ok(Self {
            definition,
            provider,
            registration,
            bounds: ReadBounds::default(),
            observation_revision: Revision::new(1)?,
        })
    }

    pub fn with_bounds(
        provider: GcpCloudSchedulerProvider<T>,
        bounds: ReadBounds,
    ) -> Result<Self, GcpCloudSchedulerResultServiceError> {
        let mut service = Self::new(provider)?;
        service.bounds = bounds;
        Ok(service)
    }

    #[must_use]
    pub fn definition(&self) -> &GcpCloudSchedulerResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &GcpCloudSchedulerScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        self.provider.secret_reference()
    }

    #[must_use]
    pub fn provider(&self) -> &GcpCloudSchedulerProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GcpCloudSchedulerProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &GcpCloudSchedulerRegistration {
        &self.registration
    }

    #[must_use]
    pub const fn bounds(&self) -> ReadBounds {
        self.bounds
    }

    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.registration.is_active()
    }

    #[must_use]
    pub fn provider_provenance(&self) -> TransportProvenance {
        self.provider.provenance()
    }

    pub fn register(&mut self) -> Result<(), GcpCloudSchedulerResultServiceError> {
        self.definition.validate()?;
        if self.registration.is_active() && self.registration.verify_digest() {
            Ok(())
        } else {
            self.registration
                .restore()
                .map_err(|_| GcpCloudSchedulerResultServiceError::RegistrationRevoked)
        }
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GcpCloudSchedulerResultServiceError> {
        self.registration
            .revoke()
            .map_err(|_| GcpCloudSchedulerResultServiceError::RegistrationRevoked)
    }

    pub fn restore_registration(&mut self) -> Result<(), GcpCloudSchedulerResultServiceError> {
        self.registration
            .restore()
            .map_err(|_| GcpCloudSchedulerResultServiceError::RegistrationRevoked)
    }

    pub fn revoke_secret_reference(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GcpCloudSchedulerResultServiceError> {
        self.provider
            .secret_reference_mut()
            .revoke()
            .map_err(|_| GcpCloudSchedulerResultServiceError::SecretRevoked)?;
        self.revoke_registration()
    }

    pub fn restore_secret_reference(&mut self) -> Result<(), GcpCloudSchedulerResultServiceError> {
        self.provider
            .secret_reference_mut()
            .restore()
            .map_err(|_| GcpCloudSchedulerResultServiceError::SecretRevoked)?;
        self.restore_registration()
    }

    fn validate_active(&self) -> Result<(), GcpCloudSchedulerResultServiceError> {
        self.definition.validate()?;
        self.scope().validate()?;
        if !self.registration.is_active() || !self.registration.verify_digest() {
            return Err(GcpCloudSchedulerResultServiceError::RegistrationRevoked);
        }
        if self.secret_reference().is_revoked() {
            return Err(GcpCloudSchedulerResultServiceError::SecretRevoked);
        }
        if self.registration.scope_digest != self.scope().scope_digest()
            || self.registration.permission_digest != self.scope().permission_digest()
            || self.registration.schedule_digest != self.scope().schedule_digest()
            || self.registration.target_digest != self.scope().target_digest()
            || self.registration.provider_digest != self.provider.definition().provider_digest()
            || self.registration.secret_reference_digest
                != *self.secret_reference().reference_digest()
        {
            return Err(GcpCloudSchedulerResultServiceError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn propose_list_jobs(
        &self,
    ) -> Result<CloudSchedulerReadProposal, GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        let request = CloudSchedulerReadRequest::list(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
            self.bounds.page_size,
            None,
            self.secret_reference(),
        )?;
        Ok(CloudSchedulerReadProposal::new(request))
    }

    pub fn propose_get_job(
        &self,
    ) -> Result<CloudSchedulerReadProposal, GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        let request = CloudSchedulerReadRequest::get(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
            self.secret_reference(),
        )?;
        Ok(CloudSchedulerReadProposal::new(request))
    }

    pub fn compile_proposal(
        &self,
    ) -> Result<CloudSchedulerReadProposal, GcpCloudSchedulerResultServiceError> {
        if self.scope().job_id().is_some() {
            self.propose_get_job()
        } else {
            self.propose_list_jobs()
        }
    }

    pub fn record_list_jobs(
        &mut self,
    ) -> Result<CloudSchedulerReadRecord, GcpCloudSchedulerResultServiceError> {
        let proposal = self.propose_list_jobs()?;
        let record = self.provider.list(proposal.request())?;
        self.verify_proposal(&proposal, &record)?;
        Ok(record)
    }

    pub fn record_get_job(
        &mut self,
    ) -> Result<CloudSchedulerReadRecord, GcpCloudSchedulerResultServiceError> {
        let proposal = self.propose_get_job()?;
        let record = self.provider.get(proposal.request())?;
        self.verify_proposal(&proposal, &record)?;
        Ok(record)
    }

    pub fn verify_proposal(
        &self,
        proposal: &CloudSchedulerReadProposal,
        record: &CloudSchedulerReadRecord,
    ) -> Result<(), GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        if !proposal.verify_digest()
            || !record.verify_integrity()
            || !proposal.request.verify_digest()
            || proposal.proposal_digest().is_empty()
            || proposal.registration_digest != self.registration.registration_digest
            || record.registration_digest != self.registration.registration_digest
            || proposal.request != record.request
            || proposal.request.scope_digest != self.scope().scope_digest()
            || proposal.request.permission_digest != self.scope().permission_digest()
            || proposal.request.schedule_digest != self.scope().schedule_digest()
            || proposal.request.target_digest != self.scope().target_digest()
        {
            return Err(GcpCloudSchedulerResultServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn read_back(
        &self,
        proposal: &CloudSchedulerReadProposal,
        record: &CloudSchedulerReadRecord,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.verify_proposal(proposal, record)?;
        self.evidence_from_record(record)
    }

    pub fn record_observation(
        &mut self,
        evidence: &GcpCloudSchedulerEvidence,
    ) -> Result<CloudSchedulerObservationRecord, GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        if !evidence.verify_digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.scope_digest != self.scope().scope_digest()
            || evidence.permission_digest != self.scope().permission_digest()
        {
            return Err(GcpCloudSchedulerResultServiceError::ObservationTampered);
        }
        let observation = CloudSchedulerObservationRecord::new(evidence, self.observation_revision);
        self.observation_revision = self.observation_revision.next()?;
        Ok(observation)
    }

    pub fn verify_observation(
        &self,
        evidence: &GcpCloudSchedulerEvidence,
        observation: &CloudSchedulerObservationRecord,
    ) -> Result<(), GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        if !evidence.verify_digest()
            || !observation.verify_digest()
            || observation.evidence_digest != *evidence.evidence_digest()
            || observation.registration_digest != self.registration.registration_digest
        {
            return Err(GcpCloudSchedulerResultServiceError::ObservationTampered);
        }
        Ok(())
    }

    pub fn evidence_from_record(
        &self,
        record: &CloudSchedulerReadRecord,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        if !record.verify_integrity()
            || !record.request.verify_digest()
            || record.registration_digest != self.registration.registration_digest
            || record.request.scope_digest != self.scope().scope_digest()
            || record.request.permission_digest != self.scope().permission_digest()
            || record.request.schedule_digest != self.scope().schedule_digest()
            || record.request.target_digest != self.scope().target_digest()
        {
            return Err(GcpCloudSchedulerResultServiceError::RecordTampered);
        }
        let state = Self::evaluate_jobs(&record.jobs);
        Ok(self.evidence(
            record.operation,
            state,
            record.jobs.clone(),
            vec![Self::request_receipt(&record.request)],
            vec![record.response.clone()],
            record.next_page_token.as_ref().map(OpaquePageToken::digest),
            None,
            0,
        ))
    }

    pub fn read_list_jobs(
        &mut self,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.read_list_jobs_at_revision(self.scope().mission_revision())
    }

    pub fn read_bounded(
        &mut self,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.read()
    }

    pub fn read_list_jobs_at_revision(
        &mut self,
        expected_mission_revision: Revision,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        if expected_mission_revision != self.scope().mission_revision() {
            return Ok(self.stale_evidence(CloudSchedulerOperation::List));
        }
        let mut jobs = Vec::new();
        let mut request_receipts = Vec::new();
        let mut response_receipts = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut seen_jobs = BTreeMap::new();
        let mut cursor = None;
        let mut final_state = EvidenceState::Complete;
        let mut next_page_token_digest = None;
        let mut failure_digest = None;
        let mut duplicate_job_count: u16 = 0;
        for _ in 0..self.bounds.max_pages {
            let request = CloudSchedulerReadRequest::list(
                self.scope(),
                self.registration.provider_digest.clone(),
                self.registration.registration_digest.clone(),
                self.bounds.page_size,
                cursor.clone(),
                self.secret_reference(),
            )?;
            request_receipts.push(Self::request_receipt(&request));
            let record = match self.provider.list(&request) {
                Ok(record) => record,
                Err(error) => {
                    final_state = if jobs.is_empty() {
                        error.evidence_state()
                    } else {
                        EvidenceState::Partial
                    };
                    failure_digest = Some(error.diagnostic_digest());
                    break;
                }
            };
            if !record.verify_integrity() {
                final_state = EvidenceState::ProviderUnknown;
                failure_digest = Some(Digest::from_text("record-integrity-failure"));
                break;
            }
            response_receipts.push(record.response.clone());
            for job in record.jobs {
                if let Some(previous_digest) = seen_jobs.insert(job.job_id.clone(), job.digest()) {
                    duplicate_job_count = duplicate_job_count.saturating_add(1);
                    if previous_digest != job.digest() {
                        final_state = EvidenceState::Stale;
                        failure_digest = Some(Digest::from_text("job-revision-drift"));
                        break;
                    }
                    continue;
                }
                jobs.push(job);
            }
            if final_state == EvidenceState::Stale {
                break;
            }
            if jobs.len() >= usize::from(self.bounds.max_jobs) {
                jobs.truncate(usize::from(self.bounds.max_jobs));
                final_state = EvidenceState::Partial;
                next_page_token_digest =
                    record.next_page_token.as_ref().map(OpaquePageToken::digest);
                break;
            }
            let Some(next_page_token) = record.next_page_token else {
                next_page_token_digest = None;
                break;
            };
            let token_digest = next_page_token.digest();
            next_page_token_digest = Some(token_digest.clone());
            if !seen_tokens.insert(token_digest) {
                final_state = EvidenceState::Partial;
                failure_digest = Some(Digest::from_text("pagination-loop"));
                break;
            }
            cursor = Some(next_page_token);
        }
        if final_state == EvidenceState::Complete
            && cursor.is_some()
            && response_receipts.len() >= usize::from(self.bounds.max_pages)
        {
            final_state = EvidenceState::Partial;
        }
        if final_state == EvidenceState::Complete {
            final_state = Self::evaluate_jobs(&jobs);
        }
        Ok(self.evidence(
            CloudSchedulerOperation::List,
            final_state,
            jobs,
            request_receipts,
            response_receipts,
            next_page_token_digest,
            failure_digest,
            duplicate_job_count,
        ))
    }

    pub fn read_get_job(
        &mut self,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.read_get_job_at_revision(self.scope().mission_revision())
    }

    pub fn read_get_bounded(
        &mut self,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.read_get_job()
    }

    pub fn read_get_job_at_revision(
        &mut self,
        expected_mission_revision: Revision,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        self.validate_active()?;
        if expected_mission_revision != self.scope().mission_revision() {
            return Ok(self.stale_evidence(CloudSchedulerOperation::Get));
        }
        let request = CloudSchedulerReadRequest::get(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
            self.secret_reference(),
        )?;
        let request_receipt = Self::request_receipt(&request);
        match self.provider.get(&request) {
            Ok(record) => {
                if !record.verify_integrity() {
                    return Ok(self.evidence(
                        CloudSchedulerOperation::Get,
                        EvidenceState::ProviderUnknown,
                        Vec::new(),
                        vec![request_receipt],
                        vec![record.response],
                        None,
                        Some(Digest::from_text("record-integrity-failure")),
                        0,
                    ));
                }
                let state = Self::evaluate_jobs(&record.jobs);
                Ok(self.evidence(
                    CloudSchedulerOperation::Get,
                    state,
                    record.jobs,
                    vec![request_receipt],
                    vec![record.response],
                    None,
                    None,
                    0,
                ))
            }
            Err(error) => Ok(self.evidence(
                CloudSchedulerOperation::Get,
                error.evidence_state(),
                Vec::new(),
                vec![request_receipt],
                Vec::new(),
                None,
                Some(error.diagnostic_digest()),
                0,
            )),
        }
    }

    pub fn read(
        &mut self,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        if self.scope().job_id().is_some() {
            self.read_get_job()
        } else {
            self.read_list_jobs()
        }
    }

    pub fn read_at_mission_revision(
        &mut self,
        expected_mission_revision: u64,
    ) -> Result<GcpCloudSchedulerEvidence, GcpCloudSchedulerResultServiceError> {
        let expected = Revision::new(expected_mission_revision)?;
        if self.scope().job_id().is_some() {
            self.read_get_job_at_revision(expected)
        } else {
            self.read_list_jobs_at_revision(expected)
        }
    }

    fn evaluate_jobs(jobs: &[SchedulerJobSummary]) -> EvidenceState {
        if jobs.iter().any(|job| !job.verify_digest()) {
            EvidenceState::ProviderUnknown
        } else if jobs
            .iter()
            .any(|job| matches!(job.state, crate::SchedulerJobState::Unknown))
        {
            EvidenceState::Partial
        } else {
            EvidenceState::Complete
        }
    }

    fn evidence(
        &self,
        operation: CloudSchedulerOperation,
        state: EvidenceState,
        jobs: Vec<SchedulerJobSummary>,
        request_receipts: Vec<CloudSchedulerRequestReceipt>,
        response_receipts: Vec<crate::CloudSchedulerResponseReceipt>,
        next_page_token_digest: Option<Digest>,
        failure_digest: Option<Digest>,
        duplicate_job_count: u16,
    ) -> GcpCloudSchedulerEvidence {
        GcpCloudSchedulerEvidence::new(
            operation,
            state,
            jobs,
            request_receipts,
            response_receipts,
            next_page_token_digest,
            failure_digest,
            self.registration.registration_digest.clone(),
            self.registration.provider_digest.clone(),
            self.registration.provider_revision.clone(),
            self.scope(),
            self.secret_reference().reference_digest().clone(),
            duplicate_job_count,
        )
    }

    fn request_receipt(request: &CloudSchedulerReadRequest) -> CloudSchedulerRequestReceipt {
        CloudSchedulerRequestReceipt {
            operation: request.operation,
            method: request.method.clone(),
            path: request.path.clone(),
            project_digest: request.project_id.digest(),
            location_digest: request.location.digest(),
            job_digest: request.job_id.as_ref().map(Digest::from_serializable),
            schedule_digest: request.schedule_digest.clone(),
            target_digest: request.target_digest.clone(),
            page_token_digest: request.page_token_digest(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            request_digest: request.request_digest.clone(),
        }
    }

    fn stale_evidence(&self, operation: CloudSchedulerOperation) -> GcpCloudSchedulerEvidence {
        self.evidence(
            operation,
            EvidenceState::Stale,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            Some(Digest::from_text("mission-revision-fence")),
            0,
        )
    }
}

pub type GcpCloudSchedulerService<T> = GcpCloudSchedulerResultService<T>;
pub type GcpCloudSchedulerResultServiceErrorAlias = GcpCloudSchedulerResultServiceError;
pub type GcpCloudSchedulerRegistrationContract = GcpCloudSchedulerRegistration;

#[must_use]
pub fn plugin_version_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT)
}

#[must_use]
pub fn evidence_policy_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_SCHEDULER_EVIDENCE_POLICY)
}

#[must_use]
pub fn provider_version_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT)
}

#[must_use]
pub fn api_version_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_SCHEDULER_API_REVISION)
}

#[must_use]
pub fn service_id() -> &'static str {
    GCP_CLOUD_SCHEDULER_SERVICE_ID
}

#[must_use]
pub fn provider_id() -> &'static str {
    GCP_CLOUD_SCHEDULER_PROVIDER_ID
}

#[must_use]
pub fn consumer_id() -> &'static str {
    MISSION_GCP_CLOUD_SCHEDULER_CONSUMER_ID
}
