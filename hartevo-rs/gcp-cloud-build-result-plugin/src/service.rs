//! Service, registration, proposal, bounded-read, and recording seams.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    CloudBuildObservationRecord, CloudBuildOperation, CloudBuildRequestReceipt, CloudBuildSummary,
    Digest, EvidenceState, GcpCloudBuildEvidence, GcpCloudBuildScope, MAX_BUILDS, MAX_PAGE_SIZE,
    MAX_PAGES, ModelError, PermissionAction, Revision, SecretReference, TransportProvenance,
};
use crate::provider::{
    CloudBuildReadProposal, CloudBuildReadRecord, CloudBuildReadRequest, GcpCloudBuildProvider,
    GcpCloudBuildProviderDefinition, GcpCloudBuildProviderError, GcpCloudBuildTransport,
    OpaquePageToken, ProviderDefinitionError,
};
use crate::{
    GCP_CLOUD_BUILD_CONTRACT_VERSION, GCP_CLOUD_BUILD_PLUGIN_VERSION_TEXT,
    GCP_CLOUD_BUILD_PROVIDER_ID, GCP_CLOUD_BUILD_PROVIDER_VERSION_TEXT,
    GCP_CLOUD_BUILD_SCHEMA_VERSION, GCP_CLOUD_BUILD_SERVICE_ID, GCP_CLOUD_BUILD_SERVICE_NAME,
    MISSION_GCP_BUILD_CONSUMER_ID, contract_digest, plugin_version_digest,
};

pub const GCP_CLOUD_BUILD_SERVICE_VERSION: &str = "1.0.0";
pub const GCP_CLOUD_BUILD_SERVICE_SCHEMA: &str = "hartevo.gcp-cloud-build-result-service/v1";
pub const GCP_CLOUD_BUILD_EVIDENCE_POLICY: &str =
    "cloud-build-v1-status-source-duration-artifact-step-digests";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpCloudBuildResultOperation {
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

impl GcpCloudBuildResultOperation {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        !matches!(
            self,
            Self::Register | Self::RevokeRegistration | Self::RestoreRegistration
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudBuildCapability {
    pub operation: GcpCloudBuildResultOperation,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudBuildResultServiceDefinition {
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
    pub capabilities: Vec<GcpCloudBuildCapability>,
}

impl Default for GcpCloudBuildResultServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpCloudBuildResultServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        let operations = [
            GcpCloudBuildResultOperation::DescribeCapabilities,
            GcpCloudBuildResultOperation::Register,
            GcpCloudBuildResultOperation::RevokeRegistration,
            GcpCloudBuildResultOperation::RestoreRegistration,
            GcpCloudBuildResultOperation::ProposeList,
            GcpCloudBuildResultOperation::ProposeGet,
            GcpCloudBuildResultOperation::ReadList,
            GcpCloudBuildResultOperation::ReadGet,
            GcpCloudBuildResultOperation::RecordObservation,
            GcpCloudBuildResultOperation::VerifyProposal,
            GcpCloudBuildResultOperation::VerifyObservation,
            GcpCloudBuildResultOperation::ConsumeMissionProjection,
        ];
        Self {
            service_id: GCP_CLOUD_BUILD_SERVICE_ID.to_owned(),
            service_name: GCP_CLOUD_BUILD_SERVICE_NAME.to_owned(),
            service_version: GCP_CLOUD_BUILD_SERVICE_VERSION.to_owned(),
            schema_version: GCP_CLOUD_BUILD_SERVICE_SCHEMA.to_owned(),
            contract_version: GCP_CLOUD_BUILD_CONTRACT_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            external_writes: false,
            capabilities: operations
                .into_iter()
                .map(|operation| GcpCloudBuildCapability {
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
    pub fn describe_capabilities(&self) -> Vec<GcpCloudBuildCapability> {
        self.capabilities.clone()
    }

    pub fn validate(&self) -> Result<(), GcpCloudBuildResultServiceError> {
        if self.service_id != GCP_CLOUD_BUILD_SERVICE_ID
            || self.service_name != GCP_CLOUD_BUILD_SERVICE_NAME
            || self.service_version != GCP_CLOUD_BUILD_SERVICE_VERSION
            || self.schema_version != GCP_CLOUD_BUILD_SERVICE_SCHEMA
            || self.contract_version != GCP_CLOUD_BUILD_CONTRACT_VERSION
            || !self.read_only
            || !self.proposal_only
            || self.native
            || self.connected
            || self.external_writes
            || self.capabilities.iter().any(|capability| {
                capability.native || capability.connected || capability.external_write
            })
        {
            return Err(GcpCloudBuildResultServiceError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

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
pub struct GcpCloudBuildRegistration {
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
    pub source_digest: Digest,
    pub trigger_digest: Option<Digest>,
    pub evidence_policy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GcpCloudBuildRegistration {
    pub fn new(
        scope: &GcpCloudBuildScope,
        secret_reference: &SecretReference,
        provider_definition: &GcpCloudBuildProviderDefinition,
    ) -> Result<Self, GcpCloudBuildResultServiceError> {
        scope.validate()?;
        provider_definition.validate()?;
        if secret_reference.is_revoked()
            || secret_reference
                .scope_digest()
                .is_some_and(|digest| digest != &scope.scope_digest())
        {
            return Err(GcpCloudBuildResultServiceError::ScopeMismatch);
        }
        let mut registration = Self {
            schema_version: GCP_CLOUD_BUILD_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_CLOUD_BUILD_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_CLOUD_BUILD_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest: plugin_version_digest(),
            contract_digest: contract_digest(),
            provider_id: provider_definition.provider_id.clone(),
            provider_version: provider_definition.provider_version.clone(),
            provider_revision: provider_definition.provider_revision.clone(),
            provider_digest: provider_definition.provider_digest(),
            api_digest: Digest::from_text(crate::provider::GCP_CLOUD_BUILD_API_REVISION),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            source_digest: scope.source_digest(),
            trigger_digest: scope.trigger_digest(),
            evidence_policy_digest: Digest::from_text(GCP_CLOUD_BUILD_EVIDENCE_POLICY),
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
        struct RegistrationDigestInput<'a> {
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
            source_digest: &'a Digest,
            trigger_digest: &'a Option<Digest>,
            evidence_policy_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
            credential_revision: Revision,
            registration_revision: Revision,
            state: RegistrationState,
        }
        Digest::from_serializable(&RegistrationDigestInput {
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
            source_digest: &self.source_digest,
            trigger_digest: &self.trigger_digest,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_builds: u16,
}

impl ReadBounds {
    pub fn new(max_pages: u16, page_size: u16, max_builds: u16) -> Result<Self, ModelError> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::OutsideBound { field: "max pages" });
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::OutsideBound { field: "page size" });
        }
        if max_builds == 0 || usize::from(max_builds) > MAX_BUILDS {
            return Err(ModelError::OutsideBound {
                field: "max builds",
            });
        }
        Ok(Self {
            max_pages,
            page_size,
            max_builds,
        })
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_builds: MAX_BUILDS as u16,
        }
    }
}

pub type GcpCloudBuildResultBounds = ReadBounds;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpCloudBuildResultServiceError {
    #[error("Cloud Build service contract drifted")]
    ContractDrift,
    #[error("Cloud Build registration is revoked or invalid")]
    RegistrationRevoked,
    #[error("Cloud Build secret reference is revoked")]
    SecretRevoked,
    #[error("Cloud Build scope mismatch")]
    ScopeMismatch,
    #[error("Cloud Build permission scope mismatch")]
    PermissionMismatch,
    #[error("Cloud Build proposal is tampered or stale")]
    ProposalTampered,
    #[error("Cloud Build provider record is tampered or stale")]
    RecordTampered,
    #[error("Cloud Build observation is tampered or stale")]
    ObservationTampered,
    #[error("Mission revision is stale: expected {expected}, actual {actual}")]
    StaleMissionRevision {
        expected: Revision,
        actual: Revision,
    },
    #[error("Cloud Build pagination loop detected")]
    PaginationLoop,
    #[error("unsupported Cloud Build operation")]
    UnsupportedOperation,
    #[error("Cloud Build model error: {0}")]
    Model(#[from] ModelError),
    #[error("Cloud Build provider definition error: {0}")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("Cloud Build provider error: {0}")]
    Provider(#[from] GcpCloudBuildProviderError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudBuildRead {
    pub evidence: GcpCloudBuildEvidence,
    pub observation: CloudBuildObservationRecord,
}

pub struct GcpCloudBuildResultService<T>
where
    T: GcpCloudBuildTransport,
{
    definition: GcpCloudBuildResultServiceDefinition,
    provider: GcpCloudBuildProvider<T>,
    registration: GcpCloudBuildRegistration,
    bounds: ReadBounds,
    observation_revision: Revision,
}

impl<T> fmt::Debug for GcpCloudBuildResultService<T>
where
    T: GcpCloudBuildTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudBuildResultService")
            .field("definition", &self.definition)
            .field("scope_digest", &self.provider.scope().scope_digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("provider_digest", &self.registration.provider_digest)
            .field("bounds", &self.bounds)
            .field("observation_revision", &self.observation_revision)
            .finish()
    }
}

impl<T> GcpCloudBuildResultService<T>
where
    T: GcpCloudBuildTransport,
{
    pub fn new(
        provider: GcpCloudBuildProvider<T>,
    ) -> Result<Self, GcpCloudBuildResultServiceError> {
        let definition = GcpCloudBuildResultServiceDefinition::new();
        definition.validate()?;
        let registration = GcpCloudBuildRegistration::new(
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
        provider: GcpCloudBuildProvider<T>,
        bounds: ReadBounds,
    ) -> Result<Self, GcpCloudBuildResultServiceError> {
        let mut service = Self::new(provider)?;
        service.bounds = bounds;
        Ok(service)
    }

    #[must_use]
    pub fn definition(&self) -> &GcpCloudBuildResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &GcpCloudBuildScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        self.provider.secret_reference()
    }

    #[must_use]
    pub fn provider(&self) -> &GcpCloudBuildProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GcpCloudBuildProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &GcpCloudBuildRegistration {
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

    pub fn register(&mut self) -> Result<(), GcpCloudBuildResultServiceError> {
        self.definition.validate()?;
        if self.registration.is_active() && self.registration.verify_digest() {
            Ok(())
        } else {
            self.registration
                .restore()
                .map_err(|_| GcpCloudBuildResultServiceError::RegistrationRevoked)
        }
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GcpCloudBuildResultServiceError> {
        self.registration
            .revoke()
            .map_err(|_| GcpCloudBuildResultServiceError::RegistrationRevoked)
    }

    pub fn restore_registration(&mut self) -> Result<(), GcpCloudBuildResultServiceError> {
        self.registration
            .restore()
            .map_err(|_| GcpCloudBuildResultServiceError::RegistrationRevoked)
    }

    pub fn revoke_secret_reference(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GcpCloudBuildResultServiceError> {
        self.provider
            .secret_reference_mut()
            .revoke()
            .map_err(|_| GcpCloudBuildResultServiceError::SecretRevoked)?;
        self.revoke_registration()
    }

    pub fn restore_secret_reference(&mut self) -> Result<(), GcpCloudBuildResultServiceError> {
        self.provider
            .secret_reference_mut()
            .restore()
            .map_err(|_| GcpCloudBuildResultServiceError::SecretRevoked)?;
        self.restore_registration()
    }

    fn validate_active(&self) -> Result<(), GcpCloudBuildResultServiceError> {
        self.definition.validate()?;
        self.scope().validate()?;
        if !self.registration.is_active() || !self.registration.verify_digest() {
            return Err(GcpCloudBuildResultServiceError::RegistrationRevoked);
        }
        if self.secret_reference().is_revoked() {
            return Err(GcpCloudBuildResultServiceError::SecretRevoked);
        }
        if self.registration.scope_digest != self.scope().scope_digest()
            || self.registration.permission_digest != self.scope().permission_digest()
            || self.registration.source_digest != self.scope().source_digest()
            || self.registration.trigger_digest != self.scope().trigger_digest()
        {
            return Err(GcpCloudBuildResultServiceError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn propose_list_builds(
        &self,
    ) -> Result<CloudBuildReadProposal, GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        let request = CloudBuildReadRequest::list(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
            self.bounds.page_size,
            None,
        )?;
        Ok(CloudBuildReadProposal::new(
            request,
            self.scope().mission_revision(),
        ))
    }

    pub fn propose_get_build(
        &self,
    ) -> Result<CloudBuildReadProposal, GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        let request = CloudBuildReadRequest::get(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
        )?;
        Ok(CloudBuildReadProposal::new(
            request,
            self.scope().mission_revision(),
        ))
    }

    pub fn compile_proposal(
        &self,
    ) -> Result<CloudBuildReadProposal, GcpCloudBuildResultServiceError> {
        if self.scope().build_id().is_some() {
            self.propose_get_build()
        } else {
            self.propose_list_builds()
        }
    }

    pub fn record_list_builds(
        &mut self,
    ) -> Result<CloudBuildReadRecord, GcpCloudBuildResultServiceError> {
        let proposal = self.propose_list_builds()?;
        let record = self.provider.list(proposal.request())?;
        self.verify_proposal(&proposal, &record)?;
        Ok(record)
    }

    pub fn record_get_build(
        &mut self,
    ) -> Result<CloudBuildReadRecord, GcpCloudBuildResultServiceError> {
        let proposal = self.propose_get_build()?;
        let record = self.provider.get(proposal.request())?;
        self.verify_proposal(&proposal, &record)?;
        Ok(record)
    }

    pub fn verify_proposal(
        &self,
        proposal: &CloudBuildReadProposal,
        record: &CloudBuildReadRecord,
    ) -> Result<(), GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        if !proposal.verify_digest()
            || !record.verify_integrity()
            || !proposal
                .request
                .verify_digest(&self.registration.provider_digest)
            || proposal.proposal_digest().is_empty()
            || proposal.registration_digest != self.registration.registration_digest
            || record.registration_digest != self.registration.registration_digest
            || proposal.request != record.request
            || proposal.request.scope_digest != self.scope().scope_digest()
            || proposal.request.permission_digest != self.scope().permission_digest()
        {
            return Err(GcpCloudBuildResultServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn record_observation(
        &mut self,
        evidence: &GcpCloudBuildEvidence,
    ) -> Result<CloudBuildObservationRecord, GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        if !evidence.verify_digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.scope_digest != self.scope().scope_digest()
            || evidence.permission_digest != self.scope().permission_digest()
        {
            return Err(GcpCloudBuildResultServiceError::ObservationTampered);
        }
        let observation = CloudBuildObservationRecord::new(evidence, self.observation_revision);
        self.observation_revision = self.observation_revision.next()?;
        Ok(observation)
    }

    pub fn verify_observation(
        &self,
        evidence: &GcpCloudBuildEvidence,
        observation: &CloudBuildObservationRecord,
    ) -> Result<(), GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        if !evidence.verify_digest()
            || !observation.verify_digest()
            || observation.evidence_digest != evidence.evidence_digest
            || observation.registration_digest != self.registration.registration_digest
        {
            return Err(GcpCloudBuildResultServiceError::ObservationTampered);
        }
        Ok(())
    }

    pub fn evidence_from_record(
        &self,
        record: &CloudBuildReadRecord,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        if !record.verify_integrity()
            || !record
                .request
                .verify_digest(&self.registration.provider_digest)
            || record.registration_digest != self.registration.registration_digest
            || record.request.scope_digest != self.scope().scope_digest()
            || record.request.permission_digest != self.scope().permission_digest()
        {
            return Err(GcpCloudBuildResultServiceError::RecordTampered);
        }
        let state = self.evaluate_builds(&record.builds);
        let request_receipt = Self::request_receipt(&record.request);
        Ok(GcpCloudBuildEvidence::new_with_provider_digest(
            record.operation,
            state,
            record.builds.clone(),
            vec![request_receipt],
            vec![record.response.clone()],
            record.next_page_token.as_ref().map(OpaquePageToken::digest),
            self.registration.registration_digest.clone(),
            self.registration.provider_digest.clone(),
            self.scope(),
        ))
    }

    pub fn read_list_builds(
        &mut self,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        self.read_list_builds_at_revision(self.scope().mission_revision())
    }

    pub fn read_bounded(
        &mut self,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        self.read_list_builds()
    }

    pub fn read_list_builds_at_revision(
        &mut self,
        expected_mission_revision: Revision,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        if expected_mission_revision != self.scope().mission_revision() {
            return Ok(self.stale_evidence(CloudBuildOperation::List));
        }
        let mut builds = Vec::new();
        let mut requests = Vec::new();
        let mut responses = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut cursor = None;
        let mut final_state = EvidenceState::Complete;
        let mut next_page_token_digest = None;
        for _ in 0..self.bounds.max_pages {
            let request = CloudBuildReadRequest::list(
                self.scope(),
                self.registration.provider_digest.clone(),
                self.registration.registration_digest.clone(),
                self.bounds.page_size,
                cursor.clone(),
            )?;
            requests.push(Self::request_receipt(&request));
            let record = match self.provider.list(&request) {
                Ok(record) => record,
                Err(error) => {
                    final_state = if builds.is_empty() {
                        error.evidence_state()
                    } else {
                        EvidenceState::Partial
                    };
                    break;
                }
            };
            if !record.verify_integrity() {
                final_state = EvidenceState::ProviderUnknown;
                break;
            }
            responses.push(record.response.clone());
            builds.extend(record.builds);
            if builds.len() >= usize::from(self.bounds.max_builds) {
                builds.truncate(usize::from(self.bounds.max_builds));
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
                break;
            }
            cursor = Some(next_page_token);
        }
        if final_state == EvidenceState::Complete
            && cursor.is_some()
            && responses.len() >= usize::from(self.bounds.max_pages)
        {
            final_state = EvidenceState::Partial;
        }
        if final_state == EvidenceState::Complete {
            final_state = self.evaluate_builds(&builds);
        }
        Ok(GcpCloudBuildEvidence::new_with_provider_digest(
            CloudBuildOperation::List,
            final_state,
            builds,
            requests,
            responses,
            next_page_token_digest,
            self.registration.registration_digest.clone(),
            self.registration.provider_digest.clone(),
            self.scope(),
        ))
    }

    pub fn read_get_build(
        &mut self,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        self.read_get_build_at_revision(self.scope().mission_revision())
    }

    pub fn read_get_bounded(
        &mut self,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        self.read_get_build()
    }

    pub fn read_get_build_at_revision(
        &mut self,
        expected_mission_revision: Revision,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        self.validate_active()?;
        if expected_mission_revision != self.scope().mission_revision() {
            return Ok(self.stale_evidence(CloudBuildOperation::Get));
        }
        let request = CloudBuildReadRequest::get(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
        )?;
        let request_receipt = Self::request_receipt(&request);
        match self.provider.get(&request) {
            Ok(record) => {
                if !record.verify_integrity() {
                    return Ok(GcpCloudBuildEvidence::new_with_provider_digest(
                        CloudBuildOperation::Get,
                        EvidenceState::ProviderUnknown,
                        Vec::new(),
                        vec![request_receipt],
                        vec![record.response],
                        None,
                        self.registration.registration_digest.clone(),
                        self.registration.provider_digest.clone(),
                        self.scope(),
                    ));
                }
                let state = self.evaluate_builds(&record.builds);
                Ok(GcpCloudBuildEvidence::new_with_provider_digest(
                    CloudBuildOperation::Get,
                    state,
                    record.builds,
                    vec![request_receipt],
                    vec![record.response],
                    None,
                    self.registration.registration_digest.clone(),
                    self.registration.provider_digest.clone(),
                    self.scope(),
                ))
            }
            Err(error) => Ok(GcpCloudBuildEvidence::new_with_provider_digest(
                CloudBuildOperation::Get,
                error.evidence_state(),
                Vec::new(),
                vec![request_receipt],
                Vec::new(),
                None,
                self.registration.registration_digest.clone(),
                self.registration.provider_digest.clone(),
                self.scope(),
            )),
        }
    }

    pub fn read(&mut self) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        if self.scope().build_id().is_some() {
            self.read_get_build()
        } else {
            self.read_list_builds()
        }
    }

    pub fn read_at_mission_revision(
        &mut self,
        expected_mission_revision: u64,
    ) -> Result<GcpCloudBuildEvidence, GcpCloudBuildResultServiceError> {
        let expected = Revision::new(expected_mission_revision)?;
        if self.scope().build_id().is_some() {
            self.read_get_build_at_revision(expected)
        } else {
            self.read_list_builds_at_revision(expected)
        }
    }

    fn request_receipt(request: &CloudBuildReadRequest) -> CloudBuildRequestReceipt {
        CloudBuildRequestReceipt {
            operation: request.operation,
            method: request.method.clone(),
            path: request.path.clone(),
            project_digest: request.project_id.digest(),
            location_digest: request.location.digest(),
            build_digest: request.build_id.as_ref().map(Digest::from_serializable),
            page_token_digest: request.page_token_digest(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            request_digest: request.request_digest.clone(),
        }
    }

    fn stale_evidence(&self, operation: CloudBuildOperation) -> GcpCloudBuildEvidence {
        GcpCloudBuildEvidence::new_with_provider_digest(
            operation,
            EvidenceState::Stale,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            self.registration.registration_digest.clone(),
            self.registration.provider_digest.clone(),
            self.scope(),
        )
    }

    fn evaluate_builds(&self, builds: &[CloudBuildSummary]) -> EvidenceState {
        if builds.iter().any(|build| !build.verify_digest()) {
            return EvidenceState::ProviderUnknown;
        }
        if builds.iter().any(|build| {
            build.project_id != self.scope().gcp_project
                || build.location != self.scope().location
                || self.scope().trigger.as_ref().is_some_and(|trigger| {
                    build
                        .trigger_id
                        .as_ref()
                        .is_some_and(|actual| actual != trigger)
                })
                || build.source_matches_scope(self.scope()) == Some(false)
        }) {
            return EvidenceState::Stale;
        }
        if builds.iter().any(|build| {
            build.source_matches_scope(self.scope()).is_none()
                || self
                    .scope()
                    .trigger
                    .as_ref()
                    .is_some_and(|_| build.trigger_id.is_none())
                || matches!(build.status, crate::CloudBuildStatus::Unknown)
        }) {
            return EvidenceState::Partial;
        }
        EvidenceState::Complete
    }
}

pub type GcpCloudBuildService<T> = GcpCloudBuildResultService<T>;
pub type GcpCloudBuildRegistrationContract = GcpCloudBuildRegistration;

#[must_use]
pub fn service_id() -> &'static str {
    GCP_CLOUD_BUILD_SERVICE_ID
}

#[must_use]
pub fn provider_id() -> &'static str {
    GCP_CLOUD_BUILD_PROVIDER_ID
}

#[must_use]
pub fn consumer_id() -> &'static str {
    MISSION_GCP_BUILD_CONSUMER_ID
}

#[must_use]
pub fn provider_version_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_BUILD_PROVIDER_VERSION_TEXT)
}

#[must_use]
pub fn evidence_policy_digest() -> Digest {
    Digest::from_text(GCP_CLOUD_BUILD_EVIDENCE_POLICY)
}

#[must_use]
pub fn permission_digest() -> Digest {
    Digest::from_serializable(&[PermissionAction::BuildsList, PermissionAction::BuildsGet])
}

#[must_use]
pub fn provider_provenance_is_layer1(provenance: TransportProvenance) -> bool {
    !provenance.is_native() && !provenance.is_connected() && !provenance.is_first_party()
}
