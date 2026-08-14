//! Bounded AWS RDS health read, proposal, recording and verification service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
    model::{
        AwsRdsHealthEvidence, AwsRdsHealthScope, AwsRdsHealthState, AwsRdsReadOperation,
        AwsRdsReadPageBody, AwsRdsReadRequest, DeploymentProjection, Digest, EndpointPresence,
        EvidenceDigests, MissionProjection, ModelError, PartialReason, PermissionAction,
        PermissionFence, ProjectProjection, ProviderErrorEvidence, RdsDatabaseObservation,
        RdsDatabaseProjection, RdsEventSeverity, RdsEventSummary, RdsMaintenanceSummary,
        RdsTargetKind, Revision, SecretReference, WorkProductProjection, deployment_projection,
        mission_projection, project_projection, work_product_projection,
    },
    provider::{
        AwsRdsProvider, AwsRdsProviderDefinition, AwsRdsProviderError, AwsRdsTransport,
        AwsRdsTransportError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("AWS RDS registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS RDS registration is already in the requested terminal state")]
    AlreadyTransitioned,
    #[error("AWS RDS registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsRdsServiceError {
    #[error("AWS RDS service model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS RDS provider error: {0}")]
    Provider(#[from] AwsRdsProviderError),
    #[error("AWS RDS registration is revoked, reversed, or inactive")]
    RegistrationRevoked,
    #[error("AWS RDS registration drifted: {0}")]
    RegistrationDrift(String),
    #[error("AWS RDS scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("AWS RDS evidence is stale or tampered")]
    EvidenceTampered,
    #[error("AWS RDS proposal is stale or tampered")]
    ProposalTampered,
    #[error("AWS RDS record is stale or tampered")]
    RecordTampered,
    #[error("AWS RDS idempotency key conflicts with an existing record")]
    RecordingConflict,
    #[error("AWS RDS registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsHealthServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl Default for AwsRdsHealthServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_digest: contract_digest(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "register".to_owned(),
                "read_bounded".to_owned(),
                "propose".to_owned(),
                "record".to_owned(),
                "verify".to_owned(),
                "revoke_registration".to_owned(),
                "reverse_registration".to_owned(),
                "restore_registration".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

impl AwsRdsHealthServiceDefinition {
    pub fn validate(&self) -> Result<(), AwsRdsServiceError> {
        let expected = Self::default();
        if self != &expected {
            return Err(AwsRdsServiceError::ScopeMismatch(
                "service definition drift".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsHealthCapabilities {
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
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl Default for AwsRdsHealthCapabilities {
    fn default() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                AwsRdsReadOperation::DescribeDbInstances
                    .api_name()
                    .to_owned(),
                AwsRdsReadOperation::DescribeDbClusters
                    .api_name()
                    .to_owned(),
                AwsRdsReadOperation::DescribeEvents.api_name().to_owned(),
                AwsRdsReadOperation::DescribePendingMaintenanceActions
                    .api_name()
                    .to_owned(),
            ],
            permissions: [
                PermissionAction::DescribeDbInstances,
                PermissionAction::DescribeDbClusters,
                PermissionAction::DescribeEvents,
                PermissionAction::DescribePendingMaintenanceActions,
                PermissionAction::MissionScope,
            ]
            .into_iter()
            .map(|permission| permission.as_str().to_owned())
            .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a str,
    provider_revision: &'a str,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    state: RegistrationState,
}

impl AwsRdsRegistration {
    pub fn new(
        scope: &AwsRdsHealthScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsRdsProviderDefinition,
    ) -> Result<Self, RegistrationError> {
        scope.validate()?;
        provider.validate().map_err(|_| {
            RegistrationError::Model(ModelError::Invalid {
                field: "provider definition",
            })
        })?;
        if permission.digest() != scope.permission_digest
            || !permission.is_layer_one_complete()
            || secret_reference.signing_region() != &scope.region
        {
            return Err(RegistrationError::Model(ModelError::ScopeMismatch {
                field: "permission or secret region",
            }));
        }
        let evidence_digest = Digest::from_parts(
            "aws-rds-evidence-policy/v1",
            &[
                ("contract", contract_digest().to_string()),
                ("max_pages", crate::MAX_PAGES.to_string()),
                ("max_page_size", crate::MAX_PAGE_SIZE.to_string()),
                ("max_events", crate::MAX_EVENTS.to_string()),
                (
                    "max_maintenance",
                    crate::MAX_MAINTENANCE_ACTIONS.to_string(),
                ),
                ("max_response_bytes", crate::MAX_RESPONSE_BYTES.to_string()),
                ("raw_endpoint", "false".to_owned()),
                ("raw_event_text", "false".to_owned()),
            ],
        );
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission.digest(),
            scope_digest: scope.digest(),
            evidence_digest,
            secret_reference_digest: secret_reference.digest().clone(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(
            &RegistrationBody {
                plugin_version: &self.plugin_version,
                contract_version: &self.contract_version,
                contract_digest: &self.contract_digest,
                provider_id: &self.provider_id,
                provider_version: &self.provider_version,
                provider_revision: &self.provider_revision,
                provider_digest: &self.provider_digest,
                api_digest: &self.api_digest,
                permission_digest: &self.permission_digest,
                scope_digest: &self.scope_digest,
                evidence_digest: &self.evidence_digest,
                secret_reference_digest: &self.secret_reference_digest,
                registration_revision: self.registration_revision,
                state: self.state,
            },
            "aws-rds-registration/v1",
        )
    }

    pub fn validate(
        &self,
        scope: &AwsRdsHealthScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsRdsProviderDefinition,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != permission.digest()
            || self.permission_digest != scope.permission_digest
            || self.scope_digest != scope.digest()
            || self.evidence_digest.is_zero()
            || self.secret_reference_digest != *secret_reference.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::Model(ModelError::ScopeMismatch {
                field: "registration digest binding",
            }));
        }
        Ok(())
    }

    fn transition(
        &mut self,
        next_state: RegistrationState,
    ) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if self.state == next_state {
            return Err(RegistrationError::AlreadyTransitioned);
        }
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        let previous = self.state;
        self.registration_revision = Revision::new(next)?;
        self.state = next_state;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence {
            from: previous,
            to: next_state,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            reversible: true,
            revocable: true,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        self.transition(RegistrationState::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationState,
    pub to: RegistrationState,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsHealthReadResult {
    pub evidence: AwsRdsHealthEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsHealthProposal {
    pub deployment: DeploymentProjection,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AwsRdsHealthState,
    pub evidence: AwsRdsHealthEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    deployment: &'a DeploymentProjection,
    mission: &'a MissionProjection,
    project: &'a ProjectProjection,
    work_product: &'a WorkProductProjection,
    state: AwsRdsHealthState,
    evidence: &'a AwsRdsHealthEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    proposal_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    outcome_adopted: bool,
    work_product_adopted: bool,
}

impl AwsRdsHealthProposal {
    fn new(
        scope: &AwsRdsHealthScope,
        evidence: AwsRdsHealthEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            deployment: deployment_projection(&scope.deployment),
            mission: mission_projection(&scope.mission),
            project: project_projection(&scope.project),
            work_product: work_product_projection(&scope.work_product),
            state: evidence.state,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(
            &ProposalBody {
                deployment: &self.deployment,
                mission: &self.mission,
                project: &self.project,
                work_product: &self.work_product,
                state: self.state,
                evidence: &self.evidence,
                proposed_at: &self.proposed_at,
                registration_digest: &self.registration_digest,
                read_only: self.read_only,
                proposal_only: self.proposal_only,
                live_execution: self.live_execution,
                connected: self.connected,
                native: self.native,
                first_party: self.first_party,
                outcome_adopted: self.outcome_adopted,
                work_product_adopted: self.work_product_adopted,
            },
            "aws-rds-health-proposal/v1",
        )
    }

    pub fn validate(&self, scope: &AwsRdsHealthScope) -> Result<(), AwsRdsServiceError> {
        self.evidence
            .validate(scope)
            .map_err(|_| AwsRdsServiceError::EvidenceTampered)?;
        if self.state != self.evidence.state
            || self.deployment.id_digest != scope.deployment.id.digest()
            || self.deployment.revision != scope.deployment.revision
            || self.mission.id_digest != scope.mission.id.digest()
            || self.mission.revision != scope.mission.revision
            || self.project.id_digest != scope.project.id.digest()
            || self.project.revision != scope.project.revision
            || self.work_product.id_digest != scope.work_product.id.digest()
            || self.work_product.revision != scope.work_product.revision
            || !self.read_only
            || !self.proposal_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsRdsServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: AwsRdsHealthState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    state: AwsRdsHealthState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsRdsRecordReceipt {
    fn new(proposal: &AwsRdsHealthProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digests.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(
            &RecordBody {
                recorded: self.recorded,
                recorded_at: &self.recorded_at,
                state: self.state,
                proposal_digest: &self.proposal_digest,
                evidence_digest: &self.evidence_digest,
                registration_digest: &self.registration_digest,
                scope_digest: &self.scope_digest,
                durable_receipt: self.durable_receipt,
                connected: self.connected,
                native: self.native,
                first_party: self.first_party,
            },
            "aws-rds-record-receipt/v1",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsVerifiedRecord {
    pub verified: bool,
    pub state: AwsRdsHealthState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    EvidenceTampered,
    ProposalTampered,
    PartialEvidence,
    AccessLoss,
    Throttled,
    TimedOut,
    ProviderUnknown,
    RevisionDrift,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_complete: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn is_review_complete(&self) -> bool {
        self.review_complete
    }
}

#[derive(Clone)]
pub struct AwsRdsHealthService<T>
where
    T: AwsRdsTransport,
{
    scope: AwsRdsHealthScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsRdsProvider<T>,
    registration: AwsRdsRegistration,
    definition: AwsRdsHealthServiceDefinition,
}

impl<T> fmt::Debug for AwsRdsHealthService<T>
where
    T: AwsRdsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRdsHealthService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsRdsHealthService<T>
where
    T: AwsRdsTransport,
{
    pub fn register(
        scope: AwsRdsHealthScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsRdsProvider<T>,
    ) -> Result<Self, AwsRdsServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsRdsHealthScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsRdsProvider<T>,
    ) -> Result<Self, AwsRdsServiceError> {
        scope.validate()?;
        if permission.digest() != scope.permission_digest || !permission.is_layer_one_complete() {
            return Err(AwsRdsServiceError::ScopeMismatch(
                "permission fence".to_owned(),
            ));
        }
        if secret_reference.signing_region() != &scope.region {
            return Err(AwsRdsServiceError::ScopeMismatch(
                "SigV4 signing region".to_owned(),
            ));
        }
        provider
            .definition()
            .validate()
            .map_err(|_| AwsRdsServiceError::ScopeMismatch("provider definition".to_owned()))?;
        let registration = AwsRdsRegistration::new(
            &scope,
            &secret_reference,
            &permission,
            provider.definition(),
        )?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
            definition: AwsRdsHealthServiceDefinition::default(),
        })
    }

    pub fn describe_capabilities() -> AwsRdsHealthCapabilities {
        AwsRdsHealthCapabilities::default()
    }

    pub fn service_definition(&self) -> &AwsRdsHealthServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &AwsRdsHealthScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsRdsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsRdsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsRdsRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsRdsRegistration {
        &mut self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn request(
        &self,
        operation: AwsRdsReadOperation,
        page_size: u16,
        max_pages: u16,
    ) -> Result<AwsRdsReadRequest, AwsRdsServiceError> {
        self.ensure_active_and_bound()?;
        Ok(AwsRdsReadRequest::for_scope(
            &self.scope,
            operation,
            page_size,
            max_pages,
            None,
        )?)
    }

    pub fn default_request(&self) -> Result<AwsRdsReadRequest, AwsRdsServiceError> {
        let operation = match self.scope.target.kind() {
            RdsTargetKind::Instance => AwsRdsReadOperation::DescribeDbInstances,
            RdsTargetKind::Cluster => AwsRdsReadOperation::DescribeDbClusters,
        };
        self.request(operation, 20, crate::MAX_PAGES)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsRdsServiceError> {
        Ok(self.registration.revoke()?)
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsRdsServiceError> {
        Ok(self.registration.reverse()?)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsRdsServiceError> {
        Ok(self.registration.restore()?)
    }

    pub fn read(&mut self) -> Result<AwsRdsHealthReadResult, AwsRdsServiceError> {
        self.read_bounded(crate::MAX_PAGES)
    }

    pub fn read_bounded(
        &mut self,
        max_pages: u16,
    ) -> Result<AwsRdsHealthReadResult, AwsRdsServiceError> {
        if max_pages == 0 || max_pages > crate::MAX_PAGES {
            return Err(AwsRdsServiceError::Model(ModelError::Invalid {
                field: "RDS page budget",
            }));
        }
        self.ensure_active_and_bound()?;
        let database_operation = match self.scope.target.kind() {
            RdsTargetKind::Instance => AwsRdsReadOperation::DescribeDbInstances,
            RdsTargetKind::Cluster => AwsRdsReadOperation::DescribeDbClusters,
        };
        let database = self.collect_operation(database_operation, max_pages)?;
        let events = self.collect_operation(AwsRdsReadOperation::DescribeEvents, max_pages)?;
        let maintenance = self.collect_operation(
            AwsRdsReadOperation::DescribePendingMaintenanceActions,
            max_pages,
        )?;
        Ok(self.combine_collections(database, events, maintenance))
    }

    pub fn read_request(
        &mut self,
        request: AwsRdsReadRequest,
    ) -> Result<AwsRdsHealthReadResult, AwsRdsServiceError> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope, &self.permission)?;
        let collection = self.collect_request(request)?;
        let is_database = collection.operation.is_database();
        let is_events = collection.operation == AwsRdsReadOperation::DescribeEvents;
        let is_maintenance =
            collection.operation == AwsRdsReadOperation::DescribePendingMaintenanceActions;
        let empty = OperationCollection::complete_empty();
        Ok(self.combine_collections(
            if is_database {
                collection.clone()
            } else {
                empty.clone()
            },
            if is_events {
                collection.clone()
            } else {
                empty.clone()
            },
            if is_maintenance { collection } else { empty },
        ))
    }

    pub fn propose(
        &mut self,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsRdsHealthProposal, AwsRdsServiceError> {
        let read = self.read()?;
        Ok(AwsRdsHealthProposal::new(
            &self.scope,
            read.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn compile_proposal(
        &mut self,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsRdsHealthProposal, AwsRdsServiceError> {
        self.propose(proposed_at)
    }

    pub fn verify_evidence(
        &self,
        evidence: &AwsRdsHealthEvidence,
    ) -> Result<(), AwsRdsServiceError> {
        self.ensure_active_and_bound()?;
        evidence
            .validate(&self.scope)
            .map_err(|_| AwsRdsServiceError::EvidenceTampered)?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.evidence_digests.provider_digest
                != self.provider.definition().provider_digest
            || evidence.evidence_digests.api_digest != self.provider.definition().api_digest
            || evidence.evidence_digests.permission_digest != self.permission.digest()
        {
            return Err(AwsRdsServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsRdsHealthProposal,
    ) -> Result<(), AwsRdsServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate(&self.scope)?;
        if proposal.registration_digest != self.registration.registration_digest {
            return Err(AwsRdsServiceError::ProposalTampered);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn record(
        &self,
        proposal: &AwsRdsHealthProposal,
    ) -> Result<AwsRdsRecordReceipt, AwsRdsServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsRdsHealthProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsRdsRecordReceipt, AwsRdsServiceError> {
        self.verify_proposal(proposal)?;
        Ok(AwsRdsRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsRdsRecordReceipt,
    ) -> Result<AwsRdsVerifiedRecord, AwsRdsServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.receipt_digest != receipt.recomputed_digest()
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.durable_receipt
        {
            return Err(AwsRdsServiceError::RecordTampered);
        }
        Ok(AwsRdsVerifiedRecord {
            verified: true,
            state: receipt.state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest: Digest::from_parts(
                "aws-rds-verified-record/v1",
                &[
                    ("receipt", receipt.receipt_digest.to_string()),
                    (
                        "registration",
                        self.registration.registration_digest.to_string(),
                    ),
                    ("scope", self.scope.digest().to_string()),
                ],
            ),
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
        })
    }

    pub fn verify_proposal_report(&self, proposal: &AwsRdsHealthProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != self.registration.registration_digest {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.evidence_digests.provider_digest
            != self.provider.definition().provider_digest
        {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.evidence_digests.api_digest != self.provider.definition().api_digest {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.evidence.evidence_digests.permission_digest != self.permission.digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.scope_digest != self.scope.digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate(&self.scope).is_err() {
            failures.push(VerificationFailure::ProposalTampered);
        }
        if proposal.evidence.validate(&self.scope).is_err() {
            failures.push(VerificationFailure::EvidenceTampered);
        }
        match proposal.state {
            AwsRdsHealthState::Partial => failures.push(VerificationFailure::PartialEvidence),
            AwsRdsHealthState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            AwsRdsHealthState::Throttled => failures.push(VerificationFailure::Throttled),
            AwsRdsHealthState::TimedOut => failures.push(VerificationFailure::TimedOut),
            AwsRdsHealthState::ProviderUnknown | AwsRdsHealthState::NotFound => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            AwsRdsHealthState::Healthy
            | AwsRdsHealthState::Degraded
            | AwsRdsHealthState::Unavailable
            | AwsRdsHealthState::RegistrationRevoked => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport {
            valid,
            review_complete: valid && proposal.state.is_review_complete(),
            verification_digest: Digest::from_parts(
                "aws-rds-verification-report/v1",
                &[
                    ("proposal", proposal.proposal_digest.to_string()),
                    (
                        "failures",
                        failures
                            .iter()
                            .map(|failure| format!("{failure:?}"))
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                ],
            ),
            failures,
        }
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsRdsServiceError> {
        if !self.registration.is_active() {
            return Err(AwsRdsServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                &self.permission,
                self.provider.definition(),
            )
            .map_err(|error| AwsRdsServiceError::RegistrationDrift(error.to_string()))
    }

    fn collect_operation(
        &mut self,
        operation: AwsRdsReadOperation,
        max_pages: u16,
    ) -> Result<OperationCollection, AwsRdsServiceError> {
        let request = AwsRdsReadRequest::for_scope(
            &self.scope,
            operation,
            crate::MAX_PAGE_SIZE,
            max_pages,
            None,
        )?;
        self.collect_request(request)
    }

    fn collect_request(
        &mut self,
        request: AwsRdsReadRequest,
    ) -> Result<OperationCollection, AwsRdsServiceError> {
        request.validate_against(&self.scope, &self.permission)?;
        let operation = request.operation;
        let mut current_request = request;
        let mut collection = OperationCollection::empty_for(operation);
        let mut seen_cursors = BTreeSet::new();
        let mut response_bytes = 0_u64;
        loop {
            collection.request_count = collection.request_count.saturating_add(1);
            let page = match self.provider.read(&current_request) {
                Ok(page) => page,
                Err(AwsRdsProviderError::Transport(error)) => {
                    collection.provider_error = Some(error.evidence(operation));
                    collection.state = Some(state_from_transport(&error));
                    if matches!(error, AwsRdsTransportError::Partial) {
                        collection.partial_reason = Some(PartialReason::Truncated);
                    }
                    break;
                }
                Err(AwsRdsProviderError::PageBinding) => {
                    collection.provider_error = Some(ProviderErrorEvidence {
                        operation,
                        kind: crate::ProviderErrorKind::RequestMismatch,
                        status_code: None,
                        retry_after_seconds: None,
                        response_digest: None,
                    });
                    collection.state = Some(AwsRdsHealthState::Partial);
                    collection.partial_reason = Some(PartialReason::TargetMismatch);
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            if page.page_number != collection.page_count.saturating_add(1) {
                collection.state = Some(AwsRdsHealthState::Partial);
                collection.partial_reason = Some(PartialReason::CursorBindingMismatch);
                break;
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if response_bytes > current_request.max_response_bytes {
                collection.state = Some(AwsRdsHealthState::Partial);
                collection.partial_reason = Some(PartialReason::ResponseTooLarge);
                break;
            }
            collection.page_count = collection.page_count.saturating_add(1);
            collection.page_digests.push(page.page_digest.clone());
            let next_cursor = page.next_cursor.clone();
            match page.body {
                AwsRdsReadPageBody::Database(database) => {
                    if let Err(error) = database.validate_against(&self.scope) {
                        collection.state = Some(AwsRdsHealthState::Partial);
                        collection.partial_reason = Some(match error {
                            ModelError::RevisionMismatch { .. } => PartialReason::RevisionDrift,
                            _ => PartialReason::TargetMismatch,
                        });
                        break;
                    }
                    if let Some(existing) = &collection.database
                        && existing.observation_digest != database.observation_digest
                    {
                        collection.state = Some(AwsRdsHealthState::Partial);
                        collection.partial_reason = Some(PartialReason::RevisionDrift);
                        break;
                    }
                    collection.database = Some(database);
                }
                AwsRdsReadPageBody::Events(events) => {
                    if events.len() > crate::MAX_EVENTS.saturating_sub(collection.events.len()) {
                        collection.state = Some(AwsRdsHealthState::Partial);
                        collection.partial_reason = Some(PartialReason::EventRetentionGap);
                        break;
                    }
                    for event in events {
                        if event.validate_against(&self.scope.time_window).is_err() {
                            collection.state = Some(AwsRdsHealthState::Partial);
                            collection.partial_reason = Some(PartialReason::EventRetentionGap);
                            break;
                        }
                        collection.events.push(event);
                    }
                    if collection.partial_reason.is_some() {
                        break;
                    }
                }
                AwsRdsReadPageBody::Maintenance(maintenance) => {
                    if maintenance.len()
                        > crate::MAX_MAINTENANCE_ACTIONS
                            .saturating_sub(collection.maintenance.len())
                    {
                        collection.state = Some(AwsRdsHealthState::Partial);
                        collection.partial_reason = Some(PartialReason::Truncated);
                        break;
                    }
                    collection.maintenance.extend(maintenance);
                }
            }
            let Some(cursor) = next_cursor else {
                collection.complete = true;
                break;
            };
            collection
                .cursor_digests
                .push(cursor.token_digest().clone());
            if !seen_cursors.insert(cursor.token_digest().clone()) {
                collection.state = Some(AwsRdsHealthState::Partial);
                collection.partial_reason = Some(PartialReason::CursorReplay);
                break;
            }
            if collection.page_count >= current_request.max_pages {
                collection.state = Some(AwsRdsHealthState::Partial);
                collection.partial_reason = Some(PartialReason::PageBudget);
                break;
            }
            current_request = current_request.with_cursor(Some(cursor))?;
        }
        Ok(collection)
    }

    fn combine_collections(
        &self,
        database: OperationCollection,
        events: OperationCollection,
        maintenance: OperationCollection,
    ) -> AwsRdsHealthReadResult {
        let collections = [&database, &events, &maintenance];
        let page_count = collections
            .iter()
            .map(|collection| collection.page_count)
            .sum();
        let request_count = collections
            .iter()
            .map(|collection| collection.request_count)
            .sum();
        let complete = collections.iter().all(|collection| collection.complete)
            && collections
                .iter()
                .all(|collection| collection.partial_reason.is_none())
            && collections
                .iter()
                .all(|collection| collection.provider_error.is_none());
        let partial_reason = collections
            .iter()
            .find_map(|collection| collection.partial_reason);
        let provider_errors = collections
            .iter()
            .filter_map(|collection| collection.provider_error.clone())
            .collect::<Vec<_>>();
        let state = collections
            .iter()
            .find_map(|collection| collection.state)
            .unwrap_or_else(|| {
                health_state(
                    database.database.as_ref(),
                    &maintenance.maintenance,
                    &events.events,
                    complete,
                )
            });
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        for collection in collections {
            page_digests.extend(collection.page_digests.clone());
            cursor_digests.extend(collection.cursor_digests.clone());
        }
        let evidence = AwsRdsHealthEvidence::new(
            state,
            &self.scope,
            self.registration.registration_digest.clone(),
            self.provider.definition().provider_digest.clone(),
            self.provider.definition().api_digest.clone(),
            database
                .database
                .map(|value| RdsDatabaseProjection::from(&value)),
            maintenance.maintenance,
            events.events,
            page_count,
            request_count,
            complete,
            partial_reason,
            provider_errors,
            page_digests.clone(),
            cursor_digests,
            self.provider.provenance(),
        );
        AwsRdsHealthReadResult {
            evidence,
            page_digests,
        }
    }
}

#[derive(Clone, Debug)]
struct OperationCollection {
    operation: AwsRdsReadOperation,
    database: Option<RdsDatabaseObservation>,
    events: Vec<RdsEventSummary>,
    maintenance: Vec<RdsMaintenanceSummary>,
    page_count: u16,
    request_count: u16,
    page_digests: Vec<Digest>,
    cursor_digests: Vec<Digest>,
    complete: bool,
    partial_reason: Option<PartialReason>,
    state: Option<AwsRdsHealthState>,
    provider_error: Option<ProviderErrorEvidence>,
}

impl OperationCollection {
    fn empty() -> Self {
        Self::empty_for(AwsRdsReadOperation::DescribeEvents)
    }

    fn complete_empty() -> Self {
        let mut collection = Self::empty();
        collection.complete = true;
        collection
    }

    fn empty_for(operation: AwsRdsReadOperation) -> Self {
        Self {
            operation,
            database: None,
            events: Vec::new(),
            maintenance: Vec::new(),
            page_count: 0,
            request_count: 0,
            page_digests: Vec::new(),
            cursor_digests: Vec::new(),
            complete: false,
            partial_reason: None,
            state: None,
            provider_error: None,
        }
    }
}

fn state_from_transport(error: &AwsRdsTransportError) -> AwsRdsHealthState {
    match error {
        AwsRdsTransportError::Unauthorized | AwsRdsTransportError::Forbidden => {
            AwsRdsHealthState::AccessLoss
        }
        AwsRdsTransportError::NotFound => AwsRdsHealthState::NotFound,
        AwsRdsTransportError::RateLimited { .. } => AwsRdsHealthState::Throttled,
        AwsRdsTransportError::Timeout => AwsRdsHealthState::TimedOut,
        AwsRdsTransportError::Partial
        | AwsRdsTransportError::Conflict
        | AwsRdsTransportError::RequestMismatch => AwsRdsHealthState::Partial,
        AwsRdsTransportError::BlockedEnvironment
        | AwsRdsTransportError::InvalidRequest
        | AwsRdsTransportError::ServerFailure { .. }
        | AwsRdsTransportError::MalformedResponse { .. }
        | AwsRdsTransportError::FixtureExhausted => AwsRdsHealthState::ProviderUnknown,
    }
}

fn health_state(
    database: Option<&RdsDatabaseObservation>,
    maintenance: &[RdsMaintenanceSummary],
    events: &[RdsEventSummary],
    complete: bool,
) -> AwsRdsHealthState {
    if !complete {
        return AwsRdsHealthState::Partial;
    }
    let Some(database) = database else {
        return AwsRdsHealthState::NotFound;
    };
    if database.status.is_terminal_failure()
        || database.endpoint_presence == EndpointPresence::Absent
    {
        return AwsRdsHealthState::Unavailable;
    }
    if !database.status.is_available()
        || maintenance.iter().any(|item| item.status.is_pending())
        || events
            .iter()
            .any(|event| event.severity == RdsEventSeverity::Critical)
    {
        return AwsRdsHealthState::Degraded;
    }
    AwsRdsHealthState::Healthy
}

pub type AwsRdsService<T> = AwsRdsHealthService<T>;
pub type AwsRdsHealthRegistration = AwsRdsRegistration;
pub type AwsRdsHealthServiceError = AwsRdsServiceError;
pub type AwsRdsProviderRevision = String;
pub type AwsRdsHealthEvidenceDigests = EvidenceDigests;
