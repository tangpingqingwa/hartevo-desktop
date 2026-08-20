//! Layer-1 AWS Elastic Beanstalk deployment observation service.
//!
//! The service binds a Mission-scoped read fence to a provider definition,
//! performs only bounded reads, and emits a proposal/evidence pair. Recording
//! is an in-memory integrity receipt; it is not a durable provider receipt and
//! it never becomes kernel Outcome authority.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_ELASTIC_BEANSTALK_PROVIDER_ID, AWS_ELASTIC_BEANSTALK_PROVIDER_VERSION, contract_digest,
    model::{
        AwsElasticBeanstalkDeploymentScope, AwsElasticBeanstalkReadOperation, Digest,
        EnvironmentRevisionProjection, EventProjection, EvidenceDigests, ModelError,
        PermissionFence, ReadBounds, Registration, RegistrationRevocation, RegistrationState,
        ResourceProjection, SecretReference,
    },
    provider::{
        AwsElasticBeanstalkProvider, AwsElasticBeanstalkTransport,
        DescribeEnvironmentResourcesRequest, DescribeEnvironmentsRequest, DescribeEventsRequest,
        ProviderError,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElasticBeanstalkDeploymentCapabilities {
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub max_pages: u16,
    pub max_items: usize,
    pub max_page_size: u16,
    pub max_requests_per_read: u16,
}

impl AwsElasticBeanstalkDeploymentCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            read_only: true,
            proposal_only: true,
            live_execution: false,
            native: false,
            connected: false,
            external_writes: false,
            max_pages: crate::model::MAX_PAGES,
            max_items: crate::model::MAX_EVENTS,
            max_page_size: crate::model::MAX_PAGE_SIZE,
            max_requests_per_read: crate::model::MAX_REQUESTS_PER_READ,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("registration is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("registration is revoked")]
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsElasticBeanstalkDeploymentServiceError {
    #[error("service model is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("provider failed: {0}")]
    Provider(#[from] ProviderError),
    #[error("registration failed: {0}")]
    Registration(#[from] RegistrationError),
    #[error("permission fence does not cover all three bounded read operations")]
    PermissionLoss,
    #[error("SigV4 secret reference is not bound to this scope")]
    SecretReferenceMismatch,
    #[error("provider identity is not the contract-bound revision")]
    ProviderRevision,
    #[error("bounded pagination exceeded its limit or repeated a page token")]
    PaginationLimit,
    #[error("evidence is tampered, incomplete, or claims forbidden authority")]
    TamperedEvidence,
    #[error("service registration is revoked")]
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuthority {
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub certification_authority: bool,
    pub kernel_outcome_adoption: bool,
}

impl EvidenceAuthority {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native_provider: false,
            first_party: false,
            durable_provider_receipt: false,
            certification_authority: false,
            kernel_outcome_adoption: false,
        }
    }

    pub const fn is_forbidden_claim(&self) -> bool {
        self.connected
            || self.native_provider
            || self.first_party
            || self.durable_provider_receipt
            || self.certification_authority
            || self.kernel_outcome_adoption
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidencePageCounts {
    pub environments: u16,
    pub resources: u16,
    pub events: u16,
    pub requests: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsElasticBeanstalkDeploymentEvidence {
    pub mission: crate::model::MissionBinding,
    pub registration_digest: Digest,
    pub status: EvidenceStatus,
    pub digests: EvidenceDigests,
    pub page_counts: EvidencePageCounts,
    pub environments: Vec<EnvironmentRevisionProjection>,
    pub resources: Vec<ResourceProjection>,
    pub events: Vec<EventProjection>,
    pub authority: EvidenceAuthority,
}

impl AwsElasticBeanstalkDeploymentEvidence {
    #[allow(clippy::too_many_arguments)]
    fn complete(
        scope: &AwsElasticBeanstalkDeploymentScope,
        registration: &Registration,
        provider_digest: Digest,
        environments: Vec<EnvironmentRevisionProjection>,
        resources: Vec<ResourceProjection>,
        events: Vec<EventProjection>,
        page_counts: EvidencePageCounts,
    ) -> Result<Self, AwsElasticBeanstalkDeploymentServiceError> {
        if environments
            .iter()
            .any(|environment| environment.version_digest != *scope.version_digest())
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::TamperedEvidence);
        }
        let mut evidence = Self {
            mission: scope.mission.clone(),
            registration_digest: registration.registration_digest.clone(),
            status: EvidenceStatus::Complete,
            digests: EvidenceDigests {
                scope_digest: scope.scope_digest.clone(),
                version_digest: scope.version.version_digest.clone(),
                provider_digest,
                permission_digest: scope.permission_digest.clone(),
                evidence_digest: Digest::zero(),
            },
            page_counts,
            environments,
            resources,
            events,
            authority: EvidenceAuthority::layer_one(),
        };
        evidence.digests.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        digest_evidence_material(
            &self.mission,
            &self.registration_digest,
            self.status,
            &self.digests.scope_digest,
            &self.digests.version_digest,
            &self.digests.provider_digest,
            &self.digests.permission_digest,
            &self.page_counts,
            &self.environments,
            &self.resources,
            &self.events,
            &self.authority,
        )
    }

    pub fn verify(&self) -> Result<(), AwsElasticBeanstalkDeploymentServiceError> {
        if self.status != EvidenceStatus::Complete
            || self.authority.is_forbidden_claim()
            || self.digests.scope_digest == Digest::zero()
            || self.digests.version_digest == Digest::zero()
            || self.digests.provider_digest == Digest::zero()
            || self.digests.permission_digest == Digest::zero()
            || self.calculate_digest()? != self.digests.evidence_digest
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::TamperedEvidence);
        }
        for environment in &self.environments {
            environment.verify()?;
        }
        for resource in &self.resources {
            resource.verify()?;
        }
        for event in &self.events {
            event.verify()?;
        }
        Ok(())
    }
}

fn digest_evidence_material(
    mission: &crate::model::MissionBinding,
    registration_digest: &Digest,
    status: EvidenceStatus,
    scope_digest: &Digest,
    version_digest: &Digest,
    provider_digest: &Digest,
    permission_digest: &Digest,
    page_counts: &EvidencePageCounts,
    environments: &[EnvironmentRevisionProjection],
    resources: &[ResourceProjection],
    events: &[EventProjection],
    authority: &EvidenceAuthority,
) -> Result<Digest, ModelError> {
    crate::model::digest_serializable(&(
        mission,
        registration_digest,
        status,
        scope_digest,
        version_digest,
        provider_digest,
        permission_digest,
        page_counts,
        environments,
        resources,
        events,
        authority,
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsElasticBeanstalkDeploymentProposal {
    pub consumer_id: String,
    pub mission: crate::model::MissionBinding,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub evidence_digest: Digest,
    pub read_only: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub proposal_digest: Digest,
}

impl AwsElasticBeanstalkDeploymentProposal {
    fn new(
        scope: &AwsElasticBeanstalkDeploymentScope,
        registration: &Registration,
        evidence: &AwsElasticBeanstalkDeploymentEvidence,
    ) -> Result<Self, ModelError> {
        let mut proposal = Self {
            consumer_id: crate::AWS_ELASTIC_BEANSTALK_CONSUMER_ID.to_owned(),
            mission: scope.mission.clone(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: evidence.digests.scope_digest.clone(),
            version_digest: evidence.digests.version_digest.clone(),
            provider_digest: evidence.digests.provider_digest.clone(),
            permission_digest: evidence.digests.permission_digest.clone(),
            evidence_digest: evidence.digests.evidence_digest.clone(),
            read_only: true,
            adopted_outcome: false,
            truth_authority: false,
            connected: false,
            native_provider: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.calculate_digest()?;
        Ok(proposal)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.consumer_id,
            &self.mission,
            &self.registration_digest,
            &self.scope_digest,
            &self.version_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.evidence_digest,
            self.read_only,
            self.adopted_outcome,
            self.truth_authority,
            self.connected,
            self.native_provider,
        ))
    }

    pub fn verify(&self) -> Result<(), AwsElasticBeanstalkDeploymentServiceError> {
        if !self.read_only
            || self.adopted_outcome
            || self.truth_authority
            || self.connected
            || self.native_provider
            || self.calculate_digest()? != self.proposal_digest
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsElasticBeanstalkRecordReceipt {
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub recorded_at: DateTime<Utc>,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub receipt_digest: Digest,
}

impl AwsElasticBeanstalkRecordReceipt {
    fn new(
        registration: &Registration,
        evidence: &AwsElasticBeanstalkDeploymentEvidence,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let mut receipt = Self {
            registration_digest: registration.registration_digest.clone(),
            evidence_digest: evidence.digests.evidence_digest.clone(),
            recorded_at,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = crate::model::digest_serializable(&(
            &receipt.registration_digest,
            &receipt.evidence_digest,
            receipt.recorded_at,
            receipt.durable_provider_receipt,
            receipt.connected,
            receipt.native,
        ))?;
        Ok(receipt)
    }

    pub fn verify(&self) -> Result<(), AwsElasticBeanstalkDeploymentServiceError> {
        let digest = crate::model::digest_serializable(&(
            &self.registration_digest,
            &self.evidence_digest,
            self.recorded_at,
            self.durable_provider_receipt,
            self.connected,
            self.native,
        ))?;
        if self.durable_provider_receipt
            || self.connected
            || self.native
            || digest != self.receipt_digest
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsElasticBeanstalkDeploymentReadResult {
    pub proposal: AwsElasticBeanstalkDeploymentProposal,
    pub evidence: AwsElasticBeanstalkDeploymentEvidence,
}

pub struct AwsElasticBeanstalkDeploymentService<T = crate::provider::BlockedEnvTransport> {
    scope: AwsElasticBeanstalkDeploymentScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsElasticBeanstalkProvider<T>,
    registration: Registration,
}

impl<T> fmt::Debug for AwsElasticBeanstalkDeploymentService<T>
where
    T: AwsElasticBeanstalkTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsElasticBeanstalkDeploymentService")
            .field("scope", &self.scope)
            .field("permission", &self.permission)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsElasticBeanstalkDeploymentService<T>
where
    T: AwsElasticBeanstalkTransport,
{
    pub fn new(
        scope: AwsElasticBeanstalkDeploymentScope,
        permission: PermissionFence,
        secret_reference: SecretReference,
        provider: AwsElasticBeanstalkProvider<T>,
    ) -> Result<Self, AwsElasticBeanstalkDeploymentServiceError> {
        scope.verify()?;
        permission.verify()?;
        if permission.permission_digest != scope.permission_digest
            || secret_reference.scope_digest() != &scope.scope_digest
            || secret_reference.signing_region() != &scope.region
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::SecretReferenceMismatch);
        }
        secret_reference.ensure_active()?;
        provider.validate()?;
        if provider.definition().provider_id.as_str() != AWS_ELASTIC_BEANSTALK_PROVIDER_ID
            || provider.definition().version != AWS_ELASTIC_BEANSTALK_PROVIDER_VERSION
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::ProviderRevision);
        }
        let registration = Registration::new(
            scope.mission.clone(),
            scope.scope_digest.clone(),
            scope.version.version_digest.clone(),
            provider.definition().provider_digest.clone(),
            permission.permission_digest.clone(),
            secret_reference.reference_digest(),
            contract_digest(),
            crate::model::Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn register(
        scope: AwsElasticBeanstalkDeploymentScope,
        permission: PermissionFence,
        secret_reference: SecretReference,
        provider: AwsElasticBeanstalkProvider<T>,
    ) -> Result<Self, AwsElasticBeanstalkDeploymentServiceError> {
        Self::new(scope, permission, secret_reference, provider)
    }

    pub const fn describe_capabilities() -> AwsElasticBeanstalkDeploymentCapabilities {
        AwsElasticBeanstalkDeploymentCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsElasticBeanstalkDeploymentScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsElasticBeanstalkProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsElasticBeanstalkProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, AwsElasticBeanstalkDeploymentServiceError> {
        self.registration
            .revoke()
            .map_err(RegistrationError::from)
            .map_err(AwsElasticBeanstalkDeploymentServiceError::Registration)
    }

    pub fn read(
        &mut self,
    ) -> Result<AwsElasticBeanstalkDeploymentReadResult, AwsElasticBeanstalkDeploymentServiceError>
    {
        let bounds = self.provider.bounds().clone();
        self.read_bounded(bounds)
    }

    pub fn read_bounded(
        &mut self,
        bounds: ReadBounds,
    ) -> Result<AwsElasticBeanstalkDeploymentReadResult, AwsElasticBeanstalkDeploymentServiceError>
    {
        self.ensure_active()?;
        bounds.validate()?;
        self.ensure_permissions()?;
        let provider_digest = self.provider.definition().provider_digest.clone();
        let (environments, environment_pages) = self.read_environments(&bounds)?;
        let (resources, resource_pages) = self.read_resources(&bounds)?;
        let (events, event_pages) = self.read_events(&bounds)?;
        let requests = environment_pages
            .saturating_add(resource_pages)
            .saturating_add(event_pages);
        if requests > crate::model::MAX_REQUESTS_PER_READ {
            return Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit);
        }
        let evidence = AwsElasticBeanstalkDeploymentEvidence::complete(
            &self.scope,
            &self.registration,
            provider_digest,
            environments,
            resources,
            events,
            EvidencePageCounts {
                environments: environment_pages,
                resources: resource_pages,
                events: event_pages,
                requests,
            },
        )?;
        let proposal = self.propose(&evidence)?;
        Ok(AwsElasticBeanstalkDeploymentReadResult { proposal, evidence })
    }

    pub fn propose(
        &self,
        evidence: &AwsElasticBeanstalkDeploymentEvidence,
    ) -> Result<AwsElasticBeanstalkDeploymentProposal, AwsElasticBeanstalkDeploymentServiceError>
    {
        self.ensure_active()?;
        evidence.verify()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.digests.scope_digest != self.scope.scope_digest
            || evidence.digests.version_digest != self.scope.version.version_digest
            || evidence.digests.provider_digest != self.provider.definition().provider_digest
            || evidence.digests.permission_digest != self.permission.permission_digest
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::TamperedEvidence);
        }
        AwsElasticBeanstalkDeploymentProposal::new(&self.scope, &self.registration, evidence)
            .map_err(Into::into)
    }

    pub fn record(
        &self,
        evidence: &AwsElasticBeanstalkDeploymentEvidence,
    ) -> Result<AwsElasticBeanstalkRecordReceipt, AwsElasticBeanstalkDeploymentServiceError> {
        self.record_at(evidence, Utc::now())
    }

    pub fn record_at(
        &self,
        evidence: &AwsElasticBeanstalkDeploymentEvidence,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsElasticBeanstalkRecordReceipt, AwsElasticBeanstalkDeploymentServiceError> {
        self.ensure_active()?;
        evidence.verify()?;
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(AwsElasticBeanstalkDeploymentServiceError::TamperedEvidence);
        }
        AwsElasticBeanstalkRecordReceipt::new(&self.registration, evidence, recorded_at)
            .map_err(Into::into)
    }

    pub fn verify(
        &self,
        result: &AwsElasticBeanstalkDeploymentReadResult,
    ) -> Result<(), AwsElasticBeanstalkDeploymentServiceError> {
        result.evidence.verify()?;
        result.proposal.verify()?;
        if result.proposal.evidence_digest != result.evidence.digests.evidence_digest
            || result.proposal.registration_digest != self.registration.registration_digest
        {
            return Err(AwsElasticBeanstalkDeploymentServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), AwsElasticBeanstalkDeploymentServiceError> {
        if !self.is_active() {
            return Err(AwsElasticBeanstalkDeploymentServiceError::Revoked);
        }
        self.registration
            .ensure_active()
            .map_err(RegistrationError::from)
            .map_err(AwsElasticBeanstalkDeploymentServiceError::Registration)
    }

    fn ensure_permissions(&self) -> Result<(), AwsElasticBeanstalkDeploymentServiceError> {
        for operation in AwsElasticBeanstalkReadOperation::ALL {
            if !self.permission.permits(operation) {
                return Err(AwsElasticBeanstalkDeploymentServiceError::PermissionLoss);
            }
        }
        Ok(())
    }

    fn read_environments(
        &mut self,
        bounds: &ReadBounds,
    ) -> Result<(Vec<EnvironmentRevisionProjection>, u16), AwsElasticBeanstalkDeploymentServiceError>
    {
        let mut request = DescribeEnvironmentsRequest::new(&self.scope, bounds)?;
        let mut pages: u16 = 0;
        let mut seen_tokens = BTreeSet::new();
        let mut values = Vec::new();
        loop {
            let page = self.provider.describe_environments(&request)?;
            pages = pages.saturating_add(1);
            values.extend(page.environments);
            if values.len() > bounds.max_items {
                return Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit);
            }
            let Some(token) = page.next_token else {
                break;
            };
            if pages >= bounds.max_pages || !seen_tokens.insert(token.digest().clone()) {
                return Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit);
            }
            request = request.with_next_token(Some(token))?;
        }
        Ok((values, pages))
    }

    fn read_resources(
        &mut self,
        bounds: &ReadBounds,
    ) -> Result<(Vec<ResourceProjection>, u16), AwsElasticBeanstalkDeploymentServiceError> {
        let mut request = DescribeEnvironmentResourcesRequest::new(&self.scope, bounds)?;
        let mut pages: u16 = 0;
        let mut seen_tokens = BTreeSet::new();
        let mut values = Vec::new();
        loop {
            let page = self.provider.describe_environment_resources(&request)?;
            pages = pages.saturating_add(1);
            values.extend(page.resources);
            if values.len() > bounds.max_items {
                return Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit);
            }
            let Some(token) = page.next_token else {
                break;
            };
            if pages >= bounds.max_pages || !seen_tokens.insert(token.digest().clone()) {
                return Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit);
            }
            request = request.with_next_token(Some(token))?;
        }
        Ok((values, pages))
    }

    fn read_events(
        &mut self,
        bounds: &ReadBounds,
    ) -> Result<(Vec<EventProjection>, u16), AwsElasticBeanstalkDeploymentServiceError> {
        let mut request = DescribeEventsRequest::new(&self.scope, bounds)?;
        let mut pages: u16 = 0;
        let mut seen_tokens = BTreeSet::new();
        let mut values = Vec::new();
        loop {
            let page = self.provider.describe_events(&request)?;
            pages = pages.saturating_add(1);
            values.extend(page.events);
            if values.len() > bounds.max_items {
                return Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit);
            }
            let Some(token) = page.next_token else {
                break;
            };
            if pages >= bounds.max_pages || !seen_tokens.insert(token.digest().clone()) {
                return Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit);
            }
            request = request.with_next_token(Some(token))?;
        }
        Ok((values, pages))
    }
}

pub type AwsElasticBeanstalkService<T> = AwsElasticBeanstalkDeploymentService<T>;
pub type AwsElasticBeanstalkReadResult = AwsElasticBeanstalkDeploymentReadResult;
pub type AwsElasticBeanstalkProposal = AwsElasticBeanstalkDeploymentProposal;
pub type AwsElasticBeanstalkServiceError = AwsElasticBeanstalkDeploymentServiceError;
pub type AwsElasticBeanstalkRegistrationReceipt = Registration;
pub type AwsElasticBeanstalkDeploymentRegistration = Registration;
pub type AwsElasticBeanstalkRegistrationState = RegistrationState;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{
            AccountId, ApplicationName, AwsElasticBeanstalkDeploymentScope, AwsRegion,
            DeploymentBinding, DeploymentId, DeploymentVersionBinding, EnvironmentId,
            EnvironmentName, EnvironmentRevisionProjection, EnvironmentStatus, EventKind,
            EventProjection, EventSeverity, HealthStatus, MissionBinding, MissionId, PermissionId,
            ProjectBinding, ProjectId, Revision, RevisionId, WorkProductBinding, WorkProductId,
        },
        provider::{
            BlockedEnvTransport, DescribeEnvironmentResourcesPage, DescribeEnvironmentsPage,
            DescribeEventsPage, FixtureAwsElasticBeanstalkTransport, ProviderProvenance,
        },
    };
    use chrono::TimeZone;

    fn setup() -> (
        AwsElasticBeanstalkDeploymentScope,
        PermissionFence,
        SecretReference,
    ) {
        let permission = PermissionFence::readonly(
            PermissionId::new("permission").expect("id"),
            Revision::new(1).expect("revision"),
        )
        .expect("permission");
        let scope = AwsElasticBeanstalkDeploymentScope::new(
            DeploymentBinding::new(
                DeploymentId::new("deployment").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            MissionBinding::new(
                MissionId::new("mission").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            ProjectBinding::new(
                ProjectId::new("project").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            WorkProductBinding::new(
                WorkProductId::new("work").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            AccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            ApplicationName::new("app").expect("application"),
            vec![EnvironmentName::new("prod").expect("environment")],
            DeploymentVersionBinding::new(
                Revision::new(1).expect("revision"),
                Digest::from_text("version"),
            )
            .expect("version"),
            permission.permission_digest.clone(),
        )
        .expect("scope");
        let secret = SecretReference::for_scope(
            "keychain-ref",
            &scope,
            RevisionId::new("secret-r1").expect("revision"),
        )
        .expect("secret");
        (scope, permission, secret)
    }

    fn pages(
        scope: &AwsElasticBeanstalkDeploymentScope,
        provider_revision: crate::model::ProviderRevision,
    ) -> (
        DescribeEnvironmentsPage,
        DescribeEnvironmentResourcesPage,
        DescribeEventsPage,
    ) {
        let bounds = ReadBounds::default();
        let environment_request =
            DescribeEnvironmentsRequest::new(scope, &bounds).expect("request");
        let resource_request =
            DescribeEnvironmentResourcesRequest::new(scope, &bounds).expect("request");
        let event_request = DescribeEventsRequest::new(scope, &bounds).expect("request");
        let timestamp = Utc.timestamp_opt(0, 0).single().expect("epoch");
        let environment = EnvironmentRevisionProjection::new(
            EnvironmentId::new("e-1").expect("environment"),
            EnvironmentName::new("prod").expect("name"),
            Revision::new(1).expect("revision"),
            EnvironmentStatus::Ready,
            HealthStatus::Green,
            scope.version.version_digest.clone(),
            timestamp,
        )
        .expect("environment");
        let resource = ResourceProjection::new(
            EnvironmentId::new("e-1").expect("environment"),
            crate::model::ResourceKind::Instance,
            1,
            Digest::from_text("instance"),
            timestamp,
        )
        .expect("resource");
        let event = EventProjection::new(
            EnvironmentId::new("e-1").expect("environment"),
            "event-1",
            Revision::new(1).expect("revision"),
            timestamp,
            EventSeverity::Info,
            EventKind::Deployment,
            "redacted message",
        )
        .expect("event");
        (
            DescribeEnvironmentsPage::new(
                &environment_request,
                vec![environment],
                None,
                64,
                ProviderProvenance::Fixture,
                provider_revision.clone(),
            )
            .expect("page"),
            DescribeEnvironmentResourcesPage::new(
                &resource_request,
                vec![resource],
                None,
                64,
                ProviderProvenance::Fixture,
                provider_revision.clone(),
            )
            .expect("page"),
            DescribeEventsPage::new(
                &event_request,
                vec![event],
                None,
                64,
                ProviderProvenance::Fixture,
                provider_revision,
            )
            .expect("page"),
        )
    }

    #[test]
    fn bounded_fixture_read_emits_three_seams_and_false_authority() {
        let (scope, permission, secret) = setup();
        let definition =
            crate::provider::AwsElasticBeanstalkProviderDefinition::new().expect("definition");
        let (environment, resource, event) = pages(&scope, definition.api_revision.clone());
        let mut transport = FixtureAwsElasticBeanstalkTransport::new();
        transport.push_describe_environments(Ok(environment));
        transport.push_describe_environment_resources(Ok(resource));
        transport.push_describe_events(Ok(event));
        let provider = AwsElasticBeanstalkProvider::new(transport).expect("provider");
        let mut service =
            AwsElasticBeanstalkDeploymentService::new(scope, permission, secret, provider)
                .expect("service");
        let result = service.read().expect("read");
        service.verify(&result).expect("verify");
        assert_eq!(result.evidence.page_counts.requests, 3);
        assert!(!result.evidence.authority.connected);
        assert!(!result.evidence.authority.native_provider);
        assert!(!result.proposal.adopted_outcome);
    }

    #[test]
    fn registration_revoke_is_reversible_in_state_and_blocks_reads() {
        let (scope, permission, secret) = setup();
        let provider = AwsElasticBeanstalkProvider::new(BlockedEnvTransport).expect("provider");
        let mut service =
            AwsElasticBeanstalkDeploymentService::new(scope, permission, secret, provider)
                .expect("service");
        let revocation = service.revoke_registration().expect("revocation");
        assert_eq!(revocation.prior_registration_digest.as_str().len(), 64);
        assert!(!service.is_active());
        assert!(matches!(
            service.read(),
            Err(AwsElasticBeanstalkDeploymentServiceError::Revoked)
        ));
    }

    #[test]
    fn blocked_env_never_becomes_partial_success() {
        let (scope, permission, secret) = setup();
        let provider = AwsElasticBeanstalkProvider::new(BlockedEnvTransport).expect("provider");
        let mut service =
            AwsElasticBeanstalkDeploymentService::new(scope, permission, secret, provider)
                .expect("service");
        let error = service.read().expect_err("blocked");
        assert!(matches!(
            error,
            AwsElasticBeanstalkDeploymentServiceError::Provider(ProviderError::Transport(_))
        ));
    }

    #[test]
    fn repeated_page_token_is_rejected_before_unbounded_reads() {
        let (scope, permission, secret) = setup();
        let bounds = ReadBounds::new(2, 256, 50, crate::model::MAX_RESPONSE_BYTES).expect("bounds");
        let first_request = DescribeEnvironmentsRequest::new(&scope, &bounds).expect("request");
        let repeated_token = crate::model::OpaquePageToken::new("repeat-me").expect("token");
        let second_request = first_request
            .with_next_token(Some(repeated_token.clone()))
            .expect("second request");
        let definition =
            crate::provider::AwsElasticBeanstalkProviderDefinition::new().expect("definition");
        let first_page = DescribeEnvironmentsPage::new(
            &first_request,
            Vec::new(),
            Some(repeated_token.clone()),
            1,
            ProviderProvenance::Fixture,
            definition.api_revision.clone(),
        )
        .expect("first page");
        let second_page = DescribeEnvironmentsPage::new(
            &second_request,
            Vec::new(),
            Some(repeated_token),
            1,
            ProviderProvenance::Fixture,
            definition.api_revision,
        )
        .expect("second page");
        let mut transport = FixtureAwsElasticBeanstalkTransport::new();
        transport.push_describe_environments(Ok(first_page));
        transport.push_describe_environments(Ok(second_page));
        let provider = AwsElasticBeanstalkProvider::new(transport).expect("provider");
        let mut service =
            AwsElasticBeanstalkDeploymentService::new(scope, permission, secret, provider)
                .expect("service");
        assert!(matches!(
            service.read_bounded(bounds),
            Err(AwsElasticBeanstalkDeploymentServiceError::PaginationLimit)
        ));
        assert_eq!(service.provider().transport().calls().len(), 2);
    }
}
