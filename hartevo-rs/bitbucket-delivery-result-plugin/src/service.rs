//! Typed read-only Bitbucket delivery-result service descriptor.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{BitbucketDeliveryEvidence, BitbucketDeliveryScope, BitbucketReadRequest};
use crate::provider::{
    BitbucketCredentialResolver, BitbucketDeliveryError, BitbucketProvider, RegistrationState,
};
use crate::transport::BitbucketDeliveryTransport;
use crate::{
    BITBUCKET_DELIVERY_RESULT_SERVICE_ID, BITBUCKET_DELIVERY_RESULT_SERVICE_NAME,
    BITBUCKET_DELIVERY_RESULT_SERVICE_SCHEMA, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BitbucketDeliveryOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadRepository,
    ReadPullRequest,
    ReadCommitStatuses,
    ReadPipeline,
    ReadDeployment,
    ConsumeObservation,
}

impl BitbucketDeliveryOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadRepository,
        Self::ReadPullRequest,
        Self::ReadCommitStatuses,
        Self::ReadPipeline,
        Self::ReadDeployment,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitbucketDeliveryCapability {
    pub capability_id: String,
    pub operation: BitbucketDeliveryOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub connected: bool,
    pub native: bool,
    pub generic_ci_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitbucketDeliveryResultServiceDefinition {
    pub service_id: String,
    pub service_name: String,
    pub version: PluginVersion,
    pub contract_digest: crate::model::Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub generic_ci_authority: bool,
    pub capabilities: Vec<BitbucketDeliveryCapability>,
}

impl Default for BitbucketDeliveryResultServiceDefinition {
    fn default() -> Self {
        let names = [
            (
                "bitbucket.delivery.result.register",
                BitbucketDeliveryOperation::Register,
            ),
            (
                "bitbucket.delivery.result.revoke_registration",
                BitbucketDeliveryOperation::RevokeRegistration,
            ),
            (
                "bitbucket.delivery.result.read_repository",
                BitbucketDeliveryOperation::ReadRepository,
            ),
            (
                "bitbucket.delivery.result.read_pull_request",
                BitbucketDeliveryOperation::ReadPullRequest,
            ),
            (
                "bitbucket.delivery.result.read_commit_statuses",
                BitbucketDeliveryOperation::ReadCommitStatuses,
            ),
            (
                "bitbucket.delivery.result.read_pipeline",
                BitbucketDeliveryOperation::ReadPipeline,
            ),
            (
                "bitbucket.delivery.result.read_deployment",
                BitbucketDeliveryOperation::ReadDeployment,
            ),
            (
                "bitbucket.delivery.result.consume_observation",
                BitbucketDeliveryOperation::ConsumeObservation,
            ),
        ];
        Self {
            service_id: BITBUCKET_DELIVERY_RESULT_SERVICE_ID.to_owned(),
            service_name: BITBUCKET_DELIVERY_RESULT_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            contract_digest: contract_digest(),
            read_only: true,
            live_execution: false,
            external_writes: false,
            generic_ci_authority: false,
            capabilities: names
                .into_iter()
                .map(|(capability_id, operation)| BitbucketDeliveryCapability {
                    capability_id: capability_id.to_owned(),
                    operation,
                    read_only: true,
                    mutates_provider: false,
                    connected: false,
                    native: false,
                    generic_ci_authority: false,
                })
                .collect(),
        }
    }
}

impl BitbucketDeliveryResultServiceDefinition {
    pub fn runtime_definition(&self) -> Result<ServiceDefinition, BitbucketDeliveryError> {
        let id = ServiceId::new(self.service_id.clone())?;
        ServiceDefinition::read_only(
            id,
            self.version,
            RuntimeDigest::from_text(BITBUCKET_DELIVERY_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(BitbucketDeliveryError::Plugin)
    }

    pub fn validate(&self) -> Result<(), BitbucketDeliveryError> {
        if self.service_id != BITBUCKET_DELIVERY_RESULT_SERVICE_ID
            || self.service_name != BITBUCKET_DELIVERY_RESULT_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || self.contract_digest != contract_digest()
            || !self.read_only
            || self.live_execution
            || self.external_writes
            || self.generic_ci_authority
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.connected
                    || capability.native
                    || capability.generic_ci_authority
            })
        {
            return Err(BitbucketDeliveryError::Contract(
                "Bitbucket service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed Layer-1 service. It delegates only to a registered provider and
/// never exposes provider mutation or generic CI capabilities.
pub struct BitbucketDeliveryResultService<T, R>
where
    T: BitbucketDeliveryTransport,
    R: BitbucketCredentialResolver,
{
    provider: BitbucketProvider<T, R>,
    definition: BitbucketDeliveryResultServiceDefinition,
}

impl<T, R> fmt::Debug for BitbucketDeliveryResultService<T, R>
where
    T: BitbucketDeliveryTransport,
    R: BitbucketCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitbucketDeliveryResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T, R> BitbucketDeliveryResultService<T, R>
where
    T: BitbucketDeliveryTransport,
    R: BitbucketCredentialResolver,
{
    pub fn new(provider: BitbucketProvider<T, R>) -> Result<Self, BitbucketDeliveryError> {
        let definition = BitbucketDeliveryResultServiceDefinition::default();
        definition.validate()?;
        if provider.registration().state() == RegistrationState::Revoked {
            return Err(BitbucketDeliveryError::RegistrationRevoked);
        }
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn from_provider(provider: BitbucketProvider<T, R>) -> Self {
        Self {
            provider,
            definition: BitbucketDeliveryResultServiceDefinition::default(),
        }
    }

    pub fn provider(&self) -> &BitbucketProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut BitbucketProvider<T, R> {
        &mut self.provider
    }

    pub fn scope(&self) -> &BitbucketDeliveryScope {
        self.provider.registration().scope()
    }

    pub fn registration(&self) -> &crate::provider::BitbucketRegistration {
        self.provider.registration()
    }

    pub fn service_definition(&self) -> &BitbucketDeliveryResultServiceDefinition {
        &self.definition
    }

    pub fn describe_capabilities(&self) -> Vec<BitbucketDeliveryCapability> {
        self.definition.capabilities.clone()
    }

    pub fn read(
        &mut self,
        request: &BitbucketReadRequest,
        at: DateTime<Utc>,
    ) -> Result<BitbucketDeliveryEvidence, BitbucketDeliveryError> {
        self.provider.read(request, at)
    }

    pub fn read_once(
        &mut self,
        request: &BitbucketReadRequest,
        at: DateTime<Utc>,
    ) -> Result<BitbucketDeliveryEvidence, BitbucketDeliveryError> {
        self.provider.read_once(request, at)
    }

    pub fn verify_evidence(
        &self,
        evidence: &BitbucketDeliveryEvidence,
    ) -> Result<(), BitbucketDeliveryError> {
        if evidence.scope_digest != self.scope().digest()
            || evidence.registration_digest != *self.registration().registration_digest()
            || evidence.contract_digest != contract_digest()
            || evidence.contract_version != crate::BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION
            || evidence.provider_revision != *self.registration().provider_revision()
            || evidence.idempotency_key.as_str().len() != 64
            || !evidence.read_only
            || evidence.connected
            || evidence.native
            || evidence.first_party
            || evidence.external_write_performed
            || evidence.generic_ci_authority
            || evidence.raw_diff_retained
            || evidence.raw_comments_retained
            || evidence.raw_artifact_bytes_retained
            || compute_digest(evidence)? != evidence.evidence_digest
        {
            return Err(BitbucketDeliveryError::StaleEvidence);
        }
        evidence.validate()?;
        Ok(())
    }

    pub fn revoke_registration(&mut self, at: DateTime<Utc>) -> Result<(), BitbucketDeliveryError> {
        self.provider.revoke(at)
    }
}

fn compute_digest(
    evidence: &BitbucketDeliveryEvidence,
) -> Result<crate::model::Digest, BitbucketDeliveryError> {
    crate::model::compute_evidence_digest(evidence).map_err(BitbucketDeliveryError::from)
}

pub type BitbucketDeliveryResultServiceError = BitbucketDeliveryError;
pub type BitbucketServiceDefinition = BitbucketDeliveryResultServiceDefinition;
