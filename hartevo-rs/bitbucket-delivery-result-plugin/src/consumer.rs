//! Mission-scoped Bitbucket delivery-result consumer.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{
    BitbucketDeliveryEvidence, BitbucketDeliveryScope, BitbucketReadRequest, DeliveryResultState,
    Digest, TransportProvenance, compute_evidence_digest, digest_serializable,
};
use crate::provider::{BitbucketCredentialResolver, BitbucketDeliveryError, BitbucketProvider};
use crate::transport::BitbucketDeliveryTransport;
use crate::{
    BITBUCKET_DELIVERY_RESULT_CONSUMER_ID, BITBUCKET_DELIVERY_RESULT_CONSUMER_SCHEMA,
    BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION, BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION,
    contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitbucketDeliveryObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_key: Digest,
    pub state: DeliveryResultState,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_write_performed: bool,
    pub generic_ci_authority: bool,
    pub observation_digest: Digest,
}

impl BitbucketDeliveryObservation {
    fn from_evidence(evidence: &BitbucketDeliveryEvidence) -> Result<Self, BitbucketDeliveryError> {
        let mut observation = Self {
            contract_version: BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: BITBUCKET_DELIVERY_RESULT_CONSUMER_ID.to_owned(),
            consumer_version: BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            idempotency_key: evidence.idempotency_key.clone(),
            state: evidence.state.clone(),
            provenance: evidence.provenance,
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_write_performed: false,
            generic_ci_authority: false,
            observation_digest: Digest::parse("0".repeat(64))?,
        };
        observation.observation_digest = digest_serializable(&(
            &observation.contract_version,
            &observation.contract_digest,
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.scope_digest,
            &observation.evidence_digest,
            &observation.idempotency_key,
            &observation.state,
            observation.provenance,
            observation.read_only,
            observation.connected,
            observation.native,
            observation.first_party,
            observation.external_write_performed,
            observation.generic_ci_authority,
        ))?;
        Ok(observation)
    }

    pub fn validate(
        &self,
        evidence: &BitbucketDeliveryEvidence,
    ) -> Result<(), BitbucketDeliveryError> {
        if self.contract_version != BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.consumer_id != BITBUCKET_DELIVERY_RESULT_CONSUMER_ID
            || self.consumer_version != BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION
            || self.scope_digest != evidence.scope_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.idempotency_key != evidence.idempotency_key
            || self.state != evidence.state
            || self.provenance != evidence.provenance
            || !self.read_only
            || self.connected
            || self.native
            || self.first_party
            || self.external_write_performed
            || self.generic_ci_authority
            || self.observation_digest
                != digest_serializable(&(
                    &self.contract_version,
                    &self.contract_digest,
                    &self.consumer_id,
                    &self.consumer_version,
                    &self.scope_digest,
                    &self.evidence_digest,
                    &self.idempotency_key,
                    &self.state,
                    self.provenance,
                    self.read_only,
                    self.connected,
                    self.native,
                    self.first_party,
                    self.external_write_performed,
                    self.generic_ci_authority,
                ))?
        {
            return Err(BitbucketDeliveryError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBitbucketDeliveryReadResult {
    pub observation: BitbucketDeliveryObservation,
    pub evidence: BitbucketDeliveryEvidence,
}

impl MissionBitbucketDeliveryReadResult {
    pub fn validate(&self, scope: &BitbucketDeliveryScope) -> Result<(), BitbucketDeliveryError> {
        self.evidence.validate()?;
        if self.evidence.scope_digest != scope.digest() {
            return Err(BitbucketDeliveryError::ScopeMismatch(
                "Mission consumer scope differs from evidence scope".to_owned(),
            ));
        }
        self.observation.validate(&self.evidence)
    }

    pub fn state(&self) -> &DeliveryResultState {
        &self.evidence.state
    }
}

pub struct MissionBitbucketDeliveryConsumer {
    scope: BitbucketDeliveryScope,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    consumed_idempotency_keys: BTreeSet<Digest>,
}

impl fmt::Debug for MissionBitbucketDeliveryConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBitbucketDeliveryConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field(
                "consumed_idempotency_count",
                &self.consumed_idempotency_keys.len(),
            )
            .finish()
    }
}

impl MissionBitbucketDeliveryConsumer {
    pub fn new(scope: BitbucketDeliveryScope) -> Self {
        Self {
            scope,
            plugin_version: BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumed_idempotency_keys: BTreeSet::new(),
        }
    }

    pub fn scope(&self) -> &BitbucketDeliveryScope {
        &self.scope
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn consume_evidence(
        &self,
        evidence: BitbucketDeliveryEvidence,
    ) -> Result<MissionBitbucketDeliveryReadResult, BitbucketDeliveryError> {
        self.verify_evidence(&evidence)?;
        let observation = BitbucketDeliveryObservation::from_evidence(&evidence)?;
        let result = MissionBitbucketDeliveryReadResult {
            observation,
            evidence,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    /// One-shot consuming variant used where a host supplies a replay fence.
    pub fn consume_once(
        &mut self,
        evidence: BitbucketDeliveryEvidence,
    ) -> Result<MissionBitbucketDeliveryReadResult, BitbucketDeliveryError> {
        let key = evidence.idempotency_key.clone();
        if self.consumed_idempotency_keys.contains(&key) {
            return Err(BitbucketDeliveryError::ReplayDetected);
        }
        let result = self.consume_evidence(evidence)?;
        self.consumed_idempotency_keys.insert(key);
        Ok(result)
    }

    pub fn read<T, R>(
        &self,
        provider: &mut BitbucketProvider<T, R>,
        request: &BitbucketReadRequest,
        at: DateTime<Utc>,
    ) -> Result<MissionBitbucketDeliveryReadResult, BitbucketDeliveryError>
    where
        T: BitbucketDeliveryTransport,
        R: BitbucketCredentialResolver,
    {
        if provider.registration().scope() != &self.scope {
            return Err(BitbucketDeliveryError::ScopeMismatch(
                "Mission consumer and provider registration scopes differ".to_owned(),
            ));
        }
        self.consume_evidence(provider.read(request, at)?)
    }

    pub fn read_once<T, R>(
        &mut self,
        provider: &mut BitbucketProvider<T, R>,
        request: &BitbucketReadRequest,
        at: DateTime<Utc>,
    ) -> Result<MissionBitbucketDeliveryReadResult, BitbucketDeliveryError>
    where
        T: BitbucketDeliveryTransport,
        R: BitbucketCredentialResolver,
    {
        if provider.registration().scope() != &self.scope {
            return Err(BitbucketDeliveryError::ScopeMismatch(
                "Mission consumer and provider registration scopes differ".to_owned(),
            ));
        }
        self.consume_once(provider.read_once(request, at)?)
    }

    fn verify_evidence(
        &self,
        evidence: &BitbucketDeliveryEvidence,
    ) -> Result<(), BitbucketDeliveryError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.contract_digest != self.contract_digest
            || evidence.contract_version != self.contract_version
            || evidence.evidence_digest != compute_evidence_digest(evidence)?
            || evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || evidence.provenance.is_first_party()
            || evidence.connected
            || evidence.native
            || evidence.first_party
            || evidence.external_write_performed
            || evidence.generic_ci_authority
            || evidence.raw_diff_retained
            || evidence.raw_comments_retained
            || evidence.raw_artifact_bytes_retained
        {
            return Err(BitbucketDeliveryError::StaleEvidence);
        }
        evidence.validate()?;
        Ok(())
    }
}

pub type BitbucketDeliveryResult = MissionBitbucketDeliveryReadResult;
pub type MissionBitbucketDeliveryResult = MissionBitbucketDeliveryReadResult;
pub const MISSION_BITBUCKET_DELIVERY_CONSUMER_SCHEMA: &str =
    BITBUCKET_DELIVERY_RESULT_CONSUMER_SCHEMA;
