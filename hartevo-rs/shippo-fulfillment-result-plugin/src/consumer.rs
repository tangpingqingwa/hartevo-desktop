//! Mission-scoped consumption of Shippo fulfillment-result evidence.

use std::{cell::RefCell, collections::BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, ShippoFulfillmentEvidence, ShippoFulfillmentResultProposal, ShippoScope,
    compute_evidence_digest, digest_serializable, expected_provider_digest,
    validate_evidence_redaction,
};
use crate::provider::{SecretReferenceResolver, ShippoProvider};
use crate::transport::{ShippoTransport, TransportProvenance};
use crate::{
    MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID, SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION,
    SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT, ShippoFulfillmentError, contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MissionShippoFulfillmentObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native_evidence: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub observation_digest: Digest,
}

impl MissionShippoFulfillmentObservation {
    fn compute_digest(&self) -> Result<Digest, ShippoFulfillmentError> {
        digest_serializable(&(
            &self.contract_version,
            &self.contract_digest,
            &self.consumer_id,
            &self.consumer_version,
            &self.scope_digest,
            &self.evidence_digest,
            &self.proposal_digest,
            self.provenance,
            self.read_only,
            self.native_evidence,
            self.connected,
            self.external_write_performed,
            self.outcome_authority,
        ))
        .map_err(ShippoFulfillmentError::from)
    }

    fn from_parts(
        evidence: &ShippoFulfillmentEvidence,
        proposal: &ShippoFulfillmentResultProposal,
    ) -> Result<Self, ShippoFulfillmentError> {
        let mut observation = Self {
            contract_version: SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID.to_owned(),
            consumer_version: SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            provenance: evidence.provenance,
            read_only: true,
            native_evidence: false,
            connected: false,
            external_write_performed: false,
            outcome_authority: false,
            observation_digest: crate::model::zero_digest(),
        };
        observation.observation_digest = observation.compute_digest()?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionShippoFulfillmentReadResult {
    pub observation: MissionShippoFulfillmentObservation,
    pub evidence: ShippoFulfillmentEvidence,
    pub proposal: ShippoFulfillmentResultProposal,
}

impl MissionShippoFulfillmentReadResult {
    pub fn validate(&self, scope: &ShippoScope) -> Result<(), ShippoFulfillmentError> {
        if self.evidence.scope != *scope
            || self.evidence.scope_digest != scope.digest()
            || self.evidence.plugin_version != SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT
            || self.evidence.contract_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
            || self.evidence.contract_digest != contract_digest()
            || self.evidence.provider_id != crate::SHIPPO_PROVIDER_ID
            || self.evidence.provider_revision.as_str() != crate::SHIPPO_PROVIDER_REVISION
            || self.evidence.provider_digest
                != expected_provider_digest(&self.evidence.scope, &self.evidence.provider_revision)
            || self.observation.scope_digest != scope.digest()
            || self.observation.provenance != self.evidence.provenance
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.proposal_digest != self.proposal.proposal_digest
            || self.proposal.scope_digest != self.evidence.scope_digest
            || self.proposal.evidence_digest != self.evidence.evidence_digest
            || self.observation.contract_digest != contract_digest()
            || self.observation.contract_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
            || self.observation.consumer_id != MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID
            || self.observation.consumer_version != SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT
            || !self.observation.read_only
            || self.observation.native_evidence
            || self.observation.connected
            || self.observation.external_write_performed
            || self.observation.outcome_authority
            || self.observation.compute_digest()? != self.observation.observation_digest
            || compute_evidence_digest(&self.evidence)? != self.evidence.evidence_digest
        {
            return Err(ShippoFulfillmentError::StaleEvidence);
        }
        self.proposal
            .validate()
            .map_err(ShippoFulfillmentError::from)?;
        validate_evidence_redaction(&self.evidence)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionShippoFulfillmentConsumer {
    scope: ShippoScope,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    consumed_evidence_digests: RefCell<BTreeSet<Digest>>,
}

impl MissionShippoFulfillmentConsumer {
    pub fn new(scope: ShippoScope) -> Self {
        Self {
            scope,
            plugin_version: SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumed_evidence_digests: RefCell::new(BTreeSet::new()),
        }
    }

    pub fn scope(&self) -> &ShippoScope {
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
        evidence: ShippoFulfillmentEvidence,
    ) -> Result<MissionShippoFulfillmentReadResult, ShippoFulfillmentError> {
        if evidence.scope != self.scope
            || evidence.scope_digest != self.scope.digest()
            || evidence.contract_digest != self.contract_digest
            || evidence.contract_version != self.contract_version
            || evidence.plugin_version != self.plugin_version
            || evidence.provider_id != crate::SHIPPO_PROVIDER_ID
            || evidence.provider_revision.as_str() != crate::SHIPPO_PROVIDER_REVISION
            || evidence.provider_digest
                != expected_provider_digest(&evidence.scope, &evidence.provider_revision)
            || evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || compute_evidence_digest(&evidence)? != evidence.evidence_digest
        {
            return Err(ShippoFulfillmentError::StaleEvidence);
        }
        validate_evidence_redaction(&evidence)?;
        let proposal = crate::ShippoFulfillmentResultService::new().compile_proposal(&evidence)?;
        let observation = MissionShippoFulfillmentObservation::from_parts(&evidence, &proposal)?;
        let result = MissionShippoFulfillmentReadResult {
            observation,
            evidence,
            proposal,
        };
        result.validate(&self.scope)?;
        if !self
            .consumed_evidence_digests
            .borrow_mut()
            .insert(result.evidence.evidence_digest.clone())
        {
            return Err(ShippoFulfillmentError::StaleEvidence);
        }
        Ok(result)
    }

    pub fn read<T, R>(
        &self,
        provider: &mut ShippoProvider<T, R>,
        request: &crate::ShippoReadRequest,
        at: DateTime<Utc>,
    ) -> Result<MissionShippoFulfillmentReadResult, ShippoFulfillmentError>
    where
        T: ShippoTransport,
        R: SecretReferenceResolver,
    {
        if provider.registration().scope() != &self.scope {
            return Err(ShippoFulfillmentError::ScopeMismatch(
                "Mission consumer and Shippo provider registration scopes differ".to_owned(),
            ));
        }
        let evidence = provider.read(request, at)?;
        self.consume_evidence(evidence)
    }

    pub fn consume_observation(
        &self,
        evidence: ShippoFulfillmentEvidence,
    ) -> Result<MissionShippoFulfillmentReadResult, ShippoFulfillmentError> {
        self.consume_evidence(evidence)
    }

    pub fn compile_proposal(
        &self,
        evidence: &ShippoFulfillmentEvidence,
    ) -> Result<ShippoFulfillmentResultProposal, ShippoFulfillmentError> {
        if evidence.scope != self.scope {
            return Err(ShippoFulfillmentError::ScopeMismatch(
                "proposal scope does not match the Mission consumer".to_owned(),
            ));
        }
        crate::ShippoFulfillmentResultService::new().compile_proposal(evidence)
    }
}
