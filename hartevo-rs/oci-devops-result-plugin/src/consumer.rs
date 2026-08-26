//! Mission-scoped consumer, deterministic proposal, and local read-back seam.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, OciDevopsEvidence, OciDevopsReadRequest, OciDevopsScope, TransportProvenance,
    compute_evidence_digest, digest_serializable,
};
use crate::provider::{OciDevopsProvider, OciSigningKeyResolver};
use crate::transport::OciDevopsTransport;
use crate::{
    MISSION_OCI_DEVOPS_CONSUMER_ID, OCI_DEVOPS_RESULT_CONTRACT_VERSION,
    OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT, OciDevopsError, contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OciDevopsObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native_evidence: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub observation_digest: Digest,
}

impl OciDevopsObservation {
    fn from_evidence(evidence: &OciDevopsEvidence) -> Result<Self, OciDevopsError> {
        let mut observation = Self {
            contract_version: OCI_DEVOPS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: MISSION_OCI_DEVOPS_CONSUMER_ID.to_owned(),
            consumer_version: OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            provenance: evidence.provenance,
            read_only: true,
            native_evidence: false,
            external_write_performed: false,
            outcome_authority: false,
            observation_digest: Digest::zero(),
        };
        observation.observation_digest = digest_serializable(&(
            &observation.contract_version,
            &observation.contract_digest,
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.scope_digest,
            &observation.evidence_digest,
            observation.provenance,
            observation.read_only,
            observation.native_evidence,
            observation.external_write_performed,
            observation.outcome_authority,
        ))?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryDecisionProposal {
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub deployment_id: String,
    pub build_run_id: String,
    pub work_request_id: String,
    pub proposed_action: String,
    pub proposal_digest: Digest,
}

impl DeliveryDecisionProposal {
    pub fn from_evidence(evidence: &OciDevopsEvidence) -> Result<Self, OciDevopsError> {
        let mut proposal = Self {
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            deployment_id: evidence.deployment.id.to_string(),
            build_run_id: evidence.build_run.id.to_string(),
            work_request_id: evidence.work_request.id.to_string(),
            proposed_action: "inspect_delivery_state_only".to_owned(),
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = digest_serializable(&(
            &proposal.scope_digest,
            &proposal.evidence_digest,
            &proposal.deployment_id,
            &proposal.build_run_id,
            &proposal.work_request_id,
            &proposal.proposed_action,
        ))?;
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), OciDevopsError> {
        if self.proposed_action != "inspect_delivery_state_only"
            || self.proposal_digest
                != digest_serializable(&(
                    &self.scope_digest,
                    &self.evidence_digest,
                    &self.deployment_id,
                    &self.build_run_id,
                    &self.work_request_id,
                    &self.proposed_action,
                ))?
        {
            return Err(OciDevopsError::ProposalTamper);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryDecisionRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub recorded_action: String,
    pub external_effect_performed: bool,
    pub record_digest: Digest,
}

impl DeliveryDecisionRecord {
    pub fn from_proposal(proposal: &DeliveryDecisionProposal) -> Result<Self, OciDevopsError> {
        proposal.validate()?;
        let mut record = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            recorded_action: proposal.proposed_action.clone(),
            external_effect_performed: false,
            record_digest: Digest::zero(),
        };
        record.record_digest = digest_serializable(&(
            &record.proposal_digest,
            &record.evidence_digest,
            &record.recorded_action,
            record.external_effect_performed,
        ))?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), OciDevopsError> {
        if self.external_effect_performed
            || self.recorded_action != "inspect_delivery_state_only"
            || self.record_digest
                != digest_serializable(&(
                    &self.proposal_digest,
                    &self.evidence_digest,
                    &self.recorded_action,
                    self.external_effect_performed,
                ))?
        {
            return Err(OciDevopsError::ProposalTamper);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDeliveryReadbackVerification {
    pub proposal_digest: Digest,
    pub record_digest: Digest,
    pub evidence_digest: Digest,
    pub verified: bool,
    pub verification_digest: Digest,
}

impl OciDeliveryReadbackVerification {
    pub fn verify(
        proposal: &DeliveryDecisionProposal,
        record: &DeliveryDecisionRecord,
        evidence: &OciDevopsEvidence,
    ) -> Result<Self, OciDevopsError> {
        proposal.validate()?;
        record.validate()?;
        evidence.validate()?;
        let verified = proposal.evidence_digest == evidence.evidence_digest
            && record.proposal_digest == proposal.proposal_digest
            && record.evidence_digest == evidence.evidence_digest
            && record.recorded_action == proposal.proposed_action;
        if !verified {
            return Err(OciDevopsError::ProposalTamper);
        }
        let verification_digest = digest_serializable(&(
            &proposal.proposal_digest,
            &record.record_digest,
            &evidence.evidence_digest,
            verified,
        ))?;
        Ok(Self {
            proposal_digest: proposal.proposal_digest.clone(),
            record_digest: record.record_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            verified,
            verification_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOciDevopsReadResult {
    pub observation: OciDevopsObservation,
    pub evidence: OciDevopsEvidence,
    pub proposal: DeliveryDecisionProposal,
    pub record: DeliveryDecisionRecord,
    pub readback: OciDeliveryReadbackVerification,
}

impl MissionOciDevopsReadResult {
    pub fn validate(&self, scope: &OciDevopsScope) -> Result<(), OciDevopsError> {
        self.evidence.validate()?;
        self.proposal.validate()?;
        self.record.validate()?;
        if self.evidence.scope_digest != scope.digest()
            || self.observation.scope_digest != scope.digest()
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.contract_digest != contract_digest()
            || self.observation.contract_version != OCI_DEVOPS_RESULT_CONTRACT_VERSION
            || self.observation.consumer_id != MISSION_OCI_DEVOPS_CONSUMER_ID
            || self.observation.consumer_version != OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT
            || !self.observation.read_only
            || self.observation.native_evidence
            || self.observation.external_write_performed
            || self.observation.outcome_authority
            || self.proposal.scope_digest != scope.digest()
            || self.proposal.evidence_digest != self.evidence.evidence_digest
            || self.record.proposal_digest != self.proposal.proposal_digest
            || self.record.external_effect_performed
            || !self.readback.verified
        {
            return Err(OciDevopsError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MissionOciDevopsConsumer {
    scope: OciDevopsScope,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    replayed_evidence: Arc<Mutex<BTreeSet<Digest>>>,
}

impl fmt::Debug for MissionOciDevopsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let replayed_evidence_count = self
            .replayed_evidence
            .lock()
            .map_or(0, |evidence| evidence.len());
        formatter
            .debug_struct("MissionOciDevopsConsumer")
            .field("scope", &self.scope)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("replayed_evidence_count", &replayed_evidence_count)
            .finish()
    }
}

impl PartialEq for MissionOciDevopsConsumer {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope
            && self.plugin_version == other.plugin_version
            && self.contract_version == other.contract_version
            && self.contract_digest == other.contract_digest
    }
}

impl Eq for MissionOciDevopsConsumer {}

impl MissionOciDevopsConsumer {
    pub fn new(scope: OciDevopsScope) -> Self {
        Self {
            scope,
            plugin_version: OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: OCI_DEVOPS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            replayed_evidence: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    pub fn scope(&self) -> &OciDevopsScope {
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
        evidence: OciDevopsEvidence,
    ) -> Result<MissionOciDevopsReadResult, OciDevopsError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.contract_digest != self.contract_digest
            || evidence.contract_version != self.contract_version
            || compute_evidence_digest(&evidence)? != evidence.evidence_digest
        {
            return Err(OciDevopsError::EvidenceDigestMismatch);
        }
        evidence.validate()?;
        let evidence_digest = evidence.evidence_digest.clone();
        let mut replayed_evidence = self
            .replayed_evidence
            .lock()
            .map_err(|_| OciDevopsError::StaleEvidence)?;
        if !replayed_evidence.insert(evidence_digest) {
            return Err(OciDevopsError::StaleEvidence);
        }
        drop(replayed_evidence);
        let observation = OciDevopsObservation::from_evidence(&evidence)?;
        let proposal = DeliveryDecisionProposal::from_evidence(&evidence)?;
        let record = DeliveryDecisionRecord::from_proposal(&proposal)?;
        let readback = OciDeliveryReadbackVerification::verify(&proposal, &record, &evidence)?;
        let result = MissionOciDevopsReadResult {
            observation,
            evidence,
            proposal,
            record,
            readback,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn propose_delivery_decision(
        &self,
        evidence: &OciDevopsEvidence,
    ) -> Result<DeliveryDecisionProposal, OciDevopsError> {
        if evidence.scope_digest != self.scope.digest() {
            return Err(OciDevopsError::ScopeMismatch(
                "consumer and evidence scopes differ".to_owned(),
            ));
        }
        evidence.validate()?;
        DeliveryDecisionProposal::from_evidence(evidence)
    }

    pub fn record_delivery_decision(
        &self,
        proposal: &DeliveryDecisionProposal,
    ) -> Result<DeliveryDecisionRecord, OciDevopsError> {
        DeliveryDecisionRecord::from_proposal(proposal)
    }

    pub fn verify_readback(
        &self,
        proposal: &DeliveryDecisionProposal,
        record: &DeliveryDecisionRecord,
        evidence: &OciDevopsEvidence,
    ) -> Result<OciDeliveryReadbackVerification, OciDevopsError> {
        if evidence.scope_digest != self.scope.digest() {
            return Err(OciDevopsError::ScopeMismatch(
                "consumer and evidence scopes differ".to_owned(),
            ));
        }
        OciDeliveryReadbackVerification::verify(proposal, record, evidence)
    }

    pub fn read<T, R>(
        &self,
        provider: &mut OciDevopsProvider<T, R>,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
    ) -> Result<MissionOciDevopsReadResult, OciDevopsError>
    where
        T: OciDevopsTransport,
        R: OciSigningKeyResolver,
    {
        if provider.registration().scope() != &self.scope {
            return Err(OciDevopsError::ScopeMismatch(
                "consumer and provider registration scopes differ".to_owned(),
            ));
        }
        let evidence = provider.read(request, at)?;
        self.consume_evidence(evidence)
    }
}
