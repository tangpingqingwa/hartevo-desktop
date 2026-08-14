//! Mission-scoped consumer for Xero Accounting read evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, EvidenceProvenance, EvidenceStatus, XeroAccountingEvidence, XeroAccountingScope,
    XeroReadRequest,
};
use crate::provider::OAuth2CredentialResolver;
use crate::service::XeroAccountingResultService;
use crate::transport::XeroTransport;
use crate::{
    MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_ID, XERO_ACCOUNTING_RESULT_CONTRACT_VERSION,
    XERO_ACCOUNTING_RESULT_PLUGIN_VERSION, XeroAccountingError,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MissionXeroAccountingObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub status: EvidenceStatus,
    pub provenance: EvidenceProvenance,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub evidence_digest: Digest,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_write_performed: bool,
    pub financial_advice: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub observation_digest: Digest,
}

impl MissionXeroAccountingObservation {
    fn from_evidence(evidence: &XeroAccountingEvidence) -> Self {
        let mut observation = Self {
            contract_version: XERO_ACCOUNTING_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            consumer_id: MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_ID.to_owned(),
            consumer_version: XERO_ACCOUNTING_RESULT_PLUGIN_VERSION.to_owned(),
            status: evidence.status,
            provenance: evidence.provenance,
            scope_digest: evidence.scope_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            api_digest: evidence.api_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            revision_digest: evidence.revision_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            read_only: true,
            connected: false,
            native: false,
            external_write_performed: false,
            financial_advice: false,
            kernel_authority: false,
            outcome_adoption: false,
            observation_digest: Digest::from_bytes(&[]),
        };
        observation.observation_digest = Digest::from_serializable(&ObservationMaterial {
            contract_version: &observation.contract_version,
            contract_digest: &observation.contract_digest,
            consumer_id: &observation.consumer_id,
            consumer_version: &observation.consumer_version,
            status: observation.status,
            provenance: observation.provenance,
            scope_digest: &observation.scope_digest,
            provider_digest: &observation.provider_digest,
            api_digest: &observation.api_digest,
            permission_digest: &observation.permission_digest,
            revision_digest: &observation.revision_digest,
            evidence_digest: &observation.evidence_digest,
            read_only: observation.read_only,
            connected: observation.connected,
            native: observation.native,
            external_write_performed: observation.external_write_performed,
            financial_advice: observation.financial_advice,
            kernel_authority: observation.kernel_authority,
            outcome_adoption: observation.outcome_adoption,
        });
        observation
    }

    pub fn validate(&self, scope: &XeroAccountingScope) -> Result<(), XeroAccountingError> {
        if self.contract_version != XERO_ACCOUNTING_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.consumer_id != MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_ID
            || self.consumer_version != XERO_ACCOUNTING_RESULT_PLUGIN_VERSION
            || self.scope_digest != scope.digest()
            || !self.read_only
            || self.connected
            || self.native
            || self.external_write_performed
            || self.financial_advice
            || self.kernel_authority
            || self.outcome_adoption
            || self.observation_digest
                != Digest::from_serializable(&ObservationMaterial {
                    contract_version: &self.contract_version,
                    contract_digest: &self.contract_digest,
                    consumer_id: &self.consumer_id,
                    consumer_version: &self.consumer_version,
                    status: self.status,
                    provenance: self.provenance,
                    scope_digest: &self.scope_digest,
                    provider_digest: &self.provider_digest,
                    api_digest: &self.api_digest,
                    permission_digest: &self.permission_digest,
                    revision_digest: &self.revision_digest,
                    evidence_digest: &self.evidence_digest,
                    read_only: self.read_only,
                    connected: self.connected,
                    native: self.native,
                    external_write_performed: self.external_write_performed,
                    financial_advice: self.financial_advice,
                    kernel_authority: self.kernel_authority,
                    outcome_adoption: self.outcome_adoption,
                })
        {
            return Err(XeroAccountingError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ObservationMaterial<'a> {
    contract_version: &'a str,
    contract_digest: &'a Digest,
    consumer_id: &'a str,
    consumer_version: &'a str,
    status: EvidenceStatus,
    provenance: EvidenceProvenance,
    scope_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    revision_digest: &'a Digest,
    evidence_digest: &'a Digest,
    read_only: bool,
    connected: bool,
    native: bool,
    external_write_performed: bool,
    financial_advice: bool,
    kernel_authority: bool,
    outcome_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionXeroAccountingReadResult {
    pub observation: MissionXeroAccountingObservation,
    pub evidence: XeroAccountingEvidence,
}

impl MissionXeroAccountingReadResult {
    pub fn validate(&self, scope: &XeroAccountingScope) -> Result<(), XeroAccountingError> {
        self.evidence.validate_for_scope(scope)?;
        self.observation.validate(scope)?;
        if self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.scope_digest != self.evidence.scope_digest
            || self.observation.status != self.evidence.status
            || self.observation.provenance != self.evidence.provenance
        {
            return Err(XeroAccountingError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionXeroAccountingConsumer {
    scope: XeroAccountingScope,
    contract_digest: Digest,
}

impl MissionXeroAccountingConsumer {
    pub fn new(scope: XeroAccountingScope) -> Self {
        Self {
            scope,
            contract_digest: crate::contract_digest(),
        }
    }

    pub fn scope(&self) -> &XeroAccountingScope {
        &self.scope
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn consume(
        &self,
        evidence: XeroAccountingEvidence,
    ) -> Result<MissionXeroAccountingReadResult, XeroAccountingError> {
        if evidence.contract_digest != self.contract_digest
            || evidence.scope_digest != self.scope.digest()
        {
            return Err(XeroAccountingError::StaleEvidence);
        }
        evidence.validate_for_scope(&self.scope)?;
        let result = MissionXeroAccountingReadResult {
            observation: MissionXeroAccountingObservation::from_evidence(&evidence),
            evidence,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read<T, R>(
        &self,
        service: &mut XeroAccountingResultService<T, R>,
        request: &XeroReadRequest,
        at: DateTime<Utc>,
    ) -> Result<MissionXeroAccountingReadResult, XeroAccountingError>
    where
        T: XeroTransport,
        R: OAuth2CredentialResolver,
    {
        if service.scope() != &self.scope {
            return Err(XeroAccountingError::ScopeMismatch(
                "Mission consumer and service scopes differ",
            ));
        }
        let evidence = service.read(request, at)?;
        self.consume(evidence)
    }
}
