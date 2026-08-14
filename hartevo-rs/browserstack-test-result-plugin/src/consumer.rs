//! Mission/Project/Work Product consumer for BrowserStack evidence.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::{
    Authority, BrowserStackReadProposal, BrowserStackScope, BrowserStackTestResultEvidence, Digest,
    EvidenceStatus, TransportProvenance,
};
use crate::provider::BrowserStackCredentialResolver;
use crate::provider::{BrowserStackProvider, BrowserStackRegistration, RegistrationState};
use crate::transport::BrowserStackTransport;
use crate::{
    BROWSERSTACK_CONTRACT_VERSION, BROWSERSTACK_PLUGIN_VERSION_TEXT, BrowserStackTestResultError,
    MISSION_BROWSERSTACK_CONSUMER_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionBrowserStackResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_write_performed: bool,
    pub kernel_authority: Authority,
    pub observation_digest: Digest,
}

impl BrowserStackObservation {
    fn from_evidence(
        evidence: &BrowserStackTestResultEvidence,
    ) -> Result<Self, BrowserStackTestResultError> {
        let mut observation = Self {
            contract_version: BROWSERSTACK_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: MISSION_BROWSERSTACK_CONSUMER_ID.to_owned(),
            consumer_version: BROWSERSTACK_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            provenance: evidence.provenance,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            external_write_performed: false,
            kernel_authority: Authority::default(),
            observation_digest: Digest::from_text("pending"),
        };
        observation.observation_digest = crate::model::digest_serializable(&(
            &observation.contract_version,
            &observation.contract_digest,
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.scope_digest,
            &observation.permission_digest,
            &observation.registration_digest,
            &observation.evidence_digest,
            observation.provenance,
            observation.read_only,
            observation.proposal_only,
            observation.connected,
            observation.native,
            observation.external_write_performed,
            observation.kernel_authority,
        ))?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBrowserStackTestResult {
    pub hartevo_project_id: String,
    pub hartevo_project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub state: MissionBrowserStackResultState,
    pub status: EvidenceStatus,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub evidence: BrowserStackTestResultEvidence,
    pub observation: BrowserStackObservation,
}

impl MissionBrowserStackTestResult {
    pub fn validate(&self, scope: &BrowserStackScope) -> Result<(), BrowserStackTestResultError> {
        self.evidence.validate()?;
        if self.evidence.scope_digest != *scope.digest()
            || self.evidence.permission_digest != *scope.permission().digest()
            || self.observation.scope_digest != *scope.digest()
            || self.observation.permission_digest != *scope.permission().digest()
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.contract_digest != contract_digest()
            || self.observation.contract_version != BROWSERSTACK_CONTRACT_VERSION
            || self.observation.consumer_id != MISSION_BROWSERSTACK_CONSUMER_ID
            || !self.observation.read_only
            || !self.observation.proposal_only
            || self.observation.connected
            || self.observation.native
            || self.observation.external_write_performed
            || self.observation.kernel_authority != Authority::default()
            || !self.proposal_only
            || self.connected
            || self.native
            || self.evidence.authority != Authority::default()
            || self.hartevo_project_id != scope.hartevo_project().id()
            || self.hartevo_project_revision != scope.hartevo_project().revision().get()
            || self.mission_id != scope.mission().id()
            || self.mission_revision != scope.mission().revision().get()
            || self.work_product_id != scope.work_product().id()
            || self.work_product_revision != scope.work_product().revision().get()
            || self.status != self.evidence.status
        {
            return Err(BrowserStackTestResultError::StaleEvidence);
        }
        Ok(())
    }
}

pub struct MissionBrowserStackTestConsumer {
    scope: BrowserStackScope,
    registration: BrowserStackRegistration,
    active: bool,
}

impl fmt::Debug for MissionBrowserStackTestConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserStackTestConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("active", &self.active)
            .finish()
    }
}

impl MissionBrowserStackTestConsumer {
    pub fn new(
        scope: BrowserStackScope,
        registration: &BrowserStackRegistration,
    ) -> Result<Self, BrowserStackTestResultError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.digest()
            || registration.permission_digest != *scope.permission().digest()
        {
            return Err(BrowserStackTestResultError::ConsumerRegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
        })
    }

    pub fn scope(&self) -> &BrowserStackScope {
        &self.scope
    }

    pub fn registration(&self) -> &BrowserStackRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), BrowserStackTestResultError> {
        if !self.active {
            return Err(BrowserStackTestResultError::ConsumerRevoked);
        }
        self.active = false;
        self.registration.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn consume(
        &self,
        evidence: BrowserStackTestResultEvidence,
    ) -> Result<MissionBrowserStackTestResult, BrowserStackTestResultError> {
        if !self.active {
            return Err(BrowserStackTestResultError::ConsumerRevoked);
        }
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.scope_digest != self.registration.scope_digest
            || evidence.permission_digest != self.registration.permission_digest
        {
            return Err(BrowserStackTestResultError::ConsumerRegistrationMismatch);
        }
        evidence.validate()?;
        let observation = BrowserStackObservation::from_evidence(&evidence)?;
        let result = MissionBrowserStackTestResult {
            hartevo_project_id: self.scope.hartevo_project().id().to_owned(),
            hartevo_project_revision: self.scope.hartevo_project().revision().get(),
            mission_id: self.scope.mission().id().to_owned(),
            mission_revision: self.scope.mission().revision().get(),
            work_product_id: self.scope.work_product().id().to_owned(),
            work_product_revision: self.scope.work_product().revision().get(),
            state: match evidence.status {
                EvidenceStatus::Complete => MissionBrowserStackResultState::PendingDecision,
                EvidenceStatus::Partial
                | EvidenceStatus::AccessLost
                | EvidenceStatus::Expired
                | EvidenceStatus::ProviderUnknown => {
                    MissionBrowserStackResultState::Layer2AdoptionRequired
                }
            },
            status: evidence.status,
            proposal_only: true,
            connected: false,
            native: false,
            evidence,
            observation,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read<T, R>(
        &self,
        provider: &mut BrowserStackProvider<T, R>,
        proposal: &BrowserStackReadProposal,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<MissionBrowserStackTestResult, BrowserStackTestResultError>
    where
        T: BrowserStackTransport,
        R: BrowserStackCredentialResolver,
    {
        if provider.scope() != &self.scope
            || provider.registration().registration_digest != self.registration.registration_digest
        {
            return Err(BrowserStackTestResultError::ScopeMismatch(
                "Mission consumer and BrowserStack provider registration differ".to_owned(),
            ));
        }
        let evidence = provider.read(proposal, at)?;
        self.consume(evidence)
    }

    pub fn record<T, R>(
        &self,
        provider: &BrowserStackProvider<T, R>,
        proposal: &BrowserStackReadProposal,
        evidence: BrowserStackTestResultEvidence,
    ) -> Result<MissionBrowserStackTestResult, BrowserStackTestResultError>
    where
        T: BrowserStackTransport,
        R: BrowserStackCredentialResolver,
    {
        if provider.scope() != &self.scope {
            return Err(BrowserStackTestResultError::ScopeMismatch(
                "Mission consumer and BrowserStack provider scopes differ".to_owned(),
            ));
        }
        self.consume(provider.record_evidence(proposal, evidence)?)
    }
}
