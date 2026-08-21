//! Mission/Project/Work Product consumer for BrowserStack evidence.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::{
    Authority, BrowserStackReadProposal, BrowserStackScope, BrowserStackTestResultEvidence, Digest,
    EvidenceStatus, Revision, TransportProvenance,
};
use crate::provider::BrowserStackCredentialResolver;
use crate::provider::{BrowserStackProvider, BrowserStackRegistration};
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
    #[serde(skip, default)]
    live_seal: bool,
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
            live_seal: true,
        };
        observation.observation_digest = observation.compute_digest()?;
        observation.validate(evidence)?;
        Ok(observation)
    }

    fn compute_digest(&self) -> Result<Digest, BrowserStackTestResultError> {
        Ok(crate::model::digest_serializable(&(
            &self.contract_version,
            &self.contract_digest,
            &self.consumer_id,
            &self.consumer_version,
            &self.scope_digest,
            &self.permission_digest,
            &self.registration_digest,
            &self.evidence_digest,
            self.provenance,
            self.read_only,
            self.proposal_only,
            self.connected,
            self.native,
            self.external_write_performed,
            self.kernel_authority,
        ))?)
    }

    pub fn validate(
        &self,
        evidence: &BrowserStackTestResultEvidence,
    ) -> Result<(), BrowserStackTestResultError> {
        if !self.live_seal
            || self.contract_version != BROWSERSTACK_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.consumer_id != MISSION_BROWSERSTACK_CONSUMER_ID
            || self.consumer_version != BROWSERSTACK_PLUGIN_VERSION_TEXT
            || self.scope_digest != evidence.scope_digest
            || self.permission_digest != evidence.permission_digest
            || self.registration_digest != evidence.registration_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.provenance != evidence.provenance
            || !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.external_write_performed
            || self.kernel_authority != Authority::default()
            || self.observation_digest != self.compute_digest()?
        {
            return Err(BrowserStackTestResultError::StaleEvidence);
        }
        Ok(())
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
    pub consumption_revision: Revision,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub evidence: BrowserStackTestResultEvidence,
    pub observation: BrowserStackObservation,
    #[serde(skip, default)]
    live_seal: bool,
}

impl MissionBrowserStackTestResult {
    pub fn validate(&self, scope: &BrowserStackScope) -> Result<(), BrowserStackTestResultError> {
        self.evidence.validate()?;
        self.observation.validate(&self.evidence)?;
        if !self.live_seal
            || self.evidence.scope_digest != *scope.digest()
            || self.evidence.permission_digest != *scope.permission().digest()
            || self.observation.scope_digest != *scope.digest()
            || self.observation.permission_digest != *scope.permission().digest()
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
            || self.state != expected_state(self.status)
            || self.consumption_revision.get() == 0
        {
            return Err(BrowserStackTestResultError::StaleEvidence);
        }
        Ok(())
    }

    fn validate_with_registration(
        &self,
        scope: &BrowserStackScope,
        registration: &BrowserStackRegistration,
    ) -> Result<(), BrowserStackTestResultError> {
        self.validate(scope)?;
        registration.validate_identity()?;
        registration.ensure_active()?;
        if self.evidence.registration_digest != *registration.registration_digest()
            || self.evidence.provider_digest != registration.provider_digest
            || self.evidence.scope_digest != *registration.scope_digest()
            || self.evidence.permission_digest != registration.permission_digest
        {
            return Err(BrowserStackTestResultError::ConsumerRegistrationMismatch);
        }
        registration
            .validate_evidence_use(&self.evidence.evidence_digest, self.consumption_revision)
    }

    pub fn validate_against_registration(
        &self,
        scope: &BrowserStackScope,
        registration: &BrowserStackRegistration,
    ) -> Result<(), BrowserStackTestResultError> {
        self.validate_with_registration(scope, registration)
    }
}

fn expected_state(status: EvidenceStatus) -> MissionBrowserStackResultState {
    match status {
        EvidenceStatus::Complete => MissionBrowserStackResultState::PendingDecision,
        EvidenceStatus::Partial
        | EvidenceStatus::AccessLost
        | EvidenceStatus::Expired
        | EvidenceStatus::ProviderUnknown => MissionBrowserStackResultState::Layer2AdoptionRequired,
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
        registration.validate_identity()?;
        registration.ensure_active()?;
        if registration.scope_digest != *scope.digest()
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

    pub fn is_active(&self) -> bool {
        self.active && self.registration.ensure_active().is_ok()
    }

    pub fn revoke(&mut self) -> Result<(), BrowserStackTestResultError> {
        if !self.active {
            return Err(BrowserStackTestResultError::ConsumerRevoked);
        }
        self.active = false;
        self.registration.revoke()?;
        Ok(())
    }

    pub fn consume(
        &self,
        evidence: BrowserStackTestResultEvidence,
    ) -> Result<MissionBrowserStackTestResult, BrowserStackTestResultError> {
        if !self.active {
            return Err(BrowserStackTestResultError::ConsumerRevoked);
        }
        self.registration.ensure_active()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.provider_digest != self.registration.provider_digest
            || evidence.scope_digest != self.registration.scope_digest
            || evidence.permission_digest != self.registration.permission_digest
        {
            return Err(BrowserStackTestResultError::ConsumerRegistrationMismatch);
        }
        evidence.validate()?;
        let observation = BrowserStackObservation::from_evidence(&evidence)?;
        let consumption_revision = self
            .registration
            .claim_evidence_use(&evidence.evidence_digest)?;
        let result = MissionBrowserStackTestResult {
            hartevo_project_id: self.scope.hartevo_project().id().to_owned(),
            hartevo_project_revision: self.scope.hartevo_project().revision().get(),
            mission_id: self.scope.mission().id().to_owned(),
            mission_revision: self.scope.mission().revision().get(),
            work_product_id: self.scope.work_product().id().to_owned(),
            work_product_revision: self.scope.work_product().revision().get(),
            state: expected_state(evidence.status),
            status: evidence.status,
            consumption_revision,
            proposal_only: true,
            connected: false,
            native: false,
            evidence,
            observation,
            live_seal: true,
        };
        result.validate_with_registration(&self.scope, &self.registration)?;
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
        if provider.scope() != &self.scope
            || provider.registration().registration_digest != self.registration.registration_digest
        {
            return Err(BrowserStackTestResultError::ScopeMismatch(
                "Mission consumer and BrowserStack provider scopes differ".to_owned(),
            ));
        }
        self.consume(provider.record_evidence(proposal, evidence)?)
    }
}
