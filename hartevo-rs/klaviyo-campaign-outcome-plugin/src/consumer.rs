use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID, KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID,
    model::{
        AdoptionAvailability, AggregateValue, Digest, KlaviyoRegistration, KlaviyoScope, MissionId,
        ModelError, ResourceId, Revision, Statistic,
    },
    service::{KlaviyoCampaignOutcomeProposal, OutcomeProjection},
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("the Mission Klaviyo consumer registration is revoked")]
    RegistrationRevoked,
    #[error("the Mission consumer binding does not match the exact service registration")]
    BindingMismatch,
    #[error("the proposal does not belong to the exact Mission, Project, or Work Product scope")]
    ScopeMismatch,
    #[error("the source proposal digest is invalid or stale")]
    StaleProposal,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerRegistration {
    pub consumer_id: String,
    pub service_id: String,
    pub scope_digest: Digest,
    pub source_registration_digest: Digest,
    pub registration_digest: Digest,
    pub active: bool,
}

impl ConsumerRegistration {
    fn new(
        scope: &KlaviyoScope,
        registration: &KlaviyoRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if registration.consumer_id.as_str() != KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID
            || registration.service_id.as_str() != KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID
            || registration.scope_digest != scope.scope_digest()
        {
            return Err(ConsumerError::BindingMismatch);
        }
        let registration_digest = Digest::from_fields(
            "klaviyo-consumer-registration/v1",
            &[
                KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID.to_owned(),
                KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID.to_owned(),
                registration.scope_digest.as_str().to_owned(),
                registration.registration_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            consumer_id: KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID.to_owned(),
            service_id: KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID.to_owned(),
            scope_digest: scope.scope_digest(),
            source_registration_digest: registration.registration_digest.clone(),
            registration_digest,
            active: true,
        })
    }

    fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            self.active = false;
            Ok(())
        } else {
            Err(ConsumerError::RegistrationRevoked)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionOutcomeState {
    PendingDecision,
    NoData,
    Partial,
    Expired,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionKlaviyoCampaignOutcome {
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub account_id: crate::AccountId,
    pub account_revision: Revision,
    pub resource: ResourceId,
    pub resource_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub state: MissionOutcomeState,
    pub delivery_state: crate::DeliveryState,
    pub metrics: std::collections::BTreeMap<Statistic, AggregateValue>,
    pub spend_minor_units: std::collections::BTreeMap<crate::CurrencyCode, i64>,
    pub source_result_digest: Digest,
    pub source_proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adoption: AdoptionAvailability,
}

impl MissionKlaviyoCampaignOutcome {
    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub fn metric(&self, statistic: Statistic) -> Option<&AggregateValue> {
        self.metrics.get(&statistic)
    }
}

pub struct MissionKlaviyoCampaignConsumer {
    scope: KlaviyoScope,
    registration: ConsumerRegistration,
}

impl fmt::Debug for MissionKlaviyoCampaignConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionKlaviyoCampaignConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .finish()
    }
}

impl MissionKlaviyoCampaignConsumer {
    pub fn new(
        scope: KlaviyoScope,
        registration: &KlaviyoRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate()?;
        let registration = ConsumerRegistration::new(&scope, registration)?;
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &KlaviyoScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.registration.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        self.registration.revoke()
    }

    pub fn unmount(&mut self) -> Result<(), ConsumerError> {
        self.revoke()
    }

    pub fn consume(
        &self,
        proposal: KlaviyoCampaignOutcomeProposal,
    ) -> Result<MissionKlaviyoCampaignOutcome, ConsumerError> {
        if !self.registration.active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if proposal.registration_digest != self.registration.source_registration_digest
            || proposal.evidence.digests.scope_digest != self.scope.scope_digest()
            || proposal.request.scope_digest != self.scope.scope_digest()
            || proposal.request.project_revision != self.scope.project_revision()
            || proposal.request.mission_revision != self.scope.mission_revision()
            || proposal.request.work_product_revision != self.scope.work_product_revision()
            || proposal.request.account_revision != self.scope.account_revision()
            || proposal.request.resource_revision != self.scope.resource_revision()
            || proposal.evidence.resource != self.scope.resource
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.proposal_digest.as_str().is_empty() {
            return Err(ConsumerError::StaleProposal);
        }
        let state = match proposal.projection {
            OutcomeProjection::Complete => MissionOutcomeState::PendingDecision,
            OutcomeProjection::NoData => MissionOutcomeState::NoData,
            OutcomeProjection::Partial => MissionOutcomeState::Partial,
            OutcomeProjection::Expired => MissionOutcomeState::Expired,
            OutcomeProjection::ProviderUnknown => MissionOutcomeState::ProviderUnknown,
        };
        Ok(MissionKlaviyoCampaignOutcome {
            project_id: self.scope.project_id.clone(),
            project_revision: self.scope.project_revision(),
            account_id: self.scope.account_id.clone(),
            account_revision: self.scope.account_revision(),
            resource: self.scope.resource.clone(),
            resource_revision: self.scope.resource_revision(),
            mission_id: self.scope.mission_id.clone(),
            mission_revision: self.scope.mission_revision(),
            work_product_id: self.scope.work_product_id.clone(),
            work_product_revision: self.scope.work_product_revision(),
            state,
            delivery_state: proposal.evidence.delivery_state,
            metrics: proposal.evidence.metrics,
            spend_minor_units: proposal.evidence.spend_minor_units,
            source_result_digest: proposal.evidence.digests.result_digest,
            source_proposal_digest: proposal.proposal_digest,
            connected: false,
            native: false,
            first_party: false,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }
}
