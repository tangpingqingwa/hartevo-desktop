use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, MixpanelAnalyticsScope, MixpanelRegistration, ModelError, ProviderProvenance,
    RegistrationRevocation, ResultStatus, SecretReference,
};
use crate::provider::{
    MixpanelProvider, MixpanelProviderDefinition, MixpanelProviderError, MixpanelProviderEvidence,
    MixpanelTransport,
};
use crate::query::{MixpanelAnalyticsResultRequest, QueryError};
use crate::{
    MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION, MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT,
    MIXPANEL_ANALYTICS_RESULT_SERVICE_ID, contract_digest, service_version_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelServiceDefinition {
    pub id: String,
    pub version: String,
    pub contract_version: String,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub capabilities: Vec<String>,
}

impl MixpanelServiceDefinition {
    pub fn new() -> Self {
        Self {
            id: MIXPANEL_ANALYTICS_RESULT_SERVICE_ID.to_owned(),
            version: MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            read_only: true,
            live_execution: false,
            connected: false,
            native_provider: false,
            first_party: false,
            capabilities: vec![
                "mixpanel.analytics.result.register".to_owned(),
                "mixpanel.analytics.result.revoke_registration".to_owned(),
                "mixpanel.analytics.result.revoke_secret".to_owned(),
                "mixpanel.analytics.result.read_insights_aggregate".to_owned(),
                "mixpanel.analytics.result.propose".to_owned(),
                "mixpanel.analytics.result.consume".to_owned(),
            ],
        }
    }

    pub fn validate(&self) -> Result<(), MixpanelAnalyticsResultServiceError> {
        if self != &Self::new()
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native_provider
            || self.first_party
        {
            Err(MixpanelAnalyticsResultServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-service-definition/v1",
            &[
                self.id.clone(),
                self.version.clone(),
                self.contract_version.clone(),
                self.read_only.to_string(),
                self.live_execution.to_string(),
                self.connected.to_string(),
                self.native_provider.to_string(),
                self.first_party.to_string(),
                self.capabilities.join(","),
            ],
        )
    }
}

impl Default for MixpanelServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MixpanelAnalyticsResultServiceError {
    #[error("Mixpanel service definition drifted")]
    DefinitionDrift,
    #[error("Mixpanel registration is revoked")]
    RegistrationRevoked,
    #[error("Mixpanel SecretReference is revoked")]
    SecretRevoked,
    #[error("Mixpanel request is outside the registered Mission/Work Product scope")]
    RequestOutOfScope,
    #[error("Mixpanel idempotency key was reused for a different request")]
    IdempotencyConflict,
    #[error("Mixpanel provider evidence failed its digest, scope, or redaction fence")]
    InvalidEvidence,
    #[error("Mixpanel model is invalid: {0}")]
    Model(String),
    #[error("Mixpanel query is invalid: {0}")]
    Query(String),
    #[error("Mixpanel provider failed: {0}")]
    Provider(String),
}

impl From<ModelError> for MixpanelAnalyticsResultServiceError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

impl From<QueryError> for MixpanelAnalyticsResultServiceError {
    fn from(error: QueryError) -> Self {
        match error {
            QueryError::ScopeMismatch | QueryError::DigestMismatch => Self::RequestOutOfScope,
            QueryError::Model(error) => Self::Query(error.to_string()),
        }
    }
}

impl From<MixpanelProviderError> for MixpanelAnalyticsResultServiceError {
    fn from(error: MixpanelProviderError) -> Self {
        match error {
            MixpanelProviderError::DefinitionDrift => Self::DefinitionDrift,
            MixpanelProviderError::InvalidRequest(error) => Self::Query(error),
            MixpanelProviderError::ScopeMismatch => Self::RequestOutOfScope,
            MixpanelProviderError::SecretRevoked => Self::SecretRevoked,
            MixpanelProviderError::InvalidResponse => Self::InvalidEvidence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelAnalyticsResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub version_digest: Digest,
    pub service_version: String,
    pub service_definition_digest: Digest,
    pub provider_digest: Digest,
    pub project_digest: Digest,
    pub report_digest: Digest,
    pub date_window_digest: Digest,
    pub event_selector_digest: Digest,
    pub privacy_policy_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: crate::model::Revision,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub requested_at: crate::model::Timestamp,
    pub mission_revision: crate::model::Revision,
    pub work_product_revision: crate::model::Revision,
    pub provenance: ProviderProvenance,
    pub status: ResultStatus,
    pub request: MixpanelAnalyticsResultRequest,
    pub evidence: MixpanelProviderEvidence,
    pub evidence_digest: Digest,
    pub read_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub https_transport: bool,
    pub raw_events_included: bool,
    pub user_pii_included: bool,
    pub causal_claim: bool,
    pub outcome_authority: bool,
    pub proposal_digest: Digest,
}

impl MixpanelAnalyticsResultProposal {
    pub fn validate(
        &self,
        scope: &MixpanelAnalyticsScope,
        registration: &MixpanelRegistration,
        secret: &SecretReference,
        provider_definition: &MixpanelProviderDefinition,
    ) -> bool {
        registration.validate().is_ok()
            && !registration.is_revoked()
            && self.registration_digest == registration.registration_digest
            && self.secret_digest_matches(secret)
            && self.validate_integrity(scope, provider_definition)
            && self
                .evidence
                .validate(&self.request, scope, secret, provider_definition)
    }

    pub fn validate_integrity(
        &self,
        scope: &MixpanelAnalyticsScope,
        provider_definition: &MixpanelProviderDefinition,
    ) -> bool {
        self.contract_version == MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION
            && self.contract_digest == contract_digest()
            && self.version_digest == service_version_digest()
            && self.service_version == MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT
            && self.service_definition_digest == MixpanelServiceDefinition::new().digest()
            && self.provider_digest == provider_definition.provider_digest()
            && self.project_digest == scope.project().digest()
            && self.report_digest == scope.report_id().digest()
            && self.date_window_digest == scope.date_window().digest()
            && self.event_selector_digest == scope.event_selector().digest()
            && self.privacy_policy_digest == scope.privacy_policy().digest()
            && self.scope_digest == scope.digest()
            && self.query_digest == *self.request.request_digest()
            && self.idempotency_key_digest == *self.request.idempotency_key_digest()
            && self.request.requested_at() == self.requested_at
            && self.request.mission_revision() == self.mission_revision
            && self.request.work_product_revision() == self.work_product_revision
            && self.provenance == self.evidence.provenance
            && self.status == self.evidence.status
            && self.read_only
            && !self.connected
            && !self.native_provider
            && !self.first_party
            && !self.https_transport
            && !self.raw_events_included
            && !self.user_pii_included
            && !self.causal_claim
            && !self.outcome_authority
            && self.evidence.redactions.is_strict()
            && self
                .evidence
                .validate_without_secret(&self.request, scope, provider_definition)
            && compute_proposal_digest(self) == self.proposal_digest
    }

    fn secret_digest_matches(&self, secret: &SecretReference) -> bool {
        self.evidence.secret_reference_digest == secret.digest()
            && self.evidence.credential_revision == secret.credential_revision()
    }

    pub fn receipt(&self) -> MixpanelAnalyticsResultReceipt {
        let receipt_digest = Digest::from_fields(
            "mixpanel-result-receipt/v1",
            &[
                self.proposal_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                format!("{:?}", self.status),
            ],
        );
        MixpanelAnalyticsResultReceipt {
            receipt_digest,
            proposal_digest: self.proposal_digest.clone(),
            evidence_digest: self.evidence_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            query_digest: self.query_digest.clone(),
            status: self.status,
            provenance: self.provenance,
            deterministic: true,
            read_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            durable_native_receipt: false,
            adopted_work_product: false,
            adopted_outcome: false,
            truth_authority: false,
        }
    }

    pub const fn status(&self) -> ResultStatus {
        self.status
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelAnalyticsResultReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub status: ResultStatus,
    pub provenance: ProviderProvenance,
    pub deterministic: bool,
    pub read_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub durable_native_receipt: bool,
    pub adopted_work_product: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
}

pub struct MixpanelAnalyticsResultService<T>
where
    T: MixpanelTransport,
{
    service_definition: MixpanelServiceDefinition,
    provider: MixpanelProvider<T>,
    scope: MixpanelAnalyticsScope,
    secret: SecretReference,
    registration: MixpanelRegistration,
    idempotency: BTreeMap<Digest, (Digest, MixpanelAnalyticsResultProposal)>,
}

impl<T> fmt::Debug for MixpanelAnalyticsResultService<T>
where
    T: MixpanelTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MixpanelAnalyticsResultService")
            .field("service_definition", &self.service_definition)
            .field("provider", &self.provider)
            .field("scope", &self.scope)
            .field("secret", &"<opaque>")
            .field("registration", &self.registration)
            .field("idempotency_entries", &self.idempotency.len())
            .finish()
    }
}

impl<T> MixpanelAnalyticsResultService<T>
where
    T: MixpanelTransport,
{
    pub fn new(
        scope: MixpanelAnalyticsScope,
        secret: SecretReference,
        provider: MixpanelProvider<T>,
    ) -> Result<Self, MixpanelAnalyticsResultServiceError> {
        scope.validate()?;
        if !secret.matches_scope(&scope) {
            return Err(MixpanelAnalyticsResultServiceError::Model(
                ModelError::SecretScopeMismatch.to_string(),
            ));
        }
        let service_definition = MixpanelServiceDefinition::new();
        service_definition.validate()?;
        provider
            .definition()
            .validate()
            .map_err(|_| MixpanelAnalyticsResultServiceError::DefinitionDrift)?;
        let registration = MixpanelRegistration::new(
            &scope,
            &secret,
            provider.definition().provider_digest(),
            contract_digest(),
        )?;
        Ok(Self {
            service_definition,
            provider,
            scope,
            secret,
            registration,
            idempotency: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &MixpanelAnalyticsScope {
        &self.scope
    }

    pub fn provider(&self) -> &MixpanelProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut MixpanelProvider<T> {
        &mut self.provider
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &MixpanelRegistration {
        &self.registration
    }

    pub fn service_definition(&self) -> &MixpanelServiceDefinition {
        &self.service_definition
    }

    pub fn read(
        &mut self,
        request: MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelAnalyticsResultProposal, MixpanelAnalyticsResultServiceError> {
        self.service_definition.validate()?;
        if self.registration.is_revoked() {
            return Err(MixpanelAnalyticsResultServiceError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(MixpanelAnalyticsResultServiceError::SecretRevoked);
        }
        request.validate_against(&self.scope)?;
        let idempotency_key = request.idempotency_key_digest().clone();
        if let Some((request_digest, proposal)) = self.idempotency.get(&idempotency_key) {
            if request_digest != request.request_digest() {
                return Err(MixpanelAnalyticsResultServiceError::IdempotencyConflict);
            }
            return Ok(proposal.clone());
        }
        let evidence = self.provider.read(&request, &self.secret)?;
        if !evidence.validate(
            &request,
            &self.scope,
            &self.secret,
            self.provider.definition(),
        ) {
            return Err(MixpanelAnalyticsResultServiceError::InvalidEvidence);
        }
        let mut proposal = MixpanelAnalyticsResultProposal {
            contract_version: MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            version_digest: service_version_digest(),
            service_version: MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            service_definition_digest: self.service_definition.digest(),
            provider_digest: self.provider.definition().provider_digest(),
            project_digest: self.scope.project().digest(),
            report_digest: self.scope.report_id().digest(),
            date_window_digest: self.scope.date_window().digest(),
            event_selector_digest: self.scope.event_selector().digest(),
            privacy_policy_digest: self.scope.privacy_policy().digest(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            scope_digest: self.scope.digest(),
            query_digest: request.request_digest().clone(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            requested_at: request.requested_at(),
            mission_revision: request.mission_revision(),
            work_product_revision: request.work_product_revision(),
            provenance: evidence.provenance,
            status: evidence.status,
            request,
            evidence_digest: evidence.evidence_digest.clone(),
            evidence,
            read_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            https_transport: false,
            raw_events_included: false,
            user_pii_included: false,
            causal_claim: false,
            outcome_authority: false,
            proposal_digest: Digest::from_text("placeholder"),
        };
        proposal.proposal_digest = compute_proposal_digest(&proposal);
        if !proposal.validate(
            &self.scope,
            &self.registration,
            &self.secret,
            self.provider.definition(),
        ) {
            return Err(MixpanelAnalyticsResultServiceError::InvalidEvidence);
        }
        self.idempotency.insert(
            idempotency_key,
            (proposal.query_digest.clone(), proposal.clone()),
        );
        Ok(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, MixpanelAnalyticsResultServiceError> {
        self.registration.revoke().map_err(Into::into)
    }

    pub fn revoke_secret(&mut self) -> Result<(), MixpanelAnalyticsResultServiceError> {
        self.secret.revoke().map_err(Into::into)
    }
}

fn compute_proposal_digest(proposal: &MixpanelAnalyticsResultProposal) -> Digest {
    Digest::from_fields(
        "mixpanel-proposal/v1",
        &[
            proposal.contract_version.clone(),
            proposal.contract_digest.as_str().to_owned(),
            proposal.version_digest.as_str().to_owned(),
            proposal.service_version.clone(),
            proposal.service_definition_digest.as_str().to_owned(),
            proposal.provider_digest.as_str().to_owned(),
            proposal.project_digest.as_str().to_owned(),
            proposal.report_digest.as_str().to_owned(),
            proposal.date_window_digest.as_str().to_owned(),
            proposal.event_selector_digest.as_str().to_owned(),
            proposal.privacy_policy_digest.as_str().to_owned(),
            proposal.registration_digest.as_str().to_owned(),
            proposal.registration_revision.get().to_string(),
            proposal.scope_digest.as_str().to_owned(),
            proposal.query_digest.as_str().to_owned(),
            proposal.idempotency_key_digest.as_str().to_owned(),
            proposal.requested_at.seconds().to_string(),
            proposal.mission_revision.get().to_string(),
            proposal.work_product_revision.get().to_string(),
            format!("{:?}", proposal.provenance),
            format!("{:?}", proposal.status),
            proposal.evidence_digest.as_str().to_owned(),
            proposal.read_only.to_string(),
            proposal.connected.to_string(),
            proposal.native_provider.to_string(),
            proposal.first_party.to_string(),
            proposal.https_transport.to_string(),
            proposal.raw_events_included.to_string(),
            proposal.user_pii_included.to_string(),
            proposal.causal_claim.to_string(),
            proposal.outcome_authority.to_string(),
        ],
    )
}
