//! Governed service orchestration, registration, and result projection.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CallMetadata, DateWindow, Digest, ExternalCrmContextIdentifiers,
    GONG_CONVERSATION_RESULT_CONTRACT_VERSION, GONG_CONVERSATION_RESULT_PLUGIN_ID,
    GONG_CONVERSATION_RESULT_SCHEMA_VERSION, GONG_CONVERSATION_RESULT_SERVICE_ID,
    GONG_PROVIDER_REVISION, GongConversationResultPluginDefinition, GongConversationScope,
    GongProvider, GongProviderDefinition, GongProviderError, GongReadOperation, GongReadPayload,
    GongReadRequest, GongReadStatus, GongTransport, GongTransportError, InteractionMetrics,
    MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID, MissionScope, PluginVersion, ProjectScope,
    ScorecardStatus, SecretReference, TopicsAndTrackers, canonical_digest, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GongServiceError {
    #[error("Gong conversation-result contract is invalid: {0}")]
    Contract(String),
    #[error("Gong conversation-result plugin definition is invalid")]
    InvalidDefinition,
    #[error(
        "Gong registration does not match the exact version, provider, scope, consent, and secret fence"
    )]
    RegistrationMismatch,
    #[error("Gong registration is revoked")]
    RegistrationRevoked,
    #[error("Gong scope does not match the Mission consumer or provider response")]
    ScopeMismatch,
    #[error("Gong response evidence was tampered with or stale")]
    TamperedEvidence,
    #[error("Gong response evidence was duplicated")]
    DuplicateEvidence,
    #[error("Gong provider definition drifted")]
    ProviderDrift,
    #[error("Gong provider request was outside the Layer-1 allowlist")]
    AllowlistViolation,
    #[error("Gong provider error: {0}")]
    Provider(#[from] GongProviderError),
    #[error("Gong transport error: {0}")]
    Transport(#[from] GongTransportError),
    #[error(transparent)]
    Model(#[from] crate::ModelError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub version: PluginVersion,
    pub provider_version: String,
    pub contract_digest: Digest,
    pub provider_capability_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

pub type GongRegistration = RegistrationReceipt;

impl RegistrationReceipt {
    pub(crate) fn new(
        definition: &GongConversationResultPluginDefinition,
        scope: &GongConversationScope,
        provider: &GongProviderDefinition,
        secret: &SecretReference,
        registration_revision: u64,
    ) -> Result<Self, GongServiceError> {
        if registration_revision == 0 {
            return Err(GongServiceError::RegistrationMismatch);
        }
        let mut receipt = Self {
            schema_version: GONG_CONVERSATION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GONG_CONVERSATION_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_id: GONG_CONVERSATION_RESULT_PLUGIN_ID.to_owned(),
            service_id: GONG_CONVERSATION_RESULT_SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            consumer_id: MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID.to_owned(),
            version: PluginVersion::V1,
            provider_version: provider.provider_version.clone(),
            contract_digest: contract_digest(),
            provider_capability_digest: provider.capability_digest.clone(),
            provider_digest: provider.provider_digest(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent.digest(),
            secret_reference_digest: secret.digest().clone(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::parse(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )?,
        };
        receipt.registration_digest = receipt.computed_digest();
        receipt.validate(definition, scope, provider, secret)?;
        Ok(receipt)
    }

    pub fn validate(
        &self,
        definition: &GongConversationResultPluginDefinition,
        scope: &GongConversationScope,
        provider: &GongProviderDefinition,
        secret: &SecretReference,
    ) -> Result<(), GongServiceError> {
        definition.validate()?;
        scope.validate()?;
        provider.validate()?;
        if self.schema_version != GONG_CONVERSATION_RESULT_SCHEMA_VERSION
            || self.contract_version != GONG_CONVERSATION_RESULT_CONTRACT_VERSION
            || self.plugin_id != GONG_CONVERSATION_RESULT_PLUGIN_ID
            || self.service_id != GONG_CONVERSATION_RESULT_SERVICE_ID
            || self.provider_id != provider.provider_id
            || self.consumer_id != MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID
            || self.version != PluginVersion::V1
            || self.provider_version != provider.provider_version
            || self.contract_digest != contract_digest()
            || self.provider_capability_digest != provider.capability_digest
            || self.provider_digest != provider.provider_digest()
            || self.scope_digest != scope.digest()
            || self.consent_digest != scope.consent.digest()
            || self.secret_reference_digest != *secret.digest()
            || self.registration_revision == 0
            || self.registration_digest != self.computed_digest()
        {
            return Err(GongServiceError::RegistrationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, GongServiceError> {
        if !self.is_active() {
            return Err(GongServiceError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&RegistrationFingerprint {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_id: &self.plugin_id,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            consumer_id: &self.consumer_id,
            version: self.version,
            provider_version: &self.provider_version,
            contract_digest: &self.contract_digest,
            provider_capability_digest: &self.provider_capability_digest,
            provider_digest: &self.provider_digest,
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationFingerprint<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    plugin_id: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    consumer_id: &'a str,
    version: PluginVersion,
    provider_version: &'a str,
    contract_digest: &'a Digest,
    provider_capability_digest: &'a Digest,
    provider_digest: &'a Digest,
    scope_digest: &'a Digest,
    consent_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: u64,
    status: RegistrationStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    MissingOperation,
    PageCap,
    ResponseBound,
    RateLimit,
    MissingData,
    ProviderError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GongConversationResultProjection {
    Analyzed,
    Processing,
    Partial(PartialReason),
    ConsentBlocked,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

pub type GongResultProjection = GongConversationResultProjection;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GongIssueCode {
    BlockedEnv,
    Unauthorized,
    Forbidden,
    RetentionGap,
    NotFound,
    RateLimited,
    DailyLimit,
    Timeout,
    ServerFailure,
    InvalidResponse,
    RequestTampered,
    DuplicateRequest,
    ResponseTooLarge,
    MutationForbidden,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongProviderIssue {
    pub operation: GongReadOperation,
    pub code: GongIssueCode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongResultEvidence {
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub call_revision: crate::Revision,
    pub analysis_revision: crate::Revision,
    pub call_metadata: Option<CallMetadata>,
    pub interaction_metrics: Option<InteractionMetrics>,
    pub topics_trackers: Option<TopicsAndTrackers>,
    pub action_item_counts: Option<crate::ActionItemCounts>,
    pub scorecard_status: Option<ScorecardStatus>,
    pub external_crm_context_identifiers: Option<ExternalCrmContextIdentifiers>,
    pub response_digests: Vec<Digest>,
    pub receipts: Vec<crate::GongResponseReceipt>,
    pub provider_issues: Vec<GongProviderIssue>,
    pub provider_provenance: crate::TransportProvenance,
    pub absence_is_not_deal_health_or_customer_intent: bool,
    pub native: bool,
    pub connected: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub evidence_digest: Digest,
}

impl GongResultEvidence {
    fn empty(scope: &GongConversationScope, provenance: crate::TransportProvenance) -> Self {
        let mut evidence = Self {
            scope_digest: scope.digest(),
            consent_digest: scope.consent.digest(),
            call_revision: scope.call_revision,
            analysis_revision: scope.analysis_revision,
            call_metadata: None,
            interaction_metrics: None,
            topics_trackers: None,
            action_item_counts: None,
            scorecard_status: None,
            external_crm_context_identifiers: None,
            response_digests: Vec::new(),
            receipts: Vec::new(),
            provider_issues: Vec::new(),
            provider_provenance: provenance,
            absence_is_not_deal_health_or_customer_intent: true,
            native: false,
            connected: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            evidence_digest: Digest::parse(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("zero digest is valid"),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence
    }

    pub fn validate_against(
        &self,
        scope: &GongConversationScope,
        registration: &RegistrationReceipt,
    ) -> Result<(), GongServiceError> {
        scope.validate()?;
        if self.scope_digest != scope.digest()
            || self.consent_digest != scope.consent.digest()
            || self.call_revision != scope.call_revision
            || self.analysis_revision != scope.analysis_revision
            || !self.absence_is_not_deal_health_or_customer_intent
            || self.native
            || self.connected
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.response_digests.len() != self.receipts.len()
            || self.evidence_digest != self.computed_digest()
            || (!registration.is_active() && self.response_digests.is_empty())
        {
            return Err(GongServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&GongEvidenceFingerprint {
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            call_revision: self.call_revision,
            analysis_revision: self.analysis_revision,
            call_metadata: self.call_metadata.as_ref(),
            interaction_metrics: self.interaction_metrics.as_ref(),
            topics_trackers: self.topics_trackers.as_ref(),
            action_item_counts: self.action_item_counts.as_ref(),
            scorecard_status: self.scorecard_status.as_ref(),
            external_crm_context_identifiers: self.external_crm_context_identifiers.as_ref(),
            response_digests: &self.response_digests,
            receipts: &self.receipts,
            provider_issues: &self.provider_issues,
            provider_provenance: self.provider_provenance,
            absence_is_not_deal_health_or_customer_intent: self
                .absence_is_not_deal_health_or_customer_intent,
            native: self.native,
            connected: self.connected,
            effect_authority: self.effect_authority,
            receipt_authority: self.receipt_authority,
            verification_authority: self.verification_authority,
            outcome_authority: self.outcome_authority,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GongEvidenceFingerprint<'a> {
    scope_digest: &'a Digest,
    consent_digest: &'a Digest,
    call_revision: crate::Revision,
    analysis_revision: crate::Revision,
    call_metadata: Option<&'a CallMetadata>,
    interaction_metrics: Option<&'a InteractionMetrics>,
    topics_trackers: Option<&'a TopicsAndTrackers>,
    action_item_counts: Option<&'a crate::ActionItemCounts>,
    scorecard_status: Option<&'a ScorecardStatus>,
    external_crm_context_identifiers: Option<&'a ExternalCrmContextIdentifiers>,
    response_digests: &'a [Digest],
    receipts: &'a [crate::GongResponseReceipt],
    provider_issues: &'a [GongProviderIssue],
    provider_provenance: crate::TransportProvenance,
    absence_is_not_deal_health_or_customer_intent: bool,
    native: bool,
    connected: bool,
    effect_authority: bool,
    receipt_authority: bool,
    verification_authority: bool,
    outcome_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongConversationResultProposal {
    pub consumer_id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provider_digest: Digest,
    pub projection: GongConversationResultProjection,
    pub evidence: GongResultEvidence,
    pub native: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub deal_health: Option<bool>,
    pub customer_intent: Option<bool>,
    pub proposal_digest: Digest,
}

impl GongConversationResultProposal {
    fn new(
        scope: &GongConversationScope,
        registration: &RegistrationReceipt,
        provider: &GongProviderDefinition,
        projection: GongConversationResultProjection,
        evidence: GongResultEvidence,
    ) -> Self {
        let mut proposal = Self {
            consumer_id: MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID.to_owned(),
            service_id: GONG_CONVERSATION_RESULT_SERVICE_ID.to_owned(),
            version: PluginVersion::V1,
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent.digest(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_digest: provider.provider_digest(),
            projection,
            evidence,
            native: false,
            connected: false,
            outcome_authority: false,
            deal_health: None,
            customer_intent: None,
            proposal_digest: Digest::parse(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("zero digest is valid"),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn validate_against(
        &self,
        scope: &GongConversationScope,
        registration: &RegistrationReceipt,
        provider: &GongProviderDefinition,
    ) -> Result<(), GongServiceError> {
        registration
            .validate(
                &GongConversationResultPluginDefinition::layer1()?,
                scope,
                provider,
                &SecretReference::new("validation-only", 1)?,
            )
            .or_else(|_| {
                if registration.scope_digest == scope.digest()
                    && registration.provider_digest == provider.provider_digest()
                    && registration.contract_digest == contract_digest()
                {
                    Ok(())
                } else {
                    Err(GongServiceError::RegistrationMismatch)
                }
            })?;
        self.evidence.validate_against(scope, registration)?;
        if self.consumer_id != MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID
            || self.service_id != GONG_CONVERSATION_RESULT_SERVICE_ID
            || self.version != PluginVersion::V1
            || self.scope_digest != scope.digest()
            || self.consent_digest != scope.consent.digest()
            || self.registration_digest != registration.registration_digest
            || self.registration_revision != registration.registration_revision
            || self.provider_digest != provider.provider_digest()
            || self.native
            || self.connected
            || self.outcome_authority
            || self.deal_health.is_some()
            || self.customer_intent.is_some()
            || self.proposal_digest != self.computed_digest()
        {
            return Err(GongServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub(crate) fn validate_for_consumer(
        &self,
        scope: &GongConversationScope,
        registration_digest: &Digest,
        registration_revision: u64,
        provider_digest: &Digest,
    ) -> Result<(), GongServiceError> {
        if self.consumer_id != MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID
            || self.service_id != GONG_CONVERSATION_RESULT_SERVICE_ID
            || self.version != PluginVersion::V1
            || self.scope_digest != scope.digest()
            || self.consent_digest != scope.consent.digest()
            || self.registration_digest != *registration_digest
            || self.registration_revision != registration_revision
            || self.provider_digest != *provider_digest
            || self.native
            || self.connected
            || self.outcome_authority
            || self.deal_health.is_some()
            || self.customer_intent.is_some()
            || self.proposal_digest != self.computed_digest()
        {
            return Err(GongServiceError::TamperedEvidence);
        }
        self.evidence.validate_against(
            scope,
            &RegistrationReceipt {
                schema_version: GONG_CONVERSATION_RESULT_SCHEMA_VERSION.to_owned(),
                contract_version: GONG_CONVERSATION_RESULT_CONTRACT_VERSION.to_owned(),
                plugin_id: GONG_CONVERSATION_RESULT_PLUGIN_ID.to_owned(),
                service_id: GONG_CONVERSATION_RESULT_SERVICE_ID.to_owned(),
                provider_id: "consumer-bound".to_owned(),
                consumer_id: MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID.to_owned(),
                version: PluginVersion::V1,
                provider_version: GONG_PROVIDER_REVISION.to_owned(),
                contract_digest: contract_digest(),
                provider_capability_digest: Digest::parse(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )?,
                provider_digest: provider_digest.clone(),
                scope_digest: scope.digest(),
                consent_digest: scope.consent.digest(),
                secret_reference_digest: Digest::parse(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )?,
                registration_revision,
                status: RegistrationStatus::Active,
                registration_digest: registration_digest.clone(),
            },
        )?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&GongProposalFingerprint {
            consumer_id: &self.consumer_id,
            service_id: &self.service_id,
            version: self.version,
            project: &self.project,
            mission: &self.mission,
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_digest: &self.provider_digest,
            projection: self.projection,
            evidence: &self.evidence,
            native: self.native,
            connected: self.connected,
            outcome_authority: self.outcome_authority,
            deal_health: self.deal_health,
            customer_intent: self.customer_intent,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GongProposalFingerprint<'a> {
    consumer_id: &'a str,
    service_id: &'a str,
    version: PluginVersion,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    scope_digest: &'a Digest,
    consent_digest: &'a Digest,
    registration_digest: &'a Digest,
    registration_revision: u64,
    provider_digest: &'a Digest,
    projection: GongConversationResultProjection,
    evidence: &'a GongResultEvidence,
    native: bool,
    connected: bool,
    outcome_authority: bool,
    deal_health: Option<bool>,
    customer_intent: Option<bool>,
}

pub struct GongConversationResultService<T = crate::BlockedEnvTransport>
where
    T: GongTransport,
{
    scope: GongConversationScope,
    secret_reference: SecretReference,
    provider: GongProvider<T>,
    definition: GongConversationResultPluginDefinition,
    registration: RegistrationReceipt,
    date_window: Option<DateWindow>,
    requested_at_epoch_seconds: u64,
}

impl<T> fmt::Debug for GongConversationResultService<T>
where
    T: GongTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GongConversationResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("date_window", &self.date_window)
            .finish_non_exhaustive()
    }
}

impl<T> GongConversationResultService<T>
where
    T: GongTransport,
{
    pub fn new(
        scope: GongConversationScope,
        secret_reference: SecretReference,
        provider: GongProvider<T>,
        date_window: Option<DateWindow>,
        requested_at_epoch_seconds: u64,
    ) -> Result<Self, GongServiceError> {
        Self::new_with_registration_revision(
            scope,
            secret_reference,
            provider,
            date_window,
            requested_at_epoch_seconds,
            1,
        )
    }

    pub fn new_with_registration_revision(
        scope: GongConversationScope,
        secret_reference: SecretReference,
        provider: GongProvider<T>,
        date_window: Option<DateWindow>,
        requested_at_epoch_seconds: u64,
        registration_revision: u64,
    ) -> Result<Self, GongServiceError> {
        scope.validate()?;
        if let Some(window) = &date_window {
            window.validate()?;
        }
        let mut definition = GongConversationResultPluginDefinition::layer1()?;
        definition.provider = provider.definition().clone();
        definition.validate()?;
        let registration = definition.bind(
            scope.clone(),
            provider.definition(),
            &secret_reference,
            registration_revision,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            definition,
            registration,
            date_window,
            requested_at_epoch_seconds,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GongConversationScope {
        &self.scope
    }

    #[must_use]
    pub fn provider(&self) -> &GongProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GongProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn definition(&self) -> &GongConversationResultPluginDefinition {
        &self.definition
    }

    #[must_use]
    pub fn registration(&self) -> &RegistrationReceipt {
        &self.registration
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, GongServiceError> {
        self.registration.revoke()
    }

    pub fn propose(&mut self) -> Result<GongConversationResultProposal, GongServiceError> {
        self.propose_at(self.requested_at_epoch_seconds)
    }

    pub fn propose_at(
        &mut self,
        requested_at_epoch_seconds: u64,
    ) -> Result<GongConversationResultProposal, GongServiceError> {
        self.active_registration()?;
        if !self.scope.consent.is_granted() {
            let evidence = GongResultEvidence::empty(&self.scope, self.provider.provenance());
            return Ok(GongConversationResultProposal::new(
                &self.scope,
                &self.registration,
                self.provider.definition(),
                GongConversationResultProjection::ConsentBlocked,
                evidence,
            ));
        }

        let operations = [
            GongReadOperation::CallMetadata,
            GongReadOperation::InteractionMetrics,
            GongReadOperation::TopicsTrackers,
            GongReadOperation::ActionItemCounts,
            GongReadOperation::ScorecardStatus,
            GongReadOperation::ExternalCrmContextIdentifiers,
        ];
        let mut evidence = GongResultEvidence::empty(&self.scope, self.provider.provenance());
        let mut seen_responses = BTreeSet::new();
        let mut saw_processing = false;
        let mut saw_retention_gap = false;
        let mut saw_access_lost = false;
        let mut saw_provider_unknown = false;
        let mut incomplete = false;

        for (index, operation) in operations.into_iter().enumerate() {
            let request = GongReadRequest::bound(
                &self.scope,
                operation,
                self.date_window.clone(),
                &self.secret_reference,
                &self.registration.registration_digest,
                &self.provider.definition().capability_digest,
                requested_at_epoch_seconds.saturating_add((index / 3) as u64),
            )?;
            match self.provider.read(&request) {
                Ok(response) => {
                    if !seen_responses.insert(response.response_digest.clone()) {
                        return Err(GongServiceError::DuplicateEvidence);
                    }
                    response
                        .validate_against(&request, &self.scope, GONG_PROVIDER_REVISION)
                        .map_err(|_| GongServiceError::TamperedEvidence)?;
                    if !response.complete {
                        incomplete = true;
                    }
                    match response.status {
                        GongReadStatus::Analyzed => {}
                        GongReadStatus::Processing => saw_processing = true,
                        GongReadStatus::RetentionGap => saw_retention_gap = true,
                    }
                    evidence
                        .response_digests
                        .push(response.response_digest.clone());
                    evidence.receipts.push(response.receipt.clone());
                    absorb_payload(&mut evidence, response.payload);
                }
                Err(error) => {
                    let code = issue_code(&error);
                    evidence
                        .provider_issues
                        .push(GongProviderIssue { operation, code });
                    match classify_error(&error) {
                        ErrorProjection::RetentionGap => saw_retention_gap = true,
                        ErrorProjection::AccessLost => saw_access_lost = true,
                        ErrorProjection::ProviderUnknown => saw_provider_unknown = true,
                        ErrorProjection::Partial => incomplete = true,
                        ErrorProjection::FailClosed => return Err(error.into()),
                    }
                }
            }
        }

        let successful_operations = evidence.response_digests.len();
        let projection = if saw_access_lost && successful_operations == 0 {
            GongConversationResultProjection::AccessLost
        } else if saw_retention_gap && successful_operations == 0 {
            GongConversationResultProjection::RetentionGap
        } else if saw_provider_unknown && successful_operations == 0 {
            GongConversationResultProjection::ProviderUnknown
        } else if saw_processing {
            GongConversationResultProjection::Processing
        } else if incomplete
            || successful_operations < operations.len()
            || !evidence.provider_issues.is_empty()
        {
            GongConversationResultProjection::Partial(PartialReason::MissingOperation)
        } else {
            GongConversationResultProjection::Analyzed
        };
        evidence.evidence_digest = evidence.computed_digest();
        Ok(GongConversationResultProposal::new(
            &self.scope,
            &self.registration,
            self.provider.definition(),
            projection,
            evidence,
        ))
    }

    pub fn read(&mut self) -> Result<GongConversationResultProposal, GongServiceError> {
        self.propose()
    }

    fn active_registration(&self) -> Result<(), GongServiceError> {
        if !self.registration.is_active() {
            return Err(GongServiceError::RegistrationRevoked);
        }
        self.registration.validate(
            &self.definition,
            &self.scope,
            self.provider.definition(),
            &self.secret_reference,
        )
    }
}

fn absorb_payload(evidence: &mut GongResultEvidence, payload: GongReadPayload) {
    match payload {
        GongReadPayload::CallMetadata(value) => evidence.call_metadata = Some(value),
        GongReadPayload::InteractionMetrics(value) => evidence.interaction_metrics = Some(value),
        GongReadPayload::TopicsTrackers(value) => evidence.topics_trackers = Some(value),
        GongReadPayload::ActionItemCounts(value) => evidence.action_item_counts = Some(value),
        GongReadPayload::ScorecardStatus(value) => evidence.scorecard_status = Some(value),
        GongReadPayload::ExternalCrmContextIdentifiers(value) => {
            evidence.external_crm_context_identifiers = Some(value);
        }
        GongReadPayload::Empty => {}
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorProjection {
    RetentionGap,
    AccessLost,
    ProviderUnknown,
    Partial,
    FailClosed,
}

fn classify_error(error: &GongProviderError) -> ErrorProjection {
    match error {
        GongProviderError::Transport(transport) => match transport {
            GongTransportError::BlockedEnv
            | GongTransportError::Unauthorized
            | GongTransportError::Forbidden => ErrorProjection::AccessLost,
            GongTransportError::RetentionGap | GongTransportError::NotFound => {
                ErrorProjection::RetentionGap
            }
            GongTransportError::RateLimited { .. } | GongTransportError::DailyLimit => {
                ErrorProjection::ProviderUnknown
            }
            GongTransportError::Timeout | GongTransportError::ServerFailure { .. } => {
                ErrorProjection::ProviderUnknown
            }
            GongTransportError::InvalidResponse | GongTransportError::ResponseTooLarge => {
                ErrorProjection::Partial
            }
            GongTransportError::RequestTampered
            | GongTransportError::DuplicateRequest
            | GongTransportError::MutationForbidden => ErrorProjection::FailClosed,
        },
        GongProviderError::BudgetExceeded => ErrorProjection::ProviderUnknown,
        GongProviderError::CapabilityDrift
        | GongProviderError::InvalidDefinition
        | GongProviderError::DuplicateRequest
        | GongProviderError::InvalidResponseBinding
        | GongProviderError::Model(_) => ErrorProjection::FailClosed,
    }
}

fn issue_code(error: &GongProviderError) -> GongIssueCode {
    match error {
        GongProviderError::Transport(transport) => match transport {
            GongTransportError::BlockedEnv => GongIssueCode::BlockedEnv,
            GongTransportError::Unauthorized => GongIssueCode::Unauthorized,
            GongTransportError::Forbidden => GongIssueCode::Forbidden,
            GongTransportError::RetentionGap => GongIssueCode::RetentionGap,
            GongTransportError::NotFound => GongIssueCode::NotFound,
            GongTransportError::RateLimited { .. } => GongIssueCode::RateLimited,
            GongTransportError::DailyLimit => GongIssueCode::DailyLimit,
            GongTransportError::Timeout => GongIssueCode::Timeout,
            GongTransportError::ServerFailure { .. } => GongIssueCode::ServerFailure,
            GongTransportError::InvalidResponse => GongIssueCode::InvalidResponse,
            GongTransportError::RequestTampered => GongIssueCode::RequestTampered,
            GongTransportError::DuplicateRequest => GongIssueCode::DuplicateRequest,
            GongTransportError::ResponseTooLarge => GongIssueCode::ResponseTooLarge,
            GongTransportError::MutationForbidden => GongIssueCode::MutationForbidden,
        },
        GongProviderError::BudgetExceeded | GongProviderError::CapabilityDrift => {
            GongIssueCode::ProviderUnknown
        }
        GongProviderError::InvalidDefinition
        | GongProviderError::DuplicateRequest
        | GongProviderError::InvalidResponseBinding
        | GongProviderError::Model(_) => GongIssueCode::InvalidResponse,
    }
}
