use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AzureEventHubPostureResultError, Result};
use crate::model::{
    AzureEventHubEvidenceState, AzureEventHubPostureProjection, AzureEventHubPostureScope, Digest,
    MissionProjection, ProjectProjection, TransportProvenance, WorkProductProjection,
};
use crate::service::{AzureEventHubPostureProposal, AzureEventHubPostureRegistration};
use crate::{CONSUMER_ID, CONTRACT_DIGEST, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID};

/// A review disposition derived only from the bounded Layer-1 evidence state.
/// No disposition is an outcome or durable provider receipt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Ready,
    InProgress,
    Disabled,
    Partial,
    StaleState,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ApiDrift,
    ScopeDrift,
    PaginationLoop,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<AzureEventHubEvidenceState> for ProposalDisposition {
    fn from(state: AzureEventHubEvidenceState) -> Self {
        match state {
            AzureEventHubEvidenceState::Ready => Self::Ready,
            AzureEventHubEvidenceState::InProgress => Self::InProgress,
            AzureEventHubEvidenceState::Disabled => Self::Disabled,
            AzureEventHubEvidenceState::Partial => Self::Partial,
            AzureEventHubEvidenceState::StaleState => Self::StaleState,
            AzureEventHubEvidenceState::AccessLoss => Self::AccessLoss,
            AzureEventHubEvidenceState::Unauthorized => Self::Unauthorized,
            AzureEventHubEvidenceState::Forbidden => Self::Forbidden,
            AzureEventHubEvidenceState::NotFound => Self::NotFound,
            AzureEventHubEvidenceState::Conflict => Self::Conflict,
            AzureEventHubEvidenceState::Throttled => Self::Throttled,
            AzureEventHubEvidenceState::TimedOut => Self::TimedOut,
            AzureEventHubEvidenceState::ApiDrift => Self::ApiDrift,
            AzureEventHubEvidenceState::ScopeDrift => Self::ScopeDrift,
            AzureEventHubEvidenceState::PaginationLoop => Self::PaginationLoop,
            AzureEventHubEvidenceState::Tampered => Self::Tampered,
            AzureEventHubEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AzureEventHubEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAzureEventHubPostureResult {
    pub service_id: String,
    pub consumer_id: String,
    pub plugin_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AzureEventHubEvidenceState,
    pub disposition: ProposalDisposition,
    pub list_complete: bool,
    pub posture: Option<AzureEventHubPostureProjection>,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub review_only: bool,
    pub can_be_adopted: bool,
    pub result_digest: Digest,
}

impl MissionAzureEventHubPostureResult {
    fn from_proposal(proposal: &AzureEventHubPostureProposal) -> Self {
        let mut result = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_digest: Digest::from_text(CONTRACT_DIGEST),
            provider_id: PROVIDER_ID.to_owned(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            list_complete: proposal.list_complete,
            posture: proposal.posture.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            provenance: proposal.provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            review_only: true,
            can_be_adopted: false,
            result_digest: Digest::from_text("unsealed-azure-event-hub-posture-result"),
        };
        result.result_digest = result.calculate_digest();
        result
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_digest != Digest::from_text(CONTRACT_DIGEST)
            || self.provider_id != PROVIDER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || !self.review_only
            || self.can_be_adopted
            || self.result_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.evidence_digest.validate()?;
        if let Some(posture) = &self.posture {
            posture.validate_integrity()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-mission-posture-result/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission projection serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project projection serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product)
                        .expect("work product projection serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("disposition", format!("{:?}", self.disposition)),
                ("list_complete", self.list_complete.to_string()),
                (
                    "posture",
                    self.posture.as_ref().map_or_else(String::new, |posture| {
                        serde_json::to_string(posture).expect("posture serializes")
                    }),
                ),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

pub type MissionAzureEventHubPostureReadResult = MissionAzureEventHubPostureResult;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAzureEventHubPostureResult {
    pub idempotency_digest: Digest,
    pub proposal_digest: Digest,
    pub state: AzureEventHubEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub recording_digest: Digest,
}

impl RecordedAzureEventHubPostureResult {
    fn new(
        idempotency_digest: Digest,
        proposal: &AzureEventHubPostureProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_digest,
            proposal_digest: proposal.digest().clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            recording_digest: Digest::from_text("unsealed-azure-event-hub-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.idempotency_digest.validate()?;
        self.proposal_digest.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-recorded-result/v1",
            &[
                ("idempotency", self.idempotency_digest.as_str().to_owned()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("disposition", format!("{:?}", self.disposition)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

pub struct MissionAzureEventHubPostureConsumer {
    scope: AzureEventHubPostureScope,
    registration: AzureEventHubPostureRegistration,
    records: BTreeMap<Digest, RecordedAzureEventHubPostureResult>,
}

impl fmt::Debug for MissionAzureEventHubPostureConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAzureEventHubPostureConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAzureEventHubPostureConsumer {
    pub fn new(
        scope: AzureEventHubPostureScope,
        registration: AzureEventHubPostureRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AzureEventHubPostureResultError::RegistrationInactive);
        }
        if registration.secret_reference().is_revoked() {
            return Err(AzureEventHubPostureResultError::SecretRevoked);
        }
        if registration.scope().digest() != scope.digest() {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AzureEventHubPostureScope {
        &self.scope
    }

    pub fn registration(&self) -> &AzureEventHubPostureRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn recorded(
        &self,
        idempotency_key: impl AsRef<str>,
    ) -> Option<&RecordedAzureEventHubPostureResult> {
        let digest = idempotency_digest(idempotency_key.as_ref())?;
        self.records.get(&digest)
    }

    pub fn consume(
        &mut self,
        proposal: &AzureEventHubPostureProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<MissionAzureEventHubPostureResult> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AzureEventHubPostureResultError::RegistrationInactive);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AzureEventHubPostureResultError::SecretRevoked);
        }
        proposal.validate_integrity()?;
        self.validate_binding(proposal)?;
        let key = idempotency_key.into();
        let idempotency_digest =
            idempotency_digest(&key).ok_or(AzureEventHubPostureResultError::InvalidRequest)?;
        if self.records.contains_key(&idempotency_digest) {
            if self
                .records
                .get(&idempotency_digest)
                .is_none_or(|recorded| recorded.proposal_digest != *proposal.digest())
            {
                return Err(AzureEventHubPostureResultError::ReplayConflict);
            }
            let recorded = self
                .records
                .get_mut(&idempotency_digest)
                .ok_or(AzureEventHubPostureResultError::ReplayConflict)?;
            recorded.replayed = true;
            recorded.recording_digest = recorded.calculate_digest();
            recorded.validate_integrity()?;
            let result = MissionAzureEventHubPostureResult::from_proposal(proposal);
            result.validate_integrity()?;
            return Ok(result);
        }
        let recorded =
            RecordedAzureEventHubPostureResult::new(idempotency_digest.clone(), proposal, false);
        recorded.validate_integrity()?;
        self.records.insert(idempotency_digest, recorded);
        let result = MissionAzureEventHubPostureResult::from_proposal(proposal);
        result.validate_integrity()?;
        Ok(result)
    }

    fn validate_binding(&self, proposal: &AzureEventHubPostureProposal) -> Result<()> {
        let evidence = &proposal.evidence;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || evidence.contract_digest != *self.registration.contract_digest()
            || evidence.provider_digest != *self.registration.provider_digest()
            || evidence.api_digest != *self.registration.api_digest()
            || evidence.permission_digest != self.registration.permission_digest()
            || evidence.consent_digest != self.registration.consent_digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.tenant_digest != self.scope.tenant_digest()
            || evidence.subscription_digest != self.scope.subscription_digest()
            || evidence.resource_group_digest != self.scope.resource_group_digest()
            || evidence.namespace_digest != self.scope.namespace_digest()
            || evidence.event_hub_digest != self.scope.event_hub_digest()
            || evidence.consumer_group_digest != self.scope.consumer_group_digest()
            || proposal.mission.id_digest != self.scope.mission().id_digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.project.id_digest != self.scope.project().id_digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.work_product.id_digest != self.scope.work_product().id_digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        Ok(())
    }
}

fn idempotency_digest(value: &str) -> Option<Digest> {
    if value.is_empty() || value.len() > crate::MAX_IDENTIFIER_BYTES || value.trim() != value {
        return None;
    }
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(Digest::from_parts(
        "azure-event-hub-idempotency-key/v1",
        &[("key", value.to_owned())],
    ))
}
