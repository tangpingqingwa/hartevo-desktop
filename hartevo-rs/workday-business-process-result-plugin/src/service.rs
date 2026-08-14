//! Typed service descriptor and Mission-facing result proposal.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, MissionResultState, WorkdayBusinessProcessResultEvidence, WorkdayReadRequest,
    WorkdayScope,
};
use crate::provider::{WorkdayProvider, WorkdayRegistration};
use crate::transport::WorkdayTransport;
use crate::{
    Layer1Authority, WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_ID,
    WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_NAME, WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_SCHEMA,
    WorkdayError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkdayBusinessProcessResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadEvents,
    ReadRaas,
    ReadWql,
    ConsumeResult,
    PrepareEffect,
    PrepareReadBack,
}

impl WorkdayBusinessProcessResultOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadEvents,
        Self::ReadRaas,
        Self::ReadWql,
        Self::ConsumeResult,
        Self::PrepareEffect,
        Self::PrepareReadBack,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayCapability {
    pub capability_id: String,
    pub operation: WorkdayBusinessProcessResultOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkdayBusinessProcessResultService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<WorkdayCapability>,
}

impl Default for WorkdayBusinessProcessResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkdayBusinessProcessResultService {
    pub fn new() -> Self {
        let capability_ids = [
            (
                "workday.business-process.result.register",
                WorkdayBusinessProcessResultOperation::Register,
            ),
            (
                "workday.business-process.result.revoke_registration",
                WorkdayBusinessProcessResultOperation::RevokeRegistration,
            ),
            (
                "workday.business-process.result.read_events",
                WorkdayBusinessProcessResultOperation::ReadEvents,
            ),
            (
                "workday.business-process.result.read_raas",
                WorkdayBusinessProcessResultOperation::ReadRaas,
            ),
            (
                "workday.business-process.result.read_wql",
                WorkdayBusinessProcessResultOperation::ReadWql,
            ),
            (
                "workday.business-process.result.consume_result",
                WorkdayBusinessProcessResultOperation::ConsumeResult,
            ),
            (
                "workday.business-process.result.prepare_effect",
                WorkdayBusinessProcessResultOperation::PrepareEffect,
            ),
            (
                "workday.business-process.result.prepare_read_back",
                WorkdayBusinessProcessResultOperation::PrepareReadBack,
            ),
        ];
        let capabilities = capability_ids
            .into_iter()
            .map(|(capability_id, operation)| WorkdayCapability {
                capability_id: capability_id.to_owned(),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect();
        Self {
            service_id: WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_ID.to_owned(),
            service_name: WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[WorkdayCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<WorkdayCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, WorkdayError> {
        let service_id = ServiceId::new(self.service_id.clone()).map_err(WorkdayError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(WorkdayError::Plugin)
    }

    pub fn validate(&self) -> Result<(), WorkdayError> {
        if self.service_id != WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_ID
            || self.service_name != WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.len() != WorkdayBusinessProcessResultOperation::ALL.len() - 1
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(WorkdayError::InvalidInput(
                "Workday service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn register<T>(
        &self,
        provider: &WorkdayProvider<T>,
        scope: &WorkdayScope,
        secret: &crate::model::SecretReference,
    ) -> Result<WorkdayRegistration, WorkdayError>
    where
        T: WorkdayTransport,
    {
        self.validate()?;
        provider.register(scope, secret)
    }

    pub fn revoke_registration(
        &self,
        provider: &impl WorkdayProviderOperations,
        registration: &mut WorkdayRegistration,
    ) -> Result<(), WorkdayError> {
        self.validate()?;
        provider.revoke_registration(registration)
    }

    pub fn propose<T>(
        &self,
        provider: &mut WorkdayProvider<T>,
        scope: &WorkdayScope,
        secret: &crate::model::SecretReference,
        registration: &WorkdayRegistration,
        request: &WorkdayReadRequest,
    ) -> Result<WorkdayBusinessProcessResultProposal, WorkdayError>
    where
        T: WorkdayTransport,
    {
        self.validate()?;
        let evidence = provider.read(scope, secret, registration, request)?;
        WorkdayBusinessProcessResultProposal::from_evidence(
            evidence,
            registration,
            secret.reference_digest(),
        )
    }
}

pub trait WorkdayProviderOperations {
    fn revoke_registration(
        &self,
        registration: &mut WorkdayRegistration,
    ) -> Result<(), WorkdayError>;
}

impl<T> WorkdayProviderOperations for WorkdayProvider<T>
where
    T: WorkdayTransport,
{
    fn revoke_registration(
        &self,
        registration: &mut WorkdayRegistration,
    ) -> Result<(), WorkdayError> {
        WorkdayProvider::revoke_registration(self, registration)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkdayDecisionAction {
    ContinueMonitoring,
    ReviewCompletion,
    ReviewCancellation,
    EscalateAccess,
    ReviewProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayDecisionProposal {
    pub action: WorkdayDecisionAction,
    pub observed_state: MissionResultState,
    pub reason: String,
    pub effect_allowed: bool,
}

impl WorkdayDecisionProposal {
    fn from_evidence(evidence: &WorkdayBusinessProcessResultEvidence) -> Self {
        let observed_state = evidence.mission_state();
        let (action, reason) = match observed_state {
            MissionResultState::Completed => (
                WorkdayDecisionAction::ReviewCompletion,
                "completed evidence is available for Mission review".to_owned(),
            ),
            MissionResultState::Cancelled | MissionResultState::Rescinded => (
                WorkdayDecisionAction::ReviewCancellation,
                "cancelled or rescinded evidence is available for Mission review".to_owned(),
            ),
            MissionResultState::AccessLost => (
                WorkdayDecisionAction::EscalateAccess,
                "provider access was lost; no business-process conclusion is proposed".to_owned(),
            ),
            MissionResultState::ProviderUnknown => (
                WorkdayDecisionAction::ReviewProviderUnknown,
                "Workday returned a status outside the allowlisted status vocabulary".to_owned(),
            ),
            MissionResultState::Overdue => (
                WorkdayDecisionAction::ContinueMonitoring,
                "the bounded event is overdue and requires a later Mission decision".to_owned(),
            ),
            MissionResultState::Partial
            | MissionResultState::Redacted
            | MissionResultState::Initiated
            | MissionResultState::Due
            | MissionResultState::InProgress
            | MissionResultState::Remaining => (
                WorkdayDecisionAction::ContinueMonitoring,
                "bounded read evidence is available without effect authority".to_owned(),
            ),
        };
        Self {
            action,
            observed_state,
            reason,
            effect_allowed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectAvailability {
    DeferredLayer2,
    NotAvailableLayer1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkdayEffectKind {
    NoMutationLayer1,
    SubmitEventLayer2,
    CancelEventLayer2,
    RescindEventLayer2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayEffectProposal {
    pub kind: WorkdayEffectKind,
    pub availability: EffectAvailability,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub native: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptAvailability {
    ProviderEvidenceOnly,
    NativeReceiptDeferredLayer2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadBackAvailability {
    DeferredLayer2,
    NotRequestedLayer1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayReadBackProposal {
    pub availability: ReadBackAvailability,
    pub expected_scope_digest: Digest,
    pub expected_event_revision: Option<crate::model::Revision>,
    pub source_evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayBusinessProcessResultProposal {
    pub evidence: WorkdayBusinessProcessResultEvidence,
    pub registration_digest: Digest,
    pub secret_reference_digest: Digest,
    pub decision: WorkdayDecisionProposal,
    pub effect: WorkdayEffectProposal,
    pub receipt: ReceiptAvailability,
    pub read_back: WorkdayReadBackProposal,
    pub adopted: bool,
    pub authority: Layer1AuthorityView,
    pub proposal_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer1AuthorityView {
    pub connected: bool,
    pub native_provider: bool,
    pub effect: bool,
    pub native_receipt: bool,
    pub exact_read_back: bool,
    pub adopted_outcome: bool,
    pub work_product_adoption: bool,
}

impl Layer1AuthorityView {
    pub const fn current() -> Self {
        Self {
            connected: false,
            native_provider: false,
            effect: false,
            native_receipt: false,
            exact_read_back: false,
            adopted_outcome: false,
            work_product_adoption: false,
        }
    }
}

impl WorkdayBusinessProcessResultProposal {
    fn from_evidence(
        evidence: WorkdayBusinessProcessResultEvidence,
        registration: &WorkdayRegistration,
        secret_reference_digest: &Digest,
    ) -> Result<Self, WorkdayError> {
        evidence
            .validate_digest()
            .map_err(|_| WorkdayError::EvidenceDigestMismatch)?;
        let decision = WorkdayDecisionProposal::from_evidence(&evidence);
        let effect = WorkdayEffectProposal {
            kind: WorkdayEffectKind::NoMutationLayer1,
            availability: EffectAvailability::NotAvailableLayer1,
            scope_digest: evidence.scope_digest.clone(),
            consent_digest: evidence.consent_digest.clone(),
            native: false,
        };
        let read_back = WorkdayReadBackProposal {
            availability: ReadBackAvailability::DeferredLayer2,
            expected_scope_digest: evidence.scope_digest.clone(),
            expected_event_revision: evidence.event.as_ref().map(|event| event.event_revision),
            source_evidence_digest: evidence.evidence_digest.clone(),
        };
        let mut proposal = Self {
            evidence,
            registration_digest: registration.registration_digest.clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            decision,
            effect,
            receipt: ReceiptAvailability::ProviderEvidenceOnly,
            read_back,
            adopted: false,
            authority: Layer1AuthorityView::current(),
            proposal_digest: Digest::from_text("uncomputed"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "workday-business-process-proposal/v1",
            &[
                self.evidence.evidence_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                serde_json::to_string(&self.decision).unwrap_or_default(),
                serde_json::to_string(&self.effect).unwrap_or_default(),
                format!("{:?}", self.receipt),
                serde_json::to_string(&self.read_back).unwrap_or_default(),
                self.adopted.to_string(),
                serde_json::to_string(&self.authority).unwrap_or_default(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), WorkdayError> {
        self.evidence
            .validate_digest()
            .map_err(|_| WorkdayError::EvidenceDigestMismatch)?;
        if self.proposal_digest != self.compute_digest()
            || self.registration_digest != self.evidence.registration_digest
            || self.effect.native
            || self.decision.effect_allowed
            || self.adopted
            || self.authority.connected
            || self.authority.native_provider
            || self.authority.effect
            || self.authority.native_receipt
            || self.authority.exact_read_back
            || self.authority.adopted_outcome
            || self.authority.work_product_adoption
        {
            return Err(WorkdayError::InvalidInput(
                "Workday proposal authority or digest fence is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn authority(&self) -> Layer1AuthorityView {
        self.authority
    }

    pub fn layer1_authority(&self) -> Layer1Authority {
        Layer1Authority
    }
}
