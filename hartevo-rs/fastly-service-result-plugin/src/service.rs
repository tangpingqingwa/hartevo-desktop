use std::{borrow::Borrow, collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, FASTLY_SERVICE_RESULT_SERVICE_ID, FASTLY_SERVICE_RESULT_SERVICE_NAME,
    contract_digest,
    error::{FastlyServiceResultError, Result},
    model::{
        Digest, FastlyEnvironmentProjection, FastlyObservationReceipt, FastlyServiceResultEvidence,
        FastlyServiceResultProposal, FastlyServiceResultScope, FastlyServiceResultState,
        FastlyVerificationReport, FastlyVersionProjection,
    },
    provider::{
        FastlyProvider, FastlyReadRequest, FastlyServiceResultRegistration, RegistrationTransition,
    },
    transport::FastlyTransport,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyServiceResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    RestoreRegistration,
    ReverseRegistration,
    ReadService,
    ReadVersion,
    ReadEnvironment,
    ReadDomain,
    ReadValidation,
    CompileProposal,
    VerifyProposal,
    RecordObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyServiceResultCapability {
    pub capability_id: String,
    pub operation: FastlyServiceResultOperation,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub mutates_provider: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FastlyServiceResultServiceDefinition {
    pub service_id: String,
    pub service_name: String,
    pub version: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub capabilities: Vec<FastlyServiceResultCapability>,
}

impl Default for FastlyServiceResultServiceDefinition {
    fn default() -> Self {
        let operations = [
            (
                "fastly.service-result.register",
                FastlyServiceResultOperation::Register,
            ),
            (
                "fastly.service-result.revoke-registration",
                FastlyServiceResultOperation::RevokeRegistration,
            ),
            (
                "fastly.service-result.restore-registration",
                FastlyServiceResultOperation::RestoreRegistration,
            ),
            (
                "fastly.service-result.reverse-registration",
                FastlyServiceResultOperation::ReverseRegistration,
            ),
            (
                "fastly.service-result.read-service",
                FastlyServiceResultOperation::ReadService,
            ),
            (
                "fastly.service-result.read-version",
                FastlyServiceResultOperation::ReadVersion,
            ),
            (
                "fastly.service-result.read-environment",
                FastlyServiceResultOperation::ReadEnvironment,
            ),
            (
                "fastly.service-result.read-domain",
                FastlyServiceResultOperation::ReadDomain,
            ),
            (
                "fastly.service-result.read-validation",
                FastlyServiceResultOperation::ReadValidation,
            ),
            (
                "fastly.service-result.compile-proposal",
                FastlyServiceResultOperation::CompileProposal,
            ),
            (
                "fastly.service-result.verify-proposal",
                FastlyServiceResultOperation::VerifyProposal,
            ),
            (
                "fastly.service-result.record-observation",
                FastlyServiceResultOperation::RecordObservation,
            ),
        ];
        Self {
            service_id: FASTLY_SERVICE_RESULT_SERVICE_ID.to_owned(),
            service_name: FASTLY_SERVICE_RESULT_SERVICE_NAME.to_owned(),
            version: "1.0.0".to_owned(),
            contract_digest: contract_digest(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            external_writes: false,
            capabilities: operations
                .into_iter()
                .map(|(capability_id, operation)| FastlyServiceResultCapability {
                    capability_id: capability_id.to_owned(),
                    operation,
                    read_only: true,
                    proposal_only: true,
                    recording_only: true,
                    mutates_provider: false,
                    connected: false,
                    native: false,
                    first_party: false,
                })
                .collect(),
        }
    }
}

impl FastlyServiceResultServiceDefinition {
    pub fn validate(&self) -> Result<()> {
        if self.service_id != FASTLY_SERVICE_RESULT_SERVICE_ID
            || self.service_name != FASTLY_SERVICE_RESULT_SERVICE_NAME
            || self.version != "1.0.0"
            || self.contract_digest != contract_digest()
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.live_execution
            || self.external_writes
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || !capability.proposal_only
                    || !capability.recording_only
                    || capability.mutates_provider
                    || capability.connected
                    || capability.native
                    || capability.first_party
            })
        {
            return Err(FastlyServiceResultError::Contract(
                "Fastly service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct FastlyServiceResultService<T>
where
    T: FastlyTransport,
{
    provider: FastlyProvider<T>,
    definition: FastlyServiceResultServiceDefinition,
    recorded: BTreeMap<Digest, Digest>,
}

impl<T> fmt::Debug for FastlyServiceResultService<T>
where
    T: FastlyTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FastlyServiceResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("recordedObservationCount", &self.recorded.len())
            .finish()
    }
}

impl<T> FastlyServiceResultService<T>
where
    T: FastlyTransport,
{
    pub fn register<P, C>(
        provider: FastlyProvider<T>,
        registration_id: impl Into<String>,
        permissions: P,
        consent: C,
        registration_revision: u64,
    ) -> Result<Self>
    where
        P: Borrow<crate::model::PermissionSnapshot>,
        C: Borrow<crate::model::ConsentScope>,
    {
        let provider =
            provider.register(registration_id, permissions, consent, registration_revision)?;
        Self::from_provider(provider)
    }

    pub fn from_provider(provider: FastlyProvider<T>) -> Result<Self> {
        if provider.registration().is_none() {
            return Err(FastlyServiceResultError::RegistrationInactive);
        }
        let definition = FastlyServiceResultServiceDefinition::default();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
            recorded: BTreeMap::new(),
        })
    }

    pub fn new(
        provider: FastlyProvider<T>,
        registration: FastlyServiceResultRegistration,
    ) -> Result<Self> {
        let mut provider = provider;
        provider.bind_registration(registration);
        Self::from_provider(provider)
    }

    #[must_use]
    pub fn provider(&self) -> &FastlyProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut FastlyProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &FastlyServiceResultScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &FastlyServiceResultRegistration {
        self.provider
            .registration()
            .expect("service construction pins a registration")
    }

    #[must_use]
    pub fn service_definition(&self) -> &FastlyServiceResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<FastlyServiceResultCapability> {
        self.definition.capabilities.clone()
    }

    pub fn read(&mut self, max_pages: u16) -> Result<FastlyServiceResultEvidence> {
        let request = FastlyReadRequest::new(
            self.scope(),
            self.registration().permission_digest(),
            self.registration().consent_digest(),
        )
        .with_max_pages(max_pages);
        self.read_with_fence(&request)
    }

    pub fn read_with_fence(
        &mut self,
        request: &FastlyReadRequest,
    ) -> Result<FastlyServiceResultEvidence> {
        self.provider.read(request)
    }

    pub fn verify_evidence(&self, evidence: &FastlyServiceResultEvidence) -> Result<()> {
        evidence.validate_integrity()?;
        if evidence.scope_digest != self.scope().digest()
            || evidence.registration_digest != *self.registration().registration_digest()
            || evidence.contract_digest != contract_digest()
            || evidence.contract_version != CONTRACT_VERSION
            || evidence.provider_digest != *self.registration().provider_digest()
            || evidence.permission_digest != *self.registration().permission_digest()
            || evidence.consent_digest != *self.registration().consent_digest()
            || evidence.project_revision != self.scope().project().revision()
            || evidence.mission_revision != self.scope().mission().revision()
            || evidence.work_product_revision != self.scope().work_product().revision()
            || evidence.connected
            || evidence.native
            || evidence.first_party
            || evidence.raw_vcl_retained
            || evidence.raw_config_retained
        {
            return Err(FastlyServiceResultError::StaleEvidence);
        }
        Ok(())
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: FastlyServiceResultEvidence,
    ) -> Result<FastlyServiceResultProposal> {
        self.verify_evidence(&evidence)?;
        let mut proposal = FastlyServiceResultProposal {
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            state: evidence.state,
            version: evidence.version.clone(),
            environment: evidence.environment.clone(),
            domains: evidence.domains.clone(),
            validation: evidence.validation.clone(),
            mission_revision: evidence.mission_revision,
            work_product_revision: evidence.work_product_revision,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            verified_work_product_adoption: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal_digest(&proposal);
        Ok(proposal)
    }

    pub fn compile_proposal(&mut self, max_pages: u16) -> Result<FastlyServiceResultProposal> {
        let evidence = self.read(max_pages)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn verify_proposal(
        &self,
        proposal: &FastlyServiceResultProposal,
    ) -> Result<FastlyVerificationReport> {
        if let Err(error) = proposal.validate_integrity() {
            return Ok(FastlyVerificationReport {
                verified: false,
                review_eligible: false,
                can_be_adopted: false,
                state: FastlyServiceResultState::Tampered,
                reason: Some(error.to_string()),
            });
        }
        if proposal.scope_digest != self.scope().digest()
            || proposal.registration_digest != *self.registration().registration_digest()
            || proposal.contract_digest != contract_digest()
            || proposal.mission_revision != self.scope().mission().revision()
            || proposal.work_product_revision != self.scope().work_product().revision()
            || proposal.proposal_digest != proposal_digest(proposal)
        {
            return Ok(FastlyVerificationReport {
                verified: false,
                review_eligible: false,
                can_be_adopted: false,
                state: FastlyServiceResultState::Stale,
                reason: Some("scope, registration, revision, or proposal digest drift".to_owned()),
            });
        }
        Ok(FastlyVerificationReport {
            verified: true,
            review_eligible: proposal.state == FastlyServiceResultState::Present,
            can_be_adopted: false,
            state: proposal.state,
            reason: None,
        })
    }

    pub fn record_observation(
        &mut self,
        proposal: &FastlyServiceResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<FastlyObservationReceipt> {
        let report = self.verify_proposal(proposal)?;
        if !report.verified {
            return Err(FastlyServiceResultError::StaleEvidence);
        }
        let idempotency_digest = Digest::from_text(idempotency_key.as_ref());
        let replayed = match self.recorded.get(&idempotency_digest) {
            Some(previous) if previous == &proposal.evidence_digest => true,
            Some(_) => return Err(FastlyServiceResultError::Replay),
            None => {
                self.recorded
                    .insert(idempotency_digest.clone(), proposal.evidence_digest.clone());
                false
            }
        };
        let receipt_digest = Digest::from_parts(
            "fastly-observation-receipt/v1",
            &[
                ("idempotency", idempotency_digest.to_string()),
                ("evidence", proposal.evidence_digest.to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                ("replayed", replayed.to_string()),
                ("recorded", (!replayed).to_string()),
            ],
        );
        Ok(FastlyObservationReceipt {
            idempotency_digest,
            evidence_digest: proposal.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            replayed,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            recorded: !replayed,
            receipt_digest,
        })
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransition> {
        self.provider
            .registration_mut()
            .ok_or(FastlyServiceResultError::RegistrationInactive)?
            .revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransition> {
        self.provider
            .registration_mut()
            .ok_or(FastlyServiceResultError::RegistrationInactive)?
            .restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransition> {
        self.provider
            .registration_mut()
            .ok_or(FastlyServiceResultError::RegistrationInactive)?
            .reverse()
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.recorded.len()
    }
}

fn proposal_digest(proposal: &FastlyServiceResultProposal) -> Digest {
    Digest::from_parts(
        "fastly-service-result-proposal/v1",
        &[
            ("scope", proposal.scope_digest.to_string()),
            ("registration", proposal.registration_digest.to_string()),
            ("contract", proposal.contract_digest.to_string()),
            ("evidence", proposal.evidence_digest.to_string()),
            ("state", format!("{:?}", proposal.state)),
            (
                "version",
                proposal.version.as_ref().map_or_else(
                    || "none".to_owned(),
                    |value: &FastlyVersionProjection| {
                        serde_json::to_string(value).unwrap_or_default()
                    },
                ),
            ),
            (
                "environment",
                proposal.environment.as_ref().map_or_else(
                    || "none".to_owned(),
                    |value: &FastlyEnvironmentProjection| {
                        serde_json::to_string(value).unwrap_or_default()
                    },
                ),
            ),
            (
                "domains",
                serde_json::to_string(&proposal.domains).unwrap_or_default(),
            ),
            (
                "validation",
                serde_json::to_string(&proposal.validation).unwrap_or_default(),
            ),
            (
                "missionRevision",
                proposal.mission_revision.get().to_string(),
            ),
            (
                "workProductRevision",
                proposal.work_product_revision.get().to_string(),
            ),
            ("reviewOnly", proposal.review_only.to_string()),
        ],
    )
}

pub type FastlyServiceResultServiceError = FastlyServiceResultError;
pub type FastlyServiceDefinition = FastlyServiceResultServiceDefinition;
pub type FastlyService = FastlyServiceResultService<crate::transport::FixtureTransport>;
pub type Registration = FastlyServiceResultRegistration;
