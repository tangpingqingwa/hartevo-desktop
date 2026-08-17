//! Mission-scoped consumer for normalized Security Hub finding evidence.

use crate::model::{
    AccessLossEvidence, AwsSecurityHubScope, Digest, EvidenceStatus, FindingsEvidence,
    FindingsProposal, FindingsReadRequest, FindingsRecord, FindingsVerification, GetFindingsPage,
    GetFindingsRequest, PartialReason, ProviderProvenance, Revision,
};
use crate::provider::{AwsSecurityHubProvider, AwsSecurityHubRegistration, RegistrationState};
use crate::service::AwsSecurityHubFindingService;
use crate::transport::AwsSecurityHubTransport;
use crate::{
    AWS_SECURITY_HUB_CONTRACT_VERSION, AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT, AwsSecurityHubError,
    MISSION_AWS_SECURITY_HUB_CONSUMER_ID, contract_digest,
};
use serde::{Deserialize, Serialize};

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsSecurityHubObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub status: EvidenceStatus,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub adoption_available: bool,
    pub observation_digest: Digest,
}

impl MissionAwsSecurityHubObservation {
    fn from_evidence(evidence: &FindingsEvidence) -> Result<Self, AwsSecurityHubError> {
        let mut observation = Self {
            contract_version: AWS_SECURITY_HUB_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: MISSION_AWS_SECURITY_HUB_CONSUMER_ID.to_owned(),
            consumer_version: AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status,
            read_only: true,
            native: false,
            connected: false,
            external_write_performed: false,
            outcome_authority: false,
            adoption_available: false,
            observation_digest: Digest::from_text("pending-observation-digest"),
        };
        observation.observation_digest = crate::model::digest_serializable(&(
            &observation.contract_version,
            &observation.contract_digest,
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.scope_digest,
            &observation.evidence_digest,
            observation.status,
            observation.read_only,
            observation.native,
            observation.connected,
            observation.external_write_performed,
            observation.outcome_authority,
            observation.adoption_available,
        ))?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsSecurityHubReadResult {
    pub observation: MissionAwsSecurityHubObservation,
    pub evidence: FindingsEvidence,
}

impl MissionAwsSecurityHubReadResult {
    pub fn validate(&self, scope: &AwsSecurityHubScope) -> Result<(), AwsSecurityHubError> {
        self.evidence
            .validate()
            .map_err(|_| AwsSecurityHubError::TamperedEvidence)?;
        if self.evidence.scope_digest != scope.digest()
            || self.observation.scope_digest != scope.digest()
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.contract_digest != contract_digest()
            || self.observation.contract_version != AWS_SECURITY_HUB_CONTRACT_VERSION
            || self.observation.consumer_id != MISSION_AWS_SECURITY_HUB_CONSUMER_ID
            || self.observation.consumer_version != AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT
            || !self.observation.read_only
            || self.observation.native
            || self.observation.connected
            || self.observation.external_write_performed
            || self.observation.outcome_authority
            || self.observation.adoption_available
        {
            return Err(AwsSecurityHubError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsSecurityHubConsumer {
    scope: AwsSecurityHubScope,
    registration: Option<AwsSecurityHubRegistration>,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
}

impl MissionAwsSecurityHubConsumer {
    pub fn new(scope: AwsSecurityHubScope) -> Self {
        Self {
            scope,
            registration: None,
            plugin_version: AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_SECURITY_HUB_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
        }
    }

    pub fn with_registration(
        scope: AwsSecurityHubScope,
        registration: AwsSecurityHubRegistration,
    ) -> Result<Self, AwsSecurityHubError> {
        if registration.scope() != &scope {
            return Err(AwsSecurityHubError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration: Some(registration),
            plugin_version: AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_SECURITY_HUB_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
        })
    }

    pub fn bind_registration(
        &mut self,
        registration: AwsSecurityHubRegistration,
    ) -> Result<(), AwsSecurityHubError> {
        if registration.scope() != &self.scope {
            return Err(AwsSecurityHubError::ScopeMismatch);
        }
        self.registration = Some(registration);
        Ok(())
    }

    pub fn scope(&self) -> &AwsSecurityHubScope {
        &self.scope
    }

    pub fn registration(&self) -> Option<&AwsSecurityHubRegistration> {
        self.registration.as_ref()
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
        evidence: FindingsEvidence,
    ) -> Result<MissionAwsSecurityHubReadResult, AwsSecurityHubError> {
        evidence
            .validate()
            .map_err(|_| AwsSecurityHubError::TamperedEvidence)?;
        if evidence.scope_digest != self.scope.digest()
            || evidence.contract_digest != self.contract_digest
            || evidence.contract_version != self.contract_version
        {
            return Err(AwsSecurityHubError::StaleEvidence);
        }
        if let Some(registration) = &self.registration {
            if !registration.is_active() {
                return Err(AwsSecurityHubError::RegistrationRevoked);
            }
            if evidence.registration_digest != *registration.registration_digest() {
                return Err(AwsSecurityHubError::StaleEvidence);
            }
        }
        let observation = MissionAwsSecurityHubObservation::from_evidence(&evidence)?;
        let result = MissionAwsSecurityHubReadResult {
            observation,
            evidence,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read<T>(
        &self,
        provider: &mut AwsSecurityHubProvider<T>,
        request: &FindingsReadRequest,
    ) -> Result<MissionAwsSecurityHubReadResult, AwsSecurityHubError>
    where
        T: AwsSecurityHubTransport,
    {
        let registration = self.assert_provider_scope(provider)?;
        let mut page_request = request.first_page(&self.scope)?;
        let mut page_bindings = Vec::new();
        let mut page_response_digests = Vec::new();
        let mut findings = Vec::new();
        let mut status = EvidenceStatus::Complete;
        let mut partial_reason = None;
        let mut access_loss = None;
        let mut seen_page_tokens: Vec<Digest> = Vec::new();

        for _ in 0..request.max_pages() {
            let binding = page_request.binding();
            page_bindings.push(binding);
            let page = match provider.read_page(&page_request) {
                Ok(page) => page,
                Err(AwsSecurityHubError::Transport(error))
                    if error.access_loss_kind().is_some() =>
                {
                    status = EvidenceStatus::AccessLost;
                    access_loss = Some(AccessLossEvidence::new(
                        error
                            .access_loss_kind()
                            .expect("guard checks access loss kind"),
                        error.provider_code(),
                        page_request.page_number(),
                    )?);
                    page_response_digests.push(Digest::from_fields(
                        "hartevo.aws-security-hub-access-loss-page/v1",
                        &[page_request.request_digest().as_str().to_owned()],
                    ));
                    break;
                }
                Err(error) => return Err(error),
            };
            page_response_digests.push(page.response_digest.clone());
            page.validate_for(&page_request)
                .map_err(|_| AwsSecurityHubError::PageBindingMismatch)?;
            if page.findings.iter().any(|finding| {
                !finding.matches_scope(&self.scope) || !request.filter().matches(finding)
            }) {
                return Err(AwsSecurityHubError::FindingOutOfScope);
            }
            if findings.len() + page.findings.len() > request.max_findings() {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::FindingLimitReached);
                break;
            }
            findings.extend(page.findings);
            if let Some(loss) = page.access_loss {
                status = EvidenceStatus::AccessLost;
                access_loss = Some(loss);
                break;
            }
            if page.partial {
                status = EvidenceStatus::Partial;
                partial_reason.get_or_insert(PartialReason::ProviderMarkedPartial);
            }
            let Some(next_page) = page.next_page else {
                break;
            };
            if seen_page_tokens.contains(next_page.digest()) {
                return Err(AwsSecurityHubError::PageLoop);
            }
            seen_page_tokens.push(next_page.digest().clone());
            if page_request.page_number() >= request.max_pages() {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::PageLimitReached);
                break;
            }
            page_request = page_request.next_page(next_page)?;
        }

        let evidence = FindingsEvidence::new(
            provider.provider_revision().to_owned(),
            provider.provider_digest().clone(),
            registration.permission_digest().clone(),
            self.scope.digest(),
            registration.registration_digest().clone(),
            registration.secret_reference().credential_revision(),
            page_bindings
                .first()
                .map(|binding| binding.request_digest.clone())
                .ok_or(AwsSecurityHubError::ResponseBoundExceeded)?,
            page_bindings
                .first()
                .map(|binding| binding.filter_digest.clone())
                .ok_or(AwsSecurityHubError::ResponseBoundExceeded)?,
            page_bindings,
            page_response_digests,
            findings,
            provider.provenance(),
            status,
            partial_reason,
            access_loss,
        )?;
        self.consume_evidence(evidence)
    }

    pub fn read_get_findings<T>(
        &self,
        provider: &mut AwsSecurityHubProvider<T>,
        request: &FindingsReadRequest,
    ) -> Result<MissionAwsSecurityHubReadResult, AwsSecurityHubError>
    where
        T: AwsSecurityHubTransport,
    {
        if request.api() != crate::GetFindingsApi::GetFindings {
            return Err(AwsSecurityHubError::PageBindingMismatch);
        }
        self.read(provider, request)
    }

    pub fn read_get_findings_v2<T>(
        &self,
        provider: &mut AwsSecurityHubProvider<T>,
        request: &FindingsReadRequest,
    ) -> Result<MissionAwsSecurityHubReadResult, AwsSecurityHubError>
    where
        T: AwsSecurityHubTransport,
    {
        if request.api() != crate::GetFindingsApi::GetFindingsV2 {
            return Err(AwsSecurityHubError::PageBindingMismatch);
        }
        self.read(provider, request)
    }

    pub fn read_page<T>(
        &self,
        provider: &mut AwsSecurityHubProvider<T>,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubError>
    where
        T: AwsSecurityHubTransport,
    {
        self.assert_provider_scope(provider)?;
        if request.scope_digest() != &self.scope.digest() {
            return Err(AwsSecurityHubError::ScopeMismatch);
        }
        provider.read_page(request)
    }

    pub fn propose<T>(
        &self,
        provider: &mut AwsSecurityHubProvider<T>,
        request: &FindingsReadRequest,
    ) -> Result<FindingsProposal, AwsSecurityHubError>
    where
        T: AwsSecurityHubTransport,
    {
        let result = self.read(provider, request)?;
        AwsSecurityHubFindingService::new().propose(result.evidence)
    }

    pub fn read_evidence<T>(
        &self,
        provider: &mut AwsSecurityHubProvider<T>,
        request: &FindingsReadRequest,
    ) -> Result<FindingsEvidence, AwsSecurityHubError>
    where
        T: AwsSecurityHubTransport,
    {
        Ok(self.read(provider, request)?.evidence)
    }

    pub fn record(
        &self,
        proposal: &FindingsProposal,
    ) -> Result<FindingsRecord, AwsSecurityHubError> {
        if proposal.evidence.scope_digest != self.scope.digest() {
            return Err(AwsSecurityHubError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if !registration.is_active() {
                return Err(AwsSecurityHubError::RegistrationRevoked);
            }
            if proposal.evidence.registration_digest != *registration.registration_digest() {
                return Err(AwsSecurityHubError::StaleEvidence);
            }
        }
        AwsSecurityHubFindingService::new().record(proposal)
    }

    pub fn verify(
        &self,
        record: &FindingsRecord,
        evidence: &FindingsEvidence,
    ) -> Result<FindingsVerification, AwsSecurityHubError> {
        if evidence.scope_digest != self.scope.digest() {
            return Err(AwsSecurityHubError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if !registration.is_active() {
                return Err(AwsSecurityHubError::RegistrationRevoked);
            }
            if evidence.registration_digest != *registration.registration_digest() {
                return Err(AwsSecurityHubError::StaleEvidence);
            }
        }
        AwsSecurityHubFindingService::new().verify(record, evidence)
    }

    fn assert_provider_scope<T>(
        &self,
        provider: &AwsSecurityHubProvider<T>,
    ) -> Result<AwsSecurityHubRegistration, AwsSecurityHubError>
    where
        T: AwsSecurityHubTransport,
    {
        let registration = provider
            .registration()
            .cloned()
            .ok_or(AwsSecurityHubError::RegistrationMissing)?;
        if !registration.is_active() {
            return Err(AwsSecurityHubError::RegistrationRevoked);
        }
        if registration.scope() != &self.scope {
            return Err(AwsSecurityHubError::ScopeMismatch);
        }
        if let Some(bound) = &self.registration {
            if bound.registration_digest() != registration.registration_digest() {
                return Err(AwsSecurityHubError::StaleEvidence);
            }
            if bound.state() == RegistrationState::Revoked {
                return Err(AwsSecurityHubError::RegistrationRevoked);
            }
        }
        Ok(registration)
    }
}

pub type MissionAwsSecurityHubFindingResult = MissionAwsSecurityHubConsumer;

#[allow(dead_code)]
fn _revision_is_typed(value: Revision) -> Revision {
    value
}

#[allow(dead_code)]
fn _provenance_is_non_native(value: ProviderProvenance) -> bool {
    !value.is_native()
}
