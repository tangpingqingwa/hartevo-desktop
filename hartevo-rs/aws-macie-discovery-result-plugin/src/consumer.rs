//! Mission-bound Macie discovery consumer below Hartevo kernel authority.

use crate::model::{
    AccessLossEvidence, Digest, EvidenceStatus, FindingId, FindingIdAllowlist,
    MacieDiscoveryEvidence, MacieDiscoveryProposal, MacieDiscoveryRecord, MacieDiscoveryScope,
    MacieDiscoveryVerification, MacieFinding, MacieReadRequest, OpaquePageToken, PartialReason,
    ProviderProvenance, ProviderUnknownEvidence,
};
use crate::provider::{MacieProvider, MacieRegistration, ProviderRegistrationState};
use crate::service::MacieDiscoveryResultService;
use crate::transport::{MacieTransport, MacieTransportError};
use crate::{MacieApiOperation, MacieDiscoveryResultError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacieDiscoveryObservation {
    pub evidence_digest: crate::model::Digest,
    pub scope_digest: crate::model::Digest,
    pub status: EvidenceStatus,
    pub finding_count: usize,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub adopted: bool,
}

impl MacieDiscoveryObservation {
    fn from_evidence(evidence: &MacieDiscoveryEvidence) -> Self {
        Self {
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            status: evidence.status,
            finding_count: evidence.findings.len(),
            provenance: evidence.provenance,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            adopted: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacieDiscoveryReadResult {
    pub evidence: MacieDiscoveryEvidence,
    pub observation: MacieDiscoveryObservation,
    pub result_digest: crate::model::Digest,
}

impl MacieDiscoveryReadResult {
    fn new(evidence: MacieDiscoveryEvidence) -> Self {
        let observation = MacieDiscoveryObservation::from_evidence(&evidence);
        let result_digest = crate::model::Digest::from_fields(
            "hartevo.aws-macie-read-result/v1",
            &[
                evidence.evidence_digest.as_str().to_owned(),
                evidence.scope_digest.as_str().to_owned(),
            ],
        );
        Self {
            evidence,
            observation,
            result_digest,
        }
    }

    pub fn validate(&self, scope: &MacieDiscoveryScope) -> Result<()> {
        self.evidence
            .validate()
            .map_err(MacieDiscoveryResultError::from)?;
        if self.evidence.scope_digest != scope.digest()
            || self.observation.scope_digest != self.evidence.scope_digest
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.finding_count != self.evidence.findings.len()
            || self.result_digest
                != crate::model::Digest::from_fields(
                    "hartevo.aws-macie-read-result/v1",
                    &[
                        self.evidence.evidence_digest.as_str().to_owned(),
                        self.evidence.scope_digest.as_str().to_owned(),
                    ],
                )
        {
            return Err(MacieDiscoveryResultError::TamperedEvidence);
        }
        if self.observation.connected
            || self.observation.native
            || self.observation.first_party
            || self.observation.truth_authority
            || self.observation.consent_authority
            || self.observation.effect_authority
            || self.observation.receipt_authority
            || self.observation.verification_authority
            || self.observation.outcome_authority
            || self.observation.adopted
        {
            return Err(MacieDiscoveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionMacieDiscoveryConsumer {
    scope: MacieDiscoveryScope,
    registration: Option<MacieRegistration>,
}

impl std::fmt::Debug for MissionMacieDiscoveryConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionMacieDiscoveryConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .finish()
    }
}

impl MissionMacieDiscoveryConsumer {
    pub fn new(scope: MacieDiscoveryScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope,
            registration: None,
        })
    }

    pub fn with_registration(
        scope: MacieDiscoveryScope,
        registration: MacieRegistration,
    ) -> Result<Self> {
        let consumer = Self::new(scope)?;
        if consumer.scope != *registration.scope() || !registration.is_active() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        Ok(Self {
            scope: consumer.scope,
            registration: Some(registration),
        })
    }

    pub fn bind_registration(&mut self, registration: MacieRegistration) -> Result<()> {
        if registration.scope() != &self.scope || !registration.is_active() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        self.registration = Some(registration);
        Ok(())
    }

    pub fn scope(&self) -> &MacieDiscoveryScope {
        &self.scope
    }

    pub fn registration(&self) -> Option<&MacieRegistration> {
        self.registration.as_ref()
    }

    #[allow(clippy::too_many_lines)]
    pub fn read<T>(
        &self,
        provider: &mut MacieProvider<T>,
        request: &MacieReadRequest,
    ) -> Result<MacieDiscoveryReadResult>
    where
        T: MacieTransport,
    {
        let registration = self.assert_provider_scope(provider)?;
        let provider_revision = provider.provider_revision().to_owned();
        let provider_digest = provider.provider_digest().clone();
        let provenance = provider.provenance();
        let mut list_request = request.first_list_page(&self.scope)?;
        let mut seen_tokens = Vec::new();
        let mut list_bindings = Vec::new();
        let mut get_bindings = Vec::new();
        let mut list_response_digests = Vec::new();
        let mut get_response_digests = Vec::new();
        let mut findings = Vec::new();
        let mut all_allowlist_digests = Vec::new();
        let mut status = EvidenceStatus::Complete;
        let mut partial_reason = None;
        let mut access_loss = None;
        let mut provider_unknown = None;

        loop {
            let list_binding = list_request.binding();
            match provider.list_findings(&list_request) {
                Ok(page) => {
                    list_bindings.push(page.binding.clone());
                    list_response_digests.push(page.response_digest.clone());
                    if page.binding != list_binding {
                        return Err(MacieDiscoveryResultError::PageBindingMismatch);
                    }
                    if page.access_loss.is_some() {
                        status = EvidenceStatus::AccessLost;
                        access_loss.clone_from(&page.access_loss);
                    }
                    if page.provider_unknown.is_some() {
                        status = EvidenceStatus::ProviderUnknown;
                        provider_unknown.clone_from(&page.provider_unknown);
                    }
                    if page.partial && status == EvidenceStatus::Complete {
                        status = EvidenceStatus::Partial;
                        partial_reason = Some(PartialReason::ProviderMarkedPartial);
                    }

                    if !page.finding_ids.is_empty() {
                        for finding_id in page.finding_ids.as_slice() {
                            if finding_id != &self.scope.finding_id {
                                return Err(MacieDiscoveryResultError::FindingOutOfScope);
                            }
                        }
                        let allowlist =
                            FindingIdAllowlist::for_get(page.finding_ids.as_slice().to_vec())?;
                        let get_request = crate::model::GetFindingsRequest::new(
                            &self.scope,
                            &list_request,
                            allowlist.clone(),
                        )?;
                        all_allowlist_digests.push(allowlist.digest());
                        let get_binding = get_request.binding();
                        match provider.get_findings(&get_request) {
                            Ok(get_page) => {
                                get_bindings.push(get_page.binding.clone());
                                get_response_digests.push(get_page.response_digest.clone());
                                if get_page.binding != get_binding {
                                    return Err(MacieDiscoveryResultError::PageBindingMismatch);
                                }
                                for finding in &get_page.findings {
                                    if !allowlist.contains(&finding.finding_id)
                                        || !finding.matches_scope(&self.scope)
                                        || !request.filter().matches(finding)
                                    {
                                        return Err(MacieDiscoveryResultError::FindingOutOfScope);
                                    }
                                }
                                if findings.len() + get_page.findings.len() > request.max_findings()
                                {
                                    status = EvidenceStatus::Partial;
                                    partial_reason = Some(PartialReason::FindingLimitReached);
                                    break;
                                }
                                findings.extend(get_page.findings);
                                if get_page.access_loss.is_some() {
                                    status = EvidenceStatus::AccessLost;
                                    access_loss.clone_from(&get_page.access_loss);
                                }
                                if get_page.provider_unknown.is_some() {
                                    status = EvidenceStatus::ProviderUnknown;
                                    provider_unknown.clone_from(&get_page.provider_unknown);
                                }
                                if get_page.partial && status == EvidenceStatus::Complete {
                                    status = EvidenceStatus::Partial;
                                    partial_reason = Some(PartialReason::ProviderMarkedPartial);
                                }
                            }
                            Err(error) => {
                                return self.result_for_transport_error(
                                    &registration,
                                    &provider_revision,
                                    &provider_digest,
                                    provenance,
                                    request,
                                    list_bindings,
                                    get_bindings,
                                    list_response_digests,
                                    get_response_digests,
                                    findings,
                                    &all_allowlist_digests,
                                    &get_request.binding(),
                                    error,
                                );
                            }
                        }
                    }

                    if status == EvidenceStatus::AccessLost
                        || status == EvidenceStatus::ProviderUnknown
                    {
                        break;
                    }
                    let Some(next_page) = page.next_page else {
                        break;
                    };
                    if seen_tokens.contains(next_page.digest()) {
                        return Err(MacieDiscoveryResultError::PageLoop);
                    }
                    seen_tokens.push(next_page.digest().clone());
                    if list_request.page_number() >= request.max_pages() {
                        status = EvidenceStatus::Partial;
                        partial_reason = Some(PartialReason::PageLimitReached);
                        break;
                    }
                    list_request = list_request.next_page(next_page)?;
                }
                Err(error) => {
                    return self.result_for_transport_error(
                        &registration,
                        &provider_revision,
                        &provider_digest,
                        provenance,
                        request,
                        list_bindings,
                        get_bindings,
                        list_response_digests,
                        get_response_digests,
                        findings,
                        &all_allowlist_digests,
                        &list_binding,
                        error,
                    );
                }
            }
        }

        let finding_allowlist_digest = crate::model::Digest::from_fields(
            "hartevo.aws-macie-finding-allowlists/v1",
            &all_allowlist_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let evidence = MacieDiscoveryEvidence::new(
            provider.provider_revision().to_owned(),
            provider.provider_digest().clone(),
            registration.permission_digest().clone(),
            self.scope.digest(),
            registration.registration_digest().clone(),
            registration.secret_reference().credential_revision(),
            request.filter().digest(),
            finding_allowlist_digest,
            list_bindings,
            get_bindings,
            list_response_digests,
            get_response_digests,
            findings,
            provider.provenance(),
            status,
            partial_reason,
            access_loss,
            provider_unknown,
        )?;
        self.consume_evidence(evidence)
    }

    fn result_for_transport_error(
        &self,
        registration: &MacieRegistration,
        provider_revision: &str,
        provider_digest: &Digest,
        provenance: ProviderProvenance,
        request: &MacieReadRequest,
        mut list_bindings: Vec<crate::model::PageBinding>,
        mut get_bindings: Vec<crate::model::PageBinding>,
        mut list_response_digests: Vec<crate::model::Digest>,
        mut get_response_digests: Vec<crate::model::Digest>,
        findings: Vec<MacieFinding>,
        allowlist_digests: &[crate::model::Digest],
        failed_binding: &crate::model::PageBinding,
        error: MacieDiscoveryResultError,
    ) -> Result<MacieDiscoveryReadResult> {
        let transport_error = match error {
            MacieDiscoveryResultError::Transport(error) => error,
            other => return Err(other),
        };
        let placeholder = crate::model::Digest::from_fields(
            "hartevo.aws-macie-missing-response/v1",
            &[
                failed_binding.operation.to_string(),
                failed_binding.page_number.to_string(),
            ],
        );
        match transport_error {
            MacieTransportError::ProviderUnknown => {
                if failed_binding.operation == MacieApiOperation::ListFindings {
                    list_bindings.push(failed_binding.clone());
                    list_response_digests.push(placeholder);
                } else {
                    get_bindings.push(failed_binding.clone());
                    get_response_digests.push(placeholder);
                }
                let unknown = ProviderUnknownEvidence::new(
                    "PROVIDER_UNKNOWN",
                    failed_binding.operation,
                    failed_binding.page_number,
                )?;
                self.result_from_parts(
                    registration,
                    provider_revision,
                    provider_digest,
                    provenance,
                    request,
                    list_bindings,
                    get_bindings,
                    list_response_digests,
                    get_response_digests,
                    findings,
                    allowlist_digests,
                    EvidenceStatus::ProviderUnknown,
                    None,
                    None,
                    Some(unknown),
                )
            }
            error => {
                let Some(kind) = error.access_loss_kind() else {
                    return Err(MacieDiscoveryResultError::Transport(error));
                };
                if failed_binding.operation == MacieApiOperation::ListFindings {
                    list_bindings.push(failed_binding.clone());
                    list_response_digests.push(placeholder);
                } else {
                    get_bindings.push(failed_binding.clone());
                    get_response_digests.push(placeholder);
                }
                let loss = AccessLossEvidence::new(
                    kind,
                    error.provider_code(),
                    failed_binding.operation,
                    failed_binding.page_number,
                )?;
                self.result_from_parts(
                    registration,
                    provider_revision,
                    provider_digest,
                    provenance,
                    request,
                    list_bindings,
                    get_bindings,
                    list_response_digests,
                    get_response_digests,
                    findings,
                    allowlist_digests,
                    EvidenceStatus::AccessLost,
                    None,
                    Some(loss),
                    None,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn result_from_parts(
        &self,
        registration: &MacieRegistration,
        provider_revision: &str,
        provider_digest: &Digest,
        provenance: ProviderProvenance,
        request: &MacieReadRequest,
        list_bindings: Vec<crate::model::PageBinding>,
        get_bindings: Vec<crate::model::PageBinding>,
        list_response_digests: Vec<crate::model::Digest>,
        get_response_digests: Vec<crate::model::Digest>,
        findings: Vec<MacieFinding>,
        allowlist_digests: &[crate::model::Digest],
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        access_loss: Option<AccessLossEvidence>,
        provider_unknown: Option<ProviderUnknownEvidence>,
    ) -> Result<MacieDiscoveryReadResult> {
        if list_bindings.is_empty() {
            return Err(MacieDiscoveryResultError::ResponseBoundExceeded);
        }
        let finding_allowlist_digest = crate::model::Digest::from_fields(
            "hartevo.aws-macie-finding-allowlists/v1",
            &allowlist_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let evidence = MacieDiscoveryEvidence::new(
            provider_revision.to_owned(),
            provider_digest.clone(),
            registration.permission_digest().clone(),
            self.scope.digest(),
            registration.registration_digest().clone(),
            registration.secret_reference().credential_revision(),
            request.filter().digest(),
            finding_allowlist_digest,
            list_bindings,
            get_bindings,
            list_response_digests,
            get_response_digests,
            findings,
            provenance,
            status,
            partial_reason,
            access_loss,
            provider_unknown,
        )?;
        self.consume_evidence(evidence)
    }

    pub fn read_list_findings<T>(
        &self,
        provider: &mut MacieProvider<T>,
        request: &crate::model::ListFindingsRequest,
    ) -> Result<crate::model::ListFindingsPage>
    where
        T: MacieTransport,
    {
        self.assert_provider_scope(provider)?;
        if request.scope_digest() != &self.scope.digest() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        provider.list_findings(request)
    }

    pub fn read_get_findings<T>(
        &self,
        provider: &mut MacieProvider<T>,
        request: &crate::model::GetFindingsRequest,
    ) -> Result<crate::model::GetFindingsPage>
    where
        T: MacieTransport,
    {
        self.assert_provider_scope(provider)?;
        if request.scope_digest() != &self.scope.digest() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        provider.get_findings(request)
    }

    pub fn propose<T>(
        &self,
        provider: &mut MacieProvider<T>,
        request: &MacieReadRequest,
    ) -> Result<MacieDiscoveryProposal>
    where
        T: MacieTransport,
    {
        let result = self.read(provider, request)?;
        MacieDiscoveryResultService::new().propose(result.evidence)
    }

    pub fn record(&self, proposal: &MacieDiscoveryProposal) -> Result<MacieDiscoveryRecord> {
        if proposal.evidence.scope_digest != self.scope.digest() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if !registration.is_active() {
                return Err(MacieDiscoveryResultError::RegistrationRevoked);
            }
            if proposal.evidence.registration_digest != *registration.registration_digest() {
                return Err(MacieDiscoveryResultError::StaleEvidence);
            }
        }
        MacieDiscoveryResultService::new().record(proposal)
    }

    pub fn verify(
        &self,
        record: &MacieDiscoveryRecord,
        evidence: &MacieDiscoveryEvidence,
    ) -> Result<MacieDiscoveryVerification> {
        if evidence.scope_digest != self.scope.digest() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if !registration.is_active() {
                return Err(MacieDiscoveryResultError::RegistrationRevoked);
            }
            if evidence.registration_digest != *registration.registration_digest() {
                return Err(MacieDiscoveryResultError::StaleEvidence);
            }
        }
        MacieDiscoveryResultService::new().verify(record, evidence)
    }

    fn consume_evidence(
        &self,
        evidence: MacieDiscoveryEvidence,
    ) -> Result<MacieDiscoveryReadResult> {
        if evidence.scope_digest != self.scope.digest() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if !registration.is_active() {
                return Err(MacieDiscoveryResultError::RegistrationRevoked);
            }
            if evidence.registration_digest != *registration.registration_digest() {
                return Err(MacieDiscoveryResultError::StaleEvidence);
            }
        }
        let result = MacieDiscoveryReadResult::new(evidence);
        result.validate(&self.scope)?;
        Ok(result)
    }

    fn assert_provider_scope<T>(&self, provider: &MacieProvider<T>) -> Result<MacieRegistration>
    where
        T: MacieTransport,
    {
        let registration = provider
            .registration()
            .cloned()
            .ok_or(MacieDiscoveryResultError::RegistrationMissing)?;
        if !registration.is_active() {
            return Err(MacieDiscoveryResultError::RegistrationRevoked);
        }
        if registration.scope() != &self.scope {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        if let Some(bound) = &self.registration {
            if bound.registration_digest() != registration.registration_digest() {
                return Err(MacieDiscoveryResultError::StaleEvidence);
            }
            if bound.state() == ProviderRegistrationState::Revoked {
                return Err(MacieDiscoveryResultError::RegistrationRevoked);
            }
        }
        Ok(registration)
    }
}

pub type MissionMacieDiscoveryResultConsumer = MissionMacieDiscoveryConsumer;

#[allow(dead_code)]
fn _finding_id_is_typed(value: FindingId) -> FindingId {
    value
}

#[allow(dead_code)]
fn _opaque_token_is_not_raw(value: &OpaquePageToken) -> crate::model::Digest {
    value.digest().clone()
}
