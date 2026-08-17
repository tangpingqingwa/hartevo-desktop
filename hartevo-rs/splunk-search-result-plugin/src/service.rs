use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, EvidenceClassification, MAX_AGGREGATE_CELLS, MAX_CELLS_PER_PAGE, MAX_FIELDS, MAX_PAGES,
    MISSION_SPLUNK_SEARCH_CONSUMER_ID, RegistrationChange, SPLUNK_API_REVISION, SPLUNK_PROVIDER_ID,
    SPLUNK_PROVIDER_VERSION, SPLUNK_SEARCH_RESULT_CONTRACT_VERSION,
    SPLUNK_SEARCH_RESULT_PLUGIN_VERSION, SPLUNK_SEARCH_RESULT_SCHEMA_VERSION, SecretReference,
    SplunkAggregateResult, SplunkEvidenceStatus, SplunkHttpMethod, SplunkProvider,
    SplunkProviderError, SplunkProviderOperation, SplunkProviderRead, SplunkProviderRequest,
    SplunkSavedSearchResultEvidence, SplunkSavedSearchResultProposal, SplunkSavedSearchResultScope,
    SplunkTiming, SplunkTransport, TransportProvenance, canonical_digest, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SplunkSavedSearchResultServiceError {
    #[error("Splunk registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Splunk SecretReference is revoked")]
    SecretRevoked,
    #[error("Splunk resource scope does not match the registered scope")]
    ScopeMismatch,
    #[error("Splunk read consent scope is denied or stale")]
    ConsentMismatch,
    #[error("Splunk evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error(transparent)]
    Model(#[from] crate::ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SplunkSavedSearchResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub proposal_only: bool,
    pub kernel_truth_authority: bool,
    pub kernel_consent_authority: bool,
    pub kernel_effect_authority: bool,
    pub kernel_receipt_authority: bool,
    pub kernel_verification_authority: bool,
    pub kernel_outcome_authority: bool,
    pub external_writes: bool,
}

impl Default for SplunkSavedSearchResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: SPLUNK_SEARCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: SPLUNK_SEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::SPLUNK_SEARCH_RESULT_SERVICE_ID.to_owned(),
            provider_id: SPLUNK_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_SPLUNK_SEARCH_CONSUMER_ID.to_owned(),
            api_revision: SPLUNK_API_REVISION.to_owned(),
            contract_digest: contract_digest(),
            read_only: true,
            live_execution: false,
            proposal_only: true,
            kernel_truth_authority: false,
            kernel_consent_authority: false,
            kernel_effect_authority: false,
            kernel_receipt_authority: false,
            kernel_verification_authority: false,
            kernel_outcome_authority: false,
            external_writes: false,
        }
    }
}

/// Layer-1 typed service for read-only status and aggregate result evidence.
/// The consent method is a typed scope check, not a native consent authority.
pub struct SplunkSavedSearchResultService<T: SplunkTransport> {
    provider: SplunkProvider<T>,
    definition: SplunkSavedSearchResultServiceDefinition,
}

impl<T: SplunkTransport> fmt::Debug for SplunkSavedSearchResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplunkSavedSearchResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: SplunkTransport> SplunkSavedSearchResultService<T> {
    pub fn new(provider: SplunkProvider<T>) -> Result<Self, SplunkSavedSearchResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| SplunkSavedSearchResultServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition: SplunkSavedSearchResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: SplunkProvider<T>) -> Self {
        Self {
            provider,
            definition: SplunkSavedSearchResultServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &SplunkProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut SplunkProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &SplunkSavedSearchResultScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &crate::SplunkRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &SplunkSavedSearchResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> crate::ConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(
        &mut self,
    ) -> Result<SplunkSavedSearchResultEvidence, SplunkSavedSearchResultServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(&consent)
    }

    pub fn read_job_status(
        &mut self,
    ) -> Result<SplunkSavedSearchResultEvidence, SplunkSavedSearchResultServiceError> {
        self.read()
    }

    pub fn read_bounded_aggregate_results(
        &mut self,
    ) -> Result<SplunkSavedSearchResultEvidence, SplunkSavedSearchResultServiceError> {
        self.read()
    }

    pub fn read_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<SplunkSavedSearchResultEvidence, SplunkSavedSearchResultServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read() {
            Ok(read) => Ok(normalize_success(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                read,
            )),
            Err(error) => Ok(normalize_failure(
                self.scope(),
                self.registration(),
                self.provider.secret_reference(),
                self.provider.provider_digest(),
                self.provider.transport_provenance(),
                &error,
            )),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<SplunkSavedSearchResultProposal, SplunkSavedSearchResultServiceError> {
        self.ensure_registration()?;
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_mission_proposal(
        &mut self,
    ) -> Result<SplunkSavedSearchResultProposal, SplunkSavedSearchResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<SplunkSavedSearchResultProposal, SplunkSavedSearchResultServiceError> {
        self.ensure_registration()?;
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: SplunkSavedSearchResultEvidence,
    ) -> Result<SplunkSavedSearchResultProposal, SplunkSavedSearchResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let source_evidence_digest = evidence.digest();
        let mut proposal = SplunkSavedSearchResultProposal {
            scope: self.scope().clone(),
            evidence,
            source_evidence_digest,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: contract_digest(),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &SplunkSavedSearchResultProposal,
    ) -> Result<(), SplunkSavedSearchResultServiceError> {
        self.ensure_registration()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.adopts_outcome
            || proposal.adopts_work_product
            || proposal.scope != *self.scope()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != contract_digest()
            || proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.proposal_digest != proposal.digest()
        {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn revoke(&mut self) -> Result<RegistrationChange, SplunkSavedSearchResultServiceError> {
        self.provider.revoke().map_err(map_provider_error)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationChange, SplunkSavedSearchResultServiceError> {
        self.revoke()
    }

    pub fn restore(&mut self) -> Result<RegistrationChange, SplunkSavedSearchResultServiceError> {
        self.provider.restore().map_err(map_provider_error)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationChange, SplunkSavedSearchResultServiceError> {
        self.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<(), SplunkSavedSearchResultServiceError> {
        self.provider.revoke_secret().map_err(map_provider_error)
    }

    fn validate_consent(
        &self,
        consent: &crate::ConsentScope,
    ) -> Result<(), SplunkSavedSearchResultServiceError> {
        consent.validate()?;
        if consent == self.scope().consent() {
            Ok(())
        } else {
            Err(SplunkSavedSearchResultServiceError::ConsentMismatch)
        }
    }

    fn ensure_registration(&self) -> Result<(), SplunkSavedSearchResultServiceError> {
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| SplunkSavedSearchResultServiceError::RegistrationRevoked)
    }

    fn verify_evidence(
        &self,
        evidence: &SplunkSavedSearchResultEvidence,
    ) -> Result<(), SplunkSavedSearchResultServiceError> {
        if evidence.evidence_digest != evidence.digest()
            || evidence.scope_digest != *self.scope().scope_digest()
            || evidence.resource_scope_digest != self.scope().resource_digest()
            || evidence.revision_digest != *self.scope().revision_digest()
            || evidence.privacy_digest != *self.scope().privacy_digest()
            || evidence.registration_digest != self.registration().registration_digest
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.search_digest != self.scope().search_digest()
            || evidence.sid_digest != self.scope().sid_digest()
            || evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || evidence.provenance.is_first_party()
            || evidence.native
            || evidence.connected
            || evidence.first_party
            || evidence.truth_authority
            || evidence.consent_authority
            || evidence.effect_authority
            || evidence.receipt_authority
            || evidence.verification_authority
            || evidence.outcome_authority
            || !evidence.proposal_only
            || evidence.page_digests.len() > usize::from(MAX_PAGES)
            || evidence.aggregate_cells.len() > MAX_AGGREGATE_CELLS
            || evidence.field_schema.len() > MAX_FIELDS
            || evidence
                .aggregate_cells
                .iter()
                .any(|row| row.cells.len() > MAX_CELLS_PER_PAGE)
            || evidence.pages_read != evidence.page_digests.len() as u16
            || !evidence.page_digests.iter().all(|digest| is_digest(digest))
            || !is_digest(&evidence.result_digest)
            || !is_digest(&evidence.response_digest)
        {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        if evidence
            .field_schema
            .iter()
            .any(|field| field.validate().is_err())
            || evidence
                .field_schema
                .windows(2)
                .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        let field_names = evidence
            .field_schema
            .iter()
            .map(|field| field.name.as_str())
            .collect::<BTreeSet<_>>();
        if evidence.aggregate_cells.iter().any(|row| {
            row.validate().is_err()
                || row
                    .cells
                    .keys()
                    .any(|name| !field_names.contains(name.as_str()))
        }) {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        if evidence
            .aggregate_cells
            .windows(2)
            .any(|pair| pair[0].digest() > pair[1].digest())
        {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        let expected_result_digest = canonical_digest(&(
            "splunk-aggregate-result/v1",
            &evidence.field_schema,
            &evidence.aggregate_cells,
            evidence.aggregate_partial,
            evidence.pages_read,
            &evidence.page_digests,
        ));
        if evidence.result_digest != expected_result_digest {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        if matches!(
            evidence.status,
            SplunkEvidenceStatus::Queued
                | SplunkEvidenceStatus::Running
                | SplunkEvidenceStatus::Failed
                | SplunkEvidenceStatus::Expired
                | SplunkEvidenceStatus::AccessLost
                | SplunkEvidenceStatus::ProviderUnknown
                | SplunkEvidenceStatus::Tampered
                | SplunkEvidenceStatus::Revoked
        ) && (!evidence.field_schema.is_empty()
            || !evidence.aggregate_cells.is_empty()
            || evidence.pages_read != 0
            || !evidence.page_digests.is_empty()
            || evidence.aggregate_partial)
        {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        if matches!(
            evidence.status,
            SplunkEvidenceStatus::Done | SplunkEvidenceStatus::Empty
        ) && evidence.aggregate_partial
        {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        if matches!(evidence.status, SplunkEvidenceStatus::Done)
            && evidence.aggregate_cells.is_empty()
        {
            return Err(SplunkSavedSearchResultServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

fn map_provider_error(error: SplunkProviderError) -> SplunkSavedSearchResultServiceError {
    match error {
        SplunkProviderError::RegistrationRevoked => {
            SplunkSavedSearchResultServiceError::RegistrationRevoked
        }
        SplunkProviderError::SecretRevoked => SplunkSavedSearchResultServiceError::SecretRevoked,
        SplunkProviderError::ScopeMismatch => SplunkSavedSearchResultServiceError::ScopeMismatch,
        SplunkProviderError::Model(error) => SplunkSavedSearchResultServiceError::Model(error),
        SplunkProviderError::ArbitrarySplRejected
        | SplunkProviderError::HttpStatus { .. }
        | SplunkProviderError::ResponseTooLarge { .. }
        | SplunkProviderError::MalformedResponse { .. }
        | SplunkProviderError::PaginationReplay { .. }
        | SplunkProviderError::ResultBoundExceeded { .. }
        | SplunkProviderError::Transport { .. } => {
            SplunkSavedSearchResultServiceError::EvidenceMismatch
        }
    }
}

fn normalize_success(
    scope: &SplunkSavedSearchResultScope,
    registration: &crate::SplunkRegistration,
    provider_digest: Digest,
    read: SplunkProviderRead,
) -> SplunkSavedSearchResultEvidence {
    evidence(
        read.status,
        classification_for_status(read.status, read.provenance),
        read.timing,
        &read.result,
        read.response_digest,
        scope,
        registration,
        provider_digest,
        read.provenance,
    )
}

fn normalize_failure(
    scope: &SplunkSavedSearchResultScope,
    registration: &crate::SplunkRegistration,
    secret_reference: &SecretReference,
    provider_digest: Digest,
    provenance: TransportProvenance,
    error: &SplunkProviderError,
) -> SplunkSavedSearchResultEvidence {
    let request = error
        .request()
        .cloned()
        .unwrap_or_else(|| fallback_request(scope, secret_reference));
    let (response_digest, _, _, _) = error.metadata().unwrap_or((
        canonical_digest(&("splunk-provider-error/v1", format!("{error:?}"))),
        0,
        None,
        request.operation,
    ));
    let status = failure_status(error, provenance);
    let result = SplunkAggregateResult::empty();
    evidence(
        status,
        classification_for_status(status, provenance),
        SplunkTiming::new(None, None).expect("empty timing is bounded"),
        &result,
        response_digest,
        scope,
        registration,
        provider_digest,
        provenance,
    )
}

fn evidence(
    status: SplunkEvidenceStatus,
    classification: EvidenceClassification,
    timing: SplunkTiming,
    result: &SplunkAggregateResult,
    response_digest: Digest,
    scope: &SplunkSavedSearchResultScope,
    registration: &crate::SplunkRegistration,
    provider_digest: Digest,
    provenance: TransportProvenance,
) -> SplunkSavedSearchResultEvidence {
    let mut evidence = SplunkSavedSearchResultEvidence {
        status,
        classification,
        timing,
        field_schema: result.field_schema.clone(),
        aggregate_cells: result.cells.clone(),
        aggregate_partial: result.partial,
        pages_read: result.pages,
        page_digests: result.page_digests.clone(),
        search_digest: scope.search_digest(),
        sid_digest: scope.sid_digest(),
        result_digest: result.result_digest.clone(),
        response_digest,
        scope_digest: scope.digest(),
        resource_scope_digest: scope.resource_digest(),
        revision_digest: scope.revision_digest().clone(),
        privacy_digest: scope.privacy_digest().clone(),
        registration_digest: registration.registration_digest.clone(),
        provider_digest,
        provenance,
        proposal_only: true,
        native: false,
        connected: false,
        first_party: false,
        truth_authority: false,
        consent_authority: false,
        effect_authority: false,
        receipt_authority: false,
        verification_authority: false,
        outcome_authority: false,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

fn failure_status(
    error: &SplunkProviderError,
    provenance: TransportProvenance,
) -> SplunkEvidenceStatus {
    if matches!(
        error,
        SplunkProviderError::RegistrationRevoked | SplunkProviderError::SecretRevoked
    ) {
        return SplunkEvidenceStatus::Revoked;
    }
    if matches!(
        error,
        SplunkProviderError::Transport {
            error: crate::SplunkTransportError::BlockedEnv,
            ..
        }
    ) || provenance.is_blocked_env()
    {
        return SplunkEvidenceStatus::AccessLost;
    }
    if let SplunkProviderError::HttpStatus {
        operation,
        status_code,
        ..
    } = error
    {
        return match status_code {
            401 | 403 => SplunkEvidenceStatus::AccessLost,
            404 => match operation {
                SplunkProviderOperation::JobStatus | SplunkProviderOperation::JobResults => {
                    SplunkEvidenceStatus::Expired
                }
            },
            _ => SplunkEvidenceStatus::ProviderUnknown,
        };
    }
    match error {
        SplunkProviderError::PaginationReplay { .. }
        | SplunkProviderError::ResultBoundExceeded { .. }
        | SplunkProviderError::MalformedResponse { .. }
        | SplunkProviderError::ResponseTooLarge { .. }
        | SplunkProviderError::ArbitrarySplRejected
        | SplunkProviderError::ScopeMismatch
        | SplunkProviderError::Model(_) => SplunkEvidenceStatus::Tampered,
        SplunkProviderError::Transport { .. } => SplunkEvidenceStatus::ProviderUnknown,
        SplunkProviderError::RegistrationRevoked | SplunkProviderError::SecretRevoked => {
            SplunkEvidenceStatus::Revoked
        }
        SplunkProviderError::HttpStatus { .. } => SplunkEvidenceStatus::ProviderUnknown,
    }
}

fn classification_for_status(
    status: SplunkEvidenceStatus,
    provenance: TransportProvenance,
) -> EvidenceClassification {
    match status {
        SplunkEvidenceStatus::Queued
        | SplunkEvidenceStatus::Running
        | SplunkEvidenceStatus::Done => EvidenceClassification::Normalized,
        SplunkEvidenceStatus::Failed | SplunkEvidenceStatus::ProviderUnknown => {
            EvidenceClassification::ProviderUnknown
        }
        SplunkEvidenceStatus::Expired | SplunkEvidenceStatus::AccessLost => {
            if provenance.is_blocked_env() {
                EvidenceClassification::BlockedEnv
            } else {
                EvidenceClassification::AccessLost
            }
        }
        SplunkEvidenceStatus::Partial => EvidenceClassification::Partial,
        SplunkEvidenceStatus::Empty => EvidenceClassification::Empty,
        SplunkEvidenceStatus::Tampered => EvidenceClassification::Tampered,
        SplunkEvidenceStatus::Revoked => EvidenceClassification::Revoked,
    }
}

fn fallback_request(
    scope: &SplunkSavedSearchResultScope,
    secret_reference: &SecretReference,
) -> SplunkProviderRequest {
    let resource = scope.resource();
    let mut request = SplunkProviderRequest {
        method: SplunkHttpMethod::Get,
        host: resource.host().as_str().to_owned(),
        path: format!("/services/search/jobs/{}", resource.sid().as_str()),
        operation: SplunkProviderOperation::JobStatus,
        page: None,
        search_digest: scope.search_digest(),
        sid_digest: scope.sid_digest(),
        scope_digest: scope.digest(),
        consent_digest: scope.consent_digest().clone(),
        secret_reference_digest: secret_reference.digest(),
        request_digest: String::new(),
    };
    request.request_digest = request.digest();
    request
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[allow(dead_code)]
fn _provider_version_is_bound() -> &'static str {
    SPLUNK_PROVIDER_VERSION
}

#[allow(dead_code)]
fn _plugin_version_is_bound() -> &'static str {
    SPLUNK_SEARCH_RESULT_PLUGIN_VERSION
}
