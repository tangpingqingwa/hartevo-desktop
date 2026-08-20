//! Typed registration and bounded read service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{AwsEmrServerlessJobResultError, AwsEmrServerlessTransportError, Result};
use crate::model::{
    AwsEmrServerlessJobResultScope, Digest, EvidenceDigests, JobRunEvidence, JobRunState,
    PartialReason, ProviderErrorEvidence, SecretReference, TransportProvenance,
    provider_error_evidence, response_digest, validate_monotonic_lifecycle,
};
use crate::provider::{
    AwsEmrServerlessOperation, AwsEmrServerlessProvider, AwsEmrServerlessProviderDefinition,
    GetApplicationRequest, GetApplicationResponse, GetJobRunRequest, GetJobRunResponse,
    ListJobRunsRequest, ListJobRunsResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = response_digest(
            "aws-emr-serverless-registration-transition/v1",
            &[
                ("previous", previous_status.as_str().to_owned()),
                ("new", new_status.as_str().to_owned()),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

/// Version, provider, scope, credential-reference, and Mission-bound
/// registration. The credential handle is retained only inside the opaque
/// `SecretReference`; it is never serialized or printed.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsEmrServerlessJobResultRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_api_revision: String,
    provider_release: String,
    provider_digest: Digest,
    permission_digest: Digest,
    scope: AwsEmrServerlessJobResultScope,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsEmrServerlessJobResultRegistration {
    pub fn new<T: crate::provider::AwsEmrServerlessTransport>(
        id: impl Into<String>,
        scope: AwsEmrServerlessJobResultScope,
        provider: &AwsEmrServerlessProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.definition().provider_id().to_owned(),
            provider_api_revision: provider.definition().api_revision().to_owned(),
            provider_release: provider.definition().release().to_owned(),
            provider_digest: provider.definition().definition_digest().clone(),
            permission_digest: crate::model::permissions_digest(),
            scope_digest: scope.scope_digest().clone(),
            secret_reference_digest: scope.secret_reference().reference_digest(),
            scope,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate_against(provider.definition())?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
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

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_api_revision(&self) -> &str {
        &self.provider_api_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope(&self) -> &AwsEmrServerlessJobResultScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.scope.secret_reference()
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_api_revision.is_empty()
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != *self.scope.scope_digest()
            || self.secret_reference_digest != self.scope.secret_reference().reference_digest()
            || self.permission_digest != crate::model::permissions_digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsEmrServerlessJobResultError::InvalidRegistration);
        }
        self.scope.validate()
    }

    pub(crate) fn validate_against(
        &self,
        provider: &AwsEmrServerlessProviderDefinition,
    ) -> Result<()> {
        self.validate()?;
        provider.validate()?;
        if self.provider_id != provider.provider_id()
            || self.provider_api_revision != provider.api_revision()
            || self.provider_release != provider.release()
            || self.provider_digest != *provider.definition_digest()
        {
            return Err(AwsEmrServerlessJobResultError::ProviderDrift);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(AwsEmrServerlessJobResultError::RegistrationReversed);
        }
        if self.status == RegistrationStatus::Revoked {
            return Err(AwsEmrServerlessJobResultError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(AwsEmrServerlessJobResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(AwsEmrServerlessJobResultError::RegistrationReversed);
        }
        if self.status != RegistrationStatus::Revoked {
            return Err(AwsEmrServerlessJobResultError::RegistrationInactive);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        response_digest(
            "aws-emr-serverless-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_id.clone()),
                ("api", self.provider_api_revision.clone()),
                ("release", self.provider_release.clone()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", self.status.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for AwsEmrServerlessJobResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEmrServerlessJobResultRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

pub type AwsEmrServerlessRegistration = AwsEmrServerlessJobResultRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEmrServerlessJobResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub scope_digest: Digest,
    pub status: JobRunState,
    pub partial_reason: Option<PartialReason>,
    pub evidence: Option<JobRunEvidence>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

impl AwsEmrServerlessJobResultProposal {
    pub fn status(&self) -> JobRunState {
        self.status
    }

    pub const fn is_complete(&self) -> bool {
        matches!(
            self.status,
            JobRunState::Success | JobRunState::Failed | JobRunState::Cancelled
        )
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn evidence_digests(&self) -> Option<&EvidenceDigests> {
        self.evidence.as_ref().map(|value| &value.digests)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.verification_authority
            || self.outcome_authority
            || self.work_product_adopted
            || self
                .evidence
                .as_ref()
                .is_some_and(|value| value.validate_integrity().is_err())
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        response_digest(
            "aws-emr-serverless-job-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                (
                    "partial_reason",
                    self.partial_reason
                        .map_or_else(String::new, |value| format!("{value:?}")),
                ),
                (
                    "evidence",
                    self.evidence.as_ref().map_or_else(String::new, |value| {
                        value.digests.evidence_digest.as_str().to_owned()
                    }),
                ),
                (
                    "provider_errors",
                    self.provider_errors
                        .iter()
                        .map(|value| value.error_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

pub struct AwsEmrServerlessJobResultService<T> {
    scope: AwsEmrServerlessJobResultScope,
    provider: AwsEmrServerlessProvider<T>,
    registration: AwsEmrServerlessJobResultRegistration,
    last_lifecycle_state: Option<JobRunState>,
}

impl<T: crate::provider::AwsEmrServerlessTransport> AwsEmrServerlessJobResultService<T> {
    pub fn new(
        scope: AwsEmrServerlessJobResultScope,
        provider: AwsEmrServerlessProvider<T>,
        registration: AwsEmrServerlessJobResultRegistration,
    ) -> Result<Self> {
        scope.validate()?;
        registration.validate_against(provider.definition())?;
        if registration.scope_digest() != scope.scope_digest() {
            return Err(AwsEmrServerlessJobResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            provider,
            registration,
            last_lifecycle_state: None,
        })
    }

    pub fn register(
        id: impl Into<String>,
        scope: AwsEmrServerlessJobResultScope,
        provider: AwsEmrServerlessProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = AwsEmrServerlessJobResultRegistration::new(
            id,
            scope.clone(),
            &provider,
            registration_revision,
        )?;
        Self::new(scope, provider, registration)
    }

    pub fn scope(&self) -> &AwsEmrServerlessJobResultScope {
        &self.scope
    }

    pub fn provider_definition(&self) -> &AwsEmrServerlessProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &AwsEmrServerlessJobResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsEmrServerlessJobResultRegistration {
        &mut self.registration
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn propose(&mut self) -> Result<AwsEmrServerlessJobResultProposal> {
        self.propose_at(Utc::now())
    }

    pub fn propose_at(&mut self, now: DateTime<Utc>) -> Result<AwsEmrServerlessJobResultProposal> {
        self.registration
            .validate_against(self.provider.definition())?;
        if !self.registration.is_active() {
            return Ok(self.build_proposal(JobRunState::Revoked, None, None, Vec::new()));
        }
        if self.scope.is_expired(now) {
            return Ok(self.build_proposal(JobRunState::Expired, None, None, Vec::new()));
        }

        let application_request = GetApplicationRequest::new(&self.scope);
        let application_response = match self.provider.get_application(&application_request) {
            Ok(response) => response,
            Err(error) => return Ok(self.transport_proposal("GetApplication", error)),
        };
        if let Err(error) = self.validate_application_response(&application_response) {
            return Ok(self.validation_proposal(error));
        }

        let job_run_request = GetJobRunRequest::new(&self.scope);
        let job_run_response = match self.provider.get_job_run(&job_run_request) {
            Ok(response) => response,
            Err(error) => return Ok(self.transport_proposal("GetJobRun", error)),
        };
        if let Err(error) = self.validate_job_run_response(&job_run_response) {
            return Ok(self.validation_proposal(error));
        }

        let application = application_response.application();
        let job_run = job_run_response.job_run();
        let mut list_response_digests = Vec::new();
        let mut exact_job_run_found = false;
        let mut next_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut page_count = 0_u16;
        let mut list_partial_reason = None;

        loop {
            page_count = page_count.saturating_add(1);
            let request = ListJobRunsRequest::new(&self.scope, crate::MAX_PAGE_SIZE, next_token)?;
            let response = match self.provider.list_job_runs(&request) {
                Ok(response) => response,
                Err(error) => {
                    let status = transport_status(error);
                    let evidence = JobRunEvidence::from_records(
                        &self.scope,
                        application,
                        job_run,
                        list_response_digest(&list_response_digests),
                        status,
                        self.provider.provenance(),
                    );
                    return Ok(self.build_proposal(
                        status,
                        Some(evidence),
                        None,
                        vec![provider_error_evidence("ListJobRuns", error)],
                    ));
                }
            };
            if let Err(error) = self.validate_list_response(&request, &response) {
                return Ok(self.validation_proposal(error));
            }
            list_response_digests.push(response.response_digest().clone());
            if response.summaries().iter().any(|summary| {
                summary.application_id() == self.scope.application_id()
                    && summary.job_run_id() == self.scope.job_run_id()
                    && summary.attempt() == self.scope.attempt()
            }) {
                exact_job_run_found = true;
            }
            let Some(token) = response.next_token().cloned() else {
                break;
            };
            if !seen_tokens.insert(token.digest()) {
                return Ok(self.validation_proposal(AwsEmrServerlessJobResultError::PageLoop));
            }
            if page_count >= MAX_PAGES {
                list_partial_reason = Some(PartialReason::PageCap);
                break;
            }
            next_token = Some(token);
        }

        if !exact_job_run_found {
            if list_partial_reason.is_some() {
                list_partial_reason = Some(PartialReason::MissingExactJobRun);
            } else {
                return Ok(
                    self.validation_proposal(AwsEmrServerlessJobResultError::ExactJobRunMissing)
                );
            }
        }

        let mut status = job_run.state();
        let mut partial_reason = list_partial_reason;
        if let Some(reason) = partial_reason {
            status = JobRunState::Partial;
            partial_reason = Some(reason);
        }
        if let Err(error) = validate_monotonic_lifecycle(self.last_lifecycle_state, status) {
            return Ok(self.validation_proposal(error));
        }
        if status.lifecycle_rank().is_some() {
            self.last_lifecycle_state = Some(status);
        }
        let evidence = JobRunEvidence::from_records(
            &self.scope,
            application,
            job_run,
            list_response_digest(&list_response_digests),
            status,
            self.provider.provenance(),
        );
        Ok(self.build_proposal_with_reason(status, partial_reason, Some(evidence), Vec::new()))
    }

    fn validate_application_response(&self, response: &GetApplicationResponse) -> Result<()> {
        response.validate()?;
        if response.scope_digest() != self.scope.scope_digest() {
            return Err(AwsEmrServerlessJobResultError::ResponseScopeMismatch);
        }
        if response.credential_revision() != self.scope.secret_reference().credential_revision() {
            return Err(AwsEmrServerlessJobResultError::CredentialMismatch);
        }
        if response.application().application_id() != self.scope.application_id()
            || response.application().release_label() != self.scope.release_label()
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_job_run_response(&self, response: &GetJobRunResponse) -> Result<()> {
        response.validate()?;
        if response.scope_digest() != self.scope.scope_digest() {
            return Err(AwsEmrServerlessJobResultError::ResponseScopeMismatch);
        }
        if response.credential_revision() != self.scope.secret_reference().credential_revision() {
            return Err(AwsEmrServerlessJobResultError::CredentialMismatch);
        }
        let job_run = response.job_run();
        if job_run.application_id() != self.scope.application_id()
            || job_run.job_run_id() != self.scope.job_run_id()
            || job_run.attempt() != self.scope.attempt()
            || job_run.execution_role_digest() != self.scope.execution_role_digest()
            || job_run.release_label() != self.scope.release_label()
            || job_run.job_driver_digest() != self.scope.job_driver_digest()
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_list_response(
        &self,
        request: &ListJobRunsRequest,
        response: &ListJobRunsResponse,
    ) -> Result<()> {
        response.validate()?;
        if response.scope_digest() != self.scope.scope_digest() {
            return Err(AwsEmrServerlessJobResultError::ResponseScopeMismatch);
        }
        if response.credential_revision() != self.scope.secret_reference().credential_revision() {
            return Err(AwsEmrServerlessJobResultError::CredentialMismatch);
        }
        if response
            .next_token()
            .is_some_and(|token| token.binding_digest() != request.binding_digest())
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn transport_proposal(
        &self,
        operation: &str,
        error: AwsEmrServerlessTransportError,
    ) -> AwsEmrServerlessJobResultProposal {
        let status = transport_status(error);
        self.build_proposal(
            status,
            None,
            Some(PartialReason::ProviderPartial).filter(|_| status == JobRunState::Partial),
            vec![provider_error_evidence(operation, error)],
        )
    }

    fn validation_proposal(
        &self,
        error: AwsEmrServerlessJobResultError,
    ) -> AwsEmrServerlessJobResultProposal {
        let status = validation_status(&error);
        let partial_reason = match error {
            AwsEmrServerlessJobResultError::PageCap => Some(PartialReason::PageCap),
            AwsEmrServerlessJobResultError::ResponseTooLarge
            | AwsEmrServerlessJobResultError::SummaryCap => Some(PartialReason::ResponseCap),
            _ => None,
        };
        self.build_proposal(status, None, partial_reason, Vec::new())
    }

    fn build_proposal(
        &self,
        status: JobRunState,
        evidence: Option<JobRunEvidence>,
        partial_reason: Option<PartialReason>,
        provider_errors: Vec<ProviderErrorEvidence>,
    ) -> AwsEmrServerlessJobResultProposal {
        self.build_proposal_with_reason(status, partial_reason, evidence, provider_errors)
    }

    fn build_proposal_with_reason(
        &self,
        status: JobRunState,
        partial_reason: Option<PartialReason>,
        evidence: Option<JobRunEvidence>,
        provider_errors: Vec<ProviderErrorEvidence>,
    ) -> AwsEmrServerlessJobResultProposal {
        let mut proposal = AwsEmrServerlessJobResultProposal {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())
                .expect("checked contract digest"),
            proposal_digest: Digest::from_text("unsealed-proposal"),
            registration_digest: self.registration.registration_digest().clone(),
            registration_revision: self.registration.registration_revision(),
            scope_digest: self.scope.scope_digest().clone(),
            status,
            partial_reason,
            evidence,
            provider_errors,
            provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            verification_authority: false,
            outcome_authority: false,
            work_product_adopted: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }
}

impl<T: crate::provider::AwsEmrServerlessTransport + fmt::Debug> fmt::Debug
    for AwsEmrServerlessJobResultService<T>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEmrServerlessJobResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("last_lifecycle_state", &self.last_lifecycle_state)
            .finish()
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn list_response_digest(digests: &[Digest]) -> Digest {
    response_digest(
        "aws-emr-serverless-list-job-runs-pages/v1",
        &[(
            "pages",
            digests
                .iter()
                .map(Digest::as_str)
                .collect::<Vec<_>>()
                .join(","),
        )],
    )
}

fn transport_status(error: AwsEmrServerlessTransportError) -> JobRunState {
    match error {
        AwsEmrServerlessTransportError::Unauthorized
        | AwsEmrServerlessTransportError::Forbidden => JobRunState::AccessLost,
        AwsEmrServerlessTransportError::NotFound => JobRunState::Expired,
        AwsEmrServerlessTransportError::Timeout | AwsEmrServerlessTransportError::Partial => {
            JobRunState::Partial
        }
        AwsEmrServerlessTransportError::BlockedEnv
        | AwsEmrServerlessTransportError::BadRequest
        | AwsEmrServerlessTransportError::RateLimited
        | AwsEmrServerlessTransportError::ServerError { .. }
        | AwsEmrServerlessTransportError::InvalidResponse => JobRunState::ProviderUnknown,
    }
}

fn validation_status(error: &AwsEmrServerlessJobResultError) -> JobRunState {
    match error {
        AwsEmrServerlessJobResultError::CredentialMismatch => JobRunState::AccessLost,
        AwsEmrServerlessJobResultError::PageCap
        | AwsEmrServerlessJobResultError::ResponseTooLarge
        | AwsEmrServerlessJobResultError::SummaryCap => JobRunState::Partial,
        AwsEmrServerlessJobResultError::ExpiredMission => JobRunState::Expired,
        AwsEmrServerlessJobResultError::RegistrationRevoked => JobRunState::Revoked,
        AwsEmrServerlessJobResultError::Transport(transport) => transport_status(*transport),
        AwsEmrServerlessJobResultError::ResponseScopeMismatch
        | AwsEmrServerlessJobResultError::TamperedEvidence
        | AwsEmrServerlessJobResultError::ExactJobRunMissing
        | AwsEmrServerlessJobResultError::PageLoop
        | AwsEmrServerlessJobResultError::LifecycleRegression => JobRunState::Tampered,
        _ => JobRunState::ProviderUnknown,
    }
}

pub(crate) fn _operation_name(operation: AwsEmrServerlessOperation) -> &'static str {
    operation.as_str()
}

pub(crate) fn _response_digest_for_tests(values: &[(&str, String)]) -> Digest {
    response_digest("aws-emr-serverless-test/v1", values)
}

pub(crate) fn _provider_error_for_tests(
    operation: &str,
    error: AwsEmrServerlessTransportError,
) -> ProviderErrorEvidence {
    provider_error_evidence(operation, error)
}

pub(crate) fn _scope_secret_for_tests(scope: &AwsEmrServerlessJobResultScope) -> &SecretReference {
    scope.secret_reference()
}
