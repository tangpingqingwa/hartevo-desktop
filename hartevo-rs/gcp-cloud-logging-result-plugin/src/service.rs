use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    GCP_CLOUD_LOGGING_RESULT_API_OPERATION, GCP_CLOUD_LOGGING_RESULT_API_VERSION,
    GCP_CLOUD_LOGGING_RESULT_CONSUMER_ID, GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION,
    GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION, GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID,
    GCP_CLOUD_LOGGING_RESULT_SCHEMA_VERSION, GCP_CLOUD_LOGGING_RESULT_SERVICE_ID, contract_digest,
    model::{
        Digest, EvidenceAuthority, GcpCloudLoggingScope, LogEntryAggregate, MAX_METADATA_SAMPLES,
        MAX_RESULT_ENTRIES, MAX_RESULT_PAGES, MAX_RETRIES, ModelError, OpaquePageToken,
        PageSummary, ProviderErrorEvidence, ProviderErrorKind, RegistrationState, RetryEvidence,
        Revision, SecretReference,
    },
    provider::{
        EntriesListRequest, GcpCloudLoggingProvider, GcpCloudLoggingProviderDefinition,
        GcpCloudLoggingTransport, LogEntriesPage, ProviderDefinitionError, TransportError,
    },
};

pub type ResultEvidence = GcpCloudLoggingResultEvidence;
pub type ResultProjection = GcpCloudLoggingProjection;

pub const EVIDENCE_POLICY_VERSION: &str = "gcp-cloud-logging-evidence-policy/v1";

pub fn evidence_policy_digest() -> Digest {
    Digest::from_fields(
        EVIDENCE_POLICY_VERSION,
        &[
            GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION.to_owned(),
            format!("max_pages={MAX_RESULT_PAGES}"),
            format!("max_entries={MAX_RESULT_ENTRIES}"),
            format!("max_metadata_samples={MAX_METADATA_SAMPLES}"),
            "raw_text=false".to_owned(),
            "raw_json=false".to_owned(),
            "raw_proto=false".to_owned(),
            "labels=false".to_owned(),
            "trace_ids=false".to_owned(),
            "span_ids=false".to_owned(),
            "pii=false".to_owned(),
            "native=false".to_owned(),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GcpCloudLoggingProjection {
    Present,
    Empty,
    Partial,
    Timeout,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    EntryBound,
    PageBound,
    RateLimited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RetryPolicy {
    pub max_retries: u8,
}

impl RetryPolicy {
    pub fn new(max_retries: u8) -> Result<Self, ModelError> {
        if max_retries > MAX_RETRIES {
            Err(ModelError::InvalidPageSize)
        } else {
            Ok(Self { max_retries })
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_retries: 2 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudLoggingRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub provider_version: String,
    pub api_digest: Digest,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl GcpCloudLoggingRegistration {
    fn new(
        scope: &GcpCloudLoggingScope,
        secret: &SecretReference,
        provider: &GcpCloudLoggingProviderDefinition,
    ) -> Result<Self, ModelError> {
        let registration_revision = Revision::new(1)?;
        let mut registration = Self {
            schema_version: GCP_CLOUD_LOGGING_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION.to_owned(),
            service_id: GCP_CLOUD_LOGGING_RESULT_SERVICE_ID.to_owned(),
            provider_id: GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: GCP_CLOUD_LOGGING_RESULT_CONSUMER_ID.to_owned(),
            provider_version: provider.version.clone(),
            api_digest: Digest::from_fields(
                "gcp-cloud-logging-api/v1",
                &[
                    GCP_CLOUD_LOGGING_RESULT_API_VERSION.to_owned(),
                    GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
                ],
            ),
            plugin_version_digest: Digest::from_text(GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest(),
            evidence_digest: evidence_policy_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn is_reversible(&self) -> bool {
        matches!(
            self.state,
            RegistrationState::Active | RegistrationState::Reversed
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-logging-registration/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.plugin_version.clone(),
                self.service_id.clone(),
                self.provider_id.clone(),
                self.consumer_id.clone(),
                self.provider_version.clone(),
                self.api_digest.as_str().to_owned(),
                self.plugin_version_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn validate(
        &self,
        scope: &GcpCloudLoggingScope,
        secret: &SecretReference,
        provider: &GcpCloudLoggingProviderDefinition,
    ) -> Result<(), ModelError> {
        if self.schema_version != GCP_CLOUD_LOGGING_RESULT_SCHEMA_VERSION
            || self.contract_version != GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION
            || self.plugin_version != GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION
            || self.service_id != GCP_CLOUD_LOGGING_RESULT_SERVICE_ID
            || self.provider_id != GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID
            || self.consumer_id != GCP_CLOUD_LOGGING_RESULT_CONSUMER_ID
            || self.provider_version != provider.version
            || self.api_digest
                != Digest::from_fields(
                    "gcp-cloud-logging-api/v1",
                    &[
                        GCP_CLOUD_LOGGING_RESULT_API_VERSION.to_owned(),
                        GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
                    ],
                )
            || self.plugin_version_digest
                != Digest::from_text(GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION)
            || self.contract_digest != contract_digest()
            || self.provider_digest != provider.provider_digest
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != scope.digest()
            || self.evidence_digest != evidence_policy_digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.registration_digest != self.recomputed_digest()
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, ModelError> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition, ModelError> {
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidLifecycle);
        }
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransition, ModelError> {
        if self.state != RegistrationState::Reversed {
            return Err(ModelError::InvalidLifecycle);
        }
        self.transition(RegistrationState::Active)
    }

    fn transition(
        &mut self,
        new_state: RegistrationState,
    ) -> Result<RegistrationTransition, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let next_revision = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(ModelError::InvalidLifecycle)?;
        let previous_state = self.state;
        self.registration_revision = Revision::new(next_revision)?;
        self.state = new_state;
        self.registration_digest = self.recomputed_digest();
        let transition_digest = Digest::from_fields(
            "gcp-cloud-logging-registration-transition/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                format!("{previous_state:?}"),
                format!("{new_state:?}"),
                self.registration_revision.get().to_string(),
            ],
        );
        Ok(RegistrationTransition {
            previous_state,
            new_state,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudLoggingResultEvidence {
    pub projection: GcpCloudLoggingProjection,
    pub scope_digest: Digest,
    pub provider_resource_digest: Digest,
    pub filter_digest: Digest,
    pub time_window_digest: Digest,
    pub permission_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub entries: Vec<LogEntryAggregate>,
    pub metadata_sample_digests: Vec<Digest>,
    pub pages: Vec<PageSummary>,
    pub retries: Vec<RetryEvidence>,
    pub provider_error: Option<ProviderErrorEvidence>,
    pub partial_reason: Option<PartialReason>,
    pub truncated: bool,
    pub evidence_digest: Digest,
    pub authority: EvidenceAuthority,
}

impl GcpCloudLoggingResultEvidence {
    fn new(
        scope: &GcpCloudLoggingScope,
        registration: &GcpCloudLoggingRegistration,
        provider_digest: &Digest,
        projection: GcpCloudLoggingProjection,
        entries: Vec<LogEntryAggregate>,
        pages: Vec<PageSummary>,
        retries: Vec<RetryEvidence>,
        provider_error: Option<ProviderErrorEvidence>,
        partial_reason: Option<PartialReason>,
        truncated: bool,
    ) -> Self {
        let mut evidence = Self {
            projection,
            scope_digest: scope.digest(),
            provider_resource_digest: scope.provider_resource_digest().clone(),
            filter_digest: scope.filter_digest().clone(),
            time_window_digest: scope.time_window_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            project_digest: scope.project.digest.clone(),
            mission_digest: scope.mission.digest.clone(),
            work_product_digest: scope.work_product.digest.clone(),
            provider_digest: provider_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            evidence_policy_digest: evidence_policy_digest(),
            metadata_sample_digests: entries
                .iter()
                .take(MAX_METADATA_SAMPLES)
                .map(|entry| entry.metadata_digest.clone())
                .collect(),
            entries,
            pages,
            retries,
            provider_error,
            partial_reason,
            truncated,
            evidence_digest: Digest::zero(),
            authority: EvidenceAuthority,
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        let entry_digests = self
            .entries
            .iter()
            .map(LogEntryAggregate::digest)
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(",");
        let page_digests = self
            .pages
            .iter()
            .map(|page| {
                format!(
                    "{}:{}:{}:{}:{}",
                    page.page_number,
                    page.page_digest,
                    page.entry_count,
                    page.next_page_token_digest
                        .as_ref()
                        .map_or("none", Digest::as_str),
                    page.complete
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let metadata_sample_digests = self
            .metadata_sample_digests
            .iter()
            .map(Digest::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let retry_digests = self
            .retries
            .iter()
            .map(|retry| {
                format!(
                    "{}:{}:{:?}:{}:{}",
                    retry.operation,
                    retry.failed_attempt,
                    retry.kind,
                    retry.status_code.map_or(0, u16::from),
                    retry.diagnostic_digest
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let provider_error_digest = self.provider_error.as_ref().map_or_else(
            || "none".to_owned(),
            |error| {
                format!(
                    "{:?}:{}:{}:{}",
                    error.kind,
                    error.status_code.map_or(0, u16::from),
                    error.diagnostic_digest,
                    error.blocked_env
                )
            },
        );
        Digest::from_fields(
            "gcp-cloud-logging-result-evidence/v1",
            &[
                format!("{:?}", self.projection),
                self.scope_digest.as_str().to_owned(),
                self.provider_resource_digest.as_str().to_owned(),
                self.filter_digest.as_str().to_owned(),
                self.time_window_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.project_digest.as_str().to_owned(),
                self.mission_digest.as_str().to_owned(),
                self.work_product_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.evidence_policy_digest.as_str().to_owned(),
                entry_digests,
                metadata_sample_digests,
                page_digests,
                retry_digests,
                provider_error_digest,
                self.partial_reason
                    .map_or_else(|| "none".to_owned(), |reason| format!("{reason:?}")),
                self.truncated.to_string(),
            ],
        )
    }

    pub fn validate(&self, scope: &GcpCloudLoggingScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.provider_resource_digest != *scope.provider_resource_digest()
            || self.filter_digest != *scope.filter_digest()
            || self.time_window_digest != *scope.time_window_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.project_digest != scope.project.digest
            || self.mission_digest != scope.mission.digest
            || self.work_product_digest != scope.work_product.digest
            || self.evidence_policy_digest != evidence_policy_digest()
            || self.entries.len() > MAX_RESULT_ENTRIES
            || self.metadata_sample_digests.len() > MAX_METADATA_SAMPLES
            || self.pages.len() > MAX_RESULT_PAGES as usize
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        for entry in &self.entries {
            entry.validate_for(scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudLoggingResultProposal {
    pub projection: GcpCloudLoggingProjection,
    pub evidence: GcpCloudLoggingResultEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub proposal_digest: Digest,
    pub authority: EvidenceAuthority,
}

impl GcpCloudLoggingResultProposal {
    fn new(
        projection: GcpCloudLoggingProjection,
        evidence: GcpCloudLoggingResultEvidence,
        registration: &GcpCloudLoggingRegistration,
        provider_digest: &Digest,
    ) -> Self {
        let mut proposal = Self {
            projection,
            evidence,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_digest: provider_digest.clone(),
            proposal_digest: Digest::zero(),
            authority: EvidenceAuthority,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-logging-result-proposal/v1",
            &[
                format!("{:?}", self.projection),
                self.evidence.evidence_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                self.provider_digest.as_str().to_owned(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), GcpCloudLoggingResultServiceError> {
        if self.evidence.evidence_digest != self.evidence.recomputed_digest()
            || self.projection != self.evidence.projection
            || self.registration_digest != self.evidence.registration_digest
            || self.provider_digest != self.evidence.provider_digest
            || self.proposal_digest != self.recomputed_digest()
        {
            Err(GcpCloudLoggingResultServiceError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpCloudLoggingResultServiceError {
    #[error("GCP Cloud Logging model error: {0}")]
    Model(#[from] ModelError),
    #[error("GCP Cloud Logging provider definition error: {0}")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("GCP Cloud Logging registration is revoked or inactive")]
    RegistrationRevoked,
    #[error("GCP Cloud Logging proposal/evidence is stale or tampered")]
    TamperedEvidence,
}

pub struct GcpCloudLoggingResultService<T>
where
    T: GcpCloudLoggingTransport,
{
    scope: GcpCloudLoggingScope,
    secret: SecretReference,
    provider: GcpCloudLoggingProvider<T>,
    registration: GcpCloudLoggingRegistration,
    retry_policy: RetryPolicy,
}

impl<T> fmt::Debug for GcpCloudLoggingResultService<T>
where
    T: GcpCloudLoggingTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudLoggingResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl<T> GcpCloudLoggingResultService<T>
where
    T: GcpCloudLoggingTransport,
{
    pub fn new(
        scope: GcpCloudLoggingScope,
        secret: SecretReference,
        provider: GcpCloudLoggingProvider<T>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, GcpCloudLoggingResultServiceError> {
        scope.validate()?;
        if secret.scope_digest() != &scope.digest() || secret.is_revoked() {
            return Err(GcpCloudLoggingResultServiceError::Model(
                ModelError::InvalidRegistration,
            ));
        }
        provider.definition().validate_scope(&scope)?;
        let registration =
            GcpCloudLoggingRegistration::new(&scope, &secret, provider.definition())?;
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            retry_policy,
        })
    }

    pub fn register(
        scope: GcpCloudLoggingScope,
        secret: SecretReference,
        provider: GcpCloudLoggingProvider<T>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, GcpCloudLoggingResultServiceError> {
        Self::new(scope, secret, provider, retry_policy)
    }

    pub fn scope(&self) -> &GcpCloudLoggingScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn provider(&self) -> &GcpCloudLoggingProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GcpCloudLoggingProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &GcpCloudLoggingRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut GcpCloudLoggingRegistration {
        &mut self.registration
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransition, ModelError> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransition, ModelError> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransition, ModelError> {
        self.registration.restore()
    }

    pub fn propose(
        &mut self,
    ) -> Result<GcpCloudLoggingResultProposal, GcpCloudLoggingResultServiceError> {
        if !self.registration.is_active() || self.secret.is_revoked() {
            return Ok(self.proposal(
                GcpCloudLoggingProjection::Revoked,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                None,
                false,
            ));
        }
        let mut request = EntriesListRequest::first(&self.scope)?;
        let mut entries = Vec::new();
        let mut pages = Vec::new();
        let mut retries = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut provider_error = None;
        let mut partial_reason = None;
        let mut truncated = false;

        let projection = loop {
            let response = self.fetch_with_retry(&request, &mut retries);
            let page = match response {
                Ok(page) => page,
                Err(error) => {
                    provider_error = Some(error.evidence().clone());
                    break if error.kind().is_access_loss() {
                        GcpCloudLoggingProjection::AccessLost
                    } else if matches!(error.kind(), ProviderErrorKind::Timeout) {
                        GcpCloudLoggingProjection::Timeout
                    } else if matches!(error.kind(), ProviderErrorKind::RateLimited)
                        && !entries.is_empty()
                    {
                        partial_reason = Some(PartialReason::RateLimited);
                        GcpCloudLoggingProjection::Partial
                    } else {
                        GcpCloudLoggingProjection::ProviderUnknown
                    };
                }
            };
            if page.validate_for(&self.scope, &request).is_err() {
                return Ok(self.tampered_proposal("page validation failed"));
            }
            pages.push(PageSummary {
                page_number: page.page_number,
                page_digest: page.page_digest.clone(),
                entry_count: page.entries.len(),
                next_page_token_digest: page
                    .next_page_token
                    .as_ref()
                    .map(|token| token.token_digest().clone()),
                complete: page.complete,
            });
            if entries.len() + page.entries.len() > MAX_RESULT_ENTRIES {
                let remaining = MAX_RESULT_ENTRIES.saturating_sub(entries.len());
                entries.extend(page.entries.into_iter().take(remaining));
                partial_reason = Some(PartialReason::EntryBound);
                truncated = true;
                break GcpCloudLoggingProjection::Partial;
            }
            entries.extend(page.entries);
            let Some(token) = page.next_page_token else {
                break if entries.is_empty() {
                    GcpCloudLoggingProjection::Empty
                } else {
                    GcpCloudLoggingProjection::Present
                };
            };
            if !seen_tokens.insert(token.token_digest().clone()) {
                return Ok(self.tampered_proposal("page token loop"));
            }
            if pages.len() >= MAX_RESULT_PAGES as usize {
                partial_reason = Some(PartialReason::PageBound);
                truncated = true;
                break GcpCloudLoggingProjection::Partial;
            }
            request = EntriesListRequest::next(&self.scope, &request, &token)?;
        };

        Ok(self.proposal(
            projection,
            entries,
            pages,
            retries,
            provider_error,
            partial_reason,
            truncated,
        ))
    }

    fn fetch_with_retry(
        &mut self,
        request: &EntriesListRequest,
        retries: &mut Vec<RetryEvidence>,
    ) -> Result<LogEntriesPage, TransportError> {
        let mut failed_attempt = 0_u8;
        loop {
            match self.provider.list_entries(request) {
                Ok(page) => return Ok(page),
                Err(error)
                    if error.kind().is_retryable()
                        && failed_attempt < self.retry_policy.max_retries =>
                {
                    failed_attempt = failed_attempt.saturating_add(1);
                    retries.push(RetryEvidence::from_error(failed_attempt, error.evidence()));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn tampered_proposal(&self, reason: &str) -> GcpCloudLoggingResultProposal {
        self.proposal(
            GcpCloudLoggingProjection::Tampered,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(ProviderErrorEvidence::new(
                ProviderErrorKind::Unknown,
                None,
                reason,
            )),
            None,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn proposal(
        &self,
        projection: GcpCloudLoggingProjection,
        entries: Vec<LogEntryAggregate>,
        pages: Vec<PageSummary>,
        retries: Vec<RetryEvidence>,
        provider_error: Option<ProviderErrorEvidence>,
        partial_reason: Option<PartialReason>,
        truncated: bool,
    ) -> GcpCloudLoggingResultProposal {
        let evidence = GcpCloudLoggingResultEvidence::new(
            &self.scope,
            &self.registration,
            self.provider.provider_digest(),
            projection,
            entries,
            pages,
            retries,
            provider_error,
            partial_reason,
            truncated,
        );
        GcpCloudLoggingResultProposal::new(
            projection,
            evidence,
            &self.registration,
            self.provider.provider_digest(),
        )
    }
}

pub type GcpCloudLoggingResultServiceAlias<T> = GcpCloudLoggingResultService<T>;

#[allow(dead_code)]
fn _keep_opaque_token_type_public(_: Option<OpaquePageToken>) {}
