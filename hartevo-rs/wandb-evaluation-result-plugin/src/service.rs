//! Typed service orchestration and reversible registration lifecycle.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    canonical_digest,
    model::{
        Digest, EvidenceSource, EvidenceStatus, NativeStatus, PluginVersion, WandbEvaluationError,
        WandbEvaluationEvidence, WandbEvaluationPage, WandbEvaluationPolicy,
        WandbEvaluationReadRequest, WandbEvaluationReceiptCandidate, WandbEvaluationResultProposal,
        WandbEvaluationScope, WandbPluginRegistration, WandbProviderError,
    },
    provider::{WandbProvider, WandbProviderManifest},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbEvaluationServiceConfig {
    pub policy: WandbEvaluationPolicy,
    pub default_as_of_ms: u64,
}

impl WandbEvaluationServiceConfig {
    #[must_use]
    pub fn fixture() -> Self {
        Self {
            policy: WandbEvaluationPolicy::fixture(),
            default_as_of_ms: 10_000,
        }
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.policy.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbCapabilities {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: PluginVersion,
    pub service_id: String,
    pub provider_id: String,
    pub source: EvidenceSource,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub metric_writes: bool,
    pub artifact_upload: bool,
    pub artifact_download: bool,
    pub sweep_launch: bool,
    pub raw_history: bool,
    pub raw_dataset: bool,
    pub raw_media: bool,
    pub generic_telemetry: bool,
    pub operations: Vec<String>,
    pub secret_reference_required: bool,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub metric_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WandbReadProposal {
    pub scope: WandbEvaluationScope,
    pub page_size: u16,
    pub history_limit: usize,
    pub max_response_bytes: usize,
    pub as_of_ms: u64,
    pub registration_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub metric_digest: Digest,
    pub external_write: bool,
    pub connected: bool,
    pub native: bool,
    pub request_digest: Digest,
}

impl WandbReadProposal {
    fn new(
        request: &WandbEvaluationReadRequest,
        registration: &WandbPluginRegistration,
        manifest: &WandbProviderManifest,
    ) -> Self {
        let mut proposal = Self {
            scope: request.scope.clone(),
            page_size: request.page_size,
            history_limit: request.history_limit,
            max_response_bytes: request.max_response_bytes,
            as_of_ms: request.as_of_ms,
            registration_digest: registration.registration_digest.clone(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
            provider_digest: manifest.provider_digest.clone(),
            api_digest: manifest.api_digest.clone(),
            permission_digest: manifest.permission_digest.clone(),
            revision_digest: manifest.revision_digest.clone(),
            metric_digest: manifest.metric_digest.clone(),
            external_write: false,
            connected: false,
            native: false,
            request_digest: Digest::from_text("uninitialized-wandb-read-proposal"),
        };
        proposal.request_digest = proposal.calculated_digest();
        proposal
    }

    pub fn validate(
        &self,
        registration: &WandbPluginRegistration,
        policy: &WandbEvaluationPolicy,
    ) -> Result<(), WandbEvaluationError> {
        registration.ensure_active(
            &self.scope,
            &crate::WandbPermissionSnapshot::read_only(self.scope.permission_revision.clone())?,
        )?;
        policy.validate()?;
        self.scope.validate()?;
        if self.scope.digest() != &registration.scope_digest
            || self.registration_digest != registration.registration_digest
            || self.provider_digest != registration.provider_digest
            || self.api_digest != registration.api_digest
            || self.permission_digest != registration.permission_digest
            || self.revision_digest != registration.revision_digest
            || self.metric_digest != registration.metric_digest
            || self.external_write
            || self.connected
            || self.native
            || self.page_size == 0
            || self.page_size > policy.max_page_size
            || self.history_limit == 0
            || self.history_limit > policy.max_history_samples
            || self.max_response_bytes == 0
            || self.max_response_bytes > policy.max_response_bytes
        {
            return Err(WandbEvaluationError::ProposalTampered);
        }
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.request_digest.validate("request_digest")?;
        if self.request_digest != self.calculated_digest() {
            return Err(WandbEvaluationError::ProposalTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ReadProposalIdentity {
            scope: self.scope.clone(),
            page_size: self.page_size,
            history_limit: self.history_limit,
            max_response_bytes: self.max_response_bytes,
            as_of_ms: self.as_of_ms,
            registration_digest: self.registration_digest.clone(),
            provider_manifest_digest: self.provider_manifest_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            revision_digest: self.revision_digest.clone(),
            metric_digest: self.metric_digest.clone(),
            external_write: self.external_write,
            connected: self.connected,
            native: self.native,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct ReadProposalIdentity {
    scope: WandbEvaluationScope,
    page_size: u16,
    history_limit: usize,
    max_response_bytes: usize,
    as_of_ms: u64,
    registration_digest: Digest,
    provider_manifest_digest: Digest,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    revision_digest: Digest,
    metric_digest: Digest,
    external_write: bool,
    connected: bool,
    native: bool,
}

/// The typed W&B service owns bounded one-run reads and proposal verification,
/// never an external effect or kernel receipt authority.
#[derive(Clone, Debug)]
pub struct WandbEvaluationResultService {
    provider: WandbProvider,
    config: WandbEvaluationServiceConfig,
}

impl WandbEvaluationResultService {
    pub fn new(provider: WandbProvider) -> Result<Self, WandbEvaluationError> {
        Self::with_config(provider, WandbEvaluationServiceConfig::fixture())
    }

    pub fn with_config(
        provider: WandbProvider,
        config: WandbEvaluationServiceConfig,
    ) -> Result<Self, WandbEvaluationError> {
        config.validate()?;
        let registration = provider.registration();
        let permission = provider.permission();
        registration.ensure_active(&provider.scope(), &permission)?;
        provider
            .provider_manifest()
            .validate(&registration, &provider.scope(), &permission)?;
        Ok(Self { provider, config })
    }

    #[must_use]
    pub fn provider(&self) -> WandbProvider {
        self.provider.clone()
    }

    #[must_use]
    pub fn registration(&self) -> WandbPluginRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn policy(&self) -> &WandbEvaluationPolicy {
        &self.config.policy
    }

    pub fn describe_capabilities(&self) -> Result<WandbCapabilities, WandbEvaluationError> {
        let manifest = self.provider.describe_capabilities()?;
        let authentication = self.provider.authentication_plan();
        Ok(WandbCapabilities {
            schema_version: String::from(crate::WANDB_EVALUATION_RESULT_SCHEMA_VERSION),
            contract_version: String::from(crate::WANDB_EVALUATION_RESULT_CONTRACT_VERSION),
            plugin_version: PluginVersion::V1,
            service_id: String::from(crate::WANDB_EVALUATION_RESULT_SERVICE_ID),
            provider_id: manifest.provider_id,
            source: manifest.evidence_source,
            native_status: manifest.native_status,
            connected: false,
            native: false,
            external_writes: false,
            metric_writes: false,
            artifact_upload: false,
            artifact_download: false,
            sweep_launch: false,
            raw_history: false,
            raw_dataset: false,
            raw_media: false,
            generic_telemetry: false,
            operations: vec![
                String::from("describe_capabilities"),
                String::from("compile_bounded_read_proposal"),
                String::from("read_one_run"),
                String::from("read_allowlisted_summary_metrics"),
                String::from("read_sampled_history"),
                String::from("read_run_state_and_timestamps"),
                String::from("read_artifact_metadata"),
                String::from("compile_evaluation_result_proposal"),
                String::from("verify_evaluation_result_proposal"),
            ],
            secret_reference_required: authentication.required,
            provider_digest: manifest.provider_digest,
            api_digest: manifest.api_digest,
            permission_digest: manifest.permission_digest,
            scope_digest: manifest.scope_digest,
            revision_digest: manifest.revision_digest,
            metric_digest: manifest.metric_digest,
        })
    }

    pub fn compile_bounded_read_proposal(
        &self,
        scope: WandbEvaluationScope,
        page_size: u16,
        as_of_ms: Option<u64>,
    ) -> Result<WandbReadProposal, WandbEvaluationError> {
        self.compile_bounded_read_proposal_with_limits(
            scope,
            page_size,
            self.config.policy.max_history_samples,
            self.config.policy.max_response_bytes,
            as_of_ms,
        )
    }

    pub fn compile_bounded_read_proposal_with_limits(
        &self,
        scope: WandbEvaluationScope,
        page_size: u16,
        history_limit: usize,
        max_response_bytes: usize,
        as_of_ms: Option<u64>,
    ) -> Result<WandbReadProposal, WandbEvaluationError> {
        let request = WandbEvaluationReadRequest::new(
            scope,
            page_size,
            history_limit,
            max_response_bytes,
            as_of_ms.unwrap_or(self.config.default_as_of_ms),
        )?;
        request.validate(&self.config.policy)?;
        let registration = self.ensure_registration()?;
        if request.scope.digest() != &registration.scope_digest {
            return Err(WandbEvaluationError::ScopeMismatch);
        }
        let manifest = self.provider.provider_manifest();
        manifest.validate(
            &registration,
            &self.provider.scope(),
            &self.provider.permission(),
        )?;
        let proposal = WandbReadProposal::new(&request, &registration, &manifest);
        proposal.validate(&registration, &self.config.policy)?;
        Ok(proposal)
    }

    pub fn read_page(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationPage, WandbEvaluationError> {
        request.validate(&self.config.policy)?;
        let registration = self.ensure_registration()?;
        Self::ensure_request_binding(request, &registration)?;
        let page = self
            .provider
            .read_run(request)
            .map_err(WandbEvaluationError::Provider)?;
        page.validate(&self.config.policy)?;
        Self::ensure_page_binding(&page, &request.scope)?;
        if page.status == EvidenceStatus::Stale {
            return Err(WandbEvaluationError::StaleResult);
        }
        if request.as_of_ms >= page.observed_at_ms
            && request.as_of_ms.saturating_sub(page.observed_at_ms) > self.config.policy.max_age_ms
        {
            return Err(WandbEvaluationError::StaleResult);
        }
        Ok(page)
    }

    pub fn read_run(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationPage, WandbEvaluationError> {
        self.read_page(request)
    }

    pub fn read_one_run(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationPage, WandbEvaluationError> {
        self.read_page(request)
    }

    pub fn read(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationPage, WandbEvaluationError> {
        self.read_page(request)
    }

    pub fn paginate(
        &self,
        request: WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationEvidence, WandbEvaluationError> {
        request.validate(&self.config.policy)?;
        let mut pages = Vec::new();
        let mut current = request;
        let mut seen_cursors = BTreeSet::new();
        for _ in 0..self.config.policy.max_pages {
            let page = self.read_page(&current)?;
            let next_cursor = page.next_cursor.clone();
            pages.push(page);
            let Some(cursor) = next_cursor else {
                break;
            };
            if !seen_cursors.insert(cursor.cursor_digest.clone()) {
                return Err(WandbEvaluationError::CursorLoop);
            }
            current = current.next_page(cursor)?;
        }
        if pages
            .last()
            .and_then(|page| page.next_cursor.as_ref())
            .is_some()
        {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "evaluation_pages",
                maximum: self.config.policy.max_pages as usize,
            });
        }
        let status = if pages
            .iter()
            .any(|page| page.status == EvidenceStatus::Partial)
        {
            EvidenceStatus::Partial
        } else if pages.is_empty() {
            EvidenceStatus::Empty
        } else {
            pages[0].status
        };
        if pages.len() != 1 {
            return Err(WandbEvaluationError::PaginationMismatch);
        }
        let page = pages
            .pop()
            .ok_or(WandbEvaluationError::PaginationMismatch)?;
        let registration = self.ensure_registration()?;
        let manifest = self.provider.provider_manifest();
        let evidence = WandbEvaluationEvidence::from_page(
            &page,
            &registration,
            manifest.provider_digest,
            manifest.evidence_source,
        )?;
        if evidence.status != status {
            return Err(WandbEvaluationError::PaginationMismatch);
        }
        evidence.validate(&registration)?;
        Ok(evidence)
    }

    pub fn propose_evaluation(
        &self,
        request: WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationResultProposal, WandbEvaluationError> {
        let evidence = self.paginate(request)?;
        let registration = self.ensure_registration()?;
        let proposal = WandbEvaluationResultProposal::new(
            evidence_scope(&evidence, &registration, &self.provider.scope())?,
            evidence,
            &registration,
        )?;
        proposal.validate(&registration)?;
        Ok(proposal)
    }

    pub fn propose(
        &self,
        request: WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationResultProposal, WandbEvaluationError> {
        self.propose_evaluation(request)
    }

    pub fn compile_evaluation_result_proposal(
        &self,
        request: WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationResultProposal, WandbEvaluationError> {
        self.propose_evaluation(request)
    }

    pub fn verify_proposal(
        &self,
        proposal: &WandbEvaluationResultProposal,
    ) -> Result<(), WandbEvaluationError> {
        let registration = self.ensure_registration()?;
        let manifest = self.provider.provider_manifest();
        manifest.validate(
            &registration,
            &self.provider.scope(),
            &self.provider.permission(),
        )?;
        if proposal.provider_digest != manifest.provider_digest
            || proposal.api_digest != manifest.api_digest
        {
            return Err(WandbEvaluationError::ProviderManifestDrift);
        }
        proposal.validate(&registration)
    }

    pub fn verify_evaluation_result_proposal(
        &self,
        proposal: &WandbEvaluationResultProposal,
    ) -> Result<(), WandbEvaluationError> {
        self.verify_proposal(proposal)
    }

    pub fn receipt_candidate(
        &self,
        proposal: &WandbEvaluationResultProposal,
    ) -> Result<WandbEvaluationReceiptCandidate, WandbEvaluationError> {
        self.verify_proposal(proposal)?;
        WandbEvaluationReceiptCandidate::from_proposal(proposal, &self.registration())
    }

    pub fn revoke(
        &self,
        reason: impl AsRef<str>,
    ) -> Result<crate::RegistrationRevocation, WandbEvaluationError> {
        self.provider.revoke(reason)
    }

    pub fn restore(&self) -> Result<(), WandbEvaluationError> {
        self.provider.restore()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.registration().active
    }

    fn ensure_registration(&self) -> Result<WandbPluginRegistration, WandbEvaluationError> {
        let registration = self.provider.registration();
        registration.ensure_active(&self.provider.scope(), &self.provider.permission())?;
        self.provider.provider_manifest().validate(
            &registration,
            &self.provider.scope(),
            &self.provider.permission(),
        )?;
        Ok(registration)
    }

    fn ensure_request_binding(
        request: &WandbEvaluationReadRequest,
        registration: &WandbPluginRegistration,
    ) -> Result<(), WandbEvaluationError> {
        if request.scope.digest() != &registration.scope_digest {
            return Err(WandbEvaluationError::ScopeMismatch);
        }
        if request.scope.permission_digest != registration.permission_digest {
            return Err(WandbEvaluationError::PermissionDrift);
        }
        if request.scope.revision_digest != registration.revision_digest {
            return Err(WandbEvaluationError::RevisionDrift);
        }
        if request.scope.metric_digest != registration.metric_digest {
            return Err(WandbEvaluationError::MetricRevisionDrift);
        }
        Ok(())
    }

    fn ensure_page_binding(
        page: &WandbEvaluationPage,
        scope: &WandbEvaluationScope,
    ) -> Result<(), WandbEvaluationError> {
        if page.scope_digest != *scope.digest() {
            return Err(WandbEvaluationError::ScopeMismatch);
        }
        if page.entity != scope.entity {
            return Err(WandbEvaluationError::EntityMismatch);
        }
        if page.project != scope.project || page.project.revision != scope.project.revision {
            return Err(WandbEvaluationError::ProjectRevisionDrift);
        }
        if page.run.entity != scope.entity {
            return Err(WandbEvaluationError::EntityMismatch);
        }
        if page.run.project != scope.project {
            return Err(WandbEvaluationError::ProjectRevisionDrift);
        }
        if page.run.run != scope.run {
            return Err(WandbEvaluationError::RunMismatch);
        }
        if page.api_digest != scope.api_digest {
            return Err(WandbEvaluationError::ApiDrift);
        }
        if page.permission_digest != scope.permission_digest {
            return Err(WandbEvaluationError::PermissionDrift);
        }
        if page.metric_digest != scope.metric_digest {
            return Err(WandbEvaluationError::MetricRevisionDrift);
        }
        if page.config_digest != scope.config.digest {
            return Err(WandbEvaluationError::ConfigRevisionDrift);
        }
        if page.artifact_digest != scope.artifact_digest {
            return Err(WandbEvaluationError::ArtifactRevisionDrift);
        }
        if page.commit_digest != scope.commit.digest {
            return Err(WandbEvaluationError::CommitRevisionDrift);
        }
        if page.revision_digest != scope.revision_digest {
            return Err(WandbEvaluationError::RevisionDrift);
        }
        if page.run.config != scope.config || page.run.commit != scope.commit {
            return Err(WandbEvaluationError::ConfigRevisionDrift);
        }
        if page.run.summary_metrics.iter().any(|metric| {
            !scope.metric_allowlist.iter().any(|binding| {
                binding.name == metric.name && binding.revision == scope.metric().revision
            })
        }) || page.run.sampled_history.iter().any(|sample| {
            !scope
                .metric_allowlist
                .iter()
                .any(|binding| binding.name == sample.name)
        }) {
            return Err(WandbEvaluationError::MetricMismatch);
        }
        for artifact in &page.run.artifacts {
            if !scope.artifact_allowlist.iter().any(|binding| {
                binding.id == artifact.id
                    && binding.revision == artifact.revision
                    && binding.digest == artifact.digest
            }) {
                return Err(WandbEvaluationError::ArtifactMismatch);
            }
        }
        if page.run.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "response_bytes",
                maximum: crate::MAX_RESPONSE_BYTES,
            });
        }
        Ok(())
    }
}

fn evidence_scope(
    evidence: &WandbEvaluationEvidence,
    registration: &WandbPluginRegistration,
    scope: &WandbEvaluationScope,
) -> Result<WandbEvaluationScope, WandbEvaluationError> {
    if evidence.scope_digest != *scope.digest()
        || evidence.registration_digest != registration.registration_digest
    {
        return Err(WandbEvaluationError::ScopeMismatch);
    }
    Ok(scope.clone())
}

impl From<WandbProviderError> for WandbEvaluationError {
    fn from(error: WandbProviderError) -> Self {
        Self::Provider(error)
    }
}
