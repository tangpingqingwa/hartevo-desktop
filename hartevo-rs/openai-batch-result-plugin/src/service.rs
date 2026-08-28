use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, SERVICE_ID,
    error::{OpenAiBatchProviderError, OpenAiBatchResultError, Result},
    model::{
        BatchCursor, BatchGetRequest, BatchListRequest, Digest, EvidenceDisposition,
        MAX_PAGE_LIMIT, MAX_PAGES, MAX_RESPONSE_BYTES, NativeStatus, OpenAiBatchEvidence,
        OpenAiBatchReadTarget, OpenAiBatchRegistration, OpenAiBatchScope, ProviderErrorProjection,
        ProviderProvenance, RegistrationRevocation, Revision,
    },
    provider::{BatchGetResponse, BatchListResponse, OpenAiBatchProvider},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchServicePolicy {
    pub max_page_limit: u32,
    pub max_pages: u32,
    pub max_response_bytes: usize,
}

impl Default for OpenAiBatchServicePolicy {
    fn default() -> Self {
        Self {
            max_page_limit: MAX_PAGE_LIMIT,
            max_pages: MAX_PAGES as u32,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl OpenAiBatchServicePolicy {
    pub fn new(max_page_limit: u32, max_pages: u32, max_response_bytes: usize) -> Result<Self> {
        if !(1..=MAX_PAGE_LIMIT).contains(&max_page_limit)
            || max_pages == 0
            || max_pages > MAX_PAGES as u32
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(OpenAiBatchResultError::InvalidRequest("service policy"));
        }
        Ok(Self {
            max_page_limit,
            max_pages,
            max_response_bytes,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.max_page_limit, self.max_pages, self.max_response_bytes).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchCapabilities {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub source: ProviderProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub prompt_retention: bool,
    pub output_retention: bool,
    pub file_download: bool,
    pub model_execution: bool,
    pub tool_execution: bool,
    pub model_registry: bool,
    pub secret_reference_required: bool,
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchReadProposal {
    pub target: OpenAiBatchReadTarget,
    pub minimum_observed_at: u64,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub proposal_digest: Digest,
}

impl OpenAiBatchReadProposal {
    fn new(
        target: OpenAiBatchReadTarget,
        minimum_observed_at: u64,
        registration: &OpenAiBatchRegistration,
        scope: &OpenAiBatchScope,
        provider: &OpenAiBatchProvider,
    ) -> Self {
        let mut proposal = Self {
            target,
            minimum_observed_at,
            registration_digest: registration.registration_digest.clone(),
            provider_digest: provider.provider_digest(),
            api_digest: scope.identity().api.digest(),
            model_digest: scope.identity().model.digest(),
            permission_digest: scope.identity().permission.digest.clone(),
            scope_digest: scope.scope_digest(),
            revision_digest: scope.revision_digest(),
            proposal_only: true,
            connected: false,
            native: false,
            external_writes: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn validate(
        &self,
        registration: &OpenAiBatchRegistration,
        scope: &OpenAiBatchScope,
        provider: &OpenAiBatchProvider,
    ) -> Result<()> {
        registration.validate_for(scope, &provider.provider_digest())?;
        for (field, digest) in [
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("model_digest", &self.model_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("revision_digest", &self.revision_digest),
        ] {
            digest.validate(field)?;
        }
        if self.registration_digest != registration.registration_digest
            || self.provider_digest != provider.provider_digest()
            || self.api_digest != scope.identity().api.digest()
            || self.model_digest != scope.identity().model.digest()
            || self.permission_digest != scope.identity().permission.digest
            || self.scope_digest != scope.scope_digest()
            || self.revision_digest != scope.revision_digest()
            || !self.proposal_only
            || self.connected
            || self.native
            || self.external_writes
            || self.proposal_digest != self.computed_digest()
        {
            return Err(OpenAiBatchResultError::ProposalTampered);
        }
        Ok(())
    }

    #[must_use]
    fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        Digest::from_serializable(&value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchResultProposal {
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub disposition: EvidenceDisposition,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub adopted: bool,
    pub proposal_digest: Digest,
}

impl OpenAiBatchResultProposal {
    fn new(evidence: &OpenAiBatchEvidence, registration: &OpenAiBatchRegistration) -> Self {
        let mut proposal = Self {
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            api_digest: evidence.api_digest.clone(),
            model_digest: evidence.model_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            revision_digest: evidence.revision_digest.clone(),
            disposition: evidence.disposition,
            proposal_only: true,
            connected: false,
            native: false,
            external_writes: false,
            adopted: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn validate(
        &self,
        evidence: &OpenAiBatchEvidence,
        registration: &OpenAiBatchRegistration,
    ) -> Result<()> {
        evidence.validate()?;
        registration.validate()?;
        for (field, digest) in [
            ("evidence_digest", &self.evidence_digest),
            ("registration_digest", &self.registration_digest),
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("model_digest", &self.model_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("revision_digest", &self.revision_digest),
        ] {
            digest.validate(field)?;
        }
        if self.evidence_digest != evidence.evidence_digest
            || self.registration_digest != registration.registration_digest
            || self.provider_digest != evidence.provider_digest
            || self.api_digest != evidence.api_digest
            || self.model_digest != evidence.model_digest
            || self.permission_digest != evidence.permission_digest
            || self.scope_digest != evidence.scope_digest
            || self.revision_digest != evidence.revision_digest
            || !self.proposal_only
            || self.connected
            || self.native
            || self.external_writes
            || self.adopted
            || self.proposal_digest != self.computed_digest()
        {
            return Err(OpenAiBatchResultError::ProposalTampered);
        }
        Ok(())
    }

    #[must_use]
    fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        Digest::from_serializable(&value)
    }
}

/// Typed service that owns registration, bounded reads, pagination, proposal
/// verification, and reversible revocation.  It has no mutation authority.
#[derive(Clone, Debug)]
pub struct OpenAiBatchResultService {
    scope: OpenAiBatchScope,
    provider: OpenAiBatchProvider,
    registration: OpenAiBatchRegistration,
    policy: OpenAiBatchServicePolicy,
    replay_guard: BTreeMap<Digest, Digest>,
}

impl OpenAiBatchResultService {
    pub fn new(scope: OpenAiBatchScope, provider: OpenAiBatchProvider) -> Result<Self> {
        Self::with_policy(scope, provider, OpenAiBatchServicePolicy::default())
    }

    pub fn with_policy(
        scope: OpenAiBatchScope,
        provider: OpenAiBatchProvider,
        policy: OpenAiBatchServicePolicy,
    ) -> Result<Self> {
        scope.validate()?;
        provider.definition().validate()?;
        policy.validate()?;
        let registration = OpenAiBatchRegistration::new(
            &scope,
            provider.provider_digest(),
            provider.definition().version().to_owned(),
            crate::contract_digest(),
        )?;
        registration.validate_for(&scope, &provider.provider_digest())?;
        Ok(Self {
            scope,
            provider,
            registration,
            policy,
            replay_guard: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &OpenAiBatchScope {
        &self.scope
    }

    #[must_use]
    pub fn provider(&self) -> &OpenAiBatchProvider {
        &self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &OpenAiBatchRegistration {
        &self.registration
    }

    #[must_use]
    pub fn policy(&self) -> &OpenAiBatchServicePolicy {
        &self.policy
    }

    pub fn describe_capabilities(&self) -> Result<OpenAiBatchCapabilities> {
        self.ensure_active()?;
        Ok(OpenAiBatchCapabilities {
            schema_version: String::from(crate::SCHEMA_VERSION),
            contract_version: String::from(CONTRACT_VERSION),
            service_id: String::from(SERVICE_ID),
            provider_id: String::from(crate::PROVIDER_ID),
            source: self.provider.provenance(),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            external_writes: false,
            kernel_authority: false,
            prompt_retention: false,
            output_retention: false,
            file_download: false,
            model_execution: false,
            tool_execution: false,
            model_registry: false,
            secret_reference_required: true,
            operations: vec![
                String::from("describe_capabilities"),
                String::from("compile_bounded_batch_list_read"),
                String::from("compile_bounded_batch_read"),
                String::from("read_batches"),
                String::from("read_batch"),
                String::from("paginate_batches"),
                String::from("compile_result_proposal"),
                String::from("verify_result_proposal"),
                String::from("revoke_registration"),
                String::from("restore_registration"),
            ],
        })
    }

    pub fn compile_bounded_batch_list_read(
        &self,
        limit: u32,
        cursor: Option<&BatchCursor>,
        minimum_observed_at: u64,
    ) -> Result<OpenAiBatchReadProposal> {
        self.ensure_active()?;
        if !(1..=self.policy.max_page_limit).contains(&limit) {
            return Err(OpenAiBatchResultError::InvalidRequest("limit"));
        }
        if let Some(cursor) = cursor
            && cursor.scope_digest() != &self.scope.scope_digest()
        {
            return Err(OpenAiBatchResultError::CursorMismatch);
        }
        let target = OpenAiBatchReadTarget {
            batch_id: None,
            limit: Some(limit),
            cursor_digest: cursor.map(BatchCursor::digest),
        };
        let proposal = OpenAiBatchReadProposal::new(
            target,
            minimum_observed_at,
            &self.registration,
            &self.scope,
            &self.provider,
        );
        proposal.validate(&self.registration, &self.scope, &self.provider)?;
        Ok(proposal)
    }

    pub fn compile_bounded_batch_read(
        &self,
        batch_id: crate::BatchId,
        minimum_observed_at: u64,
    ) -> Result<OpenAiBatchReadProposal> {
        self.ensure_active()?;
        if let Some(expected) = &self.scope.identity().batch_id
            && expected != &batch_id
        {
            return Err(OpenAiBatchResultError::BatchMismatch);
        }
        let target = OpenAiBatchReadTarget {
            batch_id: Some(batch_id),
            limit: None,
            cursor_digest: None,
        };
        let proposal = OpenAiBatchReadProposal::new(
            target,
            minimum_observed_at,
            &self.registration,
            &self.scope,
            &self.provider,
        );
        proposal.validate(&self.registration, &self.scope, &self.provider)?;
        Ok(proposal)
    }

    pub fn read_batches(
        &mut self,
        limit: u32,
        cursor: Option<BatchCursor>,
        minimum_observed_at: u64,
    ) -> Result<OpenAiBatchEvidence> {
        let proposal =
            self.compile_bounded_batch_list_read(limit, cursor.as_ref(), minimum_observed_at)?;
        let request = BatchListRequest::new(limit, cursor, minimum_observed_at)?;
        match self.provider.list_batches(&self.scope, &request) {
            Ok(response) => {
                self.validate_list_response(&proposal, &request, &response)?;
                self.remember_response(&proposal, &response.response_digest)?;
                let disposition = if response.batches.is_empty() {
                    EvidenceDisposition::Empty
                } else {
                    EvidenceDisposition::Present
                };
                OpenAiBatchEvidence::new(
                    proposal.target,
                    response.batches,
                    response.next_cursor.as_ref().map(BatchCursor::digest),
                    Some(response.response_digest),
                    1,
                    disposition,
                    None,
                    self.provider.provenance(),
                    response.observed_at,
                    response.snapshot_revision,
                    self.registration.registration_digest.clone(),
                    self.provider.provider_digest(),
                    self.scope.identity().api.digest(),
                    self.scope.identity().model.digest(),
                    self.scope.identity().permission.digest.clone(),
                    self.scope.scope_digest(),
                    self.scope.revision_digest(),
                )
            }
            Err(OpenAiBatchResultError::Provider(error)) if is_evidence_provider_error(&error) => {
                self.provider_failure_evidence(proposal.target, minimum_observed_at, error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn read_batch(
        &mut self,
        batch_id: crate::BatchId,
        minimum_observed_at: u64,
    ) -> Result<OpenAiBatchEvidence> {
        let proposal = self.compile_bounded_batch_read(batch_id.clone(), minimum_observed_at)?;
        let request = BatchGetRequest::new(batch_id, minimum_observed_at)?;
        match self.provider.get_batch(&self.scope, &request) {
            Ok(response) => {
                self.validate_get_response(&proposal, &request, &response)?;
                self.remember_response(&proposal, &response.response_digest)?;
                OpenAiBatchEvidence::new(
                    proposal.target,
                    vec![response.batch],
                    None,
                    Some(response.response_digest),
                    1,
                    EvidenceDisposition::Present,
                    None,
                    self.provider.provenance(),
                    response.observed_at,
                    response.snapshot_revision,
                    self.registration.registration_digest.clone(),
                    self.provider.provider_digest(),
                    self.scope.identity().api.digest(),
                    self.scope.identity().model.digest(),
                    self.scope.identity().permission.digest.clone(),
                    self.scope.scope_digest(),
                    self.scope.revision_digest(),
                )
            }
            Err(OpenAiBatchResultError::Provider(error)) if is_evidence_provider_error(&error) => {
                self.provider_failure_evidence(proposal.target, minimum_observed_at, error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn paginate_batches(
        &mut self,
        limit: u32,
        minimum_observed_at: u64,
    ) -> Result<OpenAiBatchEvidence> {
        if limit > self.policy.max_page_limit {
            return Err(OpenAiBatchResultError::InvalidRequest("limit"));
        }
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut batches = Vec::new();
        let mut response_digests = Vec::new();
        let mut page_count: u32 = 0;
        let (last_target, final_disposition) = loop {
            if page_count >= self.policy.max_pages {
                return Err(OpenAiBatchResultError::PageLimitExceeded);
            }
            let evidence = self.read_batches(limit, cursor.clone(), minimum_observed_at)?;
            page_count = page_count.saturating_add(1);
            if let Some(error) = &evidence.provider_error {
                let provider_error = error.clone();
                return OpenAiBatchEvidence::new(
                    evidence.target.clone(),
                    batches,
                    None,
                    if response_digests.is_empty() {
                        evidence.response_digest.clone()
                    } else {
                        Some(Digest::from_serializable(&response_digests))
                    },
                    page_count,
                    evidence.disposition,
                    Some(provider_error),
                    evidence.provenance,
                    evidence.observed_at,
                    evidence.snapshot_revision,
                    evidence.registration_digest,
                    evidence.provider_digest,
                    evidence.api_digest,
                    evidence.model_digest,
                    evidence.permission_digest,
                    evidence.scope_digest,
                    evidence.revision_digest,
                );
            }
            if let Some(response_digest) = evidence.response_digest.clone() {
                response_digests.push(response_digest);
            }
            batches.extend(evidence.batches);
            let disposition = if batches.is_empty() {
                EvidenceDisposition::Empty
            } else {
                EvidenceDisposition::Present
            };
            let Some(next_digest) = evidence.next_cursor_digest else {
                break (evidence.target, disposition);
            };
            let Some(last_batch) = batches.last() else {
                return Err(OpenAiBatchResultError::InvalidResponse(
                    "cursor without batch",
                ));
            };
            let next_cursor =
                BatchCursor::new(
                    last_batch.batch_id.as_str(),
                    self.scope.scope_digest(),
                    evidence.response_digest.clone().ok_or(
                        OpenAiBatchResultError::InvalidResponse("cursor response digest"),
                    )?,
                )?;
            if next_cursor.digest() != next_digest || !seen.insert(next_cursor.digest()) {
                return Err(OpenAiBatchResultError::CursorLoop);
            }
            cursor = Some(next_cursor);
        };
        let response_digest = if response_digests.len() == 1 {
            response_digests.into_iter().next()
        } else {
            Some(Digest::from_serializable(&response_digests))
        };
        OpenAiBatchEvidence::new(
            last_target,
            batches,
            None,
            response_digest,
            page_count,
            final_disposition,
            None,
            self.provider.provenance(),
            minimum_observed_at,
            self.scope.identity().scope_revision,
            self.registration.registration_digest.clone(),
            self.provider.provider_digest(),
            self.scope.identity().api.digest(),
            self.scope.identity().model.digest(),
            self.scope.identity().permission.digest.clone(),
            self.scope.scope_digest(),
            self.scope.revision_digest(),
        )
    }

    pub fn compile_result_proposal(
        &self,
        evidence: &OpenAiBatchEvidence,
    ) -> Result<OpenAiBatchResultProposal> {
        self.ensure_active()?;
        self.verify_evidence(evidence)?;
        Ok(OpenAiBatchResultProposal::new(evidence, &self.registration))
    }

    pub fn verify_result_proposal(
        &self,
        proposal: &OpenAiBatchResultProposal,
        evidence: &OpenAiBatchEvidence,
    ) -> Result<()> {
        self.ensure_active()?;
        self.verify_evidence(evidence)?;
        proposal.validate(evidence, &self.registration)
    }

    pub fn verify_evidence(&self, evidence: &OpenAiBatchEvidence) -> Result<()> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.api_digest != self.scope.identity().api.digest()
            || evidence.model_digest != self.scope.identity().model.digest()
            || evidence.permission_digest != self.scope.identity().permission.digest
            || evidence.scope_digest != self.scope.scope_digest()
            || evidence.revision_digest != self.scope.revision_digest()
            || evidence.provenance != self.provider.provenance()
            || evidence.connected
            || evidence.native
        {
            return Err(OpenAiBatchResultError::ScopeMismatch(
                "evidence is not bound to the active registration",
            ));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation> {
        self.registration.revoke()
    }

    pub fn restore(&mut self) -> Result<()> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.scope.revoke_secret()
    }

    pub fn restore_secret(&mut self) -> Result<()> {
        self.scope.restore_secret()
    }

    fn ensure_active(&self) -> Result<()> {
        self.registration
            .validate_for(&self.scope, &self.provider.provider_digest())?;
        if self.registration.status != crate::RegistrationStatus::Active {
            return Err(OpenAiBatchResultError::RegistrationRevoked);
        }
        self.scope.validate()
    }

    fn validate_list_response(
        &self,
        proposal: &OpenAiBatchReadProposal,
        request: &BatchListRequest,
        response: &BatchListResponse,
    ) -> Result<()> {
        self.validate_snapshot(
            response.observed_at,
            response.snapshot_revision,
            request.minimum_observed_at,
        )?;
        if response.batches.len() > self.policy.max_page_limit as usize {
            return Err(OpenAiBatchResultError::InvalidResponse("page item bound"));
        }
        if response.response_bytes > self.policy.max_response_bytes {
            return Err(OpenAiBatchResultError::ResponseTooLarge {
                actual: response.response_bytes,
                maximum: self.policy.max_response_bytes,
            });
        }
        if response.has_more != response.next_cursor.is_some() {
            return Err(OpenAiBatchResultError::InvalidResponse("cursor/has_more"));
        }
        for batch in &response.batches {
            batch.validate_for_scope(&self.scope)?;
        }
        proposal.validate(&self.registration, &self.scope, &self.provider)
    }

    fn validate_get_response(
        &self,
        proposal: &OpenAiBatchReadProposal,
        request: &BatchGetRequest,
        response: &BatchGetResponse,
    ) -> Result<()> {
        self.validate_snapshot(
            response.observed_at,
            response.snapshot_revision,
            request.minimum_observed_at,
        )?;
        if response.batch.batch_id != request.batch_id {
            return Err(OpenAiBatchResultError::BatchMismatch);
        }
        if response.response_bytes > self.policy.max_response_bytes {
            return Err(OpenAiBatchResultError::ResponseTooLarge {
                actual: response.response_bytes,
                maximum: self.policy.max_response_bytes,
            });
        }
        response.batch.validate_for_scope(&self.scope)?;
        proposal.validate(&self.registration, &self.scope, &self.provider)
    }

    fn validate_snapshot(
        &self,
        observed_at: u64,
        snapshot_revision: Revision,
        minimum_observed_at: u64,
    ) -> Result<()> {
        if observed_at < minimum_observed_at {
            return Err(OpenAiBatchResultError::StaleResult);
        }
        if snapshot_revision != self.scope.identity().scope_revision {
            return Err(OpenAiBatchResultError::RevisionDrift);
        }
        Ok(())
    }

    fn remember_response(
        &mut self,
        proposal: &OpenAiBatchReadProposal,
        digest: &Digest,
    ) -> Result<()> {
        if let Some(existing) = self.replay_guard.get(&proposal.proposal_digest)
            && existing != digest
        {
            return Err(OpenAiBatchResultError::ReplayDetected);
        }
        self.replay_guard
            .insert(proposal.proposal_digest.clone(), digest.clone());
        Ok(())
    }

    fn provider_failure_evidence(
        &self,
        target: OpenAiBatchReadTarget,
        observed_at: u64,
        error: OpenAiBatchProviderError,
    ) -> Result<OpenAiBatchEvidence> {
        let disposition = if matches!(error, OpenAiBatchProviderError::BlockedEnv) {
            EvidenceDisposition::BlockedEnv
        } else if error.is_access_loss() {
            EvidenceDisposition::AccessLost
        } else {
            EvidenceDisposition::ProviderUnknown
        };
        OpenAiBatchEvidence::new(
            target,
            Vec::new(),
            None,
            None,
            1,
            disposition,
            Some(ProviderErrorProjection::from_error(&error, None)),
            self.provider.provenance(),
            observed_at,
            self.scope.identity().scope_revision,
            self.registration.registration_digest.clone(),
            self.provider.provider_digest(),
            self.scope.identity().api.digest(),
            self.scope.identity().model.digest(),
            self.scope.identity().permission.digest.clone(),
            self.scope.scope_digest(),
            self.scope.revision_digest(),
        )
    }
}

fn is_evidence_provider_error(error: &OpenAiBatchProviderError) -> bool {
    matches!(
        error,
        OpenAiBatchProviderError::BlockedEnv
            | OpenAiBatchProviderError::Unauthorized
            | OpenAiBatchProviderError::Forbidden
            | OpenAiBatchProviderError::NotFound
            | OpenAiBatchProviderError::AccessLoss
            | OpenAiBatchProviderError::Timeout
            | OpenAiBatchProviderError::TransportUnavailable
            | OpenAiBatchProviderError::RateLimited { .. }
            | OpenAiBatchProviderError::ServerError { .. }
    )
}
