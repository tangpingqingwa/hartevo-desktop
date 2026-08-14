use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::error::{CircleCiPipelineResultError, CircleCiProviderError};
use crate::model::{
    CircleCiApprovalProjection, CircleCiApprovalState, CircleCiArtifactMetadataProjection,
    CircleCiCredentialKind, CircleCiJobProjection, CircleCiPageToken, CircleCiPipelineProjection,
    CircleCiPipelineReadRequest, CircleCiPipelineResultEvidence, CircleCiProvenance,
    CircleCiRegistration, CircleCiScope, CircleCiScopeDescription, CircleCiStatus,
    CircleCiVcsRevision, CircleCiWorkflowProjection, Digest, MAX_APPROVALS, MAX_ARTIFACT_METADATA,
    MAX_JOBS, MAX_METADATA_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_TIMESTAMP_BYTES, MAX_WORKFLOWS,
    SecretReference, canonical_digest, digest_parts,
};
use crate::transport::{
    CircleCiFixtureTransport, CircleCiPage, CircleCiTransport, CircleCiTransportOperation,
    RawApproval, RawArtifactMetadata, RawJob, RawPipeline, RawWorkflow, SecretMaterial,
};

/// Host-owned credential resolver. Native token/OIDC resolution is deliberately
/// absent from Layer 1; the default deterministic resolver is only for tests.
pub trait CircleCiCredentialResolver: Clone + fmt::Debug {
    fn resolve(&self, reference: &SecretReference)
    -> Result<SecretMaterial, CircleCiProviderError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct StaticCircleCiCredentialResolver {
    kind: CircleCiCredentialKind,
    material: String,
}

impl StaticCircleCiCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            kind: CircleCiCredentialKind::Token,
            material: value.into(),
        }
    }

    pub fn token(value: impl Into<String>) -> Self {
        Self::new(value)
    }

    pub fn oidc(value: impl Into<String>) -> Self {
        Self {
            kind: CircleCiCredentialKind::Oidc,
            material: value.into(),
        }
    }
}

impl fmt::Debug for StaticCircleCiCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticCircleCiCredentialResolver")
            .field("kind", &self.kind)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl CircleCiCredentialResolver for StaticCircleCiCredentialResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, CircleCiProviderError> {
        if reference.is_revoked() || reference.credential_kind() != self.kind {
            return Err(CircleCiProviderError::Forbidden);
        }
        Ok(SecretMaterial::new(self.kind, self.material.clone()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvCredentialResolver;

impl CircleCiCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, CircleCiProviderError> {
        Err(CircleCiProviderError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircleCiProviderState {
    Active,
    Revoked,
    Reversed,
    BlockedEnv,
    AccessLost,
}

/// Typed CircleCI provider boundary. It only reads bounded fixture-like
/// payloads and projects redacted evidence; it has no mutation operations.
#[derive(Clone, Debug)]
pub struct CircleCiProvider<T, R>
where
    T: CircleCiTransport,
    R: CircleCiCredentialResolver,
{
    registration: CircleCiRegistration,
    transport: T,
    resolver: R,
    state: CircleCiProviderState,
}

impl<T, R> CircleCiProvider<T, R>
where
    T: CircleCiTransport,
    R: CircleCiCredentialResolver,
{
    pub fn new(
        registration: CircleCiRegistration,
        transport: T,
        resolver: R,
    ) -> Result<Self, CircleCiPipelineResultError> {
        registration.validate()?;
        if transport.provenance() == CircleCiProvenance::BlockedEnv {
            return Err(CircleCiPipelineResultError::Provider(
                CircleCiProviderError::BlockedEnv,
            ));
        }
        Ok(Self {
            registration,
            transport,
            resolver,
            state: CircleCiProviderState::Active,
        })
    }

    pub fn registration(&self) -> &CircleCiRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut CircleCiRegistration {
        &mut self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    pub const fn state(&self) -> CircleCiProviderState {
        self.state
    }

    pub fn describe_scope(&self) -> Result<CircleCiScopeDescription, CircleCiPipelineResultError> {
        self.registration.validate()?;
        let provenance = self.transport.provenance();
        Ok(CircleCiScopeDescription {
            contract_version: crate::CIRCLECI_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::CIRCLECI_PROVIDER_ID.to_owned(),
            provider_version: crate::CIRCLECI_PROVIDER_VERSION,
            scope_digest: self.registration.scope.digest(),
            host: self.registration.scope.host.clone(),
            organization: self.registration.scope.organization.clone(),
            project_slug: self.registration.scope.project_slug.clone(),
            permission_snapshot: self.registration.permission_snapshot.clone(),
            provenance,
            native_transport: false,
            native_connected: false,
        })
    }

    pub fn revoke(&mut self) -> crate::model::RegistrationRevocation {
        self.state = CircleCiProviderState::Revoked;
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> crate::model::RegistrationReversal {
        self.state = CircleCiProviderState::Reversed;
        self.registration.reverse()
    }

    pub fn operations(&self) -> Vec<CircleCiTransportOperation> {
        self.transport.operations()
    }

    pub fn read_pipeline_result(
        &mut self,
        request: &CircleCiPipelineReadRequest,
    ) -> Result<CircleCiPipelineResultEvidence, CircleCiPipelineResultError> {
        if self.state != CircleCiProviderState::Active {
            return Err(match self.state {
                CircleCiProviderState::Revoked => CircleCiPipelineResultError::RegistrationRevoked,
                CircleCiProviderState::Reversed => {
                    CircleCiPipelineResultError::RegistrationReversed
                }
                CircleCiProviderState::BlockedEnv => {
                    CircleCiPipelineResultError::Provider(CircleCiProviderError::BlockedEnv)
                }
                CircleCiProviderState::AccessLost => CircleCiPipelineResultError::AccessLost,
                CircleCiProviderState::Active => CircleCiPipelineResultError::StaleEvidence,
            });
        }
        self.registration.validate()?;
        if request.scope != self.registration.scope {
            return Err(CircleCiPipelineResultError::ScopeMismatch);
        }
        let secret = match self.resolver.resolve(&self.registration.secret_reference) {
            Ok(secret) => secret,
            Err(CircleCiProviderError::BlockedEnv) => {
                self.state = CircleCiProviderState::BlockedEnv;
                return Err(CircleCiPipelineResultError::Provider(
                    CircleCiProviderError::BlockedEnv,
                ));
            }
            Err(error) => return Err(CircleCiPipelineResultError::Provider(error)),
        };

        let pipeline_response =
            self.handle_transport(self.transport.fetch_pipeline(request, &secret))?;
        Self::validate_receipt(
            &pipeline_response.receipt,
            CircleCiProvenance::from_transport(&self.transport),
        )?;
        if pipeline_response.receipt.response_digest
            != canonical_digest(&pipeline_response.pipeline)
        {
            return Err(CircleCiPipelineResultError::TamperedEvidence);
        }
        let pipeline = self.project_pipeline(&pipeline_response.pipeline)?;

        let workflows = self.read_workflows(request, &secret)?;
        let jobs = self.read_jobs(request, &secret)?;
        let approvals = self.read_approvals(request, &secret)?;
        let artifact_metadata = self.read_artifacts(request, &secret)?;

        if workflows.is_empty() {
            return Err(CircleCiPipelineResultError::MissingEvidence {
                resource: "workflow",
            });
        }
        if jobs.is_empty() {
            return Err(CircleCiPipelineResultError::MissingEvidence { resource: "job" });
        }
        ensure_no_replays(&workflows, |value| {
            format!("{}:{}", value.workflow_id, value.revision)
        })?;
        ensure_no_replays(&jobs, |value| {
            format!(
                "{}:{}:{}",
                value.job_number, value.attempt_id, value.revision
            )
        })?;
        ensure_no_replays(&approvals, |value| {
            format!(
                "{}:{}:{}:{:?}:{}",
                value.workflow_id, value.job_number, value.attempt_id, value.state, value.revision
            )
        })?;
        ensure_no_replays(&artifact_metadata, |value| {
            format!(
                "{}:{}:{}:{}:{}",
                value.workflow_id,
                value.job_number,
                value.attempt_id,
                value.name_digest,
                value.revision
            )
        })?;

        let provenance = self.transport.provenance();
        let mut evidence = CircleCiPipelineResultEvidence {
            contract_version: crate::CIRCLECI_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::CIRCLECI_PROVIDER_ID.to_owned(),
            provider_version: crate::CIRCLECI_PROVIDER_VERSION,
            scope_digest: request.scope.digest(),
            pipeline,
            workflows,
            jobs,
            approvals,
            artifact_metadata,
            permission_digest: self.registration.permission_snapshot.digest().to_owned(),
            evidence_revision: request.scope.revisions.pipeline,
            provenance,
            native_transport: false,
            native_connected: false,
            raw_logs_retained: false,
            artifact_bytes_downloaded: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence.validate(&request.scope)?;
        Ok(evidence)
    }

    fn handle_transport<V>(
        &mut self,
        result: Result<V, CircleCiProviderError>,
    ) -> Result<V, CircleCiPipelineResultError> {
        result.map_err(|error| {
            if error == CircleCiProviderError::AccessLost {
                self.state = CircleCiProviderState::AccessLost;
                CircleCiPipelineResultError::AccessLost
            } else {
                CircleCiPipelineResultError::Provider(error)
            }
        })
    }

    fn validate_receipt(
        receipt: &crate::transport::CircleCiTransportReceipt,
        expected_provenance: CircleCiProvenance,
    ) -> Result<(), CircleCiPipelineResultError> {
        if receipt.provenance != expected_provenance
            || receipt.native_transport
            || receipt.native_connected
        {
            return Err(CircleCiPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn read_workflows(
        &mut self,
        request: &CircleCiPipelineReadRequest,
        secret: &SecretMaterial,
    ) -> Result<Vec<CircleCiWorkflowProjection>, CircleCiPipelineResultError> {
        let raw = Self::read_pages(request.max_pages, MAX_WORKFLOWS, |token| {
            let page = self.handle_transport(self.transport.fetch_workflows(
                &request.scope,
                token,
                secret,
            ))?;
            Self::validate_receipt(&page.receipt, self.transport.provenance())?;
            Ok(page)
        })?;
        raw.iter()
            .map(|value| self.project_workflow(value))
            .collect()
    }

    fn read_jobs(
        &mut self,
        request: &CircleCiPipelineReadRequest,
        secret: &SecretMaterial,
    ) -> Result<Vec<CircleCiJobProjection>, CircleCiPipelineResultError> {
        let raw = Self::read_pages(request.max_pages, MAX_JOBS, |token| {
            let page =
                self.handle_transport(self.transport.fetch_jobs(&request.scope, token, secret))?;
            Self::validate_receipt(&page.receipt, self.transport.provenance())?;
            Ok(page)
        })?;
        raw.iter().map(|value| self.project_job(value)).collect()
    }

    fn read_approvals(
        &mut self,
        request: &CircleCiPipelineReadRequest,
        secret: &SecretMaterial,
    ) -> Result<Vec<CircleCiApprovalProjection>, CircleCiPipelineResultError> {
        let raw = Self::read_pages(request.max_pages, MAX_APPROVALS, |token| {
            let page = self.handle_transport(self.transport.fetch_approvals(
                &request.scope,
                token,
                secret,
            ))?;
            Self::validate_receipt(&page.receipt, self.transport.provenance())?;
            Ok(page)
        })?;
        raw.iter()
            .map(|value| self.project_approval(value))
            .collect()
    }

    fn read_artifacts(
        &mut self,
        request: &CircleCiPipelineReadRequest,
        secret: &SecretMaterial,
    ) -> Result<Vec<CircleCiArtifactMetadataProjection>, CircleCiPipelineResultError> {
        let raw = Self::read_pages(request.max_pages, MAX_ARTIFACT_METADATA, |token| {
            let page = self.handle_transport(self.transport.fetch_artifact_metadata(
                &request.scope,
                token,
                secret,
            ))?;
            Self::validate_receipt(&page.receipt, self.transport.provenance())?;
            Ok(page)
        })?;
        raw.iter()
            .map(|value| self.project_artifact(value))
            .collect()
    }

    fn read_pages<V, F>(
        max_pages: usize,
        max_items: usize,
        mut fetch: F,
    ) -> Result<Vec<V>, CircleCiPipelineResultError>
    where
        V: Serialize,
        F: FnMut(
            Option<&CircleCiPageToken>,
        ) -> Result<CircleCiPage<V>, CircleCiPipelineResultError>,
    {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(CircleCiPipelineResultError::PaginationExceeded);
        }
        let mut values = Vec::new();
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        for _ in 0..max_pages {
            let page = fetch(page_token.as_ref())?;
            if page.receipt.response_digest != canonical_digest(&page.items) {
                return Err(CircleCiPipelineResultError::TamperedEvidence);
            }
            if page.items.len() > MAX_PAGE_SIZE {
                return Err(CircleCiPipelineResultError::TruncatedEvidence);
            }
            values.extend(page.items);
            if values.len() > max_items {
                return Err(CircleCiPipelineResultError::BoundExceeded {
                    resource: "page result",
                });
            }
            let Some(next) = page.next_page_token else {
                return Ok(values);
            };
            if !seen_tokens.insert(next.digest().to_owned()) {
                return Err(CircleCiPipelineResultError::PageTokenRepeated);
            }
            page_token = Some(next);
        }
        Err(CircleCiPipelineResultError::PaginationExceeded)
    }

    fn project_pipeline(
        &self,
        raw: &RawPipeline,
    ) -> Result<CircleCiPipelineProjection, CircleCiPipelineResultError> {
        Self::validate_payload(raw, &raw.payload_digest)?;
        let scope = &self.registration.scope;
        if raw.host != scope.host.as_str() {
            return Err(CircleCiPipelineResultError::HostDrift);
        }
        if raw.organization != scope.organization {
            return Err(CircleCiPipelineResultError::OrganizationDrift);
        }
        if raw.project_slug != scope.project_slug {
            return Err(CircleCiPipelineResultError::ProjectDrift);
        }
        if raw.pipeline_id != scope.pipeline_id {
            return Err(CircleCiPipelineResultError::PipelineDrift);
        }
        if raw.attempt_id != scope.attempt_id {
            return Err(CircleCiPipelineResultError::AttemptDrift);
        }
        if raw.commit_sha != scope.commit_sha {
            return Err(CircleCiPipelineResultError::CommitDrift);
        }
        if raw.revision != scope.revisions.pipeline {
            return Err(CircleCiPipelineResultError::RevisionDrift {
                resource: "pipeline",
            });
        }
        if raw.permission_digest != self.registration.permission_snapshot.digest() {
            return Err(CircleCiPipelineResultError::PermissionDrift);
        }
        validate_timestamp(&raw.created_at, "pipeline created")?;
        validate_timestamp(&raw.updated_at, "pipeline updated")?;
        let vcs =
            CircleCiVcsRevision::new(raw.commit_sha.clone(), raw.branch.clone(), raw.tag.clone())?;
        let evidence_digest = digest_parts([
            &raw.pipeline_id,
            &raw.attempt_id,
            &raw.commit_sha,
            &raw.revision.to_string(),
            &format!("{:?}", CircleCiStatus::project(&raw.status)),
        ]);
        Ok(CircleCiPipelineProjection {
            pipeline_id: raw.pipeline_id.clone(),
            number: raw.number,
            attempt_id: raw.attempt_id.clone(),
            status: CircleCiStatus::project(&raw.status),
            vcs,
            created_at: raw.created_at.clone(),
            updated_at: raw.updated_at.clone(),
            revision: raw.revision,
            evidence_digest,
        })
    }

    fn project_workflow(
        &self,
        raw: &RawWorkflow,
    ) -> Result<CircleCiWorkflowProjection, CircleCiPipelineResultError> {
        Self::validate_payload(raw, &raw.payload_digest)?;
        let scope = &self.registration.scope;
        validate_shared_identity(
            &raw.host,
            &raw.organization,
            &raw.project_slug,
            &raw.pipeline_id,
            scope,
        )?;
        if raw.workflow_id != scope.workflow_id {
            return Err(CircleCiPipelineResultError::WorkflowDrift);
        }
        if raw.commit_sha != scope.commit_sha {
            return Err(CircleCiPipelineResultError::CommitDrift);
        }
        if raw.revision != scope.revisions.workflow {
            return Err(CircleCiPipelineResultError::RevisionDrift {
                resource: "workflow",
            });
        }
        validate_timestamp(&raw.created_at, "workflow created")?;
        if let Some(stopped_at) = &raw.stopped_at {
            validate_timestamp(stopped_at, "workflow stopped")?;
        }
        let status = CircleCiStatus::project(&raw.status);
        let approval = CircleCiApprovalState::project(&raw.approval);
        Ok(CircleCiWorkflowProjection {
            workflow_id: raw.workflow_id.clone(),
            status,
            approval,
            name_digest: sha256_text(&raw.name, "workflow name")?,
            created_at: raw.created_at.clone(),
            stopped_at: raw.stopped_at.clone(),
            revision: raw.revision,
            evidence_digest: digest_parts([
                &raw.workflow_id,
                &format!("{status:?}"),
                &format!("{approval:?}"),
                &raw.revision.to_string(),
            ]),
        })
    }

    fn project_job(
        &self,
        raw: &RawJob,
    ) -> Result<CircleCiJobProjection, CircleCiPipelineResultError> {
        Self::validate_payload(raw, &raw.payload_digest)?;
        let scope = &self.registration.scope;
        validate_shared_identity(
            &raw.host,
            &raw.organization,
            &raw.project_slug,
            &raw.pipeline_id,
            scope,
        )?;
        if raw.workflow_id != scope.workflow_id {
            return Err(CircleCiPipelineResultError::WorkflowDrift);
        }
        if raw.job_number != scope.job_number {
            return Err(CircleCiPipelineResultError::JobDrift);
        }
        if raw.attempt_id != scope.attempt_id {
            return Err(CircleCiPipelineResultError::AttemptDrift);
        }
        if raw.commit_sha != scope.commit_sha {
            return Err(CircleCiPipelineResultError::CommitDrift);
        }
        if raw.revision != scope.revisions.job {
            return Err(CircleCiPipelineResultError::RevisionDrift { resource: "job" });
        }
        if let Some(started_at) = &raw.started_at {
            validate_timestamp(started_at, "job started")?;
        }
        if let Some(stopped_at) = &raw.stopped_at {
            validate_timestamp(stopped_at, "job stopped")?;
        }
        let status = CircleCiStatus::project(&raw.status);
        let approval = CircleCiApprovalState::project(&raw.approval);
        Ok(CircleCiJobProjection {
            workflow_id: raw.workflow_id.clone(),
            job_number: raw.job_number,
            attempt_id: raw.attempt_id.clone(),
            status,
            approval,
            name_digest: sha256_text(&raw.name, "job name")?,
            commit_sha: raw.commit_sha.clone(),
            started_at: raw.started_at.clone(),
            stopped_at: raw.stopped_at.clone(),
            revision: raw.revision,
            evidence_digest: digest_parts([
                &raw.job_number.to_string(),
                &raw.attempt_id,
                &raw.commit_sha,
                &format!("{status:?}"),
                &raw.revision.to_string(),
            ]),
        })
    }

    fn project_approval(
        &self,
        raw: &RawApproval,
    ) -> Result<CircleCiApprovalProjection, CircleCiPipelineResultError> {
        Self::validate_payload(raw, &raw.payload_digest)?;
        let scope = &self.registration.scope;
        validate_shared_identity(
            &raw.host,
            &raw.organization,
            &raw.project_slug,
            &raw.pipeline_id,
            scope,
        )?;
        if raw.workflow_id != scope.workflow_id {
            return Err(CircleCiPipelineResultError::WorkflowDrift);
        }
        if raw.job_number != scope.job_number {
            return Err(CircleCiPipelineResultError::JobDrift);
        }
        if raw.attempt_id != scope.attempt_id {
            return Err(CircleCiPipelineResultError::AttemptDrift);
        }
        if raw.revision != scope.revisions.job {
            return Err(CircleCiPipelineResultError::RevisionDrift {
                resource: "approval",
            });
        }
        let state = CircleCiApprovalState::project(&raw.state);
        Ok(CircleCiApprovalProjection {
            workflow_id: raw.workflow_id.clone(),
            job_number: raw.job_number,
            attempt_id: raw.attempt_id.clone(),
            state,
            revision: raw.revision,
            evidence_digest: digest_parts([
                &raw.workflow_id,
                &raw.job_number.to_string(),
                &raw.attempt_id,
                &format!("{state:?}"),
                &raw.revision.to_string(),
            ]),
        })
    }

    fn project_artifact(
        &self,
        raw: &RawArtifactMetadata,
    ) -> Result<CircleCiArtifactMetadataProjection, CircleCiPipelineResultError> {
        Self::validate_payload(raw, &raw.payload_digest)?;
        let scope = &self.registration.scope;
        validate_shared_identity(
            &raw.host,
            &raw.organization,
            &raw.project_slug,
            &raw.pipeline_id,
            scope,
        )?;
        if raw.workflow_id != scope.workflow_id {
            return Err(CircleCiPipelineResultError::WorkflowDrift);
        }
        if raw.job_number != scope.job_number {
            return Err(CircleCiPipelineResultError::JobDrift);
        }
        if raw.attempt_id != scope.attempt_id {
            return Err(CircleCiPipelineResultError::AttemptDrift);
        }
        if raw.revision != scope.revisions.job {
            return Err(CircleCiPipelineResultError::RevisionDrift {
                resource: "artifact metadata",
            });
        }
        let name_digest = sha256_text(&raw.name, "artifact name")?;
        let path_digest = sha256_text(&raw.path, "artifact path")?;
        if let Some(media_type) = raw.media_type.as_deref() {
            validate_bounded_text(media_type, "artifact media type", MAX_METADATA_BYTES)?;
        }
        if let Some(content_digest) = raw.content_digest.as_deref()
            && !crate::model::is_sha256(content_digest)
        {
            return Err(CircleCiPipelineResultError::InvalidDigest {
                field: "artifact content",
            });
        }
        Ok(CircleCiArtifactMetadataProjection {
            workflow_id: raw.workflow_id.clone(),
            job_number: raw.job_number,
            attempt_id: raw.attempt_id.clone(),
            name_digest,
            path_digest,
            size_bytes: raw.size_bytes,
            media_type: raw.media_type.clone(),
            content_digest: raw.content_digest.clone(),
            revision: raw.revision,
            evidence_digest: digest_parts([
                &raw.job_number.to_string(),
                &raw.attempt_id,
                &raw.size_bytes.to_string(),
                &raw.revision.to_string(),
                raw.content_digest.as_deref().unwrap_or(""),
            ]),
        })
    }

    fn validate_payload<Payload: Serialize + Clone>(
        value: &Payload,
        claimed: &str,
    ) -> Result<(), CircleCiPipelineResultError> {
        let mut json = serde_json::to_value(value)
            .map_err(|_| CircleCiPipelineResultError::TamperedEvidence)?;
        let object = json
            .as_object_mut()
            .ok_or(CircleCiPipelineResultError::TamperedEvidence)?;
        let _ = object.remove("payloadDigest");
        if canonical_digest(&json) != claimed {
            return Err(CircleCiPipelineResultError::TamperedEvidence);
        }
        Ok(())
    }
}

fn validate_shared_identity(
    host: &str,
    organization: &str,
    project_slug: &str,
    pipeline_id: &str,
    scope: &CircleCiScope,
) -> Result<(), CircleCiPipelineResultError> {
    if host != scope.host.as_str() {
        return Err(CircleCiPipelineResultError::HostDrift);
    }
    if organization != scope.organization {
        return Err(CircleCiPipelineResultError::OrganizationDrift);
    }
    if project_slug != scope.project_slug {
        return Err(CircleCiPipelineResultError::ProjectDrift);
    }
    if pipeline_id != scope.pipeline_id {
        return Err(CircleCiPipelineResultError::PipelineDrift);
    }
    Ok(())
}

fn ensure_no_replays<T>(
    values: &[T],
    key: impl Fn(&T) -> String,
) -> Result<(), CircleCiPipelineResultError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(key(value)) {
            return Err(CircleCiPipelineResultError::ReplayDetected);
        }
    }
    Ok(())
}

fn validate_timestamp(value: &str, field: &'static str) -> Result<(), CircleCiPipelineResultError> {
    validate_bounded_text(value, field, MAX_TIMESTAMP_BYTES)
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), CircleCiPipelineResultError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(CircleCiPipelineResultError::InvalidInput {
            field,
            reason: String::from("must be bounded and content-safe"),
        });
    }
    Ok(())
}

fn sha256_text(value: &str, field: &'static str) -> Result<Digest, CircleCiPipelineResultError> {
    validate_bounded_text(value, field, MAX_METADATA_BYTES)?;
    Ok(crate::model::sha256_digest(value.as_bytes()))
}

impl CircleCiProvenance {
    fn from_transport<T: CircleCiTransport>(transport: &T) -> Self {
        transport.provenance()
    }
}

impl CircleCiProvider<CircleCiFixtureTransport, crate::provider::StaticCircleCiCredentialResolver> {
    pub fn fixture(
        registration: CircleCiRegistration,
        transport: CircleCiFixtureTransport,
        credential: impl Into<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        Self::new(
            registration,
            transport,
            StaticCircleCiCredentialResolver::new(credential),
        )
    }
}
