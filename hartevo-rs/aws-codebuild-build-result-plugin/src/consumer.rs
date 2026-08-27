//! Mission-scoped AWS CodeBuild evidence consumer.

use std::{cell::RefCell, collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::model::{
    AccessLossEvidence, AwsCodeBuildScope, CodeBuildEvidence, CodeBuildEvidencePage, Digest,
    EvidenceStatus, MAX_BUILDS, MAX_PAGES, MAX_PROJECTS, PartialReason, ProviderProvenance,
};
use crate::provider::{
    AwsCodeBuildProvider, AwsCodeBuildRegistration, AwsCodeBuildTransport,
    AwsCodeBuildTransportError, BatchGetBuildsRequest, BatchGetProjectsRequest,
    ListBuildsForProjectRequest, PageBinding,
};
use crate::service::AwsCodeBuildObservationReceipt;
use crate::{AwsCodeBuildError, Result};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodeBuildReadRequest {
    pub scope_digest: Digest,
    pub list_request: Option<ListBuildsForProjectRequest>,
    pub builds_request: BatchGetBuildsRequest,
    pub projects_request: BatchGetProjectsRequest,
    pub request_digest: Digest,
}

impl AwsCodeBuildReadRequest {
    pub fn new(scope: &AwsCodeBuildScope) -> Result<Self> {
        let list_request = ListBuildsForProjectRequest::new(scope, 50)?;
        let builds_request =
            BatchGetBuildsRequest::new(scope, vec![scope.build_id.clone()], false)?;
        let projects_request = BatchGetProjectsRequest::for_scope(scope, false)?;
        let mut request = Self {
            scope_digest: scope.digest(),
            list_request: Some(list_request),
            builds_request,
            projects_request,
            request_digest: Digest::from_text("pending-codebuild-read-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn for_scope(scope: &AwsCodeBuildScope) -> Result<Self> {
        Self::new(scope)
    }

    pub fn list_only(scope: &AwsCodeBuildScope, page_size: u16) -> Result<Self> {
        let mut request = Self::new(scope)?;
        request.list_request = Some(ListBuildsForProjectRequest::new(scope, page_size)?);
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn with_list_request(
        mut self,
        scope: &AwsCodeBuildScope,
        request: ListBuildsForProjectRequest,
    ) -> Result<Self> {
        request.validate(scope)?;
        if self.scope_digest != scope.digest() {
            return Err(AwsCodeBuildError::ScopeMismatch);
        }
        self.list_request = Some(request);
        self.request_digest = self.compute_digest();
        Ok(self)
    }

    #[must_use]
    pub fn without_list_request(mut self) -> Self {
        self.list_request = None;
        self.request_digest = self.compute_digest();
        self
    }

    pub fn with_build_ids(
        mut self,
        scope: &AwsCodeBuildScope,
        build_ids: Vec<crate::model::BuildId>,
        include_batch_metadata: bool,
    ) -> Result<Self> {
        self.builds_request = BatchGetBuildsRequest::new(scope, build_ids, include_batch_metadata)?;
        self.request_digest = self.compute_digest();
        Ok(self)
    }

    pub fn with_batch_metadata(mut self, scope: &AwsCodeBuildScope, enabled: bool) -> Result<Self> {
        self.builds_request =
            BatchGetBuildsRequest::new(scope, self.builds_request.build_ids.clone(), enabled)?;
        self.projects_request = BatchGetProjectsRequest::new(
            scope,
            self.projects_request.project_names.clone(),
            enabled,
        )?;
        self.request_digest = self.compute_digest();
        Ok(self)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-read-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.list_request
                    .as_ref()
                    .map_or_else(String::new, |value| {
                        value.request_digest.as_str().to_owned()
                    }),
                self.builds_request.request_digest.as_str().to_owned(),
                self.projects_request.request_digest.as_str().to_owned(),
            ],
        )
    }

    pub fn validate(&self, scope: &AwsCodeBuildScope) -> Result<()> {
        if self.scope_digest != scope.digest() || self.request_digest != self.compute_digest() {
            return Err(AwsCodeBuildError::ScopeMismatch);
        }
        if let Some(request) = &self.list_request {
            request.validate(scope)?;
        }
        self.builds_request.validate(scope)?;
        self.projects_request.validate(scope)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsCodeBuildObservation {
    pub status: EvidenceStatus,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub durable_native_receipt: bool,
    pub independent_artifact_readback: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl MissionAwsCodeBuildObservation {
    fn from_evidence(evidence: &CodeBuildEvidence) -> Self {
        Self {
            status: evidence.status,
            provenance: evidence.provenance,
            connected: false,
            native: false,
            durable_native_receipt: false,
            independent_artifact_readback: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.durable_native_receipt
            || self.independent_artifact_readback
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(AwsCodeBuildError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsCodeBuildReadResult {
    pub evidence: CodeBuildEvidence,
    pub observation: MissionAwsCodeBuildObservation,
    pub receipt: AwsCodeBuildObservationReceipt,
}

impl MissionAwsCodeBuildReadResult {
    pub fn validate(&self, scope: &AwsCodeBuildScope) -> Result<()> {
        self.evidence
            .validate_for(scope)
            .map_err(|_| AwsCodeBuildError::TamperedEvidence)?;
        self.observation.validate()?;
        self.receipt.validate()?;
        if self.receipt.evidence_digest != self.evidence.digests.evidence_digest
            || self.receipt.scope_digest != self.evidence.digests.scope_digest
            || self.receipt.registration_digest != self.evidence.digests.registration_digest
        {
            return Err(AwsCodeBuildError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionAwsCodeBuildConsumer {
    scope: AwsCodeBuildScope,
    registration: AwsCodeBuildRegistration,
    consumed_evidence: RefCell<BTreeSet<String>>,
}

impl fmt::Debug for MissionAwsCodeBuildConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCodeBuildConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field(
                "consumed_evidence_count",
                &self.consumed_evidence.borrow().len(),
            )
            .finish()
    }
}

impl MissionAwsCodeBuildConsumer {
    pub fn new(scope: AwsCodeBuildScope, registration: AwsCodeBuildRegistration) -> Result<Self> {
        if registration.scope() != &scope {
            return Err(AwsCodeBuildError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            consumed_evidence: RefCell::new(BTreeSet::new()),
        })
    }

    pub fn with_registration(
        scope: AwsCodeBuildScope,
        registration: AwsCodeBuildRegistration,
    ) -> Result<Self> {
        Self::new(scope, registration)
    }

    pub fn scope(&self) -> &AwsCodeBuildScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsCodeBuildRegistration {
        &self.registration
    }

    #[allow(clippy::too_many_lines)]
    pub fn read<T: AwsCodeBuildTransport>(
        &self,
        provider: &mut AwsCodeBuildProvider<T>,
        request: &AwsCodeBuildReadRequest,
    ) -> Result<MissionAwsCodeBuildReadResult> {
        request.validate(&self.scope)?;
        let provider_registration = provider
            .registration()
            .ok_or(AwsCodeBuildError::RegistrationMissing)?;
        provider_registration
            .validate_for(provider.provider_revision(), provider.provider_digest())?;
        if provider_registration.registration_digest() != self.registration.registration_digest()
            || provider_registration.scope() != &self.scope
        {
            return Err(AwsCodeBuildError::ScopeMismatch);
        }
        if !provider_registration.is_active() || !self.registration.is_active() {
            return Err(AwsCodeBuildError::RegistrationRevoked);
        }

        let mut pages = Vec::new();
        let mut builds = Vec::new();
        let mut projects = Vec::new();
        let mut partial_reason = None;
        let mut access_loss = None;
        let mut seen_tokens = BTreeSet::new();

        if let Some(mut list_request) = request.list_request.clone() {
            loop {
                let page_number = list_request.page_number;
                match provider.list_builds_for_project(&list_request) {
                    Ok(page) => {
                        for build in &page.builds {
                            build.validate().map_err(AwsCodeBuildError::from)?;
                            if build.project_name != self.scope.project_name {
                                return Err(AwsCodeBuildError::ScopeMismatch);
                            }
                            if build.build_id == self.scope.build_id {
                                build.validate_against(&self.scope).map_err(|error| {
                                    if matches!(error, crate::model::ModelError::ScopeDrift) {
                                        AwsCodeBuildError::SourceDrift
                                    } else {
                                        AwsCodeBuildError::Model(error)
                                    }
                                })?;
                            }
                        }
                        pages.push(Self::page(
                            "ListBuildsForProject",
                            &list_request.binding(),
                            page.response_digest.clone(),
                        ));
                        if page.partial {
                            partial_reason.get_or_insert(PartialReason::ProviderMarkedPartial);
                        }
                        if page.builds.iter().any(|build| build.status.is_unknown()) {
                            partial_reason.get_or_insert(PartialReason::UnknownStatus);
                        }
                        if builds.len() + page.builds.len() > MAX_BUILDS {
                            partial_reason.get_or_insert(PartialReason::BuildLimitReached);
                        }
                        builds.extend(page.builds.into_iter().take(MAX_BUILDS - builds.len()));
                        if let Some(loss) = page.access_loss {
                            access_loss = Some(loss);
                            partial_reason.get_or_insert(PartialReason::ProviderMarkedPartial);
                            break;
                        }
                        match page.next_page {
                            Some(token) => {
                                if !seen_tokens.insert(token.digest().as_str().to_owned()) {
                                    return Err(AwsCodeBuildError::PageLoop);
                                }
                                if list_request.page_number >= MAX_PAGES {
                                    partial_reason.get_or_insert(PartialReason::PageLimitReached);
                                    break;
                                }
                                list_request = list_request.next_page(token)?;
                            }
                            None => break,
                        }
                    }
                    Err(AwsCodeBuildError::Transport(error)) if error.is_access_loss() => {
                        let loss = Self::access_loss(&error, "ListBuildsForProject", page_number)?;
                        pages.push(Self::synthetic_page(
                            "ListBuildsForProject",
                            &list_request.binding(),
                            &error,
                        ));
                        access_loss = Some(loss);
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        let build_requests = BatchGetBuildsRequest::batch(
            &self.scope,
            request.builds_request.build_ids.clone(),
            request.builds_request.include_batch_metadata,
        )?;
        for build_request in build_requests {
            let page_number = build_request.page_number;
            match provider.batch_get_builds(&build_request) {
                Ok(page) => {
                    for build in &page.builds {
                        if build.build_id == self.scope.build_id {
                            build.validate_against(&self.scope).map_err(|error| {
                                if matches!(error, crate::model::ModelError::ScopeDrift) {
                                    AwsCodeBuildError::SourceDrift
                                } else {
                                    AwsCodeBuildError::Model(error)
                                }
                            })?;
                        }
                        if build.status.is_unknown() {
                            partial_reason.get_or_insert(PartialReason::UnknownStatus);
                        }
                    }
                    pages.push(Self::page(
                        "BatchGetBuilds",
                        &build_request.binding(&self.scope),
                        page.response_digest.clone(),
                    ));
                    if page.partial {
                        partial_reason.get_or_insert(if page.batch_metadata_truncated {
                            PartialReason::OptionalBatchMetadataTruncated
                        } else {
                            PartialReason::ProviderMarkedPartial
                        });
                    }
                    if page.not_found_ids.contains(&self.scope.build_id) {
                        partial_reason.get_or_insert(PartialReason::MissingTargetBuild);
                    }
                    if builds.len() + page.builds.len() > MAX_BUILDS {
                        partial_reason.get_or_insert(PartialReason::BuildLimitReached);
                    }
                    builds.extend(page.builds.into_iter().take(MAX_BUILDS - builds.len()));
                    if let Some(loss) = page.access_loss {
                        access_loss = Some(loss);
                        partial_reason.get_or_insert(PartialReason::ProviderMarkedPartial);
                        break;
                    }
                }
                Err(AwsCodeBuildError::Transport(error)) if error.is_access_loss() => {
                    let loss = Self::access_loss(&error, "BatchGetBuilds", page_number)?;
                    pages.push(Self::synthetic_page(
                        "BatchGetBuilds",
                        &build_request.binding(&self.scope),
                        &error,
                    ));
                    access_loss = Some(loss);
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        match provider.batch_get_projects(&request.projects_request) {
            Ok(page) => {
                for project in &page.projects {
                    project.validate_against(&self.scope).map_err(|error| {
                        if matches!(error, crate::model::ModelError::ScopeDrift) {
                            AwsCodeBuildError::ScopeMismatch
                        } else {
                            AwsCodeBuildError::Model(error)
                        }
                    })?;
                }
                pages.push(Self::page(
                    "BatchGetProjects",
                    &request.projects_request.binding(&self.scope),
                    page.response_digest.clone(),
                ));
                if page.partial {
                    partial_reason.get_or_insert(if page.batch_metadata_truncated {
                        PartialReason::OptionalBatchMetadataTruncated
                    } else {
                        PartialReason::ProviderMarkedPartial
                    });
                }
                if page.not_found_names.contains(&self.scope.project_name) {
                    partial_reason.get_or_insert(PartialReason::MissingProject);
                }
                projects.extend(page.projects.into_iter().take(MAX_PROJECTS));
                if let Some(loss) = page.access_loss {
                    access_loss = Some(loss);
                    partial_reason.get_or_insert(PartialReason::ProviderMarkedPartial);
                }
            }
            Err(AwsCodeBuildError::Transport(error)) if error.is_access_loss() => {
                let loss = Self::access_loss(&error, "BatchGetProjects", 1)?;
                pages.push(Self::synthetic_page(
                    "BatchGetProjects",
                    &request.projects_request.binding(&self.scope),
                    &error,
                ));
                access_loss = Some(loss);
            }
            Err(error) => return Err(error),
        }

        if pages.is_empty() {
            return Err(AwsCodeBuildError::ResponseBoundExceeded);
        }
        let status = if access_loss.is_some() {
            EvidenceStatus::AccessLost
        } else if partial_reason.is_some() {
            EvidenceStatus::Partial
        } else {
            EvidenceStatus::Complete
        };
        let evidence = CodeBuildEvidence::new(
            &self.scope,
            provider.provider_revision().to_owned(),
            provider.provider_digest().clone(),
            self.registration.registration_digest().clone(),
            request.request_digest.clone(),
            pages,
            builds,
            projects,
            provider.provenance(),
            status,
            partial_reason,
            access_loss,
        )?;
        let observation = MissionAwsCodeBuildObservation::from_evidence(&evidence);
        let receipt = AwsCodeBuildObservationReceipt::from_evidence(&evidence)?;
        Ok(MissionAwsCodeBuildReadResult {
            evidence,
            observation,
            receipt,
        })
    }

    pub fn consume_evidence(
        &self,
        evidence: CodeBuildEvidence,
    ) -> Result<MissionAwsCodeBuildObservation> {
        if !self.registration.is_active() {
            return Err(AwsCodeBuildError::RegistrationRevoked);
        }
        evidence
            .validate_for(&self.scope)
            .map_err(|_| AwsCodeBuildError::TamperedEvidence)?;
        if evidence.digests.registration_digest != *self.registration.registration_digest() {
            return Err(AwsCodeBuildError::StaleEvidence);
        }
        if !self
            .consumed_evidence
            .borrow_mut()
            .insert(evidence.digests.evidence_digest.as_str().to_owned())
        {
            return Err(AwsCodeBuildError::ReplayDetected);
        }
        Ok(MissionAwsCodeBuildObservation::from_evidence(&evidence))
    }

    fn page(
        operation: &str,
        binding: &PageBinding,
        response_digest: Digest,
    ) -> CodeBuildEvidencePage {
        CodeBuildEvidencePage {
            operation: operation.to_owned(),
            request_digest: binding.request_digest.clone(),
            response_digest,
            page_number: binding.page_number,
            page_token_digest: binding.page_token_digest.clone(),
        }
    }

    fn synthetic_page(
        operation: &str,
        binding: &PageBinding,
        error: &AwsCodeBuildTransportError,
    ) -> CodeBuildEvidencePage {
        Self::page(operation, binding, Digest::from_text(error.provider_code()))
    }

    fn access_loss(
        error: &AwsCodeBuildTransportError,
        operation: &str,
        page_number: u16,
    ) -> Result<AccessLossEvidence> {
        AccessLossEvidence::new(
            error.access_loss_kind(),
            error.provider_code(),
            operation,
            page_number,
        )
        .map_err(AwsCodeBuildError::from)
    }
}
