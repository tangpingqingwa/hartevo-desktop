//! Typed Layer-1 service, registration, and review proposal.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

pub use crate::model::FrameIoAuthority;
use crate::{
    Digest, FRAME_IO_PROVIDER_ID, FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION,
    FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION, FRAME_IO_REVIEW_RESULT_SCHEMA_VERSION,
    FRAME_IO_REVIEW_RESULT_SERVICE_ID, FrameIoApprovalStatus, FrameIoAssetSummary, FrameIoBounds,
    FrameIoCommentSummary, FrameIoGetRequest, FrameIoPayload, FrameIoReadFailure,
    FrameIoReadOperation, FrameIoReadReceipt, FrameIoRedactions, FrameIoReviewLinkState,
    FrameIoReviewLinkSummary, FrameIoReviewStatus, FrameIoRevisionFence, FrameIoScope,
    FrameIoTransportProvenance, FrameIoVersionSummary, MISSION_FRAME_IO_REVIEW_CONSUMER_ID,
    MissionId, ModelError, ProjectId, RegistrationState, Revision, SecretReference, WorkProductId,
    contract_digest, model::digest_serializable,
};
use crate::{
    provider::{
        FrameIoProvider, FrameIoProviderDefinition, FrameIoProviderError, FrameIoProviderRead,
        FrameIoRetryEvidence,
    },
    transport::{FrameIoTransport, FrameIoTransportErrorKind, OpaqueCursor},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl FrameIoServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: FRAME_IO_REVIEW_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: FRAME_IO_REVIEW_RESULT_SERVICE_ID.to_owned(),
            provider_id: FRAME_IO_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_FRAME_IO_REVIEW_CONSUMER_ID.to_owned(),
            contract_digest: contract_digest(),
            read_only: true,
            live_execution: false,
            external_writes: false,
            connected: false,
            native_provider: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }
}

impl Default for FrameIoServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl FrameIoRegistration {
    pub fn new(
        scope: &FrameIoScope,
        secret_reference: &SecretReference,
        provider: &FrameIoProviderDefinition,
    ) -> Result<Self, FrameIoServiceError> {
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(FrameIoServiceError::ScopeMismatch(
                "SecretReference is bound to a different Frame.io scope".to_owned(),
            ));
        }
        let registration_revision = Revision::new(1)?;
        let mut registration = Self {
            plugin_version: FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.as_str().to_owned(),
            provider_version: provider.provider_version.clone(),
            provider_digest: provider.provider_digest(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.credential_revision(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("uninitialized-frameio-registration"),
        };
        registration.registration_digest = registration.recompute_digest()?;
        Ok(registration)
    }

    pub fn recompute_digest(&self) -> Result<Digest, FrameIoServiceError> {
        let material = FrameIoRegistrationMaterial {
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version.clone(),
            provider_digest: self.provider_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            secret_reference_digest: self.secret_reference_digest.clone(),
            credential_revision: self.credential_revision,
            registration_revision: self.registration_revision,
            state: self.state,
        };
        digest_serializable(&material).map_err(FrameIoServiceError::Model)
    }

    pub fn revoke(&mut self) -> Result<(), FrameIoServiceError> {
        if self.state == RegistrationState::Revoked {
            return Err(FrameIoServiceError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_revision = Revision::new(self.registration_revision.get() + 1)?;
        self.registration_digest = self.recompute_digest()?;
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn digest(&self) -> &Digest {
        &self.registration_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrameIoRegistrationMaterial {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: String,
    provider_digest: Digest,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    registration_revision: Revision,
    state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoReviewProposalRequest {
    pub operations: Vec<FrameIoReadOperation>,
    pub bounds: FrameIoBounds,
    pub observation_window: crate::ObservationWindow,
    pub work_product_revision: Revision,
    pub request_digest: Digest,
}

impl FrameIoReviewProposalRequest {
    pub fn new(
        operations: impl IntoIterator<Item = FrameIoReadOperation>,
        bounds: FrameIoBounds,
        observation_window: crate::ObservationWindow,
        work_product_revision: Revision,
    ) -> Result<Self, FrameIoServiceError> {
        let operations = operations.into_iter().collect::<Vec<_>>();
        if operations.is_empty() {
            return Err(FrameIoServiceError::InvalidRequest(
                "at least one bounded read operation is required".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for operation in &operations {
            if !seen.insert(*operation) {
                return Err(FrameIoServiceError::InvalidRequest(
                    ModelError::DuplicateOperation.to_string(),
                ));
            }
        }
        if observation_window.duration_seconds() > bounds.max_window_seconds {
            return Err(FrameIoServiceError::InvalidRequest(
                "observation window exceeds requested bounds".to_owned(),
            ));
        }
        let material = FrameIoProposalRequestMaterial {
            operations: operations.clone(),
            bounds,
            observation_window: observation_window.clone(),
            work_product_revision,
        };
        let request_digest = digest_serializable(&material).map_err(FrameIoServiceError::Model)?;
        Ok(Self {
            operations,
            bounds,
            observation_window,
            work_product_revision,
            request_digest,
        })
    }

    pub fn recompute_digest(&self) -> Result<Digest, FrameIoServiceError> {
        let material = FrameIoProposalRequestMaterial {
            operations: self.operations.clone(),
            bounds: self.bounds,
            observation_window: self.observation_window.clone(),
            work_product_revision: self.work_product_revision,
        };
        digest_serializable(&material).map_err(FrameIoServiceError::Model)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrameIoProposalRequestMaterial {
    operations: Vec<FrameIoReadOperation>,
    bounds: FrameIoBounds,
    observation_window: crate::ObservationWindow,
    work_product_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoReviewEvidence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revision_fence: FrameIoRevisionFence,
    pub asset: Option<FrameIoAssetSummary>,
    pub version: Option<FrameIoVersionSummary>,
    pub review_link: Option<FrameIoReviewLinkSummary>,
    pub approval: Option<crate::FrameIoApprovalSummary>,
    pub comments: Option<FrameIoCommentSummary>,
    pub status: FrameIoReviewStatus,
    pub asset_digest: Digest,
    pub version_digest: Digest,
    pub review_link_digest: Digest,
    pub comment_digest: Digest,
    pub receipts: Vec<FrameIoReadReceipt>,
    pub retries: Vec<FrameIoRetryEvidence>,
    pub failures: Vec<FrameIoReadFailure>,
    pub provenance: FrameIoTransportProvenance,
    pub redactions: FrameIoRedactions,
    pub authority: FrameIoAuthority,
    pub evidence_digest: Digest,
}

impl FrameIoReviewEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &FrameIoScope,
        asset: Option<FrameIoAssetSummary>,
        version: Option<FrameIoVersionSummary>,
        review_link: Option<FrameIoReviewLinkSummary>,
        approval: Option<crate::FrameIoApprovalSummary>,
        comments: Option<FrameIoCommentSummary>,
        status: FrameIoReviewStatus,
        receipts: Vec<FrameIoReadReceipt>,
        retries: Vec<FrameIoRetryEvidence>,
        failures: Vec<FrameIoReadFailure>,
        provenance: FrameIoTransportProvenance,
    ) -> Result<Self, FrameIoServiceError> {
        let mut evidence = Self {
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            consent_digest: scope.consent_digest(),
            revision_fence: scope.fence(),
            asset_digest: optional_digest(
                "frameio-asset-evidence/v1",
                asset.as_ref().map(|value| &value.asset_digest),
            ),
            version_digest: optional_digest(
                "frameio-version-evidence/v1",
                version.as_ref().map(|value| &value.version_digest),
            ),
            review_link_digest: optional_digest(
                "frameio-review-link-evidence/v1",
                review_link.as_ref().map(|value| &value.review_link_digest),
            ),
            comment_digest: optional_digest(
                "frameio-comment-evidence/v1",
                comments.as_ref().map(|value| &value.comment_digest),
            ),
            asset,
            version,
            review_link,
            approval,
            comments,
            status,
            receipts,
            retries,
            failures,
            provenance,
            redactions: FrameIoRedactions::layer_one(),
            authority: FrameIoAuthority::layer_one(),
            evidence_digest: Digest::from_text("uninitialized-frameio-evidence"),
        };
        evidence.evidence_digest = evidence.recompute_digest()?;
        Ok(evidence)
    }

    pub fn recompute_digest(&self) -> Result<Digest, FrameIoServiceError> {
        let material = FrameIoEvidenceMaterial::from_evidence(self);
        digest_serializable(&material).map_err(FrameIoServiceError::Model)
    }

    pub fn validate(&self, scope: &FrameIoScope) -> Result<(), FrameIoServiceError> {
        if self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_digest
            || self.consent_digest != scope.consent_digest()
            || self.revision_fence != scope.fence()
            || self.redactions != FrameIoRedactions::layer_one()
            || self.authority != FrameIoAuthority::layer_one()
            || self.evidence_digest != self.recompute_digest()?
        {
            return Err(FrameIoServiceError::StaleEvidence);
        }
        if let Some(asset) = &self.asset
            && (!asset.digest_is_valid()
                || asset.asset_id != scope.asset_id
                || asset.frameio_project_id != scope.frameio_project_id
                || asset.revision != scope.revision_fence.asset_revision)
        {
            return Err(FrameIoServiceError::ScopeMismatch(
                "asset evidence drifted from the registered scope".to_owned(),
            ));
        }
        if let Some(version) = &self.version
            && (!version.digest_is_valid()
                || version.asset_id != scope.asset_id
                || version.version_id != scope.asset_version_id
                || version.revision != scope.revision_fence.version_revision)
        {
            return Err(FrameIoServiceError::ScopeMismatch(
                "version evidence drifted from the registered scope".to_owned(),
            ));
        }
        if let Some(review_link) = &self.review_link
            && (!review_link.digest_is_valid()
                || review_link.review_link_id != scope.review_link_id
                || review_link.revision != scope.revision_fence.review_link_revision)
        {
            return Err(FrameIoServiceError::ScopeMismatch(
                "review-link evidence drifted from the registered scope".to_owned(),
            ));
        }
        if let Some(approval) = &self.approval
            && (!approval.digest_is_valid()
                || approval.revision != scope.revision_fence.review_link_revision)
        {
            return Err(FrameIoServiceError::ScopeMismatch(
                "approval evidence drifted from the registered scope".to_owned(),
            ));
        }
        if let Some(comments) = &self.comments
            && (!comments.digest_is_valid()
                || comments.revision != scope.revision_fence.comment_revision)
        {
            return Err(FrameIoServiceError::ScopeMismatch(
                "comment evidence drifted from the registered scope".to_owned(),
            ));
        }
        if self.asset_digest
            != optional_digest(
                "frameio-asset-evidence/v1",
                self.asset.as_ref().map(|value| &value.asset_digest),
            )
            || self.version_digest
                != optional_digest(
                    "frameio-version-evidence/v1",
                    self.version.as_ref().map(|value| &value.version_digest),
                )
            || self.review_link_digest
                != optional_digest(
                    "frameio-review-link-evidence/v1",
                    self.review_link
                        .as_ref()
                        .map(|value| &value.review_link_digest),
                )
            || self.comment_digest
                != optional_digest(
                    "frameio-comment-evidence/v1",
                    self.comments.as_ref().map(|value| &value.comment_digest),
                )
        {
            return Err(FrameIoServiceError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrameIoEvidenceMaterial {
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    revision_fence: FrameIoRevisionFence,
    asset: Option<FrameIoAssetSummary>,
    version: Option<FrameIoVersionSummary>,
    review_link: Option<FrameIoReviewLinkSummary>,
    approval: Option<crate::FrameIoApprovalSummary>,
    comments: Option<FrameIoCommentSummary>,
    status: FrameIoReviewStatus,
    asset_digest: Digest,
    version_digest: Digest,
    review_link_digest: Digest,
    comment_digest: Digest,
    receipts: Vec<FrameIoReadReceipt>,
    retries: Vec<FrameIoRetryEvidence>,
    failures: Vec<FrameIoReadFailure>,
    provenance: FrameIoTransportProvenance,
    redactions: FrameIoRedactions,
    authority: FrameIoAuthority,
}

impl FrameIoEvidenceMaterial {
    fn from_evidence(evidence: &FrameIoReviewEvidence) -> Self {
        Self {
            scope_digest: evidence.scope_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            consent_digest: evidence.consent_digest.clone(),
            revision_fence: evidence.revision_fence,
            asset: evidence.asset.clone(),
            version: evidence.version.clone(),
            review_link: evidence.review_link.clone(),
            approval: evidence.approval.clone(),
            comments: evidence.comments.clone(),
            status: evidence.status,
            asset_digest: evidence.asset_digest.clone(),
            version_digest: evidence.version_digest.clone(),
            review_link_digest: evidence.review_link_digest.clone(),
            comment_digest: evidence.comment_digest.clone(),
            receipts: evidence.receipts.clone(),
            retries: evidence.retries.clone(),
            failures: evidence.failures.clone(),
            provenance: evidence.provenance,
            redactions: evidence.redactions,
            authority: evidence.authority,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoReviewProposal {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub read_only: bool,
    pub native_evidence: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub evidence: FrameIoReviewEvidence,
    pub proposal_digest: Digest,
}

impl FrameIoReviewProposal {
    fn new(
        scope: &FrameIoScope,
        registration: &FrameIoRegistration,
        request: &FrameIoReviewProposalRequest,
        evidence: FrameIoReviewEvidence,
    ) -> Result<Self, FrameIoServiceError> {
        let mut proposal = Self {
            plugin_version: FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            registration_digest: registration.digest().clone(),
            provider_digest: registration.provider_digest.clone(),
            request_digest: request.request_digest.clone(),
            scope_digest: scope.digest(),
            project_id: scope.project_id.clone(),
            project_revision: scope.project_revision,
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
            work_product_id: scope.work_product_id.clone(),
            work_product_revision: scope.work_product_revision,
            read_only: true,
            native_evidence: false,
            connected: false,
            external_write_performed: false,
            outcome_authority: false,
            work_product_adoption: false,
            evidence,
            proposal_digest: Digest::from_text("uninitialized-frameio-proposal"),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    pub fn recompute_digest(&self) -> Result<Digest, FrameIoServiceError> {
        digest_serializable(&FrameIoProposalMaterial::from_proposal(self))
            .map_err(FrameIoServiceError::Model)
    }

    pub fn validate(
        &self,
        scope: &FrameIoScope,
        registration: &FrameIoRegistration,
        request: &FrameIoReviewProposalRequest,
    ) -> Result<(), FrameIoServiceError> {
        self.validate_bindings(scope, registration)?;
        if self.request_digest != request.request_digest
            || request.request_digest != request.recompute_digest()?
        {
            return Err(FrameIoServiceError::StaleEvidence);
        }
        Ok(())
    }

    pub fn validate_bindings(
        &self,
        scope: &FrameIoScope,
        registration: &FrameIoRegistration,
    ) -> Result<(), FrameIoServiceError> {
        self.evidence.validate(scope)?;
        if self.plugin_version != FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION
            || self.contract_version != FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.registration_digest != registration.digest().clone()
            || self.provider_digest != registration.provider_digest.clone()
            || self.scope_digest != scope.digest()
            || self.project_id != scope.project_id
            || self.project_revision != scope.project_revision
            || self.mission_id != scope.mission_id
            || self.mission_revision != scope.mission_revision
            || self.work_product_id != scope.work_product_id
            || self.work_product_revision != scope.work_product_revision
            || !self.read_only
            || self.native_evidence
            || self.connected
            || self.external_write_performed
            || self.outcome_authority
            || self.work_product_adoption
            || self.proposal_digest != self.recompute_digest()?
        {
            return Err(FrameIoServiceError::StaleEvidence);
        }
        Ok(())
    }

    pub fn status(&self) -> FrameIoReviewStatus {
        self.evidence.status
    }

    pub fn is_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrameIoProposalMaterial {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    registration_digest: Digest,
    provider_digest: Digest,
    request_digest: Digest,
    scope_digest: Digest,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    read_only: bool,
    native_evidence: bool,
    connected: bool,
    external_write_performed: bool,
    outcome_authority: bool,
    work_product_adoption: bool,
    evidence: FrameIoReviewEvidence,
}

impl FrameIoProposalMaterial {
    fn from_proposal(proposal: &FrameIoReviewProposal) -> Self {
        Self {
            plugin_version: proposal.plugin_version.clone(),
            contract_version: proposal.contract_version.clone(),
            contract_digest: proposal.contract_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project_id: proposal.project_id.clone(),
            project_revision: proposal.project_revision,
            mission_id: proposal.mission_id.clone(),
            mission_revision: proposal.mission_revision,
            work_product_id: proposal.work_product_id.clone(),
            work_product_revision: proposal.work_product_revision,
            read_only: proposal.read_only,
            native_evidence: proposal.native_evidence,
            connected: proposal.connected,
            external_write_performed: proposal.external_write_performed,
            outcome_authority: proposal.outcome_authority,
            work_product_adoption: proposal.work_product_adoption,
            evidence: proposal.evidence.clone(),
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FrameIoServiceError {
    #[error("Frame.io request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Frame.io scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Frame.io consent scope is expired or does not allow this read")]
    ConsentDenied,
    #[error("Frame.io registration is revoked or stale")]
    RegistrationRevoked,
    #[error("Frame.io SecretReference is revoked")]
    SecretRevoked,
    #[error("Frame.io evidence is stale, tampered, or duplicated")]
    StaleEvidence,
    #[error("Frame.io cursor repeated within a bounded read")]
    PageLoop,
    #[error("Frame.io response pages exceeded the bound")]
    PageBoundExceeded,
    #[error("Frame.io provider error: {0}")]
    Provider(#[from] FrameIoProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

pub struct FrameIoReviewResultService<T> {
    scope: FrameIoScope,
    secret_reference: SecretReference,
    provider: FrameIoProvider<T>,
    registration: FrameIoRegistration,
    service_definition: FrameIoServiceDefinition,
}

impl<T: FrameIoTransport> fmt::Debug for FrameIoReviewResultService<T>
where
    FrameIoProvider<T>: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameIoReviewResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: FrameIoTransport> FrameIoReviewResultService<T> {
    pub fn new(
        scope: FrameIoScope,
        secret_reference: SecretReference,
        provider: FrameIoProvider<T>,
    ) -> Result<Self, FrameIoServiceError> {
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(FrameIoServiceError::ScopeMismatch(
                "SecretReference and service scope differ".to_owned(),
            ));
        }
        if provider.is_native() || provider.is_connected() {
            return Err(FrameIoServiceError::ScopeMismatch(
                "Layer 1 cannot mount a native or Connected provider".to_owned(),
            ));
        }
        let registration =
            FrameIoRegistration::new(&scope, &secret_reference, provider.definition())?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            service_definition: FrameIoServiceDefinition::new(),
        })
    }

    pub fn scope(&self) -> &FrameIoScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &FrameIoProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut FrameIoProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &FrameIoRegistration {
        &self.registration
    }

    pub fn service_definition(&self) -> &FrameIoServiceDefinition {
        &self.service_definition
    }

    pub fn revoke_registration(&mut self) -> Result<(), FrameIoServiceError> {
        self.registration.revoke()
    }

    pub fn revoke_secret(&mut self) -> Result<(), FrameIoServiceError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn propose(
        &mut self,
        request: FrameIoReviewProposalRequest,
        at: DateTime<Utc>,
    ) -> Result<FrameIoReviewProposal, FrameIoServiceError> {
        self.ensure_active()?;
        if request.work_product_revision != self.scope.work_product_revision {
            return Err(FrameIoServiceError::ScopeMismatch(
                "proposal work-product revision differs from the scope".to_owned(),
            ));
        }
        if request.request_digest != request.recompute_digest()? {
            return Err(FrameIoServiceError::StaleEvidence);
        }
        if request.observation_window.duration_seconds() > request.bounds.max_window_seconds
            || request.observation_window.duration_seconds() > crate::FRAME_IO_MAX_WINDOW_SECONDS
            || self.scope.consent_scope.is_expired(at)
            || request
                .operations
                .iter()
                .any(|operation| !self.scope.consent_scope.allows(*operation))
        {
            return Err(FrameIoServiceError::ConsentDenied);
        }
        if request.observation_window.end > at {
            return Err(FrameIoServiceError::InvalidRequest(
                "observation window cannot end in the future".to_owned(),
            ));
        }
        let mut accumulator = EvidenceAccumulator::default();
        for operation in &request.operations {
            self.read_operation(*operation, &request, &mut accumulator)?;
        }
        let status = derive_status(&accumulator);
        let evidence = FrameIoReviewEvidence::new(
            &self.scope,
            accumulator.asset,
            accumulator.version,
            accumulator.review_link,
            accumulator.approval,
            accumulator.comments,
            status,
            accumulator.receipts,
            accumulator.retries,
            accumulator.failures,
            self.provider.provenance(),
        )?;
        evidence.validate(&self.scope)?;
        FrameIoReviewProposal::new(&self.scope, &self.registration, &request, evidence)
    }

    fn ensure_active(&self) -> Result<(), FrameIoServiceError> {
        if !self.registration.is_active() {
            return Err(FrameIoServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(FrameIoServiceError::SecretRevoked);
        }
        Ok(())
    }

    fn read_operation(
        &mut self,
        operation: FrameIoReadOperation,
        request: &FrameIoReviewProposalRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<(), FrameIoServiceError> {
        let mut page_number = 1_u16;
        let mut cursor: Option<OpaqueCursor> = None;
        let mut seen_cursors = BTreeSet::new();
        loop {
            let get_request = FrameIoGetRequest::new(
                &self.scope,
                &self.secret_reference,
                operation,
                request.bounds,
                request.observation_window.clone(),
                page_number,
                cursor.clone(),
            )?;
            match self.provider.read(&get_request, request.bounds) {
                Ok(read) => {
                    accumulator.accept_read(operation, read, request.bounds)?;
                    let next_cursor = accumulator.next_cursor.take();
                    match next_cursor {
                        None => return Ok(()),
                        Some(next_cursor) => {
                            if !seen_cursors.insert(next_cursor.digest().clone()) {
                                return Err(FrameIoServiceError::PageLoop);
                            }
                            if page_number >= request.bounds.max_pages() {
                                accumulator.partial_due_to_bound = true;
                                accumulator.failures.push(FrameIoReadFailure {
                                    operation,
                                    kind: FrameIoTransportErrorKind::InvalidResponse,
                                    status_code: None,
                                    diagnostic_digest: Digest::from_text(
                                        "frameio-page-bound-exceeded",
                                    ),
                                    provenance: self.provider.provenance(),
                                });
                                return Ok(());
                            }
                            page_number = page_number.saturating_add(1);
                            cursor = Some(next_cursor);
                        }
                    }
                }
                Err(FrameIoProviderError::Transport(error)) => {
                    accumulator.failures.push(FrameIoReadFailure {
                        operation,
                        kind: error.kind,
                        status_code: error.status_code,
                        diagnostic_digest: error.diagnostic_digest().clone(),
                        provenance: self.provider.provenance(),
                    });
                    return Ok(());
                }
                Err(error) => return Err(FrameIoServiceError::Provider(error)),
            }
        }
    }
}

#[derive(Default)]
struct EvidenceAccumulator {
    asset: Option<FrameIoAssetSummary>,
    version: Option<FrameIoVersionSummary>,
    review_link: Option<FrameIoReviewLinkSummary>,
    approval: Option<crate::FrameIoApprovalSummary>,
    comments: Option<FrameIoCommentSummary>,
    receipts: Vec<FrameIoReadReceipt>,
    retries: Vec<FrameIoRetryEvidence>,
    failures: Vec<FrameIoReadFailure>,
    next_cursor: Option<OpaqueCursor>,
    partial_due_to_bound: bool,
}

impl EvidenceAccumulator {
    fn accept_read(
        &mut self,
        operation: FrameIoReadOperation,
        read: FrameIoProviderRead,
        bounds: FrameIoBounds,
    ) -> Result<(), FrameIoServiceError> {
        self.receipts.push(read.receipt);
        self.retries.extend(read.retries);
        self.next_cursor.clone_from(&read.response.next_cursor);
        match (operation, read.response.payload) {
            (FrameIoReadOperation::AssetMetadata, FrameIoPayload::Asset(asset)) => {
                self.asset = Some(asset);
            }
            (FrameIoReadOperation::AssetVersion, FrameIoPayload::Version(version)) => {
                self.version = Some(version);
            }
            (FrameIoReadOperation::ReviewLink, FrameIoPayload::ReviewLink(review_link)) => {
                self.review_link = Some(review_link);
            }
            (FrameIoReadOperation::ApprovalStatus, FrameIoPayload::Approval(approval)) => {
                self.approval = Some(approval);
            }
            (FrameIoReadOperation::CommentSummary, FrameIoPayload::Comments(comments)) => {
                self.comments = match self.comments.take() {
                    Some(existing) => Some(
                        existing
                            .merge(&comments, bounds.max_comment_summaries)
                            .map_err(FrameIoServiceError::Model)?,
                    ),
                    None => Some(comments),
                };
            }
            _ => {
                return Err(FrameIoServiceError::Provider(
                    FrameIoProviderError::InvalidPayload,
                ));
            }
        }
        Ok(())
    }
}

fn optional_digest(domain: &str, value: Option<&Digest>) -> Digest {
    Digest::from_fields(
        domain,
        &[value.map_or_else(|| "absent".to_owned(), |digest| digest.as_str().to_owned())],
    )
}

fn derive_status(accumulator: &EvidenceAccumulator) -> FrameIoReviewStatus {
    if accumulator.partial_due_to_bound
        || accumulator
            .comments
            .as_ref()
            .is_some_and(|comments| comments.partial)
    {
        return FrameIoReviewStatus::Partial;
    }
    if accumulator.failures.iter().any(|failure| {
        matches!(
            failure.kind,
            FrameIoTransportErrorKind::PermissionDenied | FrameIoTransportErrorKind::NotFound
        )
    }) {
        return if accumulator
            .failures
            .iter()
            .any(|failure| failure.kind == FrameIoTransportErrorKind::PermissionDenied)
        {
            FrameIoReviewStatus::AccessLost
        } else {
            FrameIoReviewStatus::RetentionGap
        };
    }
    if !accumulator.failures.is_empty() {
        return if accumulator.receipts.is_empty() {
            FrameIoReviewStatus::ProviderUnknown
        } else {
            FrameIoReviewStatus::Partial
        };
    }
    if let Some(approval) = accumulator.approval.as_ref().map(|value| value.status) {
        match approval {
            FrameIoApprovalStatus::Approved => return FrameIoReviewStatus::Approved,
            FrameIoApprovalStatus::ChangesRequested => {
                return FrameIoReviewStatus::ChangesRequested;
            }
            FrameIoApprovalStatus::Rejected => return FrameIoReviewStatus::Rejected,
            FrameIoApprovalStatus::Pending | FrameIoApprovalStatus::Unknown => {}
        }
    }
    if let Some(review_link) = &accumulator.review_link {
        match review_link.approval {
            FrameIoApprovalStatus::Approved => return FrameIoReviewStatus::Approved,
            FrameIoApprovalStatus::ChangesRequested => {
                return FrameIoReviewStatus::ChangesRequested;
            }
            FrameIoApprovalStatus::Rejected => return FrameIoReviewStatus::Rejected,
            FrameIoApprovalStatus::Pending | FrameIoApprovalStatus::Unknown => {}
        }
        if matches!(review_link.state, FrameIoReviewLinkState::Active) {
            return FrameIoReviewStatus::InReview;
        }
    }
    accumulator
        .version
        .as_ref()
        .map(|value| value.status)
        .or_else(|| accumulator.asset.as_ref().map(|value| value.status))
        .unwrap_or(FrameIoReviewStatus::ProviderUnknown)
}
