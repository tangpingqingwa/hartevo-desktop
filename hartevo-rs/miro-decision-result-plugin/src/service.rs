use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    MIRO_DECISION_RESULT_CONSUMER_ID, MIRO_DECISION_RESULT_CONTRACT_JSON,
    MIRO_DECISION_RESULT_CONTRACT_VERSION, MIRO_DECISION_RESULT_PROVIDER_ID,
    MIRO_DECISION_RESULT_SCHEMA_VERSION, MIRO_DECISION_RESULT_SERVICE_ID,
    model::{
        AdoptionAvailability, DecisionBounds, DecisionResultAuthority, Digest, EvidenceDigests,
        ItemId, MiroBoardItem, MiroBoardMetadata, MiroDecisionRegistration, MiroDecisionScope,
        ModelError, ProviderErrorEvidence, ProviderErrorKind, RegistrationRevocation, Revision,
        SecretReference, canonical_item_set_digest, canonical_redaction_digest,
        canonical_result_digest,
    },
    provider::{
        MiroBoardPage, MiroBoardProvider, MiroBoardProviderDefinition, MiroBoardReadRequest,
        ProviderDefinitionError, ProviderProvenance, TransportError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MiroDecisionResultServiceError {
    #[error("Miro decision registration is revoked")]
    RegistrationRevoked,
    #[error("Miro SecretReference is revoked")]
    SecretRevoked,
    #[error("Miro scope or secret reference does not match")]
    ScopeMismatch,
    #[error("provider definition is invalid")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("provider evidence was tampered with or its digest is stale")]
    TamperedEvidence,
    #[error("provider permission, board, or Mission revision fence changed")]
    FenceViolation,
    #[error("provider returned a different team or board")]
    BoardMismatch,
    #[error("provider returned an item outside the allowlist")]
    ItemOutsideAllowlist,
    #[error("provider returned a duplicate item")]
    DuplicateItem,
    #[error("provider returned a repeated cursor")]
    PageLoop,
    #[error("provider returned too many items for one bounded page")]
    InvalidResponseShape,
    #[error("proposal digest is stale or invalid")]
    InvalidProposal,
    #[error("registration or evidence model is invalid")]
    Model(#[from] ModelError),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RetryPolicyError {
    #[error("retry attempts must be between one and four")]
    InvalidAttempts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8) -> Result<Self, RetryPolicyError> {
        if !(1..=4).contains(&max_attempts) {
            Err(RetryPolicyError::InvalidAttempts)
        } else {
            Ok(Self { max_attempts })
        }
    }

    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MiroDecisionProposalRequest {
    pub bounds: DecisionBounds,
}

impl MiroDecisionProposalRequest {
    pub const fn new(bounds: DecisionBounds) -> Self {
        Self { bounds }
    }

    pub fn bounded(max_pages: u8, max_items: u16, page_size: u16) -> Result<Self, ModelError> {
        Ok(Self::new(DecisionBounds::new(
            max_pages, max_items, page_size,
        )?))
    }
}

impl Default for MiroDecisionProposalRequest {
    fn default() -> Self {
        Self::new(DecisionBounds::default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageCap,
    ItemCap,
    MissingCursor,
    ProviderPartial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiroDecisionResultStatus {
    Complete,
    Unsupported,
    Deleted,
    AccessLost,
    Empty,
    Partial,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnv,
    ScopeDrift,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiroDecisionProjection {
    Complete,
    Unsupported,
    Deleted,
    AccessLost,
    Empty,
    Partial(PartialReason),
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnv,
    ScopeDrift,
    ProviderUnknown,
}

impl MiroDecisionProjection {
    pub const fn status(self) -> MiroDecisionResultStatus {
        match self {
            Self::Complete => MiroDecisionResultStatus::Complete,
            Self::Unsupported => MiroDecisionResultStatus::Unsupported,
            Self::Deleted => MiroDecisionResultStatus::Deleted,
            Self::AccessLost => MiroDecisionResultStatus::AccessLost,
            Self::Empty => MiroDecisionResultStatus::Empty,
            Self::Partial(_) => MiroDecisionResultStatus::Partial,
            Self::RateLimited => MiroDecisionResultStatus::RateLimited,
            Self::ServerFailure => MiroDecisionResultStatus::ServerFailure,
            Self::Timeout => MiroDecisionResultStatus::Timeout,
            Self::BlockedEnv => MiroDecisionResultStatus::BlockedEnv,
            Self::ScopeDrift => MiroDecisionResultStatus::ScopeDrift,
            Self::ProviderUnknown => MiroDecisionResultStatus::ProviderUnknown,
        }
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryEvidence {
    pub operation: String,
    pub attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MiroDecisionEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub projection: MiroDecisionProjection,
    pub status: MiroDecisionResultStatus,
    pub team_id: crate::TeamId,
    pub board_id: crate::BoardId,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub board: Option<MiroBoardMetadata>,
    pub items: Vec<MiroBoardItem>,
    pub pages_observed: u8,
    pub cursor_digests: Vec<Digest>,
    pub warnings: Vec<ProviderErrorEvidence>,
    pub errors: Vec<ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub item_bound_exceeded: bool,
    pub raw_text_retained: bool,
    pub raw_urls_retained: bool,
    pub credential_material_retained: bool,
    pub redacted: bool,
    pub provider_provenance: ProviderProvenance,
    pub digests: EvidenceDigests,
    pub authority: DecisionResultAuthority,
    pub adoption: AdoptionAvailability,
}

impl MiroDecisionEvidence {
    pub fn validate(
        &self,
        scope: &MiroDecisionScope,
    ) -> Result<(), MiroDecisionResultServiceError> {
        if self.schema_version != MIRO_DECISION_RESULT_SCHEMA_VERSION
            || self.contract_version != MIRO_DECISION_RESULT_CONTRACT_VERSION
            || self.contract_digest != Digest::from_text(MIRO_DECISION_RESULT_CONTRACT_JSON)
            || self.provider_version.is_empty()
            || self.status != self.projection.status()
            || self.scope_digest != scope.scope_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.consent_digest != *scope.consent_digest()
            || self.team_id != *scope.team_id()
            || self.board_id != *scope.board_id()
            || self.mission_id != *scope.mission_id()
            || self.mission_revision != scope.mission_revision()
            || self.project_id != *scope.project_id()
            || self.project_revision != scope.project_revision()
            || self.work_product_id != *scope.work_product_id()
            || self.work_product_revision != scope.work_product_revision()
            || self.raw_text_retained
            || self.raw_urls_retained
            || self.credential_material_retained
            || !self.redacted
            || self.authority.connected()
            || self.authority.native_provider()
            || self.authority.first_party()
            || self.authority.durable_receipt()
            || self.authority.independent_read_back()
            || self.authority.verified_adoption()
            || self.authority.adopted_outcome()
            || self.authority.truth_authority()
            || self.adoption != AdoptionAvailability::NotAvailable
            || self.items.len() > crate::model::MAX_ITEMS
        {
            return Err(MiroDecisionResultServiceError::FenceViolation);
        }
        let mut sorted_ids = BTreeSet::new();
        for item in &self.items {
            item.validate_digest()
                .map_err(|_| MiroDecisionResultServiceError::TamperedEvidence)?;
            if !scope.contains_item(&item.id) || !sorted_ids.insert(item.id.clone()) {
                return Err(MiroDecisionResultServiceError::DuplicateItem);
            }
            if !item.kind.is_supported() {
                return Err(MiroDecisionResultServiceError::InvalidProposal);
            }
        }
        if self.board.as_ref().is_some_and(|board| {
            board.team_id != *scope.team_id()
                || board.board_id != *scope.board_id()
                || board.revision != scope.board_revision()
        }) {
            return Err(MiroDecisionResultServiceError::BoardMismatch);
        }
        let expected_item_digest = canonical_item_set_digest(&self.items);
        let expected_redaction_digest = canonical_redaction_digest(&self.items);
        let expected_result_digest = canonical_result_digest(
            scope,
            self.board.as_ref(),
            &self.items,
            &format!("{:?}", self.projection),
        );
        if self.digests.item_set_digest != expected_item_digest
            || self.digests.redaction_digest != expected_redaction_digest
            || self.digests.result_digest != expected_result_digest
            || self.digests.board_digest
                != self.board.as_ref().map(|board| board.board_digest.clone())
        {
            return Err(MiroDecisionResultServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiroDecisionResultProposal {
    pub projection: MiroDecisionProjection,
    pub evidence: MiroDecisionEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl MiroDecisionResultProposal {
    pub fn status(&self) -> MiroDecisionResultStatus {
        self.projection.status()
    }

    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub const fn authority(&self) -> DecisionResultAuthority {
        self.evidence.authority
    }

    pub fn validate(
        &self,
        scope: &MiroDecisionScope,
    ) -> Result<(), MiroDecisionResultServiceError> {
        self.evidence.validate(scope)?;
        if self.provider_definition_digest != self.evidence.provider_digest {
            return Err(MiroDecisionResultServiceError::InvalidProposal);
        }
        let expected = Digest::from_fields(
            "miro-decision-result-proposal/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                self.provider_definition_digest.as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                format!("{:?}", self.projection),
                self.evidence.digests.result_digest.as_str().to_owned(),
            ],
        );
        if expected == self.proposal_digest {
            Ok(())
        } else {
            Err(MiroDecisionResultServiceError::InvalidProposal)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MiroDecisionResultRecording {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
    pub recording_digest: Digest,
    pub status: MiroDecisionResultStatus,
    pub evidence: MiroDecisionEvidence,
    pub recorded: bool,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub independent_read_back: bool,
    pub verified_adoption: bool,
    pub adopted_outcome: bool,
}

impl MiroDecisionResultRecording {
    pub fn validate(
        &self,
        scope: &MiroDecisionScope,
    ) -> Result<(), MiroDecisionResultServiceError> {
        self.evidence.validate(scope)?;
        if self.provider_definition_digest != self.evidence.provider_digest {
            return Err(MiroDecisionResultServiceError::InvalidProposal);
        }
        if !self.recorded
            || self.durable
            || self.native
            || self.connected
            || self.first_party
            || self.independent_read_back
            || self.verified_adoption
            || self.adopted_outcome
            || self.status != self.evidence.status
        {
            return Err(MiroDecisionResultServiceError::InvalidProposal);
        }
        let expected_recording_digest = Digest::from_fields(
            "miro-decision-result-recording/v1",
            &[
                self.proposal_digest.as_str().to_owned(),
                self.evidence.digests.result_digest.as_str().to_owned(),
                "recorded=true".to_owned(),
                "durable=false".to_owned(),
                "native=false".to_owned(),
            ],
        );
        if expected_recording_digest != self.recording_digest {
            return Err(MiroDecisionResultServiceError::InvalidProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiroDecisionResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: crate::ServiceId,
    pub provider_id: crate::ProviderId,
    pub consumer_id: crate::model::ConsumerId,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub sharing_authority: bool,
    pub emits_durable_receipt: bool,
    pub adopts_outcome: bool,
}

impl MiroDecisionResultServiceDefinition {
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            schema_version: MIRO_DECISION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: MIRO_DECISION_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::ServiceId::new(MIRO_DECISION_RESULT_SERVICE_ID)?,
            provider_id: crate::ProviderId::new(MIRO_DECISION_RESULT_PROVIDER_ID)?,
            consumer_id: crate::model::ConsumerId::new(MIRO_DECISION_RESULT_CONSUMER_ID)?,
            contract_digest: Digest::from_text(MIRO_DECISION_RESULT_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            external_writes: false,
            sharing_authority: false,
            emits_durable_receipt: false,
            adopts_outcome: false,
        })
    }
}

impl Default for MiroDecisionResultServiceDefinition {
    fn default() -> Self {
        Self::new().expect("contract identifiers are valid")
    }
}

pub struct MiroDecisionResultService<P> {
    scope: MiroDecisionScope,
    secret_reference: SecretReference,
    provider: P,
    service_definition: MiroDecisionResultServiceDefinition,
    registration: MiroDecisionRegistration,
    retry_policy: RetryPolicy,
}

impl<P: MiroBoardProvider> fmt::Debug for MiroDecisionResultService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiroDecisionResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl<P: MiroBoardProvider> MiroDecisionResultService<P> {
    pub fn new(
        scope: MiroDecisionScope,
        secret_reference: SecretReference,
        provider: P,
        retry_policy: RetryPolicy,
    ) -> Result<Self, MiroDecisionResultServiceError> {
        Self::new_with_registration_revision(scope, secret_reference, provider, retry_policy, 1)
    }

    pub fn new_with_registration_revision(
        scope: MiroDecisionScope,
        secret_reference: SecretReference,
        provider: P,
        retry_policy: RetryPolicy,
        registration_revision: u64,
    ) -> Result<Self, MiroDecisionResultServiceError> {
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(MiroDecisionResultServiceError::ScopeMismatch);
        }
        provider.definition().validate()?;
        let service_definition = MiroDecisionResultServiceDefinition::default();
        let registration = MiroDecisionRegistration::new(
            &scope,
            secret_reference.reference_digest(),
            provider.definition().provider_id.clone(),
            provider.definition().provider_version.clone(),
            provider.definition().provider_digest.clone(),
            service_definition.contract_digest.clone(),
            provider.definition().implementation_digest.clone(),
            Revision::new(registration_revision)?,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition,
            registration,
            retry_policy,
        })
    }

    pub fn service_definition(&self) -> &MiroDecisionResultServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &MiroBoardProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &MiroDecisionRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &MiroDecisionScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, MiroDecisionResultServiceError> {
        self.registration
            .revoke()
            .map_err(MiroDecisionResultServiceError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), MiroDecisionResultServiceError> {
        self.secret_reference
            .revoke()
            .map_err(MiroDecisionResultServiceError::from)
    }

    pub fn read(
        &mut self,
        request: MiroDecisionProposalRequest,
    ) -> Result<MiroDecisionResultProposal, MiroDecisionResultServiceError> {
        self.propose(request)
    }

    pub fn propose(
        &mut self,
        request: MiroDecisionProposalRequest,
    ) -> Result<MiroDecisionResultProposal, MiroDecisionResultServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| MiroDecisionResultServiceError::RegistrationRevoked)?;
        if self.secret_reference.is_revoked() {
            return Err(MiroDecisionResultServiceError::SecretRevoked);
        }
        if self.secret_reference.scope_digest() != &self.scope.scope_digest() {
            return Err(MiroDecisionResultServiceError::ScopeMismatch);
        }
        let mut retries = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut items = Vec::new();
        let mut seen_items = BTreeSet::new();
        let mut seen_cursors = BTreeSet::new();
        let mut cursor_digests = Vec::new();
        let mut board: Option<MiroBoardMetadata> = None;
        let mut pages_observed = 0_u8;
        let mut item_bound_exceeded = false;
        let mut projection = MiroDecisionProjection::Complete;
        let mut page_number = 1_u8;
        let mut cursor = None;

        loop {
            let page_request = MiroBoardReadRequest::new(
                &self.scope,
                &self.secret_reference,
                request.bounds,
                page_number,
                cursor.clone(),
            )?;
            let page = match self.read_page_with_retry(&page_request, &mut retries, &mut errors) {
                Ok(page) => page,
                Err(error) => {
                    projection = projection_for_error(error.kind);
                    break;
                }
            };
            self.validate_page(&page)?;
            pages_observed = pages_observed.saturating_add(1);
            if let Some(previous) = &board {
                if previous.board_digest != page.board.board_digest {
                    return Err(MiroDecisionResultServiceError::FenceViolation);
                }
            } else {
                board = Some(page.board.clone());
            }

            let mut page_items = page.items.clone();
            page_items.sort_by(|left, right| left.id.cmp(&right.id));
            for item in page_items {
                if !self.scope.contains_item(&item.id) {
                    return Err(MiroDecisionResultServiceError::ItemOutsideAllowlist);
                }
                if !seen_items.insert(item.id.clone()) {
                    return Err(MiroDecisionResultServiceError::DuplicateItem);
                }
                if !item.kind.is_supported() {
                    projection = MiroDecisionProjection::Unsupported;
                    continue;
                }
                if items.len() >= usize::from(request.bounds.max_items()) {
                    item_bound_exceeded = true;
                    projection = MiroDecisionProjection::Partial(PartialReason::ItemCap);
                    break;
                }
                items.push(item);
            }

            if projection == MiroDecisionProjection::Unsupported || item_bound_exceeded {
                break;
            }

            let next_cursor = page.next_cursor().cloned();
            if let Some(next_cursor) = next_cursor {
                let next_digest = next_cursor.digest();
                if !seen_cursors.insert(next_digest.clone()) {
                    return Err(MiroDecisionResultServiceError::PageLoop);
                }
                cursor_digests.push(next_digest);
                if pages_observed >= request.bounds.max_pages() {
                    projection = MiroDecisionProjection::Partial(PartialReason::PageCap);
                    break;
                }
                page_number = page_number.saturating_add(1);
                cursor = Some(next_cursor);
            } else {
                break;
            }
        }

        if projection.is_complete() && items.is_empty() {
            projection = MiroDecisionProjection::Empty;
        }
        if matches!(projection, MiroDecisionProjection::Partial(_)) && errors.is_empty() {
            warnings.push(ProviderErrorEvidence::new(
                ProviderErrorKind::Partial,
                None,
                false,
                false,
                "bounded-layer-one-partial",
            ));
        }
        items.sort_by(|left, right| left.id.cmp(&right.id));
        let evidence = self.finish_evidence(
            projection,
            board,
            items,
            pages_observed,
            cursor_digests,
            warnings,
            errors,
            retries,
            item_bound_exceeded,
        );
        let provider_definition_digest = self.provider.definition().provider_digest.clone();
        let proposal_digest = Digest::from_fields(
            "miro-decision-result-proposal/v1",
            &[
                self.registration.registration_digest().as_str().to_owned(),
                self.registration.revision().get().to_string(),
                provider_definition_digest.as_str().to_owned(),
                self.scope.scope_digest().as_str().to_owned(),
                format!("{projection:?}"),
                evidence.digests.result_digest.as_str().to_owned(),
            ],
        );
        Ok(MiroDecisionResultProposal {
            projection,
            evidence,
            registration_digest: self.registration.registration_digest().clone(),
            registration_revision: self.registration.revision(),
            provider_definition_digest,
            proposal_digest,
        })
    }

    pub fn record(
        &self,
        proposal: &MiroDecisionResultProposal,
    ) -> Result<MiroDecisionResultRecording, MiroDecisionResultServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| MiroDecisionResultServiceError::RegistrationRevoked)?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.registration_revision != self.registration.revision()
            || proposal.provider_definition_digest != self.provider.definition().provider_digest
        {
            return Err(MiroDecisionResultServiceError::InvalidProposal);
        }
        proposal.validate(&self.scope)?;
        let expected_proposal_digest = Digest::from_fields(
            "miro-decision-result-proposal/v1",
            &[
                proposal.registration_digest.as_str().to_owned(),
                proposal.registration_revision.get().to_string(),
                proposal.provider_definition_digest.as_str().to_owned(),
                self.scope.scope_digest().as_str().to_owned(),
                format!("{:?}", proposal.projection),
                proposal.evidence.digests.result_digest.as_str().to_owned(),
            ],
        );
        if expected_proposal_digest != proposal.proposal_digest {
            return Err(MiroDecisionResultServiceError::InvalidProposal);
        }
        let recording_digest = Digest::from_fields(
            "miro-decision-result-recording/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                proposal.evidence.digests.result_digest.as_str().to_owned(),
                "recorded=true".to_owned(),
                "durable=false".to_owned(),
                "native=false".to_owned(),
            ],
        );
        Ok(MiroDecisionResultRecording {
            registration_digest: proposal.registration_digest.clone(),
            registration_revision: proposal.registration_revision,
            provider_definition_digest: proposal.provider_definition_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            recording_digest,
            status: proposal.status(),
            evidence: proposal.evidence.clone(),
            recorded: true,
            durable: false,
            native: false,
            connected: false,
            first_party: false,
            independent_read_back: false,
            verified_adoption: false,
            adopted_outcome: false,
        })
    }

    pub fn record_proposal(
        &self,
        proposal: &MiroDecisionResultProposal,
    ) -> Result<MiroDecisionResultRecording, MiroDecisionResultServiceError> {
        self.record(proposal)
    }

    fn read_page_with_retry(
        &mut self,
        request: &MiroBoardReadRequest,
        retries: &mut Vec<RetryEvidence>,
        errors: &mut Vec<ProviderErrorEvidence>,
    ) -> Result<MiroBoardPage, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.provider.read(request) {
                Ok(page) => return Ok(page),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    retries.push(RetryEvidence {
                        operation: "GET /v2/boards/{board_id}/items".to_owned(),
                        attempt,
                        kind: error.kind,
                        status_code: error.status_code,
                        error_digest: error.diagnostic_digest().clone(),
                    });
                }
                Err(error) => {
                    errors.push(error.evidence());
                    return Err(error);
                }
            }
        }
        unreachable!("retry loop always returns")
    }

    fn validate_page(&self, page: &MiroBoardPage) -> Result<(), MiroDecisionResultServiceError> {
        page.validate_digest()
            .map_err(|_| MiroDecisionResultServiceError::TamperedEvidence)?;
        let fence = self.scope.fence();
        if page.observed_scope_digest != fence.scope_digest
            || page.observed_permission_digest != fence.permission_digest
            || page.observed_consent_digest != fence.consent_digest
            || page.observed_mission_revision != fence.mission_revision
            || page.observed_project_revision != fence.project_revision
            || page.observed_work_product_revision != fence.work_product_revision
            || page.observed_board_revision != fence.board_revision
            || page.observed_credential_revision != self.secret_reference.credential_revision()
        {
            return Err(MiroDecisionResultServiceError::FenceViolation);
        }
        if page.board.team_id != *self.scope.team_id()
            || page.board.board_id != *self.scope.board_id()
            || page.board.revision != self.scope.board_revision()
        {
            return Err(MiroDecisionResultServiceError::BoardMismatch);
        }
        if page.items.len() > crate::model::MAX_PROVIDER_PAGE_ITEMS {
            return Err(MiroDecisionResultServiceError::InvalidResponseShape);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_evidence(
        &self,
        projection: MiroDecisionProjection,
        board: Option<MiroBoardMetadata>,
        items: Vec<MiroBoardItem>,
        pages_observed: u8,
        cursor_digests: Vec<Digest>,
        warnings: Vec<ProviderErrorEvidence>,
        errors: Vec<ProviderErrorEvidence>,
        retries: Vec<RetryEvidence>,
        item_bound_exceeded: bool,
    ) -> MiroDecisionEvidence {
        let item_set_digest = canonical_item_set_digest(&items);
        let redaction_digest = canonical_redaction_digest(&items);
        let result_digest = canonical_result_digest(
            &self.scope,
            board.as_ref(),
            &items,
            &format!("{projection:?}"),
        );
        MiroDecisionEvidence {
            schema_version: MIRO_DECISION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: MIRO_DECISION_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_text(MIRO_DECISION_RESULT_CONTRACT_JSON),
            provider_version: self.provider.definition().provider_version.clone(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            status: projection.status(),
            projection,
            team_id: self.scope.team_id().clone(),
            board_id: self.scope.board_id().clone(),
            mission_id: self.scope.mission_id().clone(),
            mission_revision: self.scope.mission_revision(),
            project_id: self.scope.project_id().clone(),
            project_revision: self.scope.project_revision(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            consent_digest: self.scope.consent_digest().clone(),
            board: board.clone(),
            items: items.clone(),
            pages_observed,
            cursor_digests,
            warnings,
            errors,
            retries,
            item_bound_exceeded,
            raw_text_retained: false,
            raw_urls_retained: false,
            credential_material_retained: false,
            redacted: true,
            provider_provenance: self.provider.provenance(),
            digests: EvidenceDigests::new(
                board.map(|value| value.board_digest),
                item_set_digest,
                redaction_digest,
                result_digest,
            ),
            authority: DecisionResultAuthority,
            adoption: AdoptionAvailability::NotAvailable,
        }
    }
}

fn projection_for_error(kind: ProviderErrorKind) -> MiroDecisionProjection {
    match kind {
        ProviderErrorKind::UnsupportedItem => MiroDecisionProjection::Unsupported,
        ProviderErrorKind::Deleted => MiroDecisionProjection::Deleted,
        ProviderErrorKind::AccessLost => MiroDecisionProjection::AccessLost,
        ProviderErrorKind::Empty => MiroDecisionProjection::Empty,
        ProviderErrorKind::Partial => {
            MiroDecisionProjection::Partial(PartialReason::ProviderPartial)
        }
        ProviderErrorKind::RateLimited => MiroDecisionProjection::RateLimited,
        ProviderErrorKind::ServerFailure => MiroDecisionProjection::ServerFailure,
        ProviderErrorKind::Timeout => MiroDecisionProjection::Timeout,
        ProviderErrorKind::BlockedEnv => MiroDecisionProjection::BlockedEnv,
        ProviderErrorKind::ScopeDrift => MiroDecisionProjection::ScopeDrift,
        ProviderErrorKind::InvalidResponse => MiroDecisionProjection::ProviderUnknown,
    }
}

pub type MiroDecisionOutcomeService<P> = MiroDecisionResultService<P>;

#[allow(dead_code)]
const _: Option<ItemId> = None;
