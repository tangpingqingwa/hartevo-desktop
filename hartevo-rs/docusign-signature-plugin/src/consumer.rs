use std::collections::BTreeSet;

use thiserror::Error;

use crate::{
    Digest, DocuSignReceipt, DocuSignScope, EnvelopeStatus, MissionId, ModelError, ProviderVersion,
    RevisionFence, SignedResultAdoptionProposal, SignedResultSource,
};

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConsumerError {
    #[error("DocuSign receipt integrity or redaction validation failed")]
    TamperedReceipt,
    #[error("DocuSign receipt scope does not match the exact Project/Mission consumer scope")]
    ScopeMismatch,
    #[error("DocuSign receipt provider version or registration digest does not match")]
    RegistrationMismatch,
    #[error("DocuSign receipt revision fence is stale")]
    StaleRevision,
    #[error("DocuSign receipt does not identify the exact Mission source")]
    MissionMismatch,
    #[error("DocuSign receipt source result or file digest does not match")]
    SourceDigestMismatch,
    #[error("DocuSign receipt recipient set does not match the signed-result source")]
    RecipientSetMismatch,
    #[error("only a completed envelope may produce a signed-result adoption proposal")]
    NotCompleted,
    #[error("completed envelope lacks verified completion evidence")]
    CompletionNotVerified,
    #[error("DocuSign consumer model rejected the source: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug)]
pub struct MissionSignedResultConsumer {
    scope: DocuSignScope,
    current_revision: RevisionFence,
    provider_version: ProviderVersion,
    registration_digest: Digest,
}

impl MissionSignedResultConsumer {
    pub fn new(
        scope: DocuSignScope,
        current_revision: RevisionFence,
        provider_version: ProviderVersion,
        registration_digest: Digest,
    ) -> Result<Self, ConsumerError> {
        scope.validate()?;
        provider_version.validate()?;
        if !registration_digest.is_valid() {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            current_revision,
            provider_version,
            registration_digest,
        })
    }

    pub fn scope(&self) -> &DocuSignScope {
        &self.scope
    }

    pub const fn current_revision(&self) -> RevisionFence {
        self.current_revision
    }

    pub const fn provider_version(&self) -> ProviderVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn propose_adoption(
        &self,
        receipt: &DocuSignReceipt,
        source: &SignedResultSource,
    ) -> Result<SignedResultAdoptionProposal, ConsumerError> {
        receipt
            .validate_integrity()
            .map_err(|_| ConsumerError::TamperedReceipt)?;
        if receipt.scope_digest() != &self.scope.digest()
            || receipt.tenant_id() != self.scope.tenant_id()
            || receipt.project_id() != self.scope.project_id()
            || receipt.mission_id() != self.scope.mission_id()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if receipt.provider_version() != self.provider_version
            || receipt.registration_digest() != &self.registration_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if receipt.revision_fence() != self.current_revision
            || source.revision_fence() != self.current_revision
        {
            return Err(ConsumerError::StaleRevision);
        }
        if source.project_id() != self.scope.project_id()
            || source.mission_id() != self.scope.mission_id()
        {
            return Err(ConsumerError::MissionMismatch);
        }
        if source.source_result_digest() != receipt.source_result_digest()
            || source.source_file_digest() != receipt.source_file_digest()
        {
            return Err(ConsumerError::SourceDigestMismatch);
        }
        let receipt_recipients = receipt
            .recipient_statuses()
            .iter()
            .map(|status| status.recipient_id().clone())
            .collect::<BTreeSet<_>>();
        let source_recipients = source
            .recipient_ids()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if receipt_recipients != source_recipients {
            return Err(ConsumerError::RecipientSetMismatch);
        }
        if !receipt.status().is_completed() {
            return Err(ConsumerError::NotCompleted);
        }
        if !receipt.is_verified_completed() {
            return Err(ConsumerError::CompletionNotVerified);
        }
        Ok(SignedResultAdoptionProposal::from_receipt(receipt, source))
    }

    pub fn accepts_status(&self, status: EnvelopeStatus) -> bool {
        status.is_completed()
    }

    pub fn mission_id(&self) -> &MissionId {
        self.scope.mission_id()
    }
}
