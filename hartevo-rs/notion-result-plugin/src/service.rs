use crate::error::NotionResultError;
use crate::model::{
    Digest, MissionWorkProduct, NativeStatus, NotionDescribeRequest, NotionPageReceipt,
    NotionPublishDestination, NotionPublishProposal, NotionReadRequest, NotionReadback,
    NotionReadbackField, NotionScopeDescription, NotionVerifiedReadback, canonical_digest,
};
use crate::provider::NotionResultProvider;

/// Typed Layer 1 service over a replaceable provider.  Construction binds the
/// provider manifest digest and every later method revalidates it.
#[derive(Debug)]
pub struct NotionResultService<P> {
    provider: P,
    bound_manifest_digest: Digest,
}

impl<P> NotionResultService<P>
where
    P: NotionResultProvider,
{
    pub fn new(provider: P) -> Result<Self, NotionResultError> {
        let manifest = provider.manifest();
        manifest.validate()?;
        if provider.external_write_available() || manifest.native_status != NativeStatus::BlockedEnv
        {
            return Err(NotionResultError::ExternalWriteAuthority);
        }
        Ok(Self {
            bound_manifest_digest: manifest.digest(),
            provider,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_manifest(
        &self,
    ) -> Result<crate::model::NotionProviderManifest, NotionResultError> {
        self.ensure_provider().map(|(manifest, _)| manifest)
    }

    pub fn describe(
        &self,
        request: &NotionDescribeRequest,
    ) -> Result<NotionScopeDescription, NotionResultError> {
        let (manifest, _) = self.ensure_provider()?;
        request.scope.validate()?;
        if request.scope != manifest.scope {
            return Err(NotionResultError::ScopeMismatch);
        }
        let description = self.provider.describe(request)?;
        if description.provider_manifest_digest != manifest.digest() {
            return Err(NotionResultError::ProviderManifestDrift {
                expected: manifest.digest(),
                actual: description.provider_manifest_digest,
            });
        }
        Ok(description)
    }

    pub fn read(&self, request: &NotionReadRequest) -> Result<NotionReadback, NotionResultError> {
        let (manifest, _) = self.ensure_provider()?;
        request.scope.validate()?;
        if request.scope != manifest.scope {
            return Err(NotionResultError::ScopeMismatch);
        }
        let readback = self.provider.read(request)?;
        if readback.provider_manifest_digest != manifest.digest() {
            return Err(NotionResultError::ProviderManifestDrift {
                expected: manifest.digest(),
                actual: readback.provider_manifest_digest,
            });
        }
        readback.validate()?;
        Ok(readback)
    }

    /// Compile, but do not execute, a scope/consent-bound proposal.
    pub fn compile_publish_proposal(
        &self,
        work_product: MissionWorkProduct,
        destination: NotionPublishDestination,
    ) -> Result<NotionPublishProposal, NotionResultError> {
        let (manifest, _) = self.ensure_provider()?;
        if destination.scope != manifest.scope {
            return Err(NotionResultError::ScopeMismatch);
        }
        NotionPublishProposal::new(&manifest, work_product, destination)
    }

    /// Record the proposal through the provider's deterministic recording seam.
    /// This method cannot perform a native Notion create/update/append.
    pub fn record_proposal(
        &self,
        proposal: &NotionPublishProposal,
    ) -> Result<NotionPageReceipt, NotionResultError> {
        let (manifest, _) = self.ensure_provider()?;
        proposal.validate()?;
        if proposal.provider_manifest_digest != manifest.digest() {
            return Err(NotionResultError::ProposalManifestMismatch);
        }
        let receipt = self.provider.record_proposal(proposal)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Verify all externally observable identifiers that a future native
    /// receipt/read-back must expose.  Raw page content is never required.
    pub fn verify_readback(
        &self,
        proposal: &NotionPublishProposal,
        receipt: &NotionPageReceipt,
        readback: &NotionReadback,
    ) -> Result<NotionVerifiedReadback, NotionResultError> {
        let (manifest, _) = self.ensure_provider()?;
        proposal.validate()?;
        receipt.validate()?;
        readback.validate()?;
        if proposal.provider_manifest_digest != manifest.digest() {
            return Err(NotionResultError::ProposalManifestMismatch);
        }
        compare(
            NotionReadbackField::ProposalDigest,
            &proposal.proposal_digest,
            &receipt.proposal_digest,
        )?;
        compare(
            NotionReadbackField::ProposalDigest,
            &receipt.proposal_digest,
            &readback.proposal_digest,
        )?;
        compare(
            NotionReadbackField::PageId,
            &receipt.page_id.to_string(),
            &readback.page_id.to_string(),
        )?;
        compare(
            NotionReadbackField::PageUrl,
            receipt.page_url.as_str(),
            readback.page_url.as_str(),
        )?;
        compare(
            NotionReadbackField::Parent,
            &canonical_digest(&receipt.parent),
            &canonical_digest(&readback.parent),
        )?;
        compare(
            NotionReadbackField::Revision,
            receipt.revision.as_str(),
            readback.revision.as_str(),
        )?;
        compare(
            NotionReadbackField::ContentFingerprint,
            &proposal.content_fingerprint,
            &readback.content_fingerprint,
        )?;
        compare(
            NotionReadbackField::ContentFingerprint,
            &receipt.content_fingerprint,
            &readback.content_fingerprint,
        )?;
        compare(
            NotionReadbackField::IdempotencyKey,
            &proposal.idempotency_key,
            &readback.idempotency_key,
        )?;
        compare(
            NotionReadbackField::ProviderManifestDigest,
            &manifest.digest(),
            &readback.provider_manifest_digest,
        )?;
        Ok(NotionVerifiedReadback {
            page_id: readback.page_id.clone(),
            page_url: readback.page_url.clone(),
            parent: readback.parent.clone(),
            revision: readback.revision.clone(),
            content_fingerprint: readback.content_fingerprint.clone(),
            proposal_digest: readback.proposal_digest.clone(),
            idempotency_key: readback.idempotency_key.clone(),
            evidence: readback.evidence,
            native_status: readback.native_status,
            verified: true,
        })
    }

    fn ensure_provider(
        &self,
    ) -> Result<(crate::model::NotionProviderManifest, Digest), NotionResultError> {
        let manifest = self.provider.manifest();
        manifest.validate()?;
        if self.provider.external_write_available()
            || manifest.native_status != NativeStatus::BlockedEnv
        {
            return Err(NotionResultError::ExternalWriteAuthority);
        }
        let actual = manifest.digest();
        if actual != self.bound_manifest_digest {
            return Err(NotionResultError::ProviderManifestDrift {
                expected: self.bound_manifest_digest.clone(),
                actual,
            });
        }
        Ok((manifest, self.bound_manifest_digest.clone()))
    }
}

fn compare(
    field: NotionReadbackField,
    expected: &str,
    actual: &str,
) -> Result<(), NotionResultError> {
    if expected == actual {
        Ok(())
    } else {
        Err(NotionResultError::ReadbackMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}
