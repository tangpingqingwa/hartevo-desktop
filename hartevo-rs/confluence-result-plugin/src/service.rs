use serde::{Deserialize, Serialize};

use crate::error::{ConfluenceKnowledgeResultError, ConfluenceProviderError};
use crate::model::{
    ConfluenceCapability, ConfluencePageReadRequest, ConfluenceScopeDescription,
    ConfluenceSearchRequest, Digest, KnowledgeEvidence, KnowledgeProposalStatus,
    KnowledgeReadbackField, KnowledgeResultProposal, KnowledgeResultReceipt,
    KnowledgeSearchEvidence, MissionWorkProduct, PageEvidence, ProviderProvenance,
    VerifiedKnowledgeResult, canonical_digest, digest_parts,
};
use crate::provider::{ConfluenceCloudProvider, ConfluenceCredentialResolver};
use crate::transport::ConfluenceTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfluenceKnowledgeResultOperation {
    DescribeContentScope,
    ReadPageEvidence,
    SearchKnowledge,
    CompileKnowledgeProposal,
    RecordKnowledgeReceipt,
    VerifyKnowledgeResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConfluenceKnowledgeResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: u64,
    pub operations: Vec<ConfluenceKnowledgeResultOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub durable_native_receipts: bool,
    pub independent_readback: bool,
    pub kernel_outcome_authority: bool,
}

impl ConfluenceKnowledgeResultServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: crate::CONFLUENCE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::CONFLUENCE_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::CONFLUENCE_SERVICE_ID.to_owned(),
            provider_id: crate::CONFLUENCE_PROVIDER_ID.to_owned(),
            consumer_id: crate::CONFLUENCE_MISSION_CONSUMER_ID.to_owned(),
            plugin_id: crate::CONFLUENCE_PLUGIN_ID.to_owned(),
            plugin_version: crate::CONFLUENCE_PLUGIN_VERSION,
            operations: vec![
                ConfluenceKnowledgeResultOperation::DescribeContentScope,
                ConfluenceKnowledgeResultOperation::ReadPageEvidence,
                ConfluenceKnowledgeResultOperation::SearchKnowledge,
                ConfluenceKnowledgeResultOperation::CompileKnowledgeProposal,
                ConfluenceKnowledgeResultOperation::RecordKnowledgeReceipt,
                ConfluenceKnowledgeResultOperation::VerifyKnowledgeResult,
            ],
            read_only: true,
            external_writes: false,
            durable_native_receipts: false,
            independent_readback: false,
            kernel_outcome_authority: false,
        }
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        if self.schema_version != crate::CONFLUENCE_RESULT_SCHEMA_VERSION
            || self.contract_version != crate::CONFLUENCE_RESULT_CONTRACT_VERSION
            || self.service_id != crate::CONFLUENCE_SERVICE_ID
            || self.provider_id != crate::CONFLUENCE_PROVIDER_ID
            || self.consumer_id != crate::CONFLUENCE_MISSION_CONSUMER_ID
            || self.plugin_id != crate::CONFLUENCE_PLUGIN_ID
            || self.plugin_version != crate::CONFLUENCE_PLUGIN_VERSION
            || self.operations.len() != 6
            || !self.read_only
            || self.external_writes
            || self.durable_native_receipts
            || self.independent_readback
            || self.kernel_outcome_authority
        {
            return Err(ConfluenceKnowledgeResultError::ExternalWriteAuthority);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Typed Layer 1 service over a bounded, replaceable Confluence provider.
/// Construction binds the provider registration and never grants kernel
/// Consent/Effect/Receipt/Verification/Outcome authority.
pub struct ConfluenceKnowledgeResultService<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    provider: ConfluenceCloudProvider<T, R>,
    definition: ConfluenceKnowledgeResultServiceDefinition,
    bound_registration_digest: Digest,
}

impl<T, R> std::fmt::Debug for ConfluenceKnowledgeResultService<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfluenceKnowledgeResultService")
            .field("registration_digest", &self.bound_registration_digest)
            .field("definition_digest", &self.definition.digest())
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T, R> ConfluenceKnowledgeResultService<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    pub fn new(
        provider: ConfluenceCloudProvider<T, R>,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        let definition = ConfluenceKnowledgeResultServiceDefinition::layer1();
        definition.validate()?;
        provider
            .provider_manifest()
            .validate(&provider.registration().scope)?;
        Ok(Self {
            bound_registration_digest: provider.registration().registration_digest.clone(),
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &ConfluenceKnowledgeResultServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &ConfluenceCloudProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut ConfluenceCloudProvider<T, R> {
        &mut self.provider
    }

    pub fn describe_content_scope(
        &mut self,
    ) -> Result<ConfluenceScopeDescription, ConfluenceKnowledgeResultError> {
        self.ensure_binding()?;
        self.provider.describe_content_scope()
    }

    pub fn read_page_evidence(
        &mut self,
        request: &ConfluencePageReadRequest,
    ) -> Result<PageEvidence, ConfluenceKnowledgeResultError> {
        self.ensure_binding()?;
        if !request
            .scope
            .permits(ConfluenceCapability::ReadPageEvidence)
        {
            return Err(ConfluenceKnowledgeResultError::ConsentRequired {
                capability: ConfluenceCapability::ReadPageEvidence,
            });
        }
        self.provider.read_page_evidence(request)
    }

    pub fn search_knowledge(
        &mut self,
        request: &ConfluenceSearchRequest,
    ) -> Result<crate::model::KnowledgeSearchEvidence, ConfluenceKnowledgeResultError> {
        self.ensure_binding()?;
        if !request.scope.permits(ConfluenceCapability::SearchKnowledge) {
            return Err(ConfluenceKnowledgeResultError::ConsentRequired {
                capability: ConfluenceCapability::SearchKnowledge,
            });
        }
        self.provider.search_knowledge(request)
    }

    /// Compile a redacted, revision-fenced proposal. No page mutation or
    /// durable native adoption occurs here.
    pub fn compile_knowledge_proposal(
        &self,
        work_product: MissionWorkProduct,
        evidence: KnowledgeEvidence,
    ) -> Result<KnowledgeResultProposal, ConfluenceKnowledgeResultError> {
        self.ensure_binding_ref()?;
        if !self
            .provider
            .registration()
            .scope
            .permits(ConfluenceCapability::CompileKnowledgeProposal)
        {
            return Err(ConfluenceKnowledgeResultError::ConsentRequired {
                capability: ConfluenceCapability::CompileKnowledgeProposal,
            });
        }
        evidence.validate()?;
        work_product.validate()?;
        let scope = &self.provider.registration().scope;
        if evidence.page.scope.digest() != scope.digest()
            || work_product.project_id != scope.project_id
            || work_product.mission_id != scope.mission_id
            || work_product.work_product_id != scope.work_product_id
            || work_product.revision != scope.work_product_revision
        {
            return Err(ConfluenceKnowledgeResultError::ScopeMismatch);
        }
        if evidence.search.as_ref().is_some_and(|search| search.empty) {
            return Err(ConfluenceKnowledgeResultError::EmptyEvidence);
        }
        let search_digest = evidence
            .search
            .as_ref()
            .map(|search| search.search_digest.clone());
        let content_digest = digest_parts([
            work_product.content_digest.as_str(),
            evidence.page.body.value_digest.as_str(),
            evidence.page.metadata.metadata_digest.as_str(),
            search_digest.as_deref().unwrap_or("empty-search"),
        ]);
        let mut proposal = KnowledgeResultProposal {
            proposal_id: String::new(),
            proposal_digest: String::new(),
            scope: scope.clone(),
            work_product,
            evidence_digest: evidence.digest(),
            page_evidence_digest: evidence.page.evidence_digest.clone(),
            search_evidence_digest: search_digest,
            content_digest,
            page_version: evidence.page.version.clone(),
            permission_digest: evidence.page.permission_digest.clone(),
            provider_manifest_digest: self.provider.provider_manifest().digest(),
            registration_digest: self.provider.registration().registration_digest.clone(),
            evidence_source: evidence.page.evidence_source,
            status: KnowledgeProposalStatus::Proposed,
            non_mutating: true,
            external_write_performed: false,
            durable_native_receipt: false,
            native_connected: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.proposal_id = format!("confluence-knowledge-{}", &proposal.proposal_digest[..24]);
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn record_knowledge_receipt(
        &mut self,
        proposal: &KnowledgeResultProposal,
    ) -> Result<KnowledgeResultReceipt, ConfluenceKnowledgeResultError> {
        self.ensure_binding()?;
        if !self
            .provider
            .registration()
            .scope
            .permits(ConfluenceCapability::RecordKnowledgeReceipt)
        {
            return Err(ConfluenceKnowledgeResultError::ConsentRequired {
                capability: ConfluenceCapability::RecordKnowledgeReceipt,
            });
        }
        self.provider.record_knowledge_receipt(proposal)
    }

    pub fn verify_knowledge_result(
        &mut self,
        proposal: &KnowledgeResultProposal,
        receipt: &KnowledgeResultReceipt,
    ) -> Result<VerifiedKnowledgeResult, ConfluenceKnowledgeResultError> {
        self.ensure_binding()?;
        if !self
            .provider
            .registration()
            .scope
            .permits(ConfluenceCapability::VerifyKnowledgeResult)
        {
            return Err(ConfluenceKnowledgeResultError::ConsentRequired {
                capability: ConfluenceCapability::VerifyKnowledgeResult,
            });
        }
        proposal.validate()?;
        receipt.validate()?;
        if receipt.evidence_source != ProviderProvenance::Recording {
            return Err(ConfluenceKnowledgeResultError::InvalidReadback);
        }
        compare(
            KnowledgeReadbackField::ProposalDigest,
            &proposal.proposal_digest,
            &receipt.proposal_digest,
        )?;
        compare(
            KnowledgeReadbackField::ScopeDigest,
            &proposal.scope.digest(),
            &receipt.scope_digest,
        )?;
        compare(
            KnowledgeReadbackField::ProviderManifestDigest,
            &proposal.provider_manifest_digest,
            &receipt.provider_manifest_digest,
        )?;
        compare(
            KnowledgeReadbackField::RegistrationDigest,
            &proposal.registration_digest,
            &receipt.registration_digest,
        )?;
        if receipt.registration_digest != self.provider.registration().registration_digest {
            return Err(ConfluenceProviderError::RegistrationDigestMismatch.into());
        }
        Ok(VerifiedKnowledgeResult {
            proposal_digest: proposal.proposal_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            scope_digest: receipt.scope_digest.clone(),
            provider_manifest_digest: receipt.provider_manifest_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verified: true,
            adopted: false,
            native_connected: false,
        })
    }

    fn ensure_binding(&mut self) -> Result<(), ConfluenceKnowledgeResultError> {
        self.ensure_binding_ref()
    }

    fn ensure_binding_ref(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        if self.provider.registration().registration_digest != self.bound_registration_digest {
            return Err(ConfluenceKnowledgeResultError::ProviderManifestDrift);
        }
        if !self.provider.registration().active {
            return Err(ConfluenceKnowledgeResultError::Provider(
                ConfluenceProviderError::RegistrationRevoked,
            ));
        }
        self.provider
            .provider_manifest()
            .validate(&self.provider.registration().scope)
            .map_err(|_| ConfluenceKnowledgeResultError::ProviderManifestDrift)
    }
}

fn compare(
    field: KnowledgeReadbackField,
    expected: &str,
    actual: &str,
) -> Result<(), ConfluenceKnowledgeResultError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ConfluenceKnowledgeResultError::ReadbackMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

#[allow(dead_code)]
fn _service_markers(
    _definition: &ConfluenceKnowledgeResultServiceDefinition,
    _search: Option<&KnowledgeSearchEvidence>,
) {
    let _ = canonical_digest(&0_u8);
}
