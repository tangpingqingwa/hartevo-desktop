use std::fmt;

use crate::error::{
    ConfluenceCredentialError, ConfluenceKnowledgeResultError, ConfluenceProviderError,
};
use crate::model::{
    ConfluenceContentId, ConfluencePageId, ConfluencePageReadRequest, ConfluencePluginRegistration,
    ConfluenceProviderManifest, ConfluenceScope, ConfluenceScopeDescription,
    ConfluenceSearchCursor, ConfluenceSearchRequest, Digest, KnowledgeResultProposal,
    KnowledgeResultReceipt, KnowledgeSearchEvidence, KnowledgeSearchHit, LabelDigest, PageEvidence,
    PageLink, PageMetadata, PageState, PageVersion, ProviderProvenance, RegistrationRevocation,
    SelectedBody, canonical_digest, digest_parts, sha256_digest,
};
use crate::transport::{
    ConfluenceTransport, ConfluenceTransportOperation, FixturePage, RawPageResponse, RawSearchHit,
};

/// Secret material exists only at the provider-to-transport call boundary.
/// Debug intentionally exposes only its byte length.
#[derive(Clone)]
pub struct SecretMaterial(String);

impl SecretMaterial {
    pub(crate) fn new(value: String) -> Result<Self, ConfluenceCredentialError> {
        if value.trim().is_empty() || value.len() > 4096 {
            return Err(ConfluenceCredentialError::Unauthorized);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("byte_length", &self.0.len())
            .finish()
    }
}

pub trait ConfluenceCredentialResolver: fmt::Debug + Send {
    fn resolve(
        &self,
        reference: &crate::model::SecretReference,
    ) -> Result<SecretMaterial, ConfluenceCredentialError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl ConfluenceCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &crate::model::SecretReference,
    ) -> Result<SecretMaterial, ConfluenceCredentialError> {
        Err(ConfluenceCredentialError::BlockedEnv)
    }
}

#[derive(Clone)]
pub struct StaticConfluenceCredentialResolver {
    token: String,
}

impl StaticConfluenceCredentialResolver {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl fmt::Debug for StaticConfluenceCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticConfluenceCredentialResolver")
            .field("token_byte_length", &self.token.len())
            .finish()
    }
}

impl ConfluenceCredentialResolver for StaticConfluenceCredentialResolver {
    fn resolve(
        &self,
        _reference: &crate::model::SecretReference,
    ) -> Result<SecretMaterial, ConfluenceCredentialError> {
        SecretMaterial::new(self.token.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfluenceProviderState {
    Ready,
    BlockedEnv,
    Revoked,
    AccessLost,
    VersionDrift,
    PermissionDrift,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfluenceProviderCall {
    DescribeContentScope {
        scope_digest: Digest,
    },
    ReadPageEvidence {
        scope_digest: Digest,
        page_digest: Digest,
        version_digest: Digest,
    },
    SearchKnowledge {
        scope_digest: Digest,
        cql_digest: Digest,
        page: u32,
        cursor_digest: Option<Digest>,
    },
    RecordKnowledgeReceipt {
        proposal_digest: Digest,
        scope_digest: Digest,
    },
}

/// Provider boundary for bounded Confluence evidence. The generic transport
/// is intentionally limited to non-native seams in this Layer 1 crate.
pub struct ConfluenceCloudProvider<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    registration: ConfluencePluginRegistration,
    manifest: ConfluenceProviderManifest,
    transport: T,
    credentials: R,
    state: ConfluenceProviderState,
    calls: Vec<ConfluenceProviderCall>,
}

impl<T, R> fmt::Debug for ConfluenceCloudProvider<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfluenceCloudProvider")
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("manifest_digest", &self.manifest.manifest_digest)
            .field("provenance", &self.provenance())
            .field("state", &self.state)
            .field("calls_count", &self.calls.len())
            .field("transport", &self.transport)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl<T, R> ConfluenceCloudProvider<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    pub fn new(
        registration: ConfluencePluginRegistration,
        transport: T,
        credentials: R,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        registration.validate()?;
        let manifest = ConfluenceProviderManifest::new(&registration.scope);
        if manifest.digest() != registration.provider_manifest_digest
            || transport.provenance().is_native()
            || transport.provenance().is_connected()
        {
            return Err(ConfluenceKnowledgeResultError::ExternalWriteAuthority);
        }
        Ok(Self {
            registration,
            manifest,
            transport,
            credentials,
            state: ConfluenceProviderState::Ready,
            calls: Vec::new(),
        })
    }

    pub fn registration(&self) -> &ConfluencePluginRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut ConfluencePluginRegistration {
        &mut self.registration
    }

    pub fn provider_manifest(&self) -> &ConfluenceProviderManifest {
        &self.manifest
    }

    pub fn state(&self) -> &ConfluenceProviderState {
        &self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub const fn native_transport(&self) -> bool {
        false
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn calls(&self) -> &[ConfluenceProviderCall] {
        &self.calls
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ConfluenceKnowledgeResultError> {
        let revocation = self.registration.revoke()?;
        self.state = ConfluenceProviderState::Revoked;
        Ok(revocation)
    }

    pub fn describe_content_scope(
        &mut self,
    ) -> Result<ConfluenceScopeDescription, ConfluenceKnowledgeResultError> {
        self.ensure_registration()?;
        let scope = &self.registration.scope;
        self.calls
            .push(ConfluenceProviderCall::DescribeContentScope {
                scope_digest: scope.digest(),
            });
        Ok(ConfluenceScopeDescription {
            scope: scope.clone(),
            scope_digest: scope.digest(),
            site_digest: scope.site.digest(),
            cloud_id_digest: scope.cloud_id.digest(),
            account_digest: scope.account_id.digest(),
            space_digest: scope.space_id.digest(),
            page_digest: scope.page_id.digest(),
            content_digest: scope.content_id.digest(),
            version_digest: scope.page_version.digest(),
            permission_digest: scope.permission_digest.clone(),
            cql_digest: scope.cql_template.digest(),
            provider_manifest_digest: self.manifest.digest(),
            evidence_source: self.provenance(),
            native_transport: false,
            native_connected: false,
        })
    }

    pub fn read_page_evidence(
        &mut self,
        request: &ConfluencePageReadRequest,
    ) -> Result<PageEvidence, ConfluenceKnowledgeResultError> {
        self.ensure_registration()?;
        request.scope.validate()?;
        self.ensure_scope(&request.scope)?;
        let secret = self.authenticate()?;
        let response = self
            .transport
            .read_page(&secret, request)
            .map_err(ConfluenceProviderError::from)?;
        let evidence = self.project_page(response, &request.scope)?;
        self.calls.push(ConfluenceProviderCall::ReadPageEvidence {
            scope_digest: request.scope.digest(),
            page_digest: request.scope.page_id.digest(),
            version_digest: request.scope.page_version.digest(),
        });
        self.state = ConfluenceProviderState::Ready;
        Ok(evidence)
    }

    pub fn search_knowledge(
        &mut self,
        request: &ConfluenceSearchRequest,
    ) -> Result<KnowledgeSearchEvidence, ConfluenceKnowledgeResultError> {
        self.ensure_registration()?;
        request.scope.validate()?;
        self.ensure_scope(&request.scope)?;
        let secret = self.authenticate()?;
        let response = self
            .transport
            .search_knowledge(&secret, request)
            .map_err(ConfluenceProviderError::from)?;
        if response.partial {
            return Err(ConfluenceProviderError::PartialResponse.into());
        }
        if response.truncated {
            return Err(ConfluenceProviderError::Truncated.into());
        }
        if response.page != request.cursor.as_ref().map_or(1, |cursor| cursor.page + 1)
            || response.hits.len() > request.page_size as usize
            || response.hits.len() > crate::model::MAX_SEARCH_HITS
        {
            return Err(ConfluenceProviderError::InvalidResponse.into());
        }
        let mut hits = Vec::with_capacity(response.hits.len());
        for hit in &response.hits {
            hits.push(Self::project_search_hit(hit, &request.scope)?);
        }
        let next_cursor = if let Some(token) = response.next_cursor {
            let cursor = ConfluenceSearchCursor::new(token, &request.scope, response.page)?;
            if request
                .cursor
                .as_ref()
                .is_some_and(|previous| previous.cursor_digest == cursor.cursor_digest)
            {
                return Err(ConfluenceProviderError::CursorLoop.into());
            }
            Some(cursor)
        } else {
            None
        };
        let evidence_source = self.provenance();
        let mut evidence = KnowledgeSearchEvidence {
            scope: request.scope.clone(),
            cql_digest: request.cql_template.digest(),
            hits,
            next_cursor,
            page: response.page,
            empty: response.hits.is_empty(),
            partial: false,
            truncated: false,
            evidence_source,
            native_transport: false,
            native_connected: false,
            search_digest: String::new(),
        };
        evidence.search_digest = evidence.calculate_digest();
        evidence.validate()?;
        self.calls.push(ConfluenceProviderCall::SearchKnowledge {
            scope_digest: request.scope.digest(),
            cql_digest: request.cql_template.digest(),
            page: response.page,
            cursor_digest: request.cursor.as_ref().map(ConfluenceSearchCursor::digest),
        });
        self.state = ConfluenceProviderState::Ready;
        Ok(evidence)
    }

    pub fn record_knowledge_receipt(
        &mut self,
        proposal: &KnowledgeResultProposal,
    ) -> Result<KnowledgeResultReceipt, ConfluenceKnowledgeResultError> {
        self.ensure_registration()?;
        proposal.validate()?;
        if proposal.scope.digest() != self.registration.scope.digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.provider_manifest_digest != self.manifest.digest()
        {
            return Err(ConfluenceProviderError::RegistrationDigestMismatch.into());
        }
        let mut receipt = KnowledgeResultReceipt {
            receipt_id: String::new(),
            receipt_digest: String::new(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope.digest(),
            provider_manifest_digest: self.manifest.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_source: ProviderProvenance::Recording,
            native_transport: false,
            native_connected: false,
            durable_native_receipt: false,
            external_write_performed: false,
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.receipt_id = format!("confluence-recording-{}", &receipt.receipt_digest[..24]);
        receipt.validate()?;
        self.calls
            .push(ConfluenceProviderCall::RecordKnowledgeReceipt {
                proposal_digest: proposal.proposal_digest.clone(),
                scope_digest: proposal.scope.digest(),
            });
        Ok(receipt)
    }

    fn ensure_registration(&mut self) -> Result<(), ConfluenceKnowledgeResultError> {
        if !self.registration.active {
            self.state = ConfluenceProviderState::Revoked;
            return Err(ConfluenceProviderError::RegistrationRevoked.into());
        }
        self.registration.validate()?;
        self.manifest.validate(&self.registration.scope)?;
        if self.registration.provider_manifest_digest != self.manifest.digest() {
            return Err(ConfluenceProviderError::ProviderManifestDrift.into());
        }
        Ok(())
    }

    fn ensure_scope(&self, scope: &ConfluenceScope) -> Result<(), ConfluenceKnowledgeResultError> {
        if scope.digest() != self.registration.scope_digest {
            return Err(ConfluenceProviderError::ScopeMismatch.into());
        }
        Ok(())
    }

    fn authenticate(&mut self) -> Result<SecretMaterial, ConfluenceKnowledgeResultError> {
        self.credentials
            .resolve(&self.registration.secret_reference)
            .map_err(|error| {
                let provider_error = ConfluenceProviderError::from(error);
                if matches!(provider_error, ConfluenceProviderError::BlockedEnv) {
                    self.state = ConfluenceProviderState::BlockedEnv;
                }
                provider_error.into()
            })
    }

    fn project_page(
        &mut self,
        response: RawPageResponse,
        scope: &ConfluenceScope,
    ) -> Result<PageEvidence, ConfluenceKnowledgeResultError> {
        let page = response.page;
        Self::ensure_page_identity(&page, scope)?;
        match page.state {
            PageState::Current => {}
            PageState::Archived => return Err(ConfluenceProviderError::Archived.into()),
            PageState::Deleted => return Err(ConfluenceProviderError::Deleted.into()),
            PageState::AccessLost => return Err(ConfluenceProviderError::AccessLost.into()),
        }
        if page.version != scope.page_version {
            self.state = ConfluenceProviderState::VersionDrift;
            return Err(ConfluenceProviderError::VersionDrift.into());
        }
        if page.permission_digest != scope.permission_digest {
            self.state = ConfluenceProviderState::PermissionDrift;
            return Err(ConfluenceProviderError::PermissionDrift.into());
        }
        if page.body_representation != scope.body_representation {
            return Err(ConfluenceProviderError::InvalidResponse.into());
        }
        if page.partial {
            return Err(ConfluenceProviderError::PartialResponse.into());
        }
        if page.truncated || page.body.len() > scope.max_body_bytes {
            return Err(ConfluenceProviderError::Truncated.into());
        }
        if page.ancestors.len() > crate::model::MAX_ANCESTORS
            || page.children.len() > crate::model::MAX_CHILDREN
            || page.labels.len() > crate::model::MAX_LABELS
        {
            return Err(ConfluenceProviderError::Truncated.into());
        }
        let body_digest = sha256_digest(page.body.as_bytes());
        if page
            .reported_body_digest
            .as_ref()
            .is_some_and(|reported| reported != &body_digest)
        {
            return Err(ConfluenceProviderError::BodyMismatch.into());
        }
        let metadata = Self::project_metadata(&page);
        if page
            .reported_metadata_digest
            .as_ref()
            .is_some_and(|reported| reported != &metadata.metadata_digest)
        {
            return Err(ConfluenceProviderError::MetadataMismatch.into());
        }
        let mut evidence = PageEvidence {
            scope: scope.clone(),
            metadata,
            body: SelectedBody {
                representation: page.body_representation,
                byte_length: page.body.len(),
                value_digest: body_digest,
                truncated: false,
            },
            version: page.version,
            permission_digest: page.permission_digest,
            evidence_source: self.provenance(),
            native_transport: false,
            native_connected: false,
            partial: false,
            truncated: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence.validate()?;
        Ok(evidence)
    }

    fn project_metadata(page: &FixturePage) -> PageMetadata {
        let ancestors = page
            .ancestors
            .iter()
            .map(|link| PageLink {
                page_id: link.page_id.clone(),
                content_id: link.content_id.clone(),
                title_digest: sha256_digest(link.title.as_bytes()),
                position: link.position,
            })
            .collect::<Vec<_>>();
        let children = page
            .children
            .iter()
            .map(|link| PageLink {
                page_id: link.page_id.clone(),
                content_id: link.content_id.clone(),
                title_digest: sha256_digest(link.title.as_bytes()),
                position: link.position,
            })
            .collect::<Vec<_>>();
        let labels = page
            .labels
            .iter()
            .map(|label| LabelDigest {
                label_digest: sha256_digest(label.as_bytes()),
            })
            .collect::<Vec<_>>();
        let mut metadata = PageMetadata {
            page_id: page.page_id.clone(),
            content_id: page.content_id.clone(),
            space_id: page.space_id.clone(),
            title_digest: sha256_digest(page.title.as_bytes()),
            state: page.state.clone(),
            version: page.version.clone(),
            ancestors,
            children,
            labels,
            metadata_digest: String::new(),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        metadata
    }

    fn project_search_hit(
        raw: &RawSearchHit,
        scope: &ConfluenceScope,
    ) -> Result<KnowledgeSearchHit, ConfluenceKnowledgeResultError> {
        if raw.page.site != scope.site || raw.page.cloud_id != scope.cloud_id {
            return Err(ConfluenceProviderError::SiteDrift.into());
        }
        if raw.page.account_id != scope.account_id {
            return Err(ConfluenceProviderError::AccountDrift.into());
        }
        if raw.page.space_id != scope.space_id {
            return Err(ConfluenceProviderError::SpaceDrift.into());
        }
        if raw.page.state != PageState::Current {
            return Err(ConfluenceProviderError::InvalidResponse.into());
        }
        let metadata = Self::project_metadata(&raw.page);
        let mut hit = KnowledgeSearchHit {
            page_id: raw.page.page_id.clone(),
            content_id: raw.page.content_id.clone(),
            space_id: raw.page.space_id.clone(),
            version: raw.page.version.clone(),
            title_digest: sha256_digest(raw.page.title.as_bytes()),
            excerpt_digest: sha256_digest(raw.excerpt.as_bytes()),
            metadata_digest: metadata.metadata_digest,
            hit_digest: String::new(),
        };
        hit.hit_digest = hit.calculate_digest();
        Ok(hit)
    }

    fn ensure_page_identity(
        page: &FixturePage,
        scope: &ConfluenceScope,
    ) -> Result<(), ConfluenceKnowledgeResultError> {
        if page.site != scope.site || page.cloud_id != scope.cloud_id {
            return Err(ConfluenceProviderError::SiteDrift.into());
        }
        if page.account_id != scope.account_id {
            return Err(ConfluenceProviderError::AccountDrift.into());
        }
        if page.space_id != scope.space_id {
            return Err(ConfluenceProviderError::SpaceDrift.into());
        }
        if page.page_id != scope.page_id || page.content_id != scope.content_id {
            return Err(ConfluenceProviderError::PageDrift.into());
        }
        Ok(())
    }
}

pub type FakeConfluenceProvider<T, R> = ConfluenceCloudProvider<T, R>;
pub type RecordingConfluenceProvider<T, R> = ConfluenceCloudProvider<T, R>;

#[allow(dead_code)]
fn _content_free_markers(
    _page_id: &ConfluencePageId,
    _content_id: &ConfluenceContentId,
    _version: &PageVersion,
    _operation: &ConfluenceTransportOperation,
) {
    let _ = digest_parts(std::iter::empty());
    let _ = canonical_digest(&0_u8);
}
