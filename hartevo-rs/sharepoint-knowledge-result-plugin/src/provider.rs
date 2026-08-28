use std::fmt;

use crate::{
    error::{
        EntraCredentialError, MicrosoftGraphSharePointProviderError, SharePointKnowledgeResultError,
    },
    model::{
        DriveItemChildrenEvidence, DriveItemDeltaEntry, DriveItemDeltaEvidence, DriveItemMetadata,
        DriveItemMetadataEvidence, DriveItemReadRequest, DriveItemSearchEvidence,
        DriveItemSearchHit, DriveItemSummary, DriveItemVersion, DriveItemVersionsEvidence,
        EvidenceEnvelope, GRAPH_API_VERSION, MAX_CHILDREN, MAX_DELTA_ENTRIES, MAX_PAGES,
        MAX_SEARCH_HITS, MAX_VERSIONS, NativeProbe, OpaqueGraphNextLink, PAGE_SIZE,
        ProviderProvenance, RegistrationRevocation, SHAREPOINT_PROVIDER_REVISION,
        SharePointCapability, SharePointKnowledgeEvidence, SharePointKnowledgeReadRequest,
        SharePointKnowledgeResultProposal, SharePointKnowledgeScope, SharePointPluginRegistration,
        SharePointProviderManifest, SharePointScopeDescription, SharePointSearchRequest,
        canonical_digest, sha256_digest,
    },
    transport::{
        DriveItemDeltaPayload, DriveItemMetadataPayload, DriveItemSearchPayload,
        DriveItemVersionPayload, MicrosoftGraphRequest, MicrosoftGraphResponse,
        MicrosoftGraphResponseBody, MicrosoftGraphSharePointTransport, SharePointGraphOperation,
    },
};

pub use crate::model::EntraSecretReference;

/// A credential resolver returns only a non-serializable lease marker. The
/// raw access token is host-owned and never appears in this crate.
#[derive(Clone, Eq, PartialEq)]
pub struct EntraCredentialLease {
    token_digest: String,
}

impl fmt::Debug for EntraCredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraCredentialLease")
            .field("token_digest", &self.token_digest)
            .finish()
    }
}

impl EntraCredentialLease {
    pub fn digest(&self) -> &str {
        &self.token_digest
    }
}

pub type CredentialLease = EntraCredentialLease;

pub trait EntraCredentialResolver: fmt::Debug + Send {
    fn resolve(
        &mut self,
        reference: &EntraSecretReference,
    ) -> Result<EntraCredentialLease, EntraCredentialError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl EntraCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &EntraSecretReference,
    ) -> Result<EntraCredentialLease, EntraCredentialError> {
        Err(EntraCredentialError::BlockedEnv)
    }
}

#[derive(Clone)]
pub struct StaticEntraCredentialResolver {
    token_digest: String,
}

impl fmt::Debug for StaticEntraCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticEntraCredentialResolver")
            .field("token_digest", &self.token_digest)
            .finish()
    }
}

impl StaticEntraCredentialResolver {
    pub fn new(token: impl AsRef<[u8]>) -> Self {
        Self {
            token_digest: sha256_digest(token),
        }
    }
}

impl EntraCredentialResolver for StaticEntraCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &EntraSecretReference,
    ) -> Result<EntraCredentialLease, EntraCredentialError> {
        Ok(EntraCredentialLease {
            token_digest: self.token_digest.clone(),
        })
    }
}

pub type FixtureEntraCredentialResolver = StaticEntraCredentialResolver;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MicrosoftGraphSharePointProviderState {
    Ready,
    BlockedEnv,
    Revoked,
    Failed,
}

pub type ProviderState = MicrosoftGraphSharePointProviderState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MicrosoftGraphSharePointProviderCall {
    DescribeScope {
        scope_digest: String,
    },
    Read {
        operation: SharePointGraphOperation,
        scope_digest: String,
        page: u16,
        cursor_digest: Option<String>,
    },
    CompileKnowledgeResult {
        evidence_digest: String,
    },
}

pub type ProviderCall = MicrosoftGraphSharePointProviderCall;

#[derive(Clone, Debug)]
pub struct SharePointRegistrationRequest {
    pub scope: SharePointKnowledgeScope,
    pub secret_reference: EntraSecretReference,
}

impl SharePointRegistrationRequest {
    pub fn new(scope: SharePointKnowledgeScope, secret_reference: EntraSecretReference) -> Self {
        Self {
            scope,
            secret_reference,
        }
    }

    pub fn register(self) -> Result<SharePointPluginRegistration, SharePointKnowledgeResultError> {
        SharePointPluginRegistration::new(self.scope, self.secret_reference)
    }
}

pub type RegistrationRequest = SharePointRegistrationRequest;

/// Typed Microsoft Graph SharePoint provider. It has no native HTTP
/// implementation and rejects any transport that could claim native access.
pub struct MicrosoftGraphSharePointProvider<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    registration: SharePointPluginRegistration,
    secret_reference: EntraSecretReference,
    manifest: SharePointProviderManifest,
    transport: T,
    credentials: R,
    state: MicrosoftGraphSharePointProviderState,
    calls: Vec<MicrosoftGraphSharePointProviderCall>,
}

impl<T, R> fmt::Debug for MicrosoftGraphSharePointProvider<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftGraphSharePointProvider")
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("manifest_digest", &self.manifest.manifest_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provenance", &self.provenance())
            .field("state", &self.state)
            .field("calls_count", &self.calls.len())
            .field("transport", &self.transport)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl<T, R> MicrosoftGraphSharePointProvider<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    pub fn new(
        scope: SharePointKnowledgeScope,
        secret_reference: EntraSecretReference,
        transport: T,
        credentials: R,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        let registration = SharePointPluginRegistration::new(scope, secret_reference.clone())?;
        Self::from_registration(registration, secret_reference, transport, credentials)
    }

    pub fn from_registration(
        registration: SharePointPluginRegistration,
        secret_reference: EntraSecretReference,
        transport: T,
        credentials: R,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        let scope = registration_scope(&registration)?;
        let manifest = SharePointProviderManifest::layer1(&scope);
        let provenance = transport.provenance();
        if registration.provider_manifest_digest != manifest.digest()
            || registration.entra_secret_reference_digest != secret_reference.digest()
            || !provenance.is_layer1_sealed()
            || provenance.is_native()
            || provenance.is_connected()
        {
            return Err(SharePointKnowledgeResultError::ExternalWriteAuthority);
        }
        registration.validate(&scope, &manifest)?;
        secret_reference.validate()?;
        Ok(Self {
            registration,
            secret_reference,
            manifest,
            transport,
            credentials,
            state: MicrosoftGraphSharePointProviderState::Ready,
            calls: Vec::new(),
        })
    }

    pub fn registration(&self) -> &SharePointPluginRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut SharePointPluginRegistration {
        &mut self.registration
    }

    pub fn provider_manifest(&self) -> &SharePointProviderManifest {
        &self.manifest
    }

    pub fn state(&self) -> &MicrosoftGraphSharePointProviderState {
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

    pub const fn connected(&self) -> bool {
        false
    }

    pub fn calls(&self) -> &[MicrosoftGraphSharePointProviderCall] {
        &self.calls
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, SharePointKnowledgeResultError> {
        let revocation = self
            .registration
            .revoke(&registration_scope(&self.registration)?, &self.manifest)?;
        self.state = MicrosoftGraphSharePointProviderState::Revoked;
        Ok(revocation)
    }

    pub fn describe_scope(
        &mut self,
    ) -> Result<SharePointScopeDescription, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        let scope = registration_scope(&self.registration)?;
        self.calls
            .push(MicrosoftGraphSharePointProviderCall::DescribeScope {
                scope_digest: scope.digest(),
            });
        Ok(SharePointScopeDescription {
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            provider_manifest_digest: self.manifest.digest(),
            evidence_source: self.provenance(),
            native_transport: false,
            native_connected: false,
            scope,
        })
    }

    pub fn read_drive_item_metadata(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemMetadataEvidence, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        request.validate()?;
        self.ensure_scope(&request.scope)?;
        if request.expected_version != request.scope.item_version {
            return Err(MicrosoftGraphSharePointProviderError::VersionDrift.into());
        }
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemMetadata)?;
        self.authenticate()?;
        let graph_request = MicrosoftGraphRequest::new(
            SharePointGraphOperation::DriveItemMetadata,
            &request.scope,
            1,
            None,
            None,
        );
        let response = self.execute(&graph_request)?;
        let next_link_digest = response.next_link_digest();
        let MicrosoftGraphResponseBody::Metadata(payload) = response.into_body() else {
            return Err(MicrosoftGraphSharePointProviderError::InvalidResponse.into());
        };
        let metadata = Self::project_metadata(payload, &request.scope)?;
        let envelope = self.envelope(&request.scope);
        let mut evidence = DriveItemMetadataEvidence {
            envelope,
            metadata,
            next_link_digest,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = canonical_digest(&(
            &evidence.envelope,
            &evidence.metadata,
            &evidence.next_link_digest,
        ));
        self.record_read(&graph_request);
        Ok(evidence)
    }

    pub fn read_drive_item_children(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemChildrenEvidence, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        request.validate()?;
        self.ensure_scope(&request.scope)?;
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemChildren)?;
        self.authenticate()?;
        let mut cursor: Option<OpaqueGraphNextLink> = None;
        let mut page = 1_u16;
        let mut cursor_digests = Vec::new();
        let mut children = Vec::new();
        loop {
            let graph_request = MicrosoftGraphRequest::new(
                SharePointGraphOperation::DriveItemChildren,
                &request.scope,
                page,
                cursor.as_ref(),
                None,
            );
            let response = self.execute(&graph_request)?;
            let MicrosoftGraphResponseBody::Children { items, next_link } = response.into_body()
            else {
                return Err(MicrosoftGraphSharePointProviderError::InvalidResponse.into());
            };
            if items.len() > crate::model::PAGE_SIZE as usize
                || children.len().saturating_add(items.len()) > MAX_CHILDREN
            {
                return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
            }
            for item in items {
                children.push(Self::project_summary(item, &request.scope)?);
            }
            let next = next_link;
            if let Some(next) = next {
                ensure_next_cursor(cursor.as_ref(), &next)?;
                cursor_digests.push(next.digest().to_owned());
                if page >= MAX_PAGES {
                    return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
                }
                page += 1;
                cursor = Some(next);
            } else {
                break;
            }
        }
        let envelope = self.envelope(&request.scope);
        let mut evidence = DriveItemChildrenEvidence {
            envelope,
            item_id: request.scope.item_id.clone(),
            children,
            page_count: page,
            cursor_digests,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = canonical_digest(&(
            &evidence.envelope,
            &evidence.item_id,
            &evidence.children,
            evidence.page_count,
            &evidence.cursor_digests,
        ));
        Ok(evidence)
    }

    pub fn search_drive_items(
        &mut self,
        request: &SharePointSearchRequest,
    ) -> Result<DriveItemSearchEvidence, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        request.validate()?;
        self.ensure_scope(&request.scope)?;
        Self::ensure_capability(&request.scope, SharePointCapability::SearchDriveItems)?;
        self.authenticate()?;
        let query_digest = request.query.digest();
        let mut cursor = request.cursor.clone();
        let mut page = 1_u16;
        let mut cursor_digests = Vec::new();
        let mut hits = Vec::new();
        loop {
            let graph_request = MicrosoftGraphRequest::new(
                SharePointGraphOperation::DriveItemSearch,
                &request.scope,
                page,
                cursor.as_ref(),
                Some(query_digest.clone()),
            );
            let response = self.execute(&graph_request)?;
            let MicrosoftGraphResponseBody::Search {
                hits: page_hits,
                next_link,
            } = response.into_body()
            else {
                return Err(MicrosoftGraphSharePointProviderError::InvalidResponse.into());
            };
            if page_hits.len() > request.page_size as usize
                || hits.len().saturating_add(page_hits.len()) > MAX_SEARCH_HITS
            {
                return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
            }
            for hit in page_hits {
                hits.push(Self::project_search_hit(hit, &request.scope)?);
            }
            if let Some(next) = next_link {
                ensure_next_cursor(cursor.as_ref(), &next)?;
                cursor_digests.push(next.digest().to_owned());
                if page >= MAX_PAGES {
                    return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
                }
                page += 1;
                cursor = Some(next);
            } else {
                break;
            }
        }
        let envelope = self.envelope(&request.scope);
        let mut evidence = DriveItemSearchEvidence {
            envelope,
            query_digest,
            hits,
            page_count: page,
            cursor_digests,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = canonical_digest(&(
            &evidence.envelope,
            &evidence.query_digest,
            &evidence.hits,
            evidence.page_count,
            &evidence.cursor_digests,
        ));
        Ok(evidence)
    }

    pub fn read_drive_item_versions(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemVersionsEvidence, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        request.validate()?;
        self.ensure_scope(&request.scope)?;
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemVersions)?;
        self.authenticate()?;
        let mut cursor = None;
        let mut page = 1_u16;
        let mut cursor_digests = Vec::new();
        let mut versions = Vec::new();
        loop {
            let graph_request = MicrosoftGraphRequest::new(
                SharePointGraphOperation::DriveItemVersions,
                &request.scope,
                page,
                cursor.as_ref(),
                None,
            );
            let response = self.execute(&graph_request)?;
            let MicrosoftGraphResponseBody::Versions {
                versions: page_versions,
                next_link,
            } = response.into_body()
            else {
                return Err(MicrosoftGraphSharePointProviderError::InvalidResponse.into());
            };
            if page_versions.len() > PAGE_SIZE as usize
                || versions.len().saturating_add(page_versions.len()) > MAX_VERSIONS
            {
                return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
            }
            for version in page_versions {
                versions.push(Self::project_version(version, &request.scope)?);
            }
            if let Some(next) = next_link {
                ensure_next_cursor(cursor.as_ref(), &next)?;
                cursor_digests.push(next.digest().to_owned());
                if page >= MAX_PAGES {
                    return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
                }
                page += 1;
                cursor = Some(next);
            } else {
                break;
            }
        }
        let envelope = self.envelope(&request.scope);
        let mut evidence = DriveItemVersionsEvidence {
            envelope,
            item_id: request.scope.item_id.clone(),
            versions,
            page_count: page,
            cursor_digests,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = canonical_digest(&(
            &evidence.envelope,
            &evidence.item_id,
            &evidence.versions,
            evidence.page_count,
            &evidence.cursor_digests,
        ));
        Ok(evidence)
    }

    pub fn read_drive_item_delta(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemDeltaEvidence, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        request.validate()?;
        self.ensure_scope(&request.scope)?;
        Self::ensure_capability(&request.scope, SharePointCapability::ReadDriveItemDelta)?;
        self.authenticate()?;
        let mut cursor = None;
        let mut page = 1_u16;
        let mut cursor_digests = Vec::new();
        let mut entries = Vec::new();
        loop {
            let graph_request = MicrosoftGraphRequest::new(
                SharePointGraphOperation::DriveItemDelta,
                &request.scope,
                page,
                cursor.as_ref(),
                None,
            );
            let response = self.execute(&graph_request)?;
            let MicrosoftGraphResponseBody::Delta {
                entries: page_entries,
                next_link,
            } = response.into_body()
            else {
                return Err(MicrosoftGraphSharePointProviderError::InvalidResponse.into());
            };
            if page_entries.len() > PAGE_SIZE as usize
                || entries.len().saturating_add(page_entries.len()) > MAX_DELTA_ENTRIES
            {
                return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
            }
            for entry in page_entries {
                entries.push(Self::project_delta(entry, &request.scope)?);
            }
            if let Some(next) = next_link {
                ensure_next_cursor(cursor.as_ref(), &next)?;
                cursor_digests.push(next.digest().to_owned());
                if page >= MAX_PAGES {
                    return Err(MicrosoftGraphSharePointProviderError::Truncated.into());
                }
                page += 1;
                cursor = Some(next);
            } else {
                break;
            }
        }
        let envelope = self.envelope(&request.scope);
        let mut evidence = DriveItemDeltaEvidence {
            envelope,
            item_id: request.scope.item_id.clone(),
            entries,
            page_count: page,
            cursor_digests,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = canonical_digest(&(
            &evidence.envelope,
            &evidence.item_id,
            &evidence.entries,
            evidence.page_count,
            &evidence.cursor_digests,
        ));
        Ok(evidence)
    }

    pub fn read_knowledge_evidence(
        &mut self,
        request: &SharePointKnowledgeReadRequest,
    ) -> Result<SharePointKnowledgeEvidence, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        request.validate()?;
        self.ensure_scope(&request.scope)?;
        let read_request = DriveItemReadRequest::new(request.scope.clone());
        let metadata = self.read_drive_item_metadata(&read_request)?;
        let children = request
            .include_children
            .then(|| self.read_drive_item_children(&read_request))
            .transpose()?;
        let versions = request
            .include_versions
            .then(|| self.read_drive_item_versions(&read_request))
            .transpose()?;
        let delta = request
            .include_delta
            .then(|| self.read_drive_item_delta(&read_request))
            .transpose()?;
        if request.include_search {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "searchQuery",
                reason: String::from("use search_drive_items with the opaque query boundary"),
            });
        }
        let mut evidence = SharePointKnowledgeEvidence {
            scope: request.scope.clone(),
            provider_manifest_digest: self.manifest.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_source: self.provenance(),
            native_connected: false,
            raw_bytes_retained: false,
            download_url_retained: false,
            pii_retained: false,
            metadata,
            children,
            search: None,
            versions,
            delta,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn compile_knowledge_result(
        &mut self,
        evidence: &SharePointKnowledgeEvidence,
        work_product: crate::model::MissionWorkProduct,
    ) -> Result<SharePointKnowledgeResultProposal, SharePointKnowledgeResultError> {
        self.ensure_registration()?;
        self.ensure_scope(&evidence.scope)?;
        Self::ensure_capability(
            &evidence.scope,
            SharePointCapability::CompileKnowledgeResult,
        )?;
        evidence.validate()?;
        if evidence.evidence_source != self.provenance() {
            return Err(SharePointKnowledgeResultError::ExternalWriteAuthority);
        }
        work_product.validate()?;
        if work_product.project_id != evidence.scope.project_id
            || work_product.mission_id != evidence.scope.mission_id
            || work_product.work_product_id != evidence.scope.work_product_id
            || work_product.revision != evidence.scope.work_product_revision
        {
            return Err(SharePointKnowledgeResultError::ScopeMismatch);
        }
        let mut proposal = SharePointKnowledgeResultProposal {
            proposal_id: format!("sharepoint-knowledge-{}", &evidence.evidence_digest[..24]),
            proposal_digest: String::new(),
            scope_digest: evidence.scope.digest(),
            project_id: work_product.project_id,
            mission_id: work_product.mission_id,
            work_product_id: work_product.work_product_id,
            work_product_revision: work_product.revision,
            evidence_digest: evidence.evidence_digest.clone(),
            metadata_digest: evidence.metadata.metadata.metadata_digest.clone(),
            children_digest: evidence
                .children
                .as_ref()
                .map(|value| value.evidence_digest.clone()),
            search_digest: evidence
                .search
                .as_ref()
                .map(|value| value.evidence_digest.clone()),
            versions_digest: evidence
                .versions
                .as_ref()
                .map(|value| value.evidence_digest.clone()),
            delta_digest: evidence
                .delta
                .as_ref()
                .map(|value| value.evidence_digest.clone()),
            provider_manifest_digest: self.manifest.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_source: evidence.evidence_source,
            status: crate::model::KnowledgeResultStatus::Proposed,
            non_mutating: true,
            external_write_performed: false,
            durable_native_receipt: false,
            native_connected: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate()?;
        self.calls.push(
            MicrosoftGraphSharePointProviderCall::CompileKnowledgeResult {
                evidence_digest: evidence.evidence_digest.clone(),
            },
        );
        Ok(proposal)
    }

    fn ensure_registration(&mut self) -> Result<(), SharePointKnowledgeResultError> {
        if !self.registration.active {
            self.state = MicrosoftGraphSharePointProviderState::Revoked;
            return Err(MicrosoftGraphSharePointProviderError::RegistrationRevoked.into());
        }
        let scope = registration_scope(&self.registration)?;
        self.registration.validate(&scope, &self.manifest)?;
        if self.registration.provider_manifest_digest != self.manifest.digest() {
            self.state = MicrosoftGraphSharePointProviderState::Failed;
            return Err(MicrosoftGraphSharePointProviderError::ProviderManifestDrift.into());
        }
        Ok(())
    }

    fn ensure_scope(
        &self,
        scope: &SharePointKnowledgeScope,
    ) -> Result<(), SharePointKnowledgeResultError> {
        if scope.digest() != self.registration.scope_digest {
            return Err(MicrosoftGraphSharePointProviderError::RegistrationDigestMismatch.into());
        }
        if scope.permission_digest != self.registration.permission_digest {
            return Err(MicrosoftGraphSharePointProviderError::PermissionDrift.into());
        }
        Ok(())
    }

    fn ensure_capability(
        scope: &SharePointKnowledgeScope,
        capability: SharePointCapability,
    ) -> Result<(), SharePointKnowledgeResultError> {
        if !scope.permits(capability) {
            return Err(SharePointKnowledgeResultError::ConsentRequired { capability });
        }
        Ok(())
    }

    fn authenticate(&mut self) -> Result<EntraCredentialLease, SharePointKnowledgeResultError> {
        self.credentials
            .resolve(&self.secret_reference)
            .map_err(|error| {
                let provider_error = MicrosoftGraphSharePointProviderError::from(error);
                if matches!(
                    provider_error,
                    MicrosoftGraphSharePointProviderError::BlockedEnv
                ) {
                    self.state = MicrosoftGraphSharePointProviderState::BlockedEnv;
                }
                provider_error.into()
            })
    }

    fn execute(
        &mut self,
        request: &MicrosoftGraphRequest,
    ) -> Result<MicrosoftGraphResponse, SharePointKnowledgeResultError> {
        let response = self.transport.execute(request).map_err(|error| {
            let provider_error = MicrosoftGraphSharePointProviderError::from(error);
            if matches!(
                provider_error,
                MicrosoftGraphSharePointProviderError::BlockedEnv
            ) {
                self.state = MicrosoftGraphSharePointProviderState::BlockedEnv;
            }
            provider_error
        })?;
        response
            .validate(request)
            .map_err(MicrosoftGraphSharePointProviderError::from)?;
        if response.status() >= 400 {
            return Err(status_error(response.status()).into());
        }
        if response.status() < 200
            || response.api_version() != GRAPH_API_VERSION
            || response.provider_revision() != SHAREPOINT_PROVIDER_REVISION
            || response.response_size() > crate::model::MAX_RESPONSE_BYTES
            || response.operation() != request.operation
        {
            return Err(if response.api_version() != GRAPH_API_VERSION {
                MicrosoftGraphSharePointProviderError::ApiVersionDrift
            } else if response.provider_revision() != SHAREPOINT_PROVIDER_REVISION {
                MicrosoftGraphSharePointProviderError::ProviderRevisionDrift
            } else {
                MicrosoftGraphSharePointProviderError::InvalidResponse
            }
            .into());
        }
        Ok(response)
    }

    fn record_read(&mut self, request: &MicrosoftGraphRequest) {
        self.calls.push(MicrosoftGraphSharePointProviderCall::Read {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            page: request.page,
            cursor_digest: request.cursor_digest.clone(),
        });
    }

    fn envelope(&self, scope: &SharePointKnowledgeScope) -> EvidenceEnvelope {
        EvidenceEnvelope::layer1(
            scope.digest(),
            self.manifest.digest(),
            self.registration.registration_digest.clone(),
            self.provenance(),
        )
    }

    fn project_metadata(
        payload: DriveItemMetadataPayload,
        scope: &SharePointKnowledgeScope,
    ) -> Result<DriveItemMetadata, SharePointKnowledgeResultError> {
        ensure_payload_identity(
            &payload.site_id,
            &payload.drive_id,
            &payload.list_id,
            &payload.item_id,
            scope,
        )?;
        if payload.version != scope.item_version {
            return Err(MicrosoftGraphSharePointProviderError::VersionDrift.into());
        }
        if payload.permission_digest != scope.permission_digest {
            return Err(MicrosoftGraphSharePointProviderError::PermissionDrift.into());
        }
        if payload.has_download_url {
            return Err(MicrosoftGraphSharePointProviderError::InvalidResponse.into());
        }
        let item = project_summary_unchecked(payload);
        let metadata_digest = canonical_digest(&(&item, &scope.list_id));
        Ok(DriveItemMetadata {
            item,
            list_id: scope.list_id.clone(),
            metadata_digest,
        })
    }

    fn project_summary(
        payload: DriveItemMetadataPayload,
        scope: &SharePointKnowledgeScope,
    ) -> Result<DriveItemSummary, SharePointKnowledgeResultError> {
        ensure_container_identity(&payload.site_id, &payload.drive_id, &payload.list_id, scope)?;
        if payload.permission_digest != scope.permission_digest || payload.has_download_url {
            return Err(if payload.has_download_url {
                MicrosoftGraphSharePointProviderError::InvalidResponse
            } else {
                MicrosoftGraphSharePointProviderError::PermissionDrift
            }
            .into());
        }
        Ok(project_summary_unchecked(payload))
    }

    fn project_search_hit(
        payload: DriveItemSearchPayload,
        scope: &SharePointKnowledgeScope,
    ) -> Result<DriveItemSearchHit, SharePointKnowledgeResultError> {
        ensure_container_identity(&payload.site_id, &payload.drive_id, &payload.list_id, scope)?;
        if payload.permission_digest != scope.permission_digest {
            return Err(MicrosoftGraphSharePointProviderError::PermissionDrift.into());
        }
        let name_digest = sha256_digest(payload.name.as_bytes());
        let path_digest = sha256_digest(payload.path.as_bytes());
        let hit_digest = canonical_digest(&(
            &payload.item_id,
            &payload.version,
            &name_digest,
            &path_digest,
            payload.rank,
            &payload.permission_digest,
        ));
        Ok(DriveItemSearchHit {
            item_id: payload.item_id,
            version: payload.version,
            name_digest,
            path_digest,
            rank: payload.rank,
            permission_digest: payload.permission_digest,
            hit_digest,
        })
    }

    fn project_version(
        payload: DriveItemVersionPayload,
        scope: &SharePointKnowledgeScope,
    ) -> Result<DriveItemVersion, SharePointKnowledgeResultError> {
        ensure_payload_identity(
            &payload.site_id,
            &payload.drive_id,
            &payload.list_id,
            &payload.item_id,
            scope,
        )?;
        if payload.permission_digest != scope.permission_digest {
            return Err(MicrosoftGraphSharePointProviderError::PermissionDrift.into());
        }
        if !crate::model::is_sha256(&payload.version_digest) {
            return Err(MicrosoftGraphSharePointProviderError::InvalidResponse.into());
        }
        Ok(DriveItemVersion {
            item_id: payload.item_id,
            version_id: payload.version_id,
            modified_at_epoch_seconds: payload.modified_at_epoch_seconds,
            version_digest: payload.version_digest,
            permission_digest: payload.permission_digest,
        })
    }

    fn project_delta(
        payload: DriveItemDeltaPayload,
        scope: &SharePointKnowledgeScope,
    ) -> Result<DriveItemDeltaEntry, SharePointKnowledgeResultError> {
        ensure_payload_identity(
            &payload.site_id,
            &payload.drive_id,
            &payload.list_id,
            &payload.item_id,
            scope,
        )?;
        if payload.permission_digest != scope.permission_digest
            || !crate::model::is_sha256(&payload.item_digest)
        {
            return Err(MicrosoftGraphSharePointProviderError::PermissionDrift.into());
        }
        Ok(DriveItemDeltaEntry {
            item_id: payload.item_id,
            change: payload.change,
            item_digest: payload.item_digest,
            version: payload.version,
            permission_digest: payload.permission_digest,
        })
    }
}

fn registration_scope(
    registration: &SharePointPluginRegistration,
) -> Result<SharePointKnowledgeScope, SharePointKnowledgeResultError> {
    registration.scope.validate()?;
    Ok(registration.scope.clone())
}

fn ensure_payload_identity(
    site_id: &crate::model::SiteId,
    drive_id: &crate::model::DriveId,
    list_id: &crate::model::ListId,
    item_id: &crate::model::DriveItemId,
    scope: &SharePointKnowledgeScope,
) -> Result<(), SharePointKnowledgeResultError> {
    ensure_container_identity(site_id, drive_id, list_id, scope)?;
    if item_id != &scope.item_id {
        return Err(MicrosoftGraphSharePointProviderError::ItemDrift.into());
    }
    Ok(())
}

fn ensure_container_identity(
    site_id: &crate::model::SiteId,
    drive_id: &crate::model::DriveId,
    list_id: &crate::model::ListId,
    scope: &SharePointKnowledgeScope,
) -> Result<(), SharePointKnowledgeResultError> {
    if site_id != &scope.site_id {
        return Err(MicrosoftGraphSharePointProviderError::SiteDrift.into());
    }
    if drive_id != &scope.drive_id {
        return Err(MicrosoftGraphSharePointProviderError::DriveDrift.into());
    }
    if list_id != &scope.list_id {
        return Err(MicrosoftGraphSharePointProviderError::ListDrift.into());
    }
    Ok(())
}

fn project_summary_unchecked(payload: DriveItemMetadataPayload) -> DriveItemSummary {
    let name_digest = sha256_digest(payload.name.as_bytes());
    let e_tag_digest = sha256_digest(payload.e_tag.as_bytes());
    let item_digest = canonical_digest(&(
        &payload.item_id,
        &payload.parent_item_id,
        payload.kind,
        payload.size_bytes,
        &name_digest,
        &e_tag_digest,
        &payload.version,
        &payload.permission_digest,
    ));
    DriveItemSummary {
        item_id: payload.item_id,
        parent_item_id: payload.parent_item_id,
        kind: payload.kind,
        size_bytes: payload.size_bytes,
        name_digest,
        e_tag_digest,
        version: payload.version,
        permission_digest: payload.permission_digest,
        item_digest,
    }
}

fn ensure_next_cursor(
    previous: Option<&OpaqueGraphNextLink>,
    next: &OpaqueGraphNextLink,
) -> Result<(), SharePointKnowledgeResultError> {
    if previous.is_some_and(|previous| previous.digest() == next.digest()) {
        return Err(MicrosoftGraphSharePointProviderError::PaginationLoop.into());
    }
    Ok(())
}

fn status_error(status: u16) -> MicrosoftGraphSharePointProviderError {
    match status {
        401 => MicrosoftGraphSharePointProviderError::Unauthorized,
        403 => MicrosoftGraphSharePointProviderError::Forbidden,
        404 => MicrosoftGraphSharePointProviderError::NotFound,
        409 => MicrosoftGraphSharePointProviderError::Conflict,
        429 => MicrosoftGraphSharePointProviderError::RateLimited {
            retry_after_seconds: None,
        },
        500 | 502 | 503 | 504 => MicrosoftGraphSharePointProviderError::ServerFailure { status },
        _ => MicrosoftGraphSharePointProviderError::InvalidResponse,
    }
}

pub fn native_probe_from_environment() -> NativeProbe {
    crate::transport::native_probe_from_environment()
}
