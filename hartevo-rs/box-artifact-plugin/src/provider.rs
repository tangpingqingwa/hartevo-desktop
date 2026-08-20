use std::env;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{BoxArtifactError, BoxTransportError};
use crate::model::{
    ArtifactAvailability, ArtifactCursor, BoxArtifactPluginRegistration, BoxArtifactScope,
    BoxContentResponse, BoxFileMetadata, BoxFileVersion, BoxFolderMetadata, BoxProviderProbe,
    BoxUserMetadata, ContentReadProjection, ContentReadRequest, FileReadProjection,
    FolderItemsProjection, FolderItemsRequest, FolderReadProjection, MAX_CONTENT_BYTES,
    MAX_PAGE_SIZE, MAX_PAGES, ProbeStatus, ProviderProvenance, RegistrationRevocation,
    SecretReference, UserReadProjection, VersionPageProjection, VersionReadRequest, digest_parts,
};
use crate::transport::{BoxArtifactTransport, SecretMaterial};

pub const BOX_ARTIFACT_TOKEN_ENVIRONMENT_VARIABLE: &str = "HARTEVO_BOX_ARTIFACT_TOKEN";
pub const BOX_ARTIFACT_NATIVE_GATE_ENVIRONMENT_VARIABLE: &str = "HARTEVO_BOX_ARTIFACT_NATIVE";

/// The host resolves an opaque SecretReference without handing the provider
/// Store, keyring, browser, or Effect authority.
pub trait BoxCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<SecretMaterial, BoxArtifactError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl BoxCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<SecretMaterial, BoxArtifactError> {
        Err(BoxArtifactError::BlockedEnv)
    }
}

/// Native HTTPS/JWT or OAuth credentials are opt-in through two explicit
/// environment boundaries.  Missing or malformed values remain BLOCKED_ENV.
#[derive(Clone, Debug, Default)]
pub struct EnvironmentBoxCredentialResolver;

impl BoxCredentialResolver for EnvironmentBoxCredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<SecretMaterial, BoxArtifactError> {
        if env::var(BOX_ARTIFACT_NATIVE_GATE_ENVIRONMENT_VARIABLE)
            .ok()
            .as_deref()
            != Some("1")
        {
            return Err(BoxArtifactError::BlockedEnv);
        }
        let token = env::var(BOX_ARTIFACT_TOKEN_ENVIRONMENT_VARIABLE)
            .map_err(|_| BoxArtifactError::BlockedEnv)?;
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(BoxArtifactError::BlockedEnv);
        }
        Ok(SecretMaterial::new(token))
    }
}

#[derive(Clone)]
pub struct StaticBoxCredentialResolver {
    material: SecretMaterial,
}

impl fmt::Debug for StaticBoxCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticBoxCredentialResolver(<redacted>)")
    }
}

impl StaticBoxCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: SecretMaterial::new(value),
        }
    }
}

impl BoxCredentialResolver for StaticBoxCredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<SecretMaterial, BoxArtifactError> {
        if self.material.as_str().trim().is_empty() {
            Err(BoxArtifactError::BlockedEnv)
        } else {
            Ok(SecretMaterial::new(self.material.as_str()))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxProviderState {
    Disconnected,
    ReadOnlyAvailable,
    Loopback,
    Fixture,
    BlockedEnv,
    Revoked,
    AccessLost,
    NotFound,
    Unknown,
}

#[derive(Debug)]
pub struct BoxArtifactProvider<T, R>
where
    T: BoxArtifactTransport,
    R: BoxCredentialResolver,
{
    registration: BoxArtifactPluginRegistration,
    transport: T,
    credentials: R,
    state: BoxProviderState,
}

impl<T, R> BoxArtifactProvider<T, R>
where
    T: BoxArtifactTransport,
    R: BoxCredentialResolver,
{
    pub fn new(
        registration: BoxArtifactPluginRegistration,
        transport: T,
        credentials: R,
    ) -> Result<Self, BoxArtifactError> {
        registration.validate()?;
        Ok(Self {
            registration,
            transport,
            credentials,
            state: BoxProviderState::Disconnected,
        })
    }

    pub fn registration(&self) -> &BoxArtifactPluginRegistration {
        &self.registration
    }

    pub fn state(&self) -> BoxProviderState {
        self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        match self.state {
            BoxProviderState::BlockedEnv | BoxProviderState::Revoked => {
                ProviderProvenance::BlockedEnv
            }
            _ => self.transport.provenance(),
        }
    }

    pub fn native_transport(&self) -> bool {
        self.provenance().is_native()
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, BoxArtifactError> {
        let revocation = self.registration.revoke()?;
        self.state = BoxProviderState::Revoked;
        Ok(revocation)
    }

    pub fn probe(&mut self) -> Result<BoxProviderProbe, BoxArtifactError> {
        let token = self.authenticate()?;
        let scope = self.registration.scope.clone();
        let user = self
            .transport
            .get_user(&token, &scope.enterprise_id, &scope.user_id);
        let user = match user {
            Ok(user) => user,
            Err(error) => return Err(self.map_transport_error(error)),
        };
        let user = Self::project_user(user, &scope)?;
        self.mark_available();
        let provenance = self.provenance();
        let status = match provenance {
            ProviderProvenance::NativeHttps => ProbeStatus::ReadOnlyNativeSeam,
            ProviderProvenance::Loopback => ProbeStatus::VerifiedLoopbackNotConnected,
            ProviderProvenance::Fixture => ProbeStatus::VerifiedFixtureNotConnected,
            ProviderProvenance::BlockedEnv => ProbeStatus::BlockedEnv,
        };
        let probe_digest = digest_parts([
            scope.digest().as_str(),
            user.user_id.as_str(),
            user.enterprise_id.as_str(),
            &status.to_string(),
            &provenance.to_string(),
        ]);
        let probe = BoxProviderProbe {
            scope: scope.clone(),
            user,
            status,
            provenance: provenance.clone(),
            native_transport: provenance.is_native(),
            native_connected: false,
            provider_version: crate::BOX_ARTIFACT_PROVIDER_VERSION,
            registration_digest: self.registration.registration_digest.clone(),
            probe_digest,
        };
        probe.validate()?;
        Ok(probe)
    }

    pub fn read_user(&mut self) -> Result<UserReadProjection, BoxArtifactError> {
        let probe = self.probe()?;
        let read_digest = digest_parts([
            probe.probe_digest.as_str(),
            probe.user.user_id.as_str(),
            probe.user.enterprise_id.as_str(),
        ]);
        Ok(UserReadProjection {
            scope: probe.scope,
            user: probe.user,
            provider_version: probe.provider_version,
            registration_digest: probe.registration_digest,
            provenance: probe.provenance,
            native_transport: probe.native_transport,
            native_connected: false,
            read_digest,
        })
    }

    pub fn read_folder(
        &mut self,
        scope: &BoxArtifactScope,
        folder_id: &crate::FolderId,
    ) -> Result<FolderReadProjection, BoxArtifactError> {
        self.ensure_scope(scope)?;
        if !scope.permits_folder(folder_id) {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        let token = self.authenticate()?;
        let folder = self
            .transport
            .get_folder(&token, scope, folder_id)
            .map_err(|error| self.map_transport_error(error))?;
        let folder = Self::project_folder(folder, scope)?;
        self.mark_available();
        let read_digest = digest_parts([
            scope.digest().as_str(),
            folder.folder_id.as_str(),
            folder
                .parent_folder_id
                .as_ref()
                .map_or("", crate::FolderId::as_str),
        ]);
        let provenance = self.provenance();
        Ok(FolderReadProjection {
            scope: scope.clone(),
            folder,
            provider_version: crate::BOX_ARTIFACT_PROVIDER_VERSION,
            registration_digest: self.registration.registration_digest.clone(),
            native_transport: provenance.is_native(),
            native_connected: false,
            provenance,
            read_digest,
        })
    }

    pub fn list_folder_items(
        &mut self,
        request: &FolderItemsRequest,
    ) -> Result<FolderItemsProjection, BoxArtifactError> {
        request.validate_for_provider(&self.registration.scope)?;
        let token = self.authenticate()?;
        let offset = request.cursor.as_ref().map_or(0, |cursor| cursor.offset);
        let page = self
            .transport
            .list_folder_items(
                &token,
                &request.scope,
                &request.folder_id,
                offset,
                request.page_size,
            )
            .map_err(|error| self.map_transport_error(error))?;
        if page.folder_id != request.folder_id || page.offset != offset {
            return Err(BoxArtifactError::InvalidCursor);
        }
        if page.entries.len() > request.page_size as usize
            || page.entries.len() > MAX_PAGE_SIZE as usize
            || offset > u64::from(MAX_PAGE_SIZE) * u64::from(MAX_PAGES)
        {
            return Err(BoxArtifactError::InvalidCursor);
        }
        let entries = page
            .entries
            .into_iter()
            .map(|file| Self::project_file(file, &request.scope, Some(&request.folder_id)))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = page
            .next_offset
            .map(|next| ArtifactCursor::folder(&request.scope, &request.folder_id, next));
        if let Some(cursor) = &next_cursor
            && (cursor.offset <= offset || cursor.offset > page.total_count)
        {
            return Err(BoxArtifactError::InvalidCursor);
        }
        self.mark_available();
        let provenance = self.provenance();
        let read_digest = digest_parts([
            request.scope.digest().as_str(),
            request.folder_id.as_str(),
            &offset.to_string(),
            &page.total_count.to_string(),
            &serde_json::to_string(&entries).map_err(|_| BoxArtifactError::Decode)?,
        ]);
        Ok(FolderItemsProjection {
            scope: request.scope.clone(),
            folder_id: request.folder_id.clone(),
            entries,
            next_cursor,
            total_count: page.total_count,
            provider_version: crate::BOX_ARTIFACT_PROVIDER_VERSION,
            registration_digest: self.registration.registration_digest.clone(),
            provenance: provenance.clone(),
            native_transport: provenance.is_native(),
            native_connected: false,
            read_digest,
        })
    }

    pub fn read_file(
        &mut self,
        request: &crate::FileReadRequest,
    ) -> Result<FileReadProjection, BoxArtifactError> {
        request.validate_for_provider(&self.registration.scope)?;
        let token = self.authenticate()?;
        let raw = match self
            .transport
            .get_file(&token, &request.scope, &request.file_id)
        {
            Ok(file) => file,
            Err(BoxTransportError::Forbidden) => {
                self.state = BoxProviderState::AccessLost;
                return Ok(self.file_state_projection(
                    request,
                    ArtifactAvailability::AccessLost,
                    None,
                ));
            }
            Err(error @ (BoxTransportError::NotFound | BoxTransportError::Gone)) => {
                self.state = BoxProviderState::NotFound;
                let _ = error;
                return Ok(self.file_state_projection(
                    request,
                    ArtifactAvailability::NotFound,
                    None,
                ));
            }
            Err(error @ BoxTransportError::UnexpectedStatus { .. }) => {
                self.state = BoxProviderState::Unknown;
                let _ = error;
                return Ok(self.file_state_projection(
                    request,
                    ArtifactAvailability::ProviderUnknown,
                    None,
                ));
            }
            Err(error) => return Err(self.map_transport_error(error)),
        };
        let metadata = Self::project_file(raw, &request.scope, None)?;
        let availability = metadata.availability();
        self.mark_available();
        Ok(self.file_state_projection(request, availability, Some(metadata)))
    }

    pub fn read_versions(
        &mut self,
        request: &VersionReadRequest,
    ) -> Result<VersionPageProjection, BoxArtifactError> {
        request.validate_for_provider(&self.registration.scope)?;
        let token = self.authenticate()?;
        let offset = request.cursor.as_ref().map_or(0, |cursor| cursor.offset);
        let page = self
            .transport
            .list_file_versions(
                &token,
                &request.scope,
                &request.file_id,
                offset,
                request.page_size,
            )
            .map_err(|error| self.map_transport_error(error))?;
        if page.file_id != request.file_id || page.offset != offset {
            return Err(BoxArtifactError::InvalidCursor);
        }
        if page.entries.len() > request.page_size as usize
            || page.entries.len() > MAX_PAGE_SIZE as usize
            || offset > u64::from(MAX_PAGE_SIZE) * u64::from(MAX_PAGES)
        {
            return Err(BoxArtifactError::InvalidCursor);
        }
        let versions = page
            .entries
            .into_iter()
            .map(project_version)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = page
            .next_offset
            .map(|next| ArtifactCursor::versions(&request.scope, &request.file_id, next));
        if let Some(cursor) = &next_cursor
            && (cursor.offset <= offset || cursor.offset > page.total_count)
        {
            return Err(BoxArtifactError::InvalidCursor);
        }
        self.mark_available();
        let provenance = self.provenance();
        let read_digest = digest_parts([
            request.scope.digest().as_str(),
            request.file_id.as_str(),
            &offset.to_string(),
            &serde_json::to_string(&versions).map_err(|_| BoxArtifactError::Decode)?,
        ]);
        Ok(VersionPageProjection {
            scope: request.scope.clone(),
            file_id: request.file_id.clone(),
            versions,
            next_cursor,
            total_count: page.total_count,
            provider_version: crate::BOX_ARTIFACT_PROVIDER_VERSION,
            registration_digest: self.registration.registration_digest.clone(),
            provenance: provenance.clone(),
            native_transport: provenance.is_native(),
            native_connected: false,
            read_digest,
        })
    }

    pub fn read_content(
        &mut self,
        request: &ContentReadRequest,
    ) -> Result<ContentReadProjection, BoxArtifactError> {
        request.validate_for_provider(&self.registration.scope)?;
        let token = self.authenticate()?;
        let current = self
            .transport
            .get_file(&token, &request.scope, &request.revision.file_id)
            .map_err(|error| self.map_transport_error(error))?;
        let current = Self::project_file(current, &request.scope, None)?;
        if !current.availability().is_present() {
            return Err(match current.availability() {
                ArtifactAvailability::AccessLost => BoxArtifactError::AccessLost,
                ArtifactAvailability::Deleted | ArtifactAvailability::NotFound => {
                    BoxArtifactError::Deleted
                }
                ArtifactAvailability::Trashed => BoxArtifactError::Trashed,
                ArtifactAvailability::ProviderUnknown | ArtifactAvailability::Present => {
                    BoxArtifactError::ProviderUnknown
                }
            });
        }
        if current.revision() != request.revision {
            return Err(BoxArtifactError::StaleRevision);
        }
        let response = self
            .transport
            .get_content(
                &token,
                &request.scope,
                &request.revision.file_id,
                &request.revision.version_id,
                request.range,
            )
            .map_err(|error| self.map_transport_error(error))?;
        validate_content_response(&response, request)?;
        let content_digest = crate::ContentDigest::from_bytes(&response.bytes);
        let complete = request.range.is_full_file(request.revision.size);
        let sha1_verified = if complete {
            if crate::Sha1Digest::from_bytes(&response.bytes) != request.revision.sha1 {
                return Err(BoxArtifactError::Sha1Mismatch);
            }
            true
        } else {
            false
        };
        if response.bytes.len() as u64 > MAX_CONTENT_BYTES {
            return Err(BoxArtifactError::ResponseTooLarge);
        }
        self.mark_available();
        let provenance = self.provenance();
        let read_digest = digest_parts([
            request.scope.digest().as_str(),
            request.revision.file_id.as_str(),
            request.revision.version_id.as_str(),
            request.revision.sha1.as_str(),
            content_digest.as_str(),
            &request.range.start.to_string(),
            &request.range.end_inclusive.to_string(),
            &sha1_verified.to_string(),
        ]);
        Ok(ContentReadProjection {
            scope: request.scope.clone(),
            revision: request.revision.clone(),
            requested_range: request.range,
            returned_range: response.range,
            bytes: response.bytes,
            content_digest,
            sha1_verified,
            complete,
            provider_version: crate::BOX_ARTIFACT_PROVIDER_VERSION,
            registration_digest: self.registration.registration_digest.clone(),
            provenance: provenance.clone(),
            native_transport: provenance.is_native(),
            native_connected: false,
            read_digest,
        })
    }

    fn ensure_scope(&self, scope: &BoxArtifactScope) -> Result<(), BoxArtifactError> {
        if scope != &self.registration.scope || !self.registration.active {
            return if self.registration.active {
                Err(BoxArtifactError::ScopeMismatch)
            } else {
                Err(BoxArtifactError::Revoked)
            };
        }
        Ok(())
    }

    fn authenticate(&mut self) -> Result<SecretMaterial, BoxArtifactError> {
        if !self.registration.active {
            self.state = BoxProviderState::Revoked;
            return Err(BoxArtifactError::Revoked);
        }
        let token = match self
            .credentials
            .resolve(&self.registration.secret_reference)
        {
            Ok(token) => token,
            Err(error @ BoxArtifactError::BlockedEnv) => {
                self.state = BoxProviderState::BlockedEnv;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if token.as_str().trim().is_empty() {
            self.state = BoxProviderState::BlockedEnv;
            return Err(BoxArtifactError::BlockedEnv);
        }
        if self.state == BoxProviderState::BlockedEnv {
            self.state = BoxProviderState::Disconnected;
        }
        Ok(token)
    }

    fn mark_available(&mut self) {
        self.state = match self.transport.provenance() {
            ProviderProvenance::NativeHttps => BoxProviderState::ReadOnlyAvailable,
            ProviderProvenance::Loopback => BoxProviderState::Loopback,
            ProviderProvenance::Fixture => BoxProviderState::Fixture,
            ProviderProvenance::BlockedEnv => BoxProviderState::BlockedEnv,
        };
    }

    fn map_transport_error(&mut self, error: BoxTransportError) -> BoxArtifactError {
        match error {
            BoxTransportError::Forbidden | BoxTransportError::Unauthorized => {
                self.state = BoxProviderState::AccessLost;
                BoxArtifactError::AccessLost
            }
            BoxTransportError::NotFound | BoxTransportError::Gone => {
                self.state = BoxProviderState::NotFound;
                BoxArtifactError::Deleted
            }
            BoxTransportError::UnexpectedStatus { status } if status >= 500 => {
                self.state = BoxProviderState::Unknown;
                BoxArtifactError::ProviderUnknown
            }
            other => other.into(),
        }
    }

    fn project_user(
        user: crate::BoxUserRecord,
        scope: &BoxArtifactScope,
    ) -> Result<BoxUserMetadata, BoxArtifactError> {
        if user.enterprise_id != scope.enterprise_id || user.user_id != scope.user_id {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Ok(BoxUserMetadata {
            enterprise_id: user.enterprise_id,
            user_id: user.user_id,
            display_name: user.display_name,
            email_address: user.email_address,
        })
    }

    fn project_folder(
        folder: crate::BoxFolderRecord,
        scope: &BoxArtifactScope,
    ) -> Result<BoxFolderMetadata, BoxArtifactError> {
        if folder.enterprise_id != scope.enterprise_id || folder.user_id != scope.user_id {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Ok(BoxFolderMetadata {
            enterprise_id: folder.enterprise_id,
            user_id: folder.user_id,
            folder_id: folder.folder_id,
            parent_folder_id: folder.parent_folder_id,
            name: folder.name,
        })
    }

    fn project_file(
        file: crate::BoxFileRecord,
        scope: &BoxArtifactScope,
        expected_folder: Option<&crate::FolderId>,
    ) -> Result<BoxFileMetadata, BoxArtifactError> {
        if file.enterprise_id != scope.enterprise_id
            || file.owner_user_id != scope.user_id
            || !scope.permits_file(&file.file_id)
            || scope
                .folder_id
                .as_ref()
                .is_some_and(|folder| folder != &file.parent_folder_id)
            || expected_folder.is_some_and(|folder| folder != &file.parent_folder_id)
            || file.media_type.trim().is_empty()
            || file.media_type.chars().any(char::is_control)
        {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Ok(BoxFileMetadata {
            enterprise_id: file.enterprise_id,
            owner_user_id: file.owner_user_id,
            file_id: file.file_id,
            parent_folder_id: file.parent_folder_id,
            name: file.name,
            media_type: file.media_type,
            size: file.size,
            sha1: file.sha1,
            version_id: file.version_id,
            trashed: file.trashed,
            deleted: file.deleted,
        })
    }

    fn file_state_projection(
        &self,
        request: &crate::FileReadRequest,
        availability: ArtifactAvailability,
        metadata: Option<BoxFileMetadata>,
    ) -> FileReadProjection {
        let provenance = self.provenance();
        let read_digest = digest_parts([
            request.scope.digest().as_str(),
            request.file_id.as_str(),
            &availability.to_string(),
        ]);
        FileReadProjection {
            scope: request.scope.clone(),
            file_id: request.file_id.clone(),
            availability,
            metadata,
            provider_version: crate::BOX_ARTIFACT_PROVIDER_VERSION,
            registration_digest: self.registration.registration_digest.clone(),
            native_transport: provenance.is_native(),
            native_connected: false,
            provenance,
            read_digest,
        }
    }
}

fn project_version(record: crate::BoxVersionRecord) -> Result<BoxFileVersion, BoxArtifactError> {
    if record.file_id.as_str().is_empty() {
        return Err(BoxArtifactError::InvalidInput {
            field: "version file id",
            reason: "must not be empty",
        });
    }
    Ok(BoxFileVersion {
        file_id: record.file_id,
        version_id: record.version_id,
        size: record.size,
        sha1: record.sha1,
        trashed: record.trashed,
        deleted: record.deleted,
    })
}

fn validate_content_response(
    response: &BoxContentResponse,
    request: &ContentReadRequest,
) -> Result<(), BoxArtifactError> {
    if response.file_id != request.revision.file_id
        || response.version_id != request.revision.version_id
        || response.range != request.range
        || response.bytes.len() as u64 != request.range.len()
        || !matches!(response.status, 200 | 206)
    {
        return Err(BoxArtifactError::RangeMismatch);
    }
    Ok(())
}

impl fmt::Display for BoxProviderState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Disconnected => "disconnected",
            Self::ReadOnlyAvailable => "read_only_available",
            Self::Loopback => "loopback",
            Self::Fixture => "fixture",
            Self::BlockedEnv => "blocked_env",
            Self::Revoked => "revoked",
            Self::AccessLost => "access_lost",
            Self::NotFound => "not_found",
            Self::Unknown => "unknown",
        };
        formatter.write_str(value)
    }
}

impl fmt::Display for ProbeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::ReadOnlyNativeSeam => "read_only_native_seam",
            Self::VerifiedLoopbackNotConnected => "verified_loopback_not_connected",
            Self::VerifiedFixtureNotConnected => "verified_fixture_not_connected",
            Self::BlockedEnv => "blocked_env",
        };
        formatter.write_str(value)
    }
}

impl fmt::Display for ArtifactAvailability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Present => "present",
            Self::Deleted => "deleted",
            Self::Trashed => "trashed",
            Self::AccessLost => "access_lost",
            Self::NotFound => "not_found",
            Self::ProviderUnknown => "provider_unknown",
        };
        formatter.write_str(value)
    }
}

impl FolderItemsRequest {
    pub(crate) fn validate_for_provider(
        &self,
        registration_scope: &BoxArtifactScope,
    ) -> Result<(), BoxArtifactError> {
        if &self.scope != registration_scope {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Self::new(
            self.scope.clone(),
            self.folder_id.clone(),
            self.cursor.clone(),
            self.page_size,
        )?;
        Ok(())
    }
}

impl VersionReadRequest {
    pub(crate) fn validate_for_provider(
        &self,
        registration_scope: &BoxArtifactScope,
    ) -> Result<(), BoxArtifactError> {
        if &self.scope != registration_scope {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Self::new(
            self.scope.clone(),
            self.file_id.clone(),
            self.cursor.clone(),
            self.page_size,
        )?;
        Ok(())
    }
}

impl crate::FileReadRequest {
    pub(crate) fn validate_for_provider(
        &self,
        registration_scope: &BoxArtifactScope,
    ) -> Result<(), BoxArtifactError> {
        if &self.scope != registration_scope {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Self::new(self.scope.clone(), self.file_id.clone())?;
        Ok(())
    }
}

impl ContentReadRequest {
    pub(crate) fn validate_for_provider(
        &self,
        registration_scope: &BoxArtifactScope,
    ) -> Result<(), BoxArtifactError> {
        if &self.scope != registration_scope {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Self::new(self.scope.clone(), self.revision.clone(), self.range)?;
        Ok(())
    }
}
