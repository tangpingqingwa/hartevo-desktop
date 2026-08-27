use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{HcpPackerArtifactResultError, HcpPackerTransportError, Result};
use crate::model::{
    ArtifactMetadataInput, BucketMetadataInput, ChannelMetadataInput, Digest,
    HcpPackerArtifactScope, OpaqueCursor, TransportProvenance, VersionMetadataInput,
    validate_response_bytes,
};
use crate::{MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum HcpPackerOperation {
    GetBucket,
    GetChannel,
    GetVersion,
    ListBuilds,
    ListArtifacts,
}

impl HcpPackerOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetBucket => "GetBucket",
            Self::GetChannel => "GetChannel",
            Self::GetVersion => "GetVersion",
            Self::ListBuilds => "ListBuilds",
            Self::ListArtifacts => "ListArtifacts",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: HcpPackerOperation,
    pub scope_digest: Digest,
    pub subject_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub page_number: Option<u16>,
    pub request_digest: Digest,
    pub method: String,
    pub redacted: bool,
}

macro_rules! simple_request {
    ($name:ident, $operation:expr, $subject:expr) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            scope: HcpPackerArtifactScope,
            request_digest: Digest,
            observed_at: DateTime<Utc>,
        }

        impl $name {
            pub fn for_scope(scope: &HcpPackerArtifactScope) -> Result<Self> {
                Self::for_scope_at(scope, Utc::now())
            }

            pub fn for_scope_at(
                scope: &HcpPackerArtifactScope,
                observed_at: DateTime<Utc>,
            ) -> Result<Self> {
                scope.validate()?;
                let request_digest = Digest::from_parts(
                    concat!("hcp-packer-", stringify!($name), "/v1"),
                    &[("scope", scope.digest().as_str().to_owned())],
                );
                Ok(Self {
                    scope: scope.clone(),
                    request_digest,
                    observed_at,
                })
            }

            pub fn scope(&self) -> &HcpPackerArtifactScope {
                &self.scope
            }

            pub fn request_digest(&self) -> &Digest {
                &self.request_digest
            }

            pub fn observed_at(&self) -> DateTime<Utc> {
                self.observed_at
            }

            pub fn redacted_path(&self) -> String {
                format!(
                    "/packer/2023-01-01/organizations/{}/projects/{}/buckets/{}/{}?scopeDigest={}",
                    self.scope.organization_id().digest().as_str(),
                    self.scope.project_id().digest().as_str(),
                    self.scope.bucket_name().digest().as_str(),
                    stringify!($name),
                    self.scope.digest().as_str()
                )
            }

            pub fn recorded_request(&self) -> RecordedRequest {
                RecordedRequest {
                    operation: $operation,
                    scope_digest: self.scope.digest(),
                    subject_digest: $subject(&self.scope),
                    cursor_digest: None,
                    page_number: None,
                    request_digest: self.request_digest.clone(),
                    method: "GET".to_owned(),
                    redacted: true,
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("scope_digest", &self.scope.digest())
                    .field("request_digest", &self.request_digest)
                    .finish()
            }
        }
    };
}

simple_request!(
    GetBucketRequest,
    HcpPackerOperation::GetBucket,
    |_scope: &HcpPackerArtifactScope| -> Option<Digest> { None }
);
simple_request!(
    GetChannelRequest,
    HcpPackerOperation::GetChannel,
    |scope: &HcpPackerArtifactScope| { Some(scope.channel_name().digest()) }
);
simple_request!(
    GetVersionRequest,
    HcpPackerOperation::GetVersion,
    |scope: &HcpPackerArtifactScope| { Some(scope.version_fingerprint().digest()) }
);

#[derive(Clone, Eq, PartialEq)]
pub struct ListBuildsRequest {
    scope: HcpPackerArtifactScope,
    page_size: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
    observed_at: DateTime<Utc>,
}

impl ListBuildsRequest {
    pub fn new(
        scope: &HcpPackerArtifactScope,
        page_size: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        Self::new_at(scope, page_size, cursor, Utc::now())
    }

    pub fn new_at(
        scope: &HcpPackerArtifactScope,
        page_size: u16,
        cursor: Option<OpaqueCursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(HcpPackerArtifactResultError::InvalidRequest);
        }
        let subject_digest = scope.version_fingerprint().digest();
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate_against(
                scope,
                HcpPackerOperation::ListBuilds.as_str(),
                &subject_digest,
                observed_at,
            )?;
        }
        let page_number = cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        if page_number > MAX_PAGES {
            return Err(HcpPackerArtifactResultError::PaginationExceeded);
        }
        let request_digest = Digest::from_parts(
            "hcp-packer-list-builds-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("subject", subject_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |cursor| {
                        cursor.token_digest().as_str().to_owned()
                    }),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            cursor,
            request_digest,
            observed_at,
        })
    }

    pub fn scope(&self) -> &HcpPackerArtifactScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn redacted_path(&self) -> String {
        format!(
            "/packer/2023-01-01/organizations/{}/projects/{}/buckets/{}/versions/{}/builds?pageSize={}&pageTokenDigest={}",
            self.scope.organization_id().digest().as_str(),
            self.scope.project_id().digest().as_str(),
            self.scope.bucket_name().digest().as_str(),
            self.scope.version_fingerprint().digest().as_str(),
            self.page_size,
            self.cursor()
                .map_or("", |cursor| cursor.token_digest().as_str())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: HcpPackerOperation::ListBuilds,
            scope_digest: self.scope.digest(),
            subject_digest: Some(self.scope.version_fingerprint().digest()),
            cursor_digest: self.cursor().map(|cursor| cursor.token_digest().clone()),
            page_number: Some(self.page_number()),
            request_digest: self.request_digest.clone(),
            method: "GET".to_owned(),
            redacted: true,
        }
    }
}

impl fmt::Debug for ListBuildsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListBuildsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListArtifactsRequest {
    scope: HcpPackerArtifactScope,
    build_digest: Digest,
    page_size: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
    observed_at: DateTime<Utc>,
}

impl ListArtifactsRequest {
    pub fn new(
        scope: &HcpPackerArtifactScope,
        build_id: impl AsRef<str>,
        page_size: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        Self::new_at(scope, build_id, page_size, cursor, Utc::now())
    }

    pub fn new_at(
        scope: &HcpPackerArtifactScope,
        build_id: impl AsRef<str>,
        page_size: u16,
        cursor: Option<OpaqueCursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        let build_id = build_id.as_ref();
        if build_id.is_empty() || build_id.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(HcpPackerArtifactResultError::InvalidRequest);
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(HcpPackerArtifactResultError::InvalidRequest);
        }
        let build_digest = Digest::from_text(build_id);
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate_against(
                scope,
                HcpPackerOperation::ListArtifacts.as_str(),
                &build_digest,
                observed_at,
            )?;
        }
        let page_number = cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        if page_number > MAX_PAGES {
            return Err(HcpPackerArtifactResultError::PaginationExceeded);
        }
        let request_digest = Digest::from_parts(
            "hcp-packer-list-artifacts-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("build", build_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |cursor| {
                        cursor.token_digest().as_str().to_owned()
                    }),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            build_digest,
            page_size,
            cursor,
            request_digest,
            observed_at,
        })
    }

    pub fn scope(&self) -> &HcpPackerArtifactScope {
        &self.scope
    }

    pub fn build_digest(&self) -> &Digest {
        &self.build_digest
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn redacted_path(&self) -> String {
        format!(
            "/packer/2023-01-01/organizations/{}/projects/{}/buckets/{}/builds/{}/artifacts?pageSize={}&pageTokenDigest={}",
            self.scope.organization_id().digest().as_str(),
            self.scope.project_id().digest().as_str(),
            self.scope.bucket_name().digest().as_str(),
            self.build_digest.as_str(),
            self.page_size,
            self.cursor()
                .map_or("", |cursor| cursor.token_digest().as_str())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: HcpPackerOperation::ListArtifacts,
            scope_digest: self.scope.digest(),
            subject_digest: Some(self.build_digest.clone()),
            cursor_digest: self.cursor().map(|cursor| cursor.token_digest().clone()),
            page_number: Some(self.page_number()),
            request_digest: self.request_digest.clone(),
            method: "GET".to_owned(),
            redacted: true,
        }
    }
}

impl fmt::Debug for ListArtifactsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListArtifactsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("build_digest", &self.build_digest)
            .field("page_size", &self.page_size)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

pub trait HcpPackerTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_bucket(
        &mut self,
        request: &GetBucketRequest,
    ) -> std::result::Result<BucketResponse, HcpPackerTransportError>;

    fn get_channel(
        &mut self,
        request: &GetChannelRequest,
    ) -> std::result::Result<ChannelResponse, HcpPackerTransportError>;

    fn get_version(
        &mut self,
        request: &GetVersionRequest,
    ) -> std::result::Result<VersionResponse, HcpPackerTransportError>;

    fn list_builds(
        &mut self,
        request: &ListBuildsRequest,
    ) -> std::result::Result<BuildPageResponse, HcpPackerTransportError>;

    fn list_artifacts(
        &mut self,
        request: &ListArtifactsRequest,
    ) -> std::result::Result<ArtifactPageResponse, HcpPackerTransportError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct BucketResponse {
    pub bucket: BucketMetadataInput,
    pub response_bytes: usize,
    pub provider_revision: u64,
    request_digest: Digest,
    declared_digest: Digest,
}

impl BucketResponse {
    pub fn new(
        request: &GetBucketRequest,
        bucket: BucketMetadataInput,
        response_bytes: usize,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            bucket,
            response_bytes,
            provider_revision: 1,
            request_digest: request.request_digest().clone(),
            declared_digest: Digest::zero(),
        };
        response.declared_digest = response.compute_digest();
        Ok(response)
    }

    pub fn with_provider_revision(mut self, provider_revision: u64) -> Self {
        self.provider_revision = provider_revision;
        self.declared_digest = self.compute_digest();
        self
    }

    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    pub fn declared_digest(&self) -> &Digest {
        &self.declared_digest
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-bucket-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("id", self.bucket.id.clone()),
                ("organization", self.bucket.organization_id.clone()),
                ("project", self.bucket.project_id.clone()),
                ("name", self.bucket.name.clone()),
                ("state", self.bucket.state.clone()),
                ("versions", self.bucket.version_count.to_string()),
                ("provider_revision", self.provider_revision.to_string()),
            ],
        )
    }

    fn validate_integrity(&self, request: &GetBucketRequest, provider_revision: u64) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.request_digest != *request.request_digest()
            || self.provider_revision != provider_revision
            || self.declared_digest != self.compute_digest()
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for BucketResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BucketResponse")
            .field("bucket", &self.bucket)
            .field("response_bytes", &self.response_bytes)
            .field("provider_revision", &self.provider_revision)
            .field("declared_digest", &self.declared_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ChannelResponse {
    pub channel: ChannelMetadataInput,
    pub response_bytes: usize,
    pub provider_revision: u64,
    request_digest: Digest,
    declared_digest: Digest,
}

impl ChannelResponse {
    pub fn new(
        request: &GetChannelRequest,
        channel: ChannelMetadataInput,
        response_bytes: usize,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            channel,
            response_bytes,
            provider_revision: 1,
            request_digest: request.request_digest().clone(),
            declared_digest: Digest::zero(),
        };
        response.declared_digest = response.compute_digest();
        Ok(response)
    }

    pub fn with_provider_revision(mut self, provider_revision: u64) -> Self {
        self.provider_revision = provider_revision;
        self.declared_digest = self.compute_digest();
        self
    }

    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-channel-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("name", self.channel.name.clone()),
                (
                    "assigned",
                    self.channel
                        .assigned_version_fingerprint
                        .clone()
                        .unwrap_or_default(),
                ),
                ("revision", self.channel.revision.to_string()),
                ("state", self.channel.state.clone()),
                ("provider_revision", self.provider_revision.to_string()),
            ],
        )
    }

    fn validate_integrity(
        &self,
        request: &GetChannelRequest,
        provider_revision: u64,
    ) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.request_digest != *request.request_digest()
            || self.provider_revision != provider_revision
            || self.declared_digest != self.compute_digest()
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for ChannelResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelResponse")
            .field("channel", &self.channel)
            .field("response_bytes", &self.response_bytes)
            .field("provider_revision", &self.provider_revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VersionResponse {
    pub version: VersionMetadataInput,
    pub response_bytes: usize,
    pub provider_revision: u64,
    request_digest: Digest,
    declared_digest: Digest,
}

impl VersionResponse {
    pub fn new(
        request: &GetVersionRequest,
        version: VersionMetadataInput,
        response_bytes: usize,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            version,
            response_bytes,
            provider_revision: 1,
            request_digest: request.request_digest().clone(),
            declared_digest: Digest::zero(),
        };
        response.declared_digest = response.compute_digest();
        Ok(response)
    }

    pub fn with_provider_revision(mut self, provider_revision: u64) -> Self {
        self.provider_revision = provider_revision;
        self.declared_digest = self.compute_digest();
        self
    }

    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-version-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("id", self.version.id.clone()),
                ("fingerprint", self.version.fingerprint.clone()),
                ("revision", self.version.revision.to_string()),
                ("state", self.version.state.clone()),
                ("build_count", self.version.build_count.to_string()),
                ("provider_revision", self.provider_revision.to_string()),
            ],
        )
    }

    fn validate_integrity(
        &self,
        request: &GetVersionRequest,
        provider_revision: u64,
    ) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.request_digest != *request.request_digest()
            || self.provider_revision != provider_revision
            || self.declared_digest != self.compute_digest()
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for VersionResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionResponse")
            .field("version", &self.version)
            .field("response_bytes", &self.response_bytes)
            .field("provider_revision", &self.provider_revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BuildPageResponse {
    pub builds: Vec<crate::model::BuildMetadataInput>,
    pub next_cursor: Option<OpaqueCursor>,
    pub page_number: u16,
    pub response_bytes: usize,
    pub provider_revision: u64,
    request_digest: Digest,
    declared_digest: Digest,
}

impl BuildPageResponse {
    pub fn new(
        request: &ListBuildsRequest,
        builds: Vec<crate::model::BuildMetadataInput>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if builds.len() > crate::MAX_BUILDS {
            return Err(HcpPackerArtifactResultError::Invalid {
                field: "build page size",
            });
        }
        let mut response = Self {
            builds,
            next_cursor,
            page_number: request.page_number(),
            response_bytes,
            provider_revision: 1,
            request_digest: request.request_digest().clone(),
            declared_digest: Digest::zero(),
        };
        response.declared_digest = response.compute_digest();
        Ok(response)
    }

    pub fn with_provider_revision(mut self, provider_revision: u64) -> Self {
        self.provider_revision = provider_revision;
        self.declared_digest = self.compute_digest();
        self
    }

    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    fn compute_digest(&self) -> Digest {
        let ids = self
            .builds
            .iter()
            .map(|build| build.id.as_str())
            .collect::<Vec<_>>()
            .join("\u{1f}");
        Digest::from_parts(
            "hcp-packer-build-page-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                ("build_ids", ids),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("provider_revision", self.provider_revision.to_string()),
            ],
        )
    }

    fn validate_integrity(
        &self,
        request: &ListBuildsRequest,
        provider_revision: u64,
    ) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.page_number != request.page_number()
            || self.request_digest != *request.request_digest()
            || self.provider_revision != provider_revision
            || self.declared_digest != self.compute_digest()
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(
                request.scope(),
                HcpPackerOperation::ListBuilds.as_str(),
                &request.scope().version_fingerprint().digest(),
                request.observed_at(),
            )?;
        }
        Ok(())
    }
}

impl fmt::Debug for BuildPageResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildPageResponse")
            .field("build_count", &self.builds.len())
            .field("next_cursor", &self.next_cursor)
            .field("page_number", &self.page_number)
            .field("response_bytes", &self.response_bytes)
            .field("provider_revision", &self.provider_revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactPageResponse {
    pub artifacts: Vec<ArtifactMetadataInput>,
    pub next_cursor: Option<OpaqueCursor>,
    pub page_number: u16,
    pub response_bytes: usize,
    pub provider_revision: u64,
    request_digest: Digest,
    declared_digest: Digest,
}

impl ArtifactPageResponse {
    pub fn new(
        request: &ListArtifactsRequest,
        artifacts: Vec<ArtifactMetadataInput>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if artifacts.len() > crate::MAX_ARTIFACTS {
            return Err(HcpPackerArtifactResultError::Invalid {
                field: "artifact page size",
            });
        }
        let mut response = Self {
            artifacts,
            next_cursor,
            page_number: request.page_number(),
            response_bytes,
            provider_revision: 1,
            request_digest: request.request_digest().clone(),
            declared_digest: Digest::zero(),
        };
        response.declared_digest = response.compute_digest();
        Ok(response)
    }

    pub fn with_provider_revision(mut self, provider_revision: u64) -> Self {
        self.provider_revision = provider_revision;
        self.declared_digest = self.compute_digest();
        self
    }

    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    fn compute_digest(&self) -> Digest {
        let ids = self
            .artifacts
            .iter()
            .map(|artifact| artifact.id.as_str())
            .collect::<Vec<_>>()
            .join("\u{1f}");
        Digest::from_parts(
            "hcp-packer-artifact-page-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                ("artifact_ids", ids),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("provider_revision", self.provider_revision.to_string()),
            ],
        )
    }

    fn validate_integrity(
        &self,
        request: &ListArtifactsRequest,
        provider_revision: u64,
    ) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.page_number != request.page_number()
            || self.request_digest != *request.request_digest()
            || self.provider_revision != provider_revision
            || self.declared_digest != self.compute_digest()
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(
                request.scope(),
                HcpPackerOperation::ListArtifacts.as_str(),
                request.build_digest(),
                request.observed_at(),
            )?;
        }
        Ok(())
    }
}

impl fmt::Debug for ArtifactPageResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactPageResponse")
            .field("artifact_count", &self.artifacts.len())
            .field("next_cursor", &self.next_cursor)
            .field("page_number", &self.page_number)
            .field("response_bytes", &self.response_bytes)
            .field("provider_revision", &self.provider_revision)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HcpPackerProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub release: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub external_writes: bool,
}

impl HcpPackerProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() {
            return Err(HcpPackerArtifactResultError::ProviderDrift);
        }
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            release,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_digest: Digest::zero(),
            api_digest: Digest::from_text(PROVIDER_API_REVISION),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            external_writes: false,
        };
        definition.provider_digest = definition.compute_digest();
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.api_revision != PROVIDER_API_REVISION
            || self.api_digest != Digest::from_text(PROVIDER_API_REVISION)
            || self.provider_digest != self.compute_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.external_writes
        {
            return Err(HcpPackerArtifactResultError::ProviderDrift);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-provider/v1",
            &[
                ("provider_id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("release", self.release.clone()),
                ("api", self.api_revision.clone()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("external_writes", self.external_writes.to_string()),
            ],
        )
    }
}

pub struct HcpPackerProvider<T = BlockedEnvTransport> {
    definition: HcpPackerProviderDefinition,
    transport: T,
}

impl<T: fmt::Debug + HcpPackerTransport> fmt::Debug for HcpPackerProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HcpPackerProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: HcpPackerTransport> HcpPackerProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, PLUGIN_VERSION)
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            definition: HcpPackerProviderDefinition::new(provider_revision, release)?,
            transport,
        })
    }

    pub fn definition(&self) -> &HcpPackerProviderDefinition {
        &self.definition
    }

    pub fn definition_mut(&mut self) -> &mut HcpPackerProviderDefinition {
        &mut self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get_bucket(&mut self, request: &GetBucketRequest) -> Result<BucketResponse> {
        self.definition.validate()?;
        let response = self.transport.get_bucket(request)?;
        response.validate_integrity(request, self.definition.provider_revision)?;
        Ok(response)
    }

    pub fn get_channel(&mut self, request: &GetChannelRequest) -> Result<ChannelResponse> {
        self.definition.validate()?;
        let response = self.transport.get_channel(request)?;
        response.validate_integrity(request, self.definition.provider_revision)?;
        Ok(response)
    }

    pub fn get_version(&mut self, request: &GetVersionRequest) -> Result<VersionResponse> {
        self.definition.validate()?;
        let response = self.transport.get_version(request)?;
        response.validate_integrity(request, self.definition.provider_revision)?;
        Ok(response)
    }

    pub fn list_builds(&mut self, request: &ListBuildsRequest) -> Result<BuildPageResponse> {
        self.definition.validate()?;
        let response = self.transport.list_builds(request)?;
        response.validate_integrity(request, self.definition.provider_revision)?;
        Ok(response)
    }

    pub fn list_artifacts(
        &mut self,
        request: &ListArtifactsRequest,
    ) -> Result<ArtifactPageResponse> {
        self.definition.validate()?;
        let response = self.transport.list_artifacts(request)?;
        response.validate_integrity(request, self.definition.provider_revision)?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for HcpPackerProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("default HCP Packer provider identity is valid")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    bucket_responses: VecDeque<std::result::Result<BucketResponse, HcpPackerTransportError>>,
    channel_responses: VecDeque<std::result::Result<ChannelResponse, HcpPackerTransportError>>,
    version_responses: VecDeque<std::result::Result<VersionResponse, HcpPackerTransportError>>,
    build_responses: VecDeque<std::result::Result<BuildPageResponse, HcpPackerTransportError>>,
    artifact_responses:
        VecDeque<std::result::Result<ArtifactPageResponse, HcpPackerTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            bucket_responses: VecDeque::new(),
            channel_responses: VecDeque::new(),
            version_responses: VecDeque::new(),
            build_responses: VecDeque::new(),
            artifact_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn fake() -> Self {
        Self::new(TransportProvenance::Fake)
    }

    pub fn push_bucket_response(
        &mut self,
        response: std::result::Result<BucketResponse, HcpPackerTransportError>,
    ) {
        self.bucket_responses.push_back(response);
    }

    pub fn push_channel_response(
        &mut self,
        response: std::result::Result<ChannelResponse, HcpPackerTransportError>,
    ) {
        self.channel_responses.push_back(response);
    }

    pub fn push_version_response(
        &mut self,
        response: std::result::Result<VersionResponse, HcpPackerTransportError>,
    ) {
        self.version_responses.push_back(response);
    }

    pub fn push_build_response(
        &mut self,
        response: std::result::Result<BuildPageResponse, HcpPackerTransportError>,
    ) {
        self.build_responses.push_back(response);
    }

    pub fn push_artifact_response(
        &mut self,
        response: std::result::Result<ArtifactPageResponse, HcpPackerTransportError>,
    ) {
        self.artifact_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn take<T>(
        queue: &mut VecDeque<std::result::Result<T, HcpPackerTransportError>>,
    ) -> std::result::Result<T, HcpPackerTransportError> {
        queue
            .pop_front()
            .unwrap_or(Err(HcpPackerTransportError::ProviderUnknown))
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl HcpPackerTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_bucket(
        &mut self,
        request: &GetBucketRequest,
    ) -> std::result::Result<BucketResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.bucket_responses)
    }

    fn get_channel(
        &mut self,
        request: &GetChannelRequest,
    ) -> std::result::Result<ChannelResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.channel_responses)
    }

    fn get_version(
        &mut self,
        request: &GetVersionRequest,
    ) -> std::result::Result<VersionResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.version_responses)
    }

    fn list_builds(
        &mut self,
        request: &ListBuildsRequest,
    ) -> std::result::Result<BuildPageResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.build_responses)
    }

    fn list_artifacts(
        &mut self,
        request: &ListArtifactsRequest,
    ) -> std::result::Result<ArtifactPageResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.artifact_responses)
    }
}

pub type FakeTransport = RecordingTransport;

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: HcpPackerArtifactScope,
    observed_at: DateTime<Utc>,
    requests: Vec<RecordedRequest>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &HcpPackerArtifactScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn bucket(&self) -> BucketMetadataInput {
        BucketMetadataInput::new(
            "01HCPBUCKET0000000000000000",
            self.scope.organization_id().as_str(),
            self.scope.project_id().as_str(),
            self.scope.bucket_name().as_str(),
            "ACTIVE",
            1,
            std::iter::once(("environment".to_owned(), "fixture".to_owned())).collect(),
        )
    }

    fn channel(&self) -> ChannelMetadataInput {
        ChannelMetadataInput::new(
            self.scope.channel_name().as_str(),
            Some(self.scope.version_fingerprint().as_str().to_owned()),
            self.scope.channel_revision().value(),
            "ACTIVE",
        )
    }

    fn version(&self) -> VersionMetadataInput {
        VersionMetadataInput::new(
            "01HCPVERSION000000000000000",
            self.scope.version_fingerprint().as_str(),
            self.scope.version_revision().value(),
            "VERSION_ACTIVE",
            1,
            std::iter::once(("owner".to_owned(), "fixture".to_owned())).collect(),
            self.observed_at,
            self.observed_at,
        )
    }

    fn build(&self) -> crate::model::BuildMetadataInput {
        crate::model::BuildMetadataInput::new(
            "01HCPBUILD00000000000000000",
            self.scope.version_fingerprint().as_str(),
            "amazon-ebs",
            "BUILD_SUCCESS",
            Some("https://private.example.invalid/artifact".to_owned()),
            self.scope.cloud().as_str(),
            self.scope.region().as_str(),
            std::iter::once(("pipeline".to_owned(), "fixture".to_owned())).collect(),
            Some("fixture build log must never cross the evidence boundary".to_owned()),
            self.observed_at,
            self.observed_at,
        )
    }

    fn artifact(&self) -> ArtifactMetadataInput {
        ArtifactMetadataInput::new(
            "01HCPARTIFACT00000000000000",
            "01HCPBUILD00000000000000000",
            self.scope.version_fingerprint().as_str(),
            self.scope.cloud().as_str(),
            self.scope.region().as_str(),
            Some("ami-private-location-should-not-leak".to_owned()),
            "READY",
            std::iter::once(("artifact-label".to_owned(), "fixture".to_owned())).collect(),
            self.observed_at,
            self.observed_at,
        )
    }
}

impl HcpPackerTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_bucket(
        &mut self,
        request: &GetBucketRequest,
    ) -> std::result::Result<BucketResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        BucketResponse::new(request, self.bucket(), 512)
            .map_err(|_| HcpPackerTransportError::MalformedResponse)
    }

    fn get_channel(
        &mut self,
        request: &GetChannelRequest,
    ) -> std::result::Result<ChannelResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        ChannelResponse::new(request, self.channel(), 512)
            .map_err(|_| HcpPackerTransportError::MalformedResponse)
    }

    fn get_version(
        &mut self,
        request: &GetVersionRequest,
    ) -> std::result::Result<VersionResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        VersionResponse::new(request, self.version(), 512)
            .map_err(|_| HcpPackerTransportError::MalformedResponse)
    }

    fn list_builds(
        &mut self,
        request: &ListBuildsRequest,
    ) -> std::result::Result<BuildPageResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        BuildPageResponse::new(request, vec![self.build()], None, 768)
            .map_err(|_| HcpPackerTransportError::MalformedResponse)
    }

    fn list_artifacts(
        &mut self,
        request: &ListArtifactsRequest,
    ) -> std::result::Result<ArtifactPageResponse, HcpPackerTransportError> {
        self.requests.push(request.recorded_request());
        ArtifactPageResponse::new(request, vec![self.artifact()], None, 768)
            .map_err(|_| HcpPackerTransportError::MalformedResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &HcpPackerArtifactScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl HcpPackerTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_bucket(
        &mut self,
        request: &GetBucketRequest,
    ) -> std::result::Result<BucketResponse, HcpPackerTransportError> {
        self.fixture.get_bucket(request)
    }

    fn get_channel(
        &mut self,
        request: &GetChannelRequest,
    ) -> std::result::Result<ChannelResponse, HcpPackerTransportError> {
        self.fixture.get_channel(request)
    }

    fn get_version(
        &mut self,
        request: &GetVersionRequest,
    ) -> std::result::Result<VersionResponse, HcpPackerTransportError> {
        self.fixture.get_version(request)
    }

    fn list_builds(
        &mut self,
        request: &ListBuildsRequest,
    ) -> std::result::Result<BuildPageResponse, HcpPackerTransportError> {
        self.fixture.list_builds(request)
    }

    fn list_artifacts(
        &mut self,
        request: &ListArtifactsRequest,
    ) -> std::result::Result<ArtifactPageResponse, HcpPackerTransportError> {
        self.fixture.list_artifacts(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl HcpPackerTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_bucket(
        &mut self,
        _request: &GetBucketRequest,
    ) -> std::result::Result<BucketResponse, HcpPackerTransportError> {
        Err(HcpPackerTransportError::BlockedEnvironment)
    }

    fn get_channel(
        &mut self,
        _request: &GetChannelRequest,
    ) -> std::result::Result<ChannelResponse, HcpPackerTransportError> {
        Err(HcpPackerTransportError::BlockedEnvironment)
    }

    fn get_version(
        &mut self,
        _request: &GetVersionRequest,
    ) -> std::result::Result<VersionResponse, HcpPackerTransportError> {
        Err(HcpPackerTransportError::BlockedEnvironment)
    }

    fn list_builds(
        &mut self,
        _request: &ListBuildsRequest,
    ) -> std::result::Result<BuildPageResponse, HcpPackerTransportError> {
        Err(HcpPackerTransportError::BlockedEnvironment)
    }

    fn list_artifacts(
        &mut self,
        _request: &ListArtifactsRequest,
    ) -> std::result::Result<ArtifactPageResponse, HcpPackerTransportError> {
        Err(HcpPackerTransportError::BlockedEnvironment)
    }
}
