//! Metadata-only AWS CodeArtifact provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver,
//! HTTP client, package-byte path, publish/delete/status mutation, or
//! arbitrary dependency-graph retention in this Layer-1 crate.

use std::{collections::VecDeque, fmt, fmt::Write as _};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{AwsCodeArtifactProvenanceError, AwsCodeArtifactTransportError, Result};
use crate::model::{
    AwsCodeArtifactProvenanceScope, Cursor, DependencyMetadataInput, DependencySummary, Digest,
    PackageVersionFilter, PackageVersionObservation, TransportProvenance,
};
use crate::{CONTRACT_VERSION, PROVIDER_API_REVISION, PROVIDER_API_VERSION, PROVIDER_ID};

pub const LIST_PACKAGE_VERSIONS_OPERATION_PATH: &str = "/v1/package/versions";
pub const DESCRIBE_PACKAGE_VERSION_OPERATION_PATH: &str = "/v1/package";
pub const LIST_PACKAGE_VERSION_DEPENDENCIES_OPERATION_PATH: &str =
    "/v1/package/version/dependencies";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsCodeArtifactOperation {
    ListPackageVersions,
    DescribePackageVersion,
    ListPackageVersionDependencies,
}

impl AwsCodeArtifactOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListPackageVersions => "ListPackageVersions",
            Self::DescribePackageVersion => "DescribePackageVersion",
            Self::ListPackageVersionDependencies => "ListPackageVersionDependencies",
        }
    }
}

pub trait AwsCodeArtifactTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_package_versions(
        &mut self,
        request: &ListPackageVersionsRequest,
    ) -> std::result::Result<ListPackageVersionsResponse, AwsCodeArtifactTransportError>;

    fn describe_package_version(
        &mut self,
        request: &DescribePackageVersionRequest,
    ) -> std::result::Result<DescribePackageVersionResponse, AwsCodeArtifactTransportError>;

    fn list_package_version_dependencies(
        &mut self,
        request: &ListPackageVersionDependenciesRequest,
    ) -> std::result::Result<ListPackageVersionDependenciesResponse, AwsCodeArtifactTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsCodeArtifactOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListPackageVersionsRequest {
    scope: AwsCodeArtifactProvenanceScope,
    filter: PackageVersionFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListPackageVersionsRequest {
    pub fn new(
        scope: &AwsCodeArtifactProvenanceScope,
        filter: PackageVersionFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate()?;
        let binding_digest = Self::pagination_binding(scope, &filter);
        if let Some(cursor) = &cursor {
            cursor.validate_against(&binding_digest)?;
        }
        let request_digest = Digest::from_parts(
            "aws-codeartifact-list-package-versions-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            cursor: cursor.clone(),
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsCodeArtifactProvenanceScope {
        &self.scope
    }

    pub fn filter(&self) -> &PackageVersionFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn pagination_binding_digest(&self) -> Digest {
        Self::pagination_binding(&self.scope, &self.filter)
    }

    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            ("domain", self.scope.domain().as_str().to_owned()),
            ("domain-owner", self.scope.account().as_str().to_owned()),
            ("repository", self.scope.repository().as_str().to_owned()),
            ("format", self.scope.format().as_str().to_owned()),
            ("package", self.scope.package().as_str().to_owned()),
            ("maxResults", self.filter.max_results.to_string()),
            ("sortBy", self.filter.sort_by.as_api().to_owned()),
        ];
        if let Some(namespace) = self.scope.namespace() {
            query.push(("namespace", namespace.as_str().to_owned()));
        }
        if let Some(status) = self.filter.status {
            query.push(("status", status.as_api().to_owned()));
        }
        if let Some(cursor) = &self.cursor {
            query.push(("nextToken", cursor.token().to_owned()));
        }
        let query = query
            .into_iter()
            .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{LIST_PACKAGE_VERSIONS_OPERATION_PATH}?{query}")
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCodeArtifactOperation::ListPackageVersions,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }

    fn pagination_binding(
        scope: &AwsCodeArtifactProvenanceScope,
        filter: &PackageVersionFilter,
    ) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-package-version-pagination/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for ListPackageVersionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListPackageVersionsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribePackageVersionRequest {
    scope: AwsCodeArtifactProvenanceScope,
    request_digest: Digest,
}

impl DescribePackageVersionRequest {
    pub fn for_scope(scope: &AwsCodeArtifactProvenanceScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-codeartifact-describe-package-version-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("version", scope.version().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsCodeArtifactProvenanceScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            ("domain", self.scope.domain().as_str().to_owned()),
            ("domain-owner", self.scope.account().as_str().to_owned()),
            ("repository", self.scope.repository().as_str().to_owned()),
            ("format", self.scope.format().as_str().to_owned()),
            ("package", self.scope.package().as_str().to_owned()),
            ("version", self.scope.version().as_str().to_owned()),
        ];
        if let Some(namespace) = self.scope.namespace() {
            query.push(("namespace", namespace.as_str().to_owned()));
        }
        let query = query
            .into_iter()
            .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{DESCRIBE_PACKAGE_VERSION_OPERATION_PATH}?{query}")
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCodeArtifactOperation::DescribePackageVersion,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribePackageVersionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribePackageVersionRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListPackageVersionDependenciesRequest {
    scope: AwsCodeArtifactProvenanceScope,
    max_results: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListPackageVersionDependenciesRequest {
    pub fn new(
        scope: &AwsCodeArtifactProvenanceScope,
        max_results: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        if !(1..=crate::MAX_PAGE_SIZE).contains(&max_results) {
            return Err(AwsCodeArtifactProvenanceError::InvalidRequest);
        }
        let binding_digest = Self::pagination_binding(scope, max_results);
        if let Some(cursor) = &cursor {
            cursor.validate_against(&binding_digest)?;
        }
        Ok(Self {
            scope: scope.clone(),
            max_results,
            cursor: cursor.clone(),
            request_digest: Digest::from_parts(
                "aws-codeartifact-list-package-version-dependencies-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("max_results", max_results.to_string()),
                    (
                        "cursor",
                        cursor.as_ref().map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                    ),
                    (
                        "page",
                        cursor.as_ref().map_or_else(
                            || "1".to_owned(),
                            |value| value.page_number().to_string(),
                        ),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsCodeArtifactProvenanceScope {
        &self.scope
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn pagination_binding_digest(&self) -> Digest {
        Self::pagination_binding(&self.scope, self.max_results)
    }

    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            ("domain", self.scope.domain().as_str().to_owned()),
            ("domain-owner", self.scope.account().as_str().to_owned()),
            ("repository", self.scope.repository().as_str().to_owned()),
            ("format", self.scope.format().as_str().to_owned()),
            ("package", self.scope.package().as_str().to_owned()),
            ("version", self.scope.version().as_str().to_owned()),
            ("maxResults", self.max_results.to_string()),
        ];
        if let Some(namespace) = self.scope.namespace() {
            query.push(("namespace", namespace.as_str().to_owned()));
        }
        if let Some(cursor) = &self.cursor {
            query.push(("nextToken", cursor.token().to_owned()));
        }
        let query = query
            .into_iter()
            .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{LIST_PACKAGE_VERSION_DEPENDENCIES_OPERATION_PATH}?{query}")
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCodeArtifactOperation::ListPackageVersionDependencies,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }

    fn pagination_binding(scope: &AwsCodeArtifactProvenanceScope, max_results: u16) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-dependency-pagination/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("max_results", max_results.to_string()),
            ],
        )
    }
}

impl fmt::Debug for ListPackageVersionDependenciesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListPackageVersionDependenciesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("max_results", &self.max_results)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPackageVersionsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub versions: Vec<PackageVersionObservation>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl ListPackageVersionsResponse {
    pub fn new(
        request: &ListPackageVersionsRequest,
        versions: Vec<PackageVersionObservation>,
        next_cursor: Option<Cursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.filter.validate()?;
        if response_bytes > crate::MAX_RESPONSE_BYTES
            || versions.len() > usize::from(request.filter.max_results)
        {
            return Err(AwsCodeArtifactProvenanceError::PartialEvidence);
        }
        for version in &versions {
            version.validate()?;
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(&request.pagination_binding_digest())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCodeArtifactProvenanceError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope.digest(),
            filter_digest: request.filter.digest(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number(),
            versions,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-codeartifact-list-response"),
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub const fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn recomputed_digest(&self) -> Digest {
        let version_digests = self
            .versions
            .iter()
            .map(|version| version.metadata_digest().as_str().to_owned())
            .collect::<Vec<_>>()
            .join("|");
        Digest::from_parts(
            "aws-codeartifact-list-package-versions-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                ("versions", version_digests),
                (
                    "next_cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self, request: &ListPackageVersionsRequest) -> Result<()> {
        if self.scope_digest != request.scope.digest()
            || self.filter_digest != request.filter.digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.versions.len() > usize::from(request.filter.max_results)
            || self.response_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        for version in &self.versions {
            version.validate()?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(&request.pagination_binding_digest())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCodeArtifactProvenanceError::CursorMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribePackageVersionResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub package_version: PackageVersionObservation,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl DescribePackageVersionResponse {
    pub fn new(
        request: &DescribePackageVersionRequest,
        package_version: PackageVersionObservation,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if response_bytes > crate::MAX_RESPONSE_BYTES
            || package_version.version() != request.scope().version()
        {
            return Err(AwsCodeArtifactProvenanceError::RevisionMismatch);
        }
        package_version.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            package_version,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-codeartifact-describe-response"),
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-describe-package-version-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "metadata",
                    self.package_version.metadata_digest().as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self, request: &DescribePackageVersionRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.package_version.version() != request.scope().version()
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.response_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        self.package_version.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPackageVersionDependenciesResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub dependencies: DependencySummary,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl ListPackageVersionDependenciesResponse {
    pub fn new(
        request: &ListPackageVersionDependenciesRequest,
        items: Vec<DependencyMetadataInput>,
        next_cursor: Option<Cursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(AwsCodeArtifactProvenanceError::PartialEvidence);
        }
        if items.len() > usize::from(request.max_results) {
            return Err(AwsCodeArtifactProvenanceError::PartialEvidence);
        }
        let dependencies = DependencySummary::from_items(&items, next_cursor.is_some())?;
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(&request.pagination_binding_digest())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCodeArtifactProvenanceError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            dependencies,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-codeartifact-dependency-response"),
        };
        response.response_digest = response.recomputed_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub const fn is_complete(&self) -> bool {
        self.next_cursor.is_none() && self.dependencies.is_complete()
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-list-package-version-dependencies-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "dependencies",
                    self.dependencies.dependency_digest.as_str().to_owned(),
                ),
                ("count", self.dependencies.dependency_count.to_string()),
                ("truncated", self.dependencies.truncated.to_string()),
                (
                    "next_cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(
        &self,
        request: &ListPackageVersionDependenciesRequest,
    ) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.response_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        self.dependencies.dependency_digest.validate()?;
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(&request.pagination_binding_digest())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCodeArtifactProvenanceError::CursorMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodeArtifactProviderDefinition {
    pub provider_id: String,
    pub api_version: String,
    pub api_revision: String,
    pub provider_revision: u64,
    pub release: String,
    pub provider_digest: Digest,
}

impl AwsCodeArtifactProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.trim().is_empty() {
            return Err(AwsCodeArtifactProvenanceError::ProviderDrift);
        }
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            api_version: PROVIDER_API_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_revision,
            release,
            provider_digest: Digest::from_text("unsealed-codeartifact-provider"),
        };
        definition.provider_digest = definition.recomputed_digest();
        Ok(definition)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-provider-definition/v1",
            &[
                ("id", self.provider_id.clone()),
                ("api_version", self.api_version.clone()),
                ("api_revision", self.api_revision.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("release", self.release.clone()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_version != PROVIDER_API_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
            || self.release.trim().is_empty()
            || self.provider_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::ProviderDrift);
        }
        Ok(())
    }
}

pub struct AwsCodeArtifactProvider<T> {
    transport: T,
    definition: AwsCodeArtifactProviderDefinition,
}

impl<T: AwsCodeArtifactTransport> fmt::Debug for AwsCodeArtifactProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodeArtifactProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .finish_non_exhaustive()
    }
}

impl<T: AwsCodeArtifactTransport> AwsCodeArtifactProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(
            transport,
            AwsCodeArtifactProviderDefinition::new(1, "1.0.0")?,
        )
    }

    pub fn with_identity(
        transport: T,
        definition: AwsCodeArtifactProviderDefinition,
    ) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsCodeArtifactProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_package_versions(
        &mut self,
        request: &ListPackageVersionsRequest,
    ) -> Result<ListPackageVersionsResponse> {
        self.definition.validate()?;
        let response = self.transport.list_package_versions(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn describe_package_version(
        &mut self,
        request: &DescribePackageVersionRequest,
    ) -> Result<DescribePackageVersionResponse> {
        self.definition.validate()?;
        let response = self.transport.describe_package_version(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn list_package_version_dependencies(
        &mut self,
        request: &ListPackageVersionDependenciesRequest,
    ) -> Result<ListPackageVersionDependenciesResponse> {
        self.definition.validate()?;
        let response = self.transport.list_package_version_dependencies(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsCodeArtifactProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("static blocked environment provider definition")
    }
}

impl<T: AwsCodeArtifactTransport> AwsCodeArtifactProvider<T> {
    pub fn from_registration(
        transport: T,
        registration: &crate::service::AwsCodeArtifactProvenanceRegistration,
    ) -> Result<Self> {
        let definition = AwsCodeArtifactProviderDefinition::new(
            registration.provider_revision(),
            registration.provider_release(),
        )?;
        if definition.provider_digest != *registration.provider_digest() {
            return Err(AwsCodeArtifactProvenanceError::ProviderDrift);
        }
        Self::with_identity(transport, definition)
    }
}

#[derive(Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListPackageVersionsResponse, AwsCodeArtifactTransportError>>,
    describe_responses: VecDeque<
        std::result::Result<DescribePackageVersionResponse, AwsCodeArtifactTransportError>,
    >,
    dependency_responses: VecDeque<
        std::result::Result<ListPackageVersionDependenciesResponse, AwsCodeArtifactTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            describe_responses: VecDeque::new(),
            dependency_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListPackageVersionsResponse, AwsCodeArtifactTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_describe_response(
        &mut self,
        response: std::result::Result<
            DescribePackageVersionResponse,
            AwsCodeArtifactTransportError,
        >,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn push_dependency_response(
        &mut self,
        response: std::result::Result<
            ListPackageVersionDependenciesResponse,
            AwsCodeArtifactTransportError,
        >,
    ) {
        self.dependency_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsCodeArtifactTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_package_versions(
        &mut self,
        request: &ListPackageVersionsRequest,
    ) -> std::result::Result<ListPackageVersionsResponse, AwsCodeArtifactTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsCodeArtifactTransportError::InvalidResponse))
    }

    fn describe_package_version(
        &mut self,
        request: &DescribePackageVersionRequest,
    ) -> std::result::Result<DescribePackageVersionResponse, AwsCodeArtifactTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_responses
            .pop_front()
            .unwrap_or(Err(AwsCodeArtifactTransportError::InvalidResponse))
    }

    fn list_package_version_dependencies(
        &mut self,
        request: &ListPackageVersionDependenciesRequest,
    ) -> std::result::Result<ListPackageVersionDependenciesResponse, AwsCodeArtifactTransportError>
    {
        self.requests.push(request.recorded_request());
        self.dependency_responses
            .pop_front()
            .unwrap_or(Err(AwsCodeArtifactTransportError::InvalidResponse))
    }
}

#[derive(Debug)]
pub struct FixtureTransport {
    inner: RecordingTransport,
}

impl FixtureTransport {
    pub fn for_scope(
        scope: &AwsCodeArtifactProvenanceScope,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Ok(Self {
            inner: fixture_recording(scope, observed_at, TransportProvenance::Fixture)?,
        })
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl AwsCodeArtifactTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn list_package_versions(
        &mut self,
        request: &ListPackageVersionsRequest,
    ) -> std::result::Result<ListPackageVersionsResponse, AwsCodeArtifactTransportError> {
        self.inner.list_package_versions(request)
    }

    fn describe_package_version(
        &mut self,
        request: &DescribePackageVersionRequest,
    ) -> std::result::Result<DescribePackageVersionResponse, AwsCodeArtifactTransportError> {
        self.inner.describe_package_version(request)
    }

    fn list_package_version_dependencies(
        &mut self,
        request: &ListPackageVersionDependenciesRequest,
    ) -> std::result::Result<ListPackageVersionDependenciesResponse, AwsCodeArtifactTransportError>
    {
        self.inner.list_package_version_dependencies(request)
    }
}

#[derive(Debug)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn for_scope(
        scope: &AwsCodeArtifactProvenanceScope,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Ok(Self {
            inner: fixture_recording(scope, observed_at, TransportProvenance::Loopback)?,
        })
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl AwsCodeArtifactTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn list_package_versions(
        &mut self,
        request: &ListPackageVersionsRequest,
    ) -> std::result::Result<ListPackageVersionsResponse, AwsCodeArtifactTransportError> {
        self.inner.list_package_versions(request)
    }

    fn describe_package_version(
        &mut self,
        request: &DescribePackageVersionRequest,
    ) -> std::result::Result<DescribePackageVersionResponse, AwsCodeArtifactTransportError> {
        self.inner.describe_package_version(request)
    }

    fn list_package_version_dependencies(
        &mut self,
        request: &ListPackageVersionDependenciesRequest,
    ) -> std::result::Result<ListPackageVersionDependenciesResponse, AwsCodeArtifactTransportError>
    {
        self.inner.list_package_version_dependencies(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsCodeArtifactTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_package_versions(
        &mut self,
        _request: &ListPackageVersionsRequest,
    ) -> std::result::Result<ListPackageVersionsResponse, AwsCodeArtifactTransportError> {
        Err(AwsCodeArtifactTransportError::BlockedEnv)
    }

    fn describe_package_version(
        &mut self,
        _request: &DescribePackageVersionRequest,
    ) -> std::result::Result<DescribePackageVersionResponse, AwsCodeArtifactTransportError> {
        Err(AwsCodeArtifactTransportError::BlockedEnv)
    }

    fn list_package_version_dependencies(
        &mut self,
        _request: &ListPackageVersionDependenciesRequest,
    ) -> std::result::Result<ListPackageVersionDependenciesResponse, AwsCodeArtifactTransportError>
    {
        Err(AwsCodeArtifactTransportError::BlockedEnv)
    }
}

fn fixture_recording(
    scope: &AwsCodeArtifactProvenanceScope,
    observed_at: DateTime<Utc>,
    provenance: TransportProvenance,
) -> Result<RecordingTransport> {
    let filter = PackageVersionFilter::all(10)?;
    let list_request = ListPackageVersionsRequest::new(scope, filter, None)?;
    let describe_request = DescribePackageVersionRequest::for_scope(scope)?;
    let dependency_request = ListPackageVersionDependenciesRequest::new(scope, 10, None)?;
    let package_arn = format!(
        "arn:aws:codeartifact:{}:{}:package/{}/{}/{}/{}/{}",
        scope.region().as_str(),
        scope.account().as_str(),
        scope.domain().as_str(),
        scope.repository().as_str(),
        scope.format().as_str(),
        scope.package().as_str(),
        scope.version().as_str()
    );
    let metadata = PackageVersionObservation::new(
        scope.version().clone(),
        "fixture-revision",
        crate::model::PackageOrigin::Internal,
        crate::model::PackageVersionStatus::Published,
        Some(observed_at),
        3,
        Some(package_arn),
    )?;
    let dependencies = vec![DependencyMetadataInput::new(
        None,
        crate::model::PackageName::new("fixture-dependency")?,
        "^1.0.0",
    )?];
    let list_response = ListPackageVersionsResponse::new(
        &list_request,
        vec![metadata.clone()],
        None,
        512,
        provenance,
    )?;
    let describe_response =
        DescribePackageVersionResponse::new(&describe_request, metadata, 512, provenance)?;
    let dependency_response = ListPackageVersionDependenciesResponse::new(
        &dependency_request,
        dependencies,
        None,
        512,
        provenance,
    )?;
    let mut transport = RecordingTransport::new(provenance);
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    transport.push_dependency_response(Ok(dependency_response));
    Ok(transport)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}
