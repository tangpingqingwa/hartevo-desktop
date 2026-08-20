//! Typed, bounded AWS Security Hub finding evidence.
//!
//! This module intentionally models only the small, normalized projection
//! needed by a Layer-1 mission. It does not contain provider JSON, access
//! tokens, SigV4 material, remediation bodies, or arbitrary filter documents.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_SECURITY_HUB_API_VERSION, AWS_SECURITY_HUB_CONTRACT_VERSION,
    AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_FILTER_VALUES: usize = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_FINDINGS: usize = 400;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    InvalidValue { field: &'static str },
    #[error("{field} exceeds the configured bound")]
    BoundExceeded { field: &'static str },
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidValue { field });
    }
    Ok(())
}

macro_rules! bounded_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_id!(AwsAccountId, "AWS account id");
bounded_id!(AwsRegion, "AWS region");
bounded_id!(ProductId, "Security Hub product ARN");
bounded_id!(SourceId, "finding source id");
bounded_id!(FindingId, "finding id");
bounded_id!(ResourceId, "finding resource id");
bounded_id!(ProjectId, "Hartevo project id");
bounded_id!(MissionId, "Mission id");
bounded_id!(WorkProductId, "Work Product id");

/// Short aliases keep the typed scope ergonomic without collapsing its fields
/// into untyped strings.
pub type AccountId = AwsAccountId;
pub type Region = AwsRegion;
pub type ProductArn = ProductId;
pub type FindingSourceId = SourceId;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(value)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields<T: AsRef<str>>(namespace: &str, fields: &[T]) -> Self {
        let mut canonical = format!("{namespace}\0");
        for field in fields {
            let value = field.as_ref();
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\0');
        }
        Self::from_text(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn sha256_digest(value: &[u8]) -> Digest {
    Digest::from_bytes(value)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| ModelError::InvalidValue {
            field: "canonical digest input",
        })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }
}

/// A Project/Mission/Work Product and AWS finding scope fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsSecurityHubScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub product_arn: ProductId,
    pub source_id: SourceId,
    pub finding_id: FindingId,
    pub resource_id: ResourceId,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
}

impl AwsSecurityHubScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        product_arn: ProductId,
        source_id: SourceId,
        finding_id: FindingId,
        resource_id: ResourceId,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
    ) -> Self {
        Self {
            account_id,
            region,
            product_arn,
            source_id,
            finding_id,
            resource_id,
            project_id,
            project_revision: Revision(1),
            mission_id,
            mission_revision: Revision(1),
            work_product_id,
            work_product_revision: Revision(1),
            permission_digest: Digest::from_text(crate::AWS_SECURITY_HUB_IAM_PERMISSION),
        }
    }

    #[must_use]
    pub fn with_revisions(
        mut self,
        project_revision: Revision,
        mission_revision: Revision,
        work_product_revision: Revision,
    ) -> Self {
        self.project_revision = project_revision;
        self.mission_revision = mission_revision;
        self.work_product_revision = work_product_revision;
        self
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("AwsSecurityHubScope is serializable")
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn product(&self) -> &ProductId {
        &self.product_arn
    }

    pub fn source(&self) -> &SourceId {
        &self.source_id
    }

    pub fn finding(&self) -> &FindingId {
        &self.finding_id
    }

    pub fn resource(&self) -> &ResourceId {
        &self.resource_id
    }

    pub fn project(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product_id
    }

    #[must_use]
    pub fn with_permission_digest(mut self, permission_digest: Digest) -> Self {
        self.permission_digest = permission_digest;
        self
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

/// Host-owned credential identity. The raw reference is deliberately private
/// and the type intentionally does not implement Serialize or Deserialize.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: Revision,
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AwsSecurityHubScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(&reference_id, "SigV4 secret reference")?;
        let credential_revision = Revision::new(credential_revision)?;
        Ok(Self {
            reference_id,
            scope_digest: scope.digest(),
            credential_revision,
        })
    }

    pub fn from_scope_digest(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(&reference_id, "SigV4 secret reference")?;
        Ok(Self {
            reference_id,
            scope_digest,
            credential_revision: Revision::new(credential_revision)?,
        })
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.sigv4-secret-reference/v1",
            &[
                self.reference_id.clone(),
                self.scope_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
            ],
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn is_for_scope(&self, scope: &AwsSecurityHubScope) -> bool {
        self.scope_digest == scope.digest()
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SigV4SecretReference({})",
            self.reference_digest()
        )
    }
}

pub type SecretReference = SigV4SecretReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    InProgress,
    Resolved,
    Suppressed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingResourceMetadata {
    pub resource_id: ResourceId,
    pub resource_type: String,
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub tags_digest: Option<Digest>,
}

impl FindingResourceMetadata {
    pub fn new(
        resource_id: ResourceId,
        resource_type: impl Into<String>,
        account_id: AwsAccountId,
        region: AwsRegion,
    ) -> Result<Self, ModelError> {
        let resource_type = resource_type.into();
        validate_text(&resource_type, "resource type")?;
        Ok(Self {
            resource_id,
            resource_type,
            account_id,
            region,
            tags_digest: None,
        })
    }

    #[must_use]
    pub fn with_tags_digest(mut self, tags_digest: Digest) -> Self {
        self.tags_digest = Some(tags_digest);
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedFindingField {
    Description,
    Remediation,
    ProductFields,
    UserDefinedFields,
    RawProviderPayload,
    ProviderAccessToken,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub redacted_fields: Vec<RedactedFindingField>,
    pub raw_provider_payload_retained: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            redacted_fields: vec![
                RedactedFindingField::Description,
                RedactedFindingField::Remediation,
                RedactedFindingField::ProductFields,
                RedactedFindingField::UserDefinedFields,
                RedactedFindingField::RawProviderPayload,
                RedactedFindingField::ProviderAccessToken,
            ],
            raw_provider_payload_retained: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityHubFinding {
    pub finding_id: FindingId,
    pub product_arn: ProductId,
    pub source_id: SourceId,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub resource: FindingResourceMetadata,
    pub redaction: RedactionSummary,
    pub finding_digest: Digest,
}

pub type AwsSecurityHubFinding = SecurityHubFinding;

impl SecurityHubFinding {
    pub fn new(
        finding_id: FindingId,
        product_arn: ProductId,
        source_id: SourceId,
        severity: FindingSeverity,
        status: FindingStatus,
        resource: FindingResourceMetadata,
    ) -> Result<Self, ModelError> {
        let mut finding = Self {
            finding_id,
            product_arn,
            source_id,
            severity,
            status,
            resource,
            redaction: RedactionSummary::default(),
            finding_digest: Digest::from_text("pending-finding-digest"),
        };
        finding.finding_digest = finding.compute_digest()?;
        Ok(finding)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.finding_id,
            &self.product_arn,
            &self.source_id,
            self.severity,
            self.status,
            &self.resource,
            &self.redaction,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.redaction.raw_provider_payload_retained
            || !self
                .redaction
                .redacted_fields
                .contains(&RedactedFindingField::RawProviderPayload)
        {
            return Err(ModelError::InvalidValue {
                field: "finding redaction",
            });
        }
        if self.finding_digest != self.compute_digest()? {
            return Err(ModelError::InvalidDigest {
                field: "finding digest",
            });
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &AwsSecurityHubScope) -> bool {
        self.finding_id == scope.finding_id
            && self.product_arn == scope.product_arn
            && self.source_id == scope.source_id
            && self.resource.resource_id == scope.resource_id
            && self.resource.account_id == scope.account_id
            && self.resource.region == scope.region
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingFilter {
    severities: Vec<FindingSeverity>,
    statuses: Vec<FindingStatus>,
    resource_types: Vec<String>,
    resource_id: Option<ResourceId>,
    source_id: Option<SourceId>,
}

impl FindingFilter {
    pub fn all() -> Self {
        Self::default()
    }

    pub fn with_severity(mut self, severity: FindingSeverity) -> Result<Self, ModelError> {
        Self::add_unique(&mut self.severities, severity)?;
        Ok(self)
    }

    pub fn with_status(mut self, status: FindingStatus) -> Result<Self, ModelError> {
        Self::add_unique(&mut self.statuses, status)?;
        Ok(self)
    }

    pub fn with_resource_type(
        mut self,
        resource_type: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let resource_type = resource_type.into();
        validate_text(&resource_type, "resource type filter")?;
        if !self.resource_types.contains(&resource_type) {
            if self.resource_types.len() >= MAX_FILTER_VALUES {
                return Err(ModelError::BoundExceeded {
                    field: "resource type filters",
                });
            }
            self.resource_types.push(resource_type);
        }
        Ok(self)
    }

    #[must_use]
    pub fn for_resource(mut self, resource_id: ResourceId) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    #[must_use]
    pub fn for_source(mut self, source_id: SourceId) -> Self {
        self.source_id = Some(source_id);
        self
    }

    fn add_unique<T: Eq>(values: &mut Vec<T>, value: T) -> Result<(), ModelError> {
        if !values.contains(&value) {
            if values.len() >= MAX_FILTER_VALUES {
                return Err(ModelError::BoundExceeded {
                    field: "finding filters",
                });
            }
            values.push(value);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("FindingFilter is serializable")
    }

    pub fn matches(&self, finding: &SecurityHubFinding) -> bool {
        (self.severities.is_empty() || self.severities.contains(&finding.severity))
            && (self.statuses.is_empty() || self.statuses.contains(&finding.status))
            && (self.resource_types.is_empty()
                || self
                    .resource_types
                    .contains(&finding.resource.resource_type))
            && self
                .resource_id
                .as_ref()
                .is_none_or(|resource_id| resource_id == &finding.resource.resource_id)
            && self
                .source_id
                .as_ref()
                .is_none_or(|source_id| source_id == &finding.source_id)
    }

    pub fn severities(&self) -> &[FindingSeverity] {
        &self.severities
    }

    pub fn statuses(&self) -> &[FindingStatus] {
        &self.statuses
    }

    pub fn resource_types(&self) -> &[String] {
        &self.resource_types
    }

    pub fn resource_id(&self) -> Option<&ResourceId> {
        self.resource_id.as_ref()
    }

    pub fn source_id(&self) -> Option<&SourceId> {
        self.source_id.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OpaquePageToken {
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(provider_token: impl AsRef<str>) -> Result<Self, ModelError> {
        let provider_token = provider_token.as_ref();
        validate_text(provider_token, "provider page token")?;
        Ok(Self {
            digest: Digest::from_text(provider_token),
        })
    }

    pub fn from_digest(digest: Digest) -> Self {
        Self { digest }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GetFindingsApi {
    GetFindings,
    GetFindingsV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageBinding {
    pub api: GetFindingsApi,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetFindingsRequest {
    api: GetFindingsApi,
    scope_digest: Digest,
    filter: FindingFilter,
    page_number: u16,
    page_size: u16,
    page_token: Option<OpaquePageToken>,
    filter_digest: Digest,
    page_digest: Digest,
    request_digest: Digest,
}

pub type GetFindingsV2Request = GetFindingsRequest;

impl GetFindingsRequest {
    pub fn new(
        scope: &AwsSecurityHubScope,
        filter: FindingFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        Self::for_api(scope, GetFindingsApi::GetFindings, filter, page_size)
    }

    pub fn v2(
        scope: &AwsSecurityHubScope,
        filter: FindingFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        Self::for_api(scope, GetFindingsApi::GetFindingsV2, filter, page_size)
    }

    fn for_api(
        scope: &AwsSecurityHubScope,
        api: GetFindingsApi,
        filter: FindingFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::BoundExceeded { field: "page size" });
        }
        Self::build(scope.digest(), api, filter, page_size, 1, None)
    }

    fn build(
        scope_digest: Digest,
        api: GetFindingsApi,
        filter: FindingFilter,
        page_size: u16,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "page number",
            });
        }
        let filter_digest = filter.digest();
        let page_token_digest = page_token.as_ref().map(|token| token.digest().clone());
        let page_digest = digest_serializable(&(api, page_number, page_size, &page_token_digest))?;
        let request_digest =
            digest_serializable(&(api, &scope_digest, &filter_digest, &page_digest))?;
        Ok(Self {
            api,
            scope_digest,
            filter,
            page_number,
            page_size,
            page_token,
            filter_digest,
            page_digest,
            request_digest,
        })
    }

    pub fn next_page(&self, page_token: OpaquePageToken) -> Result<Self, ModelError> {
        Self::build(
            self.scope_digest.clone(),
            self.api,
            self.filter.clone(),
            self.page_size,
            self.page_number.saturating_add(1),
            Some(page_token),
        )
    }

    pub const fn api(&self) -> GetFindingsApi {
        self.api
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter(&self) -> &FindingFilter {
        &self.filter
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn page_digest(&self) -> &Digest {
        &self.page_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn binding(&self) -> PageBinding {
        PageBinding {
            api: self.api,
            scope_digest: self.scope_digest.clone(),
            filter_digest: self.filter_digest.clone(),
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsReadRequest {
    api: GetFindingsApi,
    filter: FindingFilter,
    page_size: u16,
    max_pages: u16,
    max_findings: usize,
}

impl FindingsReadRequest {
    pub fn new(
        filter: FindingFilter,
        page_size: u16,
        max_pages: u16,
        max_findings: usize,
    ) -> Result<Self, ModelError> {
        Self::for_api(
            GetFindingsApi::GetFindings,
            filter,
            page_size,
            max_pages,
            max_findings,
        )
    }

    pub fn v2(
        filter: FindingFilter,
        page_size: u16,
        max_pages: u16,
        max_findings: usize,
    ) -> Result<Self, ModelError> {
        Self::for_api(
            GetFindingsApi::GetFindingsV2,
            filter,
            page_size,
            max_pages,
            max_findings,
        )
    }

    fn for_api(
        api: GetFindingsApi,
        filter: FindingFilter,
        page_size: u16,
        max_pages: u16,
        max_findings: usize,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::BoundExceeded { field: "page size" });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::BoundExceeded { field: "max pages" });
        }
        if max_findings == 0 || max_findings > MAX_FINDINGS {
            return Err(ModelError::BoundExceeded {
                field: "max findings",
            });
        }
        Ok(Self {
            api,
            filter,
            page_size,
            max_pages,
            max_findings,
        })
    }

    pub fn bounded(filter: FindingFilter) -> Result<Self, ModelError> {
        Self::new(filter, MAX_PAGE_SIZE, MAX_PAGES, MAX_FINDINGS)
    }

    pub const fn api(&self) -> GetFindingsApi {
        self.api
    }

    pub fn filter(&self) -> &FindingFilter {
        &self.filter
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn max_findings(&self) -> usize {
        self.max_findings
    }

    pub fn first_page(
        &self,
        scope: &AwsSecurityHubScope,
    ) -> Result<GetFindingsRequest, ModelError> {
        match self.api {
            GetFindingsApi::GetFindings => {
                GetFindingsRequest::new(scope, self.filter.clone(), self.page_size)
            }
            GetFindingsApi::GetFindingsV2 => {
                GetFindingsRequest::v2(scope, self.filter.clone(), self.page_size)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLossKind {
    BlockedEnv,
    AccessDenied,
    CredentialUnavailable,
    ProviderUnavailable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessLossEvidence {
    pub kind: AccessLossKind,
    pub provider_code: String,
    pub after_page: u16,
    pub detail_digest: Digest,
}

impl AccessLossEvidence {
    pub fn new(
        kind: AccessLossKind,
        provider_code: impl Into<String>,
        after_page: u16,
    ) -> Result<Self, ModelError> {
        let provider_code = provider_code.into();
        validate_text(&provider_code, "provider access-loss code")?;
        Ok(Self {
            kind,
            detail_digest: Digest::from_text(&provider_code),
            provider_code,
            after_page,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    ProviderMarkedPartial,
    PageLimitReached,
    FindingLimitReached,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetFindingsPage {
    pub binding: PageBinding,
    pub findings: Vec<SecurityHubFinding>,
    pub next_page: Option<OpaquePageToken>,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
    pub provider_revision: String,
    pub response_digest: Digest,
}

impl GetFindingsPage {
    pub fn new(
        request: &GetFindingsRequest,
        findings: Vec<SecurityHubFinding>,
        next_page: Option<OpaquePageToken>,
        partial: bool,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if findings.len() > usize::from(request.page_size()) {
            return Err(ModelError::BoundExceeded {
                field: "findings per page",
            });
        }
        let provider_revision = provider_revision.into();
        validate_text(&provider_revision, "provider revision")?;
        let mut page = Self {
            binding: request.binding(),
            findings,
            next_page,
            partial,
            access_loss: None,
            provider_revision,
            response_digest: Digest::from_text("pending-response-digest"),
        };
        page.response_digest = page.compute_digest()?;
        Ok(page)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.binding,
            &self.findings,
            &self.next_page,
            self.partial,
            &self.access_loss,
            &self.provider_revision,
        ))
    }

    pub fn with_access_loss(mut self, access_loss: AccessLossEvidence) -> Result<Self, ModelError> {
        self.partial = true;
        self.access_loss = Some(access_loss);
        self.response_digest = self.compute_digest()?;
        Ok(self)
    }

    pub fn validate_for(&self, request: &GetFindingsRequest) -> Result<(), ModelError> {
        if self.binding != request.binding() {
            return Err(ModelError::InvalidValue {
                field: "finding page binding",
            });
        }
        if self.findings.len() > usize::from(request.page_size())
            || self
                .findings
                .iter()
                .any(|finding| finding.validate().is_err())
        {
            return Err(ModelError::BoundExceeded {
                field: "finding page",
            });
        }
        if self.response_digest != self.compute_digest()? {
            return Err(ModelError::InvalidDigest {
                field: "response digest",
            });
        }
        Ok(())
    }
}

pub type GetFindingsResponse = GetFindingsPage;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsEvidence {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub credential_revision: Revision,
    pub request_digest: Digest,
    pub filter_digest: Digest,
    pub page_bindings: Vec<PageBinding>,
    pub page_response_digests: Vec<Digest>,
    pub findings: Vec<SecurityHubFinding>,
    pub provenance: ProviderProvenance,
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub access_loss: Option<AccessLossEvidence>,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct FindingsEvidenceDigestInput<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_revision: &'a str,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    credential_revision: Revision,
    request_digest: &'a Digest,
    filter_digest: &'a Digest,
    page_bindings: &'a [PageBinding],
    page_response_digests: &'a [Digest],
    findings: &'a [SecurityHubFinding],
    provenance: ProviderProvenance,
    status: EvidenceStatus,
    partial_reason: &'a Option<PartialReason>,
    access_loss: &'a Option<AccessLossEvidence>,
    redaction: &'a RedactionSummary,
}

impl FindingsEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_revision: String,
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
        credential_revision: Revision,
        request_digest: Digest,
        filter_digest: Digest,
        page_bindings: Vec<PageBinding>,
        page_response_digests: Vec<Digest>,
        findings: Vec<SecurityHubFinding>,
        provenance: ProviderProvenance,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        access_loss: Option<AccessLossEvidence>,
    ) -> Result<Self, ModelError> {
        if page_bindings.is_empty() || page_bindings.len() > usize::from(MAX_PAGES) {
            return Err(ModelError::BoundExceeded {
                field: "evidence pages",
            });
        }
        if page_bindings.len() != page_response_digests.len() {
            return Err(ModelError::InvalidValue {
                field: "page evidence digests",
            });
        }
        if findings.len() > MAX_FINDINGS {
            return Err(ModelError::BoundExceeded {
                field: "evidence findings",
            });
        }
        match status {
            EvidenceStatus::Complete if partial_reason.is_some() || access_loss.is_some() => {
                return Err(ModelError::InvalidValue {
                    field: "complete evidence status",
                });
            }
            EvidenceStatus::Partial if partial_reason.is_none() => {
                return Err(ModelError::InvalidValue {
                    field: "partial evidence reason",
                });
            }
            EvidenceStatus::AccessLost if access_loss.is_none() => {
                return Err(ModelError::InvalidValue {
                    field: "access-loss evidence",
                });
            }
            _ => {}
        }
        validate_text(&provider_revision, "provider revision")?;
        let mut evidence = Self {
            plugin_version: AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_SECURITY_HUB_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_revision,
            provider_digest,
            permission_digest,
            scope_digest,
            registration_digest,
            credential_revision,
            request_digest,
            filter_digest,
            page_bindings,
            page_response_digests,
            findings,
            provenance,
            status,
            partial_reason,
            access_loss,
            redaction: RedactionSummary::default(),
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        evidence.evidence_digest = evidence.compute_digest()?;
        Ok(evidence)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&FindingsEvidenceDigestInput {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            credential_revision: self.credential_revision,
            request_digest: &self.request_digest,
            filter_digest: &self.filter_digest,
            page_bindings: &self.page_bindings,
            page_response_digests: &self.page_response_digests,
            findings: &self.findings,
            provenance: self.provenance,
            status: self.status,
            partial_reason: &self.partial_reason,
            access_loss: &self.access_loss,
            redaction: &self.redaction,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.plugin_version != AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT
            || self.contract_version != AWS_SECURITY_HUB_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.redaction.raw_provider_payload_retained
            || self.page_bindings.is_empty()
            || self.page_bindings.len() > usize::from(MAX_PAGES)
            || self.page_bindings.len() != self.page_response_digests.len()
            || self.findings.len() > MAX_FINDINGS
            || (self.status == EvidenceStatus::Complete
                && (self.partial_reason.is_some() || self.access_loss.is_some()))
            || (self.status == EvidenceStatus::Partial && self.partial_reason.is_none())
            || (self.status == EvidenceStatus::AccessLost && self.access_loss.is_none())
            || self.page_bindings.iter().any(|binding| {
                binding.scope_digest != self.scope_digest
                    || binding.filter_digest != self.filter_digest
                    || binding.api != self.page_bindings[0].api
            })
            || self
                .findings
                .iter()
                .any(|finding| finding.validate().is_err())
            || self.evidence_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "finding evidence",
            });
        }
        Ok(())
    }

    pub fn digests(&self) -> EvidenceDigests {
        EvidenceDigests {
            contract_digest: self.contract_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            evidence_digest: self.evidence_digest.clone(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.status == EvidenceStatus::Complete
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsProposal {
    pub evidence: FindingsEvidence,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl FindingsProposal {
    pub fn new(evidence: FindingsEvidence) -> Result<Self, ModelError> {
        evidence.validate()?;
        let proposal_digest = digest_serializable(&(
            &evidence.evidence_digest,
            &evidence.scope_digest,
            &evidence.registration_digest,
        ))?;
        Ok(Self {
            evidence,
            proposal_digest,
            read_only: true,
            native: false,
            connected: false,
            outcome_authority: false,
            work_product_adoption: false,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.evidence.validate()?;
        let expected = digest_serializable(&(
            &self.evidence.evidence_digest,
            &self.evidence.scope_digest,
            &self.evidence.registration_digest,
        ))?;
        if self.proposal_digest != expected
            || !self.read_only
            || self.native
            || self.connected
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(ModelError::InvalidValue {
                field: "finding proposal authority",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub record_digest: Digest,
    pub durable: bool,
    pub verified: bool,
    pub adopted: bool,
}

impl FindingsRecord {
    pub fn new(proposal: &FindingsProposal) -> Result<Self, ModelError> {
        proposal.validate()?;
        let mut record = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            registration_digest: proposal.evidence.registration_digest.clone(),
            record_digest: Digest::from_text("pending-record-digest"),
            durable: false,
            verified: false,
            adopted: false,
        };
        record.record_digest = digest_serializable(&(
            &record.proposal_digest,
            &record.evidence_digest,
            &record.scope_digest,
            &record.registration_digest,
            record.durable,
            record.verified,
            record.adopted,
        ))?;
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    VerifiedReadOnly,
    PartialEvidence,
    AccessLost,
    Revoked,
    Tampered,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsVerification {
    pub record_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub status: VerificationStatus,
    pub accepted: bool,
    pub independent_live_readback: bool,
    pub native: bool,
    pub outcome_authority: bool,
}

impl FindingsVerification {
    pub fn from_record(
        record: &FindingsRecord,
        evidence: &FindingsEvidence,
    ) -> Result<Self, ModelError> {
        evidence.validate()?;
        let status = match evidence.status {
            EvidenceStatus::Complete => VerificationStatus::VerifiedReadOnly,
            EvidenceStatus::Partial => VerificationStatus::PartialEvidence,
            EvidenceStatus::AccessLost => VerificationStatus::AccessLost,
        };
        Ok(Self {
            record_digest: record.record_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            accepted: evidence.status == EvidenceStatus::Complete,
            status,
            independent_live_readback: false,
            native: false,
            outcome_authority: false,
        })
    }
}

pub const fn aws_security_hub_api_version() -> &'static str {
    AWS_SECURITY_HUB_API_VERSION
}
