use std::{collections::BTreeSet, fmt};

use crate::error::{Result, SodaQualityResultError};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_SECRET_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_CHECKS: usize = 32;
pub const MAX_METRICS: usize = 32;
pub const MAX_AGGREGATE_ROWS: u64 = 1_000_000_000;
pub const MAX_METRIC_VALUE: u64 = 1_000_000_000_000;
pub const MAX_RECEIPTS: usize = 4;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 32;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(SodaQualityResultError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(SodaQualityResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-$".contains(&byte))
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(SodaQualityResultError::InvalidIdentifier {
                field: "soda identifier",
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts("soda-identifier/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0) {
            Ok(())
        } else {
            Err(SodaQualityResultError::InvalidIdentifier {
                field: "soda identifier",
            })
        }
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identifier")
            .field(&format_args!(
                "{}:{}",
                "redacted",
                &self.digest().as_str()[..16]
            ))
            .finish()
    }
}

pub type SodaOrganizationId = Identifier;
pub type SodaDataSourceId = Identifier;
pub type SodaDatasetId = Identifier;
pub type SodaCheckId = Identifier;
pub type SodaScanId = Identifier;
pub type SodaMetricId = Identifier;
pub type OrganizationId = Identifier;
pub type DataSourceId = Identifier;
pub type DatasetId = Identifier;
pub type CheckId = Identifier;
pub type ScanId = Identifier;
pub type MetricId = Identifier;
pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(SodaQualityResultError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn next(self) -> Result<Self> {
        Self::new(
            self.0
                .checked_add(1)
                .ok_or(SodaQualityResultError::InvalidRevision {
                    field: "registration revision",
                })?,
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResourceBinding {
    id: Identifier,
    revision: Revision,
}

impl ResourceBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "soda-resource-binding/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self, field: &'static str) -> Result<()> {
        self.id
            .validate()
            .map_err(|_| SodaQualityResultError::InvalidScope(field))?;
        Revision::new(self.revision.get())
            .map_err(|_| SodaQualityResultError::InvalidScope(field))?;
        Ok(())
    }
}

impl fmt::Debug for ResourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceBinding")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl Serialize for ResourceBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ResourceBinding", 3)?;
        state.serialize_field("idDigest", &self.id_digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("bindingDigest", &self.digest())?;
        state.end()
    }
}

pub type SodaOrganizationBinding = ResourceBinding;
pub type SodaDataSourceBinding = ResourceBinding;
pub type SodaDatasetBinding = ResourceBinding;
pub type SodaCheckBinding = ResourceBinding;
pub type SodaScanBinding = ResourceBinding;
pub type SodaMetricBinding = ResourceBinding;
pub type ProjectBinding = ResourceBinding;
pub type MissionBinding = ResourceBinding;
pub type WorkProductBinding = ResourceBinding;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SodaQualityScopeSpec {
    pub organization: SodaOrganizationBinding,
    pub data_source: SodaDataSourceBinding,
    pub dataset: SodaDatasetBinding,
    pub check: SodaCheckBinding,
    pub scan: SodaScanBinding,
    pub metric: SodaMetricBinding,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
}

#[allow(clippy::too_many_arguments)]
impl SodaQualityScopeSpec {
    #[must_use]
    pub fn new(
        organization: SodaOrganizationBinding,
        data_source: SodaDataSourceBinding,
        dataset: SodaDatasetBinding,
        check: SodaCheckBinding,
        scan: SodaScanBinding,
        metric: SodaMetricBinding,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Self {
        Self {
            organization,
            data_source,
            dataset,
            check,
            scan,
            metric,
            project,
            mission,
            work_product,
        }
    }

    pub fn from_identifiers(
        organization: impl Into<String>,
        data_source: impl Into<String>,
        dataset: impl Into<String>,
        check: impl Into<String>,
        scan: impl Into<String>,
        metric: impl Into<String>,
        project: impl Into<String>,
        mission: impl Into<String>,
        work_product: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        Ok(Self::new(
            ResourceBinding::new(organization, revision)?,
            ResourceBinding::new(data_source, revision)?,
            ResourceBinding::new(dataset, revision)?,
            ResourceBinding::new(check, revision)?,
            ResourceBinding::new(scan, revision)?,
            ResourceBinding::new(metric, revision)?,
            ResourceBinding::new(project, revision)?,
            ResourceBinding::new(mission, revision)?,
            ResourceBinding::new(work_product, revision)?,
        ))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SodaQualityScope {
    organization: SodaOrganizationBinding,
    data_source: SodaDataSourceBinding,
    dataset: SodaDatasetBinding,
    check: SodaCheckBinding,
    scan: SodaScanBinding,
    metric: SodaMetricBinding,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    scope_digest: Digest,
    revision_digest: Digest,
}

impl SodaQualityScope {
    pub fn new(spec: SodaQualityScopeSpec) -> Result<Self> {
        let bindings = [
            (&spec.organization, "organization"),
            (&spec.data_source, "data_source"),
            (&spec.dataset, "dataset"),
            (&spec.check, "check"),
            (&spec.scan, "scan"),
            (&spec.metric, "metric"),
            (&spec.project, "project"),
            (&spec.mission, "mission"),
            (&spec.work_product, "work_product"),
        ];
        for (binding, field) in bindings {
            binding.validate(field)?;
        }
        let mut digests = BTreeSet::new();
        for binding in [
            &spec.organization,
            &spec.data_source,
            &spec.dataset,
            &spec.check,
            &spec.scan,
            &spec.metric,
            &spec.project,
            &spec.mission,
            &spec.work_product,
        ] {
            if !digests.insert(binding.digest()) {
                return Err(SodaQualityResultError::InvalidScope("duplicate binding"));
            }
        }
        let scope_digest = calculate_scope_digest(&spec);
        let revision_digest = calculate_revision_digest(&spec);
        let scope = Self {
            organization: spec.organization,
            data_source: spec.data_source,
            dataset: spec.dataset,
            check: spec.check,
            scan: spec.scan,
            metric: spec.metric,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            scope_digest,
            revision_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_identifiers(
        organization: impl Into<String>,
        data_source: impl Into<String>,
        dataset: impl Into<String>,
        check: impl Into<String>,
        scan: impl Into<String>,
        metric: impl Into<String>,
        project: impl Into<String>,
        mission: impl Into<String>,
        work_product: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        Self::new(SodaQualityScopeSpec::from_identifiers(
            organization,
            data_source,
            dataset,
            check,
            scan,
            metric,
            project,
            mission,
            work_product,
            revision,
        )?)
    }

    #[must_use]
    pub fn organization(&self) -> &SodaOrganizationBinding {
        &self.organization
    }

    #[must_use]
    pub fn data_source(&self) -> &SodaDataSourceBinding {
        &self.data_source
    }

    #[must_use]
    pub fn dataset(&self) -> &SodaDatasetBinding {
        &self.dataset
    }

    #[must_use]
    pub fn check(&self) -> &SodaCheckBinding {
        &self.check
    }

    #[must_use]
    pub fn scan(&self) -> &SodaScanBinding {
        &self.scan
    }

    #[must_use]
    pub fn metric(&self) -> &SodaMetricBinding {
        &self.metric
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub fn validate(&self) -> Result<()> {
        let spec = SodaQualityScopeSpec::new(
            self.organization.clone(),
            self.data_source.clone(),
            self.dataset.clone(),
            self.check.clone(),
            self.scan.clone(),
            self.metric.clone(),
            self.project.clone(),
            self.mission.clone(),
            self.work_product.clone(),
        );
        if self.scope_digest != calculate_scope_digest(&spec)
            || self.revision_digest != calculate_revision_digest(&spec)
        {
            return Err(SodaQualityResultError::InvalidScope("scope digest"));
        }
        Ok(())
    }
}

impl fmt::Debug for SodaQualityScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SodaQualityScope")
            .field("scope_digest", &self.scope_digest)
            .field("revision_digest", &self.revision_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for SodaQualityScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SodaQualityScope", 11)?;
        state.serialize_field("organizationDigest", &self.organization.digest())?;
        state.serialize_field("dataSourceDigest", &self.data_source.digest())?;
        state.serialize_field("datasetDigest", &self.dataset.digest())?;
        state.serialize_field("checkDigest", &self.check.digest())?;
        state.serialize_field("scanDigest", &self.scan.digest())?;
        state.serialize_field("metricDigest", &self.metric.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("revisionDigest", &self.revision_digest)?;
        state.end()
    }
}

fn calculate_scope_digest(spec: &SodaQualityScopeSpec) -> Digest {
    Digest::from_parts(
        "soda-quality-scope/v1",
        &[
            (
                "organization",
                spec.organization.digest().as_str().to_owned(),
            ),
            ("data_source", spec.data_source.digest().as_str().to_owned()),
            ("dataset", spec.dataset.digest().as_str().to_owned()),
            ("check", spec.check.digest().as_str().to_owned()),
            ("scan", spec.scan.digest().as_str().to_owned()),
            ("metric", spec.metric.digest().as_str().to_owned()),
            ("project", spec.project.digest().as_str().to_owned()),
            ("mission", spec.mission.digest().as_str().to_owned()),
            (
                "work_product",
                spec.work_product.digest().as_str().to_owned(),
            ),
        ],
    )
}

fn calculate_revision_digest(spec: &SodaQualityScopeSpec) -> Digest {
    Digest::from_parts(
        "soda-quality-revisions/v1",
        &[
            (
                "organization",
                spec.organization.revision().get().to_string(),
            ),
            ("data_source", spec.data_source.revision().get().to_string()),
            ("dataset", spec.dataset.revision().get().to_string()),
            ("check", spec.check.revision().get().to_string()),
            ("scan", spec.scan.revision().get().to_string()),
            ("metric", spec.metric.revision().get().to_string()),
            ("project", spec.project.revision().get().to_string()),
            ("mission", spec.mission.revision().get().to_string()),
            (
                "work_product",
                spec.work_product.revision().get().to_string(),
            ),
        ],
    )
}

/// A non-serializing, scope-bound reference to a credential held outside the
/// Layer-1 plugin. It stores only an opaque reference identifier; API-token
/// material is neither accepted as a provider request nor exposed by Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_reference: String,
    scope_digest: Digest,
    revision: Revision,
    reference_digest: Digest,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_token_reference: impl Into<String>,
        scope: &SodaQualityScope,
        revision: u64,
    ) -> Result<Self> {
        Self::api_token(opaque_token_reference, scope, revision)
    }

    pub fn api_token(
        opaque_token_reference: impl Into<String>,
        scope: &SodaQualityScope,
        revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        let opaque_token_reference = opaque_token_reference.into();
        if !valid_text(&opaque_token_reference, MAX_SECRET_BYTES) {
            return Err(SodaQualityResultError::InvalidSecretReference);
        }
        let revision = Revision::new(revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = secret_digest(&opaque_token_reference, &scope_digest, revision);
        Ok(Self {
            opaque_reference: opaque_token_reference,
            scope_digest,
            revision,
            reference_digest,
            revoked: false,
        })
    }

    pub fn from_scope_digest(
        opaque_token_reference: impl Into<String>,
        scope_digest: Digest,
        revision: u64,
    ) -> Result<Self> {
        scope_digest.validate()?;
        let opaque_token_reference = opaque_token_reference.into();
        if !valid_text(&opaque_token_reference, MAX_SECRET_BYTES) {
            return Err(SodaQualityResultError::InvalidSecretReference);
        }
        let revision = Revision::new(revision)?;
        let reference_digest = secret_digest(&opaque_token_reference, &scope_digest, revision);
        Ok(Self {
            opaque_reference: opaque_token_reference,
            scope_digest,
            revision,
            reference_digest,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate(&self, scope: &SodaQualityScope) -> Result<()> {
        scope.validate()?;
        if self.scope_digest != *scope.digest()
            || self.reference_digest
                != secret_digest(&self.opaque_reference, &self.scope_digest, self.revision)
        {
            return Err(SodaQualityResultError::InvalidSecretReference);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(SodaQualityResultError::SecretRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(SodaQualityResultError::InvalidSecretReference)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque_reference", &"<redacted>")
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("reference_digest", &self.reference_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

fn secret_digest(
    opaque_token_reference: &str,
    scope_digest: &Digest,
    revision: Revision,
) -> Digest {
    Digest::from_parts(
        "soda-api-token-secret-reference/v1",
        &[
            ("opaque_reference", opaque_token_reference.to_owned()),
            ("scope", scope_digest.as_str().to_owned()),
            ("revision", revision.get().to_string()),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaOperation {
    DatasetRead,
    CheckRead,
    ScanRead,
    QualityHealthRead,
}

impl SodaOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DatasetRead => "dataset_read",
            Self::CheckRead => "check_read",
            Self::ScanRead => "scan_read",
            Self::QualityHealthRead => "quality_health_read",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaQualityStatus {
    Pass,
    Fail,
    Warn,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaEvidenceState {
    Pass,
    Fail,
    Warn,
    Unknown,
    Partial,
    Denied,
    #[serde(rename = "rate_limit")]
    RateLimited,
    ProviderUnknown,
    #[serde(rename = "tamper")]
    Tampered,
}

impl SodaEvidenceState {
    pub const RATE_LIMIT: Self = Self::RateLimited;
    pub const TAMPER: Self = Self::Tampered;

    #[must_use]
    pub const fn is_provider_reported(self) -> bool {
        matches!(self, Self::Pass | Self::Fail | Self::Warn)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaEvidenceClassification {
    ProviderReported,
    Partial,
    Denied,
    RateLimit,
    ProviderUnknown,
    Tamper,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaFailureKind {
    Denied,
    RateLimit,
    ProviderUnknown,
    AccessLost,
    Partial,
    Tamper,
    TimedOut,
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaFailureEvidence {
    pub kind: SodaFailureKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub diagnostic_digest: Digest,
    pub redacted: bool,
}

impl SodaFailureEvidence {
    pub(crate) fn from_transport(error: &crate::error::SodaTransportError) -> Self {
        let kind = match error {
            crate::error::SodaTransportError::Denied => SodaFailureKind::Denied,
            crate::error::SodaTransportError::RateLimited { .. } => SodaFailureKind::RateLimit,
            crate::error::SodaTransportError::ProviderUnknown
            | crate::error::SodaTransportError::BlockedEnv => SodaFailureKind::ProviderUnknown,
            crate::error::SodaTransportError::AccessLost => SodaFailureKind::AccessLost,
            crate::error::SodaTransportError::Partial => SodaFailureKind::Partial,
            crate::error::SodaTransportError::Tampered => SodaFailureKind::Tamper,
            crate::error::SodaTransportError::TimedOut => SodaFailureKind::TimedOut,
            crate::error::SodaTransportError::InvalidResponse => SodaFailureKind::InvalidResponse,
        };
        let retry_after_seconds = match error {
            crate::error::SodaTransportError::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        };
        let diagnostic_digest = Digest::from_parts(
            "soda-failure-diagnostic/v1",
            &[("error", error.to_string())],
        );
        Self {
            kind,
            status_code: error.status_code(),
            retry_after_seconds,
            diagnostic_digest,
            redacted: true,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.diagnostic_digest.validate()?;
        if !self.redacted || self.retry_after_seconds.is_some_and(|value| value > 3_600) {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaRequestReceipt {
    pub operation: SodaOperation,
    pub scope_digest: Digest,
    pub target_digest: Digest,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub response_digest: Option<Digest>,
    pub response_bytes: usize,
    pub status_code: Option<u16>,
    pub redacted: bool,
}

impl SodaRequestReceipt {
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.target_digest.validate()?;
        self.request_digest.validate()?;
        self.path_digest.validate()?;
        self.response_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if !self.redacted || self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaCostReceipt {
    pub operation: SodaOperation,
    pub response_bytes: usize,
    pub bounded_request_units: u16,
    pub cost_digest: Digest,
    pub redacted: bool,
    pub provider_receipt: bool,
}

impl SodaCostReceipt {
    pub(crate) fn new(operation: SodaOperation, response_bytes: usize) -> Self {
        let cost_digest = Digest::from_parts(
            "soda-cost-receipt/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("response_bytes", response_bytes.to_string()),
            ],
        );
        Self {
            operation,
            response_bytes,
            bounded_request_units: 1,
            cost_digest,
            redacted: true,
            provider_receipt: false,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.cost_digest.validate()?;
        if !self.redacted
            || self.provider_receipt
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.bounded_request_units == 0
        {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaDatasetProjection {
    pub dataset_digest: Digest,
    pub revision_digest: Digest,
    pub row_count: u64,
    pub partition_count: u32,
}

impl SodaDatasetProjection {
    pub(crate) fn validate(&self) -> Result<()> {
        self.dataset_digest.validate()?;
        self.revision_digest.validate()?;
        if self.partition_count > 1_000_000 || self.row_count > MAX_AGGREGATE_ROWS {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaCheckProjection {
    pub check_digest: Digest,
    pub revision_digest: Digest,
    pub status: SodaQualityStatus,
    pub evaluated_rows: u64,
    pub failed_rows: u64,
    pub score_basis_points: u16,
}

impl SodaCheckProjection {
    pub(crate) fn validate(&self) -> Result<()> {
        self.check_digest.validate()?;
        self.revision_digest.validate()?;
        if self.evaluated_rows > MAX_AGGREGATE_ROWS
            || self.failed_rows > self.evaluated_rows
            || self.score_basis_points > 10_000
        {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaScanProjection {
    pub scan_digest: Digest,
    pub revision_digest: Digest,
    pub status: SodaQualityStatus,
    pub check_count: u16,
    pub completed_at_digest: Digest,
}

impl SodaScanProjection {
    pub(crate) fn validate(&self) -> Result<()> {
        self.scan_digest.validate()?;
        self.revision_digest.validate()?;
        self.completed_at_digest.validate()?;
        if usize::from(self.check_count) > MAX_CHECKS {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaQualityHealthProjection {
    pub metric_digest: Digest,
    pub revision_digest: Digest,
    pub status: SodaQualityStatus,
    pub metric_value: u64,
    pub threshold: Option<u64>,
    pub metric_count: u16,
}

impl SodaQualityHealthProjection {
    pub(crate) fn validate(&self) -> Result<()> {
        self.metric_digest.validate()?;
        self.revision_digest.validate()?;
        if usize::from(self.metric_count) > MAX_METRICS || self.metric_value > MAX_METRIC_VALUE {
            return Err(SodaQualityResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub dataset_digest: Digest,
    pub check_digest: Digest,
    pub scan_digest: Digest,
    pub metric_digest: Digest,
    pub dataset_response_digest: Option<Digest>,
    pub check_response_digest: Option<Digest>,
    pub scan_response_digest: Option<Digest>,
    pub health_response_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl SodaEvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.dataset_digest,
            &self.check_digest,
            &self.scan_digest,
            &self.metric_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        for digest in [
            &self.dataset_response_digest,
            &self.check_response_digest,
            &self.scan_response_digest,
            &self.health_response_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaRecommendation {
    ReviewRemediation,
    ReviewWarning,
    ReviewHealthy,
    NeedMoreEvidence,
    NoDecisionProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaQualityEvidence {
    pub state: SodaEvidenceState,
    pub classification: SodaEvidenceClassification,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub dataset: Option<SodaDatasetProjection>,
    pub check: Option<SodaCheckProjection>,
    pub scan: Option<SodaScanProjection>,
    pub quality_health: Option<SodaQualityHealthProjection>,
    pub failure: Option<SodaFailureEvidence>,
    pub request_receipts: Vec<SodaRequestReceipt>,
    pub cost_receipts: Vec<SodaCostReceipt>,
    pub digests: SodaEvidenceDigests,
    pub provenance: TransportProvenance,
    pub idempotency_key_digest: Digest,
    pub revision: Revision,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_rows: bool,
    pub data_correctness_claim: bool,
    pub evidence_digest: Digest,
}

impl SodaQualityEvidence {
    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-quality-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("classification", format!("{:?}", self.classification)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                (
                    "dataset",
                    serde_json::to_string(&self.dataset).unwrap_or_default(),
                ),
                (
                    "check",
                    serde_json::to_string(&self.check).unwrap_or_default(),
                ),
                (
                    "scan",
                    serde_json::to_string(&self.scan).unwrap_or_default(),
                ),
                (
                    "health",
                    serde_json::to_string(&self.quality_health).unwrap_or_default(),
                ),
                (
                    "failure",
                    serde_json::to_string(&self.failure).unwrap_or_default(),
                ),
                (
                    "requests",
                    serde_json::to_string(&self.request_receipts).unwrap_or_default(),
                ),
                (
                    "costs",
                    serde_json::to_string(&self.cost_receipts).unwrap_or_default(),
                ),
                (
                    "digests",
                    serde_json::to_string(&self.digests_without_evidence()).unwrap_or_default(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("revision_number", self.revision.get().to_string()),
                ("proposal_only", self.proposal_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("raw_rows", self.raw_rows.to_string()),
                (
                    "data_correctness_claim",
                    self.data_correctness_claim.to_string(),
                ),
            ],
        )
    }

    fn digests_without_evidence(&self) -> SodaEvidenceDigestMaterial<'_> {
        SodaEvidenceDigestMaterial {
            plugin_version_digest: &self.digests.plugin_version_digest,
            contract_digest: &self.digests.contract_digest,
            provider_digest: &self.digests.provider_digest,
            api_digest: &self.digests.api_digest,
            permission_digest: &self.digests.permission_digest,
            scope_digest: &self.digests.scope_digest,
            revision_digest: &self.digests.revision_digest,
            dataset_digest: &self.digests.dataset_digest,
            check_digest: &self.digests.check_digest,
            scan_digest: &self.digests.scan_digest,
            metric_digest: &self.digests.metric_digest,
            dataset_response_digest: self.digests.dataset_response_digest.as_ref(),
            check_response_digest: self.digests.check_response_digest.as_ref(),
            scan_response_digest: self.digests.scan_response_digest.as_ref(),
            health_response_digest: self.digests.health_response_digest.as_ref(),
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.revision_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        self.digests.validate()?;
        for receipt in &self.request_receipts {
            receipt.validate()?;
        }
        for receipt in &self.cost_receipts {
            receipt.validate()?;
        }
        if self.request_receipts.len() > MAX_RECEIPTS
            || self.cost_receipts.len() > MAX_RECEIPTS
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.raw_rows
            || self.data_correctness_claim
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        if let Some(dataset) = &self.dataset {
            dataset.validate()?;
        }
        if let Some(check) = &self.check {
            check.validate()?;
        }
        if let Some(scan) = &self.scan {
            scan.validate()?;
        }
        if let Some(health) = &self.quality_health {
            health.validate()?;
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_review_eligible(&self) -> bool {
        matches!(
            self.state,
            SodaEvidenceState::Pass | SodaEvidenceState::Fail | SodaEvidenceState::Warn
        )
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SodaEvidenceDigestMaterial<'a> {
    plugin_version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    revision_digest: &'a Digest,
    dataset_digest: &'a Digest,
    check_digest: &'a Digest,
    scan_digest: &'a Digest,
    metric_digest: &'a Digest,
    dataset_response_digest: Option<&'a Digest>,
    check_response_digest: Option<&'a Digest>,
    scan_response_digest: Option<&'a Digest>,
    health_response_digest: Option<&'a Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaQualityResultProposal {
    pub scope: SodaQualityScope,
    pub evidence: SodaQualityEvidence,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub recommendation: SodaRecommendation,
    pub proposal_revision: Revision,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub proposal_digest: Digest,
}

impl SodaQualityResultProposal {
    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-quality-result-proposal/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("recommendation", format!("{:?}", self.recommendation)),
                ("revision", self.proposal_revision.get().to_string()),
                ("proposal_only", self.proposal_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("adopts_outcome", self.adopts_outcome.to_string()),
                ("adopts_work_product", self.adopts_work_product.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope.validate()?;
        self.evidence.validate_integrity()?;
        self.registration_digest.validate()?;
        self.provider_digest.validate()?;
        self.contract_digest.validate()?;
        if self.contract_digest.as_str() != crate::CONTRACT_DIGEST
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.adopts_outcome
            || self.adopts_work_product
            || self.evidence.scope_digest != *self.scope.digest()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub fn state(&self) -> SodaEvidenceState {
        self.evidence.state
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionReceipt {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl SodaRegistration {
    pub fn bind(
        scope: &SodaQualityScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate(scope)?;
        provider_digest.validate()?;
        let mut registration = Self {
            plugin_version: crate::PLUGIN_VERSION.to_owned(),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(crate::CONTRACT_DIGEST.to_owned())?,
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_digest,
            api_digest: Digest::from_text(crate::API_REVISION),
            permission_digest: permission_digest(),
            scope_digest: scope.digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision: Revision::new(1)?,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-soda-registration"),
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate(
            scope,
            secret_reference,
            &registration.provider_digest.clone(),
        )?;
        Ok(registration)
    }

    pub fn new(
        scope: &SodaQualityScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Result<Self> {
        Self::bind(scope, secret_reference, provider_digest)
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-registration/v1",
            &[
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                ("status", format!("{:?}", self.status)),
                ("reversible", self.reversible.to_string()),
                ("revocable", self.revocable.to_string()),
            ],
        )
    }

    pub fn validate(
        &self,
        scope: &SodaQualityScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<()> {
        scope.validate()?;
        secret_reference.validate(scope)?;
        for digest in [
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.secret_reference_digest,
            &self.registration_digest,
        ] {
            digest.validate()?;
        }
        if self.plugin_version != crate::PLUGIN_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.contract_digest.as_str() != crate::CONTRACT_DIGEST
            || self.provider_id != crate::PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.api_digest != Digest::from_text(crate::API_REVISION)
            || self.permission_digest != permission_digest()
            || self.scope_digest != *scope.digest()
            || self.revision_digest != *scope.revision_digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.calculate_digest()
        {
            return Err(SodaQualityResultError::InvalidRegistration);
        }
        Ok(())
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    #[must_use]
    pub const fn is_reversible() -> bool {
        true
    }

    #[must_use]
    pub const fn is_revocable() -> bool {
        true
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionReceipt> {
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionReceipt> {
        self.transition(RegistrationStatus::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionReceipt> {
        if matches!(self.status, RegistrationStatus::Active) {
            return Err(SodaQualityResultError::InvalidRegistration);
        }
        self.transition(RegistrationStatus::Active)
    }

    fn transition(
        &mut self,
        new_status: RegistrationStatus,
    ) -> Result<RegistrationTransitionReceipt> {
        if self.status == new_status {
            return Err(match new_status {
                RegistrationStatus::Revoked => SodaQualityResultError::RegistrationRevoked,
                RegistrationStatus::Reversed => SodaQualityResultError::RegistrationReversed,
                RegistrationStatus::Active => SodaQualityResultError::RegistrationInactive,
            });
        }
        let previous_status = self.status;
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self.registration_revision.next()?;
        self.status = new_status;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionReceipt {
            previous_status,
            new_status,
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            connected: false,
            native: false,
        })
    }
}

#[must_use]
pub fn permission_digest() -> Digest {
    Digest::from_parts(
        "soda-layer1-permissions/v1",
        &[
            ("dataset", "soda.dataset.read".to_owned()),
            ("check", "soda.check.read".to_owned()),
            ("scan", "soda.scan.read".to_owned()),
            ("health", "soda.quality_health.read".to_owned()),
            ("mission", "mission.scope".to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaQualityRequest {
    pub scope_digest: Digest,
    pub revision: Revision,
    pub idempotency_key_digest: Digest,
    pub idempotency_binding_digest: Digest,
    pub max_response_bytes: usize,
    pub request_digest: Digest,
}

impl SodaQualityRequest {
    pub fn new(
        scope: &SodaQualityScope,
        revision: u64,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        scope.validate()?;
        let idempotency_key = idempotency_key.into();
        if !valid_text(&idempotency_key, MAX_IDENTIFIER_BYTES) {
            return Err(SodaQualityResultError::InvalidRequest);
        }
        let revision = Revision::new(revision)?;
        let scope_digest = scope.digest().clone();
        let idempotency_key_digest = Digest::from_parts(
            "soda-idempotency-key/v1",
            &[
                ("key", idempotency_key),
                ("scope", scope_digest.as_str().to_owned()),
            ],
        );
        let idempotency_binding_digest = Digest::from_parts(
            "soda-idempotency-binding/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("key", idempotency_key_digest.as_str().to_owned()),
            ],
        );
        let request_digest = Digest::from_parts(
            "soda-quality-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
                ("idempotency", idempotency_key_digest.as_str().to_owned()),
                (
                    "idempotency_binding",
                    idempotency_binding_digest.as_str().to_owned(),
                ),
                ("max_response_bytes", MAX_RESPONSE_BYTES.to_string()),
            ],
        );
        Ok(Self {
            scope_digest,
            revision,
            idempotency_key_digest,
            idempotency_binding_digest,
            max_response_bytes: MAX_RESPONSE_BYTES,
            request_digest,
        })
    }

    pub fn validate(&self, scope: &SodaQualityScope) -> Result<()> {
        scope.validate()?;
        self.scope_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        self.idempotency_binding_digest.validate()?;
        self.request_digest.validate()?;
        Revision::new(self.revision.get())?;
        if self.scope_digest != *scope.digest()
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.idempotency_binding_digest
                != Digest::from_parts(
                    "soda-idempotency-binding/v1",
                    &[
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("key", self.idempotency_key_digest.as_str().to_owned()),
                    ],
                )
            || self.request_digest != self.calculate_digest()
        {
            return Err(SodaQualityResultError::InvalidRequest);
        }
        Ok(())
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-quality-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                (
                    "idempotency_binding",
                    self.idempotency_binding_digest.as_str().to_owned(),
                ),
                ("max_response_bytes", self.max_response_bytes.to_string()),
            ],
        )
    }
}

pub type SodaScope = SodaQualityScope;
pub type SodaQualityResult = SodaQualityResultProposal;
pub type SodaEvidence = SodaQualityEvidence;
