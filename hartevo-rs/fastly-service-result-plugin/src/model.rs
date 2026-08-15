use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::Error as SerdeError};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{FastlyServiceResultError, Result};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 100;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_BACKOFF_SECONDS: u32 = 60;

pub const LAYER1_PERMISSIONS: [&str; 7] = [
    "fastly:account.read",
    "fastly:service.read",
    "fastly:version.read",
    "fastly:environment.read",
    "fastly:domain.read",
    "fastly:validation.read",
    "mission.scope",
];

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A validated SHA-256 digest. Raw provider identifiers and sensitive values
/// cross the evidence boundary only through this type.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(FastlyServiceResultError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(sha256_hex(bytes))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_component(&mut bytes, domain);
        for (label, value) in fields {
            append_component(&mut bytes, label);
            append_component(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    #[must_use]
    pub fn pending() -> Self {
        Self::from_text("unsealed-fastly-service-result-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(FastlyServiceResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl PartialEq<&str> for Digest {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

fn append_component(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(value.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'|');
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+' | b'%')
        })
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(FastlyServiceResultError::InvalidIdentifier {
                field: "identifier",
                reason: "must be bounded, trimmed, printable, and URL-safe",
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts("fastly-identifier/v1", &[("value", self.0.clone())])
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identifier")
            .field(&format!("id:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

pub type FastlyAccountId = Identifier;
pub type FastlyServiceId = Identifier;
pub type FastlyVersionId = Identifier;
pub type FastlyEnvironment = Identifier;
pub type FastlyDomain = Identifier;
pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(FastlyServiceResultError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn bump(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(FastlyServiceResultError::RevisionOverflow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    id: ProjectId,
    revision: Revision,
}

impl Project {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "fastly-hartevo-project/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    id: MissionId,
    revision: Revision,
}

impl Mission {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &MissionId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "fastly-mission/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProduct {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "fastly-work-product/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyServiceResultScope {
    account: FastlyAccountId,
    service: FastlyServiceId,
    version: FastlyVersionId,
    environment: FastlyEnvironment,
    domain: FastlyDomain,
    project: Project,
    mission: Mission,
    work_product: WorkProduct,
}

impl FastlyServiceResultScope {
    pub fn new(
        account: impl Into<String>,
        service: impl Into<String>,
        version: impl Into<String>,
        environment: impl Into<String>,
        domain: impl Into<String>,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
    ) -> Result<Self> {
        Ok(Self {
            account: Identifier::new(account)?,
            service: Identifier::new(service)?,
            version: Identifier::new(version)?,
            environment: Identifier::new(environment)?,
            domain: Identifier::new(domain)?,
            project,
            mission,
            work_product,
        })
    }

    #[must_use]
    pub fn account(&self) -> &FastlyAccountId {
        &self.account
    }

    #[must_use]
    pub fn service(&self) -> &FastlyServiceId {
        &self.service
    }

    #[must_use]
    pub fn version(&self) -> &FastlyVersionId {
        &self.version
    }

    #[must_use]
    pub fn environment(&self) -> &FastlyEnvironment {
        &self.environment
    }

    #[must_use]
    pub fn domain(&self) -> &FastlyDomain {
        &self.domain
    }

    #[must_use]
    pub fn project(&self) -> &Project {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &Mission {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProduct {
        &self.work_product
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "fastly-service-result-scope/v1",
            &[
                ("account", self.account.digest().to_string()),
                ("service", self.service.digest().to_string()),
                ("version", self.version.digest().to_string()),
                ("environment", self.environment.digest().to_string()),
                ("domain", self.domain.digest().to_string()),
                ("project", self.project.digest().to_string()),
                ("mission", self.mission.digest().to_string()),
                ("workProduct", self.work_product.digest().to_string()),
            ],
        )
    }
}

pub type FastlyScope = FastlyServiceResultScope;
pub type FastlyServiceScope = FastlyServiceResultScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    scope_digest: Digest,
    secret_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn api_token(
        token: impl AsRef<str>,
        scope: &FastlyServiceResultScope,
        revision: u64,
    ) -> Result<Self> {
        let token = token.as_ref();
        if token.is_empty()
            || token.len() > MAX_SECRET_REFERENCE_BYTES
            || token.chars().any(char::is_control)
        {
            return Err(FastlyServiceResultError::InvalidSecretReference);
        }
        let revision = Revision::new(revision)?;
        let scope_digest = scope.digest();
        let mut material = token.as_bytes().to_vec();
        let secret_digest = Digest::from_parts(
            "fastly-api-token-reference/v1",
            &[
                ("token", sha256_hex(&material)),
                ("scope", scope_digest.to_string()),
                ("revision", revision.get().to_string()),
            ],
        );
        material.zeroize();
        Ok(Self {
            kind: SecretKind::ApiToken,
            scope_digest,
            secret_digest,
            revision,
            revoked: false,
        })
    }

    pub fn fastly_api_token(
        token: impl AsRef<str>,
        scope: &FastlyServiceResultScope,
        revision: u64,
    ) -> Result<Self> {
        Self::api_token(token, scope, revision)
    }

    pub fn from_digest(
        kind: SecretKind,
        secret_digest: Digest,
        scope: &FastlyServiceResultScope,
        revision: u64,
    ) -> Result<Self> {
        secret_digest.validate()?;
        Ok(Self {
            kind,
            scope_digest: scope.digest(),
            secret_digest,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn secret_digest(&self) -> &Digest {
        &self.secret_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "fastly-secret-reference/v1",
            &[
                ("kind", format!("{:?}", self.kind)),
                ("scope", self.scope_digest.to_string()),
                ("secret", self.secret_digest.to_string()),
                ("revision", self.revision.get().to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn restore(&mut self) {
        self.revoked = false;
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(S::Error::custom(
            "Fastly API-token SecretReference is opaque and non-serializing",
        ))
    }
}

impl fmt::Display for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretReference({:?})", self.kind)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<String>,
    revision: Revision,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn for_layer_one(revision: u64) -> Result<Self> {
        let revision = Revision::new(revision)?;
        let permissions = LAYER1_PERMISSIONS
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        Ok(Self {
            digest: Digest::from_parts(
                "fastly-layer1-permissions/v1",
                &[
                    (
                        "permissions",
                        permissions.iter().cloned().collect::<Vec<_>>().join(","),
                    ),
                    ("revision", revision.get().to_string()),
                ],
            ),
            permissions,
            revision,
        })
    }

    pub fn new<I, S>(permissions: I, revision: u64) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let revision = Revision::new(revision)?;
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let digest = Digest::from_parts(
            "fastly-layer1-permissions/v1",
            &[
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
                ("revision", revision.get().to_string()),
            ],
        );
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub fn is_layer_one_exact(&self) -> bool {
        self.permissions
            == LAYER1_PERMISSIONS
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    id: Identifier,
    revision: Revision,
    max_reads: u32,
    digest: Digest,
}

impl ConsentScope {
    pub fn for_layer_one(id: impl Into<String>, revision: u64, max_reads: u32) -> Result<Self> {
        let id = Identifier::new(id)?;
        let revision = Revision::new(revision)?;
        if max_reads == 0 {
            return Err(FastlyServiceResultError::InvalidRevision { field: "max_reads" });
        }
        let digest = Digest::from_parts(
            "fastly-layer1-consent/v1",
            &[
                ("id", id.digest().to_string()),
                ("revision", revision.get().to_string()),
                ("maxReads", max_reads.to_string()),
            ],
        );
        Ok(Self {
            id,
            revision,
            max_reads,
            digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn max_reads(&self) -> u32 {
        self.max_reads
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyVersionState {
    Active,
    Staging,
    Testing,
    Draft,
    Inactive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyEnvironmentState {
    Active,
    Staging,
    Testing,
    Inactive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyDomainState {
    Present,
    Missing,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyTlsState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyValidationState {
    Passed,
    Failed,
    Pending,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyServiceResultState {
    Present,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Stale,
    Revoked,
    ValidationFailed,
    RateLimited,
    Timeout,
    ServerError,
}

impl FastlyServiceResultState {
    pub const STALE_REVISION: Self = Self::Stale;
    pub const STALE_MISSION_REVISION: Self = Self::Stale;
    pub const TAMPER: Self = Self::Tampered;
    pub const REVOKED_REGISTRATION: Self = Self::Revoked;

    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Present)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyServiceProjection {
    pub account_digest: Digest,
    pub service_digest: Digest,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyVersionProjection {
    pub version_digest: Digest,
    pub config_digest: Digest,
    pub state: FastlyVersionState,
    pub active: bool,
    pub staging: bool,
    pub testing: bool,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyEnvironmentProjection {
    pub environment_digest: Digest,
    pub version_digest: Digest,
    pub state: FastlyEnvironmentState,
    pub active: bool,
    pub staging: bool,
    pub testing: bool,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyDomainProjection {
    pub domain_digest: Digest,
    pub version_digest: Digest,
    pub state: FastlyDomainState,
    pub tls: FastlyTlsState,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyValidationProjection {
    pub validation_digest: Digest,
    pub config_digest: Digest,
    pub state: FastlyValidationState,
    pub error_count: u16,
    pub warning_count: u16,
    pub metadata_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyRequestOutcome {
    Success,
    RateLimited,
    AccessLoss,
    Timeout,
    ServerError,
    Empty,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyRequestReceipt {
    pub request_digest: Digest,
    pub endpoint: String,
    pub page: u16,
    pub attempt: u8,
    pub outcome: FastlyRequestOutcome,
    pub status: Option<u16>,
    pub response_digest: Option<Digest>,
    pub retry_after_seconds: Option<u32>,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl FastlyRequestReceipt {
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "fastly-request-receipt/v1",
            &[
                ("request", self.request_digest.to_string()),
                ("endpoint", self.endpoint.clone()),
                ("page", self.page.to_string()),
                ("attempt", self.attempt.to_string()),
                ("outcome", format!("{:?}", self.outcome)),
                (
                    "status",
                    self.status
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                ),
                (
                    "response",
                    self.response_digest
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), ToString::to_string),
                ),
                (
                    "retryAfter",
                    self.retry_after_seconds
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyRateLimitReceipt {
    pub retry_after_seconds: u32,
    pub attempts: u8,
    pub bounded: bool,
    pub redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyFailure {
    pub category: String,
    pub status: Option<u16>,
    pub retryable: bool,
    pub redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyServiceResultEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub api_revision_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub state: FastlyServiceResultState,
    pub partial: bool,
    pub service: Option<FastlyServiceProjection>,
    pub version: Option<FastlyVersionProjection>,
    pub environment: Option<FastlyEnvironmentProjection>,
    pub domains: Vec<FastlyDomainProjection>,
    pub validation: Option<FastlyValidationProjection>,
    pub request_receipts: Vec<FastlyRequestReceipt>,
    pub rate_limit: Option<FastlyRateLimitReceipt>,
    pub failure: Option<FastlyFailure>,
    pub evidence_digest: Digest,
    pub idempotency_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub independent_native_readback: bool,
    pub raw_vcl_retained: bool,
    pub raw_config_retained: bool,
    pub external_write_performed: bool,
    pub work_product_adopted: bool,
}

impl FastlyServiceResultEvidence {
    pub fn validate_integrity(&self) -> Result<()> {
        self.contract_digest.validate()?;
        self.plugin_version_digest.validate()?;
        self.provider_digest.validate()?;
        self.api_revision_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.scope_digest.validate()?;
        self.registration_digest.validate()?;
        self.evidence_digest.validate()?;
        if !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.independent_native_readback
            || self.raw_vcl_retained
            || self.raw_config_retained
            || self.external_write_performed
            || self.work_product_adopted
            || self.request_receipts.iter().any(|receipt| {
                !receipt.redacted || receipt.connected || receipt.native || receipt.first_party
            })
        {
            return Err(FastlyServiceResultError::Tampered);
        }
        if compute_evidence_digest(self) != self.evidence_digest {
            return Err(FastlyServiceResultError::Tampered);
        }
        Ok(())
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyServiceResultProposal {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub contract_digest: Digest,
    pub evidence_digest: Digest,
    pub state: FastlyServiceResultState,
    pub version: Option<FastlyVersionProjection>,
    pub environment: Option<FastlyEnvironmentProjection>,
    pub domains: Vec<FastlyDomainProjection>,
    pub validation: Option<FastlyValidationProjection>,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub verified_work_product_adoption: bool,
    pub proposal_digest: Digest,
}

impl FastlyServiceResultProposal {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.registration_digest.validate()?;
        self.contract_digest.validate()?;
        self.evidence_digest.validate()?;
        self.proposal_digest.validate()?;
        if !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.verified_work_product_adoption
        {
            return Err(FastlyServiceResultError::Tampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyObservationReceipt {
    pub idempotency_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub replayed: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_authority: bool,
    pub recorded: bool,
    pub receipt_digest: Digest,
}

impl FastlyObservationReceipt {
    pub fn validate_integrity(&self) -> Result<()> {
        let expected = Digest::from_parts(
            "fastly-observation-receipt/v1",
            &[
                ("idempotency", self.idempotency_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("proposal", self.proposal_digest.to_string()),
                ("replayed", self.replayed.to_string()),
                ("recorded", self.recorded.to_string()),
            ],
        );
        if expected != self.receipt_digest
            || self.durable_provider_receipt
            || self.connected
            || self.native
            || self.first_party
            || self.kernel_authority
        {
            return Err(FastlyServiceResultError::Tampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyMissionServiceResult {
    pub scope_digest: Digest,
    pub mission_digest: Digest,
    pub evidence_digest: Digest,
    pub state: FastlyServiceResultState,
    pub review_only: bool,
    pub verified: bool,
    pub can_adopt_work_product: bool,
    pub kernel_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl FastlyMissionServiceResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.review_only
            || !self.verified
            || self.can_adopt_work_product
            || self.kernel_authority
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(FastlyServiceResultError::Tampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyVerificationReport {
    pub verified: bool,
    pub review_eligible: bool,
    pub can_be_adopted: bool,
    pub state: FastlyServiceResultState,
    pub reason: Option<String>,
}

impl FastlyVerificationReport {
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }
}

pub(crate) fn compute_evidence_digest(evidence: &FastlyServiceResultEvidence) -> Digest {
    let mut fields = vec![
        ("contractVersion", evidence.contract_version.clone()),
        ("contract", evidence.contract_digest.to_string()),
        ("pluginVersion", evidence.plugin_version_digest.to_string()),
        ("provider", evidence.provider_digest.to_string()),
        ("apiRevision", evidence.api_revision_digest.to_string()),
        ("permission", evidence.permission_digest.to_string()),
        ("consent", evidence.consent_digest.to_string()),
        ("scope", evidence.scope_digest.to_string()),
        ("registration", evidence.registration_digest.to_string()),
        (
            "registrationRevision",
            evidence.registration_revision.get().to_string(),
        ),
        (
            "projectRevision",
            evidence.project_revision.get().to_string(),
        ),
        (
            "missionRevision",
            evidence.mission_revision.get().to_string(),
        ),
        (
            "workProductRevision",
            evidence.work_product_revision.get().to_string(),
        ),
        ("state", format!("{:?}", evidence.state)),
        ("partial", evidence.partial.to_string()),
        (
            "service",
            projection_digest(evidence.service.as_ref(), "service"),
        ),
        (
            "version",
            projection_digest(evidence.version.as_ref(), "version"),
        ),
        (
            "environment",
            projection_digest(evidence.environment.as_ref(), "environment"),
        ),
        (
            "domains",
            evidence
                .domains
                .iter()
                .map(domain_projection_digest)
                .collect::<Vec<_>>()
                .join(","),
        ),
        (
            "validation",
            projection_digest(evidence.validation.as_ref(), "validation"),
        ),
        (
            "receipts",
            evidence
                .request_receipts
                .iter()
                .map(|receipt| receipt.digest().to_string())
                .collect::<Vec<_>>()
                .join(","),
        ),
        (
            "rateLimit",
            evidence.rate_limit.as_ref().map_or_else(
                || "none".to_owned(),
                |receipt| {
                    format!(
                        "{}:{}:{}:{}",
                        receipt.retry_after_seconds,
                        receipt.attempts,
                        receipt.bounded,
                        receipt.redacted
                    )
                },
            ),
        ),
        (
            "failure",
            evidence.failure.as_ref().map_or_else(
                || "none".to_owned(),
                |failure| {
                    format!(
                        "{}:{:?}:{}:{}",
                        failure.category, failure.status, failure.retryable, failure.redacted
                    )
                },
            ),
        ),
        ("idempotency", evidence.idempotency_digest.to_string()),
    ];
    fields.push(("readOnly", evidence.read_only.to_string()));
    fields.push(("proposalOnly", evidence.proposal_only.to_string()));
    fields.push(("recordingOnly", evidence.recording_only.to_string()));
    Digest::from_parts("fastly-service-result-evidence/v1", &fields)
}

fn projection_digest<T: Serialize>(value: Option<&T>, label: &str) -> String {
    value.map_or_else(
        || "none".to_owned(),
        |value| {
            serde_json::to_vec(value)
                .map_or_else(
                    |_| Digest::pending(),
                    |bytes| Digest::from_parts(label, &[("projection", sha256_hex(&bytes))]),
                )
                .to_string()
        },
    )
}

fn domain_projection_digest(value: &FastlyDomainProjection) -> String {
    projection_digest(Some(value), "domain")
}
