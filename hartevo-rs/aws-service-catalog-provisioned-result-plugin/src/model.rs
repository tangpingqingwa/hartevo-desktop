//! Digest-only scope, cursor, and projection models for Service Catalog.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::Write as _,
    str::FromStr,
};

use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    error::{AwsServiceCatalogError, Result},
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_TOKEN_BYTES: usize = 256;
pub const MAX_SEARCH_PAGE_SIZE: u16 = 100;
pub const MAX_HISTORY_PAGE_SIZE: u16 = 20;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty() {
        return Err(AwsServiceCatalogError::Empty { field });
    }
    if value.len() > max {
        return Err(AwsServiceCatalogError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(AwsServiceCatalogError::InvalidText { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(AwsServiceCatalogError::InvalidText { field });
    }
    Ok(())
}

/// A lower-case SHA-256 digest used for every retained external identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AwsServiceCatalogError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        let value = value.to_ascii_lowercase();
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, parts: &[(&str, String)]) -> Self {
        let mut canonical = String::from(domain);
        for (name, value) in parts {
            let _ = write!(canonical, "|{name}:{}:{value}", value.len());
        }
        Self::from_text(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::parse(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("digest input serializes"))
}

fn digest_identifier(value: &str, field: &'static str) -> Result<Digest> {
    validate_identifier(value, field)?;
    Ok(Digest::from_parts(
        "aws-service-catalog-opaque-identifier/v1",
        &[("field", field.to_owned()), ("value", value.to_owned())],
    ))
}

/// The AWS region is safe routing metadata; all identity-bearing values use
/// `Digest` instead of retaining their provider spelling.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "AWS region", 64)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AwsServiceCatalogError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(format!("aws-region/v1|{}", self.0))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessLevelKind {
    Account,
    User,
    Role,
}

/// The access-level value is immediately converted to a digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLevelScope {
    pub kind: AccessLevelKind,
    pub value_digest: Digest,
}

impl AccessLevelScope {
    pub fn new(kind: AccessLevelKind, value: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            kind,
            value_digest: digest_identifier(value.as_ref(), "access level")?,
        })
    }

    pub fn account(value: impl AsRef<str>) -> Result<Self> {
        Self::new(AccessLevelKind::Account, value)
    }

    pub fn user(value: impl AsRef<str>) -> Result<Self> {
        Self::new(AccessLevelKind::User, value)
    }

    pub fn role(value: impl AsRef<str>) -> Result<Self> {
        Self::new(AccessLevelKind::Role, value)
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.value_digest.validate()
    }
}

macro_rules! revisioned_scope {
    ($name:ident, $digest_field:ident, $field_name:literal) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub $digest_field: Digest,
            pub revision: u64,
        }

        impl $name {
            pub fn new(value: impl AsRef<str>, revision: u64) -> Result<Self> {
                if revision == 0 {
                    return Err(AwsServiceCatalogError::Invalid { field: $field_name });
                }
                Ok(Self {
                    $digest_field: digest_identifier(value.as_ref(), $field_name)?,
                    revision,
                })
            }

            pub fn digest(&self) -> Digest {
                digest_serializable(self)
            }

            pub fn validate(&self) -> Result<()> {
                self.$digest_field.validate()?;
                if self.revision == 0 {
                    return Err(AwsServiceCatalogError::Invalid { field: $field_name });
                }
                Ok(())
            }
        }
    };
}

revisioned_scope!(PortfolioScope, portfolio_id_digest, "portfolio id");
revisioned_scope!(
    ProvisionedProductScope,
    provisioned_product_id_digest,
    "provisioned product id"
);
revisioned_scope!(RecordScope, record_id_digest, "record id");
revisioned_scope!(ProjectScope, project_id_digest, "Project id");
revisioned_scope!(MissionScope, mission_id_digest, "Mission id");
revisioned_scope!(WorkProductScope, work_product_id_digest, "Work Product id");

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductScope {
    pub product_id_digest: Digest,
    pub product_revision: u64,
    pub artifact_id_digest: Digest,
    pub artifact_revision: u64,
}

impl ProductScope {
    pub fn new(
        product_id: impl AsRef<str>,
        product_revision: u64,
        artifact_id: impl AsRef<str>,
        artifact_revision: u64,
    ) -> Result<Self> {
        if product_revision == 0 || artifact_revision == 0 {
            return Err(AwsServiceCatalogError::Invalid {
                field: "product/artifact revision",
            });
        }
        Ok(Self {
            product_id_digest: digest_identifier(product_id.as_ref(), "product id")?,
            product_revision,
            artifact_id_digest: digest_identifier(artifact_id.as_ref(), "artifact id")?,
            artifact_revision,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.product_id_digest.validate()?;
        self.artifact_id_digest.validate()?;
        if self.product_revision == 0 || self.artifact_revision == 0 {
            return Err(AwsServiceCatalogError::Invalid {
                field: "product/artifact revision",
            });
        }
        Ok(())
    }
}

/// The complete Service Catalog + Mission scope. Its JSON representation is
/// digest-only for identifiers and therefore safe for evidence/proposal use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceCatalogScope {
    pub account_id_digest: Digest,
    pub region: AwsRegion,
    pub access_level: AccessLevelScope,
    pub portfolio: PortfolioScope,
    pub product: ProductScope,
    pub provisioned_product: ProvisionedProductScope,
    pub record: RecordScope,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
}

impl AwsServiceCatalogScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: impl AsRef<str>,
        region: impl Into<String>,
        access_level: AccessLevelScope,
        portfolio: PortfolioScope,
        product: ProductScope,
        provisioned_product: ProvisionedProductScope,
        record: RecordScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
    ) -> Result<Self> {
        let scope = Self {
            account_id_digest: digest_identifier(account_id.as_ref(), "AWS account id")?,
            region: AwsRegion::new(region)?,
            access_level,
            portfolio,
            product,
            provisioned_product,
            record,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn account_digest(&self) -> &Digest {
        &self.account_id_digest
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn access_level_digest(&self) -> Digest {
        self.access_level.digest()
    }

    pub fn revision_fence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-service-catalog-revision-fence/v1",
            &[
                ("product", self.product.product_revision.to_string()),
                ("artifact", self.product.artifact_revision.to_string()),
                (
                    "provisioned_product",
                    self.provisioned_product.revision.to_string(),
                ),
                ("record", self.record.revision.to_string()),
                ("project", self.project.revision.to_string()),
                ("mission", self.mission.revision.to_string()),
                ("work_product", self.work_product.revision.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.account_id_digest.validate()?;
        self.access_level.validate()?;
        self.portfolio.validate()?;
        self.product.validate()?;
        self.provisioned_product.validate()?;
        self.record.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        Ok(())
    }
}

/// Opaque, non-serializing SigV4 reference. Layer 1 stores only a binding
/// digest; the supplied handle is never retained and cannot be recovered.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretReferenceKind {
    SigV4,
}

impl SecretReference {
    pub fn sigv4(scope: &AwsServiceCatalogScope, opaque_handle: impl AsRef<str>) -> Result<Self> {
        let handle = opaque_handle.as_ref();
        validate_text(
            handle,
            "opaque SigV4 secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        if handle.contains("AKIA")
            || handle.contains("AWS_SECRET")
            || handle.contains("BEGIN ")
            || handle.contains('=')
        {
            return Err(AwsServiceCatalogError::Invalid {
                field: "opaque SigV4 secret reference",
            });
        }
        let scope_digest = scope.digest();
        Ok(Self {
            kind: SecretReferenceKind::SigV4,
            reference_digest: Digest::from_parts(
                "aws-service-catalog-secret-reference/v1",
                &[
                    ("scope", scope_digest.to_string()),
                    ("handle", handle.to_owned()),
                ],
            ),
            scope_digest,
            revoked: false,
        })
    }

    pub fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn restore(&mut self) {
        self.revoked = false;
    }

    pub fn validate(&self, scope: &AwsServiceCatalogScope) -> Result<()> {
        if self.kind != SecretReferenceKind::SigV4
            || self.scope_digest != scope.digest()
            || self.reference_digest.as_str().is_empty()
        {
            return Err(AwsServiceCatalogError::InvalidRegistration);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if revision == 0 {
            return Err(AwsServiceCatalogError::Invalid {
                field: "permission revision",
            });
        }
        let permissions = permissions.into_iter().map(Into::into).collect();
        let snapshot = Self {
            revision,
            permissions,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.revision == 0 || self.permissions.is_empty() {
            return Err(AwsServiceCatalogError::Invalid {
                field: "permission snapshot",
            });
        }
        if self
            .permissions
            .iter()
            .any(|permission| permission.contains('\n') || permission.contains('\r'))
        {
            return Err(AwsServiceCatalogError::InvalidText {
                field: "permission",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(Digest);

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        validate_text(value.as_ref(), "idempotency key", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(Digest::from_parts(
            "aws-service-catalog-idempotency-key/v1",
            &[("key", value.as_ref().to_owned())],
        )))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

impl Serialize for IdempotencyKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

/// An opaque cursor contains only a page number and a binding MAC-like
/// digest. It never contains a provider token or a filter value.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PageToken {
    token: String,
    page_number: u16,
}

impl PageToken {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let token = value.into();
        validate_text(&token, "opaque page token", MAX_PAGE_TOKEN_BYTES)?;
        let mut parts = token.split('.');
        if parts.next() != Some("SC1") {
            return Err(AwsServiceCatalogError::InvalidPageToken);
        }
        let page_number = parts
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|page| (1..=MAX_PAGES + 1).contains(page))
            .ok_or(AwsServiceCatalogError::InvalidPageToken)?;
        let digest = parts
            .next()
            .ok_or(AwsServiceCatalogError::InvalidPageToken)?;
        if parts.next().is_some()
            || digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(AwsServiceCatalogError::InvalidPageToken);
        }
        Ok(Self { token, page_number })
    }

    pub(crate) fn for_binding(binding: &Digest, page_number: u16) -> Self {
        let digest = Digest::from_parts(
            "aws-service-catalog-page-token/v1",
            &[
                ("binding", binding.to_string()),
                ("page", page_number.to_string()),
            ],
        );
        Self {
            token: format!("SC1.{page_number}.{}", digest.as_str()),
            page_number,
        }
    }

    pub(crate) fn validate_against(&self, binding: &Digest, page_number: u16) -> Result<()> {
        if self.page_number != page_number
            || self.token != Self::for_binding(binding, page_number).token
        {
            return Err(AwsServiceCatalogError::CursorTampered);
        }
        Ok(())
    }

    pub fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.token)
    }
}

impl fmt::Debug for PageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageToken")
            .field("token_digest", &self.digest())
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl fmt::Display for PageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.token.fmt(formatter)
    }
}

impl FromStr for PageToken {
    type Err = AwsServiceCatalogError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for PageToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.token)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProvisionedProductStatus {
    Available,
    UnderChange,
    Tainted,
    Error,
    Terminated,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordType {
    Provision,
    Update,
    Terminate,
    Execute,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorClass {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Throttled,
    ServerError,
    Timeout,
    AccessLost,
    InvalidResponse,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "timestamp", 80)?;
        if !value.contains('T') {
            return Err(AwsServiceCatalogError::Invalid { field: "timestamp" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(format!("timestamp/v1|{}", self.0))
    }
}

impl FromStr for Timestamp {
    type Err = AwsServiceCatalogError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub mission_id_digest: Digest,
    pub mission_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub project_id_digest: Digest,
    pub project_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub work_product_id_digest: Digest,
    pub work_product_revision: u64,
}

pub fn mission_projection(scope: &MissionScope) -> MissionProjection {
    MissionProjection {
        mission_id_digest: scope.mission_id_digest.clone(),
        mission_revision: scope.revision,
    }
}

pub fn project_projection(scope: &ProjectScope) -> ProjectProjection {
    ProjectProjection {
        project_id_digest: scope.project_id_digest.clone(),
        project_revision: scope.revision,
    }
}

pub fn work_product_projection(scope: &WorkProductScope) -> WorkProductProjection {
    WorkProductProjection {
        work_product_id_digest: scope.work_product_id_digest.clone(),
        work_product_revision: scope.revision,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SearchQuery {
    All,
    Status(ProvisionedProductStatus),
    Portfolio(Digest),
    Product(Digest),
    ProvisionedProduct(Digest),
}

impl SearchQuery {
    pub fn all() -> Self {
        Self::All
    }

    pub fn status(status: ProvisionedProductStatus) -> Self {
        Self::Status(status)
    }

    pub fn portfolio(value: impl AsRef<str>) -> Self {
        Self::Portfolio(Digest::from_parts(
            "aws-service-catalog-search-value/v1",
            &[
                ("field", "portfolio".to_owned()),
                ("value", value.as_ref().to_owned()),
            ],
        ))
    }

    pub fn product(value: impl AsRef<str>) -> Self {
        Self::Product(Digest::from_parts(
            "aws-service-catalog-search-value/v1",
            &[
                ("field", "product".to_owned()),
                ("value", value.as_ref().to_owned()),
            ],
        ))
    }

    pub fn provisioned_product(value: impl AsRef<str>) -> Self {
        Self::ProvisionedProduct(Digest::from_parts(
            "aws-service-catalog-search-value/v1",
            &[
                ("field", "provisionedProduct".to_owned()),
                ("value", value.as_ref().to_owned()),
            ],
        ))
    }

    /// Parse only the explicit allowlist. Arbitrary AWS SearchQuery strings,
    /// wildcards, and provider expression syntax are never retained.
    pub fn from_allowlisted(key: impl AsRef<str>, value: impl AsRef<str>) -> Result<Self> {
        let key = key.as_ref();
        let value = value.as_ref();
        validate_text(value, "SearchQuery value", MAX_IDENTIFIER_BYTES)?;
        if value
            .chars()
            .any(|character| matches!(character, '*' | '=' | '|' | '"' | '\''))
        {
            return Err(AwsServiceCatalogError::UnsupportedSearchQuery);
        }
        match key {
            "status" => match value {
                "AVAILABLE" => Ok(Self::Status(ProvisionedProductStatus::Available)),
                "UNDER_CHANGE" => Ok(Self::Status(ProvisionedProductStatus::UnderChange)),
                "TAINTED" => Ok(Self::Status(ProvisionedProductStatus::Tainted)),
                "ERROR" => Ok(Self::Status(ProvisionedProductStatus::Error)),
                "TERMINATED" => Ok(Self::Status(ProvisionedProductStatus::Terminated)),
                "UNKNOWN" => Ok(Self::Status(ProvisionedProductStatus::Unknown)),
                _ => Err(AwsServiceCatalogError::UnsupportedSearchQuery),
            },
            "portfolio" => Ok(Self::portfolio(value)),
            "product" => Ok(Self::product(value)),
            "provisionedProduct" => Ok(Self::provisioned_product(value)),
            _ => Err(AwsServiceCatalogError::UnsupportedSearchQuery),
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Status(_) => Ok(()),
            Self::Portfolio(value) | Self::Product(value) | Self::ProvisionedProduct(value) => {
                value.validate()
            }
        }
    }
}

fn digest_pairs<I>(domain: &str, pairs: I) -> Option<Digest>
where
    I: IntoIterator<Item = (String, String)>,
{
    let values = pairs.into_iter().collect::<BTreeMap<_, _>>();
    if values.is_empty() {
        return None;
    }
    let parts = values.into_iter().collect::<Vec<_>>();
    Some(Digest::from_parts(
        domain,
        &parts
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect::<Vec<_>>(),
    ))
}

/// Safe provisioned-product metadata. Every provider identifier and
/// tag/output collection is converted to a digest before this value exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionedProductProjection {
    pub product_digest: Digest,
    pub artifact_digest: Digest,
    pub provisioned_product_digest: Digest,
    pub record_digest: Option<Digest>,
    pub status: ProvisionedProductStatus,
    pub created_at: Timestamp,
    pub last_updated_at: Timestamp,
    pub record_type: Option<RecordType>,
    pub error_class: Option<ErrorClass>,
    pub product_revision: u64,
    pub artifact_revision: u64,
    pub provisioned_product_revision: u64,
    pub record_revision: u64,
    pub tags_digest: Option<Digest>,
    pub outputs_digest: Option<Digest>,
}

impl ProvisionedProductProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn from_provider_fields<I, J>(
        scope: &AwsServiceCatalogScope,
        product_id: impl AsRef<str>,
        artifact_id: impl AsRef<str>,
        provisioned_product_id: impl AsRef<str>,
        record_id: Option<impl AsRef<str>>,
        status: ProvisionedProductStatus,
        created_at: impl Into<String>,
        last_updated_at: impl Into<String>,
        record_type: Option<RecordType>,
        error_class: Option<ErrorClass>,
        product_revision: u64,
        artifact_revision: u64,
        provisioned_product_revision: u64,
        record_revision: u64,
        tags: I,
        outputs: J,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (String, String)>,
        J: IntoIterator<Item = (String, String)>,
    {
        let projection = Self {
            product_digest: digest_identifier(product_id.as_ref(), "product id")?,
            artifact_digest: digest_identifier(artifact_id.as_ref(), "artifact id")?,
            provisioned_product_digest: digest_identifier(
                provisioned_product_id.as_ref(),
                "provisioned product id",
            )?,
            record_digest: record_id
                .map(|value| digest_identifier(value.as_ref(), "record id"))
                .transpose()?,
            status,
            created_at: Timestamp::new(created_at)?,
            last_updated_at: Timestamp::new(last_updated_at)?,
            record_type,
            error_class,
            product_revision,
            artifact_revision,
            provisioned_product_revision,
            record_revision,
            tags_digest: digest_pairs("aws-service-catalog-tags/v1", tags),
            outputs_digest: digest_pairs("aws-service-catalog-outputs/v1", outputs),
        };
        projection.validate()?;
        if !projection.matches_scope(scope) {
            return Err(AwsServiceCatalogError::ScopeViolation);
        }
        Ok(projection)
    }

    pub fn matches_scope(&self, scope: &AwsServiceCatalogScope) -> bool {
        self.product_digest == scope.product.product_id_digest
            && self.artifact_digest == scope.product.artifact_id_digest
            && self.provisioned_product_digest
                == scope.provisioned_product.provisioned_product_id_digest
            && self.record_digest.as_ref() == Some(&scope.record.record_id_digest)
            && self.product_revision == scope.product.product_revision
            && self.artifact_revision == scope.product.artifact_revision
            && self.provisioned_product_revision == scope.provisioned_product.revision
            && self.record_revision == scope.record.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.product_digest.validate()?;
        self.artifact_digest.validate()?;
        self.provisioned_product_digest.validate()?;
        if let Some(record_digest) = &self.record_digest {
            record_digest.validate()?;
        }
        self.created_at.as_str();
        self.last_updated_at.as_str();
        if self.product_revision == 0
            || self.artifact_revision == 0
            || self.provisioned_product_revision == 0
            || self.record_revision == 0
        {
            return Err(AwsServiceCatalogError::RevisionMismatch);
        }
        Ok(())
    }

    pub fn sort_key(&self) -> (&str, &str, &str) {
        (
            self.provisioned_product_digest.as_str(),
            self.product_digest.as_str(),
            self.record_digest.as_ref().map_or("", Digest::as_str),
        )
    }
}

/// Selected, redacted DescribeRecord/ListRecordHistory metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordProjection {
    pub record_digest: Digest,
    pub provisioned_product_digest: Digest,
    pub product_digest: Digest,
    pub artifact_digest: Digest,
    pub status: ProvisionedProductStatus,
    pub created_at: Timestamp,
    pub last_updated_at: Timestamp,
    pub record_type: RecordType,
    pub error_class: Option<ErrorClass>,
    pub record_revision: u64,
    pub outputs_digest: Option<Digest>,
}

impl RecordProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn from_provider_fields<I>(
        scope: &AwsServiceCatalogScope,
        record_id: impl AsRef<str>,
        provisioned_product_id: impl AsRef<str>,
        product_id: impl AsRef<str>,
        artifact_id: impl AsRef<str>,
        status: ProvisionedProductStatus,
        created_at: impl Into<String>,
        last_updated_at: impl Into<String>,
        record_type: RecordType,
        error_class: Option<ErrorClass>,
        record_revision: u64,
        outputs: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let projection = Self {
            record_digest: digest_identifier(record_id.as_ref(), "record id")?,
            provisioned_product_digest: digest_identifier(
                provisioned_product_id.as_ref(),
                "provisioned product id",
            )?,
            product_digest: digest_identifier(product_id.as_ref(), "product id")?,
            artifact_digest: digest_identifier(artifact_id.as_ref(), "artifact id")?,
            status,
            created_at: Timestamp::new(created_at)?,
            last_updated_at: Timestamp::new(last_updated_at)?,
            record_type,
            error_class,
            record_revision,
            outputs_digest: digest_pairs("aws-service-catalog-record-outputs/v1", outputs),
        };
        projection.validate()?;
        if projection.record_digest != scope.record.record_id_digest
            || projection.provisioned_product_digest
                != scope.provisioned_product.provisioned_product_id_digest
            || projection.product_digest != scope.product.product_id_digest
            || projection.artifact_digest != scope.product.artifact_id_digest
            || projection.record_revision != scope.record.revision
        {
            return Err(AwsServiceCatalogError::ScopeViolation);
        }
        Ok(projection)
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.record_digest.validate()?;
        self.provisioned_product_digest.validate()?;
        self.product_digest.validate()?;
        self.artifact_digest.validate()?;
        if self.record_revision == 0 {
            return Err(AwsServiceCatalogError::RevisionMismatch);
        }
        Ok(())
    }

    pub fn sort_key(&self) -> (&str, &str) {
        (self.created_at.as_str(), self.record_digest.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Ready,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Available,
    UnderChange,
    Tainted,
    Error,
    Terminated,
    CursorLoop,
    CursorTampered,
    ReplayRejected,
    StaleMission,
    RevisionMismatch,
    RegistrationRevoked,
    Throttled,
    NotFound,
}

impl EvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

/// A bounded, digest-only set of revisions used by requests and proposals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionFences {
    pub product_revision: u64,
    pub artifact_revision: u64,
    pub provisioned_product_revision: u64,
    pub record_revision: u64,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub digest: Digest,
}

impl RevisionFences {
    pub fn from_scope(scope: &AwsServiceCatalogScope) -> Self {
        let mut fences = Self {
            product_revision: scope.product.product_revision,
            artifact_revision: scope.product.artifact_revision,
            provisioned_product_revision: scope.provisioned_product.revision,
            record_revision: scope.record.revision,
            project_revision: scope.project.revision,
            mission_revision: scope.mission.revision,
            work_product_revision: scope.work_product.revision,
            digest: Digest::from_text("unsealed-service-catalog-revision-fences"),
        };
        fences.digest = digest_serializable(&fences_for_digest(&fences));
        fences
    }

    pub fn validate_against(&self, scope: &AwsServiceCatalogScope) -> Result<()> {
        let expected = Self::from_scope(scope);
        if self != &expected {
            return Err(AwsServiceCatalogError::RevisionMismatch);
        }
        Ok(())
    }
}

fn fences_for_digest(fences: &RevisionFences) -> (&u64, &u64, &u64, &u64, &u64, &u64, &u64) {
    (
        &fences.product_revision,
        &fences.artifact_revision,
        &fences.provisioned_product_revision,
        &fences.record_revision,
        &fences.project_revision,
        &fences.mission_revision,
        &fences.work_product_revision,
    )
}

/// Redacted projection binding used by integrity checks. Kept here so both
/// provider response and service proposal code use the same deterministic
/// ordering.
pub fn sorted_projection_digests(
    products: &[ProvisionedProductProjection],
    records: &[RecordProjection],
) -> Digest {
    let products = products
        .iter()
        .map(ProvisionedProductProjection::digest)
        .collect::<Vec<_>>();
    let records = records
        .iter()
        .map(RecordProjection::digest)
        .collect::<Vec<_>>();
    digest_serializable(&(products, records))
}

pub fn operation_binding_digest(
    operation: &str,
    scope: &AwsServiceCatalogScope,
    query: Option<&SearchQuery>,
    page_size: u16,
    page_number: u16,
) -> Digest {
    Digest::from_parts(
        "aws-service-catalog-operation-binding/v1",
        &[
            ("operation", operation.to_owned()),
            ("scope", scope.digest().to_string()),
            (
                "query",
                query.map_or_else(String::new, |value| value.digest().to_string()),
            ),
            ("page_size", page_size.to_string()),
            ("page_number", page_number.to_string()),
        ],
    )
}

/// Stable service identifiers used by integrity validation.
pub fn identity_digest() -> Digest {
    Digest::from_parts(
        "aws-service-catalog-plugin-identity/v1",
        &[
            ("service", SERVICE_ID.to_owned()),
            ("provider", PROVIDER_ID.to_owned()),
            ("consumer", CONSUMER_ID.to_owned()),
            ("plugin", PLUGIN_VERSION.to_owned()),
            ("contract", CONTRACT_VERSION.to_owned()),
            ("contract_digest", CONTRACT_DIGEST.to_owned()),
        ],
    )
}
