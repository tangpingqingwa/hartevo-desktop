use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::str::FromStr;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use url::Url;

use crate::error::FirecrawlResearchEvidenceError;

pub const FIRECRAWL_API_VERSION: &str = "v2";
pub const FIRECRAWL_API_BASE_URL: &str = "https://api.firecrawl.dev";
pub const FIRECRAWL_SCRAPE_PATH: &str = "/v2/scrape";
pub const FIRECRAWL_CRAWL_PATH: &str = "/v2/crawl";
pub const FIRECRAWL_CRAWL_STATUS_PATH: &str = "/v2/crawl/{jobId}";
pub const FIRECRAWL_SECRET_REFERENCE_ENV: &str = "HARTEVO_FIRECRAWL_API_KEY_REFERENCE";

pub const MAX_HOST_BYTES: usize = 255;
pub const MAX_URL_BYTES: usize = 4_096;
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_MARKDOWN_BYTES: usize = 64 * 1024;
pub const MAX_SNIPPET_BYTES: usize = 2 * 1024;
pub const MAX_JOB_ID_BYTES: usize = 128;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const MAX_CRAWL_PAGES: u16 = 32;
pub const MAX_CRAWL_DEPTH: u8 = 4;
pub const MAX_TIMEOUT_MS: u64 = 120_000;
pub const MAX_CACHE_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub const MAX_ALLOWLIST_RULES: usize = 64;
pub const MAX_POLL_ATTEMPTS: u16 = 64;

pub type Digest = String;

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}").expect("writing into a String cannot fail");
    }
    output
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Layer 1 contract values must serialize");
    sha256_digest(&bytes)
}

pub fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> Digest {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0);
    }
    sha256_digest(&bytes)
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), FirecrawlResearchEvidenceError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(FirecrawlResearchEvidenceError::InvalidDigest { field })
    }
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), FirecrawlResearchEvidenceError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(FirecrawlResearchEvidenceError::InvalidInput {
            field,
            reason: format!("must be non-empty, bounded to {max_bytes} bytes, and content-safe"),
        });
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), FirecrawlResearchEvidenceError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'@')
        })
    {
        return Err(FirecrawlResearchEvidenceError::InvalidInput {
            field,
            reason: String::from("must contain only bounded identifier characters"),
        });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, FirecrawlResearchEvidenceError> {
                let value = value.into();
                validate_identifier(&value, $field, $max)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                sha256_digest(self.0.as_bytes())
            }

            pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = FirecrawlResearchEvidenceError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_identifier!(ProjectId, "project_id", 128);
bounded_identifier!(MissionId, "mission_id", 128);
bounded_identifier!(WorkProductId, "work_product_id", 128);
bounded_identifier!(FirecrawlJobId, "job_id", MAX_JOB_ID_BYTES);
bounded_identifier!(ClaimId, "claim_id", 128);
bounded_identifier!(ResultId, "result_id", 128);

pub type FirecrawlProjectId = ProjectId;
pub type FirecrawlMissionId = MissionId;
pub type FirecrawlWorkProductId = WorkProductId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn parse(value: &str) -> Result<Self, FirecrawlResearchEvidenceError> {
        let parts = value.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "plugin_version",
                reason: String::from("must be major.minor.patch"),
            });
        }
        Ok(Self {
            major: parts[0]
                .parse()
                .map_err(|_| FirecrawlResearchEvidenceError::InvalidInput {
                    field: "plugin_version",
                    reason: String::from("major must be numeric"),
                })?,
            minor: parts[1]
                .parse()
                .map_err(|_| FirecrawlResearchEvidenceError::InvalidInput {
                    field: "plugin_version",
                    reason: String::from("minor must be numeric"),
                })?,
            patch: parts[2]
                .parse()
                .map_err(|_| FirecrawlResearchEvidenceError::InvalidInput {
                    field: "plugin_version",
                    reason: String::from("patch must be numeric"),
                })?,
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Canonical public HTTPS URL. Fragments, credentials, non-HTTPS schemes,
/// private/local hosts, path traversal, and login/authentication pages are
/// rejected before an allowlist decision is made.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalUrl(String);

pub type FirecrawlUrl = CanonicalUrl;

impl CanonicalUrl {
    pub fn new(value: impl Into<String>) -> Result<Self, FirecrawlResearchEvidenceError> {
        let value = value.into();
        if value.len() > MAX_URL_BYTES || value.trim() != value {
            return Err(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "URL is empty, oversized, or surrounded by whitespace",
            });
        }
        let parsed =
            Url::parse(&value).map_err(|_| FirecrawlResearchEvidenceError::UrlRefused {
                reason: "URL is not syntactically valid",
            })?;
        if parsed.scheme() != "https" {
            return Err(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "only public HTTPS URLs are allowed",
            });
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "URL credentials are forbidden",
            });
        }
        if parsed.fragment().is_some() {
            return Err(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "URL fragments are not evidence identity",
            });
        }
        if parsed.port().is_some_and(|port| port != 443) {
            return Err(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "only the default HTTPS port is allowed",
            });
        }
        let host = parsed
            .host_str()
            .ok_or(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "URL must have a host",
            })?;
        let host = normalize_host(host)?;
        reject_private_or_local_host(&host)?;
        let path = parsed.path();
        if path.split('/').any(|segment| matches!(segment, "." | ".."))
            || path.to_ascii_lowercase().contains("%2f")
            || path.to_ascii_lowercase().contains("%5c")
        {
            return Err(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "URL path traversal or encoded separators are forbidden",
            });
        }
        if is_login_like_url(&parsed) {
            return Err(FirecrawlResearchEvidenceError::LoginPageRefused);
        }

        let path = if path.is_empty() {
            String::from("/")
        } else if path.len() > 1 {
            path.trim_end_matches('/').to_owned()
        } else {
            path.to_owned()
        };
        let query = canonical_query(&parsed);
        let mut canonical = format!("https://{host}{path}");
        if !query.is_empty() {
            canonical.push('?');
            canonical.push_str(&query);
        }
        if canonical.len() > MAX_URL_BYTES {
            return Err(FirecrawlResearchEvidenceError::UrlRefused {
                reason: "canonical URL is oversized",
            });
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn host(&self) -> &str {
        self.0
            .strip_prefix("https://")
            .and_then(|value| value.split_once('/'))
            .map_or_else(|| self.0.trim_start_matches("https://"), |(host, _)| host)
            .split('?')
            .next()
            .unwrap_or_default()
    }

    pub fn path(&self) -> &str {
        self.0
            .strip_prefix("https://")
            .and_then(|value| value.find('/').map(|index| &value[index..]))
            .unwrap_or("/")
            .split('?')
            .next()
            .unwrap_or("/")
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        let canonical = Self::new(self.0.clone())?;
        if canonical != *self {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "canonical_url",
                reason: String::from("URL is not in canonical form"),
            });
        }
        Ok(())
    }
}

impl fmt::Debug for CanonicalUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalUrl")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CanonicalUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CanonicalUrl {
    type Err = FirecrawlResearchEvidenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for CanonicalUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CanonicalUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

fn normalize_host(host: &str) -> Result<String, FirecrawlResearchEvidenceError> {
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || host.ends_with('.')
        || host.contains(':')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(FirecrawlResearchEvidenceError::UrlRefused {
            reason: "host is not an allowlist-safe DNS name",
        });
    }
    Ok(host.to_ascii_lowercase())
}

fn reject_private_or_local_host(host: &str) -> Result<(), FirecrawlResearchEvidenceError> {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".intranet")
        || lower.parse::<IpAddr>().is_ok()
    {
        return Err(FirecrawlResearchEvidenceError::UrlRefused {
            reason: "private, local, or IP hosts are forbidden",
        });
    }
    Ok(())
}

fn is_login_like_url(url: &Url) -> bool {
    let login_segments = [
        "login",
        "signin",
        "sign-in",
        "oauth",
        "authorize",
        "authentication",
    ];
    url.path_segments().is_some_and(|mut segments| {
        segments.any(|segment| {
            login_segments
                .iter()
                .any(|candidate| segment.eq_ignore_ascii_case(candidate))
        })
    })
}

fn canonical_query(url: &Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.sort();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(&key, &value);
    }
    serializer.finish()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirecrawlAllowlistRule {
    ExactHost { host: String },
    ExactUrl { url: CanonicalUrl },
}

impl FirecrawlAllowlistRule {
    pub fn exact_host(host: impl Into<String>) -> Result<Self, FirecrawlResearchEvidenceError> {
        Ok(Self::ExactHost {
            host: normalize_host(&host.into())?,
        })
    }

    pub fn exact_url(url: CanonicalUrl) -> Self {
        Self::ExactUrl { url }
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        match self {
            Self::ExactHost { host } => {
                normalize_host(host)?;
                reject_private_or_local_host(host)
            }
            Self::ExactUrl { url } => url.validate(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrawlUrlAllowlist {
    pub rules: BTreeSet<FirecrawlAllowlistRule>,
}

impl FirecrawlUrlAllowlist {
    pub fn new(
        rules: impl IntoIterator<Item = FirecrawlAllowlistRule>,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let rules = rules.into_iter().collect::<BTreeSet<_>>();
        if rules.is_empty() || rules.len() > MAX_ALLOWLIST_RULES {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "allowlist",
                reason: format!("must contain 1..={MAX_ALLOWLIST_RULES} unique rules"),
            });
        }
        for rule in &rules {
            rule.validate()?;
        }
        Ok(Self { rules })
    }

    pub fn exact_host(host: impl Into<String>) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new([FirecrawlAllowlistRule::exact_host(host)?])
    }

    pub fn exact_url(url: CanonicalUrl) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new([FirecrawlAllowlistRule::exact_url(url)])
    }

    pub fn fixture() -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::exact_host("example.com")
    }

    pub fn allows(&self, url: &CanonicalUrl) -> bool {
        self.rules.iter().any(|rule| match rule {
            FirecrawlAllowlistRule::ExactHost { host } => host == url.host(),
            FirecrawlAllowlistRule::ExactUrl { url: allowed } => allowed == url,
        })
    }

    pub fn first_url(&self) -> Result<CanonicalUrl, FirecrawlResearchEvidenceError> {
        for rule in &self.rules {
            if let FirecrawlAllowlistRule::ExactUrl { url } = rule {
                return Ok(url.clone());
            }
        }
        let host = self
            .rules
            .iter()
            .find_map(|rule| match rule {
                FirecrawlAllowlistRule::ExactHost { host } => Some(host.as_str()),
                FirecrawlAllowlistRule::ExactUrl { .. } => None,
            })
            .ok_or(FirecrawlResearchEvidenceError::InvalidInput {
                field: "allowlist",
                reason: String::from("allowlist has no usable URL"),
            })?;
        CanonicalUrl::new(format!("https://{host}/"))
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        Self::new(self.rules.clone()).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretReference {
    pub reference_id: String,
    pub scope_digest: Digest,
    pub credential_revision: u64,
    pub kind: SecretKind,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::with_kind(
            SecretKind::ApiKey,
            reference_id,
            scope_digest,
            credential_revision,
        )
    }

    pub fn with_kind(
        kind: SecretKind,
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let reference = Self {
            reference_id: reference_id.into(),
            scope_digest,
            credential_revision,
            kind,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn unscoped(
        reference_id: impl Into<String>,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new(reference_id, sha256_digest(b"unbound"), 1)
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        validate_identifier(&self.reference_id, "secret_reference", 256)?;
        validate_digest(&self.scope_digest, "secret_scope_digest")?;
        if self.credential_revision == 0 {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "credential_revision",
                reason: String::from("must be positive"),
            });
        }
        if self.kind != SecretKind::ApiKey {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "secret_kind",
                reason: String::from("only opaque API-key references are supported"),
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_parts([
            self.reference_id.as_str(),
            self.scope_digest.as_str(),
            &self.credential_revision.to_string(),
            "api_key",
        ])
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field(
                "reference_id_digest",
                &sha256_digest(self.reference_id.as_bytes()),
            )
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlContentFormat {
    Markdown,
    Html,
    RawHtml,
    Json,
    Links,
    Screenshot,
    Audio,
    Video,
}

impl FirecrawlContentFormat {
    pub const fn is_layer1_allowed(self) -> bool {
        matches!(self, Self::Markdown)
    }
}

pub type ContentFormat = FirecrawlContentFormat;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlCacheMode {
    PreferCache,
    RequireCache,
    BypassCache,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlCachePolicy {
    pub mode: FirecrawlCacheMode,
    pub max_age_ms: u64,
}

impl FirecrawlCachePolicy {
    pub fn new(
        mode: FirecrawlCacheMode,
        max_age_ms: u64,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let policy = Self { mode, max_age_ms };
        policy.validate()?;
        Ok(policy)
    }

    pub fn fixture() -> Self {
        Self {
            mode: FirecrawlCacheMode::PreferCache,
            max_age_ms: 60_000,
        }
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        if self.max_age_ms == 0 || self.max_age_ms > MAX_CACHE_AGE_MS {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "max_age_ms",
                reason: format!("must be in 1..={MAX_CACHE_AGE_MS}"),
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlExtractionSchema {
    pub schema_digest: Digest,
}

impl FirecrawlExtractionSchema {
    pub fn none() -> Self {
        Self {
            schema_digest: sha256_digest(b"firecrawl-extraction-schema:none"),
        }
    }

    pub fn new(schema_digest: Digest) -> Result<Self, FirecrawlResearchEvidenceError> {
        validate_digest(&schema_digest, "extraction_schema_digest")?;
        Ok(Self { schema_digest })
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        validate_digest(&self.schema_digest, "extraction_schema_digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlScrapeOptions {
    pub content_format: FirecrawlContentFormat,
    pub timeout_ms: u64,
    pub cache: FirecrawlCachePolicy,
    pub extraction_schema: FirecrawlExtractionSchema,
    pub max_markdown_bytes: usize,
}

impl FirecrawlScrapeOptions {
    pub fn markdown(
        timeout_ms: u64,
        cache: FirecrawlCachePolicy,
        extraction_schema: FirecrawlExtractionSchema,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let options = Self {
            content_format: FirecrawlContentFormat::Markdown,
            timeout_ms,
            cache,
            extraction_schema,
            max_markdown_bytes: MAX_MARKDOWN_BYTES,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn fixture() -> Self {
        Self::markdown(
            60_000,
            FirecrawlCachePolicy::fixture(),
            FirecrawlExtractionSchema::none(),
        )
        .expect("fixture options")
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        if !self.content_format.is_layer1_allowed() {
            return Err(FirecrawlResearchEvidenceError::UnsupportedContentFormat);
        }
        validate_timeout(self.timeout_ms)?;
        self.cache.validate()?;
        self.extraction_schema.validate()?;
        if self.max_markdown_bytes == 0 || self.max_markdown_bytes > MAX_MARKDOWN_BYTES {
            return Err(FirecrawlResearchEvidenceError::CrawlLimitExceeded {
                field: "max_markdown_bytes",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlCrawlOptions {
    pub content_format: FirecrawlContentFormat,
    pub max_pages: u16,
    pub max_discovery_depth: u8,
    pub timeout_ms: u64,
    pub cache: FirecrawlCachePolicy,
    pub extraction_schema: FirecrawlExtractionSchema,
    pub max_markdown_bytes: usize,
    pub allow_external_links: bool,
    pub allow_subdomains: bool,
}

impl FirecrawlCrawlOptions {
    pub fn markdown(
        max_pages: u16,
        max_discovery_depth: u8,
        timeout_ms: u64,
        cache: FirecrawlCachePolicy,
        extraction_schema: FirecrawlExtractionSchema,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let options = Self {
            content_format: FirecrawlContentFormat::Markdown,
            max_pages,
            max_discovery_depth,
            timeout_ms,
            cache,
            extraction_schema,
            max_markdown_bytes: MAX_MARKDOWN_BYTES,
            allow_external_links: false,
            allow_subdomains: false,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn fixture() -> Self {
        Self::markdown(
            8,
            2,
            60_000,
            FirecrawlCachePolicy::fixture(),
            FirecrawlExtractionSchema::none(),
        )
        .expect("fixture options")
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        if !self.content_format.is_layer1_allowed() {
            return Err(FirecrawlResearchEvidenceError::UnsupportedContentFormat);
        }
        if self.max_pages == 0 || self.max_pages > MAX_CRAWL_PAGES {
            return Err(FirecrawlResearchEvidenceError::CrawlLimitExceeded { field: "max_pages" });
        }
        if self.max_discovery_depth > MAX_CRAWL_DEPTH {
            return Err(FirecrawlResearchEvidenceError::CrawlLimitExceeded {
                field: "max_discovery_depth",
            });
        }
        if self.allow_external_links {
            return Err(FirecrawlResearchEvidenceError::ExternalLinkExpansionRefused);
        }
        if self.allow_subdomains {
            return Err(FirecrawlResearchEvidenceError::SubdomainExpansionRefused);
        }
        validate_timeout(self.timeout_ms)?;
        self.cache.validate()?;
        self.extraction_schema.validate()?;
        if self.max_markdown_bytes == 0 || self.max_markdown_bytes > MAX_MARKDOWN_BYTES {
            return Err(FirecrawlResearchEvidenceError::CrawlLimitExceeded {
                field: "max_markdown_bytes",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

fn validate_timeout(timeout_ms: u64) -> Result<(), FirecrawlResearchEvidenceError> {
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(FirecrawlResearchEvidenceError::InvalidInput {
            field: "timeout_ms",
            reason: format!("must be in 1..={MAX_TIMEOUT_MS}"),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirecrawlJobSpec {
    Scrape {
        url: CanonicalUrl,
        options: FirecrawlScrapeOptions,
    },
    Crawl {
        start_url: CanonicalUrl,
        options: FirecrawlCrawlOptions,
    },
}

pub type FirecrawlJob = FirecrawlJobSpec;

impl FirecrawlJobSpec {
    pub fn url(&self) -> &CanonicalUrl {
        match self {
            Self::Scrape { url, .. } | Self::Crawl { start_url: url, .. } => url,
        }
    }

    pub const fn kind(&self) -> FirecrawlJobKind {
        match self {
            Self::Scrape { .. } => FirecrawlJobKind::Scrape,
            Self::Crawl { .. } => FirecrawlJobKind::Crawl,
        }
    }

    pub fn options_digest(&self) -> Digest {
        match self {
            Self::Scrape { options, .. } => options.digest(),
            Self::Crawl { options, .. } => options.digest(),
        }
    }

    pub fn content_format(&self) -> FirecrawlContentFormat {
        match self {
            Self::Scrape { options, .. } => options.content_format,
            Self::Crawl { options, .. } => options.content_format,
        }
    }

    pub fn extraction_schema_digest(&self) -> &Digest {
        match self {
            Self::Scrape { options, .. } => &options.extraction_schema.schema_digest,
            Self::Crawl { options, .. } => &options.extraction_schema.schema_digest,
        }
    }

    pub fn max_pages(&self) -> u16 {
        match self {
            Self::Scrape { .. } => 1,
            Self::Crawl { options, .. } => options.max_pages,
        }
    }

    pub fn max_markdown_bytes(&self) -> usize {
        match self {
            Self::Scrape { options, .. } => options.max_markdown_bytes,
            Self::Crawl { options, .. } => options.max_markdown_bytes,
        }
    }

    pub fn max_age_ms(&self) -> u64 {
        match self {
            Self::Scrape { options, .. } => options.cache.max_age_ms,
            Self::Crawl { options, .. } => options.cache.max_age_ms,
        }
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.url().validate()?;
        match self {
            Self::Scrape { options, .. } => options.validate(),
            Self::Crawl { options, .. } => options.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlJobKind {
    Scrape,
    Crawl,
}

impl fmt::Display for FirecrawlJobKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Scrape => "scrape",
            Self::Crawl => "crawl",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlJobRequest {
    pub scope: FirecrawlScope,
    pub job_id: FirecrawlJobId,
    pub idempotency_key: String,
    pub requested_at_ms: u64,
    pub job: FirecrawlJobSpec,
}

pub type FirecrawlRequest = FirecrawlJobRequest;

impl FirecrawlJobRequest {
    pub fn new(
        scope: FirecrawlScope,
        job_id: FirecrawlJobId,
        idempotency_key: impl Into<String>,
        requested_at_ms: u64,
        job: FirecrawlJobSpec,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let request = Self {
            scope,
            job_id,
            idempotency_key: idempotency_key.into(),
            requested_at_ms,
            job,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn scrape(
        scope: FirecrawlScope,
        job_id: FirecrawlJobId,
        idempotency_key: impl Into<String>,
        requested_at_ms: u64,
        url: CanonicalUrl,
        options: FirecrawlScrapeOptions,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new(
            scope,
            job_id,
            idempotency_key,
            requested_at_ms,
            FirecrawlJobSpec::Scrape { url, options },
        )
    }

    pub fn crawl(
        scope: FirecrawlScope,
        job_id: FirecrawlJobId,
        idempotency_key: impl Into<String>,
        requested_at_ms: u64,
        start_url: CanonicalUrl,
        options: FirecrawlCrawlOptions,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new(
            scope,
            job_id,
            idempotency_key,
            requested_at_ms,
            FirecrawlJobSpec::Crawl { start_url, options },
        )
    }

    pub fn kind(&self) -> FirecrawlJobKind {
        self.job.kind()
    }

    pub fn url(&self) -> &CanonicalUrl {
        self.job.url()
    }

    pub fn options_digest(&self) -> Digest {
        self.job.options_digest()
    }

    pub fn request_digest(&self) -> Digest {
        digest_parts([
            self.scope.digest().as_str(),
            self.job_id.as_str(),
            self.idempotency_key.as_str(),
            &self.requested_at_ms.to_string(),
            self.kind().to_string().as_str(),
            self.url().as_str(),
            self.options_digest().as_str(),
        ])
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.scope.validate()?;
        self.job_id.validate()?;
        validate_identifier(
            &self.idempotency_key,
            "idempotency_key",
            MAX_IDEMPOTENCY_KEY_BYTES,
        )?;
        self.job.validate()?;
        if self.requested_at_ms == 0 {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "requested_at_ms",
                reason: String::from("must be positive"),
            });
        }
        if !self.scope.allowlist.allows(self.url()) {
            return Err(FirecrawlResearchEvidenceError::UrlNotAllowlisted {
                url: self.url().to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlScope {
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub allowlist: FirecrawlUrlAllowlist,
    pub permission_revision: u64,
    pub permission_digest: Digest,
}

pub type FirecrawlResearchScope = FirecrawlScope;

impl FirecrawlScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        project_revision: u64,
        mission_id: MissionId,
        mission_revision: u64,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        allowlist: FirecrawlUrlAllowlist,
        permission_revision: u64,
        permission_digest: Digest,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let scope = Self {
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            allowlist,
            permission_revision,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn fixture(mission: impl Into<String>) -> Result<Self, FirecrawlResearchEvidenceError> {
        let mission_id = MissionId::new(mission)?;
        Self::new(
            ProjectId::new("project-firecrawl-fixture")?,
            1,
            mission_id,
            1,
            WorkProductId::new("work-product-firecrawl-fixture")?,
            1,
            FirecrawlUrlAllowlist::fixture()?,
            1,
            sha256_digest(b"firecrawl-permission-fixture-v1"),
        )
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        if self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || self.permission_revision == 0
        {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "scope_revision",
                reason: String::from(
                    "Project, Mission, Work Product and permission revisions must be positive",
                ),
            });
        }
        self.allowlist.validate()?;
        validate_digest(&self.permission_digest, "permission_digest")
    }

    pub fn permits(&self, url: &CanonicalUrl) -> bool {
        self.allowlist.allows(url)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlJobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Canceled,
    Expired,
    ProviderUnknown,
}

impl FirecrawlJobStatus {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "completed" | "complete" | "success" => Self::Completed,
            "failed" | "failure" => Self::Failed,
            "canceled" | "cancelled" => Self::Canceled,
            "expired" => Self::Expired,
            _ => Self::ProviderUnknown,
        }
    }

    pub const fn is_source_evidence(self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl fmt::Display for FirecrawlJobStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Expired => "expired",
            Self::ProviderUnknown => "provider_unknown",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl FirecrawlProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

pub type ProviderProvenance = FirecrawlProvenance;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlUrlDescription {
    pub canonical_url: CanonicalUrl,
    pub host: String,
    pub url_digest: Digest,
    pub allowlisted: bool,
    pub login_page: bool,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub first_party: bool,
}

impl FirecrawlUrlDescription {
    pub fn for_scope(
        url: CanonicalUrl,
        scope: &FirecrawlScope,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        Ok(Self {
            host: url.host().to_owned(),
            url_digest: url.digest(),
            allowlisted: scope.permits(&url),
            login_page: false,
            canonical_url: url,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            first_party: false,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlJobDescription {
    pub job_id: FirecrawlJobId,
    pub job_kind: FirecrawlJobKind,
    pub canonical_url: CanonicalUrl,
    pub options_digest: Digest,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub mission_revision: u64,
    pub project_revision: u64,
    pub work_product_revision: u64,
    pub status: FirecrawlJobStatus,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub first_party: bool,
}

impl FirecrawlJobDescription {
    pub fn from_request(request: &FirecrawlJobRequest) -> Self {
        Self {
            job_id: request.job_id.clone(),
            job_kind: request.kind(),
            canonical_url: request.url().clone(),
            options_digest: request.options_digest(),
            request_digest: request.request_digest(),
            scope_digest: request.scope.digest(),
            mission_revision: request.scope.mission_revision,
            project_revision: request.scope.project_revision,
            work_product_revision: request.scope.work_product_revision,
            status: FirecrawlJobStatus::ProviderUnknown,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlCitation {
    pub canonical_url: CanonicalUrl,
    pub title: String,
    pub snippet_digest: Digest,
    pub content_digest: Digest,
    pub citation_digest: Digest,
}

impl FirecrawlCitation {
    pub(crate) fn new(
        canonical_url: CanonicalUrl,
        title: String,
        snippet_digest: Digest,
        content_digest: Digest,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        validate_text(&title, "title", MAX_TITLE_BYTES)?;
        validate_digest(&snippet_digest, "snippet_digest")?;
        validate_digest(&content_digest, "content_digest")?;
        let citation_digest = digest_parts([
            canonical_url.as_str(),
            title.as_str(),
            snippet_digest.as_str(),
            content_digest.as_str(),
        ]);
        Ok(Self {
            canonical_url,
            title,
            snippet_digest,
            content_digest,
            citation_digest,
        })
    }

    pub fn calculate_digest(&self) -> Digest {
        digest_parts([
            self.canonical_url.as_str(),
            self.title.as_str(),
            self.snippet_digest.as_str(),
            self.content_digest.as_str(),
        ])
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.canonical_url.validate()?;
        validate_text(&self.title, "title", MAX_TITLE_BYTES)?;
        validate_digest(&self.snippet_digest, "snippet_digest")?;
        validate_digest(&self.content_digest, "content_digest")?;
        if self.citation_digest != self.calculate_digest() {
            return Err(FirecrawlResearchEvidenceError::CitationMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlPageEvidence {
    pub canonical_url: CanonicalUrl,
    pub title: String,
    pub status_code: u16,
    pub content_type: String,
    pub markdown: String,
    pub snippet_digest: Digest,
    pub content_digest: Digest,
    pub citation: FirecrawlCitation,
    pub extraction_schema_digest: Digest,
    pub page_digest: Digest,
}

impl fmt::Debug for FirecrawlPageEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirecrawlPageEvidence")
            .field("canonical_url", &self.canonical_url)
            .field("title", &self.title)
            .field("status_code", &self.status_code)
            .field("content_type", &self.content_type)
            .field("markdown_digest", &self.content_digest)
            .field("snippet_digest", &self.snippet_digest)
            .field("citation", &self.citation)
            .field("extraction_schema_digest", &self.extraction_schema_digest)
            .field("page_digest", &self.page_digest)
            .finish()
    }
}

impl FirecrawlPageEvidence {
    pub(crate) fn new(
        canonical_url: CanonicalUrl,
        title: String,
        status_code: u16,
        content_type: String,
        markdown: String,
        extraction_schema_digest: Digest,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        validate_text(&title, "title", MAX_TITLE_BYTES)?;
        validate_markdown(&markdown, MAX_MARKDOWN_BYTES)?;
        validate_content_type(&content_type)?;
        validate_digest(&extraction_schema_digest, "extraction_schema_digest")?;
        let content_digest = sha256_digest(markdown.as_bytes());
        let snippet = bounded_snippet(&markdown);
        let snippet_digest = sha256_digest(snippet.as_bytes());
        let citation = FirecrawlCitation::new(
            canonical_url.clone(),
            title.clone(),
            snippet_digest.clone(),
            content_digest.clone(),
        )?;
        let page_digest = page_digest_for(
            &canonical_url,
            &title,
            status_code,
            &content_type,
            &content_digest,
            &snippet_digest,
            &citation.citation_digest,
            &extraction_schema_digest,
        );
        Ok(Self {
            canonical_url,
            title,
            status_code,
            content_type,
            markdown,
            snippet_digest,
            content_digest,
            citation,
            extraction_schema_digest,
            page_digest,
        })
    }

    pub fn calculate_digest(&self) -> Digest {
        page_digest_for(
            &self.canonical_url,
            &self.title,
            self.status_code,
            &self.content_type,
            &self.content_digest,
            &self.snippet_digest,
            &self.citation.citation_digest,
            &self.extraction_schema_digest,
        )
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.canonical_url.validate()?;
        validate_text(&self.title, "title", MAX_TITLE_BYTES)?;
        validate_content_type(&self.content_type)?;
        validate_markdown(&self.markdown, MAX_MARKDOWN_BYTES)?;
        validate_digest(&self.content_digest, "content_digest")?;
        validate_digest(&self.snippet_digest, "snippet_digest")?;
        validate_digest(&self.extraction_schema_digest, "extraction_schema_digest")?;
        if self.content_digest != sha256_digest(self.markdown.as_bytes()) {
            return Err(FirecrawlResearchEvidenceError::ContentDigestMismatch);
        }
        if self.snippet_digest != sha256_digest(bounded_snippet(&self.markdown).as_bytes()) {
            return Err(FirecrawlResearchEvidenceError::CitationMismatch);
        }
        self.citation.validate()?;
        if self.citation.canonical_url != self.canonical_url
            || self.citation.title != self.title
            || self.citation.content_digest != self.content_digest
            || self.citation.snippet_digest != self.snippet_digest
        {
            return Err(FirecrawlResearchEvidenceError::CitationMismatch);
        }
        if self.page_digest != self.calculate_digest() {
            return Err(FirecrawlResearchEvidenceError::PageDigestMismatch);
        }
        Ok(())
    }
}

fn page_digest_for(
    url: &CanonicalUrl,
    title: &str,
    status_code: u16,
    content_type: &str,
    content_digest: &str,
    snippet_digest: &str,
    citation_digest: &str,
    extraction_schema_digest: &str,
) -> Digest {
    digest_parts([
        url.as_str(),
        title,
        &status_code.to_string(),
        content_type,
        content_digest,
        snippet_digest,
        citation_digest,
        extraction_schema_digest,
    ])
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlResearchEvidence {
    pub scope_digest: Digest,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub job_id: FirecrawlJobId,
    pub job_kind: FirecrawlJobKind,
    pub status: FirecrawlJobStatus,
    pub canonical_url: CanonicalUrl,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub markdown: Option<String>,
    pub snippet_digest: Option<Digest>,
    pub content_digest: Option<Digest>,
    pub citation: Option<FirecrawlCitation>,
    pub extraction_schema_digest: Digest,
    pub pages: Vec<FirecrawlPageEvidence>,
    pub job_digest: Digest,
    pub page_digest: Option<Digest>,
    pub citation_digest: Option<Digest>,
    pub response_digest: Digest,
    pub observed_at_ms: u64,
    pub cached_at_ms: Option<u64>,
    pub provenance: FirecrawlProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl fmt::Debug for FirecrawlResearchEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirecrawlResearchEvidence")
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("registration_digest", &self.registration_digest)
            .field("request_digest", &self.request_digest)
            .field("job_id", &self.job_id)
            .field("job_kind", &self.job_kind)
            .field("status", &self.status)
            .field("canonical_url", &self.canonical_url)
            .field("title", &self.title)
            .field("content_type", &self.content_type)
            .field("markdown_digest", &self.content_digest)
            .field("snippet_digest", &self.snippet_digest)
            .field("citation_digest", &self.citation_digest)
            .field("extraction_schema_digest", &self.extraction_schema_digest)
            .field("pages", &self.pages)
            .field("job_digest", &self.job_digest)
            .field("response_digest", &self.response_digest)
            .field("provenance", &self.provenance)
            .field("native_transport", &self.native_transport)
            .field("native_connected", &self.native_connected)
            .finish()
    }
}

impl FirecrawlResearchEvidence {
    pub(crate) fn from_parts(
        request: &FirecrawlJobRequest,
        provider_job_id: FirecrawlJobId,
        status: FirecrawlJobStatus,
        pages: Vec<FirecrawlPageEvidence>,
        extraction_schema_digest: Digest,
        observed_at_ms: u64,
        cached_at_ms: Option<u64>,
        registration_digest: Digest,
        provenance: FirecrawlProvenance,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let scope_digest = request.scope.digest();
        let permission_digest = request.scope.permission_digest.clone();
        let first = pages.first();
        let canonical_url = first
            .map(|page| page.canonical_url.clone())
            .unwrap_or_else(|| request.url().clone());
        let title = first.map(|page| page.title.clone());
        let content_type = first.map(|page| page.content_type.clone());
        let markdown = first.map(|page| page.markdown.clone());
        let snippet_digest = first.map(|page| page.snippet_digest.clone());
        let content_digest = first.map(|page| page.content_digest.clone());
        let citation = first.map(|page| page.citation.clone());
        let page_digest = first.map(|page| page.page_digest.clone());
        let citation_digest = first.map(|page| page.citation.citation_digest.clone());
        let page_digests = pages
            .iter()
            .map(|page| page.page_digest.as_str())
            .collect::<Vec<_>>();
        let job_digest = digest_parts([
            request.request_digest().as_str(),
            provider_job_id.as_str(),
            &status.to_string(),
            extraction_schema_digest.as_str(),
            &page_digests.join("|"),
        ]);
        let response_digest = digest_parts([
            request.request_digest().as_str(),
            job_digest.as_str(),
            registration_digest.as_str(),
            &observed_at_ms.to_string(),
            &cached_at_ms.map_or_else(String::new, |value| value.to_string()),
        ]);
        let evidence = Self {
            scope_digest,
            project_id: request.scope.project_id.clone(),
            project_revision: request.scope.project_revision,
            mission_id: request.scope.mission_id.clone(),
            mission_revision: request.scope.mission_revision,
            work_product_id: request.scope.work_product_id.clone(),
            work_product_revision: request.scope.work_product_revision,
            permission_digest,
            registration_digest,
            request_digest: request.request_digest(),
            job_id: provider_job_id,
            job_kind: request.kind(),
            status,
            canonical_url,
            title,
            content_type,
            markdown,
            snippet_digest,
            content_digest,
            citation,
            extraction_schema_digest,
            pages,
            job_digest,
            page_digest,
            citation_digest,
            response_digest,
            observed_at_ms,
            cached_at_ms,
            provenance,
            native_transport: false,
            native_connected: false,
            first_party: false,
        };
        evidence.validate_for(request)?;
        Ok(evidence)
    }

    pub fn is_source_evidence(&self) -> bool {
        self.status.is_source_evidence() && !self.pages.is_empty()
    }

    pub fn calculate_job_digest(&self) -> Digest {
        let page_digests = self
            .pages
            .iter()
            .map(|page| page.page_digest.as_str())
            .collect::<Vec<_>>();
        digest_parts([
            self.request_digest.as_str(),
            self.job_id.as_str(),
            &self.status.to_string(),
            self.extraction_schema_digest.as_str(),
            &page_digests.join("|"),
        ])
    }

    pub fn calculate_response_digest(&self) -> Digest {
        digest_parts([
            self.request_digest.as_str(),
            self.job_digest.as_str(),
            self.registration_digest.as_str(),
            &self.observed_at_ms.to_string(),
            &self
                .cached_at_ms
                .map_or_else(String::new, |value| value.to_string()),
        ])
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        validate_digest(&self.scope_digest, "scope_digest")?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        if self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
        {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "evidence_revision",
                reason: String::from(
                    "Project, Mission and Work Product revisions must be positive",
                ),
            });
        }
        validate_digest(&self.permission_digest, "permission_digest")?;
        validate_digest(&self.registration_digest, "registration_digest")?;
        validate_digest(&self.request_digest, "request_digest")?;
        validate_digest(&self.extraction_schema_digest, "extraction_schema_digest")?;
        validate_digest(&self.job_digest, "job_digest")?;
        validate_digest(&self.response_digest, "response_digest")?;
        self.job_id.validate()?;
        self.canonical_url.validate()?;
        if self.native_transport || self.native_connected || self.first_party {
            return Err(FirecrawlResearchEvidenceError::InvalidContract {
                reason: "Layer 1 evidence cannot claim native, connected, or first-party authority",
            });
        }
        if self.pages.len() > MAX_CRAWL_PAGES as usize {
            return Err(FirecrawlResearchEvidenceError::CrawlLimitExceeded {
                field: "response_pages",
            });
        }
        for page in &self.pages {
            page.validate()?;
        }
        if self.status.is_source_evidence() {
            if self.pages.is_empty() {
                return Err(FirecrawlResearchEvidenceError::MalformedResponse);
            }
            let first = &self.pages[0];
            if self.canonical_url != first.canonical_url
                || self.title.as_deref() != Some(first.title.as_str())
                || self.content_type.as_deref() != Some(first.content_type.as_str())
                || self.markdown.as_deref() != Some(first.markdown.as_str())
                || self.snippet_digest.as_ref() != Some(&first.snippet_digest)
                || self.content_digest.as_ref() != Some(&first.content_digest)
                || self.citation.as_ref() != Some(&first.citation)
                || self.page_digest.as_ref() != Some(&first.page_digest)
                || self.citation_digest.as_ref() != Some(&first.citation.citation_digest)
            {
                return Err(FirecrawlResearchEvidenceError::CitationMismatch);
            }
        }
        if self.job_digest != self.calculate_job_digest() {
            return Err(FirecrawlResearchEvidenceError::JobDigestMismatch);
        }
        if self.response_digest != self.calculate_response_digest() {
            return Err(FirecrawlResearchEvidenceError::ContentDigestMismatch);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        request: &FirecrawlJobRequest,
    ) -> Result<(), FirecrawlResearchEvidenceError> {
        request.validate()?;
        self.validate()?;
        if self.scope_digest != request.scope.digest()
            || self.project_id != request.scope.project_id
            || self.project_revision != request.scope.project_revision
            || self.mission_id != request.scope.mission_id
            || self.mission_revision != request.scope.mission_revision
            || self.work_product_id != request.scope.work_product_id
            || self.work_product_revision != request.scope.work_product_revision
            || self.request_digest != request.request_digest()
            || self.job_kind != request.kind()
            || (self.canonical_url != *request.url() && self.pages.is_empty())
        {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if self.pages.len() > request.job.max_pages() as usize {
            return Err(FirecrawlResearchEvidenceError::CrawlLimitExceeded {
                field: "response_pages",
            });
        }
        if self.extraction_schema_digest != *request.job.extraction_schema_digest() {
            return Err(FirecrawlResearchEvidenceError::ExtractionSchemaDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlProposalStatus {
    ProposalOnly,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlResearchProposal {
    pub proposal_status: FirecrawlProposalStatus,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub job_id: FirecrawlJobId,
    pub job_kind: FirecrawlJobKind,
    pub canonical_url: CanonicalUrl,
    pub title_digest: Digest,
    pub status: FirecrawlJobStatus,
    pub content_type: String,
    pub content_digest: Digest,
    pub snippet_digest: Digest,
    pub citation_digest: Digest,
    pub extraction_schema_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub job_digest: Digest,
    pub page_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub provenance: FirecrawlProvenance,
    pub adopted: bool,
    pub external_write_performed: bool,
    pub durable_native_receipt: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl fmt::Debug for FirecrawlResearchProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirecrawlResearchProposal")
            .field("proposal_status", &self.proposal_status)
            .field("project_id", &self.project_id)
            .field("project_revision", &self.project_revision)
            .field("mission_id", &self.mission_id)
            .field("mission_revision", &self.mission_revision)
            .field("work_product_id", &self.work_product_id)
            .field("work_product_revision", &self.work_product_revision)
            .field("job_id", &self.job_id)
            .field("canonical_url", &self.canonical_url)
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("content_digest", &self.content_digest)
            .field("snippet_digest", &self.snippet_digest)
            .field("citation_digest", &self.citation_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("proposal_digest", &self.proposal_digest)
            .field("provenance", &self.provenance)
            .field("adopted", &self.adopted)
            .field("native_connected", &self.native_connected)
            .finish()
    }
}

impl FirecrawlResearchProposal {
    pub(crate) fn from_evidence(
        work_product: &MissionWorkProduct,
        evidence: &FirecrawlResearchEvidence,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        evidence.validate()?;
        if !evidence.is_source_evidence() {
            return Err(FirecrawlResearchEvidenceError::StatusNotSourceEvidence {
                status: evidence.status.to_string(),
            });
        }
        if work_product.project_id != evidence.project_id
            || work_product.mission_id != evidence.mission_id
            || work_product.mission_revision != evidence.mission_revision
        {
            return Err(FirecrawlResearchEvidenceError::StaleMissionRevision {
                expected: work_product.mission_revision,
                actual: evidence.mission_revision,
            });
        }
        if work_product.project_revision != evidence.project_revision {
            return Err(FirecrawlResearchEvidenceError::StaleProjectRevision {
                expected: work_product.project_revision,
                actual: evidence.project_revision,
            });
        }
        if work_product.work_product_id != evidence.work_product_id
            || work_product.work_product_revision != evidence.work_product_revision
        {
            return Err(FirecrawlResearchEvidenceError::StaleWorkProductRevision {
                expected: work_product.work_product_revision,
                actual: evidence.work_product_revision,
            });
        }
        let page = evidence
            .pages
            .first()
            .ok_or(FirecrawlResearchEvidenceError::MalformedResponse)?;
        let mut proposal = Self {
            proposal_status: FirecrawlProposalStatus::ProposalOnly,
            project_id: work_product.project_id.clone(),
            project_revision: work_product.project_revision,
            mission_id: work_product.mission_id.clone(),
            mission_revision: work_product.mission_revision,
            work_product_id: work_product.work_product_id.clone(),
            work_product_revision: work_product.work_product_revision,
            job_id: evidence.job_id.clone(),
            job_kind: evidence.job_kind,
            canonical_url: page.canonical_url.clone(),
            title_digest: sha256_digest(page.title.as_bytes()),
            status: evidence.status,
            content_type: page.content_type.clone(),
            content_digest: page.content_digest.clone(),
            snippet_digest: page.snippet_digest.clone(),
            citation_digest: page.citation.citation_digest.clone(),
            extraction_schema_digest: evidence.extraction_schema_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            request_digest: evidence.request_digest.clone(),
            job_digest: evidence.job_digest.clone(),
            page_digest: page.page_digest.clone(),
            evidence_digest: canonical_digest(evidence),
            proposal_digest: String::new(),
            provenance: evidence.provenance,
            adopted: false,
            external_write_performed: false,
            durable_native_receipt: false,
            native_connected: false,
            first_party: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        canonical_digest(&copy)
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        self.job_id.validate()?;
        self.canonical_url.validate()?;
        validate_text(&self.content_type, "content_type", 128)?;
        for (value, field) in [
            (&self.title_digest, "title_digest"),
            (&self.content_digest, "content_digest"),
            (&self.snippet_digest, "snippet_digest"),
            (&self.citation_digest, "citation_digest"),
            (&self.extraction_schema_digest, "extraction_schema_digest"),
            (&self.scope_digest, "scope_digest"),
            (&self.permission_digest, "permission_digest"),
            (&self.registration_digest, "registration_digest"),
            (&self.request_digest, "request_digest"),
            (&self.job_digest, "job_digest"),
            (&self.page_digest, "page_digest"),
            (&self.evidence_digest, "evidence_digest"),
            (&self.proposal_digest, "proposal_digest"),
        ] {
            validate_digest(value, field)?;
        }
        if self.proposal_status != FirecrawlProposalStatus::ProposalOnly
            || self.adopted
            || self.external_write_performed
            || self.durable_native_receipt
            || self.native_connected
            || self.first_party
        {
            return Err(FirecrawlResearchEvidenceError::AdoptionForbidden);
        }
        if self.proposal_digest != self.calculate_digest() {
            return Err(FirecrawlResearchEvidenceError::ContentDigestMismatch);
        }
        Ok(())
    }

    pub const fn can_claim_verified_source(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionWorkProduct {
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub content_digest: Digest,
    pub objective_digest: Digest,
}

impl MissionWorkProduct {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        project_revision: u64,
        mission_id: MissionId,
        mission_revision: u64,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        content_digest: Digest,
        objective_digest: Digest,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let work_product = Self {
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            content_digest,
            objective_digest,
        };
        work_product.validate()?;
        Ok(work_product)
    }

    pub fn fixture(scope: &FirecrawlScope) -> Self {
        Self::new(
            scope.project_id.clone(),
            scope.project_revision,
            scope.mission_id.clone(),
            scope.mission_revision,
            scope.work_product_id.clone(),
            scope.work_product_revision,
            sha256_digest(b"firecrawl-work-product-content"),
            sha256_digest(b"firecrawl-research-objective"),
        )
        .expect("fixture work product")
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        if self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
        {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "work_product_revision",
                reason: String::from("revisions must be positive"),
            });
        }
        validate_digest(&self.content_digest, "work_product_content_digest")?;
        validate_digest(&self.objective_digest, "objective_digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlResearchReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub request_digest: Digest,
    pub job_digest: Digest,
    pub page_digest: Digest,
    pub citation_digest: Digest,
    pub content_digest: Digest,
    pub extraction_schema_digest: Digest,
    pub registration_digest: Digest,
    pub permission_digest: Digest,
    pub recorded_provenance: FirecrawlProvenance,
    pub durable: bool,
    pub external_write_performed: bool,
    pub adopted: bool,
    pub native_connected: bool,
    pub receipt_digest: Digest,
}

impl FirecrawlResearchReceipt {
    pub(crate) fn from_proposal(proposal: &FirecrawlResearchProposal) -> Self {
        let mut receipt = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            job_digest: proposal.job_digest.clone(),
            page_digest: proposal.page_digest.clone(),
            citation_digest: proposal.citation_digest.clone(),
            content_digest: proposal.content_digest.clone(),
            extraction_schema_digest: proposal.extraction_schema_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            recorded_provenance: proposal.provenance,
            durable: false,
            external_write_performed: false,
            adopted: false,
            native_connected: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.receipt_digest.clear();
        canonical_digest(&copy)
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        for (value, field) in [
            (&self.proposal_digest, "proposal_digest"),
            (&self.evidence_digest, "evidence_digest"),
            (&self.request_digest, "request_digest"),
            (&self.job_digest, "job_digest"),
            (&self.page_digest, "page_digest"),
            (&self.citation_digest, "citation_digest"),
            (&self.content_digest, "content_digest"),
            (&self.extraction_schema_digest, "extraction_schema_digest"),
            (&self.registration_digest, "registration_digest"),
            (&self.permission_digest, "permission_digest"),
            (&self.receipt_digest, "receipt_digest"),
        ] {
            validate_digest(value, field)?;
        }
        if self.durable || self.external_write_performed || self.adopted || self.native_connected {
            return Err(FirecrawlResearchEvidenceError::AdoptionForbidden);
        }
        if self.receipt_digest != self.calculate_digest() {
            return Err(FirecrawlResearchEvidenceError::ContentDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlReadbackField {
    Scope,
    Permission,
    Registration,
    Request,
    Job,
    Page,
    Content,
    Citation,
    ExtractionSchema,
    Receipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VerifiedFirecrawlResearchResult {
    pub verified: bool,
    pub adopted: bool,
    pub read_back: bool,
    pub kernel_verified: bool,
    pub native_connected: bool,
    pub first_party: bool,
    pub checked_fields: Vec<FirecrawlReadbackField>,
    pub verification_digest: Digest,
}

impl VerifiedFirecrawlResearchResult {
    pub fn verified_from(
        proposal: &FirecrawlResearchProposal,
        receipt: &FirecrawlResearchReceipt,
    ) -> Self {
        let checked_fields = vec![
            FirecrawlReadbackField::Scope,
            FirecrawlReadbackField::Permission,
            FirecrawlReadbackField::Registration,
            FirecrawlReadbackField::Request,
            FirecrawlReadbackField::Job,
            FirecrawlReadbackField::Page,
            FirecrawlReadbackField::Content,
            FirecrawlReadbackField::Citation,
            FirecrawlReadbackField::ExtractionSchema,
            FirecrawlReadbackField::Receipt,
        ];
        Self {
            verified: true,
            adopted: false,
            read_back: false,
            kernel_verified: false,
            native_connected: false,
            first_party: false,
            verification_digest: digest_parts([
                proposal.proposal_digest.as_str(),
                receipt.receipt_digest.as_str(),
                "layer1-recording-only",
            ]),
            checked_fields,
        }
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        validate_digest(&self.verification_digest, "verification_digest")?;
        if !self.verified
            || self.adopted
            || self.read_back
            || self.kernel_verified
            || self.native_connected
            || self.first_party
        {
            return Err(FirecrawlResearchEvidenceError::InvalidContract {
                reason: "Layer 1 verification cannot claim adoption, native readback, or kernel authority",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlPluginRegistration {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub permission_revision: u64,
    pub permission_digest: Digest,
    pub registration_revision: u64,
    pub reversible: bool,
    pub enabled: bool,
    pub registration_digest: Digest,
}

pub type FirecrawlPermissionRegistration = FirecrawlPluginRegistration;

impl FirecrawlPluginRegistration {
    pub fn new(scope: &FirecrawlScope) -> Result<Self, FirecrawlResearchEvidenceError> {
        let mut registration = Self {
            plugin_id: String::from("firecrawl.research-evidence"),
            plugin_version: PluginVersion::V1,
            contract_version: String::from("EXT-FIRECRAWL-01-L1/v1"),
            scope_digest: scope.digest(),
            permission_revision: scope.permission_revision,
            permission_digest: scope.permission_digest.clone(),
            registration_revision: 1,
            reversible: true,
            enabled: true,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate(scope)?;
        Ok(registration)
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.registration_digest.clear();
        canonical_digest(&copy)
    }

    pub fn validate(&self, scope: &FirecrawlScope) -> Result<(), FirecrawlResearchEvidenceError> {
        if self.plugin_id != "firecrawl.research-evidence"
            || self.plugin_version != PluginVersion::V1
            || self.contract_version != "EXT-FIRECRAWL-01-L1/v1"
            || !self.reversible
            || self.registration_revision == 0
        {
            return Err(FirecrawlResearchEvidenceError::InvalidContract {
                reason: "registration identity or reversibility drift",
            });
        }
        if self.scope_digest != scope.digest() {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if self.permission_revision != scope.permission_revision
            || self.permission_digest != scope.permission_digest
        {
            return Err(FirecrawlResearchEvidenceError::PermissionDigestMismatch);
        }
        validate_digest(&self.registration_digest, "registration_digest")?;
        if self.enabled && self.registration_digest != self.calculate_digest() {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        Ok(())
    }

    pub fn revoked(&self) -> Result<Self, FirecrawlResearchEvidenceError> {
        let mut revoked = self.clone();
        revoked.registration_revision = self.registration_revision.checked_add(1).ok_or(
            FirecrawlResearchEvidenceError::InvalidInput {
                field: "registration_revision",
                reason: String::from("overflow"),
            },
        )?;
        revoked.enabled = false;
        revoked.registration_digest = revoked.calculate_digest();
        Ok(revoked)
    }

    pub fn reactivated(&self) -> Result<Self, FirecrawlResearchEvidenceError> {
        let mut active = self.clone();
        active.registration_revision = self.registration_revision.checked_add(1).ok_or(
            FirecrawlResearchEvidenceError::InvalidInput {
                field: "registration_revision",
                reason: String::from("overflow"),
            },
        )?;
        active.enabled = true;
        active.registration_digest = active.calculate_digest();
        Ok(active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlAuthMode {
    ApiKeySecretReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlProviderManifest {
    pub provider_id: String,
    pub provider_version: u64,
    pub api_base_url: String,
    pub api_version: String,
    pub auth_mode: FirecrawlAuthMode,
    pub secret_reference: SecretReference,
    pub scope_digest: Digest,
    pub registration: FirecrawlPluginRegistration,
    pub native_status: NativeStatus,
    pub manifest_digest: Digest,
}

impl FirecrawlProviderManifest {
    pub fn new(
        scope: &FirecrawlScope,
        secret_reference: SecretReference,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        secret_reference.validate()?;
        if secret_reference.scope_digest != scope.digest() {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        let registration = FirecrawlPluginRegistration::new(scope)?;
        let mut manifest = Self {
            provider_id: String::from("FirecrawlProvider"),
            provider_version: 1,
            api_base_url: String::from(FIRECRAWL_API_BASE_URL),
            api_version: String::from(FIRECRAWL_API_VERSION),
            auth_mode: FirecrawlAuthMode::ApiKeySecretReference,
            secret_reference,
            scope_digest: scope.digest(),
            registration,
            native_status: NativeStatus::BlockedEnv,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.calculate_digest();
        manifest.validate(scope)?;
        Ok(manifest)
    }

    pub fn layer1(
        scope: &FirecrawlScope,
        secret_reference: SecretReference,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new(scope, secret_reference)
    }

    pub fn fixture(scope: &FirecrawlScope) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new(
            scope,
            SecretReference::new("secret-ref-firecrawl-fixture", scope.digest(), 1)?,
        )
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.manifest_digest.clear();
        canonical_digest(&copy)
    }

    pub fn validate(&self, scope: &FirecrawlScope) -> Result<(), FirecrawlResearchEvidenceError> {
        if self.provider_id != "FirecrawlProvider"
            || self.provider_version != 1
            || self.api_base_url != FIRECRAWL_API_BASE_URL
            || self.api_version != FIRECRAWL_API_VERSION
            || self.auth_mode != FirecrawlAuthMode::ApiKeySecretReference
            || self.native_status != NativeStatus::BlockedEnv
        {
            return Err(FirecrawlResearchEvidenceError::InvalidContract {
                reason: "provider manifest identity drift",
            });
        }
        if self.scope_digest != scope.digest() {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        self.secret_reference.validate()?;
        if self.secret_reference.scope_digest != self.scope_digest {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        self.registration.validate(scope)?;
        validate_digest(&self.manifest_digest, "manifest_digest")?;
        if self.manifest_digest != self.calculate_digest() {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        Ok(())
    }

    pub fn revoked(&self) -> Result<Self, FirecrawlResearchEvidenceError> {
        let mut revoked = self.clone();
        revoked.registration = self.registration.revoked()?;
        revoked.manifest_digest = revoked.calculate_digest();
        Ok(revoked)
    }

    pub fn reactivated(&self) -> Result<Self, FirecrawlResearchEvidenceError> {
        let mut active = self.clone();
        active.registration = self.registration.reactivated()?;
        active.manifest_digest = active.calculate_digest();
        Ok(active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionFirecrawlResearchRequest {
    pub scope: FirecrawlScope,
    pub job: FirecrawlJobRequest,
    pub expected_registration_digest: Digest,
    pub expected_permission_digest: Digest,
}

impl MissionFirecrawlResearchRequest {
    pub fn new(
        scope: FirecrawlScope,
        job: FirecrawlJobRequest,
        expected_registration_digest: Digest,
        expected_permission_digest: Digest,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let request = Self {
            scope,
            job,
            expected_registration_digest,
            expected_permission_digest,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.scope.validate()?;
        self.job.validate()?;
        if self.job.scope != self.scope {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        validate_digest(
            &self.expected_registration_digest,
            "expected_registration_digest",
        )?;
        if self.expected_permission_digest != self.scope.permission_digest {
            return Err(FirecrawlResearchEvidenceError::PermissionDigestMismatch);
        }
        Ok(())
    }
}

pub type FirecrawlResearchRequest = MissionFirecrawlResearchRequest;

fn validate_markdown(
    markdown: &str,
    max_bytes: usize,
) -> Result<(), FirecrawlResearchEvidenceError> {
    if markdown.len() > max_bytes || markdown.chars().any(|character| character == '\0') {
        return Err(FirecrawlResearchEvidenceError::ContentTooLarge);
    }
    if markdown.contains(";base64,") || markdown.to_ascii_lowercase().contains("data:image/") {
        return Err(FirecrawlResearchEvidenceError::MediaRetentionRefused);
    }
    Ok(())
}

fn bounded_snippet(markdown: &str) -> String {
    markdown.chars().take(MAX_SNIPPET_BYTES).collect()
}

fn validate_content_type(content_type: &str) -> Result<(), FirecrawlResearchEvidenceError> {
    let normalized = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        normalized.as_str(),
        "text/html" | "application/xhtml+xml" | "text/plain"
    ) {
        return Err(FirecrawlResearchEvidenceError::ContentTypeRefused {
            content_type: content_type.to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn content_type_is_allowed(content_type: &str) -> bool {
    validate_content_type(content_type).is_ok()
}
