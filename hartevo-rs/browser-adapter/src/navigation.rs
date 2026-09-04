use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserTabId, BrowserWorkspaceId};
use serde::Serialize;
use url::{Host, Url};

use crate::BrowserError;
use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};

const NAVIGATION_SCHEMA_VERSION: u32 = 2;
const MAX_NAVIGATION_URL_BYTES: usize = 32 * 1_024;
const MAX_ALLOWED_ORIGINS: usize = 64;

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserNavigationPolicy {
    allowed_origins: BTreeSet<String>,
    allow_loopback_http_for_test: bool,
    evidence_digest: String,
}

impl BrowserNavigationPolicy {
    /// Builds the narrowest production policy for one user-selected HTTPS
    /// target. Subresources remain restricted to that target's exact origin.
    pub fn for_exact_https_target(
        target_url: impl AsRef<str>,
    ) -> Result<(Self, BrowserNavigationTarget), BrowserError> {
        let target_url = target_url.as_ref();
        let (_, origin) = canonical_http_url(target_url, false)?;
        let policy = Self::https_only([origin])?;
        let target = policy.authorize(target_url)?;
        Ok((policy, target))
    }

    pub fn https_only<I, S>(origins: I) -> Result<Self, BrowserError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::build(origins, false)
    }

    #[cfg(test)]
    pub(crate) fn with_loopback_http_for_test<I, S>(origins: I) -> Result<Self, BrowserError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::build(origins, true)
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn authorize(
        &self,
        target_url: impl AsRef<str>,
    ) -> Result<BrowserNavigationTarget, BrowserError> {
        let raw_url = target_url.as_ref();
        let (canonical_url, canonical_origin) =
            canonical_http_url(raw_url, self.allow_loopback_http_for_test)?;
        if Url::parse(&canonical_url)
            .map_err(|_| BrowserError::NavigationTargetRejected)?
            .fragment()
            .is_some()
        {
            return Err(BrowserError::NavigationTargetRejected);
        }
        if !self.allowed_origins.contains(&canonical_origin) {
            return Err(BrowserError::NavigationTargetRejected);
        }
        let canonical_url_digest = digest(canonical_url.as_bytes());
        Ok(BrowserNavigationTarget {
            canonical_url,
            input_url_digest: digest(raw_url.as_bytes()),
            canonical_url_digest,
            origin_digest: digest(canonical_origin.as_bytes()),
            policy_digest: self.evidence_digest.clone(),
        })
    }

    pub(crate) fn permits_request(&self, raw_url: &str) -> bool {
        canonical_http_url(raw_url, self.allow_loopback_http_for_test)
            .is_ok_and(|(_, origin)| self.allowed_origins.contains(&origin))
    }

    pub(crate) fn permitted_origin_digest(&self, raw_url: &str) -> Option<String> {
        canonical_http_url(raw_url, self.allow_loopback_http_for_test)
            .ok()
            .filter(|(_, origin)| self.allowed_origins.contains(origin))
            .map(|(_, origin)| digest(origin.as_bytes()))
    }

    pub(crate) fn validate_target(
        &self,
        target: &BrowserNavigationTarget,
    ) -> Result<(), BrowserError> {
        if target.policy_digest != self.evidence_digest {
            return Err(BrowserError::NavigationTargetRejected);
        }
        let reauthorized = self.authorize(&target.canonical_url)?;
        if reauthorized.canonical_url != target.canonical_url
            || reauthorized.canonical_url_digest != target.canonical_url_digest
            || reauthorized.origin_digest != target.origin_digest
        {
            return Err(BrowserError::NavigationTargetRejected);
        }
        Ok(())
    }

    fn build<I, S>(origins: I, allow_loopback_http_for_test: bool) -> Result<Self, BrowserError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowed_origins = BTreeSet::new();
        for origin in origins {
            let raw = origin.as_ref();
            let (canonical_url, canonical_origin) =
                canonical_http_url(raw, allow_loopback_http_for_test)?;
            let parsed =
                Url::parse(&canonical_url).map_err(|_| BrowserError::NavigationPolicyInvalid)?;
            if parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || canonical_url != format!("{canonical_origin}/")
                || !allowed_origins.insert(canonical_origin)
                || allowed_origins.len() > MAX_ALLOWED_ORIGINS
            {
                return Err(BrowserError::NavigationPolicyInvalid);
            }
        }
        if allowed_origins.is_empty() {
            return Err(BrowserError::NavigationPolicyInvalid);
        }
        let evidence_digest = digest_json(&(
            NAVIGATION_SCHEMA_VERSION,
            &allowed_origins,
            allow_loopback_http_for_test,
        ))?;
        Ok(Self {
            allowed_origins,
            allow_loopback_http_for_test,
            evidence_digest,
        })
    }
}

impl fmt::Debug for BrowserNavigationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserNavigationPolicy")
            .field("allowed_origin_count", &self.allowed_origins.len())
            .field(
                "allow_loopback_http_for_test",
                &self.allow_loopback_http_for_test,
            )
            .field("evidence_digest", &self.evidence_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserNavigationTarget {
    canonical_url: String,
    input_url_digest: String,
    canonical_url_digest: String,
    origin_digest: String,
    policy_digest: String,
}

impl BrowserNavigationTarget {
    pub fn url_digest(&self) -> &str {
        &self.canonical_url_digest
    }

    pub fn origin_digest(&self) -> &str {
        &self.origin_digest
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub(crate) fn canonical_url(&self) -> &str {
        &self.canonical_url
    }
}

impl fmt::Debug for BrowserNavigationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserNavigationTarget")
            .field("input_url_digest", &self.input_url_digest)
            .field("canonical_url_digest", &self.canonical_url_digest)
            .field("origin_digest", &self.origin_digest)
            .field("policy_digest", &self.policy_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserNavigationReceipt {
    pub schema_version: u32,
    pub workspace_id: BrowserWorkspaceId,
    pub tab_id: BrowserTabId,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub requested_url_digest: String,
    pub final_url_digest: String,
    pub final_origin_digest: String,
    pub policy_digest: String,
    pub frame_id_digest: String,
    pub loader_id_digest: Option<String>,
    pub allowed_request_count: u32,
    pub script_execution_disabled: bool,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

impl BrowserNavigationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        workspace_id: BrowserWorkspaceId,
        tab_id: BrowserTabId,
        lease_generation: u64,
        document_generation: u64,
        requested_url_digest: String,
        final_url_digest: String,
        final_origin_digest: String,
        policy_digest: String,
        frame_id_digest: String,
        loader_id_digest: Option<String>,
        allowed_request_count: u32,
        script_execution_disabled: bool,
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let receipt = Self {
            schema_version: NAVIGATION_SCHEMA_VERSION,
            workspace_id,
            tab_id,
            lease_generation,
            document_generation,
            requested_url_digest,
            final_url_digest,
            final_origin_digest,
            policy_digest,
            frame_id_digest,
            loader_id_digest,
            allowed_request_count,
            script_execution_disabled,
            started_at,
            completed_at,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != NAVIGATION_SCHEMA_VERSION
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_bounded_identifier(self.tab_id.as_str())
            || self.lease_generation == 0
            || self.document_generation == 0
            || !is_sha256(&self.requested_url_digest)
            || !is_sha256(&self.final_url_digest)
            || !is_sha256(&self.final_origin_digest)
            || !is_sha256(&self.policy_digest)
            || !is_sha256(&self.frame_id_digest)
            || self
                .loader_id_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
            || self.allowed_request_count == 0
            || !self.script_execution_disabled
            || self.completed_at < self.started_at
        {
            return Err(BrowserError::NavigationFailed);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserNavigationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserNavigationReceipt")
            .field("schema_version", &self.schema_version)
            .field("workspace_id", &self.workspace_id)
            .field("tab_id", &self.tab_id)
            .field("lease_generation", &self.lease_generation)
            .field("document_generation", &self.document_generation)
            .field("requested_url_digest", &self.requested_url_digest)
            .field("final_url_digest", &self.final_url_digest)
            .field("final_origin_digest", &self.final_origin_digest)
            .field("policy_digest", &self.policy_digest)
            .field("frame_id_digest", &self.frame_id_digest)
            .field("loader_id_digest", &self.loader_id_digest)
            .field("allowed_request_count", &self.allowed_request_count)
            .field("script_execution_disabled", &self.script_execution_disabled)
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .finish()
    }
}

fn canonical_http_url(
    raw_url: &str,
    allow_loopback_http_for_test: bool,
) -> Result<(String, String), BrowserError> {
    if raw_url.is_empty()
        || raw_url.len() > MAX_NAVIGATION_URL_BYTES
        || raw_url.trim() != raw_url
        || raw_url.chars().any(char::is_control)
    {
        return Err(BrowserError::NavigationTargetRejected);
    }
    let parsed = Url::parse(raw_url).map_err(|_| BrowserError::NavigationTargetRejected)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host().is_none()
        || !matches!(parsed.scheme(), "https" | "http")
        || (parsed.scheme() == "http"
            && (!allow_loopback_http_for_test || !is_loopback_host(parsed.host().as_ref())))
    {
        return Err(BrowserError::NavigationTargetRejected);
    }
    let origin = parsed.origin();
    if !origin.is_tuple() {
        return Err(BrowserError::NavigationTargetRejected);
    }
    Ok((parsed.to_string(), origin.ascii_serialization()))
}

fn is_loopback_host(host: Option<&Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_policy_is_exact_normalized_and_redacted() {
        let policy = BrowserNavigationPolicy::https_only([
            "https://Example.com:443",
            "https://accounts.example.com",
        ])
        .expect("policy");
        let target = policy
            .authorize("https://example.com/a?q=secret")
            .expect("target");
        assert_eq!(target.origin_digest(), &digest(b"https://example.com"));
        assert_eq!(target.policy_digest(), policy.evidence_digest());
        assert!(!format!("{policy:?}").contains("example.com"));
        assert!(!format!("{target:?}").contains("secret"));
        assert!(policy.authorize("https://sub.example.com/").is_err());
        assert!(policy.authorize("https://user:pass@example.com/").is_err());
        assert!(policy.authorize("javascript:alert(1)").is_err());
        assert!(policy.authorize("http://example.com/").is_err());
        assert!(
            policy
                .authorize("https://example.com/path#same-document")
                .is_err()
        );
    }

    #[test]
    fn exact_https_target_derives_one_origin_and_rejects_hostile_input() {
        let (policy, target) = BrowserNavigationPolicy::for_exact_https_target(
            "https://Example.com:443/research?q=private",
        )
        .expect("exact target policy");
        assert_eq!(
            target.url_digest(),
            &digest(b"https://example.com/research?q=private")
        );
        assert_eq!(target.origin_digest(), &digest(b"https://example.com"));
        assert!(policy.authorize("https://example.com/next").is_ok());
        assert!(policy.authorize("https://other.example/next").is_err());
        assert!(BrowserNavigationPolicy::for_exact_https_target("http://example.com/").is_err());
        assert!(
            BrowserNavigationPolicy::for_exact_https_target("https://user:secret@example.com/")
                .is_err()
        );
        assert!(
            BrowserNavigationPolicy::for_exact_https_target("https://example.com/#fragment")
                .is_err()
        );
    }

    #[test]
    fn origin_manifests_reject_paths_duplicates_and_public_http() {
        assert!(BrowserNavigationPolicy::https_only(["https://example.com/path"]).is_err());
        assert!(
            BrowserNavigationPolicy::https_only(
                ["https://example.com", "https://example.com:443",]
            )
            .is_err()
        );
        assert!(BrowserNavigationPolicy::https_only(["http://127.0.0.1:8080"]).is_err());
        assert!(
            BrowserNavigationPolicy::with_loopback_http_for_test(["http://example.com"]).is_err()
        );
        assert!(
            BrowserNavigationPolicy::with_loopback_http_for_test(["http://127.0.0.1:8080"]).is_ok()
        );
    }
}
