use std::fmt;
use std::net::Ipv4Addr;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserTabId, BrowserWorkspaceId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{BrowserError, BrowserWorkspace};

const READ_OBSERVATION_SCHEMA_VERSION: u32 = 1;
const MAX_OBSERVATION_URL_BYTES: usize = 32 * 1_024;
const MAX_OBSERVATION_MEDIA_TYPE_BYTES: usize = 256;
const MAX_OBSERVATION_BODY_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_RESOURCE_TREE_NODES: usize = 4_096;

/// The only classification emitted by this adapter. Public browser reads are
/// source observations, not first-party identity or business verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserObservationClassification {
    PublicWeb,
}

/// The media surface intentionally stays a normalized MIME type rather than
/// a provider-specific enum. The adapter does not infer business semantics
/// from a response's media type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BrowserReadObservationMedia(String);

impl BrowserReadObservationMedia {
    pub(crate) fn new(raw: &str) -> Result<Self, BrowserError> {
        let media_type = canonical_media_type(raw)?;
        Ok(Self(media_type))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BrowserReadObservationMedia {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A content-free, project-scoped observation of one public HTTPS main
/// document. The response body is consumed only long enough to calculate the
/// canonical digest and byte count; it is never stored in this type.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserReadObservation {
    pub schema_version: u32,
    pub observation_id: String,
    pub workspace_id: BrowserWorkspaceId,
    pub tab_id: BrowserTabId,
    pub identity_digest: String,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub origin: String,
    pub origin_digest: String,
    pub requested_url: String,
    pub requested_url_digest: String,
    pub final_url: String,
    pub final_url_digest: String,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub execution_context_id_digest: String,
    pub execution_context_generation: u64,
    pub observed_at: DateTime<Utc>,
    pub media_type: BrowserReadObservationMedia,
    pub byte_count: u64,
    pub canonical_content_digest: String,
    pub classification: BrowserObservationClassification,
    pub first_party_confirmed: bool,
    pub business_verified: bool,
    pub observation_digest: String,
}

impl BrowserReadObservation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_managed_read(
        observation_id: impl Into<String>,
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
        requested_url: &str,
        final_url: &str,
        frame_id: &str,
        loader_id: &str,
        execution_context_id: &str,
        execution_context_generation: u64,
        observed_at: DateTime<Utc>,
        media_type: &str,
        canonical_content: &[u8],
    ) -> Result<Self, BrowserError> {
        workspace.validate()?;
        if !workspace.tabs.contains(&tab_id) {
            return Err(BrowserError::ScopeMismatch);
        }
        let requested_url = canonical_public_https_url(requested_url)?;
        let final_url = canonical_public_https_url(final_url)?;
        let requested_origin = public_origin(&requested_url)?;
        let final_origin = public_origin(&final_url)?;
        if requested_url != final_url || requested_origin != final_origin {
            return Err(BrowserError::ReadObservationTampered);
        }
        if frame_id.is_empty()
            || frame_id.len() > 4_096
            || loader_id.is_empty()
            || loader_id.len() > 4_096
            || execution_context_id.is_empty()
            || execution_context_id.len() > 4_096
        {
            return Err(BrowserError::ReadObservationResponseInvalid);
        }
        let byte_count = u64::try_from(canonical_content.len())
            .map_err(|_| BrowserError::ReadObservationBodyInvalid)?;
        if canonical_content.len() > MAX_OBSERVATION_BODY_BYTES {
            return Err(BrowserError::ReadObservationBodyInvalid);
        }
        let media_type = BrowserReadObservationMedia::new(media_type)?;
        let mut observation = Self {
            schema_version: READ_OBSERVATION_SCHEMA_VERSION,
            observation_id: observation_id.into(),
            workspace_id: workspace.id.clone(),
            tab_id,
            identity_digest: workspace.expected_identity_digest.clone(),
            lease_generation: workspace.lease_generation,
            document_generation: 1,
            origin: requested_origin.clone(),
            origin_digest: digest(requested_origin.as_bytes()),
            requested_url: requested_url.clone(),
            requested_url_digest: digest(requested_url.as_bytes()),
            final_url: final_url.clone(),
            final_url_digest: digest(final_url.as_bytes()),
            frame_id_digest: digest(frame_id.as_bytes()),
            loader_id_digest: digest(loader_id.as_bytes()),
            execution_context_id_digest: digest(execution_context_id.as_bytes()),
            execution_context_generation,
            observed_at,
            media_type,
            byte_count,
            canonical_content_digest: digest(canonical_content),
            classification: BrowserObservationClassification::PublicWeb,
            first_party_confirmed: false,
            business_verified: false,
            observation_digest: String::new(),
        };
        observation.observation_id = observation.observation_id.trim().to_owned();
        observation.observation_digest = observation.compute_observation_digest()?;
        observation.validate()?;
        Ok(observation)
    }

    /// Completes the workspace/document binding after the Chromium host has
    /// supplied its exact document generation.
    pub(crate) fn with_document_generation(
        mut self,
        document_generation: u64,
    ) -> Result<Self, BrowserError> {
        if document_generation == 0 {
            return Err(BrowserError::InvalidReadObservation);
        }
        self.document_generation = document_generation;
        self.observation_digest = self.compute_observation_digest()?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != READ_OBSERVATION_SCHEMA_VERSION
            || !is_bounded_identifier(&self.observation_id)
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.identity_digest)
            || self.lease_generation == 0
            || self.document_generation == 0
            || !is_public_https_url(&self.requested_url)
            || !is_public_https_url(&self.final_url)
            || self.requested_url != self.final_url
            || self.origin != public_origin(&self.final_url)?
            || self.origin_digest != digest(self.origin.as_bytes())
            || self.requested_url_digest != digest(self.requested_url.as_bytes())
            || self.final_url_digest != digest(self.final_url.as_bytes())
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.execution_context_id_digest)
            || self.execution_context_generation == 0
            || BrowserReadObservationMedia::new(self.media_type.as_str())?.as_str()
                != self.media_type.as_str()
            || self.byte_count > MAX_OBSERVATION_BODY_BYTES as u64
            || !is_sha256(&self.canonical_content_digest)
            || self.classification != BrowserObservationClassification::PublicWeb
            || self.first_party_confirmed
            || self.business_verified
            || !is_sha256(&self.observation_digest)
            || self.observation_digest != self.compute_observation_digest()?
        {
            return Err(BrowserError::InvalidReadObservation);
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> &str {
        &self.canonical_content_digest
    }

    pub fn content_digest(&self) -> &str {
        self.canonical_digest()
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        Ok(self.observation_digest.clone())
    }

    pub fn validate_for(&self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        self.validate()?;
        workspace.validate()?;
        if self.workspace_id != workspace.id
            || !workspace.tabs.contains(&self.tab_id)
            || self.identity_digest != workspace.expected_identity_digest
            || self.lease_generation != workspace.lease_generation
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(())
    }

    fn compute_observation_digest(&self) -> Result<String, BrowserError> {
        digest_json(&json!({
            "schemaVersion": self.schema_version,
            "observationId": self.observation_id,
            "workspaceId": self.workspace_id,
            "tabId": self.tab_id,
            "identityDigest": self.identity_digest,
            "leaseGeneration": self.lease_generation,
            "documentGeneration": self.document_generation,
            "origin": self.origin,
            "originDigest": self.origin_digest,
            "requestedUrl": self.requested_url,
            "requestedUrlDigest": self.requested_url_digest,
            "finalUrl": self.final_url,
            "finalUrlDigest": self.final_url_digest,
            "frameIdDigest": self.frame_id_digest,
            "loaderIdDigest": self.loader_id_digest,
            "executionContextIdDigest": self.execution_context_id_digest,
            "executionContextGeneration": self.execution_context_generation,
            "observedAt": self.observed_at,
            "mediaType": self.media_type,
            "byteCount": self.byte_count,
            "canonicalContentDigest": self.canonical_content_digest,
            "classification": self.classification,
            "firstPartyConfirmed": self.first_party_confirmed,
            "businessVerified": self.business_verified,
        }))
    }
}

impl fmt::Debug for BrowserReadObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserReadObservation")
            .field("schema_version", &self.schema_version)
            .field("observation_id", &self.observation_id)
            .field("workspace_id", &self.workspace_id)
            .field("tab_id", &self.tab_id)
            .field("identity_digest", &self.identity_digest)
            .field("lease_generation", &self.lease_generation)
            .field("document_generation", &self.document_generation)
            .field("origin", &"<redacted>")
            .field("origin_digest", &self.origin_digest)
            .field("requested_url", &"<redacted>")
            .field("requested_url_digest", &self.requested_url_digest)
            .field("final_url", &"<redacted>")
            .field("final_url_digest", &self.final_url_digest)
            .field("frame_id_digest", &self.frame_id_digest)
            .field("loader_id_digest", &self.loader_id_digest)
            .field(
                "execution_context_id_digest",
                &self.execution_context_id_digest,
            )
            .field(
                "execution_context_generation",
                &self.execution_context_generation,
            )
            .field("observed_at", &self.observed_at)
            .field("media_type", &self.media_type)
            .field("byte_count", &self.byte_count)
            .field("canonical_content_digest", &self.canonical_content_digest)
            .field("classification", &self.classification)
            .field("first_party_confirmed", &self.first_party_confirmed)
            .field("business_verified", &self.business_verified)
            .field("observation_digest", &self.observation_digest)
            .finish()
    }
}

pub(crate) struct MainDocumentResource {
    pub media_type: BrowserReadObservationMedia,
}

pub(crate) fn parse_main_document_resource(
    response: &Value,
    root_frame_id: &str,
    final_url: &str,
) -> Result<MainDocumentResource, BrowserError> {
    if root_frame_id.is_empty() || root_frame_id.len() > 4_096 {
        return Err(BrowserError::ReadObservationResponseInvalid);
    }
    let final_url = canonical_public_https_url(final_url)?;
    let frame_tree = response
        .get("frameTree")
        .ok_or(BrowserError::ReadObservationResponseInvalid)?;
    let mut resource = None;
    let mut visited = 0usize;
    find_main_document_resource(
        frame_tree,
        root_frame_id,
        &final_url,
        &mut resource,
        &mut visited,
    )?;
    resource.ok_or(BrowserError::ReadObservationResponseInvalid)
}

fn find_main_document_resource(
    frame_tree: &Value,
    root_frame_id: &str,
    final_url: &str,
    resource: &mut Option<MainDocumentResource>,
    visited: &mut usize,
) -> Result<(), BrowserError> {
    *visited = visited
        .checked_add(1)
        .ok_or(BrowserError::CounterOverflow)?;
    if *visited > MAX_RESOURCE_TREE_NODES {
        return Err(BrowserError::ReadObservationResponseInvalid);
    }
    let frame = frame_tree
        .get("frame")
        .and_then(Value::as_object)
        .ok_or(BrowserError::ReadObservationResponseInvalid)?;
    let frame_id = frame
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .ok_or(BrowserError::ReadObservationResponseInvalid)?;
    if frame_id == root_frame_id {
        let frame_url = frame
            .get("url")
            .and_then(Value::as_str)
            .ok_or(BrowserError::ReadObservationResponseInvalid)?;
        if canonical_public_https_url(frame_url)? != final_url {
            return Err(BrowserError::ReadObservationTampered);
        }
        let resources = frame_tree
            .get("resources")
            .and_then(Value::as_array)
            .ok_or(BrowserError::ReadObservationResponseInvalid)?;
        for candidate in resources {
            let object = candidate
                .as_object()
                .ok_or(BrowserError::ReadObservationResponseInvalid)?;
            let url = object
                .get("url")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= MAX_OBSERVATION_URL_BYTES)
                .ok_or(BrowserError::ReadObservationResponseInvalid)?;
            let Ok(resource_url) = canonical_public_https_url(url) else {
                continue;
            };
            if resource_url != final_url {
                continue;
            }
            if object
                .get("failed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || object
                    .get("cancelled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                return Err(BrowserError::ReadObservationResponseInvalid);
            }
            if object.get("type").and_then(Value::as_str) != Some("Document") {
                return Err(BrowserError::ReadObservationResponseInvalid);
            }
            let mime_type = object
                .get("mimeType")
                .and_then(Value::as_str)
                .ok_or(BrowserError::ReadObservationMediaTypeInvalid)?;
            if resource.is_some() {
                return Err(BrowserError::ReadObservationResponseInvalid);
            }
            *resource = Some(MainDocumentResource {
                media_type: BrowserReadObservationMedia::new(mime_type)?,
            });
        }
    }
    if let Some(children) = frame_tree.get("childFrames").and_then(Value::as_array) {
        for child in children {
            find_main_document_resource(child, root_frame_id, final_url, resource, visited)?;
        }
    }
    Ok(())
}

pub(crate) fn decode_resource_content(
    response: &Value,
) -> Result<Zeroizing<Vec<u8>>, BrowserError> {
    let content = response
        .get("content")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= MAX_OBSERVATION_BODY_BYTES * 2)
        .ok_or(BrowserError::ReadObservationBodyInvalid)?;
    let base64_encoded = response
        .get("base64Encoded")
        .and_then(Value::as_bool)
        .ok_or(BrowserError::ReadObservationBodyInvalid)?;
    let bytes = if base64_encoded {
        base64::engine::general_purpose::STANDARD
            .decode(content)
            .map_err(|_| BrowserError::ReadObservationBodyInvalid)?
    } else {
        content.as_bytes().to_vec()
    };
    if bytes.len() > MAX_OBSERVATION_BODY_BYTES {
        return Err(BrowserError::ReadObservationBodyInvalid);
    }
    Ok(Zeroizing::new(bytes))
}

pub(crate) fn canonical_public_https_url(raw_url: &str) -> Result<String, BrowserError> {
    if raw_url.is_empty()
        || raw_url.len() > MAX_OBSERVATION_URL_BYTES
        || raw_url.trim() != raw_url
        || raw_url.chars().any(char::is_control)
    {
        return Err(BrowserError::ReadObservationPolicyRejected);
    }
    let parsed = Url::parse(raw_url).map_err(|_| BrowserError::ReadObservationPolicyRejected)?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || has_sensitive_query_key(&parsed)
    {
        return Err(BrowserError::ReadObservationPolicyRejected);
    }
    let public_host = match parsed.host() {
        Some(Host::Domain(domain)) => {
            let domain = domain.to_ascii_lowercase();
            domain != "localhost"
                && domain != "local"
                && !domain.ends_with(".localhost")
                && domain.strip_suffix(".local").is_none()
        }
        Some(Host::Ipv4(address)) => is_public_ipv4(address),
        Some(Host::Ipv6(address)) => {
            !address.is_loopback()
                && !address.is_unique_local()
                && !address.is_unicast_link_local()
                && !address.is_unspecified()
                && !address.is_multicast()
                && address.to_ipv4().is_none_or(is_public_ipv4)
        }
        None => false,
    };
    if !public_host {
        return Err(BrowserError::ReadObservationPolicyRejected);
    }
    Ok(parsed.to_string())
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    let is_shared = octets[0] == 100 && (64..=127).contains(&octets[1]);
    !address.is_loopback()
        && !address.is_private()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !is_shared
}

fn is_public_https_url(raw_url: &str) -> bool {
    canonical_public_https_url(raw_url).is_ok_and(|canonical| canonical == raw_url)
}

fn public_origin(raw_url: &str) -> Result<String, BrowserError> {
    let parsed = Url::parse(raw_url).map_err(|_| BrowserError::ReadObservationPolicyRejected)?;
    let origin = parsed.origin();
    if !origin.is_tuple() {
        return Err(BrowserError::ReadObservationPolicyRejected);
    }
    Ok(origin.ascii_serialization())
}

fn has_sensitive_query_key(url: &Url) -> bool {
    url.query_pairs().any(|(key, _)| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "access_token"
                | "api_key"
                | "apikey"
                | "authorization"
                | "auth"
                | "cookie"
                | "credential"
                | "id_token"
                | "password"
                | "passwd"
                | "refresh_token"
                | "secret"
                | "session"
                | "signature"
                | "sig"
                | "token"
        )
    })
}

fn canonical_media_type(raw: &str) -> Result<String, BrowserError> {
    if raw.is_empty()
        || raw.len() > MAX_OBSERVATION_MEDIA_TYPE_BYTES
        || raw.chars().any(char::is_control)
    {
        return Err(BrowserError::ReadObservationMediaTypeInvalid);
    }
    let media_type = raw
        .split(';')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= MAX_OBSERVATION_MEDIA_TYPE_BYTES)
        .ok_or(BrowserError::ReadObservationMediaTypeInvalid)?
        .to_ascii_lowercase();
    let mut parts = media_type.split('/');
    let (Some(major), Some(minor), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(BrowserError::ReadObservationMediaTypeInvalid);
    };
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(is_media_type_token)
        || !minor.bytes().all(is_media_type_token)
    {
        return Err(BrowserError::ReadObservationMediaTypeInvalid);
    }
    Ok(media_type)
}

fn is_media_type_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, Mission, MissionContract, Project,
        ProjectId, StorageMode, TenantId,
    };
    use tempfile::TempDir;

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn observation_workspace() -> (TempDir, BrowserWorkspace) {
        let temp = TempDir::new().expect("temp dir");
        let now = Utc
            .with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time");
        let project = Project::create_local(
            TenantId::from("tenant-read-observation"),
            ProjectId::from("project-read-observation"),
            "Read Observation",
            "",
            temp.path().to_str().expect("project root"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            "mission-read-observation".into(),
            project.id.clone(),
            "Read one public source",
            MissionContract::bootstrap("Read one public source", ["browser.read".into()], now),
            now,
        )
        .expect("mission");
        let identity = crate::BrowserIdentity::new(
            "public-web",
            AccountId::from("account-public-web"),
            sha('a'),
            sha('b'),
            now,
        )
        .expect("identity");
        let profile = crate::BrowserProfile::create_managed(
            BrowserProfileId::from("profile-read-observation"),
            &project,
            "keyring://browser/read-observation",
            identity,
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            "workspace-read-observation".into(),
            &project,
            &mission,
            &profile,
            "tab-read-observation".into(),
            BrowserControlLeaseId::from("lease-read-observation-1"),
            now + chrono::Duration::hours(1),
            sha('c'),
            now,
        )
        .expect("workspace");
        (temp, workspace)
    }

    fn sample_observation() -> BrowserReadObservation {
        let (_temp, workspace) = observation_workspace();
        BrowserReadObservation::from_managed_read(
            "observation-read-observation",
            &workspace,
            "tab-read-observation".into(),
            "https://example.com/market.json",
            "https://example.com/market.json",
            "frame-root",
            "loader-1",
            "context-1",
            1,
            workspace.created_at,
            "application/json; charset=utf-8",
            br#"{"market":"de"}"#,
        )
        .expect("observation")
        .with_document_generation(2)
        .expect("document generation")
    }

    #[test]
    fn observation_is_content_free_and_never_verified() {
        let observation = sample_observation();
        observation.validate().expect("valid observation");
        assert_eq!(observation.media_type.as_str(), "application/json");
        assert_eq!(observation.byte_count, br#"{"market":"de"}"#.len() as u64);
        assert_eq!(
            observation.canonical_digest(),
            digest(br#"{"market":"de"}"#.as_slice()).as_str()
        );
        assert!(!observation.first_party_confirmed);
        assert!(!observation.business_verified);
        let debug = format!("{observation:?}");
        assert!(!debug.contains("market"));
        assert!(!debug.contains("example.com/market.json"));
        assert!(debug.contains(&observation.final_url_digest));
        let serialized = serde_json::to_string(&observation).expect("observation payload");
        assert!(!serialized.contains("market\":\"de"));
        assert!(serialized.contains("canonicalContentDigest"));
    }

    #[test]
    fn observation_identity_and_lease_are_workspace_bound() {
        let (_temp, workspace) = observation_workspace();
        let observation = sample_observation();
        observation
            .validate_for(&workspace)
            .expect("workspace-bound observation");

        let mut changed = observation.clone();
        changed.identity_digest = sha('d');
        assert!(matches!(
            changed.validate_for(&workspace),
            Err(BrowserError::InvalidReadObservation)
        ));
    }

    #[test]
    fn observation_tamper_fails_closed() {
        let mut observation = sample_observation();
        observation.final_url = "https://example.com/changed".into();
        assert!(matches!(
            observation.validate(),
            Err(BrowserError::InvalidReadObservation)
        ));

        let mut observation = sample_observation();
        observation.business_verified = true;
        assert!(matches!(
            observation.validate(),
            Err(BrowserError::InvalidReadObservation)
        ));

        let mut observation = sample_observation();
        observation.canonical_content_digest = sha('f');
        assert!(matches!(
            observation.validate(),
            Err(BrowserError::InvalidReadObservation)
        ));
    }

    #[test]
    fn public_url_and_media_type_canonicalization_reject_private_or_ambiguous_inputs() {
        assert_eq!(
            canonical_public_https_url("https://EXAMPLE.com:443/path").expect("canonical URL"),
            "https://example.com/path"
        );
        assert!(canonical_public_https_url("http://example.com/path").is_err());
        assert!(canonical_public_https_url("https://127.0.0.1/path").is_err());
        assert!(canonical_public_https_url("https://[::1]/path").is_err());
        assert!(canonical_public_https_url("https://[::ffff:127.0.0.1]/path").is_err());
        assert!(canonical_public_https_url("https://local/path").is_err());
        assert!(canonical_public_https_url("https://service.local/path").is_err());
        assert!(canonical_public_https_url("https://example.com/?access_token=secret").is_err());
        assert!(canonical_public_https_url("https://example.com/?cookie=secret").is_err());
        assert!(canonical_public_https_url("https://user:pass@example.com/").is_err());
        assert!(canonical_public_https_url("https://example.com/#fragment").is_err());
        assert_eq!(
            canonical_media_type("Application/JSON; charset=utf-8").expect("media type"),
            "application/json"
        );
        assert!(canonical_media_type("text").is_err());
        assert!(canonical_media_type("text/html\nset-cookie: secret").is_err());
    }

    #[test]
    fn resource_tree_requires_one_exact_main_document() {
        let resource_tree = serde_json::json!({
            "frameTree": {
                "frame": {
                    "id": "frame-root",
                    "url": "https://example.com/market.json"
                },
                "resources": [{
                    "url": "https://example.com/market.json",
                    "type": "Document",
                    "mimeType": "application/json"
                }]
            }
        });
        let resource = parse_main_document_resource(
            &resource_tree,
            "frame-root",
            "https://example.com/market.json",
        )
        .expect("main resource");
        assert_eq!(resource.media_type.as_str(), "application/json");

        let mut wrong_type = resource_tree.clone();
        wrong_type["frameTree"]["resources"][0]["type"] = Value::String("Script".into());
        assert!(
            parse_main_document_resource(
                &wrong_type,
                "frame-root",
                "https://example.com/market.json",
            )
            .is_err()
        );
    }

    #[test]
    fn body_decode_is_bounded_and_digestable_without_retaining_raw_content() {
        let plain = decode_resource_content(&serde_json::json!({
            "content": "public read",
            "base64Encoded": false
        }))
        .expect("plain body");
        assert_eq!(plain.as_slice(), b"public read");

        let encoded = base64::engine::general_purpose::STANDARD.encode(b"binary read");
        let binary = decode_resource_content(&serde_json::json!({
            "content": encoded,
            "base64Encoded": true
        }))
        .expect("binary body");
        assert_eq!(binary.as_slice(), b"binary read");
        assert!(
            decode_resource_content(&serde_json::json!({
                "content": "not base64",
                "base64Encoded": true
            }))
            .is_err()
        );
    }
}
