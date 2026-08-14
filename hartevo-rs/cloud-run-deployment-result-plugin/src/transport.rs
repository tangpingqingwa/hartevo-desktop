use std::{
    fmt,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{CloudRunDeploymentResultError, CloudRunTransportError};
use crate::model::{
    CloudRunIamRecord, CloudRunLocation, CloudRunReadiness, CloudRunRevisionName,
    CloudRunRevisionPage, CloudRunRevisionRecord, CloudRunScope, CloudRunServiceName,
    CloudRunServiceRecord, CloudRunSource, CloudRunTrafficPlan, CloudRunTrafficTarget,
    CloudRunUriMetadata, Digest, MAX_PAGE_TOKEN_BYTES, MAX_RESPONSE_BYTES, MAX_REVISIONS,
    ProviderProvenance, RevisionUid, ServiceUid,
};

/// Credential material is resolved for one provider call only. It cannot be
/// serialized, included in a registration, or recovered through Debug.
#[derive(Clone)]
pub struct SecretMaterial(Zeroizing<String>);

impl SecretMaterial {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

/// Layer 1's only provider transport surface: bounded metadata reads. There
/// are intentionally no create, patch, delete, traffic mutation, IAM
/// mutation, secret export, or raw-log methods.
pub trait CloudRunTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> ProviderProvenance;

    fn describe_service(
        &self,
        credential: &SecretMaterial,
        scope: &CloudRunScope,
    ) -> Result<CloudRunServiceRecord, CloudRunTransportError>;

    fn list_revisions(
        &self,
        credential: &SecretMaterial,
        scope: &CloudRunScope,
        page_token: Option<&str>,
        page_size: usize,
    ) -> Result<CloudRunRevisionPage, CloudRunTransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudRunTransportOperation {
    DescribeService,
    ListRevisions,
}

/// Deterministic fixture/recording/fake transport. Its provenance is explicit
/// and can never become Connected or first-party evidence.
#[derive(Clone)]
pub struct RecordingCloudRunTransport {
    service: Arc<Mutex<CloudRunServiceRecord>>,
    pages: Arc<Mutex<Vec<CloudRunRevisionPage>>>,
    provenance: ProviderProvenance,
    fault: Arc<Mutex<Option<CloudRunTransportError>>>,
    operations: Arc<Mutex<Vec<CloudRunTransportOperation>>>,
}

impl fmt::Debug for RecordingCloudRunTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingCloudRunTransport")
            .field("provenance", &self.provenance)
            .field("operations", &self.operations().len())
            .finish_non_exhaustive()
    }
}

impl RecordingCloudRunTransport {
    pub fn new(
        service: CloudRunServiceRecord,
        pages: Vec<CloudRunRevisionPage>,
        provenance: ProviderProvenance,
    ) -> Self {
        assert!(matches!(
            provenance,
            ProviderProvenance::Recording
                | ProviderProvenance::Fake
                | ProviderProvenance::Fixture
                | ProviderProvenance::Loopback
                | ProviderProvenance::BlockedEnv
        ));
        Self {
            service: Arc::new(Mutex::new(service)),
            pages: Arc::new(Mutex::new(pages)),
            provenance,
            fault: Arc::new(Mutex::new(None)),
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn from_revisions(
        service: CloudRunServiceRecord,
        revisions: Vec<CloudRunRevisionRecord>,
        provenance: ProviderProvenance,
    ) -> Self {
        Self::new(
            service,
            vec![CloudRunRevisionPage {
                revisions,
                next_page_token: None,
            }],
            provenance,
        )
    }

    pub fn recording(
        service: CloudRunServiceRecord,
        revisions: Vec<CloudRunRevisionRecord>,
    ) -> Self {
        Self::from_revisions(service, revisions, ProviderProvenance::Recording)
    }

    pub fn fake(service: CloudRunServiceRecord, revisions: Vec<CloudRunRevisionRecord>) -> Self {
        Self::from_revisions(service, revisions, ProviderProvenance::Fake)
    }

    pub fn fixture(service: CloudRunServiceRecord, revisions: Vec<CloudRunRevisionRecord>) -> Self {
        Self::from_revisions(service, revisions, ProviderProvenance::Fixture)
    }

    pub fn loopback(
        service: CloudRunServiceRecord,
        revisions: Vec<CloudRunRevisionRecord>,
    ) -> Self {
        Self::from_revisions(service, revisions, ProviderProvenance::Loopback)
    }

    pub fn blocked_env(
        service: CloudRunServiceRecord,
        revisions: Vec<CloudRunRevisionRecord>,
    ) -> Self {
        Self::from_revisions(service, revisions, ProviderProvenance::BlockedEnv)
    }

    pub fn set_pages(&self, pages: Vec<CloudRunRevisionPage>) {
        if let Ok(mut value) = self.pages.lock() {
            *value = pages;
        }
    }

    pub fn set_service(&self, service: CloudRunServiceRecord) {
        if let Ok(mut value) = self.service.lock() {
            *value = service;
        }
    }

    pub fn set_fault(&self, fault: CloudRunTransportError) {
        if let Ok(mut value) = self.fault.lock() {
            *value = Some(fault);
        }
    }

    pub fn clear_fault(&self) {
        if let Ok(mut value) = self.fault.lock() {
            *value = None;
        }
    }

    pub fn operations(&self) -> Vec<CloudRunTransportOperation> {
        self.operations
            .lock()
            .map_or_else(|_| Vec::new(), |operations| operations.clone())
    }

    fn before_call(
        &self,
        operation: CloudRunTransportOperation,
        credential: &SecretMaterial,
    ) -> Result<(), CloudRunTransportError> {
        self.operations
            .lock()
            .map_err(|_| CloudRunTransportError::Network)?
            .push(operation);
        if credential.as_str().trim().is_empty()
            || credential.as_str().chars().any(char::is_control)
        {
            return Err(CloudRunTransportError::Unauthorized);
        }
        self.fault
            .lock()
            .map_err(|_| CloudRunTransportError::Network)?
            .clone()
            .map_or(Ok(()), Err)
    }
}

impl CloudRunTransport for RecordingCloudRunTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn describe_service(
        &self,
        credential: &SecretMaterial,
        _scope: &CloudRunScope,
    ) -> Result<CloudRunServiceRecord, CloudRunTransportError> {
        self.before_call(CloudRunTransportOperation::DescribeService, credential)?;
        self.service
            .lock()
            .map_err(|_| CloudRunTransportError::Network)
            .map(|service| service.clone())
    }

    fn list_revisions(
        &self,
        credential: &SecretMaterial,
        _scope: &CloudRunScope,
        page_token: Option<&str>,
        page_size: usize,
    ) -> Result<CloudRunRevisionPage, CloudRunTransportError> {
        self.before_call(CloudRunTransportOperation::ListRevisions, credential)?;
        if page_size == 0 || page_size > MAX_REVISIONS {
            return Err(CloudRunTransportError::InvalidConfiguration);
        }
        let index = page_token
            .map(|token| {
                token
                    .strip_prefix("page:")
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or(CloudRunTransportError::InvalidConfiguration)
            })
            .transpose()?
            .unwrap_or(0);
        let pages = self
            .pages
            .lock()
            .map_err(|_| CloudRunTransportError::Network)?;
        let page = pages
            .get(index)
            .cloned()
            .ok_or(CloudRunTransportError::Decode)?;
        if page.revisions.len() > page_size {
            return Err(CloudRunTransportError::ResponseTooLarge);
        }
        Ok(page)
    }
}

pub type FakeCloudRunTransport = RecordingCloudRunTransport;
pub type CloudRunRecordingTransport = RecordingCloudRunTransport;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
}

impl RetryPolicy {
    pub const fn bounded() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
        }
    }

    pub fn new(
        max_attempts: u8,
        initial_backoff_ms: u64,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        if max_attempts == 0 || max_attempts > 5 {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "retry policy",
                reason: "attempts must be between one and five",
            });
        }
        Ok(Self {
            max_attempts,
            initial_backoff_ms,
        })
    }

    fn delay_for_attempt(self, attempt: u8) -> Duration {
        let exponent = u32::from(attempt.saturating_sub(1)).min(5);
        Duration::from_millis(self.initial_backoff_ms.saturating_mul(1_u64 << exponent))
    }
}

/// Official Cloud Run v2 HTTPS GET transport. Layer 1 exposes it as a typed
/// seam only; without a host-approved credential resolver the default provider
/// remains BLOCKED_ENV and no live read is claimed as Connected evidence.
pub struct UreqCloudRunTransport {
    base_url: String,
    agent: ureq::Agent,
    retry_policy: RetryPolicy,
    provenance: ProviderProvenance,
}

impl fmt::Debug for UreqCloudRunTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqCloudRunTransport")
            .field("base_url", &self.base_url)
            .field("retry_policy", &self.retry_policy)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl UreqCloudRunTransport {
    pub fn new(base_url: impl Into<String>) -> Result<Self, CloudRunDeploymentResultError> {
        Self::build(&base_url.into(), false)
    }

    pub fn new_loopback(
        base_url: impl Into<String>,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        Self::build(&base_url.into(), true)
    }

    pub fn with_retry_policy(
        mut self,
        retry_policy: RetryPolicy,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        self.retry_policy = retry_policy;
        Ok(self)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn build(base_url: &str, loopback: bool) -> Result<Self, CloudRunDeploymentResultError> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let parsed =
            Url::parse(&base_url).map_err(|_| CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run API base URL",
                reason: "must be an exact HTTPS or loopback URL",
            })?;
        let host = parsed
            .host_str()
            .ok_or(CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run API base URL",
                reason: "must include a host",
            })?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run API base URL",
                reason: "must not contain credentials, query, or fragment",
            });
        }
        if loopback {
            if parsed.scheme() != "http" || !is_loopback_host(host) {
                return Err(CloudRunDeploymentResultError::InvalidInput {
                    field: "Cloud Run loopback URL",
                    reason: "must be an HTTP loopback endpoint",
                });
            }
        } else if parsed.scheme() != "https" {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run API base URL",
                reason: "must use HTTPS",
            });
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-cloud-run-deployment-result/1")
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            base_url,
            agent,
            retry_policy: RetryPolicy::bounded(),
            provenance: if loopback {
                ProviderProvenance::Loopback
            } else {
                ProviderProvenance::OfficialHttps
            },
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<String, CloudRunTransportError> {
        let mut url =
            Url::parse(&self.base_url).map_err(|_| CloudRunTransportError::InvalidConfiguration)?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| CloudRunTransportError::InvalidConfiguration)?;
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        credential: &SecretMaterial,
        url: &str,
    ) -> Result<Value, CloudRunTransportError> {
        let mut attempt = 1;
        loop {
            let request = self
                .agent
                .get(url)
                .header("Authorization", format!("Bearer {}", credential.as_str()))
                .header("Accept", "application/json")
                .header("X-Hartevo-Client", "hartevo-cloud-run-deployment-result/1");
            match request.call() {
                Ok(mut response) => {
                    let body = response
                        .body_mut()
                        .read_to_string()
                        .map_err(|_| CloudRunTransportError::Network)?;
                    if body.len() > MAX_RESPONSE_BYTES {
                        return Err(CloudRunTransportError::ResponseTooLarge);
                    }
                    return serde_json::from_str(&body).map_err(|_| CloudRunTransportError::Decode);
                }
                Err(error) => {
                    let classified = classify_http_error(&error);
                    if !is_retryable(&classified) || attempt >= self.retry_policy.max_attempts {
                        return if is_retryable(&classified) && self.retry_policy.max_attempts > 1 {
                            Err(CloudRunTransportError::ServerUnavailable)
                        } else {
                            Err(classified)
                        };
                    }
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

impl CloudRunTransport for UreqCloudRunTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn describe_service(
        &self,
        credential: &SecretMaterial,
        scope: &CloudRunScope,
    ) -> Result<CloudRunServiceRecord, CloudRunTransportError> {
        let service_url = self.endpoint(&[
            "projects",
            scope.google_project_id.as_str(),
            "locations",
            scope.location.as_str(),
            "services",
            scope.service_name.as_str(),
        ])?;
        let service = self.get_json(credential, &service_url)?;
        let iam_url = self.endpoint(&[
            "projects",
            scope.google_project_id.as_str(),
            "locations",
            scope.location.as_str(),
            "services",
            &format!("{}:getIamPolicy", scope.service_name),
        ])?;
        let iam = self.get_json(credential, &iam_url)?;
        parse_service_record(&service, &iam, scope)
    }

    fn list_revisions(
        &self,
        credential: &SecretMaterial,
        scope: &CloudRunScope,
        page_token: Option<&str>,
        page_size: usize,
    ) -> Result<CloudRunRevisionPage, CloudRunTransportError> {
        if page_size == 0 || page_size > MAX_REVISIONS {
            return Err(CloudRunTransportError::InvalidConfiguration);
        }
        let base = self.endpoint(&[
            "projects",
            scope.google_project_id.as_str(),
            "locations",
            scope.location.as_str(),
            "revisions",
        ])?;
        let mut url =
            Url::parse(&base).map_err(|_| CloudRunTransportError::InvalidConfiguration)?;
        url.query_pairs_mut()
            .append_pair("pageSize", &page_size.to_string());
        if let Some(token) = page_token {
            if token.len() > MAX_PAGE_TOKEN_BYTES {
                return Err(CloudRunTransportError::InvalidConfiguration);
            }
            url.query_pairs_mut().append_pair("pageToken", token);
        }
        let document = self.get_json(credential, url.as_str())?;
        parse_revision_page(&document, scope)
    }
}

pub type CloudRunApiTransport = UreqCloudRunTransport;

fn parse_service_record(
    value: &Value,
    iam_value: &Value,
    scope: &CloudRunScope,
) -> Result<CloudRunServiceRecord, CloudRunTransportError> {
    let uid = required_string(value, "uid")?;
    let generation = required_u64(value, "generation")?;
    let observed_generation = optional_u64(value, "observedGeneration").unwrap_or(generation);
    let revision_name = optional_string(value, "latestReadyRevision")
        .or_else(|| optional_string(value, "latestCreatedRevision"))
        .unwrap_or_else(|| scope.revision_name.to_string());
    let revision_name =
        CloudRunRevisionName::new(revision_name).map_err(|_| CloudRunTransportError::Decode)?;
    let source = parse_source(value, scope)?;
    let traffic = parse_traffic(value)?;
    let readiness = parse_readiness(value);
    let uri_metadata = optional_string(value, "uri")
        .map(CloudRunUriMetadata::from_uri)
        .transpose()
        .map_err(|_| CloudRunTransportError::Decode)?;
    let policy_digest = Digest::from_serializable(iam_value);
    let binding_count = iam_value
        .get("bindings")
        .and_then(Value::as_array)
        .map_or(0, |bindings| {
            u32::try_from(bindings.len()).unwrap_or(u32::MAX)
        });
    let iam = CloudRunIamRecord::new(policy_digest, binding_count, true)
        .map_err(|_| CloudRunTransportError::Decode)?;
    Ok(CloudRunServiceRecord {
        google_project_id: scope.google_project_id.clone(),
        location: scope.location.clone(),
        service_name: scope.service_name.clone(),
        service_uid: ServiceUid::new(uid).map_err(|_| CloudRunTransportError::Decode)?,
        generation,
        observed_generation,
        revision_name,
        source,
        traffic,
        readiness,
        iam,
        uri_metadata,
        request_id: None,
        deleted: false,
        access_lost: false,
    })
}

fn parse_revision_page(
    value: &Value,
    scope: &CloudRunScope,
) -> Result<CloudRunRevisionPage, CloudRunTransportError> {
    let Some(revisions) = value.get("revisions").and_then(Value::as_array) else {
        return Err(CloudRunTransportError::Decode);
    };
    if revisions.len() > MAX_REVISIONS {
        return Err(CloudRunTransportError::ResponseTooLarge);
    }
    let mut parsed = Vec::with_capacity(revisions.len());
    for revision in revisions {
        let name = required_nested_string(revision, &["name"])
            .or_else(|_| required_nested_string(revision, &["metadata", "name"]))?;
        let uid = required_string(revision, "uid")
            .or_else(|_| required_nested_string(revision, &["metadata", "uid"]))?;
        let generation = required_u64(revision, "generation")
            .or_else(|_| required_nested_u64(revision, &["metadata", "generation"]))?;
        let observed_generation = optional_u64(revision, "observedGeneration")
            .or_else(|| optional_nested_u64(revision, &["metadata", "observedGeneration"]))
            .unwrap_or(generation);
        let source = parse_revision_source(revision, scope)?;
        let condition_digest =
            Digest::from_serializable(revision.get("conditions").unwrap_or(&Value::Null));
        parsed.push(CloudRunRevisionRecord {
            revision_name: CloudRunRevisionName::new(name)
                .map_err(|_| CloudRunTransportError::Decode)?,
            revision_uid: RevisionUid::new(uid).map_err(|_| CloudRunTransportError::Decode)?,
            generation,
            observed_generation,
            source,
            readiness: parse_readiness(revision),
            condition_digest,
        });
    }
    let next_page_token = optional_string(value, "nextPageToken");
    Ok(CloudRunRevisionPage {
        revisions: parsed,
        next_page_token,
    })
}

fn parse_source(
    value: &Value,
    scope: &CloudRunScope,
) -> Result<CloudRunSource, CloudRunTransportError> {
    parse_revision_source(value, scope)
}

fn parse_revision_source(
    value: &Value,
    scope: &CloudRunScope,
) -> Result<CloudRunSource, CloudRunTransportError> {
    let image = value
        .get("template")
        .and_then(|template| template.get("containers"))
        .and_then(Value::as_array)
        .and_then(|containers| containers.first())
        .and_then(|container| container.get("image"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| optional_string(value, "image"))
        .unwrap_or_else(|| scope.source.image.clone());
    let (repository, digest) = image
        .rsplit_once('@')
        .ok_or(CloudRunTransportError::Decode)?;
    let digest = digest
        .strip_prefix("sha256:")
        .ok_or(CloudRunTransportError::Decode)?;
    let digest = Digest::new(digest).map_err(|_| CloudRunTransportError::Decode)?;
    CloudRunSource::new(repository, digest).map_err(|_| CloudRunTransportError::Decode)
}

fn parse_traffic(value: &Value) -> Result<CloudRunTrafficPlan, CloudRunTransportError> {
    let Some(traffic) = value.get("traffic").and_then(Value::as_array) else {
        return Err(CloudRunTransportError::Decode);
    };
    let mut targets = Vec::with_capacity(traffic.len());
    for target in traffic {
        let revision = required_string(target, "revision")?;
        let percent = target
            .get("percent")
            .and_then(Value::as_u64)
            .ok_or(CloudRunTransportError::Decode)?;
        if percent > 100 {
            return Err(CloudRunTransportError::Decode);
        }
        targets.push(
            CloudRunTrafficTarget::new(
                CloudRunRevisionName::new(revision).map_err(|_| CloudRunTransportError::Decode)?,
                u8::try_from(percent).map_err(|_| CloudRunTransportError::Decode)?,
                optional_string(target, "tag"),
            )
            .map_err(|_| CloudRunTransportError::Decode)?,
        );
    }
    CloudRunTrafficPlan::new(targets).map_err(|_| CloudRunTransportError::Decode)
}

fn parse_readiness(value: &Value) -> CloudRunReadiness {
    if value
        .get("reconciling")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return CloudRunReadiness::Reconciling;
    }
    match value
        .get("terminalCondition")
        .or_else(|| {
            value
                .get("conditions")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
        })
        .and_then(|condition| condition.get("state"))
        .and_then(Value::as_str)
    {
        Some("CONDITION_SUCCEEDED" | "True" | "true") => CloudRunReadiness::Ready,
        Some("CONDITION_FAILED" | "False" | "false") => CloudRunReadiness::Failed,
        Some(_) => CloudRunReadiness::Unknown,
        None => CloudRunReadiness::Partial,
    }
}

fn required_string(value: &Value, field: &str) -> Result<String, CloudRunTransportError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(CloudRunTransportError::Decode)
}

fn optional_string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn required_u64(value: &Value, field: &str) -> Result<u64, CloudRunTransportError> {
    optional_u64(value, field).ok_or(CloudRunTransportError::Decode)
}

fn optional_u64(value: &Value, field: &str) -> Option<u64> {
    value
        .get(field)
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
}

fn required_nested_string(
    value: &Value,
    fields: &[&str],
) -> Result<String, CloudRunTransportError> {
    nested_value(value, fields)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(CloudRunTransportError::Decode)
}

fn required_nested_u64(value: &Value, fields: &[&str]) -> Result<u64, CloudRunTransportError> {
    optional_nested_u64(value, fields).ok_or(CloudRunTransportError::Decode)
}

fn optional_nested_u64(value: &Value, fields: &[&str]) -> Option<u64> {
    nested_value(value, fields)
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
}

fn nested_value<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a Value> {
    fields
        .iter()
        .try_fold(value, |current, field| current.get(*field))
}

fn is_retryable(error: &CloudRunTransportError) -> bool {
    matches!(
        error,
        CloudRunTransportError::Conflict
            | CloudRunTransportError::RateLimited { .. }
            | CloudRunTransportError::Timeout
            | CloudRunTransportError::ServerUnavailable
            | CloudRunTransportError::Network
    )
}

fn classify_http_error(error: &ureq::Error) -> CloudRunTransportError {
    match error {
        ureq::Error::StatusCode(status) => match *status {
            401 => CloudRunTransportError::Unauthorized,
            403 => CloudRunTransportError::Forbidden,
            404 => CloudRunTransportError::NotFoundOrUnauthorized,
            409 => CloudRunTransportError::Conflict,
            422 => CloudRunTransportError::UnprocessableEntity,
            429 => CloudRunTransportError::RateLimited {
                retry_after_seconds: None,
            },
            408 => CloudRunTransportError::Timeout,
            500..=599 => CloudRunTransportError::ServerUnavailable,
            _ => CloudRunTransportError::Network,
        },
        _ => CloudRunTransportError::Network,
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

impl From<CloudRunDeploymentResultError> for CloudRunTransportError {
    fn from(_: CloudRunDeploymentResultError) -> Self {
        CloudRunTransportError::Decode
    }
}

// Keep these imports visible to rustdoc users inspecting the transport seam.
#[allow(dead_code)]
fn _typed_transport_imports(
    _location: Option<CloudRunLocation>,
    _service: Option<CloudRunServiceName>,
    _plan: Option<CloudRunTrafficPlan>,
) {
}
