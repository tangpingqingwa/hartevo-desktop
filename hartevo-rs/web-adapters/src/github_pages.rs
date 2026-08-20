use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{
    AuthSession, BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorDescriptor,
    ConnectorError, ConnectorScope, ConnectorWorker, CredentialLease, DispatchBudget,
    ExecuteRequest, FreshnessWindow, LiveProbeFence, PrepareEffectRequest, PreparedEffect,
    ProbeObservation, ProbeRequest, ProbeStatus, ProviderAdapterIdentity, ProviderAdapterOperation,
    ProviderAdapterRegistry, ProviderCapabilityKey, ProviderCapabilitySupport,
    ProviderEvidenceClass, ProviderProvenanceClass, ReadObservation, ReadRequest, ReceiptCandidate,
    ReceiptCandidateStatus, ReconcileRequest, ReconciliationObservation, ReconciliationStatus,
    RefreshAuthRequest, RevokeRequest, SecretReference, VerificationObservation,
    VerificationStatus, VerifyRequest, WebhookObservation, WebhookRequest,
};
use hartevo_domain_kernel::{AccountId, ConnectionId, MissionId, ProjectId, TenantId};
use hartevo_effect_broker::ProviderEvidenceSupport;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    GITHUB_PAGES_ADAPTER_ID, GITHUB_PAGES_ADAPTER_VERSION, GITHUB_PAGES_REGISTRY_VERSION,
    GITHUB_PAGES_REQUIRED_SCOPES, GITHUB_PROVIDER_ID, GithubPagesEnvironment, PublicationTarget,
    SiteFile, WebPublicationError, canonical_files, canonical_pages_url, digest_bytes, digest_json,
    digest_parts, file_tree_digest, map_provider_connector_error,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubPagesProviderError {
    #[error("GitHub credential is unavailable in the current environment")]
    BlockedEnv,
    #[error("GitHub provider rejected the authenticated request: {detail}")]
    Unauthorized { detail: String },
    #[error("GitHub provider rejected the request: {detail}")]
    Rejected { detail: String },
    #[error("GitHub provider response is uncertain: {detail}")]
    Uncertain { detail: String },
    #[error("GitHub provider rate limit blocked the request: {detail}")]
    RateLimited { detail: String },
    #[error("GitHub provider response could not be decoded: {detail}")]
    Decode { detail: String },
    #[error("GitHub provider transport failed: {detail}")]
    Transport { detail: String },
    #[error("GitHub Pages adapter configuration is invalid: {detail}")]
    InvalidConfiguration { detail: String },
    #[error("GitHub Pages adapter scope is invalid: {detail}")]
    Scope { detail: String },
    #[error("GitHub Pages connection has been revoked")]
    Revoked,
}

impl From<GithubPagesProviderError> for WebPublicationError {
    fn from(error: GithubPagesProviderError) -> Self {
        match error {
            GithubPagesProviderError::BlockedEnv => Self::BlockedEnv {
                detail: "GitHub credential is unavailable; no Connected state was created"
                    .to_owned(),
            },
            GithubPagesProviderError::Unauthorized { detail }
            | GithubPagesProviderError::Rejected { detail } => Self::Disconnected { detail },
            GithubPagesProviderError::Uncertain { detail }
            | GithubPagesProviderError::RateLimited { detail }
            | GithubPagesProviderError::Transport { detail }
            | GithubPagesProviderError::Decode { detail } => Self::Provider { detail },
            GithubPagesProviderError::InvalidConfiguration { detail } => {
                Self::InvalidInput { detail }
            }
            GithubPagesProviderError::Scope { detail } => Self::ScopeMismatch { detail },
            GithubPagesProviderError::Revoked => Self::Disconnected {
                detail: "GitHub Pages connection or credential was revoked".to_owned(),
            },
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubPagesTransportError {
    #[error("authenticated request was rejected with HTTP status {status}")]
    Rejected { status: u16 },
    #[error("authenticated request was rate limited with HTTP status {status}")]
    RateLimited { status: u16 },
    #[error("authenticated request returned an uncertain HTTP status {status}")]
    Uncertain { status: u16 },
    #[error("HTTP transport failed: {detail}")]
    Transport { detail: String },
    #[error("provider response could not be decoded: {detail}")]
    Decode { detail: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiSource {
    pub branch: Option<String>,
    pub path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiPages {
    pub html_url: Option<String>,
    pub source: Option<GithubPagesApiSource>,
    pub environment: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiObject {
    pub sha: String,
    #[serde(rename = "type")]
    pub object_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiCommit {
    pub sha: Option<String>,
    pub tree: GithubPagesApiObject,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub parents: Option<Vec<GithubPagesApiObject>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiTreeEntry {
    pub path: String,
    pub sha: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiTree {
    pub sha: String,
    pub truncated: Option<bool>,
    pub tree: Vec<GithubPagesApiTreeEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiBlob {
    pub sha: Option<String>,
    pub content: String,
    pub encoding: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiReference {
    pub object: GithubPagesApiObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiBlobWrite {
    pub sha: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiTreeWrite {
    pub sha: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiCommitWrite {
    pub sha: String,
    pub tree: GithubPagesApiObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPagesApiRefUpdate {
    #[serde(rename = "ref")]
    pub reference: String,
    pub object: GithubPagesApiObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPagesApiTreeWriteEntry {
    pub path: String,
    pub mode: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub sha: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPagesPublicReadback {
    pub url: String,
    pub http_status: u16,
    pub dns_digest: String,
    pub root_body_digest: String,
    pub content_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubPagesPublicationAction {
    Publish,
    Rollback,
}

impl GithubPagesPublicationAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPagesPublishPayload {
    pub action: GithubPagesPublicationAction,
    pub target: PublicationTarget,
    pub base_head_sha: String,
    pub base_tree_sha: String,
    pub target_tree_digest: String,
    pub diff_digest: String,
    pub site_id: crate::SiteId,
    pub site_revision: u64,
    pub source_work_product_id: hartevo_domain_kernel::WorkProductId,
    pub source_work_product_revision: u64,
    pub source_work_product_digest: String,
    pub payload_digest: String,
    pub idempotency_key: String,
    pub files: Vec<SiteFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPagesProviderReceipt {
    pub action: GithubPagesPublicationAction,
    pub effect_digest: String,
    pub payload_digest: String,
    pub idempotency_key: String,
    pub target: PublicationTarget,
    pub base_head_sha: String,
    pub commit_sha: String,
    pub tree_sha: String,
    pub provider_request_id_digest: String,
    pub response_digest: String,
    pub accepted_at: DateTime<Utc>,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPagesIndependentReadback {
    pub target: PublicationTarget,
    pub authenticated_snapshot: GithubPagesRepositorySnapshot,
    pub public: GithubPagesPublicReadback,
    pub expected_content_digest: String,
    pub authenticated_content_matches: bool,
    pub public_content_matches: bool,
    pub independent: bool,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPagesVerification {
    pub observation: VerificationObservation,
    pub readback: GithubPagesIndependentReadback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPagesProviderExecution {
    pub receipt: GithubPagesProviderReceipt,
    pub receipt_candidate: ReceiptCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPagesProviderReconciliation {
    pub snapshot: GithubPagesRepositorySnapshot,
    pub receipt: Option<GithubPagesProviderReceipt>,
    pub observation: ReconciliationObservation,
}

/// The provider-specific HTTP boundary. Implementations receive the resolved
/// token only for the duration of a request and must not retain or serialize it.
pub trait GithubPagesHttpTransport: Send {
    fn pages(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
    ) -> Result<GithubPagesApiPages, GithubPagesTransportError>;

    fn git_ref(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        git_ref: &str,
    ) -> Result<GithubPagesApiObject, GithubPagesTransportError>;

    fn commit(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        commit_sha: &str,
    ) -> Result<GithubPagesApiCommit, GithubPagesTransportError>;

    fn tree(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        tree_sha: &str,
    ) -> Result<GithubPagesApiTree, GithubPagesTransportError>;

    fn blob(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        blob_sha: &str,
    ) -> Result<GithubPagesApiBlob, GithubPagesTransportError>;

    fn create_blob(
        &self,
        _token: &str,
        _owner: &str,
        _repository: &str,
        _content_base64: &str,
    ) -> Result<GithubPagesApiBlobWrite, GithubPagesTransportError> {
        Err(GithubPagesTransportError::Transport {
            detail: "GitHub mutation transport is not available".to_owned(),
        })
    }

    fn create_tree(
        &self,
        _token: &str,
        _owner: &str,
        _repository: &str,
        _base_tree_sha: &str,
        _entries: &[GithubPagesApiTreeWriteEntry],
    ) -> Result<GithubPagesApiTreeWrite, GithubPagesTransportError> {
        Err(GithubPagesTransportError::Transport {
            detail: "GitHub mutation transport is not available".to_owned(),
        })
    }

    fn create_commit(
        &self,
        _token: &str,
        _owner: &str,
        _repository: &str,
        _message: &str,
        _tree_sha: &str,
        _parent_sha: &str,
    ) -> Result<GithubPagesApiCommitWrite, GithubPagesTransportError> {
        Err(GithubPagesTransportError::Transport {
            detail: "GitHub mutation transport is not available".to_owned(),
        })
    }

    fn update_ref(
        &self,
        _token: &str,
        _owner: &str,
        _repository: &str,
        _git_ref: &str,
        _commit_sha: &str,
        _force: bool,
    ) -> Result<GithubPagesApiRefUpdate, GithubPagesTransportError> {
        Err(GithubPagesTransportError::Transport {
            detail: "GitHub mutation transport is not available".to_owned(),
        })
    }

    fn public_readback(
        &self,
        _pages_url: &str,
        _expected_files: &[SiteFile],
    ) -> Result<GithubPagesPublicReadback, GithubPagesTransportError> {
        Err(GithubPagesTransportError::Transport {
            detail: "independent public readback transport is not available".to_owned(),
        })
    }
}

/// Real GitHub API transport. It is deliberately separate from the adapter so
/// contract tests can use a controlled transport without pretending to be a
/// first-party provider run.
pub struct UreqGithubPagesTransport {
    base_url: String,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqGithubPagesTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqGithubPagesTransport")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl UreqGithubPagesTransport {
    pub fn new(base_url: impl Into<String>) -> Result<Self, GithubPagesProviderError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let parsed =
            Url::parse(&base_url).map_err(|_| GithubPagesProviderError::InvalidConfiguration {
                detail: "GitHub API base URL is invalid".to_owned(),
            })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(GithubPagesProviderError::InvalidConfiguration {
                detail: "GitHub API base URL must be HTTPS without credentials or query".to_owned(),
            });
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-github-pages/1")
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self { base_url, agent })
    }

    fn endpoint(
        &self,
        owner: &str,
        repository: &str,
        suffix: impl IntoIterator<Item = String>,
    ) -> Result<String, GithubPagesTransportError> {
        let mut url =
            Url::parse(&self.base_url).map_err(|error| GithubPagesTransportError::Transport {
                detail: error.to_string(),
            })?;
        {
            let mut segments =
                url.path_segments_mut()
                    .map_err(|()| GithubPagesTransportError::Transport {
                        detail: "GitHub API URL cannot accept path segments".to_owned(),
                    })?;
            segments.push("repos").push(owner).push(repository);
            for segment in suffix {
                segments.push(&segment);
            }
        }
        Ok(url.to_string())
    }

    fn authorization<S>(request: ureq::RequestBuilder<S>, token: &str) -> ureq::RequestBuilder<S> {
        request
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        url: &str,
    ) -> Result<T, GithubPagesTransportError> {
        let request = Self::authorization(self.agent.get(url), token);
        let mut response = request.call().map_err(classify_http_error)?;
        let body = response.body_mut().read_to_string().map_err(|error| {
            GithubPagesTransportError::Transport {
                detail: error.to_string(),
            }
        })?;
        serde_json::from_str(&body).map_err(|error| GithubPagesTransportError::Decode {
            detail: error.to_string(),
        })
    }

    fn post_json<T: for<'de> Deserialize<'de>, P: Serialize>(
        &self,
        token: &str,
        url: &str,
        payload: &P,
    ) -> Result<T, GithubPagesTransportError> {
        let mut response = self
            .agent
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Content-Type", "application/json")
            .send(serde_json::to_vec(payload).map_err(|error| {
                GithubPagesTransportError::Decode {
                    detail: error.to_string(),
                }
            })?)
            .map_err(classify_http_error)?;
        let body = response.body_mut().read_to_string().map_err(|error| {
            GithubPagesTransportError::Transport {
                detail: error.to_string(),
            }
        })?;
        serde_json::from_str(&body).map_err(|error| GithubPagesTransportError::Decode {
            detail: error.to_string(),
        })
    }

    fn patch_json<T: for<'de> Deserialize<'de>, P: Serialize>(
        &self,
        token: &str,
        url: &str,
        payload: &P,
    ) -> Result<T, GithubPagesTransportError> {
        let mut response = self
            .agent
            .patch(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Content-Type", "application/json")
            .send(serde_json::to_vec(payload).map_err(|error| {
                GithubPagesTransportError::Decode {
                    detail: error.to_string(),
                }
            })?)
            .map_err(classify_http_error)?;
        let body = response.body_mut().read_to_string().map_err(|error| {
            GithubPagesTransportError::Transport {
                detail: error.to_string(),
            }
        })?;
        serde_json::from_str(&body).map_err(|error| GithubPagesTransportError::Decode {
            detail: error.to_string(),
        })
    }

    fn get_public_body(&self, url: &str) -> Result<(u16, Vec<u8>), GithubPagesTransportError> {
        let mut response = self
            .agent
            .get(url)
            .header("Accept", "text/html, application/json")
            .call()
            .map_err(classify_http_error)?;
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_vec().map_err(|error| {
            GithubPagesTransportError::Transport {
                detail: error.to_string(),
            }
        })?;
        Ok((status, body))
    }
}

impl GithubPagesHttpTransport for UreqGithubPagesTransport {
    fn pages(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
    ) -> Result<GithubPagesApiPages, GithubPagesTransportError> {
        self.get_json(
            token,
            &self.endpoint(owner, repository, ["pages".to_owned()])?,
        )
    }

    fn git_ref(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        git_ref: &str,
    ) -> Result<GithubPagesApiObject, GithubPagesTransportError> {
        let mut suffix = vec!["git".to_owned(), "ref".to_owned(), "heads".to_owned()];
        suffix.extend(git_ref.split('/').map(str::to_owned));
        let reference: GithubPagesApiReference =
            self.get_json(token, &self.endpoint(owner, repository, suffix)?)?;
        Ok(reference.object)
    }

    fn commit(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        commit_sha: &str,
    ) -> Result<GithubPagesApiCommit, GithubPagesTransportError> {
        self.get_json(
            token,
            &self.endpoint(
                owner,
                repository,
                [
                    "git".to_owned(),
                    "commits".to_owned(),
                    commit_sha.to_owned(),
                ],
            )?,
        )
    }

    fn tree(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        tree_sha: &str,
    ) -> Result<GithubPagesApiTree, GithubPagesTransportError> {
        let mut url = Url::parse(&self.endpoint(
            owner,
            repository,
            ["git".to_owned(), "trees".to_owned(), tree_sha.to_owned()],
        )?)
        .map_err(|error| GithubPagesTransportError::Transport {
            detail: error.to_string(),
        })?;
        url.query_pairs_mut().append_pair("recursive", "1");
        self.get_json(token, url.as_str())
    }

    fn blob(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        blob_sha: &str,
    ) -> Result<GithubPagesApiBlob, GithubPagesTransportError> {
        self.get_json(
            token,
            &self.endpoint(
                owner,
                repository,
                ["git".to_owned(), "blobs".to_owned(), blob_sha.to_owned()],
            )?,
        )
    }

    fn create_blob(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        content_base64: &str,
    ) -> Result<GithubPagesApiBlobWrite, GithubPagesTransportError> {
        self.post_json(
            token,
            &self.endpoint(owner, repository, ["git".to_owned(), "blobs".to_owned()])?,
            &serde_json::json!({"content": content_base64, "encoding": "base64"}),
        )
    }

    fn create_tree(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        base_tree_sha: &str,
        entries: &[GithubPagesApiTreeWriteEntry],
    ) -> Result<GithubPagesApiTreeWrite, GithubPagesTransportError> {
        self.post_json(
            token,
            &self.endpoint(owner, repository, ["git".to_owned(), "trees".to_owned()])?,
            &serde_json::json!({"base_tree": base_tree_sha, "tree": entries}),
        )
    }

    fn create_commit(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        message: &str,
        tree_sha: &str,
        parent_sha: &str,
    ) -> Result<GithubPagesApiCommitWrite, GithubPagesTransportError> {
        self.post_json(
            token,
            &self.endpoint(owner, repository, ["git".to_owned(), "commits".to_owned()])?,
            &serde_json::json!({
                "message": message,
                "tree": tree_sha,
                "parents": [parent_sha]
            }),
        )
    }

    fn update_ref(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        git_ref: &str,
        commit_sha: &str,
        force: bool,
    ) -> Result<GithubPagesApiRefUpdate, GithubPagesTransportError> {
        let mut suffix = vec!["git".to_owned(), "refs".to_owned(), "heads".to_owned()];
        suffix.extend(git_ref.split('/').map(str::to_owned));
        self.patch_json(
            token,
            &self.endpoint(owner, repository, suffix)?,
            &serde_json::json!({"sha": commit_sha, "force": force}),
        )
    }

    fn public_readback(
        &self,
        pages_url: &str,
        expected_files: &[SiteFile],
    ) -> Result<GithubPagesPublicReadback, GithubPagesTransportError> {
        let pages_url = canonical_pages_url(pages_url).map_err(|error| {
            GithubPagesTransportError::Transport {
                detail: error.to_string(),
            }
        })?;
        let parsed =
            Url::parse(&pages_url).map_err(|error| GithubPagesTransportError::Transport {
                detail: error.to_string(),
            })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| GithubPagesTransportError::Transport {
                detail: "Pages URL has no host".to_owned(),
            })?;
        let port =
            parsed
                .port_or_known_default()
                .ok_or_else(|| GithubPagesTransportError::Transport {
                    detail: "Pages URL has no known port".to_owned(),
                })?;
        let mut addresses = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|error| GithubPagesTransportError::Transport {
                detail: error.to_string(),
            })?
            .map(|address| address.ip().to_string())
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(GithubPagesTransportError::Transport {
                detail: "Pages hostname did not resolve".to_owned(),
            });
        }
        let root_url = format!("{pages_url}/");
        let (root_status, root_body) = self.get_public_body(&root_url)?;
        if !(200..=299).contains(&root_status) {
            return Err(GithubPagesTransportError::Rejected {
                status: root_status,
            });
        }
        let mut served_files = Vec::with_capacity(expected_files.len());
        for file in expected_files {
            let body = if file.path == "index.html" {
                root_body.clone()
            } else {
                let mut url = Url::parse(&root_url).map_err(|error| {
                    GithubPagesTransportError::Transport {
                        detail: error.to_string(),
                    }
                })?;
                {
                    let mut segments = url.path_segments_mut().map_err(|()| {
                        GithubPagesTransportError::Transport {
                            detail: "Pages URL cannot accept a file path".to_owned(),
                        }
                    })?;
                    for segment in file.path.split('/') {
                        segments.push(segment);
                    }
                }
                let (status, body) = self.get_public_body(url.as_str())?;
                if !(200..=299).contains(&status) {
                    return Err(GithubPagesTransportError::Rejected { status });
                }
                body
            };
            let served = SiteFile::new(file.path.clone(), body).map_err(|error| {
                GithubPagesTransportError::Decode {
                    detail: error.to_string(),
                }
            })?;
            if served.content_digest != file.content_digest {
                return Err(GithubPagesTransportError::Rejected {
                    status: root_status,
                });
            }
            served_files.push(served);
        }
        let content_digest = file_tree_digest(&served_files);
        Ok(GithubPagesPublicReadback {
            url: pages_url,
            http_status: root_status,
            dns_digest: digest_parts(addresses.iter().map(String::as_str)),
            root_body_digest: digest_bytes(&root_body),
            content_digest,
            observed_at: Utc::now(),
        })
    }
}

fn classify_http_error(error: ureq::Error) -> GithubPagesTransportError {
    match error {
        ureq::Error::StatusCode(429) => GithubPagesTransportError::RateLimited { status: 429 },
        ureq::Error::StatusCode(status) if status < 500 => {
            GithubPagesTransportError::Rejected { status }
        }
        ureq::Error::StatusCode(status) => GithubPagesTransportError::Uncertain { status },
        other => GithubPagesTransportError::Transport {
            detail: other.to_string(),
        },
    }
}

pub trait GithubCredentialResolver: Send + Sync {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<String>, GithubPagesProviderError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl GithubCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<Zeroizing<String>, GithubPagesProviderError> {
        Err(GithubPagesProviderError::BlockedEnv)
    }
}

/// A host boundary for local development. The value is still returned as a
/// zeroizing secret and never appears in a projection or durable audit entry.
#[derive(Clone, Debug)]
pub struct EnvironmentGithubCredentialResolver {
    variable: String,
}

impl Default for EnvironmentGithubCredentialResolver {
    fn default() -> Self {
        Self {
            variable: "HARTEVO_GITHUB_TOKEN".to_owned(),
        }
    }
}

impl EnvironmentGithubCredentialResolver {
    pub fn new(variable: impl Into<String>) -> Result<Self, GithubPagesProviderError> {
        let variable = variable.into();
        if variable.trim().is_empty() {
            return Err(GithubPagesProviderError::InvalidConfiguration {
                detail: "credential environment variable name is empty".to_owned(),
            });
        }
        Ok(Self { variable })
    }
}

impl GithubCredentialResolver for EnvironmentGithubCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<Zeroizing<String>, GithubPagesProviderError> {
        let token = env::var(&self.variable).map_err(|_| GithubPagesProviderError::BlockedEnv)?;
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(GithubPagesProviderError::BlockedEnv);
        }
        Ok(Zeroizing::new(token))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPagesConnection {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub environment: GithubPagesEnvironment,
    pub owner: String,
    pub repository: String,
    pub git_ref: String,
    pub pages_url: String,
    pub secret_reference_id: String,
    pub credential_revision: u64,
    pub plugin_version: String,
    pub registry_version: String,
    pub adapter: ProviderAdapterIdentity,
    pub required_scopes: BTreeSet<String>,
    pub scope_digest: String,
    pub registration_digest: String,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl GithubPagesConnection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        connection_id: ConnectionId,
        account_id: AccountId,
        owner: impl Into<String>,
        repository: impl Into<String>,
        git_ref: impl Into<String>,
        pages_url: impl Into<String>,
        environment: GithubPagesEnvironment,
        secret: &SecretReference,
    ) -> Result<Self, WebPublicationError> {
        let required_scopes = required_scopes();
        let scope = ConnectorScope::new(
            tenant_id.as_str(),
            project_id.as_str(),
            GITHUB_PROVIDER_ID,
            account_id.as_str(),
            required_scopes.iter().cloned(),
        )?;
        if secret.scope() != &scope {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "SecretReference scope does not exactly match the connection".to_owned(),
            });
        }
        let target = PublicationTarget::new(
            GITHUB_PROVIDER_ID,
            account_id.as_str(),
            owner,
            repository,
            git_ref,
            pages_url,
            environment,
        )?;
        let adapter =
            ProviderAdapterIdentity::new(GITHUB_PAGES_ADAPTER_ID, GITHUB_PAGES_ADAPTER_VERSION)?;
        let mut connection = Self {
            tenant_id,
            project_id,
            mission_id,
            connection_id,
            account_id,
            environment,
            owner: target.owner,
            repository: target.repository,
            git_ref: target.git_ref,
            pages_url: target.pages_url,
            secret_reference_id: secret.reference_id().to_owned(),
            credential_revision: secret.credential_revision(),
            plugin_version: crate::GITHUB_PAGES_PLUGIN_VERSION.to_owned(),
            registry_version: GITHUB_PAGES_REGISTRY_VERSION.to_owned(),
            adapter,
            required_scopes,
            scope_digest: scope.digest(),
            registration_digest: String::new(),
            revoked_at: None,
        };
        connection.registration_digest = connection.calculate_registration_digest();
        Ok(connection)
    }

    pub fn target(&self) -> Result<PublicationTarget, WebPublicationError> {
        PublicationTarget::new(
            GITHUB_PROVIDER_ID,
            self.account_id.as_str(),
            self.owner.as_str(),
            self.repository.as_str(),
            self.git_ref.as_str(),
            self.pages_url.as_str(),
            self.environment,
        )
    }

    pub fn scope(&self) -> Result<ConnectorScope, WebPublicationError> {
        Ok(ConnectorScope::new(
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            GITHUB_PROVIDER_ID,
            self.account_id.as_str(),
            self.required_scopes.iter().cloned(),
        )?)
    }

    pub fn validate_at(
        &self,
        secret: &SecretReference,
        now: DateTime<Utc>,
    ) -> Result<(), WebPublicationError> {
        let scope = self.scope()?;
        crate::validate_identifier(self.mission_id.as_str(), "mission_id")?;
        crate::validate_identifier(self.connection_id.as_str(), "connection_id")?;
        let expected_adapter =
            ProviderAdapterIdentity::new(GITHUB_PAGES_ADAPTER_ID, GITHUB_PAGES_ADAPTER_VERSION)?;
        if self.required_scopes != required_scopes()
            || secret.scope() != &scope
            || secret.reference_id() != self.secret_reference_id
            || secret.credential_revision() != self.credential_revision
            || self.scope_digest != scope.digest()
            || self.registration_digest != self.calculate_registration_digest()
            || self.plugin_version != crate::GITHUB_PAGES_PLUGIN_VERSION
            || self.registry_version != GITHUB_PAGES_REGISTRY_VERSION
            || self.adapter != expected_adapter
        {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "connection registration or SecretReference binding changed".to_owned(),
            });
        }
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
            return Err(GithubPagesProviderError::Revoked.into());
        }
        self.target()?;
        Ok(())
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), WebPublicationError> {
        if self.revoked_at.is_some() {
            return Err(WebPublicationError::InvalidInput {
                detail: "GitHub Pages connection is already revoked".to_owned(),
            });
        }
        self.revoked_at = Some(revoked_at);
        self.registration_digest = self.calculate_registration_digest();
        Ok(())
    }

    pub fn state_at(&self, now: DateTime<Utc>) -> GithubPagesConnectionState {
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
            GithubPagesConnectionState::Disconnected
        } else {
            GithubPagesConnectionState::Registered
        }
    }

    fn calculate_registration_digest(&self) -> String {
        let revoked_at = self
            .revoked_at
            .map_or_else(|| "active".to_owned(), |at| at.to_rfc3339());
        digest_parts([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.connection_id.as_str(),
            self.account_id.as_str(),
            self.environment.as_str(),
            self.owner.as_str(),
            self.repository.as_str(),
            self.git_ref.as_str(),
            self.pages_url.as_str(),
            self.secret_reference_id.as_str(),
            &self.credential_revision.to_string(),
            self.plugin_version.as_str(),
            self.registry_version.as_str(),
            self.adapter.adapter_id(),
            &self.adapter.adapter_version().to_string(),
            &self
                .required_scopes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
            self.scope_digest.as_str(),
            revoked_at.as_str(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubPagesConnectionState {
    Registered,
    Connected,
    Disconnected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPagesRepositorySnapshot {
    pub target: PublicationTarget,
    pub head_sha: String,
    pub tree_sha: String,
    pub files: Vec<SiteFile>,
    pub content_digest: String,
    pub tree_digest: String,
    pub response_digest: String,
    pub observed_at: DateTime<Utc>,
}

pub(crate) struct AdapterState {
    failure: Mutex<Option<GithubPagesProviderError>>,
    snapshot: Mutex<Option<GithubPagesRepositorySnapshot>>,
    prepared_payloads: Mutex<BTreeMap<String, GithubPagesPublishPayload>>,
    receipts: Mutex<BTreeMap<String, GithubPagesProviderReceipt>>,
    readbacks: Mutex<BTreeMap<String, GithubPagesIndependentReadback>>,
}

impl Default for AdapterState {
    fn default() -> Self {
        Self {
            failure: Mutex::new(None),
            snapshot: Mutex::new(None),
            prepared_payloads: Mutex::new(BTreeMap::new()),
            receipts: Mutex::new(BTreeMap::new()),
            readbacks: Mutex::new(BTreeMap::new()),
        }
    }
}

impl AdapterState {
    fn record_failure(&self, error: GithubPagesProviderError) {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some(error);
        }
    }

    fn take_failure(&self) -> Option<GithubPagesProviderError> {
        self.failure
            .lock()
            .ok()
            .and_then(|mut failure| failure.take())
    }

    fn store_snapshot(&self, snapshot: GithubPagesRepositorySnapshot) {
        if let Ok(mut current) = self.snapshot.lock() {
            *current = Some(snapshot);
        }
    }

    fn snapshot(&self) -> Option<GithubPagesRepositorySnapshot> {
        self.snapshot
            .lock()
            .ok()
            .and_then(|snapshot| snapshot.clone())
    }

    fn store_payload(&self, effect_digest: String, payload: GithubPagesPublishPayload) {
        if let Ok(mut payloads) = self.prepared_payloads.lock() {
            payloads.insert(effect_digest, payload);
        }
    }

    fn payload(&self, effect_digest: &str) -> Option<GithubPagesPublishPayload> {
        self.prepared_payloads
            .lock()
            .ok()
            .and_then(|payloads| payloads.get(effect_digest).cloned())
    }

    fn store_receipt(&self, receipt: GithubPagesProviderReceipt) {
        if let Ok(mut receipts) = self.receipts.lock() {
            receipts.insert(receipt.effect_digest.clone(), receipt);
        }
    }

    fn receipt(&self, effect_digest: &str) -> Option<GithubPagesProviderReceipt> {
        self.receipts
            .lock()
            .ok()
            .and_then(|receipts| receipts.get(effect_digest).cloned())
    }

    fn store_readback(&self, effect_digest: String, readback: GithubPagesIndependentReadback) {
        if let Ok(mut readbacks) = self.readbacks.lock() {
            readbacks.insert(effect_digest, readback);
        }
    }

    fn readback(&self, effect_digest: &str) -> Option<GithubPagesIndependentReadback> {
        self.readbacks
            .lock()
            .ok()
            .and_then(|readbacks| readbacks.get(effect_digest).cloned())
    }
}

pub struct GithubPagesAdapter<T, R>
where
    T: GithubPagesHttpTransport,
    R: GithubCredentialResolver,
{
    connection: GithubPagesConnection,
    secret: SecretReference,
    transport: T,
    resolver: Arc<R>,
    descriptor: ConnectorDescriptor,
    state: Arc<AdapterState>,
}

impl<T, R> fmt::Debug for GithubPagesAdapter<T, R>
where
    T: GithubPagesHttpTransport,
    R: GithubCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPagesAdapter")
            .field("connection", &self.connection)
            .field("secret", &self.secret)
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl<T, R> GithubPagesAdapter<T, R>
where
    T: GithubPagesHttpTransport,
    R: GithubCredentialResolver,
{
    pub(crate) fn new(
        connection: GithubPagesConnection,
        secret: SecretReference,
        transport: T,
        resolver: Arc<R>,
        now: DateTime<Utc>,
    ) -> Result<(Self, Arc<AdapterState>), WebPublicationError> {
        connection.validate_at(&secret, now)?;
        let descriptor = descriptor()?;
        let state = Arc::new(AdapterState::default());
        Ok((
            Self {
                connection,
                secret,
                transport,
                resolver,
                descriptor,
                state: Arc::clone(&state),
            },
            state,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated read binds Pages configuration, ref, commit, tree, and blob content into one provider snapshot"
    )]
    fn snapshot_from_provider(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<GithubPagesRepositorySnapshot, GithubPagesProviderError> {
        let token = self.resolver.resolve(&self.secret)?;
        let target = self.connection.target().map_err(|error| {
            GithubPagesProviderError::InvalidConfiguration {
                detail: error.to_string(),
            }
        })?;
        let pages = self
            .transport
            .pages(token.as_str(), &target.owner, &target.repository)
            .map_err(map_transport_error)?;
        let pages_url = pages
            .html_url
            .as_deref()
            .ok_or_else(|| invalid_response("GitHub Pages response did not include html_url"))?;
        if canonical_pages_url(pages_url).map_err(|error| provider_invalid(&error))?
            != target.pages_url
        {
            return Err(invalid_response(
                "GitHub Pages URL does not match the exact registered target",
            ));
        }
        let source = pages
            .source
            .as_ref()
            .ok_or_else(|| invalid_response("GitHub Pages response did not include source"))?;
        if source.branch.as_deref() != Some(target.git_ref.as_str()) {
            return Err(invalid_response(
                "GitHub Pages source branch does not match the exact registered ref",
            ));
        }
        if let Some(environment) = pages.environment.as_deref()
            && environment != target.environment.as_str()
        {
            return Err(invalid_response(
                "GitHub Pages environment does not match the exact registered environment",
            ));
        }
        let reference = self
            .transport
            .git_ref(
                token.as_str(),
                &target.owner,
                &target.repository,
                &target.git_ref,
            )
            .map_err(map_transport_error)?;
        if reference.object_type.as_deref() != Some("commit") || !valid_git_sha(&reference.sha) {
            return Err(invalid_response(
                "GitHub ref did not resolve to a commit SHA",
            ));
        }
        let commit = self
            .transport
            .commit(
                token.as_str(),
                &target.owner,
                &target.repository,
                &reference.sha,
            )
            .map_err(map_transport_error)?;
        if commit
            .tree
            .object_type
            .as_deref()
            .is_some_and(|object_type| object_type != "tree")
            || !valid_git_sha(&commit.tree.sha)
        {
            return Err(invalid_response("GitHub commit did not include a tree SHA"));
        }
        let tree = self
            .transport
            .tree(
                token.as_str(),
                &target.owner,
                &target.repository,
                &commit.tree.sha,
            )
            .map_err(map_transport_error)?;
        if tree.truncated.unwrap_or(false) {
            return Err(invalid_response(
                "GitHub repository tree was truncated and cannot be canonicalized",
            ));
        }
        let mut files = Vec::new();
        let mut tree_material = Vec::new();
        for entry in tree.tree {
            if entry.entry_type == "tree" {
                continue;
            }
            if entry.entry_type != "blob" || !valid_git_sha(&entry.sha) {
                return Err(invalid_response(
                    "GitHub tree contained an unsupported or invalid entry",
                ));
            }
            let blob = self
                .transport
                .blob(
                    token.as_str(),
                    &target.owner,
                    &target.repository,
                    &entry.sha,
                )
                .map_err(map_transport_error)?;
            if blob.encoding != "base64" {
                return Err(invalid_response(
                    "GitHub blob was not returned with base64 encoding",
                ));
            }
            let encoded = blob.content.lines().collect::<String>();
            let content = STANDARD.decode(encoded.as_bytes()).map_err(|error| {
                GithubPagesProviderError::Decode {
                    detail: error.to_string(),
                }
            })?;
            files.push(
                SiteFile::new(entry.path.clone(), content)
                    .map_err(|error| provider_invalid(&error))?,
            );
            tree_material.push(format!("{}|{}|{}", entry.path, entry.entry_type, entry.sha));
        }
        let files = canonical_files(files).map_err(|error| provider_invalid(&error))?;
        let content_digest = file_tree_digest(&files);
        tree_material.sort();
        let tree_digest = digest_parts(tree_material.iter().map(String::as_str));
        let response_digest =
            digest_json(&(&pages, &reference, &commit, &tree_digest, &content_digest))
                .map_err(|error| provider_invalid(&error))?;
        Ok(GithubPagesRepositorySnapshot {
            target,
            head_sha: reference.sha,
            tree_sha: commit.tree.sha,
            files,
            content_digest,
            tree_digest,
            response_digest,
            observed_at,
        })
    }

    fn validate_payload(
        &self,
        payload: &GithubPagesPublishPayload,
    ) -> Result<Vec<SiteFile>, GithubPagesProviderError> {
        let target = self
            .connection
            .target()
            .map_err(|error| provider_invalid(&error))?;
        if payload.target != target
            || !valid_git_sha(&payload.base_head_sha)
            || !valid_git_sha(&payload.base_tree_sha)
            || !crate::is_digest(&payload.target_tree_digest)
            || !crate::is_digest(&payload.diff_digest)
            || !crate::is_digest(&payload.payload_digest)
            || payload.site_revision == 0
            || payload.source_work_product_revision == 0
        {
            return Err(GithubPagesProviderError::Scope {
                detail: "publication payload is outside the registered GitHub Pages target"
                    .to_owned(),
            });
        }
        let files =
            canonical_files(payload.files.clone()).map_err(|error| provider_invalid(&error))?;
        if file_tree_digest(&files) != payload.target_tree_digest {
            return Err(GithubPagesProviderError::Rejected {
                detail: "publication payload content digest changed after approval".to_owned(),
            });
        }
        Ok(files)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the provider mutation binds the fresh head, complete canonical tree, commit parent, ref CAS, and receipt"
    )]
    fn execute_payload(
        &mut self,
        request: &ExecuteRequest,
    ) -> Result<ReceiptCandidate, ConnectorError> {
        let payload = self
            .state
            .payload(request.prepared_effect.effect_digest())
            .ok_or_else(|| {
                self.provider_failure(GithubPagesProviderError::Rejected {
                    detail: "prepared publication payload is not available for this Effect"
                        .to_owned(),
                })
            })?;
        let files = self
            .validate_payload(&payload)
            .map_err(|error| self.provider_failure(error))?;
        let token = self
            .resolver
            .resolve(&self.secret)
            .map_err(|error| self.provider_failure(error))?;
        let current = self
            .snapshot_from_provider(request.at)
            .map_err(|error| self.provider_failure(error))?;
        if current.target != payload.target
            || current.head_sha != payload.base_head_sha
            || current.tree_sha != payload.base_tree_sha
        {
            return Err(self.provider_failure(GithubPagesProviderError::Rejected {
                detail: "GitHub Pages repository drifted after the canonical proposal".to_owned(),
            }));
        }

        let mut blob_shas = BTreeMap::new();
        for file in &files {
            let blob = self
                .transport
                .create_blob(
                    token.as_str(),
                    &payload.target.owner,
                    &payload.target.repository,
                    STANDARD.encode(&file.content).as_str(),
                )
                .map_err(|error| self.provider_failure(map_transport_error(error)))?;
            if !valid_git_sha(&blob.sha) {
                return Err(self.provider_failure(GithubPagesProviderError::Decode {
                    detail: "GitHub blob mutation returned an invalid SHA".to_owned(),
                }));
            }
            blob_shas.insert(file.path.as_str().to_owned(), blob.sha);
        }

        let target_paths = files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<BTreeSet<_>>();
        let deleted_paths = current
            .files
            .iter()
            .map(|file| file.path.as_str())
            .filter(|path| !target_paths.contains(path))
            .collect::<BTreeSet<_>>();
        let mut entries = Vec::with_capacity(files.len() + deleted_paths.len());
        for file in &files {
            entries.push(GithubPagesApiTreeWriteEntry {
                path: file.path.clone(),
                mode: "100644".to_owned(),
                entry_type: "blob".to_owned(),
                sha: blob_shas.get(file.path.as_str()).cloned(),
            });
        }
        for path in deleted_paths {
            entries.push(GithubPagesApiTreeWriteEntry {
                path: path.to_owned(),
                mode: "100644".to_owned(),
                entry_type: "blob".to_owned(),
                sha: None,
            });
        }
        let tree = self
            .transport
            .create_tree(
                token.as_str(),
                &payload.target.owner,
                &payload.target.repository,
                &payload.base_tree_sha,
                &entries,
            )
            .map_err(|error| self.provider_failure(map_transport_error(error)))?;
        if !valid_git_sha(&tree.sha) {
            return Err(self.provider_failure(GithubPagesProviderError::Decode {
                detail: "GitHub tree mutation returned an invalid SHA".to_owned(),
            }));
        }
        let action = payload.action.as_str();
        let message = format!("Hartevo {action} {}", payload.payload_digest);
        let commit = self
            .transport
            .create_commit(
                token.as_str(),
                &payload.target.owner,
                &payload.target.repository,
                &message,
                &tree.sha,
                &payload.base_head_sha,
            )
            .map_err(|error| self.provider_failure(map_transport_error(error)))?;
        if !valid_git_sha(&commit.sha) || commit.tree.sha != tree.sha {
            return Err(self.provider_failure(GithubPagesProviderError::Decode {
                detail: "GitHub commit mutation returned an invalid tree binding".to_owned(),
            }));
        }
        let updated = self
            .transport
            .update_ref(
                token.as_str(),
                &payload.target.owner,
                &payload.target.repository,
                &payload.target.git_ref,
                &commit.sha,
                false,
            )
            .map_err(|error| self.provider_failure(map_transport_error(error)))?;
        let expected_ref = format!("refs/heads/{}", payload.target.git_ref);
        if updated.reference != expected_ref || updated.object.sha != commit.sha {
            return Err(self.provider_failure(GithubPagesProviderError::Uncertain {
                detail: "GitHub ref mutation response did not bind the exact commit".to_owned(),
            }));
        }
        let provider_request_id_digest = digest_parts([
            "github-git-data",
            commit.sha.as_str(),
            tree.sha.as_str(),
            payload.payload_digest.as_str(),
            action,
        ]);
        let response_digest = digest_json(&(
            &payload.target,
            &payload.base_head_sha,
            &payload.base_tree_sha,
            &commit,
            &updated,
            &payload.target_tree_digest,
        ))
        .map_err(|error| self.provider_failure(provider_invalid(&error)))?;
        let mut receipt = GithubPagesProviderReceipt {
            action: payload.action,
            effect_digest: request.prepared_effect.effect_digest().to_owned(),
            payload_digest: payload.payload_digest.clone(),
            idempotency_key: request.prepared_effect.idempotency_key().to_owned(),
            target: payload.target.clone(),
            base_head_sha: payload.base_head_sha.clone(),
            commit_sha: commit.sha,
            tree_sha: tree.sha,
            provider_request_id_digest,
            response_digest,
            accepted_at: request.at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = digest_json(&receipt)
            .map_err(|error| self.provider_failure(provider_invalid(&error)))?;
        let candidate = ReceiptCandidate::new(
            &request.prepared_effect,
            receipt.provider_request_id_digest.clone(),
            ReceiptCandidateStatus::Accepted,
            receipt.response_digest.clone(),
            request.at,
        )?;
        self.state.store_receipt(receipt);
        Ok(candidate)
    }

    fn independent_readback_from_provider(
        &self,
        payload: &GithubPagesPublishPayload,
        effect_digest: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<GithubPagesIndependentReadback, GithubPagesProviderError> {
        let files = self.validate_payload(payload)?;
        let snapshot = self.snapshot_from_provider(observed_at)?;
        let public = self
            .transport
            .public_readback(&payload.target.pages_url, &files)
            .map_err(map_transport_error)?;
        let expected_content_digest = file_tree_digest(&files);
        let authenticated_content_matches = snapshot.target == payload.target
            && snapshot.content_digest == expected_content_digest
            && snapshot.files == files;
        let public_content_matches = public.url == payload.target.pages_url
            && (200..=299).contains(&public.http_status)
            && public.content_digest == expected_content_digest;
        let evidence_digest = digest_json(&(
            effect_digest,
            &payload.target,
            &snapshot.response_digest,
            &public,
            &expected_content_digest,
            authenticated_content_matches,
            public_content_matches,
        ))
        .map_err(|error| provider_invalid(&error))?;
        Ok(GithubPagesIndependentReadback {
            target: payload.target.clone(),
            authenticated_snapshot: snapshot,
            public,
            expected_content_digest,
            authenticated_content_matches,
            public_content_matches,
            independent: true,
            evidence_digest,
            observed_at,
        })
    }

    fn provider_failure(&self, error: GithubPagesProviderError) -> ConnectorError {
        let uncertain = matches!(
            error,
            GithubPagesProviderError::Uncertain { .. }
                | GithubPagesProviderError::Transport { .. }
                | GithubPagesProviderError::RateLimited { .. }
        );
        self.state.record_failure(error);
        if uncertain {
            ConnectorError::ProviderUncertain
        } else {
            ConnectorError::ProviderRejected
        }
    }
}

impl<T, R> ConnectorAdapter for GithubPagesAdapter<T, R>
where
    T: GithubPagesHttpTransport,
    R: GithubCredentialResolver,
{
    fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    fn begin_auth(
        &mut self,
        request: BeginAuthRequest,
    ) -> Result<hartevo_connector_sdk::AuthSession, ConnectorError> {
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn refresh_auth(
        &mut self,
        request: RefreshAuthRequest,
    ) -> Result<hartevo_connector_sdk::AuthSession, ConnectorError> {
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn probe(&mut self, request: ProbeRequest) -> Result<ProbeObservation, ConnectorError> {
        let snapshot = self
            .snapshot_from_provider(request.at)
            .map_err(|error| self.provider_failure(error))?;
        let evidence_digest = snapshot.response_digest.clone();
        self.state.store_snapshot(snapshot);
        ProbeObservation::new(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
            request.at,
            request.at + Duration::seconds(60),
            evidence_digest,
        )
    }

    fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError> {
        let snapshot = self
            .snapshot_from_provider(request.at)
            .map_err(|error| self.provider_failure(error))?;
        let item_count = u32::try_from(snapshot.files.len()).map_err(|_| {
            self.provider_failure(GithubPagesProviderError::Rejected {
                detail: "repository contains too many files".to_owned(),
            })
        })?;
        let response_digest = snapshot.response_digest.clone();
        let content_digest = snapshot.content_digest.clone();
        self.state.store_snapshot(snapshot);
        ReadObservation::new(
            format!("read-observation-{}", &response_digest[..24]),
            request.scope,
            request.capability,
            self.descriptor.identity().clone(),
            request.query_digest,
            response_digest,
            content_digest,
            ProviderProvenanceClass::ProductionProvider,
            FreshnessWindow::new(request.at, request.at + Duration::seconds(60), 1).map_err(
                |error| {
                    self.provider_failure(GithubPagesProviderError::Rejected {
                        detail: error.to_string(),
                    })
                },
            )?,
            1,
            item_count,
            None,
        )
    }

    fn prepare_effect(
        &mut self,
        request: PrepareEffectRequest,
    ) -> Result<PreparedEffect, ConnectorError> {
        PreparedEffect::new(
            request.scope,
            request.capability,
            self.descriptor.identity().clone(),
            request.payload_digest,
            request.idempotency_key,
            request.prepared_at,
            request.expires_at,
            request.cost_minor,
        )
    }

    fn execute(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<hartevo_connector_sdk::ReceiptCandidate, ConnectorError> {
        self.execute_payload(&request)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "reconciliation binds fresh repository state to an existing Effect without granting a new execution permit"
    )]
    fn reconcile(
        &mut self,
        request: ReconcileRequest,
    ) -> Result<ReconciliationObservation, ConnectorError> {
        let payload = self.state.payload(&request.effect_digest).ok_or_else(|| {
            self.provider_failure(GithubPagesProviderError::Rejected {
                detail: "reconciliation payload is not available for this Effect".to_owned(),
            })
        })?;
        let files = self
            .validate_payload(&payload)
            .map_err(|error| self.provider_failure(error))?;
        let snapshot = self
            .snapshot_from_provider(request.at)
            .map_err(|error| self.provider_failure(error))?;
        self.state.store_snapshot(snapshot.clone());
        let target_content_matches = snapshot.target == payload.target
            && snapshot.content_digest == payload.target_tree_digest
            && snapshot.files == files;
        let mut receipt = self.state.receipt(&request.effect_digest);
        let status = if let Some(existing) = receipt.clone() {
            if target_content_matches && snapshot.head_sha == existing.commit_sha {
                ReconciliationStatus::ReceiptFound
            } else {
                return Err(self.provider_failure(GithubPagesProviderError::Rejected {
                    detail: "persisted provider receipt no longer matches GitHub readback"
                        .to_owned(),
                }));
            }
        } else if target_content_matches && snapshot.head_sha != payload.base_head_sha {
            let token = self
                .resolver
                .resolve(&self.secret)
                .map_err(|error| self.provider_failure(error))?;
            let commit = self
                .transport
                .commit(
                    token.as_str(),
                    &payload.target.owner,
                    &payload.target.repository,
                    &snapshot.head_sha,
                )
                .map_err(|error| self.provider_failure(map_transport_error(error)))?;
            let expected_message = format!(
                "Hartevo {} {}",
                payload.action.as_str(),
                payload.payload_digest
            );
            let parent_matches = commit.parents.as_ref().is_some_and(|parents| {
                parents
                    .iter()
                    .any(|parent| parent.sha == payload.base_head_sha)
            });
            if commit.message.as_deref() == Some(expected_message.as_str()) && parent_matches {
                let provider_request_id_digest = digest_parts([
                    "github-git-data",
                    snapshot.head_sha.as_str(),
                    snapshot.tree_sha.as_str(),
                    payload.payload_digest.as_str(),
                    payload.action.as_str(),
                ]);
                let mut synthesized = GithubPagesProviderReceipt {
                    action: payload.action,
                    effect_digest: request.effect_digest.clone(),
                    payload_digest: payload.payload_digest.clone(),
                    idempotency_key: payload.idempotency_key.clone(),
                    target: payload.target.clone(),
                    base_head_sha: payload.base_head_sha.clone(),
                    commit_sha: snapshot.head_sha.clone(),
                    tree_sha: snapshot.tree_sha.clone(),
                    provider_request_id_digest,
                    response_digest: snapshot.response_digest.clone(),
                    accepted_at: snapshot.observed_at,
                    receipt_digest: String::new(),
                };
                synthesized.receipt_digest = digest_json(&synthesized)
                    .map_err(|error| self.provider_failure(provider_invalid(&error)))?;
                self.state.store_receipt(synthesized.clone());
                receipt = Some(synthesized);
                ReconciliationStatus::ReceiptFound
            } else {
                ReconciliationStatus::ProviderRejected
            }
        } else if snapshot.head_sha == payload.base_head_sha {
            ReconciliationStatus::NotExecuted
        } else {
            ReconciliationStatus::ProviderRejected
        };
        let freshness = FreshnessWindow::new(
            snapshot.observed_at,
            snapshot.observed_at + Duration::seconds(60),
            1,
        )
        .map_err(|error| {
            self.provider_failure(GithubPagesProviderError::Rejected {
                detail: error.to_string(),
            })
        })?;
        let observation = ReconciliationObservation::new(
            request.effect_digest,
            request.scope,
            status,
            snapshot.response_digest.clone(),
            request.at,
            freshness,
        )?;
        if receipt.is_none() && status == ReconciliationStatus::ReceiptFound {
            return Err(self.provider_failure(GithubPagesProviderError::Rejected {
                detail: "receipt-found reconciliation had no provider receipt".to_owned(),
            }));
        }
        Ok(observation)
    }

    fn verify(
        &mut self,
        request: VerifyRequest,
    ) -> Result<VerificationObservation, ConnectorError> {
        let payload = self.state.payload(&request.subject_digest).ok_or_else(|| {
            self.provider_failure(GithubPagesProviderError::Rejected {
                detail: "verification payload is not available for this Effect".to_owned(),
            })
        })?;
        let readback = self
            .independent_readback_from_provider(&payload, &request.subject_digest, request.at)
            .map_err(|error| self.provider_failure(error))?;
        let status = if readback.authenticated_content_matches && readback.public_content_matches {
            VerificationStatus::Confirmed
        } else {
            VerificationStatus::Rejected
        };
        let evidence_digest = readback.evidence_digest.clone();
        self.state
            .store_readback(request.subject_digest.clone(), readback);
        VerificationObservation::new(
            request.subject_digest,
            request.scope,
            status,
            evidence_digest,
            request.at,
            true,
        )
    }

    fn handle_webhook(
        &mut self,
        _request: WebhookRequest,
    ) -> Result<WebhookObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn revoke(&mut self, _request: RevokeRequest) -> Result<(), ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }
}

pub struct GithubPagesProvider<T, R>
where
    T: GithubPagesHttpTransport,
    R: GithubCredentialResolver,
{
    connection: GithubPagesConnection,
    secret: SecretReference,
    worker: ConnectorWorker<GithubPagesAdapter<T, R>>,
    credential_lease: CredentialLease,
    auth_session: AuthSession,
    probe_revision: u64,
    live_probe: LiveProbeFence,
    state: Arc<AdapterState>,
    connected_at: DateTime<Utc>,
}

impl<T, R> fmt::Debug for GithubPagesProvider<T, R>
where
    T: GithubPagesHttpTransport,
    R: GithubCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPagesProvider")
            .field("connection", &self.connection)
            .field("worker", &self.worker)
            .field("live_probe", &self.live_probe)
            .field("connected_at", &self.connected_at)
            .finish_non_exhaustive()
    }
}

impl<T, R> GithubPagesProvider<T, R>
where
    T: GithubPagesHttpTransport,
    R: GithubCredentialResolver,
{
    #[allow(clippy::too_many_lines)]
    pub fn connect(
        connection: GithubPagesConnection,
        secret: SecretReference,
        transport: T,
        resolver: Arc<R>,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        connection.validate_at(&secret, now)?;
        let (adapter, state) =
            GithubPagesAdapter::new(connection.clone(), secret.clone(), transport, resolver, now)?;
        let registry = registry()?;
        let scope = connection.scope()?;
        let mut worker = ConnectorWorker::new(
            format!("worker-{}", &connection.registration_digest[..24]),
            adapter,
            registry,
            scope.clone(),
            now,
            now + Duration::minutes(10),
        )?;
        let dispatch = worker.dispatch_fence();
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            connection.adapter.clone(),
            format!("lease-{}", &connection.registration_digest[..24]),
            1,
            now,
            now + Duration::minutes(5),
        )?;
        let session = worker.begin_auth(BeginAuthRequest {
            dispatch: dispatch.clone(),
            scope: scope.clone(),
            secret_reference: secret.clone(),
            credential_lease: lease.clone(),
            auth_revision: 1,
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        })?;
        let probe = worker.probe(ProbeRequest {
            dispatch,
            scope,
            secret_reference: secret.clone(),
            credential_lease: lease.clone(),
            session: session.clone(),
            probe_revision: 1,
            result_id: format!("probe-result-{}", &connection.registration_digest[..24]),
            at: now,
        });
        let probe = match probe {
            Ok(probe) => probe,
            Err(error) => return Err(provider_error_from_state(&state, &error)),
        };
        let live_probe = match worker.authorize_probe(&probe, now) {
            Ok(fence) => fence,
            Err(error) => return Err(provider_error_from_state(&state, &error)),
        };
        Ok(Self {
            connection,
            secret,
            worker,
            credential_lease: lease,
            auth_session: session,
            probe_revision: 1,
            live_probe,
            state,
            connected_at: now,
        })
    }

    pub fn connection(&self) -> &GithubPagesConnection {
        &self.connection
    }

    pub fn connection_state(&self) -> GithubPagesConnectionState {
        if self.connection.revoked_at.is_some() {
            GithubPagesConnectionState::Disconnected
        } else {
            GithubPagesConnectionState::Connected
        }
    }

    pub fn connected_at(&self) -> DateTime<Utc> {
        self.connected_at
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), WebPublicationError> {
        self.connection.revoke(revoked_at)
    }

    /// Refresh the connector probe before a long-running Pages build or
    /// readback crosses the SDK's bounded probe TTL. This renews only the
    /// provider-health fence; it never mints Effect approval or execution
    /// authority and it reuses the existing opaque credential lease/session.
    fn refresh_live_probe(&mut self, at: DateTime<Utc>) -> Result<(), WebPublicationError> {
        if at < self.live_probe.observed_valid_until() - Duration::seconds(15) {
            return Ok(());
        }
        self.worker.set_now(at);
        self.probe_revision = self.probe_revision.saturating_add(1);
        let probe = self
            .worker
            .probe(ProbeRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.connection.scope()?,
                secret_reference: self.secret.clone(),
                credential_lease: self.credential_lease.clone(),
                session: self.auth_session.clone(),
                probe_revision: self.probe_revision,
                result_id: format!(
                    "probe-result-{}-{}",
                    &self.connection.registration_digest[..24],
                    self.probe_revision
                ),
                at,
            })
            .map_err(|error| provider_error_from_state(&self.state, &error))?;
        self.live_probe = self
            .worker
            .authorize_probe(&probe, at)
            .map_err(|error| provider_error_from_state(&self.state, &error))?;
        Ok(())
    }

    pub fn read_current(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<GithubPagesProviderRead, WebPublicationError> {
        self.connection.validate_at(&self.secret, now)?;
        self.refresh_live_probe(now)?;
        self.worker.set_now(now);
        let query_digest = digest_parts([
            self.connection.registration_digest.as_str(),
            "site.read.current",
            self.connection.environment.as_str(),
        ]);
        let budget = DispatchBudget::new(100, now + Duration::seconds(60), 100, 0)?;
        let observation = self.worker.read(ReadRequest {
            dispatch: self.worker.dispatch_fence(),
            scope: self.connection.scope()?,
            live_probe: self.live_probe.clone(),
            capability: ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, "site.read")?,
            query_digest,
            cursor: None,
            page_size: 1_000,
            at: now,
            budget,
        });
        let observation = match observation {
            Ok(observation) => observation,
            Err(error) => return Err(provider_error_from_state(&self.state, &error)),
        };
        let snapshot = self
            .state
            .snapshot()
            .ok_or_else(|| WebPublicationError::Provider {
                detail: "GitHub Pages adapter returned no repository snapshot".to_owned(),
            })?;
        if observation.content_digest() != snapshot.content_digest {
            return Err(WebPublicationError::Provider {
                detail: "Connector SDK read digest does not match provider snapshot".to_owned(),
            });
        }
        Ok(GithubPagesProviderRead {
            snapshot,
            observation,
            registration_digest: self.connection.registration_digest.clone(),
            registry_version: self.connection.registry_version.clone(),
        })
    }

    pub fn prepare_publish(
        &mut self,
        payload_digest: &str,
        idempotency_key: &str,
        prepared_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<PreparedEffect, WebPublicationError> {
        self.connection.validate_at(&self.secret, prepared_at)?;
        self.refresh_live_probe(prepared_at)?;
        self.worker.set_now(prepared_at);
        let prepared = self.worker.prepare_effect(PrepareEffectRequest {
            dispatch: self.worker.dispatch_fence(),
            scope: self.connection.scope()?,
            live_probe: self.live_probe.clone(),
            capability: ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, "publication.publish")?,
            payload_digest: payload_digest.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            prepared_at,
            expires_at,
            cost_minor: 0,
        });
        prepared.map_err(|error| provider_error_from_state(&self.state, &error))
    }

    pub fn register_publish_payload(
        &mut self,
        effect_digest: impl Into<String>,
        payload: GithubPagesPublishPayload,
    ) -> Result<(), WebPublicationError> {
        let effect_digest = effect_digest.into();
        if !crate::is_digest(&effect_digest) {
            return Err(WebPublicationError::InvalidInput {
                detail: "Connector effect digest must be a lowercase SHA-256 digest".to_owned(),
            });
        }
        self.state.store_payload(effect_digest, payload);
        Ok(())
    }

    pub fn prepare_publish_payload(
        &mut self,
        payload: GithubPagesPublishPayload,
        idempotency_key: &str,
        prepared_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<PreparedEffect, WebPublicationError> {
        let prepared = self.prepare_publish(
            &payload.payload_digest,
            idempotency_key,
            prepared_at,
            expires_at,
        )?;
        self.state
            .store_payload(prepared.effect_digest().to_owned(), payload);
        Ok(prepared)
    }

    pub fn execute_publish(
        &mut self,
        payload: GithubPagesPublishPayload,
        prepared_effect: &PreparedEffect,
        execution_context: hartevo_connector_sdk::EffectExecutionContext,
        at: DateTime<Utc>,
    ) -> Result<GithubPagesProviderExecution, WebPublicationError> {
        if prepared_effect.payload_digest() != payload.payload_digest {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "prepared Effect payload does not match the approved publication"
                    .to_owned(),
            });
        }
        self.connection.validate_at(&self.secret, at)?;
        self.refresh_live_probe(at)?;
        self.state
            .store_payload(prepared_effect.effect_digest().to_owned(), payload);
        self.worker.set_now(at);
        let receipt_candidate = self
            .worker
            .execute(ExecuteRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.connection.scope()?,
                live_probe: self.live_probe.clone(),
                prepared_effect: (*prepared_effect).clone(),
                execution_context,
                at,
            })
            .map_err(|error| provider_error_from_state(&self.state, &error))?;
        let receipt = self
            .state
            .receipt(prepared_effect.effect_digest())
            .ok_or_else(|| WebPublicationError::Provider {
                detail: "GitHub mutation returned a candidate without a provider receipt"
                    .to_owned(),
            })?;
        Ok(GithubPagesProviderExecution {
            receipt,
            receipt_candidate,
        })
    }

    pub fn reconcile_publish(
        &mut self,
        payload: GithubPagesPublishPayload,
        effect_digest: &str,
        at: DateTime<Utc>,
    ) -> Result<GithubPagesProviderReconciliation, WebPublicationError> {
        if !crate::is_digest(effect_digest) {
            return Err(WebPublicationError::InvalidInput {
                detail: "Connector effect digest must be a lowercase SHA-256 digest".to_owned(),
            });
        }
        self.connection.validate_at(&self.secret, at)?;
        self.refresh_live_probe(at)?;
        self.state.store_payload(effect_digest.to_owned(), payload);
        self.worker.set_now(at);
        let observation = self
            .worker
            .reconcile(ReconcileRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.connection.scope()?,
                live_probe: self.live_probe.clone(),
                capability: ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, "publication.publish")?,
                effect_digest: effect_digest.to_owned(),
                at,
            })
            .map_err(|error| provider_error_from_state(&self.state, &error))?;
        let snapshot = self
            .state
            .snapshot()
            .ok_or_else(|| WebPublicationError::Provider {
                detail: "GitHub reconciliation returned no repository snapshot".to_owned(),
            })?;
        Ok(GithubPagesProviderReconciliation {
            snapshot,
            receipt: self.state.receipt(effect_digest),
            observation,
        })
    }

    pub fn verify_publish(
        &mut self,
        payload: GithubPagesPublishPayload,
        effect_digest: &str,
        at: DateTime<Utc>,
    ) -> Result<GithubPagesVerification, WebPublicationError> {
        if !crate::is_digest(effect_digest) {
            return Err(WebPublicationError::InvalidInput {
                detail: "Connector effect digest must be a lowercase SHA-256 digest".to_owned(),
            });
        }
        self.connection.validate_at(&self.secret, at)?;
        self.refresh_live_probe(at)?;
        self.state.store_payload(effect_digest.to_owned(), payload);
        self.worker.set_now(at);
        let observation = self
            .worker
            .verify(VerifyRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.connection.scope()?,
                live_probe: self.live_probe.clone(),
                capability: ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, "publication.publish")?,
                subject_digest: effect_digest.to_owned(),
                at,
            })
            .map_err(|error| provider_error_from_state(&self.state, &error))?;
        let readback =
            self.state
                .readback(effect_digest)
                .ok_or_else(|| WebPublicationError::Provider {
                    detail: "GitHub verification returned no independent readback".to_owned(),
                })?;
        Ok(GithubPagesVerification {
            observation,
            readback,
        })
    }

    pub fn registry_digest(&self) -> String {
        digest_parts([
            self.connection.registry_version.as_str(),
            self.connection.adapter.adapter_id(),
            &self.connection.adapter.adapter_version().to_string(),
            self.connection.registration_digest.as_str(),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct GithubPagesProviderRead {
    pub snapshot: GithubPagesRepositorySnapshot,
    pub observation: ReadObservation,
    pub registration_digest: String,
    pub registry_version: String,
}

fn registry() -> Result<ProviderAdapterRegistry, WebPublicationError> {
    let identity =
        ProviderAdapterIdentity::new(GITHUB_PAGES_ADAPTER_ID, GITHUB_PAGES_ADAPTER_VERSION)?;
    let registrations = registrations(&identity)?;
    Ok(ProviderAdapterRegistry::new(
        GITHUB_PAGES_REGISTRY_VERSION,
        registrations,
    )?)
}

fn descriptor() -> Result<ConnectorDescriptor, WebPublicationError> {
    let identity =
        ProviderAdapterIdentity::new(GITHUB_PAGES_ADAPTER_ID, GITHUB_PAGES_ADAPTER_VERSION)?;
    Ok(ConnectorDescriptor::new(
        identity.clone(),
        registrations(&identity)?,
    )?)
}

fn registrations(
    identity: &ProviderAdapterIdentity,
) -> Result<Vec<ProviderCapabilitySupport>, WebPublicationError> {
    ["connection.probe", "site.read", "publication.publish"]
        .into_iter()
        .map(|capability| {
            let key = ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, capability)?;
            let operations = match capability {
                "connection.probe" => vec![(
                    ProviderAdapterOperation::Probe,
                    ProviderEvidenceClass::ProbeObservation,
                )],
                "site.read" => vec![(
                    ProviderAdapterOperation::Read,
                    ProviderEvidenceClass::ReadObservation,
                )],
                "publication.publish" => vec![
                    (
                        ProviderAdapterOperation::PrepareEffect,
                        ProviderEvidenceClass::PreparedEffect,
                    ),
                    (
                        ProviderAdapterOperation::Execute,
                        ProviderEvidenceClass::ReceiptCandidate,
                    ),
                    (
                        ProviderAdapterOperation::Reconcile,
                        ProviderEvidenceClass::ReconciliationObservation,
                    ),
                    (
                        ProviderAdapterOperation::Verify,
                        ProviderEvidenceClass::VerificationObservation,
                    ),
                ],
                _ => unreachable!("all GitHub Pages capabilities are listed above"),
            };
            let evidence = operations
                .into_iter()
                .map(|(operation, evidence_class)| {
                    ProviderEvidenceSupport::new(
                        operation,
                        evidence_class,
                        ProviderProvenanceClass::ProductionProvider,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ProviderCapabilitySupport::new(
                key,
                identity.clone(),
                evidence,
            )?)
        })
        .collect()
}

fn required_scopes() -> BTreeSet<String> {
    GITHUB_PAGES_REQUIRED_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect()
}

fn provider_error_from_state(state: &AdapterState, error: &ConnectorError) -> WebPublicationError {
    state
        .take_failure()
        .map_or_else(|| map_provider_connector_error(error), Into::into)
}

fn map_transport_error(error: GithubPagesTransportError) -> GithubPagesProviderError {
    match error {
        GithubPagesTransportError::RateLimited { status } => {
            GithubPagesProviderError::RateLimited {
                detail: format!("GitHub API HTTP status {status}"),
            }
        }
        GithubPagesTransportError::Rejected { status } if status == 401 || status == 403 => {
            GithubPagesProviderError::Unauthorized {
                detail: format!("GitHub API HTTP status {status}"),
            }
        }
        GithubPagesTransportError::Rejected { status } => GithubPagesProviderError::Rejected {
            detail: format!("GitHub API HTTP status {status}"),
        },
        GithubPagesTransportError::Uncertain { status } => GithubPagesProviderError::Uncertain {
            detail: format!("GitHub API HTTP status {status}"),
        },
        GithubPagesTransportError::Transport { detail } => {
            GithubPagesProviderError::Transport { detail }
        }
        GithubPagesTransportError::Decode { detail } => GithubPagesProviderError::Decode { detail },
    }
}

fn provider_invalid(error: &WebPublicationError) -> GithubPagesProviderError {
    GithubPagesProviderError::InvalidConfiguration {
        detail: error.to_string(),
    }
}

fn invalid_response(detail: &str) -> GithubPagesProviderError {
    GithubPagesProviderError::Rejected {
        detail: detail.to_owned(),
    }
}

fn valid_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
