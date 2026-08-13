//! GitHub repository/Pages publication adapter.
//!
//! This module is deliberately provider-specific. It does not register a
//! generic Connector SDK operation: the existing Effect Broker remains the
//! only execution authority, while this adapter supplies the GitHub repository
//! mutation, read-only reconciliation, and independent Pages readback.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AccountId, Effect, EffectClass, EffectId, PublicationEnvironment, PublicationPublishRequest,
    Receipt, ReceiptId, Verification, VerificationId, VerificationStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    EffectExecutor, EffectReconciler, EffectVerifier, ProviderFailure, ReconciliationObservation,
};

pub const GITHUB_PAGES_PROVIDER: &str = "github";
pub const GITHUB_PAGES_MANIFEST_PATH: &str = "hartevo-publication.json";
pub const GITHUB_PAGES_ADAPTER_SCHEMA_VERSION: &str = "hartevo-github-pages/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPagesEnvironmentTarget {
    pub owner: String,
    pub repository: String,
    pub branch: String,
    pub pages_url: String,
}

impl GithubPagesEnvironmentTarget {
    pub fn new(
        owner: impl Into<String>,
        repository: impl Into<String>,
        branch: impl Into<String>,
        pages_url: impl Into<String>,
    ) -> Result<Self, GithubPagesError> {
        let target = Self {
            owner: owner.into(),
            repository: repository.into(),
            branch: branch.into(),
            pages_url: pages_url.into(),
        };
        target.validate()?;
        Ok(target)
    }

    pub fn validate(&self) -> Result<(), GithubPagesError> {
        validate_path_component(&self.owner, "GitHub owner")?;
        validate_path_component(&self.repository, "GitHub repository")?;
        validate_path_component(&self.branch, "GitHub branch")?;
        if self.branch.is_empty() || self.branch.contains("..") {
            return Err(GithubPagesError::InvalidTarget("GitHub branch"));
        }
        let parsed = Url::parse(&self.pages_url)
            .map_err(|_| GithubPagesError::InvalidTarget("GitHub Pages URL"))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(GithubPagesError::InvalidTarget("GitHub Pages URL"));
        }
        Ok(())
    }

    pub fn resource_id(&self) -> String {
        format!("{}/{}", self.owner, self.repository)
    }

    pub fn identity(&self) -> String {
        format!("{}/{}@{}", self.owner, self.repository, self.branch)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPagesTargets {
    pub staging: GithubPagesEnvironmentTarget,
    pub production: GithubPagesEnvironmentTarget,
}

impl GithubPagesTargets {
    pub fn new(
        staging: GithubPagesEnvironmentTarget,
        production: GithubPagesEnvironmentTarget,
    ) -> Result<Self, GithubPagesError> {
        let targets = Self {
            staging,
            production,
        };
        targets.validate()?;
        Ok(targets)
    }

    pub fn validate(&self) -> Result<(), GithubPagesError> {
        self.staging.validate()?;
        self.production.validate()?;
        if self.staging.identity() == self.production.identity()
            || self.staging.pages_url == self.production.pages_url
        {
            return Err(GithubPagesError::EnvironmentFence);
        }
        Ok(())
    }

    pub fn target(
        &self,
        environment: PublicationEnvironment,
        account_id: impl Into<String>,
        configuration_digest: impl Into<String>,
    ) -> hartevo_domain_kernel::PublicationTarget {
        let selected = match environment {
            PublicationEnvironment::Staging => &self.staging,
            PublicationEnvironment::Production => &self.production,
        };
        hartevo_domain_kernel::PublicationTarget {
            provider: GITHUB_PAGES_PROVIDER.into(),
            account_id: account_id.into(),
            resource_id: selected.resource_id(),
            branch: selected.branch.clone(),
            url: selected.pages_url.clone(),
            environment,
            configuration_digest: configuration_digest.into(),
        }
    }

    pub fn selected(&self, environment: PublicationEnvironment) -> &GithubPagesEnvironmentTarget {
        match environment {
            PublicationEnvironment::Staging => &self.staging,
            PublicationEnvironment::Production => &self.production,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPagesPublicationManifest {
    pub schema_version: String,
    pub effect_id: String,
    pub payload_digest: String,
    pub approval_digest: String,
    pub content_digest: String,
    pub environment: PublicationEnvironment,
    pub resource_id: String,
    pub branch: String,
    /// The in-memory transport can include the commit it created. The real
    /// GitHub API writes this as `null` because the manifest is part of the
    /// tree that is committed; readback derives the authoritative SHA from
    /// the branch head instead of publishing a placeholder or stale value.
    pub commit_sha: Option<String>,
    pub published_at: DateTime<Utc>,
}

impl GithubPagesPublicationManifest {
    fn matches(
        &self,
        effect: &Effect,
        request: &PublicationPublishRequest,
        approval_digest: &str,
    ) -> bool {
        self.schema_version == GITHUB_PAGES_ADAPTER_SCHEMA_VERSION
            && self.effect_id == effect.id.as_str()
            && self.payload_digest == request.payload_digest
            && self.approval_digest == approval_digest
            && self.content_digest == request.content_digest
            && self.environment == request.environment
            && self.resource_id == request.target.resource_id
            && self.branch == request.target.branch
    }

    fn matches_readback(
        &self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
    ) -> bool {
        self.schema_version == GITHUB_PAGES_ADAPTER_SCHEMA_VERSION
            && self.payload_digest == request.payload_digest
            && self.content_digest == request.content_digest
            && self.environment == request.environment
            && self.resource_id == request.target.resource_id
            && self.branch == target.branch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubPagesRepositorySnapshot {
    pub head_sha: String,
    pub tree_sha: String,
    pub pages_config_digest: String,
    pub pages_url: String,
    pub branch: String,
    pub files: BTreeMap<String, String>,
    pub publication_manifest: Option<GithubPagesPublicationManifest>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubPagesProviderReceipt {
    pub commit_sha: String,
    pub response_digest: String,
    pub publication_manifest_digest: String,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubPagesReconciliation {
    pub snapshot: GithubPagesRepositorySnapshot,
    pub receipt: Option<GithubPagesProviderReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubPagesReadbackObservation {
    pub root_http_status: u16,
    pub manifest_http_status: u16,
    pub dns_resolved: bool,
    pub content_digest: Option<String>,
    pub publication_digest: Option<String>,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

pub trait GithubPagesRepositoryTransport {
    fn read(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
    ) -> Result<GithubPagesRepositorySnapshot, GithubPagesError>;

    fn publish(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
        effect: &Effect,
        approval_digest: &str,
    ) -> Result<GithubPagesProviderReceipt, GithubPagesError>;

    fn reconcile(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
        effect: &Effect,
        approval_digest: &str,
    ) -> Result<GithubPagesReconciliation, GithubPagesError>;
}

pub trait GithubPagesReadbackTransport {
    fn readback(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
    ) -> Result<GithubPagesReadbackObservation, GithubPagesError>;
}

#[derive(Clone, Debug)]
struct RegisteredPublication {
    target: GithubPagesEnvironmentTarget,
    request: PublicationPublishRequest,
}

#[derive(Debug)]
pub struct GithubPagesExecutor<T> {
    targets: GithubPagesTargets,
    transport: T,
    registrations: BTreeMap<EffectId, RegisteredPublication>,
}

impl<T> GithubPagesExecutor<T> {
    pub fn new(targets: GithubPagesTargets, transport: T) -> Result<Self, GithubPagesError> {
        targets.validate()?;
        Ok(Self {
            targets,
            transport,
            registrations: BTreeMap::new(),
        })
    }

    pub fn register(
        &mut self,
        effect_id: EffectId,
        request: PublicationPublishRequest,
    ) -> Result<(), GithubPagesError> {
        request
            .validate()
            .map_err(|error| GithubPagesError::InvalidRequest(error.to_string()))?;
        let target = self.targets.selected(request.environment).clone();
        validate_request_target(&target, &request)?;
        self.registrations
            .insert(effect_id, RegisteredPublication { target, request });
        Ok(())
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T: GithubPagesRepositoryTransport> GithubPagesExecutor<T> {
    pub fn read_snapshot(
        &mut self,
        environment: PublicationEnvironment,
    ) -> Result<GithubPagesRepositorySnapshot, GithubPagesError> {
        let target = self.targets.selected(environment).clone();
        self.transport.read(&target)
    }
}

impl<T: GithubPagesRepositoryTransport> EffectExecutor for GithubPagesExecutor<T> {
    fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure> {
        let registration = self.registrations.get(&effect.id).cloned().ok_or_else(|| {
            ProviderFailure::Rejected("GitHub publication request is not registered".into())
        })?;
        if let Err(error) = validate_effect_request(effect, &registration.request) {
            return Err(ProviderFailure::Rejected(error.to_string()));
        }
        let approval_digest = effect.approval_digest();
        let receipt = self
            .transport
            .publish(
                &registration.target,
                &registration.request,
                effect,
                &approval_digest,
            )
            .map_err(provider_failure)?;
        Ok(Receipt {
            id: ReceiptId::from_stable(format!("github-pages-receipt-{}", effect.id)),
            provider: GITHUB_PAGES_PROVIDER.into(),
            external_id: receipt.commit_sha,
            accepted_at: receipt.accepted_at,
            request_digest: approval_digest,
            response_digest: receipt.response_digest,
        })
    }
}

#[derive(Debug)]
pub struct GithubPagesVerifier<T> {
    targets: GithubPagesTargets,
    transport: T,
    registrations: BTreeMap<EffectId, RegisteredPublication>,
}

impl<T> GithubPagesVerifier<T> {
    pub fn new(targets: GithubPagesTargets, transport: T) -> Result<Self, GithubPagesError> {
        targets.validate()?;
        Ok(Self {
            targets,
            transport,
            registrations: BTreeMap::new(),
        })
    }

    pub fn register(
        &mut self,
        effect_id: EffectId,
        request: PublicationPublishRequest,
    ) -> Result<(), GithubPagesError> {
        request
            .validate()
            .map_err(|error| GithubPagesError::InvalidRequest(error.to_string()))?;
        let target = self.targets.selected(request.environment).clone();
        validate_request_target(&target, &request)?;
        self.registrations
            .insert(effect_id, RegisteredPublication { target, request });
        Ok(())
    }
}

impl<T: GithubPagesReadbackTransport> EffectVerifier for GithubPagesVerifier<T> {
    fn verify(&mut self, effect: &Effect, receipt: &Receipt) -> Verification {
        let now = Utc::now();
        let verification_id =
            VerificationId::from_stable(format!("github-pages-verify-{}", effect.id));
        let Some(registration) = self.registrations.get(&effect.id).cloned() else {
            return inconclusive_verification(
                verification_id,
                "GitHub publication request is not registered",
                receipt.id.clone(),
                now,
            );
        };
        if validate_effect_request(effect, &registration.request).is_err()
            || receipt.provider != GITHUB_PAGES_PROVIDER
            || receipt.request_digest != effect.approval_digest()
        {
            return rejected_verification(
                verification_id,
                "GitHub receipt is outside the publication fence",
                receipt.id.clone(),
                now,
            );
        }
        match self
            .transport
            .readback(&registration.target, &registration.request)
        {
            Ok(observation)
                if observation.root_http_status == 200
                    && observation.manifest_http_status == 200
                    && observation.dns_resolved
                    && observation.content_digest.as_deref()
                        == Some(registration.request.content_digest.as_str())
                    && observation.publication_digest.as_deref()
                        == Some(registration.request.payload_digest.as_str()) =>
            {
                Verification {
                    id: verification_id,
                    status: VerificationStatus::Confirmed,
                    verifier: "github-pages-independent-readback-v1".into(),
                    independent: true,
                    observed_at: observation.observed_at,
                    evidence_digest: observation.evidence_digest,
                    receipt_id: receipt.id.clone(),
                }
            }
            Ok(observation) => Verification {
                id: verification_id,
                status: VerificationStatus::Rejected,
                verifier: "github-pages-independent-readback-v1".into(),
                independent: true,
                observed_at: observation.observed_at,
                evidence_digest: observation.evidence_digest,
                receipt_id: receipt.id.clone(),
            },
            Err(error) => inconclusive_verification(
                verification_id,
                &error.to_string(),
                receipt.id.clone(),
                now,
            ),
        }
    }
}

#[derive(Debug)]
pub struct GithubPagesReconciler<T> {
    targets: GithubPagesTargets,
    transport: T,
    registrations: BTreeMap<EffectId, RegisteredPublication>,
}

impl<T> GithubPagesReconciler<T> {
    pub fn new(targets: GithubPagesTargets, transport: T) -> Result<Self, GithubPagesError> {
        targets.validate()?;
        Ok(Self {
            targets,
            transport,
            registrations: BTreeMap::new(),
        })
    }

    pub fn register(
        &mut self,
        effect_id: EffectId,
        request: PublicationPublishRequest,
    ) -> Result<(), GithubPagesError> {
        request
            .validate()
            .map_err(|error| GithubPagesError::InvalidRequest(error.to_string()))?;
        let target = self.targets.selected(request.environment).clone();
        validate_request_target(&target, &request)?;
        self.registrations
            .insert(effect_id, RegisteredPublication { target, request });
        Ok(())
    }
}

impl<T: GithubPagesRepositoryTransport> EffectReconciler for GithubPagesReconciler<T> {
    fn reconcile(&mut self, effect: &Effect) -> ReconciliationObservation {
        let now = Utc::now();
        let Some(registration) = self.registrations.get(&effect.id).cloned() else {
            return ReconciliationObservation::StillUncertain {
                reason: "GitHub publication request is not registered".into(),
                evidence_digest: sha256("github-pages-registration-missing"),
                observed_at: now,
            };
        };
        if let Err(error) = validate_effect_request(effect, &registration.request) {
            return ReconciliationObservation::ProviderRejected {
                reason: error.to_string(),
                evidence_digest: sha256(error.to_string()),
                observed_at: now,
            };
        }
        let approval_digest = effect.approval_digest();
        match self.transport.reconcile(
            &registration.target,
            &registration.request,
            effect,
            &approval_digest,
        ) {
            Ok(reconciliation) => {
                let evidence_digest = sha256(format!(
                    "{}|{}|{}",
                    reconciliation.snapshot.head_sha,
                    reconciliation.snapshot.pages_config_digest,
                    reconciliation.snapshot.observed_at.to_rfc3339()
                ));
                if let Some(receipt) = reconciliation.receipt {
                    ReconciliationObservation::ReceiptFound {
                        receipt: Receipt {
                            id: ReceiptId::from_stable(format!(
                                "github-pages-receipt-{}",
                                effect.id
                            )),
                            provider: GITHUB_PAGES_PROVIDER.into(),
                            external_id: receipt.commit_sha,
                            accepted_at: receipt.accepted_at,
                            request_digest: approval_digest,
                            response_digest: receipt.response_digest,
                        },
                        evidence_digest,
                        observed_at: now.max(reconciliation.snapshot.observed_at),
                    }
                } else {
                    ReconciliationObservation::NotExecuted {
                        evidence_digest,
                        observed_at: now.max(reconciliation.snapshot.observed_at),
                    }
                }
            }
            Err(GithubPagesError::Uncertain(reason)) => ReconciliationObservation::StillUncertain {
                reason,
                evidence_digest: sha256("github-pages-reconcile-uncertain"),
                observed_at: now,
            },
            Err(error) => ReconciliationObservation::ProviderRejected {
                reason: error.to_string(),
                evidence_digest: sha256(error.to_string()),
                observed_at: now,
            },
        }
    }
}

fn validate_request_target(
    target: &GithubPagesEnvironmentTarget,
    request: &PublicationPublishRequest,
) -> Result<(), GithubPagesError> {
    if request.target.provider != GITHUB_PAGES_PROVIDER
        || request.target.resource_id != target.resource_id()
        || request.target.branch != target.branch
        || request.target.url != target.pages_url
    {
        return Err(GithubPagesError::EnvironmentFence);
    }
    Ok(())
}

fn validate_effect_request(
    effect: &Effect,
    request: &PublicationPublishRequest,
) -> Result<(), GithubPagesError> {
    let target_prefix = format!(
        "{}/site/{}/publication/",
        request.target.resource_id, request.site_id
    );
    let target_suffix = format!("/{}", request.environment.as_str());
    if effect.provider != GITHUB_PAGES_PROVIDER
        || effect.capability != "publication.publish"
        || effect.effect_class != EffectClass::ExternalWrite
        || effect.account_id.as_ref().map(AccountId::as_str)
            != Some(request.target.account_id.as_str())
        || effect.payload_digest != request.payload_digest
        || effect.idempotency_key != request.idempotency_key
        || !effect.target_resource.starts_with(&target_prefix)
        || !effect.target_resource.ends_with(&target_suffix)
        || effect
            .approval
            .as_ref()
            .is_none_or(|approval| approval.scope_digest != effect.approval_digest())
    {
        return Err(GithubPagesError::EffectFence);
    }
    Ok(())
}

fn provider_failure(error: GithubPagesError) -> ProviderFailure {
    match error {
        GithubPagesError::Uncertain(reason) => ProviderFailure::Uncertain(reason),
        error => ProviderFailure::Rejected(error.to_string()),
    }
}

fn rejected_verification(
    id: VerificationId,
    reason: &str,
    receipt_id: ReceiptId,
    now: DateTime<Utc>,
) -> Verification {
    Verification {
        id,
        status: VerificationStatus::Rejected,
        verifier: "github-pages-independent-readback-v1".into(),
        independent: true,
        observed_at: now,
        evidence_digest: sha256(reason),
        receipt_id,
    }
}

fn inconclusive_verification(
    id: VerificationId,
    reason: &str,
    receipt_id: ReceiptId,
    now: DateTime<Utc>,
) -> Verification {
    Verification {
        id,
        status: VerificationStatus::Inconclusive,
        verifier: "github-pages-independent-readback-v1".into(),
        independent: true,
        observed_at: now,
        evidence_digest: sha256(reason),
        receipt_id,
    }
}

fn validate_path_component(value: &str, field: &'static str) -> Result<(), GithubPagesError> {
    if value.trim().is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains(char::is_whitespace)
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(GithubPagesError::InvalidTarget(field));
    }
    Ok(())
}

fn sha256(value: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(value.as_ref());
    digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        })
}

/// Matches the Domain Kernel's canonical SiteFile content digest. The
/// provider readback recomputes this from the bytes served by Pages instead
/// of trusting the provider-owned manifest's claimed content digest.
fn publication_content_digest<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut bytes = Vec::new();
    for (path, content) in files {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(content.as_bytes());
        bytes.push(0);
    }
    sha256(bytes)
}

#[derive(Clone, Debug)]
struct InMemoryGithubPagesState {
    snapshot: GithubPagesRepositorySnapshot,
    mutation_count: u64,
}

/// Deterministic provider double for the native adapter contract. It models
/// the repository and Pages authorities separately from the Effect Broker and
/// deliberately makes an exact replay a read-only operation.
#[derive(Clone, Debug, Default)]
pub struct InMemoryGithubPagesTransport {
    states: Arc<Mutex<BTreeMap<String, InMemoryGithubPagesState>>>,
}

impl InMemoryGithubPagesTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(
        &self,
        target: &GithubPagesEnvironmentTarget,
        pages_config_digest: impl Into<String>,
        head_sha: impl Into<String>,
        files: BTreeMap<String, String>,
    ) -> Result<(), GithubPagesError> {
        target.validate()?;
        let head_sha = head_sha.into();
        let snapshot = GithubPagesRepositorySnapshot {
            head_sha: head_sha.clone(),
            tree_sha: sha256(format!("tree:{head_sha}")),
            pages_config_digest: pages_config_digest.into(),
            pages_url: target.pages_url.clone(),
            branch: target.branch.clone(),
            files,
            publication_manifest: None,
            observed_at: Utc::now(),
        };
        self.states
            .lock()
            .map_err(|_| GithubPagesError::StateLock)?
            .insert(
                target.identity(),
                InMemoryGithubPagesState {
                    snapshot,
                    mutation_count: 0,
                },
            );
        Ok(())
    }

    pub fn mutation_count(
        &self,
        target: &GithubPagesEnvironmentTarget,
    ) -> Result<u64, GithubPagesError> {
        self.states
            .lock()
            .map_err(|_| GithubPagesError::StateLock)?
            .get(&target.identity())
            .map_or(Ok(0), |state| Ok(state.mutation_count))
    }

    fn snapshot(
        &self,
        target: &GithubPagesEnvironmentTarget,
    ) -> Result<GithubPagesRepositorySnapshot, GithubPagesError> {
        self.states
            .lock()
            .map_err(|_| GithubPagesError::StateLock)?
            .get(&target.identity())
            .map(|state| state.snapshot.clone())
            .ok_or_else(|| GithubPagesError::Rejected("GitHub repository is not seeded".into()))
    }
}

impl GithubPagesRepositoryTransport for InMemoryGithubPagesTransport {
    fn read(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
    ) -> Result<GithubPagesRepositorySnapshot, GithubPagesError> {
        self.snapshot(target)
    }

    fn publish(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
        effect: &Effect,
        approval_digest: &str,
    ) -> Result<GithubPagesProviderReceipt, GithubPagesError> {
        if request
            .files
            .iter()
            .any(|file| file.path == GITHUB_PAGES_MANIFEST_PATH)
        {
            return Err(GithubPagesError::Rejected(
                "the provider-owned publication manifest path is reserved".into(),
            ));
        }
        let mut states = self
            .states
            .lock()
            .map_err(|_| GithubPagesError::StateLock)?;
        let state = states
            .get_mut(&target.identity())
            .ok_or_else(|| GithubPagesError::Rejected("GitHub repository is not seeded".into()))?;
        if request.target.configuration_digest != state.snapshot.pages_config_digest {
            return Err(GithubPagesError::EnvironmentFence);
        }
        if let Some(manifest) = &state.snapshot.publication_manifest
            && manifest.matches(effect, request, approval_digest)
        {
            return provider_receipt_from_manifest(manifest);
        }
        if sha256(&state.snapshot.head_sha) != request.canonical_diff.base_authority_digest {
            return Err(GithubPagesError::Rejected(
                "GitHub branch head changed after the canonical proposal".into(),
            ));
        }
        let files = request
            .files
            .iter()
            .map(|file| (file.path.clone(), file.content.clone()))
            .collect::<BTreeMap<_, _>>();
        let commit_sha = sha256(format!(
            "{}|{}|{}|{}",
            state.snapshot.head_sha, request.payload_digest, approval_digest, effect.id
        ));
        let manifest = GithubPagesPublicationManifest {
            schema_version: GITHUB_PAGES_ADAPTER_SCHEMA_VERSION.into(),
            effect_id: effect.id.as_str().into(),
            payload_digest: request.payload_digest.clone(),
            approval_digest: approval_digest.into(),
            content_digest: request.content_digest.clone(),
            environment: request.environment,
            resource_id: request.target.resource_id.clone(),
            branch: request.target.branch.clone(),
            commit_sha: Some(commit_sha.clone()),
            published_at: Utc::now(),
        };
        let manifest_json =
            serde_json::to_string(&manifest).map_err(|_| GithubPagesError::Decode)?;
        let response_digest = sha256(format!("{commit_sha}|{manifest_json}"));
        let publication_manifest_digest = sha256(manifest_json.as_bytes());
        let accepted_at = manifest.published_at;
        state.snapshot = GithubPagesRepositorySnapshot {
            head_sha: commit_sha.clone(),
            tree_sha: sha256(format!("tree:{commit_sha}")),
            pages_config_digest: state.snapshot.pages_config_digest.clone(),
            pages_url: target.pages_url.clone(),
            branch: target.branch.clone(),
            files: {
                let mut files = files;
                files.insert(GITHUB_PAGES_MANIFEST_PATH.into(), manifest_json);
                files
            },
            publication_manifest: Some(manifest),
            observed_at: accepted_at,
        };
        state.mutation_count = state.mutation_count.saturating_add(1);
        Ok(GithubPagesProviderReceipt {
            commit_sha,
            response_digest,
            publication_manifest_digest,
            accepted_at,
        })
    }

    fn reconcile(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
        effect: &Effect,
        approval_digest: &str,
    ) -> Result<GithubPagesReconciliation, GithubPagesError> {
        let snapshot = self.snapshot(target)?;
        let receipt = snapshot
            .publication_manifest
            .as_ref()
            .filter(|manifest| manifest.matches(effect, request, approval_digest))
            .map(provider_receipt_from_manifest)
            .transpose()?;
        Ok(GithubPagesReconciliation { snapshot, receipt })
    }
}

impl GithubPagesReadbackTransport for InMemoryGithubPagesTransport {
    fn readback(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
    ) -> Result<GithubPagesReadbackObservation, GithubPagesError> {
        let snapshot = self.snapshot(target)?;
        let manifest = snapshot
            .publication_manifest
            .as_ref()
            .ok_or_else(|| GithubPagesError::Readback("publication manifest is absent".into()))?;
        if !manifest.matches_readback(target, request) {
            return Err(GithubPagesError::Readback(
                "publication manifest is outside the requested fence".into(),
            ));
        }
        let root_http_status = u16::from(snapshot.files.contains_key("index.html")) * 200;
        let manifest_http_status =
            u16::from(snapshot.files.contains_key(GITHUB_PAGES_MANIFEST_PATH)) * 200;
        let dns_resolved = true;
        let observed_files = request
            .files
            .iter()
            .map(|file| {
                snapshot
                    .files
                    .get(&file.path)
                    .map(|content| (file.path.as_str(), content.as_str()))
                    .ok_or_else(|| {
                        GithubPagesError::Readback(format!(
                            "published file {} is absent from the repository snapshot",
                            file.path
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let content_digest = publication_content_digest(observed_files);
        let evidence_digest = sha256(format!(
            "{}|{}|{}|{}|{}|{}",
            root_http_status,
            manifest_http_status,
            dns_resolved,
            content_digest,
            manifest.payload_digest,
            manifest.content_digest
        ));
        Ok(GithubPagesReadbackObservation {
            root_http_status,
            manifest_http_status,
            dns_resolved,
            content_digest: Some(content_digest),
            publication_digest: Some(manifest.payload_digest.clone()),
            evidence_digest,
            observed_at: snapshot.observed_at,
        })
    }
}

fn provider_receipt_from_manifest(
    manifest: &GithubPagesPublicationManifest,
) -> Result<GithubPagesProviderReceipt, GithubPagesError> {
    let commit_sha = manifest
        .commit_sha
        .as_deref()
        .ok_or(GithubPagesError::InvalidResponse)?;
    provider_receipt_from_manifest_at(manifest, commit_sha)
}

fn provider_receipt_from_manifest_at(
    manifest: &GithubPagesPublicationManifest,
    commit_sha: &str,
) -> Result<GithubPagesProviderReceipt, GithubPagesError> {
    let manifest_json = serde_json::to_string(manifest).map_err(|_| GithubPagesError::Decode)?;
    Ok(GithubPagesProviderReceipt {
        commit_sha: commit_sha.into(),
        response_digest: sha256(format!("{commit_sha}|{manifest_json}")),
        publication_manifest_digest: sha256(manifest_json.as_bytes()),
        accepted_at: manifest.published_at,
    })
}

/// A credential holder for the GitHub API. The token never implements
/// serialization and its `Debug` output is intentionally redacted.
#[derive(Clone)]
pub struct GithubAccessToken(Zeroizing<String>);

impl GithubAccessToken {
    pub fn new(token: impl Into<String>) -> Result<Self, GithubPagesError> {
        let token = token.into();
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(GithubPagesError::InvalidTarget("GitHub access token"));
        }
        Ok(Self(Zeroizing::new(token)))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for GithubAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubAccessToken(REDACTED)")
    }
}

#[derive(Clone)]
pub struct GithubPagesApi {
    api_base: String,
    token: GithubAccessToken,
    agent: ureq::Agent,
}

impl fmt::Debug for GithubPagesApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPagesApi")
            .field("api_base", &self.api_base)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

impl GithubPagesApi {
    pub fn new(
        api_base: impl Into<String>,
        token: GithubAccessToken,
    ) -> Result<Self, GithubPagesError> {
        let api_base = api_base.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&api_base)
            .map_err(|_| GithubPagesError::InvalidTarget("GitHub API base URL"))?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(GithubPagesError::InvalidTarget("GitHub API base URL"));
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-github-pages/1")
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            api_base,
            token,
            agent,
        })
    }

    fn repository_base(&self, target: &GithubPagesEnvironmentTarget) -> String {
        format!(
            "{}/repos/{}/{}",
            self.api_base, target.owner, target.repository
        )
    }

    fn authorization<S>(&self, request: ureq::RequestBuilder<S>) -> ureq::RequestBuilder<S> {
        request
            .header("Authorization", format!("Bearer {}", self.token.as_str()))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, GithubPagesError> {
        let mut response = self
            .authorization(self.agent.get(url))
            .call()
            .map_err(classify_http_error)?;
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error| GithubPagesError::Http(error.to_string()))?;
        serde_json::from_str(&body).map_err(|_| GithubPagesError::Decode)
    }

    fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<T, GithubPagesError> {
        let mut response = self
            .authorization(self.agent.post(url))
            .send_json(payload)
            .map_err(classify_http_error)?;
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error| GithubPagesError::Http(error.to_string()))?;
        serde_json::from_str(&body).map_err(|_| GithubPagesError::Decode)
    }

    fn patch_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<T, GithubPagesError> {
        let mut response = self
            .authorization(self.agent.patch(url))
            .send_json(payload)
            .map_err(classify_http_error)?;
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error| GithubPagesError::Http(error.to_string()))?;
        serde_json::from_str(&body).map_err(|_| GithubPagesError::Decode)
    }

    fn get_blob(&self, url: &str) -> Result<String, GithubPagesError> {
        let response: GithubBlobResponse = self.get_json(url)?;
        if response.encoding != "base64" {
            return Err(GithubPagesError::Encoding);
        }
        let encoded = response.content.lines().collect::<String>();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| GithubPagesError::Encoding)?;
        String::from_utf8(bytes).map_err(|_| GithubPagesError::InvalidResponse)
    }
}

impl GithubPagesRepositoryTransport for GithubPagesApi {
    fn read(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
    ) -> Result<GithubPagesRepositorySnapshot, GithubPagesError> {
        target.validate()?;
        let repository_base = self.repository_base(target);
        let pages: GithubPagesResponse = self.get_json(&format!("{repository_base}/pages"))?;
        let pages_url = pages
            .html_url
            .clone()
            .ok_or(GithubPagesError::InvalidResponse)?;
        let pages_branch = pages
            .source
            .as_ref()
            .and_then(|source| source.branch.clone())
            .ok_or(GithubPagesError::InvalidResponse)?;
        if pages_branch != target.branch || pages_url != target.pages_url {
            return Err(GithubPagesError::EnvironmentFence);
        }
        let pages_config_digest =
            sha256(serde_json::to_vec(&pages).map_err(|_| GithubPagesError::InvalidResponse)?);
        let reference: GithubReferenceResponse = self.get_json(&format!(
            "{repository_base}/git/ref/heads/{}",
            target.branch
        ))?;
        let head_sha = reference.object.sha;
        let commit: GithubCommitResponse =
            self.get_json(&format!("{repository_base}/git/commits/{head_sha}"))?;
        let tree: GithubTreeResponse = self.get_json(&format!(
            "{repository_base}/git/trees/{}?recursive=1",
            commit.tree.sha
        ))?;
        let mut files = BTreeMap::new();
        for entry in tree.tree {
            if entry.entry_type == "blob" {
                let path = entry.path;
                let content =
                    self.get_blob(&format!("{repository_base}/git/blobs/{}", entry.sha))?;
                files.insert(path, content);
            }
        }
        let publication_manifest = files
            .get(GITHUB_PAGES_MANIFEST_PATH)
            .map(|content| {
                serde_json::from_str(content).map_err(|_| GithubPagesError::InvalidResponse)
            })
            .transpose()?;
        Ok(GithubPagesRepositorySnapshot {
            head_sha,
            tree_sha: commit.tree.sha,
            pages_config_digest,
            pages_url,
            branch: pages_branch,
            files,
            publication_manifest,
            observed_at: Utc::now(),
        })
    }

    fn publish(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
        effect: &Effect,
        approval_digest: &str,
    ) -> Result<GithubPagesProviderReceipt, GithubPagesError> {
        validate_request_target(target, request)?;
        if request
            .files
            .iter()
            .any(|file| file.path == GITHUB_PAGES_MANIFEST_PATH)
        {
            return Err(GithubPagesError::Rejected(
                "the provider-owned publication manifest path is reserved".into(),
            ));
        }
        let current = self.read(target)?;
        if request.target.configuration_digest != current.pages_config_digest {
            return Err(GithubPagesError::EnvironmentFence);
        }
        if let Some(manifest) = &current.publication_manifest
            && manifest.matches(effect, request, approval_digest)
        {
            return provider_receipt_from_manifest_at(manifest, &current.head_sha);
        }
        if sha256(&current.head_sha) != request.canonical_diff.base_authority_digest {
            return Err(GithubPagesError::Rejected(
                "GitHub branch head changed after the canonical proposal".into(),
            ));
        }
        let mut desired = current.files.clone();
        desired.remove(GITHUB_PAGES_MANIFEST_PATH);
        for entry in &request.canonical_diff.entries {
            match entry.kind {
                hartevo_domain_kernel::CanonicalDiffEntryKind::Deleted => {
                    desired.remove(&entry.path);
                }
                hartevo_domain_kernel::CanonicalDiffEntryKind::Added
                | hartevo_domain_kernel::CanonicalDiffEntryKind::Modified => {
                    let file = request
                        .files
                        .iter()
                        .find(|file| file.path == entry.path)
                        .ok_or(GithubPagesError::InvalidResponse)?;
                    desired.insert(entry.path.clone(), file.content.clone());
                }
            }
        }
        let published_at = Utc::now();
        let manifest = GithubPagesPublicationManifest {
            schema_version: GITHUB_PAGES_ADAPTER_SCHEMA_VERSION.into(),
            effect_id: effect.id.as_str().into(),
            payload_digest: request.payload_digest.clone(),
            approval_digest: approval_digest.into(),
            content_digest: request.content_digest.clone(),
            environment: request.environment,
            resource_id: request.target.resource_id.clone(),
            branch: request.target.branch.clone(),
            commit_sha: None,
            published_at,
        };
        let manifest_json =
            serde_json::to_string(&manifest).map_err(|_| GithubPagesError::Decode)?;
        desired.insert(GITHUB_PAGES_MANIFEST_PATH.into(), manifest_json);
        let repository_base = self.repository_base(target);
        let mut tree_entries = Vec::with_capacity(desired.len());
        for (path, content) in &desired {
            let blob: GithubBlobResponse = self.post_json(
                &format!("{repository_base}/git/blobs"),
                &serde_json::json!({"content": content, "encoding": "utf-8"}),
            )?;
            tree_entries.push(serde_json::json!({
                "path": path,
                "mode": "100644",
                "type": "blob",
                "sha": blob.sha,
            }));
        }
        let tree: GithubTreeResponse = self.post_json(
            &format!("{repository_base}/git/trees"),
            &serde_json::json!({"tree": tree_entries}),
        )?;
        let commit: GithubCommitResponse = self.post_json(
            &format!("{repository_base}/git/commits"),
            &serde_json::json!({
                "message": format!("Hartevo publication {}", request.payload_digest),
                "tree": tree.sha,
                "parents": [current.head_sha],
            }),
        )?;
        let _: GithubReferenceResponse = self
            .patch_json(
                &format!("{repository_base}/git/refs/heads/{}", target.branch),
                &serde_json::json!({"sha": commit.sha, "force": false}),
            )
            .map_err(|error| GithubPagesError::Uncertain(error.to_string()))?;
        let manifest_json =
            serde_json::to_string(&manifest).map_err(|_| GithubPagesError::Decode)?;
        Ok(GithubPagesProviderReceipt {
            commit_sha: commit.sha,
            response_digest: sha256(format!("{}|{}", commit.tree.sha, manifest_json)),
            publication_manifest_digest: sha256(manifest_json.as_bytes()),
            accepted_at: published_at,
        })
    }

    fn reconcile(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
        effect: &Effect,
        approval_digest: &str,
    ) -> Result<GithubPagesReconciliation, GithubPagesError> {
        let snapshot = self.read(target)?;
        let receipt = snapshot
            .publication_manifest
            .as_ref()
            .filter(|manifest| manifest.matches(effect, request, approval_digest))
            .map(|manifest| provider_receipt_from_manifest_at(manifest, &snapshot.head_sha))
            .transpose()?;
        Ok(GithubPagesReconciliation { snapshot, receipt })
    }
}

#[derive(Clone, Debug)]
pub struct GithubPagesReadbackApi {
    agent: ureq::Agent,
}

impl Default for GithubPagesReadbackApi {
    fn default() -> Self {
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-github-pages-readback/1")
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        Self { agent }
    }
}

impl GithubPagesReadbackApi {
    fn get_body(&self, url: &str) -> Result<(u16, String), GithubPagesError> {
        let mut response = self
            .agent
            .get(url)
            .header("Accept", "text/html, application/json")
            .call()
            .map_err(|error| GithubPagesError::Readback(error.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error| GithubPagesError::Readback(error.to_string()))?;
        Ok((status, body))
    }

    fn file_url(
        target: &GithubPagesEnvironmentTarget,
        path: &str,
    ) -> Result<String, GithubPagesError> {
        let mut url = Url::parse(&format!("{}/", target.pages_url.trim_end_matches('/')))
            .map_err(|_| GithubPagesError::Readback("invalid Pages URL".into()))?;
        {
            let mut segments = url.path_segments_mut().map_err(|()| {
                GithubPagesError::Readback("Pages URL cannot accept a path".into())
            })?;
            for segment in path.split('/') {
                segments.push(segment);
            }
        }
        Ok(url.to_string())
    }
}

impl GithubPagesReadbackTransport for GithubPagesReadbackApi {
    fn readback(
        &mut self,
        target: &GithubPagesEnvironmentTarget,
        request: &PublicationPublishRequest,
    ) -> Result<GithubPagesReadbackObservation, GithubPagesError> {
        target.validate()?;
        let parsed = Url::parse(&target.pages_url)
            .map_err(|_| GithubPagesError::Readback("invalid Pages URL".into()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| GithubPagesError::Readback("Pages URL has no host".into()))?;
        let port = parsed.port_or_known_default().ok_or_else(|| {
            GithubPagesError::Readback("Pages URL has no known HTTPS port".into())
        })?;
        let dns_resolved = format!("{host}:{port}")
            .to_socket_addrs()
            .is_ok_and(|mut addresses| addresses.next().is_some());
        let root_url = format!("{}/", target.pages_url.trim_end_matches('/'));
        let manifest_url = format!(
            "{}/{}",
            target.pages_url.trim_end_matches('/'),
            GITHUB_PAGES_MANIFEST_PATH
        );
        let (root_http_status, root_body) = self.get_body(&root_url)?;
        let (manifest_http_status, manifest_body) = self.get_body(&manifest_url)?;
        let manifest = serde_json::from_str::<GithubPagesPublicationManifest>(&manifest_body)
            .map_err(|_| GithubPagesError::Readback("Pages manifest is invalid".into()))?;
        if !manifest.matches_readback(target, request) {
            return Err(GithubPagesError::Readback(
                "Pages manifest is outside the requested fence".into(),
            ));
        }
        let mut observed_contents = Vec::with_capacity(request.files.len());
        for file in &request.files {
            let body = if file.path == "index.html" {
                root_body.clone()
            } else {
                let (status, body) = self.get_body(&Self::file_url(target, &file.path)?)?;
                if status != 200 {
                    return Err(GithubPagesError::Readback(format!(
                        "published file {} returned HTTP status {status}",
                        file.path
                    )));
                }
                body
            };
            observed_contents.push(body);
        }
        let content_digest = publication_content_digest(
            request
                .files
                .iter()
                .zip(observed_contents.iter())
                .map(|(file, content)| (file.path.as_str(), content.as_str())),
        );
        let evidence_digest = sha256(format!(
            "{}|{}|{}|{}|{}|{}",
            root_http_status,
            manifest_http_status,
            dns_resolved,
            sha256(root_body),
            sha256(manifest_body),
            content_digest
        ));
        Ok(GithubPagesReadbackObservation {
            root_http_status,
            manifest_http_status,
            dns_resolved,
            content_digest: Some(content_digest),
            publication_digest: Some(manifest.payload_digest),
            evidence_digest,
            observed_at: Utc::now(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct GithubReferenceResponse {
    object: GithubObject,
}

#[derive(Debug, Deserialize)]
struct GithubCommitResponse {
    sha: String,
    tree: GithubObject,
}

#[derive(Debug, Deserialize)]
struct GithubObject {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GithubTreeResponse {
    sha: String,
    tree: Vec<GithubTreeEntry>,
}

#[derive(Debug, Deserialize)]
struct GithubTreeEntry {
    path: String,
    sha: String,
    #[serde(rename = "type")]
    entry_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct GithubBlobResponse {
    sha: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    encoding: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct GithubPagesResponse {
    html_url: Option<String>,
    source: Option<GithubPagesSource>,
}

#[derive(Debug, Deserialize, Serialize)]
struct GithubPagesSource {
    branch: Option<String>,
    path: Option<String>,
}

fn classify_http_error(error: ureq::Error) -> GithubPagesError {
    match error {
        ureq::Error::StatusCode(status) if status < 500 => {
            GithubPagesError::Rejected(format!("GitHub API HTTP status {status}"))
        }
        ureq::Error::StatusCode(status) => {
            GithubPagesError::Uncertain(format!("GitHub API HTTP status {status}"))
        }
        other => GithubPagesError::Uncertain(format!("GitHub API transport error: {other}")),
    }
}

#[derive(Debug, Error)]
pub enum GithubPagesError {
    #[error("invalid GitHub Pages target: {0}")]
    InvalidTarget(&'static str),
    #[error("GitHub Pages staging and production authorities must be distinct")]
    EnvironmentFence,
    #[error("GitHub publication effect fence failed")]
    EffectFence,
    #[error("invalid publication request: {0}")]
    InvalidRequest(String),
    #[error("GitHub provider rejected the request: {0}")]
    Rejected(String),
    #[error("GitHub provider state is uncertain: {0}")]
    Uncertain(String),
    #[error("GitHub API request failed: {0}")]
    Http(String),
    #[error("GitHub API response could not be decoded")]
    Decode,
    #[error("GitHub API returned an invalid content encoding")]
    Encoding,
    #[error("GitHub API returned an invalid repository response")]
    InvalidResponse,
    #[error("independent Pages readback failed: {0}")]
    Readback(String),
    #[error("provider state lock was poisoned")]
    StateLock,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::Duration;
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, ConsentState, CurrencyCode,
        DeploymentId, DomainId, EffectRisk, EffectStatus, MissionId, Money, ProjectId,
        PublicationId, SiteFile, SiteId, SitePreview, TenantId,
    };

    use super::*;

    fn digest(value: &str) -> String {
        sha256(value)
    }

    fn targets() -> GithubPagesTargets {
        GithubPagesTargets::new(
            GithubPagesEnvironmentTarget::new(
                "owner",
                "staging-site",
                "pages",
                "https://staging.example.com",
            )
            .expect("staging target"),
            GithubPagesEnvironmentTarget::new(
                "owner",
                "production-site",
                "pages",
                "https://example.com",
            )
            .expect("production target"),
        )
        .expect("distinct targets")
    }

    fn request(targets: &GithubPagesTargets) -> PublicationPublishRequest {
        let environment = PublicationEnvironment::Production;
        PublicationPublishRequest::new(
            SiteId::from_stable("site-1"),
            DomainId::from_stable("domain-1"),
            DeploymentId::from_stable("deployment-1"),
            environment,
            targets.target(environment, "account-1", digest("production-config")),
            2,
            1,
            digest("head-1"),
            &BTreeMap::new(),
            vec![SiteFile::new("index.html", "<h1>hello</h1>").expect("site file")],
            SitePreview::new(digest("artifact"), "preview", None, Utc::now()).expect("preview"),
            Utc::now(),
        )
        .expect("publication request")
    }

    fn effect(request: &PublicationPublishRequest) -> Effect {
        let now = Utc::now();
        let publication_id = PublicationId::from_stable("publication-1");
        let mut effect = Effect {
            id: EffectId::from_stable("effect-1"),
            tenant_id: TenantId::from_stable("tenant-1"),
            project_id: ProjectId::from_stable("project-1"),
            mission_id: MissionId::from_stable("mission-1"),
            actor_id: ActorId::from_stable("actor-1"),
            capability: "publication.publish".into(),
            provider: GITHUB_PAGES_PROVIDER.into(),
            connection_id: None,
            account_id: Some(AccountId::from_stable("account-1")),
            required_scopes: BTreeSet::new(),
            effect_class: EffectClass::ExternalWrite,
            description: "publish the approved site revision".into(),
            target_resource: request.target_resource(&publication_id),
            audience_digest: None,
            payload_digest: request.payload_digest.clone(),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "policy-v1".into(),
            risk: EffectRisk::Medium,
            idempotency_key: request.idempotency_key.clone(),
            amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
            expires_at: now + Duration::hours(1),
            status: EffectStatus::Approved,
            approval: None,
            receipt: None,
            verification: None,
        };
        let scope_digest = effect.approval_digest();
        effect.approval = Some(Approval {
            id: ApprovalId::from_stable("approval-1"),
            decision: ApprovalDecision::Approved,
            decided_by: effect.actor_id.clone(),
            decided_at: now,
            valid_until: now + Duration::minutes(30),
            scope_digest,
            permission_digest: digest("permission"),
        });
        effect
    }

    #[test]
    fn real_adapter_contract_replays_without_a_second_repository_mutation() {
        let targets = targets();
        let transport = InMemoryGithubPagesTransport::new();
        let production = targets.selected(PublicationEnvironment::Production);
        transport
            .seed(
                production,
                digest("production-config"),
                "head-1",
                BTreeMap::new(),
            )
            .expect("seed repository");
        let request = request(&targets);
        let effect = effect(&request);

        let mut executor =
            GithubPagesExecutor::new(targets.clone(), transport.clone()).expect("executor");
        executor
            .register(effect.id.clone(), request.clone())
            .expect("register executor");
        let receipt = executor.execute(&effect).expect("provider receipt");
        assert_eq!(
            transport
                .mutation_count(production)
                .expect("mutation count"),
            1
        );

        let mut verifier =
            GithubPagesVerifier::new(targets.clone(), transport.clone()).expect("verifier");
        verifier
            .register(effect.id.clone(), request.clone())
            .expect("register verifier");
        let verification = verifier.verify(&effect, &receipt);
        assert_eq!(verification.status, VerificationStatus::Confirmed);
        assert!(verification.independent);

        let mut retry =
            GithubPagesExecutor::new(targets.clone(), transport.clone()).expect("retry executor");
        retry
            .register(effect.id.clone(), request.clone())
            .expect("register retry");
        let replayed_receipt = retry.execute(&effect).expect("idempotent receipt");
        assert_eq!(replayed_receipt.external_id, receipt.external_id);
        assert_eq!(
            transport
                .mutation_count(production)
                .expect("mutation count after replay"),
            1
        );

        let mut reconciler = GithubPagesReconciler::new(targets, transport).expect("reconciler");
        reconciler
            .register(effect.id.clone(), request)
            .expect("register reconciler");
        assert!(matches!(
            reconciler.reconcile(&effect),
            ReconciliationObservation::ReceiptFound { .. }
        ));
    }

    #[test]
    fn staging_and_production_targets_cannot_share_authority() {
        let production =
            GithubPagesEnvironmentTarget::new("owner", "same-site", "pages", "https://example.com")
                .expect("production target");
        let staging = production.clone();
        assert!(matches!(
            GithubPagesTargets::new(staging, production),
            Err(GithubPagesError::EnvironmentFence)
        ));
    }

    #[test]
    fn access_token_debug_is_redacted() {
        let token = GithubAccessToken::new("ghs_secret-value").expect("token");
        let debug = format!("{token:?}");
        assert!(!debug.contains("secret-value"));
        assert!(debug.contains("REDACTED"));
    }
}
