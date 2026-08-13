use std::collections::BTreeMap;
use std::env;
use std::sync::{Arc, Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_connector_sdk::{ConnectorScope, EffectExecutionContext, SecretReference};
use hartevo_domain_kernel::{
    ActorId, Approval, ApprovalDecision, EffectId, EffectStatus, Mission, MissionContract,
    MissionId, ProjectId, TenantId, WorkProduct, WorkProductId,
};
use zeroize::Zeroizing;

use crate::{
    BlockedEnvCredentialResolver, Domain, EnvironmentGithubCredentialResolver,
    GITHUB_PAGES_REQUIRED_SCOPES, GithubCredentialResolver, GithubPagesApiBlob,
    GithubPagesApiBlobWrite, GithubPagesApiCommit, GithubPagesApiCommitWrite, GithubPagesApiObject,
    GithubPagesApiPages, GithubPagesApiRefUpdate, GithubPagesApiSource, GithubPagesApiTree,
    GithubPagesApiTreeEntry, GithubPagesApiTreeWrite, GithubPagesApiTreeWriteEntry,
    GithubPagesConnection, GithubPagesEnvironment, GithubPagesHttpTransport, GithubPagesProvider,
    GithubPagesProviderError, GithubPagesTransportError, MissionPublicationProposalResult,
    PublicationAction, PublicationAuditEntry, PublicationDurableLog,
    PublicationExecutionAuthorization, PublicationOperation, PublicationProposalInput, Site,
    SiteFile, SiteId, SitePublicationService, WebPublicationError,
};

const TOKEN: &str = "controlled-test-token";
const HEAD_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TREE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const INDEX_SHA: &str = "cccccccccccccccccccccccccccccccccccccccc";
const OLD_SHA: &str = "dddddddddddddddddddddddddddddddddddddddd";
const PUBLISHED_HEAD_SHA: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const PUBLISHED_TREE_SHA: &str = "ffffffffffffffffffffffffffffffffffffffff";

#[derive(Clone, Debug)]
struct ControlledPublicationState {
    head_sha: String,
    tree_sha: String,
    files: BTreeMap<String, (String, Vec<u8>)>,
    blobs: BTreeMap<String, Vec<u8>>,
    trees: BTreeMap<String, BTreeMap<String, (String, Vec<u8>)>>,
    commits: BTreeMap<String, (String, String, String)>,
    update_ref_error: Option<GithubPagesTransportError>,
    update_ref_apply_then_error: Option<GithubPagesTransportError>,
}

impl Default for ControlledPublicationState {
    fn default() -> Self {
        Self {
            head_sha: HEAD_SHA.to_owned(),
            tree_sha: TREE_SHA.to_owned(),
            files: BTreeMap::from([
                (
                    "index.html".to_owned(),
                    (INDEX_SHA.to_owned(), b"<h1>old</h1>".to_vec()),
                ),
                ("old.txt".to_owned(), (OLD_SHA.to_owned(), b"old".to_vec())),
            ]),
            blobs: BTreeMap::new(),
            trees: BTreeMap::new(),
            commits: BTreeMap::new(),
            update_ref_error: None,
            update_ref_apply_then_error: None,
        }
    }
}

#[derive(Clone, Debug)]
struct ControlledGithubTransport {
    calls: Arc<Mutex<Vec<String>>>,
    publication: Arc<Mutex<ControlledPublicationState>>,
}

impl ControlledGithubTransport {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            publication: Arc::new(Mutex::new(ControlledPublicationState::default())),
        }
    }

    fn set_update_ref_error(&self, error: GithubPagesTransportError) {
        self.publication
            .lock()
            .expect("publication state")
            .update_ref_error = Some(error);
    }

    fn set_update_ref_apply_then_error(&self, error: GithubPagesTransportError) {
        self.publication
            .lock()
            .expect("publication state")
            .update_ref_apply_then_error = Some(error);
    }

    fn record(&self, token: &str, operation: &str) -> Result<(), GithubPagesTransportError> {
        if token != TOKEN {
            return Err(GithubPagesTransportError::Rejected { status: 401 });
        }
        self.calls
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "controlled call log poisoned".to_owned(),
            })?
            .push(operation.to_owned());
        Ok(())
    }
}

impl GithubPagesHttpTransport for ControlledGithubTransport {
    fn pages(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
    ) -> Result<GithubPagesApiPages, GithubPagesTransportError> {
        self.record(token, "GET /pages")?;
        Ok(GithubPagesApiPages {
            html_url: Some("https://example.github.io/site".to_owned()),
            source: Some(GithubPagesApiSource {
                branch: Some("main".to_owned()),
                path: Some("/".to_owned()),
            }),
            environment: Some("production".to_owned()),
        })
    }

    fn git_ref(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        _git_ref: &str,
    ) -> Result<GithubPagesApiObject, GithubPagesTransportError> {
        self.record(token, "GET /git/ref")?;
        let state = self
            .publication
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "publication state poisoned".to_owned(),
            })?;
        Ok(GithubPagesApiObject {
            sha: state.head_sha.clone(),
            object_type: Some("commit".to_owned()),
        })
    }

    fn commit(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        commit_sha: &str,
    ) -> Result<GithubPagesApiCommit, GithubPagesTransportError> {
        self.record(token, "GET /git/commits")?;
        let state = self
            .publication
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "publication state poisoned".to_owned(),
            })?;
        let (tree_sha, message, parent) = state.commits.get(commit_sha).map_or_else(
            || (state.tree_sha.clone(), None, None),
            |(tree_sha, message, parent)| {
                (
                    tree_sha.clone(),
                    Some(message.clone()),
                    Some(parent.clone()),
                )
            },
        );
        Ok(GithubPagesApiCommit {
            sha: Some(commit_sha.to_owned()),
            tree: GithubPagesApiObject {
                sha: tree_sha,
                object_type: None,
            },
            message,
            parents: parent.map(|sha| {
                vec![GithubPagesApiObject {
                    sha,
                    object_type: Some("commit".to_owned()),
                }]
            }),
        })
    }

    fn tree(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        tree_sha: &str,
    ) -> Result<GithubPagesApiTree, GithubPagesTransportError> {
        self.record(token, "GET /git/trees")?;
        let state = self
            .publication
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "publication state poisoned".to_owned(),
            })?;
        let files = state.trees.get(tree_sha).unwrap_or(&state.files);
        Ok(GithubPagesApiTree {
            sha: tree_sha.to_owned(),
            truncated: Some(false),
            tree: files
                .iter()
                .map(|(path, (sha, content))| GithubPagesApiTreeEntry {
                    path: path.clone(),
                    sha: sha.clone(),
                    entry_type: "blob".to_owned(),
                    size: Some(content.len() as u64),
                })
                .collect(),
        })
    }

    fn blob(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        blob_sha: &str,
    ) -> Result<GithubPagesApiBlob, GithubPagesTransportError> {
        self.record(token, "GET /git/blobs")?;
        let state = self
            .publication
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "publication state poisoned".to_owned(),
            })?;
        let content = if blob_sha == INDEX_SHA {
            b"<h1>old</h1>".to_vec()
        } else if blob_sha == OLD_SHA {
            b"old".to_vec()
        } else {
            state
                .blobs
                .get(blob_sha)
                .cloned()
                .ok_or(GithubPagesTransportError::Rejected { status: 404 })?
        };
        Ok(GithubPagesApiBlob {
            sha: Some(blob_sha.to_owned()),
            content: STANDARD.encode(content),
            encoding: "base64".to_owned(),
        })
    }

    fn create_blob(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        content_base64: &str,
    ) -> Result<GithubPagesApiBlobWrite, GithubPagesTransportError> {
        self.record(token, "POST /git/blobs")?;
        let content =
            STANDARD
                .decode(content_base64)
                .map_err(|error| GithubPagesTransportError::Decode {
                    detail: error.to_string(),
                })?;
        let sha = controlled_sha(&content);
        self.publication
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "publication state poisoned".to_owned(),
            })?
            .blobs
            .insert(sha.clone(), content);
        Ok(GithubPagesApiBlobWrite { sha })
    }

    fn create_tree(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        base_tree_sha: &str,
        entries: &[GithubPagesApiTreeWriteEntry],
    ) -> Result<GithubPagesApiTreeWrite, GithubPagesTransportError> {
        self.record(token, "POST /git/trees")?;
        let mut state =
            self.publication
                .lock()
                .map_err(|_| GithubPagesTransportError::Transport {
                    detail: "publication state poisoned".to_owned(),
                })?;
        let mut files = state
            .trees
            .get(base_tree_sha)
            .cloned()
            .unwrap_or_else(|| state.files.clone());
        for entry in entries {
            match &entry.sha {
                Some(sha) => {
                    let content = state
                        .blobs
                        .get(sha)
                        .cloned()
                        .ok_or(GithubPagesTransportError::Rejected { status: 422 })?;
                    files.insert(entry.path.clone(), (sha.clone(), content));
                }
                None => {
                    files.remove(&entry.path);
                }
            }
        }
        let tree_sha = if files.keys().any(|path| path == "about.html") {
            PUBLISHED_TREE_SHA.to_owned()
        } else {
            controlled_tree_sha(&files)
        };
        state.trees.insert(tree_sha.clone(), files);
        Ok(GithubPagesApiTreeWrite { sha: tree_sha })
    }

    fn create_commit(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        message: &str,
        tree_sha: &str,
        parent_sha: &str,
    ) -> Result<GithubPagesApiCommitWrite, GithubPagesTransportError> {
        self.record(token, "POST /git/commits")?;
        let commit_sha = if message.contains("rollback") {
            "2222222222222222222222222222222222222222".to_owned()
        } else {
            PUBLISHED_HEAD_SHA.to_owned()
        };
        self.publication
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "publication state poisoned".to_owned(),
            })?
            .commits
            .insert(
                commit_sha.clone(),
                (
                    tree_sha.to_owned(),
                    message.to_owned(),
                    parent_sha.to_owned(),
                ),
            );
        Ok(GithubPagesApiCommitWrite {
            sha: commit_sha,
            tree: GithubPagesApiObject {
                sha: tree_sha.to_owned(),
                object_type: Some("tree".to_owned()),
            },
        })
    }

    fn update_ref(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        git_ref: &str,
        commit_sha: &str,
        _force: bool,
    ) -> Result<GithubPagesApiRefUpdate, GithubPagesTransportError> {
        self.record(token, "PATCH /git/refs")?;
        let mut state =
            self.publication
                .lock()
                .map_err(|_| GithubPagesTransportError::Transport {
                    detail: "publication state poisoned".to_owned(),
                })?;
        if let Some(error) = state.update_ref_error.take() {
            return Err(error);
        }
        let (tree_sha, _, _) = state
            .commits
            .get(commit_sha)
            .cloned()
            .ok_or(GithubPagesTransportError::Rejected { status: 404 })?;
        state.head_sha = commit_sha.to_owned();
        state.tree_sha = tree_sha;
        state.files = state
            .trees
            .get(&state.tree_sha)
            .cloned()
            .ok_or(GithubPagesTransportError::Rejected { status: 404 })?;
        if let Some(error) = state.update_ref_apply_then_error.take() {
            return Err(error);
        }
        Ok(GithubPagesApiRefUpdate {
            reference: format!("refs/heads/{git_ref}"),
            object: GithubPagesApiObject {
                sha: commit_sha.to_owned(),
                object_type: Some("commit".to_owned()),
            },
        })
    }

    fn public_readback(
        &self,
        pages_url: &str,
        expected_files: &[SiteFile],
    ) -> Result<crate::GithubPagesPublicReadback, GithubPagesTransportError> {
        let state = self
            .publication
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "publication state poisoned".to_owned(),
            })?;
        self.calls
            .lock()
            .map_err(|_| GithubPagesTransportError::Transport {
                detail: "controlled call log poisoned".to_owned(),
            })?
            .push("PUBLIC / (no Authorization)".to_owned());
        let expected = expected_files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice()))
            .collect::<BTreeMap<_, _>>();
        let served = state
            .files
            .iter()
            .map(|(path, (_, content))| (path.as_str(), content.as_slice()))
            .collect::<BTreeMap<_, _>>();
        if expected != served {
            return Err(GithubPagesTransportError::Rejected { status: 409 });
        }
        let root = served
            .get("index.html")
            .ok_or(GithubPagesTransportError::Rejected { status: 404 })?;
        Ok(crate::GithubPagesPublicReadback {
            url: pages_url.to_owned(),
            http_status: 200,
            dns_digest: crate::digest_parts(["example.github.io"]),
            root_body_digest: crate::digest_bytes(root),
            content_digest: crate::file_tree_digest(expected_files),
            observed_at: now(),
        })
    }
}

#[derive(Clone, Debug, Default)]
struct ControlledCredentialResolver;

impl GithubCredentialResolver for ControlledCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<Zeroizing<String>, GithubPagesProviderError> {
        Ok(Zeroizing::new(TOKEN.to_owned()))
    }
}

#[derive(Debug, Default)]
struct MemoryPublicationLog {
    entries: Vec<PublicationAuditEntry>,
}

impl PublicationDurableLog for MemoryPublicationLog {
    fn append(&mut self, entry: PublicationAuditEntry) -> Result<(), WebPublicationError> {
        self.entries.push(entry);
        Ok(())
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
        .single()
        .expect("valid test time")
}

fn controlled_sha(bytes: &[u8]) -> String {
    crate::digest_bytes(bytes)[..40].to_owned()
}

fn controlled_tree_sha(files: &BTreeMap<String, (String, Vec<u8>)>) -> String {
    let material = files
        .iter()
        .map(|(path, (sha, _))| format!("{path}|{sha}"))
        .collect::<Vec<_>>()
        .join("|");
    controlled_sha(material.as_bytes())
}

fn scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-1",
        "project-1",
        "github",
        "account-1",
        GITHUB_PAGES_REQUIRED_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned()),
    )
    .expect("valid connector scope")
}

fn secret() -> SecretReference {
    SecretReference::new("secret-ref-controlled", scope(), 1).expect("valid secret reference")
}

fn connection(at: DateTime<Utc>) -> (GithubPagesConnection, SecretReference) {
    let secret = secret();
    let connection = GithubPagesConnection::new(
        TenantId::from_stable("tenant-1"),
        ProjectId::from_stable("project-1"),
        MissionId::from_stable("mission-1"),
        hartevo_domain_kernel::ConnectionId::from_stable("connection-1"),
        hartevo_domain_kernel::AccountId::from_stable("account-1"),
        "example",
        "site",
        "main",
        "https://example.github.io/site",
        GithubPagesEnvironment::Production,
        &secret,
    )
    .expect("valid GitHub Pages connection");
    assert_eq!(
        connection.state_at(at),
        crate::GithubPagesConnectionState::Registered
    );
    (connection, secret)
}

fn mission_and_site(at: DateTime<Utc>) -> (Mission, Site, Domain) {
    let tenant_id = TenantId::from_stable("tenant-1");
    let project_id = ProjectId::from_stable("project-1");
    let mut mission = Mission::compile(
        tenant_id.clone(),
        MissionId::from_stable("mission-1"),
        project_id.clone(),
        "Publish the selected site",
        MissionContract::bootstrap(
            "publish a selected site",
            ["publication.publish".to_owned()],
            at,
        ),
        at,
    )
    .expect("valid mission");
    mission
        .start_research([], at + Duration::seconds(1))
        .expect("mission starts");
    let work_product = WorkProduct::draft(
        WorkProductId::from_stable("work-product-1"),
        "Selected website",
        "A reviewable website work product",
        [],
    );
    let source_digest = work_product.content_digest.clone();
    mission
        .record_work_product(work_product, at + Duration::seconds(2))
        .expect("work product recorded");
    let site = Site::new(
        tenant_id.clone(),
        project_id.clone(),
        SiteId::from_stable("site-1"),
        7,
        [
            SiteFile::text("about.html", "<p>about</p>").expect("about file"),
            SiteFile::text("index.html", "<h1>new</h1>").expect("index file"),
        ],
        WorkProductId::from_stable("work-product-1"),
        1,
        source_digest,
    )
    .expect("valid site");
    let domain = Domain::new(
        tenant_id,
        project_id,
        crate::DomainId::from_stable("domain-1"),
        "example.github.io",
    )
    .expect("valid domain");
    (mission, site, domain)
}

fn approve_proposal(
    mission: &mut Mission,
    proposal: &MissionPublicationProposalResult,
    domain: &Domain,
    at: DateTime<Utc>,
) -> PublicationExecutionAuthorization {
    let effect_id = proposal.prepared_effect.effect_spec.id.clone();
    mission
        .propose_effect(proposal.prepared_effect.effect_spec.clone(), at)
        .expect("durable Mission Effect is proposed");
    let valid_until = mission
        .approval_valid_until(&effect_id, at)
        .expect("approval window");
    let permission_digest = "e".repeat(64);
    mission
        .approve_effect(
            &effect_id,
            Approval {
                id: hartevo_domain_kernel::ApprovalId::from_stable("approval-1"),
                decision: ApprovalDecision::Approved,
                decided_by: ActorId::from_stable("actor-1"),
                decided_at: at,
                valid_until,
                scope_digest: mission
                    .effect(&effect_id)
                    .expect("proposed effect")
                    .approval_digest(),
                permission_digest: permission_digest.clone(),
            },
        )
        .expect("effect approved");
    let effect = mission.effect(&effect_id).expect("approved effect").clone();
    let execution_context = EffectExecutionContext::from_broker(
        scope(),
        proposal.prepared_effect.connector_effect.effect_digest(),
        permission_digest,
        valid_until,
    )
    .expect("broker execution capsule");
    PublicationExecutionAuthorization::from_approved_effect(
        proposal,
        domain,
        effect,
        execution_context,
    )
}

#[test]
fn controlled_provider_produces_authenticated_read_and_prepare_only_proposal() {
    let at = now();
    let (connection, secret) = connection(at);
    let transport = ControlledGithubTransport::new();
    let calls = Arc::clone(&transport.calls);
    let provider = GithubPagesProvider::connect(
        connection,
        secret,
        transport,
        Arc::new(ControlledCredentialResolver),
        at,
    )
    .expect("controlled contract provider connects");
    let mut service = SitePublicationService::new(provider, MemoryPublicationLog::default());
    let (mission, site, domain) = mission_and_site(at);
    let mission_revision = mission.revision;
    let result = service
        .propose(
            &mission,
            &site,
            &domain,
            PublicationProposalInput::new(
                crate::PublicationId::from_stable("publication-1"),
                ActorId::from_stable("actor-1"),
                EffectId::from_stable("effect-1"),
                "policy-web-publication-v1",
                at + Duration::seconds(3),
                at + Duration::seconds(30),
            ),
        )
        .expect("controlled read/proposal");

    assert_eq!(result.publication_read.publication.target.owner, "example");
    assert_eq!(
        result.publication_read.publication.target.environment,
        GithubPagesEnvironment::Production
    );
    assert_eq!(result.publication_read.snapshot.head_sha, HEAD_SHA);
    assert_eq!(result.publication_read.snapshot.target.git_ref, "main");
    assert_eq!(
        result
            .canonical_diff
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["about.html", "index.html", "old.txt"]
    );
    assert!(result.prepared_effect.prepared_only);
    assert!(!result.prepared_effect.external_effect_created);
    assert!(result.preview_only);
    assert!(!result.external_effect_created);
    assert_eq!(
        result
            .prepared_effect
            .effect_spec
            .connection_id
            .as_ref()
            .map(hartevo_domain_kernel::ConnectionId::as_str),
        Some("connection-1")
    );
    assert_eq!(
        result.prepared_effect.effect_spec.target_resource,
        "github-pages/example/site/main/production"
    );
    assert_eq!(result.target_revision, 7);
    assert!(mission.effects.is_empty());
    assert_eq!(mission.revision, mission_revision);

    let log = service.durable_log();
    assert_eq!(log.entries.len(), 2);
    assert_eq!(log.entries[0].operation, PublicationOperation::Read);
    assert_eq!(log.entries[1].operation, PublicationOperation::Proposal);
    assert!(log.entries.iter().all(|entry| entry.model_visible));
    assert!(
        log.entries
            .iter()
            .all(|entry| entry.verify_digest().expect("valid digest"))
    );
    let serialized_log = serde_json::to_string(log.entries.as_slice()).expect("serializable log");
    assert!(!serialized_log.contains(TOKEN));
    assert!(!serialized_log.contains("<h1>new</h1>"));
    assert!(
        calls
            .lock()
            .expect("controlled calls")
            .iter()
            .all(|call| call.starts_with("GET "))
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn approved_publish_returns_receipt_and_independent_readback_without_duplicate_mutation() {
    let at = now();
    let (connection, secret) = connection(at);
    let transport = ControlledGithubTransport::new();
    let calls = Arc::clone(&transport.calls);
    let provider = GithubPagesProvider::connect(
        connection,
        secret,
        transport,
        Arc::new(ControlledCredentialResolver),
        at,
    )
    .expect("controlled provider connects");
    let mut service = SitePublicationService::new(provider, MemoryPublicationLog::default());
    let (mut mission, site, domain) = mission_and_site(at);
    let proposal = service
        .propose(
            &mission,
            &site,
            &domain,
            PublicationProposalInput::new(
                crate::PublicationId::from_stable("publication-1"),
                ActorId::from_stable("actor-1"),
                EffectId::from_stable("effect-1"),
                "policy-web-publication-v1",
                at + Duration::seconds(3),
                at + Duration::seconds(30),
            ),
        )
        .expect("canonical proposal");
    let approval = approve_proposal(&mut mission, &proposal, &domain, at + Duration::seconds(4));
    let mission_revision = mission.revision;
    let result = service
        .publish(
            &mission,
            &site,
            &domain,
            &proposal,
            &approval,
            at + Duration::seconds(5),
        )
        .expect("approved publication");
    assert_eq!(result.action, PublicationAction::Publish);
    assert!(result.adoptable);
    assert_eq!(result.receipt.commit_sha, PUBLISHED_HEAD_SHA);
    assert_eq!(
        result.verification.observation.status(),
        hartevo_connector_sdk::VerificationStatus::Confirmed
    );
    assert!(result.verification.observation.independent());
    assert!(result.verification.readback.authenticated_content_matches);
    assert!(result.verification.readback.public_content_matches);
    assert_eq!(mission.revision, mission_revision);
    assert_eq!(
        mission
            .effect(&EffectId::from_stable("effect-1"))
            .expect("effect remains durable")
            .status,
        EffectStatus::Approved
    );

    let calls_after_first = calls.lock().expect("calls").clone();
    assert!(
        calls_after_first
            .iter()
            .any(|call| call == "POST /git/blobs")
    );
    assert!(
        calls_after_first
            .iter()
            .any(|call| call == "POST /git/trees")
    );
    assert!(
        calls_after_first
            .iter()
            .any(|call| call == "POST /git/commits")
    );
    assert!(
        calls_after_first
            .iter()
            .any(|call| call == "PATCH /git/refs")
    );
    assert!(
        calls_after_first
            .iter()
            .any(|call| call == "PUBLIC / (no Authorization)")
    );
    let mutation_count = calls_after_first
        .iter()
        .filter(|call| {
            matches!(
                call.as_str(),
                "POST /git/blobs" | "POST /git/trees" | "POST /git/commits" | "PATCH /git/refs"
            )
        })
        .count();

    let replay = service
        .publish(
            &mission,
            &site,
            &domain,
            &proposal,
            &approval,
            at + Duration::seconds(6),
        )
        .expect("idempotent connector replay");
    assert_eq!(replay.receipt, result.receipt);
    let calls_after_replay = calls.lock().expect("calls").clone();
    let replay_mutation_count = calls_after_replay
        .iter()
        .filter(|call| {
            matches!(
                call.as_str(),
                "POST /git/blobs" | "POST /git/trees" | "POST /git/commits" | "PATCH /git/refs"
            )
        })
        .count();
    assert_eq!(replay_mutation_count, mutation_count);
}

#[test]
fn crash_ahead_reconcile_adopts_external_commit_without_republishing() {
    let at = now();
    let (connection, secret) = connection(at);
    let transport = ControlledGithubTransport::new();
    let restart_transport = transport.clone();
    let restart_connection = connection.clone();
    let restart_secret = secret.clone();
    let calls = Arc::clone(&transport.calls);
    transport.set_update_ref_apply_then_error(GithubPagesTransportError::Transport {
        detail: "connection dropped after GitHub accepted the ref update".to_owned(),
    });
    let provider = GithubPagesProvider::connect(
        connection,
        secret,
        transport,
        Arc::new(ControlledCredentialResolver),
        at,
    )
    .expect("controlled provider connects");
    let mut service = SitePublicationService::new(provider, MemoryPublicationLog::default());
    let (mut mission, site, domain) = mission_and_site(at);
    let proposal = service
        .propose(
            &mission,
            &site,
            &domain,
            PublicationProposalInput::new(
                crate::PublicationId::from_stable("publication-crash"),
                ActorId::from_stable("actor-1"),
                EffectId::from_stable("effect-crash"),
                "policy-web-publication-v1",
                at + Duration::seconds(3),
                at + Duration::seconds(30),
            ),
        )
        .expect("canonical proposal");
    let approval = approve_proposal(&mut mission, &proposal, &domain, at + Duration::seconds(4));
    let publish_error = service
        .publish(
            &mission,
            &site,
            &domain,
            &proposal,
            &approval,
            at + Duration::seconds(5),
        )
        .expect_err("crash-ahead must not claim a receipt before readback");
    assert_eq!(publish_error.code(), "PROVIDER_REJECTED");

    drop(service);
    let restarted_provider = GithubPagesProvider::connect(
        restart_connection,
        restart_secret,
        restart_transport,
        Arc::new(ControlledCredentialResolver),
        at + Duration::seconds(6),
    )
    .expect("provider reconnects after restart");
    let mut restarted_service =
        SitePublicationService::new(restarted_provider, MemoryPublicationLog::default());
    let reconciled = restarted_service
        .reconcile(
            &mission,
            &site,
            &domain,
            &proposal,
            at + Duration::seconds(7),
        )
        .expect("read-only crash reconciliation");
    assert_eq!(reconciled.disposition, crate::PublicationOutcome::Adoptable);
    assert!(reconciled.adoptable_result.is_some());
    assert_eq!(
        reconciled
            .adoptable_result
            .as_ref()
            .expect("adoptable result")
            .receipt
            .commit_sha,
        PUBLISHED_HEAD_SHA
    );
    let calls = calls.lock().expect("calls").clone();
    let mutation_count = calls
        .iter()
        .filter(|call| {
            matches!(
                call.as_str(),
                "POST /git/blobs" | "POST /git/trees" | "POST /git/commits" | "PATCH /git/refs"
            )
        })
        .count();
    assert_eq!(mutation_count, 5);
}

#[test]
fn approval_binding_drift_is_rejected_before_provider_mutation() {
    let at = now();
    let (connection, secret) = connection(at);
    let transport = ControlledGithubTransport::new();
    let calls = Arc::clone(&transport.calls);
    let provider = GithubPagesProvider::connect(
        connection,
        secret,
        transport,
        Arc::new(ControlledCredentialResolver),
        at,
    )
    .expect("controlled provider connects");
    let mut service = SitePublicationService::new(provider, MemoryPublicationLog::default());
    let (mut mission, site, domain) = mission_and_site(at);
    let proposal = service
        .propose(
            &mission,
            &site,
            &domain,
            PublicationProposalInput::new(
                crate::PublicationId::from_stable("publication-drift"),
                ActorId::from_stable("actor-1"),
                EffectId::from_stable("effect-drift"),
                "policy-web-publication-v1",
                at + Duration::seconds(3),
                at + Duration::seconds(30),
            ),
        )
        .expect("canonical proposal");
    let mut approval =
        approve_proposal(&mut mission, &proposal, &domain, at + Duration::seconds(4));
    approval.binding.target_revision += 1;
    let error = service
        .publish(
            &mission,
            &site,
            &domain,
            &proposal,
            &approval,
            at + Duration::seconds(5),
        )
        .expect_err("approval drift must fail closed");
    assert_eq!(error.code(), "SCOPE_MISMATCH");
    assert!(
        calls
            .lock()
            .expect("calls")
            .iter()
            .all(|call| call.starts_with("GET "))
    );
}

#[test]
fn provider_branch_protection_rejection_never_claims_receipt_or_readback() {
    let at = now();
    let (connection, secret) = connection(at);
    let transport = ControlledGithubTransport::new();
    let calls = Arc::clone(&transport.calls);
    transport.set_update_ref_error(GithubPagesTransportError::Rejected { status: 403 });
    let provider = GithubPagesProvider::connect(
        connection,
        secret,
        transport,
        Arc::new(ControlledCredentialResolver),
        at,
    )
    .expect("controlled provider connects");
    let mut service = SitePublicationService::new(provider, MemoryPublicationLog::default());
    let (mut mission, site, domain) = mission_and_site(at);
    let proposal = service
        .propose(
            &mission,
            &site,
            &domain,
            PublicationProposalInput::new(
                crate::PublicationId::from_stable("publication-403"),
                ActorId::from_stable("actor-1"),
                EffectId::from_stable("effect-403"),
                "policy-web-publication-v1",
                at + Duration::seconds(3),
                at + Duration::seconds(30),
            ),
        )
        .expect("canonical proposal");
    let approval = approve_proposal(&mut mission, &proposal, &domain, at + Duration::seconds(4));
    let error = service
        .publish(
            &mission,
            &site,
            &domain,
            &proposal,
            &approval,
            at + Duration::seconds(5),
        )
        .expect_err("branch protection must reject the controlled ref update");
    assert_eq!(error.code(), "DISCONNECTED");
    let calls = calls.lock().expect("calls").clone();
    assert!(calls.iter().any(|call| call == "PATCH /git/refs"));
    assert!(
        !calls
            .iter()
            .any(|call| call == "PUBLIC / (no Authorization)")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn rollback_is_a_new_approved_effect_with_a_new_receipt_and_readback() {
    let at = now();
    let (connection, secret) = connection(at);
    let transport = ControlledGithubTransport::new();
    let provider = GithubPagesProvider::connect(
        connection,
        secret,
        transport,
        Arc::new(ControlledCredentialResolver),
        at,
    )
    .expect("controlled provider connects");
    let mut service = SitePublicationService::new(provider, MemoryPublicationLog::default());
    let (mut mission, site, domain) = mission_and_site(at);
    let publish_proposal = service
        .propose(
            &mission,
            &site,
            &domain,
            PublicationProposalInput::new(
                crate::PublicationId::from_stable("publication-rollback-publish"),
                ActorId::from_stable("actor-1"),
                EffectId::from_stable("effect-rollback-publish"),
                "policy-web-publication-v1",
                at + Duration::seconds(3),
                at + Duration::seconds(30),
            ),
        )
        .expect("publish proposal");
    let publish_approval = approve_proposal(
        &mut mission,
        &publish_proposal,
        &domain,
        at + Duration::seconds(4),
    );
    let published = service
        .publish(
            &mission,
            &site,
            &domain,
            &publish_proposal,
            &publish_approval,
            at + Duration::seconds(5),
        )
        .expect("first publication");

    let rollback_site = Site::new(
        TenantId::from_stable("tenant-1"),
        ProjectId::from_stable("project-1"),
        SiteId::from_stable("site-1"),
        8,
        [
            SiteFile::text("index.html", "<h1>old</h1>").expect("old index"),
            SiteFile::text("old.txt", "old").expect("old file"),
        ],
        WorkProductId::from_stable("work-product-1"),
        1,
        site.source_work_product_digest.clone(),
    )
    .expect("rollback site");
    let rollback_input = crate::PublicationRollbackInput {
        proposal: PublicationProposalInput::new(
            crate::PublicationId::from_stable("publication-rollback"),
            ActorId::from_stable("actor-1"),
            EffectId::from_stable("effect-rollback"),
            "policy-web-publication-v1",
            at + Duration::seconds(7),
            at + Duration::seconds(40),
        ),
        rollback_site: rollback_site.clone(),
        expected_current_head_sha: published.receipt.commit_sha.clone(),
        expected_current_content_digest: site.content_digest.clone(),
    };
    let rollback_proposal = service
        .propose_rollback(&mission, &domain, &rollback_input)
        .expect("rollback proposal");
    let rollback_approval = approve_proposal(
        &mut mission,
        &rollback_proposal,
        &domain,
        at + Duration::seconds(8),
    );
    let rolled_back = service
        .rollback(
            &mission,
            &rollback_site,
            &domain,
            &rollback_proposal,
            &rollback_approval,
            at + Duration::seconds(9),
        )
        .expect("approved rollback");
    assert_eq!(rolled_back.action, PublicationAction::Rollback);
    assert!(rolled_back.adoptable);
    assert_eq!(
        service
            .durable_log()
            .entries
            .last()
            .map(|entry| entry.operation),
        Some(PublicationOperation::Rollback)
    );
    assert_ne!(
        rolled_back.receipt.effect_digest,
        published.receipt.effect_digest
    );
    assert_ne!(rolled_back.receipt.commit_sha, published.receipt.commit_sha);
    assert_eq!(
        rolled_back.verification.readback.expected_content_digest,
        rollback_site.content_digest
    );
    assert_eq!(mission.effects.len(), 2);
    assert!(
        mission
            .effects
            .iter()
            .all(|effect| effect.status == EffectStatus::Approved)
    );
}

#[test]
fn missing_credential_is_blocked_env_without_a_connected_provider() {
    let at = now();
    let (connection, secret) = connection(at);
    let provider = GithubPagesProvider::connect(
        connection,
        secret,
        ControlledGithubTransport::new(),
        Arc::new(BlockedEnvCredentialResolver),
        at,
    )
    .expect_err("missing credential must block the probe");
    assert_eq!(provider.code(), "BLOCKED_ENV");
    assert!(provider.to_string().contains("no Connected state"));
}

#[test]
fn revoked_registration_is_disconnected_and_cannot_be_reused() {
    let at = now();
    let (mut connection, secret) = connection(at);
    connection.revoke(at).expect("revoke registration");
    assert_eq!(
        connection.state_at(at),
        crate::GithubPagesConnectionState::Disconnected
    );
    let error = GithubPagesProvider::connect(
        connection,
        secret,
        ControlledGithubTransport::new(),
        Arc::new(ControlledCredentialResolver),
        at,
    )
    .expect_err("revoked registration must not connect");
    assert_eq!(error.code(), "DISCONNECTED");
}

#[test]
fn staging_and_production_use_distinct_target_and_registration_fences() {
    let at = now();
    let (production, secret) = connection(at);
    let staging = GithubPagesConnection::new(
        TenantId::from_stable("tenant-1"),
        ProjectId::from_stable("project-1"),
        MissionId::from_stable("mission-1"),
        hartevo_domain_kernel::ConnectionId::from_stable("connection-1"),
        hartevo_domain_kernel::AccountId::from_stable("account-1"),
        "example",
        "site",
        "main",
        "https://example.github.io/site",
        GithubPagesEnvironment::Staging,
        &secret,
    )
    .expect("valid staging connection");
    assert_ne!(
        production
            .target()
            .expect("production target")
            .configuration_digest,
        staging
            .target()
            .expect("staging target")
            .configuration_digest
    );
    assert_ne!(production.registration_digest, staging.registration_digest);
}

#[test]
fn real_transport_requires_https_and_opaque_secret_resolution_is_not_serialized() {
    assert!(crate::UreqGithubPagesTransport::new("http://api.github.com").is_err());
    assert!(crate::UreqGithubPagesTransport::new("https://api.github.com").is_ok());
    let debug = format!("{:?}", secret());
    assert!(!debug.contains(TOKEN));
}

#[test]
fn real_github_authenticated_probe_is_env_gated_and_never_uses_a_fixture() {
    if env::var("HARTEVO_GITHUB_REAL_PROBE").ok().as_deref() != Some("1") {
        return;
    }
    let Some(owner) = env::var("HARTEVO_GITHUB_REAL_OWNER").ok() else {
        return;
    };
    let Some(repository) = env::var("HARTEVO_GITHUB_REAL_REPOSITORY").ok() else {
        return;
    };
    let Some(git_ref) = env::var("HARTEVO_GITHUB_REAL_REF").ok() else {
        return;
    };
    let Some(pages_url) = env::var("HARTEVO_GITHUB_REAL_PAGES_URL").ok() else {
        return;
    };
    let account = env::var("HARTEVO_GITHUB_REAL_ACCOUNT").unwrap_or_else(|_| "real".to_owned());
    let real_scope = ConnectorScope::new(
        "tenant-real-probe",
        "project-real-probe",
        "github",
        account.as_str(),
        GITHUB_PAGES_REQUIRED_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned()),
    )
    .expect("real probe scope");
    let real_secret = SecretReference::new("secret-ref-real-probe", real_scope, 1)
        .expect("real probe SecretReference");
    let real_connection = GithubPagesConnection::new(
        TenantId::from_stable("tenant-real-probe"),
        ProjectId::from_stable("project-real-probe"),
        MissionId::from_stable("mission-real-probe"),
        hartevo_domain_kernel::ConnectionId::from_stable("connection-real-probe"),
        hartevo_domain_kernel::AccountId::from_stable(account),
        owner,
        repository,
        git_ref,
        pages_url,
        GithubPagesEnvironment::Production,
        &real_secret,
    )
    .expect("real GitHub Pages registration");
    let result = GithubPagesProvider::connect(
        real_connection,
        real_secret,
        crate::UreqGithubPagesTransport::new("https://api.github.com")
            .expect("real GitHub API transport"),
        Arc::new(EnvironmentGithubCredentialResolver::default()),
        now(),
    );
    if env::var("HARTEVO_GITHUB_TOKEN").is_err() {
        let error = result.expect_err("missing real credential is BLOCKED_ENV");
        assert_eq!(error.code(), "BLOCKED_ENV");
    } else {
        let provider = result.expect("credentialed first-party GitHub probe");
        assert_eq!(
            provider.connection_state(),
            crate::GithubPagesConnectionState::Connected
        );
    }
}

#[test]
fn checked_plugin_contract_declares_the_approval_bound_publication_seam() {
    let contract: serde_json::Value =
        serde_json::from_str(crate::GITHUB_PAGES_CONTRACT_JSON).expect("valid plugin contract");
    assert_eq!(contract["service"], crate::SITE_PUBLICATION_SERVICE);
    assert_eq!(contract["provider"], crate::GITHUB_PAGES_PROVIDER);
    assert_eq!(contract["consumer"], crate::MISSION_PUBLICATION_CONSUMER);
    assert_eq!(
        contract["operations"],
        serde_json::json!([
            "probe",
            "read",
            "prepare_effect",
            "execute",
            "reconcile",
            "verify",
            "rollback"
        ])
    );
    assert_eq!(contract["proposalOnly"], false);
    assert_eq!(contract["externalMutation"], true);
    assert_eq!(
        contract["mutationModel"],
        "non_force_git_data_commit_and_ref_update"
    );
    assert_eq!(
        contract["rollbackModel"],
        "new_effect_new_receipt_new_readback"
    );
    assert_eq!(
        contract["reconcileModel"],
        "read_only_external_state_confirmation_no_auto_replay"
    );
    assert_eq!(
        contract["independentReadback"]
            .as_array()
            .expect("readback")
            .len(),
        5
    );
    assert!(
        contract["failClosedProviderStates"]
            .as_array()
            .expect("fail closed states")
            .iter()
            .any(|state| state == "partial_commit")
    );
    assert_eq!(contract["durableModelVisibleLog"], true);
    assert_eq!(contract["registrationBinding"]["revocable"], true);
    assert_eq!(contract["claimAuthority"]["connected"], false);
    assert_eq!(contract["claimAuthority"]["providerExecution"], false);
    assert_eq!(contract["claimAuthority"]["providerReceipt"], false);
    assert_eq!(contract["claimAuthority"]["businessVerification"], false);
    assert_eq!(contract["claimAuthority"]["e4"], false);
}
