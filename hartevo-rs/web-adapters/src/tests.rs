use std::sync::{Arc, Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_connector_sdk::{ConnectorScope, SecretReference};
use hartevo_domain_kernel::{
    ActorId, EffectId, Mission, MissionContract, MissionId, ProjectId, TenantId, WorkProduct,
    WorkProductId,
};
use zeroize::Zeroizing;

use crate::{
    BlockedEnvCredentialResolver, Domain, GITHUB_PAGES_REQUIRED_SCOPES, GithubCredentialResolver,
    GithubPagesApiBlob, GithubPagesApiCommit, GithubPagesApiObject, GithubPagesApiPages,
    GithubPagesApiSource, GithubPagesApiTree, GithubPagesApiTreeEntry, GithubPagesConnection,
    GithubPagesEnvironment, GithubPagesHttpTransport, GithubPagesProvider,
    GithubPagesProviderError, GithubPagesTransportError, PublicationAuditEntry,
    PublicationDurableLog, PublicationOperation, PublicationProposalInput, Site, SiteFile, SiteId,
    SitePublicationService, WebPublicationError,
};

const TOKEN: &str = "controlled-test-token";
const HEAD_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TREE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const INDEX_SHA: &str = "cccccccccccccccccccccccccccccccccccccccc";
const OLD_SHA: &str = "dddddddddddddddddddddddddddddddddddddddd";

#[derive(Clone, Debug)]
struct ControlledGithubTransport {
    calls: Arc<Mutex<Vec<String>>>,
}

impl ControlledGithubTransport {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
        }
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
        Ok(GithubPagesApiObject {
            sha: HEAD_SHA.to_owned(),
            object_type: Some("commit".to_owned()),
        })
    }

    fn commit(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        _commit_sha: &str,
    ) -> Result<GithubPagesApiCommit, GithubPagesTransportError> {
        self.record(token, "GET /git/commits")?;
        Ok(GithubPagesApiCommit {
            sha: Some(HEAD_SHA.to_owned()),
            tree: GithubPagesApiObject {
                sha: TREE_SHA.to_owned(),
                object_type: None,
            },
        })
    }

    fn tree(
        &self,
        token: &str,
        _owner: &str,
        _repository: &str,
        _tree_sha: &str,
    ) -> Result<GithubPagesApiTree, GithubPagesTransportError> {
        self.record(token, "GET /git/trees")?;
        Ok(GithubPagesApiTree {
            sha: TREE_SHA.to_owned(),
            truncated: Some(false),
            tree: vec![
                GithubPagesApiTreeEntry {
                    path: "index.html".to_owned(),
                    sha: INDEX_SHA.to_owned(),
                    entry_type: "blob".to_owned(),
                    size: Some(12),
                },
                GithubPagesApiTreeEntry {
                    path: "old.txt".to_owned(),
                    sha: OLD_SHA.to_owned(),
                    entry_type: "blob".to_owned(),
                    size: Some(3),
                },
            ],
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
        let content = match blob_sha {
            INDEX_SHA => b"<h1>old</h1>".as_slice(),
            OLD_SHA => b"old".as_slice(),
            _ => {
                return Err(GithubPagesTransportError::Rejected { status: 404 });
            }
        };
        Ok(GithubPagesApiBlob {
            sha: Some(blob_sha.to_owned()),
            content: STANDARD.encode(content),
            encoding: "base64".to_owned(),
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
fn checked_plugin_contract_declares_the_prepare_only_seam() {
    let contract: serde_json::Value =
        serde_json::from_str(crate::GITHUB_PAGES_CONTRACT_JSON).expect("valid plugin contract");
    assert_eq!(contract["service"], crate::SITE_PUBLICATION_SERVICE);
    assert_eq!(contract["provider"], crate::GITHUB_PAGES_PROVIDER);
    assert_eq!(contract["consumer"], crate::MISSION_PUBLICATION_CONSUMER);
    assert_eq!(
        contract["operations"],
        serde_json::json!(["probe", "read", "prepare_effect"])
    );
    assert_eq!(contract["proposalOnly"], true);
    assert_eq!(contract["externalMutation"], false);
    assert_eq!(contract["durableModelVisibleLog"], true);
    assert_eq!(contract["registrationBinding"]["revocable"], true);
    assert_eq!(contract["claimAuthority"]["connected"], false);
    assert_eq!(contract["claimAuthority"]["providerExecution"], false);
    assert_eq!(contract["claimAuthority"]["providerReceipt"], false);
    assert_eq!(contract["claimAuthority"]["businessVerification"], false);
    assert_eq!(contract["claimAuthority"]["e4"], false);
}
