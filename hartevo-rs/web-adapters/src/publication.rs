use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{PreparedEffect, ReadObservation};
use hartevo_domain_kernel::{
    ActorId, ConsentState, CurrencyCode, EffectClass, EffectId, EffectRisk, EffectSpec, Mission,
    Money, WorkProductStatus,
};
use serde::{Deserialize, Serialize};

use crate::audit::{PublicationAuditEntry, PublicationDurableLog, PublicationOperation};
use crate::{
    Domain, GITHUB_PAGES_REQUIRED_SCOPES, GITHUB_PROVIDER_ID, GithubPagesProvider,
    GithubPagesProviderRead, GithubPagesRepositorySnapshot, Publication, PublicationId, Site,
    WebPublicationError, digest_json,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalDiffKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalDiffEntry {
    pub path: String,
    pub kind: CanonicalDiffKind,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub before_size: Option<u64>,
    pub after_size: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalTreeDiff {
    pub base_head_sha: String,
    pub base_tree_sha: String,
    pub target_tree_digest: String,
    pub entries: Vec<CanonicalDiffEntry>,
    pub diff_digest: String,
}

impl CanonicalTreeDiff {
    pub fn between(
        site: &Site,
        current: &GithubPagesRepositorySnapshot,
    ) -> Result<Self, WebPublicationError> {
        let target = site.files.iter().map(|file| (file.path.as_str(), file));
        let target = target.collect::<BTreeMap<_, _>>();
        let base = current
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect::<BTreeMap<_, _>>();
        let paths = target
            .keys()
            .chain(base.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut entries = Vec::new();
        for path in paths {
            match (base.get(path), target.get(path)) {
                (None, Some(after)) => entries.push(CanonicalDiffEntry {
                    path: path.to_owned(),
                    kind: CanonicalDiffKind::Added,
                    before_digest: None,
                    after_digest: Some(after.content_digest.clone()),
                    before_size: None,
                    after_size: Some(after.content.len() as u64),
                }),
                (Some(before), None) => entries.push(CanonicalDiffEntry {
                    path: path.to_owned(),
                    kind: CanonicalDiffKind::Deleted,
                    before_digest: Some(before.content_digest.clone()),
                    after_digest: None,
                    before_size: Some(before.content.len() as u64),
                    after_size: None,
                }),
                (Some(before), Some(after)) if before.content_digest != after.content_digest => {
                    entries.push(CanonicalDiffEntry {
                        path: path.to_owned(),
                        kind: CanonicalDiffKind::Modified,
                        before_digest: Some(before.content_digest.clone()),
                        after_digest: Some(after.content_digest.clone()),
                        before_size: Some(before.content.len() as u64),
                        after_size: Some(after.content.len() as u64),
                    });
                }
                (Some(_), Some(_)) | (None, None) => {}
            }
        }
        let target_tree_digest = crate::file_tree_digest(&site.files);
        let diff_digest = digest_json(&(
            &current.head_sha,
            &current.tree_sha,
            &target_tree_digest,
            &entries,
        ))?;
        Ok(Self {
            base_head_sha: current.head_sha.clone(),
            base_tree_sha: current.tree_sha.clone(),
            target_tree_digest,
            entries,
            diff_digest,
        })
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationReadResult {
    pub publication: Publication,
    pub snapshot: GithubPagesRepositorySnapshot,
    pub observation: ReadObservation,
    pub registration_digest: String,
    pub registry_version: String,
    pub result_digest: String,
}

impl PublicationReadResult {
    fn new(
        publication: Publication,
        provider_read: GithubPagesProviderRead,
    ) -> Result<Self, WebPublicationError> {
        let result_digest = digest_json(&(
            &publication,
            &provider_read.snapshot.target,
            &provider_read.snapshot.head_sha,
            &provider_read.snapshot.tree_sha,
            &provider_read.snapshot.content_digest,
            &provider_read.snapshot.tree_digest,
            &provider_read.observation,
            &provider_read.registration_digest,
            &provider_read.registry_version,
        ))?;
        Ok(Self {
            publication,
            snapshot: provider_read.snapshot,
            observation: provider_read.observation,
            registration_digest: provider_read.registration_digest,
            registry_version: provider_read.registry_version,
            result_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionPublicationReadResult {
    pub tenant_id: hartevo_domain_kernel::TenantId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub publication_read: PublicationReadResult,
    pub model_visible: bool,
    pub result_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationProposalInput {
    pub publication_id: PublicationId,
    pub actor_id: ActorId,
    pub effect_id: EffectId,
    pub policy_version: String,
    pub now: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PublicationProposalInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publication_id: PublicationId,
        actor_id: ActorId,
        effect_id: EffectId,
        policy_version: impl Into<String>,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            publication_id,
            actor_id,
            effect_id,
            policy_version: policy_version.into(),
            now,
            expires_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedPublicationEffect {
    pub effect_spec: EffectSpec,
    pub connector_effect: PreparedEffect,
    pub prepared_only: bool,
    pub external_effect_created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionPublicationProposalResult {
    pub tenant_id: hartevo_domain_kernel::TenantId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub publication_read: PublicationReadResult,
    pub canonical_diff: CanonicalTreeDiff,
    pub target_revision: u64,
    pub prepared_effect: PreparedPublicationEffect,
    pub proposal_digest: String,
    pub preview_only: bool,
    pub external_effect_created: bool,
    pub publish_authority: String,
}

pub trait PublicationResultConsumer {
    fn consume_read(
        &self,
        mission: &Mission,
        result: PublicationReadResult,
    ) -> Result<MissionPublicationReadResult, WebPublicationError>;

    fn consume_proposal(
        &self,
        mission: &Mission,
        result: MissionPublicationProposalResult,
    ) -> Result<MissionPublicationProposalResult, WebPublicationError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MissionPublicationConsumer;

impl PublicationResultConsumer for MissionPublicationConsumer {
    fn consume_read(
        &self,
        mission: &Mission,
        result: PublicationReadResult,
    ) -> Result<MissionPublicationReadResult, WebPublicationError> {
        if result.publication.tenant_id != mission.tenant_id
            || result.publication.project_id != mission.project_id
            || result.publication.mission_id != mission.id
        {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "Mission consumer rejected a publication result outside its scope"
                    .to_owned(),
            });
        }
        let result_digest = digest_json(&(
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            mission.id.as_str(),
            &result.result_digest,
        ))?;
        Ok(MissionPublicationReadResult {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            publication_read: result,
            model_visible: true,
            result_digest,
        })
    }

    fn consume_proposal(
        &self,
        mission: &Mission,
        result: MissionPublicationProposalResult,
    ) -> Result<MissionPublicationProposalResult, WebPublicationError> {
        if result.tenant_id != mission.tenant_id
            || result.project_id != mission.project_id
            || result.mission_id != mission.id
            || result.publication_read.publication.tenant_id != mission.tenant_id
            || result.publication_read.publication.project_id != mission.project_id
            || result.publication_read.publication.mission_id != mission.id
            || !result.preview_only
            || result.external_effect_created
            || !result.prepared_effect.prepared_only
            || result.prepared_effect.effect_spec.capability != "publication.publish"
            || result.prepared_effect.effect_spec.provider != GITHUB_PROVIDER_ID
            || result.prepared_effect.effect_spec.effect_class != EffectClass::ExternalWrite
            || result
                .prepared_effect
                .effect_spec
                .connection_id
                .as_ref()
                .map(hartevo_domain_kernel::ConnectionId::as_str)
                != Some(result.publication_read.publication.connection_id.as_str())
            || result.publish_authority != "deferred_until_approval_and_execute"
        {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "Mission consumer rejected a non-preview or out-of-scope proposal"
                    .to_owned(),
            });
        }
        Ok(result)
    }
}

pub struct SitePublicationService<T, R, L>
where
    T: crate::GithubPagesHttpTransport,
    R: crate::GithubCredentialResolver,
    L: PublicationDurableLog,
{
    provider: GithubPagesProvider<T, R>,
    durable_log: L,
    consumer: MissionPublicationConsumer,
}

impl<T, R, L> fmt::Debug for SitePublicationService<T, R, L>
where
    T: crate::GithubPagesHttpTransport,
    R: crate::GithubCredentialResolver,
    L: PublicationDurableLog,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SitePublicationService")
            .field("provider", &self.provider)
            .field("consumer", &self.consumer)
            .finish_non_exhaustive()
    }
}

impl<T, R, L> SitePublicationService<T, R, L>
where
    T: crate::GithubPagesHttpTransport,
    R: crate::GithubCredentialResolver,
    L: PublicationDurableLog,
{
    pub fn new(provider: GithubPagesProvider<T, R>, durable_log: L) -> Self {
        Self {
            provider,
            durable_log,
            consumer: MissionPublicationConsumer,
        }
    }

    pub fn provider(&self) -> &GithubPagesProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GithubPagesProvider<T, R> {
        &mut self.provider
    }

    pub fn durable_log(&self) -> &L {
        &self.durable_log
    }

    pub fn durable_log_mut(&mut self) -> &mut L {
        &mut self.durable_log
    }

    pub fn read(
        &mut self,
        mission: &Mission,
        site: &Site,
        domain: &Domain,
        publication_id: PublicationId,
        now: DateTime<Utc>,
    ) -> Result<MissionPublicationReadResult, WebPublicationError> {
        let publication = self.validate_context(mission, site, domain, publication_id)?;
        let result = self.read_publication(mission, site, publication, now)?;
        self.append_read_audit(&result)?;
        self.consumer.consume_read(mission, result)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the service consumes one immutable proposal command as the boundary input"
    )]
    pub fn propose(
        &mut self,
        mission: &Mission,
        site: &Site,
        domain: &Domain,
        input: PublicationProposalInput,
    ) -> Result<MissionPublicationProposalResult, WebPublicationError> {
        Self::validate_proposal_input(mission, &input)?;
        let publication =
            self.validate_context(mission, site, domain, input.publication_id.clone())?;
        let read_result = self.read_publication(mission, site, publication, input.now)?;
        self.append_read_audit(&read_result)?;
        let canonical_diff = CanonicalTreeDiff::between(site, &read_result.snapshot)?;
        let payload_digest = proposal_payload_digest(&read_result, &canonical_diff, site)?;
        let connector_effect = self.provider.prepare_publish(
            &payload_digest,
            &format!("effect-idem-{payload_digest}"),
            input.now,
            input.expires_at,
        )?;
        let effect_spec = effect_spec(
            mission,
            site,
            &read_result.publication,
            &canonical_diff,
            &input,
            &payload_digest,
        )?;
        if connector_effect.payload_digest() != effect_spec.payload_digest
            || connector_effect.idempotency_key() != effect_spec.idempotency_key
        {
            return Err(WebPublicationError::Provider {
                detail: "Connector SDK prepare-effect binding differs from Mission EffectSpec"
                    .to_owned(),
            });
        }
        let prepared_effect = PreparedPublicationEffect {
            effect_spec,
            connector_effect,
            prepared_only: true,
            external_effect_created: false,
        };
        let proposal_digest = digest_json(&(
            &read_result.result_digest,
            &canonical_diff,
            &prepared_effect.effect_spec,
            prepared_effect.connector_effect.effect_digest(),
            input.now,
            input.expires_at,
        ))?;
        let result = MissionPublicationProposalResult {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            publication_read: read_result,
            target_revision: site.revision,
            canonical_diff,
            prepared_effect,
            proposal_digest,
            preview_only: true,
            external_effect_created: false,
            publish_authority: "deferred_until_approval_and_execute".to_owned(),
        };
        self.append_proposal_audit(&result)?;
        self.consumer.consume_proposal(mission, result)
    }

    fn validate_context(
        &self,
        mission: &Mission,
        site: &Site,
        domain: &Domain,
        publication_id: PublicationId,
    ) -> Result<Publication, WebPublicationError> {
        if mission.tenant_id != site.tenant_id
            || mission.project_id != site.project_id
            || mission.tenant_id != domain.tenant_id
            || mission.project_id != domain.project_id
        {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "Mission, Site, and Domain must share tenant/project scope".to_owned(),
            });
        }
        site.validate()?;
        domain.validate()?;
        let connection = self.provider.connection();
        if connection.tenant_id != mission.tenant_id
            || connection.project_id != mission.project_id
            || connection.mission_id != mission.id
        {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "GitHub Pages connection is not registered to this Mission scope"
                    .to_owned(),
            });
        }
        validate_source_work_product(mission, site)?;
        Publication::new(
            mission,
            site,
            domain,
            publication_id,
            connection.connection_id.as_str(),
            connection.target()?,
        )
    }

    fn validate_proposal_input(
        mission: &Mission,
        input: &PublicationProposalInput,
    ) -> Result<(), WebPublicationError> {
        if !mission
            .contract
            .enabled_capabilities
            .contains("publication.publish")
            || mission
                .contract
                .forbidden_capabilities
                .contains("publication.publish")
        {
            return Err(WebPublicationError::Contract {
                detail: "Mission contract does not enable publication.publish".to_owned(),
            });
        }
        if input.policy_version.trim().is_empty()
            || input.effect_id.as_str().trim().is_empty()
            || input.expires_at <= input.now
            || input.now >= mission.contract.valid_until
            || input.expires_at > mission.contract.valid_until
        {
            return Err(WebPublicationError::Contract {
                detail: "publication proposal must have a bounded policy and expiry".to_owned(),
            });
        }
        Ok(())
    }

    fn read_publication(
        &mut self,
        _mission: &Mission,
        _site: &Site,
        publication: Publication,
        now: DateTime<Utc>,
    ) -> Result<PublicationReadResult, WebPublicationError> {
        let provider_read = self.provider.read_current(now)?;
        PublicationReadResult::new(publication, provider_read)
    }

    fn append_read_audit(
        &mut self,
        result: &PublicationReadResult,
    ) -> Result<(), WebPublicationError> {
        let entry = audit_entry(PublicationOperation::Read, result, None, None)?;
        self.durable_log.append(entry)
    }

    fn append_proposal_audit(
        &mut self,
        result: &MissionPublicationProposalResult,
    ) -> Result<(), WebPublicationError> {
        let entry = audit_entry(
            PublicationOperation::Proposal,
            &result.publication_read,
            Some(&result.canonical_diff.diff_digest),
            Some(result.prepared_effect.connector_effect.effect_digest()),
        )?;
        self.durable_log.append(entry)
    }
}

fn validate_source_work_product(mission: &Mission, site: &Site) -> Result<(), WebPublicationError> {
    let work_product = mission
        .work_products
        .iter()
        .find(|work_product| work_product.id == site.source_work_product_id)
        .ok_or_else(|| WebPublicationError::ScopeMismatch {
            detail: "Site source Work Product is not attached to the Mission".to_owned(),
        })?;
    if !matches!(
        work_product.status,
        WorkProductStatus::ReadyForReview | WorkProductStatus::Accepted
    ) {
        return Err(WebPublicationError::Contract {
            detail: "only a reviewable or accepted Work Product can be proposed".to_owned(),
        });
    }
    if work_product.revision != site.source_work_product_revision
        || work_product.content_digest != site.source_work_product_digest
    {
        return Err(WebPublicationError::ScopeMismatch {
            detail: "Site source Work Product revision or digest is stale".to_owned(),
        });
    }
    Ok(())
}

fn proposal_payload_digest(
    read_result: &PublicationReadResult,
    canonical_diff: &CanonicalTreeDiff,
    site: &Site,
) -> Result<String, WebPublicationError> {
    let publication_digest = read_result.publication.digest();
    digest_json(&(
        &publication_digest,
        &read_result.publication,
        &read_result.snapshot.target,
        &read_result.snapshot.head_sha,
        &read_result.snapshot.tree_sha,
        &read_result.snapshot.content_digest,
        &canonical_diff.diff_digest,
        &canonical_diff.target_tree_digest,
        &site.revision,
        &site.content_digest,
        &site.source_work_product_id,
        &site.source_work_product_revision,
        &site.source_work_product_digest,
    ))
}

fn effect_spec(
    _mission: &Mission,
    site: &Site,
    publication: &Publication,
    canonical_diff: &CanonicalTreeDiff,
    input: &PublicationProposalInput,
    payload_digest: &str,
) -> Result<EffectSpec, WebPublicationError> {
    let currency =
        CurrencyCode::parse("USD").map_err(|error| WebPublicationError::InvalidInput {
            detail: error.to_string(),
        })?;
    let mut asset_digests = BTreeSet::new();
    asset_digests.insert(site.content_digest.clone());
    asset_digests.insert(site.source_work_product_digest.clone());
    asset_digests.insert(canonical_diff.diff_digest.clone());
    asset_digests.insert(publication.target.configuration_digest.clone());
    Ok(EffectSpec {
        id: input.effect_id.clone(),
        actor_id: input.actor_id.clone(),
        capability: "publication.publish".to_owned(),
        provider: GITHUB_PROVIDER_ID.to_owned(),
        connection_id: Some(hartevo_domain_kernel::ConnectionId::from_stable(
            publication.connection_id.clone(),
        )),
        account_id: Some(hartevo_domain_kernel::AccountId::from_stable(
            publication.target.account_id.clone(),
        )),
        required_scopes: GITHUB_PAGES_REQUIRED_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        effect_class: EffectClass::ExternalWrite,
        description: format!(
            "Publish Site revision {} to GitHub Pages {}",
            site.revision, publication.target.pages_url
        ),
        target_resource: format!(
            "github-pages/{}/{}/{}/{}",
            publication.target.owner,
            publication.target.repository,
            publication.target.git_ref,
            publication.target.environment.as_str()
        ),
        audience_digest: Some(crate::digest_parts([
            publication.domain_id.as_str(),
            publication.target.pages_url.as_str(),
        ])),
        payload_digest: payload_digest.to_owned(),
        asset_digests,
        scheduled_for: None,
        timezone: "UTC".to_owned(),
        consent: ConsentState::NotRequired,
        consent_record_id: None,
        consent_requirement: None,
        conversation_guard: None,
        creator_contact_guard: None,
        policy_version: input.policy_version.clone(),
        risk: EffectRisk::Medium,
        idempotency_key: format!("effect-idem-{payload_digest}"),
        amount: Money::zero(currency),
        expires_at: input.expires_at,
    })
}

fn audit_entry(
    operation: PublicationOperation,
    result: &PublicationReadResult,
    diff_digest: Option<&str>,
    effect_digest: Option<&str>,
) -> Result<PublicationAuditEntry, WebPublicationError> {
    let target = &result.publication.target;
    let file_count = u32::try_from(result.snapshot.files.len()).map_err(|_| {
        WebPublicationError::InvalidInput {
            detail: "repository file count exceeds audit bounds".to_owned(),
        }
    })?;
    PublicationAuditEntry {
        schema_version: crate::WEB_PUBLICATION_SCHEMA_VERSION.to_owned(),
        event_id: format!(
            "publication-{}-{}",
            result.publication.id,
            result.observation.observation_id()
        ),
        event_digest: String::new(),
        operation,
        model_visible: true,
        tenant_id: result.publication.tenant_id.clone(),
        project_id: result.publication.project_id.clone(),
        mission_id: result.publication.mission_id.clone(),
        connection_id: result.publication.connection_id.clone(),
        account_id: target.account_id.clone(),
        registration_digest: result.registration_digest.clone(),
        registry_version: result.registry_version.clone(),
        scope_digest: result.observation.scope().digest(),
        plugin_version: crate::GITHUB_PAGES_PLUGIN_VERSION.to_owned(),
        adapter_id: result.observation.adapter().adapter_id().to_owned(),
        adapter_version: result.observation.adapter().adapter_version(),
        environment: target.environment,
        owner: target.owner.clone(),
        repository: target.repository.clone(),
        git_ref: target.git_ref.clone(),
        pages_url: target.pages_url.clone(),
        source_work_product_id: result.publication.source_work_product_id.clone(),
        source_work_product_revision: result.publication.source_work_product_revision,
        source_work_product_digest: result.publication.source_work_product_digest.clone(),
        site_revision: result.publication.site_revision,
        base_head_sha: result.snapshot.head_sha.clone(),
        base_tree_sha: result.snapshot.tree_sha.clone(),
        observed_content_digest: result.snapshot.content_digest.clone(),
        observed_tree_digest: result.snapshot.tree_digest.clone(),
        observed_file_count: file_count,
        result_digest: result.result_digest.clone(),
        diff_digest: diff_digest.map(str::to_owned),
        effect_digest: effect_digest.map(str::to_owned),
        observed_at: result.snapshot.observed_at,
    }
    .finalize()
}
