//! Web publication plugin vertical slice.
//!
//! This module is intentionally web-publication-specific. It binds a real
//! Mission WorkProductManifest to a site revision, asks the registered
//! provider for a canonical preview, proposes an approval-bound Effect, and
//! consumes only the Broker's receipt plus independent readback as an
//! adoptable result.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AccountId, ActorId, ConnectionId, CurrencyCode, Effect, EffectClass, EffectId, EffectRisk,
    EffectSpec, EffectStatus, Mission, MissionError, Money, PublicationEnvironment, PublicationId,
    PublicationPublishRequest, PublicationTarget, PublicationWorkProductSelection, SiteId,
    SitePreview, SiteRevision, VerificationStatus, WebPublicationError, WorkProductId,
    WorkProductManifest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::github_pages::{
    GITHUB_PAGES_PROVIDER, GithubPagesError, GithubPagesExecutor, GithubPagesReadbackTransport,
    GithubPagesRepositorySnapshot, GithubPagesRepositoryTransport, GithubPagesTargets,
};
use crate::{BrokerError, BrokerResult, EffectBroker, EffectInfrastructure};

pub const WEB_PUBLICATION_PLUGIN_ID: &str = "hartevo.web-publication.github-pages/v1";
const REQUIRED_GITHUB_SCOPES: [&str; 3] = ["contents:read", "contents:write", "pages:read"];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationPluginConnectionStatus {
    Disconnected,
    Connected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPagesPluginRegistration {
    pub provider_id: String,
    pub connection_id: ConnectionId,
    pub account_id: String,
    pub scopes: BTreeSet<String>,
    pub staging_configuration_digest: String,
    pub production_configuration_digest: String,
}

impl GithubPagesPluginRegistration {
    pub fn new(
        connection_id: ConnectionId,
        account_id: impl Into<String>,
        scopes: impl IntoIterator<Item = String>,
        staging_configuration_digest: impl Into<String>,
        production_configuration_digest: impl Into<String>,
    ) -> Result<Self, WebPublicationPluginError> {
        let registration = Self {
            provider_id: GITHUB_PAGES_PROVIDER.into(),
            connection_id,
            account_id: account_id.into(),
            scopes: scopes.into_iter().collect(),
            staging_configuration_digest: staging_configuration_digest.into(),
            production_configuration_digest: production_configuration_digest.into(),
        };
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), WebPublicationPluginError> {
        if self.provider_id != GITHUB_PAGES_PROVIDER
            || self.connection_id.as_str().trim().is_empty()
            || self.account_id.trim().is_empty()
            || REQUIRED_GITHUB_SCOPES
                .iter()
                .any(|scope| !self.scopes.contains(*scope))
            || !is_digest(&self.staging_configuration_digest)
            || !is_digest(&self.production_configuration_digest)
        {
            return Err(WebPublicationPluginError::InvalidRegistration);
        }
        Ok(())
    }

    fn configuration_digest(&self, environment: PublicationEnvironment) -> &str {
        match environment {
            PublicationEnvironment::Staging => &self.staging_configuration_digest,
            PublicationEnvironment::Production => &self.production_configuration_digest,
        }
    }
}

#[derive(Debug)]
enum GithubPagesPluginProviderState<P> {
    Disconnected,
    Connected {
        registration: GithubPagesPluginRegistration,
        executor: Box<GithubPagesExecutor<P>>,
        verifier: Box<crate::github_pages::GithubPagesVerifier<P>>,
        reconciler: Box<crate::github_pages::GithubPagesReconciler<P>>,
    },
}

#[derive(Debug)]
pub struct GithubPagesPublicationPluginProvider<P> {
    targets: GithubPagesTargets,
    state: GithubPagesPluginProviderState<P>,
}

impl<P> GithubPagesPublicationPluginProvider<P> {
    pub fn disconnected(targets: GithubPagesTargets) -> Result<Self, WebPublicationPluginError> {
        targets.validate()?;
        Ok(Self {
            targets,
            state: GithubPagesPluginProviderState::Disconnected,
        })
    }

    pub fn connection_status(&self) -> PublicationPluginConnectionStatus {
        match self.state {
            GithubPagesPluginProviderState::Disconnected => {
                PublicationPluginConnectionStatus::Disconnected
            }
            GithubPagesPluginProviderState::Connected { .. } => {
                PublicationPluginConnectionStatus::Connected
            }
        }
    }

    pub fn registration(&self) -> Option<&GithubPagesPluginRegistration> {
        match &self.state {
            GithubPagesPluginProviderState::Disconnected => None,
            GithubPagesPluginProviderState::Connected { registration, .. } => Some(registration),
        }
    }

    fn require_registration(
        &self,
    ) -> Result<&GithubPagesPluginRegistration, WebPublicationPluginError> {
        self.registration()
            .ok_or(WebPublicationPluginError::Disconnected)
    }

    fn target_for(
        &self,
        environment: PublicationEnvironment,
    ) -> Result<PublicationTarget, WebPublicationPluginError> {
        let registration = self.require_registration()?;
        Ok(self.targets.target(
            environment,
            registration.account_id.clone(),
            registration.configuration_digest(environment),
        ))
    }
}

impl<P> GithubPagesPublicationPluginProvider<P>
where
    P: Clone + GithubPagesRepositoryTransport + GithubPagesReadbackTransport,
{
    pub fn connect(
        targets: GithubPagesTargets,
        registration: GithubPagesPluginRegistration,
        transport: P,
    ) -> Result<Self, WebPublicationPluginError> {
        targets.validate()?;
        registration.validate()?;
        let executor = GithubPagesExecutor::new(targets.clone(), transport.clone())?;
        let verifier =
            crate::github_pages::GithubPagesVerifier::new(targets.clone(), transport.clone())?;
        let reconciler =
            crate::github_pages::GithubPagesReconciler::new(targets.clone(), transport)?;
        Ok(Self {
            targets,
            state: GithubPagesPluginProviderState::Connected {
                registration,
                executor: Box::new(executor),
                verifier: Box::new(verifier),
                reconciler: Box::new(reconciler),
            },
        })
    }

    pub fn read_snapshot(
        &mut self,
        environment: PublicationEnvironment,
    ) -> Result<GithubPagesRepositorySnapshot, WebPublicationPluginError> {
        match &mut self.state {
            GithubPagesPluginProviderState::Disconnected => {
                Err(WebPublicationPluginError::Disconnected)
            }
            GithubPagesPluginProviderState::Connected { executor, .. } => {
                Ok(executor.read_snapshot(environment)?)
            }
        }
    }

    fn register_publish(
        &mut self,
        effect_id: EffectId,
        request: PublicationPublishRequest,
    ) -> Result<(), WebPublicationPluginError> {
        match &mut self.state {
            GithubPagesPluginProviderState::Disconnected => {
                Err(WebPublicationPluginError::Disconnected)
            }
            GithubPagesPluginProviderState::Connected {
                executor,
                verifier,
                reconciler,
                ..
            } => {
                executor.register(effect_id.clone(), request.clone())?;
                verifier.register(effect_id.clone(), request.clone())?;
                reconciler.register(effect_id, request)?;
                Ok(())
            }
        }
    }

    fn execute(
        &mut self,
        broker: &mut EffectBroker,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        now: DateTime<Utc>,
    ) -> Result<BrokerResult, WebPublicationPluginError> {
        match &mut self.state {
            GithubPagesPluginProviderState::Disconnected => {
                Err(WebPublicationPluginError::Disconnected)
            }
            GithubPagesPluginProviderState::Connected {
                executor, verifier, ..
            } => Ok(broker.execute_and_verify(
                mission,
                effect_id,
                infrastructure,
                &mut **executor,
                &mut **verifier,
                now,
            )?),
        }
    }

    fn reconcile(
        &mut self,
        broker: &mut EffectBroker,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        now: DateTime<Utc>,
    ) -> Result<BrokerResult, WebPublicationPluginError> {
        match &mut self.state {
            GithubPagesPluginProviderState::Disconnected => {
                Err(WebPublicationPluginError::Disconnected)
            }
            GithubPagesPluginProviderState::Connected {
                reconciler,
                verifier,
                ..
            } => Ok(broker.reconcile_uncertain(
                mission,
                effect_id,
                infrastructure,
                &mut **reconciler,
                &mut **verifier,
                now,
            )?),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicationPluginPreviewInput<'a> {
    pub mission: &'a Mission,
    pub site_id: SiteId,
    pub domain_id: hartevo_domain_kernel::DomainId,
    pub deployment_id: hartevo_domain_kernel::DeploymentId,
    pub publication_id: PublicationId,
    pub work_product_id: &'a WorkProductId,
    pub manifest: &'a WorkProductManifest,
    pub site_revision: SiteRevision,
    pub environment: PublicationEnvironment,
    pub base_revision: u64,
    pub preview_url: Option<String>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct PublicationPluginPreview {
    pub selection: PublicationWorkProductSelection,
    pub manifest: WorkProductManifest,
    pub request: PublicationPublishRequest,
    pub publication_id: PublicationId,
    pub provider_status: PublicationPluginConnectionStatus,
    pub base_head_sha: String,
    pub result_url: String,
    pub external_effect_created: bool,
}

#[derive(Clone, Debug)]
pub struct PublicationPluginPublishInput {
    pub actor_id: ActorId,
    pub effect_id: EffectId,
    pub policy_version: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct PublicationPluginPublishPlan {
    pub effect_id: EffectId,
    pub request: PublicationPublishRequest,
    pub selection: PublicationWorkProductSelection,
    pub result_url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationAdoptableResult {
    pub plugin_id: String,
    pub provider: String,
    pub effect_id: EffectId,
    pub result_url: String,
    pub source_mission_revision: u64,
    pub source_work_product_id: WorkProductId,
    pub source_work_product_revision: u64,
    pub source_revision: u64,
    pub source_digest: String,
    pub source_manifest_digest: String,
    pub preview_digest: String,
    pub payload_digest: String,
    pub receipt_external_id: String,
    pub receipt_request_digest: String,
    pub receipt_response_digest: String,
    pub verification_status: VerificationStatus,
    pub readback_evidence_digest: String,
    pub inline_summary: String,
    pub adoptable: bool,
    pub consumed_at: DateTime<Utc>,
}

pub trait PublicationPluginConsumer {
    fn consume(
        &self,
        plan: &PublicationPluginPublishPlan,
        effect: &Effect,
        result: &BrokerResult,
        consumed_at: DateTime<Utc>,
    ) -> Result<PublicationAdoptableResult, WebPublicationPluginError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InlinePublicationConsumer;

impl PublicationPluginConsumer for InlinePublicationConsumer {
    fn consume(
        &self,
        plan: &PublicationPluginPublishPlan,
        effect: &Effect,
        result: &BrokerResult,
        consumed_at: DateTime<Utc>,
    ) -> Result<PublicationAdoptableResult, WebPublicationPluginError> {
        if effect.id != plan.effect_id
            || effect.status != EffectStatus::Verified
            || result.receipt.request_digest != effect.approval_digest()
            || result.verification.status != VerificationStatus::Confirmed
            || !result.verification.independent
            || result.verification.receipt_id != result.receipt.id
        {
            return Err(WebPublicationPluginError::ResultNotAdoptable);
        }
        Ok(PublicationAdoptableResult {
            plugin_id: WEB_PUBLICATION_PLUGIN_ID.into(),
            provider: result.receipt.provider.clone(),
            effect_id: plan.effect_id.clone(),
            result_url: plan.result_url.clone(),
            source_mission_revision: plan.selection.mission_revision,
            source_work_product_id: plan.selection.work_product_id.clone(),
            source_work_product_revision: plan.selection.work_product_revision,
            source_revision: plan.selection.site_revision.revision,
            source_digest: plan.selection.site_revision.artifact_digest.clone(),
            source_manifest_digest: plan.selection.manifest_digest.clone(),
            preview_digest: plan.request.preview.preview_digest.clone(),
            payload_digest: plan.request.payload_digest.clone(),
            receipt_external_id: result.receipt.external_id.clone(),
            receipt_request_digest: result.receipt.request_digest.clone(),
            receipt_response_digest: result.receipt.response_digest.clone(),
            verification_status: result.verification.status.clone(),
            readback_evidence_digest: result.verification.evidence_digest.clone(),
            inline_summary: format!(
                "Published WorkProduct r{} from source revision r{}; independent readback confirmed.",
                plan.selection.work_product_revision, plan.selection.site_revision.revision
            ),
            adoptable: true,
            consumed_at,
        })
    }
}

#[derive(Debug)]
pub struct WebPublicationPluginService<P, C = InlinePublicationConsumer> {
    provider: GithubPagesPublicationPluginProvider<P>,
    consumer: C,
}

impl<P> WebPublicationPluginService<P, InlinePublicationConsumer> {
    pub fn disconnected(targets: GithubPagesTargets) -> Result<Self, WebPublicationPluginError> {
        Ok(Self {
            provider: GithubPagesPublicationPluginProvider::disconnected(targets)?,
            consumer: InlinePublicationConsumer,
        })
    }
}

impl<P, C> WebPublicationPluginService<P, C> {
    pub fn with_provider(provider: GithubPagesPublicationPluginProvider<P>, consumer: C) -> Self {
        Self { provider, consumer }
    }

    pub fn connection_status(&self) -> PublicationPluginConnectionStatus {
        self.provider.connection_status()
    }

    pub fn provider(&self) -> &GithubPagesPublicationPluginProvider<P> {
        &self.provider
    }
}

impl<P, C> WebPublicationPluginService<P, C>
where
    P: Clone + GithubPagesRepositoryTransport + GithubPagesReadbackTransport,
    C: PublicationPluginConsumer,
{
    pub fn connect(
        targets: GithubPagesTargets,
        registration: GithubPagesPluginRegistration,
        transport: P,
        consumer: C,
    ) -> Result<Self, WebPublicationPluginError> {
        Ok(Self::with_provider(
            GithubPagesPublicationPluginProvider::connect(targets, registration, transport)?,
            consumer,
        ))
    }

    pub fn preview(
        &mut self,
        input: &PublicationPluginPreviewInput<'_>,
    ) -> Result<PublicationPluginPreview, WebPublicationPluginError> {
        let snapshot = self.provider.read_snapshot(input.environment)?;
        let selection = PublicationWorkProductSelection::from_mission(
            input.mission,
            &input.site_id,
            input.work_product_id,
            input.manifest,
            input.site_revision.clone(),
        )?;
        let target = self.provider.target_for(input.environment)?;
        let base_files = snapshot
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != crate::github_pages::GITHUB_PAGES_MANIFEST_PATH)
            .map(|(path, content)| (path.clone(), content.clone()))
            .collect();
        let preview = SitePreview::new(
            selection.site_revision.artifact_digest.clone(),
            &selection.preview.text,
            input.preview_url.clone(),
            input.now,
        )?;
        let request = PublicationPublishRequest::new(
            selection.site_id.clone(),
            input.domain_id.clone(),
            input.deployment_id.clone(),
            input.environment,
            target,
            selection.site_revision.revision,
            input.base_revision,
            sha256(snapshot.head_sha.as_bytes()),
            &base_files,
            selection.site_revision.files.clone(),
            preview,
            input.now,
        )?;
        Ok(PublicationPluginPreview {
            selection,
            manifest: input.manifest.clone(),
            publication_id: input.publication_id.clone(),
            result_url: request.target.url.clone(),
            request,
            provider_status: self.connection_status(),
            base_head_sha: snapshot.head_sha,
            external_effect_created: false,
        })
    }

    pub fn propose_publish(
        &mut self,
        mission: &mut Mission,
        preview: PublicationPluginPreview,
        input: PublicationPluginPublishInput,
        now: DateTime<Utc>,
    ) -> Result<PublicationPluginPublishPlan, WebPublicationPluginError> {
        let registration = self.provider.require_registration()?.clone();
        if !preview.selection.is_adoptable()
            || preview.selection.mission_revision != mission.revision
            || preview.selection.mission_id != mission.id
            || preview.selection.project_id != mission.project_id
            || preview.request.site_id != preview.selection.site_id
        {
            return Err(WebPublicationPluginError::SourceChanged);
        }
        let rebound_selection = PublicationWorkProductSelection::from_mission(
            mission,
            &preview.selection.site_id,
            &preview.selection.work_product_id,
            &preview.manifest,
            preview.selection.site_revision.clone(),
        )
        .map_err(|_| WebPublicationPluginError::SourceChanged)?;
        let current_snapshot = self.provider.read_snapshot(preview.request.environment)?;
        let expected_target = self.provider.target_for(preview.request.environment)?;
        let request = preview.request;
        if rebound_selection != preview.selection
            || current_snapshot.head_sha != preview.base_head_sha
            || sha256(current_snapshot.head_sha.as_bytes())
                != request.canonical_diff.base_authority_digest
            || request.target != expected_target
            || request.source_revision != preview.selection.site_revision.revision
            || request.files != preview.selection.site_revision.files
            || request.preview.artifact_digest != preview.selection.site_revision.artifact_digest
            || request.preview.preview_digest != preview.selection.preview.content_digest
        {
            return Err(WebPublicationPluginError::SourceChanged);
        }
        request.validate()?;
        let effect_spec = EffectSpec {
            id: input.effect_id.clone(),
            actor_id: input.actor_id,
            capability: "publication.publish".into(),
            provider: GITHUB_PAGES_PROVIDER.into(),
            connection_id: Some(registration.connection_id),
            account_id: Some(AccountId::from_stable(registration.account_id)),
            required_scopes: registration.scopes,
            effect_class: EffectClass::ExternalWrite,
            description: format!(
                "publish adopted WorkProduct {} to GitHub Pages",
                preview.selection.work_product_id
            ),
            target_resource: request.target_resource(&preview.publication_id),
            audience_digest: Some(preview.selection.manifest_digest.clone()),
            payload_digest: request.payload_digest.clone(),
            asset_digests: BTreeSet::from([
                preview.selection.manifest_digest.clone(),
                preview.selection.site_revision.artifact_digest.clone(),
                request.preview.preview_digest.clone(),
            ]),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: hartevo_domain_kernel::ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: input.policy_version,
            risk: EffectRisk::Medium,
            idempotency_key: request.idempotency_key.clone(),
            amount: Money::zero(CurrencyCode::parse("USD").expect("USD is valid")),
            expires_at: input.expires_at,
        };
        let effect_id = mission.propose_effect(effect_spec, now)?;
        self.provider
            .register_publish(effect_id.clone(), request.clone())?;
        Ok(PublicationPluginPublishPlan {
            effect_id,
            result_url: request.target.url.clone(),
            request,
            selection: preview.selection,
        })
    }

    pub fn publish(
        &mut self,
        broker: &mut EffectBroker,
        mission: &mut Mission,
        plan: &PublicationPluginPublishPlan,
        infrastructure: &mut impl EffectInfrastructure,
        now: DateTime<Utc>,
    ) -> Result<PublicationAdoptableResult, WebPublicationPluginError> {
        let result =
            self.provider
                .execute(broker, mission, &plan.effect_id, infrastructure, now)?;
        let effect = mission.effect(&plan.effect_id)?.clone();
        self.consumer.consume(plan, &effect, &result, now)
    }

    pub fn reconcile(
        &mut self,
        broker: &mut EffectBroker,
        mission: &mut Mission,
        plan: &PublicationPluginPublishPlan,
        infrastructure: &mut impl EffectInfrastructure,
        now: DateTime<Utc>,
    ) -> Result<PublicationAdoptableResult, WebPublicationPluginError> {
        let result =
            self.provider
                .reconcile(broker, mission, &plan.effect_id, infrastructure, now)?;
        let effect = mission.effect(&plan.effect_id)?.clone();
        self.consumer.consume(plan, &effect, &result, now)
    }
}

#[derive(Debug, Error)]
pub enum WebPublicationPluginError {
    #[error("web publication provider is disconnected: registration or authentication is missing")]
    Disconnected,
    #[error("GitHub Pages plugin registration is invalid or incomplete")]
    InvalidRegistration,
    #[error("the selected WorkProduct source changed before publication proposal")]
    SourceChanged,
    #[error("provider receipt or independent readback result is not adoptable")]
    ResultNotAdoptable,
    #[error(transparent)]
    GithubPages(#[from] GithubPagesError),
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error(transparent)]
    Mission(#[from] MissionError),
    #[error(transparent)]
    WebPublication(#[from] WebPublicationError),
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(value: impl AsRef<[u8]>) -> String {
    use sha2::{Digest, Sha256};

    Sha256::digest(value.as_ref())
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write as _;

            let _ = write!(output, "{byte:02x}");
            output
        })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{DateTime, Duration, Utc};
    use hartevo_domain_kernel::{
        ApprovalPolicy, Effect, EffectStatus, ExecutionAttemptId, MissionContract, Receipt,
        SiteFile, TenantId, Verification, WorkProduct, WorkProductDependencies, WorkProductPreview,
    };

    use super::*;
    use crate::github_pages::{GithubPagesEnvironmentTarget, InMemoryGithubPagesTransport};
    use crate::{
        DurableEffectLedger, EffectPermissionResolver, EffectPolicy, EffectRateLimit,
        ExecutionClaimContext, ExecutionLease, LedgerClaim, LedgerError, PermissionEvidence,
        PermissionFailure, PermissionFence, ReconciliationClaim, ReconciliationDisposition,
        ReconciliationLease, ReconciliationObservation, ReconciliationPolicy,
    };

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
        .expect("targets")
    }

    fn registration() -> GithubPagesPluginRegistration {
        GithubPagesPluginRegistration::new(
            ConnectionId::from_stable("connection-1"),
            "account-1",
            REQUIRED_GITHUB_SCOPES.iter().map(|scope| (*scope).into()),
            digest("staging-config"),
            digest("production-config"),
        )
        .expect("registration")
    }

    fn mission_and_manifest(now: DateTime<Utc>) -> (Mission, WorkProductManifest, SiteRevision) {
        let tenant_id = TenantId::from_stable("tenant-1");
        let project_id = hartevo_domain_kernel::ProjectId::from_stable("project-1");
        let mission_id = hartevo_domain_kernel::MissionId::from_stable("mission-1");
        let mut contract = MissionContract::bootstrap(
            "publish an adopted site",
            ["publication.publish".into()],
            now,
        );
        contract.approval_policy = ApprovalPolicy {
            required_effect_classes: BTreeSet::from([EffectClass::ExternalWrite]),
            validity_seconds: 300,
            exact_scope_required: true,
        };
        let mut mission = Mission::compile(
            tenant_id,
            mission_id,
            project_id,
            "Web publication mission",
            contract,
            now,
        )
        .expect("mission");
        mission.start_research([], now).expect("start mission");
        let files = vec![SiteFile::new("index.html", "<h1>adoptable</h1>").expect("file")];
        let site_revision =
            SiteRevision::new(SiteId::from_stable("site-1"), 2, files, now).expect("site revision");
        let work_product = WorkProduct::draft(
            WorkProductId::from_stable("work-product-1"),
            "Adoptable site",
            "The site body",
            [],
        );
        mission
            .record_work_product(work_product.clone(), now)
            .expect("record product");
        let ready_for_review = mission
            .work_products
            .last()
            .cloned()
            .expect("recorded product");
        let accepted = ready_for_review.accept().expect("accepted product");
        mission
            .revise_work_product(accepted.clone(), now)
            .expect("accept product");
        let preview = WorkProductPreview::new("text/plain", "preview").expect("preview");
        let manifest = WorkProductManifest::create(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            &accepted,
            "site_build",
            WorkProductDependencies::default(),
            Some(site_revision.artifact_digest.clone()),
            preview,
            BTreeSet::from(["/site/files".into()]),
            now,
        )
        .expect("manifest");
        (mission, manifest, site_revision)
    }

    fn connected_service() -> (
        WebPublicationPluginService<InMemoryGithubPagesTransport>,
        InMemoryGithubPagesTransport,
    ) {
        let targets = targets();
        let transport = InMemoryGithubPagesTransport::new();
        transport
            .seed(
                targets.selected(PublicationEnvironment::Production),
                digest("production-config"),
                "head-1",
                BTreeMap::new(),
            )
            .expect("seed");
        let service = WebPublicationPluginService::connect(
            targets,
            registration(),
            transport.clone(),
            InlinePublicationConsumer,
        )
        .expect("service");
        (service, transport)
    }

    #[derive(Debug, Default)]
    struct PublicationTestInfrastructure {
        receipt: Option<Receipt>,
        verification: Option<Verification>,
        execution_started_at: Option<DateTime<Utc>>,
    }

    impl DurableEffectLedger for PublicationTestInfrastructure {
        fn claim(
            &mut self,
            effect: &Effect,
            context: Option<&ExecutionClaimContext>,
            owner: &str,
            now: DateTime<Utc>,
            lease_expires_at: DateTime<Utc>,
        ) -> Result<LedgerClaim, LedgerError> {
            if self.receipt.is_none() {
                let Some(context) = context else {
                    return Ok(LedgerClaim::AuthorizationRequired);
                };
                context.validate_dispatch_at(effect, now)?;
                self.execution_started_at = Some(now);
            }
            Ok(LedgerClaim::Acquired {
                lease: ExecutionLease {
                    attempt_id: ExecutionAttemptId::from_stable("publication-execution"),
                    owner: owner.into(),
                    generation: 1,
                    expires_at: lease_expires_at,
                },
                receipt: self.receipt.clone(),
                execution_started_at: self.execution_started_at.unwrap_or(now),
            })
        }

        fn record_receipt(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            receipt: &Receipt,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.receipt = Some(receipt.clone());
            Ok(())
        }

        fn record_verification(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            verification: &Verification,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.verification = Some(verification.clone());
            Ok(())
        }

        fn record_failed(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            _reason: &str,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            Ok(())
        }

        fn record_uncertain(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            _reason: &str,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            Ok(())
        }

        fn claim_reconciliation(
            &mut self,
            _effect: &Effect,
            _policy: &ReconciliationPolicy,
            _owner: &str,
            _now: DateTime<Utc>,
            _lease_expires_at: DateTime<Utc>,
        ) -> Result<ReconciliationClaim, LedgerError> {
            Ok(ReconciliationClaim::NotRequired)
        }

        fn record_reconciliation(
            &mut self,
            _effect: &Effect,
            _lease: &ReconciliationLease,
            _observation: &ReconciliationObservation,
            _now: DateTime<Utc>,
        ) -> Result<ReconciliationDisposition, LedgerError> {
            Err(LedgerError::Persistence(
                "reconciliation is not part of the successful publication fixture".into(),
            ))
        }
    }

    impl EffectPermissionResolver for PublicationTestInfrastructure {
        fn authorize(
            &self,
            effect: &Effect,
            _now: DateTime<Utc>,
        ) -> Result<PermissionEvidence, PermissionFailure> {
            let Some(connection_id) = effect.connection_id.clone() else {
                return Err(PermissionFailure::ConnectionMissing);
            };
            Ok(PermissionEvidence {
                connection_evidence_digest: Some(digest("live-connection")),
                consent_evidence_digest: None,
                conversation_evidence_digest: None,
                creator_contact_evidence_digest: None,
                fences: BTreeSet::from([PermissionFence::Connection {
                    connection_id,
                    revision: 1,
                }]),
            })
        }
    }

    fn publication_broker() -> EffectBroker {
        EffectBroker::new(
            EffectPolicy {
                version: "policy-v1".into(),
                allowed_capabilities: BTreeSet::from(["publication.publish".into()]),
                allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                max_amounts_minor: BTreeMap::from([(
                    CurrencyCode::parse("USD").expect("USD is valid"),
                    0,
                )]),
                rate_limits: vec![EffectRateLimit {
                    rule_id: "publication-publish-per-minute".into(),
                    provider: "github".into(),
                    capability: "publication.publish".into(),
                    max_executions: 10,
                    window_seconds: 60,
                }],
            },
            "web-publication-test-worker",
        )
    }

    #[test]
    fn unregistered_provider_is_disconnected_and_fixture_is_not_adoptable() {
        let targets = targets();
        let mut service =
            WebPublicationPluginService::<InMemoryGithubPagesTransport>::disconnected(targets)
                .expect("disconnected service");
        assert_eq!(
            service.connection_status(),
            PublicationPluginConnectionStatus::Disconnected
        );
        assert!(matches!(
            service
                .provider
                .read_snapshot(PublicationEnvironment::Production),
            Err(WebPublicationPluginError::Disconnected)
        ));
        let now = Utc::now();
        let (mut mission, mut manifest, site_revision) = mission_and_manifest(now);
        manifest.work_product_type = "visual_fixture".into();
        manifest.manifest_digest = digest("tampered");
        assert!(matches!(
            PublicationWorkProductSelection::from_mission(
                &mission,
                &SiteId::from_stable("site-1"),
                &WorkProductId::from_stable("work-product-1"),
                &manifest,
                site_revision,
            ),
            Err(WebPublicationError::InvalidSourceBinding
                | WebPublicationError::FixtureWorkProduct(_)
                | WebPublicationError::WorkProductManifestMismatch,)
        ));
        mission.effects.clear();
    }

    #[test]
    fn preview_is_local_to_plugin_and_publish_requires_effect_authority() {
        let now = Utc::now();
        let (mut mission, manifest, site_revision) = mission_and_manifest(now);
        let (mut service, transport) = connected_service();
        let input = PublicationPluginPreviewInput {
            mission: &mission,
            site_id: SiteId::from_stable("site-1"),
            domain_id: hartevo_domain_kernel::DomainId::from_stable("domain-1"),
            deployment_id: hartevo_domain_kernel::DeploymentId::from_stable("deployment-1"),
            publication_id: PublicationId::from_stable("publication-1"),
            work_product_id: &WorkProductId::from_stable("work-product-1"),
            manifest: &manifest,
            site_revision,
            environment: PublicationEnvironment::Production,
            base_revision: 1,
            preview_url: Some("https://preview.example.com".into()),
            now,
        };
        let preview = service.preview(&input).expect("preview");
        assert!(!preview.external_effect_created);
        assert_eq!(preview.selection.site_revision.revision, 2);
        assert_eq!(preview.selection.work_product_revision, 2);
        assert_eq!(
            preview.request.preview.preview_digest,
            manifest.preview.content_digest
        );
        let plan = service
            .propose_publish(
                &mut mission,
                preview,
                PublicationPluginPublishInput {
                    actor_id: ActorId::from_stable("actor-1"),
                    effect_id: EffectId::from_stable("effect-1"),
                    policy_version: "policy-v1".into(),
                    expires_at: now + Duration::minutes(5),
                },
                now,
            )
            .expect("publish proposal");
        assert_eq!(
            mission.effect(&plan.effect_id).expect("effect").status,
            EffectStatus::Proposed
        );
        assert_eq!(
            transport
                .mutation_count(
                    service
                        .provider()
                        .targets
                        .selected(PublicationEnvironment::Production)
                )
                .expect("count"),
            0
        );
    }

    fn assert_adoptable_result(
        result: &PublicationAdoptableResult,
        plan: &PublicationPluginPublishPlan,
        effect: &Effect,
        infrastructure: &PublicationTestInfrastructure,
    ) {
        assert!(result.adoptable);
        assert_eq!(result.plugin_id, WEB_PUBLICATION_PLUGIN_ID);
        assert_eq!(result.provider, "github");
        assert_eq!(result.effect_id, plan.effect_id);
        assert_eq!(result.result_url, "https://example.com");
        assert_eq!(
            result.source_mission_revision,
            plan.selection.mission_revision
        );
        assert_eq!(
            result.source_work_product_id,
            plan.selection.work_product_id
        );
        assert_eq!(result.source_work_product_revision, 2);
        assert_eq!(result.source_revision, 2);
        assert_eq!(
            result.source_digest,
            plan.selection.site_revision.artifact_digest
        );
        assert_eq!(
            result.source_manifest_digest,
            plan.selection.manifest_digest
        );
        assert_eq!(result.preview_digest, plan.request.preview.preview_digest);
        assert_eq!(result.payload_digest, plan.request.payload_digest);
        assert_eq!(result.receipt_request_digest, effect.approval_digest());
        assert!(!result.receipt_external_id.is_empty());
        assert!(is_digest(&result.receipt_response_digest));
        assert_eq!(result.verification_status, VerificationStatus::Confirmed);
        assert!(is_digest(&result.readback_evidence_digest));
        assert!(
            result
                .inline_summary
                .contains("independent readback confirmed")
        );
        assert_eq!(
            infrastructure
                .verification
                .as_ref()
                .expect("durable verification")
                .status,
            VerificationStatus::Confirmed
        );
    }

    #[test]
    fn approved_publish_returns_receipt_readback_and_replay_safe_adoptable_result() {
        let now = Utc::now();
        let (mut mission, manifest, site_revision) = mission_and_manifest(now);
        let (mut service, transport) = connected_service();
        let production_target = service
            .provider()
            .targets
            .selected(PublicationEnvironment::Production)
            .clone();
        let preview = service
            .preview(&PublicationPluginPreviewInput {
                mission: &mission,
                site_id: SiteId::from_stable("site-1"),
                domain_id: hartevo_domain_kernel::DomainId::from_stable("domain-1"),
                deployment_id: hartevo_domain_kernel::DeploymentId::from_stable("deployment-1"),
                publication_id: PublicationId::from_stable("publication-1"),
                work_product_id: &WorkProductId::from_stable("work-product-1"),
                manifest: &manifest,
                site_revision,
                environment: PublicationEnvironment::Production,
                base_revision: 1,
                preview_url: Some("https://preview.example.com".into()),
                now,
            })
            .expect("preview");
        let plan = service
            .propose_publish(
                &mut mission,
                preview,
                PublicationPluginPublishInput {
                    actor_id: ActorId::from_stable("actor-1"),
                    effect_id: EffectId::from_stable("effect-1"),
                    policy_version: "policy-v1".into(),
                    expires_at: now + Duration::minutes(5),
                },
                now,
            )
            .expect("publish proposal");

        let mut infrastructure = PublicationTestInfrastructure::default();
        let mut broker = publication_broker();
        broker
            .approve(
                &mut mission,
                &plan.effect_id,
                ActorId::from_stable("approver-1"),
                &infrastructure,
                now,
            )
            .expect("approval");
        assert_eq!(
            mission
                .effect(&plan.effect_id)
                .expect("approved effect")
                .status,
            EffectStatus::Approved
        );

        let result = service
            .publish(&mut broker, &mut mission, &plan, &mut infrastructure, now)
            .expect("publication result");
        let effect = mission.effect(&plan.effect_id).expect("verified effect");
        assert_eq!(effect.status, EffectStatus::Verified);
        assert_adoptable_result(&result, &plan, effect, &infrastructure);
        assert_eq!(
            transport
                .mutation_count(&production_target)
                .expect("mutation count"),
            1
        );

        let replay = service
            .publish(&mut broker, &mut mission, &plan, &mut infrastructure, now)
            .expect("replayed publication result");
        assert_eq!(replay.receipt_external_id, result.receipt_external_id);
        assert_eq!(
            replay.readback_evidence_digest,
            result.readback_evidence_digest
        );
        assert_eq!(
            transport
                .mutation_count(&production_target)
                .expect("replay mutation count"),
            1
        );
    }
}
