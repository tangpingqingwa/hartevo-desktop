//! Application-owned VM-07 research orchestration.
//!
//! The observation adapter in this module is deliberately transport-neutral.
//! It is the seam that the controlled Browser read-observation work can bind to
//! later; it does not re-export or model Browser host types.  The Application
//! owns the Mission/Contract/Checkpoint/plan/source fences and persists the
//! accepted observation, Evidence, Pack revision, progress Event, and Outbox
//! in the existing WorkProduct atomic boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Evidence, EvidenceId, EvidenceStatus, MarketCounterevidence, MarketDecisionRecommendation,
    MarketEvidenceClaim, MarketEvidenceClassification, MarketEvidencePack,
    MarketExperimentPlanItem, MarketUncertainty, MarketUncertaintyMateriality, Mission,
    MissionCheckpointCompletionPolicy, MissionCheckpointExecutor, MissionCheckpointStatus,
    WorkProduct, WorkProductDependencies, WorkProductManifest, WorkProductPreview,
    WorkProductStatus,
};
use hartevo_storage::{DomainEventRecord, PendingEvent, ProjectStore, StorageError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    ApplicationError, ApplicationService, canonical_sha256, validate_vm07_market_pack_scope,
};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId, WorkProductId};

const VM07_OBSERVATION_CHECKPOINTS: [&str; 4] = [
    "evidence_plan",
    "scoped_collection",
    "confirmed_estimated_inferred_unknown_conflict",
    "scenarios_risks_counterevidence",
];
const VM07_RESEARCH_WORK_PRODUCT_TYPE: &str = "market_evidence_pack";
const VM07_RUNTIME_CAPABILITY_RESEARCH: &str = "research.discover";
const VM07_RUNTIME_CAPABILITY_SEARCH: &str = "search.measure";
const VM07_RUNTIME_CAPABILITY_GROUND_TRUTH: &str = "ground_truth.measure";
const VM07_RUNTIME_CAPABILITY_MARKETPLACE: &str = "marketplace.read";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07ObservationOrigin {
    Public,
    FirstParty,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07ObservationRole {
    Supporting,
    Counterevidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07SourceScope {
    pub source_id: String,
    pub source_uri: String,
    pub origin: Vm07ObservationOrigin,
    pub role: Vm07ObservationRole,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07UncertaintyTemplate {
    pub statement: String,
    pub materiality: MarketUncertaintyMateriality,
    pub resolution: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ResearchPlan {
    pub plan_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub checkpoint_id: String,
    pub checkpoint_revision: u64,
    pub mission_revision: u64,
    pub capability_id: String,
    pub contract_digest: String,
    pub market: String,
    pub language: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub sources: BTreeMap<String, Vm07SourceScope>,
    pub uncertainties: BTreeMap<String, Vm07UncertaintyTemplate>,
    pub recommendation_rationale: String,
    pub experiment_plan: Vec<MarketExperimentPlanItem>,
    pub plan_digest: String,
}

impl Vm07ResearchPlan {
    pub fn seal(mut self) -> Result<Self, ApplicationError> {
        self.plan_digest = self.calculate_digest()?;
        self.validate_shape()?;
        Ok(self)
    }

    pub fn calculate_digest(&self) -> Result<String, ApplicationError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(ApplicationError::Vm07ResearchPlanInvalid)?
            .insert("planDigest".into(), Value::String(String::new()));
        canonical_sha256(&value)
    }

    pub fn validate_shape(&self) -> Result<(), ApplicationError> {
        if self.plan_id.trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || !VM07_OBSERVATION_CHECKPOINTS.contains(&self.checkpoint_id.as_str())
            || self.checkpoint_revision == 0
            || self.mission_revision == 0
            || !is_sha256(&self.contract_digest)
            || self.market.trim().is_empty()
            || self.language.trim().is_empty()
            || self.requested_at >= self.expires_at
            || self.sources.is_empty()
            || self.uncertainties.is_empty()
            || self.recommendation_rationale.trim().is_empty()
            || self.experiment_plan.is_empty()
            || !is_sha256(&self.plan_digest)
            || self.plan_digest != self.calculate_digest()?
        {
            return Err(ApplicationError::Vm07ResearchPlanInvalid);
        }
        if self.capability_id != expected_capability(self.checkpoint_id.as_str()) {
            return Err(ApplicationError::Vm07ResearchPlanInvalid);
        }
        for (source_id, source) in &self.sources {
            if source_id != &source.source_id
                || source_id.trim().is_empty()
                || !is_public_https(&source.source_uri)
            {
                return Err(ApplicationError::Vm07ResearchPlanInvalid);
            }
        }
        for (uncertainty_id, uncertainty) in &self.uncertainties {
            if uncertainty_id.trim().is_empty()
                || uncertainty.statement.trim().is_empty()
                || uncertainty.resolution.trim().is_empty()
            {
                return Err(ApplicationError::Vm07ResearchPlanInvalid);
            }
        }
        for experiment in &self.experiment_plan {
            if experiment.id.trim().is_empty() || !experiment.no_external_write {
                return Err(ApplicationError::Vm07ResearchPlanInvalid);
            }
        }
        Ok(())
    }

    fn validate_for_current_mission(
        &self,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationError> {
        self.validate_shape()?;
        if self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.mission_revision != mission.revision
            || self.market != mission.contract.market
            || self.language != mission.contract.language
            || self.contract_digest != canonical_sha256(&serde_json::to_value(&mission.contract)?)?
            || self.requested_at > now
            || now > self.expires_at
        {
            return Err(ApplicationError::Vm07ResearchPlanStale);
        }
        let checkpoint = mission
            .definition
            .as_ref()
            .and_then(|definition| definition.current_checkpoint())
            .ok_or(ApplicationError::Vm07ResearchCheckpointUnavailable)?;
        let route = checkpoint
            .route
            .as_ref()
            .ok_or(ApplicationError::Vm07ResearchCheckpointUnavailable)?;
        if checkpoint.id != self.checkpoint_id
            || checkpoint.status != MissionCheckpointStatus::Running
            || checkpoint.revision != self.checkpoint_revision
            || route.executor != MissionCheckpointExecutor::Runtime
            || route.completion_policy != Some(MissionCheckpointCompletionPolicy::WorkProduct)
            || route.capability_id != self.capability_id
        {
            return Err(ApplicationError::Vm07ResearchCheckpointUnavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07RuntimeRequest {
    pub request_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub checkpoint_id: String,
    pub checkpoint_revision: u64,
    pub mission_revision: u64,
    pub capability_id: String,
    pub contract_digest: String,
    pub plan_digest: String,
    pub expected_pack_revision: Option<u64>,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub sources: BTreeMap<String, Vm07SourceScope>,
    pub external_write_authority: bool,
    pub release_authority: bool,
    pub request_digest: String,
}

impl Vm07RuntimeRequest {
    fn from_plan(
        plan: &Vm07ResearchPlan,
        expected_pack_revision: Option<u64>,
    ) -> Result<Self, ApplicationError> {
        let mut request = Self {
            request_id: format!("vm07-runtime-request:{}", plan.plan_id),
            tenant_id: plan.tenant_id.clone(),
            project_id: plan.project_id.clone(),
            mission_id: plan.mission_id.clone(),
            checkpoint_id: plan.checkpoint_id.clone(),
            checkpoint_revision: plan.checkpoint_revision,
            mission_revision: plan.mission_revision,
            capability_id: plan.capability_id.clone(),
            contract_digest: plan.contract_digest.clone(),
            plan_digest: plan.plan_digest.clone(),
            expected_pack_revision,
            requested_at: plan.requested_at,
            expires_at: plan.expires_at,
            sources: plan.sources.clone(),
            external_write_authority: false,
            release_authority: false,
            request_digest: String::new(),
        };
        request.request_digest = request.calculate_digest()?;
        Ok(request)
    }

    pub fn calculate_digest(&self) -> Result<String, ApplicationError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(ApplicationError::Vm07RuntimeRequestInvalid)?
            .insert("requestDigest".into(), Value::String(String::new()));
        canonical_sha256(&value)
    }

    pub fn validate(&self) -> Result<(), ApplicationError> {
        if self.request_id.trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || !VM07_OBSERVATION_CHECKPOINTS.contains(&self.checkpoint_id.as_str())
            || self.checkpoint_revision == 0
            || self.mission_revision == 0
            || self.capability_id != expected_capability(self.checkpoint_id.as_str())
            || !is_sha256(&self.contract_digest)
            || !is_sha256(&self.plan_digest)
            || self.sources.is_empty()
            || self.external_write_authority
            || self.release_authority
            || !is_sha256(&self.request_digest)
            || self.request_digest != self.calculate_digest()?
        {
            return Err(ApplicationError::Vm07RuntimeRequestInvalid);
        }
        Ok(())
    }
}

/// Transport-neutral observation returned by the future #42 adapter seam.
/// `content` is intake-only and is never copied into Mission, Event, Outbox,
/// or WorkProduct state.  Its Debug implementation is deliberately redacted.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07RuntimeObservation {
    pub observation_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub checkpoint_id: String,
    pub checkpoint_revision: u64,
    pub contract_digest: String,
    pub plan_digest: String,
    pub request_digest: String,
    pub source_id: String,
    pub source_uri: String,
    pub origin: Vm07ObservationOrigin,
    pub observed_at: DateTime<Utc>,
    pub content: String,
    pub content_digest: String,
    pub statement: String,
    pub classification: MarketEvidenceClassification,
    pub confidence: u8,
    pub uncertainty_id: String,
}

impl fmt::Debug for Vm07RuntimeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Vm07RuntimeObservation")
            .field("observation_id", &self.observation_id)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("checkpoint_id", &self.checkpoint_id)
            .field("checkpoint_revision", &self.checkpoint_revision)
            .field("contract_digest", &self.contract_digest)
            .field("plan_digest", &self.plan_digest)
            .field("request_digest", &self.request_digest)
            .field("source_id", &self.source_id)
            .field("source_uri", &self.source_uri)
            .field("origin", &self.origin)
            .field("observed_at", &self.observed_at)
            .field("content_digest", &self.content_digest)
            .field("content_bytes", &self.content.len())
            .field("statement", &self.statement)
            .field("classification", &self.classification)
            .field("confidence", &self.confidence)
            .field("uncertainty_id", &self.uncertainty_id)
            .finish()
    }
}

impl Vm07RuntimeObservation {
    fn observation_digest(&self) -> Result<String, ApplicationError> {
        canonical_sha256(&serde_json::json!({
            "observationId": self.observation_id,
            "tenantId": self.tenant_id,
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "checkpointId": self.checkpoint_id,
            "checkpointRevision": self.checkpoint_revision,
            "contractDigest": self.contract_digest,
            "planDigest": self.plan_digest,
            "requestDigest": self.request_digest,
            "sourceId": self.source_id,
            "sourceUri": self.source_uri,
            "origin": self.origin,
            "observedAt": self.observed_at,
            "contentDigest": self.content_digest,
            "statement": self.statement,
            "classification": self.classification,
            "confidence": self.confidence,
            "uncertaintyId": self.uncertainty_id,
        }))
    }
}

pub trait Vm07RuntimeObservationAdapter {
    type Error: fmt::Display;

    fn collect(
        &mut self,
        request: &Vm07RuntimeRequest,
    ) -> Result<Vec<Vm07RuntimeObservation>, Self::Error>;
}

#[derive(Clone, Debug)]
pub struct RunVm07MarketResearch {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub plan: Vm07ResearchPlan,
    pub expected_pack_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Vm07ResearchNextStep {
    NeedMoreEvidence,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Vm07ResearchResult {
    pub mission: Mission,
    pub request: Vm07RuntimeRequest,
    pub manifest: WorkProductManifest,
    pub work_product: WorkProduct,
    pub pack: MarketEvidencePack,
    pub accepted_observation_ids: BTreeSet<String>,
    pub next_step: Vm07ResearchNextStep,
    pub replayed: bool,
}

impl ApplicationService {
    /// Runs the Application half of VM-07 research through a narrow adapter
    /// boundary.  The adapter is called only after the current Mission and
    /// route have been fenced.  The returned batch is then fully validated
    /// before one Mission/Manifest/Event/Outbox transaction is attempted.
    pub fn run_vm07_market_research<A>(
        &mut self,
        command: RunVm07MarketResearch,
        adapter: &mut A,
        now: DateTime<Utc>,
    ) -> Result<Vm07ResearchResult, ApplicationError>
    where
        A: Vm07RuntimeObservationAdapter,
    {
        let mission = self
            .store
            .load_mission(&command.project_id, &command.mission_id)?;
        validate_command_identity(&command)?;
        command.plan.validate_shape()?;
        if mission.stage.is_terminal() {
            return Err(ApplicationError::Vm07ResearchMissionStopped);
        }
        let request = Vm07RuntimeRequest::from_plan(&command.plan, command.expected_pack_revision)?;
        request.validate()?;

        if let Some(result) = self.replay_vm07_research_if_present(&mission, &command, &request)? {
            return Ok(result);
        }

        command.plan.validate_for_current_mission(&mission, now)?;
        let observations = adapter
            .collect(&request)
            .map_err(|error| ApplicationError::Vm07ObservationAdapter(error.to_string()))?;
        if observations.is_empty() {
            return Err(ApplicationError::Vm07ObservationBatchEmpty);
        }
        self.accept_vm07_observations(&mission, &command, request, observations, now)
    }

    fn replay_vm07_research_if_present(
        &self,
        mission: &Mission,
        command: &RunVm07MarketResearch,
        request: &Vm07RuntimeRequest,
    ) -> Result<Option<Vm07ResearchResult>, ApplicationError> {
        let events = self
            .store
            .events_for_mission(&command.project_id, &command.mission_id)?;
        let Some(request_event) = events.iter().find(|event| {
            event.event_type == "mission.vm07_research_requested"
                && event.payload.get("requestDigest")
                    == Some(&Value::String(request.request_digest.clone()))
                && event.payload.get("workProductId")
                    == Some(&Value::String(command.work_product_id.to_string()))
        }) else {
            return Ok(None);
        };
        let manifest = self
            .store
            .load_work_product_manifest(&command.project_id, &command.work_product_id)?;
        let work_product = mission
            .work_products
            .iter()
            .find(|product| product.id == command.work_product_id)
            .cloned()
            .ok_or(ApplicationError::Vm07ResearchPackConflict)?;
        if manifest.work_product_type != VM07_RESEARCH_WORK_PRODUCT_TYPE
            || manifest.work_product_revision
                != request_event
                    .payload
                    .get("packRevision")
                    .and_then(Value::as_u64)
                    .ok_or(ApplicationError::Vm07ResearchPackConflict)?
        {
            return Err(ApplicationError::Vm07ResearchPackConflict);
        }
        let pack = load_pipeline_pack(&mission, &command.work_product_id)?;
        if pack.pack_revision != manifest.work_product_revision
            || pack.content_digest
                != request_event
                    .payload
                    .get("packContentDigest")
                    .and_then(Value::as_str)
                    .ok_or(ApplicationError::Vm07ResearchPackConflict)?
        {
            return Err(ApplicationError::Vm07ResearchPackConflict);
        }
        let accepted_observation_ids = events
            .iter()
            .filter(|event| {
                event.event_type == "mission.vm07_observation_accepted"
                    && event.payload.get("requestDigest")
                        == Some(&Value::String(request.request_digest.clone()))
            })
            .filter_map(|event| {
                event
                    .payload
                    .get("observationId")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<BTreeSet<_>>();
        if accepted_observation_ids.is_empty() {
            return Err(ApplicationError::Vm07ResearchPackConflict);
        }
        Ok(Some(Vm07ResearchResult {
            mission: mission.clone(),
            request: request.clone(),
            manifest,
            work_product,
            pack,
            accepted_observation_ids,
            next_step: Vm07ResearchNextStep::NeedMoreEvidence,
            replayed: true,
        }))
    }

    fn accept_vm07_observations(
        &mut self,
        initial_mission: &Mission,
        command: &RunVm07MarketResearch,
        request: Vm07RuntimeRequest,
        observations: Vec<Vm07RuntimeObservation>,
        now: DateTime<Utc>,
    ) -> Result<Vm07ResearchResult, ApplicationError> {
        let events = self
            .store
            .events_for_mission(&command.project_id, &command.mission_id)?;
        let mut observation_ids = BTreeSet::new();
        for observation in &observations {
            validate_observation(initial_mission, &command.plan, &request, observation, now)?;
            if !observation_ids.insert(observation.observation_id.clone()) {
                return Err(ApplicationError::Vm07ObservationBatchInvalid);
            }
            validate_observation_history(&events, &request, command, observation)?;
        }

        let previous_manifest =
            load_optional_manifest(&self.store, &command.project_id, &command.work_product_id)?;
        let previous_product = initial_mission
            .work_products
            .iter()
            .find(|product| product.id == command.work_product_id)
            .cloned();
        let is_new_product = previous_product.is_none();
        let previous_pack = match (&previous_manifest, &previous_product) {
            (None, None) => None,
            (Some(manifest), Some(product)) => {
                if manifest.work_product_type != VM07_RESEARCH_WORK_PRODUCT_TYPE
                    || manifest.work_product_revision != product.revision
                    || product.status != WorkProductStatus::ReadyForReview
                {
                    return Err(ApplicationError::Vm07ResearchPackConflict);
                }
                let pack = load_pipeline_pack(initial_mission, &command.work_product_id)?;
                if pack.pack_revision != product.revision {
                    return Err(ApplicationError::Vm07ResearchPackConflict);
                }
                Some(pack)
            }
            _ => return Err(ApplicationError::Vm07ResearchPackConflict),
        };
        if let Some(pack) = &previous_pack {
            if command.expected_pack_revision != Some(pack.pack_revision) {
                return Err(ApplicationError::Vm07ResearchPackRevisionMismatch);
            }
        } else if command.expected_pack_revision.is_some() {
            return Err(ApplicationError::Vm07ResearchPackRevisionMismatch);
        }

        let mut new_observations = Vec::with_capacity(observations.len());
        for observation in observations {
            if let Some(pack) = &previous_pack {
                let claim_id = observation_claim_id(&observation.observation_id);
                if let Some(claim) = pack.claims.iter().find(|claim| claim.id == claim_id) {
                    if !claim_matches_observation(claim, &observation)
                        || !counterevidence_matches_observation(pack, &observation, &command.plan)?
                    {
                        return Err(ApplicationError::Vm07ObservationReplayMismatch);
                    }
                    continue;
                }
            }
            new_observations.push(observation);
        }
        if new_observations.is_empty() {
            return Err(ApplicationError::Vm07ObservationReplayMismatch);
        }
        if previous_pack.is_some() {
            command
                .plan
                .validate_for_current_mission(initial_mission, now)?;
        }

        let expected_mission_revision = initial_mission.revision;
        let mut mission = initial_mission.clone();
        for observation in &new_observations {
            mission.record_evidence(
                Evidence {
                    id: observation_evidence_id(&mission.id, &observation.observation_id),
                    title: observation.statement.clone(),
                    source_uri: observation.source_uri.clone(),
                    observed_at: observation.observed_at,
                    confidence: f32::from(observation.confidence) / 100.0,
                    status: evidence_status(observation),
                    content_digest: observation.content_digest.clone(),
                },
                now,
            )?;
        }

        let pack = build_pack(
            &mission,
            &command.plan,
            previous_pack.as_ref(),
            &new_observations,
            now,
        )?;
        validate_vm07_market_pack_scope(&mission, &pack, now)?;
        let evidence_ids = mission
            .evidence
            .iter()
            .filter(|evidence| {
                evidence
                    .id
                    .as_str()
                    .starts_with("vm07-observation-evidence:")
            })
            .map(|evidence| evidence.id.clone())
            .collect::<BTreeSet<_>>();
        let body = pack.canonical_body()?;
        let title = format!("Market Evidence Pack · {}", pack.market);
        let (manifest, work_product, event_kind) = match (previous_manifest, previous_product) {
            (None, None) => {
                let product = WorkProduct::draft(
                    command.work_product_id.clone(),
                    title,
                    body,
                    evidence_ids.clone(),
                );
                mission.record_work_product(product.clone(), now)?;
                let product = mission
                    .work_products
                    .iter()
                    .find(|candidate| candidate.id == command.work_product_id)
                    .cloned()
                    .ok_or_else(|| ApplicationError::Vm07ResearchPackConflict)?;
                let manifest = WorkProductManifest::create(
                    mission.tenant_id.clone(),
                    mission.project_id.clone(),
                    mission.id.clone(),
                    &product,
                    VM07_RESEARCH_WORK_PRODUCT_TYPE,
                    WorkProductDependencies {
                        fact_ids: BTreeSet::new(),
                        evidence_ids,
                        task_ids: mission.tasks.iter().map(|task| task.id.clone()).collect(),
                    },
                    None,
                    pack_preview(&pack)?,
                    BTreeSet::from(["/vm07/market_evidence_pack".into()]),
                    now,
                )?;
                (manifest, product, "work_product.created")
            }
            (Some(manifest), Some(previous)) => {
                let revised = previous.revise_content(title, body, evidence_ids.clone())?;
                mission.revise_work_product(revised.clone(), now)?;
                let manifest = manifest.revise(
                    &revised,
                    WorkProductDependencies {
                        fact_ids: BTreeSet::new(),
                        evidence_ids,
                        task_ids: mission.tasks.iter().map(|task| task.id.clone()).collect(),
                    },
                    None,
                    pack_preview(&pack)?,
                    BTreeSet::from(["/vm07/market_evidence_pack".into()]),
                    now,
                )?;
                (manifest, revised, "work_product.revised")
            }
            _ => return Err(ApplicationError::Vm07ResearchPackConflict),
        };
        let accepted_observation_ids = new_observations
            .iter()
            .map(|observation| observation.observation_id.clone())
            .collect::<BTreeSet<_>>();
        let mut pending_events = vec![PendingEvent::new(
            "mission.vm07_research_requested",
            serde_json::json!({
                "tenantId": mission.tenant_id,
                "projectId": mission.project_id,
                "missionId": mission.id,
                "checkpointId": request.checkpoint_id,
                "checkpointRevision": request.checkpoint_revision,
                "missionRevision": request.mission_revision,
                "capabilityId": request.capability_id,
                "contractDigest": request.contract_digest,
                "planDigest": request.plan_digest,
                "requestDigest": request.request_digest,
                "workProductId": command.work_product_id,
                "expectedPackRevision": command.expected_pack_revision,
                "packRevision": pack.pack_revision,
                "packContentDigest": pack.content_digest,
                "externalWrite": false,
                "runtimeAuthority": false,
                "releaseAuthority": false,
            }),
            now,
        )];
        for observation in &new_observations {
            pending_events.push(PendingEvent::new(
                "mission.vm07_observation_accepted",
                observation_event_payload(
                    &mission,
                    &request,
                    &command.work_product_id,
                    &command.plan,
                    observation,
                    pack.pack_revision,
                )?,
                now,
            ));
        }
        pending_events.push(PendingEvent::new(
            "mission.vm07_research_progressed",
            serde_json::json!({
                "missionId": mission.id,
                "workProductId": command.work_product_id,
                "packRevision": pack.pack_revision,
                "packContentDigest": pack.content_digest,
                "acceptedObservationCount": accepted_observation_ids.len(),
                "nextStep": "need_more_evidence",
                "terminalRecommendation": false,
                "externalWrite": false,
                "runtimeAuthority": false,
                "releaseAuthority": false,
            }),
            now,
        ));
        pending_events.push(PendingEvent::new(
            "evidence.ready",
            serde_json::json!({
                "missionId": mission.id,
                "workProductId": command.work_product_id,
                "packContentDigest": pack.content_digest,
                "packRevision": pack.pack_revision,
                "sourceCount": pack.claims.len(),
                "confirmedFactCount": pack.claims.iter().filter(|claim| claim.classification == MarketEvidenceClassification::ConfirmedFact).count(),
                "uncertaintyCount": pack.truth_uncertainty_map.len(),
                "counterevidenceCount": pack.counterevidence.len(),
            }),
            now,
        ));
        pending_events.push(PendingEvent::new(
            event_kind,
            serde_json::json!({
                "workProductId": manifest.work_product_id,
                "workProductType": manifest.work_product_type,
                "manifestVersion": manifest.version,
                "manifestDigest": manifest.manifest_digest,
                "packContentDigest": pack.content_digest,
                "packRevision": pack.pack_revision,
            }),
            now,
        ));
        if is_new_product {
            self.store.create_work_product_manifest_atomic(
                &mission,
                expected_mission_revision,
                &manifest,
                &pending_events,
            )?;
        } else {
            self.store.revise_work_product_manifest_atomic(
                &mission,
                expected_mission_revision,
                &manifest,
                manifest.version.saturating_sub(1),
                &pending_events,
            )?;
        }
        Ok(Vm07ResearchResult {
            mission,
            request,
            manifest,
            work_product,
            pack,
            accepted_observation_ids,
            next_step: Vm07ResearchNextStep::NeedMoreEvidence,
            replayed: false,
        })
    }
}

fn validate_command_identity(command: &RunVm07MarketResearch) -> Result<(), ApplicationError> {
    if command.project_id != command.plan.project_id
        || command.mission_id != command.plan.mission_id
        || command.work_product_id.as_str().trim().is_empty()
    {
        return Err(ApplicationError::Vm07ResearchScopeMismatch);
    }
    Ok(())
}

fn validate_observation(
    mission: &Mission,
    plan: &Vm07ResearchPlan,
    request: &Vm07RuntimeRequest,
    observation: &Vm07RuntimeObservation,
    now: DateTime<Utc>,
) -> Result<(), ApplicationError> {
    let source = plan
        .sources
        .get(&observation.source_id)
        .ok_or(ApplicationError::Vm07ObservationSourceDrift)?;
    if observation.observation_id.trim().is_empty()
        || observation.tenant_id != mission.tenant_id
        || observation.project_id != mission.project_id
        || observation.mission_id != mission.id
        || observation.checkpoint_id != request.checkpoint_id
        || observation.checkpoint_revision != request.checkpoint_revision
        || observation.contract_digest != request.contract_digest
        || observation.plan_digest != request.plan_digest
        || observation.request_digest != request.request_digest
        || observation.source_uri != source.source_uri
        || observation.origin != source.origin
        || observation.observed_at < plan.requested_at
        || observation.observed_at > plan.expires_at
        || observation.observed_at > now
        || observation.statement.trim().is_empty()
        || observation.content.is_empty()
        || observation.content_digest != sha256(observation.content.as_bytes())
        || !is_sha256(&observation.content_digest)
        || observation.confidence > 100
        || !plan.uncertainties.contains_key(&observation.uncertainty_id)
        || (observation.classification == MarketEvidenceClassification::ConfirmedFact
            && observation.origin != Vm07ObservationOrigin::FirstParty)
    {
        return Err(
            if observation.source_uri != source.source_uri || observation.origin != source.origin {
                ApplicationError::Vm07ObservationSourceDrift
            } else if observation.observed_at < plan.requested_at
                || observation.observed_at > plan.expires_at
                || observation.observed_at > now
            {
                ApplicationError::Vm07ObservationTimeInvalid
            } else if observation.content_digest != sha256(observation.content.as_bytes())
                || !is_sha256(&observation.content_digest)
            {
                ApplicationError::Vm07ObservationDigestMismatch
            } else if observation.classification == MarketEvidenceClassification::ConfirmedFact
                && observation.origin != Vm07ObservationOrigin::FirstParty
            {
                ApplicationError::Vm07PublicObservationCannotBeConfirmed
            } else {
                ApplicationError::Vm07ObservationScopeMismatch
            },
        );
    }
    if source.role == Vm07ObservationRole::Counterevidence
        && observation.classification == MarketEvidenceClassification::ConfirmedFact
        && observation.origin != Vm07ObservationOrigin::FirstParty
    {
        return Err(ApplicationError::Vm07PublicObservationCannotBeConfirmed);
    }
    Ok(())
}

fn validate_observation_history(
    events: &[DomainEventRecord],
    request: &Vm07RuntimeRequest,
    command: &RunVm07MarketResearch,
    observation: &Vm07RuntimeObservation,
) -> Result<(), ApplicationError> {
    let observation_digest = observation.observation_digest()?;
    for event in events.iter().filter(|event| {
        event.event_type == "mission.vm07_observation_accepted"
            && event.payload.get("observationId")
                == Some(&Value::String(observation.observation_id.clone()))
    }) {
        if event.payload.get("requestDigest")
            != Some(&Value::String(request.request_digest.clone()))
            || event.payload.get("planDigest") != Some(&Value::String(request.plan_digest.clone()))
            || event.payload.get("workProductId")
                != Some(&Value::String(command.work_product_id.to_string()))
        {
            return Err(ApplicationError::Vm07ObservationReplayMismatch);
        }
        if event.payload.get("observationDigest")
            != Some(&Value::String(observation_digest.clone()))
        {
            return Err(ApplicationError::Vm07ObservationReplayMismatch);
        }
    }
    Ok(())
}

fn build_pack(
    mission: &Mission,
    plan: &Vm07ResearchPlan,
    previous: Option<&MarketEvidencePack>,
    observations: &[Vm07RuntimeObservation],
    now: DateTime<Utc>,
) -> Result<MarketEvidencePack, ApplicationError> {
    let (
        mut claims,
        mut uncertainties,
        mut counterevidence,
        mut supporting_claim_ids,
        mut counterevidence_ids,
        recommendation_rationale,
        experiment_plan,
        pack_revision,
    ) = if let Some(previous) = previous {
        if previous.recommendation != MarketDecisionRecommendation::NeedMoreEvidence
            || previous.experiment_plan != plan.experiment_plan
        {
            return Err(ApplicationError::Vm07ResearchPlanMismatch);
        }
        (
            previous.claims.clone(),
            previous
                .truth_uncertainty_map
                .iter()
                .map(|item| (item.id.clone(), item.clone()))
                .collect::<BTreeMap<_, _>>(),
            previous.counterevidence.clone(),
            previous.supporting_claim_ids.clone(),
            previous.counterevidence_ids.clone(),
            previous.recommendation_rationale.clone(),
            previous.experiment_plan.clone(),
            previous
                .pack_revision
                .checked_add(1)
                .ok_or(ApplicationError::Vm07ResearchPackConflict)?,
        )
    } else {
        (
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            plan.recommendation_rationale.clone(),
            plan.experiment_plan.clone(),
            1,
        )
    };
    for observation in observations {
        let source = plan
            .sources
            .get(&observation.source_id)
            .ok_or(ApplicationError::Vm07ObservationSourceDrift)?;
        let claim_id = observation_claim_id(&observation.observation_id);
        let claim = MarketEvidenceClaim {
            id: claim_id.clone(),
            statement: observation.statement.clone(),
            source_id: observation.source_id.clone(),
            source_uri: observation.source_uri.clone(),
            observed_at: observation.observed_at,
            content_digest: observation.content_digest.clone(),
            classification: observation.classification,
            confidence: observation.confidence,
            uncertainty_id: observation.uncertainty_id.clone(),
        };
        if claims.iter().any(|existing| existing.id == claim.id) {
            continue;
        }
        claims.push(claim);
        let template = plan
            .uncertainties
            .get(&observation.uncertainty_id)
            .ok_or(ApplicationError::Vm07ResearchPlanInvalid)?;
        let uncertainty = uncertainties
            .entry(observation.uncertainty_id.clone())
            .or_insert_with(|| MarketUncertainty {
                id: observation.uncertainty_id.clone(),
                statement: template.statement.clone(),
                materiality: template.materiality,
                claim_ids: BTreeSet::new(),
                resolution: template.resolution.clone(),
            });
        if uncertainty.statement != template.statement
            || uncertainty.materiality != template.materiality
            || uncertainty.resolution != template.resolution
        {
            return Err(ApplicationError::Vm07ResearchPlanMismatch);
        }
        uncertainty.claim_ids.insert(claim_id.clone());
        match source.role {
            Vm07ObservationRole::Supporting => {
                supporting_claim_ids.insert(claim_id);
            }
            Vm07ObservationRole::Counterevidence => {
                let counter_id = counterevidence_id(&observation.observation_id);
                counterevidence_ids.insert(counter_id.clone());
                counterevidence.push(MarketCounterevidence {
                    id: counter_id,
                    statement: observation.statement.clone(),
                    source_id: observation.source_id.clone(),
                    source_uri: observation.source_uri.clone(),
                    observed_at: observation.observed_at,
                    content_digest: observation.content_digest.clone(),
                    claim_ids: BTreeSet::from([claim_id]),
                });
            }
        }
    }
    let mut truth_uncertainty_map = uncertainties.into_values().collect::<Vec<_>>();
    truth_uncertainty_map.sort_by(|left, right| left.id.cmp(&right.id));
    if claims.is_empty()
        || supporting_claim_ids.is_empty()
        || counterevidence_ids.is_empty()
        || truth_uncertainty_map.is_empty()
    {
        return Err(ApplicationError::Vm07ObservationBatchInvalid);
    }
    let mut pack = MarketEvidencePack {
        schema_version: MarketEvidencePack::SCHEMA_VERSION,
        tenant_id: mission.tenant_id.clone(),
        project_id: mission.project_id.clone(),
        mission_id: mission.id.clone(),
        contract_digest: canonical_sha256(&serde_json::to_value(&mission.contract)?)?,
        mission_revision: mission.revision,
        pack_revision,
        market: mission.contract.market.clone(),
        language: mission.contract.language.clone(),
        claims,
        truth_uncertainty_map,
        counterevidence,
        recommendation: MarketDecisionRecommendation::NeedMoreEvidence,
        recommendation_rationale,
        supporting_claim_ids,
        counterevidence_ids,
        experiment_plan,
        content_digest: String::new(),
    };
    if pack.claims.iter().any(|claim| claim.observed_at > now) {
        return Err(ApplicationError::Vm07ObservationTimeInvalid);
    }
    pack = pack.seal()?;
    Ok(pack)
}

fn observation_event_payload(
    mission: &Mission,
    request: &Vm07RuntimeRequest,
    work_product_id: &WorkProductId,
    plan: &Vm07ResearchPlan,
    observation: &Vm07RuntimeObservation,
    pack_revision: u64,
) -> Result<Value, ApplicationError> {
    let source = plan
        .sources
        .get(&observation.source_id)
        .ok_or(ApplicationError::Vm07ObservationSourceDrift)?;
    Ok(serde_json::json!({
        "tenantId": mission.tenant_id,
        "projectId": mission.project_id,
        "missionId": mission.id,
        "workProductId": work_product_id,
        "observationId": observation.observation_id,
        "observationDigest": observation.observation_digest()?,
        "sourceIdDigest": sha256(observation.source_id.as_bytes()),
        "sourceUriDigest": sha256(observation.source_uri.as_bytes()),
        "origin": observation.origin,
        "role": source.role,
        "observedAt": observation.observed_at,
        "contentDigest": observation.content_digest,
        "classification": observation.classification,
        "confidence": observation.confidence,
        "uncertaintyId": observation.uncertainty_id,
        "checkpointId": request.checkpoint_id,
        "checkpointRevision": request.checkpoint_revision,
        "planDigest": request.plan_digest,
        "requestDigest": request.request_digest,
        "packRevision": pack_revision,
        "externalWrite": false,
        "runtimeAuthority": false,
        "releaseAuthority": false,
    }))
}

fn claim_matches_observation(
    claim: &MarketEvidenceClaim,
    observation: &Vm07RuntimeObservation,
) -> bool {
    claim.statement == observation.statement
        && claim.source_id == observation.source_id
        && claim.source_uri == observation.source_uri
        && claim.observed_at == observation.observed_at
        && claim.content_digest == observation.content_digest
        && claim.classification == observation.classification
        && claim.confidence == observation.confidence
        && claim.uncertainty_id == observation.uncertainty_id
}

fn counterevidence_matches_observation(
    pack: &MarketEvidencePack,
    observation: &Vm07RuntimeObservation,
    plan: &Vm07ResearchPlan,
) -> Result<bool, ApplicationError> {
    let source = plan
        .sources
        .get(&observation.source_id)
        .ok_or(ApplicationError::Vm07ObservationSourceDrift)?;
    let id = counterevidence_id(&observation.observation_id);
    let Some(item) = pack.counterevidence.iter().find(|item| item.id == id) else {
        return Ok(source.role != Vm07ObservationRole::Counterevidence);
    };
    Ok(source.role == Vm07ObservationRole::Counterevidence
        && item.statement == observation.statement
        && item.source_id == observation.source_id
        && item.source_uri == observation.source_uri
        && item.observed_at == observation.observed_at
        && item.content_digest == observation.content_digest)
}

fn load_optional_manifest(
    store: &ProjectStore,
    project_id: &ProjectId,
    work_product_id: &WorkProductId,
) -> Result<Option<WorkProductManifest>, ApplicationError> {
    match store.load_work_product_manifest(project_id, work_product_id) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(StorageError::ScopedRecordNotFound { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn load_pipeline_pack(
    mission: &Mission,
    work_product_id: &WorkProductId,
) -> Result<MarketEvidencePack, ApplicationError> {
    let product = mission
        .work_products
        .iter()
        .find(|product| &product.id == work_product_id)
        .ok_or(ApplicationError::Vm07ResearchPackConflict)?;
    let pack: MarketEvidencePack = serde_json::from_str(&product.body)?;
    pack.validate()?;
    Ok(pack)
}

fn pack_preview(pack: &MarketEvidencePack) -> Result<WorkProductPreview, ApplicationError> {
    Ok(WorkProductPreview::new(
        "application/json",
        format!(
            "VM-07 Market Evidence Pack {} revision {} ({})",
            pack.market, pack.pack_revision, pack.content_digest
        ),
    )?)
}

fn observation_claim_id(observation_id: &str) -> String {
    format!("vm07-observation:{observation_id}")
}

fn observation_evidence_id(mission_id: &MissionId, observation_id: &str) -> EvidenceId {
    EvidenceId::from_stable(format!(
        "vm07-observation-evidence:{}:{observation_id}",
        mission_id.as_str()
    ))
}

fn counterevidence_id(observation_id: &str) -> String {
    format!("vm07-counterevidence:{observation_id}")
}

fn evidence_status(observation: &Vm07RuntimeObservation) -> EvidenceStatus {
    match observation.classification {
        MarketEvidenceClassification::ConfirmedFact => EvidenceStatus::Confirmed,
        MarketEvidenceClassification::Conflict => EvidenceStatus::Conflicted,
        MarketEvidenceClassification::ProviderEstimate
        | MarketEvidenceClassification::Inference
        | MarketEvidenceClassification::Unknown => EvidenceStatus::Candidate,
    }
}

fn expected_capability(checkpoint_id: &str) -> &'static str {
    match checkpoint_id {
        "evidence_plan" => VM07_RUNTIME_CAPABILITY_RESEARCH,
        "scoped_collection" => VM07_RUNTIME_CAPABILITY_SEARCH,
        "confirmed_estimated_inferred_unknown_conflict" => VM07_RUNTIME_CAPABILITY_GROUND_TRUTH,
        "scenarios_risks_counterevidence" => VM07_RUNTIME_CAPABILITY_MARKETPLACE,
        _ => "",
    }
}

fn is_public_https(value: &str) -> bool {
    value.starts_with("https://") && !value.contains(char::is_whitespace)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        CurrencyCode, KpiContract, KpiDirection, MissionCheckpointCompletion, MissionDefinition,
        MissionStage, Money, OperatingMode, Task, TaskStatus,
    };
    use tempfile::TempDir;

    use crate::{CreateProject, StartCatalogMission};

    #[derive(Debug)]
    struct FakeObservationAdapter {
        observations: Vec<Vm07RuntimeObservation>,
        seen_request: Option<Vm07RuntimeRequest>,
    }

    impl Vm07RuntimeObservationAdapter for FakeObservationAdapter {
        type Error = &'static str;

        fn collect(
            &mut self,
            request: &Vm07RuntimeRequest,
        ) -> Result<Vec<Vm07RuntimeObservation>, Self::Error> {
            self.seen_request = Some(request.clone());
            Ok(self.observations.clone())
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0)
            .single()
            .expect("valid test time")
    }

    fn kpis() -> BTreeMap<String, KpiContract> {
        BTreeMap::from([(
            "decision_ready".into(),
            KpiContract {
                baseline: None,
                target: rust_decimal::Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            },
        )])
    }

    fn start_service() -> (ApplicationService, TempDir, ProjectId, MissionId) {
        let workspace = tempfile::tempdir().expect("workspace");
        let project_id = ProjectId::from("gm01-pipeline-project");
        let mission_id = MissionId::from("gm01-pipeline-mission");
        let mut service = ApplicationService::new(ProjectStore::in_memory().expect("store"));
        service
            .create_project(
                CreateProject {
                    tenant_id: TenantId::from("gm01-pipeline-tenant"),
                    id: project_id.clone(),
                    name: "GM-01 pipeline".into(),
                    description: String::new(),
                    workspace_root: workspace.path().to_path_buf(),
                    storage_mode: hartevo_domain_kernel::StorageMode::LocalNew,
                },
                now(),
            )
            .expect("project");
        service
            .start_catalog_mission(
                StartCatalogMission {
                    id: mission_id.clone(),
                    first_task_id: hartevo_domain_kernel::TaskId::from("gm01-first-task"),
                    project_id: project_id.clone(),
                    manifest_id: "VM-07".into(),
                    mode: OperatingMode::OneOffDecision,
                    parent_mission_id: None,
                    title: Some("Germany market research".into()),
                    goal: "Decide whether to enter Germany with the replacement accessory".into(),
                    market: "DE".into(),
                    language: "de-DE".into(),
                    audience: "DTC buyers".into(),
                    timezone: "Europe/Berlin".into(),
                    kpis: kpis(),
                    budget: Money::zero(CurrencyCode::parse("EUR").expect("EUR")),
                },
                now(),
            )
            .expect("VM-07 Mission");
        (service, workspace, project_id, mission_id)
    }

    fn advance_to_scoped_collection(
        service: &mut ApplicationService,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Mission {
        let mut mission = service
            .load_mission(project_id, mission_id)
            .expect("mission");
        let expected_revision = mission.revision;
        let first = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .cloned()
            .expect("first checkpoint");
        let first_route = first.route.clone().expect("first route");
        mission
            .begin_checkpoint_verification(&first.id, now() + Duration::seconds(1))
            .expect("verify first checkpoint");
        mission
            .complete_checkpoint(
                &first.id,
                MissionCheckpointCompletion {
                    oracle_ids: first_route.oracle_ids,
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: sha256(b"constraints-confirmed"),
                    verified_at: now() + Duration::seconds(2),
                },
            )
            .expect("complete first checkpoint");
        let next = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .cloned()
            .expect("evidence plan checkpoint");
        let next_route = next.route.clone().expect("next route");
        mission
            .begin_checkpoint_with_task(
                &next.id,
                Task {
                    id: hartevo_domain_kernel::TaskId::from("gm01-evidence-plan-task"),
                    title: "Checkpoint: evidence_plan".into(),
                    status: TaskStatus::Running,
                    capability: next_route.capability_id,
                },
                now() + Duration::seconds(3),
            )
            .expect("start evidence plan");
        let checkpoint_evidence_id = EvidenceId::from_stable("gm01-evidence-plan-fixture-evidence");
        mission
            .record_evidence(
                Evidence {
                    id: checkpoint_evidence_id.clone(),
                    title: "Evidence plan fixture".into(),
                    source_uri: "fixture://gm01/evidence-plan".into(),
                    observed_at: now() + Duration::seconds(3),
                    confidence: 1.0,
                    status: EvidenceStatus::Confirmed,
                    content_digest: sha256(b"gm01-evidence-plan-fixture"),
                },
                now() + Duration::seconds(3),
            )
            .expect("record evidence plan fixture");
        let checkpoint_work_product_id =
            WorkProductId::from_stable("gm01-evidence-plan-fixture-product");
        mission
            .record_work_product(
                WorkProduct::draft(
                    checkpoint_work_product_id.clone(),
                    "Evidence plan fixture",
                    "Deterministic evidence plan fixture for VM-07 staging",
                    [checkpoint_evidence_id],
                ),
                now() + Duration::seconds(3),
            )
            .expect("record evidence plan work product fixture");
        let evidence_plan = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .cloned()
            .expect("running evidence plan");
        let evidence_route = evidence_plan.route.clone().expect("evidence route");
        mission
            .begin_checkpoint_verification(&evidence_plan.id, now() + Duration::seconds(4))
            .expect("verify evidence plan");
        mission
            .complete_checkpoint(
                &evidence_plan.id,
                MissionCheckpointCompletion {
                    oracle_ids: evidence_route.oracle_ids,
                    work_product_ids: BTreeSet::from([checkpoint_work_product_id]),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: sha256(b"evidence-plan-ready"),
                    verified_at: now() + Duration::seconds(5),
                },
            )
            .expect("complete evidence plan");
        let next = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .cloned()
            .expect("scoped collection ready");
        let next_route = next.route.clone().expect("collection route");
        mission
            .begin_checkpoint_with_task(
                &next.id,
                Task {
                    id: hartevo_domain_kernel::TaskId::from("gm01-collection-task"),
                    title: "Checkpoint: scoped_collection".into(),
                    status: TaskStatus::Running,
                    capability: next_route.capability_id,
                },
                now() + Duration::seconds(6),
            )
            .expect("start scoped collection");
        mission.updated_at = now() + Duration::seconds(6);
        service
            .store
            .update_mission_atomic(
                &mission,
                expected_revision,
                &[PendingEvent::new(
                    "test.vm07_scoped_collection_ready",
                    serde_json::json!({"checkpointId": "scoped_collection"}),
                    now() + Duration::seconds(6),
                )],
            )
            .expect("persist staged route");
        service
            .load_mission(project_id, mission_id)
            .expect("staged mission")
    }

    fn plan_for(mission: &Mission) -> Vm07ResearchPlan {
        let checkpoint = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .expect("current checkpoint");
        let contract_digest =
            canonical_sha256(&serde_json::to_value(&mission.contract).expect("contract JSON"))
                .expect("contract digest");
        Vm07ResearchPlan {
            plan_id: "gm01-plan-1".into(),
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            checkpoint_id: checkpoint.id.clone(),
            checkpoint_revision: checkpoint.revision,
            mission_revision: mission.revision,
            capability_id: expected_capability(&checkpoint.id).into(),
            contract_digest,
            market: mission.contract.market.clone(),
            language: mission.contract.language.clone(),
            requested_at: now(),
            expires_at: now() + Duration::hours(1),
            sources: BTreeMap::from([
                (
                    "keyword-volume".into(),
                    Vm07SourceScope {
                        source_id: "keyword-volume".into(),
                        source_uri: "https://public.example/de/keyword-volume".into(),
                        origin: Vm07ObservationOrigin::Public,
                        role: Vm07ObservationRole::Supporting,
                    },
                ),
                (
                    "distribution-risk".into(),
                    Vm07SourceScope {
                        source_id: "distribution-risk".into(),
                        source_uri: "https://public.example/de/distribution-risk".into(),
                        origin: Vm07ObservationOrigin::Public,
                        role: Vm07ObservationRole::Counterevidence,
                    },
                ),
            ]),
            uncertainties: BTreeMap::from([(
                "conversion-uncertainty".into(),
                Vm07UncertaintyTemplate {
                    statement: "Search demand may not become paid demand".into(),
                    materiality: MarketUncertaintyMateriality::High,
                    resolution: "Run a bounded read-only interest test".into(),
                },
            )]),
            recommendation_rationale: "The read-only batch is not a terminal market recommendation"
                .into(),
            experiment_plan: vec![MarketExperimentPlanItem {
                id: "interest-test".into(),
                hypothesis: "German prospects will request the accessory".into(),
                success_metric: "Five qualified requests".into(),
                budget_minor: 500,
                currency: "EUR".into(),
                max_duration_days: 14,
                no_external_write: true,
            }],
            plan_digest: String::new(),
        }
        .seal()
        .expect("sealed plan")
    }

    fn observations(
        mission: &Mission,
        plan: &Vm07ResearchPlan,
        work_product_id: &WorkProductId,
    ) -> (Vm07RuntimeRequest, Vec<Vm07RuntimeObservation>) {
        let request = Vm07RuntimeRequest::from_plan(plan, None).expect("request");
        let request_digest = request.request_digest.clone();
        let make = |id: &str,
                    source_id: &str,
                    statement: &str,
                    classification: MarketEvidenceClassification| {
            let content = format!("raw observation {id}");
            Vm07RuntimeObservation {
                observation_id: id.into(),
                tenant_id: mission.tenant_id.clone(),
                project_id: mission.project_id.clone(),
                mission_id: mission.id.clone(),
                checkpoint_id: plan.checkpoint_id.clone(),
                checkpoint_revision: plan.checkpoint_revision,
                contract_digest: plan.contract_digest.clone(),
                plan_digest: plan.plan_digest.clone(),
                request_digest: request_digest.clone(),
                source_id: source_id.into(),
                source_uri: plan.sources[source_id].source_uri.clone(),
                origin: plan.sources[source_id].origin,
                observed_at: now() + Duration::seconds(7),
                content: content.clone(),
                content_digest: sha256(content.as_bytes()),
                statement: statement.into(),
                classification,
                confidence: 70,
                uncertainty_id: "conversion-uncertainty".into(),
            }
        };
        let _ = work_product_id;
        (
            request,
            vec![
                make(
                    "obs-demand",
                    "keyword-volume",
                    "German category demand is measurable",
                    MarketEvidenceClassification::ProviderEstimate,
                ),
                make(
                    "obs-risk",
                    "distribution-risk",
                    "Local incumbents have strong distribution",
                    MarketEvidenceClassification::Conflict,
                ),
            ],
        )
    }

    #[test]
    fn fake_runtime_journey_persists_typed_pack_and_is_read_only() {
        let (mut service, _workspace, project_id, mission_id) = start_service();
        let mission = advance_to_scoped_collection(&mut service, &project_id, &mission_id);
        let plan = plan_for(&mission);
        let work_product_id = WorkProductId::from("gm01-market-pack");
        let (request, batch) = observations(&mission, &plan, &work_product_id);
        let before_effects = mission.effects.clone();
        let events_before = service
            .mission_events(&project_id, &mission_id)
            .expect("events before intake")
            .len();
        let outbox_before = all_outbox_count(&service);
        let mut adapter = FakeObservationAdapter {
            observations: batch,
            seen_request: None,
        };
        let result = service
            .run_vm07_market_research(
                RunVm07MarketResearch {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    plan,
                    expected_pack_revision: None,
                },
                &mut adapter,
                now() + Duration::seconds(8),
            )
            .expect("research journey");
        assert_eq!(
            adapter.seen_request.expect("request").request_digest,
            request.request_digest
        );
        assert_eq!(
            result.pack.recommendation,
            MarketDecisionRecommendation::NeedMoreEvidence
        );
        assert_eq!(result.next_step, Vm07ResearchNextStep::NeedMoreEvidence);
        assert!(!result.replayed);
        assert_eq!(result.accepted_observation_ids.len(), 2);
        assert_eq!(result.mission.effects, before_effects);
        assert!(
            result
                .pack
                .claims
                .iter()
                .all(|claim| claim.classification != MarketEvidenceClassification::ConfirmedFact)
        );
        let events = service
            .mission_events(&project_id, &mission_id)
            .expect("events");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == "mission.vm07_research_progressed")
        );
        let outbox_count = all_outbox_count(&service);
        assert_eq!(outbox_count - outbox_before, events.len() - events_before);
        let event_json = serde_json::to_string(&events).expect("event JSON");
        assert!(!event_json.contains("raw observation"));
    }

    #[test]
    fn exact_replay_adds_no_rows_and_payload_swap_is_fail_closed() {
        let (mut service, _workspace, project_id, mission_id) = start_service();
        let mission = advance_to_scoped_collection(&mut service, &project_id, &mission_id);
        let plan = plan_for(&mission);
        let work_product_id = WorkProductId::from("gm01-replay-pack");
        let (_request, batch) = observations(&mission, &plan, &work_product_id);
        let mut adapter = FakeObservationAdapter {
            observations: batch.clone(),
            seen_request: None,
        };
        let command = RunVm07MarketResearch {
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            work_product_id: work_product_id.clone(),
            plan: plan.clone(),
            expected_pack_revision: None,
        };
        service
            .run_vm07_market_research(command.clone(), &mut adapter, now() + Duration::seconds(8))
            .expect("first intake");
        let event_count = service
            .mission_events(&project_id, &mission_id)
            .expect("events")
            .len();
        let outbox_count = all_outbox_count(&service);
        let mut replay_adapter = FakeObservationAdapter {
            observations: batch,
            seen_request: None,
        };
        let replay = service
            .run_vm07_market_research(
                command.clone(),
                &mut replay_adapter,
                now() + Duration::seconds(9),
            )
            .expect("replay");
        assert!(replay.replayed);
        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("events")
                .len(),
            event_count
        );
        assert_eq!(all_outbox_count(&service), outbox_count);

        let mut swapped = command;
        swapped.plan.plan_digest = "f".repeat(64);
        let mut swapped_adapter = FakeObservationAdapter {
            observations: Vec::new(),
            seen_request: None,
        };
        assert!(matches!(
            service.run_vm07_market_research(
                swapped,
                &mut swapped_adapter,
                now() + Duration::seconds(10)
            ),
            Err(ApplicationError::Vm07ResearchPlanInvalid)
        ));
        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("events")
                .len(),
            event_count
        );
        assert_eq!(all_outbox_count(&service), outbox_count);
    }

    #[test]
    fn stale_cross_scope_public_confirmed_digest_swap_and_stop_are_rejected() {
        let (mut service, _workspace, project_id, mission_id) = start_service();
        let mission = advance_to_scoped_collection(&mut service, &project_id, &mission_id);
        let plan = plan_for(&mission);
        let work_product_id = WorkProductId::from("gm01-negative-pack");
        let (_request, batch) = observations(&mission, &plan, &work_product_id);
        let mut public_confirmed = batch[0].clone();
        public_confirmed.classification = MarketEvidenceClassification::ConfirmedFact;
        let mut adapter = FakeObservationAdapter {
            observations: vec![public_confirmed],
            seen_request: None,
        };
        assert!(matches!(
            service.run_vm07_market_research(
                RunVm07MarketResearch {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    plan: plan.clone(),
                    expected_pack_revision: None,
                },
                &mut adapter,
                now() + Duration::seconds(8),
            ),
            Err(ApplicationError::Vm07PublicObservationCannotBeConfirmed)
        ));
        let mut digest_swap = batch[0].clone();
        digest_swap.content_digest = sha256(b"different content");
        let mut adapter = FakeObservationAdapter {
            observations: vec![digest_swap],
            seen_request: None,
        };
        assert!(matches!(
            service.run_vm07_market_research(
                RunVm07MarketResearch {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    plan: plan.clone(),
                    expected_pack_revision: None,
                },
                &mut adapter,
                now() + Duration::seconds(8),
            ),
            Err(ApplicationError::Vm07ObservationDigestMismatch)
        ));
        let mut cross_scope = batch[0].clone();
        cross_scope.project_id = ProjectId::from("other-project");
        let mut adapter = FakeObservationAdapter {
            observations: vec![cross_scope],
            seen_request: None,
        };
        assert!(matches!(
            service.run_vm07_market_research(
                RunVm07MarketResearch {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id,
                    plan: plan.clone(),
                    expected_pack_revision: None,
                },
                &mut adapter,
                now() + Duration::seconds(8),
            ),
            Err(ApplicationError::Vm07ObservationScopeMismatch)
        ));
        let events_before_stop = service
            .mission_events(&project_id, &mission_id)
            .expect("events")
            .len();
        let mut stopped = service
            .load_mission(&project_id, &mission_id)
            .expect("mission");
        let expected_revision = stopped.revision;
        stopped.stage = MissionStage::Completed;
        stopped.updated_at = now() + Duration::seconds(9);
        stopped.revision = stopped.revision.saturating_add(1);
        service
            .store
            .update_mission_atomic(
                &stopped,
                expected_revision,
                &[PendingEvent::new(
                    "test.vm07_stopped",
                    serde_json::json!({}),
                    now() + Duration::seconds(9),
                )],
            )
            .expect("stop");
        let mut adapter = FakeObservationAdapter {
            observations: batch,
            seen_request: None,
        };
        assert!(matches!(
            service.run_vm07_market_research(
                RunVm07MarketResearch {
                    project_id,
                    mission_id: mission_id.clone(),
                    work_product_id: WorkProductId::from("gm01-stopped-pack"),
                    plan,
                    expected_pack_revision: None,
                },
                &mut adapter,
                now() + Duration::seconds(10),
            ),
            Err(ApplicationError::Vm07ResearchMissionStopped)
        ));
        assert_eq!(
            service
                .mission_events(&ProjectId::from("gm01-pipeline-project"), &mission_id)
                .expect("events")
                .len(),
            events_before_stop + 1
        );
    }

    fn all_outbox_count(service: &ApplicationService) -> usize {
        (1_i64..)
            .map_while(|sequence| match service.store.outbox_message(sequence) {
                Ok(_) => Some(1),
                Err(StorageError::DomainDecode(message))
                    if message == format!("unknown outbox message {sequence}") =>
                {
                    None
                }
                Err(error) => panic!("outbox: {error}"),
            })
            .sum()
    }
}
