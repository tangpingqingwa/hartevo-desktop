//! A domain quote may request explicit payment approval; it cannot authorize payment.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_catalog::Catalog;
use hartevo_domain_kernel::{
    AccountId, ActorId, ApprovalDecision, ConnectionId, ConsentState, Effect, EffectClass,
    EffectId, EffectRisk, EffectSpec, EffectStatus, Mission, MissionCheckpoint,
    MissionCheckpointCompletion, MissionCheckpointCompletionPolicy, MissionCheckpointExecutor,
    MissionCheckpointStatus, MissionId, MissionStage, Money, ProjectId, Receipt, TaskStatus,
    Verification, VerificationStatus, WorkProduct, WorkProductId, WorkProductStatus,
};
use hartevo_effect_broker::{EffectPolicy, EffectRateLimit};
use hartevo_storage::{
    ApplicationSourceKind, ApplicationSourceRevisionFence, PendingEvent, ProjectStore, StorageError,
};
use serde::{Deserialize, Serialize};

use super::{
    ApplicationError, ApplicationService, MissionCheckpointDispatch, canonical_sha256,
    current_checkpoint_dispatch_projection, is_sha256_text, mission_effect_matches_spec,
    start_ready_catalog_checkpoint_in_memory,
};

pub const VM03_DOMAIN_PURCHASE_CAPABILITY: &str = "domain.purchase";
pub const VM03_DOMAIN_PURCHASE_CHECKPOINT_ID: &str = "domain_purchase_approval";
const POLICY_VERSION: &str = "vm03-domain-purchase-policy/v1";
const DESCRIPTION: &str = "Register the accepted VM-03 domain quote";
pub(super) const QUOTE_OUTPUT_CONTRACT: &str = "For VM-03 domain_search_and_quote, return the adopted quote as a JSON WorkProduct body with schemaVersion=hartevo-domain-quote/v1 and exactly these fields: domainName (lowercase ASCII DNS name), provider, connectionId, accountId, connectionRevision, quoteId, registrationYears (1..10), amount {amountMinor,currency}, quotedAt, validUntil (RFC3339 UTC), available=true, autoRenew=false. Copy only supplied registrar evidence, never invent availability, price, quote IDs, account identity or expiry. Quote validity must be within the current Operating Contract and at most one hour. If no authenticated quote is available, return a blocked explanation instead of a purchasable quote. This draft does not authorize domain.purchase, automatic renewal, payment or deployment.";

/// References the adopted quote; price, registrar, account and expiry are never caller overrides.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ProposeVm03DomainPurchase {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub effect_id: EffectId,
    pub actor_id: ActorId,
    pub work_product_id: WorkProductId,
    pub idempotency_key: String,
    pub expected_mission_revision: u64,
    pub expected_checkpoint_revision: u64,
    pub expected_connection_revision: u64,
    pub expected_work_product_revision: u64,
    pub expected_manifest_version: u64,
}

impl fmt::Debug for ProposeVm03DomainPurchase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposeVm03DomainPurchase")
            .field("mission_id", &self.mission_id)
            .field("effect_id", &self.effect_id)
            .field("work_product_id", &self.work_product_id)
            .finish_non_exhaustive()
    }
}

impl ProposeVm03DomainPurchase {
    pub fn authority_payload_bytes(&self) -> Result<Vec<u8>, ApplicationError> {
        Ok(serde_json::to_vec(self)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteVm03DomainPurchase {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub effect_id: EffectId,
    pub expected_mission_revision: u64,
    pub expected_checkpoint_revision: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Vm03DomainPurchaseCompletion {
    pub mission: Mission,
    pub next_dispatch: Option<MissionCheckpointDispatch>,
    pub replayed: bool,
}

/// Private WorkProduct body, not a Provider verification or an authorization.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DomainQuote {
    schema_version: String,
    domain_name: String,
    provider: String,
    connection_id: ConnectionId,
    account_id: AccountId,
    connection_revision: u64,
    quote_id: String,
    registration_years: u8,
    amount: Money,
    quoted_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    available: bool,
    auto_renew: bool,
}

/// Private quote terms, available only in an unlocked Project projection.
/// Readiness is advisory: the command rechecks every source and time fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm03DomainQuoteProjection {
    pub domain_name: String,
    pub provider: String,
    pub registration_years: u8,
    pub amount: Money,
    pub quoted_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub manifest_version: u64,
    pub connection_revision: u64,
    pub can_propose: bool,
}

pub(super) fn quote_projection(
    store: &ProjectStore,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<Option<Vm03DomainQuoteProjection>, ApplicationError> {
    let checkpoint = match current_purchase_checkpoint(mission) {
        Ok(checkpoint) => checkpoint,
        Err(ApplicationError::Vm03DomainPurchaseMismatch) => return Ok(None),
        Err(error) => return Err(error),
    };
    let (product, quote) = match selected_quote(mission) {
        Ok(selected) => selected,
        Err(ApplicationError::Vm03DomainPurchaseMismatch) => return Ok(None),
        Err(error) => return Err(error),
    };
    let manifest = store.load_work_product_manifest(&mission.project_id, &product.id)?;
    manifest.validate_against(product)?;
    if manifest.tenant_id != mission.tenant_id
        || manifest.project_id != mission.project_id
        || manifest.mission_id != mission.id
        || manifest.work_product_type != "runtime_draft"
        || manifest.adoption_status != WorkProductStatus::Accepted
    {
        return Ok(None);
    }
    let connection = match store.load_connection(&mission.project_id, &quote.connection_id) {
        Ok(connection) => Some(connection),
        Err(StorageError::ScopedRecordNotFound { .. }) => None,
        Err(error) => return Err(error.into()),
    };
    let can_propose = mission.stage == MissionStage::Running
        && checkpoint.status == MissionCheckpointStatus::Running
        && mission.contract.validate(now).is_ok()
        && quote.quoted_at <= now
        && now < quote.valid_until
        && mission.tasks.iter().any(|task| {
            task.status == TaskStatus::Running && task.capability == VM03_DOMAIN_PURCHASE_CAPABILITY
        })
        && !mission
            .effects
            .iter()
            .any(|effect| effect.capability == VM03_DOMAIN_PURCHASE_CAPABILITY)
        && connection.is_some_and(|connection| {
            connection.tenant_id() == &mission.tenant_id
                && connection.project_id() == &mission.project_id
                && connection.provider() == quote.provider
                && connection.account_id() == &quote.account_id
                && connection.revision() == quote.connection_revision
                && connection.permits_scopes(
                    &BTreeSet::from([VM03_DOMAIN_PURCHASE_CAPABILITY.into()]),
                    now,
                )
        });
    Ok(Some(Vm03DomainQuoteProjection {
        domain_name: quote.domain_name,
        provider: quote.provider,
        registration_years: quote.registration_years,
        amount: quote.amount,
        quoted_at: quote.quoted_at,
        valid_until: quote.valid_until,
        work_product_id: product.id.clone(),
        work_product_revision: product.revision,
        manifest_version: manifest.version,
        connection_revision: quote.connection_revision,
        can_propose,
    }))
}

fn mismatch() -> ApplicationError {
    ApplicationError::Vm03DomainPurchaseMismatch
}

pub(super) fn purchased_domain_name(mission: &Mission) -> Result<String, ApplicationError> {
    let checkpoint = purchase_checkpoint(mission)?;
    let completion = checkpoint.completion.as_ref().ok_or_else(mismatch)?;
    if checkpoint.status != MissionCheckpointStatus::Completed
        || completion.effect_ids.len() != 1
        || !completion.work_product_ids.is_empty()
        || completion.application_evidence.is_some()
        || !is_sha256_text(&completion.evidence_digest)
        || completion.oracle_ids
            != BTreeSet::from(["decision".into(), "effect".into(), "operating_state".into()])
    {
        return Err(mismatch());
    }
    let effect = mission.effect(completion.effect_ids.first().ok_or_else(mismatch)?)?;
    let (_, verification) = vm03_domain_purchase_verified_receipt(mission, effect)?;
    if completion.verified_at != verification.observed_at {
        return Err(mismatch());
    }
    Ok(selected_quote(mission)?.1.domain_name)
}

fn purchase_checkpoint(mission: &Mission) -> Result<&MissionCheckpoint, ApplicationError> {
    let definition = mission.definition.as_ref().ok_or_else(mismatch)?;
    let checkpoint = definition
        .checkpoints
        .iter()
        .find(|checkpoint| checkpoint.id == VM03_DOMAIN_PURCHASE_CHECKPOINT_ID)
        .ok_or_else(mismatch)?;
    let route = checkpoint.route.as_ref().ok_or_else(mismatch)?;
    if definition.manifest_id != "VM-03"
        || definition.manifest_version != 3
        || route.capability_id != VM03_DOMAIN_PURCHASE_CAPABILITY
        || route.executor != MissionCheckpointExecutor::EffectBroker
        || route.completion_policy != Some(MissionCheckpointCompletionPolicy::VerifiedEffect)
        || route.oracle_ids
            != BTreeSet::from(["decision".into(), "effect".into(), "operating_state".into()])
        || checkpoint.depends_on != BTreeSet::from(["domain_search_and_quote".into()])
    {
        return Err(mismatch());
    }
    Ok(checkpoint)
}

fn current_purchase_checkpoint(mission: &Mission) -> Result<&MissionCheckpoint, ApplicationError> {
    let checkpoint = purchase_checkpoint(mission)?;
    let definition = mission.definition.as_ref().ok_or_else(mismatch)?;
    if definition.catalog_digest != Catalog::load()?.snapshot()?.digest
        || definition.current_checkpoint().map(|current| &current.id) != Some(&checkpoint.id)
    {
        return Err(mismatch());
    }
    Ok(checkpoint)
}

fn domain_name_is_valid(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && name
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().any(|byte| byte.is_ascii_lowercase()))
}

fn selected_quote(mission: &Mission) -> Result<(&WorkProduct, DomainQuote), ApplicationError> {
    purchase_checkpoint(mission)?;
    let checkpoint = mission
        .definition
        .as_ref()
        .ok_or_else(mismatch)?
        .checkpoints
        .iter()
        .find(|checkpoint| {
            checkpoint.id == "domain_search_and_quote"
                && checkpoint.status == MissionCheckpointStatus::Completed
        })
        .ok_or_else(mismatch)?;
    let route = checkpoint.route.as_ref().ok_or_else(mismatch)?;
    let completion = checkpoint.completion.as_ref().ok_or_else(mismatch)?;
    if route.capability_id != "domain.search"
        || route.executor != MissionCheckpointExecutor::Runtime
        || route.completion_policy != Some(MissionCheckpointCompletionPolicy::WorkProduct)
        || route.oracle_ids
            != BTreeSet::from([
                "truth".into(),
                "work_product".into(),
                "operating_state".into(),
            ])
        || completion.oracle_ids != route.oracle_ids
        || completion.work_product_ids.len() != 1
        || !completion.effect_ids.is_empty()
        || completion.application_evidence.is_some()
        || !is_sha256_text(&completion.evidence_digest)
    {
        return Err(mismatch());
    }
    let work_product = mission
        .work_products
        .iter()
        .find(|product| {
            completion.work_product_ids.contains(&product.id)
                && product.status == WorkProductStatus::Accepted
        })
        .ok_or_else(mismatch)?;
    work_product.validate()?;
    let quote: DomainQuote = serde_json::from_str(&work_product.body).map_err(|_| mismatch())?;
    let catalog = Catalog::load()?;
    let manifest = catalog.mission("VM-03").ok_or_else(mismatch)?;
    let contracted = manifest.provider_ids.contains(&quote.provider)
        && catalog.providers.providers.iter().any(|provider| {
            provider.id == quote.provider
                && provider.requires_external_approval
                && provider
                    .capability_ids
                    .iter()
                    .any(|id| id == VM03_DOMAIN_PURCHASE_CAPABILITY)
                && provider
                    .capability_ids
                    .iter()
                    .any(|id| id == "domain.search")
        });
    // ponytail: one fixed-price registration, no automatic renewal; recurring renewals need a separate explicit Effect.
    if quote.schema_version != "hartevo-domain-quote/v1"
        || !contracted
        || !domain_name_is_valid(&quote.domain_name)
        || !quote.available
        || quote.auto_renew
        || !(1..=10).contains(&quote.registration_years)
        || quote.quote_id.trim().is_empty()
        || quote.quote_id.trim() != quote.quote_id
        || quote.quote_id.len() > 256
        || quote.quote_id.chars().any(char::is_control)
        || quote.connection_revision == 0
        || quote.connection_id.as_str().trim().is_empty()
        || quote.account_id.as_str().trim().is_empty()
        || quote.amount.amount_minor <= 0
        || quote.amount.currency != mission.contract.budget.currency
        || quote.amount.amount_minor > mission.contract.budget.amount_minor
        || quote.quoted_at < mission.contract.valid_from
        || quote.quoted_at > completion.verified_at
        || quote.valid_until <= quote.quoted_at
        || quote.valid_until > mission.contract.valid_until
        || quote.valid_until > quote.quoted_at + Duration::hours(1)
    {
        return Err(mismatch());
    }
    Ok((work_product, quote))
}

fn effect_spec(
    mission: &Mission,
    product: &WorkProduct,
    quote: &DomainQuote,
    manifest_digest: &str,
    id: EffectId,
    actor_id: ActorId,
    idempotency_key: String,
) -> EffectSpec {
    EffectSpec {
        id,
        actor_id,
        capability: VM03_DOMAIN_PURCHASE_CAPABILITY.into(),
        provider: quote.provider.clone(),
        connection_id: Some(quote.connection_id.clone()),
        account_id: Some(quote.account_id.clone()),
        required_scopes: BTreeSet::from([VM03_DOMAIN_PURCHASE_CAPABILITY.into()]),
        effect_class: EffectClass::Payment,
        description: DESCRIPTION.into(),
        target_resource: format!("domain-purchase://{}/{}", mission.project_id, product.id),
        audience_digest: None,
        payload_digest: product.content_digest.clone(),
        asset_digests: BTreeSet::from([manifest_digest.into()]),
        scheduled_for: None,
        timezone: mission.contract.timezone.clone(),
        consent: ConsentState::NotRequired,
        consent_record_id: None,
        consent_requirement: None,
        conversation_guard: None,
        creator_contact_guard: None,
        policy_version: POLICY_VERSION.into(),
        risk: EffectRisk::Critical,
        idempotency_key,
        amount: quote.amount.clone(),
        expires_at: quote.valid_until,
    }
}

fn validate_effect(mission: &Mission, effect: &Effect) -> Result<(), ApplicationError> {
    let (product, quote) = selected_quote(mission)?;
    let manifest_digest = effect.asset_digests.first().ok_or_else(mismatch)?;
    let spec = effect_spec(
        mission,
        product,
        &quote,
        manifest_digest,
        effect.id.clone(),
        effect.actor_id.clone(),
        effect.idempotency_key.clone(),
    );
    if !mission.contract.approval_policy.exact_scope_required
        || !mission
            .contract
            .approval_policy
            .required_effect_classes
            .contains(&EffectClass::Payment)
        || effect.asset_digests.len() != 1
        || !is_sha256_text(manifest_digest)
        || effect.id.as_str().trim().is_empty()
        || effect.actor_id.as_str().trim().is_empty()
        || effect.idempotency_key.trim().is_empty()
        || effect.idempotency_key.trim() != effect.idempotency_key
        || !mission_effect_matches_spec(mission, effect, &spec)
    {
        return Err(mismatch());
    }
    Ok(())
}

/// Used by both explicit approval and the existing Broker's first execution.
pub fn vm03_domain_purchase_effect_policy(
    mission: &Mission,
    effect: &Effect,
) -> Result<EffectPolicy, ApplicationError> {
    let checkpoint = current_purchase_checkpoint(mission)?;
    if !matches!(
        checkpoint.status,
        MissionCheckpointStatus::Running
            | MissionCheckpointStatus::WaitingApproval
            | MissionCheckpointStatus::Verifying
    ) {
        return Err(mismatch());
    }
    validate_effect(mission, effect)?;
    Ok(EffectPolicy {
        version: POLICY_VERSION.into(),
        allowed_capabilities: BTreeSet::from([VM03_DOMAIN_PURCHASE_CAPABILITY.into()]),
        allowed_classes: BTreeSet::from([EffectClass::Payment]),
        max_amounts_minor: BTreeMap::from([(
            mission.contract.budget.currency.clone(),
            effect.amount.amount_minor,
        )]),
        rate_limits: vec![EffectRateLimit {
            rule_id: "desktop-vm03-domain-purchase-hourly".into(),
            provider: effect.provider.clone(),
            capability: VM03_DOMAIN_PURCHASE_CAPABILITY.into(),
            max_executions: 1,
            window_seconds: 3_600,
        }],
    })
}

/// A durable verification is readable after quote expiry; it never grants another execution.
pub fn vm03_domain_purchase_verified_receipt<'a>(
    mission: &Mission,
    effect: &'a Effect,
) -> Result<(&'a Receipt, &'a Verification), ApplicationError> {
    validate_effect(mission, effect)?;
    let receipt = effect.receipt.as_ref().ok_or_else(mismatch)?;
    let verification = effect.verification.as_ref().ok_or_else(mismatch)?;
    if effect.status != EffectStatus::Verified
        || effect.approval.as_ref().is_none_or(|approval| {
            approval.decision != ApprovalDecision::Approved
                || approval.scope_digest != effect.approval_digest()
        })
        || receipt.provider != effect.provider
        || receipt.request_digest != effect.approval_digest()
        || receipt.accepted_at >= effect.expires_at
        || verification.status != VerificationStatus::Confirmed
        || !verification.independent
        || verification.receipt_id != receipt.id
        || verification.observed_at < receipt.accepted_at
    {
        return Err(mismatch());
    }
    Ok((receipt, verification))
}

impl ApplicationService {
    /// Persist one content-minimized payment proposal. No executor is available at this boundary.
    #[allow(
        clippy::too_many_lines,
        reason = "quote, manifest, Connection, exact replay and atomic Mission/source fences are one proposal boundary"
    )]
    pub fn propose_vm03_domain_purchase(
        &mut self,
        command: &ProposeVm03DomainPurchase,
        now: DateTime<Utc>,
    ) -> Result<EffectId, ApplicationError> {
        let mut mission = self
            .store
            .load_mission(&command.project_id, &command.mission_id)?;
        let checkpoint = current_purchase_checkpoint(&mission)?;
        let checkpoint_revision = checkpoint.revision;
        let checkpoint_status = checkpoint.status;
        let (product, quote) = selected_quote(&mission)?;
        let product = product.clone();
        let manifest = self
            .store
            .load_work_product_manifest(&command.project_id, &product.id)?;
        manifest.validate_against(&product)?;
        mission
            .contract
            .validate(now)
            .map_err(super::MissionError::from)?;
        if command.expected_mission_revision == 0
            || command.expected_checkpoint_revision == 0
            || command.expected_connection_revision != quote.connection_revision
            || command.work_product_id != product.id
            || command.expected_work_product_revision != product.revision
            || command.expected_manifest_version != manifest.version
            || manifest.tenant_id != mission.tenant_id
            || manifest.project_id != mission.project_id
            || manifest.mission_id != mission.id
            || manifest.work_product_type != "runtime_draft"
            || manifest.adoption_status != WorkProductStatus::Accepted
            || quote.quoted_at > now
            || quote.valid_until <= now
            || command.effect_id.as_str().trim().is_empty()
            || command.actor_id.as_str().trim().is_empty()
            || command.idempotency_key.trim().is_empty()
            || command.idempotency_key.trim() != command.idempotency_key
        {
            return Err(mismatch());
        }
        let spec = effect_spec(
            &mission,
            &product,
            &quote,
            &manifest.manifest_digest,
            command.effect_id.clone(),
            command.actor_id.clone(),
            command.idempotency_key.clone(),
        );
        if let Some(effect) = mission
            .effects
            .iter()
            .find(|effect| effect.id == command.effect_id)
        {
            if mission_effect_matches_spec(&mission, effect, &spec) {
                return Ok(effect.id.clone());
            }
            return Err(mismatch());
        }
        if mission.revision != command.expected_mission_revision
            || checkpoint_revision != command.expected_checkpoint_revision
            || checkpoint_status != MissionCheckpointStatus::Running
            || !mission.tasks.iter().any(|task| {
                task.status == TaskStatus::Running
                    && task.capability == VM03_DOMAIN_PURCHASE_CAPABILITY
            })
        {
            return Err(mismatch());
        }
        let connection = self
            .store
            .load_connection(&mission.project_id, &quote.connection_id)?;
        if connection.tenant_id() != &mission.tenant_id
            || connection.project_id() != &mission.project_id
            || connection.provider() != quote.provider
            || connection.account_id() != &quote.account_id
            || connection.revision() != quote.connection_revision
            || !connection.permits_scopes(&spec.required_scopes, now)
        {
            return Err(mismatch());
        }
        let expected_revision = mission.revision;
        let effect_id = mission.propose_effect(spec, now)?;
        let effect = mission.effect(&effect_id)?;
        vm03_domain_purchase_effect_policy(&mission, effect)?;
        self.store.update_mission_atomic_with_application_source_fences_only(&mission, expected_revision,
            &[ApplicationSourceRevisionFence::present(ApplicationSourceKind::Connection, connection.id().to_string(), connection.revision())],
            &[PendingEvent::new("vm03.domain_purchase_approval_requested", serde_json::json!({
                "missionId": mission.id, "checkpointId": VM03_DOMAIN_PURCHASE_CHECKPOINT_ID,
                "effectId": effect_id, "workProductId": product.id, "workProductRevision": product.revision,
                "manifestVersion": manifest.version, "connectionRevision": connection.revision(),
                "approvalDigest": effect.approval_digest(), "amountMinor": effect.amount.amount_minor,
                "currency": effect.amount.currency, "providerExecuted": false,
            }), now)])?;
        Ok(effect_id)
    }

    /// Recover or complete the payment from durable independent verification, then start site specification.
    pub fn complete_vm03_domain_purchase(
        &mut self,
        command: &CompleteVm03DomainPurchase,
        now: DateTime<Utc>,
    ) -> Result<Vm03DomainPurchaseCompletion, ApplicationError> {
        let mut mission = self
            .store
            .load_mission(&command.project_id, &command.mission_id)?;
        let effect = mission.effect(&command.effect_id)?.clone();
        let (receipt, verification) = vm03_domain_purchase_verified_receipt(&mission, &effect)?;
        let evidence_digest = canonical_sha256(&serde_json::json!({
            "schemaVersion": "vm03-domain-purchase-completion/v1", "missionId": mission.id,
            "effectId": effect.id, "approvalDigest": effect.approval_digest(),
            "receiptId": receipt.id, "requestDigest": receipt.request_digest, "responseDigest": receipt.response_digest,
            "verificationId": verification.id, "evidenceDigest": verification.evidence_digest, "verifiedAt": verification.observed_at,
        }))?;
        let checkpoint = purchase_checkpoint(&mission)?;
        let completion = MissionCheckpointCompletion {
            oracle_ids: checkpoint
                .route
                .as_ref()
                .ok_or_else(mismatch)?
                .oracle_ids
                .clone(),
            work_product_ids: BTreeSet::new(),
            effect_ids: BTreeSet::from([effect.id.clone()]),
            application_evidence: None,
            evidence_digest,
            verified_at: verification.observed_at,
        };
        if checkpoint.status == MissionCheckpointStatus::Completed {
            if checkpoint.completion.as_ref() != Some(&completion) {
                return Err(mismatch());
            }
            return Ok(Vm03DomainPurchaseCompletion {
                next_dispatch: current_checkpoint_dispatch_projection(&mission)?,
                mission,
                replayed: true,
            });
        }
        let checkpoint = current_purchase_checkpoint(&mission)?;
        if command.expected_mission_revision == 0
            || command.expected_checkpoint_revision == 0
            || mission.revision != command.expected_mission_revision
            || checkpoint.revision != command.expected_checkpoint_revision
            || checkpoint.status != MissionCheckpointStatus::Verifying
            || now < verification.observed_at
        {
            return Err(mismatch());
        }
        let expected_revision = mission.revision;
        mission.complete_checkpoint(VM03_DOMAIN_PURCHASE_CHECKPOINT_ID, completion)?;
        let mut events = vec![PendingEvent::new(
            "vm03.domain_purchase_verified",
            serde_json::json!({
                "missionId": mission.id, "checkpointId": VM03_DOMAIN_PURCHASE_CHECKPOINT_ID, "effectId": effect.id,
                "receiptId": receipt.id, "verificationId": verification.id, "independent": true,
            }),
            now,
        )];
        if let Some((checkpoint_id, checkpoint_revision, capability_id, executor, task_id, cycle)) =
            start_ready_catalog_checkpoint_in_memory(&mut mission, now)?
        {
            events.push(PendingEvent::new("mission.checkpoint_started", serde_json::json!({
                "missionId": mission.id, "checkpointId": checkpoint_id, "checkpointRevision": checkpoint_revision,
                "capabilityId": capability_id, "executor": executor, "taskId": task_id, "cycle": cycle,
            }), now));
        }
        self.store
            .update_mission_atomic(&mission, expected_revision, &events)?;
        Ok(Vm03DomainPurchaseCompletion {
            next_dispatch: current_checkpoint_dispatch_projection(&mission)?,
            mission,
            replayed: false,
        })
    }
}
