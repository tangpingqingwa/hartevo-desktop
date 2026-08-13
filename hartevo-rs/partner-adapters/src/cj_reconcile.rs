//! CJ cursor and delivery reconciliation.
//!
//! This layer consumes only first-party read results and SDK-verified webhook
//! observations.  It keeps CJ account/advertiser/program identity, provider
//! generation, source bytes, cursors, event ids, and evidence digests in one
//! crash-reopenable state machine; it never creates network relationship or
//! settlement facts.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{
    ConnectorScope, ProbeStatus, ProviderProvenanceClass, WebhookEnvelope, WebhookObservation,
};
use hartevo_domain_kernel::Mission;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    CJ_ADAPTER_ID, CJ_ADAPTER_VERSION, CJ_PROVIDER_ID, CJ_RECONCILE_MISSION_CAPABILITY,
    CJ_RECONCILE_SERVICE_ID, CJ_SCHEMA_VERSION, CJ_SERVICE_ID, CjAdvertiserId, CjCostReceipt,
    CjDurableCursor, CjError, CjObservationClassification, CjProbeReceipt, CjProgramId,
    CjPublisherId, CjReadPlan, CjReadResource, CjReadResult, CjScope, digest_parts,
    extract_xml_values, is_sha256, revision_from_digest, sha256_hex,
};

pub const CJ_RECONCILE_SCHEMA_VERSION: &str = "hartevo-cj-cursor-reconcile/v1";

const CJ_RECONCILE_FRESHNESS_SECONDS: i64 = 60;

/// The second-layer scope adds the CJ program identity to the first-layer
/// publisher-account/advertiser scope.  The base ConnectorScope remains the
/// SDK authentication scope; this digest is the durable reconciliation scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjReconcileScope {
    base: CjScope,
    program_id: CjProgramId,
}

impl CjReconcileScope {
    pub fn new(base: CjScope, program_id: CjProgramId) -> Result<Self, CjError> {
        let scope = Self { base, program_id };
        scope.base.connector_scope()?;
        Ok(scope)
    }

    pub fn base(&self) -> &CjScope {
        &self.base
    }

    pub fn tenant_id(&self) -> &str {
        self.base.tenant_id()
    }

    pub fn project_id(&self) -> &str {
        self.base.project_id()
    }

    pub fn publisher_id(&self) -> &CjPublisherId {
        self.base.publisher_id()
    }

    pub fn advertiser_id(&self) -> &CjAdvertiserId {
        self.base.advertiser_id()
    }

    pub fn program_id(&self) -> &CjProgramId {
        &self.program_id
    }

    pub fn connector_scope(&self) -> Result<ConnectorScope, CjError> {
        self.base.connector_scope()
    }

    pub fn base_digest(&self) -> Result<String, CjError> {
        self.base.digest()
    }

    pub fn digest(&self) -> Result<String, CjError> {
        Ok(digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            self.base.digest()?.as_str(),
            self.program_id.as_str(),
        ]))
    }
}

/// The authenticated provider generation that owns every second-layer
/// cursor and delivery.  Credential, probe, and provider-source revisions
/// are all required to match before a cursor can be resumed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjProviderGeneration {
    provider_id: String,
    publisher_id: CjPublisherId,
    advertiser_id: CjAdvertiserId,
    program_id: CjProgramId,
    credential_revision: u64,
    adapter_id: String,
    adapter_version: u32,
    probe_revision: u64,
    provider_generation: u64,
    generation_digest: String,
}

impl CjProviderGeneration {
    pub fn from_probe(
        scope: &CjScope,
        program_id: CjProgramId,
        probe: &CjProbeReceipt,
    ) -> Result<Self, CjError> {
        let source_revision = probe
            .observation
            .source_revision
            .ok_or(CjError::Disconnected)?;
        let adapter = probe.connector_result.adapter();
        let exact = probe.observation.status == super::CjProbeStatus::Reachable
            && probe.observation.classification == CjObservationClassification::FirstParty
            && probe.observation.provider_id == CJ_PROVIDER_ID
            && probe.observation.publisher_id == *scope.publisher_id()
            && probe.observation.advertiser_id == *scope.advertiser_id()
            && probe.observation.credential_revision == probe.credential_revision
            && probe.connector_result.status() == ProbeStatus::Reachable
            && probe.connector_result.provenance_class()
                == ProviderProvenanceClass::ProductionProvider
            && probe.connector_result.scope() == &scope.connector_scope()?
            && adapter.adapter_id() == CJ_ADAPTER_ID
            && adapter.adapter_version() == CJ_ADAPTER_VERSION
            && probe.connector_result.evidence_digest() == probe.observation.evidence_digest
            && is_sha256(&probe.observation.source_digest)
            && is_sha256(&probe.observation.evidence_digest);
        if !exact || source_revision == 0 || probe.connector_result.probe_revision() == 0 {
            return Err(CjError::GenerationDrift);
        }
        let scope_digest = scope.digest()?;
        let generation_digest = digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            CJ_PROVIDER_ID,
            scope_digest.as_str(),
            scope.publisher_id().as_str(),
            scope.advertiser_id().as_str(),
            program_id.as_str(),
            &probe.credential_revision.to_string(),
            adapter.adapter_id(),
            &adapter.adapter_version().to_string(),
            &probe.connector_result.probe_revision().to_string(),
            &source_revision.to_string(),
            probe.observation.source_digest.as_str(),
            probe.observation.evidence_digest.as_str(),
        ]);
        Ok(Self {
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().clone(),
            program_id,
            credential_revision: probe.credential_revision,
            adapter_id: adapter.adapter_id().to_owned(),
            adapter_version: adapter.adapter_version(),
            probe_revision: probe.connector_result.probe_revision(),
            provider_generation: source_revision,
            generation_digest,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn publisher_id(&self) -> &CjPublisherId {
        &self.publisher_id
    }

    pub fn advertiser_id(&self) -> &CjAdvertiserId {
        &self.advertiser_id
    }

    pub fn program_id(&self) -> &CjProgramId {
        &self.program_id
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub const fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    pub fn digest(&self) -> &str {
        &self.generation_digest
    }

    fn validate_scope(&self, scope: &CjReconcileScope) -> Result<(), CjError> {
        let exact = self.provider_id == CJ_PROVIDER_ID
            && self.publisher_id == *scope.publisher_id()
            && self.advertiser_id == *scope.advertiser_id()
            && self.program_id == *scope.program_id()
            && self.adapter_id == CJ_ADAPTER_ID
            && self.adapter_version == CJ_ADAPTER_VERSION
            && self.credential_revision > 0
            && self.probe_revision > 0
            && self.provider_generation > 0
            && is_sha256(&self.generation_digest);
        if exact {
            Ok(())
        } else {
            Err(CjError::GenerationDrift)
        }
    }
}

#[derive(Debug, Default)]
struct CjReconcileAuthorityState {
    active_generation: Option<String>,
    invalidated: bool,
}

/// Shared lifecycle fence.  Re-authentication, probe replacement, revoke,
/// or unmount invalidates every session and reopened checkpoint using an old
/// provider generation.
#[derive(Clone, Debug, Default)]
pub struct CjReconcileAuthority {
    state: Arc<Mutex<CjReconcileAuthorityState>>,
}

impl CjReconcileAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn activate(&self) -> Result<(), CjError> {
        let mut state = self.state.lock().map_err(|_| CjError::StatePoisoned)?;
        state.active_generation = None;
        state.invalidated = false;
        Ok(())
    }

    fn bind(&self, generation: &CjProviderGeneration) -> Result<(), CjError> {
        let mut state = self.state.lock().map_err(|_| CjError::StatePoisoned)?;
        if state.invalidated {
            return Err(CjError::GenerationDrift);
        }
        match state.active_generation.as_deref() {
            Some(active) if active == generation.digest() => Ok(()),
            Some(_) => Err(CjError::GenerationDrift),
            None => {
                state.active_generation = Some(generation.digest().to_owned());
                Ok(())
            }
        }
    }

    pub fn invalidate(&self) -> Result<(), CjError> {
        let mut state = self.state.lock().map_err(|_| CjError::StatePoisoned)?;
        state.active_generation = None;
        state.invalidated = true;
        Ok(())
    }

    fn validate(&self, generation: &CjProviderGeneration) -> Result<(), CjError> {
        let state = self.state.lock().map_err(|_| CjError::StatePoisoned)?;
        if state.active_generation.as_deref() == Some(generation.digest()) && !state.invalidated {
            Ok(())
        } else {
            Err(CjError::GenerationDrift)
        }
    }
}

/// Durable page continuation bound to the exact CJ program and provider
/// generation, in addition to the first-layer page cursor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjReconcileCursor {
    schema_version: String,
    resource: CjReadResource,
    scope_digest: String,
    query_digest: String,
    generation_digest: String,
    credential_revision: u64,
    probe_revision: u64,
    provider_generation: u64,
    page_cursor: CjDurableCursor,
    cursor_digest: String,
}

impl CjReconcileCursor {
    pub fn from_durable(
        page_cursor: CjDurableCursor,
        scope: &CjReconcileScope,
        plan: &CjReadPlan,
        generation: &CjProviderGeneration,
    ) -> Result<Self, CjError> {
        generation.validate_scope(scope)?;
        let query_digest = plan.query_digest(scope.base())?;
        page_cursor.validate_against(plan, scope.base(), &query_digest)?;
        let mut cursor = Self {
            schema_version: CJ_RECONCILE_SCHEMA_VERSION.to_owned(),
            resource: plan.resource(),
            scope_digest: scope.digest()?,
            query_digest,
            generation_digest: generation.digest().to_owned(),
            credential_revision: generation.credential_revision(),
            probe_revision: generation.probe_revision(),
            provider_generation: generation.provider_generation(),
            page_cursor,
            cursor_digest: String::new(),
        };
        cursor.cursor_digest = cursor.calculated_cursor_digest();
        Ok(cursor)
    }

    pub fn resource(&self) -> CjReadResource {
        self.resource
    }

    pub const fn next_page(&self) -> u32 {
        self.page_cursor.next_page()
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn cursor_digest(&self) -> &str {
        &self.cursor_digest
    }

    pub fn page_cursor(&self) -> &CjDurableCursor {
        &self.page_cursor
    }

    fn validate_against(
        &self,
        scope: &CjReconcileScope,
        plan: &CjReadPlan,
        generation: &CjProviderGeneration,
    ) -> Result<(), CjError> {
        generation.validate_scope(scope)?;
        let query_digest = plan.query_digest(scope.base())?;
        if self.schema_version != CJ_RECONCILE_SCHEMA_VERSION
            || self.resource != plan.resource()
            || self.scope_digest != scope.digest()?
            || self.query_digest != query_digest
            || self.generation_digest != generation.digest()
            || self.credential_revision != generation.credential_revision()
            || self.probe_revision != generation.probe_revision()
            || self.provider_generation != generation.provider_generation()
            || !is_sha256(&self.cursor_digest)
            || self.cursor_digest != self.calculated_cursor_digest()
        {
            return Err(CjError::GenerationDrift);
        }
        self.page_cursor
            .validate_against(plan, scope.base(), &query_digest)
    }

    fn calculated_cursor_digest(&self) -> String {
        digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            &format!("{:?}", self.resource),
            &self.scope_digest,
            &self.query_digest,
            &self.generation_digest,
            &self.credential_revision.to_string(),
            &self.probe_revision.to_string(),
            &self.provider_generation.to_string(),
            self.page_cursor.cursor_digest(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CjDeliveryStream {
    Pagination,
    Webhook,
}

/// Provider-native event identity shared by page and webhook deliveries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjProviderEventIdentity {
    provider_id: String,
    publisher_id: CjPublisherId,
    advertiser_id: CjAdvertiserId,
    program_id: CjProgramId,
    stream: CjDeliveryStream,
    event_id: String,
    sequence: u64,
    payload_digest: String,
}

impl CjProviderEventIdentity {
    fn page(
        scope: &CjReconcileScope,
        sequence: u64,
        payload_digest: &str,
    ) -> Result<Self, CjError> {
        if sequence == 0 || !is_sha256(payload_digest) {
            return Err(CjError::InvalidDelivery);
        }
        let event_id = format!("cj-page-event-{sequence}-{}", &payload_digest[..24]);
        Self::new(
            scope,
            CjDeliveryStream::Pagination,
            event_id,
            sequence,
            payload_digest.to_owned(),
        )
    }

    fn webhook(scope: &CjReconcileScope, envelope: &WebhookEnvelope) -> Result<Self, CjError> {
        Self::new(
            scope,
            CjDeliveryStream::Webhook,
            envelope.event_id().to_owned(),
            envelope.sequence(),
            envelope.payload_digest().to_owned(),
        )
    }

    fn new(
        scope: &CjReconcileScope,
        stream: CjDeliveryStream,
        event_id: String,
        sequence: u64,
        payload_digest: String,
    ) -> Result<Self, CjError> {
        if !valid_provider_event_id(&event_id) || sequence == 0 || !is_sha256(&payload_digest) {
            return Err(CjError::ProviderEventMismatch);
        }
        Ok(Self {
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().clone(),
            program_id: scope.program_id().clone(),
            stream,
            event_id,
            sequence,
            payload_digest,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn publisher_id(&self) -> &CjPublisherId {
        &self.publisher_id
    }

    pub fn advertiser_id(&self) -> &CjAdvertiserId {
        &self.advertiser_id
    }

    pub fn program_id(&self) -> &CjProgramId {
        &self.program_id
    }

    pub const fn stream(&self) -> CjDeliveryStream {
        self.stream
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    fn validate_against(
        &self,
        scope: &CjReconcileScope,
        stream: CjDeliveryStream,
    ) -> Result<(), CjError> {
        if self.provider_id != CJ_PROVIDER_ID
            || self.publisher_id != *scope.publisher_id()
            || self.advertiser_id != *scope.advertiser_id()
            || self.program_id != *scope.program_id()
            || self.stream != stream
            || !valid_provider_event_id(&self.event_id)
            || self.sequence == 0
            || !is_sha256(&self.payload_digest)
        {
            return Err(CjError::ProviderEventMismatch);
        }
        Ok(())
    }
}

/// A first-party page delivery sealed with the source bytes from the first
/// layer.  A page is accepted only once for its exact provider event id and
/// cursor generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjPageDelivery {
    resource: CjReadResource,
    sequence: u32,
    scope_digest: String,
    generation_digest: String,
    credential_revision: u64,
    probe_revision: u64,
    provider_generation: u64,
    source_revision: u64,
    publisher_id: CjPublisherId,
    advertiser_id: CjAdvertiserId,
    program_id: CjProgramId,
    input_cursor: Option<CjReconcileCursor>,
    next_cursor: Option<CjReconcileCursor>,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_uri: String,
    source_digest: String,
    content_digest: String,
    result_digest: String,
    source_bytes: String,
    item_count: u32,
    cost: CjCostReceipt,
    event: CjProviderEventIdentity,
    idempotency_key: String,
    delivery_digest: String,
}

impl CjPageDelivery {
    #[allow(clippy::too_many_lines)]
    pub fn from_read(
        scope: &CjReconcileScope,
        plan: &CjReadPlan,
        generation: &CjProviderGeneration,
        input_cursor: Option<&CjReconcileCursor>,
        result: &CjReadResult,
        at: DateTime<Utc>,
    ) -> Result<Self, CjError> {
        generation.validate_scope(scope)?;
        let envelope = &result.envelope;
        let observation = &result.connector_observation;
        let base_scope_digest = scope.base_digest()?;
        let query_digest = plan.query_digest(scope.base())?;
        let source_bytes = envelope.data.payload.clone();
        if source_bytes.is_empty() {
            return Err(CjError::MissingSourceBytes);
        }
        let source_program = source_value(&source_bytes, "program-id")
            .and_then(|value| CjProgramId::new(value).ok())
            .ok_or(CjError::InvalidDelivery)?;
        let exact_scope = envelope.schema_version == CJ_SCHEMA_VERSION
            && envelope.service_id == CJ_SERVICE_ID
            && envelope.provider_id == CJ_PROVIDER_ID
            && envelope.scope_digest == base_scope_digest
            && envelope.publisher_id == *scope.publisher_id()
            && envelope.advertiser_id == *scope.advertiser_id()
            && envelope.resource == plan.resource()
            && envelope.query_digest == query_digest
            && envelope.credential_revision == generation.credential_revision()
            && envelope.source_revision > 0
            && envelope.classification == CjObservationClassification::FirstParty
            && observation.scope() == &scope.connector_scope()?
            && observation.adapter().adapter_id() == CJ_ADAPTER_ID
            && observation.adapter().adapter_version() == CJ_ADAPTER_VERSION
            && observation.provenance_class() == ProviderProvenanceClass::ProductionProvider
            && observation.request_digest() == envelope.query_digest
            && observation.response_digest() == envelope.source_digest
            && observation.content_digest() == envelope.content_digest
            && observation.page_sequence() > 0
            && observation.next_cursor().is_some() == envelope.cursor.is_some()
            && observation.freshness().observed_at() == envelope.observed_at
            && observation.freshness().valid_until() == envelope.valid_until
            && at >= envelope.observed_at
            && at < envelope.valid_until
            && envelope.valid_until > envelope.observed_at
            && envelope.source_uri.starts_with("https://")
            && is_sha256(&envelope.source_digest)
            && is_sha256(&envelope.content_digest)
            && is_sha256(&envelope.result_digest)
            && envelope.source_digest == sha256_hex(&source_bytes)
            && envelope.content_digest == sha256_hex(&source_bytes)
            && source_program == *scope.program_id();
        if !exact_scope {
            return Err(CjError::InvalidDelivery);
        }
        let sequence =
            u32::try_from(observation.page_sequence()).map_err(|_| CjError::InvalidDelivery)?;
        let input_cursor = input_cursor.cloned();
        if sequence == 1 {
            if input_cursor.is_some() {
                return Err(CjError::InvalidDelivery);
            }
        } else if input_cursor
            .as_ref()
            .is_none_or(|cursor| cursor.next_page() != sequence)
        {
            return Err(CjError::CursorRollback);
        }
        if let Some(cursor) = &input_cursor {
            cursor.validate_against(scope, plan, generation)?;
        }
        let next_cursor = envelope
            .cursor
            .clone()
            .map(|cursor| CjReconcileCursor::from_durable(cursor, scope, plan, generation))
            .transpose()?;
        if next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.next_page() != sequence.saturating_add(1))
        {
            return Err(CjError::CursorRollback);
        }
        let event =
            CjProviderEventIdentity::page(scope, u64::from(sequence), &envelope.source_digest)?;
        let idempotency_key = digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            generation.digest(),
            &sequence.to_string(),
            event.event_id(),
            envelope.source_digest.as_str(),
            envelope.content_digest.as_str(),
            envelope.result_digest.as_str(),
        ]);
        let mut delivery = Self {
            resource: plan.resource(),
            sequence,
            scope_digest: scope.digest()?,
            generation_digest: generation.digest().to_owned(),
            credential_revision: generation.credential_revision(),
            probe_revision: generation.probe_revision(),
            provider_generation: generation.provider_generation(),
            source_revision: envelope.source_revision,
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().clone(),
            program_id: scope.program_id().clone(),
            input_cursor,
            next_cursor,
            observed_at: envelope.observed_at,
            valid_until: envelope.valid_until,
            source_uri: envelope.source_uri.clone(),
            source_digest: envelope.source_digest.clone(),
            content_digest: envelope.content_digest.clone(),
            result_digest: envelope.result_digest.clone(),
            source_bytes,
            item_count: observation.item_count(),
            cost: envelope.cost.clone(),
            event,
            idempotency_key,
            delivery_digest: String::new(),
        };
        delivery.delivery_digest = delivery.calculated_delivery_digest();
        Ok(delivery)
    }

    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    pub fn resource(&self) -> CjReadResource {
        self.resource
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn input_cursor(&self) -> Option<&CjReconcileCursor> {
        self.input_cursor.as_ref()
    }

    pub fn next_cursor(&self) -> Option<&CjReconcileCursor> {
        self.next_cursor.as_ref()
    }

    pub fn source_uri(&self) -> &str {
        &self.source_uri
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub fn source_bytes(&self) -> &str {
        &self.source_bytes
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub fn cost(&self) -> &CjCostReceipt {
        &self.cost
    }

    pub fn event(&self) -> &CjProviderEventIdentity {
        &self.event
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn delivery_digest(&self) -> &str {
        &self.delivery_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    fn validate_against(
        &self,
        scope: &CjReconcileScope,
        plan: &CjReadPlan,
        generation: &CjProviderGeneration,
    ) -> Result<(), CjError> {
        generation.validate_scope(scope)?;
        let exact = self.resource == plan.resource()
            && self.scope_digest == scope.digest()?
            && self.generation_digest == generation.digest()
            && self.credential_revision == generation.credential_revision()
            && self.probe_revision == generation.probe_revision()
            && self.provider_generation == generation.provider_generation()
            && self.source_revision > 0
            && self.publisher_id == *scope.publisher_id()
            && self.advertiser_id == *scope.advertiser_id()
            && self.program_id == *scope.program_id()
            && self.sequence > 0
            && self.observed_at < self.valid_until
            && self.source_uri.starts_with("https://")
            && !self.source_bytes.is_empty()
            && is_sha256(&self.source_digest)
            && is_sha256(&self.content_digest)
            && is_sha256(&self.result_digest)
            && self.source_digest == sha256_hex(&self.source_bytes)
            && self.content_digest == sha256_hex(&self.source_bytes)
            && self.source_bytes.contains(scope.program_id().as_str())
            && self.cost.cost_units >= 0
            && self
                .event
                .validate_against(scope, CjDeliveryStream::Pagination)
                .is_ok()
            && self.event.sequence() == u64::from(self.sequence)
            && self.event.payload_digest() == self.source_digest
            && is_sha256(&self.idempotency_key)
            && self.idempotency_key == self.calculated_idempotency_key()
            && is_sha256(&self.delivery_digest)
            && self.delivery_digest == self.calculated_delivery_digest();
        if !exact {
            return Err(CjError::InvalidDelivery);
        }
        if self.sequence == 1 && self.input_cursor.is_some() {
            return Err(CjError::CursorRollback);
        }
        if self.sequence > 1
            && self
                .input_cursor
                .as_ref()
                .is_none_or(|cursor| cursor.next_page() != self.sequence)
        {
            return Err(CjError::CursorRollback);
        }
        if let Some(cursor) = &self.input_cursor {
            cursor.validate_against(scope, plan, generation)?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(scope, plan, generation)?;
            if cursor.next_page() != self.sequence.saturating_add(1) {
                return Err(CjError::CursorRollback);
            }
        }
        Ok(())
    }

    fn calculated_idempotency_key(&self) -> String {
        digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            &self.generation_digest,
            &self.sequence.to_string(),
            self.event.event_id(),
            &self.source_digest,
            &self.content_digest,
            &self.result_digest,
        ])
    }

    fn calculated_delivery_digest(&self) -> String {
        digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            &format!("{:?}", self.resource),
            &self.sequence.to_string(),
            &self.scope_digest,
            &self.generation_digest,
            &self.credential_revision.to_string(),
            &self.probe_revision.to_string(),
            &self.provider_generation.to_string(),
            &self.source_revision.to_string(),
            self.publisher_id.as_str(),
            self.advertiser_id.as_str(),
            self.program_id.as_str(),
            self.input_cursor
                .as_ref()
                .map_or("", CjReconcileCursor::cursor_digest),
            self.next_cursor
                .as_ref()
                .map_or("", CjReconcileCursor::cursor_digest),
            &self.observed_at.to_rfc3339(),
            &self.valid_until.to_rfc3339(),
            &self.source_uri,
            &self.source_digest,
            &self.content_digest,
            &self.result_digest,
            &self.source_bytes.len().to_string(),
            &self.item_count.to_string(),
            &self.cost.cost_units.to_string(),
            self.event.event_id(),
            &self.idempotency_key,
        ])
    }
}

/// A webhook delivery must be built from an SDK-verified envelope and its
/// original source bytes.  The source is retained so checkpoint reopen can
/// re-check the payload digest instead of trusting metadata alone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjWebhookDelivery {
    scope_digest: String,
    generation_digest: String,
    credential_revision: u64,
    probe_revision: u64,
    provider_generation: u64,
    publisher_id: CjPublisherId,
    advertiser_id: CjAdvertiserId,
    program_id: CjProgramId,
    envelope: WebhookEnvelope,
    envelope_digest: String,
    observation: CjWebhookObservation,
    source_bytes: Vec<u8>,
    source_revision: u64,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    event: CjProviderEventIdentity,
    idempotency_key: String,
    delivery_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjWebhookObservation {
    event_id: String,
    scope_digest: String,
    payload_digest: String,
    sequence: u64,
    observed_at: DateTime<Utc>,
}

impl CjWebhookObservation {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl CjWebhookDelivery {
    pub fn from_verified_webhook(
        scope: &CjReconcileScope,
        generation: &CjProviderGeneration,
        envelope: WebhookEnvelope,
        observation: &WebhookObservation,
        source_bytes: Vec<u8>,
        at: DateTime<Utc>,
    ) -> Result<Self, CjError> {
        generation.validate_scope(scope)?;
        if source_bytes.is_empty() {
            return Err(CjError::MissingSourceBytes);
        }
        let source_digest = sha256_bytes(&source_bytes);
        let advertiser_id = source_value_bytes(&source_bytes, "advertiser-id")
            .and_then(|value| CjAdvertiserId::new(value).ok())
            .ok_or(CjError::InvalidDelivery)?;
        let program_id = source_value_bytes(&source_bytes, "program-id")
            .and_then(|value| CjProgramId::new(value).ok())
            .ok_or(CjError::InvalidDelivery)?;
        let connector_scope = scope.connector_scope()?;
        let cj_observation = CjWebhookObservation {
            event_id: observation.event_id().to_owned(),
            scope_digest: observation.scope().digest(),
            payload_digest: observation.payload_digest().to_owned(),
            sequence: observation.sequence(),
            observed_at: at,
        };
        let exact = envelope.provider_id() == CJ_PROVIDER_ID
            && envelope.account_id() == scope.publisher_id().as_str()
            && envelope.adapter().adapter_id() == CJ_ADAPTER_ID
            && envelope.adapter().adapter_version() == CJ_ADAPTER_VERSION
            && cj_observation.scope_digest == connector_scope.digest()
            && cj_observation.event_id == envelope.event_id()
            && cj_observation.payload_digest == envelope.payload_digest()
            && cj_observation.sequence == envelope.sequence()
            && source_digest == envelope.payload_digest()
            && advertiser_id == *scope.advertiser_id()
            && program_id == *scope.program_id();
        if !exact {
            return Err(CjError::ProviderEventMismatch);
        }
        let event = CjProviderEventIdentity::webhook(scope, &envelope)?;
        let envelope_digest = serialized_digest(&envelope);
        let source_revision = revision_from_digest(&source_digest);
        let valid_until = at
            .checked_add_signed(Duration::seconds(CJ_RECONCILE_FRESHNESS_SECONDS))
            .ok_or(CjError::InvalidDelivery)?;
        let idempotency_key = digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            generation.digest(),
            event.event_id(),
            &event.sequence().to_string(),
            event.payload_digest(),
        ]);
        let mut delivery = Self {
            scope_digest: scope.digest()?,
            generation_digest: generation.digest().to_owned(),
            credential_revision: generation.credential_revision(),
            probe_revision: generation.probe_revision(),
            provider_generation: generation.provider_generation(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id,
            program_id,
            envelope,
            envelope_digest,
            observation: cj_observation,
            source_bytes,
            source_revision,
            observed_at: at,
            valid_until,
            event,
            idempotency_key,
            delivery_digest: String::new(),
        };
        delivery.delivery_digest = delivery.calculated_delivery_digest();
        Ok(delivery)
    }

    pub const fn sequence(&self) -> u64 {
        self.event.sequence()
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn publisher_id(&self) -> &CjPublisherId {
        &self.publisher_id
    }

    pub fn advertiser_id(&self) -> &CjAdvertiserId {
        &self.advertiser_id
    }

    pub fn program_id(&self) -> &CjProgramId {
        &self.program_id
    }

    pub fn envelope(&self) -> &WebhookEnvelope {
        &self.envelope
    }

    pub fn observation(&self) -> &CjWebhookObservation {
        &self.observation
    }

    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    pub fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn event(&self) -> &CjProviderEventIdentity {
        &self.event
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn delivery_digest(&self) -> &str {
        &self.delivery_digest
    }

    fn validate_against(
        &self,
        scope: &CjReconcileScope,
        generation: &CjProviderGeneration,
    ) -> Result<(), CjError> {
        generation.validate_scope(scope)?;
        let source_digest = sha256_bytes(&self.source_bytes);
        let exact = self.scope_digest == scope.digest()?
            && self.generation_digest == generation.digest()
            && self.credential_revision == generation.credential_revision()
            && self.probe_revision == generation.probe_revision()
            && self.provider_generation == generation.provider_generation()
            && self.publisher_id == *scope.publisher_id()
            && self.advertiser_id == *scope.advertiser_id()
            && self.program_id == *scope.program_id()
            && !self.source_bytes.is_empty()
            && source_digest == self.envelope.payload_digest()
            && self.source_revision == revision_from_digest(&source_digest)
            && self.observed_at < self.valid_until
            && self.envelope.provider_id() == CJ_PROVIDER_ID
            && self.envelope.account_id() == scope.publisher_id().as_str()
            && self.envelope.adapter().adapter_id() == CJ_ADAPTER_ID
            && self.envelope.adapter().adapter_version() == CJ_ADAPTER_VERSION
            && is_sha256(&self.envelope_digest)
            && self.envelope_digest == serialized_digest(&self.envelope)
            && self.observation.scope_digest == scope.connector_scope()?.digest()
            && self.observation.event_id == self.envelope.event_id()
            && self.observation.payload_digest == self.envelope.payload_digest()
            && self.observation.sequence == self.envelope.sequence()
            && source_value_bytes(&self.source_bytes, "advertiser-id")
                .and_then(|value| CjAdvertiserId::new(value).ok())
                == Some(self.advertiser_id.clone())
            && source_value_bytes(&self.source_bytes, "program-id")
                .and_then(|value| CjProgramId::new(value).ok())
                == Some(self.program_id.clone())
            && self
                .event
                .validate_against(scope, CjDeliveryStream::Webhook)
                .is_ok()
            && self.event.event_id() == self.envelope.event_id()
            && self.event.payload_digest() == self.envelope.payload_digest()
            && is_sha256(&self.idempotency_key)
            && self.idempotency_key == self.calculated_idempotency_key()
            && is_sha256(&self.delivery_digest)
            && self.delivery_digest == self.calculated_delivery_digest();
        if exact {
            Ok(())
        } else {
            Err(CjError::InvalidDelivery)
        }
    }

    fn calculated_idempotency_key(&self) -> String {
        digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            &self.generation_digest,
            self.event.event_id(),
            &self.event.sequence().to_string(),
            self.event.payload_digest(),
        ])
    }

    fn calculated_delivery_digest(&self) -> String {
        digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            "webhook",
            &self.scope_digest,
            &self.generation_digest,
            &self.credential_revision.to_string(),
            &self.probe_revision.to_string(),
            &self.provider_generation.to_string(),
            self.publisher_id.as_str(),
            self.advertiser_id.as_str(),
            self.program_id.as_str(),
            self.event.event_id(),
            &self.event.sequence().to_string(),
            self.event.payload_digest(),
            &self.envelope_digest,
            &self.source_revision.to_string(),
            &self.observed_at.to_rfc3339(),
            &self.valid_until.to_rfc3339(),
            &self.source_bytes.len().to_string(),
            &self.idempotency_key,
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjEvidenceNode {
    stream: CjDeliveryStream,
    sequence: u64,
    event_id: String,
    delivery_digest: String,
    source_revision: u64,
    source_digest: String,
    content_digest: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    cost_units: i64,
    node_digest: String,
}

impl CjEvidenceNode {
    fn from_page(delivery: &CjPageDelivery) -> Self {
        let mut node = Self {
            stream: CjDeliveryStream::Pagination,
            sequence: u64::from(delivery.sequence),
            event_id: delivery.event.event_id().to_owned(),
            delivery_digest: delivery.delivery_digest.clone(),
            source_revision: delivery.source_revision,
            source_digest: delivery.source_digest.clone(),
            content_digest: delivery.content_digest.clone(),
            observed_at: delivery.observed_at,
            valid_until: delivery.valid_until,
            cost_units: delivery.cost.cost_units,
            node_digest: String::new(),
        };
        node.node_digest = node.calculated_digest();
        node
    }

    fn from_webhook(delivery: &CjWebhookDelivery) -> Self {
        let source_digest = delivery.envelope.payload_digest().to_owned();
        let mut node = Self {
            stream: CjDeliveryStream::Webhook,
            sequence: delivery.sequence(),
            event_id: delivery.event.event_id().to_owned(),
            delivery_digest: delivery.delivery_digest.clone(),
            source_revision: delivery.source_revision,
            source_digest: source_digest.clone(),
            content_digest: source_digest,
            observed_at: delivery.observed_at,
            valid_until: delivery.valid_until,
            cost_units: 0,
            node_digest: String::new(),
        };
        node.node_digest = node.calculated_digest();
        node
    }

    pub const fn stream(&self) -> CjDeliveryStream {
        self.stream
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn node_digest(&self) -> &str {
        &self.node_digest
    }

    pub const fn cost_units(&self) -> i64 {
        self.cost_units
    }

    fn calculated_digest(&self) -> String {
        digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            &format!("{:?}", self.stream),
            &self.sequence.to_string(),
            &self.event_id,
            &self.delivery_digest,
            &self.source_revision.to_string(),
            &self.source_digest,
            &self.content_digest,
            &self.observed_at.to_rfc3339(),
            &self.valid_until.to_rfc3339(),
            &self.cost_units.to_string(),
        ])
    }

    fn validate(&self) -> Result<(), CjError> {
        if self.sequence == 0
            || !valid_provider_event_id(&self.event_id)
            || !is_sha256(&self.delivery_digest)
            || !is_sha256(&self.source_digest)
            || !is_sha256(&self.content_digest)
            || !is_sha256(&self.node_digest)
            || self.observed_at >= self.valid_until
            || self.cost_units < 0
            || self.node_digest != self.calculated_digest()
        {
            return Err(CjError::InvalidCheckpoint);
        }
        Ok(())
    }
}

/// Closed evidence over every contiguous page and webhook event.  It is the
/// durable result boundary consumed by Mission composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjEvidenceRoot {
    schema_version: String,
    scope_digest: String,
    generation_digest: String,
    provider_generation: u64,
    resource: CjReadResource,
    query_digest: String,
    page_count: u32,
    webhook_count: u64,
    nodes: Vec<CjEvidenceNode>,
    cost: CjCostReceipt,
    valid_until: DateTime<Utc>,
    root_digest: String,
    closed_at: DateTime<Utc>,
}

impl CjEvidenceRoot {
    fn new(
        scope: &CjReconcileScope,
        plan: &CjReadPlan,
        generation: &CjProviderGeneration,
        page_nodes: &BTreeMap<u32, CjEvidenceNode>,
        webhook_nodes: &BTreeMap<u64, CjEvidenceNode>,
        cost: CjCostReceipt,
        closed_at: DateTime<Utc>,
    ) -> Result<Self, CjError> {
        let nodes = page_nodes
            .values()
            .chain(webhook_nodes.values())
            .cloned()
            .collect::<Vec<_>>();
        if nodes.is_empty() || nodes.iter().any(|node| node.validate().is_err()) {
            return Err(CjError::EvidenceRootOpen);
        }
        if nodes
            .iter()
            .any(|node| closed_at < node.observed_at || closed_at >= node.valid_until)
        {
            return Err(CjError::EvidenceRootOpen);
        }
        let scope_digest = scope.digest()?;
        let query_digest = plan.query_digest(scope.base())?;
        let valid_until = nodes
            .iter()
            .map(|node| node.valid_until)
            .min()
            .ok_or(CjError::EvidenceRootOpen)?;
        let root_digest = digest_parts(
            std::iter::once(CJ_RECONCILE_SCHEMA_VERSION)
                .chain(std::iter::once(scope_digest.as_str()))
                .chain(std::iter::once(generation.digest()))
                .chain(std::iter::once(query_digest.as_str()))
                .chain(nodes.iter().map(CjEvidenceNode::node_digest))
                .chain(std::iter::once(cost.cost_units.to_string().as_str())),
        );
        Ok(Self {
            schema_version: CJ_RECONCILE_SCHEMA_VERSION.to_owned(),
            scope_digest,
            generation_digest: generation.digest().to_owned(),
            provider_generation: generation.provider_generation(),
            resource: plan.resource(),
            query_digest,
            page_count: u32::try_from(page_nodes.len()).map_err(|_| CjError::EvidenceRootOpen)?,
            webhook_count: u64::try_from(webhook_nodes.len())
                .map_err(|_| CjError::EvidenceRootOpen)?,
            nodes,
            cost,
            valid_until,
            root_digest,
            closed_at,
        })
    }

    pub fn is_closed(&self) -> bool {
        true
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn resource(&self) -> CjReadResource {
        self.resource
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub const fn page_count(&self) -> u32 {
        self.page_count
    }

    pub const fn webhook_count(&self) -> u64 {
        self.webhook_count
    }

    pub fn nodes(&self) -> &[CjEvidenceNode] {
        &self.nodes
    }

    pub fn cost(&self) -> &CjCostReceipt {
        &self.cost
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn root_digest(&self) -> &str {
        &self.root_digest
    }

    pub const fn closed_at(&self) -> DateTime<Utc> {
        self.closed_at
    }

    fn validate_against(
        &self,
        scope: &CjReconcileScope,
        plan: &CjReadPlan,
        generation: &CjProviderGeneration,
        page_nodes: &BTreeMap<u32, CjEvidenceNode>,
        webhook_nodes: &BTreeMap<u64, CjEvidenceNode>,
    ) -> Result<(), CjError> {
        let expected = Self::new(
            scope,
            plan,
            generation,
            page_nodes,
            webhook_nodes,
            self.cost.clone(),
            self.closed_at,
        )?;
        if self.schema_version == expected.schema_version
            && self.scope_digest == expected.scope_digest
            && self.generation_digest == expected.generation_digest
            && self.provider_generation == expected.provider_generation
            && self.resource == expected.resource
            && self.query_digest == expected.query_digest
            && self.page_count == expected.page_count
            && self.webhook_count == expected.webhook_count
            && self.nodes == expected.nodes
            && self.valid_until == expected.valid_until
            && self.root_digest == expected.root_digest
        {
            Ok(())
        } else {
            Err(CjError::InvalidCheckpoint)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CjDeliveryStatus {
    Applied,
    Duplicate,
    OutOfOrder,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjDeliveryReceipt {
    status: CjDeliveryStatus,
    stream: CjDeliveryStream,
    event_id: String,
    sequence: u64,
    expected_sequence: u64,
    next_sequence: u64,
    idempotency_key: String,
    generation_digest: String,
    evidence_root_digest: Option<String>,
    receipt_digest: String,
}

impl CjDeliveryReceipt {
    pub fn status(&self) -> &CjDeliveryStatus {
        &self.status
    }

    pub const fn stream(&self) -> CjDeliveryStream {
        self.stream
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub fn evidence_root_digest(&self) -> Option<&str> {
        self.evidence_root_digest.as_deref()
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjReconcileCheckpoint {
    schema_version: String,
    scope: CjReconcileScope,
    plan: CjReadPlan,
    generation: CjProviderGeneration,
    expected_webhook_events: u64,
    next_page: u32,
    pending_cursor: Option<CjReconcileCursor>,
    next_webhook_sequence: u64,
    pages: BTreeMap<u32, CjPageDelivery>,
    webhooks: BTreeMap<u64, CjWebhookDelivery>,
    page_nodes: BTreeMap<u32, CjEvidenceNode>,
    webhook_nodes: BTreeMap<u64, CjEvidenceNode>,
    evidence_root: Option<CjEvidenceRoot>,
    checkpoint_digest: String,
}

impl CjReconcileCheckpoint {
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    pub const fn next_page(&self) -> u32 {
        self.next_page
    }

    pub fn pending_cursor(&self) -> Option<&CjReconcileCursor> {
        self.pending_cursor.as_ref()
    }

    pub fn evidence_root(&self) -> Option<&CjEvidenceRoot> {
        self.evidence_root.as_ref()
    }

    pub fn validate(&self) -> Result<(), CjError> {
        if self.schema_version != CJ_RECONCILE_SCHEMA_VERSION
            || self.generation.validate_scope(&self.scope).is_err()
            || !is_sha256(&self.checkpoint_digest)
            || self.checkpoint_digest != self.calculated_checkpoint_digest()?
            || self.next_page == 0
            || self.next_webhook_sequence == 0
        {
            return Err(CjError::InvalidCheckpoint);
        }
        let query_digest = self.plan.query_digest(self.scope.base())?;
        for sequence in 1..self.next_page {
            let delivery = self
                .pages
                .get(&sequence)
                .ok_or(CjError::InvalidCheckpoint)?;
            delivery.validate_against(&self.scope, &self.plan, &self.generation)?;
            if delivery.sequence() != sequence
                || self
                    .page_nodes
                    .get(&sequence)
                    .is_none_or(|node| node != &CjEvidenceNode::from_page(delivery))
            {
                return Err(CjError::InvalidCheckpoint);
            }
            let expected_input = if sequence == 1 {
                None
            } else {
                self.pages
                    .get(&(sequence - 1))
                    .and_then(CjPageDelivery::next_cursor)
                    .cloned()
            };
            if delivery.input_cursor != expected_input {
                return Err(CjError::InvalidCheckpoint);
            }
            if query_digest
                != delivery
                    .input_cursor
                    .as_ref()
                    .map_or(query_digest.as_str(), CjReconcileCursor::query_digest)
            {
                return Err(CjError::InvalidCheckpoint);
            }
        }
        if self.pages.len() != self.page_nodes.len()
            || u32::try_from(self.pages.len())
                .map_or(true, |len| len != self.next_page.saturating_sub(1))
        {
            return Err(CjError::InvalidCheckpoint);
        }
        let expected_pending = self
            .pages
            .values()
            .next_back()
            .and_then(CjPageDelivery::next_cursor)
            .cloned();
        if self.pending_cursor != expected_pending {
            return Err(CjError::InvalidCheckpoint);
        }
        for sequence in 1..self.next_webhook_sequence {
            let delivery = self
                .webhooks
                .get(&sequence)
                .ok_or(CjError::InvalidCheckpoint)?;
            delivery.validate_against(&self.scope, &self.generation)?;
            if delivery.sequence() != sequence
                || self
                    .webhook_nodes
                    .get(&sequence)
                    .is_none_or(|node| node != &CjEvidenceNode::from_webhook(delivery))
            {
                return Err(CjError::InvalidCheckpoint);
            }
        }
        if self.webhooks.len() != self.webhook_nodes.len()
            || self.webhooks.len() as u64 != self.next_webhook_sequence.saturating_sub(1)
            || self.webhooks.len() as u64 > self.expected_webhook_events
        {
            return Err(CjError::InvalidCheckpoint);
        }
        if let Some(root) = &self.evidence_root {
            if self.pending_cursor.is_some()
                || self.webhooks.len() as u64 != self.expected_webhook_events
            {
                return Err(CjError::InvalidCheckpoint);
            }
            root.validate_against(
                &self.scope,
                &self.plan,
                &self.generation,
                &self.page_nodes,
                &self.webhook_nodes,
            )?;
        }
        Ok(())
    }

    fn calculated_checkpoint_digest(&self) -> Result<String, CjError> {
        let mut unsigned = self.clone();
        unsigned.checkpoint_digest.clear();
        let value = serde_json::to_value(unsigned).map_err(|_| CjError::InvalidCheckpoint)?;
        Ok(sha256_json(&value))
    }
}

#[derive(Clone, Debug)]
pub struct CjReconcileSession {
    scope: CjReconcileScope,
    plan: CjReadPlan,
    query_digest: String,
    generation: CjProviderGeneration,
    authority: CjReconcileAuthority,
    expected_webhook_events: u64,
    next_page: u32,
    pending_cursor: Option<CjReconcileCursor>,
    next_webhook_sequence: u64,
    pages: BTreeMap<u32, CjPageDelivery>,
    webhooks: BTreeMap<u64, CjWebhookDelivery>,
    page_nodes: BTreeMap<u32, CjEvidenceNode>,
    webhook_nodes: BTreeMap<u64, CjEvidenceNode>,
    evidence_root: Option<CjEvidenceRoot>,
}

impl CjReconcileSession {
    pub fn new(
        base_scope: CjScope,
        plan: CjReadPlan,
        generation: CjProviderGeneration,
        authority: CjReconcileAuthority,
        expected_webhook_events: u64,
    ) -> Result<Self, CjError> {
        let scope = CjReconcileScope::new(base_scope, generation.program_id().clone())?;
        generation.validate_scope(&scope)?;
        let query_digest = plan.query_digest(scope.base())?;
        authority.bind(&generation)?;
        Ok(Self {
            scope,
            plan,
            query_digest,
            generation,
            authority,
            expected_webhook_events,
            next_page: 1,
            pending_cursor: None,
            next_webhook_sequence: 1,
            pages: BTreeMap::new(),
            webhooks: BTreeMap::new(),
            page_nodes: BTreeMap::new(),
            webhook_nodes: BTreeMap::new(),
            evidence_root: None,
        })
    }

    pub fn scope(&self) -> &CjReconcileScope {
        &self.scope
    }

    pub fn plan(&self) -> &CjReadPlan {
        &self.plan
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn generation(&self) -> &CjProviderGeneration {
        &self.generation
    }

    pub const fn next_page(&self) -> u32 {
        self.next_page
    }

    pub fn pending_cursor(&self) -> Option<&CjReconcileCursor> {
        self.pending_cursor.as_ref()
    }

    pub fn pages(&self) -> impl Iterator<Item = &CjPageDelivery> {
        self.pages.values()
    }

    pub fn webhooks(&self) -> impl Iterator<Item = &CjWebhookDelivery> {
        self.webhooks.values()
    }

    pub fn evidence_root(&self) -> Option<&CjEvidenceRoot> {
        self.evidence_root.as_ref()
    }

    pub fn accept_page(
        &mut self,
        delivery: CjPageDelivery,
        at: DateTime<Utc>,
    ) -> Result<CjReconcileOutcome, CjError> {
        self.authority.validate(&self.generation)?;
        delivery.validate_against(&self.scope, &self.plan, &self.generation)?;
        if let Some(existing) = self.pages.get(&delivery.sequence()) {
            if existing.delivery_digest == delivery.delivery_digest {
                return Ok(CjReconcileOutcome::Duplicate(self.delivery_receipt(
                    CjDeliveryStatus::Duplicate,
                    &delivery.event,
                    u64::from(self.next_page),
                    u64::from(self.next_page),
                    &delivery.idempotency_key,
                )));
            }
            return Err(CjError::DigestMismatch);
        }
        if self
            .pages
            .values()
            .any(|existing| existing.event.event_id() == delivery.event.event_id())
        {
            return Err(CjError::ProviderEventMismatch);
        }
        if self.evidence_root.is_some() {
            return Err(CjError::EvidenceRootClosed);
        }
        if at < delivery.observed_at || at >= delivery.valid_until {
            return Err(CjError::Disconnected);
        }
        if delivery.sequence() > self.next_page {
            return Ok(CjReconcileOutcome::OutOfOrder(self.delivery_receipt(
                CjDeliveryStatus::OutOfOrder,
                &delivery.event,
                u64::from(self.next_page),
                u64::from(self.next_page),
                &delivery.idempotency_key,
            )));
        }
        if delivery.sequence() < self.next_page {
            return Err(CjError::CursorRollback);
        }
        if delivery.input_cursor != self.pending_cursor {
            return Err(CjError::CursorRollback);
        }
        let next_cursor = delivery.next_cursor.clone();
        let sequence = delivery.sequence();
        let idempotency_key = delivery.idempotency_key.clone();
        let event = delivery.event.clone();
        self.page_nodes
            .insert(sequence, CjEvidenceNode::from_page(&delivery));
        self.pages.insert(sequence, delivery);
        self.next_page = sequence.saturating_add(1);
        self.pending_cursor = next_cursor;
        Ok(CjReconcileOutcome::Applied(self.delivery_receipt(
            CjDeliveryStatus::Applied,
            &event,
            u64::from(sequence),
            u64::from(self.next_page),
            &idempotency_key,
        )))
    }

    pub fn accept_webhook(
        &mut self,
        delivery: CjWebhookDelivery,
        at: DateTime<Utc>,
    ) -> Result<CjReconcileOutcome, CjError> {
        self.authority.validate(&self.generation)?;
        delivery.validate_against(&self.scope, &self.generation)?;
        if let Some(existing) = self
            .webhooks
            .values()
            .find(|existing| existing.event.event_id() == delivery.event.event_id())
        {
            if existing.delivery_digest == delivery.delivery_digest {
                return Ok(CjReconcileOutcome::Duplicate(self.delivery_receipt(
                    CjDeliveryStatus::Duplicate,
                    &delivery.event,
                    self.next_webhook_sequence,
                    self.next_webhook_sequence,
                    &delivery.idempotency_key,
                )));
            }
            return Err(CjError::DigestMismatch);
        }
        if self.webhooks.contains_key(&delivery.sequence()) {
            return Err(CjError::ProviderEventMismatch);
        }
        if self.evidence_root.is_some() {
            return Err(CjError::EvidenceRootClosed);
        }
        if at < delivery.observed_at || at >= delivery.valid_until {
            return Err(CjError::Disconnected);
        }
        if delivery.sequence() > self.next_webhook_sequence {
            return Ok(CjReconcileOutcome::OutOfOrder(self.delivery_receipt(
                CjDeliveryStatus::OutOfOrder,
                &delivery.event,
                self.next_webhook_sequence,
                self.next_webhook_sequence,
                &delivery.idempotency_key,
            )));
        }
        if delivery.sequence() < self.next_webhook_sequence {
            return Err(CjError::WebhookReplay);
        }
        let sequence = delivery.sequence();
        let idempotency_key = delivery.idempotency_key.clone();
        let event = delivery.event.clone();
        self.webhook_nodes
            .insert(sequence, CjEvidenceNode::from_webhook(&delivery));
        self.webhooks.insert(sequence, delivery);
        self.next_webhook_sequence = sequence.saturating_add(1);
        Ok(CjReconcileOutcome::Applied(self.delivery_receipt(
            CjDeliveryStatus::Applied,
            &event,
            sequence,
            self.next_webhook_sequence,
            &idempotency_key,
        )))
    }

    pub fn close_result(&mut self, at: DateTime<Utc>) -> Result<CjMissionReconcileResult, CjError> {
        self.authority.validate(&self.generation)?;
        if self.evidence_root.is_some() {
            return Err(CjError::EvidenceRootClosed);
        }
        if self.pages.is_empty()
            || self.pending_cursor.is_some()
            || u32::try_from(self.pages.len())
                .map_or(true, |len| self.next_page != len.saturating_add(1))
            || self.webhooks.len() as u64 != self.expected_webhook_events
            || self.next_webhook_sequence != self.expected_webhook_events.saturating_add(1)
        {
            return Err(CjError::EvidenceRootOpen);
        }
        if self
            .pages
            .values()
            .any(|delivery| at < delivery.observed_at() || at >= delivery.valid_until())
            || self
                .webhooks
                .values()
                .any(|delivery| at < delivery.observed_at() || at >= delivery.valid_until())
        {
            return Err(CjError::EvidenceRootOpen);
        }
        let cost = self
            .pages
            .values()
            .next_back()
            .ok_or(CjError::EvidenceRootOpen)?
            .cost()
            .clone();
        let root = CjEvidenceRoot::new(
            &self.scope,
            &self.plan,
            &self.generation,
            &self.page_nodes,
            &self.webhook_nodes,
            cost,
            at,
        )?;
        let result =
            CjMissionReconcileResult::from_root(&self.scope, &self.generation, root.clone())?;
        self.evidence_root = Some(root);
        Ok(result)
    }

    pub fn checkpoint(&self) -> Result<CjReconcileCheckpoint, CjError> {
        self.authority.validate(&self.generation)?;
        self.validate_state()?;
        let mut checkpoint = CjReconcileCheckpoint {
            schema_version: CJ_RECONCILE_SCHEMA_VERSION.to_owned(),
            scope: self.scope.clone(),
            plan: self.plan.clone(),
            generation: self.generation.clone(),
            expected_webhook_events: self.expected_webhook_events,
            next_page: self.next_page,
            pending_cursor: self.pending_cursor.clone(),
            next_webhook_sequence: self.next_webhook_sequence,
            pages: self.pages.clone(),
            webhooks: self.webhooks.clone(),
            page_nodes: self.page_nodes.clone(),
            webhook_nodes: self.webhook_nodes.clone(),
            evidence_root: self.evidence_root.clone(),
            checkpoint_digest: String::new(),
        };
        checkpoint.checkpoint_digest = checkpoint.calculated_checkpoint_digest()?;
        Ok(checkpoint)
    }

    pub fn reopen(
        checkpoint: CjReconcileCheckpoint,
        base_scope: CjScope,
        plan: CjReadPlan,
        generation: CjProviderGeneration,
        authority: CjReconcileAuthority,
    ) -> Result<Self, CjError> {
        checkpoint.validate()?;
        let expected_scope = CjReconcileScope::new(base_scope, generation.program_id().clone())?;
        if checkpoint.scope != expected_scope
            || checkpoint.plan != plan
            || checkpoint.generation != generation
        {
            return Err(CjError::GenerationDrift);
        }
        let mut session = Self::new(
            expected_scope.base.clone(),
            plan,
            generation,
            authority,
            checkpoint.expected_webhook_events,
        )?;
        session.next_page = checkpoint.next_page;
        session.pending_cursor = checkpoint.pending_cursor;
        session.next_webhook_sequence = checkpoint.next_webhook_sequence;
        session.pages = checkpoint.pages;
        session.webhooks = checkpoint.webhooks;
        session.page_nodes = checkpoint.page_nodes;
        session.webhook_nodes = checkpoint.webhook_nodes;
        session.evidence_root = checkpoint.evidence_root;
        session.validate_state()?;
        Ok(session)
    }

    fn validate_state(&self) -> Result<(), CjError> {
        self.generation.validate_scope(&self.scope)?;
        if self.next_page == 0
            || self.next_webhook_sequence == 0
            || u32::try_from(self.pages.len())
                .map_or(true, |len| len != self.next_page.saturating_sub(1))
            || self.webhooks.len() as u64 != self.next_webhook_sequence.saturating_sub(1)
            || self.webhooks.len() as u64 > self.expected_webhook_events
            || self.pages.len() != self.page_nodes.len()
            || self.webhooks.len() != self.webhook_nodes.len()
        {
            return Err(CjError::InvalidCheckpoint);
        }
        for sequence in 1..self.next_page {
            let delivery = self
                .pages
                .get(&sequence)
                .ok_or(CjError::InvalidCheckpoint)?;
            delivery.validate_against(&self.scope, &self.plan, &self.generation)?;
            if self.page_nodes.get(&sequence) != Some(&CjEvidenceNode::from_page(delivery)) {
                return Err(CjError::InvalidCheckpoint);
            }
            let expected_input = if sequence == 1 {
                None
            } else {
                self.pages
                    .get(&(sequence - 1))
                    .and_then(CjPageDelivery::next_cursor)
                    .cloned()
            };
            if delivery.input_cursor != expected_input {
                return Err(CjError::InvalidCheckpoint);
            }
        }
        let expected_pending = self
            .pages
            .values()
            .next_back()
            .and_then(CjPageDelivery::next_cursor)
            .cloned();
        if self.pending_cursor != expected_pending {
            return Err(CjError::InvalidCheckpoint);
        }
        for sequence in 1..self.next_webhook_sequence {
            let delivery = self
                .webhooks
                .get(&sequence)
                .ok_or(CjError::InvalidCheckpoint)?;
            delivery.validate_against(&self.scope, &self.generation)?;
            if self.webhook_nodes.get(&sequence) != Some(&CjEvidenceNode::from_webhook(delivery)) {
                return Err(CjError::InvalidCheckpoint);
            }
        }
        if let Some(root) = &self.evidence_root {
            if self.pending_cursor.is_some()
                || self.webhooks.len() as u64 != self.expected_webhook_events
            {
                return Err(CjError::InvalidCheckpoint);
            }
            root.validate_against(
                &self.scope,
                &self.plan,
                &self.generation,
                &self.page_nodes,
                &self.webhook_nodes,
            )?;
        }
        Ok(())
    }

    fn delivery_receipt(
        &self,
        status: CjDeliveryStatus,
        event: &CjProviderEventIdentity,
        expected_sequence: u64,
        next_sequence: u64,
        idempotency_key: &str,
    ) -> CjDeliveryReceipt {
        let status_digest = format!("{status:?}");
        let evidence_root_digest = self
            .evidence_root
            .as_ref()
            .map(|root| root.root_digest().to_owned());
        let receipt_digest = digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            &status_digest,
            &format!("{:?}", event.stream()),
            event.event_id(),
            &event.sequence().to_string(),
            &expected_sequence.to_string(),
            &next_sequence.to_string(),
            idempotency_key,
            self.generation.digest(),
            evidence_root_digest.as_deref().unwrap_or(""),
        ]);
        CjDeliveryReceipt {
            status,
            stream: event.stream(),
            event_id: event.event_id().to_owned(),
            sequence: event.sequence(),
            expected_sequence,
            next_sequence,
            idempotency_key: idempotency_key.to_owned(),
            generation_digest: self.generation.digest().to_owned(),
            evidence_root_digest,
            receipt_digest,
        }
    }
}

/// Closed, typed reconciliation evidence that Mission composition can accept.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjMissionReconcileResult {
    pub mission_capability: String,
    pub provider_id: String,
    pub publisher_id: CjPublisherId,
    pub advertiser_id: CjAdvertiserId,
    pub program_id: CjProgramId,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub provider_generation: u64,
    pub generation_digest: String,
    pub evidence_root_digest: String,
    pub page_count: u32,
    pub webhook_count: u64,
    pub valid_until: DateTime<Utc>,
    pub result_digest: String,
    pub evidence_root: CjEvidenceRoot,
}

impl CjMissionReconcileResult {
    fn from_root(
        scope: &CjReconcileScope,
        generation: &CjProviderGeneration,
        evidence_root: CjEvidenceRoot,
    ) -> Result<Self, CjError> {
        if !evidence_root.is_closed()
            || evidence_root.scope_digest() != scope.digest()?
            || evidence_root.generation_digest() != generation.digest()
            || evidence_root.provider_generation() != generation.provider_generation()
        {
            return Err(CjError::InvalidCheckpoint);
        }
        let result_digest = digest_parts([
            CJ_RECONCILE_SCHEMA_VERSION,
            CJ_RECONCILE_SERVICE_ID,
            scope.digest()?.as_str(),
            generation.digest(),
            evidence_root.root_digest(),
            &evidence_root.page_count().to_string(),
            &evidence_root.webhook_count().to_string(),
            &evidence_root.closed_at().to_rfc3339(),
        ]);
        Ok(Self {
            mission_capability: CJ_RECONCILE_MISSION_CAPABILITY.to_owned(),
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().clone(),
            program_id: scope.program_id().clone(),
            credential_revision: generation.credential_revision(),
            probe_revision: generation.probe_revision(),
            provider_generation: generation.provider_generation(),
            generation_digest: generation.digest().to_owned(),
            evidence_root_digest: evidence_root.root_digest().to_owned(),
            page_count: evidence_root.page_count(),
            webhook_count: evidence_root.webhook_count(),
            valid_until: evidence_root.valid_until(),
            result_digest,
            evidence_root,
        })
    }

    pub fn evidence_root(&self) -> &CjEvidenceRoot {
        &self.evidence_root
    }
}

#[derive(Clone, Debug)]
pub struct CjMissionReconcileExpectation {
    pub mission_id: String,
    pub mission_revision: u64,
    pub provider_id: String,
    pub publisher_id: CjPublisherId,
    pub advertiser_id: CjAdvertiserId,
    pub program_id: CjProgramId,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub provider_generation: u64,
    pub generation_digest: String,
    pub evidence_root_digest: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjMissionReconcileReceipt {
    pub mission_id: String,
    pub mission_revision: u64,
    pub provider_id: String,
    pub publisher_id: CjPublisherId,
    pub advertiser_id: CjAdvertiserId,
    pub program_id: CjProgramId,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub provider_generation: u64,
    pub generation_digest: String,
    pub evidence_root_digest: String,
    pub result_digest: String,
}

#[derive(Clone, Debug, Default)]
pub struct CjMissionReconcileConsumer;

impl CjMissionReconcileConsumer {
    pub fn consume(
        &self,
        mission: &Mission,
        scope: &CjReconcileScope,
        result: &CjMissionReconcileResult,
        expected: &CjMissionReconcileExpectation,
        at: DateTime<Utc>,
    ) -> Result<CjMissionReconcileReceipt, CjError> {
        mission
            .contract
            .validate(at)
            .map_err(|error| CjError::Mission(error.to_string()))?;
        let exact = mission.id.as_str() == expected.mission_id
            && mission.revision == expected.mission_revision
            && mission.tenant_id.as_str() == scope.tenant_id()
            && mission.project_id.as_str() == scope.project_id()
            && mission
                .contract
                .enabled_capabilities
                .contains(CJ_RECONCILE_MISSION_CAPABILITY)
            && expected.provider_id == CJ_PROVIDER_ID
            && expected.publisher_id == *scope.publisher_id()
            && expected.advertiser_id == *scope.advertiser_id()
            && expected.program_id == *scope.program_id()
            && expected.credential_revision == result.credential_revision
            && expected.probe_revision == result.probe_revision
            && expected.provider_generation == result.provider_generation
            && expected.generation_digest == result.generation_digest
            && expected.evidence_root_digest == result.evidence_root_digest
            && result.mission_capability == CJ_RECONCILE_MISSION_CAPABILITY
            && result.provider_id == CJ_PROVIDER_ID
            && result.publisher_id == *scope.publisher_id()
            && result.advertiser_id == *scope.advertiser_id()
            && result.program_id == *scope.program_id()
            && result.evidence_root.scope_digest() == scope.digest()?
            && result.evidence_root.generation_digest() == result.generation_digest
            && result.evidence_root.provider_generation() == result.provider_generation
            && result.evidence_root.root_digest() == result.evidence_root_digest
            && result.evidence_root.page_count() == result.page_count
            && result.evidence_root.webhook_count() == result.webhook_count
            && result.evidence_root.is_closed()
            && at >= result.evidence_root.closed_at()
            && at < result.valid_until
            && result.result_digest == calculated_result_digest(scope, result);
        if !exact {
            return Err(CjError::MissionBinding);
        }
        Ok(CjMissionReconcileReceipt {
            mission_id: expected.mission_id.clone(),
            mission_revision: expected.mission_revision,
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: expected.publisher_id.clone(),
            advertiser_id: expected.advertiser_id.clone(),
            program_id: expected.program_id.clone(),
            credential_revision: expected.credential_revision,
            probe_revision: expected.probe_revision,
            provider_generation: expected.provider_generation,
            generation_digest: expected.generation_digest.clone(),
            evidence_root_digest: expected.evidence_root_digest.clone(),
            result_digest: result.result_digest.clone(),
        })
    }
}

fn calculated_result_digest(scope: &CjReconcileScope, result: &CjMissionReconcileResult) -> String {
    let scope_digest = scope
        .digest()
        .unwrap_or_else(|_| "invalid-scope".to_owned());
    digest_parts([
        CJ_RECONCILE_SCHEMA_VERSION,
        CJ_RECONCILE_SERVICE_ID,
        scope_digest.as_str(),
        result.evidence_root.generation_digest(),
        result.evidence_root.root_digest(),
        &result.page_count.to_string(),
        &result.webhook_count.to_string(),
        &result.evidence_root.closed_at().to_rfc3339(),
    ])
}

fn valid_provider_event_id(value: &str) -> bool {
    (value.starts_with("cj-page-event-") || value.starts_with("webhook-event-"))
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn source_value(body: &str, tag: &str) -> Option<String> {
    extract_xml_values(body, tag).into_iter().next()
}

fn source_value_bytes(body: &[u8], tag: &str) -> Option<String> {
    std::str::from_utf8(body)
        .ok()
        .and_then(|value| source_value(value, tag))
}

fn sha256_bytes(value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(value);
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn sha256_json(value: &Value) -> String {
    serde_json::to_string(value).map_or_else(
        |_| sha256_hex("invalid-json"),
        |encoded| sha256_hex(&encoded),
    )
}

fn serialized_digest<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .map_or_else(|_| sha256_hex("invalid-json"), |value| sha256_json(&value))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CjReconcileOutcome {
    Applied(CjDeliveryReceipt),
    Duplicate(CjDeliveryReceipt),
    OutOfOrder(CjDeliveryReceipt),
}
