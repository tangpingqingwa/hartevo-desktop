//! The first production-authenticated partner read service.
//!
//! This module deliberately wraps the existing Connector SDK worker instead of
//! defining another auth, probe, or dispatch lifecycle. It adds the
//! provider-specific Mission contract that the generic SDK observation cannot
//! carry: Mission identity, official source URI, durable page cursor, cost,
//! freshness and evidence classification.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{
    ConnectorAdapter, ConnectorError, ConnectorScope, ConnectorWorker, Cursor, DispatchBudget,
    ProbeResult, ProviderAdapterOperation, ProviderAdapterRegistry, ProviderCapabilityKey,
    ProviderEvidenceClass, ProviderProvenanceClass, ReadObservation,
};
use hartevo_domain_kernel::Mission;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contract::{
    NetworkProvider, NetworkResource, NetworkScope, canonical_digest, digest_bytes,
};
use crate::{NetworkAccountId, ProgramId};

pub const IMPACT_PROGRAM_READ_SERVICE_ID: &str = "partner.impact.programs.read/v1";
pub const PARTNER_PROGRAM_READ_MISSION_CAPABILITY: &str = "partner.program.read";
pub const PARTNER_READ_CURSOR_SCHEMA_VERSION: &str = "hartevo-partner-read-cursor/v1";
pub const PARTNER_READ_RECEIPT_SCHEMA_VERSION: &str = "hartevo-partner-read-receipt/v1";

/// Tenant/project/Mission/account/program binding for a provider read.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartnerReadScope {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub account_id: NetworkAccountId,
    pub program_id: Option<ProgramId>,
}

impl PartnerReadScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        account_id: NetworkAccountId,
        program_id: Option<ProgramId>,
    ) -> Result<Self, PartnerReadError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            account_id,
            program_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_mission(
        mission: &Mission,
        account_id: NetworkAccountId,
        program_id: Option<ProgramId>,
    ) -> Result<Self, PartnerReadError> {
        Self::new(
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            mission.id.as_str(),
            account_id,
            program_id,
        )
    }

    pub fn validate(&self) -> Result<(), PartnerReadError> {
        if self.tenant_id.trim().is_empty()
            || self.project_id.trim().is_empty()
            || self.mission_id.trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.tenant_id.chars().any(char::is_control)
            || self.project_id.chars().any(char::is_control)
            || self.mission_id.chars().any(char::is_control)
        {
            return Err(PartnerReadError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_digest(self).expect("PartnerReadScope is serializable")
    }

    pub fn network_scope(&self) -> Result<NetworkScope, PartnerReadError> {
        NetworkScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            self.account_id.clone(),
            self.program_id.clone(),
        )
        .map_err(|_| PartnerReadError::InvalidScope)
    }

    pub fn connector_scope(&self) -> Result<ConnectorScope, PartnerReadError> {
        let mut capabilities = vec![PARTNER_PROGRAM_READ_MISSION_CAPABILITY.to_owned()];
        if let Some(program_id) = &self.program_id {
            capabilities.push(format!("program:{program_id}"));
        }
        ConnectorScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            NetworkProvider::Impact.as_str(),
            self.account_id.as_str(),
            capabilities,
        )
        .map_err(|_| PartnerReadError::InvalidScope)
    }
}

/// The unit/currency/source tuple is a budget fact, not a claim about
/// Impact's settlement or a payout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartnerReadCost {
    pub units: u64,
    pub currency: Option<String>,
    pub pricing_source: String,
    pub observed_at: DateTime<Utc>,
}

impl PartnerReadCost {
    pub fn new(
        units: u64,
        currency: Option<String>,
        pricing_source: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, PartnerReadError> {
        let pricing_source = pricing_source.into();
        if units == 0
            || pricing_source.trim().is_empty()
            || pricing_source.chars().any(char::is_control)
            || currency
                .as_deref()
                .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err(PartnerReadError::InvalidCost);
        }
        Ok(Self {
            units,
            currency,
            pricing_source,
            observed_at,
        })
    }
}

/// Per-dispatch budget supplied by the Mission consumer. The SDK's own
/// DispatchBudget remains authoritative for quota/rate admission; this typed
/// budget additionally charges the service's known provider-read cost because
/// the generic SDK read operation has zero effect cost by design.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartnerReadBudget {
    pub rate_remaining: u64,
    pub rate_reset_at: DateTime<Utc>,
    pub quota_remaining: u64,
    pub cost_limit_minor: i64,
}

impl Default for PartnerReadBudget {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            rate_remaining: 1,
            rate_reset_at: now + Duration::minutes(1),
            quota_remaining: 1,
            cost_limit_minor: 1,
        }
    }
}

impl PartnerReadBudget {
    pub fn new(
        rate_remaining: u64,
        rate_reset_at: DateTime<Utc>,
        quota_remaining: u64,
        cost_limit_minor: i64,
    ) -> Result<Self, PartnerReadError> {
        if cost_limit_minor < 0 {
            return Err(PartnerReadError::InvalidCost);
        }
        Ok(Self {
            rate_remaining,
            rate_reset_at,
            quota_remaining,
            cost_limit_minor,
        })
    }

    pub fn check(&self, cost: &PartnerReadCost, at: DateTime<Utc>) -> Result<(), PartnerReadError> {
        if self.rate_remaining == 0 && at < self.rate_reset_at {
            return Err(PartnerReadError::RateLimited);
        }
        if self.quota_remaining == 0 {
            return Err(PartnerReadError::QuotaExceeded);
        }
        let units = i64::try_from(cost.units).map_err(|_| PartnerReadError::InvalidCost)?;
        if units > self.cost_limit_minor {
            return Err(PartnerReadError::CostLimitExceeded);
        }
        Ok(())
    }

    fn dispatch_budget(&self) -> Result<DispatchBudget, PartnerReadError> {
        DispatchBudget::new(
            self.rate_remaining,
            self.rate_reset_at,
            self.quota_remaining,
            self.cost_limit_minor,
        )
        .map_err(PartnerReadError::from)
    }
}

/// A provider-native page cursor that is safe to persist and replay only for
/// the exact Mission/account/query binding that created it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurablePartnerReadCursor {
    pub schema_version: String,
    pub service_id: String,
    pub scope_digest: String,
    pub query_digest: String,
    pub page: u64,
    pub provider_cursor: String,
    pub source_digest: String,
    pub cursor_digest: String,
}

impl DurablePartnerReadCursor {
    pub fn new(
        service_id: impl Into<String>,
        scope: &PartnerReadScope,
        query_digest: impl Into<String>,
        page: u64,
        provider_cursor: impl Into<String>,
        source_digest: impl Into<String>,
    ) -> Result<Self, PartnerReadError> {
        let mut cursor = Self {
            schema_version: PARTNER_READ_CURSOR_SCHEMA_VERSION.into(),
            service_id: service_id.into(),
            scope_digest: scope.digest(),
            query_digest: query_digest.into(),
            page,
            provider_cursor: provider_cursor.into(),
            source_digest: source_digest.into(),
            cursor_digest: String::new(),
        };
        cursor.validate_binding(scope)?;
        cursor.cursor_digest = cursor.binding_digest();
        Ok(cursor)
    }

    pub fn page(&self) -> u64 {
        self.page
    }

    pub fn provider_cursor(&self) -> &str {
        &self.provider_cursor
    }

    pub fn validate_for(
        &self,
        service_id: &str,
        scope: &PartnerReadScope,
        query_digest: &str,
    ) -> Result<(), PartnerReadError> {
        self.validate_binding(scope)?;
        if self.service_id != service_id
            || self.query_digest != query_digest
            || self.cursor_digest != self.binding_digest()
        {
            return Err(PartnerReadError::CursorMismatch);
        }
        Ok(())
    }

    fn validate_binding(&self, scope: &PartnerReadScope) -> Result<(), PartnerReadError> {
        scope.validate()?;
        if self.schema_version != PARTNER_READ_CURSOR_SCHEMA_VERSION
            || self.scope_digest != scope.digest()
            || !is_sha256(&self.query_digest)
            || !is_sha256(&self.source_digest)
            || self.page == 0
            || self.provider_cursor != format!("page:{}", self.page)
        {
            return Err(PartnerReadError::InvalidCursor);
        }
        Ok(())
    }

    fn binding_digest(&self) -> String {
        digest_bytes(
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                self.schema_version,
                self.service_id,
                self.scope_digest,
                self.query_digest,
                self.page,
                self.provider_cursor,
                self.source_digest,
            )
            .as_bytes(),
        )
    }
}

/// Evidence classification is intentionally separate from a Connected or
/// Opt-in state. Only `ProductionAuthenticated` can produce a product read
/// receipt; fixture and BLOCKED_ENV paths remain test/environment outcomes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartnerReadClassification {
    ProductionAuthenticated,
    ControlledProvider,
    Fixture,
    BlockedEnv,
    Disconnected,
}

impl PartnerReadClassification {
    fn from_sdk(provenance: ProviderProvenanceClass) -> Self {
        match provenance {
            ProviderProvenanceClass::ProductionProvider => Self::ProductionAuthenticated,
            ProviderProvenanceClass::ControlledProvider => Self::ControlledProvider,
            ProviderProvenanceClass::Fixture | ProviderProvenanceClass::ComponentHarness => {
                Self::Fixture
            }
        }
    }
}

/// Registry metadata state. `Registered` is not a Connected claim and is not
/// sufficient to complete a product read; a live production probe is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartnerReadConnectionState {
    Disconnected,
    Registered,
}

impl PartnerReadConnectionState {
    pub const fn is_disconnected(self) -> bool {
        matches!(self, Self::Disconnected)
    }
}

#[derive(Clone, Debug)]
pub struct ImpactProgramReadServiceDefinition {
    pub service_id: String,
    pub provider: NetworkProvider,
    pub capability: ProviderCapabilityKey,
    pub resource: NetworkResource,
    pub freshness: Duration,
    pub cost: PartnerReadCost,
}

impl Default for ImpactProgramReadServiceDefinition {
    fn default() -> Self {
        Self::new(Utc::now()).expect("static Impact read definition is valid")
    }
}

impl ImpactProgramReadServiceDefinition {
    pub fn new(observed_at: DateTime<Utc>) -> Result<Self, PartnerReadError> {
        Ok(Self {
            service_id: IMPACT_PROGRAM_READ_SERVICE_ID.into(),
            provider: NetworkProvider::Impact,
            capability: ProviderCapabilityKey::new(
                NetworkProvider::Impact.as_str(),
                PARTNER_PROGRAM_READ_MISSION_CAPABILITY,
            )
            .map_err(|_| PartnerReadError::InvalidDefinition)?,
            resource: NetworkResource::Programs,
            freshness: Duration::seconds(30),
            cost: PartnerReadCost::new(1, None, "impact-official-api/v1", observed_at)?,
        })
    }

    pub fn connection_state(
        &self,
        registry: &ProviderAdapterRegistry,
    ) -> PartnerReadConnectionState {
        if registry.is_empty() || registry.validate().is_err() {
            return PartnerReadConnectionState::Disconnected;
        }
        let probe_key = ProviderCapabilityKey::new(self.provider.as_str(), "connection.probe").ok();
        let has_production = |key: &ProviderCapabilityKey, operation| {
            registry.registrations().iter().any(|registration| {
                registration.key() == key
                    && registration.evidence_support().iter().any(|support| {
                        support.operation() == operation
                            && support.evidence_class() == ProviderEvidenceClass::ReadObservation
                            && support.provenance_class()
                                == ProviderProvenanceClass::ProductionProvider
                    })
            })
        };
        let has_probe = probe_key.is_some_and(|key| {
            registry.registrations().iter().any(|registration| {
                registration.key() == &key
                    && registration.evidence_support().iter().any(|support| {
                        support.operation() == ProviderAdapterOperation::Probe
                            && support.evidence_class() == ProviderEvidenceClass::ProbeObservation
                            && support.provenance_class()
                                == ProviderProvenanceClass::ProductionProvider
                    })
            })
        });
        if has_probe && has_production(&self.capability, ProviderAdapterOperation::Read) {
            PartnerReadConnectionState::Registered
        } else {
            PartnerReadConnectionState::Disconnected
        }
    }

    pub fn read_mission<A: ConnectorAdapter>(
        &self,
        worker: &mut ConnectorWorker<A>,
        mission: &Mission,
        probe: &ProbeResult,
        request: &ImpactProgramReadRequest,
    ) -> Result<PartnerReadReceipt, PartnerReadError> {
        if mission.tenant_id.as_str() != request.scope.tenant_id
            || mission.project_id.as_str() != request.scope.project_id
            || mission.id.as_str() != request.scope.mission_id
        {
            return Err(PartnerReadError::MissionScopeMismatch);
        }
        if !mission
            .contract
            .enabled_capabilities
            .contains(self.capability.capability_id())
        {
            return Err(PartnerReadError::MissionCapabilityMissing);
        }
        if request.at < mission.contract.valid_from || request.at >= mission.contract.valid_until {
            return Err(PartnerReadError::MissionContractExpired);
        }
        request.validate(self)?;
        let expected_scope = request.scope.connector_scope()?;
        if worker.scope() != &expected_scope {
            return Err(PartnerReadError::MissionScopeMismatch);
        }
        request.budget.check(&self.cost, request.at)?;
        if probe.provenance_class() != ProviderProvenanceClass::ProductionProvider {
            return Err(PartnerReadError::NonProductionEvidence(
                PartnerReadClassification::from_sdk(probe.provenance_class()),
            ));
        }
        let live_probe = worker
            .authorize_probe(probe, request.at)
            .map_err(PartnerReadError::from)?;
        let sdk_cursor = request
            .cursor
            .as_ref()
            .map(|cursor| {
                Cursor::new(
                    &expected_scope,
                    request.query_digest.clone(),
                    cursor.page.saturating_sub(1),
                    digest_bytes(cursor.provider_cursor.as_bytes()),
                )
                .map_err(PartnerReadError::from)
            })
            .transpose()?;
        let observation = worker
            .read(hartevo_connector_sdk::ReadRequest {
                dispatch: worker.dispatch_fence(),
                scope: expected_scope.clone(),
                live_probe,
                capability: self.capability.clone(),
                query_digest: request.query_digest.clone(),
                cursor: sdk_cursor,
                page_size: request.page_size,
                at: request.at,
                budget: request.budget.dispatch_budget()?,
            })
            .map_err(PartnerReadError::from)?;
        self.receipt(request, &observation)
    }

    fn receipt(
        &self,
        request: &ImpactProgramReadRequest,
        observation: &ReadObservation,
    ) -> Result<PartnerReadReceipt, PartnerReadError> {
        let classification = PartnerReadClassification::from_sdk(observation.provenance_class());
        if classification != PartnerReadClassification::ProductionAuthenticated {
            return Err(PartnerReadError::NonProductionEvidence(classification));
        }
        let page = observation.page_sequence();
        let source_uri = crate::impact::program_page_url(
            &request.scope.account_id,
            page,
            u16::try_from(request.page_size).map_err(|_| PartnerReadError::InvalidPageSize)?,
        );
        let next_cursor = observation
            .next_cursor()
            .map(|_| {
                DurablePartnerReadCursor::new(
                    self.service_id.clone(),
                    &request.scope,
                    request.query_digest.clone(),
                    page.saturating_add(1),
                    format!("page:{}", page.saturating_add(1)),
                    observation.response_digest(),
                )
            })
            .transpose()?;
        Ok(PartnerReadReceipt::new(
            self,
            request,
            observation,
            source_uri,
            classification,
            next_cursor,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImpactProgramReadRequest {
    pub scope: PartnerReadScope,
    pub query_digest: String,
    pub cursor: Option<DurablePartnerReadCursor>,
    pub page_size: u32,
    pub at: DateTime<Utc>,
    #[serde(skip)]
    pub budget: PartnerReadBudget,
}

impl ImpactProgramReadRequest {
    pub fn new(scope: PartnerReadScope, at: DateTime<Utc>) -> Result<Self, PartnerReadError> {
        let query_digest = digest_bytes(scope.digest().as_bytes());
        Ok(Self {
            scope,
            query_digest,
            cursor: None,
            page_size: 100,
            at,
            budget: PartnerReadBudget::new(1, at + Duration::minutes(1), 1, 1)?,
        })
    }

    #[must_use]
    pub fn with_query_digest(mut self, query_digest: impl Into<String>) -> Self {
        self.query_digest = query_digest.into();
        self
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: DurablePartnerReadCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    #[must_use]
    pub fn with_page_size(mut self, page_size: u32) -> Self {
        self.page_size = page_size;
        self
    }

    #[must_use]
    pub fn with_budget(mut self, budget: PartnerReadBudget) -> Self {
        self.budget = budget;
        self
    }

    fn validate(
        &self,
        definition: &ImpactProgramReadServiceDefinition,
    ) -> Result<(), PartnerReadError> {
        self.scope.validate()?;
        if !is_sha256(&self.query_digest) {
            return Err(PartnerReadError::InvalidRequest);
        }
        if !(1..=500).contains(&self.page_size) {
            return Err(PartnerReadError::InvalidPageSize);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate_for(&definition.service_id, &self.scope, &self.query_digest)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartnerReadReceipt {
    pub schema_version: String,
    pub service_id: String,
    pub provider: NetworkProvider,
    pub resource: NetworkResource,
    pub scope: PartnerReadScope,
    pub source_uri: String,
    pub observed_at: DateTime<Utc>,
    pub freshness_valid_until: DateTime<Utc>,
    pub source_revision: u64,
    pub request_digest: String,
    pub source_digest: String,
    pub content_digest: String,
    pub classification: PartnerReadClassification,
    pub page_sequence: u64,
    pub item_count: u32,
    pub cost: PartnerReadCost,
    pub quota_consumed: u64,
    pub next_cursor: Option<DurablePartnerReadCursor>,
    pub receipt_digest: String,
}

impl PartnerReadReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        definition: &ImpactProgramReadServiceDefinition,
        request: &ImpactProgramReadRequest,
        observation: &ReadObservation,
        source_uri: String,
        classification: PartnerReadClassification,
        next_cursor: Option<DurablePartnerReadCursor>,
    ) -> Self {
        let mut receipt = Self {
            schema_version: PARTNER_READ_RECEIPT_SCHEMA_VERSION.into(),
            service_id: definition.service_id.clone(),
            provider: definition.provider,
            resource: definition.resource,
            scope: request.scope.clone(),
            source_uri,
            observed_at: observation.freshness().observed_at(),
            freshness_valid_until: observation
                .freshness()
                .valid_until()
                .min(observation.freshness().observed_at() + definition.freshness),
            source_revision: observation.freshness().source_revision(),
            request_digest: observation.request_digest().to_owned(),
            source_digest: observation.response_digest().to_owned(),
            content_digest: observation.content_digest().to_owned(),
            classification,
            page_sequence: observation.page_sequence(),
            item_count: observation.item_count(),
            cost: definition.cost.clone(),
            quota_consumed: 1,
            next_cursor,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.binding_digest();
        receipt
    }

    pub fn validate(&self) -> Result<(), PartnerReadError> {
        if self.schema_version != PARTNER_READ_RECEIPT_SCHEMA_VERSION
            || self.classification != PartnerReadClassification::ProductionAuthenticated
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.source_digest)
            || !is_sha256(&self.content_digest)
            || self.page_sequence == 0
            || self.source_uri.trim().is_empty()
            || self.freshness_valid_until <= self.observed_at
            || self.source_revision == 0
            || self.quota_consumed != 1
            || self.receipt_digest != self.binding_digest()
        {
            return Err(PartnerReadError::InvalidReceipt);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for(&self.service_id, &self.scope, &self.request_digest)?;
        }
        Ok(())
    }

    pub fn source_time(&self) -> DateTime<Utc> {
        self.observed_at
    }

    fn binding_digest(&self) -> String {
        digest_bytes(
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                self.schema_version,
                self.service_id,
                self.provider.as_str(),
                self.resource as u8,
                self.scope.digest(),
                self.source_uri,
                self.observed_at.to_rfc3339(),
                self.freshness_valid_until.to_rfc3339(),
                self.source_revision,
                self.request_digest,
                self.source_digest,
                self.content_digest,
                self.page_sequence,
                self.item_count,
                self.classification as u8,
            )
            .as_bytes(),
        )
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PartnerReadError {
    #[error("partner read service is disconnected because no exact registry exists")]
    Disconnected,
    #[error("Mission contract does not enable the partner program read")]
    MissionCapabilityMissing,
    #[error("Mission and connector read scope do not match")]
    MissionScopeMismatch,
    #[error("Mission contract is not valid at the requested read time")]
    MissionContractExpired,
    #[error("partner read scope is invalid")]
    InvalidScope,
    #[error("partner read service definition is invalid")]
    InvalidDefinition,
    #[error("partner read request is invalid")]
    InvalidRequest,
    #[error("partner read page size is outside the bounded range")]
    InvalidPageSize,
    #[error("durable partner read cursor is invalid")]
    InvalidCursor,
    #[error("durable partner read cursor does not match the request")]
    CursorMismatch,
    #[error("partner read cost is invalid")]
    InvalidCost,
    #[error("partner read quota is exhausted")]
    QuotaExceeded,
    #[error("partner read rate limit is exhausted")]
    RateLimited,
    #[error("partner read cost limit is exhausted")]
    CostLimitExceeded,
    #[error("fixture or blocked environment evidence cannot complete a product read: {0:?}")]
    NonProductionEvidence(PartnerReadClassification),
    #[error("partner read receipt is invalid")]
    InvalidReceipt,
    #[error("connector SDK error: {0}")]
    Sdk(#[source] ConnectorError),
}

impl From<ConnectorError> for PartnerReadError {
    fn from(error: ConnectorError) -> Self {
        match error {
            ConnectorError::UnregisteredAdapter => Self::Disconnected,
            ConnectorError::UnsupportedProvenance => {
                Self::NonProductionEvidence(PartnerReadClassification::Disconnected)
            }
            ConnectorError::QuotaExceeded => Self::QuotaExceeded,
            ConnectorError::RateLimited => Self::RateLimited,
            ConnectorError::CostLimitExceeded => Self::CostLimitExceeded,
            ConnectorError::InvalidPageSize => Self::InvalidPageSize,
            ConnectorError::CursorMismatch => Self::CursorMismatch,
            ConnectorError::InvalidCursor => Self::InvalidCursor,
            error => Self::Sdk(error),
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl fmt::Display for PartnerReadConnectionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => formatter.write_str("disconnected"),
            Self::Registered => formatter.write_str("registered"),
        }
    }
}
