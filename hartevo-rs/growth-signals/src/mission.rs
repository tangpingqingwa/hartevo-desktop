use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{ConnectorError, ConnectorScope, ProviderProvenanceClass};
use hartevo_domain_kernel::{
    Evidence, EvidenceId, EvidenceStatus, Mission, MissionError, MissionId, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DATAFORSEO_LABS_READ_CAPABILITY, DATAFORSEO_PROVIDER_ID, DataForSeoError,
    DataForSeoEvidenceClassification, DataForSeoGrowthSignal, Ga4GrowthSignal, GscGrowthSignal,
};

pub const DATAFORSEO_MISSION_CONSUMER_ID: &str = "mission.consumer.dataforseo.labs.read";

#[derive(Clone, Debug, Error, PartialEq)]
pub enum DataForSeoMissionError {
    #[error("Mission consumer scope does not match the growth signal")]
    ScopeMismatch,
    #[error("Mission consumer accepts only estimate-only DataForSEO evidence")]
    FirstPartyClaim,
    #[error("Mission is not writable")]
    Mission(#[from] MissionError),
    #[error("DataForSEO result is invalid")]
    Provider(#[from] DataForSeoError),
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataForSeoMissionConsumer {
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    account_id: String,
}

impl DataForSeoMissionConsumer {
    pub fn new(
        mission_id: MissionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        account_id: impl Into<String>,
    ) -> Result<Self, DataForSeoMissionError> {
        let account_id = account_id.into();
        if account_id.trim().is_empty() {
            return Err(DataForSeoMissionError::ScopeMismatch);
        }
        Ok(Self {
            mission_id,
            tenant_id,
            project_id,
            account_id,
        })
    }

    pub fn from_mission(
        mission: &Mission,
        account_id: impl Into<String>,
    ) -> Result<Self, DataForSeoMissionError> {
        Self::new(
            mission.id.clone(),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            account_id,
        )
    }

    pub fn consume(
        &self,
        signal: &DataForSeoGrowthSignal,
    ) -> Result<DataForSeoMissionOutput, DataForSeoMissionError> {
        let scope = signal.scope();
        let observation = signal.read_observation();
        if scope.provider_id() != DATAFORSEO_PROVIDER_ID
            || scope.account_id() != self.account_id
            || scope.tenant_id() != self.tenant_id.as_str()
            || scope.project_id() != self.project_id.as_str()
            || observation.scope() != scope
            || observation.capability().provider_id() != DATAFORSEO_PROVIDER_ID
            || observation.capability().capability_id() != DATAFORSEO_LABS_READ_CAPABILITY
            || (observation.provenance_class() != ProviderProvenanceClass::ProductionProvider
                && observation.provenance_class() != ProviderProvenanceClass::ControlledProvider)
        {
            return Err(DataForSeoMissionError::ScopeMismatch);
        }
        if signal.classification() != DataForSeoEvidenceClassification::ProviderEstimate
            || signal.first_party()
            || signal.estimate().first_party()
        {
            return Err(DataForSeoMissionError::FirstPartyClaim);
        }
        let evidence_id = EvidenceId::from_stable(format!(
            "dataforseo-evidence-{}",
            stable_digest(&[
                self.mission_id.as_str(),
                signal.raw_evidence_digest(),
                &observation.page_sequence().to_string(),
            ])
        ));
        let evidence = Evidence {
            id: evidence_id,
            title: format!(
                "DataForSEO estimated keyword demand for {}",
                signal.request().target_domain()
            ),
            source_uri: signal.source_uri().to_owned(),
            observed_at: signal.observed_at(),
            confidence: 0.0,
            status: EvidenceStatus::Candidate,
            content_digest: signal.raw_evidence_digest().to_owned(),
        };
        Ok(DataForSeoMissionOutput {
            consumer_id: DATAFORSEO_MISSION_CONSUMER_ID.to_owned(),
            mission_id: self.mission_id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            provider_id: scope.provider_id().to_owned(),
            account_id: scope.account_id().to_owned(),
            classification: signal.classification(),
            first_party: signal.first_party(),
            page_sequence: observation.page_sequence(),
            item_count: observation.item_count(),
            charged: signal.charged(),
            replayed: signal.replayed(),
            source_revision: signal.source_revision(),
            raw_evidence_digest: signal.raw_evidence_digest().to_owned(),
            evidence,
        })
    }

    pub fn record_into(
        &self,
        mission: &mut Mission,
        signal: &DataForSeoGrowthSignal,
        now: DateTime<Utc>,
    ) -> Result<DataForSeoMissionOutput, DataForSeoMissionError> {
        if mission.id != self.mission_id
            || mission.tenant_id != self.tenant_id
            || mission.project_id != self.project_id
        {
            return Err(DataForSeoMissionError::ScopeMismatch);
        }
        let output = self.consume(signal)?;
        mission.record_evidence(output.evidence.clone(), now)?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoMissionOutput {
    consumer_id: String,
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    provider_id: String,
    account_id: String,
    classification: DataForSeoEvidenceClassification,
    first_party: bool,
    page_sequence: u64,
    item_count: u32,
    charged: bool,
    replayed: bool,
    source_revision: u64,
    raw_evidence_digest: String,
    evidence: Evidence,
}

impl DataForSeoMissionOutput {
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub const fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub const fn classification(&self) -> DataForSeoEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

fn stable_digest(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

/// The two Google first-party read providers share a Mission-facing result
/// vocabulary, while their request/response and transport types remain owned
/// by `gsc.rs` and `ga4.rs` respectively.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchAnalyticsProvider {
    GoogleSearchConsole,
    GoogleAnalytics4,
}

impl SearchAnalyticsProvider {
    pub const fn provider_id(self) -> &'static str {
        match self {
            Self::GoogleSearchConsole => "google-search-console",
            Self::GoogleAnalytics4 => "google-analytics-4",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchAnalyticsEvidenceClassification {
    FirstParty,
    ControlledFixture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchAnalyticsCostClass {
    ProviderReadFree,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAnalyticsQuotaReceipt {
    pub(crate) provider_request_id: String,
    pub(crate) quota_units: u64,
    pub(crate) quota_limit: Option<u64>,
    pub(crate) quota_remaining: Option<u64>,
    pub(crate) charged: bool,
}

impl SearchAnalyticsQuotaReceipt {
    pub(crate) fn new(
        provider_request_id: impl Into<String>,
        quota_units: u64,
        quota_limit: Option<u64>,
        quota_remaining: Option<u64>,
        charged: bool,
    ) -> Self {
        Self {
            provider_request_id: provider_request_id.into(),
            quota_units,
            quota_limit,
            quota_remaining,
            charged,
        }
    }

    pub fn provider_request_id(&self) -> &str {
        &self.provider_request_id
    }

    pub const fn quota_units(&self) -> u64 {
        self.quota_units
    }

    pub const fn quota_limit(&self) -> Option<u64> {
        self.quota_limit
    }

    pub const fn quota_remaining(&self) -> Option<u64> {
        self.quota_remaining
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAnalyticsFreshness {
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) valid_until: DateTime<Utc>,
    pub(crate) source_revision: u64,
}

impl SearchAnalyticsFreshness {
    pub(crate) fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        source_revision: u64,
    ) -> Result<Self, ConnectorError> {
        if valid_until <= observed_at || source_revision == 0 {
            return Err(ConnectorError::InvalidFreshness);
        }
        Ok(Self {
            observed_at,
            valid_until,
            source_revision,
        })
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAnalyticsReadReceipt {
    pub(crate) provider: SearchAnalyticsProvider,
    pub(crate) endpoint: String,
    pub(crate) api_version: String,
    pub(crate) provider_request_id: String,
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) response_digest: String,
    pub(crate) raw_evidence_digest: String,
    pub(crate) cost_class: SearchAnalyticsCostClass,
}

impl SearchAnalyticsReadReceipt {
    pub(crate) fn new(
        provider: SearchAnalyticsProvider,
        endpoint: impl Into<String>,
        api_version: impl Into<String>,
        provider_request_id: impl Into<String>,
        observed_at: DateTime<Utc>,
        response_digest: impl Into<String>,
        raw_evidence_digest: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            endpoint: endpoint.into(),
            api_version: api_version.into(),
            provider_request_id: provider_request_id.into(),
            observed_at,
            response_digest: response_digest.into(),
            raw_evidence_digest: raw_evidence_digest.into(),
            cost_class: SearchAnalyticsCostClass::ProviderReadFree,
        }
    }

    pub const fn provider(&self) -> SearchAnalyticsProvider {
        self.provider
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub fn provider_request_id(&self) -> &str {
        &self.provider_request_id
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn cost_class(&self) -> SearchAnalyticsCostClass {
        self.cost_class
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SearchAnalyticsSignal {
    GoogleSearchConsole(GscGrowthSignal),
    GoogleAnalytics4(Ga4GrowthSignal),
}

impl SearchAnalyticsSignal {
    pub const fn provider(&self) -> SearchAnalyticsProvider {
        match self {
            Self::GoogleSearchConsole(_) => SearchAnalyticsProvider::GoogleSearchConsole,
            Self::GoogleAnalytics4(_) => SearchAnalyticsProvider::GoogleAnalytics4,
        }
    }

    pub fn scope(&self) -> &ConnectorScope {
        match self {
            Self::GoogleSearchConsole(signal) => signal.scope(),
            Self::GoogleAnalytics4(signal) => signal.scope(),
        }
    }

    pub fn property_id(&self) -> &str {
        match self {
            Self::GoogleSearchConsole(signal) => signal.property(),
            Self::GoogleAnalytics4(signal) => signal.property_id(),
        }
    }

    pub fn source_uri(&self) -> &str {
        match self {
            Self::GoogleSearchConsole(signal) => signal.source_uri(),
            Self::GoogleAnalytics4(signal) => signal.source_uri(),
        }
    }

    pub const fn classification(&self) -> SearchAnalyticsEvidenceClassification {
        match self {
            Self::GoogleSearchConsole(signal) => signal.classification(),
            Self::GoogleAnalytics4(signal) => signal.classification(),
        }
    }

    pub const fn first_party(&self) -> bool {
        match self {
            Self::GoogleSearchConsole(signal) => signal.first_party(),
            Self::GoogleAnalytics4(signal) => signal.first_party(),
        }
    }

    pub const fn page_sequence(&self) -> u64 {
        match self {
            Self::GoogleSearchConsole(signal) => signal.page_sequence(),
            Self::GoogleAnalytics4(signal) => signal.page_sequence(),
        }
    }

    pub const fn item_count(&self) -> u32 {
        match self {
            Self::GoogleSearchConsole(signal) => signal.item_count(),
            Self::GoogleAnalytics4(signal) => signal.item_count(),
        }
    }

    pub const fn source_revision(&self) -> u64 {
        match self {
            Self::GoogleSearchConsole(signal) => signal.source_revision(),
            Self::GoogleAnalytics4(signal) => signal.source_revision(),
        }
    }

    pub fn raw_evidence_digest(&self) -> &str {
        match self {
            Self::GoogleSearchConsole(signal) => signal.raw_evidence_digest(),
            Self::GoogleAnalytics4(signal) => signal.raw_evidence_digest(),
        }
    }

    pub const fn charged(&self) -> bool {
        match self {
            Self::GoogleSearchConsole(signal) => signal.charged(),
            Self::GoogleAnalytics4(signal) => signal.charged(),
        }
    }

    pub const fn replayed(&self) -> bool {
        match self {
            Self::GoogleSearchConsole(signal) => signal.replayed(),
            Self::GoogleAnalytics4(signal) => signal.replayed(),
        }
    }
}

pub const SEARCH_ANALYTICS_MISSION_CONSUMER_ID: &str =
    "mission.consumer.google.search-analytics.read";

#[derive(Clone, Debug, Error, PartialEq)]
pub enum SearchAnalyticsMissionError {
    #[error("Mission consumer scope does not match the search analytics signal")]
    ScopeMismatch,
    #[error("Mission is not writable")]
    Mission(#[from] MissionError),
}

/// Mission-facing consumer for either first-party Google read result.  It
/// accepts only the typed provider result envelope; it cannot authorize an
/// Effect or turn a controlled fixture into a connected provider.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchAnalyticsReadService {
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    account_id: String,
}

impl SearchAnalyticsReadService {
    pub fn new(
        mission_id: MissionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        account_id: impl Into<String>,
    ) -> Result<Self, SearchAnalyticsMissionError> {
        let account_id = account_id.into();
        if account_id.trim().is_empty() {
            return Err(SearchAnalyticsMissionError::ScopeMismatch);
        }
        Ok(Self {
            mission_id,
            tenant_id,
            project_id,
            account_id,
        })
    }

    pub fn from_mission(
        mission: &Mission,
        account_id: impl Into<String>,
    ) -> Result<Self, SearchAnalyticsMissionError> {
        Self::new(
            mission.id.clone(),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            account_id,
        )
    }

    pub fn consume(
        &self,
        signal: &SearchAnalyticsSignal,
    ) -> Result<SearchAnalyticsMissionOutput, SearchAnalyticsMissionError> {
        let scope = signal.scope();
        if scope.tenant_id() != self.tenant_id.as_str()
            || scope.project_id() != self.project_id.as_str()
            || scope.account_id() != self.account_id
            || scope.provider_id() != signal.provider().provider_id()
            || signal.first_party()
                != (signal.classification() == SearchAnalyticsEvidenceClassification::FirstParty)
        {
            return Err(SearchAnalyticsMissionError::ScopeMismatch);
        }
        let evidence_id = EvidenceId::from_stable(format!(
            "search-analytics-evidence-{}",
            stable_digest(&[
                self.mission_id.as_str(),
                signal.raw_evidence_digest(),
                &signal.page_sequence().to_string(),
            ])
        ));
        let evidence = Evidence {
            id: evidence_id,
            title: format!(
                "{} search analytics for {}",
                signal.provider().provider_id(),
                signal.property_id()
            ),
            source_uri: signal.source_uri().to_owned(),
            observed_at: match signal {
                SearchAnalyticsSignal::GoogleSearchConsole(value) => value.observed_at(),
                SearchAnalyticsSignal::GoogleAnalytics4(value) => value.observed_at(),
            },
            confidence: if signal.first_party() { 0.8 } else { 0.0 },
            status: EvidenceStatus::Candidate,
            content_digest: signal.raw_evidence_digest().to_owned(),
        };
        Ok(SearchAnalyticsMissionOutput {
            consumer_id: SEARCH_ANALYTICS_MISSION_CONSUMER_ID.to_owned(),
            mission_id: self.mission_id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            provider_id: scope.provider_id().to_owned(),
            account_id: scope.account_id().to_owned(),
            property_id: signal.property_id().to_owned(),
            classification: signal.classification(),
            first_party: signal.first_party(),
            page_sequence: signal.page_sequence(),
            item_count: signal.item_count(),
            source_revision: signal.source_revision(),
            charged: signal.charged(),
            replayed: signal.replayed(),
            raw_evidence_digest: signal.raw_evidence_digest().to_owned(),
            evidence,
        })
    }

    pub fn record_into(
        &self,
        mission: &mut Mission,
        signal: &SearchAnalyticsSignal,
        now: DateTime<Utc>,
    ) -> Result<SearchAnalyticsMissionOutput, SearchAnalyticsMissionError> {
        if mission.id != self.mission_id
            || mission.tenant_id != self.tenant_id
            || mission.project_id != self.project_id
        {
            return Err(SearchAnalyticsMissionError::ScopeMismatch);
        }
        let output = self.consume(signal)?;
        mission.record_evidence(output.evidence.clone(), now)?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAnalyticsMissionOutput {
    consumer_id: String,
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    provider_id: String,
    account_id: String,
    property_id: String,
    classification: SearchAnalyticsEvidenceClassification,
    first_party: bool,
    page_sequence: u64,
    item_count: u32,
    source_revision: u64,
    charged: bool,
    replayed: bool,
    raw_evidence_digest: String,
    evidence: Evidence,
}

impl SearchAnalyticsMissionOutput {
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn classification(&self) -> SearchAnalyticsEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn property_id(&self) -> &str {
        &self.property_id
    }
}
