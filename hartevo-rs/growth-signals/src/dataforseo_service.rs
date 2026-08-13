//! DataForSEO's Mission-facing read-only connector service seam.
//!
//! This module owns the provider-specific service definition, registration
//! lifecycle, bounded read provider, and Mission consumer. It projects into
//! the merged Connector SDK types; it does not introduce another connector
//! lifecycle trait or mutate Application/Desktop state.

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{
    ConnectorDescriptor, ConnectorError, ConnectorScope, ProbeStatus, ProviderAdapterOperation,
    ProviderProvenanceClass, ReadObservation,
};
use hartevo_domain_kernel::{
    Evidence, EvidenceId, EvidenceStatus, Mission, MissionError, MissionId, ProjectId, TenantId,
};
use rust_decimal::Decimal;
use serde::Serialize;
use thiserror::Error;

use crate::{
    EvidenceClassification, Freshness, canonical_digest,
    dataforseo::{
        DATAFORSEO_MAX_PAGE_SIZE, DATAFORSEO_PROVIDER_ID, DataForSeoAccountProbe, DataForSeoClient,
        DataForSeoError, DataForSeoPageCursor, DataForSeoRateLimit, DataForSeoSearchPage,
        DataForSeoSearchRequest, DataForSeoTransport,
    },
    sdk::{ADAPTER_VERSION, capability, descriptor_for},
};

pub const DATAFORSEO_SERVICE_ID: &str = "growth-signals.dataforseo.read";
pub const DATAFORSEO_MISSION_CONSUMER_ID: &str = "hartevo.mission.growth-signal";
pub const DATAFORSEO_PROBE_CAPABILITY: &str = "connection.probe";
pub const DATAFORSEO_READ_CAPABILITY: &str = "search.measure";
const DATAFORSEO_ADAPTER_ID: &str = "hartevo.dataforseo";

/// The non-secret contract exposed by the provider service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoConnectorServiceDefinition {
    service_id: String,
    provider_id: String,
    adapter_id: String,
    adapter_version: u32,
    capability_ids: Vec<String>,
    read_only: bool,
}

impl DataForSeoConnectorServiceDefinition {
    pub fn new() -> Result<Self, ConnectorError> {
        let descriptor = descriptor_for(DATAFORSEO_PROVIDER_ID, DATAFORSEO_ADAPTER_ID)?;
        let probe_capability = capability(DATAFORSEO_PROVIDER_ID, DATAFORSEO_PROBE_CAPABILITY)?;
        let read_capability = capability(DATAFORSEO_PROVIDER_ID, DATAFORSEO_READ_CAPABILITY)?;
        if !descriptor.supports(
            &probe_capability,
            ProviderAdapterOperation::Probe,
            ProviderProvenanceClass::ControlledProvider,
        ) || !descriptor.supports(
            &probe_capability,
            ProviderAdapterOperation::Probe,
            ProviderProvenanceClass::ProductionProvider,
        ) || !descriptor.supports(
            &read_capability,
            ProviderAdapterOperation::Read,
            ProviderProvenanceClass::ControlledProvider,
        ) || !descriptor.supports(
            &read_capability,
            ProviderAdapterOperation::Read,
            ProviderProvenanceClass::ProductionProvider,
        ) {
            return Err(ConnectorError::UnregisteredAdapter);
        }
        Ok(Self {
            service_id: DATAFORSEO_SERVICE_ID.into(),
            provider_id: DATAFORSEO_PROVIDER_ID.into(),
            adapter_id: DATAFORSEO_ADAPTER_ID.into(),
            adapter_version: ADAPTER_VERSION,
            capability_ids: vec![
                DATAFORSEO_PROBE_CAPABILITY.into(),
                DATAFORSEO_READ_CAPABILITY.into(),
            ],
            read_only: true,
        })
    }

    pub fn descriptor(&self) -> Result<ConnectorDescriptor, ConnectorError> {
        descriptor_for(&self.provider_id, &self.adapter_id)
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub const fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    pub fn capability_ids(&self) -> &[String] {
        &self.capability_ids
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum DataForSeoServiceError {
    #[error(transparent)]
    DataForSeo(#[from] DataForSeoError),
    #[error(transparent)]
    Connector(#[from] ConnectorError),
    #[error("DataForSEO provider scope does not exactly match the requested tenant/project")]
    ScopeMismatch,
    #[error("DataForSEO service registration is not mounted")]
    NotMounted,
    #[error("DataForSEO service registration is revoked")]
    Revoked,
    #[error("DataForSEO service registration has an invalid revocation reason digest")]
    InvalidRevocationReason,
    #[error("DataForSEO service registration is already revoked")]
    AlreadyRevoked,
    #[error("DataForSEO Mission consumer configuration is invalid")]
    InvalidConsumer,
    #[error(transparent)]
    Mission(#[from] MissionError),
}

/// A typed DataForSEO provider. The first read authenticates through the
/// account probe, then returns one bounded keyword observation and its durable
/// next cursor. The client replay ledger ensures later cursor reads do not
/// dispatch the same billable SERP request again.
#[derive(Debug)]
pub struct DataForSeoReadProvider<T: DataForSeoTransport> {
    client: DataForSeoClient<T>,
    request: DataForSeoSearchRequest,
    page_size: usize,
    observed_at: DateTime<Utc>,
    provenance: ProviderProvenanceClass,
    account_probe: Option<DataForSeoAccountProbe>,
}

impl<T: DataForSeoTransport> DataForSeoReadProvider<T> {
    pub fn new(
        client: DataForSeoClient<T>,
        request: DataForSeoSearchRequest,
        page_size: usize,
        observed_at: DateTime<Utc>,
        provenance: ProviderProvenanceClass,
    ) -> Result<Self, DataForSeoServiceError> {
        let connector_scope = client.secret_reference().scope();
        if request.mode() != crate::dataforseo::DataForSeoMode::Live
            || page_size == 0
            || page_size > DATAFORSEO_MAX_PAGE_SIZE
        {
            return Err(DataForSeoError::InvalidRequest.into());
        }
        if connector_scope.tenant_id() != request.scope().tenant_id().as_str()
            || connector_scope.project_id() != request.scope().project_id().as_str()
        {
            return Err(DataForSeoServiceError::ScopeMismatch);
        }
        Ok(Self {
            client,
            request,
            page_size,
            observed_at,
            provenance,
            account_probe: None,
        })
    }

    pub fn read_result(&mut self) -> Result<DataForSeoReadResult, DataForSeoServiceError> {
        self.read_page(None)
    }

    pub fn read_page(
        &mut self,
        cursor: Option<&DataForSeoPageCursor>,
    ) -> Result<DataForSeoReadResult, DataForSeoServiceError> {
        let account_probe = if let Some(probe) = &self.account_probe {
            probe.clone()
        } else {
            let probe = self
                .client
                .probe_account_with_provenance(self.observed_at, self.provenance)?;
            self.account_probe = Some(probe.clone());
            probe
        };
        let page =
            self.client
                .read_live_page(&self.request, self.page_size, cursor, self.observed_at)?;
        let sdk_observation = self
            .client
            .sdk_read_page_observation(&page, self.provenance)?;
        Ok(DataForSeoReadResult {
            account_probe,
            page,
            sdk_observation,
            estimated_cost_usd: self.request.estimate_only_evidence().estimated_cost_usd(),
        })
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), DataForSeoServiceError> {
        self.client.revoke(revoked_at)?;
        Ok(())
    }

    pub const fn request(&self) -> &DataForSeoSearchRequest {
        &self.request
    }

    pub fn scope(&self) -> &ConnectorScope {
        self.client.secret_reference().scope()
    }

    pub fn account_id(&self) -> &str {
        self.scope().account_id()
    }

    pub const fn page_size(&self) -> usize {
        self.page_size
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoReadResult {
    account_probe: DataForSeoAccountProbe,
    page: DataForSeoSearchPage,
    sdk_observation: ReadObservation,
    estimated_cost_usd: Decimal,
}

impl DataForSeoReadResult {
    pub const fn account_probe(&self) -> &DataForSeoAccountProbe {
        &self.account_probe
    }

    pub const fn page(&self) -> &DataForSeoSearchPage {
        &self.page
    }

    pub const fn sdk_observation(&self) -> &ReadObservation {
        &self.sdk_observation
    }

    pub const fn connector_scope(&self) -> &ConnectorScope {
        self.account_probe.scope()
    }

    pub fn account_id(&self) -> &str {
        self.connector_scope().account_id()
    }

    pub fn next_cursor(&self) -> Option<&DataForSeoPageCursor> {
        self.page.next_cursor()
    }

    pub fn estimated_cost_usd(&self) -> Decimal {
        self.estimated_cost_usd
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoRegistrationState {
    Mounted,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoServiceRegistration {
    registration_id: String,
    service_id: String,
    provider_id: String,
    scope_digest: String,
    request_digest: String,
    state: DataForSeoRegistrationState,
    revocation_reason_digest: Option<String>,
    revoked_at: Option<DateTime<Utc>>,
}

impl DataForSeoServiceRegistration {
    pub fn registration_id(&self) -> &str {
        &self.registration_id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn state(&self) -> DataForSeoRegistrationState {
        self.state
    }

    pub fn revocation_reason_digest(&self) -> Option<&str> {
        self.revocation_reason_digest.as_deref()
    }

    pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }
}

/// A registration that can be mounted, unmounted, and revoked without
/// exposing credentials or creating a second generic connector interface.
#[derive(Debug)]
pub struct DataForSeoConnectorService<T: DataForSeoTransport> {
    definition: DataForSeoConnectorServiceDefinition,
    registration: DataForSeoServiceRegistration,
    provider: DataForSeoReadProvider<T>,
}

impl<T: DataForSeoTransport> DataForSeoConnectorService<T> {
    pub fn new(provider: DataForSeoReadProvider<T>) -> Result<Self, DataForSeoServiceError> {
        let definition = DataForSeoConnectorServiceDefinition::new()?;
        let request_digest = provider.request().request_digest();
        let scope_digest = provider.scope().digest();
        let registration_digest =
            canonical_digest(&(scope_digest.as_str(), request_digest.as_str()));
        Ok(Self {
            registration: DataForSeoServiceRegistration {
                registration_id: format!("dataforseo-registration-{registration_digest}"),
                service_id: definition.service_id().into(),
                provider_id: definition.provider_id().into(),
                scope_digest,
                request_digest,
                state: DataForSeoRegistrationState::Unmounted,
                revocation_reason_digest: None,
                revoked_at: None,
            },
            definition,
            provider,
        })
    }

    pub fn mount(&mut self) -> Result<(), DataForSeoServiceError> {
        match self.registration.state {
            DataForSeoRegistrationState::Mounted => Ok(()),
            DataForSeoRegistrationState::Unmounted => {
                self.registration.state = DataForSeoRegistrationState::Mounted;
                Ok(())
            }
            DataForSeoRegistrationState::Revoked => Err(DataForSeoServiceError::Revoked),
        }
    }

    pub fn unmount(&mut self) -> Result<(), DataForSeoServiceError> {
        match self.registration.state {
            DataForSeoRegistrationState::Mounted | DataForSeoRegistrationState::Unmounted => {
                self.registration.state = DataForSeoRegistrationState::Unmounted;
                Ok(())
            }
            DataForSeoRegistrationState::Revoked => Err(DataForSeoServiceError::Revoked),
        }
    }

    pub fn revoke(
        &mut self,
        reason_digest: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), DataForSeoServiceError> {
        if !is_sha256(reason_digest) {
            return Err(DataForSeoServiceError::InvalidRevocationReason);
        }
        if self.registration.state == DataForSeoRegistrationState::Revoked {
            return Err(DataForSeoServiceError::AlreadyRevoked);
        }
        self.provider.revoke(revoked_at)?;
        self.registration.state = DataForSeoRegistrationState::Revoked;
        self.registration.revocation_reason_digest = Some(reason_digest.to_owned());
        self.registration.revoked_at = Some(revoked_at);
        Ok(())
    }

    pub fn read_result(&mut self) -> Result<DataForSeoReadResult, DataForSeoServiceError> {
        if self.registration.state != DataForSeoRegistrationState::Mounted {
            return Err(match self.registration.state {
                DataForSeoRegistrationState::Revoked => DataForSeoServiceError::Revoked,
                DataForSeoRegistrationState::Mounted | DataForSeoRegistrationState::Unmounted => {
                    DataForSeoServiceError::NotMounted
                }
            });
        }
        self.provider.read_result()
    }

    pub fn read_page(
        &mut self,
        cursor: Option<&DataForSeoPageCursor>,
    ) -> Result<DataForSeoReadResult, DataForSeoServiceError> {
        if self.registration.state != DataForSeoRegistrationState::Mounted {
            return Err(match self.registration.state {
                DataForSeoRegistrationState::Revoked => DataForSeoServiceError::Revoked,
                DataForSeoRegistrationState::Mounted | DataForSeoRegistrationState::Unmounted => {
                    DataForSeoServiceError::NotMounted
                }
            });
        }
        self.provider.read_page(cursor)
    }

    pub const fn definition(&self) -> &DataForSeoConnectorServiceDefinition {
        &self.definition
    }

    pub const fn registration(&self) -> &DataForSeoServiceRegistration {
        &self.registration
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataForSeoMissionConsumer {
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    account_id: String,
    capability_id: String,
}

impl DataForSeoMissionConsumer {
    pub fn new(
        mission_id: MissionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        account_id: impl Into<String>,
        capability_id: impl Into<String>,
    ) -> Result<Self, DataForSeoServiceError> {
        let account_id = account_id.into();
        let capability_id = capability_id.into();
        if account_id.trim().is_empty() || capability_id != DATAFORSEO_READ_CAPABILITY {
            return Err(DataForSeoServiceError::InvalidConsumer);
        }
        Ok(Self {
            mission_id,
            tenant_id,
            project_id,
            account_id,
            capability_id,
        })
    }

    pub fn from_mission(
        mission: &Mission,
        account_id: impl Into<String>,
        capability_id: impl Into<String>,
    ) -> Result<Self, DataForSeoServiceError> {
        Self::new(
            mission.id.clone(),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            account_id,
            capability_id,
        )
    }

    pub fn consume(
        &self,
        result: &DataForSeoReadResult,
    ) -> Result<DataForSeoMissionOutput, DataForSeoServiceError> {
        let scope = result.connector_scope();
        if scope.provider_id() != DATAFORSEO_PROVIDER_ID
            || scope.account_id() != self.account_id
            || scope.tenant_id() != self.tenant_id.as_str()
            || scope.project_id() != self.project_id.as_str()
            || result.sdk_observation().scope() != scope
            || result.sdk_observation().capability().provider_id() != DATAFORSEO_PROVIDER_ID
            || result.sdk_observation().capability().capability_id() != self.capability_id
        {
            return Err(DataForSeoServiceError::ScopeMismatch);
        }
        if result.account_probe().status() != ProbeStatus::Reachable {
            return Err(DataForSeoServiceError::ScopeMismatch);
        }
        let observation = result.page().observation();
        if observation.classification() != EvidenceClassification::ProviderEstimate
            || observation.first_party()
        {
            return Err(DataForSeoServiceError::ScopeMismatch);
        }
        let evidence_id = EvidenceId::from_stable(format!(
            "dataforseo-evidence-{}",
            canonical_digest(&(self.mission_id.as_str(), observation.raw_evidence_digest(),))
        ));
        let evidence = Evidence {
            id: evidence_id,
            title: format!(
                "DataForSEO estimated search observation: {}",
                observation.keyword()
            ),
            source_uri: format!(
                "dataforseo://{}/serp/google/organic/live/regular?request={}",
                scope.account_id(),
                observation.receipt_reference().request_digest()
            ),
            observed_at: observation.freshness().observed_at(),
            confidence: 0.0,
            status: EvidenceStatus::Candidate,
            content_digest: observation.raw_evidence_digest().to_owned(),
        };
        Ok(DataForSeoMissionOutput {
            consumer_id: DATAFORSEO_MISSION_CONSUMER_ID.into(),
            mission_id: self.mission_id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            provider_id: scope.provider_id().into(),
            account_id: scope.account_id().into(),
            capability_id: self.capability_id.clone(),
            classification: observation.classification(),
            first_party: observation.first_party(),
            request_digest: observation.receipt_reference().request_digest().into(),
            raw_evidence_digest: observation.raw_evidence_digest().into(),
            source_revision: observation.source_revision(),
            page_sequence: result.page().page_sequence(),
            item_count: result.page().items().len(),
            charged: result.page().charged(),
            replayed: result.page().replayed(),
            estimated_cost_usd: result.estimated_cost_usd(),
            provider_cost_usd: observation.cost_usd(),
            rate_limit: observation.rate_limit().clone(),
            freshness: observation.freshness().clone(),
            cursor: result.next_cursor().cloned(),
            probe_status: result.account_probe().status(),
            probe_evidence_digest: result.account_probe().evidence_digest().into(),
            account_probe: result.account_probe().clone(),
            read_observation: result.sdk_observation().clone(),
            evidence,
        })
    }

    pub fn record_into(
        &self,
        mission: &mut Mission,
        result: &DataForSeoReadResult,
        now: DateTime<Utc>,
    ) -> Result<DataForSeoMissionOutput, DataForSeoServiceError> {
        if mission.id != self.mission_id
            || mission.tenant_id != self.tenant_id
            || mission.project_id != self.project_id
        {
            return Err(DataForSeoServiceError::ScopeMismatch);
        }
        let output = self.consume(result)?;
        mission.record_evidence(output.evidence.clone(), now)?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoMissionOutput {
    consumer_id: String,
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    provider_id: String,
    account_id: String,
    capability_id: String,
    classification: EvidenceClassification,
    first_party: bool,
    request_digest: String,
    raw_evidence_digest: String,
    source_revision: u64,
    page_sequence: u64,
    item_count: usize,
    charged: bool,
    replayed: bool,
    estimated_cost_usd: Decimal,
    provider_cost_usd: Decimal,
    rate_limit: DataForSeoRateLimit,
    freshness: Freshness,
    cursor: Option<DataForSeoPageCursor>,
    probe_status: ProbeStatus,
    probe_evidence_digest: String,
    account_probe: DataForSeoAccountProbe,
    read_observation: ReadObservation,
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

    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub const fn item_count(&self) -> usize {
        self.item_count
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub fn cursor(&self) -> Option<&DataForSeoPageCursor> {
        self.cursor.as_ref()
    }

    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub const fn read_observation(&self) -> &ReadObservation {
        &self.read_observation
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_connector_sdk::ConnectorScope;
    use hartevo_domain_kernel::{MissionContract, Task, TaskId, TaskStatus};

    use super::*;
    use crate::{
        CalendarDateRange, LanguageCode, MarketCode, ReadScope,
        dataforseo::{
            DataForSeoDevice, DataForSeoMode, DataForSeoWorldScenario, FakeDataForSeoTransport,
        },
        parse_date,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time")
    }

    fn request() -> DataForSeoSearchRequest {
        let scope = ReadScope::new(
            TenantId::from("tenant-service"),
            ProjectId::from("project-service"),
            MarketCode::new("DE").expect("market"),
            LanguageCode::new("de").expect("language"),
            CalendarDateRange::new(
                parse_date("2026-08-01").expect("date"),
                parse_date("2026-08-07").expect("date"),
            )
            .expect("window"),
        );
        DataForSeoSearchRequest::new(
            scope,
            "service keyword",
            2276,
            DataForSeoDevice::Desktop,
            10,
            DataForSeoMode::Live,
            Decimal::new(10, 2),
            Some(Decimal::new(20, 2)),
        )
        .expect("request")
    }

    fn client() -> DataForSeoClient<FakeDataForSeoTransport> {
        let request = request();
        let scope = ConnectorScope::new(
            request.scope().tenant_id().as_str(),
            request.scope().project_id().as_str(),
            DATAFORSEO_PROVIDER_ID,
            "dataforseo-account",
            ["serp.read".into()],
        )
        .expect("connector scope");
        let secret =
            hartevo_connector_sdk::SecretReference::new("secret-ref-service-test", scope, 1)
                .expect("secret reference");
        DataForSeoClient::new(
            secret,
            FakeDataForSeoTransport::new(DataForSeoWorldScenario::PaginatedResults),
        )
        .expect("client")
    }

    fn provider() -> DataForSeoReadProvider<FakeDataForSeoTransport> {
        DataForSeoReadProvider::new(
            client(),
            request(),
            2,
            now(),
            ProviderProvenanceClass::ControlledProvider,
        )
        .expect("provider")
    }

    #[test]
    fn provider_probe_read_result_binds_scope_cursor_and_sdk_observation() {
        let mut provider = provider();
        let result = provider.read_result().expect("read result");
        assert_eq!(result.account_probe().status(), ProbeStatus::Reachable);
        assert_eq!(result.account_id(), "dataforseo-account");
        assert_eq!(result.connector_scope().tenant_id(), "tenant-service");
        assert_eq!(result.connector_scope().project_id(), "project-service");
        assert_eq!(result.page().items().len(), 2);
        assert_eq!(
            result.sdk_observation().capability().capability_id(),
            "search.measure"
        );
        assert_eq!(result.sdk_observation().page_sequence(), 1);
        assert_eq!(result.next_cursor().expect("next cursor").sequence(), 2);
        assert_eq!(result.account_probe().cost_usd(), Decimal::ZERO);
        assert_eq!(result.account_probe().raw_evidence_digest().len(), 64);

        let cursor = result.next_cursor().cloned().expect("durable cursor");
        let second = provider.read_page(Some(&cursor)).expect("second page");
        assert!(second.page().replayed());
        assert!(!second.page().charged());
    }

    #[test]
    fn registration_mount_unmount_and_revoke_are_fail_closed() {
        let mut service = DataForSeoConnectorService::new(provider()).expect("service");
        assert_eq!(
            service.registration().state(),
            DataForSeoRegistrationState::Unmounted
        );
        assert_eq!(
            service.read_result().expect_err("unmounted"),
            DataForSeoServiceError::NotMounted
        );
        service.mount().expect("mount");
        assert_eq!(
            service.registration().state(),
            DataForSeoRegistrationState::Mounted
        );
        service.read_result().expect("mounted read");
        service.unmount().expect("unmount");
        assert_eq!(
            service.read_result().expect_err("unmounted"),
            DataForSeoServiceError::NotMounted
        );
        service.mount().expect("remount");
        let reason = canonical_digest(&"credential rotation");
        service.revoke(&reason, now()).expect("revoke");
        assert_eq!(
            service.registration().state(),
            DataForSeoRegistrationState::Revoked
        );
        assert_eq!(
            service.read_result().expect_err("revoked"),
            DataForSeoServiceError::Revoked
        );
        assert_eq!(
            service.mount().expect_err("revoked remount"),
            DataForSeoServiceError::Revoked
        );
    }

    #[test]
    fn mission_consumer_records_estimate_candidate_with_exact_scope() {
        let mut service = DataForSeoConnectorService::new(provider()).expect("service");
        service.mount().expect("mount");
        let result = service.read_result().expect("read result");
        let mission_id = MissionId::from_stable("mission-dataforseo-service");
        let consumer = DataForSeoMissionConsumer::new(
            mission_id.clone(),
            TenantId::from("tenant-service"),
            ProjectId::from("project-service"),
            "dataforseo-account",
            DATAFORSEO_READ_CAPABILITY,
        )
        .expect("consumer");
        let mut mission = Mission::compile(
            TenantId::from("tenant-service"),
            mission_id,
            ProjectId::from("project-service"),
            "DataForSEO service mission",
            MissionContract::bootstrap(
                "Observe one bounded search result",
                [DATAFORSEO_READ_CAPABILITY.to_owned()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from_stable("task-dataforseo-service"),
                    title: "Read one bounded DataForSEO result".into(),
                    status: TaskStatus::Ready,
                    capability: DATAFORSEO_READ_CAPABILITY.into(),
                }],
                now(),
            )
            .expect("start mission");
        let output = consumer
            .record_into(&mut mission, &result, now())
            .expect("mission output");
        assert_eq!(output.consumer_id(), DATAFORSEO_MISSION_CONSUMER_ID);
        assert_eq!(output.provider_id(), DATAFORSEO_PROVIDER_ID);
        assert_eq!(output.account_id(), "dataforseo-account");
        assert_eq!(
            output.classification(),
            EvidenceClassification::ProviderEstimate
        );
        assert!(!output.first_party());
        assert_eq!(output.evidence().status, EvidenceStatus::Candidate);
        assert!(output.evidence().confidence.abs() < f32::EPSILON);
        assert_eq!(output.raw_evidence_digest().len(), 64);
        assert_eq!(output.cursor().expect("durable cursor").sequence(), 2);
        assert_eq!(mission.evidence.len(), 1);
        assert_eq!(mission.evidence[0].id, output.evidence().id);
    }

    #[test]
    fn service_definition_is_read_only_and_uses_registered_adapter() {
        let definition = DataForSeoConnectorServiceDefinition::new().expect("definition");
        assert_eq!(definition.service_id(), DATAFORSEO_SERVICE_ID);
        assert_eq!(definition.provider_id(), DATAFORSEO_PROVIDER_ID);
        assert_eq!(definition.adapter_id(), DATAFORSEO_ADAPTER_ID);
        assert_eq!(definition.adapter_version(), ADAPTER_VERSION);
        assert!(definition.read_only());
        assert!(
            definition
                .capability_ids()
                .contains(&DATAFORSEO_READ_CAPABILITY.into())
        );
        assert!(definition.descriptor().expect("descriptor").supports(
            &capability(DATAFORSEO_PROVIDER_ID, DATAFORSEO_READ_CAPABILITY).expect("capability"),
            ProviderAdapterOperation::Read,
            ProviderProvenanceClass::ProductionProvider,
        ));
    }

    #[test]
    fn provider_rejects_tenant_or_project_scope_drift_before_dispatch() {
        let mut request = request();
        let drifted_scope = ReadScope::new(
            TenantId::from("tenant-drift"),
            ProjectId::from("project-service"),
            request.scope().market().clone(),
            request.scope().language().clone(),
            request.scope().window(),
        );
        request = DataForSeoSearchRequest::new(
            drifted_scope,
            request.keyword(),
            request.location_code(),
            DataForSeoDevice::Desktop,
            10,
            DataForSeoMode::Live,
            Decimal::new(10, 2),
            Some(Decimal::new(20, 2)),
        )
        .expect("request");
        assert_eq!(
            DataForSeoReadProvider::new(
                client(),
                request,
                2,
                now(),
                ProviderProvenanceClass::ControlledProvider,
            )
            .expect_err("scope drift"),
            DataForSeoServiceError::ScopeMismatch
        );
    }
}
