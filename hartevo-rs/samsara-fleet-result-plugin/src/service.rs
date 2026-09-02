use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    SAMSARA_FLEET_RESULT_CONSUMER_ID, SAMSARA_FLEET_RESULT_CONTRACT_JSON,
    SAMSARA_FLEET_RESULT_CONTRACT_VERSION, SAMSARA_FLEET_RESULT_PLUGIN_VERSION,
    SAMSARA_FLEET_RESULT_PROVIDER_ID, SAMSARA_FLEET_RESULT_SCHEMA_VERSION,
    SAMSARA_FLEET_RESULT_SERVICE_ID, canonical_digest,
    model::{
        AlertRecord, AssetCondition, AssetReference, Digest, DvirRecord, EquipmentRecord,
        FleetProjection, MAX_BACKOFF_SECONDS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RECORDS_PER_READ,
        MAX_RETRY_ATTEMPTS, MaintenanceRecord, ModelError, OpaqueCursor, RegistrationState,
        Revision, SafetyEventRecord, SamsaraFleetScope, SecretReference, TimeWindow, TripRecord,
        VehicleRecord,
    },
    provider::{
        ProviderDefinitionError, ProviderProvenance, ResponseReceipt, SamsaraEndpoint,
        SamsaraProvider, SamsaraProviderDefinition, SamsaraReadOptions, SamsaraResponseBody,
        SamsaraTransport, TransportError, TransportErrorKind,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("Samsara registration is revoked")]
    RegistrationRevoked,
    #[error("Samsara SecretReference is revoked")]
    SecretRevoked,
    #[error("Samsara provider or service scope does not match")]
    ScopeMismatch,
    #[error("Samsara registration digest or version fence is tampered")]
    RegistrationTampered,
    #[error("Samsara read request is tampered or stale")]
    RequestTampered,
    #[error("Samsara response crossed an allowlisted asset scope")]
    ResponseScopeMismatch,
    #[error("Samsara response exceeded the bounded typed evidence shape")]
    InvalidResponseShape,
    #[error("Samsara page cursor repeated")]
    PageLoop,
    #[error("Samsara provider response was invalid")]
    InvalidProviderResponse,
    #[error(transparent)]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraFleetResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
}

impl SamsaraFleetResultServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: SAMSARA_FLEET_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: SAMSARA_FLEET_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: SAMSARA_FLEET_RESULT_PLUGIN_VERSION.to_owned(),
            service_id: SAMSARA_FLEET_RESULT_SERVICE_ID.to_owned(),
            provider_id: SAMSARA_FLEET_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: SAMSARA_FLEET_RESULT_CONSUMER_ID.to_owned(),
            contract_digest: Digest::from_text(SAMSARA_FLEET_RESULT_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            proposal_only: true,
            native: false,
            connected: false,
        }
    }
}

impl Default for SamsaraFleetResultServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub service_version: String,
    pub provider_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub organization_digest: Digest,
    pub tag_scope_digest: Digest,
    pub vehicle_scope_digest: Digest,
    pub equipment_scope_digest: Digest,
    pub mission_scope_digest: Digest,
    pub project_scope_digest: Digest,
    pub consent_scope_digest: Digest,
    pub permission_digest: Digest,
    pub policy_revision: Revision,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

impl SamsaraRegistration {
    pub fn new(
        scope: &SamsaraFleetScope,
        secret_reference: &SecretReference,
        provider: &SamsaraProviderDefinition,
    ) -> Result<Self, ServiceError> {
        if secret_reference.scope_digest() != scope.scope_digest()
            || provider.provider_id != SAMSARA_FLEET_RESULT_PROVIDER_ID
            || !provider.read_only
            || provider.live_execution
            || provider.native
            || provider.connected
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let revision = Revision::new(1)?;
        let contract_digest = Digest::from_text(SAMSARA_FLEET_RESULT_CONTRACT_JSON);
        let registration_digest = Self::compute_digest(
            &contract_digest,
            &provider.provider_digest(),
            scope,
            secret_reference,
            revision,
        );
        Ok(Self {
            schema_version: SAMSARA_FLEET_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: SAMSARA_FLEET_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: SAMSARA_FLEET_RESULT_PLUGIN_VERSION.to_owned(),
            service_id: SAMSARA_FLEET_RESULT_SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            consumer_id: SAMSARA_FLEET_RESULT_CONSUMER_ID.to_owned(),
            service_version: SAMSARA_FLEET_RESULT_PLUGIN_VERSION.to_owned(),
            provider_version: provider.provider_version.clone(),
            contract_digest,
            provider_digest: provider.provider_digest(),
            scope_digest: scope.scope_digest().clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            organization_digest: scope.organization().digest(),
            tag_scope_digest: scope.tags().digest(),
            vehicle_scope_digest: scope.vehicles().digest(),
            equipment_scope_digest: scope.equipment().digest(),
            mission_scope_digest: scope.mission().digest(),
            project_scope_digest: scope.project().digest(),
            consent_scope_digest: scope.consent().digest(),
            permission_digest: scope.permission_digest().clone(),
            policy_revision: scope.policy_revision(),
            registration_digest,
            revision,
            state: RegistrationState::Active,
        })
    }

    pub fn ensure_active(&self) -> Result<(), ServiceError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ServiceError::RegistrationRevoked)
        }
    }

    pub fn validate_integrity(
        &self,
        scope: &SamsaraFleetScope,
        secret_reference: &SecretReference,
        provider: &SamsaraProviderDefinition,
    ) -> Result<(), ServiceError> {
        if self.schema_version != SAMSARA_FLEET_RESULT_SCHEMA_VERSION
            || self.contract_version != SAMSARA_FLEET_RESULT_CONTRACT_VERSION
            || self.plugin_version != SAMSARA_FLEET_RESULT_PLUGIN_VERSION
            || self.service_id != SAMSARA_FLEET_RESULT_SERVICE_ID
            || self.provider_id != provider.provider_id
            || self.consumer_id != SAMSARA_FLEET_RESULT_CONSUMER_ID
            || self.service_version != SAMSARA_FLEET_RESULT_PLUGIN_VERSION
            || self.provider_version != provider.provider_version
            || self.revision.get() == 0
            || self.contract_digest != Digest::from_text(SAMSARA_FLEET_RESULT_CONTRACT_JSON)
            || self.provider_digest != provider.provider_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.organization_digest != scope.organization().digest()
            || self.tag_scope_digest != scope.tags().digest()
            || self.vehicle_scope_digest != scope.vehicles().digest()
            || self.equipment_scope_digest != scope.equipment().digest()
            || self.mission_scope_digest != scope.mission().digest()
            || self.project_scope_digest != scope.project().digest()
            || self.consent_scope_digest != scope.consent().digest()
            || self.permission_digest != *scope.permission_digest()
            || self.policy_revision != scope.policy_revision()
            || self.registration_digest
                != Self::compute_digest(
                    &self.contract_digest,
                    &self.provider_digest,
                    scope,
                    secret_reference,
                    self.revision,
                )
        {
            return Err(ServiceError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ServiceError> {
        self.ensure_active()?;
        self.state = RegistrationState::Revoked;
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revocation_digest: Digest::from_fields(
                "samsara-registration-revocation/v1",
                &[
                    self.registration_digest.as_str().to_owned(),
                    self.scope_digest.as_str().to_owned(),
                    self.revision.get().to_string(),
                ],
            ),
        })
    }

    fn compute_digest(
        contract_digest: &Digest,
        provider_digest: &Digest,
        scope: &SamsaraFleetScope,
        secret_reference: &SecretReference,
        revision: Revision,
    ) -> Digest {
        Digest::from_fields(
            "samsara-registration/v1",
            &[
                SAMSARA_FLEET_RESULT_SCHEMA_VERSION.to_owned(),
                SAMSARA_FLEET_RESULT_CONTRACT_VERSION.to_owned(),
                SAMSARA_FLEET_RESULT_PLUGIN_VERSION.to_owned(),
                SAMSARA_FLEET_RESULT_SERVICE_ID.to_owned(),
                SAMSARA_FLEET_RESULT_PROVIDER_ID.to_owned(),
                SAMSARA_FLEET_RESULT_CONSUMER_ID.to_owned(),
                contract_digest.as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                secret_reference.reference_digest().as_str().to_owned(),
                scope.organization().digest().as_str().to_owned(),
                scope.tags().digest().as_str().to_owned(),
                scope.vehicles().digest().as_str().to_owned(),
                scope.equipment().digest().as_str().to_owned(),
                scope.mission().digest().as_str().to_owned(),
                scope.project().digest().as_str().to_owned(),
                scope.consent().digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.policy_revision().get().to_string(),
                revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraFleetResultRequest {
    pub scope_digest: Digest,
    pub observation_window: TimeWindow,
    pub max_pages: u16,
    pub page_size: u16,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub consent_revision: Revision,
    pub permission_digest: Digest,
}

impl SamsaraFleetResultRequest {
    pub fn new(
        scope: &SamsaraFleetScope,
        observation_window: TimeWindow,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            observation_window,
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            mission_revision: scope.mission().revision,
            project_revision: scope.project().revision,
            consent_revision: scope.consent().revision,
            permission_digest: scope.permission_digest().clone(),
        })
    }

    pub fn with_bounds(mut self, max_pages: u16, page_size: u16) -> Result<Self, ServiceError> {
        if max_pages == 0 || max_pages > MAX_PAGES || page_size == 0 || page_size > MAX_PAGE_SIZE {
            Err(ServiceError::RequestTampered)
        } else {
            self.max_pages = max_pages;
            self.page_size = page_size;
            Ok(self)
        }
    }

    pub fn validate(&self, scope: &SamsaraFleetScope) -> Result<(), ServiceError> {
        if self.scope_digest != *scope.scope_digest()
            || self.mission_revision != scope.mission().revision
            || self.project_revision != scope.project().revision
            || self.consent_revision != scope.consent().revision
            || self.permission_digest != *scope.permission_digest()
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || !window_contains(scope.trips().window, self.observation_window)
            || !window_contains(scope.safety_events().window, self.observation_window)
            || !window_contains(scope.maintenance().window, self.observation_window)
            || !window_contains(scope.dvir().window, self.observation_window)
            || !window_contains(scope.alerts().window, self.observation_window)
        {
            Err(ServiceError::RequestTampered)
        } else {
            Ok(())
        }
    }
}

fn window_contains(outer: TimeWindow, inner: TimeWindow) -> bool {
    inner.start_epoch_seconds() >= outer.start_epoch_seconds()
        && inner.end_epoch_seconds() <= outer.end_epoch_seconds()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraProviderErrorEvidence {
    pub operation: String,
    pub kind: TransportErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub diagnostic_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraRetryEvidence {
    pub operation: String,
    pub attempt: u8,
    pub kind: TransportErrorKind,
    pub retry_after_seconds: Option<u64>,
    pub bounded_backoff_seconds: u64,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SamsaraAuthorityEvidence {
    pub connected: bool,
    pub native_provider: bool,
    pub durable_native_receipt: bool,
    pub external_write: bool,
    pub verification: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraFleetResultEvidence {
    pub scope_digest: Digest,
    pub organization_digest: Digest,
    pub tag_scope_digest: Digest,
    pub vehicle_scope_digest: Digest,
    pub equipment_scope_digest: Digest,
    pub trip_scope_digest: Digest,
    pub safety_event_scope_digest: Digest,
    pub maintenance_scope_digest: Digest,
    pub dvir_scope_digest: Digest,
    pub alert_scope_digest: Digest,
    pub mission_id: String,
    pub mission_revision: Revision,
    pub project_id: String,
    pub project_revision: Revision,
    pub consent_id: String,
    pub consent_revision: Revision,
    pub permission_digest: Digest,
    pub observation_window: TimeWindow,
    pub vehicles: Vec<VehicleRecord>,
    pub equipment: Vec<EquipmentRecord>,
    pub trips: Vec<TripRecord>,
    pub safety_events: Vec<SafetyEventRecord>,
    pub maintenance: Vec<MaintenanceRecord>,
    pub dvir: Vec<DvirRecord>,
    pub alerts: Vec<AlertRecord>,
    pub receipts: Vec<ResponseReceipt>,
    pub provider_errors: Vec<SamsaraProviderErrorEvidence>,
    pub retries: Vec<SamsaraRetryEvidence>,
    pub provider_provenance: ProviderProvenance,
    pub pages_observed: u16,
    pub partial: bool,
    pub retention_gap: bool,
    pub access_lost: bool,
    pub evidence_digest: Digest,
    pub authority: SamsaraAuthorityEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraFleetResultProposal {
    pub projection: FleetProjection,
    pub evidence: SamsaraFleetResultEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl SamsaraFleetResultProposal {
    pub fn status(&self) -> FleetProjection {
        self.projection
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub fn validate_digest(&self) -> bool {
        self.proposal_digest
            == proposal_digest(
                self.projection,
                &self.evidence,
                &self.registration_digest,
                self.registration_revision,
                &self.provider_definition_digest,
            )
    }

    pub fn authority(&self) -> SamsaraAuthorityEvidence {
        self.evidence.authority.clone()
    }
}

pub struct SamsaraFleetResultService<T> {
    scope: SamsaraFleetScope,
    secret_reference: SecretReference,
    provider: SamsaraProvider<T>,
    service_definition: SamsaraFleetResultServiceDefinition,
    registration: SamsaraRegistration,
}

impl<T: SamsaraTransport> fmt::Debug for SamsaraFleetResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamsaraFleetResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: SamsaraTransport> SamsaraFleetResultService<T> {
    pub fn new(
        scope: SamsaraFleetScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ServiceError> {
        let provider = SamsaraProvider::new(scope.clone(), secret_reference.clone(), transport)?;
        Self::from_provider(provider, secret_reference)
    }

    pub fn from_provider(
        provider: SamsaraProvider<T>,
        secret_reference: SecretReference,
    ) -> Result<Self, ServiceError> {
        if secret_reference.scope_digest() != provider.scope().scope_digest()
            || secret_reference.reference_digest() != provider.secret_reference().reference_digest()
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let service_definition = SamsaraFleetResultServiceDefinition::new();
        let registration =
            SamsaraRegistration::new(provider.scope(), &secret_reference, provider.definition())?;
        Ok(Self {
            scope: provider.scope().clone(),
            secret_reference,
            provider,
            service_definition,
            registration,
        })
    }

    pub fn service_definition(&self) -> &SamsaraFleetResultServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &SamsaraProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &SamsaraRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &SamsaraFleetScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &SamsaraProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SamsaraProvider<T> {
        &mut self.provider
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, ServiceError> {
        self.registration.revoke()
    }

    pub fn revoke_secret(&mut self) -> Result<(), ModelError> {
        self.provider.revoke_secret()?;
        self.secret_reference.revoke()
    }

    pub fn propose(
        &mut self,
        request: SamsaraFleetResultRequest,
    ) -> Result<SamsaraFleetResultProposal, ServiceError> {
        self.registration.ensure_active()?;
        if self.secret_reference.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        self.registration.validate_integrity(
            &self.scope,
            &self.secret_reference,
            self.provider.definition(),
        )?;
        request.validate(&self.scope)?;

        let mut accumulator = EvidenceAccumulator::new(
            &self.scope,
            request.observation_window,
            self.provider.provenance(),
        );
        for endpoint in [
            SamsaraEndpoint::Vehicles,
            SamsaraEndpoint::VehicleTrips,
            SamsaraEndpoint::SafetySignals,
            SamsaraEndpoint::MaintenanceStatus,
            SamsaraEndpoint::DvirStatus,
            SamsaraEndpoint::Alerts,
        ] {
            self.read_bounded(endpoint, &request, &mut accumulator)?;
        }
        let projection = accumulator.projection();
        let evidence = accumulator.finish();
        let provider_definition_digest = self.provider.provider_digest();
        let proposal_digest = proposal_digest(
            projection,
            &evidence,
            &self.registration.registration_digest,
            self.registration.revision,
            &provider_definition_digest,
        );
        Ok(SamsaraFleetResultProposal {
            projection,
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_definition_digest,
            proposal_digest,
        })
    }

    fn read_bounded(
        &mut self,
        endpoint: SamsaraEndpoint,
        request: &SamsaraFleetResultRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<(), ServiceError> {
        let page_size = if endpoint == SamsaraEndpoint::Alerts {
            request.page_size.min(self.scope.alerts().max_alerts)
        } else {
            request.page_size
        };
        let mut options = SamsaraReadOptions::new(request.observation_window)
            .with_page_size(page_size)
            .map_err(ServiceError::Model)?;
        let mut seen_cursors = BTreeSet::new();
        loop {
            let Some(response) = self.read_with_bounded_retry(endpoint, &options, accumulator)
            else {
                return Ok(());
            };
            accumulator.record_response(endpoint, response)?;
            let next_cursor = accumulator
                .last_page_cursor(endpoint)
                .and_then(|digest| OpaqueCursor::from_digest(digest).ok());
            let Some(next_cursor) = next_cursor else {
                return Ok(());
            };
            if options.page() >= request.max_pages {
                accumulator.partial = true;
                return Ok(());
            }
            if !seen_cursors.insert(next_cursor.digest().clone()) {
                return Err(ServiceError::PageLoop);
            }
            let next_page = options.page().saturating_add(1);
            options = options
                .with_page(next_page)
                .map_err(ServiceError::Model)?
                .with_cursor(next_cursor);
        }
    }

    fn read_with_bounded_retry(
        &mut self,
        endpoint: SamsaraEndpoint,
        options: &SamsaraReadOptions,
        accumulator: &mut EvidenceAccumulator,
    ) -> Option<crate::SamsaraReadResponse> {
        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            match self.provider.read_endpoint(endpoint, options) {
                Ok(response) => return Some(response),
                Err(error) if error.retryable() && attempt < MAX_RETRY_ATTEMPTS => {
                    accumulator.record_retry(endpoint, attempt, &error);
                }
                Err(error) => {
                    accumulator.record_error(endpoint, &error);
                    return None;
                }
            }
        }
        None
    }
}

struct EvidenceAccumulator {
    scope_digest: Digest,
    organization_digest: Digest,
    tag_scope_digest: Digest,
    vehicle_scope_digest: Digest,
    equipment_scope_digest: Digest,
    trip_scope_digest: Digest,
    safety_event_scope_digest: Digest,
    maintenance_scope_digest: Digest,
    dvir_scope_digest: Digest,
    alert_scope_digest: Digest,
    mission_id: String,
    mission_revision: Revision,
    project_id: String,
    project_revision: Revision,
    consent_id: String,
    consent_revision: Revision,
    permission_digest: Digest,
    observation_window: TimeWindow,
    vehicles: Vec<VehicleRecord>,
    equipment: Vec<EquipmentRecord>,
    trips: Vec<TripRecord>,
    safety_events: Vec<SafetyEventRecord>,
    maintenance: Vec<MaintenanceRecord>,
    dvir: Vec<DvirRecord>,
    alerts: Vec<AlertRecord>,
    receipts: Vec<ResponseReceipt>,
    provider_errors: Vec<SamsaraProviderErrorEvidence>,
    retries: Vec<SamsaraRetryEvidence>,
    provider_provenance: ProviderProvenance,
    vehicle_ids: BTreeSet<crate::VehicleId>,
    equipment_ids: BTreeSet<crate::EquipmentId>,
    pages_observed: u16,
    successful_reads: u8,
    partial: bool,
    retention_gap: bool,
    access_lost: bool,
    blocked_env: bool,
    last_cursors: [Option<Digest>; 6],
}

impl EvidenceAccumulator {
    fn new(
        scope: &SamsaraFleetScope,
        observation_window: TimeWindow,
        provider_provenance: ProviderProvenance,
    ) -> Self {
        Self {
            scope_digest: scope.scope_digest().clone(),
            organization_digest: scope.organization().digest(),
            tag_scope_digest: scope.tags().digest(),
            vehicle_scope_digest: scope.vehicles().digest(),
            equipment_scope_digest: scope.equipment().digest(),
            trip_scope_digest: scope.trips().digest(),
            safety_event_scope_digest: scope.safety_events().digest(),
            maintenance_scope_digest: scope.maintenance().digest(),
            dvir_scope_digest: scope.dvir().digest(),
            alert_scope_digest: scope.alerts().digest(),
            mission_id: scope.mission().mission_id.as_str().to_owned(),
            mission_revision: scope.mission().revision,
            project_id: scope.project().project_id.as_str().to_owned(),
            project_revision: scope.project().revision,
            consent_id: scope.consent().consent_id.as_str().to_owned(),
            consent_revision: scope.consent().revision,
            permission_digest: scope.permission_digest().clone(),
            observation_window,
            vehicles: Vec::new(),
            equipment: Vec::new(),
            trips: Vec::new(),
            safety_events: Vec::new(),
            maintenance: Vec::new(),
            dvir: Vec::new(),
            alerts: Vec::new(),
            receipts: Vec::new(),
            provider_errors: Vec::new(),
            retries: Vec::new(),
            provider_provenance,
            vehicle_ids: scope.vehicles().vehicle_ids.clone(),
            equipment_ids: scope.equipment().equipment_ids.clone(),
            pages_observed: 0,
            successful_reads: 0,
            partial: false,
            retention_gap: false,
            access_lost: false,
            blocked_env: false,
            last_cursors: std::array::from_fn(|_| None),
        }
    }

    fn record_error(&mut self, endpoint: SamsaraEndpoint, error: &TransportError) {
        self.provider_errors.push(SamsaraProviderErrorEvidence {
            operation: endpoint.operation().to_owned(),
            kind: error.kind(),
            status_code: error.status_code(),
            retryable: error.retryable(),
            blocked_env: error.blocked_env(),
            diagnostic_digest: error.diagnostic_digest(),
        });
        self.access_lost |= error.access_lost();
        self.blocked_env |= error.blocked_env();
        self.partial = true;
    }

    fn record_retry(&mut self, endpoint: SamsaraEndpoint, attempt: u8, error: &TransportError) {
        self.retries.push(SamsaraRetryEvidence {
            operation: endpoint.operation().to_owned(),
            attempt,
            kind: error.kind(),
            retry_after_seconds: error.retry_after_seconds(),
            bounded_backoff_seconds: error
                .retry_after_seconds()
                .unwrap_or(1)
                .min(MAX_BACKOFF_SECONDS),
            error_digest: error.diagnostic_digest(),
        });
    }

    fn record_response(
        &mut self,
        endpoint: SamsaraEndpoint,
        response: crate::SamsaraReadResponse,
    ) -> Result<(), ServiceError> {
        self.successful_reads = self.successful_reads.saturating_add(1);
        self.pages_observed = self.pages_observed.saturating_add(1);
        self.retention_gap |= response.body.page().retention_gap;
        self.last_cursors[endpoint_index(endpoint)]
            .clone_from(&response.body.page().next_cursor_digest);
        if self.receipts.len() >= MAX_PAGES as usize * 6 {
            self.partial = true;
        } else {
            self.receipts.push(response.receipt);
        }
        self.merge_body(endpoint, response.body)
    }

    fn merge_body(
        &mut self,
        endpoint: SamsaraEndpoint,
        body: SamsaraResponseBody,
    ) -> Result<(), ServiceError> {
        if endpoint != body.endpoint() {
            return Err(ServiceError::InvalidProviderResponse);
        }
        match body {
            SamsaraResponseBody::Vehicles { records, .. } => {
                for record in records {
                    if !self.scope_vehicle_allowed(&record.vehicle_id) {
                        return Err(ServiceError::ResponseScopeMismatch);
                    }
                    push_bounded(&mut self.vehicles, record, &mut self.partial);
                }
            }
            SamsaraResponseBody::VehicleTrips { records, .. } => {
                for record in records {
                    if !self.scope_vehicle_allowed(&record.vehicle_id) {
                        return Err(ServiceError::ResponseScopeMismatch);
                    }
                    push_bounded(&mut self.trips, record, &mut self.partial);
                }
            }
            SamsaraResponseBody::SafetySignals { records, .. } => {
                for record in records {
                    if !self.scope_vehicle_allowed(&record.vehicle_id) {
                        return Err(ServiceError::ResponseScopeMismatch);
                    }
                    push_bounded(&mut self.safety_events, record, &mut self.partial);
                }
            }
            SamsaraResponseBody::MaintenanceStatus { records, .. } => {
                for record in records {
                    if !self.scope_asset_allowed(&record.asset) {
                        return Err(ServiceError::ResponseScopeMismatch);
                    }
                    push_bounded(&mut self.maintenance, record, &mut self.partial);
                }
            }
            SamsaraResponseBody::DvirStatus { records, .. } => {
                for record in records {
                    if !self.scope_asset_allowed(&record.asset) {
                        return Err(ServiceError::ResponseScopeMismatch);
                    }
                    push_bounded(&mut self.dvir, record, &mut self.partial);
                }
            }
            SamsaraResponseBody::Alerts { records, .. } => {
                for record in records {
                    if record
                        .asset
                        .as_ref()
                        .is_some_and(|asset| !self.scope_asset_allowed(asset))
                    {
                        return Err(ServiceError::ResponseScopeMismatch);
                    }
                    push_bounded(&mut self.alerts, record, &mut self.partial);
                }
            }
        }
        Ok(())
    }

    fn scope_vehicle_allowed(&self, vehicle_id: &crate::VehicleId) -> bool {
        self.scope_vehicle_ids().is_empty() || self.scope_vehicle_ids().contains(vehicle_id)
    }

    fn scope_asset_allowed(&self, asset: &AssetReference) -> bool {
        let vehicles = self.scope_vehicle_ids();
        let equipment = self.scope_equipment_ids();
        if vehicles.is_empty() && equipment.is_empty() {
            return true;
        }
        match asset {
            AssetReference::Vehicle(id) => vehicles.contains(id),
            AssetReference::Equipment(id) => equipment.contains(id),
        }
    }

    fn scope_vehicle_ids(&self) -> &BTreeSet<crate::VehicleId> {
        &self.vehicle_ids
    }

    fn scope_equipment_ids(&self) -> &BTreeSet<crate::EquipmentId> {
        &self.equipment_ids
    }

    fn last_page_cursor(&self, endpoint: SamsaraEndpoint) -> Option<Digest> {
        self.last_cursors[endpoint_index(endpoint)].clone()
    }

    fn projection(&self) -> FleetProjection {
        if self.access_lost {
            return FleetProjection::AccessLost;
        }
        if self.blocked_env || (self.successful_reads == 0 && !self.provider_errors.is_empty()) {
            return FleetProjection::ProviderUnknown;
        }
        if self.partial && self.successful_reads > 0 {
            return FleetProjection::Partial;
        }
        if self.retention_gap {
            return FleetProjection::RetentionGap;
        }
        if self
            .safety_events
            .iter()
            .any(|event| event.severity.is_alert())
            || self.alerts.iter().any(|alert| {
                matches!(
                    alert.state,
                    crate::AlertState::Active | crate::AlertState::Acknowledged
                ) && alert.severity.is_alert()
            })
        {
            return FleetProjection::SafetyAlert;
        }
        if self.maintenance.iter().any(|item| item.state.is_due())
            || self.dvir.iter().any(|item| item.state.is_due())
        {
            return FleetProjection::MaintenanceDue;
        }
        let conditions = self
            .vehicles
            .iter()
            .map(|record| record.condition)
            .chain(self.equipment.iter().map(|record| record.condition))
            .collect::<Vec<_>>();
        if conditions.is_empty() {
            return FleetProjection::RetentionGap;
        }
        if conditions.contains(&AssetCondition::Offline) {
            return FleetProjection::Offline;
        }
        if conditions.contains(&AssetCondition::Degraded)
            || conditions.contains(&AssetCondition::Unknown)
        {
            return FleetProjection::Degraded;
        }
        if conditions
            .iter()
            .all(|condition| *condition == AssetCondition::Healthy)
        {
            FleetProjection::Healthy
        } else {
            FleetProjection::Operational
        }
    }

    fn finish(self) -> SamsaraFleetResultEvidence {
        let mut evidence = SamsaraFleetResultEvidence {
            scope_digest: self.scope_digest,
            organization_digest: self.organization_digest,
            tag_scope_digest: self.tag_scope_digest,
            vehicle_scope_digest: self.vehicle_scope_digest,
            equipment_scope_digest: self.equipment_scope_digest,
            trip_scope_digest: self.trip_scope_digest,
            safety_event_scope_digest: self.safety_event_scope_digest,
            maintenance_scope_digest: self.maintenance_scope_digest,
            dvir_scope_digest: self.dvir_scope_digest,
            alert_scope_digest: self.alert_scope_digest,
            mission_id: self.mission_id,
            mission_revision: self.mission_revision,
            project_id: self.project_id,
            project_revision: self.project_revision,
            consent_id: self.consent_id,
            consent_revision: self.consent_revision,
            permission_digest: self.permission_digest,
            observation_window: self.observation_window,
            vehicles: self.vehicles,
            equipment: self.equipment,
            trips: self.trips,
            safety_events: self.safety_events,
            maintenance: self.maintenance,
            dvir: self.dvir,
            alerts: self.alerts,
            receipts: self.receipts,
            provider_errors: self.provider_errors,
            retries: self.retries,
            provider_provenance: self.provider_provenance,
            pages_observed: self.pages_observed,
            partial: self.partial,
            retention_gap: self.retention_gap,
            access_lost: self.access_lost,
            evidence_digest: Digest::from_text("pending"),
            authority: SamsaraAuthorityEvidence::default(),
        };
        evidence.evidence_digest = canonical_digest(&evidence_without_digest(&evidence));
        evidence
    }
}

fn endpoint_index(endpoint: SamsaraEndpoint) -> usize {
    match endpoint {
        SamsaraEndpoint::Vehicles => 0,
        SamsaraEndpoint::VehicleTrips => 1,
        SamsaraEndpoint::SafetySignals => 2,
        SamsaraEndpoint::MaintenanceStatus => 3,
        SamsaraEndpoint::DvirStatus => 4,
        SamsaraEndpoint::Alerts => 5,
    }
}

fn push_bounded<T>(values: &mut Vec<T>, value: T, partial: &mut bool) {
    if values.len() < MAX_RECORDS_PER_READ {
        values.push(value);
    } else {
        *partial = true;
    }
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    scope_digest: &'a Digest,
    organization_digest: &'a Digest,
    tag_scope_digest: &'a Digest,
    vehicle_scope_digest: &'a Digest,
    equipment_scope_digest: &'a Digest,
    trip_scope_digest: &'a Digest,
    safety_event_scope_digest: &'a Digest,
    maintenance_scope_digest: &'a Digest,
    dvir_scope_digest: &'a Digest,
    alert_scope_digest: &'a Digest,
    mission_id: &'a str,
    mission_revision: Revision,
    project_id: &'a str,
    project_revision: Revision,
    consent_id: &'a str,
    consent_revision: Revision,
    permission_digest: &'a Digest,
    observation_window: TimeWindow,
    vehicles: &'a [VehicleRecord],
    equipment: &'a [EquipmentRecord],
    trips: &'a [TripRecord],
    safety_events: &'a [SafetyEventRecord],
    maintenance: &'a [MaintenanceRecord],
    dvir: &'a [DvirRecord],
    alerts: &'a [AlertRecord],
    receipts: &'a [ResponseReceipt],
    provider_errors: &'a [SamsaraProviderErrorEvidence],
    retries: &'a [SamsaraRetryEvidence],
    provider_provenance: ProviderProvenance,
    pages_observed: u16,
    partial: bool,
    retention_gap: bool,
    access_lost: bool,
    authority: &'a SamsaraAuthorityEvidence,
}

fn evidence_without_digest(evidence: &SamsaraFleetResultEvidence) -> EvidenceDigestInput<'_> {
    EvidenceDigestInput {
        scope_digest: &evidence.scope_digest,
        organization_digest: &evidence.organization_digest,
        tag_scope_digest: &evidence.tag_scope_digest,
        vehicle_scope_digest: &evidence.vehicle_scope_digest,
        equipment_scope_digest: &evidence.equipment_scope_digest,
        trip_scope_digest: &evidence.trip_scope_digest,
        safety_event_scope_digest: &evidence.safety_event_scope_digest,
        maintenance_scope_digest: &evidence.maintenance_scope_digest,
        dvir_scope_digest: &evidence.dvir_scope_digest,
        alert_scope_digest: &evidence.alert_scope_digest,
        mission_id: &evidence.mission_id,
        mission_revision: evidence.mission_revision,
        project_id: &evidence.project_id,
        project_revision: evidence.project_revision,
        consent_id: &evidence.consent_id,
        consent_revision: evidence.consent_revision,
        permission_digest: &evidence.permission_digest,
        observation_window: evidence.observation_window,
        vehicles: &evidence.vehicles,
        equipment: &evidence.equipment,
        trips: &evidence.trips,
        safety_events: &evidence.safety_events,
        maintenance: &evidence.maintenance,
        dvir: &evidence.dvir,
        alerts: &evidence.alerts,
        receipts: &evidence.receipts,
        provider_errors: &evidence.provider_errors,
        retries: &evidence.retries,
        provider_provenance: evidence.provider_provenance,
        pages_observed: evidence.pages_observed,
        partial: evidence.partial,
        retention_gap: evidence.retention_gap,
        access_lost: evidence.access_lost,
        authority: &evidence.authority,
    }
}

#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    projection: FleetProjection,
    evidence: &'a SamsaraFleetResultEvidence,
    registration_digest: &'a Digest,
    registration_revision: Revision,
    provider_definition_digest: &'a Digest,
}

fn proposal_digest(
    projection: FleetProjection,
    evidence: &SamsaraFleetResultEvidence,
    registration_digest: &Digest,
    registration_revision: Revision,
    provider_definition_digest: &Digest,
) -> Digest {
    canonical_digest(&ProposalDigestInput {
        projection,
        evidence,
        registration_digest,
        registration_revision,
        provider_definition_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConsentId, ConsentScope, MissionId, MissionScope, OrganizationId, ProjectId, ProjectScope,
        Revision, SafetySeverity, SamsaraFleetScope, SamsaraFleetScopeInput, TimeWindow,
        provider::{BlockedEnvTransport, RecordingSamsaraTransport, SamsaraHttpResponse},
    };

    fn scope() -> SamsaraFleetScope {
        SamsaraFleetScope::minimal(
            OrganizationId::new("org-1").expect("organization"),
            MissionScope::new(
                MissionId::new("mission-1").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectScope::new(
                ProjectId::new("project-1").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            ConsentScope::new(
                ConsentId::new("consent-1").expect("consent"),
                Revision::new(1).expect("revision"),
            ),
            Digest::from_text("permission"),
            TimeWindow::new(100, 200).expect("window"),
        )
        .expect("scope")
    }

    #[test]
    fn blocked_environment_is_unknown_and_never_native() {
        let scope = scope();
        let secret =
            SecretReference::new("vault/samsara", scope.scope_digest(), 1).expect("secret");
        let provider = SamsaraProvider::new(scope.clone(), secret.clone(), BlockedEnvTransport)
            .expect("provider");
        let mut service =
            SamsaraFleetResultService::from_provider(provider, secret).expect("service");
        let request =
            SamsaraFleetResultRequest::new(&scope, scope.trips().window).expect("request");
        let proposal = service.propose(request).expect("proposal");
        assert_eq!(proposal.projection, FleetProjection::ProviderUnknown);
        assert!(!proposal.is_native());
        assert!(!proposal.is_connected());
        assert!(!proposal.is_adopted());
        assert!(proposal.evidence.receipts.is_empty());
    }

    #[test]
    fn registration_revocation_is_reversible_and_fail_closed() {
        let scope = scope();
        let secret =
            SecretReference::new("vault/samsara", scope.scope_digest(), 1).expect("secret");
        let provider = SamsaraProvider::new(scope.clone(), secret.clone(), BlockedEnvTransport)
            .expect("provider");
        let mut service =
            SamsaraFleetResultService::from_provider(provider, secret).expect("service");
        let request =
            SamsaraFleetResultRequest::new(&scope, scope.trips().window).expect("request");
        service.revoke_registration().expect("revoke");
        assert_eq!(
            service.propose(request),
            Err(ServiceError::RegistrationRevoked)
        );
    }

    fn asset_scope() -> (SamsaraFleetScope, crate::VehicleId) {
        let window = TimeWindow::new(100, 200).expect("window");
        let vehicle = crate::VehicleId::new("vehicle-1").expect("vehicle");
        let vehicles = crate::VehicleScope::new([vehicle.clone()]).expect("vehicles");
        let equipment =
            crate::EquipmentScope::new(Vec::<crate::EquipmentId>::new()).expect("equipment");
        let scope = SamsaraFleetScope::new(SamsaraFleetScopeInput {
            organization: crate::OrganizationScope::new(
                OrganizationId::new("org-1").expect("organization"),
            ),
            tags: crate::TagScope::new(Vec::<crate::TagId>::new()).expect("tags"),
            vehicles: vehicles.clone(),
            equipment: equipment.clone(),
            trips: crate::TripScope {
                window,
                vehicles: vehicles.clone(),
            },
            safety_events: crate::SafetyEventScope {
                window,
                vehicles: vehicles.clone(),
            },
            maintenance: crate::MaintenanceScope {
                window,
                vehicles: vehicles.clone(),
                equipment: equipment.clone(),
            },
            dvir: crate::DvirScope {
                window,
                vehicles,
                equipment,
            },
            alerts: crate::AlertScope::new(window, 10).expect("alerts"),
            mission: MissionScope::new(
                MissionId::new("mission-1").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            project: ProjectScope::new(
                ProjectId::new("project-1").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            consent: ConsentScope::new(
                ConsentId::new("consent-1").expect("consent"),
                Revision::new(1).expect("revision"),
            ),
            permission_digest: Digest::from_text("permission"),
            policy_revision: Revision::new(1).expect("policy revision"),
        })
        .expect("scope");
        (scope, vehicle)
    }

    fn response(
        endpoint: SamsaraEndpoint,
        body: SamsaraResponseBody,
    ) -> Result<SamsaraHttpResponse, TransportError> {
        SamsaraHttpResponse::new(endpoint, 200, body)
    }

    fn empty_body(endpoint: SamsaraEndpoint) -> SamsaraResponseBody {
        match endpoint {
            SamsaraEndpoint::Vehicles => SamsaraResponseBody::Vehicles {
                records: Vec::new(),
                page: crate::PageInfo::complete(),
            },
            SamsaraEndpoint::VehicleTrips => SamsaraResponseBody::VehicleTrips {
                records: Vec::new(),
                page: crate::PageInfo::complete(),
            },
            SamsaraEndpoint::SafetySignals => SamsaraResponseBody::SafetySignals {
                records: Vec::new(),
                page: crate::PageInfo::complete(),
            },
            SamsaraEndpoint::MaintenanceStatus => SamsaraResponseBody::MaintenanceStatus {
                records: Vec::new(),
                page: crate::PageInfo::complete(),
            },
            SamsaraEndpoint::DvirStatus => SamsaraResponseBody::DvirStatus {
                records: Vec::new(),
                page: crate::PageInfo::complete(),
            },
            SamsaraEndpoint::Alerts => SamsaraResponseBody::Alerts {
                records: Vec::new(),
                page: crate::PageInfo::complete(),
            },
        }
    }

    fn baseline_responses(
        vehicle: &crate::VehicleId,
        condition: AssetCondition,
    ) -> Vec<Result<SamsaraHttpResponse, TransportError>> {
        vec![
            response(
                SamsaraEndpoint::Vehicles,
                SamsaraResponseBody::Vehicles {
                    records: vec![VehicleRecord {
                        vehicle_id: vehicle.clone(),
                        condition,
                        observed_at_epoch_seconds: 150,
                    }],
                    page: crate::PageInfo::complete(),
                },
            ),
            response(
                SamsaraEndpoint::VehicleTrips,
                empty_body(SamsaraEndpoint::VehicleTrips),
            ),
            response(
                SamsaraEndpoint::SafetySignals,
                empty_body(SamsaraEndpoint::SafetySignals),
            ),
            response(
                SamsaraEndpoint::MaintenanceStatus,
                empty_body(SamsaraEndpoint::MaintenanceStatus),
            ),
            response(
                SamsaraEndpoint::DvirStatus,
                empty_body(SamsaraEndpoint::DvirStatus),
            ),
            response(SamsaraEndpoint::Alerts, empty_body(SamsaraEndpoint::Alerts)),
        ]
    }

    fn service_for(
        scope: &SamsaraFleetScope,
        responses: Vec<Result<SamsaraHttpResponse, TransportError>>,
    ) -> SamsaraFleetResultService<RecordingSamsaraTransport> {
        let secret =
            SecretReference::new("vault/samsara", scope.scope_digest(), 1).expect("secret");
        SamsaraFleetResultService::new(
            scope.clone(),
            secret,
            RecordingSamsaraTransport::fixture(responses),
        )
        .expect("service")
    }

    fn proposal_for(
        scope: &SamsaraFleetScope,
        responses: Vec<Result<SamsaraHttpResponse, TransportError>>,
    ) -> SamsaraFleetResultProposal {
        let mut service = service_for(scope, responses);
        let request = SamsaraFleetResultRequest::new(scope, scope.trips().window).expect("request");
        service.propose(request).expect("proposal")
    }

    #[test]
    fn explicit_asset_health_is_distinct_from_alert_absence() {
        let (scope, vehicle) = asset_scope();
        let proposal = proposal_for(
            &scope,
            baseline_responses(&vehicle, AssetCondition::Healthy),
        );
        assert_eq!(proposal.projection, FleetProjection::Healthy);
        assert!(proposal.evidence.provider_errors.is_empty());
        assert!(
            proposal
                .evidence
                .receipts
                .iter()
                .all(ResponseReceipt::is_redacted)
        );
        assert!(proposal.validate_digest());
    }

    #[test]
    fn safety_and_maintenance_projections_are_explicit() {
        let (scope, vehicle) = asset_scope();
        let mut safety = baseline_responses(&vehicle, AssetCondition::Healthy);
        safety[2] = response(
            SamsaraEndpoint::SafetySignals,
            SamsaraResponseBody::SafetySignals {
                records: vec![SafetyEventRecord {
                    safety_event_id: crate::SafetyEventId::new("safety-1").expect("event"),
                    vehicle_id: vehicle.clone(),
                    severity: SafetySeverity::Critical,
                    occurred_at_epoch_seconds: 150,
                }],
                page: crate::PageInfo::complete(),
            },
        );
        assert_eq!(
            proposal_for(&scope, safety).projection,
            FleetProjection::SafetyAlert
        );

        let mut maintenance = baseline_responses(&vehicle, AssetCondition::Healthy);
        maintenance[3] = response(
            SamsaraEndpoint::MaintenanceStatus,
            SamsaraResponseBody::MaintenanceStatus {
                records: vec![MaintenanceRecord {
                    maintenance_id: crate::MaintenanceId::new("maintenance-1")
                        .expect("maintenance"),
                    asset: AssetReference::Vehicle(vehicle),
                    state: crate::MaintenanceState::Due,
                    observed_at_epoch_seconds: 150,
                }],
                page: crate::PageInfo::complete(),
            },
        );
        assert_eq!(
            proposal_for(&scope, maintenance).projection,
            FleetProjection::MaintenanceDue
        );
    }

    #[test]
    fn offline_partial_retention_and_access_projections_are_distinct() {
        let (scope, vehicle) = asset_scope();
        assert_eq!(
            proposal_for(
                &scope,
                baseline_responses(&vehicle, AssetCondition::Offline)
            )
            .projection,
            FleetProjection::Offline
        );

        let mut partial = baseline_responses(&vehicle, AssetCondition::Operational);
        partial[5] = Err(TransportError::Timeout);
        assert_eq!(
            proposal_for(&scope, partial).projection,
            FleetProjection::Partial
        );

        let mut retention = baseline_responses(&vehicle, AssetCondition::Operational);
        retention[0] = response(
            SamsaraEndpoint::Vehicles,
            SamsaraResponseBody::Vehicles {
                records: vec![VehicleRecord {
                    vehicle_id: vehicle.clone(),
                    condition: AssetCondition::Operational,
                    observed_at_epoch_seconds: 150,
                }],
                page: crate::PageInfo::with_retention_gap(None),
            },
        );
        assert_eq!(
            proposal_for(&scope, retention).projection,
            FleetProjection::RetentionGap
        );

        let mut access_lost = baseline_responses(&vehicle, AssetCondition::Operational);
        access_lost[0] = Err(TransportError::Unauthorized);
        assert_eq!(
            proposal_for(&scope, access_lost).projection,
            FleetProjection::AccessLost
        );
    }

    #[test]
    fn rate_limit_is_retried_with_a_bounded_redacted_backoff_record() {
        let (scope, vehicle) = asset_scope();
        let mut retried = baseline_responses(&vehicle, AssetCondition::Operational);
        retried[0] = Err(TransportError::RateLimited {
            retry_after_seconds: Some(5),
        });
        retried.insert(
            1,
            response(
                SamsaraEndpoint::Vehicles,
                SamsaraResponseBody::Vehicles {
                    records: vec![VehicleRecord {
                        vehicle_id: vehicle,
                        condition: AssetCondition::Operational,
                        observed_at_epoch_seconds: 150,
                    }],
                    page: crate::PageInfo::complete(),
                },
            ),
        );
        let proposal = proposal_for(&scope, retried);
        assert_eq!(proposal.projection, FleetProjection::Operational);
        assert_eq!(proposal.evidence.retries.len(), 1);
        assert_eq!(proposal.evidence.retries[0].attempt, 1);
        assert_eq!(proposal.evidence.retries[0].bounded_backoff_seconds, 5);
        assert!(proposal.evidence.provider_errors.is_empty());
    }

    #[test]
    fn pagination_is_bounded_and_scope_drift_fails_closed() {
        let (scope, vehicle) = asset_scope();
        let cursor = OpaqueCursor::new("opaque-page-token").expect("cursor");
        let mut paged = baseline_responses(&vehicle, AssetCondition::Operational);
        paged[0] = response(
            SamsaraEndpoint::Vehicles,
            SamsaraResponseBody::Vehicles {
                records: vec![VehicleRecord {
                    vehicle_id: vehicle.clone(),
                    condition: AssetCondition::Operational,
                    observed_at_epoch_seconds: 150,
                }],
                page: crate::PageInfo::next(&cursor),
            },
        );
        let second_page = response(
            SamsaraEndpoint::Vehicles,
            SamsaraResponseBody::Vehicles {
                records: Vec::new(),
                page: crate::PageInfo::complete(),
            },
        );
        paged.insert(1, second_page);
        let proposal = proposal_for(&scope, paged);
        assert_eq!(proposal.projection, FleetProjection::Operational);
        assert_eq!(proposal.evidence.pages_observed, 7);
        assert_eq!(proposal.evidence.receipts.len(), 7);

        let other_vehicle = crate::VehicleId::new("vehicle-2").expect("vehicle");
        let drifted = baseline_responses(&other_vehicle, AssetCondition::Healthy);
        let mut service = service_for(&scope, drifted);
        let request =
            SamsaraFleetResultRequest::new(&scope, scope.trips().window).expect("request");
        assert_eq!(
            service.propose(request),
            Err(ServiceError::ResponseScopeMismatch)
        );
    }
}
