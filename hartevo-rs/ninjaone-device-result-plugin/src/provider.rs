//! Typed bounded NinjaOne provider and redacted evidence normalization.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, HealthStatus, NinjaOneActivityProjection, NinjaOneAlertProjection,
    NinjaOneDeviceProjection, NinjaOneDeviceResultEvidence, NinjaOneDeviceResultEvidenceParts,
    NinjaOneError, NinjaOneOrganizationProjection, NinjaOnePatchHealthProjection,
    NinjaOneProviderErrorProjection, NinjaOneRegistration, NinjaOneResultProjection, NinjaOneScope,
    NinjaOneSiteProjection, RegistrationTransition, Revision, TransportMode,
};
use crate::transport::{
    BlockedEnvNinjaOneTransport, FixtureNinjaOneTransport, LoopbackNinjaOneTransport,
    NinjaOneDeviceHealthRecord, NinjaOneEndpoint, NinjaOneGetRequest, NinjaOnePayload,
    NinjaOneResponse, NinjaOneTransport, NinjaOneTransportError, RecordingNinjaOneTransport,
    receipt_for,
};
use crate::{MAX_ACTIVITIES, MAX_ALERTS, MAX_PAGE_SIZE, MAX_PAGES, MAX_PATCHES, Result};

/// Provider lifecycle state. `Connected` and `Native` are intentionally not
/// represented as variants in this Layer-1 crate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NinjaOneProviderState {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
    Unmounted,
    Revoked,
    RateLimited,
    Timeout,
    ServerFailure,
    Unauthorized,
    Forbidden,
    NotFound,
    Partial,
    ProviderUnknown,
}

impl NinjaOneProviderState {
    pub const fn can_claim_native_or_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneBackoff {
    pub consecutive_failures: u32,
    pub retry_after_seconds: Option<u32>,
    pub suggested_delay_seconds: u32,
    pub sleeping_performed: bool,
}

impl NinjaOneBackoff {
    fn reset(&mut self) {
        self.consecutive_failures = 0;
        self.retry_after_seconds = None;
        self.suggested_delay_seconds = 0;
        self.sleeping_performed = false;
    }

    fn note_retryable(&mut self, retry_after_seconds: Option<u32>) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.retry_after_seconds = retry_after_seconds;
        let exponential = 2_u32.saturating_pow(self.consecutive_failures.min(8));
        self.suggested_delay_seconds = retry_after_seconds.unwrap_or(exponential).min(900);
        self.sleeping_performed = false;
    }
}

#[derive(Clone, Debug)]
struct EndpointRead {
    responses: Vec<NinjaOneResponse>,
    error: Option<NinjaOneTransportError>,
}

/// Bounded provider over a fixture, recording, loopback, or blocked transport.
pub struct NinjaOneProvider<T: NinjaOneTransport = RecordingNinjaOneTransport> {
    registration: NinjaOneRegistration,
    transport: T,
    scope: Option<NinjaOneScope>,
    state: NinjaOneProviderState,
    backoff: NinjaOneBackoff,
    observed_revisions: BTreeMap<NinjaOneEndpoint, Revision>,
}

impl<T: NinjaOneTransport> fmt::Debug for NinjaOneProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NinjaOneProvider")
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .field(
                "scope",
                &self.scope.as_ref().map(NinjaOneScope::scope_digest),
            )
            .field("state", &self.state)
            .field("backoff", &self.backoff)
            .field("observed_revision_count", &self.observed_revisions.len())
            .finish()
    }
}

impl<T: NinjaOneTransport> NinjaOneProvider<T> {
    pub fn new(registration: NinjaOneRegistration, transport: T) -> Result<Self> {
        let state = state_for_mode(transport.mode());
        Ok(Self {
            registration,
            transport,
            scope: None,
            state,
            backoff: NinjaOneBackoff::default(),
            observed_revisions: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &NinjaOneRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut NinjaOneRegistration {
        &mut self.registration
    }

    pub fn bind_scope(&mut self, scope: NinjaOneScope) -> Result<()> {
        self.registration.validate(&scope)?;
        if let Some(bound_scope) = &self.scope {
            if bound_scope.scope_digest() != scope.scope_digest() {
                return Err(NinjaOneError::ProviderScopeMismatch);
            }
        } else {
            self.scope = Some(scope);
        }
        Ok(())
    }

    pub fn scope(&self) -> Option<&NinjaOneScope> {
        self.scope.as_ref()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn provider_state(&self) -> NinjaOneProviderState {
        self.state
    }

    pub const fn state(&self) -> NinjaOneProviderState {
        self.state
    }

    pub fn backoff(&self) -> &NinjaOneBackoff {
        &self.backoff
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransition> {
        let transition = self.registration.unmount()?;
        self.state = NinjaOneProviderState::Unmounted;
        Ok(transition)
    }

    pub fn remount(&mut self) -> Result<RegistrationTransition> {
        let transition = self.registration.remount()?;
        self.state = state_for_mode(self.transport.mode());
        Ok(transition)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        let transition = self.registration.revoke()?;
        self.state = NinjaOneProviderState::Revoked;
        Ok(transition)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        let transition = self.registration.reverse()?;
        self.state = NinjaOneProviderState::Revoked;
        Ok(transition)
    }

    pub fn reject_mutation(&self, operation: &'static str) -> Result<()> {
        Err(NinjaOneError::MutationForbidden { operation })
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        self.reject_mutation(operation)
    }

    /// Read all bounded metadata seams and normalize them into a redacted
    /// device-result evidence object. Transport failures become explicit
    /// projections so access loss and provider uncertainty remain observable.
    pub fn read_device_result(
        &mut self,
        scope: &NinjaOneScope,
    ) -> Result<NinjaOneDeviceResultEvidence> {
        self.registration.ensure_active(scope)?;
        if let Some(bound_scope) = &self.scope {
            if bound_scope.scope_digest() != scope.scope_digest() {
                return Err(NinjaOneError::ProviderScopeMismatch);
            }
        } else {
            self.scope = Some(scope.clone());
        }
        let mut receipts = Vec::new();
        let organizations = self.collect_pages(
            scope,
            NinjaOneEndpoint::Organizations,
            MAX_PAGE_SIZE,
            &mut receipts,
        );
        let devices = self.collect_pages(
            scope,
            NinjaOneEndpoint::Devices,
            MAX_PAGE_SIZE,
            &mut receipts,
        );
        let alerts = self.collect_pages(
            scope,
            NinjaOneEndpoint::DeviceAlerts,
            MAX_PAGE_SIZE,
            &mut receipts,
        );
        let health = self.collect_pages(
            scope,
            NinjaOneEndpoint::DeviceHealth,
            MAX_PAGE_SIZE,
            &mut receipts,
        );
        let os_patches = self.collect_pages(
            scope,
            NinjaOneEndpoint::DeviceOsPatches,
            MAX_PAGE_SIZE,
            &mut receipts,
        );
        let software_patches = self.collect_pages(
            scope,
            NinjaOneEndpoint::DeviceSoftwarePatches,
            MAX_PAGE_SIZE,
            &mut receipts,
        );
        let activities =
            self.collect_pages(scope, NinjaOneEndpoint::DeviceActivities, 32, &mut receipts);

        let mut partial = false;
        let mut provider_error = None;
        let mut note_error = |read: &EndpointRead| {
            if let Some(error) = &read.error {
                partial = true;
                if provider_error.is_none() {
                    provider_error = Some(error_projection(error));
                }
            }
        };
        for read in [
            &organizations,
            &devices,
            &alerts,
            &health,
            &os_patches,
            &software_patches,
            &activities,
        ] {
            note_error(read);
        }

        let organization = normalize_organization(scope, &organizations, &mut partial)?;
        let device = normalize_device(scope, &devices, &mut partial, &mut self.observed_revisions)?;
        let site = device.as_ref().map(|item| NinjaOneSiteProjection {
            organization_id: item.organization_id.clone(),
            site_id: item.site_id.clone(),
            site_revision: scope.revisions().site,
            identity_digest: Digest::from_serializable(&(
                "ninjaone-site-projection/v1",
                &item.organization_id,
                &item.site_id,
                scope.revisions().site,
            )),
        });
        let agent = device.as_ref().map(|item| crate::NinjaOneAgentProjection {
            device_id: item.device_id.clone(),
            agent_id: item.agent_id.clone(),
            agent_revision: scope.revisions().agent,
            last_contact_at_millis: item.last_contact_at_millis,
            identity_digest: Digest::from_serializable(&(
                "ninjaone-agent-projection/v1",
                &item.device_id,
                &item.agent_id,
                scope.revisions().agent,
            )),
        });
        let alert_projections =
            normalize_alerts(scope, &alerts, &mut partial, &mut self.observed_revisions)?;
        let patch_health = normalize_patch_health(
            scope,
            &health,
            &os_patches,
            &software_patches,
            &mut partial,
            &mut self.observed_revisions,
        )?;
        let activity_projections = normalize_activities(
            scope,
            &activities,
            &mut partial,
            &mut self.observed_revisions,
        )?;

        let offline = device.as_ref().is_some_and(|item| item.offline)
            || health_records(&health).iter().any(|item| item.offline);
        let pending_patch_count = patch_health
            .as_ref()
            .map_or(0, |item| item.pending_patch_count);
        let failed_patch_count = patch_health
            .as_ref()
            .map_or(0, |item| item.failed_patch_count);
        let health_status = patch_health
            .as_ref()
            .map_or(HealthStatus::Unknown, |item| item.health_status);
        let mut states = Vec::new();
        if offline {
            states.push(crate::NinjaOneDeviceState::Offline);
        }
        if matches!(
            health_status,
            HealthStatus::NeedsAttention | HealthStatus::Unhealthy
        ) {
            states.push(crate::NinjaOneDeviceState::Degraded);
        }
        if !alert_projections.is_empty() {
            states.push(crate::NinjaOneDeviceState::Alerted);
        }
        if pending_patch_count > 0 {
            states.push(crate::NinjaOneDeviceState::PatchPending);
        }
        if let Some(error) = provider_error.as_ref() {
            if error.code == "unauthorized" || error.code == "forbidden" {
                states.push(crate::NinjaOneDeviceState::AccessLost);
            } else if error.code == "not_found" {
                states.push(crate::NinjaOneDeviceState::RetentionGap);
            } else {
                states.push(crate::NinjaOneDeviceState::ProviderUnknown);
            }
        }
        if device.is_none()
            || patch_health.is_none()
            || matches!(health_status, HealthStatus::Unknown)
        {
            partial = true;
        }
        if states.is_empty() {
            if partial {
                states.push(crate::NinjaOneDeviceState::Partial);
            } else if health_status == HealthStatus::Healthy {
                states.push(crate::NinjaOneDeviceState::Healthy);
            } else {
                states.push(crate::NinjaOneDeviceState::ProviderUnknown);
            }
        }
        let projection = NinjaOneResultProjection::new(
            states,
            partial,
            offline,
            alert_projections.len(),
            pending_patch_count,
            failed_patch_count,
            health_status,
            provider_error,
        )?;
        let observed_at_millis = observed_timestamp(
            device.as_ref(),
            patch_health.as_ref(),
            &alert_projections,
            &activity_projections,
        );
        let evidence =
            NinjaOneDeviceResultEvidence::from_parts(NinjaOneDeviceResultEvidenceParts {
                organization,
                site,
                device,
                agent,
                alerts: alert_projections,
                patch_health,
                activities: activity_projections,
                projection,
                partial,
                observed_at_millis,
                receipts,
                scope_digest: scope.scope_digest().clone(),
                revision_digest: scope.revision_digest().clone(),
                registration_digest: self.registration.registration_digest().clone(),
                provider_digest: self.registration.provider_digest().clone(),
                api_digest: self.registration.api_digest().clone(),
                permission_digest: self.registration.permission_digest().clone(),
                provenance: self.transport.mode(),
            });
        evidence.verify_integrity()?;
        Ok(evidence)
    }

    fn collect_pages(
        &mut self,
        scope: &NinjaOneScope,
        endpoint: NinjaOneEndpoint,
        page_size: usize,
        receipts: &mut Vec<crate::NinjaOneRedactedReceipt>,
    ) -> EndpointRead {
        let mut responses = Vec::new();
        let mut after = None;
        let mut seen = BTreeSet::new();
        let mut error = None;
        for _ in 0..MAX_PAGES {
            if after.is_some_and(|cursor| !seen.insert(cursor)) {
                error = Some(NinjaOneTransportError::PaginationLoop);
                break;
            }
            let request = if let Ok(request) = NinjaOneGetRequest::new(
                endpoint,
                scope,
                self.registration.secret_reference(),
                page_size,
                after,
            ) {
                request
            } else {
                error = Some(NinjaOneTransportError::Malformed);
                break;
            };
            match self.transport.get(&request) {
                Ok(response) => {
                    receipts.push(receipt_for(&request, &response));
                    if !(200..300).contains(&response.status()) {
                        error = Some(error_from_status(response.status()));
                        break;
                    }
                    after = response.next_after();
                    responses.push(response);
                    if after.is_none() {
                        self.backoff.reset();
                        break;
                    }
                }
                Err(transport_error) => {
                    let status = transport_error.status();
                    if let Ok(response) = NinjaOneResponse::failure(status.unwrap_or(0), 0) {
                        receipts.push(receipt_for(&request, &response));
                    }
                    if transport_error.retryable() {
                        let retry_after = match transport_error {
                            NinjaOneTransportError::RateLimited429 {
                                retry_after_seconds,
                            } => retry_after_seconds,
                            _ => None,
                        };
                        self.backoff.note_retryable(retry_after);
                    }
                    self.state = state_for_error(&transport_error);
                    error = Some(transport_error);
                    break;
                }
            }
        }
        if after.is_some() && error.is_none() {
            error = Some(NinjaOneTransportError::PaginationLoop);
        }
        EndpointRead { responses, error }
    }
}

impl NinjaOneProvider<RecordingNinjaOneTransport> {
    pub fn recording(
        scope: &NinjaOneScope,
        lease: &crate::PermissionLease,
        secret: crate::SecretReference,
        responses: impl IntoIterator<Item = (NinjaOneEndpoint, NinjaOneResponse)>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = NinjaOneRegistration::new(scope, lease, secret, registration_revision)?;
        Self::new(
            registration,
            RecordingNinjaOneTransport::recording(responses)?,
        )
    }
}

impl NinjaOneProvider<FixtureNinjaOneTransport> {
    pub fn fixture(
        scope: &NinjaOneScope,
        lease: &crate::PermissionLease,
        secret: crate::SecretReference,
        responses: impl IntoIterator<Item = (NinjaOneEndpoint, NinjaOneResponse)>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = NinjaOneRegistration::new(scope, lease, secret, registration_revision)?;
        Self::new(registration, FixtureNinjaOneTransport::fixture(responses)?)
    }
}

impl NinjaOneProvider<LoopbackNinjaOneTransport> {
    pub fn loopback(
        scope: &NinjaOneScope,
        lease: &crate::PermissionLease,
        secret: crate::SecretReference,
        responses: impl IntoIterator<Item = (NinjaOneEndpoint, NinjaOneResponse)>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = NinjaOneRegistration::new(scope, lease, secret, registration_revision)?;
        Self::new(
            registration,
            LoopbackNinjaOneTransport::loopback(responses)?,
        )
    }
}

impl NinjaOneProvider<BlockedEnvNinjaOneTransport> {
    pub fn blocked_env(
        scope: &NinjaOneScope,
        lease: &crate::PermissionLease,
        secret: crate::SecretReference,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = NinjaOneRegistration::new(scope, lease, secret, registration_revision)?;
        Self::new(registration, BlockedEnvNinjaOneTransport)
    }
}

fn state_for_mode(mode: TransportMode) -> NinjaOneProviderState {
    match mode {
        TransportMode::Recording => NinjaOneProviderState::Recording,
        TransportMode::Fixture => NinjaOneProviderState::Fixture,
        TransportMode::Loopback => NinjaOneProviderState::Loopback,
        TransportMode::BlockedEnv => NinjaOneProviderState::BlockedEnv,
    }
}

fn state_for_error(error: &NinjaOneTransportError) -> NinjaOneProviderState {
    match error {
        NinjaOneTransportError::Unauthorized401 => NinjaOneProviderState::Unauthorized,
        NinjaOneTransportError::Forbidden403 => NinjaOneProviderState::Forbidden,
        NinjaOneTransportError::NotFound404 => NinjaOneProviderState::NotFound,
        NinjaOneTransportError::RateLimited429 { .. } => NinjaOneProviderState::RateLimited,
        NinjaOneTransportError::Server5xx { .. } => NinjaOneProviderState::ServerFailure,
        NinjaOneTransportError::Timeout => NinjaOneProviderState::Timeout,
        NinjaOneTransportError::BlockedEnv => NinjaOneProviderState::BlockedEnv,
        NinjaOneTransportError::MissingRecording
        | NinjaOneTransportError::UnexpectedEndpoint
        | NinjaOneTransportError::Malformed
        | NinjaOneTransportError::ResponseTooLarge
        | NinjaOneTransportError::BoundExceeded
        | NinjaOneTransportError::PaginationLoop => NinjaOneProviderState::ProviderUnknown,
        NinjaOneTransportError::Conflict409 => NinjaOneProviderState::Partial,
    }
}

fn error_from_status(status: u16) -> NinjaOneTransportError {
    match status {
        401 => NinjaOneTransportError::Unauthorized401,
        403 => NinjaOneTransportError::Forbidden403,
        404 => NinjaOneTransportError::NotFound404,
        409 => NinjaOneTransportError::Conflict409,
        429 => NinjaOneTransportError::RateLimited429 {
            retry_after_seconds: None,
        },
        500..=599 => NinjaOneTransportError::Server5xx { status },
        _ => NinjaOneTransportError::Malformed,
    }
}

fn error_projection(error: &NinjaOneTransportError) -> NinjaOneProviderErrorProjection {
    NinjaOneProviderErrorProjection {
        code: error.code().to_owned(),
        http_status: error.status(),
        retryable: error.retryable(),
        error_digest: crate::Digest::from_text(error.code()),
    }
}

fn normalize_organization(
    scope: &NinjaOneScope,
    read: &EndpointRead,
    partial: &mut bool,
) -> Result<Option<NinjaOneOrganizationProjection>> {
    let mut found = None;
    for response in &read.responses {
        if let Some(NinjaOnePayload::Organizations(items)) = response.payload() {
            for item in items {
                if item.organization_id == *scope.organization_id() {
                    if !item.site_ids.is_empty() && !item.site_ids.contains(scope.site_id()) {
                        return Err(NinjaOneError::ProviderScopeMismatch);
                    }
                    if item.revision != scope.revisions().organization {
                        return Err(NinjaOneError::StaleProviderRevision);
                    }
                    found = Some(NinjaOneOrganizationProjection {
                        organization_id: item.organization_id.clone(),
                        site_count: item.site_ids.len(),
                        organization_revision: item.revision,
                        identity_digest: item.metadata_digest.clone(),
                    });
                }
            }
        }
    }
    if found.is_none() {
        *partial = true;
    }
    Ok(found)
}

fn normalize_device(
    scope: &NinjaOneScope,
    read: &EndpointRead,
    partial: &mut bool,
    revisions: &mut BTreeMap<NinjaOneEndpoint, Revision>,
) -> Result<Option<NinjaOneDeviceProjection>> {
    let mut found = None;
    for response in &read.responses {
        if let Some(NinjaOnePayload::Devices(items)) = response.payload() {
            for item in items {
                if item.organization_id == *scope.organization_id()
                    && item.site_id == *scope.site_id()
                    && item.device_id == *scope.device_id()
                {
                    if item.agent_id != *scope.agent_id() {
                        return Err(NinjaOneError::ProviderScopeMismatch);
                    }
                    if item.revision != scope.revisions().device
                        || item.revision != scope.revisions().agent
                    {
                        return Err(NinjaOneError::StaleProviderRevision);
                    }
                    check_revision(revisions, NinjaOneEndpoint::Devices, item.revision)?;
                    found = Some(NinjaOneDeviceProjection {
                        organization_id: item.organization_id.clone(),
                        site_id: item.site_id.clone(),
                        device_id: item.device_id.clone(),
                        agent_id: item.agent_id.clone(),
                        offline: item.offline,
                        last_contact_at_millis: item.last_contact_at_millis,
                        device_revision: item.revision,
                        identity_digest: item.metadata_digest.clone(),
                    });
                }
            }
        }
    }
    if found.is_none() {
        *partial = true;
    }
    Ok(found)
}

fn normalize_alerts(
    scope: &NinjaOneScope,
    read: &EndpointRead,
    partial: &mut bool,
    revisions: &mut BTreeMap<NinjaOneEndpoint, Revision>,
) -> Result<Vec<NinjaOneAlertProjection>> {
    let mut output = Vec::new();
    for response in &read.responses {
        if let Some(NinjaOnePayload::DeviceAlerts(items)) = response.payload() {
            for item in items {
                if item.device_id == *scope.device_id() && item.alert_id == *scope.alert_id() {
                    if item.revision != scope.revisions().alert {
                        return Err(NinjaOneError::StaleProviderRevision);
                    }
                    check_revision(revisions, NinjaOneEndpoint::DeviceAlerts, item.revision)?;
                    if output.len() >= MAX_ALERTS {
                        return Err(NinjaOneError::BoundExceeded { kind: "alerts" });
                    }
                    output.push(NinjaOneAlertProjection {
                        alert_id: item.alert_id.clone(),
                        device_id: item.device_id.clone(),
                        kind: item.kind,
                        created_at_millis: item.created_at_millis,
                        updated_at_millis: item.updated_at_millis,
                        alert_revision: item.revision,
                        body_digest: item.body_digest.clone(),
                        metadata_digest: Digest::from_serializable(&(
                            item.metadata_digest.clone(),
                            item.source_digest.clone(),
                        )),
                    });
                }
            }
        }
    }
    if read.error.is_some() {
        *partial = true;
    }
    Ok(output)
}

fn normalize_patch_health(
    scope: &NinjaOneScope,
    health: &EndpointRead,
    os_patches: &EndpointRead,
    software_patches: &EndpointRead,
    partial: &mut bool,
    revisions: &mut BTreeMap<NinjaOneEndpoint, Revision>,
) -> Result<Option<NinjaOnePatchHealthProjection>> {
    let mut record = None;
    for response in &health.responses {
        if let Some(NinjaOnePayload::DeviceHealth(items)) = response.payload() {
            for item in items {
                if item.device_id == *scope.device_id() {
                    if item.patch_health_id != *scope.patch_health_id() {
                        return Err(NinjaOneError::ProviderScopeMismatch);
                    }
                    if item.revision != scope.revisions().patch_health {
                        return Err(NinjaOneError::StaleProviderRevision);
                    }
                    check_revision(revisions, NinjaOneEndpoint::DeviceHealth, item.revision)?;
                    record = Some(item.clone());
                }
            }
        }
    }
    let mut pending = record.as_ref().map_or(0, |item| {
        item.pending_os_patches + item.pending_software_patches
    });
    let mut failed = record.as_ref().map_or(0, |item| {
        item.failed_os_patches + item.failed_software_patches
    });
    count_patches(os_patches, scope, &mut pending, &mut failed, revisions)?;
    count_patches(
        software_patches,
        scope,
        &mut pending,
        &mut failed,
        revisions,
    )?;
    if pending > MAX_PATCHES || failed > MAX_PATCHES {
        return Err(NinjaOneError::BoundExceeded { kind: "patches" });
    }
    let output = record.map(|item| NinjaOnePatchHealthProjection {
        patch_health_id: item.patch_health_id,
        device_id: item.device_id,
        health_status: item.health_status,
        pending_patch_count: pending,
        failed_patch_count: failed,
        observed_at_millis: item.observed_at_millis,
        patch_health_revision: item.revision,
        metadata_digest: item.metadata_digest,
    });
    if output.is_none() {
        *partial = true;
    }
    Ok(output)
}

fn count_patches(
    read: &EndpointRead,
    scope: &NinjaOneScope,
    pending: &mut usize,
    failed: &mut usize,
    revisions: &mut BTreeMap<NinjaOneEndpoint, Revision>,
) -> Result<()> {
    for response in &read.responses {
        let items = match response.payload() {
            Some(NinjaOnePayload::OsPatches(items) | NinjaOnePayload::SoftwarePatches(items)) => {
                items
            }
            _ => continue,
        };
        for item in items {
            if item.device_id == *scope.device_id() || item.device_id.as_str() == "scoped-device" {
                let endpoint = response
                    .payload()
                    .map_or(NinjaOneEndpoint::DeviceOsPatches, NinjaOnePayload::endpoint);
                check_revision(revisions, endpoint, item.revision)?;
                match item.status {
                    crate::PatchStatus::Pending | crate::PatchStatus::Rejected => {
                        *pending = pending.saturating_add(1);
                    }
                    crate::PatchStatus::Failed => *failed = failed.saturating_add(1),
                    crate::PatchStatus::Installed | crate::PatchStatus::Unknown => {}
                }
            }
        }
    }
    Ok(())
}

fn normalize_activities(
    scope: &NinjaOneScope,
    read: &EndpointRead,
    partial: &mut bool,
    revisions: &mut BTreeMap<NinjaOneEndpoint, Revision>,
) -> Result<Vec<NinjaOneActivityProjection>> {
    let mut output = Vec::new();
    for response in &read.responses {
        if let Some(NinjaOnePayload::DeviceActivities(items)) = response.payload() {
            for item in items {
                if item.device_id == *scope.device_id() && item.activity_id == *scope.activity_id()
                {
                    if item.revision != scope.revisions().activity {
                        return Err(NinjaOneError::StaleProviderRevision);
                    }
                    check_revision(revisions, NinjaOneEndpoint::DeviceActivities, item.revision)?;
                    if output.len() >= MAX_ACTIVITIES {
                        return Err(NinjaOneError::BoundExceeded { kind: "activities" });
                    }
                    output.push(NinjaOneActivityProjection {
                        activity_id: item.activity_id.clone(),
                        device_id: item.device_id.clone(),
                        kind: item.kind,
                        severity: item.severity,
                        result: item.result,
                        activity_at_millis: item.activity_at_millis,
                        activity_revision: item.revision,
                        metadata_digest: Digest::from_serializable(&(
                            item.metadata_digest.clone(),
                            item.activity_type_digest.clone(),
                        )),
                    });
                }
            }
        }
    }
    if read.error.is_some() {
        *partial = true;
    }
    Ok(output)
}

fn check_revision(
    revisions: &mut BTreeMap<NinjaOneEndpoint, Revision>,
    endpoint: NinjaOneEndpoint,
    revision: Revision,
) -> Result<()> {
    if let Some(previous) = revisions.get(&endpoint)
        && revision < *previous
    {
        return Err(NinjaOneError::StaleProviderRevision);
    }
    revisions.insert(endpoint, revision);
    Ok(())
}

fn health_records(read: &EndpointRead) -> Vec<&NinjaOneDeviceHealthRecord> {
    read.responses
        .iter()
        .filter_map(|response| match response.payload() {
            Some(NinjaOnePayload::DeviceHealth(items)) => Some(items.iter()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn observed_timestamp(
    device: Option<&NinjaOneDeviceProjection>,
    patch_health: Option<&NinjaOnePatchHealthProjection>,
    alerts: &[NinjaOneAlertProjection],
    activities: &[NinjaOneActivityProjection],
) -> u64 {
    let mut timestamp = device
        .and_then(|item| item.last_contact_at_millis)
        .unwrap_or(0);
    timestamp = timestamp.max(
        patch_health
            .and_then(|item| item.observed_at_millis)
            .unwrap_or(0),
    );
    for alert in alerts {
        timestamp = timestamp.max(
            alert
                .updated_at_millis
                .or(alert.created_at_millis)
                .unwrap_or(0),
        );
    }
    for activity in activities {
        timestamp = timestamp.max(activity.activity_at_millis.unwrap_or(0));
    }
    timestamp
}
