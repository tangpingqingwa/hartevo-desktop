use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    ComponentGroupId, ComponentId, ComponentStatus, Digest, IncidentId, IncidentImpact,
    IncidentStatus, MAX_COMPONENT_GROUPS, MAX_COMPONENTS, MAX_INCIDENTS, MAX_REQUESTS_PER_MINUTE,
    MAX_RESPONSE_BYTES, MAX_UPDATES, MaintenanceState, ModelError, PageId, SecretReference,
    StatuspageAcl, StatuspageAffectedComponent, StatuspageComponentGroupObservation,
    StatuspageComponentObservation, StatuspageHttpMethod, StatuspageIncidentObservation,
    StatuspageIncidentResult, StatuspageIncidentResultScope, StatuspageIncidentUpdate,
    StatuspageMaintenanceObservation, StatuspagePermission, StatuspageRateLimitReceipt,
    StatuspageReadSeam, StatuspageRegistration, StatuspageRequest, StatuspageRequestReceipt,
    TransportProvenance, canonical_digest,
};

/// Layer-1 provider metadata. `native`, `connected`, and `first_party` remain
/// false for every supported provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub acl_digest: Digest,
    pub provenance: TransportProvenance,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub max_items_per_collection: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl StatuspageProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: TransportProvenance, acl: &StatuspageAcl) -> Self {
        let capability_digest = canonical_digest(&(
            crate::STATUSPAGE_INCIDENT_RESULT_SCHEMA_VERSION,
            crate::STATUSPAGE_PROVIDER_ID,
            crate::STATUSPAGE_API_REVISION,
            StatuspageReadSeam::PageProfile,
            StatuspageReadSeam::Components,
            StatuspageReadSeam::ComponentGroups,
            StatuspageReadSeam::Incidents,
            StatuspageReadSeam::ScheduledMaintenances,
            "get_only",
            "no_subscribers",
            "no_writes",
        ));
        Self {
            schema_version: crate::STATUSPAGE_INCIDENT_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: crate::STATUSPAGE_PROVIDER_ID.to_owned(),
            provider_version: crate::STATUSPAGE_PROVIDER_VERSION.to_owned(),
            api_revision: crate::STATUSPAGE_API_REVISION.to_owned(),
            capability_digest,
            acl_digest: acl.digest(),
            provenance,
            max_requests_per_minute: MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_items_per_collection: MAX_INCIDENTS,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: StatuspageRateLimitReceipt,
}

impl fmt::Debug for StatuspageResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatuspageResponse")
            .field("status", &self.status)
            .field("body_digest", &crate::sha256_digest(&self.body))
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl StatuspageResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, StatuspageRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: StatuspageRateLimitReceipt,
    ) -> Self {
        Self {
            status,
            body: serde_json::to_vec(value).expect("Statuspage fixture serializes"),
            rate_limit,
        }
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: StatuspageRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        crate::sha256_digest(&self.body)
    }

    #[must_use]
    pub fn response_bytes(&self) -> usize {
        self.body.len()
    }
}

pub trait StatuspageTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &StatuspageRequest,
    ) -> Result<StatuspageResponse, StatuspageTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureStatuspageTransport {
    response: StatuspageResponse,
}

impl FixtureStatuspageTransport {
    #[must_use]
    pub fn new(response: StatuspageResponse) -> Self {
        Self { response }
    }
}

impl StatuspageTransport for FixtureStatuspageTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &StatuspageRequest,
    ) -> Result<StatuspageResponse, StatuspageTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingStatuspageTransport {
    response: StatuspageResponse,
    requests: Vec<StatuspageRequest>,
}

impl RecordingStatuspageTransport {
    #[must_use]
    pub fn new(response: StatuspageResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[StatuspageRequest] {
        &self.requests
    }
}

impl StatuspageTransport for RecordingStatuspageTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &StatuspageRequest,
    ) -> Result<StatuspageResponse, StatuspageTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackStatuspageTransport {
    response: StatuspageResponse,
    requests: Vec<StatuspageRequest>,
}

impl LoopbackStatuspageTransport {
    #[must_use]
    pub fn new(response: StatuspageResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[StatuspageRequest] {
        &self.requests
    }
}

impl StatuspageTransport for LoopbackStatuspageTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &StatuspageRequest,
    ) -> Result<StatuspageResponse, StatuspageTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvStatuspageTransport;

impl StatuspageTransport for BlockedEnvStatuspageTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &StatuspageRequest,
    ) -> Result<StatuspageResponse, StatuspageTransportError> {
        Err(StatuspageTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StatuspageTransportError {
    #[error("Statuspage native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Statuspage transport timed out")]
    Timeout,
    #[error("Statuspage transport failed without a native response")]
    ProviderUnknown,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StatuspageProviderError {
    #[error("Statuspage registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Statuspage SecretReference is revoked")]
    SecretRevoked,
    #[error("Statuspage permission is missing")]
    MissingPermission { permission: StatuspagePermission },
    #[error("Statuspage page or component scope does not match")]
    ScopeMismatch,
    #[error("Statuspage API rate limit was reached")]
    RateLimited {
        request: StatuspageRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: StatuspageRateLimitReceipt,
        status_code: u16,
    },
    #[error("Statuspage API returned a non-success status")]
    HttpStatus {
        request: StatuspageRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: StatuspageRateLimitReceipt,
        status_code: u16,
    },
    #[error("Statuspage response exceeded the Layer-1 bound")]
    ResponseTooLarge {
        request: StatuspageRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: StatuspageRateLimitReceipt,
        status_code: u16,
    },
    #[error("Statuspage response was malformed")]
    MalformedResponse {
        request: StatuspageRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: StatuspageRateLimitReceipt,
        status_code: u16,
    },
    #[error("Statuspage transport is unavailable")]
    Transport {
        request: StatuspageRequest,
        error: StatuspageTransportError,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl StatuspageProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&StatuspageRequest> {
        match self {
            Self::RateLimited { request, .. }
            | Self::HttpStatus { request, .. }
            | Self::ResponseTooLarge { request, .. }
            | Self::MalformedResponse { request, .. }
            | Self::Transport { request, .. } => Some(request),
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingPermission { .. }
            | Self::ScopeMismatch
            | Self::Model(_) => None,
        }
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, StatuspageRateLimitReceipt, Option<u16>)> {
        match self {
            Self::RateLimited {
                response_digest,
                response_bytes,
                rate_limit,
                status_code,
                ..
            }
            | Self::HttpStatus {
                response_digest,
                response_bytes,
                rate_limit,
                status_code,
                ..
            }
            | Self::ResponseTooLarge {
                response_digest,
                response_bytes,
                rate_limit,
                status_code,
                ..
            }
            | Self::MalformedResponse {
                response_digest,
                response_bytes,
                rate_limit,
                status_code,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                Some(*status_code),
            )),
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingPermission { .. }
            | Self::ScopeMismatch
            | Self::Transport { .. }
            | Self::Model(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StatuspageProviderRead {
    pub result: StatuspageIncidentResult,
    pub request_receipts: Vec<StatuspageRequestReceipt>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: StatuspageRateLimitReceipt,
    pub provenance: TransportProvenance,
}

pub struct StatuspageProvider<T: StatuspageTransport> {
    scope: StatuspageIncidentResultScope,
    secret_reference: SecretReference,
    definition: StatuspageProviderDefinition,
    registration: StatuspageRegistration,
    transport: T,
}

impl<T: StatuspageTransport> fmt::Debug for StatuspageProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatuspageProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: StatuspageTransport> StatuspageProvider<T> {
    pub fn new(
        scope: StatuspageIncidentResultScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, StatuspageProviderError> {
        scope.validate()?;
        ensure_permissions(scope.acl())?;
        let definition = StatuspageProviderDefinition::layer1(transport.provenance(), scope.acl());
        let registration =
            StatuspageRegistration::bind(&scope, &secret_reference, &definition.provider_digest())?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    pub fn with_registration(
        scope: StatuspageIncidentResultScope,
        secret_reference: SecretReference,
        transport: T,
        registration: StatuspageRegistration,
    ) -> Result<Self, StatuspageProviderError> {
        scope.validate()?;
        ensure_permissions(scope.acl())?;
        let definition = StatuspageProviderDefinition::layer1(transport.provenance(), scope.acl());
        if registration.is_revoked() {
            return Err(StatuspageProviderError::RegistrationRevoked);
        }
        registration.validate(&scope, &secret_reference, &definition.provider_digest())?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &StatuspageIncidentResultScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &StatuspageProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &StatuspageRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<StatuspageProviderRead, StatuspageProviderError> {
        self.ensure_ready()?;
        let seams = [
            StatuspageReadSeam::PageProfile,
            StatuspageReadSeam::Components,
            StatuspageReadSeam::ComponentGroups,
            StatuspageReadSeam::Incidents,
            StatuspageReadSeam::ScheduledMaintenances,
        ];
        let mut parsed = ParsedResponses::default();
        let mut request_receipts = Vec::with_capacity(seams.len());
        let mut response_digests = Vec::with_capacity(seams.len());
        let mut response_bytes = 0_usize;
        let mut rate_limit = StatuspageRateLimitReceipt::default();
        for seam in seams {
            let request = self.build_request(seam);
            let response = self.transport.execute(&request).map_err(|error| {
                StatuspageProviderError::Transport {
                    request: request.clone(),
                    error,
                }
            })?;
            let response_digest = response.response_digest();
            response_bytes = response_bytes.saturating_add(response.response_bytes());
            rate_limit = response.rate_limit.clone();
            if response.response_bytes() > MAX_RESPONSE_BYTES {
                return Err(StatuspageProviderError::ResponseTooLarge {
                    request,
                    response_digest,
                    response_bytes: response.response_bytes(),
                    rate_limit: response.rate_limit,
                    status_code: response.status,
                });
            }
            if response.status == 420 || response.status == 429 {
                return Err(StatuspageProviderError::RateLimited {
                    request,
                    response_digest,
                    response_bytes: response.response_bytes(),
                    rate_limit: response.rate_limit,
                    status_code: response.status,
                });
            }
            if !(200..300).contains(&response.status) {
                return Err(StatuspageProviderError::HttpStatus {
                    request,
                    response_digest,
                    response_bytes: response.response_bytes(),
                    rate_limit: response.rate_limit,
                    status_code: response.status,
                });
            }
            let value: Value = serde_json::from_slice(&response.body).map_err(|_| {
                StatuspageProviderError::MalformedResponse {
                    request: request.clone(),
                    response_digest: response_digest.clone(),
                    response_bytes: response.response_bytes(),
                    rate_limit: response.rate_limit.clone(),
                    status_code: response.status,
                }
            })?;
            parsed.ingest(seam, &value, &self.scope).map_err(|_| {
                StatuspageProviderError::MalformedResponse {
                    request: request.clone(),
                    response_digest: response_digest.clone(),
                    response_bytes: response.response_bytes(),
                    rate_limit: response.rate_limit.clone(),
                    status_code: response.status,
                }
            })?;
            response_digests.push(response_digest.clone());
            request_receipts.push(StatuspageRequestReceipt {
                method: request.method,
                seam,
                endpoint: request.endpoint(),
                request_digest: request.request_digest,
                response_digest,
                status_code: Some(response.status),
                response_bytes: response.response_bytes(),
                rate_limit_digest: response.rate_limit.digest(),
            });
        }
        let result = parsed.finish(&self.scope)?;
        Ok(StatuspageProviderRead {
            result,
            request_receipts,
            response_digest: canonical_digest(&response_digests),
            response_bytes,
            rate_limit,
            provenance: self.transport.provenance(),
        })
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, StatuspageProviderError> {
        self.registration.revoke().map_err(Into::into)
    }

    pub fn restore(&mut self) -> Result<(), StatuspageProviderError> {
        self.registration.restore().map_err(Into::into)
    }

    pub fn revoke_secret(&mut self) -> Result<(), StatuspageProviderError> {
        self.secret_reference.revoke().map_err(Into::into)
    }

    pub fn restore_secret(&mut self) -> Result<(), StatuspageProviderError> {
        self.secret_reference.restore().map_err(Into::into)
    }

    fn ensure_ready(&self) -> Result<(), StatuspageProviderError> {
        self.scope.validate()?;
        ensure_permissions(self.scope.acl())?;
        if self.secret_reference.is_revoked() {
            return Err(StatuspageProviderError::SecretRevoked);
        }
        if self.registration.is_revoked() {
            return Err(StatuspageProviderError::RegistrationRevoked);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| StatuspageProviderError::RegistrationRevoked)
    }

    fn build_request(&self, seam: StatuspageReadSeam) -> StatuspageRequest {
        let path = seam
            .path_template()
            .replace("{page_id}", self.scope.page().id());
        let mut request = StatuspageRequest {
            method: StatuspageHttpMethod::Get,
            host: "https://api.statuspage.io".to_owned(),
            api_revision: "v1".to_owned(),
            seam,
            path,
            page_id: PageId::new(self.scope.page().id()).expect("validated page binding"),
            page: 1,
            per_page: 100,
            scope_digest: self.scope.digest(),
            consent_digest: self.scope.consent_digest().clone(),
            secret_reference_digest: self.secret_reference.digest(),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    }
}

pub type StatuspageIncidentResultProvider<T> = StatuspageProvider<T>;

fn ensure_permissions(acl: &StatuspageAcl) -> Result<(), StatuspageProviderError> {
    for permission in StatuspageAcl::required_permissions() {
        if !acl.has(permission) {
            return Err(StatuspageProviderError::MissingPermission { permission });
        }
    }
    Ok(())
}

#[derive(Default)]
struct ParsedResponses {
    page: Option<Value>,
    components: Vec<Value>,
    component_groups: Vec<Value>,
    incidents: Vec<Value>,
    maintenances: Vec<Value>,
    partial: bool,
}

impl ParsedResponses {
    fn ingest(
        &mut self,
        seam: StatuspageReadSeam,
        value: &Value,
        scope: &StatuspageIncidentResultScope,
    ) -> Result<(), ModelError> {
        self.partial |= value
            .get("partial")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match seam {
            StatuspageReadSeam::PageProfile => {
                self.page = Some(value.get("page").cloned().unwrap_or_else(|| value.clone()));
            }
            StatuspageReadSeam::Components => {
                self.components.extend(array_for(value, &["components"]));
            }
            StatuspageReadSeam::ComponentGroups => {
                self.component_groups.extend(array_for(
                    value,
                    &["component_groups", "componentGroups", "groups"],
                ));
            }
            StatuspageReadSeam::Incidents => {
                self.incidents.extend(array_for(value, &["incidents"]));
            }
            StatuspageReadSeam::ScheduledMaintenances => {
                self.maintenances.extend(array_for(
                    value,
                    &[
                        "scheduled_maintenances",
                        "scheduledMaintenances",
                        "maintenances",
                        "incidents",
                    ],
                ));
            }
        }
        if scope.page().id().is_empty() {
            return Err(ModelError::InvalidScope("page"));
        }
        Ok(())
    }

    fn finish(
        self,
        scope: &StatuspageIncidentResultScope,
    ) -> Result<StatuspageIncidentResult, ModelError> {
        let page = self
            .page
            .map(|value| parse_page(&value, scope))
            .transpose()?;
        let components = parse_components(&self.components, scope)?;
        let component_groups = parse_component_groups(&self.component_groups, scope)?;
        let incidents = parse_incidents(&self.incidents, scope)?;
        let maintenances = parse_maintenances(&self.maintenances, scope)?;
        Ok(StatuspageIncidentResult {
            page,
            components,
            component_groups,
            incidents,
            maintenances,
            partial: self.partial,
        })
    }
}

fn array_for(value: &Value, keys: &[&str]) -> Vec<Value> {
    if let Some(array) = value.as_array() {
        return array.clone();
    }
    for key in keys {
        if let Some(array) = value.get(*key).and_then(Value::as_array) {
            return array.clone();
        }
    }
    Vec::new()
}

fn parse_page(
    value: &Value,
    scope: &StatuspageIncidentResultScope,
) -> Result<crate::StatuspagePageProfile, ModelError> {
    let id = value
        .get("id")
        .or_else(|| value.get("page_id"))
        .and_then(Value::as_str)
        .unwrap_or(scope.page().id());
    let page_id = PageId::new(id)?;
    if page_id.as_str() != scope.page().id() {
        return Err(ModelError::InvalidScope("page id"));
    }
    Ok(crate::StatuspagePageProfile {
        id: page_id,
        updated_at: value
            .get("updated_at")
            .and_then(Value::as_str)
            .map(str::to_owned),
        time_zone: value
            .get("time_zone")
            .and_then(Value::as_str)
            .map(str::to_owned),
        public_url_digest: value
            .get("url")
            .and_then(Value::as_str)
            .map(|url| sha256_digest(format!("statuspage-public-url/v1|{url}").as_bytes())),
    })
}

fn parse_components(
    values: &[Value],
    scope: &StatuspageIncidentResultScope,
) -> Result<Vec<StatuspageComponentObservation>, ModelError> {
    if values.len() > MAX_COMPONENTS {
        return Err(ModelError::InvalidBoundedData);
    }
    let selected = selected_ids(scope.components());
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        let id = required_id(value, "id", "component")?;
        if !selected.is_empty() && !selected.contains(&id) {
            continue;
        }
        if !seen.insert(id.clone()) {
            continue;
        }
        let page_id = optional_id(value, "page_id").unwrap_or_else(|| scope.page().id().to_owned());
        if page_id != scope.page().id() {
            return Err(ModelError::InvalidScope("component page"));
        }
        let group_id = optional_id(value, "group_id");
        let status = value
            .get("status")
            .and_then(Value::as_str)
            .map_or(ComponentStatus::ProviderUnknown, ComponentStatus::parse);
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&id)
            .to_owned();
        result.push(StatuspageComponentObservation {
            id: ComponentId::new(id)?,
            page_id: PageId::new(page_id)?,
            group_id: group_id.map(ComponentGroupId::new).transpose()?,
            name_digest: sha256_digest(format!("statuspage-component-name/v1|{name}").as_bytes()),
            status,
            updated_at: value
                .get("updated_at")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    result.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(result)
}

fn parse_component_groups(
    values: &[Value],
    scope: &StatuspageIncidentResultScope,
) -> Result<Vec<StatuspageComponentGroupObservation>, ModelError> {
    if values.len() > MAX_COMPONENT_GROUPS {
        return Err(ModelError::InvalidBoundedData);
    }
    let selected = selected_ids(scope.component_groups());
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        let id = required_id(value, "id", "component group")?;
        if !selected.is_empty() && !selected.contains(&id) {
            continue;
        }
        if !seen.insert(id.clone()) {
            continue;
        }
        let page_id = optional_id(value, "page_id").unwrap_or_else(|| scope.page().id().to_owned());
        if page_id != scope.page().id() {
            return Err(ModelError::InvalidScope("component group page"));
        }
        let component_ids = value
            .get("components")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        item.as_str()
                            .or_else(|| item.get("id").and_then(Value::as_str))
                    })
                    .map(ComponentId::new)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&id)
            .to_owned();
        result.push(StatuspageComponentGroupObservation {
            id: ComponentGroupId::new(id)?,
            page_id: PageId::new(page_id)?,
            name_digest: sha256_digest(
                format!("statuspage-component-group-name/v1|{name}").as_bytes(),
            ),
            component_ids,
            updated_at: value
                .get("updated_at")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    result.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(result)
}

fn parse_incidents(
    values: &[Value],
    scope: &StatuspageIncidentResultScope,
) -> Result<Vec<StatuspageIncidentObservation>, ModelError> {
    if values.len() > MAX_INCIDENTS {
        return Err(ModelError::InvalidBoundedData);
    }
    let selected = selected_ids(scope.components());
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        let id = required_id(value, "id", "incident")?;
        if !seen.insert(id.clone()) {
            continue;
        }
        let page_id = optional_id(value, "page_id").unwrap_or_else(|| scope.page().id().to_owned());
        if page_id != scope.page().id() {
            return Err(ModelError::InvalidScope("incident page"));
        }
        let component_ids = component_ids(value)?;
        if !selected.is_empty()
            && !component_ids
                .iter()
                .any(|component| selected.contains(component.as_str()))
        {
            continue;
        }
        let timestamps = incident_timestamps(value);
        if !timestamps.is_empty()
            && !timestamps
                .iter()
                .any(|timestamp| scope.time_window().contains(timestamp))
        {
            continue;
        }
        let updates = parse_updates(value, &id, scope, &selected)?;
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&id)
            .to_owned();
        result.push(StatuspageIncidentObservation {
            id: IncidentId::new(id)?,
            page_id: PageId::new(page_id)?,
            name_digest: sha256_digest(format!("statuspage-incident-name/v1|{name}").as_bytes()),
            status: value
                .get("status")
                .and_then(Value::as_str)
                .map_or(IncidentStatus::ProviderUnknown, IncidentStatus::parse),
            impact: IncidentImpact::parse(value.get("impact").and_then(Value::as_str)),
            created_at: optional_string(value, "created_at"),
            updated_at: optional_string(value, "updated_at"),
            monitoring_at: optional_string(value, "monitoring_at"),
            resolved_at: optional_string(value, "resolved_at"),
            scheduled_for: optional_string(value, "scheduled_for"),
            scheduled_until: optional_string(value, "scheduled_until"),
            component_ids,
            updates,
        });
    }
    result.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(result)
}

fn parse_maintenances(
    values: &[Value],
    scope: &StatuspageIncidentResultScope,
) -> Result<Vec<StatuspageMaintenanceObservation>, ModelError> {
    if values.len() > MAX_INCIDENTS {
        return Err(ModelError::InvalidBoundedData);
    }
    let selected = selected_ids(scope.components());
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        let id = required_id(value, "id", "maintenance")?;
        if !seen.insert(id.clone()) {
            continue;
        }
        let page_id = optional_id(value, "page_id").unwrap_or_else(|| scope.page().id().to_owned());
        if page_id != scope.page().id() {
            return Err(ModelError::InvalidScope("maintenance page"));
        }
        let component_ids = component_ids(value)?;
        if !selected.is_empty()
            && !component_ids
                .iter()
                .any(|component| selected.contains(component.as_str()))
        {
            continue;
        }
        let timestamps = incident_timestamps(value);
        if !timestamps.is_empty()
            && !timestamps
                .iter()
                .any(|timestamp| scope.time_window().contains(timestamp))
        {
            continue;
        }
        let updates = parse_updates(value, &id, scope, &selected)?;
        result.push(StatuspageMaintenanceObservation {
            incident_id: IncidentId::new(id)?,
            page_id: PageId::new(page_id)?,
            state: value
                .get("status")
                .and_then(Value::as_str)
                .map_or(MaintenanceState::ProviderUnknown, MaintenanceState::parse),
            scheduled_for: optional_string(value, "scheduled_for"),
            scheduled_until: optional_string(value, "scheduled_until"),
            component_ids,
            updates,
        });
    }
    result.sort_by(|left, right| left.incident_id.cmp(&right.incident_id));
    Ok(result)
}

fn parse_updates(
    value: &Value,
    incident_id: &str,
    window: &StatuspageIncidentResultScope,
    selected: &BTreeSet<String>,
) -> Result<Vec<StatuspageIncidentUpdate>, ModelError> {
    let values = value
        .get("incident_updates")
        .or_else(|| value.get("incidentUpdates"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if values.len() > MAX_UPDATES {
        return Err(ModelError::InvalidBoundedData);
    }
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for update in values {
        let id = required_id(&update, "id", "incident update")?;
        if !seen.insert(id.clone()) {
            continue;
        }
        let update_incident_id =
            optional_id(&update, "incident_id").unwrap_or_else(|| incident_id.to_owned());
        if update_incident_id != incident_id {
            return Err(ModelError::InvalidScope("incident update incident"));
        }
        let timestamps = [
            optional_string(&update, "created_at"),
            optional_string(&update, "display_at"),
            optional_string(&update, "updated_at"),
        ];
        if timestamps.iter().flatten().next().is_some()
            && !timestamps
                .iter()
                .flatten()
                .any(|timestamp| window.time_window().contains(timestamp))
        {
            continue;
        }
        let affected_components = parse_affected_components(&update, selected)?;
        let body_digest = update
            .get("body")
            .and_then(Value::as_str)
            .map(|body| sha256_digest(format!("statuspage-update-body/v1|{body}").as_bytes()));
        result.push(StatuspageIncidentUpdate {
            id: crate::UpdateId::new(id)?,
            incident_id: IncidentId::new(incident_id)?,
            status: update
                .get("status")
                .and_then(Value::as_str)
                .map_or(IncidentStatus::ProviderUnknown, IncidentStatus::parse),
            created_at: timestamps[0].clone(),
            display_at: timestamps[1].clone(),
            updated_at: timestamps[2].clone(),
            body_digest,
            affected_components,
        });
    }
    result.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(result)
}

fn parse_affected_components(
    update: &Value,
    selected: &BTreeSet<String>,
) -> Result<Vec<StatuspageAffectedComponent>, ModelError> {
    let values = update
        .get("affected_components")
        .or_else(|| update.get("affectedComponents"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut result = Vec::new();
    for affected in values {
        let id = affected
            .get("code")
            .or_else(|| affected.get("id"))
            .and_then(Value::as_str)
            .ok_or(ModelError::InvalidProviderResponse)?;
        if !selected.is_empty() && !selected.contains(id) {
            continue;
        }
        result.push(StatuspageAffectedComponent {
            component_id: ComponentId::new(id)?,
            old_status: affected
                .get("old_status")
                .or_else(|| affected.get("oldStatus"))
                .and_then(Value::as_str)
                .map_or(ComponentStatus::ProviderUnknown, ComponentStatus::parse),
            new_status: affected
                .get("new_status")
                .or_else(|| affected.get("newStatus"))
                .and_then(Value::as_str)
                .map_or(ComponentStatus::ProviderUnknown, ComponentStatus::parse),
        });
    }
    result.sort_by(|left, right| left.component_id.cmp(&right.component_id));
    Ok(result)
}

fn component_ids(value: &Value) -> Result<Vec<ComponentId>, ModelError> {
    let Some(components) = value.get("components") else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    if let Some(items) = components.as_array() {
        for item in items {
            let id = item
                .as_str()
                .or_else(|| item.get("id").and_then(Value::as_str))
                .ok_or(ModelError::InvalidProviderResponse)?;
            ids.push(ComponentId::new(id)?);
        }
    } else if let Some(object) = components.as_object() {
        for id in object.keys() {
            ids.push(ComponentId::new(id)?);
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn incident_timestamps(value: &Value) -> Vec<String> {
    [
        "created_at",
        "updated_at",
        "monitoring_at",
        "resolved_at",
        "scheduled_for",
        "scheduled_until",
    ]
    .into_iter()
    .filter_map(|key| optional_string(value, key))
    .collect()
}

fn selected_ids(bindings: &[crate::ResourceBinding]) -> BTreeSet<String> {
    bindings
        .iter()
        .map(|binding| binding.id().to_owned())
        .collect()
}

fn required_id(value: &Value, key: &str, label: &'static str) -> Result<String, ModelError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ModelError::InvalidProviderResponse)
        .and_then(|id| {
            crate::PageId::new(id.to_owned())
                .map(|_| id.to_owned())
                .map_err(|_| ModelError::InvalidIdentifier { label })
        })
}

fn optional_id(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn sha256_digest(bytes: &[u8]) -> Digest {
    crate::sha256_digest(bytes)
}
