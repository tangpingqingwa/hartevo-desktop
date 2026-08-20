//! Provider and transport seams for bounded Cloud Build list/get reads.
//!
//! There is deliberately no HTTP client, credential resolver, or mutation
//! method in this module. Transports are fixture/recording/loopback seams so
//! Layer 2 can later supply native HTTPS under a separately reviewed boundary.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{
    ArtifactKind, ArtifactMetadata, BuildId, BuildSelector, BuildStepDigest, CloudBuildOperation,
    CloudBuildResponseReceipt, CloudBuildStatus, CloudBuildStepStatus, CloudBuildSummary, Digest,
    EvidenceState, GcpCloudBuildScope, Location, MAX_ARTIFACTS_PER_BUILD, MAX_BUILDS,
    MAX_OPAQUE_PAGE_TOKEN_BYTES, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, MAX_STEPS_PER_BUILD,
    ModelError, ProjectId, SecretReference, SourceCommit, SourceRepository, TransportProvenance,
};

pub const GCP_CLOUD_BUILD_API_VERSION: &str = "v1";
pub const GCP_CLOUD_BUILD_API_REVISION: &str = "cloud-build-rest-v1-projects-builds-list-get";
pub const GCP_CLOUD_BUILD_BASE_URL: &str = "https://cloudbuild.googleapis.com";
pub const GCP_CLOUD_BUILD_PROVIDER_REVISION: &str = "gcp-cloud-build-v1-r1";

/// A page token is carried only inside the provider seam. Debug and serde
/// expose its digest, never the opaque provider value.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    value: String,
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_OPAQUE_PAGE_TOKEN_BYTES {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        if value.trim() != value || value.chars().any(char::is_control) {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        Ok(Self {
            digest: Digest::from_text(&value),
            value,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaquePageToken", 1)?;
        state.serialize_field("digest", &self.digest)?;
        state.end()
    }
}

pub type OpaqueCursor = OpaquePageToken;
pub type PageToken = OpaquePageToken;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    Timeout,
    Malformed,
    ScopeDrift,
    PaginationLoop,
    RequestTampered,
    ResponseTampered,
    BlockedEnv,
}

impl ProviderFailureClass {
    #[must_use]
    pub const fn evidence_state(self) -> EvidenceState {
        match self {
            Self::Unauthorized | Self::Forbidden | Self::BlockedEnv => EvidenceState::AccessLost,
            Self::NotFound => EvidenceState::NotFound,
            Self::Conflict => EvidenceState::Conflict,
            Self::RateLimited => EvidenceState::RateLimited,
            Self::Timeout => EvidenceState::Timeout,
            Self::ScopeDrift => EvidenceState::Stale,
            Self::PaginationLoop | Self::Malformed => EvidenceState::Partial,
            Self::Server | Self::RequestTampered | Self::ResponseTampered => {
                EvidenceState::ProviderUnknown
            }
        }
    }

    #[must_use]
    pub const fn from_status(status: u16) -> Option<Self> {
        match status {
            408 => Some(Self::Timeout),
            401 => Some(Self::Unauthorized),
            403 => Some(Self::Forbidden),
            404 => Some(Self::NotFound),
            409 => Some(Self::Conflict),
            429 => Some(Self::RateLimited),
            500..=599 => Some(Self::Server),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpCloudBuildProviderError {
    #[error("Cloud Build provider failure: {class:?} ({status_code:?})")]
    Failure {
        class: ProviderFailureClass,
        status_code: Option<u16>,
        response_digest: Option<Digest>,
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("Cloud Build request model is invalid: {0}")]
    InvalidRequest(#[from] ModelError),
}

impl GcpCloudBuildProviderError {
    #[must_use]
    pub fn failure(
        class: ProviderFailureClass,
        status_code: Option<u16>,
        response_digest: Option<Digest>,
        provenance: TransportProvenance,
    ) -> Self {
        let diagnostic_digest = Digest::from_serializable(&(class, status_code, &response_digest));
        Self::Failure {
            class,
            status_code,
            response_digest,
            diagnostic_digest,
            provenance,
        }
    }

    #[must_use]
    pub const fn class(&self) -> Option<ProviderFailureClass> {
        match self {
            Self::Failure { class, .. } => Some(*class),
            Self::InvalidRequest(_) => None,
        }
    }

    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Failure { status_code, .. } => *status_code,
            Self::InvalidRequest(_) => None,
        }
    }

    #[must_use]
    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Failure {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::InvalidRequest(error) => Digest::from_text(error.to_string()),
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Option<Digest> {
        match self {
            Self::Failure {
                response_digest, ..
            } => response_digest.clone(),
            Self::InvalidRequest(_) => None,
        }
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        match self {
            Self::Failure { provenance, .. } => *provenance,
            Self::InvalidRequest(_) => TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn evidence_state(&self) -> EvidenceState {
        self.class().map_or(
            EvidenceState::ProviderUnknown,
            ProviderFailureClass::evidence_state,
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider definition drifted from the Cloud Build contract")]
    ContractDrift,
    #[error("provider version or revision is empty")]
    InvalidVersion,
    #[error("provider permission surface is invalid")]
    InvalidPermissions,
    #[error("model error: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudBuildProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub api_version: String,
    pub api_revision: String,
    pub permission_names: Vec<String>,
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl GcpCloudBuildProviderDefinition {
    pub fn new(provenance: TransportProvenance) -> Result<Self, ProviderDefinitionError> {
        let permission_names = vec![
            "cloudbuild.builds.list".to_owned(),
            "cloudbuild.builds.get".to_owned(),
        ];
        let capability_digest = Digest::from_serializable(&(
            crate::GCP_CLOUD_BUILD_SCHEMA_VERSION,
            crate::GCP_CLOUD_BUILD_PROVIDER_ID,
            GCP_CLOUD_BUILD_API_REVISION,
            &permission_names,
            "GET_ONLY",
            "NO_CREATE_CANCEL_RETRY_TRIGGER_MUTATION",
        ));
        let definition = Self {
            schema_version: crate::GCP_CLOUD_BUILD_PROVIDER_SCHEMA.to_owned(),
            provider_id: crate::GCP_CLOUD_BUILD_PROVIDER_ID.to_owned(),
            provider_version: crate::GCP_CLOUD_BUILD_PROVIDER_VERSION_TEXT.to_owned(),
            provider_revision: GCP_CLOUD_BUILD_PROVIDER_REVISION.to_owned(),
            api_version: GCP_CLOUD_BUILD_API_VERSION.to_owned(),
            api_revision: GCP_CLOUD_BUILD_API_REVISION.to_owned(),
            permission_names,
            capability_digest,
            provenance,
            native: false,
            connected: false,
            first_party: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != crate::GCP_CLOUD_BUILD_PROVIDER_SCHEMA
            || self.provider_id != crate::GCP_CLOUD_BUILD_PROVIDER_ID
            || self.provider_version != crate::GCP_CLOUD_BUILD_PROVIDER_VERSION_TEXT
            || self.provider_revision != GCP_CLOUD_BUILD_PROVIDER_REVISION
            || self.api_version != GCP_CLOUD_BUILD_API_VERSION
            || self.api_revision != GCP_CLOUD_BUILD_API_REVISION
            || self.permission_names
                != [
                    "cloudbuild.builds.list".to_owned(),
                    "cloudbuild.builds.get".to_owned(),
                ]
            || self.native
            || self.connected
            || self.first_party
        {
            return Err(ProviderDefinitionError::ContractDrift);
        }
        if self.capability_digest
            != Digest::from_serializable(&(
                crate::GCP_CLOUD_BUILD_SCHEMA_VERSION,
                crate::GCP_CLOUD_BUILD_PROVIDER_ID,
                GCP_CLOUD_BUILD_API_REVISION,
                &self.permission_names,
                "GET_ONLY",
                "NO_CREATE_CANCEL_RETRY_TRIGGER_MUTATION",
            ))
        {
            return Err(ProviderDefinitionError::ContractDrift);
        }
        Ok(())
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn is_first_party(&self) -> bool {
        self.first_party
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CloudBuildResponse {
    pub status_code: u16,
    body: Vec<u8>,
    provenance: TransportProvenance,
}

impl fmt::Debug for CloudBuildResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudBuildResponse")
            .field("status_code", &self.status_code)
            .field("body_digest", &Digest::from_bytes(&self.body))
            .field("body_bytes", &self.body.len())
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl Serialize for CloudBuildResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CloudBuildResponse", 4)?;
        state.serialize_field("statusCode", &self.status_code)?;
        state.serialize_field("bodyDigest", &Digest::from_bytes(&self.body))?;
        state.serialize_field("bodyBytes", &self.body.len())?;
        state.serialize_field("provenance", &self.provenance)?;
        state.end()
    }
}

impl CloudBuildResponse {
    #[must_use]
    pub fn json<T: Serialize>(status_code: u16, value: &T) -> Self {
        Self::json_with_provenance(status_code, value, TransportProvenance::Fixture)
    }

    #[must_use]
    pub fn json_with_provenance(
        status_code: u16,
        value: &impl Serialize,
        provenance: TransportProvenance,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Cloud Build fixture JSON serializes");
        Self {
            status_code,
            body,
            provenance,
        }
    }

    #[must_use]
    pub fn new(status_code: u16, body: Vec<u8>) -> Self {
        Self {
            status_code,
            body,
            provenance: TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    fn body(&self) -> &[u8] {
        &self.body
    }

    fn receipt(&self) -> CloudBuildResponseReceipt {
        let body_digest = Digest::from_bytes(&self.body);
        let response_digest = Digest::from_serializable(&(
            self.status_code,
            &body_digest,
            self.body.len(),
            self.provenance,
        ));
        CloudBuildResponseReceipt {
            status_code: self.status_code,
            body_digest,
            body_bytes: self.body.len(),
            response_digest,
        }
    }

    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudBuildReadRequest {
    pub operation: CloudBuildOperation,
    pub method: String,
    pub path: String,
    pub project_id: ProjectId,
    pub location: Location,
    pub build_id: Option<BuildId>,
    pub page_size: Option<u16>,
    page_token: Option<OpaquePageToken>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
}

impl Serialize for CloudBuildReadRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CloudBuildReadRequest", 13)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("projectId", &self.project_id)?;
        state.serialize_field("location", &self.location)?;
        state.serialize_field("buildId", &self.build_id)?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field(
            "pageTokenDigest",
            &self.page_token.as_ref().map(OpaquePageToken::digest),
        )?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

impl CloudBuildReadRequest {
    pub fn list(
        scope: &GcpCloudBuildScope,
        provider_digest: Digest,
        registration_digest: Digest,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::OutsideBound {
                field: "Cloud Build page size",
            });
        }
        Self::build(
            CloudBuildOperation::List,
            scope,
            provider_digest,
            registration_digest,
            None,
            Some(page_size),
            page_token,
        )
    }

    pub fn get(
        scope: &GcpCloudBuildScope,
        provider_digest: Digest,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        let build_id = scope
            .build_selector
            .build_id()
            .cloned()
            .ok_or(ModelError::InvalidProviderPayload)?;
        Self::build(
            CloudBuildOperation::Get,
            scope,
            provider_digest,
            registration_digest,
            Some(build_id),
            None,
            None,
        )
    }

    fn build(
        operation: CloudBuildOperation,
        scope: &GcpCloudBuildScope,
        provider_digest: Digest,
        registration_digest: Digest,
        build_id: Option<BuildId>,
        page_size: Option<u16>,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        let path = match &build_id {
            Some(build_id) => format!(
                "/{GCP_CLOUD_BUILD_API_VERSION}/projects/{}/builds/{build_id}",
                scope.gcp_project
            ),
            None => format!(
                "/{GCP_CLOUD_BUILD_API_VERSION}/projects/{}/builds",
                scope.gcp_project
            ),
        };
        let mut request = Self {
            operation,
            method: "GET".to_owned(),
            path,
            project_id: scope.gcp_project.clone(),
            location: scope.location.clone(),
            build_id,
            page_size,
            page_token,
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest(),
            registration_digest,
            request_digest: Digest::from_text("placeholder"),
        };
        request.request_digest = request.compute_digest(&provider_digest);
        Ok(request)
    }

    fn compute_digest(&self, provider_digest: &Digest) -> Digest {
        Digest::from_serializable(&(
            &self.operation,
            &self.method,
            &self.path,
            &self.project_id,
            &self.location,
            &self.build_id,
            &self.page_size,
            &self.page_token.as_ref().map(OpaquePageToken::digest),
            &self.scope_digest,
            &self.permission_digest,
            &self.registration_digest,
            provider_digest,
        ))
    }

    #[must_use]
    pub fn verify_digest(&self, provider_digest: &Digest) -> bool {
        self.request_digest == self.compute_digest(provider_digest)
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBuildReadProposal {
    pub operation: CloudBuildOperation,
    pub request: CloudBuildReadRequest,
    pub registration_digest: Digest,
    pub mission_revision: crate::Revision,
    pub proposal_digest: Digest,
}

impl CloudBuildReadProposal {
    pub fn new(request: CloudBuildReadRequest, mission_revision: crate::Revision) -> Self {
        let registration_digest = request.registration_digest.clone();
        let proposal_digest =
            Digest::from_serializable(&(&request, &registration_digest, mission_revision));
        Self {
            operation: request.operation,
            request,
            registration_digest,
            mission_revision,
            proposal_digest,
        }
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.proposal_digest
            == Digest::from_serializable(&(
                &self.request,
                &self.registration_digest,
                self.mission_revision,
            ))
    }

    #[must_use]
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn request(&self) -> &CloudBuildReadRequest {
        &self.request
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudBuildReadRecord {
    pub operation: CloudBuildOperation,
    pub request: CloudBuildReadRequest,
    pub builds: Vec<CloudBuildSummary>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response: CloudBuildResponseReceipt,
    pub registration_digest: Digest,
    pub record_digest: Digest,
}

impl CloudBuildReadRecord {
    fn new(
        request: CloudBuildReadRequest,
        builds: Vec<CloudBuildSummary>,
        next_page_token: Option<OpaquePageToken>,
        response: CloudBuildResponseReceipt,
    ) -> Self {
        let registration_digest = request.registration_digest.clone();
        let mut record = Self {
            operation: request.operation,
            request,
            builds,
            next_page_token,
            response,
            registration_digest,
            record_digest: Digest::from_text("placeholder"),
        };
        record.record_digest = record.compute_digest();
        record
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.operation,
            &self.request,
            &self.builds,
            &self.next_page_token.as_ref().map(OpaquePageToken::digest),
            &self.response,
            &self.registration_digest,
        ))
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.builds.iter().all(CloudBuildSummary::verify_digest)
            && self.record_digest == self.compute_digest()
    }

    #[must_use]
    pub fn record_digest(&self) -> &Digest {
        &self.record_digest
    }

    #[must_use]
    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }
}

pub trait GcpCloudBuildTransport: fmt::Debug {
    fn list_builds(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError>;

    fn get_build(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError>;

    fn provenance(&self) -> TransportProvenance;
}

pub struct GcpCloudBuildProvider<T>
where
    T: GcpCloudBuildTransport,
{
    scope: GcpCloudBuildScope,
    secret_reference: SecretReference,
    definition: GcpCloudBuildProviderDefinition,
    transport: T,
}

impl<T> fmt::Debug for GcpCloudBuildProvider<T>
where
    T: GcpCloudBuildTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudBuildProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider_digest", &self.definition.provider_digest())
            .field("provenance", &self.definition.provenance)
            .finish_non_exhaustive()
    }
}

impl<T> GcpCloudBuildProvider<T>
where
    T: GcpCloudBuildTransport,
{
    pub fn new(
        scope: GcpCloudBuildScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderDefinitionError> {
        scope.validate()?;
        if secret_reference.is_revoked()
            || secret_reference
                .scope_digest()
                .is_some_and(|digest| digest != &scope.scope_digest())
        {
            return Err(ProviderDefinitionError::Model(ModelError::InvalidConsent));
        }
        let definition = GcpCloudBuildProviderDefinition::new(transport.provenance())?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            transport,
        })
    }

    pub fn layer1(
        scope: GcpCloudBuildScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(scope, secret_reference, transport)
    }

    #[must_use]
    pub fn scope(&self) -> &GcpCloudBuildScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &GcpCloudBuildProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn list(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildReadRecord, GcpCloudBuildProviderError> {
        self.read(request, CloudBuildOperation::List)
    }

    pub fn get(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildReadRecord, GcpCloudBuildProviderError> {
        self.read(request, CloudBuildOperation::Get)
    }

    fn read(
        &mut self,
        request: &CloudBuildReadRequest,
        operation: CloudBuildOperation,
    ) -> Result<CloudBuildReadRecord, GcpCloudBuildProviderError> {
        self.validate_request(request, operation)?;
        if self.secret_reference.is_revoked() {
            return Err(GcpCloudBuildProviderError::failure(
                ProviderFailureClass::BlockedEnv,
                None,
                None,
                self.provenance(),
            ));
        }
        let response = match operation {
            CloudBuildOperation::List => self.transport.list_builds(request),
            CloudBuildOperation::Get => self.transport.get_build(request),
        }?;
        if response.body().len() > MAX_RESPONSE_BYTES {
            return Err(GcpCloudBuildProviderError::failure(
                ProviderFailureClass::Malformed,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance(),
            ));
        }
        if !(200..300).contains(&response.status_code) {
            return Err(GcpCloudBuildProviderError::failure(
                ProviderFailureClass::from_status(response.status_code)
                    .unwrap_or(ProviderFailureClass::Server),
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance(),
            ));
        }
        let mut receipt = response.receipt();
        let parsed = match operation {
            CloudBuildOperation::List => parse_list_payload(response.body(), request),
            CloudBuildOperation::Get => parse_get_payload(response.body(), request),
        }
        .map_err(|error| {
            GcpCloudBuildProviderError::failure(
                if error == ModelError::ScopeDrift {
                    ProviderFailureClass::ScopeDrift
                } else {
                    ProviderFailureClass::Malformed
                },
                Some(response.status_code),
                Some(receipt.body_digest.clone()),
                response.provenance(),
            )
            .with_diagnostic(error)
        })?;
        receipt.response_digest = Digest::from_serializable(&(
            receipt.status_code,
            &parsed.builds,
            &parsed.next_page_token.as_ref().map(OpaquePageToken::digest),
        ));
        Ok(CloudBuildReadRecord::new(
            request.clone(),
            parsed.builds,
            parsed.next_page_token,
            receipt,
        ))
    }

    fn validate_request(
        &self,
        request: &CloudBuildReadRequest,
        operation: CloudBuildOperation,
    ) -> Result<(), GcpCloudBuildProviderError> {
        if request.operation != operation
            || request.method != "GET"
            || request.project_id != self.scope.gcp_project
            || request.location != self.scope.location
            || request.scope_digest != self.scope.scope_digest()
            || request.permission_digest != self.scope.permission_digest()
            || !request.verify_digest(&self.provider_digest())
        {
            return Err(GcpCloudBuildProviderError::failure(
                ProviderFailureClass::RequestTampered,
                None,
                None,
                self.provenance(),
            ));
        }
        match operation {
            CloudBuildOperation::List if request.page_size.is_none() => Err(
                GcpCloudBuildProviderError::InvalidRequest(ModelError::InvalidProviderPayload),
            ),
            CloudBuildOperation::Get if request.build_id.is_none() => Err(
                GcpCloudBuildProviderError::InvalidRequest(ModelError::InvalidProviderPayload),
            ),
            CloudBuildOperation::List | CloudBuildOperation::Get => Ok(()),
        }
    }
}

impl GcpCloudBuildProviderError {
    fn with_diagnostic(self, error: ModelError) -> Self {
        match self {
            Self::Failure {
                class,
                status_code,
                response_digest,
                provenance,
                ..
            } => Self::Failure {
                class,
                status_code,
                response_digest,
                diagnostic_digest: Digest::from_text(error.to_string()),
                provenance,
            },
            other @ Self::InvalidRequest(_) => other,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureGcpCloudBuildTransport {
    builds: Vec<CloudBuildSummary>,
    list_responses: VecDeque<Result<CloudBuildResponse, GcpCloudBuildProviderError>>,
    get_responses: VecDeque<Result<CloudBuildResponse, GcpCloudBuildProviderError>>,
    requests: Vec<CloudBuildReadRequest>,
}

impl FixtureGcpCloudBuildTransport {
    pub fn new(builds: impl IntoIterator<Item = CloudBuildSummary>) -> Self {
        Self {
            builds: builds.into_iter().collect(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn from_response(response: CloudBuildResponse) -> Self {
        let mut transport = Self::default();
        transport.list_responses.push_back(Ok(response.clone()));
        transport.get_responses.push_back(Ok(response));
        transport
    }

    pub fn push_response(&mut self, response: CloudBuildResponse) {
        self.list_responses.push_back(Ok(response.clone()));
        self.get_responses.push_back(Ok(response));
    }

    pub fn push_list_response(&mut self, response: CloudBuildResponse) {
        self.list_responses.push_back(Ok(response));
    }

    pub fn push_get_response(&mut self, response: CloudBuildResponse) {
        self.get_responses.push_back(Ok(response));
    }

    pub fn push_failure(&mut self, error: GcpCloudBuildProviderError) {
        self.list_responses.push_back(Err(error.clone()));
        self.get_responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[CloudBuildReadRequest] {
        &self.requests
    }

    #[must_use]
    pub fn builds(&self) -> &[CloudBuildSummary] {
        &self.builds
    }
}

impl GcpCloudBuildTransport for FixtureGcpCloudBuildTransport {
    fn list_builds(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        self.requests.push(request.clone());
        if let Some(response) = self.list_responses.pop_front() {
            return response;
        }
        let page_number = request
            .page_token
            .as_ref()
            .and_then(|token| token.value.strip_prefix("fixture-page-"))
            .and_then(|page| page.parse::<usize>().ok())
            .unwrap_or(0);
        let page_size = request.page_size.unwrap_or(MAX_PAGE_SIZE) as usize;
        let start = page_number.saturating_mul(page_size);
        let end = (start + page_size).min(self.builds.len());
        let page = if start < self.builds.len() {
            self.builds[start..end].to_vec()
        } else {
            Vec::new()
        };
        let next_page_token = (end < self.builds.len())
            .then(|| format!("fixture-page-{}", page_number.saturating_add(1)));
        let value = json!({
            "builds": page,
            "nextPageToken": next_page_token,
        });
        Ok(CloudBuildResponse::json_with_provenance(
            200,
            &value,
            TransportProvenance::Fixture,
        ))
    }

    fn get_build(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        self.requests.push(request.clone());
        if let Some(response) = self.get_responses.pop_front() {
            return response;
        }
        let Some(build_id) = request.build_id.as_ref() else {
            return Err(GcpCloudBuildProviderError::failure(
                ProviderFailureClass::Malformed,
                None,
                None,
                TransportProvenance::Fixture,
            ));
        };
        self.builds
            .iter()
            .find(|build| &build.build_id == build_id)
            .map_or_else(
                || {
                    Ok(CloudBuildResponse::json_with_provenance(
                        404,
                        &json!({"message":"fixture build not found"}),
                        TransportProvenance::Fixture,
                    ))
                },
                |build| {
                    Ok(CloudBuildResponse::json_with_provenance(
                        200,
                        build,
                        TransportProvenance::Fixture,
                    ))
                },
            )
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }
}

pub type FakeGcpCloudBuildTransport = FixtureGcpCloudBuildTransport;

#[derive(Clone, Debug, Default)]
pub struct RecordingGcpCloudBuildTransport {
    list_responses: VecDeque<Result<CloudBuildResponse, GcpCloudBuildProviderError>>,
    get_responses: VecDeque<Result<CloudBuildResponse, GcpCloudBuildProviderError>>,
    requests: Vec<CloudBuildReadRequest>,
}

impl RecordingGcpCloudBuildTransport {
    #[must_use]
    pub fn new(response: CloudBuildResponse) -> Self {
        let mut transport = Self::default();
        transport.push_list_response(response.clone());
        transport.push_get_response(response);
        transport
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn push_list_response(&mut self, response: CloudBuildResponse) {
        self.list_responses.push_back(Ok(response));
    }

    pub fn push_get_response(&mut self, response: CloudBuildResponse) {
        self.get_responses.push_back(Ok(response));
    }

    pub fn push_list_failure(&mut self, error: GcpCloudBuildProviderError) {
        self.list_responses.push_back(Err(error));
    }

    pub fn push_get_failure(&mut self, error: GcpCloudBuildProviderError) {
        self.get_responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[CloudBuildReadRequest] {
        &self.requests
    }

    #[must_use]
    pub fn remaining_list_responses(&self) -> usize {
        self.list_responses.len()
    }

    #[must_use]
    pub fn remaining_get_responses(&self) -> usize {
        self.get_responses.len()
    }
}

impl GcpCloudBuildTransport for RecordingGcpCloudBuildTransport {
    fn list_builds(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        self.requests.push(request.clone());
        self.list_responses.pop_front().unwrap_or_else(|| {
            Err(GcpCloudBuildProviderError::failure(
                ProviderFailureClass::Malformed,
                None,
                None,
                TransportProvenance::Recording,
            ))
        })
    }

    fn get_build(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        self.requests.push(request.clone());
        self.get_responses.pop_front().unwrap_or_else(|| {
            Err(GcpCloudBuildProviderError::failure(
                ProviderFailureClass::Malformed,
                None,
                None,
                TransportProvenance::Recording,
            ))
        })
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }
}

pub type RecordingTransport = RecordingGcpCloudBuildTransport;

#[derive(Clone, Debug, Default)]
pub struct LoopbackGcpCloudBuildTransport {
    inner: FixtureGcpCloudBuildTransport,
}

impl LoopbackGcpCloudBuildTransport {
    pub fn new(builds: impl IntoIterator<Item = CloudBuildSummary>) -> Self {
        Self {
            inner: FixtureGcpCloudBuildTransport::new(builds),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[CloudBuildReadRequest] {
        self.inner.requests()
    }
}

impl GcpCloudBuildTransport for LoopbackGcpCloudBuildTransport {
    fn list_builds(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        self.inner
            .list_builds(request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }

    fn get_build(
        &mut self,
        request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        self.inner
            .get_build(request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
}

pub type LoopbackTransport = LoopbackGcpCloudBuildTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpCloudBuildTransport;

impl GcpCloudBuildTransport for BlockedEnvGcpCloudBuildTransport {
    fn list_builds(
        &mut self,
        _request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        Err(GcpCloudBuildProviderError::failure(
            ProviderFailureClass::BlockedEnv,
            None,
            None,
            TransportProvenance::BlockedEnv,
        ))
    }

    fn get_build(
        &mut self,
        _request: &CloudBuildReadRequest,
    ) -> Result<CloudBuildResponse, GcpCloudBuildProviderError> {
        Err(GcpCloudBuildProviderError::failure(
            ProviderFailureClass::BlockedEnv,
            None,
            None,
            TransportProvenance::BlockedEnv,
        ))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

pub type BlockedEnvTransport = BlockedEnvGcpCloudBuildTransport;

pub fn fake_page_token_for_page(page: u16) -> Result<OpaquePageToken, ModelError> {
    OpaquePageToken::new(format!("fixture-page-{page}"))
}

fn parse_list_payload(
    body: &[u8],
    request: &CloudBuildReadRequest,
) -> Result<ParsedPayload, ModelError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| ModelError::InvalidProviderPayload)?;
    let object = value
        .as_object()
        .ok_or(ModelError::InvalidProviderPayload)?;
    let values = object
        .get("builds")
        .and_then(Value::as_array)
        .ok_or(ModelError::InvalidProviderPayload)?;
    if values.len() > MAX_BUILDS {
        return Err(ModelError::OutsideBound {
            field: "builds per response",
        });
    }
    let mut builds = Vec::with_capacity(values.len());
    for value in values {
        builds.push(parse_build(value, request)?);
    }
    let next_page_token = object
        .get("nextPageToken")
        .and_then(Value::as_str)
        .map(OpaquePageToken::new)
        .transpose()?;
    Ok(ParsedPayload {
        builds,
        next_page_token,
    })
}

fn parse_get_payload(
    body: &[u8],
    request: &CloudBuildReadRequest,
) -> Result<ParsedPayload, ModelError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| ModelError::InvalidProviderPayload)?;
    let build_value = value.get("build").unwrap_or(&value);
    let build = parse_build(build_value, request)?;
    if request.build_id.as_ref() != Some(&build.build_id) {
        return Err(ModelError::ScopeDrift);
    }
    Ok(ParsedPayload {
        builds: vec![build],
        next_page_token: None,
    })
}

struct ParsedPayload {
    builds: Vec<CloudBuildSummary>,
    next_page_token: Option<OpaquePageToken>,
}

fn parse_build(
    value: &Value,
    request: &CloudBuildReadRequest,
) -> Result<CloudBuildSummary, ModelError> {
    let object = value
        .as_object()
        .ok_or(ModelError::InvalidProviderPayload)?;
    let build_id = BuildId::new(
        object
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ModelError::InvalidProviderPayload)?,
    )?;
    let project_id = ProjectId::new(
        object
            .get("projectId")
            .and_then(Value::as_str)
            .unwrap_or(request.project_id.as_str()),
    )?;
    if project_id != request.project_id {
        return Err(ModelError::ScopeDrift);
    }
    if let Some(location) = object
        .get("location")
        .or_else(|| object.get("region"))
        .and_then(Value::as_str)
        && location != request.location.as_str()
    {
        return Err(ModelError::ScopeDrift);
    }
    let trigger_id = object
        .get("triggerId")
        .and_then(Value::as_str)
        .map(TriggerIdForParse::parse)
        .transpose()?;
    let (source_repository, source_commit) = parse_source(object)?;
    let status = CloudBuildStatus::parse(object.get("status").and_then(Value::as_str));
    let duration_seconds = parse_duration(object)?;
    let artifact_metadata = parse_artifacts(object)?;
    let step_digests = parse_steps(object)?;
    CloudBuildSummary::new(
        build_id,
        project_id,
        request.location.clone(),
        trigger_id,
        source_repository,
        source_commit,
        status,
        duration_seconds,
        artifact_metadata,
        step_digests,
    )
}

struct TriggerIdForParse;

impl TriggerIdForParse {
    fn parse(value: &str) -> Result<crate::TriggerId, ModelError> {
        crate::TriggerId::new(value)
    }
}

fn parse_source(
    object: &serde_json::Map<String, Value>,
) -> Result<(Option<SourceRepository>, Option<SourceCommit>), ModelError> {
    let source = object.get("source").and_then(Value::as_object);
    let repo_source = source
        .and_then(|value| value.get("repoSource"))
        .and_then(Value::as_object);
    let git_source = source
        .and_then(|value| value.get("gitSource"))
        .and_then(Value::as_object);
    let repository = repo_source
        .and_then(|value| value.get("repoName").or_else(|| value.get("url")))
        .or_else(|| git_source.and_then(|value| value.get("url")))
        .and_then(Value::as_str)
        .map(SourceRepository::new)
        .transpose()?;
    let resolved_commit = object
        .get("sourceProvenance")
        .and_then(Value::as_object)
        .and_then(|value| value.get("resolvedRepoSource"))
        .and_then(Value::as_object)
        .and_then(|value| value.get("commitSha"))
        .and_then(Value::as_str);
    let commit = repo_source
        .and_then(|value| value.get("commitSha").or_else(|| value.get("revision")))
        .or_else(|| git_source.and_then(|value| value.get("revision")))
        .and_then(Value::as_str)
        .or(resolved_commit)
        .map(SourceCommit::new)
        .transpose()?;
    Ok((repository, commit))
}

fn parse_duration(object: &serde_json::Map<String, Value>) -> Result<Option<u64>, ModelError> {
    let start = object.get("startTime").and_then(Value::as_str);
    let finish = object.get("finishTime").and_then(Value::as_str);
    match (start, finish) {
        (Some(start), Some(finish)) => {
            let start = parse_timestamp(start).ok_or(ModelError::InvalidTiming)?;
            let finish = parse_timestamp(finish).ok_or(ModelError::InvalidTiming)?;
            let seconds = finish.signed_duration_since(start).num_seconds();
            if seconds < 0 {
                return Err(ModelError::InvalidTiming);
            }
            Ok(Some(seconds as u64))
        }
        _ => Ok(None),
    }
}

fn parse_timestamp(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

fn parse_steps(
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<BuildStepDigest>, ModelError> {
    let Some(steps) = object.get("steps") else {
        return Ok(Vec::new());
    };
    let steps = steps.as_array().ok_or(ModelError::InvalidProviderPayload)?;
    if steps.len() > MAX_STEPS_PER_BUILD {
        return Err(ModelError::OutsideBound {
            field: "steps per build",
        });
    }
    steps
        .iter()
        .enumerate()
        .map(|(ordinal, step)| {
            let step_object = step.as_object().ok_or(ModelError::InvalidProviderPayload)?;
            let status =
                CloudBuildStepStatus::parse(step_object.get("status").and_then(Value::as_str));
            let name = step_object
                .get("id")
                .or_else(|| step_object.get("name"))
                .and_then(Value::as_str);
            BuildStepDigest::from_safe_fields(ordinal, status, name, step_object.get("results"))
        })
        .collect()
}

fn parse_artifacts(
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<ArtifactMetadata>, ModelError> {
    let mut artifacts = Vec::new();
    if let Some(images) = object.get("images").and_then(Value::as_array) {
        for image in images {
            if let Some(reference) = image.as_str() {
                artifacts.push(ArtifactMetadata::new(
                    ArtifactKind::ContainerImage,
                    reference,
                    None,
                )?);
            }
        }
    }
    if let Some(results) = object.get("results").and_then(Value::as_object)
        && let Some(images) = results.get("images").and_then(Value::as_array)
    {
        for image in images {
            let Some(image) = image.as_object() else {
                continue;
            };
            let reference = image
                .get("name")
                .or_else(|| image.get("digest"))
                .and_then(Value::as_str);
            if let Some(reference) = reference {
                artifacts.push(ArtifactMetadata::new(
                    ArtifactKind::ContainerImage,
                    reference,
                    image.get("sizeBytes").and_then(Value::as_u64),
                )?);
            }
        }
    }
    if let Some(artifact_root) = object.get("artifacts").and_then(Value::as_object)
        && let Some(objects) = artifact_root.get("objects").and_then(Value::as_array)
    {
        for artifact in objects {
            let Some(artifact) = artifact.as_object() else {
                continue;
            };
            if let Some(reference) = artifact
                .get("location")
                .or_else(|| artifact.get("name"))
                .and_then(Value::as_str)
            {
                artifacts.push(ArtifactMetadata::new(
                    ArtifactKind::Object,
                    reference,
                    artifact.get("sizeBytes").and_then(Value::as_u64),
                )?);
            }
        }
    }
    if artifacts.len() > MAX_ARTIFACTS_PER_BUILD {
        return Err(ModelError::OutsideBound {
            field: "artifacts per build",
        });
    }
    Ok(artifacts)
}

pub fn provider_failure_projection(error: &GcpCloudBuildProviderError) -> EvidenceState {
    error.evidence_state()
}

pub fn permission_names() -> [&'static str; 2] {
    ["cloudbuild.builds.list", "cloudbuild.builds.get"]
}

pub fn project_digest(project: &ProjectId) -> Digest {
    project.digest()
}

pub fn build_selector_digest(selector: &BuildSelector) -> Digest {
    selector.digest()
}

pub fn build_status_digest(status: CloudBuildStatus) -> Digest {
    Digest::from_text(status.as_str())
}
