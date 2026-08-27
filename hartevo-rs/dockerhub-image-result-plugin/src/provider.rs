use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;

use crate::error::{DockerHubImageResultError, DockerHubTransportError, Result};
use crate::model::{
    CostReceipt, Digest, DockerHubImageResultProjection, DockerHubImageResultScope,
    DockerHubPlatformImage, DockerHubTagStatus, ImmutableDigest, PlatformTuple, RequestReceipt,
    SecretReference, TransportProvenance,
};
use crate::{API_REVISION, MAX_LAYERS_PER_IMAGE, MAX_RESPONSE_BYTES, PLUGIN_VERSION, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum DockerHubOperation {
    ReadRepositoryTag,
}

impl DockerHubOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadRepositoryTag => "ReadRepositoryTag",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedDockerHubRequest {
    pub operation: DockerHubOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub redacted: bool,
}

impl RecordedDockerHubRequest {
    pub fn receipt(&self) -> Result<RequestReceipt> {
        self.validate()?;
        RequestReceipt::new(
            self.operation.as_str(),
            self.request_digest.clone(),
            self.path_digest.clone(),
            self.scope_digest.clone(),
        )
    }

    fn validate(&self) -> Result<()> {
        if !self.redacted {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.path_digest.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DockerHubTagRequest {
    scope: DockerHubImageResultScope,
    request_digest: Digest,
    path_digest: Digest,
    max_response_bytes: u64,
}

impl DockerHubTagRequest {
    pub fn new(scope: &DockerHubImageResultScope, max_response_bytes: u64) -> Result<Self> {
        scope.validate()?;
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(DockerHubImageResultError::InvalidRequest);
        }
        let path_digest = Digest::from_parts(
            "dockerhub-tag-path/v1",
            &[
                ("namespace", scope.namespace().digest().as_str().to_owned()),
                (
                    "repository",
                    scope.repository().digest().as_str().to_owned(),
                ),
                ("tag", scope.tag().digest().as_str().to_owned()),
            ],
        );
        let request_digest = Digest::from_parts(
            "dockerhub-tag-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("path", path_digest.as_str().to_owned()),
                ("max_response_bytes", max_response_bytes.to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            request_digest,
            path_digest,
            max_response_bytes,
        })
    }

    pub fn scope(&self) -> &DockerHubImageResultScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_digest(&self) -> &Digest {
        &self.path_digest
    }

    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    pub fn path_template(&self) -> &'static str {
        "/v2/namespaces/{namespace}/repositories/{repository}/tags/{tag}"
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/v2/namespaces/{}/repositories/{}/tags/{}",
            &self.scope.namespace().digest().as_str()[..16],
            &self.scope.repository().digest().as_str()[..16],
            &self.scope.tag().digest().as_str()[..16],
        )
    }

    pub fn recorded_request(&self) -> RecordedDockerHubRequest {
        RecordedDockerHubRequest {
            operation: DockerHubOperation::ReadRepositoryTag,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest.clone(),
            redacted: true,
        }
    }
}

impl fmt::Debug for DockerHubTagRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerHubTagRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .field("path_digest", &self.path_digest)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SafeImageRecord {
    immutable_digest: ImmutableDigest,
    platform: PlatformTuple,
    image_size_bytes: u64,
    layer_count: u16,
    layer_size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SafeTagRecord {
    tag_name_digest: Digest,
    status: DockerHubTagStatus,
    last_updated: DateTime<Utc>,
    tag_manifest_identity: Option<ImmutableDigest>,
    images: Vec<SafeImageRecord>,
    full_size_bytes: Option<u64>,
    normalized_digest: Digest,
}

impl SafeTagRecord {
    fn normalized_digest(
        tag_name_digest: &Digest,
        status: DockerHubTagStatus,
        last_updated: DateTime<Utc>,
        tag_manifest_identity: Option<&ImmutableDigest>,
        images: &[SafeImageRecord],
        full_size_bytes: Option<u64>,
    ) -> Digest {
        Digest::from_parts(
            "dockerhub-safe-tag-record/v1",
            &[
                ("tag_name", tag_name_digest.as_str().to_owned()),
                ("status", format!("{status:?}")),
                ("last_updated", last_updated.to_rfc3339()),
                (
                    "tag_manifest",
                    tag_manifest_identity.map_or_else(String::new, |value| {
                        value.deterministic_digest().as_str().to_owned()
                    }),
                ),
                (
                    "images",
                    images
                        .iter()
                        .map(|image| {
                            Digest::from_parts(
                                "dockerhub-safe-image/v1",
                                &[
                                    (
                                        "digest",
                                        image
                                            .immutable_digest
                                            .deterministic_digest()
                                            .as_str()
                                            .to_owned(),
                                    ),
                                    ("platform", image.platform.digest().as_str().to_owned()),
                                    ("size", image.image_size_bytes.to_string()),
                                    ("layers", image.layer_count.to_string()),
                                    ("layer_size", image.layer_size_bytes.to_string()),
                                ],
                            )
                            .as_str()
                            .to_owned()
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "full_size",
                    full_size_bytes.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DockerHubTagResponse {
    status_code: u16,
    response_bytes: u64,
    record: Option<SafeTagRecord>,
    response_digest: Digest,
    declared_digest: Option<Digest>,
}

impl DockerHubTagResponse {
    pub fn json(status_code: u16, payload: &Value) -> Result<Self> {
        let serialized =
            serde_json::to_vec(payload).map_err(|_| DockerHubImageResultError::InvalidResponse)?;
        let response_bytes = serialized.len() as u64;
        if status_code != 200 {
            return Ok(Self {
                status_code,
                response_bytes,
                record: None,
                response_digest: Digest::from_parts(
                    "dockerhub-error-response/v1",
                    &[
                        ("status", status_code.to_string()),
                        ("bytes", response_bytes.to_string()),
                    ],
                ),
                declared_digest: None,
            });
        }
        let record = parse_safe_tag(payload)?;
        let response_digest = record.normalized_digest.clone();
        Ok(Self {
            status_code,
            response_bytes,
            record: Some(record),
            response_digest,
            declared_digest: None,
        })
    }

    pub fn from_json(status_code: u16, payload: &Value) -> Result<Self> {
        Self::json(status_code, payload)
    }

    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.declared_digest = Some(digest);
        self
    }

    pub fn request_receipt(&self, request: &DockerHubTagRequest) -> Result<RequestReceipt> {
        request.recorded_request().receipt()
    }

    pub fn cost_receipt(&self) -> Result<CostReceipt> {
        CostReceipt::new(
            DockerHubOperation::ReadRepositoryTag.as_str(),
            self.response_bytes,
        )
    }

    pub fn is_success(&self) -> bool {
        self.status_code == 200
    }

    pub(crate) fn validate_integrity(&self, request: &DockerHubTagRequest) -> Result<()> {
        if self.response_bytes > request.max_response_bytes() {
            return Err(DockerHubImageResultError::PartialEvidence);
        }
        if self
            .declared_digest
            .as_ref()
            .is_some_and(|declared| declared != &self.response_digest)
        {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        if self.status_code != 200 {
            return Ok(());
        }
        let record = self
            .record
            .as_ref()
            .ok_or(DockerHubImageResultError::InvalidResponse)?;
        if record.tag_name_digest != request.scope().tag().digest() {
            return Err(DockerHubImageResultError::ScopeMismatch);
        }
        if record.images.is_empty() {
            return Err(DockerHubImageResultError::InvalidResponse);
        }
        for image in &record.images {
            if !request.scope().platform_scope().allows(&image.platform) {
                return Err(DockerHubImageResultError::PlatformDrift);
            }
        }
        if let Some(expected) = request.scope().expected_manifest_identity() {
            let matches_tag = record
                .tag_manifest_identity
                .as_ref()
                .is_some_and(|identity| identity == expected);
            let matches_image = record
                .images
                .iter()
                .any(|image| &image.immutable_digest == expected);
            if !matches_tag && !matches_image {
                return Err(DockerHubImageResultError::ManifestDrift);
            }
        }
        Ok(())
    }

    pub(crate) fn projection(
        &self,
        request: &DockerHubTagRequest,
    ) -> Result<DockerHubImageResultProjection> {
        self.validate_integrity(request)?;
        let record = self
            .record
            .as_ref()
            .ok_or(DockerHubImageResultError::InvalidResponse)?;
        let images = record
            .images
            .iter()
            .map(|image| DockerHubPlatformImage {
                immutable_digest: image.immutable_digest.clone(),
                platform: image.platform.clone(),
                image_size_bytes: image.image_size_bytes,
                layer_count: image.layer_count,
                layer_size_bytes: image.layer_size_bytes,
            })
            .collect();
        DockerHubImageResultProjection::new(
            record.status,
            record.last_updated,
            record.tag_manifest_identity.clone(),
            images,
            record.full_size_bytes,
        )
    }
}

impl fmt::Debug for DockerHubTagResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerHubTagResponse")
            .field("status_code", &self.status_code)
            .field("response_bytes", &self.response_bytes)
            .field("response_digest", &self.response_digest)
            .field("has_projection", &self.record.is_some())
            .finish()
    }
}

fn parse_safe_tag(payload: &Value) -> Result<SafeTagRecord> {
    let object = payload
        .as_object()
        .ok_or(DockerHubImageResultError::InvalidResponse)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DockerHubImageResultError::InvalidResponse)?;
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .map_or(DockerHubTagStatus::Unknown, DockerHubTagStatus::parse);
    let last_updated = object
        .get("last_updated")
        .and_then(Value::as_str)
        .ok_or(DockerHubImageResultError::InvalidResponse)
        .and_then(parse_timestamp)?;
    let tag_manifest_identity = object
        .get("digest")
        .or_else(|| object.get("manifest_digest"))
        .and_then(Value::as_str)
        .map(ImmutableDigest::new)
        .transpose()?;
    let full_size_bytes = object.get("full_size").and_then(Value::as_u64);
    let raw_images = match object.get("images") {
        Some(Value::Array(values)) => values.clone(),
        Some(Value::Object(value)) => vec![Value::Object(value.clone())],
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err(DockerHubImageResultError::InvalidResponse),
    };
    if raw_images.len() > crate::MAX_IMAGES {
        return Err(DockerHubImageResultError::PartialEvidence);
    }
    let mut images = Vec::with_capacity(raw_images.len());
    for raw_image in raw_images {
        images.push(parse_safe_image(&raw_image)?);
    }
    images.sort_by_key(|image| {
        (
            image.platform.clone(),
            image.immutable_digest.clone(),
            image.image_size_bytes,
        )
    });
    let tag_name_digest = Digest::from_parts("dockerhub-tag/v1", &[("value", name.to_owned())]);
    let normalized_digest = SafeTagRecord::normalized_digest(
        &tag_name_digest,
        status,
        last_updated,
        tag_manifest_identity.as_ref(),
        &images,
        full_size_bytes,
    );
    Ok(SafeTagRecord {
        tag_name_digest,
        status,
        last_updated,
        tag_manifest_identity,
        images,
        full_size_bytes,
        normalized_digest,
    })
}

fn parse_safe_image(value: &Value) -> Result<SafeImageRecord> {
    let object = value
        .as_object()
        .ok_or(DockerHubImageResultError::InvalidResponse)?;
    let immutable_digest = object
        .get("digest")
        .and_then(Value::as_str)
        .ok_or(DockerHubImageResultError::InvalidResponse)
        .and_then(ImmutableDigest::new)?;
    let nested_platform = object.get("platform").and_then(Value::as_object);
    let os = object
        .get("os")
        .and_then(Value::as_str)
        .or_else(|| nested_platform.and_then(|platform| platform.get("os").and_then(Value::as_str)))
        .ok_or(DockerHubImageResultError::InvalidResponse)?;
    let architecture = object
        .get("architecture")
        .and_then(Value::as_str)
        .or_else(|| {
            nested_platform
                .and_then(|platform| platform.get("architecture").and_then(Value::as_str))
        })
        .ok_or(DockerHubImageResultError::InvalidResponse)?;
    let variant = object
        .get("variant")
        .and_then(Value::as_str)
        .or_else(|| {
            nested_platform.and_then(|platform| platform.get("variant").and_then(Value::as_str))
        })
        .map(str::to_owned);
    let platform = PlatformTuple::new(os, architecture, variant)?;
    let image_size_bytes = object
        .get("size")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let (layer_count, layer_size_bytes) = match object.get("layers") {
        Some(Value::Array(layers)) => {
            if layers.len() > MAX_LAYERS_PER_IMAGE {
                return Err(DockerHubImageResultError::PartialEvidence);
            }
            let mut total = 0_u64;
            for layer in layers {
                let size = layer
                    .get("size")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                total = total
                    .checked_add(size)
                    .ok_or(DockerHubImageResultError::PartialEvidence)?;
            }
            (layers.len() as u16, total)
        }
        Some(Value::Null) | None => (0, 0),
        Some(_) => return Err(DockerHubImageResultError::InvalidResponse),
    };
    Ok(SafeImageRecord {
        immutable_digest,
        platform,
        image_size_bytes,
        layer_count,
        layer_size_bytes,
    })
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|date| date.with_timezone(&Utc))
        .map_err(|_| DockerHubImageResultError::InvalidResponse)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerHubProviderDefinition {
    pub provider_id: String,
    pub api_revision: String,
    pub release: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_snapshot: crate::model::PermissionSnapshot,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub external_writes: bool,
}

impl DockerHubProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() {
            return Err(DockerHubImageResultError::ProviderDrift);
        }
        let permission_snapshot = crate::model::PermissionSnapshot::layer1();
        let api_digest = Digest::from_parts(
            "dockerhub-api-revision/v1",
            &[("revision", API_REVISION.to_owned())],
        );
        let provider_digest = Digest::from_parts(
            "dockerhub-provider-definition/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("api", api_digest.as_str().to_owned()),
                ("release", release.clone()),
                ("revision", provider_revision.to_string()),
                (
                    "permissions",
                    permission_snapshot.digest().as_str().to_owned(),
                ),
            ],
        );
        let definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            release,
            provider_digest,
            api_digest,
            permission_snapshot,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            external_writes: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != API_REVISION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.external_writes
        {
            return Err(DockerHubImageResultError::ProviderDrift);
        }
        self.permission_snapshot.validate()?;
        self.api_digest.validate()?;
        self.provider_digest.validate()
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_snapshot(&self) -> &crate::model::PermissionSnapshot {
        &self.permission_snapshot
    }
}

impl Serialize for DockerHubProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("DockerHubProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.serialize_field("providerReceipt", &self.provider_receipt)?;
        state.end()
    }
}

pub trait DockerHubTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_repository_tag(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError>;
}

pub struct DockerHubProvider<T: DockerHubTransport> {
    scope: DockerHubImageResultScope,
    secret_reference: SecretReference,
    definition: DockerHubProviderDefinition,
    transport: T,
}

impl<T: DockerHubTransport> fmt::Debug for DockerHubProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerHubProvider")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: DockerHubTransport> DockerHubProvider<T> {
    pub fn new(
        scope: DockerHubImageResultScope,
        mut secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        scope.validate()?;
        if secret_reference.is_unbound() {
            secret_reference.bind_scope(&scope)?;
        } else {
            secret_reference.validate_against(&scope)?;
        }
        let definition = DockerHubProviderDefinition::new(1, PLUGIN_VERSION)?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            transport,
        })
    }

    pub fn scope(&self) -> &DockerHubImageResultScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn definition(&self) -> &DockerHubProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.definition.api_digest
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read_tag(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        if request.scope().digest() != self.scope.digest() {
            return Err(DockerHubTransportError::ScopeDrift);
        }
        if self.secret_reference.is_revoked() {
            return Err(DockerHubTransportError::AccessLost);
        }
        let response = self.transport.read_repository_tag(request)?;
        response
            .validate_integrity(request)
            .map_err(|error| match error {
                DockerHubImageResultError::PartialEvidence => DockerHubTransportError::Partial,
                DockerHubImageResultError::TamperedEvidence => DockerHubTransportError::Tampered,
                DockerHubImageResultError::ScopeMismatch
                | DockerHubImageResultError::ManifestDrift
                | DockerHubImageResultError::PlatformDrift => DockerHubTransportError::ScopeDrift,
                _ => DockerHubTransportError::InvalidResponse,
            })?;
        Ok(response)
    }

    pub fn read_repository_tag(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        self.read_tag(request)
    }

    pub fn read(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        self.read_tag(request)
    }

    pub fn revoke_secret(&mut self) {
        self.secret_reference.revoke();
    }
}

#[derive(Clone, Debug)]
pub struct FixtureDockerHubTransport {
    response: DockerHubTagResponse,
    requests: Vec<RecordedDockerHubRequest>,
}

impl FixtureDockerHubTransport {
    pub fn new(response: DockerHubTagResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    pub fn response(&self) -> &DockerHubTagResponse {
        &self.response
    }

    pub fn requests(&self) -> &[RecordedDockerHubRequest] {
        &self.requests
    }
}

impl DockerHubTransport for FixtureDockerHubTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_repository_tag(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        self.requests.push(request.recorded_request());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeDockerHubTransport {
    response: DockerHubTagResponse,
    requests: Vec<RecordedDockerHubRequest>,
}

impl FakeDockerHubTransport {
    pub fn new(response: DockerHubTagResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[RecordedDockerHubRequest] {
        &self.requests
    }
}

impl DockerHubTransport for FakeDockerHubTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read_repository_tag(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        self.requests.push(request.recorded_request());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackDockerHubTransport {
    response: DockerHubTagResponse,
    requests: Vec<RecordedDockerHubRequest>,
}

impl LoopbackDockerHubTransport {
    pub fn new(response: DockerHubTagResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[RecordedDockerHubRequest] {
        &self.requests
    }
}

impl DockerHubTransport for LoopbackDockerHubTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_repository_tag(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        self.requests.push(request.recorded_request());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingDockerHubTransport {
    responses: VecDeque<DockerHubTagResponse>,
    requests: Vec<RecordedDockerHubRequest>,
}

impl RecordingDockerHubTransport {
    pub fn new(response: DockerHubTagResponse) -> Self {
        Self {
            responses: VecDeque::from([response]),
            requests: Vec::new(),
        }
    }

    pub fn from_responses(responses: Vec<DockerHubTagResponse>) -> Self {
        Self {
            responses: responses.into(),
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[RecordedDockerHubRequest] {
        &self.requests
    }
}

impl DockerHubTransport for RecordingDockerHubTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_repository_tag(
        &mut self,
        request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        self.requests.push(request.recorded_request());
        self.responses
            .pop_front()
            .ok_or(DockerHubTransportError::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvDockerHubTransport;

impl DockerHubTransport for BlockedEnvDockerHubTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_repository_tag(
        &mut self,
        _request: &DockerHubTagRequest,
    ) -> std::result::Result<DockerHubTagResponse, DockerHubTransportError> {
        Err(DockerHubTransportError::BlockedEnv)
    }
}

pub type DockerHubRecordingTransport = RecordingDockerHubTransport;
pub type DockerHubFixtureTransport = FixtureDockerHubTransport;
pub type DockerHubLoopbackTransport = LoopbackDockerHubTransport;
