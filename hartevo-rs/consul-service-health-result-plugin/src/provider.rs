use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CONSUL_API_REVISION, CONSUL_API_VERSION, CONSUL_HEALTH_PROVIDER_ID,
    CONSUL_HEALTH_PROVIDER_NAME, CONSUL_HEALTH_PROVIDER_VERSION, SCHEMA_VERSION,
    model::{
        ConsulServiceHealthScope, Datacenter, Digest, ModelError, ReadBounds, Scope,
        api_binding_digest,
    },
};

pub const HEALTH_SERVICE_PATH: &str = "/v1/health/service/:service";
pub const CATALOG_SERVICE_PATH: &str = "/v1/catalog/service/:service";
pub const ACL_FILTERED_HEADER: &str = "X-Consul-Results-Filtered-By-ACLs";
pub const CONSUL_INDEX_HEADER: &str = "X-Consul-Index";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConsulReadOperation {
    #[serde(rename = "health-service")]
    HealthService,
    #[serde(rename = "catalog-service")]
    CatalogService,
}

impl ConsulReadOperation {
    pub const fn path(self) -> &'static str {
        match self {
            Self::HealthService => HEALTH_SERVICE_PATH,
            Self::CatalogService => CATALOG_SERVICE_PATH,
        }
    }

    pub const fn required_permission(self) -> &'static str {
        match self {
            Self::HealthService => "service:read",
            Self::CatalogService => "node:read",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryParameter {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulHttpRequest {
    pub operation: ConsulReadOperation,
    pub method: HttpMethod,
    pub path: String,
    pub query: Vec<QueryParameter>,
    pub headers: BTreeMap<String, String>,
    pub request_digest: Digest,
}

impl ConsulHttpRequest {
    fn new(operation: ConsulReadOperation, scope: &ConsulServiceHealthScope) -> Self {
        let mut query = vec![
            QueryParameter {
                name: "dc".to_owned(),
                value: scope.datacenter.as_str().to_owned(),
            },
            QueryParameter {
                name: "partition".to_owned(),
                value: scope.admin_partition.as_str().to_owned(),
            },
            QueryParameter {
                name: "ns".to_owned(),
                value: scope.namespace.as_str().to_owned(),
            },
        ];
        if let Some(tag) = &scope.tag {
            query.push(QueryParameter {
                name: "tag".to_owned(),
                value: tag.as_str().to_owned(),
            });
        }
        if let Some(node) = &scope.node {
            query.push(QueryParameter {
                name: "node".to_owned(),
                value: node.as_str().to_owned(),
            });
        }
        if let Some(instance) = &scope.service_instance {
            query.push(QueryParameter {
                name: "service_instance".to_owned(),
                value: instance.as_str().to_owned(),
            });
        }
        if let Some(check) = &scope.check {
            query.push(QueryParameter {
                name: "check".to_owned(),
                value: check.as_str().to_owned(),
            });
        }
        let path = operation
            .path()
            .replace(":service", &percent_encode(scope.service.as_str()));
        let headers = BTreeMap::from([(String::from("Accept"), String::from("application/json"))]);
        let mut request = Self {
            operation,
            method: HttpMethod::Get,
            path,
            query,
            headers,
            request_digest: Digest::from_text("uninitialized-consul-request"),
        };
        request.request_digest = request.computed_digest();
        request
    }

    fn computed_digest(&self) -> Digest {
        let query = self
            .query
            .iter()
            .map(|parameter| format!("{}={}", parameter.name, parameter.value))
            .collect::<Vec<_>>()
            .join("&");
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| format!("{name}:{value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let operation = format!("{:?}", self.operation);
        let method = format!("{:?}", self.method);
        Digest::from_parts(
            "consul-http-request/v1",
            &[
                operation.as_str(),
                method.as_str(),
                self.path.as_str(),
                query.as_str(),
                headers.as_str(),
            ],
        )
    }

    pub fn query_string(&self) -> String {
        self.query
            .iter()
            .map(|parameter| {
                format!(
                    "{}={}",
                    percent_encode(&parameter.name),
                    percent_encode(&parameter.value)
                )
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    pub fn url(&self, endpoint: &str) -> String {
        format!("{endpoint}{}?{}", self.path, self.query_string())
    }

    pub fn contains_secret_material(&self) -> bool {
        let material = self
            .path
            .chars()
            .chain(self.query.iter().flat_map(|item| item.name.chars()))
            .chain(self.query.iter().flat_map(|item| item.value.chars()))
            .chain(
                self.headers
                    .iter()
                    .flat_map(|(name, value)| name.chars().chain(value.chars())),
            )
            .collect::<String>()
            .to_ascii_lowercase();
        material.contains("token")
            || self
                .headers
                .keys()
                .any(|header| header.eq_ignore_ascii_case("Authorization"))
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.method != HttpMethod::Get || self.request_digest != self.computed_digest() {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawNode {
    #[serde(rename = "ID", alias = "Id")]
    pub id: String,
    pub node: String,
    pub address: String,
    pub datacenter: String,
    #[serde(default)]
    pub tagged_addresses: BTreeMap<String, String>,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
    #[serde(default)]
    pub create_index: u64,
    #[serde(default)]
    pub modify_index: u64,
}

impl RawNode {
    pub fn new(
        id: impl Into<String>,
        node: impl Into<String>,
        address: impl Into<String>,
        datacenter: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            node: node.into(),
            address: address.into(),
            datacenter: datacenter.into(),
            tagged_addresses: BTreeMap::new(),
            meta: BTreeMap::new(),
            create_index: 0,
            modify_index: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawService {
    #[serde(rename = "ID", alias = "Id")]
    pub id: String,
    pub service: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub tagged_addresses: BTreeMap<String, String>,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub partition: String,
}

impl RawService {
    pub fn new(
        id: impl Into<String>,
        service: impl Into<String>,
        tags: Vec<String>,
        address: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            id: id.into(),
            service: service.into(),
            tags,
            address: address.into(),
            port,
            tagged_addresses: BTreeMap::new(),
            meta: BTreeMap::new(),
            namespace: String::new(),
            partition: String::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawCheck {
    #[serde(rename = "CheckID", alias = "CheckId")]
    pub check_id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub output: String,
    #[serde(rename = "ServiceID", alias = "ServiceId")]
    #[serde(default)]
    pub service_id: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub service_tags: Vec<String>,
    #[serde(default)]
    pub create_index: u64,
    #[serde(default)]
    pub modify_index: u64,
}

impl RawCheck {
    pub fn new(
        check_id: impl Into<String>,
        name: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            check_id: check_id.into(),
            name: name.into(),
            status: status.into(),
            notes: String::new(),
            output: String::new(),
            service_id: String::new(),
            service_name: String::new(),
            service_tags: Vec::new(),
            create_index: 0,
            modify_index: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawHealthServiceEntry {
    pub node: RawNode,
    pub service: RawService,
    #[serde(default)]
    pub checks: Vec<RawCheck>,
}

pub type HealthServiceEntry = RawHealthServiceEntry;

impl RawHealthServiceEntry {
    pub fn new(node: RawNode, service: RawService, checks: Vec<RawCheck>) -> Self {
        Self {
            node,
            service,
            checks,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawCatalogServiceEntry {
    pub node: RawNode,
    pub service: RawService,
}

pub type CatalogServiceEntry = RawCatalogServiceEntry;

impl RawCatalogServiceEntry {
    pub fn new(node: RawNode, service: RawService) -> Self {
        Self { node, service }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConsulResponseBody {
    Health(Vec<RawHealthServiceEntry>),
    Catalog(Vec<RawCatalogServiceEntry>),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConsulResponseOperation {
    HealthService,
    CatalogService,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsulHttpResponse {
    operation: ConsulResponseOperation,
    status: u16,
    headers: BTreeMap<String, String>,
    body: ConsulResponseBody,
    response_bytes: usize,
    provenance: ProviderProvenance,
    response_digest: Digest,
}

impl ConsulHttpResponse {
    pub fn health(entries: Vec<RawHealthServiceEntry>, index: u64) -> Self {
        Self::new(
            ConsulResponseOperation::HealthService,
            ConsulResponseBody::Health(entries),
            index,
        )
    }

    pub fn catalog(entries: Vec<RawCatalogServiceEntry>, index: u64) -> Self {
        Self::new(
            ConsulResponseOperation::CatalogService,
            ConsulResponseBody::Catalog(entries),
            index,
        )
    }

    fn new(operation: ConsulResponseOperation, body: ConsulResponseBody, index: u64) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert(CONSUL_INDEX_HEADER.to_owned(), index.to_string());
        let mut response = Self {
            operation,
            status: 200,
            headers,
            body,
            response_bytes: 0,
            provenance: ProviderProvenance::Fixture,
            response_digest: Digest::from_text("uninitialized-consul-response"),
        };
        response.recompute_metadata();
        response
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self.recompute_metadata();
        self
    }

    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.recompute_digest();
        self
    }

    pub fn with_acl_filtered(mut self, filtered: bool) -> Self {
        if filtered {
            self.headers
                .insert(ACL_FILTERED_HEADER.to_owned(), "true".to_owned());
        } else {
            self.headers.remove(ACL_FILTERED_HEADER);
        }
        self.recompute_digest();
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self.recompute_digest();
        self
    }

    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self.recompute_digest();
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn operation(&self) -> ConsulResponseOperation {
        self.operation
    }

    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn index(&self) -> Option<u64> {
        self.header(CONSUL_INDEX_HEADER)?.parse().ok()
    }

    pub fn acl_filtered(&self) -> bool {
        self.header(ACL_FILTERED_HEADER)
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    }

    pub fn body(&self) -> &ConsulResponseBody {
        &self.body
    }

    pub fn validate_for(
        &self,
        operation: ConsulResponseOperation,
        bounds: &ReadBounds,
    ) -> Result<(), TransportError> {
        if self.operation != operation {
            return Err(TransportError::malformed("response operation mismatch"));
        }
        if !(200..300).contains(&self.status) {
            return Err(TransportError::from_status(self.status));
        }
        if self.response_bytes > bounds.max_response_bytes {
            return Err(TransportError::malformed("response byte bound exceeded"));
        }
        if self.index().is_none() {
            return Err(TransportError::malformed("missing X-Consul-Index"));
        }
        match (operation, &self.body) {
            (ConsulResponseOperation::HealthService, ConsulResponseBody::Health(_))
            | (ConsulResponseOperation::CatalogService, ConsulResponseBody::Catalog(_)) => Ok(()),
            _ => Err(TransportError::malformed(
                "response body operation mismatch",
            )),
        }
    }

    fn recompute_metadata(&mut self) {
        if self.response_bytes == 0 {
            self.response_bytes = serde_json::to_vec(&self.body).map_or(0, |bytes| bytes.len());
        }
        self.recompute_digest();
    }

    fn recompute_digest(&mut self) {
        let body_digest = serde_json::to_vec(&self.body).map_or_else(
            |_| Digest::from_text("malformed-consul-body"),
            |bytes| Digest::from_bytes(&bytes),
        );
        let fields = vec![
            format!("{:?}", self.operation),
            self.status.to_string(),
            self.response_bytes.to_string(),
            body_digest.as_str().to_owned(),
            self.headers
                .iter()
                .map(|(name, value)| format!("{name}:{value}"))
                .collect::<Vec<_>>()
                .join("\n"),
            self.provenance.as_str().to_owned(),
        ];
        self.response_digest = Digest::from_fields("consul-http-response/v1", &fields);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
pub enum TransportFailure {
    #[error("HTTP 400 bad request")]
    BadRequest,
    #[error("HTTP 401 unauthorized")]
    Unauthorized,
    #[error("HTTP 403 forbidden")]
    Forbidden,
    #[error("HTTP 404 not found")]
    NotFound,
    #[error("HTTP 429 too many requests")]
    TooManyRequests,
    #[error("HTTP 5xx provider failure")]
    Server,
    #[error("transport timeout")]
    Timeout,
    #[error("access was lost")]
    AccessLost,
    #[error("evidence is partial")]
    Partial,
    #[error("response was malformed or outside its bound")]
    Malformed,
    #[error("BLOCKED_ENV prevents native transport")]
    BlockedEnv,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::TooManyRequests => Some(429),
            Self::Server => Some(500),
            Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::Malformed
            | Self::BlockedEnv => None,
        }
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("Consul transport failure: {failure}")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure, diagnostic: impl AsRef<[u8]>) -> Self {
        let diagnostic = diagnostic.as_ref();
        let diagnostic = &diagnostic[..diagnostic.len().min(crate::model::MAX_DIAGNOSTIC_BYTES)];
        Self {
            failure,
            status_code: failure.status_code(),
            diagnostic_digest: Digest::from_bytes(diagnostic),
        }
    }

    pub fn malformed(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(TransportFailure::Malformed, diagnostic)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv, "BLOCKED_ENV")
    }

    pub fn from_status(status: u16) -> Self {
        let failure = match status {
            400 => TransportFailure::BadRequest,
            401 => TransportFailure::Unauthorized,
            403 => TransportFailure::Forbidden,
            404 => TransportFailure::NotFound,
            429 => TransportFailure::TooManyRequests,
            500..=599 => TransportFailure::Server,
            _ => TransportFailure::Malformed,
        };
        let mut error = Self::new(failure, format!("HTTP {status}"));
        error.status_code = Some(status);
        error
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProviderDefinitionError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("provider version or API binding is empty")]
    EmptyBinding,
    #[error("Layer 1 cannot register a native or connected provider")]
    NativeProviderForbidden,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_name: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub scope_digest: Digest,
    pub endpoint_digest: Digest,
    pub permission_digest: Digest,
    pub permissions: crate::PermissionScope,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_digest: Digest,
}

pub type ProviderDefinition = ConsulProviderDefinition;

impl ConsulProviderDefinition {
    pub fn new(
        scope: &Scope,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        scope.validate()?;
        let permissions = scope.permissions.clone();
        permissions.validate()?;
        let mut definition = Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            provider_id: CONSUL_HEALTH_PROVIDER_ID.to_owned(),
            provider_name: CONSUL_HEALTH_PROVIDER_NAME.to_owned(),
            provider_version: CONSUL_HEALTH_PROVIDER_VERSION.to_owned(),
            api_version: CONSUL_API_VERSION.to_owned(),
            api_revision: CONSUL_API_REVISION.to_owned(),
            scope_digest: scope.scope_digest().clone(),
            endpoint_digest: Digest::from_text(scope.endpoint.as_str()),
            permission_digest: permissions.digest(),
            permissions,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_digest: Digest::from_text("uninitialized-consul-provider"),
        };
        definition.provider_digest = definition.computed_digest();
        Ok(definition)
    }

    pub fn layer_one(
        scope: &Scope,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(scope, provenance)
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != SCHEMA_VERSION
            || self.provider_id != CONSUL_HEALTH_PROVIDER_ID
            || self.provider_name != CONSUL_HEALTH_PROVIDER_NAME
            || self.provider_version != CONSUL_HEALTH_PROVIDER_VERSION
            || self.api_version != CONSUL_API_VERSION
            || self.api_revision != CONSUL_API_REVISION
            || self.connected
            || self.native
            || self.first_party
            || self.permissions.validate().is_err()
            || self.provider_digest != self.computed_digest()
        {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &Scope) -> Result<(), ProviderDefinitionError> {
        self.validate()?;
        if self.scope_digest == *scope.scope_digest()
            && self.endpoint_digest == Digest::from_text(scope.endpoint.as_str())
            && self.permission_digest == scope.permission_digest()
        {
            Ok(())
        } else {
            Err(ProviderDefinitionError::Model(ModelError::InvalidScope))
        }
    }

    pub fn computed_digest(&self) -> Digest {
        let fields = vec![
            self.schema_version.clone(),
            self.provider_id.clone(),
            self.provider_name.clone(),
            self.provider_version.clone(),
            self.api_version.clone(),
            self.api_revision.clone(),
            self.scope_digest.as_str().to_owned(),
            self.endpoint_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            format!("{:?}", self.provenance),
            self.connected.to_string(),
            self.native.to_string(),
            self.first_party.to_string(),
            api_binding_digest().as_str().to_owned(),
        ];
        Digest::from_fields("consul-provider-definition/v1", &fields)
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulServiceHealthReadRequest {
    pub scope_digest: Digest,
    pub endpoint: crate::HttpsEndpoint,
    pub datacenter: Datacenter,
    pub admin_partition: crate::AdminPartition,
    pub namespace: crate::Namespace,
    pub service: crate::ServiceName,
    pub tag: Option<crate::Tag>,
    pub node: Option<crate::NodeId>,
    pub service_instance: Option<crate::ServiceInstanceId>,
    pub check: Option<crate::CheckId>,
    pub bounds: ReadBounds,
    pub observed_at: u64,
    pub health_request: ConsulHttpRequest,
    pub catalog_request: ConsulHttpRequest,
    pub request_digest: Digest,
}

impl ConsulServiceHealthReadRequest {
    pub fn new(
        scope: &ConsulServiceHealthScope,
        bounds: ReadBounds,
        observed_at: u64,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        bounds.validate()?;
        let health_request = ConsulHttpRequest::new(ConsulReadOperation::HealthService, scope);
        let catalog_request = ConsulHttpRequest::new(ConsulReadOperation::CatalogService, scope);
        let mut request = Self {
            scope_digest: scope.scope_digest().clone(),
            endpoint: scope.endpoint.clone(),
            datacenter: scope.datacenter.clone(),
            admin_partition: scope.admin_partition.clone(),
            namespace: scope.namespace.clone(),
            service: scope.service.clone(),
            tag: scope.tag.clone(),
            node: scope.node.clone(),
            service_instance: scope.service_instance.clone(),
            check: scope.check.clone(),
            bounds,
            observed_at,
            health_request,
            catalog_request,
            request_digest: Digest::from_text("uninitialized-consul-read-request"),
        };
        request.request_digest = request.computed_digest();
        Ok(request)
    }

    pub fn validate_against(&self, scope: &ConsulServiceHealthScope) -> Result<(), ModelError> {
        scope.validate()?;
        self.bounds.validate()?;
        let expected = Self::new(scope, self.bounds.clone(), self.observed_at)?;
        if self == &expected {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        self.health_request.validate_integrity()?;
        self.catalog_request.validate_integrity()?;
        if self.request_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn requests(&self) -> [&ConsulHttpRequest; 2] {
        [&self.health_request, &self.catalog_request]
    }

    pub fn contains_secret_material(&self) -> bool {
        self.requests()
            .iter()
            .any(|request| request.contains_secret_material())
    }

    fn computed_digest(&self) -> Digest {
        let observed_at = self.observed_at.to_string();
        let max_instances = self.bounds.max_instances.to_string();
        let max_checks = self.bounds.max_checks_per_instance.to_string();
        let max_tags = self.bounds.max_tags_per_instance.to_string();
        let max_bytes = self.bounds.max_response_bytes.to_string();
        Digest::from_parts(
            "consul-service-health-read-request/v1",
            &[
                self.scope_digest.as_str(),
                self.endpoint.as_str(),
                self.health_request.request_digest.as_str(),
                self.catalog_request.request_digest.as_str(),
                observed_at.as_str(),
                max_instances.as_str(),
                max_checks.as_str(),
                max_tags.as_str(),
                max_bytes.as_str(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsulProviderRead {
    pub request_digest: Digest,
    pub health: Vec<RawHealthServiceEntry>,
    pub catalog: Vec<RawCatalogServiceEntry>,
    pub health_response_digest: Digest,
    pub catalog_response_digest: Digest,
    pub health_index: u64,
    pub catalog_index: u64,
    pub health_acl_filtered: bool,
    pub catalog_acl_filtered: bool,
    pub observed_at: u64,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("provider definition is invalid: {0}")]
    Definition(#[from] ProviderDefinitionError),
    #[error("read request is invalid: {0}")]
    Request(#[from] ModelError),
    #[error("Layer 1 accepts GET-only Consul reads")]
    NonGetRequest,
    #[error("response operation did not match the requested endpoint")]
    ResponseOperationMismatch,
    #[error("health and catalog revisions differ")]
    RevisionMismatch,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("transport provenance did not match the registered provider")]
    ProvenanceMismatch,
}

impl ProviderError {
    pub fn transport_failure(&self) -> Option<TransportFailure> {
        match self {
            Self::Transport(error) => Some(error.failure),
            _ => None,
        }
    }
}

pub trait ConsulHealthTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;
    fn read(&mut self, request: &ConsulHttpRequest) -> Result<ConsulHttpResponse, TransportError>;
}

#[derive(Debug)]
pub struct ConsulHealthProvider<T> {
    definition: ConsulProviderDefinition,
    transport: T,
}

impl<T> ConsulHealthProvider<T>
where
    T: ConsulHealthTransport,
{
    pub fn new(
        transport: T,
        definition: ConsulProviderDefinition,
    ) -> Result<Self, ProviderDefinitionError> {
        definition.validate()?;
        if definition.provenance != transport.provenance() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn layer_one(
        transport: T,
        scope: &Scope,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(transport, ConsulProviderDefinition::new(scope, provenance)?)
    }

    pub fn definition(&self) -> &ConsulProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &ConsulServiceHealthReadRequest,
    ) -> Result<ConsulProviderRead, ProviderError> {
        request.validate_integrity()?;
        request.bounds.validate().map_err(ProviderError::Request)?;
        if request.contains_secret_material() {
            return Err(ProviderError::NonGetRequest);
        }
        if request.scope_digest != self.definition.scope_digest
            || Digest::from_text(request.endpoint.as_str()) != self.definition.endpoint_digest
        {
            return Err(ProviderError::Request(ModelError::InvalidScope));
        }
        if self.transport.provenance() != self.definition.provenance {
            return Err(ProviderError::ProvenanceMismatch);
        }
        let health_response = self.transport.read(&request.health_request)?;
        health_response.validate_for(ConsulResponseOperation::HealthService, &request.bounds)?;
        let catalog_response = self.transport.read(&request.catalog_request)?;
        catalog_response.validate_for(ConsulResponseOperation::CatalogService, &request.bounds)?;
        let (ConsulResponseBody::Health(health), ConsulResponseBody::Catalog(catalog)) =
            (health_response.body(), catalog_response.body())
        else {
            return Err(ProviderError::ResponseOperationMismatch);
        };
        let health_index = health_response.index().ok_or_else(|| {
            ProviderError::Transport(TransportError::malformed("missing health index"))
        })?;
        let catalog_index = catalog_response.index().ok_or_else(|| {
            ProviderError::Transport(TransportError::malformed("missing catalog index"))
        })?;
        if health_index != catalog_index {
            return Err(ProviderError::RevisionMismatch);
        }
        Ok(ConsulProviderRead {
            request_digest: request.request_digest.clone(),
            health: health.clone(),
            catalog: catalog.clone(),
            health_response_digest: health_response.response_digest().clone(),
            catalog_response_digest: catalog_response.response_digest().clone(),
            health_index,
            catalog_index,
            health_acl_filtered: health_response.acl_filtered(),
            catalog_acl_filtered: catalog_response.acl_filtered(),
            observed_at: request.observed_at,
        })
    }
}

#[derive(Clone, Debug)]
struct QueuedTransport {
    provenance: ProviderProvenance,
    responses: VecDeque<Result<ConsulHttpResponse, TransportError>>,
    calls: Vec<ConsulHttpRequest>,
}

impl QueuedTransport {
    fn new(provenance: ProviderProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    fn push_response(&mut self, response: Result<ConsulHttpResponse, TransportError>) {
        self.responses.push_back(response);
    }

    fn calls(&self) -> &[ConsulHttpRequest] {
        &self.calls
    }

    fn read(&mut self, request: &ConsulHttpRequest) -> Result<ConsulHttpResponse, TransportError> {
        self.calls.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            if self.provenance.is_blocked_env() {
                Err(TransportError::blocked_env())
            } else {
                Err(TransportError::malformed(
                    "fixture response queue exhausted",
                ))
            }
        })
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            inner: QueuedTransport,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    inner: QueuedTransport::new($provenance),
                }
            }

            pub fn with_responses(
                responses: impl IntoIterator<Item = Result<ConsulHttpResponse, TransportError>>,
            ) -> Self {
                let mut transport = Self::new();
                transport.inner.responses.extend(responses);
                transport
            }

            pub fn push_response(&mut self, response: Result<ConsulHttpResponse, TransportError>) {
                self.inner.push_response(response);
            }

            pub fn calls(&self) -> &[ConsulHttpRequest] {
                self.inner.calls()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ConsulHealthTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }

            fn read(
                &mut self,
                request: &ConsulHttpRequest,
            ) -> Result<ConsulHttpResponse, TransportError> {
                self.inner.read(request)
            }
        }
    };
}

queued_transport!(FixtureConsulHealthTransport, ProviderProvenance::Fixture);
pub type FixtureTransport = FixtureConsulHealthTransport;

queued_transport!(
    RecordingConsulHealthTransport,
    ProviderProvenance::Recording
);
pub type RecordingTransport = RecordingConsulHealthTransport;

queued_transport!(
    BlockedEnvConsulHealthTransport,
    ProviderProvenance::BlockedEnv
);
pub type BlockedEnvTransport = BlockedEnvConsulHealthTransport;

queued_transport!(FakeConsulHealthTransport, ProviderProvenance::Fake);
pub type FakeTransport = FakeConsulHealthTransport;

#[derive(Clone, Debug)]
pub struct LoopbackConsulHealthTransport {
    inner: QueuedTransport,
}

pub type LoopbackTransport = LoopbackConsulHealthTransport;

impl LoopbackConsulHealthTransport {
    pub fn new(health: ConsulHttpResponse, catalog: ConsulHttpResponse) -> Self {
        Self {
            inner: QueuedTransport {
                provenance: ProviderProvenance::Loopback,
                responses: VecDeque::from([Ok(health), Ok(catalog)]),
                calls: Vec::new(),
            },
        }
    }

    pub fn push_response(&mut self, response: Result<ConsulHttpResponse, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn calls(&self) -> &[ConsulHttpRequest] {
        self.inner.calls()
    }
}

impl ConsulHealthTransport for LoopbackConsulHealthTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn read(&mut self, request: &ConsulHttpRequest) -> Result<ConsulHttpResponse, TransportError> {
        self.inner.read(request)
    }
}
