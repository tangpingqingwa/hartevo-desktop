use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    DYNATRACE_PROBLEM_RESULT_API_VERSION, DYNATRACE_PROBLEM_RESULT_LIST_PATH,
    DYNATRACE_PROBLEM_RESULT_PROVIDER_ID, DYNATRACE_PROBLEM_RESULT_PROVIDER_VERSION,
    model::{
        AccountId, Digest, DynatraceProblemScope, EntitySelector, EnvironmentId,
        MAX_AFFECTED_ENTITIES_PER_PROBLEM, MAX_NEXT_PAGE_KEY_BYTES, MAX_PAGE_SIZE,
        MAX_PROBLEMS_PER_PAGE, MAX_RESPONSE_BYTES, ManagementZoneId, ProblemId, ProviderProvenance,
        SecretReference, project_entity_type_counts, validate_raw_identifier,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynatraceHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynatraceApiRequestKind {
    List,
    Detail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynatraceListRequest {
    pub kind: DynatraceApiRequestKind,
    pub method: DynatraceHttpMethod,
    pub environment_id: EnvironmentId,
    pub account_id: AccountId,
    pub management_zone_id: ManagementZoneId,
    pub entity_selector: EntitySelector,
    pub problem_id: Option<ProblemId>,
    pub from_ms: u64,
    pub to_ms: u64,
    pub page_index: u8,
    pub page_size: u16,
    pub next_page_key: Option<String>,
    pub path: String,
    pub query: String,
    pub scope_digest: Digest,
}

impl DynatraceListRequest {
    pub fn new(
        scope: &DynatraceProblemScope,
        page_index: u8,
        page_size: u16,
        next_page_key: Option<String>,
    ) -> Result<Self, TransportError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || page_index >= crate::model::MAX_PAGES {
            return Err(TransportError::InvalidRequest);
        }
        if let Some(key) = &next_page_key
            && (key.is_empty() || key.len() > MAX_NEXT_PAGE_KEY_BYTES)
        {
            return Err(TransportError::InvalidRequest);
        }
        let query = build_query(scope, page_size, next_page_key.as_deref(), false);
        Ok(Self {
            kind: DynatraceApiRequestKind::List,
            method: DynatraceHttpMethod::Get,
            environment_id: scope.environment_id().clone(),
            account_id: scope.account_id().clone(),
            management_zone_id: scope.management_zone_id().clone(),
            entity_selector: scope.entity_selector().clone(),
            problem_id: scope.problem_id().cloned(),
            from_ms: scope.time_window().from_ms(),
            to_ms: scope.time_window().to_ms(),
            page_index,
            page_size,
            next_page_key,
            path: DYNATRACE_PROBLEM_RESULT_LIST_PATH.to_owned(),
            query,
            scope_digest: scope.digest(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynatraceDetailRequest {
    pub kind: DynatraceApiRequestKind,
    pub method: DynatraceHttpMethod,
    pub environment_id: EnvironmentId,
    pub account_id: AccountId,
    pub management_zone_id: ManagementZoneId,
    pub entity_selector: EntitySelector,
    pub problem_id: ProblemId,
    pub from_ms: u64,
    pub to_ms: u64,
    pub path: String,
    pub query: String,
    pub scope_digest: Digest,
}

impl DynatraceDetailRequest {
    pub fn new(scope: &DynatraceProblemScope, problem_id: &ProblemId) -> Self {
        Self {
            kind: DynatraceApiRequestKind::Detail,
            method: DynatraceHttpMethod::Get,
            environment_id: scope.environment_id().clone(),
            account_id: scope.account_id().clone(),
            management_zone_id: scope.management_zone_id().clone(),
            entity_selector: scope.entity_selector().clone(),
            problem_id: problem_id.clone(),
            from_ms: scope.time_window().from_ms(),
            to_ms: scope.time_window().to_ms(),
            path: format!("/api/v2/problems/{}", percent_encode(problem_id.as_str())),
            query: String::new(),
            scope_digest: scope.digest(),
        }
    }
}

fn build_query(
    scope: &DynatraceProblemScope,
    page_size: u16,
    next_page_key: Option<&str>,
    detail: bool,
) -> String {
    let problem_selector = scope.problem_id().map_or_else(
        || {
            format!(
                "managementZoneIds(\"{}\")",
                scope.management_zone_id().as_str()
            )
        },
        |problem_id| {
            format!(
                "managementZoneIds(\"{}\"),problemId(\"{}\")",
                scope.management_zone_id().as_str(),
                problem_id.as_str()
            )
        },
    );
    let mut parameters = vec![
        format!("from={}", scope.time_window().from_ms()),
        format!("to={}", scope.time_window().to_ms()),
        format!(
            "entitySelector={}",
            percent_encode(scope.entity_selector().as_str())
        ),
        format!("problemSelector={}", percent_encode(&problem_selector)),
    ];
    if !detail {
        parameters.push(format!("pageSize={page_size}"));
        if let Some(next_page_key) = next_page_key {
            parameters.push(format!("nextPageKey={}", percent_encode(next_page_key)));
        }
    }
    parameters.join("&")
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("access token is unavailable or access was denied")]
    AccessDenied,
    #[error("provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("provider request timed out")]
    Timeout,
    #[error("provider response is malformed")]
    MalformedResponse,
    #[error("provider API version drifted")]
    ApiVersionDrift,
    #[error("provider value is unknown")]
    ProviderUnknown,
    #[error("request is invalid or exceeds a Layer-1 bound")]
    InvalidRequest,
    #[error("request scope does not match the opaque secret reference")]
    ScopeMismatch,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DynatraceProviderDefinitionError {
    #[error("provider version is empty or malformed")]
    InvalidVersion,
    #[error("provider API version is not v2")]
    UnsupportedApiVersion,
    #[error("provider is missing problems.read")]
    MissingPermission,
    #[error("Layer-1 cannot register a native, connected, or first-party provider")]
    NativeProviderForbidden,
    #[error("provider definition digest or identity is tampered")]
    TamperedDefinition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum DynatracePermission {
    #[serde(rename = "problems.read")]
    ProblemsRead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DynatraceProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_version: String,
    pub permissions: Vec<DynatracePermission>,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_digest: Digest,
}

impl DynatraceProviderDefinition {
    pub fn new(provenance: ProviderProvenance) -> Result<Self, DynatraceProviderDefinitionError> {
        Self::with_version(provenance, DYNATRACE_PROBLEM_RESULT_PROVIDER_VERSION)
    }

    pub fn with_version(
        provenance: ProviderProvenance,
        version: impl Into<String>,
    ) -> Result<Self, DynatraceProviderDefinitionError> {
        let version = version.into();
        if version.is_empty()
            || version.len() > 96
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(DynatraceProviderDefinitionError::InvalidVersion);
        }
        let mut definition = Self {
            id: DYNATRACE_PROBLEM_RESULT_PROVIDER_ID.to_owned(),
            version,
            api_version: DYNATRACE_PROBLEM_RESULT_API_VERSION.to_owned(),
            permissions: vec![DynatracePermission::ProblemsRead],
            provenance,
            native: false,
            connected: false,
            first_party: false,
            provider_digest: Digest::from_text("uncomputed"),
        };
        definition.provider_digest = definition.compute_digest();
        Ok(definition)
    }

    fn compute_digest(&self) -> Digest {
        let mut value = serde_json::to_value(self).expect("provider definition serializes");
        value
            .as_object_mut()
            .expect("provider definition is an object")
            .remove("providerDigest");
        Digest::from_serializable(&value)
    }

    pub fn validate(&self) -> Result<(), DynatraceProviderDefinitionError> {
        if self.id != DYNATRACE_PROBLEM_RESULT_PROVIDER_ID
            || self.api_version != DYNATRACE_PROBLEM_RESULT_API_VERSION
            || self.permissions != [DynatracePermission::ProblemsRead]
        {
            return Err(DynatraceProviderDefinitionError::TamperedDefinition);
        }
        if self.native || self.connected || self.first_party {
            return Err(DynatraceProviderDefinitionError::NativeProviderForbidden);
        }
        if self.compute_digest() != self.provider_digest {
            return Err(DynatraceProviderDefinitionError::TamperedDefinition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynatraceRawEntity {
    pub entity_id: String,
    pub entity_type: String,
}

impl DynatraceRawEntity {
    pub fn new(
        entity_id: impl Into<String>,
        entity_type: impl Into<String>,
    ) -> Result<Self, crate::model::ModelError> {
        let entity_id = entity_id.into();
        let entity_type = entity_type.into();
        validate_raw_identifier(&entity_id, "affected entity id")?;
        validate_raw_identifier(&entity_type, "affected entity type")?;
        Ok(Self {
            entity_id,
            entity_type,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynatraceProblemPayload {
    pub problem_id: String,
    pub status: String,
    pub severity_level: String,
    pub impact_level: String,
    pub start_time_ms: i64,
    pub end_time_ms: i64,
    pub affected_entities: Vec<DynatraceRawEntity>,
}

impl DynatraceProblemPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        problem_id: impl Into<String>,
        status: impl Into<String>,
        severity_level: impl Into<String>,
        impact_level: impl Into<String>,
        start_time_ms: i64,
        end_time_ms: i64,
        affected_entities: Vec<DynatraceRawEntity>,
    ) -> Result<Self, crate::model::ModelError> {
        let problem_id = problem_id.into();
        let status = status.into();
        let severity_level = severity_level.into();
        let impact_level = impact_level.into();
        validate_raw_identifier(&problem_id, "problem id")?;
        validate_raw_identifier(&status, "status")?;
        validate_raw_identifier(&severity_level, "severity level")?;
        validate_raw_identifier(&impact_level, "impact level")?;
        if start_time_ms < 0 || end_time_ms < -1 || end_time_ms >= 0 && end_time_ms < start_time_ms
        {
            return Err(crate::model::ModelError::MalformedProviderResponse);
        }
        if affected_entities.len() > MAX_AFFECTED_ENTITIES_PER_PROBLEM {
            return Err(crate::model::ModelError::BoundExceeded {
                field: "affected entities",
            });
        }
        Ok(Self {
            problem_id,
            status,
            severity_level,
            impact_level,
            start_time_ms,
            end_time_ms,
            affected_entities,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynatraceProblemPage {
    page_index: u8,
    page_size: u16,
    total_count: u32,
    next_page_key: Option<String>,
    problems: Vec<DynatraceProblemPayload>,
    response_bytes: usize,
    declared_digest: Digest,
}

impl DynatraceProblemPage {
    pub fn new(
        page_index: u8,
        page_size: u16,
        total_count: u32,
        next_page_key: Option<String>,
        problems: Vec<DynatraceProblemPayload>,
    ) -> Result<Self, crate::model::ModelError> {
        if page_index >= crate::model::MAX_PAGES
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || problems.len() > MAX_PROBLEMS_PER_PAGE
        {
            return Err(crate::model::ModelError::BoundExceeded {
                field: "problem page",
            });
        }
        if let Some(next_page_key) = &next_page_key
            && (next_page_key.is_empty() || next_page_key.len() > MAX_NEXT_PAGE_KEY_BYTES)
        {
            return Err(crate::model::ModelError::BoundExceeded {
                field: "next page key",
            });
        }
        let mut page = Self {
            page_index,
            page_size,
            total_count,
            next_page_key,
            problems,
            response_bytes: 0,
            declared_digest: Digest::from_text("uncomputed"),
        };
        page.declared_digest = page.compute_digest();
        Ok(page)
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    pub fn compute_digest(&self) -> Digest {
        let problems = self
            .problems
            .iter()
            .map(problem_fingerprint)
            .collect::<Vec<_>>();
        let input = PageDigestInput {
            page_index: self.page_index,
            page_size: self.page_size,
            total_count: self.total_count,
            next_page_key_digest: self.next_page_key.as_deref().map(Digest::from_text),
            problems,
        };
        Digest::from_serializable(&input)
    }

    pub fn validate(&self) -> Result<(), crate::model::ModelError> {
        if self.response_bytes > MAX_RESPONSE_BYTES || self.compute_digest() != self.declared_digest
        {
            return Err(crate::model::ModelError::DigestMismatch { field: "page" });
        }
        Ok(())
    }

    pub const fn page_index(&self) -> u8 {
        self.page_index
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn total_count(&self) -> u32 {
        self.total_count
    }

    pub fn next_page_key(&self) -> Option<&str> {
        self.next_page_key.as_deref()
    }

    pub fn problems(&self) -> &[DynatraceProblemPayload] {
        &self.problems
    }

    pub fn declared_digest(&self) -> &Digest {
        &self.declared_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynatraceProblemDetail {
    problem: DynatraceProblemPayload,
    response_bytes: usize,
    declared_digest: Digest,
}

impl DynatraceProblemDetail {
    pub fn new(problem: DynatraceProblemPayload) -> Self {
        let mut detail = Self {
            problem,
            response_bytes: 0,
            declared_digest: Digest::from_text("uncomputed"),
        };
        detail.declared_digest = detail.compute_digest();
        detail
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&DetailDigestInput {
            problem: problem_fingerprint(&self.problem),
        })
    }

    pub fn validate(&self) -> Result<(), crate::model::ModelError> {
        if self.response_bytes > MAX_RESPONSE_BYTES || self.compute_digest() != self.declared_digest
        {
            return Err(crate::model::ModelError::DigestMismatch { field: "detail" });
        }
        Ok(())
    }

    pub fn problem(&self) -> &DynatraceProblemPayload {
        &self.problem
    }

    pub fn declared_digest(&self) -> &Digest {
        &self.declared_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PageDigestInput {
    page_index: u8,
    page_size: u16,
    total_count: u32,
    next_page_key_digest: Option<Digest>,
    problems: Vec<ProblemFingerprint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DetailDigestInput {
    problem: ProblemFingerprint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ProblemFingerprint {
    problem_id_digest: Digest,
    status: String,
    severity_level: String,
    impact_level: String,
    start_time_ms: i64,
    end_time_ms: i64,
    entity_id_digests: Vec<Digest>,
    entity_type_digests: Vec<Digest>,
}

fn problem_fingerprint(problem: &DynatraceProblemPayload) -> ProblemFingerprint {
    let entity_id_digests = problem
        .affected_entities
        .iter()
        .map(|entity| Digest::from_text(&entity.entity_id))
        .collect();
    let entity_type_digests = problem
        .affected_entities
        .iter()
        .map(|entity| Digest::from_text(&entity.entity_type))
        .collect();
    ProblemFingerprint {
        problem_id_digest: Digest::from_text(&problem.problem_id),
        status: problem.status.clone(),
        severity_level: problem.severity_level.clone(),
        impact_level: problem.impact_level.clone(),
        start_time_ms: problem.start_time_ms,
        end_time_ms: problem.end_time_ms,
        entity_id_digests,
        entity_type_digests,
    }
}

pub trait DynatraceProblemTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list(
        &mut self,
        request: &DynatraceListRequest,
        secret: &SecretReference,
    ) -> Result<DynatraceProblemPage, TransportError>;

    fn detail(
        &mut self,
        request: &DynatraceDetailRequest,
        secret: &SecretReference,
    ) -> Result<DynatraceProblemDetail, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProblemTransportCall {
    pub kind: DynatraceApiRequestKind,
    pub method: DynatraceHttpMethod,
    pub path: String,
    pub query: String,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug)]
pub struct RecordingDynatraceTransport {
    provenance: ProviderProvenance,
    list_responses: VecDeque<Result<DynatraceProblemPage, TransportError>>,
    detail_responses: VecDeque<Result<DynatraceProblemDetail, TransportError>>,
    calls: Vec<ProblemTransportCall>,
}

impl RecordingDynatraceTransport {
    pub fn new(
        provenance: ProviderProvenance,
        list_responses: impl IntoIterator<Item = Result<DynatraceProblemPage, TransportError>>,
        detail_responses: impl IntoIterator<Item = Result<DynatraceProblemDetail, TransportError>>,
    ) -> Self {
        Self {
            provenance,
            list_responses: list_responses.into_iter().collect(),
            detail_responses: detail_responses.into_iter().collect(),
            calls: Vec::new(),
        }
    }

    pub fn fixture(
        list_responses: impl IntoIterator<Item = Result<DynatraceProblemPage, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Fixture, list_responses, [])
    }

    pub fn fixture_with_details(
        list_responses: impl IntoIterator<Item = Result<DynatraceProblemPage, TransportError>>,
        detail_responses: impl IntoIterator<Item = Result<DynatraceProblemDetail, TransportError>>,
    ) -> Self {
        Self::new(
            ProviderProvenance::Fixture,
            list_responses,
            detail_responses,
        )
    }

    pub fn recording(
        list_responses: impl IntoIterator<Item = Result<DynatraceProblemPage, TransportError>>,
        detail_responses: impl IntoIterator<Item = Result<DynatraceProblemDetail, TransportError>>,
    ) -> Self {
        Self::new(
            ProviderProvenance::Recording,
            list_responses,
            detail_responses,
        )
    }

    pub fn loopback(
        list_responses: impl IntoIterator<Item = Result<DynatraceProblemPage, TransportError>>,
        detail_responses: impl IntoIterator<Item = Result<DynatraceProblemDetail, TransportError>>,
    ) -> Self {
        Self::new(
            ProviderProvenance::Loopback,
            list_responses,
            detail_responses,
        )
    }

    pub fn blocked_env() -> Self {
        Self::new(
            ProviderProvenance::BlockedEnv,
            [Err(TransportError::AccessDenied)],
            [Err(TransportError::AccessDenied)],
        )
    }

    pub fn calls(&self) -> &[ProblemTransportCall] {
        &self.calls
    }
}

impl DynatraceProblemTransport for RecordingDynatraceTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn list(
        &mut self,
        request: &DynatraceListRequest,
        secret: &SecretReference,
    ) -> Result<DynatraceProblemPage, TransportError> {
        self.calls.push(ProblemTransportCall {
            kind: request.kind,
            method: request.method,
            path: request.path.clone(),
            query: request.query.clone(),
            scope_digest: request.scope_digest.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            provenance: self.provenance,
            connected: false,
            native: false,
            first_party: false,
        });
        self.list_responses
            .pop_front()
            .unwrap_or(Err(TransportError::ProviderUnknown))
    }

    fn detail(
        &mut self,
        request: &DynatraceDetailRequest,
        secret: &SecretReference,
    ) -> Result<DynatraceProblemDetail, TransportError> {
        self.calls.push(ProblemTransportCall {
            kind: request.kind,
            method: request.method,
            path: request.path.clone(),
            query: request.query.clone(),
            scope_digest: request.scope_digest.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            provenance: self.provenance,
            connected: false,
            native: false,
            first_party: false,
        });
        self.detail_responses
            .pop_front()
            .unwrap_or(Err(TransportError::ProviderUnknown))
    }
}

pub type FixtureDynatraceTransport = RecordingDynatraceTransport;
pub type LoopbackDynatraceTransport = RecordingDynatraceTransport;
pub type BlockedEnvDynatraceTransport = RecordingDynatraceTransport;
pub type FakeDynatraceTransport = RecordingDynatraceTransport;

#[derive(Debug)]
pub struct DynatraceProvider<T: DynatraceProblemTransport> {
    definition: DynatraceProviderDefinition,
    transport: T,
}

impl<T: DynatraceProblemTransport> DynatraceProvider<T> {
    pub fn new(transport: T) -> Result<Self, DynatraceProviderDefinitionError> {
        let definition = DynatraceProviderDefinition::new(transport.provenance())?;
        Self::with_definition(definition, transport)
    }

    pub fn with_definition(
        definition: DynatraceProviderDefinition,
        transport: T,
    ) -> Result<Self, DynatraceProviderDefinitionError> {
        definition.validate()?;
        if definition.provenance != transport.provenance() {
            return Err(DynatraceProviderDefinitionError::TamperedDefinition);
        }
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &DynatraceProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list(
        &mut self,
        request: &DynatraceListRequest,
        secret: &SecretReference,
    ) -> Result<DynatraceProblemPage, TransportError> {
        if request.scope_digest != *secret.scope_digest() {
            return Err(TransportError::ScopeMismatch);
        }
        self.transport.list(request, secret)
    }

    pub fn detail(
        &mut self,
        request: &DynatraceDetailRequest,
        secret: &SecretReference,
    ) -> Result<DynatraceProblemDetail, TransportError> {
        if request.scope_digest != *secret.scope_digest() {
            return Err(TransportError::ScopeMismatch);
        }
        self.transport.detail(request, secret)
    }
}

fn project_problem(
    problem: &DynatraceProblemPayload,
    state: crate::model::ProblemObservationState,
) -> Result<crate::model::ProblemProjection, crate::model::ModelError> {
    validate_raw_identifier(&problem.problem_id, "problem id")?;
    if problem.start_time_ms < 0
        || problem.end_time_ms < -1
        || problem.end_time_ms >= 0 && problem.end_time_ms < problem.start_time_ms
        || problem.affected_entities.len() > MAX_AFFECTED_ENTITIES_PER_PROBLEM
    {
        return Err(crate::model::ModelError::MalformedProviderResponse);
    }
    let status = crate::model::DynatraceProblemStatus::parse(&problem.status)?;
    let severity = crate::model::DynatraceSeverity::parse(&problem.severity_level)?;
    let impact = crate::model::DynatraceImpact::parse(&problem.impact_level)?;
    let affected_entity_types = project_entity_type_counts(
        problem
            .affected_entities
            .iter()
            .map(|entity| entity.entity_type.clone()),
    )?;
    Ok(crate::model::ProblemProjection {
        problem_id_digest: Digest::from_text(&problem.problem_id),
        state,
        status,
        severity,
        impact,
        start_time_ms: u64::try_from(problem.start_time_ms)
            .map_err(|_| crate::model::ModelError::MalformedProviderResponse)?,
        end_time_ms: if problem.end_time_ms == -1 {
            None
        } else {
            Some(
                u64::try_from(problem.end_time_ms)
                    .map_err(|_| crate::model::ModelError::MalformedProviderResponse)?,
            )
        },
        affected_entity_types,
    })
}

pub(crate) fn project_problem_payload(
    problem: &DynatraceProblemPayload,
    previous_status: Option<crate::model::DynatraceProblemStatus>,
) -> Result<crate::model::ProblemProjection, crate::model::ModelError> {
    let status = crate::model::DynatraceProblemStatus::parse(&problem.status)?;
    let state = match (previous_status, status) {
        (
            Some(crate::model::DynatraceProblemStatus::Open),
            crate::model::DynatraceProblemStatus::Closed,
        ) => crate::model::ProblemObservationState::Resolved,
        (_, crate::model::DynatraceProblemStatus::Open) => {
            crate::model::ProblemObservationState::Open
        }
        (_, crate::model::DynatraceProblemStatus::Closed) => {
            crate::model::ProblemObservationState::Closed
        }
    };
    project_problem(problem, state)
}

pub(crate) fn status_of_payload(
    problem: &DynatraceProblemPayload,
) -> Result<crate::model::DynatraceProblemStatus, crate::model::ModelError> {
    crate::model::DynatraceProblemStatus::parse(&problem.status)
}

#[cfg(test)]
mod provider_tests {
    use super::*;

    #[test]
    fn all_offline_provenances_are_honest() {
        for provenance in [
            ProviderProvenance::Fixture,
            ProviderProvenance::Recording,
            ProviderProvenance::Loopback,
            ProviderProvenance::BlockedEnv,
        ] {
            assert!(!provenance.is_connected());
            assert!(!provenance.is_native());
            assert!(!provenance.is_first_party());
        }
    }
}
