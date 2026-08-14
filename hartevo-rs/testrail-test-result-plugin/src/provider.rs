use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    API_REVISION, MAX_COMMENT_BYTES, MAX_DEFECT_BYTES, MAX_DEFECTS, MAX_ITEMS, MAX_PAGE_SIZE,
    MAX_PAGES, MAX_RESPONSE_BYTES, MAX_VERSION_BYTES, TestRailError, TransportError,
    model::{DefectIdentity, Digest, SecretReference, TestRailRegistration, TestRailScope},
};

pub const GET_RUN_PATH: &str = "/api/v2/get_run";
pub const GET_TESTS_PATH: &str = "/api/v2/get_tests";
pub const GET_RESULTS_FOR_RUN_PATH: &str = "/api/v2/get_results_for_run";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }
    pub const fn claims_connected(self) -> bool {
        false
    }
    pub const fn claims_first_party(self) -> bool {
        false
    }
    pub const fn is_explicit_non_native(self) -> bool {
        true
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRailEndpoint {
    GetRun,
    GetTests,
    GetResultsForRun,
}

impl TestRailEndpoint {
    pub const fn base_path(self) -> &'static str {
        match self {
            Self::GetRun => GET_RUN_PATH,
            Self::GetTests => GET_TESTS_PATH,
            Self::GetResultsForRun => GET_RESULTS_FOR_RUN_PATH,
        }
    }

    pub const fn allows_pagination(self) -> bool {
        !matches!(self, Self::GetRun)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestRailRequest {
    pub endpoint: TestRailEndpoint,
    pub path: String,
    pub project_id: u64,
    pub run_id: u64,
    pub offset: usize,
    pub limit: usize,
}

impl TestRailRequest {
    pub fn new_for_test(
        endpoint: TestRailEndpoint,
        project_id: u64,
        run_id: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Self, TestRailError> {
        Self::new(endpoint, project_id, run_id, offset, limit)
    }

    fn new(
        endpoint: TestRailEndpoint,
        project_id: u64,
        run_id: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Self, TestRailError> {
        if project_id == 0 || run_id == 0 || limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(TestRailError::InvalidInput("bounded TestRail request"));
        }
        let base_path = format!("{}/{run_id}", endpoint.base_path());
        let path = if endpoint.allows_pagination() {
            format!("{base_path}?limit={limit}&offset={offset}")
        } else {
            base_path
        };
        Ok(Self {
            endpoint,
            path,
            project_id,
            run_id,
            offset,
            limit,
        })
    }
}

/// A bounded fixture/recording response.  Its body is only transient transport
/// input; provider projections never retain or serialize it.
pub struct TestRailResponse {
    pub status: u16,
    body: Vec<u8>,
    pub provenance: TransportProvenance,
}

impl Clone for TestRailResponse {
    fn clone(&self) -> Self {
        Self {
            status: self.status,
            body: self.body.clone(),
            provenance: self.provenance,
        }
    }
}

impl PartialEq for TestRailResponse {
    fn eq(&self, other: &Self) -> bool {
        self.status == other.status
            && self.body == other.body
            && self.provenance == other.provenance
    }
}

impl Eq for TestRailResponse {}

impl fmt::Debug for TestRailResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestRailResponse")
            .field("status", &self.status)
            .field(
                "body",
                &format_args!("<redacted {} bytes>", self.body.len()),
            )
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl TestRailResponse {
    pub fn from_json(status: u16, body: impl AsRef<[u8]>, provenance: TransportProvenance) -> Self {
        Self {
            status,
            body: body.as_ref().to_vec(),
            provenance,
        }
    }

    pub fn json(body: impl AsRef<[u8]>, provenance: TransportProvenance) -> Self {
        Self::from_json(200, body, provenance)
    }

    pub fn error(status: u16, provenance: TransportProvenance) -> Self {
        Self::from_json(status, b"{}", provenance)
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

pub trait TestRailTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn execute(&mut self, request: &TestRailRequest) -> Result<TestRailResponse, TransportError>;
}

fn pop_queued(
    queue: &mut VecDeque<Result<TestRailResponse, TransportError>>,
    provenance: TransportProvenance,
    _request: &TestRailRequest,
) -> Result<TestRailResponse, TransportError> {
    let response = queue
        .pop_front()
        .ok_or(TransportError::UnexpectedRequest)??;
    Ok(TestRailResponse {
        status: response.status,
        body: response.body,
        provenance,
    })
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    queue: VecDeque<Result<TestRailResponse, TransportError>>,
}

impl FixtureTransport {
    pub fn new(response: TestRailResponse) -> Self {
        Self::from_responses([response])
    }

    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = TestRailResponse>,
    {
        Self {
            queue: responses.into_iter().map(Ok).collect(),
        }
    }

    pub fn from_results<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<TestRailResponse, TransportError>>,
    {
        Self {
            queue: responses.into_iter().collect(),
        }
    }

    pub fn push(&mut self, response: TestRailResponse) {
        self.queue.push_back(Ok(response));
    }
}

impl TestRailTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(&mut self, request: &TestRailRequest) -> Result<TestRailResponse, TransportError> {
        let provenance = self.provenance();
        pop_queued(&mut self.queue, provenance, request)
    }
}

pub type FakeTransport = FixtureTransport;

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    queue: VecDeque<Result<TestRailResponse, TransportError>>,
}

impl RecordingTransport {
    pub fn new(response: TestRailResponse) -> Self {
        Self::from_responses([response])
    }

    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = TestRailResponse>,
    {
        Self {
            queue: responses.into_iter().map(Ok).collect(),
        }
    }

    pub fn from_results<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<TestRailResponse, TransportError>>,
    {
        Self {
            queue: responses.into_iter().collect(),
        }
    }

    pub fn push(&mut self, response: TestRailResponse) {
        self.queue.push_back(Ok(response));
    }
}

impl TestRailTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(&mut self, request: &TestRailRequest) -> Result<TestRailResponse, TransportError> {
        let provenance = self.provenance();
        pop_queued(&mut self.queue, provenance, request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    queue: VecDeque<Result<TestRailResponse, TransportError>>,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = TestRailResponse>,
    {
        Self {
            queue: responses.into_iter().map(Ok).collect(),
        }
    }

    pub fn push(&mut self, response: TestRailResponse) {
        self.queue.push_back(Ok(response));
    }
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TestRailTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(&mut self, request: &TestRailRequest) -> Result<TestRailResponse, TransportError> {
        let provenance = self.provenance();
        pop_queued(&mut self.queue, provenance, request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl TestRailTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(&mut self, _request: &TestRailRequest) -> Result<TestRailResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRailResultStatus {
    Passed,
    Failed,
    Blocked,
    Skipped,
    Untested,
    Partial,
    Expired,
    AccessLoss,
    ProviderUnknown,
}

impl TestRailResultStatus {
    pub const fn is_terminal_evidence(self) -> bool {
        matches!(
            self,
            Self::Passed | Self::Failed | Self::Blocked | Self::Skipped | Self::Expired
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusCounts {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub untested: usize,
    pub partial: usize,
    pub expired: usize,
    pub provider_unknown: usize,
}

impl StatusCounts {
    fn add(&mut self, status: TestRailResultStatus) {
        self.total += 1;
        match status {
            TestRailResultStatus::Passed => self.passed += 1,
            TestRailResultStatus::Failed => self.failed += 1,
            TestRailResultStatus::Blocked => self.blocked += 1,
            TestRailResultStatus::Skipped => self.skipped += 1,
            TestRailResultStatus::Untested => self.untested += 1,
            TestRailResultStatus::Partial => self.partial += 1,
            TestRailResultStatus::Expired => self.expired += 1,
            TestRailResultStatus::AccessLoss | TestRailResultStatus::ProviderUnknown => {
                self.provider_unknown += 1;
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEvidence {
    pub id: u64,
    pub name_digest: Digest,
    pub project_id: u64,
    pub suite_id: u64,
    pub updated_on: u64,
    pub due_on: Option<u64>,
    pub is_completed: bool,
    pub run_fingerprint: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestEvidence {
    pub id: u64,
    pub case_id: Option<u64>,
    pub status_id: u16,
    pub status: TestRailResultStatus,
    pub title_digest: Digest,
    pub section_id: Option<u64>,
    pub test_fingerprint: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedResultMetadata {
    pub id: u64,
    pub test_id: u64,
    pub status_id: u16,
    pub status: TestRailResultStatus,
    pub created_on: u64,
    pub defect_count: usize,
    pub defect_digests: Vec<Digest>,
    pub comment_present: bool,
    pub comment_bytes: usize,
    pub comment_digest: Option<Digest>,
    pub version_digest: Option<Digest>,
    pub redaction: RedactionState,
    pub result_fingerprint: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    MetadataOnly,
    CommentAndDefectMetadataRedacted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct TestRailResultProjection {
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub host_digest: Digest,
    pub project_digest: Digest,
    pub suite_digest: Digest,
    pub section_digest: Digest,
    pub run_digest: Digest,
    pub test_fingerprint: Digest,
    pub result_fingerprint: Digest,
    pub status_fingerprint: Digest,
    pub source_digest: Digest,
    pub mission_digest: Digest,
    pub hartevo_project_digest: Digest,
    pub work_product_digest: Digest,
    pub run_revision: u64,
    pub run_updated_on: u64,
    pub status: TestRailResultStatus,
    pub counts: StatusCounts,
    pub run: RunEvidence,
    pub tests: Vec<TestEvidence>,
    pub results: Vec<RedactedResultMetadata>,
    pub provenance: TransportProvenance,
    pub complete: bool,
    pub source_verified: bool,
    pub section_verified: bool,
    pub metadata_redacted: bool,
    pub raw_payload_retained: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verified: bool,
    pub projection_digest: Digest,
}

impl TestRailResultProjection {
    pub fn validate_integrity(&self) -> Result<(), TestRailError> {
        let expected = self.compute_digest();
        if expected != self.projection_digest {
            return Err(TestRailError::TamperDetected);
        }
        if self.connected
            || self.native
            || self.first_party
            || self.verified
            || self.raw_payload_retained
        {
            return Err(TestRailError::TamperDetected);
        }
        if !self.metadata_redacted || !self.provenance.is_explicit_non_native() {
            return Err(TestRailError::TamperDetected);
        }
        Ok(())
    }

    pub fn is_adoptable(&self) -> bool {
        false
    }
    pub fn is_complete(&self) -> bool {
        self.complete
    }
    pub fn is_native(&self) -> bool {
        self.native
    }
    pub fn claims_connected(&self) -> bool {
        self.connected
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ProjectionMaterial::from_projection(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
struct ProjectionMaterial {
    scope_digest: Digest,
    version_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    revision_digest: Digest,
    host_digest: Digest,
    project_digest: Digest,
    suite_digest: Digest,
    section_digest: Digest,
    run_digest: Digest,
    test_fingerprint: Digest,
    result_fingerprint: Digest,
    status_fingerprint: Digest,
    source_digest: Digest,
    mission_digest: Digest,
    hartevo_project_digest: Digest,
    work_product_digest: Digest,
    run_revision: u64,
    run_updated_on: u64,
    status: TestRailResultStatus,
    counts: StatusCounts,
    run: RunEvidence,
    tests: Vec<TestEvidence>,
    results: Vec<RedactedResultMetadata>,
    provenance: TransportProvenance,
    complete: bool,
    source_verified: bool,
    section_verified: bool,
    metadata_redacted: bool,
}

impl ProjectionMaterial {
    fn from_projection(projection: &TestRailResultProjection) -> Self {
        Self {
            scope_digest: projection.scope_digest.clone(),
            version_digest: projection.version_digest.clone(),
            contract_digest: projection.contract_digest.clone(),
            provider_digest: projection.provider_digest.clone(),
            permission_digest: projection.permission_digest.clone(),
            revision_digest: projection.revision_digest.clone(),
            host_digest: projection.host_digest.clone(),
            project_digest: projection.project_digest.clone(),
            suite_digest: projection.suite_digest.clone(),
            section_digest: projection.section_digest.clone(),
            run_digest: projection.run_digest.clone(),
            test_fingerprint: projection.test_fingerprint.clone(),
            result_fingerprint: projection.result_fingerprint.clone(),
            status_fingerprint: projection.status_fingerprint.clone(),
            source_digest: projection.source_digest.clone(),
            mission_digest: projection.mission_digest.clone(),
            hartevo_project_digest: projection.hartevo_project_digest.clone(),
            work_product_digest: projection.work_product_digest.clone(),
            run_revision: projection.run_revision,
            run_updated_on: projection.run_updated_on,
            status: projection.status,
            counts: projection.counts.clone(),
            run: projection.run.clone(),
            tests: projection.tests.clone(),
            results: projection.results.clone(),
            provenance: projection.provenance,
            complete: projection.complete,
            source_verified: projection.source_verified,
            section_verified: projection.section_verified,
            metadata_redacted: projection.metadata_redacted,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestRailBounds {
    pub page_size: usize,
    pub max_pages: usize,
    pub max_response_bytes: usize,
}

impl TestRailBounds {
    pub fn new(
        page_size: usize,
        max_pages: usize,
        max_response_bytes: usize,
    ) -> Result<Self, TestRailError> {
        let bounds = Self {
            page_size,
            max_pages,
            max_response_bytes,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    fn validate(&self) -> Result<(), TestRailError> {
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
        {
            return Err(TestRailError::InvalidInput("TestRail bounds"));
        }
        Ok(())
    }
}

impl Default for TestRailBounds {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

pub struct TestRailProvider<T> {
    registration: TestRailRegistration,
    transport: T,
    bounds: TestRailBounds,
}

impl<T: fmt::Debug> fmt::Debug for TestRailProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestRailProvider")
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .field("bounds", &self.bounds)
            .finish()
    }
}

impl<T: TestRailTransport> TestRailProvider<T> {
    pub fn new(registration: TestRailRegistration, transport: T) -> Result<Self, TestRailError> {
        registration.validate_integrity()?;
        Ok(Self {
            registration,
            transport,
            bounds: TestRailBounds::default(),
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn with_secret(
        registration: TestRailRegistration,
        secret: SecretReference,
        transport: T,
    ) -> Result<Self, TestRailError> {
        if secret.scope_digest() != &registration.scope.scope_digest()
            || secret.reference_digest() != registration.secret_reference().reference_digest()
        {
            return Err(TestRailError::RegistrationMismatch);
        }
        Self::new(registration, transport)
    }

    pub fn with_bounds(mut self, bounds: TestRailBounds) -> Result<Self, TestRailError> {
        bounds.validate()?;
        self.bounds = bounds;
        Ok(self)
    }

    pub fn registration(&self) -> &TestRailRegistration {
        &self.registration
    }
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }
    pub fn bounds(&self) -> TestRailBounds {
        self.bounds
    }

    pub fn read_run(&mut self) -> Result<RunEvidence, TestRailError> {
        self.registration.ensure_active()?;
        let value = self.request(TestRailEndpoint::GetRun, 0)?;
        self.parse_run(&value)
    }

    pub fn read_tests(&mut self) -> Result<Vec<TestEvidence>, TestRailError> {
        self.registration.ensure_active()?;
        let scope = self.registration.scope.clone();
        let tests = self.collect_pages(TestRailEndpoint::GetTests, "tests", move |item| {
            Self::parse_test_for_scope(&scope, item)
        })?;
        if tests
            .iter()
            .map(|test| test.id)
            .collect::<BTreeSet<_>>()
            .len()
            != tests.len()
        {
            return Err(TestRailError::TestDrift);
        }
        Ok(tests)
    }

    pub fn read_results(&mut self) -> Result<Vec<RedactedResultMetadata>, TestRailError> {
        self.registration.ensure_active()?;
        let expected = self.registration.scope.expected_test_ids();
        self.collect_results(&expected)
    }

    pub fn read_result_projection(&mut self) -> Result<TestRailResultProjection, TestRailError> {
        self.registration.ensure_active()?;
        let run = self.read_run()?;
        let tests = self.read_tests()?;
        let known_tests: BTreeSet<_> = tests.iter().map(|test| test.id).collect();
        let results = self.collect_results(&known_tests)?;
        self.build_projection(run, tests, results)
    }

    pub fn read(&mut self) -> Result<TestRailResultProjection, TestRailError> {
        self.read_result_projection()
    }

    fn request(
        &mut self,
        endpoint: TestRailEndpoint,
        offset: usize,
    ) -> Result<Value, TestRailError> {
        if self.registration.scope.api_revision != API_REVISION {
            return Err(TestRailError::UnsupportedApiVersion);
        }
        let request = TestRailRequest::new(
            endpoint,
            self.registration.scope.project.id,
            self.registration.scope.run.id,
            offset,
            if endpoint.allows_pagination() {
                self.bounds.page_size
            } else {
                1
            },
        )?;
        let response = self
            .transport
            .execute(&request)
            .map_err(TestRailError::Transport)?;
        if response.status != 200 {
            return Err(TestRailError::Transport(TransportError::from_status(
                response.status,
            )));
        }
        if response.body_len() > self.bounds.max_response_bytes {
            return Err(TestRailError::ResponseTooLarge);
        }
        serde_json::from_slice::<Value>(&response.body)
            .map_err(|_| TestRailError::MalformedResponse)
    }

    fn read_page(
        &mut self,
        endpoint: TestRailEndpoint,
        key: &str,
        offset: usize,
    ) -> Result<Page, TestRailError> {
        let value = self.request(endpoint, offset)?;
        let object = value.as_object().ok_or(TestRailError::MalformedResponse)?;
        let response_offset = usize::try_from(
            object
                .get("offset")
                .and_then(Value::as_u64)
                .ok_or(TestRailError::MalformedResponse)?,
        )
        .map_err(|_| TestRailError::ProviderDrift)?;
        let limit = usize::try_from(
            object
                .get("limit")
                .and_then(Value::as_u64)
                .ok_or(TestRailError::MalformedResponse)?,
        )
        .map_err(|_| TestRailError::ProviderDrift)?;
        let size = usize::try_from(
            object
                .get("size")
                .and_then(Value::as_u64)
                .ok_or(TestRailError::MalformedResponse)?,
        )
        .map_err(|_| TestRailError::ProviderDrift)?;
        if response_offset != offset
            || !(1..=MAX_PAGE_SIZE).contains(&limit)
            || limit > self.bounds.page_size
        {
            return Err(TestRailError::ProviderDrift);
        }
        let items = object
            .get(key)
            .and_then(Value::as_array)
            .ok_or(TestRailError::MalformedResponse)?
            .clone();
        if size != items.len() || items.len() > limit {
            return Err(TestRailError::PartialResponse);
        }
        let links = object
            .get("_links")
            .and_then(Value::as_object)
            .ok_or(TestRailError::ProviderDrift)?;
        let next_offset = match links.get("next") {
            Some(Value::Null) => None,
            Some(Value::String(next)) => Some(parse_next_offset(endpoint, next)?),
            _ => return Err(TestRailError::ProviderDrift),
        };
        if items.is_empty() && next_offset.is_some() {
            return Err(TestRailError::PaginationLoop);
        }
        if let Some(next_offset) = next_offset
            && (next_offset <= offset
                || (next_offset != offset.saturating_add(items.len())
                    && next_offset != offset.saturating_add(limit)))
        {
            return Err(TestRailError::PaginationLoop);
        }
        Ok(Page { items, next_offset })
    }

    fn collect_pages<U, F>(
        &mut self,
        endpoint: TestRailEndpoint,
        key: &str,
        mut parse: F,
    ) -> Result<Vec<U>, TestRailError>
    where
        F: FnMut(&Value) -> Result<U, TestRailError>,
    {
        let mut offset = 0usize;
        let mut seen_offsets = BTreeSet::new();
        let mut output = Vec::new();
        for page_index in 0..self.bounds.max_pages {
            if !seen_offsets.insert(offset) {
                return Err(TestRailError::PaginationLoop);
            }
            let page = self.read_page(endpoint, key, offset)?;
            for item in &page.items {
                if output.len() >= MAX_ITEMS {
                    return Err(TestRailError::PaginationLimit);
                }
                output.push(parse(item)?);
            }
            match page.next_offset {
                None => return Ok(output),
                Some(next) if page_index + 1 < self.bounds.max_pages => offset = next,
                Some(_) => return Err(TestRailError::PaginationLimit),
            }
        }
        Err(TestRailError::PaginationLimit)
    }

    fn collect_results(
        &mut self,
        known_test_ids: &BTreeSet<u64>,
    ) -> Result<Vec<RedactedResultMetadata>, TestRailError> {
        let scope = self.registration.scope.clone();
        let known_test_ids = known_test_ids.clone();
        let mut results =
            self.collect_pages(TestRailEndpoint::GetResultsForRun, "results", |item| {
                Self::parse_result_for_scope(&scope, item, &known_test_ids)
            })?;
        results.sort_by_key(|result| (result.test_id, result.created_on, result.id));
        if results
            .iter()
            .map(|result| result.id)
            .collect::<BTreeSet<_>>()
            .len()
            != results.len()
        {
            return Err(TestRailError::ResultDrift);
        }
        let expected = self.registration.scope.expected_result_ids();
        if !expected.is_empty() {
            let actual: BTreeSet<_> = results.iter().map(|result| result.id).collect();
            if actual != expected {
                return Err(TestRailError::ResultDrift);
            }
        }
        Ok(results)
    }

    fn parse_run(&self, value: &Value) -> Result<RunEvidence, TestRailError> {
        let object = value.as_object().ok_or(TestRailError::MalformedResponse)?;
        let scope = &self.registration.scope;
        let id = required_u64(object, "id")?;
        let project_id = required_u64(object, "project_id")?;
        let suite_id = required_u64(object, "suite_id")?;
        let name = required_string(object, "name")?;
        let updated_on = required_u64(object, "updated_on")?;
        let due_on = optional_u64(object, "due_on")?;
        let is_completed = object
            .get("is_completed")
            .and_then(Value::as_bool)
            .ok_or(TestRailError::MalformedResponse)?;
        if id != scope.run.id || project_id != scope.project.id {
            return Err(TestRailError::RunDrift);
        }
        if suite_id != scope.suite.id || name != scope.run.name {
            return Err(TestRailError::SuiteDrift);
        }
        if updated_on != scope.run.updated_on || scope.run.due_on != due_on {
            return Err(TestRailError::RunRevisionDrift);
        }
        let run_fingerprint = Digest::from_serializable(&(
            id,
            project_id,
            suite_id,
            &name,
            updated_on,
            due_on,
            is_completed,
        ));
        Ok(RunEvidence {
            id,
            name_digest: Digest::from_text(name),
            project_id,
            suite_id,
            updated_on,
            due_on,
            is_completed,
            run_fingerprint,
        })
    }

    fn parse_test_for_scope(
        scope: &TestRailScope,
        value: &Value,
    ) -> Result<TestEvidence, TestRailError> {
        let object = value.as_object().ok_or(TestRailError::MalformedResponse)?;
        let id = required_u64(object, "id")?;
        let case_id = optional_u64(object, "case_id")?;
        let run_id = optional_u64(object, "run_id")?;
        let title = required_string(object, "title")?;
        let status_id = required_u16(object, "status_id")?;
        let section_id = optional_u64(object, "section_id")?;
        if run_id.is_some_and(|run_id| run_id != scope.run.id) {
            return Err(TestRailError::RunDrift);
        }
        if !scope.allowed_status_ids.contains(&status_id) {
            return Err(TestRailError::StatusNotAllowlisted);
        }
        if section_id.is_some_and(|section_id| section_id != scope.section.id) {
            return Err(TestRailError::SectionDrift);
        }
        if let Some(expected) = scope.tests.iter().find(|test| test.id == id) {
            if expected.case_id != case_id || expected.title != title {
                return Err(TestRailError::TestDrift);
            }
        } else if !scope.tests.is_empty() {
            return Err(TestRailError::TestDrift);
        }
        let status = status_for_id(status_id, status_label(scope, status_id));
        let title_digest = Digest::from_text(title);
        let test_fingerprint =
            Digest::from_serializable(&(id, case_id, status_id, &title_digest, section_id));
        Ok(TestEvidence {
            id,
            case_id,
            status_id,
            status,
            title_digest,
            section_id,
            test_fingerprint,
        })
    }

    fn parse_result_for_scope(
        scope: &TestRailScope,
        value: &Value,
        known_test_ids: &BTreeSet<u64>,
    ) -> Result<RedactedResultMetadata, TestRailError> {
        let object = value.as_object().ok_or(TestRailError::MalformedResponse)?;
        let id = required_u64(object, "id")?;
        let test_id = required_u64(object, "test_id")?;
        let status_id = required_u16(object, "status_id")?;
        let created_on = required_u64(object, "created_on")?;
        if !known_test_ids.is_empty() && !known_test_ids.contains(&test_id) {
            return Err(TestRailError::TestDrift);
        }
        if !scope.allowed_status_ids.contains(&status_id) {
            return Err(TestRailError::StatusNotAllowlisted);
        }
        if !scope.result.result_ids.is_empty() && !scope.result.result_ids.contains(&id) {
            return Err(TestRailError::ResultDrift);
        }
        let defects = parse_defects(object.get("defects"))?;
        validate_defects(&defects, &scope.defects)?;
        let comment_digest = match object.get("comment") {
            None | Some(Value::Null) => None,
            Some(Value::String(comment)) => {
                if comment.len() > MAX_COMMENT_BYTES {
                    return Err(TestRailError::ResponseTooLarge);
                }
                Some(Digest::from_text(comment))
            }
            _ => return Err(TestRailError::MalformedResponse),
        };
        let comment_bytes = object
            .get("comment")
            .and_then(Value::as_str)
            .map_or(0, str::len);
        let version_digest = match object.get("version") {
            None | Some(Value::Null) => None,
            Some(Value::String(version)) => {
                if version.len() > MAX_VERSION_BYTES {
                    return Err(TestRailError::ResponseTooLarge);
                }
                Some(Digest::from_text(version))
            }
            _ => return Err(TestRailError::MalformedResponse),
        };
        let status = status_for_id(status_id, status_label(scope, status_id));
        let result_fingerprint = Digest::from_serializable(&(
            id,
            test_id,
            status_id,
            status,
            created_on,
            &defects,
            comment_digest.clone(),
            version_digest.clone(),
        ));
        Ok(RedactedResultMetadata {
            id,
            test_id,
            status_id,
            status,
            created_on,
            defect_count: defects.len(),
            defect_digests: defects,
            comment_present: comment_digest.is_some(),
            comment_bytes,
            comment_digest,
            version_digest,
            redaction: RedactionState::CommentAndDefectMetadataRedacted,
            result_fingerprint,
        })
    }

    fn build_projection(
        &self,
        run: RunEvidence,
        mut tests: Vec<TestEvidence>,
        mut results: Vec<RedactedResultMetadata>,
    ) -> Result<TestRailResultProjection, TestRailError> {
        tests.sort_by_key(|test| test.id);
        results.sort_by_key(|result| (result.test_id, result.created_on, result.id));
        let scope = &self.registration.scope;
        let expected_test_ids = scope.expected_test_ids();
        if !expected_test_ids.is_empty() {
            let actual: BTreeSet<_> = tests.iter().map(|test| test.id).collect();
            if actual != expected_test_ids {
                return Err(TestRailError::TestDrift);
            }
        }
        let section_verified = tests
            .iter()
            .all(|test| test.section_id == Some(scope.section.id));
        let mut counts = StatusCounts::default();
        let mut latest_by_test: BTreeMap<u64, &RedactedResultMetadata> = BTreeMap::new();
        for result in &results {
            let replace = latest_by_test.get(&result.test_id).is_none_or(|current| {
                (result.created_on, result.id) > (current.created_on, current.id)
            });
            if replace {
                latest_by_test.insert(result.test_id, result);
            }
        }
        let mut source_verified = true;
        for test in &tests {
            if let Some(result) = latest_by_test.get(&test.id) {
                counts.add(result.status);
                if !source_version_matches(scope, result) {
                    source_verified = false;
                }
            } else {
                counts.add(test.status);
                source_verified = false;
            }
        }
        for result in &results {
            if !tests.iter().any(|test| test.id == result.test_id) {
                return Err(TestRailError::TestDrift);
            }
        }
        let status = overall_status(&counts);
        let complete = section_verified
            && source_verified
            && !tests.is_empty()
            && !results.is_empty()
            && counts.provider_unknown == 0;
        let test_fingerprint = Digest::from_serializable(&tests);
        let result_fingerprint = Digest::from_serializable(&results);
        let status_fingerprint = Digest::from_serializable(&counts);
        let provenance = self.transport.provenance();
        let mut projection = TestRailResultProjection {
            scope_digest: scope.scope_digest(),
            version_digest: scope.version_digest(),
            contract_digest: scope.contract_digest(),
            provider_digest: self.registration.provider.digest(),
            permission_digest: self.registration.permission_snapshot.digest.clone(),
            revision_digest: scope.revision_digest(),
            host_digest: scope.host_digest(),
            project_digest: scope.project_digest(),
            suite_digest: scope.suite_digest(),
            section_digest: scope.section_digest(),
            run_digest: scope.run_digest(),
            test_fingerprint,
            result_fingerprint,
            status_fingerprint,
            source_digest: scope.source_digest(),
            mission_digest: scope.mission_digest(),
            hartevo_project_digest: scope.hartevo_project_digest(),
            work_product_digest: scope.work_product_digest(),
            run_revision: scope.run.revision,
            run_updated_on: run.updated_on,
            status,
            counts,
            run,
            tests,
            results,
            provenance,
            complete,
            source_verified,
            section_verified,
            metadata_redacted: true,
            raw_payload_retained: false,
            connected: false,
            native: false,
            first_party: false,
            verified: false,
            projection_digest: Digest::from_text("placeholder"),
        };
        projection.projection_digest = projection.compute_digest();
        projection.validate_integrity()?;
        Ok(projection)
    }
}

fn required_u64(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<u64, TestRailError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(TestRailError::MalformedResponse)
}

fn required_u16(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<u16, TestRailError> {
    let value = required_u64(object, key)?;
    u16::try_from(value).map_err(|_| TestRailError::ProviderDrift)
}

fn optional_u64(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<u64>, TestRailError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(TestRailError::MalformedResponse),
    }
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, TestRailError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(TestRailError::MalformedResponse)
}

fn parse_next_offset(endpoint: TestRailEndpoint, next: &str) -> Result<usize, TestRailError> {
    let expected = endpoint.base_path();
    if !next.starts_with(expected) || next.contains("..") || next.contains('#') {
        return Err(TestRailError::ProviderDrift);
    }
    let offset = next
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("offset="))
        .ok_or(TestRailError::ProviderDrift)?;
    offset
        .parse::<usize>()
        .map_err(|_| TestRailError::ProviderDrift)
}

struct Page {
    items: Vec<Value>,
    next_offset: Option<usize>,
}

fn status_label(scope: &TestRailScope, id: u16) -> Option<&str> {
    scope
        .statuses
        .iter()
        .find(|status| status.id == id)
        .map(|status| status.label.as_str())
}

pub fn status_for_id(id: u16, label: Option<&str>) -> TestRailResultStatus {
    if let Some(label) = label {
        let label = label.to_ascii_lowercase();
        if label.contains("expire") {
            return TestRailResultStatus::Expired;
        }
        if label.contains("skip") {
            return TestRailResultStatus::Skipped;
        }
        if label.contains("partial") {
            return TestRailResultStatus::Partial;
        }
    }
    match id {
        1 => TestRailResultStatus::Passed,
        2 => TestRailResultStatus::Blocked,
        3 => TestRailResultStatus::Untested,
        4 => TestRailResultStatus::Partial,
        5 => TestRailResultStatus::Failed,
        _ => TestRailResultStatus::ProviderUnknown,
    }
}

fn overall_status(counts: &StatusCounts) -> TestRailResultStatus {
    if counts.total == 0 {
        return TestRailResultStatus::Untested;
    }
    if counts.provider_unknown > 0 {
        return TestRailResultStatus::ProviderUnknown;
    }
    if counts.failed == counts.total {
        return TestRailResultStatus::Failed;
    }
    if counts.blocked == counts.total {
        return TestRailResultStatus::Blocked;
    }
    if counts.skipped == counts.total {
        return TestRailResultStatus::Skipped;
    }
    if counts.untested == counts.total {
        return TestRailResultStatus::Untested;
    }
    if counts.expired == counts.total {
        return TestRailResultStatus::Expired;
    }
    if counts.passed == counts.total {
        return TestRailResultStatus::Passed;
    }
    TestRailResultStatus::Partial
}

fn parse_defects(value: Option<&Value>) -> Result<Vec<Digest>, TestRailError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(raw) = value.as_str() else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err(TestRailError::MalformedResponse);
    };
    if raw.len() > MAX_DEFECTS * MAX_DEFECT_BYTES {
        return Err(TestRailError::ResponseTooLarge);
    }
    let mut defects = Vec::new();
    for defect in raw
        .split(',')
        .map(str::trim)
        .filter(|defect| !defect.is_empty())
    {
        if defects.len() >= MAX_DEFECTS || defect.len() > MAX_DEFECT_BYTES {
            return Err(TestRailError::ResponseTooLarge);
        }
        defects.push(Digest::from_text(defect));
    }
    defects.sort();
    defects.dedup();
    Ok(defects)
}

fn validate_defects(actual: &[Digest], expected: &[DefectIdentity]) -> Result<(), TestRailError> {
    if expected.is_empty() {
        return Ok(());
    }
    let expected: BTreeSet<_> = expected
        .iter()
        .map(|defect| Digest::from_text(&defect.key))
        .collect();
    if actual.iter().any(|digest| !expected.contains(digest)) || actual.len() != expected.len() {
        return Err(TestRailError::DefectDrift);
    }
    Ok(())
}

fn source_version_matches(scope: &TestRailScope, result: &RedactedResultMetadata) -> bool {
    let Some(version_digest) = &result.version_digest else {
        return false;
    };
    version_digest == &Digest::from_text(scope.source.binding_value())
}
