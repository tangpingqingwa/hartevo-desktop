use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    SALESFORCE_BLOCKED_ENV, SALESFORCE_CRM_RESULT_SCHEMA_VERSION, SALESFORCE_MAX_APPROVAL_STEPS,
    SALESFORCE_MAX_HISTORY_ENTRIES, SALESFORCE_MAX_PAGES, SALESFORCE_PROVIDER_ID,
    SalesforceCrmResultError,
    model::{
        ApprovalFixture, Digest, HistoryFixture, ModelError, PluginVersion, ProviderErrorEvidence,
        ProviderErrorKind, QuerySeam, RegistrationState, SalesforceField, SalesforceObject,
        SalesforceReadRequest, SalesforceRecordFixture, SalesforceRecordProjection,
        SalesforceRegistration, SalesforceScope, SecretReference, TransportProvenance,
        canonical_digest,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Salesforce provider version is empty or invalid")]
    InvalidVersion,
    #[error("Layer 1 cannot register a native Salesforce provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub rest_query: bool,
    pub graphql_query: bool,
    pub live_execution: bool,
    pub native: bool,
}

impl SalesforceProviderDefinition {
    pub fn new(provenance: TransportProvenance) -> Result<Self, ProviderDefinitionError> {
        Self::with_version(PluginVersion::new(1, 0, 0), provenance)
    }

    pub fn with_version(
        provider_version: PluginVersion,
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        if provider_version != PluginVersion::new(1, 0, 0) || provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_fields(
            "salesforce-provider-capability/v1",
            &[
                SALESFORCE_CRM_RESULT_SCHEMA_VERSION.to_owned(),
                SALESFORCE_PROVIDER_ID.to_owned(),
                provider_version.to_string(),
                format!("{provenance:?}"),
                "rest_query".to_owned(),
                "graphql_query".to_owned(),
                "live_execution=false".to_owned(),
                "native=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: SALESFORCE_CRM_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: SALESFORCE_PROVIDER_ID.to_owned(),
            provider_version,
            capability_digest,
            provenance,
            rest_query: true,
            graphql_query: true,
            live_execution: false,
            native: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != SALESFORCE_CRM_RESULT_SCHEMA_VERSION
            || self.provider_id != SALESFORCE_PROVIDER_ID
            || self.provider_version != PluginVersion::new(1, 0, 0)
            || !self.rest_query
            || !self.graphql_query
            || self.live_execution
            || self.native
        {
            Err(ProviderDefinitionError::InvalidVersion)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SalesforceTransportError {
    #[error("Salesforce returned HTTP {status_code} ({kind:?})")]
    HttpStatus {
        status_code: u16,
        kind: ProviderErrorKind,
        diagnostic_digest: Digest,
    },
    #[error("Salesforce response could not be decoded")]
    Decode { diagnostic_digest: Digest },
    #[error("Salesforce transport timed out")]
    Timeout { diagnostic_digest: Digest },
    #[error("BLOCKED_ENV: native Salesforce OAuth/HTTPS is unavailable")]
    BlockedEnv,
    #[error("Salesforce deterministic transport has no response")]
    FixtureExhausted,
    #[error("Salesforce pagination cursor repeated")]
    PaginationLoop,
}

impl SalesforceTransportError {
    pub fn http(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        Self::HttpStatus {
            status_code,
            kind: kind_for_status(status_code),
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn timeout(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::Timeout {
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::HttpStatus { kind, .. } => *kind,
            Self::Decode { .. } => ProviderErrorKind::Decode,
            Self::Timeout { .. } => ProviderErrorKind::Timeout,
            Self::BlockedEnv => ProviderErrorKind::BlockedEnv,
            Self::FixtureExhausted => ProviderErrorKind::Unknown,
            Self::PaginationLoop => ProviderErrorKind::Pagination,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status_code, .. } => Some(*status_code),
            _ => None,
        }
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        let diagnostic = match self {
            Self::HttpStatus {
                diagnostic_digest, ..
            }
            | Self::Decode { diagnostic_digest }
            | Self::Timeout { diagnostic_digest } => diagnostic_digest.as_str(),
            Self::BlockedEnv => SALESFORCE_BLOCKED_ENV,
            Self::FixtureExhausted => "fixture-exhausted",
            Self::PaginationLoop => "pagination-loop",
        };
        ProviderErrorEvidence::new(self.kind(), self.status_code(), diagnostic)
    }
}

pub trait SalesforceTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn send(
        &mut self,
        request: &SalesforceHttpRequest,
    ) -> Result<SalesforceHttpResponse, SalesforceTransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceHttpRequest {
    pub api_version: String,
    pub object: SalesforceObject,
    pub record_id: String,
    pub fields: Vec<SalesforceField>,
    pub seam: QuerySeam,
    pub include_approval: bool,
    pub include_history: bool,
    pub page: u8,
    pub cursor_digest: Option<Digest>,
    pub expected_record_revision: Digest,
    pub path: String,
    pub query_text: String,
    pub approval_query_text: Option<String>,
    pub history_query_text: Option<String>,
    pub request_digest: Digest,
}

impl SalesforceHttpRequest {
    pub fn new(
        scope: &SalesforceScope,
        request: &SalesforceReadRequest,
    ) -> Result<Self, SalesforceCrmResultError> {
        Self::from_scope(scope, request)
    }

    pub(crate) fn from_scope(
        scope: &SalesforceScope,
        request: &SalesforceReadRequest,
    ) -> Result<Self, SalesforceCrmResultError> {
        request.validate_for(scope)?;
        let fields = request.selected_fields_with_revision();
        let api_version = scope.api_version().as_str().to_owned();
        let path = match request.seam {
            QuerySeam::RestSoql => format!("/services/data/{api_version}/query/"),
            QuerySeam::GraphQl => format!("/services/data/{api_version}/graphql"),
        };
        let query_text =
            build_query_text(request.object, &request.record_id, &fields, request.seam);
        let approval_query_text = request.include_approval.then(|| {
            build_metadata_query(
                request.object,
                &request.record_id,
                request.seam,
                MetadataQueryKind::Approval,
            )
        });
        let history_query_text = request.include_history.then(|| {
            build_metadata_query(
                request.object,
                &request.record_id,
                request.seam,
                MetadataQueryKind::History,
            )
        });
        let request_digest = request_digest(
            &api_version,
            request.object,
            &request.record_id,
            &fields,
            request.seam,
            request.include_approval,
            request.include_history,
            1,
            None,
            scope.record_revision(),
        );
        Ok(Self {
            api_version,
            object: request.object,
            record_id: request.record_id.clone(),
            fields,
            seam: request.seam,
            include_approval: request.include_approval,
            include_history: request.include_history,
            page: 1,
            cursor_digest: None,
            expected_record_revision: scope.record_revision().clone(),
            path,
            query_text,
            approval_query_text,
            history_query_text,
            request_digest,
        })
    }

    pub(crate) fn next_page(&self, cursor_digest: Digest) -> Self {
        let page = self.page.saturating_add(1);
        let mut next = self.clone();
        next.page = page;
        next.cursor_digest = Some(cursor_digest);
        next.query_text = build_query_text(self.object, &self.record_id, &self.fields, self.seam);
        next.request_digest = request_digest(
            &next.api_version,
            next.object,
            &next.record_id,
            &next.fields,
            next.seam,
            next.include_approval,
            next.include_history,
            next.page,
            next.cursor_digest.as_ref(),
            &next.expected_record_revision,
        );
        next
    }

    pub fn path_and_query(&self) -> String {
        match (self.seam, &self.cursor_digest) {
            (QuerySeam::RestSoql, None) => {
                format!("{}?q={}", self.path, percent_encode(&self.query_text))
            }
            (QuerySeam::RestSoql, Some(cursor)) => format!(
                "{}?page={}&cursorDigest={}",
                self.path,
                self.page,
                cursor.as_str()
            ),
            (QuerySeam::GraphQl, _) => self.path.clone(),
        }
    }

    pub fn is_read_only(&self) -> bool {
        [
            self.query_text.as_str(),
            self.approval_query_text.as_deref().unwrap_or_default(),
            self.history_query_text.as_deref().unwrap_or_default(),
        ]
        .into_iter()
        .all(|query| !query.to_ascii_lowercase().contains("mutation"))
    }

    pub fn validate_integrity(&self) -> Result<(), SalesforceCrmResultError> {
        let expected_path = match self.seam {
            QuerySeam::RestSoql => format!("/services/data/{}/query/", self.api_version),
            QuerySeam::GraphQl => format!("/services/data/{}/graphql", self.api_version),
        };
        let expected_query =
            build_query_text(self.object, &self.record_id, &self.fields, self.seam);
        let expected_approval_query = self.include_approval.then(|| {
            build_metadata_query(
                self.object,
                &self.record_id,
                self.seam,
                MetadataQueryKind::Approval,
            )
        });
        let expected_history_query = self.include_history.then(|| {
            build_metadata_query(
                self.object,
                &self.record_id,
                self.seam,
                MetadataQueryKind::History,
            )
        });
        let expected_digest = request_digest(
            &self.api_version,
            self.object,
            &self.record_id,
            &self.fields,
            self.seam,
            self.include_approval,
            self.include_history,
            self.page,
            self.cursor_digest.as_ref(),
            &self.expected_record_revision,
        );
        if self.path != expected_path
            || self.query_text != expected_query
            || self.approval_query_text != expected_approval_query
            || self.history_query_text != expected_history_query
            || self.request_digest != expected_digest
            || self.page == 0
            || self.fields.is_empty()
            || !self.is_read_only()
        {
            Err(SalesforceCrmResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

fn request_digest(
    api_version: &str,
    object: SalesforceObject,
    record_id: &str,
    fields: &[SalesforceField],
    seam: QuerySeam,
    include_approval: bool,
    include_history: bool,
    page: u8,
    cursor_digest: Option<&Digest>,
    expected_record_revision: &Digest,
) -> Digest {
    canonical_digest(&(
        api_version,
        object,
        record_id,
        fields,
        seam,
        include_approval,
        include_history,
        page,
        cursor_digest,
        expected_record_revision,
    ))
}

fn build_query_text(
    object: SalesforceObject,
    record_id: &str,
    fields: &[SalesforceField],
    seam: QuerySeam,
) -> String {
    let field_names = fields
        .iter()
        .map(|field| match seam {
            QuerySeam::RestSoql => field.api_name(),
            QuerySeam::GraphQl => field.graphql_name(),
        })
        .collect::<Vec<_>>();
    match seam {
        QuerySeam::RestSoql => format!(
            "SELECT {} FROM {} WHERE Id = '{}' LIMIT 1",
            field_names.join(","),
            object.api_name(),
            record_id
        ),
        QuerySeam::GraphQl => format!(
            "query SalesforceRecord {{ uiapi {{ query {{ {}(where: {{ Id: {{ eq: \"{}\" }} }}) {{ edges {{ node {{ {} }} }} }} }} }} }}",
            object.api_name(),
            record_id,
            field_names.join(" ")
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataQueryKind {
    Approval,
    History,
}

fn build_metadata_query(
    object: SalesforceObject,
    record_id: &str,
    seam: QuerySeam,
    kind: MetadataQueryKind,
) -> String {
    match (seam, kind) {
        (QuerySeam::RestSoql, MetadataQueryKind::Approval) => format!(
            "SELECT Status,CreatedDate,CompletedDate,LastActorId FROM ProcessInstance WHERE TargetObjectId = '{record_id}' ORDER BY CreatedDate DESC LIMIT {SALESFORCE_MAX_APPROVAL_STEPS}"
        ),
        (QuerySeam::RestSoql, MetadataQueryKind::History) => format!(
            "SELECT Field,CreatedDate,OldValue,NewValue FROM {}History WHERE ParentId = '{record_id}' ORDER BY CreatedDate DESC LIMIT {SALESFORCE_MAX_HISTORY_ENTRIES}",
            object.api_name()
        ),
        (QuerySeam::GraphQl, MetadataQueryKind::Approval) => format!(
            "query SalesforceApprovalMetadata {{ uiapi {{ query {{ ProcessInstance(where: {{ TargetObjectId: {{ eq: \"{record_id}\" }} }}, first: {SALESFORCE_MAX_APPROVAL_STEPS}) {{ edges {{ node {{ Status CreatedDate CompletedDate }} }} }} }} }} }}"
        ),
        (QuerySeam::GraphQl, MetadataQueryKind::History) => format!(
            "query SalesforceHistoryMetadata {{ uiapi {{ query {{ {}History(where: {{ ParentId: {{ eq: \"{record_id}\" }} }}, first: {SALESFORCE_MAX_HISTORY_ENTRIES}) {{ edges {{ node {{ Field CreatedDate OldValue NewValue }} }} }} }} }} }}",
            object.api_name()
        ),
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'A' + value - 10),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforcePage {
    pub page_number: u8,
    pub record: Option<SalesforceRecordProjection>,
    pub next_records_url_digest: Option<Digest>,
    pub done: bool,
    pub page_digest: Digest,
    pub raw_payload_retained: bool,
}

impl SalesforcePage {
    pub fn from_fixture(
        request: &SalesforceHttpRequest,
        fixture: SalesforceRecordFixture,
        next_records_url: Option<&str>,
        done: bool,
    ) -> Result<Self, SalesforceCrmResultError> {
        if fixture.object != request.object || fixture.record_id != request.record_id {
            return Err(SalesforceCrmResultError::RecordDrift);
        }
        let record = SalesforceRecordProjection::from_fixture(
            &fixture,
            &request.fields,
            request.include_approval,
            request.include_history,
        )?;
        let next_records_url_digest = next_records_url.map(Digest::from_text);
        let mut page = Self {
            page_number: request.page,
            record: Some(record),
            next_records_url_digest,
            done,
            page_digest: Digest::from_text("placeholder"),
            raw_payload_retained: false,
        };
        page.page_digest = canonical_digest(&(
            page.page_number,
            &page.record,
            &page.next_records_url_digest,
            page.done,
            page.raw_payload_retained,
        ));
        Ok(page)
    }

    pub fn empty(
        request: &SalesforceHttpRequest,
        next_records_url: Option<&str>,
        done: bool,
    ) -> Self {
        let next_records_url_digest = next_records_url.map(Digest::from_text);
        let mut page = Self {
            page_number: request.page,
            record: None,
            next_records_url_digest,
            done,
            page_digest: Digest::from_text("placeholder"),
            raw_payload_retained: false,
        };
        page.page_digest = canonical_digest(&(
            page.page_number,
            &page.record,
            &page.next_records_url_digest,
            page.done,
            page.raw_payload_retained,
        ));
        page
    }

    pub fn validate(&self) -> Result<(), SalesforceCrmResultError> {
        if self.page_number == 0
            || self.raw_payload_retained
            || self
                .record
                .as_ref()
                .is_some_and(|record| record.validate().is_err())
            || self.page_digest
                != canonical_digest(&(
                    self.page_number,
                    &self.record,
                    &self.next_records_url_digest,
                    self.done,
                    self.raw_payload_retained,
                ))
        {
            Err(SalesforceCrmResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceHttpResponse {
    pub status_code: u16,
    pub response_digest: Digest,
    pub page: Option<SalesforcePage>,
    pub raw_payload_retained: bool,
}

impl SalesforceHttpResponse {
    pub fn ok(page: SalesforcePage, response_seed: impl AsRef<[u8]>) -> Self {
        Self {
            status_code: 200,
            response_digest: Digest::from_text(response_seed),
            page: Some(page),
            raw_payload_retained: false,
        }
    }

    pub fn status(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        Self {
            status_code,
            response_digest: Digest::from_text(diagnostic),
            page: None,
            raw_payload_retained: false,
        }
    }

    pub fn from_json(
        request: &SalesforceHttpRequest,
        status_code: u16,
        raw_payload: &str,
    ) -> Result<Self, SalesforceTransportError> {
        let response_digest = Digest::from_text(raw_payload);
        if !(200..=299).contains(&status_code) {
            return Ok(Self {
                status_code,
                response_digest,
                page: None,
                raw_payload_retained: false,
            });
        }
        let root = serde_json::from_str::<Value>(raw_payload).map_err(|_| {
            SalesforceTransportError::Decode {
                diagnostic_digest: response_digest.clone(),
            }
        })?;
        let record_value = find_record_value(&root);
        let mut page = match record_value {
            Some(record_value) => {
                let fixture = fixture_from_json(request, record_value)?;
                SalesforcePage::from_fixture(
                    request,
                    fixture,
                    root.get("nextRecordsUrl").and_then(Value::as_str),
                    root.get("done").and_then(Value::as_bool).unwrap_or(true),
                )
                .map_err(|error| SalesforceTransportError::Decode {
                    diagnostic_digest: Digest::from_text(error.to_string()),
                })?
            }
            None => SalesforcePage::empty(
                request,
                root.get("nextRecordsUrl").and_then(Value::as_str),
                root.get("done").and_then(Value::as_bool).unwrap_or(true),
            ),
        };
        if request.include_approval || request.include_history {
            // Approval/history are only accepted through the typed fixture
            // seam in Layer 1. Native JSON adapters may add them later, but
            // this parser never retains or exposes arbitrary metadata.
            if let Some(record) = page.record.as_mut() {
                if !request.include_approval {
                    record.approval = ApprovalFixture::default().into_metadata().map_err(|_| {
                        SalesforceTransportError::Decode {
                            diagnostic_digest: response_digest.clone(),
                        }
                    })?;
                }
                if !request.include_history {
                    record.history = HistoryFixture::default().into_metadata().map_err(|_| {
                        SalesforceTransportError::Decode {
                            diagnostic_digest: response_digest.clone(),
                        }
                    })?;
                }
                record.record_digest = record.compute_digest();
                page.page_digest = canonical_digest(&(
                    page.page_number,
                    &page.record,
                    &page.next_records_url_digest,
                    page.done,
                    page.raw_payload_retained,
                ));
            }
        }
        Ok(Self {
            status_code,
            response_digest,
            page: Some(page),
            raw_payload_retained: false,
        })
    }

    pub fn validate(&self) -> Result<(), SalesforceCrmResultError> {
        if self.raw_payload_retained
            || !is_valid_status_code(self.status_code)
            || self
                .page
                .as_ref()
                .is_some_and(|page| page.validate().is_err())
        {
            Err(SalesforceCrmResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

fn fixture_from_json(
    request: &SalesforceHttpRequest,
    record_value: &Value,
) -> Result<SalesforceRecordFixture, SalesforceTransportError> {
    let record_id = request
        .fields
        .iter()
        .find(|field| field.is_identifier() && field.api_name() == "Id")
        .and_then(|field| record_value.get(field.api_name()))
        .and_then(value_as_string)
        .unwrap_or_else(|| request.record_id.clone());
    let revision = record_value
        .get(SalesforceField::RecordRevision.api_name())
        .and_then(value_as_string)
        .map_or_else(
            || request.expected_record_revision.clone(),
            Digest::from_text,
        );
    let mut fixture =
        SalesforceRecordFixture::new(request.object, record_id, revision).map_err(|_| {
            SalesforceTransportError::Decode {
                diagnostic_digest: Digest::from_text("invalid-record-identity"),
            }
        })?;
    for field in &request.fields {
        if let Some(value) = record_value.get(field.api_name())
            && let Some(value) = json_to_fixture_value(value)
        {
            fixture = fixture.with_field(*field, value);
        }
    }
    Ok(fixture)
}

fn find_record_value(value: &Value) -> Option<&Value> {
    if let Some(records) = value.get("records").and_then(Value::as_array) {
        return records.first();
    }
    if value.get("node").is_some() {
        return value.get("node");
    }
    match value {
        Value::Object(map) => map.values().find_map(find_record_value),
        Value::Array(values) => values.iter().find_map(find_record_value),
        _ => None,
    }
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Object(map) => map.get("value").and_then(value_as_string),
        _ => None,
    }
}

fn json_to_fixture_value(value: &Value) -> Option<crate::SalesforceFixtureValue> {
    let value = match value {
        Value::Object(map) => map.get("value")?,
        value => value,
    };
    match value {
        Value::String(value) => Some(crate::SalesforceFixtureValue::Text(value.clone())),
        Value::Number(value) => Some(crate::SalesforceFixtureValue::Decimal(value.to_string())),
        Value::Bool(value) => Some(crate::SalesforceFixtureValue::Boolean(*value)),
        Value::Null => Some(crate::SalesforceFixtureValue::Null),
        Value::Object(_) | Value::Array(_) => None,
    }
}

fn is_valid_status_code(status_code: u16) -> bool {
    (100..=599).contains(&status_code)
}

fn kind_for_status(status_code: u16) -> ProviderErrorKind {
    match status_code {
        400 => ProviderErrorKind::BadRequest,
        401 => ProviderErrorKind::Unauthenticated,
        403 => ProviderErrorKind::PermissionDenied,
        404 => ProviderErrorKind::NotFound,
        409 => ProviderErrorKind::Conflict,
        429 => ProviderErrorKind::RateLimited,
        500..=599 => ProviderErrorKind::ServerFailure,
        _ => ProviderErrorKind::Unknown,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectedSalesforceResponses {
    pub responses: Vec<SalesforceHttpResponse>,
    pub pagination: crate::PaginationEvidence,
}

#[derive(Clone, Debug)]
pub struct RecordingSalesforceTransport {
    responses: VecDeque<Result<SalesforceHttpResponse, SalesforceTransportError>>,
    requests: Vec<SalesforceHttpRequest>,
    provenance: TransportProvenance,
}

impl Default for RecordingSalesforceTransport {
    fn default() -> Self {
        Self::recording([])
    }
}

impl RecordingSalesforceTransport {
    pub fn fixture(
        responses: impl IntoIterator<Item = Result<SalesforceHttpResponse, SalesforceTransportError>>,
    ) -> Self {
        Self::with_provenance(responses, TransportProvenance::Fixture)
    }

    pub fn recording(
        responses: impl IntoIterator<Item = Result<SalesforceHttpResponse, SalesforceTransportError>>,
    ) -> Self {
        Self::with_provenance(responses, TransportProvenance::Recording)
    }

    pub fn fake(
        responses: impl IntoIterator<Item = Result<SalesforceHttpResponse, SalesforceTransportError>>,
    ) -> Self {
        Self::with_provenance(responses, TransportProvenance::Fake)
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<SalesforceHttpResponse, SalesforceTransportError>>,
    ) -> Self {
        Self::with_provenance(responses, TransportProvenance::Loopback)
    }

    pub fn with_provenance(
        responses: impl IntoIterator<Item = Result<SalesforceHttpResponse, SalesforceTransportError>>,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance,
        }
    }

    pub fn push_response(
        &mut self,
        response: Result<SalesforceHttpResponse, SalesforceTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[SalesforceHttpRequest] {
        &self.requests
    }

    pub fn response_count(&self) -> usize {
        self.responses.len()
    }
}

impl SalesforceTransport for RecordingSalesforceTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn send(
        &mut self,
        request: &SalesforceHttpRequest,
    ) -> Result<SalesforceHttpResponse, SalesforceTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(SalesforceTransportError::FixtureExhausted))
    }
}

pub type FixtureSalesforceTransport = RecordingSalesforceTransport;
pub type FakeSalesforceTransport = RecordingSalesforceTransport;
pub type LoopbackSalesforceTransport = RecordingSalesforceTransport;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl SalesforceTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &SalesforceHttpRequest,
    ) -> Result<SalesforceHttpResponse, SalesforceTransportError> {
        Err(SalesforceTransportError::BlockedEnv)
    }
}

pub struct SalesforceProvider<T = BlockedEnvTransport> {
    scope: SalesforceScope,
    secret_reference: SecretReference,
    definition: SalesforceProviderDefinition,
    registration: SalesforceRegistration,
    transport: T,
}

impl<T: fmt::Debug> fmt::Debug for SalesforceProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SalesforceProvider")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: SalesforceTransport> SalesforceProvider<T> {
    pub fn new(
        scope: SalesforceScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, SalesforceCrmResultError> {
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(SalesforceCrmResultError::ScopeMismatch(
                "secret reference and provider scope differ".to_owned(),
            ));
        }
        let definition = SalesforceProviderDefinition::new(transport.provenance())?;
        let registration = SalesforceRegistration::new(
            PluginVersion::new(1, 0, 0),
            definition.provider_version,
            definition.provider_digest(),
            &scope,
        );
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    pub fn scope(&self) -> &SalesforceScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn definition(&self) -> &SalesforceProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn registration(&self) -> &SalesforceRegistration {
        &self.registration
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RevocationReceipt, SalesforceCrmResultError> {
        self.registration
            .revoke()
            .map_err(|error| SalesforceCrmResultError::RegistrationDrift(error.to_string()))
    }

    pub fn restore_registration(&mut self) -> Result<(), SalesforceCrmResultError> {
        self.registration
            .restore()
            .map_err(|error| SalesforceCrmResultError::RegistrationDrift(error.to_string()))
    }

    pub fn revoke_secret(&mut self) -> Result<(), SalesforceCrmResultError> {
        self.secret_reference
            .revoke()
            .map_err(|_| SalesforceCrmResultError::SecretRevoked)
    }

    pub fn restore_secret(&mut self) -> Result<(), SalesforceCrmResultError> {
        self.secret_reference
            .restore()
            .map_err(|_| SalesforceCrmResultError::SecretRevoked)
    }

    pub(crate) fn collect(
        &mut self,
        request: &SalesforceHttpRequest,
        max_pages: u8,
    ) -> Result<CollectedSalesforceResponses, SalesforceTransportError> {
        if self.registration.state != RegistrationState::Active {
            return Err(SalesforceTransportError::HttpStatus {
                status_code: 409,
                kind: ProviderErrorKind::Conflict,
                diagnostic_digest: Digest::from_text("registration-revoked"),
            });
        }
        if self.secret_reference.is_revoked() {
            return Err(SalesforceTransportError::HttpStatus {
                status_code: 401,
                kind: ProviderErrorKind::Unauthenticated,
                diagnostic_digest: Digest::from_text("secret-revoked"),
            });
        }
        if max_pages == 0 || max_pages > SALESFORCE_MAX_PAGES {
            return Err(SalesforceTransportError::PaginationLoop);
        }
        let mut responses = Vec::new();
        let mut cursors = BTreeSet::new();
        let mut next_request = request.clone();
        let mut next_records_url_digests = Vec::new();
        let mut truncated = false;
        let mut loop_detected = false;
        for _ in 0..max_pages {
            let response = self.transport.send(&next_request)?;
            let next_cursor = response
                .page
                .as_ref()
                .and_then(|page| page.next_records_url_digest.clone());
            let done = response.page.as_ref().is_none_or(|page| page.done);
            responses.push(response);
            if let Some(cursor) = next_cursor {
                next_records_url_digests.push(cursor.clone());
                if !cursors.insert(cursor.clone()) {
                    loop_detected = true;
                    truncated = true;
                    break;
                }
                if done {
                    break;
                }
                if responses.len() >= usize::from(max_pages) {
                    truncated = true;
                    break;
                }
                next_request = next_request.next_page(cursor);
            } else {
                break;
            }
        }
        if responses.len() >= usize::from(max_pages)
            && responses
                .last()
                .and_then(|response| response.page.as_ref())
                .is_some_and(|page| page.next_records_url_digest.is_some() && !page.done)
        {
            truncated = true;
        }
        Ok(CollectedSalesforceResponses {
            pagination: crate::PaginationEvidence {
                pages: responses.len() as u8,
                next_records_url_digests,
                truncated,
                loop_detected,
            },
            responses,
        })
    }
}

impl ApprovalFixture {
    fn into_metadata(self) -> Result<crate::ApprovalMetadata, ModelError> {
        crate::ApprovalMetadata::from_fixture(&self)
    }
}

impl HistoryFixture {
    fn into_metadata(self) -> Result<crate::HistoryMetadata, ModelError> {
        crate::HistoryMetadata::from_fixture(&self)
    }
}
