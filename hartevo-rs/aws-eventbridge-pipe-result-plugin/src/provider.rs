//! Read-only AWS EventBridge Pipes provider boundary.
//!
//! A Layer-1 transport can be recording, fixture, loopback, or
//! `BLOCKED_ENV`. There is deliberately no native credential, SigV4 signer,
//! HTTPS client, event payload, or lifecycle-effect method.

use std::{collections::VecDeque, fmt, fmt::Write};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;
use thiserror::Error;

use crate::error::{
    AwsEventBridgePipeError, AwsEventBridgePipeTransportError, ErrorClassification, Result,
};
use crate::model::{
    AwsEventBridgePipeScope, CurrentPipeState, Cursor, DesiredPipeState, Digest, PipeDescription,
    PipeListFilter, PipeSummary, TransportProvenance,
};
use crate::service::AwsEventBridgePipeRegistration;
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION,
    PROVIDER_ID,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsEventBridgePipeProviderError {
    #[error("EventBridge Pipes provider model error: {0}")]
    Model(#[from] AwsEventBridgePipeError),
    #[error("EventBridge Pipes provider transport error: {0}")]
    Transport(#[from] AwsEventBridgePipeTransportError),
    #[error("EventBridge Pipes provider page binding or digest is invalid")]
    PageBinding,
    #[error("EventBridge Pipes provider revision is incompatible")]
    ProviderRevision,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PipeOperation {
    #[serde(rename = "ListPipes")]
    ListPipes,
    #[serde(rename = "DescribePipe")]
    DescribePipe,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: PipeOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListPipesRequest {
    scope: AwsEventBridgePipeScope,
    filter: PipeListFilter,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListPipesRequest {
    pub fn new(
        scope: &AwsEventBridgePipeScope,
        filter: PipeListFilter,
        page_number: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        if !(1..=MAX_PAGES).contains(&page_number) {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
            if cursor.page_number() != page_number {
                return Err(AwsEventBridgePipeError::CursorMismatch);
            }
        }
        let request_digest = Digest::from_parts(
            "aws-eventbridge-pipe-list-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                ("page", page_number.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            page_number,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsEventBridgePipeScope {
        &self.scope
    }

    pub fn filter(&self) -> &PipeListFilter {
        &self.filter
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        let mut query = Vec::new();
        if let Some(prefix) = self.filter.name_prefix() {
            query.push(("namePrefix", prefix.to_owned()));
        }
        if let Some(prefix) = self.filter.source_prefix() {
            query.push(("sourcePrefix", prefix.to_owned()));
        }
        if let Some(prefix) = self.filter.target_prefix() {
            query.push(("targetPrefix", prefix.to_owned()));
        }
        if let Some(state) = self.filter.current_state() {
            query.push(("currentState", api_current_state(state).to_owned()));
        }
        if let Some(state) = self.filter.desired_state() {
            query.push(("desiredState", api_desired_state(state).to_owned()));
        }
        query.push(("limit", self.filter.limit().to_string()));
        query.push(("page", self.page_number.to_string()));
        if let Some(cursor) = &self.cursor {
            query.push(("nextTokenDigest", cursor.token_digest().as_str().to_owned()));
        }
        let query = query
            .into_iter()
            .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("/pipes?{query}")
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: PipeOperation::ListPipes,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListPipesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListPipesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListPipesRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ListPipesRequest", 5)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("filterDigest", &self.filter.digest())?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribePipeRequest {
    scope: AwsEventBridgePipeScope,
    request_digest: Digest,
}

impl DescribePipeRequest {
    pub fn for_scope(scope: &AwsEventBridgePipeScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-eventbridge-pipe-describe-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("pipe", scope.pipe().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsEventBridgePipeScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/pipes/{}?nameDigest={}",
            percent_encode(self.scope.pipe().name().as_str()),
            self.scope.pipe().name().digest()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: PipeOperation::DescribePipe,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribePipeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribePipeRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for DescribePipeRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DescribePipeRequest", 2)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPipesResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub pipes: Vec<PipeSummary>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListPipesResponse {
    pub fn new(
        request: &ListPipesRequest,
        pipes: Vec<PipeSummary>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if pipes.len() > request.filter().limit() as usize {
            return Err(AwsEventBridgePipeError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsEventBridgePipeError::CursorMismatch);
            }
        }
        for pipe in &pipes {
            pipe.validate()?;
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            pipes,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-eventbridge-pipe-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListPipesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.pipes.len() > request.filter().limit() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsEventBridgePipeError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsEventBridgePipeError::CursorMismatch);
            }
        }
        for pipe in &self.pipes {
            pipe.validate()?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-pipe-list-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "pipes",
                    self.pipes
                        .iter()
                        .map(PipeSummary::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", format!("{:?}", self.provenance)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribePipeResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub description: PipeDescription,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribePipeResponse {
    pub fn new(
        request: &DescribePipeRequest,
        description: PipeDescription,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        description.validate_basic()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            description,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-eventbridge-pipe-describe-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribePipeRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsEventBridgePipeError::TamperedEvidence);
        }
        self.description.validate_basic()
    }

    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-pipe-describe-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("description", self.description.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", format!("{:?}", self.provenance)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsEventBridgePipeProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsEventBridgePipeProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0
            || release.is_empty()
            || release.len() > crate::MAX_IDENTIFIER_BYTES
            || release.chars().any(char::is_control)
        {
            return Err(AwsEventBridgePipeError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-eventbridge-pipe-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .chain([
                    ("operation", "ListPipes".to_owned()),
                    ("operation", "DescribePipe".to_owned()),
                ])
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-eventbridge-pipe-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsEventBridgePipeError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsEventBridgePipeProviderDefinition {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsEventBridgePipeProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

/// Typed provider exposing exactly the two Layer-1 read operations.
pub struct AwsEventBridgePipeProvider<T> {
    transport: T,
    definition: AwsEventBridgePipeProviderDefinition,
}

impl<T: AwsEventBridgePipeTransport> fmt::Debug for AwsEventBridgePipeProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEventBridgePipeProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsEventBridgePipeTransport> AwsEventBridgePipeProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsEventBridgePipeProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsEventBridgePipeProviderDefinition {
        &self.definition
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

    pub fn list_pipes(
        &mut self,
        request: &ListPipesRequest,
    ) -> std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError> {
        let response = self.transport.list_pipes(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsEventBridgePipeTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn describe_pipe(
        &mut self,
        request: &DescribePipeRequest,
    ) -> std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError> {
        let response = self.transport.describe_pipe(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsEventBridgePipeTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn from_registration(
        registration: &AwsEventBridgePipeRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsEventBridgePipeError::ProviderDrift);
        }
        Ok(provider)
    }

    /// Parse only bounded ListPipes fields from an already bounded response.
    /// Unknown fields, including any event data, are ignored and never
    /// retained.
    pub fn parse_list_json(
        request: &ListPipesRequest,
        status_code: u16,
        body: &[u8],
    ) -> std::result::Result<ListPipesResponse, AwsEventBridgePipeProviderError> {
        check_json_response(status_code, body)?;
        let value = serde_json::from_slice::<Value>(body).map_err(|_| {
            AwsEventBridgePipeProviderError::Transport(
                AwsEventBridgePipeTransportError::InvalidResponse,
            )
        })?;
        let items = value.get("Pipes").and_then(Value::as_array).ok_or(
            AwsEventBridgePipeProviderError::Transport(
                AwsEventBridgePipeTransportError::InvalidResponse,
            ),
        )?;
        let mut pipes = Vec::with_capacity(items.len());
        for item in items {
            let current_state =
                CurrentPipeState::parse_api(required_string(item, "CurrentState")?)?;
            let desired_state =
                DesiredPipeState::parse_api(required_string(item, "DesiredState")?)?;
            let error_classification = if current_state.is_failed()
                || item
                    .get("StateReason")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| !reason.is_empty())
            {
                ErrorClassification::ProviderReported
            } else {
                ErrorClassification::None
            };
            pipes.push(PipeSummary::new(
                required_string(item, "Name")?,
                required_string(item, "Arn")?,
                current_state,
                desired_state,
                required_timestamp(item, "CreationTime")?,
                required_timestamp(item, "LastModifiedTime")?,
                error_classification,
            )?);
        }
        let next_cursor = value
            .get("NextToken")
            .and_then(Value::as_str)
            .map(|token| {
                Cursor::new(
                    token,
                    request.scope(),
                    request.filter(),
                    request.page_number().saturating_add(1),
                )
            })
            .transpose()?;
        ListPipesResponse::new(
            request,
            pipes,
            next_cursor,
            body.len() as u64,
            TransportProvenance::Recording,
        )
        .map_err(AwsEventBridgePipeProviderError::Model)
    }

    /// Parse only bounded DescribePipe fields. Enrichment/filter presence is
    /// retained as a boolean; the configuration and any payload are dropped.
    pub fn parse_describe_json(
        request: &DescribePipeRequest,
        status_code: u16,
        body: &[u8],
    ) -> std::result::Result<DescribePipeResponse, AwsEventBridgePipeProviderError> {
        check_json_response(status_code, body)?;
        let value = serde_json::from_slice::<Value>(body).map_err(|_| {
            AwsEventBridgePipeProviderError::Transport(
                AwsEventBridgePipeTransportError::InvalidResponse,
            )
        })?;
        let current_state = CurrentPipeState::parse_api(required_string(&value, "CurrentState")?)?;
        let desired_state = DesiredPipeState::parse_api(required_string(&value, "DesiredState")?)?;
        let error_classification = if current_state.is_failed()
            || value
                .get("StateReason")
                .and_then(Value::as_str)
                .is_some_and(|reason| !reason.is_empty())
        {
            ErrorClassification::ProviderReported
        } else {
            ErrorClassification::None
        };
        let description = PipeDescription::new(
            required_string(&value, "Name")?,
            required_string(&value, "Arn")?,
            required_string(&value, "Source")?,
            required_string(&value, "Target")?,
            current_state,
            desired_state,
            required_timestamp(&value, "CreationTime")?,
            required_timestamp(&value, "LastModifiedTime")?,
            value
                .get("Enrichment")
                .is_some_and(|enrichment| !enrichment.is_null()),
            value
                .get("FilterCriteria")
                .is_some_and(|filter| !filter.is_null()),
            error_classification,
        )?;
        DescribePipeResponse::new(
            request,
            description,
            body.len() as u64,
            TransportProvenance::Recording,
        )
        .map_err(AwsEventBridgePipeProviderError::Model)
    }
}

impl Default for AwsEventBridgePipeProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked EventBridge Pipes provider definition")
    }
}

pub trait AwsEventBridgePipeTransport: Send {
    fn provenance(&self) -> TransportProvenance;

    fn list_pipes(
        &mut self,
        request: &ListPipesRequest,
    ) -> std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError>;

    fn describe_pipe(
        &mut self,
        request: &DescribePipeRequest,
    ) -> std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError>>,
    describe_responses:
        VecDeque<std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            describe_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_describe_response(
        &mut self,
        response: std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsEventBridgePipeTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_pipes(
        &mut self,
        request: &ListPipesRequest,
    ) -> std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsEventBridgePipeTransportError::InvalidResponse))
    }

    fn describe_pipe(
        &mut self,
        request: &DescribePipeRequest,
    ) -> std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_responses
            .pop_front()
            .unwrap_or(Err(AwsEventBridgePipeTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsEventBridgePipeScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsEventBridgePipeScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn summary(&self) -> Result<PipeSummary> {
        PipeSummary::new(
            self.scope.pipe().name().as_str(),
            self.scope.pipe().arn().as_str(),
            CurrentPipeState::Running,
            DesiredPipeState::Running,
            self.observed_at - chrono::Duration::hours(1),
            self.observed_at,
            ErrorClassification::None,
        )
    }

    fn description(&self) -> Result<PipeDescription> {
        PipeDescription::for_scope(
            &self.scope,
            CurrentPipeState::Running,
            DesiredPipeState::Running,
            self.observed_at - chrono::Duration::hours(1),
            self.observed_at,
            false,
            false,
            ErrorClassification::None,
        )
    }
}

impl AwsEventBridgePipeTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_pipes(
        &mut self,
        request: &ListPipesRequest,
    ) -> std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError> {
        ListPipesResponse::new(
            request,
            vec![
                self.summary()
                    .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)?,
            ],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)
    }

    fn describe_pipe(
        &mut self,
        request: &DescribePipeRequest,
    ) -> std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError> {
        DescribePipeResponse::new(
            request,
            self.description()
                .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)?,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsEventBridgePipeScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsEventBridgePipeTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_pipes(
        &mut self,
        request: &ListPipesRequest,
    ) -> std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError> {
        ListPipesResponse::new(
            request,
            vec![
                self.inner
                    .summary()
                    .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)?,
            ],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)
    }

    fn describe_pipe(
        &mut self,
        request: &DescribePipeRequest,
    ) -> std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError> {
        DescribePipeResponse::new(
            request,
            self.inner
                .description()
                .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)?,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsEventBridgePipeTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsEventBridgePipeTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_pipes(
        &mut self,
        _request: &ListPipesRequest,
    ) -> std::result::Result<ListPipesResponse, AwsEventBridgePipeTransportError> {
        Err(AwsEventBridgePipeTransportError::BlockedEnv)
    }

    fn describe_pipe(
        &mut self,
        _request: &DescribePipeRequest,
    ) -> std::result::Result<DescribePipeResponse, AwsEventBridgePipeTransportError> {
        Err(AwsEventBridgePipeTransportError::BlockedEnv)
    }
}

fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsEventBridgePipeError::PartialEvidence)
    } else {
        Ok(())
    }
}

fn api_current_state(state: CurrentPipeState) -> &'static str {
    match state {
        CurrentPipeState::Running => "RUNNING",
        CurrentPipeState::Stopped => "STOPPED",
        CurrentPipeState::Creating => "CREATING",
        CurrentPipeState::Updating => "UPDATING",
        CurrentPipeState::Starting => "STARTING",
        CurrentPipeState::Stopping => "STOPPING",
        CurrentPipeState::Deleting => "DELETING",
        CurrentPipeState::CreateFailed => "CREATE_FAILED",
        CurrentPipeState::UpdateFailed => "UPDATE_FAILED",
        CurrentPipeState::StartFailed => "START_FAILED",
        CurrentPipeState::StopFailed => "STOP_FAILED",
        CurrentPipeState::DeleteFailed => "DELETE_FAILED",
        CurrentPipeState::Unknown => "UNKNOWN",
    }
}

fn api_desired_state(state: DesiredPipeState) -> &'static str {
    match state {
        DesiredPipeState::Running => "RUNNING",
        DesiredPipeState::Stopped => "STOPPED",
        DesiredPipeState::Deleted => "DELETED",
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            let _ = write!(encoded, "{byte:02X}");
        }
    }
    encoded
}

fn check_json_response(
    status_code: u16,
    body: &[u8],
) -> std::result::Result<(), AwsEventBridgePipeProviderError> {
    if status_code != 200 {
        return Err(AwsEventBridgePipeProviderError::Transport(
            transport_error_for_status(status_code),
        ));
    }
    if body.is_empty() || body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(AwsEventBridgePipeProviderError::Transport(
            AwsEventBridgePipeTransportError::Partial,
        ));
    }
    Ok(())
}

fn transport_error_for_status(status_code: u16) -> AwsEventBridgePipeTransportError {
    match status_code {
        400 => AwsEventBridgePipeTransportError::BadRequest,
        401 => AwsEventBridgePipeTransportError::Unauthorized,
        403 => AwsEventBridgePipeTransportError::Forbidden,
        404 => AwsEventBridgePipeTransportError::NotFound,
        409 => AwsEventBridgePipeTransportError::Conflict,
        429 => AwsEventBridgePipeTransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => AwsEventBridgePipeTransportError::ServerError {
            status: status_code,
        },
        _ => AwsEventBridgePipeTransportError::InvalidResponse,
    }
}

fn required_string<'a>(value: &'a Value, field: &'static str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AwsEventBridgePipeError::InvalidRequest)
}

fn required_timestamp(value: &Value, field: &'static str) -> Result<DateTime<Utc>> {
    let raw = required_string(value, field)?;
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| AwsEventBridgePipeError::InvalidRequest)
}

pub type FixtureAwsEventBridgePipeTransport = FixtureTransport;
pub type LoopbackAwsEventBridgePipeTransport = LoopbackTransport;
