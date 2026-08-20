//! Non-native, metadata-only AWS Cost Anomaly Detection provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver,
//! native HTTP client, notification API, billing mutation, or raw provider
//! payload path in this Layer-1 crate.

use std::{collections::VecDeque, fmt, fmt::Write as _};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::{AwsCostAnomalyError, AwsCostAnomalyTransportError, Result};
use crate::model::{
    AnomalyFilter, AnomalyMetadata, AnomalyMetadataInput, AwsCostAnomalyScope, Cursor, Digest,
    MonitorFilter, MonitorMetadata, MonitorMetadataInput, SubscriptionFilter, SubscriptionMetadata,
    SubscriptionMetadataInput, TransportProvenance, validate_response_bytes,
};
use crate::service::AwsCostAnomalyRegistration;
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID,
};

pub const GET_ANOMALIES_OPERATION_PATH: &str = "/GetAnomalies";
pub const GET_ANOMALY_MONITORS_OPERATION_PATH: &str = "/GetAnomalyMonitors";
pub const GET_ANOMALY_SUBSCRIPTIONS_OPERATION_PATH: &str = "/GetAnomalySubscriptions";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCostAnomalyOperation {
    GetAnomalies,
    GetAnomalyMonitors,
    GetAnomalySubscriptions,
}

impl AwsCostAnomalyOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetAnomalies => "GetAnomalies",
            Self::GetAnomalyMonitors => "GetAnomalyMonitors",
            Self::GetAnomalySubscriptions => "GetAnomalySubscriptions",
        }
    }
}

/// The only transport trait exposed by this Layer-1 provider.
pub trait AwsCostAnomalyTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_anomalies(
        &mut self,
        request: &GetAnomaliesRequest,
    ) -> std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError>;

    fn get_anomaly_monitors(
        &mut self,
        request: &GetAnomalyMonitorsRequest,
    ) -> std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError>;

    fn get_anomaly_subscriptions(
        &mut self,
        request: &GetAnomalySubscriptionsRequest,
    ) -> std::result::Result<GetAnomalySubscriptionsResponse, AwsCostAnomalyTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsCostAnomalyOperation,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetAnomaliesRequest {
    scope: AwsCostAnomalyScope,
    filter: AnomalyFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl GetAnomaliesRequest {
    pub fn new(
        scope: &AwsCostAnomalyScope,
        filter: AnomalyFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-cost-anomaly-get-anomalies-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("filter", filter.digest().as_str().to_owned()),
                    (
                        "cursor",
                        cursor.as_ref().map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                    ),
                    (
                        "page",
                        cursor.as_ref().map_or_else(
                            || "1".to_owned(),
                            |value| value.page_number().to_string(),
                        ),
                    ),
                ],
            ),
            filter,
            cursor,
        })
    }

    pub fn scope(&self) -> &AwsCostAnomalyScope {
        &self.scope
    }

    pub fn filter(&self) -> &AnomalyFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            (
                "accountId",
                self.scope().account().digest().as_str().to_owned(),
            ),
            (
                "monitorArnDigest",
                self.filter.monitor_digest().as_str().to_owned(),
            ),
            ("startDate", self.filter.start_date().to_rfc3339()),
            ("endDate", self.filter.end_date().to_rfc3339()),
            ("maxResults", self.filter.max_results().to_string()),
        ];
        if let Some(cursor) = &self.cursor {
            query.push(("nextTokenDigest", cursor.token_digest().as_str().to_owned()));
        }
        format!(
            "{}?{}",
            GET_ANOMALIES_OPERATION_PATH,
            query
                .into_iter()
                .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
                .collect::<Vec<_>>()
                .join("&")
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCostAnomalyOperation::GetAnomalies,
            scope_digest: self.scope.digest(),
            filter_digest: self.filter.digest(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetAnomaliesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetAnomaliesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetAnomalyMonitorsRequest {
    scope: AwsCostAnomalyScope,
    filter: MonitorFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl GetAnomalyMonitorsRequest {
    pub fn new(
        scope: &AwsCostAnomalyScope,
        filter: MonitorFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-cost-anomaly-get-monitors-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("filter", filter.digest().as_str().to_owned()),
                    (
                        "cursor",
                        cursor.as_ref().map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                    ),
                    (
                        "page",
                        cursor.as_ref().map_or_else(
                            || "1".to_owned(),
                            |value| value.page_number().to_string(),
                        ),
                    ),
                ],
            ),
            filter,
            cursor,
        })
    }

    pub fn scope(&self) -> &AwsCostAnomalyScope {
        &self.scope
    }

    pub fn filter(&self) -> &MonitorFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            (
                "accountId",
                self.scope().account().digest().as_str().to_owned(),
            ),
            (
                "monitorArnDigest",
                self.filter.monitor_digest().as_str().to_owned(),
            ),
            ("maxResults", self.filter.max_results().to_string()),
        ];
        if let Some(cursor) = &self.cursor {
            query.push(("nextTokenDigest", cursor.token_digest().as_str().to_owned()));
        }
        format!(
            "{}?{}",
            GET_ANOMALY_MONITORS_OPERATION_PATH,
            query
                .into_iter()
                .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
                .collect::<Vec<_>>()
                .join("&")
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCostAnomalyOperation::GetAnomalyMonitors,
            scope_digest: self.scope.digest(),
            filter_digest: self.filter.digest(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetAnomalyMonitorsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetAnomalyMonitorsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetAnomalySubscriptionsRequest {
    scope: AwsCostAnomalyScope,
    filter: SubscriptionFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl GetAnomalySubscriptionsRequest {
    pub fn new(
        scope: &AwsCostAnomalyScope,
        filter: SubscriptionFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-cost-anomaly-get-subscriptions-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("filter", filter.digest().as_str().to_owned()),
                    (
                        "cursor",
                        cursor.as_ref().map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                    ),
                    (
                        "page",
                        cursor.as_ref().map_or_else(
                            || "1".to_owned(),
                            |value| value.page_number().to_string(),
                        ),
                    ),
                ],
            ),
            filter,
            cursor,
        })
    }

    pub fn scope(&self) -> &AwsCostAnomalyScope {
        &self.scope
    }

    pub fn filter(&self) -> &SubscriptionFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            (
                "subscriptionArnDigest",
                self.filter.subscription_digest().as_str().to_owned(),
            ),
            ("maxResults", self.filter.max_results().to_string()),
        ];
        if let Some(cursor) = &self.cursor {
            query.push(("nextTokenDigest", cursor.token_digest().as_str().to_owned()));
        }
        format!(
            "{}?{}",
            GET_ANOMALY_SUBSCRIPTIONS_OPERATION_PATH,
            query
                .into_iter()
                .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
                .collect::<Vec<_>>()
                .join("&")
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCostAnomalyOperation::GetAnomalySubscriptions,
            scope_digest: self.scope.digest(),
            filter_digest: self.filter.digest(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetAnomalySubscriptionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetAnomalySubscriptionsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAnomaliesResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub anomalies: Vec<AnomalyMetadata>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetAnomaliesResponse {
    pub fn new(
        request: &GetAnomaliesRequest,
        anomalies: Vec<AnomalyMetadata>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if anomalies.len() > request.filter.max_results() as usize {
            return Err(AwsCostAnomalyError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCostAnomalyError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            anomalies,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-cost-anomaly-anomalies-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &GetAnomaliesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.anomalies.len() > request.filter.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCostAnomalyError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCostAnomalyError::CursorMismatch);
            }
        }
        for anomaly in &self.anomalies {
            anomaly.validate_list_item_against(request.scope(), request.filter())?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-get-anomalies-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "anomalies",
                    self.anomalies
                        .iter()
                        .map(AnomalyMetadata::digest)
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
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAnomalyMonitorsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub monitors: Vec<MonitorMetadata>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetAnomalyMonitorsResponse {
    pub fn new(
        request: &GetAnomalyMonitorsRequest,
        monitors: Vec<MonitorMetadata>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if monitors.len() > request.filter.max_results() as usize {
            return Err(AwsCostAnomalyError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCostAnomalyError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            monitors,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-cost-anomaly-monitors-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &GetAnomalyMonitorsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.monitors.len() > request.filter.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCostAnomalyError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCostAnomalyError::CursorMismatch);
            }
        }
        for monitor in &self.monitors {
            monitor.validate_against(request.scope())?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-get-monitors-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "monitors",
                    self.monitors
                        .iter()
                        .map(MonitorMetadata::digest)
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
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAnomalySubscriptionsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub subscriptions: Vec<SubscriptionMetadata>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetAnomalySubscriptionsResponse {
    pub fn new(
        request: &GetAnomalySubscriptionsRequest,
        subscriptions: Vec<SubscriptionMetadata>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if subscriptions.len() > request.filter.max_results() as usize {
            return Err(AwsCostAnomalyError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCostAnomalyError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            subscriptions,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-cost-anomaly-subscriptions-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &GetAnomalySubscriptionsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.subscriptions.len() > request.filter.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCostAnomalyError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCostAnomalyError::CursorMismatch);
            }
        }
        for subscription in &self.subscriptions {
            subscription.validate_against(request.scope())?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-get-subscriptions-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "subscriptions",
                    self.subscriptions
                        .iter()
                        .map(SubscriptionMetadata::digest)
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
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwsCostAnomalyProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsCostAnomalyProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > MAX_IDENTIFIER_BYTES {
            return Err(AwsCostAnomalyError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-cost-anomaly-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-cost-anomaly-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.plugin_version != PLUGIN_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsCostAnomalyError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsCostAnomalyProviderDefinition {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AwsCostAnomalyProviderDefinition", 12)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.serialize_field("providerReceipt", &self.provider_receipt)?;
        state.end()
    }
}

pub struct AwsCostAnomalyProvider<T> {
    transport: T,
    definition: AwsCostAnomalyProviderDefinition,
}

impl<T: AwsCostAnomalyTransport> fmt::Debug for AwsCostAnomalyProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCostAnomalyProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsCostAnomalyTransport> AwsCostAnomalyProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsCostAnomalyProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsCostAnomalyProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn get_anomalies(
        &mut self,
        request: &GetAnomaliesRequest,
    ) -> std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError> {
        let response = self.transport.get_anomalies(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCostAnomalyTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn get_anomaly_monitors(
        &mut self,
        request: &GetAnomalyMonitorsRequest,
    ) -> std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError> {
        let response = self.transport.get_anomaly_monitors(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCostAnomalyTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn get_anomaly_subscriptions(
        &mut self,
        request: &GetAnomalySubscriptionsRequest,
    ) -> std::result::Result<GetAnomalySubscriptionsResponse, AwsCostAnomalyTransportError> {
        let response = self.transport.get_anomaly_subscriptions(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCostAnomalyTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsCostAnomalyProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS Cost Anomaly provider definition")
    }
}

impl<T: AwsCostAnomalyTransport> AwsCostAnomalyProvider<T> {
    pub fn from_registration(
        registration: &AwsCostAnomalyRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsCostAnomalyError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    anomaly_responses:
        VecDeque<std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError>>,
    monitor_responses:
        VecDeque<std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError>>,
    subscription_responses: VecDeque<
        std::result::Result<GetAnomalySubscriptionsResponse, AwsCostAnomalyTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            anomaly_responses: VecDeque::new(),
            monitor_responses: VecDeque::new(),
            subscription_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_anomalies_response(
        &mut self,
        response: std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError>,
    ) {
        self.anomaly_responses.push_back(response);
    }

    pub fn push_monitors_response(
        &mut self,
        response: std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError>,
    ) {
        self.monitor_responses.push_back(response);
    }

    pub fn push_subscriptions_response(
        &mut self,
        response: std::result::Result<
            GetAnomalySubscriptionsResponse,
            AwsCostAnomalyTransportError,
        >,
    ) {
        self.subscription_responses.push_back(response);
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

impl AwsCostAnomalyTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance.clone()
    }

    fn get_anomalies(
        &mut self,
        request: &GetAnomaliesRequest,
    ) -> std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError> {
        self.requests.push(request.recorded_request());
        self.anomaly_responses
            .pop_front()
            .unwrap_or(Err(AwsCostAnomalyTransportError::InvalidResponse))
    }

    fn get_anomaly_monitors(
        &mut self,
        request: &GetAnomalyMonitorsRequest,
    ) -> std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError> {
        self.requests.push(request.recorded_request());
        self.monitor_responses
            .pop_front()
            .unwrap_or(Err(AwsCostAnomalyTransportError::InvalidResponse))
    }

    fn get_anomaly_subscriptions(
        &mut self,
        request: &GetAnomalySubscriptionsRequest,
    ) -> std::result::Result<GetAnomalySubscriptionsResponse, AwsCostAnomalyTransportError> {
        self.requests.push(request.recorded_request());
        self.subscription_responses
            .pop_front()
            .unwrap_or(Err(AwsCostAnomalyTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsCostAnomalyScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsCostAnomalyScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn anomaly(&self) -> Result<AnomalyMetadata> {
        AnomalyMetadata::new(
            &self.scope,
            AnomalyMetadataInput {
                anomaly_id: self.scope.anomaly().id().clone(),
                monitor_arn: self.scope.monitor().clone(),
                window: self.scope.anomaly().window().clone(),
                impact_usd: Some(500),
                feedback: crate::model::AnomalyFeedback::NotProvided,
                root_cause_dimensions: Vec::new(),
            },
        )
    }

    fn monitor(&self) -> Result<MonitorMetadata> {
        MonitorMetadata::new(
            &self.scope,
            MonitorMetadataInput {
                monitor_arn: self.scope.monitor().clone(),
                monitor_name: "layer1-fixture-monitor".to_owned(),
                monitor_type: crate::model::MonitorType::Dimensional,
                status: crate::model::MonitorStatus::Active,
                evaluation_start: Some(self.observed_at - Duration::days(7)),
                evaluation_end: Some(self.observed_at),
            },
        )
    }

    fn subscription(&self) -> Result<SubscriptionMetadata> {
        SubscriptionMetadata::new(
            &self.scope,
            SubscriptionMetadataInput {
                subscription_arn: self.scope.subscription().clone(),
                frequency: crate::model::SubscriptionFrequency::Daily,
                status: crate::model::SubscriptionStatus::Active,
                subscriber_addresses: Vec::new(),
            },
        )
    }
}

impl AwsCostAnomalyTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_anomalies(
        &mut self,
        request: &GetAnomaliesRequest,
    ) -> std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError> {
        GetAnomaliesResponse::new(
            request,
            vec![
                self.anomaly()
                    .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?,
            ],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)
    }

    fn get_anomaly_monitors(
        &mut self,
        request: &GetAnomalyMonitorsRequest,
    ) -> std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError> {
        GetAnomalyMonitorsResponse::new(
            request,
            vec![
                self.monitor()
                    .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?,
            ],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)
    }

    fn get_anomaly_subscriptions(
        &mut self,
        request: &GetAnomalySubscriptionsRequest,
    ) -> std::result::Result<GetAnomalySubscriptionsResponse, AwsCostAnomalyTransportError> {
        GetAnomalySubscriptionsResponse::new(
            request,
            vec![
                self.subscription()
                    .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?,
            ],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsCostAnomalyScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsCostAnomalyTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_anomalies(
        &mut self,
        request: &GetAnomaliesRequest,
    ) -> std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError> {
        let anomaly = self
            .inner
            .anomaly()
            .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?;
        GetAnomaliesResponse::new(
            request,
            vec![anomaly],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)
    }

    fn get_anomaly_monitors(
        &mut self,
        request: &GetAnomalyMonitorsRequest,
    ) -> std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError> {
        let monitor = self
            .inner
            .monitor()
            .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?;
        GetAnomalyMonitorsResponse::new(
            request,
            vec![monitor],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)
    }

    fn get_anomaly_subscriptions(
        &mut self,
        request: &GetAnomalySubscriptionsRequest,
    ) -> std::result::Result<GetAnomalySubscriptionsResponse, AwsCostAnomalyTransportError> {
        let subscription = self
            .inner
            .subscription()
            .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)?;
        GetAnomalySubscriptionsResponse::new(
            request,
            vec![subscription],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsCostAnomalyTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsCostAnomalyTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_anomalies(
        &mut self,
        _request: &GetAnomaliesRequest,
    ) -> std::result::Result<GetAnomaliesResponse, AwsCostAnomalyTransportError> {
        Err(AwsCostAnomalyTransportError::BlockedEnv)
    }

    fn get_anomaly_monitors(
        &mut self,
        _request: &GetAnomalyMonitorsRequest,
    ) -> std::result::Result<GetAnomalyMonitorsResponse, AwsCostAnomalyTransportError> {
        Err(AwsCostAnomalyTransportError::BlockedEnv)
    }

    fn get_anomaly_subscriptions(
        &mut self,
        _request: &GetAnomalySubscriptionsRequest,
    ) -> std::result::Result<GetAnomalySubscriptionsResponse, AwsCostAnomalyTransportError> {
        Err(AwsCostAnomalyTransportError::BlockedEnv)
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
