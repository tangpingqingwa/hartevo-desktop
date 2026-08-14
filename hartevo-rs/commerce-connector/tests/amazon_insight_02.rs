use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_commerce_connector::amazon::{
    AmazonAccountIdentity, AmazonAccountScope, AmazonError, AmazonLwaAuthState,
    AmazonNotificationCursor, AmazonOperation, AmazonReport, AmazonReportStatus, AmazonRole,
    AmazonSpApiRequest, AmazonSpApiResponse, AmazonSpApiTransport, AmazonTransportError,
    LwaAccessTokenObservation, list_reports_request, parse_notification_subscriptions_page_read,
    parse_report_read, parse_reports_page_read,
};
use hartevo_commerce_connector::amazon_insight::{
    AMAZON_INSIGHT_CAPABILITY_ID, AMAZON_INSIGHT_LIVE_VALIDATION_STATUS,
    AMAZON_REPORT_CREATION_POLICY, AmazonDocumentCursor, AmazonFreshnessEvidence,
    AmazonInsightClassification, AmazonInsightCursor, AmazonInsightDurableStore,
    AmazonInsightError, AmazonInsightProviderError, AmazonInsightReadRequest, AmazonInsightRecord,
    AmazonInsightSource, AmazonNotificationEvent, AmazonNotificationFeed, AmazonNotificationPage,
    AmazonNotificationPageRequest, AmazonNotificationType, AmazonPreauthorizedReportJob,
    AmazonProviderGeneration, AmazonQuotaCostEvidence, AmazonReportDocumentId,
    AmazonReportDocumentPage, AmazonReportDocumentPageRequest, AmazonReportStatusPage,
    AmazonReportStatusRequest, AmazonSpApiInsightAdapter, CommerceInsightReadService,
    amazon_scope_digest, live_probe_enabled, notification_cursor_sp_api_request,
    report_document_sp_api_request, report_status_sp_api_request,
};
use hartevo_connector_sdk::{ConnectorScope, ProviderProvenanceClass, SecretReference};
use serde::Deserialize;
use serde_json::{Value, json};

const NOW_YEAR: i32 = 2026;

#[derive(Clone, Debug)]
struct LoopbackHttpRequest {
    request_line: String,
    headers: BTreeMap<String, String>,
}

#[derive(Debug)]
struct LoopbackHttpServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<LoopbackHttpRequest>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl LoopbackHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("Amazon loopback listener");
        listener
            .set_nonblocking(true)
            .expect("Amazon loopback nonblocking listener");
        let address = listener.local_addr().expect("Amazon loopback address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let requests_for_thread = Arc::clone(&requests);
        let stop_for_thread = Arc::clone(&stop);
        let join = thread::spawn(move || {
            while !stop_for_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Ok(request) = read_loopback_request(&mut stream) {
                            requests_for_thread
                                .lock()
                                .expect("Amazon loopback request state")
                                .push(request.clone());
                            let response = loopback_response(&request.request_line);
                            let _ = write_loopback_response(&mut stream, &response);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            join: Some(join),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn requests(&self) -> Vec<LoopbackHttpRequest> {
        self.requests
            .lock()
            .expect("Amazon loopback request state")
            .clone()
    }
}

impl Drop for LoopbackHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Clone, Debug)]
struct LoopbackAmazonSpApiTransport {
    address: SocketAddr,
}

impl LoopbackAmazonSpApiTransport {
    fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    fn execute_path(
        &mut self,
        path: &str,
        token_digest: &str,
    ) -> Result<AmazonSpApiResponse, AmazonTransportError> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: loopback.amazon.test\r\nAccept: application/json\r\nX-Amz-Access-Token: {token_digest}\r\nConnection: close\r\n\r\n"
        );
        let mut stream = TcpStream::connect(self.address)
            .map_err(|error| AmazonTransportError::Failed(error.to_string()))?;
        stream
            .set_read_timeout(Some(StdDuration::from_secs(1)))
            .map_err(|error| AmazonTransportError::Failed(error.to_string()))?;
        stream
            .set_write_timeout(Some(StdDuration::from_secs(1)))
            .map_err(|error| AmazonTransportError::Failed(error.to_string()))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|error| AmazonTransportError::Failed(error.to_string()))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| AmazonTransportError::Failed(error.to_string()))?;
        parse_loopback_response(&response)
    }

    fn read_document_content(
        &mut self,
        url: &str,
        cursor: Option<&AmazonDocumentCursor>,
        token_digest: &str,
    ) -> Result<AmazonSpApiResponse, AmazonTransportError> {
        let prefix = "https://loopback.amazon.test";
        let mut path = url
            .strip_prefix(prefix)
            .ok_or_else(|| AmazonTransportError::Failed("unexpected document URL host".into()))?
            .to_owned();
        if let Some(cursor) = cursor {
            path.push_str("?cursor=");
            path.push_str(cursor.as_str());
        }
        self.execute_path(&path, token_digest)
    }
}

impl AmazonSpApiTransport for LoopbackAmazonSpApiTransport {
    fn execute(
        &mut self,
        request: AmazonSpApiRequest,
    ) -> Result<AmazonSpApiResponse, AmazonTransportError> {
        request
            .endpoint()
            .map_err(|error| AmazonTransportError::Failed(error.to_string()))?;
        let query = request
            .query
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        let path = if query.is_empty() {
            request.path
        } else {
            format!("{}?{query}", request.path)
        };
        self.execute_path(&path, &request.access_token.token_digest)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoopbackReportDocumentDescriptor {
    report_document_id: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoopbackDocumentPagePayload {
    report_document_id: String,
    records: Vec<LoopbackDocumentRecord>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoopbackDocumentRecord {
    record_id: String,
    content_digest: String,
    observed_at: DateTime<Utc>,
}

#[derive(Debug)]
struct LoopbackAmazonInsightAdapter {
    transport: LoopbackAmazonSpApiTransport,
}

impl LoopbackAmazonInsightAdapter {
    fn new(address: SocketAddr) -> Self {
        Self {
            transport: LoopbackAmazonSpApiTransport::new(address),
        }
    }

    fn quota(
        request: &AmazonSpApiRequest,
        response: &AmazonSpApiResponse,
    ) -> Result<AmazonQuotaCostEvidence, AmazonInsightProviderError> {
        let metadata = response
            .metadata()
            .map_err(|error| AmazonInsightProviderError::Malformed(error.to_string()))?;
        AmazonQuotaCostEvidence::new(
            request.operation,
            metadata.rate_limit,
            None,
            1,
            metadata.request_id,
        )
        .map_err(|error| AmazonInsightProviderError::Malformed(error.to_string()))
    }

    fn freshness(
        at: DateTime<Utc>,
        generation: AmazonProviderGeneration,
    ) -> Result<AmazonFreshnessEvidence, AmazonInsightProviderError> {
        AmazonFreshnessEvidence::new(at, at + Duration::seconds(60), generation.value())
            .map_err(|error| AmazonInsightProviderError::Malformed(error.to_string()))
    }

    fn amazon_error(error: &AmazonError) -> AmazonInsightProviderError {
        AmazonInsightProviderError::Malformed(error.to_string())
    }
}

impl AmazonSpApiInsightAdapter for LoopbackAmazonInsightAdapter {
    fn read_report_status(
        &mut self,
        request: AmazonReportStatusRequest,
    ) -> Result<AmazonReportStatusPage, AmazonInsightProviderError> {
        let http_request =
            report_status_sp_api_request(&request).map_err(|error| Self::amazon_error(&error))?;
        let response = self
            .transport
            .execute(http_request.clone())
            .map_err(|error| AmazonInsightProviderError::Transport(error.to_string()))?;
        let report = parse_report_read(&http_request, &response, request.at)
            .map_err(|error| Self::amazon_error(&error))?;
        Ok(AmazonReportStatusPage {
            report: report.value,
            quota: Self::quota(&http_request, &response)?,
            freshness: Self::freshness(request.at, request.provider_generation)?,
        })
    }

    fn read_report_document_page(
        &mut self,
        request: AmazonReportDocumentPageRequest,
    ) -> Result<AmazonReportDocumentPage, AmazonInsightProviderError> {
        let http_request =
            report_document_sp_api_request(&request).map_err(|error| Self::amazon_error(&error))?;
        let requested_cursor = request.requested_cursor.clone();
        let descriptor_response = self
            .transport
            .execute(http_request.clone())
            .map_err(|error| AmazonInsightProviderError::Transport(error.to_string()))?;
        let descriptor = descriptor_response
            .payload::<LoopbackReportDocumentDescriptor>()
            .map_err(|error| Self::amazon_error(&error))?;
        if descriptor.report_document_id != request.document_id.as_str() {
            return Err(AmazonInsightProviderError::ScopeDrift);
        }
        let content_response = self
            .transport
            .read_document_content(
                &descriptor.url,
                requested_cursor.as_ref(),
                &request.access_token.token_digest,
            )
            .map_err(|error| AmazonInsightProviderError::Transport(error.to_string()))?;
        let page = content_response
            .json::<LoopbackDocumentPagePayload>()
            .map_err(|error| Self::amazon_error(&error))?;
        if page.report_document_id != request.document_id.as_str() {
            return Err(AmazonInsightProviderError::ScopeDrift);
        }
        let records = page
            .records
            .into_iter()
            .map(|record| {
                AmazonInsightRecord::new(
                    record.record_id,
                    record.content_digest,
                    record.observed_at,
                )
                .map_err(|error| AmazonInsightProviderError::Malformed(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = page
            .next_cursor
            .map(AmazonDocumentCursor::parse)
            .transpose()
            .map_err(|error| AmazonInsightProviderError::Malformed(error.to_string()))?;
        let page_sequence = if requested_cursor.is_some() { 2 } else { 1 };
        Ok(AmazonReportDocumentPage {
            document_id: request.document_id,
            document_url_digest: digest(&descriptor.url),
            document_url_expires_at: request.at + Duration::seconds(300),
            requested_cursor,
            page_sequence,
            next_cursor,
            records,
            observed_at: request.at,
            quota: Self::quota(&http_request, &content_response)?,
            freshness: Self::freshness(request.at, request.provider_generation)?,
        })
    }

    fn read_notification_page(
        &mut self,
        request: AmazonNotificationPageRequest,
    ) -> Result<AmazonNotificationPage, AmazonInsightProviderError> {
        let http_request = notification_cursor_sp_api_request(&request)
            .map_err(|error| Self::amazon_error(&error))?;
        let requested_cursor = request.requested_cursor.clone();
        let response = self
            .transport
            .execute(http_request.clone())
            .map_err(|error| AmazonInsightProviderError::Transport(error.to_string()))?;
        let subscriptions =
            parse_notification_subscriptions_page_read(&http_request, &response, request.at)
                .map_err(|error| Self::amazon_error(&error))?
                .value;
        let events = subscriptions
            .subscriptions
            .into_iter()
            .map(|subscription| {
                let sequence = subscription
                    .subscription_id
                    .rsplit('-')
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| {
                        AmazonInsightProviderError::Malformed(
                            "loopback notification sequence".into(),
                        )
                    })?;
                AmazonNotificationEvent::new(
                    subscription.subscription_id.clone(),
                    sequence,
                    request.feed.notification_type.clone(),
                    request.at,
                    digest(&subscription.subscription_id),
                )
                .map_err(|error| AmazonInsightProviderError::Malformed(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AmazonNotificationPage {
            notification_type: request.feed.notification_type.clone(),
            requested_cursor,
            page_sequence: if request.requested_cursor.is_some() {
                2
            } else {
                1
            },
            next_cursor: subscriptions.next_cursor,
            events,
            observed_at: request.at,
            quota: Self::quota(&http_request, &response)?,
            freshness: Self::freshness(request.at, request.provider_generation)?,
        })
    }
}

fn read_loopback_request(stream: &mut TcpStream) -> std::io::Result<LoopbackHttpRequest> {
    stream.set_read_timeout(Some(StdDuration::from_secs(1)))?;
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if find_subsequence(&bytes, b"\r\n\r\n").is_some() {
            break;
        }
    }
    let header_end = find_subsequence(&bytes, b"\r\n\r\n").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing loopback HTTP request headers",
        )
    })?;
    let header = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = header.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Ok(LoopbackHttpRequest {
        request_line,
        headers,
    })
}

fn write_loopback_response(stream: &mut TcpStream, body: &Value) -> std::io::Result<()> {
    let body = body.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-amzn-RequestId: loopback-request-{}\r\nx-amzn-RateLimit-Limit: 0.5\r\nConnection: close\r\n\r\n{}",
        body.len(),
        digest(&body)[..12].to_owned(),
        body
    )?;
    stream.flush()
}

fn parse_loopback_response(bytes: &[u8]) -> Result<AmazonSpApiResponse, AmazonTransportError> {
    let separator = find_subsequence(bytes, b"\r\n\r\n")
        .ok_or_else(|| AmazonTransportError::Failed("missing loopback response body".into()))?;
    let header = String::from_utf8_lossy(&bytes[..separator]);
    let mut lines = header.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| AmazonTransportError::Failed("invalid loopback HTTP status".into()))?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_owned(), value.trim().to_owned()))
        .collect();
    let body = serde_json::from_slice(&bytes[separator + 4..])
        .map_err(|error| AmazonTransportError::Failed(error.to_string()))?;
    Ok(AmazonSpApiResponse {
        status,
        headers,
        body,
    })
}

fn loopback_response(request_line: &str) -> Value {
    let path = request_line.split_whitespace().nth(1).unwrap_or_default();
    if path == "/reports/2021-06-30/reports" || path.starts_with("/reports/2021-06-30/reports?") {
        let second_page = path.contains("nextToken=reports-cursor-2");
        return json!({
            "reports": if second_page {
                json!([{
                    "reportId": "report-2",
                    "reportType": "GET_MERCHANT_LISTINGS_ALL_DATA",
                    "processingStatus": "DONE",
                    "createdTime": "2026-08-14T05:00:00Z",
                    "reportDocumentId": "DOC-2"
                }])
            } else {
                json!([{
                    "reportId": "report-1",
                    "reportType": "GET_MERCHANT_LISTINGS_ALL_DATA",
                    "processingStatus": "DONE",
                    "createdTime": "2026-08-14T05:00:00Z",
                    "reportDocumentId": "DOC-1"
                }])
            },
            "nextToken": if second_page { Value::Null } else { json!("reports-cursor-2") }
        });
    }
    if path == "/reports/2021-06-30/reports/report-1" {
        return json!({
            "payload": {
                "reportId": "report-1",
                "reportType": "GET_MERCHANT_LISTINGS_ALL_DATA",
                "processingStatus": "DONE",
                "createdTime": "2026-08-14T05:00:00Z",
                "processingEndTime": "2026-08-14T05:01:00Z",
                "reportDocumentId": "DOC-1"
            }
        });
    }
    if path == "/reports/2021-06-30/documents/DOC-1" {
        return json!({
            "payload": {
                "reportDocumentId": "DOC-1",
                "url": "https://loopback.amazon.test/document-content/DOC-1"
            }
        });
    }
    if path.starts_with("/document-content/DOC-1") {
        let second_page = path.contains("cursor=document-cursor-2");
        return json!({
            "reportDocumentId": "DOC-1",
            "records": if second_page {
                json!([{
                    "recordId": "row-2",
                    "contentDigest": digest("row-2"),
                    "observedAt": "2026-08-14T05:00:00Z"
                }])
            } else {
                json!([{
                    "recordId": "row-1",
                    "contentDigest": digest("row-1"),
                    "observedAt": "2026-08-14T05:00:00Z"
                }])
            },
            "nextCursor": if second_page { Value::Null } else { json!("document-cursor-2") }
        });
    }
    if path.starts_with("/notifications/v1/subscriptions") {
        let second_page = path.contains("nextToken=notification-cursor-2");
        return json!({
            "payload": {
                "subscriptions": if second_page {
                    json!([
                        {"subscriptionId": "delivery-2", "payloadVersion": "1.0", "destinationId": "destination-2"},
                        {"subscriptionId": "delivery-3", "payloadVersion": "1.0", "destinationId": "destination-3"}
                    ])
                } else {
                    json!([
                        {"subscriptionId": "delivery-1", "payloadVersion": "1.0", "destinationId": "destination-1"},
                        {"subscriptionId": "delivery-2", "payloadVersion": "1.0", "destinationId": "destination-2"}
                    ])
                },
                "nextToken": if second_page { Value::Null } else { json!("notification-cursor-2") }
            }
        });
    }
    json!({"errors": [{"message": "unexpected loopback Amazon path"}]})
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Clone, Debug)]
struct FakeAmazonState {
    report_status_calls: u32,
    report_document_calls: u32,
    notification_calls: u32,
    report_status: AmazonReportStatusPage,
    report_pages: BTreeMap<String, AmazonReportDocumentPage>,
    notification_pages: BTreeMap<String, AmazonNotificationPage>,
    rate_limit_document_once: bool,
    expired_document_url: bool,
}

#[derive(Clone, Debug)]
struct FakeAmazonSpApiAdapter {
    state: Arc<Mutex<FakeAmazonState>>,
}

impl FakeAmazonSpApiAdapter {
    fn new(state: Arc<Mutex<FakeAmazonState>>) -> Self {
        Self { state }
    }
}

impl AmazonSpApiInsightAdapter for FakeAmazonSpApiAdapter {
    fn read_report_status(
        &mut self,
        _request: AmazonReportStatusRequest,
    ) -> Result<AmazonReportStatusPage, AmazonInsightProviderError> {
        let mut state = self.state.lock().expect("fake Amazon state");
        state.report_status_calls += 1;
        Ok(state.report_status.clone())
    }

    fn read_report_document_page(
        &mut self,
        request: AmazonReportDocumentPageRequest,
    ) -> Result<AmazonReportDocumentPage, AmazonInsightProviderError> {
        let mut state = self.state.lock().expect("fake Amazon state");
        state.report_document_calls += 1;
        if state.rate_limit_document_once {
            state.rate_limit_document_once = false;
            return Err(AmazonInsightProviderError::RateLimited {
                retry_after_seconds: 10,
                quota: quota(AmazonOperation::ReportsDocument, "rate-limited"),
            });
        }
        let key = request
            .requested_cursor
            .as_ref()
            .map_or_else(|| "<start>".to_owned(), |cursor| cursor.as_str().to_owned());
        let mut page = state
            .report_pages
            .get(&key)
            .cloned()
            .expect("configured report page");
        if state.expired_document_url {
            page.document_url_expires_at = request.at - Duration::seconds(1);
        }
        Ok(page)
    }

    fn read_notification_page(
        &mut self,
        request: AmazonNotificationPageRequest,
    ) -> Result<AmazonNotificationPage, AmazonInsightProviderError> {
        let mut state = self.state.lock().expect("fake Amazon state");
        state.notification_calls += 1;
        let key = request
            .requested_cursor
            .as_ref()
            .map_or_else(|| "<start>".to_owned(), |cursor| cursor.as_str().to_owned());
        Ok(state
            .notification_pages
            .get(&key)
            .cloned()
            .expect("configured notification page"))
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW_YEAR, 8, 14, 5, 0, 0)
        .single()
        .expect("stable test time")
}

fn digest(value: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn connector_scope(account_id: &str) -> ConnectorScope {
    ConnectorScope::new(
        "tenant-amazon",
        "project-commerce",
        "amazon-sp-api",
        account_id,
        ["reports.read".to_owned(), "notifications.read".to_owned()],
    )
    .expect("Amazon ConnectorScope")
}

fn seller_scope() -> AmazonAccountScope {
    AmazonAccountScope::new(
        AmazonAccountIdentity::seller("A1SELLER01").expect("seller"),
        hartevo_commerce_connector::amazon::AmazonMarketplace::us(),
        BTreeSet::from([AmazonRole::reports(), AmazonRole::notifications()]),
    )
    .expect("Amazon account scope")
}

fn secret(scope: &AmazonAccountScope) -> SecretReference {
    SecretReference::new(
        "secret-ref-amazon-insight-1",
        connector_scope(scope.account.account_id()),
        7,
    )
    .expect("opaque Amazon SecretReference")
}

fn generation() -> AmazonProviderGeneration {
    AmazonProviderGeneration::new(7).expect("provider generation")
}

fn auth_state() -> AmazonLwaAuthState {
    let token = LwaAccessTokenObservation::from_raw_token(
        b"controlled-token-only",
        now() - Duration::seconds(10),
        600,
    )
    .expect("token observation");
    AmazonLwaAuthState::token_observed(token)
}

fn report_job(scope: &AmazonAccountScope) -> AmazonPreauthorizedReportJob {
    AmazonPreauthorizedReportJob::new(
        scope,
        generation(),
        "report-1",
        "GET_MERCHANT_LISTINGS_ALL_DATA",
        digest("external-preauthorized-report-job"),
        now() - Duration::seconds(30),
    )
    .expect("pre-authorized report job")
}

fn report_request(scope: &AmazonAccountScope) -> AmazonInsightReadRequest {
    AmazonInsightReadRequest::new(
        "mission-research-report-1",
        scope.clone(),
        generation(),
        AmazonInsightSource::Report {
            job: report_job(scope),
        },
        now() - Duration::seconds(20),
        now() + Duration::seconds(300),
        100,
    )
    .expect("report research request")
}

fn notification_request(scope: AmazonAccountScope) -> AmazonInsightReadRequest {
    AmazonInsightReadRequest::new(
        "mission-research-notifications-1",
        scope,
        generation(),
        AmazonInsightSource::Notifications {
            feed: AmazonNotificationFeed::new("ORDER_CHANGE", "1.0", "subscription-1")
                .expect("notification feed"),
        },
        now() - Duration::seconds(20),
        now() + Duration::seconds(300),
        100,
    )
    .expect("notification research request")
}

fn quota(operation: AmazonOperation, request_id: &str) -> AmazonQuotaCostEvidence {
    AmazonQuotaCostEvidence::new(
        operation,
        Some(
            hartevo_commerce_connector::amazon::AmazonRateLimit::parse("0.0167")
                .expect("rate limit"),
        ),
        None,
        1,
        Some(request_id.to_owned()),
    )
    .expect("quota evidence")
}

fn freshness(revision: u64) -> AmazonFreshnessEvidence {
    AmazonFreshnessEvidence::new(
        now() - Duration::seconds(1),
        now() + Duration::seconds(60),
        revision,
    )
    .expect("freshness evidence")
}

fn report_status_page() -> AmazonReportStatusPage {
    AmazonReportStatusPage {
        report: AmazonReport::new(
            "report-1",
            "GET_MERCHANT_LISTINGS_ALL_DATA",
            AmazonReportStatus::Done,
            Some("DOC-1".to_owned()),
            now() - Duration::seconds(20),
            Some(now() - Duration::seconds(10)),
        )
        .expect("done report"),
        quota: quota(AmazonOperation::ReportsGet, "status-1"),
        freshness: freshness(1),
    }
}

fn report_page(
    requested_cursor: Option<AmazonDocumentCursor>,
    page_sequence: u64,
    next_cursor: Option<AmazonDocumentCursor>,
    record_id: &str,
) -> AmazonReportDocumentPage {
    AmazonReportDocumentPage {
        document_id: AmazonReportDocumentId::parse("DOC-1").expect("document id"),
        document_url_digest: digest("presigned-document-url"),
        document_url_expires_at: now() + Duration::seconds(300),
        requested_cursor,
        page_sequence,
        next_cursor,
        records: vec![
            hartevo_commerce_connector::amazon_insight::AmazonInsightRecord::new(
                record_id,
                digest(record_id),
                now(),
            )
            .expect("report record"),
        ],
        observed_at: now(),
        quota: quota(AmazonOperation::ReportsDocument, "document-1"),
        freshness: freshness(page_sequence),
    }
}

fn report_state() -> Arc<Mutex<FakeAmazonState>> {
    Arc::new(Mutex::new(FakeAmazonState {
        report_status_calls: 0,
        report_document_calls: 0,
        notification_calls: 0,
        report_status: report_status_page(),
        report_pages: BTreeMap::from([
            (
                "<start>".to_owned(),
                report_page(
                    None,
                    1,
                    Some(AmazonDocumentCursor::parse("document-cursor-2").expect("cursor")),
                    "row-1",
                ),
            ),
            (
                "document-cursor-2".to_owned(),
                report_page(
                    Some(AmazonDocumentCursor::parse("document-cursor-2").expect("cursor")),
                    2,
                    None,
                    "row-2",
                ),
            ),
        ]),
        notification_pages: BTreeMap::new(),
        rate_limit_document_once: false,
        expired_document_url: false,
    }))
}

fn notification_state() -> Arc<Mutex<FakeAmazonState>> {
    let notification_type = AmazonNotificationType::parse("ORDER_CHANGE").expect("type");
    let event_type = notification_type.clone();
    let event = move |delivery_id: &str, sequence: u64| {
        AmazonNotificationEvent::new(
            delivery_id,
            sequence,
            event_type.clone(),
            now(),
            digest(delivery_id),
        )
        .expect("notification event")
    };
    Arc::new(Mutex::new(FakeAmazonState {
        report_status_calls: 0,
        report_document_calls: 0,
        notification_calls: 0,
        report_status: report_status_page(),
        report_pages: BTreeMap::new(),
        notification_pages: BTreeMap::from([
            (
                "<start>".to_owned(),
                AmazonNotificationPage {
                    notification_type: notification_type.clone(),
                    requested_cursor: None,
                    page_sequence: 1,
                    next_cursor: Some(
                        AmazonNotificationCursor::parse("notification-cursor-2").expect("cursor"),
                    ),
                    events: vec![event("delivery-1", 1), event("delivery-2", 2)],
                    observed_at: now(),
                    quota: quota(AmazonOperation::NotificationsSubscriptionsList, "notif-1"),
                    freshness: freshness(1),
                },
            ),
            (
                "notification-cursor-2".to_owned(),
                AmazonNotificationPage {
                    notification_type: notification_type.clone(),
                    requested_cursor: Some(
                        AmazonNotificationCursor::parse("notification-cursor-2").expect("cursor"),
                    ),
                    page_sequence: 2,
                    next_cursor: None,
                    events: vec![event("delivery-2", 2), event("delivery-3", 3)],
                    observed_at: now(),
                    quota: quota(AmazonOperation::NotificationsSubscriptionsList, "notif-2"),
                    freshness: freshness(2),
                },
            ),
        ]),
        rate_limit_document_once: false,
        expired_document_url: false,
    }))
}

fn service(
    state: Arc<Mutex<FakeAmazonState>>,
    scope: AmazonAccountScope,
    auth: AmazonLwaAuthState,
    store: AmazonInsightDurableStore,
    secret_reference: SecretReference,
) -> CommerceInsightReadService<FakeAmazonSpApiAdapter> {
    CommerceInsightReadService::new(
        FakeAmazonSpApiAdapter::new(state),
        secret_reference,
        scope,
        generation(),
        auth,
        ProviderProvenanceClass::ControlledProvider,
        store,
    )
    .expect("Amazon insight service")
}

fn new_store(
    scope: &AmazonAccountScope,
    secret_reference: &SecretReference,
) -> AmazonInsightDurableStore {
    AmazonInsightDurableStore::new(scope, secret_reference, generation()).expect("durable store")
}

#[test]
#[allow(clippy::too_many_lines)]
fn loopback_sp_api_http_reads_paginate_and_reconcile_durably() {
    let server = LoopbackHttpServer::start();
    let address = server.address();
    let scope = seller_scope();
    let token_digest = match auth_state() {
        AmazonLwaAuthState::TokenObserved { token, .. } => token.token_digest,
        AmazonLwaAuthState::Disconnected { .. } | AmazonLwaAuthState::BlockedEnv { .. } => {
            panic!("loopback token observation")
        }
    };

    let mut list_transport = LoopbackAmazonSpApiTransport::new(address);
    let first_list_request = list_reports_request(
        scope.clone(),
        LwaAccessTokenObservation::from_raw_token(
            b"controlled-token-only",
            now() - Duration::seconds(10),
            600,
        )
        .expect("list token"),
        None,
    )
    .expect("first reports list request");
    let first_list_response = list_transport
        .execute(first_list_request.clone())
        .expect("first reports list response");
    let first_list = parse_reports_page_read(&first_list_request, &first_list_response, now())
        .expect("first reports list page");
    assert_eq!(first_list.value.reports.len(), 1);
    assert_eq!(first_list.value.reports[0].report_id, "report-1");
    assert_eq!(
        first_list.value.next_token.as_deref(),
        Some("reports-cursor-2")
    );
    let second_list_request = list_reports_request(
        scope.clone(),
        LwaAccessTokenObservation::from_raw_token(
            b"controlled-token-only",
            now() - Duration::seconds(10),
            600,
        )
        .expect("list token"),
        first_list.value.next_token,
    )
    .expect("second reports list request");
    let second_list_response = list_transport
        .execute(second_list_request.clone())
        .expect("second reports list response");
    let second_list = parse_reports_page_read(&second_list_request, &second_list_response, now())
        .expect("second reports list page");
    assert_eq!(second_list.value.reports[0].report_id, "report-2");
    assert_eq!(second_list.value.next_token, None);

    let report_read_request = report_request(&scope);
    let report_secret = secret(&scope);
    let mut report_service = CommerceInsightReadService::new(
        LoopbackAmazonInsightAdapter::new(address),
        report_secret.clone(),
        scope.clone(),
        generation(),
        auth_state(),
        ProviderProvenanceClass::ControlledProvider,
        new_store(&scope, &report_secret),
    )
    .expect("loopback report service");
    let first_report = report_service
        .read(&report_read_request, now())
        .expect("first report document page");
    assert_eq!(first_report.page_sequence, 1);
    assert_eq!(first_report.items[0].item_id, "row-1");
    assert!(matches!(
        first_report.next_cursor,
        AmazonInsightCursor::Report(Some(_))
    ));
    assert_eq!(first_report.scope_digest, amazon_scope_digest(&scope));
    assert_eq!(first_report.provider_generation, generation());
    assert_eq!(
        first_report.provider_request_id,
        first_report.quota.request_id
    );
    assert_eq!(
        first_report
            .quota
            .rate_limit
            .as_ref()
            .expect("loopback report rate")
            .raw,
        "0.5"
    );
    assert_eq!(
        first_report.live_validation_status,
        AMAZON_INSIGHT_LIVE_VALIDATION_STATUS
    );
    assert!(!first_report.is_first_party());
    assert!(first_report.is_mission_adoptable());

    let restored_store: AmazonInsightDurableStore = serde_json::from_slice(
        &serde_json::to_vec(report_service.store()).expect("report checkpoint JSON"),
    )
    .expect("reopened report checkpoint");
    let mut restarted_report_service = CommerceInsightReadService::new(
        LoopbackAmazonInsightAdapter::new(address),
        report_secret,
        scope.clone(),
        generation(),
        auth_state(),
        ProviderProvenanceClass::ControlledProvider,
        restored_store,
    )
    .expect("restarted loopback report service");
    let second_report = restarted_report_service
        .read(&report_read_request, now() + Duration::seconds(1))
        .expect("second report document page after restart");
    assert_eq!(second_report.page_sequence, 2);
    assert_eq!(second_report.items[0].item_id, "row-2");
    assert_eq!(second_report.next_cursor, AmazonInsightCursor::Report(None));
    assert!(matches!(
        restarted_report_service.read(&report_read_request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::ResearchComplete)
    ));

    let notification_read_request = notification_request(scope.clone());
    let notification_secret = secret(&scope);
    let mut notification_service = CommerceInsightReadService::new(
        LoopbackAmazonInsightAdapter::new(address),
        notification_secret.clone(),
        scope.clone(),
        generation(),
        auth_state(),
        ProviderProvenanceClass::ControlledProvider,
        new_store(&scope, &notification_secret),
    )
    .expect("loopback notification service");
    let first_notification = notification_service
        .read(&notification_read_request, now())
        .expect("first notification page");
    assert_eq!(first_notification.items.len(), 2);
    let second_notification = notification_service
        .read(&notification_read_request, now() + Duration::seconds(1))
        .expect("second notification page");
    assert_eq!(second_notification.items.len(), 1);
    assert_eq!(second_notification.items[0].item_id, "delivery-3");
    assert_eq!(
        second_notification
            .quota
            .rate_limit
            .as_ref()
            .expect("loopback notification rate")
            .raw,
        "0.5"
    );
    assert!(!second_notification.is_first_party());
    assert_eq!(
        notification_service.store().checkpoints()[&notification_read_request.research_id]
            .seen_delivery_identities
            .len(),
        3
    );
    assert!(matches!(
        notification_service.read(&notification_read_request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::ResearchComplete)
    ));

    let requests = server.requests();
    assert_eq!(requests.len(), 9);
    assert!(requests.iter().all(|request| {
        request
            .headers
            .get("x-amz-access-token")
            .is_some_and(|value| value == &token_digest)
    }));
    assert_eq!(
        requests[0].request_line,
        "GET /reports/2021-06-30/reports HTTP/1.1"
    );
    assert!(
        requests[1]
            .request_line
            .contains("nextToken=reports-cursor-2")
    );
    assert_eq!(
        requests[2].request_line,
        "GET /reports/2021-06-30/reports/report-1 HTTP/1.1"
    );
    assert!(
        requests[3]
            .request_line
            .starts_with("GET /reports/2021-06-30/documents/DOC-1 HTTP/1.1")
    );
    assert_eq!(
        requests[4].request_line,
        "GET /document-content/DOC-1 HTTP/1.1"
    );
    assert!(
        requests[5]
            .request_line
            .starts_with("GET /reports/2021-06-30/documents/DOC-1 HTTP/1.1")
    );
    assert!(
        requests[6]
            .request_line
            .contains("/document-content/DOC-1?cursor=document-cursor-2")
    );
    assert!(
        requests[7]
            .request_line
            .contains("/notifications/v1/subscriptions")
    );
    assert!(
        requests[7]
            .request_line
            .contains("notificationTypes=ORDER_CHANGE")
    );
    assert!(
        requests[8]
            .request_line
            .contains("nextToken=notification-cursor-2")
    );
}

#[test]
fn report_and_notification_request_helpers_are_get_only_and_no_create_policy() {
    let scope = seller_scope();
    let token = match auth_state() {
        AmazonLwaAuthState::TokenObserved { token, .. } => token,
        AmazonLwaAuthState::Disconnected { .. } | AmazonLwaAuthState::BlockedEnv { .. } => {
            panic!("token observation")
        }
    };
    let job = report_job(&scope);
    let status_request = AmazonReportStatusRequest {
        scope: scope.clone(),
        job,
        access_token: token.clone(),
        provider_generation: generation(),
        at: now(),
    };
    let status_http = report_status_sp_api_request(&status_request).expect("status GET");
    assert_eq!(status_http.method, "GET");
    assert_eq!(status_http.path, "/reports/2021-06-30/reports/report-1");

    let document_http = report_document_sp_api_request(&AmazonReportDocumentPageRequest {
        scope: scope.clone(),
        document_id: AmazonReportDocumentId::parse("DOC-1").expect("document"),
        access_token: token.clone(),
        provider_generation: generation(),
        requested_cursor: None,
        page_size: 100,
        at: now(),
    })
    .expect("document GET");
    assert_eq!(document_http.method, "GET");
    assert_eq!(document_http.path, "/reports/2021-06-30/documents/DOC-1");

    let notification_http = notification_cursor_sp_api_request(&AmazonNotificationPageRequest {
        scope,
        feed: AmazonNotificationFeed::new("ORDER_CHANGE", "1.0", "subscription-1").expect("feed"),
        access_token: token,
        provider_generation: generation(),
        requested_cursor: Some(
            AmazonNotificationCursor::parse("notification-cursor-2").expect("cursor"),
        ),
        page_size: 100,
        at: now(),
    })
    .expect("notification GET");
    assert_eq!(notification_http.method, "GET");
    assert_eq!(notification_http.path, "/notifications/v1/subscriptions");
    assert_eq!(
        notification_http.query.get("nextToken"),
        Some(&"notification-cursor-2".to_owned())
    );
    assert_eq!(
        AMAZON_REPORT_CREATION_POLICY,
        "PREAUTHORIZED_REPORT_JOB_ONLY"
    );
}

#[test]
fn report_status_document_cursor_is_durable_and_restart_has_zero_duplicate_rows() {
    let scope = seller_scope();
    let request = report_request(&scope);
    let secret_reference = secret(&scope);
    let state = report_state();
    let store = new_store(&scope, &secret_reference);
    let mut first_service = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        store,
        secret_reference.clone(),
    );

    let first = first_service
        .read(&request, now())
        .expect("first report page");
    assert_eq!(first.page_sequence, 1);
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].item_id, "row-1");
    assert_eq!(
        first.classification,
        AmazonInsightClassification::ReportRecord
    );
    assert_eq!(
        first.source,
        hartevo_commerce_connector::amazon_insight::AmazonInsightSourceKind::Report
    );
    assert_eq!(first.scope_digest, amazon_scope_digest(&scope));
    assert_eq!(
        first.report_type.as_ref().expect("report type").as_str(),
        "GET_MERCHANT_LISTINGS_ALL_DATA"
    );
    assert!(first.processing_job_digest.is_some());
    assert!(first.document_id.is_some());
    assert!(!first.content_digest.is_empty());
    assert!(!first.result_digest.is_empty());
    assert_eq!(first.quota.cost_units, 1);
    assert!(first.freshness.valid_until > now());
    assert!(!first.is_connected());
    assert!(!first.is_first_party());
    assert!(first.is_mission_adoptable());
    assert_eq!(
        first.live_validation_status,
        AMAZON_INSIGHT_LIVE_VALIDATION_STATUS
    );

    let checkpoint_bytes =
        serde_json::to_vec(first_service.store()).expect("durable checkpoint JSON");
    let checkpoint_json = String::from_utf8(checkpoint_bytes.clone()).expect("checkpoint UTF-8");
    assert!(!checkpoint_json.contains("controlled-token-only"));
    let restored_store: AmazonInsightDurableStore =
        serde_json::from_slice(&checkpoint_bytes).expect("restored checkpoint");
    let mut restarted = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        restored_store,
        secret_reference,
    );
    let second = restarted
        .read(&request, now() + Duration::seconds(1))
        .expect("second report page after restart");
    assert_eq!(second.page_sequence, 2);
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].item_id, "row-2");
    assert_ne!(first.items[0].item_id, second.items[0].item_id);
    assert!(matches!(
        second.next_cursor,
        AmazonInsightCursor::Report(None)
    ));
    assert!(matches!(
        restarted.read(&request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::ResearchComplete)
    ));
    let state = state.lock().expect("fake state");
    assert_eq!(state.report_status_calls, 1);
    assert_eq!(state.report_document_calls, 2);
}

#[test]
fn notifications_resume_cursor_and_dedupe_duplicate_delivery_without_duplicate_result_items() {
    let scope = seller_scope();
    let request = notification_request(scope.clone());
    let secret_reference = secret(&scope);
    let state = notification_state();
    let mut notification_service = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );

    let first = notification_service
        .read(&request, now())
        .expect("first notification page");
    assert_eq!(first.items.len(), 2);
    assert_eq!(
        first.classification,
        AmazonInsightClassification::NotificationEvent
    );
    let second = notification_service
        .read(&request, now() + Duration::seconds(1))
        .expect("second notification page");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].item_id, "delivery-3");
    assert!(matches!(
        second.next_cursor,
        AmazonInsightCursor::Notifications(None)
    ));
    assert!(matches!(
        notification_service.read(&request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::ResearchComplete)
    ));
    assert_eq!(
        notification_service.store().checkpoints()[&request.research_id]
            .seen_delivery_identities
            .len(),
        3
    );
    let state = state.lock().expect("fake state");
    assert_eq!(state.notification_calls, 2);
}

#[test]
fn cursor_rollback_and_out_of_order_notification_fail_closed() {
    let scope = seller_scope();
    let request = notification_request(scope.clone());
    let secret_reference = secret(&scope);
    let state = notification_state();
    {
        let mut fake = state.lock().expect("fake state");
        let page = fake
            .notification_pages
            .get_mut("notification-cursor-2")
            .expect("second page");
        page.next_cursor = Some(
            AmazonNotificationCursor::parse("notification-cursor-2").expect("rollback cursor"),
        );
        page.events = vec![
            AmazonNotificationEvent::new(
                "delivery-3",
                3,
                AmazonNotificationType::parse("ORDER_CHANGE").expect("type"),
                now(),
                digest("delivery-3"),
            )
            .expect("event"),
        ];
    }
    let mut rollback_service = service(
        state,
        scope,
        auth_state(),
        new_store(&seller_scope(), &secret_reference),
        secret_reference,
    );
    rollback_service.read(&request, now()).expect("first page");
    assert!(matches!(
        rollback_service.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::CursorRollback)
    ));
    assert!(matches!(
        rollback_service.read(&request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::PreviouslyFailedClosed)
    ));

    let out_of_order_state = notification_state();
    {
        let mut fake = out_of_order_state.lock().expect("fake state");
        let page = fake
            .notification_pages
            .get_mut("notification-cursor-2")
            .expect("second page");
        page.next_cursor = None;
        page.events = vec![
            AmazonNotificationEvent::new(
                "delivery-old",
                1,
                AmazonNotificationType::parse("ORDER_CHANGE").expect("type"),
                now(),
                digest("delivery-old"),
            )
            .expect("event"),
        ];
    }
    let scope = seller_scope();
    let secret_reference = secret(&scope);
    let mut out_of_order = service(
        out_of_order_state,
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    out_of_order.read(&request, now()).expect("first page");
    assert!(matches!(
        out_of_order.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::OutOfOrderNotification)
    ));
}

#[test]
fn retry_after_is_durable_and_expired_document_url_fails_closed() {
    let scope = seller_scope();
    let request = report_request(&scope);
    let secret_reference = secret(&scope);
    let state = report_state();
    state.lock().expect("fake state").rate_limit_document_once = true;
    let mut retry_service = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference.clone(),
    );
    assert!(matches!(
        retry_service.read(&request, now()),
        Err(AmazonInsightError::RetryAfter { .. })
    ));
    assert!(matches!(
        retry_service.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::RetryAfterNotElapsed { .. })
    ));
    let recovered = retry_service
        .read(&request, now() + Duration::seconds(11))
        .expect("retry after elapsed");
    assert_eq!(recovered.page_sequence, 1);

    let expired_state = report_state();
    expired_state
        .lock()
        .expect("fake state")
        .expired_document_url = true;
    let mut expired = service(
        expired_state,
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    assert!(matches!(
        expired.read(&request, now()),
        Err(AmazonInsightError::DocumentUrlExpired)
    ));
    assert!(matches!(
        expired.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::PreviouslyFailedClosed)
    ));
}

#[test]
fn scope_drift_revoke_and_no_credentials_are_fail_closed_without_connected_authority() {
    let scope = seller_scope();
    let request = report_request(&scope);
    let secret_reference = secret(&scope);
    let state = report_state();
    let mut no_credentials = service(
        state.clone(),
        scope.clone(),
        AmazonLwaAuthState::no_credentials(now()),
        new_store(&scope, &secret_reference),
        secret_reference.clone(),
    );
    assert!(!no_credentials.is_connected());
    assert!(matches!(
        no_credentials.read(&request, now()),
        Err(AmazonInsightError::BlockedEnv)
    ));
    assert_eq!(state.lock().expect("fake state").report_status_calls, 0);

    let drifted_scope = AmazonAccountScope::new(
        AmazonAccountIdentity::seller("A1SELLER02").expect("seller"),
        hartevo_commerce_connector::amazon::AmazonMarketplace::us(),
        BTreeSet::from([AmazonRole::reports()]),
    )
    .expect("drift scope");
    let drifted_job = AmazonPreauthorizedReportJob::new(
        &seller_scope(),
        generation(),
        "report-1",
        "GET_MERCHANT_LISTINGS_ALL_DATA",
        digest("external-preauthorized-report-job"),
        now() - Duration::seconds(30),
    )
    .expect("job");
    assert!(matches!(
        AmazonInsightReadRequest::new(
            "mission-research-report-drift",
            drifted_scope,
            generation(),
            AmazonInsightSource::Report { job: drifted_job },
            now() - Duration::seconds(10),
            now() + Duration::seconds(100),
            100,
        ),
        Err(AmazonInsightError::ScopeDrift)
    ));

    let scope = seller_scope();
    let secret_reference = secret(&scope);
    let mut revoked = service(
        report_state(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    revoked.revoke(now()).expect("revoke");
    assert!(matches!(
        revoked.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::ConsumerNotMounted)
    ));
    assert!(revoked.store().checkpoints().is_empty());
}

#[test]
#[ignore = "requires HARTEVO_AMAZON_SP_API_LIVE=1, real LWA credentials, and an external read adapter"]
fn env_gated_live_probe_is_explicit() {
    assert!(live_probe_enabled());
}

#[test]
fn mission_capability_is_read_only_and_source_is_amazon_sp_api() {
    let scope = seller_scope();
    let request = notification_request(scope.clone());
    let secret_reference = secret(&scope);
    let service = service(
        notification_state(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    let capability = service.capability(&request);
    assert_eq!(capability.capability_id, AMAZON_INSIGHT_CAPABILITY_ID);
    assert_eq!(capability.provider_id, "amazon-sp-api");
    assert!(capability.read_only);
    assert!(!capability.connected);
    assert_eq!(capability.scope_digest, amazon_scope_digest(&scope));
}

#[test]
fn scope_digest_keeps_seller_vendor_marketplace_region_and_generation_exact() {
    let seller = seller_scope();
    let vendor = AmazonAccountScope::new(
        AmazonAccountIdentity::vendor("VENDOR01").expect("vendor"),
        hartevo_commerce_connector::amazon::AmazonMarketplace::uk(),
        BTreeSet::from([AmazonRole::reports()]),
    )
    .expect("vendor scope");
    assert_eq!(
        vendor.marketplace.region,
        hartevo_commerce_connector::amazon::AmazonRegion::Europe
    );
    assert_ne!(amazon_scope_digest(&seller), amazon_scope_digest(&vendor));
    assert!(
        AmazonInsightDurableStore::new(
            &seller,
            &SecretReference::new(
                "secret-ref-amazon-insight-generation-mismatch",
                connector_scope(seller.account.account_id()),
                8,
            )
            .expect("generation mismatch secret"),
            generation(),
        )
        .is_err()
    );
}
