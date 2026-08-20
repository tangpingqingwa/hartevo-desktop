use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration, TimeZone, Utc};
use hartevo_commerce_connector::sorftime::{
    SorftimeAccountId, SorftimeApiRequest, SorftimeCliRequest, SorftimeDataset, SorftimeMarket,
    SorftimeResponse, SorftimeTransport, SorftimeTransportError, SorftimeTransportKind,
};
use hartevo_commerce_connector::sorftime_outcome::{
    SorftimeEstimateAdoptionRequest, SorftimeEstimateOutcomeConsumer,
    SorftimeEstimateOutcomePacket, SorftimeEstimateWorkProduct, SorftimeMissionBinding,
    SorftimeOutcomeCheckpoint, SorftimeOutcomeCheckpointState, SorftimeOutcomeError,
    SorftimeOutcomePlan, commerce_connector_contract_digest,
};
use hartevo_commerce_connector::sorftime_plugin::{
    SorftimeCheckpointState, SorftimeDurableCheckpoint, SorftimeEstimateProvider,
    SorftimeEstimateService, SorftimeProviderError, SorftimeProviderResponse,
    SorftimeQuotaEvidence, SorftimeReadPlan, SorftimeTransportIdentity,
};
use hartevo_commerce_connector::{MarketId, SORFTIME_ADAPTER_ID, sorftime_adapter_identity};
use hartevo_connector_sdk::{
    ConnectorAuth, ConnectorScope, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{CurrencyCode, MissionId, ProjectId};
use serde_json::{Value, json};

#[derive(Clone, Debug)]
struct LoopbackSorftimeRequest {
    request_line: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

#[derive(Debug)]
struct LoopbackSorftimeServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<LoopbackSorftimeRequest>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl LoopbackSorftimeServer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("Sorftime loopback listener");
        listener
            .set_nonblocking(true)
            .expect("Sorftime loopback nonblocking listener");
        let address = listener.local_addr().expect("Sorftime loopback address");
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
                                .expect("Sorftime loopback request state")
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

    fn requests(&self) -> Vec<LoopbackSorftimeRequest> {
        self.requests
            .lock()
            .expect("Sorftime loopback request state")
            .clone()
    }
}

impl Drop for LoopbackSorftimeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Clone, Debug)]
struct LoopbackSorftimeTransport {
    address: SocketAddr,
    secret_reference_id: String,
    lease_id: String,
}

impl LoopbackSorftimeTransport {
    fn new(address: SocketAddr, secret_reference_id: &str, lease_id: &str) -> Self {
        Self {
            address,
            secret_reference_id: secret_reference_id.into(),
            lease_id: lease_id.into(),
        }
    }

    fn post(
        &mut self,
        path: &str,
        body: &Value,
    ) -> Result<SorftimeResponse, SorftimeTransportError> {
        let body = body.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: loopback.sorftime.test\r\nContent-Type: application/json\r\nX-Sorftime-Secret-Reference: {}\r\nX-Sorftime-Credential-Lease: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.secret_reference_id,
            self.lease_id,
            body.len()
        );
        let mut stream = TcpStream::connect(self.address)
            .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?;
        stream
            .set_read_timeout(Some(StdDuration::from_secs(1)))
            .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?;
        stream
            .set_write_timeout(Some(StdDuration::from_secs(1)))
            .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?;
        parse_loopback_response(&response)
    }
}

impl SorftimeTransport for LoopbackSorftimeTransport {
    fn execute_api(
        &mut self,
        request: SorftimeApiRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError> {
        self.post(
            "/api/v1/estimate",
            &serde_json::to_value(request)
                .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?,
        )
    }

    fn execute_cli(
        &mut self,
        request: SorftimeCliRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError> {
        self.post(
            "/cli/v1/estimate",
            &serde_json::to_value(request)
                .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?,
        )
    }
}

#[derive(Debug)]
struct LoopbackSorftimeProvider {
    transport: LoopbackSorftimeTransport,
    calls: Arc<Mutex<u32>>,
}

impl LoopbackSorftimeProvider {
    fn new(
        address: SocketAddr,
        secret_reference_id: &str,
        lease_id: &str,
        calls: Arc<Mutex<u32>>,
    ) -> Self {
        Self {
            transport: LoopbackSorftimeTransport::new(address, secret_reference_id, lease_id),
            calls,
        }
    }
}

impl SorftimeEstimateProvider for LoopbackSorftimeProvider {
    fn execute(
        &mut self,
        request: &SorftimeCliRequest,
        secret: &SecretReference,
        lease: &hartevo_connector_sdk::CredentialLease,
        scope: &ConnectorScope,
        _now: chrono::DateTime<Utc>,
    ) -> Result<SorftimeProviderResponse, SorftimeProviderError> {
        if request.account.as_str() != scope.account_id()
            || secret.scope() != scope
            || lease.scope() != scope
            || self.transport.secret_reference_id != secret.reference_id()
            || self.transport.lease_id != lease.lease_id()
        {
            return Err(SorftimeProviderError::CredentialInjectionRejected);
        }
        *self.calls.lock().expect("Sorftime loopback call count") += 1;
        let response = self
            .transport
            .execute_cli(request.clone())
            .map_err(|error| SorftimeProviderError::CommandFailed {
                code: 1,
                stderr_digest: error.to_string(),
            })?;
        let observed_at = fixture_time();
        Ok(SorftimeProviderResponse {
            response,
            observed_at,
            quota: SorftimeQuotaEvidence::new(997, "loopback-cli-quota/v1", observed_at)
                .expect("loopback quota"),
            transport: SorftimeTransportIdentity::controlled("loopback-cli-http/v1")
                .expect("loopback transport"),
        })
    }

    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ControlledProvider
    }

    fn transport_identity(&self) -> SorftimeTransportIdentity {
        SorftimeTransportIdentity::controlled("loopback-cli-http/v1").expect("transport")
    }
}

fn read_loopback_request(stream: &mut TcpStream) -> std::io::Result<LoopbackSorftimeRequest> {
    stream.set_read_timeout(Some(StdDuration::from_secs(1)))?;
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break find_subsequence(&bytes, b"\r\n\r\n");
        }
        bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = find_subsequence(&bytes, b"\r\n\r\n") else {
            continue;
        };
        let header = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = header.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        });
        if bytes.len() >= header_end + 4 + content_length.unwrap_or_default() {
            break Some(header_end);
        }
    }
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing Sorftime loopback request headers",
        )
    })?;
    let header = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = header.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let body: Value = serde_json::from_slice(
        &bytes[header_end + 4..header_end + 4 + content_length],
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(LoopbackSorftimeRequest {
        request_line,
        headers,
        body,
    })
}

fn write_loopback_response(stream: &mut TcpStream, body: &Value) -> std::io::Result<()> {
    let body = body.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()
}

fn parse_loopback_response(bytes: &[u8]) -> Result<SorftimeResponse, SorftimeTransportError> {
    let separator = find_subsequence(bytes, b"\r\n\r\n")
        .ok_or_else(|| SorftimeTransportError::Failed("missing loopback response body".into()))?;
    let header = String::from_utf8_lossy(&bytes[..separator]);
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| SorftimeTransportError::Failed("invalid loopback status".into()))?;
    let body: Value = serde_json::from_slice(&bytes[separator + 4..])
        .map_err(|error| SorftimeTransportError::Failed(error.to_string()))?;
    let request_id = body
        .get("requestId")
        .and_then(Value::as_str)
        .ok_or_else(|| SorftimeTransportError::Failed("missing provider request id".into()))?;
    Ok(SorftimeResponse {
        status,
        request_id: request_id.into(),
        body,
        cost_units: 3,
        cost_currency: None,
        cost_source: "loopback-cli-price/v1".into(),
    })
}

fn loopback_response(request_line: &str) -> Value {
    if request_line != "POST /cli/v1/estimate HTTP/1.1"
        && request_line != "POST /api/v1/estimate HTTP/1.1"
    {
        return json!({"requestId":"loopback-provider-request-1","code":1});
    }
    json!({
        "requestId": "loopback-provider-request-1",
        "RequestLeft": 997,
        "code": 0,
        "asin": "B0C0MERC01",
        "estimatedUnits": 420,
        "estimatedRevenueMinor": 42000,
        "currency": "USD"
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Clone, Debug)]
struct FakeProvider {
    calls: Rc<RefCell<u32>>,
    response: SorftimeResponse,
    observed_at: chrono::DateTime<Utc>,
    quota: SorftimeQuotaEvidence,
    transport: SorftimeTransportIdentity,
}

impl SorftimeEstimateProvider for FakeProvider {
    fn execute(
        &mut self,
        request: &SorftimeCliRequest,
        secret: &SecretReference,
        lease: &hartevo_connector_sdk::CredentialLease,
        scope: &ConnectorScope,
        _now: chrono::DateTime<Utc>,
    ) -> Result<SorftimeProviderResponse, SorftimeProviderError> {
        assert_eq!(request.account.as_str(), scope.account_id());
        assert_eq!(secret.scope(), scope);
        assert_eq!(lease.scope(), scope);
        *self.calls.borrow_mut() += 1;
        Ok(SorftimeProviderResponse {
            response: self.response.clone(),
            observed_at: self.observed_at,
            quota: self.quota.clone(),
            transport: self.transport.clone(),
        })
    }

    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ControlledProvider
    }

    fn transport_identity(&self) -> SorftimeTransportIdentity {
        self.transport.clone()
    }
}

fn fixture_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
        .single()
        .expect("fixture time")
}

fn fixture_scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-sorftime",
        "project-sorftime",
        "sorftime",
        "sorftime-fixture-account",
        BTreeSet::from(["read_estimates".to_owned()]),
    )
    .expect("scope")
}

fn fixture_request() -> SorftimeCliRequest {
    SorftimeCliRequest::new(
        SorftimeAccountId::parse("sorftime-fixture-account").expect("account"),
        SorftimeMarket::new(
            MarketId::parse("ATVPDKIKX0DER").expect("market"),
            "en-US",
            CurrencyCode::parse("USD").expect("currency"),
        )
        .expect("market"),
        SorftimeDataset::Product,
        "mission-sorftime-read-01",
        json!({"asin":"B0C0MERC01","trend":1}),
    )
    .expect("request")
}

fn fixture_service(calls: Rc<RefCell<u32>>) -> SorftimeEstimateService<FakeProvider> {
    let scope = fixture_scope();
    let secret = SecretReference::new("secret-ref-sorftime-fixture", scope.clone(), 1)
        .expect("secret reference");
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        sorftime_adapter_identity().expect("adapter"),
        "credential-lease-sorftime-fixture",
        1,
        fixture_time(),
        fixture_time() + Duration::minutes(5),
    )
    .expect("credential lease");
    let observed_at = fixture_time();
    let transport = SorftimeTransportIdentity::controlled("outcome-contract").expect("transport");
    let quota = SorftimeQuotaEvidence::new(997, "fixture-quota", observed_at).expect("quota");
    let provider = FakeProvider {
        calls,
        response: SorftimeResponse {
            status: 200,
            request_id: "provider-request-sorftime-outcome-01".into(),
            body: json!({
                "asin":"B0C0MERC01",
                "estimatedUnits":420,
                "estimatedRevenueMinor":42000,
                "currency":"USD"
            }),
            cost_units: 3,
            cost_currency: None,
            cost_source: "fixture-price-list/v1".into(),
        },
        observed_at,
        quota,
        transport,
    };
    SorftimeEstimateService::with_freshness(provider, secret, lease, scope, Duration::minutes(5))
        .expect("service")
}

fn committed_receipt(calls: Rc<RefCell<u32>>) -> SorftimeDurableCheckpoint {
    let mut service = fixture_service(calls);
    let now = fixture_time();
    let request = fixture_request();
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), now)
        .expect("prepare");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("new provider request replayed"),
    };
    let (_result, checkpoint) = service
        .execute_prepared(&prepared, now)
        .expect("controlled provider result");
    checkpoint
}

fn binding(generation: u64) -> SorftimeMissionBinding {
    SorftimeMissionBinding::new(
        ProjectId::from("project-sorftime"),
        MissionId::from("mission-sorftime-outcome-01"),
        generation,
        SORFTIME_ADAPTER_ID,
        "a".repeat(64),
        commerce_connector_contract_digest(),
    )
    .expect("binding")
}

fn adoption_request(
    checkpoint: SorftimeDurableCheckpoint,
    generation: u64,
) -> SorftimeEstimateAdoptionRequest {
    SorftimeEstimateAdoptionRequest::new(binding(generation), checkpoint)
}

#[allow(clippy::too_many_lines)]
#[test]
fn loopback_cli_estimate_reaches_durable_outcome_and_replays_without_provider_call() {
    let server = LoopbackSorftimeServer::start();
    let calls = Arc::new(Mutex::new(0));
    let scope = fixture_scope();
    let secret = SecretReference::new("secret-ref-sorftime-loopback", scope.clone(), 1)
        .expect("loopback secret reference");
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        sorftime_adapter_identity().expect("adapter"),
        "credential-lease-sorftime-loopback",
        1,
        fixture_time(),
        fixture_time() + Duration::minutes(5),
    )
    .expect("loopback credential lease");
    let provider = LoopbackSorftimeProvider::new(
        server.address(),
        secret.reference_id(),
        lease.lease_id(),
        calls.clone(),
    );
    let mut service = SorftimeEstimateService::with_freshness(
        provider,
        secret,
        lease,
        scope.clone(),
        Duration::minutes(5),
    )
    .expect("loopback estimate service");
    let request = fixture_request();
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), fixture_time())
        .expect("prepare loopback estimate");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("empty provider checkpoint replayed"),
    };
    let (result, receipt_checkpoint) = service
        .execute_prepared(&prepared, fixture_time())
        .expect("loopback estimate response");
    assert_eq!(*calls.lock().expect("loopback calls"), 1);
    assert_eq!(result.request_id, request.request_id);
    assert_eq!(result.dataset, SorftimeDataset::Product);
    assert_eq!(result.transport.transport, SorftimeTransportKind::Cli);
    assert_eq!(result.provenance_class, "controlled_provider");
    assert_eq!(result.live_validation_status, "BLOCKED_ENV");
    assert_eq!(result.cost.units, 3);
    assert_eq!(result.quota.request_left, 997);
    assert!(result.is_estimate_only());
    assert!(result.is_mission_adoptable());
    assert!(!result.is_connected());
    assert!(!result.is_first_party_amazon_fact());

    let receipt_json = serde_json::to_string(&receipt_checkpoint).expect("receipt JSON");
    assert!(!receipt_json.contains("raw-secret"));
    let reopened_receipt: SorftimeDurableCheckpoint =
        serde_json::from_str(&receipt_json).expect("reopened committed receipt");
    assert!(reopened_receipt.committed_receipt().is_ok());

    let request = adoption_request(reopened_receipt, 7);
    let consumer =
        SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("outcome consumer");
    let prepared = match consumer
        .prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time())
        .expect("prepare estimate adoption")
    {
        SorftimeOutcomePlan::Adopt(prepared) => prepared,
        SorftimeOutcomePlan::Replay(_) => panic!("empty outcome checkpoint replayed"),
    };
    assert!(prepared.work_product().is_estimate_only());
    assert_eq!(prepared.work_product().account.as_str(), scope.account_id());
    assert_eq!(prepared.work_product().dataset, SorftimeDataset::Product);
    let (outcome, outcome_checkpoint) = consumer
        .commit_adoption(&prepared, fixture_time())
        .expect("commit estimate adoption");
    assert!(outcome.is_estimate_only());
    assert!(!outcome.is_connected());
    assert!(!outcome.is_first_party_amazon_fact());
    assert!(!outcome.has_effect_e4_authority());
    assert_eq!(outcome.receipt_digest, outcome.work_product.receipt_digest);

    let outcome_json = serde_json::to_string(&outcome_checkpoint).expect("outcome JSON");
    let reopened_outcome: SorftimeOutcomeCheckpoint =
        serde_json::from_str(&outcome_json).expect("reopened outcome checkpoint");
    let replay = consumer
        .prepare_adoption(
            &request,
            reopened_outcome,
            fixture_time() + Duration::seconds(1),
        )
        .expect("replay committed outcome");
    let replayed = match replay {
        SorftimeOutcomePlan::Replay(outcome) => outcome,
        SorftimeOutcomePlan::Adopt(_) => panic!("committed outcome adopted twice"),
    };
    assert!(replayed.replayed);
    assert_eq!(replayed.outcome_digest, outcome.outcome_digest);
    assert_eq!(
        replayed.work_product.work_product_digest,
        outcome.work_product.work_product_digest
    );
    assert_eq!(*calls.lock().expect("loopback calls"), 1);

    let mut api_transport = LoopbackSorftimeTransport::new(
        server.address(),
        "secret-ref-sorftime-loopback",
        "credential-lease-sorftime-loopback",
    );
    let api_request = SorftimeApiRequest::new(
        "https://open.sorftime.com/api",
        SorftimeAccountId::parse("sorftime-fixture-account").expect("API account"),
        SorftimeMarket::new(
            MarketId::parse("ATVPDKIKX0DER").expect("API market"),
            "en-US",
            CurrencyCode::parse("USD").expect("API currency"),
        )
        .expect("API market identity"),
        SorftimeDataset::Product,
        "loopback-api-request-1",
        json!({"asin":"B0C0MERC01"}),
    )
    .expect("API request");
    let api_response = api_transport
        .execute_api(api_request.clone())
        .expect("loopback API response");
    assert_eq!(api_response.status, 200);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].request_line, "POST /cli/v1/estimate HTTP/1.1");
    assert_eq!(requests[1].request_line, "POST /api/v1/estimate HTTP/1.1");
    assert_eq!(
        requests[0].headers.get("x-sorftime-secret-reference"),
        Some(&"secret-ref-sorftime-loopback".to_owned())
    );
    assert_eq!(
        requests[0].headers.get("x-sorftime-credential-lease"),
        Some(&"credential-lease-sorftime-loopback".to_owned())
    );
    assert_eq!(requests[0].body["program"], "sorftime");
    assert_eq!(requests[0].body["requestId"], "mission-sorftime-read-01");
    assert_eq!(requests[0].body["dataset"], "product");
    assert_eq!(requests[0].body["payload"]["asin"], "B0C0MERC01");
    assert!(
        requests[0].body["args"]
            .as_array()
            .expect("CLI args")
            .windows(2)
            .any(|window| window == ["--output", "json"])
    );
    assert_eq!(
        requests[1].body["endpoint"].as_str(),
        Some(api_request.endpoint.as_str())
    );
    assert!(
        !serde_json::to_string(&requests[0].body)
            .expect("wire body JSON")
            .contains("raw-secret")
    );
}

#[test]
fn committed_receipt_becomes_complete_estimate_work_product_and_replays_without_duplication() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls.clone());
    assert_eq!(*calls.borrow(), 1);
    let request = adoption_request(receipt_checkpoint.clone(), 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");

    let plan = consumer
        .prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time())
        .expect("prepare adoption");
    let prepared = match plan {
        SorftimeOutcomePlan::Adopt(prepared) => prepared,
        SorftimeOutcomePlan::Replay(_) => panic!("empty adoption checkpoint replayed"),
    };
    assert_eq!(
        prepared.checkpoint().state,
        SorftimeOutcomeCheckpointState::InFlight
    );
    assert_eq!(
        prepared.work_product().account.as_str(),
        "sorftime-fixture-account"
    );
    assert_eq!(prepared.work_product().dataset, SorftimeDataset::Product);
    assert_eq!(prepared.work_product().cost.units, 3);
    assert_eq!(prepared.work_product().quota.request_left, 997);
    assert_eq!(prepared.work_product().counterevidence.len(), 3);
    assert_eq!(prepared.work_product().limitations.len(), 4);
    assert!(prepared.work_product().is_estimate_only());
    assert!(!prepared.work_product().is_connected());
    assert!(!prepared.work_product().is_first_party_amazon_fact());
    assert!(!prepared.work_product().has_effect_e4_authority());

    let durable_in_flight = serde_json::to_string(prepared.checkpoint()).expect("checkpoint JSON");
    assert!(!durable_in_flight.contains("fixture-account-secret"));
    let reopened_in_flight: SorftimeOutcomeCheckpoint =
        serde_json::from_str(&durable_in_flight).expect("reopen in-flight checkpoint");
    assert!(matches!(
        consumer.prepare_adoption(&request, reopened_in_flight, fixture_time()),
        Err(SorftimeOutcomeError::UnknownTerminal)
    ));

    let (outcome, committed) = consumer
        .commit_adoption(&prepared, fixture_time())
        .expect("commit adoption");
    assert!(outcome.is_estimate_only());
    assert!(!outcome.is_connected());
    assert!(!outcome.is_first_party_amazon_fact());
    assert!(!outcome.has_effect_e4_authority());
    assert!(!outcome.replayed);
    assert_eq!(committed.state, SorftimeOutcomeCheckpointState::Committed);
    assert_eq!(
        committed.receipt_digest,
        Some(outcome.receipt_digest.clone())
    );
    assert_eq!(*calls.borrow(), 1);

    let committed_json = serde_json::to_string(&committed).expect("committed JSON");
    let reopened_committed: SorftimeOutcomeCheckpoint =
        serde_json::from_str(&committed_json).expect("reopen committed checkpoint");
    let replay = consumer
        .prepare_adoption(
            &request,
            reopened_committed,
            fixture_time() + Duration::seconds(1),
        )
        .expect("replay outcome");
    let replayed = match replay {
        SorftimeOutcomePlan::Replay(outcome) => outcome,
        SorftimeOutcomePlan::Adopt(_) => panic!("committed adoption executed twice"),
    };
    assert!(replayed.replayed);
    assert_eq!(replayed.outcome_digest, outcome.outcome_digest);
    assert_eq!(
        replayed.work_product.work_product_digest,
        outcome.work_product.work_product_digest
    );
    assert_eq!(*calls.borrow(), 1);
}

#[test]
fn exact_binding_and_receipt_states_fail_closed() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint.clone(), 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");

    let wrong_request =
        SorftimeEstimateAdoptionRequest::new(binding(8), receipt_checkpoint.clone());
    assert!(matches!(
        consumer.prepare_adoption(
            &wrong_request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::BindingMismatch)
    ));

    let mut in_flight_receipt = receipt_checkpoint.clone();
    in_flight_receipt.state = SorftimeCheckpointState::InFlight;
    assert!(matches!(
        consumer.prepare_adoption(
            &adoption_request(in_flight_receipt, 7),
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::ReceiptUnknownTerminal)
    ));

    let mut failed_receipt = receipt_checkpoint.clone();
    failed_receipt.state = SorftimeCheckpointState::FailedClosed;
    failed_receipt.result = None;
    failed_receipt.result_digest = None;
    assert!(matches!(
        consumer.prepare_adoption(
            &adoption_request(failed_receipt, 7),
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::ReceiptFailedClosed)
    ));

    let mut tampered_receipt = receipt_checkpoint;
    tampered_receipt.scope_digest = Some("b".repeat(64));
    assert!(matches!(
        consumer.prepare_adoption(
            &adoption_request(tampered_receipt, 7),
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::InvalidReceipt(_))
    ));

    let failed_outcome_checkpoint = SorftimeOutcomeCheckpoint::empty()
        .failed_closed(&SorftimeOutcomeError::UnknownTerminal, fixture_time());
    assert!(matches!(
        consumer.prepare_adoption(&request, failed_outcome_checkpoint, fixture_time()),
        Err(SorftimeOutcomeError::PreviouslyFailedClosed)
    ));
}

#[test]
fn revoke_unmount_rotation_and_freshness_never_adopt_an_old_packet() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint, 7);
    let mut consumer =
        SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");

    consumer.unmount();
    assert!(matches!(
        consumer.prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time()),
        Err(SorftimeOutcomeError::Unmounted)
    ));

    let mut revoked_consumer =
        SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    revoked_consumer.revoke();
    assert!(matches!(
        revoked_consumer.prepare_adoption(
            &request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::Revoked)
    ));

    let mut rotating_consumer =
        SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    let prepared = match rotating_consumer
        .prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time())
        .expect("prepare before rotation")
    {
        SorftimeOutcomePlan::Adopt(prepared) => prepared,
        SorftimeOutcomePlan::Replay(_) => panic!("empty adoption checkpoint replayed"),
    };
    rotating_consumer
        .rotate_generation(8)
        .expect("rotate generation");
    assert!(matches!(
        rotating_consumer.commit_adoption(&prepared, fixture_time()),
        Err(SorftimeOutcomeError::CheckpointMismatch)
    ));

    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    assert!(matches!(
        consumer.prepare_adoption(
            &request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time() - Duration::seconds(1)
        ),
        Err(SorftimeOutcomeError::Stale)
    ));
    assert!(matches!(
        consumer.prepare_adoption(
            &request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time() + Duration::minutes(5)
        ),
        Err(SorftimeOutcomeError::Expired)
    ));
}

#[test]
fn packet_tampering_cannot_promote_estimate_to_first_party_or_effect_authority() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint, 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    let prepared = match consumer
        .prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time())
        .expect("prepare")
    {
        SorftimeOutcomePlan::Adopt(prepared) => prepared,
        SorftimeOutcomePlan::Replay(_) => panic!("empty adoption checkpoint replayed"),
    };
    let mut product = prepared.work_product().clone();
    product.classification = "amazon_first_party_fact".into();
    assert!(matches!(
        product.validate(),
        Err(SorftimeOutcomeError::InvalidWorkProduct(_) | SorftimeOutcomeError::InvalidReceipt(_))
    ));

    let (outcome, _) = consumer
        .commit_adoption(&prepared, fixture_time())
        .expect("commit");
    let mut tampered = outcome.clone();
    tampered.work_product.limitations.clear();
    assert!(matches!(
        tampered.validate(),
        Err(SorftimeOutcomeError::InvalidWorkProduct(_))
    ));
    assert!(outcome.is_estimate_only());
    assert!(!SorftimeEstimateOutcomePacket::is_connected(&outcome));
    assert!(!SorftimeEstimateOutcomePacket::is_first_party_amazon_fact(
        &outcome
    ));
    assert!(!SorftimeEstimateWorkProduct::has_effect_e4_authority(
        &outcome.work_product
    ));
}

#[test]
fn unsupported_outcome_checkpoint_is_unknown_not_replayable() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint, 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    let mut checkpoint = SorftimeOutcomeCheckpoint::empty();
    checkpoint.checkpoint_version = "future-outcome-checkpoint/v9".into();
    assert!(matches!(
        consumer.prepare_adoption(&request, checkpoint, fixture_time()),
        Err(SorftimeOutcomeError::UnknownTerminal)
    ));
}
