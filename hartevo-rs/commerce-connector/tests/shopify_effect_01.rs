use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_commerce_connector::shopify::{ShopDomain, ShopifyApiVersion};
use hartevo_commerce_connector::shopify_effect::{
    DraftFulfillmentRequest, FULFILLMENT_CREATE_MUTATION, FULFILLMENT_READBACK_QUERY,
    SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS, SHOPIFY_FULFILLMENT_READ_SCOPE,
    SHOPIFY_FULFILLMENT_WRITE_SCOPE, ShopifyApprovalRevision, ShopifyEffectIdempotencyKey,
    ShopifyEffectLifecycle, ShopifyFulfillmentEffectError, ShopifyFulfillmentEffectService,
    ShopifyFulfillmentEffectStore, ShopifyFulfillmentLineItem, ShopifyFulfillmentOrderGid,
    ShopifyFulfillmentOrderLineItemGid, ShopifyFulfillmentProvider,
    ShopifyFulfillmentProviderError, ShopifyFulfillmentRecordState, ShopifyFulfillmentScope,
    ShopifyOrderGid, ShopifyProbeStatus, ShopifyProviderReceipt, ShopifyReadbackLookup,
    ShopifyReadbackObservation, ShopifyReadbackStatus, ShopifyScopeProbe, ShopifyScopeProbeRequest,
    shopify_fulfillment_adapter_identity, shopify_fulfillment_provider_digest,
};
use hartevo_connector_sdk::{
    ConnectorAuth, ConnectorScope, ProviderProvenanceClass, SecretReference,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const NOW_YEAR: i32 = 2026;

#[derive(Clone, Debug, Default)]
struct FakeState {
    probe_calls: u32,
    execute_calls: u32,
    readback_calls: u32,
    timeout_after_commit: bool,
    missing_write_scope: bool,
    wrong_generation: bool,
    operations: BTreeMap<String, ShopifyProviderReceipt>,
}

#[derive(Clone, Debug)]
struct FakeShopifyFulfillmentProvider {
    state: Arc<Mutex<FakeState>>,
}

impl FakeShopifyFulfillmentProvider {
    fn new(state: Arc<Mutex<FakeState>>) -> Self {
        Self { state }
    }
}

impl ShopifyFulfillmentProvider for FakeShopifyFulfillmentProvider {
    fn probe_scope(
        &mut self,
        request: &ShopifyScopeProbeRequest,
    ) -> Result<ShopifyScopeProbe, ShopifyFulfillmentProviderError> {
        let mut state = self.state.lock().expect("fake provider state");
        state.probe_calls += 1;
        let mut granted_scopes = request.required_scopes.clone();
        if state.missing_write_scope {
            granted_scopes.remove(SHOPIFY_FULFILLMENT_WRITE_SCOPE);
        }
        let provider_generation = if state.wrong_generation {
            request.provider_generation + 1
        } else {
            request.provider_generation
        };
        Ok(ShopifyScopeProbe {
            status: ShopifyProbeStatus::Reachable,
            scope_digest: request.scope.digest(),
            shop: request.scope.shop().clone(),
            provider_digest: request.provider_digest.clone(),
            provider_generation,
            granted_scopes,
            observed_at: request.at,
            expires_at: request.at + Duration::seconds(30),
            evidence_digest: digest("shopify-probe-evidence"),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        })
    }

    fn execute_draft_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
    ) -> Result<ShopifyProviderReceipt, ShopifyFulfillmentProviderError> {
        let mut state = self.state.lock().expect("fake provider state");
        state.execute_calls += 1;
        let receipt = ShopifyProviderReceipt {
            receipt_id: format!(
                "shopify-provider-receipt-{}",
                request.idempotency_key().as_str()
            ),
            provider_operation_id: format!(
                "shopify-provider-op-{}",
                request.idempotency_key().as_str()
            ),
            request_digest: request.request_digest().to_owned(),
            idempotency_key: request.idempotency_key().clone(),
            scope_digest: request.tenant_scope().digest(),
            shop: request.tenant_scope().shop().clone(),
            order_gid: request.order_gid().clone(),
            fulfillment_order_gid: request.fulfillment_order_gid().clone(),
            line_items: request.line_items().to_owned(),
            provider_generation: request.provider_generation(),
            approval_revision: request.approval_revision(),
            provider_digest: shopify_fulfillment_provider_digest(request.api_version()),
            observed_at: request.created_at(),
            evidence_digest: digest("shopify-provider-receipt-evidence"),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        };
        state.operations.insert(
            request.idempotency_key().as_str().to_owned(),
            receipt.clone(),
        );
        if state.timeout_after_commit {
            state.timeout_after_commit = false;
            return Err(ShopifyFulfillmentProviderError::Timeout);
        }
        Ok(receipt)
    }

    fn readback_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
        lookup: &ShopifyReadbackLookup,
    ) -> Result<Option<ShopifyReadbackObservation>, ShopifyFulfillmentProviderError> {
        let mut state = self.state.lock().expect("fake provider state");
        state.readback_calls += 1;
        assert_eq!(lookup.idempotency_key, *request.idempotency_key());
        assert_eq!(lookup.request_digest, request.request_digest());
        let Some(provider_receipt) = state
            .operations
            .get(request.idempotency_key().as_str())
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(ShopifyReadbackObservation {
            provider_receipt,
            status: ShopifyReadbackStatus::Fulfilled,
            observed_at: request.created_at(),
            evidence_digest: digest("shopify-readback-evidence"),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        }))
    }
}

#[derive(Debug)]
struct LoopbackHttpServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl LoopbackHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let requests_for_thread = Arc::clone(&requests);
        let stop_for_thread = Arc::clone(&stop);
        let join = thread::spawn(move || {
            while !stop_for_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        if let Ok((request_line, body)) = read_http_request(&mut stream) {
                            requests_for_thread
                                .lock()
                                .expect("loopback request state")
                                .push((request_line, body.clone()));
                            let response = loopback_response(&body);
                            let _ = write_http_response(&mut stream, &response);
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

    fn requests(&self) -> Vec<(String, String)> {
        self.requests
            .lock()
            .expect("loopback request state")
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

#[derive(Debug)]
struct LoopbackShopifyFulfillmentProvider {
    address: SocketAddr,
    api_version: ShopifyApiVersion,
    operations: BTreeMap<String, ShopifyProviderReceipt>,
}

impl LoopbackShopifyFulfillmentProvider {
    fn new(address: SocketAddr, api_version: ShopifyApiVersion) -> Self {
        Self {
            address,
            api_version,
            operations: BTreeMap::new(),
        }
    }

    fn post_graphql(
        &self,
        query: &str,
        variables: &Value,
    ) -> Result<Value, ShopifyFulfillmentProviderError> {
        let payload = json!({ "query": query, "variables": variables }).to_string();
        let path = format!("/admin/api/{}/graphql.json", self.api_version.as_str());
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: loopback.shopify.test\r\nContent-Type: application/json\r\nX-Shopify-Access-Token: loopback-test-only\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let mut stream = TcpStream::connect(self.address)
            .map_err(|error| ShopifyFulfillmentProviderError::Unavailable(error.to_string()))?;
        stream
            .set_read_timeout(Some(StdDuration::from_secs(1)))
            .map_err(|error| ShopifyFulfillmentProviderError::Unavailable(error.to_string()))?;
        stream
            .set_write_timeout(Some(StdDuration::from_secs(1)))
            .map_err(|error| ShopifyFulfillmentProviderError::Unavailable(error.to_string()))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|error| ShopifyFulfillmentProviderError::Unavailable(error.to_string()))?;
        let response = read_http_response(&mut stream)
            .map_err(|error| ShopifyFulfillmentProviderError::Unavailable(error.to_string()))?;
        let separator = find_subsequence(&response, b"\r\n\r\n").ok_or_else(|| {
            ShopifyFulfillmentProviderError::Unavailable("missing HTTP response body".to_owned())
        })?;
        let content_length = http_content_length(&response[..separator]).ok_or_else(|| {
            ShopifyFulfillmentProviderError::Unavailable(
                "missing HTTP response content length".to_owned(),
            )
        })?;
        let body_start = separator + 4;
        let body_end = body_start + content_length;
        let value: Value = serde_json::from_slice(&response[body_start..body_end])
            .map_err(|error| ShopifyFulfillmentProviderError::Unavailable(error.to_string()))?;
        if value.get("errors").is_some() {
            return Err(ShopifyFulfillmentProviderError::Rejected(
                "loopback GraphQL error".to_owned(),
            ));
        }
        Ok(value)
    }
}

impl ShopifyFulfillmentProvider for LoopbackShopifyFulfillmentProvider {
    fn probe_scope(
        &mut self,
        request: &ShopifyScopeProbeRequest,
    ) -> Result<ShopifyScopeProbe, ShopifyFulfillmentProviderError> {
        if request.api_version != self.api_version {
            return Err(ShopifyFulfillmentProviderError::Rejected(
                "API version drift".to_owned(),
            ));
        }
        let response = self.post_graphql(
            "query ShopifyScopeProbe { shop { id } }",
            &json!({
                "shop": request.scope.shop().as_str(),
                "scopeDigest": request.scope.digest(),
                "providerGeneration": request.provider_generation,
            }),
        )?;
        if response.pointer("/data/shop/id").and_then(Value::as_str) != Some("gid://shopify/Shop/1")
        {
            return Err(ShopifyFulfillmentProviderError::Rejected(
                "loopback shop probe mismatch".to_owned(),
            ));
        }
        Ok(ShopifyScopeProbe {
            status: ShopifyProbeStatus::Reachable,
            scope_digest: request.scope.digest(),
            shop: request.scope.shop().clone(),
            provider_digest: request.provider_digest.clone(),
            provider_generation: request.provider_generation,
            granted_scopes: request.required_scopes.clone(),
            observed_at: request.at,
            expires_at: request.at + Duration::seconds(30),
            evidence_digest: digest("loopback-shopify-probe"),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        })
    }

    fn execute_draft_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
    ) -> Result<ShopifyProviderReceipt, ShopifyFulfillmentProviderError> {
        let response = self.post_graphql(
            FULFILLMENT_CREATE_MUTATION,
            &json!({
                "fulfillment": {
                    "orderId": request.order_gid().as_str(),
                    "fulfillmentOrderId": request.fulfillment_order_gid().as_str(),
                    "lineItems": request.line_items(),
                },
                "idempotencyKey": request.idempotency_key().as_str(),
            }),
        )?;
        let fulfillment_id = response
            .pointer("/data/fulfillmentCreate/fulfillment/id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ShopifyFulfillmentProviderError::Rejected(
                    "loopback fulfillment mutation did not return an ID".to_owned(),
                )
            })?;
        if fulfillment_id != "gid://shopify/Fulfillment/3001" {
            return Err(ShopifyFulfillmentProviderError::Rejected(
                "loopback fulfillment ID mismatch".to_owned(),
            ));
        }
        let receipt = ShopifyProviderReceipt {
            receipt_id: format!("shopify-provider-receipt-{fulfillment_id}"),
            provider_operation_id: format!("shopify-provider-op-{fulfillment_id}"),
            request_digest: request.request_digest().to_owned(),
            idempotency_key: request.idempotency_key().clone(),
            scope_digest: request.tenant_scope().digest(),
            shop: request.tenant_scope().shop().clone(),
            order_gid: request.order_gid().clone(),
            fulfillment_order_gid: request.fulfillment_order_gid().clone(),
            line_items: request.line_items().to_owned(),
            provider_generation: request.provider_generation(),
            approval_revision: request.approval_revision(),
            provider_digest: shopify_fulfillment_provider_digest(request.api_version()),
            observed_at: request.created_at(),
            evidence_digest: digest(&response.to_string()),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        };
        self.operations.insert(
            request.idempotency_key().as_str().to_owned(),
            receipt.clone(),
        );
        Ok(receipt)
    }

    fn readback_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
        lookup: &ShopifyReadbackLookup,
    ) -> Result<Option<ShopifyReadbackObservation>, ShopifyFulfillmentProviderError> {
        let operation_id = lookup.provider_operation_id.as_deref().ok_or_else(|| {
            ShopifyFulfillmentProviderError::Rejected(
                "readback requires the provider operation identity".to_owned(),
            )
        })?;
        let response = self.post_graphql(
            FULFILLMENT_READBACK_QUERY,
            &json!({
                "id": "gid://shopify/Fulfillment/3001",
                "providerOperationId": operation_id,
                "idempotencyKey": lookup.idempotency_key.as_str(),
            }),
        )?;
        if response
            .pointer("/data/node/status")
            .and_then(Value::as_str)
            != Some("SUCCESS")
        {
            return Ok(None);
        }
        let provider_receipt = self
            .operations
            .get(request.idempotency_key().as_str())
            .cloned()
            .ok_or_else(|| {
                ShopifyFulfillmentProviderError::Unavailable(
                    "loopback operation receipt was not retained".to_owned(),
                )
            })?;
        Ok(Some(ShopifyReadbackObservation {
            provider_receipt,
            status: ShopifyReadbackStatus::Fulfilled,
            observed_at: request.created_at(),
            evidence_digest: digest(&response.to_string()),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        }))
    }
}

fn read_http_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(StdDuration::from_secs(1)))?;
    let mut bytes = Vec::new();
    let body_end = loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated HTTP response headers or body",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = find_subsequence(&bytes, b"\r\n\r\n") else {
            continue;
        };
        let content_length = http_content_length(&bytes[..header_end]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing HTTP response content length",
            )
        })?;
        let body_end = header_end + 4 + content_length;
        if bytes.len() >= body_end {
            break body_end;
        }
    };
    while bytes.len() < body_end {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated HTTP response body",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    bytes.truncate(body_end);
    Ok(bytes)
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<(String, String)> {
    stream.set_read_timeout(Some(StdDuration::from_secs(1)))?;
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = find_subsequence(&bytes, b"\r\n\r\n") {
            let content_length = http_content_length(&bytes[..header_end]);
            if bytes.len() >= header_end + 4 + content_length.unwrap_or_default() {
                break;
            }
        }
    }
    let header_end = find_subsequence(&bytes, b"\r\n\r\n").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing HTTP request headers",
        )
    })?;
    let header = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = http_content_length(&bytes[..header_end]).unwrap_or_default();
    let body_start = header_end + 4;
    if bytes.len() < body_start + content_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated HTTP request body",
        ));
    }
    let request_line = header.lines().next().unwrap_or_default().to_owned();
    let body =
        String::from_utf8_lossy(&bytes[body_start..body_start + content_length]).into_owned();
    Ok((request_line, body))
}

fn http_content_length(header: &[u8]) -> Option<usize> {
    String::from_utf8_lossy(header).lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
}

fn write_http_response(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)
}

fn loopback_response(request_body: &str) -> String {
    if request_body.contains("ShopifyScopeProbe") {
        json!({ "data": { "shop": { "id": "gid://shopify/Shop/1" } } }).to_string()
    } else if request_body.contains("ShopifyFulfillmentCreate") {
        json!({
            "data": {
                "fulfillmentCreate": {
                    "fulfillment": {
                        "id": "gid://shopify/Fulfillment/3001",
                        "status": "SUCCESS"
                    },
                    "userErrors": []
                }
            }
        })
        .to_string()
    } else if request_body.contains("ShopifyFulfillmentReadback") {
        json!({
            "data": {
                "node": {
                    "id": "gid://shopify/Fulfillment/3001",
                    "status": "SUCCESS"
                }
            }
        })
        .to_string()
    } else {
        json!({ "errors": [{ "message": "unexpected GraphQL query" }] }).to_string()
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW_YEAR, 8, 14, 3, 0, 0)
        .single()
        .expect("stable test time")
}

fn scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-1",
        "project-1",
        "shopify",
        "account-1",
        [
            SHOPIFY_FULFILLMENT_READ_SCOPE.to_owned(),
            SHOPIFY_FULFILLMENT_WRITE_SCOPE.to_owned(),
        ],
    )
    .expect("Shopify connector scope")
}

fn fulfillment_scope() -> ShopifyFulfillmentScope {
    ShopifyFulfillmentScope::new(
        scope(),
        ShopDomain::parse("demo.myshopify.com").expect("Shopify shop"),
    )
    .expect("Shopify fulfillment scope")
}

fn auth_binding(
    generation: u64,
) -> hartevo_commerce_connector::shopify_effect::ShopifyFulfillmentAuthBinding {
    let scope = scope();
    let issued_at = now() - Duration::seconds(30);
    let secret = SecretReference::new(
        format!("secret-ref-shopify-{generation}"),
        scope,
        generation,
    )
    .expect("opaque secret reference");
    let adapter = shopify_fulfillment_adapter_identity().expect("Shopify effect adapter");
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        adapter.clone(),
        format!("lease-shopify-{generation}"),
        generation,
        issued_at,
        now() + Duration::seconds(300),
    )
    .expect("credential lease");
    let session = ConnectorAuth::begin_auth_session(
        &secret,
        &lease,
        format!("auth-session-shopify-{generation}"),
        generation,
        issued_at,
        now() + Duration::seconds(240),
    )
    .expect("auth session");
    hartevo_commerce_connector::shopify_effect::ShopifyFulfillmentAuthBinding::new(
        secret, lease, session, adapter,
    )
    .expect("Shopify auth binding")
}

fn request(
    generation: u64,
    approval_revision: u64,
    idempotency_suffix: &str,
) -> DraftFulfillmentRequest {
    let line_item = ShopifyFulfillmentLineItem::new(
        ShopifyFulfillmentOrderLineItemGid::parse("gid://shopify/FulfillmentOrderLineItem/5001")
            .expect("line item GID"),
        2,
    )
    .expect("line item");
    DraftFulfillmentRequest::new(
        format!("shopify-draft-fulfillment-{idempotency_suffix}"),
        "mission-commerce-69",
        fulfillment_scope(),
        ShopifyApiVersion::latest(),
        ShopifyOrderGid::parse("gid://shopify/Order/1001").expect("order GID"),
        ShopifyFulfillmentOrderGid::parse("gid://shopify/FulfillmentOrder/2001")
            .expect("fulfillment order GID"),
        vec![line_item],
        generation,
        ShopifyApprovalRevision::new(approval_revision).expect("approval revision"),
        ShopifyEffectIdempotencyKey::parse(format!("shopify-effect-idem-{idempotency_suffix}"))
            .expect("idempotency key"),
        now() - Duration::seconds(30),
        now() + Duration::seconds(300),
    )
    .expect("draft fulfillment request")
}

fn service(
    state: Arc<Mutex<FakeState>>,
    generation: u64,
    provenance_class: ProviderProvenanceClass,
    auth: Option<hartevo_commerce_connector::shopify_effect::ShopifyFulfillmentAuthBinding>,
) -> ShopifyFulfillmentEffectService<FakeShopifyFulfillmentProvider> {
    ShopifyFulfillmentEffectService::new(
        FakeShopifyFulfillmentProvider::new(state),
        fulfillment_scope(),
        ShopifyApiVersion::latest(),
        provenance_class,
        ShopifyFulfillmentEffectStore::new(generation).expect("effect store"),
        auth,
    )
    .expect("Shopify effect service")
}

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let mut output = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut output, "{byte:02x}").expect("write to String");
    }
    output
}

#[test]
fn draft_binds_mission_shop_order_items_generation_approval_and_idempotency() {
    assert!(FULFILLMENT_CREATE_MUTATION.contains("fulfillmentCreate"));
    assert!(FULFILLMENT_READBACK_QUERY.contains("Fulfillment"));

    let draft = request(1, 7, "binding");
    let encoded = serde_json::to_value(&draft).expect("draft JSON");
    let decoded: DraftFulfillmentRequest = serde_json::from_value(encoded).expect("draft decode");
    assert_eq!(decoded, draft);
    assert_eq!(draft.mission_id(), "mission-commerce-69");
    assert_eq!(draft.tenant_scope().shop().as_str(), "demo.myshopify.com");
    assert_eq!(draft.provider_generation(), 1);
    assert_eq!(draft.approval_revision().value(), 7);
    assert_eq!(draft.line_items().len(), 1);
    assert_eq!(draft.request_digest().len(), 64);

    let json: Value = serde_json::to_value(&draft).expect("draft JSON");
    assert!(json.get("requestDigest").is_some());
    assert!(json.get("idempotencyKey").is_some());
}

#[test]
fn controlled_provider_probes_before_execute_and_returns_receipt_with_readback() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut service = service(
        state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    let result = service
        .submit_draft_at(&request(1, 7, "success"), now())
        .expect("controlled fulfillment result");

    assert!(result.is_verified());
    assert!(!result.is_first_party());
    assert_eq!(
        result.live_validation_status,
        SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS
    );
    assert_eq!(result.provider_generation, 1);
    assert_eq!(result.approval_revision.value(), 7);
    assert!(!result.provider_receipt.receipt_id.is_empty());
    assert!(result.readback.verified);
    let state = state.lock().expect("fake provider state");
    assert_eq!(state.probe_calls, 1);
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.readback_calls, 1);
}

#[test]
fn loopback_shopify_provider_exercises_http_probe_mutation_and_readback() {
    let server = LoopbackHttpServer::start();
    let api_version = ShopifyApiVersion::latest();
    let mut effect_service = ShopifyFulfillmentEffectService::new(
        LoopbackShopifyFulfillmentProvider::new(server.address(), api_version.clone()),
        fulfillment_scope(),
        api_version,
        ProviderProvenanceClass::ControlledProvider,
        ShopifyFulfillmentEffectStore::new(1).expect("effect store"),
        Some(auth_binding(1)),
    )
    .expect("loopback Shopify effect service");

    let result = effect_service
        .submit_draft_at(&request(1, 7, "loopback-http"), now())
        .expect("loopback HTTP fulfillment result");
    assert!(result.is_verified());
    assert!(!result.is_first_party());
    assert_eq!(
        result.live_validation_status,
        SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|(request_line, _)| {
        request_line.starts_with("POST /admin/api/") && request_line.ends_with("HTTP/1.1")
    }));
    assert!(requests[0].1.contains("ShopifyScopeProbe"));
    assert!(requests[1].1.contains(FULFILLMENT_CREATE_MUTATION));
    assert!(requests[2].1.contains(FULFILLMENT_READBACK_QUERY));
    assert!(requests[1].1.contains("shopify-effect-idem-loopback-http"));
}

#[test]
fn timeout_after_commit_restarts_by_readback_without_a_second_execute() {
    let state = Arc::new(Mutex::new(FakeState {
        timeout_after_commit: true,
        ..FakeState::default()
    }));
    let draft = request(1, 7, "timeout");
    let mut first = service(
        state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    assert_eq!(
        first.submit_draft_at(&draft, now()),
        Err(ShopifyFulfillmentEffectError::ExecutionUncertain)
    );
    assert_eq!(
        first.store().records()[draft.idempotency_key().as_str()].state,
        ShopifyFulfillmentRecordState::Uncertain
    );
    let durable_store = serde_json::to_vec(first.store()).expect("durable effect checkpoint");
    let recovered_store: ShopifyFulfillmentEffectStore =
        serde_json::from_slice(&durable_store).expect("reopen effect checkpoint");

    let mut recovered = ShopifyFulfillmentEffectService::new(
        FakeShopifyFulfillmentProvider::new(state.clone()),
        fulfillment_scope(),
        ShopifyApiVersion::latest(),
        ProviderProvenanceClass::ControlledProvider,
        recovered_store,
        Some(auth_binding(1)),
    )
    .expect("recovered Shopify service");
    let result = recovered
        .submit_draft_at(&draft, now())
        .expect("readback after restart");
    assert!(result.replayed);
    assert!(result.is_verified());

    let state_snapshot = state.lock().expect("fake provider state");
    assert_eq!(state_snapshot.execute_calls, 1);
    assert_eq!(state_snapshot.probe_calls, 2);
    assert_eq!(state_snapshot.readback_calls, 1);
    drop(state_snapshot);

    let replay = recovered
        .submit_draft_at(&draft, now())
        .expect("durable verified replay");
    assert!(replay.replayed);
    let state = state.lock().expect("fake provider state");
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.probe_calls, 2);
    assert_eq!(state.readback_calls, 1);
}

#[test]
fn idempotency_conflict_never_reuses_a_key_for_different_approval_revision() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut service = service(
        state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    service
        .submit_draft_at(&request(1, 7, "conflict"), now())
        .expect("initial fulfillment");
    assert_eq!(
        service.submit_draft_at(&request(1, 8, "conflict"), now()),
        Err(ShopifyFulfillmentEffectError::IdempotencyConflict)
    );
    let state = state.lock().expect("fake provider state");
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.readback_calls, 1);
}

#[test]
fn probe_scope_and_production_environment_fail_closed_before_execute() {
    let missing_scope_state = Arc::new(Mutex::new(FakeState {
        missing_write_scope: true,
        ..FakeState::default()
    }));
    let mut missing_scope = service(
        missing_scope_state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    assert_eq!(
        missing_scope.submit_draft_at(&request(1, 7, "missing-scope"), now()),
        Err(ShopifyFulfillmentEffectError::ProbeMissingScope)
    );
    let missing_scope_state = missing_scope_state.lock().expect("fake provider state");
    assert_eq!(missing_scope_state.execute_calls, 0);

    let production_state = Arc::new(Mutex::new(FakeState::default()));
    let mut production = service(
        production_state.clone(),
        1,
        ProviderProvenanceClass::ProductionProvider,
        Some(auth_binding(1)),
    );
    assert_eq!(
        production.submit_draft_at(&request(1, 7, "blocked-env"), now()),
        Err(ShopifyFulfillmentEffectError::BlockedEnv)
    );
    let production_state = production_state.lock().expect("fake provider state");
    assert_eq!(production_state.probe_calls, 0);
    assert_eq!(production_state.execute_calls, 0);

    let no_auth_state = Arc::new(Mutex::new(FakeState::default()));
    let mut no_auth = service(
        no_auth_state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        None,
    );
    assert_eq!(
        no_auth.submit_draft_at(&request(1, 7, "no-auth"), now()),
        Err(ShopifyFulfillmentEffectError::BlockedEnv)
    );
}

#[test]
fn rotation_revoke_and_unmount_invalidate_old_generation_and_durable_records() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut effect_service = service(
        state,
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    effect_service
        .submit_draft_at(&request(1, 7, "lifecycle"), now())
        .expect("initial fulfillment");
    assert_eq!(effect_service.store().records().len(), 1);

    effect_service
        .rotate_auth(auth_binding(2))
        .expect("credential rotation");
    assert!(effect_service.store().records().is_empty());
    assert_eq!(
        effect_service.submit_draft_at(&request(1, 7, "lifecycle"), now()),
        Err(ShopifyFulfillmentEffectError::GenerationMismatch)
    );

    effect_service
        .submit_draft_at(&request(2, 8, "lifecycle-new-generation"), now())
        .expect("new generation fulfillment");
    let revoked = effect_service.revoke(now());
    assert_eq!(revoked.lifecycle, ShopifyEffectLifecycle::Revoked);
    assert!(effect_service.store().records().is_empty());
    assert_eq!(
        effect_service.submit_draft_at(&request(2, 8, "after-revoke"), now()),
        Err(ShopifyFulfillmentEffectError::ConsumerNotMounted)
    );

    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut unmounted = service(
        state,
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    let unmounted_receipt = unmounted.unmount(now());
    assert_eq!(
        unmounted_receipt.lifecycle,
        ShopifyEffectLifecycle::Unmounted
    );
    assert_eq!(
        unmounted.submit_draft_at(&request(1, 7, "after-unmount"), now()),
        Err(ShopifyFulfillmentEffectError::ConsumerNotMounted)
    );
}
