//! Small HTTP boundary used by the paid-social adapters.
//!
//! Requests are represented explicitly so tests can inspect the exact provider
//! path/query/auth contract without putting a provider SDK inside the application.

use crate::paid_social_types::{ConnectorError, OAuth1Credentials, digest_bytes};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use ring::hmac;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub query: Vec<(String, String)>,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: BTreeMap::new(),
            query: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_query(mut self, query: Vec<(String, String)>) -> Self {
        self.query = query;
        self
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name.into(), value.into());
    }

    pub fn path(&self) -> Result<String, ConnectorError> {
        Url::parse(&self.url)
            .map(|url| url.path().to_owned())
            .map_err(|_| ConnectorError::InvalidRequest)
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| {
                let lower = name.to_ascii_lowercase();
                let rendered = if lower == "authorization"
                    || lower.contains("token")
                    || lower.contains("secret")
                    || lower == "cookie"
                {
                    "REDACTED".to_owned()
                } else {
                    value.clone()
                };
                (name, rendered)
            })
            .collect::<BTreeMap<_, _>>();
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("query", &self.query)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body_length", &self.body.len())
            .field("received_at", &self.received_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailureKind {
    Build,
    Send,
    Read,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HttpTransportError {
    #[error("http client could not be built")]
    Build,
    #[error("http request could not be sent")]
    Send,
    #[error("http response could not be read")]
    Read,
}

pub trait HttpTransport: fmt::Debug + Send + Sync {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, HttpTransportError>;
}

#[derive(Debug)]
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new(timeout: Duration) -> Result<Self, HttpTransportError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| HttpTransportError::Build)?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
        };
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if !request.query.is_empty() {
            builder = builder.query(&request.query);
        }
        let response = builder.send().map_err(|_| HttpTransportError::Send)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
            })
            .collect();
        let body = response
            .bytes()
            .map_err(|_| HttpTransportError::Read)?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
            received_at: Utc::now(),
        })
    }
}

pub fn query_digest(query: &[(String, String)]) -> String {
    let mut query = query.to_vec();
    query.sort();
    let encoded = serde_json::to_vec(&query).expect("query tuples serialize");
    digest_bytes(&encoded)
}

pub fn oauth1_authorization(
    request: &HttpRequest,
    credentials: &OAuth1Credentials,
    now: DateTime<Utc>,
) -> Result<String, ConnectorError> {
    let url = Url::parse(&request.url).map_err(|_| ConnectorError::InvalidRequest)?;
    let base_url = format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.path()
    );
    let oauth_values = [
        (
            "oauth_consumer_key",
            credentials.consumer_key.expose().to_owned(),
        ),
        ("oauth_nonce", Uuid::now_v7().simple().to_string()),
        ("oauth_signature_method", "HMAC-SHA1".to_owned()),
        ("oauth_timestamp", now.timestamp().to_string()),
        ("oauth_token", credentials.access_token.expose().to_owned()),
        ("oauth_version", "1.0".to_owned()),
    ];

    let mut parameters = Vec::new();
    for (name, value) in &request.query {
        parameters.push((name.clone(), value.clone()));
    }
    for (name, value) in &oauth_values {
        parameters.push(((*name).to_owned(), value.clone()));
    }
    parameters.sort_by(|left, right| {
        encode(&left.0)
            .cmp(&encode(&right.0))
            .then_with(|| encode(&left.1).cmp(&encode(&right.1)))
    });
    let normalized = parameters
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let signature_base = format!(
        "{}&{}&{}",
        request.method.as_str(),
        encode(&base_url),
        encode(&normalized)
    );
    let signing_key = format!(
        "{}&{}",
        encode(credentials.consumer_secret.expose()),
        encode(credentials.access_token_secret.expose())
    );
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, signing_key.as_bytes());
    let signature = BASE64.encode(hmac::sign(&key, signature_base.as_bytes()).as_ref());

    let mut header_values = oauth_values
        .iter()
        .map(|(name, value)| format!("{}=\"{}\"", encode(name), encode(value)))
        .collect::<Vec<_>>();
    header_values.push(format!("oauth_signature=\"{}\"", encode(&signature)));
    Ok(format!("OAuth {}", header_values.join(", ")))
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paid_social_types::{OAuth1Credentials, SecretString};

    #[test]
    fn request_debug_redacts_auth_material() {
        let mut request = HttpRequest::get("https://example.test/resource");
        request.set_header("Authorization", "Bearer very-secret-token");
        request.set_header("X-Token-Id", "opaque-token");
        let debug = format!("{request:?}");
        assert!(!debug.contains("very-secret-token"));
        assert!(!debug.contains("opaque-token"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn oauth1_signature_contains_no_secret() {
        let request = HttpRequest::get("https://ads-api.x.com/12/accounts/a")
            .with_query(vec![("count".to_owned(), "10".to_owned())]);
        let credentials = OAuth1Credentials {
            consumer_key: SecretString::new("consumer"),
            consumer_secret: SecretString::new("consumer-secret"),
            access_token: SecretString::new("access"),
            access_token_secret: SecretString::new("access-secret"),
        };
        let header = oauth1_authorization(&request, &credentials, Utc::now()).expect("oauth");
        assert!(header.starts_with("OAuth "));
        assert!(!header.contains("consumer-secret"));
        assert!(!header.contains("access-secret"));
        assert!(header.contains("oauth_signature"));
    }
}
