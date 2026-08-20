use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use reqwest::blocking::Client;
use thiserror::Error;
use url::Url;

/// Layer 1 deliberately exposes only authenticated GET requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
}

/// A provider request.  Debug output redacts bearer credentials and the
/// OAuth `access_token` query parameter.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: Url,
    pub headers: BTreeMap<String, String>,
}

impl HttpRequest {
    pub fn get(url: Url) -> Self {
        Self {
            method: HttpMethod::Get,
            url,
            headers: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_bearer(mut self, access_token: &str) -> Self {
        self.headers
            .insert("authorization".to_owned(), format!("Bearer {access_token}"));
        self
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str(),
                    if name.eq_ignore_ascii_case("authorization") {
                        "<redacted>"
                    } else {
                        value.as_str()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &redacted_url(&self.url))
            .field("headers", &headers)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: BTreeMap::from([(
                String::from("content-type"),
                String::from("application/json"),
            )]),
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }
}

/// Transport failures are kept separate from Google HTTP semantics so a
/// deterministic loopback transport can be used without depending on
/// reqwest internals.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("request failed: {message}")]
    Request { message: String },
    #[error("response exceeded {limit} bytes")]
    ResponseTooLarge { limit: usize },
}

pub trait HttpTransport: Send + Sync {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

#[derive(Clone)]
pub struct ReqwestTransport {
    client: Client,
    max_response_bytes: usize,
}

impl fmt::Debug for ReqwestTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReqwestTransport")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl ReqwestTransport {
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

    pub fn production() -> Result<Self, TransportError> {
        let client = Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|error| TransportError::Request {
                message: error.to_string(),
            })?;
        Ok(Self {
            client,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    pub fn loopback() -> Result<Self, TransportError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|error| TransportError::Request {
                message: error.to_string(),
            })?;
        Ok(Self {
            client,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }
}

impl HttpTransport for ReqwestTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut builder = match request.method {
            HttpMethod::Get => self.client.get(request.url.clone()),
        };
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let response = builder.send().map_err(|error| TransportError::Request {
            message: error.to_string(),
        })?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let body = response
            .bytes()
            .map_err(|error| TransportError::Request {
                message: error.to_string(),
            })?
            .to_vec();
        if body.len() > self.max_response_bytes {
            return Err(TransportError::ResponseTooLarge {
                limit: self.max_response_bytes,
            });
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

fn redacted_url(url: &Url) -> Url {
    let mut redacted = url.clone();
    let pairs = redacted
        .query_pairs()
        .map(|(name, value)| {
            if name == "access_token" {
                (name.into_owned(), String::from("<redacted>"))
            } else {
                (name.into_owned(), value.into_owned())
            }
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        redacted.set_query(None);
    } else {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in pairs {
            serializer.append_pair(&name, &value);
        }
        redacted.set_query(Some(&serializer.finish()));
    }
    redacted
}
