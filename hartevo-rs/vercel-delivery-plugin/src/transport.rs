use std::{fmt, thread, time::Duration};

use serde::de::DeserializeOwned;
use url::Url;

use crate::{
    DeploymentEventApi, DeploymentListApi, ProjectApi, ProviderProvenance, TeamApi,
    VercelApiTransport,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
}

impl RetryPolicy {
    pub const fn bounded() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
        }
    }

    pub fn new(
        max_attempts: u8,
        initial_backoff_ms: u64,
    ) -> Result<Self, VercelHttpTransportConfigurationError> {
        if max_attempts == 0 {
            return Err(VercelHttpTransportConfigurationError::InvalidRetryPolicy);
        }
        Ok(Self {
            max_attempts,
            initial_backoff_ms,
        })
    }

    fn delay_for_attempt(self, attempt: u8) -> Duration {
        let exponent = u32::from(attempt.saturating_sub(1)).min(6);
        Duration::from_millis(self.initial_backoff_ms.saturating_mul(1_u64 << exponent))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VercelHttpTransportConfigurationError {
    #[error("Vercel API base URL is invalid")]
    InvalidBaseUrl,
    #[error("native Vercel API transport requires HTTPS")]
    InsecureBaseUrl,
    #[error("loopback transport must target localhost or a loopback address")]
    NonLoopbackTestUrl,
    #[error("retry policy must allow at least one attempt")]
    InvalidRetryPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VercelTransportError {
    #[error("Vercel API rejected authentication with HTTP {status}")]
    Unauthorized { status: u16 },
    #[error("Vercel API rejected the request with HTTP {status}")]
    Rejected { status: u16 },
    #[error("Vercel API rate limited the request with HTTP {status}")]
    RateLimited {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("Vercel API returned an uncertain HTTP {status}")]
    Uncertain { status: u16 },
    #[error("Vercel API transport failed: {detail}")]
    Transport { detail: String },
    #[error("Vercel API response could not be decoded: {detail}")]
    Decode { detail: String },
    #[error("Vercel API retry budget exhausted: {detail}")]
    RetryExhausted { detail: String },
    #[error("Vercel API transport configuration is invalid: {detail}")]
    InvalidConfiguration { detail: String },
}

/// Official REST transport. The native constructor only accepts HTTPS; the
/// explicit loopback constructor is controlled evidence and is never native.
pub struct UreqVercelHttpTransport {
    base_url: String,
    agent: ureq::Agent,
    retry_policy: RetryPolicy,
    provenance: ProviderProvenance,
}

impl fmt::Debug for UreqVercelHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqVercelHttpTransport")
            .field("base_url", &self.base_url)
            .field("retry_policy", &self.retry_policy)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl UreqVercelHttpTransport {
    pub fn new(base_url: impl Into<String>) -> Result<Self, VercelHttpTransportConfigurationError> {
        let base_url = base_url.into();
        Self::build(base_url.as_str(), RetryPolicy::bounded(), false)
    }

    pub fn new_loopback(
        base_url: impl Into<String>,
    ) -> Result<Self, VercelHttpTransportConfigurationError> {
        let base_url = base_url.into();
        Self::build(base_url.as_str(), RetryPolicy::bounded(), true)
    }

    pub fn with_retry_policy(
        mut self,
        retry_policy: RetryPolicy,
    ) -> Result<Self, VercelHttpTransportConfigurationError> {
        if retry_policy.max_attempts == 0 {
            return Err(VercelHttpTransportConfigurationError::InvalidRetryPolicy);
        }
        self.retry_policy = retry_policy;
        Ok(self)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn build(
        base_url: &str,
        retry_policy: RetryPolicy,
        loopback: bool,
    ) -> Result<Self, VercelHttpTransportConfigurationError> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let parsed = Url::parse(&base_url)
            .map_err(|_| VercelHttpTransportConfigurationError::InvalidBaseUrl)?;
        if parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(VercelHttpTransportConfigurationError::InvalidBaseUrl);
        }
        if loopback {
            if parsed.scheme() != "http" || !is_loopback_host(parsed.host_str()) {
                return Err(VercelHttpTransportConfigurationError::NonLoopbackTestUrl);
            }
        } else if parsed.scheme() != "https" {
            return Err(VercelHttpTransportConfigurationError::InsecureBaseUrl);
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-vercel-delivery/1")
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            base_url,
            agent,
            retry_policy,
            provenance: if loopback {
                ProviderProvenance::ControlledProvider
            } else {
                ProviderProvenance::ProductionProvider
            },
        })
    }

    fn endpoint(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<String, VercelTransportError> {
        let mut url = Url::parse(&self.base_url).map_err(|error| {
            VercelTransportError::InvalidConfiguration {
                detail: error.to_string(),
            }
        })?;
        {
            let mut path = url.path_segments_mut().map_err(|()| {
                VercelTransportError::InvalidConfiguration {
                    detail: "base URL cannot accept path segments".to_owned(),
                }
            })?;
            for segment in segments {
                path.push(segment);
            }
        }
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url.to_string())
    }

    fn get_json<T: DeserializeOwned>(
        &self,
        bearer_token: &str,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<T, VercelTransportError> {
        let url = self.endpoint(segments, query)?;
        let mut attempt = 1;
        loop {
            let request = self
                .agent
                .get(&url)
                .header("Authorization", format!("Bearer {bearer_token}"))
                .header("Accept", "application/json")
                .header("X-Vercel-Client", "hartevo-vercel-delivery/1");
            match request.call() {
                Ok(mut response) => {
                    let body = response.body_mut().read_to_string().map_err(|error| {
                        VercelTransportError::Transport {
                            detail: error.to_string(),
                        }
                    })?;
                    return serde_json::from_str(&body).map_err(|error| {
                        VercelTransportError::Decode {
                            detail: error.to_string(),
                        }
                    });
                }
                Err(error) => {
                    let classified = classify_http_error(error);
                    if !is_retryable(&classified) || attempt >= self.retry_policy.max_attempts {
                        return if is_retryable(&classified) && self.retry_policy.max_attempts > 1 {
                            Err(VercelTransportError::RetryExhausted {
                                detail: classified.to_string(),
                            })
                        } else {
                            Err(classified)
                        };
                    }
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

impl VercelApiTransport for UreqVercelHttpTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn get_team(&self, bearer_token: &str, team_id: &str) -> Result<TeamApi, VercelTransportError> {
        self.get_json(bearer_token, &["v2", "teams", team_id], &[])
    }

    fn get_project(
        &self,
        bearer_token: &str,
        team_id: &str,
        project_id: &str,
    ) -> Result<ProjectApi, VercelTransportError> {
        self.get_json(
            bearer_token,
            &["v9", "projects", project_id],
            &[("teamId", team_id.to_owned())],
        )
    }

    fn list_deployments(
        &self,
        bearer_token: &str,
        team_id: &str,
        project_id: &str,
    ) -> Result<DeploymentListApi, VercelTransportError> {
        self.get_json(
            bearer_token,
            &["v6", "deployments"],
            &[
                ("teamId", team_id.to_owned()),
                ("projectId", project_id.to_owned()),
            ],
        )
    }

    fn get_deployment(
        &self,
        bearer_token: &str,
        team_id: &str,
        deployment_id_or_url: &str,
    ) -> Result<crate::VercelDeploymentApi, VercelTransportError> {
        self.get_json(
            bearer_token,
            &["v13", "deployments", deployment_id_or_url],
            &[("teamId", team_id.to_owned())],
        )
    }

    fn get_deployment_events(
        &self,
        bearer_token: &str,
        team_id: &str,
        deployment_id_or_url: &str,
    ) -> Result<Vec<DeploymentEventApi>, VercelTransportError> {
        self.get_json(
            bearer_token,
            &["v3", "deployments", deployment_id_or_url, "events"],
            &[
                ("teamId", team_id.to_owned()),
                ("direction", "backward".to_owned()),
                ("limit", "100".to_owned()),
            ],
        )
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

fn is_retryable(error: &VercelTransportError) -> bool {
    matches!(
        error,
        VercelTransportError::RateLimited { .. } | VercelTransportError::Uncertain { .. }
    )
}

fn classify_http_error(error: ureq::Error) -> VercelTransportError {
    match error {
        ureq::Error::StatusCode(status) if status == 401 || status == 403 => {
            VercelTransportError::Unauthorized { status }
        }
        ureq::Error::StatusCode(429) => VercelTransportError::RateLimited {
            status: 429,
            retry_after_seconds: None,
        },
        ureq::Error::StatusCode(status) if status >= 500 => {
            VercelTransportError::Uncertain { status }
        }
        ureq::Error::StatusCode(status) => VercelTransportError::Rejected { status },
        other => VercelTransportError::Transport {
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
    };

    use super::*;

    fn read_headers(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 512];
        loop {
            let count = stream.read(&mut chunk).expect("request headers");
            assert!(count > 0, "client closed before request headers");
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).expect("UTF-8 request headers")
    }

    fn spawn_server(responses: Vec<(u16, &'static str)>) -> (String, mpsc::Receiver<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().expect("HTTP client");
                requests.push(read_headers(&mut stream));
                let reason = match status {
                    200 => "OK",
                    429 => "Too Many Requests",
                    _ => "Error",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
                stream
                    .shutdown(std::net::Shutdown::Both)
                    .expect("close response");
            }
            sender.send(requests).expect("send captured requests");
        });
        (format!("http://{address}"), receiver)
    }

    #[test]
    fn loopback_transport_sends_bearer_auth_and_official_read_paths() {
        let (base_url, requests) = spawn_server(vec![
            (200, r#"{"id":"team_1","slug":"team","name":"Team"}"#),
            (
                200,
                r#"{"id":"prj_1","name":"Project","accountId":"team_1","framework":"nextjs"}"#,
            ),
        ]);
        let transport = UreqVercelHttpTransport::new_loopback(base_url)
            .expect("loopback transport")
            .with_retry_policy(RetryPolicy::new(1, 0).expect("retry policy"))
            .expect("retry policy");
        let team = transport.get_team("secret-token", "team_1").expect("team");
        let project = transport
            .get_project("secret-token", "team_1", "prj_1")
            .expect("project");
        assert_eq!(team.id, "team_1");
        assert_eq!(project.id, "prj_1");
        assert_eq!(
            transport.provenance(),
            ProviderProvenance::ControlledProvider
        );
        assert!(!transport.provenance().is_native());

        let requests = requests.recv().expect("captured requests");
        assert!(requests[0].starts_with("GET /v2/teams/team_1 HTTP/1.1"));
        assert!(requests[1].starts_with("GET /v9/projects/prj_1?teamId=team_1 HTTP/1.1"));
        assert!(requests.iter().all(|request| {
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer secret-token")
        }));
    }

    #[test]
    fn rate_limit_retries_with_a_bounded_policy() {
        let (base_url, requests) = spawn_server(vec![
            (429, r#"{"error":{"code":"rate_limited"}}"#),
            (200, r#"{"id":"team_1","slug":"team","name":"Team"}"#),
        ]);
        let transport = UreqVercelHttpTransport::new_loopback(base_url)
            .expect("loopback transport")
            .with_retry_policy(RetryPolicy::new(2, 0).expect("retry policy"))
            .expect("retry policy");
        let team = transport
            .get_team("secret-token", "team_1")
            .expect("retry succeeds");
        assert_eq!(team.id, "team_1");
        assert_eq!(requests.recv().expect("captured requests").len(), 2);
    }

    #[test]
    fn loopback_transport_reads_deployment_and_event_endpoints() {
        let (base_url, requests) = spawn_server(vec![
            (
                200,
                r#"{"deployments":[{"id":"dpl_1","url":"preview.vercel.app","state":"READY","target":"preview","projectId":"prj_1","teamId":"team_1"}],"pagination":{"count":1,"next":null,"prev":null}}"#,
            ),
            (
                200,
                r#"{"id":"dpl_1","url":"preview.vercel.app","readyState":"READY","target":"preview","projectId":"prj_1","teamId":"team_1"}"#,
            ),
            (
                200,
                r#"[{"type":"deployment-state","created":1,"payload":{"info":{"readyState":"READY"}}}]"#,
            ),
        ]);
        let transport = UreqVercelHttpTransport::new_loopback(base_url)
            .expect("loopback transport")
            .with_retry_policy(RetryPolicy::new(1, 0).expect("retry policy"))
            .expect("retry policy");
        let list = transport
            .list_deployments("secret-token", "team_1", "prj_1")
            .expect("deployment list");
        let deployment = transport
            .get_deployment("secret-token", "team_1", "dpl_1")
            .expect("deployment");
        let events = transport
            .get_deployment_events("secret-token", "team_1", "dpl_1")
            .expect("events");
        assert_eq!(list.deployments.len(), 1);
        assert_eq!(deployment.id, "dpl_1");
        assert_eq!(events.len(), 1);

        let requests = requests.recv().expect("captured requests");
        assert!(
            requests[0].starts_with("GET /v6/deployments?teamId=team_1&projectId=prj_1 HTTP/1.1")
        );
        assert!(requests[1].starts_with("GET /v13/deployments/dpl_1?teamId=team_1 HTTP/1.1"));
        assert!(requests[2].starts_with(
            "GET /v3/deployments/dpl_1/events?teamId=team_1&direction=backward&limit=100 HTTP/1.1"
        ));
    }

    #[test]
    fn native_transport_rejects_insecure_and_non_loopback_urls() {
        assert!(matches!(
            UreqVercelHttpTransport::new("http://127.0.0.1:8080"),
            Err(VercelHttpTransportConfigurationError::InsecureBaseUrl)
        ));
        assert!(matches!(
            UreqVercelHttpTransport::new_loopback("http://example.com"),
            Err(VercelHttpTransportConfigurationError::NonLoopbackTestUrl)
        ));
    }
}
