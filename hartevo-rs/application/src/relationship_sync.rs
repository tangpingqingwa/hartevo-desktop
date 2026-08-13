use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AccountId, CanonicalRelationshipRecord, ProjectId, RelationshipProjectionError,
    RelationshipSourceCursor, RelationshipSourceRef, RelationshipSourceStream, TenantId,
    canonical_relationship_id, digest_relationship_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{OpaqueCredential, ProviderHttpRequest, ProviderHttpTransport, ProviderTransportError};

pub const HUBSPOT_READ_PROBE_GATE_ENV: &str = "HARTEVO_HUBSPOT_READ_PROBE";
pub const HUBSPOT_ACCESS_TOKEN_ENV: &str = "HARTEVO_HUBSPOT_ACCESS_TOKEN";
pub const HUBSPOT_API_BASE_URL_ENV: &str = "HARTEVO_HUBSPOT_API_BASE_URL";
pub const HUBSPOT_DEFAULT_API_BASE_URL: &str = "https://api.hubapi.com";
pub const HUBSPOT_DEFAULT_PAGE_SIZE: u16 = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HubSpotReadConfig {
    pub base_url: String,
    pub page_size: u16,
    pub properties: Vec<String>,
}

impl HubSpotReadConfig {
    pub fn new(base_url: impl Into<String>) -> Result<Self, ProviderReadError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&base_url).map_err(|_| ProviderReadError::InvalidConfig)?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(ProviderReadError::InvalidConfig);
        }
        Ok(Self {
            base_url,
            page_size: HUBSPOT_DEFAULT_PAGE_SIZE,
            properties: vec![
                "email".into(),
                "firstname".into(),
                "lastname".into(),
                "lastmodifieddate".into(),
                "phone".into(),
            ],
        })
    }

    pub fn from_env() -> Result<Self, ProviderReadError> {
        Self::new(
            std::env::var(HUBSPOT_API_BASE_URL_ENV)
                .unwrap_or_else(|_| HUBSPOT_DEFAULT_API_BASE_URL.to_owned()),
        )
    }

    fn contacts_url(
        &self,
        cursor: Option<&RelationshipSourceCursor>,
    ) -> Result<String, ProviderReadError> {
        let mut url = Url::parse(&format!("{}/crm/v3/objects/contacts", self.base_url))
            .map_err(|_| ProviderReadError::InvalidConfig)?;
        let mut properties = self.properties.clone();
        properties.sort();
        properties.dedup();
        url.query_pairs_mut()
            .append_pair("limit", &self.page_size.to_string())
            .append_pair("properties", &properties.join(","));
        if let Some(cursor) = cursor.and_then(|cursor| cursor.position.as_deref()) {
            url.query_pairs_mut().append_pair("after", cursor);
        }
        Ok(url.to_string())
    }
}

#[derive(Debug)]
pub struct HubSpotRelationshipReader<'a, T> {
    transport: &'a T,
    config: HubSpotReadConfig,
}

impl<'a, T: ProviderHttpTransport> HubSpotRelationshipReader<'a, T> {
    pub fn new(transport: &'a T, config: HubSpotReadConfig) -> Self {
        Self { transport, config }
    }

    pub fn read_contacts(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        account_id: &AccountId,
        cursor: Option<&RelationshipSourceCursor>,
        credential: &OpaqueCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<HubSpotReadPage, ProviderReadError> {
        validate_cursor_scope(tenant_id, project_id, account_id, cursor)?;
        let request =
            ProviderHttpRequest::get(self.config.contacts_url(cursor)?, credential.clone());
        let response = self.transport.send(request)?;
        if !(200..300).contains(&response.status()) {
            return Err(ProviderReadError::HttpStatus {
                status: response.status(),
            });
        }
        let wire: HubSpotContactPageWire =
            serde_json::from_slice(response.body()).map_err(|_| ProviderReadError::InvalidJson)?;
        let record_count = wire.results.len();
        let mut records = Vec::with_capacity(record_count);
        for contact in &wire.results {
            records.push(canonical_contact_record(
                tenant_id,
                project_id,
                account_id,
                contact,
                observed_at,
            )?);
        }
        let next_position = wire
            .paging
            .and_then(|paging| paging.next)
            .map(|next| next.after)
            .filter(|after| !after.trim().is_empty());
        let source_revision = cursor.map_or(Ok(1), |cursor| {
            cursor
                .source_revision
                .checked_add(1)
                .ok_or(ProviderReadError::RevisionOverflow)
        })?;
        let revision = cursor.map_or(Ok(1), |cursor| {
            cursor
                .revision
                .checked_add(1)
                .ok_or(ProviderReadError::RevisionOverflow)
        })?;
        let next_cursor = RelationshipSourceCursor::new(
            tenant_id.clone(),
            project_id.clone(),
            "hubspot",
            account_id.clone(),
            RelationshipSourceStream::People,
            next_position,
            source_revision,
            revision,
            observed_at,
        )?;
        let scope_digest = next_cursor.scope_digest.clone();
        let next_cursor_digest = next_cursor
            .position
            .as_deref()
            .map(digest_relationship_value);
        let evidence_digest = digest_read_observation(
            account_id,
            &next_cursor.scope_digest,
            source_revision,
            record_count,
            next_cursor_digest.as_deref(),
        );
        Ok(HubSpotReadPage {
            records,
            cursor: next_cursor,
            observation: HubSpotReadObservation {
                provider: "hubspot".into(),
                account_id: account_id.clone(),
                status: response.status(),
                record_count,
                next_cursor_digest,
                scope_digest,
                evidence_digest,
                observed_at,
            },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HubSpotReadObservation {
    pub provider: String,
    pub account_id: AccountId,
    pub status: u16,
    pub record_count: usize,
    pub next_cursor_digest: Option<String>,
    pub scope_digest: String,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HubSpotReadPage {
    pub records: Vec<CanonicalRelationshipRecord>,
    pub cursor: RelationshipSourceCursor,
    pub observation: HubSpotReadObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HubSpotReadProbeOutcome {
    BlockedEnv { reason: String },
    Observed(Box<HubSpotReadPage>),
}

pub fn run_hubspot_read_probe_from_env<T: ProviderHttpTransport>(
    transport: &T,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    cursor: Option<&RelationshipSourceCursor>,
    observed_at: DateTime<Utc>,
) -> Result<HubSpotReadProbeOutcome, ProviderReadError> {
    if !env_gate_enabled(HUBSPOT_READ_PROBE_GATE_ENV) {
        return Ok(HubSpotReadProbeOutcome::BlockedEnv {
            reason: format!("{HUBSPOT_READ_PROBE_GATE_ENV} is not enabled"),
        });
    }
    let credential = match OpaqueCredential::from_env(HUBSPOT_ACCESS_TOKEN_ENV) {
        Ok(credential) => credential,
        Err(ProviderTransportError::MissingCredential) => {
            return Ok(HubSpotReadProbeOutcome::BlockedEnv {
                reason: format!("{HUBSPOT_ACCESS_TOKEN_ENV} is missing"),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let config = HubSpotReadConfig::from_env()?;
    let page = HubSpotRelationshipReader::new(transport, config).read_contacts(
        tenant_id,
        project_id,
        account_id,
        cursor,
        &credential,
        observed_at,
    )?;
    Ok(HubSpotReadProbeOutcome::Observed(Box::new(page)))
}

fn canonical_contact_record(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    contact: &HubSpotContactWire,
    observed_at: DateTime<Utc>,
) -> Result<CanonicalRelationshipRecord, ProviderReadError> {
    let external_id = contact.id.trim().to_owned();
    if external_id.is_empty() {
        return Err(ProviderReadError::InvalidContact);
    }
    let first_name = property_text(&contact.properties, "firstname");
    let last_name = property_text(&contact.properties, "lastname");
    let display_name = [first_name.as_deref(), last_name.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let display_name = if display_name.is_empty() {
        external_id.clone()
    } else {
        display_name
    };
    let source = RelationshipSourceRef {
        provider: "hubspot".into(),
        account_id: account_id.clone(),
        stream: RelationshipSourceStream::People,
        external_id,
    };
    source.validate()?;
    let mut value_digests = BTreeSet::new();
    for key in ["email", "phone"] {
        if let Some(value) = property_text(&contact.properties, key) {
            value_digests.insert(digest_relationship_value(&value));
        }
    }
    let source_revision = property_text(&contact.properties, "lastmodifieddate")
        .unwrap_or_else(|| format!("hubspot-contact:{}", source.external_id));
    Ok(CanonicalRelationshipRecord {
        canonical_id: canonical_relationship_id(tenant_id, project_id, &source),
        source,
        source_revision,
        display_name_digest: digest_relationship_value(&display_name),
        value_digests,
        observed_at,
        revision: 1,
    })
}

fn property_text(properties: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    properties
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn validate_cursor_scope(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    cursor: Option<&RelationshipSourceCursor>,
) -> Result<(), ProviderReadError> {
    if cursor.is_some_and(|cursor| {
        cursor.tenant_id != *tenant_id
            || cursor.project_id != *project_id
            || cursor.provider != "hubspot"
            || cursor.account_id != *account_id
            || cursor.stream != RelationshipSourceStream::People
    }) {
        return Err(ProviderReadError::CursorScopeMismatch);
    }
    if let Some(cursor) = cursor {
        cursor.validate()?;
    }
    Ok(())
}

fn digest_read_observation(
    account_id: &AccountId,
    scope_digest: &str,
    source_revision: u64,
    record_count: usize,
    next_cursor_digest: Option<&str>,
) -> String {
    let value = json!({
        "provider": "hubspot",
        "accountId": account_id,
        "scopeDigest": scope_digest,
        "sourceRevision": source_revision,
        "recordCount": record_count,
        "nextCursorDigest": next_cursor_digest,
    });
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}

fn env_gate_enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}

#[derive(Debug, Deserialize)]
struct HubSpotContactPageWire {
    #[serde(default)]
    results: Vec<HubSpotContactWire>,
    paging: Option<HubSpotPagingWire>,
}

#[derive(Debug, Deserialize)]
struct HubSpotContactWire {
    id: String,
    #[serde(default)]
    properties: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct HubSpotPagingWire {
    next: Option<HubSpotNextWire>,
}

#[derive(Debug, Deserialize)]
struct HubSpotNextWire {
    after: String,
}

#[derive(Debug, Error)]
pub enum ProviderReadError {
    #[error(transparent)]
    Transport(#[from] ProviderTransportError),
    #[error(transparent)]
    Projection(#[from] RelationshipProjectionError),
    #[error("HubSpot read configuration is invalid")]
    InvalidConfig,
    #[error("HubSpot response JSON could not be decoded")]
    InvalidJson,
    #[error("HubSpot contact record is invalid")]
    InvalidContact,
    #[error("HubSpot read cursor is outside the requested account/project scope")]
    CursorScopeMismatch,
    #[error("HubSpot relationship read requires a HubSpot connection in the requested scope")]
    ConnectionScopeMismatch,
    #[error("HubSpot returned HTTP status {status}")]
    HttpStatus { status: u16 },
    #[error("HubSpot read revision overflowed")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::{ProviderHttpMethod, ProviderHttpRequest, ProviderHttpResponse};

    #[derive(Debug)]
    struct ScriptedTransport {
        response: ProviderHttpResponse,
        requests: Mutex<Vec<ProviderHttpRequest>>,
    }

    impl ScriptedTransport {
        fn new(body: &'static [u8]) -> Self {
            Self {
                response: ProviderHttpResponse::new(200, body.to_vec()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProviderHttpTransport for ScriptedTransport {
        fn send(
            &self,
            request: ProviderHttpRequest,
        ) -> Result<ProviderHttpResponse, ProviderTransportError> {
            self.requests.lock().expect("request lock").push(request);
            Ok(self.response.clone())
        }
    }

    fn observed_at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_760_000_000, 0).expect("valid time")
    }

    #[test]
    fn hubspot_transport_contract_is_deterministic_and_redacts_credential_and_body() {
        let transport = ScriptedTransport::new(
            br#"{
              "results": [
                {
                  "id": "contact-42",
                  "properties": {
                    "email": "private@example.test",
                    "firstname": "Ada",
                    "lastname": "Lovelace",
                    "lastmodifieddate": "2026-08-13T00:00:00Z"
                  }
                }
              ],
              "paging": { "next": { "after": "20" } }
            }"#,
        );
        let reader = HubSpotRelationshipReader::new(
            &transport,
            HubSpotReadConfig::new("https://api.hubapi.test").expect("config"),
        );
        let credential = OpaqueCredential::new("hubspot-secret-token").expect("credential");
        let tenant = TenantId::from("tenant-rel");
        let project = ProjectId::from("project-rel");
        let account = AccountId::from("account-rel");
        let first = reader
            .read_contacts(
                &tenant,
                &project,
                &account,
                None,
                &credential,
                observed_at(),
            )
            .expect("HubSpot page");
        let second = reader
            .read_contacts(
                &tenant,
                &project,
                &account,
                None,
                &credential,
                observed_at(),
            )
            .expect("same HubSpot page");
        assert_eq!(first, second);
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.cursor.position.as_deref(), Some("20"));
        assert_eq!(first.observation.status, 200);
        let request = &transport.requests.lock().expect("request lock")[0];
        assert_eq!(request.method(), ProviderHttpMethod::Get);
        assert!(request.url().contains("/crm/v3/objects/contacts"));
        assert!(request.url().contains("properties=email%2Cfirstname"));
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("hubspot-secret-token"));
        assert!(!request_debug.contains("private@example.test"));
    }

    #[test]
    fn hubspot_read_rejects_a_cursor_from_another_account() {
        let transport = ScriptedTransport::new(br#"{"results":[]}"#);
        let reader = HubSpotRelationshipReader::new(
            &transport,
            HubSpotReadConfig::new("https://api.hubapi.test").expect("config"),
        );
        let cursor = RelationshipSourceCursor::new(
            TenantId::from("tenant-rel"),
            ProjectId::from("project-rel"),
            "hubspot",
            AccountId::from("other-account"),
            RelationshipSourceStream::People,
            Some("20".into()),
            1,
            1,
            observed_at(),
        )
        .expect("cursor");
        let error = reader
            .read_contacts(
                &TenantId::from("tenant-rel"),
                &ProjectId::from("project-rel"),
                &AccountId::from("account-rel"),
                Some(&cursor),
                &OpaqueCredential::new("token").expect("credential"),
                observed_at(),
            )
            .expect_err("scope mismatch");
        assert!(matches!(error, ProviderReadError::CursorScopeMismatch));
    }
}
