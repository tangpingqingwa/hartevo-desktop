use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AccountId, CanonicalRelationshipRecord, ConversationId, ConversationSourceProjection,
    ConversationSourceState, ProjectId, RelationshipProjectionError, RelationshipSourceCursor,
    RelationshipSourceEvent, RelationshipSourceRef, RelationshipSourceStream, TenantId,
    canonical_conversation_id, canonical_relationship_id, digest_relationship_value,
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
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        if parsed.scheme() != "https"
            || !is_allowed_hubspot_api_host(&host)
            || parsed.port().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
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

    fn contact_url(&self, external_id: &str) -> Result<String, ProviderReadError> {
        let mut url = Url::parse(&self.base_url).map_err(|_| ProviderReadError::InvalidConfig)?;
        url.path_segments_mut()
            .map_err(|()| ProviderReadError::InvalidConfig)?
            .extend(["crm", "v3", "objects", "contacts", external_id]);
        let mut properties = self.properties.clone();
        properties.sort();
        properties.dedup();
        url.query_pairs_mut()
            .append_pair("properties", &properties.join(","));
        Ok(url.to_string())
    }

    fn conversation_threads_url(
        &self,
        cursor: Option<&RelationshipSourceCursor>,
    ) -> Result<String, ProviderReadError> {
        let mut url = Url::parse(&format!(
            "{}/conversations/v3/conversations/threads",
            self.base_url
        ))
        .map_err(|_| ProviderReadError::InvalidConfig)?;
        url.query_pairs_mut()
            .append_pair("limit", &self.page_size.to_string());
        if let Some(cursor) = cursor.and_then(|cursor| cursor.position.as_deref()) {
            url.query_pairs_mut().append_pair("after", cursor);
        }
        Ok(url.to_string())
    }

    fn conversation_thread_url(&self, external_id: &str) -> Result<String, ProviderReadError> {
        let mut url = Url::parse(&self.base_url).map_err(|_| ProviderReadError::InvalidConfig)?;
        url.path_segments_mut()
            .map_err(|()| ProviderReadError::InvalidConfig)?
            .extend([
                "conversations",
                "v3",
                "conversations",
                "threads",
                external_id,
            ]);
        Ok(url.to_string())
    }

    fn account_details_url(&self) -> Result<String, ProviderReadError> {
        Url::parse(&format!("{}/account-info/v3/details", self.base_url))
            .map(|url| url.to_string())
            .map_err(|_| ProviderReadError::InvalidConfig)
    }
}

fn is_allowed_hubspot_api_host(host: &str) -> bool {
    host == "api.hubapi.com"
        || host.ends_with(".hubapi.com")
        || host == "api.hubapi.test"
        || host.ends_with(".hubapi.test")
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

    pub fn verify_account_scope(
        &self,
        expected_external_account_id: &str,
        credential: &OpaqueCredential,
    ) -> Result<(), ProviderReadError> {
        if expected_external_account_id.trim().is_empty() {
            return Err(ProviderReadError::ConnectionScopeMismatch);
        }
        let request =
            ProviderHttpRequest::get(self.config.account_details_url()?, credential.clone());
        let response = self.transport.send(request)?;
        if !(200..300).contains(&response.status()) {
            return Err(ProviderReadError::HttpStatus {
                status: response.status(),
            });
        }
        let details: HubSpotAccountDetailsWire =
            serde_json::from_slice(response.body()).map_err(|_| ProviderReadError::InvalidJson)?;
        let portal_id = scalar_value_text(&details.portal_id)?;
        if portal_id != expected_external_account_id.trim() {
            return Err(ProviderReadError::ConnectionScopeMismatch);
        }
        Ok(())
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

    pub fn read_conversation_threads(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        account_id: &AccountId,
        cursor: Option<&RelationshipSourceCursor>,
        credential: &OpaqueCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<HubSpotConversationReadPage, ProviderReadError> {
        validate_cursor_scope_for_stream(
            tenant_id,
            project_id,
            account_id,
            cursor,
            RelationshipSourceStream::Conversations,
        )?;
        let request = ProviderHttpRequest::get(
            self.config.conversation_threads_url(cursor)?,
            credential.clone(),
        );
        let response = self.transport.send(request)?;
        if !(200..300).contains(&response.status()) {
            return Err(ProviderReadError::HttpStatus {
                status: response.status(),
            });
        }
        let wire: HubSpotConversationPageWire =
            serde_json::from_slice(response.body()).map_err(|_| ProviderReadError::InvalidJson)?;
        let record_count = wire.results.len();
        let mut sources = Vec::with_capacity(record_count);
        for thread in &wire.results {
            sources.push(canonical_conversation_source(
                tenant_id,
                project_id,
                account_id,
                thread,
                observed_at,
            )?);
        }
        let next_position = wire
            .paging
            .and_then(|paging| paging.next)
            .map(|next| next.after)
            .filter(|after| !after.trim().is_empty());
        let source_revision = next_source_revision(cursor)?;
        let revision = next_cursor_revision(cursor)?;
        let next_cursor = RelationshipSourceCursor::new(
            tenant_id.clone(),
            project_id.clone(),
            "hubspot",
            account_id.clone(),
            RelationshipSourceStream::Conversations,
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
        Ok(HubSpotConversationReadPage {
            sources,
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

    pub fn read_contact(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        account_id: &AccountId,
        external_id: &str,
        credential: &OpaqueCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<CanonicalRelationshipRecord, ProviderReadError> {
        let external_id = non_empty_external_id(external_id)?;
        let request =
            ProviderHttpRequest::get(self.config.contact_url(&external_id)?, credential.clone());
        let response = self.transport.send(request)?;
        if !(200..300).contains(&response.status()) {
            return Err(ProviderReadError::HttpStatus {
                status: response.status(),
            });
        }
        let contact: HubSpotContactWire =
            serde_json::from_slice(response.body()).map_err(|_| ProviderReadError::InvalidJson)?;
        canonical_contact_record(tenant_id, project_id, account_id, &contact, observed_at)
    }

    pub fn read_conversation_thread(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        account_id: &AccountId,
        external_id: &str,
        credential: &OpaqueCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<ConversationSourceProjection, ProviderReadError> {
        let external_id = non_empty_external_id(external_id)?;
        let request = ProviderHttpRequest::get(
            self.config.conversation_thread_url(&external_id)?,
            credential.clone(),
        );
        let response = self.transport.send(request)?;
        if !(200..300).contains(&response.status()) {
            return Err(ProviderReadError::HttpStatus {
                status: response.status(),
            });
        }
        let thread: HubSpotConversationThreadWire =
            serde_json::from_slice(response.body()).map_err(|_| ProviderReadError::InvalidJson)?;
        canonical_conversation_source(tenant_id, project_id, account_id, &thread, observed_at)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the journey keeps tenant/project/account scope, independent stream cursors, credential, and observation time explicit"
    )]
    pub fn read_journey(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        account_id: &AccountId,
        people_cursor: Option<&RelationshipSourceCursor>,
        conversation_cursor: Option<&RelationshipSourceCursor>,
        credential: &OpaqueCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<HubSpotRelationshipReadJourney, ProviderReadError> {
        let people = self.read_contacts(
            tenant_id,
            project_id,
            account_id,
            people_cursor,
            credential,
            observed_at,
        )?;
        let conversations = self.read_conversation_threads(
            tenant_id,
            project_id,
            account_id,
            conversation_cursor,
            credential,
            observed_at,
        )?;
        Ok(HubSpotRelationshipReadJourney {
            people,
            conversations,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the scoped journey keeps both local and provider account identifiers visible at the authenticated boundary"
    )]
    pub fn read_scoped_journey(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        account_id: &AccountId,
        expected_external_account_id: &str,
        people_cursor: Option<&RelationshipSourceCursor>,
        conversation_cursor: Option<&RelationshipSourceCursor>,
        credential: &OpaqueCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<HubSpotRelationshipReadJourney, ProviderReadError> {
        self.verify_account_scope(expected_external_account_id, credential)?;
        self.read_journey(
            tenant_id,
            project_id,
            account_id,
            people_cursor,
            conversation_cursor,
            credential,
            observed_at,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HubSpotConversationReadPage {
    pub sources: Vec<ConversationSourceProjection>,
    pub cursor: RelationshipSourceCursor,
    pub observation: HubSpotReadObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HubSpotRelationshipReadJourney {
    pub people: HubSpotReadPage,
    pub conversations: HubSpotConversationReadPage,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HubSpotWebhookEvent {
    pub source: RelationshipSourceRef,
    pub event_id: String,
    pub event_digest: String,
    pub portal_id: String,
    pub subscription_type: String,
    pub occurred_at: DateTime<Utc>,
    pub attempt_number: u32,
    pub property_name: Option<String>,
}

impl fmt::Debug for HubSpotWebhookEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HubSpotWebhookEvent")
            .field("source", &self.source)
            .field("event_id", &self.event_id)
            .field("event_digest", &self.event_digest)
            .field("portal_id", &self.portal_id)
            .field("subscription_type", &self.subscription_type)
            .field("occurred_at", &self.occurred_at)
            .field("attempt_number", &self.attempt_number)
            .field("property_name", &self.property_name)
            .finish()
    }
}

impl HubSpotWebhookEvent {
    pub fn as_source_event(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        observed_at: DateTime<Utc>,
    ) -> RelationshipSourceEvent {
        RelationshipSourceEvent {
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            source: self.source.clone(),
            event_id: self.event_id.clone(),
            event_digest: self.event_digest.clone(),
            occurred_at: self.occurred_at,
            observed_at,
            revision: 1,
        }
    }
}

/// Verifies HubSpot's legacy-compatible `X-HubSpot-Signature` scheme over the
/// unparsed body. The raw body is never retained or included in an error.
pub fn verify_hubspot_webhook_signature(
    raw_body: &[u8],
    signature: &str,
    client_secret: &OpaqueCredential,
) -> Result<(), ProviderReadError> {
    let expected = format!(
        "{:x}",
        Sha256::digest(
            [client_secret.expose().as_bytes(), raw_body]
                .into_iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
        )
    );
    let supplied = signature
        .trim()
        .strip_prefix("v1=")
        .unwrap_or(signature.trim());
    let supplied = supplied.as_bytes();
    let mut difference = expected.len() ^ supplied.len();
    for (left, right) in expected.as_bytes().iter().zip(supplied.iter()) {
        difference |= usize::from(left ^ right);
    }
    if difference != 0 {
        return Err(ProviderReadError::InvalidWebhookSignature);
    }
    Ok(())
}

pub fn parse_hubspot_webhook_events(
    raw_body: &[u8],
    signature: &str,
    client_secret: &OpaqueCredential,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    observed_at: DateTime<Utc>,
) -> Result<Vec<HubSpotWebhookEvent>, ProviderReadError> {
    parse_hubspot_webhook_events_for_account(
        raw_body,
        signature,
        client_secret,
        tenant_id,
        project_id,
        account_id,
        account_id.as_str(),
        observed_at,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "webhook parsing keeps raw signature inputs and both local and provider account scopes explicit"
)]
pub fn parse_hubspot_webhook_events_for_account(
    raw_body: &[u8],
    signature: &str,
    client_secret: &OpaqueCredential,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    expected_external_account_id: &str,
    observed_at: DateTime<Utc>,
) -> Result<Vec<HubSpotWebhookEvent>, ProviderReadError> {
    verify_hubspot_webhook_signature(raw_body, signature, client_secret)?;
    let payload: HubSpotWebhookPayloadWire =
        serde_json::from_slice(raw_body).map_err(|_| ProviderReadError::InvalidJson)?;
    let events = match payload {
        HubSpotWebhookPayloadWire::Batch(events) => events,
        HubSpotWebhookPayloadWire::Single(event) => vec![event],
    };
    let mut normalized = events
        .into_iter()
        .map(|event| {
            normalize_hubspot_webhook_event(
                event,
                tenant_id,
                project_id,
                account_id,
                expected_external_account_id,
                observed_at,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort_by(|left, right| {
        (
            left.occurred_at,
            left.event_id.as_str(),
            left.source.external_id.as_str(),
        )
            .cmp(&(
                right.occurred_at,
                right.event_id.as_str(),
                right.source.external_id.as_str(),
            ))
    });
    Ok(normalized)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HubSpotRelationshipReadProbeOutcome {
    BlockedEnv { reason: String },
    Observed(Box<HubSpotRelationshipReadJourney>),
}

#[allow(
    clippy::too_many_arguments,
    reason = "the env-gated read seam keeps tenant/project/account scopes, independent cursors, and observation time explicit"
)]
pub fn run_hubspot_relationship_read_probe_from_env<T: ProviderHttpTransport>(
    transport: &T,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    expected_external_account_id: &str,
    people_cursor: Option<&RelationshipSourceCursor>,
    conversation_cursor: Option<&RelationshipSourceCursor>,
    observed_at: DateTime<Utc>,
) -> Result<HubSpotRelationshipReadProbeOutcome, ProviderReadError> {
    if !env_gate_enabled(HUBSPOT_READ_PROBE_GATE_ENV) {
        return Ok(HubSpotRelationshipReadProbeOutcome::BlockedEnv {
            reason: format!("{HUBSPOT_READ_PROBE_GATE_ENV} is not enabled"),
        });
    }
    let credential = match OpaqueCredential::from_env(HUBSPOT_ACCESS_TOKEN_ENV) {
        Ok(credential) => credential,
        Err(ProviderTransportError::MissingCredential) => {
            return Ok(HubSpotRelationshipReadProbeOutcome::BlockedEnv {
                reason: format!("{HUBSPOT_ACCESS_TOKEN_ENV} is missing"),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let config = HubSpotReadConfig::from_env()?;
    let reader = HubSpotRelationshipReader::new(transport, config);
    let journey = reader.read_scoped_journey(
        tenant_id,
        project_id,
        account_id,
        expected_external_account_id,
        people_cursor,
        conversation_cursor,
        &credential,
        observed_at,
    )?;
    Ok(HubSpotRelationshipReadProbeOutcome::Observed(Box::new(
        journey,
    )))
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
        deleted: false,
        observed_at,
        revision: 1,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the adapter normalizes one provider thread into a bounded content-free source projection"
)]
fn canonical_conversation_source(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    thread: &HubSpotConversationThreadWire,
    observed_at: DateTime<Utc>,
) -> Result<ConversationSourceProjection, ProviderReadError> {
    let external_id = non_empty_external_id(&thread.id)?;
    let source = RelationshipSourceRef {
        provider: "hubspot".into(),
        account_id: account_id.clone(),
        stream: RelationshipSourceStream::Conversations,
        external_id,
    };
    source.validate()?;
    let person_id = thread
        .associated_contact_id
        .as_deref()
        .map(non_empty_external_id)
        .transpose()?
        .map(|contact_id| {
            let person_source = RelationshipSourceRef {
                provider: "hubspot".into(),
                account_id: account_id.clone(),
                stream: RelationshipSourceStream::People,
                external_id: contact_id,
            };
            hartevo_domain_kernel::PersonId::from_stable(canonical_relationship_id(
                tenant_id,
                project_id,
                &person_source,
            ))
        });
    let latest_activity_at = [
        thread.latest_message_timestamp.as_deref(),
        thread.latest_message_received_timestamp.as_deref(),
        thread.latest_message_sent_timestamp.as_deref(),
        thread.created_at.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(parse_hubspot_timestamp)
    .max();
    let latest_received_at = thread
        .latest_message_received_timestamp
        .as_deref()
        .and_then(parse_hubspot_timestamp);
    let latest_sent_at = thread
        .latest_message_sent_timestamp
        .as_deref()
        .and_then(parse_hubspot_timestamp);
    let source_revision = [
        thread.latest_message_timestamp.as_deref(),
        thread.latest_message_received_timestamp.as_deref(),
        thread.latest_message_sent_timestamp.as_deref(),
        thread.created_at.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|value| parse_hubspot_timestamp(value).map(|parsed| (parsed, value)))
    .max_by_key(|(parsed, _)| *parsed)
    .map_or_else(
        || format!("hubspot-conversation:{}", source.external_id),
        |(_, value)| value.trim().to_owned(),
    );
    let source_state = if thread.archived {
        ConversationSourceState::Archived
    } else {
        match thread
            .status
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_uppercase)
            .as_deref()
        {
            Some("OPEN") => ConversationSourceState::Open,
            Some("CLOSED") => ConversationSourceState::Closed,
            Some("ARCHIVED") => ConversationSourceState::Archived,
            _ => ConversationSourceState::Unknown,
        }
    };
    let source_revision_digest = digest_relationship_value(
        &json!({
            "source": source.external_id,
            "associatedContactId": thread.associated_contact_id,
            "createdAt": thread.created_at,
            "latestMessageTimestamp": thread.latest_message_timestamp,
            "latestMessageReceivedTimestamp": thread.latest_message_received_timestamp,
            "latestMessageSentTimestamp": thread.latest_message_sent_timestamp,
            "archived": thread.archived,
            "status": thread.status,
        })
        .to_string(),
    );
    Ok(ConversationSourceProjection {
        tenant_id: tenant_id.clone(),
        project_id: project_id.clone(),
        conversation_id: ConversationId::from_stable(canonical_conversation_id(
            tenant_id, project_id, &source,
        )),
        person_id,
        source,
        source_revision,
        source_revision_digest,
        source_state,
        archived: thread.archived,
        deleted: false,
        latest_activity_at,
        latest_received_at,
        latest_sent_at,
        observed_at,
        revision: 1,
    })
}

fn non_empty_external_id(value: &str) -> Result<String, ProviderReadError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ProviderReadError::InvalidSourceObject);
    }
    Ok(value.to_owned())
}

fn parse_hubspot_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
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
    validate_cursor_scope_for_stream(
        tenant_id,
        project_id,
        account_id,
        cursor,
        RelationshipSourceStream::People,
    )
}

fn validate_cursor_scope_for_stream(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    cursor: Option<&RelationshipSourceCursor>,
    stream: RelationshipSourceStream,
) -> Result<(), ProviderReadError> {
    if cursor.is_some_and(|cursor| {
        cursor.tenant_id != *tenant_id
            || cursor.project_id != *project_id
            || cursor.provider != "hubspot"
            || cursor.account_id != *account_id
            || cursor.stream != stream
    }) {
        return Err(ProviderReadError::CursorScopeMismatch);
    }
    if let Some(cursor) = cursor {
        cursor.validate()?;
    }
    Ok(())
}

fn next_source_revision(
    cursor: Option<&RelationshipSourceCursor>,
) -> Result<u64, ProviderReadError> {
    cursor.map_or(Ok(1), |cursor| {
        cursor
            .source_revision
            .checked_add(1)
            .ok_or(ProviderReadError::RevisionOverflow)
    })
}

fn next_cursor_revision(
    cursor: Option<&RelationshipSourceCursor>,
) -> Result<u64, ProviderReadError> {
    cursor.map_or(Ok(1), |cursor| {
        cursor
            .revision
            .checked_add(1)
            .ok_or(ProviderReadError::RevisionOverflow)
    })
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

#[derive(Deserialize)]
struct HubSpotContactPageWire {
    #[serde(default)]
    results: Vec<HubSpotContactWire>,
    paging: Option<HubSpotPagingWire>,
}

#[derive(Deserialize)]
struct HubSpotContactWire {
    id: String,
    #[serde(default)]
    properties: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct HubSpotPagingWire {
    next: Option<HubSpotNextWire>,
}

#[derive(Deserialize)]
struct HubSpotNextWire {
    after: String,
}

#[derive(Deserialize)]
struct HubSpotConversationPageWire {
    #[serde(default)]
    results: Vec<HubSpotConversationThreadWire>,
    paging: Option<HubSpotPagingWire>,
}

#[derive(Deserialize)]
struct HubSpotConversationThreadWire {
    id: String,
    #[serde(rename = "associatedContactId")]
    associated_contact_id: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
    #[serde(rename = "latestMessageReceivedTimestamp")]
    latest_message_received_timestamp: Option<String>,
    #[serde(rename = "latestMessageSentTimestamp")]
    latest_message_sent_timestamp: Option<String>,
    #[serde(rename = "latestMessageTimestamp")]
    latest_message_timestamp: Option<String>,
    #[serde(default)]
    archived: bool,
    status: Option<String>,
}

#[derive(Deserialize)]
struct HubSpotAccountDetailsWire {
    #[serde(rename = "portalId")]
    portal_id: Value,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HubSpotWebhookPayloadWire {
    Batch(Vec<HubSpotWebhookEventWire>),
    Single(HubSpotWebhookEventWire),
}

#[derive(Deserialize)]
struct HubSpotWebhookEventWire {
    #[serde(rename = "eventId")]
    event_id: Option<Value>,
    #[serde(rename = "portalId")]
    portal_id: Value,
    #[serde(rename = "objectId")]
    object_id: Value,
    #[serde(rename = "subscriptionType")]
    subscription_type: String,
    #[serde(rename = "occurredAt")]
    occurred_at: i64,
    #[serde(rename = "attemptNumber", default)]
    attempt_number: u32,
    #[serde(rename = "propertyName")]
    property_name: Option<String>,
}

fn normalize_hubspot_webhook_event(
    event: HubSpotWebhookEventWire,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    account_id: &AccountId,
    expected_external_account_id: &str,
    observed_at: DateTime<Utc>,
) -> Result<HubSpotWebhookEvent, ProviderReadError> {
    let portal_id = scalar_value_text(&event.portal_id)?;
    if portal_id != expected_external_account_id.trim() {
        return Err(ProviderReadError::ConnectionScopeMismatch);
    }
    let external_id = non_empty_external_id(&scalar_value_text(&event.object_id)?)?;
    let stream = webhook_stream(&event.subscription_type).ok_or_else(|| {
        ProviderReadError::UnsupportedWebhookEvent {
            subscription_type: event.subscription_type.clone(),
        }
    })?;
    let source = RelationshipSourceRef {
        provider: "hubspot".into(),
        account_id: account_id.clone(),
        stream,
        external_id,
    };
    source.validate()?;
    let occurred_at = DateTime::from_timestamp_millis(event.occurred_at)
        .ok_or(ProviderReadError::InvalidWebhookTimestamp)?;
    let event_id = event
        .event_id
        .as_ref()
        .map(scalar_value_text)
        .transpose()?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("derived-{}", webhook_event_digest(&event, &source)));
    let event_digest = webhook_event_digest(&event, &source);
    let event = HubSpotWebhookEvent {
        source,
        event_id,
        event_digest,
        portal_id,
        subscription_type: event.subscription_type,
        occurred_at,
        attempt_number: event.attempt_number,
        property_name: event.property_name,
    };
    if event.occurred_at > observed_at + chrono::Duration::minutes(10) {
        return Err(ProviderReadError::InvalidWebhookTimestamp);
    }
    if tenant_id.as_str().trim().is_empty() || project_id.as_str().trim().is_empty() {
        return Err(ProviderReadError::ConnectionScopeMismatch);
    }
    Ok(event)
}

fn scalar_value_text(value: &Value) -> Result<String, ProviderReadError> {
    match value {
        Value::String(value) => Ok(value.trim().to_owned()),
        Value::Number(value) => Ok(value.to_string()),
        _ => Err(ProviderReadError::InvalidWebhookPayload),
    }
}

fn webhook_stream(subscription_type: &str) -> Option<RelationshipSourceStream> {
    if subscription_type.starts_with("contact.") {
        Some(RelationshipSourceStream::People)
    } else if subscription_type.starts_with("conversation.") {
        Some(RelationshipSourceStream::Conversations)
    } else {
        None
    }
}

fn webhook_event_digest(event: &HubSpotWebhookEventWire, source: &RelationshipSourceRef) -> String {
    let value = json!({
        "provider": source.provider,
        "accountId": source.account_id,
        "stream": source.stream,
        "sourceId": source.external_id,
        "eventId": event.event_id,
        "portalId": event.portal_id,
        "subscriptionType": event.subscription_type,
        "occurredAt": event.occurred_at,
        "propertyName": event.property_name,
    });
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
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
    #[error("HubSpot source object identifier is invalid")]
    InvalidSourceObject,
    #[error("HubSpot webhook payload is invalid")]
    InvalidWebhookPayload,
    #[error("HubSpot webhook signature is invalid")]
    InvalidWebhookSignature,
    #[error("HubSpot webhook timestamp is invalid")]
    InvalidWebhookTimestamp,
    #[error("HubSpot webhook subscription is unsupported: {subscription_type}")]
    UnsupportedWebhookEvent { subscription_type: String },
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

    #[test]
    fn hubspot_conversation_read_is_account_scoped_and_body_free() {
        let transport = ScriptedTransport::new(
            br#"{
              "results": [
                {
                  "id": "thread-7",
                  "associatedContactId": "contact-42",
                  "createdAt": "2026-08-13T00:00:00Z",
                  "latestMessageReceivedTimestamp": "2026-08-13T00:05:00Z",
                  "latestMessageTimestamp": "2026-08-13T00:05:00Z",
                  "archived": false,
                  "status": "OPEN"
                }
              ],
              "paging": { "next": { "after": "thread-page-2" } }
            }"#,
        );
        let reader = HubSpotRelationshipReader::new(
            &transport,
            HubSpotReadConfig::new("https://api.hubapi.test").expect("config"),
        );
        let page = reader
            .read_conversation_threads(
                &TenantId::from("tenant-rel"),
                &ProjectId::from("project-rel"),
                &AccountId::from("account-rel"),
                None,
                &OpaqueCredential::new("hubspot-token").expect("credential"),
                observed_at(),
            )
            .expect("conversation page");
        assert_eq!(page.sources.len(), 1);
        assert_eq!(page.sources[0].source.external_id, "thread-7");
        assert_eq!(page.sources[0].source_state, ConversationSourceState::Open);
        assert_eq!(
            page.sources[0].latest_received_at,
            Some(
                DateTime::parse_from_rfc3339("2026-08-13T00:05:00Z")
                    .expect("thread time")
                    .with_timezone(&Utc),
            )
        );
        assert_eq!(page.cursor.position.as_deref(), Some("thread-page-2"));
        let request = &transport.requests.lock().expect("request lock")[0];
        assert!(
            request
                .url()
                .contains("/conversations/v3/conversations/threads")
        );
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("hubspot-token"));
        assert!(!request_debug.contains("private@example.test"));
    }

    #[test]
    fn hubspot_account_scope_requires_the_provider_portal_id() {
        let transport = ScriptedTransport::new(br#"{"portalId":"portal-42"}"#);
        let reader = HubSpotRelationshipReader::new(
            &transport,
            HubSpotReadConfig::new("https://api.hubapi.test").expect("config"),
        );
        reader
            .verify_account_scope(
                "portal-42",
                &OpaqueCredential::new("hubspot-token").expect("credential"),
            )
            .expect("matching provider portal");
        let error = reader
            .verify_account_scope(
                "portal-other",
                &OpaqueCredential::new("hubspot-token").expect("credential"),
            )
            .expect_err("wrong provider portal");
        assert!(matches!(error, ProviderReadError::ConnectionScopeMismatch));
        assert!(
            transport.requests.lock().expect("request lock")[0]
                .url()
                .contains("/account-info/v3/details")
        );
    }

    #[test]
    fn hubspot_webhook_signature_is_verified_and_event_dedup_ignores_retry_attempt() {
        let raw = br#"[
          {
            "eventId": "event-1",
            "portalId": "account-rel",
            "objectId": "contact-42",
            "subscriptionType": "contact.propertyChange",
            "occurredAt": 1762992000000,
            "attemptNumber": 0,
            "propertyName": "email",
            "propertyValue": "private@example.test"
          }
        ]"#;
        let retry = br#"[
          {
            "eventId": "event-1",
            "portalId": "account-rel",
            "objectId": "contact-42",
            "subscriptionType": "contact.propertyChange",
            "occurredAt": 1762992000000,
            "attemptNumber": 1,
            "propertyName": "email",
            "propertyValue": "private@example.test"
          }
        ]"#;
        let secret = OpaqueCredential::new("hubspot-client-secret").expect("secret");
        let signature = format!(
            "{:x}",
            Sha256::digest(
                [secret.expose().as_bytes(), raw]
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>(),
            )
        );
        let events = parse_hubspot_webhook_events(
            raw,
            &signature,
            &secret,
            &TenantId::from("tenant-rel"),
            &ProjectId::from("project-rel"),
            &AccountId::from("account-rel"),
            DateTime::from_timestamp_millis(1_762_992_000_000).expect("observed time"),
        )
        .expect("verified webhook");
        let retry_signature = format!(
            "{:x}",
            Sha256::digest(
                [secret.expose().as_bytes(), retry]
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>(),
            )
        );
        let retry_events = parse_hubspot_webhook_events(
            retry,
            &retry_signature,
            &secret,
            &TenantId::from("tenant-rel"),
            &ProjectId::from("project-rel"),
            &AccountId::from("account-rel"),
            DateTime::from_timestamp_millis(1_762_992_000_000).expect("observed time"),
        )
        .expect("verified retry");
        assert_eq!(events[0].event_id, "event-1");
        assert_eq!(events[0].event_digest, retry_events[0].event_digest);
        assert_eq!(events[0].source.stream, RelationshipSourceStream::People);
        let locally_scoped = parse_hubspot_webhook_events_for_account(
            raw,
            &signature,
            &secret,
            &TenantId::from("tenant-rel"),
            &ProjectId::from("project-rel"),
            &AccountId::from("local-account"),
            "account-rel",
            DateTime::from_timestamp_millis(1_762_992_000_000).expect("observed time"),
        )
        .expect("provider and local account scopes");
        assert_eq!(
            locally_scoped[0].source.account_id,
            AccountId::from("local-account")
        );
        let event_debug = format!("{:?}", events[0]);
        assert!(!event_debug.contains("private@example.test"));
        assert!(matches!(
            verify_hubspot_webhook_signature(raw, "not-a-signature", &secret),
            Err(ProviderReadError::InvalidWebhookSignature)
        ));
    }
}
