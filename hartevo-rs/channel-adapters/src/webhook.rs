//! Provider-neutral late/duplicate webhook admission.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{ContentIdentity, ProviderId, RevisionIdentity, WebhookEventId};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WebhookEnvelope {
    event_id: WebhookEventId,
    provider: ProviderId,
    content: ContentIdentity,
    revision: RevisionIdentity,
    occurred_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
}

impl WebhookEnvelope {
    pub fn new(
        event_id: WebhookEventId,
        provider: ProviderId,
        content: ContentIdentity,
        revision: RevisionIdentity,
        occurred_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<Self, WebhookError> {
        if provider != content.provider() || provider != revision.provider() {
            return Err(WebhookError::ProviderIdentityMismatch);
        }
        if revision.content() != &content {
            return Err(WebhookError::RevisionIdentityMismatch);
        }
        if received_at < occurred_at {
            return Err(WebhookError::ReceivedBeforeOccurred);
        }
        Ok(Self {
            event_id,
            provider,
            content,
            revision,
            occurred_at,
            received_at,
        })
    }

    pub const fn event_id(&self) -> &WebhookEventId {
        &self.event_id
    }

    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn revision(&self) -> &RevisionIdentity {
        &self.revision
    }

    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub const fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDisposition {
    Applied,
    Duplicate,
    Late,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WebhookError {
    #[error("webhook provider and identity provider differ")]
    ProviderIdentityMismatch,
    #[error("webhook revision is bound to a different content identity")]
    RevisionIdentityMismatch,
    #[error("webhook received before its occurrence time")]
    ReceivedBeforeOccurred,
}

#[derive(Clone, Debug, Default)]
pub struct WebhookLedger {
    seen_events: BTreeSet<WebhookEventId>,
    latest_by_content: BTreeMap<ContentIdentity, DateTime<Utc>>,
}

impl WebhookLedger {
    pub fn ingest(&mut self, event: &WebhookEnvelope) -> WebhookDisposition {
        if !self.seen_events.insert(event.event_id.clone()) {
            return WebhookDisposition::Duplicate;
        }
        let disposition = match self.latest_by_content.get(event.content()) {
            Some(latest) if event.occurred_at < *latest => WebhookDisposition::Late,
            _ => WebhookDisposition::Applied,
        };
        self.latest_by_content
            .entry(event.content.clone())
            .and_modify(|latest| *latest = (*latest).max(event.occurred_at))
            .or_insert(event.occurred_at);
        disposition
    }

    pub fn latest_occurrence(&self, content: &ContentIdentity) -> Option<DateTime<Utc>> {
        self.latest_by_content.get(content).copied()
    }

    pub fn seen_event_count(&self) -> usize {
        self.seen_events.len()
    }
}
