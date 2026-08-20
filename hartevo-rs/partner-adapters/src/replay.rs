use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::callback::{CallbackDisposition, CallbackEvent};
use crate::contract::{NetworkScope, PartnerNetworkError};
use crate::ids::{CallbackEventId, ConversionId};

const REPLAY_WINDOW: Duration = Duration::hours(48);
pub(crate) const MAX_REPLAY_EVENTS: usize = 1_024;
pub(crate) const MAX_REPLAY_CONVERSIONS: usize = 1_024;
pub(crate) const MAX_REPLAY_SCOPES: usize = 256;
pub(crate) const MAX_REPLAY_EVENTS_PER_SCOPE: usize = 256;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplayGuard {
    event_ids: BTreeSet<CallbackEventId>,
    conversion_ids: BTreeSet<ConversionId>,
    latest_by_scope: BTreeMap<String, DateTime<Utc>>,
    accepted: Vec<CallbackEvent>,
    #[serde(default)]
    event_received_at: BTreeMap<CallbackEventId, DateTime<Utc>>,
    #[serde(default)]
    conversion_received_at: BTreeMap<ConversionId, DateTime<Utc>>,
    #[serde(default)]
    rate_window_by_scope: BTreeMap<String, Vec<DateTime<Utc>>>,
}

impl ReplayGuard {
    pub(crate) fn ingest(
        &mut self,
        scope: &NetworkScope,
        event: CallbackEvent,
        received_at: DateTime<Utc>,
    ) -> Result<CallbackDisposition, PartnerNetworkError> {
        if event.occurred_at > received_at || received_at - event.occurred_at > REPLAY_WINDOW {
            return Err(PartnerNetworkError::ReplayWindowExpired);
        }
        self.prune(received_at);
        if !self.event_ids.insert(event.id.clone()) {
            return Ok(CallbackDisposition::Duplicate);
        }
        if self.event_ids.len() > MAX_REPLAY_EVENTS {
            self.event_ids.remove(&event.id);
            return Err(PartnerNetworkError::ReplayQuotaExceeded);
        }
        if event
            .conversion_id
            .as_ref()
            .is_some_and(|id| self.conversion_ids.contains(id))
        {
            self.event_received_at.insert(event.id.clone(), received_at);
            return Ok(CallbackDisposition::Duplicate);
        }
        if event
            .conversion_id
            .as_ref()
            .is_some_and(|_| self.conversion_ids.len() >= MAX_REPLAY_CONVERSIONS)
        {
            self.event_ids.remove(&event.id);
            return Err(PartnerNetworkError::ReplayQuotaExceeded);
        }

        let scope_digest = scope.digest();
        let rate_window = self
            .rate_window_by_scope
            .entry(scope_digest.clone())
            .or_default();
        if rate_window.len() >= MAX_REPLAY_EVENTS_PER_SCOPE {
            self.event_ids.remove(&event.id);
            return Err(PartnerNetworkError::ReplayRateLimited);
        }
        if !self.latest_by_scope.contains_key(&scope_digest)
            && self.latest_by_scope.len() >= MAX_REPLAY_SCOPES
        {
            self.event_ids.remove(&event.id);
            return Err(PartnerNetworkError::ReplayQuotaExceeded);
        }
        let disposition = if self
            .latest_by_scope
            .get(&scope_digest)
            .is_some_and(|latest| event.occurred_at < *latest)
        {
            CallbackDisposition::OutOfOrder
        } else {
            CallbackDisposition::Accepted
        };
        self.latest_by_scope
            .entry(scope_digest)
            .and_modify(|latest| *latest = (*latest).max(event.occurred_at))
            .or_insert(event.occurred_at);
        if let Some(conversion_id) = &event.conversion_id {
            self.conversion_ids.insert(conversion_id.clone());
            self.conversion_received_at
                .insert(conversion_id.clone(), received_at);
        }
        self.event_received_at.insert(event.id.clone(), received_at);
        rate_window.push(received_at);
        self.accepted.push(event);
        Ok(disposition)
    }

    fn prune(&mut self, received_at: DateTime<Utc>) {
        let cutoff = received_at - REPLAY_WINDOW;
        self.event_received_at
            .retain(|_, observed_at| *observed_at >= cutoff);
        self.event_ids
            .retain(|event_id| self.event_received_at.contains_key(event_id));
        self.conversion_received_at
            .retain(|_, observed_at| *observed_at >= cutoff);
        self.conversion_ids
            .retain(|conversion_id| self.conversion_received_at.contains_key(conversion_id));
        self.latest_by_scope
            .retain(|_, observed_at| *observed_at >= cutoff);
        self.rate_window_by_scope.retain(|_, timestamps| {
            timestamps.retain(|observed_at| *observed_at >= cutoff);
            !timestamps.is_empty()
        });
        self.accepted
            .retain(|event| self.event_received_at.contains_key(&event.id));
    }

    pub(crate) fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.event_ids.len() > MAX_REPLAY_EVENTS
            || self.event_received_at.len() > MAX_REPLAY_EVENTS
            || self.conversion_ids.len() > MAX_REPLAY_CONVERSIONS
            || self.conversion_received_at.len() > MAX_REPLAY_CONVERSIONS
            || self.latest_by_scope.len() > MAX_REPLAY_SCOPES
            || self.rate_window_by_scope.len() > MAX_REPLAY_SCOPES
            || self.accepted.len() > MAX_REPLAY_EVENTS
            || self
                .rate_window_by_scope
                .values()
                .any(|timestamps| timestamps.len() > MAX_REPLAY_EVENTS_PER_SCOPE)
            || self
                .event_ids
                .iter()
                .any(|event_id| !self.event_received_at.contains_key(event_id))
            || self
                .conversion_ids
                .iter()
                .any(|conversion_id| !self.conversion_received_at.contains_key(conversion_id))
        {
            return Err(PartnerNetworkError::DurabilityUnavailable);
        }
        Ok(())
    }

    pub(crate) fn accepted(&self) -> Vec<CallbackEvent> {
        self.accepted.clone()
    }

    pub(crate) fn reset(&mut self) {
        self.event_ids.clear();
        self.conversion_ids.clear();
        self.latest_by_scope.clear();
        self.accepted.clear();
        self.event_received_at.clear();
        self.conversion_received_at.clear();
        self.rate_window_by_scope.clear();
    }
}
