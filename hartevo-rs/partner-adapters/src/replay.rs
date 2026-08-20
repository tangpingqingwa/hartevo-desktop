use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::callback::{CallbackDisposition, CallbackEvent};
use crate::contract::{NetworkScope, PartnerNetworkError};
use crate::ids::{CallbackEventId, ConversionId};

const REPLAY_WINDOW: Duration = Duration::hours(48);

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplayGuard {
    event_ids: BTreeSet<CallbackEventId>,
    conversion_ids: BTreeSet<ConversionId>,
    latest_by_scope: BTreeMap<String, DateTime<Utc>>,
    accepted: Vec<CallbackEvent>,
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
        if !self.event_ids.insert(event.id.clone()) {
            return Ok(CallbackDisposition::Duplicate);
        }
        if event
            .conversion_id
            .as_ref()
            .is_some_and(|id| self.conversion_ids.contains(id))
        {
            return Ok(CallbackDisposition::Duplicate);
        }

        let scope_digest = scope.digest();
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
        }
        self.accepted.push(event);
        Ok(disposition)
    }

    pub(crate) fn accepted(&self) -> Vec<CallbackEvent> {
        self.accepted.clone()
    }

    pub(crate) fn reset(&mut self) {
        self.event_ids.clear();
        self.conversion_ids.clear();
        self.latest_by_scope.clear();
        self.accepted.clear();
    }
}
