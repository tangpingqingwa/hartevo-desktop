//! Typed bounded Fivetran provider.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::{
    ConnectionListItemProjection, ConnectionListProjection, ConnectionListRequest,
    DestinationIdentityProjection, FivetranConnectionListPayload, FivetranConnectionPayload,
    FivetranConnectionProjection, FivetranConnectionStatePayload,
    FivetranConnectionStateProjection, FivetranError, FivetranProvenance, FivetranResultState,
    FivetranSchemaTableProjection, FivetranScope, FivetranStatusPayload, FivetranSyncEvidence,
    FivetranSyncRecording, FivetranSyncResultProposal, RegistrationStatus, SetupState, SyncState,
    UpdateState, VerificationReport,
};
use crate::transport::{
    FivetranEndpoint, FivetranHttpResponse, FivetranRequest, FivetranResponsePayload,
    FivetranTransport, FivetranTransportError,
};
use crate::{CONTRACT_VERSION, FivetranRegistration, MAX_PAGE_ITEMS, MAX_PAGES, Result};

/// Provider lifecycle state. `Connected` is deliberately absent: upstream
/// setup state is represented in a projection while transport provenance is
/// always non-native in Layer 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FivetranProviderState {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
    Unmounted,
    Revoked,
    RateLimited,
    Timeout,
    ServerFailure,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Partial,
    ProviderUnknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranBackoff {
    pub consecutive_failures: u32,
    pub retry_after_seconds: Option<u32>,
    pub suggested_delay_seconds: u32,
    pub sleeping_performed: bool,
}

impl FivetranBackoff {
    fn reset(&mut self) {
        self.consecutive_failures = 0;
        self.retry_after_seconds = None;
        self.suggested_delay_seconds = 0;
        self.sleeping_performed = false;
    }

    fn note_retryable(&mut self, retry_after_seconds: Option<u32>) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.retry_after_seconds = retry_after_seconds;
        let exponential = 2_u32.saturating_pow(self.consecutive_failures.min(8));
        self.suggested_delay_seconds = retry_after_seconds.unwrap_or(exponential).min(900);
        self.sleeping_performed = false;
    }
}

/// Bounded Fivetran provider. It has no native credential resolver and the
/// transport can only be one of the four non-native Layer-1 modes.
pub struct FivetranProvider<T>
where
    T: FivetranTransport,
{
    registration: FivetranRegistration,
    transport: T,
    state: FivetranProviderState,
    backoff: FivetranBackoff,
    last_sync_revision: Option<u64>,
    last_sync_state: Option<SyncState>,
    recorded_evidence: BTreeSet<crate::Digest>,
}

impl<T> std::fmt::Debug for FivetranProvider<T>
where
    T: FivetranTransport,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FivetranProvider")
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .field("state", &self.state)
            .field("backoff", &self.backoff)
            .field("last_sync_revision", &self.last_sync_revision)
            .field("last_sync_state", &self.last_sync_state)
            .field("recorded_evidence_count", &self.recorded_evidence.len())
            .finish()
    }
}

impl<T> FivetranProvider<T>
where
    T: FivetranTransport,
{
    pub fn new(registration: FivetranRegistration, transport: T) -> Result<Self> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active {
            return if matches!(
                registration.status,
                RegistrationStatus::Revoked | RegistrationStatus::Reversed
            ) {
                Err(FivetranError::RegistrationRevoked)
            } else {
                Err(FivetranError::RegistrationNotActive)
            };
        }
        let state = match transport.mode() {
            crate::TransportMode::Recording => FivetranProviderState::Recording,
            crate::TransportMode::Fixture => FivetranProviderState::Fixture,
            crate::TransportMode::Loopback => FivetranProviderState::Loopback,
            crate::TransportMode::BlockedEnv => FivetranProviderState::BlockedEnv,
        };
        Ok(Self {
            registration,
            transport,
            state,
            backoff: FivetranBackoff::default(),
            last_sync_revision: None,
            last_sync_state: None,
            recorded_evidence: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &FivetranRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &FivetranScope {
        &self.registration.scope
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn state(&self) -> FivetranProviderState {
        self.state
    }

    pub fn backoff(&self) -> &FivetranBackoff {
        &self.backoff
    }

    pub fn unmount(&mut self) -> Result<crate::RegistrationTransition> {
        let transition = self.registration.unmount()?;
        self.state = FivetranProviderState::Unmounted;
        Ok(transition)
    }

    pub fn remount(&mut self) -> Result<crate::RegistrationTransition> {
        let transition = self.registration.remount()?;
        self.state = match self.transport.mode() {
            crate::TransportMode::Recording => FivetranProviderState::Recording,
            crate::TransportMode::Fixture => FivetranProviderState::Fixture,
            crate::TransportMode::Loopback => FivetranProviderState::Loopback,
            crate::TransportMode::BlockedEnv => FivetranProviderState::BlockedEnv,
        };
        Ok(transition)
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationTransition> {
        let transition = self.registration.revoke()?;
        self.state = FivetranProviderState::Revoked;
        Ok(transition)
    }

    pub fn reverse(&mut self) -> Result<crate::RegistrationTransition> {
        let transition = self.registration.reverse()?;
        self.state = FivetranProviderState::Revoked;
        Ok(transition)
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(FivetranError::MutationForbidden { operation })
    }

    pub fn describe_connection(&mut self) -> Result<FivetranConnectionProjection> {
        self.ensure_active()?;
        let request = FivetranRequest::connection(self.scope())?;
        let response = self.execute(&request)?;
        let payload = match response.payload.as_ref() {
            Some(FivetranResponsePayload::Connection(payload)) => payload,
            _ => return Err(FivetranError::MalformedPayload),
        };
        payload.validate()?;
        let destination = self.check_connection_scope(payload)?;
        let provenance = self.provenance(&request, &response);
        let mut projection = FivetranConnectionProjection {
            scope_digest: self.scope().digest(),
            account_id: payload
                .account_id
                .clone()
                .unwrap_or_else(|| self.scope().account_id.clone()),
            group_id: payload.group_id.clone(),
            destination,
            connection_id: payload.id.clone(),
            service: payload.service.clone(),
            schema_name: payload.schema_name.clone(),
            setup_state: payload.status.setup_state,
            sync_state: payload.status.sync_state,
            update_state: payload.status.update_state,
            latest_success_at: payload.succeeded_at.clone(),
            latest_failure_at: payload.failed_at.clone(),
            rescheduled_for: payload.status.rescheduled_for.clone(),
            connection_revision: payload.revision,
            sync_state_revision: payload.status.state_revision,
            partial: response.partial || payload.partial,
            provenance,
            projection_digest: crate::Digest::pending(),
        };
        projection.projection_digest = crate::Digest::from_serializable(&serde_json::json!([
            &projection.scope_digest,
            &projection.account_id,
            &projection.group_id,
            &projection.destination,
            &projection.connection_id,
            &projection.service,
            &projection.schema_name,
            projection.setup_state,
            projection.sync_state,
            projection.update_state,
            &projection.latest_success_at,
            &projection.latest_failure_at,
            &projection.rescheduled_for,
            projection.connection_revision,
            projection.sync_state_revision,
            projection.partial,
            &projection.provenance,
        ]));
        Ok(projection)
    }

    pub fn read_connection_state(&mut self) -> Result<FivetranConnectionStateProjection> {
        self.ensure_active()?;
        let request = FivetranRequest::connection_state(self.scope())?;
        let response = self.execute(&request)?;
        let payload = match response.payload.as_ref() {
            Some(FivetranResponsePayload::ConnectionState(payload)) => payload,
            _ => return Err(FivetranError::MalformedPayload),
        };
        payload.state_digest.validate()?;
        if payload.state_field_count > crate::MAX_STATE_FIELDS {
            return Err(FivetranError::BoundExceeded {
                field: "connection state fields",
                limit: crate::MAX_STATE_FIELDS,
            });
        }
        if let Some(id) = &payload.id {
            id.validate()?;
        }
        if let Some(group_id) = &payload.group_id {
            group_id.validate()?;
        }
        let destination = self.check_state_scope(payload)?;
        let provenance = self.provenance(&request, &response);
        let mut projection = FivetranConnectionStateProjection {
            scope_digest: self.scope().digest(),
            connection_id: payload
                .id
                .clone()
                .unwrap_or_else(|| self.scope().connection_id.clone()),
            group_id: payload
                .group_id
                .clone()
                .unwrap_or_else(|| self.scope().group_id.clone()),
            destination,
            setup_state: payload.status.as_ref().map(|status| status.setup_state),
            sync_state: payload.status.as_ref().map(|status| status.sync_state),
            update_state: payload.status.as_ref().map(|status| status.update_state),
            latest_success_at: payload.succeeded_at.clone(),
            latest_failure_at: payload.failed_at.clone(),
            sync_state_revision: payload.status.as_ref().map_or(payload.revision, |status| {
                status.state_revision.max(payload.revision)
            }),
            state_digest: payload.state_digest.clone(),
            state_field_count: payload.state_field_count,
            partial: response.partial || payload.partial,
            provenance,
            projection_digest: crate::Digest::pending(),
        };
        projection.projection_digest = crate::Digest::from_serializable(&(
            &projection.scope_digest,
            &projection.connection_id,
            &projection.group_id,
            &projection.destination,
            projection.setup_state,
            projection.sync_state,
            projection.update_state,
            &projection.latest_success_at,
            &projection.latest_failure_at,
            projection.sync_state_revision,
            &projection.state_digest,
            projection.state_field_count,
            projection.partial,
            &projection.provenance,
        ));
        Ok(projection)
    }

    pub fn list_connections_bounded(
        &mut self,
        request: &ConnectionListRequest,
    ) -> Result<ConnectionListProjection> {
        self.ensure_active()?;
        request.validate()?;
        let mut cursor = request.cursor.clone();
        let mut seen_cursors = BTreeSet::new();
        if let Some(initial) = &cursor {
            seen_cursors.insert(initial.clone());
        }
        let mut items = Vec::new();
        let mut pages_read = 0_usize;
        let mut partial = false;
        let mut response_digests = Vec::new();
        let mut provenance_mode = self.transport.mode();

        loop {
            if pages_read >= request.max_pages || pages_read >= MAX_PAGES {
                return Err(FivetranError::PaginationExceeded);
            }
            let mut page_request = request.clone();
            page_request.cursor.clone_from(&cursor);
            let transport_request = FivetranRequest::list(self.scope(), &page_request)?;
            let response = self.execute(&transport_request)?;
            let payload = match response.payload.as_ref() {
                Some(FivetranResponsePayload::ConnectionList(payload)) => payload,
                _ => return Err(FivetranError::MalformedPayload),
            };
            if payload.items.len() > request.limit || payload.items.len() > MAX_PAGE_ITEMS {
                return Err(FivetranError::BoundExceeded {
                    field: "connection list items",
                    limit: request.limit.min(MAX_PAGE_ITEMS),
                });
            }
            response_digests.push(response.response_digest.clone());
            partial |= response.partial || payload.partial;
            for item in &payload.items {
                self.validate_summary_scope(item, request)?;
                let destination =
                    self.destination_from(item.destination_id.as_ref(), None, false)?;
                items.push(ConnectionListItemProjection {
                    scope_digest: self.scope().digest(),
                    id: item.id.clone(),
                    service: item.service.clone(),
                    schema_name: item.schema_name.clone(),
                    group_id: item.group_id.clone(),
                    destination,
                    setup_state: item.status.setup_state,
                    sync_state: item.status.sync_state,
                    update_state: item.status.update_state,
                    latest_success_at: item.succeeded_at.clone(),
                    latest_failure_at: item.failed_at.clone(),
                    revision: item.revision,
                    partial: item.partial || response.partial,
                });
            }
            pages_read += 1;
            let next_cursor = payload.next_cursor.clone();
            match &next_cursor {
                None => break,
                Some(next) => {
                    if next.len() > crate::MAX_CURSOR_BYTES || next.is_empty() {
                        return Err(FivetranError::BoundExceeded {
                            field: "cursor",
                            limit: crate::MAX_CURSOR_BYTES,
                        });
                    }
                    if !seen_cursors.insert(next.clone()) {
                        return Err(FivetranError::CursorRepeated);
                    }
                    cursor = Some(next.clone());
                }
            }
            provenance_mode = self.transport.mode();
        }

        let request_digest =
            crate::Digest::from_serializable(&(self.scope().digest(), request, pages_read));
        let response_digest = crate::Digest::from_serializable(&response_digests);
        let provenance =
            FivetranProvenance::for_mode(provenance_mode, request_digest, response_digest);
        let mut projection = ConnectionListProjection {
            scope_digest: self.scope().digest(),
            items,
            pages_read,
            next_cursor: None,
            partial,
            provenance,
            projection_digest: crate::Digest::pending(),
        };
        projection.projection_digest = crate::Digest::from_serializable(&(
            &projection.scope_digest,
            &projection.items,
            projection.pages_read,
            &projection.next_cursor,
            projection.partial,
            &projection.provenance,
        ));
        Ok(projection)
    }

    pub fn read_schema_table_metadata(&mut self) -> Result<FivetranSchemaTableProjection> {
        self.ensure_active()?;
        let request = FivetranRequest::schemas(self.scope())?;
        let response = self.execute(&request)?;
        let payload = match response.payload.as_ref() {
            Some(FivetranResponsePayload::Schemas(payload)) => payload,
            _ => return Err(FivetranError::MalformedPayload),
        };
        payload.validate_bounds()?;
        let schema = payload
            .schemas
            .iter()
            .find(|schema| schema.name == self.scope().schema_name)
            .ok_or(if response.partial || payload.partial {
                FivetranError::PartialPayload
            } else {
                FivetranError::SchemaDrift
            })?;
        let table = schema
            .tables
            .iter()
            .find(|table| table.name == self.scope().table_name)
            .ok_or(if response.partial || payload.partial {
                FivetranError::PartialPayload
            } else {
                FivetranError::TableDrift
            })?;
        let table_count = payload.schemas.iter().map(|item| item.tables.len()).sum();
        let column_count = payload
            .schemas
            .iter()
            .flat_map(|item| &item.tables)
            .map(|item| item.columns.len())
            .sum();
        let schema_fingerprint = crate::Digest::from_serializable(schema);
        let table_fingerprint = crate::Digest::from_serializable(table);
        let provenance = self.provenance(&request, &response);
        let mut projection = FivetranSchemaTableProjection {
            scope_digest: self.scope().digest(),
            connection_id: self.scope().connection_id.clone(),
            schema_name: schema.name.clone(),
            table_name: table.name.clone(),
            schema_fingerprint,
            table_fingerprint,
            schema_status: None,
            schema_count: payload.schemas.len(),
            table_count,
            column_count,
            partial: response.partial || payload.partial,
            provenance,
            projection_digest: crate::Digest::pending(),
        };
        projection.projection_digest = crate::Digest::from_serializable(&(
            &projection.scope_digest,
            &projection.connection_id,
            &projection.schema_name,
            &projection.table_name,
            &projection.schema_fingerprint,
            &projection.table_fingerprint,
            &projection.schema_status,
            projection.schema_count,
            projection.table_count,
            projection.column_count,
            projection.partial,
            &projection.provenance,
        ));
        Ok(projection)
    }

    pub fn read_sync_evidence(&mut self) -> Result<FivetranSyncEvidence> {
        self.ensure_active()?;
        let connection = self.describe_connection()?;
        let state = self.read_connection_state()?;
        if connection.connection_id != state.connection_id {
            return Err(FivetranError::ConnectionDrift);
        }
        if connection.group_id != state.group_id
            || connection.destination.destination_id != state.destination.destination_id
            || connection.destination.group_id != state.destination.group_id
        {
            return Err(FivetranError::DestinationDrift);
        }
        if connection.sync_state_revision == state.sync_state_revision
            && state
                .sync_state
                .is_some_and(|sync_state| sync_state != connection.sync_state)
        {
            return Err(FivetranError::ConnectionDrift);
        }
        let schema_table = self.read_schema_table_metadata()?;
        let setup_state = state.setup_state.unwrap_or(connection.setup_state);
        let sync_state = state.sync_state.unwrap_or(connection.sync_state);
        let update_state = state.update_state.unwrap_or(connection.update_state);
        let sync_revision = connection
            .sync_state_revision
            .max(state.sync_state_revision)
            .max(self.scope().sync_revision);
        self.observe_sync_state(sync_revision, sync_state)?;
        let partial = connection.partial || state.partial || schema_table.partial;
        let result_state = if partial {
            FivetranResultState::Partial
        } else {
            result_state(setup_state, sync_state, update_state)
        };
        let provenance = FivetranProvenance::for_mode(
            self.transport.mode(),
            crate::Digest::from_serializable(&(
                &connection.provenance.request_digest,
                &state.provenance.request_digest,
                &schema_table.provenance.request_digest,
            )),
            crate::Digest::from_serializable(&(
                &connection.provenance.response_digest,
                &state.provenance.response_digest,
                &schema_table.provenance.response_digest,
            )),
        );
        let mut evidence = FivetranSyncEvidence {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            scope: self.scope().clone(),
            scope_digest: self.scope().digest(),
            account_id: connection.account_id,
            group_id: connection.group_id,
            destination: connection.destination,
            connection_id: connection.connection_id,
            sync_id: self.scope().sync_id.clone(),
            schema_name: schema_table.schema_name,
            table_name: schema_table.table_name,
            setup_state,
            sync_state,
            update_state,
            result_state,
            latest_success_at: connection.latest_success_at.or(state.latest_success_at),
            latest_failure_at: connection.latest_failure_at.or(state.latest_failure_at),
            schema_fingerprint: schema_table.schema_fingerprint,
            table_fingerprint: schema_table.table_fingerprint,
            connection_revision: connection.connection_revision,
            schema_revision: self.scope().schema_revision,
            sync_state_revision: sync_revision,
            mission_revision: self.scope().mission_revision,
            partial,
            provenance,
            evidence_digest: crate::Digest::pending(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn compile_sync_result_proposal(
        &self,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncResultProposal> {
        self.ensure_active()?;
        self.validate_evidence_binding(evidence)?;
        Ok(FivetranSyncResultProposal::from_evidence(evidence))
    }

    pub fn record_sync_projection(
        &mut self,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncRecording> {
        self.ensure_active()?;
        self.validate_evidence_binding(evidence)?;
        if !self
            .recorded_evidence
            .insert(evidence.evidence_digest.clone())
        {
            return Err(FivetranError::ReplayDetected {
                subject: "sync evidence",
            });
        }
        Ok(FivetranSyncRecording::from_evidence(evidence))
    }

    pub fn verify_sync_result(
        &self,
        proposal: &FivetranSyncResultProposal,
        evidence: &FivetranSyncEvidence,
    ) -> Result<FivetranSyncResultProposal> {
        self.ensure_active()?;
        self.validate_evidence_binding(evidence)?;
        proposal.validate(evidence)?;
        Ok(proposal.clone())
    }

    pub fn verify_sync_result_report(
        &self,
        proposal: &FivetranSyncResultProposal,
        evidence: &FivetranSyncEvidence,
    ) -> VerificationReport {
        match self.verify_sync_result(proposal, evidence) {
            Ok(verified) => VerificationReport::success(evidence, &verified),
            Err(error) => VerificationReport {
                verified: false,
                failures: vec![error.to_string()],
                evidence_digest: evidence.evidence_digest.clone(),
                proposal_digest: proposal.proposal_digest.clone(),
            },
        }
    }

    fn ensure_active(&self) -> Result<()> {
        if self.registration.status != RegistrationStatus::Active {
            if matches!(
                self.registration.status,
                RegistrationStatus::Revoked | RegistrationStatus::Reversed
            ) {
                return Err(FivetranError::RegistrationRevoked);
            }
            return Err(FivetranError::RegistrationNotActive);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(FivetranError::RegistrationRevoked);
        }
        Ok(())
    }

    fn execute(&mut self, request: &FivetranRequest) -> Result<FivetranHttpResponse> {
        let response = self
            .transport
            .execute(request)
            .map_err(|error| match error {
                FivetranTransportError::BlockedEnv => FivetranError::BlockedEnv,
                FivetranTransportError::Timeout => {
                    self.state = FivetranProviderState::Timeout;
                    self.backoff.note_retryable(None);
                    FivetranError::Timeout
                }
                FivetranTransportError::MalformedResponse => FivetranError::MalformedPayload,
                FivetranTransportError::Other(message) => FivetranError::Transport(message),
            })?;
        if response.endpoint != request.endpoint {
            return Err(FivetranError::EndpointMismatch);
        }
        response.validate()?;
        match response.status {
            200..=299 => {
                if response.payload.is_none() {
                    return Err(FivetranError::MalformedPayload);
                }
                self.backoff.reset();
                Ok(response)
            }
            401 => {
                self.state = FivetranProviderState::Unauthorized;
                Err(FivetranError::Unauthorized)
            }
            403 => {
                self.state = FivetranProviderState::Forbidden;
                Err(FivetranError::Forbidden)
            }
            404 => {
                self.state = FivetranProviderState::NotFound;
                Err(FivetranError::NotFound)
            }
            408 | 504 => {
                self.state = FivetranProviderState::Timeout;
                self.backoff.note_retryable(response.retry_after_seconds);
                Err(FivetranError::Timeout)
            }
            409 => {
                self.state = FivetranProviderState::Conflict;
                Err(FivetranError::Conflict)
            }
            429 => {
                self.state = FivetranProviderState::RateLimited;
                self.backoff.note_retryable(response.retry_after_seconds);
                Err(FivetranError::RateLimited {
                    retry_after_seconds: response.retry_after_seconds,
                })
            }
            500..=599 => {
                self.state = FivetranProviderState::ServerFailure;
                self.backoff.note_retryable(response.retry_after_seconds);
                Err(FivetranError::ServerFailure {
                    status: response.status,
                })
            }
            _ => {
                self.state = FivetranProviderState::ProviderUnknown;
                Err(FivetranError::Transport(format!(
                    "unexpected Fivetran HTTP status {}",
                    response.status
                )))
            }
        }
    }

    fn provenance(
        &self,
        request: &FivetranRequest,
        response: &FivetranHttpResponse,
    ) -> FivetranProvenance {
        FivetranProvenance::for_mode(
            self.transport.mode(),
            request.request_digest.clone(),
            response.response_digest.clone(),
        )
    }

    fn check_connection_scope(
        &self,
        payload: &FivetranConnectionPayload,
    ) -> Result<DestinationIdentityProjection> {
        if payload.id != self.scope().connection_id {
            return Err(FivetranError::ConnectionDrift);
        }
        if payload.group_id != self.scope().group_id {
            return Err(FivetranError::GroupDrift);
        }
        if payload.schema_name != self.scope().schema_name {
            return Err(FivetranError::SchemaDrift);
        }
        if let Some(account_id) = &payload.account_id
            && account_id != &self.scope().account_id
        {
            return Err(FivetranError::AccountDrift);
        }
        self.destination_from(
            payload.destination_id.as_ref(),
            payload.destination_group_id.as_ref(),
            payload.destination_id.is_some(),
        )
    }

    fn check_state_scope(
        &self,
        payload: &FivetranConnectionStatePayload,
    ) -> Result<DestinationIdentityProjection> {
        if let Some(id) = &payload.id
            && id != &self.scope().connection_id
        {
            return Err(FivetranError::ConnectionDrift);
        }
        if let Some(group_id) = &payload.group_id
            && group_id != &self.scope().group_id
        {
            return Err(FivetranError::GroupDrift);
        }
        self.destination_from(
            payload.destination_id.as_ref(),
            None,
            payload.destination_id.is_some(),
        )
    }

    fn destination_from(
        &self,
        destination_id: Option<&crate::FivetranDestinationId>,
        destination_group_id: Option<&crate::FivetranDestinationId>,
        provider_reported: bool,
    ) -> Result<DestinationIdentityProjection> {
        if let Some(destination_id) = destination_id
            && destination_id != &self.scope().destination_id
        {
            return Err(FivetranError::DestinationDrift);
        }
        if let Some(destination_group_id) = destination_group_id
            && destination_group_id.as_str() != self.scope().destination_id.as_str()
            && destination_group_id.as_str() != self.scope().group_id.as_str()
        {
            return Err(FivetranError::DestinationDrift);
        }
        DestinationIdentityProjection::new(
            self.scope().destination_id.clone(),
            self.scope().group_id.clone(),
            None,
            provider_reported,
        )
    }

    fn validate_summary_scope(
        &self,
        item: &crate::model::FivetranConnectionSummary,
        request: &ConnectionListRequest,
    ) -> Result<()> {
        item.id.validate()?;
        item.group_id.validate()?;
        item.schema_name.validate()?;
        if item.group_id != request.group_id || item.schema_name != request.schema_name {
            return Err(FivetranError::PaginationScopeDrift);
        }
        if let Some(destination_id) = &item.destination_id
            && destination_id != &self.scope().destination_id
        {
            return Err(FivetranError::DestinationDrift);
        }
        Ok(())
    }

    fn observe_sync_state(&mut self, revision: u64, state: SyncState) -> Result<()> {
        if let Some(previous) = self.last_sync_revision {
            if revision < previous {
                return Err(FivetranError::NonMonotonicSyncState {
                    previous,
                    observed: revision,
                });
            }
            if revision == previous && self.last_sync_state != Some(state) {
                return Err(FivetranError::ReplayDetected {
                    subject: "same-revision sync state",
                });
            }
        }
        self.last_sync_revision = Some(revision);
        self.last_sync_state = Some(state);
        Ok(())
    }

    fn validate_evidence_binding(&self, evidence: &FivetranSyncEvidence) -> Result<()> {
        evidence.validate()?;
        if evidence.scope_digest != self.scope().digest()
            || evidence.registration_digest != self.registration.registration_digest
        {
            return Err(FivetranError::TamperDetected {
                subject: "registration or scope binding",
            });
        }
        Ok(())
    }
}

fn result_state(setup: SetupState, sync: SyncState, update: UpdateState) -> FivetranResultState {
    match setup {
        SetupState::Broken => FivetranResultState::Broken,
        SetupState::Incomplete | SetupState::Unknown => FivetranResultState::Incomplete,
        SetupState::Connected => match sync {
            SyncState::Syncing => FivetranResultState::Syncing,
            SyncState::Paused => FivetranResultState::Paused,
            SyncState::Rescheduled => FivetranResultState::Rescheduled,
            SyncState::Scheduled | SyncState::Unknown => match update {
                UpdateState::Delayed => FivetranResultState::Delayed,
                UpdateState::OnSchedule | UpdateState::Unknown => FivetranResultState::Scheduled,
            },
        },
    }
}

#[allow(dead_code)]
fn status_revision(status: &FivetranStatusPayload) -> u64 {
    status.state_revision
}

#[allow(dead_code)]
fn endpoint_for_payload(payload: &FivetranResponsePayload) -> FivetranEndpoint {
    payload.endpoint()
}

#[allow(dead_code)]
fn is_bounded_list(limit: usize) -> bool {
    (1..=MAX_PAGE_ITEMS).contains(&limit) && MAX_PAGES > 0
}

#[allow(dead_code)]
fn _keep_payload_types_linked(_: FivetranConnectionListPayload, _: FivetranConnectionStatePayload) {
}
