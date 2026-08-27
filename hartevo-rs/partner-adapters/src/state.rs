use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::callback::{
    CallbackObservation, CallbackRequest, callback_evidence_digest_with_authority, parse_callback,
    verify_signature,
};
use crate::contract::{
    AuthorizationGrant, AuthorizationObservation, AuthorizationState, NetworkCapability,
    NetworkProvider, NetworkScope, PartnerNetworkError, authorization_observation, is_sha256,
    scope_authorized,
};
use crate::replay::ReplayGuard;

const DURABLE_STATE_SCHEMA: &str = "hartevo-partner-adapter-state/v1";
const MAX_DURABLE_RECEIPTS: usize = 1_024;
const DURABLE_RECEIPT_WINDOW: Duration = Duration::days(7);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableReceipt {
    pub kind: String,
    pub scope_digest: String,
    pub reference_revision: Option<u64>,
    pub event_digest: String,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedAdapterState {
    schema_version: String,
    provider: NetworkProvider,
    grant: Option<AuthorizationGrant>,
    revoked_scopes: Vec<NetworkScope>,
    replay: ReplayGuard,
    receipts: Vec<DurableReceipt>,
    generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStateStore {
    path: PathBuf,
}

impl DurableStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(
        &self,
        provider: NetworkProvider,
    ) -> Result<Option<PersistedAdapterState>, PartnerNetworkError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(PartnerNetworkError::DurabilityUnavailable),
        };
        let state = serde_json::from_slice::<PersistedAdapterState>(&bytes)
            .map_err(|_| PartnerNetworkError::DurabilityUnavailable)?;
        if state.schema_version != DURABLE_STATE_SCHEMA || state.provider != provider {
            return Err(PartnerNetworkError::DurabilityUnavailable);
        }
        state.replay.validate()?;
        if state.receipts.len() > MAX_DURABLE_RECEIPTS
            || state.receipts.iter().any(|receipt| {
                !is_sha256(&receipt.scope_digest)
                    || !is_sha256(&receipt.event_digest)
                    || !is_sha256(&receipt.evidence_digest)
            })
        {
            return Err(PartnerNetworkError::DurabilityUnavailable);
        }
        Ok(Some(state))
    }

    fn save(&self, state: &PersistedAdapterState) -> Result<(), PartnerNetworkError> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            return Err(PartnerNetworkError::DurabilityUnavailable);
        }
        let bytes =
            serde_json::to_vec(state).map_err(|_| PartnerNetworkError::DurabilityUnavailable)?;
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, bytes)
            .map_err(|_| PartnerNetworkError::DurabilityUnavailable)?;
        std::fs::rename(&temporary, &self.path)
            .map_err(|_| PartnerNetworkError::DurabilityUnavailable)
    }

    fn clear(&self) -> Result<(), PartnerNetworkError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(PartnerNetworkError::DurabilityUnavailable),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AdapterState {
    provider: NetworkProvider,
    grant: Option<AuthorizationGrant>,
    revoked_scopes: Vec<NetworkScope>,
    replay: ReplayGuard,
    receipts: Arc<Mutex<Vec<DurableReceipt>>>,
    generation: u64,
    store: Option<DurableStateStore>,
}

impl AdapterState {
    pub(crate) fn new(provider: NetworkProvider) -> Self {
        Self {
            provider,
            grant: None,
            revoked_scopes: Vec::new(),
            replay: ReplayGuard::default(),
            receipts: Arc::new(Mutex::new(Vec::new())),
            generation: 1,
            store: None,
        }
    }

    pub(crate) fn with_state_file(
        provider: NetworkProvider,
        path: impl Into<PathBuf>,
    ) -> Result<Self, PartnerNetworkError> {
        let store = DurableStateStore::new(path);
        let mut state = Self::new(provider);
        if let Some(persisted) = store.load(provider)? {
            state.grant = persisted.grant;
            state.revoked_scopes = persisted.revoked_scopes;
            state.replay = persisted.replay;
            state.receipts = Arc::new(Mutex::new(persisted.receipts));
            state.generation = persisted.generation.max(1);
        }
        state.store = Some(store);
        Ok(state)
    }

    fn persisted(&self) -> Result<PersistedAdapterState, PartnerNetworkError> {
        let receipts = self
            .receipts
            .lock()
            .map_err(|_| PartnerNetworkError::DurabilityUnavailable)?
            .clone();
        Ok(PersistedAdapterState {
            schema_version: DURABLE_STATE_SCHEMA.into(),
            provider: self.provider,
            grant: self.grant.clone(),
            revoked_scopes: self.revoked_scopes.clone(),
            replay: self.replay.clone(),
            receipts,
            generation: self.generation,
        })
    }

    fn persist(&self) -> Result<(), PartnerNetworkError> {
        if let Some(store) = &self.store {
            store.save(&self.persisted()?)?;
        }
        Ok(())
    }

    fn receipt(
        &self,
        kind: &str,
        scope: &NetworkScope,
        reference_revision: Option<u64>,
        event_digest: String,
        observed_at: DateTime<Utc>,
        evidence_digest: String,
    ) -> Result<(), PartnerNetworkError> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| PartnerNetworkError::DurabilityUnavailable)?;
        let cutoff = observed_at - DURABLE_RECEIPT_WINDOW;
        receipts.retain(|receipt| receipt.observed_at >= cutoff);
        receipts.push(DurableReceipt {
            kind: kind.into(),
            scope_digest: scope.digest(),
            reference_revision,
            event_digest,
            observed_at,
            evidence_digest,
        });
        if receipts.len() > MAX_DURABLE_RECEIPTS {
            let remove = receipts.len() - MAX_DURABLE_RECEIPTS;
            receipts.drain(..remove);
        }
        Ok(())
    }

    pub(crate) fn durable_receipts(&self) -> Vec<DurableReceipt> {
        self.receipts
            .lock()
            .map_or_else(|_| Vec::new(), |receipts| receipts.clone())
    }

    pub(crate) fn record_read_receipt(
        &self,
        scope: &NetworkScope,
        reference_revision: u64,
        event_digest: String,
        observed_at: DateTime<Utc>,
        evidence_digest: String,
    ) -> Result<(), PartnerNetworkError> {
        self.receipt(
            "read.budget",
            scope,
            Some(reference_revision),
            event_digest,
            observed_at,
            evidence_digest,
        )?;
        self.persist()
    }

    pub(crate) fn authorize(
        &mut self,
        grant: AuthorizationGrant,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError> {
        if grant.provenance() == crate::NetworkProvenance::ProductionProvider
            && grant
                .native_canary()
                .is_none_or(|receipt| !receipt.is_attested())
        {
            return Err(PartnerNetworkError::BlockedEnv {
                provider: self.provider,
                reason: crate::BlockedEnvironmentReason::OfficialApiCapabilityNotEnabled,
            });
        }
        grant.validate_at(observed_at)?;
        let rotated = self.grant.as_ref().is_some_and(|previous| {
            previous.secret_reference.reference_id() != grant.secret_reference.reference_id()
                || previous.secret_reference.revision() != grant.secret_reference.revision()
        });
        self.revoked_scopes
            .retain(|revoked| !grant.scope.covers(revoked));
        if rotated {
            self.replay.reset();
        }
        self.generation = self.generation.saturating_add(1);
        let observation = authorization_observation(
            self.provider,
            &grant,
            AuthorizationState::Granted,
            observed_at,
        );
        self.grant = Some(grant);
        self.receipt(
            "authorization.granted",
            &observation.scope,
            observation.reference_revision,
            observation.evidence_digest.clone(),
            observed_at,
            observation.evidence_digest.clone(),
        )?;
        self.persist()?;
        Ok(observation)
    }

    pub(crate) fn grant_for(
        &self,
        scope: &NetworkScope,
        capability: NetworkCapability,
        now: DateTime<Utc>,
    ) -> Result<&AuthorizationGrant, PartnerNetworkError> {
        scope_authorized(
            self.provider,
            self.grant.as_ref(),
            &self.revoked_scopes,
            scope,
            capability,
            now,
        )
    }

    pub(crate) fn revoke(
        &mut self,
        scope: &NetworkScope,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError> {
        scope.validate()?;
        let Some(grant) = self.grant.as_ref() else {
            let digest = format!(
                "{}:{}:{:?}:{}",
                self.provider,
                scope.digest(),
                AuthorizationState::Revoked,
                observed_at.to_rfc3339()
            );
            let evidence_digest = crate::contract::digest_bytes(digest.as_bytes());
            let observation = AuthorizationObservation {
                provider: self.provider,
                scope: scope.clone(),
                state: AuthorizationState::Revoked,
                provenance: None,
                reference_revision: None,
                observed_at,
                evidence_digest: evidence_digest.clone(),
            };
            self.replay.reset();
            self.generation = self.generation.saturating_add(1);
            self.receipt(
                "authorization.revoked",
                scope,
                None,
                evidence_digest.clone(),
                observed_at,
                evidence_digest,
            )?;
            self.persist()?;
            return Ok(observation);
        };
        if !grant.scope.covers(scope) {
            return Err(PartnerNetworkError::ScopeMismatch);
        }
        if !self.revoked_scopes.iter().any(|revoked| revoked == scope) {
            self.revoked_scopes.push(scope.clone());
        }
        let observation = authorization_observation(
            self.provider,
            grant,
            AuthorizationState::Revoked,
            observed_at,
        );
        self.replay.reset();
        self.generation = self.generation.saturating_add(1);
        self.receipt(
            "authorization.revoked",
            scope,
            observation.reference_revision,
            observation.evidence_digest.clone(),
            observed_at,
            observation.evidence_digest.clone(),
        )?;
        self.persist()?;
        Ok(observation)
    }

    pub(crate) fn callback(
        &mut self,
        request: &CallbackRequest<'_>,
    ) -> Result<CallbackObservation, PartnerNetworkError> {
        let grant = self.grant_for(
            &request.scope,
            NetworkCapability::OutcomeIngest,
            request.received_at,
        )?;
        let secret_reference_revision = grant.secret_reference.revision();
        let grant_expires_at = grant.expires_at;
        let provenance = grant.provenance();
        let lease_digest = request.signature_key.validate_for(
            self.provider,
            &request.scope,
            provenance,
            request.scheme,
            &grant.secret_reference,
            request.received_at,
        )?;
        verify_signature(
            request.scheme,
            request.signature_key.key(),
            request.body,
            request.signature,
        )?;
        let event = parse_callback(self.provider, request.body)?;
        if event.account_id != request.scope.account_id
            || request
                .scope
                .program_id
                .as_ref()
                .is_some_and(|program_id| program_id != &event.program_id)
        {
            return Err(PartnerNetworkError::CallbackScopeMismatch);
        }
        let disposition = self
            .replay
            .ingest(&request.scope, event.clone(), request.received_at)?;
        let evidence_digest = callback_evidence_digest_with_authority(
            self.provider,
            &request.scope,
            request.channel,
            request.scheme,
            &event,
            disposition,
            secret_reference_revision,
            grant_expires_at,
            lease_digest,
            provenance,
        )?;
        let observation = CallbackObservation {
            provider: self.provider,
            scope: request.scope.clone(),
            channel: request.channel,
            event,
            disposition,
            signature_scheme: request.scheme,
            secret_reference_revision,
            grant_expires_at,
            lease_digest: lease_digest.to_owned(),
            provenance,
            signature_verified: true,
            observed_at: request.received_at,
            evidence_digest,
        };
        self.receipt(
            "callback.delivery",
            &observation.scope,
            Some(secret_reference_revision),
            observation.event.raw_payload_digest.clone(),
            observation.observed_at,
            observation.evidence_digest.clone(),
        )?;
        self.persist()?;
        Ok(observation)
    }

    pub(crate) fn unmount(&mut self) -> Result<(), PartnerNetworkError> {
        self.grant = None;
        self.revoked_scopes.clear();
        self.replay.reset();
        self.receipts
            .lock()
            .map_err(|_| PartnerNetworkError::DurabilityUnavailable)?
            .clear();
        self.generation = self.generation.saturating_add(1);
        if let Some(store) = &self.store {
            store.clear()?;
        }
        Ok(())
    }

    pub(crate) fn accepted_callbacks(&self) -> Vec<crate::callback::CallbackEvent> {
        self.replay.accepted()
    }
}
