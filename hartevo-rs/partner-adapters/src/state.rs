use chrono::{DateTime, Utc};

use crate::callback::{
    CallbackObservation, CallbackRequest, callback_evidence_digest, parse_callback,
    verify_signature,
};
use crate::contract::{
    AuthorizationGrant, AuthorizationObservation, AuthorizationState, NetworkCapability,
    NetworkProvider, NetworkScope, PartnerNetworkError, authorization_observation,
    scope_authorized,
};
use crate::replay::ReplayGuard;

#[derive(Clone, Debug)]
pub(crate) struct AdapterState {
    provider: NetworkProvider,
    grant: Option<AuthorizationGrant>,
    revoked_scopes: Vec<NetworkScope>,
    replay: ReplayGuard,
}

impl AdapterState {
    pub(crate) fn new(provider: NetworkProvider) -> Self {
        Self {
            provider,
            grant: None,
            revoked_scopes: Vec::new(),
            replay: ReplayGuard::default(),
        }
    }

    pub(crate) fn authorize(
        &mut self,
        grant: AuthorizationGrant,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError> {
        grant.validate_at(observed_at)?;
        self.revoked_scopes
            .retain(|revoked| !grant.scope.covers(revoked));
        let observation = authorization_observation(
            self.provider,
            &grant,
            AuthorizationState::Granted,
            observed_at,
        );
        self.grant = Some(grant);
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
            return Ok(AuthorizationObservation {
                provider: self.provider,
                scope: scope.clone(),
                state: AuthorizationState::Revoked,
                provenance: None,
                reference_revision: None,
                observed_at,
                evidence_digest: crate::contract::digest_bytes(digest.as_bytes()),
            });
        };
        if !grant.scope.covers(scope) {
            return Err(PartnerNetworkError::ScopeMismatch);
        }
        if !self.revoked_scopes.iter().any(|revoked| revoked == scope) {
            self.revoked_scopes.push(scope.clone());
        }
        Ok(authorization_observation(
            self.provider,
            grant,
            AuthorizationState::Revoked,
            observed_at,
        ))
    }

    pub(crate) fn callback(
        &mut self,
        request: &CallbackRequest<'_>,
    ) -> Result<CallbackObservation, PartnerNetworkError> {
        let _grant = self.grant_for(
            &request.scope,
            NetworkCapability::OutcomeIngest,
            request.received_at,
        )?;
        verify_signature(
            request.scheme,
            request.signature_key,
            request.body,
            request.signature,
        )?;
        let event = parse_callback(self.provider, request.body)?;
        if request
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
        let evidence_digest =
            callback_evidence_digest(self.provider, request.channel, &event, disposition)?;
        Ok(CallbackObservation {
            provider: self.provider,
            channel: request.channel,
            event,
            disposition,
            signature_verified: true,
            observed_at: request.received_at,
            evidence_digest,
        })
    }

    pub(crate) fn accepted_callbacks(&self) -> Vec<crate::callback::CallbackEvent> {
        self.replay.accepted()
    }
}
