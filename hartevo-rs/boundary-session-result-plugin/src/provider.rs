//! Typed Boundary provider identity and bounded GET reads.
//!
//! The provider has no credential resolver, native HTTP client, mutation
//! method, session connection, or recording download path.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::model::{
    BoundaryHttpResponse, BoundaryModelError, BoundaryReadEvidence, BoundaryReadOperation,
    BoundaryReadRequest, BoundaryResponseBody, BoundaryResponseType, BoundaryScope,
    BoundarySessionMetadata, BoundarySessionResultState, BoundaryTargetMetadata, Digest,
    PermissionSnapshot, SessionId, TransportProvenance,
};
use crate::transport::{BoundaryTransport, BoundaryTransportError};
use crate::{
    BOUNDARY_MAX_PAGES, BOUNDARY_MAX_RESPONSE_BYTES, BOUNDARY_PLUGIN_VERSION,
    BOUNDARY_PROVIDER_API_VERSION, BOUNDARY_PROVIDER_ID, BOUNDARY_PROVIDER_IMPLEMENTATION,
    BOUNDARY_PROVIDER_REVISION, contract_digest, provider_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BoundaryProviderError {
    #[error("Boundary provider model error: {0}")]
    Model(#[from] BoundaryModelError),
    #[error("Boundary provider transport error: {0}")]
    Transport(#[from] BoundaryTransportError),
    #[error("Boundary provider response was too large")]
    ResponseTooLarge,
    #[error("Boundary provider returned an unsupported HTTP status")]
    UnsupportedStatus(u16),
    #[error("Boundary provider response was outside the exact scope: {0}")]
    ScopeMismatch(&'static str),
    #[error("Boundary provider revision drifted")]
    ProviderRevisionDrift,
    #[error("Boundary list-token pagination repeated a token")]
    PaginationLoop,
    #[error("Boundary session lifecycle regressed")]
    LifecycleRegression,
    #[error("Boundary provider returned an unexpected body")]
    MalformedResponse,
    #[error("Boundary provider permission binding is not read-only")]
    PermissionMismatch,
}

impl BoundaryProviderError {
    pub const fn is_access_lost(&self) -> bool {
        matches!(
            self,
            Self::Transport(BoundaryTransportError::HttpStatus(401 | 403 | 404))
        )
    }

    pub const fn is_provider_unknown(&self) -> bool {
        matches!(
            self,
            Self::Transport(
                BoundaryTransportError::BlockedEnv
                    | BoundaryTransportError::Timeout
                    | BoundaryTransportError::TransportUnavailable
                    | BoundaryTransportError::MalformedResponse
                    | BoundaryTransportError::ResponseTooLarge
                    | BoundaryTransportError::InvalidRequest
                    | BoundaryTransportError::HttpStatus(408 | 429 | 500..=599)
            ) | Self::MalformedResponse
                | Self::UnsupportedStatus(_)
        )
    }

    pub const fn is_partial(&self) -> bool {
        matches!(self, Self::PaginationLoop)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryProviderDefinition {
    pub provider_id: String,
    pub implementation: String,
    pub version: String,
    pub api_version: String,
    pub provider_revision: String,
    pub permission_snapshot: PermissionSnapshot,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl BoundaryProviderDefinition {
    pub fn baseline() -> Self {
        let permissions = PermissionSnapshot::read_only();
        Self {
            provider_id: BOUNDARY_PROVIDER_ID.to_owned(),
            implementation: BOUNDARY_PROVIDER_IMPLEMENTATION.to_owned(),
            version: BOUNDARY_PLUGIN_VERSION.to_owned(),
            api_version: BOUNDARY_PROVIDER_API_VERSION.to_owned(),
            provider_revision: BOUNDARY_PROVIDER_REVISION.to_owned(),
            permission_snapshot: permissions,
            provider_digest: provider_digest(),
            api_digest: Digest::from_fields([
                "GET /v1/sessions",
                "GET /v1/sessions/{id}",
                "GET /v1/targets/{id}",
                "include_terminated=true",
                "opaque_list_token_pagination",
            ]),
            native: false,
            connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self) -> Result<(), BoundaryProviderError> {
        if self.provider_id != BOUNDARY_PROVIDER_ID
            || self.implementation != BOUNDARY_PROVIDER_IMPLEMENTATION
            || self.version != BOUNDARY_PLUGIN_VERSION
            || self.api_version != BOUNDARY_PROVIDER_API_VERSION
            || self.provider_revision != BOUNDARY_PROVIDER_REVISION
            || self.provider_digest != provider_digest()
            || !self.permission_snapshot.is_exact_read_only()
            || self.native
            || self.connected
            || self.first_party
        {
            return Err(BoundaryProviderError::ProviderRevisionDrift);
        }
        Ok(())
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }
}

pub struct BoundaryProvider<T> {
    transport: T,
    definition: BoundaryProviderDefinition,
    lifecycle: BTreeMap<SessionId, BoundarySessionResultState>,
}

impl<T: BoundaryTransport + fmt::Debug> fmt::Debug for BoundaryProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .field("tracked_sessions", &self.lifecycle.len())
            .finish_non_exhaustive()
    }
}

impl<T: BoundaryTransport> BoundaryProvider<T> {
    pub fn new(transport: T) -> Result<Self, BoundaryProviderError> {
        let definition = BoundaryProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            lifecycle: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &BoundaryProviderDefinition {
        &self.definition
    }

    pub fn definition_mut(&mut self) -> &mut BoundaryProviderDefinition {
        &mut self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest.clone()
    }

    pub fn provider_revision(&self) -> &str {
        &self.definition.provider_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        self.definition.permission_digest()
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_sessions(
        &mut self,
        scope: &BoundaryScope,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundaryReadEvidence, BoundaryProviderError> {
        self.ensure_scope(scope, crate::model::BoundaryPermission::SessionList)?;
        let mut list_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut sessions = Vec::new();
        let mut list_token_digests = Vec::new();
        let mut removed_id_digests = Vec::new();
        let mut request_digests = Vec::new();
        let mut response_digests = Vec::new();
        let mut page_count = 0_u16;
        let mut partial = false;

        loop {
            let request = BoundaryReadRequest::list(
                scope,
                crate::BOUNDARY_DEFAULT_PAGE_SIZE,
                list_token.clone(),
            )?;
            let request_digest = request.request_digest(scope);
            let response = self.get(&request)?;
            request_digests.push(request_digest);
            response_digests.push(response.response_digest.clone());
            page_count = page_count.saturating_add(1);
            let (page_sessions, next_token, response_type, removed) =
                Self::validate_list_response(response)?;
            for session in page_sessions {
                self.validate_session(scope, &session, observed_at)?;
                sessions.push(session);
            }
            if sessions.len() > crate::BOUNDARY_MAX_SESSIONS_TOTAL {
                return Err(BoundaryProviderError::Model(BoundaryModelError::TooMany {
                    field: "sessions",
                }));
            }
            removed_id_digests.extend(removed);
            if removed_id_digests.len() > crate::BOUNDARY_MAX_SESSIONS_TOTAL {
                return Err(BoundaryProviderError::Model(BoundaryModelError::TooMany {
                    field: "removed session identifiers",
                }));
            }
            let Some(next_token) = next_token else {
                if response_type == BoundaryResponseType::Delta {
                    partial = true;
                }
                break;
            };
            if !seen_tokens.insert(next_token.digest().clone()) {
                return Err(BoundaryProviderError::PaginationLoop);
            }
            list_token_digests.push(next_token.digest().clone());
            if page_count >= BOUNDARY_MAX_PAGES {
                partial = true;
                break;
            }
            list_token = Some(next_token);
        }

        if sessions.is_empty() {
            return Err(BoundaryProviderError::ScopeMismatch(
                "exact session was not present in the bounded list",
            ));
        }
        Ok(BoundaryReadEvidence::success(
            BoundaryReadOperation::ListSessions,
            sessions,
            None,
            page_count,
            request_digests.len() as u16,
            partial,
            list_token_digests,
            removed_id_digests,
            request_digests,
            response_digests,
            scope.scope_digest().clone(),
            scope.permission_digest().clone(),
            self.provider_digest(),
            self.provider_revision().to_owned(),
            contract_digest(),
            self.provenance(),
            observed_at,
        ))
    }

    pub fn read_session(
        &mut self,
        scope: &BoundaryScope,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundaryReadEvidence, BoundaryProviderError> {
        self.ensure_scope(scope, crate::model::BoundaryPermission::SessionRead)?;
        let request = BoundaryReadRequest::session(scope);
        let request_digest = request.request_digest(scope);
        let response = self.get(&request)?;
        let response_digest = response.response_digest.clone();
        let session = match response.body {
            BoundaryResponseBody::Session(session) => session,
            _ => return Err(BoundaryProviderError::MalformedResponse),
        };
        self.validate_session(scope, &session, observed_at)?;
        Ok(BoundaryReadEvidence::success(
            BoundaryReadOperation::ReadSession,
            vec![session],
            None,
            1,
            1,
            false,
            Vec::new(),
            Vec::new(),
            vec![request_digest],
            vec![response_digest],
            scope.scope_digest().clone(),
            scope.permission_digest().clone(),
            self.provider_digest(),
            self.provider_revision().to_owned(),
            contract_digest(),
            self.provenance(),
            observed_at,
        ))
    }

    pub fn read_target(
        &mut self,
        scope: &BoundaryScope,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundaryReadEvidence, BoundaryProviderError> {
        self.ensure_scope(scope, crate::model::BoundaryPermission::TargetRead)?;
        let request = BoundaryReadRequest::target(scope);
        let request_digest = request.request_digest(scope);
        let response = self.get(&request)?;
        let response_digest = response.response_digest.clone();
        let target = match response.body {
            BoundaryResponseBody::Target(target) => target,
            _ => return Err(BoundaryProviderError::MalformedResponse),
        };
        Self::validate_target(scope, &target)?;
        Ok(BoundaryReadEvidence::success(
            BoundaryReadOperation::ReadTarget,
            Vec::new(),
            Some(target),
            1,
            1,
            false,
            Vec::new(),
            Vec::new(),
            vec![request_digest],
            vec![response_digest],
            scope.scope_digest().clone(),
            scope.permission_digest().clone(),
            self.provider_digest(),
            self.provider_revision().to_owned(),
            contract_digest(),
            self.provenance(),
            observed_at,
        ))
    }

    fn ensure_scope(
        &self,
        scope: &BoundaryScope,
        permission: crate::model::BoundaryPermission,
    ) -> Result<(), BoundaryProviderError> {
        scope.validate()?;
        self.definition.validate()?;
        if !self.definition.permission_snapshot.allows(permission)
            || self.definition.permission_digest() != scope.permission_digest()
        {
            return Err(BoundaryProviderError::PermissionMismatch);
        }
        if scope.scope_digest() != &scope.recompute_digest() {
            return Err(BoundaryProviderError::ScopeMismatch(
                "scope digest does not match its fields",
            ));
        }
        Ok(())
    }

    fn get(
        &mut self,
        request: &BoundaryReadRequest,
    ) -> Result<BoundaryHttpResponse, BoundaryProviderError> {
        let response = self.transport.get(request)?;
        if response.response_bytes > BOUNDARY_MAX_RESPONSE_BYTES {
            return Err(BoundaryProviderError::ResponseTooLarge);
        }
        match response.status {
            200 => Ok(response),
            401 | 403 | 404 => Err(BoundaryProviderError::Transport(
                BoundaryTransportError::HttpStatus(response.status),
            )),
            status => Err(BoundaryProviderError::UnsupportedStatus(status)),
        }
    }

    fn validate_list_response(
        response: BoundaryHttpResponse,
    ) -> Result<
        (
            Vec<BoundarySessionMetadata>,
            Option<crate::model::OpaqueListToken>,
            BoundaryResponseType,
            Vec<Digest>,
        ),
        BoundaryProviderError,
    > {
        if let BoundaryResponseBody::SessionList {
            sessions,
            next_list_token,
            response_type,
            estimated_item_count: _,
            removed_id_digests,
        } = response.body
        {
            Ok((sessions, next_list_token, response_type, removed_id_digests))
        } else {
            Err(BoundaryProviderError::MalformedResponse)
        }
    }

    fn validate_session(
        &mut self,
        scope: &BoundaryScope,
        session: &BoundarySessionMetadata,
        _observed_at: DateTime<Utc>,
    ) -> Result<(), BoundaryProviderError> {
        session.validate_integrity()?;
        if session.id != scope.session.id {
            return Err(BoundaryProviderError::ScopeMismatch("session id"));
        }
        if session.target_id != scope.target.id {
            return Err(BoundaryProviderError::ScopeMismatch("target id"));
        }
        if session.scope_id != scope.scope.id {
            return Err(BoundaryProviderError::ScopeMismatch("scope id"));
        }
        if session.revision != scope.session.revision {
            return Err(BoundaryProviderError::ScopeMismatch("session revision"));
        }
        if session
            .host_id
            .as_ref()
            .is_some_and(|id| id != &scope.host.id)
            || session
                .organization_id
                .as_ref()
                .is_some_and(|id| id != &scope.organization.id)
            || session
                .project_id
                .as_ref()
                .is_some_and(|id| id != &scope.project.id)
            || session
                .auth_method_id
                .as_ref()
                .is_some_and(|id| id != &scope.auth_method.id)
            || session
                .account_id
                .as_ref()
                .is_some_and(|id| id != &scope.account.id)
            || session
                .principal_digest
                .as_ref()
                .is_some_and(|digest| digest != &scope.principal_digest)
        {
            return Err(BoundaryProviderError::ScopeMismatch(
                "host, organization, project, auth method, account, or principal",
            ));
        }
        if let Some(previous) = self.lifecycle.get(&session.id).copied()
            && BoundarySessionResultState::lifecycle_regression(previous, session.state)
        {
            return Err(BoundaryProviderError::LifecycleRegression);
        }
        self.lifecycle.insert(session.id.clone(), session.state);
        Ok(())
    }

    fn validate_target(
        scope: &BoundaryScope,
        target: &BoundaryTargetMetadata,
    ) -> Result<(), BoundaryProviderError> {
        target.validate_integrity()?;
        if target.id != scope.target.id {
            return Err(BoundaryProviderError::ScopeMismatch("target id"));
        }
        if target.scope_id != scope.scope.id {
            return Err(BoundaryProviderError::ScopeMismatch("target scope id"));
        }
        if target.revision != scope.target.revision {
            return Err(BoundaryProviderError::ScopeMismatch("target revision"));
        }
        if target
            .organization_id
            .as_ref()
            .is_some_and(|id| id != &scope.organization.id)
            || target
                .project_id
                .as_ref()
                .is_some_and(|id| id != &scope.project.id)
        {
            return Err(BoundaryProviderError::ScopeMismatch(
                "target organization or project",
            ));
        }
        Ok(())
    }
}
