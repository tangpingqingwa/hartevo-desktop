use std::{collections::BTreeSet, collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    MIRO_DECISION_RESULT_CONTRACT_JSON, MIRO_DECISION_RESULT_CONTRACT_VERSION,
    MIRO_DECISION_RESULT_PROVIDER_ID, MIRO_DECISION_RESULT_SCHEMA_VERSION,
    model::{
        DecisionBounds, Digest, ItemId, MiroBoardItem, MiroBoardMetadata, MiroDecisionScope,
        ModelError, OpaqueCursor, PermissionFence, ProviderErrorEvidence, ProviderErrorKind,
        ProviderId, Revision, SecretReference,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty, too long, or contains whitespace")]
    InvalidVersion,
    #[error("provider definition claims a Layer-2 capability")]
    UnauthorizedCapability,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MiroBoardProviderDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub implementation_digest: Digest,
    pub provenance: ProviderProvenance,
    pub read_board: bool,
    pub read_allowlisted_items: bool,
    pub live_execution: bool,
    pub native: bool,
    pub first_party: bool,
    pub connected: bool,
    pub mutating_operations: Vec<String>,
}

impl MiroBoardProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty()
            || provider_version.len() > 128
            || provider_version.chars().any(char::is_control)
            || provider_version.chars().any(char::is_whitespace)
        {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        let provider_id = ProviderId::new(MIRO_DECISION_RESULT_PROVIDER_ID)?;
        let contract_digest = Digest::from_text(MIRO_DECISION_RESULT_CONTRACT_JSON);
        let implementation_digest = Digest::from_fields(
            "miro-board-provider-implementation/v1",
            &[
                MIRO_DECISION_RESULT_SCHEMA_VERSION.to_owned(),
                MIRO_DECISION_RESULT_CONTRACT_VERSION.to_owned(),
                provider_id.as_str().to_owned(),
                provider_version.clone(),
                provenance.as_str().to_owned(),
                "GET /v2/boards/{board_id}".to_owned(),
                "GET /v2/boards/{board_id}/items".to_owned(),
                "live_execution=false".to_owned(),
                "mutating_operations=[]".to_owned(),
            ],
        );
        let provider_digest = Digest::from_fields(
            "miro-board-provider-definition/v1",
            &[
                MIRO_DECISION_RESULT_SCHEMA_VERSION.to_owned(),
                MIRO_DECISION_RESULT_CONTRACT_VERSION.to_owned(),
                contract_digest.as_str().to_owned(),
                provider_id.as_str().to_owned(),
                provider_version.clone(),
                implementation_digest.as_str().to_owned(),
                provenance.as_str().to_owned(),
                "read_board=true".to_owned(),
                "read_allowlisted_items=true".to_owned(),
                "live_execution=false".to_owned(),
                "native=false".to_owned(),
                "first_party=false".to_owned(),
                "connected=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: MIRO_DECISION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: MIRO_DECISION_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id,
            provider_version,
            provider_digest,
            implementation_digest,
            provenance,
            read_board: true,
            read_allowlisted_items: true,
            live_execution: false,
            native: false,
            first_party: false,
            connected: false,
            mutating_operations: Vec::new(),
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != MIRO_DECISION_RESULT_SCHEMA_VERSION
            || self.contract_version != MIRO_DECISION_RESULT_CONTRACT_VERSION
            || self.contract_digest != Digest::from_text(MIRO_DECISION_RESULT_CONTRACT_JSON)
            || self.provider_id.as_str() != MIRO_DECISION_RESULT_PROVIDER_ID
            || !self.read_board
            || !self.read_allowlisted_items
            || self.live_execution
            || self.native
            || self.first_party
            || self.connected
            || !self.mutating_operations.is_empty()
        {
            return Err(ProviderDefinitionError::UnauthorizedCapability);
        }
        let expected = Self::new(self.provider_version.clone(), self.provenance)?;
        if self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.implementation_digest != expected.implementation_digest
        {
            return Err(ProviderDefinitionError::UnauthorizedCapability);
        }
        Ok(())
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MiroBoardReadRequest {
    pub team_id: crate::TeamId,
    pub board_id: crate::BoardId,
    pub allowlisted_item_ids: BTreeSet<ItemId>,
    pub bounds: DecisionBounds,
    pub page_number: u8,
    cursor: Option<OpaqueCursor>,
    pub fence: PermissionFence,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub api_version: String,
}

impl fmt::Debug for MiroBoardReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiroBoardReadRequest")
            .field("team_id", &self.team_id)
            .field("board_id", &self.board_id)
            .field("allowlisted_item_ids", &self.allowlisted_item_ids)
            .field("bounds", &self.bounds)
            .field("page_number", &self.page_number)
            .field(
                "cursor_digest",
                &self.cursor.as_ref().map(OpaqueCursor::digest),
            )
            .field("fence", &self.fence)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("api_version", &self.api_version)
            .finish()
    }
}

impl MiroBoardReadRequest {
    pub fn new(
        scope: &MiroDecisionScope,
        secret_reference: &SecretReference,
        bounds: DecisionBounds,
        page_number: u8,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        if secret_reference.scope_digest() != &scope.scope_digest()
            || page_number == 0
            || page_number > bounds.max_pages()
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(Self {
            team_id: scope.team_id().clone(),
            board_id: scope.board_id().clone(),
            allowlisted_item_ids: scope.allowlisted_item_ids().clone(),
            bounds,
            page_number,
            cursor,
            fence: scope.fence(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.credential_revision(),
            api_version: "v2".to_owned(),
        })
    }

    pub fn cursor_digest(&self) -> Option<Digest> {
        self.cursor.as_ref().map(OpaqueCursor::digest)
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn path_and_query(&self) -> String {
        self.items_path_and_query()
    }

    pub fn board_path(&self) -> String {
        format!("/v2/boards/{}", self.board_id.as_str())
    }

    pub fn items_path_and_query(&self) -> String {
        let mut path = format!(
            "/v2/boards/{}/items?limit={}",
            self.board_id.as_str(),
            self.bounds.page_size()
        );
        if self.cursor.is_some() {
            path.push_str("&cursor=<opaque>");
        }
        path
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MiroBoardPage {
    pub board: MiroBoardMetadata,
    pub items: Vec<MiroBoardItem>,
    pub next_cursor_digest: Option<Digest>,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_mission_revision: Revision,
    pub observed_project_revision: Revision,
    pub observed_work_product_revision: Revision,
    pub observed_board_revision: Revision,
    pub observed_credential_revision: Revision,
    pub response_digest: Digest,
    #[serde(skip)]
    next_cursor: Option<OpaqueCursor>,
}

impl MiroBoardPage {
    pub fn new(
        board: MiroBoardMetadata,
        items: Vec<MiroBoardItem>,
        next_cursor: Option<OpaqueCursor>,
        fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        let next_cursor_digest = next_cursor.as_ref().map(OpaqueCursor::digest);
        let response_digest = compute_page_digest(
            &board,
            &items,
            next_cursor_digest.as_ref(),
            &fence,
            observed_credential_revision,
        );
        Self {
            board,
            items,
            next_cursor_digest,
            observed_scope_digest: fence.scope_digest,
            observed_permission_digest: fence.permission_digest,
            observed_consent_digest: fence.consent_digest,
            observed_mission_revision: fence.mission_revision,
            observed_project_revision: fence.project_revision,
            observed_work_product_revision: fence.work_product_revision,
            observed_board_revision: fence.board_revision,
            observed_credential_revision,
            response_digest,
            next_cursor,
        }
    }

    pub fn next_cursor(&self) -> Option<&OpaqueCursor> {
        self.next_cursor.as_ref()
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.board.validate_digest()?;
        for item in &self.items {
            item.validate_digest()?;
        }
        let expected = compute_page_digest(
            &self.board,
            &self.items,
            self.next_cursor_digest.as_ref(),
            &PermissionFence {
                scope_digest: self.observed_scope_digest.clone(),
                permission_digest: self.observed_permission_digest.clone(),
                consent_digest: self.observed_consent_digest.clone(),
                mission_revision: self.observed_mission_revision,
                project_revision: self.observed_project_revision,
                work_product_revision: self.observed_work_product_revision,
                board_revision: self.observed_board_revision,
            },
            self.observed_credential_revision,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

fn compute_page_digest(
    board: &MiroBoardMetadata,
    items: &[MiroBoardItem],
    next_cursor_digest: Option<&Digest>,
    fence: &PermissionFence,
    observed_credential_revision: Revision,
) -> Digest {
    Digest::from_fields(
        "miro-board-page/v1",
        &[
            board.board_digest.as_str().to_owned(),
            crate::model::canonical_item_set_digest(items)
                .as_str()
                .to_owned(),
            next_cursor_digest
                .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            fence.scope_digest.as_str().to_owned(),
            fence.permission_digest.as_str().to_owned(),
            fence.consent_digest.as_str().to_owned(),
            fence.mission_revision.get().to_string(),
            fence.project_revision.get().to_string(),
            fence.work_product_revision.get().to_string(),
            fence.board_revision.get().to_string(),
            observed_credential_revision.get().to_string(),
        ],
    )
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Miro board provider transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        let blocked_env = kind == ProviderErrorKind::BlockedEnv;
        Self {
            kind,
            status_code,
            retryable,
            blocked_env,
            diagnostic_digest: Digest::from_bytes(diagnostic.as_ref()),
        }
    }

    pub fn unsupported_item() -> Self {
        Self::new(ProviderErrorKind::UnsupportedItem, None, "unsupported-item")
    }

    pub fn deleted() -> Self {
        Self::new(ProviderErrorKind::Deleted, Some(404), "deleted")
    }

    pub fn access_lost() -> Self {
        Self::new(ProviderErrorKind::AccessLost, Some(403), "access-lost")
    }

    pub fn empty() -> Self {
        Self::new(ProviderErrorKind::Empty, Some(200), "empty")
    }

    pub fn partial() -> Self {
        Self::new(ProviderErrorKind::Partial, Some(206), "partial")
    }

    pub fn rate_limited() -> Self {
        Self::new(ProviderErrorKind::RateLimited, Some(429), "rate-limited")
    }

    pub fn server_failure(status_code: u16) -> Self {
        Self::new(
            ProviderErrorKind::ServerFailure,
            Some(status_code),
            "server-failure",
        )
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn scope_drift() -> Self {
        Self::new(ProviderErrorKind::ScopeDrift, None, "scope-drift")
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence::new(
            self.kind,
            self.status_code,
            self.retryable,
            self.blocked_env,
            self.diagnostic_digest.as_str(),
        )
    }
}

pub trait MiroBoardProvider: fmt::Debug {
    fn definition(&self) -> &MiroBoardProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn read_board_page(
        &mut self,
        request: &MiroBoardReadRequest,
    ) -> Result<MiroBoardPage, TransportError>;

    fn read(&mut self, request: &MiroBoardReadRequest) -> Result<MiroBoardPage, TransportError> {
        self.read_board_page(request)
    }
}

pub trait MiroBoardTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn read_board_page(
        &mut self,
        request: &MiroBoardReadRequest,
    ) -> Result<MiroBoardPage, TransportError>;
}

#[derive(Debug)]
pub struct MiroBoardProviderAdapter<T> {
    transport: T,
    definition: MiroBoardProviderDefinition,
}

impl<T: MiroBoardTransport> MiroBoardProviderAdapter<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = MiroBoardProviderDefinition::new(provider_version, provenance)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: MiroBoardTransport> MiroBoardProvider for MiroBoardProviderAdapter<T> {
    fn definition(&self) -> &MiroBoardProviderDefinition {
        &self.definition
    }

    fn read_board_page(
        &mut self,
        request: &MiroBoardReadRequest,
    ) -> Result<MiroBoardPage, TransportError> {
        self.transport.read_board_page(request)
    }
}

pub type MiroBoardProviderClient<T> = MiroBoardProviderAdapter<T>;

#[derive(Debug)]
pub struct RecordingMiroBoardTransport {
    provenance: ProviderProvenance,
    responses: VecDeque<Result<MiroBoardPage, TransportError>>,
    requests: Vec<MiroBoardReadRequest>,
}

impl RecordingMiroBoardTransport {
    pub fn new(
        provenance: ProviderProvenance,
        responses: impl IntoIterator<Item = Result<MiroBoardPage, TransportError>>,
    ) -> Self {
        Self {
            provenance,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<MiroBoardPage, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Fixture, responses)
    }

    pub fn recording(
        responses: impl IntoIterator<Item = Result<MiroBoardPage, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Recording, responses)
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<MiroBoardPage, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Loopback, responses)
    }

    pub fn push_response(&mut self, response: Result<MiroBoardPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[MiroBoardReadRequest] {
        &self.requests
    }

    pub const fn provenance_value(&self) -> ProviderProvenance {
        self.provenance
    }
}

impl Default for RecordingMiroBoardTransport {
    fn default() -> Self {
        Self::new(ProviderProvenance::Recording, [])
    }
}

impl MiroBoardTransport for RecordingMiroBoardTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn read_board_page(
        &mut self,
        request: &MiroBoardReadRequest,
    ) -> Result<MiroBoardPage, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }
}

pub type FakeMiroBoardTransport = RecordingMiroBoardTransport;
pub type LoopbackMiroBoardTransport = RecordingMiroBoardTransport;
pub type BlockedEnvTransport = BlockedEnvMiroBoardTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvMiroBoardTransport;

impl MiroBoardTransport for BlockedEnvMiroBoardTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn read_board_page(
        &mut self,
        _request: &MiroBoardReadRequest,
    ) -> Result<MiroBoardPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}
