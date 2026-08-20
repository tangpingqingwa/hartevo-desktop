use std::{collections::BTreeSet, fmt, sync::Arc};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    API_REVISION, BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL,
    Layer1Authority, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    consumer::{MissionAwsNeptuneConsumer, RegistrationFence},
    error::{AwsNeptuneGraphResultError, AwsNeptuneTransportError, Result},
    model::{
        AwsNeptuneGraphScope, Digest, EvidenceDigests, GraphRowProjection, NeptuneEvidenceState,
        NeptuneGraphEvidence, PartialReason, PermissionSnapshot, QueryLimits, SecretReference,
        TransportProvenance,
    },
    provider::{AwsNeptuneProvider, AwsNeptuneProviderDefinition, ExecuteOpenCypherQueryRequest},
    query::OpenCypherQuery,
};

/// Reversible registration state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

/// Digest-only evidence for a registration transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

/// Version/provider/permission/scope/evidence-bound registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNeptuneGraphResultRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: u64,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl AwsNeptuneGraphResultRegistration {
    pub(crate) fn new(
        scope: &AwsNeptuneGraphScope,
        permission: &PermissionSnapshot,
        secret: &SecretReference,
        provider: &AwsNeptuneProviderDefinition,
    ) -> Result<Self> {
        permission.validate()?;
        secret.validate_against(scope)?;
        provider.validate()?;
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_text(CONTRACT_DIGEST_INPUT),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: 1,
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission.digest(),
            scope_digest: scope.digest(),
            evidence_digest: Digest::from_parts(
                "aws-neptune-registration-evidence/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("provider", provider.provider_digest.as_str().to_owned()),
                ],
            ),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision: 1,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("unsealed-neptune-registration"),
        };
        registration.registration_digest = registration.recomputed_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-neptune-registration/v1",
            &[
                ("plugin", self.plugin_id.clone()),
                ("version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("state", format!("{:?}", self.state)),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PLUGIN_VERSION
            || self.provider_revision == 0
            || self.registration_revision == 0
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(AwsNeptuneGraphResultError::InvalidRegistration);
        }
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.api_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.evidence_digest.validate()?;
        self.secret_reference_digest.validate()?;
        Ok(())
    }

    fn transition(
        &mut self,
        new_state: RegistrationState,
    ) -> Result<RegistrationTransitionEvidence> {
        self.validate()?;
        let previous_state = self.state;
        self.state = new_state;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.recomputed_digest();
        self.validate()?;
        Ok(RegistrationTransitionEvidence {
            previous_state,
            new_state,
            registration_digest: self.registration_digest.clone(),
            transition_digest: Digest::from_parts(
                "aws-neptune-registration-transition/v1",
                &[
                    ("previous", format!("{previous_state:?}")),
                    ("new", format!("{new_state:?}")),
                    ("registration", self.registration_digest.as_str().to_owned()),
                ],
            ),
        })
    }

    pub(crate) fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationState::Revoked)
    }

    pub(crate) fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationState::Reversed)
    }

    pub(crate) fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationState::Active)
    }
}

/// Capability metadata exposed by the typed service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNeptuneCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub operations: [&'static str; 8],
    pub allowlisted_api_operations: [&'static str; 1],
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub raw_query_text: bool,
    pub raw_graph_payload: bool,
}

impl AwsNeptuneCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            operations: [
                "describe_capabilities",
                "describe_scope",
                "register",
                "execute_open_cypher_query",
                "propose",
                "verify",
                "record",
                "revoke_registration",
            ],
            allowlisted_api_operations: ["ExecuteOpenCypherQuery"],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
            raw_query_text: false,
            raw_graph_payload: false,
        }
    }
}

/// Stable failure metadata with only a bounded category and digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub error_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(error: &AwsNeptuneTransportError) -> Self {
        Self {
            category: error.category().to_owned(),
            status_code: error.status_code(),
            retry_after_seconds: error.retry_after_seconds(),
            error_digest: Digest::from_parts(
                "aws-neptune-provider-error/v1",
                &[
                    ("category", error.category().to_owned()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    ),
                ],
            ),
        }
    }
}

/// Mission-facing bounded proposal.  It is review-only evidence below kernel
/// Truth, Outcome, Receipt, Verification, and Work Product authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNeptuneGraphResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub state: NeptuneEvidenceState,
    pub partial_reason: Option<PartialReason>,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub vpc_endpoint_digest: Digest,
    pub cluster_digest: Digest,
    pub graph_digest: Digest,
    pub query_template_digest: Digest,
    pub parameter_digest: Digest,
    pub query_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub rows: Vec<GraphRowProjection>,
    pub row_count: u32,
    pub node_count: u32,
    pub edge_count: u32,
    pub response_bytes: u64,
    pub elapsed_ms: u64,
    pub page_count: u16,
    pub result_digest: Digest,
    pub evidence: NeptuneGraphEvidence,
    pub failure: Option<FailureEvidence>,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsNeptuneGraphResultProposal {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-neptune-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("state", format!("{:?}", self.state)),
                (
                    "partial",
                    self.partial_reason
                        .map_or_else(|| "none".to_owned(), |reason| format!("{reason:?}")),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("endpoint", self.vpc_endpoint_digest.as_str().to_owned()),
                ("cluster", self.cluster_digest.as_str().to_owned()),
                ("graph", self.graph_digest.as_str().to_owned()),
                ("template", self.query_template_digest.as_str().to_owned()),
                ("parameter", self.parameter_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("mission", self.mission_digest.as_str().to_owned()),
                ("project", self.project_digest.as_str().to_owned()),
                ("work_product", self.work_product_digest.as_str().to_owned()),
                (
                    "rows",
                    self.rows
                        .iter()
                        .map(|row| row.row_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("elapsed", self.elapsed_ms.to_string()),
                ("pages", self.page_count.to_string()),
                ("result", self.result_digest.as_str().to_owned()),
                (
                    "evidence",
                    self.evidence.digests.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(
                        || "none".to_owned(),
                        |value| value.error_digest.as_str().to_owned(),
                    ),
                ),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
            || self.provenance != self.evidence.provenance
            || (matches!(
                self.state,
                NeptuneEvidenceState::Partial | NeptuneEvidenceState::Timeout
            ) != self.partial_reason.is_some())
            || self.row_count != self.rows.len() as u32
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsNeptuneGraphResultError::TamperedEvidence);
        }
        let mut nodes = 0_u32;
        let mut edges = 0_u32;
        let mut bytes = 0_u64;
        for row in &self.rows {
            row.validate()?;
            nodes = nodes.saturating_add(row.nodes.len() as u32);
            edges = edges.saturating_add(row.edges.len() as u32);
            bytes = bytes.saturating_add(row.byte_size);
        }
        if nodes != self.node_count || edges != self.edge_count || bytes != self.response_bytes {
            return Err(AwsNeptuneGraphResultError::TamperedEvidence);
        }
        if self.result_digest
            != aggregate_result_digest(&self.query_digest, &self.rows, self.response_bytes)
        {
            return Err(AwsNeptuneGraphResultError::ResultDigestMismatch);
        }
        if self.evidence.state != self.state
            || self.evidence.partial_reason != self.partial_reason
            || self.evidence.row_count != self.row_count
            || self.evidence.node_count != self.node_count
            || self.evidence.edge_count != self.edge_count
            || self.evidence.response_bytes != self.response_bytes
            || self.evidence.elapsed_ms != self.elapsed_ms
            || self.evidence.page_count != self.page_count
            || self.evidence.result_digest != self.result_digest
            || self.evidence.provenance != self.provenance
            || self.evidence.digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence.digests.contract_digest != Digest::from_text(CONTRACT_DIGEST_INPUT)
            || self.evidence.digests.scope_digest != self.scope_digest
            || self.evidence.digests.query_template_digest != self.query_template_digest
            || self.evidence.digests.parameter_digest != self.parameter_digest
            || self.evidence.digests.query_digest != self.query_digest
            || self.evidence.digests.result_digest != self.result_digest
            || self.evidence.digests.evidence_digest != self.evidence.digest()
        {
            return Err(AwsNeptuneGraphResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Verification result that remains below kernel Verification authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub state: NeptuneEvidenceState,
    pub verification_digest: Digest,
}

/// Input to a proposal operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphQueryProposalRequest {
    pub query: OpenCypherQuery,
    pub observed_at: DateTime<Utc>,
}

impl GraphQueryProposalRequest {
    pub fn new(query: OpenCypherQuery, observed_at: DateTime<Utc>) -> Self {
        Self { query, observed_at }
    }
}

impl From<OpenCypherQuery> for GraphQueryProposalRequest {
    fn from(query: OpenCypherQuery) -> Self {
        Self {
            query,
            observed_at: Utc::now(),
        }
    }
}

/// Typed Neptune Layer-1 service.
pub struct AwsNeptuneGraphResultService<T> {
    scope: AwsNeptuneGraphScope,
    permission: PermissionSnapshot,
    secret_reference: SecretReference,
    provider: AwsNeptuneProvider<T>,
    limits: QueryLimits,
    registration: AwsNeptuneGraphResultRegistration,
    registration_fence: Arc<RegistrationFence>,
}

impl<T: crate::AwsNeptuneTransport> fmt::Debug for AwsNeptuneGraphResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsNeptuneGraphResultService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("limits", &self.limits)
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: crate::AwsNeptuneTransport> AwsNeptuneGraphResultService<T> {
    /// Register a provider, permission snapshot, secret reference, and exact scope.
    pub fn new(
        scope: AwsNeptuneGraphScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AwsNeptuneProvider<T>,
        limits: QueryLimits,
    ) -> Result<Self> {
        scope.validate()?;
        limits.validate()?;
        secret_reference.validate_against(&scope)?;
        permission.validate()?;
        provider.definition().validate()?;
        crate::AwsNeptuneGraphResultContract::baseline()?;
        let registration = AwsNeptuneGraphResultRegistration::new(
            &scope,
            &permission,
            &secret_reference,
            provider.definition(),
        )?;
        let registration_fence = Arc::new(RegistrationFence::new(&registration));
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            limits,
            registration,
            registration_fence,
        })
    }

    /// Convenience constructor with the Layer-1 permission and maximum bounds.
    pub fn new_layer_one(
        scope: AwsNeptuneGraphScope,
        secret_reference: SecretReference,
        provider: AwsNeptuneProvider<T>,
    ) -> Result<Self> {
        Self::new(
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            provider,
            QueryLimits::layer_one(),
        )
    }

    pub fn register(
        scope: AwsNeptuneGraphScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AwsNeptuneProvider<T>,
        limits: QueryLimits,
    ) -> Result<Self> {
        Self::new(scope, secret_reference, permission, provider, limits)
    }

    pub const fn describe_capabilities() -> AwsNeptuneCapabilities {
        AwsNeptuneCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsNeptuneGraphScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsNeptuneProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsNeptuneProvider<T> {
        &mut self.provider
    }

    pub fn limits(&self) -> QueryLimits {
        self.limits
    }

    pub fn registration(&self) -> &AwsNeptuneGraphResultRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        let transition = self.registration.revoke()?;
        self.registration_fence.sync(&self.registration);
        Ok(transition)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke_registration()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        let transition = self.registration.reverse()?;
        self.registration_fence.sync(&self.registration);
        Ok(transition)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse_registration()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        let transition = self.registration.restore()?;
        self.registration_fence.sync(&self.registration);
        Ok(transition)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.restore_registration()
    }

    pub fn consumer(&self) -> Result<MissionAwsNeptuneConsumer> {
        self.ensure_registration_fences()?;
        MissionAwsNeptuneConsumer::new_with_fence(
            self.scope.clone(),
            self.registration.clone(),
            self.registration_fence.clone(),
        )
        .map_err(|_| AwsNeptuneGraphResultError::RegistrationInactive)
    }

    /// Compile/propose one exact Mission-scoped bounded read.
    pub fn propose<R: Into<GraphQueryProposalRequest>>(
        &mut self,
        request: R,
    ) -> Result<AwsNeptuneGraphResultProposal> {
        let request = request.into();
        self.ensure_active()?;
        self.secret_reference.validate_against(&self.scope)?;
        self.permission.validate()?;
        request
            .query
            .bind_to_scope(&self.scope)
            .map_err(|_| AwsNeptuneGraphResultError::ScopeMismatch)?;
        if request.query.limits().max_rows > self.limits.max_rows
            || request.query.limits().max_bytes > self.limits.max_bytes
            || request.query.limits().timeout_ms > self.limits.timeout_ms
            || request.query.limits().max_pages > self.limits.max_pages
        {
            return Err(AwsNeptuneGraphResultError::InvalidBounds);
        }
        let initial_request = ExecuteOpenCypherQueryRequest::new(&self.scope, request.query)?;
        self.execute_proposal(initial_request, request.observed_at)
    }

    pub fn verify(&self, proposal: &AwsNeptuneGraphResultProposal) -> VerificationReport {
        let valid = self.registration.is_active()
            && proposal.registration_digest == self.registration.registration_digest
            && proposal.registration_revision == self.registration.registration_revision
            && proposal.scope_digest == self.scope.digest()
            && proposal.account_digest == self.scope.account().digest()
            && proposal.region_digest == self.scope.region().digest()
            && proposal.vpc_endpoint_digest == self.scope.vpc_endpoint().digest()
            && proposal.cluster_digest == self.scope.cluster().digest()
            && proposal.graph_digest == self.scope.graph().digest()
            && proposal.query_template_digest == *self.scope.query_template_digest()
            && proposal.parameter_digest == *self.scope.parameter_digest()
            && proposal.mission_digest == self.scope.mission().digest()
            && proposal.project_digest == self.scope.project().digest()
            && proposal.work_product_digest == self.scope.work_product().digest()
            && proposal.evidence.digests.permission_digest == self.permission.digest()
            && proposal.evidence.digests.contract_digest
                == Digest::from_text(CONTRACT_DIGEST_INPUT)
            && proposal.evidence.digests.provider_digest
                == self.provider.definition().provider_digest
            && proposal.evidence.digests.plugin_version_digest == Digest::from_text(PLUGIN_VERSION)
            && self.ensure_registration_fences().is_ok()
            && !matches!(
                proposal.state,
                NeptuneEvidenceState::Tampered | NeptuneEvidenceState::Revoked
            )
            && proposal.validate_integrity().is_ok();
        let verification_digest = Digest::from_parts(
            "aws-neptune-verification/v1",
            &[
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                (
                    "registration",
                    self.registration.registration_digest.as_str().to_owned(),
                ),
                ("valid", valid.to_string()),
            ],
        );
        VerificationReport {
            valid,
            review_eligible: valid && proposal.state.review_eligible(),
            state: if valid {
                proposal.state
            } else {
                NeptuneEvidenceState::Tampered
            },
            verification_digest,
        }
    }

    fn ensure_active(&self) -> Result<()> {
        if !self.registration.is_active() {
            return Err(AwsNeptuneGraphResultError::RegistrationInactive);
        }
        self.ensure_registration_fences()
    }

    fn ensure_registration_fences(&self) -> Result<()> {
        self.registration.validate()?;
        let expected_evidence_digest = Digest::from_parts(
            "aws-neptune-registration-evidence/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "provider",
                    self.provider
                        .definition()
                        .provider_digest
                        .as_str()
                        .to_owned(),
                ),
            ],
        );
        if !self.registration_fence.matches(&self.registration)
            || self.registration.plugin_id != PLUGIN_ID
            || self.registration.plugin_version != PLUGIN_VERSION
            || self.registration.contract_version != CONTRACT_VERSION
            || self.registration.contract_digest.as_str() != CONTRACT_DIGEST
            || self.registration.scope_digest != self.scope.digest()
            || self.registration.permission_digest != self.permission.digest()
            || self.registration.secret_reference_digest
                != *self.secret_reference.reference_digest()
            || self.registration.provider_revision == 0
            || self.registration.provider_digest != self.provider.definition().provider_digest
            || self.registration.api_digest != self.provider.definition().api_digest
            || self.registration.provider_id != self.provider.definition().provider_id
            || self.registration.provider_version != self.provider.definition().provider_version
            || self.registration.evidence_digest != expected_evidence_digest
        {
            Err(AwsNeptuneGraphResultError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    fn execute_proposal(
        &mut self,
        mut request: ExecuteOpenCypherQueryRequest,
        _observed_at: DateTime<Utc>,
    ) -> Result<AwsNeptuneGraphResultProposal> {
        let provenance = self.provider.provenance();
        let query = request.query().clone();
        let mut rows = Vec::new();
        let mut response_bytes = 0_u64;
        let mut elapsed_ms = 0_u64;
        let mut page_count = 0_u16;
        let mut partial_reason = None;
        let mut failure = None;
        let mut state = NeptuneEvidenceState::Present;
        let mut cursors = BTreeSet::new();

        loop {
            page_count = page_count.saturating_add(1);
            if page_count > query.limits().max_pages {
                state = NeptuneEvidenceState::Partial;
                partial_reason = Some(PartialReason::PageLimit);
                page_count = query.limits().max_pages;
                break;
            }
            let response = match self.provider.execute_open_cypher_query(&request) {
                Ok(response) => response,
                Err(error) => {
                    failure = Some(FailureEvidence::from_transport(&error));
                    state = state_for_transport(&error);
                    if state == NeptuneEvidenceState::Timeout {
                        partial_reason = Some(PartialReason::Timeout);
                    }
                    if !rows.is_empty() && state == NeptuneEvidenceState::Present {
                        state = NeptuneEvidenceState::Partial;
                        partial_reason = Some(PartialReason::MorePages);
                    }
                    break;
                }
            };
            let integrity = if response.provenance != provenance {
                Err(AwsNeptuneGraphResultError::ResponseFenceMismatch)
            } else {
                response.validate_integrity(&request)
            };
            if let Err(error) = integrity {
                failure = Some(FailureEvidence {
                    category: "tampered".to_owned(),
                    status_code: None,
                    retry_after_seconds: None,
                    error_digest: Digest::from_parts(
                        "aws-neptune-tampered-response/v1",
                        &[
                            ("request", request.request_digest().as_str().to_owned()),
                            ("error", format!("{error:?}")),
                        ],
                    ),
                });
                state = NeptuneEvidenceState::Tampered;
                break;
            }
            elapsed_ms = elapsed_ms.saturating_add(response.elapsed_ms);
            if elapsed_ms > query.limits().timeout_ms {
                state = NeptuneEvidenceState::Timeout;
                partial_reason = Some(PartialReason::Timeout);
                break;
            }
            for row in response.rows {
                if rows.len() as u32 >= query.limits().max_rows {
                    state = NeptuneEvidenceState::Partial;
                    partial_reason = Some(PartialReason::RowLimit);
                    break;
                }
                if response_bytes.saturating_add(row.byte_size) > query.limits().max_bytes {
                    state = NeptuneEvidenceState::Partial;
                    partial_reason = Some(PartialReason::ByteLimit);
                    break;
                }
                response_bytes = response_bytes.saturating_add(row.byte_size);
                rows.push(row);
            }
            if partial_reason.is_some() {
                break;
            }
            if let Some(cursor) = response.next_cursor {
                if !cursors.insert(cursor.token_digest().clone()) {
                    failure = Some(FailureEvidence {
                        category: "pagination_loop".to_owned(),
                        status_code: None,
                        retry_after_seconds: None,
                        error_digest: Digest::from_text(cursor.token_digest().as_str()),
                    });
                    state = NeptuneEvidenceState::Tampered;
                    break;
                }
                if page_count >= query.limits().max_pages {
                    state = NeptuneEvidenceState::Partial;
                    partial_reason = Some(PartialReason::PageLimit);
                    break;
                }
                request = request.with_cursor(cursor)?;
            } else {
                break;
            }
        }

        if state == NeptuneEvidenceState::Present && rows.is_empty() {
            state = NeptuneEvidenceState::Empty;
        }
        let result_digest = aggregate_result_digest(query.query_digest(), &rows, response_bytes);
        let digests = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::from_text(CONTRACT_DIGEST_INPUT),
            provider_digest: self.provider.definition().provider_digest.clone(),
            permission_digest: self.permission.digest(),
            scope_digest: self.scope.digest(),
            query_template_digest: query.template_digest().clone(),
            parameter_digest: query.parameter_digest().clone(),
            query_digest: query.query_digest().clone(),
            result_digest: result_digest.clone(),
            evidence_digest: Digest::from_text("unsealed-neptune-evidence"),
        };
        let node_count = rows.iter().map(|row| row.nodes.len() as u32).sum();
        let edge_count = rows.iter().map(|row| row.edges.len() as u32).sum();
        let mut evidence = NeptuneGraphEvidence {
            state,
            partial_reason,
            row_count: rows.len() as u32,
            node_count,
            edge_count,
            response_bytes,
            elapsed_ms,
            page_count,
            result_digest: result_digest.clone(),
            digests,
            provenance,
        };
        evidence.digests.evidence_digest = evidence.digest();
        let mut proposal = AwsNeptuneGraphResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            state,
            partial_reason,
            scope_digest: self.scope.digest(),
            account_digest: self.scope.account().digest(),
            region_digest: self.scope.region().digest(),
            vpc_endpoint_digest: self.scope.vpc_endpoint().digest(),
            cluster_digest: self.scope.cluster().digest(),
            graph_digest: self.scope.graph().digest(),
            query_template_digest: query.template_digest().clone(),
            parameter_digest: query.parameter_digest().clone(),
            query_digest: query.query_digest().clone(),
            mission_digest: self.scope.mission().digest(),
            project_digest: self.scope.project().digest(),
            work_product_digest: self.scope.work_product().digest(),
            rows,
            row_count: evidence.row_count,
            node_count,
            edge_count,
            response_bytes,
            elapsed_ms,
            page_count,
            result_digest,
            evidence,
            failure,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-neptune-proposal"),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal.validate_integrity()?;
        Ok(proposal)
    }
}

fn aggregate_result_digest(
    query_digest: &Digest,
    rows: &[GraphRowProjection],
    response_bytes: u64,
) -> Digest {
    Digest::from_parts(
        "aws-neptune-result/v1",
        &[
            ("query", query_digest.as_str().to_owned()),
            (
                "rows",
                rows.iter()
                    .map(|row| row.row_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("bytes", response_bytes.to_string()),
        ],
    )
}

fn state_for_transport(error: &AwsNeptuneTransportError) -> NeptuneEvidenceState {
    match error {
        AwsNeptuneTransportError::BadRequest => NeptuneEvidenceState::BadRequest,
        AwsNeptuneTransportError::Unauthorized => NeptuneEvidenceState::AccessLost,
        AwsNeptuneTransportError::Forbidden => NeptuneEvidenceState::AccessLost,
        AwsNeptuneTransportError::NotFound => NeptuneEvidenceState::AccessLost,
        AwsNeptuneTransportError::Conflict => NeptuneEvidenceState::Conflict,
        AwsNeptuneTransportError::RateLimited { .. } => NeptuneEvidenceState::Throttled,
        AwsNeptuneTransportError::Server { .. } => NeptuneEvidenceState::ServerError,
        AwsNeptuneTransportError::Timeout => NeptuneEvidenceState::Timeout,
        AwsNeptuneTransportError::BlockedEnvironment | AwsNeptuneTransportError::Unknown => {
            NeptuneEvidenceState::ProviderUnknown
        }
    }
}

pub type AwsNeptuneService<T> = AwsNeptuneGraphResultService<T>;
pub type AwsNeptuneGraphResult = AwsNeptuneGraphResultProposal;

const CONTRACT_DIGEST_INPUT: &str = crate::CONTRACT_DIGEST_INPUT;

#[allow(dead_code)]
const _LAYER1_METADATA_FENCES: (&str, &str, &str) = (EVIDENCE_LEVEL, BLOCKED_ENV, API_REVISION);

#[allow(dead_code)]
const _AUTHORITY_FENCE: (bool, bool, bool) = (
    Layer1Authority::connected(),
    Layer1Authority::native(),
    Layer1Authority::kernel_authority(),
);
