use std::fmt;

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionRedisCloudDatabaseConsumer;
use crate::error::{RedisCloudDatabaseResultError, RedisCloudTransportError, Result};
use crate::model::{
    CostReceipt, Digest, PermissionSnapshot, ProviderProvenance, RedisCloudDatabasePosture,
    RedisCloudDatabaseScope, RedisCloudEvidenceState, RedisCloudResponsePayload,
    RedisCloudSubscriptionPosture, RequestReceipt, SecretReference,
};
use crate::provider::{
    RedisCloudOperation, RedisCloudProvider, RedisCloudProviderDefinition, RedisCloudReadRequest,
    RedisCloudTransport,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_DIGEST,
    LAYER1_PERMISSIONS, MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisCloudRegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudRegistrationTransition {
    pub previous_status: RedisCloudRegistrationStatus,
    pub new_status: RedisCloudRegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RedisCloudRegistrationTransition {
    fn new(
        previous_status: RedisCloudRegistrationStatus,
        new_status: RedisCloudRegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "redis-cloud-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RedisCloudDatabaseResultRegistration {
    id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope: RedisCloudDatabaseScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    evidence_digest: Digest,
    registration_revision: u64,
    status: RedisCloudRegistrationStatus,
    registration_digest: Digest,
}

pub type RedisCloudRegistration = RedisCloudDatabaseResultRegistration;

impl RedisCloudDatabaseResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: RedisCloudDatabaseScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: &RedisCloudProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if !valid_registration_id(&id) || registration_revision == 0 {
            return Err(RedisCloudDatabaseResultError::InvalidRegistration);
        }
        scope.validate()?;
        secret_reference.validate(&scope)?;
        permission_snapshot.validate()?;
        provider.validate()?;
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id().to_owned(),
            provider_revision: provider.provider_revision(),
            provider_release: provider.release().to_owned(),
            provider_digest: provider.provider_digest().clone(),
            api_digest: provider.api_digest().clone(),
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            evidence_digest: Digest::parse(EVIDENCE_DIGEST.to_owned())?,
            registration_revision,
            status: RedisCloudRegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-redis-cloud-registration"),
        };
        registration.registration_digest = registration.calculate_registration_digest();
        registration.validate()?;
        Ok(registration)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }
    #[must_use]
    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }
    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }
    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    #[must_use]
    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }
    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
    #[must_use]
    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }
    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }
    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }
    #[must_use]
    pub fn scope(&self) -> &RedisCloudDatabaseScope {
        &self.scope
    }
    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }
    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }
    #[must_use]
    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }
    #[must_use]
    pub const fn status(&self) -> RedisCloudRegistrationStatus {
        self.status
    }
    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RedisCloudRegistrationStatus::Active)
    }
    #[must_use]
    pub const fn is_reversible() -> bool {
        true
    }
    #[must_use]
    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != Digest::parse(CONTRACT_DIGEST.to_owned())?
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.provider_release.len() > crate::MAX_IDENTIFIER_BYTES
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.scope_digest != self.scope.digest()
            || self.registration_revision == 0
            || self.evidence_digest != Digest::parse(EVIDENCE_DIGEST.to_owned())?
            || self.registration_digest != self.calculate_registration_digest()
        {
            return Err(RedisCloudDatabaseResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.permission_snapshot.validate()?;
        self.provider_digest.validate()?;
        self.api_digest.validate()
    }

    pub fn revoke(&mut self) -> Result<RedisCloudRegistrationTransition> {
        self.transition(RedisCloudRegistrationStatus::Revoked)
    }
    pub fn reverse(&mut self) -> Result<RedisCloudRegistrationTransition> {
        if matches!(self.status, RedisCloudRegistrationStatus::Reversed) {
            return Err(RedisCloudDatabaseResultError::RegistrationReversed);
        }
        self.transition(RedisCloudRegistrationStatus::Reversed)
    }
    pub fn restore(&mut self) -> Result<RedisCloudRegistrationTransition> {
        if matches!(self.status, RedisCloudRegistrationStatus::Reversed) {
            return Err(RedisCloudDatabaseResultError::RegistrationReversed);
        }
        self.transition(RedisCloudRegistrationStatus::Active)
    }

    fn transition(
        &mut self,
        new_status: RedisCloudRegistrationStatus,
    ) -> Result<RedisCloudRegistrationTransition> {
        let previous_status = self.status;
        self.status = new_status;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RedisCloudRegistrationTransition::new(
            previous_status,
            new_status,
            self.registration_digest.clone(),
        ))
    }

    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.secret_reference.revoke();
        self.registration_digest = self.calculate_registration_digest();
        Ok(())
    }

    fn calculate_registration_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-database-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "secret_revoked",
                    self.secret_reference.is_revoked().to_string(),
                ),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for RedisCloudDatabaseResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisCloudDatabaseResultRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("version_digest", &self.version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for RedisCloudDatabaseResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("RedisCloudDatabaseResultRegistration", 22)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("revocable", &true)?;
        state.serialize_field("connected", &false)?;
        state.serialize_field("native", &false)?;
        state.serialize_field("firstParty", &false)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudEvidenceRequest {
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub request_digest: Digest,
}

impl RedisCloudEvidenceRequest {
    pub fn new(
        scope: &RedisCloudDatabaseScope,
        page_size: u16,
        max_pages: u16,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(RedisCloudDatabaseResultError::PaginationRejected);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        let mut request = Self {
            scope_digest: scope.digest(),
            page_size,
            max_pages,
            expected_provider_digest,
            expected_registration_digest,
            request_digest: Digest::from_text("unsealed-redis-cloud-request"),
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }
    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
            ],
        )
    }
    fn validate(
        &self,
        scope: &RedisCloudDatabaseScope,
        registration: &RedisCloudDatabaseResultRegistration,
        provider: &RedisCloudProviderDefinition,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.page_size != MAX_PAGE_SIZE
            || self.max_pages != MAX_PAGES
            || self.expected_provider_digest != *provider.provider_digest()
            || self.expected_registration_digest != *registration.registration_digest()
            || self.request_digest != self.calculate_digest()
        {
            return Err(RedisCloudDatabaseResultError::ScopeDrift);
        }
        self.request_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudFailureEvidence {
    pub operation: Option<String>,
    pub status_code: Option<u16>,
    pub category: String,
    pub response_digest: Option<Digest>,
    pub failure_digest: Digest,
}

impl RedisCloudFailureEvidence {
    fn from_transport(error: &RedisCloudTransportError) -> Self {
        let category = match error {
            RedisCloudTransportError::BlockedEnv => "blocked_env",
            RedisCloudTransportError::BadRequest { .. } => "bad_request",
            RedisCloudTransportError::Unauthorized { .. } => "unauthorized",
            RedisCloudTransportError::Forbidden { .. } => "forbidden",
            RedisCloudTransportError::NotFound { .. } => "not_found",
            RedisCloudTransportError::RateLimited { .. } => "throttled",
            RedisCloudTransportError::ServerError { .. } => "server_error",
            RedisCloudTransportError::Timeout { .. } => "timed_out",
            RedisCloudTransportError::AccessLost { .. } => "access_loss",
            RedisCloudTransportError::Partial { .. } => "partial",
            RedisCloudTransportError::Truncated { .. } => "truncated",
            RedisCloudTransportError::Pagination { .. }
            | RedisCloudTransportError::PaginationLoop { .. } => "pagination_rejected",
            RedisCloudTransportError::ProviderUnknown { .. } => "provider_unknown",
            RedisCloudTransportError::InvalidResponse { .. } => "invalid_response",
            RedisCloudTransportError::Tampered { .. } => "tampered",
            RedisCloudTransportError::ScopeDrift { .. } => "stale",
            RedisCloudTransportError::Unsupported { .. } => "unsupported",
        }
        .to_owned();
        let operation = error
            .operation()
            .and_then(safe_failure_operation)
            .map(str::to_owned);
        let response_digest = error.response_digest().cloned();
        let failure_digest = Digest::from_parts(
            "redis-cloud-failure/v1",
            &[
                ("operation", operation.clone().unwrap_or_default()),
                ("category", category.clone()),
                (
                    "status",
                    error
                        .http_status()
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "response",
                    response_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        Self {
            operation,
            status_code: error.http_status(),
            category,
            response_digest,
            failure_digest,
        }
    }

    fn validate(&self) -> Result<()> {
        if let Some(response_digest) = &self.response_digest {
            response_digest.validate()?;
        }
        if self
            .operation
            .as_deref()
            .is_some_and(|value| safe_failure_operation(value).is_none())
            || self.category.is_empty()
            || self.failure_digest != self.calculate_digest()
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-failure/v1",
            &[
                ("operation", self.operation.clone().unwrap_or_default()),
                ("category", self.category.clone()),
                (
                    "status",
                    self.status_code
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "response",
                    self.response_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}

fn safe_failure_operation(value: &str) -> Option<&str> {
    match value {
        "GetAccount"
        | "GetSubscription"
        | "GetDatabase"
        | "posture-aggregate"
        | "missing-posture-component" => Some(value),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudDatabaseResultEvidence {
    pub plugin_version_digest: Digest,
    pub contract_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub account_digest: Digest,
    pub subscription_digest: Digest,
    pub database_digest: Digest,
    pub evidence_digest: Digest,
}

impl RedisCloudDatabaseResultEvidence {
    fn new(
        registration: &RedisCloudDatabaseResultRegistration,
        request: &RedisCloudEvidenceRequest,
        response_digests: &[Digest],
        account: &Digest,
        subscription: &Digest,
        database: &Digest,
        state: RedisCloudEvidenceState,
        failure: Option<&RedisCloudFailureEvidence>,
    ) -> Self {
        let response_digest = Digest::from_parts(
            "redis-cloud-response-set/v1",
            &[(
                "responses",
                response_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join("|"),
            )],
        );
        let mut evidence = Self {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version_digest: Digest::from_text(CONTRACT_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            api_digest: registration.api_digest.clone(),
            permission_digest: registration.permission_digest(),
            scope_digest: registration.scope_digest.clone(),
            secret_reference_digest: registration.secret_reference_digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            request_digest: request.digest().clone(),
            response_digest,
            account_digest: account.clone(),
            subscription_digest: subscription.clone(),
            database_digest: database.clone(),
            evidence_digest: Digest::from_text("unsealed-redis-cloud-evidence"),
        };
        evidence.evidence_digest = evidence.calculate_digest(state, failure);
        evidence
    }

    fn calculate_digest(
        &self,
        state: RedisCloudEvidenceState,
        failure: Option<&RedisCloudFailureEvidence>,
    ) -> Digest {
        Digest::from_parts(
            "redis-cloud-database-evidence/v1",
            &[
                ("plugin", self.plugin_version_digest.as_str().to_owned()),
                (
                    "contract_version",
                    self.contract_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("response", self.response_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("database", self.database_digest.as_str().to_owned()),
                ("state", format!("{state:?}")),
                (
                    "failure",
                    failure.map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudDatabaseResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub account_digest: Digest,
    pub subscription_digest: Digest,
    pub database_digest: Digest,
    pub mission_id_digest: Digest,
    pub project_id_digest: Digest,
    pub work_product_id_digest: Digest,
    pub state: RedisCloudEvidenceState,
    pub subscription: Option<RedisCloudSubscriptionPosture>,
    pub database: Option<RedisCloudDatabasePosture>,
    pub failure: Option<RedisCloudFailureEvidence>,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub evidence: RedisCloudDatabaseResultEvidence,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl RedisCloudDatabaseResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &RedisCloudDatabaseResultRegistration,
        request: &RedisCloudEvidenceRequest,
        state: RedisCloudEvidenceState,
        subscription: Option<RedisCloudSubscriptionPosture>,
        database: Option<RedisCloudDatabasePosture>,
        failure: Option<RedisCloudFailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        response_digests: &[Digest],
        provenance: ProviderProvenance,
    ) -> Self {
        let account_digest = registration.scope.account().digest();
        let subscription_digest = registration.scope.subscription().digest();
        let database_digest = registration.scope.database().digest();
        let evidence = RedisCloudDatabaseResultEvidence::new(
            registration,
            request,
            response_digests,
            &account_digest,
            &subscription_digest,
            &database_digest,
            state,
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            request_digest: request.digest().clone(),
            account_digest,
            subscription_digest,
            database_digest,
            mission_id_digest: registration.scope.mission().id_digest().clone(),
            project_id_digest: registration.scope.project().id_digest().clone(),
            work_product_id_digest: registration.scope.work_product().id_digest().clone(),
            state,
            subscription,
            database,
            failure,
            request_receipts,
            cost_receipts,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-redis-cloud-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn validate_integrity(&self) -> Result<()> {
        let expected_contract = Digest::parse(CONTRACT_DIGEST.to_owned())?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence.registration_digest != self.registration_digest
            || self.evidence.scope_digest != self.scope_digest
            || self.evidence.request_digest != self.request_digest
            || self.evidence.account_digest != self.account_digest
            || self.evidence.subscription_digest != self.subscription_digest
            || self.evidence.database_digest != self.database_digest
            || self.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence.contract_version_digest != Digest::from_text(CONTRACT_VERSION)
            || self.evidence.contract_digest != expected_contract
            || self.evidence.api_digest != Digest::from_text(API_REVISION)
            || self
                .request_receipts
                .iter()
                .any(|receipt| !receipt.redacted)
            || self
                .cost_receipts
                .iter()
                .any(|receipt| receipt.durable_provider_receipt)
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.account_digest.validate()?;
        self.subscription_digest.validate()?;
        self.database_digest.validate()?;
        self.evidence.plugin_version_digest.validate()?;
        self.evidence.contract_version_digest.validate()?;
        self.evidence.contract_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.api_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.secret_reference_digest.validate()?;
        self.evidence.registration_digest.validate()?;
        self.evidence.request_digest.validate()?;
        self.evidence.response_digest.validate()?;
        self.evidence.evidence_digest.validate()?;
        for receipt in &self.request_receipts {
            receipt.request_digest.validate()?;
            receipt.path_digest.validate()?;
        }
        for receipt in &self.cost_receipts {
            receipt.cost_digest.validate()?;
            receipt.validate()?;
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        if matches!(self.state, RedisCloudEvidenceState::Ready)
            && (self.subscription.is_none() || self.database.is_none() || self.failure.is_some())
        {
            return Err(RedisCloudDatabaseResultError::InvalidProposal);
        }
        if !matches!(self.state, RedisCloudEvidenceState::Ready) && self.failure.is_none() {
            return Err(RedisCloudDatabaseResultError::InvalidProposal);
        }
        if let Some(subscription) = &self.subscription {
            subscription.validate()?;
            if subscription.subscription_digest != self.subscription_digest {
                return Err(RedisCloudDatabaseResultError::ScopeDrift);
            }
        }
        if let Some(database) = &self.database {
            database.validate()?;
            if database.database_digest != self.database_digest {
                return Err(RedisCloudDatabaseResultError::ScopeDrift);
            }
        }
        if self.evidence.evidence_digest
            != self
                .evidence
                .calculate_digest(self.state, self.failure.as_ref())
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-database-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("database", self.database_digest.as_str().to_owned()),
                ("mission", self.mission_id_digest.as_str().to_owned()),
                ("project", self.project_id_digest.as_str().to_owned()),
                (
                    "work_product",
                    self.work_product_id_digest.as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "subscription_projection",
                    self.subscription
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.metadata_digest.as_str().to_owned()
                        }),
                ),
                (
                    "database_projection",
                    self.database.as_ref().map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisCloudVerificationFailure {
    InvalidProposal,
    TamperedEvidence,
    RegistrationMismatch,
    NotReviewEligible,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<RedisCloudVerificationFailure>,
}

impl RedisCloudVerificationReport {
    fn invalid(failure: RedisCloudVerificationFailure) -> Self {
        Self {
            valid: false,
            review_eligible: false,
            failures: vec![failure],
        }
    }
}

pub struct RedisCloudDatabaseResultService<T: RedisCloudTransport> {
    registration: RedisCloudDatabaseResultRegistration,
    provider: RedisCloudProvider<T>,
}

impl<T: RedisCloudTransport> fmt::Debug for RedisCloudDatabaseResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisCloudDatabaseResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: RedisCloudTransport> RedisCloudDatabaseResultService<T> {
    pub fn new(
        scope: RedisCloudDatabaseScope,
        secret_reference: SecretReference,
        provider: RedisCloudProvider<T>,
    ) -> Result<Self> {
        Self::new_with_identity(
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            provider,
            "redis-cloud-database-registration",
            1,
        )
    }

    pub fn new_with_identity(
        scope: RedisCloudDatabaseScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: RedisCloudProvider<T>,
        registration_id: impl Into<String>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = RedisCloudDatabaseResultRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn with_registration(
        registration: RedisCloudDatabaseResultRegistration,
        provider: RedisCloudProvider<T>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.provider_digest() != provider.definition().provider_digest()
            || registration.api_digest() != provider.definition().api_digest()
        {
            return Err(RedisCloudDatabaseResultError::ProviderDrift);
        }
        Ok(Self {
            registration,
            provider,
        })
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: [
                RedisCloudOperation::GetAccount,
                RedisCloudOperation::GetSubscription,
                RedisCloudOperation::GetDatabase,
            ]
            .into_iter()
            .map(|value| value.as_str().to_owned())
            .collect(),
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }
    #[must_use]
    pub fn scope(&self) -> &RedisCloudDatabaseScope {
        self.registration.scope()
    }
    #[must_use]
    pub fn registration(&self) -> &RedisCloudDatabaseResultRegistration {
        &self.registration
    }
    #[must_use]
    pub fn registration_mut(&mut self) -> &mut RedisCloudDatabaseResultRegistration {
        &mut self.registration
    }
    #[must_use]
    pub fn provider(&self) -> &RedisCloudProvider<T> {
        &self.provider
    }
    #[must_use]
    pub fn provider_mut(&mut self) -> &mut RedisCloudProvider<T> {
        &mut self.provider
    }

    pub fn default_request(&self) -> Result<RedisCloudEvidenceRequest> {
        RedisCloudEvidenceRequest::new(
            self.scope(),
            MAX_PAGE_SIZE,
            MAX_PAGES,
            self.provider.definition().provider_digest().clone(),
            self.registration.registration_digest().clone(),
        )
    }
    pub fn request(&self) -> Result<RedisCloudEvidenceRequest> {
        self.default_request()
    }
    pub fn revoke(&mut self) -> Result<RedisCloudRegistrationTransition> {
        self.registration.revoke()
    }
    pub fn revoke_registration(&mut self) -> Result<RedisCloudRegistrationTransition> {
        self.revoke()
    }
    pub fn reverse(&mut self) -> Result<RedisCloudRegistrationTransition> {
        self.registration.reverse()
    }
    pub fn reverse_registration(&mut self) -> Result<RedisCloudRegistrationTransition> {
        self.reverse()
    }
    pub fn restore_registration(&mut self) -> Result<RedisCloudRegistrationTransition> {
        self.registration.restore()
    }
    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.registration.revoke_secret_reference()
    }
    pub fn consumer(&self) -> Result<MissionRedisCloudDatabaseConsumer> {
        MissionRedisCloudDatabaseConsumer::new(self.scope().clone(), self.registration.clone())
    }
    pub fn read(
        &mut self,
        request: RedisCloudEvidenceRequest,
    ) -> Result<RedisCloudDatabaseResultProposal> {
        self.propose(request)
    }

    pub fn propose(
        &mut self,
        request: RedisCloudEvidenceRequest,
    ) -> Result<RedisCloudDatabaseResultProposal> {
        self.preflight(&request)?;
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();
        let mut response_digests = Vec::new();
        let mut subscription = None;
        let mut database = None;
        let scope = self.scope().clone();
        for operation in [
            RedisCloudOperation::GetAccount,
            RedisCloudOperation::GetSubscription,
            RedisCloudOperation::GetDatabase,
        ] {
            let operation_request =
                RedisCloudReadRequest::new(&scope, operation, request.page_size, None)?;
            request_receipts.push(operation_request.recorded_request()?);
            match self.provider.execute(&operation_request, &scope) {
                Ok(response) => {
                    response_digests.push(response.response_digest.clone());
                    cost_receipts.push(response.cost_receipt.clone());
                    match response.payload {
                        RedisCloudResponsePayload::Account { account_digest } => {
                            if operation != RedisCloudOperation::GetAccount
                                || account_digest != self.scope().account().digest()
                            {
                                return Ok(self.failed_proposal(
                                    &request,
                                    RedisCloudEvidenceState::Stale,
                                    Some(RedisCloudFailureEvidence::from_transport(
                                        &RedisCloudTransportError::ScopeDrift {
                                            operation: operation.as_str().to_owned(),
                                        },
                                    )),
                                    request_receipts,
                                    cost_receipts,
                                    response_digests,
                                    subscription,
                                    database,
                                ));
                            }
                        }
                        RedisCloudResponsePayload::Subscription(value) => {
                            if operation != RedisCloudOperation::GetSubscription
                                || subscription.replace(value).is_some()
                            {
                                return Ok(self.failed_proposal(
                                    &request,
                                    RedisCloudEvidenceState::Tampered,
                                    Some(RedisCloudFailureEvidence::from_transport(
                                        &RedisCloudTransportError::Tampered {
                                            operation: operation.as_str().to_owned(),
                                            response_digest: response.response_digest,
                                        },
                                    )),
                                    request_receipts,
                                    cost_receipts,
                                    response_digests,
                                    subscription,
                                    database,
                                ));
                            }
                        }
                        RedisCloudResponsePayload::Database(value) => {
                            if operation != RedisCloudOperation::GetDatabase
                                || database.replace(value).is_some()
                            {
                                return Ok(self.failed_proposal(
                                    &request,
                                    RedisCloudEvidenceState::Tampered,
                                    Some(RedisCloudFailureEvidence::from_transport(
                                        &RedisCloudTransportError::Tampered {
                                            operation: operation.as_str().to_owned(),
                                            response_digest: response.response_digest,
                                        },
                                    )),
                                    request_receipts,
                                    cost_receipts,
                                    response_digests,
                                    subscription,
                                    database,
                                ));
                            }
                        }
                    }
                }
                Err(error) => {
                    return Ok(self.failed_proposal(
                        &request,
                        state_for_transport(&error),
                        Some(RedisCloudFailureEvidence::from_transport(&error)),
                        request_receipts,
                        cost_receipts,
                        response_digests,
                        subscription,
                        database,
                    ));
                }
            }
        }
        let subscription = subscription.ok_or(RedisCloudDatabaseResultError::PartialEvidence)?;
        let database = database.ok_or(RedisCloudDatabaseResultError::PartialEvidence)?;
        if subscription.account_digest != self.scope().account().digest()
            || subscription.subscription_digest != self.scope().subscription().digest()
            || database.account_digest != self.scope().account().digest()
            || database.subscription_digest != self.scope().subscription().digest()
            || database.database_digest != self.scope().database().digest()
        {
            return Ok(self.failed_proposal(
                &request,
                RedisCloudEvidenceState::Stale,
                Some(RedisCloudFailureEvidence::from_transport(
                    &RedisCloudTransportError::ScopeDrift {
                        operation: "posture-aggregate".to_owned(),
                    },
                )),
                request_receipts,
                cost_receipts,
                response_digests,
                Some(subscription),
                Some(database),
            ));
        }
        let proposal = RedisCloudDatabaseResultProposal::new(
            &self.registration,
            &request,
            RedisCloudEvidenceState::Ready,
            Some(subscription),
            Some(database),
            None,
            request_receipts,
            cost_receipts,
            &response_digests,
            self.provider.provenance(),
        );
        proposal.validate_integrity()?;
        Ok(proposal)
    }

    pub fn verify(
        &self,
        proposal: &RedisCloudDatabaseResultProposal,
    ) -> RedisCloudVerificationReport {
        if proposal.validate_integrity().is_err() {
            return RedisCloudVerificationReport::invalid(
                RedisCloudVerificationFailure::TamperedEvidence,
            );
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.api_digest != *self.registration.api_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.secret_reference_digest
                != *self.registration.secret_reference_digest()
        {
            return RedisCloudVerificationReport::invalid(
                RedisCloudVerificationFailure::RegistrationMismatch,
            );
        }
        if !proposal.state.is_review_eligible() {
            return RedisCloudVerificationReport::invalid(
                RedisCloudVerificationFailure::NotReviewEligible,
            );
        }
        RedisCloudVerificationReport {
            valid: true,
            review_eligible: true,
            failures: Vec::new(),
        }
    }

    fn preflight(&self, request: &RedisCloudEvidenceRequest) -> Result<()> {
        crate::RedisCloudDatabaseResultContract::baseline()?;
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(match self.registration.status() {
                RedisCloudRegistrationStatus::Revoked => {
                    RedisCloudDatabaseResultError::RegistrationRevoked
                }
                RedisCloudRegistrationStatus::Reversed => {
                    RedisCloudDatabaseResultError::RegistrationReversed
                }
                RedisCloudRegistrationStatus::Active => {
                    RedisCloudDatabaseResultError::RegistrationInactive
                }
            });
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(RedisCloudDatabaseResultError::SecretRevoked);
        }
        if self.registration.provider_digest() != self.provider.definition().provider_digest()
            || self.registration.api_digest() != self.provider.definition().api_digest()
            || self.provider.definition().provenance().is_native()
            || self.provider.definition().provenance().is_connected()
            || self.provider.definition().provenance().is_first_party()
        {
            return Err(RedisCloudDatabaseResultError::ProviderDrift);
        }
        request.validate(self.scope(), &self.registration, self.provider.definition())
    }

    #[allow(clippy::too_many_arguments)]
    fn failed_proposal(
        &self,
        request: &RedisCloudEvidenceRequest,
        state: RedisCloudEvidenceState,
        failure: Option<RedisCloudFailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        response_digests: Vec<Digest>,
        subscription: Option<RedisCloudSubscriptionPosture>,
        database: Option<RedisCloudDatabasePosture>,
    ) -> RedisCloudDatabaseResultProposal {
        RedisCloudDatabaseResultProposal::new(
            &self.registration,
            request,
            state,
            subscription,
            database,
            failure,
            request_receipts,
            cost_receipts,
            &response_digests,
            self.provider.provenance(),
        )
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn state_for_transport(error: &RedisCloudTransportError) -> RedisCloudEvidenceState {
    match error {
        RedisCloudTransportError::Partial { .. } => RedisCloudEvidenceState::Partial,
        RedisCloudTransportError::Truncated { .. } => RedisCloudEvidenceState::Truncated,
        RedisCloudTransportError::Pagination { .. }
        | RedisCloudTransportError::PaginationLoop { .. } => {
            RedisCloudEvidenceState::PaginationRejected
        }
        RedisCloudTransportError::Unauthorized { .. }
        | RedisCloudTransportError::Forbidden { .. }
        | RedisCloudTransportError::AccessLost { .. } => RedisCloudEvidenceState::AccessLoss,
        RedisCloudTransportError::Tampered { .. } => RedisCloudEvidenceState::Tampered,
        RedisCloudTransportError::ScopeDrift { .. } => RedisCloudEvidenceState::Stale,
        RedisCloudTransportError::ProviderUnknown { .. }
        | RedisCloudTransportError::BlockedEnv
        | RedisCloudTransportError::BadRequest { .. }
        | RedisCloudTransportError::NotFound { .. }
        | RedisCloudTransportError::RateLimited { .. }
        | RedisCloudTransportError::ServerError { .. }
        | RedisCloudTransportError::Timeout { .. }
        | RedisCloudTransportError::InvalidResponse { .. }
        | RedisCloudTransportError::Unsupported { .. } => RedisCloudEvidenceState::ProviderUnknown,
    }
}
