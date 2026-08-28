//! BrowserStack provider and reversible Layer-1 registration.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::model::{
    BrowserStackBuildPayload, BrowserStackBuildProjection, BrowserStackProduct,
    BrowserStackReadProposal, BrowserStackReadRequest, BrowserStackResponseBody,
    BrowserStackResponseReceipt, BrowserStackScope, BrowserStackSessionPayload,
    BrowserStackSessionProjection, BrowserStackTestResultEvidence, Digest, EvidenceStatus,
    FailureClass, PartialReason, ProviderFailure, RequestBounds, Revision, SecretReference,
    TransportProvenance,
};
use crate::transport::{
    BrowserStackEndpoint, BrowserStackHttpRequest, BrowserStackHttpResponse, BrowserStackTransport,
    BrowserStackTransportAttestation, BrowserStackTransportError, trusted_transport_attestation,
};
use crate::{
    BROWSERSTACK_CONTRACT_VERSION, BROWSERSTACK_PLUGIN_VERSION_TEXT, BROWSERSTACK_PROVIDER_ID,
    BROWSERSTACK_PROVIDER_NAME, BROWSERSTACK_PROVIDER_REVISION, BROWSERSTACK_SCHEMA_VERSION,
    BROWSERSTACK_SERVICE_ID, BrowserStackTestResultError, BrowserStackTestResultService,
    contract_digest,
};

const MAX_CREDENTIAL_LEASE_SECONDS: i64 = 900;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrowserStackCredentialError {
    #[error("BLOCKED_ENV: BrowserStack credential authority is unavailable")]
    BlockedEnv,
    #[error("BrowserStack credential reference is unavailable")]
    Unavailable,
    #[error("BrowserStack credential lease is invalid or expired")]
    Invalid,
    #[error("BrowserStack SecretReference is revoked")]
    Revoked,
    #[error("BrowserStack credential revision does not match the reference")]
    RevisionMismatch,
}

impl From<BrowserStackCredentialError> for BrowserStackTestResultError {
    fn from(error: BrowserStackCredentialError) -> Self {
        match error {
            BrowserStackCredentialError::BlockedEnv => Self::BlockedEnv,
            BrowserStackCredentialError::Revoked => Self::SecretRevoked,
            BrowserStackCredentialError::Invalid
            | BrowserStackCredentialError::RevisionMismatch => Self::CredentialExpired,
            BrowserStackCredentialError::Unavailable => {
                Self::Credential("credential reference unavailable".to_owned())
            }
        }
    }
}

/// A short-lived host-owned lease. It is deliberately not `Clone` or
/// `Serialize`, and its Debug output never prints either credential.
pub struct BrowserStackCredentialLease {
    username: String,
    access_key: String,
    reference_digest: Digest,
    credential_revision: Revision,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for BrowserStackCredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserStackCredentialLease")
            .field("username", &"<redacted>")
            .field("access_key", &"<redacted>")
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl BrowserStackCredentialLease {
    pub(crate) fn new(
        username: impl Into<String>,
        access_key: impl Into<String>,
        reference: &SecretReference,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, BrowserStackCredentialError> {
        let username = username.into();
        let access_key = access_key.into();
        if reference.is_revoked()
            || username.trim().is_empty()
            || access_key.trim().is_empty()
            || username.chars().any(char::is_control)
            || access_key.chars().any(char::is_control)
            || expires_at <= issued_at
            || expires_at - issued_at > Duration::seconds(MAX_CREDENTIAL_LEASE_SECONDS)
        {
            return Err(BrowserStackCredentialError::Invalid);
        }
        Ok(Self {
            username,
            access_key,
            reference_digest: reference.reference_digest().clone(),
            credential_revision: reference.credential_revision(),
            issued_at,
            expires_at,
        })
    }

    pub(crate) fn fixture(
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<Self, BrowserStackCredentialError> {
        Self::new(
            "fixture-browserstack-username",
            "fixture-browserstack-access-key",
            reference,
            at - Duration::seconds(1),
            at + Duration::minutes(5),
        )
    }

    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn access_key(&self) -> &str {
        &self.access_key
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn validate_at(
        &self,
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<(), BrowserStackCredentialError> {
        if reference.is_revoked() {
            return Err(BrowserStackCredentialError::Revoked);
        }
        if self.reference_digest != *reference.reference_digest()
            || self.credential_revision != reference.credential_revision()
            || at < self.issued_at
            || at >= self.expires_at
        {
            return Err(BrowserStackCredentialError::RevisionMismatch);
        }
        Ok(())
    }
}

impl Drop for BrowserStackCredentialLease {
    fn drop(&mut self) {
        self.username.zeroize();
        self.access_key.zeroize();
    }
}

pub trait BrowserStackCredentialResolver: fmt::Debug {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<BrowserStackCredentialLease, BrowserStackCredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl BrowserStackCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<BrowserStackCredentialLease, BrowserStackCredentialError> {
        Err(BrowserStackCredentialError::BlockedEnv)
    }
}

/// A fixture-only resolver. The returned values are test placeholders and
/// remain in a non-serializable, zeroizing lease for one request.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixtureCredentialResolver;

impl BrowserStackCredentialResolver for FixtureCredentialResolver {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<BrowserStackCredentialLease, BrowserStackCredentialError> {
        BrowserStackCredentialLease::fixture(reference, at)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_name: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub product: BrowserStackProduct,
    pub provenance: TransportProvenance,
    pub capabilities: Vec<String>,
    pub read_only: bool,
    pub native: bool,
    pub provider_digest: Digest,
}

impl BrowserStackProviderDefinition {
    fn canonical_digest(&self) -> Digest {
        Digest::from_fields(
            "browserstack-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.clone(),
                self.provider_revision.clone(),
                format!("{:?}", self.product),
                format!("{:?}", self.provenance),
                self.capabilities.join(","),
                format!("read_only={}", self.read_only),
                format!("native={}", self.native),
            ],
        )
    }

    pub fn new(
        product: BrowserStackProduct,
        provenance: TransportProvenance,
    ) -> Result<Self, BrowserStackTestResultError> {
        let capabilities = vec![
            "build_metadata_read".to_owned(),
            "session_page_read".to_owned(),
            "session_detail_read".to_owned(),
            "bounded_outcome_count".to_owned(),
        ];
        let provider_digest = Digest::from_fields(
            "browserstack-provider-definition/v1",
            &[
                BROWSERSTACK_SCHEMA_VERSION.to_owned(),
                BROWSERSTACK_PROVIDER_ID.to_owned(),
                BROWSERSTACK_PROVIDER_REVISION.to_owned(),
                format!("{product:?}"),
                format!("{provenance:?}"),
                capabilities.join(","),
                "read_only=true".to_owned(),
                "native=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: BROWSERSTACK_SCHEMA_VERSION.to_owned(),
            provider_id: BROWSERSTACK_PROVIDER_ID.to_owned(),
            provider_name: BROWSERSTACK_PROVIDER_NAME.to_owned(),
            provider_version: BROWSERSTACK_PLUGIN_VERSION_TEXT.to_owned(),
            provider_revision: BROWSERSTACK_PROVIDER_REVISION.to_owned(),
            product,
            provenance,
            capabilities,
            read_only: true,
            native: false,
            provider_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn validate(&self) -> Result<(), BrowserStackTestResultError> {
        if self.schema_version != BROWSERSTACK_SCHEMA_VERSION
            || self.provider_id != BROWSERSTACK_PROVIDER_ID
            || self.provider_name != BROWSERSTACK_PROVIDER_NAME
            || self.provider_version != BROWSERSTACK_PLUGIN_VERSION_TEXT
            || self.provider_revision != BROWSERSTACK_PROVIDER_REVISION
            || !self.read_only
            || self.native
            || self.capabilities.is_empty()
            || self.provider_digest != self.canonical_digest()
        {
            return Err(BrowserStackTestResultError::InvalidInput(
                "BrowserStack provider definition drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub provider_revision: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    #[serde(skip, default = "new_registration_shared_state")]
    shared: Arc<RegistrationSharedState>,
    #[serde(skip, default)]
    live_seal: bool,
}

impl Clone for BrowserStackRegistration {
    fn clone(&self) -> Self {
        Self {
            schema_version: self.schema_version.clone(),
            contract_version: self.contract_version.clone(),
            plugin_version: self.plugin_version.clone(),
            service_id: self.service_id.clone(),
            provider_id: self.provider_id.clone(),
            consumer_id: self.consumer_id.clone(),
            provider_revision: self.provider_revision.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            secret_reference_digest: self.secret_reference_digest.clone(),
            revision: self.revision,
            registration_digest: self.registration_digest.clone(),
            state: self.state,
            shared: Arc::clone(&self.shared),
            live_seal: self.live_seal,
        }
    }
}

impl fmt::Debug for BrowserStackRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserStackRegistration")
            .field("schema_version", &self.schema_version)
            .field("contract_version", &self.contract_version)
            .field("plugin_version", &self.plugin_version)
            .field("service_id", &self.service_id)
            .field("provider_id", &self.provider_id)
            .field("consumer_id", &self.consumer_id)
            .field("provider_revision", &self.provider_revision)
            .field("contract_digest", &self.contract_digest)
            .field("provider_digest", &self.provider_digest)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("revision", &self.revision)
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl PartialEq for BrowserStackRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.contract_version == other.contract_version
            && self.plugin_version == other.plugin_version
            && self.service_id == other.service_id
            && self.provider_id == other.provider_id
            && self.consumer_id == other.consumer_id
            && self.provider_revision == other.provider_revision
            && self.contract_digest == other.contract_digest
            && self.provider_digest == other.provider_digest
            && self.scope_digest == other.scope_digest
            && self.permission_digest == other.permission_digest
            && self.secret_reference_digest == other.secret_reference_digest
            && self.revision == other.revision
            && self.registration_digest == other.registration_digest
            && self.state == other.state
    }
}

impl Eq for BrowserStackRegistration {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct BrowserStackRegistrationRequest {
    pub scope: BrowserStackScope,
    pub secret_reference: SecretReference,
    pub provider_revision: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
}

#[derive(Debug)]
struct RegistrationUseState {
    revoked: bool,
    next_use_revision: u64,
    consumed_evidence: BTreeMap<String, Revision>,
}

impl Default for RegistrationUseState {
    fn default() -> Self {
        Self {
            revoked: false,
            next_use_revision: 1,
            consumed_evidence: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct RegistrationSharedState {
    use_state: Mutex<RegistrationUseState>,
}

fn new_registration_shared_state() -> Arc<RegistrationSharedState> {
    Arc::new(RegistrationSharedState {
        use_state: Mutex::new(RegistrationUseState::default()),
    })
}

impl BrowserStackRegistrationRequest {
    pub fn baseline(
        scope: BrowserStackScope,
        secret_reference: SecretReference,
        provider_digest: Digest,
    ) -> Result<Self, BrowserStackTestResultError> {
        Ok(Self {
            scope,
            secret_reference,
            provider_revision: BROWSERSTACK_PROVIDER_REVISION.to_owned(),
            contract_digest: contract_digest(),
            provider_digest,
        })
    }
}

impl BrowserStackRegistration {
    pub fn new(
        request: &BrowserStackRegistrationRequest,
    ) -> Result<Self, BrowserStackTestResultError> {
        request.scope.permission().validate()?;
        if request.secret_reference.is_revoked() {
            return Err(BrowserStackTestResultError::SecretRevoked);
        }
        if request.contract_digest != contract_digest()
            || request.provider_revision != BROWSERSTACK_PROVIDER_REVISION
            || !request.provider_digest.is_sha256()
        {
            return Err(BrowserStackTestResultError::RegistrationDrift(
                "registration request contract/provider revision is not current".to_owned(),
            ));
        }
        let revision = Revision::new(1)?;
        let registration_digest = Digest::from_fields(
            "browserstack-registration/v1",
            &[
                BROWSERSTACK_SCHEMA_VERSION.to_owned(),
                BROWSERSTACK_CONTRACT_VERSION.to_owned(),
                BROWSERSTACK_PLUGIN_VERSION_TEXT.to_owned(),
                BROWSERSTACK_SERVICE_ID.to_owned(),
                BROWSERSTACK_PROVIDER_ID.to_owned(),
                crate::MISSION_BROWSERSTACK_CONSUMER_ID.to_owned(),
                request.provider_revision.clone(),
                request.contract_digest.as_str().to_owned(),
                request.provider_digest.as_str().to_owned(),
                request.scope.digest().as_str().to_owned(),
                request.scope.permission().digest().as_str().to_owned(),
                request
                    .secret_reference
                    .reference_digest()
                    .as_str()
                    .to_owned(),
                revision.get().to_string(),
            ],
        );
        let registration = Self {
            schema_version: BROWSERSTACK_SCHEMA_VERSION.to_owned(),
            contract_version: BROWSERSTACK_CONTRACT_VERSION.to_owned(),
            plugin_version: BROWSERSTACK_PLUGIN_VERSION_TEXT.to_owned(),
            service_id: BROWSERSTACK_SERVICE_ID.to_owned(),
            provider_id: BROWSERSTACK_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_BROWSERSTACK_CONSUMER_ID.to_owned(),
            provider_revision: request.provider_revision.clone(),
            contract_digest: request.contract_digest.clone(),
            provider_digest: request.provider_digest.clone(),
            scope_digest: request.scope.digest().clone(),
            permission_digest: request.scope.permission().digest().clone(),
            secret_reference_digest: request.secret_reference.reference_digest().clone(),
            revision,
            registration_digest,
            state: RegistrationState::Active,
            shared: new_registration_shared_state(),
            live_seal: true,
        };
        registration.validate_identity()?;
        Ok(registration)
    }

    fn canonical_registration_digest(&self) -> Digest {
        Digest::from_fields(
            "browserstack-registration/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.plugin_version.clone(),
                self.service_id.clone(),
                self.provider_id.clone(),
                self.consumer_id.clone(),
                self.provider_revision.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub fn validate_identity(&self) -> Result<(), BrowserStackTestResultError> {
        let digests = [
            &self.contract_digest,
            &self.provider_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
            &self.registration_digest,
        ];
        if !self.live_seal
            || self.schema_version != BROWSERSTACK_SCHEMA_VERSION
            || self.contract_version != BROWSERSTACK_CONTRACT_VERSION
            || self.plugin_version != BROWSERSTACK_PLUGIN_VERSION_TEXT
            || self.service_id != BROWSERSTACK_SERVICE_ID
            || self.provider_id != BROWSERSTACK_PROVIDER_ID
            || self.consumer_id != crate::MISSION_BROWSERSTACK_CONSUMER_ID
            || self.provider_revision != BROWSERSTACK_PROVIDER_REVISION
            || self.revision.get() == 0
            || digests.iter().any(|digest| !digest.is_sha256())
            || self.registration_digest != self.canonical_registration_digest()
        {
            return Err(BrowserStackTestResultError::RegistrationDrift(
                "registration immutable identity or digest tuple is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    fn shared_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, RegistrationUseState>, BrowserStackTestResultError> {
        self.shared.use_state.lock().map_err(|_| {
            BrowserStackTestResultError::RegistrationDrift(
                "registration shared state is poisoned".to_owned(),
            )
        })
    }

    pub fn ensure_active(&self) -> Result<(), BrowserStackTestResultError> {
        self.validate_identity()?;
        if self.state != RegistrationState::Active || self.shared_state()?.revoked {
            Err(BrowserStackTestResultError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, BrowserStackTestResultError> {
        self.ensure_active()?;
        self.shared_state()?.revoked = true;
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "browserstack-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    pub fn validate_against(
        &self,
        scope: &BrowserStackScope,
        secret: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), BrowserStackTestResultError> {
        self.ensure_active()?;
        if self.scope_digest != *scope.digest()
            || self.permission_digest != *scope.permission().digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.provider_digest != *provider_digest
            || self.contract_digest != contract_digest()
            || self.provider_revision != BROWSERSTACK_PROVIDER_REVISION
        {
            return Err(BrowserStackTestResultError::RegistrationDrift(
                "registration is not bound to current scope, permission, secret, provider, or contract"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn claim_evidence_use(
        &self,
        evidence_digest: &Digest,
    ) -> Result<Revision, BrowserStackTestResultError> {
        self.validate_identity()?;
        let mut shared = self.shared_state()?;
        if self.state != RegistrationState::Active || shared.revoked {
            return Err(BrowserStackTestResultError::RegistrationRevoked);
        }
        if shared
            .consumed_evidence
            .contains_key(evidence_digest.as_str())
        {
            return Err(BrowserStackTestResultError::EvidenceReplay);
        }
        let revision = Revision::new(shared.next_use_revision).map_err(|_| {
            BrowserStackTestResultError::RegistrationDrift(
                "registration use revision overflowed".to_owned(),
            )
        })?;
        shared.next_use_revision = shared.next_use_revision.checked_add(1).ok_or_else(|| {
            BrowserStackTestResultError::RegistrationDrift(
                "registration use revision overflowed".to_owned(),
            )
        })?;
        shared
            .consumed_evidence
            .insert(evidence_digest.as_str().to_owned(), revision);
        Ok(revision)
    }

    pub(crate) fn validate_evidence_use(
        &self,
        evidence_digest: &Digest,
        use_revision: Revision,
    ) -> Result<(), BrowserStackTestResultError> {
        self.validate_identity()?;
        let shared = self.shared_state()?;
        if self.state != RegistrationState::Active || shared.revoked {
            return Err(BrowserStackTestResultError::RegistrationRevoked);
        }
        if shared.consumed_evidence.get(evidence_digest.as_str()) == Some(&use_revision) {
            Ok(())
        } else {
            Err(BrowserStackTestResultError::StaleEvidence)
        }
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

pub struct BrowserStackProvider<
    T = crate::RecordingBrowserStackTransport,
    R = BlockedEnvCredentialResolver,
> where
    T: BrowserStackTransport,
    R: BrowserStackCredentialResolver,
{
    service: BrowserStackTestResultService,
    scope: BrowserStackScope,
    secret_reference: SecretReference,
    definition: BrowserStackProviderDefinition,
    registration: BrowserStackRegistration,
    transport: T,
    credential_resolver: R,
    bounds: RequestBounds,
    attestation: BrowserStackTransportAttestation,
}

impl<T, R> fmt::Debug for BrowserStackProvider<T, R>
where
    T: BrowserStackTransport,
    R: BrowserStackCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserStackProvider")
            .field("scope_digest", &self.scope.digest())
            .field("provider_digest", &self.definition.provider_digest)
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("provenance", &self.attestation.provenance())
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T, R> BrowserStackProvider<T, R>
where
    T: BrowserStackTransport,
    R: BrowserStackCredentialResolver,
{
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        scope: BrowserStackScope,
        secret_reference: SecretReference,
        transport: T,
        credential_resolver: R,
    ) -> Result<Self, BrowserStackTestResultError> {
        let attestation = trusted_transport_attestation(&transport)?;
        let definition =
            BrowserStackProviderDefinition::new(scope.product(), attestation.provenance())?;
        let request = BrowserStackRegistrationRequest::baseline(
            scope.clone(),
            secret_reference.clone(),
            definition.provider_digest.clone(),
        )?;
        Self::from_registration_request(
            request,
            transport,
            credential_resolver,
            RequestBounds::default(),
        )
    }

    pub fn from_registration_request(
        request: BrowserStackRegistrationRequest,
        transport: T,
        credential_resolver: R,
        bounds: RequestBounds,
    ) -> Result<Self, BrowserStackTestResultError> {
        bounds.validate()?;
        let attestation = trusted_transport_attestation(&transport)?;
        let definition =
            BrowserStackProviderDefinition::new(request.scope.product(), attestation.provenance())?;
        if request.provider_digest != definition.provider_digest {
            return Err(BrowserStackTestResultError::RegistrationDrift(
                "registration provider digest does not match the transport definition".to_owned(),
            ));
        }
        let registration = BrowserStackRegistration::new(&request)?;
        let service = BrowserStackTestResultService::new();
        service.validate()?;
        definition.validate()?;
        Ok(Self {
            service,
            scope: request.scope,
            secret_reference: request.secret_reference,
            definition,
            registration,
            transport,
            credential_resolver,
            bounds,
            attestation,
        })
    }

    pub fn service(&self) -> &BrowserStackTestResultService {
        &self.service
    }

    pub fn scope(&self) -> &BrowserStackScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn definition(&self) -> &BrowserStackProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    pub fn registration(&self) -> &BrowserStackRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn bounds(&self) -> RequestBounds {
        self.bounds
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, BrowserStackTestResultError> {
        self.registration.revoke()
    }

    pub fn propose(
        &self,
        request: BrowserStackReadRequest,
    ) -> Result<BrowserStackReadProposal, BrowserStackTestResultError> {
        self.registration.validate_against(
            &self.scope,
            &self.secret_reference,
            self.provider_digest(),
        )?;
        if self.secret_reference.is_revoked() {
            return Err(BrowserStackTestResultError::SecretRevoked);
        }
        if !self.scope.permission().allows_product(self.scope.product()) {
            return Err(BrowserStackTestResultError::ScopeMismatch(
                "permission snapshot does not allow bounded BrowserStack build/session reads"
                    .to_owned(),
            ));
        }
        if request
            .expected_build_revision
            .is_some_and(|revision| revision != self.scope.build_revision().get())
            || request.expected_session_revision.is_some_and(|revision| {
                self.scope.session_revision() != Revision::new(revision).ok()
            })
        {
            return Err(BrowserStackTestResultError::ScopeMismatch(
                "read proposal revision fence differs from registration scope".to_owned(),
            ));
        }
        BrowserStackReadProposal::new(
            &self.scope,
            request,
            self.bounds,
            self.registration.registration_digest.clone(),
            self.definition.provider_digest.clone(),
        )
        .map_err(Into::into)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(
        &mut self,
        proposal: &BrowserStackReadProposal,
        at: DateTime<Utc>,
    ) -> Result<BrowserStackTestResultEvidence, BrowserStackTestResultError> {
        self.validate_proposal(proposal)?;
        if self.secret_reference.is_revoked() {
            return Err(BrowserStackTestResultError::SecretRevoked);
        }
        let credential = match self.credential_resolver.resolve(&self.secret_reference, at) {
            Ok(credential) => credential,
            Err(error) => {
                let (status, partial_reason) = match error {
                    crate::BrowserStackCredentialError::BlockedEnv => {
                        (EvidenceStatus::ProviderUnknown, None)
                    }
                    crate::BrowserStackCredentialError::Revoked => {
                        return Err(BrowserStackTestResultError::SecretRevoked);
                    }
                    _ => (EvidenceStatus::AccessLost, None),
                };
                let blocked_env = matches!(&error, crate::BrowserStackCredentialError::BlockedEnv);
                return self.failure_evidence(
                    proposal,
                    status,
                    partial_reason,
                    ProviderFailure::new(
                        if blocked_env {
                            FailureClass::BlockedEnv
                        } else {
                            FailureClass::AccessLoss
                        },
                        None,
                        false,
                        error.to_string(),
                    ),
                    Vec::new(),
                    None,
                    Vec::new(),
                );
            }
        };
        credential.validate_at(&self.secret_reference, at)?;

        let build_request = BrowserStackHttpRequest::new(
            BrowserStackEndpoint::Build {
                product: self.scope.product(),
                project_id: self.scope.browserstack_project_id().to_owned(),
                build_id: self.scope.build_id().to_owned(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let mut receipts = Vec::new();
        let build_response = match self.execute(&credential, &build_request) {
            Ok(response) => response,
            Err(error) => {
                return self.failure_from_transport(
                    proposal,
                    &build_request,
                    &error,
                    receipts,
                    None,
                    Vec::new(),
                );
            }
        };
        receipts.push(build_response.receipt().clone());
        self.validate_response(&build_response, &build_request)?;
        if build_response.status() != 200 {
            return self.failure_from_http(proposal, &build_response, receipts, None, Vec::new());
        }
        let Some(BrowserStackResponseBody::Build(build_payload)) = build_response.body() else {
            return Err(BrowserStackTestResultError::Decode(
                "build endpoint returned a non-build body".to_owned(),
            ));
        };
        self.validate_build(build_payload, &proposal.request)?;
        let build_projection = BrowserStackBuildProjection::from(build_payload.clone());

        let mut sessions = Vec::new();
        let mut page = 0_u16;
        let mut offset = 0_u32;
        let mut seen_offsets = std::collections::BTreeSet::new();
        let mut seen_page_digests = std::collections::BTreeSet::new();
        let mut session_found = false;
        let mut partial_reason = None;
        let mut failures = Vec::new();
        loop {
            if page >= self.bounds.max_pages {
                partial_reason = Some(PartialReason::PageBound);
                failures.push(ProviderFailure::new(
                    FailureClass::Partial,
                    None,
                    false,
                    "session page bound exceeded",
                ));
                break;
            }
            if !seen_offsets.insert(offset) {
                return Err(BrowserStackTestResultError::PaginationLoop);
            }
            let sessions_request = BrowserStackHttpRequest::new(
                BrowserStackEndpoint::Sessions {
                    product: self.scope.product(),
                    project_id: self.scope.browserstack_project_id().to_owned(),
                    build_id: self.scope.build_id().to_owned(),
                    offset,
                    limit: self.bounds.page_size,
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = match self.execute(&credential, &sessions_request) {
                Ok(response) => response,
                Err(error) => {
                    return self.failure_from_transport(
                        proposal,
                        &sessions_request,
                        &error,
                        receipts,
                        Some(build_projection),
                        sessions,
                    );
                }
            };
            receipts.push(response.receipt().clone());
            self.validate_response(&response, &sessions_request)?;
            if response.status() != 200 {
                return self.failure_from_http(
                    proposal,
                    &response,
                    receipts,
                    Some(build_projection),
                    sessions,
                );
            }
            let Some(BrowserStackResponseBody::Sessions(page_sessions)) = response.body() else {
                return Err(BrowserStackTestResultError::Decode(
                    "session endpoint returned a non-session body".to_owned(),
                ));
            };
            if page_sessions.len() > self.bounds.page_size as usize {
                return Err(BrowserStackTestResultError::Decode(
                    "recorded session page exceeds its request limit".to_owned(),
                ));
            }
            let page_digest = crate::model::digest_serializable(page_sessions)?;
            if !seen_page_digests.insert(page_digest) {
                return Err(BrowserStackTestResultError::PaginationLoop);
            }
            for payload in page_sessions {
                if sessions.len() >= self.bounds.max_sessions {
                    return Err(BrowserStackTestResultError::SessionBoundExceeded);
                }
                self.validate_session(payload, &proposal.request)?;
                let matches_target = self
                    .scope
                    .session_id()
                    .is_none_or(|session_id| session_id == payload.id);
                if matches_target {
                    session_found = session_found || self.scope.session_id().is_some();
                    sessions.push(BrowserStackSessionProjection::from(payload.clone()));
                }
            }
            page += 1;
            if self.scope.session_id().is_some() && session_found {
                break;
            }
            if page_sessions.len() < self.bounds.page_size as usize {
                break;
            }
            let increment = u32::try_from(page_sessions.len())
                .map_err(|error| BrowserStackTestResultError::InvalidInput(error.to_string()))?;
            offset = offset
                .checked_add(increment)
                .ok_or(BrowserStackTestResultError::PaginationLoop)?;
        }

        if self.scope.session_id().is_some() && !session_found {
            return Err(BrowserStackTestResultError::SessionNotFound);
        }

        if let Some(session_id) = self.scope.session_id()
            && let Some(existing) = sessions.first().cloned()
        {
            let detail_request = BrowserStackHttpRequest::new(
                BrowserStackEndpoint::Session {
                    product: self.scope.product(),
                    project_id: self.scope.browserstack_project_id().to_owned(),
                    build_id: self.scope.build_id().to_owned(),
                    session_id: session_id.to_owned(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = match self.execute(&credential, &detail_request) {
                Ok(response) => response,
                Err(error) => {
                    partial_reason = Some(PartialReason::MissingSessionDetail);
                    failures.push(ProviderFailure::new(
                        transport_failure_class(&error),
                        error.status_code(),
                        error.retryable(),
                        error.diagnostic_digest().as_str(),
                    ));
                    sessions = vec![existing];
                    let status = EvidenceStatus::Partial;
                    return BrowserStackTestResultEvidence::new(
                        contract_digest(),
                        self.definition.provider_digest.clone(),
                        self.scope.digest().clone(),
                        self.scope.permission().digest().clone(),
                        self.registration.registration_digest.clone(),
                        self.attestation.provenance(),
                        status,
                        partial_reason,
                        Some(build_projection),
                        sessions,
                        failures,
                        receipts,
                    )
                    .map_err(Into::into);
                }
            };
            receipts.push(response.receipt().clone());
            self.validate_response(&response, &detail_request)?;
            if response.status() != 200 {
                partial_reason = Some(PartialReason::MissingSessionDetail);
                failures.push(status_failure(response.status()));
            } else if let Some(BrowserStackResponseBody::Session(payload)) = response.body() {
                self.validate_session(payload, &proposal.request)?;
                sessions = vec![BrowserStackSessionProjection::from(payload.clone())];
            } else {
                return Err(BrowserStackTestResultError::Decode(
                    "session detail endpoint returned a non-session body".to_owned(),
                ));
            }
        }

        let status = if partial_reason.is_some() {
            EvidenceStatus::Partial
        } else {
            EvidenceStatus::Complete
        };
        BrowserStackTestResultEvidence::new(
            contract_digest(),
            self.definition.provider_digest.clone(),
            self.scope.digest().clone(),
            self.scope.permission().digest().clone(),
            self.registration.registration_digest.clone(),
            self.attestation.provenance(),
            status,
            partial_reason,
            Some(build_projection),
            sessions,
            failures,
            receipts,
        )
        .map_err(Into::into)
    }

    pub fn record_evidence(
        &self,
        proposal: &BrowserStackReadProposal,
        evidence: BrowserStackTestResultEvidence,
    ) -> Result<BrowserStackTestResultEvidence, BrowserStackTestResultError> {
        self.validate_proposal(proposal)?;
        evidence.validate()?;
        if evidence.contract_digest != contract_digest()
            || evidence.provider_digest != *self.provider_digest()
            || evidence.scope_digest != *self.scope.digest()
            || evidence.permission_digest != *self.scope.permission().digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provenance != self.attestation.provenance()
        {
            return Err(BrowserStackTestResultError::StaleEvidence);
        }
        Ok(evidence)
    }

    fn validate_proposal(
        &self,
        proposal: &BrowserStackReadProposal,
    ) -> Result<(), BrowserStackTestResultError> {
        self.registration.validate_against(
            &self.scope,
            &self.secret_reference,
            self.provider_digest(),
        )?;
        proposal.verify_integrity()?;
        if proposal.contract_digest != contract_digest()
            || proposal.provider_digest != *self.provider_digest()
            || proposal.scope_digest != *self.scope.digest()
            || proposal.permission_digest != *self.scope.permission().digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_revision != BROWSERSTACK_PROVIDER_REVISION
            || proposal.bounds != self.bounds
        {
            return Err(BrowserStackTestResultError::RegistrationDigestMismatch);
        }
        proposal.bounds.validate()?;
        Ok(())
    }

    fn execute(
        &mut self,
        credential: &BrowserStackCredentialLease,
        request: &BrowserStackHttpRequest,
    ) -> Result<BrowserStackHttpResponse, BrowserStackTransportError> {
        self.transport.execute(credential, request)
    }

    fn validate_response(
        &self,
        response: &BrowserStackHttpResponse,
        request: &BrowserStackHttpRequest,
    ) -> Result<(), BrowserStackTestResultError> {
        response.validate_against(request)?;
        if response.receipt().provider_revision != BROWSERSTACK_PROVIDER_REVISION {
            return Err(BrowserStackTestResultError::ProviderRevisionDrift {
                expected: BROWSERSTACK_PROVIDER_REVISION.to_owned(),
                actual: response.receipt().provider_revision.clone(),
            });
        }
        if response.receipt().response_size > self.bounds.max_response_bytes {
            return Err(BrowserStackTestResultError::ResponseTooLarge {
                size: response.receipt().response_size,
            });
        }
        Ok(())
    }

    fn validate_build(
        &self,
        payload: &BrowserStackBuildPayload,
        request: &BrowserStackReadRequest,
    ) -> Result<(), BrowserStackTestResultError> {
        payload.validate()?;
        if payload.id != self.scope.build_id() {
            return Err(BrowserStackTestResultError::BuildNotFound);
        }
        if payload.product != self.scope.product()
            || payload
                .project_id
                .as_deref()
                .is_some_and(|project| project != self.scope.browserstack_project_id())
        {
            return Err(BrowserStackTestResultError::ProductOrProjectMismatch);
        }
        if payload.revision != self.scope.build_revision()
            || request
                .expected_build_revision
                .is_some_and(|revision| revision != payload.revision.get())
        {
            return Err(BrowserStackTestResultError::BuildRevisionMismatch);
        }
        validate_commit_artifact(
            self.scope.commit(),
            self.scope.artifact(),
            payload.commit.as_deref(),
            payload.artifact.as_deref(),
        )?;
        Ok(())
    }

    fn validate_session(
        &self,
        payload: &BrowserStackSessionPayload,
        request: &BrowserStackReadRequest,
    ) -> Result<(), BrowserStackTestResultError> {
        payload.validate()?;
        if payload.build_id != self.scope.build_id()
            || payload.product != self.scope.product()
            || payload
                .project_id
                .as_deref()
                .is_some_and(|project| project != self.scope.browserstack_project_id())
        {
            return Err(BrowserStackTestResultError::ProductOrProjectMismatch);
        }
        if self
            .scope
            .session_id()
            .is_some_and(|session_id| session_id != payload.id)
        {
            return Err(BrowserStackTestResultError::SessionNotFound);
        }
        if self.scope.session_revision().is_some_and(|revision| {
            payload.revision != revision
                || request
                    .expected_session_revision
                    .is_some_and(|expected| expected != payload.revision.get())
        }) {
            return Err(BrowserStackTestResultError::SessionRevisionMismatch);
        }
        validate_commit_artifact(
            self.scope.commit(),
            self.scope.artifact(),
            payload.commit.as_deref(),
            payload.artifact.as_deref(),
        )?;
        if payload.outcomes.total > self.bounds.max_outcome_count {
            return Err(BrowserStackTestResultError::OutcomeBoundExceeded);
        }
        Ok(())
    }

    fn failure_from_transport(
        &self,
        proposal: &BrowserStackReadProposal,
        request: &BrowserStackHttpRequest,
        error: &BrowserStackTransportError,
        mut receipts: Vec<BrowserStackResponseReceipt>,
        build: Option<BrowserStackBuildProjection>,
        sessions: Vec<BrowserStackSessionProjection>,
    ) -> Result<BrowserStackTestResultEvidence, BrowserStackTestResultError> {
        receipts.push(failure_receipt(request, error)?);
        let (status, partial_reason) = if error.timeout() {
            (EvidenceStatus::Partial, Some(PartialReason::Timeout))
        } else {
            (EvidenceStatus::ProviderUnknown, None)
        };
        self.failure_evidence(
            proposal,
            status,
            partial_reason,
            ProviderFailure::new(
                transport_failure_class(error),
                error.status_code(),
                error.retryable(),
                error.diagnostic_digest().as_str(),
            ),
            receipts,
            build,
            sessions,
        )
    }

    fn failure_from_http(
        &self,
        proposal: &BrowserStackReadProposal,
        response: &BrowserStackHttpResponse,
        receipts: Vec<BrowserStackResponseReceipt>,
        build: Option<BrowserStackBuildProjection>,
        sessions: Vec<BrowserStackSessionProjection>,
    ) -> Result<BrowserStackTestResultEvidence, BrowserStackTestResultError> {
        let status_code = response.status();
        let failure = status_failure(status_code);
        let (status, partial_reason) = match status_code {
            401 | 403 | 404 => (EvidenceStatus::AccessLost, None),
            429 => (EvidenceStatus::Partial, Some(PartialReason::RateLimited)),
            _ => (EvidenceStatus::ProviderUnknown, None),
        };
        self.failure_evidence(
            proposal,
            status,
            partial_reason,
            failure,
            receipts,
            build,
            sessions,
        )
    }

    fn failure_evidence(
        &self,
        _proposal: &BrowserStackReadProposal,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        failure: ProviderFailure,
        receipts: Vec<BrowserStackResponseReceipt>,
        build: Option<BrowserStackBuildProjection>,
        sessions: Vec<BrowserStackSessionProjection>,
    ) -> Result<BrowserStackTestResultEvidence, BrowserStackTestResultError> {
        BrowserStackTestResultEvidence::new(
            contract_digest(),
            self.definition.provider_digest.clone(),
            self.scope.digest().clone(),
            self.scope.permission().digest().clone(),
            self.registration.registration_digest.clone(),
            self.attestation.provenance(),
            status,
            partial_reason,
            build,
            sessions,
            vec![failure],
            receipts,
        )
        .map_err(Into::into)
    }
}

fn validate_commit_artifact(
    expected_commit: Option<&str>,
    expected_artifact: Option<&str>,
    observed_commit: Option<&str>,
    observed_artifact: Option<&str>,
) -> Result<(), BrowserStackTestResultError> {
    if expected_commit.is_some_and(|expected| observed_commit != Some(expected)) {
        return Err(BrowserStackTestResultError::CommitMismatch);
    }
    if expected_artifact.is_some_and(|expected| observed_artifact != Some(expected)) {
        return Err(BrowserStackTestResultError::ArtifactMismatch);
    }
    Ok(())
}

fn status_failure(status: u16) -> ProviderFailure {
    let (class, retryable) = match status {
        401 => (FailureClass::Unauthorized, false),
        403 => (FailureClass::Forbidden, false),
        404 => (FailureClass::Deleted, false),
        409 => (FailureClass::Conflict, true),
        429 => (FailureClass::RateLimited, true),
        500..=599 => (FailureClass::ServerFailure, true),
        _ => (FailureClass::ProviderUnknown, false),
    };
    ProviderFailure::new(class, Some(status), retryable, format!("http-{status}"))
}

fn transport_failure_class(error: &BrowserStackTransportError) -> FailureClass {
    if matches!(error, BrowserStackTransportError::BlockedEnv) {
        FailureClass::BlockedEnv
    } else if error.timeout() {
        FailureClass::Timeout
    } else if error.status_code() == Some(429) {
        FailureClass::RateLimited
    } else if error.status_code().is_some_and(|status| status == 401) {
        FailureClass::Unauthorized
    } else if error.status_code().is_some_and(|status| status == 403) {
        FailureClass::Forbidden
    } else if error.status_code().is_some_and(|status| status == 404) {
        FailureClass::Deleted
    } else if error
        .status_code()
        .is_some_and(|status| (500..=599).contains(&status))
    {
        FailureClass::ServerFailure
    } else {
        FailureClass::Transport
    }
}

fn failure_receipt(
    request: &BrowserStackHttpRequest,
    error: &BrowserStackTransportError,
) -> Result<BrowserStackResponseReceipt, BrowserStackTestResultError> {
    let response =
        BrowserStackHttpResponse::from_status(request, error.status_code().unwrap_or(0))?;
    Ok(response.receipt().clone())
}
