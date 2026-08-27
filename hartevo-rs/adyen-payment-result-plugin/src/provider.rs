use std::{env, fmt, sync::Arc};

use crate::error::{AdyenPaymentResultError, AdyenPaymentTransportError, Result};
use crate::model::{
    AdyenPaymentEvidence, AdyenPaymentProjection, AdyenPaymentReadMode, AdyenPaymentRegistration,
    AdyenPaymentResultProposal, AdyenPaymentScope, AdyenPaymentStatus, ProviderProvenance,
    RegistrationRevocation, RegistrationStatus, SecretReference,
};
use crate::transport::{AdyenPaymentTransport, SecretMaterial};

pub const ADYEN_API_KEY_ENVIRONMENT_VARIABLE: &str = "HARTEVO_ADYEN_API_KEY";

/// Credential resolution is host-provided and returns opaque, zeroized
/// material only for the duration of a bounded GET call.
pub trait AdyenCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<SecretMaterial>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl AdyenCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<SecretMaterial> {
        Err(AdyenPaymentResultError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentAdyenCredentialResolver;

impl AdyenCredentialResolver for EnvironmentAdyenCredentialResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<SecretMaterial> {
        if reference.is_revoked() {
            return Err(AdyenPaymentResultError::RegistrationRevoked);
        }
        let value = env::var(ADYEN_API_KEY_ENVIRONMENT_VARIABLE)
            .map_err(|_| AdyenPaymentResultError::BlockedEnv)?;
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(AdyenPaymentResultError::BlockedEnv);
        }
        Ok(SecretMaterial::new(value))
    }
}

#[derive(Clone)]
pub struct StaticAdyenCredentialResolver {
    material: Arc<SecretMaterial>,
}

impl fmt::Debug for StaticAdyenCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticAdyenCredentialResolver")
            .field("material", &self.material)
            .finish()
    }
}

impl StaticAdyenCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: Arc::new(SecretMaterial::new(value)),
        }
    }
}

impl AdyenCredentialResolver for StaticAdyenCredentialResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<SecretMaterial> {
        if reference.is_revoked() {
            Err(AdyenPaymentResultError::RegistrationRevoked)
        } else if self.material.as_str().trim().is_empty()
            || self.material.as_str().chars().any(char::is_control)
        {
            Err(AdyenPaymentResultError::BlockedEnv)
        } else {
            Ok((*self.material).clone())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdyenProviderState {
    Registered,
    ReadOnlyAvailable,
    Recording,
    Fake,
    Fixture,
    Loopback,
    BlockedEnv,
    Unauthorized,
    Forbidden,
    NotFoundOrUnauthorized,
    Conflict,
    RateLimited,
    ServerUnavailable,
    Timeout,
    ProviderUnknown,
    Revoked,
}

/// Typed provider for bounded Adyen payment retrieval/status evidence.
#[derive(Debug)]
pub struct AdyenPaymentsProvider<T, R>
where
    T: AdyenPaymentTransport,
    R: AdyenCredentialResolver,
{
    registration: AdyenPaymentRegistration,
    transport: T,
    credentials: R,
    state: AdyenProviderState,
    provider_revision: u64,
    last_payment_identity: Option<crate::Digest>,
    last_status: Option<AdyenPaymentStatus>,
}

impl<T, R> AdyenPaymentsProvider<T, R>
where
    T: AdyenPaymentTransport,
    R: AdyenCredentialResolver,
{
    pub fn new(
        registration: AdyenPaymentRegistration,
        transport: T,
        credentials: R,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active
            || registration.secret_reference().is_revoked()
        {
            return Err(AdyenPaymentResultError::RegistrationRevoked);
        }
        Ok(Self {
            registration,
            state: state_for_provenance(transport.provenance()),
            transport,
            credentials,
            provider_revision: 1,
            last_payment_identity: None,
            last_status: None,
        })
    }

    pub fn registration(&self) -> &AdyenPaymentRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AdyenPaymentRegistration {
        &mut self.registration
    }

    pub fn scope(&self) -> &AdyenPaymentScope {
        &self.registration.scope
    }

    pub fn state(&self) -> AdyenProviderState {
        self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn is_native(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn retrieve_payment(&mut self) -> Result<AdyenPaymentProjection> {
        self.read_projection(AdyenPaymentReadMode::PaymentLink, false)
    }

    pub fn read_payment_status(&mut self) -> Result<AdyenPaymentProjection> {
        self.read_projection(AdyenPaymentReadMode::Session, true)
    }

    pub fn read_evidence(&mut self) -> Result<AdyenPaymentEvidence> {
        let payment = self.read_projection(AdyenPaymentReadMode::PaymentLink, false)?;
        let status = self.read_projection(AdyenPaymentReadMode::Session, true)?;
        if payment.merchant_account != status.merchant_account
            || payment.account_id != status.account_id
            || payment.payment_reference != status.payment_reference
            || payment.amount != status.amount
            || payment.customer_fingerprint != status.customer_fingerprint
        {
            return Err(AdyenPaymentResultError::SamePaymentReplacement);
        }
        let mut combined = status;
        combined.payment_method_digest = payment.payment_method_digest;
        combined.created_timestamp_digest = payment.created_timestamp_digest;
        combined.reconciliation_digest = crate::Digest::from_parts(
            "hartevo-adyen-reconciliation-combined/v1",
            &[
                ("payment", payment.reconciliation_digest.as_str().to_owned()),
                ("status", combined.reconciliation_digest.as_str().to_owned()),
            ],
        );
        combined.projection_digest = crate::Digest::pending();
        combined.projection_digest = combined.compute_projection_digest_for_provider();
        combined.validate(self.scope())?;
        let evidence = AdyenPaymentEvidence::new(
            self.scope().clone(),
            combined,
            self.registration.registration_digest().clone(),
            self.provider_revision,
        )?;
        Ok(evidence)
    }

    pub fn record_payment_receipt(
        &self,
        evidence: &AdyenPaymentEvidence,
        recorded_at_ms: u64,
    ) -> Result<crate::AdyenPaymentReceipt> {
        self.ensure_active()?;
        if evidence.registration_digest != *self.registration.registration_digest() {
            return Err(AdyenPaymentResultError::RegistrationDigestMismatch);
        }
        evidence.validate()?;
        crate::AdyenPaymentReceipt::new(evidence, recorded_at_ms)
    }

    pub fn compile_payment_result_proposal(
        &self,
        evidence: &AdyenPaymentEvidence,
        receipt: &crate::AdyenPaymentReceipt,
    ) -> Result<AdyenPaymentResultProposal> {
        self.ensure_active()?;
        if evidence.registration_digest != *self.registration.registration_digest() {
            return Err(AdyenPaymentResultError::RegistrationDigestMismatch);
        }
        crate::AdyenPaymentResultProposal::new(evidence, receipt)
    }

    pub fn verify_payment_result(
        &self,
        proposal: &AdyenPaymentResultProposal,
        evidence: &AdyenPaymentEvidence,
        receipt: &crate::AdyenPaymentReceipt,
    ) -> Result<AdyenPaymentResultProposal> {
        self.ensure_active()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || receipt.registration_digest != *self.registration.registration_digest()
        {
            return Err(AdyenPaymentResultError::RegistrationDigestMismatch);
        }
        proposal.validate(evidence, receipt)?;
        Ok(proposal.clone())
    }

    pub fn read_back_and_verify(
        &mut self,
        evidence: &AdyenPaymentEvidence,
    ) -> Result<crate::AdyenReadBackVerification> {
        self.ensure_active()?;
        let read_back = self.read_evidence()?;
        crate::AdyenReadBackVerification::new(evidence, &read_back)
    }

    pub fn revoke(&mut self, revoked_at_ms: u64) -> Result<RegistrationRevocation> {
        let revocation = self.registration.revoke(revoked_at_ms)?;
        self.state = AdyenProviderState::Revoked;
        self.provider_revision = self.provider_revision.saturating_add(1);
        Ok(revocation)
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(AdyenPaymentResultError::MutationForbidden { operation })
    }

    fn read_projection(
        &mut self,
        mode: AdyenPaymentReadMode,
        is_status_read: bool,
    ) -> Result<AdyenPaymentProjection> {
        self.ensure_active()?;
        let credential = self
            .credentials
            .resolve(self.registration.secret_reference())
            .map_err(|error| {
                if matches!(error, AdyenPaymentResultError::BlockedEnv) {
                    self.state = AdyenProviderState::BlockedEnv;
                }
                error
            })?;
        let record = if is_status_read {
            self.transport
                .read_payment_status(&credential, self.scope(), mode)
        } else {
            self.transport
                .retrieve_payment(&credential, self.scope(), mode)
        }
        .map_err(|error| self.map_transport_error(error))?;
        let projection = AdyenPaymentProjection::from_api(
            &record,
            self.scope(),
            self.transport.provenance(),
            self.provider_revision,
        )?;
        self.ensure_identity(&projection)?;
        self.ensure_status_transition(projection.status)?;
        self.state = state_for_status(projection.status, self.transport.provenance());
        Ok(projection)
    }

    fn ensure_active(&self) -> Result<()> {
        if !self.registration.is_active() || self.state == AdyenProviderState::Revoked {
            Err(AdyenPaymentResultError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }

    fn ensure_identity(&mut self, projection: &AdyenPaymentProjection) -> Result<()> {
        let identity = crate::Digest::from_parts(
            "hartevo-adyen-payment-identity/v1",
            &[
                (
                    "merchant_account",
                    projection.merchant_account.as_str().to_owned(),
                ),
                ("account_id", projection.account_id.as_str().to_owned()),
                (
                    "payment_reference",
                    projection.payment_reference.as_str().to_owned(),
                ),
                ("amount", projection.amount.digest().as_str().to_owned()),
                (
                    "customer_fingerprint",
                    projection.customer_fingerprint.digest().as_str().to_owned(),
                ),
            ],
        );
        if self
            .last_payment_identity
            .as_ref()
            .is_some_and(|previous| previous != &identity)
        {
            self.state = AdyenProviderState::ProviderUnknown;
            return Err(AdyenPaymentResultError::SamePaymentReplacement);
        }
        self.last_payment_identity = Some(identity);
        Ok(())
    }

    fn ensure_status_transition(&mut self, status: AdyenPaymentStatus) -> Result<()> {
        if let Some(previous) = self.last_status {
            if status != previous && status.rank() < previous.rank() {
                self.state = AdyenProviderState::ProviderUnknown;
                return Err(AdyenPaymentResultError::StatusRegression);
            }
            if previous.is_terminal() && status != previous {
                self.state = AdyenProviderState::ProviderUnknown;
                return Err(AdyenPaymentResultError::InvalidStatusTransition);
            }
        }
        self.last_status = Some(status);
        Ok(())
    }

    fn map_transport_error(
        &mut self,
        error: AdyenPaymentTransportError,
    ) -> AdyenPaymentResultError {
        self.state = match error {
            AdyenPaymentTransportError::Unauthorized => AdyenProviderState::Unauthorized,
            AdyenPaymentTransportError::Forbidden => AdyenProviderState::Forbidden,
            AdyenPaymentTransportError::NotFoundOrUnauthorized => {
                AdyenProviderState::NotFoundOrUnauthorized
            }
            AdyenPaymentTransportError::Conflict => AdyenProviderState::Conflict,
            AdyenPaymentTransportError::RateLimited { .. } => AdyenProviderState::RateLimited,
            AdyenPaymentTransportError::ServerUnavailable => AdyenProviderState::ServerUnavailable,
            AdyenPaymentTransportError::Timeout => AdyenProviderState::Timeout,
            AdyenPaymentTransportError::NotFound
            | AdyenPaymentTransportError::Network
            | AdyenPaymentTransportError::Decode
            | AdyenPaymentTransportError::ResponseTooLarge
            | AdyenPaymentTransportError::InvalidConfiguration => self.state,
        };
        error.into()
    }
}

fn state_for_provenance(provenance: ProviderProvenance) -> AdyenProviderState {
    match provenance {
        ProviderProvenance::OfficialHttps => AdyenProviderState::ReadOnlyAvailable,
        ProviderProvenance::Recording => AdyenProviderState::Recording,
        ProviderProvenance::Fake => AdyenProviderState::Fake,
        ProviderProvenance::Fixture => AdyenProviderState::Fixture,
        ProviderProvenance::Loopback => AdyenProviderState::Loopback,
        ProviderProvenance::BlockedEnv => AdyenProviderState::BlockedEnv,
    }
}

fn state_for_status(
    status: AdyenPaymentStatus,
    provenance: ProviderProvenance,
) -> AdyenProviderState {
    if matches!(provenance, ProviderProvenance::Recording) {
        return AdyenProviderState::Recording;
    }
    if matches!(provenance, ProviderProvenance::Fake) {
        return AdyenProviderState::Fake;
    }
    if matches!(provenance, ProviderProvenance::Fixture) {
        return AdyenProviderState::Fixture;
    }
    if matches!(provenance, ProviderProvenance::Loopback) {
        return AdyenProviderState::Loopback;
    }
    match status {
        AdyenPaymentStatus::Unknown => AdyenProviderState::ProviderUnknown,
        _ => AdyenProviderState::ReadOnlyAvailable,
    }
}

trait ProjectionDigestForProvider {
    fn compute_projection_digest_for_provider(&self) -> crate::Digest;
}

impl ProjectionDigestForProvider for AdyenPaymentProjection {
    fn compute_projection_digest_for_provider(&self) -> crate::Digest {
        crate::Digest::from_parts(
            "hartevo-adyen-payment-projection/v1",
            &[
                (
                    "merchant_account",
                    self.merchant_account.as_str().to_owned(),
                ),
                ("account_id", self.account_id.as_str().to_owned()),
                (
                    "payment_reference",
                    self.payment_reference.as_str().to_owned(),
                ),
                ("amount", self.amount.digest().as_str().to_owned()),
                ("status", self.status_digest.as_str().to_owned()),
                (
                    "customer_fingerprint",
                    self.customer_fingerprint.digest().as_str().to_owned(),
                ),
                (
                    "payment_method",
                    self.payment_method_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "created_at",
                    self.created_timestamp_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "updated_at",
                    self.updated_timestamp_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "reconciliation",
                    self.reconciliation_digest.as_str().to_owned(),
                ),
                ("provenance", format!("{:?}", self.provenance)),
                ("native_connected", self.native_connected.to_string()),
                ("provider_revision", self.provider_revision.to_string()),
            ],
        )
    }
}

pub type AdyenRecordingProvider =
    AdyenPaymentsProvider<crate::AdyenRecordingTransport, StaticAdyenCredentialResolver>;

// Keep the public transport error import used by downstream type aliases
// without exposing any raw response content.
#[allow(dead_code)]
fn _transport_error_marker(_error: AdyenPaymentTransportError) {}
