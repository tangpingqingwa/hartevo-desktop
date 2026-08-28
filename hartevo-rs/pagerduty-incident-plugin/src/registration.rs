//! Reversible, scope-bound plugin registration.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ApiRegion, Digest, PagerDutyScope, SecretKind, SecretReference, Timestamp, canonical_digest,
};

pub const PLUGIN_ID: &str = "hartevo.pagerduty-incident";
pub const SERVICE_ID: &str = "pagerduty.incident";
pub const PROVIDER_ID: &str = "pagerduty-incident";
pub const CONSUMER_ID: &str = "mission.pagerduty-incident";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.pagerduty-incident.contract/v1";
pub const CONTRACT_VERSION: &str = "pagerduty-incident-layer1/v1";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/pagerduty-incident/pagerduty-incident.v1.json");

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_JSON)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("registration identifier or plugin version is invalid")]
    InvalidMetadata,
    #[error("registration contract digest does not match the Layer-1 contract")]
    ContractDigestMismatch,
    #[error("registration provider identifier is invalid")]
    ProviderMismatch,
    #[error("registration provider revision is invalid")]
    InvalidProviderRevision,
    #[error("registration secret reference is not an API token or OAuth reference")]
    InvalidAuthReference,
    #[error("registration secret reference scope does not match the exact scope")]
    SecretScopeMismatch,
    #[error("an active registration already exists")]
    ActiveRegistration,
    #[error("registration does not exist")]
    UnknownRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration digest does not match its immutable registration fields")]
    DigestMismatch,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationAction {
    Registered,
    Revoked,
    Restored,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationLifecycle {
    Active,
    Revoked { at: Timestamp },
}

impl RegistrationLifecycle {
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationSpec {
    pub registration_id: String,
    pub plugin_version: String,
    pub contract_digest: Digest,
    pub provider_revision: u64,
    pub scope: PagerDutyScope,
    pub secret_reference: SecretReference,
}

impl RegistrationSpec {
    pub fn validate(&self) -> Result<(), RegistrationError> {
        if self.registration_id.is_empty()
            || self.registration_id.len() > 128
            || self.plugin_version.is_empty()
            || self.plugin_version.len() > 64
        {
            return Err(RegistrationError::InvalidMetadata);
        }
        if self.contract_digest != contract_digest() {
            return Err(RegistrationError::ContractDigestMismatch);
        }
        if self.provider_revision == 0 {
            return Err(RegistrationError::InvalidProviderRevision);
        }
        if self.secret_reference.scope_digest() != &self.scope.digest() {
            return Err(RegistrationError::SecretScopeMismatch);
        }
        if !matches!(
            self.secret_reference.kind(),
            SecretKind::ApiToken | SecretKind::OAuthAccessToken
        ) {
            return Err(RegistrationError::InvalidAuthReference);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PagerDutyRegistration {
    pub registration_id: String,
    pub plugin_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: u64,
    pub scope: PagerDutyScope,
    pub secret_reference: SecretReference,
    pub lifecycle: RegistrationLifecycle,
    pub registration_revision: u64,
    pub registration_digest: Digest,
}

impl PagerDutyRegistration {
    pub fn validate_integrity(&self) -> Result<(), RegistrationError> {
        if self.registration_digest != registration_digest(self) {
            return Err(RegistrationError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub action: RegistrationAction,
    pub registration_id: String,
    pub registration_revision: u64,
    pub provider_id: String,
    pub provider_revision: u64,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub at: Timestamp,
}

#[derive(Clone, Debug, Default)]
pub struct RegistrationRegistry {
    current: Option<PagerDutyRegistration>,
    next_revision: u64,
}

impl RegistrationRegistry {
    pub fn new() -> Self {
        Self {
            current: None,
            next_revision: 1,
        }
    }

    pub fn active(&self) -> Option<&PagerDutyRegistration> {
        self.current
            .as_ref()
            .filter(|registration| registration.lifecycle.is_active())
    }

    pub fn current(&self) -> Option<&PagerDutyRegistration> {
        self.current.as_ref()
    }

    pub fn register(
        &mut self,
        spec: RegistrationSpec,
        at: Timestamp,
    ) -> Result<RegistrationReceipt, RegistrationError> {
        spec.validate()?;
        if self.active().is_some() {
            return Err(RegistrationError::ActiveRegistration);
        }
        let revision = self.take_revision()?;
        let registration = make_registration(spec, revision, RegistrationLifecycle::Active);
        let receipt = make_receipt(&registration, RegistrationAction::Registered, at);
        self.current = Some(registration);
        Ok(receipt)
    }

    pub fn revoke(
        &mut self,
        registration_id: &str,
        at: Timestamp,
    ) -> Result<RegistrationReceipt, RegistrationError> {
        {
            let current = self
                .current
                .as_ref()
                .ok_or(RegistrationError::UnknownRegistration)?;
            if current.registration_id != registration_id {
                return Err(RegistrationError::UnknownRegistration);
            }
            if !current.lifecycle.is_active() {
                return Err(RegistrationError::AlreadyRevoked);
            }
        }
        let revision = self.take_revision()?;
        let current = self
            .current
            .as_mut()
            .ok_or(RegistrationError::UnknownRegistration)?;
        current.lifecycle = RegistrationLifecycle::Revoked { at };
        current.registration_revision = revision;
        current.registration_digest = registration_digest(current);
        Ok(make_receipt(current, RegistrationAction::Revoked, at))
    }

    pub fn restore(
        &mut self,
        registration_id: &str,
        at: Timestamp,
    ) -> Result<RegistrationReceipt, RegistrationError> {
        let existing = {
            let existing = self
                .current
                .as_ref()
                .ok_or(RegistrationError::UnknownRegistration)?;
            if existing.registration_id != registration_id {
                return Err(RegistrationError::UnknownRegistration);
            }
            if existing.lifecycle.is_active() {
                return Err(RegistrationError::NotRevoked);
            }
            existing.clone()
        };
        let revision = self.take_revision()?;
        let mut restored = existing;
        restored.lifecycle = RegistrationLifecycle::Active;
        restored.registration_revision = revision;
        restored.registration_digest = registration_digest(&restored);
        let receipt = make_receipt(&restored, RegistrationAction::Restored, at);
        self.current = Some(restored);
        Ok(receipt)
    }

    fn take_revision(&mut self) -> Result<u64, RegistrationError> {
        let revision = self.next_revision;
        self.next_revision = self
            .next_revision
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        Ok(revision)
    }
}

fn make_registration(
    spec: RegistrationSpec,
    registration_revision: u64,
    lifecycle: RegistrationLifecycle,
) -> PagerDutyRegistration {
    let mut registration = PagerDutyRegistration {
        registration_id: spec.registration_id,
        plugin_version: spec.plugin_version,
        contract_digest: spec.contract_digest,
        provider_id: PROVIDER_ID.to_owned(),
        provider_revision: spec.provider_revision,
        scope: spec.scope,
        secret_reference: spec.secret_reference,
        lifecycle,
        registration_revision,
        registration_digest: Digest::from_text("pending"),
    };
    registration.registration_digest = registration_digest(&registration);
    registration
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationMaterial<'a> {
    registration_id: &'a str,
    plugin_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_revision: u64,
    scope: &'a PagerDutyScope,
    secret_reference: &'a SecretReference,
    lifecycle: &'a RegistrationLifecycle,
    registration_revision: u64,
}

fn registration_digest(registration: &PagerDutyRegistration) -> Digest {
    canonical_digest(&RegistrationMaterial {
        registration_id: &registration.registration_id,
        plugin_version: &registration.plugin_version,
        contract_digest: &registration.contract_digest,
        provider_id: &registration.provider_id,
        provider_revision: registration.provider_revision,
        scope: &registration.scope,
        secret_reference: &registration.secret_reference,
        lifecycle: &registration.lifecycle,
        registration_revision: registration.registration_revision,
    })
}

fn make_receipt(
    registration: &PagerDutyRegistration,
    action: RegistrationAction,
    at: Timestamp,
) -> RegistrationReceipt {
    RegistrationReceipt {
        action,
        registration_id: registration.registration_id.clone(),
        registration_revision: registration.registration_revision,
        provider_id: registration.provider_id.clone(),
        provider_revision: registration.provider_revision,
        contract_digest: registration.contract_digest.clone(),
        scope_digest: registration.scope.digest(),
        registration_digest: registration.registration_digest.clone(),
        at,
    }
}

pub const fn expected_api_region_host(region: ApiRegion) -> &'static str {
    region.host()
}
