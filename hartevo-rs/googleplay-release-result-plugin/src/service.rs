//! Typed read-only service and digest-bound registration lifecycle.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::consumer::{
    GooglePlayReleaseProposal, GooglePlayReleaseRecordingLog, MissionAndroidReleaseConsumer,
    RecordedGooglePlayReleaseResult,
};
use crate::model::{
    Digest, GooglePlayReleaseEvidence, GooglePlayReleaseScope, PermissionSnapshot, SecretReference,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, GooglePlayReleaseResultError, PLUGIN_ID,
    PLUGIN_VERSION, PROVIDER_ID, PROVIDER_REVISION, PluginVersion, Result, SERVICE_ID,
    contract_digest, provider_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GooglePlayRegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

impl GooglePlayRegistrationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayRegistrationRequest {
    pub scope: GooglePlayReleaseScope,
    pub secret_reference: SecretReference,
    pub permissions: PermissionSnapshot,
    pub registration_revision: u64,
}

impl GooglePlayRegistrationRequest {
    pub fn new(
        scope: GooglePlayReleaseScope,
        secret_reference: SecretReference,
        permissions: PermissionSnapshot,
        registration_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        permissions.validate()?;
        if registration_revision == 0 {
            return Err(GooglePlayReleaseResultError::InvalidRegistration);
        }
        if secret_reference.is_revoked() {
            return Err(GooglePlayReleaseResultError::SecretRevoked);
        }
        if !secret_reference.is_bound_to(&scope, &permissions) {
            return if secret_reference.scope_digest() == &scope.digest() {
                Err(GooglePlayReleaseResultError::SecretPermissionMismatch)
            } else {
                Err(GooglePlayReleaseResultError::SecretScopeMismatch)
            };
        }
        Ok(Self {
            scope,
            secret_reference,
            permissions,
            registration_revision,
        })
    }
}

/// Immutable registration identity with reversible and revocable status
/// transitions.  Status is deliberately excluded from the identity digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub consumer_id: String,
    pub permission_snapshot_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub scope: GooglePlayReleaseScope,
    pub secret_reference: SecretReference,
    pub permissions: PermissionSnapshot,
    pub status: GooglePlayRegistrationStatus,
    pub registration_digest: Digest,
}

impl GooglePlayRegistration {
    pub fn from_request(request: GooglePlayRegistrationRequest) -> Result<Self> {
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_api_revision: API_REVISION.to_owned(),
            provider_revision: PROVIDER_REVISION.to_owned(),
            provider_digest: provider_digest(),
            consumer_id: CONSUMER_ID.to_owned(),
            permission_snapshot_digest: request.permissions.digest.clone(),
            scope_digest: request.scope.digest(),
            secret_reference_digest: request.secret_reference.reference_digest().clone(),
            registration_revision: request.registration_revision,
            scope: request.scope,
            secret_reference: request.secret_reference,
            permissions: request.permissions,
            status: GooglePlayRegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-googleplay-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.provider_api_revision != API_REVISION
            || self.provider_revision != PROVIDER_REVISION
            || self.provider_digest != provider_digest()
            || self.consumer_id != CONSUMER_ID
            || self.registration_revision == 0
            || self.permission_snapshot_digest != self.permissions.digest
            || self.scope_digest != self.scope.digest()
            || self.secret_reference_digest != *self.secret_reference.reference_digest()
            || !self
                .secret_reference
                .is_bound_to(&self.scope, &self.permissions)
            || self.registration_digest != self.calculate_digest()
        {
            return Err(GooglePlayReleaseResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permissions.validate()?;
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, GooglePlayRegistrationStatus::Active)
    }

    pub fn scope(&self) -> &GooglePlayReleaseScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        self.transition(GooglePlayRegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        self.transition(GooglePlayRegistrationStatus::Reversed)
    }

    fn transition(&mut self, to: GooglePlayRegistrationStatus) -> Result<RegistrationTransition> {
        let from = self.status;
        if from != GooglePlayRegistrationStatus::Active {
            return Err(match from {
                GooglePlayRegistrationStatus::Revoked => {
                    GooglePlayReleaseResultError::RegistrationRevoked
                }
                GooglePlayRegistrationStatus::Reversed => {
                    GooglePlayReleaseResultError::RegistrationReversed
                }
                GooglePlayRegistrationStatus::Active => {
                    GooglePlayReleaseResultError::InvalidRegistration
                }
            });
        }
        self.status = to;
        Ok(RegistrationTransition::new(
            self.registration_digest.clone(),
            from,
            to,
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "googleplay-release-result/registration/v1",
            [
                ("plugin".to_owned(), self.plugin_id.clone()),
                ("plugin_version".to_owned(), self.plugin_version.clone()),
                ("contract".to_owned(), self.contract_version.clone()),
                (
                    "contract_digest".to_owned(),
                    self.contract_digest.as_str().to_owned(),
                ),
                ("service".to_owned(), self.service_id.clone()),
                ("provider".to_owned(), self.provider_id.clone()),
                (
                    "provider_api_revision".to_owned(),
                    self.provider_api_revision.clone(),
                ),
                (
                    "provider_revision".to_owned(),
                    self.provider_revision.clone(),
                ),
                (
                    "provider_digest".to_owned(),
                    self.provider_digest.as_str().to_owned(),
                ),
                ("consumer".to_owned(), self.consumer_id.clone()),
                (
                    "permission".to_owned(),
                    self.permission_snapshot_digest.as_str().to_owned(),
                ),
                ("scope".to_owned(), self.scope_digest.as_str().to_owned()),
                (
                    "secret_reference".to_owned(),
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                (
                    "registration_revision".to_owned(),
                    self.registration_revision.to_string(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransition {
    pub registration_digest: Digest,
    pub from: GooglePlayRegistrationStatus,
    pub to: GooglePlayRegistrationStatus,
    pub transition_digest: Digest,
    pub reversible: bool,
}

impl RegistrationTransition {
    fn new(
        registration_digest: Digest,
        from: GooglePlayRegistrationStatus,
        to: GooglePlayRegistrationStatus,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "googleplay-release-result/registration-transition/v1",
            [
                (
                    "registration".to_owned(),
                    registration_digest.as_str().to_owned(),
                ),
                ("from".to_owned(), from.as_str().to_owned()),
                ("to".to_owned(), to.as_str().to_owned()),
            ],
        );
        Self {
            registration_digest,
            from,
            to,
            transition_digest,
            reversible: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_digest: Digest,
    pub status: GooglePlayRegistrationStatus,
    pub registration_revision: u64,
    pub permission_snapshot_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub provider_digest: Digest,
    pub transition_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub credential_material: bool,
}

impl RegistrationReceipt {
    fn from_registration(registration: &GooglePlayRegistration, transition_digest: Digest) -> Self {
        Self {
            registration_digest: registration.registration_digest.clone(),
            status: registration.status,
            registration_revision: registration.registration_revision,
            permission_snapshot_digest: registration.permission_snapshot_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            secret_reference_digest: registration.secret_reference_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            transition_digest,
            reversible: true,
            revocable: true,
            connected: false,
            native: false,
            credential_material: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub transport_provenance: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub kernel_authority: bool,
    pub raw_release_notes: bool,
    pub tester_pii: bool,
    pub artifact_bytes: bool,
}

#[derive(Clone, Debug, Default)]
pub struct GooglePlayReleaseService {
    registrations: BTreeMap<Digest, GooglePlayRegistration>,
}

impl GooglePlayReleaseService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: crate::plugin_version(),
            api_revision: API_REVISION.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "reverse_registration".to_owned(),
                "compile_release_proposal".to_owned(),
                "record_release_result".to_owned(),
                "verify_release_evidence".to_owned(),
            ],
            transport_provenance: vec![
                "official_https_read".to_owned(),
                "fixture".to_owned(),
                "recording".to_owned(),
                "loopback".to_owned(),
                "blocked_env".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            external_writes: false,
            connected: false,
            native: false,
            kernel_authority: false,
            raw_release_notes: false,
            tester_pii: false,
            artifact_bytes: false,
        }
    }

    pub fn register(
        &mut self,
        request: GooglePlayRegistrationRequest,
    ) -> Result<RegistrationReceipt> {
        let registration = GooglePlayRegistration::from_request(request)?;
        let key = registration.registration_digest.clone();
        if self.registrations.contains_key(&key) {
            return Err(GooglePlayReleaseResultError::RegistrationAlreadyExists);
        }
        let transition = RegistrationTransition::new(
            key.clone(),
            GooglePlayRegistrationStatus::Active,
            GooglePlayRegistrationStatus::Active,
        );
        let receipt =
            RegistrationReceipt::from_registration(&registration, transition.transition_digest);
        self.registrations.insert(key, registration);
        Ok(receipt)
    }

    pub fn get(&self, registration_digest: &Digest) -> Result<&GooglePlayRegistration> {
        self.registrations
            .get(registration_digest)
            .ok_or(GooglePlayReleaseResultError::RegistrationUnknown)
    }

    pub fn revoke_registration(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationReceipt> {
        self.transition_registration(registration_digest, false)
    }

    pub fn reverse_registration(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationReceipt> {
        self.transition_registration(registration_digest, true)
    }

    pub fn verify_release_evidence(
        &self,
        registration_digest: &Digest,
        evidence: &GooglePlayReleaseEvidence,
    ) -> Result<()> {
        let registration = self.get(registration_digest)?;
        registration.validate()?;
        if !registration.is_active()
            || evidence.registration_digest != *registration_digest
            || evidence.scope_digest != registration.scope_digest
        {
            return Err(
                if matches!(registration.status, GooglePlayRegistrationStatus::Revoked) {
                    GooglePlayReleaseResultError::RegistrationRevoked
                } else if matches!(registration.status, GooglePlayRegistrationStatus::Reversed) {
                    GooglePlayReleaseResultError::RegistrationReversed
                } else {
                    GooglePlayReleaseResultError::RegistrationDrift
                },
            );
        }
        evidence.validate()
    }

    pub fn compile_release_proposal(
        &self,
        registration_digest: &Digest,
        evidence: &GooglePlayReleaseEvidence,
        idempotency_key: &str,
    ) -> Result<GooglePlayReleaseProposal> {
        let registration = self.get(registration_digest)?;
        let consumer = MissionAndroidReleaseConsumer::new(registration)?;
        consumer.compile_release_proposal(evidence, idempotency_key)
    }

    pub fn record_release_result(
        &self,
        registration_digest: &Digest,
        proposal: &GooglePlayReleaseProposal,
        log: &mut GooglePlayReleaseRecordingLog,
    ) -> Result<RecordedGooglePlayReleaseResult> {
        let registration = self.get(registration_digest)?;
        let consumer = MissionAndroidReleaseConsumer::new(registration)?;
        consumer.record(proposal, log)
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    fn transition_registration(
        &mut self,
        registration_digest: &Digest,
        reverse: bool,
    ) -> Result<RegistrationReceipt> {
        let registration = self
            .registrations
            .get_mut(registration_digest)
            .ok_or(GooglePlayReleaseResultError::RegistrationUnknown)?;
        let transition = if reverse {
            registration.reverse()?
        } else {
            registration.revoke()?
        };
        Ok(RegistrationReceipt::from_registration(
            registration,
            transition.transition_digest,
        ))
    }
}
