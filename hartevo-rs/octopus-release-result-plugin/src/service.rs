//! Typed read-only service and reversible registration fence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{OctopusScope, PermissionSnapshot, SecretReference};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, Digest, OctopusReleaseResultError, PLUGIN_ID,
    PLUGIN_VERSION, PROVIDER_ID, PROVIDER_REVISION, PluginVersion, Result, SERVICE_ID,
    contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OctopusRegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

impl OctopusRegistrationStatus {
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
pub struct OctopusRegistrationRequest {
    pub scope: OctopusScope,
    pub secret_reference: SecretReference,
    pub permissions: PermissionSnapshot,
    pub registration_revision: u64,
}

impl OctopusRegistrationRequest {
    pub fn new(
        scope: OctopusScope,
        secret_reference: SecretReference,
        permissions: PermissionSnapshot,
        registration_revision: u64,
    ) -> Result<Self> {
        if registration_revision == 0 {
            return Err(OctopusReleaseResultError::InvalidRegistration);
        }
        scope.validate()?;
        permissions.validate()?;
        if secret_reference.revoked {
            return Err(OctopusReleaseResultError::SecretRevoked);
        }
        if secret_reference.scope_digest != scope.digest() {
            return Err(OctopusReleaseResultError::SecretScopeMismatch);
        }
        if secret_reference.permission_digest != permissions.digest {
            return Err(OctopusReleaseResultError::SecretPermissionMismatch);
        }
        Ok(Self {
            scope,
            secret_reference,
            permissions,
            registration_revision,
        })
    }
}

/// Registration is immutable with respect to its digest-bound inputs. Status
/// transitions are reversible evidence around that stable identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OctopusRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub provider_revision: String,
    pub consumer_id: String,
    pub permission_snapshot_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub scope: OctopusScope,
    pub secret_reference: SecretReference,
    pub permissions: PermissionSnapshot,
    pub status: OctopusRegistrationStatus,
    pub registration_digest: Digest,
}

impl OctopusRegistration {
    pub fn from_request(request: OctopusRegistrationRequest) -> Result<Self> {
        let registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_api_revision: API_REVISION.to_owned(),
            provider_revision: PROVIDER_REVISION.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            permission_snapshot_digest: request.permissions.digest.clone(),
            scope_digest: request.scope.digest(),
            secret_reference_digest: request.secret_reference.reference_digest.clone(),
            registration_revision: request.registration_revision,
            scope: request.scope,
            secret_reference: request.secret_reference,
            permissions: request.permissions,
            status: OctopusRegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-octopus-registration")
                .expect("digest"),
        };
        let mut registration = registration;
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
            || self.consumer_id != CONSUMER_ID
            || self.registration_revision == 0
            || self.permission_snapshot_digest != self.permissions.digest
            || self.scope_digest != self.scope.digest()
            || self.secret_reference_digest != self.secret_reference.reference_digest
            || self.secret_reference.revoked
            || !self
                .secret_reference
                .is_bound_to(&self.scope, &self.permissions)
            || self.registration_digest != self.calculate_digest()
        {
            return Err(OctopusReleaseResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permissions.validate()?;
        self.contract_digest.validate()?;
        self.permission_snapshot_digest.validate()?;
        self.scope_digest.validate()?;
        self.secret_reference_digest.validate()?;
        self.registration_digest.validate()?;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.status == OctopusRegistrationStatus::Active
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        self.transition(OctopusRegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        self.transition(OctopusRegistrationStatus::Reversed)
    }

    fn transition(&mut self, to: OctopusRegistrationStatus) -> Result<RegistrationTransition> {
        let from = self.status;
        if from != OctopusRegistrationStatus::Active {
            return Err(match from {
                OctopusRegistrationStatus::Revoked => {
                    OctopusReleaseResultError::RegistrationRevoked
                }
                OctopusRegistrationStatus::Reversed => {
                    OctopusReleaseResultError::RegistrationReversed
                }
                OctopusRegistrationStatus::Active => OctopusReleaseResultError::InvalidRegistration,
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
            "octopus-release-result/registration/v1",
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
    pub from: OctopusRegistrationStatus,
    pub to: OctopusRegistrationStatus,
    pub transition_digest: Digest,
    pub reversible: bool,
}

impl RegistrationTransition {
    fn new(
        registration_digest: Digest,
        from: OctopusRegistrationStatus,
        to: OctopusRegistrationStatus,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "octopus-release-result/registration-transition/v1",
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
    pub status: OctopusRegistrationStatus,
    pub registration_revision: u64,
    pub permission_snapshot_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub transition_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub credential_material: bool,
}

impl RegistrationReceipt {
    fn from_registration(registration: &OctopusRegistration, transition_digest: Digest) -> Self {
        Self {
            registration_digest: registration.registration_digest.clone(),
            status: registration.status,
            registration_revision: registration.registration_revision,
            permission_snapshot_digest: registration.permission_snapshot_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            secret_reference_digest: registration.secret_reference_digest.clone(),
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
    pub raw_task_logs: bool,
    pub raw_scripts: bool,
    pub package_bytes: bool,
    pub generic_deployment_registry: bool,
}

#[derive(Clone, Debug, Default)]
pub struct OctopusReleaseResultService {
    registrations: BTreeMap<Digest, OctopusRegistration>,
}

impl OctopusReleaseResultService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PluginVersion::new(1, 0, 0),
            api_revision: API_REVISION.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "reverse_registration".to_owned(),
                "read_spaces".to_owned(),
                "read_projects".to_owned(),
                "read_channels".to_owned(),
                "read_environments".to_owned(),
                "read_tenants".to_owned(),
                "read_releases".to_owned(),
                "read_deployment_process_metadata".to_owned(),
                "read_deployment_state".to_owned(),
                "read_task_state".to_owned(),
                "compile_release_result".to_owned(),
                "record_release_result".to_owned(),
            ],
            transport_provenance: vec![
                "recording".to_owned(),
                "fixture".to_owned(),
                "loopback".to_owned(),
                "blocked_env".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            external_writes: false,
            connected: false,
            native: false,
            kernel_authority: false,
            raw_task_logs: false,
            raw_scripts: false,
            package_bytes: false,
            generic_deployment_registry: false,
        }
    }

    pub fn register(&mut self, request: OctopusRegistrationRequest) -> Result<RegistrationReceipt> {
        let registration = OctopusRegistration::from_request(request)?;
        let key = registration.registration_digest.clone();
        if self.registrations.contains_key(&key) {
            return Err(OctopusReleaseResultError::RegistrationAlreadyExists);
        }
        let transition = RegistrationTransition::new(
            key.clone(),
            OctopusRegistrationStatus::Active,
            OctopusRegistrationStatus::Active,
        );
        let receipt = RegistrationReceipt::from_registration(
            &registration,
            transition.transition_digest.clone(),
        );
        self.registrations.insert(key, registration);
        Ok(receipt)
    }

    pub fn get(&self, registration_digest: &Digest) -> Result<&OctopusRegistration> {
        self.registrations
            .get(registration_digest)
            .ok_or(OctopusReleaseResultError::RegistrationUnknown)
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
            .ok_or(OctopusReleaseResultError::RegistrationUnknown)?;
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
