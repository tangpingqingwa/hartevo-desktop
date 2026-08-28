//! Typed service and reversible registration boundary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{
    JobResultProposal, MissionModalJobConsumer, ModalJobResultRecordingLog, RecordedModalJobResult,
};
use crate::model::{
    Digest, ModalScope, PermissionSnapshot, PluginVersion, RegistrationId, RegistrationStatus,
    SecretReference, TransportProvenance,
};
use crate::provider::{
    FunctionHandle, FunctionLookupResponse, ModalProvider, ModalTransport, ProviderCallResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL, ModalJobResultError, PLUGIN_ID,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, Result, SERVICE_ID, contract_digest,
    validate_text,
};

/// Provider identity is metadata only and does not grant native execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub release: String,
}

impl ProviderIdentity {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        validate_text(&release, "providerRelease", 128)?;
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
        {
            return Err(ModalJobResultError::InvalidRegistration);
        }
        validate_text(&self.release, "providerRelease", 128)
    }
}

/// Version/contract/provider/permission/scope/secret-bound registration.
#[derive(Clone, Eq, PartialEq)]
pub struct ModalRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: ModalScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl ModalRegistration {
    pub fn new(
        id: RegistrationId,
        scope: ModalScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: ProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id,
            plugin_version: PluginVersion::V1,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_hex(CONTRACT_DIGEST)?,
            provider,
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-modal-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.scope.validate()?;
        self.provider.validate()?;
        self.permission_snapshot.validate()?;
        self.secret_reference.validate()?;
        if self.plugin_version != PluginVersion::V1
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(ModalJobResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn id(&self) -> &RegistrationId {
        &self.id
    }

    pub const fn plugin_version(&self) -> PluginVersion {
        self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn scope(&self) -> &ModalScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn revoke(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Revoked;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(ModalJobResultError::RegistrationReversed),
        }
    }

    pub fn reverse(&mut self) -> Result<()> {
        self.status = RegistrationStatus::Reversed;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Active;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(ModalJobResultError::RegistrationReversed),
        }
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "modal-registration-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("plugin_version", self.plugin_version.to_string()),
                ("contract_version", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                (
                    "provider",
                    serde_json::to_string(&self.provider).expect("provider metadata"),
                ),
                (
                    "permissions",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "secret_revision",
                    self.secret_reference.revision().to_string(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
            ],
        )
    }
}

impl fmt::Debug for ModalRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModalRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider", &self.provider)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("scope_digest", &self.scope_digest)
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for ModalRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ModalRegistration", 13)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("provider", &self.provider)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "secretReference",
            &SafeSecretReference {
                kind: self.secret_reference.kind(),
                reference_digest: self.secret_reference.reference_digest(),
                revision: self.secret_reference.revision(),
                revoked: self.secret_reference.is_revoked(),
            },
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SafeSecretReference<'a> {
    kind: crate::SecretKind,
    reference_digest: &'a Digest,
    revision: u64,
    revoked: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationReceipt {
    pub registration_id: RegistrationId,
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub binding_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationReceipt {
    fn for_registration(registration: &ModalRegistration) -> Self {
        Self {
            registration_id: registration.id.clone(),
            status: registration.status,
            registration_revision: registration.registration_revision,
            binding_digest: registration.binding_digest.clone(),
            reversible: true,
            revocable: true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ModalRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, ModalRegistration>,
}

impl ModalRegistrationRegistry {
    pub fn register(&mut self, registration: ModalRegistration) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(ModalJobResultError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&ModalRegistration> {
        self.registrations
            .get(id)
            .ok_or(ModalJobResultError::RegistrationUnknown)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut ModalRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(ModalJobResultError::RegistrationUnknown)
    }

    pub fn revoke(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.revoke()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn reverse(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.reverse()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn restore(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.restore()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModalRegistration> {
        self.registrations.values()
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub plugin_id: String,
    pub layer: u8,
    pub evidence_level: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub allowed_provenance: Vec<TransportProvenance>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adoption: bool,
}

impl CapabilityDescription {
    fn layer_one() -> Self {
        Self {
            plugin_id: PLUGIN_ID.to_owned(),
            layer: 1,
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "register_scope".to_owned(),
                "lookup_deployed_function".to_owned(),
                "spawn_function_call_projection".to_owned(),
                "poll_function_call_projection".to_owned(),
                "compile_job_result_proposal".to_owned(),
                "record_job_result".to_owned(),
            ],
            allowed_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adoption: false,
        }
    }
}

/// Safe exact-scope description. It exposes revision/digest metadata only;
/// the SecretReference itself remains opaque.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDescription {
    pub scope_digest: Digest,
    pub host: crate::HostIdentity,
    pub workspace: crate::WorkspaceIdentity,
    pub app: crate::AppIdentity,
    pub function: crate::FunctionIdentity,
    pub environment: crate::EnvironmentIdentity,
    pub call: crate::FunctionCallIdentity,
    pub input: crate::InputIdentity,
    pub retry: crate::RetryPolicy,
    pub mission: crate::MissionIdentity,
    pub project: crate::ProjectIdentity,
    pub work_product: crate::WorkProductIdentity,
    pub permission_snapshot_digest: Digest,
    pub permission_revision: u64,
    pub permissions: Vec<String>,
    pub secret_reference_digest: Digest,
    pub secret_reference_revision: u64,
    pub registration_revision: u64,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

/// Typed Modal service composed with a bounded transport.
#[derive(Clone, Debug)]
pub struct ModalJobResultService<T> {
    provider: ModalProvider<T>,
}

impl<T: ModalTransport> ModalJobResultService<T> {
    pub fn new(registration: ModalRegistration, transport: T) -> Result<Self> {
        Ok(Self {
            provider: ModalProvider::new(registration, transport)?,
        })
    }

    pub fn provider(&self) -> &ModalProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut ModalProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &ModalRegistration {
        self.provider.registration()
    }

    pub fn registration_mut(&mut self) -> &mut ModalRegistration {
        self.provider.registration_mut()
    }

    pub fn scope(&self) -> &ModalScope {
        self.registration().scope()
    }

    pub fn describe_scope(&self) -> ScopeDescription {
        let registration = self.registration();
        let scope = registration.scope();
        ScopeDescription {
            scope_digest: scope.digest(),
            host: scope.host.clone(),
            workspace: scope.workspace.clone(),
            app: scope.app.clone(),
            function: scope.function.clone(),
            environment: scope.environment.clone(),
            call: scope.call.clone(),
            input: scope.input.clone(),
            retry: scope.retry.clone(),
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            permission_snapshot_digest: registration.permission_snapshot().digest().clone(),
            permission_revision: registration.permission_snapshot().revision(),
            permissions: registration
                .permission_snapshot()
                .permissions()
                .iter()
                .cloned()
                .collect(),
            secret_reference_digest: registration.secret_reference().reference_digest().clone(),
            secret_reference_revision: registration.secret_reference().revision(),
            registration_revision: registration.registration_revision(),
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription::layer_one()
    }

    pub fn describe_workspace_app_function(&mut self) -> Result<FunctionLookupResponse> {
        self.provider.describe_workspace_app_function()
    }

    pub fn lookup_function(&mut self) -> Result<FunctionHandle> {
        self.provider.lookup_function()
    }

    pub fn spawn_function_call(
        &mut self,
        handle: &FunctionHandle,
    ) -> Result<crate::FunctionCallProjection> {
        self.provider.spawn_function_call(handle)
    }

    pub fn poll_function_call(
        &mut self,
        handle: &FunctionHandle,
        current: &crate::FunctionCallProjection,
    ) -> Result<crate::FunctionCallProjection> {
        self.provider.poll_function_call(handle, current)
    }

    pub fn observe_bounded(&mut self) -> Result<crate::FunctionCallProjection> {
        self.provider.observe_bounded()
    }

    pub fn compile_job_result_proposal(
        &self,
        projection: &crate::FunctionCallProjection,
        idempotency_key: &str,
    ) -> Result<JobResultProposal> {
        self.provider.ensure_ready()?;
        self.compile_job_result_proposal_at_revision(
            projection,
            idempotency_key,
            self.scope().mission.revision,
        )
    }

    pub fn compile_job_result_proposal_at_revision(
        &self,
        projection: &crate::FunctionCallProjection,
        idempotency_key: &str,
        current_mission_revision: u64,
    ) -> Result<JobResultProposal> {
        self.provider.ensure_ready()?;
        let consumer = MissionModalJobConsumer::new(self.scope().clone());
        consumer.compile_proposal_at_revision(projection, idempotency_key, current_mission_revision)
    }

    pub fn record_job_result(
        &self,
        proposal: &JobResultProposal,
        idempotency_key: &str,
        log: &mut ModalJobResultRecordingLog,
    ) -> Result<RecordedModalJobResult> {
        self.provider.ensure_ready()?;
        let consumer = MissionModalJobConsumer::new(self.scope().clone());
        consumer.record_with_key(proposal, idempotency_key, log)
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationReceipt> {
        self.provider.registration_mut().revoke()?;
        Ok(RegistrationReceipt::for_registration(self.registration()))
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationReceipt> {
        self.provider.registration_mut().reverse()?;
        Ok(RegistrationReceipt::for_registration(self.registration()))
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationReceipt> {
        self.provider.registration_mut().restore()?;
        Ok(RegistrationReceipt::for_registration(self.registration()))
    }
}

#[allow(dead_code)]
fn _keep_provider_response_public(_: ProviderCallResponse) {}
