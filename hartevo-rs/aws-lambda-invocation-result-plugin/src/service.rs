//! Typed service and reversible registration boundary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{
    AwsLambdaInvocationResultProposal, AwsLambdaResultRecordingLog, MissionAwsLambdaResultConsumer,
    RecordedAwsLambdaResult,
};
use crate::model::{
    AwsLambdaScope, Digest, InvocationProposal, InvocationResultProjection, PermissionSnapshot,
    PluginVersion, RegistrationId, RegistrationStatus, SecretReference, TransportProvenance,
    VerificationReport,
};
use crate::provider::{AwsLambdaProvider, AwsLambdaTransport, FunctionLookupResponse};
use crate::{
    AwsLambdaInvocationResultError, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL,
    OBJECTIVE_TYPE, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, Result,
    SERVICE_ID, contract_digest,
};

/// Provider identity is metadata only and never grants live AWS access.
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
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release: release.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.release.len() > 128
            || self.release.trim() != self.release
            || self.release.chars().any(char::is_control)
        {
            return Err(AwsLambdaInvocationResultError::InvalidRegistration);
        }
        Ok(())
    }
}

/// Version/contract/provider/permission/scope/secret-bound registration.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsLambdaRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: AwsLambdaScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsLambdaRegistration {
    pub fn new(
        id: RegistrationId,
        scope: AwsLambdaScope,
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
            binding_digest: Digest::from_text("unsealed-aws-lambda-registration"),
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
            return Err(AwsLambdaInvocationResultError::InvalidRegistration);
        }
        if let Some(secret_scope_digest) = self.secret_reference.scope_digest() {
            let account_region_digest = Digest::from_parts(
                "aws-lambda-sigv4-scope/v1",
                &[
                    ("account", self.scope.account.as_str().to_owned()),
                    ("region", self.scope.region.as_str().to_owned()),
                ],
            );
            if secret_scope_digest != &self.scope_digest
                && secret_scope_digest != &account_region_digest
            {
                return Err(AwsLambdaInvocationResultError::RegistrationDrift);
            }
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

    pub fn scope(&self) -> &AwsLambdaScope {
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

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Revoked;
                Ok(RegistrationTransitionEvidence::for_registration(self))
            }
            RegistrationStatus::Reversed => {
                Err(AwsLambdaInvocationResultError::RegistrationReversed)
            }
        }
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.status = RegistrationStatus::Reversed;
        Ok(RegistrationTransitionEvidence::for_registration(self))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        match self.status {
            RegistrationStatus::Active => {
                Ok(RegistrationTransitionEvidence::for_registration(self))
            }
            RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Active;
                Ok(RegistrationTransitionEvidence::for_registration(self))
            }
            RegistrationStatus::Reversed => {
                Err(AwsLambdaInvocationResultError::RegistrationReversed)
            }
        }
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-registration-binding/v1",
            &[
                ("id", self.id.id.clone()),
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

impl fmt::Debug for AwsLambdaRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsLambdaRegistration")
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

impl Serialize for AwsLambdaRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsLambdaRegistration", 13)?;
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
                scope_digest: self.secret_reference.scope_digest(),
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
    kind: crate::model::SecretKind,
    reference_digest: &'a Digest,
    scope_digest: Option<&'a Digest>,
    revision: u64,
    revoked: bool,
}

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
    fn for_registration(registration: &AwsLambdaRegistration) -> Self {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub registration_id: RegistrationId,
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub binding_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationTransitionEvidence {
    fn for_registration(registration: &AwsLambdaRegistration) -> Self {
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
pub struct AwsLambdaRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, AwsLambdaRegistration>,
}

impl AwsLambdaRegistrationRegistry {
    pub fn register(&mut self, registration: AwsLambdaRegistration) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(AwsLambdaInvocationResultError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&AwsLambdaRegistration> {
        self.registrations
            .get(id)
            .ok_or(AwsLambdaInvocationResultError::RegistrationUnknown)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut AwsLambdaRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(AwsLambdaInvocationResultError::RegistrationUnknown)
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

    pub fn iter(&self) -> impl Iterator<Item = &AwsLambdaRegistration> {
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
                "read_function_metadata".to_owned(),
                "compile_invocation_proposal".to_owned(),
                "project_invocation_result".to_owned(),
                "compile_execution_result_proposal".to_owned(),
                "record_execution_result".to_owned(),
                "verify_execution_result".to_owned(),
                "revoke_registration".to_owned(),
                "reverse_registration".to_owned(),
                "restore_registration".to_owned(),
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDescription {
    pub objective_type: &'static str,
    pub scope_digest: Digest,
    pub account: crate::model::AwsAccountId,
    pub region: crate::model::AwsRegion,
    pub function: crate::model::FunctionTarget,
    pub invocation_type: crate::model::InvocationType,
    pub input: crate::model::InputIdentity,
    pub config: crate::model::InvocationConfig,
    pub retry: crate::model::RetryPolicy,
    pub mission: crate::model::MissionIdentity,
    pub project: crate::model::ProjectIdentity,
    pub work_product: crate::model::WorkProductIdentity,
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

/// Typed Layer-1 service composed with a fixture-only provider transport.
#[derive(Debug)]
pub struct AwsLambdaInvocationResultService<T> {
    provider: AwsLambdaProvider<T>,
}

impl<T: AwsLambdaTransport> AwsLambdaInvocationResultService<T> {
    pub fn new(registration: AwsLambdaRegistration, transport: T) -> Result<Self> {
        Ok(Self {
            provider: AwsLambdaProvider::new(registration, transport)?,
        })
    }

    pub fn provider(&self) -> &AwsLambdaProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsLambdaProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsLambdaRegistration {
        self.provider.registration()
    }

    pub fn registration_mut(&mut self) -> &mut AwsLambdaRegistration {
        self.provider.registration_mut()
    }

    pub fn scope(&self) -> &AwsLambdaScope {
        self.registration().scope()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription::layer_one()
    }

    pub fn describe_scope(&self) -> ScopeDescription {
        let registration = self.registration();
        let scope = registration.scope();
        ScopeDescription {
            objective_type: OBJECTIVE_TYPE,
            scope_digest: scope.digest(),
            account: scope.account.clone(),
            region: scope.region.clone(),
            function: scope.function.clone(),
            invocation_type: scope.invocation_type,
            input: scope.input.clone(),
            config: scope.config.clone(),
            retry: scope.retry.clone(),
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            permission_snapshot_digest: registration.permission_snapshot().digest(),
            permission_revision: registration.permission_snapshot().revision,
            permissions: registration
                .permission_snapshot()
                .permissions
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

    pub fn read_function_metadata(&mut self) -> Result<FunctionLookupResponse> {
        self.provider.read_function_metadata()
    }

    pub fn compile_invocation_proposal(&self) -> Result<InvocationProposal> {
        self.provider.ensure_ready()?;
        InvocationProposal::new(
            self.registration().id().clone(),
            self.registration().binding_digest().clone(),
            self.scope(),
            self.provider.provenance(),
        )
    }

    pub fn project_invocation_result(
        &mut self,
        proposal: &InvocationProposal,
    ) -> Result<InvocationResultProjection> {
        self.provider.project_invocation_result(proposal)
    }

    pub fn invoke(&mut self, proposal: &InvocationProposal) -> Result<InvocationResultProjection> {
        self.project_invocation_result(proposal)
    }

    pub fn observe_bounded(
        &mut self,
        proposal: &InvocationProposal,
    ) -> Result<InvocationResultProjection> {
        self.provider.observe_bounded(proposal)
    }

    pub fn compile_execution_result_proposal(
        &self,
        projection: &InvocationResultProjection,
        idempotency_key: &str,
    ) -> Result<AwsLambdaInvocationResultProposal> {
        self.provider.ensure_ready()?;
        MissionAwsLambdaResultConsumer::new(self.scope().clone())
            .compile_proposal(projection, idempotency_key)
    }

    pub fn record_execution_result(
        &self,
        proposal: &AwsLambdaInvocationResultProposal,
        idempotency_key: &str,
        log: &mut AwsLambdaResultRecordingLog,
    ) -> Result<RecordedAwsLambdaResult> {
        self.provider.ensure_ready()?;
        MissionAwsLambdaResultConsumer::new(self.scope().clone()).record_with_key(
            proposal,
            idempotency_key,
            log,
        )
    }

    pub fn verify_execution_result(
        &self,
        invocation: &InvocationProposal,
        projection: &InvocationResultProjection,
        result: &AwsLambdaInvocationResultProposal,
    ) -> Result<VerificationReport> {
        self.provider.ensure_ready()?;
        MissionAwsLambdaResultConsumer::new(self.scope().clone()).verify(
            invocation,
            projection,
            result,
            self.registration().binding_digest(),
        )
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
fn _keep_imports_visible(_: PermissionSnapshot, _: FunctionLookupResponse, _: TransportProvenance) {
}
