use std::fmt;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::canonical::{digest_parts, serialized_digest, validate_digest};
use crate::model::{
    AuthIdentityObservation, CapabilityDescription, EvidenceProvenance,
    ManagementMetadataObservation, MissionScope, NativeStatus, PostgrestMetadataObservation,
    SecretReference, SupabaseOperation, SupabasePermissionSet, SupabaseScope, TableScope,
    TransportMode,
};
use crate::{
    CAPABILITY_ID, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
    SupabaseIdentityError, SupabaseProviderError,
};

/// Provider manifest used only as a version/scope/permission fence.  It is
/// not a catalog entry and it grants no execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "provider authority flags are explicit fail-closed contract fields"
)]
pub struct SupabaseProviderManifest {
    pub provider_id: String,
    pub provider_api_revision: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub provider_digest: String,
    pub permission_digest: String,
    pub scope_digest: String,
    pub project_ref: String,
    pub region: String,
    pub management_api_host: String,
    pub auth_api_host: String,
    pub postgrest_api_host: String,
    pub scope: SupabaseScope,
    pub transport_mode: TransportMode,
    pub connected: bool,
    pub native: bool,
    pub native_status: NativeStatus,
    pub mutation_authority: bool,
    pub identity_authority: bool,
    pub truth_authority: bool,
}

impl SupabaseProviderManifest {
    pub fn baseline(
        scope: &SupabaseScope,
        permissions: &SupabasePermissionSet,
        transport_mode: TransportMode,
    ) -> Result<Self, SupabaseIdentityError> {
        scope.validate()?;
        permissions.validate()?;
        let mut manifest = Self {
            provider_id: PROVIDER_ID.into(),
            provider_api_revision: PROVIDER_API_REVISION.into(),
            plugin_version: PLUGIN_VERSION.into(),
            contract_version: CONTRACT_VERSION.into(),
            contract_digest: crate::contract_digest(),
            provider_digest: String::new(),
            permission_digest: permissions.digest(),
            scope_digest: scope.digest(),
            project_ref: scope.project_ref.clone(),
            region: scope.region.clone(),
            management_api_host: scope.management_api_host.clone(),
            auth_api_host: scope.auth_api_host.clone(),
            postgrest_api_host: scope.postgrest_api_host.clone(),
            scope: scope.clone(),
            transport_mode,
            connected: false,
            native: false,
            native_status: NativeStatus::BlockedEnv,
            mutation_authority: false,
            identity_authority: false,
            truth_authority: false,
        };
        manifest.provider_digest = manifest.expected_provider_digest()?;
        Ok(manifest)
    }

    fn expected_provider_digest(&self) -> Result<String, SupabaseIdentityError> {
        serialized_digest(&ProviderDigestMaterial {
            provider_id: &self.provider_id,
            provider_api_revision: &self.provider_api_revision,
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            project_ref: &self.project_ref,
            region: &self.region,
            management_api_host: &self.management_api_host,
            auth_api_host: &self.auth_api_host,
            postgrest_api_host: &self.postgrest_api_host,
            transport_mode: self.transport_mode,
        })
    }

    pub fn validate_for(
        &self,
        scope: &SupabaseScope,
        permissions: &SupabasePermissionSet,
    ) -> Result<(), SupabaseIdentityError> {
        scope.validate()?;
        permissions.validate()?;
        validate_digest(&self.contract_digest, "provider contract_digest")?;
        validate_digest(&self.provider_digest, "provider_digest")?;
        validate_digest(&self.permission_digest, "provider permission_digest")?;
        validate_digest(&self.scope_digest, "provider scope_digest")?;
        if self.provider_id != PROVIDER_ID
            || self.provider_api_revision != PROVIDER_API_REVISION
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.permission_digest != permissions.digest()
            || self.scope_digest != scope.digest()
            || self.project_ref != scope.project_ref
            || self.region != scope.region
            || self.management_api_host != scope.management_api_host
            || self.auth_api_host != scope.auth_api_host
            || self.postgrest_api_host != scope.postgrest_api_host
            || self.scope != *scope
            || self.connected
            || self.native
            || self.native_status != NativeStatus::BlockedEnv
            || self.mutation_authority
            || self.identity_authority
            || self.truth_authority
            || self.provider_digest != self.expected_provider_digest()?
        {
            return Err(SupabaseIdentityError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProviderDigestMaterial<'a> {
    provider_id: &'a str,
    provider_api_revision: &'a str,
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a str,
    permission_digest: &'a str,
    scope_digest: &'a str,
    project_ref: &'a str,
    region: &'a str,
    management_api_host: &'a str,
    auth_api_host: &'a str,
    postgrest_api_host: &'a str,
    transport_mode: TransportMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagementMetadataRequest {
    pub scope_digest: String,
    pub project_ref: String,
    pub region: String,
    pub secret_reference: SecretReference,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthIdentityRequest {
    pub scope_digest: String,
    pub project_ref: String,
    pub region: String,
    pub tenant_id: String,
    pub auth_audience: String,
    pub auth_issuer: String,
    pub subject_user_id: Option<String>,
    pub allowed_roles: Vec<String>,
    pub secret_reference: SecretReference,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgrestMetadataRequest {
    pub scope_digest: String,
    pub project_ref: String,
    pub region: String,
    pub tenant_id: String,
    pub tables: Vec<TableScope>,
    pub allowlisted_columns: Vec<(TableScope, Vec<String>)>,
    pub allowed_roles: Vec<String>,
    pub grant_revision: String,
    pub policy_revision: String,
    pub secret_reference: SecretReference,
    pub observed_at: DateTime<Utc>,
}

/// The HTTPS seams are intentionally metadata-only.  A native HTTP client is
/// not part of this Layer-1 crate; implementations supplied by a host must
/// return redacted, bounded observations.
pub trait SupabaseHttpsTransport: fmt::Debug + Send + Sync {
    fn mode(&self) -> TransportMode;

    fn read_management_metadata(
        &self,
        request: &ManagementMetadataRequest,
    ) -> Result<ManagementMetadataObservation, SupabaseProviderError>;

    fn read_auth_identity(
        &self,
        request: &AuthIdentityRequest,
    ) -> Result<AuthIdentityObservation, SupabaseProviderError>;

    fn read_postgrest_metadata(
        &self,
        request: &PostgrestMetadataRequest,
    ) -> Result<PostgrestMetadataObservation, SupabaseProviderError>;
}

/// Alias emphasizing that the three seams are metadata-only.
pub use SupabaseHttpsTransport as SupabaseMetadataTransport;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupabaseProviderCall {
    ManagementMetadata {
        scope_digest: String,
        project_ref: String,
        secret_reference_id: String,
    },
    AuthIdentity {
        scope_digest: String,
        project_ref: String,
        tenant_id: String,
        subject_user_id: Option<String>,
        secret_reference_id: String,
    },
    PostgrestMetadata {
        scope_digest: String,
        project_ref: String,
        tenant_id: String,
        table_digests: Vec<String>,
        secret_reference_id: String,
    },
}

#[derive(Clone)]
pub struct RecordingSupabaseTransport {
    mode: TransportMode,
    management_observation: Arc<Mutex<Option<ManagementMetadataObservation>>>,
    identity_observation: Arc<Mutex<Option<AuthIdentityObservation>>>,
    policy_observation: Arc<Mutex<Option<PostgrestMetadataObservation>>>,
    fault: Arc<Mutex<Option<SupabaseProviderError>>>,
    calls: Arc<Mutex<Vec<SupabaseProviderCall>>>,
}

impl fmt::Debug for RecordingSupabaseTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingSupabaseTransport")
            .field("mode", &self.mode)
            .field(
                "has_management_observation",
                &self
                    .management_observation
                    .lock()
                    .is_ok_and(|value| value.is_some()),
            )
            .field(
                "has_identity_observation",
                &self
                    .identity_observation
                    .lock()
                    .is_ok_and(|value| value.is_some()),
            )
            .field(
                "has_policy_observation",
                &self
                    .policy_observation
                    .lock()
                    .is_ok_and(|value| value.is_some()),
            )
            .finish_non_exhaustive()
    }
}

impl Default for RecordingSupabaseTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingSupabaseTransport {
    pub fn new() -> Self {
        Self::with_mode(TransportMode::Fixture)
    }

    pub fn with_mode(mode: TransportMode) -> Self {
        Self {
            mode,
            management_observation: Arc::new(Mutex::new(None)),
            identity_observation: Arc::new(Mutex::new(None)),
            policy_observation: Arc::new(Mutex::new(None)),
            fault: Arc::new(Mutex::new(None)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn fixture() -> Self {
        Self::with_mode(TransportMode::Fixture)
    }

    pub fn recording() -> Self {
        Self::with_mode(TransportMode::Recording)
    }

    pub fn loopback() -> Self {
        Self::with_mode(TransportMode::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::with_mode(TransportMode::BlockedEnv)
    }

    pub fn set_fault(&self, fault: SupabaseProviderError) {
        *self.fault.lock().expect("fault lock") = Some(fault);
    }

    pub fn clear_fault(&self) {
        *self.fault.lock().expect("fault lock") = None;
    }

    pub fn set_management_observation(&self, observation: ManagementMetadataObservation) {
        *self
            .management_observation
            .lock()
            .expect("management observation lock") = Some(observation);
    }

    pub fn set_identity_observation(&self, observation: AuthIdentityObservation) {
        *self
            .identity_observation
            .lock()
            .expect("identity observation lock") = Some(observation);
    }

    pub fn set_policy_observation(&self, observation: PostgrestMetadataObservation) {
        *self
            .policy_observation
            .lock()
            .expect("policy observation lock") = Some(observation);
    }

    pub fn calls(&self) -> Vec<SupabaseProviderCall> {
        self.calls.lock().expect("calls lock").clone()
    }

    fn fault(&self) -> Result<(), SupabaseProviderError> {
        self.fault
            .lock()
            .expect("fault lock")
            .clone()
            .map_or(Ok(()), Err)
    }

    fn ensure_environment(&self) -> Result<(), SupabaseProviderError> {
        if self.mode == TransportMode::BlockedEnv {
            Err(SupabaseProviderError::BlockedEnv)
        } else {
            Ok(())
        }
    }

    fn default_management(
        request: &ManagementMetadataRequest,
    ) -> Result<ManagementMetadataObservation, SupabaseProviderError> {
        ManagementMetadataObservation::new(
            &SupabaseScope {
                project_id: "fixture-project".into(),
                project_ref: request.project_ref.clone(),
                region: request.region.clone(),
                management_api_host: "https://api.supabase.com".into(),
                auth_api_host: SupabaseScope::expected_auth_issuer(&request.project_ref),
                postgrest_api_host: format!("https://{}.supabase.co/rest/v1", request.project_ref),
                auth_issuer: SupabaseScope::expected_auth_issuer(&request.project_ref),
                auth_audience: "authenticated".into(),
                tenant_id: "fixture-tenant".into(),
                subject_user_id: Some("fixture-user".into()),
                allowed_roles: std::collections::BTreeSet::from(["authenticated".into()]),
                tables: std::collections::BTreeSet::from([TableScope::new("public", "profiles")
                    .map_err(|_| {
                    SupabaseProviderError::InvalidResponse {
                        field: "fixture_scope".into(),
                    }
                })?]),
                allowlisted_columns: std::collections::BTreeMap::new(),
                allowed_functions: std::collections::BTreeSet::new(),
                grant_revision: "grant-revision-1".into(),
                policy_revision: "policy-revision-1".into(),
                mission: MissionScope::default(),
            },
            PROVIDER_API_REVISION,
            request.observed_at,
            256,
        )
        .map_err(|_| SupabaseProviderError::InvalidResponse {
            field: "management_observation".into(),
        })
    }

    fn default_identity(
        request: &AuthIdentityRequest,
    ) -> Result<AuthIdentityObservation, SupabaseProviderError> {
        let mut scope = crate::SupabaseScope::fixture();
        scope.project_ref.clone_from(&request.project_ref);
        scope.region.clone_from(&request.region);
        scope.auth_audience.clone_from(&request.auth_audience);
        scope.auth_issuer.clone_from(&request.auth_issuer);
        scope.auth_api_host.clone_from(&request.auth_issuer);
        scope.tenant_id.clone_from(&request.tenant_id);
        scope.mission.tenant_id.clone_from(&request.tenant_id);
        scope.subject_user_id.clone_from(&request.subject_user_id);
        scope.allowed_roles = request.allowed_roles.iter().cloned().collect();
        scope
            .validate()
            .map_err(|_| SupabaseProviderError::InvalidResponse {
                field: "fixture_scope".into(),
            })?;
        let identity = crate::SupabaseIdentityRecord::new(
            request
                .subject_user_id
                .clone()
                .unwrap_or_else(|| "fixture-user".into()),
            request.tenant_id.clone(),
            request
                .allowed_roles
                .first()
                .cloned()
                .unwrap_or_else(|| "authenticated".into()),
            crate::IdentityState::Active,
            PROVIDER_API_REVISION,
        )
        .map_err(|_| SupabaseProviderError::InvalidResponse {
            field: "identity".into(),
        })?;
        let claims =
            crate::JwtClaimsEvidence::fixture(&scope, request.observed_at, &identity.user_id);
        let mut observation = AuthIdentityObservation::new(
            &scope,
            Some(identity),
            Some(claims),
            PROVIDER_API_REVISION,
            request.observed_at,
            1024,
        )
        .map_err(|_| SupabaseProviderError::InvalidResponse {
            field: "identity_observation".into(),
        })?;
        observation.scope_digest.clone_from(&request.scope_digest);
        observation.response_digest = observation.expected_response_digest().map_err(|_| {
            SupabaseProviderError::InvalidResponse {
                field: "identity_digest".into(),
            }
        })?;
        Ok(observation)
    }

    fn default_policy(
        request: &PostgrestMetadataRequest,
    ) -> Result<PostgrestMetadataObservation, SupabaseProviderError> {
        let mut grants = Vec::new();
        let mut policies = Vec::new();
        let scope = crate::SupabaseScope::fixture();
        for table in &request.tables {
            for role in &request.allowed_roles {
                grants.push(
                    crate::DatabaseGrant::select(
                        role.clone(),
                        table.clone(),
                        request.tenant_id.clone(),
                    )
                    .map_err(|_| SupabaseProviderError::InvalidResponse {
                        field: "grant".into(),
                    })?,
                );
                policies.push(
                    crate::RlsPolicyEvidence::allow_read(
                        format!("fixture-{}-{}", table.key(), role),
                        table.clone(),
                        role.clone(),
                        request.tenant_id.clone(),
                        request.policy_revision.clone(),
                    )
                    .map_err(|_| SupabaseProviderError::InvalidResponse {
                        field: "policy".into(),
                    })?,
                );
            }
        }
        let mut observation = PostgrestMetadataObservation::new(
            &scope,
            grants,
            policies,
            PROVIDER_API_REVISION,
            request.observed_at,
            4096,
        )
        .map_err(|_| SupabaseProviderError::InvalidResponse {
            field: "policy_observation".into(),
        })?;
        observation.scope_digest.clone_from(&request.scope_digest);
        observation.project_ref.clone_from(&request.project_ref);
        observation.region.clone_from(&request.region);
        observation.tenant_id.clone_from(&request.tenant_id);
        observation
            .grant_revision
            .clone_from(&request.grant_revision);
        observation
            .policy_revision
            .clone_from(&request.policy_revision);
        observation.response_digest = observation.expected_response_digest().map_err(|_| {
            SupabaseProviderError::InvalidResponse {
                field: "policy_digest".into(),
            }
        })?;
        Ok(observation)
    }
}

impl SupabaseHttpsTransport for RecordingSupabaseTransport {
    fn mode(&self) -> TransportMode {
        self.mode
    }

    fn read_management_metadata(
        &self,
        request: &ManagementMetadataRequest,
    ) -> Result<ManagementMetadataObservation, SupabaseProviderError> {
        self.fault()?;
        self.ensure_environment()?;
        self.calls
            .lock()
            .expect("calls lock")
            .push(SupabaseProviderCall::ManagementMetadata {
                scope_digest: request.scope_digest.clone(),
                project_ref: request.project_ref.clone(),
                secret_reference_id: request.secret_reference.reference_id().into(),
            });
        self.management_observation
            .lock()
            .expect("management observation lock")
            .clone()
            .map_or_else(|| Self::default_management(request), Ok)
    }

    fn read_auth_identity(
        &self,
        request: &AuthIdentityRequest,
    ) -> Result<AuthIdentityObservation, SupabaseProviderError> {
        self.fault()?;
        self.ensure_environment()?;
        self.calls
            .lock()
            .expect("calls lock")
            .push(SupabaseProviderCall::AuthIdentity {
                scope_digest: request.scope_digest.clone(),
                project_ref: request.project_ref.clone(),
                tenant_id: request.tenant_id.clone(),
                subject_user_id: request.subject_user_id.clone(),
                secret_reference_id: request.secret_reference.reference_id().into(),
            });
        self.identity_observation
            .lock()
            .expect("identity observation lock")
            .clone()
            .map_or_else(|| Self::default_identity(request), Ok)
    }

    fn read_postgrest_metadata(
        &self,
        request: &PostgrestMetadataRequest,
    ) -> Result<PostgrestMetadataObservation, SupabaseProviderError> {
        self.fault()?;
        self.ensure_environment()?;
        let table_digests = request
            .tables
            .iter()
            .map(|table| digest_parts(&[&table.key()]))
            .collect();
        self.calls
            .lock()
            .expect("calls lock")
            .push(SupabaseProviderCall::PostgrestMetadata {
                scope_digest: request.scope_digest.clone(),
                project_ref: request.project_ref.clone(),
                tenant_id: request.tenant_id.clone(),
                table_digests,
                secret_reference_id: request.secret_reference.reference_id().into(),
            });
        self.policy_observation
            .lock()
            .expect("policy observation lock")
            .clone()
            .map_or_else(|| Self::default_policy(request), Ok)
    }
}

/// Typed provider that can only call the three redacted metadata seams.
#[derive(Clone)]
pub struct SupabaseIdentityProvider {
    manifest: SupabaseProviderManifest,
    transport: Arc<dyn SupabaseHttpsTransport>,
}

impl fmt::Debug for SupabaseIdentityProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupabaseIdentityProvider")
            .field("manifest", &self.manifest)
            .field("transport_mode", &self.transport.mode())
            .finish()
    }
}

impl SupabaseIdentityProvider {
    pub fn new<T>(
        scope: &SupabaseScope,
        permissions: &SupabasePermissionSet,
        transport: T,
    ) -> Result<Self, SupabaseIdentityError>
    where
        T: SupabaseHttpsTransport + 'static,
    {
        let manifest = SupabaseProviderManifest::baseline(scope, permissions, transport.mode())?;
        Self::from_manifest(manifest, permissions, transport)
    }

    pub fn from_manifest<T>(
        manifest: SupabaseProviderManifest,
        permissions: &SupabasePermissionSet,
        transport: T,
    ) -> Result<Self, SupabaseIdentityError>
    where
        T: SupabaseHttpsTransport + 'static,
    {
        manifest.validate_for(&manifest.scope, permissions)?;
        if manifest.transport_mode != transport.mode()
            || transport.mode().native_status() != NativeStatus::BlockedEnv
        {
            return Err(SupabaseIdentityError::ContractDrift);
        }
        Ok(Self {
            manifest,
            transport: Arc::new(transport),
        })
    }

    pub fn fixture(
        scope: &SupabaseScope,
        permissions: &SupabasePermissionSet,
    ) -> Result<Self, SupabaseIdentityError> {
        Self::new(scope, permissions, RecordingSupabaseTransport::fixture())
    }

    pub fn blocked_env(
        scope: &SupabaseScope,
        permissions: &SupabasePermissionSet,
    ) -> Result<Self, SupabaseIdentityError> {
        Self::new(
            scope,
            permissions,
            RecordingSupabaseTransport::blocked_env(),
        )
    }

    pub fn manifest(&self) -> &SupabaseProviderManifest {
        &self.manifest
    }

    pub fn provider_digest(&self) -> &str {
        &self.manifest.provider_digest
    }

    pub fn permission_digest(&self) -> &str {
        &self.manifest.permission_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.manifest.scope_digest
    }

    pub fn transport_mode(&self) -> TransportMode {
        self.transport.mode()
    }

    pub fn provenance(&self) -> EvidenceProvenance {
        self.transport.mode().into()
    }

    pub const fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn capability_description(
        &self,
        scope: &SupabaseScope,
    ) -> Result<CapabilityDescription, SupabaseIdentityError> {
        if self.manifest.scope_digest != scope.digest() {
            return Err(SupabaseIdentityError::RegistrationDrift);
        }
        Ok(CapabilityDescription {
            capability_id: CAPABILITY_ID.into(),
            plugin_id: PLUGIN_ID.into(),
            plugin_version: PLUGIN_VERSION.into(),
            provider_id: PROVIDER_ID.into(),
            contract_digest: crate::contract_digest(),
            provider_digest: self.manifest.provider_digest.clone(),
            permission_digest: self.manifest.permission_digest.clone(),
            scope_digest: self.manifest.scope_digest.clone(),
            operations: [
                SupabaseOperation::DescribeCapabilities,
                SupabaseOperation::ProbeRegistration,
                SupabaseOperation::ReadProjectMetadata,
                SupabaseOperation::ReadAuthIdentity,
                SupabaseOperation::ReadJwtClaimEvidence,
                SupabaseOperation::ReadDatabaseGrants,
                SupabaseOperation::ReadRlsPolicyMetadata,
                SupabaseOperation::CompilePolicyDecisionProposal,
            ]
            .into_iter()
            .collect(),
            provenance: self.provenance(),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            identity_authority: false,
            truth_authority: false,
            effect_authority: false,
        })
    }

    pub fn read_management_metadata(
        &self,
        scope: &SupabaseScope,
        secret_reference: &SecretReference,
        observed_at: DateTime<Utc>,
    ) -> Result<ManagementMetadataObservation, SupabaseProviderError> {
        self.validate_request(scope, secret_reference)?;
        let request = ManagementMetadataRequest {
            scope_digest: scope.digest(),
            project_ref: scope.project_ref.clone(),
            region: scope.region.clone(),
            secret_reference: secret_reference.clone(),
            observed_at,
        };
        self.transport.read_management_metadata(&request)
    }

    pub fn read_auth_identity(
        &self,
        scope: &SupabaseScope,
        secret_reference: &SecretReference,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthIdentityObservation, SupabaseProviderError> {
        self.validate_request(scope, secret_reference)?;
        let request = AuthIdentityRequest {
            scope_digest: scope.digest(),
            project_ref: scope.project_ref.clone(),
            region: scope.region.clone(),
            tenant_id: scope.tenant_id.clone(),
            auth_audience: scope.auth_audience.clone(),
            auth_issuer: scope.auth_issuer.clone(),
            subject_user_id: scope.subject_user_id.clone(),
            allowed_roles: scope.allowed_roles.iter().cloned().collect(),
            secret_reference: secret_reference.clone(),
            observed_at,
        };
        self.transport.read_auth_identity(&request)
    }

    pub fn read_postgrest_metadata(
        &self,
        scope: &SupabaseScope,
        secret_reference: &SecretReference,
        observed_at: DateTime<Utc>,
    ) -> Result<PostgrestMetadataObservation, SupabaseProviderError> {
        self.validate_request(scope, secret_reference)?;
        let allowlisted_columns = scope
            .allowlisted_columns
            .iter()
            .map(|(table, columns)| (table.clone(), columns.iter().cloned().collect()))
            .collect();
        let request = PostgrestMetadataRequest {
            scope_digest: scope.digest(),
            project_ref: scope.project_ref.clone(),
            region: scope.region.clone(),
            tenant_id: scope.tenant_id.clone(),
            tables: scope.tables.iter().cloned().collect(),
            allowlisted_columns,
            allowed_roles: scope.allowed_roles.iter().cloned().collect(),
            grant_revision: scope.grant_revision.clone(),
            policy_revision: scope.policy_revision.clone(),
            secret_reference: secret_reference.clone(),
            observed_at,
        };
        self.transport.read_postgrest_metadata(&request)
    }

    fn validate_request(
        &self,
        scope: &SupabaseScope,
        secret_reference: &SecretReference,
    ) -> Result<(), SupabaseProviderError> {
        if secret_reference.is_service_role() {
            return Err(SupabaseProviderError::ServiceRoleRejected);
        }
        if secret_reference.validate().is_err()
            || secret_reference.project_ref() != scope.project_ref
            || secret_reference.scope_digest() != scope.digest()
            || self.manifest.scope_digest != scope.digest()
        {
            return Err(SupabaseProviderError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Name required by the external plugin seam in the issue description.
pub type SupabaseAuthRlsProvider = SupabaseIdentityProvider;
