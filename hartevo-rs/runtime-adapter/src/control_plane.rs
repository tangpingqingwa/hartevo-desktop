//! Provider / model / harness control-plane types and protocol helpers.
//!
//! This module deliberately contains only runtime configuration and opaque credential
//! references.  It does not know about Hartevo missions, business effects, receipts, or
//! verification.  Secrets are resolved for one child-process spawn and are never retained by
//! the runtime adapter after the OS process has inherited its environment.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    AdapterError, AppServerContract, JsonRpcResponse, RuntimeMapping, RuntimeProtocolWriteReceipt,
    StdioRuntime,
};

const CONTROL_PLANE_CONTRACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/openinterpreter/control-plane.v1.json"
));
const CONTROL_PLANE_SCHEMA: &str = "hartevo.openinterpreter-control-plane/v1";
pub const CONTROL_PLANE_CONTRACT_SHA256: &str =
    "d3fca6f6829cdb4d4dde4aec98b2e62c7839f6e80c47ee375ac2e089a95e1798";
const SECRET_REFERENCE_SCHEMA_VERSION: u32 = 1;
const RUNTIME_CONFIG_SCHEMA_VERSION: u32 = 1;
const RUNTIME_CATALOG_SCHEMA_VERSION: u32 = 1;
const MAX_CATALOG_ENTRIES: usize = 4_096;
const MAX_CONFIG_STRING_BYTES: usize = 1_024;
const MAX_SECRET_BYTES: usize = 256 * 1024;

/// The App Server wire protocol selected by a provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeWireApi {
    Responses,
    Chat,
    Messages,
}

/// The endpoint class is kept separate from the provider's display metadata so that a
/// configuration cannot silently change wire protocol during a restart.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEndpointClass {
    Responses,
    Chat,
    Messages,
    Local,
}

impl RuntimeEndpointClass {
    fn from_wire_api(value: &str) -> Option<Self> {
        match value {
            "responses" => Some(Self::Responses),
            "chat" => Some(Self::Chat),
            "messages" => Some(Self::Messages),
            "local" => Some(Self::Local),
            _ => None,
        }
    }
}

/// Data-retention boundary declared by the selected runtime route.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDataBoundary {
    ProjectLocal,
    ProviderDeclared,
    ProviderNoTraining,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeBudget {
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_turns: u32,
    pub max_turn_duration_ms: u64,
}

impl RuntimeBudget {
    pub fn new(
        max_input_tokens: u64,
        max_output_tokens: u64,
        max_turns: u32,
        max_turn_duration_ms: u64,
    ) -> Result<Self, AdapterError> {
        let budget = Self {
            max_input_tokens,
            max_output_tokens,
            max_turns,
            max_turn_duration_ms,
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.max_input_tokens == 0
            || self.max_input_tokens > 64 * 1024 * 1024
            || self.max_output_tokens == 0
            || self.max_output_tokens > 64 * 1024 * 1024
            || self.max_turns == 0
            || self.max_turns > 1_024
            || self.max_turn_duration_ms == 0
            || self.max_turn_duration_ms > 24 * 60 * 60 * 1_000
        {
            return Err(AdapterError::InvalidRuntimeBudget);
        }
        Ok(())
    }
}

/// An opaque reference to a credential owned by an OS keyring or another Hartevo-owned secret
/// store.  The reference is safe to persist; the resolved material is intentionally not.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretReference {
    pub schema_version: u32,
    pub provider_id: String,
    pub account_id: String,
    pub reference_id: String,
    pub project_scope_digest: String,
    pub revision: u64,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("schema_version", &self.schema_version)
            .field("provider_digest", &digest(self.provider_id.as_bytes()))
            .field("account_digest", &digest(self.account_id.as_bytes()))
            .field("reference_digest", &digest(self.reference_id.as_bytes()))
            .field("project_scope_digest", &self.project_scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        provider_id: impl Into<String>,
        account_id: impl Into<String>,
        reference_id: impl Into<String>,
        project_scope_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, AdapterError> {
        let reference = Self {
            schema_version: SECRET_REFERENCE_SCHEMA_VERSION,
            provider_id: provider_id.into(),
            account_id: account_id.into(),
            reference_id: reference_id.into(),
            project_scope_digest: project_scope_digest.into(),
            revision,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema_version != SECRET_REFERENCE_SCHEMA_VERSION
            || !catalog_identifier(&self.provider_id)
            || !bounded_string(&self.account_id)
            || !bounded_string(&self.reference_id)
            || !is_sha256(&self.project_scope_digest)
            || self.revision == 0
        {
            return Err(AdapterError::InvalidSecretReference);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, AdapterError> {
        self.validate()?;
        digest_json(self)
    }
}

/// A short-lived secret value.  It has no serialization implementation and its Debug output is
/// deliberately redacted.
pub struct ResolvedSecret {
    value: Zeroizing<String>,
}

impl ResolvedSecret {
    pub fn new(value: impl Into<String>) -> Result<Self, AdapterError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.contains('\0') {
            return Err(AdapterError::InvalidSecretMaterial);
        }
        Ok(Self {
            value: Zeroizing::new(value),
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSecret")
            .field("byte_count", &self.value.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Hartevo-owned secret boundary.  Implementations may use OS keyring, encrypted local state,
/// or a test fixture; the runtime adapter never owns the backing store.
pub trait SecretResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<ResolvedSecret, AdapterError>;
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretBinding {
    pub environment_key: String,
    pub reference: SecretReference,
}

impl fmt::Debug for SecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBinding")
            .field("environment_key", &self.environment_key)
            .field("reference", &self.reference)
            .finish()
    }
}

impl SecretBinding {
    pub fn new(
        environment_key: impl Into<String>,
        reference: SecretReference,
    ) -> Result<Self, AdapterError> {
        let binding = Self {
            environment_key: environment_key.into(),
            reference,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if !environment_key(&self.environment_key) {
            return Err(AdapterError::InvalidSecretBinding);
        }
        self.reference.validate()
    }
}

pub(crate) struct ResolvedSecretBinding {
    pub(crate) environment_key: String,
    pub(crate) secret: ResolvedSecret,
}

pub(crate) fn resolve_secret_bindings(
    bindings: &[SecretBinding],
    resolver: &dyn SecretResolver,
) -> Result<Vec<ResolvedSecretBinding>, AdapterError> {
    validate_secret_bindings(bindings)?;
    bindings
        .iter()
        .map(|binding| {
            let reference_digest = binding.reference.digest()?;
            let secret = resolver
                .resolve(&binding.reference)
                .map_err(|_| AdapterError::SecretResolutionFailed { reference_digest })?;
            if secret.as_str().is_empty() {
                return Err(AdapterError::InvalidSecretMaterial);
            }
            Ok(ResolvedSecretBinding {
                environment_key: binding.environment_key.clone(),
                secret,
            })
        })
        .collect()
}

pub(crate) fn validate_secret_bindings(bindings: &[SecretBinding]) -> Result<(), AdapterError> {
    if bindings.len() > 16 {
        return Err(AdapterError::TooManySecretBindings);
    }
    let mut keys = BTreeSet::new();
    for binding in bindings {
        binding.validate()?;
        if !keys.insert(binding.environment_key.as_str()) {
            return Err(AdapterError::DuplicateSecretEnvironmentKey);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeServiceTier {
    pub id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProviderDescriptor {
    pub id: String,
    pub revision: String,
    pub endpoint_class: RuntimeEndpointClass,
    pub credential_environment_key: Option<String>,
    pub configured: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeModelDescriptor {
    pub provider_id: String,
    pub id: String,
    pub revision: String,
    pub supported_reasoning_efforts: Vec<String>,
    pub service_tiers: Vec<RuntimeServiceTier>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeHarnessDescriptor {
    pub provider_id: String,
    pub model_id: Option<String>,
    pub id: String,
    pub revision: String,
    pub recommended: bool,
}

/// Canonical, content-free Provider / Model / Harness catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCatalog {
    pub schema_version: u32,
    pub catalog_version: String,
    pub app_server_schema_digest: String,
    pub providers: Vec<RuntimeProviderDescriptor>,
    pub models: Vec<RuntimeModelDescriptor>,
    pub harnesses: Vec<RuntimeHarnessDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeModelDiscovery {
    pub provider_id: String,
    pub response: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHarnessDiscovery {
    pub provider_id: String,
    pub model_id: Option<String>,
    pub response: Value,
}

impl RuntimeCatalog {
    pub fn new(
        catalog_version: impl Into<String>,
        app_server_schema_digest: impl Into<String>,
        providers: Vec<RuntimeProviderDescriptor>,
        models: Vec<RuntimeModelDescriptor>,
        harnesses: Vec<RuntimeHarnessDescriptor>,
    ) -> Result<Self, AdapterError> {
        let catalog = Self {
            schema_version: RUNTIME_CATALOG_SCHEMA_VERSION,
            catalog_version: catalog_version.into(),
            app_server_schema_digest: app_server_schema_digest.into(),
            providers,
            models,
            harnesses,
        };
        let mut catalog = catalog;
        catalog.canonicalize();
        catalog.validate()?;
        Ok(catalog)
    }

    fn canonicalize(&mut self) {
        self.providers.sort_by(|left, right| left.id.cmp(&right.id));
        self.models.sort_by(|left, right| {
            left.provider_id
                .cmp(&right.provider_id)
                .then_with(|| left.id.cmp(&right.id))
        });
        for model in &mut self.models {
            model.supported_reasoning_efforts.sort();
            model
                .service_tiers
                .sort_by(|left, right| left.id.cmp(&right.id));
        }
        self.harnesses.sort_by(|left, right| {
            left.provider_id
                .cmp(&right.provider_id)
                .then_with(|| left.model_id.cmp(&right.model_id))
                .then_with(|| left.id.cmp(&right.id))
        });
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema_version != RUNTIME_CATALOG_SCHEMA_VERSION
            || !bounded_string(&self.catalog_version)
            || !is_schema_digest(&self.app_server_schema_digest)
            || self.providers.is_empty()
            || self.providers.len() > MAX_CATALOG_ENTRIES
            || self.models.len() > MAX_CATALOG_ENTRIES
            || self.harnesses.len() > MAX_CATALOG_ENTRIES
        {
            return Err(AdapterError::InvalidRuntimeCatalog);
        }
        let provider_ids = self
            .providers
            .iter()
            .map(|provider| {
                validate_provider_descriptor(provider)?;
                Ok(provider.id.as_str())
            })
            .collect::<Result<BTreeSet<_>, AdapterError>>()?;
        if provider_ids.len() != self.providers.len() {
            return Err(AdapterError::DuplicateRuntimeCatalogEntry);
        }
        let mut model_keys = BTreeSet::new();
        for model in &self.models {
            validate_model_descriptor(model)?;
            if !provider_ids.contains(model.provider_id.as_str())
                || !model_keys.insert((model.provider_id.as_str(), model.id.as_str()))
            {
                return Err(AdapterError::InvalidRuntimeCatalog);
            }
        }
        let mut harness_keys = BTreeSet::new();
        for harness in &self.harnesses {
            validate_harness_descriptor(harness)?;
            if !provider_ids.contains(harness.provider_id.as_str())
                || harness.model_id.as_ref().is_some_and(|model| {
                    !model_keys.contains(&(harness.provider_id.as_str(), model))
                })
                || !harness_keys.insert((
                    harness.provider_id.as_str(),
                    harness.model_id.as_deref(),
                    harness.id.as_str(),
                ))
            {
                return Err(AdapterError::InvalidRuntimeCatalog);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, AdapterError> {
        let mut canonical = self.clone();
        canonical.canonicalize();
        canonical.validate()?;
        digest_json(&canonical)
    }

    pub fn provider(&self, id: &str) -> Option<&RuntimeProviderDescriptor> {
        self.providers.iter().find(|provider| provider.id == id)
    }

    pub fn model(&self, provider_id: &str, id: &str) -> Option<&RuntimeModelDescriptor> {
        self.models
            .iter()
            .find(|model| model.provider_id == provider_id && model.id == id)
    }

    pub fn harness(
        &self,
        provider_id: &str,
        model_id: &str,
        id: &str,
    ) -> Option<&RuntimeHarnessDescriptor> {
        self.harnesses.iter().find(|harness| {
            harness.provider_id == provider_id
                && harness.id == id
                && harness
                    .model_id
                    .as_deref()
                    .is_none_or(|candidate| candidate == model_id)
        })
    }

    /// Parse the exact response envelopes returned by the pinned App Server.  When upstream
    /// does not expose a semantic revision field, the canonical response entry digest becomes
    /// the revision.  This is a pin, not a claim that the provider supplied a release version.
    #[allow(
        clippy::too_many_lines,
        reason = "discovery parsing remains one auditable canonicalization boundary for the pinned App Server response shapes"
    )]
    pub fn from_app_server_discovery(
        catalog_version: impl Into<String>,
        app_server_schema_digest: impl Into<String>,
        provider_response: &Value,
        model_responses: &[RuntimeModelDiscovery],
        harness_responses: &[RuntimeHarnessDiscovery],
    ) -> Result<Self, AdapterError> {
        let provider_entries = response_data(provider_response)?;
        let mut providers = Vec::with_capacity(provider_entries.len());
        for entry in provider_entries {
            let id = required_string(entry, "id")?;
            let endpoint_class = entry
                .get("wireApi")
                .and_then(Value::as_str)
                .and_then(RuntimeEndpointClass::from_wire_api)
                .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?;
            let credential_environment_key = entry
                .get("envKey")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if credential_environment_key
                .as_deref()
                .is_some_and(|key| !environment_key(key))
            {
                return Err(AdapterError::InvalidRuntimeCatalogResponse);
            }
            providers.push(RuntimeProviderDescriptor {
                id,
                revision: response_revision(entry)?,
                endpoint_class,
                credential_environment_key,
                configured: entry
                    .get("configured")
                    .and_then(Value::as_bool)
                    .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?,
            });
        }
        let provider_ids = providers
            .iter()
            .map(|provider| provider.id.as_str())
            .collect::<BTreeSet<_>>();

        let mut models = Vec::new();
        for discovery in model_responses {
            if !catalog_identifier(&discovery.provider_id) {
                return Err(AdapterError::InvalidRuntimeCatalogResponse);
            }
            for entry in response_data(&discovery.response)? {
                let id = entry
                    .get("model")
                    .and_then(Value::as_str)
                    .or_else(|| entry.get("id").and_then(Value::as_str))
                    .filter(|value| bounded_string(value))
                    .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?
                    .to_owned();
                let supported_reasoning_efforts = entry
                    .get("supportedReasoningEfforts")
                    .and_then(Value::as_array)
                    .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?
                    .iter()
                    .map(|option| {
                        option
                            .get("reasoningEffort")
                            .and_then(Value::as_str)
                            .filter(|value| bounded_string(value))
                            .map(str::to_owned)
                            .ok_or(AdapterError::InvalidRuntimeCatalogResponse)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let service_tiers = entry
                    .get("serviceTiers")
                    .and_then(Value::as_array)
                    .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?
                    .iter()
                    .map(|tier| {
                        let id = required_string(tier, "id")?;
                        Ok(RuntimeServiceTier {
                            id,
                            revision: response_revision(tier)?,
                        })
                    })
                    .collect::<Result<Vec<_>, AdapterError>>()?;
                models.push(RuntimeModelDescriptor {
                    provider_id: discovery.provider_id.clone(),
                    id,
                    revision: response_revision(entry)?,
                    supported_reasoning_efforts,
                    service_tiers,
                });
            }
        }
        let mut harnesses = Vec::new();
        for discovery in harness_responses {
            if !provider_ids.contains(discovery.provider_id.as_str()) {
                return Err(AdapterError::InvalidRuntimeCatalogResponse);
            }
            for entry in response_data(&discovery.response)? {
                let id = entry
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .unwrap_or("native")
                    .to_owned();
                harnesses.push(RuntimeHarnessDescriptor {
                    provider_id: discovery.provider_id.clone(),
                    model_id: discovery.model_id.clone(),
                    id,
                    revision: response_revision(entry)?,
                    recommended: entry
                        .get("isRecommended")
                        .and_then(Value::as_bool)
                        .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?,
                });
            }
        }
        Self::new(
            catalog_version,
            app_server_schema_digest,
            providers,
            models,
            harnesses,
        )
    }

    pub fn validate_config(&self, config: &RuntimeExecutionConfig) -> Result<(), AdapterError> {
        config.validate()?;
        let actual_catalog_digest = self.digest()?;
        if config.catalog_digest != actual_catalog_digest {
            return Err(AdapterError::RuntimeCatalogDrift {
                expected_digest: config.catalog_digest.clone(),
                actual_digest: actual_catalog_digest,
            });
        }
        let provider = self
            .provider(&config.provider_id)
            .ok_or(AdapterError::RuntimeProviderUnavailable)?;
        if provider.revision != config.provider_revision
            || provider.endpoint_class != config.endpoint_class
        {
            return Err(AdapterError::RuntimeConfigDrift { field: "provider" });
        }
        let model = self
            .model(&config.provider_id, &config.model_id)
            .ok_or(AdapterError::RuntimeModelUnavailable)?;
        if model.revision != config.model_revision
            || config
                .reasoning_effort
                .as_ref()
                .is_some_and(|effort| !model.supported_reasoning_efforts.contains(effort))
            || config.service_tier.as_ref().is_some_and(|tier| {
                !model
                    .service_tiers
                    .iter()
                    .any(|candidate| candidate.id == *tier)
            })
        {
            return Err(AdapterError::RuntimeConfigDrift { field: "model" });
        }
        let harness = self
            .harness(&config.provider_id, &config.model_id, &config.harness_id)
            .ok_or(AdapterError::RuntimeHarnessUnavailable)?;
        if harness.revision != config.harness_revision {
            return Err(AdapterError::RuntimeConfigDrift { field: "harness" });
        }
        if config.credential_reference.provider_id != config.provider_id {
            return Err(AdapterError::RuntimeConfigDrift {
                field: "credential_reference",
            });
        }
        Ok(())
    }

    /// Resolve the provider's declared environment slot without resolving the secret itself.
    /// The returned binding is still opaque and must be handed to
    /// `StdioRuntime::spawn_with_secret_resolver`.
    pub fn secret_binding(
        &self,
        config: &RuntimeExecutionConfig,
    ) -> Result<Option<SecretBinding>, AdapterError> {
        self.validate_config(config)?;
        let Some(environment_key) = self
            .provider(&config.provider_id)
            .and_then(|provider| provider.credential_environment_key.clone())
        else {
            return Ok(None);
        };
        SecretBinding::new(environment_key, config.credential_reference.clone()).map(Some)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeExecutionConfig {
    pub schema_version: u32,
    pub provider_id: String,
    pub provider_revision: String,
    pub model_id: String,
    pub model_revision: String,
    pub harness_id: String,
    pub harness_revision: String,
    pub reasoning_effort: Option<String>,
    pub service_tier: Option<String>,
    pub endpoint_class: RuntimeEndpointClass,
    pub budget: RuntimeBudget,
    pub data_boundary: RuntimeDataBoundary,
    pub credential_reference: SecretReference,
    pub catalog_digest: String,
}

impl fmt::Debug for RuntimeExecutionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeExecutionConfig")
            .field("schema_version", &self.schema_version)
            .field("provider_digest", &digest(self.provider_id.as_bytes()))
            .field("provider_revision", &self.provider_revision)
            .field("model_digest", &digest(self.model_id.as_bytes()))
            .field("model_revision", &self.model_revision)
            .field("harness_id", &self.harness_id)
            .field("harness_revision", &self.harness_revision)
            .field("reasoning_effort", &self.reasoning_effort)
            .field("service_tier", &self.service_tier)
            .field("endpoint_class", &self.endpoint_class)
            .field("budget", &self.budget)
            .field("data_boundary", &self.data_boundary)
            .field("credential_reference", &self.credential_reference)
            .field("catalog_digest", &self.catalog_digest)
            .finish()
    }
}

impl RuntimeExecutionConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: impl Into<String>,
        provider_revision: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        harness_id: impl Into<String>,
        harness_revision: impl Into<String>,
        reasoning_effort: Option<String>,
        service_tier: Option<String>,
        endpoint_class: RuntimeEndpointClass,
        budget: RuntimeBudget,
        data_boundary: RuntimeDataBoundary,
        credential_reference: SecretReference,
        catalog_digest: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        let config = Self {
            schema_version: RUNTIME_CONFIG_SCHEMA_VERSION,
            provider_id: provider_id.into(),
            provider_revision: provider_revision.into(),
            model_id: model_id.into(),
            model_revision: model_revision.into(),
            harness_id: harness_id.into(),
            harness_revision: harness_revision.into(),
            reasoning_effort,
            service_tier,
            endpoint_class,
            budget,
            data_boundary,
            credential_reference,
            catalog_digest: catalog_digest.into(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema_version != RUNTIME_CONFIG_SCHEMA_VERSION
            || !catalog_identifier(&self.provider_id)
            || !is_sha256(&self.provider_revision)
            || !bounded_string(&self.model_id)
            || !is_sha256(&self.model_revision)
            || !catalog_identifier(&self.harness_id)
            || !is_sha256(&self.harness_revision)
            || self
                .reasoning_effort
                .as_deref()
                .is_some_and(|value| !bounded_string(value))
            || self
                .service_tier
                .as_deref()
                .is_some_and(|value| !catalog_identifier(value))
            || !is_sha256(&self.catalog_digest)
        {
            return Err(AdapterError::InvalidRuntimeExecutionConfig);
        }
        self.budget.validate()?;
        self.credential_reference.validate()
    }

    pub fn digest(&self) -> Result<String, AdapterError> {
        self.validate()?;
        digest_json(self)
    }

    pub fn wire_harness(&self) -> Option<&str> {
        (self.harness_id != "native").then_some(self.harness_id.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "capability negotiation is an explicit wire-compatible feature bitset"
)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCapabilities {
    pub protocol_version: String,
    pub schema_digest: String,
    pub provider_catalog: bool,
    pub model_catalog: bool,
    pub harness_catalog: bool,
    pub local_approval: bool,
    pub interrupt: bool,
    pub steer: bool,
    pub bounded_stream: bool,
    pub typed_tool_recovery: bool,
}

impl RuntimeCapabilities {
    pub fn supports(&self, capability: &str) -> bool {
        match capability {
            "provider-catalog" => self.provider_catalog,
            "model-catalog" => self.model_catalog,
            "harness-catalog" => self.harness_catalog,
            "local-approval" => self.local_approval,
            "interrupt" => self.interrupt,
            "steer" => self.steer,
            "bounded-stream" => self.bounded_stream,
            "typed-tool-recovery" => self.typed_tool_recovery,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRecoveryAction {
    ReconcileBeforeRetry,
    RebuildContext,
    UserReview,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRecoveryHint {
    pub item_id_digest: String,
    pub error_digest: String,
    pub category: String,
    pub action: RuntimeRecoveryAction,
    pub automatic_retry_allowed: bool,
}

pub(crate) fn recovery_hint_for_item(item: &Value) -> Option<RuntimeRecoveryHint> {
    let error = item.get("error")?;
    let item_id = item
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("unknown-item");
    let category = error
        .get("code")
        .and_then(Value::as_str)
        .or_else(|| error.get("type").and_then(Value::as_str))
        .unwrap_or("tool_error");
    let action = match category {
        "context_length_exceeded" | "context_overflow" => RuntimeRecoveryAction::RebuildContext,
        "timeout" | "rate_limit" | "temporarily_unavailable" | "server_error" => {
            RuntimeRecoveryAction::ReconcileBeforeRetry
        }
        _ => RuntimeRecoveryAction::UserReview,
    };
    Some(RuntimeRecoveryHint {
        item_id_digest: digest(item_id.as_bytes()),
        error_digest: digest_json(error).ok()?,
        category: category.to_owned(),
        action,
        automatic_retry_allowed: false,
    })
}

impl StdioRuntime {
    pub fn negotiate_capabilities(
        &mut self,
        timeout: Duration,
    ) -> Result<RuntimeCapabilities, AdapterError> {
        let health = self.health_check(timeout)?;
        let provider_request = AppServerContract::provider_list(self.next_request_id()?, true);
        let provider_catalog =
            self.probe_data_method(provider_request, "interpreter/provider/list", timeout)?;
        let model_request = AppServerContract::model_list(self.next_request_id()?, None, false);
        let model_catalog =
            self.probe_data_method(model_request, "interpreter/model/list", timeout)?;
        let harness_catalog = if provider_catalog {
            let provider_id = self
                .last_control_plane_provider_id
                .clone()
                .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?;
            let harness_request =
                AppServerContract::harness_list(self.next_request_id()?, &provider_id, None);
            self.probe_data_method(harness_request, "interpreter/harness/list", timeout)?
        } else {
            false
        };
        Ok(RuntimeCapabilities {
            protocol_version: super::PROTOCOL_VERSION.to_owned(),
            schema_digest: health.schema_digest,
            provider_catalog,
            model_catalog,
            harness_catalog,
            local_approval: AppServerContract::stable_server_requests().map(|methods| {
                methods
                    .iter()
                    .any(|method| method.ends_with("requestApproval"))
            })?,
            interrupt: AppServerContract::stable_methods()?
                .iter()
                .any(|method| method == "turn/interrupt"),
            steer: AppServerContract::stable_methods()?
                .iter()
                .any(|method| method == "turn/steer"),
            bounded_stream: true,
            typed_tool_recovery: true,
        })
    }

    pub fn discover_runtime_catalog(
        &mut self,
        catalog_version: impl Into<String>,
        timeout: Duration,
    ) -> Result<RuntimeCatalog, AdapterError> {
        let capabilities = self.negotiate_capabilities(timeout)?;
        if !capabilities.provider_catalog
            || !capabilities.model_catalog
            || !capabilities.harness_catalog
        {
            return Err(AdapterError::CapabilityNotNegotiated {
                capability: "provider/model/harness catalog",
            });
        }
        let provider_request = AppServerContract::provider_list(self.next_request_id()?, true);
        let provider_response =
            self.control_plane_response(provider_request, "interpreter/provider/list", timeout)?;
        let provider_ids = response_data(
            provider_response
                .result
                .as_ref()
                .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?,
        )?
        .iter()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
        if provider_ids.is_empty() {
            return Err(AdapterError::InvalidRuntimeCatalogResponse);
        }
        let mut model_responses = Vec::new();
        let mut harness_responses = Vec::new();
        for provider_id in &provider_ids {
            let model_request =
                AppServerContract::model_list(self.next_request_id()?, Some(provider_id), false);
            let model_response =
                self.control_plane_response(model_request, "interpreter/model/list", timeout)?;
            for model in response_data(
                model_response
                    .result
                    .as_ref()
                    .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?,
            )? {
                let model_id = model
                    .get("model")
                    .and_then(Value::as_str)
                    .or_else(|| model.get("id").and_then(Value::as_str))
                    .ok_or(AdapterError::InvalidRuntimeCatalogResponse)?
                    .to_owned();
                let harness_request = AppServerContract::harness_list(
                    self.next_request_id()?,
                    provider_id,
                    Some(&model_id),
                );
                let harness_response = self.control_plane_response(
                    harness_request,
                    "interpreter/harness/list",
                    timeout,
                )?;
                harness_responses.push(RuntimeHarnessDiscovery {
                    provider_id: provider_id.clone(),
                    model_id: Some(model_id),
                    response: harness_response.result.unwrap_or(Value::Null),
                });
            }
            model_responses.push(RuntimeModelDiscovery {
                provider_id: provider_id.clone(),
                response: model_response.result.unwrap_or(Value::Null),
            });
        }
        RuntimeCatalog::from_app_server_discovery(
            catalog_version,
            &capabilities.schema_digest,
            &provider_response.result.unwrap_or(Value::Null),
            &model_responses,
            &harness_responses,
        )
    }

    pub fn apply_runtime_config(
        &mut self,
        capabilities: &RuntimeCapabilities,
        catalog: &RuntimeCatalog,
        config: &RuntimeExecutionConfig,
        timeout: Duration,
    ) -> Result<String, AdapterError> {
        if let Err(error) = catalog.validate_config(config) {
            self.poisoned = true;
            return Err(error);
        }
        if capabilities.schema_digest != catalog.app_server_schema_digest {
            self.poisoned = true;
            return Err(AdapterError::RuntimeSchemaDrift {
                expected_digest: catalog.app_server_schema_digest.clone(),
                actual_digest: capabilities.schema_digest.clone(),
            });
        }
        for capability in ["provider-catalog", "model-catalog", "harness-catalog"] {
            if !capabilities.supports(capability) {
                self.poisoned = true;
                return Err(AdapterError::CapabilityNotNegotiated { capability });
            }
        }
        let provider_set_request =
            AppServerContract::provider_set(self.next_request_id()?, &config.provider_id);
        self.expect_empty_config_response(
            provider_set_request,
            "interpreter/provider/set",
            timeout,
        )?;
        let model_set_request = AppServerContract::model_set(
            self.next_request_id()?,
            &config.model_id,
            config.reasoning_effort.as_deref(),
        );
        self.expect_empty_config_response(model_set_request, "interpreter/model/set", timeout)?;
        let harness_set_request =
            AppServerContract::harness_set(self.next_request_id()?, config.wire_harness());
        self.expect_empty_config_response(harness_set_request, "interpreter/harness/set", timeout)?;
        config.digest()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the configured thread boundary keeps project, mission, workspace, negotiated catalog, exact config, and timeout explicit"
    )]
    pub fn start_mapped_thread_with_config(
        &mut self,
        project_id: &str,
        mission_id: &str,
        runtime_generation: u64,
        workspace_root: &Path,
        capabilities: &RuntimeCapabilities,
        catalog: &RuntimeCatalog,
        config: &RuntimeExecutionConfig,
        timeout: Duration,
    ) -> Result<RuntimeMapping, AdapterError> {
        self.apply_runtime_config(capabilities, catalog, config, timeout)?;
        let mapping = self.start_mapped_thread(
            project_id,
            mission_id,
            runtime_generation,
            workspace_root,
            Some(&config.model_id),
            timeout,
        )?;
        let binding_matches = mapping.runtime_model_provider == config.provider_id
            && mapping.runtime_model == config.model_id;
        if !binding_matches {
            self.poisoned = true;
            return Err(AdapterError::RuntimeConfigDrift { field: "thread" });
        }
        RuntimeMapping::new_with_config(
            project_id,
            mission_id,
            runtime_generation,
            self.instance_digest().to_owned(),
            config.clone(),
            mapping.runtime_thread_id,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the configured resume boundary keeps project, mission, persisted thread, workspace, negotiated catalog, exact config, and timeout explicit"
    )]
    pub fn resume_mapped_thread_with_config(
        &mut self,
        project_id: &str,
        mission_id: &str,
        runtime_generation: u64,
        runtime_thread_id: &str,
        workspace_root: &Path,
        capabilities: &RuntimeCapabilities,
        catalog: &RuntimeCatalog,
        config: &RuntimeExecutionConfig,
        timeout: Duration,
    ) -> Result<RuntimeMapping, AdapterError> {
        self.apply_runtime_config(capabilities, catalog, config, timeout)?;
        let mapping = self.resume_mapped_thread(
            project_id,
            mission_id,
            runtime_generation,
            runtime_thread_id,
            workspace_root,
            timeout,
        )?;
        if mapping.runtime_model_provider != config.provider_id
            || mapping.runtime_model != config.model_id
        {
            self.poisoned = true;
            return Err(AdapterError::RuntimeConfigDrift { field: "resume" });
        }
        RuntimeMapping::new_with_config(
            project_id,
            mission_id,
            runtime_generation,
            self.instance_digest().to_owned(),
            config.clone(),
            mapping.runtime_thread_id,
        )
    }

    pub fn start_mapped_turn_with_config(
        &mut self,
        mapping: &RuntimeMapping,
        config: &RuntimeExecutionConfig,
        client_user_message_id: &str,
        prompt: &str,
        timeout: Duration,
    ) -> Result<super::RuntimeTurnDispatch, AdapterError> {
        let config_digest = config.digest()?;
        if mapping
            .runtime_config
            .as_ref()
            .and_then(|bound| bound.digest().ok())
            .as_deref()
            != Some(config_digest.as_str())
        {
            self.poisoned = true;
            return Err(AdapterError::RuntimeConfigDrift { field: "turn" });
        }
        self.start_mapped_turn(mapping, client_user_message_id, prompt, timeout)
    }

    pub fn steer_mapped_turn(
        &mut self,
        mapping: &RuntimeMapping,
        client_user_message_id: &str,
        prompt: &str,
        timeout: Duration,
    ) -> Result<RuntimeProtocolWriteReceipt, AdapterError> {
        self.validate_live_mapping(mapping, true)?;
        if !super::is_stable_client_method("turn/steer")
            || !super::is_bounded_identifier(client_user_message_id)
            || prompt.trim().is_empty()
        {
            return Err(AdapterError::InvalidTurnRequest);
        }
        let turn_id = mapping
            .runtime_turn_id
            .as_deref()
            .ok_or(AdapterError::InvalidRuntimeMapping)?;
        let id = self.next_request_id()?;
        let request = AppServerContract::turn_steer(
            id.clone(),
            &mapping.runtime_thread_id,
            turn_id,
            client_user_message_id,
            prompt,
        );
        let request_digest = digest_json(&serde_json::to_value(&request)?)?;
        self.send_request(&request)?;
        let (response, elapsed) = self.await_response(&id, "turn/steer", timeout)?;
        let response_digest = digest_json(&serde_json::to_value(&response)?)?;
        if let Some(error) = response.error {
            return Err(AdapterError::TurnSteerRejected {
                error_digest: digest_json(&error)?,
            });
        }
        if response
            .result
            .as_ref()
            .and_then(|result| result.get("turnId"))
            .and_then(Value::as_str)
            != Some(turn_id)
        {
            self.poisoned = true;
            return Err(AdapterError::InvalidTurnResponse { response_digest });
        }
        Ok(RuntimeProtocolWriteReceipt {
            request_digest,
            response_digest,
            elapsed,
        })
    }

    fn probe_data_method(
        &mut self,
        request: super::JsonRpcRequest,
        method: &str,
        timeout: Duration,
    ) -> Result<bool, AdapterError> {
        let response = self.control_plane_response(request, method, timeout)?;
        if response.error.is_some() {
            return Ok(false);
        }
        let data = response
            .result
            .as_ref()
            .and_then(|result| result.get("data"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                self.poisoned = true;
                AdapterError::InvalidRuntimeCatalogResponse
            })?;
        if method == "interpreter/provider/list" {
            self.last_control_plane_provider_id = data
                .first()
                .and_then(|entry| entry.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        Ok(true)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "request ownership makes the response correlation boundary consume exactly one outbound request"
    )]
    fn control_plane_response(
        &mut self,
        request: super::JsonRpcRequest,
        method: &str,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, AdapterError> {
        let id = request.id.clone();
        self.send_request(&request)?;
        let (response, _) = self.await_response(&id, method, timeout)?;
        Ok(response)
    }

    fn expect_empty_config_response(
        &mut self,
        request: super::JsonRpcRequest,
        method: &str,
        timeout: Duration,
    ) -> Result<(), AdapterError> {
        let response = self.control_plane_response(request, method, timeout)?;
        if let Some(error) = response.error {
            return Err(AdapterError::RuntimeConfigRequestRejected {
                method: method.to_owned(),
                error_digest: digest_json(&error)?,
            });
        }
        if response
            .result
            .as_ref()
            .and_then(Value::as_object)
            .is_none_or(|object| !object.is_empty())
        {
            self.poisoned = true;
            return Err(AdapterError::InvalidRuntimeConfigResponse {
                method: method.to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_provider_descriptor(provider: &RuntimeProviderDescriptor) -> Result<(), AdapterError> {
    if !catalog_identifier(&provider.id)
        || !is_sha256(&provider.revision)
        || provider
            .credential_environment_key
            .as_deref()
            .is_some_and(|key| !environment_key(key))
    {
        return Err(AdapterError::InvalidRuntimeCatalog);
    }
    Ok(())
}

fn validate_model_descriptor(model: &RuntimeModelDescriptor) -> Result<(), AdapterError> {
    let mut reasoning_efforts = BTreeSet::new();
    let mut service_tiers = BTreeSet::new();
    if !catalog_identifier(&model.provider_id)
        || !bounded_string(&model.id)
        || !is_sha256(&model.revision)
        || model
            .supported_reasoning_efforts
            .iter()
            .any(|effort| !bounded_string(effort) || !reasoning_efforts.insert(effort.as_str()))
        || model.service_tiers.iter().any(|tier| {
            !catalog_identifier(&tier.id)
                || !is_sha256(&tier.revision)
                || !service_tiers.insert(tier.id.as_str())
        })
    {
        return Err(AdapterError::InvalidRuntimeCatalog);
    }
    Ok(())
}

fn validate_harness_descriptor(harness: &RuntimeHarnessDescriptor) -> Result<(), AdapterError> {
    if !catalog_identifier(&harness.provider_id)
        || harness
            .model_id
            .as_deref()
            .is_some_and(|model| !bounded_string(model))
        || !catalog_identifier(&harness.id)
        || !is_sha256(&harness.revision)
    {
        return Err(AdapterError::InvalidRuntimeCatalog);
    }
    Ok(())
}

fn response_data(response: &Value) -> Result<&[Value], AdapterError> {
    response
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(AdapterError::InvalidRuntimeCatalogResponse)
}

fn response_revision(entry: &Value) -> Result<String, AdapterError> {
    if let Some(revision) = entry.get("revision").and_then(Value::as_str) {
        if is_sha256(revision) {
            return Ok(revision.to_owned());
        }
        return Err(AdapterError::InvalidRuntimeCatalogResponse);
    }
    digest_json(entry)
}

fn required_string(value: &Value, key: &str) -> Result<String, AdapterError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| bounded_string(value))
        .map(str::to_owned)
        .ok_or(AdapterError::InvalidRuntimeCatalogResponse)
}

fn control_plane_contract_valid() -> Result<(), AdapterError> {
    let value: Value = serde_json::from_str(CONTROL_PLANE_CONTRACT)?;
    if value.get("schema").and_then(Value::as_str) != Some(CONTROL_PLANE_SCHEMA)
        || value
            .get("catalog")
            .and_then(|catalog| catalog.get("identity"))
            .and_then(Value::as_str)
            != Some("sha256(canonical-json)")
    {
        return Err(AdapterError::InvalidControlPlaneContract);
    }
    Ok(())
}

pub fn control_plane_contract_digest() -> Result<String, AdapterError> {
    let value: Value = serde_json::from_str(CONTROL_PLANE_CONTRACT)?;
    control_plane_contract_valid()?;
    let digest = digest_json(&value)?;
    if digest != CONTROL_PLANE_CONTRACT_SHA256 {
        return Err(AdapterError::InvalidControlPlaneContract);
    }
    Ok(digest)
}

fn bounded_string(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONFIG_STRING_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

fn catalog_identifier(value: &str) -> bool {
    bounded_string(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn environment_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_schema_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256)
}

fn digest(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

fn digest_json(value: &impl Serialize) -> Result<String, AdapterError> {
    Ok(digest(&serde_json::to_vec(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision(byte: u8) -> String {
        (0..64).map(|_| char::from(byte)).collect()
    }

    fn schema_digest() -> String {
        format!("sha256:{}", revision(b'a'))
    }

    fn catalog() -> RuntimeCatalog {
        RuntimeCatalog::new(
            "fake-catalog-v1",
            schema_digest(),
            vec![RuntimeProviderDescriptor {
                id: "openai".to_owned(),
                revision: revision(b'b'),
                endpoint_class: RuntimeEndpointClass::Responses,
                credential_environment_key: Some("OPENAI_API_KEY".to_owned()),
                configured: true,
            }],
            vec![RuntimeModelDescriptor {
                provider_id: "openai".to_owned(),
                id: "gpt-5.6".to_owned(),
                revision: revision(b'c'),
                supported_reasoning_efforts: vec!["medium".to_owned(), "high".to_owned()],
                service_tiers: vec![
                    RuntimeServiceTier {
                        id: "default".to_owned(),
                        revision: revision(b'd'),
                    },
                    RuntimeServiceTier {
                        id: "flex".to_owned(),
                        revision: revision(b'1'),
                    },
                ],
            }],
            vec![RuntimeHarnessDescriptor {
                provider_id: "openai".to_owned(),
                model_id: Some("gpt-5.6".to_owned()),
                id: "native".to_owned(),
                revision: revision(b'e'),
                recommended: true,
            }],
        )
        .expect("valid fake catalog")
    }

    fn execution_config(catalog: &RuntimeCatalog) -> RuntimeExecutionConfig {
        RuntimeExecutionConfig::new(
            "openai",
            revision(b'b'),
            "gpt-5.6",
            revision(b'c'),
            "native",
            revision(b'e'),
            Some("medium".to_owned()),
            Some("default".to_owned()),
            RuntimeEndpointClass::Responses,
            RuntimeBudget::new(8_192, 4_096, 8, 60_000).expect("valid budget"),
            RuntimeDataBoundary::ProviderDeclared,
            SecretReference::new(
                "openai",
                "test-account",
                "keyring/openai/test",
                revision(b'f'),
                1,
            )
            .expect("valid reference"),
            catalog.digest().expect("catalog digest"),
        )
        .expect("valid execution config")
    }

    #[test]
    fn catalog_identity_and_exact_config_fail_closed_on_drift() {
        let catalog = catalog();
        let config = execution_config(&catalog);
        assert!(catalog.validate_config(&config).is_ok());
        let binding = catalog
            .secret_binding(&config)
            .expect("binding lookup")
            .expect("provider credential binding");
        assert_eq!(binding.environment_key, "OPENAI_API_KEY");
        assert_eq!(config.wire_harness(), None);
        let mut reordered = catalog.clone();
        reordered.models[0].supported_reasoning_efforts.reverse();
        reordered.models[0].service_tiers.reverse();
        assert_eq!(
            catalog.digest().expect("catalog digest"),
            reordered.digest().expect("canonical catalog digest")
        );

        let mut drifted_catalog = catalog.clone();
        drifted_catalog.models[0].revision = revision(b'0');
        assert!(matches!(
            drifted_catalog.validate_config(&config),
            Err(AdapterError::RuntimeCatalogDrift { .. })
        ));

        let mut drifted = config.clone();
        drifted.model_revision = revision(b'0');
        assert!(matches!(
            catalog.validate_config(&drifted),
            Err(AdapterError::RuntimeConfigDrift { field: "model" })
        ));
        assert_ne!(
            config.digest().expect("config digest"),
            drifted.digest().expect("config digest")
        );

        let mut harness_drift = config.clone();
        harness_drift.harness_revision = revision(b'0');
        assert!(matches!(
            catalog.validate_config(&harness_drift),
            Err(AdapterError::RuntimeConfigDrift { field: "harness" })
        ));
    }

    #[test]
    fn app_server_discovery_normalizes_native_harness_and_pins_entry_digests() {
        let provider_response = serde_json::json!({
            "data": [{
                "id": "openai",
                "wireApi": "responses",
                "envKey": "OPENAI_API_KEY",
                "configured": true
            }]
        });
        let model_response = serde_json::json!({
            "data": [{
                "model": "gpt-5.6",
                "supportedReasoningEfforts": [{"reasoningEffort": "medium"}],
                "serviceTiers": [{"id": "default"}]
            }]
        });
        let harness_response = serde_json::json!({
            "data": [{
                "id": null,
                "label": "Native",
                "description": "",
                "isRecommended": true
            }]
        });
        let catalog = RuntimeCatalog::from_app_server_discovery(
            "fake-discovery-v1",
            schema_digest(),
            &provider_response,
            &[RuntimeModelDiscovery {
                provider_id: "openai".to_owned(),
                response: model_response,
            }],
            &[RuntimeHarnessDiscovery {
                provider_id: "openai".to_owned(),
                model_id: Some("gpt-5.6".to_owned()),
                response: harness_response,
            }],
        )
        .expect("discovery catalog");
        assert_eq!(catalog.providers[0].id, "openai");
        assert_eq!(catalog.models[0].id, "gpt-5.6");
        assert_eq!(catalog.harnesses[0].id, "native");
        assert_eq!(catalog.harnesses[0].revision.len(), 64);
        assert_eq!(catalog.digest().expect("catalog digest").len(), 64);
    }

    #[test]
    fn recovery_hints_are_typed_and_never_authorize_uncertain_replay() {
        let hint = recovery_hint_for_item(&serde_json::json!({
            "id": "item-private",
            "error": {"code": "rate_limit", "message": "private detail"}
        }))
        .expect("typed recovery hint");
        assert_eq!(hint.action, RuntimeRecoveryAction::ReconcileBeforeRetry);
        assert!(!hint.automatic_retry_allowed);
        let rendered = format!("{hint:?}");
        assert!(!rendered.contains("private detail"));
    }

    #[test]
    fn secret_resolution_is_opaque_and_digest_only() {
        struct FakeResolver;

        impl SecretResolver for FakeResolver {
            fn resolve(&self, reference: &SecretReference) -> Result<ResolvedSecret, AdapterError> {
                assert_eq!(reference.provider_id, "openai");
                ResolvedSecret::new("credential-secret")
            }
        }

        let reference = SecretReference::new(
            "openai",
            "test-account",
            "keyring/openai/test",
            revision(b'f'),
            1,
        )
        .expect("reference");
        let binding = SecretBinding::new("OPENAI_API_KEY", reference.clone()).expect("binding");
        let resolved = resolve_secret_bindings(&[binding], &FakeResolver).expect("resolved");
        assert_eq!(resolved[0].secret.as_str(), "credential-secret");
        assert!(!format!("{reference:?}").contains("credential-secret"));
        assert!(!format!("{:?}", resolved[0].secret).contains("credential-secret"));
    }

    #[test]
    fn control_plane_contract_digest_is_canonical_and_pinned() {
        let digest = control_plane_contract_digest().expect("control-plane contract");
        assert_eq!(digest.len(), 64);
        assert!(control_plane_contract_valid().is_ok());
    }
}
