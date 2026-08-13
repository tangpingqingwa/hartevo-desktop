//! Vendor-neutral Runtime service-provider plugin lifecycle.
//!
//! A provider manifest may name a concrete implementation, but the service definition and the
//! Mission-facing mount are deliberately generic. Registration teardown is explicit: every
//! stream, tool, and hook registered by a mount must be stopped or removed before the mount can
//! become unmounted or revoked.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::to_vec;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const RUNTIME_SERVICE_DEFINITION_SCHEMA: &str = "hartevo.runtime-service-definition/v1";
pub const RUNTIME_SERVICE_PROVIDER_MANIFEST_SCHEMA: &str =
    "hartevo.runtime-service-provider-manifest/v1";
pub const RUNTIME_PLUGIN_SCOPE_SCHEMA: &str = "hartevo.runtime-plugin-scope/v1";
pub const RUNTIME_PLUGIN_MOUNT_SCHEMA: &str = "hartevo.runtime-plugin-mount/v1";
const MAX_CAPABILITIES: usize = 32;
const MAX_REGISTRATIONS: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeServiceCapability {
    Initialize,
    Thread,
    Turn,
    ItemStream,
    Interrupt,
    Resume,
    TypedResultPacket,
    ModelVisibleSessionLog,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeServiceDefinition {
    pub schema: String,
    pub service_id: String,
    pub revision: String,
    pub capabilities: Vec<RuntimeServiceCapability>,
    pub service_digest: String,
}

impl RuntimeServiceDefinition {
    pub fn new(
        service_id: impl Into<String>,
        revision: impl Into<String>,
        mut capabilities: Vec<RuntimeServiceCapability>,
    ) -> Result<Self, RuntimePluginError> {
        capabilities.sort_unstable();
        capabilities.dedup();
        let mut definition = Self {
            schema: RUNTIME_SERVICE_DEFINITION_SCHEMA.to_owned(),
            service_id: service_id.into(),
            revision: revision.into(),
            capabilities,
            service_digest: String::new(),
        };
        definition.service_digest = definition.computed_digest()?;
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), RuntimePluginError> {
        if self.schema != RUNTIME_SERVICE_DEFINITION_SCHEMA
            || !bounded_identifier(&self.service_id)
            || !bounded_identifier(&self.revision)
            || self.capabilities.is_empty()
            || self.capabilities.len() > MAX_CAPABILITIES
            || self
                .capabilities
                .windows(2)
                .any(|window| window[0] >= window[1])
            || !is_digest(&self.service_digest)
            || self.computed_digest()? != self.service_digest
        {
            return Err(RuntimePluginError::InvalidServiceDefinition);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, RuntimePluginError> {
        self.validate()?;
        Ok(self.service_digest.clone())
    }

    fn computed_digest(&self) -> Result<String, RuntimePluginError> {
        let material = ServiceDefinitionDigestMaterial {
            schema: &self.schema,
            service_id: &self.service_id,
            revision: &self.revision,
            capabilities: &self.capabilities,
        };
        digest_json(&material)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceDefinitionDigestMaterial<'a> {
    schema: &'a str,
    service_id: &'a str,
    revision: &'a str,
    capabilities: &'a [RuntimeServiceCapability],
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeServiceProviderManifest {
    pub schema: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub service_definition: RuntimeServiceDefinition,
    pub service_definition_digest: String,
    pub manifest_digest: String,
}

impl RuntimeServiceProviderManifest {
    pub fn new(
        provider_id: impl Into<String>,
        provider_revision: impl Into<String>,
        service_definition: &RuntimeServiceDefinition,
    ) -> Result<Self, RuntimePluginError> {
        service_definition.validate()?;
        let mut manifest = Self {
            schema: RUNTIME_SERVICE_PROVIDER_MANIFEST_SCHEMA.to_owned(),
            provider_id: provider_id.into(),
            provider_revision: provider_revision.into(),
            service_definition: service_definition.clone(),
            service_definition_digest: service_definition.digest()?,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.computed_digest()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), RuntimePluginError> {
        if self.schema != RUNTIME_SERVICE_PROVIDER_MANIFEST_SCHEMA
            || !bounded_identifier(&self.provider_id)
            || !bounded_identifier(&self.provider_revision)
            || self.service_definition.validate().is_err()
            || self.service_definition.digest()? != self.service_definition_digest
            || !is_digest(&self.service_definition_digest)
            || !is_digest(&self.manifest_digest)
            || self.computed_digest()? != self.manifest_digest
        {
            return Err(RuntimePluginError::InvalidProviderManifest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, RuntimePluginError> {
        self.validate()?;
        Ok(self.manifest_digest.clone())
    }
}

impl fmt::Debug for RuntimeServiceProviderManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeServiceProviderManifest")
            .field("schema", &self.schema)
            .field("provider_digest", &digest(self.provider_id.as_bytes()))
            .field("provider_revision", &self.provider_revision)
            .field("service_definition_digest", &self.service_definition_digest)
            .field("manifest_digest", &self.manifest_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderManifestDigestMaterial<'a> {
    schema: &'a str,
    provider_id: &'a str,
    provider_revision: &'a str,
    service_definition_digest: &'a str,
}

impl RuntimeServiceProviderManifest {
    fn computed_digest(&self) -> Result<String, RuntimePluginError> {
        digest_json(&ProviderManifestDigestMaterial {
            schema: &self.schema,
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            service_definition_digest: &self.service_definition_digest,
        })
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimePluginScope {
    pub schema: String,
    pub project_id: String,
    pub mission_id: String,
    pub session_id: String,
    pub scope_digest: String,
}

impl RuntimePluginScope {
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Result<Self, RuntimePluginError> {
        let mut scope = Self {
            schema: RUNTIME_PLUGIN_SCOPE_SCHEMA.to_owned(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            session_id: session_id.into(),
            scope_digest: String::new(),
        };
        scope.scope_digest = scope.computed_digest()?;
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), RuntimePluginError> {
        if self.schema != RUNTIME_PLUGIN_SCOPE_SCHEMA
            || !bounded_identifier(&self.project_id)
            || !bounded_identifier(&self.mission_id)
            || !bounded_identifier(&self.session_id)
            || !is_digest(&self.scope_digest)
            || self.computed_digest()? != self.scope_digest
        {
            return Err(RuntimePluginError::InvalidPluginScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, RuntimePluginError> {
        self.validate()?;
        Ok(self.scope_digest.clone())
    }
}

impl fmt::Debug for RuntimePluginScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePluginScope")
            .field("schema", &self.schema)
            .field("project_digest", &digest(self.project_id.as_bytes()))
            .field("mission_digest", &digest(self.mission_id.as_bytes()))
            .field("session_digest", &digest(self.session_id.as_bytes()))
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginScopeDigestMaterial<'a> {
    schema: &'a str,
    project_id: &'a str,
    mission_id: &'a str,
    session_id: &'a str,
}

impl RuntimePluginScope {
    fn computed_digest(&self) -> Result<String, RuntimePluginError> {
        digest_json(&PluginScopeDigestMaterial {
            schema: &self.schema,
            project_id: &self.project_id,
            mission_id: &self.mission_id,
            session_id: &self.session_id,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePluginRegistrationKind {
    Stream,
    Tool,
    Hook,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePluginMountState {
    Mounted,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimePluginRegistration {
    pub registration_digest: String,
    pub kind: RuntimePluginRegistrationKind,
}

/// A mounted provider's exact reversible registration set.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimePluginMount {
    pub schema: String,
    pub manifest: RuntimeServiceProviderManifest,
    pub scope: RuntimePluginScope,
    pub mount_digest: String,
    pub state: RuntimePluginMountState,
    registrations: BTreeMap<String, RuntimePluginRegistration>,
}

impl fmt::Debug for RuntimePluginMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePluginMount")
            .field("schema", &self.schema)
            .field("manifest", &self.manifest)
            .field("scope", &self.scope)
            .field("mount_digest", &self.mount_digest)
            .field("state", &self.state)
            .field("registration_count", &self.registrations.len())
            .finish()
    }
}

impl RuntimePluginMount {
    pub fn new(
        manifest: RuntimeServiceProviderManifest,
        scope: RuntimePluginScope,
    ) -> Result<Self, RuntimePluginError> {
        manifest.validate()?;
        scope.validate()?;
        let mut mount = Self {
            schema: RUNTIME_PLUGIN_MOUNT_SCHEMA.to_owned(),
            manifest,
            scope,
            mount_digest: String::new(),
            state: RuntimePluginMountState::Mounted,
            registrations: BTreeMap::new(),
        };
        mount.mount_digest = mount.computed_digest()?;
        mount.validate()?;
        Ok(mount)
    }

    pub fn validate(&self) -> Result<(), RuntimePluginError> {
        if self.schema != RUNTIME_PLUGIN_MOUNT_SCHEMA
            || self.registrations.len() > MAX_REGISTRATIONS
            || (self.state != RuntimePluginMountState::Mounted && !self.registrations.is_empty())
            || !is_digest(&self.mount_digest)
            || self.computed_digest()? != self.mount_digest
        {
            return Err(RuntimePluginError::InvalidPluginMount);
        }
        self.manifest.validate()?;
        self.scope.validate()?;
        for (key, registration) in &self.registrations {
            if key != &registration.registration_digest || !is_digest(key) {
                return Err(RuntimePluginError::InvalidPluginRegistration);
            }
        }
        Ok(())
    }

    pub fn register(
        &mut self,
        kind: RuntimePluginRegistrationKind,
        opaque_registration_id: &str,
    ) -> Result<String, RuntimePluginError> {
        if self.state != RuntimePluginMountState::Mounted {
            return Err(RuntimePluginError::PluginMountNotActive);
        }
        if !bounded_identifier(opaque_registration_id)
            || self.registrations.len() >= MAX_REGISTRATIONS
        {
            return Err(RuntimePluginError::InvalidPluginRegistration);
        }
        let registration_digest = digest(opaque_registration_id.as_bytes());
        if self.registrations.contains_key(&registration_digest) {
            return Err(RuntimePluginError::DuplicatePluginRegistration);
        }
        self.registrations.insert(
            registration_digest.clone(),
            RuntimePluginRegistration {
                registration_digest: registration_digest.clone(),
                kind,
            },
        );
        self.validate()?;
        Ok(registration_digest)
    }

    pub fn active_registration_count(&self) -> usize {
        self.registrations.len()
    }

    pub fn unmount(
        &mut self,
        stopper: &mut dyn RuntimePluginRegistrationStopper,
    ) -> Result<RuntimePluginTeardownReceipt, RuntimePluginError> {
        self.teardown(RuntimePluginMountState::Unmounted, stopper)
    }

    pub fn revoke(
        &mut self,
        stopper: &mut dyn RuntimePluginRegistrationStopper,
    ) -> Result<RuntimePluginTeardownReceipt, RuntimePluginError> {
        self.teardown(RuntimePluginMountState::Revoked, stopper)
    }

    fn teardown(
        &mut self,
        target_state: RuntimePluginMountState,
        stopper: &mut dyn RuntimePluginRegistrationStopper,
    ) -> Result<RuntimePluginTeardownReceipt, RuntimePluginError> {
        if self.state == RuntimePluginMountState::Revoked {
            return Ok(self.teardown_receipt(0));
        }
        if self.state == RuntimePluginMountState::Unmounted
            && target_state == RuntimePluginMountState::Unmounted
        {
            return Ok(self.teardown_receipt(0));
        }
        let registrations = self.registrations.values().cloned().collect::<Vec<_>>();
        for registration in &registrations {
            match registration.kind {
                RuntimePluginRegistrationKind::Stream => {
                    stopper.stop_stream(&registration.registration_digest)?;
                }
                RuntimePluginRegistrationKind::Tool => {
                    stopper.unregister_tool(&registration.registration_digest)?;
                }
                RuntimePluginRegistrationKind::Hook => {
                    stopper.remove_hook(&registration.registration_digest)?;
                }
            }
        }
        self.registrations.clear();
        self.state = target_state;
        self.validate()?;
        Ok(self.teardown_receipt(registrations.len()))
    }

    fn teardown_receipt(&self, stopped_registration_count: usize) -> RuntimePluginTeardownReceipt {
        RuntimePluginTeardownReceipt {
            mount_digest: self.mount_digest.clone(),
            state: self.state,
            stopped_registration_count,
            residual_registration_count: self.registrations.len(),
        }
    }

    fn computed_digest(&self) -> Result<String, RuntimePluginError> {
        digest_json(&PluginMountDigestMaterial {
            schema: &self.schema,
            manifest_digest: &self.manifest.manifest_digest,
            scope_digest: &self.scope.scope_digest,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginMountDigestMaterial<'a> {
    schema: &'a str,
    manifest_digest: &'a str,
    scope_digest: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimePluginTeardownReceipt {
    pub mount_digest: String,
    pub state: RuntimePluginMountState,
    pub stopped_registration_count: usize,
    pub residual_registration_count: usize,
}

pub trait RuntimePluginRegistrationStopper {
    fn stop_stream(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError>;
    fn unregister_tool(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError>;
    fn remove_hook(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError>;
}

#[derive(Debug, Error)]
pub enum RuntimePluginError {
    #[error("runtime plugin service definition is invalid")]
    InvalidServiceDefinition,
    #[error("runtime plugin provider manifest is invalid")]
    InvalidProviderManifest,
    #[error("runtime plugin scope is invalid")]
    InvalidPluginScope,
    #[error("runtime plugin mount is invalid")]
    InvalidPluginMount,
    #[error("runtime plugin registration is invalid")]
    InvalidPluginRegistration,
    #[error("runtime plugin registration is duplicated")]
    DuplicatePluginRegistration,
    #[error("runtime plugin mount is not active")]
    PluginMountNotActive,
    #[error("runtime plugin registration teardown failed")]
    RegistrationTeardownFailed,
    #[error("runtime plugin JSON serialization failed")]
    Serialization(#[from] serde_json::Error),
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, RuntimePluginError> {
    Ok(digest(&to_vec(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[derive(Default)]
    struct RecordingStopper {
        streams: BTreeSet<String>,
        tools: BTreeSet<String>,
        hooks: BTreeSet<String>,
    }

    impl RuntimePluginRegistrationStopper for RecordingStopper {
        fn stop_stream(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError> {
            self.streams.insert(registration_digest.to_owned());
            Ok(())
        }

        fn unregister_tool(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError> {
            self.tools.insert(registration_digest.to_owned());
            Ok(())
        }

        fn remove_hook(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError> {
            self.hooks.insert(registration_digest.to_owned());
            Ok(())
        }
    }

    fn definition() -> RuntimeServiceDefinition {
        RuntimeServiceDefinition::new(
            "runtime.execution",
            "v1",
            vec![
                RuntimeServiceCapability::Initialize,
                RuntimeServiceCapability::Thread,
                RuntimeServiceCapability::Turn,
                RuntimeServiceCapability::ItemStream,
                RuntimeServiceCapability::Interrupt,
                RuntimeServiceCapability::Resume,
                RuntimeServiceCapability::TypedResultPacket,
                RuntimeServiceCapability::ModelVisibleSessionLog,
            ],
        )
        .expect("service definition")
    }

    #[test]
    fn service_definition_is_vendor_neutral_and_digest_bound() {
        let definition = definition();
        let wire = serde_json::to_string(&definition).expect("definition wire");
        assert!(!wire.contains("openinterpreter"));
        assert_eq!(definition.service_digest.len(), 64);
        assert!(definition.validate().is_ok());

        let mut manifest =
            RuntimeServiceProviderManifest::new("provider-a", "revision-a", &definition)
                .expect("provider manifest");
        manifest.service_definition.capabilities.pop();
        assert!(matches!(
            manifest.validate(),
            Err(RuntimePluginError::InvalidProviderManifest)
        ));
    }

    #[test]
    fn unmount_stops_every_registration_and_leaves_no_residue() {
        let manifest =
            RuntimeServiceProviderManifest::new("openinterpreter", "rust-v0.0.34", &definition())
                .expect("provider manifest");
        let scope = RuntimePluginScope::new("project-plugin", "mission-plugin", "session-plugin")
            .expect("plugin scope");
        let mut mount = RuntimePluginMount::new(manifest, scope).expect("mount");
        let stream = mount
            .register(RuntimePluginRegistrationKind::Stream, "turn-stream")
            .expect("stream registration");
        let tool = mount
            .register(RuntimePluginRegistrationKind::Tool, "tool-registration")
            .expect("tool registration");
        let hook = mount
            .register(RuntimePluginRegistrationKind::Hook, "hook-registration")
            .expect("hook registration");
        let mut stopper = RecordingStopper::default();
        let receipt = mount.unmount(&mut stopper).expect("unmount");
        assert_eq!(receipt.state, RuntimePluginMountState::Unmounted);
        assert_eq!(receipt.stopped_registration_count, 3);
        assert_eq!(receipt.residual_registration_count, 0);
        assert_eq!(mount.active_registration_count(), 0);
        assert!(stopper.streams.contains(&stream));
        assert!(stopper.tools.contains(&tool));
        assert!(stopper.hooks.contains(&hook));
        assert!(matches!(
            mount.register(RuntimePluginRegistrationKind::Tool, "late-tool"),
            Err(RuntimePluginError::PluginMountNotActive)
        ));
        let revoked = mount
            .revoke(&mut stopper)
            .expect("revoke unmounted provider");
        assert_eq!(revoked.state, RuntimePluginMountState::Revoked);
        assert_eq!(revoked.residual_registration_count, 0);
    }

    #[test]
    fn revoke_directly_stops_registrations_and_is_idempotent() {
        let manifest =
            RuntimeServiceProviderManifest::new("provider-a", "revision-a", &definition())
                .expect("provider manifest");
        let scope =
            RuntimePluginScope::new("project-a", "mission-a", "session-a").expect("plugin scope");
        let mut mount = RuntimePluginMount::new(manifest, scope).expect("mount");
        mount
            .register(RuntimePluginRegistrationKind::Stream, "stream-a")
            .expect("stream registration");
        let mut stopper = RecordingStopper::default();
        let receipt = mount.revoke(&mut stopper).expect("revoke");
        assert_eq!(receipt.state, RuntimePluginMountState::Revoked);
        assert_eq!(receipt.stopped_registration_count, 1);
        assert_eq!(receipt.residual_registration_count, 0);
        let replay = mount.revoke(&mut stopper).expect("idempotent revoke");
        assert_eq!(replay.stopped_registration_count, 0);
        assert_eq!(replay.residual_registration_count, 0);
        assert_eq!(stopper.streams.len(), 1);
    }
}
