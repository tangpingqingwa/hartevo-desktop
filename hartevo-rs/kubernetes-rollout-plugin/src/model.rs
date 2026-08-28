use crate::{
    digest_json, digest_text, valid_digest_map, valid_identifier, valid_kubernetes_name,
    valid_sha256_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;

pub const MAX_CONDITIONS: usize = 32;
pub const MAX_REPLICA_SETS: usize = 32;
pub const MAX_PODS: usize = 256;
pub const MAX_CONTAINER_NAMES: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    KubeCredential,
    WorkloadIdentity,
}

/// Opaque identity for a credential supplied by the host.  It deliberately
/// has no secret bytes, serialization implementation, or conversion into a
/// bearer token, client key, certificate, or kubeconfig.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: String,
    scope_digest: Option<String>,
    credential_revision: u64,
    kind: AuthKind,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("kind", &self.kind)
            .finish()
    }
}

impl SecretReference {
    /// Creates an opaque, scope-unbound reference.  A service must bind it to
    /// the exact rollout scope before it can be used.
    pub fn new(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::with_kind(reference_id, credential_revision, AuthKind::KubeCredential)
    }

    pub fn for_workload_identity(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::with_kind(
            reference_id,
            credential_revision,
            AuthKind::WorkloadIdentity,
        )
    }

    pub fn for_scope(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
        scope_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let mut reference =
            Self::with_kind(reference_id, credential_revision, AuthKind::KubeCredential)?;
        let scope_digest = scope_digest.into();
        if !valid_sha256_digest(&scope_digest) {
            return Err(ModelError::InvalidDigest("secret reference scope".into()));
        }
        reference.scope_digest = Some(scope_digest);
        Ok(reference)
    }

    pub fn for_workload_identity_scope(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
        scope_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let mut reference = Self::with_kind(
            reference_id,
            credential_revision,
            AuthKind::WorkloadIdentity,
        )?;
        let scope_digest = scope_digest.into();
        if !valid_sha256_digest(&scope_digest) {
            return Err(ModelError::InvalidDigest("secret reference scope".into()));
        }
        reference.scope_digest = Some(scope_digest);
        Ok(reference)
    }

    fn with_kind(
        reference_id: impl AsRef<str>,
        credential_revision: u64,
        kind: AuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.as_ref();
        if !valid_identifier(reference_id, 256) || credential_revision == 0 {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: digest_text(reference_id),
            scope_digest: None,
            credential_revision,
            kind,
        })
    }

    pub fn reference_digest(&self) -> &str {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> Option<&str> {
        self.scope_digest.as_deref()
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn kind(&self) -> AuthKind {
        self.kind
    }

    pub(crate) fn validate_for_scope(&self, scope_digest: &str) -> Result<(), ModelError> {
        if self.scope_digest() != Some(scope_digest) {
            return Err(ModelError::AuthScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiServerEndpoint {
    pub url: String,
}

impl ApiServerEndpoint {
    pub fn new(url: impl Into<String>) -> Result<Self, ModelError> {
        let endpoint = Self { url: url.into() };
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let lower = self.url.to_ascii_lowercase();
        let authority = self
            .url
            .strip_prefix("https://")
            .or_else(|| self.url.strip_prefix("HTTPS://"))
            .or_else(|| lower.strip_prefix("https://"))
            .and_then(|value| value.split(['/', '?', '#']).next())
            .unwrap_or_default();
        if !lower.starts_with("https://")
            || authority.is_empty()
            || self.url.chars().any(char::is_whitespace)
            || self.url.contains('?')
            || self.url.contains('#')
        {
            return Err(ModelError::ApiServerMustBeHttps);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterIdentity {
    pub cluster_id: String,
    pub server_name: String,
}

impl ClusterIdentity {
    pub fn new(
        cluster_id: impl Into<String>,
        server_name: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let identity = Self {
            cluster_id: cluster_id.into(),
            server_name: server_name.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.cluster_id, 256) || !valid_identifier(&self.server_name, 256) {
            return Err(ModelError::InvalidClusterIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentIdentity {
    pub namespace: String,
    pub name: String,
    pub uid: String,
}

impl DeploymentIdentity {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        uid: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let identity = Self {
            namespace: namespace.into(),
            name: name.into(),
            uid: uid.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_kubernetes_name(&self.namespace)
            || !valid_kubernetes_name(&self.name)
            || !valid_identifier(&self.uid, 256)
        {
            return Err(ModelError::InvalidDeploymentIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageReference {
    pub repository: String,
    pub digest: String,
}

impl ImageReference {
    pub fn new(
        repository: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let image = Self {
            repository: repository.into(),
            digest: digest.into(),
        };
        image.validate()?;
        Ok(image)
    }

    pub fn canonical(&self) -> String {
        format!("{}@{}", self.repository, self.digest)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let repository = self.repository.as_str();
        let last_component = repository.rsplit('/').next().unwrap_or_default();
        if !valid_identifier(repository, 512)
            || repository.contains('@')
            || last_component.contains(':')
            || !valid_sha256_digest(&self.digest)
            || self.digest != self.digest.to_ascii_lowercase()
        {
            return Err(ModelError::ImageMustUseExactDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RbacCapability {
    GetDeployment,
    ListReplicaSets,
    GetReplicaSet,
    ListPods,
    GetPod,
    DryRunDeployment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RbacCapabilitySnapshot {
    pub revision: String,
    pub capabilities: BTreeSet<RbacCapability>,
    pub snapshot_digest: String,
}

impl RbacCapabilitySnapshot {
    pub fn new(
        revision: impl Into<String>,
        capabilities: impl IntoIterator<Item = RbacCapability>,
    ) -> Result<Self, ModelError> {
        let mut snapshot = Self {
            revision: revision.into(),
            capabilities: capabilities.into_iter().collect(),
            snapshot_digest: String::new(),
        };
        snapshot.validate_without_digest()?;
        snapshot.snapshot_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn read_only_default(revision: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(
            revision,
            [
                RbacCapability::GetDeployment,
                RbacCapability::ListReplicaSets,
                RbacCapability::GetReplicaSet,
                RbacCapability::ListPods,
                RbacCapability::GetPod,
                RbacCapability::DryRunDeployment,
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_without_digest()?;
        if self.snapshot_digest != self.compute_digest() {
            return Err(ModelError::RbacDigestMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> &str {
        &self.snapshot_digest
    }

    fn validate_without_digest(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.revision, 128) || self.capabilities.is_empty() {
            return Err(ModelError::InvalidRbacSnapshot);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            revision: &'a str,
            capabilities: &'a BTreeSet<RbacCapability>,
        }
        digest_json(&Material {
            revision: &self.revision,
            capabilities: &self.capabilities,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubernetesRolloutScope {
    pub api_server: ApiServerEndpoint,
    pub cluster_ca_spki_sha256: String,
    pub cluster_identity: ClusterIdentity,
    pub namespace: String,
    pub deployment: DeploymentIdentity,
    pub field_manager: String,
    pub allowed_images: BTreeMap<String, ImageReference>,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub consent_revision: u64,
    pub policy_revision: u64,
    pub rbac: RbacCapabilitySnapshot,
}

impl KubernetesRolloutScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_server: ApiServerEndpoint,
        cluster_ca_spki_sha256: impl Into<String>,
        cluster_identity: ClusterIdentity,
        namespace: impl Into<String>,
        deployment_name: impl Into<String>,
        deployment_uid: impl Into<String>,
        field_manager: impl Into<String>,
        allowed_images: BTreeMap<String, ImageReference>,
        mission_id: impl Into<String>,
        project_id: impl Into<String>,
        work_product_id: impl Into<String>,
        consent_revision: u64,
        policy_revision: u64,
        rbac: RbacCapabilitySnapshot,
    ) -> Result<Self, ModelError> {
        let namespace = namespace.into();
        let scope = Self {
            api_server,
            cluster_ca_spki_sha256: cluster_ca_spki_sha256.into(),
            cluster_identity,
            deployment: DeploymentIdentity {
                namespace: namespace.clone(),
                name: deployment_name.into(),
                uid: deployment_uid.into(),
            },
            namespace,
            field_manager: field_manager.into(),
            allowed_images,
            mission_id: mission_id.into(),
            project_id: project_id.into(),
            work_product_id: work_product_id.into(),
            consent_revision,
            policy_revision,
            rbac,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.api_server.validate()?;
        if !valid_sha256_digest(&self.cluster_ca_spki_sha256) {
            return Err(ModelError::InvalidDigest("cluster CA/SPKI".into()));
        }
        self.cluster_identity.validate()?;
        self.deployment.validate()?;
        if self.namespace != self.deployment.namespace
            || !valid_kubernetes_name(&self.namespace)
            || !valid_identifier(&self.field_manager, 128)
            || self.field_manager.contains('/')
            || self.allowed_images.is_empty()
            || self.allowed_images.len() > MAX_CONTAINER_NAMES
            || self.mission_id.is_empty()
            || self.project_id.is_empty()
            || self.work_product_id.is_empty()
            || !valid_identifier(&self.mission_id, 256)
            || !valid_identifier(&self.project_id, 256)
            || !valid_identifier(&self.work_product_id, 256)
            || self.consent_revision == 0
            || self.policy_revision == 0
        {
            return Err(ModelError::InvalidScope);
        }
        if self
            .allowed_images
            .iter()
            .any(|(name, image)| !valid_kubernetes_name(name) || image.validate().is_err())
        {
            return Err(ModelError::InvalidScope);
        }
        self.rbac.validate()
    }

    pub fn digest(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            api_server: &'a ApiServerEndpoint,
            cluster_ca_spki_sha256: &'a str,
            cluster_identity: &'a ClusterIdentity,
            namespace: &'a str,
            deployment: &'a DeploymentIdentity,
            field_manager: &'a str,
            allowed_images: &'a BTreeMap<String, ImageReference>,
            mission_id: &'a str,
            project_id: &'a str,
            work_product_id: &'a str,
            consent_revision: u64,
            policy_revision: u64,
            rbac_digest: &'a str,
        }
        digest_json(&Material {
            api_server: &self.api_server,
            cluster_ca_spki_sha256: &self.cluster_ca_spki_sha256,
            cluster_identity: &self.cluster_identity,
            namespace: &self.namespace,
            deployment: &self.deployment,
            field_manager: &self.field_manager,
            allowed_images: &self.allowed_images,
            mission_id: &self.mission_id,
            project_id: &self.project_id,
            work_product_id: &self.work_product_id,
            consent_revision: self.consent_revision,
            policy_revision: self.policy_revision,
            rbac_digest: self.rbac.digest(),
        })
    }

    pub fn expected_image_digests(&self) -> BTreeMap<String, String> {
        self.allowed_images
            .iter()
            .map(|(name, image)| (name.clone(), image.digest.clone()))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl EvidenceProvenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    Progressing,
    Available,
    Paused,
    Degraded,
    Stalled,
    Complete,
    Deleted,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloutCondition {
    pub condition_type: String,
    pub status: String,
    pub reason: Option<String>,
    pub observed_generation: Option<u64>,
}

impl RolloutCondition {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.condition_type, 128)
            || !matches!(self.status.as_str(), "True" | "False" | "Unknown")
            || self
                .reason
                .as_ref()
                .is_some_and(|value| !valid_identifier(value, 256))
        {
            return Err(ModelError::InvalidCondition);
        }
        Ok(())
    }

    fn is_known_type(&self) -> bool {
        matches!(
            self.condition_type.as_str(),
            "Available" | "Progressing" | "ReplicaFailure"
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplicaSetSnapshot {
    pub name: String,
    pub uid: String,
    pub revision: String,
    pub resource_version: String,
    pub desired_replicas: u32,
    pub updated_replicas: u32,
    pub ready_replicas: u32,
    pub available_replicas: u32,
}

impl ReplicaSetSnapshot {
    fn validate(&self) -> Result<(), ModelError> {
        if !valid_kubernetes_name(&self.name)
            || !valid_identifier(&self.uid, 256)
            || !valid_identifier(&self.revision, 128)
            || !valid_identifier(&self.resource_version, 128)
        {
            return Err(ModelError::InvalidEvidence("ReplicaSet identity".into()));
        }
        if self.ready_replicas > self.updated_replicas.max(self.desired_replicas)
            || self.available_replicas > self.updated_replicas.max(self.desired_replicas)
        {
            return Err(ModelError::InvalidEvidence(
                "ReplicaSet replica counts".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodRolloutEvidence {
    pub uid: String,
    pub phase: String,
    pub ready: bool,
    pub container_image_digests: BTreeMap<String, String>,
    pub resource_version: String,
}

impl PodRolloutEvidence {
    fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.uid, 256)
            || !valid_identifier(&self.phase, 64)
            || !valid_identifier(&self.resource_version, 128)
            || !valid_digest_map(&self.container_image_digests)
            || self
                .container_image_digests
                .keys()
                .any(|name| !valid_kubernetes_name(name))
        {
            return Err(ModelError::InvalidEvidence("Pod evidence".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentSnapshot {
    pub identity: DeploymentIdentity,
    pub resource_version: String,
    pub generation: u64,
    pub observed_generation: u64,
    pub spec_fingerprint: String,
    pub template_fingerprint: String,
    pub image_digests: BTreeMap<String, String>,
    pub desired_replicas: u32,
    pub updated_replicas: u32,
    pub ready_replicas: u32,
    pub available_replicas: u32,
    pub unavailable_replicas: u32,
    pub paused: bool,
    pub progress_deadline_seconds: Option<u32>,
    pub conditions: Vec<RolloutCondition>,
    pub replica_sets: Vec<ReplicaSetSnapshot>,
    pub pods: Vec<PodRolloutEvidence>,
    pub request_id: Option<String>,
}

impl DeploymentSnapshot {
    pub fn validate(&self) -> Result<(), ModelError> {
        self.identity.validate()?;
        if !valid_identifier(&self.resource_version, 128)
            || !valid_sha256_digest(&self.spec_fingerprint)
            || !valid_sha256_digest(&self.template_fingerprint)
            || !valid_digest_map(&self.image_digests)
            || self
                .image_digests
                .keys()
                .any(|name| !valid_kubernetes_name(name))
            || self.conditions.is_empty()
            || self.conditions.len() > MAX_CONDITIONS
            || self.replica_sets.len() > MAX_REPLICA_SETS
            || self.pods.len() > MAX_PODS
            || self
                .request_id
                .as_ref()
                .is_some_and(|value| !valid_identifier(value, 256))
        {
            return Err(ModelError::InvalidEvidence("Deployment snapshot".into()));
        }
        if self.updated_replicas > self.desired_replicas
            || self.ready_replicas > self.updated_replicas
            || self.available_replicas > self.updated_replicas
            || self.unavailable_replicas > self.desired_replicas
            || self.observed_generation > self.generation
            || self
                .progress_deadline_seconds
                .is_some_and(|seconds| seconds == 0)
        {
            return Err(ModelError::InvalidEvidence(
                "Deployment replica counts".into(),
            ));
        }
        for condition in &self.conditions {
            condition.validate()?;
            if condition
                .observed_generation
                .is_some_and(|generation| generation > self.generation)
            {
                return Err(ModelError::InvalidEvidence(
                    "condition observedGeneration".into(),
                ));
            }
        }
        for replica_set in &self.replica_sets {
            replica_set.validate()?;
        }
        for pod in &self.pods {
            pod.validate()?;
            if pod
                .container_image_digests
                .iter()
                .any(|(name, digest)| self.image_digests.get(name) != Some(digest))
            {
                return Err(ModelError::ImageDigestMismatch);
            }
        }
        Ok(())
    }

    pub fn object_fingerprint(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            identity: &'a DeploymentIdentity,
            resource_version: &'a str,
            generation: u64,
            spec_fingerprint: &'a str,
            template_fingerprint: &'a str,
            image_digests: &'a BTreeMap<String, String>,
        }
        digest_json(&Material {
            identity: &self.identity,
            resource_version: &self.resource_version,
            generation: self.generation,
            spec_fingerprint: &self.spec_fingerprint,
            template_fingerprint: &self.template_fingerprint,
            image_digests: &self.image_digests,
        })
    }

    pub fn status_fingerprint(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            observed_generation: u64,
            desired_replicas: u32,
            updated_replicas: u32,
            ready_replicas: u32,
            available_replicas: u32,
            unavailable_replicas: u32,
            paused: bool,
            progress_deadline_seconds: Option<u32>,
            conditions: &'a [RolloutCondition],
            replica_sets: &'a [ReplicaSetSnapshot],
            pods: &'a [PodRolloutEvidence],
        }
        digest_json(&Material {
            observed_generation: self.observed_generation,
            desired_replicas: self.desired_replicas,
            updated_replicas: self.updated_replicas,
            ready_replicas: self.ready_replicas,
            available_replicas: self.available_replicas,
            unavailable_replicas: self.unavailable_replicas,
            paused: self.paused,
            progress_deadline_seconds: self.progress_deadline_seconds,
            conditions: &self.conditions,
            replica_sets: &self.replica_sets,
            pods: &self.pods,
        })
    }

    pub fn exact_image_digests(&self) -> &BTreeMap<String, String> {
        &self.image_digests
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterDescription {
    pub api_server: ApiServerEndpoint,
    pub cluster_ca_spki_sha256: String,
    pub cluster_identity: ClusterIdentity,
    pub namespace: String,
    pub rbac: RbacCapabilitySnapshot,
    pub provenance: EvidenceProvenance,
    pub request_id: Option<String>,
    pub connected: bool,
    pub native: bool,
}

impl ClusterDescription {
    pub fn validate_against(&self, scope: &KubernetesRolloutScope) -> Result<(), ModelError> {
        self.api_server.validate()?;
        self.cluster_identity.validate()?;
        self.rbac.validate()?;
        if self.api_server != scope.api_server
            || self.cluster_ca_spki_sha256 != scope.cluster_ca_spki_sha256
            || self.cluster_identity != scope.cluster_identity
            || self.namespace != scope.namespace
            || self.rbac.digest() != scope.rbac.digest()
            || self.connected
            || self.native
            || self.provenance.is_connected()
            || self.provenance.is_native()
        {
            return Err(ModelError::TrustOrProvenanceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloutReadRequest {
    pub scope_digest: String,
    pub deployment: DeploymentIdentity,
    pub expected_generation: u64,
    pub expected_image_digests: BTreeMap<String, String>,
    pub previous_resource_version: Option<String>,
    pub max_attempts: u8,
}

impl RolloutReadRequest {
    pub fn new(
        scope: &KubernetesRolloutScope,
        expected_generation: u64,
        expected_image_digests: BTreeMap<String, String>,
    ) -> Result<Self, ModelError> {
        if expected_generation == 0 || !valid_digest_map(&expected_image_digests) {
            return Err(ModelError::InvalidReadRequest);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            deployment: scope.deployment.clone(),
            expected_generation,
            expected_image_digests,
            previous_resource_version: None,
            max_attempts: 3,
        })
    }

    #[must_use]
    pub fn with_previous_resource_version(mut self, resource_version: impl Into<String>) -> Self {
        self.previous_resource_version = Some(resource_version.into());
        self
    }

    pub fn with_max_attempts(mut self, max_attempts: u8) -> Result<Self, ModelError> {
        if !(1..=5).contains(&max_attempts) {
            return Err(ModelError::InvalidReadRequest);
        }
        self.max_attempts = max_attempts;
        Ok(self)
    }

    pub fn validate_against(&self, scope: &KubernetesRolloutScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.deployment != scope.deployment
            || self.expected_generation == 0
            || !valid_digest_map(&self.expected_image_digests)
            || self.max_attempts == 0
            || self.max_attempts > 5
        {
            return Err(ModelError::InvalidReadRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloutObservation {
    pub phase: RolloutPhase,
    pub complete: bool,
    pub object_uid: String,
    pub resource_version: String,
    pub generation: u64,
    pub observed_generation: u64,
    pub exact_image_digests: BTreeMap<String, String>,
    pub object_fingerprint: String,
    pub status_fingerprint: String,
    pub reasons: Vec<String>,
    pub provenance: EvidenceProvenance,
    pub connected: bool,
    pub native: bool,
}

impl RolloutObservation {
    pub(crate) fn from_snapshot(
        snapshot: &DeploymentSnapshot,
        scope: &KubernetesRolloutScope,
        request: &RolloutReadRequest,
        provenance: EvidenceProvenance,
    ) -> Result<Self, ModelError> {
        snapshot.validate()?;
        if snapshot.identity != scope.deployment {
            return Err(ModelError::ObjectIdentityMismatch);
        }
        if snapshot.generation < request.expected_generation {
            return Err(ModelError::StaleGeneration);
        }
        let newer_generation = snapshot.generation > request.expected_generation;
        if snapshot.image_digests != request.expected_image_digests {
            return Err(ModelError::ImageDigestMismatch);
        }

        let mut reasons = Vec::new();
        let mut unknown = false;
        let mut stalled = false;
        let mut degraded = false;
        let mut available = false;
        for condition in &snapshot.conditions {
            if !condition.is_known_type() || condition.status == "Unknown" {
                unknown = true;
            }
            if condition.condition_type == "Available" && condition.status == "True" {
                available = true;
            }
            if condition.condition_type == "ReplicaFailure" && condition.status == "True" {
                degraded = true;
                reasons.push("replica_failure".into());
            }
            if condition.condition_type == "Available" && condition.status == "False" {
                degraded = true;
                reasons.push("not_available".into());
            }
            if condition.condition_type == "Progressing"
                && condition.status == "False"
                && condition.reason.as_deref() == Some("ProgressDeadlineExceeded")
            {
                stalled = true;
                reasons.push("progress_deadline_exceeded".into());
            }
        }
        if unknown {
            reasons.push("unknown_condition".into());
        }
        if snapshot.observed_generation < snapshot.generation {
            reasons.push("observed_generation_lag".into());
        }
        if newer_generation {
            reasons.push("newer_generation".into());
        }
        if snapshot.updated_replicas < snapshot.desired_replicas
            || snapshot.ready_replicas < snapshot.desired_replicas
            || snapshot.available_replicas < snapshot.desired_replicas
        {
            reasons.push("partial_readiness".into());
        }

        let complete = !unknown
            && !newer_generation
            && !snapshot.paused
            && !stalled
            && !degraded
            && snapshot.observed_generation == snapshot.generation
            && snapshot.updated_replicas == snapshot.desired_replicas
            && snapshot.ready_replicas == snapshot.desired_replicas
            && snapshot.available_replicas == snapshot.desired_replicas
            && snapshot.unavailable_replicas == 0
            && available;
        let phase = if unknown || newer_generation {
            RolloutPhase::ProviderUnknown
        } else if snapshot.paused {
            reasons.push("paused".into());
            RolloutPhase::Paused
        } else if stalled {
            RolloutPhase::Stalled
        } else if degraded {
            RolloutPhase::Degraded
        } else if complete {
            RolloutPhase::Complete
        } else if snapshot.observed_generation < snapshot.generation {
            RolloutPhase::Progressing
        } else if available {
            RolloutPhase::Available
        } else {
            RolloutPhase::Progressing
        };

        Ok(Self {
            phase,
            complete,
            object_uid: snapshot.identity.uid.clone(),
            resource_version: snapshot.resource_version.clone(),
            generation: snapshot.generation,
            observed_generation: snapshot.observed_generation,
            exact_image_digests: snapshot.image_digests.clone(),
            object_fingerprint: snapshot.object_fingerprint(),
            status_fingerprint: snapshot.status_fingerprint(),
            reasons,
            provenance,
            connected: false,
            native: false,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloutEvidence {
    pub evidence_version: String,
    pub scope_digest: String,
    pub requested_generation: u64,
    pub requested_image_digests: BTreeMap<String, String>,
    pub snapshot: DeploymentSnapshot,
    pub observation: RolloutObservation,
    pub request_id: Option<String>,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: String,
    pub connected: bool,
    pub native: bool,
}

impl RolloutEvidence {
    pub(crate) fn new(
        scope: &KubernetesRolloutScope,
        snapshot: DeploymentSnapshot,
        request: &RolloutReadRequest,
        provenance: EvidenceProvenance,
    ) -> Result<Self, ModelError> {
        let observation = RolloutObservation::from_snapshot(&snapshot, scope, request, provenance)?;
        let mut evidence = Self {
            evidence_version: "kubernetes-rollout-evidence/v1".into(),
            scope_digest: scope.digest(),
            requested_generation: request.expected_generation,
            requested_image_digests: request.expected_image_digests.clone(),
            request_id: snapshot.request_id.clone(),
            snapshot,
            observation,
            provenance,
            evidence_digest: String::new(),
            connected: false,
            native: false,
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.snapshot.validate()?;
        if self.evidence_version != "kubernetes-rollout-evidence/v1"
            || !valid_sha256_digest(&self.scope_digest)
            || self.requested_generation == 0
            || !valid_digest_map(&self.requested_image_digests)
            || self.connected
            || self.native
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.observation.connected
            || self.observation.native
            || self.evidence_digest != self.compute_digest()
        {
            return Err(ModelError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn validate_against_scope(&self, scope: &KubernetesRolloutScope) -> Result<(), ModelError> {
        self.validate()?;
        if self.scope_digest != scope.digest() || self.snapshot.identity != scope.deployment {
            return Err(ModelError::TamperedEvidence);
        }
        let request = RolloutReadRequest::new(
            scope,
            self.requested_generation,
            self.requested_image_digests.clone(),
        )?;
        let projected =
            RolloutObservation::from_snapshot(&self.snapshot, scope, &request, self.provenance)?;
        if self.observation != projected || self.request_id != self.snapshot.request_id {
            return Err(ModelError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            evidence_version: &'a str,
            scope_digest: &'a str,
            requested_generation: u64,
            requested_image_digests: &'a BTreeMap<String, String>,
            snapshot: &'a DeploymentSnapshot,
            observation: &'a RolloutObservation,
            request_id: &'a Option<String>,
            provenance: EvidenceProvenance,
        }
        digest_json(&Material {
            evidence_version: &self.evidence_version,
            scope_digest: &self.scope_digest,
            requested_generation: self.requested_generation,
            requested_image_digests: &self.requested_image_digests,
            snapshot: &self.snapshot,
            observation: &self.observation,
            request_id: &self.request_id,
            provenance: self.provenance,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Error)]
pub enum ModelError {
    #[error("API server must be an exact HTTPS endpoint without query or fragment")]
    ApiServerMustBeHttps,
    #[error("invalid digest for {0}")]
    InvalidDigest(String),
    #[error("invalid cluster identity")]
    InvalidClusterIdentity,
    #[error("invalid deployment identity")]
    InvalidDeploymentIdentity,
    #[error("image references must use exact immutable SHA-256 digests")]
    ImageMustUseExactDigest,
    #[error("invalid RBAC capability snapshot")]
    InvalidRbacSnapshot,
    #[error("RBAC capability snapshot digest does not match its contents")]
    RbacDigestMismatch,
    #[error("invalid rollout scope")]
    InvalidScope,
    #[error("opaque secret reference is invalid")]
    InvalidSecretReference,
    #[error("opaque secret reference is not bound to this exact scope")]
    AuthScopeMismatch,
    #[error("invalid rollout condition")]
    InvalidCondition,
    #[error("invalid rollout evidence: {0}")]
    InvalidEvidence(String),
    #[error("invalid rollout read request")]
    InvalidReadRequest,
    #[error("deployment object identity does not match the registered UID")]
    ObjectIdentityMismatch,
    #[error("deployment generation is stale")]
    StaleGeneration,
    #[error("deployment image digest does not match the intended exact digest")]
    ImageDigestMismatch,
    #[error("API-server trust or evidence provenance does not match the scope")]
    TrustOrProvenanceMismatch,
    #[error("rollout evidence digest or bounded fields were tampered with")]
    TamperedEvidence,
}
