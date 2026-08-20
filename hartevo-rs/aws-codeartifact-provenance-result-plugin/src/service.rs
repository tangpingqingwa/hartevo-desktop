//! Typed service, proposal, verification, and reversible registration.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::consumer::MissionAwsCodeArtifactConsumer;
use crate::error::{AwsCodeArtifactProvenanceError, AwsCodeArtifactTransportError, Result};
use crate::model::{
    AwsCodeArtifactProvenanceScope, ConsentScope, DependencySummary, Digest, EvidenceDigests,
    MissionProjection, PackageVersionFilter, PackageVersionObservation, PermissionSnapshot,
    ProjectProjection, SecretReference, TransportProvenance, WorkProductProjection,
};
use crate::provider::{
    AwsCodeArtifactProvider, AwsCodeArtifactProviderDefinition, DescribePackageVersionRequest,
    ListPackageVersionDependenciesRequest, ListPackageVersionsRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_SCHEMA, CONTRACT_VERSION,
    EVIDENCE_LEVEL, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_API_VERSION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodeArtifactContractError {
    #[error("contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("contract identity drifted: {0}")]
    Identity(&'static str),
    #[error("contract authority boundary widened: {0}")]
    Boundary(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCodeArtifactContract {
    value: serde_json::Value,
}

impl AwsCodeArtifactContract {
    pub fn baseline() -> std::result::Result<Self, AwsCodeArtifactContractError> {
        let value = serde_json::from_str(crate::CONTRACT_JSON)
            .map_err(|error| AwsCodeArtifactContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        Digest::parse(CONTRACT_DIGEST.to_owned()).expect("checked contract digest")
    }

    pub fn validate(&self) -> std::result::Result<(), AwsCodeArtifactContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsCodeArtifactContractError::Shape(
                "contract is not an object",
            ))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "metadata",
            "evidence",
            "provenance",
            "authorityBoundary",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(AwsCodeArtifactContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_SCHEMA)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(AwsCodeArtifactContractError::Identity(
                "top-level contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeArtifactContractError::Shape(
                "service is not an object",
            ))?;
        if service.get("type").and_then(serde_json::Value::as_str)
            != Some("AwsCodeArtifactProvenanceService")
            || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCodeArtifactContractError::Identity(
                "service identity or authority drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeArtifactContractError::Shape(
                "provider is not an object",
            ))?;
        if provider.get("type").and_then(serde_json::Value::as_str)
            != Some("AwsCodeArtifactProvider")
            || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_VERSION)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstPartyEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCodeArtifactContractError::Identity(
                "provider identity or honesty drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeArtifactContractError::Shape(
                "consumer is not an object",
            ))?;
        if consumer.get("type").and_then(serde_json::Value::as_str)
            != Some("MissionAwsCodeArtifactConsumer")
            || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCodeArtifactContractError::Identity(
                "consumer identity or authority drifted",
            ));
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeArtifactContractError::Shape(
                "credentials is not an object",
            ))?;
        if credentials.get("serialized") != Some(&serde_json::Value::Bool(false))
            || credentials.get("debugRedacted") != Some(&serde_json::Value::Bool(true))
            || credentials.get("rawMaterialAccepted") != Some(&serde_json::Value::Bool(false))
            || credentials.get("resolvedByLayer") != Some(&serde_json::Value::from(2))
        {
            return Err(AwsCodeArtifactContractError::Boundary(
                "credential boundary widened",
            ));
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeArtifactContractError::Shape(
                "provenance is not an object",
            ))?;
        for key in [
            "connectedClaim",
            "nativeClaim",
            "firstPartyClaim",
            "providerReceipt",
        ] {
            if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsCodeArtifactContractError::Boundary(
                    "native or connected provenance claim widened",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodeArtifactProvenanceServiceDefinition {
    pub id: String,
    pub contract_schema: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub contract_digest: Digest,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl Default for AwsCodeArtifactProvenanceServiceDefinition {
    fn default() -> Self {
        Self {
            id: SERVICE_ID.to_owned(),
            contract_schema: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())
                .expect("checked CodeArtifact contract digest"),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "register_scope".to_owned(),
                "read_package_versions".to_owned(),
                "describe_package_version".to_owned(),
                "read_package_version_dependencies".to_owned(),
                "compile_provenance_proposal".to_owned(),
                "verify_provenance".to_owned(),
                "revoke_registration".to_owned(),
                "reverse_registration".to_owned(),
                "restore_registration".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

impl AwsCodeArtifactProvenanceServiceDefinition {
    pub fn validate(&self) -> Result<()> {
        let expected = Self::default();
        if self != &expected {
            return Err(AwsCodeArtifactProvenanceError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-codeartifact-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsCodeArtifactProvenanceRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsCodeArtifactProvenanceScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsCodeArtifactProvenanceRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsCodeArtifactProvenanceScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsCodeArtifactProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-codeartifact-registration"),
        };
        registration.registration_digest = registration.recomputed_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsCodeArtifactProvenanceScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > crate::MAX_IDENTIFIER_BYTES
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        self.scope.validate()?;
        self.secret_reference.ensure_active(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsCodeArtifactProvenanceError::InvalidConsent);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCodeArtifactProvenanceError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCodeArtifactProvenanceError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCodeArtifactProvenanceError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest().as_str().to_owned(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsCodeArtifactProvenanceRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodeArtifactProvenanceRegistration")
            .field("id", &self.id)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for AwsCodeArtifactProvenanceRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCodeArtifactProvenanceRegistration", 13)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

pub type AwsCodeArtifactRegistration = AwsCodeArtifactProvenanceRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub layer: u8,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCodeArtifactReadRequest {
    scope: AwsCodeArtifactProvenanceScope,
    filter: PackageVersionFilter,
    cursor: Option<crate::model::Cursor>,
    include_dependencies: bool,
    observed_at: DateTime<Utc>,
    request_digest: Digest,
}

impl AwsCodeArtifactReadRequest {
    pub fn new(
        scope: &AwsCodeArtifactProvenanceScope,
        filter: PackageVersionFilter,
        cursor: Option<crate::model::Cursor>,
        include_dependencies: bool,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let list = ListPackageVersionsRequest::new(scope, filter.clone(), cursor.clone())?;
        Ok(Self {
            scope: scope.clone(),
            filter,
            cursor,
            include_dependencies,
            observed_at,
            request_digest: Digest::from_parts(
                "aws-codeartifact-read-request/v1",
                &[
                    ("list", list.request_digest().as_str().to_owned()),
                    ("include_dependencies", include_dependencies.to_string()),
                    ("observed_at", observed_at.to_rfc3339()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsCodeArtifactProvenanceScope {
        &self.scope
    }

    pub fn filter(&self) -> &PackageVersionFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&crate::model::Cursor> {
        self.cursor.as_ref()
    }

    pub const fn include_dependencies(&self) -> bool {
        self.include_dependencies
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn list_request(&self) -> Result<ListPackageVersionsRequest> {
        ListPackageVersionsRequest::new(&self.scope, self.filter.clone(), self.cursor.clone())
    }

    pub fn describe_request(&self) -> Result<DescribePackageVersionRequest> {
        DescribePackageVersionRequest::for_scope(&self.scope)
    }

    pub fn dependency_request(&self) -> Result<ListPackageVersionDependenciesRequest> {
        ListPackageVersionDependenciesRequest::new(&self.scope, self.filter.max_results, None)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCodeArtifactEvidenceState {
    Completed,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    RevisionDrift,
    ProviderUnknown,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub error_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(error: &AwsCodeArtifactTransportError) -> Self {
        let category = match error {
            AwsCodeArtifactTransportError::BlockedEnv => "blocked_env",
            AwsCodeArtifactTransportError::BadRequest => "bad_request",
            AwsCodeArtifactTransportError::Unauthorized => "unauthorized",
            AwsCodeArtifactTransportError::Forbidden => "forbidden",
            AwsCodeArtifactTransportError::NotFound => "not_found",
            AwsCodeArtifactTransportError::Conflict => "conflict",
            AwsCodeArtifactTransportError::RateLimited { .. } => "throttled",
            AwsCodeArtifactTransportError::ServerError { .. } => "server_error",
            AwsCodeArtifactTransportError::Timeout => "timeout",
            AwsCodeArtifactTransportError::AccessLost => "access_loss",
            AwsCodeArtifactTransportError::Partial => "partial",
            AwsCodeArtifactTransportError::InvalidResponse => "invalid_response",
        };
        Self {
            category: category.to_owned(),
            status_code: error.status_code(),
            retry_after_seconds: match error {
                AwsCodeArtifactTransportError::RateLimited {
                    retry_after_seconds,
                } => *retry_after_seconds,
                _ => None,
            },
            error_digest: Digest::from_parts(
                "aws-codeartifact-transport-error/v1",
                &[
                    ("category", category.to_owned()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |value| value.to_string()),
                    ),
                ],
            ),
        }
    }

    fn local(category: &str) -> Self {
        Self {
            category: category.to_owned(),
            status_code: None,
            retry_after_seconds: None,
            error_digest: Digest::from_parts(
                "aws-codeartifact-local-failure/v1",
                &[("category", category.to_owned())],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodeArtifactProvenanceProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AwsCodeArtifactEvidenceState,
    pub package_version: Option<PackageVersionObservation>,
    pub dependencies: Option<DependencySummary>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub dependency_complete: bool,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub failure: Option<FailureEvidence>,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsCodeArtifactProvenanceProposal {
    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-provenance-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("mission", self.mission.id_digest.as_str().to_owned()),
                ("mission_revision", self.mission.revision.to_string()),
                ("project", self.project.id_digest.as_str().to_owned()),
                ("project_revision", self.project.revision.to_string()),
                (
                    "work_product",
                    self.work_product.id_digest.as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product.revision.to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "package_version",
                    self.package_version
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.metadata_digest().as_str().to_owned()
                        }),
                ),
                (
                    "dependencies",
                    self.dependencies
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.dependency_digest.as_str().to_owned()
                        }),
                ),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                ("dependency_complete", self.dependency_complete.to_string()),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "failure",
                    self.failure
                        .as_ref()
                        .map_or_else(String::new, |value| value.error_digest.as_str().to_owned()),
                ),
                ("review_only", self.review_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.list_pages == 0
            || self.list_pages > crate::MAX_PAGES
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.evidence.validate()?;
        if let Some(package_version) = &self.package_version {
            package_version.validate()?;
        }
        if let Some(dependencies) = &self.dependencies {
            dependencies.dependency_digest.validate()?;
        }
        if self.state == AwsCodeArtifactEvidenceState::Completed
            && (self.package_version.is_none()
                || !self.list_complete
                || !self.dependency_complete
                || self.failure.is_some()
                || self
                    .dependencies
                    .as_ref()
                    .is_some_and(|dependencies| dependencies.truncated))
        {
            return Err(AwsCodeArtifactProvenanceError::PartialEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCodeArtifactVerificationFailure {
    TamperedEvidence,
    RegistrationInactive,
    ScopeMismatch,
    ProviderDrift,
    ContractDrift,
    IncompleteEvidence,
    NotCompleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodeArtifactVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failure: Option<AwsCodeArtifactVerificationFailure>,
    pub evidence_digest: Digest,
}

pub struct AwsCodeArtifactProvenanceService<T = crate::provider::BlockedEnvTransport> {
    definition: AwsCodeArtifactProvenanceServiceDefinition,
    scope: AwsCodeArtifactProvenanceScope,
    registration: AwsCodeArtifactProvenanceRegistration,
    provider: AwsCodeArtifactProvider<T>,
}

impl<T: crate::provider::AwsCodeArtifactTransport> fmt::Debug
    for AwsCodeArtifactProvenanceService<T>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodeArtifactProvenanceService")
            .field("definition", &self.definition)
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsCodeArtifactTransport> AwsCodeArtifactProvenanceService<T> {
    pub fn new(
        scope: AwsCodeArtifactProvenanceScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsCodeArtifactProvider<T>,
        _observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let definition = AwsCodeArtifactProvenanceServiceDefinition::default();
        definition.validate()?;
        let registration = AwsCodeArtifactProvenanceRegistration::new(
            "codeartifact-provenance-registration-1",
            scope.clone(),
            secret_reference,
            permission_snapshot,
            consent,
            provider.definition(),
            1,
        )?;
        if registration.provider_digest() != &provider.definition().provider_digest {
            return Err(AwsCodeArtifactProvenanceError::ProviderDrift);
        }
        Ok(Self {
            definition,
            scope,
            registration,
            provider,
        })
    }

    pub fn with_registration(
        scope: AwsCodeArtifactProvenanceScope,
        registration: AwsCodeArtifactProvenanceRegistration,
        provider: AwsCodeArtifactProvider<T>,
    ) -> Result<Self> {
        let definition = AwsCodeArtifactProvenanceServiceDefinition::default();
        definition.validate()?;
        registration.validate()?;
        if registration.scope_digest() != &scope.digest()
            || registration.provider_digest() != &provider.definition().provider_digest
        {
            return Err(AwsCodeArtifactProvenanceError::ScopeMismatch);
        }
        Ok(Self {
            definition,
            scope,
            registration,
            provider,
        })
    }

    pub fn service_definition(&self) -> &AwsCodeArtifactProvenanceServiceDefinition {
        &self.definition
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            layer: 1,
            operations: self.definition.operations.clone(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsCodeArtifactProvenanceScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsCodeArtifactProvenanceRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsCodeArtifactProvenanceRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsCodeArtifactProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCodeArtifactProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        filter: PackageVersionFilter,
        cursor: Option<crate::model::Cursor>,
        include_dependencies: bool,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsCodeArtifactReadRequest> {
        if !self.registration.is_active() {
            return Err(AwsCodeArtifactProvenanceError::RegistrationInactive);
        }
        AwsCodeArtifactReadRequest::new(
            &self.scope,
            filter,
            cursor,
            include_dependencies,
            observed_at,
        )
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsCodeArtifactReadRequest> {
        let include_dependencies = self
            .registration
            .permission_snapshot()
            .allows("codeartifact:ListPackageVersionDependencies");
        self.request(
            PackageVersionFilter::all(10)?,
            None,
            include_dependencies,
            observed_at,
        )
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn consumer(
        &self,
    ) -> std::result::Result<MissionAwsCodeArtifactConsumer, crate::consumer::ConsumerError> {
        MissionAwsCodeArtifactConsumer::new(self.scope.clone(), self.registration.clone())
    }

    pub fn verify(
        &self,
        proposal: &AwsCodeArtifactProvenanceProposal,
    ) -> AwsCodeArtifactVerificationReport {
        let mut report = AwsCodeArtifactVerificationReport {
            valid: false,
            review_eligible: false,
            failure: None,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
        };
        if proposal.validate_integrity().is_err() {
            report.failure = Some(AwsCodeArtifactVerificationFailure::TamperedEvidence);
            return report;
        }
        if !self.registration.is_active() {
            report.failure = Some(AwsCodeArtifactVerificationFailure::RegistrationInactive);
            return report;
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || proposal.evidence.contract_digest != *self.registration.contract_digest()
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.consent_digest != self.registration.consent_digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().id_digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.project.id_digest != self.scope.project().id_digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.work_product.id_digest != self.scope.work_product().id_digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            report.failure = Some(AwsCodeArtifactVerificationFailure::ScopeMismatch);
            return report;
        }
        if proposal.state != AwsCodeArtifactEvidenceState::Completed {
            report.valid = true;
            report.failure = Some(AwsCodeArtifactVerificationFailure::NotCompleted);
            return report;
        }
        report.valid = true;
        report.review_eligible = true;
        report
    }

    pub fn propose(
        &mut self,
        request: AwsCodeArtifactReadRequest,
    ) -> Result<AwsCodeArtifactProvenanceProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsCodeArtifactProvenanceError::RegistrationInactive);
        }
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsCodeArtifactProvenanceError::ScopeMismatch);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at())
        {
            return Err(if self.registration.consent().revoked {
                AwsCodeArtifactProvenanceError::ConsentRevoked
            } else {
                AwsCodeArtifactProvenanceError::ConsentExpired
            });
        }
        let mut list_request = request.list_request()?;
        let mut list_pages = 0;
        let mut list_digests = Vec::new();
        let mut target: Option<PackageVersionObservation> = None;
        let list_complete;
        loop {
            let response = match self.provider.list_package_versions(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return self.failure_proposal(
                        &request,
                        provider_error_state(&error),
                        Some(provider_error_failure(&error)),
                        list_pages.max(1),
                        Digest::from_parts(
                            "aws-codeartifact-list-pages/v1",
                            &[("pages", list_digests.join("|"))],
                        ),
                        Digest::from_text("aws-codeartifact-describe-not-run"),
                        None,
                        None,
                        false,
                        false,
                    );
                }
            };
            list_pages = response.page_number;
            list_digests.push(response.response_digest.as_str().to_owned());
            if let Some(page_target) = response
                .versions
                .iter()
                .find(|version| version.version() == self.scope.version())
                .cloned()
            {
                if let Some(existing_target) = &target
                    && !metadata_matches(existing_target, &page_target)
                {
                    return self.failure_proposal(
                        &request,
                        AwsCodeArtifactEvidenceState::RevisionDrift,
                        Some(FailureEvidence::local(
                            "paginated_revision_status_origin_drift",
                        )),
                        list_pages,
                        Digest::from_parts(
                            "aws-codeartifact-list-pages/v1",
                            &[("pages", list_digests.join("|"))],
                        ),
                        Digest::from_text("aws-codeartifact-describe-not-run"),
                        Some(existing_target.clone()),
                        None,
                        false,
                        false,
                    );
                }
                target = Some(page_target);
            }
            if let Some(cursor) = response.next_cursor {
                if cursor.page_number() > crate::MAX_PAGES {
                    return self.failure_proposal(
                        &request,
                        AwsCodeArtifactEvidenceState::Partial,
                        Some(FailureEvidence::local("pagination_limit")),
                        list_pages,
                        Digest::from_parts(
                            "aws-codeartifact-list-pages/v1",
                            &[("pages", list_digests.join("|"))],
                        ),
                        Digest::from_text("aws-codeartifact-describe-not-run"),
                        target,
                        None,
                        false,
                        false,
                    );
                }
                list_request = ListPackageVersionsRequest::new(
                    &self.scope,
                    request.filter().clone(),
                    Some(cursor),
                )?;
            } else {
                list_complete = true;
                break;
            }
        }
        let list_digest = Digest::from_parts(
            "aws-codeartifact-list-pages/v1",
            &[("pages", list_digests.join("|"))],
        );
        let Some(list_metadata) = target else {
            return self.failure_proposal(
                &request,
                AwsCodeArtifactEvidenceState::NotFound,
                Some(FailureEvidence::local("not_found")),
                list_pages,
                list_digest,
                Digest::from_text("aws-codeartifact-describe-not-run"),
                None,
                None,
                list_complete,
                true,
            );
        };
        let describe_request = request.describe_request()?;
        let describe = match self.provider.describe_package_version(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                return self.failure_proposal(
                    &request,
                    provider_error_state(&error),
                    Some(provider_error_failure(&error)),
                    list_pages,
                    list_digest,
                    Digest::from_text("aws-codeartifact-describe-failed"),
                    Some(list_metadata),
                    None,
                    list_complete,
                    false,
                );
            }
        };
        let describe_digest = describe.response_digest.clone();
        if !metadata_matches(&list_metadata, &describe.package_version) {
            return self.failure_proposal(
                &request,
                AwsCodeArtifactEvidenceState::RevisionDrift,
                Some(FailureEvidence::local("revision_status_origin_drift")),
                list_pages,
                list_digest,
                describe_digest,
                Some(list_metadata),
                None,
                list_complete,
                false,
            );
        }
        let mut package_version = describe.package_version;
        let mut dependencies = None;
        let mut dependency_complete = true;
        let mut dependency_digest = None;
        if request.include_dependencies() {
            if !self
                .registration
                .permission_snapshot()
                .allows("codeartifact:ListPackageVersionDependencies")
            {
                return self.failure_proposal(
                    &request,
                    AwsCodeArtifactEvidenceState::AccessLoss,
                    Some(FailureEvidence::local("dependency_permission_missing")),
                    list_pages,
                    list_digest,
                    describe_digest,
                    Some(package_version),
                    None,
                    list_complete,
                    false,
                );
            }
            let dependency_request = request.dependency_request()?;
            let response = match self
                .provider
                .list_package_version_dependencies(&dependency_request)
            {
                Ok(response) => response,
                Err(error) => {
                    return self.failure_proposal(
                        &request,
                        provider_error_state(&error),
                        Some(provider_error_failure(&error)),
                        list_pages,
                        list_digest,
                        describe_digest,
                        Some(package_version),
                        None,
                        list_complete,
                        false,
                    );
                }
            };
            dependencies = Some(response.dependencies.clone());
            dependency_digest = Some(response.response_digest.clone());
            dependency_complete = response.is_complete();
            package_version = package_version.with_dependencies(response.dependencies);
            if !dependency_complete {
                return self.failure_proposal(
                    &request,
                    AwsCodeArtifactEvidenceState::Partial,
                    Some(FailureEvidence::local("dependency_truncated")),
                    list_pages,
                    list_digest,
                    describe_digest,
                    Some(package_version),
                    dependencies,
                    list_complete,
                    false,
                );
            }
        }
        self.make_proposal(
            &request,
            AwsCodeArtifactEvidenceState::Completed,
            Some(package_version),
            dependencies,
            list_pages,
            list_complete,
            dependency_complete,
            list_digest,
            describe_digest,
            dependency_digest,
            None,
        )
    }

    fn failure_proposal(
        &self,
        request: &AwsCodeArtifactReadRequest,
        state: AwsCodeArtifactEvidenceState,
        failure: Option<FailureEvidence>,
        list_pages: u16,
        list_digest: Digest,
        describe_digest: Digest,
        package_version: Option<PackageVersionObservation>,
        dependencies: Option<DependencySummary>,
        list_complete: bool,
        dependency_complete: bool,
    ) -> Result<AwsCodeArtifactProvenanceProposal> {
        self.make_proposal(
            request,
            state,
            package_version,
            dependencies,
            list_pages.max(1),
            list_complete,
            dependency_complete,
            list_digest,
            describe_digest,
            None,
            failure,
        )
    }

    fn make_proposal(
        &self,
        request: &AwsCodeArtifactReadRequest,
        state: AwsCodeArtifactEvidenceState,
        package_version: Option<PackageVersionObservation>,
        dependencies: Option<DependencySummary>,
        list_pages: u16,
        list_complete: bool,
        dependency_complete: bool,
        list_digest: Digest,
        describe_digest: Digest,
        dependency_digest: Option<Digest>,
        failure: Option<FailureEvidence>,
    ) -> Result<AwsCodeArtifactProvenanceProposal> {
        let evidence = EvidenceDigests::new(
            Digest::from_text(PLUGIN_VERSION),
            Digest::parse(CONTRACT_DIGEST.to_owned())?,
            self.registration.provider_digest().clone(),
            self.registration.permission_digest(),
            self.registration.consent_digest(),
            self.scope.digest(),
            list_digest,
            describe_digest,
            dependency_digest,
        );
        let mut proposal = AwsCodeArtifactProvenanceProposal {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.scope.digest(),
            mission: MissionProjection::from(self.scope.mission()),
            project: ProjectProjection::from(self.scope.project()),
            work_product: WorkProductProjection::from(self.scope.work_product()),
            state,
            package_version,
            dependencies,
            list_pages,
            list_complete,
            dependency_complete,
            evidence,
            provenance: self.provider.provenance(),
            failure,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-codeartifact-proposal"),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal.validate_integrity()?;
        let _ = request.request_digest();
        Ok(proposal)
    }
}

fn metadata_matches(left: &PackageVersionObservation, right: &PackageVersionObservation) -> bool {
    left.version() == right.version()
        && left.revision_digest() == right.revision_digest()
        && left.origin() == right.origin()
        && left.status() == right.status()
        && left.published_at() == right.published_at()
        && left.asset_count() == right.asset_count()
        && left.package_version_arn_digest() == right.package_version_arn_digest()
}

impl AwsCodeArtifactEvidenceState {
    fn from_transport(error: &AwsCodeArtifactTransportError) -> Self {
        match error {
            AwsCodeArtifactTransportError::Unauthorized
            | AwsCodeArtifactTransportError::Forbidden
            | AwsCodeArtifactTransportError::AccessLost => Self::AccessLoss,
            AwsCodeArtifactTransportError::NotFound => Self::NotFound,
            AwsCodeArtifactTransportError::RateLimited { .. } => Self::Throttled,
            AwsCodeArtifactTransportError::Partial => Self::Partial,
            AwsCodeArtifactTransportError::BlockedEnv
            | AwsCodeArtifactTransportError::BadRequest
            | AwsCodeArtifactTransportError::Conflict
            | AwsCodeArtifactTransportError::ServerError { .. }
            | AwsCodeArtifactTransportError::Timeout
            | AwsCodeArtifactTransportError::InvalidResponse => Self::ProviderUnknown,
        }
    }
}

fn provider_error_state(error: &AwsCodeArtifactProvenanceError) -> AwsCodeArtifactEvidenceState {
    match error {
        AwsCodeArtifactProvenanceError::Transport(transport) => {
            AwsCodeArtifactEvidenceState::from_transport(transport)
        }
        _ => AwsCodeArtifactEvidenceState::ProviderUnknown,
    }
}

fn provider_error_failure(error: &AwsCodeArtifactProvenanceError) -> FailureEvidence {
    match error {
        AwsCodeArtifactProvenanceError::Transport(transport) => {
            FailureEvidence::from_transport(transport)
        }
        _ => FailureEvidence::local("provider_contract_error"),
    }
}

pub type AwsCodeArtifactProvenanceResultService<T> = AwsCodeArtifactProvenanceService<T>;
pub type AwsCodeArtifactService<T> = AwsCodeArtifactProvenanceService<T>;
