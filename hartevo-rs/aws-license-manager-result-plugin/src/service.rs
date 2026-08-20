//! Typed AWS License Manager service, evidence, and reversible registration.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsLicenseManagerConsumer;
use crate::error::{AwsLicenseManagerError, AwsLicenseManagerTransportError, Result};
use crate::model::{
    AwsLicenseManagerScope, ConfigurationProjection, Digest, EvidenceState,
    LicenseConfigurationMetadata, ManagedResourceStatus, PermissionSnapshot, ProviderProvenance,
    QuotaState, SecretReference, UsageProjection, UsageWindow,
};
use crate::provider::{
    AwsLicenseManagerOperation, AwsLicenseManagerProvider, AwsLicenseManagerProviderDefinition,
    GetLicenseConfigurationRequest, ListLicenseConfigurationsRequest,
    ListUsageForLicenseConfigurationRequest,
};
use crate::{
    AWS_LICENSE_MANAGER_CONSUMER_ID, AWS_LICENSE_MANAGER_CONTRACT_DIGEST,
    AWS_LICENSE_MANAGER_CONTRACT_VERSION, AWS_LICENSE_MANAGER_PLUGIN_VERSION_TEXT,
    AWS_LICENSE_MANAGER_PROVIDER_ID, AWS_LICENSE_MANAGER_SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_state: RegistrationState,
        new_state: RegistrationState,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_fields(
            "aws-license-manager-registration-transition/v1",
            &[
                format!("{previous_state:?}"),
                format!("{new_state:?}"),
                registration_digest.to_string(),
            ],
        );
        Self {
            previous_state,
            new_state,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsLicenseManagerRegistrationRequest {
    pub id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub scope: AwsLicenseManagerScope,
    pub permission_snapshot: PermissionSnapshot,
    pub secret_reference: SecretReference,
    pub registration_revision: u64,
}

impl AwsLicenseManagerRegistrationRequest {
    pub fn new(
        id: impl Into<String>,
        scope: AwsLicenseManagerScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: AwsLicenseManagerProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty()
            || id.len() > crate::AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES
            || id.chars().any(char::is_control)
            || registration_revision == 0
        {
            return Err(AwsLicenseManagerError::InvalidRegistration);
        }
        provider.validate()?;
        scope.validate()?;
        secret_reference.ensure_bound(&scope)?;
        permission_snapshot.validate()?;
        Ok(Self {
            id,
            plugin_version: AWS_LICENSE_MANAGER_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_LICENSE_MANAGER_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id,
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest,
            scope,
            permission_snapshot,
            secret_reference,
            registration_revision,
        })
    }

    pub fn baseline(
        scope: AwsLicenseManagerScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: AwsLicenseManagerProviderDefinition,
    ) -> Result<Self> {
        Self::new(
            "aws-license-manager-registration",
            scope,
            secret_reference,
            permission_snapshot,
            provider,
            1,
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsLicenseManagerRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: String,
    provider_digest: Digest,
    scope: AwsLicenseManagerScope,
    scope_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    secret_reference: SecretReference,
    registration_revision: u64,
    state: RegistrationState,
    evidence_binding_digest: Digest,
    registration_digest: Digest,
}

impl AwsLicenseManagerRegistration {
    pub fn new(request: AwsLicenseManagerRegistrationRequest) -> Result<Self> {
        if request.plugin_version != AWS_LICENSE_MANAGER_PLUGIN_VERSION_TEXT
            || request.contract_version != AWS_LICENSE_MANAGER_CONTRACT_VERSION
            || request.contract_digest != contract_digest()
            || request.provider_id != AWS_LICENSE_MANAGER_PROVIDER_ID
        {
            return Err(AwsLicenseManagerError::InvalidRegistration);
        }
        request.scope.validate()?;
        request.secret_reference.ensure_bound(&request.scope)?;
        request.permission_snapshot.validate()?;
        if request.provider_revision.is_empty() || request.registration_revision == 0 {
            return Err(AwsLicenseManagerError::InvalidRegistration);
        }
        let scope_digest = request.scope.digest();
        let evidence_binding_digest = Digest::from_fields(
            "aws-license-manager-evidence-binding/v1",
            &[
                request.contract_digest.to_string(),
                request.provider_digest.to_string(),
                request.permission_snapshot.digest().to_string(),
                scope_digest.to_string(),
                request.secret_reference.reference_digest().to_string(),
            ],
        );
        let mut registration = Self {
            id: request.id,
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            provider_id: request.provider_id,
            provider_revision: request.provider_revision,
            provider_digest: request.provider_digest,
            scope: request.scope,
            scope_digest,
            permission_snapshot: request.permission_snapshot,
            secret_reference: request.secret_reference,
            registration_revision: request.registration_revision,
            state: RegistrationState::Active,
            evidence_binding_digest,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate_for(&self, provider: &AwsLicenseManagerProviderDefinition) -> Result<()> {
        provider.validate()?;
        self.validate()?;
        if self.provider_id != provider.provider_id
            || self.provider_revision != provider.provider_revision
            || self.provider_digest != provider.provider_digest
        {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > crate::AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES
            || self.id.chars().any(char::is_control)
            || self.plugin_version != AWS_LICENSE_MANAGER_PLUGIN_VERSION_TEXT
            || self.contract_version != AWS_LICENSE_MANAGER_CONTRACT_VERSION
            || self.contract_digest.as_str() != AWS_LICENSE_MANAGER_CONTRACT_DIGEST
            || self.contract_digest != contract_digest()
            || self.provider_id != AWS_LICENSE_MANAGER_PROVIDER_ID
            || self.provider_revision.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsLicenseManagerError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.secret_reference.ensure_bound(&self.scope)?;
        self.evidence_binding_digest.validate()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-registration/v1",
            &[
                Digest::from_text(&self.id).to_string(),
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_id.clone(),
                self.provider_revision.clone(),
                self.provider_digest.to_string(),
                self.permission_snapshot.digest().to_string(),
                self.scope_digest.to_string(),
                self.scope.license_configuration().digest().to_string(),
                self.secret_reference.reference_digest().to_string(),
                self.evidence_binding_digest.to_string(),
                self.registration_revision.to_string(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_text(&self.id)
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

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn scope(&self) -> &AwsLicenseManagerScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub fn evidence_binding_digest(&self) -> &Digest {
        &self.evidence_binding_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.state == RegistrationState::Reversed {
            return Err(AwsLicenseManagerError::RegistrationReversed);
        }
        let previous_state = self.state;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.state == RegistrationState::Reversed {
            return Err(AwsLicenseManagerError::RegistrationReversed);
        }
        let previous_state = self.state;
        self.state = RegistrationState::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.state == RegistrationState::Reversed {
            return Err(AwsLicenseManagerError::RegistrationReversed);
        }
        if self.state != RegistrationState::Revoked {
            return Err(AwsLicenseManagerError::RegistrationInactive);
        }
        let previous_state = self.state;
        self.state = RegistrationState::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }
}

impl fmt::Debug for AwsLicenseManagerRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsLicenseManagerRegistration")
            .field("id_digest", &self.id_digest())
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field(
                "license_configuration_digest",
                &self.scope.license_configuration().digest(),
            )
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("evidence_binding_digest", &self.evidence_binding_digest)
            .field("registration_revision", &self.registration_revision)
            .field("state", &self.state)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsLicenseManagerRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsLicenseManagerRegistration", 16)?;
        state.serialize_field("idDigest", &self.id_digest())?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        state.serialize_field(
            "licenseConfigurationDigest",
            &self.scope.license_configuration().digest(),
        )?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("evidenceBindingDigest", &self.evidence_binding_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLicenseManagerCapability {
    pub capability_id: String,
    pub operation: AwsLicenseManagerOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLicenseManagerReadRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub usage_window: UsageWindow,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

pub type LicenseManagerReadRequest = AwsLicenseManagerReadRequest;

impl AwsLicenseManagerReadRequest {
    pub fn new(
        scope: &AwsLicenseManagerScope,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        if page_size == 0
            || page_size > crate::AWS_LICENSE_MANAGER_MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > crate::AWS_LICENSE_MANAGER_MAX_PAGES
        {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let usage_window = scope.usage_window().clone();
        let request_digest = Digest::from_fields(
            "aws-license-manager-read-request/v1",
            &[
                scope.digest().to_string(),
                expected_provider_digest.to_string(),
                expected_registration_digest.to_string(),
                page_size.to_string(),
                max_pages.to_string(),
                usage_window.digest().to_string(),
                observed_at.to_rfc3339(),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest,
            expected_registration_digest,
            page_size,
            max_pages,
            usage_window,
            observed_at,
            request_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub(crate) fn validate_for(
        &self,
        scope: &AwsLicenseManagerScope,
        provider_digest: &Digest,
        registration_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.expected_provider_digest != *provider_digest
            || self.expected_registration_digest != *registration_digest
            || self.usage_window != *scope.usage_window()
            || self.request_digest
                != Digest::from_fields(
                    "aws-license-manager-read-request/v1",
                    &[
                        scope.digest().to_string(),
                        self.expected_provider_digest.to_string(),
                        self.expected_registration_digest.to_string(),
                        self.page_size.to_string(),
                        self.max_pages.to_string(),
                        self.usage_window.digest().to_string(),
                        self.observed_at.to_rfc3339(),
                    ],
                )
        {
            return Err(AwsLicenseManagerError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceFailure {
    pub operation: AwsLicenseManagerOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl EvidenceFailure {
    fn from_error(operation: AwsLicenseManagerOperation, error: &AwsLicenseManagerError) -> Self {
        let (status_code, category) = match error {
            AwsLicenseManagerError::Transport(transport) => {
                (transport.status_code(), transport.category())
            }
            AwsLicenseManagerError::TamperedEvidence => (None, "tampered_evidence"),
            AwsLicenseManagerError::PageLoop => (None, "pagination_loop"),
            AwsLicenseManagerError::ConfigurationDrift => (None, "configuration_drift"),
            AwsLicenseManagerError::ResourceDrift => (None, "resource_drift"),
            AwsLicenseManagerError::UsageWindowDrift => (None, "usage_window_drift"),
            AwsLicenseManagerError::PartialEvidence => (None, "partial"),
            _ => (None, "provider_unknown"),
        };
        Self {
            operation,
            status_code,
            category: category.to_owned(),
            failure_digest: Digest::from_fields(
                "aws-license-manager-failure/v1",
                &[
                    operation.as_api_name().to_owned(),
                    category.to_owned(),
                    status_code.map_or_else(String::new, |status| status.to_string()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLicenseManagerEvidence {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub license_configuration_digest: Digest,
    pub list_digest: Option<Digest>,
    pub get_digest: Option<Digest>,
    pub usage_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub evidence_binding_digest: Digest,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub list_pages: u16,
    pub usage_pages: u16,
    pub list_complete: bool,
    pub usage_complete: bool,
    pub configuration: Option<ConfigurationProjection>,
    pub usage: UsageProjection,
    pub failure: Option<EvidenceFailure>,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_inventory_retained: bool,
    pub raw_license_text_retained: bool,
}

impl AwsLicenseManagerEvidence {
    fn new(
        registration: &AwsLicenseManagerRegistration,
        provider: &AwsLicenseManagerProviderDefinition,
        state: EvidenceState,
        list_pages: u16,
        usage_pages: u16,
        list_complete: bool,
        usage_complete: bool,
        configuration: Option<ConfigurationProjection>,
        usage: UsageProjection,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        usage_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        failure: Option<EvidenceFailure>,
        provenance: ProviderProvenance,
    ) -> Self {
        let mut evidence = Self {
            plugin_version: AWS_LICENSE_MANAGER_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_LICENSE_MANAGER_CONTRACT_VERSION.to_owned(),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: registration.permission_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            license_configuration_digest: registration.scope.license_configuration().digest(),
            list_digest,
            get_digest,
            usage_digest,
            cursor_digest,
            evidence_binding_digest: registration.evidence_binding_digest.clone(),
            evidence_digest: Digest::zero(),
            state,
            list_pages,
            usage_pages,
            list_complete,
            usage_complete,
            configuration,
            usage,
            failure,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_inventory_retained: false,
            raw_license_text_retained: false,
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-license-manager-evidence/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_digest.to_string(),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
                self.registration_digest.to_string(),
                self.license_configuration_digest.to_string(),
                self.list_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.get_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.usage_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.cursor_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.evidence_binding_digest.to_string(),
                format!("{:?}", self.state),
                self.list_pages.to_string(),
                self.usage_pages.to_string(),
                self.list_complete.to_string(),
                self.usage_complete.to_string(),
                self.configuration
                    .as_ref()
                    .map_or_else(String::new, |configuration| {
                        configuration.metadata_digest.to_string()
                    }),
                self.usage.usage_digest.to_string(),
                self.usage.consumed_licenses.to_string(),
                format!("{:?}", self.usage.quota_state),
                self.failure
                    .as_ref()
                    .map_or_else(String::new, |failure| failure.failure_digest.to_string()),
                self.provenance.as_str().to_owned(),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for digest in [
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.registration_digest,
            &self.license_configuration_digest,
            &self.evidence_binding_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self
            .list_digest
            .as_ref()
            .is_some_and(|digest| digest.validate().is_err())
            || self
                .get_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self
                .usage_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self
                .cursor_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.raw_inventory_retained
            || self.raw_license_text_retained
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        if self.state == EvidenceState::Complete
            && (!self.list_complete
                || !self.usage_complete
                || self.configuration.is_none()
                || self.usage.quota_state == QuotaState::Unknown
                || self.usage.resource_status == ManagedResourceStatus::Unknown
                || self.failure.is_some())
        {
            return Err(AwsLicenseManagerError::PartialEvidence);
        }
        Ok(())
    }

    pub fn is_review_eligible(&self) -> bool {
        self.state.review_eligible() && self.validate_integrity().is_ok()
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLicenseManagerProposal {
    pub evidence: AwsLicenseManagerEvidence,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub financial_or_legal_advice: bool,
}

impl AwsLicenseManagerProposal {
    fn new(evidence: AwsLicenseManagerEvidence) -> Self {
        let state = evidence.state;
        let scope_digest = evidence.scope_digest.clone();
        let registration_digest = evidence.registration_digest.clone();
        let proposal_digest = Digest::from_fields(
            "aws-license-manager-proposal/v1",
            &[
                evidence.evidence_digest.to_string(),
                scope_digest.to_string(),
                registration_digest.to_string(),
                format!("{state:?}"),
            ],
        );
        Self {
            evidence,
            state,
            scope_digest,
            registration_digest,
            proposal_digest,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            financial_or_legal_advice: false,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.state != self.evidence.state
            || self.scope_digest != self.evidence.scope_digest
            || self.registration_digest != self.evidence.registration_digest
            || !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.financial_or_legal_advice
            || self.proposal_digest
                != Digest::from_fields(
                    "aws-license-manager-proposal/v1",
                    &[
                        self.evidence.evidence_digest.to_string(),
                        self.scope_digest.to_string(),
                        self.registration_digest.to_string(),
                        format!("{:?}", self.state),
                    ],
                )
        {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn is_review_only(&self) -> bool {
        self.read_only && self.proposal_only && !self.connected && !self.native
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLicenseManagerRecord {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub state: EvidenceState,
    pub recording_digest: Digest,
    pub recorded: bool,
    pub replayed: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

impl AwsLicenseManagerRecord {
    pub(crate) fn new(
        proposal: &AwsLicenseManagerProposal,
        idempotency_key_digest: Digest,
        replayed: bool,
    ) -> Self {
        let recording_digest = Digest::from_fields(
            "aws-license-manager-recording/v1",
            &[
                idempotency_key_digest.to_string(),
                proposal.proposal_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.scope_digest.to_string(),
                format!("{:?}", proposal.state),
            ],
        );
        Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            recording_digest,
            recorded: true,
            replayed,
            durable_receipt: false,
            connected: false,
            native: false,
            adopted_outcome: false,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.recorded
            || self.durable_receipt
            || self.connected
            || self.native
            || self.adopted_outcome
            || self.recording_digest
                != Digest::from_fields(
                    "aws-license-manager-recording/v1",
                    &[
                        self.idempotency_key_digest.to_string(),
                        self.proposal_digest.to_string(),
                        self.evidence_digest.to_string(),
                        self.scope_digest.to_string(),
                        format!("{:?}", self.state),
                    ],
                )
        {
            // The state is deliberately checked by the service against the
            // proposal; this branch catches all serialization/tamper flags.
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ContractDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    EvidenceBindingMismatch,
    TamperedEvidence,
    PartialEvidence,
    QuotaExceeded,
    DriftedEvidence,
    AccessLoss,
    ProviderUnknown,
    NotFound,
    Throttled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub connected: bool,
    pub native: bool,
    pub independent_live_readback: bool,
    pub adopted_outcome: bool,
}

pub type AwsLicenseManagerVerification = VerificationReport;
pub type AwsLicenseManagerResultEvidence = AwsLicenseManagerEvidence;

impl VerificationReport {
    fn from_failures(mut failures: Vec<VerificationFailure>) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        Self {
            valid,
            review_eligible: valid,
            failures,
            connected: false,
            native: false,
            independent_live_readback: false,
            adopted_outcome: false,
        }
    }
}

pub struct AwsLicenseManagerService<T: crate::provider::AwsLicenseManagerTransport> {
    scope: AwsLicenseManagerScope,
    provider: AwsLicenseManagerProvider<T>,
    registration: AwsLicenseManagerRegistration,
    records: BTreeMap<Digest, AwsLicenseManagerRecord>,
}

impl<T> fmt::Debug for AwsLicenseManagerService<T>
where
    T: crate::provider::AwsLicenseManagerTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsLicenseManagerService")
            .field("scope_digest", &self.scope.digest())
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T> AwsLicenseManagerService<T>
where
    T: crate::provider::AwsLicenseManagerTransport,
{
    pub fn new(
        scope: AwsLicenseManagerScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        mut provider: AwsLicenseManagerProvider<T>,
    ) -> Result<Self> {
        let registration =
            provider.register_scope(scope.clone(), secret_reference, permission_snapshot)?;
        Ok(Self {
            scope,
            provider,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn with_registration(
        scope: AwsLicenseManagerScope,
        registration: AwsLicenseManagerRegistration,
        mut provider: AwsLicenseManagerProvider<T>,
    ) -> Result<Self> {
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsLicenseManagerError::ScopeMismatch);
        }
        registration.validate_for(provider.definition())?;
        provider.bind_registration(registration.clone())?;
        Ok(Self {
            scope,
            provider,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsLicenseManagerScope {
        &self.scope
    }

    pub fn provider(&self) -> &AwsLicenseManagerProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsLicenseManagerProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsLicenseManagerRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsLicenseManagerRegistration {
        &mut self.registration
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: AWS_LICENSE_MANAGER_SERVICE_ID.to_owned(),
            provider_id: AWS_LICENSE_MANAGER_PROVIDER_ID.to_owned(),
            consumer_id: AWS_LICENSE_MANAGER_CONSUMER_ID.to_owned(),
            operations: AwsLicenseManagerOperation::ALL
                .iter()
                .map(|operation| operation.as_api_name().to_owned())
                .collect(),
            permissions: crate::AWS_LICENSE_MANAGER_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn capabilities(&self) -> Vec<AwsLicenseManagerCapability> {
        AwsLicenseManagerOperation::ALL
            .iter()
            .map(|operation| AwsLicenseManagerCapability {
                capability_id: format!("aws-license-manager-result.{}", operation.as_api_name()),
                operation: *operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect()
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsLicenseManagerReadRequest> {
        AwsLicenseManagerReadRequest::new(
            &self.scope,
            self.provider.provider_digest().clone(),
            self.registration.registration_digest().clone(),
            page_size,
            max_pages,
            observed_at,
        )
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsLicenseManagerReadRequest> {
        self.request(10, crate::AWS_LICENSE_MANAGER_MAX_PAGES, observed_at)
    }

    pub fn read(
        &mut self,
        request: AwsLicenseManagerReadRequest,
    ) -> Result<AwsLicenseManagerEvidence> {
        self.ensure_request(&request)?;
        self.collect(request)
    }

    pub fn propose(
        &mut self,
        request: AwsLicenseManagerReadRequest,
    ) -> Result<AwsLicenseManagerProposal> {
        let evidence = self.read(request)?;
        Ok(AwsLicenseManagerProposal::new(evidence))
    }

    pub fn record(
        &mut self,
        proposal: &AwsLicenseManagerProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsLicenseManagerRecord> {
        self.ensure_active()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(AwsLicenseManagerError::StaleEvidence);
        }
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsLicenseManagerError::ReplayConflict);
            }
            return Ok(AwsLicenseManagerRecord::new(proposal, key_digest, true));
        }
        let record = AwsLicenseManagerRecord::new(proposal, key_digest.clone(), false);
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }

    pub fn verify(&self, proposal: &AwsLicenseManagerProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != self.scope.digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.contract_digest != *self.registration.contract_digest() {
            failures.push(VerificationFailure::ContractDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.provider.provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != *self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.evidence_binding_digest != *self.registration.evidence_binding_digest()
        {
            failures.push(VerificationFailure::EvidenceBindingMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        push_state_failure(&mut failures, proposal.state);
        let mut report = VerificationReport::from_failures(failures);
        report.review_eligible = report.valid && proposal.evidence.is_review_eligible();
        report
    }

    pub fn verify_record(&self, record: &AwsLicenseManagerRecord) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if record.scope_digest != self.scope.digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if record.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        VerificationReport::from_failures(failures)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        let transition = self.registration.revoke()?;
        self.provider.bind_registration(self.registration.clone())?;
        Ok(transition)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        let transition = self.registration.reverse()?;
        self.provider.bind_registration(self.registration.clone())?;
        Ok(transition)
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        let transition = self.registration.restore()?;
        self.provider.bind_registration(self.registration.clone())?;
        Ok(transition)
    }

    pub fn consumer(&self) -> Result<MissionAwsLicenseManagerConsumer> {
        MissionAwsLicenseManagerConsumer::new(self.scope.clone(), self.registration.clone())
    }

    fn ensure_active(&self) -> Result<()> {
        if !self.registration.is_active() {
            Err(AwsLicenseManagerError::RegistrationInactive)
        } else {
            Ok(())
        }
    }

    fn ensure_request(&self, request: &AwsLicenseManagerReadRequest) -> Result<()> {
        self.ensure_active()?;
        self.registration.validate_for(self.provider.definition())?;
        request.validate_for(
            &self.scope,
            self.provider.provider_digest(),
            self.registration.registration_digest(),
        )
    }

    fn collect(
        &mut self,
        request: AwsLicenseManagerReadRequest,
    ) -> Result<AwsLicenseManagerEvidence> {
        let mut list_cursor = None;
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut list_digests = Vec::new();
        let mut cursor_digest = None;
        let mut configuration: Option<LicenseConfigurationMetadata> = None;

        loop {
            if list_pages >= request.max_pages {
                break;
            }
            let list_request = ListLicenseConfigurationsRequest::new(
                &self.scope,
                request.page_size,
                list_cursor.clone(),
            )?;
            let page = match self.provider.list_license_configurations(&list_request) {
                Ok(page) => page,
                Err(error) => {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::from_list_error(&error),
                        list_pages,
                        0,
                        list_complete,
                        false,
                        configuration.as_ref(),
                        UsageProjection::empty(&self.scope),
                        nonempty_digest(&list_digests),
                        None,
                        None,
                        cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListLicenseConfigurations,
                            &error,
                        )),
                    ));
                }
            };
            list_pages = list_pages.saturating_add(1);
            list_digests.push(page.page_digest.clone());
            if page.partial {
                return Ok(self.failure_evidence(
                    request,
                    EvidenceState::Partial,
                    list_pages,
                    0,
                    false,
                    false,
                    configuration.as_ref(),
                    UsageProjection::empty(&self.scope),
                    nonempty_digest(&list_digests),
                    None,
                    None,
                    cursor_digest,
                    Some(EvidenceFailure::from_error(
                        AwsLicenseManagerOperation::ListLicenseConfigurations,
                        &AwsLicenseManagerError::PartialEvidence,
                    )),
                ));
            }
            for item in &page.items {
                if item.identity().digest() != self.scope.license_configuration().digest() {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Drifted,
                        list_pages,
                        0,
                        false,
                        false,
                        Some(item),
                        UsageProjection::empty(&self.scope),
                        nonempty_digest(&list_digests),
                        None,
                        None,
                        cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListLicenseConfigurations,
                            &AwsLicenseManagerError::ConfigurationDrift,
                        )),
                    ));
                }
                if configuration
                    .as_ref()
                    .is_some_and(|previous| previous.digest() != item.digest())
                {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Drifted,
                        list_pages,
                        0,
                        false,
                        false,
                        Some(item),
                        UsageProjection::empty(&self.scope),
                        nonempty_digest(&list_digests),
                        None,
                        None,
                        cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListLicenseConfigurations,
                            &AwsLicenseManagerError::ConfigurationDrift,
                        )),
                    ));
                }
                configuration = Some(item.clone());
            }
            if let Some(token) = page.next_token {
                cursor_digest = Some(token.token_digest().clone());
                if list_cursor
                    .as_ref()
                    .is_some_and(|previous| previous.token_digest() == token.token_digest())
                {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Drifted,
                        list_pages,
                        0,
                        false,
                        false,
                        configuration.as_ref(),
                        UsageProjection::empty(&self.scope),
                        nonempty_digest(&list_digests),
                        None,
                        None,
                        cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListLicenseConfigurations,
                            &AwsLicenseManagerError::PageLoop,
                        )),
                    ));
                }
                list_cursor = Some(token);
            } else {
                list_complete = true;
                break;
            }
        }

        if !list_complete {
            return Ok(self.failure_evidence(
                request,
                EvidenceState::Partial,
                list_pages,
                0,
                false,
                false,
                configuration.as_ref(),
                UsageProjection::empty(&self.scope),
                nonempty_digest(&list_digests),
                None,
                None,
                cursor_digest,
                Some(EvidenceFailure::from_error(
                    AwsLicenseManagerOperation::ListLicenseConfigurations,
                    &AwsLicenseManagerError::PartialEvidence,
                )),
            ));
        }
        let Some(configuration) = configuration else {
            return Ok(self.failure_evidence(
                request,
                EvidenceState::NotFound,
                list_pages,
                0,
                true,
                false,
                None,
                UsageProjection::empty(&self.scope),
                nonempty_digest(&list_digests),
                None,
                None,
                cursor_digest,
                Some(EvidenceFailure::from_error(
                    AwsLicenseManagerOperation::ListLicenseConfigurations,
                    &AwsLicenseManagerError::Transport(AwsLicenseManagerTransportError::NotFound),
                )),
            ));
        };

        let get_request = GetLicenseConfigurationRequest::for_scope(&self.scope)?;
        let get_page = match self.provider.get_license_configuration(&get_request) {
            Ok(page) => page,
            Err(error) => {
                return Ok(self.failure_evidence(
                    request,
                    EvidenceState::from_get_error(&error),
                    list_pages,
                    0,
                    true,
                    false,
                    Some(&configuration),
                    UsageProjection::empty(&self.scope),
                    nonempty_digest(&list_digests),
                    None,
                    None,
                    cursor_digest,
                    Some(EvidenceFailure::from_error(
                        AwsLicenseManagerOperation::GetLicenseConfiguration,
                        &error,
                    )),
                ));
            }
        };
        if get_page.configuration.digest() != configuration.digest() {
            return Ok(self.failure_evidence(
                request,
                EvidenceState::Drifted,
                list_pages,
                0,
                true,
                false,
                Some(&get_page.configuration),
                UsageProjection::empty(&self.scope),
                nonempty_digest(&list_digests),
                Some(get_page.page_digest),
                None,
                cursor_digest,
                Some(EvidenceFailure::from_error(
                    AwsLicenseManagerOperation::GetLicenseConfiguration,
                    &AwsLicenseManagerError::ConfigurationDrift,
                )),
            ));
        }

        let mut usage_cursor = None;
        let mut usage_pages = 0_u16;
        let mut usage_complete = false;
        let mut usage_digests = Vec::new();
        let mut usage_items = Vec::new();
        let mut usage_cursor_digest = cursor_digest;
        loop {
            if usage_pages >= request.max_pages {
                break;
            }
            let usage_request = ListUsageForLicenseConfigurationRequest::new(
                &self.scope,
                request.usage_window.clone(),
                request.page_size,
                usage_cursor.clone(),
            )?;
            let page = match self
                .provider
                .list_usage_for_license_configuration(&usage_request)
            {
                Ok(page) => page,
                Err(error) => {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::from_usage_error(&error),
                        list_pages,
                        usage_pages,
                        true,
                        usage_complete,
                        Some(&configuration),
                        usage_projection(&self.scope, &configuration, &usage_items),
                        nonempty_digest(&list_digests),
                        Some(get_page.page_digest),
                        nonempty_digest(&usage_digests),
                        usage_cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                            &error,
                        )),
                    ));
                }
            };
            usage_pages = usage_pages.saturating_add(1);
            usage_digests.push(page.page_digest.clone());
            if page.partial {
                return Ok(self.failure_evidence(
                    request,
                    EvidenceState::Partial,
                    list_pages,
                    usage_pages,
                    true,
                    false,
                    Some(&configuration),
                    usage_projection(&self.scope, &configuration, &usage_items),
                    nonempty_digest(&list_digests),
                    Some(get_page.page_digest),
                    nonempty_digest(&usage_digests),
                    usage_cursor_digest,
                    Some(EvidenceFailure::from_error(
                        AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                        &AwsLicenseManagerError::PartialEvidence,
                    )),
                ));
            }
            for item in page.items {
                if !self.scope.usage_window().contains(item.association_time()) {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Drifted,
                        list_pages,
                        usage_pages,
                        true,
                        false,
                        Some(&configuration),
                        usage_projection(&self.scope, &configuration, &usage_items),
                        nonempty_digest(&list_digests),
                        Some(get_page.page_digest),
                        nonempty_digest(&usage_digests),
                        usage_cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                            &AwsLicenseManagerError::UsageWindowDrift,
                        )),
                    ));
                }
                if usage_items.len() >= crate::AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Partial,
                        list_pages,
                        usage_pages,
                        true,
                        false,
                        Some(&configuration),
                        usage_projection(&self.scope, &configuration, &usage_items),
                        nonempty_digest(&list_digests),
                        Some(get_page.page_digest),
                        nonempty_digest(&usage_digests),
                        usage_cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                            &AwsLicenseManagerError::PartialEvidence,
                        )),
                    ));
                }
                if usage_items
                    .iter()
                    .any(|previous| previous.digest() == item.digest())
                {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Drifted,
                        list_pages,
                        usage_pages,
                        true,
                        false,
                        Some(&configuration),
                        usage_projection(&self.scope, &configuration, &usage_items),
                        nonempty_digest(&list_digests),
                        Some(get_page.page_digest),
                        nonempty_digest(&usage_digests),
                        usage_cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                            &AwsLicenseManagerError::ResourceDrift,
                        )),
                    ));
                }
                let current_consumed = usage_items.iter().try_fold(0_u64, |total, previous| {
                    total.checked_add(previous.consumed_licenses())
                });
                if current_consumed
                    .and_then(|total| total.checked_add(item.consumed_licenses()))
                    .is_none()
                {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Drifted,
                        list_pages,
                        usage_pages,
                        true,
                        false,
                        Some(&configuration),
                        usage_projection(&self.scope, &configuration, &usage_items),
                        nonempty_digest(&list_digests),
                        Some(get_page.page_digest),
                        nonempty_digest(&usage_digests),
                        usage_cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                            &AwsLicenseManagerError::ResourceDrift,
                        )),
                    ));
                }
                usage_items.push(item);
            }
            if let Some(token) = page.next_token {
                usage_cursor_digest = Some(token.token_digest().clone());
                if usage_cursor
                    .as_ref()
                    .is_some_and(|previous| previous.token_digest() == token.token_digest())
                {
                    return Ok(self.failure_evidence(
                        request,
                        EvidenceState::Drifted,
                        list_pages,
                        usage_pages,
                        true,
                        false,
                        Some(&configuration),
                        usage_projection(&self.scope, &configuration, &usage_items),
                        nonempty_digest(&list_digests),
                        Some(get_page.page_digest),
                        nonempty_digest(&usage_digests),
                        usage_cursor_digest,
                        Some(EvidenceFailure::from_error(
                            AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                            &AwsLicenseManagerError::PageLoop,
                        )),
                    ));
                }
                usage_cursor = Some(token);
            } else {
                usage_complete = true;
                break;
            }
        }
        if !usage_complete {
            return Ok(self.failure_evidence(
                request,
                EvidenceState::Partial,
                list_pages,
                usage_pages,
                true,
                false,
                Some(&configuration),
                usage_projection(&self.scope, &configuration, &usage_items),
                nonempty_digest(&list_digests),
                Some(get_page.page_digest),
                nonempty_digest(&usage_digests),
                usage_cursor_digest,
                Some(EvidenceFailure::from_error(
                    AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
                    &AwsLicenseManagerError::PartialEvidence,
                )),
            ));
        }
        let usage = usage_projection(&self.scope, &configuration, &usage_items);
        let state = if usage.quota_state == QuotaState::Exceeded {
            EvidenceState::QuotaExceeded
        } else if usage.quota_state == QuotaState::Unknown
            || usage.resource_status == ManagedResourceStatus::Unknown
            || configuration.status() != crate::model::LicenseConfigurationStatus::Active
            || matches!(
                configuration.license_type(),
                crate::model::LicenseType::Unknown
            )
        {
            EvidenceState::ProviderUnknown
        } else {
            EvidenceState::Complete
        };
        Ok(AwsLicenseManagerEvidence::new(
            &self.registration,
            self.provider.definition(),
            state,
            list_pages,
            usage_pages,
            true,
            true,
            Some(ConfigurationProjection::from(&configuration)),
            usage,
            nonempty_digest(&list_digests),
            Some(get_page.page_digest),
            nonempty_digest(&usage_digests),
            usage_cursor_digest,
            None,
            self.provider.provenance(),
        ))
    }

    fn failure_evidence(
        &self,
        _request: AwsLicenseManagerReadRequest,
        state: EvidenceState,
        list_pages: u16,
        usage_pages: u16,
        list_complete: bool,
        usage_complete: bool,
        configuration: Option<&LicenseConfigurationMetadata>,
        usage: UsageProjection,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        usage_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        failure: Option<EvidenceFailure>,
    ) -> AwsLicenseManagerEvidence {
        AwsLicenseManagerEvidence::new(
            &self.registration,
            self.provider.definition(),
            state,
            list_pages,
            usage_pages,
            list_complete,
            usage_complete,
            configuration.map(ConfigurationProjection::from),
            usage,
            list_digest,
            get_digest,
            usage_digest,
            cursor_digest,
            failure,
            self.provider.provenance(),
        )
    }
}

fn nonempty_digest(digests: &[Digest]) -> Option<Digest> {
    (!digests.is_empty()).then(|| {
        Digest::from_fields(
            "aws-license-manager-page-digests/v1",
            &[digests
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")],
        )
    })
}

fn usage_projection(
    scope: &AwsLicenseManagerScope,
    configuration: &LicenseConfigurationMetadata,
    items: &[crate::model::LicenseUsageItem],
) -> UsageProjection {
    let mut consumed_licenses = 0_u64;
    let mut resource_digests = BTreeSet::new();
    let mut statuses = BTreeSet::new();
    let mut item_digests = Vec::new();
    for item in items {
        consumed_licenses = consumed_licenses.saturating_add(item.consumed_licenses());
        resource_digests.insert(item.resource().digest());
        statuses.insert(item.status());
        item_digests.push(item.digest());
    }
    let resource_status = if statuses.contains(&ManagedResourceStatus::Unknown) {
        ManagedResourceStatus::Unknown
    } else if statuses.contains(&ManagedResourceStatus::Inactive) {
        ManagedResourceStatus::Inactive
    } else if statuses.is_empty() {
        ManagedResourceStatus::Unknown
    } else {
        ManagedResourceStatus::Active
    };
    let quota_state = if resource_status == ManagedResourceStatus::Unknown {
        QuotaState::Unknown
    } else if consumed_licenses > configuration.license_count() {
        QuotaState::Exceeded
    } else if consumed_licenses == configuration.license_count() {
        QuotaState::AtLimit
    } else {
        QuotaState::WithinLimit
    };
    UsageProjection {
        usage_window: scope.usage_window().clone(),
        usage_item_count: u32::try_from(items.len()).unwrap_or(u32::MAX),
        consumed_licenses,
        resource_status,
        resource_digests: resource_digests.into_iter().collect(),
        usage_digest: Digest::from_fields(
            "aws-license-manager-usage-summary/v1",
            &[item_digests
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")],
        ),
        quota_state,
    }
}

fn push_state_failure(failures: &mut Vec<VerificationFailure>, state: EvidenceState) {
    match state {
        EvidenceState::Complete => {}
        EvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
        EvidenceState::QuotaExceeded => failures.push(VerificationFailure::QuotaExceeded),
        EvidenceState::Drifted => failures.push(VerificationFailure::DriftedEvidence),
        EvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
        EvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
        EvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
        EvidenceState::ProviderUnknown => failures.push(VerificationFailure::ProviderUnknown),
        EvidenceState::RegistrationRevoked => {
            failures.push(VerificationFailure::RegistrationInactive);
        }
    }
}

trait ErrorState {
    fn from_list_error(error: &AwsLicenseManagerError) -> EvidenceState;
    fn from_get_error(error: &AwsLicenseManagerError) -> EvidenceState;
    fn from_usage_error(error: &AwsLicenseManagerError) -> EvidenceState;
}

impl ErrorState for EvidenceState {
    fn from_list_error(error: &AwsLicenseManagerError) -> EvidenceState {
        state_from_error(error)
    }

    fn from_get_error(error: &AwsLicenseManagerError) -> EvidenceState {
        state_from_error(error)
    }

    fn from_usage_error(error: &AwsLicenseManagerError) -> EvidenceState {
        state_from_error(error)
    }
}

fn state_from_error(error: &AwsLicenseManagerError) -> EvidenceState {
    match error {
        AwsLicenseManagerError::RegistrationRevoked
        | AwsLicenseManagerError::RegistrationInactive => EvidenceState::RegistrationRevoked,
        AwsLicenseManagerError::Transport(transport) => match transport {
            AwsLicenseManagerTransportError::BadRequest
            | AwsLicenseManagerTransportError::InvalidResponse => EvidenceState::Drifted,
            AwsLicenseManagerTransportError::Unauthorized
            | AwsLicenseManagerTransportError::Forbidden
            | AwsLicenseManagerTransportError::AccessLost
            | AwsLicenseManagerTransportError::BlockedEnv => EvidenceState::AccessLoss,
            AwsLicenseManagerTransportError::NotFound => EvidenceState::NotFound,
            AwsLicenseManagerTransportError::RateLimited { .. } => EvidenceState::Throttled,
            AwsLicenseManagerTransportError::Partial => EvidenceState::Partial,
            AwsLicenseManagerTransportError::ServerError { .. }
            | AwsLicenseManagerTransportError::Timeout
            | AwsLicenseManagerTransportError::QueueExhausted => EvidenceState::ProviderUnknown,
        },
        AwsLicenseManagerError::PartialEvidence | AwsLicenseManagerError::PageLoop => {
            EvidenceState::Partial
        }
        AwsLicenseManagerError::ConfigurationDrift
        | AwsLicenseManagerError::ResourceDrift
        | AwsLicenseManagerError::UsageWindowDrift
        | AwsLicenseManagerError::TamperedEvidence => EvidenceState::Drifted,
        AwsLicenseManagerError::QuotaExceeded => EvidenceState::QuotaExceeded,
        _ => EvidenceState::ProviderUnknown,
    }
}
