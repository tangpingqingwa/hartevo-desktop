use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::model::{
    BambooHrDirectoryRequest, BambooHrDirectoryScope, BambooHrEmployeeListBounds,
    BambooHrEmployeeListRequest, Consent, Digest, DirectoryEmployeeProjection,
    DirectoryFieldProjection, Mission, ModelError, Project, ProviderRevision, ReadBounds,
    SecretReference, TransportProvenance,
};
use crate::provider::{BambooHrDirectoryResponse, BambooHrProvider, ProviderError};
use crate::{
    BAMBOOHR_DIRECTORY_CONSUMER_ID, BAMBOOHR_DIRECTORY_PROVIDER_ID,
    BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION, BAMBOOHR_DIRECTORY_RESULT_PLUGIN_ID,
    BAMBOOHR_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT, BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION,
    BAMBOOHR_DIRECTORY_SERVICE_ID, api_digest, contract_digest, evidence_schema_digest,
    permission_digest,
};
use crate::{BambooHrDirectoryResultError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl Default for BambooHrDirectoryCapabilities {
    fn default() -> Self {
        Self {
            service_id: BAMBOOHR_DIRECTORY_SERVICE_ID.to_owned(),
            provider_id: BAMBOOHR_DIRECTORY_PROVIDER_ID.to_owned(),
            consumer_id: BAMBOOHR_DIRECTORY_CONSUMER_ID.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "reverse_registration".to_owned(),
                "restore_registration".to_owned(),
                "revoke_registration".to_owned(),
                "read_employees_directory".to_owned(),
                "read_employee_metadata".to_owned(),
                "compile_evidence_proposal".to_owned(),
                "verify_proposal".to_owned(),
                "record_proposal".to_owned(),
                "read_back_record".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            external_writes: false,
            kernel_authority: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Reversed,
    Revoked,
}

impl RegistrationStatus {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub next_status: RegistrationStatus,
    pub registration_revision: crate::model::Revision,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

/// Version-, contract-, provider-, API-, permission-, scope-, secret-, and
/// evidence-schema-bound registration. The secret handle itself is omitted
/// from serialization and only its digest crosses the registration boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryRegistration {
    pub registration_id: String,
    pub registration_revision: crate::model::Revision,
    pub status: RegistrationStatus,
    pub scope: BambooHrDirectoryScope,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub fieldset_digest: Digest,
    pub employee_scope_digest: Digest,
    pub evidence_schema_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    #[serde(skip)]
    secret_reference: SecretReference,
}

impl BambooHrDirectoryRegistration {
    pub fn new(
        registration_id: impl Into<String>,
        scope: BambooHrDirectoryScope,
        secret_reference: SecretReference,
        provider: &BambooHrProvider,
    ) -> Result<Self> {
        Self::new_with_revision(
            registration_id,
            scope,
            secret_reference,
            provider,
            crate::model::Revision::new(1)?,
        )
    }

    pub fn new_with_revision(
        registration_id: impl Into<String>,
        scope: BambooHrDirectoryScope,
        secret_reference: SecretReference,
        provider: &BambooHrProvider,
        registration_revision: crate::model::Revision,
    ) -> Result<Self> {
        let registration_id = registration_id.into();
        if registration_id.is_empty()
            || registration_id.len() > crate::model::MAX_IDENTIFIER_BYTES
            || !registration_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(BambooHrDirectoryResultError::Model(ModelError::Invalid {
                field: "registration id".to_owned(),
                reason: "must be a bounded opaque identifier".to_owned(),
            }));
        }
        scope.validate()?;
        secret_reference.validate_against(&scope)?;
        let mut registration = Self {
            registration_id,
            registration_revision,
            status: RegistrationStatus::Active,
            scope: scope.clone(),
            plugin_id: BAMBOOHR_DIRECTORY_RESULT_PLUGIN_ID.to_owned(),
            plugin_version: BAMBOOHR_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            plugin_version_digest: Digest::from_text(BAMBOOHR_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT),
            contract_version: BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_version_digest: Digest::from_text(BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id().to_owned(),
            provider_revision: provider.provider_revision().clone(),
            provider_digest: provider.provider_digest().clone(),
            api_digest: provider.api_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            fieldset_digest: scope.fieldset_digest().clone(),
            employee_scope_digest: scope.employee_scope_digest().clone(),
            evidence_schema_digest: evidence_schema_digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_digest: Digest::from_text("unsealed-bamboohr-registration"),
            secret_reference,
        };
        registration.registration_digest = registration.compute_digest();
        registration.validate(provider)?;
        Ok(registration)
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.is_active() && !self.secret_reference.is_revoked()
    }

    #[must_use]
    pub const fn is_reversible(&self) -> bool {
        true
    }

    pub fn validate(&self, provider: &BambooHrProvider) -> Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate_against(&self.scope)?;
        if self.plugin_id != BAMBOOHR_DIRECTORY_RESULT_PLUGIN_ID
            || self.plugin_version != BAMBOOHR_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT
            || self.plugin_version_digest
                != Digest::from_text(BAMBOOHR_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT)
            || self.contract_version != BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION
            || self.contract_version_digest
                != Digest::from_text(BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION)
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id()
            || self.provider_revision != *provider.provider_revision()
            || self.provider_digest != *provider.provider_digest()
            || self.api_digest != *provider.api_digest()
            || self.permission_digest != permission_digest()
            || self.fieldset_digest != *self.scope.fieldset_digest()
            || self.employee_scope_digest != *self.scope.employee_scope_digest()
            || self.evidence_schema_digest != evidence_schema_digest()
            || self.secret_reference_digest != *self.secret_reference.reference_digest()
            || self.scope.scope_digest() != &self.scope_digest
            || self.registration_revision.value() == 0
            || self.registration_digest != self.compute_digest()
        {
            return Err(BambooHrDirectoryResultError::RegistrationDrift);
        }
        if self.secret_reference.scope_digest() != &self.scope_digest {
            return Err(BambooHrDirectoryResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn reverse(
        &mut self,
        provider: &BambooHrProvider,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Active {
            return Err(BambooHrDirectoryResultError::InvalidRegistrationTransition);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.bump_revision_and_seal(provider)?;
        Ok(RegistrationTransitionEvidence {
            previous_status,
            next_status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            reversible: true,
            revocable: true,
        })
    }

    pub fn restore(
        &mut self,
        provider: &BambooHrProvider,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Reversed || self.secret_reference.is_revoked() {
            return Err(BambooHrDirectoryResultError::InvalidRegistrationTransition);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.bump_revision_and_seal(provider)?;
        Ok(RegistrationTransitionEvidence {
            previous_status,
            next_status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            reversible: true,
            revocable: true,
        })
    }

    pub fn revoke(
        &mut self,
        provider: &BambooHrProvider,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Revoked {
            return Err(BambooHrDirectoryResultError::InvalidRegistrationTransition);
        }
        let previous_status = self.status;
        if !self.secret_reference.is_revoked() {
            self.secret_reference.revoke()?;
        }
        self.status = RegistrationStatus::Revoked;
        self.bump_revision_and_seal(provider)?;
        Ok(RegistrationTransitionEvidence {
            previous_status,
            next_status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            reversible: false,
            revocable: true,
        })
    }

    pub fn revoke_secret_reference(&mut self, provider: &BambooHrProvider) -> Result<()> {
        if !self.secret_reference.is_revoked() {
            self.secret_reference.revoke()?;
        }
        self.bump_revision_and_seal(provider)
    }

    pub fn restore_secret_reference(&mut self, provider: &BambooHrProvider) -> Result<()> {
        self.secret_reference.restore()?;
        self.bump_revision_and_seal(provider)
    }

    fn bump_revision_and_seal(&mut self, provider: &BambooHrProvider) -> Result<()> {
        self.registration_revision =
            crate::model::Revision::new(self.registration_revision.value().saturating_add(1))?;
        self.registration_digest = self.compute_digest();
        self.validate(provider)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-directory-registration/v1",
            &[
                self.registration_id.clone(),
                self.registration_revision.value().to_string(),
                format!("{:?}", self.status),
                self.plugin_id.clone(),
                self.plugin_version_digest.as_str().to_owned(),
                self.contract_version_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.provider_id.clone(),
                self.provider_revision.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.fieldset_digest.as_str().to_owned(),
                self.employee_scope_digest.as_str().to_owned(),
                self.evidence_schema_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryProjection {
    pub company_domain_digest: Digest,
    pub only_current: bool,
    pub fields_digest: Digest,
    pub field_count: usize,
    pub employees_digest: Digest,
    pub employee_count: usize,
    pub snapshot_digest: Digest,
    pub provider_revision: ProviderRevision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryRequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub company_domain_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub redacted: bool,
}

impl BambooHrDirectoryRequestReceipt {
    fn from_request(request: &BambooHrDirectoryRequest) -> Self {
        Self {
            operation: "get_employees_directory".to_owned(),
            request_digest: request.request_digest.clone(),
            path_digest: request.path_digest.clone(),
            company_domain_digest: request.company_domain_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            redacted: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrEmployeeListRequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub field_selection_digest: Digest,
    pub page_number: u16,
    pub cursor_digest: Option<Digest>,
    pub redacted: bool,
}

impl BambooHrEmployeeListRequestReceipt {
    fn from_request(request: &BambooHrEmployeeListRequest) -> Self {
        Self {
            operation: "list_employees_metadata".to_owned(),
            request_digest: request.request_digest.clone(),
            path_digest: request.path_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            field_selection_digest: request.field_selection_digest.clone(),
            page_number: request.page_number,
            cursor_digest: request.cursor_digest.clone(),
            redacted: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryCostReceipt {
    pub operation: String,
    pub response_bytes: usize,
    pub bounded_request_units: u32,
    pub cost_digest: Digest,
    pub estimate_only: bool,
    pub redacted: bool,
}

impl BambooHrDirectoryCostReceipt {
    fn from_response(response: &BambooHrDirectoryResponse) -> Self {
        let bounded_request_units = 1;
        let cost_digest = Digest::from_fields(
            "bamboohr-directory-cost/v1",
            &[
                response.response_bytes.to_string(),
                bounded_request_units.to_string(),
                response.response_digest.as_str().to_owned(),
            ],
        );
        Self {
            operation: "get_employees_directory".to_owned(),
            response_bytes: response.response_bytes,
            bounded_request_units,
            cost_digest,
            estimate_only: true,
            redacted: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BambooHrDirectoryEvidenceStatus {
    Ready,
    Present,
    Empty,
    FieldsetLimited,
    Inactive,
    Partial,
    Unauthorized,
    Forbidden,
    AccessLost,
    NotFound,
    RateLimited,
    TimedOut,
    ProviderUnknown,
    RegistrationRevoked,
    Tampered,
}

pub type EvidenceStatus = BambooHrDirectoryEvidenceStatus;
pub type BambooHrDirectoryEvidenceState = BambooHrDirectoryEvidenceStatus;

impl BambooHrDirectoryEvidenceStatus {
    #[must_use]
    pub const fn review_eligible(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Present | Self::Empty | Self::FieldsetLimited | Self::Inactive
        )
    }

    #[must_use]
    pub fn from_provider_error(error: &ProviderError) -> Self {
        match error.class() {
            crate::provider::ProviderFailureClass::Unauthorized => Self::Unauthorized,
            crate::provider::ProviderFailureClass::Forbidden => Self::AccessLost,
            crate::provider::ProviderFailureClass::NotFound => Self::NotFound,
            crate::provider::ProviderFailureClass::RateLimited => Self::RateLimited,
            crate::provider::ProviderFailureClass::Timeout => Self::TimedOut,
            crate::provider::ProviderFailureClass::Partial => Self::Partial,
            crate::provider::ProviderFailureClass::Tampered => Self::Tampered,
            crate::provider::ProviderFailureClass::BlockedEnv
            | crate::provider::ProviderFailureClass::Conflict
            | crate::provider::ProviderFailureClass::Server
            | crate::provider::ProviderFailureClass::Unsupported
            | crate::provider::ProviderFailureClass::Transport => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub company_domain_digest: Digest,
    pub only_current: bool,
    pub project: Project,
    pub mission: Mission,
    pub work_product: crate::model::WorkProduct,
    pub consent: Consent,
    pub fieldset_digest: Digest,
    pub employee_scope_digest: Digest,
    pub fields: Vec<DirectoryFieldProjection>,
    pub employees: Vec<DirectoryEmployeeProjection>,
    pub fields_digest: Digest,
    pub employees_digest: Digest,
    pub snapshot_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub request_receipts: Vec<BambooHrDirectoryRequestReceipt>,
    pub cost_receipts: Vec<BambooHrDirectoryCostReceipt>,
    pub status: BambooHrDirectoryEvidenceStatus,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_employee_ids_retained: bool,
    pub raw_field_values_retained: bool,
    pub raw_response_retained: bool,
}

impl BambooHrDirectoryEvidence {
    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-directory-evidence/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.company_domain_digest.as_str().to_owned(),
                self.only_current.to_string(),
                serde_json::to_string(&self.project).expect("project serializes"),
                serde_json::to_string(&self.mission).expect("mission serializes"),
                serde_json::to_string(&self.work_product).expect("work product serializes"),
                serde_json::to_string(&self.consent).expect("consent serializes"),
                self.fieldset_digest.as_str().to_owned(),
                self.employee_scope_digest.as_str().to_owned(),
                serde_json::to_string(&self.fields).expect("fields serialize"),
                serde_json::to_string(&self.employees).expect("employees serialize"),
                self.fields_digest.as_str().to_owned(),
                self.employees_digest.as_str().to_owned(),
                self.snapshot_digest.as_str().to_owned(),
                self.provider_revision.as_str().to_owned(),
                self.provenance.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
                self.response_digest.as_str().to_owned(),
                self.response_bytes.to_string(),
                serde_json::to_string(&self.request_receipts).expect("request receipts serialize"),
                serde_json::to_string(&self.cost_receipts).expect("cost receipts serialize"),
                format!("{:?}", self.status),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
                self.provider_receipt.to_string(),
                self.raw_employee_ids_retained.to_string(),
                self.raw_field_values_retained.to_string(),
                self.raw_response_retained.to_string(),
            ],
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.evidence_digest == self.compute_digest()
            && self.scope_digest.is_valid()
            && self.registration_digest.is_valid()
            && self.provider_digest.is_valid()
            && self.api_digest.is_valid()
            && self.permission_digest.is_valid()
            && self.company_domain_digest.is_valid()
            && self.fieldset_digest.is_valid()
            && self.employee_scope_digest.is_valid()
            && self.request_digest.is_valid()
            && self.response_digest.is_valid()
            && self.fields_digest.is_valid()
            && self.employees_digest.is_valid()
            && self.snapshot_digest.is_valid()
            && !self.connected
            && !self.native
            && !self.first_party
            && !self.provider_receipt
            && !self.raw_employee_ids_retained
            && !self.raw_field_values_retained
            && !self.raw_response_retained
    }

    #[must_use]
    pub fn review_eligible(&self) -> bool {
        matches!(
            self.status,
            BambooHrDirectoryEvidenceStatus::Ready
                | BambooHrDirectoryEvidenceStatus::Present
                | BambooHrDirectoryEvidenceStatus::Empty
                | BambooHrDirectoryEvidenceStatus::FieldsetLimited
                | BambooHrDirectoryEvidenceStatus::Inactive
        )
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

/// Digest-only bounded evidence for the cursor-paginated BambooHR employee
/// metadata seam. Raw cursor tokens, names, contact data, and response bodies
/// never cross this evidence boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrEmployeeMetadataEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub company_domain_digest: Digest,
    pub only_current: bool,
    pub project: Project,
    pub mission: Mission,
    pub work_product: crate::model::WorkProduct,
    pub consent: Consent,
    pub fieldset_digest: Digest,
    pub employee_scope_digest: Digest,
    pub employees: Vec<DirectoryEmployeeProjection>,
    pub employees_digest: Digest,
    pub total: usize,
    pub page_count: usize,
    pub page_digests: Vec<Digest>,
    pub cursor_digests: Vec<Digest>,
    pub request_receipts: Vec<BambooHrEmployeeListRequestReceipt>,
    pub change_fence_digest: Digest,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub status: BambooHrDirectoryEvidenceStatus,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_employee_ids_retained: bool,
    pub raw_field_values_retained: bool,
    pub raw_response_retained: bool,
}

impl BambooHrEmployeeMetadataEvidence {
    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-employee-metadata-evidence/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.company_domain_digest.as_str().to_owned(),
                self.only_current.to_string(),
                serde_json::to_string(&self.project).expect("project serializes"),
                serde_json::to_string(&self.mission).expect("mission serializes"),
                serde_json::to_string(&self.work_product).expect("work product serializes"),
                serde_json::to_string(&self.consent).expect("consent serializes"),
                self.fieldset_digest.as_str().to_owned(),
                self.employee_scope_digest.as_str().to_owned(),
                serde_json::to_string(&self.employees).expect("employees serialize"),
                self.employees_digest.as_str().to_owned(),
                self.total.to_string(),
                self.page_count.to_string(),
                serde_json::to_string(&self.page_digests).expect("page digests serialize"),
                serde_json::to_string(&self.cursor_digests).expect("cursor digests serialize"),
                serde_json::to_string(&self.request_receipts).expect("request receipts serialize"),
                self.change_fence_digest.as_str().to_owned(),
                self.response_bytes.to_string(),
                self.provider_revision.as_str().to_owned(),
                self.provenance.as_str().to_owned(),
                format!("{:?}", self.status),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
                self.provider_receipt.to_string(),
                self.raw_employee_ids_retained.to_string(),
                self.raw_field_values_retained.to_string(),
                self.raw_response_retained.to_string(),
            ],
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.evidence_digest == self.compute_digest()
            && self.scope_digest.is_valid()
            && self.registration_digest.is_valid()
            && self.provider_digest.is_valid()
            && self.api_digest.is_valid()
            && self.permission_digest.is_valid()
            && self.company_domain_digest.is_valid()
            && self.fieldset_digest.is_valid()
            && self.employee_scope_digest.is_valid()
            && self.employees_digest.is_valid()
            && self.change_fence_digest.is_valid()
            && self.page_count == self.page_digests.len()
            && self.cursor_digests.len() <= self.page_count
            && self.request_receipts.len() == self.page_count
            && self.request_receipts.iter().all(|receipt| receipt.redacted)
            && self.total >= self.employees.len()
            && self
                .employees
                .iter()
                .all(DirectoryEmployeeProjection::verify_integrity)
            && !self.connected
            && !self.native
            && !self.first_party
            && !self.provider_receipt
            && !self.raw_employee_ids_retained
            && !self.raw_field_values_retained
            && !self.raw_response_retained
    }

    #[must_use]
    pub fn review_eligible(&self) -> bool {
        self.status.review_eligible()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrEmployeeMetadataProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub fieldset_digest: Digest,
    pub employee_scope_digest: Digest,
    pub project: Project,
    pub mission: Mission,
    pub work_product: crate::model::WorkProduct,
    pub consent: Consent,
    pub provider_revision: ProviderRevision,
    pub evidence_digest: Digest,
    pub status: BambooHrDirectoryEvidenceStatus,
    pub evidence: BambooHrEmployeeMetadataEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub adopted_by_kernel: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl BambooHrEmployeeMetadataProposal {
    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-employee-metadata-proposal/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.fieldset_digest.as_str().to_owned(),
                self.employee_scope_digest.as_str().to_owned(),
                serde_json::to_string(&self.project).expect("project serializes"),
                serde_json::to_string(&self.mission).expect("mission serializes"),
                serde_json::to_string(&self.work_product).expect("work product serializes"),
                serde_json::to_string(&self.consent).expect("consent serializes"),
                self.provider_revision.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                format!("{:?}", self.status),
                self.evidence.evidence_digest.as_str().to_owned(),
                self.review_only.to_string(),
                self.adopted_by_kernel.to_string(),
                self.external_writes.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
            ],
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.evidence.verify_integrity()
            && self.evidence_digest == self.evidence.evidence_digest
            && self.status == self.evidence.status
            && self.proposal_digest == self.compute_digest()
            && self.review_only
            && !self.adopted_by_kernel
            && !self.external_writes
            && !self.connected
            && !self.native
            && !self.first_party
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub fieldset_digest: Digest,
    pub employee_scope_digest: Digest,
    pub project: Project,
    pub mission: Mission,
    pub work_product: crate::model::WorkProduct,
    pub consent: Consent,
    pub provider_revision: ProviderRevision,
    pub evidence_digest: Digest,
    pub status: BambooHrDirectoryEvidenceStatus,
    pub evidence: BambooHrDirectoryEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub adopted_by_kernel: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl BambooHrDirectoryProposal {
    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-directory-proposal/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.fieldset_digest.as_str().to_owned(),
                self.employee_scope_digest.as_str().to_owned(),
                serde_json::to_string(&self.project).expect("project serializes"),
                serde_json::to_string(&self.mission).expect("mission serializes"),
                serde_json::to_string(&self.work_product).expect("work product serializes"),
                serde_json::to_string(&self.consent).expect("consent serializes"),
                self.provider_revision.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                format!("{:?}", self.status),
                self.evidence.evidence_digest.as_str().to_owned(),
                self.review_only.to_string(),
                self.adopted_by_kernel.to_string(),
                self.external_writes.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
            ],
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.evidence.verify_integrity()
            && self.evidence_digest == self.evidence.evidence_digest
            && self.proposal_digest == self.compute_digest()
            && self.review_only
            && !self.adopted_by_kernel
            && !self.external_writes
            && !self.connected
            && !self.native
            && !self.first_party
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

pub type BambooHrDirectoryResultProposal = BambooHrDirectoryProposal;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryRecordedProposal {
    pub record_id: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub fieldset_digest: Digest,
    pub employee_scope_digest: Digest,
    pub project: Project,
    pub mission: Mission,
    pub work_product: crate::model::WorkProduct,
    pub consent: Consent,
    pub provider_revision: ProviderRevision,
    pub recorded_registration_revision: crate::model::Revision,
    pub record_digest: Digest,
}

impl BambooHrDirectoryRecordedProposal {
    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.record_id,
            &self.proposal_digest,
            &self.evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.fieldset_digest,
            &self.employee_scope_digest,
            &self.project,
            &self.mission,
            &self.work_product,
            &self.consent,
            &self.provider_revision,
            &self.recorded_registration_revision,
        ))
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.record_digest == self.compute_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryReadBack {
    pub verified: bool,
    pub record_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub independent_provider_reread: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub struct BambooHrDirectoryResultService {
    provider: BambooHrProvider,
    registration: BambooHrDirectoryRegistration,
    recorded: BTreeMap<Digest, BambooHrDirectoryRecordedProposal>,
}

impl fmt::Debug for BambooHrDirectoryResultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BambooHrDirectoryResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recorded_count", &self.recorded.len())
            .finish()
    }
}

impl BambooHrDirectoryResultService {
    pub fn new(
        provider: BambooHrProvider,
        registration: BambooHrDirectoryRegistration,
    ) -> Result<Self> {
        registration.validate(&provider)?;
        Ok(Self {
            provider,
            registration,
            recorded: BTreeMap::new(),
        })
    }

    pub fn register(
        provider: BambooHrProvider,
        registration_id: impl Into<String>,
        scope: BambooHrDirectoryScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        let registration = BambooHrDirectoryRegistration::new(
            registration_id,
            scope,
            secret_reference,
            &provider,
        )?;
        Self::new(provider, registration)
    }

    pub fn register_with_revision(
        provider: BambooHrProvider,
        registration_id: impl Into<String>,
        scope: BambooHrDirectoryScope,
        secret_reference: SecretReference,
        registration_revision: crate::model::Revision,
    ) -> Result<Self> {
        let registration = BambooHrDirectoryRegistration::new_with_revision(
            registration_id,
            scope,
            secret_reference,
            &provider,
            registration_revision,
        )?;
        Self::new(provider, registration)
    }

    #[must_use]
    pub fn provider(&self) -> &BambooHrProvider {
        &self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &BambooHrDirectoryRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &BambooHrDirectoryScope {
        &self.registration.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        self.registration.secret_reference()
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> BambooHrDirectoryCapabilities {
        BambooHrDirectoryCapabilities::default()
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(&self) -> bool {
        false
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse(&self.provider)
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore(&self.provider)
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke(&self.provider)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.registration.revoke_secret_reference(&self.provider)
    }

    pub fn restore_secret_reference(&mut self) -> Result<()> {
        self.registration.restore_secret_reference(&self.provider)
    }

    pub fn read_directory(&self) -> Result<BambooHrDirectoryProjection> {
        let evidence = self.read_directory_evidence(ReadBounds::default())?;
        Ok(BambooHrDirectoryProjection {
            company_domain_digest: evidence.company_domain_digest,
            only_current: evidence.only_current,
            fields_digest: evidence.fields_digest,
            field_count: evidence.fields.len(),
            employees_digest: evidence.employees_digest,
            employee_count: evidence.employees.len(),
            snapshot_digest: evidence.snapshot_digest,
            provider_revision: evidence.provider_revision,
        })
    }

    pub fn read_directory_evidence(&self, bounds: ReadBounds) -> Result<BambooHrDirectoryEvidence> {
        self.ensure_active()?;
        bounds.validate()?;
        let request = BambooHrDirectoryRequest::new(self.scope())?;
        let response = self.provider.read_directory(&request)?;
        self.validate_response(&response, &request, &bounds)?;
        Ok(self.evidence_from_response(request, response))
    }

    pub fn read_directory_snapshot(&self, bounds: ReadBounds) -> Result<BambooHrDirectoryEvidence> {
        self.read_directory_evidence(bounds)
    }

    pub fn read_employee_metadata(
        &self,
        bounds: BambooHrEmployeeListBounds,
    ) -> Result<BambooHrEmployeeMetadataEvidence> {
        self.ensure_active()?;
        bounds.validate()?;
        let mut request = BambooHrEmployeeListRequest::new(self.scope(), &bounds)?;
        let mut employees = BTreeMap::new();
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut request_receipts = Vec::new();
        let mut seen_page_digests = std::collections::BTreeSet::new();
        let mut seen_cursor_digests = std::collections::BTreeSet::new();
        let mut change_fence_digest = None;
        let mut total = None;
        let mut response_bytes = 0_usize;

        loop {
            request_receipts.push(BambooHrEmployeeListRequestReceipt::from_request(&request));
            let page = self.provider.list_employees(&request)?;
            if !page.verify_integrity()
                || page.request_digest != request.request_digest
                || page.scope_digest != *self.scope().scope_digest()
                || page.field_selection_digest != *self.scope().employee_scope_digest()
                || page.provider_revision != *self.provider.provider_revision()
                || page.provenance != self.provider.provenance()
                || page.response_bytes > bounds.max_response_bytes
            {
                return Err(BambooHrDirectoryResultError::RevisionDrift);
            }
            if page.employees.len() > bounds.max_records {
                return Err(BambooHrDirectoryResultError::PartialResponse);
            }
            if page.total < page.employees.len() {
                return Err(BambooHrDirectoryResultError::RecordMismatch);
            }
            if !seen_page_digests.insert(page.page_digest.clone()) {
                return Err(BambooHrDirectoryResultError::RecordMismatch);
            }
            if let Some(expected_total) = total {
                if expected_total != page.total {
                    return Err(BambooHrDirectoryResultError::RevisionDrift);
                }
            } else {
                total = Some(page.total);
            }
            if let Some(expected_fence) = &change_fence_digest {
                if expected_fence != &page.change_fence_digest {
                    return Err(BambooHrDirectoryResultError::RevisionDrift);
                }
            } else {
                change_fence_digest = Some(page.change_fence_digest.clone());
            }
            response_bytes = response_bytes
                .checked_add(page.response_bytes)
                .ok_or(BambooHrDirectoryResultError::PartialResponse)?;
            if response_bytes > bounds.max_response_bytes {
                return Err(BambooHrDirectoryResultError::PartialResponse);
            }
            page_digests.push(page.page_digest.clone());
            for employee in page.employees {
                if employees
                    .insert(employee.employee_id_digest.clone(), employee)
                    .is_some()
                {
                    return Err(BambooHrDirectoryResultError::RecordMismatch);
                }
                if employees.len() > bounds.max_records {
                    return Err(BambooHrDirectoryResultError::PartialResponse);
                }
            }

            let Some(next_cursor) = page.next_cursor else {
                if !page.complete {
                    return Err(BambooHrDirectoryResultError::PartialResponse);
                }
                break;
            };
            if page_digests.len() >= usize::from(bounds.max_pages) {
                return Err(BambooHrDirectoryResultError::PartialResponse);
            }
            next_cursor.validate_against(
                self.scope(),
                &self.scope().employee_fields,
                bounds.now_epoch_seconds,
            )?;
            if !seen_cursor_digests.insert(next_cursor.digest().clone()) {
                return Err(BambooHrDirectoryResultError::RecordMismatch);
            }
            cursor_digests.push(next_cursor.digest().clone());
            request = BambooHrEmployeeListRequest::with_cursor(self.scope(), &bounds, next_cursor)?;
        }

        let employees = employees.into_values().collect::<Vec<_>>();
        let employees_digest = Digest::from_serializable(&employees);
        let status = if employees.is_empty() {
            BambooHrDirectoryEvidenceStatus::Empty
        } else if self.scope().fieldset.limited {
            BambooHrDirectoryEvidenceStatus::FieldsetLimited
        } else if employees
            .iter()
            .any(|employee| employee.status == crate::model::EmployeeStatus::Inactive)
        {
            BambooHrDirectoryEvidenceStatus::Inactive
        } else {
            BambooHrDirectoryEvidenceStatus::Present
        };
        let mut evidence = BambooHrEmployeeMetadataEvidence {
            schema_version: BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: self.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            api_digest: api_digest(),
            permission_digest: self.scope().permission_digest().clone(),
            company_domain_digest: self.scope().company_domain.digest(),
            only_current: self.scope().only_current,
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            work_product: self.scope().work_product.clone(),
            consent: self.scope().consent.clone(),
            fieldset_digest: self.scope().fieldset_digest().clone(),
            employee_scope_digest: self.scope().employee_scope_digest().clone(),
            employees,
            employees_digest,
            total: total.unwrap_or_default(),
            page_count: page_digests.len(),
            page_digests,
            cursor_digests,
            request_receipts,
            change_fence_digest: change_fence_digest
                .unwrap_or_else(|| Digest::from_text("bamboohr-empty-change-fence")),
            response_bytes,
            provider_revision: self.provider.provider_revision().clone(),
            provenance: self.provider.provenance(),
            status,
            evidence_digest: Digest::from_text("unsealed-bamboohr-employee-metadata-evidence"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_employee_ids_retained: false,
            raw_field_values_retained: false,
            raw_response_retained: false,
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub fn compile_employee_metadata_proposal(
        &self,
        evidence: BambooHrEmployeeMetadataEvidence,
    ) -> Result<BambooHrEmployeeMetadataProposal> {
        self.ensure_active()?;
        if !evidence.verify_integrity() {
            return Err(BambooHrDirectoryResultError::TamperedEvidence);
        }
        if evidence.scope_digest != *self.scope().scope_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provider_digest != *self.provider.provider_digest()
            || evidence.api_digest != *self.provider.api_digest()
            || evidence.permission_digest != *self.scope().permission_digest()
            || evidence.fieldset_digest != *self.scope().fieldset_digest()
            || evidence.employee_scope_digest != *self.scope().employee_scope_digest()
            || evidence.provider_revision != *self.provider.provider_revision()
            || evidence.project != self.scope().project
            || evidence.mission != self.scope().mission
            || evidence.work_product != self.scope().work_product
            || evidence.consent != self.scope().consent
            || evidence.company_domain_digest != self.scope().company_domain.digest()
            || evidence.only_current != self.scope().only_current
        {
            return Err(BambooHrDirectoryResultError::ScopeMismatch);
        }
        let mut proposal = BambooHrEmployeeMetadataProposal {
            schema_version: BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: self.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            api_digest: self.provider.api_digest().clone(),
            permission_digest: self.scope().permission_digest().clone(),
            fieldset_digest: self.scope().fieldset_digest().clone(),
            employee_scope_digest: self.scope().employee_scope_digest().clone(),
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            work_product: self.scope().work_product.clone(),
            consent: self.scope().consent.clone(),
            provider_revision: self.provider.provider_revision().clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status,
            evidence,
            proposal_digest: Digest::from_text("unsealed-bamboohr-employee-metadata-proposal"),
            review_only: true,
            adopted_by_kernel: false,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn verify_employee_metadata_proposal(
        &self,
        proposal: &BambooHrEmployeeMetadataProposal,
    ) -> Result<()> {
        self.ensure_active()?;
        if !proposal.verify_integrity() {
            return Err(BambooHrDirectoryResultError::TamperedEvidence);
        }
        if proposal.schema_version != BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION
            || proposal.contract_version != BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION
            || proposal.scope_digest != *self.scope().scope_digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_digest != *self.provider.provider_digest()
            || proposal.api_digest != *self.provider.api_digest()
            || proposal.permission_digest != *self.scope().permission_digest()
            || proposal.fieldset_digest != *self.scope().fieldset_digest()
            || proposal.employee_scope_digest != *self.scope().employee_scope_digest()
            || proposal.provider_revision != *self.provider.provider_revision()
            || proposal.project != self.scope().project
            || proposal.mission != self.scope().mission
            || proposal.work_product != self.scope().work_product
            || proposal.consent != self.scope().consent
            || proposal.evidence_digest != proposal.evidence.evidence_digest
            || proposal.status != proposal.evidence.status
        {
            return Err(BambooHrDirectoryResultError::StaleProposal);
        }
        Ok(())
    }

    pub fn compile_evidence_proposal(
        &self,
        evidence: BambooHrDirectoryEvidence,
    ) -> Result<BambooHrDirectoryProposal> {
        self.ensure_active()?;
        if !evidence.verify_integrity() {
            return Err(BambooHrDirectoryResultError::TamperedEvidence);
        }
        if evidence.scope_digest != *self.scope().scope_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provider_digest != *self.provider.provider_digest()
            || evidence.api_digest != *self.provider.api_digest()
            || evidence.permission_digest != *self.scope().permission_digest()
            || evidence.fieldset_digest != *self.scope().fieldset_digest()
            || evidence.employee_scope_digest != *self.scope().employee_scope_digest()
            || evidence.provider_revision != *self.provider.provider_revision()
            || evidence.project != self.scope().project
            || evidence.mission != self.scope().mission
            || evidence.work_product != self.scope().work_product
            || evidence.consent != self.scope().consent
            || evidence.company_domain_digest != self.scope().company_domain.digest()
            || evidence.only_current != self.scope().only_current
        {
            return Err(BambooHrDirectoryResultError::ScopeMismatch);
        }
        let mut proposal = BambooHrDirectoryProposal {
            schema_version: BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: self.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            api_digest: self.provider.api_digest().clone(),
            permission_digest: self.scope().permission_digest().clone(),
            fieldset_digest: self.scope().fieldset_digest().clone(),
            employee_scope_digest: self.scope().employee_scope_digest().clone(),
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            work_product: self.scope().work_product.clone(),
            consent: self.scope().consent.clone(),
            provider_revision: self.provider.provider_revision().clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status,
            evidence,
            proposal_digest: Digest::from_text("unsealed-bamboohr-proposal"),
            review_only: true,
            adopted_by_kernel: false,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn compile_proposal(
        &self,
        evidence: BambooHrDirectoryEvidence,
    ) -> Result<BambooHrDirectoryProposal> {
        self.compile_evidence_proposal(evidence)
    }

    pub fn verify_proposal(&self, proposal: &BambooHrDirectoryProposal) -> Result<()> {
        self.ensure_active()?;
        if !proposal.verify_integrity() {
            return Err(BambooHrDirectoryResultError::TamperedEvidence);
        }
        if proposal.schema_version != BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION
            || proposal.contract_version != BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION
            || proposal.scope_digest != *self.scope().scope_digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_digest != *self.provider.provider_digest()
            || proposal.api_digest != *self.provider.api_digest()
            || proposal.permission_digest != *self.scope().permission_digest()
            || proposal.fieldset_digest != *self.scope().fieldset_digest()
            || proposal.employee_scope_digest != *self.scope().employee_scope_digest()
            || proposal.provider_revision != *self.provider.provider_revision()
            || proposal.project != self.scope().project
            || proposal.mission != self.scope().mission
            || proposal.work_product != self.scope().work_product
            || proposal.consent != self.scope().consent
            || proposal.evidence.scope_digest != proposal.scope_digest
            || proposal.evidence.registration_digest != proposal.registration_digest
            || proposal.evidence_digest != proposal.evidence.evidence_digest
            || proposal.status != proposal.evidence.status
        {
            return Err(BambooHrDirectoryResultError::StaleProposal);
        }
        Ok(())
    }

    pub fn record_proposal(
        &mut self,
        proposal: &BambooHrDirectoryProposal,
    ) -> Result<BambooHrDirectoryRecordedProposal> {
        self.verify_proposal(proposal)?;
        if self.recorded.contains_key(&proposal.proposal_digest) {
            return Err(BambooHrDirectoryResultError::StaleRecord);
        }
        let record_id = Digest::from_fields(
            "bamboohr-directory-record-id/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                self.registration.registration_revision.value().to_string(),
            ],
        );
        let mut record = BambooHrDirectoryRecordedProposal {
            record_id,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            api_digest: proposal.api_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            fieldset_digest: proposal.fieldset_digest.clone(),
            employee_scope_digest: proposal.employee_scope_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            consent: proposal.consent.clone(),
            provider_revision: proposal.provider_revision.clone(),
            recorded_registration_revision: self.registration.registration_revision,
            record_digest: Digest::from_text("unsealed-bamboohr-record"),
        };
        record.record_digest = record.compute_digest();
        self.recorded
            .insert(proposal.proposal_digest.clone(), record.clone());
        Ok(record)
    }

    pub fn record(
        &mut self,
        proposal: &BambooHrDirectoryProposal,
    ) -> Result<BambooHrDirectoryRecordedProposal> {
        self.record_proposal(proposal)
    }

    pub fn read_back_record(
        &self,
        record: &BambooHrDirectoryRecordedProposal,
    ) -> Result<BambooHrDirectoryReadBack> {
        self.ensure_active()?;
        if !record.verify_integrity()
            || self.recorded.get(&record.proposal_digest) != Some(record)
            || record.registration_digest != *self.registration.registration_digest()
            || record.provider_digest != *self.provider.provider_digest()
            || record.api_digest != *self.provider.api_digest()
            || record.scope_digest != *self.scope().scope_digest()
            || record.permission_digest != *self.scope().permission_digest()
            || record.fieldset_digest != *self.scope().fieldset_digest()
            || record.employee_scope_digest != *self.scope().employee_scope_digest()
            || record.provider_revision != *self.provider.provider_revision()
            || record.project != self.scope().project
            || record.mission != self.scope().mission
            || record.work_product != self.scope().work_product
            || record.consent != self.scope().consent
            || record.recorded_registration_revision != self.registration.registration_revision
        {
            return Err(BambooHrDirectoryResultError::ReadBackFence);
        }
        Ok(BambooHrDirectoryReadBack {
            verified: true,
            record_digest: record.record_digest.clone(),
            proposal_digest: record.proposal_digest.clone(),
            evidence_digest: record.evidence_digest.clone(),
            scope_digest: record.scope_digest.clone(),
            registration_digest: record.registration_digest.clone(),
            independent_provider_reread: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn read_back(
        &self,
        record: &BambooHrDirectoryRecordedProposal,
    ) -> Result<BambooHrDirectoryReadBack> {
        self.read_back_record(record)
    }

    pub fn verify_record(
        &self,
        record: &BambooHrDirectoryRecordedProposal,
    ) -> Result<BambooHrDirectoryReadBack> {
        self.read_back_record(record)
    }

    fn ensure_active(&self) -> Result<()> {
        match self.registration.status() {
            RegistrationStatus::Revoked => {
                return Err(BambooHrDirectoryResultError::RegistrationRevoked);
            }
            RegistrationStatus::Reversed => {
                return Err(BambooHrDirectoryResultError::RegistrationInactive);
            }
            RegistrationStatus::Active => {}
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(BambooHrDirectoryResultError::SecretReferenceRevoked);
        }
        self.registration.validate(&self.provider)
    }

    fn validate_response(
        &self,
        response: &BambooHrDirectoryResponse,
        request: &BambooHrDirectoryRequest,
        bounds: &ReadBounds,
    ) -> Result<()> {
        if !response.verify_integrity() {
            return Err(BambooHrDirectoryResultError::TamperedEvidence);
        }
        if response.request_digest != request.request_digest
            || response.scope_digest != *self.scope().scope_digest()
            || response.provider_revision != *self.provider.provider_revision()
            || response.provenance != self.provider.provenance()
            || response.response_bytes > bounds.max_response_bytes
        {
            return Err(BambooHrDirectoryResultError::RevisionDrift);
        }
        if response.snapshot.fields.len() > bounds.max_fields
            || response.snapshot.employees.len() > bounds.max_records
            || !response.snapshot.verify_integrity()
        {
            return Err(BambooHrDirectoryResultError::PartialResponse);
        }
        Ok(())
    }

    fn evidence_from_response(
        &self,
        request: BambooHrDirectoryRequest,
        response: BambooHrDirectoryResponse,
    ) -> BambooHrDirectoryEvidence {
        let snapshot = response.snapshot.clone();
        let mut evidence = BambooHrDirectoryEvidence {
            schema_version: BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: self.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            api_digest: api_digest(),
            permission_digest: self.scope().permission_digest().clone(),
            company_domain_digest: self.scope().company_domain.digest(),
            only_current: self.scope().only_current,
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            work_product: self.scope().work_product.clone(),
            consent: self.scope().consent.clone(),
            fieldset_digest: self.scope().fieldset_digest().clone(),
            employee_scope_digest: self.scope().employee_scope_digest().clone(),
            fields: snapshot.fields.clone(),
            employees: snapshot.employees.clone(),
            fields_digest: snapshot.fields_digest,
            employees_digest: snapshot.employees_digest,
            snapshot_digest: snapshot.snapshot_digest,
            provider_revision: response.provider_revision.clone(),
            provenance: response.provenance,
            request_digest: request.request_digest.clone(),
            response_digest: response.response_digest.clone(),
            response_bytes: response.response_bytes,
            request_receipts: vec![BambooHrDirectoryRequestReceipt::from_request(&request)],
            cost_receipts: vec![BambooHrDirectoryCostReceipt::from_response(&response)],
            status: if response.snapshot.employees.is_empty() {
                BambooHrDirectoryEvidenceStatus::Empty
            } else if self.scope().fieldset.limited {
                BambooHrDirectoryEvidenceStatus::FieldsetLimited
            } else if response
                .snapshot
                .employees
                .iter()
                .any(|employee| employee.status == crate::model::EmployeeStatus::Inactive)
            {
                BambooHrDirectoryEvidenceStatus::Inactive
            } else {
                BambooHrDirectoryEvidenceStatus::Ready
            },
            evidence_digest: Digest::from_text("unsealed-bamboohr-evidence"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_employee_ids_retained: false,
            raw_field_values_retained: false,
            raw_response_retained: false,
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }
}

pub type BambooHRDirectoryResultService = BambooHrDirectoryResultService;
