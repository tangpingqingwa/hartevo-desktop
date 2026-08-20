use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{DockerHubImageResultError, DockerHubTransportError, Result};
use crate::model::{
    CostReceipt, Digest, DockerHubEvidenceState, DockerHubImageResultProjection,
    DockerHubImageResultRequest, DockerHubImageResultScope, PermissionSnapshot, RequestReceipt,
    SecretReference, TransportProvenance,
};
use crate::provider::{
    DockerHubOperation, DockerHubProvider, DockerHubProviderDefinition, DockerHubTagRequest,
    DockerHubTransport,
};
use crate::{
    API_REVISION, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerHubRegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubRegistrationTransition {
    pub previous_status: DockerHubRegistrationStatus,
    pub new_status: DockerHubRegistrationStatus,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl DockerHubRegistrationTransition {
    fn new(
        previous_status: DockerHubRegistrationStatus,
        new_status: DockerHubRegistrationStatus,
        previous_registration_digest: Digest,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "dockerhub-registration-transition/v1",
            &[
                ("previous_status", format!("{previous_status:?}")),
                ("new_status", format!("{new_status:?}")),
                (
                    "previous_registration",
                    previous_registration_digest.as_str().to_owned(),
                ),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            previous_registration_digest,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerHubImageResultRegistration {
    service_id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: u64,
    registration_digest: Digest,
    status: DockerHubRegistrationStatus,
}

pub type DockerHubRegistration = DockerHubImageResultRegistration;

impl DockerHubImageResultRegistration {
    fn new(
        scope: &DockerHubImageResultScope,
        definition: &DockerHubProviderDefinition,
        secret_reference: &SecretReference,
    ) -> Result<Self> {
        scope.validate()?;
        definition.validate()?;
        secret_reference.validate_against(scope)?;
        let permission_snapshot = definition.permission_snapshot.clone();
        let mut registration = Self {
            service_id: SERVICE_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_parts(
                "dockerhub-plugin-version/v1",
                &[("version", PLUGIN_VERSION.to_owned())],
            ),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_text(crate::CONTRACT_DIGEST_INPUT),
            provider_id: PROVIDER_ID.to_owned(),
            provider_release: definition.release.clone(),
            provider_digest: definition.provider_digest.clone(),
            api_digest: definition.api_digest.clone(),
            permission_snapshot,
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision: 1,
            registration_digest: Digest::from_text("uninitialized"),
            status: DockerHubRegistrationStatus::Active,
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
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

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn status(&self) -> DockerHubRegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, DockerHubRegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.provider_id != PROVIDER_ID
            || self.provider_release.is_empty()
            || self.registration_revision == 0
        {
            return Err(DockerHubImageResultError::InvalidRegistration);
        }
        if self.contract_digest != Digest::from_text(crate::CONTRACT_DIGEST_INPUT)
            || self.version_digest
                != Digest::from_parts(
                    "dockerhub-plugin-version/v1",
                    &[("version", PLUGIN_VERSION.to_owned())],
                )
            || self.api_digest
                != Digest::from_parts(
                    "dockerhub-api-revision/v1",
                    &[("revision", API_REVISION.to_owned())],
                )
        {
            return Err(DockerHubImageResultError::ContractDrift);
        }
        self.permission_snapshot.validate()?;
        self.scope_digest.validate()?;
        self.secret_reference_digest.validate()?;
        self.provider_digest.validate()?;
        if self.registration_digest != self.calculate_digest() {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<DockerHubRegistrationTransition> {
        if matches!(self.status, DockerHubRegistrationStatus::Reversed) {
            return Err(DockerHubImageResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        let previous_digest = self.registration_digest.clone();
        self.status = DockerHubRegistrationStatus::Revoked;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(DockerHubRegistrationTransition::new(
            previous_status,
            self.status,
            previous_digest,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<DockerHubRegistrationTransition> {
        if matches!(self.status, DockerHubRegistrationStatus::Reversed) {
            return Err(DockerHubImageResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        let previous_digest = self.registration_digest.clone();
        self.status = DockerHubRegistrationStatus::Reversed;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(DockerHubRegistrationTransition::new(
            previous_status,
            self.status,
            previous_digest,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<DockerHubRegistrationTransition> {
        if matches!(self.status, DockerHubRegistrationStatus::Reversed) {
            return Err(DockerHubImageResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        let previous_digest = self.registration_digest.clone();
        self.status = DockerHubRegistrationStatus::Active;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(DockerHubRegistrationTransition::new(
            previous_status,
            self.status,
            previous_digest,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "dockerhub-image-result-registration/v1",
            &[
                ("service", self.service_id.clone()),
                ("plugin_version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl Serialize for DockerHubImageResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("DockerHubImageResultRegistration", 16)?;
        state.serialize_field("serviceId", &self.service_id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("status", &self.status)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub api_revision: &'static str,
    pub evidence_level: &'static str,
    pub operations: Vec<&'static str>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub forbidden_effects: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubFailureEvidence {
    pub operation: DockerHubOperation,
    pub status_code: Option<u16>,
    pub classification: String,
    pub error_digest: Digest,
    pub redacted: bool,
}

impl DockerHubFailureEvidence {
    fn from_transport(error: &DockerHubTransportError) -> Self {
        let classification = match error {
            DockerHubTransportError::BlockedEnv => "blocked_env",
            DockerHubTransportError::BadRequest => "bad_request",
            DockerHubTransportError::Unauthorized => "unauthorized",
            DockerHubTransportError::Forbidden => "forbidden",
            DockerHubTransportError::NotFound => "not_found",
            DockerHubTransportError::RateLimited => "rate_limited",
            DockerHubTransportError::ServerError { .. } => "server_error",
            DockerHubTransportError::Timeout => "timeout",
            DockerHubTransportError::AccessLost => "access_lost",
            DockerHubTransportError::Partial => "partial",
            DockerHubTransportError::Unknown => "unknown",
            DockerHubTransportError::InvalidResponse => "invalid_response",
            DockerHubTransportError::Tampered => "tampered",
            DockerHubTransportError::ScopeDrift => "scope_drift",
        };
        let error_digest = Digest::from_parts(
            "dockerhub-provider-error/v1",
            &[
                ("classification", classification.to_owned()),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |status| status.to_string()),
                ),
            ],
        );
        Self {
            operation: DockerHubOperation::ReadRepositoryTag,
            status_code: error.status_code(),
            classification: classification.to_owned(),
            error_digest,
            redacted: true,
        }
    }

    fn validate(&self) -> Result<()> {
        if !self.redacted || self.classification.is_empty() {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.error_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubImageResultEvidence {
    pub state: DockerHubEvidenceState,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub projection: Option<DockerHubImageResultProjection>,
    pub failure: Option<DockerHubFailureEvidence>,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub evidence_digest: Digest,
}

impl DockerHubImageResultEvidence {
    fn new(
        registration: &DockerHubImageResultRegistration,
        definition: &DockerHubProviderDefinition,
        request: &DockerHubImageResultRequest,
        state: DockerHubEvidenceState,
        projection: Option<DockerHubImageResultProjection>,
        failure: Option<DockerHubFailureEvidence>,
        request_receipt: RequestReceipt,
        cost_receipt: CostReceipt,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let evidence_digest = Self::calculate_digest(
            state,
            registration,
            definition,
            &request.digest(),
            projection.as_ref(),
            failure.as_ref(),
            &request_receipt,
            &cost_receipt,
            provenance,
        );
        let evidence = Self {
            state,
            request_digest: request.digest(),
            scope_digest: registration.scope_digest.clone(),
            plugin_version_digest: registration.version_digest.clone(),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: definition.provider_digest.clone(),
            api_digest: definition.api_digest.clone(),
            permission_digest: definition.permission_snapshot.digest().clone(),
            secret_reference_digest: registration.secret_reference_digest.clone(),
            projection,
            failure,
            request_receipt,
            cost_receipt,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            evidence_digest,
        };
        evidence.validate_integrity(registration, definition, request)?;
        Ok(evidence)
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn state(&self) -> DockerHubEvidenceState {
        self.state
    }

    pub fn validate_integrity(
        &self,
        registration: &DockerHubImageResultRegistration,
        definition: &DockerHubProviderDefinition,
        request: &DockerHubImageResultRequest,
    ) -> Result<()> {
        if self.request_digest != request.digest() {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.validate_static(registration, definition)
    }

    fn validate_static(
        &self,
        registration: &DockerHubImageResultRegistration,
        definition: &DockerHubProviderDefinition,
    ) -> Result<()> {
        if self.scope_digest != *registration.scope_digest()
            || self.plugin_version_digest != *registration.version_digest()
            || self.contract_digest != *registration.contract_digest()
            || self.provider_digest != *definition.provider_digest()
            || self.api_digest != *definition.api_digest()
            || self.permission_digest != *definition.permission_snapshot().digest()
            || self.secret_reference_digest != *registration.secret_reference_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
        {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.request_receipt.validate()?;
        self.cost_receipt.validate()?;
        if let Some(projection) = self.projection.as_ref() {
            projection.validate()?;
        }
        if let Some(failure) = self.failure.as_ref() {
            failure.validate()?;
        }
        if self.evidence_digest
            != Self::calculate_digest(
                self.state,
                registration,
                definition,
                &self.request_digest,
                self.projection.as_ref(),
                self.failure.as_ref(),
                &self.request_receipt,
                &self.cost_receipt,
                self.provenance,
            )
        {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(
        state: DockerHubEvidenceState,
        registration: &DockerHubImageResultRegistration,
        definition: &DockerHubProviderDefinition,
        request_digest: &Digest,
        projection: Option<&DockerHubImageResultProjection>,
        failure: Option<&DockerHubFailureEvidence>,
        request_receipt: &RequestReceipt,
        cost_receipt: &CostReceipt,
        provenance: TransportProvenance,
    ) -> Digest {
        Digest::from_parts(
            "dockerhub-image-result-evidence/v1",
            &[
                ("state", format!("{state:?}")),
                ("scope", registration.scope_digest.as_str().to_owned()),
                ("plugin", registration.version_digest.as_str().to_owned()),
                ("contract", registration.contract_digest.as_str().to_owned()),
                ("provider", definition.provider_digest.as_str().to_owned()),
                ("api", definition.api_digest.as_str().to_owned()),
                (
                    "permission",
                    definition.permission_snapshot.digest().as_str().to_owned(),
                ),
                (
                    "secret",
                    registration.secret_reference_digest.as_str().to_owned(),
                ),
                ("request", request_digest.as_str().to_owned()),
                (
                    "projection",
                    projection.map_or_else(String::new, |value| {
                        value.projection_digest.as_str().to_owned()
                    }),
                ),
                (
                    "failure",
                    failure
                        .map_or_else(String::new, |value| value.error_digest.as_str().to_owned()),
                ),
                (
                    "request_receipt",
                    request_receipt.request_digest.as_str().to_owned(),
                ),
                ("cost", cost_receipt.cost_digest.as_str().to_owned()),
                ("provenance", format!("{provenance:?}")),
                ("connected", "false".to_owned()),
                ("native", "false".to_owned()),
                ("first_party", "false".to_owned()),
                ("provider_receipt", "false".to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubImageResultProposal {
    pub evidence: DockerHubImageResultEvidence,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub proposal_digest: Digest,
}

impl DockerHubImageResultProposal {
    fn new(
        registration: &DockerHubImageResultRegistration,
        definition: &DockerHubProviderDefinition,
        evidence: DockerHubImageResultEvidence,
    ) -> Result<Self> {
        let mut proposal = Self {
            evidence,
            registration_digest: registration.registration_digest.clone(),
            provider_digest: definition.provider_digest.clone(),
            contract_digest: registration.contract_digest.clone(),
            permission_digest: definition.permission_snapshot.digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            provider_receipt: false,
            adopts_outcome: false,
            adopts_work_product: false,
            proposal_digest: Digest::from_text("uninitialized"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(
        &self,
        registration: &DockerHubImageResultRegistration,
        definition: &DockerHubProviderDefinition,
        request: &DockerHubImageResultRequest,
    ) -> Result<()> {
        if !self.proposal_only
            || self.native
            || self.connected
            || self.first_party
            || self.provider_receipt
            || self.adopts_outcome
            || self.adopts_work_product
            || self.registration_digest != *registration.registration_digest()
            || self.provider_digest != *definition.provider_digest()
            || self.contract_digest != *registration.contract_digest()
            || self.permission_digest != *definition.permission_snapshot().digest()
            || self.scope_digest != *registration.scope_digest()
            || self.evidence.evidence_digest != *self.evidence.digest()
        {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.evidence
            .validate_integrity(registration, definition, request)?;
        if self.proposal_digest != self.calculate_digest() {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_structure(
        &self,
        registration: &DockerHubImageResultRegistration,
        definition: &DockerHubProviderDefinition,
    ) -> Result<()> {
        if !self.proposal_only
            || self.native
            || self.connected
            || self.first_party
            || self.provider_receipt
            || self.adopts_outcome
            || self.adopts_work_product
            || self.registration_digest != *registration.registration_digest()
            || self.provider_digest != *definition.provider_digest()
            || self.contract_digest != *registration.contract_digest()
            || self.permission_digest != *definition.permission_snapshot().digest()
            || self.scope_digest != *registration.scope_digest()
        {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.evidence.validate_static(registration, definition)?;
        if self.proposal_digest != self.calculate_digest() {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "dockerhub-image-result-proposal/v1",
            &[
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("proposal_only", self.proposal_only.to_string()),
                ("native", self.native.to_string()),
                ("connected", self.connected.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("adopts_outcome", self.adopts_outcome.to_string()),
                ("adopts_work_product", self.adopts_work_product.to_string()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerHubVerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    SecretReferenceDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Throttled,
    TimedOut,
    ConfigDrift,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<DockerHubVerificationFailure>,
    pub verification_digest: Digest,
}

impl DockerHubVerificationReport {
    fn new(
        valid: bool,
        review_eligible: bool,
        mut failures: Vec<DockerHubVerificationFailure>,
    ) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = Digest::from_parts(
            "dockerhub-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct DockerHubImageResultService<T: DockerHubTransport> {
    provider: DockerHubProvider<T>,
    registration: DockerHubImageResultRegistration,
}

impl<T: DockerHubTransport> fmt::Debug for DockerHubImageResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerHubImageResultService")
            .field("scope_digest", &self.provider.scope().digest())
            .field("registration", &self.registration)
            .field("provenance", &self.provider.provenance())
            .finish()
    }
}

impl<T: DockerHubTransport> DockerHubImageResultService<T> {
    pub fn new(provider: DockerHubProvider<T>) -> Result<Self> {
        let registration = DockerHubImageResultRegistration::new(
            provider.scope(),
            provider.definition(),
            provider.secret_reference(),
        )?;
        Ok(Self {
            provider,
            registration,
        })
    }

    pub fn with_registration(
        provider: DockerHubProvider<T>,
        registration: DockerHubImageResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &provider.scope().digest()
            || registration.provider_digest() != provider.provider_digest()
            || registration.secret_reference_digest()
                != provider.secret_reference().reference_digest()
        {
            return Err(DockerHubImageResultError::ProviderDrift);
        }
        Ok(Self {
            provider,
            registration,
        })
    }

    pub fn scope(&self) -> &DockerHubImageResultScope {
        self.provider.scope()
    }

    pub fn registration(&self) -> &DockerHubImageResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut DockerHubImageResultRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &DockerHubProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut DockerHubProvider<T> {
        &mut self.provider
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            api_revision: API_REVISION,
            evidence_level: EVIDENCE_LEVEL,
            operations: vec![DockerHubOperation::ReadRepositoryTag.as_str()],
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            kernel_authority: false,
            outcome_adoption: false,
            forbidden_effects: vec![
                "login",
                "pull",
                "push",
                "delete",
                "tag",
                "build",
                "scan",
                "webhook_mutation",
                "download_layer",
                "execute_image",
            ],
        }
    }

    pub fn request(&self, observed_at: DateTime<Utc>) -> DockerHubImageResultRequest {
        DockerHubImageResultRequest::bound(
            self.scope(),
            observed_at,
            self.provider.provider_digest().clone(),
            self.registration.registration_digest().clone(),
        )
    }

    pub fn default_request(&self) -> DockerHubImageResultRequest {
        self.request(Utc::now())
    }

    pub fn revoke(&mut self) -> Result<DockerHubRegistrationTransition> {
        self.registration.revoke()
    }

    pub fn revoke_registration(&mut self) -> Result<DockerHubRegistrationTransition> {
        self.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<DockerHubRegistrationTransition> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<DockerHubRegistrationTransition> {
        self.registration.restore()
    }

    pub fn read(&mut self) -> Result<DockerHubImageResultEvidence> {
        Ok(self.compile_proposal()?.evidence)
    }

    pub fn compile_proposal(&mut self) -> Result<DockerHubImageResultProposal> {
        self.propose(self.default_request())
    }

    pub fn propose(
        &mut self,
        request: DockerHubImageResultRequest,
    ) -> Result<DockerHubImageResultProposal> {
        self.validate_request(&request)?;
        let tag_request = DockerHubTagRequest::new(self.scope(), request.max_response_bytes())?;
        let recorded_request = tag_request.recorded_request();
        let request_receipt = recorded_request.receipt()?;
        match self.provider.read_tag(&tag_request) {
            Ok(response) => {
                let cost_receipt = response.cost_receipt()?;
                if !response.is_success() {
                    let error = error_for_status(response.status_code());
                    let state = state_for_transport(&error);
                    let failure = DockerHubFailureEvidence::from_transport(&error);
                    let evidence = DockerHubImageResultEvidence::new(
                        &self.registration,
                        self.provider.definition(),
                        &request,
                        state,
                        None,
                        Some(failure),
                        request_receipt,
                        cost_receipt,
                        self.provider.provenance(),
                    )?;
                    return DockerHubImageResultProposal::new(
                        &self.registration,
                        self.provider.definition(),
                        evidence,
                    );
                }
                match response.projection(&tag_request) {
                    Ok(projection) => {
                        let evidence = DockerHubImageResultEvidence::new(
                            &self.registration,
                            self.provider.definition(),
                            &request,
                            DockerHubEvidenceState::Ready,
                            Some(projection),
                            None,
                            request_receipt,
                            cost_receipt,
                            self.provider.provenance(),
                        )?;
                        DockerHubImageResultProposal::new(
                            &self.registration,
                            self.provider.definition(),
                            evidence,
                        )
                    }
                    Err(error) => {
                        let transport_error = transport_error_for_model(&error);
                        let evidence = DockerHubImageResultEvidence::new(
                            &self.registration,
                            self.provider.definition(),
                            &request,
                            state_for_transport(&transport_error),
                            None,
                            Some(DockerHubFailureEvidence::from_transport(&transport_error)),
                            request_receipt,
                            cost_receipt,
                            self.provider.provenance(),
                        )?;
                        DockerHubImageResultProposal::new(
                            &self.registration,
                            self.provider.definition(),
                            evidence,
                        )
                    }
                }
            }
            Err(error) => {
                let cost_receipt =
                    CostReceipt::new(DockerHubOperation::ReadRepositoryTag.as_str(), 0)?;
                let state = state_for_transport(&error);
                let evidence = DockerHubImageResultEvidence::new(
                    &self.registration,
                    self.provider.definition(),
                    &request,
                    state,
                    None,
                    Some(DockerHubFailureEvidence::from_transport(&error)),
                    request_receipt,
                    cost_receipt,
                    self.provider.provenance(),
                )?;
                DockerHubImageResultProposal::new(
                    &self.registration,
                    self.provider.definition(),
                    evidence,
                )
            }
        }
    }

    pub fn verify(&self, proposal: &DockerHubImageResultProposal) -> DockerHubVerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(DockerHubVerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(DockerHubVerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.provider_digest != *self.provider.provider_digest() {
            failures.push(DockerHubVerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.api_digest != *self.provider.api_digest() {
            failures.push(DockerHubVerificationFailure::ApiDigestMismatch);
        }
        if proposal.permission_digest != *self.registration.permission_digest() {
            failures.push(DockerHubVerificationFailure::PermissionDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(DockerHubVerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.secret_reference_digest != *self.registration.secret_reference_digest()
        {
            failures.push(DockerHubVerificationFailure::SecretReferenceDigestMismatch);
        }
        if proposal
            .validate_structure(&self.registration, self.provider.definition())
            .is_err()
        {
            failures.push(DockerHubVerificationFailure::TamperedEvidence);
        }
        match proposal.evidence.state {
            DockerHubEvidenceState::Partial => {
                failures.push(DockerHubVerificationFailure::PartialEvidence);
            }
            DockerHubEvidenceState::AccessLoss => {
                failures.push(DockerHubVerificationFailure::AccessLoss);
            }
            DockerHubEvidenceState::Unauthorized => {
                failures.push(DockerHubVerificationFailure::Unauthorized);
            }
            DockerHubEvidenceState::Forbidden => {
                failures.push(DockerHubVerificationFailure::Forbidden);
            }
            DockerHubEvidenceState::NotFound => {
                failures.push(DockerHubVerificationFailure::NotFound);
            }
            DockerHubEvidenceState::Throttled => {
                failures.push(DockerHubVerificationFailure::Throttled);
            }
            DockerHubEvidenceState::TimedOut => {
                failures.push(DockerHubVerificationFailure::TimedOut);
            }
            DockerHubEvidenceState::ConfigDrift => {
                failures.push(DockerHubVerificationFailure::ConfigDrift);
            }
            DockerHubEvidenceState::Tampered => {
                failures.push(DockerHubVerificationFailure::TamperedEvidence);
            }
            DockerHubEvidenceState::ProviderUnknown
            | DockerHubEvidenceState::RegistrationRevoked => {
                failures.push(DockerHubVerificationFailure::ProviderUnknown);
            }
            DockerHubEvidenceState::Ready => {}
        }
        let valid = failures.is_empty();
        let review_eligible = valid
            && proposal.evidence.state.is_complete()
            && proposal.evidence.projection.is_some()
            && !proposal.evidence.connected
            && !proposal.evidence.native
            && !proposal.evidence.first_party
            && !proposal.evidence.provider_receipt;
        DockerHubVerificationReport::new(valid, review_eligible, failures)
    }

    pub fn verify_proposal(&self, proposal: &DockerHubImageResultProposal) -> Result<()> {
        proposal.validate_structure(&self.registration, self.provider.definition())
    }

    fn validate_request(&self, request: &DockerHubImageResultRequest) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(DockerHubImageResultError::RegistrationInactive);
        }
        if request.scope_digest() != self.registration.scope_digest()
            || request.expected_provider_digest() != self.provider.provider_digest()
            || request.expected_registration_digest() != self.registration.registration_digest()
        {
            return Err(DockerHubImageResultError::ScopeMismatch);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(DockerHubImageResultError::SecretRevoked);
        }
        request.validate()
    }
}

fn error_for_status(status: u16) -> DockerHubTransportError {
    match status {
        400 => DockerHubTransportError::BadRequest,
        401 => DockerHubTransportError::Unauthorized,
        403 => DockerHubTransportError::Forbidden,
        404 => DockerHubTransportError::NotFound,
        408 => DockerHubTransportError::Timeout,
        429 => DockerHubTransportError::RateLimited,
        500..=599 => DockerHubTransportError::ServerError { status },
        _ => DockerHubTransportError::Unknown,
    }
}

fn transport_error_for_model(error: &DockerHubImageResultError) -> DockerHubTransportError {
    match error {
        DockerHubImageResultError::PartialEvidence => DockerHubTransportError::Partial,
        DockerHubImageResultError::TamperedEvidence => DockerHubTransportError::Tampered,
        DockerHubImageResultError::ScopeMismatch
        | DockerHubImageResultError::ManifestDrift
        | DockerHubImageResultError::PlatformDrift => DockerHubTransportError::ScopeDrift,
        _ => DockerHubTransportError::InvalidResponse,
    }
}

fn state_for_transport(error: &DockerHubTransportError) -> DockerHubEvidenceState {
    match error {
        DockerHubTransportError::BlockedEnv
        | DockerHubTransportError::Unknown
        | DockerHubTransportError::InvalidResponse
        | DockerHubTransportError::ServerError { .. }
        | DockerHubTransportError::BadRequest => DockerHubEvidenceState::ProviderUnknown,
        DockerHubTransportError::Unauthorized => DockerHubEvidenceState::Unauthorized,
        DockerHubTransportError::Forbidden => DockerHubEvidenceState::Forbidden,
        DockerHubTransportError::NotFound => DockerHubEvidenceState::NotFound,
        DockerHubTransportError::RateLimited => DockerHubEvidenceState::Throttled,
        DockerHubTransportError::Timeout => DockerHubEvidenceState::TimedOut,
        DockerHubTransportError::AccessLost => DockerHubEvidenceState::AccessLoss,
        DockerHubTransportError::Partial => DockerHubEvidenceState::Partial,
        DockerHubTransportError::Tampered => DockerHubEvidenceState::Tampered,
        DockerHubTransportError::ScopeDrift => DockerHubEvidenceState::ConfigDrift,
    }
}
