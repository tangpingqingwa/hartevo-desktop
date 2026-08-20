use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsMarketplaceEntitlementConsumer;
use crate::error::{AwsMarketplaceEntitlementError, AwsMarketplaceTransportError, Result};
use crate::model::{
    AwsMarketplaceEntitlementScope, ConsentScope, Digest, EntitlementEvidenceState,
    EntitlementProjection, EvidenceDigests, ExpiryProjection, GetEntitlementsFilter,
    MissionProjection, PermissionSnapshot, ProjectProjection, SecretReference, TransportProvenance,
    WorkProductProjection, mission_projection, project_projection, work_product_projection,
};
use crate::provider::{
    AwsMarketplaceEntitlementProvider, AwsMarketplaceEntitlementProviderDefinition,
    GetEntitlementsRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID, contract_digest,
};

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
            "aws-marketplace-entitlement-registration-transition/v1",
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

/// Version/contract/provider/permission/consent/scope/secret-bound
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsMarketplaceEntitlementRegistration {
    id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsMarketplaceEntitlementScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsMarketplaceEntitlementRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsMarketplaceEntitlementScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsMarketplaceEntitlementProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id().to_owned(),
            provider_revision: provider.provider_revision(),
            provider_release: provider.release().to_owned(),
            provider_digest: provider.provider_digest().clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-aws-marketplace-entitlement-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
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

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
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

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsMarketplaceEntitlementScope {
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
        &self.binding_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub const fn is_reversible() -> bool {
        true
    }

    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest().as_str()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsMarketplaceEntitlementError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsMarketplaceEntitlementError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsMarketplaceEntitlementError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsMarketplaceEntitlementError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsMarketplaceEntitlementError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-entitlement-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type AwsMarketplaceRegistration = AwsMarketplaceEntitlementRegistration;

impl fmt::Debug for AwsMarketplaceEntitlementRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsMarketplaceEntitlementRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsMarketplaceEntitlementRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsMarketplaceEntitlementRegistration", 17)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
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
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEntitlementsEvidenceRequest {
    pub scope_digest: Digest,
    pub filter: GetEntitlementsFilter,
    pub observed_at: DateTime<Utc>,
    pub page_size: u8,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub request_digest: Digest,
}

impl GetEntitlementsEvidenceRequest {
    pub fn new(
        scope: &AwsMarketplaceEntitlementScope,
        observed_at: DateTime<Utc>,
        page_size: u8,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
    ) -> Result<Self> {
        if observed_at != scope.expiry().observed_at()
            || !(1..=crate::MAX_PAGE_SIZE).contains(&page_size)
        {
            return Err(AwsMarketplaceEntitlementError::InvalidRequest);
        }
        let filter = GetEntitlementsFilter::for_scope(scope)?;
        let mut request = Self {
            scope_digest: scope.digest(),
            filter,
            observed_at,
            page_size,
            expected_provider_digest,
            expected_registration_digest,
            request_digest: Digest::from_text("unsealed-aws-marketplace-evidence-request"),
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-get-entitlements-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter.digest().as_str().to_owned()),
                ("observed_at", self.observed_at.to_rfc3339()),
                ("page_size", self.page_size.to_string()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

pub type EntitlementEvidenceRequest = GetEntitlementsEvidenceRequest;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    BlockedEnv,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ServerError,
    Timeout,
    AccessLost,
    Partial,
    InvalidResponse,
    PaginationLoop,
    Tampered,
    RegistrationRevoked,
    RegistrationReversed,
    ConsentExpired,
    ConsentRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub code: FailureCode,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub detail_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(error: &AwsMarketplaceTransportError) -> Self {
        let code = match error {
            AwsMarketplaceTransportError::BlockedEnv => FailureCode::BlockedEnv,
            AwsMarketplaceTransportError::BadRequest => FailureCode::BadRequest,
            AwsMarketplaceTransportError::Unauthorized => FailureCode::Unauthorized,
            AwsMarketplaceTransportError::Forbidden => FailureCode::Forbidden,
            AwsMarketplaceTransportError::NotFound => FailureCode::NotFound,
            AwsMarketplaceTransportError::RateLimited { .. } => FailureCode::RateLimited,
            AwsMarketplaceTransportError::ServerError { .. } => FailureCode::ServerError,
            AwsMarketplaceTransportError::Timeout => FailureCode::Timeout,
            AwsMarketplaceTransportError::AccessLost => FailureCode::AccessLost,
            AwsMarketplaceTransportError::Partial => FailureCode::Partial,
            AwsMarketplaceTransportError::InvalidResponse => FailureCode::InvalidResponse,
            AwsMarketplaceTransportError::PaginationLoop => FailureCode::PaginationLoop,
        };
        Self {
            code,
            status_code: error.status_code(),
            retry_after_seconds: match error {
                AwsMarketplaceTransportError::RateLimited {
                    retry_after_seconds,
                } => *retry_after_seconds,
                _ => None,
            },
            detail_digest: Digest::from_parts(
                "aws-marketplace-transport-failure/v1",
                &[("error", format!("{error:?}"))],
            ),
        }
    }

    fn from_error(error: &AwsMarketplaceEntitlementError) -> Self {
        let (code, status_code) = match error {
            AwsMarketplaceEntitlementError::RegistrationRevoked => {
                (FailureCode::RegistrationRevoked, None)
            }
            AwsMarketplaceEntitlementError::RegistrationReversed => {
                (FailureCode::RegistrationReversed, None)
            }
            AwsMarketplaceEntitlementError::ConsentExpired => (FailureCode::ConsentExpired, None),
            AwsMarketplaceEntitlementError::ConsentRevoked => (FailureCode::ConsentRevoked, None),
            AwsMarketplaceEntitlementError::TamperedEvidence => (FailureCode::Tampered, None),
            _ => (FailureCode::InvalidResponse, None),
        };
        Self {
            code,
            status_code,
            retry_after_seconds: None,
            detail_digest: Digest::from_parts(
                "aws-marketplace-entitlement-failure/v1",
                &[("error", format!("{error:?}"))],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMarketplaceEntitlementRead {
    pub state: EntitlementEvidenceState,
    pub pages: u8,
    pub list_complete: bool,
    pub empty_page_fence: bool,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_digests: Vec<Digest>,
    pub entitlements: Vec<EntitlementProjection>,
    pub expiry_projection: ExpiryProjection,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMarketplaceEntitlementProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EntitlementEvidenceState,
    pub pages: u8,
    pub list_complete: bool,
    pub empty_page_fence: bool,
    pub entitlements: Vec<EntitlementProjection>,
    pub expiry_projection: ExpiryProjection,
    pub evidence: EvidenceDigests,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsMarketplaceEntitlementProposal {
    fn new(
        registration: &AwsMarketplaceEntitlementRegistration,
        provider: &AwsMarketplaceEntitlementProviderDefinition,
        request: &GetEntitlementsEvidenceRequest,
        read: AwsMarketplaceEntitlementRead,
    ) -> Self {
        let pages_digest = nonempty_digest(&read.page_digests);
        let expiry_digest = read.expiry_projection.digest();
        let evidence_digest = calculate_evidence_digest(
            registration,
            provider,
            request,
            &read,
            pages_digest.as_ref(),
            &expiry_digest,
        );
        let evidence = EvidenceDigests {
            registration_digest: registration.registration_digest().clone(),
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest().clone(),
            provider_digest: provider.provider_digest().clone(),
            api_digest: registration.api_digest().clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest().clone(),
            filter_digest: read.filter_digest.clone(),
            request_digest: read.request_digest.clone(),
            pages_digest,
            expiry_digest,
            evidence_digest,
        };
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: provider.provider_id().to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            filter_digest: read.filter_digest.clone(),
            request_digest: read.request_digest.clone(),
            mission: mission_projection(registration.scope().mission()),
            project: project_projection(registration.scope().project()),
            work_product: work_product_projection(registration.scope().work_product()),
            state: read.state,
            pages: read.pages,
            list_complete: read.list_complete,
            empty_page_fence: read.empty_page_fence,
            entitlements: read.entitlements,
            expiry_projection: read.expiry_projection,
            evidence,
            failure: read.failure,
            provenance: read.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-marketplace-entitlement-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
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
            || self.pages > crate::MAX_PAGES
            || self.evidence.registration_digest != self.registration_digest
            || self.evidence.scope_digest != self.scope_digest
            || self.evidence.filter_digest != self.filter_digest
            || self.evidence.request_digest != self.request_digest
            || self.evidence.evidence_digest != self.calculate_evidence_digest_from_self()
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(AwsMarketplaceEntitlementError::TamperedEvidence);
        }
        if self.state.is_complete()
            && (!self.list_complete
                || self.entitlements.is_empty()
                || !self.expiry_projection.is_fully_valid()
                || self.failure.is_some())
        {
            return Err(AwsMarketplaceEntitlementError::PartialEvidence);
        }
        for entitlement in &self.entitlements {
            entitlement.validate_integrity()?;
        }
        Ok(())
    }

    pub fn validate_for(&self, scope: &AwsMarketplaceEntitlementScope) -> Result<()> {
        self.validate_integrity()?;
        if self.scope_digest != scope.digest()
            || self.mission.id_digest != scope.mission().id_digest()
            || self.project.id_digest != scope.project().id_digest()
            || self.work_product.id_digest != scope.work_product().id_digest()
        {
            return Err(AwsMarketplaceEntitlementError::ScopeMismatch);
        }
        for entitlement in &self.entitlements {
            entitlement.validate_against(scope)?;
        }
        Ok(())
    }

    fn calculate_evidence_digest_from_self(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-entitlement-evidence/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "plugin_version",
                    self.evidence.plugin_version_digest.as_str().to_owned(),
                ),
                (
                    "contract",
                    self.evidence.contract_digest.as_str().to_owned(),
                ),
                (
                    "provider",
                    self.evidence.provider_digest.as_str().to_owned(),
                ),
                ("api", self.evidence.api_digest.as_str().to_owned()),
                (
                    "permission",
                    self.evidence.permission_digest.as_str().to_owned(),
                ),
                ("consent", self.evidence.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "pages",
                    self.evidence
                        .pages_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("expiry", self.evidence.expiry_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("page_count", self.pages.to_string()),
                ("complete", self.list_complete.to_string()),
                ("empty_page_fence", self.empty_page_fence.to_string()),
                (
                    "entitlements",
                    self.entitlements
                        .iter()
                        .map(EntitlementProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |failure| {
                        serde_json::to_string(failure).expect("failure serializes")
                    }),
                ),
            ],
        )
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-entitlement-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).expect("work product serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("pages", self.pages.to_string()),
                ("complete", self.list_complete.to_string()),
                ("empty_page_fence", self.empty_page_fence.to_string()),
                (
                    "entitlements",
                    serde_json::to_string(&self.entitlements).expect("entitlements serialize"),
                ),
                (
                    "expiry",
                    serde_json::to_string(&self.expiry_projection)
                        .expect("expiry projection serializes"),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failure",
                    serde_json::to_string(&self.failure).expect("failure serializes"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
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
}

pub type AwsMarketplaceEntitlementResult = AwsMarketplaceEntitlementProposal;

pub struct AwsMarketplaceEntitlementService<T: crate::provider::AwsMarketplaceEntitlementTransport>
{
    registration: AwsMarketplaceEntitlementRegistration,
    provider: AwsMarketplaceEntitlementProvider<T>,
}

impl<T: crate::provider::AwsMarketplaceEntitlementTransport> fmt::Debug
    for AwsMarketplaceEntitlementService<T>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsMarketplaceEntitlementService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsMarketplaceEntitlementTransport> AwsMarketplaceEntitlementService<T> {
    pub fn new(
        scope: AwsMarketplaceEntitlementScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsMarketplaceEntitlementProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-marketplace-entitlement-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsMarketplaceEntitlementScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsMarketplaceEntitlementProvider<T>,
        registration_revision: u64,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let _ = registration_time;
        let registration = AwsMarketplaceEntitlementRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec!["GetEntitlements".to_owned()],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsMarketplaceEntitlementScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsMarketplaceEntitlementRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsMarketplaceEntitlementRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsMarketplaceEntitlementProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsMarketplaceEntitlementProvider<T> {
        &mut self.provider
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<GetEntitlementsEvidenceRequest> {
        self.request(observed_at, crate::MAX_PAGE_SIZE)
    }

    pub fn request(
        &self,
        observed_at: DateTime<Utc>,
        page_size: u8,
    ) -> Result<GetEntitlementsEvidenceRequest> {
        GetEntitlementsEvidenceRequest::new(
            self.scope(),
            observed_at,
            page_size,
            self.provider.definition().provider_digest().clone(),
            self.registration.registration_digest().clone(),
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

    pub fn consumer(&self) -> Result<MissionAwsMarketplaceEntitlementConsumer> {
        MissionAwsMarketplaceEntitlementConsumer::new(
            self.scope().clone(),
            self.registration.clone(),
        )
    }

    #[allow(unused_assignments)]
    pub fn read(
        &mut self,
        request: &GetEntitlementsEvidenceRequest,
    ) -> Result<AwsMarketplaceEntitlementRead> {
        self.validate_request(request)?;
        let first_request = GetEntitlementsRequest::new(
            self.scope(),
            request.filter.clone(),
            request.page_size,
            1,
            None,
        )?;
        first_request.validate(self.scope())?;
        let mut current_request = first_request;
        let mut page_digests = Vec::new();
        let mut entitlements = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut pages = 0_u8;
        let mut state = None;
        let mut list_complete = false;
        let mut empty_page_fence = false;
        let mut failure = None;

        loop {
            if pages >= crate::MAX_PAGES {
                state = Some(EntitlementEvidenceState::PageLimitExceeded);
                failure = Some(FailureEvidence::from_error(
                    &AwsMarketplaceEntitlementError::PageLimitExceeded,
                ));
                break;
            }
            let response = match self.provider.get_entitlements(&current_request) {
                Ok(response) => response,
                Err(error) => {
                    state = Some(state_for_transport(&error));
                    failure = Some(FailureEvidence::from_transport(&error));
                    break;
                }
            };
            if response.validate_integrity(&current_request).is_err() {
                state = Some(EntitlementEvidenceState::Tampered);
                failure = Some(FailureEvidence::from_error(
                    &AwsMarketplaceEntitlementError::TamperedEvidence,
                ));
                break;
            }
            pages = pages.saturating_add(1);
            page_digests.push(response.response_digest().clone());
            if response.entitlements().is_empty() {
                if response.next_token().is_some() {
                    state = Some(EntitlementEvidenceState::EmptyPage);
                    empty_page_fence = true;
                    failure = Some(FailureEvidence::from_error(
                        &AwsMarketplaceEntitlementError::EmptyPage,
                    ));
                } else if entitlements.is_empty() {
                    state = Some(EntitlementEvidenceState::Empty);
                } else {
                    state = Some(EntitlementEvidenceState::Complete);
                    list_complete = true;
                }
                break;
            }
            let mut filter_failed = false;
            for entitlement in response.entitlements() {
                if entitlement.validate_against(self.scope()).is_err() {
                    filter_failed = true;
                    break;
                }
                entitlements.push(entitlement.clone());
            }
            if filter_failed {
                state = Some(EntitlementEvidenceState::FilterMismatch);
                failure = Some(FailureEvidence::from_error(
                    &AwsMarketplaceEntitlementError::FilterMismatch,
                ));
                break;
            }
            let expiry = ExpiryProjection::from_entitlements(self.scope().expiry(), &entitlements);
            if expiry.expired > 0 || expiry.outside_required_window > 0 {
                state = Some(EntitlementEvidenceState::Expired);
                failure = Some(FailureEvidence::from_error(
                    &AwsMarketplaceEntitlementError::ExpiredEntitlement,
                ));
                break;
            }
            let Some(next_token) = response.next_token().cloned() else {
                state = Some(EntitlementEvidenceState::Complete);
                list_complete = true;
                break;
            };
            let token_digest = next_token.digest().clone();
            if current_request
                .next_token()
                .is_some_and(|current| current.digest() == &token_digest)
                || !seen_tokens.insert(token_digest)
            {
                state = Some(EntitlementEvidenceState::PaginationLoop);
                failure = Some(FailureEvidence::from_error(
                    &AwsMarketplaceEntitlementError::PaginationLoop,
                ));
                break;
            }
            if pages >= crate::MAX_PAGES {
                state = Some(EntitlementEvidenceState::PageLimitExceeded);
                failure = Some(FailureEvidence::from_error(
                    &AwsMarketplaceEntitlementError::PageLimitExceeded,
                ));
                break;
            }
            current_request = current_request.next_page(self.scope(), next_token, pages + 1)?;
        }

        let expiry_projection =
            ExpiryProjection::from_entitlements(self.scope().expiry(), &entitlements);
        Ok(AwsMarketplaceEntitlementRead {
            state: state.unwrap_or(EntitlementEvidenceState::ProviderUnknown),
            pages,
            list_complete,
            empty_page_fence,
            filter_digest: request.filter.digest(),
            request_digest: request.request_digest.clone(),
            page_digests,
            entitlements,
            expiry_projection,
            failure,
            provenance: self.provider.provenance(),
        })
    }

    pub fn propose(
        &mut self,
        request: &GetEntitlementsEvidenceRequest,
    ) -> Result<AwsMarketplaceEntitlementProposal> {
        if let Err(error) = self.validate_request(request) {
            return Ok(self.blocked_proposal(request, error));
        }
        let read = self.read(request)?;
        Ok(AwsMarketplaceEntitlementProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            read,
        ))
    }

    pub fn verify(&self, proposal: &AwsMarketplaceEntitlementProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.provider.definition().provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.provenance.is_native()
            || proposal.provenance.is_connected()
            || proposal.provenance.is_first_party()
        {
            failures.push(VerificationFailure::NonNativeClaim);
        }
        if proposal.expiry_projection.expired > 0
            || proposal.expiry_projection.outside_required_window > 0
        {
            failures.push(VerificationFailure::ExpiredEntitlement);
        }
        if !proposal.state.is_complete() {
            failures.push(VerificationFailure::PartialEvidence);
        }
        VerificationReport::new(failures.is_empty(), failures.is_empty(), failures)
    }

    fn validate_request(&self, request: &GetEntitlementsEvidenceRequest) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return match self.registration.status() {
                RegistrationStatus::Revoked => {
                    Err(AwsMarketplaceEntitlementError::RegistrationRevoked)
                }
                RegistrationStatus::Reversed => {
                    Err(AwsMarketplaceEntitlementError::RegistrationReversed)
                }
                RegistrationStatus::Active => {
                    Err(AwsMarketplaceEntitlementError::RegistrationInactive)
                }
            };
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != *self.provider.definition().provider_digest()
            || request.expected_registration_digest != *self.registration.registration_digest()
            || request.filter.validate_against(self.scope()).is_err()
            || request.observed_at != self.scope().expiry().observed_at()
            || request.request_digest != request.calculate_digest()
        {
            return Err(AwsMarketplaceEntitlementError::ScopeMismatch);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsMarketplaceEntitlementError::SecretRevoked);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsMarketplaceEntitlementError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsMarketplaceEntitlementError::ConsentExpired);
        }
        Ok(())
    }

    fn blocked_proposal(
        &self,
        request: &GetEntitlementsEvidenceRequest,
        error: AwsMarketplaceEntitlementError,
    ) -> AwsMarketplaceEntitlementProposal {
        let state = match error {
            AwsMarketplaceEntitlementError::RegistrationRevoked => {
                EntitlementEvidenceState::RegistrationRevoked
            }
            AwsMarketplaceEntitlementError::RegistrationReversed => {
                EntitlementEvidenceState::RegistrationReversed
            }
            AwsMarketplaceEntitlementError::ConsentExpired => {
                EntitlementEvidenceState::ConsentExpired
            }
            AwsMarketplaceEntitlementError::ConsentRevoked => {
                EntitlementEvidenceState::ConsentRevoked
            }
            _ => EntitlementEvidenceState::ProviderUnknown,
        };
        let read = AwsMarketplaceEntitlementRead {
            state,
            pages: 0,
            list_complete: false,
            empty_page_fence: false,
            filter_digest: request.filter.digest(),
            request_digest: request.request_digest.clone(),
            page_digests: Vec::new(),
            entitlements: Vec::new(),
            expiry_projection: ExpiryProjection::from_entitlements(self.scope().expiry(), &[]),
            failure: Some(FailureEvidence::from_error(&error)),
            provenance: self.provider.provenance(),
        };
        AwsMarketplaceEntitlementProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            read,
        )
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn nonempty_digest(values: &[Digest]) -> Option<Digest> {
    (!values.is_empty()).then(|| {
        Digest::from_parts(
            "aws-marketplace-entitlement-pages/v1",
            &[(
                "pages",
                values
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    })
}

fn calculate_evidence_digest(
    registration: &AwsMarketplaceEntitlementRegistration,
    provider: &AwsMarketplaceEntitlementProviderDefinition,
    request: &GetEntitlementsEvidenceRequest,
    read: &AwsMarketplaceEntitlementRead,
    pages_digest: Option<&Digest>,
    expiry_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "aws-marketplace-entitlement-evidence/v1",
        &[
            (
                "registration",
                registration.registration_digest().as_str().to_owned(),
            ),
            (
                "plugin_version",
                Digest::from_text(PLUGIN_VERSION).as_str().to_owned(),
            ),
            (
                "contract",
                registration.contract_digest().as_str().to_owned(),
            ),
            ("provider", provider.provider_digest().as_str().to_owned()),
            ("api", registration.api_digest().as_str().to_owned()),
            (
                "permission",
                registration.permission_digest().as_str().to_owned(),
            ),
            ("consent", registration.consent_digest().as_str().to_owned()),
            ("scope", registration.scope_digest().as_str().to_owned()),
            ("filter", request.filter.digest().as_str().to_owned()),
            ("request", request.request_digest.as_str().to_owned()),
            (
                "pages",
                pages_digest.map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("expiry", expiry_digest.as_str().to_owned()),
            ("state", format!("{:?}", read.state)),
            ("page_count", read.pages.to_string()),
            ("complete", read.list_complete.to_string()),
            ("empty_page_fence", read.empty_page_fence.to_string()),
            (
                "entitlements",
                read.entitlements
                    .iter()
                    .map(EntitlementProjection::digest)
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            (
                "failure",
                read.failure.as_ref().map_or_else(String::new, |failure| {
                    serde_json::to_string(failure).expect("failure serializes")
                }),
            ),
        ],
    )
}

fn state_for_transport(error: &AwsMarketplaceTransportError) -> EntitlementEvidenceState {
    match error {
        AwsMarketplaceTransportError::Unauthorized
        | AwsMarketplaceTransportError::Forbidden
        | AwsMarketplaceTransportError::AccessLost => EntitlementEvidenceState::AccessLoss,
        AwsMarketplaceTransportError::RateLimited { .. } => EntitlementEvidenceState::Throttled,
        AwsMarketplaceTransportError::NotFound => EntitlementEvidenceState::NotFound,
        AwsMarketplaceTransportError::Partial => EntitlementEvidenceState::Partial,
        AwsMarketplaceTransportError::PaginationLoop => EntitlementEvidenceState::PaginationLoop,
        AwsMarketplaceTransportError::BlockedEnv
        | AwsMarketplaceTransportError::BadRequest
        | AwsMarketplaceTransportError::ServerError { .. }
        | AwsMarketplaceTransportError::Timeout
        | AwsMarketplaceTransportError::InvalidResponse => {
            EntitlementEvidenceState::ProviderUnknown
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    ExpiredEntitlement,
    NonNativeClaim,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "aws-marketplace-entitlement-verification-report/v1",
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
