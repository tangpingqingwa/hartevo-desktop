//! Typed Layer-1 service, proposal, verification, and registration seams.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsDataZoneSubscriptionResultConsumer;
use crate::error::{AwsDataZoneSubscriptionResultError, AwsDataZoneTransportError, Result};
use crate::model::{
    AssetMetadata, AwsDataZoneSubscriptionScope, DataZoneEvidenceState, Digest, EvidenceDigests,
    PermissionSnapshot, ProjectProjection, SecretReference, SubscriptionMetadata,
    SubscriptionRequestFilter, SubscriptionRequestMetadata, TransportProvenance,
    WorkProductProjection, mission_projection, project_projection, work_product_projection,
};
use crate::provider::{
    AwsDataZoneOperation, AwsDataZoneProvider, AwsDataZoneProviderDefinition, GetAssetRequest,
    GetSubscriptionRequest, GetSubscriptionRequestDetailsRequest, ListSubscriptionRequestsRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
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
            "aws-datazone-registration-transition/v1",
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
pub struct AwsDataZoneSubscriptionResultRegistration {
    id: String,
    plugin_version: String,
    plugin_version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: crate::model::ConsentScope,
    scope: AwsDataZoneSubscriptionScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsDataZoneSubscriptionResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsDataZoneSubscriptionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: crate::model::ConsentScope,
        provider: &AwsDataZoneProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
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
            binding_digest: Digest::from_text("unsealed-aws-datazone-registration"),
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

    pub fn plugin_version_digest(&self) -> &Digest {
        &self.plugin_version_digest
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

    pub fn consent(&self) -> &crate::model::ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsDataZoneSubscriptionScope {
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

    pub fn evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-registration-evidence/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
            ],
        )
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::InvalidRegistration);
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
            return Err(AwsDataZoneSubscriptionResultError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDataZoneSubscriptionResultError::RegistrationReversed);
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
            return Err(AwsDataZoneSubscriptionResultError::RegistrationReversed);
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
            return Err(AwsDataZoneSubscriptionResultError::RegistrationReversed);
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
            "aws-datazone-subscription-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                (
                    "plugin_version_digest",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("evidence", self.evidence_digest().as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type AwsDataZoneSubscriptionRegistration = AwsDataZoneSubscriptionResultRegistration;

impl fmt::Debug for AwsDataZoneSubscriptionResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDataZoneSubscriptionResultRegistration")
            .field("id", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("plugin_version_digest", &self.plugin_version_digest)
            .field("contract_version", &self.contract_version)
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
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsDataZoneSubscriptionResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state =
            serializer.serialize_struct("AwsDataZoneSubscriptionResultRegistration", 16)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("pluginVersionDigest", &self.plugin_version_digest)?;
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
        state.serialize_field("evidenceDigest", &self.evidence_digest())?;
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
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

pub type ServiceDefinition = CapabilityDescription;
pub type AwsDataZoneServiceDefinition = CapabilityDescription;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataZoneEvidenceRequest {
    pub scope_digest: Digest,
    pub filter: SubscriptionRequestFilter,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
}

impl DataZoneEvidenceRequest {
    pub fn new(
        scope: &AwsDataZoneSubscriptionScope,
        filter: SubscriptionRequestFilter,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        filter.validate_against(scope)?;
        if max_pages == 0 || max_pages > crate::MAX_PAGES {
            return Err(AwsDataZoneSubscriptionResultError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            filter,
            expected_provider_digest,
            expected_registration_digest,
            max_pages,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-subscription-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter.digest().as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("max_pages", self.max_pages.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsDataZoneOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsDataZoneOperation, error: &AwsDataZoneTransportError) -> Self {
        let category = match error {
            AwsDataZoneTransportError::BlockedEnv => "blocked_env",
            AwsDataZoneTransportError::BadRequest => "bad_request",
            AwsDataZoneTransportError::Unauthorized => "unauthorized",
            AwsDataZoneTransportError::Forbidden => "forbidden",
            AwsDataZoneTransportError::NotFound => "not_found",
            AwsDataZoneTransportError::Conflict => "conflict",
            AwsDataZoneTransportError::RateLimited { .. } => "throttled",
            AwsDataZoneTransportError::ServerError { .. } => "server_error",
            AwsDataZoneTransportError::Timeout => "timeout",
            AwsDataZoneTransportError::AccessLost => "access_loss",
            AwsDataZoneTransportError::Partial => "partial",
            AwsDataZoneTransportError::InvalidResponse => "invalid_response",
        }
        .to_owned();
        Self {
            operation,
            status_code: error.status_code(),
            failure_digest: Digest::from_parts(
                "aws-datazone-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.clone()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |status| status.to_string()),
                    ),
                ],
            ),
            category,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDataZoneSubscriptionResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub domain_digest: Digest,
    pub datazone_project_digest: Digest,
    pub asset_digest: Digest,
    pub listing_digest: Digest,
    pub subscription_request_digest: Digest,
    pub subscription_digest: Digest,
    pub subscription_grant_digest: Digest,
    pub revision_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: DataZoneEvidenceState,
    pub list_pages: u16,
    pub list_complete: bool,
    pub asset: Option<AssetMetadata>,
    pub subscription_request: Option<SubscriptionRequestMetadata>,
    pub subscription: Option<SubscriptionMetadata>,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub subscription_effect_claim: bool,
    pub data_access_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsDataZoneSubscriptionResultProposal {
    fn new(
        registration: &AwsDataZoneSubscriptionResultRegistration,
        provider: &AwsDataZoneProviderDefinition,
        request: &DataZoneEvidenceRequest,
        state: DataZoneEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        asset: Option<AssetMetadata>,
        subscription_request: Option<SubscriptionRequestMetadata>,
        subscription: Option<SubscriptionMetadata>,
        asset_evidence_digest: Option<Digest>,
        details_evidence_digest: Option<Digest>,
        subscription_evidence_digest: Option<Digest>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            filter_digest: request.filter.digest(),
            cursor_digest,
            list_digest,
            asset_digest: asset_evidence_digest,
            subscription_request_details_digest: details_evidence_digest,
            subscription_digest: subscription_evidence_digest,
            evidence_digest: Digest::from_text("unsealed-aws-datazone-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            list_pages,
            list_complete,
            asset.as_ref(),
            subscription_request.as_ref(),
            subscription.as_ref(),
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            account_digest: registration.scope.account().digest(),
            region_digest: registration.scope.region().digest(),
            domain_digest: registration.scope.domain().digest(),
            datazone_project_digest: registration.scope.datazone_project().digest(),
            asset_digest: registration.scope.asset().digest(),
            listing_digest: registration.scope.listing().digest(),
            subscription_request_digest: registration.scope.subscription_request().digest(),
            subscription_digest: registration.scope.subscription().digest(),
            subscription_grant_digest: registration.scope.subscription_grant().digest(),
            revision_digest: registration.scope.revision().digest(),
            mission: mission_projection(registration.scope.mission()),
            project: project_projection(registration.scope.project()),
            work_product: work_product_projection(registration.scope.work_product()),
            state,
            list_pages,
            list_complete,
            asset,
            subscription_request,
            subscription,
            failure,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            subscription_effect_claim: false,
            data_access_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-datazone-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.subscription_effect_claim
            || self.data_access_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provenance.is_native()
            || self.evidence.evidence_digest != self.calculate_evidence_digest()
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::TamperedEvidence);
        }
        self.evidence.plugin_version_digest.validate()?;
        self.evidence.contract_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.consent_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.filter_digest.validate()?;
        for digest in [
            self.evidence.cursor_digest.as_ref(),
            self.evidence.list_digest.as_ref(),
            self.evidence.asset_digest.as_ref(),
            self.evidence.subscription_request_details_digest.as_ref(),
            self.evidence.subscription_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        if let Some(asset) = &self.asset {
            asset.asset_digest.validate()?;
        }
        if let Some(request) = &self.subscription_request {
            request.request_digest.validate()?;
        }
        if let Some(subscription) = &self.subscription {
            subscription.subscription_digest.validate()?;
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_evidence_digest(&self) -> Digest {
        calculate_evidence_digest(
            &self.evidence,
            self.state,
            self.list_pages,
            self.list_complete,
            self.asset.as_ref(),
            self.subscription_request.as_ref(),
            self.subscription.as_ref(),
            self.failure.as_ref(),
        )
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-subscription-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "datazone_project",
                    self.datazone_project_digest.as_str().to_owned(),
                ),
                ("listing", self.listing_digest.as_str().to_owned()),
                (
                    "subscription_grant",
                    self.subscription_grant_digest.as_str().to_owned(),
                ),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                (
                    "asset",
                    self.asset
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "request",
                    self.subscription_request
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "subscription",
                    self.subscription
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure evidence serializes")
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

pub type AwsDataZoneSubscriptionProposal = AwsDataZoneSubscriptionResultProposal;
pub type AwsDataZoneSubscriptionResult = AwsDataZoneSubscriptionResultProposal;

pub struct AwsDataZoneSubscriptionResultService<T: crate::provider::AwsDataZoneTransport> {
    registration: AwsDataZoneSubscriptionResultRegistration,
    provider: AwsDataZoneProvider<T>,
}

impl<T: crate::provider::AwsDataZoneTransport> fmt::Debug
    for AwsDataZoneSubscriptionResultService<T>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDataZoneSubscriptionResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsDataZoneTransport> AwsDataZoneSubscriptionResultService<T> {
    pub fn new(
        scope: AwsDataZoneSubscriptionScope,
        secret_reference: SecretReference,
        consent: crate::model::ConsentScope,
        provider: AwsDataZoneProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-datazone-subscription-registration",
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
        scope: AwsDataZoneSubscriptionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: crate::model::ConsentScope,
        provider: AwsDataZoneProvider<T>,
        registration_revision: u64,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsDataZoneSubscriptionResultRegistration::new(
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
            operations: vec![
                AwsDataZoneOperation::GetAsset.as_str().to_owned(),
                AwsDataZoneOperation::GetSubscriptionRequestDetails
                    .as_str()
                    .to_owned(),
                AwsDataZoneOperation::GetSubscription.as_str().to_owned(),
                AwsDataZoneOperation::ListSubscriptionRequests
                    .as_str()
                    .to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
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

    pub fn scope(&self) -> &AwsDataZoneSubscriptionScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsDataZoneSubscriptionResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsDataZoneSubscriptionResultRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsDataZoneProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsDataZoneProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        filter: SubscriptionRequestFilter,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<DataZoneEvidenceRequest> {
        DataZoneEvidenceRequest::new(
            self.scope(),
            filter,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            max_pages,
            observed_at,
        )
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<DataZoneEvidenceRequest> {
        let filter = SubscriptionRequestFilter::for_scope(self.scope(), 50, None)?;
        self.request(filter, 1, observed_at)
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

    pub fn consumer(&self) -> Result<MissionAwsDataZoneSubscriptionResultConsumer> {
        MissionAwsDataZoneSubscriptionResultConsumer::new(
            self.scope().clone(),
            self.registration.clone(),
        )
    }

    pub fn verify(&self, proposal: &AwsDataZoneSubscriptionResultProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            DataZoneEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            DataZoneEvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            DataZoneEvidenceState::AccessLost => failures.push(VerificationFailure::AccessLoss),
            DataZoneEvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            DataZoneEvidenceState::Tampered => failures.push(VerificationFailure::TamperedEvidence),
            DataZoneEvidenceState::Drift => failures.push(VerificationFailure::EvidenceDrift),
            DataZoneEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            DataZoneEvidenceState::Pending
            | DataZoneEvidenceState::Accepted
            | DataZoneEvidenceState::Rejected
            | DataZoneEvidenceState::Expired
            | DataZoneEvidenceState::Ready
            | DataZoneEvidenceState::Revoked => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn propose(
        &mut self,
        request: DataZoneEvidenceRequest,
    ) -> Result<AwsDataZoneSubscriptionResultProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsDataZoneSubscriptionResultError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::ScopeMismatch);
        }
        request.filter.validate_against(self.scope())?;
        if self.registration.consent().is_revoked() {
            return Err(AwsDataZoneSubscriptionResultError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsDataZoneSubscriptionResultError::ConsentExpired);
        }

        let mut cursor: Option<crate::model::Cursor> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut list_digests = Vec::new();
        let mut target_from_list: Option<SubscriptionRequestMetadata> = None;
        let mut final_cursor_digest = None;
        loop {
            if list_pages >= request.max_pages {
                break;
            }
            let list_request = ListSubscriptionRequestsRequest::new(
                self.scope(),
                request.filter.clone(),
                cursor.clone(),
            )?;
            let response = match self.provider.list_subscription_requests(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_for_failure(
                        &request,
                        state_from_transport(&error),
                        list_pages,
                        false,
                        nonempty_digest(&list_digests),
                        final_cursor_digest,
                        None,
                        None,
                        None,
                        Some(FailureEvidence::from_transport(
                            AwsDataZoneOperation::ListSubscriptionRequests,
                            &error,
                        )),
                    ));
                }
            };
            list_pages = list_pages.saturating_add(1);
            list_digests.push(response.evidence_digest.clone());
            for item in &response.items {
                if item.request_digest == self.scope().subscription_request().digest() {
                    if let Some(previous) = &target_from_list {
                        if previous.digest() != item.digest() {
                            return Ok(self.proposal_for_failure(
                                &request,
                                DataZoneEvidenceState::Drift,
                                list_pages,
                                false,
                                nonempty_digest(&list_digests),
                                final_cursor_digest,
                                None,
                                None,
                                None,
                                Some(FailureEvidence {
                                    operation: AwsDataZoneOperation::ListSubscriptionRequests,
                                    status_code: None,
                                    category: "subscription_request_replaced".to_owned(),
                                    failure_digest: Digest::from_text(
                                        "aws-datazone-subscription-request-replaced",
                                    ),
                                }),
                            ));
                        }
                    }
                    target_from_list = Some(item.clone());
                }
            }
            if let Some(next_cursor) = response.next_cursor.clone() {
                let cursor_digest = next_cursor.token_digest().clone();
                if !seen_cursors.insert(cursor_digest.clone()) {
                    return Ok(self.proposal_for_failure(
                        &request,
                        DataZoneEvidenceState::Drift,
                        list_pages,
                        false,
                        nonempty_digest(&list_digests),
                        Some(cursor_digest),
                        None,
                        None,
                        None,
                        Some(FailureEvidence {
                            operation: AwsDataZoneOperation::ListSubscriptionRequests,
                            status_code: None,
                            category: "pagination_loop".to_owned(),
                            failure_digest: Digest::from_text(
                                "aws-datazone-subscription-pagination-loop",
                            ),
                        }),
                    ));
                }
                final_cursor_digest = Some(next_cursor.token_digest().clone());
                cursor = Some(next_cursor);
            } else {
                list_complete = true;
                break;
            }
        }

        let list_digest = nonempty_digest(&list_digests);
        if !list_complete {
            final_cursor_digest = cursor.as_ref().map(|value| value.token_digest().clone());
        }

        let asset_request = GetAssetRequest::for_scope(self.scope())?;
        let asset_response = match self.provider.get_asset(&asset_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    if list_complete {
                        state_from_transport(&error)
                    } else {
                        DataZoneEvidenceState::Partial
                    },
                    list_pages,
                    list_complete,
                    list_digest,
                    final_cursor_digest,
                    None,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsDataZoneOperation::GetAsset,
                        &error,
                    )),
                ));
            }
        };
        let asset_evidence_digest = Some(asset_response.evidence_digest.clone());
        let asset = asset_response.metadata;

        let details_request = GetSubscriptionRequestDetailsRequest::for_scope(self.scope())?;
        let details_response = match self
            .provider
            .get_subscription_request_details(&details_request)
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    if list_complete {
                        state_from_transport(&error)
                    } else {
                        DataZoneEvidenceState::Partial
                    },
                    list_pages,
                    list_complete,
                    list_digest,
                    final_cursor_digest,
                    Some(asset),
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsDataZoneOperation::GetSubscriptionRequestDetails,
                        &error,
                    )),
                ));
            }
        };
        let details_evidence_digest = Some(details_response.evidence_digest.clone());
        let details = details_response.metadata;

        let subscription_request = GetSubscriptionRequest::for_scope(self.scope())?;
        let subscription_response = match self.provider.get_subscription(&subscription_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    if list_complete {
                        state_from_transport(&error)
                    } else {
                        DataZoneEvidenceState::Partial
                    },
                    list_pages,
                    list_complete,
                    list_digest,
                    final_cursor_digest,
                    Some(asset),
                    Some(details),
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsDataZoneOperation::GetSubscription,
                        &error,
                    )),
                ));
            }
        };
        let subscription_evidence_digest = Some(subscription_response.evidence_digest.clone());
        let subscription = subscription_response.metadata;

        let drift = target_from_list
            .as_ref()
            .is_some_and(|listed| listed.digest() != details.digest())
            || details.asset_digest != asset.asset_digest
            || details
                .subscription_digest
                .as_ref()
                .is_some_and(|digest| *digest != subscription.subscription_digest)
            || subscription.request_digest != self.scope().subscription_request().digest();
        let (state, failure) = if !list_complete {
            (
                DataZoneEvidenceState::Partial,
                Some(FailureEvidence {
                    operation: AwsDataZoneOperation::ListSubscriptionRequests,
                    status_code: None,
                    category: "bounded_page_limit".to_owned(),
                    failure_digest: Digest::from_text("aws-datazone-bounded-page-limit"),
                }),
            )
        } else if target_from_list.is_none() {
            (
                DataZoneEvidenceState::NotFound,
                Some(FailureEvidence {
                    operation: AwsDataZoneOperation::ListSubscriptionRequests,
                    status_code: Some(404),
                    category: "subscription_request_not_found_in_complete_list".to_owned(),
                    failure_digest: Digest::from_text(
                        "aws-datazone-subscription-request-not-found-in-list",
                    ),
                }),
            )
        } else if drift {
            (
                DataZoneEvidenceState::Drift,
                Some(FailureEvidence {
                    operation: AwsDataZoneOperation::GetSubscriptionRequestDetails,
                    status_code: None,
                    category: "status_revision_reviewer_role_or_resource_drift".to_owned(),
                    failure_digest: Digest::from_text("aws-datazone-evidence-drift"),
                }),
            )
        } else {
            (
                state_from_metadata(&details, &subscription, request.observed_at),
                None,
            )
        };
        Ok(AwsDataZoneSubscriptionResultProposal::new(
            &self.registration,
            self.provider.definition(),
            &request,
            state,
            list_pages,
            list_complete,
            list_digest,
            final_cursor_digest,
            Some(asset),
            Some(details),
            Some(subscription),
            asset_evidence_digest,
            details_evidence_digest,
            subscription_evidence_digest,
            failure,
            self.provider.provenance(),
        ))
    }

    fn proposal_for_failure(
        &self,
        request: &DataZoneEvidenceRequest,
        state: DataZoneEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        asset: Option<AssetMetadata>,
        subscription_request: Option<SubscriptionRequestMetadata>,
        subscription: Option<SubscriptionMetadata>,
        failure: Option<FailureEvidence>,
    ) -> AwsDataZoneSubscriptionResultProposal {
        AwsDataZoneSubscriptionResultProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_pages,
            list_complete,
            list_digest,
            cursor_digest,
            asset,
            subscription_request,
            subscription,
            None,
            None,
            None,
            failure,
            self.provider.provenance(),
        )
    }
}

pub type AwsDataZoneSubscriptionService<T> = AwsDataZoneSubscriptionResultService<T>;
pub type AwsDataZoneService<T> = AwsDataZoneSubscriptionResultService<T>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    PartialEvidence,
    NotFound,
    AccessLoss,
    Throttled,
    TamperedEvidence,
    EvidenceDrift,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        Self {
            valid,
            review_eligible,
            failures,
        }
    }
}

fn valid_id(value: &str) -> bool {
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
            "aws-datazone-list-pages/v1",
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

fn state_from_transport(error: &AwsDataZoneTransportError) -> DataZoneEvidenceState {
    match error {
        AwsDataZoneTransportError::Unauthorized
        | AwsDataZoneTransportError::Forbidden
        | AwsDataZoneTransportError::AccessLost => DataZoneEvidenceState::AccessLost,
        AwsDataZoneTransportError::RateLimited { .. } => DataZoneEvidenceState::Throttled,
        AwsDataZoneTransportError::NotFound => DataZoneEvidenceState::NotFound,
        AwsDataZoneTransportError::Partial => DataZoneEvidenceState::Partial,
        AwsDataZoneTransportError::InvalidResponse => DataZoneEvidenceState::Tampered,
        AwsDataZoneTransportError::Conflict => DataZoneEvidenceState::Drift,
        AwsDataZoneTransportError::BlockedEnv
        | AwsDataZoneTransportError::BadRequest
        | AwsDataZoneTransportError::ServerError { .. }
        | AwsDataZoneTransportError::Timeout => DataZoneEvidenceState::ProviderUnknown,
    }
}

fn state_from_metadata(
    request: &SubscriptionRequestMetadata,
    subscription: &SubscriptionMetadata,
    observed_at: DateTime<Utc>,
) -> DataZoneEvidenceState {
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at <= observed_at)
    {
        return DataZoneEvidenceState::Expired;
    }
    if matches!(
        subscription.status,
        crate::model::SubscriptionStatus::Revoked | crate::model::SubscriptionStatus::Cancelled
    ) {
        return DataZoneEvidenceState::Revoked;
    }
    match request.status {
        crate::model::SubscriptionRequestStatus::Pending => DataZoneEvidenceState::Pending,
        crate::model::SubscriptionRequestStatus::Accepted => DataZoneEvidenceState::Accepted,
        crate::model::SubscriptionRequestStatus::Rejected => DataZoneEvidenceState::Rejected,
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: DataZoneEvidenceState,
    list_pages: u16,
    list_complete: bool,
    asset: Option<&AssetMetadata>,
    subscription_request: Option<&SubscriptionRequestMetadata>,
    subscription: Option<&SubscriptionMetadata>,
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "aws-datazone-subscription-evidence/v1",
        &[
            (
                "plugin_version",
                evidence.plugin_version_digest.as_str().to_owned(),
            ),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("filter", evidence.filter_digest.as_str().to_owned()),
            (
                "cursor",
                evidence
                    .cursor_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "list",
                evidence
                    .list_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "asset_evidence",
                evidence
                    .asset_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "details_evidence",
                evidence
                    .subscription_request_details_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "subscription_evidence",
                evidence
                    .subscription_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            (
                "asset",
                asset.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            (
                "subscription_request",
                subscription_request
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            (
                "subscription",
                subscription.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("failure evidence serializes")
                }),
            ),
        ],
    )
}
