use std::{collections::BTreeSet, fmt};

use serde::Serialize;

use crate::error::{GcpMemorystoreError, GcpMemorystoreTransportError, Result};
use crate::model::{
    CostReceipt, Digest, EvidenceDigests, EvidenceState, GcpMemorystoreScope, InstanceState,
    MissionProjection, ProjectProjection, ProposalDisposition, RedisInstanceProjection,
    RequestReceipt, SecretReference, TransportProvenance, WorkProductProjection, join_digests,
    mission_projection, project_projection, work_product_projection,
};
use crate::provider::{
    GcpMemorystoreAdminProvider, GcpMemorystoreOperation, GcpMemorystoreProviderDefinition,
    GcpMemorystoreTransport, GetInstanceRequest, ListInstancesRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST_INPUT, CONTRACT_SCHEMA, CONTRACT_VERSION,
    MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_revision: u64,
    pub transition_digest: Digest,
}
impl RegistrationTransitionEvidence {
    fn new(
        from: RegistrationStatus,
        to: RegistrationStatus,
        revision: u64,
        registration_digest: &Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "gcp-memorystore-registration-transition/v1",
            &[
                ("from", format!("{from:?}")),
                ("to", format!("{to:?}")),
                ("revision", revision.to_string()),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            from,
            to,
            registration_revision: revision,
            transition_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMemorystoreInstanceRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: u64,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub consent_digest: Digest,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub status: RegistrationStatus,
    pub transition_digest: Digest,
    #[serde(skip)]
    transition_from: RegistrationStatus,
}
pub type GcpMemorystoreRegistration = GcpMemorystoreInstanceRegistration;
impl GcpMemorystoreInstanceRegistration {
    pub(crate) fn new(
        scope: &GcpMemorystoreScope,
        secret: &SecretReference,
        provider: &GcpMemorystoreProviderDefinition,
    ) -> Result<Self> {
        scope.validate()?;
        provider.validate()?;
        if secret.scope_digest() != &scope.digest()
            || provider.permission_digest() != scope.permission_digest()
        {
            return Err(GcpMemorystoreError::PermissionDrift);
        }
        let contract_digest = Digest::from_text(CONTRACT_DIGEST_INPUT);
        let api_digest = scope.api_digest();
        let revision = 1;
        let registration_digest = registration_digest(
            scope,
            secret,
            provider,
            &contract_digest,
            &api_digest,
            revision,
        );
        let transition = RegistrationTransitionEvidence::new(
            RegistrationStatus::Reversed,
            RegistrationStatus::Active,
            revision,
            &registration_digest,
        );
        Ok(Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest.clone(),
            api_digest,
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            registration_revision: revision,
            registration_digest,
            status: RegistrationStatus::Active,
            transition_digest: transition.transition_digest,
            transition_from: RegistrationStatus::Reversed,
        })
    }
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }
    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }
    pub fn validate(&self) -> Result<()> {
        for digest in [
            Some(&self.contract_digest),
            Some(&self.provider_digest),
            Some(&self.api_digest),
            Some(&self.permission_digest),
            Some(&self.scope_digest),
            Some(&self.secret_reference_digest),
            Some(&self.consent_digest),
            Some(&self.registration_digest),
            Some(&self.transition_digest),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != Digest::from_text(CONTRACT_DIGEST_INPUT)
            || self.provider_id != PROVIDER_ID
            || self.provider_version.is_empty()
            || self.provider_revision == 0
            || self.api_digest.as_str()
                != Digest::from_parts(
                    "gcp-memorystore-api/v1",
                    &[("revision", API_REVISION.to_owned())],
                )
                .as_str()
            || self.registration_revision == 0
            || self.registration_digest != registration_digest_from_fields(self)
        {
            return Err(GcpMemorystoreError::InvalidRegistration);
        }
        let expected_transition = RegistrationTransitionEvidence::new(
            self.transition_from,
            self.status,
            self.registration_revision,
            &self.registration_digest,
        )
        .transition_digest;
        if self.transition_digest != expected_transition {
            Err(GcpMemorystoreError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(GcpMemorystoreError::RegistrationRevoked);
        }
        let from = self.status;
        self.status = RegistrationStatus::Revoked;
        self.transition_from = from;
        let evidence = RegistrationTransitionEvidence::new(
            from,
            self.status,
            self.registration_revision,
            &self.registration_digest,
        );
        self.transition_digest = evidence.transition_digest.clone();
        Ok(evidence)
    }
    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(GcpMemorystoreError::RegistrationRevoked);
        }
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(GcpMemorystoreError::RegistrationReversed);
        }
        let from = self.status;
        self.status = RegistrationStatus::Reversed;
        self.transition_from = from;
        let evidence = RegistrationTransitionEvidence::new(
            from,
            self.status,
            self.registration_revision,
            &self.registration_digest,
        );
        self.transition_digest = evidence.transition_digest.clone();
        Ok(evidence)
    }
    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(GcpMemorystoreError::RegistrationRevoked);
        }
        if !matches!(self.status, RegistrationStatus::Reversed) {
            return Err(GcpMemorystoreError::RegistrationInactive);
        }
        let from = self.status;
        self.status = RegistrationStatus::Active;
        self.transition_from = from;
        let evidence = RegistrationTransitionEvidence::new(
            from,
            self.status,
            self.registration_revision,
            &self.registration_digest,
        );
        self.transition_digest = evidence.transition_digest.clone();
        Ok(evidence)
    }
}
fn registration_digest(
    scope: &GcpMemorystoreScope,
    secret: &SecretReference,
    provider: &GcpMemorystoreProviderDefinition,
    contract: &Digest,
    api: &Digest,
    revision: u64,
) -> Digest {
    Digest::from_parts(
        "gcp-memorystore-registration/v1",
        &[
            (
                "plugin",
                Digest::from_text(PLUGIN_VERSION).as_str().to_owned(),
            ),
            ("contract_version", CONTRACT_VERSION.to_owned()),
            ("contract", contract.as_str().to_owned()),
            ("provider", provider.provider_digest().as_str().to_owned()),
            ("provider_id", provider.provider_id.clone()),
            ("provider_revision", provider.provider_revision.to_string()),
            ("api", api.as_str().to_owned()),
            ("permission", scope.permission_digest().as_str().to_owned()),
            ("scope", scope.digest().as_str().to_owned()),
            ("secret", secret.reference_digest().as_str().to_owned()),
            ("consent", scope.consent_digest().as_str().to_owned()),
            ("revision", revision.to_string()),
        ],
    )
}
fn registration_digest_from_fields(value: &GcpMemorystoreInstanceRegistration) -> Digest {
    Digest::from_parts(
        "gcp-memorystore-registration/v1",
        &[
            (
                "plugin",
                Digest::from_text(&value.plugin_version).as_str().to_owned(),
            ),
            ("contract_version", value.contract_version.clone()),
            ("contract", value.contract_digest.as_str().to_owned()),
            ("provider", value.provider_digest.as_str().to_owned()),
            ("provider_id", value.provider_id.clone()),
            ("provider_revision", value.provider_revision.to_string()),
            ("api", value.api_digest.as_str().to_owned()),
            ("permission", value.permission_digest.as_str().to_owned()),
            ("scope", value.scope_digest.as_str().to_owned()),
            ("secret", value.secret_reference_digest.as_str().to_owned()),
            ("consent", value.consent_digest.as_str().to_owned()),
            ("revision", value.registration_revision.to_string()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMemorystoreServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_external_io: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}
impl Default for GcpMemorystoreServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_digest: Digest::from_text(CONTRACT_DIGEST_INPUT),
            read_only: true,
            live_external_io: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMemorystoreEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub expected_api_digest: Digest,
    pub expected_permission_digest: Digest,
    pub page_size: u32,
    pub max_pages: u16,
    pub observed_at: u64,
    pub request_digest: Digest,
}
impl GcpMemorystoreEvidenceRequest {
    pub fn new(
        scope: &GcpMemorystoreScope,
        registration: &GcpMemorystoreInstanceRegistration,
        page_size: u32,
        max_pages: u16,
        observed_at: u64,
    ) -> Result<Self> {
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) || !(1..=MAX_PAGES).contains(&max_pages) {
            return Err(GcpMemorystoreError::InvalidRequest);
        }
        let value = Self {
            scope_digest: scope.digest(),
            expected_provider_digest: registration.provider_digest.clone(),
            expected_registration_digest: registration.registration_digest.clone(),
            expected_api_digest: scope.api_digest(),
            expected_permission_digest: scope.permission_digest().clone(),
            page_size,
            max_pages,
            observed_at,
            request_digest: Digest::from_text("uncomputed-gcp-memorystore-request"),
        };
        let request_digest = Digest::from_parts(
            "gcp-memorystore-evidence-request/v1",
            &[
                ("scope", value.scope_digest.as_str().to_owned()),
                (
                    "provider",
                    value.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    value.expected_registration_digest.as_str().to_owned(),
                ),
                ("api", value.expected_api_digest.as_str().to_owned()),
                (
                    "permission",
                    value.expected_permission_digest.as_str().to_owned(),
                ),
                ("page_size", page_size.to_string()),
                ("max_pages", max_pages.to_string()),
                ("observed_at", observed_at.to_string()),
            ],
        );
        Ok(Self {
            request_digest,
            ..value
        })
    }
    pub fn for_scope(
        scope: &GcpMemorystoreScope,
        registration: &GcpMemorystoreInstanceRegistration,
    ) -> Result<Self> {
        Self::new(scope, registration, MAX_PAGE_SIZE, MAX_PAGES, 1)
    }
    fn validate(
        &self,
        scope: &GcpMemorystoreScope,
        registration: &GcpMemorystoreInstanceRegistration,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.expected_provider_digest != *registration.provider_digest()
            || self.expected_registration_digest != *registration.registration_digest()
            || self.expected_api_digest != scope.api_digest()
            || self.expected_permission_digest != *scope.permission_digest()
            || !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || self.request_digest
                != Digest::from_parts(
                    "gcp-memorystore-evidence-request/v1",
                    &[
                        ("scope", self.scope_digest.as_str().to_owned()),
                        (
                            "provider",
                            self.expected_provider_digest.as_str().to_owned(),
                        ),
                        (
                            "registration",
                            self.expected_registration_digest.as_str().to_owned(),
                        ),
                        ("api", self.expected_api_digest.as_str().to_owned()),
                        (
                            "permission",
                            self.expected_permission_digest.as_str().to_owned(),
                        ),
                        ("page_size", self.page_size.to_string()),
                        ("max_pages", self.max_pages.to_string()),
                        ("observed_at", self.observed_at.to_string()),
                    ],
                )
        {
            Err(GcpMemorystoreError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: GcpMemorystoreOperation,
    pub error_digest: Digest,
    pub status_code: Option<u16>,
}
impl FailureEvidence {
    fn new(operation: GcpMemorystoreOperation, error: &GcpMemorystoreTransportError) -> Self {
        Self {
            operation,
            error_digest: Digest::from_text(format!("{error:?}")),
            status_code: error.status_code(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMemorystoreInstanceProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub request_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub list_pages: u16,
    pub list_complete: bool,
    pub list_digest: Option<Digest>,
    pub get_digest: Option<Digest>,
    pub projection: Option<RedisInstanceProjection>,
    pub evidence: EvidenceDigests,
    pub failure: Option<FailureEvidence>,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
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
impl GcpMemorystoreInstanceProposal {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        for receipt in &self.request_receipts {
            receipt.validate()?;
        }
        for receipt in &self.cost_receipts {
            receipt.validate()?;
        }
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != proposal_digest(self)
        {
            return Err(GcpMemorystoreError::TamperedEvidence);
        }
        if let Some(projection) = &self.projection {
            projection.validate()?;
            if self.evidence.projection_digest.as_ref() != Some(&projection.projection_digest) {
                return Err(GcpMemorystoreError::TamperedEvidence);
            }
        }
        Ok(())
    }
}
fn proposal_digest(value: &GcpMemorystoreInstanceProposal) -> Digest {
    Digest::from_parts(
        "gcp-memorystore-instance-proposal/v1",
        &[
            ("request", value.request_digest.as_str().to_owned()),
            (
                "registration",
                value.registration_digest.as_str().to_owned(),
            ),
            ("provider", value.provider_digest.as_str().to_owned()),
            ("api", value.api_digest.as_str().to_owned()),
            ("permission", value.permission_digest.as_str().to_owned()),
            ("scope", value.scope_digest.as_str().to_owned()),
            ("state", format!("{:?}", value.state)),
            ("list_pages", value.list_pages.to_string()),
            ("list_complete", value.list_complete.to_string()),
            (
                "list",
                value
                    .list_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "get",
                value
                    .get_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "projection",
                value.projection.as_ref().map_or_else(String::new, |value| {
                    value.projection_digest.as_str().to_owned()
                }),
            ),
            (
                "evidence",
                value.evidence.evidence_digest.as_str().to_owned(),
            ),
            (
                "failure",
                value
                    .failure
                    .as_ref()
                    .map_or_else(String::new, |value| value.error_digest.as_str().to_owned()),
            ),
        ],
    )
}

pub struct GcpMemorystoreInstanceResultService<T: GcpMemorystoreTransport> {
    scope: GcpMemorystoreScope,
    secret_reference: SecretReference,
    provider: GcpMemorystoreAdminProvider<T>,
    service_definition: GcpMemorystoreServiceDefinition,
    registration: GcpMemorystoreInstanceRegistration,
}
impl<T: GcpMemorystoreTransport> fmt::Debug for GcpMemorystoreInstanceResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpMemorystoreInstanceResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}
impl<T: GcpMemorystoreTransport> GcpMemorystoreInstanceResultService<T> {
    pub fn new(
        scope: GcpMemorystoreScope,
        secret_reference: SecretReference,
        provider: GcpMemorystoreAdminProvider<T>,
    ) -> Result<Self> {
        scope.validate()?;
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(GcpMemorystoreError::ScopeMismatch);
        }
        provider.definition().validate()?;
        if provider.definition().permission_digest() != scope.permission_digest() {
            return Err(GcpMemorystoreError::PermissionDrift);
        }
        let registration = GcpMemorystoreInstanceRegistration::new(
            &scope,
            &secret_reference,
            provider.definition(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition: GcpMemorystoreServiceDefinition::default(),
            registration,
        })
    }
    pub fn service_definition(&self) -> &GcpMemorystoreServiceDefinition {
        &self.service_definition
    }
    pub fn provider_definition(&self) -> &GcpMemorystoreProviderDefinition {
        self.provider.definition()
    }
    pub fn registration(&self) -> &GcpMemorystoreInstanceRegistration {
        &self.registration
    }
    pub fn scope(&self) -> &GcpMemorystoreScope {
        &self.scope
    }
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }
    pub fn provider(&self) -> &GcpMemorystoreAdminProvider<T> {
        &self.provider
    }
    pub fn provider_mut(&mut self) -> &mut GcpMemorystoreAdminProvider<T> {
        &mut self.provider
    }
    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }
    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }
    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }
    pub fn revoke_secret(&mut self) -> Result<()> {
        self.secret_reference.revoke()
    }
    pub fn propose(
        &mut self,
        request: GcpMemorystoreEvidenceRequest,
    ) -> Result<GcpMemorystoreInstanceProposal> {
        self.registration.validate()?;
        request.validate(&self.scope, &self.registration)?;
        if !self.registration.is_active() {
            return Err(GcpMemorystoreError::RegistrationInactive);
        }
        if self.secret_reference.is_revoked() {
            return Err(GcpMemorystoreError::SecretRevoked);
        }
        if self.scope.consent().is_revoked() {
            return Err(GcpMemorystoreError::ConsentRevoked);
        }
        if !self.scope.consent().is_active_at(request.observed_at) {
            return Err(GcpMemorystoreError::ConsentExpired);
        }
        let mut list_request = ListInstancesRequest::first(&self.scope, request.page_size)?;
        let mut seen = BTreeSet::new();
        let mut list_digests = Vec::new();
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();
        let mut target = None;
        let mut pages;
        let complete;
        loop {
            pages = list_request.page_number();
            let response = match self.provider.list_instances(&list_request) {
                Ok(value) => value,
                Err(error) => {
                    request_receipts.push(list_request.recorded_request().receipt());
                    cost_receipts.push(CostReceipt::new(
                        GcpMemorystoreOperation::InstancesList.as_str(),
                        0,
                    )?);
                    return Ok(self.failed(
                        &request,
                        state_for_transport(&error),
                        pages,
                        false,
                        digest_pages(&list_digests),
                        None,
                        None,
                        Some(FailureEvidence::new(
                            GcpMemorystoreOperation::InstancesList,
                            &error,
                        )),
                        request_receipts,
                        cost_receipts,
                    ));
                }
            };
            request_receipts.push(response.request_receipt.clone());
            cost_receipts.push(response.cost_receipt.clone());
            list_digests.push(response.evidence_digest.clone());
            if !response.unreachable.is_empty() {
                return Ok(self.failed(
                    &request,
                    EvidenceState::UnreachableLocation,
                    pages,
                    false,
                    digest_pages(&list_digests),
                    None,
                    None,
                    Some(FailureEvidence {
                        operation: GcpMemorystoreOperation::InstancesList,
                        error_digest: Digest::from_text("unreachable-location"),
                        status_code: None,
                    }),
                    request_receipts,
                    cost_receipts,
                ));
            }
            for summary in &response.instances {
                let prefix = format!(
                    "projects/{}/locations/{}/instances/",
                    self.scope.gcp_project().as_str(),
                    self.scope.location().as_str()
                );
                if !summary.resource_name().starts_with(&prefix) {
                    return Ok(self.failed(
                        &request,
                        EvidenceState::ScopeDrift,
                        pages,
                        false,
                        digest_pages(&list_digests),
                        None,
                        None,
                        None,
                        request_receipts,
                        cost_receipts,
                    ));
                }
                if summary.resource_name() == self.scope.raw_resource_name() {
                    if target.is_some() {
                        return Ok(self.failed(
                            &request,
                            EvidenceState::ScopeDrift,
                            pages,
                            false,
                            digest_pages(&list_digests),
                            None,
                            None,
                            None,
                            request_receipts,
                            cost_receipts,
                        ));
                    }
                    target = Some(summary.clone());
                }
            }
            if let Some(token) = response.next_page_token {
                let token_digest = token.digest();
                if !seen.insert(token_digest) {
                    return Ok(self.failed(
                        &request,
                        EvidenceState::PaginationLoop,
                        pages,
                        false,
                        digest_pages(&list_digests),
                        None,
                        None,
                        Some(FailureEvidence {
                            operation: GcpMemorystoreOperation::InstancesList,
                            error_digest: Digest::from_text("pagination-loop"),
                            status_code: None,
                        }),
                        request_receipts,
                        cost_receipts,
                    ));
                }
                if pages >= request.max_pages {
                    return Ok(self.failed(
                        &request,
                        EvidenceState::Truncated,
                        pages,
                        false,
                        digest_pages(&list_digests),
                        None,
                        None,
                        Some(FailureEvidence {
                            operation: GcpMemorystoreOperation::InstancesList,
                            error_digest: Digest::from_text("page-cap"),
                            status_code: None,
                        }),
                        request_receipts,
                        cost_receipts,
                    ));
                }
                list_request = ListInstancesRequest::new(
                    &self.scope,
                    request.page_size,
                    pages.saturating_add(1),
                    Some(token),
                )?;
            } else {
                complete = true;
                break;
            }
        }
        let list_digest = digest_pages(&list_digests);
        let Some(summary) = target else {
            return Ok(self.failed(
                &request,
                EvidenceState::NotFound,
                pages,
                complete,
                list_digest,
                None,
                None,
                None,
                request_receipts,
                cost_receipts,
            ));
        };
        let get_request = GetInstanceRequest::new(&self.scope)?;
        let get_response = match self.provider.get_instance(&get_request) {
            Ok(value) => value,
            Err(error) => {
                request_receipts.push(get_request.recorded_request().receipt());
                cost_receipts.push(CostReceipt::new(
                    GcpMemorystoreOperation::InstancesGet.as_str(),
                    0,
                )?);
                return Ok(self.failed(
                    &request,
                    state_for_transport(&error),
                    pages,
                    complete,
                    list_digest,
                    None,
                    None,
                    Some(FailureEvidence::new(
                        GcpMemorystoreOperation::InstancesGet,
                        &error,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        request_receipts.push(get_response.request_receipt.clone());
        cost_receipts.push(get_response.cost_receipt.clone());
        let get_digest = Some(get_response.evidence_digest.clone());
        let projection = match get_response.projection(&self.scope) {
            Ok(value) => value,
            Err(error) => {
                return Ok(self.failed(
                    &request,
                    state_for_error(&error),
                    pages,
                    complete,
                    list_digest,
                    get_digest,
                    None,
                    None,
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        if summary.state() != projection.state {
            return Ok(self.failed(
                &request,
                EvidenceState::Stale,
                pages,
                complete,
                list_digest,
                get_digest,
                Some(projection.projection_digest.clone()),
                Some(FailureEvidence {
                    operation: GcpMemorystoreOperation::InstancesGet,
                    error_digest: Digest::from_text("list-get-state-drift"),
                    status_code: None,
                }),
                request_receipts,
                cost_receipts,
            ));
        }
        let state = if projection.state == InstanceState::Unknown
            || projection.state == InstanceState::Error
        {
            EvidenceState::ProviderUnknown
        } else if projection.state.is_stable() {
            EvidenceState::Ready
        } else {
            EvidenceState::Stale
        };
        Ok(self.finish(
            &request,
            state,
            pages,
            complete,
            list_digest,
            get_digest,
            Some(projection),
            None,
            request_receipts,
            cost_receipts,
        ))
    }
    fn failed(
        &self,
        request: &GcpMemorystoreEvidenceRequest,
        state: EvidenceState,
        pages: u16,
        complete: bool,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        projection_digest: Option<Digest>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> GcpMemorystoreInstanceProposal {
        self.finish_with_projection(
            request,
            state,
            pages,
            complete,
            list_digest,
            get_digest,
            None,
            projection_digest,
            failure,
            request_receipts,
            cost_receipts,
        )
    }
    fn finish(
        &self,
        request: &GcpMemorystoreEvidenceRequest,
        state: EvidenceState,
        pages: u16,
        complete: bool,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        projection: Option<RedisInstanceProjection>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> GcpMemorystoreInstanceProposal {
        let projection_digest = projection
            .as_ref()
            .map(|value| value.projection_digest.clone());
        self.finish_with_projection(
            request,
            state,
            pages,
            complete,
            list_digest,
            get_digest,
            projection,
            projection_digest,
            failure,
            request_receipts,
            cost_receipts,
        )
    }
    fn finish_with_projection(
        &self,
        request: &GcpMemorystoreEvidenceRequest,
        state: EvidenceState,
        pages: u16,
        complete: bool,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        projection: Option<RedisInstanceProjection>,
        projection_digest: Option<Digest>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> GcpMemorystoreInstanceProposal {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::from_text(CONTRACT_DIGEST_INPUT),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: self.scope.api_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            scope_digest: self.scope.digest(),
            secret_reference_digest: self.secret_reference.reference_digest().clone(),
            list_digest: list_digest.clone(),
            get_digest: get_digest.clone(),
            projection_digest: projection_digest.clone(),
            evidence_digest: Digest::from_text("uncomputed-evidence"),
        };
        evidence.evidence_digest = evidence.compute_evidence_digest();
        let mut proposal = GcpMemorystoreInstanceProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            request_digest: request.request_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: self.scope.api_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            scope_digest: self.scope.digest(),
            mission: mission_projection(self.scope.mission()),
            project: project_projection(self.scope.project()),
            work_product: work_product_projection(self.scope.work_product()),
            state,
            disposition: state.into(),
            list_pages: pages,
            list_complete: complete,
            list_digest,
            get_digest,
            projection,
            evidence,
            failure,
            request_receipts,
            cost_receipts,
            provenance: self.provider.provenance(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("uncomputed-proposal"),
        };
        proposal.proposal_digest = proposal_digest(&proposal);
        proposal
    }
    pub fn verify(&self, proposal: &GcpMemorystoreInstanceProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if self.registration.validate().is_err() || !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        if proposal.registration_digest != self.registration.registration_digest {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.api_digest != self.scope.api_digest() {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.permission_digest != *self.scope.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.scope_digest != self.scope.digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        match proposal.state {
            EvidenceState::Ready => {}
            EvidenceState::Stale => failures.push(VerificationFailure::StaleState),
            EvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            EvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            EvidenceState::Unauthorized => failures.push(VerificationFailure::Unauthorized),
            EvidenceState::Forbidden => failures.push(VerificationFailure::Forbidden),
            EvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            EvidenceState::Conflict => failures.push(VerificationFailure::Conflict),
            EvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            EvidenceState::TimedOut => failures.push(VerificationFailure::TimedOut),
            EvidenceState::UnreachableLocation => {
                failures.push(VerificationFailure::UnreachableLocation);
            }
            EvidenceState::ScopeDrift => failures.push(VerificationFailure::ScopeDrift),
            EvidenceState::ApiDrift => failures.push(VerificationFailure::ApiDrift),
            EvidenceState::PaginationLoop => failures.push(VerificationFailure::PaginationLoop),
            EvidenceState::Truncated => failures.push(VerificationFailure::TruncatedEvidence),
            EvidenceState::Tampered => failures.push(VerificationFailure::TamperedEvidence),
            EvidenceState::ProviderUnknown => failures.push(VerificationFailure::ProviderUnknown),
            EvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            EvidenceState::ReplayDetected => failures.push(VerificationFailure::ReplayDetected),
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        let review_eligible = valid
            && proposal.list_complete
            && proposal.projection.is_some()
            && proposal.state.is_review_complete()
            && !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt;
        VerificationReport::new(valid, review_eligible, failures)
    }
}
pub type GcpMemorystoreService<T> = GcpMemorystoreInstanceResultService<T>;

fn digest_pages(values: &[Digest]) -> Option<Digest> {
    (!values.is_empty()).then(|| {
        Digest::from_parts(
            "gcp-memorystore-pages/v1",
            &[("pages", join_digests(values.iter().cloned()))],
        )
    })
}
fn state_for_transport(error: &GcpMemorystoreTransportError) -> EvidenceState {
    match error {
        GcpMemorystoreTransportError::Unauthorized => EvidenceState::Unauthorized,
        GcpMemorystoreTransportError::Forbidden => EvidenceState::Forbidden,
        GcpMemorystoreTransportError::NotFound => EvidenceState::NotFound,
        GcpMemorystoreTransportError::Conflict => EvidenceState::Conflict,
        GcpMemorystoreTransportError::RateLimited { .. } => EvidenceState::Throttled,
        GcpMemorystoreTransportError::Timeout => EvidenceState::TimedOut,
        GcpMemorystoreTransportError::AccessLost => EvidenceState::AccessLoss,
        GcpMemorystoreTransportError::Partial => EvidenceState::Partial,
        GcpMemorystoreTransportError::UnreachableLocation => EvidenceState::UnreachableLocation,
        GcpMemorystoreTransportError::ApiDrift => EvidenceState::ApiDrift,
        GcpMemorystoreTransportError::Truncated => EvidenceState::Truncated,
        GcpMemorystoreTransportError::PaginationLoop => EvidenceState::PaginationLoop,
        GcpMemorystoreTransportError::Tampered => EvidenceState::Tampered,
        GcpMemorystoreTransportError::BlockedEnv
        | GcpMemorystoreTransportError::BadRequest
        | GcpMemorystoreTransportError::ServerError { .. }
        | GcpMemorystoreTransportError::Unknown
        | GcpMemorystoreTransportError::InvalidResponse => EvidenceState::ProviderUnknown,
    }
}
fn state_for_error(error: &GcpMemorystoreError) -> EvidenceState {
    match error {
        GcpMemorystoreError::ScopeDrift | GcpMemorystoreError::ScopeMismatch => {
            EvidenceState::ScopeDrift
        }
        GcpMemorystoreError::StaleState => EvidenceState::Stale,
        GcpMemorystoreError::TamperedEvidence => EvidenceState::Tampered,
        GcpMemorystoreError::TruncatedEvidence => EvidenceState::Truncated,
        GcpMemorystoreError::ApiDrift => EvidenceState::ApiDrift,
        _ => EvidenceState::ProviderUnknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    StaleState,
    PartialEvidence,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    UnreachableLocation,
    ScopeDrift,
    ApiDrift,
    PaginationLoop,
    TruncatedEvidence,
    ProviderUnknown,
    ReplayDetected,
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
            "gcp-memorystore-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|value| format!("{value:?}"))
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
