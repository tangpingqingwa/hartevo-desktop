use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;

use crate::error::{BigCommerceOrderResultError, BigCommerceTransportError, Result};
use crate::model::{
    BigCommerceOrderScope, BigCommerceOrderSnapshot, BigCommerceSecretReference, Digest,
    OrderListFilter, Revision, TransportProvenance,
};
use crate::provider::{
    BigCommerceOrderOperation, BigCommerceProviderContract, BigCommerceProviderDefinition,
    GetOrderRequest, GetOrderResponse, ListOrdersRequest, ListOrdersResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, MAX_ORDERS, MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION,
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
            "bigcommerce-registration-transition/v1",
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
pub struct BigCommerceOrderRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: String,
    api_revision: String,
    provider_digest: Digest,
    scope: BigCommerceOrderScope,
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for BigCommerceOrderRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BigCommerceOrderRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("api_revision", &self.api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl BigCommerceOrderRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: BigCommerceOrderScope,
        secret: &BigCommerceSecretReference,
        provider: &BigCommerceProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty()
            || id.len() > crate::MAX_IDENTIFIER_BYTES
            || id.contains(char::is_whitespace)
        {
            return Err(BigCommerceOrderResultError::InvalidRegistration);
        }
        scope.validate()?;
        secret.validate(&scope)?;
        provider.validate()?;
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            scope,
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-bigcommerce-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn scope(&self) -> &BigCommerceOrderScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    #[must_use]
    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    #[must_use]
    pub const fn is_reversible() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id.is_empty()
            || self.provider_version.is_empty()
            || self.api_revision.is_empty()
            || self.scope_digest != self.scope.scope_digest()
            || self.permission_digest != *self.scope.permission_digest()
            || self.consent_digest != *self.scope.consent_digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(BigCommerceOrderResultError::InvalidRegistration);
        }
        self.scope.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(BigCommerceOrderResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(BigCommerceOrderResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(BigCommerceOrderResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-order-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("api_revision", self.api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("revision", self.registration_revision.get().to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BigCommerceResultProjection {
    Complete,
    Partial,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    ProviderUnknown,
}

impl BigCommerceResultProjection {
    #[must_use]
    pub const fn status(self) -> EvidenceState {
        match self {
            Self::Complete => EvidenceState::Complete,
            Self::Partial => EvidenceState::Partial,
            Self::AccessLost => EvidenceState::AccessLost,
            Self::NotFound => EvidenceState::NotFound,
            Self::Conflict => EvidenceState::Conflict,
            Self::RateLimited => EvidenceState::RateLimited,
            Self::ProviderUnknown => EvidenceState::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BigCommerceOrderEvidenceRequest {
    pub page_size: u16,
    pub max_pages: u16,
    pub get_order_details: bool,
    pub filter: OrderListFilter,
}

impl BigCommerceOrderEvidenceRequest {
    pub fn new(page_size: u16, max_pages: u16, get_order_details: bool) -> Result<Self> {
        Self::with_filter(
            page_size,
            max_pages,
            get_order_details,
            OrderListFilter::default(),
        )
    }

    pub fn with_filter(
        page_size: u16,
        max_pages: u16,
        get_order_details: bool,
        filter: OrderListFilter,
    ) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(BigCommerceOrderResultError::ResponseBoundExceeded);
        }
        Ok(Self {
            page_size,
            max_pages,
            get_order_details,
            filter,
        })
    }
}

impl Default for BigCommerceOrderEvidenceRequest {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            get_order_details: true,
            filter: OrderListFilter::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: BigCommerceOrderOperation,
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub receipt_digest: Digest,
}

impl RequestReceipt {
    fn success(
        operation: BigCommerceOrderOperation,
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Self {
        let mut receipt = Self {
            operation,
            request_digest,
            response_digest: Some(response_digest),
            error_digest: None,
            response_bytes,
            provenance,
            connected: false,
            native: false,
            provider_receipt: false,
            receipt_digest: Digest::from_text("unsealed-bigcommerce-receipt"),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt
    }

    fn failure(
        operation: BigCommerceOrderOperation,
        request_digest: Digest,
        error: &BigCommerceTransportError,
        provenance: TransportProvenance,
    ) -> Self {
        let mut receipt = Self {
            operation,
            request_digest,
            response_digest: None,
            error_digest: Some(Digest::from_parts(
                "bigcommerce-provider-error/v1",
                &[("error", format!("{error:?}"))],
            )),
            response_bytes: 0,
            provenance,
            connected: false,
            native: false,
            provider_receipt: false,
            receipt_digest: Digest::from_text("unsealed-bigcommerce-receipt"),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-request-receipt/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "response",
                    self.response_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "error",
                    self.error_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.provider_receipt
            || self.receipt_digest != self.calculate_digest()
        {
            Err(BigCommerceOrderResultError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub operation: BigCommerceOrderOperation,
    pub class: ProviderFailureClass,
    pub status_code: Option<u16>,
    pub blocked_env: bool,
    pub access_loss: bool,
    pub retryable: bool,
    pub error_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerError,
    Timeout,
    AccessLost,
    BlockedEnv,
    Partial,
    InvalidResponse,
}

impl ProviderErrorEvidence {
    fn new(operation: BigCommerceOrderOperation, error: &BigCommerceTransportError) -> Self {
        Self {
            operation,
            class: provider_failure_class(error),
            status_code: error.status_code(),
            blocked_env: error.is_blocked_env(),
            access_loss: error.is_access_loss(),
            retryable: error.is_retryable(),
            error_digest: Digest::from_parts(
                "bigcommerce-provider-error/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("error", format!("{error:?}")),
                ],
            ),
        }
    }
}

fn provider_failure_class(error: &BigCommerceTransportError) -> ProviderFailureClass {
    match error {
        BigCommerceTransportError::BadRequest => ProviderFailureClass::BadRequest,
        BigCommerceTransportError::Unauthorized => ProviderFailureClass::Unauthorized,
        BigCommerceTransportError::Forbidden => ProviderFailureClass::Forbidden,
        BigCommerceTransportError::NotFound => ProviderFailureClass::NotFound,
        BigCommerceTransportError::Conflict => ProviderFailureClass::Conflict,
        BigCommerceTransportError::RateLimited { .. } => ProviderFailureClass::RateLimited,
        BigCommerceTransportError::ServerError { .. } => ProviderFailureClass::ServerError,
        BigCommerceTransportError::Timeout => ProviderFailureClass::Timeout,
        BigCommerceTransportError::AccessLost => ProviderFailureClass::AccessLost,
        BigCommerceTransportError::BlockedEnv => ProviderFailureClass::BlockedEnv,
        BigCommerceTransportError::Partial => ProviderFailureClass::Partial,
        BigCommerceTransportError::InvalidResponse => ProviderFailureClass::InvalidResponse,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub revision_digests: Vec<Digest>,
    pub amount_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigCommerceOrderEvidence {
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub orders: Vec<BigCommerceOrderSnapshot>,
    pub pages_observed: u16,
    pub requests: Vec<RequestReceipt>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub provider_provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub digests: EvidenceDigests,
}

impl BigCommerceOrderEvidence {
    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.orders.len() > MAX_ORDERS
            || self.digests.scope_digest != self.scope_digest
            || self.digests.permission_digest != self.permission_digest
            || self.digests.consent_digest != self.consent_digest
            || self.digests.work_product_revision != self.work_product_revision
        {
            return Err(BigCommerceOrderResultError::InvalidProposal);
        }
        for order in &self.orders {
            order.validate()?;
        }
        for receipt in &self.requests {
            receipt.validate()?;
        }
        let (revision_digests, amount_digests) = collect_order_digests(&self.orders);
        if revision_digests != self.digests.revision_digests
            || amount_digests != self.digests.amount_digests
            || self.digests.evidence_digest
                != evidence_digest(
                    self.state,
                    &self.scope_digest,
                    self.pages_observed,
                    &self.orders,
                    &self.requests,
                    &self.provider_errors,
                    self.provider_provenance,
                    &self.digests.revision_digests,
                    &self.digests.amount_digests,
                )
        {
            return Err(BigCommerceOrderResultError::InvalidProposal);
        }
        Ok(())
    }

    #[must_use]
    pub fn revision_digests(&self) -> &[Digest] {
        &self.digests.revision_digests
    }

    #[must_use]
    pub fn amount_digests(&self) -> &[Digest] {
        &self.digests.amount_digests
    }
}

fn collect_order_digests(orders: &[BigCommerceOrderSnapshot]) -> (Vec<Digest>, Vec<Digest>) {
    let mut revisions = BTreeSet::new();
    let mut amounts = BTreeSet::new();
    for order in orders {
        revisions.extend(order.revision_digests());
        amounts.extend(order.amount_digests());
    }
    (
        revisions.into_iter().collect(),
        amounts.into_iter().collect(),
    )
}

fn evidence_digest(
    state: EvidenceState,
    scope_digest: &Digest,
    pages_observed: u16,
    orders: &[BigCommerceOrderSnapshot],
    requests: &[RequestReceipt],
    errors: &[ProviderErrorEvidence],
    provenance: TransportProvenance,
    revisions: &[Digest],
    amounts: &[Digest],
) -> Digest {
    Digest::from_parts(
        "bigcommerce-order-evidence/v1",
        &[
            ("state", format!("{state:?}")),
            ("scope", scope_digest.as_str().to_owned()),
            ("pages", pages_observed.to_string()),
            (
                "orders",
                orders
                    .iter()
                    .map(|value| value.digest().as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "requests",
                requests
                    .iter()
                    .map(|value| value.receipt_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "errors",
                errors
                    .iter()
                    .map(|value| value.error_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("provenance", provenance.as_str().to_owned()),
            (
                "revisions",
                revisions
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "amounts",
                amounts
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigCommerceOrderResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub scope_digest: Digest,
    pub projection: BigCommerceResultProjection,
    pub evidence: BigCommerceOrderEvidence,
    pub proposal_digest: Digest,
}

impl BigCommerceOrderResultProposal {
    #[must_use]
    pub const fn status(&self) -> EvidenceState {
        self.projection.status()
    }

    #[must_use]
    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.scope_digest != self.evidence.scope_digest
            || self.registration_digest.as_str().len() != 64
            || self.provider_definition_digest.as_str().len() != 64
            || self.proposal_digest
                != proposal_digest(
                    &self.registration_digest,
                    self.registration_revision,
                    &self.provider_definition_digest,
                    &self.scope_digest,
                    self.projection,
                    &self.evidence.digests.evidence_digest,
                )
        {
            Err(BigCommerceOrderResultError::InvalidProposal)
        } else {
            Ok(())
        }
    }
}

fn proposal_digest(
    registration_digest: &Digest,
    registration_revision: Revision,
    provider_definition_digest: &Digest,
    scope_digest: &Digest,
    projection: BigCommerceResultProjection,
    evidence_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "bigcommerce-order-proposal/v1",
        &[
            ("registration", registration_digest.as_str().to_owned()),
            (
                "registration_revision",
                registration_revision.get().to_string(),
            ),
            ("provider", provider_definition_digest.as_str().to_owned()),
            ("scope", scope_digest.as_str().to_owned()),
            ("projection", format!("{projection:?}")),
            ("evidence", evidence_digest.as_str().to_owned()),
        ],
    )
}

pub struct BigCommerceOrderResultService<P> {
    scope: BigCommerceOrderScope,
    secret_reference: BigCommerceSecretReference,
    provider: P,
    registration: BigCommerceOrderRegistration,
}

impl<P: BigCommerceProviderContract> fmt::Debug for BigCommerceOrderResultService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BigCommerceOrderResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<P: BigCommerceProviderContract> BigCommerceOrderResultService<P> {
    pub fn new(
        scope: BigCommerceOrderScope,
        secret_reference: BigCommerceSecretReference,
        provider: P,
        registration_revision: Revision,
    ) -> Result<Self> {
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(BigCommerceOrderResultError::ScopeMismatch);
        }
        let registration = BigCommerceOrderRegistration::new(
            "bigcommerce-order-registration",
            scope.clone(),
            &secret_reference,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn with_registration(
        scope: BigCommerceOrderScope,
        secret_reference: BigCommerceSecretReference,
        provider: P,
        registration: BigCommerceOrderRegistration,
    ) -> Result<Self> {
        provider.definition().validate()?;
        if registration.scope_digest() != &scope.scope_digest()
            || secret_reference.scope_digest() != &scope.scope_digest()
            || registration.secret_reference_digest() != secret_reference.reference_digest()
            || registration.provider_digest() != &provider.definition().provider_digest()
        {
            return Err(BigCommerceOrderResultError::ScopeMismatch);
        }
        registration.validate()?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &BigCommerceOrderScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &BigCommerceSecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn provider(&self) -> &P {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &BigCommerceOrderRegistration {
        &self.registration
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
        request: BigCommerceOrderEvidenceRequest,
    ) -> Result<BigCommerceOrderResultProposal> {
        self.provider.definition().validate()?;
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(BigCommerceOrderResultError::RegistrationInactive);
        }
        if self.secret_reference.is_revoked() {
            return Err(BigCommerceOrderResultError::SecretRevoked);
        }
        if self.registration.secret_reference_digest() != self.secret_reference.reference_digest()
            || self.registration.provider_digest() != &self.provider.definition().provider_digest()
        {
            return Err(BigCommerceOrderResultError::FenceViolation);
        }
        self.secret_reference.validate(&self.scope)?;

        let mut orders = BTreeMap::new();
        let mut requests = Vec::new();
        let mut provider_errors = Vec::new();
        let provenance = self.provider.provenance();
        let effective_filter = if request.filter == OrderListFilter::default() {
            OrderListFilter::for_scope(&self.scope)
        } else {
            request.filter.clone()
        };
        let mut pages_observed = 0;
        let mut next_cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut projection = BigCommerceResultProjection::Complete;

        loop {
            if pages_observed >= request.max_pages {
                projection = BigCommerceResultProjection::Partial;
                break;
            }
            let list_request = ListOrdersRequest::with_filter(
                &self.scope,
                &self.secret_reference,
                request.page_size,
                next_cursor.take(),
                effective_filter.clone(),
            )?;
            let list_request_digest = list_request.request_digest.clone();
            let page = match self.provider.list_orders(&list_request) {
                Ok(response) => {
                    validate_list_response(&self.scope, &list_request, &response)?;
                    requests.push(RequestReceipt::success(
                        BigCommerceOrderOperation::ListOrders,
                        list_request_digest,
                        response.response_digest.clone(),
                        response.response_bytes,
                        provenance,
                    ));
                    response
                }
                Err(error) => {
                    requests.push(RequestReceipt::failure(
                        BigCommerceOrderOperation::ListOrders,
                        list_request_digest,
                        &error,
                        provenance,
                    ));
                    provider_errors.push(ProviderErrorEvidence::new(
                        BigCommerceOrderOperation::ListOrders,
                        &error,
                    ));
                    projection = projection_for_error(&error);
                    break;
                }
            };
            pages_observed = pages_observed.saturating_add(1);
            for order in page.orders {
                if !orders.contains_key(&order.order_id.get()) && orders.len() >= MAX_ORDERS {
                    projection = BigCommerceResultProjection::Partial;
                    break;
                }
                if orders.insert(order.order_id.get(), order).is_some() {
                    return Err(BigCommerceOrderResultError::DuplicateOrder);
                }
            }
            if projection == BigCommerceResultProjection::Partial {
                break;
            }
            next_cursor = page.next_cursor;
            let Some(cursor) = next_cursor.as_ref() else {
                break;
            };
            if !seen_cursors.insert(cursor.token_digest().clone()) {
                return Err(BigCommerceOrderResultError::PageLoop);
            }
            if pages_observed >= request.max_pages {
                projection = BigCommerceResultProjection::Partial;
                break;
            }
        }

        if request.get_order_details && !orders.is_empty() {
            let order_ids = orders.keys().copied().collect::<Vec<_>>();
            for order_id in order_ids {
                let get_request = GetOrderRequest::new(
                    &self.scope,
                    &self.secret_reference,
                    crate::OrderId::new(order_id)?,
                )?;
                let get_request_digest = get_request.request_digest.clone();
                let response = match self.provider.get_order(&get_request) {
                    Ok(response) => {
                        validate_get_response(&self.scope, &get_request, &response)?;
                        requests.push(RequestReceipt::success(
                            BigCommerceOrderOperation::GetOrder,
                            get_request_digest,
                            response.response_digest.clone(),
                            response.response_bytes,
                            provenance,
                        ));
                        response
                    }
                    Err(error) => {
                        requests.push(RequestReceipt::failure(
                            BigCommerceOrderOperation::GetOrder,
                            get_request_digest,
                            &error,
                            provenance,
                        ));
                        provider_errors.push(ProviderErrorEvidence::new(
                            BigCommerceOrderOperation::GetOrder,
                            &error,
                        ));
                        projection = projection_for_error(&error);
                        break;
                    }
                };
                if let Some(summary) = orders.get(&response.order.order_id.get())
                    && (summary.store != response.order.store
                        || summary.revision_digest != response.order.revision_digest)
                {
                    return Err(BigCommerceOrderResultError::OrderRevisionDrift);
                }
                orders.insert(response.order.order_id.get(), response.order);
            }
        }

        let orders = orders.into_values().collect::<Vec<_>>();
        let (revision_digests, amount_digests) = collect_order_digests(&orders);
        let digests = EvidenceDigests {
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            consent_digest: self.scope.consent_digest().clone(),
            work_product_revision: self.scope.work_product().revision(),
            evidence_digest: Digest::from_text("unsealed-bigcommerce-evidence"),
            revision_digests,
            amount_digests,
        };
        let mut evidence = BigCommerceOrderEvidence {
            state: projection.status(),
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            consent_digest: self.scope.consent_digest().clone(),
            work_product_revision: self.scope.work_product().revision(),
            orders,
            pages_observed,
            requests,
            provider_errors,
            provider_provenance: provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            digests,
        };
        evidence.digests.evidence_digest = evidence_digest(
            evidence.state,
            &evidence.scope_digest,
            evidence.pages_observed,
            &evidence.orders,
            &evidence.requests,
            &evidence.provider_errors,
            evidence.provider_provenance,
            &evidence.digests.revision_digests,
            &evidence.digests.amount_digests,
        );
        let proposal_digest = proposal_digest(
            self.registration.registration_digest(),
            self.registration.registration_revision(),
            &self.provider.definition().provider_digest(),
            &self.scope.scope_digest(),
            projection,
            &evidence.digests.evidence_digest,
        );
        let proposal = BigCommerceOrderResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            registration_revision: self.registration.registration_revision(),
            provider_definition_digest: self.provider.definition().provider_digest(),
            scope_digest: self.scope.scope_digest(),
            projection,
            evidence,
            proposal_digest,
        };
        proposal.validate_integrity()?;
        Ok(proposal)
    }
}

fn validate_list_response(
    scope: &BigCommerceOrderScope,
    request: &ListOrdersRequest,
    response: &ListOrdersResponse,
) -> Result<()> {
    response.validate()?;
    if response.orders.len() > request.page_size as usize {
        return Err(BigCommerceOrderResultError::ResponseBoundExceeded);
    }
    if response.observed_fence.scope_digest != request.scope_digest
        || response.observed_fence.permission_digest != request.permission_digest
        || response.observed_fence.consent_digest != request.consent_digest
        || response.observed_fence.work_product_revision != request.work_product_revision
        || response.observed_fence.credential_revision != request.credential_revision
        || response.observed_fence.secret_reference_digest != request.secret_reference_digest
    {
        return Err(BigCommerceOrderResultError::FenceViolation);
    }
    for order in &response.orders {
        scope.allows(order)?;
    }
    Ok(())
}

fn validate_get_response(
    scope: &BigCommerceOrderScope,
    request: &GetOrderRequest,
    response: &GetOrderResponse,
) -> Result<()> {
    response.validate()?;
    if response.order.order_id != request.order_id || response.observed_fence != request.fence() {
        return Err(BigCommerceOrderResultError::FenceViolation);
    }
    scope.allows(&response.order)
}

fn projection_for_error(error: &BigCommerceTransportError) -> BigCommerceResultProjection {
    match error {
        BigCommerceTransportError::Unauthorized
        | BigCommerceTransportError::Forbidden
        | BigCommerceTransportError::AccessLost => BigCommerceResultProjection::AccessLost,
        BigCommerceTransportError::NotFound => BigCommerceResultProjection::NotFound,
        BigCommerceTransportError::Conflict => BigCommerceResultProjection::Conflict,
        BigCommerceTransportError::RateLimited { .. } => BigCommerceResultProjection::RateLimited,
        BigCommerceTransportError::BadRequest
        | BigCommerceTransportError::ServerError { .. }
        | BigCommerceTransportError::Timeout
        | BigCommerceTransportError::BlockedEnv
        | BigCommerceTransportError::Partial
        | BigCommerceTransportError::InvalidResponse => {
            BigCommerceResultProjection::ProviderUnknown
        }
    }
}
