//! Typed, redacted models for the bounded Ramp Layer-1 spend-evidence seam.
//!
//! Provider payloads are intentionally converted into this module's digest and
//! bucket forms before they can cross the provider boundary.  No type here
//! stores card numbers, CVV, bank details, employee/vendor PII, receipt bytes,
//! raw OAuth material, or arbitrary memo/comment text.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    MAX_AUDIT_EVENTS, MAX_CURSOR_BYTES, MAX_DATE_WINDOW_SECONDS, MAX_EVENT_TYPE_BYTES,
    MAX_IDENTIFIER_BYTES, MAX_MERCHANTS, MAX_PAGE_SIZE, MAX_PAGES, MAX_TRANSACTIONS,
};

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    format!("{:x}", Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Ramp value serializes");
    sha256_digest(&bytes)
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), crate::RampSpendOutcomeError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(crate::RampSpendOutcomeError::InvalidIdentifier { field });
    }
    Ok(())
}

pub(crate) fn validate_bounded_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), crate::RampSpendOutcomeError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(crate::RampSpendOutcomeError::InvalidIdentifier { field });
    }
    Ok(())
}

pub(crate) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), crate::RampSpendOutcomeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crate::RampSpendOutcomeError::InvalidDigest { field });
    }
    Ok(())
}

/// An opaque host-owned handle.  The underlying identifier is never exposed
/// through `Serialize`, `Deserialize`, `Display`, or `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    revision: u64,
}

impl SecretReference {
    pub fn oauth(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        Self::new(SecretKind::OAuth, opaque_id, revision)
    }

    pub fn client_credentials(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        Self::new(SecretKind::ClientCredentials, opaque_id, revision)
    }

    fn new(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let opaque_id = opaque_id.into();
        if revision == 0
            || opaque_id.is_empty()
            || opaque_id.len() > MAX_IDENTIFIER_BYTES
            || opaque_id.trim() != opaque_id
            || opaque_id.chars().any(char::is_control)
        {
            return Err(crate::RampSpendOutcomeError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            opaque_id,
            revision,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "ramp-secret-reference|{}|{}|{}",
                self.kind.label(),
                self.revision,
                self.opaque_id
            )
            .as_bytes(),
        )
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("opaque_id", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ClientCredentials,
}

impl SecretKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::ClientCredentials => "client_credentials",
        }
    }
}

/// A provider identifier retained only as a digest in serialized scope and
/// evidence.  The raw identifier is available only inside this crate while a
/// request is being assembled.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundIdentifier {
    value: String,
}

impl BoundIdentifier {
    pub(crate) fn new(
        value: impl Into<String>,
        field: &'static str,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let value = value.into();
        validate_identifier(&value, field)?;
        Ok(Self { value })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(self.value.as_bytes())
    }

    pub(crate) fn raw(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for BoundIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundIdentifier")
            .field("digest", &self.digest())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Serialize for BoundIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.digest())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RampReadScope {
    BusinessRead,
    EntitiesRead,
    SpendProgramsRead,
    FundsRead,
    CardsRead,
    MerchantsRead,
    VendorsRead,
    TransactionsRead,
    AuditLogsRead,
}

impl RampReadScope {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::BusinessRead => "business:read",
            Self::EntitiesRead => "entities:read",
            Self::SpendProgramsRead => "spend_programs:read",
            Self::FundsRead => "funds:read",
            Self::CardsRead => "cards:read",
            Self::MerchantsRead => "merchants:read",
            Self::VendorsRead => "vendors:read",
            Self::TransactionsRead => "transactions:read",
            Self::AuditLogsRead => "audit_logs:read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub requested: BTreeSet<RampReadScope>,
    pub granted: BTreeSet<RampReadScope>,
    pub revision: u64,
}

impl PermissionSnapshot {
    pub fn new(
        requested: BTreeSet<RampReadScope>,
        granted: BTreeSet<RampReadScope>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let snapshot = Self {
            requested,
            granted,
            revision,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub fn least_privilege_for(spec: &RampSpendScopeSpec) -> Self {
        let mut scopes = BTreeSet::from([
            RampReadScope::BusinessRead,
            RampReadScope::TransactionsRead,
            RampReadScope::MerchantsRead,
            RampReadScope::AuditLogsRead,
        ]);
        if spec.entity_id.is_some() {
            scopes.insert(RampReadScope::EntitiesRead);
        }
        if spec.spend_program_id.is_some() {
            scopes.insert(RampReadScope::SpendProgramsRead);
        }
        if spec.card_id.is_some() {
            scopes.insert(RampReadScope::CardsRead);
        }
        if spec.vendor_id.is_some() {
            scopes.insert(RampReadScope::VendorsRead);
        }
        Self {
            requested: scopes.clone(),
            granted: scopes,
            revision: 1,
        }
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.revision == 0
            || self.requested.is_empty()
            || self.requested != self.granted
            || self
                .requested
                .iter()
                .any(|scope| !scope.label().ends_with(":read"))
        {
            return Err(crate::RampSpendOutcomeError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn has(&self, scope: RampReadScope) -> bool {
        self.granted.contains(&scope)
    }

    pub(crate) fn require(&self, scope: RampReadScope) -> Result<(), crate::RampSpendOutcomeError> {
        if self.has(scope.clone()) {
            Ok(())
        } else {
            Err(crate::RampSpendOutcomeError::MissingReadScope {
                scope: scope.label(),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateWindow {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl DateWindow {
    pub fn closed(
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let window = Self { from, to };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        let seconds = (self.to - self.from).num_seconds();
        if self.to <= self.from || seconds <= 0 || seconds > MAX_DATE_WINDOW_SECONDS {
            return Err(crate::RampSpendOutcomeError::InvalidDateWindow);
        }
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, value: DateTime<Utc>) -> bool {
        value >= self.from && value <= self.to
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    pub id: String,
    pub revision: u64,
}

impl IdentityBinding {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        field: &'static str,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let id = id.into();
        validate_identifier(&id, field)?;
        if revision == 0 {
            return Err(crate::RampSpendOutcomeError::InvalidIdentifier { field });
        }
        Ok(Self { id, revision })
    }
}

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;
pub type DeploymentBinding = IdentityBinding;
pub type ReleaseBinding = IdentityBinding;

#[derive(Clone)]
pub struct RampSpendScopeSpec {
    pub business_id: String,
    pub entity_id: Option<String>,
    pub spend_program_id: Option<String>,
    pub card_id: Option<String>,
    pub vendor_id: Option<String>,
    pub transaction_id: Option<String>,
    pub audit_event_id: Option<String>,
    pub date_window: DateWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub deployment: Option<DeploymentBinding>,
    pub release: Option<ReleaseBinding>,
    pub policy_revision: u64,
    pub permissions: PermissionSnapshot,
}

impl fmt::Debug for RampSpendScopeSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampSpendScopeSpec")
            .field("business_id", &"<redacted>")
            .field("entity_id", &self.entity_id.as_ref().map(|_| "<redacted>"))
            .field(
                "spend_program_id",
                &self.spend_program_id.as_ref().map(|_| "<redacted>"),
            )
            .field("card_id", &self.card_id.as_ref().map(|_| "<redacted>"))
            .field("vendor_id", &self.vendor_id.as_ref().map(|_| "<redacted>"))
            .field(
                "transaction_id",
                &self.transaction_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "audit_event_id",
                &self.audit_event_id.as_ref().map(|_| "<redacted>"),
            )
            .field("date_window", &self.date_window)
            .field("policy_revision", &self.policy_revision)
            .field("project", &"<redacted>")
            .field("mission", &"<redacted>")
            .field("work_product", &"<redacted>")
            .field(
                "deployment",
                &self.deployment.as_ref().map(|_| "<redacted>"),
            )
            .field("release", &self.release.as_ref().map(|_| "<redacted>"))
            .field("permissions", &self.permissions)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RampSpendScope {
    pub business_id: BoundIdentifier,
    pub entity_id: Option<BoundIdentifier>,
    pub spend_program_id: Option<BoundIdentifier>,
    pub card_id: Option<BoundIdentifier>,
    pub vendor_id: Option<BoundIdentifier>,
    pub transaction_id: Option<BoundIdentifier>,
    pub audit_event_id: Option<BoundIdentifier>,
    pub date_window: DateWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub deployment: Option<DeploymentBinding>,
    pub release: Option<ReleaseBinding>,
    pub policy_revision: u64,
    pub permissions: PermissionSnapshot,
    pub secret_kind: SecretKind,
    pub secret_revision: u64,
    pub secret_reference_digest: Digest,
}

impl RampSpendScope {
    pub fn new(
        spec: RampSpendScopeSpec,
        secret_reference: &SecretReference,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let scope = Self {
            business_id: BoundIdentifier::new(spec.business_id, "business id")?,
            entity_id: spec
                .entity_id
                .map(|value| BoundIdentifier::new(value, "entity id"))
                .transpose()?,
            spend_program_id: spec
                .spend_program_id
                .map(|value| BoundIdentifier::new(value, "spend program id"))
                .transpose()?,
            card_id: spec
                .card_id
                .map(|value| BoundIdentifier::new(value, "card id"))
                .transpose()?,
            vendor_id: spec
                .vendor_id
                .map(|value| BoundIdentifier::new(value, "vendor id"))
                .transpose()?,
            transaction_id: spec
                .transaction_id
                .map(|value| BoundIdentifier::new(value, "transaction id"))
                .transpose()?,
            audit_event_id: spec
                .audit_event_id
                .map(|value| BoundIdentifier::new(value, "audit event id"))
                .transpose()?,
            date_window: spec.date_window,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            deployment: spec.deployment,
            release: spec.release,
            policy_revision: spec.policy_revision,
            permissions: spec.permissions,
            secret_kind: secret_reference.kind(),
            secret_revision: secret_reference.revision(),
            secret_reference_digest: secret_reference.digest(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        self.date_window.validate()?;
        self.permissions.validate()?;
        self.permissions.require(RampReadScope::BusinessRead)?;
        self.permissions.require(RampReadScope::TransactionsRead)?;
        self.permissions.require(RampReadScope::MerchantsRead)?;
        self.permissions.require(RampReadScope::AuditLogsRead)?;
        if self.entity_id.is_some() {
            self.permissions.require(RampReadScope::EntitiesRead)?;
        }
        if self.spend_program_id.is_some() {
            self.permissions.require(RampReadScope::SpendProgramsRead)?;
        }
        if self.card_id.is_some() {
            self.permissions.require(RampReadScope::CardsRead)?;
        }
        if self.vendor_id.is_some() {
            self.permissions.require(RampReadScope::VendorsRead)?;
        }
        if self.policy_revision == 0
            || self.secret_revision == 0
            || self.project.revision == 0
            || self.mission.revision == 0
            || self.work_product.revision == 0
        {
            return Err(crate::RampSpendOutcomeError::InvalidScope);
        }
        validate_digest(&self.secret_reference_digest, "secret reference")?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn matches_identifier(
        &self,
        expected: &Option<BoundIdentifier>,
        actual: Option<&str>,
    ) -> bool {
        match (expected, actual) {
            (None, _) => true,
            (Some(expected), Some(actual)) => expected.raw() == actual,
            (Some(_), None) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    PendingInitiation,
    Pending,
    Authorized,
    Cleared,
    Completion,
    Declined,
    Error,
    Refunded,
    Reversed,
    ProviderUnknown,
}

impl TransactionState {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "PENDING_INITIATION" => Self::PendingInitiation,
            "PENDING" => Self::Pending,
            "AUTHORIZED" | "AUTHORIZATION" => Self::Authorized,
            "CLEARED" => Self::Cleared,
            "COMPLETION" | "COMPLETED" => Self::Completion,
            "DECLINED" => Self::Declined,
            "ERROR" => Self::Error,
            "REFUNDED" | "REFUND" => Self::Refunded,
            "REVERSED" | "REVERSAL" => Self::Reversed,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundState {
    NotRefunded,
    Partial,
    Full,
    Reversed,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountBucket {
    Zero,
    UnderOneHundred,
    OneHundredToOneThousand,
    OneThousandToTenThousand,
    TenThousandOrMore,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorClass {
    PolicyAgent,
    Ramp,
    SpendRequestAgent,
    User,
    ProviderUnknown,
}

impl ActorClass {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "policy_agent" => Self::PolicyAgent,
            "ramp" => Self::Ramp,
            "spend_request_agent" => Self::SpendRequestAgent,
            "user" => Self::User,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Transaction,
    VendorMerchant,
    Card,
    SpendProgram,
    Fund,
    Business,
    Entity,
    ProviderUnknown,
}

impl ResourceKind {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "transaction" => Self::Transaction,
            "vendor / merchant" | "vendor_merchant" | "merchant" | "vendor" => Self::VendorMerchant,
            "card" => Self::Card,
            "spend program" | "spend_program" => Self::SpendProgram,
            "fund" => Self::Fund,
            "business" => Self::Business,
            "entity" => Self::Entity,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    RetentionGap,
    AccessLost,
    Tampered,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    OfficialApiParser,
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionEvidence {
    pub transaction_id_digest: Digest,
    pub state: TransactionState,
    pub refund_state: RefundState,
    pub amount_bucket: AmountBucket,
    pub amount_digest: Option<Digest>,
    pub currency_code: Option<String>,
    pub entity_id_digest: Option<Digest>,
    pub spend_program_id_digest: Option<Digest>,
    pub card_id_digest: Option<Digest>,
    pub vendor_id_digest: Option<Digest>,
    pub vendor_name_digest: Option<Digest>,
    pub category_id_digest: Option<Digest>,
    pub category_name_digest: Option<Digest>,
    pub original_transaction_id_digest: Option<Digest>,
    pub transaction_time: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub settlement_date: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MerchantEvidence {
    pub merchant_id_digest: Digest,
    pub merchant_name_digest: Digest,
    pub category_name_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEventEvidence {
    pub audit_event_id_digest: Digest,
    pub event_type_digest: Digest,
    pub actor_class: ActorClass,
    pub resource_kind: ResourceKind,
    pub resource_id_digest: Option<Digest>,
    pub event_time: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendEvidence {
    pub status: EvidenceStatus,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub transactions: Vec<TransactionEvidence>,
    pub merchants: Vec<MerchantEvidence>,
    pub audit_events: Vec<AuditEventEvidence>,
    pub high_water_mark_digest: Digest,
    pub page_count: u16,
    pub request_receipt_digest: Digest,
    pub response_receipt_digest: Digest,
    pub provenance: TransportProvenance,
    pub native: bool,
    pub connected: bool,
    pub evidence_digest: Digest,
}

impl SpendEvidence {
    pub(crate) fn new(
        scope_digest: Digest,
        registration_digest: Digest,
        provider_digest: Digest,
        contract_digest: Digest,
        transactions: Vec<TransactionEvidence>,
        merchants: Vec<MerchantEvidence>,
        audit_events: Vec<AuditEventEvidence>,
        high_water_mark_digest: Digest,
        page_count: u16,
        request_receipt_digest: Digest,
        response_receipt_digest: Digest,
        provenance: TransportProvenance,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        if transactions.is_empty() && merchants.is_empty() && audit_events.is_empty() {
            return Err(crate::RampSpendOutcomeError::EmptyEvidence);
        }
        if transactions.len() > MAX_TRANSACTIONS {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "transactions",
                maximum: MAX_TRANSACTIONS,
            });
        }
        if merchants.len() > MAX_MERCHANTS {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "merchants",
                maximum: MAX_MERCHANTS,
            });
        }
        if audit_events.len() > MAX_AUDIT_EVENTS {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "audit events",
                maximum: MAX_AUDIT_EVENTS,
            });
        }
        if page_count == 0 || page_count as usize > MAX_PAGES {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "pages",
                maximum: MAX_PAGES,
            });
        }
        validate_digest(&scope_digest, "scope")?;
        validate_digest(&registration_digest, "registration")?;
        validate_digest(&provider_digest, "provider")?;
        validate_digest(&contract_digest, "contract")?;
        validate_digest(&high_water_mark_digest, "high-water mark")?;
        validate_digest(&request_receipt_digest, "request receipt")?;
        validate_digest(&response_receipt_digest, "response receipt")?;
        let mut evidence = Self {
            status: EvidenceStatus::Complete,
            scope_digest,
            registration_digest,
            provider_digest,
            contract_digest,
            transactions,
            merchants,
            audit_events,
            high_water_mark_digest,
            page_count,
            request_receipt_digest,
            response_receipt_digest,
            provenance,
            native: false,
            connected: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.computed_digest();
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.status != EvidenceStatus::Complete
            || self.native
            || self.connected
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.transactions.is_empty()
                && self.merchants.is_empty()
                && self.audit_events.is_empty()
        {
            return Err(crate::RampSpendOutcomeError::PartialEvidence);
        }
        if self.evidence_digest != self.computed_digest() {
            return Err(crate::RampSpendOutcomeError::ResponseTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn tampered(mut self) -> Self {
        self.evidence_digest = "0".repeat(64);
        self
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&EvidenceFingerprint {
            status: self.status,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            transactions: &self.transactions,
            merchants: &self.merchants,
            audit_events: &self.audit_events,
            high_water_mark_digest: &self.high_water_mark_digest,
            page_count: self.page_count,
            request_receipt_digest: &self.request_receipt_digest,
            response_receipt_digest: &self.response_receipt_digest,
            provenance: self.provenance,
            native: self.native,
            connected: self.connected,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceFingerprint<'a> {
    status: EvidenceStatus,
    scope_digest: &'a str,
    registration_digest: &'a str,
    provider_digest: &'a str,
    contract_digest: &'a str,
    transactions: &'a [TransactionEvidence],
    merchants: &'a [MerchantEvidence],
    audit_events: &'a [AuditEventEvidence],
    high_water_mark_digest: &'a str,
    page_count: u16,
    request_receipt_digest: &'a str,
    response_receipt_digest: &'a str,
    provenance: TransportProvenance,
    native: bool,
    connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeProposal {
    pub proposal_kind: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub evidence_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub policy_revision: u64,
    pub transaction_states: Vec<TransactionState>,
    pub refund_states: Vec<RefundState>,
    pub audit_event_count: u16,
    pub native: bool,
    pub connected: bool,
    pub effect_requested: bool,
    pub proposal_digest: Digest,
}

impl OutcomeProposal {
    pub(crate) fn from_evidence(
        evidence: &SpendEvidence,
        scope: &RampSpendScope,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        evidence.validate()?;
        if evidence.scope_digest != scope.digest() {
            return Err(crate::RampSpendOutcomeError::ScopeMismatch);
        }
        let mut proposal = Self {
            proposal_kind: "bounded_ramp_spend_evidence_candidate".to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            policy_revision: scope.policy_revision,
            transaction_states: evidence
                .transactions
                .iter()
                .map(|item| item.state)
                .collect(),
            refund_states: evidence
                .transactions
                .iter()
                .map(|item| item.refund_state)
                .collect(),
            audit_event_count: evidence.audit_events.len() as u16,
            native: false,
            connected: false,
            effect_requested: false,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.proposal_kind != "bounded_ramp_spend_evidence_candidate"
            || self.native
            || self.connected
            || self.effect_requested
            || self.proposal_digest != self.computed_digest()
        {
            return Err(crate::RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ProposalFingerprint {
            proposal_kind: &self.proposal_kind,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            evidence_digest: &self.evidence_digest,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            policy_revision: self.policy_revision,
            transaction_states: &self.transaction_states,
            refund_states: &self.refund_states,
            audit_event_count: self.audit_event_count,
            native: self.native,
            connected: self.connected,
            effect_requested: self.effect_requested,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalFingerprint<'a> {
    proposal_kind: &'a str,
    scope_digest: &'a str,
    registration_digest: &'a str,
    provider_digest: &'a str,
    contract_digest: &'a str,
    evidence_digest: &'a str,
    project: &'a ProjectBinding,
    mission: &'a MissionBinding,
    work_product: &'a WorkProductBinding,
    policy_revision: u64,
    transaction_states: &'a [TransactionState],
    refund_states: &'a [RefundState],
    audit_event_count: u16,
    native: bool,
    connected: bool,
    effect_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReceipt {
    pub receipt_kind: String,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub provenance: TransportProvenance,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub receipt_digest: Digest,
}

impl EvidenceReceipt {
    pub(crate) fn from_evidence(
        evidence: &SpendEvidence,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        evidence.validate()?;
        let mut receipt = Self {
            receipt_kind: "ramp_spend_evidence_recording_receipt".to_owned(),
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            provenance: evidence.provenance,
            durable: false,
            native: false,
            connected: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.receipt_kind != "ramp_spend_evidence_recording_receipt"
            || self.durable
            || self.native
            || self.connected
            || self.receipt_digest != self.computed_digest()
        {
            return Err(crate::RampSpendOutcomeError::ReceiptTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ReceiptFingerprint {
            receipt_kind: &self.receipt_kind,
            evidence_digest: &self.evidence_digest,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            provenance: self.provenance,
            durable: self.durable,
            native: self.native,
            connected: self.connected,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptFingerprint<'a> {
    receipt_kind: &'a str,
    evidence_digest: &'a str,
    scope_digest: &'a str,
    registration_digest: &'a str,
    provider_digest: &'a str,
    contract_digest: &'a str,
    provenance: TransportProvenance,
    durable: bool,
    native: bool,
    connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerification {
    pub receipt_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verified: bool,
    pub native: bool,
    pub connected: bool,
    pub adoptable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capabilities {
    pub service_id: String,
    pub provider_id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub operations: Vec<String>,
    pub transport: TransportProvenance,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub implementation: String,
    pub version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_revision: u64,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl RegistrationReceipt {
    pub(crate) fn bind(
        contract_digest: Digest,
        provider_digest: Digest,
        scope: &RampSpendScope,
        provider_revision: u64,
        registration_revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        if provider_revision == 0 || registration_revision == 0 {
            return Err(crate::RampSpendOutcomeError::RegistrationMismatch);
        }
        let mut receipt = Self {
            plugin_id: crate::RAMP_PROVIDER_ID.to_owned(),
            service_id: crate::RAMP_SPEND_OUTCOME_SERVICE_ID.to_owned(),
            provider_id: crate::RAMP_PROVIDER_ID.to_owned(),
            implementation: crate::RAMP_PROVIDER_IMPLEMENTATION.to_owned(),
            version: crate::RAMP_PLUGIN_VERSION.to_owned(),
            contract_digest,
            provider_digest,
            scope_digest: scope.digest(),
            permission_digest: scope.permissions.digest(),
            provider_revision,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: String::new(),
        };
        receipt.registration_digest = receipt.computed_digest();
        Ok(receipt)
    }

    pub fn validate(
        &self,
        contract_digest: &str,
        provider_digest: &str,
        scope: &RampSpendScope,
    ) -> Result<(), crate::RampSpendOutcomeError> {
        if self.plugin_id != crate::RAMP_PROVIDER_ID
            || self.service_id != crate::RAMP_SPEND_OUTCOME_SERVICE_ID
            || self.provider_id != crate::RAMP_PROVIDER_ID
            || self.implementation != crate::RAMP_PROVIDER_IMPLEMENTATION
            || self.version != crate::RAMP_PLUGIN_VERSION
            || self.contract_digest != contract_digest
            || self.provider_digest != provider_digest
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permissions.digest()
            || self.provider_revision == 0
            || self.registration_revision == 0
            || self.registration_digest != self.computed_digest()
        {
            return Err(crate::RampSpendOutcomeError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt, crate::RampSpendOutcomeError> {
        if self.status == RegistrationStatus::Revoked {
            return Err(crate::RampSpendOutcomeError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&RegistrationFingerprint {
            plugin_id: &self.plugin_id,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            implementation: &self.implementation,
            version: &self.version,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            provider_revision: self.provider_revision,
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationFingerprint<'a> {
    plugin_id: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    implementation: &'a str,
    version: &'a str,
    contract_digest: &'a str,
    provider_digest: &'a str,
    scope_digest: &'a str,
    permission_digest: &'a str,
    provider_revision: u64,
    registration_revision: u64,
    status: RegistrationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
}

pub(crate) fn amount_evidence(
    amount_minor: Option<i64>,
    currency_code: Option<&str>,
) -> Result<(AmountBucket, Option<Digest>, Option<String>), crate::RampSpendOutcomeError> {
    let currency = currency_code.map(str::to_owned);
    if let Some(currency_code) = currency_code
        && (currency_code.is_empty()
            || currency_code.len() > 12
            || !currency_code.bytes().all(|byte| byte.is_ascii_uppercase()))
    {
        return Err(crate::RampSpendOutcomeError::InvalidResponse);
    }
    let Some(amount_minor) = amount_minor else {
        return Ok((AmountBucket::Unknown, None, currency));
    };
    let absolute = amount_minor.unsigned_abs();
    let bucket = match absolute {
        0 => AmountBucket::Zero,
        1..=9_999 => AmountBucket::UnderOneHundred,
        10_000..=99_999 => AmountBucket::OneHundredToOneThousand,
        100_000..=999_999 => AmountBucket::OneThousandToTenThousand,
        _ => AmountBucket::TenThousandOrMore,
    };
    let digest = sha256_digest(
        format!(
            "ramp-amount|{}|{}",
            currency_code.unwrap_or("unknown"),
            amount_minor
        )
        .as_bytes(),
    );
    Ok((bucket, Some(digest), currency))
}

pub(crate) fn refund_state(
    state: TransactionState,
    amount_minor: Option<i64>,
    declared: Option<RefundState>,
) -> RefundState {
    if let Some(declared) = declared {
        return declared;
    }
    if matches!(state, TransactionState::Refunded) {
        return RefundState::Full;
    }
    if matches!(state, TransactionState::Reversed) {
        return RefundState::Reversed;
    }
    if amount_minor.is_some_and(|amount| amount < 0) {
        RefundState::Partial
    } else {
        RefundState::NotRefunded
    }
}

pub(crate) fn validate_cursor(value: &str) -> Result<(), crate::RampSpendOutcomeError> {
    validate_bounded_text(value, "cursor", MAX_CURSOR_BYTES)
}

pub(crate) fn validate_high_water(value: &str) -> Result<(), crate::RampSpendOutcomeError> {
    validate_bounded_text(value, "high-water mark", MAX_CURSOR_BYTES)
}

pub(crate) fn validate_event_type(value: &str) -> Result<(), crate::RampSpendOutcomeError> {
    validate_bounded_text(value, "event type", MAX_EVENT_TYPE_BYTES)
}

pub(crate) fn validate_page_size(value: usize) -> Result<(), crate::RampSpendOutcomeError> {
    if value == 0 || value > MAX_PAGE_SIZE {
        return Err(crate::RampSpendOutcomeError::InvalidPageSize);
    }
    Ok(())
}
