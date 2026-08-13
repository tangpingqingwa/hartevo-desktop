use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{CurrencyCode, Money};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ids::{
    ActionId, ClickId, CommissionId, ContractId, ConversionId, LinkId, NetworkAccountId,
    NetworkOrderId, PartnerId, PayoutId, ProgramId, ReportId, ReversalId,
};

pub const PARTNER_NETWORK_CONTRACT_SCHEMA_VERSION: &str = "hartevo-partner-network-contract/v1";
pub const PARTNER_NETWORK_CONTRACT_VERSION: &str = "partner-network-e1/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProvider {
    Impact,
    Awin,
    Cj,
}

impl NetworkProvider {
    pub const ALL: [Self; 3] = [Self::Impact, Self::Awin, Self::Cj];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Impact => "impact",
            Self::Awin => "awin",
            Self::Cj => "cj",
        }
    }
}

impl fmt::Display for NetworkProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProvenance {
    Fixture,
    ControlledProvider,
    ProductionProvider,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    E1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCapability {
    Probe,
    PartnerRead,
    PartnerEngage,
    OutcomeIngest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkScope {
    pub tenant_id: String,
    pub project_id: String,
    pub account_id: NetworkAccountId,
    pub program_id: Option<ProgramId>,
}

impl NetworkScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        account_id: NetworkAccountId,
        program_id: Option<ProgramId>,
    ) -> Result<Self, PartnerNetworkError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            account_id,
            program_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account_scope(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        account_id: NetworkAccountId,
    ) -> Result<Self, PartnerNetworkError> {
        Self::new(tenant_id, project_id, account_id, None)
    }

    pub fn program_scope(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        account_id: NetworkAccountId,
        program_id: ProgramId,
    ) -> Result<Self, PartnerNetworkError> {
        Self::new(tenant_id, project_id, account_id, Some(program_id))
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.tenant_id.trim().is_empty()
            || self.project_id.trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
        {
            return Err(PartnerNetworkError::InvalidScope);
        }
        if self
            .tenant_id
            .chars()
            .chain(self.project_id.chars())
            .chain(self.account_id.as_str().chars())
            .any(char::is_control)
        {
            return Err(PartnerNetworkError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_digest(self).expect("NetworkScope is serializable")
    }

    pub fn is_account_scope(&self) -> bool {
        self.program_id.is_none()
    }

    pub fn covers(&self, requested: &Self) -> bool {
        self.tenant_id == requested.tenant_id
            && self.project_id == requested.project_id
            && self.account_id == requested.account_id
            && (self.program_id.is_none() || self.program_id == requested.program_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueSecretReference {
    reference_id: String,
    revision: u64,
}

impl OpaqueSecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, PartnerNetworkError> {
        let reference = Self {
            reference_id: reference_id.into(),
            revision,
        };
        if reference.reference_id.trim().is_empty()
            || reference.reference_id.chars().any(char::is_control)
            || reference.revision == 0
        {
            return Err(PartnerNetworkError::InvalidAuthorizationReference);
        }
        Ok(reference)
    }

    pub fn fixture() -> Self {
        Self {
            reference_id: "fixture:opaque-secret-reference".into(),
            revision: 1,
        }
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationState {
    Missing,
    Granted,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationGrant {
    pub scope: NetworkScope,
    pub secret_reference: OpaqueSecretReference,
    pub capabilities: BTreeSet<NetworkCapability>,
    pub expires_at: DateTime<Utc>,
    pub provenance: NetworkProvenance,
}

impl AuthorizationGrant {
    pub fn fixture(scope: NetworkScope, expires_at: DateTime<Utc>) -> Self {
        Self {
            scope,
            secret_reference: OpaqueSecretReference::fixture(),
            capabilities: BTreeSet::from([
                NetworkCapability::Probe,
                NetworkCapability::PartnerRead,
                NetworkCapability::OutcomeIngest,
            ]),
            expires_at,
            provenance: NetworkProvenance::Fixture,
        }
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.validate_at(Utc::now())
    }

    pub(crate) fn validate_at(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        if self.capabilities.is_empty() || self.expires_at <= observed_at {
            return Err(PartnerNetworkError::InvalidAuthorizationGrant);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationObservation {
    pub provider: NetworkProvider,
    pub scope: NetworkScope,
    pub state: AuthorizationState,
    pub provenance: Option<NetworkProvenance>,
    pub reference_revision: Option<u64>,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramExpectation {
    pub program_id: ProgramId,
    pub revision: u64,
    pub terms_digest: String,
}

impl ProgramExpectation {
    pub fn new(
        program_id: ProgramId,
        revision: u64,
        terms_digest: impl Into<String>,
    ) -> Result<Self, PartnerNetworkError> {
        let expectation = Self {
            program_id,
            revision,
            terms_digest: terms_digest.into(),
        };
        expectation.validate()?;
        Ok(expectation)
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.revision == 0 || !is_sha256(&self.terms_digest) {
            return Err(PartnerNetworkError::InvalidProgramExpectation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProbeRequest {
    pub scope: NetworkScope,
    pub expected_program: Option<ProgramExpectation>,
    pub requested_capabilities: BTreeSet<NetworkCapability>,
    pub observed_at: DateTime<Utc>,
}

impl NetworkProbeRequest {
    pub fn new(scope: NetworkScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope,
            expected_program: None,
            requested_capabilities: BTreeSet::from([NetworkCapability::Probe]),
            observed_at,
        }
    }

    pub fn for_program(
        scope: NetworkScope,
        expected_program: ProgramExpectation,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            scope,
            expected_program: Some(expected_program),
            requested_capabilities: BTreeSet::from([
                NetworkCapability::Probe,
                NetworkCapability::PartnerRead,
            ]),
            observed_at,
        }
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        if let Some(expected_program) = &self.expected_program {
            expected_program.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProbeStatus {
    Reachable,
    AuthorizationRequired,
    ScopeRevoked,
    ProgramDrift,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProbeObservation {
    pub provider: NetworkProvider,
    pub scope: NetworkScope,
    pub status: NetworkProbeStatus,
    pub provenance: NetworkProvenance,
    pub evidence_level: EvidenceLevel,
    pub claim_authority: &'static str,
    pub observed_account_id: NetworkAccountId,
    pub observed_program_id: Option<ProgramId>,
    pub program_revision: Option<u64>,
    pub program_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
}

impl NetworkProbeObservation {
    pub fn can_claim_connected(&self) -> bool {
        self.status == NetworkProbeStatus::Reachable
            && self.provenance == NetworkProvenance::ProductionProvider
            && self.claim_authority == "connection_state_only"
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkResource {
    Programs,
    Partners,
    Contracts,
    Links,
    Clicks,
    Conversions,
    Actions,
    Commissions,
    Reversals,
    Payouts,
    Reports,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ReadCursor(String);

impl ReadCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, PartnerNetworkError> {
        let value = value.into();
        let cursor = Self(value);
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.0.trim().is_empty() || self.0.chars().any(char::is_control) {
            return Err(PartnerNetworkError::InvalidReadCursor);
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadPage {
    pub cursor: Option<ReadCursor>,
    pub next_cursor: Option<ReadCursor>,
    pub has_more: bool,
    pub item_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkReadRequest {
    pub scope: NetworkScope,
    pub resource: NetworkResource,
    pub expected_program: Option<ProgramExpectation>,
    pub cursor: Option<ReadCursor>,
    pub limit: u16,
    pub observed_at: DateTime<Utc>,
}

impl NetworkReadRequest {
    pub fn new(scope: NetworkScope, resource: NetworkResource, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope,
            resource,
            expected_program: None,
            cursor: None,
            limit: 100,
            observed_at,
        }
    }

    pub fn for_program(
        scope: NetworkScope,
        resource: NetworkResource,
        expected_program: ProgramExpectation,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            scope,
            resource,
            expected_program: Some(expected_program),
            cursor: None,
            limit: 100,
            observed_at,
        }
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        if let Some(expected_program) = &self.expected_program {
            expected_program.validate()?;
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        if self.limit == 0 || self.limit > 500 {
            return Err(PartnerNetworkError::InvalidReadLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramState {
    Active,
    Paused,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartnerRelationshipState {
    Applied,
    Active,
    Suspended,
    Terminated,
    NotJoined,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractState {
    Pending,
    Active,
    Expired,
    Terminated,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionState {
    Pending,
    Approved,
    Declined,
    Refunded,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    Pending,
    Approved,
    Reversed,
    Paid,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommissionState {
    Pending,
    Accrued,
    Reversed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReversalState {
    Pending,
    Applied,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutState {
    Pending,
    Completed,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSettlementState {
    Current,
    RecalculationRequired,
    Outstanding,
    Paid,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementPeriod {
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
}

impl SettlementPeriod {
    pub fn new(
        started_at: DateTime<Utc>,
        ended_at: DateTime<Utc>,
    ) -> Result<Self, PartnerNetworkError> {
        if started_at >= ended_at {
            return Err(PartnerNetworkError::InvalidSettlementPeriod);
        }
        Ok(Self {
            started_at,
            ended_at,
        })
    }
}

macro_rules! source_record {
    ($name:ident { $($field:ident : $type:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            $(pub $field: $type,)*
            pub observed_at: DateTime<Utc>,
            pub source_digest: String,
        }
    };
}

source_record!(ProgramRecord {
    account_id: NetworkAccountId,
    id: ProgramId,
    revision: u64,
    state: ProgramState,
    terms_digest: String,
});

source_record!(PartnerRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: PartnerId,
    relationship: PartnerRelationshipState,
    display_name_digest: String,
});

source_record!(ContractRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ContractId,
    partner_id: PartnerId,
    state: ContractState,
    currency: CurrencyCode,
    terms_digest: String,
    effective_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
});

source_record!(TrackingLinkRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: LinkId,
    partner_id: PartnerId,
    destination_digest: String,
    tracking_reference_digest: String,
    active: bool,
});

source_record!(ClickRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ClickId,
    link_id: LinkId,
    occurred_at: DateTime<Utc>,
});

source_record!(ConversionRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ConversionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    click_id: Option<ClickId>,
    action_id: Option<ActionId>,
    state: ConversionState,
    amount: Money,
    occurred_at: DateTime<Utc>,
});

source_record!(ActionRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ActionId,
    conversion_id: ConversionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    click_id: Option<ClickId>,
    state: ActionState,
    commission_id: Option<CommissionId>,
    amount: Money,
    occurred_at: DateTime<Utc>,
});

source_record!(CommissionRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: CommissionId,
    action_id: ActionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    state: CommissionState,
    amount: Money,
    occurred_at: DateTime<Utc>,
});

source_record!(ReversalRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ReversalId,
    commission_id: CommissionId,
    action_id: ActionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    state: ReversalState,
    amount: Money,
    reason_digest: String,
    occurred_at: DateTime<Utc>,
});

source_record!(PayoutRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: PayoutId,
    partner_id: PartnerId,
    state: PayoutState,
    amount: Money,
    period: SettlementPeriod,
    occurred_at: DateTime<Utc>,
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRow {
    pub action_id: Option<ActionId>,
    pub conversion_id: Option<ConversionId>,
    pub commission_id: Option<CommissionId>,
    pub reversal_id: Option<ReversalId>,
    pub payout_id: Option<PayoutId>,
    pub amount: Option<Money>,
    pub occurred_at: DateTime<Utc>,
    pub source_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRecord {
    pub account_id: NetworkAccountId,
    pub program_id: ProgramId,
    pub id: ReportId,
    pub period: SettlementPeriod,
    pub settlement_state: ReportSettlementState,
    pub rows: Vec<ReportRow>,
    pub commissions: Vec<CommissionRecord>,
    pub reversals: Vec<ReversalRecord>,
    pub payouts: Vec<PayoutRecord>,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "resource")]
pub enum NetworkReadData {
    Programs { records: Vec<ProgramRecord> },
    Partners { records: Vec<PartnerRecord> },
    Contracts { records: Vec<ContractRecord> },
    Links { records: Vec<TrackingLinkRecord> },
    Clicks { records: Vec<ClickRecord> },
    Conversions { records: Vec<ConversionRecord> },
    Actions { records: Vec<ActionRecord> },
    Commissions { records: Vec<CommissionRecord> },
    Reversals { records: Vec<ReversalRecord> },
    Payouts { records: Vec<PayoutRecord> },
    Reports { records: Vec<ReportRecord> },
}

impl NetworkReadData {
    pub const fn resource(&self) -> NetworkResource {
        match self {
            Self::Programs { .. } => NetworkResource::Programs,
            Self::Partners { .. } => NetworkResource::Partners,
            Self::Contracts { .. } => NetworkResource::Contracts,
            Self::Links { .. } => NetworkResource::Links,
            Self::Clicks { .. } => NetworkResource::Clicks,
            Self::Conversions { .. } => NetworkResource::Conversions,
            Self::Actions { .. } => NetworkResource::Actions,
            Self::Commissions { .. } => NetworkResource::Commissions,
            Self::Reversals { .. } => NetworkResource::Reversals,
            Self::Payouts { .. } => NetworkResource::Payouts,
            Self::Reports { .. } => NetworkResource::Reports,
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::Programs { records } => records.len(),
            Self::Partners { records } => records.len(),
            Self::Contracts { records } => records.len(),
            Self::Links { records } => records.len(),
            Self::Clicks { records } => records.len(),
            Self::Conversions { records } => records.len(),
            Self::Actions { records } => records.len(),
            Self::Commissions { records } => records.len(),
            Self::Reversals { records } => records.len(),
            Self::Payouts { records } => records.len(),
            Self::Reports { records } => records.len(),
        }
    }

    pub fn program_ids(&self) -> BTreeSet<ProgramId> {
        match self {
            Self::Programs { records } => records.iter().map(|record| record.id.clone()).collect(),
            Self::Partners { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Contracts { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Links { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Clicks { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Conversions { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Actions { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Commissions { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Reversals { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Payouts { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Reports { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate_for(&self, scope: &NetworkScope) -> Result<(), PartnerNetworkError> {
        let account_id = &scope.account_id;
        let program_id = scope.program_id.as_ref();
        let validate = |record_account: &NetworkAccountId,
                        record_program: Option<&ProgramId>,
                        source_digest: &str| {
            if record_account != account_id
                || program_id.is_some_and(|expected| record_program != Some(expected))
                || !is_sha256(source_digest)
            {
                Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch)
            } else {
                Ok(())
            }
        };
        match self {
            Self::Programs { records } => {
                for record in records {
                    validate(&record.account_id, Some(&record.id), &record.source_digest)?;
                }
            }
            Self::Partners { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Contracts { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Links { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Clicks { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Conversions { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Actions { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Commissions { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Reversals { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Payouts { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Reports { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                    for commission in &record.commissions {
                        validate(
                            &commission.account_id,
                            Some(&commission.program_id),
                            &commission.source_digest,
                        )?;
                    }
                    for reversal in &record.reversals {
                        validate(
                            &reversal.account_id,
                            Some(&reversal.program_id),
                            &reversal.source_digest,
                        )?;
                    }
                    for payout in &record.payouts {
                        validate(
                            &payout.account_id,
                            Some(&payout.program_id),
                            &payout.source_digest,
                        )?;
                    }
                    for row in &record.rows {
                        if !is_sha256(&row.source_digest) {
                            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkReadObservation {
    pub provider: NetworkProvider,
    pub scope: NetworkScope,
    pub request: NetworkResource,
    pub data: NetworkReadData,
    pub page: ReadPage,
    pub provenance: NetworkProvenance,
    pub evidence_level: EvidenceLevel,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
}

impl NetworkReadObservation {
    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        let expected_source_digest = canonical_digest(&self.data)?;
        if self.request != self.data.resource()
            || self.page.item_count as usize != self.data.item_count()
            || self.source_digest != expected_source_digest
        {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        self.data.validate_for(&self.scope)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureScenario {
    HappyPath,
    DuplicateConversion,
    CrossPeriodRefund,
    CommissionReversal,
    DelayedPayout,
    ScopeRevoked,
    ProgramDrift,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvironmentReason {
    CommercialAuthorizationMissing,
    TransportNotConfigured,
    OfficialApiCapabilityNotEnabled,
    ProductionCallbackVerifierRequired,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PartnerNetworkError {
    #[error("partner network scope is invalid")]
    InvalidScope,
    #[error("partner network authorization reference is invalid")]
    InvalidAuthorizationReference,
    #[error("partner network authorization grant is invalid")]
    InvalidAuthorizationGrant,
    #[error("authorization is required for {provider} scope {scope_digest}")]
    AuthorizationRequired {
        provider: NetworkProvider,
        scope_digest: String,
    },
    #[error("partner network environment is blocked for {provider}: {reason:?}")]
    BlockedEnv {
        provider: NetworkProvider,
        reason: BlockedEnvironmentReason,
    },
    #[error("partner network scope has been revoked")]
    ScopeRevoked,
    #[error("partner network program drifted from the requested revision")]
    ProgramDrift,
    #[error("partner network request scope does not match the adapter")]
    ScopeMismatch,
    #[error("partner network authorization has expired")]
    AuthorizationExpired,
    #[error("partner network read cursor is invalid")]
    InvalidReadCursor,
    #[error("partner network read limit is outside the bounded range")]
    InvalidReadLimit,
    #[error("partner network program expectation is invalid")]
    InvalidProgramExpectation,
    #[error("partner network read scope or source evidence is invalid")]
    ReadScopeOrEvidenceMismatch,
    #[error("partner network callback signature is invalid")]
    InvalidSignature,
    #[error("partner network callback body is malformed")]
    MalformedCallback,
    #[error("partner network callback replay identity is invalid")]
    InvalidReplayIdentity,
    #[error("partner network callback timestamp is outside the replay window")]
    ReplayWindowExpired,
    #[error("partner network callback is out of scope")]
    CallbackScopeMismatch,
    #[error("partner network provider transport is unavailable")]
    ProviderUnavailable,
    #[error("partner network identity is duplicated in one response")]
    DuplicateIdentity,
    #[error("partner network settlement period is invalid")]
    InvalidSettlementPeriod,
    #[error("partner network callback signature scheme is unsupported")]
    UnsupportedCallbackSignature,
}

/// Provider-native typed operations consumed by the SDK bridge. This is not
/// a second connector lifecycle: callers use `hartevo_connector_sdk::ConnectorAdapter`
/// and `ConnectorWorker` for generic auth, probes, reads, callbacks, and
/// revocation; this crate keeps only the network-shaped evidence seam here.
pub trait TypedPartnerNetworkAdapter {
    fn provider(&self) -> NetworkProvider;

    fn authorize(
        &mut self,
        grant: AuthorizationGrant,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError>;

    fn probe(
        &self,
        request: NetworkProbeRequest,
    ) -> Result<NetworkProbeObservation, PartnerNetworkError>;

    fn read(
        &self,
        request: NetworkReadRequest,
    ) -> Result<NetworkReadObservation, PartnerNetworkError>;

    fn handle_callback(
        &mut self,
        request: crate::callback::CallbackRequest<'_>,
    ) -> Result<crate::callback::CallbackObservation, PartnerNetworkError>;

    fn revoke(
        &mut self,
        scope: &NetworkScope,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError>;

    fn accepted_callbacks(&self) -> Vec<crate::callback::CallbackEvent>;
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, PartnerNetworkError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PartnerNetworkError::MalformedCallback)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn fixture_digest(label: &str) -> String {
    digest_bytes(label.as_bytes())
}

pub(crate) fn authorization_observation(
    provider: NetworkProvider,
    grant: &AuthorizationGrant,
    state: AuthorizationState,
    observed_at: DateTime<Utc>,
) -> AuthorizationObservation {
    let binding = format!(
        "{}:{}:{}:{}:{:?}",
        provider,
        grant.scope.digest(),
        grant.secret_reference.revision(),
        grant.expires_at.to_rfc3339(),
        state
    );
    AuthorizationObservation {
        provider,
        scope: grant.scope.clone(),
        state,
        provenance: Some(grant.provenance),
        reference_revision: Some(grant.secret_reference.revision()),
        observed_at,
        evidence_digest: digest_bytes(binding.as_bytes()),
    }
}

pub(crate) fn scope_authorized<'a>(
    provider: NetworkProvider,
    grant: Option<&'a AuthorizationGrant>,
    revoked_scopes: &[NetworkScope],
    scope: &NetworkScope,
    capability: NetworkCapability,
    now: DateTime<Utc>,
) -> Result<&'a AuthorizationGrant, PartnerNetworkError> {
    scope.validate()?;
    if revoked_scopes.iter().any(|revoked| revoked.covers(scope)) {
        return Err(PartnerNetworkError::ScopeRevoked);
    }
    let grant = grant.ok_or_else(|| PartnerNetworkError::AuthorizationRequired {
        provider,
        scope_digest: scope.digest(),
    })?;
    if !grant.scope.covers(scope) {
        return Err(PartnerNetworkError::AuthorizationRequired {
            provider,
            scope_digest: scope.digest(),
        });
    }
    if grant.expires_at <= now {
        return Err(PartnerNetworkError::AuthorizationExpired);
    }
    if !grant.capabilities.contains(&capability) {
        return Err(PartnerNetworkError::AuthorizationRequired {
            provider,
            scope_digest: scope.digest(),
        });
    }
    Ok(grant)
}

pub(crate) fn verify_program_expectation(
    request_scope: &NetworkScope,
    expected: Option<&ProgramExpectation>,
    observed_program_id: Option<&ProgramId>,
    observed_revision: Option<u64>,
    observed_terms_digest: Option<&str>,
) -> Result<(), PartnerNetworkError> {
    if let Some(expected) = expected {
        if request_scope.program_id.as_ref() != Some(&expected.program_id)
            || observed_program_id != Some(&expected.program_id)
            || observed_revision != Some(expected.revision)
            || observed_terms_digest != Some(expected.terms_digest.as_str())
        {
            return Err(PartnerNetworkError::ProgramDrift);
        }
    } else if let Some(requested_program) = &request_scope.program_id
        && observed_program_id != Some(requested_program)
    {
        return Err(PartnerNetworkError::ProgramDrift);
    }
    Ok(())
}

pub(crate) fn validate_scope_record_ids(data: &NetworkReadData) -> Result<(), PartnerNetworkError> {
    let mut ids = BTreeSet::new();
    match data {
        NetworkReadData::Programs { records } => {
            for record in records {
                if !ids.insert(format!("program:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Partners { records } => {
            for record in records {
                if !ids.insert(format!("partner:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Contracts { records } => {
            for record in records {
                if !ids.insert(format!("contract:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Links { records } => {
            for record in records {
                if !ids.insert(format!("link:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Clicks { records } => {
            for record in records {
                if !ids.insert(format!("click:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Conversions { records } => {
            for record in records {
                if !ids.insert(format!("conversion:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Actions { records } => {
            for record in records {
                if !ids.insert(format!("action:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Commissions { records } => {
            for record in records {
                if !ids.insert(format!("commission:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Reversals { records } => {
            for record in records {
                if !ids.insert(format!("reversal:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Payouts { records } => {
            for record in records {
                if !ids.insert(format!("payout:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Reports { records } => {
            for record in records {
                if !ids.insert(format!("report:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn default_fixture_expiry(at: DateTime<Utc>) -> DateTime<Utc> {
    at + Duration::hours(1)
}
