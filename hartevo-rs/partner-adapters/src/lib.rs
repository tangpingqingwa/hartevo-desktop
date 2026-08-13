//! Provider-specific official partner-network adapters for VM-06/VM-11.
//!
//! This crate deliberately owns only the partner-network vertical contract:
//! typed network identities, account/program scope, provider-native reads,
//! signed callbacks and deterministic fixture worlds. The generic Connector
//! SDK lifecycle remains an integration boundary owned by CONN-01 (#67).
//! It does not create Hartevo Opt-in consent, employment, escrow, or hiring
//! payout facts; those remain separate domain/effect-broker concerns.

mod callback;
mod contract;
mod fixture;
mod ids;
mod replay;
mod state;
mod support;

pub mod awin;
pub mod cj;
pub mod impact;

pub use callback::{
    CallbackChannel, CallbackDisposition, CallbackEvent, CallbackEventKind, CallbackObservation,
    CallbackRequest, CallbackSignatureScheme,
};
pub use contract::{
    ActionRecord, ActionState, AuthorizationGrant, AuthorizationObservation, AuthorizationState,
    BlockedEnvironmentReason, ClickRecord, CommissionRecord, CommissionState, ContractRecord,
    ContractState, ConversionRecord, ConversionState, EvidenceLevel, FixtureScenario,
    NetworkCapability, NetworkProbeObservation, NetworkProbeRequest, NetworkProbeStatus,
    NetworkProvenance, NetworkProvider, NetworkReadData, NetworkReadObservation,
    NetworkReadRequest, NetworkResource, NetworkScope, OpaqueSecretReference,
    PARTNER_NETWORK_CONTRACT_SCHEMA_VERSION, PARTNER_NETWORK_CONTRACT_VERSION,
    PartnerNetworkAdapter, PartnerNetworkError, PartnerRecord, PartnerRelationshipState,
    PayoutRecord, PayoutState, ProgramExpectation, ProgramRecord, ProgramState, ReadCursor,
    ReadPage, ReportRecord, ReportRow, ReportSettlementState, ReversalRecord, ReversalState,
    SettlementPeriod, TrackingLinkRecord,
};
pub use ids::{
    ActionId, CallbackEventId, ClickId, CommissionId, ContractId, ConversionId, LinkId,
    NetworkAccountId, NetworkIdentityError, NetworkOrderId, PartnerId, PayoutId, ProgramId,
    ReportId, ReversalId,
};

#[cfg(test)]
mod tests;
