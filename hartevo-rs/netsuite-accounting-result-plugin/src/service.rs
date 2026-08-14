//! Mission-scoped accounting-result proposal service.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION, NETSUITE_ACCOUNTING_RESULT_PLUGIN_ID,
    NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION, NETSUITE_ACCOUNTING_RESULT_SCHEMA_VERSION,
    NETSUITE_ACCOUNTING_RESULT_SERVICE_ID, NETSUITE_ACCOUNTING_RESULT_SERVICE_NAME,
    NETSUITE_PROVIDER_ID,
    model::{
        Digest, ModelError, NetSuiteBounds, NetSuitePayload, NetSuiteReadOperation, NetSuiteScope,
        NetSuiteSelectedRecordSummary, NetSuiteSuiteQlField, NetSuiteSuiteQlStatement,
        ObservationWindow, Revision, SecretReference, digest_serializable,
    },
    provider::{
        NetSuiteProviderDefinition, NetSuiteProviderError, NetSuiteReadFailure,
        NetSuiteReadReceipt, NetSuiteRetryEvidence, NetSuiteSuiteTalkProvider,
        NetSuiteTransportProvenance,
    },
    transport::{NetSuiteGetRequest, NetSuiteTransportErrorKind},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteServiceDefinition {
    pub schema_version: String,
    pub service_id: String,
    pub implementation: String,
    pub version: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub live_execution: bool,
    pub writes: bool,
}

impl Default for NetSuiteServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: NETSUITE_ACCOUNTING_RESULT_SCHEMA_VERSION.to_owned(),
            service_id: NETSUITE_ACCOUNTING_RESULT_SERVICE_ID.to_owned(),
            implementation: NETSUITE_ACCOUNTING_RESULT_SERVICE_NAME.to_owned(),
            version: NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "revoke_secret".to_owned(),
                "read_record_metadata".to_owned(),
                "read_record_collection".to_owned(),
                "read_selected_record".to_owned(),
                "compile_parameterized_suiteql_proposal".to_owned(),
                "record_suiteql_proposal".to_owned(),
                "consume_suiteql_proposal".to_owned(),
            ],
            read_only: true,
            live_execution: false,
            writes: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuiteRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NetSuiteServiceError {
    #[error("NetSuite scope or registration binding is invalid: {0}")]
    ScopeMismatch(String),
    #[error("NetSuite registration is revoked or stale")]
    RegistrationRevoked,
    #[error("NetSuite SecretReference is revoked")]
    SecretRevoked,
    #[error("NetSuite consent does not permit the requested operation")]
    ConsentDenied,
    #[error("NetSuite proposal request is invalid: {0}")]
    InvalidRequest(String),
    #[error("NetSuite evidence is stale or tampered")]
    StaleEvidence,
    #[error("NetSuite SuiteQL proposal is invalid")]
    InvalidSuiteQl,
    #[error(transparent)]
    Provider(#[from] NetSuiteProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_definition_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub contract_digest: Digest,
    pub state: NetSuiteRegistrationState,
    pub registration_digest: Digest,
}

impl NetSuiteRegistration {
    pub fn new(
        scope: &NetSuiteScope,
        secret_reference: &SecretReference,
        provider: &NetSuiteProviderDefinition,
        contract_digest: Digest,
    ) -> Result<Self, NetSuiteServiceError> {
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "SecretReference is bound to a different scope".to_owned(),
            ));
        }
        if secret_reference.is_revoked() {
            return Err(NetSuiteServiceError::SecretRevoked);
        }
        if provider.provider_id != NETSUITE_PROVIDER_ID
            || provider.native
            || provider.connected
            || provider.live_execution
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "only a non-native, non-connected provider may register".to_owned(),
            ));
        }
        let mut registration = Self {
            plugin_id: NETSUITE_ACCOUNTING_RESULT_PLUGIN_ID.to_owned(),
            plugin_version: NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: NETSUITE_ACCOUNTING_RESULT_SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_definition_digest: provider.provider_digest(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent_scope().digest().clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.credential_revision(),
            contract_digest,
            state: NetSuiteRegistrationState::Active,
            registration_digest: Digest::from_text("uninitialized-netsuite-registration"),
        };
        registration.registration_digest = registration.recompute_digest()?;
        Ok(registration)
    }

    pub fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
        let material = NetSuiteRegistrationMaterial {
            plugin_id: self.plugin_id.clone(),
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            service_id: self.service_id.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version.clone(),
            provider_definition_digest: self.provider_definition_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            secret_reference_digest: self.secret_reference_digest.clone(),
            credential_revision: self.credential_revision,
            contract_digest: self.contract_digest.clone(),
            state: self.state,
        };
        digest_serializable(&material).map_err(NetSuiteServiceError::Model)
    }

    pub fn validate_digest(&self) -> Result<(), NetSuiteServiceError> {
        if self.registration_digest == self.recompute_digest()? {
            Ok(())
        } else {
            Err(NetSuiteServiceError::StaleEvidence)
        }
    }

    pub fn revoke(&mut self) -> Result<(), NetSuiteServiceError> {
        if self.state == NetSuiteRegistrationState::Revoked {
            return Err(NetSuiteServiceError::RegistrationRevoked);
        }
        self.state = NetSuiteRegistrationState::Revoked;
        self.registration_digest = self.recompute_digest()?;
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, NetSuiteRegistrationState::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetSuiteRegistrationMaterial {
    plugin_id: String,
    plugin_version: String,
    contract_version: String,
    service_id: String,
    provider_id: String,
    provider_version: String,
    provider_definition_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    consent_digest: Digest,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    contract_digest: Digest,
    state: NetSuiteRegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteAccountingProposalRequest {
    operations: Vec<NetSuiteReadOperation>,
    bounds: NetSuiteBounds,
    window: ObservationWindow,
    work_product_revision: Revision,
    request_digest: Digest,
}

impl NetSuiteAccountingProposalRequest {
    pub fn new(
        operations: impl IntoIterator<Item = NetSuiteReadOperation>,
        bounds: NetSuiteBounds,
        window: ObservationWindow,
        work_product_revision: Revision,
    ) -> Result<Self, NetSuiteServiceError> {
        let operations = operations.into_iter().collect::<Vec<_>>();
        if operations.is_empty() || operations.len() > 3 || operations.iter().any(|op| !op.is_get())
        {
            return Err(NetSuiteServiceError::InvalidRequest(
                "only bounded SuiteTalk GET operations may be requested here".to_owned(),
            ));
        }
        let mut unique = BTreeSet::new();
        if operations
            .iter()
            .any(|operation| !unique.insert(*operation))
        {
            return Err(NetSuiteServiceError::InvalidRequest(
                "duplicate read operation".to_owned(),
            ));
        }
        let mut request = Self {
            operations,
            bounds,
            window,
            work_product_revision,
            request_digest: Digest::from_text("uninitialized-netsuite-request"),
        };
        request.request_digest = request.recompute_digest()?;
        Ok(request)
    }

    pub fn operations(&self) -> &[NetSuiteReadOperation] {
        &self.operations
    }

    pub fn bounds(&self) -> &NetSuiteBounds {
        &self.bounds
    }

    pub fn window(&self) -> &ObservationWindow {
        &self.window
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
        let material = NetSuiteProposalRequestMaterial {
            operations: self.operations.clone(),
            bounds: self.bounds.clone(),
            window: self.window.clone(),
            work_product_revision: self.work_product_revision,
        };
        digest_serializable(&material).map_err(NetSuiteServiceError::Model)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetSuiteProposalRequestMaterial {
    operations: Vec<NetSuiteReadOperation>,
    bounds: NetSuiteBounds,
    window: ObservationWindow,
    work_product_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuiteAccountingStatus {
    Observed,
    Partial,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteRedactions {
    pub raw_provider_payload: bool,
    pub raw_financial_values: bool,
    pub customer_vendor_identity: bool,
    pub contact_data: bool,
    pub addresses: bool,
    pub bank_tax_payment_identifiers: bool,
    pub transaction_memos: bool,
    pub credentials: bool,
}

impl Default for NetSuiteRedactions {
    fn default() -> Self {
        Self {
            raw_provider_payload: true,
            raw_financial_values: true,
            customer_vendor_identity: true,
            contact_data: true,
            addresses: true,
            bank_tax_payment_identifiers: true,
            transaction_memos: true,
            credentials: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteAccountingEvidence {
    pub provenance: NetSuiteTransportProvenance,
    pub metadata: Option<crate::model::NetSuiteRecordMetadata>,
    pub collections: Vec<crate::model::NetSuiteCollectionSummary>,
    pub selected_record: Option<NetSuiteSelectedRecordSummary>,
    pub receipts: Vec<NetSuiteReadReceipt>,
    pub retries: Vec<NetSuiteRetryEvidence>,
    pub failures: Vec<NetSuiteReadFailure>,
    pub bounded_truncation: bool,
    pub redactions: NetSuiteRedactions,
    pub evidence_digest: Digest,
}

impl NetSuiteAccountingEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        provenance: NetSuiteTransportProvenance,
        metadata: Option<crate::model::NetSuiteRecordMetadata>,
        collections: Vec<crate::model::NetSuiteCollectionSummary>,
        selected_record: Option<NetSuiteSelectedRecordSummary>,
        receipts: Vec<NetSuiteReadReceipt>,
        retries: Vec<NetSuiteRetryEvidence>,
        failures: Vec<NetSuiteReadFailure>,
        bounded_truncation: bool,
    ) -> Result<Self, NetSuiteServiceError> {
        let mut evidence = Self {
            provenance,
            metadata,
            collections,
            selected_record,
            receipts,
            retries,
            failures,
            bounded_truncation,
            redactions: NetSuiteRedactions::default(),
            evidence_digest: Digest::from_text("uninitialized-netsuite-evidence"),
        };
        evidence.evidence_digest = evidence.recompute_digest()?;
        Ok(evidence)
    }

    pub fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
        let material = NetSuiteEvidenceMaterial {
            provenance: self.provenance,
            metadata: self.metadata.clone(),
            collections: self.collections.clone(),
            selected_record: self.selected_record.clone(),
            receipts: self.receipts.clone(),
            retries: self.retries.clone(),
            failures: self.failures.clone(),
            bounded_truncation: self.bounded_truncation,
            redactions: self.redactions.clone(),
        };
        digest_serializable(&material).map_err(NetSuiteServiceError::Model)
    }

    fn validate(
        &self,
        scope: &NetSuiteScope,
        credential_revision: Revision,
    ) -> Result<(), NetSuiteServiceError> {
        if self.evidence_digest != self.recompute_digest()? {
            return Err(NetSuiteServiceError::StaleEvidence);
        }
        if self.redactions != NetSuiteRedactions::default()
            || self
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.record_type() != scope.record_type())
            || self
                .collections
                .iter()
                .any(|collection| collection.record_type() != scope.record_type())
            || self
                .selected_record
                .as_ref()
                .is_some_and(|selected| selected.record_type() != scope.record_type())
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "evidence does not match the typed scope".to_owned(),
            ));
        }
        for receipt in &self.receipts {
            if receipt.scope_digest != scope.digest()
                || receipt.permission_digest != *scope.permission_digest()
                || receipt.consent_digest != *scope.consent_scope().digest()
                || receipt.credential_revision != credential_revision
            {
                return Err(NetSuiteServiceError::ScopeMismatch(
                    "receipt fence does not match the typed scope".to_owned(),
                ));
            }
        }
        if let Some(metadata) = &self.metadata {
            metadata.validate_digest()?;
        }
        for collection in &self.collections {
            collection.validate_digest()?;
        }
        if let Some(selected) = &self.selected_record {
            selected.validate_digest()?;
            if let Some(record_id) = scope.record_id()
                && selected.record_id_digest() != &Digest::from_text(record_id.as_str())
            {
                return Err(NetSuiteServiceError::ScopeMismatch(
                    "selected record digest does not match the scoped record id".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetSuiteEvidenceMaterial {
    provenance: NetSuiteTransportProvenance,
    metadata: Option<crate::model::NetSuiteRecordMetadata>,
    collections: Vec<crate::model::NetSuiteCollectionSummary>,
    selected_record: Option<NetSuiteSelectedRecordSummary>,
    receipts: Vec<NetSuiteReadReceipt>,
    retries: Vec<NetSuiteRetryEvidence>,
    failures: Vec<NetSuiteReadFailure>,
    bounded_truncation: bool,
    redactions: NetSuiteRedactions,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteAccountingProposal {
    pub request: NetSuiteAccountingProposalRequest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub status: NetSuiteAccountingStatus,
    pub evidence: NetSuiteAccountingEvidence,
    pub connected: bool,
    pub native_evidence: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub proposal_digest: Digest,
}

impl NetSuiteAccountingProposal {
    fn new(
        request: NetSuiteAccountingProposalRequest,
        registration: &NetSuiteRegistration,
        scope: &NetSuiteScope,
        status: NetSuiteAccountingStatus,
        evidence: NetSuiteAccountingEvidence,
    ) -> Result<Self, NetSuiteServiceError> {
        let mut proposal = Self {
            request,
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.digest(),
            status,
            evidence,
            connected: false,
            native_evidence: false,
            outcome_authority: false,
            work_product_adoption: false,
            proposal_digest: Digest::from_text("uninitialized-netsuite-proposal"),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    pub fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
        let material = NetSuiteProposalMaterial {
            request: self.request.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            status: self.status,
            evidence: self.evidence.clone(),
            connected: self.connected,
            native_evidence: self.native_evidence,
            outcome_authority: self.outcome_authority,
            work_product_adoption: self.work_product_adoption,
        };
        digest_serializable(&material).map_err(NetSuiteServiceError::Model)
    }

    pub fn validate_bindings(
        &self,
        scope: &NetSuiteScope,
        registration: &NetSuiteRegistration,
    ) -> Result<(), NetSuiteServiceError> {
        if !registration.is_active()
            || registration.validate_digest().is_err()
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != scope.digest()
            || self.request.request_digest != self.request.recompute_digest()?
            || self.proposal_digest != self.recompute_digest()?
        {
            return Err(NetSuiteServiceError::StaleEvidence);
        }
        self.evidence
            .validate(scope, registration.credential_revision)
    }

    pub const fn is_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetSuiteProposalMaterial {
    request: NetSuiteAccountingProposalRequest,
    registration_digest: Digest,
    scope_digest: Digest,
    status: NetSuiteAccountingStatus,
    evidence: NetSuiteAccountingEvidence,
    connected: bool,
    native_evidence: bool,
    outcome_authority: bool,
    work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteSuiteQlProposal {
    pub statement: NetSuiteSuiteQlStatement,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_definition_digest: Digest,
    pub provenance: NetSuiteTransportProvenance,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub executed: bool,
    pub connected: bool,
    pub native: bool,
    pub proposal_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetSuiteSuiteQlProposalMaterial {
    statement: NetSuiteSuiteQlStatement,
    provider_id: String,
    provider_version: String,
    provider_definition_digest: Digest,
    provenance: NetSuiteTransportProvenance,
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    registration_digest: Digest,
    executed: bool,
    connected: bool,
    native: bool,
}

impl NetSuiteSuiteQlProposal {
    fn new(
        statement: NetSuiteSuiteQlStatement,
        provider: &NetSuiteProviderDefinition,
        scope: &NetSuiteScope,
        registration: &NetSuiteRegistration,
    ) -> Result<Self, NetSuiteServiceError> {
        let mut proposal = Self {
            statement,
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_definition_digest: provider.provider_digest(),
            provenance: provider.provenance,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_scope().digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            executed: false,
            connected: false,
            native: false,
            proposal_digest: Digest::from_text("uninitialized-netsuite-suiteql-proposal"),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    pub fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
        let material = NetSuiteSuiteQlProposalMaterial {
            statement: self.statement.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version.clone(),
            provider_definition_digest: self.provider_definition_digest.clone(),
            provenance: self.provenance,
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            executed: self.executed,
            connected: self.connected,
            native: self.native,
        };
        digest_serializable(&material).map_err(NetSuiteServiceError::Model)
    }

    pub fn validate_bindings(
        &self,
        scope: &NetSuiteScope,
        registration: &NetSuiteRegistration,
    ) -> Result<(), NetSuiteServiceError> {
        if !registration.is_active()
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != scope.digest()
            || self.permission_digest != *scope.permission_digest()
            || self.consent_digest != *scope.consent_scope().digest()
            || self.executed
            || self.connected
            || self.native
            || self.proposal_digest != self.recompute_digest()?
        {
            return Err(NetSuiteServiceError::StaleEvidence);
        }
        self.statement.validate_digest()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteSuiteQlRecord {
    pub proposal_digest: Digest,
    pub statement_digest: Digest,
    pub provider_id: String,
    pub provenance: NetSuiteTransportProvenance,
    pub scope_digest: Digest,
    pub recorded_at: DateTime<Utc>,
    pub executed: bool,
    pub connected: bool,
    pub native: bool,
    pub record_digest: Digest,
}

#[derive(Debug)]
pub struct NetSuiteAccountingResultService<T> {
    scope: NetSuiteScope,
    secret_reference: SecretReference,
    provider: NetSuiteSuiteTalkProvider<T>,
    registration: NetSuiteRegistration,
}

impl<T: crate::transport::NetSuiteTransport> NetSuiteAccountingResultService<T> {
    pub fn new(
        scope: NetSuiteScope,
        secret_reference: SecretReference,
        provider: NetSuiteSuiteTalkProvider<T>,
    ) -> Result<Self, NetSuiteServiceError> {
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "SecretReference scope digest does not match service scope".to_owned(),
            ));
        }
        let registration = NetSuiteRegistration::new(
            &scope,
            &secret_reference,
            provider.definition(),
            crate::contract_digest(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn definition(&self) -> NetSuiteServiceDefinition {
        NetSuiteServiceDefinition::default()
    }

    pub fn scope(&self) -> &NetSuiteScope {
        &self.scope
    }

    pub fn registration(&self) -> &NetSuiteRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &NetSuiteSuiteTalkProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut NetSuiteSuiteTalkProvider<T> {
        &mut self.provider
    }

    pub fn revoke_registration(&mut self) -> Result<(), NetSuiteServiceError> {
        self.registration.revoke()
    }

    pub fn revoke_secret(&mut self) -> Result<(), NetSuiteServiceError> {
        self.secret_reference
            .revoke()
            .map_err(NetSuiteServiceError::Model)
    }

    pub fn propose(
        &mut self,
        request: NetSuiteAccountingProposalRequest,
        at: DateTime<Utc>,
    ) -> Result<NetSuiteAccountingProposal, NetSuiteServiceError> {
        self.ensure_active()?;
        if request.window() != self.scope.observation_window()
            || request.work_product_revision() != self.scope.work_product_revision()
            || request.request_digest != request.recompute_digest()?
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "proposal request window or work-product revision drifted".to_owned(),
            ));
        }
        for operation in request.operations() {
            if !self.scope.consent_scope().permits(*operation, at) {
                return Err(NetSuiteServiceError::ConsentDenied);
            }
        }
        let scope = self.scope.clone();
        let secret_reference = self.secret_reference.clone();
        let provenance = self.provider.provenance();
        let bounds = request.bounds().clone();
        let mut metadata = None;
        let mut collections = Vec::new();
        let mut selected_record = None;
        let mut receipts = Vec::new();
        let mut retries = Vec::new();
        let mut failures = Vec::new();
        let mut bounded_truncation = false;

        for operation in request.operations() {
            let mut page_number = 1_u16;
            let mut cursor = None;
            loop {
                let get_request = NetSuiteGetRequest::new(
                    &scope,
                    &secret_reference,
                    *operation,
                    bounds.clone(),
                    request.window().clone(),
                    page_number,
                    cursor.clone(),
                )?;
                match self.provider.read(&get_request, bounds.clone()) {
                    Ok(read) => {
                        receipts.push(read.receipt);
                        retries.extend(read.retries);
                        let next_cursor = read.response.next_cursor().cloned();
                        match read.response.payload().clone() {
                            NetSuitePayload::RecordMetadata(value) => {
                                metadata = Some(value);
                                break;
                            }
                            NetSuitePayload::RecordCollection(value) => {
                                let has_more = value.has_more();
                                collections.push(value);
                                if has_more {
                                    if page_number >= bounds.max_pages() {
                                        bounded_truncation = true;
                                        break;
                                    }
                                    cursor = next_cursor;
                                    page_number = page_number.saturating_add(1);
                                } else {
                                    break;
                                }
                            }
                            NetSuitePayload::SelectedRecord(value) => {
                                selected_record = Some(value);
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        failures.push(failure_from_error(*operation, provenance, &error));
                        break;
                    }
                }
            }
        }
        let status = if receipts.is_empty() {
            NetSuiteAccountingStatus::ProviderUnknown
        } else if !failures.is_empty() || bounded_truncation {
            NetSuiteAccountingStatus::Partial
        } else {
            NetSuiteAccountingStatus::Observed
        };
        let evidence = NetSuiteAccountingEvidence::new(
            provenance,
            metadata,
            collections,
            selected_record,
            receipts,
            retries,
            failures,
            bounded_truncation,
        )?;
        NetSuiteAccountingProposal::new(request, &self.registration, &scope, status, evidence)
    }

    pub fn compile_parameterized_suiteql_proposal(
        &self,
        fields: Vec<NetSuiteSuiteQlField>,
        bounds: NetSuiteBounds,
        window: ObservationWindow,
        at: DateTime<Utc>,
    ) -> Result<NetSuiteSuiteQlProposal, NetSuiteServiceError> {
        self.ensure_active()?;
        if !self
            .scope
            .consent_scope()
            .permits(NetSuiteReadOperation::SuiteQlProposal, at)
        {
            return Err(NetSuiteServiceError::ConsentDenied);
        }
        if window != *self.scope.observation_window() {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "SuiteQL window drifted from the registered scope".to_owned(),
            ));
        }
        let statement = NetSuiteSuiteQlStatement::new(
            self.scope.record_type(),
            fields,
            self.scope.collection_filter().clone(),
            window,
            bounds.max_records(),
        )?;
        NetSuiteSuiteQlProposal::new(
            statement,
            self.provider.definition(),
            &self.scope,
            &self.registration,
        )
    }

    pub fn propose_parameterized_suiteql(
        &self,
        fields: Vec<NetSuiteSuiteQlField>,
        bounds: NetSuiteBounds,
        window: ObservationWindow,
        at: DateTime<Utc>,
    ) -> Result<NetSuiteSuiteQlProposal, NetSuiteServiceError> {
        self.compile_parameterized_suiteql_proposal(fields, bounds, window, at)
    }

    pub fn record_suiteql_proposal(
        &self,
        proposal: &NetSuiteSuiteQlProposal,
        at: DateTime<Utc>,
    ) -> Result<NetSuiteSuiteQlRecord, NetSuiteServiceError> {
        self.ensure_active()?;
        proposal.validate_bindings(&self.scope, &self.registration)?;
        if !self
            .scope
            .consent_scope()
            .permits(NetSuiteReadOperation::SuiteQlProposal, at)
        {
            return Err(NetSuiteServiceError::ConsentDenied);
        }
        let record_digest = Digest::from_fields(
            "netsuite-suiteql-record/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                proposal.statement.query_digest().as_str().to_owned(),
                proposal.scope_digest.as_str().to_owned(),
                at.to_rfc3339(),
                "executed=false".to_owned(),
            ],
        );
        Ok(NetSuiteSuiteQlRecord {
            proposal_digest: proposal.proposal_digest.clone(),
            statement_digest: proposal.statement.query_digest().clone(),
            provider_id: proposal.provider_id.clone(),
            provenance: proposal.provenance,
            scope_digest: proposal.scope_digest.clone(),
            recorded_at: at,
            executed: false,
            connected: false,
            native: false,
            record_digest,
        })
    }

    fn ensure_active(&self) -> Result<(), NetSuiteServiceError> {
        if !self.registration.is_active() {
            return Err(NetSuiteServiceError::RegistrationRevoked);
        }
        self.registration.validate_digest()?;
        if self.secret_reference.is_revoked() {
            return Err(NetSuiteServiceError::SecretRevoked);
        }
        if self.secret_reference.scope_digest() != &self.scope.digest()
            || self.registration.scope_digest != self.scope.digest()
            || self.registration.permission_digest != *self.scope.permission_digest()
            || self.registration.consent_digest != *self.scope.consent_scope().digest()
            || self.registration.credential_revision != self.secret_reference.credential_revision()
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "registration or credential fence drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

fn failure_from_error(
    operation: NetSuiteReadOperation,
    provenance: NetSuiteTransportProvenance,
    error: &NetSuiteProviderError,
) -> NetSuiteReadFailure {
    match error {
        NetSuiteProviderError::Transport(transport_error) => NetSuiteReadFailure {
            operation,
            kind: transport_error.kind(),
            status_code: transport_error.status_code(),
            diagnostic_digest: transport_error.diagnostic_digest().clone(),
            provenance,
        },
        other => NetSuiteReadFailure {
            operation,
            kind: NetSuiteTransportErrorKind::InvalidResponse,
            status_code: None,
            diagnostic_digest: Digest::from_text(other.to_string()),
            provenance,
        },
    }
}
