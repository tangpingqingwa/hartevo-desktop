//! Mission-scoped accounting-result proposal service.

use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

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
        is_revocation_tombstoned, tombstone_revocation,
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

impl NetSuiteServiceDefinition {
    pub fn digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(self)
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

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteRegistration {
    plugin_id: String,
    plugin_version: String,
    contract_version: String,
    service_id: String,
    service_version: String,
    service_definition_digest: Digest,
    provider_id: String,
    provider_version: String,
    provider_provenance: NetSuiteTransportProvenance,
    provider_definition_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    consent_digest: Digest,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    contract_digest: Digest,
    state: NetSuiteRegistrationState,
    registration_digest: Digest,
    #[serde(skip)]
    bound_secret_reference: SecretReference,
    #[serde(skip)]
    revocation: Arc<AtomicBool>,
    #[serde(skip)]
    replay_fence: Arc<Mutex<BTreeSet<Digest>>>,
}

impl PartialEq for NetSuiteRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.plugin_id == other.plugin_id
            && self.plugin_version == other.plugin_version
            && self.contract_version == other.contract_version
            && self.service_id == other.service_id
            && self.service_version == other.service_version
            && self.service_definition_digest == other.service_definition_digest
            && self.provider_id == other.provider_id
            && self.provider_version == other.provider_version
            && self.provider_provenance == other.provider_provenance
            && self.provider_definition_digest == other.provider_definition_digest
            && self.permission_digest == other.permission_digest
            && self.scope_digest == other.scope_digest
            && self.consent_digest == other.consent_digest
            && self.secret_reference_digest == other.secret_reference_digest
            && self.credential_revision == other.credential_revision
            && self.contract_digest == other.contract_digest
            && self.state == other.state
            && self.registration_digest == other.registration_digest
    }
}

impl Eq for NetSuiteRegistration {}

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
        if provider.provider_id() != NETSUITE_PROVIDER_ID
            || provider.is_native()
            || provider.is_connected()
            || provider.live_execution()
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "only a non-native, non-connected provider may register".to_owned(),
            ));
        }
        let service = NetSuiteServiceDefinition::default();
        let mut registration = Self {
            plugin_id: NETSUITE_ACCOUNTING_RESULT_PLUGIN_ID.to_owned(),
            plugin_version: NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: NETSUITE_ACCOUNTING_RESULT_SERVICE_ID.to_owned(),
            service_version: service.version.clone(),
            service_definition_digest: service.digest()?,
            provider_id: provider.provider_id().to_owned(),
            provider_version: provider.provider_version().to_owned(),
            provider_provenance: provider.provenance(),
            provider_definition_digest: provider.provider_digest(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent_scope().digest().clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.credential_revision(),
            contract_digest,
            state: NetSuiteRegistrationState::Active,
            registration_digest: Digest::from_text("uninitialized-netsuite-registration"),
            bound_secret_reference: secret_reference.clone(),
            revocation: Arc::new(AtomicBool::new(false)),
            replay_fence: Arc::new(Mutex::new(BTreeSet::new())),
        };
        registration.registration_digest = registration.recompute_digest()?;
        if is_revocation_tombstoned("netsuite-registration", &registration.registration_digest) {
            return Err(NetSuiteServiceError::RegistrationRevoked);
        }
        Ok(registration)
    }

    fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
        let material = NetSuiteRegistrationMaterial {
            plugin_id: self.plugin_id.clone(),
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            service_id: self.service_id.clone(),
            service_version: self.service_version.clone(),
            service_definition_digest: self.service_definition_digest.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version.clone(),
            provider_provenance: self.provider_provenance,
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

    pub fn validate_canonical(
        &self,
        scope: &NetSuiteScope,
        secret_reference: &SecretReference,
    ) -> Result<(), NetSuiteServiceError> {
        if !self.is_active() {
            return Err(NetSuiteServiceError::RegistrationRevoked);
        }
        self.validate_digest()?;
        scope.validate_digest()?;
        if secret_reference.is_revoked() {
            return Err(NetSuiteServiceError::SecretRevoked);
        }
        if secret_reference.scope_digest() != &scope.digest()
            || self.plugin_id != NETSUITE_ACCOUNTING_RESULT_PLUGIN_ID
            || self.plugin_version != NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION
            || self.contract_version != NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION
            || self.service_id != NETSUITE_ACCOUNTING_RESULT_SERVICE_ID
            || self.service_version != NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION
            || self.service_definition_digest != NetSuiteServiceDefinition::default().digest()?
            || self.provider_id != NETSUITE_PROVIDER_ID
            || self.contract_digest != crate::contract_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != scope.digest()
            || self.consent_digest != *scope.consent_scope().digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.credential_revision != secret_reference.credential_revision()
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "canonical NetSuite registration integrity fence failed".to_owned(),
            ));
        }
        let provider = NetSuiteProviderDefinition::new(
            self.provider_version.clone(),
            self.provider_provenance,
        )
        .map_err(|error| NetSuiteServiceError::ScopeMismatch(error.to_string()))?;
        if provider.provider_id() != self.provider_id
            || provider.provider_version() != self.provider_version
            || provider.provider_digest() != self.provider_definition_digest
            || provider.is_native()
            || provider.is_connected()
            || provider.live_execution()
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "provider definition does not match canonical registration".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), NetSuiteServiceError> {
        if !self.is_active()
            || self
                .revocation
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(NetSuiteServiceError::RegistrationRevoked);
        }
        tombstone_revocation("netsuite-registration", &self.registration_digest).map_err(
            |error| match error {
                ModelError::AlreadyRevoked => NetSuiteServiceError::RegistrationRevoked,
                other => NetSuiteServiceError::Model(other),
            },
        )?;
        self.state = NetSuiteRegistrationState::Revoked;
        self.registration_digest = self.recompute_digest()?;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, NetSuiteRegistrationState::Active)
            && !self.revocation.load(Ordering::Acquire)
            && !is_revocation_tombstoned("netsuite-registration", &self.registration_digest)
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    pub fn service_definition_digest(&self) -> &Digest {
        &self.service_definition_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub const fn provider_provenance(&self) -> NetSuiteTransportProvenance {
        self.provider_provenance
    }

    pub fn provider_definition_digest(&self) -> &Digest {
        &self.provider_definition_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> NetSuiteRegistrationState {
        self.state
    }

    pub(crate) fn bound_secret_reference(&self) -> &SecretReference {
        &self.bound_secret_reference
    }

    pub(crate) fn claim_proposal(&self, digest: &Digest) -> Result<bool, NetSuiteServiceError> {
        if !self.is_active() {
            return Err(NetSuiteServiceError::RegistrationRevoked);
        }
        self.replay_fence
            .lock()
            .map_err(|_| NetSuiteServiceError::StaleEvidence)
            .map(|mut fence| fence.insert(digest.clone()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetSuiteRegistrationMaterial {
    plugin_id: String,
    plugin_version: String,
    contract_version: String,
    service_id: String,
    service_version: String,
    service_definition_digest: Digest,
    provider_id: String,
    provider_version: String,
    provider_provenance: NetSuiteTransportProvenance,
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
        scope.validate_digest()?;
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
            || scope
                .collection_filter()
                .validate_for_window(scope.observation_window())
                .is_err()
            || self.metadata.as_ref().is_some_and(|metadata| {
                !scope.observation_window().contains(metadata.observed_at())
            })
            || self.selected_record.as_ref().is_some_and(|selected| {
                !scope.observation_window().contains(selected.observed_at())
            })
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
    pub provider_id: String,
    pub provider_version: String,
    pub provider_definition_digest: Digest,
    pub provenance: NetSuiteTransportProvenance,
    pub connected: bool,
    pub native_evidence: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    proposal_digest: Digest,
}

impl NetSuiteAccountingProposal {
    fn new(
        request: NetSuiteAccountingProposalRequest,
        registration: &NetSuiteRegistration,
        scope: &NetSuiteScope,
        status: NetSuiteAccountingStatus,
        evidence: NetSuiteAccountingEvidence,
        provider: &NetSuiteProviderDefinition,
    ) -> Result<Self, NetSuiteServiceError> {
        let mut proposal = Self {
            request,
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            status,
            evidence,
            provider_id: provider.provider_id().to_owned(),
            provider_version: provider.provider_version().to_owned(),
            provider_definition_digest: provider.provider_digest(),
            provenance: provider.provenance(),
            connected: false,
            native_evidence: false,
            outcome_authority: false,
            work_product_adoption: false,
            proposal_digest: Digest::from_text("uninitialized-netsuite-proposal"),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
        let material = NetSuiteProposalMaterial {
            request: self.request.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            status: self.status,
            evidence: self.evidence.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version.clone(),
            provider_definition_digest: self.provider_definition_digest.clone(),
            provenance: self.provenance,
            connected: self.connected,
            native_evidence: self.native_evidence,
            outcome_authority: self.outcome_authority,
            work_product_adoption: self.work_product_adoption,
        };
        digest_serializable(&material).map_err(NetSuiteServiceError::Model)
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_bindings(
        &self,
        scope: &NetSuiteScope,
        registration: &NetSuiteRegistration,
    ) -> Result<(), NetSuiteServiceError> {
        if !registration.is_active()
            || registration.validate_digest().is_err()
            || self.registration_digest != *registration.registration_digest()
            || self.scope_digest != scope.digest()
            || self.request.request_digest != self.request.recompute_digest()?
            || self.proposal_digest != self.recompute_digest()?
            || self.provider_id != registration.provider_id()
            || self.provider_version != registration.provider_version()
            || self.provider_definition_digest != *registration.provider_definition_digest()
            || self.provenance != registration.provider_provenance()
            || self.evidence.provenance != self.provenance
            || self.connected
            || self.native_evidence
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(NetSuiteServiceError::StaleEvidence);
        }
        self.evidence
            .validate(scope, registration.credential_revision())
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
    provider_id: String,
    provider_version: String,
    provider_definition_digest: Digest,
    provenance: NetSuiteTransportProvenance,
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
    pub native_evidence: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    proposal_digest: Digest,
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
    native_evidence: bool,
    outcome_authority: bool,
    work_product_adoption: bool,
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
            provider_id: provider.provider_id().to_owned(),
            provider_version: provider.provider_version().to_owned(),
            provider_definition_digest: provider.provider_digest(),
            provenance: provider.provenance(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_scope().digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            executed: false,
            connected: false,
            native: false,
            native_evidence: false,
            outcome_authority: false,
            work_product_adoption: false,
            proposal_digest: Digest::from_text("uninitialized-netsuite-suiteql-proposal"),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    fn recompute_digest(&self) -> Result<Digest, NetSuiteServiceError> {
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
            native_evidence: self.native_evidence,
            outcome_authority: self.outcome_authority,
            work_product_adoption: self.work_product_adoption,
        };
        digest_serializable(&material).map_err(NetSuiteServiceError::Model)
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_bindings(
        &self,
        scope: &NetSuiteScope,
        registration: &NetSuiteRegistration,
    ) -> Result<(), NetSuiteServiceError> {
        if !registration.is_active()
            || registration.validate_digest().is_err()
            || self.registration_digest != *registration.registration_digest()
            || self.scope_digest != scope.digest()
            || self.permission_digest != *scope.permission_digest()
            || self.consent_digest != *scope.consent_scope().digest()
            || self.provider_id != registration.provider_id()
            || self.provider_version != registration.provider_version()
            || self.provider_definition_digest != *registration.provider_definition_digest()
            || self.provenance != registration.provider_provenance()
            || self.executed
            || self.connected
            || self.native
            || self.native_evidence
            || self.outcome_authority
            || self.work_product_adoption
            || self.proposal_digest != self.recompute_digest()?
        {
            return Err(NetSuiteServiceError::StaleEvidence);
        }
        self.statement.validate_digest()?;
        if self.statement.record_type() != scope.record_type()
            || self.statement.filter().digest() != scope.collection_filter().digest()
            || self.statement.observation_window() != scope.observation_window()
            || self
                .statement
                .filter()
                .validate_for_window(scope.observation_window())
                .is_err()
        {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "SuiteQL statement is outside the registered scope".to_owned(),
            ));
        }
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
        registration.validate_canonical(&scope, &secret_reference)?;
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
        NetSuiteAccountingProposal::new(
            request,
            &self.registration,
            &scope,
            status,
            evidence,
            self.provider.definition(),
        )
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
                proposal.proposal_digest().as_str().to_owned(),
                proposal.statement.query_digest().as_str().to_owned(),
                proposal.scope_digest.as_str().to_owned(),
                at.to_rfc3339(),
                "executed=false".to_owned(),
            ],
        );
        if !self.scope.observation_window().contains(at) {
            return Err(NetSuiteServiceError::ScopeMismatch(
                "SuiteQL record timestamp is outside the registered observation window".to_owned(),
            ));
        }
        Ok(NetSuiteSuiteQlRecord {
            proposal_digest: proposal.proposal_digest().clone(),
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
        self.registration
            .validate_canonical(&self.scope, &self.secret_reference)
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
