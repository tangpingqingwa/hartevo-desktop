//! Mission-scoped, review-only projection for a Bigtable posture proposal.

use std::{cell::RefCell, collections::BTreeSet};

use serde::Serialize;
use thiserror::Error;

use crate::{
    GCP_BIGTABLE_TABLE_RESULT_CONSUMER, GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID,
    GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID,
    model::{Digest, GcpBigtableTableScope, Revision, TablePosture},
    service::{GcpBigtableRegistration, GcpBigtableTableResultProposal, RegistrationStatus},
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("consumer scope or registration binding does not match")]
    ScopeMismatch,
    #[error("proposal service/provider/consumer binding does not match")]
    IdentityMismatch,
    #[error("proposal evidence violates the consumer fence or Layer-1 boundary")]
    EvidenceMismatch,
    #[error("proposal has already been consumed by this Mission consumer")]
    ReplayRejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub digest: Digest,
    pub bounded: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceProjection {
    pub digest: Digest,
    pub bounded: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableIdentityProjection {
    pub digest: Digest,
    pub bounded: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub digest: Digest,
    pub bounded: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub digest: Digest,
    pub bounded: String,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGcpBigtableTableResult {
    pub service_id: String,
    pub consumer_id: String,
    pub project: ProjectProjection,
    pub instance: InstanceProjection,
    pub table: TableIdentityProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub posture: TablePosture,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence: crate::GcpBigtableResultEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub rows_read: bool,
    pub writes_performed: bool,
    pub durable_provider_receipt: bool,
    pub work_product_adopted: bool,
}

impl MissionGcpBigtableTableResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionGcpBigtableTableConsumer {
    scope: GcpBigtableTableScope,
    registration_digest: Digest,
    registration_revision: Revision,
    provider_definition_digest: Digest,
    consumed_proposals: RefCell<BTreeSet<Digest>>,
}

impl std::fmt::Debug for MissionGcpBigtableTableConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionGcpBigtableTableConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field(
                "provider_definition_digest",
                &self.provider_definition_digest,
            )
            .field(
                "consumed_proposal_count",
                &self.consumed_proposals.borrow().len(),
            )
            .finish()
    }
}

impl MissionGcpBigtableTableConsumer {
    pub fn new(
        scope: GcpBigtableTableScope,
        registration: &GcpBigtableRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.status != RegistrationStatus::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if registration.scope_digest != scope.scope_digest()
            || registration.service_id != GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID
            || registration.provider_id != GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID
            || registration.consumer_id != GCP_BIGTABLE_TABLE_RESULT_CONSUMER
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.revision,
            provider_definition_digest: registration.provider_definition_digest.clone(),
            consumed_proposals: RefCell::new(BTreeSet::new()),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpBigtableTableScope {
        &self.scope
    }

    pub fn consume(
        &self,
        proposal: GcpBigtableTableResultProposal,
    ) -> Result<MissionGcpBigtableTableResult, ConsumerError> {
        if proposal.service_id != GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID
            || proposal.provider_id != GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID
            || proposal.consumer_id != GCP_BIGTABLE_TABLE_RESULT_CONSUMER
        {
            return Err(ConsumerError::IdentityMismatch);
        }
        if proposal.scope_digest != self.scope.scope_digest()
            || proposal.registration_digest != self.registration_digest
            || proposal.registration_revision != self.registration_revision
            || proposal.provider_definition_digest != self.provider_definition_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let evidence = &proposal.evidence;
        if evidence.scope_digest != self.scope.scope_digest()
            || evidence.permission_digest != *self.scope.permission_digest()
            || evidence.consent_digest != *self.scope.consent_digest()
            || evidence.work_product_revision != self.scope.work_product_revision()
            || evidence.provider_resource_scope.table_digest != self.scope.table().digest()
            || evidence.authority != crate::Layer1Authority::offline()
            || evidence.rows_read
            || evidence.writes_performed
            || evidence.raw_values_retained
            || evidence.credentials_retained
            || evidence.pii_retained
            || evidence.durable_provider_receipt
        {
            return Err(ConsumerError::EvidenceMismatch);
        }
        if !self
            .consumed_proposals
            .borrow_mut()
            .insert(proposal.proposal_digest.clone())
        {
            return Err(ConsumerError::ReplayRejected);
        }
        Ok(MissionGcpBigtableTableResult {
            service_id: proposal.service_id,
            consumer_id: proposal.consumer_id,
            project: ProjectProjection {
                digest: self.scope.project().digest(),
                bounded: self.scope.project().redacted(),
            },
            instance: InstanceProjection {
                digest: self.scope.instance().digest(),
                bounded: self.scope.instance().redacted(),
            },
            table: TableIdentityProjection {
                digest: self.scope.table().digest(),
                bounded: self.scope.table().table().redacted(),
            },
            mission: MissionProjection {
                digest: self.scope.mission().digest(),
                bounded: self.scope.mission().redacted(),
            },
            work_product: WorkProductProjection {
                digest: self.scope.work_product().digest(),
                bounded: self.scope.work_product().redacted(),
                revision: self.scope.work_product_revision(),
            },
            posture: proposal.posture,
            proposal_digest: proposal.proposal_digest,
            scope_digest: proposal.scope_digest,
            registration_digest: proposal.registration_digest,
            evidence: proposal.evidence,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            rows_read: false,
            writes_performed: false,
            durable_provider_receipt: false,
            work_product_adopted: false,
        })
    }
}

pub type MissionGcpBigtableConsumer = MissionGcpBigtableTableConsumer;
pub type MissionGcpBigtableResult = MissionGcpBigtableTableResult;
