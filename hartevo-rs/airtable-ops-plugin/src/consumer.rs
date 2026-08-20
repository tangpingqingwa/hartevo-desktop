use crate::error::AirtableError;
use crate::model::{
    AirtableFieldAllowlist, AirtableScope, AirtableTableSchema, MissionOutput,
    MissionRecordProposalRequest, RecordProposal,
};
use crate::service::AirtableOpsService;

/// Mission-facing seam for adopting a WorkProduct or OutcomeCandidate as an
/// Airtable structured-record proposal.  It never has an external write
/// method; the service owns the deterministic compiler and verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AirtableMissionConsumer {
    service: AirtableOpsService,
}

impl Default for AirtableMissionConsumer {
    fn default() -> Self {
        Self::new()
    }
}

impl AirtableMissionConsumer {
    pub fn new() -> Self {
        Self {
            service: AirtableOpsService::new(),
        }
    }

    pub fn with_service(service: AirtableOpsService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &AirtableOpsService {
        &self.service
    }

    pub const fn consumer_id() -> &'static str {
        crate::AIRTABLE_MISSION_CONSUMER_ID
    }

    pub fn compile_record_proposal(
        &self,
        request: MissionRecordProposalRequest,
    ) -> Result<RecordProposal, AirtableError> {
        self.service.compile_record_proposal(request)
    }

    pub fn compile_output(
        &self,
        scope: AirtableScope,
        schema: AirtableTableSchema,
        field_allowlist: AirtableFieldAllowlist,
        output: MissionOutput,
    ) -> Result<RecordProposal, AirtableError> {
        self.service
            .compile_record_proposal_for_output(scope, schema, field_allowlist, output)
    }
}

pub type MissionRecordConsumer = AirtableMissionConsumer;
