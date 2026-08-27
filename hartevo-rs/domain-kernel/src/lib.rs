//! Hartevo's deterministic business state.
//!
//! Runtime threads, model output, and provider responses are projections into this
//! kernel. They are never accepted as business truth without a domain command.

mod attribution_evidence_query;
mod attribution_outcome_adoption;
mod attribution_spine;
mod connection;
mod context;
mod context_collaboration;
mod context_foundation;
mod creator_hiring;
mod creator_work;
mod deletion;
mod identity;
mod identity_project_invite;
mod ids;
mod key_management;
mod market_evidence;
mod mission;
mod mission_conversation;
mod mission_schedule;
mod money;
mod outcome;
mod project;
mod relationship;
mod runtime_process;
mod runtime_recovery;
mod runtime_turn;
mod truth;
mod work_product;

pub use attribution_evidence_query::{
    ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_MOUNT_EVENT_TYPE,
    ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_REVOKE_EVENT_TYPE,
    ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION, ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE,
    ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE, ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION,
    AttributionEvidenceAdoptionDecision, AttributionEvidenceAdoptionFeedback,
    AttributionEvidenceConfidence, AttributionEvidenceCounterevidence,
    AttributionEvidenceFreshness, AttributionEvidenceFreshnessState,
    AttributionEvidenceQueryConsumer, AttributionEvidenceQueryConsumerRecord,
    AttributionEvidenceQueryConsumerState, AttributionEvidenceQueryError,
    AttributionEvidenceQueryId, AttributionEvidenceQueryProvider, AttributionEvidenceQueryRecord,
    AttributionEvidenceQueryRequest, AttributionEvidenceQueryResponse,
    AttributionEvidenceQueryScope, AttributionEvidenceQueryService,
    AttributionEvidenceQuerySnapshot, AttributionEvidenceQueryWindow,
    AttributionEvidenceSourceCoverage,
};
pub use attribution_outcome_adoption::{
    ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE, ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE,
    ATTRIBUTION_ADOPTION_CONSUMER_REVOKE_EVENT_TYPE,
    ATTRIBUTION_ADOPTION_CONSUMER_UNMOUNT_EVENT_TYPE, ATTRIBUTION_ADOPTION_RECEIPT_EVENT_TYPE,
    ATTRIBUTION_OUTCOME_ADOPTION_CONTRACT_VERSION, ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION,
    ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE, ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE,
    AttributionAdoptionConsumer, AttributionAdoptionConsumerRecord,
    AttributionAdoptionConsumerState, AttributionAdoptionDecision, AttributionAdoptionError,
    AttributionAdoptionReceipt, AttributionAdoptionScope, AttributionAdoptionSnapshot,
    AttributionModelVersion, AttributionOutcomeCandidate, AttributionVerificationRecord,
};
pub use attribution_spine::{
    ATTRIBUTION_SPINE_EVENT_TYPE, ATTRIBUTION_SPINE_SCHEMA_VERSION, AttributionAssignment,
    AttributionError, AttributionLedger, AttributionProjection, AttributionReason,
    AttributionWindow, BatchIngestResult, ConnectorObservationSource, CorrectionKind,
    CorrectionLineage, IngestDisposition, ObservationOrigin, ObservationProvenance,
    OutcomeCandidate, OutcomeCandidateId, OutcomeKind, OutcomeVerification, ProviderCursor,
    ProviderEntityRef, ProviderEventIdentity, SourceEntityKind, SourceEvent, SourceEventId,
    SourceEventKind, SourceEventLinks, SourceObservationBatch, VerificationMethod, VerifiedOutcome,
    VerifiedOutcomeId,
};

/// Stable contract constants for storage crates.  The candidate and verified
/// event names are also owned by the attribution-outcome adoption contract on
/// newer bootstrap compositions, so they intentionally stay out of the root
/// re-export above to avoid duplicate public names when that slice is composed.
pub mod attribution_spine_contract {
    pub use super::attribution_spine::{
        ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE, ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE,
    };
}
pub use context::{
    ContextBranch, ContextBranchStatus, ContextBudget, ContextCapsule, ContextCapsuleStatus,
    ContextDataClass, ContextDataPolicy, ContextError, ContextFactGrant, ContextInputRefs,
    ContextMergePolicy, ContextReturnContract, ContextReturnReceipt, ContextWorkspace, WorkerLease,
    WorkerLeaseStatus, validate_context_branch_lineage,
};
pub use context_collaboration::{
    ContextBranchMerge, ContextBranchMergeDisposition, ContextWorkerMessage,
    ContextWorkerMessageKind, ContextWorkerMessageStatus, WorkerHandle, WorkerHandleStatus,
    WorkerMailbox, WorkerUsage,
};
pub use context_foundation::{
    ContextCheckpoint, ContextCompactionRecord, ContextEffectInvariant, ContextEvidenceInvariant,
    ContextFoundationSnapshot, ContextInvariantBlock, ContextItemAvailability,
    ContextTaskInvariant, ContextTruthInvariant, ContextWorkProductInvariant, ContextWorkingItem,
    ContextWorkingItemKind, ContextWorkingSet, ContinuationEntry, ContinuationEntryInput,
    ContinuationEntryKind, ContinuationLedger,
};
pub use deletion::{
    DeletionError, DeletionPropagationReceipt, DeletionPropagationStatus, DeletionReason,
    DeletionRecord, DeletionRetentionMode, DeletionSurface, DeletionSurfaceState,
    DeletionTombstone,
};
pub use identity::{
    Company, ConsentPurpose, ConsentRecord, ConsentRequirement, ConsentStatus, ContactChannel,
    ContactPermission, ContactPoint, ConversationIdentitySnapshot, CreatorIdentitySnapshot,
    ExternalIdentity, IdentityError, IdentityLink, IdentityLinkDecision, IdentityLinkStatus,
    IdentitySubject, LegalBasis, Partner, PartnerSupplyClass, Person,
};
pub use identity_project_invite::{
    ApprovedInvite, DEFAULT_PROJECT_INVITE_TTL, DraftInvite, DraftInviteHandle, DraftInviteRequest,
    InviteApproval, InviteReceipt, ProjectInviteConsumer, ProjectInviteError, ProjectInviteEvent,
    ProjectInviteMembershipStatus, ProjectInvitePluginService, ProjectInviteProjectScope,
    ProjectInviteProvider, ProjectInviteRole, ProjectInviteScope, ProjectInviteService,
    ProjectInviteSession, ProjectInviteSessionStatus, ProjectInviteStatus,
    ProjectInviteTeamMembership, ProjectMembershipBinding, ProjectMembershipBindingStatus,
};
pub use ids::{
    AccountId, ActorId, ApprovalId, AttributionId, BrowserActionBatchId, BrowserControlLeaseId,
    BrowserFileClaimId, BrowserFileGrantId, BrowserProfileId, BrowserRecipeId, BrowserSnapshotId,
    BrowserTabId, BrowserWorkspaceId, CampaignId, CommissionId, CompanyId, ConnectionId,
    ConsentRecordId, ContextAssemblyId, ContextBranchId, ContextBranchMergeId, ContextCapsuleId,
    ContextCheckpointId, ContextCompactionRecordId, ContextContinuationLedgerId,
    ContextWorkerMailboxId, ContextWorkerMessageId, ContextWorkingSetId, ContextWorkspaceId,
    ConversationId, CreatorApplicationId, CreatorHiringId, CreatorId, CreatorMilestoneId,
    CreatorTaskId, DeletionId, DeletionReceiptId, DeliverableId, DeviceAttachmentId,
    DeviceHandoffId, DeviceId, EffectId, EvidenceId, ExecutionAttemptId, FactId, IdentityLinkId,
    IdentitySessionId, KeyEnvelopeId, MemberId, MessageId, MissionConversationId,
    MissionConversationMessageId, MissionId, MissionScheduleId, OpportunityId, OrderId,
    OutcomeEventId, PartnerId, PayoutId, PersonId, ProjectId, ProjectInviteEventId,
    ProjectInviteId, ProjectInviteReceiptId, ProjectMembershipBindingId, ReceiptId, RefundId,
    ReviewId, RuntimeRecoveryAttemptId, RuntimeTurnAttemptId, TaskId, TeamId, TenantId,
    VerificationId, WorkProductId, WorkerId, WorkerLeaseId,
};
pub use key_management::{
    DeviceAttachment, DeviceAttachmentMethod, DeviceAttachmentStatus, DeviceHandoffCiphertext,
    DeviceHandoffClaim, DeviceHandoffConsumption, DeviceHandoffContext, DeviceHandoffGrant,
    DeviceHandoffRevocation, DeviceKeyAgreementAlgorithm, DevicePublicKeyRegistration, KeyEnvelope,
    KeyManagementError, KeyRecipient, KeyWrapAlgorithm, ProjectEncryptionMode, ProjectKeyring,
    ProjectKeyringBootstrap, WrappedKeyCiphertext,
};
pub use market_evidence::{
    MarketCounterevidence, MarketDecisionRecommendation, MarketEvidenceClaim,
    MarketEvidenceClassification, MarketEvidenceError, MarketEvidencePack,
    MarketExperimentPlanItem, MarketUncertainty, MarketUncertaintyMateriality, Vm07DecisionAction,
    Vm07DecisionBinding,
};
pub use mission::{
    Approval, ApprovalDecision, ApprovalPolicy, AutonomyLevel, Cadence, CadenceTriggerKind,
    ConsentState, Constraint, ConversationEffectGuard, CreatorContactEffectGuard,
    DurableProviderState, Effect, EffectClass, EffectRisk, EffectSpec, EffectStatus, Evidence,
    EvidenceStatus, KpiContract, KpiDirection, MetricValue, Mission, MissionBlock,
    MissionCheckpoint, MissionCheckpointApplicationEvidence, MissionCheckpointCompletion,
    MissionCheckpointCompletionPolicy, MissionCheckpointExecutor, MissionCheckpointOracleSource,
    MissionCheckpointRoute, MissionCheckpointStatus, MissionContract, MissionDefinition,
    MissionError, MissionStage, MissionTerminalDisposition, OperatingContract,
    OperatingContractError, OperatingMode, Outcome, OutcomeDecision, Receipt, Task, TaskStatus,
    Verification, VerificationStatus, WorkProduct, WorkProductStatus,
};
pub use mission_conversation::{
    MissionConversation, MissionConversationError, MissionConversationMessage,
    MissionConversationMessageKind, MissionConversationRole,
};
pub use mission_schedule::{
    MissionSchedule, MissionScheduleError, MissionScheduleFailure, MissionScheduleFailureClass,
    MissionScheduleLease, MissionScheduleSignal, MissionScheduleStatus,
};
pub use money::{CurrencyCode, FxQuote, Money, MoneyError};
pub use outcome::{
    AttributionModel, AttributionRecord, AttributionTrafficClass, CommissionRecord,
    CommissionStatus, MissionKpiMeasurement, MissionKpiObservedValue, MissionKpiProjection,
    OrderAttributionView, OrderSettlementView, OutcomeAttributionProjection, OutcomeEvent,
    OutcomeEventKind, OutcomeIdentityChainProjection, OutcomeLedger, OutcomeLedgerError,
    OutcomeNormalizationProjection, OutcomeOrder, OutcomeRefund, OutcomeReviewActionGate,
    OutcomeReviewCausalStatus, OutcomeReviewCaveat, OutcomeReviewDecision,
    OutcomeReviewDecisionGateStatus, OutcomeReviewGateStatus, OutcomeReviewLoopPolicy,
    OutcomeReviewMoneyView, OutcomeReviewNextContractIntent, OutcomeReviewNextContractResolution,
    OutcomeReviewProjection, OutcomeReviewRoiStatus, OutcomeSettlementProjection,
    OutcomeSourceVerification, OutcomeVerificationMethod, PartnerSettlementView,
    SettlementCommissionBasis, SettlementGroupStatus, Touchpoint,
    attribution_effect_provider_identity_digest,
};
pub use project::{Project, ProjectDataCell, ProjectError, StorageMode};
pub use relationship::{
    AutomatedReplyAuthorization, BuyingCommitteeMember, BuyingCommitteeRole, Campaign,
    CampaignRecipient, CampaignRecipientState, CampaignSendAuthorization, CampaignStatus,
    Conversation, ConversationContentRisk, ConversationControl, ConversationMessage,
    ConversationState, InboundIngest, InboundMessageInput, MessageDelivery, MessageDirection,
    MessagingGateway, Opportunity, OpportunityStage, PreparedAutomaticReply, RelationshipError,
    StageTransition, SuppressionReason, WebhookAttestation,
};
pub use runtime_process::{
    RuntimeProcessClaim, RuntimeProcessClaimStatus, RuntimeProcessCleanupDisposition,
    RuntimeProcessCleanupEvidence, RuntimeProcessIdentity,
};
pub use runtime_recovery::{
    RuntimeRecoveryAttempt, RuntimeRecoveryFailure, RuntimeRecoveryFailureClass,
    RuntimeRecoveryStatus, RuntimeResumeStrategy,
};
pub use runtime_turn::{
    RuntimeTurnAttempt, RuntimeTurnError, RuntimeTurnEvidence, RuntimeTurnEvidenceKind,
    RuntimeTurnFailure, RuntimeTurnFailureClass, RuntimeTurnObservedKind,
    RuntimeTurnPrivateMessage, RuntimeTurnPrivateTextDelta, RuntimeTurnRestartDisposition,
    RuntimeTurnScope, RuntimeTurnStatus,
};
pub use truth::{
    TruthCandidate, TruthError, TruthFact, TruthRevisionLink, TruthSource, TruthStatus, TruthValue,
};
pub use work_product::{
    WorkProductDependencies, WorkProductManifest, WorkProductManifestError, WorkProductPreview,
};

/// Domain schema recorded with every build and persisted snapshot.
pub const DOMAIN_SCHEMA_VERSION: &str = "hartevo-domain/v1";
pub use connection::{
    Connection, ConnectionError, ConnectionProbe, ConnectionSnapshot, ConnectionStatus,
    ProbeOutcome,
};
pub use creator_hiring::{
    CreatorApplication, CreatorApplicationInput, CreatorApplicationOrigin,
    CreatorApplicationStatus, CreatorCandidate, CreatorCandidateStatus, CreatorExternalProof,
    CreatorHiring, CreatorHiringAward, CreatorHiringError, CreatorHiringSpec, CreatorHiringStatus,
    CreatorInvitation, CreatorListingPublication,
};
pub use creator_work::{
    AcceptanceCheck, CreatorAcceptance, CreatorDeliverable, CreatorDeliverableInput,
    CreatorEligibility, CreatorMilestone, CreatorMilestoneSpec, CreatorMilestoneStatus,
    CreatorPayoutConfirmation, CreatorPayoutRecord, CreatorTask, CreatorTaskSpec,
    CreatorTaskStatus, CreatorWorkError, DeliverableAssessment, DeliverableEntitlementStatus,
    DeliverableReview, DeliverableReviewInput, DeliverableStatus, FundingReservation,
    PayoutAuthorization, ReviewDecision, RightsAttestation, UsageRights,
};
