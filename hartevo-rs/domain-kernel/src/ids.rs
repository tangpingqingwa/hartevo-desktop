use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! entity_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7().to_string())
            }

            pub fn from_stable(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::from_stable(value)
            }
        }
    };
}

entity_id!(ActorId);
entity_id!(AccountId);
entity_id!(ApprovalId);
entity_id!(AttributionId);
entity_id!(BrowserActionBatchId);
entity_id!(BrowserControlLeaseId);
entity_id!(BrowserFileClaimId);
entity_id!(BrowserFileGrantId);
entity_id!(BrowserProfileId);
entity_id!(BrowserRecipeId);
entity_id!(BrowserSnapshotId);
entity_id!(BrowserTabId);
entity_id!(BrowserWorkspaceId);
entity_id!(ConnectionId);
entity_id!(ContextAssemblyId);
entity_id!(ContextBranchId);
entity_id!(ContextBranchMergeId);
entity_id!(ContextCapsuleId);
entity_id!(ContextCheckpointId);
entity_id!(ContextCompactionRecordId);
entity_id!(ContextContinuationLedgerId);
entity_id!(ContextWorkerMailboxId);
entity_id!(ContextWorkerMessageId);
entity_id!(ContextWorkingSetId);
entity_id!(ContextWorkspaceId);
entity_id!(ConversationId);
entity_id!(ConsentRecordId);
entity_id!(CompanyId);
entity_id!(CommissionId);
entity_id!(CreatorId);
entity_id!(CreatorApplicationId);
entity_id!(CreatorHiringId);
entity_id!(CreatorMilestoneId);
entity_id!(CreatorTaskId);
entity_id!(DeliverableId);
entity_id!(DeletionId);
entity_id!(DeletionReceiptId);
entity_id!(DeviceAttachmentId);
entity_id!(DeviceHandoffId);
entity_id!(DeviceId);
entity_id!(EffectId);
entity_id!(EvidenceId);
entity_id!(ExecutionAttemptId);
entity_id!(FactId);
entity_id!(IdentityLinkId);
entity_id!(IdentitySessionId);
entity_id!(KeyEnvelopeId);
entity_id!(MemberId);
entity_id!(MessageId);
entity_id!(MissionId);
entity_id!(MissionScheduleId);
entity_id!(MissionConversationId);
entity_id!(MissionConversationMessageId);
entity_id!(OpportunityId);
entity_id!(OutcomeEventId);
entity_id!(OrderId);
entity_id!(PartnerId);
entity_id!(PayoutId);
entity_id!(PersonId);
entity_id!(ProjectId);
entity_id!(ProjectInviteEventId);
entity_id!(ProjectInviteId);
entity_id!(ProjectInviteDecisionReceiptId);
entity_id!(ProjectInviteReceiptId);
entity_id!(ProjectInviteRevocationReceiptId);
entity_id!(ProjectMembershipBindingId);
entity_id!(CampaignId);
entity_id!(ReceiptId);
entity_id!(ReviewId);
entity_id!(RefundId);
entity_id!(RuntimeRecoveryAttemptId);
entity_id!(RuntimeTurnAttemptId);
entity_id!(TaskId);
entity_id!(TeamId);
entity_id!(TenantId);
entity_id!(VerificationId);
entity_id!(WorkerLeaseId);
entity_id!(WorkerId);
entity_id!(WorkProductId);
