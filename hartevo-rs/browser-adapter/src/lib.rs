//! Project-scoped browser control and typed action boundary.
//!
//! B0 provides deterministic lease/effect fencing through a fake host. B1a
//! adds a managed Chromium pipe and narrowly allowlisted read boundary; B1b
//! adds one exact Effect-bound semantic click with live geometry and hit-test
//! fencing. B1c adds redacted, empty-field text insertion and the narrow B2
//! slice selects one File-Broker-staged file in an exact file input. Signed
//! Recipe foundations add two-purpose Ed25519 trust, evidence-gated promotion,
//! monotonic CAS activation, exact prepared-plan binding, and dispatch-time
//! revalidation after recovery. Their canonical snapshots are restored by the
//! project-local SQLCipher v34 Registry in `hartevo-storage`; Cell replication,
//! production key administration, and real Provider Recipes are not complete.
//! No local action claims Provider submission, business completion, or
//! independent verification.

mod action;
mod artifact;
#[cfg(unix)]
mod chromium_host;
mod fake_host;
mod file_broker;
mod locator;
mod navigation;
mod profile_dir;
#[cfg(test)]
mod real_chromium_signed_recipe_test;
mod recipe;
#[cfg(unix)]
mod scanner;
mod workspace;

pub use action::{
    BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserActionRisk, BrowserActionSurface,
    BrowserEffectBinding, BrowserElementRef, BrowserPromptRisk, BrowserTextInput, SemanticSnapshot,
};
pub use artifact::{
    BrowserArtifactAdoptionState, BrowserArtifactCapture, BrowserArtifactCaptureInput,
    BrowserArtifactFileInspectionRequest, BrowserArtifactFileInspectionResult,
    BrowserArtifactFrameObservation, BrowserArtifactFrameRevision, BrowserArtifactHost,
    BrowserArtifactInspectionEvidence, BrowserArtifactInspectionVerdict, BrowserArtifactInspector,
    BrowserArtifactPlugin, BrowserArtifactProviderState, BrowserArtifactQuarantineReceipt,
    BrowserArtifactResultLog, BrowserArtifactResultSink, BrowserArtifactSafeForAdoption,
    BrowserArtifactScope, UnavailableBrowserArtifactHost, UnavailableBrowserArtifactInspector,
};
#[cfg(unix)]
pub use chromium_host::{
    ChromiumClickDispatchEvidence, ChromiumCredentialStoreMode, ChromiumFileUploadDispatchEvidence,
    ChromiumHostHealth, ChromiumHostShutdown, ChromiumLaunchConfig,
    ChromiumTextInputDispatchEvidence, ManagedChromiumClickExecutor,
    ManagedChromiumFileUploadExecutor, ManagedChromiumHost, ManagedChromiumTextInputExecutor,
};
pub use fake_host::{
    BrowserActionResult, BrowserBatchCursor, FakeBrowserEffectExecutor, FakeBrowserHost,
    FakeBrowserPage,
};
pub use file_broker::{
    BrowserFileGrant, BrowserFileGrantState, BrowserFileType, FileBroker, FileBrokerReconciliation,
    FileClaimPlan, FileSafetyScanner, FileScanDecision, FileScanReport, FileScanRequest,
    FileTerminalPlan, FileUploadHandle,
};
pub use locator::{BrowserLocatorResolution, BrowserStableLocator};
pub use navigation::{BrowserNavigationPolicy, BrowserNavigationReceipt, BrowserNavigationTarget};
pub use profile_dir::{BrowserExecutableIdentity, ManagedProfileDirectory};
pub use recipe::{
    BrowserRecipeActivation, BrowserRecipeActiveVersion, BrowserRecipeCandidate,
    BrowserRecipeEvaluationEvidence, BrowserRecipeExecutionAuthorization, BrowserRecipeKeyPurpose,
    BrowserRecipeManifest, BrowserRecipePreparedPlan, BrowserRecipePromotion,
    BrowserRecipeRegistry, BrowserRecipeRegistrySnapshot, BrowserRecipeRelease,
    BrowserRecipeResolvedAction, BrowserRecipeStep, BrowserRecipeStepBinding,
    BrowserRecipeTrustSnapshot, BrowserRecipeTrustStore, TrustedBrowserRecipeKey,
};
#[cfg(unix)]
pub use scanner::{ProductionFileScanner, ScannerProcessLimits, ScannerReleasePin};
pub use workspace::{
    BrowserControlState, BrowserControlTransition, BrowserIdentity, BrowserLeaseProof,
    BrowserProfile, BrowserProfileSource, BrowserProfileStatus, BrowserWorkspace,
};

/// Minimal fail-closed boundary used by the Application layer for control
/// transitions. Implementations must fence the previous lease before returning
/// success from a restrictive transition.
pub trait BrowserControlHost {
    fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError>;
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("browser identity is malformed or lacks exact probe evidence")]
    InvalidIdentity,
    #[error("browser profile is malformed")]
    InvalidProfile,
    #[error("browser profile transition is invalid")]
    InvalidProfileTransition,
    #[error("browser profile, project, mission, workspace, or tab scope does not match")]
    ScopeMismatch,
    #[error("browser workspace is malformed")]
    InvalidWorkspace,
    #[error("browser control transition is invalid")]
    InvalidControlTransition,
    #[error("browser tab transition is invalid")]
    InvalidTabTransition,
    #[error("browser control lease is stale, expired, or no longer agent-controlled")]
    ControlLeaseLost,
    #[error("browser semantic snapshot is malformed")]
    InvalidSnapshot,
    #[error("browser action is malformed")]
    InvalidAction,
    #[error("browser action batch is malformed or expired")]
    InvalidBatch,
    #[error("potential browser external write requires the Effect Broker")]
    EffectBrokerRequired,
    #[error("browser action batch does not match the exact approved Effect")]
    EffectScopeMismatch,
    #[error("browser workspace is not registered in this host")]
    WorkspaceNotRegistered,
    #[error("browser tab was not found in this workspace")]
    TabNotFound,
    #[error("browser account identity no longer matches the project profile")]
    AccountIdentityMismatch,
    #[error("browser snapshot is stale after navigation, document change, or control handoff")]
    StaleSnapshot,
    #[error("browser element reference is stale, hidden, or non-unique")]
    StaleElementRef,
    #[error("browser stable locator is malformed or outside the current scope")]
    StableLocatorInvalid,
    #[error("browser stable locator expired before resolution")]
    StableLocatorExpired,
    #[error("browser stable locator matched no current accessible element")]
    StableLocatorNotFound,
    #[error("browser stable locator matched more than one current accessible element")]
    StableLocatorAmbiguous,
    #[error("browser element has no safe viewport geometry or is not interactable")]
    ElementNotInteractable,
    #[error("browser hit test resolved to an occluding or out-of-scope element")]
    HitTestMismatch,
    #[error("browser real action batch is unsupported or was already consumed")]
    RealActionRejected,
    #[error("browser text input is empty, oversized, or contains unsupported control data")]
    InvalidTextInput,
    #[error("browser text target is not a supported editable input")]
    TextTargetNotEditable,
    #[error("browser text target is not empty; replacement semantics require a separate contract")]
    TextTargetNotEmpty,
    #[error("browser text input readback did not match the exact approved content")]
    TextReadbackMismatch,
    #[error("browser upload target is not a supported visible file input")]
    FileInputTargetInvalid,
    #[error("browser file selection readback did not change after the exact upload handle")]
    FileSelectionReadbackMismatch,
    #[error("browser Recipe manifest, action template, or validity window is invalid")]
    InvalidRecipe,
    #[error("browser Recipe trust key is malformed or invalid for this use and time")]
    InvalidRecipeKey,
    #[error("browser Recipe trust key is unavailable")]
    RecipeKeyUnavailable,
    #[error("browser Recipe trust key has been revoked")]
    RecipeKeyRevoked,
    #[error("browser Recipe Ed25519 signature is invalid")]
    RecipeSignatureInvalid,
    #[error("browser Recipe promotion record is invalid")]
    InvalidRecipePromotion,
    #[error("browser Recipe V1/V2, safety, contamination, or rollback evidence failed its gate")]
    RecipeEvaluationGateFailed,
    #[error("browser Recipe Candidate has no verified production promotion")]
    RecipeCandidateNotPromoted,
    #[error("browser Recipe id and version were rebound to different immutable content")]
    RecipeVersionConflict,
    #[error("browser Recipe activation lost its CAS or attempted a downgrade")]
    RecipeActivationConflict,
    #[error("browser Recipe does not match the exact profile, locator, action, or Effect scope")]
    RecipeScopeMismatch,
    #[error("browser Recipe batch requires current activation and trust revalidation at dispatch")]
    RecipeRuntimeAuthorizationRequired,
    #[error("browser content contains suspected or confirmed prompt injection")]
    PromptInjectionDetected,
    #[error("browser host restarted; an in-flight batch cannot be replayed automatically")]
    HostRestarted,
    #[error("browser executable is missing, mutable by another principal, or not executable")]
    InvalidExecutable,
    #[error("browser managed profile directory is not private, canonical, or symlink-safe")]
    InvalidProfileDirectory,
    #[error("browser managed profile is already leased by another host")]
    ProfileInUse,
    #[error("browser managed profile binding no longer matches its immutable marker")]
    ProfileBindingMismatch,
    #[error("browser DevTools pipe transport is unavailable on this platform")]
    ProtocolUnavailable,
    #[error("browser DevTools pipe request timed out")]
    ProtocolTimeout,
    #[error("browser DevTools pipe was poisoned by malformed, oversized, or mismatched data")]
    ProtocolPoisoned,
    #[error("browser DevTools command failed with code {code}")]
    ProtocolCommandFailed { code: i64 },
    #[error("browser process exited before the requested operation completed")]
    HostExited,
    #[error("browser navigation policy is empty, malformed, or not exact-origin scoped")]
    NavigationPolicyInvalid,
    #[error("browser navigation target is outside the exact allowed origin set")]
    NavigationTargetRejected,
    #[error("browser navigation or a redirected/subresource request was blocked by policy")]
    NavigationRequestBlocked,
    #[error("browser navigation failed without producing a verified document")]
    NavigationFailed,
    #[error("browser navigation attempted to produce a download outside the File Broker")]
    NavigationDownloadBlocked,
    #[error("browser artifact metadata, bytes, source, or receipt is malformed")]
    InvalidArtifact,
    #[error("browser artifact is outside the exact Mission, profile, workspace, or frame scope")]
    ArtifactScopeMismatch,
    #[error("browser artifact has already been captured or delivered")]
    ArtifactDuplicate,
    #[error("browser artifact provider is no longer mounted")]
    ArtifactProviderUnavailable,
    #[error("browser artifact frame, loader, navigation, or source changed during capture")]
    ArtifactFrameStale,
    #[error("browser artifact provider was revoked")]
    ArtifactProviderRevoked,
    #[error("browser artifact provider was restarted and its old cursor is invalid")]
    ArtifactProviderRestarted,
    #[error("browser artifact File Inspection request or result is malformed")]
    ArtifactInspectionInvalid,
    #[error("browser artifact File Inspection scanner was unavailable")]
    ArtifactInspectionUnavailable,
    #[error("browser artifact File Inspection did not produce a clean verdict")]
    ArtifactInspectionRejected,
    #[error("browser artifact File Inspection request was already closed or replayed")]
    ArtifactInspectionReopened,
    #[error("browser artifact File Inspection request or result was duplicated")]
    ArtifactInspectionDuplicate,
    #[error("browser artifact is not currently SafeForAdoption")]
    ArtifactNotSafeForAdoption,
    #[error("browser file is outside every canonical project root or crosses a symlink")]
    FileOutsideProject,
    #[error("browser file is empty or exceeds the configured size boundary")]
    FileSizeRejected,
    #[error("browser file type is unsupported or differs from the user-authorized type")]
    FileTypeRejected,
    #[error("browser file changed during staging, scanning, or claim")]
    FileChanged,
    #[error("browser file safety scanner rejected the staged content")]
    FileScanRejected,
    #[error("browser file safety scanner did not produce a usable clean verdict")]
    FileScanUnavailable,
    #[error("browser file grant or claim is malformed or scope-mismatched")]
    InvalidFileGrant,
    #[error("browser file grant expired before the upload action")]
    FileGrantExpired,
    #[error("browser file grant is already claimed, consumed, revoked, or otherwise unavailable")]
    FileGrantUnavailable,
    #[error("durable browser file broker is already open in another process")]
    FileBrokerInUse,
    #[error("durable browser file broker directory contains an unrecognized or unsafe entry")]
    FileBrokerDirectoryTampered,
    #[error("browser revision changed: expected {expected}, actual {actual}")]
    RevisionMismatch { expected: u64, actual: u64 },
    #[error("browser counter overflow")]
    CounterOverflow,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl BrowserError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidIdentity => "BROWSER_INVALID_IDENTITY",
            Self::InvalidProfile => "BROWSER_INVALID_PROFILE",
            Self::InvalidProfileTransition => "BROWSER_INVALID_PROFILE_TRANSITION",
            Self::ScopeMismatch => "BROWSER_SCOPE_MISMATCH",
            Self::InvalidWorkspace => "BROWSER_INVALID_WORKSPACE",
            Self::InvalidControlTransition => "BROWSER_INVALID_CONTROL_TRANSITION",
            Self::InvalidTabTransition => "BROWSER_INVALID_TAB_TRANSITION",
            Self::ControlLeaseLost => "BROWSER_CONTROL_LEASE_LOST",
            Self::InvalidSnapshot => "BROWSER_INVALID_SNAPSHOT",
            Self::InvalidAction => "BROWSER_INVALID_ACTION",
            Self::InvalidBatch => "BROWSER_INVALID_BATCH",
            Self::EffectBrokerRequired => "BROWSER_EFFECT_BROKER_REQUIRED",
            Self::EffectScopeMismatch => "BROWSER_EFFECT_SCOPE_MISMATCH",
            Self::WorkspaceNotRegistered => "BROWSER_WORKSPACE_NOT_REGISTERED",
            Self::TabNotFound => "BROWSER_TAB_NOT_FOUND",
            Self::AccountIdentityMismatch => "BROWSER_ACCOUNT_IDENTITY_MISMATCH",
            Self::StaleSnapshot => "BROWSER_STALE_SNAPSHOT",
            Self::StaleElementRef => "BROWSER_STALE_ELEMENT_REF",
            Self::StableLocatorInvalid => "BROWSER_STABLE_LOCATOR_INVALID",
            Self::StableLocatorExpired => "BROWSER_STABLE_LOCATOR_EXPIRED",
            Self::StableLocatorNotFound => "BROWSER_STABLE_LOCATOR_NOT_FOUND",
            Self::StableLocatorAmbiguous => "BROWSER_STABLE_LOCATOR_AMBIGUOUS",
            Self::ElementNotInteractable => "BROWSER_ELEMENT_NOT_INTERACTABLE",
            Self::HitTestMismatch => "BROWSER_HIT_TEST_MISMATCH",
            Self::RealActionRejected => "BROWSER_REAL_ACTION_REJECTED",
            Self::InvalidTextInput => "BROWSER_INVALID_TEXT_INPUT",
            Self::TextTargetNotEditable => "BROWSER_TEXT_TARGET_NOT_EDITABLE",
            Self::TextTargetNotEmpty => "BROWSER_TEXT_TARGET_NOT_EMPTY",
            Self::TextReadbackMismatch => "BROWSER_TEXT_READBACK_MISMATCH",
            Self::FileInputTargetInvalid => "BROWSER_FILE_INPUT_TARGET_INVALID",
            Self::FileSelectionReadbackMismatch => "BROWSER_FILE_SELECTION_READBACK_MISMATCH",
            Self::InvalidRecipe => "BROWSER_INVALID_RECIPE",
            Self::InvalidRecipeKey => "BROWSER_INVALID_RECIPE_KEY",
            Self::RecipeKeyUnavailable => "BROWSER_RECIPE_KEY_UNAVAILABLE",
            Self::RecipeKeyRevoked => "BROWSER_RECIPE_KEY_REVOKED",
            Self::RecipeSignatureInvalid => "BROWSER_RECIPE_SIGNATURE_INVALID",
            Self::InvalidRecipePromotion => "BROWSER_INVALID_RECIPE_PROMOTION",
            Self::RecipeEvaluationGateFailed => "BROWSER_RECIPE_EVALUATION_GATE_FAILED",
            Self::RecipeCandidateNotPromoted => "BROWSER_RECIPE_CANDIDATE_NOT_PROMOTED",
            Self::RecipeVersionConflict => "BROWSER_RECIPE_VERSION_CONFLICT",
            Self::RecipeActivationConflict => "BROWSER_RECIPE_ACTIVATION_CONFLICT",
            Self::RecipeScopeMismatch => "BROWSER_RECIPE_SCOPE_MISMATCH",
            Self::RecipeRuntimeAuthorizationRequired => {
                "BROWSER_RECIPE_RUNTIME_AUTHORIZATION_REQUIRED"
            }
            Self::PromptInjectionDetected => "BROWSER_PROMPT_INJECTION_DETECTED",
            Self::HostRestarted => "BROWSER_HOST_RESTARTED",
            Self::InvalidExecutable => "BROWSER_INVALID_EXECUTABLE",
            Self::InvalidProfileDirectory => "BROWSER_INVALID_PROFILE_DIRECTORY",
            Self::ProfileInUse => "BROWSER_PROFILE_IN_USE",
            Self::ProfileBindingMismatch => "BROWSER_PROFILE_BINDING_MISMATCH",
            Self::ProtocolUnavailable => "BROWSER_PROTOCOL_UNAVAILABLE",
            Self::ProtocolTimeout => "BROWSER_PROTOCOL_TIMEOUT",
            Self::ProtocolPoisoned => "BROWSER_PROTOCOL_POISONED",
            Self::ProtocolCommandFailed { .. } => "BROWSER_PROTOCOL_COMMAND_FAILED",
            Self::HostExited => "BROWSER_HOST_EXITED",
            Self::NavigationPolicyInvalid => "BROWSER_NAVIGATION_POLICY_INVALID",
            Self::NavigationTargetRejected => "BROWSER_NAVIGATION_TARGET_REJECTED",
            Self::NavigationRequestBlocked => "BROWSER_NAVIGATION_REQUEST_BLOCKED",
            Self::NavigationFailed => "BROWSER_NAVIGATION_FAILED",
            Self::NavigationDownloadBlocked => "BROWSER_NAVIGATION_DOWNLOAD_BLOCKED",
            Self::InvalidArtifact => "BROWSER_INVALID_ARTIFACT",
            Self::ArtifactScopeMismatch => "BROWSER_ARTIFACT_SCOPE_MISMATCH",
            Self::ArtifactDuplicate => "BROWSER_ARTIFACT_DUPLICATE",
            Self::ArtifactProviderUnavailable => "BROWSER_ARTIFACT_PROVIDER_UNAVAILABLE",
            Self::ArtifactFrameStale => "BROWSER_ARTIFACT_FRAME_STALE",
            Self::ArtifactProviderRevoked => "BROWSER_ARTIFACT_PROVIDER_REVOKED",
            Self::ArtifactProviderRestarted => "BROWSER_ARTIFACT_PROVIDER_RESTARTED",
            Self::ArtifactInspectionInvalid => "BROWSER_ARTIFACT_INSPECTION_INVALID",
            Self::ArtifactInspectionUnavailable => "BROWSER_ARTIFACT_INSPECTION_UNAVAILABLE",
            Self::ArtifactInspectionRejected => "BROWSER_ARTIFACT_INSPECTION_REJECTED",
            Self::ArtifactInspectionReopened => "BROWSER_ARTIFACT_INSPECTION_REOPENED",
            Self::ArtifactInspectionDuplicate => "BROWSER_ARTIFACT_INSPECTION_DUPLICATE",
            Self::ArtifactNotSafeForAdoption => "BROWSER_ARTIFACT_NOT_SAFE_FOR_ADOPTION",
            Self::FileOutsideProject => "BROWSER_FILE_OUTSIDE_PROJECT",
            Self::FileSizeRejected => "BROWSER_FILE_SIZE_REJECTED",
            Self::FileTypeRejected => "BROWSER_FILE_TYPE_REJECTED",
            Self::FileChanged => "BROWSER_FILE_CHANGED",
            Self::FileScanRejected => "BROWSER_FILE_SCAN_REJECTED",
            Self::FileScanUnavailable => "BROWSER_FILE_SCAN_UNAVAILABLE",
            Self::InvalidFileGrant => "BROWSER_INVALID_FILE_GRANT",
            Self::FileGrantExpired => "BROWSER_FILE_GRANT_EXPIRED",
            Self::FileGrantUnavailable => "BROWSER_FILE_GRANT_UNAVAILABLE",
            Self::FileBrokerInUse => "BROWSER_FILE_BROKER_IN_USE",
            Self::FileBrokerDirectoryTampered => "BROWSER_FILE_BROKER_DIRECTORY_TAMPERED",
            Self::RevisionMismatch { .. } => "BROWSER_REVISION_MISMATCH",
            Self::CounterOverflow => "BROWSER_COUNTER_OVERFLOW",
            Self::Json(_) => "BROWSER_JSON_ERROR",
            Self::Io(_) => "BROWSER_IO_ERROR",
        }
    }
}
