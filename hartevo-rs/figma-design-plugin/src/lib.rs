//! Typed, read/recording-only Figma design-result plugin boundary.
//!
//! Layer 1 preserves exact team/project/file/node/version scope, provider
//! registration and digest bindings, bounded export bytes, redacted receipts,
//! and Mission revision fences. It intentionally has no host wiring, no live
//! Figma session, no external write authority, and no Connected/native claim.

mod consumer;
mod contract;
mod provider;
mod service;
mod types;

pub use consumer::{
    AdoptionError, AdoptionReason, AdoptionRequest, DesignAdoptionProposal, MissionDesignResult,
    MissionDesignResultConsumer, MissionDesignResultError, ProposalStatus,
};
pub use contract::{
    FIGMA_DESIGN_CONTRACT_JSON, FIGMA_DESIGN_CONTRACT_VERSION, FIGMA_DESIGN_EVIDENCE_LEVEL,
    FIGMA_DESIGN_SCHEMA_VERSION, FigmaContractError, FigmaContractLimits, FigmaDesignContract,
};
pub use provider::{
    BlockedEnvTransport, ExportResponse, FIGMA_ADAPTER_ID, FIGMA_PROVIDER_ID,
    FIGMA_PROVIDER_VERSION, FigmaDesignProvider, FigmaHttpsEndpoint, FigmaHttpsTransport,
    FigmaProviderAvailability, FigmaProviderError, FigmaProviderEvidence, FigmaTransport,
    FigmaTransportCall, FigmaTransportError, FigmaTransportErrorKind, FileMetadataResponse,
    NodeMetadataResponse, PageCursor, ProviderObservation, RecordingFigmaTransport, RetryPolicy,
    VersionHistoryResponse, fixture_file_metadata, fixture_provider_version,
};
pub use service::{
    FigmaDesignService, FigmaExportReceipt, FigmaReadOperation, FigmaReadReceipt, FigmaReadResult,
    FigmaReceiptStatus, FigmaServiceError, VersionListPlan,
};
pub use types::{
    AdapterId, ExportFormat, ExportRequest, ExportScale, FigmaAuthMethod, FigmaDesignRegistration,
    FigmaEvidenceClass, FigmaExportMetadata, FigmaExportPayload, FigmaFileMetadata, FigmaNodeKind,
    FigmaNodeMetadata, FigmaProjectId, FigmaProviderMode, FigmaRegistrationBinding, FigmaScope,
    FigmaTimestamp, FigmaTypeError, FigmaVersion, FileKey, MAX_EXPORT_BYTES, MAX_NODE_IDS,
    MAX_RETRY_ATTEMPTS, MAX_VERSION_PAGE_SIZE, MAX_VERSION_PAGES, MissionDesignSource, MissionId,
    NodeId, ProjectId, ProposalId, ProviderVersion, REDACTED_VALUE, ReceiptId, RedactedText,
    RegistrationId, RegistrationStatus, ResultId, SecretReference, SecretReferenceId, Sha256Digest,
    TeamId, TenantId, VersionId,
};

/// The crate is intentionally E1 metadata/recording evidence only.
pub const EVIDENCE_LEVEL: &str = FIGMA_DESIGN_EVIDENCE_LEVEL;

/// Builds the exact binding used by the fixture/loopback provider seam.
pub fn figma_registration(
    scope: FigmaScope,
    registration_id: impl Into<String>,
    implementation_digest: Sha256Digest,
) -> Result<FigmaDesignRegistration, FigmaTypeError> {
    let binding = FigmaRegistrationBinding::new(
        FIGMA_PROVIDER_ID,
        AdapterId::new(FIGMA_ADAPTER_ID)?,
        1,
        ProviderVersion::new(FIGMA_PROVIDER_VERSION)?,
        implementation_digest,
        FigmaDesignContract::baseline()
            .map_err(|_| FigmaTypeError::InvalidDigest)?
            .digest(),
    )?;
    FigmaDesignRegistration::register(RegistrationId::new(registration_id)?, binding, scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_exactly_read_only_and_non_native() {
        let contract = FigmaDesignContract::baseline().expect("contract");
        assert_eq!(contract.schema_version(), FIGMA_DESIGN_SCHEMA_VERSION);
        assert_eq!(contract.contract_version(), FIGMA_DESIGN_CONTRACT_VERSION);
        assert_eq!(contract.evidence_level(), EVIDENCE_LEVEL);
        assert!(contract.read_only());
        assert!(!contract.connected());
        assert!(!contract.native());
        assert_eq!(contract.limits().max_node_ids(), MAX_NODE_IDS);
        assert_eq!(contract.limits().max_export_bytes(), MAX_EXPORT_BYTES);
        assert_eq!(
            contract.provider_modes(),
            &[
                FigmaProviderMode::Fixture,
                FigmaProviderMode::Loopback,
                FigmaProviderMode::BlockedEnv
            ]
        );
    }

    #[test]
    fn secret_reference_debug_and_serialized_metadata_are_redacted() {
        let scope = fixture_scope();
        let secret = SecretReference::new("secret-ref-fixture", &scope, 1).expect("secret");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("secret-ref-fixture"));
        let file = fixture_file_metadata(&scope);
        let encoded = serde_json::to_string(&file).expect("file metadata JSON");
        assert!(encoded.contains(REDACTED_VALUE));
        assert!(!encoded.contains("fixture design file"));
    }

    fn fixture_scope() -> FigmaScope {
        FigmaScope::new(
            TenantId::new("tenant-fixture").expect("tenant"),
            ProjectId::new("project-fixture").expect("project"),
            MissionId::new("mission-fixture").expect("mission"),
            TeamId::new("team-fixture").expect("team"),
            FigmaProjectId::new("figma-project-fixture").expect("Figma project"),
            FileKey::new("file-fixture").expect("file"),
            [
                NodeId::new("1:1").expect("node"),
                NodeId::new("1:2").expect("node"),
            ],
            VersionId::new("version-fixture").expect("version"),
        )
        .expect("scope")
    }
}
