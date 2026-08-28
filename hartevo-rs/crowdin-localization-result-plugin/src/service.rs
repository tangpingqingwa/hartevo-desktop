//! Typed service descriptor and canonical proposal compiler.

use crate::model::{
    CrowdinLocalizationResultProposal, CrowdinLocalizationScope, CrowdinReadOperation,
    ObservationWindow, ReadBounds, SecretReference,
};
use crate::{
    CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION, CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT,
    CROWDIN_LOCALIZATION_RESULT_SERVICE_ID, CROWDIN_LOCALIZATION_RESULT_SERVICE_NAME,
    CROWDIN_PROVIDER_ID, CROWDIN_PROVIDER_REVISION, CrowdinError, contract_digest,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrowdinCapability {
    pub capability_id: String,
    pub operation: String,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrowdinLocalizationResultService {
    service_id: String,
    service_name: String,
    version: String,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<CrowdinCapability>,
}

impl Default for CrowdinLocalizationResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl CrowdinLocalizationResultService {
    pub fn new() -> Self {
        let operations = [
            (
                "crowdin.localization-result.describe",
                "describe_capabilities",
            ),
            ("crowdin.localization-result.register", "register"),
            ("crowdin.localization-result.revoke", "revoke_registration"),
            (
                "crowdin.localization-result.project-metadata",
                "read_project_metadata",
            ),
            (
                "crowdin.localization-result.language-coverage",
                "read_language_coverage",
            ),
            (
                "crowdin.localization-result.source-file-metadata",
                "read_source_file_metadata",
            ),
            (
                "crowdin.localization-result.translation-progress",
                "read_translation_progress",
            ),
            (
                "crowdin.localization-result.translation-build-status",
                "read_translation_build_status",
            ),
            (
                "crowdin.localization-result.compile-proposal",
                "compile_localization_result_proposal",
            ),
            (
                "crowdin.localization-result.record",
                "record_localization_result",
            ),
        ];
        Self {
            service_id: CROWDIN_LOCALIZATION_RESULT_SERVICE_ID.to_owned(),
            service_name: CROWDIN_LOCALIZATION_RESULT_SERVICE_NAME.to_owned(),
            version: CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            read_only: true,
            native_connected: false,
            capabilities: operations
                .into_iter()
                .map(|(capability_id, operation)| CrowdinCapability {
                    capability_id: capability_id.to_owned(),
                    operation: operation.to_owned(),
                    read_only: true,
                    mutates_provider: false,
                    native_evidence: false,
                })
                .collect(),
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[CrowdinCapability] {
        &self.capabilities
    }

    pub fn validate(&self) -> Result<(), CrowdinError> {
        let contract = crate::CrowdinLocalizationResultContract::baseline()?;
        if self.service_id != CROWDIN_LOCALIZATION_RESULT_SERVICE_ID
            || self.service_name != CROWDIN_LOCALIZATION_RESULT_SERVICE_NAME
            || self.version != CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT
            || !self.read_only
            || self.native_connected
            || self.capabilities.len() != contract.service.operations.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(CrowdinError::InvalidInput(
                "Crowdin Localization Result service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn compile_proposal(
        &self,
        scope: &CrowdinLocalizationScope,
        secret_reference: &SecretReference,
        observation_window: ObservationWindow,
    ) -> Result<CrowdinLocalizationResultProposal, CrowdinError> {
        self.compile_proposal_with_bounds(
            scope,
            secret_reference,
            observation_window,
            ReadBounds::layer1(),
        )
    }

    pub fn compile_proposal_with_bounds(
        &self,
        scope: &CrowdinLocalizationScope,
        secret_reference: &SecretReference,
        observation_window: ObservationWindow,
        bounds: ReadBounds,
    ) -> Result<CrowdinLocalizationResultProposal, CrowdinError> {
        self.validate()?;
        let proposal = CrowdinLocalizationResultProposal::new(
            scope.clone(),
            secret_reference,
            observation_window,
            bounds,
            contract_digest(),
            CROWDIN_PROVIDER_REVISION,
        )?;
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn allowed_read_operations(&self) -> Vec<CrowdinReadOperation> {
        vec![
            CrowdinReadOperation::ProjectMetadata,
            CrowdinReadOperation::LanguageCoverage,
            CrowdinReadOperation::SourceFileMetadata,
            CrowdinReadOperation::TranslationProgress,
            CrowdinReadOperation::TranslationBuildStatus,
        ]
    }

    pub fn contract_version(&self) -> &'static str {
        CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION
    }

    pub fn provider_id(&self) -> &'static str {
        CROWDIN_PROVIDER_ID
    }
}
