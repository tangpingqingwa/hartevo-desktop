//! Standalone Layer-1 governed Workato recipe/job result evidence.
//!
//! The crate is intentionally read/proposal/recording-only. It binds one
//! Workato workspace/project/folder/recipe/version/job/retry/step scope and
//! one exact Hartevo Mission scope. It has no native credential resolver,
//! HTTP client, scheduler, worker runtime, external effect authority,
//! durable native receipt, independent read-back, or Outcome adoption.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::return_self_not_must_use
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionWorkatoRecipeConsumer, MissionWorkatoRecipeResult,
    MissionWorkatoRecipeState,
};
pub use model::{
    ConsentScope, ConsumerId, Digest, FolderId, JobHandle, JobIdentity, JobProjection, JobStatus,
    MissionId, MissionScope, ModelError, PermissionScope, ProjectId, RecipeId, RecipeProjection,
    RecipeVersionBinding, RecipeVersionId, RecipeVersionProjection, RegistrationState,
    RegistrationTransition, RetentionState, RetryIdentity, RetryProjection, Revision, SecretKind,
    SecretReference, ServiceId, StepId, StepProjection, StepScope, StepStatus, WorkProductId,
    WorkatoOperation, WorkatoProjectId, WorkatoRegistration, WorkatoResultStatus, WorkatoScope,
    WorkspaceId,
};
pub use provider::{
    BlockedEnvTransport, FixtureTransport, FixtureWorkatoTransport, JobPageProjection,
    JobPageRequest, JobStatusFilter, JobSummaryProjection, LoopbackTransport,
    LoopbackWorkatoTransport, ProviderDefinitionError, ProviderError, ProviderErrorEvidence,
    ProviderErrorKind, ProviderProvenance, ProviderRead, RawJob, RawRecipe, RawRecipeVersion,
    RawStep, RecipeVersionPageRequest, RecordingTransport, RecordingWorkatoTransport, RetryAttempt,
    RetryPolicy, TransportError, WorkatoProvider, WorkatoProviderDefinition, WorkatoReadReceipt,
    WorkatoReadRequest, WorkatoResponse, WorkatoResponseBody, WorkatoTransport,
};
pub use service::{
    AdoptionDisposition, WorkatoEffectKind, WorkatoEffectProposal, WorkatoReadBackProjection,
    WorkatoReadBackRequest, WorkatoRecipeResultService, WorkatoRecordingReceipt,
    WorkatoResultEvidence, WorkatoResultProposal, WorkatoServiceDefinition, WorkatoServiceError,
    WorkatoVerificationProjection,
};

pub const WORKATO_RECIPE_RESULT_SCHEMA_VERSION: &str = "hartevo.workato-recipe-result/v1";
pub const WORKATO_RECIPE_RESULT_CONTRACT_VERSION: &str = "EXT-WORKATO-01-L1/v1";
pub const WORKATO_RECIPE_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const WORKATO_RECIPE_RESULT_SERVICE_ID: &str = "workato.recipe-result";
pub const WORKATO_RECIPE_RESULT_PROVIDER_ID: &str = "workato.developer-api";
pub const WORKATO_RECIPE_RESULT_CONSUMER_ID: &str = "mission.workato-recipe-result";
pub const WORKATO_RECIPE_RESULT_SERVICE_NAME: &str = "WorkatoRecipeResultService";
pub const WORKATO_RECIPE_RESULT_PROVIDER_NAME: &str = "WorkatoProvider";
pub const WORKATO_RECIPE_RESULT_CONSUMER_NAME: &str = "MissionWorkatoRecipeConsumer";
pub const WORKATO_RECIPE_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const WORKATO_RECIPE_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/workato-recipe-result/service.v1.json");

/// Layer 1's authority boundary is intentionally empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn scheduler_authority() -> bool {
        false
    }

    pub const fn effect_authority() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn independent_read_back() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(WORKATO_RECIPE_RESULT_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkatoContract {
    document: serde_json::Value,
}

impl WorkatoContract {
    pub fn baseline() -> Result<Self, String> {
        let document =
            serde_json::from_str::<serde_json::Value>(WORKATO_RECIPE_RESULT_CONTRACT_JSON)
                .map_err(|error| error.to_string())?;
        let contract = Self { document };
        contract.validate()?;
        Ok(contract)
    }

    pub fn document(&self) -> &serde_json::Value {
        &self.document
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), String> {
        let exact = [
            ("schemaVersion", WORKATO_RECIPE_RESULT_SCHEMA_VERSION),
            ("contractVersion", WORKATO_RECIPE_RESULT_CONTRACT_VERSION),
            ("pluginVersion", WORKATO_RECIPE_RESULT_PLUGIN_VERSION),
            ("service.id", WORKATO_RECIPE_RESULT_SERVICE_ID),
            ("service.implementation", WORKATO_RECIPE_RESULT_SERVICE_NAME),
            ("provider.id", WORKATO_RECIPE_RESULT_PROVIDER_ID),
            (
                "provider.implementation",
                WORKATO_RECIPE_RESULT_PROVIDER_NAME,
            ),
            ("consumer.id", WORKATO_RECIPE_RESULT_CONSUMER_ID),
            (
                "consumer.implementation",
                WORKATO_RECIPE_RESULT_CONSUMER_NAME,
            ),
        ];
        for (path, expected) in exact {
            if schema_const(&self.document, path).and_then(serde_json::Value::as_str)
                != Some(expected)
            {
                return Err(format!("{path} does not match the Layer-1 contract"));
            }
        }
        if schema_const(&self.document, "layer").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err("layer must be 1".to_owned());
        }
        for path in [
            "service.readOnly",
            "service.proposalOnly",
            "service.recordingOnly",
            "registration.reversible",
            "registration.revocable",
            "consent.readProposal",
            "consent.digestBound",
            "receipts.requestRedacted",
            "receipts.resultRedacted",
        ] {
            if schema_const(&self.document, path).and_then(serde_json::Value::as_bool) != Some(true)
            {
                return Err(format!("{path} must be true"));
            }
        }
        for path in [
            "service.liveExecution",
            "service.schedulerAuthority",
            "service.effectAuthority",
            "service.receiptAuthority",
            "service.verificationAuthority",
            "provider.native",
            "provider.connected",
            "provider.firstParty",
            "provider.externalWrites",
            "consumer.adoptsOutcome",
            "consumer.adoptsWorkProduct",
            "consumer.truthAuthority",
            "consumer.schedulerAuthority",
            "allowlist.methodIsWrite",
            "consent.externalEffects",
            "consent.effectAuthority",
            "receipts.durableNative",
            "receipts.independentReadBack",
            "honesty.connected",
            "honesty.native",
            "honesty.firstParty",
            "honesty.schedulerAuthority",
            "honesty.kernelOutcomeAdopted",
        ] {
            if let Some(value) = schema_const(&self.document, path)
                && value.as_bool() == Some(true)
            {
                return Err(format!("{path} must be false or absent"));
            }
        }
        if schema_const(&self.document, "provider.readRatePerMinute")
            .and_then(serde_json::Value::as_u64)
            != Some(60)
            || schema_const(&self.document, "bounds.readRatePerMinute")
                .and_then(serde_json::Value::as_u64)
                != Some(60)
            || schema_const(&self.document, "bounds.maxRetryAttempts")
                .and_then(serde_json::Value::as_u64)
                != Some(3)
        {
            return Err("Workato read bounds do not match the Layer-1 ceiling".to_owned());
        }
        let modes = schema_const(&self.document, "provider.acceptedProvenance")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "provider.acceptedProvenance is not an array".to_owned())?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        if modes != ["fixture", "recording", "loopback", "BLOCKED_ENV"] {
            return Err("provider provenance must remain non-native".to_owned());
        }
        if schema_const(&self.document, "allowlist.writes")
            != Some(&serde_json::Value::Array(Vec::new()))
        {
            return Err("Workato allowlist must contain no writes".to_owned());
        }
        if schema_const(&self.document, "allowlist.method").and_then(serde_json::Value::as_str)
            != Some("GET")
        {
            return Err("Workato allowlist method must be GET".to_owned());
        }
        Ok(())
    }
}

fn schema_const<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get("properties")?.get(segment)?;
    }
    current.get("const")
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_non_native() {
        let contract = WorkatoContract::baseline().expect("valid Workato contract");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::scheduler_authority());
        assert!(!Layer1Authority::effect_authority());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::independent_read_back());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
        assert_eq!(WORKATO_RECIPE_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    }
}
