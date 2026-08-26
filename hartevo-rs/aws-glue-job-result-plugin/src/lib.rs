//! Standalone Layer-1 governed AWS Glue job-run result evidence plugin.
//!
//! This crate freezes AWS account/region/catalog/job/run/attempt and
//! Mission/Project/Work Product fences, reads only bounded job-run metadata,
//! and returns redacted evidence for a later decision. It does not resolve
//! credentials, sign native SigV4/HTTPS requests, start or stop jobs, mutate
//! Glue jobs/triggers/bookmarks, expose arguments/source/logs/data rows, claim
//! transformation or data-quality authority, create a durable provider
//! receipt, or adopt kernel Outcome authority.

#![forbid(unsafe_code)]
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
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

use thiserror::Error;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionAwsGlueJobConsumer, MissionAwsGlueJobResult,
    MissionResultState,
};
pub use model::*;
pub use provider::{
    AwsGlueProvider, AwsGlueProviderDefinition, AwsGlueProviderTransport,
    BlockedEnvAwsGlueTransport, BlockedEnvTransport, FakeAwsGlueTransport, FixtureAwsGlueTransport,
    GetJobDefinitionRequest, GetJobDefinitionResponse, GetJobRunRequest, GetJobRunResponse,
    GetJobRunsRequest, GetJobRunsResponse, LoopbackAwsGlueTransport, ProviderDefinitionError,
    ProviderFence, RecordingAwsGlueTransport, TransportCall, TransportError, is_access_loss,
};
pub use service::{
    AwsGlueJobResultEvidence, AwsGlueJobResultProposal, AwsGlueJobResultReceipt,
    AwsGlueJobResultService, AwsGlueJobResultServiceError, RedactedReceipt, RetryEvidence,
    RetryPolicy, RetryPolicyError, ServiceCapabilities, VerificationReport,
};

pub const AWS_GLUE_JOB_RESULT_SCHEMA_VERSION: &str = "hartevo.aws-glue-job-result.contract/v1";
pub const AWS_GLUE_JOB_RESULT_CONTRACT_VERSION: &str = "aws-glue-job-result-e1/v1";
pub const AWS_GLUE_JOB_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const AWS_GLUE_JOB_RESULT_SERVICE_ID: &str = "aws.glue.job-result";
pub const AWS_GLUE_JOB_RESULT_PROVIDER_ID: &str = "aws.glue.job-runs";
pub const AWS_GLUE_JOB_RESULT_PROVIDER_API_REVISION: &str = "glue-get-job-run-read-r1";
pub const AWS_GLUE_JOB_RESULT_API_REVISION: &str = AWS_GLUE_JOB_RESULT_PROVIDER_API_REVISION;
pub const AWS_GLUE_JOB_RESULT_CONSUMER_ID: &str = "mission.aws-glue-job.result.consumer";
pub const AWS_GLUE_JOB_RESULT_EVIDENCE_LEVEL: &str = "E1_PROVIDER_EVIDENCE";
pub const AWS_GLUE_JOB_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_GLUE_JOB_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-glue-job-result/aws-glue-job-result.v1.json");

pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_GLUE_JOB_RESULT_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractValidationError {
    #[error("AWS Glue contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Glue contract is missing a required key: {0}")]
    MissingKey(&'static str),
    #[error("AWS Glue contract identity drifted: {0}")]
    Identity(&'static str),
    #[error("AWS Glue contract authority boundary widened: {0}")]
    Boundary(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsGlueJobResultContract {
    value: serde_json::Value,
}

impl AwsGlueJobResultContract {
    pub fn baseline() -> Result<Self, ContractValidationError> {
        let value = serde_json::from_str(AWS_GLUE_JOB_RESULT_CONTRACT_JSON)
            .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), ContractValidationError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractValidationError::Identity(
                "contract is not an object",
            ))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "bounds",
            "evidence",
            "registration",
            "authority",
            "honesty",
            "forbidden",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(ContractValidationError::MissingKey(key));
            }
        }
        let text = |key: &'static str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or(ContractValidationError::Identity(key))
        };
        if text("schemaVersion")? != AWS_GLUE_JOB_RESULT_SCHEMA_VERSION
            || text("contractVersion")? != AWS_GLUE_JOB_RESULT_CONTRACT_VERSION
            || text("pluginVersion")? != AWS_GLUE_JOB_RESULT_PLUGIN_VERSION
            || text("layer")? != "Layer-1"
        {
            return Err(ContractValidationError::Identity("top-level identity"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Identity("service"))?;
        if service.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_GLUE_JOB_RESULT_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsGlueJobResultService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Identity("service"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Identity("provider"))?;
        if provider.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_GLUE_JOB_RESULT_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsGlueProvider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Identity("provider"));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Identity("consumer"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_GLUE_JOB_RESULT_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsGlueJobConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Identity("consumer"));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Identity("authority"))?;
        for key in [
            "connected",
            "native",
            "durableReceipt",
            "startJobRun",
            "stopJobRun",
            "jobMutation",
            "triggerMutation",
            "rawArguments",
            "rawScriptOrSource",
            "cloudWatchLogs",
            "dataRows",
            "transformationAuthority",
            "dataQualityAuthority",
            "kernelOutcomeAdoption",
            "workProductAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractValidationError::Boundary(key));
            }
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractValidationError::Boundary("forbidden"))?;
        for required in [
            "StartJobRun",
            "BatchStopJobRun",
            "mutateJob",
            "mutateTrigger",
            "rawJobArguments",
            "scriptSource",
            "cloudWatchLogs",
            "dataRows",
            "transformationClaim",
            "dataQualityClaim",
            "resolveLiveCredentials",
            "adoptKernelOutcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(ContractValidationError::Boundary(required));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn durable_receipt(self) -> bool {
        false
    }

    pub const fn adopted_outcome(self) -> bool {
        false
    }

    pub const fn transformation_authority(self) -> bool {
        false
    }

    pub const fn data_quality_authority(self) -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_layer_one_boundary() {
        let contract = AwsGlueJobResultContract::baseline().expect("AWS Glue contract");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!Layer1Authority.connected());
        assert!(!Layer1Authority.native());
        assert!(!Layer1Authority.durable_receipt());
        assert!(!Layer1Authority.adopted_outcome());
        assert!(!Layer1Authority.transformation_authority());
        assert!(!Layer1Authority.data_quality_authority());
    }
}
