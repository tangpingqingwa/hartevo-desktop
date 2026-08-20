use serde::{Deserialize, Serialize};

use crate::{
    AWS_VERIFIED_PERMISSIONS_SERVICE_ID, AWS_VERIFIED_PERMISSIONS_SERVICE_NAME,
    AWS_VERIFIED_PERMISSIONS_SERVICE_SCHEMA, AWS_VERIFIED_PERMISSIONS_VERSION, Digest, ModelError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsVerifiedPermissionsOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    IsAuthorizedRead,
    ProposeAuthorization,
    RecordAuthorization,
    VerifyAuthorization,
    ConsumeObservation,
}

impl AwsVerifiedPermissionsOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::IsAuthorizedRead,
        Self::ProposeAuthorization,
        Self::RecordAuthorization,
        Self::VerifyAuthorization,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }

    pub const fn mutates_registration(self) -> bool {
        matches!(self, Self::Register | Self::RevokeRegistration)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsVerifiedPermissionsCapability {
    pub capability_id: String,
    pub operation: AwsVerifiedPermissionsOperation,
    pub read_only: bool,
    pub mutates_registration: bool,
    pub mutates_policy: bool,
    pub executes_external_action: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsVerifiedPermissionsService {
    service_id: String,
    service_name: String,
    version: String,
    read_only: bool,
    live_execution: bool,
    policy_mutation: bool,
    external_action_execution: bool,
    capabilities: Vec<AwsVerifiedPermissionsCapability>,
}

impl Default for AwsVerifiedPermissionsService {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsVerifiedPermissionsService {
    pub fn new() -> Self {
        let capability_names = [
            (
                "aws.verified-permissions.result.describe_capabilities",
                AwsVerifiedPermissionsOperation::DescribeCapabilities,
            ),
            (
                "aws.verified-permissions.result.register",
                AwsVerifiedPermissionsOperation::Register,
            ),
            (
                "aws.verified-permissions.result.revoke_registration",
                AwsVerifiedPermissionsOperation::RevokeRegistration,
            ),
            (
                "aws.verified-permissions.result.is_authorized_read",
                AwsVerifiedPermissionsOperation::IsAuthorizedRead,
            ),
            (
                "aws.verified-permissions.result.propose_authorization",
                AwsVerifiedPermissionsOperation::ProposeAuthorization,
            ),
            (
                "aws.verified-permissions.result.record_authorization",
                AwsVerifiedPermissionsOperation::RecordAuthorization,
            ),
            (
                "aws.verified-permissions.result.verify_authorization",
                AwsVerifiedPermissionsOperation::VerifyAuthorization,
            ),
            (
                "aws.verified-permissions.result.consume_observation",
                AwsVerifiedPermissionsOperation::ConsumeObservation,
            ),
        ];
        let capabilities = capability_names
            .into_iter()
            .map(
                |(capability_id, operation)| AwsVerifiedPermissionsCapability {
                    capability_id: capability_id.to_owned(),
                    operation,
                    read_only: true,
                    mutates_registration: operation.mutates_registration(),
                    mutates_policy: false,
                    executes_external_action: false,
                    native_evidence: false,
                },
            )
            .collect();
        Self {
            service_id: AWS_VERIFIED_PERMISSIONS_SERVICE_ID.to_owned(),
            service_name: AWS_VERIFIED_PERMISSIONS_SERVICE_NAME.to_owned(),
            version: AWS_VERIFIED_PERMISSIONS_VERSION.to_owned(),
            read_only: true,
            live_execution: false,
            policy_mutation: false,
            external_action_execution: false,
            capabilities,
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

    pub fn version_digest(&self) -> Digest {
        Digest::from_text(self.version.as_bytes())
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn live_execution(&self) -> bool {
        self.live_execution
    }

    pub const fn policy_mutation(&self) -> bool {
        self.policy_mutation
    }

    pub const fn external_action_execution(&self) -> bool {
        self.external_action_execution
    }

    pub fn capabilities(&self) -> &[AwsVerifiedPermissionsCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<AwsVerifiedPermissionsCapability> {
        self.capabilities.clone()
    }

    pub fn capability_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-service-capability/v1",
            &self
                .capabilities
                .iter()
                .map(|capability| {
                    format!(
                        "{}:{:?}:{}:{}:{}:{}:{}",
                        capability.capability_id,
                        capability.operation,
                        capability.read_only,
                        capability.mutates_registration,
                        capability.mutates_policy,
                        capability.executes_external_action,
                        capability.native_evidence
                    )
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn service_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-service/v1",
            &[
                self.service_id.clone(),
                self.service_name.clone(),
                self.version.clone(),
                self.read_only.to_string(),
                self.live_execution.to_string(),
                self.policy_mutation.to_string(),
                self.external_action_execution.to_string(),
                self.capability_digest().as_str().to_owned(),
                AWS_VERIFIED_PERMISSIONS_SERVICE_SCHEMA.to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.service_id != AWS_VERIFIED_PERMISSIONS_SERVICE_ID
            || self.service_name != AWS_VERIFIED_PERMISSIONS_SERVICE_NAME
            || self.version != AWS_VERIFIED_PERMISSIONS_VERSION
            || !self.read_only
            || self.live_execution
            || self.policy_mutation
            || self.external_action_execution
            || self.capabilities.len() != AwsVerifiedPermissionsOperation::ALL.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_policy
                    || capability.executes_external_action
                    || capability.native_evidence
            })
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}
