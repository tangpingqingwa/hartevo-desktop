use std::{
    fmt,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use hartevo_connector_sdk::{ProviderAdapterIdentity, SecretReference};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

use crate::{
    STEP_FUNCTIONS_PROVIDER_ID, STEP_FUNCTIONS_WORKER_CONTRACT_VERSION,
    STEP_FUNCTIONS_WORKER_SCHEMA_VERSION, contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    #[error("identifier is empty, too long, or contains unsupported characters")]
    InvalidIdentifier,
    #[error("digest must be a lowercase SHA-256 hexadecimal value")]
    InvalidDigest,
    #[error("AWS account id must contain exactly twelve decimal digits")]
    InvalidAwsAccountId,
    #[error("AWS region is invalid")]
    InvalidAwsRegion,
    #[error("state-machine ARN is invalid or not an AWS Step Functions ARN")]
    InvalidStateMachineArn,
    #[error("execution ARN is invalid or not an AWS Step Functions execution ARN")]
    InvalidExecutionArn,
    #[error("execution name is invalid")]
    InvalidExecutionName,
    #[error("provider identity is invalid")]
    InvalidProviderIdentity,
    #[error("unknown provider state code is invalid")]
    InvalidUnknownState,
    #[error("task token is empty or exceeds the AWS callback bound")]
    InvalidTaskToken,
    #[error("state-machine ARN does not match the account and region scope")]
    StateMachineScopeMismatch,
    #[error("execution ARN does not match the account and region scope")]
    ExecutionScopeMismatch,
    #[error("execution projection is inconsistent with its exact AWS state")]
    InvalidExecutionProjection,
    #[error("polling policy is outside the bounded Layer-1 limits")]
    InvalidPollingPolicy,
    #[error("polling evidence is internally inconsistent")]
    InvalidPollingEvidence,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("registration contract version is not supported")]
    UnsupportedContractVersion,
    #[error("registration contract digest does not match the checked-in contract")]
    ContractDigestMismatch,
    #[error("registration provider identity is invalid")]
    InvalidProvider,
    #[error("registration has already been revoked")]
    AlreadyRevoked,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hex_encode(&hasher.finalize()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub(crate) fn from_parts(parts: &[&str]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        Self(hex_encode(&hasher.finalize()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

macro_rules! validated_text {
    ($name:ident, $validator:ident) => {
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err(ValidationError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

fn valid_mission_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_unknown_state(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

validated_text!(MissionId, valid_mission_id);
validated_text!(UnknownStateCode, valid_unknown_state);

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidAwsAccountId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AwsAccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAccountId")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric);
        if valid {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidAwsRegion)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AwsRegion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct ExecutionName(String);

impl ExecutionName {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 80
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if valid {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidExecutionName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ExecutionName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for ExecutionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExecutionName")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ExecutionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct StateMachineArn(String);

impl StateMachineArn {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if parse_states_arn(&value, "stateMachine").is_some() {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidStateMachineArn)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn account_id(&self) -> AwsAccountId {
        let parts = parse_states_arn(&self.0, "stateMachine").expect("validated state-machine ARN");
        AwsAccountId::new(parts.account.to_owned()).expect("validated account in ARN")
    }

    pub fn region(&self) -> AwsRegion {
        let parts = parse_states_arn(&self.0, "stateMachine").expect("validated state-machine ARN");
        AwsRegion::new(parts.region.to_owned()).expect("validated region in ARN")
    }

    pub(crate) fn partition(&self) -> &str {
        parse_states_arn(&self.0, "stateMachine")
            .expect("validated state-machine ARN")
            .partition
    }
}

impl<'de> Deserialize<'de> for StateMachineArn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for StateMachineArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateMachineArn")
            .field("digest", &Digest::from_text(&self.0))
            .finish()
    }
}

impl fmt::Display for StateMachineArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct ExecutionArn(String);

impl ExecutionArn {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if parse_states_arn(&value, "execution").is_some() {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidExecutionArn)
        }
    }

    pub(crate) fn for_fixture(
        scope: &StepFunctionsMissionScope,
        identity: &StartExecutionIdentity,
        ordinal: u64,
    ) -> Result<Self, ValidationError> {
        let digest = Digest::from_parts(&[
            scope.binding_digest().as_str(),
            identity.idempotency_key().as_str(),
            &ordinal.to_string(),
        ]);
        let resource = format!(
            "fixture-{}:{}",
            &digest.as_str()[..24],
            identity.name().as_str()
        );
        Self::new(format!(
            "arn:{}:states:{}:{}:execution:{}",
            scope.state_machine_arn().partition(),
            scope.region().as_str(),
            scope.account_id().as_str(),
            resource
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn account_id(&self) -> AwsAccountId {
        let parts = parse_states_arn(&self.0, "execution").expect("validated execution ARN");
        AwsAccountId::new(parts.account.to_owned()).expect("validated account in ARN")
    }

    pub fn region(&self) -> AwsRegion {
        let parts = parse_states_arn(&self.0, "execution").expect("validated execution ARN");
        AwsRegion::new(parts.region.to_owned()).expect("validated region in ARN")
    }
}

impl<'de> Deserialize<'de> for ExecutionArn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for ExecutionArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionArn")
            .field("digest", &Digest::from_text(&self.0))
            .finish()
    }
}

impl fmt::Display for ExecutionArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepFunctionsMissionScope {
    account_id: AwsAccountId,
    region: AwsRegion,
    state_machine_arn: StateMachineArn,
    mission_id: MissionId,
}

impl StepFunctionsMissionScope {
    pub fn new(
        account_id: impl Into<String>,
        region: impl Into<String>,
        state_machine_arn: impl Into<String>,
        mission_id: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        Self::from_typed(
            AwsAccountId::new(account_id)?,
            AwsRegion::new(region)?,
            StateMachineArn::new(state_machine_arn)?,
            MissionId::new(mission_id)?,
        )
    }

    pub fn from_typed(
        account_id: AwsAccountId,
        region: AwsRegion,
        state_machine_arn: StateMachineArn,
        mission_id: MissionId,
    ) -> Result<Self, ValidationError> {
        if state_machine_arn.account_id() != account_id || state_machine_arn.region() != region {
            return Err(ValidationError::StateMachineScopeMismatch);
        }
        Ok(Self {
            account_id,
            region,
            state_machine_arn,
            mission_id,
        })
    }

    pub fn account_id(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn state_machine_arn(&self) -> &StateMachineArn {
        &self.state_machine_arn
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn binding_digest(&self) -> Digest {
        Digest::from_parts(&[
            self.account_id.as_str(),
            self.region.as_str(),
            self.state_machine_arn.as_str(),
            self.mission_id.as_str(),
        ])
    }

    pub(crate) fn matches_execution(&self, execution_arn: &ExecutionArn) -> bool {
        execution_arn.account_id() == self.account_id && execution_arn.region() == self.region
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractVersion {
    V1,
}

impl ContractVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => STEP_FUNCTIONS_WORKER_CONTRACT_VERSION,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdentity {
    adapter: ProviderAdapterIdentity,
    implementation_digest: Digest,
}

impl ProviderIdentity {
    pub fn new(
        provider_id: impl Into<String>,
        provider_version: u32,
        implementation_digest: Digest,
    ) -> Result<Self, ValidationError> {
        let adapter = ProviderAdapterIdentity::new(provider_id, provider_version)
            .map_err(|_| ValidationError::InvalidProviderIdentity)?;
        Ok(Self {
            adapter,
            implementation_digest,
        })
    }

    pub fn step_functions(
        provider_version: u32,
        implementation_digest: Digest,
    ) -> Result<Self, ValidationError> {
        Self::new(
            STEP_FUNCTIONS_PROVIDER_ID,
            provider_version,
            implementation_digest,
        )
    }

    pub fn provider_id(&self) -> &str {
        self.adapter.adapter_id()
    }

    pub const fn provider_version(&self) -> u32 {
        self.adapter.adapter_version()
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }
}

#[derive(Debug)]
struct RegistrationGate {
    revoked: AtomicBool,
}

#[derive(Clone)]
pub struct RegistrationBinding {
    contract_version: ContractVersion,
    contract_digest: Digest,
    provider: ProviderIdentity,
    scope: StepFunctionsMissionScope,
    registration_digest: Digest,
    gate: Arc<RegistrationGate>,
}

impl RegistrationBinding {
    pub fn new(
        scope: StepFunctionsMissionScope,
        provider_version: u32,
        provider_digest: Digest,
    ) -> Result<Self, RegistrationError> {
        let provider = ProviderIdentity::step_functions(provider_version, provider_digest)
            .map_err(|_| RegistrationError::InvalidProvider)?;
        Self::new_with_contract(scope, ContractVersion::V1, contract_digest(), provider)
    }

    pub fn new_with_contract(
        scope: StepFunctionsMissionScope,
        contract_version: ContractVersion,
        contract_digest: Digest,
        provider: ProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        if contract_version.as_str() != STEP_FUNCTIONS_WORKER_CONTRACT_VERSION {
            return Err(RegistrationError::UnsupportedContractVersion);
        }
        if contract_digest != crate::contract_digest() {
            return Err(RegistrationError::ContractDigestMismatch);
        }
        if provider.provider_id() != STEP_FUNCTIONS_PROVIDER_ID || provider.provider_version() == 0
        {
            return Err(RegistrationError::InvalidProvider);
        }
        let registration_digest = Digest::from_parts(&[
            STEP_FUNCTIONS_WORKER_SCHEMA_VERSION,
            contract_version.as_str(),
            contract_digest.as_str(),
            provider.provider_id(),
            &provider.provider_version().to_string(),
            provider.implementation_digest().as_str(),
            scope.binding_digest().as_str(),
        ]);
        Ok(Self {
            contract_version,
            contract_digest,
            provider,
            scope,
            registration_digest,
            gate: Arc::new(RegistrationGate {
                revoked: AtomicBool::new(false),
            }),
        })
    }

    pub fn contract_version(&self) -> ContractVersion {
        self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub fn scope(&self) -> &StepFunctionsMissionScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn is_active(&self) -> bool {
        !self.gate.revoked.load(Ordering::Acquire)
    }

    pub fn revoke(&self) -> Result<(), RegistrationError> {
        if self.gate.revoked.swap(true, Ordering::AcqRel) {
            Err(RegistrationError::AlreadyRevoked)
        } else {
            Ok(())
        }
    }

    pub(crate) fn require_active(&self) -> Result<(), RegistrationError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(RegistrationError::AlreadyRevoked)
        }
    }
}

impl fmt::Debug for RegistrationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationBinding")
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("registration_digest", &self.registration_digest)
            .field("scope_digest", &self.scope.binding_digest())
            .field("provider", &self.provider)
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

impl PartialEq for RegistrationBinding {
    fn eq(&self, other: &Self) -> bool {
        self.registration_digest == other.registration_digest && self.scope == other.scope
    }
}

impl Eq for RegistrationBinding {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReferenceBinding {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: u64,
}

impl SecretReferenceBinding {
    pub(crate) fn from_secret(
        secret: &SecretReference,
        scope: &StepFunctionsMissionScope,
    ) -> Result<Self, crate::provider::ProviderError> {
        if secret.scope().provider_id() != STEP_FUNCTIONS_PROVIDER_ID
            || secret.scope().account_id() != scope.account_id().as_str()
        {
            return Err(crate::provider::ProviderError::AuthenticationScopeMismatch);
        }
        Ok(Self {
            reference_digest: Digest::from_text(secret.reference_id()),
            scope_digest: Digest::from_text(secret.scope().digest()),
            credential_revision: secret.credential_revision(),
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAvailability {
    Fixture,
    Loopback,
    BlockedEnv,
    NativeLayer2Gap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Loopback,
    BlockedEnv,
    NativeLayer2Gap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionEvidence {
    availability: ProviderAvailability,
    provenance: ProviderProvenance,
    connected: bool,
    native: bool,
    registration_digest: Digest,
}

impl ConnectionEvidence {
    pub fn new(
        availability: ProviderAvailability,
        provenance: ProviderProvenance,
        registration: &RegistrationBinding,
    ) -> Self {
        Self {
            availability,
            provenance,
            connected: false,
            native: false,
            registration_digest: registration.registration_digest().clone(),
        }
    }

    pub const fn availability(&self) -> ProviderAvailability {
        self.availability
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    pub const fn is_native(&self) -> bool {
        self.native
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Standard,
    Express,
}

impl ExecutionMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::Express => "EXPRESS",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartExecutionIdentity {
    mode: ExecutionMode,
    name: ExecutionName,
    input_digest: Digest,
    idempotency_key: Digest,
}

impl StartExecutionIdentity {
    pub fn new(mode: ExecutionMode, name: ExecutionName, input_digest: Digest) -> Self {
        let idempotency_key =
            Digest::from_parts(&[mode.as_str(), name.as_str(), input_digest.as_str()]);
        Self {
            mode,
            name,
            input_digest,
            idempotency_key,
        }
    }

    pub fn mode(&self) -> ExecutionMode {
        self.mode
    }

    pub fn name(&self) -> &ExecutionName {
        &self.name
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    pub fn idempotency_key(&self) -> &Digest {
        &self.idempotency_key
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        let expected = Digest::from_parts(&[
            self.mode.as_str(),
            self.name.as_str(),
            self.input_digest.as_str(),
        ]);
        if self.idempotency_key == expected {
            Ok(())
        } else {
            Err(ValidationError::InvalidDigest)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartExecutionProposal {
    scope: StepFunctionsMissionScope,
    identity: StartExecutionIdentity,
    registration_digest: Digest,
}

impl StartExecutionProposal {
    pub(crate) fn new(
        registration: &RegistrationBinding,
        identity: StartExecutionIdentity,
    ) -> Result<Self, ValidationError> {
        identity.validate()?;
        Ok(Self {
            scope: registration.scope().clone(),
            identity,
            registration_digest: registration.registration_digest().clone(),
        })
    }

    pub fn scope(&self) -> &StepFunctionsMissionScope {
        &self.scope
    }

    pub fn identity(&self) -> &StartExecutionIdentity {
        &self.identity
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartExecutionOutcome {
    Started,
    DuplicateSameInput,
    ExpressNonIdempotent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReceipt {
    scope: StepFunctionsMissionScope,
    execution_arn: ExecutionArn,
    identity: StartExecutionIdentity,
    registration_digest: Digest,
    provider: ProviderIdentity,
    provenance: ProviderProvenance,
}

impl ExecutionReceipt {
    pub(crate) fn new(
        scope: StepFunctionsMissionScope,
        execution_arn: ExecutionArn,
        identity: StartExecutionIdentity,
        registration: &RegistrationBinding,
        provenance: ProviderProvenance,
    ) -> Result<Self, ValidationError> {
        identity.validate()?;
        if !scope.matches_execution(&execution_arn) {
            return Err(ValidationError::ExecutionScopeMismatch);
        }
        Ok(Self {
            scope,
            execution_arn,
            identity,
            registration_digest: registration.registration_digest().clone(),
            provider: registration.provider().clone(),
            provenance,
        })
    }

    pub fn scope(&self) -> &StepFunctionsMissionScope {
        &self.scope
    }

    pub fn execution_arn(&self) -> &ExecutionArn {
        &self.execution_arn
    }

    pub fn identity(&self) -> &StartExecutionIdentity {
        &self.identity
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartExecutionReceipt {
    outcome: StartExecutionOutcome,
    execution: ExecutionReceipt,
}

impl StartExecutionReceipt {
    pub(crate) fn new(outcome: StartExecutionOutcome, execution: ExecutionReceipt) -> Self {
        Self { outcome, execution }
    }

    pub const fn outcome(&self) -> StartExecutionOutcome {
        self.outcome
    }

    pub fn execution(&self) -> &ExecutionReceipt {
        &self.execution
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeExecutionRequest {
    execution: ExecutionReceipt,
}

impl DescribeExecutionRequest {
    pub(crate) fn new(execution: ExecutionReceipt) -> Self {
        Self { execution }
    }

    pub fn execution(&self) -> &ExecutionReceipt {
        &self.execution
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "code")]
pub enum ExecutionStatus {
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Aborted,
    PendingRedrive,
    ProviderUnknown(UnknownStateCode),
}

impl ExecutionStatus {
    pub fn from_wire(value: impl Into<String>) -> Self {
        match value.into().as_str() {
            "RUNNING" => Self::Running,
            "SUCCEEDED" => Self::Succeeded,
            "FAILED" => Self::Failed,
            "TIMED_OUT" => Self::TimedOut,
            "ABORTED" => Self::Aborted,
            "PENDING_REDRIVE" => Self::PendingRedrive,
            value => Self::ProviderUnknown(
                UnknownStateCode::new(value).unwrap_or_else(|_| UnknownStateCode("INVALID".into())),
            ),
        }
    }

    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::TimedOut => "TIMED_OUT",
            Self::Aborted => "ABORTED",
            Self::PendingRedrive => "PENDING_REDRIVE",
            Self::ProviderUnknown(_) => "PROVIDER_UNKNOWN",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::TimedOut | Self::Aborted
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    pub fn requires_failure(&self) -> bool {
        matches!(self, Self::Failed | Self::TimedOut | Self::Aborted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "digest")]
pub enum OutputEvidence {
    Present(Digest),
    Missing,
}

impl OutputEvidence {
    pub fn present(digest: Digest) -> Self {
        Self::Present(digest)
    }

    pub const fn missing() -> Self {
        Self::Missing
    }

    pub fn digest(&self) -> Option<&Digest> {
        match self {
            Self::Present(digest) => Some(digest),
            Self::Missing => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "digest")]
pub enum FailureEvidence {
    Present(Digest),
    Missing,
}

impl FailureEvidence {
    pub fn present(digest: Digest) -> Self {
        Self::Present(digest)
    }

    pub const fn missing() -> Self {
        Self::Missing
    }

    pub fn digest(&self) -> Option<&Digest> {
        match self {
            Self::Present(digest) => Some(digest),
            Self::Missing => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationConsistency {
    Fresh,
    EventuallyConsistent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeExecutionFixture {
    execution_arn: ExecutionArn,
    state_machine_arn: StateMachineArn,
    status: ExecutionStatus,
    output: OutputEvidence,
    failure: FailureEvidence,
    consistency: ObservationConsistency,
}

impl DescribeExecutionFixture {
    pub fn new(
        execution_arn: ExecutionArn,
        state_machine_arn: StateMachineArn,
        status: ExecutionStatus,
        output: OutputEvidence,
        failure: FailureEvidence,
        consistency: ObservationConsistency,
    ) -> Self {
        Self {
            execution_arn,
            state_machine_arn,
            status,
            output,
            failure,
            consistency,
        }
    }

    pub fn execution_arn(&self) -> &ExecutionArn {
        &self.execution_arn
    }

    pub fn state_machine_arn(&self) -> &StateMachineArn {
        &self.state_machine_arn
    }

    pub fn status(&self) -> ExecutionStatus {
        self.status.clone()
    }

    pub fn output(&self) -> &OutputEvidence {
        &self.output
    }

    pub fn failure(&self) -> &FailureEvidence {
        &self.failure
    }

    pub const fn consistency(&self) -> ObservationConsistency {
        self.consistency
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionStatusProjection {
    scope: StepFunctionsMissionScope,
    execution_arn: ExecutionArn,
    state_machine_arn: StateMachineArn,
    identity: StartExecutionIdentity,
    status: ExecutionStatus,
    output: OutputEvidence,
    failure: FailureEvidence,
    consistency: ObservationConsistency,
    registration_digest: Digest,
    provider: ProviderIdentity,
    provenance: ProviderProvenance,
}

impl ExecutionStatusProjection {
    pub(crate) fn from_fixture(
        request: &DescribeExecutionRequest,
        fixture: DescribeExecutionFixture,
        registration: &RegistrationBinding,
        provenance: ProviderProvenance,
    ) -> Result<Self, ValidationError> {
        let execution = request.execution();
        if fixture.execution_arn != *execution.execution_arn()
            || fixture.state_machine_arn != *execution.scope().state_machine_arn()
            || fixture.state_machine_arn.account_id() != *execution.scope().account_id()
            || fixture.state_machine_arn.region() != *execution.scope().region()
        {
            return Err(ValidationError::InvalidExecutionProjection);
        }
        if fixture.status.is_success() && !matches!(fixture.failure, FailureEvidence::Missing) {
            return Err(ValidationError::InvalidExecutionProjection);
        }
        if !fixture.status.is_success() && !matches!(fixture.output, OutputEvidence::Missing) {
            return Err(ValidationError::InvalidExecutionProjection);
        }
        Ok(Self {
            scope: execution.scope().clone(),
            execution_arn: execution.execution_arn().clone(),
            state_machine_arn: fixture.state_machine_arn,
            identity: execution.identity().clone(),
            status: fixture.status,
            output: fixture.output,
            failure: fixture.failure,
            consistency: fixture.consistency,
            registration_digest: registration.registration_digest().clone(),
            provider: registration.provider().clone(),
            provenance,
        })
    }

    pub fn scope(&self) -> &StepFunctionsMissionScope {
        &self.scope
    }

    pub fn execution_arn(&self) -> &ExecutionArn {
        &self.execution_arn
    }

    pub fn state_machine_arn(&self) -> &StateMachineArn {
        &self.state_machine_arn
    }

    pub fn identity(&self) -> &StartExecutionIdentity {
        &self.identity
    }

    pub fn status(&self) -> ExecutionStatus {
        self.status.clone()
    }

    pub fn output(&self) -> &OutputEvidence {
        &self.output
    }

    pub fn failure(&self) -> &FailureEvidence {
        &self.failure
    }

    pub const fn consistency(&self) -> ObservationConsistency {
        self.consistency
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollingEvidence {
    attempts: u16,
    delays_ms: Vec<u64>,
    eventual_consistency_observed: bool,
    bounded: bool,
}

impl PollingEvidence {
    pub fn new(
        attempts: u16,
        delays_ms: Vec<u64>,
        eventual_consistency_observed: bool,
        bounded: bool,
    ) -> Result<Self, ValidationError> {
        if attempts == 0 || delays_ms.len() != usize::from(attempts.saturating_sub(1)) {
            return Err(ValidationError::InvalidPollingEvidence);
        }
        Ok(Self {
            attempts,
            delays_ms,
            eventual_consistency_observed,
            bounded,
        })
    }

    pub const fn attempts(&self) -> u16 {
        self.attempts
    }

    pub fn delays_ms(&self) -> &[u64] {
        &self.delays_ms
    }

    pub const fn eventual_consistency_observed(&self) -> bool {
        self.eventual_consistency_observed
    }

    pub const fn is_bounded(&self) -> bool {
        self.bounded
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollPolicy {
    max_attempts: u16,
    initial_delay_ms: u64,
    max_delay_ms: u64,
}

impl PollPolicy {
    pub fn new(
        max_attempts: u16,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Result<Self, ValidationError> {
        if !(1..=32).contains(&max_attempts)
            || initial_delay_ms == 0
            || initial_delay_ms > max_delay_ms
            || max_delay_ms > 60_000
        {
            return Err(ValidationError::InvalidPollingPolicy);
        }
        Ok(Self {
            max_attempts,
            initial_delay_ms,
            max_delay_ms,
        })
    }

    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }

    pub const fn initial_delay_ms(self) -> u64 {
        self.initial_delay_ms
    }

    pub const fn max_delay_ms(self) -> u64 {
        self.max_delay_ms
    }

    pub(crate) fn delay_before_retry(self, attempt: u16) -> u64 {
        let shift = u32::from(attempt.saturating_sub(1).min(16));
        self.initial_delay_ms
            .saturating_mul(1_u64 << shift)
            .min(self.max_delay_ms)
    }
}

impl Default for PollPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_delay_ms: 100,
            max_delay_ms: 1_000,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TaskToken(String);

impl TaskToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if !value.is_empty() && value.len() <= 2_048 && !value.chars().any(char::is_control) {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidTaskToken)
        }
    }

    pub(crate) fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Debug for TaskToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskToken")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskTokenCallbackKind {
    Success,
    Failure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskTokenCallback {
    scope: StepFunctionsMissionScope,
    execution_arn: ExecutionArn,
    token: TaskToken,
    kind: TaskTokenCallbackKind,
    payload_digest: Option<Digest>,
}

impl TaskTokenCallback {
    pub fn new(
        scope: StepFunctionsMissionScope,
        execution_arn: ExecutionArn,
        token: TaskToken,
        kind: TaskTokenCallbackKind,
        payload_digest: Option<Digest>,
    ) -> Result<Self, ValidationError> {
        if !scope.matches_execution(&execution_arn) {
            return Err(ValidationError::ExecutionScopeMismatch);
        }
        if payload_digest.is_none() {
            return Err(ValidationError::InvalidExecutionProjection);
        }
        Ok(Self {
            scope,
            execution_arn,
            token,
            kind,
            payload_digest,
        })
    }

    pub fn scope(&self) -> &StepFunctionsMissionScope {
        &self.scope
    }

    pub fn execution_arn(&self) -> &ExecutionArn {
        &self.execution_arn
    }

    pub fn kind(&self) -> TaskTokenCallbackKind {
        self.kind
    }

    pub fn payload_digest(&self) -> Option<&Digest> {
        self.payload_digest.as_ref()
    }

    pub(crate) fn token_digest(&self) -> Digest {
        self.token.digest()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTokenReceipt {
    scope: StepFunctionsMissionScope,
    execution_arn: ExecutionArn,
    token_digest: Digest,
    kind: TaskTokenCallbackKind,
    payload_digest: Digest,
    registration_digest: Digest,
    provider: ProviderIdentity,
    provenance: ProviderProvenance,
    projected_only: bool,
}

impl TaskTokenReceipt {
    pub(crate) fn from_callback(
        callback: &TaskTokenCallback,
        registration: &RegistrationBinding,
        provenance: ProviderProvenance,
    ) -> Self {
        Self {
            scope: callback.scope.clone(),
            execution_arn: callback.execution_arn.clone(),
            token_digest: callback.token_digest(),
            kind: callback.kind,
            payload_digest: callback
                .payload_digest
                .clone()
                .expect("callback validates a payload digest"),
            registration_digest: registration.registration_digest().clone(),
            provider: registration.provider().clone(),
            provenance,
            projected_only: true,
        }
    }

    pub fn scope(&self) -> &StepFunctionsMissionScope {
        &self.scope
    }

    pub fn execution_arn(&self) -> &ExecutionArn {
        &self.execution_arn
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn kind(&self) -> TaskTokenCallbackKind {
        self.kind
    }

    pub fn payload_digest(&self) -> &Digest {
        &self.payload_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub const fn is_projected_only(&self) -> bool {
        self.projected_only
    }
}

fn parse_states_arn<'a>(value: &'a str, expected_resource_type: &str) -> Option<ArnParts<'a>> {
    let mut parts = value.splitn(6, ':');
    let prefix = parts.next()?;
    let partition = parts.next()?;
    let service = parts.next()?;
    let region = parts.next()?;
    let account = parts.next()?;
    let resource = parts.next()?;
    let (resource_type, resource_value) = resource.split_once(':')?;
    if prefix != "arn"
        || partition.is_empty()
        || service != "states"
        || resource_type != expected_resource_type
        || resource_value.is_empty()
        || value.len() > 256
        || AwsAccountId::new(account).is_err()
        || AwsRegion::new(region).is_err()
    {
        return None;
    }
    Some(ArnParts {
        partition,
        region,
        account,
        resource: resource_value,
    })
}

struct ArnParts<'a> {
    partition: &'a str,
    region: &'a str,
    account: &'a str,
    #[allow(dead_code)]
    resource: &'a str,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}
