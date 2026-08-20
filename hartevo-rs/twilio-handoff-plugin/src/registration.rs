use serde::{Deserialize, Serialize};

use crate::error::TwilioHandoffError;
use crate::model::{RegistrationDigest, TwilioScope, sha256_hex};

/// A local, reversible registration bound to one checked-in contract digest
/// and one exact Twilio Project/Mission scope.  It contains no credential
/// material and grants no host authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwilioHandoffRegistration {
    pub plugin_id: String,
    pub plugin_version: u32,
    pub contract_version: String,
    pub contract_digest: RegistrationDigest,
    pub scope: TwilioScope,
    pub scope_digest: RegistrationDigest,
    pub registration_digest: RegistrationDigest,
    pub registration_revision: u64,
    pub active: bool,
}

impl TwilioHandoffRegistration {
    pub fn new(scope: TwilioScope) -> Result<Self, TwilioHandoffError> {
        scope.validate()?;
        let contract_digest = RegistrationDigest::new(crate::twilio_handoff_contract_digest())?;
        let scope_digest = RegistrationDigest::new(scope.digest())?;
        let registration_digest = RegistrationDigest::new(sha256_hex(
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                crate::TWILIO_HANDOFF_PLUGIN_ID,
                crate::TWILIO_HANDOFF_PLUGIN_VERSION,
                crate::TWILIO_HANDOFF_CONTRACT_VERSION,
                contract_digest,
                scope_digest,
                crate::TWILIO_HANDOFF_PROVIDER_ID
            )
            .as_bytes(),
        ))?;
        Ok(Self {
            plugin_id: String::from(crate::TWILIO_HANDOFF_PLUGIN_ID),
            plugin_version: crate::TWILIO_HANDOFF_PLUGIN_VERSION,
            contract_version: String::from(crate::TWILIO_HANDOFF_CONTRACT_VERSION),
            contract_digest,
            scope,
            scope_digest,
            registration_digest,
            registration_revision: 1,
            active: true,
        })
    }

    pub fn validate(&self) -> Result<(), TwilioHandoffError> {
        if self.plugin_id != crate::TWILIO_HANDOFF_PLUGIN_ID
            || self.plugin_version != crate::TWILIO_HANDOFF_PLUGIN_VERSION
            || self.contract_version != crate::TWILIO_HANDOFF_CONTRACT_VERSION
            || self.contract_digest.as_str() != crate::twilio_handoff_contract_digest()
            || self.scope_digest.as_str() != self.scope.digest()
            || self.registration_digest.as_str() != self.expected_registration_digest()
        {
            return Err(TwilioHandoffError::RegistrationDigestInvalid);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn scope_digest(&self) -> &RegistrationDigest {
        &self.scope_digest
    }

    pub fn registration_digest(&self) -> &RegistrationDigest {
        &self.registration_digest
    }

    pub fn expected_registration_digest(&self) -> String {
        sha256_hex(
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                self.plugin_id,
                self.plugin_version,
                self.contract_version,
                self.contract_digest,
                self.scope_digest,
                crate::TWILIO_HANDOFF_PROVIDER_ID
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, TwilioHandoffError> {
        self.validate()?;
        if !self.active {
            return Err(TwilioHandoffError::RegistrationRevoked);
        }
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(TwilioHandoffError::RegistrationRevisionOverflow)?;
        self.active = false;
        Ok(RegistrationRevocation {
            plugin_id: self.plugin_id.clone(),
            plugin_version: self.plugin_version,
            contract_digest: self.contract_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            revocation_revision: self.registration_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub plugin_id: String,
    pub plugin_version: u32,
    pub contract_digest: RegistrationDigest,
    pub scope_digest: RegistrationDigest,
    pub registration_digest: RegistrationDigest,
    pub revocation_revision: u64,
}
