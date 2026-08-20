use serde::Deserialize;

use crate::digest::Digest;

pub const DOCUSIGN_SIGNATURE_SCHEMA_VERSION: &str = "hartevo-docusign-signature-contract/v1";
pub const DOCUSIGN_SIGNATURE_CONTRACT_VERSION: &str = "docusign-signature-layer1/v1";
pub const DOCUSIGN_SIGNATURE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/docusign-signature/docusign-signature.v1.json");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocuSignSignatureContract {
    schema_version: String,
    contract_version: String,
    evidence_level: String,
    authority: ContractAuthority,
    scope_bindings: Vec<String>,
    operations: Vec<String>,
    envelope_states: Vec<String>,
    recipient_states: Vec<String>,
    transport: ContractTransport,
    redaction: ContractRedaction,
    registration: ContractRegistration,
    non_connected_evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ContractAuthority {
    envelope_proposal: bool,
    receipt_projection: bool,
    recipient_status_projection: bool,
    signed_result_adoption_proposal: bool,
    connected: bool,
    native: bool,
    external_writes: bool,
    business_verification: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContractTransport {
    protocol: String,
    authentication: String,
    native_opt_in_environment: String,
    live_calls_permitted: bool,
    layer2_gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContractRedaction {
    oauth_access_and_refresh_material: String,
    signer_pii: String,
    document_bytes: String,
    raw_connect_payload: String,
    raw_provider_response: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ContractRegistration {
    version_bound: bool,
    digest_bound: bool,
    scope_bound: bool,
    reversible: bool,
}

impl DocuSignSignatureContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let contract = serde_json::from_str::<Self>(DOCUSIGN_SIGNATURE_CONTRACT_JSON)
            .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn evidence_level(&self) -> &str {
        &self.evidence_level
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<(), ContractError> {
        let exact = |actual: &[String], expected: &[&str], field: &'static str| {
            let actual = actual.iter().map(String::as_str).collect::<Vec<_>>();
            if actual == expected {
                Ok(())
            } else {
                Err(ContractError::InvalidShape(field))
            }
        };

        if self.schema_version != DOCUSIGN_SIGNATURE_SCHEMA_VERSION
            || self.contract_version != DOCUSIGN_SIGNATURE_CONTRACT_VERSION
            || self.evidence_level != "E1"
            || !self.authority.envelope_proposal
            || !self.authority.receipt_projection
            || !self.authority.recipient_status_projection
            || !self.authority.signed_result_adoption_proposal
            || self.authority.connected
            || self.authority.native
            || self.authority.external_writes
            || self.authority.business_verification
            || self.transport.protocol != "https"
            || self.transport.authentication != "oauth2-secret-reference-only"
            || self.transport.native_opt_in_environment != "HARTEVO_DOCUSIGN_NATIVE_LAYER2"
            || self.transport.live_calls_permitted
            || self.redaction.oauth_access_and_refresh_material != "omitted"
            || self.redaction.signer_pii != "digestOnly"
            || self.redaction.document_bytes != "omitted"
            || self.redaction.raw_connect_payload != "omitted"
            || self.redaction.raw_provider_response != "digestOnly"
            || !self.registration.version_bound
            || !self.registration.digest_bound
            || !self.registration.scope_bound
            || !self.registration.reversible
        {
            return Err(ContractError::InvalidShape("authority or transport"));
        }

        exact(
            &self.scope_bindings,
            &[
                "tenant",
                "project",
                "mission",
                "account",
                "baseUri",
                "providerVersion",
                "registrationDigest",
                "projectRevision",
                "missionRevision",
                "sourceRevision",
            ],
            "scopeBindings",
        )?;
        exact(
            &self.operations,
            &[
                "envelopeProposal",
                "receiptProjection",
                "recipientStatusProjection",
                "signedResultAdoptionProposal",
                "registration",
                "unregistration",
                "revocation",
            ],
            "operations",
        )?;
        exact(
            &self.envelope_states,
            &[
                "created",
                "sent",
                "delivered",
                "completed",
                "declined",
                "voided",
                "providerUnknown",
            ],
            "envelopeStates",
        )?;
        exact(
            &self.recipient_states,
            &[
                "created",
                "sent",
                "delivered",
                "completed",
                "declined",
                "voided",
                "providerUnknown",
            ],
            "recipientStates",
        )?;
        exact(
            &self.transport.layer2_gaps,
            &[
                "envelopeCreate",
                "envelopeSend",
                "signingCeremony",
                "envelopeIdAndUrlReceipt",
                "boundedStatusReconciliation",
                "independentDocumentReadback",
                "connectVerification",
                "ambiguousCreateRecovery",
            ],
            "transport.layer2Gaps",
        )?;
        exact(
            &self.non_connected_evidence,
            &[
                "fixture",
                "loopback",
                "blockedEnv",
                "missingCredentials",
                "accountMismatch",
                "unsupportedStatus",
                "rateLimited",
                "timeout",
                "eventualConsistency",
                "nativeLayer2Gap",
            ],
            "nonConnectedEvidence",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractError {
    #[error("DocuSign signature contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("DocuSign signature contract has an invalid {0} shape")]
    InvalidShape(&'static str),
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(DOCUSIGN_SIGNATURE_CONTRACT_JSON.as_bytes())
}
