use std::collections::BTreeSet;

use crate::error::{AirtableError, ReadbackMismatch, ReadbackMismatchField};
use crate::model::{
    AirtableCapability, AirtableFieldAllowlist, AirtableProviderManifest,
    AirtableProviderProvenance, AirtableReadRecordsResult, AirtableRecordBatch, AirtableRecordPage,
    AirtableSchemaDescription, AirtableScope, AirtableTableSchema, ListRecordsRequest,
    MissionOutput, MissionOutputKind, MissionRecordProposalRequest, ProposedField, ReadbackReceipt,
    ReceiptKind, RecordProposal, RecordReadback, RecordReceipt, RecordValue, SecretReference,
    StableRecordField, content_fingerprint, idempotency_key,
};
use crate::provider::AirtableOpsProvider;

/// Typed Layer 1 service.  It owns no Store, keyring, browser profile, effect
/// broker, HTTP write transport, or webhook truth authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AirtableOpsService {
    contract_digest: String,
}

impl Default for AirtableOpsService {
    fn default() -> Self {
        Self::new()
    }
}

impl AirtableOpsService {
    pub fn new() -> Self {
        Self {
            contract_digest: crate::contract_digest(),
        }
    }

    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }

    pub fn provider_manifest(
        &self,
        scope: AirtableScope,
        provenance: AirtableProviderProvenance,
    ) -> AirtableProviderManifest {
        AirtableProviderManifest::baseline(scope, provenance)
    }

    /// Read and validate the current base/table schema.  The SecretReference
    /// is handed to the provider boundary and never copied into the receipt.
    pub fn describe_schema<P: AirtableOpsProvider>(
        &self,
        provider: &mut P,
        scope: &AirtableScope,
        secret: &SecretReference,
    ) -> Result<AirtableSchemaDescription, AirtableError> {
        Self::validate_provider(provider, scope)?;
        let schema = provider.describe_schema(scope, secret)?;
        if schema.scope != *scope {
            return Err(AirtableError::ScopeMismatch {
                expected: Box::new(scope.clone()),
                observed: Box::new(schema.scope),
            });
        }
        schema.validate()?;
        Ok(AirtableSchemaDescription {
            schema,
            provider_manifest_digest: provider.manifest().contract_digest.clone(),
            provenance: provider.provenance(),
        })
    }

    /// Compile a WorkProduct or OutcomeCandidate into one base/table scoped
    /// structured record proposal.  Only stable fields present in the
    /// explicit allowlist are emitted.
    pub fn compile_record_proposal(
        &self,
        request: MissionRecordProposalRequest,
    ) -> Result<RecordProposal, AirtableError> {
        if request.schema.scope != request.scope {
            return Err(AirtableError::ScopeMismatch {
                expected: Box::new(request.scope),
                observed: Box::new(request.schema.scope),
            });
        }
        request.schema.validate()?;
        request.field_allowlist.validate(&request.schema)?;
        Self::require_identity_allowlist(&request.field_allowlist, request.output.kind())?;

        let content_digest = content_fingerprint(&request.output);
        let field_fingerprint = request.field_allowlist.field_fingerprint();
        let idempotency = idempotency_key(
            &request.scope,
            &request.output,
            &content_digest,
            &self.contract_digest,
            &field_fingerprint,
        );
        let mut fields = Vec::new();
        for (stable_field, binding) in &request.field_allowlist.bindings {
            let Some(value) = stable_value(
                *stable_field,
                &request.output,
                &content_digest,
                &idempotency,
            ) else {
                continue;
            };
            if !binding.field_type.accepts(&value) {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.field_id.to_string(),
                    reason: format!(
                        "stable field {} does not fit the approved Airtable type {:?}",
                        stable_field.key(),
                        binding.field_type
                    ),
                });
            }
            fields.push(ProposedField {
                stable_field: *stable_field,
                field_id: binding.field_id.clone(),
                field_name: binding.field_name.clone(),
                field_type: binding.field_type,
                value,
            });
        }

        Ok(RecordProposal {
            scope: request.scope,
            mission_id: request.output.mission_id().clone(),
            project_id: request.output.project_id().clone(),
            output_kind: request.output.kind(),
            output_id: request.output.output_id(),
            revision: request.output.revision(),
            manifest_digest: self.contract_digest.clone(),
            schema_fingerprint: request.schema.schema_fingerprint,
            field_fingerprint,
            content_fingerprint: content_digest,
            idempotency_key: idempotency,
            fields,
            provenance: AirtableProviderProvenance::Recording,
        })
    }

    pub fn compile_record_proposal_for_output(
        &self,
        scope: AirtableScope,
        schema: AirtableTableSchema,
        field_allowlist: AirtableFieldAllowlist,
        output: MissionOutput,
    ) -> Result<RecordProposal, AirtableError> {
        self.compile_record_proposal(MissionRecordProposalRequest::new(
            scope,
            schema,
            field_allowlist,
            output,
        )?)
    }

    /// Read every page using Airtable's opaque offset and return a receipt of
    /// the traversal.  A repeated offset is a fail-closed pagination error.
    pub fn read_records<P: AirtableOpsProvider>(
        &self,
        provider: &mut P,
        scope: &AirtableScope,
        secret: &SecretReference,
        page_size: usize,
        max_records: Option<usize>,
    ) -> Result<AirtableReadRecordsResult, AirtableError> {
        Self::validate_provider(provider, scope)?;
        let mut request = ListRecordsRequest::new(page_size)?;
        let mut records = Vec::new();
        let mut pages = 0;
        let mut offsets = Vec::new();
        let mut seen_offsets = BTreeSet::new();
        loop {
            let current_offset = request.offset.clone();
            let page: AirtableRecordPage = provider.list_records(scope, &request, secret)?;
            pages += 1;
            if page.records.len() > request.page_size {
                return Err(AirtableError::Pagination {
                    reason: format!(
                        "provider returned {} records for requested page size {}",
                        page.records.len(),
                        request.page_size
                    ),
                });
            }
            for record in page.records {
                if record.scope != *scope {
                    return Err(AirtableError::ScopeMismatch {
                        expected: Box::new(scope.clone()),
                        observed: Box::new(record.scope),
                    });
                }
                records.push(record);
                if max_records.is_some_and(|maximum| records.len() >= maximum) {
                    let record_count = records.len();
                    return Ok(AirtableReadRecordsResult {
                        scope: scope.clone(),
                        records,
                        pagination: crate::model::PaginationReceipt {
                            pages,
                            records: record_count,
                            offsets,
                        },
                        provenance: provider.provenance(),
                    });
                }
            }
            let Some(next_offset) = page.next_offset else {
                break;
            };
            if Some(next_offset.clone()) == current_offset
                || !seen_offsets.insert(next_offset.clone())
            {
                return Err(AirtableError::Pagination {
                    reason: "provider returned a repeated pagination offset".to_owned(),
                });
            }
            offsets.push(next_offset.to_string());
            request = request.with_offset(next_offset);
        }
        let record_count = records.len();
        Ok(AirtableReadRecordsResult {
            scope: scope.clone(),
            records,
            pagination: crate::model::PaginationReceipt {
                pages,
                records: record_count,
                offsets,
            },
            provenance: provider.provenance(),
        })
    }

    pub fn batch_proposals(&self, proposals: Vec<RecordProposal>) -> Vec<AirtableRecordBatch> {
        AirtableRecordBatch::partition(proposals)
    }

    /// Verify the identity, scoped schema, revision, and content digest of a
    /// provider read-back against both the proposal and the recording receipt.
    pub fn verify_record_readback(
        &self,
        proposal: &RecordProposal,
        receipt: &RecordReceipt,
        readback: &RecordReadback,
    ) -> Result<ReadbackReceipt, AirtableError> {
        if proposal.manifest_digest != self.contract_digest {
            return Err(AirtableError::ContractDrift {
                expected: self.contract_digest.clone(),
                observed: proposal.manifest_digest.clone(),
            });
        }
        compare(
            ReadbackMismatchField::Scope,
            &proposal.scope.fingerprint(),
            &receipt.scope.fingerprint(),
        )?;
        compare(
            ReadbackMismatchField::FieldFingerprint,
            &proposal.field_fingerprint,
            &receipt.field_fingerprint,
        )?;
        compare(
            ReadbackMismatchField::Revision,
            &proposal.revision.to_string(),
            &receipt.revision.to_string(),
        )?;
        compare(
            ReadbackMismatchField::ContentDigest,
            &proposal.content_fingerprint,
            &receipt.content_digest,
        )?;
        compare(
            ReadbackMismatchField::IdempotencyKey,
            &proposal.idempotency_key,
            &receipt.idempotency_key,
        )?;
        compare(
            ReadbackMismatchField::ManifestDigest,
            &proposal.manifest_digest,
            &receipt.manifest_digest,
        )?;
        if receipt.write_executed {
            return Err(AirtableError::ReceiptMismatch {
                reason: "Layer 1 receipts cannot claim an executed external write".to_owned(),
            });
        }
        if receipt.provenance.is_connected() || readback.provenance.is_connected() {
            return Err(AirtableError::ContractDrift {
                expected: "Layer 1 non-native read-back provenance".to_owned(),
                observed: "native_https".to_owned(),
            });
        }
        compare(
            ReadbackMismatchField::RecordId,
            receipt.record_id.as_str(),
            readback.record_id.as_str(),
        )?;
        compare(
            ReadbackMismatchField::Scope,
            &receipt.scope.fingerprint(),
            &readback.scope.fingerprint(),
        )?;
        compare(
            ReadbackMismatchField::FieldFingerprint,
            &receipt.field_fingerprint,
            &readback.field_fingerprint,
        )?;
        compare(
            ReadbackMismatchField::Revision,
            &receipt.revision.to_string(),
            &readback.revision.to_string(),
        )?;
        compare(
            ReadbackMismatchField::ContentDigest,
            &receipt.content_digest,
            &readback.content_digest,
        )?;
        if receipt.provenance != readback.provenance {
            return Err(AirtableError::ReadbackMismatch(ReadbackMismatch::new(
                ReadbackMismatchField::ProviderProvenance,
                format!("{:?}", receipt.provenance),
                format!("{:?}", readback.provenance),
            )));
        }
        Ok(ReadbackReceipt {
            record_id: readback.record_id.clone(),
            scope: readback.scope.clone(),
            field_fingerprint: readback.field_fingerprint.clone(),
            revision: readback.revision,
            content_digest: readback.content_digest.clone(),
            manifest_digest: proposal.manifest_digest.clone(),
            verified: true,
            provenance: readback.provenance,
        })
    }

    pub fn readback_and_verify<P: AirtableOpsProvider>(
        &self,
        provider: &mut P,
        proposal: &RecordProposal,
        receipt: &RecordReceipt,
        secret: &SecretReference,
    ) -> Result<ReadbackReceipt, AirtableError> {
        Self::validate_provider(provider, &proposal.scope)?;
        let field_ids = proposal.field_ids().into_iter().collect::<Vec<_>>();
        let readback =
            provider.read_record(&proposal.scope, &receipt.record_id, &field_ids, secret)?;
        self.verify_record_readback(proposal, receipt, &readback)
    }

    pub fn recording_receipt<P: AirtableOpsProvider>(
        &self,
        provider: &P,
        proposal: &RecordProposal,
        record_id: crate::model::AirtableRecordId,
    ) -> Result<RecordReceipt, AirtableError> {
        let kind = match provider.provenance() {
            AirtableProviderProvenance::Recording => ReceiptKind::Recording,
            AirtableProviderProvenance::Fixture => ReceiptKind::Fixture,
            other => {
                return Err(AirtableError::ContractDrift {
                    expected: "recording or fixture provider".to_owned(),
                    observed: format!("{other:?}"),
                });
            }
        };
        RecordReceipt::from_proposal(proposal, record_id, provider.provenance(), kind)
    }

    fn validate_provider<P: AirtableOpsProvider>(
        provider: &P,
        scope: &AirtableScope,
    ) -> Result<(), AirtableError> {
        provider.manifest().validate_for(scope)?;
        if provider.provenance().is_connected() || provider.writes_enabled() {
            return Err(AirtableError::ContractDrift {
                expected: "Layer 1 non-connected, non-writing provider".to_owned(),
                observed: "provider claims native or write authority".to_owned(),
            });
        }
        for capability in [
            AirtableCapability::DescribeSchema,
            AirtableCapability::ReadRecords,
        ] {
            if !provider.manifest().capabilities.contains(&capability) {
                return Err(AirtableError::ContractDrift {
                    expected: format!("provider capability {capability:?}"),
                    observed: "capability missing".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn require_identity_allowlist(
        allowlist: &AirtableFieldAllowlist,
        kind: MissionOutputKind,
    ) -> Result<(), AirtableError> {
        let required = [
            StableRecordField::MissionId,
            StableRecordField::ProjectId,
            StableRecordField::Revision,
            StableRecordField::ContentFingerprint,
            StableRecordField::IdempotencyKey,
        ];
        for field in required {
            if !allowlist.contains(field) {
                return Err(AirtableError::FieldAllowlist {
                    field: field.key().to_owned(),
                    reason: "stable identity field is required".to_owned(),
                });
            }
        }
        let output_field = match kind {
            MissionOutputKind::WorkProduct => StableRecordField::WorkProductId,
            MissionOutputKind::OutcomeCandidate => StableRecordField::OutcomeCandidateId,
        };
        if !allowlist.contains(output_field) {
            return Err(AirtableError::FieldAllowlist {
                field: output_field.key().to_owned(),
                reason: "output identity field is required".to_owned(),
            });
        }
        Ok(())
    }
}

fn stable_value(
    stable_field: StableRecordField,
    output: &MissionOutput,
    content_digest: &str,
    idempotency: &str,
) -> Option<RecordValue> {
    match stable_field {
        StableRecordField::MissionId => Some(RecordValue::Text(output.mission_id().to_string())),
        StableRecordField::ProjectId => Some(RecordValue::Text(output.project_id().to_string())),
        StableRecordField::WorkProductId => match output {
            MissionOutput::WorkProduct(product) => {
                Some(RecordValue::Text(product.work_product_id.to_string()))
            }
            MissionOutput::OutcomeCandidate(_) => None,
        },
        StableRecordField::OutcomeCandidateId => match output {
            MissionOutput::WorkProduct(_) => None,
            MissionOutput::OutcomeCandidate(candidate) => {
                Some(RecordValue::Text(candidate.candidate_id.to_string()))
            }
        },
        StableRecordField::OutputKind => Some(RecordValue::Text(match output.kind() {
            MissionOutputKind::WorkProduct => "work_product".to_owned(),
            MissionOutputKind::OutcomeCandidate => "outcome_candidate".to_owned(),
        })),
        StableRecordField::Revision => i64::try_from(output.revision())
            .ok()
            .map(RecordValue::Integer),
        StableRecordField::Title => Some(RecordValue::Text(output.title().to_owned())),
        StableRecordField::Summary => Some(RecordValue::Text(output.summary().to_owned())),
        StableRecordField::ContentFingerprint => Some(RecordValue::Text(content_digest.to_owned())),
        StableRecordField::IdempotencyKey => Some(RecordValue::Text(idempotency.to_owned())),
    }
}

fn compare(
    field: ReadbackMismatchField,
    expected: &str,
    observed: &str,
) -> Result<(), AirtableError> {
    if expected == observed {
        Ok(())
    } else {
        Err(AirtableError::ReadbackMismatch(ReadbackMismatch::new(
            field, expected, observed,
        )))
    }
}
