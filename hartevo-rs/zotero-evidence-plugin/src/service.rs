use crate::error::ZoteroEvidenceError;
use crate::model::{
    Digest, MissionResearchEvidenceRequest, ZoteroCapabilityProbeRequest,
    ZoteroCapabilityProbeResponse, ZoteroCitationRequest, ZoteroCitationResponse,
    ZoteroEvidenceProposal, ZoteroEvidenceScope, ZoteroProviderManifest, ZoteroReadRequest,
    ZoteroReadResponse,
};
use crate::provider::ZoteroEvidenceProvider;

/// Typed Layer 1 service over a replaceable provider. Provider registration,
/// version, digest, scope, provenance, and native status are revalidated for
/// every call.
#[derive(Debug)]
pub struct ZoteroEvidenceService<P> {
    provider: P,
    bound_manifest_digest: Digest,
}

impl<P> ZoteroEvidenceService<P>
where
    P: ZoteroEvidenceProvider,
{
    pub fn new(provider: P) -> Result<Self, ZoteroEvidenceError> {
        let manifest = provider.manifest();
        manifest.validate()?;
        if provider.external_write_available() {
            return Err(ZoteroEvidenceError::ExternalWriteAuthority);
        }
        Ok(Self {
            provider,
            bound_manifest_digest: manifest.manifest_digest,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_manifest(&self) -> Result<ZoteroProviderManifest, ZoteroEvidenceError> {
        self.ensure_provider()
    }

    pub fn probe(
        &self,
        request: &ZoteroCapabilityProbeRequest,
    ) -> Result<ZoteroCapabilityProbeResponse, ZoteroEvidenceError> {
        let manifest = self.ensure_provider()?;
        ensure_scope(&request.scope, &manifest.scope)?;
        let response = self.provider.probe(request)?;
        response.validate()?;
        ensure_response_binding(
            &response.scope,
            response.provenance,
            response.native_status,
            &response.provider_manifest_digest,
            &manifest,
        )?;
        Ok(response)
    }

    pub fn read(
        &self,
        request: &ZoteroReadRequest,
    ) -> Result<ZoteroReadResponse, ZoteroEvidenceError> {
        let manifest = self.ensure_provider()?;
        request.scope.validate()?;
        if request.scope != manifest.scope {
            return Err(ZoteroEvidenceError::ScopeMismatch);
        }
        if let Some(cursor) = &request.since {
            cursor.validate_for(&request.scope, manifest.provenance)?;
        }
        if let Some(conditional) = &request.conditional {
            conditional.validate_for(&request.scope)?;
        }
        let response = self.provider.read(request)?;
        response.validate()?;
        ensure_response_binding(
            &response.scope,
            response.provenance,
            response.native_status,
            &response.provider_manifest_digest,
            &manifest,
        )?;
        if let (Some(requested), Some(returned)) =
            (request.since.as_ref(), response.since_cursor.as_ref())
            && returned.version < requested.version
        {
            return Err(ZoteroEvidenceError::CursorRegressed {
                requested: requested.version,
                returned: returned.version,
            });
        }
        Ok(response)
    }

    /// Named alias for callers that make the incremental nature explicit.
    pub fn read_since(
        &self,
        request: &ZoteroReadRequest,
    ) -> Result<ZoteroReadResponse, ZoteroEvidenceError> {
        self.read(request)
    }

    pub fn citation(
        &self,
        request: &ZoteroCitationRequest,
    ) -> Result<ZoteroCitationResponse, ZoteroEvidenceError> {
        let manifest = self.ensure_provider()?;
        if request.scope != manifest.scope {
            return Err(ZoteroEvidenceError::ScopeMismatch);
        }
        let response = self.provider.citation(request)?;
        response.validate()?;
        ensure_response_binding(
            &response.scope,
            response.provenance,
            response.native_status,
            &response.provider_manifest_digest,
            &manifest,
        )?;
        Ok(response)
    }

    /// Named alias for citation/export metadata reads.
    pub fn citation_metadata(
        &self,
        request: &ZoteroCitationRequest,
    ) -> Result<ZoteroCitationResponse, ZoteroEvidenceError> {
        self.citation(request)
    }

    /// Compile an exact, idempotent Mission research-evidence proposal. This
    /// method never adopts evidence durably or claims source verification.
    pub fn propose_research_evidence(
        &self,
        request: &MissionResearchEvidenceRequest,
        read: &ZoteroReadResponse,
        citation: &ZoteroCitationResponse,
    ) -> Result<ZoteroEvidenceProposal, ZoteroEvidenceError> {
        let manifest = self.ensure_provider()?;
        if request.scope != manifest.scope {
            return Err(ZoteroEvidenceError::ScopeMismatch);
        }
        ZoteroEvidenceProposal::from_observations(request, read, citation, &manifest)
    }

    fn ensure_provider(&self) -> Result<ZoteroProviderManifest, ZoteroEvidenceError> {
        let manifest = self.provider.manifest();
        manifest.validate()?;
        if self.provider.external_write_available() {
            return Err(ZoteroEvidenceError::ExternalWriteAuthority);
        }
        if manifest.manifest_digest != self.bound_manifest_digest {
            return Err(ZoteroEvidenceError::ProviderManifestDrift {
                expected: self.bound_manifest_digest.clone(),
                actual: manifest.manifest_digest,
            });
        }
        Ok(manifest)
    }
}

fn ensure_scope(
    actual: &ZoteroEvidenceScope,
    expected: &ZoteroEvidenceScope,
) -> Result<(), ZoteroEvidenceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ZoteroEvidenceError::ScopeMismatch)
    }
}

fn ensure_response_binding(
    scope: &ZoteroEvidenceScope,
    provenance: crate::model::ZoteroProvenance,
    native_status: crate::model::NativeStatus,
    provider_manifest_digest: &str,
    manifest: &ZoteroProviderManifest,
) -> Result<(), ZoteroEvidenceError> {
    ensure_scope(scope, &manifest.scope)?;
    if provenance != manifest.provenance {
        return Err(ZoteroEvidenceError::ProvenanceMismatch);
    }
    if native_status != crate::model::NativeStatus::BlockedEnv {
        return Err(ZoteroEvidenceError::ExternalWriteAuthority);
    }
    if provider_manifest_digest != manifest.manifest_digest {
        return Err(ZoteroEvidenceError::ProviderManifestDrift {
            expected: manifest.manifest_digest.clone(),
            actual: provider_manifest_digest.to_owned(),
        });
    }
    Ok(())
}
