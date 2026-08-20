use crate::error::GoogleWorkspaceError;
use crate::model::{
    DocumentAdoptionDestination, DocumentAdoptionProposal, MissionWorkProductSelection, PluginScope,
};
use crate::provider::ResultWorkspaceService;
use crate::registration::GoogleWorkspacePluginRegistration;

/// The typed Mission-facing input to result adoption.  It carries the exact
/// scope and Work Product revision/digest that the proposal must preserve.
#[derive(Clone, Debug)]
pub struct MissionAdoptionRequest {
    pub scope: PluginScope,
    pub selection: MissionWorkProductSelection,
    pub destination: DocumentAdoptionDestination,
}

/// Layer 1 Mission consumer.  It can only ask the provider for a canonical
/// proposal; it has no method that executes the proposal.
#[derive(Clone, Debug)]
pub struct MissionResultWorkspaceConsumer {
    registration: GoogleWorkspacePluginRegistration,
}

impl MissionResultWorkspaceConsumer {
    pub fn new(registration: GoogleWorkspacePluginRegistration) -> Self {
        Self { registration }
    }

    pub fn registration(&self) -> &GoogleWorkspacePluginRegistration {
        &self.registration
    }

    pub fn propose_adoption<P: ResultWorkspaceService>(
        &self,
        provider: &P,
        request: MissionAdoptionRequest,
    ) -> Result<DocumentAdoptionProposal, GoogleWorkspaceError> {
        if !self.registration.is_active() {
            return Err(GoogleWorkspaceError::PluginRevoked);
        }
        if request.scope != self.registration.scope {
            return Err(GoogleWorkspaceError::ScopeMismatch);
        }
        provider.propose_document_adoption(request.selection, request.destination)
    }
}
