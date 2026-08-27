use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

use crate::{
    model::{
        DynatraceProblemEvidence, DynatraceProblemScope, DynatraceProblemStatus,
        DynatraceRegistration, EvidenceState, MAX_PAGE_SIZE, MAX_PAGES, ModelError,
        ProblemObservationState, ProviderRevision, SecretReference,
    },
    provider::{
        DynatraceDetailRequest, DynatraceListRequest, DynatraceProblemTransport, DynatraceProvider,
        TransportError, project_problem_payload, status_of_payload,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DynatraceProblemResultServiceError {
    #[error("registration is revoked")]
    Revoked,
    #[error("registration is invalid or scope-bound metadata drifted")]
    InvalidRegistration,
    #[error("scope or revision does not match the registration")]
    ScopeMismatch,
    #[error("read request is invalid")]
    InvalidRequest,
    #[error("system clock is unavailable")]
    ClockUnavailable,
}

impl From<ModelError> for DynatraceProblemResultServiceError {
    fn from(error: ModelError) -> Self {
        match error {
            ModelError::Revoked => Self::Revoked,
            ModelError::ScopeMismatch | ModelError::SecretReferenceMismatch => Self::ScopeMismatch,
            ModelError::InvalidRegistration => Self::InvalidRegistration,
            _ => Self::InvalidRequest,
        }
    }
}

pub struct DynatraceProblemResultService<T: DynatraceProblemTransport> {
    provider: DynatraceProvider<T>,
    scope: DynatraceProblemScope,
    secret: SecretReference,
    registration: DynatraceRegistration,
    previous_statuses: BTreeMap<crate::Digest, DynatraceProblemStatus>,
}

impl<T: DynatraceProblemTransport> std::fmt::Debug for DynatraceProblemResultService<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynatraceProblemResultService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider.definition())
            .field("secret", &self.secret)
            .field("previous_status_count", &self.previous_statuses.len())
            .finish()
    }
}

impl<T: DynatraceProblemTransport> DynatraceProblemResultService<T> {
    pub fn new(
        provider: DynatraceProvider<T>,
        scope: DynatraceProblemScope,
        secret: SecretReference,
    ) -> Result<Self, DynatraceProblemResultServiceError> {
        if secret.scope_digest() != &scope.digest() {
            return Err(DynatraceProblemResultServiceError::ScopeMismatch);
        }
        let registration = DynatraceRegistration::new(
            provider.definition().provider_digest.clone(),
            &scope,
            &secret,
        )?;
        Ok(Self {
            provider,
            scope,
            secret,
            registration,
            previous_statuses: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &DynatraceProblemScope {
        &self.scope
    }

    pub fn provider(&self) -> &DynatraceProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut DynatraceProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &DynatraceRegistration {
        &self.registration
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn revoke(&mut self) -> Result<(), DynatraceProblemResultServiceError> {
        self.registration.revoke().map_err(Into::into)
    }

    pub fn restore(&mut self) -> Result<(), DynatraceProblemResultServiceError> {
        self.registration.restore().map_err(Into::into)
    }

    pub fn read(&mut self) -> Result<DynatraceProblemEvidence, DynatraceProblemResultServiceError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DynatraceProblemResultServiceError::ClockUnavailable)?
            .as_millis();
        let now_ms = u64::try_from(now_ms)
            .map_err(|_| DynatraceProblemResultServiceError::ClockUnavailable)?;
        self.read_at(now_ms)
    }

    pub fn read_at(
        &mut self,
        at_ms: u64,
    ) -> Result<DynatraceProblemEvidence, DynatraceProblemResultServiceError> {
        if !self.registration.active {
            return Err(DynatraceProblemResultServiceError::Revoked);
        }
        if self.scope.time_window().is_expired(at_ms) {
            return self.empty_evidence(EvidenceState::Expired, false, Vec::new(), Vec::new());
        }
        if self.scope.problem_id().is_some() {
            self.read_detail()
        } else {
            self.read_list()
        }
    }

    fn read_detail(
        &mut self,
    ) -> Result<DynatraceProblemEvidence, DynatraceProblemResultServiceError> {
        let problem_id = self
            .scope
            .problem_id()
            .expect("detail reads have a scoped problem id")
            .clone();
        let request = DynatraceDetailRequest::new(&self.scope, &problem_id);
        let detail = match self.provider.detail(&request, &self.secret) {
            Ok(detail) => detail,
            Err(error) => return self.evidence_for_transport_error(error, Vec::new(), Vec::new()),
        };
        if detail.validate().is_err() {
            return self.empty_evidence(EvidenceState::Tampered, false, Vec::new(), Vec::new());
        }
        if detail.problem().problem_id != problem_id.as_str() {
            return self.empty_evidence(EvidenceState::Tampered, false, Vec::new(), Vec::new());
        }
        let problem_digest = crate::Digest::from_text(&detail.problem().problem_id);
        let previous_status = self.previous_statuses.get(&problem_digest).copied();
        let Ok(projection) = project_problem_payload(detail.problem(), previous_status) else {
            return self.empty_evidence(
                EvidenceState::ProviderUnknown,
                false,
                vec![detail.declared_digest().clone()],
                Vec::new(),
            );
        };
        if let Ok(status) = status_of_payload(detail.problem()) {
            self.previous_statuses.insert(problem_digest, status);
        }
        let state = evidence_state_for_problems(std::slice::from_ref(&projection), false);
        self.empty_evidence(
            state,
            false,
            vec![detail.declared_digest().clone()],
            vec![projection],
        )
    }

    fn read_list(
        &mut self,
    ) -> Result<DynatraceProblemEvidence, DynatraceProblemResultServiceError> {
        let mut next_page_key = None;
        let mut pages = Vec::new();
        let mut projections = Vec::new();
        let mut partial = false;
        let mut terminal_state = None;

        for page_index in 0..MAX_PAGES {
            let request = DynatraceListRequest::new(
                &self.scope,
                page_index,
                MAX_PAGE_SIZE,
                next_page_key.clone(),
            )
            .map_err(|_| DynatraceProblemResultServiceError::InvalidRequest)?;
            let page = match self.provider.list(&request, &self.secret) {
                Ok(page) => page,
                Err(error) => {
                    if pages.is_empty() {
                        terminal_state = Some(state_for_transport_error(error));
                    } else {
                        partial = true;
                        terminal_state = Some(match error {
                            TransportError::AccessDenied => EvidenceState::AccessLost,
                            _ => EvidenceState::Partial,
                        });
                    }
                    break;
                }
            };
            if page.page_index() != request.page_index || page.page_size() != request.page_size {
                terminal_state = Some(EvidenceState::Tampered);
                break;
            }
            if page.validate().is_err() {
                terminal_state = Some(EvidenceState::Tampered);
                break;
            }
            pages.push(page.declared_digest().clone());
            for problem in page.problems() {
                let problem_digest = crate::Digest::from_text(&problem.problem_id);
                let previous_status = self.previous_statuses.get(&problem_digest).copied();
                if let Ok(projection) = project_problem_payload(problem, previous_status) {
                    if let Ok(status) = status_of_payload(problem) {
                        self.previous_statuses.insert(problem_digest, status);
                    }
                    projections.push(projection);
                } else {
                    terminal_state = Some(EvidenceState::ProviderUnknown);
                    break;
                }
            }
            if terminal_state.is_some() {
                break;
            }
            match page.next_page_key() {
                Some(next) if page_index + 1 < MAX_PAGES => {
                    next_page_key = Some(next.to_owned());
                }
                Some(_) => {
                    partial = true;
                    terminal_state = Some(EvidenceState::Partial);
                    break;
                }
                None => break,
            }
        }

        let state =
            terminal_state.unwrap_or_else(|| evidence_state_for_problems(&projections, partial));
        self.empty_evidence(state, partial, pages, projections)
    }

    fn evidence_for_transport_error(
        &self,
        error: TransportError,
        pages: Vec<crate::Digest>,
        problems: Vec<crate::model::ProblemProjection>,
    ) -> Result<DynatraceProblemEvidence, DynatraceProblemResultServiceError> {
        let partial = !problems.is_empty();
        self.empty_evidence(
            if partial {
                match error {
                    TransportError::AccessDenied => EvidenceState::AccessLost,
                    _ => EvidenceState::Partial,
                }
            } else {
                state_for_transport_error(error)
            },
            partial,
            pages,
            problems,
        )
    }

    fn empty_evidence(
        &self,
        state: EvidenceState,
        partial: bool,
        pages: Vec<crate::Digest>,
        problems: Vec<crate::model::ProblemProjection>,
    ) -> Result<DynatraceProblemEvidence, DynatraceProblemResultServiceError> {
        let provider_revision =
            ProviderRevision::new(self.provider.definition().version.clone())
                .map_err(|_| DynatraceProblemResultServiceError::InvalidRegistration)?;
        DynatraceProblemEvidence::new(
            self.scope.digest(),
            self.registration.registration_digest.clone(),
            self.provider.definition().provider_digest.clone(),
            provider_revision,
            self.provider.definition().provenance,
            state,
            partial,
            pages,
            problems,
        )
        .map_err(|_| DynatraceProblemResultServiceError::InvalidRequest)
    }
}

fn state_for_transport_error(error: TransportError) -> EvidenceState {
    match error {
        TransportError::AccessDenied | TransportError::ScopeMismatch => EvidenceState::AccessLost,
        TransportError::MalformedResponse
        | TransportError::ApiVersionDrift
        | TransportError::ProviderUnknown
        | TransportError::HttpStatus(_)
        | TransportError::Timeout
        | TransportError::InvalidRequest => EvidenceState::ProviderUnknown,
    }
}

fn evidence_state_for_problems(
    problems: &[crate::model::ProblemProjection],
    partial: bool,
) -> EvidenceState {
    if partial {
        return EvidenceState::Partial;
    }
    if problems
        .iter()
        .any(|problem| problem.state == ProblemObservationState::Open)
    {
        EvidenceState::Open
    } else if problems
        .iter()
        .any(|problem| problem.state == ProblemObservationState::Resolved)
    {
        EvidenceState::Resolved
    } else {
        EvidenceState::Closed
    }
}
