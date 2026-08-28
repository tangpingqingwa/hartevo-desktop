use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    QUALTRICS_PROVIDER_ID, QUALTRICS_SURVEY_RESULT_CONTRACT_VERSION,
    QUALTRICS_SURVEY_RESULT_PLUGIN_VERSION, QUALTRICS_SURVEY_RESULT_SERVICE_ID,
    model::{
        AnswerPage, BoundedAnswer, Digest, ModelError, OpaqueExportReference, OpaquePageToken,
        QualtricsResultBounds, QualtricsScope, QuestionKind, QuestionMetadata, RegistrationState,
        ResponseExportProgress, ResponseMetadata, ResponseStatus, ResponseStatusEvidence, Revision,
        SecretReference, SurveyAnswer, SurveyMetadata,
    },
    provider::{
        ProviderObservation, QualtricsProvider, QualtricsProviderError, QualtricsReadReceipt,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QualtricsRegistrationError {
    #[error("SecretReference is not bound to the exact Qualtrics scope")]
    SecretScopeMismatch,
    #[error("provider definition is not bound to the Qualtrics service")]
    ProviderMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: String,
    provider_digest: Digest,
    datacenter: String,
    survey: String,
    scope_digest: Digest,
    mission_revision: u64,
    project_revision: u64,
    consent_revision: u64,
    secret_reference_digest: Digest,
    credential_revision: u64,
    registration_digest: Digest,
    state: RegistrationState,
}

impl QualtricsRegistration {
    pub(crate) fn new(
        scope: &QualtricsScope,
        secret: &SecretReference,
        provider: &QualtricsProvider,
    ) -> Result<Self, QualtricsRegistrationError> {
        if secret.scope_digest() != scope.scope_digest() {
            return Err(QualtricsRegistrationError::SecretScopeMismatch);
        }
        if provider.definition().service_id() != QUALTRICS_SURVEY_RESULT_SERVICE_ID
            || provider.definition().id() != QUALTRICS_PROVIDER_ID
        {
            return Err(QualtricsRegistrationError::ProviderMismatch);
        }
        let contract_digest = crate::contract_digest();
        let registration_digest = Digest::from_fields(
            "qualtrics-registration/v1",
            &[
                QUALTRICS_SURVEY_RESULT_PLUGIN_VERSION.to_owned(),
                QUALTRICS_SURVEY_RESULT_CONTRACT_VERSION.to_owned(),
                contract_digest.as_str().to_owned(),
                provider.definition().id().to_owned(),
                provider.definition().version().to_owned(),
                provider.provider_digest().as_str().to_owned(),
                scope.datacenter().as_str().to_owned(),
                scope.survey().as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                scope.mission_revision().get().to_string(),
                scope.project_revision().get().to_string(),
                scope.consent().revision().get().to_string(),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            plugin_version: QUALTRICS_SURVEY_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: QUALTRICS_SURVEY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: provider.definition().id().to_owned(),
            provider_version: provider.definition().version().to_owned(),
            provider_digest: provider.provider_digest().clone(),
            datacenter: scope.datacenter().as_str().to_owned(),
            survey: scope.survey().as_str().to_owned(),
            scope_digest: scope.scope_digest().clone(),
            mission_revision: scope.mission_revision().get(),
            project_revision: scope.project_revision().get(),
            consent_revision: scope.consent().revision().get(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision().get(),
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn datacenter(&self) -> &str {
        &self.datacenter
    }

    pub fn survey(&self) -> &str {
        &self.survey
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub const fn consent_revision(&self) -> u64 {
        self.consent_revision
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) {
        self.state = RegistrationState::Revoked;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualtricsSurveyResultRequest {
    bounds: QualtricsResultBounds,
    expected_survey_revision: Option<u64>,
    expected_question_revision: Option<u64>,
    expected_response_revision: Option<u64>,
    export_reference: Option<OpaqueExportReference>,
}

impl QualtricsSurveyResultRequest {
    pub fn new(bounds: QualtricsResultBounds) -> Self {
        Self {
            bounds,
            expected_survey_revision: None,
            expected_question_revision: None,
            expected_response_revision: None,
            export_reference: None,
        }
    }

    pub fn for_scope(scope: &QualtricsScope, bounds: QualtricsResultBounds) -> Self {
        let mut request =
            Self::new(bounds).with_expected_survey_revision(scope.survey_revision().get());
        if let Some(revision) = scope.question_revision() {
            request = request.with_expected_question_revision(revision.get());
        }
        if let Some(revision) = scope.response_revision() {
            request = request.with_expected_response_revision(revision.get());
        }
        request
    }

    pub fn with_expected_survey_revision(mut self, revision: u64) -> Self {
        self.expected_survey_revision = Some(revision);
        self
    }

    pub fn with_expected_question_revision(mut self, revision: u64) -> Self {
        self.expected_question_revision = Some(revision);
        self
    }

    pub fn with_expected_response_revision(mut self, revision: u64) -> Self {
        self.expected_response_revision = Some(revision);
        self
    }

    pub fn with_export_progress(mut self, export_reference: OpaqueExportReference) -> Self {
        self.export_reference = Some(export_reference);
        self
    }

    pub fn bounds(&self) -> &QualtricsResultBounds {
        &self.bounds
    }

    pub fn export_reference(&self) -> Option<&OpaqueExportReference> {
        self.export_reference.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualtricsResultState {
    Completed,
    InProgress,
    Partial,
    Expired,
    ConsentBlocked,
    AccessLost,
    ProviderUnknown,
}

pub type ResultProjection = QualtricsResultState;
pub type MissionResultState = QualtricsResultState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    ResponseReportedPartial,
    AnswerPageLimit,
    AnswerLimit,
    MissingAnswerPage,
    ExportProgressUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsAuthority;

impl QualtricsAuthority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn external_writes(self) -> bool {
        false
    }

    pub const fn durable_receipt(self) -> bool {
        false
    }

    pub const fn truth(self) -> bool {
        false
    }

    pub const fn adopted_outcome(self) -> bool {
        false
    }

    pub const fn causal_inference(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsSurveyResultEvidence {
    survey: Option<SurveyMetadata>,
    question: Option<QuestionMetadata>,
    response: Option<ResponseMetadata>,
    status: Option<ResponseStatusEvidence>,
    answers: Vec<SurveyAnswer>,
    export_progress: Option<ResponseExportProgress>,
    receipts: Vec<QualtricsReadReceipt>,
    partial_reason: Option<PartialReason>,
    result_digest: Digest,
}

impl QualtricsSurveyResultEvidence {
    fn new(
        survey: Option<SurveyMetadata>,
        question: Option<QuestionMetadata>,
        response: Option<ResponseMetadata>,
        status: Option<ResponseStatusEvidence>,
        answers: Vec<SurveyAnswer>,
        export_progress: Option<ResponseExportProgress>,
        receipts: Vec<QualtricsReadReceipt>,
        partial_reason: Option<PartialReason>,
        scope_digest: &Digest,
    ) -> Self {
        let mut fields = vec![scope_digest.as_str().to_owned()];
        fields.push(survey.as_ref().map_or_else(String::new, |value| {
            value.payload_digest().as_str().to_owned()
        }));
        fields.push(question.as_ref().map_or_else(String::new, |value| {
            value.payload_digest().as_str().to_owned()
        }));
        fields.push(response.as_ref().map_or_else(String::new, |value| {
            value.payload_digest().as_str().to_owned()
        }));
        fields.push(status.as_ref().map_or_else(String::new, |value| {
            value.payload_digest().as_str().to_owned()
        }));
        fields.extend(
            answers
                .iter()
                .map(|answer| answer.answer_digest().as_str().to_owned()),
        );
        fields.push(export_progress.as_ref().map_or_else(String::new, |value| {
            value.payload_digest().as_str().to_owned()
        }));
        fields.push(partial_reason.map_or_else(String::new, |value| format!("{value:?}")));
        fields.extend(
            receipts
                .iter()
                .map(|receipt| receipt.response().response_digest().as_str().to_owned()),
        );
        let result_digest = Digest::from_fields("qualtrics-survey-result/v1", &fields);
        Self {
            survey,
            question,
            response,
            status,
            answers,
            export_progress,
            receipts,
            partial_reason,
            result_digest,
        }
    }

    pub fn survey(&self) -> Option<&SurveyMetadata> {
        self.survey.as_ref()
    }

    pub fn question(&self) -> Option<&QuestionMetadata> {
        self.question.as_ref()
    }

    pub fn response(&self) -> Option<&ResponseMetadata> {
        self.response.as_ref()
    }

    pub fn status(&self) -> Option<&ResponseStatusEvidence> {
        self.status.as_ref()
    }

    pub fn answers(&self) -> &[SurveyAnswer] {
        &self.answers
    }

    pub fn export_progress(&self) -> Option<&ResponseExportProgress> {
        self.export_progress.as_ref()
    }

    pub fn receipts(&self) -> &[QualtricsReadReceipt] {
        &self.receipts
    }

    pub const fn partial_reason(&self) -> Option<PartialReason> {
        self.partial_reason
    }

    pub fn result_digest(&self) -> &Digest {
        &self.result_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsSurveyResultProposal {
    state: QualtricsResultState,
    scope_digest: Digest,
    registration_digest: Digest,
    provider_digest: Digest,
    evidence: QualtricsSurveyResultEvidence,
    authority: QualtricsAuthority,
    proposal_only: bool,
    adopted: bool,
}

impl QualtricsSurveyResultProposal {
    fn new(
        state: QualtricsResultState,
        scope: &QualtricsScope,
        registration: &QualtricsRegistration,
        provider: &QualtricsProvider,
        evidence: QualtricsSurveyResultEvidence,
    ) -> Self {
        Self {
            state,
            scope_digest: scope.scope_digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            provider_digest: provider.provider_digest().clone(),
            evidence,
            authority: QualtricsAuthority,
            proposal_only: true,
            adopted: false,
        }
    }

    pub const fn state(&self) -> QualtricsResultState {
        self.state
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn evidence(&self) -> &QualtricsSurveyResultEvidence {
        &self.evidence
    }

    pub const fn authority(&self) -> QualtricsAuthority {
        self.authority
    }

    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
    }

    pub const fn is_adopted(&self) -> bool {
        self.adopted
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QualtricsServiceError {
    #[error("Qualtrics registration is revoked")]
    RegistrationRevoked,
    #[error("Qualtrics SecretReference is revoked")]
    SecretRevoked,
    #[error("provider, service, or registration digest does not match the scope")]
    RegistrationDrift,
    #[error("provider evidence is tampered with or stale")]
    TamperedEvidence,
    #[error("provider or payload scope drifted")]
    ScopeMismatch,
    #[error("survey, question, response, or distribution revision drifted")]
    RevisionDrift,
    #[error("response status and response metadata disagree")]
    StatusDrift,
    #[error("answer page loop or duplicate answer was observed")]
    PageLoop,
    #[error("provider response exceeded the request bounds")]
    ResponseTooLarge,
    #[error("provider access was lost while reading bounded answers")]
    AccessLost,
    #[error("provider became unknown while reading bounded answers")]
    ProviderUnknown,
    #[error("provider returned an invalid typed payload")]
    InvalidPayload,
    #[error("provider returned an access or environment failure")]
    ProviderUnavailable,
    #[error(transparent)]
    Registration(#[from] QualtricsRegistrationError),
    #[error(transparent)]
    Provider(#[from] QualtricsProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

pub struct QualtricsSurveyResultService {
    scope: QualtricsScope,
    secret: SecretReference,
    provider: QualtricsProvider,
    registration: QualtricsRegistration,
}

impl fmt::Debug for QualtricsSurveyResultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualtricsSurveyResultService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl QualtricsSurveyResultService {
    pub fn new(
        scope: QualtricsScope,
        secret: SecretReference,
        provider: QualtricsProvider,
    ) -> Result<Self, QualtricsServiceError> {
        if secret.scope_digest() != scope.scope_digest() {
            return Err(QualtricsServiceError::RegistrationDrift);
        }
        let registration = QualtricsRegistration::new(&scope, &secret, &provider)?;
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
        })
    }

    pub fn scope(&self) -> &QualtricsScope {
        &self.scope
    }

    pub fn registration(&self) -> &QualtricsRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &QualtricsProvider {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut QualtricsProvider {
        &mut self.provider
    }

    pub fn revoke_registration(&mut self) {
        self.registration.revoke();
    }

    pub fn propose(
        &mut self,
        request: QualtricsSurveyResultRequest,
    ) -> Result<QualtricsSurveyResultProposal, QualtricsServiceError> {
        request.bounds().validate()?;
        self.validate_registration()?;
        if !self.scope.consent().status().is_granted() {
            return Ok(self.proposal_for_state(QualtricsResultState::ConsentBlocked, None));
        }
        self.scope.require_question()?;
        self.scope.require_response()?;
        self.validate_requested_revisions(&request)?;
        self.provider.set_bounds(request.bounds())?;

        let survey_observation = match self.provider.get_survey_metadata(&self.scope) {
            Ok(observation) => observation,
            Err(error) => return self.handle_provider_failure(error),
        };
        validate_survey(&self.scope, survey_observation.value())?;
        Self::ensure_response_size(&survey_observation, request.bounds())?;

        let question_observation = match self.provider.get_question_metadata(&self.scope) {
            Ok(observation) => observation,
            Err(error) => return self.handle_provider_failure(error),
        };
        validate_question(&self.scope, question_observation.value())?;
        Self::ensure_response_size(&question_observation, request.bounds())?;

        let response_observation = match self.provider.get_response_metadata(&self.scope) {
            Ok(observation) => observation,
            Err(error) => return self.handle_provider_failure(error),
        };
        validate_response(&self.scope, response_observation.value())?;
        Self::ensure_response_size(&response_observation, request.bounds())?;

        let status_observation = match self.provider.get_response_status(&self.scope) {
            Ok(observation) => observation,
            Err(error) => return self.handle_provider_failure(error),
        };
        validate_status(&self.scope, status_observation.value())?;
        Self::ensure_response_size(&status_observation, request.bounds())?;
        if response_observation.value().status() != status_observation.value().status() {
            return Err(QualtricsServiceError::StatusDrift);
        }

        let (answers, answer_complete, answer_reason) =
            match self.read_answers(&request, question_observation.value().kind()) {
                Ok(value) => value,
                Err(QualtricsServiceError::AccessLost) => {
                    return Ok(self.proposal_for_state(QualtricsResultState::AccessLost, None));
                }
                Err(QualtricsServiceError::ProviderUnknown) => {
                    return Ok(self.proposal_for_state(QualtricsResultState::ProviderUnknown, None));
                }
                Err(error) => return Err(error),
            };
        let mut export_progress = None;
        let mut optional_reason = answer_reason;
        if let Some(export_reference) = request.export_reference() {
            match self
                .provider
                .get_response_export_progress(&self.scope, export_reference)
            {
                Ok(observation) => {
                    validate_export_progress(&self.scope, export_reference, observation.value())?;
                    Self::ensure_response_size(&observation, request.bounds())?;
                    export_progress = Some(observation.into_value());
                }
                Err(error) if provider_failure_state(&error).is_some() => {
                    optional_reason.get_or_insert(PartialReason::ExportProgressUnavailable);
                }
                Err(error) => return Err(error.into()),
            }
        }

        let state = project_state(
            response_observation.value().status(),
            answer_complete,
            optional_reason,
        );
        let receipts = self.provider.take_receipts();
        let evidence = QualtricsSurveyResultEvidence::new(
            Some(survey_observation.into_value()),
            Some(question_observation.into_value()),
            Some(response_observation.into_value()),
            Some(status_observation.into_value()),
            answers,
            export_progress,
            receipts,
            optional_reason,
            self.scope.scope_digest(),
        );
        Ok(QualtricsSurveyResultProposal::new(
            state,
            &self.scope,
            &self.registration,
            &self.provider,
            evidence,
        ))
    }

    pub fn propose_result(
        &mut self,
        request: QualtricsSurveyResultRequest,
    ) -> Result<QualtricsSurveyResultProposal, QualtricsServiceError> {
        self.propose(request)
    }

    fn validate_registration(&self) -> Result<(), QualtricsServiceError> {
        if !self.registration.is_active() {
            return Err(QualtricsServiceError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(QualtricsServiceError::SecretRevoked);
        }
        if self.secret.scope_digest() != self.scope.scope_digest()
            || self.registration.scope_digest() != self.scope.scope_digest()
            || self.registration.provider_digest() != self.provider.provider_digest()
            || self.registration.datacenter() != self.scope.datacenter().as_str()
            || self.registration.survey() != self.scope.survey().as_str()
        {
            return Err(QualtricsServiceError::RegistrationDrift);
        }
        Ok(())
    }

    fn validate_requested_revisions(
        &self,
        request: &QualtricsSurveyResultRequest,
    ) -> Result<(), QualtricsServiceError> {
        if request
            .expected_survey_revision
            .is_some_and(|revision| revision != self.scope.survey_revision().get())
            || request.expected_question_revision.is_some_and(|revision| {
                Some(revision) != self.scope.question_revision().map(Revision::get)
            })
            || request.expected_response_revision.is_some_and(|revision| {
                Some(revision) != self.scope.response_revision().map(Revision::get)
            })
        {
            return Err(QualtricsServiceError::RevisionDrift);
        }
        Ok(())
    }

    fn ensure_response_size<T>(
        observation: &ProviderObservation<T>,
        bounds: &QualtricsResultBounds,
    ) -> Result<(), QualtricsServiceError> {
        if observation.receipt().response().response_size_bytes() > bounds.max_response_bytes() {
            Err(QualtricsServiceError::ResponseTooLarge)
        } else {
            Ok(())
        }
    }

    fn read_answers(
        &mut self,
        request: &QualtricsSurveyResultRequest,
        question_kind: QuestionKind,
    ) -> Result<(Vec<SurveyAnswer>, bool, Option<PartialReason>), QualtricsServiceError> {
        let mut answers = Vec::new();
        let mut page_token: Option<OpaquePageToken> = None;
        let mut seen_tokens = BTreeSet::new();
        let mut seen_answers = BTreeSet::new();
        let mut complete = false;
        let mut partial_reason = None;
        for expected_page in 0..request.bounds().max_pages() {
            let observation = match self.provider.get_numeric_choice_answers_bounded(
                &self.scope,
                page_token.as_ref(),
                request.bounds().page_size(),
            ) {
                Ok(observation) => observation,
                Err(error) => {
                    if let Some(state) = provider_failure_state(&error) {
                        return Err(state_to_service_error(state));
                    }
                    return Err(error.into());
                }
            };
            Self::ensure_response_size(&observation, request.bounds())?;
            validate_answer_page(
                &self.scope,
                observation.value(),
                expected_page as u16,
                question_kind,
            )?;
            for answer in observation.value().answers() {
                let answer_digest = answer.answer_digest();
                if !seen_answers.insert(answer_digest) {
                    return Err(QualtricsServiceError::PageLoop);
                }
                answers.push(answer.clone());
                if answers.len() == request.bounds().max_answers() {
                    if observation.value().complete() && observation.value().next_page().is_none() {
                        complete = true;
                    } else {
                        partial_reason = Some(PartialReason::AnswerLimit);
                    }
                    break;
                }
            }
            if partial_reason.is_some() || observation.value().complete() {
                complete = observation.value().complete() && partial_reason.is_none();
                break;
            }
            let next_page = observation.value().next_page().cloned();
            match next_page {
                Some(next_page) if seen_tokens.insert(next_page.digest().clone()) => {
                    page_token = Some(next_page);
                }
                Some(_) => return Err(QualtricsServiceError::PageLoop),
                None => {
                    partial_reason = Some(PartialReason::MissingAnswerPage);
                    break;
                }
            }
        }
        if !complete && partial_reason.is_none() {
            partial_reason = Some(PartialReason::AnswerPageLimit);
        }
        Ok((answers, complete, partial_reason))
    }

    fn proposal_for_state(
        &mut self,
        state: QualtricsResultState,
        partial_reason: Option<PartialReason>,
    ) -> QualtricsSurveyResultProposal {
        let receipts = self.provider.take_receipts();
        let evidence = QualtricsSurveyResultEvidence::new(
            None,
            None,
            None,
            None,
            Vec::new(),
            None,
            receipts,
            partial_reason,
            self.scope.scope_digest(),
        );
        QualtricsSurveyResultProposal::new(
            state,
            &self.scope,
            &self.registration,
            &self.provider,
            evidence,
        )
    }

    fn handle_provider_failure(
        &mut self,
        error: QualtricsProviderError,
    ) -> Result<QualtricsSurveyResultProposal, QualtricsServiceError> {
        if let Some(state) = provider_failure_state(&error) {
            let proposal = self.proposal_for_state(state, None);
            return Ok(proposal);
        }
        Err(map_provider_error(error))
    }
}

fn validate_scope_digest(actual: &Digest, expected: &Digest) -> Result<(), QualtricsServiceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(QualtricsServiceError::ScopeMismatch)
    }
}

fn validate_survey(
    scope: &QualtricsScope,
    metadata: &SurveyMetadata,
) -> Result<(), QualtricsServiceError> {
    validate_scope_digest(metadata.scope_digest(), scope.scope_digest())?;
    if metadata.survey() != scope.survey() || metadata.revision() != scope.survey_revision() {
        return Err(QualtricsServiceError::RevisionDrift);
    }
    Ok(())
}

fn validate_question(
    scope: &QualtricsScope,
    metadata: &QuestionMetadata,
) -> Result<(), QualtricsServiceError> {
    validate_scope_digest(metadata.scope_digest(), scope.scope_digest())?;
    if metadata.survey() != scope.survey()
        || Some(metadata.question()) != scope.question()
        || Some(metadata.revision()) != scope.question_revision()
    {
        return Err(QualtricsServiceError::RevisionDrift);
    }
    Ok(())
}

fn validate_response(
    scope: &QualtricsScope,
    metadata: &ResponseMetadata,
) -> Result<(), QualtricsServiceError> {
    validate_scope_digest(metadata.scope_digest(), scope.scope_digest())?;
    if metadata.survey() != scope.survey()
        || Some(metadata.response()) != scope.response()
        || Some(metadata.revision()) != scope.response_revision()
        || metadata.distribution() != scope.distribution()
    {
        return Err(QualtricsServiceError::RevisionDrift);
    }
    Ok(())
}

fn validate_status(
    scope: &QualtricsScope,
    status: &ResponseStatusEvidence,
) -> Result<(), QualtricsServiceError> {
    validate_scope_digest(status.scope_digest(), scope.scope_digest())?;
    if status.survey() != scope.survey()
        || Some(status.response()) != scope.response()
        || Some(status.revision()) != scope.response_revision()
    {
        return Err(QualtricsServiceError::RevisionDrift);
    }
    Ok(())
}

fn validate_answer_page(
    scope: &QualtricsScope,
    page: &AnswerPage,
    expected_page: u16,
    question_kind: QuestionKind,
) -> Result<(), QualtricsServiceError> {
    validate_scope_digest(page.scope_digest(), scope.scope_digest())?;
    if page.survey() != scope.survey()
        || Some(page.question()) != scope.question()
        || Some(page.response()) != scope.response()
        || Some(page.question_revision()) != scope.question_revision()
        || Some(page.response_revision()) != scope.response_revision()
        || page.page_index() != expected_page
    {
        return Err(QualtricsServiceError::RevisionDrift);
    }
    for answer in page.answers() {
        if answer.survey() != scope.survey()
            || Some(answer.question()) != scope.question()
            || Some(answer.response()) != scope.response()
            || Some(answer.question_revision()) != scope.question_revision()
            || Some(answer.response_revision()) != scope.response_revision()
        {
            return Err(QualtricsServiceError::ScopeMismatch);
        }
        let answer_is_allowed = matches!(
            (question_kind, answer.answer()),
            (QuestionKind::Numeric, BoundedAnswer::Numeric(_))
                | (QuestionKind::Choice, BoundedAnswer::Choice(_))
        );
        if !answer_is_allowed {
            return Err(QualtricsServiceError::InvalidPayload);
        }
    }
    Ok(())
}

fn validate_export_progress(
    scope: &QualtricsScope,
    export_reference: &OpaqueExportReference,
    progress: &ResponseExportProgress,
) -> Result<(), QualtricsServiceError> {
    validate_scope_digest(progress.scope_digest(), scope.scope_digest())?;
    if progress.export_reference() != export_reference.digest() || progress.file_available() {
        return Err(QualtricsServiceError::InvalidPayload);
    }
    Ok(())
}

fn project_state(
    response_status: ResponseStatus,
    answer_complete: bool,
    partial_reason: Option<PartialReason>,
) -> QualtricsResultState {
    match response_status {
        ResponseStatus::Completed if answer_complete && partial_reason.is_none() => {
            QualtricsResultState::Completed
        }
        ResponseStatus::Completed => QualtricsResultState::Partial,
        ResponseStatus::InProgress => QualtricsResultState::InProgress,
        ResponseStatus::Partial => QualtricsResultState::Partial,
        ResponseStatus::Expired => QualtricsResultState::Expired,
        ResponseStatus::Unknown => QualtricsResultState::ProviderUnknown,
    }
}

fn provider_failure_state(error: &QualtricsProviderError) -> Option<QualtricsResultState> {
    match error {
        QualtricsProviderError::AccessLost => Some(QualtricsResultState::AccessLost),
        QualtricsProviderError::ProviderUnknown
        | QualtricsProviderError::RateLimited
        | QualtricsProviderError::BlockedEnvironment
        | QualtricsProviderError::Transport(_) => Some(QualtricsResultState::ProviderUnknown),
        _ => None,
    }
}

fn state_to_service_error(state: QualtricsResultState) -> QualtricsServiceError {
    match state {
        QualtricsResultState::AccessLost => QualtricsServiceError::AccessLost,
        _ => QualtricsServiceError::ProviderUnknown,
    }
}

fn map_provider_error(error: QualtricsProviderError) -> QualtricsServiceError {
    match error {
        QualtricsProviderError::TamperedEvidence => QualtricsServiceError::TamperedEvidence,
        QualtricsProviderError::ResponseTooLarge => QualtricsServiceError::ResponseTooLarge,
        QualtricsProviderError::ProviderRevisionDrift => QualtricsServiceError::RevisionDrift,
        QualtricsProviderError::UnexpectedPayload => QualtricsServiceError::InvalidPayload,
        QualtricsProviderError::InvalidRequest => QualtricsServiceError::ScopeMismatch,
        other => QualtricsServiceError::Provider(other),
    }
}
