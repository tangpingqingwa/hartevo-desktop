use std::{borrow::Borrow, collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    API_REVISION, CONTRACT_VERSION, FASTLY_SERVICE_RESULT_PLUGIN_VERSION,
    FASTLY_SERVICE_RESULT_PROVIDER_ID, contract_digest,
    error::{FastlyServiceResultError, Result},
    model::{
        ConsentScope, Digest, FastlyDomainProjection, FastlyEnvironmentProjection, FastlyFailure,
        FastlyRateLimitReceipt, FastlyRequestOutcome, FastlyRequestReceipt,
        FastlyServiceProjection, FastlyServiceResultEvidence, FastlyServiceResultScope,
        FastlyServiceResultState, FastlyValidationProjection, FastlyVersionProjection,
        MAX_BACKOFF_SECONDS, MAX_PAGES, MAX_RETRY_ATTEMPTS, PermissionSnapshot, Revision,
        SecretReference, compute_evidence_digest,
    },
    transport::{
        FastlyEndpoint, FastlyRequest, FastlyResponse, FastlyResponseBody, FastlyTransport,
        FastlyTransportError, TransportProvenance,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationState {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransition {
    pub previous_status: RegistrationState,
    pub new_status: RegistrationState,
    pub previous_digest: Digest,
    pub new_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyServiceResultRegistration {
    registration_id: String,
    state: RegistrationState,
    scope_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_digest: Digest,
    api_revision: String,
    api_revision_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    secret_reference_digest: Digest,
    evidence_digest: Digest,
    registration_revision: Revision,
    registration_digest: Digest,
}

impl FastlyServiceResultRegistration {
    pub(crate) fn new(
        registration_id: impl Into<String>,
        scope: &FastlyServiceResultScope,
        secret_reference: &SecretReference,
        permissions: &PermissionSnapshot,
        consent: &ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration_id = registration_id.into();
        if registration_id.is_empty()
            || registration_id.len() > crate::model::MAX_IDENTIFIER_BYTES
            || registration_id.trim() != registration_id
        {
            return Err(FastlyServiceResultError::InvalidIdentifier {
                field: "registration_id",
                reason: "must be bounded and trimmed",
            });
        }
        if !permissions.is_layer_one_exact() {
            return Err(FastlyServiceResultError::PermissionMismatch);
        }
        if secret_reference.is_revoked() {
            return Err(FastlyServiceResultError::SecretReferenceRevoked);
        }
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(FastlyServiceResultError::ScopeMismatch);
        }
        let registration_revision = Revision::new(registration_revision)?;
        let scope_digest = scope.digest();
        let contract_digest = contract_digest();
        let provider_digest = Digest::from_parts(
            "fastly-provider-registration/v1",
            &[
                ("provider", FASTLY_SERVICE_RESULT_PROVIDER_ID.to_owned()),
                ("apiRevision", API_REVISION.to_owned()),
                ("contract", contract_digest.to_string()),
            ],
        );
        let api_revision_digest = Digest::from_text(API_REVISION);
        let registration_digest = registration_digest(
            &registration_id,
            RegistrationState::Active,
            &scope_digest,
            &contract_digest,
            &provider_digest,
            &api_revision_digest,
            permissions.digest(),
            consent.digest(),
            &secret_reference.reference_digest(),
            registration_revision,
        );
        let evidence_digest = Digest::from_parts(
            "fastly-registration-evidence/v1",
            &[
                ("registration", registration_digest.to_string()),
                ("scope", scope_digest.to_string()),
                ("evidenceContract", CONTRACT_VERSION.to_owned()),
            ],
        );
        Ok(Self {
            registration_id,
            state: RegistrationState::Active,
            scope_digest,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: FASTLY_SERVICE_RESULT_PROVIDER_ID.to_owned(),
            provider_digest,
            api_revision: API_REVISION.to_owned(),
            api_revision_digest,
            permission_digest: permissions.digest().clone(),
            consent_digest: consent.digest().clone(),
            secret_reference_digest: secret_reference.reference_digest(),
            evidence_digest,
            registration_revision,
            registration_digest,
        })
    }

    #[must_use]
    pub fn registration_id(&self) -> &str {
        &self.registration_id
    }

    #[must_use]
    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    #[must_use]
    pub fn api_revision_digest(&self) -> &Digest {
        &self.api_revision_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    #[must_use]
    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransition> {
        if self.state == RegistrationState::Reversed {
            return Err(FastlyServiceResultError::RegistrationNotReversible);
        }
        self.transition(RegistrationState::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        self.transition(RegistrationState::Reversed)
    }

    fn transition(&mut self, new_status: RegistrationState) -> Result<RegistrationTransition> {
        let previous_status = self.state;
        if previous_status == new_status {
            return Err(if new_status == RegistrationState::Active {
                FastlyServiceResultError::RegistrationAlreadyActive
            } else {
                FastlyServiceResultError::RegistrationInactive
            });
        }
        let previous_digest = self.registration_digest.clone();
        self.state = new_status;
        self.registration_revision = self.registration_revision.bump()?;
        self.registration_digest = registration_digest(
            &self.registration_id,
            self.state,
            &self.scope_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_revision_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            self.registration_revision,
        );
        self.evidence_digest = Digest::from_parts(
            "fastly-registration-evidence/v1",
            &[
                ("registration", self.registration_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("evidenceContract", self.contract_version.clone()),
            ],
        );
        Ok(RegistrationTransition {
            previous_status,
            new_status,
            previous_digest,
            new_digest: self.registration_digest.clone(),
        })
    }
}

fn registration_digest(
    registration_id: &str,
    state: RegistrationState,
    scope_digest: &Digest,
    contract_digest: &Digest,
    provider_digest: &Digest,
    api_revision_digest: &Digest,
    permission_digest: &Digest,
    consent_digest: &Digest,
    secret_reference_digest: &Digest,
    registration_revision: Revision,
) -> Digest {
    Digest::from_parts(
        "fastly-service-result-registration/v1",
        &[
            ("id", registration_id.to_owned()),
            ("state", format!("{state:?}")),
            ("scope", scope_digest.to_string()),
            ("contract", contract_digest.to_string()),
            ("provider", provider_digest.to_string()),
            ("apiRevision", api_revision_digest.to_string()),
            ("permission", permission_digest.to_string()),
            ("consent", consent_digest.to_string()),
            ("secretReference", secret_reference_digest.to_string()),
            ("revision", registration_revision.get().to_string()),
        ],
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyReadRequest {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub max_pages: u16,
}

impl FastlyReadRequest {
    #[must_use]
    pub fn new(
        scope: &FastlyServiceResultScope,
        permission_digest: &Digest,
        consent_digest: &Digest,
    ) -> Self {
        Self {
            scope_digest: scope.digest(),
            permission_digest: permission_digest.clone(),
            consent_digest: consent_digest.clone(),
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            max_pages: MAX_PAGES,
        }
    }

    #[must_use]
    pub fn with_max_pages(mut self, max_pages: u16) -> Self {
        self.max_pages = max_pages.clamp(1, MAX_PAGES);
        self
    }
}

#[derive(Clone, Debug)]
pub struct FastlyProvider<T>
where
    T: FastlyTransport,
{
    transport: T,
    scope: FastlyServiceResultScope,
    secret_reference: SecretReference,
    registration: Option<FastlyServiceResultRegistration>,
}

impl<T> FastlyProvider<T>
where
    T: FastlyTransport,
{
    pub fn new(
        transport: T,
        scope: FastlyServiceResultScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        if secret_reference.is_revoked() {
            return Err(FastlyServiceResultError::SecretReferenceRevoked);
        }
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(FastlyServiceResultError::ScopeMismatch);
        }
        Ok(Self {
            transport,
            scope,
            secret_reference,
            registration: None,
        })
    }

    pub fn register<P, C>(
        mut self,
        registration_id: impl Into<String>,
        permissions: P,
        consent: C,
        registration_revision: u64,
    ) -> Result<Self>
    where
        P: Borrow<PermissionSnapshot>,
        C: Borrow<ConsentScope>,
    {
        let registration = FastlyServiceResultRegistration::new(
            registration_id,
            &self.scope,
            &self.secret_reference,
            permissions.borrow(),
            consent.borrow(),
            registration_revision,
        )?;
        self.registration = Some(registration);
        Ok(self)
    }

    pub(crate) fn bind_registration(&mut self, registration: FastlyServiceResultRegistration) {
        self.registration = Some(registration);
    }

    #[must_use]
    pub fn scope(&self) -> &FastlyServiceResultScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration(&self) -> Option<&FastlyServiceResultRegistration> {
        self.registration.as_ref()
    }

    pub(crate) fn registration_mut(&mut self) -> Option<&mut FastlyServiceResultRegistration> {
        self.registration.as_mut()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_parts(
            "fastly-provider/v1",
            &[
                ("provider", FASTLY_SERVICE_RESULT_PROVIDER_ID.to_owned()),
                ("apiRevision", API_REVISION.to_owned()),
            ],
        )
    }

    pub fn reject_write(&self, operation: impl Into<String>) -> Result<()> {
        Err(FastlyServiceResultError::MutationForbidden {
            operation: operation.into(),
        })
    }

    pub fn read(&mut self, request: &FastlyReadRequest) -> Result<FastlyServiceResultEvidence> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(FastlyServiceResultError::RegistrationInactive)?
            .clone();
        if !registration.is_active() {
            return Err(match registration.state() {
                RegistrationState::Revoked => FastlyServiceResultError::RegistrationRevoked,
                RegistrationState::Reversed => FastlyServiceResultError::RegistrationReversed,
                RegistrationState::Active => FastlyServiceResultError::RegistrationInactive,
            });
        }
        self.validate_request(request, &registration)?;

        let mut receipts = Vec::new();
        let mut rate_limit = None;
        let service = match self.read_service(request, &mut receipts, &mut rate_limit) {
            Ok(value) => Some(value),
            Err(failure) => {
                return Ok(Self::failed_evidence(
                    &registration,
                    request,
                    FastlyServiceResultState::from_failure(&failure),
                    true,
                    None,
                    None,
                    None,
                    Vec::new(),
                    None,
                    receipts,
                    rate_limit,
                    Some(failure.into_public()),
                ));
            }
        };
        let version = match self.read_version(request, &mut receipts, &mut rate_limit) {
            Ok(value) => Some(value),
            Err(failure) => {
                return Ok(Self::failed_evidence(
                    &registration,
                    request,
                    FastlyServiceResultState::from_failure(&failure),
                    true,
                    service,
                    None,
                    None,
                    Vec::new(),
                    None,
                    receipts,
                    rate_limit,
                    Some(failure.into_public()),
                ));
            }
        };
        let environment = match self.read_environment(request, &mut receipts, &mut rate_limit) {
            Ok(value) => Some(value),
            Err(failure) => {
                return Ok(Self::failed_evidence(
                    &registration,
                    request,
                    FastlyServiceResultState::from_failure(&failure),
                    true,
                    service,
                    version,
                    None,
                    Vec::new(),
                    None,
                    receipts,
                    rate_limit,
                    Some(failure.into_public()),
                ));
            }
        };

        let (domains, domain_partial) =
            match self.read_domains(request, &mut receipts, &mut rate_limit) {
                Ok(value) => value,
                Err(failure) => {
                    return Ok(Self::failed_evidence(
                        &registration,
                        request,
                        FastlyServiceResultState::from_failure(&failure),
                        true,
                        service,
                        version,
                        environment,
                        Vec::new(),
                        None,
                        receipts,
                        rate_limit,
                        Some(failure.into_public()),
                    ));
                }
            };

        let validation = match self.read_validation(request, &mut receipts, &mut rate_limit) {
            Ok(value) => Some(value),
            Err(failure) => {
                return Ok(Self::failed_evidence(
                    &registration,
                    request,
                    FastlyServiceResultState::from_failure(&failure),
                    true,
                    service,
                    version,
                    environment,
                    domains,
                    None,
                    receipts,
                    rate_limit,
                    Some(failure.into_public()),
                ));
            }
        };
        if validation.as_ref().is_some_and(|value| {
            version
                .as_ref()
                .is_some_and(|version| value.config_digest != version.config_digest)
        }) {
            return Ok(Self::build_evidence(
                &registration,
                request,
                FastlyServiceResultState::Tampered,
                true,
                service,
                version,
                environment,
                domains,
                validation,
                receipts,
                rate_limit,
                Some(FastlyFailure {
                    category: "config_digest_mismatch".to_owned(),
                    status: None,
                    retryable: false,
                    redacted: true,
                }),
            ));
        }
        let state = if domain_partial {
            FastlyServiceResultState::Partial
        } else if domains.is_empty() {
            FastlyServiceResultState::Empty
        } else if validation
            .as_ref()
            .is_some_and(|value| value.state == crate::model::FastlyValidationState::Failed)
        {
            FastlyServiceResultState::ValidationFailed
        } else {
            FastlyServiceResultState::Present
        };
        Ok(Self::build_evidence(
            &registration,
            request,
            state,
            domain_partial,
            service,
            version,
            environment,
            domains,
            validation,
            receipts,
            rate_limit,
            None,
        ))
    }

    pub fn read_once(
        &mut self,
        request: &FastlyReadRequest,
    ) -> Result<FastlyServiceResultEvidence> {
        self.read(request)
    }

    fn validate_request(
        &self,
        request: &FastlyReadRequest,
        registration: &FastlyServiceResultRegistration,
    ) -> Result<()> {
        let scope_digest = self.scope.digest();
        if request.scope_digest != scope_digest
            || registration.scope_digest() != &scope_digest
            || request.permission_digest != *registration.permission_digest()
            || request.consent_digest != *registration.consent_digest()
            || request.project_revision != self.scope.project().revision()
            || request.mission_revision != self.scope.mission().revision()
            || request.work_product_revision != self.scope.work_product().revision()
            || request.max_pages == 0
            || request.max_pages > MAX_PAGES
        {
            return Err(FastlyServiceResultError::StaleRevision);
        }
        Ok(())
    }

    fn read_service(
        &mut self,
        request: &FastlyReadRequest,
        receipts: &mut Vec<FastlyRequestReceipt>,
        rate_limit: &mut Option<FastlyRateLimitReceipt>,
    ) -> std::result::Result<FastlyServiceProjection, ReadFailure> {
        let endpoint = FastlyEndpoint::Service {
            account_digest: self.scope.account().digest(),
            service_digest: self.scope.service().digest(),
        };
        let response = self.execute_bounded(
            FastlyRequest::scoped(endpoint, &request.scope_digest, 1),
            receipts,
            rate_limit,
        )?;
        let FastlyResponseBody::Service(payload) = response.body.ok_or(ReadFailure::tampered())?
        else {
            return Err(ReadFailure::tampered());
        };
        if payload.account_digest != self.scope.account().digest()
            || payload.service_digest != self.scope.service().digest()
        {
            return Err(ReadFailure::tampered());
        }
        Ok(FastlyServiceProjection {
            account_digest: payload.account_digest,
            service_digest: payload.service_digest,
            metadata_digest: payload.metadata_digest,
        })
    }

    fn read_version(
        &mut self,
        request: &FastlyReadRequest,
        receipts: &mut Vec<FastlyRequestReceipt>,
        rate_limit: &mut Option<FastlyRateLimitReceipt>,
    ) -> std::result::Result<FastlyVersionProjection, ReadFailure> {
        let endpoint = FastlyEndpoint::Version {
            service_digest: self.scope.service().digest(),
            version_digest: self.scope.version().digest(),
        };
        let response = self.execute_bounded(
            FastlyRequest::scoped(endpoint, &request.scope_digest, 1),
            receipts,
            rate_limit,
        )?;
        let FastlyResponseBody::Version(payload) = response.body.ok_or(ReadFailure::tampered())?
        else {
            return Err(ReadFailure::tampered());
        };
        if payload.version_digest != self.scope.version().digest()
            || payload.config_digest == Digest::pending()
        {
            return Err(ReadFailure::tampered());
        }
        Ok(FastlyVersionProjection {
            version_digest: payload.version_digest,
            config_digest: payload.config_digest,
            state: payload.state,
            active: payload.active,
            staging: payload.staging,
            testing: payload.testing,
            metadata_digest: payload.metadata_digest,
        })
    }

    fn read_environment(
        &mut self,
        request: &FastlyReadRequest,
        receipts: &mut Vec<FastlyRequestReceipt>,
        rate_limit: &mut Option<FastlyRateLimitReceipt>,
    ) -> std::result::Result<FastlyEnvironmentProjection, ReadFailure> {
        let endpoint = FastlyEndpoint::Environment {
            service_digest: self.scope.service().digest(),
            version_digest: self.scope.version().digest(),
            environment_digest: self.scope.environment().digest(),
        };
        let response = self.execute_bounded(
            FastlyRequest::scoped(endpoint, &request.scope_digest, 1),
            receipts,
            rate_limit,
        )?;
        let FastlyResponseBody::Environment(payload) =
            response.body.ok_or(ReadFailure::tampered())?
        else {
            return Err(ReadFailure::tampered());
        };
        if payload.environment_digest != self.scope.environment().digest()
            || payload.version_digest != self.scope.version().digest()
        {
            return Err(ReadFailure::tampered());
        }
        Ok(FastlyEnvironmentProjection {
            environment_digest: payload.environment_digest,
            version_digest: payload.version_digest,
            state: payload.state,
            active: payload.active,
            staging: payload.staging,
            testing: payload.testing,
            metadata_digest: payload.metadata_digest,
        })
    }

    fn read_domains(
        &mut self,
        request: &FastlyReadRequest,
        receipts: &mut Vec<FastlyRequestReceipt>,
        rate_limit: &mut Option<FastlyRateLimitReceipt>,
    ) -> std::result::Result<(Vec<FastlyDomainProjection>, bool), ReadFailure> {
        let mut page = 1;
        let mut domains = Vec::new();
        let mut partial = false;
        let mut seen = BTreeSet::new();
        loop {
            let endpoint = FastlyEndpoint::Domain {
                service_digest: self.scope.service().digest(),
                version_digest: self.scope.version().digest(),
                domain_digest: self.scope.domain().digest(),
            };
            let response = self.execute_bounded(
                FastlyRequest::scoped(endpoint, &request.scope_digest, page),
                receipts,
                rate_limit,
            )?;
            let FastlyResponseBody::Domain(payload) =
                response.body.ok_or(ReadFailure::tampered())?
            else {
                return Err(ReadFailure::tampered());
            };
            if payload.page != page || payload.total_pages < payload.page {
                return Err(ReadFailure::tampered());
            }
            let total_pages = payload.total_pages;
            partial |= payload.partial;
            for domain in payload.entries {
                if domain.version_digest != self.scope.version().digest()
                    || !seen.insert(domain.domain_digest.clone())
                {
                    return Err(ReadFailure::tampered());
                }
                domains.push(domain);
            }
            if page >= total_pages {
                break;
            }
            if page >= request.max_pages.min(MAX_PAGES) {
                partial = true;
                break;
            }
            page = page.saturating_add(1);
        }
        if !domains.is_empty()
            && !domains
                .iter()
                .any(|domain| domain.domain_digest == self.scope.domain().digest())
        {
            return Err(ReadFailure::tampered());
        }
        Ok((domains, partial))
    }

    fn read_validation(
        &mut self,
        request: &FastlyReadRequest,
        receipts: &mut Vec<FastlyRequestReceipt>,
        rate_limit: &mut Option<FastlyRateLimitReceipt>,
    ) -> std::result::Result<FastlyValidationProjection, ReadFailure> {
        let endpoint = FastlyEndpoint::Validation {
            service_digest: self.scope.service().digest(),
            version_digest: self.scope.version().digest(),
        };
        let response = self.execute_bounded(
            FastlyRequest::scoped(endpoint, &request.scope_digest, 1),
            receipts,
            rate_limit,
        )?;
        let FastlyResponseBody::Validation(payload) =
            response.body.ok_or(ReadFailure::tampered())?
        else {
            return Err(ReadFailure::tampered());
        };
        if payload.config_digest == Digest::pending() {
            return Err(ReadFailure::tampered());
        }
        Ok(FastlyValidationProjection {
            validation_digest: payload.validation_digest,
            config_digest: payload.config_digest,
            state: payload.state,
            error_count: payload.error_count,
            warning_count: payload.warning_count,
            metadata_digest: payload.metadata_digest,
        })
    }

    fn execute_bounded(
        &mut self,
        request: FastlyRequest,
        receipts: &mut Vec<FastlyRequestReceipt>,
        rate_limit: &mut Option<FastlyRateLimitReceipt>,
    ) -> std::result::Result<FastlyResponse, ReadFailure> {
        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            match self.transport.execute(&request) {
                Ok(response) => {
                    let status = response.status;
                    if status == 429 {
                        let retry_after = MAX_BACKOFF_SECONDS.min(1);
                        receipts.push(receipt(
                            &request,
                            attempt,
                            FastlyRequestOutcome::RateLimited,
                            Some(status),
                            None,
                            Some(retry_after),
                        ));
                        *rate_limit = Some(FastlyRateLimitReceipt {
                            retry_after_seconds: retry_after,
                            attempts: attempt,
                            bounded: true,
                            redacted: true,
                        });
                        if attempt < MAX_RETRY_ATTEMPTS {
                            continue;
                        }
                        return Err(ReadFailure::rate_limited(status));
                    }
                    if status == 401 || status == 403 {
                        receipts.push(receipt(
                            &request,
                            attempt,
                            FastlyRequestOutcome::AccessLoss,
                            Some(status),
                            None,
                            None,
                        ));
                        return Err(ReadFailure::access_loss(status));
                    }
                    if status == 404 {
                        receipts.push(receipt(
                            &request,
                            attempt,
                            FastlyRequestOutcome::Empty,
                            Some(status),
                            None,
                            None,
                        ));
                        return Err(ReadFailure::empty(status));
                    }
                    if status >= 500 {
                        receipts.push(receipt(
                            &request,
                            attempt,
                            FastlyRequestOutcome::ServerError,
                            Some(status),
                            None,
                            None,
                        ));
                        return Err(ReadFailure::server_error(status));
                    }
                    response
                        .validate_for(&request)
                        .map_err(|error| match error {
                            FastlyTransportError::Tampered => ReadFailure::tampered(),
                            FastlyTransportError::ResponseTooLarge => ReadFailure {
                                state: FastlyServiceResultState::Partial,
                                category: "response_too_large",
                                status: None,
                                retryable: false,
                            },
                            _ => ReadFailure::tampered(),
                        })?;
                    let digest = response.body.as_ref().map(FastlyResponseBody::digest);
                    receipts.push(receipt(
                        &request,
                        attempt,
                        FastlyRequestOutcome::Success,
                        Some(status),
                        digest,
                        None,
                    ));
                    return Ok(response);
                }
                Err(error) => {
                    let (outcome, retry_after) = match error {
                        FastlyTransportError::RateLimited {
                            retry_after_seconds,
                        } => (FastlyRequestOutcome::RateLimited, retry_after_seconds),
                        FastlyTransportError::AccessLoss => {
                            (FastlyRequestOutcome::AccessLoss, None)
                        }
                        FastlyTransportError::Timeout => (FastlyRequestOutcome::Timeout, None),
                        FastlyTransportError::ServerError { .. } => {
                            (FastlyRequestOutcome::ServerError, None)
                        }
                        FastlyTransportError::NotFound => (FastlyRequestOutcome::Empty, None),
                        FastlyTransportError::BlockedEnv
                        | FastlyTransportError::ProviderUnknown => {
                            (FastlyRequestOutcome::Unknown, None)
                        }
                        FastlyTransportError::ResponseTooLarge
                        | FastlyTransportError::UnexpectedBody
                        | FastlyTransportError::Tampered => (FastlyRequestOutcome::Unknown, None),
                    };
                    receipts.push(receipt(
                        &request,
                        attempt,
                        outcome,
                        error.status(),
                        None,
                        retry_after,
                    ));
                    if matches!(error, FastlyTransportError::RateLimited { .. }) {
                        let bounded_retry_after = retry_after.unwrap_or(1).min(MAX_BACKOFF_SECONDS);
                        *rate_limit = Some(FastlyRateLimitReceipt {
                            retry_after_seconds: bounded_retry_after,
                            attempts: attempt,
                            bounded: true,
                            redacted: true,
                        });
                        if attempt < MAX_RETRY_ATTEMPTS {
                            continue;
                        }
                        return Err(ReadFailure::rate_limited(error.status().unwrap_or(429)));
                    }
                    return Err(ReadFailure::from_transport(error));
                }
            }
        }
        Err(ReadFailure::rate_limited(429))
    }

    fn failed_evidence(
        registration: &FastlyServiceResultRegistration,
        request: &FastlyReadRequest,
        state: FastlyServiceResultState,
        partial: bool,
        service: Option<FastlyServiceProjection>,
        version: Option<FastlyVersionProjection>,
        environment: Option<FastlyEnvironmentProjection>,
        domains: Vec<FastlyDomainProjection>,
        validation: Option<FastlyValidationProjection>,
        receipts: Vec<FastlyRequestReceipt>,
        rate_limit: Option<FastlyRateLimitReceipt>,
        failure: Option<FastlyFailure>,
    ) -> FastlyServiceResultEvidence {
        Self::build_evidence(
            registration,
            request,
            state,
            partial,
            service,
            version,
            environment,
            domains,
            validation,
            receipts,
            rate_limit,
            failure,
        )
    }

    fn build_evidence(
        registration: &FastlyServiceResultRegistration,
        request: &FastlyReadRequest,
        state: FastlyServiceResultState,
        partial: bool,
        service: Option<FastlyServiceProjection>,
        version: Option<FastlyVersionProjection>,
        environment: Option<FastlyEnvironmentProjection>,
        domains: Vec<FastlyDomainProjection>,
        validation: Option<FastlyValidationProjection>,
        request_receipts: Vec<FastlyRequestReceipt>,
        rate_limit: Option<FastlyRateLimitReceipt>,
        failure: Option<FastlyFailure>,
    ) -> FastlyServiceResultEvidence {
        let idempotency_digest = Digest::from_parts(
            "fastly-read-idempotency/v1",
            &[
                ("scope", request.scope_digest.to_string()),
                (
                    "registration",
                    registration.registration_digest().to_string(),
                ),
                (
                    "projectRevision",
                    request.project_revision.get().to_string(),
                ),
                (
                    "missionRevision",
                    request.mission_revision.get().to_string(),
                ),
                (
                    "workProductRevision",
                    request.work_product_revision.get().to_string(),
                ),
                ("maxPages", request.max_pages.to_string()),
            ],
        );
        let mut evidence = FastlyServiceResultEvidence {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: registration.contract_digest().clone(),
            plugin_version_digest: Digest::from_text(FASTLY_SERVICE_RESULT_PLUGIN_VERSION),
            provider_digest: registration.provider_digest().clone(),
            api_revision_digest: registration.api_revision_digest().clone(),
            permission_digest: registration.permission_digest().clone(),
            consent_digest: registration.consent_digest().clone(),
            scope_digest: request.scope_digest.clone(),
            registration_digest: registration.registration_digest().clone(),
            registration_revision: registration.registration_revision(),
            project_revision: request.project_revision,
            mission_revision: request.mission_revision,
            work_product_revision: request.work_product_revision,
            state,
            partial,
            service,
            version,
            environment,
            domains,
            validation,
            request_receipts,
            rate_limit,
            failure,
            evidence_digest: Digest::pending(),
            idempotency_digest,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            independent_native_readback: false,
            raw_vcl_retained: false,
            raw_config_retained: false,
            external_write_performed: false,
            work_product_adopted: false,
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence);
        evidence
    }
}

impl FastlyServiceResultState {
    fn from_failure(failure: &ReadFailure) -> Self {
        failure.state
    }
}

impl<T> fmt::Display for FastlyProvider<T>
where
    T: FastlyTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FastlyProvider")
            .field("provider", &FASTLY_SERVICE_RESULT_PROVIDER_ID)
            .field("scopeDigest", &self.scope.digest())
            .field("provenance", &self.provenance())
            .field("registered", &self.registration.is_some())
            .finish()
    }
}

#[derive(Clone, Debug)]
struct ReadFailure {
    state: FastlyServiceResultState,
    category: &'static str,
    status: Option<u16>,
    retryable: bool,
}

impl ReadFailure {
    const fn access_loss(status: u16) -> Self {
        Self {
            state: FastlyServiceResultState::AccessLoss,
            category: "access_loss",
            status: Some(status),
            retryable: false,
        }
    }

    const fn empty(status: u16) -> Self {
        Self {
            state: FastlyServiceResultState::Empty,
            category: "empty",
            status: Some(status),
            retryable: false,
        }
    }

    const fn rate_limited(status: u16) -> Self {
        Self {
            state: FastlyServiceResultState::RateLimited,
            category: "rate_limited",
            status: Some(status),
            retryable: true,
        }
    }

    const fn server_error(status: u16) -> Self {
        Self {
            state: FastlyServiceResultState::ServerError,
            category: "server_error",
            status: Some(status),
            retryable: true,
        }
    }

    const fn tampered() -> Self {
        Self {
            state: FastlyServiceResultState::Tampered,
            category: "tamper",
            status: None,
            retryable: false,
        }
    }

    fn from_transport(error: FastlyTransportError) -> Self {
        match error {
            FastlyTransportError::RateLimited { .. } => Self::rate_limited(429),
            FastlyTransportError::AccessLoss => Self::access_loss(403),
            FastlyTransportError::ProviderUnknown | FastlyTransportError::BlockedEnv => Self {
                state: FastlyServiceResultState::ProviderUnknown,
                category: "provider_unknown",
                status: None,
                retryable: false,
            },
            FastlyTransportError::Timeout => Self {
                state: FastlyServiceResultState::Timeout,
                category: "timeout",
                status: None,
                retryable: true,
            },
            FastlyTransportError::ServerError { status } => Self::server_error(status),
            FastlyTransportError::NotFound => Self::empty(404),
            FastlyTransportError::ResponseTooLarge => Self {
                state: FastlyServiceResultState::Partial,
                category: "response_too_large",
                status: None,
                retryable: false,
            },
            FastlyTransportError::UnexpectedBody | FastlyTransportError::Tampered => {
                Self::tampered()
            }
        }
    }

    fn into_public(self) -> FastlyFailure {
        FastlyFailure {
            category: self.category.to_owned(),
            status: self.status,
            retryable: self.retryable,
            redacted: true,
        }
    }
}

fn receipt(
    request: &FastlyRequest,
    attempt: u8,
    outcome: FastlyRequestOutcome,
    status: Option<u16>,
    response_digest: Option<Digest>,
    retry_after_seconds: Option<u32>,
) -> FastlyRequestReceipt {
    FastlyRequestReceipt {
        request_digest: request.digest(),
        endpoint: request.endpoint.name().to_owned(),
        page: request.page,
        attempt,
        outcome,
        status,
        response_digest,
        retry_after_seconds,
        redacted: true,
        connected: false,
        native: false,
        first_party: false,
    }
}

impl FastlyRequest {
    pub(crate) fn scoped(endpoint: FastlyEndpoint, scope_digest: &Digest, page: u16) -> Self {
        Self {
            method: crate::transport::FastlyHttpMethod::Get,
            endpoint,
            scope_digest: scope_digest.clone(),
            page: page.max(1),
            per_page: crate::model::PAGE_SIZE,
        }
    }
}

pub type Registration = FastlyServiceResultRegistration;
