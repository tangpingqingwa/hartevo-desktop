//! Typed service and Mission-consumer seam for Calendly result evidence.

use std::collections::{BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    API_REVISION, CONSUMER_ID, CalendlyPage, CalendlyProviderPort, CalendlySchedulingResultError,
    CalendlyScope, DEFAULT_PLUGIN_VERSION, Digest, EvidenceCompleteness, IMPLEMENTATION_REVISION,
    InviteeStatusProjection, MeetingResultState, MissionContext, PLUGIN_ID, PROVIDER_ID,
    PROVIDER_REVISION, PageBudget, PermissionLease, ProviderError, ProviderLifecycle, ProviderMode,
    ProviderProvenance, ProviderRequest, ProviderState, SERVICE_ID, ScheduledEventProjection,
    SecretReference, WebhookChangeSignal, WebhookReplayPolicy, contract_digest,
    digest_serialized_with_domain, implementation_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

/// Registration material is explicit so a provider cannot be mounted under a
/// different version, contract, implementation, permission, or event scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRequest {
    plugin_version: crate::PluginVersion,
    api_revision: String,
    contract_digest: Digest,
    provider_digest: Digest,
    implementation_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    event_revision: crate::Revision,
}

impl RegistrationRequest {
    pub fn new(
        plugin_version: crate::PluginVersion,
        contract_digest: Digest,
        provider_digest: Digest,
        implementation_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        event_revision: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Ok(Self {
            plugin_version,
            api_revision: API_REVISION.to_owned(),
            contract_digest,
            provider_digest,
            implementation_digest,
            permission_digest,
            scope_digest,
            event_revision: crate::Revision::new(event_revision)?,
        })
    }

    pub fn current<P: CalendlyProviderPort>(
        provider: &P,
        scope: &CalendlyScope,
        lease: &PermissionLease,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(
            DEFAULT_PLUGIN_VERSION,
            contract_digest()?,
            provider.provider_digest().clone(),
            implementation_digest()?,
            lease.permission_digest().clone(),
            scope.scope_digest().clone(),
            scope.event_revision().get(),
        )
    }

    pub const fn plugin_version(&self) -> crate::PluginVersion {
        self.plugin_version
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn event_revision(&self) -> crate::Revision {
        self.event_revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlyRegistration {
    plugin_id: String,
    request: RegistrationRequest,
    registration_digest: Digest,
    state: RegistrationState,
}

impl CalendlyRegistration {
    fn create(request: RegistrationRequest) -> Result<Self, CalendlySchedulingResultError> {
        #[derive(Serialize)]
        struct RegistrationBody<'a> {
            plugin_id: &'a str,
            request: &'a RegistrationRequest,
        }
        let registration_digest = digest_serialized_with_domain(
            "hartevo.calendly-registration/v1",
            &RegistrationBody {
                plugin_id: PLUGIN_ID,
                request: &request,
            },
        )?;
        Ok(Self {
            plugin_id: PLUGIN_ID.to_owned(),
            request,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    fn revoke(&mut self) -> Result<(), CalendlySchedulingResultError> {
        if self.state == RegistrationState::Revoked {
            Err(CalendlySchedulingResultError::RegistrationRevoked)
        } else {
            self.state = RegistrationState::Revoked;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlySchedulingResultServiceDefinition {
    service_id: String,
    version: crate::PluginVersion,
    contract_digest: Digest,
    implementation_digest: Digest,
    operations: Vec<String>,
    required_read_scopes: Vec<String>,
    read_only: bool,
    proposal_only: bool,
    external_writes: bool,
    calendar_authority: bool,
    booking_authority: bool,
}

impl CalendlySchedulingResultServiceDefinition {
    fn new() -> Result<Self, CalendlySchedulingResultError> {
        Ok(Self {
            service_id: SERVICE_ID.to_owned(),
            version: DEFAULT_PLUGIN_VERSION,
            contract_digest: contract_digest()?,
            implementation_digest: implementation_digest()?,
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "read_organization_user".to_owned(),
                "read_event_type".to_owned(),
                "read_scheduled_event".to_owned(),
                "read_invitee_status".to_owned(),
                "read_webhook_change_signals".to_owned(),
                "compile_adoption_proposal".to_owned(),
                "record_redacted_evidence".to_owned(),
            ],
            required_read_scopes: vec![
                "users:read".to_owned(),
                "event_types:read".to_owned(),
                "scheduled_events:read".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            external_writes: false,
            calendar_authority: false,
            booking_authority: false,
        })
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub const fn version(&self) -> crate::PluginVersion {
        self.version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn operations(&self) -> &[String] {
        &self.operations
    }

    pub fn required_read_scopes(&self) -> &[String] {
        &self.required_read_scopes
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
    }

    pub const fn external_writes(&self) -> bool {
        self.external_writes
    }

    pub const fn calendar_authority(&self) -> bool {
        self.calendar_authority
    }

    pub const fn booking_authority(&self) -> bool {
        self.booking_authority
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlyProviderDefinition {
    provider_id: String,
    provider_revision: String,
    provider_digest: Digest,
    implementation_revision: String,
    implementation_digest: Digest,
    api_revision: String,
    mode: ProviderMode,
    provenance: ProviderProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    reversible: bool,
    revocable: bool,
}

impl CalendlyProviderDefinition {
    fn new<P: CalendlyProviderPort>(provider: &P) -> Result<Self, CalendlySchedulingResultError> {
        let state = provider.state();
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: PROVIDER_REVISION.to_owned(),
            provider_digest: provider.provider_digest().clone(),
            implementation_revision: IMPLEMENTATION_REVISION.to_owned(),
            implementation_digest: implementation_digest()?,
            api_revision: crate::API_REVISION.to_owned(),
            mode: state.mode(),
            provenance: state.provenance(),
            connected: false,
            native: false,
            first_party: false,
            reversible: true,
            revocable: true,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn implementation_revision(&self) -> &str {
        &self.implementation_revision
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub const fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn reversible(&self) -> bool {
        self.reversible
    }

    pub const fn revocable(&self) -> bool {
        self.revocable
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCalendlyMeetingConsumerDefinition {
    consumer_id: String,
    service_id: String,
    mission_scoped: bool,
    project_revision_bound: bool,
    mission_revision_bound: bool,
    work_product_revision_bound: bool,
    proposal_only: bool,
    mutates_external_state: bool,
    adopts_work_product: bool,
    calendar_authority: bool,
}

impl MissionCalendlyMeetingConsumerDefinition {
    fn new() -> Self {
        Self {
            consumer_id: CONSUMER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            mission_scoped: true,
            project_revision_bound: true,
            mission_revision_bound: true,
            work_product_revision_bound: true,
            proposal_only: true,
            mutates_external_state: false,
            adopts_work_product: false,
            calendar_authority: false,
        }
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub const fn mission_scoped(&self) -> bool {
        self.mission_scoped
    }

    pub const fn project_revision_bound(&self) -> bool {
        self.project_revision_bound
    }

    pub const fn mission_revision_bound(&self) -> bool {
        self.mission_revision_bound
    }

    pub const fn work_product_revision_bound(&self) -> bool {
        self.work_product_revision_bound
    }

    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
    }

    pub const fn mutates_external_state(&self) -> bool {
        self.mutates_external_state
    }

    pub const fn adopts_work_product(&self) -> bool {
        self.adopts_work_product
    }

    pub const fn calendar_authority(&self) -> bool {
        self.calendar_authority
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlySchedulingResultCapabilityDescription {
    plugin_id: String,
    version: crate::PluginVersion,
    service: CalendlySchedulingResultServiceDefinition,
    provider: CalendlyProviderDefinition,
    consumer: MissionCalendlyMeetingConsumerDefinition,
    registration: Option<CalendlyRegistration>,
    connected: bool,
    native: bool,
    first_party: bool,
    calendar_authority: bool,
    booking_authority: bool,
}

impl CalendlySchedulingResultCapabilityDescription {
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub const fn version(&self) -> crate::PluginVersion {
        self.version
    }

    pub fn service(&self) -> &CalendlySchedulingResultServiceDefinition {
        &self.service
    }

    pub fn provider(&self) -> &CalendlyProviderDefinition {
        &self.provider
    }

    pub fn consumer(&self) -> &MissionCalendlyMeetingConsumerDefinition {
        &self.consumer
    }

    pub fn registration(&self) -> Option<&CalendlyRegistration> {
        self.registration.as_ref()
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn calendar_authority(&self) -> bool {
        self.calendar_authority
    }

    pub const fn booking_authority(&self) -> bool {
        self.booking_authority
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteeStatusCounts {
    total: u16,
    active: u16,
    canceled: u16,
    no_show: u16,
    unknown: u16,
}

impl InviteeStatusCounts {
    fn from_invitees(invitees: &[InviteeStatusProjection]) -> Self {
        let mut counts = Self {
            total: invitees.len() as u16,
            active: 0,
            canceled: 0,
            no_show: 0,
            unknown: 0,
        };
        for invitee in invitees {
            match invitee.status() {
                crate::InviteeStatus::Active => counts.active += 1,
                crate::InviteeStatus::Canceled => counts.canceled += 1,
                crate::InviteeStatus::Unknown => counts.unknown += 1,
            }
            if invitee.no_show() {
                counts.no_show += 1;
            }
        }
        counts
    }

    pub const fn total(self) -> u16 {
        self.total
    }

    pub const fn active(self) -> u16 {
        self.active
    }

    pub const fn canceled(self) -> u16 {
        self.canceled
    }

    pub const fn no_show(self) -> u16 {
        self.no_show
    }

    pub const fn unknown(self) -> u16 {
        self.unknown
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultDigests {
    event_digest: Digest,
    invitee_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    permission_digest: Digest,
    provider_digest: Digest,
    implementation_digest: Digest,
    contract_digest: Digest,
}

impl ResultDigests {
    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn invitee_digest(&self) -> &Digest {
        &self.invitee_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    credential_material_serialized: bool,
    invitee_pii_serialized: bool,
    raw_tracking_values_serialized: bool,
    raw_webhook_payload_serialized: bool,
    raw_location_or_join_url_serialized: bool,
    calendar_authority: bool,
    booking_authority: bool,
}

impl RedactionSummary {
    pub const fn layer1() -> Self {
        Self {
            credential_material_serialized: false,
            invitee_pii_serialized: false,
            raw_tracking_values_serialized: false,
            raw_webhook_payload_serialized: false,
            raw_location_or_join_url_serialized: false,
            calendar_authority: false,
            booking_authority: false,
        }
    }

    pub const fn credential_material_serialized(self) -> bool {
        self.credential_material_serialized
    }

    pub const fn invitee_pii_serialized(self) -> bool {
        self.invitee_pii_serialized
    }

    pub const fn raw_tracking_values_serialized(self) -> bool {
        self.raw_tracking_values_serialized
    }

    pub const fn raw_webhook_payload_serialized(self) -> bool {
        self.raw_webhook_payload_serialized
    }

    pub const fn raw_location_or_join_url_serialized(self) -> bool {
        self.raw_location_or_join_url_serialized
    }

    pub const fn calendar_authority(self) -> bool {
        self.calendar_authority
    }

    pub const fn booking_authority(self) -> bool {
        self.booking_authority
    }
}

/// Bounded, redacted scheduled meeting evidence below kernel authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlySchedulingResult {
    scope: CalendlyScope,
    organization: crate::OrganizationProjection,
    user: crate::UserProjection,
    event_type: crate::EventTypeProjection,
    scheduled_event: ScheduledEventProjection,
    invitees: Vec<InviteeStatusProjection>,
    webhook_signals: Vec<WebhookChangeSignal>,
    state: MeetingResultState,
    completeness: EvidenceCompleteness,
    invitee_status_counts: InviteeStatusCounts,
    pages_examined: u16,
    provider_revision: u64,
    provider_mode: ProviderMode,
    provider_provenance: ProviderProvenance,
    digests: ResultDigests,
    redaction: RedactionSummary,
    projection_digest: Digest,
}

impl CalendlySchedulingResult {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        scope: CalendlyScope,
        organization: crate::OrganizationProjection,
        user: crate::UserProjection,
        event_type: crate::EventTypeProjection,
        scheduled_event: ScheduledEventProjection,
        invitees: Vec<InviteeStatusProjection>,
        webhook_signals: Vec<WebhookChangeSignal>,
        pages_examined: u16,
        provider_state: ProviderState,
        provider_digest: Digest,
        implementation_digest: Digest,
        contract_digest: Digest,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let invitee_status_counts = InviteeStatusCounts::from_invitees(&invitees);
        let no_show = scheduled_event.no_show().no_show()
            || invitees.iter().any(InviteeStatusProjection::no_show)
            || webhook_signals
                .iter()
                .any(|signal| signal.event_kind() == crate::WebhookEventKind::InviteeNoShowCreated);
        let rescheduled = scheduled_event.reschedule().rescheduled()
            || webhook_signals.iter().any(WebhookChangeSignal::rescheduled);
        let state = if no_show {
            MeetingResultState::NoShow
        } else if rescheduled {
            MeetingResultState::Rescheduled
        } else {
            scheduled_event.result_state()
        };
        let completeness = if state == MeetingResultState::Unknown {
            EvidenceCompleteness::Unknown
        } else if invitees.is_empty()
            || invitees
                .iter()
                .any(|invitee| invitee.status() == crate::InviteeStatus::Unknown)
        {
            EvidenceCompleteness::Partial
        } else {
            EvidenceCompleteness::Complete
        };
        let invitee_digest =
            digest_serialized_with_domain("hartevo.calendly-invitee-list/v1", &invitees)?;
        #[derive(Serialize)]
        struct RevisionBody<'a> {
            event_revision: crate::Revision,
            project_revision: crate::Revision,
            mission_revision: crate::Revision,
            work_product_revision: crate::Revision,
            provider_revision: u64,
            provider_digest: &'a Digest,
            implementation_digest: &'a Digest,
        }
        let revision_digest = digest_serialized_with_domain(
            "hartevo.calendly-revision-fence/v1",
            &RevisionBody {
                event_revision: scope.event_revision(),
                project_revision: scope.project_revision(),
                mission_revision: scope.mission_revision(),
                work_product_revision: scope.work_product_revision(),
                provider_revision: provider_state.provider_revision(),
                provider_digest: &provider_digest,
                implementation_digest: &implementation_digest,
            },
        )?;
        let digests = ResultDigests {
            event_digest: scheduled_event.event_digest().clone(),
            invitee_digest,
            scope_digest: scope.scope_digest().clone(),
            revision_digest,
            permission_digest: scope.permission_digest().clone(),
            provider_digest,
            implementation_digest,
            contract_digest,
        };
        #[derive(Serialize)]
        struct ProjectionBody<'a> {
            scope: &'a CalendlyScope,
            organization: &'a crate::OrganizationProjection,
            user: &'a crate::UserProjection,
            event_type: &'a crate::EventTypeProjection,
            scheduled_event: &'a ScheduledEventProjection,
            invitees: &'a [InviteeStatusProjection],
            webhook_signals: &'a [WebhookChangeSignal],
            state: MeetingResultState,
            completeness: EvidenceCompleteness,
            invitee_status_counts: InviteeStatusCounts,
            pages_examined: u16,
            provider_revision: u64,
            provider_mode: ProviderMode,
            provider_provenance: ProviderProvenance,
            digests: &'a ResultDigests,
        }
        let projection_digest = digest_serialized_with_domain(
            "hartevo.calendly-scheduling-result/v1",
            &ProjectionBody {
                scope: &scope,
                organization: &organization,
                user: &user,
                event_type: &event_type,
                scheduled_event: &scheduled_event,
                invitees: &invitees,
                webhook_signals: &webhook_signals,
                state,
                completeness,
                invitee_status_counts,
                pages_examined,
                provider_revision: provider_state.provider_revision(),
                provider_mode: provider_state.mode(),
                provider_provenance: provider_state.provenance(),
                digests: &digests,
            },
        )?;
        Ok(Self {
            scope,
            organization,
            user,
            event_type,
            scheduled_event,
            invitees,
            webhook_signals,
            state,
            completeness,
            invitee_status_counts,
            pages_examined,
            provider_revision: provider_state.provider_revision(),
            provider_mode: provider_state.mode(),
            provider_provenance: provider_state.provenance(),
            digests,
            redaction: RedactionSummary::layer1(),
            projection_digest,
        })
    }

    pub fn scope(&self) -> &CalendlyScope {
        &self.scope
    }

    pub fn organization(&self) -> &crate::OrganizationProjection {
        &self.organization
    }

    pub fn user(&self) -> &crate::UserProjection {
        &self.user
    }

    pub fn event_type(&self) -> &crate::EventTypeProjection {
        &self.event_type
    }

    pub fn scheduled_event(&self) -> &ScheduledEventProjection {
        &self.scheduled_event
    }

    pub fn invitees(&self) -> &[InviteeStatusProjection] {
        &self.invitees
    }

    pub fn webhook_signals(&self) -> &[WebhookChangeSignal] {
        &self.webhook_signals
    }

    pub const fn state(&self) -> MeetingResultState {
        self.state
    }

    pub const fn completeness(&self) -> EvidenceCompleteness {
        self.completeness
    }

    pub const fn invitee_status_counts(&self) -> InviteeStatusCounts {
        self.invitee_status_counts
    }

    pub const fn pages_examined(&self) -> u16 {
        self.pages_examined
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub const fn provider_mode(&self) -> ProviderMode {
        self.provider_mode
    }

    pub const fn provider_provenance(&self) -> ProviderProvenance {
        self.provider_provenance
    }

    pub fn digests(&self) -> &ResultDigests {
        &self.digests
    }

    pub fn event_digest(&self) -> &Digest {
        self.digests.event_digest()
    }

    pub fn invitee_digest(&self) -> &Digest {
        self.digests.invitee_digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        self.digests.scope_digest()
    }

    pub fn revision_digest(&self) -> &Digest {
        self.digests.revision_digest()
    }

    pub fn redaction(&self) -> RedactionSummary {
        self.redaction
    }

    pub fn projection_digest(&self) -> &Digest {
        &self.projection_digest
    }

    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    pub const fn has_calendar_authority(&self) -> bool {
        false
    }

    pub const fn has_booking_authority(&self) -> bool {
        false
    }
}

/// Canonical non-mutating proposal. It is not an adoption command or a
/// verified Outcome and contains no external effect handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlyMeetingAdoptionProposal {
    proposal_schema: String,
    project_id: crate::ProjectId,
    project_revision: crate::Revision,
    mission_id: crate::MissionId,
    mission_revision: crate::Revision,
    work_product_id: crate::WorkProductId,
    work_product_revision: crate::Revision,
    event_revision: crate::Revision,
    scheduled_event_uri: crate::ScheduledEventUri,
    state: MeetingResultState,
    completeness: EvidenceCompleteness,
    event_digest: Digest,
    invitee_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    provider_mode: ProviderMode,
    provider_provenance: ProviderProvenance,
    non_mutating: bool,
    external_write: bool,
    calendar_authority: bool,
    booking_authority: bool,
    work_product_adopted: bool,
    outcome_adopted: bool,
    proposal_digest: Digest,
}

impl CalendlyMeetingAdoptionProposal {
    fn from_result(
        result: &CalendlySchedulingResult,
    ) -> Result<Self, CalendlySchedulingResultError> {
        #[derive(Serialize)]
        struct ProposalBody<'a> {
            proposal_schema: &'a str,
            project_id: &'a crate::ProjectId,
            project_revision: crate::Revision,
            mission_id: &'a crate::MissionId,
            mission_revision: crate::Revision,
            work_product_id: &'a crate::WorkProductId,
            work_product_revision: crate::Revision,
            event_revision: crate::Revision,
            scheduled_event_uri: &'a crate::ScheduledEventUri,
            state: MeetingResultState,
            completeness: EvidenceCompleteness,
            event_digest: &'a Digest,
            invitee_digest: &'a Digest,
            scope_digest: &'a Digest,
            revision_digest: &'a Digest,
            provider_mode: ProviderMode,
            provider_provenance: ProviderProvenance,
            non_mutating: bool,
            external_write: bool,
            calendar_authority: bool,
            booking_authority: bool,
            work_product_adopted: bool,
            outcome_adopted: bool,
        }
        let proposal_schema = "hartevo.calendly-scheduling-result-proposal/v1";
        let proposal_digest = digest_serialized_with_domain(
            "hartevo.calendly-adoption-proposal/v1",
            &ProposalBody {
                proposal_schema,
                project_id: result.scope.project_id(),
                project_revision: result.scope.project_revision(),
                mission_id: result.scope.mission_id(),
                mission_revision: result.scope.mission_revision(),
                work_product_id: result.scope.work_product_id(),
                work_product_revision: result.scope.work_product_revision(),
                event_revision: result.scope.event_revision(),
                scheduled_event_uri: result.scheduled_event.uri(),
                state: result.state,
                completeness: result.completeness,
                event_digest: result.digests.event_digest(),
                invitee_digest: result.digests.invitee_digest(),
                scope_digest: result.digests.scope_digest(),
                revision_digest: result.digests.revision_digest(),
                provider_mode: result.provider_mode,
                provider_provenance: result.provider_provenance,
                non_mutating: true,
                external_write: false,
                calendar_authority: false,
                booking_authority: false,
                work_product_adopted: false,
                outcome_adopted: false,
            },
        )?;
        Ok(Self {
            proposal_schema: proposal_schema.to_owned(),
            project_id: result.scope.project_id().clone(),
            project_revision: result.scope.project_revision(),
            mission_id: result.scope.mission_id().clone(),
            mission_revision: result.scope.mission_revision(),
            work_product_id: result.scope.work_product_id().clone(),
            work_product_revision: result.scope.work_product_revision(),
            event_revision: result.scope.event_revision(),
            scheduled_event_uri: result.scheduled_event.uri().clone(),
            state: result.state,
            completeness: result.completeness,
            event_digest: result.digests.event_digest().clone(),
            invitee_digest: result.digests.invitee_digest().clone(),
            scope_digest: result.digests.scope_digest().clone(),
            revision_digest: result.digests.revision_digest().clone(),
            provider_mode: result.provider_mode,
            provider_provenance: result.provider_provenance,
            non_mutating: true,
            external_write: false,
            calendar_authority: false,
            booking_authority: false,
            work_product_adopted: false,
            outcome_adopted: false,
            proposal_digest,
        })
    }

    pub fn proposal_schema(&self) -> &str {
        &self.proposal_schema
    }

    pub fn project_id(&self) -> &crate::ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> crate::Revision {
        self.project_revision
    }

    pub fn mission_id(&self) -> &crate::MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> crate::Revision {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &crate::WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> crate::Revision {
        self.work_product_revision
    }

    pub const fn event_revision(&self) -> crate::Revision {
        self.event_revision
    }

    pub fn scheduled_event_uri(&self) -> &crate::ScheduledEventUri {
        &self.scheduled_event_uri
    }

    pub const fn state(&self) -> MeetingResultState {
        self.state
    }

    pub const fn completeness(&self) -> EvidenceCompleteness {
        self.completeness
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn invitee_digest(&self) -> &Digest {
        &self.invitee_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub const fn non_mutating(&self) -> bool {
        self.non_mutating
    }

    pub const fn external_write(&self) -> bool {
        self.external_write
    }

    pub const fn calendar_authority(&self) -> bool {
        self.calendar_authority
    }

    pub const fn booking_authority(&self) -> bool {
        self.booking_authority
    }

    pub const fn work_product_adopted(&self) -> bool {
        self.work_product_adopted
    }

    pub const fn outcome_adopted(&self) -> bool {
        self.outcome_adopted
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

pub type CalendlySchedulingResultProposal = CalendlyMeetingAdoptionProposal;

/// A bounded redacted recording below kernel authority. It is not a durable
/// native provider receipt and does not imply that a write was performed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlyRedactedRecording {
    recording_schema: String,
    recorded_at_millis: u64,
    provider_mode: ProviderMode,
    provider_provenance: ProviderProvenance,
    state: MeetingResultState,
    completeness: EvidenceCompleteness,
    event_digest: Digest,
    invitee_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    projection_digest: Digest,
    raw_provider_payload_serialized: bool,
    credential_material_serialized: bool,
    invitee_pii_serialized: bool,
    durable_native_receipt: bool,
    independently_verified: bool,
    work_product_adopted: bool,
    recording_digest: Digest,
}

impl CalendlyRedactedRecording {
    fn from_result(
        result: &CalendlySchedulingResult,
        recorded_at_millis: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if recorded_at_millis == 0 {
            return Err(CalendlySchedulingResultError::InvalidScope);
        }
        let recording_schema = "hartevo.calendly-scheduling-result-recording/v1";
        #[derive(Serialize)]
        struct RecordingBody<'a> {
            recording_schema: &'a str,
            recorded_at_millis: u64,
            provider_mode: ProviderMode,
            provider_provenance: ProviderProvenance,
            state: MeetingResultState,
            completeness: EvidenceCompleteness,
            event_digest: &'a Digest,
            invitee_digest: &'a Digest,
            scope_digest: &'a Digest,
            revision_digest: &'a Digest,
            projection_digest: &'a Digest,
            raw_provider_payload_serialized: bool,
            credential_material_serialized: bool,
            invitee_pii_serialized: bool,
            durable_native_receipt: bool,
            independently_verified: bool,
            work_product_adopted: bool,
        }
        let recording_digest = digest_serialized_with_domain(
            "hartevo.calendly-redacted-recording/v1",
            &RecordingBody {
                recording_schema,
                recorded_at_millis,
                provider_mode: result.provider_mode,
                provider_provenance: result.provider_provenance,
                state: result.state,
                completeness: result.completeness,
                event_digest: result.digests.event_digest(),
                invitee_digest: result.digests.invitee_digest(),
                scope_digest: result.digests.scope_digest(),
                revision_digest: result.digests.revision_digest(),
                projection_digest: result.projection_digest(),
                raw_provider_payload_serialized: false,
                credential_material_serialized: false,
                invitee_pii_serialized: false,
                durable_native_receipt: false,
                independently_verified: false,
                work_product_adopted: false,
            },
        )?;
        Ok(Self {
            recording_schema: recording_schema.to_owned(),
            recorded_at_millis,
            provider_mode: result.provider_mode,
            provider_provenance: result.provider_provenance,
            state: result.state,
            completeness: result.completeness,
            event_digest: result.digests.event_digest().clone(),
            invitee_digest: result.digests.invitee_digest().clone(),
            scope_digest: result.digests.scope_digest().clone(),
            revision_digest: result.digests.revision_digest().clone(),
            projection_digest: result.projection_digest().clone(),
            raw_provider_payload_serialized: false,
            credential_material_serialized: false,
            invitee_pii_serialized: false,
            durable_native_receipt: false,
            independently_verified: false,
            work_product_adopted: false,
            recording_digest,
        })
    }

    pub fn recording_schema(&self) -> &str {
        &self.recording_schema
    }

    pub const fn recorded_at_millis(&self) -> u64 {
        self.recorded_at_millis
    }

    pub const fn state(&self) -> MeetingResultState {
        self.state
    }

    pub const fn completeness(&self) -> EvidenceCompleteness {
        self.completeness
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn invitee_digest(&self) -> &Digest {
        &self.invitee_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub fn projection_digest(&self) -> &Digest {
        &self.projection_digest
    }

    pub const fn raw_provider_payload_serialized(&self) -> bool {
        self.raw_provider_payload_serialized
    }

    pub const fn credential_material_serialized(&self) -> bool {
        self.credential_material_serialized
    }

    pub const fn invitee_pii_serialized(&self) -> bool {
        self.invitee_pii_serialized
    }

    pub const fn durable_native_receipt(&self) -> bool {
        self.durable_native_receipt
    }

    pub const fn independently_verified(&self) -> bool {
        self.independently_verified
    }

    pub const fn work_product_adopted(&self) -> bool {
        self.work_product_adopted
    }

    pub fn recording_digest(&self) -> &Digest {
        &self.recording_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    registration_digest: Digest,
    revoked_at_millis: u64,
    reversible: bool,
    provider_unmounted: bool,
    secret_reference_revoked: bool,
}

impl RevocationReceipt {
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn revoked_at_millis(&self) -> u64 {
        self.revoked_at_millis
    }

    pub const fn reversible(&self) -> bool {
        self.reversible
    }

    pub const fn provider_unmounted(&self) -> bool {
        self.provider_unmounted
    }

    pub const fn secret_reference_revoked(&self) -> bool {
        self.secret_reference_revoked
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionCalendlyMeetingResult {
    result: CalendlySchedulingResult,
    proposal: CalendlyMeetingAdoptionProposal,
    recording: CalendlyRedactedRecording,
}

impl MissionCalendlyMeetingResult {
    pub fn result(&self) -> &CalendlySchedulingResult {
        &self.result
    }

    pub fn proposal(&self) -> &CalendlyMeetingAdoptionProposal {
        &self.proposal
    }

    pub fn recording(&self) -> &CalendlyRedactedRecording {
        &self.recording
    }
}

/// Layer-1 service implementation. It owns an in-memory registration and a
/// controlled provider port, but no kernel storage or external effect port.
#[derive(Clone, Debug)]
pub struct CalendlySchedulingResultService<P = crate::CalendlyProvider>
where
    P: CalendlyProviderPort,
{
    provider: P,
    scope: CalendlyScope,
    permission_lease: PermissionLease,
    secret_reference: SecretReference,
    registration: CalendlyRegistration,
    page_budget: PageBudget,
    webhook_policy: WebhookReplayPolicy,
}

impl<P> CalendlySchedulingResultService<P>
where
    P: CalendlyProviderPort,
{
    pub fn register(
        provider: P,
        scope: CalendlyScope,
        permission_lease: PermissionLease,
        secret_reference: SecretReference,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if permission_lease.permission_digest() != scope.permission_digest() {
            return Err(CalendlySchedulingResultError::SecretPermissionMismatch);
        }
        if secret_reference.scope_digest() != scope.scope_digest() {
            return Err(CalendlySchedulingResultError::SecretScopeMismatch);
        }
        if secret_reference.permission_digest() != permission_lease.permission_digest() {
            return Err(CalendlySchedulingResultError::SecretPermissionMismatch);
        }
        let request = RegistrationRequest::current(&provider, &scope, &permission_lease)?;
        let registration = CalendlyRegistration::create(request)?;
        Ok(Self {
            provider,
            scope,
            permission_lease,
            secret_reference,
            registration,
            page_budget: PageBudget::bounded(),
            webhook_policy: WebhookReplayPolicy::bounded(),
        })
    }

    pub fn new(
        provider: P,
        scope: CalendlyScope,
        permission_lease: PermissionLease,
        secret_reference: SecretReference,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Self::register(provider, scope, permission_lease, secret_reference)
    }

    pub fn with_bounds(
        mut self,
        page_budget: PageBudget,
        webhook_policy: WebhookReplayPolicy,
    ) -> Self {
        self.page_budget = page_budget;
        self.webhook_policy = webhook_policy;
        self
    }

    fn assert_active(
        &self,
        context: &MissionContext,
        now_millis: u64,
    ) -> Result<(), CalendlySchedulingResultError> {
        if now_millis == 0 {
            return Err(CalendlySchedulingResultError::InvalidScope);
        }
        if self.registration.state() == RegistrationState::Revoked {
            return Err(CalendlySchedulingResultError::RegistrationRevoked);
        }
        if self.provider.state().lifecycle() == ProviderLifecycle::Revoked {
            return Err(CalendlySchedulingResultError::Provider(
                ProviderError::ProviderRevoked,
            ));
        }
        let request = self.registration.request();
        if request.plugin_version() != DEFAULT_PLUGIN_VERSION {
            return Err(CalendlySchedulingResultError::RegistrationVersionMismatch);
        }
        if request.api_revision() != API_REVISION {
            return Err(CalendlySchedulingResultError::RegistrationApiRevisionMismatch);
        }
        if request.contract_digest() != &contract_digest()? {
            return Err(CalendlySchedulingResultError::RegistrationContractMismatch);
        }
        if request.provider_digest() != self.provider.provider_digest() {
            return Err(CalendlySchedulingResultError::RegistrationProviderMismatch);
        }
        if request.implementation_digest() != &implementation_digest()? {
            return Err(CalendlySchedulingResultError::RegistrationImplementationMismatch);
        }
        if request.permission_digest() != self.permission_lease.permission_digest()
            || request.permission_digest() != self.scope.permission_digest()
        {
            return Err(CalendlySchedulingResultError::RegistrationPermissionMismatch);
        }
        if request.scope_digest() != self.scope.scope_digest() {
            return Err(CalendlySchedulingResultError::RegistrationScopeMismatch);
        }
        if request.event_revision() != self.scope.event_revision() {
            return Err(CalendlySchedulingResultError::RegistrationEventRevisionMismatch);
        }
        if self.secret_reference.is_revoked() {
            return Err(CalendlySchedulingResultError::SecretRevoked);
        }
        if self.secret_reference.scope_digest() != self.scope.scope_digest() {
            return Err(CalendlySchedulingResultError::SecretScopeMismatch);
        }
        if self.secret_reference.permission_digest() != self.permission_lease.permission_digest() {
            return Err(CalendlySchedulingResultError::SecretPermissionMismatch);
        }
        self.permission_lease.validate_at(now_millis)?;
        context.matches(&self.scope)
    }

    fn validate_page_identity(
        &self,
        page: &CalendlyPage,
        first_page: Option<&CalendlyPage>,
    ) -> Result<(), CalendlySchedulingResultError> {
        if page.organization().uri() != self.scope.organization_uri()
            || page.user().uri() != self.scope.user_uri()
        {
            return Err(CalendlySchedulingResultError::OrganizationUserScopeMismatch);
        }
        if page.event_type().uri() != self.scope.event_type_uri() {
            return Err(CalendlySchedulingResultError::EventTypeScopeMismatch);
        }
        if page.scheduled_event().uri() != self.scope.scheduled_event_uri() {
            return Err(CalendlySchedulingResultError::EventScopeMismatch);
        }
        if page.scheduled_event().event_revision() != self.scope.event_revision() {
            return Err(CalendlySchedulingResultError::StaleEventRevision);
        }
        let date_window = self.scope.date_window();
        if page.scheduled_event().start_at_millis() < date_window.start_at_millis()
            || page.scheduled_event().end_at_millis() > date_window.end_at_millis()
        {
            return Err(CalendlySchedulingResultError::EventScopeMismatch);
        }
        if page.provider_revision() != self.provider.provider_revision()
            || page.permission_digest() != self.permission_lease.permission_digest()
        {
            return Err(CalendlySchedulingResultError::ProviderRevisionDrift);
        }
        if let Some(first_page) = first_page
            && (page.organization() != first_page.organization()
                || page.user() != first_page.user()
                || page.event_type() != first_page.event_type()
                || page.scheduled_event().event_digest()
                    != first_page.scheduled_event().event_digest())
        {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        Ok(())
    }

    /// Read and project one bounded scheduled meeting result.
    pub fn read_result(
        &self,
        context: &MissionContext,
        now_millis: u64,
    ) -> Result<CalendlySchedulingResult, CalendlySchedulingResultError> {
        self.assert_active(context, now_millis)?;
        let mut cursor: Option<crate::PageCursor> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_invitee_uris = HashSet::new();
        let mut seen_delivery_ids = HashSet::new();
        let mut first_page: Option<CalendlyPage> = None;
        let mut organization = None;
        let mut user = None;
        let mut event_type = None;
        let mut scheduled_event = None;
        let mut invitees = Vec::new();
        let mut webhook_signals = Vec::new();
        let mut pages_examined = 0_u16;

        loop {
            if pages_examined >= self.page_budget.max_pages() {
                return Err(CalendlySchedulingResultError::PageBudgetExceeded);
            }
            let request = ProviderRequest::new(
                &self.scope,
                &self.secret_reference,
                &self.permission_lease,
                cursor.as_ref(),
                100,
                now_millis,
            )?;
            let page = self.provider.read_page(request)?;
            self.validate_page_identity(&page, first_page.as_ref())?;
            if first_page.is_none() {
                organization = Some(page.organization().clone());
                user = Some(page.user().clone());
                event_type = Some(page.event_type().clone());
                scheduled_event = Some(page.scheduled_event().clone());
                first_page = Some(page.clone());
            }
            pages_examined += 1;
            if invitees.len() + page.invitees().len() > self.page_budget.max_invitees() {
                return Err(CalendlySchedulingResultError::PageBudgetExceeded);
            }
            for invitee in page.invitees() {
                if !seen_invitee_uris.insert(invitee.uri().clone()) {
                    return Err(CalendlySchedulingResultError::MalformedProviderData);
                }
                invitees.push(invitee.clone());
            }
            if webhook_signals.len() + page.webhook_signals().len()
                > self.page_budget.max_webhook_signals()
            {
                return Err(CalendlySchedulingResultError::PageBudgetExceeded);
            }
            for signal in page.webhook_signals() {
                if signal.event_uri() != self.scope.scheduled_event_uri() {
                    return Err(CalendlySchedulingResultError::EventScopeMismatch);
                }
                signal.validate_at(now_millis, self.webhook_policy)?;
                if !seen_delivery_ids.insert(signal.delivery_id().clone()) {
                    return Err(CalendlySchedulingResultError::DuplicateWebhookDelivery);
                }
                webhook_signals.push(signal.clone());
            }
            match page.next_cursor().cloned() {
                None => break,
                Some(next_cursor) => {
                    if !seen_cursors.insert(next_cursor.as_str().to_owned()) {
                        return Err(CalendlySchedulingResultError::PaginationLoop);
                    }
                    cursor = Some(next_cursor);
                }
            }
        }

        CalendlySchedulingResult::from_parts(
            self.scope.clone(),
            organization.ok_or(CalendlySchedulingResultError::MalformedProviderData)?,
            user.ok_or(CalendlySchedulingResultError::MalformedProviderData)?,
            event_type.ok_or(CalendlySchedulingResultError::MalformedProviderData)?,
            scheduled_event.ok_or(CalendlySchedulingResultError::MalformedProviderData)?,
            invitees,
            webhook_signals,
            pages_examined,
            self.provider.state(),
            self.provider.provider_digest().clone(),
            implementation_digest()?,
            contract_digest()?,
        )
    }

    pub fn read_scheduled_meeting(
        &self,
        context: &MissionContext,
        now_millis: u64,
    ) -> Result<CalendlySchedulingResult, CalendlySchedulingResultError> {
        self.read_result(context, now_millis)
    }

    pub fn read_meeting_result(
        &self,
        context: &MissionContext,
        now_millis: u64,
    ) -> Result<CalendlySchedulingResult, CalendlySchedulingResultError> {
        self.read_result(context, now_millis)
    }

    pub fn compile_adoption_proposal(
        &self,
        result: &CalendlySchedulingResult,
    ) -> Result<CalendlyMeetingAdoptionProposal, CalendlySchedulingResultError> {
        if result.scope().scope_digest() != self.scope.scope_digest() {
            return Err(CalendlySchedulingResultError::RegistrationScopeMismatch);
        }
        if result.digests().provider_digest() != self.provider.provider_digest()
            || result.digests().permission_digest() != self.permission_lease.permission_digest()
        {
            return Err(CalendlySchedulingResultError::RegistrationProviderMismatch);
        }
        CalendlyMeetingAdoptionProposal::from_result(result)
    }

    pub fn record_redacted_evidence(
        &self,
        result: &CalendlySchedulingResult,
        recorded_at_millis: u64,
    ) -> Result<CalendlyRedactedRecording, CalendlySchedulingResultError> {
        if result.scope().scope_digest() != self.scope.scope_digest() {
            return Err(CalendlySchedulingResultError::RegistrationScopeMismatch);
        }
        CalendlyRedactedRecording::from_result(result, recorded_at_millis)
    }

    /// This validates the in-memory projection identity only. It does not
    /// perform an independent provider read-back or claim verification.
    pub fn verify_projection(
        &self,
        result: &CalendlySchedulingResult,
    ) -> Result<(), CalendlySchedulingResultError> {
        if result.scope().scope_digest() != self.scope.scope_digest()
            || result.digests().provider_digest() != self.provider.provider_digest()
            || result.digests().implementation_digest() != &implementation_digest()?
            || result.digests().contract_digest() != &contract_digest()?
        {
            Err(CalendlySchedulingResultError::RegistrationScopeMismatch)
        } else {
            Ok(())
        }
    }

    pub fn revoke_registration(
        &mut self,
        revoked_at_millis: u64,
    ) -> Result<RevocationReceipt, CalendlySchedulingResultError> {
        if revoked_at_millis == 0 {
            return Err(CalendlySchedulingResultError::InvalidScope);
        }
        self.registration.revoke()?;
        self.provider.revoke();
        let secret_reference_revoked = if self.secret_reference.is_revoked() {
            true
        } else {
            self.secret_reference.revoke()?;
            true
        };
        Ok(RevocationReceipt {
            registration_digest: self.registration.registration_digest().clone(),
            revoked_at_millis,
            reversible: true,
            provider_unmounted: true,
            secret_reference_revoked,
        })
    }

    pub fn revoke(
        &mut self,
        revoked_at_millis: u64,
    ) -> Result<RevocationReceipt, CalendlySchedulingResultError> {
        self.revoke_registration(revoked_at_millis)
    }

    pub fn unmount(
        &mut self,
        revoked_at_millis: u64,
    ) -> Result<RevocationReceipt, CalendlySchedulingResultError> {
        self.revoke_registration(revoked_at_millis)
    }

    pub fn registration(&self) -> &CalendlyRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &CalendlyScope {
        &self.scope
    }

    pub fn permission_lease(&self) -> &PermissionLease {
        &self.permission_lease
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_state(&self) -> ProviderState {
        self.provider.state()
    }

    pub fn page_budget(&self) -> PageBudget {
        self.page_budget
    }

    pub fn webhook_policy(&self) -> WebhookReplayPolicy {
        self.webhook_policy
    }

    pub fn describe_capabilities(
        &self,
    ) -> Result<CalendlySchedulingResultCapabilityDescription, CalendlySchedulingResultError> {
        Ok(CalendlySchedulingResultCapabilityDescription {
            plugin_id: PLUGIN_ID.to_owned(),
            version: DEFAULT_PLUGIN_VERSION,
            service: CalendlySchedulingResultServiceDefinition::new()?,
            provider: CalendlyProviderDefinition::new(&self.provider)?,
            consumer: MissionCalendlyMeetingConsumerDefinition::new(),
            registration: Some(self.registration.clone()),
            connected: false,
            native: false,
            first_party: false,
            calendar_authority: false,
            booking_authority: false,
        })
    }
}

/// Typed Mission consumer that turns a read into a proposal and redacted
/// recording. It has no adoption or effect method.
#[derive(Clone, Debug, Default)]
pub struct MissionCalendlyMeetingConsumer;

impl MissionCalendlyMeetingConsumer {
    pub const fn new() -> Self {
        Self
    }

    pub fn definition(&self) -> MissionCalendlyMeetingConsumerDefinition {
        MissionCalendlyMeetingConsumerDefinition::new()
    }

    pub fn consume<P: CalendlyProviderPort>(
        &self,
        service: &CalendlySchedulingResultService<P>,
        context: &MissionContext,
        now_millis: u64,
    ) -> Result<MissionCalendlyMeetingResult, CalendlySchedulingResultError> {
        let result = service.read_result(context, now_millis)?;
        let proposal = service.compile_adoption_proposal(&result)?;
        let recording = service.record_redacted_evidence(&result, now_millis)?;
        Ok(MissionCalendlyMeetingResult {
            result,
            proposal,
            recording,
        })
    }
}

pub type CalendlyMeetingResult = CalendlySchedulingResult;
pub type MissionCalendlyResult = MissionCalendlyMeetingResult;
