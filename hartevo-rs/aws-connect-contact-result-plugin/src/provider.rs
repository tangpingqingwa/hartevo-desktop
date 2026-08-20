//! Provider seams for the bounded Amazon Connect Layer-1 contract.
//!
//! There is deliberately no AWS SDK, credential resolver, HTTP client, or
//! native transport in this module. The four transports are explicit test and
//! provenance boundaries only.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};

use crate::error::{AwsConnectContactResultError, AwsConnectTransportError, Result};
use crate::model::{
    AttributeValueInput, AwsConnectContactScope, ContactLifecycle, ContactRecord, ContactState,
    DescribeContactRequest, DescribeContactResponse, Digest, GetContactAttributesRequest,
    GetContactAttributesResponse, InitiationMethod, SearchContactsRequest, SearchContactsResponse,
    TransportProvenance,
};
use crate::{CONTRACT_DIGEST, PROVIDER_API_REVISION, PROVIDER_ID};

pub const PROVIDER_REVISION: u64 = 1;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AwsConnectOperation {
    SearchContacts,
    DescribeContact,
    GetContactAttributes,
}

impl AwsConnectOperation {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SearchContacts => "SearchContacts",
            Self::DescribeContact => "DescribeContact",
            Self::GetContactAttributes => "GetContactAttributes",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsConnectProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub operations: Vec<AwsConnectOperation>,
    pub provenance: TransportProvenance,
    pub provider_digest: Digest,
}

impl AwsConnectProviderDefinition {
    fn for_provenance(provenance: TransportProvenance) -> Self {
        let operations = vec![
            AwsConnectOperation::SearchContacts,
            AwsConnectOperation::DescribeContact,
            AwsConnectOperation::GetContactAttributes,
        ];
        let provider_digest = Digest::from_parts(
            "aws-connect-provider-definition/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("revision", PROVIDER_REVISION.to_string()),
                ("api", PROVIDER_API_REVISION.to_owned()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(AwsConnectOperation::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("provenance", provenance.as_str().to_owned()),
                ("contract", CONTRACT_DIGEST.to_owned()),
                ("connected", "false".to_owned()),
                ("native", "false".to_owned()),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: PROVIDER_REVISION,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations,
            provenance,
            provider_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision != PROVIDER_REVISION
            || self.api_revision != PROVIDER_API_REVISION
            || self.operations
                != vec![
                    AwsConnectOperation::SearchContacts,
                    AwsConnectOperation::DescribeContact,
                    AwsConnectOperation::GetContactAttributes,
                ]
            || self.provider_digest != Self::for_provenance(self.provenance.clone()).provider_digest
        {
            return Err(AwsConnectContactResultError::ProviderDrift);
        }
        self.provider_digest.validate()
    }
}

pub trait AwsConnectTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn search_contacts(
        &mut self,
        request: &SearchContactsRequest,
    ) -> std::result::Result<SearchContactsResponse, AwsConnectTransportError>;

    fn describe_contact(
        &mut self,
        request: &DescribeContactRequest,
    ) -> std::result::Result<DescribeContactResponse, AwsConnectTransportError>;

    fn get_contact_attributes(
        &mut self,
        request: &GetContactAttributesRequest,
    ) -> std::result::Result<GetContactAttributesResponse, AwsConnectTransportError>;
}

pub struct AwsConnectProvider<T: AwsConnectTransport> {
    definition: AwsConnectProviderDefinition,
    transport: T,
}

impl<T: AwsConnectTransport> AwsConnectProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = AwsConnectProviderDefinition::for_provenance(transport.provenance());
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &AwsConnectProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> &TransportProvenance {
        &self.definition.provenance
    }

    pub fn search_contacts(
        &mut self,
        request: &SearchContactsRequest,
    ) -> std::result::Result<SearchContactsResponse, AwsConnectTransportError> {
        self.transport.search_contacts(request)
    }

    pub fn describe_contact(
        &mut self,
        request: &DescribeContactRequest,
    ) -> std::result::Result<DescribeContactResponse, AwsConnectTransportError> {
        self.transport.describe_contact(request)
    }

    pub fn get_contact_attributes(
        &mut self,
        request: &GetContactAttributesRequest,
    ) -> std::result::Result<GetContactAttributesResponse, AwsConnectTransportError> {
        self.transport.get_contact_attributes(request)
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: AwsConnectTransport> fmt::Debug for AwsConnectProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsConnectProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsConnectTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn search_contacts(
        &mut self,
        _request: &SearchContactsRequest,
    ) -> std::result::Result<SearchContactsResponse, AwsConnectTransportError> {
        Err(AwsConnectTransportError::BlockedEnv)
    }

    fn describe_contact(
        &mut self,
        _request: &DescribeContactRequest,
    ) -> std::result::Result<DescribeContactResponse, AwsConnectTransportError> {
        Err(AwsConnectTransportError::BlockedEnv)
    }

    fn get_contact_attributes(
        &mut self,
        _request: &GetContactAttributesRequest,
    ) -> std::result::Result<GetContactAttributesResponse, AwsConnectTransportError> {
        Err(AwsConnectTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    contact: ContactRecord,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsConnectContactScope, _observed_at: DateTime<Utc>) -> Self {
        let initiation = scope.time_window().start() + Duration::hours(1);
        let connected = initiation + Duration::minutes(2);
        let ended = connected + Duration::minutes(8);
        let lifecycle = ContactLifecycle::new(
            initiation,
            Some(connected),
            ended,
            Some(ended),
            ContactState::Ended,
            InitiationMethod::Inbound,
            Some(crate::model::DisconnectReasonClass::AgentDisconnect),
        )
        .expect("fixture lifecycle");
        let contact = ContactRecord::for_scope(scope, lifecycle).expect("fixture contact");
        Self {
            scope_digest: scope.digest(),
            contact,
        }
    }

    fn response_attributes(
        request: &GetContactAttributesRequest,
    ) -> Result<GetContactAttributesResponse> {
        let values = request
            .key_classes()
            .iter()
            .map(|key_class| AttributeValueInput::from_raw(*key_class, "fixture-redacted-value"))
            .collect::<Result<Vec<_>>>()?;
        GetContactAttributesResponse::new(request, values, 768, TransportProvenance::Fixture)
    }
}

impl AwsConnectTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn search_contacts(
        &mut self,
        request: &SearchContactsRequest,
    ) -> std::result::Result<SearchContactsResponse, AwsConnectTransportError> {
        if request.scope_digest() != &self.scope_digest {
            return Err(AwsConnectTransportError::InvalidResponse);
        }
        SearchContactsResponse::new(
            request,
            vec![self.contact.clone()],
            None,
            1024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsConnectTransportError::InvalidResponse)
    }

    fn describe_contact(
        &mut self,
        request: &DescribeContactRequest,
    ) -> std::result::Result<DescribeContactResponse, AwsConnectTransportError> {
        if request.contact_digest() != self.contact.contact().digest() {
            return Err(AwsConnectTransportError::NotFound);
        }
        DescribeContactResponse::new(
            request,
            self.contact.clone(),
            1024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsConnectTransportError::InvalidResponse)
    }

    fn get_contact_attributes(
        &mut self,
        request: &GetContactAttributesRequest,
    ) -> std::result::Result<GetContactAttributesResponse, AwsConnectTransportError> {
        if request.contact() != self.contact.contact() {
            return Err(AwsConnectTransportError::NotFound);
        }
        Self::response_attributes(request).map_err(|_| AwsConnectTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    scope_digest: Digest,
    contact: ContactRecord,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsConnectContactScope, _observed_at: DateTime<Utc>) -> Self {
        let initiation = scope.time_window().start() + Duration::minutes(30);
        let connected = initiation + Duration::minutes(1);
        let ended = connected + Duration::minutes(4);
        let lifecycle = ContactLifecycle::new(
            initiation,
            Some(connected),
            ended,
            Some(ended),
            ContactState::Ended,
            InitiationMethod::Callback,
            Some(crate::model::DisconnectReasonClass::ContactFlowEnd),
        )
        .expect("loopback lifecycle");
        Self {
            scope_digest: scope.digest(),
            contact: ContactRecord::for_scope(scope, lifecycle).expect("loopback contact"),
        }
    }
}

impl AwsConnectTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn search_contacts(
        &mut self,
        request: &SearchContactsRequest,
    ) -> std::result::Result<SearchContactsResponse, AwsConnectTransportError> {
        if request.scope_digest() != &self.scope_digest {
            return Err(AwsConnectTransportError::InvalidResponse);
        }
        SearchContactsResponse::new(
            request,
            vec![self.contact.clone()],
            None,
            1024,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsConnectTransportError::InvalidResponse)
    }

    fn describe_contact(
        &mut self,
        request: &DescribeContactRequest,
    ) -> std::result::Result<DescribeContactResponse, AwsConnectTransportError> {
        DescribeContactResponse::new(
            request,
            self.contact.clone(),
            1024,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsConnectTransportError::InvalidResponse)
    }

    fn get_contact_attributes(
        &mut self,
        request: &GetContactAttributesRequest,
    ) -> std::result::Result<GetContactAttributesResponse, AwsConnectTransportError> {
        let values = request
            .key_classes()
            .iter()
            .map(|key_class| AttributeValueInput::from_raw(*key_class, "loopback-redacted-value"))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| AwsConnectTransportError::InvalidResponse)?;
        GetContactAttributesResponse::new(request, values, 768, TransportProvenance::Loopback)
            .map_err(|_| AwsConnectTransportError::InvalidResponse)
    }
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    search_responses:
        VecDeque<std::result::Result<SearchContactsResponse, AwsConnectTransportError>>,
    describe_responses:
        VecDeque<std::result::Result<DescribeContactResponse, AwsConnectTransportError>>,
    attribute_responses:
        VecDeque<std::result::Result<GetContactAttributesResponse, AwsConnectTransportError>>,
}

impl RecordingTransport {
    pub fn push_search_response(
        &mut self,
        response: std::result::Result<SearchContactsResponse, AwsConnectTransportError>,
    ) {
        self.search_responses.push_back(response);
    }

    pub fn push_describe_response(
        &mut self,
        response: std::result::Result<DescribeContactResponse, AwsConnectTransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn push_attribute_response(
        &mut self,
        response: std::result::Result<GetContactAttributesResponse, AwsConnectTransportError>,
    ) {
        self.attribute_responses.push_back(response);
    }
}

impl AwsConnectTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn search_contacts(
        &mut self,
        _request: &SearchContactsRequest,
    ) -> std::result::Result<SearchContactsResponse, AwsConnectTransportError> {
        self.search_responses
            .pop_front()
            .unwrap_or(Err(AwsConnectTransportError::BlockedEnv))
    }

    fn describe_contact(
        &mut self,
        _request: &DescribeContactRequest,
    ) -> std::result::Result<DescribeContactResponse, AwsConnectTransportError> {
        self.describe_responses
            .pop_front()
            .unwrap_or(Err(AwsConnectTransportError::BlockedEnv))
    }

    fn get_contact_attributes(
        &mut self,
        _request: &GetContactAttributesRequest,
    ) -> std::result::Result<GetContactAttributesResponse, AwsConnectTransportError> {
        self.attribute_responses
            .pop_front()
            .unwrap_or(Err(AwsConnectTransportError::BlockedEnv))
    }
}
