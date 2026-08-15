use std::fmt;

use crate::error::CodaTransportError;
use crate::model::{CodaReadRequest, CodaResponse, CodaTransportProvenance};

/// Layer-1 transport seam. It accepts only bounded fixture-like responses;
/// the crate supplies no native HTTPS implementation.
pub trait CodaTransport: fmt::Debug {
    fn provenance(&self) -> CodaTransportProvenance;

    fn execute(&mut self, request: &CodaReadRequest) -> Result<CodaResponse, CodaTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureCodaTransport {
    response: CodaResponse,
}

impl FixtureCodaTransport {
    #[must_use]
    pub fn new(response: CodaResponse) -> Self {
        Self { response }
    }

    #[must_use]
    pub fn response(&self) -> &CodaResponse {
        &self.response
    }

    pub fn set_response(&mut self, response: CodaResponse) {
        self.response = response;
    }
}

impl CodaTransport for FixtureCodaTransport {
    fn provenance(&self) -> CodaTransportProvenance {
        CodaTransportProvenance::Fixture
    }

    fn execute(&mut self, _request: &CodaReadRequest) -> Result<CodaResponse, CodaTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingCodaTransport {
    response: CodaResponse,
    requests: Vec<CodaReadRequest>,
    failure: Option<CodaTransportError>,
}

impl RecordingCodaTransport {
    #[must_use]
    pub fn new(response: CodaResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
            failure: None,
        }
    }

    #[must_use]
    pub fn with_failure(mut self, failure: CodaTransportError) -> Self {
        self.failure = Some(failure);
        self
    }

    pub fn set_failure(&mut self, failure: Option<CodaTransportError>) {
        self.failure = failure;
    }

    pub fn set_response(&mut self, response: CodaResponse) {
        self.response = response;
    }

    #[must_use]
    pub fn requests(&self) -> &[CodaReadRequest] {
        &self.requests
    }

    #[must_use]
    pub fn response(&self) -> &CodaResponse {
        &self.response
    }
}

impl CodaTransport for RecordingCodaTransport {
    fn provenance(&self) -> CodaTransportProvenance {
        CodaTransportProvenance::Recording
    }

    fn execute(&mut self, request: &CodaReadRequest) -> Result<CodaResponse, CodaTransportError> {
        self.requests.push(request.clone());
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        Ok(self.response.clone())
    }
}

/// A fake transport is intentionally separate from the fixture type so test
/// callers can state their provenance explicitly without implying native I/O.
#[derive(Clone, Debug)]
pub struct FakeCodaTransport {
    response: CodaResponse,
}

impl FakeCodaTransport {
    #[must_use]
    pub fn new(response: CodaResponse) -> Self {
        Self { response }
    }
}

impl CodaTransport for FakeCodaTransport {
    fn provenance(&self) -> CodaTransportProvenance {
        CodaTransportProvenance::Fake
    }

    fn execute(&mut self, _request: &CodaReadRequest) -> Result<CodaResponse, CodaTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackCodaTransport {
    response: CodaResponse,
}

impl LoopbackCodaTransport {
    #[must_use]
    pub fn new(response: CodaResponse) -> Self {
        Self { response }
    }
}

impl CodaTransport for LoopbackCodaTransport {
    fn provenance(&self) -> CodaTransportProvenance {
        CodaTransportProvenance::Loopback
    }

    fn execute(&mut self, _request: &CodaReadRequest) -> Result<CodaResponse, CodaTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvCodaTransport;

impl BlockedEnvCodaTransport {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CodaTransport for BlockedEnvCodaTransport {
    fn provenance(&self) -> CodaTransportProvenance {
        CodaTransportProvenance::BlockedEnv
    }

    fn execute(&mut self, _request: &CodaReadRequest) -> Result<CodaResponse, CodaTransportError> {
        Err(CodaTransportError::BlockedEnv)
    }
}

pub type CodaFixtureTransport = FixtureCodaTransport;
pub type CodaRecordingTransport = RecordingCodaTransport;
pub type CodaFakeTransport = FakeCodaTransport;
pub type CodaLoopbackTransport = LoopbackCodaTransport;
