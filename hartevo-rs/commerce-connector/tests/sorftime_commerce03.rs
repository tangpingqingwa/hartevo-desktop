use chrono::{DateTime, Utc};
use hartevo_commerce_connector::sorftime::{
    SORFTIME_ESTIMATE_EVIDENCE_LEVEL, SORFTIME_LIVE_VALIDATION_STATUS, SorftimeAccountId,
    SorftimeApiRequest, SorftimeAuthState, SorftimeAuthStatus, SorftimeBlockedEnvReason,
    SorftimeCredentialReference, SorftimeDataset, SorftimeError, SorftimeEvidenceAuthority,
    SorftimeMarket, SorftimeResponse, SorftimeTransport, SorftimeTransportError,
    query_estimate_api,
};
use hartevo_commerce_connector::{Asin, MarketId};
use hartevo_domain_kernel::CurrencyCode;
use serde_json::json;

struct FakeSorftimeTransport {
    response: SorftimeResponse,
}

impl SorftimeTransport for FakeSorftimeTransport {
    fn execute_api(
        &mut self,
        _request: SorftimeApiRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError> {
        Ok(self.response.clone())
    }

    fn execute_cli(
        &mut self,
        _request: hartevo_commerce_connector::sorftime::SorftimeCliRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError> {
        Ok(self.response.clone())
    }
}

fn fixture_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-13T00:00:00Z")
        .expect("fixture time")
        .with_timezone(&Utc)
}

fn request() -> SorftimeApiRequest {
    SorftimeApiRequest::new(
        "https://open.sorftime.com/api",
        SorftimeAccountId::parse("sorftime-fixture-account").expect("account"),
        SorftimeMarket::new(
            MarketId::parse("ATVPDKIKX0DER").expect("market"),
            "en-US",
            CurrencyCode::parse("USD").expect("currency"),
        )
        .expect("market"),
        SorftimeDataset::ProductTrend,
        "sorftime-commerce03-request",
        json!({"asin":"B0C0MERC01"}),
    )
    .expect("request")
}

#[test]
fn auth_state_is_disconnected_or_blocked_without_claiming_connected_access() {
    let observed_at = fixture_time();
    let disconnected = SorftimeAuthState::disconnected(observed_at);
    assert_eq!(disconnected.status(), SorftimeAuthStatus::Disconnected);
    assert!(!disconnected.can_issue_live_read());
    assert!(!disconnected.grants_connected_authority());

    let blocked = SorftimeAuthState::no_credentials(observed_at);
    assert_eq!(blocked.status(), SorftimeAuthStatus::BlockedEnv);
    assert!(matches!(
        blocked,
        SorftimeAuthState::BlockedEnv {
            reason: SorftimeBlockedEnvReason::CredentialsUnavailable,
            ..
        }
    ));
    assert_eq!(SORFTIME_LIVE_VALIDATION_STATUS, "BLOCKED_ENV");

    let credential = SorftimeCredentialReference::parse("keychain://sorftime/commerce03")
        .expect("opaque reference");
    let reference_only = SorftimeAuthState::credential_reference_only(observed_at, credential);
    assert_eq!(
        reference_only.status(),
        SorftimeAuthStatus::CredentialReferenceOnly
    );
    assert_eq!(
        reference_only.credential().expect("reference").as_str(),
        "keychain://sorftime/commerce03"
    );
    assert!(!reference_only.can_issue_live_read());
    assert!(!reference_only.grants_connected_authority());
}

#[test]
fn estimate_response_binds_digest_and_stays_estimate_only() {
    let response = SorftimeResponse {
        status: 200,
        request_id: "sorftime-response-03".into(),
        body: json!({
            "asin":"B0C0MERC01",
            "estimatedUnits":420,
            "estimatedRevenueMinor":42000,
            "currency":"USD"
        }),
        cost_units: 3,
        cost_currency: None,
        cost_source: "fixture-price-list/v1".into(),
    };
    let mut transport = FakeSorftimeTransport { response };
    let estimate =
        query_estimate_api(&mut transport, request(), fixture_time()).expect("estimate response");

    assert_eq!(
        estimate.provenance.authority,
        SorftimeEvidenceAuthority::EstimateOnly
    );
    assert_eq!(
        estimate.provenance.evidence_level,
        SORFTIME_ESTIMATE_EVIDENCE_LEVEL
    );
    assert!(estimate.provenance.is_estimate_only());
    assert_eq!(estimate.response_digest.len(), 64);
    assert!(
        estimate
            .response_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert_eq!(
        estimate.target_asin,
        Some(Asin::parse("B0C0MERC01").expect("ASIN"))
    );
    assert!(!estimate.grants_first_party_authority());
}

#[test]
fn response_metadata_and_provider_provenance_fail_closed() {
    let response = SorftimeResponse {
        status: 200,
        request_id: String::new(),
        body: json!({"asin":"B0C0MERC01"}),
        cost_units: 1,
        cost_currency: None,
        cost_source: "fixture-price-list/v1".into(),
    };
    let mut transport = FakeSorftimeTransport { response };
    assert!(matches!(
        query_estimate_api(&mut transport, request(), fixture_time()),
        Err(SorftimeError::InvalidToken { .. })
    ));
}
