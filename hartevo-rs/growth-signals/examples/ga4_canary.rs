use std::process::ExitCode;

use chrono::Utc;
use hartevo_connector_sdk::DispatchBudget;
use hartevo_growth_signals::{
    Ga4EnvConfig, Ga4EnvError, Ga4HttpTransport, Ga4ReplayLedger, Ga4SearchAnalyticsService,
};

fn main() -> ExitCode {
    let config = match Ga4EnvConfig::from_env() {
        Ok(config) => config,
        Err(Ga4EnvError::BlockedEnv(missing)) => {
            eprintln!("BLOCKED_ENV: missing {missing:?}");
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("GA4 canary configuration failed: {error}");
            return ExitCode::from(1);
        }
    };
    let scope = match config.scope() {
        Ok(scope) => scope,
        Err(error) => {
            eprintln!("GA4 scope failed: {error}");
            return ExitCode::from(1);
        }
    };
    let request = match config.request(scope.clone()) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("GA4 request failed: {error}");
            return ExitCode::from(1);
        }
    };
    let secret = match config.secret_reference(scope.clone()) {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("GA4 secret reference failed: {error}");
            return ExitCode::from(1);
        }
    };
    let credentials = match config.credentials() {
        Ok(credentials) => credentials,
        Err(error) => {
            eprintln!("GA4 credentials failed: {error}");
            return ExitCode::from(1);
        }
    };
    let now = Utc::now();
    let transport = match Ga4HttpTransport::production(credentials, &config.policy()) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("GA4 transport failed: {error}");
            return ExitCode::from(1);
        }
    };
    let mut service = match Ga4SearchAnalyticsService::new(
        secret,
        request,
        transport,
        config.policy(),
        now,
        Ga4ReplayLedger::default(),
    ) {
        Ok(service) => service,
        Err(error) => {
            eprintln!("GA4 service failed: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = service.mount(now) {
        eprintln!("GA4 authenticated property probe failed: {error}");
        return ExitCode::from(1);
    }
    let budget = match DispatchBudget::new(100, now + chrono::Duration::minutes(1), 100, 0) {
        Ok(budget) => budget,
        Err(error) => {
            eprintln!("GA4 dispatch budget failed: {error}");
            return ExitCode::from(1);
        }
    };
    match service.read(None, now, budget) {
        Ok(signal) => {
            println!(
                "provider={} property={} page_sequence={} items={} classification={:?} raw_evidence_digest={} provider_request_id={}",
                signal.receipt().provider().provider_id(),
                signal.property_id(),
                signal.page_sequence(),
                signal.item_count(),
                signal.classification(),
                signal.raw_evidence_digest(),
                signal.receipt().provider_request_id()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("GA4 read failed: {error}");
            ExitCode::from(1)
        }
    }
}
