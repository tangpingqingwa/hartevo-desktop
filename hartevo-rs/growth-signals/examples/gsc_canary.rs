use std::process::ExitCode;

use chrono::Utc;
use hartevo_connector_sdk::DispatchBudget;
use hartevo_growth_signals::{
    GscEnvConfig, GscEnvError, GscHttpTransport, GscReplayLedger, GscSearchAnalyticsService,
};

fn main() -> ExitCode {
    let config = match GscEnvConfig::from_env() {
        Ok(config) => config,
        Err(GscEnvError::BlockedEnv(missing)) => {
            eprintln!("BLOCKED_ENV: missing {missing:?}");
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("GSC canary configuration failed: {error}");
            return ExitCode::from(1);
        }
    };
    let scope = match config.scope() {
        Ok(scope) => scope,
        Err(error) => {
            eprintln!("GSC scope failed: {error}");
            return ExitCode::from(1);
        }
    };
    let request = match config.request(scope.clone()) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("GSC request failed: {error}");
            return ExitCode::from(1);
        }
    };
    let secret = match config.secret_reference(scope.clone()) {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("GSC secret reference failed: {error}");
            return ExitCode::from(1);
        }
    };
    let credentials = match config.credentials() {
        Ok(credentials) => credentials,
        Err(error) => {
            eprintln!("GSC credentials failed: {error}");
            return ExitCode::from(1);
        }
    };
    let now = Utc::now();
    let transport = match GscHttpTransport::production(credentials, &config.policy()) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("GSC transport failed: {error}");
            return ExitCode::from(1);
        }
    };
    let mut service = match GscSearchAnalyticsService::new(
        secret,
        request,
        transport,
        config.policy(),
        now,
        GscReplayLedger::default(),
    ) {
        Ok(service) => service,
        Err(error) => {
            eprintln!("GSC service failed: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = service.mount(now) {
        eprintln!("GSC authenticated probe failed: {error}");
        return ExitCode::from(1);
    }
    let budget = match DispatchBudget::new(100, now + chrono::Duration::minutes(1), 100, 0) {
        Ok(budget) => budget,
        Err(error) => {
            eprintln!("GSC dispatch budget failed: {error}");
            return ExitCode::from(1);
        }
    };
    match service.read(None, now, budget) {
        Ok(signal) => {
            println!(
                "provider={} property={} page_sequence={} items={} classification={:?} raw_evidence_digest={} provider_request_id={}",
                signal.receipt().provider().provider_id(),
                signal.property(),
                signal.page_sequence(),
                signal.item_count(),
                signal.classification(),
                signal.raw_evidence_digest(),
                signal.receipt().provider_request_id()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("GSC read failed: {error}");
            ExitCode::from(1)
        }
    }
}
