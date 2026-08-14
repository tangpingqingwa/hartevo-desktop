use std::process::ExitCode;

use chrono::Utc;
use hartevo_connector_sdk::DispatchBudget;
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    GoogleAdsEnvConfig, GoogleAdsEnvError, GoogleAdsHttpTransport, GoogleAdsMissionConsumer,
    GoogleAdsReplayLedger, GoogleAdsService,
};
use serde_json::json;

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(GoogleAdsEnvError::BlockedEnv(missing)) => {
            eprintln!("BLOCKED_ENV missing={missing:?}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("Google Ads canary failed closed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, GoogleAdsEnvError> {
    let config = GoogleAdsEnvConfig::from_env()?;
    let scope = config.scope()?;
    let tenant_id = TenantId::from(scope.tenant_id());
    let project_id = ProjectId::from(scope.project_id());
    let account_id = scope.account_id().to_owned();
    let request = config.request(scope.clone())?;
    let secret = config.secret_reference(scope)?;
    let policy = config.policy();
    let transport = GoogleAdsHttpTransport::production(
        config.credentials()?,
        request.login_customer_id(),
        &policy,
    )?;
    let now = Utc::now();
    let mut service = GoogleAdsService::new(
        secret,
        request,
        transport,
        policy,
        now,
        GoogleAdsReplayLedger::default(),
    )?;
    service.mount(now)?;
    let signal = service.read(
        None,
        now,
        DispatchBudget::new(
            100,
            now + chrono::Duration::minutes(1),
            service.request().max_quota_units(),
            0,
        )
        .map_err(|_| GoogleAdsEnvError::Invalid)?,
    )?;
    let mission = GoogleAdsMissionConsumer::new(
        MissionId::from("mission-google-ads-canary"),
        tenant_id,
        project_id,
        account_id,
    )
    .map_err(|_| GoogleAdsEnvError::Invalid)?
    .consume(&signal)
    .map_err(|_| GoogleAdsEnvError::Invalid)?;
    serde_json::to_string_pretty(&json!({
        "signal": signal,
        "mission": mission,
    }))
    .map_err(|_| GoogleAdsEnvError::Invalid)
}
