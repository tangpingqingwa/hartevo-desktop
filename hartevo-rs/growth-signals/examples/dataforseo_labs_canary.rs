use std::process::ExitCode;

use chrono::Utc;
use hartevo_connector_sdk::DispatchBudget;
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    DataForSeoEnvConfig, DataForSeoEnvError, DataForSeoHttpTransport, DataForSeoLabsService,
    DataForSeoMissionConsumer, DataForSeoReplayLedger,
};
use serde_json::json;

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(DataForSeoEnvError::BlockedEnv(missing)) => {
            eprintln!("BLOCKED_ENV missing={missing:?}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("DataForSEO canary failed closed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, DataForSeoEnvError> {
    let config = DataForSeoEnvConfig::from_env()?;
    let scope = config.scope()?;
    let tenant_id = TenantId::from(scope.tenant_id());
    let project_id = ProjectId::from(scope.project_id());
    let account_id = scope.account_id().to_owned();
    let request = config.request(scope.clone())?;
    let secret = config.secret_reference(scope)?;
    let policy = config.policy();
    let transport = DataForSeoHttpTransport::production(config.credentials()?, &policy)?;
    let now = Utc::now();
    let mut service = DataForSeoLabsService::new(
        secret,
        request,
        transport,
        policy,
        now,
        DataForSeoReplayLedger::default(),
    )?;
    service.mount(now)?;
    let signal = service.read(
        None,
        now,
        DispatchBudget::new(1_000, now + chrono::Duration::minutes(1), 1, 1_000_000)
            .map_err(|_| DataForSeoEnvError::Invalid)?,
    )?;
    let mission = DataForSeoMissionConsumer::new(
        MissionId::from("mission-dataforseo-canary"),
        tenant_id,
        project_id,
        account_id,
    )
    .map_err(|_| DataForSeoEnvError::Invalid)?
    .consume(&signal)
    .map_err(|_| DataForSeoEnvError::Invalid)?;
    serde_json::to_string_pretty(&json!({
        "signal": signal,
        "mission": mission,
    }))
    .map_err(|_| DataForSeoEnvError::Invalid)
}
