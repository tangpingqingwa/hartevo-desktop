use std::{env, process::ExitCode};

use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    dataforseo_canary::{DataForSeoCanaryEnv, DataForSeoCanaryError},
    dataforseo_service::{
        DATAFORSEO_READ_CAPABILITY, DataForSeoConnectorService, DataForSeoMissionConsumer,
    },
};

fn main() -> ExitCode {
    let environment = match DataForSeoCanaryEnv::from_env() {
        Ok(environment) => environment,
        Err(DataForSeoCanaryError::BlockedEnv { missing }) => {
            eprintln!("BLOCKED_ENV: missing {}", missing.join(", "));
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("MISSION_CANARY_CONFIG_ERROR: {error}");
            return ExitCode::from(1);
        }
    };
    let mission_id = match env::var("DATAFORSEO_MISSION_ID") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!("BLOCKED_ENV: missing DATAFORSEO_MISSION_ID");
            return ExitCode::from(2);
        }
    };

    let provider = match environment.authenticated_read_provider() {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("MISSION_CANARY_FAILED: {error}");
            return ExitCode::from(1);
        }
    };
    let mut service = match DataForSeoConnectorService::new(provider) {
        Ok(service) => service,
        Err(error) => {
            eprintln!("MISSION_CANARY_SERVICE_ERROR: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = service.mount() {
        eprintln!("MISSION_CANARY_MOUNT_ERROR: {error}");
        return ExitCode::from(1);
    }
    let result = match service.read_result() {
        Ok(result) => result,
        Err(error) => {
            eprintln!("MISSION_CANARY_READ_ERROR: {error}");
            return ExitCode::from(1);
        }
    };
    let scope = result.connector_scope();
    let consumer = match DataForSeoMissionConsumer::new(
        MissionId::from_stable(mission_id),
        TenantId::from(scope.tenant_id()),
        ProjectId::from(scope.project_id()),
        scope.account_id(),
        DATAFORSEO_READ_CAPABILITY,
    ) {
        Ok(consumer) => consumer,
        Err(error) => {
            eprintln!("MISSION_CANARY_CONSUMER_ERROR: {error}");
            return ExitCode::from(1);
        }
    };
    match consumer.consume(&result) {
        Ok(output) => match serde_json::to_string_pretty(&output) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("MISSION_CANARY_OUTPUT_ERROR: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            eprintln!("MISSION_CANARY_CONSUME_ERROR: {error}");
            ExitCode::from(1)
        }
    }
}
