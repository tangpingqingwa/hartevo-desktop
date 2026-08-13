use std::process::ExitCode;

use hartevo_growth_signals::dataforseo_canary::{
    DataForSeoCanaryEnv, DataForSeoCanaryError, run_authenticated,
};

fn main() -> ExitCode {
    let environment = match DataForSeoCanaryEnv::from_env() {
        Ok(environment) => environment,
        Err(DataForSeoCanaryError::BlockedEnv { missing }) => {
            eprintln!("BLOCKED_ENV: missing {}", missing.join(", "));
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("CANARY_CONFIG_ERROR: {error}");
            return ExitCode::from(1);
        }
    };

    match run_authenticated(&environment) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("CANARY_REPORT_ERROR: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            eprintln!("CANARY_FAILED: {error}");
            ExitCode::from(1)
        }
    }
}
