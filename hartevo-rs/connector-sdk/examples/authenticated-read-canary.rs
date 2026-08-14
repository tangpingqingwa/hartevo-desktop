use std::process::ExitCode;

use chrono::Utc;
use hartevo_connector_sdk::{
    LiveCanaryError, NativeReadRunner, ReadCanaryStatus, SecretResolutionError,
};

fn main() -> ExitCode {
    let result = NativeReadRunner::from_environment(Utc::now()).and_then(|runner| runner.run());
    match result {
        Ok(report) => {
            match serde_json::to_string(report.evidence()) {
                Ok(envelope) => println!("{envelope}"),
                Err(_) => return ExitCode::from(1),
            }
            if report.status() == ReadCanaryStatus::Connected {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(LiveCanaryError::BlockedEnv(missing)) => {
            eprintln!("BLOCKED_ENV: {missing}");
            ExitCode::from(2)
        }
        Err(LiveCanaryError::SecretResolution(SecretResolutionError::BlockedEnv { variable })) => {
            eprintln!("BLOCKED_ENV: {variable}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("CONNECTOR_CANARY_ERROR: {error}");
            ExitCode::from(1)
        }
    }
}
