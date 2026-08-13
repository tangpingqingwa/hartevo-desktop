mod driver;

use std::env;
use std::process;

use anyhow::{Context, Result, bail};
use driver::{NativeProbeOutcome, RuntimeDispatchReport, run_fake_dispatch, run_native_probe};
use serde_json::json;

fn main() {
    let exit_code = match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema": "hartevo.runtime-dispatch-report/v1",
                    "status": "FAIL",
                    "errorCode": "RUNTIME_DISPATCH_FAILED",
                    "error": error.to_string(),
                    "nativeProbe": false,
                    "effectAuthority": false,
                    "outcomeAuthority": false,
                }))
                .expect("static failure report must serialize")
            );
            1
        }
    };
    process::exit(exit_code);
}

fn run() -> Result<i32> {
    let command = env::args().nth(1).unwrap_or_else(|| "fake".to_owned());
    match command.as_str() {
        "fake" => {
            let workspace = env::current_dir()
                .context("read fake eval workspace")?
                .canonicalize()
                .context("canonicalize fake eval workspace")?;
            let report = run_fake_dispatch(&workspace)?;
            print_report(&report)?;
            Ok(0)
        }
        "native-probe" => match run_native_probe()? {
            NativeProbeOutcome::BlockedEnvironment { missing_env } => {
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schema": "hartevo.runtime-dispatch-report/v1",
                        "status": "BLOCKED_ENV",
                        "errorCode": "NATIVE_PROBE_ENVIRONMENT_UNAVAILABLE",
                        "missingEnv": missing_env,
                        "nativeProbe": true,
                        "runtimeStarted": false,
                        "effectAuthority": false,
                        "outcomeAuthority": false,
                    }))?
                );
                Ok(2)
            }
            NativeProbeOutcome::Ready(report) => {
                let exit_code = i32::from(report.status != "PASS");
                print_report(&report)?;
                Ok(exit_code)
            }
        },
        "--help" | "-h" => {
            println!("hartevo-runtime-dispatch [fake | native-probe]");
            println!("fake runs the deterministic stream/interrupt/restart contract.");
            println!("native-probe requires a pinned binary, isolated home, and credential.");
            Ok(0)
        }
        _ => bail!("unsupported command; use fake, native-probe, or --help"),
    }
}

fn print_report(report: &RuntimeDispatchReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}
