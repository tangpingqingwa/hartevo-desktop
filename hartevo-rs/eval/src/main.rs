use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use hartevo_eval::{
    VERTICAL_SLICE_ID, catalog_snapshot, run_vertical_slice, wave_zero_release_evidence,
};
use serde::Serialize;

fn main() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [command] if command == "validate-assets" => {
            let snapshot = catalog_snapshot()?;
            let report = run_vertical_slice()?;
            if !report.passed {
                bail!("{VERTICAL_SLICE_ID} failed asset validation");
            }
            println!(
                "{}: {} Missions, {}/{} Application handlers implemented ({} NOT_IMPLEMENTED), {} dataset cases and {} cross-cutting cases valid; {VERTICAL_SLICE_ID} bootstrap replay valid",
                snapshot.schema_version,
                snapshot.summary.mission_count,
                snapshot.summary.implemented_application_handler_count,
                snapshot.summary.application_route_count,
                snapshot.summary.not_implemented_application_route_count,
                snapshot.summary.dataset_case_count,
                snapshot.summary.cross_cutting_case_count
            );
        }
        [catalog, command] if catalog == "catalog" && command == "validate" => {
            let snapshot = catalog_snapshot()?;
            println!(
                "{} {}: {} Missions, {} capabilities, {} providers, {}/{} Application handlers implemented ({} NOT_IMPLEMENTED), {} dataset cases, {} cross-cutting cases",
                snapshot.schema_version,
                snapshot.digest,
                snapshot.summary.mission_count,
                snapshot.summary.capability_count,
                snapshot.summary.provider_count,
                snapshot.summary.implemented_application_handler_count,
                snapshot.summary.application_route_count,
                snapshot.summary.not_implemented_application_route_count,
                snapshot.summary.dataset_case_count,
                snapshot.summary.cross_cutting_case_count
            );
        }
        [catalog, command, output_flag, output]
            if catalog == "catalog" && command == "export" && output_flag == "--output" =>
        {
            let snapshot = catalog_snapshot()?;
            write_json(&PathBuf::from(output), &snapshot)?;
        }
        [evidence, command, commit_flag, commit, output_flag, output]
            if evidence == "evidence"
                && command == "baseline"
                && commit_flag == "--commit"
                && output_flag == "--output" =>
        {
            let report = wave_zero_release_evidence(commit, Utc::now())?;
            write_json(&PathBuf::from(output), &report)?;
        }
        [command, mission_flag, mission] if command == "run" && mission_flag == "--mission" => {
            run(mission, None)?;
        }
        [command, mission_flag, mission, output_flag, output]
            if command == "run" && mission_flag == "--mission" && output_flag == "--output" =>
        {
            run(mission, Some(PathBuf::from(output)))?;
        }
        [flag] if flag == "--help" || flag == "-h" => print_help(),
        _ => {
            print_help();
            bail!("invalid eval command");
        }
    }
    Ok(())
}

fn run(mission: &str, output: Option<PathBuf>) -> Result<()> {
    if mission != VERTICAL_SLICE_ID {
        bail!("unknown Mission fixture {mission}; available: {VERTICAL_SLICE_ID}");
    }
    let report = run_vertical_slice()?;
    if let Some(output) = output {
        write_json(&output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    if !report.passed {
        bail!("{VERTICAL_SLICE_ID} failed");
    }
    Ok(())
}

fn write_json(path: &PathBuf, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create report directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, format!("{json}\n"))
        .with_context(|| format!("write report {}", path.display()))?;
    println!("{}", path.display());
    Ok(())
}

fn print_help() {
    println!(
        "Hartevo Mission Eval\n\n\
         Usage:\n  \
         hartevo-eval validate-assets\n  \
         hartevo-eval catalog validate\n  \
         hartevo-eval catalog export --output <path>\n  \
         hartevo-eval evidence baseline --commit <sha> --output <path>\n  \
         hartevo-eval run --mission VS-01 [--output <path>]"
    );
}
