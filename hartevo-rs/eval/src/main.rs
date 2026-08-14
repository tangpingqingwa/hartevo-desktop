use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use hartevo_eval::{
    DistributionVerificationPaths, HarnessEvaluationInput, HarnessLabPlan, HarnessPromotionKey,
    HarnessSignedPromotionRecord, VERTICAL_SLICE_ID, catalog_snapshot, evaluate_harness_lab,
    export_public_key, finalize_evaluation_run, generate_keypair, harness_lab_source_commit,
    run_vertical_slice, sign_file, validate_evaluation_run, validate_gate, verify_distribution,
    verify_file, wave_zero_release_evidence,
};
use serde::{Deserialize, Serialize};

fn main() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|command| command == "harness-lab")
    {
        return run_harness_command(&arguments);
    }
    run_standard_command(&arguments)
}

fn run_standard_command(arguments: &[String]) -> Result<()> {
    match arguments {
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
        [evaluation_run, command, root_flag, root]
            if evaluation_run == "evaluation-run"
                && command == "finalize"
                && root_flag == "--run-dir" =>
        {
            let receipt = finalize_evaluation_run(root)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        [evaluation_run, command, root_flag, root]
            if evaluation_run == "evaluation-run"
                && command == "validate"
                && root_flag == "--run-dir" =>
        {
            let receipt = validate_evaluation_run(root)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        [distribution, ..] if distribution == "distribution" => run_distribution(arguments)?,
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

fn run_harness_command(arguments: &[String]) -> Result<()> {
    ensure!(
        arguments.len() >= 6
            && arguments[0] == "harness-lab"
            && arguments[1] == "validate"
            && arguments[2] == "--plan"
            && arguments[4] == "--results",
        "invalid Harness Lab command"
    );
    let plan_path = &arguments[3];
    let results_path = &arguments[5];
    let mut keys_path = None;
    let mut promotion_path = None;
    let mut index = 6;
    while index < arguments.len() {
        ensure!(
            index + 1 < arguments.len(),
            "Harness Lab option has no value"
        );
        match arguments[index].as_str() {
            "--keys" => {
                ensure!(keys_path.is_none(), "duplicate Harness Lab --keys option");
                keys_path = Some(arguments[index + 1].as_str());
            }
            "--promotion" => {
                ensure!(
                    promotion_path.is_none(),
                    "duplicate Harness Lab --promotion option"
                );
                promotion_path = Some(arguments[index + 1].as_str());
            }
            _ => bail!("unknown Harness Lab option {}", arguments[index]),
        }
        index += 2;
    }
    run_harness_lab_validation(plan_path, results_path, keys_path, promotion_path)
}

fn run_distribution(arguments: &[String]) -> Result<()> {
    if arguments.get(1).is_some_and(|command| command == "verify") {
        return run_distribution_verify(arguments);
    }
    match arguments {
        [distribution, validate, gate_flag, gate, commit_flag, commit]
            if distribution == "distribution"
                && validate == "validate"
                && gate_flag == "--gate"
                && commit_flag == "--commit" =>
        {
            validate_gate(gate, commit)?;
            println!(
                r#"{{"schema":"hartevo-distribution-gate-verification/v1","status":"PASS","releaseDecision":"NOT_EVALUATED","releasePassed":false,"releaseCommit":"{commit}"}}"#
            );
        }
        [
            distribution,
            crypto,
            operation,
            private_flag,
            private_path,
            public_flag,
            public_path,
        ] if distribution == "distribution"
            && crypto == "crypto"
            && operation == "keygen"
            && private_flag == "--private-key"
            && public_flag == "--public-key" =>
        {
            generate_keypair(private_path, public_path)?;
        }
        [
            distribution,
            crypto,
            operation,
            private_flag,
            private_path,
            public_flag,
            public_path,
        ] if distribution == "distribution"
            && crypto == "crypto"
            && operation == "public-key"
            && private_flag == "--private-key"
            && public_flag == "--public-key" =>
        {
            export_public_key(private_path, public_path)?;
        }
        [
            distribution,
            crypto,
            operation,
            private_flag,
            private_path,
            input_flag,
            input_path,
            output_flag,
            output_path,
        ] if distribution == "distribution"
            && crypto == "crypto"
            && operation == "sign"
            && private_flag == "--private-key"
            && input_flag == "--input"
            && output_flag == "--output" =>
        {
            sign_file(private_path, input_path, output_path)?;
        }
        [
            distribution,
            crypto,
            operation,
            public_flag,
            public_path,
            input_flag,
            input_path,
            signature_flag,
            signature_path,
        ] if distribution == "distribution"
            && crypto == "crypto"
            && operation == "verify"
            && public_flag == "--public-key"
            && input_flag == "--input"
            && signature_flag == "--signature" =>
        {
            verify_file(public_path, input_path, signature_path)?;
        }
        _ => {
            print_help();
            bail!("invalid distribution command");
        }
    }
    Ok(())
}

fn run_distribution_verify(arguments: &[String]) -> Result<()> {
    ensure!(
        arguments.len() >= 2 && arguments[0] == "distribution" && arguments[1] == "verify",
        "invalid distribution verify command"
    );
    let mut root = None;
    let mut manifest = None;
    let mut cyclonedx = None;
    let mut spdx = None;
    let mut checksums = None;
    let mut provenance = None;
    let mut telemetry = None;
    let mut commit = None;
    let mut output = None;
    let mut index = 2;
    while index < arguments.len() {
        ensure!(
            index + 1 < arguments.len(),
            "distribution verify option has no value"
        );
        let value = arguments[index + 1].as_str();
        let slot = match arguments[index].as_str() {
            "--root" => &mut root,
            "--manifest" => &mut manifest,
            "--cyclonedx" => &mut cyclonedx,
            "--spdx" => &mut spdx,
            "--checksums" => &mut checksums,
            "--provenance" => &mut provenance,
            "--telemetry" => &mut telemetry,
            "--commit" => &mut commit,
            "--output" => &mut output,
            option => bail!("unknown distribution verify option {option}"),
        };
        ensure!(slot.is_none(), "duplicate distribution verify option");
        *slot = Some(value);
        index += 2;
    }
    let root = root.context("distribution verify requires --root")?;
    let manifest = manifest.context("distribution verify requires --manifest")?;
    let cyclonedx = cyclonedx.context("distribution verify requires --cyclonedx")?;
    let spdx = spdx.context("distribution verify requires --spdx")?;
    let checksums = checksums.context("distribution verify requires --checksums")?;
    let provenance = provenance.context("distribution verify requires --provenance")?;
    let telemetry = telemetry.context("distribution verify requires --telemetry")?;
    let commit = commit.context("distribution verify requires --commit")?;
    let receipt = verify_distribution(&DistributionVerificationPaths {
        root: PathBuf::from(root),
        manifest: PathBuf::from(manifest),
        cyclonedx: PathBuf::from(cyclonedx),
        spdx: PathBuf::from(spdx),
        checksums: PathBuf::from(checksums),
        provenance: PathBuf::from(provenance),
        telemetry: PathBuf::from(telemetry),
        expected_commit: commit.to_string(),
    })?;
    if let Some(output) = output {
        write_json(&PathBuf::from(output), &receipt)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
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
         hartevo-eval evaluation-run finalize --run-dir <path>\n  \
         hartevo-eval evaluation-run validate --run-dir <path>\n  \
         hartevo-eval harness-lab validate --plan <plan.json> --results <results.json> [--keys <keys.json>] [--promotion <record.json>]\n  \
         hartevo-eval distribution validate --gate <path> --commit <sha>\n  \
         hartevo-eval distribution verify --root <repo> --manifest <path> --cyclonedx <path> --spdx <path> --checksums <path> --provenance <path> --telemetry <path> --commit <sha> [--output <path>]\n  \
         hartevo-eval distribution crypto keygen --private-key <path> --public-key <path>\n  \
         hartevo-eval distribution crypto public-key --private-key <path> --public-key <path>\n  \
         hartevo-eval distribution crypto sign --private-key <path> --input <path> --output <path>\n  \
         hartevo-eval distribution crypto verify --public-key <path> --input <path> --signature <path>\n  \
         hartevo-eval run --mission VS-01 [--output <path>]"
    );
}

fn run_harness_lab_validation(
    plan_path: &str,
    results_path: &str,
    keys_path: Option<&str>,
    promotion_path: Option<&str>,
) -> Result<()> {
    let plan = read_json::<HarnessLabPlan>(plan_path)?;
    let results = read_json::<Vec<hartevo_eval::HarnessRunResult>>(results_path)?;
    let keys = keys_path
        .map(read_json::<Vec<HarnessPromotionKey>>)
        .transpose()?
        .unwrap_or_default();
    let promotion = promotion_path
        .map(read_json::<HarnessSignedPromotionRecord>)
        .transpose()?;
    let source_commit = harness_lab_source_commit()?;
    let input = HarnessEvaluationInput {
        plan: &plan,
        results: &results,
        signed_record: promotion.as_ref(),
        trusted_keys: &keys,
        expected_source_commit: &source_commit,
    };
    let report = evaluate_harness_lab(&input)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read JSON input {path}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON input {path}"))
}
