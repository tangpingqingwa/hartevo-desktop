mod digest;
mod model;
mod verifier;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;

use crate::verifier::{
    DistributionReport, MetadataInput, POLICY_PATH, POLICY_SCHEMA_PATH, RELEASE_DECISION,
    VALIDATION_SCHEMA_VERSION, verify,
};

fn main() {
    if let Err(error) = run() {
        let failure = json!({
            "schemaVersion": VALIDATION_SCHEMA_VERSION,
            "releaseDecision": RELEASE_DECISION,
            "status": "CODE_FAILURE",
            "release": false,
            "deployment": false,
            "writesPerformed": false,
            "errorCode": "DISTRIBUTION_ADVISORY_CONTRACT_FAILED",
            "error": error.to_string(),
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&failure)
                .expect("static distribution validator failure must serialize")
        );
        eprintln!("Distribution advisory contract error: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.is_empty()
        || arguments
            .first()
            .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        print_help();
        return Ok(());
    }
    ensure!(
        arguments.first().is_some_and(|arg| arg == "verify"),
        "unsupported distribution contract command; use verify or --help"
    );
    let options = parse_options(&arguments[1..])?;
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let policy_path = options
        .policy
        .unwrap_or_else(|| repository_root.join(POLICY_PATH));
    let schema_path = options
        .schema
        .unwrap_or_else(|| repository_root.join(POLICY_SCHEMA_PATH));
    let lock_path = options.lock.context("verify requires --lock PATH")?;
    let audit_path = options.audit.context("verify requires --audit PATH")?;
    let source_commit = options
        .source_commit
        .context("verify requires --source-commit GIT_SHA")?;
    let evaluated_at = options
        .evaluated_at
        .context("verify requires --as-of RFC3339")?;
    ensure!(
        !options.metadata.is_empty(),
        "verify requires one or more --metadata TARGET_ID=PATH arguments"
    );
    let report = verify(
        &read_path(&policy_path, "dependency advisory policy")?,
        &read_path(&schema_path, "dependency advisory policy schema")?,
        &read_path(&lock_path, "Cargo.lock")?,
        &read_path(&audit_path, "cargo-audit receipt")?,
        &source_commit,
        &evaluated_at,
        options.expected_lock_digest.as_deref(),
        &options
            .metadata
            .iter()
            .map(|(target_id, path)| {
                Ok(MetadataInput {
                    target_id: target_id.clone(),
                    bytes: read_path(path, "target cargo metadata")?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    )?;
    write_report(&report, options.output.as_deref())?;
    if report.status == "CODE_FAILURE" {
        std::process::exit(2);
    }
    Ok(())
}

#[derive(Default)]
struct Options {
    policy: Option<PathBuf>,
    schema: Option<PathBuf>,
    lock: Option<PathBuf>,
    audit: Option<PathBuf>,
    source_commit: Option<String>,
    evaluated_at: Option<String>,
    expected_lock_digest: Option<String>,
    output: Option<PathBuf>,
    metadata: Vec<(String, PathBuf)>,
}

fn parse_options(arguments: &[std::ffi::OsString]) -> Result<Options> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .with_context(|| format!("argument #{} is not valid UTF-8", index + 1))?;
        let (value, consumed) = match flag {
            "--policy" => (Some("policy"), true),
            "--schema" => (Some("schema"), true),
            "--lock" => (Some("lock"), true),
            "--audit" => (Some("audit"), true),
            "--source-commit" => (Some("source-commit"), true),
            "--as-of" => (Some("as-of"), true),
            "--expected-lock-digest" => (Some("expected-lock-digest"), true),
            "--output" => (Some("output"), true),
            "--metadata" => (Some("metadata"), true),
            other => bail!("unknown option {other}"),
        };
        ensure!(
            consumed && index + 1 < arguments.len(),
            "option {flag} requires a value"
        );
        let raw_value = arguments[index + 1]
            .to_str()
            .with_context(|| format!("value for {flag} is not valid UTF-8"))?;
        match value.expect("all supported options have a value") {
            "policy" => options.policy = Some(PathBuf::from(raw_value)),
            "schema" => options.schema = Some(PathBuf::from(raw_value)),
            "lock" => options.lock = Some(PathBuf::from(raw_value)),
            "audit" => options.audit = Some(PathBuf::from(raw_value)),
            "source-commit" => options.source_commit = Some(raw_value.to_owned()),
            "as-of" => options.evaluated_at = Some(raw_value.to_owned()),
            "expected-lock-digest" => options.expected_lock_digest = Some(raw_value.to_owned()),
            "output" => options.output = Some(PathBuf::from(raw_value)),
            "metadata" => {
                let (target_id, path) = raw_value
                    .split_once('=')
                    .context("--metadata must be TARGET_ID=PATH")?;
                ensure!(
                    !target_id.is_empty() && !path.is_empty(),
                    "--metadata must contain non-empty TARGET_ID and PATH"
                );
                options
                    .metadata
                    .push((target_id.to_owned(), PathBuf::from(path)));
            }
            _ => unreachable!("option name is exhaustive"),
        }
        index += 2;
    }
    Ok(options)
}

fn read_path(path: &Path, label: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read {label} at {}", path.display()))
}

fn write_report(report: &DistributionReport, output: Option<&Path>) -> Result<()> {
    let serialized = serde_json::to_string_pretty(report)? + "\n";
    if let Some(output) = output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create report directory {}", parent.display()))?;
        }
        fs::write(output, serialized)
            .with_context(|| format!("write distribution report at {}", output.display()))?;
    } else {
        print!("{serialized}");
    }
    Ok(())
}

fn print_help() {
    println!(
        "Usage: cargo run -p hartevo-eval --example hartevo-distribution-contract -- verify \\\n  [--policy PATH] [--schema PATH] --lock PATH --audit PATH \\\n  --source-commit GIT_SHA --as-of RFC3339 \\\n  --metadata TARGET_ID=PATH [--metadata TARGET_ID=PATH ...] \\\n  [--expected-lock-digest SHA256] [--output PATH]"
    );
    println!("Verifies target-aware cargo-audit findings and emits deterministic records.");
    println!(
        "Release and deployment remain false; target-unreachable and CI-only findings are recorded as informational warnings."
    );
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn parser_keeps_repeated_metadata_inputs() {
        let arguments = vec![
            "--source-commit".into(),
            "a".repeat(40).into(),
            "--as-of".into(),
            "2026-08-14T00:00:00Z".into(),
            "--metadata".into(),
            "macos-aarch64=macos.json".into(),
            "--metadata".into(),
            "linux-x86_64-ci=linux.json".into(),
        ];
        let options = parse_options(&arguments).expect("options");
        assert_eq!(options.metadata.len(), 2);
    }
}
