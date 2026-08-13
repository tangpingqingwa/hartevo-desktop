use std::{error::Error, io};

use chrono::{DateTime, Duration, Utc};
use hartevo_cloud_storage::{CellScope, CloudRemoteWorkerCompletion, DataCell, PostgresCellStore};
use hartevo_domain_kernel::{MissionId, ProjectId, TaskId, TenantId, WorkerId, WorkerLeaseId};
use tokio_postgres::NoTls;

type HarnessResult = Result<(), Box<dyn Error>>;

#[tokio::main]
async fn main() -> HarnessResult {
    let mode = std::env::args()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing harness mode"))?;
    match mode.as_str() {
        "claim" => claim().await,
        "complete" => complete().await,
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported harness mode {other}"),
        )
        .into()),
    }
}

async fn claim() -> HarnessResult {
    let (mut client, _connection_task) = connect().await?;
    let scope = scope()?;
    let project_id = ProjectId::from_stable(required("HARTEVO_CELL_PROJECT")?);
    let mission_id = MissionId::from_stable(required("HARTEVO_CELL_MISSION")?);
    let dispatch_registration_id = required("HARTEVO_CELL_DISPATCH_REGISTRATION")?;
    let worker_id = WorkerId::from_stable(required("HARTEVO_CELL_WORKER")?);
    let owner = required("HARTEVO_CELL_LEASE_OWNER")?;
    let token_digest = required("HARTEVO_CELL_LEASE_TOKEN_DIGEST")?;
    let claim_key = required("HARTEVO_CELL_CLAIM_KEY")?;
    let now = timestamp("HARTEVO_CELL_NOW")?;
    let lease_seconds = required("HARTEVO_CELL_LEASE_SECONDS")?.parse::<i64>()?;
    let store = PostgresCellStore::new(DataCell::Us);
    let result = store
        .claim_remote_worker_task(
            &mut client,
            &scope,
            &project_id,
            &mission_id,
            &dispatch_registration_id,
            &worker_id,
            &owner,
            &token_digest,
            &claim_key,
            now,
            Duration::seconds(lease_seconds),
        )
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no remote task available"))?;
    let lease = result.lease;
    println!(
        "CLAIM|{}|{}|{}|{}|{}|{}|{}|{}",
        result.duplicate,
        lease.task_id.as_str(),
        lease.lease_id.as_str(),
        lease.lease_generation,
        lease.lease_owner,
        lease.lease_token_digest,
        lease.heartbeat_at.to_rfc3339(),
        lease.lease_expires_at.to_rfc3339()
    );
    Ok(())
}

async fn complete() -> HarnessResult {
    let (mut client, _connection_task) = connect().await?;
    let scope = scope()?;
    let project_id = ProjectId::from_stable(required("HARTEVO_CELL_PROJECT")?);
    let mission_id = MissionId::from_stable(required("HARTEVO_CELL_MISSION")?);
    let task_id = TaskId::from_stable(required("HARTEVO_CELL_TASK")?);
    let dispatch_registration_id = required("HARTEVO_CELL_DISPATCH_REGISTRATION")?;
    let lease_id = WorkerLeaseId::from_stable(required("HARTEVO_CELL_LEASE_ID")?);
    let lease_generation = required("HARTEVO_CELL_LEASE_GENERATION")?.parse::<u64>()?;
    let lease_owner = required("HARTEVO_CELL_LEASE_OWNER")?;
    let lease_token_digest = required("HARTEVO_CELL_LEASE_TOKEN_DIGEST")?;
    let result_digest = required("HARTEVO_CELL_RESULT_DIGEST")?;
    let idempotency_key_digest = required("HARTEVO_CELL_COMPLETION_KEY")?;
    let completed_at = timestamp("HARTEVO_CELL_NOW")?;
    let store = PostgresCellStore::new(DataCell::Us);
    let result = store
        .complete_remote_worker_task(
            &mut client,
            &CloudRemoteWorkerCompletion {
                scope,
                project_id,
                mission_id,
                task_id,
                dispatch_registration_id,
                lease_id,
                lease_generation,
                lease_owner,
                lease_token_digest,
                result_digest,
                idempotency_key_digest,
                completed_at,
            },
        )
        .await?;
    println!("COMPLETE|{}|{}", result.task_id.as_str(), result.duplicate);
    Ok(())
}

async fn connect() -> Result<(tokio_postgres::Client, tokio::task::JoinHandle<()>), Box<dyn Error>>
{
    let url = required("HARTEVO_TEST_POSTGRES_URL")?;
    let (client, connection) = tokio_postgres::connect(&url, NoTls).await?;
    let connection_task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("cell process connection failed: {error}");
        }
    });
    Ok((client, connection_task))
}

fn scope() -> Result<CellScope, Box<dyn Error>> {
    Ok(CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::from_stable(required("HARTEVO_CELL_TENANT")?),
    })
}

fn required(name: &str) -> Result<String, io::Error> {
    std::env::var(name).map_err(|_| io::Error::new(io::ErrorKind::NotFound, name))
}

fn timestamp(name: &str) -> Result<DateTime<Utc>, Box<dyn Error>> {
    Ok(DateTime::parse_from_rfc3339(&required(name)?)?.with_timezone(&Utc))
}
