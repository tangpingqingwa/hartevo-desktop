use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ProjectStore, StorageError};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    Pending,
    Leased,
    Published,
    DeadLetter,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxMessage {
    pub sequence: i64,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: Option<MissionId>,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub event_type: String,
    pub payload: Value,
    pub status: OutboxStatus,
    pub attempts: u32,
    pub available_at: DateTime<Utc>,
    pub lease_owner: Option<String>,
    pub lease_generation: u64,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxAcknowledgeTimes {
    pub published_at: DateTime<Utc>,
    pub operation_at: DateTime<Utc>,
}

impl OutboxAcknowledgeTimes {
    pub fn new(
        published_at: DateTime<Utc>,
        operation_at: DateTime<Utc>,
    ) -> Result<Self, StorageError> {
        let times = Self {
            published_at,
            operation_at,
        };
        times.validate()?;
        Ok(times)
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        if self.published_at > self.operation_at {
            Err(StorageError::DomainDecode(
                "outbox acknowledgement requires published_at <= operation_at".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxReleaseTimes {
    pub available_at: DateTime<Utc>,
    pub operation_at: DateTime<Utc>,
}

impl OutboxReleaseTimes {
    pub fn new(
        available_at: DateTime<Utc>,
        operation_at: DateTime<Utc>,
    ) -> Result<Self, StorageError> {
        let times = Self {
            available_at,
            operation_at,
        };
        times.validate()?;
        Ok(times)
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        if self.available_at < self.operation_at {
            Err(StorageError::DomainDecode(
                "outbox release requires available_at >= operation_at".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxRelease {
    Requeue(OutboxReleaseTimes),
    DeadLetter(OutboxReleaseTimes),
}

impl ProjectStore {
    pub fn claim_outbox(
        &mut self,
        owner: &str,
        now: DateTime<Utc>,
        lease_for: Duration,
        limit: usize,
    ) -> Result<Vec<OutboxMessage>, StorageError> {
        if owner.trim().is_empty() || lease_for <= Duration::zero() || limit == 0 {
            return Err(StorageError::DomainDecode(
                "outbox claim requires an owner, positive lease, and non-zero limit".into(),
            ));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| StorageError::DomainDecode("outbox claim limit overflow".into()))?;
        let transaction = self.connection.transaction()?;
        let now_text = now.to_rfc3339();
        let lease_expires_at = (now + lease_for).to_rfc3339();
        let sequences = {
            let mut statement = transaction.prepare(
                "SELECT sequence FROM outbox_messages
                 WHERE (status = 'pending' AND available_at <= ?1)
                    OR (status = 'leased' AND lease_expires_at <= ?1)
                 ORDER BY sequence ASC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![now_text, limit], |row| row.get::<_, i64>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut claimed = Vec::with_capacity(sequences.len());
        for sequence in sequences {
            let updated = transaction.execute(
                "UPDATE outbox_messages SET
                   status = 'leased', lease_owner = ?2,
                   lease_generation = lease_generation + 1,
                   lease_expires_at = ?3, attempts = attempts + 1
                 WHERE sequence = ?1
                   AND ((status = 'pending' AND available_at <= ?4)
                     OR (status = 'leased' AND lease_expires_at <= ?4))",
                params![sequence, owner, lease_expires_at, now_text],
            )?;
            if updated == 1 {
                claimed.push(load_outbox_message(&transaction, sequence)?);
            }
        }
        transaction.commit()?;
        Ok(claimed)
    }

    pub fn acknowledge_outbox(
        &mut self,
        sequence: i64,
        owner: &str,
        generation: u64,
        times: OutboxAcknowledgeTimes,
    ) -> Result<(), StorageError> {
        times.validate()?;
        let updated = self.connection.execute(
            "UPDATE outbox_messages SET
               status = 'published', published_at = ?4,
               lease_owner = NULL, lease_expires_at = NULL
             WHERE sequence = ?1 AND status = 'leased'
               AND lease_owner = ?2 AND lease_generation = ?3
               AND lease_expires_at > ?5",
            params![
                sequence,
                owner,
                to_sql_generation(generation)?,
                times.published_at.to_rfc3339(),
                times.operation_at.to_rfc3339(),
            ],
        )?;
        require_lease(updated, sequence, owner, generation)
    }

    pub fn release_outbox(
        &mut self,
        sequence: i64,
        owner: &str,
        generation: u64,
        release: OutboxRelease,
    ) -> Result<(), StorageError> {
        let (status, times) = match release {
            OutboxRelease::Requeue(times) => ("pending", times),
            OutboxRelease::DeadLetter(times) => ("dead_letter", times),
        };
        times.validate()?;
        let updated = self.connection.execute(
            "UPDATE outbox_messages SET
               status = ?4, available_at = ?5,
               lease_owner = NULL, lease_expires_at = NULL
             WHERE sequence = ?1 AND status = 'leased'
               AND lease_owner = ?2 AND lease_generation = ?3
               AND lease_expires_at > ?6",
            params![
                sequence,
                owner,
                to_sql_generation(generation)?,
                status,
                times.available_at.to_rfc3339(),
                times.operation_at.to_rfc3339(),
            ],
        )?;
        require_lease(updated, sequence, owner, generation)
    }

    pub fn outbox_message(&self, sequence: i64) -> Result<OutboxMessage, StorageError> {
        load_outbox_message(&self.connection, sequence)
    }
}

fn load_outbox_message(
    connection: &rusqlite::Connection,
    sequence: i64,
) -> Result<OutboxMessage, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type,
                    payload_json, status, attempts, available_at, lease_owner,
                    lease_generation, lease_expires_at, created_at, published_at
             FROM outbox_messages WHERE sequence = ?1",
            [sequence],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, Option<String>>(14)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::DomainDecode(format!("unknown outbox message {sequence}")))?;
    Ok(OutboxMessage {
        sequence,
        tenant_id: TenantId::from_stable(row.0),
        project_id: ProjectId::from_stable(row.1),
        mission_id: row.2.map(MissionId::from_stable),
        aggregate_type: row.3,
        aggregate_id: row.4,
        event_type: row.5,
        payload: serde_json::from_str(&row.6)?,
        status: decode_status(&row.7)?,
        attempts: u32::try_from(row.8)
            .map_err(|_| StorageError::DomainDecode("outbox attempts overflow".into()))?,
        available_at: parse_time(&row.9)?,
        lease_owner: row.10,
        lease_generation: u64::try_from(row.11)
            .map_err(|_| StorageError::DomainDecode("outbox generation overflow".into()))?,
        lease_expires_at: row.12.as_deref().map(parse_time).transpose()?,
        created_at: parse_time(&row.13)?,
        published_at: row.14.as_deref().map(parse_time).transpose()?,
    })
}

fn decode_status(value: &str) -> Result<OutboxStatus, StorageError> {
    match value {
        "pending" => Ok(OutboxStatus::Pending),
        "leased" => Ok(OutboxStatus::Leased),
        "published" => Ok(OutboxStatus::Published),
        "dead_letter" => Ok(OutboxStatus::DeadLetter),
        other => Err(StorageError::DomainDecode(format!(
            "unknown outbox status {other}"
        ))),
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sql_generation(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::DomainDecode("outbox generation overflow".into()))
}

fn require_lease(
    updated: usize,
    sequence: i64,
    owner: &str,
    generation: u64,
) -> Result<(), StorageError> {
    if updated == 1 {
        Ok(())
    } else {
        Err(StorageError::OutboxLeaseLost {
            sequence,
            owner: owner.into(),
            generation,
        })
    }
}
