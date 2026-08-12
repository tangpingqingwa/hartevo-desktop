use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Company, CompanyId, IdentityLink, IdentityLinkId, IdentitySubject, Partner, PartnerId, Person,
    PersonId, ProjectId, TenantId,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{PersistedMutation, ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_company(
        &mut self,
        company: &Company,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        company
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_initial(company.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &company.tenant_id, &company.project_id)?;
        insert_company_record(&transaction, company)?;
        finish(
            transaction,
            &company.tenant_id,
            &company.project_id,
            "company",
            company.id.as_str(),
            company.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_company(
        &mut self,
        company: &Company,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        company
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_next(expected_revision, company.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &company.tenant_id, &company.project_id)?;
        let updated = transaction.execute(
            "UPDATE companies SET legal_name = ?4, market = ?5, revision = ?6
             WHERE id = ?1 AND tenant_id = ?2 AND project_id = ?3 AND revision = ?7",
            params![
                company.id.as_str(),
                company.tenant_id.as_str(),
                company.project_id.as_str(),
                company.legal_name,
                company.market,
                to_sql_u64(company.revision)?,
                to_sql_u64(expected_revision)?,
            ],
        )?;
        require_updated(updated, "company", company.id.as_str(), expected_revision)?;
        finish(
            transaction,
            &company.tenant_id,
            &company.project_id,
            "company",
            company.id.as_str(),
            company.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_company(
        &self,
        project_id: &ProjectId,
        company_id: &CompanyId,
    ) -> Result<Company, StorageError> {
        self.connection
            .query_row(
                "SELECT id, tenant_id, project_id, legal_name, market, revision
                 FROM companies WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), company_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?
            .map(|row| -> Result<Company, StorageError> {
                Ok(Company {
                    id: CompanyId::from_stable(row.0),
                    tenant_id: TenantId::from_stable(row.1),
                    project_id: ProjectId::from_stable(row.2),
                    legal_name: row.3,
                    market: row.4,
                    revision: from_sql_u64(row.5, "company revision")?,
                })
            })
            .transpose()?
            .ok_or_else(|| missing("company", project_id, company_id.as_str()))
    }

    pub fn create_person(
        &mut self,
        person: &Person,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        person
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_initial(person.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &person.tenant_id, &person.project_id)?;
        ensure_company_reference(
            &transaction,
            &person.tenant_id,
            &person.project_id,
            person.company_id.as_ref(),
        )?;
        insert_person_record(&transaction, person)?;
        finish(
            transaction,
            &person.tenant_id,
            &person.project_id,
            "person",
            person.id.as_str(),
            person.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_person(
        &mut self,
        person: &Person,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        person
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_next(expected_revision, person.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &person.tenant_id, &person.project_id)?;
        ensure_company_reference(
            &transaction,
            &person.tenant_id,
            &person.project_id,
            person.company_id.as_ref(),
        )?;
        let updated = transaction.execute(
            "UPDATE people SET display_name = ?4, company_id = ?5,
               contacts_json = ?6, revision = ?7
             WHERE id = ?1 AND tenant_id = ?2 AND project_id = ?3 AND revision = ?8",
            params![
                person.id.as_str(),
                person.tenant_id.as_str(),
                person.project_id.as_str(),
                person.display_name,
                person.company_id.as_ref().map(CompanyId::as_str),
                serde_json::to_string(&person.contacts)?,
                to_sql_u64(person.revision)?,
                to_sql_u64(expected_revision)?,
            ],
        )?;
        require_updated(updated, "person", person.id.as_str(), expected_revision)?;
        finish(
            transaction,
            &person.tenant_id,
            &person.project_id,
            "person",
            person.id.as_str(),
            person.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_person(
        &self,
        project_id: &ProjectId,
        person_id: &PersonId,
    ) -> Result<Person, StorageError> {
        self.connection
            .query_row(
                "SELECT id, tenant_id, project_id, display_name, company_id, contacts_json, revision
                 FROM people WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), person_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?
            .map(|row| -> Result<Person, StorageError> {
                Ok(Person {
                    id: PersonId::from_stable(row.0),
                    tenant_id: TenantId::from_stable(row.1),
                    project_id: ProjectId::from_stable(row.2),
                    display_name: row.3,
                    company_id: row.4.map(CompanyId::from_stable),
                    contacts: decode_json(&row.5)?,
                    revision: from_sql_u64(row.6, "person revision")?,
                })
            })
            .transpose()?
            .ok_or_else(|| missing("person", project_id, person_id.as_str()))
    }

    pub fn create_partner(
        &mut self,
        partner: &Partner,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        partner
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_initial(partner.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &partner.tenant_id, &partner.project_id)?;
        ensure_partner_references(&transaction, partner)?;
        insert_partner(&transaction, partner)?;
        finish(
            transaction,
            &partner.tenant_id,
            &partner.project_id,
            "partner",
            partner.id.as_str(),
            partner.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_partner(
        &mut self,
        partner: &Partner,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        partner
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_next(expected_revision, partner.revision)?;
        let previous = self.load_partner(&partner.project_id, &partner.id)?;
        if previous.revision != expected_revision
            || !partner
                .follows(&previous)
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "partner permission transition",
                id: partner.id.to_string(),
            });
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &partner.tenant_id, &partner.project_id)?;
        ensure_partner_references(&transaction, partner)?;
        let updated = transaction.execute(
            "UPDATE partners SET person_id = ?4, company_id = ?5, display_name = ?6,
               supply_class = ?7, contact_permission = ?8,
               permission_evidence_digest = ?9, revision = ?10
             WHERE id = ?1 AND tenant_id = ?2 AND project_id = ?3 AND revision = ?11",
            params![
                partner.id.as_str(),
                partner.tenant_id.as_str(),
                partner.project_id.as_str(),
                partner.person_id.as_ref().map(PersonId::as_str),
                partner.company_id.as_ref().map(CompanyId::as_str),
                partner.display_name,
                enum_name(&partner.supply_class)?,
                enum_name(&partner.contact_permission)?,
                partner.permission_evidence_digest,
                to_sql_u64(partner.revision)?,
                to_sql_u64(expected_revision)?,
            ],
        )?;
        require_updated(updated, "partner", partner.id.as_str(), expected_revision)?;
        finish(
            transaction,
            &partner.tenant_id,
            &partner.project_id,
            "partner",
            partner.id.as_str(),
            partner.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_partner(
        &self,
        project_id: &ProjectId,
        partner_id: &PartnerId,
    ) -> Result<Partner, StorageError> {
        self.connection
            .query_row(
                "SELECT id, tenant_id, project_id, person_id, company_id, display_name,
                        supply_class, contact_permission, permission_evidence_digest, revision
                 FROM partners WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), partner_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()?
            .map(|row| -> Result<Partner, StorageError> {
                Ok(Partner {
                    id: PartnerId::from_stable(row.0),
                    tenant_id: TenantId::from_stable(row.1),
                    project_id: ProjectId::from_stable(row.2),
                    person_id: row.3.map(PersonId::from_stable),
                    company_id: row.4.map(CompanyId::from_stable),
                    display_name: row.5,
                    supply_class: decode_enum(&row.6)?,
                    contact_permission: decode_enum(&row.7)?,
                    permission_evidence_digest: row.8,
                    revision: from_sql_u64(row.9, "partner revision")?,
                })
            })
            .transpose()?
            .ok_or_else(|| missing("partner", project_id, partner_id.as_str()))
    }

    pub fn create_identity_link(
        &mut self,
        link: &IdentityLink,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        link.validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_initial(link.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &link.tenant_id, &link.project_id)?;
        ensure_subject(
            &transaction,
            &link.tenant_id,
            &link.project_id,
            &link.subject,
        )?;
        insert_identity_link(&transaction, link)?;
        finish(
            transaction,
            &link.tenant_id,
            &link.project_id,
            "identity_link",
            link.id.as_str(),
            link.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_identity_link(
        &mut self,
        link: &IdentityLink,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        link.validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_next(expected_revision, link.revision)?;
        let previous = self.load_identity_link(&link.project_id, &link.id)?;
        if previous.revision != expected_revision
            || !link
                .follows(&previous)
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::DomainDecode(
                "identity link update is not one exact decision append".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &link.tenant_id, &link.project_id)?;
        ensure_subject(
            &transaction,
            &link.tenant_id,
            &link.project_id,
            &link.subject,
        )?;
        let updated = transaction.execute(
            "UPDATE identity_links SET subject_json = ?4, identities_json = ?5,
               confidence = ?6, status = ?7, confirmed_by = ?8, confirmed_at = ?9,
               decision_history_json = ?10, revision = ?11
             WHERE id = ?1 AND tenant_id = ?2 AND project_id = ?3 AND revision = ?12",
            identity_link_params(link, Some(expected_revision))?,
        )?;
        require_updated(
            updated,
            "identity_link",
            link.id.as_str(),
            expected_revision,
        )?;
        finish(
            transaction,
            &link.tenant_id,
            &link.project_id,
            "identity_link",
            link.id.as_str(),
            link.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_identity_link(
        &self,
        project_id: &ProjectId,
        link_id: &IdentityLinkId,
    ) -> Result<IdentityLink, StorageError> {
        self.connection
            .query_row(
                "SELECT id, tenant_id, project_id, subject_json, identities_json, confidence,
                        status, confirmed_by, confirmed_at, decision_history_json, revision
                 FROM identity_links WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), link_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .optional()?
            .map(|row| -> Result<IdentityLink, StorageError> {
                let link = IdentityLink {
                    id: IdentityLinkId::from_stable(row.0),
                    tenant_id: TenantId::from_stable(row.1),
                    project_id: ProjectId::from_stable(row.2),
                    subject: decode_json(&row.3)?,
                    identities: decode_json(&row.4)?,
                    confidence: decode_json(&row.5)?,
                    status: decode_enum(&row.6)?,
                    decisions: decode_json(&row.9)?,
                    revision: from_sql_u64(row.10, "identity link revision")?,
                };
                let legacy_confirmation_matches = match link.last_confirmation() {
                    Some(decision) => {
                        row.7.as_deref() == Some(decision.decided_by.as_str())
                            && row.8.as_deref().map(parse_time).transpose()?
                                == Some(decision.decided_at)
                    }
                    None => row.7.is_none() && row.8.is_none(),
                };
                if !legacy_confirmation_matches {
                    return Err(StorageError::DomainDecode(
                        "identity link confirmation projection disagrees with decision history"
                            .into(),
                    ));
                }
                link.validate()
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                Ok(link)
            })
            .transpose()?
            .ok_or_else(|| missing("identity_link", project_id, link_id.as_str()))
    }
}

pub(crate) fn insert_company_record(
    transaction: &Transaction<'_>,
    company: &Company,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO companies
           (id, tenant_id, project_id, legal_name, market, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            company.id.as_str(),
            company.tenant_id.as_str(),
            company.project_id.as_str(),
            company.legal_name,
            company.market,
            to_sql_u64(company.revision)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn insert_person_record(
    transaction: &Transaction<'_>,
    person: &Person,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO people
           (id, tenant_id, project_id, display_name, company_id, contacts_json, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            person.id.as_str(),
            person.tenant_id.as_str(),
            person.project_id.as_str(),
            person.display_name,
            person.company_id.as_ref().map(CompanyId::as_str),
            serde_json::to_string(&person.contacts)?,
            to_sql_u64(person.revision)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn insert_partner(
    transaction: &Transaction<'_>,
    partner: &Partner,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO partners
           (id, tenant_id, project_id, person_id, company_id, display_name, supply_class,
            contact_permission, permission_evidence_digest, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            partner.id.as_str(),
            partner.tenant_id.as_str(),
            partner.project_id.as_str(),
            partner.person_id.as_ref().map(PersonId::as_str),
            partner.company_id.as_ref().map(CompanyId::as_str),
            partner.display_name,
            enum_name(&partner.supply_class)?,
            enum_name(&partner.contact_permission)?,
            partner.permission_evidence_digest,
            to_sql_u64(partner.revision)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn insert_identity_link(
    transaction: &Transaction<'_>,
    link: &IdentityLink,
) -> Result<(), StorageError> {
    link.validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
    transaction.execute(
        "INSERT INTO identity_links
           (id, tenant_id, project_id, subject_json, identities_json, confidence, status,
            confirmed_by, confirmed_at, decision_history_json, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        identity_link_params(link, None)?,
    )?;
    Ok(())
}

fn identity_link_params(
    link: &IdentityLink,
    expected_revision: Option<u64>,
) -> Result<impl rusqlite::Params + use<>, StorageError> {
    let confirmation = link.last_confirmation();
    let mut values = vec![
        rusqlite::types::Value::from(link.id.as_str().to_owned()),
        rusqlite::types::Value::from(link.tenant_id.as_str().to_owned()),
        rusqlite::types::Value::from(link.project_id.as_str().to_owned()),
        serde_json::to_string(&link.subject)?.into(),
        serde_json::to_string(&link.identities)?.into(),
        serde_json::to_string(&link.confidence)?.into(),
        enum_name(&link.status)?.into(),
        confirmation
            .map(|decision| decision.decided_by.as_str().to_owned())
            .into(),
        confirmation
            .map(|decision| decision.decided_at.to_rfc3339())
            .into(),
        serde_json::to_string(&link.decisions)?.into(),
        to_sql_u64(link.revision)?.into(),
    ];
    if let Some(expected_revision) = expected_revision {
        values.push(to_sql_u64(expected_revision)?.into());
    }
    Ok(rusqlite::params_from_iter(values))
}

pub(crate) fn ensure_project(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
) -> Result<(), StorageError> {
    let stored_tenant = transaction
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))?;
    if stored_tenant != tenant_id.as_str() {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

pub(crate) fn ensure_company_reference(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    company_id: Option<&CompanyId>,
) -> Result<(), StorageError> {
    let Some(company_id) = company_id else {
        return Ok(());
    };
    ensure_scoped_record(
        transaction,
        "companies",
        "company",
        tenant_id,
        project_id,
        company_id.as_str(),
    )
}

pub(crate) fn ensure_partner_references(
    transaction: &Transaction<'_>,
    partner: &Partner,
) -> Result<(), StorageError> {
    if let Some(person_id) = &partner.person_id {
        ensure_scoped_record(
            transaction,
            "people",
            "person",
            &partner.tenant_id,
            &partner.project_id,
            person_id.as_str(),
        )?;
    }
    ensure_company_reference(
        transaction,
        &partner.tenant_id,
        &partner.project_id,
        partner.company_id.as_ref(),
    )
}

pub(crate) fn ensure_subject(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    subject: &IdentitySubject,
) -> Result<(), StorageError> {
    let (table, kind, id) = match subject {
        IdentitySubject::Person(id) => ("people", "person", id.as_str()),
        IdentitySubject::Company(id) => ("companies", "company", id.as_str()),
        IdentitySubject::Partner(id) => ("partners", "partner", id.as_str()),
    };
    ensure_scoped_record(transaction, table, kind, tenant_id, project_id, id)
}

fn ensure_scoped_record(
    transaction: &Transaction<'_>,
    table: &str,
    kind: &'static str,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    id: &str,
) -> Result<(), StorageError> {
    let stored_tenant = transaction
        .query_row(
            &format!("SELECT tenant_id FROM {table} WHERE project_id = ?1 AND id = ?2"),
            params![project_id.as_str(), id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| missing(kind, project_id, id))?;
    if stored_tenant != tenant_id.as_str() {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish(
    transaction: Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    aggregate_type: &str,
    aggregate_id: &str,
    revision: u64,
    event_type: &str,
    payload: &Value,
    recorded_at: DateTime<Utc>,
) -> Result<PersistedMutation, StorageError> {
    if event_type.trim().is_empty() {
        return Err(StorageError::EmptyEventType);
    }
    let payload_json = serde_json::to_string(payload)?;
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let event_sequence = transaction.last_insert_rowid();
    transaction.execute(
        "INSERT INTO outbox_messages
           (tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type,
            payload_json, available_at, created_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            aggregate_type,
            aggregate_id,
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let outbox_sequence = transaction.last_insert_rowid();
    transaction.commit()?;
    Ok(PersistedMutation {
        event_sequence,
        outbox_sequence,
        state_revision: revision,
    })
}

fn require_initial(revision: u64) -> Result<(), StorageError> {
    if revision == 1 {
        Ok(())
    } else {
        Err(StorageError::InvalidInitialRevision(revision))
    }
}

fn require_next(expected: u64, actual: u64) -> Result<(), StorageError> {
    let next = expected
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(expected))?;
    if actual == next {
        Ok(())
    } else {
        Err(StorageError::UnexpectedNextRevision {
            expected: next,
            actual,
        })
    }
}

fn require_updated(
    updated: usize,
    kind: &str,
    id: &str,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if updated == 1 {
        Ok(())
    } else {
        Err(StorageError::OptimisticConflict {
            aggregate: format!("{kind}:{id}"),
            expected_revision,
        })
    }
}

fn missing(kind: &'static str, project_id: &ProjectId, id: &str) -> StorageError {
    StorageError::ScopedRecordNotFound {
        kind,
        project_id: project_id.clone(),
        id: id.to_owned(),
    }
}

fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

fn decode_enum<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(Value::String(value.to_owned()))?)
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(value)?)
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        AccountId, ActorId, ContactChannel, ContactPermission, ContactPoint, ExternalIdentity,
        IdentityLinkStatus, PartnerSupplyClass, Project, StorageMode,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 14, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> (ProjectStore, ProjectId) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project_id = ProjectId::from("project-identities");
        store
            .save_project(
                &Project::create_local(
                    TenantId::from("tenant-identities"),
                    project_id.clone(),
                    "Identity project",
                    "",
                    "/tmp/hartevo-identities",
                    StorageMode::LocalExisting,
                )
                .expect("project"),
            )
            .expect("persist project");
        (store, project_id)
    }

    fn persist_identity_subjects(
        store: &mut ProjectStore,
        project_id: &ProjectId,
    ) -> (Company, Person, Partner) {
        let tenant_id = TenantId::from("tenant-identities");
        let company = Company::create(
            CompanyId::from("company-1"),
            tenant_id.clone(),
            project_id.clone(),
            "Creator Studio LLC",
            "US",
        )
        .expect("company");
        store
            .create_company(&company, "company.created", &serde_json::json!({}), now())
            .expect("company persisted");
        let person = Person::create(
            PersonId::from("person-1"),
            tenant_id.clone(),
            project_id.clone(),
            "Verified Creator",
            Some(company.id.clone()),
            vec![ContactPoint {
                channel: ContactChannel::Email,
                encrypted_value_ref: "ciphertext://contact/person-1/email".into(),
                value_digest: "1".repeat(64),
                verified_at: Some(now()),
            }],
        )
        .expect("person");
        store
            .create_person(&person, "person.created", &serde_json::json!({}), now())
            .expect("person persisted");
        let partner = Partner::create(
            PartnerId::from("partner-1"),
            tenant_id,
            project_id.clone(),
            Some(person.id.clone()),
            Some(company.id.clone()),
            "Verified Creator",
            PartnerSupplyClass::HartevoOptIn,
            ContactPermission::ExplicitOptIn,
            Some("2".repeat(64)),
        )
        .expect("partner");
        store
            .create_partner(&partner, "partner.created", &serde_json::json!({}), now())
            .expect("partner persisted");
        (company, person, partner)
    }

    #[test]
    fn identity_chain_is_project_scoped_persisted_and_confirmed_with_cas() {
        let (mut store, project_id) = setup();
        let (company, person, partner) = persist_identity_subjects(&mut store, &project_id);
        let mut link = IdentityLink::propose(
            IdentityLinkId::from("identity-link-1"),
            TenantId::from("tenant-identities"),
            project_id.clone(),
            IdentitySubject::Partner(partner.id.clone()),
            [ExternalIdentity {
                provider: "stripe-connect".into(),
                account_id: AccountId::from("acct-creator-1"),
                external_subject_digest: "3".repeat(64),
                encrypted_subject_ref: "ciphertext://stripe/account/creator-1".into(),
                evidence_digest: "4".repeat(64),
            }],
            "0.95".parse().expect("decimal"),
        )
        .expect("identity link");
        store
            .create_identity_link(
                &link,
                "identity_link.proposed",
                &serde_json::json!({}),
                now(),
            )
            .expect("link persisted");
        link.confirm(ActorId::from("reviewer-1"), "4".repeat(64), now())
            .expect("confirmation");
        let mut rewritten = link.clone();
        let original_identity = rewritten
            .identities
            .iter()
            .next()
            .expect("external identity")
            .clone();
        rewritten.identities.remove(&original_identity);
        let mut changed_identity = original_identity;
        changed_identity.encrypted_subject_ref =
            "ciphertext://stripe/account/silently-rewritten".into();
        rewritten.identities.insert(changed_identity);
        assert!(matches!(
            store.update_identity_link(
                &rewritten,
                1,
                "identity_link.confirmed",
                &serde_json::json!({}),
                now(),
            ),
            Err(StorageError::DomainDecode(_))
        ));
        assert_eq!(
            store
                .load_identity_link(&project_id, &link.id)
                .expect("proposal unchanged after rewrite attempt")
                .status,
            IdentityLinkStatus::Proposed
        );
        store
            .update_identity_link(
                &link,
                1,
                "identity_link.confirmed",
                &serde_json::json!({}),
                now(),
            )
            .expect("confirmation persisted");

        assert_eq!(
            store
                .load_company(&project_id, &company.id)
                .expect("company"),
            company
        );
        assert_eq!(
            store.load_person(&project_id, &person.id).expect("person"),
            person
        );
        assert_eq!(
            store
                .load_partner(&project_id, &partner.id)
                .expect("partner"),
            partner
        );
        let loaded = store
            .load_identity_link(&project_id, &link.id)
            .expect("identity link");
        assert_eq!(loaded.status, IdentityLinkStatus::Confirmed);
        assert_eq!(loaded, link);
    }

    #[test]
    fn person_cannot_reference_company_from_another_project() {
        let (mut store, project_id) = setup();
        let other_id = ProjectId::from("project-other");
        store
            .save_project(
                &Project::create_local(
                    TenantId::from("tenant-identities"),
                    other_id.clone(),
                    "Other project",
                    "",
                    "/tmp/hartevo-other",
                    StorageMode::LocalExisting,
                )
                .expect("other project"),
            )
            .expect("persist other");
        let company = Company::create(
            CompanyId::from("company-other"),
            TenantId::from("tenant-identities"),
            other_id,
            "Other Company",
            "US",
        )
        .expect("company");
        store
            .create_company(&company, "company.created", &serde_json::json!({}), now())
            .expect("company");
        let person = Person::create(
            PersonId::from("person-cross-project"),
            TenantId::from("tenant-identities"),
            project_id,
            "Cross project",
            Some(company.id),
            vec![],
        )
        .expect("person shape");

        assert!(matches!(
            store.create_person(&person, "person.created", &serde_json::json!({}), now(),),
            Err(StorageError::ScopedRecordNotFound {
                kind: "company",
                ..
            })
        ));
    }
}
