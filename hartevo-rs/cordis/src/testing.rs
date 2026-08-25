//! Fixture Domain Kernel facts for host and desktop tests.
//!
//! These construct live kernel records. They are not a Cordis mount stamp and
//! must not be used as a production grant path. Production still fail-closes
//! until [`crate::CordisHost::bind_domain_kernel_facts`] receives real records.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ActorId, Approval, ApprovalDecision, ApprovalId, ConsentPurpose, ConsentRecord,
    ConsentRecordId, ConsentRequirement, ConsentState, ContactChannel, CurrencyCode, Effect,
    EffectClass, EffectId, EffectRisk, EffectStatus, LegalBasis, MissionId, Money, PersonId,
    ProjectId, TenantId,
};

use crate::DomainKernelFacts;

/// Granted consent + approved effect that the host gate accepts at `now`.
#[must_use]
pub fn permitted_kernel_facts(now: DateTime<Utc>) -> DomainKernelFacts {
    let consent = granted_consent(now);
    let effect = approved_effect(now, Some(&consent));
    DomainKernelFacts {
        consent: Some(consent),
        effect: Some(effect),
        observed_at: None,
    }
}

/// Approved effect whose Domain Kernel consent state is `NotRequired`.
#[must_use]
pub fn not_required_kernel_facts(now: DateTime<Utc>) -> DomainKernelFacts {
    DomainKernelFacts {
        consent: None,
        effect: Some(approved_effect(now, None)),
        observed_at: None,
    }
}

/// Confirmed consent that is live at `now`.
#[must_use]
pub fn granted_consent(now: DateTime<Utc>) -> ConsentRecord {
    ConsentRecord::grant(
        ConsentRecordId::from("consent-1"),
        TenantId::from("tenant-1"),
        ProjectId::from("project-1"),
        PersonId::from("person-1"),
        ConsentPurpose::EmailMarketing,
        ContactChannel::Email,
        "DE",
        LegalBasis::ExplicitConsent,
        "double-opt-in",
        "b".repeat(64),
        now,
        Some(now + chrono::Duration::days(30)),
    )
    .expect("fixture consent")
}

fn requirement() -> ConsentRequirement {
    ConsentRequirement {
        person_id: PersonId::from("person-1"),
        purpose: ConsentPurpose::EmailMarketing,
        channel: ContactChannel::Email,
        market: "DE".into(),
    }
}

fn approved_effect(now: DateTime<Utc>, consent: Option<&ConsentRecord>) -> Effect {
    let (consent_state, consent_record_id, consent_requirement) = match consent {
        Some(record) => (
            ConsentState::Confirmed,
            Some(record.id.clone()),
            Some(requirement()),
        ),
        None => (ConsentState::NotRequired, None, None),
    };
    let mut effect = Effect {
        id: EffectId::from("effect-1"),
        tenant_id: TenantId::from("tenant-1"),
        project_id: ProjectId::from("project-1"),
        mission_id: MissionId::from("mission-1"),
        actor_id: ActorId::from("user-1"),
        capability: "channel.preview".into(),
        provider: "fixture-provider".into(),
        connection_id: None,
        account_id: None,
        required_scopes: BTreeSet::new(),
        effect_class: EffectClass::ExternalWrite,
        description: "Publish preview".into(),
        target_resource: "preview.example/launch".into(),
        audience_digest: None,
        payload_digest: "a".repeat(64),
        asset_digests: BTreeSet::new(),
        scheduled_for: None,
        timezone: "UTC".into(),
        consent: consent_state,
        consent_record_id,
        consent_requirement,
        conversation_guard: None,
        creator_contact_guard: None,
        policy_version: "policy-v1".into(),
        risk: EffectRisk::Low,
        idempotency_key: "mission-1:preview:v1".into(),
        amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
        expires_at: now + chrono::Duration::hours(1),
        status: EffectStatus::Approved,
        approval: None,
        receipt: None,
        verification: None,
    };
    let scope_digest = effect.approval_digest();
    effect.approval = Some(Approval {
        id: ApprovalId::from("approval-1"),
        decision: ApprovalDecision::Approved,
        decided_by: ActorId::from("user-1"),
        decided_at: now,
        valid_until: now + chrono::Duration::seconds(60),
        scope_digest,
        permission_digest: "b".repeat(64),
    });
    effect
}
