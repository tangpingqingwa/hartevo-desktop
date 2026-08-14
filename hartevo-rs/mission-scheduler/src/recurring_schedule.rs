//! Conversation-authored recurring Mission schedules.
//!
//! The upstream conversation layer supplies a typed [`MissionScheduleDraft`]
//! after turning an objective such as “every Monday, summarize …” into a
//! bounded recurrence.  This scheduler-owned module makes that draft durable,
//! resolves local calendar times with an explicit timezone/DST policy, arms
//! one OS/Cell wake, and hands a capability-only request to a Mission
//! consumer.  It has no Runtime, Browser, or Effect completion authority.
//!
//! Every wake token binds the Project/Mission scope, schedule revision,
//! recurrence/timezone/DST digests, plugin composition and invocation,
//! provider epoch, lease revision, and clock epoch.  Lifecycle mutations use
//! the same exact revision CAS.  A dispatch is first durably reserved and then
//! retried with the same idempotency digest after a crash or storage failure.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, NaiveTime, Utc, Weekday};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plugin_invocation::{
    DispatchAuthority, MissionScope, PluginComposition, PluginInvocation, PluginInvocationError,
    PluginManifest,
};
use crate::scheduler_digest;

pub const MAX_TIMEZONE_ID_BYTES: usize = 128;
pub const MAX_RECURRENCE_INTERVAL: u32 = 366;
pub const MAX_RECURRENCE_LOOKAHEAD_DAYS: u32 = 36_600;
pub const MAX_MISSED_TICKS: u32 = 1_024;
pub const MAX_WAKE_CONTRACT_SECONDS: u64 = 366 * 24 * 60 * 60;

/// Calendar weekday used by the bounded RRULE-like weekly recurrence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleWeekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl ScheduleWeekday {
    fn from_chrono(day: Weekday) -> Self {
        match day {
            Weekday::Mon => Self::Monday,
            Weekday::Tue => Self::Tuesday,
            Weekday::Wed => Self::Wednesday,
            Weekday::Thu => Self::Thursday,
            Weekday::Fri => Self::Friday,
            Weekday::Sat => Self::Saturday,
            Weekday::Sun => Self::Sunday,
        }
    }

    fn index(self) -> i64 {
        match self {
            Self::Monday => 0,
            Self::Tuesday => 1,
            Self::Wednesday => 2,
            Self::Thursday => 3,
            Self::Friday => 4,
            Self::Saturday => 5,
            Self::Sunday => 6,
        }
    }
}

/// Which numbered weekday in a month defines a DST transition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionWeek {
    First,
    Second,
    Third,
    Fourth,
    Last,
}

/// A bounded annual local-time DST transition rule.  The explicit rule is
/// persisted with the timezone so the schedule does not depend on a mutable
/// host timezone database.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DstTransitionRule {
    pub month: u8,
    pub week: TransitionWeek,
    pub weekday: ScheduleWeekday,
    pub local_time: NaiveTime,
}

impl DstTransitionRule {
    pub fn new(
        month: u8,
        week: TransitionWeek,
        weekday: ScheduleWeekday,
        local_time: NaiveTime,
    ) -> Result<Self, RecurringScheduleError> {
        let rule = Self {
            month,
            week,
            weekday,
            local_time,
        };
        rule.validate()?;
        Ok(rule)
    }

    pub fn validate(&self) -> Result<(), RecurringScheduleError> {
        if !(1..=12).contains(&self.month) {
            return Err(RecurringScheduleError::InvalidTimezone);
        }
        Ok(())
    }

    fn local_datetime(&self, year: i32) -> Result<NaiveDateTime, RecurringScheduleError> {
        self.validate()?;
        let first = NaiveDate::from_ymd_opt(year, u32::from(self.month), 1)
            .ok_or(RecurringScheduleError::InvalidTimezone)?;
        let date = match self.week {
            TransitionWeek::First
            | TransitionWeek::Second
            | TransitionWeek::Third
            | TransitionWeek::Fourth => {
                let delta = (self.weekday.index() - weekday_index(first.weekday()) + 7) % 7;
                let week = match self.week {
                    TransitionWeek::First => 0,
                    TransitionWeek::Second => 1,
                    TransitionWeek::Third => 2,
                    TransitionWeek::Fourth => 3,
                    TransitionWeek::Last => unreachable!("last is handled above"),
                };
                first
                    .checked_add_signed(Duration::days(delta + 7 * week))
                    .ok_or(RecurringScheduleError::InvalidTimezone)?
            }
            TransitionWeek::Last => {
                let next_month = if self.month == 12 {
                    NaiveDate::from_ymd_opt(year + 1, 1, 1)
                } else {
                    NaiveDate::from_ymd_opt(year, u32::from(self.month + 1), 1)
                }
                .ok_or(RecurringScheduleError::InvalidTimezone)?;
                let last = next_month
                    .checked_sub_signed(Duration::days(1))
                    .ok_or(RecurringScheduleError::InvalidTimezone)?;
                let delta = (weekday_index(last.weekday()) - self.weekday.index() + 7) % 7;
                last.checked_sub_signed(Duration::days(delta))
                    .ok_or(RecurringScheduleError::InvalidTimezone)?
            }
        };
        if date.month() != u32::from(self.month) {
            return Err(RecurringScheduleError::InvalidTimezone);
        }
        Ok(date.and_time(self.local_time))
    }
}

/// Explicit handling for a nonexistent local time during a spring-forward
/// gap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DstGapPolicy {
    Reject,
    ShiftForward,
    Skip,
}

/// Explicit handling for an ambiguous local time during a fall-back fold.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DstFoldPolicy {
    Reject,
    Earlier,
    Later,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DstPolicy {
    pub gap: DstGapPolicy,
    pub fold: DstFoldPolicy,
}

impl Default for DstPolicy {
    fn default() -> Self {
        Self {
            gap: DstGapPolicy::ShiftForward,
            fold: DstFoldPolicy::Earlier,
        }
    }
}

impl DstPolicy {
    pub fn validate(self) -> Result<(), RecurringScheduleError> {
        Ok(())
    }
}

/// A self-contained timezone definition.  UTC and fixed offsets are useful
/// for deterministic tests; annual transition rules cover a named DST zone
/// without consulting process-global timezone state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleTimezone {
    pub timezone_id: String,
    pub standard_offset_seconds: i32,
    pub daylight_offset_seconds: Option<i32>,
    pub dst_start: Option<DstTransitionRule>,
    pub dst_end: Option<DstTransitionRule>,
    pub timezone_digest: String,
}

impl ScheduleTimezone {
    pub fn utc() -> Self {
        Self::fixed("UTC", 0).expect("UTC timezone is valid")
    }

    pub fn fixed(
        timezone_id: impl Into<String>,
        offset_seconds: i32,
    ) -> Result<Self, RecurringScheduleError> {
        Self::new(timezone_id, offset_seconds, None, None, None)
    }

    pub fn with_dst(
        timezone_id: impl Into<String>,
        standard_offset_seconds: i32,
        daylight_offset_seconds: i32,
        dst_start: DstTransitionRule,
        dst_end: DstTransitionRule,
    ) -> Result<Self, RecurringScheduleError> {
        Self::new(
            timezone_id,
            standard_offset_seconds,
            Some(daylight_offset_seconds),
            Some(dst_start),
            Some(dst_end),
        )
    }

    pub fn new(
        timezone_id: impl Into<String>,
        standard_offset_seconds: i32,
        daylight_offset_seconds: Option<i32>,
        dst_start: Option<DstTransitionRule>,
        dst_end: Option<DstTransitionRule>,
    ) -> Result<Self, RecurringScheduleError> {
        let mut timezone = Self {
            timezone_id: timezone_id.into(),
            standard_offset_seconds,
            daylight_offset_seconds,
            dst_start,
            dst_end,
            timezone_digest: String::new(),
        };
        timezone.timezone_digest = timezone.expected_digest()?;
        timezone.validate()?;
        Ok(timezone)
    }

    pub fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.timezone_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), RecurringScheduleError> {
        if self.timezone_id.trim().is_empty()
            || self.timezone_id.len() > MAX_TIMEZONE_ID_BYTES
            || self.timezone_id.bytes().any(|byte| byte.is_ascii_control())
            || !valid_offset(self.standard_offset_seconds)
            || !is_digest(&self.timezone_digest)
            || self.timezone_digest != self.expected_digest()?
        {
            return Err(RecurringScheduleError::InvalidTimezone);
        }
        match (
            self.daylight_offset_seconds,
            self.dst_start.as_ref(),
            self.dst_end.as_ref(),
        ) {
            (None, None, None) => {}
            (Some(daylight), Some(start), Some(end))
                if valid_offset(daylight)
                    && daylight != self.standard_offset_seconds
                    && start.validate().is_ok()
                    && end.validate().is_ok() => {}
            _ => return Err(RecurringScheduleError::InvalidTimezone),
        }
        Ok(())
    }

    pub fn resolve_local(
        &self,
        local: NaiveDateTime,
        policy: DstPolicy,
    ) -> Result<Option<ResolvedLocalTime>, RecurringScheduleError> {
        self.validate()?;
        policy.validate()?;
        let offsets = self.candidate_offsets();
        let mut candidates = offsets
            .into_iter()
            .filter_map(|offset| {
                let utc = utc_from_local_offset(local, offset)?;
                (self.local_from_utc(utc).0 == local).then_some((utc, offset))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| candidate.0);
        candidates.dedup_by_key(|candidate| candidate.0);
        match candidates.as_slice() {
            [] => self.resolve_gap(local, policy.gap),
            [(utc, offset)] => Ok(Some(ResolvedLocalTime {
                requested_local: local,
                resolved_local: local,
                planned_at: *utc,
                offset_seconds: *offset,
                resolution: if self.daylight_offset_seconds == Some(*offset) {
                    DstResolution::Daylight
                } else {
                    DstResolution::Standard
                },
            })),
            [(earlier_utc, earlier_offset), (later_utc, later_offset)] => match policy.fold {
                DstFoldPolicy::Reject => Err(RecurringScheduleError::DstFold),
                DstFoldPolicy::Earlier => Ok(Some(ResolvedLocalTime {
                    requested_local: local,
                    resolved_local: local,
                    planned_at: *earlier_utc,
                    offset_seconds: *earlier_offset,
                    resolution: DstResolution::FoldEarlier,
                })),
                DstFoldPolicy::Later => Ok(Some(ResolvedLocalTime {
                    requested_local: local,
                    resolved_local: local,
                    planned_at: *later_utc,
                    offset_seconds: *later_offset,
                    resolution: DstResolution::FoldLater,
                })),
            },
            _ => Err(RecurringScheduleError::InvalidTimezone),
        }
    }

    pub fn local_from_utc(&self, utc: DateTime<Utc>) -> (NaiveDateTime, i32) {
        let offset = self.offset_at_utc(utc);
        (
            utc.naive_utc()
                .checked_add_signed(Duration::seconds(i64::from(offset)))
                .unwrap_or(utc.naive_utc()),
            offset,
        )
    }

    pub fn offset_at_utc(&self, utc: DateTime<Utc>) -> i32 {
        let (Some(daylight), Some(start), Some(end)) = (
            self.daylight_offset_seconds,
            self.dst_start.as_ref(),
            self.dst_end.as_ref(),
        ) else {
            return self.standard_offset_seconds;
        };
        let year = utc.year();
        let start_utc = utc_from_transition(
            start.local_datetime(year).ok(),
            self.standard_offset_seconds,
        );
        let end_utc = utc_from_transition(end.local_datetime(year).ok(), daylight);
        let Some((start_utc, end_utc)) = start_utc.zip(end_utc) else {
            return self.standard_offset_seconds;
        };
        let in_daylight = if start_utc < end_utc {
            utc >= start_utc && utc < end_utc
        } else {
            utc >= start_utc || utc < end_utc
        };
        if in_daylight {
            daylight
        } else {
            self.standard_offset_seconds
        }
    }

    fn candidate_offsets(&self) -> Vec<i32> {
        let mut offsets = vec![self.standard_offset_seconds];
        if let Some(daylight) = self.daylight_offset_seconds {
            offsets.push(daylight);
        }
        offsets
    }

    fn resolve_gap(
        &self,
        local: NaiveDateTime,
        policy: DstGapPolicy,
    ) -> Result<Option<ResolvedLocalTime>, RecurringScheduleError> {
        let (Some(daylight), Some(start), Some(_end)) = (
            self.daylight_offset_seconds,
            self.dst_start.as_ref(),
            self.dst_end.as_ref(),
        ) else {
            return Err(RecurringScheduleError::InvalidTimezone);
        };
        let transition = start.local_datetime(local.year())?;
        let gap = i64::from(daylight - self.standard_offset_seconds);
        if gap <= 0 || local < transition {
            return match policy {
                DstGapPolicy::Skip => Ok(None),
                DstGapPolicy::Reject | DstGapPolicy::ShiftForward => {
                    Err(RecurringScheduleError::DstGap)
                }
            };
        }
        let gap_end = transition
            .checked_add_signed(Duration::seconds(gap))
            .ok_or(RecurringScheduleError::InvalidTimezone)?;
        if local >= gap_end {
            return match policy {
                DstGapPolicy::Skip => Ok(None),
                DstGapPolicy::Reject | DstGapPolicy::ShiftForward => {
                    Err(RecurringScheduleError::DstGap)
                }
            };
        }
        match policy {
            DstGapPolicy::Reject => Err(RecurringScheduleError::DstGap),
            DstGapPolicy::Skip => Ok(None),
            DstGapPolicy::ShiftForward => {
                let resolved_local = local
                    .checked_add_signed(Duration::seconds(gap))
                    .ok_or(RecurringScheduleError::InvalidTimezone)?;
                let planned_at = utc_from_local_offset(resolved_local, daylight)
                    .ok_or(RecurringScheduleError::InvalidTimezone)?;
                Ok(Some(ResolvedLocalTime {
                    requested_local: local,
                    resolved_local,
                    planned_at,
                    offset_seconds: daylight,
                    resolution: DstResolution::GapShifted,
                }))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DstResolution {
    Standard,
    Daylight,
    FoldEarlier,
    FoldLater,
    GapShifted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedLocalTime {
    pub requested_local: NaiveDateTime,
    pub resolved_local: NaiveDateTime,
    pub planned_at: DateTime<Utc>,
    pub offset_seconds: i32,
    pub resolution: DstResolution,
}

/// Bounded daily/weekly recurrence.  It intentionally does not implement an
/// unbounded arbitrary RRULE parser; conversation-authored schedules must be
/// normalized into this small durable contract first.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecurrenceRule {
    pub start_local: NaiveDateTime,
    pub frequency: RecurrenceFrequency,
    pub interval: u32,
    pub weekdays: Vec<ScheduleWeekday>,
    pub until_local: Option<NaiveDateTime>,
    pub max_occurrences: Option<u32>,
    pub recurrence_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecurrenceFrequency {
    Daily,
    Weekly,
}

impl RecurrenceRule {
    pub fn daily(
        start_local: NaiveDateTime,
        interval: u32,
    ) -> Result<Self, RecurringScheduleError> {
        Self::new(
            start_local,
            RecurrenceFrequency::Daily,
            interval,
            Vec::new(),
            None,
            None,
        )
    }

    pub fn weekly(
        start_local: NaiveDateTime,
        interval: u32,
        weekdays: Vec<ScheduleWeekday>,
    ) -> Result<Self, RecurringScheduleError> {
        Self::new(
            start_local,
            RecurrenceFrequency::Weekly,
            interval,
            weekdays,
            None,
            None,
        )
    }

    pub fn new(
        start_local: NaiveDateTime,
        frequency: RecurrenceFrequency,
        interval: u32,
        mut weekdays: Vec<ScheduleWeekday>,
        until_local: Option<NaiveDateTime>,
        max_occurrences: Option<u32>,
    ) -> Result<Self, RecurringScheduleError> {
        weekdays.sort();
        weekdays.dedup();
        let mut recurrence = Self {
            start_local,
            frequency,
            interval,
            weekdays,
            until_local,
            max_occurrences,
            recurrence_digest: String::new(),
        };
        recurrence.recurrence_digest = recurrence.expected_digest()?;
        recurrence.validate()?;
        Ok(recurrence)
    }

    pub fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.recurrence_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), RecurringScheduleError> {
        if self.interval == 0
            || self.interval > MAX_RECURRENCE_INTERVAL
            || !is_digest(&self.recurrence_digest)
            || self.recurrence_digest != self.expected_digest()?
            || self
                .until_local
                .is_some_and(|until| until < self.start_local)
            || self.max_occurrences.is_some_and(|count| count == 0)
        {
            return Err(RecurringScheduleError::InvalidRecurrence);
        }
        if matches!(self.frequency, RecurrenceFrequency::Daily) && !self.weekdays.is_empty() {
            return Err(RecurringScheduleError::InvalidRecurrence);
        }
        if matches!(self.frequency, RecurrenceFrequency::Weekly) && self.weekdays.is_empty() {
            return Err(RecurringScheduleError::InvalidRecurrence);
        }
        Ok(())
    }

    fn first_after(
        &self,
        after: DateTime<Utc>,
        timezone: &ScheduleTimezone,
        dst_policy: DstPolicy,
    ) -> Result<Option<ResolvedOccurrence>, RecurringScheduleError> {
        self.next_after(None, after, timezone, dst_policy)
    }

    fn next_after(
        &self,
        previous: Option<&ResolvedOccurrence>,
        after: DateTime<Utc>,
        timezone: &ScheduleTimezone,
        dst_policy: DstPolicy,
    ) -> Result<Option<ResolvedOccurrence>, RecurringScheduleError> {
        self.validate()?;
        timezone.validate()?;
        let mut date = previous.map_or(self.start_local.date(), |occurrence| {
            occurrence.requested_local.date()
        });
        let start_date = self.start_local.date();
        let start_time = self.start_local.time();
        let mut ordinal = previous.map_or(0, |occurrence| occurrence.ordinal);
        for _ in 0..=MAX_RECURRENCE_LOOKAHEAD_DAYS {
            if previous.is_some()
                && date <= previous.expect("previous exists").requested_local.date()
            {
                date = date
                    .checked_add_signed(Duration::days(1))
                    .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
                continue;
            }
            let local = date.and_time(start_time);
            let matches = self.matches_date(date, start_date)?;
            if matches {
                if self.until_local.is_some_and(|until| local > until) {
                    return Ok(None);
                }
                if let Some(max) = self.max_occurrences
                    && ordinal >= u64::from(max)
                {
                    return Ok(None);
                }
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
                if let Some(resolved) = timezone.resolve_local(local, dst_policy)?
                    && resolved.planned_at > after
                {
                    return Ok(Some(ResolvedOccurrence {
                        ordinal,
                        requested_local: resolved.requested_local,
                        resolved_local: resolved.resolved_local,
                        planned_at: resolved.planned_at,
                        offset_seconds: resolved.offset_seconds,
                        resolution: resolved.resolution,
                    }));
                }
            }
            date = date
                .checked_add_signed(Duration::days(1))
                .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
        }
        Err(RecurringScheduleError::RecurrenceExhausted)
    }

    fn matches_date(
        &self,
        date: NaiveDate,
        start_date: NaiveDate,
    ) -> Result<bool, RecurringScheduleError> {
        if date < start_date {
            return Ok(false);
        }
        let days = (date - start_date).num_days();
        match self.frequency {
            RecurrenceFrequency::Daily => Ok(days % i64::from(self.interval) == 0),
            RecurrenceFrequency::Weekly => {
                let anchor_monday = start_date
                    .checked_sub_signed(Duration::days(weekday_index(start_date.weekday())))
                    .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
                let current_monday = date
                    .checked_sub_signed(Duration::days(weekday_index(date.weekday())))
                    .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
                let weeks = (current_monday - anchor_monday).num_days() / 7;
                Ok(weeks % i64::from(self.interval) == 0
                    && self
                        .weekdays
                        .contains(&ScheduleWeekday::from_chrono(date.weekday())))
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedOccurrence {
    pub ordinal: u64,
    pub requested_local: NaiveDateTime,
    pub resolved_local: NaiveDateTime,
    pub planned_at: DateTime<Utc>,
    pub offset_seconds: i32,
    pub resolution: DstResolution,
}

/// Explicit bounded handling for a wake that covers multiple recurrence ticks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LateWakePolicy {
    FailClosed,
    Coalesce { max_missed_ticks: u32 },
}

impl LateWakePolicy {
    pub fn validate(self) -> Result<(), RecurringScheduleError> {
        if let Self::Coalesce { max_missed_ticks } = self
            && !(1..=MAX_MISSED_TICKS).contains(&max_missed_ticks)
        {
            return Err(RecurringScheduleError::InvalidLateWakePolicy);
        }
        Ok(())
    }

    fn max_ticks(self) -> u32 {
        match self {
            Self::FailClosed => 1,
            Self::Coalesce { max_missed_ticks } => max_missed_ticks,
        }
    }
}

/// Durable worker lease revision used by every wake token and dispatch receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleLease {
    pub owner_digest: String,
    pub lease_revision: u64,
    pub generation: u64,
    pub expires_at: DateTime<Utc>,
    pub lease_digest: String,
}

impl ScheduleLease {
    pub fn new(
        owner_digest: impl Into<String>,
        lease_revision: u64,
        generation: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, RecurringScheduleError> {
        let mut lease = Self {
            owner_digest: owner_digest.into(),
            lease_revision,
            generation,
            expires_at,
            lease_digest: String::new(),
        };
        lease.lease_digest = lease.expected_digest()?;
        lease.validate()?;
        Ok(lease)
    }

    fn renewed(&self, at: DateTime<Utc>) -> Result<Self, RecurringScheduleError> {
        let expires_at = if self.expires_at > at {
            self.expires_at
        } else {
            at.checked_add_signed(Duration::hours(1))
                .ok_or(RecurringScheduleError::InvalidLease)?
        };
        Self::new(
            self.owner_digest.clone(),
            self.lease_revision
                .checked_add(1)
                .ok_or(RecurringScheduleError::InvalidLease)?,
            self.generation
                .checked_add(1)
                .ok_or(RecurringScheduleError::InvalidLease)?,
            expires_at,
        )
    }

    pub fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.lease_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.owner_digest)
            || self.lease_revision == 0
            || self.generation == 0
            || !is_digest(&self.lease_digest)
            || self.lease_digest != self.expected_digest()?
        {
            return Err(RecurringScheduleError::InvalidLease);
        }
        Ok(())
    }
}

/// Typed conversation result mounted by MissionScheduleService.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScheduleDraft {
    pub schedule_id_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub recurrence: RecurrenceRule,
    pub timezone: ScheduleTimezone,
    pub dst_policy: DstPolicy,
    pub late_wake_policy: LateWakePolicy,
    pub wake_contract_seconds: u64,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub lease: ScheduleLease,
}

impl MissionScheduleDraft {
    pub fn validate(&self) -> Result<(), RecurringScheduleError> {
        self.scope.validate()?;
        self.recurrence.validate()?;
        self.timezone.validate()?;
        self.dst_policy.validate()?;
        self.late_wake_policy.validate()?;
        self.lease.validate()?;
        self.composition.validate()?;
        validate_invocation(&self.invocation, &self.composition)?;
        if !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || self.composition.scope != self.scope
            || !(1..=MAX_WAKE_CONTRACT_SECONDS).contains(&self.wake_contract_seconds)
        {
            return Err(RecurringScheduleError::InvalidDraft);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionScheduleStatus {
    Active,
    Paused,
    Cancelled,
    Revoked,
    Completed,
    Dispatching,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleWakeRequest {
    pub token_digest: String,
    pub schedule_id_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub contract_valid_until: DateTime<Utc>,
    pub timezone_digest: String,
    pub recurrence_digest: String,
    pub composition_digest: String,
    pub invocation_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
}

impl ScheduleWakeRequest {
    fn validate(&self) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.token_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || !is_digest(&self.timezone_digest)
            || !is_digest(&self.recurrence_digest)
            || !is_digest(&self.composition_digest)
            || !is_digest(&self.invocation_digest)
            || !is_digest(&self.provider_id_digest)
            || self.schedule_revision == 0
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.clock_epoch == 0
            || self.planned_at >= self.contract_valid_until
        {
            return Err(RecurringScheduleError::InvalidWakeRequest);
        }
        self.scope.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleWakeReceipt {
    pub token_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub woke_at: DateTime<Utc>,
}

impl ScheduleWakeReceipt {
    fn validate_for(&self, request: &ScheduleWakeRequest) -> Result<(), RecurringScheduleError> {
        request.validate()?;
        if self.token_digest != request.token_digest
            || self.provider_id_digest != request.provider_id_digest
            || self.provider_epoch != request.provider_epoch
        {
            return Err(RecurringScheduleError::WakeReceiptConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchWakeToken {
    pub schedule_id_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub timezone_digest: String,
    pub recurrence_digest: String,
    pub dst_policy: DstPolicy,
    pub composition_digest: String,
    pub invocation_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub token_digest: String,
}

impl DispatchWakeToken {
    fn issue(
        record: &MissionScheduleRecord,
        occurrence: &ResolvedOccurrence,
    ) -> Result<Self, RecurringScheduleError> {
        let mut token = Self {
            schedule_id_digest: record.schedule_id_digest.clone(),
            objective_digest: record.objective_digest.clone(),
            scope: record.scope.clone(),
            schedule_revision: record.schedule_revision,
            planned_at: occurrence.planned_at,
            timezone_digest: record.timezone.timezone_digest.clone(),
            recurrence_digest: record.recurrence.recurrence_digest.clone(),
            dst_policy: record.dst_policy,
            composition_digest: record.composition.composition_digest.clone(),
            invocation_digest: record.invocation.digest()?,
            provider_id_digest: record.provider_id_digest.clone(),
            provider_epoch: record.provider_epoch,
            lease_revision: record.lease.lease_revision,
            clock_epoch: record.clock_epoch,
            token_digest: String::new(),
        };
        token.token_digest = token.expected_digest()?;
        token.validate_for(record, occurrence)?;
        Ok(token)
    }

    fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.token_digest.clear();
        digest_json(&material)
    }

    fn validate_for(
        &self,
        record: &MissionScheduleRecord,
        occurrence: &ResolvedOccurrence,
    ) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.token_digest)
            || self.token_digest != self.expected_digest()?
            || self.schedule_id_digest != record.schedule_id_digest
            || self.objective_digest != record.objective_digest
            || self.scope != record.scope
            || self.schedule_revision != record.schedule_revision
            || self.planned_at != occurrence.planned_at
            || self.timezone_digest != record.timezone.timezone_digest
            || self.recurrence_digest != record.recurrence.recurrence_digest
            || self.dst_policy != record.dst_policy
            || self.composition_digest != record.composition.composition_digest
            || self.invocation_digest != record.invocation.digest()?
            || self.provider_id_digest != record.provider_id_digest
            || self.provider_epoch != record.provider_epoch
            || self.lease_revision != record.lease.lease_revision
            || self.clock_epoch != record.clock_epoch
        {
            return Err(RecurringScheduleError::StaleWakeToken);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCapabilityRequest {
    pub dispatch_id_digest: String,
    pub wake_token_digest: String,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub scope: MissionScope,
    pub objective_digest: String,
    pub timezone: ScheduleTimezone,
    pub recurrence: RecurrenceRule,
    pub dst_policy: DstPolicy,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u32,
    pub next_run_at: Option<DateTime<Utc>>,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub authority: DispatchAuthority,
}

impl MissionCapabilityRequest {
    fn validate(&self) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.dispatch_id_digest)
            || !is_digest(&self.wake_token_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || !is_digest(&self.provider_id_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.clock_epoch == 0
            || self.authority != DispatchAuthority::CapabilityRequestOnly
        {
            return Err(RecurringScheduleError::InvalidCapabilityRequest);
        }
        self.scope.validate()?;
        self.timezone.validate()?;
        self.recurrence.validate()?;
        self.composition.validate()?;
        validate_invocation(&self.invocation, &self.composition)?;
        if self.composition.scope != self.scope {
            return Err(RecurringScheduleError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCapabilityAck {
    pub dispatch_id_digest: String,
    pub consumer_id_digest: String,
    pub requested_at: DateTime<Utc>,
    pub authority: DispatchAuthority,
    pub ack_digest: String,
}

impl MissionCapabilityAck {
    fn validate_for(
        &self,
        request: &MissionCapabilityRequest,
        consumer_id_digest: &str,
    ) -> Result<(), RecurringScheduleError> {
        if self.dispatch_id_digest != request.dispatch_id_digest
            || self.consumer_id_digest != consumer_id_digest
            || self.authority != DispatchAuthority::CapabilityRequestOnly
            || !is_digest(&self.ack_digest)
            || self.ack_digest != self.expected_digest()?
        {
            return Err(RecurringScheduleError::InvalidCapabilityAck);
        }
        Ok(())
    }

    pub fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.ack_digest.clear();
        digest_json(&material)
    }
}

/// Durable model-visible evidence for a capability-only recurring dispatch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCapabilityDispatchReceipt {
    pub receipt_id_digest: String,
    pub dispatch_id_digest: String,
    pub wake_token_digest: String,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub scope: MissionScope,
    pub objective_digest: String,
    pub timezone: ScheduleTimezone,
    pub recurrence: RecurrenceRule,
    pub dst_policy: DstPolicy,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u32,
    pub next_run_at: Option<DateTime<Utc>>,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub consumer_id_digest: String,
    pub requested_at: DateTime<Utc>,
    pub authority: DispatchAuthority,
    pub receipt_digest: String,
}

impl MissionCapabilityDispatchReceipt {
    fn from_parts(
        request: &MissionCapabilityRequest,
        ack: &MissionCapabilityAck,
    ) -> Result<Self, RecurringScheduleError> {
        request.validate()?;
        ack.validate_for(request, &ack.consumer_id_digest)?;
        let mut receipt = Self {
            receipt_id_digest: digest_json(&(
                request.dispatch_id_digest.clone(),
                ack.ack_digest.clone(),
            ))?,
            dispatch_id_digest: request.dispatch_id_digest.clone(),
            wake_token_digest: request.wake_token_digest.clone(),
            schedule_id_digest: request.schedule_id_digest.clone(),
            schedule_revision: request.schedule_revision,
            scope: request.scope.clone(),
            objective_digest: request.objective_digest.clone(),
            timezone: request.timezone.clone(),
            recurrence: request.recurrence.clone(),
            dst_policy: request.dst_policy,
            composition: request.composition.clone(),
            invocation: request.invocation.clone(),
            planned_at: request.planned_at,
            woke_at: request.woke_at,
            coalesced_ticks: request.coalesced_ticks,
            next_run_at: request.next_run_at,
            provider_id_digest: request.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            lease_revision: request.lease_revision,
            clock_epoch: request.clock_epoch,
            consumer_id_digest: ack.consumer_id_digest.clone(),
            requested_at: ack.requested_at,
            authority: DispatchAuthority::CapabilityRequestOnly,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.receipt_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.receipt_id_digest)
            || !is_digest(&self.dispatch_id_digest)
            || !is_digest(&self.wake_token_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || !is_digest(&self.provider_id_digest)
            || !is_digest(&self.consumer_id_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.clock_epoch == 0
            || self.authority != DispatchAuthority::CapabilityRequestOnly
            || self.receipt_digest != self.expected_digest()?
        {
            return Err(RecurringScheduleError::InvalidDispatchReceipt);
        }
        self.scope.validate()?;
        self.timezone.validate()?;
        self.recurrence.validate()?;
        self.composition.validate()?;
        validate_invocation(&self.invocation, &self.composition)?;
        if self.composition.scope != self.scope || self.timezone.timezone_digest.is_empty() {
            return Err(RecurringScheduleError::InvalidDispatchReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LateWakeRejection {
    MultipleTicksFailClosed,
    MissedTicksExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LateWakeReceipt {
    pub receipt_id_digest: String,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub wake_token_digest: String,
    pub woke_at: DateTime<Utc>,
    pub due_ticks: u32,
    pub next_run_at: Option<DateTime<Utc>>,
    pub rejection: LateWakeRejection,
    pub receipt_digest: String,
}

impl LateWakeReceipt {
    fn new(
        schedule_id_digest: &str,
        schedule_revision: u64,
        wake_token_digest: &str,
        woke_at: DateTime<Utc>,
        due_ticks: u32,
        next_run_at: Option<DateTime<Utc>>,
        rejection: LateWakeRejection,
    ) -> Result<Self, RecurringScheduleError> {
        let mut receipt = Self {
            receipt_id_digest: digest_json(&(
                schedule_id_digest,
                schedule_revision,
                wake_token_digest,
                woke_at,
            ))?,
            schedule_id_digest: schedule_id_digest.to_owned(),
            schedule_revision,
            wake_token_digest: wake_token_digest.to_owned(),
            woke_at,
            due_ticks,
            next_run_at,
            rejection,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn expected_id_digest(&self) -> Result<String, RecurringScheduleError> {
        digest_json(&(
            self.schedule_id_digest.clone(),
            self.schedule_revision,
            self.wake_token_digest.clone(),
            self.woke_at,
        ))
    }

    pub fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.receipt_digest.clear();
        digest_json(&material)
    }

    fn validate(&self) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.receipt_id_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.wake_token_digest)
            || !is_digest(&self.receipt_digest)
            || self.schedule_revision == 0
            || self.due_ticks == 0
            || self.receipt_id_digest != self.expected_id_digest()?
            || self.receipt_digest != self.expected_digest()?
        {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionScheduleEvent {
    Created,
    Paused,
    Resumed,
    Cancelled,
    Rescheduled,
    Revoked,
    LateWakeRejected,
}

/// Model-visible durable schedule log entry.  The complete recurrence and
/// plugin composition are included so a Mission can render the next run
/// without reading a dashboard-specific projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScheduleModelReceipt {
    pub event_id_digest: String,
    pub event: MissionScheduleEvent,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub scope: MissionScope,
    pub objective_digest: String,
    pub timezone: ScheduleTimezone,
    pub recurrence: RecurrenceRule,
    pub dst_policy: DstPolicy,
    pub late_wake_policy: LateWakePolicy,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub next_run_at: Option<DateTime<Utc>>,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub occurred_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl MissionScheduleModelReceipt {
    fn from_record(
        record: &MissionScheduleRecord,
        event: MissionScheduleEvent,
        occurred_at: DateTime<Utc>,
    ) -> Result<Self, RecurringScheduleError> {
        let mut receipt = Self {
            event_id_digest: digest_json(&(
                record.schedule_id_digest.clone(),
                record.schedule_revision,
                event,
                occurred_at,
            ))?,
            event,
            schedule_id_digest: record.schedule_id_digest.clone(),
            schedule_revision: record.schedule_revision,
            scope: record.scope.clone(),
            objective_digest: record.objective_digest.clone(),
            timezone: record.timezone.clone(),
            recurrence: record.recurrence.clone(),
            dst_policy: record.dst_policy,
            late_wake_policy: record.late_wake_policy,
            composition: record.composition.clone(),
            invocation: record.invocation.clone(),
            next_run_at: record
                .next_occurrence
                .as_ref()
                .map(|occurrence| occurrence.planned_at),
            provider_id_digest: record.provider_id_digest.clone(),
            provider_epoch: record.provider_epoch,
            lease_revision: record.lease.lease_revision,
            clock_epoch: record.clock_epoch,
            occurred_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn expected_event_id_digest(&self) -> Result<String, RecurringScheduleError> {
        digest_json(&(
            self.schedule_id_digest.clone(),
            self.schedule_revision,
            self.event,
            self.occurred_at,
        ))
    }

    fn expected_digest(&self) -> Result<String, RecurringScheduleError> {
        let mut material = self.clone();
        material.receipt_digest.clear();
        digest_json(&material)
    }

    fn validate(&self) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.event_id_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || !is_digest(&self.provider_id_digest)
            || !is_digest(&self.receipt_digest)
            || self.schedule_revision == 0
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.clock_epoch == 0
            || self.event_id_digest != self.expected_event_id_digest()?
            || self.receipt_digest != self.expected_digest()?
        {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        self.scope.validate()?;
        self.timezone.validate()?;
        self.recurrence.validate()?;
        self.late_wake_policy.validate()?;
        self.composition.validate()?;
        validate_invocation(&self.invocation, &self.composition)?;
        if self.composition.scope != self.scope {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleDispatchReservation {
    pub token: DispatchWakeToken,
    pub due_occurrences: Vec<ResolvedOccurrence>,
    pub next_occurrence: Option<ResolvedOccurrence>,
    pub coalesced_ticks: u32,
    pub woke_at: DateTime<Utc>,
    pub dispatch_id_digest: String,
    pub schedule_revision: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub reserved_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScheduleRecord {
    pub schedule_id_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_revision: u64,
    pub recurrence: RecurrenceRule,
    pub timezone: ScheduleTimezone,
    pub dst_policy: DstPolicy,
    pub late_wake_policy: LateWakePolicy,
    pub wake_contract_seconds: u64,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub clock_epoch: u64,
    pub lease: ScheduleLease,
    pub status: MissionScheduleStatus,
    pub next_occurrence: Option<ResolvedOccurrence>,
    pub armed_wake: Option<ScheduleWakeRequest>,
    pub armed_receipt: Option<ScheduleWakeReceipt>,
    pub pending_dispatch: Option<ScheduleDispatchReservation>,
    pub last_observed_at: DateTime<Utc>,
    pub last_woke_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

impl MissionScheduleRecord {
    fn from_draft(
        draft: &MissionScheduleDraft,
        provider_id_digest: &str,
        provider_epoch: u64,
        clock_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, RecurringScheduleError> {
        draft.validate()?;
        let after = observed_at
            .checked_sub_signed(Duration::nanoseconds(1))
            .ok_or(RecurringScheduleError::InvalidRecurrence)?;
        let next_occurrence = draft
            .recurrence
            .first_after(after, &draft.timezone, draft.dst_policy)?
            .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
        Ok(Self {
            schedule_id_digest: draft.schedule_id_digest.clone(),
            objective_digest: draft.objective_digest.clone(),
            scope: draft.scope.clone(),
            schedule_revision: 1,
            recurrence: draft.recurrence.clone(),
            timezone: draft.timezone.clone(),
            dst_policy: draft.dst_policy,
            late_wake_policy: draft.late_wake_policy,
            wake_contract_seconds: draft.wake_contract_seconds,
            composition: draft.composition.clone(),
            invocation: draft.invocation.clone(),
            provider_id_digest: provider_id_digest.to_owned(),
            provider_epoch,
            clock_epoch,
            lease: draft.lease.clone(),
            status: MissionScheduleStatus::Active,
            next_occurrence: Some(next_occurrence),
            armed_wake: None,
            armed_receipt: None,
            pending_dispatch: None,
            last_observed_at: observed_at,
            last_woke_at: None,
            updated_at: observed_at,
        })
    }

    fn validate(&self, provider_id_digest: &str) -> Result<(), RecurringScheduleError> {
        if !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || self.schedule_revision == 0
            || self.provider_id_digest != provider_id_digest
            || self.provider_epoch == 0
            || self.clock_epoch == 0
            || !(1..=MAX_WAKE_CONTRACT_SECONDS).contains(&self.wake_contract_seconds)
        {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        self.scope.validate()?;
        self.recurrence.validate()?;
        self.timezone.validate()?;
        self.dst_policy.validate()?;
        self.late_wake_policy.validate()?;
        self.composition.validate()?;
        validate_invocation(&self.invocation, &self.composition)?;
        self.lease.validate()?;
        if self.composition.scope != self.scope {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        if let (Some(request), Some(receipt), Some(occurrence)) = (
            self.armed_wake.as_ref(),
            self.armed_receipt.as_ref(),
            self.next_occurrence.as_ref(),
        ) {
            request.validate()?;
            receipt.validate_for(request)?;
            let token = DispatchWakeToken::issue(self, occurrence)?;
            if request.token_digest != token.token_digest
                || request.schedule_revision != self.schedule_revision
                || request.planned_at != occurrence.planned_at
            {
                return Err(RecurringScheduleError::CorruptSchedule);
            }
        } else if self.armed_wake.is_some() || self.armed_receipt.is_some() {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        if let Some(reservation) = &self.pending_dispatch {
            reservation.validate(self)?;
        }
        if self.status == MissionScheduleStatus::Dispatching && self.pending_dispatch.is_none() {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        if self.status != MissionScheduleStatus::Dispatching && self.pending_dispatch.is_some() {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        Ok(())
    }
}

impl ScheduleDispatchReservation {
    fn validate(&self, record: &MissionScheduleRecord) -> Result<(), RecurringScheduleError> {
        let due_ticks = u32::try_from(self.due_occurrences.len())
            .map_err(|_| RecurringScheduleError::CorruptSchedule)?;
        if self.due_occurrences.is_empty()
            || self.coalesced_ticks != due_ticks
            || self.schedule_revision != record.schedule_revision
            || self.lease_revision != record.lease.lease_revision
            || self.clock_epoch != record.clock_epoch
            || !is_digest(&self.dispatch_id_digest)
        {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        let first = self
            .due_occurrences
            .first()
            .ok_or(RecurringScheduleError::CorruptSchedule)?;
        self.token.validate_for(record, first)?;
        if let Some(armed) = &record.armed_wake
            && self.token.token_digest != armed.token_digest
        {
            return Err(RecurringScheduleError::CorruptSchedule);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScheduleSnapshot {
    pub schedules: Vec<MissionScheduleRecord>,
    pub model_receipts: Vec<MissionScheduleModelReceipt>,
    pub dispatch_receipts: Vec<MissionCapabilityDispatchReceipt>,
    pub late_wake_receipts: Vec<LateWakeReceipt>,
    pub revoked_plugins: Vec<PluginManifest>,
    pub clock_epoch: u64,
    #[serde(default)]
    pub provider_epoch: u64,
    #[serde(default)]
    pub wake_uncertainty: Option<WakeStateUncertainty>,
}

/// Durable fail-closed marker for a provider wake transition whose external
/// state could not be restored after a rejected snapshot write.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeStateUncertainty {
    pub operation: String,
    pub schedule_id_digest: Option<String>,
    pub store_error: String,
    pub compensation_error: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MissionScheduleStoreError {
    #[error("mission schedule snapshot serialization failed: {0}")]
    Serialization(String),
    #[error("mission schedule snapshot is corrupt")]
    Corrupt,
    #[error("mission schedule SQLite store failed: {0}")]
    Sqlite(String),
    #[error("mission schedule store rejected a write")]
    WriteRejected,
}

pub trait MissionScheduleStore: fmt::Debug {
    fn load(&self) -> Result<MissionScheduleSnapshot, MissionScheduleStoreError>;
    fn save(&mut self, snapshot: &MissionScheduleSnapshot)
    -> Result<(), MissionScheduleStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryMissionScheduleStore {
    snapshot: MissionScheduleSnapshot,
}

impl MemoryMissionScheduleStore {
    pub fn snapshot(&self) -> &MissionScheduleSnapshot {
        &self.snapshot
    }
}

impl MissionScheduleStore for MemoryMissionScheduleStore {
    fn load(&self) -> Result<MissionScheduleSnapshot, MissionScheduleStoreError> {
        Ok(self.snapshot.clone())
    }

    fn save(
        &mut self,
        snapshot: &MissionScheduleSnapshot,
    ) -> Result<(), MissionScheduleStoreError> {
        self.snapshot = snapshot.clone();
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqliteMissionScheduleStore {
    connection: Connection,
}

impl SqliteMissionScheduleStore {
    pub fn open_in_memory() -> Result<Self, MissionScheduleStoreError> {
        Self::new(Connection::open_in_memory().map_err(|error| sqlite_error(&error))?)
    }

    pub fn new(connection: Connection) -> Result<Self, MissionScheduleStoreError> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scheduler_recurring_missions (
                    snapshot_id INTEGER PRIMARY KEY CHECK (snapshot_id = 1),
                    snapshot_json TEXT NOT NULL
                )",
            )
            .map_err(|error| sqlite_error(&error))?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl MissionScheduleStore for SqliteMissionScheduleStore {
    fn load(&self) -> Result<MissionScheduleSnapshot, MissionScheduleStoreError> {
        let json = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM scheduler_recurring_missions WHERE snapshot_id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| sqlite_error(&error))?;
        json.map_or_else(
            || Ok(MissionScheduleSnapshot::default()),
            |value| {
                serde_json::from_str(&value)
                    .map_err(|error| MissionScheduleStoreError::Serialization(error.to_string()))
            },
        )
    }

    fn save(
        &mut self,
        snapshot: &MissionScheduleSnapshot,
    ) -> Result<(), MissionScheduleStoreError> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| MissionScheduleStoreError::Serialization(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO scheduler_recurring_missions(snapshot_id, snapshot_json)
                 VALUES (1, ?1)
                 ON CONFLICT(snapshot_id) DO UPDATE SET snapshot_json = excluded.snapshot_json",
                params![json],
            )
            .map_err(|error| sqlite_error(&error))?;
        Ok(())
    }
}

fn sqlite_error(error: &rusqlite::Error) -> MissionScheduleStoreError {
    MissionScheduleStoreError::Sqlite(error.to_string())
}

/// OS/Cell wake provider.  It only arms/disarms typed wake requests and never
/// exposes Runtime, Browser, or Effect authority.
pub trait MissionScheduleWakeProvider: fmt::Debug {
    fn provider_id_digest(&self) -> &str;
    fn provider_epoch(&self) -> u64;
    fn arm_wake(
        &mut self,
        request: &ScheduleWakeRequest,
    ) -> Result<ScheduleWakeReceipt, MissionScheduleProviderError>;
    fn disarm_wake(
        &mut self,
        receipt: &ScheduleWakeReceipt,
    ) -> Result<(), MissionScheduleProviderError>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MissionScheduleProviderError {
    #[error("mission schedule provider identity or epoch is stale")]
    EpochLost,
    #[error("mission schedule provider wake receipt conflicts")]
    ReceiptConflict,
    #[error("mission schedule provider wake request is unavailable")]
    Unavailable,
    #[error("mission schedule provider backend failed")]
    Backend,
}

/// Mission consumer boundary.  The request is explicitly capability-only and
/// does not grant Effect execution or completion authority.
pub trait MissionCapabilityConsumer: fmt::Debug {
    fn consumer_id_digest(&self) -> &str;
    fn request_capability(
        &mut self,
        request: &MissionCapabilityRequest,
    ) -> Result<MissionCapabilityAck, MissionCapabilityConsumerError>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MissionCapabilityConsumerError {
    #[error("mission capability consumer identity is invalid")]
    IdentityMismatch,
    #[error("mission capability consumer rejected the exact request")]
    Rejected,
    #[error("mission capability consumer backend failed")]
    Backend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleLifecycleResult {
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub lease_revision: u64,
    pub status: MissionScheduleStatus,
    pub next_run_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleRescheduleCommand {
    pub schedule_id_digest: String,
    pub expected_schedule_revision: u64,
    pub expected_lease_revision: u64,
    pub new_schedule_revision: u64,
    pub recurrence: RecurrenceRule,
    pub timezone: ScheduleTimezone,
    pub dst_policy: DstPolicy,
    pub late_wake_policy: LateWakePolicy,
    pub wake_contract_seconds: u64,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakePreparation {
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub token: DispatchWakeToken,
    pub due_occurrences: Vec<ResolvedOccurrence>,
    pub next_occurrence: Option<ResolvedOccurrence>,
    pub woke_at: DateTime<Utc>,
    pub dispatch_id_digest: String,
    pub late_rejection: Option<LateWakeRejection>,
}

type DueCollection = (
    Vec<ResolvedOccurrence>,
    Option<ResolvedOccurrence>,
    Option<LateWakeRejection>,
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MissionScheduleWakeOutcome {
    Dispatched(MissionCapabilityDispatchReceipt),
    AlreadyDispatched(MissionCapabilityDispatchReceipt),
    LateRejected(LateWakeReceipt),
}

/// Durable service for conversation-authored recurring Mission schedules.
#[derive(Debug)]
pub struct MissionScheduleService<P, C, S = MemoryMissionScheduleStore> {
    provider: P,
    consumer: C,
    store: S,
    provider_id_digest: String,
    provider_epoch: u64,
    clock_epoch: u64,
    schedules: BTreeMap<String, MissionScheduleRecord>,
    model_receipts: Vec<MissionScheduleModelReceipt>,
    dispatch_receipts: BTreeMap<String, MissionCapabilityDispatchReceipt>,
    late_wake_receipts: Vec<LateWakeReceipt>,
    revoked_plugins: BTreeSet<PluginManifest>,
    wake_uncertainty: Option<WakeStateUncertainty>,
}

pub type ScheduledMissionScheduleService<P, C, S = MemoryMissionScheduleStore> =
    MissionScheduleService<P, C, S>;

impl<P, C> MissionScheduleService<P, C, MemoryMissionScheduleStore>
where
    P: MissionScheduleWakeProvider,
    C: MissionCapabilityConsumer,
{
    pub fn new(provider: P, consumer: C) -> Result<Self, RecurringScheduleError> {
        Self::with_store(provider, consumer, MemoryMissionScheduleStore::default())
    }
}

impl<P, C, S> MissionScheduleService<P, C, S>
where
    P: MissionScheduleWakeProvider,
    C: MissionCapabilityConsumer,
    S: MissionScheduleStore,
{
    pub fn with_store(provider: P, consumer: C, store: S) -> Result<Self, RecurringScheduleError> {
        let provider_id_digest = provider.provider_id_digest().to_owned();
        let provider_epoch = provider.provider_epoch();
        if !is_digest(&provider_id_digest) || provider_epoch == 0 {
            return Err(RecurringScheduleError::InvalidProvider);
        }
        let snapshot = store.load()?;
        let wake_uncertainty = snapshot.wake_uncertainty.clone();
        let mut schedules = BTreeMap::new();
        let mut clock_epoch = snapshot.clock_epoch;
        for schedule in snapshot.schedules {
            schedule.validate(&provider_id_digest)?;
            if schedules
                .insert(schedule.schedule_id_digest.clone(), schedule.clone())
                .is_some()
            {
                return Err(RecurringScheduleError::CorruptSchedule);
            }
            clock_epoch = clock_epoch.max(schedule.clock_epoch);
        }
        for receipt in &snapshot.dispatch_receipts {
            receipt.validate()?;
        }
        for receipt in &snapshot.model_receipts {
            receipt.validate()?;
        }
        for receipt in &snapshot.late_wake_receipts {
            receipt.validate()?;
        }
        for plugin in &snapshot.revoked_plugins {
            plugin.validate()?;
        }
        if clock_epoch == 0 {
            clock_epoch = 1;
        }
        let dispatch_receipts = snapshot
            .dispatch_receipts
            .into_iter()
            .map(|receipt| (receipt.dispatch_id_digest.clone(), receipt))
            .collect();
        Ok(Self {
            provider,
            consumer,
            store,
            provider_id_digest,
            provider_epoch,
            clock_epoch,
            schedules,
            model_receipts: snapshot.model_receipts,
            dispatch_receipts,
            late_wake_receipts: snapshot.late_wake_receipts,
            revoked_plugins: snapshot.revoked_plugins.into_iter().collect(),
            wake_uncertainty,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn consumer(&self) -> &C {
        &self.consumer
    }

    pub fn consumer_mut(&mut self) -> &mut C {
        &mut self.consumer
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn schedule(&self, schedule_id_digest: &str) -> Option<&MissionScheduleRecord> {
        self.schedules.get(schedule_id_digest)
    }

    pub fn model_receipts(&self) -> &[MissionScheduleModelReceipt] {
        &self.model_receipts
    }

    pub fn dispatch_receipt(
        &self,
        dispatch_id_digest: &str,
    ) -> Option<&MissionCapabilityDispatchReceipt> {
        self.dispatch_receipts.get(dispatch_id_digest)
    }

    pub fn snapshot(&self) -> MissionScheduleSnapshot {
        MissionScheduleSnapshot {
            schedules: self.schedules.values().cloned().collect(),
            model_receipts: self.model_receipts.clone(),
            dispatch_receipts: self.dispatch_receipts.values().cloned().collect(),
            late_wake_receipts: self.late_wake_receipts.clone(),
            revoked_plugins: self.revoked_plugins.iter().cloned().collect(),
            clock_epoch: self.clock_epoch,
            provider_epoch: self.provider_epoch,
            wake_uncertainty: self.wake_uncertainty.clone(),
        }
    }

    pub fn wake_uncertainty(&self) -> Option<&WakeStateUncertainty> {
        self.wake_uncertainty.as_ref()
    }

    /// Persist a new exact conversation-authored schedule and arm its first
    /// occurrence.  Exact duplicate drafts are idempotent; conflicting
    /// schedule IDs fail closed.
    pub fn create(
        &mut self,
        draft: &MissionScheduleDraft,
        observed_at: DateTime<Utc>,
    ) -> Result<MissionScheduleModelReceipt, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        let before = self.snapshot();
        draft.validate()?;
        if draft.lease.expires_at <= observed_at {
            return Err(RecurringScheduleError::LeaseExpired);
        }
        if draft
            .composition
            .plugins
            .iter()
            .any(|plugin| self.revoked_plugins.contains(plugin))
        {
            return Err(RecurringScheduleError::PluginRevoked);
        }
        if let Some(existing) = self.schedules.get(&draft.schedule_id_digest) {
            if Self::matches_draft(existing, draft) {
                return self
                    .model_receipts
                    .iter()
                    .rev()
                    .find(|receipt| receipt.schedule_id_digest == draft.schedule_id_digest)
                    .cloned()
                    .ok_or(RecurringScheduleError::CorruptSchedule);
            }
            return Err(RecurringScheduleError::ScheduleConflict);
        }
        if draft.lease.lease_revision != 1 || draft.lease.generation != 1 {
            return Err(RecurringScheduleError::InvalidLease);
        }
        if self.provider_epoch != self.provider.provider_epoch() {
            return Err(RecurringScheduleError::ProviderEpochLost);
        }
        let mut record = MissionScheduleRecord::from_draft(
            draft,
            &self.provider_id_digest,
            self.provider_epoch,
            self.clock_epoch,
            observed_at,
        )?;
        self.arm_record(&mut record)?;
        let receipt = MissionScheduleModelReceipt::from_record(
            &record,
            MissionScheduleEvent::Created,
            observed_at,
        )?;
        self.insert_record(record, receipt.clone(), &before)?;
        Ok(receipt)
    }

    /// Prepare a wake.  The final CAS is intentionally separate so a
    /// cancellation/reschedule can win after wake resolution but before the
    /// capability request is handed to the Mission consumer.
    pub fn prepare_wake(
        &mut self,
        token: &DispatchWakeToken,
        woke_at: DateTime<Utc>,
    ) -> Result<WakePreparation, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        let record = self
            .schedules
            .get(&token.schedule_id_digest)
            .cloned()
            .ok_or(RecurringScheduleError::ScheduleNotFound)?;
        if record.status != MissionScheduleStatus::Dispatching {
            Self::validate_token(&record, token)?;
        }
        if record.status == MissionScheduleStatus::Dispatching {
            let pending = record
                .pending_dispatch
                .as_ref()
                .ok_or(RecurringScheduleError::DispatchReserved)?;
            if pending.token != *token {
                return Err(RecurringScheduleError::StaleWakeToken);
            }
            return Ok(WakePreparation {
                schedule_id_digest: record.schedule_id_digest.clone(),
                schedule_revision: pending.schedule_revision,
                lease_revision: pending.lease_revision,
                clock_epoch: pending.clock_epoch,
                token: pending.token.clone(),
                due_occurrences: pending.due_occurrences.clone(),
                next_occurrence: pending.next_occurrence.clone(),
                woke_at: pending.woke_at,
                dispatch_id_digest: pending.dispatch_id_digest.clone(),
                late_rejection: None,
            });
        }
        if record.status != MissionScheduleStatus::Active {
            return Err(status_error(record.status));
        }
        if woke_at < record.last_observed_at {
            return Err(RecurringScheduleError::ClockRollback);
        }
        if !record.lease_is_live(woke_at) {
            return Err(RecurringScheduleError::LeaseExpired);
        }
        let next = record
            .next_occurrence
            .clone()
            .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
        let (due, next_occurrence, rejection) = Self::collect_due(&record, &next, woke_at)?;
        if due.is_empty() {
            return Err(RecurringScheduleError::WakeNotDue);
        }
        let coalesced_ticks =
            u32::try_from(due.len()).map_err(|_| RecurringScheduleError::InvalidWakePreparation)?;
        let dispatch_id_digest = digest_json(&(
            token.token_digest.clone(),
            woke_at,
            coalesced_ticks,
            next_occurrence
                .as_ref()
                .map(|occurrence| occurrence.planned_at),
        ))?;
        Ok(WakePreparation {
            schedule_id_digest: record.schedule_id_digest,
            schedule_revision: record.schedule_revision,
            lease_revision: record.lease.lease_revision,
            clock_epoch: record.clock_epoch,
            token: token.clone(),
            due_occurrences: due,
            next_occurrence,
            woke_at,
            dispatch_id_digest,
            late_rejection: rejection,
        })
    }

    /// Commit a prepared wake.  The reservation is durable before the Mission
    /// consumer is called; retry therefore reuses the same dispatch digest.
    pub fn commit_wake(
        &mut self,
        preparation: &WakePreparation,
    ) -> Result<MissionScheduleWakeOutcome, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        let current = self
            .schedules
            .get(&preparation.schedule_id_digest)
            .cloned()
            .ok_or(RecurringScheduleError::ScheduleNotFound)?;
        self.validate_preparation(&current, preparation)?;
        if let Some(existing) = self.dispatch_receipts.get(&preparation.dispatch_id_digest) {
            return Ok(MissionScheduleWakeOutcome::AlreadyDispatched(
                existing.clone(),
            ));
        }
        if let Some(pending) = &current.pending_dispatch
            && pending.dispatch_id_digest != preparation.dispatch_id_digest
        {
            return Err(RecurringScheduleError::DispatchReserved);
        }
        if let Some(rejection) = preparation.late_rejection {
            return self.commit_late_rejection(&current, preparation, rejection);
        }
        let (reservation, reserved) = if let Some(pending) = &current.pending_dispatch {
            (pending.clone(), current.clone())
        } else {
            let reservation = ScheduleDispatchReservation {
                token: preparation.token.clone(),
                due_occurrences: preparation.due_occurrences.clone(),
                next_occurrence: preparation.next_occurrence.clone(),
                coalesced_ticks: u32::try_from(preparation.due_occurrences.len())
                    .map_err(|_| RecurringScheduleError::InvalidWakePreparation)?,
                woke_at: preparation.woke_at,
                dispatch_id_digest: preparation.dispatch_id_digest.clone(),
                schedule_revision: preparation.schedule_revision,
                lease_revision: preparation.lease_revision,
                clock_epoch: preparation.clock_epoch,
                reserved_at: preparation.woke_at,
            };
            let mut reserved = current.clone();
            reserved.status = MissionScheduleStatus::Dispatching;
            reserved.pending_dispatch = Some(reservation.clone());
            reserved.armed_wake = None;
            reserved.armed_receipt = None;
            reserved.last_observed_at = preparation.woke_at;
            reserved.last_woke_at = Some(preparation.woke_at);
            reserved.updated_at = preparation.woke_at;
            let before_reservation = self.snapshot();
            if let Some(receipt) = &current.armed_receipt {
                self.provider
                    .disarm_wake(receipt)
                    .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
            }
            self.replace_schedule(reserved.clone(), &before_reservation)?;
            (reservation, reserved)
        };

        let request = Self::capability_request(&reserved, &reservation)?;
        let ack = self
            .consumer
            .request_capability(&request)
            .map_err(|error| RecurringScheduleError::Consumer(error.to_string()))?;
        ack.validate_for(&request, self.consumer.consumer_id_digest())?;
        let receipt = MissionCapabilityDispatchReceipt::from_parts(&request, &ack)?;
        let mut completed = reserved;
        completed.status = if preparation.next_occurrence.is_some() {
            MissionScheduleStatus::Active
        } else {
            MissionScheduleStatus::Completed
        };
        completed
            .next_occurrence
            .clone_from(&preparation.next_occurrence);
        completed.pending_dispatch = None;
        let before_completion = self.snapshot();
        if completed.status == MissionScheduleStatus::Active {
            self.arm_record(&mut completed)?;
        }
        completed.updated_at = ack.requested_at;
        self.complete_dispatch(completed, &receipt, &before_completion)?;
        Ok(MissionScheduleWakeOutcome::Dispatched(receipt))
    }

    pub fn wake_once(
        &mut self,
        token: &DispatchWakeToken,
        woke_at: DateTime<Utc>,
    ) -> Result<MissionScheduleWakeOutcome, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        if let Some(existing) = self.dispatch_receipts.values().find(|receipt| {
            receipt.wake_token_digest == token.token_digest
                && receipt.schedule_id_digest == token.schedule_id_digest
                && receipt.planned_at == token.planned_at
                && receipt.schedule_revision == token.schedule_revision
        }) {
            return Ok(MissionScheduleWakeOutcome::AlreadyDispatched(
                existing.clone(),
            ));
        }
        let preparation = self.prepare_wake(token, woke_at)?;
        self.commit_wake(&preparation)
    }

    pub fn pause(
        &mut self,
        schedule_id_digest: &str,
        expected_schedule_revision: u64,
        expected_lease_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<ScheduleLifecycleResult, RecurringScheduleError> {
        self.mutate_status(
            schedule_id_digest,
            expected_schedule_revision,
            expected_lease_revision,
            MissionScheduleStatus::Paused,
            MissionScheduleEvent::Paused,
            observed_at,
        )
    }

    pub fn resume(
        &mut self,
        schedule_id_digest: &str,
        expected_schedule_revision: u64,
        expected_lease_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<ScheduleLifecycleResult, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        let current = self
            .schedules
            .get(schedule_id_digest)
            .cloned()
            .ok_or(RecurringScheduleError::ScheduleNotFound)?;
        Self::ensure_cas(
            &current,
            expected_schedule_revision,
            expected_lease_revision,
        )?;
        if current.status != MissionScheduleStatus::Paused {
            return Err(status_error(current.status));
        }
        let new_lease = current.lease.renewed(observed_at)?;
        let after = observed_at
            .checked_sub_signed(Duration::nanoseconds(1))
            .ok_or(RecurringScheduleError::InvalidRecurrence)?;
        let next = current
            .recurrence
            .first_after(after, &current.timezone, current.dst_policy)?;
        let before = self.snapshot();
        let old_receipt = current.armed_receipt.clone();
        let mut resumed = current;
        resumed.schedule_revision = resumed
            .schedule_revision
            .checked_add(1)
            .ok_or(RecurringScheduleError::InvalidScheduleRevision)?;
        resumed.lease = new_lease;
        resumed.status = if next.is_some() {
            MissionScheduleStatus::Active
        } else {
            MissionScheduleStatus::Completed
        };
        resumed.next_occurrence = next;
        resumed.pending_dispatch = None;
        resumed.armed_wake = None;
        resumed.armed_receipt = None;
        resumed.last_observed_at = observed_at;
        resumed.updated_at = observed_at;
        if let Some(receipt) = old_receipt.as_ref() {
            self.provider
                .disarm_wake(receipt)
                .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
        }
        if resumed.status == MissionScheduleStatus::Active {
            self.arm_record(&mut resumed)?;
        }
        let receipt = MissionScheduleModelReceipt::from_record(
            &resumed,
            MissionScheduleEvent::Resumed,
            observed_at,
        )?;
        self.replace_with_receipt(resumed.clone(), receipt, &before)?;
        Ok(lifecycle_result(&resumed))
    }

    pub fn cancel(
        &mut self,
        schedule_id_digest: &str,
        expected_schedule_revision: u64,
        expected_lease_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<ScheduleLifecycleResult, RecurringScheduleError> {
        self.mutate_status(
            schedule_id_digest,
            expected_schedule_revision,
            expected_lease_revision,
            MissionScheduleStatus::Cancelled,
            MissionScheduleEvent::Cancelled,
            observed_at,
        )
    }

    pub fn reschedule(
        &mut self,
        command: ScheduleRescheduleCommand,
    ) -> Result<ScheduleLifecycleResult, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        command.recurrence.validate()?;
        command.timezone.validate()?;
        command.dst_policy.validate()?;
        command.late_wake_policy.validate()?;
        command.composition.validate()?;
        validate_invocation(&command.invocation, &command.composition)?;
        if command.new_schedule_revision == 0
            || command.new_schedule_revision <= command.expected_schedule_revision
            || !(1..=MAX_WAKE_CONTRACT_SECONDS).contains(&command.wake_contract_seconds)
        {
            return Err(RecurringScheduleError::InvalidScheduleRevision);
        }
        let current = self
            .schedules
            .get(&command.schedule_id_digest)
            .cloned()
            .ok_or(RecurringScheduleError::ScheduleNotFound)?;
        Self::ensure_cas(
            &current,
            command.expected_schedule_revision,
            command.expected_lease_revision,
        )?;
        if matches!(
            current.status,
            MissionScheduleStatus::Dispatching
                | MissionScheduleStatus::Cancelled
                | MissionScheduleStatus::Revoked
        ) {
            return Err(RecurringScheduleError::DispatchReserved);
        }
        if command.composition.scope != current.scope {
            return Err(RecurringScheduleError::ScopeMismatch);
        }
        let after = command
            .observed_at
            .checked_sub_signed(Duration::nanoseconds(1))
            .ok_or(RecurringScheduleError::InvalidRecurrence)?;
        let next = command
            .recurrence
            .first_after(after, &command.timezone, command.dst_policy)?;
        let before = self.snapshot();
        if let Some(receipt) = &current.armed_receipt {
            self.provider
                .disarm_wake(receipt)
                .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
        }
        let mut next_record = current;
        next_record.schedule_revision = command.new_schedule_revision;
        next_record.recurrence = command.recurrence;
        next_record.timezone = command.timezone;
        next_record.dst_policy = command.dst_policy;
        next_record.late_wake_policy = command.late_wake_policy;
        next_record.wake_contract_seconds = command.wake_contract_seconds;
        next_record.composition = command.composition;
        next_record.invocation = command.invocation;
        next_record.lease = next_record.lease.renewed(command.observed_at)?;
        next_record.status = if next.is_some() {
            MissionScheduleStatus::Active
        } else {
            MissionScheduleStatus::Completed
        };
        next_record.next_occurrence = next;
        next_record.armed_wake = None;
        next_record.armed_receipt = None;
        next_record.pending_dispatch = None;
        next_record.last_observed_at = command.observed_at;
        next_record.updated_at = command.observed_at;
        if next_record.status == MissionScheduleStatus::Active {
            self.arm_record(&mut next_record)?;
        }
        let receipt = MissionScheduleModelReceipt::from_record(
            &next_record,
            MissionScheduleEvent::Rescheduled,
            command.observed_at,
        )?;
        self.replace_with_receipt(next_record.clone(), receipt, &before)?;
        Ok(lifecycle_result(&next_record))
    }

    /// Rebinds all active schedules to a new OS/Cell provider epoch after
    /// sleep/resume or restart.  All old epoch wake tokens become stale.
    pub fn rebind_provider_epoch(
        &mut self,
        new_provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        if new_provider_epoch == 0
            || new_provider_epoch <= self.provider_epoch
            || self.provider.provider_epoch() != new_provider_epoch
        {
            return Err(RecurringScheduleError::ProviderEpochLost);
        }
        if self
            .schedules
            .values()
            .any(|record| record.status == MissionScheduleStatus::Dispatching)
        {
            return Err(RecurringScheduleError::DispatchReserved);
        }
        let before = self.snapshot();
        self.provider_epoch = new_provider_epoch;
        self.clock_epoch = self
            .clock_epoch
            .checked_add(1)
            .ok_or(RecurringScheduleError::ClockEpochExhausted)?;
        let ids = self.schedules.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let mut record = self
                .schedules
                .get(&id)
                .cloned()
                .ok_or(RecurringScheduleError::ScheduleNotFound)?;
            if let Some(receipt) = &record.armed_receipt {
                self.provider
                    .disarm_wake(receipt)
                    .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
            }
            record.provider_epoch = new_provider_epoch;
            record.clock_epoch = self.clock_epoch;
            record.armed_wake = None;
            record.armed_receipt = None;
            record.updated_at = observed_at;
            if record.status == MissionScheduleStatus::Active {
                self.arm_record(&mut record)?;
            }
            self.schedules.insert(id, record);
        }
        self.persist_wake_transition(&before, "rebind_provider_epoch")
    }

    pub fn revoke_plugin(
        &mut self,
        plugin: &PluginManifest,
        observed_at: DateTime<Utc>,
    ) -> Result<Vec<ScheduleLifecycleResult>, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        plugin.validate()?;
        let before = self.snapshot();
        self.revoked_plugins.insert(plugin.clone());
        let ids = self.schedules.keys().cloned().collect::<Vec<_>>();
        let mut results = Vec::new();
        for id in ids {
            let current = self
                .schedules
                .get(&id)
                .cloned()
                .ok_or(RecurringScheduleError::ScheduleNotFound)?;
            if !current.composition.contains(plugin)
                || matches!(
                    current.status,
                    MissionScheduleStatus::Cancelled
                        | MissionScheduleStatus::Revoked
                        | MissionScheduleStatus::Completed
                )
            {
                continue;
            }
            if current.status == MissionScheduleStatus::Dispatching {
                self.restore_memory(&before);
                return Err(RecurringScheduleError::DispatchReserved);
            }
            if let Some(receipt) = &current.armed_receipt {
                self.provider
                    .disarm_wake(receipt)
                    .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
            }
            let mut revoked = current;
            revoked.status = MissionScheduleStatus::Revoked;
            revoked.schedule_revision = revoked
                .schedule_revision
                .checked_add(1)
                .ok_or(RecurringScheduleError::InvalidScheduleRevision)?;
            revoked.lease = revoked.lease.renewed(observed_at)?;
            revoked.armed_wake = None;
            revoked.armed_receipt = None;
            revoked.updated_at = observed_at;
            let receipt = MissionScheduleModelReceipt::from_record(
                &revoked,
                MissionScheduleEvent::Revoked,
                observed_at,
            )?;
            results.push(lifecycle_result(&revoked));
            self.schedules.insert(id, revoked);
            self.model_receipts.push(receipt);
        }
        self.persist_wake_transition(&before, "revoke_plugin")?;
        Ok(results)
    }

    fn matches_draft(record: &MissionScheduleRecord, draft: &MissionScheduleDraft) -> bool {
        record.objective_digest == draft.objective_digest
            && record.scope == draft.scope
            && record.recurrence == draft.recurrence
            && record.timezone == draft.timezone
            && record.dst_policy == draft.dst_policy
            && record.late_wake_policy == draft.late_wake_policy
            && record.wake_contract_seconds == draft.wake_contract_seconds
            && record.composition == draft.composition
            && record.invocation == draft.invocation
            && record.lease == draft.lease
    }

    fn collect_due(
        record: &MissionScheduleRecord,
        first: &ResolvedOccurrence,
        woke_at: DateTime<Utc>,
    ) -> Result<DueCollection, RecurringScheduleError> {
        let max_ticks = record.late_wake_policy.max_ticks();
        let mut due = Vec::new();
        let mut current = first.clone();
        loop {
            if current.planned_at > woke_at {
                break;
            }
            due.push(current.clone());
            let due_ticks = u32::try_from(due.len())
                .map_err(|_| RecurringScheduleError::InvalidWakePreparation)?;
            if due_ticks > max_ticks {
                let next = record.recurrence.next_after(
                    Some(&current),
                    woke_at,
                    &record.timezone,
                    record.dst_policy,
                )?;
                let rejection = match record.late_wake_policy {
                    LateWakePolicy::FailClosed => LateWakeRejection::MultipleTicksFailClosed,
                    LateWakePolicy::Coalesce { .. } => LateWakeRejection::MissedTicksExceeded,
                };
                return Ok((due, next, Some(rejection)));
            }
            let Some(next) = record.recurrence.next_after(
                Some(&current),
                current.planned_at,
                &record.timezone,
                record.dst_policy,
            )?
            else {
                break;
            };
            current = next;
        }
        let next = record.recurrence.next_after(
            due.last(),
            woke_at,
            &record.timezone,
            record.dst_policy,
        )?;
        Ok((due, next, None))
    }

    fn capability_request(
        record: &MissionScheduleRecord,
        reservation: &ScheduleDispatchReservation,
    ) -> Result<MissionCapabilityRequest, RecurringScheduleError> {
        let first = reservation
            .due_occurrences
            .first()
            .ok_or(RecurringScheduleError::InvalidCapabilityRequest)?;
        let request = MissionCapabilityRequest {
            dispatch_id_digest: reservation.dispatch_id_digest.clone(),
            wake_token_digest: reservation.token.token_digest.clone(),
            schedule_id_digest: record.schedule_id_digest.clone(),
            schedule_revision: record.schedule_revision,
            scope: record.scope.clone(),
            objective_digest: record.objective_digest.clone(),
            timezone: record.timezone.clone(),
            recurrence: record.recurrence.clone(),
            dst_policy: record.dst_policy,
            composition: record.composition.clone(),
            invocation: record.invocation.clone(),
            planned_at: first.planned_at,
            woke_at: reservation.woke_at,
            coalesced_ticks: reservation.coalesced_ticks,
            next_run_at: reservation
                .next_occurrence
                .as_ref()
                .map(|occurrence| occurrence.planned_at),
            provider_id_digest: record.provider_id_digest.clone(),
            provider_epoch: record.provider_epoch,
            lease_revision: record.lease.lease_revision,
            clock_epoch: record.clock_epoch,
            authority: DispatchAuthority::CapabilityRequestOnly,
        };
        request.validate()?;
        Ok(request)
    }

    fn commit_late_rejection(
        &mut self,
        current: &MissionScheduleRecord,
        preparation: &WakePreparation,
        rejection: LateWakeRejection,
    ) -> Result<MissionScheduleWakeOutcome, RecurringScheduleError> {
        let before = self.snapshot();
        let receipt = LateWakeReceipt::new(
            &current.schedule_id_digest,
            current.schedule_revision,
            &preparation.token.token_digest,
            preparation.woke_at,
            u32::try_from(preparation.due_occurrences.len())
                .map_err(|_| RecurringScheduleError::InvalidWakePreparation)?,
            preparation
                .next_occurrence
                .as_ref()
                .map(|occurrence| occurrence.planned_at),
            rejection,
        )?;
        let mut next = current.clone();
        if let Some(armed) = &current.armed_receipt {
            self.provider
                .disarm_wake(armed)
                .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
        }
        next.next_occurrence
            .clone_from(&preparation.next_occurrence);
        next.last_observed_at = preparation.woke_at;
        next.last_woke_at = Some(preparation.woke_at);
        next.armed_wake = None;
        next.armed_receipt = None;
        next.status = if next.next_occurrence.is_some() {
            MissionScheduleStatus::Active
        } else {
            MissionScheduleStatus::Completed
        };
        next.updated_at = preparation.woke_at;
        if next.status == MissionScheduleStatus::Active {
            self.arm_record(&mut next)?;
        }
        let model = MissionScheduleModelReceipt::from_record(
            &next,
            MissionScheduleEvent::LateWakeRejected,
            preparation.woke_at,
        )?;
        self.late_wake_receipts.push(receipt.clone());
        self.replace_with_receipt(next, model, &before)?;
        Ok(MissionScheduleWakeOutcome::LateRejected(receipt))
    }

    fn mutate_status(
        &mut self,
        schedule_id_digest: &str,
        expected_schedule_revision: u64,
        expected_lease_revision: u64,
        status: MissionScheduleStatus,
        event: MissionScheduleEvent,
        observed_at: DateTime<Utc>,
    ) -> Result<ScheduleLifecycleResult, RecurringScheduleError> {
        self.ensure_wake_state_known()?;
        let current = self
            .schedules
            .get(schedule_id_digest)
            .cloned()
            .ok_or(RecurringScheduleError::ScheduleNotFound)?;
        Self::ensure_cas(
            &current,
            expected_schedule_revision,
            expected_lease_revision,
        )?;
        if current.status == MissionScheduleStatus::Dispatching {
            return Err(RecurringScheduleError::DispatchReserved);
        }
        let valid = match status {
            MissionScheduleStatus::Paused => current.status == MissionScheduleStatus::Active,
            MissionScheduleStatus::Cancelled => matches!(
                current.status,
                MissionScheduleStatus::Active | MissionScheduleStatus::Paused
            ),
            _ => false,
        };
        if !valid {
            return Err(status_error(current.status));
        }
        let before = self.snapshot();
        if let Some(receipt) = &current.armed_receipt {
            self.provider
                .disarm_wake(receipt)
                .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
        }
        let mut next = current;
        next.status = status;
        next.schedule_revision = next
            .schedule_revision
            .checked_add(1)
            .ok_or(RecurringScheduleError::InvalidScheduleRevision)?;
        next.lease = next.lease.renewed(observed_at)?;
        next.armed_wake = None;
        next.armed_receipt = None;
        next.updated_at = observed_at;
        let receipt = MissionScheduleModelReceipt::from_record(&next, event, observed_at)?;
        self.replace_with_receipt(next.clone(), receipt, &before)?;
        Ok(lifecycle_result(&next))
    }

    fn validate_token(
        record: &MissionScheduleRecord,
        token: &DispatchWakeToken,
    ) -> Result<(), RecurringScheduleError> {
        let occurrence = record
            .next_occurrence
            .as_ref()
            .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
        token.validate_for(record, occurrence)?;
        let armed = record
            .armed_wake
            .as_ref()
            .ok_or(RecurringScheduleError::WakeNotArmed)?;
        if armed.token_digest != token.token_digest {
            return Err(RecurringScheduleError::StaleWakeToken);
        }
        Ok(())
    }

    fn validate_preparation(
        &self,
        record: &MissionScheduleRecord,
        preparation: &WakePreparation,
    ) -> Result<(), RecurringScheduleError> {
        if record.status == MissionScheduleStatus::Active {
            Self::validate_token(record, &preparation.token)?;
        } else if record
            .pending_dispatch
            .as_ref()
            .is_none_or(|pending| pending.token != preparation.token)
        {
            return Err(RecurringScheduleError::StaleWakeToken);
        }
        if record.schedule_revision != preparation.schedule_revision
            || record.lease.lease_revision != preparation.lease_revision
            || record.clock_epoch != preparation.clock_epoch
            || record.provider_epoch != self.provider_epoch
            || !matches!(
                record.status,
                MissionScheduleStatus::Active | MissionScheduleStatus::Dispatching
            )
        {
            return Err(RecurringScheduleError::StaleScheduleRevision);
        }
        if preparation.due_occurrences.is_empty()
            || preparation.due_occurrences[0].planned_at != preparation.token.planned_at
        {
            return Err(RecurringScheduleError::InvalidWakePreparation);
        }
        Ok(())
    }

    fn ensure_cas(
        record: &MissionScheduleRecord,
        schedule_revision: u64,
        lease_revision: u64,
    ) -> Result<(), RecurringScheduleError> {
        if record.schedule_revision != schedule_revision {
            return Err(RecurringScheduleError::StaleScheduleRevision);
        }
        if record.lease.lease_revision != lease_revision {
            return Err(RecurringScheduleError::LeaseRevisionConflict);
        }
        Ok(())
    }

    fn arm_record(
        &mut self,
        record: &mut MissionScheduleRecord,
    ) -> Result<(), RecurringScheduleError> {
        let occurrence = record
            .next_occurrence
            .as_ref()
            .ok_or(RecurringScheduleError::RecurrenceExhausted)?;
        let token = DispatchWakeToken::issue(record, occurrence)?;
        let contract_valid_until = occurrence
            .planned_at
            .checked_add_signed(Duration::seconds(
                i64::try_from(record.wake_contract_seconds)
                    .map_err(|_| RecurringScheduleError::InvalidWakeRequest)?,
            ))
            .ok_or(RecurringScheduleError::InvalidWakeRequest)?;
        let request = ScheduleWakeRequest {
            token_digest: token.token_digest.clone(),
            schedule_id_digest: record.schedule_id_digest.clone(),
            objective_digest: record.objective_digest.clone(),
            scope: record.scope.clone(),
            schedule_revision: record.schedule_revision,
            planned_at: occurrence.planned_at,
            contract_valid_until,
            timezone_digest: record.timezone.timezone_digest.clone(),
            recurrence_digest: record.recurrence.recurrence_digest.clone(),
            composition_digest: record.composition.composition_digest.clone(),
            invocation_digest: record.invocation.digest()?,
            provider_id_digest: record.provider_id_digest.clone(),
            provider_epoch: record.provider_epoch,
            lease_revision: record.lease.lease_revision,
            clock_epoch: record.clock_epoch,
        };
        request.validate()?;
        let receipt = self
            .provider
            .arm_wake(&request)
            .map_err(|error| RecurringScheduleError::Provider(error.to_string()))?;
        receipt.validate_for(&request)?;
        record.armed_wake = Some(request);
        record.armed_receipt = Some(receipt);
        Ok(())
    }

    fn insert_record(
        &mut self,
        record: MissionScheduleRecord,
        receipt: MissionScheduleModelReceipt,
        before: &MissionScheduleSnapshot,
    ) -> Result<(), RecurringScheduleError> {
        if self
            .schedules
            .insert(record.schedule_id_digest.clone(), record)
            .is_some()
        {
            return Err(RecurringScheduleError::ScheduleConflict);
        }
        self.model_receipts.push(receipt);
        self.persist_wake_transition(before, "create")
    }

    fn replace_with_receipt(
        &mut self,
        record: MissionScheduleRecord,
        receipt: MissionScheduleModelReceipt,
        before: &MissionScheduleSnapshot,
    ) -> Result<(), RecurringScheduleError> {
        self.schedules
            .insert(record.schedule_id_digest.clone(), record);
        self.model_receipts.push(receipt);
        self.persist_wake_transition(before, "replace_schedule")
    }

    fn replace_schedule(
        &mut self,
        record: MissionScheduleRecord,
        before: &MissionScheduleSnapshot,
    ) -> Result<(), RecurringScheduleError> {
        self.schedules
            .insert(record.schedule_id_digest.clone(), record);
        self.persist_wake_transition(before, "replace_schedule")
    }

    fn complete_dispatch(
        &mut self,
        record: MissionScheduleRecord,
        receipt: &MissionCapabilityDispatchReceipt,
        before: &MissionScheduleSnapshot,
    ) -> Result<(), RecurringScheduleError> {
        let id = record.schedule_id_digest.clone();
        self.schedules.insert(id, record);
        self.dispatch_receipts
            .insert(receipt.dispatch_id_digest.clone(), receipt.clone());
        self.persist_wake_transition(before, "complete_dispatch")
    }

    fn ensure_wake_state_known(&self) -> Result<(), RecurringScheduleError> {
        if let Some(uncertainty) = &self.wake_uncertainty {
            return Err(RecurringScheduleError::WakeStateUncertain {
                operation: uncertainty.operation.clone(),
            });
        }
        Ok(())
    }

    fn restore_memory(&mut self, snapshot: &MissionScheduleSnapshot) {
        self.schedules = snapshot
            .schedules
            .iter()
            .cloned()
            .map(|record| (record.schedule_id_digest.clone(), record))
            .collect();
        self.model_receipts.clone_from(&snapshot.model_receipts);
        self.dispatch_receipts = snapshot
            .dispatch_receipts
            .iter()
            .cloned()
            .map(|receipt| (receipt.dispatch_id_digest.clone(), receipt))
            .collect();
        self.late_wake_receipts
            .clone_from(&snapshot.late_wake_receipts);
        self.revoked_plugins = snapshot.revoked_plugins.iter().cloned().collect();
        self.clock_epoch = snapshot.clock_epoch;
        if snapshot.provider_epoch != 0 {
            self.provider_epoch = snapshot.provider_epoch;
        }
        self.wake_uncertainty.clone_from(&snapshot.wake_uncertainty);
    }

    fn wake_bindings(
        snapshot: &MissionScheduleSnapshot,
    ) -> BTreeMap<String, (ScheduleWakeRequest, ScheduleWakeReceipt)> {
        snapshot
            .schedules
            .iter()
            .filter_map(|record| {
                Some((
                    record.schedule_id_digest.clone(),
                    (record.armed_wake.clone()?, record.armed_receipt.clone()?),
                ))
            })
            .collect()
    }

    fn compensate_provider_wakes(
        &mut self,
        before: &MissionScheduleSnapshot,
        after: &MissionScheduleSnapshot,
    ) -> Result<(), String> {
        let previous = Self::wake_bindings(before);
        let current = Self::wake_bindings(after);
        for (schedule_id, (_, receipt)) in &current {
            if previous.get(schedule_id) != Some(&current[schedule_id]) {
                self.provider
                    .disarm_wake(receipt)
                    .map_err(|error| error.to_string())?;
            }
        }
        for (schedule_id, (request, _)) in &previous {
            if current.get(schedule_id) == previous.get(schedule_id) {
                continue;
            }
            if request.provider_epoch != self.provider.provider_epoch() {
                return Err(format!(
                    "provider epoch {} cannot restore wake epoch {}",
                    self.provider.provider_epoch(),
                    request.provider_epoch
                ));
            }
            let receipt = self
                .provider
                .arm_wake(request)
                .map_err(|error| error.to_string())?;
            receipt
                .validate_for(request)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn persist_wake_transition(
        &mut self,
        before: &MissionScheduleSnapshot,
        operation: &str,
    ) -> Result<(), RecurringScheduleError> {
        let after = self.snapshot();
        match self.store.save(&after) {
            Ok(()) => Ok(()),
            Err(save_error) => {
                let save_message = save_error.to_string();
                match self.compensate_provider_wakes(before, &after) {
                    Ok(()) => match self.store.save(before) {
                        Ok(()) => {
                            self.restore_memory(before);
                            Err(RecurringScheduleError::Store(save_error))
                        }
                        Err(restore_error) => Err(self.enter_wake_uncertainty(
                            operation,
                            &save_message,
                            &format!("durable rollback failed: {restore_error}"),
                            before
                                .schedules
                                .first()
                                .map(|record| record.schedule_id_digest.clone()),
                        )),
                    },
                    Err(compensation_error) => Err(self.enter_wake_uncertainty(
                        operation,
                        &save_message,
                        &compensation_error,
                        before
                            .schedules
                            .first()
                            .map(|record| record.schedule_id_digest.clone()),
                    )),
                }
            }
        }
    }

    fn enter_wake_uncertainty(
        &mut self,
        operation: &str,
        store_error: &str,
        compensation_error: &str,
        schedule_id_digest: Option<String>,
    ) -> RecurringScheduleError {
        self.wake_uncertainty = Some(WakeStateUncertainty {
            operation: operation.to_owned(),
            schedule_id_digest,
            store_error: store_error.to_owned(),
            compensation_error: compensation_error.to_owned(),
        });
        let _ = self.store.save(&self.snapshot());
        RecurringScheduleError::WakeStateUncertain {
            operation: operation.to_owned(),
        }
    }
}

fn lifecycle_result(record: &MissionScheduleRecord) -> ScheduleLifecycleResult {
    ScheduleLifecycleResult {
        schedule_id_digest: record.schedule_id_digest.clone(),
        schedule_revision: record.schedule_revision,
        lease_revision: record.lease.lease_revision,
        status: record.status,
        next_run_at: record
            .next_occurrence
            .as_ref()
            .map(|occurrence| occurrence.planned_at),
    }
}

fn status_error(status: MissionScheduleStatus) -> RecurringScheduleError {
    match status {
        MissionScheduleStatus::Paused => RecurringScheduleError::SchedulePaused,
        MissionScheduleStatus::Cancelled => RecurringScheduleError::ScheduleCancelled,
        MissionScheduleStatus::Revoked => RecurringScheduleError::PluginRevoked,
        MissionScheduleStatus::Completed => RecurringScheduleError::RecurrenceExhausted,
        MissionScheduleStatus::Dispatching => RecurringScheduleError::DispatchReserved,
        MissionScheduleStatus::Active => RecurringScheduleError::ScheduleStateConflict,
    }
}

impl MissionScheduleRecord {
    fn lease_is_live(&self, at: DateTime<Utc>) -> bool {
        at <= self.lease.expires_at
    }
}

fn validate_invocation(
    invocation: &PluginInvocation,
    composition: &PluginComposition,
) -> Result<(), RecurringScheduleError> {
    let canonical =
        PluginInvocation::new(invocation.plugin_id.clone(), invocation.operation.clone())?;
    if canonical != *invocation || composition.plugin(&invocation.plugin_id).is_none() {
        return Err(RecurringScheduleError::PluginCompositionMismatch);
    }
    Ok(())
}

fn weekday_index(day: Weekday) -> i64 {
    match day {
        Weekday::Mon => 0,
        Weekday::Tue => 1,
        Weekday::Wed => 2,
        Weekday::Thu => 3,
        Weekday::Fri => 4,
        Weekday::Sat => 5,
        Weekday::Sun => 6,
    }
}

fn utc_from_local_offset(local: NaiveDateTime, offset_seconds: i32) -> Option<DateTime<Utc>> {
    local
        .checked_sub_signed(Duration::seconds(i64::from(offset_seconds)))
        .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn utc_from_transition(local: Option<NaiveDateTime>, before_offset: i32) -> Option<DateTime<Utc>> {
    utc_from_local_offset(local?, before_offset)
}

fn valid_offset(offset_seconds: i32) -> bool {
    (-24 * 60 * 60..=24 * 60 * 60).contains(&offset_seconds)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, RecurringScheduleError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| RecurringScheduleError::Serialization(error.to_string()))?;
    Ok(scheduler_digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RecurringScheduleError {
    #[error("recurring schedule plugin contract is invalid: {0}")]
    Invocation(#[from] PluginInvocationError),
    #[error("recurring schedule draft is invalid")]
    InvalidDraft,
    #[error("recurring schedule timezone is invalid")]
    InvalidTimezone,
    #[error("recurring schedule recurrence is invalid")]
    InvalidRecurrence,
    #[error("recurring schedule recurrence is exhausted")]
    RecurrenceExhausted,
    #[error("recurring schedule DST local time is a gap")]
    DstGap,
    #[error("recurring schedule DST local time is a fold")]
    DstFold,
    #[error("recurring schedule late-wake policy is invalid")]
    InvalidLateWakePolicy,
    #[error("recurring schedule lease is invalid")]
    InvalidLease,
    #[error("recurring schedule lease has expired")]
    LeaseExpired,
    #[error("recurring schedule provider is invalid")]
    InvalidProvider,
    #[error("recurring schedule provider epoch is stale")]
    ProviderEpochLost,
    #[error("recurring schedule provider failed: {0}")]
    Provider(String),
    #[error("recurring schedule wake state is uncertain; automatic retry is disabled: {operation}")]
    WakeStateUncertain { operation: String },
    #[error("recurring schedule consumer failed: {0}")]
    Consumer(String),
    #[error("recurring schedule ID is already bound to a different draft")]
    ScheduleConflict,
    #[error("recurring schedule was not found")]
    ScheduleNotFound,
    #[error("recurring schedule state does not permit the operation")]
    ScheduleStateConflict,
    #[error("recurring schedule is paused")]
    SchedulePaused,
    #[error("recurring schedule is cancelled")]
    ScheduleCancelled,
    #[error("recurring schedule dispatch reservation already won")]
    DispatchReserved,
    #[error("recurring schedule revision lost the exact CAS")]
    StaleScheduleRevision,
    #[error("recurring schedule revision is invalid")]
    InvalidScheduleRevision,
    #[error("recurring schedule lease revision lost the exact CAS")]
    LeaseRevisionConflict,
    #[error("recurring schedule plugin is revoked")]
    PluginRevoked,
    #[error("recurring schedule scope does not match the plugin composition")]
    ScopeMismatch,
    #[error("recurring schedule wake token is stale")]
    StaleWakeToken,
    #[error("recurring schedule wake was not armed")]
    WakeNotArmed,
    #[error("recurring schedule wake receipt conflicts")]
    WakeReceiptConflict,
    #[error("recurring schedule wake request is invalid")]
    InvalidWakeRequest,
    #[error("recurring schedule wake is not due")]
    WakeNotDue,
    #[error("recurring schedule clock moved backwards")]
    ClockRollback,
    #[error("recurring schedule clock epoch is exhausted")]
    ClockEpochExhausted,
    #[error("recurring schedule wake preparation is invalid")]
    InvalidWakePreparation,
    #[error("recurring schedule capability request is invalid")]
    InvalidCapabilityRequest,
    #[error("recurring schedule capability acknowledgement is invalid")]
    InvalidCapabilityAck,
    #[error("recurring schedule dispatch receipt is invalid")]
    InvalidDispatchReceipt,
    #[error("recurring schedule plugin composition is not exact")]
    PluginCompositionMismatch,
    #[error("recurring schedule record is corrupt")]
    CorruptSchedule,
    #[error("recurring schedule store failed: {0}")]
    Store(#[from] MissionScheduleStoreError),
    #[error("recurring schedule serialization failed: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;
    use hartevo_cloud_storage::DataCell;

    use super::*;

    fn digest(byte: u8) -> String {
        scheduler_digest([byte])
    }

    fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0)
            .single()
            .expect("valid UTC test time")
    }

    fn local(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(year, month, day)
            .expect("valid local date")
            .and_hms_opt(hour, minute, 0)
            .expect("valid local time")
    }

    fn scope() -> MissionScope {
        MissionScope::new(
            DataCell::Us,
            "tenant-recurring",
            "project-recurring",
            "mission-recurring",
            4,
        )
        .expect("scope")
    }

    fn composition(scope: &MissionScope, version: &str, plugin_byte: u8) -> PluginComposition {
        PluginComposition::new(
            scope.clone(),
            2,
            vec![
                PluginManifest::new("summary-plugin", version, digest(plugin_byte))
                    .expect("plugin"),
            ],
        )
        .expect("composition")
    }

    fn daily_draft(
        schedule_byte: u8,
        start_local: NaiveDateTime,
        timezone: ScheduleTimezone,
        late_wake_policy: LateWakePolicy,
    ) -> MissionScheduleDraft {
        let scope = scope();
        let recurrence = RecurrenceRule::daily(start_local, 1).expect("daily recurrence");
        MissionScheduleDraft {
            schedule_id_digest: digest(schedule_byte),
            objective_digest: digest(b'o'),
            scope: scope.clone(),
            recurrence,
            timezone,
            dst_policy: DstPolicy::default(),
            late_wake_policy,
            wake_contract_seconds: 7 * 24 * 60 * 60,
            composition: composition(&scope, "1.4.0", b'v'),
            invocation: PluginInvocation::new("summary-plugin", "summarize").expect("invocation"),
            lease: ScheduleLease::new(digest(b'l'), 1, 1, utc(2026, 8, 20, 0, 0)).expect("lease"),
        }
    }

    #[derive(Debug, Default)]
    struct RecordingWakeProvider {
        provider_id_digest: String,
        epoch: u64,
        armed: BTreeMap<String, ScheduleWakeReceipt>,
        arm_calls: usize,
        disarm_calls: usize,
        fail_disarm: bool,
    }

    impl RecordingWakeProvider {
        fn new(provider_id_digest: String) -> Self {
            Self {
                provider_id_digest,
                epoch: 1,
                ..Self::default()
            }
        }
    }

    impl MissionScheduleWakeProvider for RecordingWakeProvider {
        fn provider_id_digest(&self) -> &str {
            &self.provider_id_digest
        }

        fn provider_epoch(&self) -> u64 {
            self.epoch
        }

        fn arm_wake(
            &mut self,
            request: &ScheduleWakeRequest,
        ) -> Result<ScheduleWakeReceipt, MissionScheduleProviderError> {
            if request.provider_id_digest != self.provider_id_digest
                || request.provider_epoch != self.epoch
            {
                return Err(MissionScheduleProviderError::EpochLost);
            }
            if let Some(existing) = self.armed.get(&request.token_digest) {
                existing
                    .validate_for(request)
                    .map_err(|_| MissionScheduleProviderError::ReceiptConflict)?;
                return Ok(existing.clone());
            }
            self.arm_calls += 1;
            let receipt = ScheduleWakeReceipt {
                token_digest: request.token_digest.clone(),
                provider_id_digest: self.provider_id_digest.clone(),
                provider_epoch: self.epoch,
                woke_at: request.planned_at,
            };
            self.armed
                .insert(request.token_digest.clone(), receipt.clone());
            Ok(receipt)
        }

        fn disarm_wake(
            &mut self,
            receipt: &ScheduleWakeReceipt,
        ) -> Result<(), MissionScheduleProviderError> {
            self.disarm_calls += 1;
            if self.fail_disarm {
                return Err(MissionScheduleProviderError::Backend);
            }
            self.armed.remove(&receipt.token_digest);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailOnceStore {
        snapshot: MissionScheduleSnapshot,
        saves: usize,
        fail_at: usize,
    }

    impl FailOnceStore {
        fn new(fail_at: usize) -> Self {
            Self {
                snapshot: MissionScheduleSnapshot::default(),
                saves: 0,
                fail_at,
            }
        }
    }

    impl MissionScheduleStore for FailOnceStore {
        fn load(&self) -> Result<MissionScheduleSnapshot, MissionScheduleStoreError> {
            Ok(self.snapshot.clone())
        }

        fn save(
            &mut self,
            snapshot: &MissionScheduleSnapshot,
        ) -> Result<(), MissionScheduleStoreError> {
            self.saves += 1;
            if self.saves == self.fail_at {
                return Err(MissionScheduleStoreError::WriteRejected);
            }
            self.snapshot = snapshot.clone();
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingConsumer {
        consumer_id_digest: String,
        acknowledgements: BTreeMap<String, MissionCapabilityAck>,
        calls: usize,
    }

    impl RecordingConsumer {
        fn new(consumer_id_digest: String) -> Self {
            Self {
                consumer_id_digest,
                ..Self::default()
            }
        }
    }

    impl MissionCapabilityConsumer for RecordingConsumer {
        fn consumer_id_digest(&self) -> &str {
            &self.consumer_id_digest
        }

        fn request_capability(
            &mut self,
            request: &MissionCapabilityRequest,
        ) -> Result<MissionCapabilityAck, MissionCapabilityConsumerError> {
            request
                .validate()
                .map_err(|_| MissionCapabilityConsumerError::Rejected)?;
            if let Some(existing) = self.acknowledgements.get(&request.dispatch_id_digest) {
                return Ok(existing.clone());
            }
            self.calls += 1;
            let mut ack = MissionCapabilityAck {
                dispatch_id_digest: request.dispatch_id_digest.clone(),
                consumer_id_digest: self.consumer_id_digest.clone(),
                requested_at: request.woke_at,
                authority: DispatchAuthority::CapabilityRequestOnly,
                ack_digest: String::new(),
            };
            ack.ack_digest = ack.expected_digest().expect("ack digest");
            self.acknowledgements
                .insert(request.dispatch_id_digest.clone(), ack.clone());
            Ok(ack)
        }
    }

    fn new_service() -> MissionScheduleService<RecordingWakeProvider, RecordingConsumer> {
        MissionScheduleService::new(
            RecordingWakeProvider::new(digest(b'p')),
            RecordingConsumer::new(digest(b'c')),
        )
        .expect("service")
    }

    fn token_for(
        service: &MissionScheduleService<RecordingWakeProvider, RecordingConsumer>,
        schedule_id_digest: &str,
    ) -> DispatchWakeToken {
        let record = service.schedule(schedule_id_digest).expect("schedule");
        DispatchWakeToken::issue(
            record,
            record.next_occurrence.as_ref().expect("next occurrence"),
        )
        .expect("token")
    }

    #[test]
    fn conversation_draft_arms_once_dispatches_capability_and_persists_next_run() {
        let mut service = new_service();
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b's',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::Coalesce {
                max_missed_ticks: 3,
            },
        );
        let created = service.create(&draft, observed_at).expect("create");
        assert_eq!(created.event, MissionScheduleEvent::Created);
        assert_eq!(created.next_run_at, Some(utc(2026, 8, 14, 9, 0)));
        assert_eq!(service.provider().arm_calls, 1);
        let token = token_for(&service, &draft.schedule_id_digest);
        let outcome = service
            .wake_once(&token, utc(2026, 8, 14, 9, 1))
            .expect("wake");
        let receipt = match outcome {
            MissionScheduleWakeOutcome::Dispatched(receipt) => receipt,
            other => panic!("unexpected outcome: {other:?}"),
        };
        receipt.validate().expect("receipt");
        assert_eq!(receipt.scope.project_id, "project-recurring");
        assert_eq!(receipt.scope.mission_id, "mission-recurring");
        assert_eq!(receipt.composition, draft.composition);
        assert_eq!(receipt.invocation, draft.invocation);
        assert_eq!(receipt.coalesced_ticks, 1);
        assert_eq!(receipt.next_run_at, Some(utc(2026, 8, 15, 9, 0)));
        assert_eq!(receipt.authority, DispatchAuthority::CapabilityRequestOnly);
        assert_eq!(service.consumer().calls, 1);
        assert_eq!(service.provider().arm_calls, 2);
        let mut forged_token = token.clone();
        forged_token.token_digest = digest(b'!');
        assert_eq!(
            service.wake_once(&forged_token, utc(2026, 8, 14, 9, 2)),
            Err(RecurringScheduleError::StaleWakeToken)
        );
        assert_eq!(
            service.schedule(&draft.schedule_id_digest).unwrap().status,
            MissionScheduleStatus::Active
        );
        assert_eq!(
            service
                .wake_once(&token, utc(2026, 8, 14, 9, 2))
                .expect("replay"),
            MissionScheduleWakeOutcome::AlreadyDispatched(receipt)
        );
        assert_eq!(service.consumer().calls, 1);
        assert_eq!(service.model_receipts().len(), 1);
    }

    #[test]
    fn dst_gap_and_fold_follow_the_persisted_policy() {
        let start = DstTransitionRule::new(
            3,
            TransitionWeek::Second,
            ScheduleWeekday::Sunday,
            NaiveTime::from_hms_opt(2, 0, 0).expect("time"),
        )
        .expect("start rule");
        let end = DstTransitionRule::new(
            11,
            TransitionWeek::First,
            ScheduleWeekday::Sunday,
            NaiveTime::from_hms_opt(2, 0, 0).expect("time"),
        )
        .expect("end rule");
        let timezone =
            ScheduleTimezone::with_dst("America/New_York", -5 * 60 * 60, -4 * 60 * 60, start, end)
                .expect("timezone");
        let gap = timezone
            .resolve_local(local(2026, 3, 8, 2, 30), DstPolicy::default())
            .expect("gap resolution")
            .expect("shifted gap");
        assert_eq!(gap.planned_at, utc(2026, 3, 8, 7, 30));
        assert_eq!(gap.resolution, DstResolution::GapShifted);
        assert_eq!(
            timezone.resolve_local(
                local(2026, 3, 8, 2, 30),
                DstPolicy {
                    gap: DstGapPolicy::Reject,
                    fold: DstFoldPolicy::Earlier,
                },
            ),
            Err(RecurringScheduleError::DstGap)
        );
        let earlier = timezone
            .resolve_local(
                local(2026, 11, 1, 1, 30),
                DstPolicy {
                    gap: DstGapPolicy::Reject,
                    fold: DstFoldPolicy::Earlier,
                },
            )
            .expect("fold")
            .expect("earlier fold");
        let later = timezone
            .resolve_local(
                local(2026, 11, 1, 1, 30),
                DstPolicy {
                    gap: DstGapPolicy::Reject,
                    fold: DstFoldPolicy::Later,
                },
            )
            .expect("fold")
            .expect("later fold");
        assert_eq!(earlier.planned_at, utc(2026, 11, 1, 5, 30));
        assert_eq!(later.planned_at, utc(2026, 11, 1, 6, 30));
    }

    #[test]
    fn cancellation_and_reschedule_win_before_capability_dispatch() {
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b'x',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::FailClosed,
        );
        let mut service = new_service();
        service.create(&draft, observed_at).expect("create");
        let token = token_for(&service, &draft.schedule_id_digest);
        let preparation = service
            .prepare_wake(&token, utc(2026, 8, 14, 9, 1))
            .expect("prepare");
        let paused = service
            .pause(&draft.schedule_id_digest, 1, 1, utc(2026, 8, 14, 9, 1))
            .expect("pause CAS");
        assert_eq!(paused.status, MissionScheduleStatus::Paused);
        assert_eq!(
            service.commit_wake(&preparation),
            Err(RecurringScheduleError::StaleWakeToken)
        );
        assert_eq!(service.consumer().calls, 0);

        let mut service = new_service();
        service.create(&draft, observed_at).expect("create");
        let token = token_for(&service, &draft.schedule_id_digest);
        let preparation = service
            .prepare_wake(&token, utc(2026, 8, 14, 9, 1))
            .expect("prepare");
        let rescheduled = service
            .reschedule(ScheduleRescheduleCommand {
                schedule_id_digest: draft.schedule_id_digest.clone(),
                expected_schedule_revision: 1,
                expected_lease_revision: 1,
                new_schedule_revision: 2,
                recurrence: RecurrenceRule::daily(local(2026, 8, 15, 10, 0), 1)
                    .expect("new recurrence"),
                timezone: ScheduleTimezone::utc(),
                dst_policy: DstPolicy::default(),
                late_wake_policy: LateWakePolicy::Coalesce {
                    max_missed_ticks: 2,
                },
                wake_contract_seconds: 86_400,
                composition: draft.composition.clone(),
                invocation: draft.invocation.clone(),
                observed_at: utc(2026, 8, 14, 9, 1),
            })
            .expect("reschedule CAS");
        assert_eq!(rescheduled.schedule_revision, 2);
        assert_eq!(
            service.commit_wake(&preparation),
            Err(RecurringScheduleError::StaleWakeToken)
        );
        assert_eq!(service.consumer().calls, 0);
    }

    #[test]
    fn missed_ticks_are_typed_and_bounded() {
        let scope = scope();
        let recurrence =
            RecurrenceRule::weekly(local(2026, 8, 10, 9, 0), 1, vec![ScheduleWeekday::Monday])
                .expect("weekly");
        let mut draft = daily_draft(
            b'm',
            local(2026, 8, 10, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::Coalesce {
                max_missed_ticks: 2,
            },
        );
        draft.scope = scope.clone();
        draft.recurrence = recurrence.clone();
        draft.composition = composition(&scope, "1.4.0", b'v');
        draft.lease =
            ScheduleLease::new(digest(b'l'), 1, 1, utc(2026, 9, 10, 0, 0)).expect("long lease");
        let mut service = new_service();
        service
            .create(&draft, utc(2026, 8, 10, 8, 0))
            .expect("create");
        let token = token_for(&service, &draft.schedule_id_digest);
        let outcome = service
            .wake_once(&token, utc(2026, 8, 31, 10, 0))
            .expect("late wake");
        match outcome {
            MissionScheduleWakeOutcome::LateRejected(receipt) => {
                assert_eq!(receipt.rejection, LateWakeRejection::MissedTicksExceeded);
                assert!(receipt.due_ticks >= 3);
                assert_eq!(service.consumer().calls, 0);
                assert_eq!(
                    service
                        .schedule(&draft.schedule_id_digest)
                        .unwrap()
                        .next_occurrence
                        .as_ref()
                        .unwrap()
                        .planned_at,
                    utc(2026, 9, 7, 9, 0)
                );
            }
            other => panic!("unexpected late outcome: {other:?}"),
        }
    }

    #[test]
    fn clock_rollback_and_provider_epoch_fences_fail_closed() {
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b'r',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::FailClosed,
        );
        let mut service = new_service();
        service.create(&draft, observed_at).expect("create");
        let token = token_for(&service, &draft.schedule_id_digest);
        assert_eq!(
            service.wake_once(&token, utc(2026, 8, 14, 7, 0)),
            Err(RecurringScheduleError::ClockRollback)
        );
        service.provider_mut().epoch = 2;
        service
            .rebind_provider_epoch(2, utc(2026, 8, 14, 9, 0))
            .expect("provider wake epoch");
        assert_eq!(
            service.wake_once(&token, utc(2026, 8, 14, 9, 1)),
            Err(RecurringScheduleError::StaleWakeToken)
        );
        let new_token = token_for(&service, &draft.schedule_id_digest);
        assert!(matches!(
            service
                .wake_once(&new_token, utc(2026, 8, 14, 9, 1))
                .expect("new epoch wake"),
            MissionScheduleWakeOutcome::Dispatched(_)
        ));
    }

    #[test]
    fn plugin_revocation_cancels_future_wakes_and_logs_model_receipt() {
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b'v',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::FailClosed,
        );
        let plugin = draft.composition.plugins[0].clone();
        let mut service = new_service();
        service.create(&draft, observed_at).expect("create");
        let token = token_for(&service, &draft.schedule_id_digest);
        let result = service.revoke_plugin(&plugin, utc(2026, 8, 14, 8, 30));
        assert_eq!(
            result.expect("revoke")[0].status,
            MissionScheduleStatus::Revoked
        );
        assert_eq!(service.consumer().calls, 0);
        assert!(matches!(
            service.wake_once(&token, utc(2026, 8, 14, 9, 1)),
            Err(RecurringScheduleError::StaleWakeToken | RecurringScheduleError::WakeNotArmed)
        ));
        assert_eq!(
            service.model_receipts().last().unwrap().event,
            MissionScheduleEvent::Revoked
        );
    }

    #[test]
    fn sqlite_restart_and_consumer_retry_are_idempotent() {
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b'z',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::FailClosed,
        );
        let store = SqliteMissionScheduleStore::open_in_memory().expect("sqlite");
        let mut service = MissionScheduleService::with_store(
            RecordingWakeProvider::new(digest(b'p')),
            RecordingConsumer::new(digest(b'c')),
            store,
        )
        .expect("service");
        service.create(&draft, observed_at).expect("create");
        let token = token_for_service(&service, &draft.schedule_id_digest);
        let first = service
            .wake_once(&token, utc(2026, 8, 14, 9, 1))
            .expect("dispatch");
        let receipt = match first {
            MissionScheduleWakeOutcome::Dispatched(receipt) => receipt,
            other => panic!("unexpected outcome: {other:?}"),
        };
        let store = service.into_store();
        let mut restarted = MissionScheduleService::with_store(
            RecordingWakeProvider::new(digest(b'p')),
            RecordingConsumer::new(digest(b'c')),
            store,
        )
        .expect("restart");
        assert_eq!(
            restarted
                .wake_once(&token, utc(2026, 8, 14, 9, 2))
                .expect("receipt replay"),
            MissionScheduleWakeOutcome::AlreadyDispatched(receipt)
        );
        assert_eq!(restarted.consumer().calls, 0);
    }

    #[test]
    fn storage_failure_after_consumer_ack_retries_reserved_dispatch_once() {
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b'f',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::FailClosed,
        );
        let mut service = MissionScheduleService::with_store(
            RecordingWakeProvider::new(digest(b'p')),
            RecordingConsumer::new(digest(b'c')),
            FailOnceStore::new(3),
        )
        .expect("service");
        service.create(&draft, observed_at).expect("create");
        let token = token_for_fail_once_store(&service, &draft.schedule_id_digest);
        assert_eq!(
            service.wake_once(&token, utc(2026, 8, 14, 9, 1)),
            Err(RecurringScheduleError::Store(
                MissionScheduleStoreError::WriteRejected,
            ))
        );
        let reserved = service
            .schedule(&draft.schedule_id_digest)
            .expect("reserved");
        assert_eq!(reserved.status, MissionScheduleStatus::Dispatching);
        assert!(reserved.pending_dispatch.is_some());
        assert_eq!(service.consumer().calls, 1);

        let retried = service
            .wake_once(&token, utc(2026, 8, 14, 9, 2))
            .expect("retry");
        let receipt = match retried {
            MissionScheduleWakeOutcome::Dispatched(receipt) => receipt,
            other => panic!("unexpected retry outcome: {other:?}"),
        };
        assert_eq!(receipt.wake_token_digest, token.token_digest);
        assert_eq!(service.consumer().calls, 1);
        assert_eq!(
            service
                .schedule(&draft.schedule_id_digest)
                .expect("active")
                .status,
            MissionScheduleStatus::Active
        );
        assert_eq!(
            service.dispatch_receipt(&receipt.dispatch_id_digest),
            Some(&receipt)
        );
    }

    #[test]
    fn create_save_failure_compensates_wake_before_retry() {
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b'c',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::FailClosed,
        );
        let mut service = MissionScheduleService::with_store(
            RecordingWakeProvider::new(digest(b'p')),
            RecordingConsumer::new(digest(b'c')),
            FailOnceStore::new(1),
        )
        .expect("service");
        assert_eq!(
            service.create(&draft, observed_at),
            Err(RecurringScheduleError::Store(
                MissionScheduleStoreError::WriteRejected,
            ))
        );
        assert!(service.provider().armed.is_empty());
        assert!(service.schedule(&draft.schedule_id_digest).is_none());

        service.create(&draft, observed_at).expect("retry");
        assert_eq!(service.provider().armed.len(), 1);
        assert_eq!(service.provider().arm_calls, 2);
    }

    #[test]
    fn create_compensation_failure_is_typed_uncertain_and_blocks_replay() {
        let observed_at = utc(2026, 8, 14, 8, 0);
        let draft = daily_draft(
            b'u',
            local(2026, 8, 14, 9, 0),
            ScheduleTimezone::utc(),
            LateWakePolicy::FailClosed,
        );
        let mut service = MissionScheduleService::with_store(
            RecordingWakeProvider::new(digest(b'p')),
            RecordingConsumer::new(digest(b'c')),
            FailOnceStore::new(1),
        )
        .expect("service");
        service.provider_mut().fail_disarm = true;

        assert_eq!(
            service.create(&draft, observed_at),
            Err(RecurringScheduleError::WakeStateUncertain {
                operation: "create".to_owned(),
            })
        );
        assert!(service.wake_uncertainty().is_some());
        assert_eq!(service.provider().armed.len(), 1);
        assert_eq!(service.provider().arm_calls, 1);
        assert_eq!(
            service.create(&draft, observed_at),
            Err(RecurringScheduleError::WakeStateUncertain {
                operation: "create".to_owned(),
            })
        );
        assert_eq!(service.provider().arm_calls, 1);
    }

    fn token_for_fail_once_store(
        service: &MissionScheduleService<RecordingWakeProvider, RecordingConsumer, FailOnceStore>,
        schedule_id_digest: &str,
    ) -> DispatchWakeToken {
        let record = service.schedule(schedule_id_digest).expect("schedule");
        DispatchWakeToken::issue(
            record,
            record.next_occurrence.as_ref().expect("next occurrence"),
        )
        .expect("token")
    }

    fn token_for_service<P, C>(
        service: &MissionScheduleService<P, C, SqliteMissionScheduleStore>,
        schedule_id_digest: &str,
    ) -> DispatchWakeToken
    where
        P: MissionScheduleWakeProvider,
        C: MissionCapabilityConsumer,
    {
        let record = service.schedule(schedule_id_digest).expect("schedule");
        DispatchWakeToken::issue(
            record,
            record.next_occurrence.as_ref().expect("next occurrence"),
        )
        .expect("token")
    }
}
