//! Optional provider-routed model-request retry executor.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::context::{Context, CordisError, keys};
use crate::event::WaterfallFailure;
use crate::service::Service;
use crate::session::{SessionError, SessionEventKind, SessionLlmRetryMode, SessionStore};
use crate::surface::{
    AgentRequestError, AgentRequestErrorAction, AgentRetrySchedule, LlmRetryPolicy,
    LlmRetryPolicyMode, events,
};

/// Dependencies required by the retry executor.
pub const LLM_RETRY_KEYS: &[&str] = &[keys::SESSIONS];

/// Optional Cordis plugin that applies each failed adapter generation's policy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LlmRetry;

impl Service for LlmRetry {
    fn inject() -> &'static [&'static str] {
        LLM_RETRY_KEYS
    }

    fn apply(self, ctx: &mut Context) -> Result<(), CordisError> {
        let sessions = ctx
            .sessions::<SessionStore>()
            .ok_or_else(|| CordisError::MissingDependencies(vec![keys::SESSIONS.to_string()]))?;
        ctx.try_on_waterfall(events::AGENT_REQUEST_ERROR, move |recovery, next| {
            let Some(policy) = recovery.retry_policy().cloned() else {
                return next(recovery);
            };
            if recovery.cancellation().is_cancelled() {
                return Ok(recovery);
            }

            match policy.mode() {
                LlmRetryPolicyMode::Always => {
                    let fallback = recovery.clone();
                    match next(recovery) {
                        Ok(downstream)
                            if downstream.cancellation().is_cancelled()
                                || downstream.action() == AgentRequestErrorAction::Retry =>
                        {
                            Ok(downstream)
                        }
                        Ok(downstream) => schedule_or_preserve(&sessions, downstream, &policy),
                        Err(_) if fallback.cancellation().is_cancelled() => Ok(fallback),
                        Err(_) => schedule_or_preserve(&sessions, fallback, &policy),
                    }
                }
                LlmRetryPolicyMode::Normal {
                    retryable_codes, ..
                } if retryable_codes
                    .iter()
                    .any(|code| code == recovery.failure().code.as_str()) =>
                {
                    schedule_or_delegate(&sessions, recovery, &policy, next)
                }
                LlmRetryPolicyMode::Normal { .. } => next(recovery),
            }
        })?;
        Ok(())
    }
}

fn schedule_or_preserve(
    sessions: &SessionStore,
    recovery: AgentRequestError,
    policy: &LlmRetryPolicy,
) -> Result<AgentRequestError, WaterfallFailure> {
    Ok(match retry_schedule(sessions, &recovery, policy)? {
        Some(schedule) => recovery.retry_with_schedule(schedule),
        None => recovery,
    })
}

fn schedule_or_delegate(
    sessions: &SessionStore,
    recovery: AgentRequestError,
    policy: &LlmRetryPolicy,
    next: crate::event::TryWaterfallNext<AgentRequestError>,
) -> Result<AgentRequestError, WaterfallFailure> {
    match retry_schedule(sessions, &recovery, policy)? {
        Some(schedule) => Ok(recovery.retry_with_schedule(schedule)),
        None => next(recovery),
    }
}

fn retry_schedule(
    sessions: &SessionStore,
    recovery: &AgentRequestError,
    policy: &LlmRetryPolicy,
) -> Result<Option<AgentRetrySchedule>, WaterfallFailure> {
    let session = sessions
        .get(recovery.session_id())
        .map_err(WaterfallFailure::source)?
        .ok_or_else(|| {
            WaterfallFailure::source(SessionError::SessionNotFound {
                id: recovery.session_id().clone(),
            })
        })?;
    let events = session.events().map_err(WaterfallFailure::source)?;
    let policy_key = policy.policy_key();
    let prior = events.iter().rev().find_map(|event| {
        let SessionEventKind::LlmRetry { retry } = &event.kind else {
            return None;
        };
        (retry.turn == recovery.turn()
            && retry.step == recovery.step()
            && retry.provider == recovery.provider()
            && retry.policy_key == policy_key)
            .then_some((retry.retry_id.clone(), retry.retry))
    });
    let previous_retry = prior.as_ref().map_or(0, |(_, retry)| *retry);
    let (mode, max_retries) = match policy.mode() {
        LlmRetryPolicyMode::Normal { max_retries, .. } => {
            if previous_retry >= *max_retries {
                return Ok(None);
            }
            (SessionLlmRetryMode::Normal, Some(*max_retries))
        }
        LlmRetryPolicyMode::Always => (SessionLlmRetryMode::Always, None),
    };
    let retry = previous_retry.checked_add(1).ok_or_else(|| {
        WaterfallFailure::source(SessionError::InvalidLlmRetry {
            expected: "a retry number without overflow",
        })
    })?;
    let delay_ms = match recovery.failure().provider_retry_after_ms {
        Some(delay) if delay > 0 && delay <= policy.max_delay_ms() => delay,
        Some(delay) if delay > policy.max_delay_ms() && mode == SessionLlmRetryMode::Normal => {
            return Ok(None);
        }
        _ => local_delay(policy, retry),
    };
    let retry_id = prior.map_or_else(
        || {
            format!(
                "{}:{}:{}:{}:{}",
                recovery.session_id(),
                recovery.turn(),
                recovery.step(),
                recovery.provider(),
                events.len(),
            )
        },
        |(retry_id, _)| retry_id,
    );
    Ok(Some(AgentRetrySchedule::new(
        retry_id,
        mode,
        policy_key,
        retry,
        max_retries,
        delay_ms,
    )))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "validated millisecond bounds are exactly representable; flooring implements timer quantization"
)]
fn local_delay(policy: &LlmRetryPolicy, retry: u64) -> u64 {
    let exponent = u32::try_from(retry.saturating_sub(1))
        .unwrap_or(u32::MAX)
        .min(63);
    let exponential = policy
        .initial_delay_ms()
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(policy.max_delay_ms());
    let random = random_sample();
    let multiplier = 1.0 - policy.jitter_ratio() + 2.0 * policy.jitter_ratio() * random;
    ((exponential as f64 * multiplier).floor() as u64).min(policy.max_delay_ms())
}

fn random_sample() -> f64 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let time = elapsed.as_secs() ^ u64::from(elapsed.subsec_nanos());
    let mut value = time
        ^ SEQUENCE
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    let bits = value.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11;
    #[allow(
        clippy::cast_precision_loss,
        reason = "the upper 53 bits intentionally form a uniform floating-point jitter sample"
    )]
    let sample = bits as f64 / ((1_u64 << 53) - 1) as f64;
    sample
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_delay_is_exponential_and_capped_without_jitter() {
        let policy = LlmRetryPolicy::always(10, 25, 0.0).unwrap();
        assert_eq!(local_delay(&policy, 1), 10);
        assert_eq!(local_delay(&policy, 2), 20);
        assert_eq!(local_delay(&policy, 3), 25);
        assert_eq!(local_delay(&policy, u64::MAX), 25);
    }

    #[test]
    fn production_jitter_sample_stays_inclusive_zero_to_one() {
        for _ in 0..128 {
            assert!((0.0..=1.0).contains(&random_sample()));
        }
    }
}
