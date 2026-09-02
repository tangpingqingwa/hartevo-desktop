use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use hartevo_cordis::{
    AgentRef, JobControl, JobError, JobKillOutcome, JobOutcome, JobStatus, JobTerminalStatus,
    JobsSurface, LifecycleCancellation, SessionId,
};

fn session(id: &str) -> SessionId {
    SessionId::new(id).unwrap()
}

#[test]
fn jobs_are_session_fenced_and_publish_one_terminal_result() {
    let jobs = JobsSurface::new(2);
    let owner = session("jobs-owner");
    let agent = AgentRef::new("jobs-owner-agent");
    let other = session("jobs-other");
    let job_id = jobs
        .start(&owner, &agent, "bash", "printf ready", |completion| {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                assert!(
                    completion.complete(
                        JobOutcome::new(JobTerminalStatus::Completed)
                            .with_detail("exit code: 0")
                            .with_output("ready"),
                    )
                );
            });
            Ok(JobControl::new(|_| {}))
        })
        .unwrap();

    assert_eq!(job_id.as_str(), "bash-1");
    assert_eq!(jobs.list(&owner).len(), 1);
    assert!(jobs.list(&other).is_empty());
    assert!(matches!(
        jobs.get(job_id.as_str(), &other),
        Err(JobError::AccessDenied { .. })
    ));
    assert!(
        jobs.read(job_id.as_str(), &owner)
            .unwrap()
            .output()
            .is_empty()
    );

    let snapshot = jobs
        .wait(
            job_id.as_str(),
            &owner,
            Duration::from_secs(1),
            &LifecycleCancellation::default(),
        )
        .unwrap();
    assert_eq!(snapshot.status(), JobStatus::Completed);
    assert_eq!(snapshot.detail(), Some("exit code: 0"));
    assert!(snapshot.finished_at_ms().is_some());
    let read = jobs.read(job_id.as_str(), &owner).unwrap();
    assert_eq!(read.output(), "ready");
    assert_eq!(read.snapshot(), &snapshot);
    assert_eq!(
        jobs.read(job_id.as_str(), &owner).unwrap().output(),
        "ready"
    );
}

#[test]
fn controller_kill_owns_cancellation_and_wait_observes_killed() {
    let jobs = JobsSurface::new(2);
    let owner = session("jobs-kill");
    let agent = AgentRef::new("jobs-kill-agent");
    let stopped = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_stop = Arc::clone(&stopped);
    let control_stop = Arc::clone(&stopped);
    let job_id = jobs
        .start(&owner, &agent, "bash", "sleep 30", move |completion| {
            std::thread::spawn(move || {
                let (lock, changed) = &*worker_stop;
                let mut stopped = lock.lock().unwrap();
                while !*stopped {
                    stopped = changed.wait(stopped).unwrap();
                }
                assert!(completion.complete(
                    JobOutcome::new(JobTerminalStatus::Killed).with_detail("killed before exit"),
                ));
            });
            Ok(JobControl::new(move |_| {
                let (lock, changed) = &*control_stop;
                *lock.lock().unwrap() = true;
                changed.notify_all();
            }))
        })
        .unwrap();

    assert_eq!(
        jobs.kill(job_id.as_str(), &owner, Some("not needed"))
            .unwrap(),
        JobKillOutcome::Requested
    );
    let settled = jobs
        .wait(
            job_id.as_str(),
            &owner,
            Duration::from_secs(1),
            &LifecycleCancellation::default(),
        )
        .unwrap();
    assert_eq!(settled.status(), JobStatus::Killed);
    assert_eq!(
        jobs.kill(job_id.as_str(), &owner, None).unwrap(),
        JobKillOutcome::AlreadyFinished
    );
}

#[test]
fn per_session_limit_and_owner_teardown_leave_no_live_job() {
    let jobs = JobsSurface::new(1);
    let owner = session("jobs-limit");
    let agent = AgentRef::new("jobs-limit-agent");
    let stopped = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_stop = Arc::clone(&stopped);
    let control_stop = Arc::clone(&stopped);
    let first = jobs
        .start(&owner, &agent, "bash", "first", move |completion| {
            std::thread::spawn(move || {
                let (lock, changed) = &*worker_stop;
                let mut stopped = lock.lock().unwrap();
                while !*stopped {
                    stopped = changed.wait(stopped).unwrap();
                }
                let _ = completion.complete(JobOutcome::new(JobTerminalStatus::Killed));
            });
            Ok(JobControl::new(move |_| {
                let (lock, changed) = &*control_stop;
                *lock.lock().unwrap() = true;
                changed.notify_all();
            }))
        })
        .unwrap();

    assert!(matches!(
        jobs.start(&owner, &agent, "bash", "second", |_| Ok(JobControl::new(
            |_| {}
        ))),
        Err(JobError::LimitReached { limit: 1, .. })
    ));
    let same_id_replacement = AgentRef::new(agent.id.clone());
    assert!(jobs.dispose_agent_and_wait(&same_id_replacement, Duration::from_secs(1)));
    assert_eq!(
        jobs.get(first.as_str(), &owner).unwrap().status(),
        JobStatus::Running
    );
    assert!(jobs.dispose_agent_and_wait(&agent, Duration::from_secs(1)));
    assert!(matches!(
        jobs.get(first.as_str(), &owner),
        Err(JobError::Unknown { .. })
    ));

    let second = jobs
        .start(&owner, &agent, "bash", "second", |completion| {
            let _ = completion.complete(JobOutcome::new(JobTerminalStatus::Completed));
            Ok(JobControl::new(|_| {}))
        })
        .unwrap();
    assert_eq!(
        jobs.get(second.as_str(), &owner).unwrap().status(),
        JobStatus::Completed
    );
    assert!(jobs.shutdown());
    assert!(matches!(
        jobs.start(&owner, &agent, "bash", "third", |_| Ok(JobControl::new(
            |_| {}
        ))),
        Err(JobError::ShuttingDown)
    ));
}

#[test]
fn wait_cancellation_does_not_stop_the_job() {
    let jobs = JobsSurface::new(1);
    let owner = session("jobs-wait-cancel");
    let agent = AgentRef::new("jobs-wait-cancel-agent");
    let stopped = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_stop = Arc::clone(&stopped);
    let control_stop = Arc::clone(&stopped);
    let id = jobs
        .start(&owner, &agent, "bash", "held", move |completion| {
            std::thread::spawn(move || {
                let (lock, changed) = &*worker_stop;
                let mut stopped = lock.lock().unwrap();
                while !*stopped {
                    stopped = changed.wait(stopped).unwrap();
                }
                let _ = completion.complete(JobOutcome::new(JobTerminalStatus::Killed));
            });
            Ok(JobControl::new(move |_| {
                let (lock, changed) = &*control_stop;
                *lock.lock().unwrap() = true;
                changed.notify_all();
            }))
        })
        .unwrap();
    let cancellation = LifecycleCancellation::default();
    cancellation.cancel();

    assert_eq!(
        jobs.wait(id.as_str(), &owner, Duration::from_secs(1), &cancellation,)
            .unwrap_err(),
        JobError::WaitCancelled
    );
    assert_eq!(
        jobs.get(id.as_str(), &owner).unwrap().status(),
        JobStatus::Running
    );
    assert_eq!(
        jobs.kill(id.as_str(), &owner, None).unwrap(),
        JobKillOutcome::Requested
    );
    assert!(jobs.dispose_agent_and_wait(&agent, Duration::from_secs(1)));
}
