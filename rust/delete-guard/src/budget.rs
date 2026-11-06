use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::errors::Stop;

/// A nested call clears the outer timer instead of restoring its remaining interval: Python's finally passes 0 to setitimer and drops the previous value.
static TIMER: Mutex<Timer> = Mutex::new(Timer {
    generation: 0,
    deadline: None,
});
static TIMER_CV: Condvar = Condvar::new();
static OUTPUT: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct Timer {
    generation: u64,
    deadline: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItimerError;

pub const HOOK_BUDGET_SECONDS: f64 = 3.0;

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    deadline: Option<Instant>,
    expired: bool,
}

impl Budget {
    pub fn new(seconds: f64) -> Self {
        if seconds == 0.0 {
            return Self {
                deadline: None,
                expired: false,
            };
        }
        if !seconds.is_finite() || seconds < 0.0 {
            return Self {
                deadline: None,
                expired: true,
            };
        }
        match Duration::try_from_secs_f64(seconds) {
            Ok(duration) => Self {
                deadline: Instant::now().checked_add(duration),
                expired: false,
            },
            Err(_) => Self {
                deadline: None,
                expired: true,
            },
        }
    }

    pub fn check(&self) -> Result<(), Stop> {
        if self.expired {
            return Err(Stop::TooSlow);
        }
        if let Some(deadline) = self.deadline {
            if Instant::now() >= deadline {
                return Err(Stop::TooSlow);
            }
        }
        Ok(())
    }
}

pub fn hook_budget_seconds() -> f64 {
    guard_common::overrides::number("HOOK_BUDGET_SECONDS").unwrap_or(HOOK_BUDGET_SECONDS)
}

pub fn with_output_lock<T>(body: impl FnOnce() -> T) -> T {
    let _guard = output_guard();
    body()
}

pub fn run_with_budget<W, S>(seconds: f64, work: W, on_too_slow: S) -> Result<(), ItimerError>
where
    W: FnOnce(),
    S: FnOnce() + Send + 'static,
{
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(ItimerError);
    }
    let duration = if seconds == 0.0 {
        None
    } else {
        Some(Duration::try_from_secs_f64(seconds).map_err(|_| ItimerError)?)
    };
    let generation = arm(duration);
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let watcher = match duration {
        Some(_) => {
            let flag = std::sync::Arc::clone(&done);
            Some(thread::spawn(move || watch(generation, flag, on_too_slow)))
        }
        None => None,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
    with_output_lock(|| {
        done.store(true, Ordering::SeqCst);
    });
    disarm_if_current(generation);
    if let Some(handle) = watcher {
        let _ = handle.join();
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
    Ok(())
}

fn output_guard() -> MutexGuard<'static, ()> {
    match OUTPUT.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn timer_lock() -> MutexGuard<'static, Timer> {
    match TIMER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn arm(duration: Option<Duration>) -> u64 {
    let mut timer = timer_lock();
    timer.generation = timer.generation.saturating_add(1);
    timer.deadline = duration.and_then(|span| Instant::now().checked_add(span));
    let generation = timer.generation;
    TIMER_CV.notify_all();
    generation
}

fn disarm_if_current(generation: u64) {
    let mut timer = timer_lock();
    if timer.generation == generation {
        timer.generation = timer.generation.saturating_add(1);
        timer.deadline = None;
        TIMER_CV.notify_all();
    }
}

#[cfg(test)]
fn timer_is_armed() -> bool {
    timer_lock().deadline.is_some()
}

fn watch(generation: u64, done: std::sync::Arc<AtomicBool>, on_too_slow: impl FnOnce()) {
    loop {
        let timer = timer_lock();
        if timer.generation != generation {
            return;
        }
        let Some(deadline) = timer.deadline else {
            return;
        };
        let now = Instant::now();
        if now >= deadline {
            drop(timer);
            break;
        }
        let wait = deadline.saturating_duration_since(now);
        let (timer, _) = match TIMER_CV.wait_timeout(timer, wait) {
            Ok(pair) => pair,
            Err(poisoned) => poisoned.into_inner(),
        };
        drop(timer);
    }
    let _output = output_guard();
    if done.load(Ordering::SeqCst) {
        return;
    }
    {
        let timer = timer_lock();
        if timer.generation != generation {
            return;
        }
    }
    on_too_slow();
    loop {
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        hook_budget_seconds, run_with_budget, timer_is_armed, with_output_lock, Budget, ItimerError,
        HOOK_BUDGET_SECONDS,
    };
    use crate::errors::Stop;
    use std::process::Command;
    use std::sync::{Arc, Barrier, Mutex, MutexGuard};
    use std::thread;
    use std::time::Duration;

    static TIMER_TEST: Mutex<()> = Mutex::new(());

    fn timer_test_lock() -> MutexGuard<'static, ()> {
        match TIMER_TEST.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn budget_constant_matches_python() {
        assert_eq!(HOOK_BUDGET_SECONDS, 3.0);
        assert_eq!(hook_budget_seconds(), 3.0);
    }

    #[test]
    fn cooperative_budget_expires_only_when_armed() {
        assert!(Budget::new(30.0).check().is_ok());
        assert!(Budget::new(0.0).check().is_ok());
        assert_eq!(Budget::new(-1.0).check(), Err(Stop::TooSlow));
        assert_eq!(Budget::new(f64::NAN).check(), Err(Stop::TooSlow));
        let expired = Budget::new(0.05);
        thread::sleep(Duration::from_millis(80));
        assert_eq!(expired.check(), Err(Stop::TooSlow));
    }

    #[test]
    fn zero_budget_disarms_and_runs_the_work() {
        let _timer = timer_test_lock();
        let mut ran = false;
        let result = run_with_budget(
            0.0,
            || {
                ran = true;
                assert!(!timer_is_armed());
            },
            || panic!("zero budget must not time out"),
        );
        assert_eq!(result, Ok(()));
        assert!(ran);
        assert!(!timer_is_armed());
    }

    #[test]
    fn negative_budget_does_not_run_and_leaves_an_outer_timer() {
        let _timer = timer_test_lock();
        let result = run_with_budget(
            30.0,
            || {
                assert!(timer_is_armed());
                let inner = run_with_budget(-0.1, || panic!("negative budget ran the work"), || {});
                assert_eq!(inner, Err(ItimerError));
                assert!(timer_is_armed());
                let huge = run_with_budget(1e308, || panic!("overflow budget ran the work"), || {});
                assert_eq!(huge, Err(ItimerError));
                assert!(timer_is_armed());
            },
            || panic!("outer budget must not fire"),
        );
        assert_eq!(result, Ok(()));
        assert!(!timer_is_armed());
    }

    #[test]
    fn nested_call_disarms_the_outer_timer() {
        let _timer = timer_test_lock();
        let result = run_with_budget(
            30.0,
            || {
                assert!(timer_is_armed());
                run_with_budget(
                    0.0,
                    || {
                        assert!(!timer_is_armed());
                    },
                    || panic!("inner zero budget fired"),
                )
                .expect("zero budget");
                assert!(!timer_is_armed());
                run_with_budget(
                    30.0,
                    || {
                        assert!(timer_is_armed());
                    },
                    || panic!("inner positive budget fired"),
                )
                .expect("inner budget");
                assert!(!timer_is_armed());
            },
            || panic!("outer budget fired after a nested call"),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn finished_work_disarms_the_timer() {
        let _timer = timer_test_lock();
        let result = run_with_budget(30.0, || assert!(timer_is_armed()), || panic!("fired"));
        assert_eq!(result, Ok(()));
        assert!(!timer_is_armed());
    }

    #[test]
    fn output_lock_is_exclusive() {
        let barrier = Arc::new(Barrier::new(2));
        let started = Arc::clone(&barrier);
        let holder = thread::spawn(move || {
            with_output_lock(|| {
                started.wait();
                thread::sleep(Duration::from_millis(200));
            });
        });
        barrier.wait();
        let began = std::time::Instant::now();
        with_output_lock(|| {});
        assert!(began.elapsed() >= Duration::from_millis(100));
        holder.join().expect("holder");
    }

    #[test]
    fn timeout_runs_the_slow_callback_and_does_not_return() {
        let _timer = timer_test_lock();
        if std::env::var_os("D0_TIMEOUT_CHILD").is_some() {
            let _ = run_with_budget(
                0.2,
                || {
                    thread::sleep(Duration::from_secs(3));
                    println!("RETURNED");
                },
                || {
                    println!("TOO_SLOW");
                    std::process::exit(7);
                },
            );
            println!("AFTER");
            return;
        }
        let exe = std::env::current_exe().expect("test binary");
        let output = Command::new(exe)
            .env("D0_TIMEOUT_CHILD", "1")
            .args(["--exact", "budget::tests::timeout_runs_the_slow_callback_and_does_not_return", "--nocapture"])
            .output()
            .expect("spawn timeout child");
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(7), "{text}");
        assert!(text.contains("TOO_SLOW"), "{text}");
        assert!(!text.contains("RETURNED"), "{text}");
        assert!(!text.contains("AFTER"), "{text}");
    }
}
