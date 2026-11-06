use std::cell::Cell;
use std::thread::LocalKey;

#[derive(Debug)]
pub struct RecursionLimit;

struct Restore(&'static LocalKey<Cell<usize>>);

impl Drop for Restore {
    fn drop(&mut self) {
        self.0.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub fn with_depth<T>(counter: &'static LocalKey<Cell<usize>>, limit: usize, body: impl FnOnce() -> T) -> T {
    let level = counter.with(|depth| {
        depth.set(depth.get() + 1);
        depth.get()
    });
    let _restore = Restore(counter);
    if level > limit {
        std::panic::panic_any(RecursionLimit);
    }
    body()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{with_depth, RecursionLimit};

    thread_local! {
        static LEVEL: Cell<usize> = const { Cell::new(0) };
    }

    fn nest(count: usize) -> usize {
        with_depth(&LEVEL, 10, || if count == 0 { 0 } else { 1 + nest(count - 1) })
    }

    #[test]
    fn deeper_than_the_limit_raises_and_the_counter_recovers() {
        assert_eq!(nest(9), 9);
        let caught = std::panic::catch_unwind(|| nest(10));
        assert!(caught.is_err_and(|payload| payload.downcast_ref::<RecursionLimit>().is_some()));
        assert_eq!(nest(9), 9);
    }
}
