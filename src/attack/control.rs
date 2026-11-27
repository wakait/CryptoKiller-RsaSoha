use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use super::Error;

/// Default number of pure-enumeration candidates shared by one attack run.
pub const DEFAULT_SEARCH_BUDGET: u64 = 1 << 28;
/// Maximum number of candidates processed between cancellation checks.
pub const CANCEL_CHECK_BATCH: usize = 1024;
/// Maximum supported LLL basis dimension.
pub const MAX_LLL_DIMENSION: usize = 64;
/// Maximum supported number of LLL iterations.
pub const MAX_LLL_ITERATIONS: usize = 100_000;
/// Maximum supported polynomial degree.
pub const MAX_POLYNOMIAL_DEGREE: usize = 257;
/// Maximum deterministic shifts tried to split one square-free finite-field factor.
pub const MAX_ROOT_SPLIT_ATTEMPTS: usize = 256;

/// Cooperative cancellation and a shared atomic candidate budget.
#[derive(Debug, Clone)]
pub struct AttackControl {
    cancelled: Arc<AtomicBool>,
    used: Arc<AtomicU64>,
    budget: u64,
}

impl AttackControl {
    /// Create a control object with the given candidate budget.
    pub fn new(budget: u64) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            used: Arc::new(AtomicU64::new(0)),
            budget,
        }
    }

    /// Cancel all attacks sharing this control object.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Return whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Return `Error::Cancelled` when cancellation has been requested.
    pub fn check_cancelled(&self) -> Result<(), Error> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Return the number of candidates still available to reserve.
    pub fn remaining(&self) -> u64 {
        self.budget.saturating_sub(self.used.load(Ordering::SeqCst))
    }

    /// Atomically reserve `count` candidates without exceeding the shared budget.
    pub fn reserve_candidates(&self, count: u64) -> Result<(), Error> {
        self.check_cancelled()?;
        if count == 0 {
            return Ok(());
        }
        self.used
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                if self.is_cancelled() {
                    return None;
                }
                used.checked_add(count).filter(|next| *next <= self.budget)
            })
            .map_err(|_| {
                if self.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::BudgetExceeded
                }
            })?;
        self.check_cancelled()
    }
}

impl Default for AttackControl {
    fn default() -> Self {
        Self::new(DEFAULT_SEARCH_BUDGET)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn reservations_are_shared_across_clones() {
        let control = AttackControl::new(10);
        let clone = control.clone();
        control.reserve_candidates(6).unwrap();
        clone.reserve_candidates(4).unwrap();
        assert_eq!(clone.reserve_candidates(1), Err(Error::BudgetExceeded));
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn cancellation_wins_over_budget() {
        let control = AttackControl::new(0);
        control.cancel();
        assert_eq!(control.reserve_candidates(1), Err(Error::Cancelled));
    }

    #[test]
    fn zero_budget_disables_enumeration() {
        let control = AttackControl::new(0);
        assert_eq!(control.reserve_candidates(1), Err(Error::BudgetExceeded));
    }

    #[test]
    fn concurrent_reservations_never_exceed_budget() {
        let control = Arc::new(AttackControl::new(100));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let control = control.clone();
                thread::spawn(move || control.reserve_candidates(20))
            })
            .collect();
        let successes = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap().ok())
            .count();
        assert_eq!(successes, 5);
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn default_control_uses_default_search_budget() {
        let control = AttackControl::default();
        assert_eq!(control.remaining(), DEFAULT_SEARCH_BUDGET);
    }
}
