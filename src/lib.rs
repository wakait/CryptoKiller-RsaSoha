#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rug::integer::IsPrime;
use rug::Integer;
use std::cell::RefCell;
use std::sync::mpsc;
use std::sync::Arc;

mod attack;
mod factors;
mod key;
mod math;
mod params;
mod solution;

pub use attack::*;
pub use factors::*;
pub use key::*;
pub use math::conversion::{
    bytes_to_integer, integer_to_bytes, integer_to_string, string_to_integer,
};
pub use params::*;
pub use solution::*;

fn check_n_prime(n: &Option<Integer>) -> bool {
    if let Some(n) = &n {
        match n.is_probably_prime(100) {
            IsPrime::Yes => {
                return true;
            }
            IsPrime::Probably => {
                eprintln!("Warning: n is probably prime, but not certain");
            }
            _ => {}
        }
    }
    false
}

fn create_multi_progress(nb_attacks: usize) -> (Arc<MultiProgress>, Arc<ProgressBar>) {
    let mp = Arc::new(MultiProgress::new());
    let pb_main = Arc::new(mp.add(ProgressBar::new(nb_attacks as u64)));

    pb_main.set_style(
        ProgressStyle::with_template(
            "{prefix:>12.bold} [{elapsed_precise}] {msg}[{wide_bar}] {pos}/{len:<4}",
        )
        .unwrap()
        .progress_chars("=> "),
    );
    pb_main.set_prefix("Running");
    (mp, pb_main)
}

fn create_progress_bar(mp: &MultiProgress) -> ProgressBar {
    let pb = mp.insert(0, ProgressBar::new(1));
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:>12.bold} [{elapsed_precise}] [{wide_bar}] {percent:>3}% ({eta:^4}) ",
        )
        .unwrap(),
    );
    pb
}

async fn _run_attacks(
    params: Arc<Parameters>,
    attacks: &[Arc<dyn Attack + Sync + Send>],
    sender: mpsc::Sender<Result<Solution, Error>>,
    mp: Arc<MultiProgress>,
    control: AttackControl,
) {
    // Create all progress bars
    let pbs = RefCell::new(Vec::with_capacity(attacks.len()));
    for _ in 0..attacks.len() {
        pbs.borrow_mut().push(Arc::new(create_progress_bar(&mp)));
    }

    for (attack, pb) in attacks.iter().cloned().zip(pbs.borrow().iter().cloned()) {
        // Clone variables for closure
        let params = Arc::clone(&params);
        let sender = sender.clone();
        let mp = Arc::clone(&mp);
        let pbs = RefCell::clone(&pbs);
        let control = control.clone();

        // Spawn attack as a task
        tokio::task::spawn(async move {
            // This unhide the progress bar
            pb.set_prefix(attack.name());

            let solution =
                attack
                    .run_cancellable(&params, Some(&pb), &control)
                    .map(|mut solution| {
                        // Try to decrypt the cipher if no message was found
                        if let (Some(pk), None, Some(c)) = (&solution.pk, &solution.m, &params.c) {
                            solution.m = Some(pk.decrypt(c))
                        }
                        solution
                    });

            // Remove progress bar from list
            mp.remove(&pb);
            // If attack was successful, cancel its siblings and clear all progress bars
            if solution.is_ok() {
                control.cancel();
                for pb in pbs.borrow().iter() {
                    pb.finish_and_clear();
                }
            }

            // Send result to main thread
            // Note: error if channel closed
            sender.send(solution).ok();
        });
    }
}

/// Run all attacks on all available CPU cores.
pub fn run_attacks(params: &Parameters) -> Result<Solution, Option<Factors>> {
    run_specific_attacks_with_threads(params, &ATTACKS, num_cpus::get())
}

/// Run specific attacks on all available CPU cores.
pub fn run_specific_attacks(
    params: &Parameters,
    attacks: &[Arc<dyn Attack + Sync + Send>],
) -> Result<Solution, Option<Factors>> {
    run_specific_attacks_with_threads(params, attacks, num_cpus::get())
}

/// Run all attacks on a given number of threads.
pub fn run_attacks_with_threads(
    params: &Parameters,
    threads: usize,
) -> Result<Solution, Option<Factors>> {
    run_specific_attacks_with_threads(params, &ATTACKS, threads)
}

/// Run specific attacks on a given number of threads.
pub fn run_specific_attacks_with_threads(
    params: &Parameters,
    attacks: &[Arc<dyn Attack + Sync + Send>],
    threads: usize,
) -> Result<Solution, Option<Factors>> {
    run_specific_attacks_with_control(params, attacks, threads, AttackControl::default())
}

/// Run specific attacks with an explicit shared cancellation and candidate-budget control.
pub fn run_specific_attacks_with_control(
    params: &Parameters,
    attacks: &[Arc<dyn Attack + Sync + Send>],
    threads: usize,
    control: AttackControl,
) -> Result<Solution, Option<Factors>> {
    if check_n_prime(&params.n)
        && !(params.c.is_some() && attacks.iter().any(|attack| attack.supports_prime_modulus()))
    {
        eprintln!("Error: N is prime, no selected attack can use it");
        return Err(None);
    }

    // Used for key build from partial factors
    let param_e = params.e.clone();

    // Create channel for sending result
    let (sender, receiver) = mpsc::channel();

    // Create progress bar
    let (mp, pb_main) = create_multi_progress(attacks.len());

    // Create runtime
    let params = Arc::new(params.clone());
    let r = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();

    // Spawn attacks in background
    let attacks = attacks.to_vec();
    r.spawn(async move { _run_attacks(params, &attacks, sender, mp, control).await });

    // Retrieve result
    let mut partial_factors: Option<Factors> = None;
    let solution = loop {
        // Receive solution or error for each attack
        match receiver.recv() {
            Ok(Ok(solution)) => break Some(solution),
            Ok(Err(Error::PartialFactorization(factor))) => {
                if let Some(partial_factors) = &mut partial_factors {
                    partial_factors.merge(&factor);
                } else {
                    partial_factors = Some(factor);
                }

                // Try to create a private key from the partial factors
                if let Ok(private_key) =
                    PrivateKey::from_factors(partial_factors.as_ref().unwrap().clone(), &param_e)
                {
                    break Some(Solution::new_pk("Partial factors", private_key));
                }
                pb_main.set_message(format!(
                    "({} factors found) ",
                    partial_factors.as_ref().unwrap().len()
                ));
            }
            Ok(_) => {}
            Err(_) => {
                // Channel closed, no more results available
                break None;
            }
        }

        // Update progress bar
        pb_main.inc(1);
    };

    // Shut down runtime
    r.shutdown_background();

    if let Some(solution) = solution {
        Ok(solution)
    } else {
        Err(partial_factors)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use rug::ops::Pow;

    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct CancellationObserver {
        started: Arc<AtomicBool>,
        observed: Arc<AtomicBool>,
    }

    impl Attack for CancellationObserver {
        fn name(&self) -> &'static str {
            "cancellation_observer"
        }

        fn run(&self, _params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
            Err(Error::NotFound)
        }

        fn run_cancellable(
            &self,
            _params: &Parameters,
            _pb: Option<&ProgressBar>,
            control: &AttackControl,
        ) -> Result<Solution, Error> {
            self.started.store(true, Ordering::SeqCst);
            while !control.is_cancelled() {
                std::thread::yield_now();
            }
            self.observed.store(true, Ordering::SeqCst);
            Err(Error::Cancelled)
        }
    }

    #[derive(Debug)]
    struct WaitForObserver {
        started: Arc<AtomicBool>,
    }

    impl Attack for WaitForObserver {
        fn name(&self) -> &'static str {
            "wait_for_observer"
        }

        fn run(&self, _params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
            Err(Error::NotFound)
        }

        fn run_cancellable(
            &self,
            _params: &Parameters,
            _pb: Option<&ProgressBar>,
            _control: &AttackControl,
        ) -> Result<Solution, Error> {
            for _ in 0..10_000 {
                if self.started.load(Ordering::SeqCst) {
                    return Ok(Solution::new_m(self.name(), Integer::from(1)));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(Error::NotFound)
        }
    }

    #[test]
    fn successful_attack_cancels_shared_control() {
        let started = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let attacks: Vec<Arc<dyn Attack + Sync + Send>> = vec![
            Arc::new(CancellationObserver {
                started: started.clone(),
                observed: observed.clone(),
            }),
            Arc::new(WaitForObserver {
                started: started.clone(),
            }),
        ];
        let params = Parameters {
            n: Some(Integer::from(3233)),
            ..Default::default()
        };

        let solution =
            run_specific_attacks_with_control(&params, &attacks, 2, AttackControl::default())
                .unwrap();
        assert_eq!(solution.attack, "wait_for_observer");

        for _ in 0..1_000 {
            if observed.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(observed.load(Ordering::SeqCst));
    }

    #[test]
    fn explicit_control_budget_reaches_partial_prime() {
        let params = Parameters {
            n: Some(Integer::from(3233)),
            partial_p: Some(PartialPrime::Partial {
                radix: 16,
                k: Some(2),
                orient: Orientation::MsbKnown,
                known: Integer::from(0x3d),
            }),
            ..Default::default()
        };
        assert!(run_specific_attacks_with_control(
            &params,
            &[Arc::new(PartialPrimeAttack)],
            1,
            AttackControl::new(0),
        )
        .is_err());
    }

    #[test]
    fn small_n_prime() {
        let params = Parameters {
            n: Some(17.into()),
            ..Default::default()
        };

        assert!(run_attacks(&params).is_err());
    }

    #[test]
    fn prime_modulus_attack_is_not_blocked_by_prime_guard() {
        let params = Parameters {
            n: Some(Integer::from(17)),
            e: Integer::from(5),
            c: Some(Integer::from(5)),
            ..Default::default()
        };

        let solution =
            run_specific_attacks_with_threads(&params, &[Arc::new(PrimeModulusAttack)], 1).unwrap();
        assert_eq!(solution.m, Some(Integer::from(3)));
    }

    #[test]
    fn cipolla_attack_is_not_blocked_by_prime_guard() {
        let params = Parameters {
            n: Some(Integer::from(23)),
            e: Integer::from(2),
            c: Some(Integer::from(4)),
            ..Default::default()
        };

        let solution =
            run_specific_attacks_with_threads(&params, &[Arc::new(CipollaAttack)], 1).unwrap();
        assert!(solution.ms.contains(&Integer::from(2)));
    }

    #[test]
    fn medium_n_prime() {
        let params = Parameters {
            n: Some(Integer::from_str("220375572875274133043506876099").unwrap()),
            ..Default::default()
        };

        assert!(run_attacks(&params).is_err());
    }

    #[test]
    fn partial_factors() {
        // n == 2 ^ 63 * 690712633549859897233 ^ 6
        let p = Integer::from(690712633549859897233u128);
        let params = Parameters {
            n: Some(Integer::from(2).pow(63) * p.clone().pow(5)),
            ..Default::default()
        };

        let err = run_specific_attacks(&params, &[Arc::new(SmallPrimeAttack)]).unwrap_err();
        let partial_factors = err.unwrap();
        assert_eq!(
            partial_factors.0,
            BTreeMap::from([(Integer::from(2), 63), (p.pow(5), 1),])
        );
    }
}
