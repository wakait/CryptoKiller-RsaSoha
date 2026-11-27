use indicatif::ProgressBar;
use rug::ops::Pow;
use rug::{integer::IsPrime, Complete, Integer};

use crate::{
    attack::advanced::CoppersmithFactorAttack, key::PrivateKey, Attack, AttackControl, AttackKind,
    AttackSpeed, Error, Orientation, Parameters, PartialPrime, Solution, CANCEL_CHECK_BATCH,
};

/// Partial prime attack (MSB or LSB of prime known)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialPrimeAttack;

impl PartialPrimeAttack {
    fn prefer_error(current: Error, next: Error) -> Error {
        match (current, next) {
            (Error::Cancelled, _) | (_, Error::Cancelled) => Error::Cancelled,
            (Error::BudgetExceeded, _) | (_, Error::BudgetExceeded) => Error::BudgetExceeded,
            (Error::Unsupported, _) | (_, Error::Unsupported) => Error::Unsupported,
            (Error::NotFound, next) => next,
            (current, _) => current,
        }
    }

    fn enumeration_limit(
        search_space: &Integer,
        radix_k: &Integer,
        known: &Integer,
        orient: &Orientation,
        n: &Integer,
    ) -> Integer {
        if radix_k == &Integer::from(0) {
            return Integer::from(0);
        }

        let limit = match orient {
            Orientation::LsbKnown => {
                let distance = (n - known).complete();
                if distance <= 0 {
                    Integer::from(0)
                } else {
                    let numerator = distance + radix_k - Integer::from(1);
                    numerator / radix_k
                }
            }
            Orientation::MsbKnown => {
                let base = (known * radix_k).complete();
                let distance = n - base;
                if distance <= 0 {
                    Integer::from(0)
                } else {
                    distance
                }
            }
        };

        if &limit > search_space {
            search_space.clone()
        } else {
            limit
        }
    }

    /// Recover prime from partial information.
    /// Generic algorithm: p = known + radix^k * x or known * radix^k + x.
    fn recover(
        known: &Integer,
        radix: u32,
        k: usize,
        orient: &Orientation,
        n: &Integer,
        e: &Integer,
        pb: Option<&ProgressBar>,
        control: &AttackControl,
    ) -> Result<Integer, Error> {
        control.check_cancelled()?;

        // For radix > 1, radix^k is at least 2^64 when k >= 64, which no
        // u64 budget can hold. Avoid constructing an unnecessarily huge Integer.
        if radix > 1 && k >= 64 {
            return Err(Error::BudgetExceeded);
        }
        if radix == 0 && k > 0 {
            return Err(Error::NotFound);
        }
        let exponent = if radix <= 1 {
            0
        } else {
            u32::try_from(k).map_err(|_| Error::Unsupported)?
        };
        let search_space = Integer::from(radix).pow(exponent);
        if search_space == Integer::from(0) {
            return Err(Error::NotFound);
        }
        if &search_space > &Integer::from(control.remaining()) {
            if let Some(pb) = pb {
                pb.println("Candidate search budget exceeded.");
            }
            return Err(Error::BudgetExceeded);
        }

        let radix_k = search_space.clone();
        let limit_integer = Self::enumeration_limit(&search_space, &radix_k, known, orient, n);
        let limit = limit_integer.to_u64().ok_or(Error::Unsupported)?;
        if limit == 0 {
            return Err(Error::NotFound);
        }

        let unknown_bits = if radix > 1 {
            (k as f64 * (radix as f64).log2()).ceil() as u32
        } else {
            0
        };
        let n_bits = n.significant_bits();
        let known_bits_approx = (n_bits / 2).saturating_sub(unknown_bits);
        if let Some(pb) = pb {
            pb.println(format!(
                "Partial prime recovery: ~{} unknown bits, ~{} known bits (n has {} bits)",
                unknown_bits, known_bits_approx, n_bits
            ));
            if known_bits_approx < n_bits / 4 {
                pb.println(format!(
                    "Warning: Known bits ({}) < n/4 ({}). Success not guaranteed (trying heuristically).",
                    known_bits_approx, n_bits / 4
                ));
            }
            pb.set_length(limit);
        }

        let tick_size = (limit / 100).max(1);
        let mut next_tick = tick_size;
        let mut x = 0u64;
        while x < limit {
            control.check_cancelled()?;
            let batch_end = x.saturating_add((CANCEL_CHECK_BATCH as u64).min(limit - x));
            control.reserve_candidates(batch_end - x)?;

            while x < batch_end {
                let candidate = match orient {
                    Orientation::LsbKnown => Integer::from(known + &radix_k * x),
                    Orientation::MsbKnown => (known * &radix_k).complete() + x,
                };

                if candidate > 1 && &candidate < n {
                    let (other, rem) = n.div_rem_ref(&candidate).complete();
                    if rem == 0
                        && other > 1
                        && candidate.is_probably_prime(100) != IsPrime::No
                        && other.is_probably_prime(100) != IsPrime::No
                        && PrivateKey::from_p_q(&candidate, &other, e).is_ok()
                    {
                        if let Some(pb) = pb {
                            pb.println(format!("Found prime factor after {} iterations!", x + 1));
                            pb.set_position(x + 1);
                        }
                        return Ok(candidate);
                    }
                }

                x += 1;
                if x >= next_tick {
                    if let Some(pb) = pb {
                        pb.set_position(x);
                    }
                    next_tick = x.saturating_add(tick_size);
                }
            }
            control.check_cancelled()?;
        }

        if let Some(pb) = pb {
            pb.set_position(limit);
        }
        Err(Error::NotFound)
    }
}

impl Attack for PartialPrimeAttack {
    fn name(&self) -> &'static str {
        "partial_prime"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn required_parameters(&self) -> &'static [&'static str] {
        &["n", "e", "partial_p|partial_q|p|q"]
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        self.run_cancellable(params, pb, &AttackControl::new(params.search_budget))
    }

    fn run_cancellable(
        &self,
        params: &Parameters,
        pb: Option<&ProgressBar>,
        control: &AttackControl,
    ) -> Result<Solution, Error> {
        control.check_cancelled()?;
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        if params.partial_p.is_none() && params.partial_q.is_none() {
            return Err(Error::MissingParameters);
        }

        let recover_prime = |partial: &PartialPrime| -> Result<Integer, Error> {
            match partial {
                PartialPrime::Full(value) => Ok(value.clone()),
                PartialPrime::Partial {
                    radix,
                    k,
                    orient,
                    known,
                } => {
                    if *orient == Orientation::MsbKnown {
                        match CoppersmithFactorAttack::recover_partial(n, e, partial, control) {
                            Ok((candidate, _)) => return Ok(candidate),
                            Err(Error::Cancelled) => return Err(Error::Cancelled),
                            Err(Error::Unsupported | Error::NotFound) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    if let Some(k_val) = k {
                        Self::recover(known, *radix, *k_val, orient, n, e, pb, control)
                    } else {
                        let n_bits = n.significant_bits();
                        let p_bits = n_bits / 2;
                        let known_bits = known.significant_bits();
                        let unknown_bits = p_bits.saturating_sub(known_bits);
                        let k_base = if *radix > 1 {
                            (unknown_bits as f64 / (*radix as f64).log2()).ceil() as usize
                        } else {
                            1
                        };
                        let k_base = i32::try_from(k_base).unwrap_or(i32::MAX);
                        let mut attempted = Vec::new();
                        let mut error = Error::NotFound;

                        for k_offset in [0, -1, 1, -2] {
                            let k_try = k_base.saturating_add(k_offset).max(1) as usize;
                            if attempted.contains(&k_try) {
                                continue;
                            }
                            attempted.push(k_try);

                            match Self::recover(known, *radix, k_try, orient, n, e, pb, control) {
                                Ok(result) => return Ok(result),
                                Err(Error::Cancelled) => return Err(Error::Cancelled),
                                Err(next) => error = Self::prefer_error(error, next),
                            }
                        }
                        Err(error)
                    }
                }
            }
        };

        let solution_from_prime = |candidate: Integer| -> Result<Solution, Error> {
            if candidate <= 1 || candidate >= *n {
                return Err(Error::NotFound);
            }
            let (other, rem) = n.div_rem_ref(&candidate).complete();
            if rem != 0 || other <= 1 {
                return Err(Error::NotFound);
            }
            if candidate.is_probably_prime(100) == IsPrime::No
                || other.is_probably_prime(100) == IsPrime::No
            {
                return Err(Error::NotFound);
            }
            Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(&candidate, &other, e)?,
            ))
        };

        let mut errors = Vec::new();
        for partial in params.partial_p.iter().chain(params.partial_q.iter()) {
            control.check_cancelled()?;
            match recover_prime(partial) {
                Ok(candidate) => {
                    control.check_cancelled()?;
                    match solution_from_prime(candidate) {
                        Ok(solution) => return Ok(solution),
                        Err(Error::Cancelled) => return Err(Error::Cancelled),
                        Err(error) => errors.push(error),
                    }
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => errors.push(error),
            }
        }

        Err(errors
            .into_iter()
            .reduce(Self::prefer_error)
            .unwrap_or(Error::NotFound))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::attack::advanced::CoppersmithFactorAttack;
    use crate::{Attack, AttackControl, Parameters, PartialPrime};

    use super::*;

    #[test]
    fn zero_budget_rejects_enumeration_without_panicking() {
        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let params = Parameters {
            n: Some((&p * &q).into()),
            search_budget: 0,
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(20),
                orient: Orientation::LsbKnown,
                known: p.clone() & ((Integer::from(1) << 11) - 1),
            }),
            ..Default::default()
        };
        let error = PartialPrimeAttack
            .run_cancellable(&params, None, &AttackControl::new(0))
            .unwrap_err();
        assert_eq!(error, Error::BudgetExceeded);
    }

    #[test]
    fn failed_partial_p_does_not_block_partial_q() {
        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let params = Parameters {
            n: Some((&p * &q).into()),
            search_budget: 1 << 20,
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(20),
                orient: Orientation::LsbKnown,
                known: Integer::from(2),
            }),
            partial_q: Some(PartialPrime::Full(q.clone())),
            ..Default::default()
        };
        let solution = PartialPrimeAttack
            .run_cancellable(&params, None, &AttackControl::new(1 << 20))
            .unwrap();
        assert_eq!(solution.pk.unwrap().q(), q);
    }

    #[test]
    fn invalid_full_partial_p_does_not_block_partial_q() {
        let params = Parameters {
            n: Some(Integer::from(15)),
            partial_p: Some(PartialPrime::Full(Integer::from(4))),
            partial_q: Some(PartialPrime::Full(Integer::from(5))),
            ..Default::default()
        };
        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        assert_eq!(solution.pk.unwrap().n, Integer::from(15));
    }

    #[test]
    fn zero_candidate_is_not_divided_into_n() {
        let params = Parameters {
            n: Some(Integer::from(15)),
            search_budget: 1,
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(1),
                orient: Orientation::LsbKnown,
                known: Integer::from(0),
            }),
            ..Default::default()
        };
        assert!(PartialPrimeAttack.run(&params, None).is_err());
    }

    #[test]
    fn insufficient_budget_is_reported() {
        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let params = Parameters {
            n: Some((&p * &q).into()),
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(20),
                orient: Orientation::LsbKnown,
                known: p & ((Integer::from(1) << 11) - 1),
            }),
            ..Default::default()
        };
        assert_eq!(
            PartialPrimeAttack
                .run_cancellable(&params, None, &AttackControl::new((1 << 20) - 1))
                .unwrap_err(),
            Error::BudgetExceeded
        );
    }

    #[test]
    fn zero_radix_has_no_search_space() {
        let params = Parameters {
            n: Some(Integer::from(15)),
            partial_p: Some(PartialPrime::Partial {
                radix: 0,
                k: Some(1),
                orient: Orientation::LsbKnown,
                known: Integer::from(5),
            }),
            ..Default::default()
        };
        assert_eq!(
            PartialPrimeAttack.run(&params, None).unwrap_err(),
            Error::NotFound
        );
    }

    #[test]
    fn composite_divisor_is_rejected() {
        let params = Parameters {
            n: Some(Integer::from(105)),
            partial_p: Some(PartialPrime::Partial {
                radix: 10,
                k: Some(1),
                orient: Orientation::MsbKnown,
                known: Integer::from(1),
            }),
            ..Default::default()
        };
        assert_eq!(
            PartialPrimeAttack.run(&params, None).unwrap_err(),
            Error::NotFound
        );
    }

    #[test]
    fn pre_cancelled_control_wins() {
        let params = Parameters {
            n: Some(Integer::from(3233)),
            partial_q: Some(PartialPrime::Full(Integer::from(53))),
            ..Default::default()
        };
        let control = AttackControl::default();
        control.cancel();
        assert_eq!(
            PartialPrimeAttack
                .run_cancellable(&params, None, &control)
                .unwrap_err(),
            Error::Cancelled
        );
    }

    #[test]
    fn lsb_known() {
        // Use actual primes for testing
        // p = 1073741827 (next prime after 2^30)
        // q = 2147483659 (next prime after 2^31)
        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Extract LSB (lower 20 bits known, upper bits unknown)
        let unknown_count = 20;
        let mask = (Integer::from(1) << (p.significant_bits() - unknown_count as u32)) - 1;
        let known_lsb = p.clone() & mask;

        let params = Parameters {
            n: Some(n),
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(unknown_count),
                orient: Orientation::LsbKnown,
                known: known_lsb,
            }),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn msb_known() {
        // Use actual primes for testing
        // p = 1073741827 (next prime after 2^30)
        // q = 2147483659 (next prime after 2^31)
        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Extract MSB (upper bits known, lower 20 bits unknown)
        let unknown_count = 20;
        let known_msb = p.clone() >> unknown_count;

        let params = Parameters {
            n: Some(n),
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(unknown_count),
                orient: Orientation::MsbKnown,
                known: known_msb,
            }),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn decimal_msb_known() {
        // Test with decimal wildcards parsing
        // Test the actual parsing path to ensure it works end-to-end
        use crate::PartialPrimeArg;
        use std::str::FromStr;

        let p = Integer::from(1073741827u64);
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Parse "10737418??" which represents p with 2 unknown digits
        let arg = PartialPrimeArg::from_str("10737418??").unwrap();

        let params = Parameters {
            n: Some(n),
            partial_p: Some(arg.0),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn ellipsis_lsb_known() {
        // Test ellipsis with LSB known
        use crate::PartialPrimeArg;
        use std::str::FromStr;

        let p = Integer::from(1073741827u64); // 0x40000003
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Use ellipsis to indicate unknown MSB
        // p = 0x40000003, so LSB (lower 24 bits) is 0x000003
        // We'll use a smaller known part: just the lowest byte 0x03
        let arg = PartialPrimeArg::from_str("0x...03").unwrap();

        let params = Parameters {
            n: Some(n),
            partial_p: Some(arg.0),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn ellipsis_msb_known() {
        // Test ellipsis with MSB known
        use crate::PartialPrimeArg;
        use std::str::FromStr;

        let p = Integer::from(1073741827u64); // 0x40000003
        let q = Integer::from(2147483659u64);
        let n = Integer::from(&p * &q);

        // Use ellipsis to indicate unknown LSB
        // p = 0x40000003, so MSB (upper bits) after shifting right by 24 is 0x40
        // We'll use upper 2 bytes: 0x4000
        let arg = PartialPrimeArg::from_str("0x4000...").unwrap();

        let params = Parameters {
            n: Some(n),
            partial_p: Some(arg.0),
            ..Default::default()
        };

        let solution = PartialPrimeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn coppersmith_factor_recovers_large_unknown_lsb_with_zero_bruteforce_budget() {
        let p = Integer::from_str(
            "112219243609243706223486619551298085362360091408633161457003404046681540344297",
        )
        .unwrap();
        let q = Integer::from_str(
            "64052533192509995760322742160163582601357132095571262796409705234000154367147",
        )
        .unwrap();
        let unknown = 40usize;
        let params = Parameters {
            n: Some((&p * &q).into()),
            search_budget: 0,
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(unknown),
                orient: Orientation::MsbKnown,
                known: p.clone() >> unknown,
            }),
            ..Default::default()
        };
        let control = AttackControl::new(0);
        let solution = PartialPrimeAttack
            .run_cancellable(&params, None, &control)
            .unwrap();
        let pk = solution.pk.unwrap();
        // PrivateKey stores factors in ascending order; this fixture has p > q.
        assert_eq!(pk.factors.to_vec(), vec![q, p]);
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn coppersmith_factor_recovers_inferred_msb_width_with_zero_budget() {
        let p = Integer::from_str(
            "112219243609243706223486619551298085362360091408633161457003404046681540344297",
        )
        .unwrap();
        let q = Integer::from_str(
            "64052533192509995760322742160163582601357132095571262796409705234000154367147",
        )
        .unwrap();
        let params = Parameters {
            n: Some((&p * &q).into()),
            search_budget: 0,
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: None,
                orient: Orientation::MsbKnown,
                known: p.clone() >> 40,
            }),
            ..Default::default()
        };
        let control = AttackControl::new(0);

        let solution = PartialPrimeAttack
            .run_cancellable(&params, None, &control)
            .unwrap();

        assert_eq!(solution.pk.unwrap().factors.to_vec(), vec![q, p]);
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn coppersmith_factor_rejects_bound_outside_conservative_condition() {
        let p = Integer::from(61);
        let q = Integer::from(53);
        let params = Parameters {
            n: Some((&p * &q).into()),
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(4),
                orient: Orientation::MsbKnown,
                known: Integer::from(3),
            }),
            ..Default::default()
        };
        assert_eq!(
            CoppersmithFactorAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn coppersmith_factor_rejects_wrong_known_bits() {
        let params = Parameters {
            n: Some(Integer::from(3233)),
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(2),
                orient: Orientation::MsbKnown,
                known: Integer::from(99),
            }),
            ..Default::default()
        };
        assert_eq!(
            CoppersmithFactorAttack.run(&params, None).unwrap_err(),
            Error::NotFound
        );
    }
}
