use indicatif::ProgressBar;
use rug::{integer::IsPrime, ops::Pow, Complete, Integer, Rational};

use crate::{
    key::PrivateKey, math::polynomial::Polynomial, Attack, AttackControl, AttackKind, AttackSpeed,
    Error, Orientation, Parameters, PartialPrime, Solution,
};

use super::small_roots_monic;

/// Recover a prime factor from known high digits with Coppersmith's method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoppersmithFactorAttack;

impl CoppersmithFactorAttack {
    pub(crate) fn recover_partial(
        n: &Integer,
        e: &Integer,
        partial: &PartialPrime,
        control: &AttackControl,
    ) -> Result<(Integer, PrivateKey), Error> {
        control.check_cancelled()?;
        let PartialPrime::Partial {
            radix,
            k,
            orient,
            known,
        } = partial
        else {
            return Err(Error::Unsupported);
        };
        if *orient != Orientation::MsbKnown || *radix < 2 || *known < 0 {
            return Err(Error::Unsupported);
        }

        let widths = match k {
            Some(width) => vec![*width],
            None => {
                let widths = inferred_widths(n, known, *radix);
                if widths.is_empty() {
                    return Err(Error::Unsupported);
                }
                widths
            }
        };
        let mut error = Error::NotFound;
        for width in widths {
            control.check_cancelled()?;
            let exponent = u32::try_from(width).map_err(|_| Error::Unsupported)?;
            let radix_power = Integer::from(*radix).pow(exponent);
            if radix_power <= 0 {
                return Err(Error::Unsupported);
            }
            let base = Integer::from(known * &radix_power);
            if k.is_none() {
                let largest_candidate = Integer::from(&base + &radix_power) - Integer::from(1);
                if largest_candidate.pow(2) <= *n {
                    error = Error::Unsupported;
                    continue;
                }
            }
            // In the unknown factor p's ring, p_known * R + x = p = 0.
            let polynomial = Polynomial::new(vec![base.clone(), Integer::from(1)], n.clone())?;
            let roots = match small_roots_monic(
                &polynomial,
                n,
                &(Rational::from(1) / Rational::from(2)),
                &radix_power,
                control,
            ) {
                Ok(roots) => roots,
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(Error::Unsupported) => {
                    error = Error::Unsupported;
                    continue;
                }
                Err(Error::NotFound) => continue,
                Err(next) => return Err(next),
            };

            for root in roots {
                control.check_cancelled()?;
                let candidate = Integer::from(&base + root);
                if candidate <= 1 || candidate >= *n {
                    continue;
                }
                let (other, remainder) = n.div_rem_ref(&candidate).complete();
                if remainder != 0
                    || other <= 1
                    || candidate.is_probably_prime(100) == IsPrime::No
                    || other.is_probably_prime(100) == IsPrime::No
                {
                    continue;
                }
                if let Ok(private_key) = PrivateKey::from_p_q(&candidate, &other, e) {
                    return Ok((candidate, private_key));
                }
            }
        }
        Err(error)
    }
}

impl Attack for CoppersmithFactorAttack {
    fn name(&self) -> &'static str {
        "coppersmith_factor"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn required_parameters(&self) -> &'static [&'static str] {
        &["n", "e", "partial_p|partial_q"]
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        self.run_cancellable(params, pb, &AttackControl::default())
    }

    fn run_cancellable(
        &self,
        params: &Parameters,
        _pb: Option<&ProgressBar>,
        control: &AttackControl,
    ) -> Result<Solution, Error> {
        control.check_cancelled()?;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        if params.partial_p.is_none() && params.partial_q.is_none() {
            return Err(Error::MissingParameters);
        }

        let mut supported = false;
        let mut error = Error::NotFound;
        for partial in params.partial_p.iter().chain(params.partial_q.iter()) {
            if !matches!(
                partial,
                PartialPrime::Partial {
                    orient: Orientation::MsbKnown,
                    ..
                }
            ) {
                continue;
            }
            supported = true;
            match Self::recover_partial(n, &params.e, partial, control) {
                Ok((_, private_key)) => {
                    return Ok(Solution::new_pk(self.name(), private_key));
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(Error::Unsupported) => error = Error::Unsupported,
                Err(Error::NotFound) => {}
                Err(next) => return Err(next),
            }
        }
        if supported {
            Err(error)
        } else {
            Err(Error::Unsupported)
        }
    }
}

fn inferred_widths(n: &Integer, known: &Integer, radix: u32) -> Vec<usize> {
    let unknown_bits = (n.significant_bits() / 2).saturating_sub(known.significant_bits());
    let mut base = 0i32;
    let mut radix_power = Integer::from(1);
    while radix_power.significant_bits() <= unknown_bits {
        radix_power *= Integer::from(radix);
        base += 1;
    }
    let mut widths = Vec::new();
    for offset in [0, -1, 1, -2] {
        let width = base.saturating_add(offset).max(1) as usize;
        if widths.contains(&width) {
            continue;
        }
        let Ok(exponent) = u32::try_from(width) else {
            continue;
        };
        let radix_power = Integer::from(radix).pow(exponent);
        if radix_power.pow(4) < *n {
            widths.push(width);
        }
    }
    widths
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{AttackControl, Orientation, Parameters, PartialPrime, PartialPrimeArg};

    fn fixture() -> (Integer, Integer) {
        let p = Integer::from_str(
            "112219243609243706223486619551298085362360091408633161457003404046681540344297",
        )
        .unwrap();
        let q = Integer::from_str(
            "64052533192509995760322742160163582601357132095571262796409705234000154367147",
        )
        .unwrap();
        (p, q)
    }

    #[test]
    fn coppersmith_factor_recovers_partial_q_without_consuming_budget() {
        let (p, q) = fixture();
        let params = Parameters {
            n: Some((&p * &q).into()),
            partial_q: Some(crate::PartialPrime::Partial {
                radix: 16,
                k: Some(10),
                orient: crate::Orientation::MsbKnown,
                known: q.clone() >> 40,
            }),
            ..Default::default()
        };
        let control = AttackControl::new(0);

        let solution = CoppersmithFactorAttack
            .run_cancellable(&params, None, &control)
            .unwrap();

        assert_eq!(solution.attack, "coppersmith_factor");
        assert!(solution.pk.unwrap().factors.to_vec().contains(&q));
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn coppersmith_factor_rejects_lsb_and_full_inputs_as_unsupported() {
        for partial in [
            crate::PartialPrime::Full(Integer::from(61)),
            crate::PartialPrime::Partial {
                radix: 2,
                k: Some(4),
                orient: crate::Orientation::LsbKnown,
                known: Integer::from(13),
            },
        ] {
            let params = Parameters {
                n: Some(Integer::from(3233)),
                partial_p: Some(partial),
                ..Default::default()
            };
            assert_eq!(
                CoppersmithFactorAttack.run(&params, None).unwrap_err(),
                Error::Unsupported
            );
        }
    }

    #[test]
    fn inferred_widths_discard_conservatively_unsupported_candidates() {
        let n = Integer::from(2).pow(58);
        let known = Integer::from(2).pow(12);

        assert_eq!(inferred_widths(&n, &known, 2), vec![14]);
    }

    #[test]
    fn coppersmith_factor_recovers_unbalanced_ellipsis_with_zero_budget() {
        // p is about twice q. The estimate starts at the actual width 14.
        let two = Integer::from(2);
        let offset = Integer::from(1000);
        let p: Integer = (two.clone().pow(101) - &offset).next_prime();
        let q: Integer = (two.clone().pow(100) + &offset).next_prime();
        let n = Integer::from(&p * &q);
        let known: Integer = p.clone() >> 14;
        assert_eq!(n.significant_bits() / 2 - known.significant_bits(), 14);
        assert!(Integer::from(2).pow(56) < n);

        let explicit = Parameters {
            n: Some(n.clone()),
            search_budget: 0,
            partial_p: Some(PartialPrime::Partial {
                radix: 2,
                k: Some(14),
                orient: Orientation::MsbKnown,
                known: known.clone(),
            }),
            ..Default::default()
        };
        let explicit_control = AttackControl::new(0);
        let explicit_solution = CoppersmithFactorAttack
            .run_cancellable(&explicit, None, &explicit_control)
            .unwrap();
        let mut expected = vec![p.clone(), q.clone()];
        expected.sort_unstable();
        assert_eq!(explicit_solution.pk.unwrap().factors.to_vec(), expected);
        assert_eq!(explicit_control.remaining(), 0);

        let ellipsis = format!("0b{}...", known.to_string_radix(2));
        let inferred = Parameters {
            n: Some(n),
            search_budget: 0,
            partial_p: Some(PartialPrimeArg::from_str(&ellipsis).unwrap().0),
            ..Default::default()
        };
        let inferred_control = AttackControl::new(0);
        let inferred_solution = crate::PartialPrimeAttack
            .run_cancellable(&inferred, None, &inferred_control)
            .unwrap();
        assert_eq!(inferred_solution.pk.unwrap().factors.to_vec(), expected);
        assert_eq!(inferred_control.remaining(), 0);
    }

    #[test]
    fn coppersmith_factor_checks_cancellation_before_parameters() {
        let control = AttackControl::new(0);
        control.cancel();

        assert_eq!(
            CoppersmithFactorAttack
                .run_cancellable(&Parameters::default(), None, &control)
                .unwrap_err(),
            Error::Cancelled
        );
    }
}
