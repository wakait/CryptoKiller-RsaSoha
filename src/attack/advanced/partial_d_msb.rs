use indicatif::ProgressBar;
use rug::{integer::IsPrime, ops::Pow, Complete, Integer};

use crate::{
    attack::advanced::CoppersmithFactorAttack,
    key::PrivateKey,
    math::number_theory::{integer_sqrt, is_perfect_square},
    Attack, AttackControl, AttackKind, AttackSpeed, Error, Orientation, Parameters, PartialPrime,
    Solution, CANCEL_CHECK_BATCH,
};

const MAX_SMALL_INTERVAL_CANDIDATES: u64 = CANCEL_CHECK_BATCH as u64;

struct SmallIntervalContext<'a> {
    n: &'a Integer,
    e: &'a Integer,
    s_hi: &'a Integer,
    s_step: &'a Integer,
    count: u64,
    d_lower: &'a Integer,
    d_upper: &'a Integer,
    control: &'a AttackControl,
}

/// Recover an RSA private key from known most-significant bits of `d`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialDMsbAttack;

fn prefer_error(current: Error, next: Error) -> Error {
    match (current, next) {
        (Error::Cancelled, _) | (_, Error::Cancelled) => Error::Cancelled,
        (Error::BudgetExceeded, _) | (_, Error::BudgetExceeded) => Error::BudgetExceeded,
        (Error::Unsupported, _) | (_, Error::Unsupported) => Error::Unsupported,
        (Error::NotFound, next) => next,
        (current, _) => current,
    }
}

fn ceil_sqrt(value: &Integer) -> Integer {
    match is_perfect_square(value) {
        Some(root) => root,
        None => integer_sqrt(value) + Integer::from(1),
    }
}

fn solve_x_residue(e: &Integer, k: &Integer, rhs: &Integer) -> Option<Integer> {
    let gcd = e.gcd_ref(k).complete();
    if (rhs % &gcd).complete() != 0 {
        return None;
    }
    let step = (k / &gcd).complete();
    if step == 1 {
        return Some(Integer::ZERO);
    }
    let reduced_e = (e / &gcd).complete();
    let reduced_rhs = (rhs / &gcd).complete();
    let inverse: Integer = reduced_e.invert_ref(&step)?.complete();
    let residue = &reduced_rhs * inverse % &step;
    Some(if residue < 0 { residue + step } else { residue })
}

fn validate_private_key(
    n: &Integer,
    e: &Integer,
    private_key: &PrivateKey,
    d_lower: &Integer,
    d_upper: &Integer,
) -> Option<PrivateKey> {
    if private_key.n != *n
        || private_key.e != *e
        || private_key.d < *d_lower
        || private_key.d >= *d_upper
    {
        return None;
    }
    let phi = private_key.phi();
    let ed = (&private_key.e * &private_key.d).complete();
    if phi <= 0 || (&ed % &phi).complete() != 1 {
        return None;
    }
    let k = (&ed - Integer::ONE).complete() / &phi;
    if k < 1 || k >= private_key.e {
        return None;
    }
    Some(private_key.clone())
}

fn candidate_to_key(
    n: &Integer,
    e: &Integer,
    p: &Integer,
    q: &Integer,
    d_lower: &Integer,
    d_upper: &Integer,
) -> Option<PrivateKey> {
    if *p <= 1
        || *q <= 1
        || (p * q).complete() != *n
        || p.is_probably_prime(100) == IsPrime::No
        || q.is_probably_prime(100) == IsPrime::No
    {
        return None;
    }
    let private_key = PrivateKey::from_p_q(p, q, e).ok()?;
    validate_private_key(n, e, &private_key, d_lower, d_upper)
}

fn larger_factor_bounds(n: &Integer, s_lo: &Integer, s_hi: &Integer) -> Option<(Integer, Integer)> {
    let four_n = n.clone() << 2;
    let disc_lo = s_lo.clone().pow(2) - &four_n;
    let disc_hi = s_hi.clone().pow(2) - &four_n;
    if disc_lo < 0 || disc_hi < 0 {
        return None;
    }

    let root_lo = integer_sqrt(&disc_lo);
    let numerator_lo = (s_lo + &root_lo).complete();
    let mut p_lo = &numerator_lo / Integer::from(2);
    if is_perfect_square(&disc_lo).is_none() || !numerator_lo.is_even() {
        p_lo += Integer::from(1);
    }
    let p_hi = (s_hi + integer_sqrt(&disc_hi)) / Integer::from(2);
    (p_lo <= p_hi).then_some((p_lo, p_hi))
}

fn common_msb_partial(
    n: &Integer,
    s_lo: &Integer,
    s_hi: &Integer,
) -> Result<(PartialPrime, Integer, Integer), Error> {
    let (p_lo, p_hi) = larger_factor_bounds(n, s_lo, s_hi).ok_or(Error::Unsupported)?;
    if p_lo <= integer_sqrt(n) {
        return Err(Error::Unsupported);
    }
    if p_lo == p_hi {
        return Ok((PartialPrime::Full(p_lo.clone()), p_lo.clone(), p_hi));
    }

    let difference = (&p_lo ^ &p_hi).complete();
    let unknown_bits =
        usize::try_from(difference.significant_bits()).map_err(|_| Error::Unsupported)?;
    let exponent = u32::try_from(unknown_bits).map_err(|_| Error::Unsupported)?;
    let radix_power = Integer::from(2).pow(exponent);
    if radix_power.clone().pow(4) >= *n {
        return Err(Error::Unsupported);
    }
    let partial = PartialPrime::Partial {
        radix: 2,
        k: Some(unknown_bits),
        orient: Orientation::MsbKnown,
        known: (&p_lo >> unknown_bits).complete(),
    };
    Ok((partial, p_lo, p_hi))
}

fn enumerate_small_interval(
    context: &SmallIntervalContext<'_>,
) -> Result<Option<PrivateKey>, Error> {
    context.control.reserve_candidates(context.count)?;
    for index in 0..context.count {
        if index.is_multiple_of(CANCEL_CHECK_BATCH as u64) {
            context.control.check_cancelled()?;
        }
        let s = (context.s_hi - &Integer::from(index) * context.s_step).complete();
        let four_n = context.n.clone() << 2;
        let discriminant = s.clone().pow(2) - four_n;
        let Some(root) = is_perfect_square(&discriminant) else {
            continue;
        };
        if !(&s + &root).complete().is_even() {
            continue;
        }
        let p = (&s - &root).complete() / Integer::from(2);
        let q = (&s + &root).complete() / Integer::from(2);
        if let Some(private_key) = candidate_to_key(
            context.n,
            context.e,
            &p,
            &q,
            context.d_lower,
            context.d_upper,
        ) {
            return Ok(Some(private_key));
        }
    }
    Ok(None)
}

fn recover_large_interval(
    n: &Integer,
    e: &Integer,
    s_lo: &Integer,
    s_hi: &Integer,
    d_lower: &Integer,
    d_upper: &Integer,
    control: &AttackControl,
) -> Result<Option<PrivateKey>, Error> {
    control.check_cancelled()?;
    let (partial, p_lo, p_hi) = common_msb_partial(n, s_lo, s_hi)?;
    if let PartialPrime::Full(candidate) = partial {
        let (other, remainder) = n.div_rem_ref(&candidate).complete();
        if remainder != 0 {
            return Ok(None);
        }
        return Ok(candidate_to_key(n, e, &candidate, &other, d_lower, d_upper));
    }

    let (_, private_key) = CoppersmithFactorAttack::recover_partial(n, e, &partial, control)?;
    if private_key.q() < p_lo || private_key.q() > p_hi {
        return Ok(None);
    }
    Ok(validate_private_key(n, e, &private_key, d_lower, d_upper))
}

impl Attack for PartialDMsbAttack {
    fn name(&self) -> &'static str {
        "partial_d_msb"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn required_parameters(&self) -> &'static [&'static str] {
        &["n", "e", "d_known_msb+d_unknown_bits"]
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        self.run_cancellable(params, pb, &AttackControl::new(params.search_budget))
    }

    fn run_cancellable(
        &self,
        params: &Parameters,
        _pb: Option<&ProgressBar>,
        control: &AttackControl,
    ) -> Result<Solution, Error> {
        control.check_cancelled()?;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let known = params
            .d_known_msb
            .as_ref()
            .ok_or(Error::MissingParameters)?;
        let unknown_bits = params.d_unknown_bits.ok_or(Error::MissingParameters)?;
        let e = &params.e;
        let e_u32 = e.to_u32().ok_or(Error::Unsupported)?;
        let exponent = u32::try_from(unknown_bits).map_err(|_| Error::Unsupported)?;
        if *n <= 1 || *known < 0 || e_u32 < 2 || unknown_bits > n.significant_bits() as usize {
            return Err(Error::Unsupported);
        }

        let unknown_space = Integer::from(2).pow(exponent);
        let base = (known * &unknown_space).complete();
        let d_upper = (known.clone() + 1) * &unknown_space;
        let s_min = ceil_sqrt(&(n.clone() << 2));
        let mut error = Error::NotFound;
        let small_interval_limit = Integer::from(MAX_SMALL_INTERVAL_CANDIDATES);

        for k_value in 1..e_u32 {
            if k_value.is_multiple_of(CANCEL_CHECK_BATCH as u32) {
                control.check_cancelled()?;
            }
            let k = Integer::from(k_value);
            let rhs = Integer::ONE.clone() - e * &base;
            let Some(x_first) = solve_x_residue(e, &k, &rhs) else {
                continue;
            };
            if x_first >= unknown_space {
                continue;
            }
            let gcd = e.gcd_ref(&k).complete();
            let x_step = (&k / &gcd).complete();
            let s_step = (e / &gcd).complete();
            let d_first = (&base + &x_first).complete();
            let ed_minus_one = e * &d_first - Integer::from(1);
            let phi = (&ed_minus_one / &k).complete();
            let s_first: Integer = n.clone() + 1 - &phi;
            if s_first < s_min {
                continue;
            }
            let s_span = s_first.clone() - s_min.clone();
            let s_count = s_span / &s_step + Integer::ONE;
            let x_count = (&unknown_space - Integer::from(1) - &x_first) / &x_step + Integer::ONE;
            let count = if s_count < x_count { s_count } else { x_count };
            let last_offset = &count - Integer::from(1);
            let x_offset = (&last_offset * &x_step).complete();
            let s_offset = (&last_offset * &s_step).complete();
            let x_last = &x_first + x_offset;
            let s_lo = &s_first - s_offset;
            debug_assert!(x_last < unknown_space);
            debug_assert!(s_lo >= s_min);

            let result = if count <= small_interval_limit {
                let count = count.to_u64().ok_or(Error::Unsupported)?;
                enumerate_small_interval(&SmallIntervalContext {
                    n,
                    e,
                    s_hi: &s_first,
                    s_step: &s_step,
                    count,
                    d_lower: &base,
                    d_upper: &d_upper,
                    control,
                })
            } else {
                recover_large_interval(n, e, &s_lo, &s_first, &base, &d_upper, control)
            };
            match result {
                Ok(Some(private_key)) => return Ok(Solution::new_pk(self.name(), private_key)),
                Ok(None) => {}
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(next) => error = prefer_error(error, next),
            }
        }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::{ops::Pow, Integer};

    use super::*;
    use crate::{Attack, AttackControl, Error, Parameters, PrivateKey};

    fn fixed_params() -> Parameters {
        Parameters {
            n: Some(3233.into()),
            e: 17.into(),
            d_known_msb: Some(172.into()),
            d_unknown_bits: Some(4),
            ..Default::default()
        }
    }

    #[test]
    fn partial_d_msb_recovers_fixed_key() {
        let solution = PartialDMsbAttack.run(&fixed_params(), None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(solution.attack, "partial_d_msb");
        assert_eq!(pk.p(), 53);
        assert_eq!(pk.q(), 61);
        assert_eq!(pk.d, 2753);
        let ed = (&pk.e * &pk.d).complete();
        assert_eq!((&ed % &pk.phi()).complete(), Integer::from(1));
    }

    #[test]
    fn partial_d_msb_rejects_candidate_outside_interval() {
        let params = Parameters {
            d_known_msb: Some(170.into()),
            ..fixed_params()
        };

        assert_eq!(PartialDMsbAttack.run(&params, None), Err(Error::NotFound));
    }

    #[test]
    fn partial_d_msb_honors_pre_cancelled_control() {
        let control = AttackControl::default();
        control.cancel();

        assert_eq!(
            PartialDMsbAttack.run_cancellable(&fixed_params(), None, &control),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn partial_d_msb_accepts_zero_unknown_bits() {
        let params = Parameters {
            d_known_msb: Some(2753.into()),
            d_unknown_bits: Some(0),
            ..fixed_params()
        };

        let pk = PartialDMsbAttack.run(&params, None).unwrap().pk.unwrap();
        assert_eq!(pk.d, 2753);
    }

    #[test]
    fn partial_d_msb_zero_budget_disables_small_enumeration() {
        let control = AttackControl::new(0);

        assert_eq!(
            PartialDMsbAttack.run_cancellable(&fixed_params(), None, &control),
            Err(Error::BudgetExceeded)
        );
    }

    #[test]
    fn partial_d_msb_shared_budget_is_consumed_by_enumeration() {
        let control = AttackControl::new(1);
        let pk = PartialDMsbAttack
            .run_cancellable(&fixed_params(), None, &control)
            .unwrap()
            .pk
            .unwrap();
        assert_eq!(pk.d, 2753);
        assert_eq!(control.remaining(), 0);

        let control = AttackControl::new(1);
        control.reserve_candidates(1).unwrap();
        assert_eq!(
            PartialDMsbAttack.run_cancellable(&fixed_params(), None, &control),
            Err(Error::BudgetExceeded)
        );
    }

    #[test]
    fn partial_d_msb_rejects_missing_and_unsupported_inputs() {
        assert_eq!(
            PartialDMsbAttack.run(
                &Parameters {
                    n: Some(3233.into()),
                    e: 17.into(),
                    ..Default::default()
                },
                None,
            ),
            Err(Error::MissingParameters)
        );

        for params in [
            Parameters {
                n: Some(1.into()),
                ..fixed_params()
            },
            Parameters {
                e: 1.into(),
                ..fixed_params()
            },
            Parameters {
                d_known_msb: Some((-1).into()),
                ..fixed_params()
            },
        ] {
            assert_eq!(
                PartialDMsbAttack.run(&params, None),
                Err(Error::Unsupported)
            );
        }
    }

    #[test]
    fn partial_d_msb_uses_coppersmith_for_large_interval_without_budget() {
        let p = Integer::from_str(
            "112219243609243706223486619551298085362360091408633161457003404046681540344297",
        )
        .unwrap();
        let q = Integer::from_str(
            "64052533192509995760322742160163582601357132095571262796409705234000154367147",
        )
        .unwrap();
        let e = Integer::from(5);
        let expected = PrivateKey::from_p_q(&p, &q, &e).unwrap();
        let params = Parameters {
            n: Some((&p * &q).complete()),
            e,
            d_known_msb: Some(expected.d.clone() >> 40),
            d_unknown_bits: Some(40),
            ..Default::default()
        };
        let control = AttackControl::new(0);

        let pk = PartialDMsbAttack
            .run_cancellable(&params, None, &control)
            .unwrap()
            .pk
            .unwrap();

        assert_eq!(pk, expected);
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn partial_d_msb_returns_unsupported_when_large_prefix_bound_fails() {
        let two = Integer::from(2);
        let offset = Integer::from(1000);
        let p: Integer = (two.clone().pow(127) - &offset).next_prime();
        let q: Integer = (two.clone().pow(127) + &offset).next_prime();
        let e = Integer::from(17);
        let expected = PrivateKey::from_p_q(&p, &q, &e).unwrap();
        let params = Parameters {
            n: Some((&p * &q).complete()),
            e,
            d_known_msb: Some(expected.d.clone() >> 70),
            d_unknown_bits: Some(70),
            ..Default::default()
        };

        assert_eq!(
            PartialDMsbAttack.run_cancellable(&params, None, &AttackControl::new(0)),
            Err(Error::Unsupported)
        );
    }
}
