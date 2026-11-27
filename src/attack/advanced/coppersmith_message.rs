use indicatif::ProgressBar;
use rug::{ops::Pow, Complete, Integer, Rational};

use crate::{
    attack::{AttackControl, Error, MAX_LLL_DIMENSION, MAX_POLYNOMIAL_DEGREE},
    math::polynomial::Polynomial,
    Attack, AttackKind, AttackSpeed, Parameters, Solution,
};

use super::small_roots_monic;

const MAX_DIRECT_SMALL_ROOT_BOUND: u32 = 1 << 12;

/// Recover a plaintext from known most-significant bits with Coppersmith's method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoppersmithMessageAttack;

impl Attack for CoppersmithMessageAttack {
    fn name(&self) -> &'static str {
        "coppersmith_message"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn required_parameters(&self) -> &'static [&'static str] {
        &["n", "e", "c", "m_known+m_unknown_bits"]
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
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;
        let known = params.m_known.as_ref().ok_or(Error::MissingParameters)?;
        let unknown_bits = params.m_unknown_bits.ok_or(Error::MissingParameters)?;
        let exponent = params.e.to_u32().ok_or(Error::Unsupported)?;
        let degree = usize::try_from(exponent).map_err(|_| Error::Unsupported)?;

        if *n <= 1
            || *known < 0
            || exponent > MAX_POLYNOMIAL_DEGREE as u32
            || degree + degree / 2 > MAX_LLL_DIMENSION
        {
            return Err(Error::Unsupported);
        }
        let exponent = u32::try_from(unknown_bits).map_err(|_| Error::Unsupported)?;
        let bound = Integer::from(2).pow(exponent);
        if bound.clone().pow(degree as u32) >= *n {
            return Err(Error::Unsupported);
        }

        let base = (known * &bound).complete();
        if bound
            .to_u32()
            .is_some_and(|value| value <= MAX_DIRECT_SMALL_ROOT_BOUND)
        {
            let limit = bound.to_u32().ok_or(Error::Unsupported)?;
            for root in 0..limit {
                control.check_cancelled()?;
                let candidate = (&base + root).complete();
                if candidate
                    .clone()
                    .pow_mod(&params.e, n)
                    .is_ok_and(|value| value == *c)
                {
                    return Ok(Solution::new_m(self.name(), candidate));
                }
            }
            return Err(Error::NotFound);
        }

        // In the message ring, m_known * 2^u + x = m, so f(x) = m^e - c.
        let polynomial =
            Polynomial::from_affine_power(&Integer::from(1), &base, degree as u32, c, n.clone());
        let roots = small_roots_monic(&polynomial, n, &Rational::from(1), &bound, control)?;

        for root in roots {
            control.check_cancelled()?;
            if root < 0 || root >= bound {
                continue;
            }
            let candidate = &base + root;
            if candidate
                .clone()
                .pow_mod(&params.e, n)
                .is_ok_and(|value| value == *c)
            {
                return Ok(Solution::new_m(self.name(), candidate));
            }
        }
        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use rug::{ops::Pow, Integer};

    use super::*;
    use crate::{AttackControl, Error, Parameters};

    #[test]
    fn coppersmith_message_recovers_fixed_vector() {
        let p = Integer::from(1000003);
        let q = Integer::from(1000033);
        let n = (&p * &q).complete();
        let m = Integer::from(123456);
        let c = m.clone().pow_mod(&5.into(), &n).unwrap();
        let params = Parameters {
            n: Some(n),
            e: 5.into(),
            c: Some(c),
            m_known: Some(964.into()),
            m_unknown_bits: Some(7),
            ..Default::default()
        };
        assert_eq!(
            CoppersmithMessageAttack.run(&params, None).unwrap().m,
            Some(m)
        );
    }

    #[test]
    fn coppersmith_message_rejects_wrong_ciphertext() {
        let params = Parameters {
            n: Some(Integer::from(1000003) * Integer::from(1000033)),
            e: 5.into(),
            c: Some(0.into()),
            m_known: Some(964.into()),
            m_unknown_bits: Some(7),
            ..Default::default()
        };
        assert_eq!(
            CoppersmithMessageAttack.run(&params, None),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn coppersmith_message_small_bound_wrong_ciphertext_finishes_without_lll() {
        let params = Parameters {
            n: Some(Integer::from(1000003) * Integer::from(1000033)),
            e: 5.into(),
            c: Some(0.into()),
            m_known: Some(964.into()),
            m_unknown_bits: Some(7),
            ..Default::default()
        };
        let control = AttackControl::new(0);
        let attack_control = control.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let attack = std::thread::spawn(move || {
            let result = CoppersmithMessageAttack.run_cancellable(&params, None, &attack_control);
            sender.send(result).unwrap();
        });
        std::thread::sleep(std::time::Duration::from_secs(2));
        control.cancel();

        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("small-bound wrong-ciphertext search did not finish promptly");
        attack.join().unwrap();

        assert_eq!(result, Err(Error::NotFound));
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn coppersmith_message_rejects_root_valid_for_only_one_factor() {
        // 5^3 is 24 modulo 101 but 22 modulo 103, so this root is invalid modulo n.
        let params = Parameters {
            n: Some(10403.into()),
            e: 3.into(),
            c: Some(24.into()),
            m_known: Some(0.into()),
            m_unknown_bits: Some(3),
            ..Default::default()
        };

        assert_eq!(
            CoppersmithMessageAttack.run(&params, None),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn coppersmith_message_rejects_excessive_exponent() {
        let params = Parameters {
            n: Some(10403.into()),
            e: 258.into(),
            c: Some(1.into()),
            m_known: Some(0.into()),
            m_unknown_bits: Some(1),
            ..Default::default()
        };

        assert_eq!(
            CoppersmithMessageAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn coppersmith_message_rejects_excessive_minimum_lattice_dimension() {
        let params = Parameters {
            n: Some(Integer::from(2).pow(400)),
            e: 44.into(),
            c: Some(1.into()),
            m_known: Some(0.into()),
            m_unknown_bits: Some(7),
            ..Default::default()
        };

        assert_eq!(
            CoppersmithMessageAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn coppersmith_message_uses_no_candidate_budget() {
        let params = Parameters {
            n: Some(Integer::from(1000036000099u64)),
            e: 5.into(),
            c: Some(Integer::from(819449521559u64)),
            m_known: Some(964.into()),
            m_unknown_bits: Some(7),
            ..Default::default()
        };
        let control = AttackControl::new(0);

        let solution = CoppersmithMessageAttack
            .run_cancellable(&params, None, &control)
            .unwrap();

        assert_eq!(solution.m, Some(123456.into()));
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn coppersmith_message_checks_cancellation_before_parameters() {
        let control = AttackControl::new(7);
        control.cancel();

        assert_eq!(
            CoppersmithMessageAttack
                .run_cancellable(&Parameters::default(), None, &control)
                .unwrap_err(),
            Error::Cancelled
        );
        assert_eq!(control.remaining(), 7);
    }

    #[test]
    fn coppersmith_message_rejects_excessive_unknown_bits() {
        let params = Parameters {
            n: Some(3233.into()),
            e: 5.into(),
            c: Some(1.into()),
            m_known: Some(0.into()),
            m_unknown_bits: Some(12),
            ..Default::default()
        };
        assert_eq!(
            CoppersmithMessageAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }
}
