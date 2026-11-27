use indicatif::ProgressBar;
use rug::{ops::RemRounding, Integer};

use crate::{
    attack::{AttackControl, Error, MAX_POLYNOMIAL_DEGREE},
    math::polynomial::Polynomial,
    Attack, AttackKind, AttackSpeed, Parameters, Solution,
};

/// Recover a message from two RSA ciphertexts with affine-related plaintexts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FranklinReiterAttack;

impl Attack for FranklinReiterAttack {
    fn name(&self) -> &'static str {
        "franklin_reiter"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn required_parameters(&self) -> &'static [&'static str] {
        &[
            "n",
            "e",
            "c",
            "related_c+related_a1+related_b1+related_a2+related_b2",
        ]
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
        let related_c = params.related_c.as_ref().ok_or(Error::MissingParameters)?;
        let a1 = params.related_a1.as_ref().ok_or(Error::MissingParameters)?;
        let b1 = params.related_b1.as_ref().ok_or(Error::MissingParameters)?;
        let a2 = params.related_a2.as_ref().ok_or(Error::MissingParameters)?;
        let b2 = params.related_b2.as_ref().ok_or(Error::MissingParameters)?;
        let exponent = params.e.to_u32().ok_or(Error::Unsupported)?;
        if *n <= 1 || exponent < 2 || exponent > MAX_POLYNOMIAL_DEGREE as u32 {
            return Err(Error::Unsupported);
        }

        // Floor-modulo normalization makes polynomial construction and final
        // verification agree for non-canonical positive and negative inputs.
        let c = Integer::from(c.rem_floor(n));
        let related_c = Integer::from(related_c.rem_floor(n));

        // The two affine maps must be independent over Z/nZ.
        let determinant = Integer::from(a1 * b2) - Integer::from(a2 * b1);
        determinant.invert_ref(n).ok_or(Error::Unsupported)?;

        let f1 = Polynomial::from_affine_power(a1, b1, exponent, &c, n.clone());
        let f2 = Polynomial::from_affine_power(a2, b2, exponent, &related_c, n.clone());
        let gcd = f1.gcd(&f2)?;
        control.check_cancelled()?;
        if gcd.degree().is_none_or(|degree| degree == 0) {
            return Err(Error::NotFound);
        }
        let gcd = gcd.monic()?;
        if gcd.degree() != Some(1) {
            return Err(Error::Unsupported);
        }

        // A linear monic GCD over a composite modulus is x + constant.
        let x = Integer::from(-&gcd.coeffs[0]) % n;
        let x = if x < 0 { Integer::from(x + n) } else { x };
        let m1 = Integer::from(a1 * &x + b1) % n;
        let m1 = if m1 < 0 { Integer::from(m1 + n) } else { m1 };
        let m2 = Integer::from(a2 * &x + b2) % n;
        let m2 = if m2 < 0 { Integer::from(m2 + n) } else { m2 };
        if m1
            .clone()
            .pow_mod(&params.e, n)
            .is_ok_and(|value| value == c)
            && m2
                .clone()
                .pow_mod(&params.e, n)
                .is_ok_and(|value| value == related_c)
        {
            Ok(Solution::new_m(self.name(), x))
        } else {
            Err(Error::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_params() -> Parameters {
        Parameters {
            n: Some(3233.into()),
            e: 3.into(),
            c: Some(1680.into()),
            related_c: Some(1411.into()),
            related_a1: Some(2.into()),
            related_b1: Some(3.into()),
            related_a2: Some(3.into()),
            related_b2: Some(5.into()),
            ..Default::default()
        }
    }

    #[test]
    fn franklin_reiter_recovers_related_message() {
        let solution = FranklinReiterAttack.run(&fixed_params(), None).unwrap();
        assert_eq!(solution.m, Some(7.into()));
    }

    #[test]
    fn franklin_reiter_normalizes_positive_non_canonical_ciphertexts() {
        let params = Parameters {
            c: Some(4913.into()),
            related_c: Some(4644.into()),
            ..fixed_params()
        };
        let solution = FranklinReiterAttack.run(&params, None).unwrap();
        assert_eq!(solution.m, Some(7.into()));
    }

    #[test]
    fn franklin_reiter_normalizes_negative_non_canonical_ciphertexts() {
        let params = Parameters {
            c: Some((-1553).into()),
            related_c: Some((-1822).into()),
            ..fixed_params()
        };
        let solution = FranklinReiterAttack.run(&params, None).unwrap();
        assert_eq!(solution.m, Some(7.into()));
    }

    #[test]
    fn franklin_reiter_rejects_wrong_related_ciphertext() {
        let params = Parameters {
            related_c: Some(0.into()),
            ..fixed_params()
        };
        assert_eq!(
            FranklinReiterAttack.run(&params, None),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn franklin_reiter_rejects_excessive_exponent() {
        let params = Parameters {
            e: 65537.into(),
            ..fixed_params()
        };
        assert_eq!(
            FranklinReiterAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn franklin_reiter_rejects_non_invertible_relation() {
        let params = Parameters {
            related_c: Some(1.into()),
            related_a1: Some(61.into()),
            related_b1: Some(0.into()),
            related_a2: Some(0.into()),
            related_b2: Some(1.into()),
            ..fixed_params()
        };
        assert_eq!(
            FranklinReiterAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn franklin_reiter_rejects_non_invertible_polynomial_coefficient() {
        let params = Parameters {
            related_a1: Some(61.into()),
            related_b1: Some(1.into()),
            related_a2: Some(1.into()),
            related_b2: Some(0.into()),
            ..fixed_params()
        };
        assert_eq!(
            FranklinReiterAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn franklin_reiter_rejects_non_linear_gcd() {
        // Over each prime factor, x^2 = (x+1)^2 has the root x = -1/2.
        // With three prime factors the composite-ring GCD is cubic.
        let params = Parameters {
            n: Some(105.into()),
            e: 2.into(),
            c: Some(1.into()),
            related_c: Some(1.into()),
            related_a1: Some(1.into()),
            related_b1: Some(0.into()),
            related_a2: Some(1.into()),
            related_b2: Some(1.into()),
            ..Default::default()
        };
        assert_eq!(
            FranklinReiterAttack.run(&params, None).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn franklin_reiter_requires_complete_related_fields() {
        assert_eq!(
            FranklinReiterAttack.run(&Parameters::default(), None),
            Err(Error::MissingParameters)
        );
        let params = Parameters {
            related_b2: None,
            ..fixed_params()
        };
        assert_eq!(
            FranklinReiterAttack.run(&params, None),
            Err(Error::MissingParameters)
        );
    }

    #[test]
    fn franklin_reiter_honors_pre_cancelled_control() {
        let control = AttackControl::default();
        control.cancel();
        assert_eq!(
            FranklinReiterAttack.run_cancellable(&fixed_params(), None, &control),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn franklin_reiter_uses_no_candidate_budget() {
        let control = AttackControl::new(0);
        let solution = FranklinReiterAttack
            .run_cancellable(&fixed_params(), None, &control)
            .unwrap();
        assert_eq!(solution.m, Some(Integer::from(7)));
        assert_eq!(control.remaining(), 0);
    }
}
