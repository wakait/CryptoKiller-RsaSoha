use rug::{ops::Pow, Complete, Integer, Rational};

use crate::{
    attack::{AttackControl, Error, MAX_LLL_DIMENSION, MAX_POLYNOMIAL_DEGREE},
    math::{
        lattice::lll,
        polynomial::{integer_roots, Polynomial},
    },
};

/// Find small non-negative roots of a monic polynomial modulo a nontrivial
/// divisor of `modulus`, using an exact Howgrave–Graham lattice. The conservative bound is
/// `X^(d * denom(beta)^2) < modulus^numer(beta)^2`.
///
/// Lattice dimensions are increased until the shared dimension limit is
/// exceeded. Candidate enumeration budget is never reserved or consumed.
pub fn small_roots_monic(
    f: &Polynomial,
    modulus: &Integer,
    beta: &Rational,
    bound: &Integer,
    control: &AttackControl,
) -> Result<Vec<Integer>, Error> {
    control.check_cancelled()?;
    if *modulus <= 1 || *bound <= 0 || f.modulus != *modulus {
        return Err(Error::Unsupported);
    }
    if *beta.numer() <= 0 || *beta.numer() > *beta.denom() {
        return Err(Error::Unsupported);
    }
    let degree = f.degree().ok_or(Error::Unsupported)?;
    if degree == 0
        || degree > MAX_POLYNOMIAL_DEGREE
        || f.coeffs.get(degree) != Some(&Integer::from(1))
    {
        return Err(Error::Unsupported);
    }

    let beta_numerator = beta.numer().to_u32().ok_or(Error::Unsupported)?;
    let beta_denominator = beta.denom().to_u32().ok_or(Error::Unsupported)?;
    let denominator_squared = beta_denominator
        .checked_mul(beta_denominator)
        .ok_or(Error::Unsupported)?;
    let numerator_squared = beta_numerator
        .checked_mul(beta_numerator)
        .ok_or(Error::Unsupported)?;
    let left_exponent = degree
        .checked_mul(denominator_squared as usize)
        .and_then(|exponent| u32::try_from(exponent).ok())
        .ok_or(Error::Unsupported)?;
    if bound.clone().pow(left_exponent) >= modulus.clone().pow(numerator_squared) {
        return Err(Error::Unsupported);
    }

    // m = 1 has dimension d + floor(d/2). No larger m can fit if this fails.
    if degree + degree / 2 > MAX_LLL_DIMENSION {
        return Err(Error::Unsupported);
    }
    if !has_possible_small_root(f, modulus, bound, control)? {
        return Err(Error::NotFound);
    }

    for m in 1..=MAX_LLL_DIMENSION {
        control.check_cancelled()?;
        let t = degree * m / 2;
        let dimension = degree * m + t;
        if dimension > MAX_LLL_DIMENSION {
            return Err(Error::NotFound);
        }

        let x_powers = integer_powers(bound, dimension)?;
        let modulus_powers = integer_powers(modulus, m + 1)?;
        let f_powers = integer_polynomial_powers(&f.coeffs, m)?;

        let mut basis = Vec::with_capacity(dimension);
        for i in 0..m {
            for j in 0..degree {
                control.check_cancelled()?;
                basis.push(scale_row(
                    shifted_polynomial(&f_powers[i], &modulus_powers[m - i], j, dimension)?,
                    &x_powers,
                ));
            }
        }
        for i in 0..t {
            control.check_cancelled()?;
            basis.push(scale_row(
                shifted_polynomial(&f_powers[m], &Integer::from(1), i, dimension)?,
                &x_powers,
            ));
        }

        let reduced = lll(&basis, control)?;
        let roots = roots_from_reduced(f, modulus, reduced, bound, control)?;
        if !roots.is_empty() {
            return Ok(roots);
        }
    }

    Err(Error::NotFound)
}

fn roots_from_reduced(
    f: &Polynomial,
    modulus: &Integer,
    reduced: Vec<Vec<Integer>>,
    bound: &Integer,
    control: &AttackControl,
) -> Result<Vec<Integer>, Error> {
    let x_powers = integer_powers(bound, reduced.len())?;
    let mut roots = Vec::new();
    for row in reduced {
        let mut coefficients = Vec::with_capacity(row.len());
        for (power, value) in row.iter().enumerate() {
            let (coefficient, remainder) = value.div_rem_ref(&x_powers[power]).complete();
            if remainder != 0 {
                return Err(Error::Unsupported);
            }
            coefficients.push(coefficient);
        }
        let row_roots = roots_in_bound(&coefficients, bound, control)?;
        for root in row_roots {
            if root >= 0 && root < *bound && f.eval(&root).gcd(modulus) > 1 {
                roots.push(root);
            }
        }
    }
    roots.sort_unstable();
    roots.dedup();
    Ok(roots)
}

fn has_possible_small_root(
    f: &Polynomial,
    modulus: &Integer,
    bound: &Integer,
    control: &AttackControl,
) -> Result<bool, Error> {
    let Some(limit) = bound.to_u32().filter(|value| *value <= 64) else {
        return Ok(true);
    };
    for candidate in 0..limit {
        control.check_cancelled()?;
        if f.eval(&Integer::from(candidate)).gcd(modulus) > 1 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn roots_in_bound(
    coefficients: &[Integer],
    bound: &Integer,
    control: &AttackControl,
) -> Result<Vec<Integer>, Error> {
    if bound.to_u32().is_some_and(|value| value <= 64) {
        let mut roots = Vec::new();
        for candidate in 0..bound.to_u32().ok_or(Error::Unsupported)? {
            control.check_cancelled()?;
            let root = Integer::from(candidate);
            if eval_integer_polynomial(coefficients, &root) == 0 {
                roots.push(root);
            }
        }
        return Ok(roots);
    }
    integer_roots(coefficients, bound, control)
}

fn eval_integer_polynomial(coefficients: &[Integer], x: &Integer) -> Integer {
    coefficients
        .iter()
        .rev()
        .fold(Integer::ZERO, |value, coefficient| value * x + coefficient)
}

fn integer_powers(base: &Integer, count: usize) -> Result<Vec<Integer>, Error> {
    let mut powers = Vec::with_capacity(count);
    powers.push(Integer::from(1));
    for _ in 1..count {
        powers.push((powers.last().ok_or(Error::Unsupported)? * base).complete());
    }
    Ok(powers)
}

fn shifted_polynomial(
    polynomial: &[Integer],
    scalar: &Integer,
    shift: usize,
    dimension: usize,
) -> Result<Vec<Integer>, Error> {
    let mut row = vec![Integer::from(0); dimension];
    for (degree, coefficient) in polynomial.iter().enumerate() {
        let column = degree.checked_add(shift).ok_or(Error::Unsupported)?;
        let target = row.get_mut(column).ok_or(Error::Unsupported)?;
        *target = (coefficient * scalar).complete();
    }
    Ok(row)
}

fn integer_polynomial_powers(
    coefficients: &[Integer],
    exponent: usize,
) -> Result<Vec<Vec<Integer>>, Error> {
    if coefficients.is_empty() {
        return Err(Error::Unsupported);
    }
    let mut powers = Vec::with_capacity(exponent + 1);
    powers.push(vec![Integer::from(1)]);
    for _ in 0..exponent {
        powers.push(integer_polynomial_mul(
            powers.last().ok_or(Error::Unsupported)?,
            coefficients,
        )?);
    }
    Ok(powers)
}

fn integer_polynomial_mul(left: &[Integer], right: &[Integer]) -> Result<Vec<Integer>, Error> {
    if left.is_empty() || right.is_empty() {
        return Err(Error::Unsupported);
    }
    let coefficient_count = left
        .len()
        .checked_add(right.len() - 1)
        .ok_or(Error::Unsupported)?;
    if coefficient_count > MAX_POLYNOMIAL_DEGREE + 1 {
        return Err(Error::Unsupported);
    }
    let mut product = vec![Integer::ZERO; coefficient_count];
    for (left_degree, left_coefficient) in left.iter().enumerate() {
        for (right_degree, right_coefficient) in right.iter().enumerate() {
            product[left_degree + right_degree] += left_coefficient * right_coefficient;
        }
    }
    while product.len() > 1 && product.last() == Some(&Integer::ZERO) {
        product.pop();
    }
    Ok(product)
}

fn scale_row(mut row: Vec<Integer>, x_powers: &[Integer]) -> Vec<Integer> {
    for (value, power) in row.iter_mut().zip(x_powers) {
        *value = (&*value * power).complete();
    }
    row
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn half() -> Rational {
        Rational::from(1) / Rational::from(2)
    }

    #[test]
    fn small_roots_monic_recovers_linear_modular_root_with_zero_budget() {
        let p = Integer::from_str(
            "112219243609243706223486619551298085362360091408633161457003404046681540344297",
        )
        .unwrap();
        let q = Integer::from_str(
            "64052533192509995760322742160163582601357132095571262796409705234000154367147",
        )
        .unwrap();
        let n = (&p * &q).complete();
        let bound = Integer::from(2).pow(40);
        let known = p.clone() >> 40;
        let base: Integer = known << 40;
        let expected = p.clone() - base.clone();
        let f = Polynomial::new(vec![base, 1.into()], n.clone()).unwrap();
        let control = AttackControl::new(0);

        let roots = small_roots_monic(&f, &n, &half(), &bound, &control).unwrap();

        assert!(roots.iter().all(|root| f.eval(root).gcd(&n) > 1));
        assert!(roots.contains(&expected));
        assert!(roots.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(roots.iter().all(|root| *root >= 0 && *root < bound));
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn small_roots_monic_recovers_root_from_reduced_polynomial() {
        let n: Integer = Integer::from(101) * 103;
        let f = Polynomial::new(vec![2.into(), (-3).into(), 1.into()], n.clone()).unwrap();

        let roots = small_roots_monic(&f, &n, &half(), &2.into(), &AttackControl::new(0)).unwrap();

        assert_eq!(roots, vec![Integer::from(1)]);
    }

    #[test]
    fn small_roots_monic_rejects_invalid_polynomials_and_beta() {
        let n = Integer::from(10403);
        let control = AttackControl::default();
        let non_monic = Polynomial::new(vec![1.into(), 2.into()], n.clone()).unwrap();
        let monic = Polynomial::new(vec![1.into(), 1.into()], n.clone()).unwrap();
        let mismatched = Polynomial::new(vec![1.into(), 1.into()], 10407.into()).unwrap();

        for (f, modulus, beta) in [
            (non_monic, n.clone(), half()),
            (mismatched, n.clone(), half()),
            (monic.clone(), n.clone(), Rational::from(0)),
            (monic.clone(), n.clone(), Rational::from(-1)),
            (monic.clone(), n.clone(), Rational::from(2)),
        ] {
            assert_eq!(
                small_roots_monic(&f, &modulus, &beta, &2.into(), &control),
                Err(Error::Unsupported)
            );
        }
    }

    #[test]
    fn small_roots_monic_rejects_bound_at_exact_conservative_boundary() {
        let n = Integer::from(256);
        let f = Polynomial::new(vec![0.into(), 1.into()], n.clone()).unwrap();

        assert_eq!(
            small_roots_monic(&f, &n, &half(), &4.into(), &AttackControl::default()),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn small_roots_monic_rejects_excessive_degree_before_building_a_basis() {
        let n = Integer::from(10403);
        let mut coeffs = vec![Integer::from(0); MAX_POLYNOMIAL_DEGREE + 1];
        coeffs[MAX_POLYNOMIAL_DEGREE] = Integer::from(1);
        let f = Polynomial::new(coeffs, n.clone()).unwrap();

        assert_eq!(
            small_roots_monic(&f, &n, &half(), &1.into(), &AttackControl::default()),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn small_roots_monic_honors_cancellation_without_consuming_budget() {
        let n = Integer::from(10403);
        let f = Polynomial::new(vec![100.into(), 1.into()], n.clone()).unwrap();
        let control = AttackControl::new(7);
        control.cancel();

        assert_eq!(
            small_roots_monic(&f, &n, &half(), &4.into(), &control),
            Err(Error::Cancelled)
        );
        assert_eq!(control.remaining(), 7);
    }
}
