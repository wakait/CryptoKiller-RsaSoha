use std::collections::{BTreeMap, BTreeSet};

use indicatif::ProgressBar;
use rug::{integer::IsPrime, ops::Pow, Complete, Integer};

use crate::{
    attack::MAX_LLL_DIMENSION,
    key::PrivateKey,
    math::{
        lattice::lll,
        number_theory::{integer_nth_root, integer_sqrt, is_perfect_square},
        polynomial::{integer_roots, BivariatePolynomial, Polynomial},
    },
    Attack, AttackControl, AttackKind, AttackSpeed, Error, Parameters, Solution,
};

const DELTA: (u32, u32) = (1, 4);
const LATTICE_PARAMETERS: [u32; 4] = [4, 6, 7, 8];
const MAX_BOUNDED_Y_CANDIDATES: usize = 4096;
/// Fixed cap on lattice-row resultants per lattice parameter. The first two
/// reduced rows are always tried first; larger bases are never scanned exhaustively.
const MAX_LATTICE_RESULTANT_PAIRS: usize = 16;

type LatticeResult = Result<(Vec<(u32, u32, u32)>, Vec<Vec<Integer>>), Error>;

struct RecoveryContext<'a> {
    n: &'a Integer,
    e: &'a Integer,
    a: &'a Integer,
    x_bound: &'a Integer,
    y_bound: &'a Integer,
    control: &'a AttackControl,
}

/// Recover a balanced RSA key with a conservatively small private exponent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BonehDurfeeAttack;

fn candidate_to_key(n: Integer, e: Integer, d: Integer, y: Integer) -> Option<PrivateKey> {
    if n <= 1 || e < 2 || d <= 0 {
        return None;
    }

    let s: Integer = -2 * y;
    let discriminant = s.clone().pow(2) - (n.clone() << 2);
    let root = is_perfect_square(&discriminant)?;
    let p_numerator: Integer = (&s + &root).complete();
    let q_numerator: Integer = (&s - &root).complete();
    if !p_numerator.is_even() || !q_numerator.is_even() {
        return None;
    }
    let p: Integer = p_numerator / 2;
    let q: Integer = q_numerator / 2;
    let product = p.clone() * q.clone();
    if p <= 1 || q <= 1 || product != n {
        return None;
    }
    if p.is_probably_prime(100) == IsPrime::No || q.is_probably_prime(100) == IsPrime::No {
        return None;
    }

    let p_minus_one = p.clone() - 1;
    let q_minus_one = q.clone() - 1;
    let phi = p_minus_one * q_minus_one;
    let ed = (&e * &d).complete();
    if phi <= 0 {
        return None;
    }
    let ed_remainder = ed % phi;
    if ed_remainder != 1 {
        return None;
    }
    let private_key = PrivateKey::from_p_q(p, q, e.clone()).ok()?;
    let private_ed = (&private_key.e * &private_key.d).complete();
    if private_key.n != n
        || private_key.e != e
        || private_key.d != d
        || (&private_ed % &private_key.phi()).complete() != 1
    {
        return None;
    }
    Some(private_key)
}

fn f_polynomial(a: &Integer) -> BivariatePolynomial {
    BivariatePolynomial::new(BTreeMap::from([
        ((0, 0, 0), Integer::ONE.clone()),
        ((0, 1, 0), a.clone()),
        ((0, 1, 1), Integer::ONE.clone()),
    ]))
}

fn x_shift(polynomial: &BivariatePolynomial, shift: u32, scale: &Integer) -> BivariatePolynomial {
    BivariatePolynomial::new(
        polynomial
            .terms
            .iter()
            .map(|(&(u, x, y), coefficient)| ((u, x + shift, y), (coefficient * scale).complete()))
            .collect(),
    )
    .canonicalize()
}

fn y_shift(polynomial: &BivariatePolynomial, shift: u32, scale: &Integer) -> BivariatePolynomial {
    BivariatePolynomial::new(
        polynomial
            .terms
            .iter()
            .map(|(&(u, x, y), coefficient)| ((u, x, y + shift), (coefficient * scale).complete()))
            .collect(),
    )
    .canonicalize()
}

fn build_lattice(n: &Integer, e: &Integer, m: u32, control: &AttackControl) -> LatticeResult {
    control.check_cancelled()?;
    let a: Integer = (n.clone() + 1) / 2;
    let x_bound: Integer = 2 * integer_nth_root(n, 4) + 2;
    let y_bound: Integer = integer_sqrt(n) + 1;
    let u_scale: Integer = x_bound.clone() * y_bound.clone() + 1;
    let f = f_polynomial(&a);
    let t = m * (DELTA.1 - 2 * DELTA.0) / DELTA.1;

    let mut polynomials = Vec::new();
    let mut x_monomials = BTreeSet::new();
    for k in 0..=m {
        control.check_cancelled()?;
        let power = f.pow(k);
        let scale = e.pow(m - k).complete();
        for i in 0..=m - k {
            control.check_cancelled()?;
            let polynomial = x_shift(&power, i, &scale);
            x_monomials.extend(polynomial.terms.keys().copied());
            polynomials.push(polynomial);
        }
    }

    let mut monomials: Vec<_> = x_monomials.into_iter().collect();
    monomials.retain(|monomial| *monomial != (0, 0, 0));
    for j in 1..=t {
        control.check_cancelled()?;
        for k in (m / t) * j..=m {
            control.check_cancelled()?;
            let power = f.pow(k);
            let scale = e.pow(m - k).complete();
            let polynomial = y_shift(&power, j, &scale);
            monomials.extend(polynomial.terms.keys().copied());
            polynomials.push(polynomial);
        }
    }

    // Keep every monomial occurring in a shift. Dropping non-leading terms
    // from y-shifts breaks the lattice invariant h(x0, y0) = 0 (mod e).
    monomials.sort_unstable();
    monomials.dedup();
    monomials.retain(|monomial| *monomial != (0, 0, 0));
    let dimension = polynomials.len();
    if dimension > MAX_LLL_DIMENSION || monomials.len() + 1 > MAX_LLL_DIMENSION {
        return Err(Error::Unsupported);
    }
    let scales: Vec<_> = monomials
        .iter()
        .map(|&(u, x, y)| u_scale.clone().pow(u) * x_bound.clone().pow(x) * y_bound.clone().pow(y))
        .collect();
    let mut basis = Vec::with_capacity(dimension);
    for polynomial in polynomials {
        control.check_cancelled()?;
        let mut row = Vec::with_capacity(monomials.len() + 1);
        row.push(
            polynomial
                .terms
                .get(&(0, 0, 0))
                .cloned()
                .unwrap_or_default(),
        );
        for (&monomial, scale) in monomials.iter().zip(&scales) {
            let coefficient = polynomial.terms.get(&monomial).cloned().unwrap_or_default();
            row.push(coefficient * scale);
        }
        basis.push(row);
    }
    Ok((monomials, basis))
}

fn polynomial_from_row(
    row: &[Integer],
    monomials: &[(u32, u32, u32)],
    scales: &[Integer],
    control: &AttackControl,
) -> Result<BivariatePolynomial, Error> {
    control.check_cancelled()?;
    if row.len() != monomials.len() + 1 || scales.len() != monomials.len() {
        return Err(Error::Unsupported);
    }
    let mut terms = BTreeMap::new();
    if row[0] != 0 {
        terms.insert((0, 0, 0), row[0].clone());
    }
    for (index, (&(u, x, y), scale)) in monomials.iter().zip(scales).enumerate() {
        control.check_cancelled()?;
        let coefficient = &row[index + 1];
        if *coefficient == 0 {
            continue;
        }
        let (coefficient, remainder) = coefficient.clone().div_rem(scale.clone());
        if remainder != 0 {
            return Err(Error::Unsupported);
        }
        let mut binomial = Integer::ONE.clone();
        for power in 0..=u {
            *terms.entry((0, x + power, y + power)).or_default() += &coefficient * &binomial;
            if power < u {
                binomial = (&binomial * (u - power)).complete() / (power + 1);
            }
        }
    }
    Ok(BivariatePolynomial::new(terms))
}

fn polynomials_are_proportional(left: &BivariatePolynomial, right: &BivariatePolynomial) -> bool {
    let Some((_, left_coefficient)) = left.terms.iter().next() else {
        return right.terms.is_empty();
    };
    let Some((_, right_coefficient)) = right.terms.iter().next() else {
        return false;
    };
    left.terms.keys().chain(right.terms.keys()).all(|monomial| {
        (left.terms.get(monomial).unwrap_or(&Integer::ZERO) * right_coefficient).complete()
            == (right.terms.get(monomial).unwrap_or(&Integer::ZERO) * left_coefficient).complete()
    })
}

fn signed_roots(
    polynomial: &Polynomial,
    bound: &Integer,
    control: &AttackControl,
) -> Result<Vec<Integer>, Error> {
    control.check_cancelled()?;
    if *bound < 0 {
        return Ok(Vec::new());
    }
    let modulus = &polynomial.modulus;
    let mut roots: Vec<_> = polynomial
        .roots(control)?
        .into_iter()
        .map(|root| {
            let doubled = root.clone() * 2;
            if doubled > *modulus {
                root - modulus
            } else {
                root
            }
        })
        .filter(|root| root.clone().abs() <= *bound)
        .collect();
    roots.sort_unstable();
    roots.dedup();
    Ok(roots)
}

fn specialize_x(
    polynomial: &BivariatePolynomial,
    y: &Integer,
    control: &AttackControl,
) -> Result<Vec<Integer>, Error> {
    let degree = polynomial
        .terms
        .keys()
        .map(|&(_, x, _)| x as usize)
        .max()
        .unwrap_or(0);
    let mut coefficients = vec![Integer::ZERO; degree + 1];
    let y_degrees = polynomial.terms.keys().map(|key| key.2).max().unwrap_or(0);
    let mut power = Integer::ONE.clone();
    for y_degree in 0..=y_degrees {
        control.check_cancelled()?;
        for (&(_, x, coefficient_y), coefficient) in &polynomial.terms {
            if coefficient_y == y_degree {
                coefficients[x as usize] += coefficient * &power;
            }
        }
        power *= y;
    }
    Ok(coefficients)
}

fn candidate_from_x_y(
    n: &Integer,
    e: &Integer,
    a: &Integer,
    x: Integer,
    y: Integer,
) -> Option<PrivateKey> {
    if !x.is_even() {
        return None;
    }
    let sum: Integer = (a + &y).complete();
    let numerator: Integer = x * sum + 1;
    if numerator <= 0 {
        return None;
    }
    let (d, remainder) = numerator.div_rem(e.clone());
    if remainder != 0 || d <= 0 {
        return None;
    }
    candidate_to_key(n.clone(), e.clone(), d, y)
}

/// Recover from every lattice row when the complete y interval is small.
///
/// This bounded fallback handles small keys where the standard rows share the
/// known factor `f` modulo `e`, making their pairwise resultant degenerate.
fn recover_from_bounded_y(
    n: &Integer,
    e: &Integer,
    a: &Integer,
    x_bound: &Integer,
    y_bound: &Integer,
    rows: &[BivariatePolynomial],
    control: &AttackControl,
) -> Result<Option<PrivateKey>, Error> {
    control.check_cancelled()?;
    if *y_bound < 0 || *x_bound < 0 || rows.is_empty() {
        return Ok(None);
    }
    let bound = y_bound.to_usize().ok_or(Error::Unsupported)?;
    if bound > (MAX_BOUNDED_Y_CANDIDATES - 1) / 2 {
        return Ok(None);
    }
    let candidate_count = u64::try_from(bound * 2 + 1).map_err(|_| Error::Unsupported)?;
    control.reserve_candidates(candidate_count)?;
    let mut y = Integer::from(-(bound as i64));
    let last_y = Integer::from(bound as i64);
    while y <= last_y {
        control.check_cancelled()?;
        for row in rows {
            control.check_cancelled()?;
            let coefficients = specialize_x(row, &y, control)?;
            if coefficients.iter().all(|coefficient| *coefficient == 0) {
                continue;
            }
            let polynomial = Polynomial::new(coefficients, e.clone())?;
            if polynomial.degree().is_none() {
                continue;
            }
            for x in signed_roots(&polynomial, x_bound, control)? {
                control.check_cancelled()?;
                if let Some(private_key) = candidate_from_x_y(n, e, a, x, y.clone()) {
                    return Ok(Some(private_key));
                }
            }
        }
        y += 1;
    }
    Ok(None)
}

fn recover_from_rows(
    context: &RecoveryContext<'_>,
    monomials: &[(u32, u32, u32)],
    scales: &[Integer],
    rows: &[Vec<Integer>],
) -> Result<Option<PrivateKey>, Error> {
    context.control.check_cancelled()?;
    if rows.len() < 2 {
        return Err(Error::Unsupported);
    }
    let mut polynomials = Vec::new();
    for row in rows {
        context.control.check_cancelled()?;
        if row.iter().all(|coefficient| *coefficient == 0) {
            continue;
        }
        let polynomial = polynomial_from_row(row, monomials, scales, context.control)?;
        polynomials.push(polynomial);
    }
    if polynomials.is_empty() {
        return Ok(None);
    }

    // Integer row combinations need no modulo-e factorization or common-factor
    // stripping. Cap the number of resultants independently of basis dimension.
    recover_from_independent_pairs(context, &polynomials)
}

fn recover_from_independent_pairs(
    context: &RecoveryContext<'_>,
    polynomials: &[BivariatePolynomial],
) -> Result<Option<PrivateKey>, Error> {
    let mut attempted = 0usize;
    for left in 0..polynomials.len() {
        context.control.check_cancelled()?;
        for right in left + 1..polynomials.len() {
            if attempted == MAX_LATTICE_RESULTANT_PAIRS {
                return Ok(None);
            }
            context.control.check_cancelled()?;
            attempted += 1;
            if !polynomials_are_proportional(&polynomials[left], &polynomials[right]) {
                if let Some(private_key) =
                    recover_from_pair(context, &polynomials[left], &polynomials[right])?
                {
                    return Ok(Some(private_key));
                }
            }
        }
    }
    Ok(None)
}

fn recover_from_pair(
    context: &RecoveryContext<'_>,
    h1: &BivariatePolynomial,
    h2: &BivariatePolynomial,
) -> Result<Option<PrivateKey>, Error> {
    context.control.check_cancelled()?;
    let (h1, h2) = if h1.terms.keys().any(|monomial| monomial.1 != 0) {
        (h1, h2)
    } else if h2.terms.keys().any(|monomial| monomial.1 != 0) {
        (h2, h1)
    } else {
        return Ok(None);
    };
    if h1.terms.is_empty() || h2.terms.is_empty() {
        return Ok(None);
    }
    let resultant = h1.resultant(h2, context.control)?;
    if resultant.len() <= 1 || resultant.iter().all(|coefficient| *coefficient == 0) {
        return Ok(None);
    }
    let y_roots = integer_roots(&resultant, context.y_bound, context.control)?;
    for y in y_roots {
        context.control.check_cancelled()?;
        let x_polynomials = [h1, h2]
            .into_iter()
            .map(|polynomial| specialize_x(polynomial, &y, context.control))
            .collect::<Result<Vec<_>, _>>()?;
        for coefficients in x_polynomials {
            if coefficients.iter().all(|coefficient| *coefficient == 0) {
                continue;
            }
            let x_roots = integer_roots(&coefficients, context.x_bound, context.control)?;
            for x in x_roots {
                context.control.check_cancelled()?;
                if let Some(private_key) =
                    candidate_from_x_y(context.n, context.e, context.a, x, y.clone())
                {
                    return Ok(Some(private_key));
                }
            }
        }
    }
    Ok(None)
}

impl Attack for BonehDurfeeAttack {
    fn name(&self) -> &'static str {
        "boneh_durfee"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Slow
    }

    fn kind(&self) -> AttackKind {
        AttackKind::Factorization
    }

    fn required_parameters(&self) -> &'static [&'static str] {
        &["n", "e"]
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
        let e = &params.e;
        if *n <= 1 || *e < 2 || e.is_probably_prime(100) == IsPrime::No {
            return Err(Error::Unsupported);
        }
        let a: Integer = (n.clone() + 1) / 2;
        let x_bound: Integer = 2 * integer_nth_root(n, 4) + 2;
        let y_bound: Integer = integer_sqrt(n) + 1;
        let u_scale: Integer = x_bound.clone() * y_bound.clone() + 1;
        let context = RecoveryContext {
            n,
            e,
            a: &a,
            x_bound: &x_bound,
            y_bound: &y_bound,
            control,
        };

        for m in LATTICE_PARAMETERS {
            control.check_cancelled()?;
            let (monomials, basis) = build_lattice(n, e, m, control)?;
            let scales: Vec<_> = monomials
                .iter()
                .map(|&(u, x, y)| {
                    u_scale.clone().pow(u) * x_bound.clone().pow(x) * y_bound.clone().pow(y)
                })
                .collect();
            let reduced = if y_bound
                .to_usize()
                .is_some_and(|bound| bound <= (MAX_BOUNDED_Y_CANDIDATES - 1) / 2)
            {
                let rows = basis
                    .iter()
                    .map(|row| polynomial_from_row(row, &monomials, &scales, control))
                    .collect::<Result<Vec<_>, _>>()?;
                return match recover_from_bounded_y(n, e, &a, &x_bound, &y_bound, &rows, control)? {
                    Some(private_key) => Ok(Solution::new_pk(self.name(), private_key)),
                    None => Err(Error::NotFound),
                };
            } else {
                lll(&basis, control)?
            };
            if let Some(private_key) = recover_from_rows(&context, &monomials, &scales, &reduced)? {
                return Ok(Solution::new_pk(self.name(), private_key));
            }
        }
        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::Integer;

    use crate::math::polynomial::Polynomial;

    use super::*;
    use crate::{Attack, AttackControl, Error, Parameters};

    #[test]
    fn boneh_durfee_recovers_conservative_small_d() {
        // p=61, q=53, phi=3120, d=7, e=1783, k=4.
        let params = Parameters {
            n: Some(3233.into()),
            e: 1783.into(),
            ..Default::default()
        };
        let solution = BonehDurfeeAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();
        assert_eq!(pk.p(), Integer::from(53));
        assert_eq!(pk.q(), Integer::from(61));
        assert_eq!(pk.d, Integer::from(7));
    }

    #[test]
    fn boneh_durfee_rejects_invalid_candidate() {
        assert!(candidate_to_key(3233.into(), 1783.into(), 6.into(), (-57).into()).is_none());
    }

    #[test]
    fn boneh_durfee_returns_not_found_for_large_d_instance() {
        let params = Parameters {
            n: Some(3233.into()),
            e: 17.into(),
            ..Default::default()
        };
        assert_eq!(BonehDurfeeAttack.run(&params, None), Err(Error::NotFound));
    }

    #[test]
    fn boneh_durfee_rejects_composite_public_exponent() {
        let params = Parameters {
            n: Some(3233.into()),
            e: 9.into(),
            ..Default::default()
        };
        assert_eq!(
            BonehDurfeeAttack.run(&params, None),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn boneh_durfee_signed_roots_are_centered_and_bounded() {
        let control = AttackControl::default();
        // (y-3)(y-7)(y+2) modulo 13; 7 has signed representative -6.
        let f = Polynomial::new(vec![3.into(), 1.into(), 5.into(), 1.into()], 13.into()).unwrap();
        assert_eq!(
            signed_roots(&f, &6.into(), &control).unwrap(),
            vec![Integer::from(-6), Integer::from(-2), Integer::from(3)]
        );
        assert_eq!(
            signed_roots(&f, &2.into(), &control).unwrap(),
            vec![Integer::from(-2)]
        );
        assert!(signed_roots(&f, &(-1).into(), &control).unwrap().is_empty());
    }

    #[test]
    fn boneh_durfee_bounded_y_recovers_signed_x_root() {
        let n = Integer::from(3233);
        let e = Integer::from(1783);
        let a: Integer = (n.clone() + 1) / 2;
        let control = AttackControl::default();
        let rows = vec![f_polynomial(&a)];
        let key = recover_from_bounded_y(&n, &e, &a, &16.into(), &57.into(), &rows, &control)
            .unwrap()
            .expect("bounded finite-field recovery should find the fixed key");
        assert_eq!(key.d, Integer::from(7));
    }

    #[test]
    fn boneh_durfee_bounded_y_reserves_entire_shared_interval() {
        let n = Integer::from(3233);
        let e = Integer::from(1783);
        let a: Integer = (n.clone() + 1) / 2;
        let rows = vec![f_polynomial(&a)];

        let control = AttackControl::new(114);
        assert_eq!(
            recover_from_bounded_y(&n, &e, &a, &16.into(), &57.into(), &rows, &control),
            Err(Error::BudgetExceeded)
        );
        assert_eq!(control.remaining(), 114);

        let control = AttackControl::new(115);
        let key = recover_from_bounded_y(&n, &e, &a, &16.into(), &57.into(), &rows, &control)
            .unwrap()
            .expect("bounded finite-field recovery should find the fixed key");
        assert_eq!(key.d, Integer::from(7));
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn boneh_durfee_zero_budget_disables_bounded_y_enumeration() {
        let params = Parameters {
            n: Some(3233.into()),
            e: 1783.into(),
            search_budget: 0,
            ..Default::default()
        };
        let control = AttackControl::new(0);
        assert_eq!(
            BonehDurfeeAttack.run_cancellable(&params, None, &control),
            Err(Error::BudgetExceeded)
        );
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn boneh_durfee_row_scan_continues_past_degenerate_resultants() {
        let n = Integer::from(3233);
        let e = Integer::from(1783);
        let a: Integer = (n.clone() + 1) / 2;
        let control = AttackControl::default();
        let x_bound = Integer::from(16);
        let y_bound = Integer::from(57);
        let context = RecoveryContext {
            n: &n,
            e: &e,
            a: &a,
            x_bound: &x_bound,
            y_bound: &y_bound,
            control: &control,
        };
        let monomials = vec![(0, 2, 0), (0, 1, 1), (0, 1, 0), (0, 0, 1)];
        let scales = vec![Integer::ONE.clone(); monomials.len()];
        // h1 = x+y+49. h2 = h1*(x+1) has zero resultant with h1.
        // h3 is constant, and h4 = x-8 yields the valid fixed-key resultant.
        let rows = [
            [49.into(), 0.into(), 0.into(), 1.into(), 1.into()],
            [49.into(), 1.into(), 1.into(), 50.into(), 1.into()],
            [2.into(), 0.into(), 0.into(), 0.into(), 0.into()],
            [(-8).into(), 0.into(), 0.into(), 1.into(), 0.into()],
        ];
        let h1 = polynomial_from_row(&rows[0], &monomials, &scales, &control).unwrap();
        let h4 = polynomial_from_row(&rows[3], &monomials, &scales, &control).unwrap();
        assert!(
            recover_from_pair(&context, &h1, &h4).unwrap().is_some(),
            "direct valid pair should recover the fixed key"
        );
        let polynomials: Vec<_> = rows
            .iter()
            .map(|row| polynomial_from_row(row, &monomials, &scales, &control).unwrap())
            .collect();
        let key = recover_from_independent_pairs(&context, &polynomials)
            .unwrap()
            .expect("row scan should continue past zero and constant resultants");
        assert_eq!(key.d, Integer::from(7));
    }

    #[test]
    fn boneh_durfee_reconstructed_lattice_rows_vanish_at_small_root_mod_e() {
        let n = Integer::from_str("236894635691475796834317810819055966273").unwrap();
        let e = Integer::from_str("157929757127650531202356698060357130499").unwrap();
        let x_bound: Integer = 2 * integer_nth_root(&n, 4) + 2;
        let y_bound: Integer = integer_sqrt(&n) + 1;
        let u_scale: Integer = x_bound.clone() * y_bound.clone() + 1;
        let control = AttackControl::default();
        let (monomials, basis) = build_lattice(&n, &e, 4, &control).unwrap();
        let scales: Vec<_> = monomials
            .iter()
            .map(|&(u, x, y)| {
                u_scale.clone().pow(u) * x_bound.clone().pow(x) * y_bound.clone().pow(y)
            })
            .collect();

        // ed - 1 = 2*phi, hence x0 = 2*k = 4 and y0 = -(p+q)/2.
        let x0 = Integer::from(4);
        let y0 = Integer::from_str("-15391381864260135263").unwrap();
        for (index, row) in basis.iter().enumerate() {
            let polynomial = polynomial_from_row(row, &monomials, &scales, &control).unwrap();
            let coefficients = specialize_x(&polynomial, &y0, &control).unwrap();
            let mut value = Integer::ZERO;
            for coefficient in coefficients.iter().rev() {
                value = (&value * &x0 + coefficient).complete();
            }
            assert_eq!(
                (&value % &e).complete(),
                Integer::ZERO,
                "lattice row {index} must vanish at the RSA small root modulo e"
            );
        }
    }

    #[test]
    fn boneh_durfee_recovers_large_fixture_via_lll_and_resultant() {
        // p=2003, q=2111, phi=4222200*4228332, d=3, e=2816147, k=2.
        // Y=2057 deliberately exceeds the bounded-y threshold; this fixture
        // must use LLL, an integer resultant and exact integer root recovery.
        let p = Integer::from(2003);
        let q = Integer::from(2111);
        let n = Integer::from(4228333);
        let e = Integer::from(2816147);
        let a: Integer = (n.clone() + 1) / 2;
        let x_bound: Integer = 2 * integer_nth_root(&n, 4) + 2;
        let y_bound: Integer = integer_sqrt(&n) + 1;
        assert_eq!((&p * &q).complete(), n);
        assert!(y_bound > 2047);
        assert_eq!(y_bound, Integer::from(2057));
        let d = Integer::from(3);
        let x0 = Integer::from(4);
        let y0 = Integer::from(-2057);
        assert!(y0.clone().abs() <= y_bound);
        let phi = (p.clone() - 1) * (q.clone() - 1);
        let ed_minus_one = (&e * &d).complete() - 1;
        let two_phi: Integer = Integer::from(2) * &phi;
        assert_eq!(ed_minus_one, two_phi);
        let lhs: Integer = 1 + x0.clone() * (a.clone() + y0.clone());
        assert_eq!(lhs, (&e * &d).complete());
        assert_eq!(e.is_probably_prime(100), IsPrime::Yes);

        let control = AttackControl::new(0);
        let context = RecoveryContext {
            n: &n,
            e: &e,
            a: &a,
            x_bound: &x_bound,
            y_bound: &y_bound,
            control: &control,
        };
        let mut recovered = None;
        for m in LATTICE_PARAMETERS {
            let (monomials, basis) = build_lattice(&n, &e, m, &control).unwrap();
            let u_scale: Integer = x_bound.clone() * y_bound.clone() + 1;
            let scales: Vec<_> = monomials
                .iter()
                .map(|&(u, x, y)| {
                    u_scale.clone().pow(u) * x_bound.clone().pow(x) * y_bound.clone().pow(y)
                })
                .collect();
            let reduced = crate::math::lattice::lll(&basis, &control).unwrap();
            let h1 = polynomial_from_row(&reduced[0], &monomials, &scales, &control).unwrap();
            let h2 = polynomial_from_row(&reduced[1], &monomials, &scales, &control).unwrap();
            let first_pair_key = recover_from_pair(&context, &h1, &h2).unwrap();
            assert!(
                first_pair_key.is_none(),
                "m={m} first two rows have a cancelling resultant; the capped scan must continue"
            );
            if let Some(key) = recover_from_rows(&context, &monomials, &scales, &reduced).unwrap() {
                recovered = Some(key);
                break;
            }
        }
        let key = recovered.expect("LLL/resultant path should recover the large fixture");
        assert_eq!(key.p(), p);
        assert_eq!(key.q(), q);
        assert_eq!(key.d, d);
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn boneh_durfee_honors_pre_cancelled_control() {
        let params = Parameters {
            n: Some(3233.into()),
            e: 1783.into(),
            ..Default::default()
        };
        let control = AttackControl::default();
        control.cancel();
        assert_eq!(
            BonehDurfeeAttack.run_cancellable(&params, None, &control),
            Err(Error::Cancelled)
        );
    }
}
