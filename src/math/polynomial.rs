//! Exact polynomial arithmetic and integer root isolation.

use std::collections::BTreeMap;

use rug::{ops::DivRounding, Complete, Integer, Rational};

use crate::attack::{
    AttackControl, Error, CANCEL_CHECK_BATCH, MAX_POLYNOMIAL_DEGREE, MAX_ROOT_SPLIT_ATTEMPTS,
};

/// A polynomial over `Z / modulus Z`, with coefficients in ascending order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coeffs: Vec<Integer>,
    pub modulus: Integer,
}

impl Polynomial {
    /// Construct a normalized polynomial, rejecting invalid domains and input
    /// degrees above the shared resource limit.
    pub fn new(coeffs: Vec<Integer>, modulus: Integer) -> Result<Self, Error> {
        if modulus <= 1 || coeffs.is_empty() || coeffs.len() > MAX_POLYNOMIAL_DEGREE + 1 {
            return Err(Error::Unsupported);
        }
        let mut polynomial = Self { coeffs, modulus };
        for coefficient in &mut polynomial.coeffs {
            let normalized = normalize_coefficient(coefficient, &polynomial.modulus);
            *coefficient = normalized;
        }
        polynomial.trim();
        Ok(polynomial)
    }

    /// Construct zero. Panics if the modulus is not a valid polynomial ring.
    pub fn zero(modulus: Integer) -> Self {
        assert!(modulus > 1, "invalid polynomial modulus");
        Self {
            coeffs: vec![Integer::ZERO],
            modulus,
        }
    }

    /// Construct one. Panics if the modulus is not a valid polynomial ring.
    pub fn one(modulus: Integer) -> Self {
        assert!(modulus > 1, "invalid polynomial modulus");
        Self {
            coeffs: vec![Integer::ONE.clone()],
            modulus,
        }
    }

    pub fn degree(&self) -> Option<usize> {
        self.coeffs
            .iter()
            .rposition(|coefficient| *coefficient != 0)
    }

    pub fn add(&self, other: &Self) -> Self {
        self.check_same_modulus(other);
        let mut coeffs = vec![Integer::ZERO; self.coeffs.len().max(other.coeffs.len())];
        for (index, coefficient) in coeffs.iter_mut().enumerate() {
            let sum = (self.coeffs.get(index).unwrap_or(&Integer::ZERO)
                + other.coeffs.get(index).unwrap_or(&Integer::ZERO))
            .complete();
            *coefficient = normalize_coefficient(&sum, &self.modulus);
        }
        Self::from_normalized(coeffs, self.modulus.clone())
    }

    pub fn sub(&self, other: &Self) -> Self {
        self.check_same_modulus(other);
        let mut coeffs = vec![Integer::ZERO; self.coeffs.len().max(other.coeffs.len())];
        for (index, coefficient) in coeffs.iter_mut().enumerate() {
            let difference = (self.coeffs.get(index).unwrap_or(&Integer::ZERO)
                - other.coeffs.get(index).unwrap_or(&Integer::ZERO))
            .complete();
            *coefficient = normalize_coefficient(&difference, &self.modulus);
        }
        Self::from_normalized(coeffs, self.modulus.clone())
    }

    pub fn mul(&self, other: &Self) -> Self {
        self.check_same_modulus(other);
        let degree = self.degree().unwrap_or(0) + other.degree().unwrap_or(0);
        assert!(
            degree <= MAX_POLYNOMIAL_DEGREE,
            "polynomial degree limit exceeded"
        );
        if self.degree().is_none() || other.degree().is_none() {
            return Self::zero(self.modulus.clone());
        }
        let mut coeffs = vec![Integer::ZERO; degree + 1];
        for (i, left) in self.coeffs.iter().enumerate() {
            for (j, right) in other.coeffs.iter().enumerate() {
                let product = (&coeffs[i + j] + left * right).complete();
                coeffs[i + j] = normalize_coefficient(&product, &self.modulus);
            }
        }
        Self::from_normalized(coeffs, self.modulus.clone())
    }

    pub fn pow(&self, exponent: u32) -> Self {
        assert!(
            u64::from(self.degree().unwrap_or(0) as u32) * u64::from(exponent)
                <= MAX_POLYNOMIAL_DEGREE as u64,
            "polynomial degree limit exceeded"
        );
        let mut result = Self::one(self.modulus.clone());
        let mut base = self.clone();
        let mut exponent = exponent;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = result.mul(&base);
            }
            exponent >>= 1;
            if exponent != 0 {
                base = base.mul(&base);
            }
        }
        result
    }

    /// Return all distinct roots in the prime field, sorted by canonical residue.
    ///
    /// Square-free factorization is exact. Splitting uses a deterministic
    /// Berlekamp nullspace basis and constant shifts, returning `Unsupported`
    /// if a fixed per-splitter attempt limit is exhausted. No candidate budget
    /// is consumed.
    pub fn roots(&self, control: &AttackControl) -> Result<Vec<Integer>, Error> {
        control.check_cancelled()?;
        if self.modulus.is_probably_prime(100) == rug::integer::IsPrime::No {
            return Err(Error::Unsupported);
        }
        if self.degree().is_none() {
            return Err(Error::Unsupported);
        }
        let mut roots = roots_recursive(&self.monic()?, control)?;
        roots.sort_unstable();
        roots.dedup();
        Ok(roots)
    }

    /// Polynomial long division over the modular coefficient ring.
    pub fn rem(&self, divisor: &Self) -> Result<Self, Error> {
        self.check_same_modulus(divisor);
        let divisor_degree = divisor.degree().ok_or(Error::Unsupported)?;
        if divisor_degree == 0 {
            divisor.coeffs[0]
                .invert_ref(&self.modulus)
                .ok_or(Error::Unsupported)?;
            return Ok(Self::zero(self.modulus.clone()));
        }
        assert!(
            divisor_degree <= MAX_POLYNOMIAL_DEGREE,
            "polynomial degree limit exceeded"
        );
        let inverse = divisor.coeffs[divisor_degree]
            .invert_ref(&self.modulus)
            .ok_or(Error::Unsupported)?
            .complete();
        let mut remainder = self.clone();
        while remainder
            .degree()
            .is_some_and(|degree| degree >= divisor_degree)
        {
            let degree = remainder.degree().unwrap_or(0);
            let shift = degree - divisor_degree;
            let product = (&remainder.coeffs[degree] * &inverse).complete();
            let factor = normalize_coefficient(&product, &self.modulus);
            for (index, coefficient) in divisor.coeffs.iter().enumerate() {
                let difference =
                    (&remainder.coeffs[index + shift] - &factor * coefficient).complete();
                remainder.coeffs[index + shift] = normalize_coefficient(&difference, &self.modulus);
            }
            remainder.trim();
        }
        Ok(remainder)
    }

    pub fn monic(&self) -> Result<Self, Error> {
        let degree = self.degree().ok_or(Error::Unsupported)?;
        let inverse = self.coeffs[degree]
            .invert_ref(&self.modulus)
            .ok_or(Error::Unsupported)?
            .complete();
        Ok(Self::from_normalized(
            self.coeffs
                .iter()
                .map(|coefficient| {
                    let product = (coefficient * &inverse).complete();
                    normalize_coefficient(&product, &self.modulus)
                })
                .collect(),
            self.modulus.clone(),
        ))
    }

    pub fn gcd(&self, other: &Self) -> Result<Self, Error> {
        self.check_same_modulus(other);
        let mut left = self.clone();
        let mut right = other.clone();
        while right.degree().is_some() {
            let remainder = left.rem(&right)?;
            left = right;
            right = remainder;
        }
        if left.degree().is_none() {
            Ok(left)
        } else {
            left.monic()
        }
    }

    pub fn eval(&self, x: &Integer) -> Integer {
        self.coeffs
            .iter()
            .rev()
            .fold(Integer::ZERO, |value, coefficient| {
                let product = value * x + coefficient;
                normalize_coefficient(&product, &self.modulus)
            })
    }

    /// Expand `(a*x + b)^e - c` in the modular polynomial ring.
    pub fn from_affine_power(
        a: &Integer,
        b: &Integer,
        e: u32,
        c: &Integer,
        modulus: Integer,
    ) -> Self {
        assert!(modulus > 1, "invalid polynomial modulus");
        assert!(
            e as usize <= MAX_POLYNOMIAL_DEGREE,
            "polynomial degree limit exceeded"
        );
        let base = Self::new(vec![b.clone(), a.clone()], modulus.clone())
            .expect("validated polynomial domain and degree");
        let mut result = base.pow(e);
        let difference = (&result.coeffs[0] - c).complete();
        result.coeffs[0] = normalize_coefficient(&difference, &modulus);
        result.trim();
        result
    }

    fn check_same_modulus(&self, other: &Self) {
        assert_eq!(self.modulus, other.modulus, "polynomial modulus mismatch");
    }

    fn from_normalized(mut coeffs: Vec<Integer>, modulus: Integer) -> Self {
        while coeffs.len() > 1 && coeffs.last() == Some(&Integer::ZERO) {
            coeffs.pop();
        }
        Self { coeffs, modulus }
    }

    fn trim(&mut self) {
        while self.coeffs.len() > 1 && self.coeffs.last() == Some(&Integer::ZERO) {
            self.coeffs.pop();
        }
    }
}

/// Return all distinct integer roots in `[-bound, bound]`, sorted ascending.
/// Isolation uses an exact rational Sturm sequence; no floating-point root
/// approximation or candidate-budget reservation is involved.
pub fn integer_roots(
    coeffs: &[Integer],
    bound: &Integer,
    control: &AttackControl,
) -> Result<Vec<Integer>, Error> {
    control.check_cancelled()?;
    if coeffs.is_empty() || coeffs.len() > MAX_POLYNOMIAL_DEGREE + 1 {
        return Err(Error::Unsupported);
    }
    let mut integer_coeffs = coeffs.to_vec();
    while integer_coeffs.len() > 1 && integer_coeffs.last() == Some(&Integer::ZERO) {
        integer_coeffs.pop();
    }
    if integer_coeffs.len() == 1 {
        return if integer_coeffs[0] == 0 {
            Err(Error::Unsupported)
        } else {
            Ok(Vec::new())
        };
    }
    if *bound < 0 {
        return Ok(Vec::new());
    }
    let polynomial: Vec<Rational> = integer_coeffs.iter().cloned().map(Rational::from).collect();
    let derivative = rational_derivative(&polynomial);
    let mut sturm = vec![polynomial.clone(), derivative];
    loop {
        control.check_cancelled()?;
        let remainder = rational_rem(
            sturm[sturm.len() - 2].clone(),
            sturm[sturm.len() - 1].clone(),
        )?;
        if remainder.is_empty() {
            break;
        }
        sturm.push(
            remainder
                .into_iter()
                .map(|coefficient| -coefficient)
                .collect(),
        );
    }
    let left = Rational::from(-(bound + Integer::from(1)));
    let right = Rational::from(bound + 1);
    let mut pending = vec![(left.clone(), right.clone())];
    let mut roots = Vec::new();
    let mut visited = 0usize;
    while let Some((left, right)) = pending.pop() {
        if visited.is_multiple_of(CANCEL_CHECK_BATCH) {
            control.check_cancelled()?;
        }
        visited += 1;
        let count = sign_variations(&sturm, &left).saturating_sub(sign_variations(&sturm, &right));
        if count == 0 {
            continue;
        }
        if (&right - &left).complete() <= 1 {
            let first = rational_ceil(&left);
            let last = rational_floor(&right);
            let mut candidate = first;
            while candidate <= last {
                if candidate.clone().abs() <= *bound
                    && eval_integer(&integer_coeffs, &candidate) == 0
                {
                    roots.push(candidate.clone());
                }
                candidate += 1;
            }
            continue;
        }
        let middle = (&left + &right).complete() / Rational::from(2);
        let middle_integer = rational_floor(&middle);
        if middle.numer() == &middle_integer
            && middle.denom() == Integer::ONE
            && eval_integer(&integer_coeffs, &middle_integer) == 0
        {
            roots.push(middle_integer);
        }
        let left_count =
            sign_variations(&sturm, &left).saturating_sub(sign_variations(&sturm, &middle));
        let right_count =
            sign_variations(&sturm, &middle).saturating_sub(sign_variations(&sturm, &right));
        if left_count != 0 {
            pending.push((left, middle.clone()));
        }
        if right_count != 0 {
            pending.push((middle, right));
        }
    }
    roots.sort_unstable();
    roots.dedup();
    Ok(roots)
}

fn roots_recursive(
    polynomial: &Polynomial,
    control: &AttackControl,
) -> Result<Vec<Integer>, Error> {
    control.check_cancelled()?;
    let Some(degree) = polynomial.degree() else {
        return Ok(Vec::new());
    };
    if degree == 0 {
        return Ok(Vec::new());
    }
    if degree == 1 {
        let root = normalize_coefficient(&-polynomial.coeffs[0].clone(), &polynomial.modulus);
        return Ok(vec![root]);
    }
    if polynomial.modulus == 2 {
        return Ok((0..2)
            .map(Integer::from)
            .filter(|root| polynomial.eval(root) == 0)
            .collect());
    }

    let derivative = polynomial_derivative(polynomial);
    if derivative.degree().is_none() {
        let p = polynomial.modulus.to_usize().ok_or(Error::Unsupported)?;
        return roots_recursive(&polynomial_pth_root(polynomial, p)?, control);
    }
    let repeated = polynomial.gcd(&derivative)?;
    if repeated.degree() == polynomial.degree() {
        return roots_recursive(&derivative, control);
    }
    if repeated.degree().is_some_and(|degree| degree > 0) {
        let mut roots = roots_recursive(&repeated, control)?;
        roots.extend(roots_recursive(
            &polynomial_div_exact(polynomial, &repeated)?,
            control,
        )?);
        return Ok(roots);
    }

    let prime = polynomial.modulus.to_usize().ok_or(Error::Unsupported)?;
    let prime_u32 = polynomial.modulus.to_u32().ok_or(Error::Unsupported)?;
    let exponent = (prime_u32 - 1) / 2;
    let one = Polynomial::one(polynomial.modulus.clone());
    let mut saw_nonconstant_splitter = false;
    for splitter in berlekamp_basis(polynomial, control)? {
        if splitter.degree().unwrap_or(0) == 0 {
            continue;
        }
        saw_nonconstant_splitter = true;
        for shift in 0..prime.min(MAX_ROOT_SPLIT_ATTEMPTS) {
            control.check_cancelled()?;
            let shifted = splitter.add(&Polynomial::new(
                vec![Integer::from(shift)],
                polynomial.modulus.clone(),
            )?);
            let powered = polynomial_pow_mod(&shifted, exponent, polynomial, control)?;
            let factor = polynomial.gcd(&powered.sub(&one))?;
            if factor
                .degree()
                .is_some_and(|factor_degree| factor_degree > 0 && factor_degree < degree)
            {
                let mut roots = roots_recursive(&factor, control)?;
                roots.extend(roots_recursive(
                    &polynomial_div_exact(polynomial, &factor)?,
                    control,
                )?);
                return Ok(roots);
            }
        }
    }
    if !saw_nonconstant_splitter {
        // A square-free polynomial with a one-dimensional Berlekamp algebra is
        // irreducible over F_p, so it has no roots in the base field.
        return Ok(Vec::new());
    }
    Err(Error::Unsupported)
}

fn berlekamp_basis(
    polynomial: &Polynomial,
    control: &AttackControl,
) -> Result<Vec<Polynomial>, Error> {
    let dimension = polynomial.degree().ok_or(Error::Unsupported)?;
    let x = Polynomial::new(
        vec![Integer::ZERO, Integer::ONE.clone()],
        polynomial.modulus.clone(),
    )?;
    let mut matrix = vec![vec![Integer::ZERO; dimension]; dimension];
    let prime_u32 = polynomial.modulus.to_u32().ok_or(Error::Unsupported)?;
    let mut powers = Vec::with_capacity(dimension);
    for column in 0..dimension {
        let exponent = prime_u32
            .checked_mul(u32::try_from(column).map_err(|_| Error::Unsupported)?)
            .ok_or(Error::Unsupported)?;
        powers.push(polynomial_pow_mod(&x, exponent, polynomial, control)?);
    }
    for (row, matrix_row) in matrix.iter_mut().enumerate() {
        for (column, entry) in matrix_row.iter_mut().enumerate() {
            *entry = powers[column].coeffs.get(row).cloned().unwrap_or_default();
            if row == column {
                *entry -= 1;
            }
            *entry = normalize_coefficient(entry, &polynomial.modulus);
        }
    }

    let mut pivot_columns = Vec::new();
    let mut rank = 0;
    for column in 0..dimension {
        control.check_cancelled()?;
        let Some(pivot) = matrix[rank..]
            .iter()
            .position(|row| row[column] != 0)
            .map(|offset| rank + offset)
        else {
            continue;
        };
        matrix.swap(rank, pivot);
        let (above, below) = matrix.split_at_mut(rank);
        let (pivot_row, below) = below.split_first_mut().expect("ranked pivot row");
        let inverse = pivot_row[column]
            .invert_ref(&polynomial.modulus)
            .ok_or(Error::Unsupported)?
            .complete();
        for value in &mut *pivot_row {
            *value = normalize_coefficient(&(&*value * &inverse).complete(), &polynomial.modulus);
        }
        for values in above.iter_mut().chain(below.iter_mut()) {
            let factor = values[column].clone();
            if factor == 0 {
                continue;
            }
            for (value, pivot_value) in values.iter_mut().zip(pivot_row.iter()) {
                let difference = (&*value - &factor * pivot_value).complete();
                *value = normalize_coefficient(&difference, &polynomial.modulus);
            }
        }
        pivot_columns.push(column);
        rank += 1;
    }

    let mut basis = Vec::new();
    for free_column in 0..dimension {
        if pivot_columns.contains(&free_column) {
            continue;
        }
        let mut vector = vec![Integer::ZERO; dimension];
        vector[free_column] = Integer::ONE.clone();
        for (row, pivot_column) in pivot_columns.iter().enumerate() {
            vector[*pivot_column] =
                normalize_coefficient(&(-matrix[row][free_column].clone()), &polynomial.modulus);
        }
        basis.push(Polynomial::new(vector, polynomial.modulus.clone())?);
    }
    Ok(basis)
}

fn polynomial_derivative(polynomial: &Polynomial) -> Polynomial {
    let mut coeffs: Vec<_> = polynomial.coeffs[1..]
        .iter()
        .enumerate()
        .map(|(index, coefficient)| {
            normalize_coefficient(&(coefficient * (index + 1)).complete(), &polynomial.modulus)
        })
        .collect();
    if coeffs.is_empty() {
        coeffs.push(Integer::ZERO);
    }
    Polynomial::from_normalized(coeffs, polynomial.modulus.clone())
}

fn polynomial_pth_root(polynomial: &Polynomial, p: usize) -> Result<Polynomial, Error> {
    let mut coeffs = vec![Integer::ZERO; (polynomial.coeffs.len() - 1) / p + 1];
    for (degree, coefficient) in polynomial.coeffs.iter().enumerate() {
        if *coefficient != 0 {
            if degree % p != 0 {
                return Err(Error::Unsupported);
            }
            coeffs[degree / p] = coefficient.clone();
        }
    }
    Polynomial::new(coeffs, polynomial.modulus.clone())
}

fn polynomial_div_exact(dividend: &Polynomial, divisor: &Polynomial) -> Result<Polynomial, Error> {
    let divisor_degree = divisor.degree().ok_or(Error::Unsupported)?;
    let mut remainder = dividend.clone();
    let mut quotient = vec![Integer::ZERO; dividend.coeffs.len()];
    while remainder
        .degree()
        .is_some_and(|degree| degree >= divisor_degree)
    {
        let degree = remainder.degree().unwrap_or(0);
        let shift = degree - divisor_degree;
        let factor = normalize_coefficient(
            &(&remainder.coeffs[degree] * &divisor.coeffs[divisor_degree]).complete(),
            &dividend.modulus,
        );
        quotient[shift] = factor.clone();
        for (index, coefficient) in divisor.coeffs.iter().enumerate() {
            let difference = (&remainder.coeffs[index + shift] - &factor * coefficient).complete();
            remainder.coeffs[index + shift] = normalize_coefficient(&difference, &dividend.modulus);
        }
        remainder.trim();
    }
    if remainder.degree().is_some() {
        return Err(Error::Unsupported);
    }
    Polynomial::new(quotient, dividend.modulus.clone())
}

fn polynomial_pow_mod(
    base: &Polynomial,
    mut exponent: u32,
    modulus: &Polynomial,
    control: &AttackControl,
) -> Result<Polynomial, Error> {
    let mut result = Polynomial::one(modulus.modulus.clone());
    let mut power = base.clone().rem(modulus)?;
    while exponent != 0 {
        control.check_cancelled()?;
        if exponent & 1 != 0 {
            result = polynomial_mul_mod(&result, &power, modulus)?;
        }
        exponent >>= 1;
        if exponent != 0 {
            power = polynomial_mul_mod(&power, &power, modulus)?;
        }
    }
    Ok(result)
}

fn polynomial_mul_mod(
    left: &Polynomial,
    right: &Polynomial,
    modulus: &Polynomial,
) -> Result<Polynomial, Error> {
    left.check_same_modulus(right);
    left.check_same_modulus(modulus);
    let left_degree = left.degree().unwrap_or(0);
    let right_degree = right.degree().unwrap_or(0);
    let degree = left_degree
        .checked_add(right_degree)
        .ok_or(Error::Unsupported)?;
    let mut coefficients = vec![Integer::ZERO; degree + 1];
    for (left_index, left_coefficient) in left.coeffs.iter().enumerate() {
        for (right_index, right_coefficient) in right.coeffs.iter().enumerate() {
            let product = left_coefficient * right_coefficient;
            coefficients[left_index + right_index] =
                (&coefficients[left_index + right_index] + product).complete();
        }
    }
    for coefficient in &mut coefficients {
        *coefficient = normalize_coefficient(coefficient, &left.modulus);
    }
    // The unreduced product may exceed the shared degree limit. Polynomial::new
    // would reject it before the remainder can be reduced to a legal degree.
    let product = Polynomial::from_normalized(coefficients, left.modulus.clone());
    let reduced = product.rem(modulus)?;
    if reduced
        .degree()
        .is_some_and(|degree| degree > MAX_POLYNOMIAL_DEGREE)
    {
        return Err(Error::Unsupported);
    }
    Ok(reduced)
}

fn normalize_coefficient(value: &Integer, modulus: &Integer) -> Integer {
    let reduced = (value % modulus).complete();
    if reduced < 0 {
        reduced + modulus
    } else {
        reduced
    }
}

fn rational_floor(value: &Rational) -> Integer {
    value.numer().clone().div_floor(value.denom())
}

fn rational_ceil(value: &Rational) -> Integer {
    let negative_numerator = (-value.numer()).complete();
    -negative_numerator.div_floor(value.denom())
}

fn eval_integer(coeffs: &[Integer], x: &Integer) -> Integer {
    coeffs
        .iter()
        .rev()
        .fold(Integer::ZERO, |value, coefficient| value * x + coefficient)
}

fn rational_derivative(polynomial: &[Rational]) -> Vec<Rational> {
    if polynomial.len() <= 1 {
        return Vec::new();
    }
    polynomial[1..]
        .iter()
        .enumerate()
        .map(|(index, coefficient)| (coefficient * (index + 1)).complete())
        .collect()
}

fn rational_trim(polynomial: &mut Vec<Rational>) {
    while polynomial.last() == Some(Rational::ZERO) {
        polynomial.pop();
    }
}

fn rational_rem(
    mut dividend: Vec<Rational>,
    divisor: Vec<Rational>,
) -> Result<Vec<Rational>, Error> {
    rational_trim(&mut dividend);
    rational_trim(&mut divisor.clone());
    if divisor.is_empty() {
        return Err(Error::Unsupported);
    }
    let divisor_degree = divisor.len() - 1;
    let inverse = Rational::from(1) / divisor[divisor_degree].clone();
    while !dividend.is_empty() && dividend.len() >= divisor.len() {
        let shift = dividend.len() - divisor.len();
        let factor = dividend.last().expect("non-empty dividend").clone() * &inverse;
        for (index, coefficient) in divisor.iter().enumerate() {
            dividend[index + shift] -= (&factor * coefficient).complete();
        }
        rational_trim(&mut dividend);
    }
    Ok(dividend)
}

fn sign_variations(sturm: &[Vec<Rational>], x: &Rational) -> usize {
    let mut previous = 0;
    let mut variations = 0;
    for polynomial in sturm {
        let value = polynomial
            .iter()
            .rev()
            .fold(Rational::ZERO.clone(), |value, coefficient| {
                value * x + coefficient
            });
        let sign = if value > 0 {
            1
        } else if value < 0 {
            -1
        } else {
            0
        };
        if sign != 0 {
            if previous != 0 && previous != sign {
                variations += 1;
            }
            previous = sign;
        }
    }
    variations
}

/// A sparse integer polynomial in `u^a x^b y^c`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BivariatePolynomial {
    pub terms: BTreeMap<(u32, u32, u32), Integer>,
}

impl BivariatePolynomial {
    pub fn new(terms: BTreeMap<(u32, u32, u32), Integer>) -> Self {
        Self {
            terms: terms
                .into_iter()
                .filter(|(_, coefficient)| *coefficient != 0)
                .collect(),
        }
    }

    /// Apply the exact substitution `u = 1 + x*y`, so `(x*y)^r = (u-1)^r`.
    pub fn canonicalize(&self) -> Self {
        let mut result = BTreeMap::new();
        for (&(a, b, c), coefficient) in &self.terms {
            let repeated = b.min(c);
            let mut binomial = Integer::ONE.clone();
            for s in 0..=repeated {
                let sign = if (repeated - s) % 2 == 0 { 1 } else { -1 };
                let key = (a + s, b - repeated, c - repeated);
                let scaled = (coefficient * &binomial).complete() * sign;
                *result.entry(key).or_default() += scaled;
                if s < repeated {
                    binomial = (&binomial * (repeated - s)).complete() / (s + 1);
                }
            }
        }
        Self::new(result)
    }

    /// Raise to an integer power, rejecting results whose degree in any of
    /// `u`, `x`, or `y` would exceed the shared polynomial degree limit.
    pub fn pow(&self, exponent: u32) -> Self {
        assert!(
            self.max_degrees().iter().all(|degree| {
                u64::from(*degree) * u64::from(exponent) <= MAX_POLYNOMIAL_DEGREE as u64
            }),
            "bivariate polynomial degree limit exceeded"
        );
        let mut result = Self::new(BTreeMap::from([((0, 0, 0), Integer::ONE.clone())]));
        let mut base = self.clone();
        let mut exponent = exponent;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = result.mul(&base);
            }
            exponent >>= 1;
            if exponent != 0 {
                base = base.mul(&base);
            }
        }
        result
    }

    /// Eliminate `x` with a Sylvester determinant. The returned coefficients
    /// are polynomials in `y`, represented in ascending order. All `u`
    /// exponents must already be zero; otherwise the result cannot be
    /// represented by the return type and the operation is unsupported.
    pub fn resultant(&self, other: &Self, control: &AttackControl) -> Result<Vec<Integer>, Error> {
        control.check_cancelled()?;
        let max_x_degree = |terms: &BTreeMap<(u32, u32, u32), Integer>| {
            terms.keys().map(|key| key.1).max().unwrap_or(0)
        };
        if max_x_degree(&self.terms) as usize > MAX_POLYNOMIAL_DEGREE
            || max_x_degree(&other.terms) as usize > MAX_POLYNOMIAL_DEGREE
        {
            return Err(Error::Unsupported);
        }
        let left = x_coefficients(&self.terms);
        let right = x_coefficients(&other.terms);
        if self.terms.is_empty() || other.terms.is_empty() {
            return Ok(vec![Integer::ZERO]);
        }
        if self.terms.keys().any(|(u, _, _)| *u != 0) || other.terms.keys().any(|(u, _, _)| *u != 0)
        {
            return Err(Error::Unsupported);
        }
        let left_degree = left.len() - 1;
        let right_degree = right.len() - 1;
        let dimension = left_degree + right_degree;
        if dimension == 0 {
            return Ok(vec![Integer::ONE.clone()]);
        }
        let mut matrix = Vec::with_capacity(dimension);
        for shift in 0..right_degree {
            let mut row = vec![YPolynomial::new(); dimension];
            for (index, coefficient) in left.iter().rev().enumerate() {
                row[index + shift] = coefficient.clone();
            }
            matrix.push(row);
        }
        for shift in 0..left_degree {
            let mut row = vec![YPolynomial::new(); dimension];
            for (index, coefficient) in right.iter().rev().enumerate() {
                row[index + shift] = coefficient.clone();
            }
            matrix.push(row);
        }
        let determinant = bareiss(matrix, control)?;
        let Some(max_degree) = determinant.keys().next_back().copied() else {
            return Ok(vec![Integer::ZERO]);
        };
        let mut coefficients = vec![Integer::ZERO; max_degree as usize + 1];
        for (degree, coefficient) in determinant {
            coefficients[degree as usize] = coefficient;
        }
        Ok(coefficients)
    }

    fn max_degrees(&self) -> [u32; 3] {
        let mut degrees = [0; 3];
        for &(u, x, y) in self.terms.keys() {
            degrees[0] = degrees[0].max(u);
            degrees[1] = degrees[1].max(x);
            degrees[2] = degrees[2].max(y);
        }
        degrees
    }

    fn mul(&self, other: &Self) -> Self {
        assert!(
            self.max_degrees()
                .iter()
                .zip(other.max_degrees())
                .all(|(left, right)| {
                    u64::from(*left) + u64::from(right) <= MAX_POLYNOMIAL_DEGREE as u64
                }),
            "bivariate polynomial degree limit exceeded"
        );
        let mut terms = BTreeMap::new();
        for (&left, left_coefficient) in &self.terms {
            for (&right, right_coefficient) in &other.terms {
                let key = (
                    left.0
                        .checked_add(right.0)
                        .expect("bivariate u exponent overflow"),
                    left.1
                        .checked_add(right.1)
                        .expect("bivariate x exponent overflow"),
                    left.2
                        .checked_add(right.2)
                        .expect("bivariate y exponent overflow"),
                );
                *terms.entry(key).or_default() += left_coefficient * right_coefficient;
            }
        }
        Self::new(terms)
    }
}

type YPolynomial = BTreeMap<u32, Integer>;

fn x_coefficients(terms: &BTreeMap<(u32, u32, u32), Integer>) -> Vec<YPolynomial> {
    let degree = terms.keys().map(|key| key.1).max().unwrap_or(0);
    let mut coefficients = vec![YPolynomial::new(); degree as usize + 1];
    for (&(_, x_degree, y_degree), coefficient) in terms {
        coefficients[x_degree as usize].insert(y_degree, coefficient.clone());
    }
    coefficients
}

fn y_mul(left: &YPolynomial, right: &YPolynomial) -> YPolynomial {
    let mut result = YPolynomial::new();
    for (&left_degree, left_coefficient) in left {
        for (&right_degree, right_coefficient) in right {
            let degree = left_degree
                .checked_add(right_degree)
                .expect("resultant y exponent overflow");
            *result.entry(degree).or_default() += left_coefficient * right_coefficient;
        }
    }
    result.retain(|_, coefficient| *coefficient != 0);
    result
}

fn y_div_exact(dividend: &YPolynomial, divisor: &YPolynomial) -> YPolynomial {
    let mut remainder = dividend.clone();
    let mut quotient = YPolynomial::new();
    let divisor_degree = *divisor.keys().next_back().expect("non-zero Bareiss pivot");
    while !remainder.is_empty() {
        let degree = *remainder.keys().next_back().expect("non-empty remainder");
        if degree < divisor_degree {
            break;
        }
        let shift = degree - divisor_degree;
        let (leading, rest) = remainder[&degree]
            .clone()
            .div_rem(divisor[&divisor_degree].clone());
        assert!(rest == 0, "Bareiss leading coefficient must divide exactly");
        for (&divisor_degree, coefficient) in divisor {
            let target = divisor_degree + shift;
            *remainder.entry(target).or_default() -= &leading * coefficient;
        }
        remainder.retain(|_, coefficient| *coefficient != 0);
        if leading != 0 {
            quotient.insert(shift, leading);
        }
    }
    assert!(
        remainder.is_empty(),
        "Bareiss polynomial division must be exact"
    );
    quotient
}

fn bareiss(
    mut matrix: Vec<Vec<YPolynomial>>,
    control: &AttackControl,
) -> Result<YPolynomial, Error> {
    let dimension = matrix.len();
    let mut previous_pivot = YPolynomial::from([(0, Integer::ONE.clone())]);
    let mut sign = Integer::ONE.clone();
    let mut operations = 0usize;
    for pivot_index in 0..dimension - 1 {
        if matrix[pivot_index][pivot_index].is_empty() {
            let Some((replacement, _)) = matrix
                .iter()
                .enumerate()
                .skip(pivot_index + 1)
                .find(|(_, row)| !row[pivot_index].is_empty())
            else {
                return Ok(YPolynomial::new());
            };
            matrix.swap(pivot_index, replacement);
            sign = -sign;
        }
        let pivot = matrix[pivot_index][pivot_index].clone();
        let (pivot_row, lower_rows) = matrix[pivot_index..]
            .split_first_mut()
            .expect("non-empty Bareiss matrix");
        for row in lower_rows {
            let row_pivot = row[pivot_index].clone();
            let (_, row_columns) = row.split_at_mut(pivot_index + 1);
            let (_, pivot_columns) = pivot_row.split_at(pivot_index + 1);
            for (entry, pivot_entry) in row_columns.iter_mut().zip(pivot_columns) {
                if operations.is_multiple_of(CANCEL_CHECK_BATCH) {
                    control.check_cancelled()?;
                }
                operations += 1;
                let product = y_mul(entry, &pivot);
                let cross = y_mul(&row_pivot, pivot_entry);
                let mut numerator = product;
                for (degree, coefficient) in cross {
                    *numerator.entry(degree).or_default() -= coefficient;
                }
                numerator.retain(|_, coefficient| *coefficient != 0);
                *entry = if pivot_index == 0 {
                    numerator
                } else {
                    y_div_exact(&numerator, &previous_pivot)
                };
            }
        }
        previous_pivot = pivot;
    }
    let determinant = matrix[dimension - 1][dimension - 1].clone();
    Ok(determinant
        .into_iter()
        .map(|(degree, coefficient)| (degree, coefficient * &sign))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::{AttackControl, Error, MAX_POLYNOMIAL_DEGREE};
    use std::collections::BTreeMap;

    fn bivariate(terms: &[(u32, u32, u32, i32)]) -> BivariatePolynomial {
        BivariatePolynomial::new(
            terms
                .iter()
                .map(|&(a, b, c, coefficient)| ((a, b, c), coefficient.into()))
                .collect(),
        )
    }

    #[test]
    fn modular_polynomial_arithmetic_and_gcd() {
        let n = Integer::from(3233);
        let f = Polynomial::new(vec![7.into(), 0.into(), 1.into()], n.clone()).unwrap();
        let g = Polynomial::new(vec![7.into(), (-1).into()], n).unwrap();
        assert_eq!(f.gcd(&g).unwrap().coeffs, vec![Integer::from(1)]);
        assert_eq!(f.eval(&Integer::from(5)), Integer::from(32));
    }

    #[test]
    fn polynomial_mul_mod_reduces_max_degree_inputs_before_limit() {
        let mut modulus_coeffs = vec![Integer::from(0); MAX_POLYNOMIAL_DEGREE + 1];
        modulus_coeffs[0] = Integer::from(1);
        modulus_coeffs[MAX_POLYNOMIAL_DEGREE] = Integer::from(1);
        let modulus = Polynomial::new(modulus_coeffs, 101.into()).unwrap();

        let mut remainder_coeffs = vec![Integer::from(0); MAX_POLYNOMIAL_DEGREE];
        remainder_coeffs[MAX_POLYNOMIAL_DEGREE - 1] = Integer::from(1);
        let remainder = Polynomial::new(remainder_coeffs, 101.into()).unwrap();
        let reduced = polynomial_mul_mod(&remainder, &remainder, &modulus).unwrap();
        assert_eq!(reduced.degree(), Some(MAX_POLYNOMIAL_DEGREE - 2));
        assert_eq!(
            reduced.coeffs[MAX_POLYNOMIAL_DEGREE - 2],
            Integer::from(100)
        );
        assert!(reduced
            .coeffs
            .iter()
            .enumerate()
            .all(|(index, coefficient)| {
                index == MAX_POLYNOMIAL_DEGREE - 2 || *coefficient == 0
            }));

        let mut max_coeffs = vec![Integer::from(0); MAX_POLYNOMIAL_DEGREE + 1];
        max_coeffs[MAX_POLYNOMIAL_DEGREE] = Integer::from(1);
        let max_degree = Polynomial::new(max_coeffs, 101.into()).unwrap();
        assert_eq!(
            polynomial_mul_mod(&max_degree, &max_degree, &modulus)
                .unwrap()
                .coeffs,
            vec![Integer::from(1)]
        );
    }

    #[test]
    fn modular_polynomial_add_sub_mul_pow_and_rem() {
        let f = Polynomial::new(vec![1.into(), 2.into(), 1.into()], 101.into()).unwrap();
        let g = Polynomial::new(vec![1.into(), 1.into()], 101.into()).unwrap();
        assert_eq!(
            f.add(&g).coeffs,
            vec![Integer::from(2), Integer::from(3), Integer::from(1)]
        );
        assert_eq!(
            f.sub(&g).coeffs,
            vec![Integer::from(0), Integer::from(1), Integer::from(1)]
        );
        assert_eq!(
            f.mul(&g).coeffs,
            vec![
                Integer::from(1),
                Integer::from(3),
                Integer::from(3),
                Integer::from(1)
            ]
        );
        assert_eq!(
            f.pow(2).coeffs,
            vec![
                Integer::from(1),
                Integer::from(4),
                Integer::from(6),
                Integer::from(4),
                Integer::from(1)
            ]
        );
        assert_eq!(f.rem(&g).unwrap().degree(), None);
    }

    #[test]
    fn finite_field_roots_handle_repeated_and_inseparable_roots() {
        let control = AttackControl::default();
        // (x-3)^2(x+2) over F_11.
        let f = Polynomial::new(vec![7.into(), 8.into(), 7.into(), 1.into()], 11.into()).unwrap();
        assert_eq!(
            f.roots(&control).unwrap(),
            vec![Integer::from(3), Integer::from(9)]
        );
        // x^7 - 2 = (x-2)^7 in characteristic 7.
        let inseparable = Polynomial::new(
            vec![
                5.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                1.into(),
            ],
            7.into(),
        )
        .unwrap();
        assert_eq!(inseparable.roots(&control).unwrap(), vec![Integer::from(2)]);
    }

    #[test]
    fn finite_field_roots_find_known_root_in_mixed_degree_polynomial() {
        let control = AttackControl::default();
        // This quartic has 83 as a root over F_1783.
        let f = Polynomial::new(
            vec![1339.into(), 494.into(), 77.into(), 651.into(), 1679.into()],
            1783.into(),
        )
        .unwrap();
        assert_eq!(f.roots(&control).unwrap(), vec![Integer::from(83)]);
    }

    #[test]
    fn finite_field_roots_split_quadratic_with_large_residue_roots() {
        let control = AttackControl::default();
        // Both roots exceed the first 256 constant shifts: (x-1070)(x-1210).
        let f = Polynomial::new(vec![242.into(), 1286.into(), 1.into()], 1783.into()).unwrap();
        assert_eq!(
            f.roots(&control).unwrap(),
            vec![Integer::from(1070), Integer::from(1210)]
        );
    }

    #[test]
    fn finite_field_roots_return_empty_for_irreducible_polynomial() {
        let control = AttackControl::default();
        // x^2 + 1 has no root over F_7 because -1 is not a quadratic residue.
        let f = Polynomial::new(vec![1.into(), 0.into(), 1.into()], 7.into()).unwrap();
        assert!(f.roots(&control).unwrap().is_empty());
    }

    #[test]
    fn finite_field_roots_validate_field_and_honor_control() {
        let control = AttackControl::new(0);
        let linear = Polynomial::new(vec![1.into(), 1.into()], 7.into()).unwrap();
        assert_eq!(linear.roots(&control).unwrap(), vec![Integer::from(6)]);
        assert_eq!(control.remaining(), 0);
        assert_eq!(
            Polynomial::new(vec![1.into(), 1.into()], 9.into())
                .unwrap()
                .roots(&control)
                .unwrap_err(),
            Error::Unsupported
        );
        assert_eq!(
            Polynomial::zero(7.into()).roots(&control).unwrap_err(),
            Error::Unsupported
        );
        control.cancel();
        assert_eq!(linear.roots(&control), Err(Error::Cancelled));
        assert_eq!(control.remaining(), 0);
    }

    #[test]
    fn affine_power_matches_direct_expansion() {
        let f = Polynomial::from_affine_power(&2.into(), &3.into(), 3, &17.into(), 101.into());
        assert_eq!(f.eval(&4.into()), Integer::from(1));
        assert_eq!(
            f.coeffs,
            vec![
                Integer::from(10),
                Integer::from(54),
                Integer::from(36),
                Integer::from(8)
            ]
        );
    }

    #[test]
    fn non_invertible_leading_coefficient_is_unsupported() {
        let f = Polynomial::new(vec![1.into(), 61.into()], 3233.into()).unwrap();
        assert_eq!(f.monic().unwrap_err(), Error::Unsupported);
        let divisor = Polynomial::new(vec![1.into(), 61.into()], 3233.into()).unwrap();
        assert_eq!(f.rem(&divisor).unwrap_err(), Error::Unsupported);
    }

    #[test]
    fn integer_roots_are_exact_and_bounded() {
        let control = AttackControl::default();
        // (x-3)(x+2)(x-9) = x^3 - 10x^2 + 3x + 54
        let roots = integer_roots(
            &[54.into(), 3.into(), (-10).into(), 1.into()],
            &10.into(),
            &control,
        )
        .unwrap();
        assert_eq!(
            roots,
            vec![Integer::from(-2), Integer::from(3), Integer::from(9)]
        );
    }

    #[test]
    fn constructor_normalizes_coefficients_and_trims_high_zeroes() {
        let f = Polynomial::new(vec![(-1).into(), 102.into(), 0.into()], 101.into()).unwrap();
        assert_eq!(f.coeffs, vec![Integer::from(100), Integer::from(1)]);
        assert_eq!(f.modulus, Integer::from(101));
        assert_eq!(f.degree(), Some(1));
        assert_eq!(Polynomial::zero(101.into()).degree(), None);
        assert_eq!(
            Polynomial::one(101.into()).eval(&7.into()),
            Integer::from(1)
        );
    }

    #[test]
    fn constructor_rejects_invalid_modulus_empty_and_excessive_degree() {
        for modulus in [0.into(), 1.into(), (-2).into()] {
            assert_eq!(
                Polynomial::new(vec![1.into()], modulus).unwrap_err(),
                Error::Unsupported
            );
        }
        assert_eq!(
            Polynomial::new(vec![], 101.into()).unwrap_err(),
            Error::Unsupported
        );
        let excessive = vec![Integer::from(0); MAX_POLYNOMIAL_DEGREE + 2];
        assert_eq!(
            Polynomial::new(excessive, 101.into()).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    #[should_panic(expected = "polynomial degree limit")]
    fn multiplication_rejects_excessive_degree() {
        let mut coeffs = vec![Integer::from(0); MAX_POLYNOMIAL_DEGREE + 1];
        coeffs[MAX_POLYNOMIAL_DEGREE] = Integer::from(1);
        let high = Polynomial::new(coeffs, 101.into()).unwrap();
        let _ = high.mul(&high);
    }

    #[test]
    #[should_panic(expected = "polynomial degree limit")]
    fn exponentiation_rejects_excessive_degree() {
        let f = Polynomial::new(vec![0.into(), 1.into()], 101.into()).unwrap();
        let _ = f.pow(MAX_POLYNOMIAL_DEGREE as u32 + 1);
    }

    #[test]
    #[should_panic(expected = "polynomial degree limit")]
    fn affine_power_rejects_excessive_exponent() {
        let _ = Polynomial::from_affine_power(&1.into(), &1.into(), 258, &0.into(), 101.into());
    }

    #[test]
    fn division_by_constant_and_zero_divisor_have_defined_errors() {
        let f = Polynomial::new(vec![3.into(), 4.into()], 101.into()).unwrap();
        let constant = Polynomial::new(vec![2.into()], 101.into()).unwrap();
        assert_eq!(f.rem(&constant).unwrap().degree(), None);
        let composite = Polynomial::new(vec![3.into(), 4.into()], 3233.into()).unwrap();
        let non_invertible_constant = Polynomial::new(vec![61.into()], 3233.into()).unwrap();
        assert_eq!(
            composite.rem(&non_invertible_constant).unwrap_err(),
            Error::Unsupported
        );
        assert_eq!(
            f.rem(&Polynomial::zero(101.into())).unwrap_err(),
            Error::Unsupported
        );
        assert_eq!(
            Polynomial::zero(101.into()).gcd(&f).unwrap().coeffs,
            vec![Integer::from(26), Integer::from(1)]
        );
        assert_eq!(
            Polynomial::zero(101.into())
                .gcd(&Polynomial::zero(101.into()))
                .unwrap()
                .degree(),
            None
        );
    }

    #[test]
    fn integer_roots_include_midpoint_repeated_and_zero_roots_once() {
        // x(x-1)^2(x+2) = x^4 - 3x^2 + 2x
        let roots = integer_roots(
            &[0.into(), 2.into(), (-3).into(), 0.into(), 1.into()],
            &3.into(),
            &AttackControl::default(),
        )
        .unwrap();
        assert_eq!(
            roots,
            vec![Integer::from(-2), Integer::from(0), Integer::from(1)]
        );
    }

    #[test]
    fn integer_roots_handle_constants_trimming_negative_bounds_and_cancellation() {
        let control = AttackControl::default();
        assert!(integer_roots(&[7.into(), 0.into()], &10.into(), &control)
            .unwrap()
            .is_empty());
        assert!(
            integer_roots(&[0.into(), 0.into(), 1.into()], &(-1).into(), &control)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            integer_roots(&[], &10.into(), &control).unwrap_err(),
            Error::Unsupported
        );
        assert_eq!(
            integer_roots(&[0.into()], &10.into(), &control).unwrap_err(),
            Error::Unsupported
        );
        control.cancel();
        assert_eq!(
            integer_roots(&[(-1).into(), 0.into(), 1.into()], &10.into(), &control),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn integer_roots_reject_excessive_degree() {
        let coeffs = vec![Integer::from(0); MAX_POLYNOMIAL_DEGREE + 2];
        assert_eq!(
            integer_roots(&coeffs, &10.into(), &AttackControl::default()).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn bivariate_power_and_canonicalization_expand_binomial_exactly() {
        let f = bivariate(&[(0, 1, 0, 1), (0, 0, 1, 1)]);
        let expected = BTreeMap::from([
            ((0, 2, 0), Integer::from(1)),
            ((0, 1, 1), Integer::from(2)),
            ((0, 0, 2), Integer::from(1)),
        ]);
        assert_eq!(f.pow(2).terms, expected);
        assert_eq!(
            bivariate(&[(0, 1, 1, 1)]).canonicalize().terms,
            BTreeMap::from([
                ((0, 0, 0), Integer::from(-1)),
                ((1, 0, 0), Integer::from(1))
            ])
        );
        assert_eq!(
            bivariate(&[(2, 3, 2, 1)]).canonicalize().terms,
            BTreeMap::from([
                ((2, 1, 0), Integer::from(1)),
                ((3, 1, 0), Integer::from(-2)),
                ((4, 1, 0), Integer::from(1)),
            ])
        );
        assert_eq!(
            bivariate(&[(0, 3, 3, 1)]).canonicalize().terms,
            BTreeMap::from([
                ((0, 0, 0), Integer::from(-1)),
                ((1, 0, 0), Integer::from(3)),
                ((2, 0, 0), Integer::from(-3)),
                ((3, 0, 0), Integer::from(1)),
            ])
        );
    }

    #[test]
    #[should_panic(expected = "bivariate polynomial degree limit exceeded")]
    fn bivariate_power_rejects_excessive_x_degree() {
        let f = bivariate(&[(0, 1, 0, 1)]);
        let _ = f.pow(MAX_POLYNOMIAL_DEGREE as u32 + 1);
    }

    #[test]
    #[should_panic(expected = "bivariate polynomial degree limit exceeded")]
    fn bivariate_power_rejects_excessive_y_degree() {
        let f = bivariate(&[(0, 0, 1, 1)]);
        let _ = f.pow(MAX_POLYNOMIAL_DEGREE as u32 + 1);
    }

    #[test]
    #[should_panic(expected = "bivariate polynomial degree limit exceeded")]
    fn bivariate_power_rejects_excessive_u_degree() {
        let f = bivariate(&[(1, 0, 0, 1)]);
        let _ = f.pow(MAX_POLYNOMIAL_DEGREE as u32 + 1);
    }

    #[test]
    #[should_panic(expected = "bivariate polynomial degree limit exceeded")]
    fn bivariate_multiplication_rejects_excessive_x_degree() {
        let high = bivariate(&[(0, MAX_POLYNOMIAL_DEGREE as u32, 0, 1)]);
        let _ = high.mul(&high);
    }

    #[test]
    #[should_panic(expected = "bivariate polynomial degree limit exceeded")]
    fn bivariate_multiplication_rejects_excessive_y_degree() {
        let high = bivariate(&[(0, 0, MAX_POLYNOMIAL_DEGREE as u32, 1)]);
        let _ = high.mul(&high);
    }

    #[test]
    #[should_panic(expected = "bivariate polynomial degree limit exceeded")]
    fn bivariate_multiplication_rejects_excessive_u_degree() {
        let high = bivariate(&[(MAX_POLYNOMIAL_DEGREE as u32, 0, 0, 1)]);
        let _ = high.mul(&high);
    }

    #[test]
    fn bivariate_constructor_drops_zero_terms() {
        assert_eq!(bivariate(&[(1, 2, 3, 0)]).terms, BTreeMap::new());
    }

    #[test]
    fn resultant_eliminates_x_and_returns_ascending_y_coefficients() {
        let control = AttackControl::default();
        let f = bivariate(&[(0, 1, 0, 1), (0, 0, 1, 1)]);
        let g = bivariate(&[(0, 1, 0, 1), (0, 0, 1, -1)]);
        assert_eq!(
            f.resultant(&g, &control).unwrap(),
            vec![Integer::from(0), Integer::from(-2)]
        );

        let f = bivariate(&[(0, 2, 0, 1), (0, 0, 1, 1)]);
        let g = bivariate(&[(0, 1, 0, 1), (0, 0, 2, 1)]);
        assert_eq!(
            f.resultant(&g, &control).unwrap(),
            vec![
                Integer::from(0),
                Integer::from(1),
                Integer::from(0),
                Integer::from(0),
                Integer::from(1)
            ]
        );
    }

    #[test]
    fn resultant_divides_by_non_monic_polynomial_pivots() {
        let control = AttackControl::default();
        let f = bivariate(&[
            (0, 2, 0, 2),
            (0, 2, 1, 2),
            (0, 1, 0, 1),
            (0, 1, 1, 1),
            (0, 0, 0, 1),
            (0, 0, 1, 1),
        ]);
        let g = bivariate(&[(0, 1, 0, 1), (0, 0, 0, 1)]);
        assert_eq!(
            f.resultant(&g, &control).unwrap(),
            vec![Integer::from(2), Integer::from(2)]
        );
    }

    #[test]
    fn resultant_handles_zero_and_constant_polynomials() {
        let control = AttackControl::default();
        let zero = bivariate(&[]);
        let x = bivariate(&[(0, 1, 0, 1)]);
        let constant = bivariate(&[(0, 0, 0, 2)]);
        assert_eq!(
            zero.resultant(&x, &control).unwrap(),
            vec![Integer::from(0)]
        );
        assert_eq!(
            constant.resultant(&constant, &control).unwrap(),
            vec![Integer::from(1)]
        );
        assert_eq!(
            constant.resultant(&x, &control).unwrap(),
            vec![Integer::from(2)]
        );
    }

    #[test]
    fn resultant_returns_zero_for_polynomials_with_common_roots() {
        let f = bivariate(&[(0, 2, 0, 1), (0, 0, 0, -1)]);
        assert_eq!(
            f.resultant(&f, &AttackControl::default()).unwrap(),
            vec![Integer::from(0)]
        );
    }

    #[test]
    fn resultant_rejects_uneliminated_u_terms() {
        let f = bivariate(&[(1, 1, 0, 1), (0, 0, 0, 1)]);
        let g = bivariate(&[(0, 1, 0, 1)]);
        assert_eq!(
            f.resultant(&g, &AttackControl::default()).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn resultant_checks_cancellation_and_x_degree_limit() {
        let control = AttackControl::default();
        control.cancel();
        assert_eq!(
            bivariate(&[]).resultant(&bivariate(&[]), &control),
            Err(Error::Cancelled)
        );
        let excessive = bivariate(&[(0, MAX_POLYNOMIAL_DEGREE as u32 + 1, 0, 1)]);
        assert_eq!(
            excessive
                .resultant(&bivariate(&[]), &AttackControl::default())
                .unwrap_err(),
            Error::Unsupported
        );
    }
}
