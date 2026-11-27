//! Exact rational Gram–Schmidt orthogonalization and LLL reduction.

use rug::{Complete, Integer, Rational};

use crate::attack::{
    AttackControl, Error, CANCEL_CHECK_BATCH, MAX_LLL_DIMENSION, MAX_LLL_ITERATIONS,
};

/// Compute the exact Gram–Schmidt coefficients and squared norms of a
/// full-row-rank row basis.
pub fn gram_schmidt(basis: &[Vec<Integer>]) -> Result<(Vec<Vec<Rational>>, Vec<Rational>), Error> {
    validate_basis_shape(basis)?;
    let dimension = basis.len();
    let mut mu = vec![vec![Rational::ZERO.clone(); dimension]; dimension];
    let mut norms: Vec<Rational> = Vec::with_capacity(dimension);
    let mut orthogonal: Vec<Vec<Rational>> = Vec::with_capacity(dimension);
    for (i, row) in basis.iter().enumerate() {
        let mut current: Vec<Rational> = row.iter().cloned().map(Rational::from).collect();
        for j in 0..i {
            let dot = current
                .iter()
                .zip(&orthogonal[j])
                .map(|(left, right): (&Rational, &Rational)| left.clone() * right.clone())
                .sum::<Rational>();
            mu[i][j] = dot / norms[j].clone();
            for (coordinate, projection) in current.iter_mut().zip(&orthogonal[j]) {
                *coordinate -= mu[i][j].clone() * projection.clone();
            }
        }
        let norm = current
            .iter()
            .map(|coordinate| coordinate.clone() * coordinate.clone())
            .sum::<Rational>();
        if &norm == Rational::ZERO {
            return Err(Error::Unsupported);
        }
        orthogonal.push(current);
        norms.push(norm);
    }
    Ok((mu, norms))
}

/// LLL-reduce a full-row-rank integer basis with exact `delta = 3/4`.
/// Rectangular bases are supported when they have at least as many columns as
/// independent rows. Row operations are integer additions, negations and swaps only.
pub fn lll(basis: &[Vec<Integer>], control: &AttackControl) -> Result<Vec<Vec<Integer>>, Error> {
    validate_basis_shape(basis)?;
    control.check_cancelled()?;
    let mut reduced = basis.to_vec();
    let (mut mu, mut norms) = gram_schmidt(&reduced)?;
    let delta = Rational::from(3) / Rational::from(4);
    let mut k = 1;
    let mut iterations = 0usize;
    while k < reduced.len() {
        if iterations.is_multiple_of(CANCEL_CHECK_BATCH) {
            control.check_cancelled()?;
        }
        if iterations >= MAX_LLL_ITERATIONS {
            return Err(Error::Unsupported);
        }
        iterations += 1;
        for j in (0..k).rev() {
            let quotient = nearest_integer(&mu[k][j]);
            if quotient != 0 {
                for coordinate in 0..reduced[0].len() {
                    let source = reduced[j][coordinate].clone();
                    reduced[k][coordinate] =
                        (&reduced[k][coordinate] - &quotient * &source).complete();
                }
                // b_k <- b_k - q*b_j leaves b_k^* unchanged. Update only
                // its Gram--Schmidt coordinates instead of recomputing the
                // entire exact orthogonalization.
                for index in 0..j {
                    let projection = (&quotient * &mu[j][index]).complete();
                    mu[k][index] -= projection;
                }
                mu[k][j] -= quotient;
            }
        }
        let square = mu[k][k - 1].clone() * mu[k][k - 1].clone();
        let lovasz_rhs = (delta.clone() - square) * norms[k - 1].clone();
        if norms[k] >= lovasz_rhs {
            k += 1;
        } else {
            reduced.swap(k, k - 1);
            update_after_swap(&mut mu, &mut norms, k);
            k = k.saturating_sub(1).max(1);
        }
    }
    Ok(reduced)
}

/// Update exact Gram--Schmidt data after swapping adjacent rows `k-1` and
/// `k`. Orthogonal components of later rows are unchanged because they are
/// orthogonal to both swapped vectors.
fn update_after_swap(mu: &mut [Vec<Rational>], norms: &mut [Rational], k: usize) {
    let coupling = mu[k][k - 1].clone();
    let previous_norm = norms[k - 1].clone();
    let current_norm = norms[k].clone();
    let coupling_squared = coupling.clone() * coupling.clone();
    let new_previous_norm = current_norm.clone() + coupling_squared * previous_norm.clone();
    let alpha = coupling.clone() * previous_norm.clone() / new_previous_norm.clone();
    let one_minus_coupling_alpha: Rational = 1 - coupling.clone() * alpha.clone();
    let new_current_norm = previous_norm * current_norm / new_previous_norm.clone();

    let old_previous_lower = mu[k - 1][..k - 1].to_vec();
    let old_current_lower = mu[k][..k - 1].to_vec();

    for mu_row in mu.iter_mut().skip(k + 1) {
        let old_previous = mu_row[k - 1].clone();
        let old_current = mu_row[k].clone();
        mu_row[k - 1] = old_current.clone() * one_minus_coupling_alpha.clone()
            + old_previous.clone() * alpha.clone();
        mu_row[k] = old_previous - coupling.clone() * old_current;
    }

    let (previous_row, current_rows) = mu[k - 1..=k]
        .split_first_mut()
        .expect("two adjacent Gram--Schmidt rows");
    previous_row[..k - 1].clone_from_slice(&old_current_lower);
    current_rows[0][..k - 1].clone_from_slice(&old_previous_lower);
    mu[k - 1][k - 1] = Rational::ZERO.clone();
    mu[k][k - 1] = alpha;
    norms[k - 1] = new_previous_norm;
    norms[k] = new_current_norm;
}

fn validate_basis_shape(basis: &[Vec<Integer>]) -> Result<(), Error> {
    if basis.is_empty()
        || basis[0].len() > MAX_LLL_DIMENSION
        || basis.len() > basis[0].len()
        || basis.iter().any(|row| row.len() != basis[0].len())
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// Round to the nearest integer, resolving exact halves away from zero.
fn nearest_integer(value: &Rational) -> Integer {
    let numerator = value.numer().clone().abs();
    let denominator = value.denom().clone().abs();
    let mut rounded = (&numerator / &denominator).complete();
    if ((&numerator % &denominator).complete() * 2) >= denominator {
        rounded += 1;
    }
    if value < Rational::ZERO {
        -rounded
    } else {
        rounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::{AttackControl, Error, MAX_LLL_DIMENSION};

    fn rational(numerator: i32, denominator: i32) -> Rational {
        Rational::from(numerator) / Rational::from(denominator)
    }

    #[test]
    fn lll_reduces_known_basis() {
        let control = AttackControl::default();
        let basis = [vec![1.into(), 0.into()], vec![100.into(), 1.into()]];
        let (mu, norms) = gram_schmidt(&basis).unwrap();
        assert_eq!(mu[1][0], rug::Rational::from(100));
        assert_eq!(norms, vec![rug::Rational::from(1), rug::Rational::from(1)]);
        let reduced = lll(&basis, &control).unwrap();
        assert_eq!(
            reduced,
            vec![
                vec![Integer::from(1), Integer::from(0)],
                vec![Integer::from(0), Integer::from(1)]
            ]
        );
    }

    #[test]
    fn gram_schmidt_is_exact_for_non_orthogonal_basis() {
        let (mu, norms) =
            gram_schmidt(&[vec![2.into(), 1.into()], vec![1.into(), 3.into()]]).unwrap();
        assert_eq!(
            mu,
            vec![
                vec![Rational::from(0), Rational::from(0)],
                vec![Rational::from(1), Rational::from(0)]
            ]
        );
        assert_eq!(norms, vec![Rational::from(5), Rational::from(5)]);
    }

    #[test]
    fn lll_uses_deterministic_size_reduction() {
        let basis = [vec![4.into(), 1.into()], vec![2.into(), 2.into()]];
        assert_eq!(
            lll(&basis, &AttackControl::default()).unwrap(),
            vec![
                vec![Integer::from(-2), Integer::from(1)],
                vec![Integer::from(2), Integer::from(2)]
            ]
        );
    }

    #[test]
    fn nearest_integer_rounds_half_values_away_from_zero() {
        for (numerator, denominator, expected) in [
            (0, 1, 0),
            (1, 2, 1),
            (-1, 2, -1),
            (3, 2, 2),
            (-3, 2, -2),
            (49, 20, 2),
            (-49, 20, -2),
        ] {
            assert_eq!(
                nearest_integer(&rational(numerator, denominator)),
                Integer::from(expected)
            );
        }
    }

    #[test]
    fn lll_rejects_dimension_above_limit() {
        let basis = vec![vec![Integer::from(0); MAX_LLL_DIMENSION + 1]; MAX_LLL_DIMENSION + 1];
        assert_eq!(
            lll(&basis, &AttackControl::default()).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn lll_rejects_empty_ragged_and_dependent_bases() {
        let control = AttackControl::default();
        assert_eq!(lll(&[], &control).unwrap_err(), Error::Unsupported);
        assert_eq!(
            lll(&[vec![1.into(), 0.into()], vec![1.into()]], &control).unwrap_err(),
            Error::Unsupported
        );
        assert_eq!(
            lll(
                &[vec![1.into(), 2.into()], vec![2.into(), 4.into()]],
                &control
            )
            .unwrap_err(),
            Error::Unsupported
        );
        assert_eq!(gram_schmidt(&[]).unwrap_err(), Error::Unsupported);
        assert_eq!(
            gram_schmidt(&[vec![1.into(), 2.into()], vec![2.into(), 4.into()]]).unwrap_err(),
            Error::Unsupported
        );
    }

    fn lll_by_recomputation(basis: &[Vec<Integer>]) -> Vec<Vec<Integer>> {
        let mut reduced = basis.to_vec();
        let (mut mu, mut norms) = gram_schmidt(&reduced).unwrap();
        let delta = Rational::from(3) / Rational::from(4);
        let mut k = 1;
        while k < reduced.len() {
            for j in (0..k).rev() {
                let quotient = nearest_integer(&mu[k][j]);
                if quotient != 0 {
                    for coordinate in 0..reduced[0].len() {
                        let source = reduced[j][coordinate].clone();
                        reduced[k][coordinate] =
                            (&reduced[k][coordinate] - &quotient * &source).complete();
                    }
                    (mu, norms) = gram_schmidt(&reduced).unwrap();
                }
            }
            let square = mu[k][k - 1].clone() * mu[k][k - 1].clone();
            let lovasz_rhs = (delta.clone() - square) * norms[k - 1].clone();
            if norms[k] >= lovasz_rhs {
                k += 1;
            } else {
                reduced.swap(k, k - 1);
                (mu, norms) = gram_schmidt(&reduced).unwrap();
                k = k.saturating_sub(1).max(1);
            }
        }
        reduced
    }

    #[test]
    fn incremental_lll_matches_full_recomputation() {
        let bases = [
            vec![vec![4.into(), 1.into()], vec![2.into(), 2.into()]],
            vec![
                vec![101.into(), 37.into(), 11.into()],
                vec![53.into(), 89.into(), 7.into()],
                vec![17.into(), 5.into(), 61.into()],
            ],
            vec![
                vec![1009.into(), 37.into(), 11.into(), 3.into()],
                vec![53.into(), 899.into(), 7.into(), 13.into()],
                vec![17.into(), 5.into(), 611.into(), 19.into()],
                vec![29.into(), 101.into(), 43.into(), 709.into()],
            ],
        ];
        for basis in bases {
            assert_eq!(
                lll(&basis, &AttackControl::default()).unwrap(),
                lll_by_recomputation(&basis)
            );
        }
    }

    #[test]
    fn incremental_rectangular_lll_matches_full_recomputation() {
        let basis = [
            vec![101.into(), 37.into(), 11.into(), 3.into(), 7.into()],
            vec![53.into(), 89.into(), 7.into(), 13.into(), 2.into()],
            vec![17.into(), 5.into(), 61.into(), 19.into(), 4.into()],
        ];
        assert_eq!(
            lll(&basis, &AttackControl::default()).unwrap(),
            lll_by_recomputation(&basis)
        );
    }

    #[test]
    fn lll_reduces_independent_rectangular_rows() {
        let basis = [
            vec![2.into(), 0.into(), 0.into()],
            vec![0.into(), 3.into(), 0.into()],
        ];
        let reduced = lll(&basis, &AttackControl::default()).unwrap();
        assert_eq!(reduced, basis);
        assert_eq!(gram_schmidt(&basis).unwrap().1.len(), basis.len());
    }

    #[test]
    fn lll_size_reduction_updates_every_rectangular_column() {
        let basis = [
            vec![2.into(), 0.into(), 0.into(), 0.into(), 1.into()],
            vec![2.into(), 1.into(), 1.into(), 0.into(), 3.into()],
        ];
        let expected: Vec<Vec<Integer>> = vec![
            vec![2.into(), 0.into(), 0.into(), 0.into(), 1.into()],
            vec![0.into(), 1.into(), 1.into(), 0.into(), 2.into()],
        ];
        assert_eq!(lll(&basis, &AttackControl::default()).unwrap(), expected);
        assert_eq!(lll_by_recomputation(&basis), expected);
    }

    #[test]
    fn lll_honors_pre_cancelled_control() {
        let control = AttackControl::default();
        control.cancel();
        assert_eq!(lll(&[vec![1.into()]], &control), Err(Error::Cancelled));
    }

    #[test]
    fn lll_preserves_determinant_for_integer_basis() {
        // det([[4, 1], [2, 2]]) = 6; LLL uses only unimodular row operations.
        let basis = [vec![4.into(), 1.into()], vec![2.into(), 2.into()]];
        let reduced = lll(&basis, &AttackControl::default()).unwrap();
        let positive = &reduced[0][0] * &reduced[1][1];
        let negative = &reduced[0][1] * &reduced[1][0];
        let determinant: Integer = positive.complete() - negative.complete();
        assert_eq!(determinant.abs(), Integer::from(6));
    }
}
