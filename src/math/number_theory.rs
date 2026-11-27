//! Mathematical utilities for number theory and related algorithms.

use rug::{
    ops::{DivRounding, Pow},
    Integer,
};

/// Return the floor of the real square root, or zero for negative inputs.
pub fn integer_sqrt(n: &Integer) -> Integer {
    if *n < 0 {
        return Integer::ZERO;
    }
    n.clone().sqrt_rem(Integer::new()).0
}

/// Return `Some(root)` exactly when `n` is a non-negative perfect square.
pub fn is_perfect_square(n: &Integer) -> Option<Integer> {
    if *n < 0 {
        return None;
    }
    let (root, remainder) = n.clone().sqrt_rem(Integer::new());
    (remainder == 0).then_some(root)
}

/// Return the floor of the non-negative integer `degree`-th root.
///
/// Negative inputs and degree zero return zero. The binary search and its
/// power-of-two upper bound use integer arithmetic exclusively.
pub fn integer_nth_root(n: &Integer, degree: u32) -> Integer {
    if *n <= 0 || degree == 0 {
        return Integer::ZERO;
    }
    if degree == 1 {
        return n.clone();
    }
    let bits = n.significant_bits();
    let shift = ((u64::from(bits) + u64::from(degree) - 1) / u64::from(degree)) as usize;
    let mut high = Integer::from(1) << shift;
    let mut low = Integer::ONE.clone();
    while low <= high {
        let mid: Integer = Integer::from(&low + &high) >> 1;
        if mid.clone().pow(degree) <= *n {
            low = Integer::from(&mid + 1);
        } else {
            high = Integer::from(&mid - 1);
        }
    }
    high
}

pub fn rational_to_contfrac(x: &Integer, y: &Integer) -> Vec<Integer> {
    let a = x.clone().div_floor(y);

    if a.clone() * y == *x {
        vec![a]
    } else {
        let mut pquotients = rational_to_contfrac(y, &(x - a.clone() * y));
        pquotients.insert(0, a);
        pquotients
    }
}

pub fn contfrac_to_rational(frac: &[Integer]) -> (Integer, Integer) {
    if frac.is_empty() {
        (0.into(), 1.into())
    } else if frac.len() == 1 {
        (frac[0].clone(), 1.into())
    } else {
        let (num, denom) = contfrac_to_rational(&frac[1..]);
        (frac[0].clone() * num.clone() + denom, num)
    }
}

#[allow(dead_code)]
pub fn convergents_from_contfrac(frac: &[Integer]) -> Vec<(Integer, Integer)> {
    (0..=frac.len())
        .map(|i| contfrac_to_rational(&frac[0..i]))
        .collect()
}

pub fn trivial_factorization_with_n_phi(n: &Integer, phi: &Integer) -> Option<(Integer, Integer)> {
    let m = n.clone() - phi.clone() + Integer::from(1);
    let m2n2 = m.clone().pow(2) - Integer::from(n << 2);

    if m2n2 > 0 {
        let (i, _) = m2n2.sqrt_rem(Integer::new());
        let roots: (Integer, Integer) = ((m.clone() - i.clone()) >> 1, (m + i) >> 1);

        if roots.0.clone() * roots.1.clone() == *n {
            return Some(roots);
        }
    }
    None
}

pub fn crt(residues: &[Integer], modulli: &[Integer]) -> Option<Integer> {
    let prod = modulli.iter().product::<Integer>();
    let mut sum = Integer::ZERO;

    for (residue, modulus) in residues.iter().zip(modulli) {
        let p = prod.clone() / modulus;
        sum += residue * Integer::from(p.invert_ref(modulus)?) * p
    }

    Some(sum % prod)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn integer_square_and_fourth_root_are_exact() {
        assert_eq!(integer_sqrt(&100.into()), Integer::from(10));
        assert_eq!(is_perfect_square(&101.into()), None);
        assert_eq!(integer_nth_root(&81.into(), 4), Integer::from(3));
        assert_eq!(integer_nth_root(&80.into(), 4), Integer::from(2));
    }

    #[test]
    fn integer_roots_of_large_values_and_invalid_inputs_are_total() {
        let square = Integer::from_str(
            "115792089237316195423570985008687907853269984665640564039457584007913129639936",
        )
        .unwrap();
        assert_eq!(
            integer_sqrt(&square),
            Integer::from_str("340282366920938463463374607431768211456").unwrap()
        );
        assert_eq!(is_perfect_square(&(square.clone() - 1)), None);
        assert_eq!(is_perfect_square(&0.into()), Some(Integer::from(0)));
        assert_eq!(integer_sqrt(&(-1).into()), Integer::from(0));
        assert_eq!(integer_nth_root(&(-1).into(), 3), Integer::from(0));
        assert_eq!(integer_nth_root(&27.into(), 0), Integer::from(0));
        assert_eq!(integer_nth_root(&27.into(), 1), Integer::from(27));
        assert_eq!(integer_nth_root(&0.into(), 7), Integer::from(0));
    }

    #[test]
    fn chinese_remainder_theorem() {
        assert_eq!(
            crt(
                &[3.into(), 5.into(), 7.into()],
                &[2.into(), 3.into(), 1.into()]
            ),
            Some(Integer::from(5))
        );
        assert_eq!(
            crt(
                &[1.into(), 4.into(), 6.into()],
                &[3.into(), 5.into(), 7.into()]
            ),
            Some(Integer::from(34))
        );
        assert_eq!(
            crt(
                &[1.into(), 4.into(), 6.into()],
                &[1.into(), 2.into(), 0.into()]
            ),
            None
        );
        assert_eq!(
            crt(
                &[2.into(), 5.into(), 7.into()],
                &[6.into(), 9.into(), 15.into()]
            ),
            None
        );
    }
}
