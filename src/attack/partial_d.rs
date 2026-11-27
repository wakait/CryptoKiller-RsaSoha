use indicatif::ProgressBar;
use rug::Integer;

use crate::{Attack, AttackKind, AttackSpeed, Error, KnownDAttack, Parameters, Solution};

/// Partial d leaked attack (more that half of the bits of d are known)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialDAttack;

impl Attack for PartialDAttack {
    fn name(&self) -> &'static str {
        "partial_d"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn required_parameters(&self) -> &'static [&'static str] {
        &["n", "e", "partial_d|d"]
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let e_u32 = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let (d_lsb, known_bits) = if let Some(partial_d) = &params.partial_d {
            (
                partial_d,
                params
                    .partial_d_bits
                    .unwrap_or_else(|| partial_d.significant_bits() as usize),
            )
        } else if let Some(d) = &params.d {
            (d, d.significant_bits() as usize)
        } else {
            return Err(Error::MissingParameters);
        };
        if known_bits == 0 || known_bits >= n.significant_bits() as usize {
            return Err(Error::NotFound);
        }
        let known_bits = known_bits as u32;
        let known_mask = (Integer::from(1) << known_bits) - 1;
        let d_lsb = d_lsb & known_mask;

        for k in 1..e_u32 {
            let d_candidate = (n.clone() * k + 1u64) / e;
            let d_msb = (d_candidate >> known_bits) << known_bits;
            let d = d_msb | &d_lsb;

            // Verify the candidate as an RSA private exponent, not modulo the loop counter.
            let valid = if let Some(c) = &params.c {
                c.clone()
                    .pow_mod(&d, n)
                    .ok()
                    .and_then(|m| m.pow_mod(e, n).ok())
                    == Some(c.clone())
            } else {
                Integer::from(2)
                    .pow_mod(e, n)
                    .ok()
                    .and_then(|m| m.pow_mod(&d, n).ok())
                    == Some(Integer::from(2))
            };
            if valid {
                return KnownDAttack
                    .run(
                        &(Parameters {
                            d: Some(d),
                            ..Default::default()
                        } + params),
                        _pb,
                    )
                    .map(|mut s| {
                        s.attack = self.name();
                        s
                    });
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::ops::Pow;

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn explicit_partial_d_lsb_recovers_private_key() {
        let params = Parameters {
            n: Some(Integer::from(3233)),
            e: Integer::from(17),
            c: Some(Integer::from(2557)),
            partial_d: Some(Integer::from(193)),
            partial_d_bits: Some(8),
            ..Default::default()
        };

        let solution = PartialDAttack.run(&params, None).unwrap();
        assert_eq!(solution.m, Some(Integer::from(42)));
    }

    #[test]
    fn attack() {
        let p = Integer::from_str("619725990001524703456465713279465625846752832414168572011466066232082436863841189586501588353354943054775532335900016320501197905886582011529076059068049302722289071314361386097002051734252322740808308805710458547662135247973085180484778717957169307399128511564888941495042113300382369335995877815563").unwrap();
        let q = Integer::from_str("961141430710150744852888885216606265327700813871292735032123072541546834239236573911369525935582156732540361058711390750890531374856612832113164217347913046140103022163728329963032320241017138138876928547833993486588456012463816930437584873444942767568476855020374256145222297933467290778138867303179").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();
        let partial_d = d.clone() % Integer::from(2).pow(d.significant_bits() / 2 + 2);

        let params = Parameters {
            n: Some(factors.product()),
            d: Some(partial_d),
            ..Default::default()
        };

        let solution = PartialDAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
