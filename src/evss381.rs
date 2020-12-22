use crate::*;

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;

pub type F381 = <Bls12_381 as PairingEngine>::Fr;
pub type Poly381 = DensePolynomial<F381>;
pub type PC381 = MarlinKZG10<Bls12_381, Poly381>;
pub type EVSS381 = evss::EVSS<F381, Poly381, PC381>;
pub type EVSSParams381 = evss::EVSSParams<F381, Poly381, PC381>;
pub type EVSSPublicParams381 = evss::EVSSPublicParams<F381, Poly381, PC381>;
pub type EVSSShare381 = evss::EVSSShare<F381, Poly381, PC381>;

#[cfg(test)]
mod tests {

    use crate::evss381::*;

    use ark_ff::UniformRand;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::test_rng;

    use serde_json;

    const DEGREE: usize = 10;
    const INDEX_BEGIN: usize = 1;

    #[test]
    fn test_functionality() -> Result<(), <PC381 as PolynomialCommitment<F381, Poly381>>::Error> {
        let rng = &mut test_rng();
        let secret = F381::rand(rng);
        let params = EVSS381::setup(secret, DEGREE, rng)?;
        let mut shares = Vec::new();
        for i in INDEX_BEGIN..INDEX_BEGIN + DEGREE + 1 {
            shares.push(EVSS381::get_share(F381::from(i as u32), &params, rng)?);
        }
        for sh in &shares {
            assert!(EVSS381::check(&params.get_public_params(), sh, rng)?);
        }
        assert_eq!(secret, EVSS381::reconstruct(&shares));
        Ok(())
    }

    #[test]
    fn test_serde() -> Result<(), serde_json::Error> {
        let rng = &mut test_rng();
        let secret = F381::rand(rng);
        let params = EVSS381::setup(secret, DEGREE, rng).unwrap();
        let _: EVSSParams381 = serde_json::from_str(&serde_json::to_string(&params)?)?;
        let _: EVSSPublicParams381 =
            serde_json::from_str(&serde_json::to_string(&params.get_public_params())?)?;
        for i in INDEX_BEGIN..INDEX_BEGIN + DEGREE + 1 {
            println!(
                "{}",
                serde_json::to_string(
                    &EVSS381::get_share(F381::from(i as u32), &params, rng).unwrap()
                )?
            );
            let _: EVSSShare381 = serde_json::from_str(&serde_json::to_string(
                &EVSS381::get_share(F381::from(i as u32), &params, rng).unwrap(),
            )?)?;
        }
        Ok(())
    }

}
