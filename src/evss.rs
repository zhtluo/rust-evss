use ark_ff::Field;
use ark_poly::UVPolynomial;
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment};
use ark_std::{iter::once, marker::PhantomData, vec::Vec};

use rand_core::RngCore;

pub struct EVSSParams<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    committer_key: PC::CommitterKey,
    verifier_key: PC::VerifierKey,
    polynomial: LabeledPolynomial<F, P>,
    commit: LabeledCommitment<PC::Commitment>,
    rands: PC::Randomness,
}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> EVSSParams<F, P, PC> {
    pub fn get_public_params(&self) -> EVSSPublicParams<F, P, PC> {
        EVSSPublicParams {
            verifier_key: self.verifier_key.clone(),
            commit: self.commit.clone(),
        }
    }
}

pub struct EVSSPublicParams<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    verifier_key: PC::VerifierKey,
    commit: LabeledCommitment<PC::Commitment>,
}

pub struct EVSSShare<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    point: F,
    value: F,
    challenge: F,
    proof: PC::Proof,
}

pub struct EVSS<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    _f: PhantomData<F>,
    _p: PhantomData<P>,
    _pc: PhantomData<PC>,
}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> EVSS<F, P, PC> {
    pub fn setup<R: RngCore>(
        secret: F,
        degree: usize,
        rng: &mut R,
    ) -> Result<EVSSParams<F, P, PC>, PC::Error> {
        let pp = PC::setup(degree, None, rng)?;
        let vec: Vec<F> = (0..degree)
            .map(|i| if i == 0 { secret } else { F::rand(rng) })
            .collect();
        let poly = LabeledPolynomial::new("".to_owned(), P::from_coefficients_vec(vec), None, None);
        let (ck, vk) = PC::trim(&pp, degree, 0, None)?;
        let (lc, r) = PC::commit(&ck, once(&poly), Some(rng))?;
        Ok(EVSSParams {
            committer_key: ck,
            verifier_key: vk,
            polynomial: poly,
            commit: lc[0].clone(),
            rands: r[0].clone(),
        })
    }

    pub fn get_share<R: RngCore>(
        point: F,
        params: &EVSSParams<F, P, PC>,
        rng: &mut R,
    ) -> Result<EVSSShare<F, P, PC>, PC::Error> {
        let ch = F::rand(rng);
        let pr = PC::open(
            &params.committer_key,
            once(&params.polynomial),
            once(&params.commit),
            &point,
            ch,
            once(&params.rands),
            Some(rng),
        )?;
        Ok(EVSSShare {
            point: point,
            value: params.polynomial.polynomial().evaluate(&point),
            challenge: ch,
            proof: pr,
        })
    }

    pub fn check<R: RngCore>(
        params: &EVSSPublicParams<F, P, PC>,
        share: &EVSSShare<F, P, PC>,
        rng: &mut R,
    ) -> Result<bool, PC::Error> {
        PC::check(
            &params.verifier_key,
            once(&params.commit),
            &share.point,
            once(share.value),
            &share.proof,
            share.challenge,
            Some(rng),
        )
    }

    pub fn reconstruct<'a, I>(shares: &'a I) -> F
    where
        &'a I: IntoIterator<Item = &'a EVSSShare<F, P, PC>>,
        P: 'a,
        PC: 'a,
    {
        let mut res = F::zero();
        for sh1 in shares {
            let mut term = sh1.value;
            for sh2 in shares {
                if sh1.point != sh2.point {
                    term *= (-sh2.point) / (sh1.point - sh2.point)
                }
            }
            res += term;
        }
        res
    }
}

#[cfg(test)]
mod tests {

    use crate::*;

    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_ff::UniformRand;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::test_rng;

    type F381 = <Bls12_381 as PairingEngine>::Fr;
    type Poly381 = DensePolynomial<F381>;
    type PC381 = MarlinKZG10<Bls12_381, Poly381>;
    type EVSS381 = evss::EVSS<F381, Poly381, PC381>;

    const DEGREE: usize = 10;
    const INDEX_BEGIN: usize = 1;

    #[test]
    fn test() -> Result<(), <PC381 as PolynomialCommitment<F381, Poly381>>::Error> {
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
}
