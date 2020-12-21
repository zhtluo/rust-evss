use ark_ff::Field;
use ark_poly::UVPolynomial;
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment};
use ark_std::{iter::once, marker::PhantomData, vec::Vec};

use rand_core::RngCore;

use crate::ark_serde::{canonical_serialize, canonical_deserialize};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EVSSParams<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    committer_key: PC::CommitterKey,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    verifier_key: PC::VerifierKey,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    polynomial: P,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    commit: PC::Commitment,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct EVSSPublicParams<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    verifier_key: PC::VerifierKey,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    commit: PC::Commitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EVSSShare<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    point: F,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    value: F,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    challenge: F,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    proof: PC::Proof,
}

pub struct EVSS<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    _f: PhantomData<F>,
    _p: PhantomData<P>,
    _pc: PhantomData<PC>,
}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> EVSS<F, P, PC> {

    fn label_polynomial(polynomial: &P) -> LabeledPolynomial<F, P> {
        LabeledPolynomial::new("".to_owned(), polynomial.clone(), None, None)
    }

    fn label_commit(commit: &PC::Commitment) -> LabeledCommitment<PC::Commitment> {
        LabeledCommitment::new("".to_owned(), commit.clone(), None)
    }

    pub fn setup<R: RngCore>(
        secret: F,
        degree: usize,
        rng: &mut R,
    ) -> Result<EVSSParams<F, P, PC>, PC::Error> {
        let pp = PC::setup(degree, None, rng)?;
        let vec: Vec<F> = (0..degree)
            .map(|i| if i == 0 { secret } else { F::rand(rng) })
            .collect();
        let poly = Self::label_polynomial(&P::from_coefficients_vec(vec));
        let (ck, vk) = PC::trim(&pp, degree, 0, None)?;
        let (lc, r) = PC::commit(&ck, once(&poly), Some(rng))?;
        Ok(EVSSParams {
            committer_key: ck,
            verifier_key: vk,
            polynomial: poly.polynomial().clone(),
            commit: lc[0].commitment().clone(),
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
            once(&Self::label_polynomial(&params.polynomial)),
            once(&Self::label_commit(&params.commit)),
            &point,
            ch,
            once(&params.rands),
            Some(rng),
        )?;
        Ok(EVSSShare {
            point: point,
            value: params.polynomial.evaluate(&point),
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
            once(&Self::label_commit(&params.commit)),
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

    use serde_json;

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
            let serialized = serde_json::to_string(&EVSS381::get_share(F381::from(i as u32), &params, rng)?).unwrap();
            println!("{}", serialized);
            shares.push(serde_json::from_str(&serialized).unwrap());
        }
        for sh in &shares {
            assert!(EVSS381::check(&params.get_public_params(), sh, rng)?);
        }
        assert_eq!(secret, EVSS381::reconstruct(&shares));
        Ok(())
    }
}
