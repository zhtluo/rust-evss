use ark_ff::Field;
use ark_poly::UVPolynomial;
use ark_poly_commit::PolynomialCommitment;
use ark_std::{iter::once, marker::PhantomData, vec::Vec};

use rand_core::RngCore;

use crate::ark_serde::{canonical_deserialize, canonical_serialize};
use crate::helper::{label_polynomial, label_commit};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EVSSParams<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub committer_key: PC::CommitterKey,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub verifier_key: PC::VerifierKey,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub polynomial: P,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub commit: PC::Commitment,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub rands: PC::Randomness,
}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> EVSSParams<F, P, PC> {
    pub fn get_public_params(&self) -> EVSSPublicParams<F, P, PC> {
        EVSSPublicParams {
            verifier_key: self.verifier_key.clone(),
            commit: self.commit.clone(),
        }
    }
}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> std::fmt::Debug for EVSSParams<F, P, PC> {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EVSSParams")
         .field("committer_key", &self.committer_key)
         .field("verifier_key", &self.verifier_key)
         .field("polynomial", &self.polynomial)
         // .field("commit", &self.commit)
         // .field("rands", &self.rands)
         .finish()
    }

}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> Clone for EVSSParams<F, P, PC> {

    fn clone(&self) -> Self {
        EVSSParams {
            committer_key: self.committer_key.clone(),
            verifier_key: self.verifier_key.clone(),
            polynomial: self.polynomial.clone(),
            commit: self.commit.clone(),
            rands: self.rands.clone(),
        }
    }

}

#[derive(Serialize, Deserialize)]
pub struct EVSSPublicParams<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub verifier_key: PC::VerifierKey,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub commit: PC::Commitment,
}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> std::fmt::Debug for EVSSPublicParams<F, P, PC> {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EVSSPublicParams")
         .field("verifier_key", &self.verifier_key)
         // .field("commit", &self.commit)
         .finish()
    }

}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> Clone for EVSSPublicParams<F, P, PC> {

    fn clone(&self) -> Self {
        EVSSPublicParams {
            verifier_key: self.verifier_key.clone(),
            commit: self.commit.clone(),
        }
    }

}

#[derive(Serialize, Deserialize)]
pub struct EVSSShare<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub point: F,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub value: F,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub challenge: F,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub proof: PC::Proof,
}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> std::fmt::Debug for EVSSShare<F, P, PC> {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EVSSShare")
         .field("point", &self.point)
         .field("value", &self.value)
         .field("challenge", &self.challenge)
         // .field("proof", &self.proof)
         .finish()
    }

}

impl<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>> Clone for EVSSShare<F, P, PC> {

    fn clone(&self) -> Self {
        EVSSShare {
            point: self.point.clone(),
            value: self.value.clone(),
            challenge: self.challenge.clone(),
            proof: self.proof.clone(),
        }
    }

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
        let poly = label_polynomial(&P::from_coefficients_vec(vec));
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
            once(&label_polynomial(&params.polynomial)),
            once(&label_commit::<F, P, PC>(&params.commit)),
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
            once(&label_commit::<F, P, PC>(&params.commit)),
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
