use ark_ff::Field;
use ark_poly::UVPolynomial;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use ark_std::{iter::once, marker::PhantomData};

use crate::evss::*;
use crate::helper::{label_polynomial, label_commit};

use rand_core::RngCore;

pub struct Biaccumulator<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    _f: PhantomData<F>,
    _pc: PhantomData<PC>,
}

impl<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> Biaccumulator<F, PC> {

    pub fn setup<R: RngCore>(
        cred: &[F],
        degree: usize,
        rng: &mut R,
    ) -> Result<EVSSParams<F, DensePolynomial<F>, PC>, PC::Error> {
        let mut p = DensePolynomial::<F>::from_coefficients_slice(&[F::from(1 as u32)]);
        for &c in cred {
            p = p.naive_mul(&DensePolynomial::<F>::from_coefficients_slice(&[-c, F::from(1 as u32)]));
        }
        let pp = PC::setup(degree, None, rng)?;
        let poly = label_polynomial(&p);
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

    pub fn create_witness<R: RngCore>(
        cred: F,
        params: &EVSSParams<F, DensePolynomial<F>, PC>,
        rng: &mut R,
    ) -> Result<EVSSShare<F, DensePolynomial<F>, PC>, PC::Error> {
        EVSS::get_share(cred, params, rng)
    }

    pub fn check<R: RngCore>(
        params: &EVSSPublicParams<F, DensePolynomial<F>, PC>,
        share: &EVSSShare<F, DensePolynomial<F>, PC>,
        rng: &mut R,
    ) -> Result<bool, PC::Error> {
        if share.value != F::from(0 as u32) {
            return Ok(false); 
        }
        PC::check(
            &params.verifier_key,
            once(&label_commit::<F, DensePolynomial<F>, PC>(&params.commit)),
            &share.point,
            once(share.value),
            &share.proof,
            share.challenge,
            Some(rng),
        )
    }

}

