use crate::*;
pub use crate::evss381::*;

pub type Biaccumulator381 = biaccumulator::Biaccumulator<F381, PC381>;

#[cfg(test)]
mod tests {

    use crate::biaccumulator381::*;

    use ark_std::test_rng;

    const DEGREE: usize = 10;

    #[test]
    fn test_functionality() -> Result<(), <PC381 as PolynomialCommitment<F381, Poly381>>::Error> {
        let rng = &mut test_rng();
        let vec: Vec<F381> = (0..DEGREE).map(|_| F381::rand(rng)).collect();
        let params = Biaccumulator381::setup(DEGREE, rng)?;
        let poly = Biaccumulator381::commit(&params, &vec[..], rng)?;
        for cred in &vec {
            let witness = Biaccumulator381::create_witness(*cred, &params, &poly, rng)?;
            assert!(Biaccumulator381::check(&params.get_public_params(), &poly.get_commit(), &witness, rng)?);
        }
        Ok(())
    }

}
