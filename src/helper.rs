use ark_ff::Field;
use ark_poly::UVPolynomial;
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment};

pub fn label_polynomial<F: Field, P: UVPolynomial<F>>(polynomial: &P) -> LabeledPolynomial<F, P> {
    LabeledPolynomial::new("".to_owned(), polynomial.clone(), None, None)
}

pub fn label_commit<F: Field, P: UVPolynomial<F>, PC: PolynomialCommitment<F, P>>(commit: &PC::Commitment) -> LabeledCommitment<PC::Commitment> {
    LabeledCommitment::new("".to_owned(), commit.clone(), None)
}
