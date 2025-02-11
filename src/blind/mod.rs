use bls12_381::Scalar;

mod core;
pub(crate) mod interface;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedProof {
    s: Scalar,
    ss: Vec<Scalar>,
    sss: Scalar,
}
