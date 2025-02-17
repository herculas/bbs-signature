use crate::suite::cipher::Cipher;

use bls12_381::{G1Affine, G1Projective, Scalar};
use crate::utils::scalar::random_scalar;

/// Calculate the `b` value for the proof of knowledge of a signature.
///
/// - `generators`: a list of at least one point from the G1 group.
/// - `commitment`: a point from the G1 group. If not supplied, it defaults to the Identity_G1 point.
/// - `nym_generator`: a point from the G1 group. If not supplied, it defaults to the Identity_G1 point.
/// - `messages`: a list of scalar values. If not supplied, it defaults to an empty list.
/// - `cipher`: the cipher suite.
///
/// Return an element from the G1 subgroup, along with a scalar value, or INVALID.
pub fn calculate_b_with_nym(
    generators: &Vec<G1Affine>,
    commitment: Option<&G1Affine>,
    nym_generator: Option<&G1Affine>,
    messages: Option<&Vec<Scalar>>,
    cipher: &Cipher,
) -> (G1Projective, Scalar) {
    let default_nym_generator = G1Affine::identity();
    let default_commitment = G1Affine::identity();
    let default_messages = vec![];

    let nym_generator = nym_generator.unwrap_or(&default_nym_generator);
    let commitment = commitment.unwrap_or(&default_commitment);
    let messages = messages.unwrap_or(&default_messages);
    
    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. If len(generators) != L + 1, return INVALID.
    // 3. (Q_1, H_1, ..., H_L) := generators.

    let l = messages.len();
    if generators.len() != l + 1 {
        panic!("the number of generators must be equal to the number of messages plus one");
    }
    let h_points = &generators[1..];

    // Procedure:
    //
    // 1. B := Q_1 + H_1 * msg_1 + ... + H_L * msg_L + commitment.
    // 2. signer_nym_entropy := get_random().
    // 3. B := B + nym_generator * signer_nym_entropy.
    // 4. If B is Identity_G1, return INVALID.
    // 5. Return (B, signer_nym_entropy).

    let p_1: G1Affine = G1Affine::from_compressed(&cipher.singularity).unwrap();
    let mut b: G1Projective = h_points
        .iter()
        .zip(messages.iter())
        .fold(p_1.into(), |acc: G1Projective, (h, msg)| {
            (acc + h * msg).into()
        });
    // b += commitment;

    let signer_nym_entropy = random_scalar();
    b = b + commitment + nym_generator * signer_nym_entropy;
    if b == G1Projective::identity() {
        panic!("the B value must not be the Identity_G1 point");
    }
    
    (b, signer_nym_entropy)
}
