use crate::blind::CommittedProof;
use bls12_381::{G1Affine, Scalar};

/// Commit to the proof of knowledge of a signature.
///
/// - `blind_generators`: a list of pseudo-random points from the G1 group.
/// - `committed_messages`: a list of scalar values. If not supplied, it defaults to an empty list.
/// - `api_id`: an octet string representing the API identifier.
///
///
pub(super) fn commit(
    blind_generators: Vec<G1Affine>,
    committed_messages: Option<&Vec<Scalar>>,
    api_id: Option<&[u8]>,
) {
    // Deserialization:
    //
    // 1. M := len(committed_messages).
    // 2. If len(blind_generators) != M + 1, return INVALID.
    // 3. (Q_2, J_1, ..., J_M) := blind_generators.

    // Procedure:
    //
    // 1. (secret_prover_blind, tilde_s, tilde_m_1, ..., tilde_m_M) := get_random_scalars(M + 2).
    // 2. C := Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M.
    // 3. C_bar := Q_2 * tilde_s + J_1 * tilde_m_1 + ... + J_M * tilde_m_M.
    // 4. challenge := calculate_blind_challenge(C, C_bar, blind_generators, api_id).
    // 5. hat_s := tilde_s + secret_prover_blind * challenge.
    // 6. For m in (1, 2, ..., M): hat_m_i := tilde_m_i + msg_i * challenge.
    // 7. proof := (hat_s, (hat_m_1, ..., hat_m_M), challenge).
    // 8. commit_with_proof := commitment_with_proof_to_octets(C, proof).
    // 9. Return (commit_with_proof, secret_prover_blind).
}

/// Verify the correctness of a committed proof for a supplied commitment, over a list of points of G1 called the blind
/// generators, used to compute that commitment.
///
/// - `commitment`: a point from the G1 group.
/// - `commitment_proof`: a proof of correctness of the commitment.
/// - `blind_generators`: a list of pseudo-random points from the G1 group.
/// - `api_id`: an octet string representing the API identifier.
///
/// Return `true` if the proof is correct, `false` otherwise.
pub(super) fn commit_verify(
    commitment: &G1Affine,
    commitment_proof: &CommittedProof,
    blind_generators: Vec<G1Affine>,
    api_id: Option<&[u8]>,
) {
    // Deserialization:
    //
    // 1. (hat_s, commitments, cp) := commitment_proof.
    // 2. M := len(commitments).
    // 3. (hat_m_1, ..., hat_m_M) := commitments.
    // 4. If len(blind_generators) != M + 1, return INVALID.
    // 5. (Q_2, J_1, ..., J_M) := blind_generators.

    // Procedure:
    //
    // 1. C_bar := Q_2 * hat_s + J_1 * hat_m_1 + ... + J_M * hat_m_M + commitment * (-cp).
    // 2. cv := calculate_blind_challenge(commitment, C_bar, blind_generators, api_id).
    // 3. If cv != cp, return INVALID.
    // 4. Return VALID.
}

/// Compute a blind BBS signature, from a secret key, a set of generators, a supplied commitment with its proof of
/// correctness, a header, and a set of messages.
///
/// - `secret_key`: a scalar representing the secret key.
/// - `public_key`: an octet string representing the public key.
/// - `b`: a point from the G1 group, different from the Identity_G1 point.
/// - `generators`: a list of pseudo-random points from the G1 group.
/// - `blind_generators`: a list of pseudo-random points from G1. If not supplied, it defaults to an empty list.
/// - `header`: an octet string containing the context and application specific information.
/// - `api_id`: an octet string representing the API identifier.
///
/// Return a blind BBS signature encoded as an octet string.
pub(super) fn finalize_blind_sign(
    secret_key: &Scalar,
    public_key: &[u8],
    b: &G1Affine,
    generators: &Vec<G1Affine>,
    blind_generators: Option<&Vec<G1Affine>>,
    header: Option<&[u8]>,
    api_id: Option<&[u8]>,
) {
    // Definitions:
    //
    // 1. hash_to_scalar_dst: an octet string representing the domain separation tag: "<api_id> || H2S_".

    // Deserialization:
    //
    // 1. L := len(generators) - 1.
    // 2. M := len(blind_generators) - 1.
    // 3. If L <= 0 or M <= 0, return INVALID.
    // 4. (Q_1, H_1, ..., H_L) := generators.
    // 5. (Q_2, J_1, ..., J_M) := blind_generators.

    // Procedure:
    //
    // 1. domain := calculate_domain(public_key, Q_1, (H_1, ..., H_L, J_1, ..., J_M), header, api_id).
    // 2. e_octets := serialize(secret_key, B, domain).
    // 3. e := hash_to_scalar(e_octets, hash_to_scalar_dst).
    // 4. A := B * (1 / (secret_key + e)).
    // 5. Return signature_to_octets(A, e).
}
