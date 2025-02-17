use super::{BlindProof, CommitmentWithProof, Signature};

use crate::suite::cipher::Cipher;

use crate::utils::blind::calculate_blind_challenge;
use crate::utils::scalar::{calculate_domain, hash_to_scalar, random_scalars};
use crate::utils::serialize::{Deserialize, Serialize};

use bls12_381::{G1Affine, G1Projective, Scalar};

/// Commit to the proof of knowledge of a signature.
///
/// - `blind_generators`: a list of pseudo-random points from the G1 group.
/// - `committed_messages`: a list of scalar values. If not supplied, it defaults to an empty list.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a tuple containing the commitment with proof encoded as an octet string, and a scalar value.
pub(super) fn blind_commit(
    blind_generators: &Vec<G1Affine>,
    committed_messages: Option<&Vec<Scalar>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
    random_scalar_sampler: Option<fn(usize) -> Vec<Scalar>>,
) -> (CommitmentWithProof, Scalar) {
    let default_committed_messages = vec![];
    let default_random_scalar_sampler = random_scalars;

    let committed_messages = committed_messages.unwrap_or(&default_committed_messages);
    let random_scalar_sampler = random_scalar_sampler.unwrap_or(default_random_scalar_sampler);

    // Deserialization:
    //
    // 1. M := len(committed_messages).
    // 2. If len(blind_generators) != M + 1, return INVALID.
    // 3. (Q_2, J_1, ..., J_M) := blind_generators.

    let m = committed_messages.len();
    if blind_generators.len() != m + 1 {
        panic!("The length of the blind generators must be equal to the length of the committed messages plus one.");
    }
    let q_2 = blind_generators[0];
    let j_points = &blind_generators[1..];

    // Procedure:
    //
    // 1. (secret_prover_blind, tilde_s, tilde_m_1, ..., tilde_m_M) := random_scalars(M + 2).
    // 2. C := Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M.
    // 3. C_bar := Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M.
    // 4. challenge := calculate_blind_challenge(C, C_bar, blind_generators, api_id).
    // 5. s^ := s~ + secret_prover_blind * challenge.
    // 6. For m in (1, 2, ..., M): m^_i := m~_i + msg_i * challenge.
    // 7. proof := (s^, (m^_1, ..., m^_M), challenge).
    // 8. commit_with_proof := commitment_with_proof_to_octets(C, proof).
    // 9. Return (commit_with_proof, secret_prover_blind).

    let random_scalars = random_scalar_sampler(m + 2);
    let secret_prover_blind = random_scalars[0];
    let tilde_s = random_scalars[1];
    let tilde_m_points = &random_scalars[2..];

    let c: G1Projective = j_points.iter().zip(committed_messages.iter()).fold(
        (q_2 * secret_prover_blind).into(),
        |acc: G1Projective, (j, msg)| (acc + j * msg).into(),
    );
    let c_bar: G1Projective = j_points
        .iter()
        .zip(tilde_m_points.iter())
        .fold((q_2 * tilde_s).into(), |acc: G1Projective, (j, tilde_m)| {
            (acc + j * tilde_m).into()
        });

    let challenge =
        calculate_blind_challenge(&c.into(), &c_bar.into(), &blind_generators, api_id, cipher);
    let s_hat = tilde_s + secret_prover_blind * challenge;
    let m_hats: Vec<Scalar> = tilde_m_points
        .iter()
        .zip(committed_messages.iter())
        .map(|(tilde_m, msg)| tilde_m + msg * challenge)
        .collect();

    let proof = BlindProof {
        s_hat,
        m_hats,
        challenge,
    };

    (
        CommitmentWithProof {
            commitment: c.into(),
            proof,
        },
        secret_prover_blind,
    )
}

/// Verify the correctness of a committed proof for a supplied commitment, over a list of points of G1 called the blind
/// generators, used to compute that commitment.
///
/// - `commitment`: a point from the G1 group.
/// - `commitment_proof`: a proof of correctness of the commitment.
/// - `blind_generators`: a list of pseudo-random points from the G1 group.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return `true` if the proof is correct, `false` otherwise.
pub(super) fn blind_commit_verify(
    commitment: &G1Affine,
    commitment_proof: &BlindProof,
    blind_generators: &Vec<G1Affine>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> bool {
    // Deserialization:
    //
    // 1. (s^, commitments, cp) := commitment_proof.
    // 2. M := len(commitments).
    // 3. (m^_1, ..., m^_M) := commitments.
    // 4. If len(blind_generators) != M + 1, return INVALID.
    // 5. (Q_2, J_1, ..., J_M) := blind_generators.

    let s_hat = commitment_proof.s_hat.clone();
    let m_hats = commitment_proof.m_hats.clone();
    let cp = commitment_proof.challenge.clone();

    let m = commitment_proof.m_hats.len();
    if blind_generators.len() != m + 1 {
        panic!("The length of the blind generators must be equal to the length of the commitments plus one.");
    }
    let q_2 = blind_generators[0];
    let j_points = &blind_generators[1..];

    // Procedure:
    //
    // 1. c_bar := Q_2 * s^ + J_1 * m^_1 + ... + J_M * m^_M + commitment * (-cp).
    // 2. cv := calculate_blind_challenge(commitment, c_bar, blind_generators, api_id).
    // 3. If cv != cp, return INVALID.
    // 4. Return VALID.

    let mut c_bar: G1Projective = j_points
        .iter()
        .zip(m_hats.iter())
        .fold((q_2 * s_hat).into(), |acc: G1Projective, (j, m_hat)| {
            (acc + j * m_hat).into()
        });
    c_bar += commitment * (-cp);

    let cv =
        calculate_blind_challenge(&commitment, &c_bar.into(), blind_generators, api_id, cipher);
    cv == cp
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
/// - `cipher`: a cipher suite.
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
    cipher: &Cipher,
) -> Signature {
    let default_blind_generators = vec![];
    let default_api_id = vec![];

    let blind_generators = blind_generators.unwrap_or(&default_blind_generators);
    let api_id = api_id.unwrap_or(&default_api_id);

    // Definitions:
    //
    // 1. hash_to_scalar_dst: an octet string representing the domain separation tag: "<api_id> || H2S_".
    let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

    // Deserialization:
    //
    // 1. L := len(generators) - 1.
    // 2. M := len(blind_generators) - 1.
    // 3. If L <= 0 or M <= 0, return INVALID.
    // 4. (Q_1, H_1, ..., H_L) := generators.
    // 5. (Q_2, J_1, ..., J_M) := blind_generators.

    // let l = generators.len() - 1;
    // let m = blind_generators.len() - 1;
    // if l < 0 || m < 0 {
    //     panic!("The number of generators must be greater than zero.");
    // }
    let q_1 = generators[0];
    let q_2 = blind_generators[0];
    let h_points = &generators[1..];
    let j_points = &blind_generators[1..];

    // Procedure:
    //
    // 1. domain := calculate_domain(public_key, Q_1, (H_1, ..., H_L, Q_2, J_1, ..., J_M), header, api_id).
    // 2. e_octets := serialize(secret_key, B, domain).
    // 3. e := hash_to_scalar(e_octets, hash_to_scalar_dst).
    // 4. A := B * (1 / (secret_key + e)).
    // 5. Return signature_to_octets(A, e).

    // the combined points should be (H_1, ..., H_L) combined with Q_2 and then (J_1, ..., J_M)
    let combined_points: Vec<G1Affine> = h_points
        .iter()
        .chain(std::iter::once(&q_2))
        .chain(j_points.iter())
        .cloned()
        .collect();

    let domain = calculate_domain(
        &public_key,
        q_1,
        combined_points,
        header,
        Some(&api_id),
        cipher,
    );

    // update b = b + Q_1 * domain
    let b: G1Affine = (b + q_1 * domain).into();

    let secret_key_serialized = secret_key.serialize();
    let b_serialized = b.serialize();
    // let domain_serialized = domain.serialize();

    let e_octets = &[
        secret_key_serialized.as_slice(),
        b_serialized.as_slice(),
        // domain_serialized.as_slice(),
    ]
    .concat();
    let e = hash_to_scalar(e_octets, &hash_to_scalar_dst, cipher);

    let a: G1Affine = (b * (secret_key + e).invert().unwrap()).into();
    Signature { a, e }
}

/// Validate an optional commitment. If a commitment is not supplied, or if it is the Identity_G1 point, this operation
/// will return the Identity_G1 as the default commitment point, which will be ignored by all computations during blind
/// signing.
///
/// - `commitment_with_proof`: an octet string representing the commitment and its proof of correctness.
/// - `blind_generators`: a list of points from the G1 group.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a point from the G1 group as the commitment.
pub(super) fn deserialize_and_validate_blind_commit(
    commitment_with_proof: Option<&[u8]>,
    blind_generators: Option<&Vec<G1Affine>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> G1Affine {
    if commitment_with_proof.is_none() || commitment_with_proof.unwrap().is_empty() {
        return G1Affine::identity();
    };

    let default_blind_generators = vec![];

    let commitment_with_proof = commitment_with_proof.unwrap();
    let blind_generators = blind_generators.unwrap_or(&default_blind_generators);

    // Procedure:
    //
    // 1. If commitment_with_proof is the empty string, return Identity_G1.
    // 2. com_res := octets_to_commitment_with_proof(commitment_with_proof).
    // 3. If com_res is INVALID, return INVALID.
    // 4. (commit, commit_proof) := com_res.
    // 5. If len(commit_proof[1]) + 1 != len(blind_generators), return INVALID.
    // 6. validation_res := core_commit_verify(commit, commit_proof, blind_generators, api_id).
    // 7. If validation_res is INVALID, return INVALID.
    // 8. Return commit.

    let commitment_with_proof = CommitmentWithProof::deserialize(&commitment_with_proof);
    let commitment_proof = commitment_with_proof.proof;
    let commitment = commitment_with_proof.commitment;

    if commitment_proof.m_hats.len() + 1 != blind_generators.len() {
        panic!("The length of the commitment proof must be equal to the length of the blind generators plus one.");
    };

    let validation_res = blind_commit_verify(
        &commitment,
        &commitment_proof,
        blind_generators,
        api_id,
        cipher,
    );
    if validation_res == false {
        panic!("The commitment is invalid.");
    }
    commitment
}
