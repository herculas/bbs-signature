use crate::proof::{PreProof, Proof};
use crate::signature::Signature;
use crate::suite::cipher::Cipher;
use crate::suite::constants::PADDING_HASH_TO_SCALAR;
use crate::utils::format::i2osp;
use crate::utils::scalar::{calculate_domain, hash_to_scalar};
use crate::utils::serialize::Serialize;
use bls12_381::{G1Affine, G1Projective, Scalar};

/// Initialize the proof and return one of the inputs passed to the challenge calculation operation.
/// The input `message` MUST be supplied in the same order as they were signed.
///
/// The prover need to provide the messages which are not to be disclosed. For this purpose, along
/// with the list of signed messages, this operation also accepts a set of integers between 0 and
/// L - 1, where L is the number of the vector of messages, in ascending order, representing the
/// indexes of the undisclosed messages.
///
/// To blind the inputted `signature` and the undisclosed messages, this operation also accepts a
/// set of uniformly sampled random scalars. This set MUST have exactly 5 more items than the list
/// of undisclosed indexes.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a signature.
/// - `generators`: a list of pseudo-random G1 generators.
/// - `random_scalars`: a list of uniformly sampled random scalars.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of scalars representing the messages.
/// - `undisclosed_indexes`: a list of integers representing the indexes of undisclosed messages.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a pre-proof containing 5 G1 points and a scalar.
pub(super) fn initialize_proof(
    public_key: &[u8],
    signature: &Signature,
    generators: &Vec<G1Affine>,
    random_scalars: &Vec<Scalar>,
    header: Option<&[u8]>,
    messages: Option<&Vec<Scalar>>,
    undisclosed_indexes: Option<&Vec<usize>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> PreProof {
    let empty_message_vec = vec![];
    let empty_index_vec = vec![];
    let inner_messages = messages.unwrap_or(&empty_message_vec);
    let inner_undisclosed_indexes = undisclosed_indexes.unwrap_or(&empty_index_vec);

    // Deserialization:
    //
    // 1. (A, e) := signature.
    // 2. L := len(messages).
    // 3. U := len(undisclosed_indexes).
    // 4. (j_1, j_2, ..., j_U) := undisclosed_indexes.
    // 5. If len(random_scalars) != U + 5, return INVALID.
    // 6. (r_1, r_2, ~e, ~r_1, ~r_3, ~m_{j_1}, ~m_{j_2}, ..., ~m_{j_U}) := random_scalars.
    // 7. (msg_1, msg_2, ..., msg_L) := messages.
    //
    // 8. If len(generators) != L + 1, return INVALID.
    // 9. (Q_1, msg_generators) := generators.
    // 10. (H_1, ..., H_L) := msg_generators.
    // 11. (H_{j_1}, ..., H_{j_U}) := (msg_generators[j_1], ..., msg_generators[j_U]).
    let a = signature.a;
    let e = signature.e;
    let l = inner_messages.len();
    let u = inner_undisclosed_indexes.len();
    if random_scalars.len() != u + 5 {
        panic!("the number of random scalars must be equal to the number of undisclosed indexes plus five");
    }
    let r_1 = random_scalars[0];
    let r_2 = random_scalars[1];
    let e_tilde = random_scalars[2];
    let r_1_tilde = random_scalars[3];
    let r_3_tilde = random_scalars[4];
    let m_tildes = &random_scalars[5..];

    if generators.len() != l + 1 {
        panic!("the number of generators must be equal to the number of messages plus one");
    }
    let q_1 = generators[0];
    let h_points = &generators[1..];

    // ABORT IF:
    //
    // 1. For i in undisclosed_indexes, i < 0 or i > L - 1.
    // 2. U > L.
    inner_undisclosed_indexes.iter().for_each(|&i| {
        if i >= l {
            panic!("The undisclosed indexes must be in the range [0, L - 1].");
        }
    });
    if u > l {
        panic!("the number of undisclosed indexes must be less than or equal to the number of messages");
    }

    // Procedure:
    //
    // 1. domain := calculate_domain(public_key, Q_1, (H_1, ..., H_L), header, api_id).
    //
    // 2. B := P_1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L.
    // 3. D := B * r_2.
    // 4. A_bar := A * (r_1 * r_2).
    // 5. B_bar := D * r_1 - A_bar * e.
    //
    // 6. T_1 := A_bar * ~e + D * ~r_1.
    // 7. T_2 := D * ~r_3 + H_{j_1} * ~m_{j_1} + ... + H_{j_U} * ~m_{j_U}.
    //
    // 8. Return (A_bar, B_bar, T_1, T_2, domain).
    let domain = calculate_domain(
        &public_key,
        q_1,
        h_points.to_vec(),
        header,
        api_id,
        &cipher,
    );
    let p_1: G1Affine = G1Affine::from_compressed(&cipher.singularity).unwrap();
    let b: G1Projective = h_points.iter().zip(inner_messages.iter()).fold(
        (p_1 + q_1 * domain).into(),
        |acc: G1Projective, (h, msg)| (acc + h * msg).into(),
    );
    let d = b * r_2;
    let a_bar = a * (r_1 * r_2);
    let b_bar = d * r_1 - a_bar * e;

    let t_1 = a_bar * e_tilde + d * r_1_tilde;
    let t_2 = inner_undisclosed_indexes
        .iter()
        .zip(m_tildes.iter())
        .fold(d * r_3_tilde, |acc: G1Projective, (&j, &m)| {
            (acc + h_points[j] * m).into()
        });

    PreProof {
        a_bar: a_bar.into(),
        b_bar: b_bar.into(),
        d: d.into(),
        t_1: t_1.into(),
        t_2: t_2.into(),
        domain,
    }
}

/// Finalize the proof calculation and return the serialized proof.
///
/// This operation accepts the output of the initialization operation, and a scalar representing the
/// challenge. It also requires the scalar part `e` of the BBS Signature, the random scalars used to
/// generate the proof, and a set of scalars representing the messages the prover wants to keep
/// undisclosed. The undisclosed messages MUST be supplied in the same order as they were signed.
///
/// - `init_output`: the output of the initialization operation.
/// - `challenge`: a scalar representing the challenge.
/// - `e`: a scalar representing the `e` part of the BBS Signature.
/// - `random_scalars`: a list of uniformly sampled random scalars.
/// - `undisclosed_messages`: a list of scalars representing the undisclosed messages.
///
/// Return a proof.
pub(super) fn finalize_proof(
    init_output: &PreProof,
    challenge: &Scalar,
    e: &Scalar,
    random_scalars: &Vec<Scalar>,
    undisclosed_messages: Option<&Vec<Scalar>>,
) -> Proof {
    let empty_vec = vec![];
    let inner_undisclosed_messages = undisclosed_messages.unwrap_or(&empty_vec);

    // Deserialization:
    //
    // 1. U := len(undisclosed_messages).
    // 2. If len(random_scalars) != U + 5, return INVALID.
    // 3. (r_1, r_2, ~e, ~r_1, ~r_3, ~m_{j_1}, ~m_{j_2}, ..., ~m_{j_U}) := random_scalars.
    // 4. (undisclosed_1, undisclosed_2, ..., undisclosed_U) := undisclosed_messages.
    // 5. (A_bar, B_bar, D, _, _, _) := init_output.
    let u = inner_undisclosed_messages.len();
    if random_scalars.len() != u + 5 {
        panic!("the number of random scalars must be equal to the number of undisclosed messages plus five");
    }
    let r_1 = random_scalars[0];
    let r_2 = random_scalars[1];
    let e_tilde = random_scalars[2];
    let r_1_tilde = random_scalars[3];
    let r_3_tilde = random_scalars[4];
    let m_tildes = &random_scalars[5..];

    let a_bar = init_output.a_bar;
    let b_bar = init_output.b_bar;
    let d = init_output.d;

    // Procedure:
    //
    // 1. r_3 := r_2 ^ {-1} mod r.
    // 2. ^e := ~e + e * challenge.
    // 3. ^r_1 := ~r_1 - r_1 * challenge.
    // 4. ^r_3 := ~r_3 - r_3 * challenge.
    // 5. For j in (1, ..., U): ^m_{j} := ~m_{j} + undisclosed_j * challenge mod r.
    //
    // 6. proof := (A_bar, B_bar, D, ^e, ^r_1, ^r_3, (^m_{j_1}, ..., ^m_{j_U}), challenge).
    // 7. Return proof_to_octets(proof).
    let r_3 = r_2.invert().unwrap();
    let e_hat = e_tilde + e * challenge;
    let r_1_hat = r_1_tilde - r_1 * challenge;
    let r_3_hat = r_3_tilde - r_3 * challenge;
    let m_hats: Vec<Scalar> = m_tildes
        .iter()
        .zip(inner_undisclosed_messages.iter())
        .map(|(&m_tilde, &m)| m_tilde + m * challenge)
        .collect();

    Proof {
        a_bar,
        b_bar,
        d,
        e_hat,
        r_1_hat,
        r_3_hat,
        m_hats,
        challenge: *challenge,
    }
}

/// Initialize the proof verification and return part of the input that will be passed to the
/// challenge calculation operation.
///
/// Note that the scalars representing the disclosed messages MUST be supplied in the same order as
/// they were signed. Similarly, the indexes of the disclosed messages MUST be supplied in ascending
/// order.
///
/// - `public_key`: an octet string representing the public key.
/// - `proof`: a proof.
/// - `generators`: a list of pseudo-random G1 generators.
/// - `header`: an octet string containing the context and application specific information.
/// - `disclosed_messages`: a list of scalars representing the disclosed messages.
/// - `disclosed_indexes`: a list of integers representing the indexes of disclosed messages.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a pre-proof containing 5 G1 points and a scalar.
pub(super) fn prepare_verification(
    public_key: &[u8],
    proof: &Proof,
    generators: &Vec<G1Affine>,
    header: Option<&[u8]>,
    disclosed_messages: Option<&Vec<Scalar>>,
    disclosed_indexes: Option<&Vec<usize>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> PreProof {
    let empty_message_vec = vec![];
    let empty_index_vec = vec![];
    let inner_disclosed_messages = disclosed_messages.unwrap_or(&empty_message_vec);
    let inner_disclosed_indexes = disclosed_indexes.unwrap_or(&empty_index_vec);

    // Deserialization:
    //
    // 1. (A_bar, B_bar, D, ^e, ^r_1, ^r_3, commitments, c) := proof.
    // 2. U := len(commitments).
    // 3. R := len(disclosed_indexes).
    // 4. L := R + U.
    // 5. (i_1, i_2, ..., i_R) := disclosed_indexes.
    // 6. For i in disclosed_indexes: if i < 0 or i > L - 1, return INVALID.
    // 7. (j_1, j_2, ..., j_U) := (0, 1, ..., L - 1) \ disclosed_indexes.
    // 8. If len(disclosed_messages) != R, return INVALID.
    // 9. (msg_{i_1}, msg_{i_2}, ..., msg_{i_R}) := disclosed_messages.
    // 10. (^m_{j_1}, ^m_{j_2}, ..., ^m_{j_U}) := commitments.
    //
    // 11. If len(generators) != L + 1, return INVALID.
    // 12. (Q_1, msg_generators) := generators.
    // 13. (H_1, ..., H_L) := msg_generators.
    // 14. (H_{i_1}, ..., H_{i_R}) := (msg_generators[i_1], ..., msg_generators[i_R]).
    // 15. (H_{j_1}, ..., H_{j_U}) := (msg_generators[j_1], ..., msg_generators[j_U]).
    let a_bar = proof.a_bar;
    let b_bar = proof.b_bar;
    let d = proof.d;
    let e_hat = proof.e_hat;
    let r_1_hat = proof.r_1_hat;
    let r_3_hat = proof.r_3_hat;
    let commitments = &proof.m_hats;
    let c = proof.challenge;

    let u = commitments.len();
    let r = inner_disclosed_indexes.len();
    let l = r + u;
    inner_disclosed_indexes.iter().for_each(|&i| {
        if i >= l {
            panic!("The disclosed indexes must be in the range [0, L - 1].");
        }
    });
    if inner_disclosed_messages.len() != r {
        panic!("the number of disclosed messages must be equal to the number of disclosed indexes");
    }
    if generators.len() != l + 1 {
        panic!("the number of generators must be equal to the number of messages plus one");
    }

    let q_1 = generators[0];
    let h_points = &generators[1..];

    let disclosed_indexes_set = inner_disclosed_indexes
        .iter()
        .collect::<std::collections::HashSet<_>>();
    let undisclosed_indexes: Vec<usize> = (0..l)
        .filter(|i| !disclosed_indexes_set.contains(i))
        .collect();

    // Procedure:
    // 1. domain := calculate_domain(public_key, Q_1, (H_1, ..., H_L), header, api_id).
    // 2. T_1 := B_bar * c + A_bar * ^e + D * ^r_1.
    // 3. B_v := P_1 + Q_1 * domain + H_{i_1} * msg_{i_1} + ... + H_{i_R} * msg_{i_R}.
    // 4. T_2 := B_v * c + D * ^r_3 + H_{j_1} * ^m_{j_1} + ... + H_{j_U} * ^m_{j_U}.
    // 5. Return (A_bar, B_bar, D, T_1, T_2, domain).
    let domain = calculate_domain(
        &public_key,
        q_1,
        h_points.to_vec(),
        header,
        api_id,
        &cipher,
    );
    let t_1 = b_bar * c + a_bar * e_hat + d * r_1_hat;
    let p_1: G1Affine = G1Affine::from_compressed(&cipher.singularity).unwrap();
    let b_v: G1Projective = inner_disclosed_indexes
        .iter()
        .zip(inner_disclosed_messages.iter())
        .fold(
            (p_1 + q_1 * domain).into(),
            |acc: G1Projective, (&i, &msg)| (acc + h_points[i] * msg).into(),
        );

    let t_2: G1Projective = undisclosed_indexes
        .iter()
        .zip(commitments.iter())
        .fold(b_v * c + d * r_3_hat, |acc: G1Projective, (&j, &m)| {
            (acc + h_points[j] * m).into()
        });

    PreProof {
        a_bar,
        b_bar,
        d,
        t_1: t_1.into(),
        t_2: t_2.into(),
        domain,
    }
}

/// Calculate the challenge scalar used during proof generation and verification, as part of the
/// Fiat-Shamir heuristic, for making the proof non-interactive. In an interactive setting, the
/// challenge would be a random value sampled by the verifier.
///
/// At a high level, the challenge will be calculated as the digest of the following values:
///     - The total number of the disclosed messages.
///     - Each index in the `disclosed_indexes` list, followed by the corresponding disclosed
///         message. For example, if `disclosed_indexes` is `[i_1, i_2]` and `disclosed_messages` is
///         `[msg_{i_1}, msg_{i_2}]`, then the input will include
///         `i_1 || msg_{i_1} || i_2 || msg_{i_2}`.
///     - The points `A_bar`, `B_bar`, `D`, `T_1`, `T_2`, and the `domain` scalar, calculated during
///       the proof initialization and verification operations.
///     - The presentation header.
///
/// - `init_output`: the output of the initialization operation.
/// - `disclosed_messages`: a list of scalars representing the disclosed messages.
/// - `disclosed_indexes`: a list of integers representing the indexes of disclosed messages.
/// - `presentation_header`: an octet string containing the context specific information.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a scalar representing the challenge.
pub(super) fn calculate_challenge(
    init_output: &PreProof,
    disclosed_messages: Option<&Vec<Scalar>>,
    disclosed_indexes: Option<&Vec<usize>>,
    presentation_header: Option<&[u8]>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> Scalar {
    let empty_message_vec = vec![];
    let empty_index_vec = vec![];
    let inner_disclosed_messages = disclosed_messages.unwrap_or(&empty_message_vec);
    let inner_disclosed_indexes = disclosed_indexes.unwrap_or(&empty_index_vec);
    let inner_presentation_header = presentation_header.unwrap_or(&[]);
    let inner_api_id = api_id.unwrap_or(&[]);

    // Definition:
    //
    // 1. hash_to_scalar_dst: an octet string representing the domain separation tag:
    //          "<api_id> || H2S_".
    let hash_to_scalar_dst = [inner_api_id, PADDING_HASH_TO_SCALAR].concat();

    // Deserialization:
    //
    // 1. R := len(disclosed_indexes).
    // 2. (i_1, i_2, ..., i_R) := disclosed_indexes.
    // 3. If len(disclosed_messages) != R, return INVALID.
    // 4. (msg_{i_1}, msg_{i_2}, ..., msg_{i_R}) := disclosed_messages.
    // 5. (A_bar, B_bar, D, T_1, T_2, domain) := init_output.
    let r = inner_disclosed_indexes.len();
    if inner_disclosed_messages.len() != r {
        panic!("the number of disclosed messages must be equal to the number of disclosed indexes");
    }

    // ABORT IF:
    //
    // 1. R > 2^64 - 1.
    // 2. len(presentation_header) > 2^64 - 1.
    if r > usize::MAX {
        panic!("the number of disclosed indexes must be less than 2^64 - 1");
    }
    if inner_presentation_header.len() > usize::MAX {
        panic!("the length of the presentation header must be less than 2^64 - 1");
    }

    // Procedure:
    //
    // 1. c_arr := (R,
    //          i_1, msg_{i_1}, i_2, msg_{i_2}, ..., i_R, msg_{i_R},
    //          A_bar, B_bar, D, T_1, T_2, domain).
    // 2. c_octets := serialize(c_arr) || i2osp(len(presentation_header), 8) || presentation_header.
    // 3. Return hash_to_scalar(c_octets, hash_to_scalar_dst).
    let r_serialized = (r as u64).serialize();
    let disclosed_indexes_serialized: Vec<u8> = inner_disclosed_indexes
        .iter()
        .zip(inner_disclosed_messages.iter())
        .flat_map(|(&i, &msg)| [(i as u64).serialize(), msg.serialize()].concat())
        .collect();
    let pre_proof_serialized = init_output.serialize();
    let presentation_header_len = i2osp(inner_presentation_header.len() as u64, 8);
    let c_octets: Vec<u8> = [
        r_serialized,
        disclosed_indexes_serialized,
        pre_proof_serialized,
        presentation_header_len,
        inner_presentation_header.to_vec(),
    ]
        .iter()
        .flatten()
        .cloned()
        .collect();
    hash_to_scalar(&c_octets, &hash_to_scalar_dst, &cipher)
}
