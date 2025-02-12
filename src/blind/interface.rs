use crate::blind::commitment::deserialize_and_validate_commit;
use crate::blind::core::finalize_blind_sign;
use crate::proof::Proof;
use crate::signature::Signature;
use crate::suite::cipher::Cipher;
use crate::suite::constants::{LENGTH_G1_POINT, LENGTH_SCALAR, PADDING_API_ID, PADDING_BLIND};
use crate::utils::blind::{calculate_b, prepare_parameters};
use crate::utils::generator::create_generators;
use crate::utils::scalar::messages_to_scalars;
use bls12_381::{G1Affine, Scalar};

/// Calculate a BBS blind signature from a secret key, over a header, a set of messages, and optionally a commitment
/// value. If supplied, the commitment value MUST be accompanied by its proof of correctness (commitment_with_proof, as
/// outputted by the commit operation).
///
/// The blind sign operation makes use of the `finalize_blind_sign` procedure and the calculate_B procedure. The
/// calculate_B procedure is defined to return an array of elements, to establish extendability of the scheme by
/// allowing the calculate_B operation to return more elements than just the point to be signed.
///
/// - `secret_key`: a scalar representing the secret key.
/// - `public_key`: an octet string representing the public key.
/// - `commitment_with_proof`: an octet string, representing a serialized commitment and commitment proof, as the first
///         element outputted by the commit operation. If not supplied, it defaults to an empty octet string.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of octet strings containing the messages to be signed.
/// - `cipher`: a cipher suite.
///
/// Return a blind BBS signature.
pub fn sign(
    secret_key: &Scalar,
    public_key: &[u8],
    commitment_with_proof: Option<&[u8]>,
    header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    cipher: &Cipher,
) -> Signature {
    let empty_commitment_with_proof_vec = vec![];
    let empty_messages_vec = vec![];

    let inner_commit_with_proof = commitment_with_proof.unwrap_or(&empty_commitment_with_proof_vec);
    let inner_messages = messages.unwrap_or(&empty_messages_vec);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || BLIND_H2G_HM2S_", where <cipher_suite_id> is defined by the
    //      cipher suite and "BLIND_H2G_HM2S_" is an ASCII string composed of 15 bytes.

    let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. M := len(commitment_with_proof).
    // 3. If M != 0, M := M - octet_point_length - octet_scalar_length.
    // 4. M := M / octet_scalar_length.
    // 5. If M < 0, return INVALID.

    let l = inner_messages.len();
    let mut m = inner_commit_with_proof.len();
    if m != 0 {
        m -= LENGTH_G1_POINT - LENGTH_SCALAR;
    }
    m /= LENGTH_SCALAR;

    // Procedure:
    //
    // 1. generators := create_generators(L + 1, api_id).
    // 2. blind_generators := create_generators(M + 1, "BLIND_" || api_id).
    // 3. commit := deserialize_and_validate_commit(commitment_with_proof, blind_generators, api_id).
    // 4. If commit is INVALID, return INVALID.
    // 5. message_scalars := messages_to_scalars(messages, api_id).
    // 6. res := calculate_B(generators, commit, message_scalars).
    // 7. If res is INVALID, return INVALID.
    // 8. (B) := res.
    // 9. blind_sig := finalize_blind_sign(secret_key, public_key, B, generators, blind_generators, header, api_id).
    // 10. If blind_sig is INVALID, return INVALID.
    // 11. Return blind_sig.

    let generators = create_generators(l + 1, Some(&api_id), cipher);
    let blind_api_id = [PADDING_BLIND, cipher.id, PADDING_BLIND, PADDING_API_ID].concat();
    let blind_generators = create_generators(m + 1, Some(&blind_api_id), cipher);
    let commit = deserialize_and_validate_commit(
        Some(&inner_commit_with_proof),
        Some(&blind_generators),
        Some(&api_id),
        cipher,
    );
    let message_scalars = messages_to_scalars(inner_messages, Some(&api_id), cipher);
    let res = calculate_b(&generators, Some(&commit), Some(&message_scalars));
    let b: G1Affine = res.into();
    finalize_blind_sign(
        secret_key,
        public_key,
        &b,
        &generators,
        Some(&blind_generators),
        header,
        Some(&api_id),
        cipher,
    )
}

/// Verify a blind BBS signature, given the signer's public key, a header, a set of, known to the signer, messages, and
/// if used, a set of committed messages, and the `secret_prover_blind` value returned by the commit operation.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a BBS Signature.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of octet strings containing the messages to be signed.
/// - `committed_messages`: a list of octet strings containing the committed messages.
/// - `secret_prover_blind`: a scalar representing the secret prover blind value.
/// - `cipher`: a cipher suite.
///
/// Return `true` if the signature is valid, `false` otherwise.
pub fn verify(
    public_key: &[u8],
    signature: &Signature,
    header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    committed_messages: Option<&Vec<&[u8]>>,
    secret_prover_blind: Option<&Scalar>,
    cipher: &Cipher,
) -> bool {
    let empty_messages_vec = vec![];
    let empty_committed_messages_vec = vec![];
    let default_secret_prover_blind = Scalar::zero();

    let inner_messages = messages.unwrap_or(&empty_messages_vec);
    let inner_committed_messages = committed_messages.unwrap_or(&empty_committed_messages_vec);
    let inner_secret_prover_blind = secret_prover_blind.unwrap_or(&default_secret_prover_blind);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || BLIND_H2G_HM2S_".

    let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

    // Procedure:
    //
    // 1. (message_scalars, generators) := prepare_parameters(
    //          messages,
    //          committed_messages,
    //          len(messages) + 1,
    //          len(committed_messages) + 1,
    //          secret_prover_blind,
    //          api_id).
    // 2. res := core_verify(
    //          public_key,
    //          signature,
    //          generators,
    //          header,
    //          message_scalars,
    //          api_id).
    // 3. Return res.

    let (message_scalars, generators) = prepare_parameters(
        Some(&inner_messages),
        Some(&inner_committed_messages),
        inner_messages.len() + 1,
        inner_committed_messages.len() + 1,
        Some(&inner_secret_prover_blind),
        Some(&api_id),
        cipher,
    );
    crate::signature::core::verify(
        public_key,
        signature,
        &generators,
        header,
        Some(&message_scalars),
        Some(&api_id),
        cipher,
    )
}

/// Create a BBS proof, which is a zero-knowledge proof-of-knowledge of a BBS signature, while optionally disclosing any
/// subset of the signed messages. Note that in contrast to the pure proof generation operation, the blind proof
/// generation operation defined here accepts two more lists of messages and disclosed indexes, one for the messages
/// known to the signer (`messages`) and the corresponding disclosed indexes (`disclosed_indexes`), and one for the
/// messages committed by the prover (`committed_messages`) and the corresponding disclosed indexes
/// (`disclosed_commitment_indexes`).
///
/// Furthermore, the operation also expects the `secret_prover_blind` (as returned from the commit operation) value. If
/// the BBS signature is generated using a commitment value, then the `secret_prover_blind` returned by the commit
/// operation used to generate the commitment should be provided to the proof generation operation, otherwise the
/// resulting proof will be invalid.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a BBS Signature.
/// - `header`: an octet string representing the signed header.
/// - `presentation_header`: an octet string representing the presentation header.
/// - `messages`: a list of octet strings representing the signed messages.
/// - `committed_messages`: a list of octet strings representing the committed messages.
/// - `disclosed_indexes`: a list of integers in ascending order representing the indexes of disclosed messages.
/// - `disclosed_commitment_indexes`: a list of integers representing the indexes of disclosed commitment messages.
/// - `secret_prover_blind`: a scalar representing the secret prover blind value.
/// - `cipher`: a cipher suite.
///
/// Return a BBS proof.
pub fn prove(
    public_key: &[u8],
    signature: &Signature,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    committed_messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    disclosed_commitment_indexes: Option<&Vec<usize>>,
    secret_prover_blind: Option<&Scalar>,
    cipher: &Cipher,
) -> Proof {
    let empty_message_vec = vec![];
    let empty_committed_message_vec = vec![];
    let empty_disclosed_index_vec = vec![];
    let empty_disclosed_commitment_index_vec = vec![];
    let default_secret_prover_blind = Scalar::zero();

    let inner_messages = messages.unwrap_or(&empty_message_vec);
    let inner_committed_messages = committed_messages.unwrap_or(&empty_committed_message_vec);
    let inner_disclosed_indexes = disclosed_indexes.unwrap_or(&empty_disclosed_index_vec);
    let inner_disclosed_commitment_indexes =
        disclosed_commitment_indexes.unwrap_or(&empty_disclosed_commitment_index_vec);
    let inner_secret_prover_blind = secret_prover_blind.unwrap_or(&default_secret_prover_blind);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || BLIND_H2G_HM2S_".

    let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. M := len(committed_messages).
    // 3. If len(disclosed_indexes) > L, return INVALID.
    // 4. For i in disclosed_indexes, if i < 0 or i >= L, return INVALID.
    // 5. If len(disclosed_commitment_indexes) > M, return INVALID.
    // 6. For j in disclosed_commitment_indexes, if j < 0 or j >= M, return INVALID.

    let l = inner_messages.len();
    let m = inner_committed_messages.len();
    if inner_disclosed_indexes.len() > l {
        panic!("Invalid disclosed indexes");
    }
    inner_disclosed_indexes.iter().for_each(|&i| {
        if i >= l {
            panic!("Invalid disclosed indexes");
        }
    });
    if inner_disclosed_commitment_indexes.len() > m {
        panic!("Invalid disclosed commitment indexes");
    }
    inner_disclosed_commitment_indexes.iter().for_each(|&j| {
        if j >= m {
            panic!("Invalid disclosed commitment indexes");
        }
    });

    // Procedure:
    //
    // 1. (message_scalars, generators) := prepare_parameters(
    //          messages,
    //          committed_messages,
    //          len(messages) + 1,
    //          len(committed_messages) + 1,
    //          secret_prover_blind,
    //          api_id).
    // 2. indexes := ().
    // 3. indexes.append(disclosed_indexes).
    // 4. For j in disclosed_commitment_indexes: indexes.append(j + L + 1).
    // 5. proof := core_prove(
    //          public_key,
    //          signature,
    //          generators,
    //          header,
    //          presentation_header,
    //          message_scalars,
    //          indexes,
    //          api_id).
    // 6. Return proof.

    let (message_scalars, generators) = prepare_parameters(
        Some(&inner_messages),
        Some(&inner_committed_messages),
        l + 1,
        m + 1,
        Some(&inner_secret_prover_blind),
        Some(&api_id),
        cipher,
    );

    let mut indexes: Vec<usize> = Vec::new();
    indexes.extend(inner_disclosed_indexes);
    inner_disclosed_commitment_indexes.iter().for_each(|&j| {
        indexes.push(j + l + 1);
    });

    crate::proof::core::prove(
        public_key,
        signature,
        &generators,
        header,
        presentation_header,
        Some(&message_scalars),
        Some(&indexes),
        Some(&api_id),
        cipher,
    )
}

/// Validate a BBS proof, given the signer's public key, a header, a presentation header, two arrays of disclosed
/// messages (the ones known to the signer and the ones committed by the prover), and two corresponding arrays of
/// indexes those messages had in the original vectors of signed messages.
///
/// In addition, this blind proof validation operation also accepts an integer `L`, representing the total number of
/// signed messages known by the signer.
///
/// - `public_key`: an octet string representing the public key.
/// - `proof`: a BBS proof.
/// - `header`: an octet string representing the signed header.
/// - `presentation_header`: an octet string representing the presentation header.
/// - `l`: an integer representing the total number of signed messages known by the signer.
/// - `disclosed_messages`: a list of octet strings representing the disclosed messages.
/// - `disclosed_commitment_messages`: a list of octet strings representing the disclosed commitment messages.
/// - `disclosed_indexes`: a list of integers representing the indexes of disclosed messages.
/// - `disclosed_commitment_indexes`: a list of integers representing the indexes of disclosed commitment messages.
/// - `cipher`: a cipher suite.
///
/// Return `true` if the proof is valid, `false` otherwise.
pub fn validate(
    public_key: &[u8],
    proof: &Proof,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    l: Option<usize>,
    disclosed_messages: Option<&Vec<&[u8]>>,
    disclosed_commitment_messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    disclosed_commitment_indexes: Option<&Vec<usize>>,
    cipher: &Cipher,
) -> bool {
    let empty_disclosed_messages_vec = vec![];
    let empty_disclosed_commitment_messages_vec = vec![];
    let empty_disclosed_indexes_vec = vec![];
    let empty_disclosed_commitment_indexes_vec = vec![];

    let inner_disclosed_messages = disclosed_messages.unwrap_or(&empty_disclosed_messages_vec);
    let inner_disclosed_commitment_messages =
        disclosed_commitment_messages.unwrap_or(&empty_disclosed_commitment_messages_vec);
    let inner_disclosed_indexes = disclosed_indexes.unwrap_or(&empty_disclosed_indexes_vec);
    let inner_disclosed_commitment_indexes =
        disclosed_commitment_indexes.unwrap_or(&empty_disclosed_commitment_indexes_vec);
    let l = l.unwrap_or(0);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || BLIND_H2G_HM2S_".
    // - octet_point_length: the length of the octet string representation of a G1 point.
    // - octet_scalar_length: the length of the octet string representation of a scalar.

    let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

    // Deserialization:
    //
    // 1. proof_len_floor := 2 * octet_point_length + 3 * octet_scalar_length.
    // 2. If len(proof) < proof_len_floor, return INVALID.
    // 3. U := floor((len(proof) - proof_len_floor) / octet_scalar_length).
    // 4. total_no_messages := len(disclosed_indexes) + len(disclosed_commitment_indexes) + U.
    // 5. M := total_no_messages - L.

    let u = proof.m_hats.len();
    let total_no_messages =
        inner_disclosed_indexes.len() + inner_disclosed_commitment_indexes.len() + u;
    let m = total_no_messages - l;

    // Procedure:
    //
    // 1. (message_scalars, generators) := prepare_parameters(
    //          disclosed_messages,
    //          disclosed_commitment_messages,
    //          L + 1,
    //          M,
    //          None,
    //          api_id).
    // 2. indexes := ().
    // 3. indexes.append(disclosed_indexes).
    // 4. For j in disclosed_commitment_indexes: indexes.append(j + L + 1).
    // 5. result := core_proof_verify(
    //          public_key,
    //          proof,
    //          generators,
    //          header,
    //          presentation_header,
    //          message_scalars,
    //          indexes,
    //          api_id).
    // 6. Return result.

    let (message_scalars, generators) = prepare_parameters(
        Some(&inner_disclosed_messages),
        Some(&inner_disclosed_commitment_messages),
        l + 1,
        m,
        None,
        Some(&api_id),
        cipher,
    );
    let mut indexes: Vec<usize> = Vec::new();
    indexes.extend(inner_disclosed_indexes);
    inner_disclosed_commitment_indexes.iter().for_each(|&j| {
        indexes.push(j + l + 1);
    });
    crate::proof::core::verify(
        public_key,
        proof,
        &generators,
        header,
        presentation_header,
        Some(&message_scalars),
        Some(&indexes),
        Some(&api_id),
        cipher,
    )
}
