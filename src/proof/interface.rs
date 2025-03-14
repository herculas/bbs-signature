use super::Proof;

use crate::signature::Signature;

use crate::suite::cipher::Cipher;
use crate::suite::constants::{PADDING_API_ID, PADDING_BLIND, PADDING_PSEUDONYM};

use crate::utils::blind::prepare_parameters;
use crate::utils::generator::create_generators;
use crate::utils::scalar::messages_to_scalars;

use bls12_381::{G1Affine, Scalar};

/// Create a BBS proof, which is a zero-knowledge proof-of-knowledge of a BBS Signature, while optionally disclosing any
/// subset of the signed messages.
///
/// Other than the signer's public key, the BBS Signature and the signed header and messages, this operation also
/// accepts a presentation header, which will be bound to the resulting proof. To indicate which of the messages are to
/// be disclosed, the operation accepts a list of integers in ascending order, each representing the index of a message
/// in the list of signed messages.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a BBS Signature.
/// - `header`: an octet string representing the signed header.
/// - `presentation_header`: an octet string representing the presentation header.
/// - `messages`: a list of octet strings representing the signed messages.
/// - `disclosed_indexes`: a list of integers representing the indexes of disclosed messages.
/// - `cipher`: a cipher suite.
///
/// Return a BBS proof.
pub(crate) fn prove(
    public_key: &[u8],
    signature: &Signature,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    cipher: &Cipher,
    random_scalar_sampler: Option<fn(usize) -> Vec<Scalar>>,
) -> Proof {
    let default_messages = vec![];
    let messages = messages.unwrap_or(&default_messages);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || H2G_HM2S_".

    let api_id = [cipher.id, PADDING_API_ID].concat();

    // Procedure:
    //
    // 1. message_scalars := messages_to_scalars(messages, api_id).
    // 2. generators := create_generators(len(messages) + 1, api_id).
    // 3. proof := core_prove(
    //          public_key,
    //          signature,
    //          generators,
    //          header,
    //          presentation_header,
    //          message_scalars,
    //          disclosed_indexes,
    //          api_id,
    //          cipher).
    // 4. If proof is INVALID, return INVALID.
    // 5. Return proof.

    let message_scalars = messages_to_scalars(messages, Some(&api_id), cipher);
    let generators = create_generators(messages.len() + 1, Some(&api_id), cipher);
    super::core::prove(
        public_key,
        signature,
        &generators,
        header,
        presentation_header,
        Some(&message_scalars),
        disclosed_indexes,
        Some(&api_id),
        cipher,
        random_scalar_sampler,
    )
}

/// Validate a BBS proof, given the signer's public key, a header, a presentation header, a list of disclosed messages,
/// and the indexes of those messages in the original list of signed messages.
///
/// Validating the proof guarantees the authenticity and integrity of the header and the disclosed messages, as well as
/// the knowledge of a valid BBS Signature.
///
/// - `public_key`: an octet string representing the public key.
/// - `proof`: a BBS proof.
/// - `header`: an octet string representing the signed header.
/// - `presentation_header`: an octet string representing the presentation header.
/// - `disclosed_messages`: a list of octet strings representing the disclosed messages.
/// - `disclosed_indexes`: a list of integers representing the indexes of disclosed messages.
/// - `cipher`: a cipher suite.
///
/// Return `true` if the proof is valid, `false` otherwise.
pub(crate) fn validate(
    public_key: &[u8],
    proof: &Proof,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    disclosed_messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    cipher: &Cipher,
) -> bool {
    let default_disclosed_messages = vec![];
    let disclosed_messages = disclosed_messages.unwrap_or(&default_disclosed_messages);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || H2G_HM2S_".
    // - octet_point_length: the length of the octet string representation of a G1 point.
    // - octet_scalar_length: the length of the octet string representation of a scalar.

    let api_id = [cipher.id, PADDING_API_ID].concat();

    // Deserialization:
    //
    // 1. proof_len_floor := 3 * octet_point_length + 4 * octet_scalar_length.
    // 2. If len(proof) < proof_len_floor, return INVALID.
    // 3. U := floor((len(proof) - proof_len_floor) / octet_scalar_length).
    // 4. R := len(disclosed_indexes).

    let u = proof.m_hats.len();
    let r = disclosed_messages.len();

    // Procedure:
    //
    // 1. message_scalars := messages_to_scalars(disclosed_messages, api_id).
    // 2. generators := create_generators(U + R + 1, api_id).
    // 3. result := core_verify(
    //          public_key,
    //          proof,
    //          generators,
    //          header,
    //          presentation_header,
    //          message_scalars,
    //          disclosed_indexes,
    //          api_id,
    //          cipher).
    // 4. Return result.

    let message_scalars = messages_to_scalars(disclosed_messages, Some(&api_id), cipher);
    let generators = create_generators(u + r + 1, Some(&api_id), cipher);
    super::core::validate(
        public_key,
        proof,
        &generators,
        header,
        presentation_header,
        Some(&message_scalars),
        disclosed_indexes,
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
pub fn blind_prove(
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
    random_scalar_sampler: Option<fn(usize) -> Vec<Scalar>>,
) -> Proof {
    let default_messages = vec![];
    let default_committed_messages = vec![];
    let default_disclosed_indexes = vec![];
    let default_disclosed_commitment_indexes = vec![];
    let default_secret_prover_blind = Scalar::zero();

    let messages = messages.unwrap_or(&default_messages);
    let committed_messages = committed_messages.unwrap_or(&default_committed_messages);
    let disclosed_indexes = disclosed_indexes.unwrap_or(&default_disclosed_indexes);
    let disclosed_commitment_indexes =
        disclosed_commitment_indexes.unwrap_or(&default_disclosed_commitment_indexes);
    let secret_prover_blind = secret_prover_blind.unwrap_or(&default_secret_prover_blind);

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

    let l = messages.len();
    let m = committed_messages.len();
    if disclosed_indexes.len() > l {
        panic!("Invalid disclosed indexes");
    }
    disclosed_indexes.iter().for_each(|&i| {
        if i >= l {
            panic!("Invalid disclosed indexes");
        }
    });
    if disclosed_commitment_indexes.len() > m {
        panic!("Invalid disclosed commitment indexes");
    }
    disclosed_commitment_indexes.iter().for_each(|&j| {
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
        Some(&messages),
        Some(&committed_messages),
        l + 1,
        m + 1,
        Some(&secret_prover_blind),
        Some(&api_id),
        cipher,
    );

    let mut indexes: Vec<usize> = Vec::new();
    indexes.extend(disclosed_indexes);
    disclosed_commitment_indexes.iter().for_each(|&j| {
        indexes.push(j + l + 1);
    });

    super::core::prove(
        public_key,
        signature,
        &generators,
        header,
        presentation_header,
        Some(&message_scalars),
        Some(&indexes),
        Some(&api_id),
        cipher,
        random_scalar_sampler,
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
pub fn blind_validate(
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
    let default_disclosed_messages = vec![];
    let default_disclosed_commitment_messages = vec![];
    let default_disclosed_indexes = vec![];
    let default_disclosed_commitment_indexes = vec![];

    let disclosed_messages = disclosed_messages.unwrap_or(&default_disclosed_messages);
    let disclosed_commitment_messages =
        disclosed_commitment_messages.unwrap_or(&default_disclosed_commitment_messages);
    let disclosed_indexes = disclosed_indexes.unwrap_or(&default_disclosed_indexes);
    let disclosed_commitment_indexes =
        disclosed_commitment_indexes.unwrap_or(&default_disclosed_commitment_indexes);

    let l = l.unwrap_or(0);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || BLIND_H2G_HM2S_".
    // - octet_point_length: the length of the octet string representation of a G1 point.
    // - octet_scalar_length: the length of the octet string representation of a scalar.

    // this is a bug in the spec, the api_id should be BLIND_H2G_HM2S_ instead of H2G_HM2S_
    let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

    // Deserialization:
    //
    // 1. proof_len_floor := 2 * octet_point_length + 3 * octet_scalar_length.
    // 2. If len(proof) < proof_len_floor, return INVALID.
    // 3. U := floor((len(proof) - proof_len_floor) / octet_scalar_length).
    // 4. total_no_messages := len(disclosed_indexes) + len(disclosed_commitment_indexes) + U.
    // 5. M := total_no_messages - L.

    let u = proof.m_hats.len();
    let total_no_messages = disclosed_indexes.len() + disclosed_commitment_indexes.len() + u;
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
        Some(&disclosed_messages),
        Some(&disclosed_commitment_messages),
        l + 1,
        m,
        None,
        Some(&api_id),
        cipher,
    );
    let mut indexes: Vec<usize> = Vec::new();
    indexes.extend(disclosed_indexes);
    disclosed_commitment_indexes.iter().for_each(|&j| {
        indexes.push(j + l + 1);
    });
    super::core::validate(
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

/// Calculate a BBS proof with a pseudonym. The BBS proof is extended to include a zero-knowledge proof-of-correctness
/// of the pseudonym value, i.e., that is correctly calculated using the undisclosed pseudonym secret, and that is
/// "bound" to the underlying BBS signature (i.e., that the `nym_secret` value is signed by the signer).
///
/// Validating the proof guarantees the authenticity and integrity of the header, the presentation header, and disclosed
/// messages, knowledge of a valid BBS signature as well as the correctness of the ownership of the pseudonym.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a BBS Signature.
/// - `header`: an octet string representing the signed header.
/// - `presentation_header`: an octet string representing the presentation header.
/// - `messages`: a list of octet strings representing the signed messages.
/// - `disclosed_indexes`: a list of integers representing the indexes of disclosed messages.
/// - `cipher`: a cipher suite.
///
/// Return a BBS proof and a pseudonym.
pub(crate) fn blind_prove_with_nym(
    public_key: &[u8],
    signature: &Signature,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    nym_secret: Option<&Scalar>,
    context_id: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    committed_messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    disclosed_commitment_indexes: Option<&Vec<usize>>,
    secret_prover_blind: Option<&Scalar>,
    cipher: &Cipher,
    random_scalar_sampler: Option<fn(usize) -> Vec<Scalar>>,
) -> (Proof, G1Affine) {
    let default_nym_secret = Scalar::zero();
    let default_context_id = vec![];
    let default_messages = vec![];
    let default_committed_messages = vec![];
    let default_disclosed_indexes = vec![];
    let default_disclosed_commitment_indexes = vec![];
    let default_secret_prover_blind = Scalar::zero();

    let nym_secret = nym_secret.unwrap_or(&default_nym_secret);
    let context_id = context_id.unwrap_or(&default_context_id);
    let messages = messages.unwrap_or(&default_messages);
    let committed_messages = committed_messages.unwrap_or(&default_committed_messages);
    let disclosed_indexes = disclosed_indexes.unwrap_or(&default_disclosed_indexes);
    let disclosed_commitment_indexes =
        disclosed_commitment_indexes.unwrap_or(&default_disclosed_commitment_indexes);
    let secret_prover_blind = secret_prover_blind.unwrap_or(&default_secret_prover_blind);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || H2G_HM2S_PSEUDONYM_".

    let api_id = [cipher.id, PADDING_API_ID, PADDING_PSEUDONYM].concat();

    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. M := len(committed_messages).
    // 3. If len(disclosed_indexes) > L, return INVALID.
    // 4. For i in disclosed_indexes, if i < 0 or i >= L, return INVALID.
    // 5. If len(disclosed_commitment_indexes) > M, return INVALID.
    // 6. For j in disclosed_commitment_indexes, if j < 0 or j >= M, return INVALID.

    let l = messages.len();
    let m = committed_messages.len();
    if disclosed_indexes.len() > l {
        panic!("Invalid disclosed indexes");
    }
    disclosed_indexes.iter().for_each(|&i| {
        if i >= l {
            panic!("Invalid disclosed indexes");
        }
    });
    if disclosed_commitment_indexes.len() > m {
        panic!("Invalid disclosed commitment indexes");
    }
    disclosed_commitment_indexes.iter().for_each(|&j| {
        if j >= m {
            panic!("Invalid disclosed commitment indexes");
        }
    });

    // Procedure:
    //
    // 1. (message_scalars, generators) := prepare_parameters(
    //          messages,
    //          committed_messages,
    //          L + 1,
    //          M + 2,
    //          secret_prover_blind,
    //          api_id).
    // 2. message_scalars.append(nym_secret).
    // 3. indexes := ().
    // 4. indexes.append(disclosed_indexes).
    // 5. For j in disclosed_commitment_indexes: indexes.append(j + L + 1).
    // 6. (proof, pseudonym) := core_prove_with_nym(
    //          public_key,
    //          signature,
    //          generators,
    //          header,
    //          presentation_header,
    //          context_id,
    //          message_scalars,
    //          indexes,
    //          api_id).
    // 6. Return (proof, pseudonym).

    let (message_scalars, generators) = prepare_parameters(
        Some(&messages),
        Some(&committed_messages),
        l + 1,
        m + 2,
        Some(&secret_prover_blind),
        Some(&api_id),
        cipher,
    );
    let mut message_scalars = message_scalars;
    message_scalars.push(nym_secret.clone());

    let mut indexes: Vec<usize> = Vec::new();
    indexes.extend(disclosed_indexes);
    disclosed_commitment_indexes.iter().for_each(|&j| {
        indexes.push(j + l + 1);
    });

    super::core::prove_with_nym(
        public_key,
        signature,
        &context_id,
        &generators,
        header,
        presentation_header,
        Some(&message_scalars),
        Some(&indexes),
        Some(&api_id),
        cipher,
        random_scalar_sampler,
    )
}

/// Validate a BBS proof with a pseudonym, given the signer's public key, the proof, the pseudonym, the context
/// identifier that was used to create it, a header and presentation header, the disclosed messages and committed
/// messages as well as the indexes those messages had in the original vectors of signed messages.
///
/// Validating the proof also validates the correctness and ownership by the prover of the received pseudonym.
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
pub fn blind_validate_with_nym(
    public_key: &[u8],
    proof: &Proof,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    pseudonym: Option<&G1Affine>,
    context_id: Option<&[u8]>,
    l: Option<usize>,
    disclosed_messages: Option<&Vec<&[u8]>>,
    disclosed_commitment_messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    disclosed_commitment_indexes: Option<&Vec<usize>>,
    cipher: &Cipher,
) -> bool {
    let default_pseudonym = G1Affine::identity();
    let default_context_id = vec![];
    let default_disclosed_messages = vec![];
    let default_disclosed_commitment_messages = vec![];
    let default_disclosed_indexes = vec![];
    let default_disclosed_commitment_indexes = vec![];

    let pseudonym = pseudonym.unwrap_or(&default_pseudonym);
    let context_id = context_id.unwrap_or(&default_context_id);
    let disclosed_messages = disclosed_messages.unwrap_or(&default_disclosed_messages);
    let disclosed_commitment_messages =
        disclosed_commitment_messages.unwrap_or(&default_disclosed_commitment_messages);
    let disclosed_indexes = disclosed_indexes.unwrap_or(&default_disclosed_indexes);
    let disclosed_commitment_indexes =
        disclosed_commitment_indexes.unwrap_or(&default_disclosed_commitment_indexes);

    let l = l.unwrap_or(0);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || H2G_HM2S_PSEUDONYM_".

    let api_id = [cipher.id, PADDING_API_ID, PADDING_PSEUDONYM].concat();

    // Deserialization:
    //
    // 1. proof_len_floor := 2 * octet_point_length + 3 * octet_scalar_length.
    // 2. If len(proof) < proof_len_floor, return INVALID.
    // 3. U := floor((len(proof) - proof_len_floor) / octet_scalar_length).
    // 4. total_no_messages := len(disclosed_indexes) + len(disclosed_commitment_indexes) + U.
    // 5. M := total_no_messages - L.

    let u = proof.m_hats.len();
    let total_no_messages = disclosed_indexes.len() + disclosed_commitment_indexes.len() + u;
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
    // 5. result := core_proof_verify_with_pseudonym(
    //          public_key,
    //          proof,
    //          pseudonym,
    //          context_id,
    //          generators,
    //          header,
    //          presentation_header,
    //          message_scalars,
    //          indexes,
    //          api_id).
    // 6. Return result.

    let (message_scalars, generators) = prepare_parameters(
        Some(&disclosed_messages),
        Some(&disclosed_commitment_messages),
        l + 1,
        m,
        None,
        Some(&api_id),
        cipher,
    );
    let mut indexes: Vec<usize> = Vec::new();
    indexes.extend(disclosed_indexes);
    disclosed_commitment_indexes.iter().for_each(|&j| {
        indexes.push(j + l + 1);
    });

    super::core::validate_with_nym(
        public_key,
        proof,
        &pseudonym,
        &context_id,
        &generators,
        header,
        presentation_header,
        Some(&message_scalars),
        Some(&indexes),
        Some(&api_id),
        cipher,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::subroutine::{calculate_challenge, finalize_proof, initialize_proof};
    use crate::suite::instance::{BLS12_381_G1_XMD_SHA_256, BLS12_381_G1_XOF_SHAKE_256};
    use crate::utils::format::{bytes_to_hex, hex_to_bytes};
    use crate::utils::scalar::seeded_random_scalars;
    use crate::utils::serialize::{Deserialize, Serialize};
    use bls12_381::Scalar;

    #[test]
    fn shake_256_single_message() {
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
        let msg_bytes =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7\
                    1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0\
                    b97a12025a283d78b7136bb9825d04ef",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2",
        ));

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;

        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(2, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(&vec![&msg_bytes], Some(&api_id), &cipher);
        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde];

        let disclosed_indexes = vec![0];
        let undisclosed_indexes = vec![];

        // disclosed_messages are the messages with disclosed_indexes as indexes in the message_scalars list
        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&vec![&msg_bytes]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "\
                91a10e73cf4090812e8ea25f31aaa61be53fcb42ce86e9f0e5df6f6dac4c3eee\
                62ac846b0b83a5cfcbe78315175a4961"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "\
                988f3d473186634e41478dc4527cf240e64de23a763037454d39a876862ebc61\
                7738ba6c458142e3746b01eab58ca8d7"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c7\
                37fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa\
                5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceed\
                b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57\
                e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625\
                e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d\
                93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775a\
                b32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d679\
                1940ccbd75e719537f7ace6ee817298d"
        );
        assert!(verified);
    }

    #[test]
    fn shake_256_multiple_messages() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08\
                    faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67\
                    fb7d3253e1e2acbcf90ef59a6911931e",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2",
        ));

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;

        let api_id = [cipher.id, PADDING_API_ID].concat();
        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde];
        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let undisclosed_indexes = vec![];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "8890adfc78da24768d59dbfdb3f380e2793e9018b20c23e9ba05baa60f1b21456bc047a5d27049dab5dc6a94696ce711"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "a49f953636d3651a3ae6fe45a99a2e4fec079eef3be8b8a6a4ba70885d7e028642f7224e9f451529915c88a7edc59fbe"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                91b0f598268c57b67bc9e55327c3c2b9b1654be89a0cf963ab392fa9e1637c56\
                5241d71fd6d7bbd7dfe243de85a9bac8b7461575c1e13b5055fed0b51fd0ec14\
                33096607755b2f2f9ba6dc614dfa456916ca0d7fc6482b39c679cfb747a50ea1\
                b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8\
                fbdf45cd19fde45038bb310d5135f5205fc550b077e381fb3a3543dca31a0d8b\
                ba97bc0b660a5aa239eb74921e184aa3035fa01eaba32f52029319ec3df4fa4a\
                4f716edb31a6ce19a19dbb971380099345070bd0fdeecf7c4774a33e0a116e06\
                9d5e215992fb637984802066dee6919146ae50b70ea52332dfe57f6e05c66e99\
                f1764d8b890d121d65bfcc2984886ee0"
        );
        assert!(verified);
    }

    #[test]
    fn shake_256_multiple_messages_partial_disclosed() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08\
                    faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67\
                    fb7d3253e1e2acbcf90ef59a6911931e",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089",
        ));
        let m_tildes = [
            Scalar::deserialize(&hex_to_bytes(
                "020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995",
            )),
        ];

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde]
            .iter()
            .chain(m_tildes.iter())
            .map(|s| *s)
            .collect::<Vec<_>>();

        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 2, 4, 6];
        let undisclosed_indexes = vec![1, 3, 5, 7, 8, 9];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&vec![&msg_1, &msg_3, &msg_5, &msg_7]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "8b497dd4dcdcf7eb58c9b43e57e06bcea3468a223ae2fc015d7a86506a952d68055e73f5a5847e58f133ea154256d0da"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "8655584d3da1313f881f48c239384a5623d2d292f08dae7ac1d8129c19a02a89b82fa45de3f6c2c439510fce5919656f"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac\
                279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3b\
                a036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0\
                b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595\
                ea1b13330615011050a0dfcffdb21af356dd39bf8bcbfd41bf95d913f4c9b297\
                9e1ed2ca10ac7e881bb6a271722549681e398d29e9ba4eac8848b168eddd5e4a\
                cec7df4103e2ed165e6e32edc80f0a3b28c36fb39ca19b4b8acee570deadba2d\
                a9ec20d1f236b571e0d4c2ea3b826fe924175ed4dfffbf18a9cfa98546c241ef\
                b9164c444d970e8c89849bc8601e96cf228fdefe38ab3b7e289cac859e68d9cb\
                b0e648faf692b27df5ff6539c30da17e5444a65143de02ca64cee7b0823be658\
                65cdc310be038ec6b594b99280072ae067bad1117b0ff3201a5506a8533b925c\
                7ffae9cdb64558857db0ac5f5e0f18e750ae77ec9cf35263474fef3f78138c7a\
                1ef5cfbc878975458239824fad3ce05326ba3969b1f5451bd82bd1f8075f3d32\
                ece2d61d89a064ab4804c3c892d651d11bc325464a71cd7aacc2d956a811aaff\
                13ea4c35cef7842b656e8ba4758e7558"
        );
        assert!(verified);
    }

    #[test]
    fn shake_256_multiple_messages_partial_disclosed_no_header() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15\
                    f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d\
                    3ca745ecbe39f655ea61fb700137fded",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089",
        ));
        let m_tildes = [
            Scalar::deserialize(&hex_to_bytes(
                "020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995",
            )),
        ];

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde]
            .iter()
            .chain(m_tildes.iter())
            .map(|s| *s)
            .collect::<Vec<_>>();

        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 2, 4, 6];
        let undisclosed_indexes = vec![1, 3, 5, 7, 8, 9];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            None,
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            None,
            Some(&presentation_header),
            Some(&vec![&msg_1, &msg_3, &msg_5, &msg_7]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "a5405cc2c5965dda18714ab35f4d4a7ae4024f388fa7a5ba71202d4455b50b316ec37b360659e3012234562fa8989980"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "9827a40454cdc90a70e9c927f097019dbdd84768babb10ebcb460c2d918e1ce1c0512bf2cc49ed7ec476dfcde7a6a10c"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "333d8686761cff65a3a2ef20bfa217d37bdf19105e87c210e9ce64ea1210a157"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                8ac336eea1d278656372d9914483c3d3b3069dfa4a7862293ac021dfeeebca93\
                cadd7eb2b818f7b89719cdeffa5aa85989a7d691be11b1929a2bf089bfe9f2ad\
                c2c06788edc30585546efb74877f34ad91f0d6923b4ed7a53c49051dda8d056a\
                95644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a\
                5d1d9e6bd05a4dee6a50dd277ffc646f2429372f3ad9d5946ffeb53f24d41ffc\
                c83c32cbb68afc9b6e0b64eebd24c69c6a7bd3bca8a6394ed8ae315abd555a69\
                96f34d9da7680447947b3f35f54c38b562e990ee4d17a21569af4fc02f2991e6\
                db78cc32d3ef9f6069fc5c2d47c8d8ff116dfb8a59641641961b854427f67649\
                df14ab6e63f2d0d2a0cba2b2e1e835d20cd45e41f274532e9d50f31a690e5fef\
                1c1456b65c668b80d8ec17b09bd5fb3b2c4edd6d6f5f790a5d6da22eb9a1aa21\
                96d1a607f3c753813ba2bc6ece15d35263218fc7667c5f0fabfffe74745a8000\
                e0415c8dafd5654ce6850ac2c6485d02433fdaebd9993f8b86a2eebb3beb10b4\
                cc7735330384a3f4dfd4d5b21998ad0227b37e736cf9c144a0386f28cccf27a0\
                1e50aab45dda8275eb877728e77d2055309dba8c6604e7cff0d2c46ce6026b8e\
                232c192955f909da6e47c2130c7e3f4f"
        );
        assert!(verified);
    }

    #[test]
    fn shake_256_multiple_messages_partial_disclosed_no_presentation_header() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08\
                    faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67\
                    fb7d3253e1e2acbcf90ef59a6911931e",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089",
        ));
        let m_tildes = [
            Scalar::deserialize(&hex_to_bytes(
                "020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995",
            )),
        ];

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde]
            .iter()
            .chain(m_tildes.iter())
            .map(|s| *s)
            .collect::<Vec<_>>();

        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 2, 4, 6];
        let undisclosed_indexes = vec![1, 3, 5, 7, 8, 9];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            None,
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            None,
            Some(&vec![&msg_1, &msg_3, &msg_5, &msg_7]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "8b497dd4dcdcf7eb58c9b43e57e06bcea3468a223ae2fc015d7a86506a952d68055e73f5a5847e58f133ea154256d0da"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "8655584d3da1313f881f48c239384a5623d2d292f08dae7ac1d8129c19a02a89b82fa45de3f6c2c439510fce5919656f"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac\
                279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3b\
                a036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0\
                b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595\
                ea1b13330615011050a0dfcffdb21af33fda9e14ba4cc0fcad8015bce3fecc47\
                04799bef9924ab19688fc04f760c4da35017072a3e295788eff1b0dc2311bb19\
                9c186f86ea0540379d5a2ac8b7bd02d22487f2acc0e299115e16097b970badea\
                802752a6fcb56cfbbcc2569916a8d3fe6d2d0fb1ae801cfc5ce056699adf23e3\
                cd16b1fdf197deac099ab093da049a5b4451d038c71b7cc69e8390967594f677\
                7a855c7f5d301f0f0573211ac85e2e165ea196f78c33f54092645a51341b777f\
                0f5342301991f3da276c04b0224f7308090ae0b290d428a0570a71605a27977e\
                7daf01d42dfbdcec252686c3060a73d81f6e151e23e3df2473b322da389f15a5\
                5cb2cd8a2bf29ef0d83d4876117735465fae956d8df56ec9eb0e4748ad3ef558\
                7797368c51a0ccd67eb6da38602a1c2d4fd411214efc6932334ba0bcbf562626\
                e7c0e1ae0db912c28d99f194fa3cd3a2"
        );
        assert!(verified);
    }

    #[test]
    fn shake_256_all_prover_committed_messages_and_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_commitment_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                    fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                    5ab02449b8d375f869a8df15db78eb02",
        );
        let prover_blind_bytes =
            hex_to_bytes("41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                8f5edaeeba071bee79350cc4727893732842e80d936448974ea9e1628aa94703\
                adb1c0795d1b2ec66d4b750bdb1a4409ac7e95178c30d0ca8427578368818619\
                102571c1862b51abc7560fe1271d86a49439b172709ef7012f527f8cbaac758a\
                b803cab84c7c19d5d4e28241da72c141f2518df44d42846ca7b5802a903bec75\
                7c83352a5789ba2d57e3686b49f41b7a1803b642118ed8acc19bdb90bcb4fbac\
                1fc16213d557e3ffb13184c908a1b5375072cd58c4773bc9e84f65f5fb845cd4\
                318636f91ed2c6fa619ea193be77b18e46a7760242df2ff117ba27a38574fb8c\
                a2904423d92cfc3420f58a063703ff71170ffd1e323f667b46197f432aa9d116\
                08ff06b0d4aae0669e0dab0599372f9645526dc44104c6e23c16279daf102b68\
                742a1430eeae18b7e256143d17369128",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_half_prover_committed_messages_and_all_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_commitment_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                    fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                    5ab02449b8d375f869a8df15db78eb02",
        );
        let prover_blind_bytes =
            hex_to_bytes("41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                a52e00a77f6982dcac9fe2ab683073ce3f9bc195a26d721181a3dd6217889174\
                379afb78920d43bd28210d535cf7e581ab496573095fa41f0a134705da4037ed\
                3099bd386d29087886f746295593c881ef1a5ad19ccbcee4a6041f00172a4dfc\
                b18aab20ee55c319e9f76f22ab565da3dc7ddfb797bd1ccf257fdf649742fba8\
                f01252fa17bae1a59a419de5412afaf056bac7ab67ffac0ca97ed1916cb859d9\
                e9ab5abb1a1fcfe290d19b1660cd7dc7581b3437904023dcdebdff473e114728\
                0719c5c65338f62b5bea1d17afc0c778047141ed5dac569b761d59989b26f79c\
                175d3cc30e18c8519c2fc755cc4965d6448f96e8dcad1d07f8f932125645570d\
                84b9138897ad9ce402ce6cfe73dcb70554b787a12c1eb61c2a4f3e9b6c425f2a\
                e08c5c5eb65359e9e3a7faf08e0c6a486305fc931dda475ccd443a16310d618b\
                71d2693d3d6ceed4d6c7d643e06ac04c4699df8ccebe97b807f5912144014bea\
                421cc7e53b82acf1188f7420a59bcad5",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_all_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_commitment_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                    fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                    5ab02449b8d375f869a8df15db78eb02",
        );
        let prover_blind_bytes =
            hex_to_bytes("41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                b9b86d89d9e2a9431a8c17b5ea8426448214775d354674b2a0e956c7e10dd7e0\
                d5a1034ae733f5591eaa4bec1f3828bba1c5f4f9fa371916a11786c4d249c433\
                f8da8cd3d8134f3539347081d0d59aa63119406e5363beac4104dbdb22959a24\
                8e1694bd75dd3ff05a40707f9a3bc9f3e1f41ce555ca811d87514e81baa6e019\
                23520686eab039a50cb09f9bd4c227084fdb55d2c016f406148575c08b6ee615\
                6cb3df0de1662fea2f501ed628a34f4857213f57043ea334a655e17b3710b195\
                02d472e7f325d5ef6a64a62c944cb84f2e2500bffdfe1fe9918e78501d2fef37\
                2cb1373c181394a4ce9adf7e37831c765b0b7ba3fcbe305cf14df858204ecb92\
                17e9eb4f99df376f4be5d5ba43dc608551a87d6b3fcfc435c71923f32d3e8bad\
                a181269d445453ca4dbccc8a967c90af6d6194f7c3d3f92b7517ef67b7c041ae\
                7540ff9299bf5234d6e795c8d186ffdc1c418707616978e67038f823a2327f0f\
                12b9c015c4ca56171c4116a13c91a86a732a56e7d0261ab21b38218cb8b5701f\
                485424e7fc1e886d021b605c37d047a134563c97d4f51161ddffa6553495fef3\
                220918c436afcb433e82a7606feed6667137f42d2323aae0fce28b89d8188168\
                642178799c25dd6e2e84a8939f11c77a",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_half_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_commitment_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                    fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                    5ab02449b8d375f869a8df15db78eb02",
        );
        let prover_blind_bytes =
            hex_to_bytes("41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                86645a1d743284cd08b0659c0f884432de1340f1fb105a7e21ba0cfc34758d75\
                6e9e20437e318a4ddff4e1b1d80720138b40b6e3b1b1f9d86aa8ccf51c1bfce1\
                0a19b8ac8a6fe4e5256f1e2ee542d44dfacfc6717780b2e4e6601d21e194442d\
                b47d0504a29994d88421cdd33950cd46a69b7c31384b17cf98c268c0de5bafb0\
                2febaae8fbe66e3246311d80d81149e82fe87605c0e233625c108c1c0bad5ba4\
                cce88c6c363f4180f6e18dd252c3b79d06f66513eabcca7f127e2e62c84ab727\
                f167f5732af269619f0f78a279dbe98653a70f99993f65d38fe6f180abf9286c\
                b975b4ce6834467d86c5ec1a1ef4e8c3391f30e14b16a7a6c96e38eef5834785\
                be198207bd5e80213ce626c72ca4222f7281120ee67e850b79b66918863b84ab\
                894cb47cc8729af1300e6c116fa9218c6d7e90119a4964abbddf82238bb7d35a\
                5d4390a8879fe56c6b39427623111f391c211571cf5ba209aca019c448aa7524\
                acfeaa7504b8fa3d0e95cc0e99e83ae41b0a8663c8a440ff3b77b50808934cb4\
                fef2645f4d000a452e692881274359fb597aaff6f73b0a33134c4d7333adc1b5\
                01c3bdf1296d5131c497bc556ad0b280409185b1cc65dd2f907e8cb93db88ce4\
                e52c37c02dbbf696b81ecd57a11890796315d19c9bde637d9c1fbaeaa14b092d\
                ae8d7e50343e8b5f753bbff7f1944ca366a90c03c8cf53516b6fc592dce852df\
                5bdda6151c17c199d52cca1be066f530",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_no_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_commitment_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                    fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                    5ab02449b8d375f869a8df15db78eb02",
        );
        let prover_blind_bytes =
            hex_to_bytes("41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                84de896fc56822074415cda24d66c850e5870365120586dfe07ffbb9d58dd9e8\
                b290d72b649b63dfc8bc2473e77ea26dac12380f076960d8416cacba2fe2d5cb\
                d3b381ebc7ceb94d7bf966b70122efb7d30d9232a8d33983d94cc8d8792ad98c\
                95b9b4cf8007e45767c0d393c4f8366f5f483fffe59a457bcf33e810785361fd\
                4b174d7a477accf0046b5cf0496617d2316579de07be03d310881b640aa6cf0b\
                70c23178bfbefd65aa26e33dd28217e9627633d09dba0a6ee70ead27cd17c3bb\
                62b92b68d5c434a913ce73e29359dc0d6dd8e735847e809ff1310218ba987d39\
                b3a8751ef93e12c8ff3cfa9b1d4edecc10c34cc7d5c4df79a40baeeafd1ca1cc\
                5202a8b4e366096d7a14fbc15a103f142ddbb490f422a4ccc277f0b0e2f82b0d\
                b214bf7b042a6b2f8901710bbc76f73034c4491ee7f652bedb5d75362cfeb255\
                08071c8637c2a9fa25f49ea1be0ac97670fde3b36ea07c54a0770ceb46eb8913\
                da3781c2537e40a71d99b1725fb85a672d8bec46660b40f5b8223492274412a6\
                6eda24a3870af56c6ccfde2e54ea37e0307f0439f18fa06e8ab46850707dfdde\
                b3c5298df0cfc5fad95ef97d3c05bbef5f534af6366ab5cb7b6d54bb5e97afc3\
                1517c03165b0666281c67752e0be8d4c46f960bdc4b5bd35cf81cba16f3cbdc1\
                4eca3d870f8fee8697f17b06c02b76505250be5edde0c39c1397bbdec2b16696\
                bd558aedb7efe9b1c3057798bb41b02265aeb737b02e3dc747ab2b974d6c7980\
                5802ec1a2c4117e9ebba0992c8d454fd2e8f16d1058b298fae0c6bd73287917e\
                8bde4ed5c52e312cc2f462d23ac2a843477a74b3d777518a92fb4ef3b34ba3b6\
                3c5282bfc2cd617f19985858425bf2b7",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_half_prover_committed_messages_and_no_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_commitment_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                    fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                    5ab02449b8d375f869a8df15db78eb02",
        );
        let prover_blind_bytes =
            hex_to_bytes("41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                aaf787d7c259d7acedd1294d0523586acfd5e05c9352ef3ba19147bebba3136d\
                f55cb7af38abede5736351ad1b7a967c80b662ac990335f89b5202e881770c41\
                b6d5da92a2d997f414ccc9e0f5ff07a916eb2262346e19127baa6d63477c40c1\
                adfad4fc36849254eb5baca5da75b5ee3574d0f4b06655b2669ee88ed7d1fc76\
                badaf119576cadea140b4441ba3f4ed869ed74d1349b5d625f52879d09987f9a\
                37f67b515c1c3ae37ff95887c44641db0562dda674e046d0dd0329498d78a4c0\
                4525f5f70d46bbeba884f1315d1e0e0a11d64d2d7135ac5247d66dfc755d0cea\
                aacd435eb379968482f13054121743b2330bd2102da2f876bf6379f7f345a6ae\
                731aaeeb63e3a1986c7325ce5707c9c73908d5be9fa555615626dbbc3a889304\
                6af612189b39441e42b7433ef181d1423f3df67021fc9de3fbb3a34d69a9bee7\
                cda3db6cfea80f3ef464b9d5abea25db3174abd99e71dc0f396f14d5579556e5\
                c11186156a8c07938cbf860ac0f45b3c235dc8b744baf5656e76fcb25020e306\
                9fd5e9a71966118f81246b85a46c62a070a6e66132aca408454be0fe2fa4909d\
                e71fecad7c85b2869da3787d81fa1d735c72f5479b811bc8c4cbc3af332dd714\
                6cd8f933c009ae417a86d8c3ca9f1e5738b6050be9b690422a10128428408f13\
                99a628c89f0d2296a4402c0fa529e06729ed80f59c2c8513f7b2776b1e5750dd\
                71aaecc0dbf1ed783c35af918099340d614971744f1687cbf988438f7f6598a3\
                651be1453ba4491f5c6e6442c973de305c452a8114ff07163107dbb65f96fc7a\
                c33ea89db973bfd7e5e4c3a57654b317189220a753c30a77902cd969d7e615ec\
                7114795d42a3f3810dadc115ee67e44b29cf35181da3903b5219fbef708e73f0\
                03e474b1b8dbfc53e1dd7a9134f17b1c48119c1d708f74bc0949d4c8192562b4\
                dbfd026d123aa296af59e1c64dbb35b1",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_no_prover_committed_messages_and_no_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_commitment_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                    fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                    5ab02449b8d375f869a8df15db78eb02",
        );
        let prover_blind_bytes =
            hex_to_bytes("41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                9341832e2e6739548581a238cd563ac3f32749c2e9b3bdfe6b2c92fb72c92add\
                1e961ce105ff9db40b4e54c4a8fd4567afaa5d76ba043383225573bedbfa7902\
                f877a399d4eca9b78b49aa12991f5c875e1a6dcccb7901b203e1865cf27d9a75\
                acca75dc526343fe7c0f93f546931ccb77f0e641e0c2201798fe1048163eb0f6\
                655b337e37c832ad1ce3715c8084f0211cdf757f4db45e4a5bcabf8490f2f3b6\
                5246d0e7ee30e475cfef6349de51b637173acf28d05753dd275fc590883eaf10\
                69e362debbb1775ccfb9b35381e21d5d5e06f74bf17819ded6ee4342e8bcaaa6\
                06363c70bc9f2b7b774edb83614d763a0f84229c99f6a33529c382c2fea6d230\
                5ff4acc6d289bb3a576147e96d660b76058eeba1e2f0fbfd877deefbf30c218e\
                b2eff9e5dafb65a4f3e0ce00c1ea9c734ef834dea68fd5c7ffc1bf3de96818d6\
                7a4e4c8640297a405b28285f8a4caae44d6b7b22f7afa1a9f6aeb9bb017f0ab1\
                ebdbd894eebf5a1bd56ff3b21a2de642435935e7cb3208ad1543a01ed8473ef1\
                7ea3635d1743733253b5285a737dbd9000cd2834d27f3029b47fdafa389a56c4\
                34176f540dc39934e80fe6e1b4c210e00dc7e6b8573106fb2b2f8b772b5197c1\
                5afeeead937ed5bbd440e29e3ef6db6a60614c8462a497041549aa47f0a176ca\
                ca4dfbbe27320b6f063fa1ef94fa64750f6eb670d1bd14c85bd943c948814f68\
                0c3702f5ff1cf35bb7827a43d1e85a8c57afb55285bb9d3c4315fa37ee32cf1f\
                98125ffa662919d37426623fb827ddbc2c2da69355a9a92d23ba7aaf4276cba1\
                d333dd96d1124e2753d08b2092a3408c19d6691443c4081593c84f05032c26c1\
                68086471f09b1906805cda31ce4a49d400679c2c4bf1aa06ac44627566a53edd\
                ff25095bdde0eb4ea4a47817e5d138fb0053401f5f6413d862679c1997439828\
                c055c5a46de460b1eb84d077bf5b4a6f4e54296ea1b8e062a944b4678dc961b7\
                9928f6f7743d30bdb220365800508f9849b31bf2625b27b7d18cee197f2270a2\
                26872cb69ba853d0edd9245d2a4ab5bc2fbf52fe4cd4ddc5d94a808edb0ee59f\
                72b54a5a52f2f30b1f43c169b297c741",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_undefined_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];

        let signature_bytes = hex_to_bytes(
            "\
                    b80f73e22cf6c050159018539af4fd2c8ed75a7dfa247feadbdecd983e16ddb3\
                    3ac5c61bfd7f17b4063a7957456ddc0b71d46e6a05b1a464df601aabf480edf1\
                    7ff1d6052089c294577fcfb7b851baad",
        );

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            None,
            Some(&disclosed_indexes),
            None,
            None,
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                a5de46751c4f2662be4aec33c0a7b869e0d0dd26d4131f1d4c87127058fedb60\
                ad474c387775e8c6209c4e60f6848d91a6f09b4587a5a6ec3e2c7ce0b46ed344\
                630f10554bdef8f92bb0b28086bc6bd77f53f3d769b8be9d0b06a4b11e38ee2c\
                90e1a97c1b0d339107ae11f72cc2662b304b2fabc7fc3b3752d85f831873cf2a\
                e01919569fa98f68182fa99847e4e71628e9f541ec9f9642af2eb044e33930ac\
                345bfb59df26e0cfa02625ec836919eb4ae762b7b9f650cb6c623e51fb294cc9\
                1a5de51dbf6c6e933ce095432a0a03710af14cd2b2eea0f80bd44d4211dc56eb\
                2a2f8482b411a2a7ecfe4e4f2702411f1855a295575288f4915f4d18c6f65f31\
                929a22cd838571d986e8483470ace5a248a5ef191deedd241cc5613ff865b864\
                ab19b80a600c741bd57842fab0b7284f449731f6a8071d84ebdeb3af42cfe104\
                85b6071de72abc2b792ff729783bcea86e9d3797cbb5c6f2a14214e254bece4b\
                797048d2a23bc6509086b4e07dd42f1b30765973fea40fb02702dcebec349889\
                c802d8b20d4451e8f8418c9c931acbf865f2bf6e3dcde2dece63dd45ffcdecc8\
                019f04664cb245f45ecdbc945e8a47725e3d58462e7eb65980e0253414373959\
                c691e2e039b389beb064cfcdfcf7e3c5",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            None,
            Some(&disclosed_indexes),
            None,
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn shake_256_pseudonym_all_committed_messages_and_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_committed_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4a\
                    d9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d4\
                    1a387bcfff7275ae96b00d6f805bb32e",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                87c87375d670774600975ae2cb67a08d884f1a40a0ed279d49e9f9347758f712\
                a23b60ac21b6b210ec6a4b0e80ad7716a604ee9ef21240f4874fb365a4e7a46c\
                c34d9b681ff02a94335ba5e6d3cedcad0e10e5b5a7e1cb75ed9b4b7c64b34072\
                9308f98ceff347fc7632a81bdf1c4a50f95347d6108a018857a90f0fb213c4cb\
                36b74c48e120f061d4e725ef3c89f55271ac7b7e303c9d58dac01d03a5efb470\
                f9dabde27d9a0935201f960323826aa27278bfcf22fa6094c9caf7a19e263fbf\
                e0a1d2c49ea6db45cb82f0af71b856775a2cb6a9698360cc005b4fccc24256a5\
                d628552e8405b082360c5b618076e86619b79d53c20f1ad73db7ceebdf80af65\
                f5bdaa099d7ede9c043f234f6fd322364168c1e09a10a9ce109646243c70b39f\
                8a6aa42031ba4594d76e6aadc5b3c1c71e2ffc5d9bc0f6c649c460d99b27d52f\
                0c2d6244bf0dc1c1382e73a9782d0851",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn shake_256_pseudonym_half_committed_messages_and_all_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_committed_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4a\
                    d9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d4\
                    1a387bcfff7275ae96b00d6f805bb32e",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                a368748cfab5ea798707998a21db421647144f932990c63dd69fac0b2046f6f4\
                910a806098932ca655ab37f4276a9290b05d44f6755a4f3bb1ee0647d29e81e3\
                0d9972c22b96c99434b86a9877cd97fb18b923318fa135da8162861ef99c4988\
                b264641475a51a0e1ec8a6289db1bb555e3ce8c05a5079011411ca8a9d80b671\
                a0df37aabb8b65df3aa2dd5db766f23318665d8086ffdd1b21268ff4f85a485b\
                e1d05fbb4740a6c9012249924ab956656037629f1ffb6790ff7e9d6fa4b62a06\
                585c8246e522b8ffc35b4c830091a7c42b760b6035286156b95246ee177462ba\
                fe07e34599b00bb2e161188ea4f19e3f3a890b73ece45df6a71602ca3598b0c9\
                81f39f3b30104ea893e410a86b6612a90cf576c196ea2a9c31a514dbfd90118a\
                ef0598714b98d32066185be45e70cab0461715872ec7d7d08374a9e2751a99b9\
                222f5b7d5164e039e65ac80e55672f4b42713d94b077f14f2fac74085fe3d300\
                c19802a758d4e4d9a63c1d23bafb54b13970666b9cdd0f4ab9c4abbc46907422\
                c2538d704a7b8ce1655f76ebb86648b4",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn shake_256_pseudonym_all_committed_messages_and_half_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_committed_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4a\
                    d9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d4\
                    1a387bcfff7275ae96b00d6f805bb32e",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                ae0e79f2e30926b255f576949b1f34a4843d061b9279732d20315c1b1e133ee1\
                9d54dccae8e1aa90d628e0b4a423e958a4b674599ce231c77c779cf55436be40\
                6c72296cbef3d46f72702323baab6197223ff60a15e67e9540dcc6875b6fd764\
                b27df0665f39469a94270c0433c070598d11deb8692f8db5d06ef2ce323d8593\
                d46160a43df880d624e9a64b2935651b638b586d67c809e60e7a0b5affbb5a3e\
                6e5d39a6e3dac8d18d7ac31f9b8573e76b6a5579b3d139d1d076a37d300d7fa5\
                bb9f406ef0ee9b23799c78d88209812e1e03306d7648dc4ec8281c77222f2852\
                2bc98e2dfe93c76e707a23a303cc50f81f3e26d2481661f9a69fff45bb93ab27\
                743397092a4b21afb4d7d8fe6f8ca452207e85ea56bdcaa7822f032b40ddbdbb\
                0cc4a7a0a49e72939cb60878b0b6075f31dc4f65e1fbdadf8aafcf4dcf8b7c11\
                36d00d2eec96fc3c85bb08ceefd4cebb3e81e8c3ae6a868aa7aa388d3baa4846\
                e97698255ceabd698814348c76f99a0673cd718d246c215fed3bf658d2eab39d\
                387d56b9165374fd8fb6388d824d30574224b0ccc6927fefff9baa7761ee5f08\
                4cfb6611a8d39621c77d04f4252b211f0164c4c5c56ffede4146709687a52af7\
                380dc12f05081fcb522ec4dcd6218572084934b53547e3d7b33807f770c2a6c4\
                fb51d11358bf650ce01b0965a50041ce",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn shake_256_pseudonym_half_committed_messages_and_half_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_committed_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4a\
                    d9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d4\
                    1a387bcfff7275ae96b00d6f805bb32e",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                ad1d728a7fb4b68de8d6ac04842bbe08fe39c4ddcdb6693415efde9565e61afa\
                1cd095bacd7830364b5c14f505b4b6cb906de91cf57f482da1ad9dd5d9cb60c2\
                44568f09f6d30cbee78c09900a1f1c345ee43373d0beb5a4c83659ac3042fab6\
                ac9e660eb2e2b4e11550b27783379deddad2a05528768f0306fbb4e040e4ab04\
                02c4b96e34c6adb77c8b37f38db432a74ff95092207821daa45b30115a36d053\
                803a71d0c61be79f9b5c7e465f53df732aba7902a9d67e32398909267866e6f3\
                619fa1229c3c0778523f5b7d028ce355272481ca52aa203c049f3890f14793e8\
                f744e51bd3f45fc4a7af2a5eadb1427e5b4d7064123101951dd034b723a75922\
                8ee439cbed30a4866beb7840663c825303264769801674e6ddf0781e54585929\
                b13c4243b4299cdc0292450ea2d74ae328778abb5ac27fc5a7c1f0b011751f7e\
                38b6a0033c565b369efa0d49d45889b51c616f1cdcdfd499afe2ca256eeb84d2\
                15fec570026b18429105dee0451a7682697c045f40d132846f1428fb1d4e403e\
                93bd8150a597c6033f84a110dc14da045800e29cc062358ca304b1e382b1251c\
                851cb839e59b5ecfafccc3dedbb6594920c7348026598ffa59f7fe3df27d86bb\
                8069c10c5225c8aa8c09ebf23819838663a7474fbda2635b2ed3e829870c4fa1\
                208497773650d6d1c315ce5df97b1de16e097279c1eebab239fd37861ff106d5\
                75f9bcb01a259aef02cff53f0a3b26e1025fa34d8302ee4f998f00214fbc429e\
                2551dfebda5b46b22319ed8f08821da0",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn shake_256_pseudonym_half_committed_messages_and_no_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_committed_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4a\
                    d9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d4\
                    1a387bcfff7275ae96b00d6f805bb32e",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                a07906dab5d5d523a80986c377f6c85618875bdac8bf8bdfd35439051f98762c\
                8abdfef2ef08cdc7a6e14beacf7b303b8094057395b26030b2a7450bd5a87664\
                87fff98768e705e636916c928adb95a3fd3f80b83f232b18a88396bb9dd11128\
                85192a7fa6872221c29a9659f05e7a482e554c6a9b4f5a5571938bb099c2bd5f\
                9a29a9fb9495625248d975ebb478758f1bfad60f4750647b1f2f3c33a14fa527\
                3c67a0542e2725d911195d9a94d7ec183328166651feaa3ff0ddf7e3394426af\
                c1dd26fe2c4a89a2acc8c5ce71f3ca50113e7b1c8a2a8c22fe81505fe1cc944b\
                4ea86c4dc9020661e7011231e9db581e037ebe34ae083de76e9a22cc100b9304\
                c4796e57cc9d6f5386cc0ef16b66506c43a976dd5a104ee0ce5745cb4e61080b\
                3b0aa25777d85c64eade558b63f24edb594ff2add441fb95d9ebb22bd807a6f9\
                6f82d10fb77fb6af178b002e81983e9e5396ab8e6c7777398370d557a1570cb4\
                a90c3ab9bd9d4b77d475b2b10e2472632590567f0951fe70b7b62645985af928\
                4dc234d91c722d0a730a75df83af042c4f6965f8286ec4479b102e006e463f46\
                7e7eccb5bb192bae8e52c1c219edad503d2473de89a67dd8720c31e73923914e\
                e8496bd13743192b8b881b0c11b604810249678be3865dfd15e225d264a408f0\
                5114a5b1f3634a117a2e7e11ff7571d56847e8ff18edb02d0119049b4ccccb76\
                34e4343ade7e788e87da183fd916cfc2111e147a13e2cc1667ae18cc5983412b\
                936b0b3ca207134da3febd66368d865f701a22b026c3f1f457c471ce02ac90ab\
                44c1d3a3eb65b571bddfd911a93da38a446200e6a0adce64aa23a52ca7a8e521\
                3cfe08c8356f244391d7ad8fc8e352c35a08681488a2c99af62a6fff67798ea5\
                57b7a3fdb5087904b1ac25e1ea0c94b5",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn shake_256_pseudonym_no_committed_messages_and_half_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_committed_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4a\
                    d9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d4\
                    1a387bcfff7275ae96b00d6f805bb32e",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                a8910fb960eaca764593b00202a3f062c53f25d71701531083a72acc34c3e7b0\
                8642aa58f67f1835d9fd607c93765d35b13e33dc916ccd3582410b9d3b5f0ce2\
                5b3bb8d2a0954880798251662b0707ed4e09fcaa2a8c5b35b77712ed4f68cbfe\
                985bb1ffa92458f9a8b54b19fbba33119e46deada623a3f7e7cfbc9e021feca9\
                bb3273151330a55e7a73a8471e4b4f493856d71fd4c4291e17dc48e75b31bf4e\
                85878efbac859197a31fdd0370dc627454c801ce876590e605acaa176bb1900b\
                82d556e7217fcd93ee75970e99ec0d71326a36f02944b36f043c6f93c178bd77\
                3f3271d7c813e7f8d5fe47cfdf946358401e543e3e8453964a4df41617097872\
                c81e622849ea544210174076fea749a25481f060d4f4c8ee179da05998e1fee1\
                cf7b2e16fbb47966b96d4f34f18eedea1b91a0f917201c2cb05ccf1bbf9330a1\
                adf5ebd6a6a9a3d37bf1cd1f08137bad407d72d185f1a08715292ce4cc74585f\
                d9c60c5e0e2b0b37beae01a89f3c3f8e3be9fef9a8c8c9cb04d6d6a12bca7133\
                87f269684905db470cc88414977aa238651fedfa25521a1a038f3aa1f184c062\
                b48170cf2420c626a3f08b81a8a5948e38ebc4798bee33c93c984580d73dcc7d\
                c25a54977dfede551d7e2b5e79bdca1b60da532dfd00ae4696004bc9d1ecf57c\
                ba492145558b7867c721a50556d937c540b5b38313120be55d43c3fb5d9b4a40\
                9ec44f62038dda9ac16f0aaf48848d2d646ef4c6cef5de59f969b42ee46d5486\
                7833f299582729a06280331e1e77cc2065c5b24ad2d8ee2b7e4038384f703a01\
                25fa8e8e2e050885eb20a087c0cf168508b9c68d1f3b72fc7609e3b7096e6dbb\
                7c51bfc85f4726d99e1826a736d02cd245fd76b4800f7c313654f21506e02179\
                51fb8417afed7e462e1cc246fe0580a73daadd9e38188255ec3a8345fc34bde9\
                95bdadf3922d2a380f9c1a2a15d054f710f838acdfd31ccec8b5f53427465e5b\
                715df435647cef473216fe38b707aa8f",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn shake_256_pseudonym_no_committed_messages_and_no_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_committed_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4a\
                    d9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d4\
                    1a387bcfff7275ae96b00d6f805bb32e",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                8d3b51ea093c025a125c461892b18d561dd5205e7c01d5d61dc38278d45fcca8\
                241a5fcc42a50558ea24926a6577e37597dfe3f3264cf81a17752c364e0cd355\
                099408f5b37bbc812996533c13c27eb5649082ccadab658253d44f83919a9166\
                a92b28c33d426a662fdd57c2ea3f84b89dcad87b7091018ec26234ec12ad9a74\
                13cfeeceb7af93be473a95911d2d47f43df6551812412dab2de651d09d2c12b6\
                b4536ead479bd7e9201124a963dd94913bf550b84a160073ce170a83ad5b841e\
                c384a1316acdd647a07c4d55168105b41489e6e56033f92a57855cc8ed2fddc9\
                3be3f625490baece8e551be6491f36c145a945a24f4693602e511e03647d50b7\
                08caaf02f49eaf19cec6c596fe6f79bd18a9da98d1aae28f1bc10d205a16b241\
                c97de75a17ff24bf1e47f063775e219257e7dfad9b87b9127f294210d51e0263\
                57a11822e2e4ead4fa1fb2f7615dca5a6bd8ba2094981c377579a2442cdfba15\
                4f41fc69330a5f0f3f029fcb5ab5ee161edbc12157e33cf37578cde84633bba1\
                144de3a61b23886237efd56fdf5576ee3d15e7e4eca557f30c4334dbf2921bcc\
                f53ac38bf9efe620182a80e49ed9771e63b904eded8388ce34fbe47bf5417b0c\
                9ff9dbe489c398c0c93e3778ddaa9b2928dc21e690854e283b146ad30d91117e\
                446aeab2a6552cb1e27fa4a9ff976b0705d0b0ef8a24f62618724af86b655486\
                a265bfdfc3d920588c74ffedb193821d006253535daaac1ab794b0033b0f88fa\
                ed65df6ca145a8478c3d4161136cd72e50c40fc7a2320de35238c0c47f3737c2\
                46be00932155cfdca71d17cc8e305f6462058dfdc7e87492e052b221dabb2981\
                621ac4be7a0f075264a4748e8c7b2a58396e193a8ea15d7760af0e75339c9e16\
                c0deb36633f082e8831759fd48f28a835960c5846dde3b0a7b480d8a6f9c5933\
                4b0a844c9553b58ddc849a9b0d785c655dfddbbfd9d24896f93c2597f3b6dd58\
                126229fda71ed410a6338117cbb41711738dfc6736435578e6b23d6f03aa939b\
                4016aa995c3b56597516d99133a854130461c8ce5244caf5b23ffeebfa3b6c8a\
                c8df1194e1a65ed740daf129a325ff3b15d12484c7e398e9d97533363068d1b7\
                cc38676e915fbf93264c2209860e37c2",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn sha_256_single_message() {
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
        let msg_bytes =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525\
                    3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb\
                    4c892340be5969920d0916067b4565a0",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1",
        ));

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;

        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(2, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(&vec![&msg_bytes], Some(&api_id), &cipher);
        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde];

        let disclosed_indexes = vec![0];
        let undisclosed_indexes = vec![];

        // disclosed_messages are the messages with disclosed_indexes as indexes in the message_scalars list
        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&vec![&msg_bytes]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "a862fa5d3ab4c264c22b8a02636fd4030e8b14ac20dee14e08fdb6cfc445432c08abb49ec111c1eb9d90abef50134a60"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "ab9543a6b04303e997621d3d5cbd85924e7e69da498a2a9e9d3a8b01f39259c9c5920bd530de1d3b0afb99eb0c549d5a"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104\
                ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825\
                788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aad\
                aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32\
                c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f\
                94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf2\
                9417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e\
                940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d45\
                5feeb04426193c57086c9b6d397d9418"
        );
        assert!(verified);
    }

    #[test]
    fn sha_256_multiple_messages() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146\
                    3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36\
                    32078557b2ace7d44caed846e1a0a1e8",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1",
        ));

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;

        let api_id = [cipher.id, PADDING_API_ID].concat();
        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde];
        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let undisclosed_indexes = vec![];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "9881efa96b2411626d490e399eb1c06badf23c2c0760bd403f50f45a6b470c5a9dbeef53a27916f2f165085a3878f1f4"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "b9f8cf9271d10a04ae7116ad021f4b69c435d20a5af10ddd8f5b1ec6b9b8b91605aca76a140241784b7f161e21dfc3e7"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab\
                52db2d4b379935c4823281eaf767fd37b08ce80dc65de8f9769d27099ae649ad\
                4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64\
                a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef\
                47855480b7b30b5e4052c92a4360110c67327365763f5aa9fb85ddcbc2975449\
                b8c03db1216ca66b310f07d0ccf12ab460cdc6003b677fed36d0a23d0818a9d4\
                d098d44f749e91008cf50e8567ef936704c8277b7710f41ab7e6e16408ab520e\
                dc290f9801349aee7b7b4e318e6a76e028e1dea911e2e7baec6a6a174da1a223\
                62717fbae1cd961d7bf4adce1d31c2ab"
        );
        assert!(verified);
    }

    #[test]
    fn sha_256_multiple_messages_partial_disclosed() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146\
                    3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36\
                    32078557b2ace7d44caed846e1a0a1e8",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "44679831fe60eca50938ef0e812e2a9284ad7971b6932a38c7303538b712e457",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "6481692f89086cce11779e847ff884db8eebb85a13e81b2d0c79d6c1062069d8",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "721ce4c4c148a1d5826f326af6fd6ac2844f29533ba4127c3a43d222d51b7081",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "1ecfaf5a079b0504b00a1f0d6fe8857291dd798291d7ad7454b398114393f37f",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "0a4b3d59b34707bb9999bc6e2a6d382a2d2e214bff36ecd88639a14124b1622e",
        ));
        let m_tildes = [
            Scalar::deserialize(&hex_to_bytes(
                "7217411a9e329c7a5705e8db552274646e2949d62c288d7537dd62bc284715e4",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "67d4d43660746759f598caac106a2b5f58ccd1c3eefaec31841a4f77d2548870",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "715d965b1c3912d20505b381470ff1a528700b673e50ba89fd287e13171cc137",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "4d3281a149674e58c9040fc7a10dd92cb9c7f76f6f0815a1afc3b09d74b92fe4",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "438feebaa5894ca0da49992df2c97d872bf153eab07e08ff73b28131c46ff415",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "602b723c8bbaec1b057d70f18269ae5e6de6197a5884967b03b933fa80006121",
            )),
        ];

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde]
            .iter()
            .chain(m_tildes.iter())
            .map(|s| *s)
            .collect::<Vec<_>>();

        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 2, 4, 6];
        let undisclosed_indexes = vec![1, 3, 5, 7, 8, 9];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&vec![&msg_1, &msg_3, &msg_5, &msg_7]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "84719c2b5bb275ee74913dbf95fb9054f690c8e4035f1259e184e9024544bc4bbea9c244e7897f9db7c82b7b14b27d28"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "8f5f191c956aefd5c960e57d2dfbab6761eb0ebc5efdba1aca1403dcc19e05296b16c9feb7636cb4ef2a360c5a148483"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d\
                340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47a\
                fe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f\
                897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436af\
                d24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604\
                a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5\
                b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb\
                2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f04\
                9a02cb9127dac894418105fa1641d5a206ec9c42177af9316f43341744147827\
                6ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e\
                1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b6\
                32585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e\
                160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba\
                05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a\
                2650a21d59f09e8305dcd3fc3ac30e2a"
        );
        assert!(verified);
    }

    #[test]
    fn sha_256_multiple_messages_partial_disclosed_no_header() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4\
                    f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fd\
                    c63a32731347e810fd12e9c58355aa0d",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "44679831fe60eca50938ef0e812e2a9284ad7971b6932a38c7303538b712e457",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "6481692f89086cce11779e847ff884db8eebb85a13e81b2d0c79d6c1062069d8",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "721ce4c4c148a1d5826f326af6fd6ac2844f29533ba4127c3a43d222d51b7081",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "1ecfaf5a079b0504b00a1f0d6fe8857291dd798291d7ad7454b398114393f37f",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "0a4b3d59b34707bb9999bc6e2a6d382a2d2e214bff36ecd88639a14124b1622e",
        ));
        let m_tildes = [
            Scalar::deserialize(&hex_to_bytes(
                "7217411a9e329c7a5705e8db552274646e2949d62c288d7537dd62bc284715e4",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "67d4d43660746759f598caac106a2b5f58ccd1c3eefaec31841a4f77d2548870",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "715d965b1c3912d20505b381470ff1a528700b673e50ba89fd287e13171cc137",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "4d3281a149674e58c9040fc7a10dd92cb9c7f76f6f0815a1afc3b09d74b92fe4",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "438feebaa5894ca0da49992df2c97d872bf153eab07e08ff73b28131c46ff415",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "602b723c8bbaec1b057d70f18269ae5e6de6197a5884967b03b933fa80006121",
            )),
        ];

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde]
            .iter()
            .chain(m_tildes.iter())
            .map(|s| *s)
            .collect::<Vec<_>>();

        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 2, 4, 6];
        let undisclosed_indexes = vec![1, 3, 5, 7, 8, 9];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            None,
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            Some(&presentation_header),
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            None,
            Some(&presentation_header),
            Some(&vec![&msg_1, &msg_3, &msg_5, &msg_7]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "41c5fe0290d0da734ce9bba57bfe0dfc14f3f9cfef18a0d7438cf2075fd71cc7"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                81925c2e525d9fbb0ba95b438b5a13fff5874c7c0515c193628d7d143ddc3bb4\
                87771ad73658895997a88dd5b254ed29abc019bfca62c09b8dafb37e5f09b1d3\
                80e084ec3623d071ec38d6b8602af93aa0ddbada307c9309cca86be16db53dc7\
                ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bf\
                ea5af347a88ab83746c9342ba76db3675ff70ce9006d166fd813a81b448a6322\
                16521c864594f3f92965974914992f8d1845230915b11680cf44b25886c56709\
                04ac2d88255c8c31aea7b072e9c4eb7e4c3fdd38836ae9d2e9fa271c8d9fd42f\
                669a9938aeeba9d8ae613bf11f489ce947616f5cbaee95511dfaa5c73d85e4dd\
                d2f29340f821dc2fb40db3eae5f5bc08467eb195e38d7d436b63e556ea653168\
                282a23b53d5792a107f85b1203f82aab46f6940650760e5b320261ffc0ca5f15\
                917b51e7d2ad4bcbec94de792e229db663abff23af392a5e73ce115c27e8492e\
                c24a0815091c69874dbd9dae2d2eed000810c748a798a78a804a39034c6e745c\
                ee455812cc982eea7105948b2cb55b82278a77237fcbec4748e2d2255af0994d\
                d09dba8ac60515a39b24632a2c1c840c4a70506add5b2eb0be9ff66e3ea8deae\
                666f198edfbb1391c6834e6df4f1026d"
        );
        assert!(verified);
    }

    #[test]
    fn sha_256_multiple_messages_partial_disclosed_no_presentation_header() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_3 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_4 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_5 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_6 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_7 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_8 = hex_to_bytes("ac55fb33a75909ed");
        let msg_9 = hex_to_bytes("96012096");
        let msg_10 = hex_to_bytes("");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146\
                    3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36\
                    32078557b2ace7d44caed846e1a0a1e8",
        );

        let r_1 = Scalar::deserialize(&hex_to_bytes(
            "44679831fe60eca50938ef0e812e2a9284ad7971b6932a38c7303538b712e457",
        ));
        let r_2 = Scalar::deserialize(&hex_to_bytes(
            "6481692f89086cce11779e847ff884db8eebb85a13e81b2d0c79d6c1062069d8",
        ));
        let e_tilde = Scalar::deserialize(&hex_to_bytes(
            "721ce4c4c148a1d5826f326af6fd6ac2844f29533ba4127c3a43d222d51b7081",
        ));
        let r_1_tilde = Scalar::deserialize(&hex_to_bytes(
            "1ecfaf5a079b0504b00a1f0d6fe8857291dd798291d7ad7454b398114393f37f",
        ));
        let r_3_tilde = Scalar::deserialize(&hex_to_bytes(
            "0a4b3d59b34707bb9999bc6e2a6d382a2d2e214bff36ecd88639a14124b1622e",
        ));
        let m_tildes = [
            Scalar::deserialize(&hex_to_bytes(
                "7217411a9e329c7a5705e8db552274646e2949d62c288d7537dd62bc284715e4",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "67d4d43660746759f598caac106a2b5f58ccd1c3eefaec31841a4f77d2548870",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "715d965b1c3912d20505b381470ff1a528700b673e50ba89fd287e13171cc137",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "4d3281a149674e58c9040fc7a10dd92cb9c7f76f6f0815a1afc3b09d74b92fe4",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "438feebaa5894ca0da49992df2c97d872bf153eab07e08ff73b28131c46ff415",
            )),
            Scalar::deserialize(&hex_to_bytes(
                "602b723c8bbaec1b057d70f18269ae5e6de6197a5884967b03b933fa80006121",
            )),
        ];

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let signature = Signature::deserialize(&signature_bytes);
        let e = signature.e;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let random_scalars = vec![r_1, r_2, e_tilde, r_1_tilde, r_3_tilde]
            .iter()
            .chain(m_tildes.iter())
            .map(|s| *s)
            .collect::<Vec<_>>();

        let generators = create_generators(11, Some(&api_id), &cipher);
        let message_scalars = messages_to_scalars(
            &vec![
                &msg_1, &msg_2, &msg_3, &msg_4, &msg_5, &msg_6, &msg_7, &msg_8, &msg_9, &msg_10,
            ],
            Some(&api_id),
            &cipher,
        );

        let disclosed_indexes = vec![0, 2, 4, 6];
        let undisclosed_indexes = vec![1, 3, 5, 7, 8, 9];

        let disclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let undisclosed_messages = message_scalars
            .iter()
            .enumerate()
            .filter(|(i, _)| undisclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let init_res = initialize_proof(
            &public_key_bytes,
            &signature,
            &generators,
            &random_scalars,
            Some(&header),
            Some(&message_scalars),
            Some(&undisclosed_indexes),
            Some(&api_id),
            &cipher,
        );
        let c = calculate_challenge(
            &init_res,
            Some(&disclosed_messages),
            Some(&disclosed_indexes),
            None,
            Some(&api_id),
            &cipher,
        );
        let proof = finalize_proof(
            &init_res,
            &c,
            &e,
            &random_scalars,
            Some(&undisclosed_messages),
        );

        let verified = validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            None,
            Some(&vec![&msg_1, &msg_3, &msg_5, &msg_7]),
            Some(&disclosed_indexes),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(init_res.t_1.serialize().as_slice()),
            "84719c2b5bb275ee74913dbf95fb9054f690c8e4035f1259e184e9024544bc4bbea9c244e7897f9db7c82b7b14b27d28"
        );
        assert_eq!(
            bytes_to_hex(init_res.t_2.serialize().as_slice()),
            "8f5f191c956aefd5c960e57d2dfbab6761eb0ebc5efdba1aca1403dcc19e05296b16c9feb7636cb4ef2a360c5a148483"
        );
        assert_eq!(
            bytes_to_hex(init_res.domain.serialize().as_slice()),
            "6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47"
        );
        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d\
                340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47a\
                fe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f\
                897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436af\
                d24457658acbaba5ddac2e693ac48135672556358e78b5398f1a547a2a98dfe1\
                6230f244ba742dea737e4f810b4d94e03ac068ef840aaadf12b2ed51d3fb774c\
                2a0a620019fd1f39c52c6f89a0e6067e3039413a91129791b2af215a82ad2356\
                b6bc305c1d7a828fe519619dd026eaaf07ea81cee52b21aab3e8320519bf37c2\
                bb228a8b580f899d84327bdc5e84a66000e8bac17d2fa039bb2246c8eacc623c\
                cd9eb26e184a96a9e3a6702e1dbafe194772394b05251f72bcd2d20f542b15b2\
                406f899791f6f285c7b469e7c7b9624147f305c38c903273a949f6e85b9774ae\
                eccfafa432e2cdd7c8f97d1687741ed30d725444428dd87d9884711d9a46baaf\
                0c04b03a2a228b7033be0841880134b03b15f698756eca5f37503a0411a9586d\
                3027a8b8b9118e95a9949b2719e85e4a669d9e4b7bb6d4544c8cc558c30d79f9\
                c85a87e1a95611400b7c7dac5673d800"
        );
        assert!(verified);
    }

    #[test]
    fn sha_256_all_prover_committed_messages_and_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_commitment_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                    3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                    aa8feb7f3a236e92b2da38462358c48a",
        );
        let prover_blind_bytes =
            hex_to_bytes("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                a80ea73d954433eca5bff121e0ad4b41e91d2b600cc717eff3804f11ef21cc9b\
                9b20da25387722ae6b2dd78103a3413484c3a88248f51c9bfe93cbd88dabc619\
                ba8a432814b15f8dfe601c1cac5404986541968307c8d06acf63ab906c41177b\
                a9e5e8f4f1ff77426d3e905b7809243e9ae10acd1013c40525c257e3fe6f1bec\
                2a5204433d354f3508eb93e24c91e49b60e8c0bd15af07241c43301024d5d870\
                1516307a7b1bb381fbc3bfcaefa4d092519b4996840e199e7e2c40d75d593a99\
                3ea002fe4d411a9ef650cd0416033ff04d1bb51ca8377b789a274720695c86f5\
                e70ecb56c4abcb3b6ff88edf48677c273ca24547a67e10d4deab8b9c989c48d9\
                414b1c05bf61b8f8ae73c9d48c37dec55c1dd59fd821e66b06a117d7248b8676\
                e5c15da737cbeb371790a37917130e74",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_half_prover_committed_messages_and_all_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_commitment_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                    3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                    aa8feb7f3a236e92b2da38462358c48a",
        );
        let prover_blind_bytes =
            hex_to_bytes("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                a1fe94ec24e6d325d2494e10bdc395bd82e613e8dd08ca8f4eeffee294246b93\
                21cc0e5997de7ae473a4d4c39f27b9088c815c0ff4f8ff7da0ef6d3338e048e2\
                b28d98e148e1e8717b6ff6dfc4c74379aab5f409212986ce667c0b9ae4c48c27\
                8720d66be792af1a62989ea56f433a17f05af1f761b48b9ae2bb244182081116\
                80d75c8b7d781186afedbe7c7f293b644cad32737358fed7adc516ec64319298\
                fa4d22e2119db88e846f4d8665858b0930016a56245de910baa76242d3b2f48d\
                61e78491695773063178c1f35d392198616b619fb5019a17fd6ec0bbbf6820cf\
                e6bf8eb58801049465d86aca537126b759f76d65d2239d71584c85c371ff9bc0\
                fd38ebd6623df2cba477ef0ffb0c0c9f35e8a6b4c2c865f4e1b0e5bc543601c0\
                a209816a420bd9a6b71e0cf9bc330cc2078c8d74f7c741b2fc6ce3e553fe11d4\
                ee2e02b34e81bd06074dfc892b87046a6f77fc07c8857b819c764ae92d3779b4\
                bf76f875b4589b37daad83c6bf1889ba",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_all_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_commitment_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                    3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                    aa8feb7f3a236e92b2da38462358c48a",
        );
        let prover_blind_bytes =
            hex_to_bytes("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                82a7815ebceefbfb5c1728c940b8ec6efe0d64c6c53c5b7e5a01a598f3e904bf\
                4eb43f94f3c41c2c73bf86ad6b4d9a6f87b89bb4c08ab7d0aa1afa52de982fb5\
                f173b88db16b09a25358489da59d7d8da1f603aa83b55a6664e276e8b24985de\
                93c5ee7b5fe52c329660f963fa3a26b9316aaddbdb83e764fdb4323be9870a9d\
                7fa18c9136ad79d06f6de5e820631cd30a1739ba5dd8f204020cf071e8a1a531\
                3e4a3eb1ba058c91f37f397976920eff270ff2bb79bdab9dd006752c915b22e2\
                fff4f362a1dd663b2a178bb7ae08d1a6251e39fb11ff14b24a237ff2d8be9fe8\
                d0db493dc019535e53dd31c0608543fb69f9fb31d1483514e65edc9c51112814\
                09df08b88d333e4cc76fc41a45e49767523813f5e585c562933a6d7fd8b66410\
                2bd4822ba062ccee37ea50a3c9e03fc642b84c7d422155b61d69e5a832e41169\
                bb08748ac245be18e159be1bb343afc170483a8887fe5b889adc43f410529c7f\
                ad530084b1cc90f8854d8bf402def3f90e525e4bc99b5b8b8095495651f2cb68\
                44b91a7832744954ca5bbf9a4f9c863c6b3485ad58bdb54fa6c71058fe29296e\
                ab761ab1a2c4be2db749c40f173f8b2e03ec71a4d9d89d066763fd6a055e6a9e\
                42a3b6a153732a42a5be5bfd2cf85b7d",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_half_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_commitment_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                    3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                    aa8feb7f3a236e92b2da38462358c48a",
        );
        let prover_blind_bytes =
            hex_to_bytes("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                906a557b649ef5fa3ae1b17f814bbf1e78936daed6ac985416ce97bdaada5e87\
                4d60f34074c5f2a8c02b1c33c3cb041294aa3da2e1bb55674a4b94d860f3477b\
                e7eb1adb763894796b285df22112a153ad13c35e4b9707046de269833e27c16d\
                9621b73f05e4c7c543bf995e76ac1013839c6e8a9909b36e979192c5497bcc9f\
                c534aa9296ec36ae43c398cdd328d3b606ebb0642786b508eb1d38893cfffe8c\
                9cff3c385644bd3641e0d1cbeda08bf16902d6dfeefa3ac8f8840a5f155c5469\
                5b908e729b7f0d06fa9453d28746dfae608580fab158d2966ed54a3b528346d7\
                2d49b0d69576b1094b3b14bfcba67af81c4467b424e9ac53fbf9cf8ca7c4cd20\
                ac61243d61d91cd937eb82cb1524e38b24bd0ef235886c9f32e139ffe0b371bf\
                1a310dd4a81bdda3994f1c2f85bd4b775dd2b716ad1a06e4b604448a8bad5a75\
                581b8c655652b284b1f727f52fe74ff501990b95918fdac4a00c3509bcb97837\
                0224b2c38aea21d811f30fcf623aa3f917ca0193ae9fd3ad3f82c7e1dd80c571\
                2d280faa027b90d27ffb37fad3ea7bcc5c69885dfe74acfb07213d01cd974133\
                e5f6c423d7e3fa118c590cbf5edac814486965aadec16206156c97e37f7ebc83\
                7f9482f2b7c97e691bf80d0d4a02ccff38794349ef189ef7e7c909dc0c420236\
                abac3be7613c66e41dee0a3246a759225c2e5be0db5131fee3e284bb3bdc98ff\
                34eccb03eb70cac6b8aedef376110de7",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_no_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_commitment_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                    3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                    aa8feb7f3a236e92b2da38462358c48a",
        );
        let prover_blind_bytes =
            hex_to_bytes("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                98805466f2fb4858dd9f60cfdc24d73b5192df64fce827b6ce942a6f2c8d5b33\
                f7eb7bf178353cf4bac91a4d6b84b536a89f504e4b46dea57ed2bc29d83993d7\
                1fb0b5a012d36aa8c3f0ba25220435be5f1b632166228bbb496eaebc1e38267e\
                b46b5550d6e4d32d2f5559ada94828f729cac8f192a8fdb7aac7ffcf0102fef6\
                8314723ded1927965f30096e5f89103a036f32fb9980015f9d7781f86e661e90\
                d7b01f4c4c1bca0f7e0101098d9abcb603c3945c14b8cb298eecda9e7a8271dd\
                407e68a45c4d2d4842b7095392873ccb4f2a0136ed04e9410b8c65eced108f5b\
                87b9c5b84c5ff95d3345f410d8a0efd51b5d24978c578859f2183cacaffc17c0\
                31c24dc58ffc29d46922e16672140d1b078b8e7e9f87d31663ee49790274b273\
                5bc807562c8e76f3223925ad2c15093e118ed7ec82eb590d8a9227408339f409\
                1363da652e68cdf02c0003c94e35a2085d621447c2b0840b22af2a5d62fea5e8\
                98dba51d93bdd5f23c6b448f722d95d70459fd68f59b617adeb62b0441745b0d\
                69e865e0fc956359e137cf4706286a9764e6b7efd431cde598876b992196c156\
                62ba6c6768ad0ed4291963ac304dfa951c41d7233d6d85d2a9ff903468590ea7\
                87d413205b56d1892fa666230c93a87756d96fe3832930f01826651f8f449a94\
                5c0a3a9b50472c2060eceb566ec39961685560f49c36b50031dc8b4339da942e\
                5c25498919a812209bbff527c332a5e50f27a539f805caa7c1a774034906d2aa\
                e0b6c2db4696d3ed91453ea0f1e42d4129a9812dbddec71d55d3ec1598202db8\
                8e15f3ad7f8eef3098102be8f978785e2327ce643cc12df227ef05f13ab395a6\
                d318c59e2195d410e768cdf9e7a1784c",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_half_prover_committed_messages_and_no_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_commitment_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                    3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                    aa8feb7f3a236e92b2da38462358c48a",
        );
        let prover_blind_bytes =
            hex_to_bytes("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                aff98a4a0bc336e459d47c19816f372de628581bc626fdd20e907db10d2218dd\
                47530fbebc78afed77f2557d344d620d9097016e84b0dc7588686bbeacb44fc5\
                5bb3004bf79e89d82ed37df3e1835975cc63a00b76685eecc4aff51426fb43cb\
                87d8ba852fb786f1cf649271517bcc4bb72af3e3b2fa4ae57bea485b6f9886fe\
                33d0e5bd95d21f4ccaa4d80b64692caa23d32c7368ef99f1b9ab1672ecb3ae73\
                93a3a4d3efa6f4dc18d8563788f97d8b3fb7427593bdc21aed4332d17b94d82b\
                8c20ea1236a756a4ec2cfa5e1050588e04582299196c1f28e04c2349c5d9e717\
                ba6a581ed255f20bf4210f852d2cd95844fdaacf4d8339a14fe7982be4f44781\
                2616433a3e23990c180ec2540c13f9d467e996cd9a2df2bdd1b0bfe3e51c116e\
                13888d21e26ee61d7ca070968bc13e9d3d33dce20dfc52618bfa4d340f558660\
                f41d67d11f5af9a1e185f261a2d14eb667987d700ce77ed24e3b70c29e49c188\
                b5963dfb16ab7c2439ec6824f738e3df128865e180a41b06b1dbad2eed8a8272\
                8fc4dd34046410345c38415d9daaa3076efbbf84b8f3c52c2bf527d10ae882b0\
                790a7f3b6b3e2c877fbb5a7d18bda860278598f1a83c855e67e3b8f8d807b295\
                14d2420753ace9356a39e70fe49c5f2e29cea65820b57f3b25363685a5559c57\
                7ca48046d5eaa35568a935f58dbd9dae2744eb4dfe33cbb66bc2b351f2b634f5\
                08fe2e37ae19c89f14b4d6d6f636890d62e0f4ccb9565d4f8786b429188c7351\
                f08538aff7b760da7867683315700ab549b639a59b9025fbf67ffb34a834d8b9\
                e893d9d5969e9022813c4529115e682758166b4d2b8af72f44b00dff7b769bb9\
                85c40bef59e18034febfd7bb5ee847b13160b0da82b28cd400c53ff004038e67\
                b9fd49511f9e8b69df923f3aa73fb1636f1ee88214bdcd79462a1f7411e0c8ab\
                10a8bba0140c9cddfbcdc88d7ca19dfd",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_no_prover_committed_messages_and_no_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let committed_message_0 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_message_1 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_message_2 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_message_3 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_message_4 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_messages = &vec![
            committed_message_0.as_slice(),
            committed_message_1.as_slice(),
            committed_message_2.as_slice(),
            committed_message_3.as_slice(),
            committed_message_4.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_commitment_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                    3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                    aa8feb7f3a236e92b2da38462358c48a",
        );
        let prover_blind_bytes =
            hex_to_bytes("4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589");
        let prover_blind = Scalar::deserialize(&prover_blind_bytes);

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&prover_blind),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                b27d9bc8c52a582d00db93da283346751c8da54a902703110e511fa39f184ed6\
                c464d78c81d4bbcc57b7de1b31c7644184ba8f06266dfa8b2662b756f8c89bf3\
                b01f7f66753028dc0ca85a0417a4f6d9dae4b393aaf5c152734f210a790a5f96\
                a2ad1aaab7c1f5167484d18bf19570e2fa4d58b481225a1a576286bac7e4353a\
                a7cba80939eabc492347fc05f8bd701f5410ecb5faf54d4a617bddf39bcb314d\
                750257e99db7f0b03d043f8674668479322dc83c5c1e9e05dd760a4e1b5c45a0\
                44072bfe4e0f21bea9cc6362a38664532b4e10d0e7c4751452ff3072470b6919\
                bded88d3e591e96a4b71603944015ca36594432351d9de6309820d5a837e28e6\
                90b662a959833fd51faf6b77e7636f206385eee2d3aa1d99758e1ef310a914f1\
                a9fa3cd8eb2feb170c13de8e36de2dd2726430e0782cd0d5eaef64d11bd871eb\
                27b6b2a9536a4189731b32cd16ee25ba305ee01d99689e66534d58399a514b92\
                813873ed28f377679f3aab6e977d62226dd4fa0eef43f7b69f92ca0d69588fb8\
                339ba0b35d1fbc3623fdf2d761fa537d54b0b2cd094a8bf98f1117a8f665c5f6\
                8f101926f729185a6d830894f4864f606d47b5b5fab349b23b9be04443d1d6be\
                f67a1755bcb5ac2d46e8af259bc449ce19edc5a4a20f5d236bf6089012df8021\
                ebb68c756aa85528a98aa758a5524cf71ccc9867ec837576d092c68844d8ace2\
                81fd063343b212399dcd1cc80fd7cbd822e559df5616c81eb8e6e7768d8f9819\
                b757d3a1f9211d047bdbb172c26e2e3f0a4541d7e30b05d25b6905abba445488\
                543a16729090eb6d0a45cef159f17cea4ebdc307f9191d76dc52277cda93c0ae\
                75d8021ced39b064229271d673cf28ec645ba56637ecf0f54982f78773cf3ae8\
                514dfcd4932c41337c766e9d9e6041bd0a01062da4ad80106520b29888ca5c48\
                93a8b447cf502e6672b038698bf1b7ae0d87c4e546ae98c7b6c21ad1fb56d54e\
                e930ba9524c55705c00b05c3b6dd0c3f42ca9f9c06748cdda8c1ca428122e780\
                a80ae78c66c1d02728ea751dce0ac100134eed0aa579badf2131c90aea352b28\
                586cd1dc6663008e9e38866a9f383aeb",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_commitment_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_undefined_prover_committed_messages_and_half_signer_messages_revealed() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];

        let signature_bytes = hex_to_bytes(
            "\
                    8aa8fdfb190987d1fe1c8e34e69eae25594701958064e4483d74580a4a0f51f0\
                    58a87735d727383b864904aa7b5e4a9b3821a18319df0ccb2e351a9bf75bf1f3\
                    4d8858dde57119bfafd8ff56e0c54fa4",
        );

        let proof = blind_prove(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            None,
            Some(&disclosed_indexes),
            None,
            None,
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(proof.serialize().as_slice()),
            "\
                a8c57d443b888815e25ca197a543c3a007c573cea5d2cc3c7aa312dbe4aa33a6\
                2490ced4d8f5c0a99aeada24f79b2d34b32cb742dab22663402104828af5e085\
                a6019fb073e08374e9be9b1af64140a4d1ce2b8016f85ebca3ebb5aa02847b91\
                936d649f19d0e85a19118e5e13e2beabf2d705e1db59f8945adddafc77310b0a\
                02042093a5477d9efd4a98cb2fad4dc535fa9f5e6a96f744ece30bbf1fcca709\
                d5b4fcc8c390b4e2ad755292cc20817141d9348e4a7d7c864493625c8aaa455c\
                486afab64ae63f56c10b90047bbfa20825b2cb00f19ee3b54f7c7bdcea55f581\
                1803b9cff2c2f2e96495dd12236e17c9581997b7880062715aa7deec4ca4b3b4\
                eebba824cbe0adcba83f8e70bc0004ee350b5365138297983171d9cca33ca237\
                6157f390a724f857b4212fe834898d332a582083b8791969d2a07057722a22b4\
                4132c5fc2ed0035b3b2e71f9ec08ebc33e019a1fa76bd8d642da21cd0a8b3608\
                0203c2c4d5b10411e90b8bebd454040556480519175f28f31210870454bfad29\
                05d49e9b655b5bea6318955ba210938b279717a2b1e1d34cccfddfe9c8e3729f\
                6e92e28197a09459c6dcd56e3920a0d73954d79b681f1e93f70566a73f42610c\
                389ec3f0d65a4727229df891a61511d2",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(10),
            Some(&disclosed_messages),
            None,
            Some(&disclosed_indexes),
            None,
            &cipher,
        );

        assert!(validation_result);
    }

    #[test]
    fn sha_256_pseudonym_all_committed_messages_and_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_committed_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb6\
                    21a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe\
                    34c00ca333a9006e769b4930e39210c8",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                80c5bbf18019cab060588417725e00cb1b21aa86d79100af2c2cf90d6f2b8a04\
                2196bba6e686adaceebaad41a15ead368fbf593c7170044f4290d90484013c22\
                4c7104650e8eaa874f8456879988a403295aa6de5c6a00af182e68e5c01ab2ce\
                8bbe372d8ec346fdd3c6cd07e857490b46c0169fa367286cda03204ef9a5615b\
                faabb50b47ab8ff77c87b890f400f49e10ada3b9b8add504356e8ec72ac512a2\
                0aa9b2f05e0dd58f409533d2157d36355d71d3458e86b39df14b591b8460f578\
                4f9e7de26bebd3bb68d30a4a7baf55a84eda86f3d04aa375b988e550d81face6\
                020808875ed84263f23252545ad66b2c2ea39d49d2fdeb716f67039bbb6e6e88\
                99ebe394623be9508f3f850302fe0e530031541ba38a3a0aa195344002fbb453\
                e065d22ce32ed9079baa4e553d31d0eb617597a06f858d771f98e38f1a708718\
                b838e0e50fa5ad9ca8ef61284deb2b3c",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn sha_256_pseudonym_half_committed_messages_and_all_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let disclosed_committed_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb6\
                    21a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe\
                    34c00ca333a9006e769b4930e39210c8",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                b3609d5604e27ef07ed771fbe781640c4945f65626c1ec447e836ae27914cccf\
                69c91817af6a29d32d83c895540c9cf1b959e4cc8e689ab3b3f8b2247cd4be9e\
                82cc19af253ed1785ca1a34a97267f9d301539d1f7f204816d7b91e8e32ab82e\
                a30a03cf553a9c598db24b5a1da8b69aadb79e0a942321c1621035cd6d275b68\
                8a5a18fe740d3e1ef58f50819940cb963ce17df31e0f03dc5d326bbbe0772446\
                8f3d4f693a70a98cb7cbe6bd7596c7bf592b58a7f2bf640a673d33d669a528a2\
                0475befc50bf69bdf78160cac32a3521419dec99be743e27d975fff7077e322c\
                b163d4088be7492c3c7e2104bdaac0a84597622aac2f1c5d85fa9f199fc562c0\
                01c01ac9ad614827bbd0b2d43602c2bb6d722fb78212e9d169252f7ad85f77e0\
                43f6cb9acf117308a7b2e8d03a77ceba4bee9a1fb735ca38048dc9a98c54d3bd\
                3413b45223c59e15afb0c26f01ff66f137179d0006e1584323581974b75cb784\
                93c87ffe12f432d7ed812fc95424a8c24635c8a4a27781a120bf80df9db922f9\
                ca1ad13da46a49bb0094847603083b63",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn sha_256_pseudonym_all_committed_messages_and_half_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_committed_indexes = vec![0, 1, 2, 3, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb6\
                    21a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe\
                    34c00ca333a9006e769b4930e39210c8",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                9862cf4d03193c24f13781a02394df3f7b9ce04511592f4b8a1ec0e24331397b\
                a967ea5bf1053b99f1c82e6e0351e1d0b7934c1a1d935eb89de7b45c427f0a55\
                0b9432d0a58f594098ba0f8f470f9f2e4c8b4a50736d3b51d3810fa18d4b3438\
                83e607bcc4bdc4e76a5b39161ca96391354facdfa4fa47cc5b0fe1bd91768f20\
                139e599d4ee9bbc231bf3044cf2385d768b0ebf68e5ce4d8cc846fb7c6bd8f64\
                1e44a68170462ce0d5204045544c60a5183b0116de517928cb1aadb5e59c89c8\
                a77bc0df77de9fb1134d66ca9454f0cf603952748fd41c40dbaa4d9ef1b30980\
                4ec7f158db099fcd0c7866b6b3336ff3406ea07011efa8af032b60ab5e93baa2\
                0db28a5b31478ebbd9440f33d69028a23339683c120fdd978369b26d05a2a029\
                c76f5277fb058431623a2c9be517ba4b619c942be097ddf277c9884aa3fc9faa\
                e80f3dafaa2ad535721c247760838a603842da75da3ba276344f4cf0713c91b7\
                6df021356e667db02b70f714ab71d966664d9e679f1527473a3ffa9c930782a8\
                f349b8dceade0fb6b8121a276ab689fe5330cf4e6d5650b13ac4a8ab4930da89\
                4f94d2dae09fc94e664dd8490fee8a7d5a7dd52f10f88c828d7ea137fb95103e\
                dd7cc5497ed3e98bc2c6582e34234d2131328cfa0e1e39db013c0988dcf4978c\
                866c1e757c67e9a729d308ca22ed8f0d",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn sha_256_pseudonym_half_committed_messages_and_half_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_committed_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb6\
                    21a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe\
                    34c00ca333a9006e769b4930e39210c8",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                8a62e1920818e649ed51e28aacf1eb069dc06817882b6c5018801c3acfff44a6\
                d311ec93ba167ad6538de41aa08f8b37970916033aefb249f7d458f9e10f6303\
                1cb1c45cc64b094d07dd4cac6b2341b31a454581ae68b59eb7fc56cfac702ff7\
                92abc5535f3fc5db8e0765fb902d648b64d8640d6bb53f09553ba8c1e125de90\
                2abf7a3aa01b541e0a97c2895fc452570bd08e5b513b1d416c3c43b8817688b9\
                06b67c7eab1e39bdcd1f72159c657bc15252e9747d127ec276a560cf51df9d56\
                d595a27a804dd219dc202afe946a14543f44ef35f10dc02e00264b590af5a4db\
                d2271eaf67d6701aac36f781d7278e321d023d8ef84426176b3aa6b142e18cbe\
                0dd4b66fd1b740d700b38f48714aaa7857bcb869dbc53971c58ae9f521005a6d\
                73b4cd6b86a4e75af543477dc16fb9685145d1c847a8912577bbfd5367a5d9dc\
                e109b5b50e30a58a4ba349afe98183730fdbf9baeeda7efb9c2592d33c6a0629\
                4b048c9c7ae97f5e53610399c57385aa0afb15864255c6891a72c3e668afd970\
                bc832694c6faff88ede68b04932b28914bdfa291bf16a7426528b25f4f2df26c\
                2816a341ab3c5473a42ed5d54b91c16a0a4c16b3556a768fe0b33de2e06fe4d0\
                d634746d1bed19363c9d1b779e1b39b846d660b16c66baa30b377800b3cbecde\
                0a2a96a6672af4dd6178c24e1396ead043bd37eaeb27e027c18581a523ad9cc3\
                11cab68b972b7143eecaa519c81499402748906732822a82890eb57f7561c8b5\
                db183574eff0fafc91eb05ca80072e1d",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn sha_256_pseudonym_half_committed_messages_and_no_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![0, 2, 4, 6, 8];
        let disclosed_committed_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb6\
                    21a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe\
                    34c00ca333a9006e769b4930e39210c8",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                add3221aa11a1857cc7a42ca1a92275f4ce564f0914b181751c5a900fd4f8995\
                e72ec98b9033758cbc33761549ed0b538e711dc3d91b28d4309648731ad9c749\
                15ffa9c17ded7f4df05ca10c0c44adaa4d5b945f6d008692cd14bdd59ea012ef\
                84460c9e82eaa6b55f48b0a2c3a437e72b96c568716df6fc4dcf9cce56b7ddc8\
                fcc7dbcec9090ef6794e861dc8f7fea255707d38665a55aa3b6d177d4282b81e\
                d0b93367dd6208700a0207abe13593d1288974c28380354320a1e73fa5fb9746\
                18d5a852a5e5deb3e06afe3bc82315a73dc4917f064a21eed9f702932588254f\
                bed51202cc1fc0a38ca42c243816ca2b6dfefd7c76dcfad9321c1907371b78be\
                f1fccd5e42be16d36757f2c0f6ef15f52ac81bd46499410f75bca592b750aa59\
                6c07ca4fd6bd244c9d321f9422e8c15d504cd6614df24c75854030793c703daf\
                a917e24162a4ca6aef0826597c3ba41c1586b1971334fc632f83505fc7dd1264\
                1aa603260b1425d896d6f363bd61ef732dc56aaf64ae6d55047dc52bf73c1381\
                61c16a46f995b20999a53599a48bb1ba734a3be4f4dfe1c9ff81efec2d4970a0\
                b800de0ffcbbf209c83c55c462b756d9200bbf2ccb5d007daaa344067037f525\
                c63d5fa8ef51ac2d2fc7f0b380cfbd2c29996b8add5333b467b4505973ba289a\
                5d10efa4bc8ca51933ba48b16d82977f43c19bda9aff9a963d12e6a1bf073575\
                90d49d23de780ce9486c5103d25682f32931aaaa162ed80b9066eb60125c33e1\
                91793c910f1557f9790ffddbaea850d42e510b4661b3038ed606e59452ec8318\
                7b88af9488ebf83797ace665449acd054471790c1fe9a37bc23aa50b3dde7fe2\
                4c2de1955fda7ddcb8dfb62baf91db20373282dd627ee2b2dd2595deb4b502e0\
                d8c319f49a47464ba97e6de55adc99d1",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn sha_256_pseudonym_no_committed_messages_and_half_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_committed_indexes = vec![0, 2, 4];

        let signature_bytes = hex_to_bytes(
            "\
                    99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb6\
                    21a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe\
                    34c00ca333a9006e769b4930e39210c8",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                a95d0c2f1e89fa4f4049f45ecc89fa8a82589f296657ae2f1b50b73af04e251d\
                97b4822566f24c04b52bdb3c230b540ea55f4db83a932a5803a29573e1a37705\
                a1fa5a8bc59d3bc4e2f2e2bb39471ae191acf4e6738c3d962171dcb16d81063b\
                88b4b9f2b517d1b428806e01b1fd245631e668cbabbe4d4a7d6ca7b6b60fdbc7\
                f234e4b158e41ce72702c8586e260ee42f92cafb6f46f584b11d9ac0cc12d6e0\
                3727ea8f9ef0cdfc6c9d179ce0a8d1042d403a80bd935645cfceb09c455d1c27\
                e1e563489f501482c969710077e49a2e4096157ba62f966f3314d4cdc23f6775\
                8a9e6e302e4dda34a6900067415e05f626644cd91fa518243deafe3ea3dd1134\
                13729b66f3a3aadd7f6a417428609847077a7495d2fb0bd5c54b8733bf735d87\
                6e3f70e46db442c6307829ea4f7229360de17e0ab31c82491cba75560a2bc168\
                59f70f48647f28c3805240924f256b4e7234c8e83b8c569f3fbac04e6157effa\
                690240f38d611ecb61354e2d7ec0870a36da985dabad7847f8939cb91f7dedb3\
                601cec88af2169ff03668f0f381a20bd0e9dbe69cda97561279731e2b04d8fc0\
                d48c9a92ad1f2b857b1bbf6d50ae8a6441ba5eb50c85ed05a3c6eaf00af0f8a8\
                ce2b9f4d4a06d3cff8a243fd11652dd94176236d55d2d390936b15f676f81918\
                1cc2d73f77682db9cc06b9b14a411ce0375c56eb49ef752459c02dc8c065c3f5\
                a8d795497e93a1ab59ae55a5505caec8515efb86c055331b1d8a31ec0fc18108\
                5c1e1ba1ee6df93c32af3f6930814a2552602f381fc24754beb43c9ca9c931ec\
                c7a4c31220970ec805f604c01ed651f1166a583823774ccd6088d1be3b6af9f4\
                2b63178c7d1a5b70196421fbbdc5fb36238c8bbd6bd4cf886036d95abb86e4e7\
                158e87813a5f9ba95df0e853964f4e040c663fcd0c745e54e0c939b8de61176d\
                6d474fca6952dc0fd3720600e525038f32469e79368ded96f86056d48fdd9850\
                ae1dcf7de039024b8940750c8f68d593",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }

    #[test]
    fn sha_256_pseudonym_no_committed_messages_and_no_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let presentation_header =
            hex_to_bytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        let message_0 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let message_1 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let message_2 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let message_3 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let message_4 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let message_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let message_6 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let message_7 = hex_to_bytes("ac55fb33a75909ed");
        let message_8 = hex_to_bytes("96012096");
        let message_9 = hex_to_bytes("");

        let messages = &vec![
            message_0.as_slice(),
            message_1.as_slice(),
            message_2.as_slice(),
            message_3.as_slice(),
            message_4.as_slice(),
            message_5.as_slice(),
            message_6.as_slice(),
            message_7.as_slice(),
            message_8.as_slice(),
            message_9.as_slice(),
        ];

        let committed_msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let committed_msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let committed_msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let committed_msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let committed_msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            committed_msg_1.as_slice(),
            committed_msg_2.as_slice(),
            committed_msg_3.as_slice(),
            committed_msg_4.as_slice(),
            committed_msg_5.as_slice(),
        ];

        let disclosed_indexes = vec![];
        let disclosed_committed_indexes = vec![];

        let signature_bytes = hex_to_bytes(
            "\
                    99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb6\
                    21a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe\
                    34c00ca333a9006e769b4930e39210c8",
        );

        let nym_secret_bytes =
            hex_to_bytes("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc");
        let nym_secret = Scalar::deserialize(&nym_secret_bytes);

        let prover_blindness_bytes =
            "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8";
        let prover_blindness = Scalar::deserialize(&hex_to_bytes(prover_blindness_bytes));

        let context_id =
            hex_to_bytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a");

        let (proof, pseudonym) = blind_prove_with_nym(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&presentation_header),
            Some(&nym_secret),
            Some(&context_id),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            Some(&prover_blindness),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            bytes_to_hex(&proof.serialize()),
            "\
                8a088a3619f2be6061e47e93048b0ea5391e54a8e551e6064f8065e0f09db7be\
                36dacfb2349797d889b9c456a07d0df5b93e0792af6d74293aac66b6be0902cd\
                dab66c1fce327d2690323d6083a80153969a46c2c3f3462fecb3d47fb6c9b909\
                aea8b5cfbebe68f0b88f4e5718ea1a307eb84887e8a28b07cc1ab76f3ba34a9c\
                81a9fa1ad7c2a59dff8b9fd993270ed63cc4723517f556b1657220c7b7e3946d\
                88aaaccd7620eaeb0d52fa272bd2cd871c74d9a5a2ea52d2c4cb309fb267a831\
                5eecb02a37906ae71cf47c50267f198806700d239566921e7b2ae7461fb6f2c1\
                028702469ada2358c769ac5bbe79d3762adcc226be4f743984d8c2dffb27d7ea\
                c58fca920dead9129da6b4ced872e60d5d83b93c38a0d2b51b58967ffb8fa0cb\
                904346755f84969e583ec69d697806d0492180385da37acf8640160c60f82d28\
                3ea0bd23f47362af5eeb1bbbc0c8d8d942a1647d78d787105d49b9493d912522\
                d384e1ddd71ba917cf8eda4a8f2651fe33e9466d024a9771a4288bd0690e07d8\
                dda9dce39b81ebca66509fc4a5990d4639f6d1f8cfd949d2090eda44d55e4356\
                3a33ff0371d4ed7ca039c65064f2b5d957d60baf654f6c2afaf8b49d1933d607\
                d667b77e896ffdfeb1f6572dc6999f1a1ea753e05445a16000c237f762e9cfec\
                ba5f43fc65f126e1ed0d31c7855115540ab6c54ad8f321bc0428b998e52eb77e\
                b5ddcd363a7eb4846d8ca820673d0e40447a71b207badeb394d7037fbce0c30e\
                b50c6d2cde0f5fc1212fb6be8ed392e4448c278d7afc6992a4cbab933429a5f8\
                7e372b0ef6d11439862796fb130cc1d1621785848ae5512894ed4e97f87a1a1a\
                85c0fe5ea8ed7e6ceabedc26c935266106cf619410fea374f4ba9604d01ce60e\
                f4dfd25962b3174d007d997b9ef7c8120111a9a040d7cf4ef178da51d74627cd\
                a2cfb52ee6c33c3584bc37e7d89d727a02fbb2ab1639e5c5355c2233112d49bc\
                48ef30e09f11a9933feeb936d26635af0445eb7eafdac863378175b936461a71\
                83d848406b788f42c2dead4d419e51f150a7dc72cb46987b2444321a0ce9bc09\
                0fd936aa1f27dd3dffe3a8c5d490e96924d132773d7773051b9d594aa059a479\
                3902948cf5ef5743e8865bf7cb320ada",
        );

        assert_eq!(
            bytes_to_hex(&pseudonym.serialize()),
            "b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487",
        );

        let disclosed_messages = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();
        let disclosed_committed_messages = committed_messages
            .iter()
            .enumerate()
            .filter(|(i, _)| disclosed_committed_indexes.contains(i))
            .map(|(_, m)| *m)
            .collect::<Vec<_>>();

        let validation_result = blind_validate_with_nym(
            &public_key_bytes,
            &proof,
            Some(&header),
            Some(&presentation_header),
            Some(&pseudonym),
            Some(&context_id),
            Some(10),
            Some(&disclosed_messages),
            Some(&disclosed_committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_committed_indexes),
            &cipher,
        );
        assert!(validation_result);
    }
}
