use super::subroutine::{commit, deserialize_and_validate_commit, finalize_blind_sign};
use super::{CommitmentWithProof, Signature};

use crate::suite::cipher::Cipher;
use crate::suite::constants::{LENGTH_G1_POINT, LENGTH_SCALAR, PADDING_API_ID, PADDING_BLIND};

use crate::utils::blind::{calculate_b, prepare_parameters};
use crate::utils::generator::create_generators;
use crate::utils::scalar::messages_to_scalars;

use bls12_381::{G1Affine, Scalar};

/// Generate a BBS Signature from a secret key, over a header and a set of messages.
///
/// - `secret_key`: a scalar representing the secret key.
/// - `public_key`: an octet string representing the public key.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of octet strings containing the messages to be signed.
/// - `cipher`: a cipher suite.
///
/// Return a BBS Signature.
pub fn sign(
    secret_key: &Scalar,
    public_key: &[u8],
    header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    cipher: &Cipher,
) -> Signature {
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
    // 3. signature := core_sign(
    //          secret_key,
    //          public_key,
    //          generators,
    //          header,
    //          message_scalars,
    //          api_id,
    //          cipher).
    // 4. If signature is INVALID, return INVALID.
    // 5. Return signature.

    let message_scalars = messages_to_scalars(messages, Some(&api_id), &cipher);
    let generators = create_generators(messages.len() + 1, Some(&api_id), &cipher);
    super::core::sign(
        &secret_key,
        &public_key,
        &generators,
        header,
        Some(&message_scalars),
        Some(&api_id),
        &cipher,
    )
}

/// Validate a BBS Signature, given a public key, a header, and a set of messages.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a BBS Signature.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of octet strings containing the messages to be signed.
/// - `cipher`: a cipher suite.
///
/// Return `true` if the signature is valid, `false` otherwise.
pub fn verify(
    public_key: &[u8],
    signature: &Signature,
    header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    cipher: &Cipher,
) -> bool {
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
    // 3. result := core_verify(
    //          public_key,
    //          signature,
    //          generators,
    //          header,
    //          message_scalars,
    //          api_id,
    //          cipher).
    // 4. Return result.

    let message_scalars = messages_to_scalars(messages, Some(&api_id), &cipher);
    let generators = create_generators(messages.len() + 1, Some(&api_id), &cipher);
    super::core::verify(
        &public_key,
        &signature,
        &generators,
        header,
        Some(&message_scalars),
        Some(&api_id),
        &cipher,
    )
}

/// Create a commitment to a set of messages that the prover intend to include in the blind signature. This operation
/// returns both the serialized combination of the commitment and its proof of correctness, as well as the random scalar
/// used to blind the commitment.
///
/// - `committed_messages`: a list of octet strings containing the messages to be committed.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a tuple comprising from an octet string and a random scalar in that order.
pub fn blind_messages(
    committed_messages: Option<&Vec<&[u8]>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
    random_scalar_sampler: Option<fn(usize) -> Vec<Scalar>>,
) -> (CommitmentWithProof, Scalar) {
    let default_committed_messages = vec![];
    let default_api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

    let committed_messages = committed_messages.unwrap_or(&default_committed_messages);
    let api_id = api_id.unwrap_or(&default_api_id);

    // Procedure:
    //
    // 1. committed_message_scalars := messages_to_scalars(committed_messages, api_id).
    // 2. blind_generators := create_generators(len(committed_message_scalars) + 1, "BLIND_" || api_id).
    // 3. return core_commit(committed_message_scalars, blind_generators, api_id).

    let committed_message_scalars = messages_to_scalars(committed_messages, Some(&api_id), cipher);
    let l = committed_message_scalars.len() + 1;
    let blind_generator_dst = [PADDING_BLIND, api_id].concat();
    let blind_generators = create_generators(l, Some(&blind_generator_dst), cipher);
    commit(
        &blind_generators,
        Some(&committed_message_scalars),
        Some(&api_id),
        cipher,
        random_scalar_sampler,
    )
}

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
pub fn blind_sign(
    secret_key: &Scalar,
    public_key: &[u8],
    commitment_with_proof: Option<&[u8]>,
    header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    cipher: &Cipher,
) -> Signature {
    let default_commitment_with_proof = vec![];
    let default_messages = vec![];

    let commitment_with_proof = commitment_with_proof.unwrap_or(&default_commitment_with_proof);
    let messages = messages.unwrap_or(&default_messages);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || BLIND_H2G_HM2S_".

    let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();
    let blind_api_id = [PADDING_BLIND, cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. M := len(commitment_with_proof).
    // 3. If M != 0, M := M - octet_point_length - octet_scalar_length.
    // 4. M := M / octet_scalar_length.
    // 5. If M < 0, return INVALID.

    let l = messages.len();
    let mut m = commitment_with_proof.len();
    if m != 0 {
        if m < LENGTH_G1_POINT + 2 * LENGTH_SCALAR {
            panic!("The commitment with proof should be at least a G1 point and two scalars.");
        }
        m -= LENGTH_G1_POINT + 2 * LENGTH_SCALAR;
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
    let blind_generators = create_generators(m + 1, Some(&blind_api_id), cipher);

    let commitment = deserialize_and_validate_commit(
        Some(&commitment_with_proof),
        Some(&blind_generators),
        Some(&api_id),
        cipher,
    );

    let message_scalars = messages_to_scalars(messages, Some(&api_id), cipher);

    let res = calculate_b(
        &generators,
        Some(&commitment),
        Some(&message_scalars),
        cipher,
    );
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
pub fn blind_verify(
    public_key: &[u8],
    signature: &Signature,
    header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    committed_messages: Option<&Vec<&[u8]>>,
    secret_prover_blind: Option<&Scalar>,
    cipher: &Cipher,
) -> bool {
    let default_messages = vec![];
    let default_committed_messages = vec![];
    let default_secret_prover_blind = Scalar::zero();

    let messages = messages.unwrap_or(&default_messages);
    let committed_messages = committed_messages.unwrap_or(&default_committed_messages);
    let secret_prover_blind = secret_prover_blind.unwrap_or(&default_secret_prover_blind);

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
        Some(&messages),
        Some(&committed_messages),
        messages.len() + 1,
        committed_messages.len() + 1,
        Some(&secret_prover_blind),
        Some(&api_id),
        cipher,
    );
    super::core::verify(
        public_key,
        signature,
        &generators,
        header,
        Some(&message_scalars),
        Some(&api_id),
        cipher,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Signature;
    use crate::suite::instance::{BLS12_381_G1_XMD_SHA_256, BLS12_381_G1_XOF_SHAKE_256};
    use crate::utils::format::{bytes_to_hex, hex_to_bytes};
    use crate::utils::generator::create_generators;
    use crate::utils::scalar::{calculate_domain, seeded_random_scalars};
    use crate::utils::serialize::{Deserialize, Serialize};
    use bls12_381::Scalar;

    #[test]
    fn shake_256_single_message() {
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let message_bytes =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(2, Some(&api_id), &cipher);

        let domain = calculate_domain(
            &public_key_bytes,
            generators[0],
            generators[1..].to_vec(),
            Some(&header),
            Some(&api_id),
            &cipher,
        );
        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let messages = vec![message_bytes.as_slice()];
        let signature = sign(
            &secret_key,
            &public_key_bytes,
            Some(&header),
            Some(&messages),
            &cipher,
        );
        let verification_result = verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            domain.to_string(),
            "0x2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9"
        );
        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7\
                1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b\
                97a12025a283d78b7136bb9825d04ef"
        );
        assert!(verification_result);
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
        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(11, Some(&api_id), &cipher);

        let domain = calculate_domain(
            &public_key_bytes,
            generators[0],
            generators[1..].to_vec(),
            Some(&header),
            Some(&api_id),
            &cipher,
        );
        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let messages = vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];
        let signature = sign(
            &secret_key,
            &public_key_bytes,
            Some(&header),
            Some(&messages),
            &cipher,
        );
        let verification_result = verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            domain.to_string(),
            "0x6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b"
        );
        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08\
                faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67\
                fb7d3253e1e2acbcf90ef59a6911931e"
        );
        assert!(verification_result);
    }

    #[test]
    fn shake_256_no_header() {
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

        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(11, Some(&api_id), &cipher);

        let domain = calculate_domain(
            &public_key_bytes,
            generators[0],
            generators[1..].to_vec(),
            None,
            Some(&api_id),
            &cipher,
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let messages = vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let signature = sign(
            &secret_key,
            &public_key_bytes,
            None,
            Some(&messages),
            &cipher,
        );
        let verification_result = verify(
            &public_key_bytes,
            &signature,
            None,
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            domain.to_string(),
            "0x333d8686761cff65a3a2ef20bfa217d37bdf19105e87c210e9ce64ea1210a157"
        );
        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15\
                f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d\
                3ca745ecbe39f655ea61fb700137fded"
        );
        assert!(verification_result);
    }

    #[test]
    fn shake_256_modified_message() {
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let message_bytes = hex_to_bytes("");
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

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let messages = vec![message_bytes.as_slice()];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn shake_256_extra_unsigned_message() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
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

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let messages = &vec![msg_1.as_slice(), msg_2.as_slice()];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn shake_256_missing_message() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");

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

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let messages = &vec![msg_1.as_slice(), msg_2.as_slice()];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn shake_256_reordered_messages() {
        let msg_10 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_9 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_8 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_7 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_6 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_4 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_3 = hex_to_bytes("ac55fb33a75909ed");
        let msg_2 = hex_to_bytes("96012096");
        let msg_1 = hex_to_bytes("");

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

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn shake_256_wrong_public_key() {
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
                    b24c723803f84e210f7a95f6265c5cbfa4ecc51488bf7acf24b921807801c079\
                    8b725b9a2dcfa29953efcdfef03328720196c78b2e613727fd6e085302a0cc2d\
                    8d7e1d820cf1d36b20e79eee78c13a1a5da51a298f1aef86f07bc33388f089d8",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08\
                    faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67\
                    fb7d3253e1e2acbcf90ef59a6911931e",
        );
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn shake_256_wrong_header_valid_signature() {
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

        let header = hex_to_bytes("ffeeddccbbaa00998877665544332211");
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

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn shake_256_blind_commit_no_messages_with_proof() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

        let committed_messages: Vec<&[u8]> = vec![];
        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249"
        );
        
        
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365\
                a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4e\
                d9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d4194\
                06945f1e79d4be58dbaf9dc95237c951"
        );
    }

    #[test]
    fn shake_256_blind_commit_multiple_messages_with_proof() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        // let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

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
        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            // Some(&api_id),
            None,
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598\
                a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c8\
                24bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e1\
                4105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad\
                2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b0\
                5d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c972\
                6d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac2884\
                0e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797bef\
                f88b1c8e8459dba0730ecace09177f79"
        );
    }

    #[test]
    fn shake_256_blind_no_prover_committed_messages_no_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

        let messages: Vec<&[u8]> = vec![];
        let committed_messages: Vec<&[u8]> = vec![];

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365\
                a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4e\
                d9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d4194\
                06945f1e79d4be58dbaf9dc95237c951"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                94403c30badaccf53c4d5f6a15e66c98fe021c149254a5b54b75f15fe6749788\
                97284db9fb6a8716fa17e69c80acfef45e56e7199abc42be2ba46cdfef5b30b3\
                cc1ed12802225733183f02fc535a2127",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn shake_256_blind_multiple_prover_committed_messages_no_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

        let messages: Vec<&[u8]> = vec![];
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

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598\
                a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c8\
                24bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e1\
                4105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad\
                2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b0\
                5d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c972\
                6d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac2884\
                0e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797bef\
                f88b1c8e8459dba0730ecace09177f79"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                82f5137b728baea7d23bc610888e7dbabdae8b6ce404d5e591608bc0d550f246\
                194cbab590eda33dd2a8aafc0f107f0f3158d330459681d5156d65f6dbdc7b3b\
                fd003212a89052d668935b53895e70d2",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn shake_256_blind_no_prover_committed_messages_multiple_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

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

        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let committed_messages: Vec<&[u8]> = vec![];

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365\
                a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4e\
                d9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d4194\
                06945f1e79d4be58dbaf9dc95237c951"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                a4999abd5d20fd706cabeb2a44e6dd42b76d6ccfc29ac83d947351a19807e57b\
                0d951d4b79d03250e0e84cc1204a143336c4decbbc7417060f1fc44159192e23\
                e437fe0aaee3971ce89e901f99405b90",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn shake_256_blind_multiple_prover_committed_messages_multiple_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

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

        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
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

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XOF_SHAKE_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598\
                a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c8\
                24bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e1\
                4105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad\
                2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b0\
                5d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c972\
                6d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac2884\
                0e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797bef\
                f88b1c8e8459dba0730ecace09177f79"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61\
                fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1\
                5ab02449b8d375f869a8df15db78eb02",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn shake_256_blind_undefined_prover_committed_messages_multiple_signer_messages() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;

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

        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
        let public_key_bytes = hex_to_bytes(
            "\
                    92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                    8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                    eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            None,
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                b80f73e22cf6c050159018539af4fd2c8ed75a7dfa247feadbdecd983e16ddb3\
                3ac5c61bfd7f17b4063a7957456ddc0b71d46e6a05b1a464df601aabf480edf1\
                7ff1d6052089c294577fcfb7b851baad",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            None,
            None,
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn sha_256_single_message() {
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let message_bytes =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(2, Some(&api_id), &cipher);

        let domain = calculate_domain(
            &public_key_bytes,
            generators[0],
            generators[1..].to_vec(),
            Some(&header),
            Some(&api_id),
            &cipher,
        );
        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let messages = vec![message_bytes.as_slice()];
        let signature = sign(
            &secret_key,
            &public_key_bytes,
            Some(&header),
            Some(&messages),
            &cipher,
        );
        let verification_result = verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            domain.to_string(),
            "0x25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c"
        );
        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525\
                3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb\
                4c892340be5969920d0916067b4565a0"
        );
        assert!(verification_result);
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
        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(11, Some(&api_id), &cipher);

        let domain = calculate_domain(
            &public_key_bytes,
            generators[0],
            generators[1..].to_vec(),
            Some(&header),
            Some(&api_id),
            &cipher,
        );
        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let messages = vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];
        let signature = sign(
            &secret_key,
            &public_key_bytes,
            Some(&header),
            Some(&messages),
            &cipher,
        );
        let verification_result = verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            domain.to_string(),
            "0x6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47"
        );
        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146\
                3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36\
                32078557b2ace7d44caed846e1a0a1e8"
        );
        assert!(verification_result);
    }

    #[test]
    fn sha_256_no_header() {
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

        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generators(11, Some(&api_id), &cipher);

        let domain = calculate_domain(
            &public_key_bytes,
            generators[0],
            generators[1..].to_vec(),
            None,
            Some(&api_id),
            &cipher,
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let messages = vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let signature = sign(
            &secret_key,
            &public_key_bytes,
            None,
            Some(&messages),
            &cipher,
        );
        let verification_result = verify(
            &public_key_bytes,
            &signature,
            None,
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            domain.to_string(),
            "0x41c5fe0290d0da734ce9bba57bfe0dfc14f3f9cfef18a0d7438cf2075fd71cc7"
        );
        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4\
                f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fd\
                c63a32731347e810fd12e9c58355aa0d"
        );
        assert!(verification_result);
    }

    #[test]
    fn sha_256_modified_message() {
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let message_bytes = hex_to_bytes("");
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

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let messages = vec![message_bytes.as_slice()];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }
    //
    #[test]
    fn sha_256_extra_unsigned_message() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
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

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let messages = &vec![msg_1.as_slice(), msg_2.as_slice()];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn sha_256_missing_message() {
        let msg_1 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_2 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");

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

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let messages = &vec![msg_1.as_slice(), msg_2.as_slice()];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn sha_256_reordered_messages() {
        let msg_10 =
            hex_to_bytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let msg_9 =
            hex_to_bytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
        let msg_8 = hex_to_bytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
        let msg_7 = hex_to_bytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
        let msg_6 = hex_to_bytes("496694774c5604ab1b2544eababcf0f53278ff50");
        let msg_5 = hex_to_bytes("515ae153e22aae04ad16f759e07237b4");
        let msg_4 = hex_to_bytes("d183ddc6e2665aa4e2f088af");
        let msg_3 = hex_to_bytes("ac55fb33a75909ed");
        let msg_2 = hex_to_bytes("96012096");
        let msg_1 = hex_to_bytes("");

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

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn sha_256_wrong_public_key() {
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
                    b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20\
                    610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d\
                    0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6",
        );
        let signature_bytes = hex_to_bytes(
            "\
                    8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146\
                    3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36\
                    32078557b2ace7d44caed846e1a0a1e8",
        );

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn sha_256_wrong_header_valid_signature() {
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

        let header = hex_to_bytes("ffeeddccbbaa00998877665544332211");
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

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let verification_result = verify(
            &public_key_bytes,
            &Signature::deserialize(&signature_bytes),
            Some(&header),
            Some(&messages),
            &cipher,
        );
        assert!(!verification_result);
    }

    #[test]
    fn sha_256_blind_commit_no_messages_with_proof() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

        let committed_messages: Vec<&[u8]> = vec![];
        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef\
                60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09\
                ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf\
                5306bcabf3e7cc95f5ba98cdd9bf3768"
        );
    }

    #[test]
    fn sha_256_blind_commit_multiple_messages_with_proof() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

        let msg_1 =
            hex_to_bytes("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3");
        let msg_2 = hex_to_bytes("a75d8b634891af92282cc81a675972d1929d3149863c1fc0");
        let msg_3 = hex_to_bytes("835889a40744813a892eff9deb1edaeb");
        let msg_4 = hex_to_bytes("e1ca9729410dc6ba");
        let msg_5 = hex_to_bytes("");

        let committed_messages = vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
        ];
        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cf\
                e2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e\
                82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885\
                d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af\
                8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5\
                c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5d\
                fff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928\
                bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed\
                3968b396a07f079b22b5bf2139e51a03"
        );
    }

    #[test]
    fn sha_256_blind_no_prover_committed_messages_no_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

        let messages: Vec<&[u8]> = vec![];
        let committed_messages: Vec<&[u8]> = vec![];

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef\
                60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09\
                ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf\
                5306bcabf3e7cc95f5ba98cdd9bf3768"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                ab54c35fb2af5c75d6368bc5772547e126d60a92205d011bb9ee5d1149432e91\
                611fd376fe5b79d6ed7c2ba00a19b7434744945fd77bf02cd4628a6e5deeae50\
                768116d55510251bb6a716a38340e184",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn sha_256_blind_multiple_prover_committed_messages_no_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

        let messages: Vec<&[u8]> = vec![];
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

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cf\
                e2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e\
                82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885\
                d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af\
                8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5\
                c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5d\
                fff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928\
                bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed\
                3968b396a07f079b22b5bf2139e51a03"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                b7446e6ae4e8b5707ac0108f3b1049e9ea01bd6b2b4a7dcf06e5ad1c62a9c0b1\
                585829f0e30fba6c9761469ed908deca52ba5499cef2827b99527b4adf1f3052\
                2ce32366385ba87594b8d0e44d156eec",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn sha_256_blind_no_prover_committed_messages_multiple_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

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

        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let committed_messages: Vec<&[u8]> = vec![];

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef\
                60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09\
                ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf\
                5306bcabf3e7cc95f5ba98cdd9bf3768"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                b869cccbe84dce890949db3393c963ead72d044863b2c75bc26c0adfbe08b5bb\
                01db9e4db3313fc660ebb3283634772809d177d191bffde6fe7fbd8ca95d7b84\
                2e434ae973b7e458325b9eb23b6cf076",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn sha_256_blind_multiple_prover_committed_messages_multiple_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_BLIND, PADDING_API_ID].concat();

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

        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
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

        let (commitment_with_proof, prover_blind) = blind_messages(
            Some(&committed_messages),
            Some(&api_id),
            &cipher,
            Some(|count: usize| -> Vec<Scalar> {
                seeded_random_scalars(
                    b"3.141592653589793238462643383279",
                    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_",
                    count,
                    &BLS12_381_G1_XMD_SHA_256,
                )
            }),
        );

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        assert_eq!(
            prover_blind.to_string(),
            "0x4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"
        );
        assert_eq!(
            bytes_to_hex(&commitment_with_proof.serialize()),
            "\
                a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cf\
                e2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e\
                82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885\
                d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af\
                8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5\
                c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5d\
                fff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928\
                bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed\
                3968b396a07f079b22b5bf2139e51a03"
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            Some(&commitment_with_proof.serialize()),
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c\
                3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc\
                aa8feb7f3a236e92b2da38462358c48a",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            Some(&prover_blind),
            &cipher,
        );

        assert!(verification_result);
    }

    #[test]
    fn sha_256_blind_undefined_prover_committed_messages_multiple_signer_messages() {
        let cipher = BLS12_381_G1_XMD_SHA_256;

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

        let messages = &vec![
            msg_1.as_slice(),
            msg_2.as_slice(),
            msg_3.as_slice(),
            msg_4.as_slice(),
            msg_5.as_slice(),
            msg_6.as_slice(),
            msg_7.as_slice(),
            msg_8.as_slice(),
            msg_9.as_slice(),
            msg_10.as_slice(),
        ];

        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let secret_key_bytes =
            hex_to_bytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
        let public_key_bytes = hex_to_bytes(
            "\
                    a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                    51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                    1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );

        let secret_key = Scalar::deserialize(&secret_key_bytes);
        let signature = blind_sign(
            &secret_key,
            &public_key_bytes,
            None,
            Some(&header),
            Some(&messages),
            &cipher,
        );

        assert_eq!(
            bytes_to_hex(&signature.serialize()),
            "\
                8aa8fdfb190987d1fe1c8e34e69eae25594701958064e4483d74580a4a0f51f0\
                58a87735d727383b864904aa7b5e4a9b3821a18319df0ccb2e351a9bf75bf1f3\
                4d8858dde57119bfafd8ff56e0c54fa4",
        );

        let verification_result = blind_verify(
            &public_key_bytes,
            &signature,
            Some(&header),
            Some(&messages),
            None,
            None,
            &cipher,
        );

        assert!(verification_result);
    }
}
