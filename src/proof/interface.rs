use crate::proof::Proof;
use crate::signature::Signature;
use crate::suite::cipher::Cipher;
use crate::suite::constants::PADDING_API_ID;
use crate::utils::generator::create_generator;
use crate::utils::scalar::message_to_scalars;

/// Create a BBS proof, which is a zero-knowledge proof-of-knowledge of a BBS Signature, while
/// optionally disclosing any subset of the signed messages.
///
/// Other than the signer's public key, the BBS Signature and the signed header and messages, this
/// operation also accepts a presentation header, which will be bound to the resulting proof. To
/// indicate which of the messages are to be disclosed, the operation accepts a list of integers in
/// ascending order, each representing the index of a message in the list of signed messages.
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
pub fn prove(
    public_key: &[u8],
    signature: &Signature,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    cipher: &Cipher,
) -> Proof {
    let empty_message_vec = vec![];
    let inner_messages = messages.unwrap_or(&empty_message_vec);

    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || H2G_HM2S_".
    let api_id = [cipher.id, PADDING_API_ID].concat();

    // Procedure:
    //
    // 1. message_scalars := message_to_scalars(messages, api_id).
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
    let message_scalars = message_to_scalars(inner_messages, Some(&api_id), cipher);
    let generators = create_generator(inner_messages.len() + 1, Some(&api_id), cipher);
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
    )
}

/// Validate a BBS proof, given the signer's public key, a header, a presentation header, a list of
/// disclosed messages, and the indexes of those messages in the original list of signed messages.
///
/// Validating the proof guarantees the authenticity and integrity of the header and the disclosed
/// messages, as well as the knowledge of a valid BBS Signature.
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
pub fn verify(
    public_key: &[u8],
    proof: &Proof,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    disclosed_messages: Option<&Vec<&[u8]>>,
    disclosed_indexes: Option<&Vec<usize>>,
    cipher: &Cipher,
) -> bool {
    let empty_vec = vec![];
    let inner_disclosed_messages = disclosed_messages.unwrap_or(&empty_vec);

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
    let r = inner_disclosed_messages.len();

    // Procedure:
    //
    // 1. message_scalars := message_to_scalars(disclosed_messages, api_id).
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
    let message_scalars = message_to_scalars(inner_disclosed_messages, Some(&api_id), cipher);
    let generators = create_generator(u + r + 1, Some(&api_id), cipher);
    super::core::verify(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::subroutine::{calculate_challenge, finalize_proof, initialize_proof};
    use crate::suite::instance::BLS12_381_G1_XOF_SHAKE_256;
    use crate::utils::format::{bytes_to_hex, hex_to_bytes};
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
        let generators = create_generator(2, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(&vec![&msg_bytes], Some(&api_id), &cipher);
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

        let verified = verify(
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
}
