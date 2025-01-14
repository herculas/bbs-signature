use crate::proof::Proof;
use crate::signature::Signature;
use crate::suite::cipher::Cipher;
use crate::suite::constants::PADDING_API_ID;
use crate::utils::generator::create_generator;
use crate::utils::scalar::message_to_scalars;

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
    use crate::suite::instance::{BLS12_381_G1_XMD_SHA_256, BLS12_381_G1_XOF_SHAKE_256};
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
        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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

        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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

        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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

        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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
        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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

        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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

        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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

        let generators = create_generator(11, Some(&api_id), &cipher);
        let message_scalars = message_to_scalars(
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

        let verified = verify(
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
}
