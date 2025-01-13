use crate::signature::Signature;
use crate::suite::cipher::Cipher;
use crate::suite::constants::PADDING_API_ID;
use crate::utils::generator::create_generator;
use crate::utils::scalar::message_to_scalars;
use bls12_381::Scalar;

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
    let empty_vec = vec![];
    let inner_messages = messages.unwrap_or(&empty_vec);
    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || H2G_HM2S_".
    let api_id = [cipher.id, PADDING_API_ID].concat();

    // Procedure:
    //
    // 1. message_scalars := message_to_scalars(messages, api_id).
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
    let message_scalars = message_to_scalars(inner_messages, Some(&api_id), &cipher);
    let generators = create_generator(inner_messages.len() + 1, Some(&api_id), &cipher);
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
    let empty_vec = vec![];
    let inner_messages = messages.unwrap_or(&empty_vec);
    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || H2G_HM2S_".
    let api_id = [cipher.id, PADDING_API_ID].concat();

    // Procedure:
    //
    // 1. message_scalars := message_to_scalars(messages, api_id).
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
    let message_scalars = message_to_scalars(inner_messages, Some(&api_id), &cipher);
    let generators = create_generator(inner_messages.len() + 1, Some(&api_id), &cipher);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Signature;
    use crate::suite::instance::BLS12_381_G1_XOF_SHAKE_256;
    use crate::utils::format::{bytes_to_hex, hex_to_bytes};
    use crate::utils::generator::create_generator;
    use crate::utils::scalar::calculate_domain;
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
        let api_id = [cipher.id, b"H2G_HM2S_"].concat();
        let generators = create_generator(2, Some(&api_id), &cipher);

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
        assert_eq!(verification_result, true);
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
        let api_id = [cipher.id, b"H2G_HM2S_"].concat();
        let generators = create_generator(11, Some(&api_id), &cipher);

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
        assert_eq!(verification_result, true);
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
        let api_id = [cipher.id, b"H2G_HM2S_"].concat();
        let generators = create_generator(11, Some(&api_id), &cipher);

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
        assert_eq!(verification_result, true);
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

        assert_eq!(verification_result, false);
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

        assert_eq!(verification_result, false);
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

        assert_eq!(verification_result, false);
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

        assert_eq!(verification_result, false);
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

        assert_eq!(verification_result, false);
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

        assert_eq!(verification_result, false);
    }
}
