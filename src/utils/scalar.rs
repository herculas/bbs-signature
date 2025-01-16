use crate::suite::cipher::Cipher;
use crate::suite::constants::{
    LENGTH_MESSAGE_EXPAND, PADDING_HASH_TO_SCALAR, PADDING_MAP_TO_SCALAR,
};
use crate::utils::format::i2osp;
use crate::utils::serialize::Serialize;
use bls12_381::hash_to_curve::HashToField;
use bls12_381::{G1Affine, Scalar};
use digest::consts::U48;
use digest::generic_array::GenericArray;
use getrandom::getrandom;

/// Hash an arbitrary octet string to a scalar value in the multiplicative group of integers modulo the prime order `r`.
///
/// This operation takes as input an octet string representing the octet string to be hashed, and a domain separation
/// tag. The length of the tag MUST be less than 255 octets.
///
/// - `msg`: the octet string to be hashed.
/// - `dst`: the domain separation tag.
/// - `cipher`: the cipher suite.
///
/// Returns a `Scalar` value.
pub fn hash_to_scalar(msg: &[u8], dst: &[u8], cipher: &Cipher) -> Scalar {
    // ABORT if:
    // 1. len(dst) > 255.

    if dst.len() > 255 {
        panic!("hash_to_scalar: dst too long");
    }

    // Procedure:
    // 1. uniform_bytes := expand_message(msg_octets, dst, expand_len).
    // 2. Return os2ip(uniform_bytes) mod r.

    let bytes = (cipher.expand_message)(msg, dst, None);
    let array: GenericArray<u8, U48> = GenericArray::clone_from_slice(&bytes);
    Scalar::from_okm(&array)
}

/// Map a list of messages to their respective scalar values.
///
/// - `messages`: a list of octet strings.
/// - `api_id`: an octet string representing the API identifier. It defaults to an empty string.
/// - `cipher`: the cipher suite.
///
/// Return a list of `Scalar` values.
pub fn message_to_scalars(
    messages: &Vec<&[u8]>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> Vec<Scalar> {
    let inner_api_id = api_id.unwrap_or(&[]);

    // Definition:
    //
    // 1. map_dst: an octet string representing the domain separation tag:
    //             "<api_id> || MAP_MSG_TO_SCALAR_AS_HASH_".
    let map_dst = [inner_api_id, PADDING_MAP_TO_SCALAR].concat();

    // ABORT IF:
    //
    // 1. len(messages) > 2^64 - 1.
    if messages.len() > usize::MAX {
        panic!("messages is too long");
    }

    // Procedure:
    //
    // 1. L := len(messages).
    // 2. For i in (1, 2, ..., L):
    // 3.     msg_scalar_i := hash_to_scalar(messages[i], map_dst).
    // 4. Return (msg_scalar_1, msg_scalar_2, ..., msg_scalar_L).
    messages
        .iter()
        .map(|msg| hash_to_scalar(msg, &map_dst, cipher))
        .collect()
}

/// Sample a random scalar value.
///
/// Return a `Scalar` value.
#[allow(dead_code)]
pub fn random_scalar() -> Scalar {
    let mut buf = [0u8; LENGTH_MESSAGE_EXPAND];
    getrandom(&mut buf).unwrap();
    let array: GenericArray<u8, U48> = GenericArray::clone_from_slice(&buf);
    Scalar::from_okm(&array)
}

/// Sample the requested number of random scalar values.
///
/// - `count`: the number of scalar values to sample.
/// - `cipher`: the cipher suite.
///
/// Return a list of `Scalar` values.
pub fn random_scalars(count: usize) -> Vec<Scalar> {
    // (0..count).map(|_| Scalar::one()).collect()
    // Procedure:
    //
    // 1. For i in (1, 2, ..., count):
    // 2.   scalar_i := os2ip(get_random(expand_len)) mod r.
    // 3. Return (scalar_1, scalar_2, ..., scalar_count).
    (0..count)
        .map(|_| {
            let mut buf = [0u8; LENGTH_MESSAGE_EXPAND];
            getrandom(&mut buf).unwrap();
            let array: GenericArray<u8, U48> = GenericArray::clone_from_slice(&buf);
            Scalar::from_okm(&array)
        })
        .collect()
}

/// Deterministically calculate `count` pseudo-random scalars from a single `seed`, given a domain separation tag `dst`.
///
/// - `seed`: the seed octet string.
/// - `dst`: the domain separation tag.
/// - `count`: the number of scalars to generate.
/// - `cipher`: the cipher suite.
///
/// Return the requested number of pseudo-random scalars.
#[allow(dead_code)]
pub fn seeded_random_scalars(
    seed: &[u8],
    dst: &[u8],
    count: usize,
    cipher: &Cipher,
) -> Vec<Scalar> {
    // ABORT IF:
    //
    // 1. count * expand_len > 65535.
    if count * LENGTH_MESSAGE_EXPAND > 65535 {
        panic!("seeded_random_scalars: count * expand_len too large");
    }

    // Procedure:
    //
    // 1. out_len := expand_len * count.
    // 2. v := expand_message(seed, dst, out_len).
    // 3. If v is INVALID, return INVALID.
    //
    // 4. For i in (1, 2, ..., count):
    // 5.     start_idx := (i - 1) * expand_len.
    // 6.     end_idx := i * expand_len - 1.
    // 7.     scalar_i := os2ip(v[start_idx..end_idx]) mod r.
    // 8. Return (scalar_1, scalar_2, ..., scalar_count).
    let out_len = LENGTH_MESSAGE_EXPAND * count;
    let v = (cipher.expand_message)(seed, dst, Some(out_len));

    if v.is_empty() {
        panic!("seeded_random_scalars: invalid output");
    }

    (0..count)
        .map(|i| {
            let start_idx = i * LENGTH_MESSAGE_EXPAND;
            let end_idx = (i + 1) * LENGTH_MESSAGE_EXPAND;
            let array: GenericArray<u8, U48> =
                GenericArray::clone_from_slice(&v[start_idx..end_idx]);
            Scalar::from_okm(&array)
        })
        .collect()
}

/// Calculate the domain value, a scalar representing the distillation of all essential contextual information for a
/// signature. The same domain value be calculated by all parties (the signer, the prover, and the verifier) for both
/// the signatures and the proofs to be validated.
///
/// The input to the domain value includes a `header` property chosen by the signer to encode any information that is
/// required to be revealed by the prover (such as an expiration date, or an identifier for the target audience). This
/// in contrast to the signed message values, which may be withheld during a proof.
///
/// When a signature is generated, the domain value is combined with a specific generator point `q_1` to protect the
/// integrity of the public parameters and the header.
///
/// - `public_key`: an octet string representing the public key of the signer.
/// - `q_1`: a generator point.
/// - `h_points`: a list of generator points.
/// - `header`: an octet string representing the header. It defaults to an empty string.
/// - `api_id`: an octet string representing the API identifier. It defaults to an empty string.
/// - `cipher`: a cipher suite.
///
/// Return a scalar.
pub fn calculate_domain(
    public_key: &[u8],
    q_1: G1Affine,
    h_points: Vec<G1Affine>,
    header: Option<&[u8]>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> Scalar {
    let inner_header = header.unwrap_or(&[]);
    let inner_api_id = api_id.unwrap_or(&[]);

    // definitions:
    //
    // 1. hash_to_scalar_dst: an octet string representing the domain separation tag:
    //                        "<api_id> || H2S_".
    let hash_to_scalar_dst = [inner_api_id, PADDING_HASH_TO_SCALAR].concat();

    // Deserialization:
    //
    // 1. L := len(h_points).
    // 2. (h_1, h_2, ..., h_L) := h_points.
    let l = h_points.len();

    // ABORT IF:
    //
    // 1. len(header) > 2^64 - 1, or L > 2^64 - 1.
    if inner_header.len() > usize::MAX || l > usize::MAX {
        panic!("header or L is too long");
    }

    // Procedure:
    //
    // 1. dom_array := (L, q_1, h_1, h_2, ..., h_L).
    // 2. dom_octets := serialize(dom_array) || api_id.
    // 3. dom_input := public_key || dom_octets || i2osp(len(header), 8) || header.
    // 4. Return hash_to_scalar(dom_input, hash_to_scalar_dst).
    let l_bytes = (l as u64).serialize();
    let q_1_bytes: Vec<u8> = q_1.serialize();
    let h_points_bytes: Vec<u8> = h_points.iter().flat_map(|h| h.serialize()).collect();

    let dom_octets = [l_bytes, q_1_bytes, h_points_bytes, inner_api_id.to_vec()].concat();
    let dom_input = [
        public_key.to_vec(),
        dom_octets,
        i2osp(inner_header.len() as u64, 8),
        inner_header.to_vec(),
    ]
    .concat();
    hash_to_scalar(&dom_input, &hash_to_scalar_dst, cipher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::constants::{PADDING_API_ID, PADDING_SEED_RANDOM_SCALAR};
    use crate::suite::instance::{BLS12_381_G1_XMD_SHA_256, BLS12_381_G1_XOF_SHAKE_256};
    use crate::utils::format::hex_to_bytes;
    use crate::utils::generator::create_generator;

    #[test]
    fn shake_256_messages_to_scalars() {
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

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let messages = vec![
            msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10,
        ];
        let messages: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();
        let scalars = message_to_scalars(&messages, Some(&api_id), &cipher);

        assert_eq!(
            scalars[0].to_string(),
            "0x1e0dea6c9ea8543731d331a0ab5f64954c188542b33c5bbc8ae5b3a830f2d99f"
        );
        assert_eq!(
            scalars[1].to_string(),
            "0x3918a40fb277b4c796805d1371931e08a314a8bf8200a92463c06054d2c56a9f"
        );
        assert_eq!(
            scalars[2].to_string(),
            "0x6642b981edf862adf34214d933c5d042bfa8f7ef343165c325131e2ffa32fa94"
        );
        assert_eq!(
            scalars[3].to_string(),
            "0x33c021236956a2006f547e22ff8790c9d2d40c11770c18cce6037786c6f23512"
        );
        assert_eq!(
            scalars[4].to_string(),
            "0x52b249313abbe323e7d84230550f448d99edfb6529dec8c4e783dbd6dd2a8471"
        );
        assert_eq!(
            scalars[5].to_string(),
            "0x2a50bdcbe7299e47e1046100aadffe35b4247bf3f059d525f921537484dd54fc"
        );
        assert_eq!(
            scalars[6].to_string(),
            "0x0e92550915e275f8cfd6da5e08e334d8ef46797ee28fa29de40a1ebccd9d95d3"
        );
        assert_eq!(
            scalars[7].to_string(),
            "0x4c28f612e6c6f82f51f95e1e4faaf597547f93f6689827a6dcda3cb94971d356"
        );
        assert_eq!(
            scalars[8].to_string(),
            "0x1db51bedc825b85efe1dab3e3ab0274fa82bbd39732be3459525faf70f197650"
        );
        assert_eq!(
            scalars[9].to_string(),
            "0x27878da72f7775e709bb693d81b819dc4e9fa60711f4ea927740e40073489e78"
        );
    }

    #[test]
    fn sha_256_messages_to_scalars() {
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

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = [cipher.id, PADDING_API_ID].concat();

        let messages = vec![
            msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10,
        ];
        let messages: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();
        let scalars = message_to_scalars(&messages, Some(&api_id), &cipher);

        assert_eq!(
            scalars[0].to_string(),
            "0x1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430"
        );
        assert_eq!(
            scalars[1].to_string(),
            "0x154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952"
        );
        assert_eq!(
            scalars[2].to_string(),
            "0x0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22"
        );
        assert_eq!(
            scalars[3].to_string(),
            "0x4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888"
        );
        assert_eq!(
            scalars[4].to_string(),
            "0x34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e"
        );
        assert_eq!(
            scalars[5].to_string(),
            "0x4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08"
        );
        assert_eq!(
            scalars[6].to_string(),
            "0x064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743"
        );
        assert_eq!(
            scalars[7].to_string(),
            "0x34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02"
        );
        assert_eq!(
            scalars[8].to_string(),
            "0x57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74"
        );
        assert_eq!(
            scalars[9].to_string(),
            "0x08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16"
        );
    }

    #[test]
    fn shake_256_seed_scalars() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let seed = hex_to_bytes("332e313431353932363533353839373933323338343632363433333833323739");
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let dst = [api_id.as_slice(), PADDING_SEED_RANDOM_SCALAR].concat();

        let scalars = seeded_random_scalars(&seed, &dst, 10, &cipher);

        assert_eq!(
            scalars[0].to_string(),
            "0x1004262112c3eaa95941b2b0d1311c09c845db0099a50e67eda628ad26b43083"
        );
        assert_eq!(
            scalars[1].to_string(),
            "0x6da7f145a94c1fa7f116b2482d59e4d466fe49c955ae8726e79453065156a9a4"
        );
        assert_eq!(
            scalars[2].to_string(),
            "0x05017919b3607e78c51e8ec34329955d49c8c90e4488079c43e74824e98f1306"
        );
        assert_eq!(
            scalars[3].to_string(),
            "0x4d451dad519b6a226bba79e11b44c441f1a74800eecfec6a2e2d79ea65b9d32d"
        );
        assert_eq!(
            scalars[4].to_string(),
            "0x5e7e4894e6dbe68023bc92ef15c410b01f3828109fc72b3b5ab159fc427b3f51"
        );
        assert_eq!(
            scalars[5].to_string(),
            "0x646e3014f49accb375253d268eb6c7f3289a1510f1e9452b612dd73a06ec5dd4"
        );
        assert_eq!(
            scalars[6].to_string(),
            "0x363ecc4c1f9d6d9144374de8f1f7991405e3345a3ec49dd485a39982753c11a4"
        );
        assert_eq!(
            scalars[7].to_string(),
            "0x12e592fe28d91d7b92a198c29afaa9d5329a4dcfdaf8b08557807412faeb4ac6"
        );
        assert_eq!(
            scalars[8].to_string(),
            "0x513325acdcdec7ea572360587b350a8b095ca19bdd8258c5c69d375e8706141a"
        );
        assert_eq!(
            scalars[9].to_string(),
            "0x6474fceba35e7e17365dde1a0284170180e446ae96c82943290d7baa3a6ed429"
        );
    }

    #[test]
    fn sha_256_seed_scalars() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let seed = hex_to_bytes("332e313431353932363533353839373933323338343632363433333833323739");
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let dst = [api_id.as_slice(), PADDING_SEED_RANDOM_SCALAR].concat();

        let scalars = seeded_random_scalars(&seed, &dst, 10, &cipher);

        assert_eq!(
            scalars[0].to_string(),
            "0x04f8e2518993c4383957ad14eb13a023c4ad0c67d01ec86eeb902e732ed6df3f"
        );
        assert_eq!(
            scalars[1].to_string(),
            "0x5d87c1ba64c320ad601d227a1b74188a41a100325cecf00223729863966392b1"
        );
        assert_eq!(
            scalars[2].to_string(),
            "0x0444607600ac70482e9c983b4b063214080b9e808300aa4cc02a91b3a92858fe"
        );
        assert_eq!(
            scalars[3].to_string(),
            "0x548cd11eae4318e88cda10b4cd31ae29d41c3a0b057196ee9cf3a69d471e4e94"
        );
        assert_eq!(
            scalars[4].to_string(),
            "0x2264b06a08638b69b4627756a62f08e0dc4d8240c1b974c9c7db779a769892f4"
        );
        assert_eq!(
            scalars[5].to_string(),
            "0x4d99352986a9f8978b93485d21525244b21b396cf61f1d71f7c48e3fbc970a42"
        );
        assert_eq!(
            scalars[6].to_string(),
            "0x5ed8be91662386243a6771fbdd2c627de31a44220e8d6f745bad5d99821a4880"
        );
        assert_eq!(
            scalars[7].to_string(),
            "0x62ff1734b939ddd87beeb37a7bbcafa0a274cbc1b07384198f0e88398272208d"
        );
        assert_eq!(
            scalars[8].to_string(),
            "0x05c2a0af016df58e844db8944082dcaf434de1b1e2e7136ec8a99b939b716223"
        );
        assert_eq!(
            scalars[9].to_string(),
            "0x485e2adab17b76f5334c95bf36c03ccf91cef77dcfcdc6b8a69e2090b3156663"
        );
    }

    #[test]
    fn shake_256_calculate_domain() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let public_key = hex_to_bytes(
            "\
            92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
            8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
            eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        );
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generator(2, Some(&api_id), &cipher);
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let domain = calculate_domain(
            &public_key,
            generators[0],
            generators[1..].to_vec(),
            Some(&header),
            Some(&api_id),
            &cipher,
        );
        assert_eq!(
            domain.to_string(),
            "0x2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9"
        );
    }

    #[test]
    fn sha_256_calculate_domain() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let public_key = hex_to_bytes(
            "\
            a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
            51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
            1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        );
        let api_id = [cipher.id, PADDING_API_ID].concat();
        let generators = create_generator(2, Some(&api_id), &cipher);
        let header = hex_to_bytes("11223344556677889900aabbccddeeff");
        let domain = calculate_domain(
            &public_key,
            generators[0],
            generators[1..].to_vec(),
            Some(&header),
            Some(&api_id),
            &cipher,
        );
        assert_eq!(
            domain.to_string(),
            "0x25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c"
        );
    }
}
